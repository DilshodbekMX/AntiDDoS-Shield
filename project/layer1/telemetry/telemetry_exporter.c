#include "telemetry_exporter.h"
#include <rte_log.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <sqlite3.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define RTE_LOGTYPE_TELEMETRY RTE_LOGTYPE_USER6

// ==================== Global State ====================

static struct telemetry_config config;
static sqlite3 *db = NULL;
static struct rte_ring *flow_ring = NULL;
static struct rte_ring *event_ring = NULL;

static struct rte_mempool *flow_pool = NULL;
static struct rte_mempool *event_pool = NULL;

static pthread_t export_thread;
static bool initialized = false;
static volatile bool stop_requested = false;

// Runtime configurable (atomic access)
static volatile uint32_t flow_sample_rate = 1;      // 1 = all, 100 = 1:100
static volatile bool events_enabled = true;

// OPTIMIZED: Per-lcore sampling counters to avoid contention
// Each lcore maintains its own counter, eliminating atomic operations in fast path
#define TELEMETRY_MAX_LCORES RTE_MAX_LCORE
static uint64_t flow_counter_per_lcore[TELEMETRY_MAX_LCORES] __rte_cache_aligned;

// Statistics
static uint64_t flows_exported = 0;
static uint64_t flows_sampled = 0;
static uint64_t flows_skipped = 0;
static uint64_t events_exported = 0;
static uint64_t export_errors = 0;
static uint64_t flow_alloc_failed = 0;
static uint64_t event_alloc_failed = 0;

// ==================== Database Schema ====================

static const char *CREATE_TABLES_SQL =
    "CREATE TABLE IF NOT EXISTS flows ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  timestamp INTEGER NOT NULL,"
    "  src_ip INTEGER NOT NULL,"
    "  dst_ip INTEGER NOT NULL,"
    "  src_port INTEGER,"
    "  dst_port INTEGER,"
    "  protocol INTEGER,"
    "  direction INTEGER,"
    "  first_seen_ns INTEGER,"
    "  last_seen_ns INTEGER,"
    "  packet_count INTEGER,"
    "  byte_count INTEGER,"
    "  tcp_flags_seen INTEGER,"
    "  tcp_state INTEGER,"
    "  avg_packet_size INTEGER,"
    "  max_packet_size INTEGER,"
    "  avg_inter_arrival_us INTEGER,"
    "  avg_payload_entropy INTEGER,"
    "  avg_header_entropy INTEGER,"
    "  retransmit_count INTEGER,"
    "  out_of_order_count INTEGER,"
    "  dropped INTEGER,"
    "  drop_reason INTEGER"
    ");"
    ""
    "CREATE TABLE IF NOT EXISTS attack_events ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  timestamp_ns INTEGER NOT NULL,"
    "  event_type INTEGER NOT NULL,"
    "  severity INTEGER,"
    "  direction INTEGER,"
    "  src_ip INTEGER,"
    "  dst_ip INTEGER,"
    "  src_port INTEGER,"
    "  dst_port INTEGER,"
    "  protocol INTEGER,"
    "  drop_reason INTEGER,"
    "  packet_count INTEGER,"
    "  byte_count INTEGER,"
    "  description TEXT"
    ");"
    ""
    "CREATE TABLE IF NOT EXISTS statistics ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  timestamp INTEGER NOT NULL,"
    "  total_packets INTEGER,"
    "  total_bytes INTEGER,"
    "  packets_accepted INTEGER,"
    "  packets_dropped INTEGER,"
    "  drop_validation INTEGER,"
    "  drop_blacklist INTEGER,"
    "  drop_rate_limit INTEGER,"
    "  drop_policy INTEGER,"
    "  drop_reputation INTEGER,"
    "  active_flows INTEGER,"
    "  whitelist_hits INTEGER,"
    "  sample_rate INTEGER"
    ");"
    ""
    "CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp);"
    "CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip);"
    "CREATE INDEX IF NOT EXISTS idx_flows_direction ON flows(direction);"
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON attack_events(timestamp_ns);"
    "CREATE INDEX IF NOT EXISTS idx_events_type ON attack_events(event_type);"
    "CREATE INDEX IF NOT EXISTS idx_events_src_ip ON attack_events(src_ip);";

// ==================== Database Operations ====================

static int db_execute(const char *sql) {
    char *err_msg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);

    if (rc != SQLITE_OK) {
        RTE_LOG(ERR, TELEMETRY, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    return 0;
}

static int export_flow_record(const struct flow_record *record) {
    static const char *INSERT_SQL =
        "INSERT INTO flows (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, "
        "direction, first_seen_ns, last_seen_ns, packet_count, byte_count, tcp_flags_seen, "
        "tcp_state, avg_packet_size, max_packet_size, avg_inter_arrival_us, "
        "avg_payload_entropy, avg_header_entropy, retransmit_count, out_of_order_count, "
        "dropped, drop_reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, INSERT_SQL, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    time_t now = time(NULL);

    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_bind_int(stmt, 2, rte_be_to_cpu_32(record->src_ip));
    sqlite3_bind_int(stmt, 3, rte_be_to_cpu_32(record->dst_ip));
    sqlite3_bind_int(stmt, 4, record->src_port);
    sqlite3_bind_int(stmt, 5, record->dst_port);
    sqlite3_bind_int(stmt, 6, record->protocol);
    sqlite3_bind_int(stmt, 7, record->direction);
    sqlite3_bind_int64(stmt, 8, record->first_seen_ns);
    sqlite3_bind_int64(stmt, 9, record->last_seen_ns);
    sqlite3_bind_int64(stmt, 10, record->packet_count);
    sqlite3_bind_int64(stmt, 11, record->byte_count);
    sqlite3_bind_int(stmt, 12, record->tcp_flags_seen);
    sqlite3_bind_int(stmt, 13, record->tcp_state);
    sqlite3_bind_int(stmt, 14, record->avg_packet_size);
    sqlite3_bind_int(stmt, 15, record->max_packet_size);
    sqlite3_bind_int(stmt, 16, record->avg_inter_arrival_us);
    sqlite3_bind_int(stmt, 17, record->avg_payload_entropy);
    sqlite3_bind_int(stmt, 18, record->avg_header_entropy);
    sqlite3_bind_int(stmt, 19, record->retransmit_count);
    sqlite3_bind_int(stmt, 20, record->out_of_order_count);
    sqlite3_bind_int(stmt, 21, record->dropped);
    sqlite3_bind_int(stmt, 22, record->drop_reason);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        __atomic_add_fetch(&export_errors, 1, __ATOMIC_RELAXED);
        return -1;
    }

    __atomic_add_fetch(&flows_exported, 1, __ATOMIC_RELAXED);
    return 0;
}

static int export_attack_event(const struct attack_event *event) {
    static const char *INSERT_SQL =
        "INSERT INTO attack_events (timestamp_ns, event_type, severity, direction, "
        "src_ip, dst_ip, src_port, dst_port, protocol, drop_reason, "
        "packet_count, byte_count, description) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, INSERT_SQL, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, event->timestamp_ns);
    sqlite3_bind_int(stmt, 2, event->event_type);
    sqlite3_bind_int(stmt, 3, event->severity);
    sqlite3_bind_int(stmt, 4, event->direction);
    sqlite3_bind_int(stmt, 5, rte_be_to_cpu_32(event->src_ip));
    sqlite3_bind_int(stmt, 6, rte_be_to_cpu_32(event->dst_ip));
    sqlite3_bind_int(stmt, 7, event->src_port);
    sqlite3_bind_int(stmt, 8, event->dst_port);
    sqlite3_bind_int(stmt, 9, event->protocol);
    sqlite3_bind_int(stmt, 10, event->drop_reason);
    sqlite3_bind_int64(stmt, 11, event->packet_count);
    sqlite3_bind_int64(stmt, 12, event->byte_count);
    sqlite3_bind_text(stmt, 13, event->description, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        __atomic_add_fetch(&export_errors, 1, __ATOMIC_RELAXED);
        return -1;
    }

    __atomic_add_fetch(&events_exported, 1, __ATOMIC_RELAXED);
    return 0;
}

// ==================== Export Thread ====================

static void *export_thread_func(void *arg) {
    (void)arg;

    // OPTIMIZED: Larger batch size for better throughput
    void *flow_ptrs[512];
    void *event_ptrs[256];

    RTE_LOG(INFO, TELEMETRY, "Export thread started (interval=%us)\n",
            config.export_interval_sec);

    while (!stop_requested) {
        // Export flow records in larger batches for efficiency
        unsigned int flow_count = rte_ring_dequeue_burst(flow_ring, flow_ptrs, 512, NULL);

        if (flow_count > 0) {
            db_execute("BEGIN TRANSACTION");
            for (unsigned int i = 0; i < flow_count; i++) {
                struct flow_record *rec = (struct flow_record *)flow_ptrs[i];
                export_flow_record(rec);
                rte_mempool_put(flow_pool, rec);
            }
            db_execute("COMMIT");

            // If we got a full batch, there might be more - don't sleep
            if (flow_count >= 512) {
                continue;
            }
        }

        // Export attack events (high priority - always process immediately)
        unsigned int event_count = rte_ring_dequeue_burst(event_ring, event_ptrs, 256, NULL);

        if (event_count > 0) {
            db_execute("BEGIN TRANSACTION");
            for (unsigned int i = 0; i < event_count; i++) {
                struct attack_event *evt = (struct attack_event *)event_ptrs[i];
                export_attack_event(evt);
                rte_mempool_put(event_pool, evt);
            }
            db_execute("COMMIT");

            // If we got events, check for more flows before sleeping
            if (event_count >= 64) {
                continue;
            }
        }

        // Only sleep if both queues are relatively empty
        usleep(config.export_interval_sec * 1000000);
    }

    // Drain remaining items before exit
    unsigned int remaining;
    do {
        remaining = rte_ring_dequeue_burst(flow_ring, flow_ptrs, 256, NULL);
        for (unsigned int i = 0; i < remaining; i++) {
            struct flow_record *rec = (struct flow_record *)flow_ptrs[i];
            export_flow_record(rec);
            rte_mempool_put(flow_pool, rec);
        }
    } while (remaining > 0);

    do {
        remaining = rte_ring_dequeue_burst(event_ring, event_ptrs, 256, NULL);
        for (unsigned int i = 0; i < remaining; i++) {
            struct attack_event *evt = (struct attack_event *)event_ptrs[i];
            export_attack_event(evt);
            rte_mempool_put(event_pool, evt);
        }
    } while (remaining > 0);

    RTE_LOG(INFO, TELEMETRY, "Export thread stopped\n");
    return NULL;
}

// ==================== Initialization ====================

int telemetry_init(const struct telemetry_config *cfg) {
    if (!cfg) {
        RTE_LOG(ERR, TELEMETRY, "Invalid config\n");
        return -1;
    }

    if (initialized) {
        RTE_LOG(WARNING, TELEMETRY, "Already initialized\n");
        return 0;
    }

    memcpy(&config, cfg, sizeof(config));
    
    // Set initial sampling rate
    flow_sample_rate = (cfg->flow_sample_rate > 0) ? cfg->flow_sample_rate : 1;
    events_enabled = cfg->events_enabled;

    RTE_LOG(INFO, TELEMETRY, "Initializing telemetry:\n");
    RTE_LOG(INFO, TELEMETRY, "  Database: %s\n", config.db_path);
    RTE_LOG(INFO, TELEMETRY, "  Export interval: %u sec\n", config.export_interval_sec);
    RTE_LOG(INFO, TELEMETRY, "  Flow sample rate: 1:%u\n", flow_sample_rate);
    RTE_LOG(INFO, TELEMETRY, "  Events enabled: %s\n", events_enabled ? "yes" : "no");

    // Open database
    int rc = sqlite3_open(config.db_path, &db);
    if (rc != SQLITE_OK) {
        RTE_LOG(ERR, TELEMETRY, "Failed to open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Enable WAL mode for better concurrent performance
    db_execute("PRAGMA journal_mode=WAL");
    db_execute("PRAGMA synchronous=NORMAL");

    if (db_execute(CREATE_TABLES_SQL) < 0) {
        sqlite3_close(db);
        db = NULL;
        return -1;
    }

    // Create mempools
    flow_pool = rte_mempool_create("telemetry_flow_pool",
                                   config.max_flow_records,
                                   sizeof(struct flow_record),
                                   0, 0,
                                   NULL, NULL, NULL, NULL,
                                   rte_socket_id(),
                                   MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
    if (!flow_pool) {
        RTE_LOG(ERR, TELEMETRY, "Failed to create flow mempool\n");
        sqlite3_close(db);
        db = NULL;
        return -1;
    }

    event_pool = rte_mempool_create("telemetry_event_pool",
                                    4096,
                                    sizeof(struct attack_event),
                                    0, 0,
                                    NULL, NULL, NULL, NULL,
                                    rte_socket_id(),
                                    MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
    if (!event_pool) {
        RTE_LOG(ERR, TELEMETRY, "Failed to create event mempool\n");
        rte_mempool_free(flow_pool);
        flow_pool = NULL;
        sqlite3_close(db);
        db = NULL;
        return -1;
    }

    // Create ring buffers
    flow_ring = rte_ring_create("telemetry_flows", config.max_flow_records,
                                rte_socket_id(), RING_F_SC_DEQ);
    if (!flow_ring) {
        RTE_LOG(ERR, TELEMETRY, "Failed to create flow ring\n");
        rte_mempool_free(event_pool);
        rte_mempool_free(flow_pool);
        sqlite3_close(db);
        db = NULL;
        return -1;
    }

    event_ring = rte_ring_create("telemetry_events", 4096,
                                 rte_socket_id(), RING_F_SC_DEQ);
    if (!event_ring) {
        RTE_LOG(ERR, TELEMETRY, "Failed to create event ring\n");
        rte_ring_free(flow_ring);
        rte_mempool_free(event_pool);
        rte_mempool_free(flow_pool);
        sqlite3_close(db);
        db = NULL;
        return -1;
    }

    // Start export thread
    stop_requested = false;
    if (pthread_create(&export_thread, NULL, export_thread_func, NULL) != 0) {
        RTE_LOG(ERR, TELEMETRY, "Failed to create export thread\n");
        rte_ring_free(event_ring);
        rte_ring_free(flow_ring);
        rte_mempool_free(event_pool);
        rte_mempool_free(flow_pool);
        sqlite3_close(db);
        return -1;
    }

    initialized = true;
    RTE_LOG(INFO, TELEMETRY, "Telemetry initialized successfully\n");
    return 0;
}

void telemetry_cleanup(void) {
    if (!initialized) {
        return;
    }

    RTE_LOG(INFO, TELEMETRY, "Cleaning up telemetry...\n");

    stop_requested = true;
    pthread_join(export_thread, NULL);

    if (flow_ring) {
        rte_ring_free(flow_ring);
        flow_ring = NULL;
    }
    if (event_ring) {
        rte_ring_free(event_ring);
        event_ring = NULL;
    }
    if (flow_pool) {
        rte_mempool_free(flow_pool);
        flow_pool = NULL;
    }
    if (event_pool) {
        rte_mempool_free(event_pool);
        event_pool = NULL;
    }
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }

    initialized = false;
    RTE_LOG(INFO, TELEMETRY, "Telemetry cleanup complete\n");
}

bool telemetry_is_initialized(void) {
    return initialized;
}

// ==================== Recording Functions ====================

/**
 * Internal function to actually enqueue a flow record
 */
static void enqueue_flow_record(const struct flow_record *record) {
    struct flow_record *rec;
    if (rte_mempool_get(flow_pool, (void **)&rec) < 0) {
        __atomic_add_fetch(&flow_alloc_failed, 1, __ATOMIC_RELAXED);
        return;
    }

    memcpy(rec, record, sizeof(*record));

    if (rte_ring_enqueue(flow_ring, rec) < 0) {
        rte_mempool_put(flow_pool, rec);
    }
}

void telemetry_record_flow(const struct flow_record *record) {
    if (unlikely(!initialized || !flow_ring || !flow_pool)) {
        return;
    }

    uint32_t rate = __atomic_load_n(&flow_sample_rate, __ATOMIC_RELAXED);

    // rate == 0 means disabled
    if (unlikely(rate == 0)) {
        __atomic_add_fetch(&flows_skipped, 1, __ATOMIC_RELAXED);
        return;
    }

    // OPTIMIZED: Per-lcore counter - NO ATOMICS in fast path
    // Each lcore independently samples, which is statistically equivalent
    // to global sampling but without contention
    unsigned int lcore_id = rte_lcore_id();
    if (unlikely(lcore_id >= TELEMETRY_MAX_LCORES)) {
        lcore_id = 0;  // Fallback for non-DPDK threads
    }

    uint64_t count = ++flow_counter_per_lcore[lcore_id];

    if (likely((count % rate) != 0)) {
        // Fast path: skip this flow (most common case with sampling)
        __atomic_add_fetch(&flows_skipped, 1, __ATOMIC_RELAXED);
        return;
    }

    __atomic_add_fetch(&flows_sampled, 1, __ATOMIC_RELAXED);
    enqueue_flow_record(record);
}

void telemetry_record_flow_force(const struct flow_record *record) {
    if (!initialized || !flow_ring || !flow_pool) {
        return;
    }

    __atomic_add_fetch(&flows_sampled, 1, __ATOMIC_RELAXED);
    enqueue_flow_record(record);
}

void telemetry_record_attack(const struct attack_event *event) {
    if (!initialized || !event_ring || !event_pool) {
        return;
    }

    if (!__atomic_load_n(&events_enabled, __ATOMIC_RELAXED)) {
        return;
    }

    struct attack_event *evt;
    if (rte_mempool_get(event_pool, (void **)&evt) < 0) {
        __atomic_add_fetch(&event_alloc_failed, 1, __ATOMIC_RELAXED);
        return;
    }

    memcpy(evt, event, sizeof(*evt));

    if (rte_ring_enqueue(event_ring, evt) < 0) {
        rte_mempool_put(event_pool, evt);
    }
}

void telemetry_export_stats(void) {
    // TODO: Export aggregated Layer 1 statistics
}

// ==================== Runtime Configuration ====================

void telemetry_set_flow_sample_rate(uint32_t rate) {
    uint32_t old_rate = __atomic_exchange_n(&flow_sample_rate, rate, __ATOMIC_RELAXED);
    RTE_LOG(INFO, TELEMETRY, "Flow sample rate changed: 1:%u -> 1:%u\n", old_rate, rate);
}

uint32_t telemetry_get_flow_sample_rate(void) {
    return __atomic_load_n(&flow_sample_rate, __ATOMIC_RELAXED);
}

void telemetry_set_events_enabled(bool enable) {
    __atomic_store_n(&events_enabled, enable, __ATOMIC_RELAXED);
    RTE_LOG(INFO, TELEMETRY, "Events %s\n", enable ? "enabled" : "disabled");
}

bool telemetry_get_events_enabled(void) {
    return __atomic_load_n(&events_enabled, __ATOMIC_RELAXED);
}

// ==================== Statistics ====================

void telemetry_get_stats(uint64_t *flows_exported_out,
                         uint64_t *flows_sampled_out,
                         uint64_t *flows_skipped_out,
                         uint64_t *events_exported_out,
                         uint64_t *export_errors_out,
                         uint64_t *alloc_failures_out) {
    if (flows_exported_out) {
        *flows_exported_out = __atomic_load_n(&flows_exported, __ATOMIC_RELAXED);
    }
    if (flows_sampled_out) {
        *flows_sampled_out = __atomic_load_n(&flows_sampled, __ATOMIC_RELAXED);
    }
    if (flows_skipped_out) {
        *flows_skipped_out = __atomic_load_n(&flows_skipped, __ATOMIC_RELAXED);
    }
    if (events_exported_out) {
        *events_exported_out = __atomic_load_n(&events_exported, __ATOMIC_RELAXED);
    }
    if (export_errors_out) {
        *export_errors_out = __atomic_load_n(&export_errors, __ATOMIC_RELAXED);
    }
    if (alloc_failures_out) {
        *alloc_failures_out = __atomic_load_n(&flow_alloc_failed, __ATOMIC_RELAXED) +
                              __atomic_load_n(&event_alloc_failed, __ATOMIC_RELAXED);
    }
}

void telemetry_print_stats(void) {
    uint64_t f_exp, f_samp, f_skip, e_exp, errs, alloc;
    telemetry_get_stats(&f_exp, &f_samp, &f_skip, &e_exp, &errs, &alloc);

    printf("\n=== Telemetry Statistics ===\n");
    printf("  Sample rate:      1:%u\n", telemetry_get_flow_sample_rate());
    printf("  Events enabled:   %s\n", telemetry_get_events_enabled() ? "yes" : "no");
    printf("  Flows sampled:    %lu\n", f_samp);
    printf("  Flows skipped:    %lu\n", f_skip);
    printf("  Flows exported:   %lu\n", f_exp);
    printf("  Events exported:  %lu\n", e_exp);
    printf("  Export errors:    %lu\n", errs);
    printf("  Alloc failures:   %lu\n", alloc);
    printf("============================\n\n");
}