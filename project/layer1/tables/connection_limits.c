#include "connection_limits.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <string.h>

#define RTE_LOGTYPE_CONNLIMIT RTE_LOGTYPE_USER4

// ==================== Global State ====================

static struct rte_hash *conn_hash = NULL;
static struct connection_tracker *trackers = NULL;
static struct connection_limits_config config;
static bool initialized = false;

// Statistics (atomic for thread safety)
static uint64_t limits_exceeded = 0;
static uint64_t total_checks = 0;

// ==================== Initialization ====================

int connection_limits_init(const struct connection_limits_config *cfg) {
    if (!cfg) {
        RTE_LOG(ERR, CONNLIMIT, "Invalid config\n");
        return -1;
    }

    if (initialized) {
        RTE_LOG(WARNING, CONNLIMIT, "Connection limits already initialized\n");
        return 0;
    }

    memcpy(&config, cfg, sizeof(config));

    RTE_LOG(INFO, CONNLIMIT, "Initializing connection limits (thread-safe):\n");
    RTE_LOG(INFO, CONNLIMIT, "  Max IPs: %u\n", config.max_ips);
    RTE_LOG(INFO, CONNLIMIT, "  Max connections/IP: %u\n", config.max_connections_per_ip);
    RTE_LOG(INFO, CONNLIMIT, "  Time window: %u sec\n", config.time_window_sec);

    // Create hash table with thread safety
    // Uses rte_hash_add_key which returns index directly - no separate index allocation needed
    struct rte_hash_parameters hash_params = {
        .name = "conn_limit_hash",
        .entries = config.max_ips,
        .key_len = sizeof(uint32_t),  // IP address
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        // CRITICAL: Enable thread-safe concurrent access
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                      RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
    };

    conn_hash = rte_hash_create(&hash_params);
    if (!conn_hash) {
        RTE_LOG(ERR, CONNLIMIT, "Failed to create hash table\n");
        return -1;
    }

    // Allocate tracker array - index comes from hash table
    trackers = rte_zmalloc("conn_trackers",
                          config.max_ips * sizeof(struct connection_tracker),
                          RTE_CACHE_LINE_SIZE);
    if (!trackers) {
        RTE_LOG(ERR, CONNLIMIT, "Failed to allocate tracker array\n");
        rte_hash_free(conn_hash);
        conn_hash = NULL;
        return -1;
    }

    initialized = true;
    RTE_LOG(INFO, CONNLIMIT, "Connection limits initialized successfully (thread-safe)\n");
    return 0;
}

void connection_limits_cleanup(void) {
    if (conn_hash) {
        rte_hash_free(conn_hash);
        conn_hash = NULL;
    }

    if (trackers) {
        rte_free(trackers);
        trackers = NULL;
    }

    initialized = false;
    RTE_LOG(INFO, CONNLIMIT, "Connection limits cleanup complete\n");
}

// ==================== Connection Tracking ====================

bool connection_limits_check(uint32_t ip, uint16_t port) {
    (void)port;  // Reserved for per-port tracking

    if (!initialized) {
        return true;  // Fail-open
    }

    __atomic_add_fetch(&total_checks, 1, __ATOMIC_RELAXED);

    uint64_t now_tsc = rte_get_tsc_cycles();
    uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t window_tsc = config.time_window_sec * tsc_hz;

    // Try to find existing tracker
    int32_t index = rte_hash_lookup(conn_hash, &ip);

    if (index < 0) {
        // New IP - add to hash table
        // rte_hash_add_key returns the index to use
        index = rte_hash_add_key(conn_hash, &ip);
        
        if (index < 0) {
            // Table full - fail-open
            static uint64_t log_count = 0;
            if (__atomic_fetch_add(&log_count, 1, __ATOMIC_RELAXED) < 10) {
                RTE_LOG(WARNING, CONNLIMIT, "Connection tracker table full\n");
            }
            return true;
        }

        // Initialize tracker at the index provided by hash table
        struct connection_tracker *tracker = &trackers[index];
        __atomic_store_n(&tracker->ip, ip, __ATOMIC_RELAXED);
        __atomic_store_n(&tracker->total_connections, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&tracker->active_connections, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&tracker->connections_last_window, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&tracker->last_update_tsc, now_tsc, __ATOMIC_RELAXED);
        __atomic_store_n(&tracker->window_start_tsc, now_tsc, __ATOMIC_RELAXED);

        return true;  // First connection from this IP - allow
    }

    // Existing IP - check limits
    struct connection_tracker *tracker = &trackers[index];

    // Check if we need to reset the sliding window
    uint64_t window_start = __atomic_load_n(&tracker->window_start_tsc, __ATOMIC_ACQUIRE);
    uint64_t time_since_window_start = now_tsc - window_start;
    
    if (time_since_window_start > window_tsc) {
        // Window expired - reset (use CAS for thread safety)
        if (__atomic_compare_exchange_n(&tracker->window_start_tsc, 
                                        &window_start, now_tsc,
                                        false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            __atomic_store_n(&tracker->connections_last_window, 0, __ATOMIC_RELAXED);
        }
    }

    // Check limit
    uint32_t conns = __atomic_load_n(&tracker->connections_last_window, __ATOMIC_ACQUIRE);
    if (conns >= config.max_connections_per_ip) {
        __atomic_add_fetch(&limits_exceeded, 1, __ATOMIC_RELAXED);

        // Log first few occurrences
        static uint64_t log_count = 0;
        if (__atomic_fetch_add(&log_count, 1, __ATOMIC_RELAXED) < 10) {
            RTE_LOG(WARNING, CONNLIMIT,
                    "Connection limit exceeded: IP=%u.%u.%u.%u (%u conns in %u sec)\n",
                    (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
                    (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
                    (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
                    rte_be_to_cpu_32(ip) & 0xFF,
                    conns,
                    config.time_window_sec);
        }

        return false;  // Limit exceeded
    }

    // Update counters atomically
    __atomic_add_fetch(&tracker->total_connections, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&tracker->active_connections, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&tracker->connections_last_window, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&tracker->last_update_tsc, now_tsc, __ATOMIC_RELAXED);

    return true;  // Allowed
}

void connection_limits_update(uint32_t ip, enum connection_state state) {
    if (!initialized) {
        return;
    }

    int32_t index = rte_hash_lookup(conn_hash, &ip);
    if (index < 0) {
        return;  // IP not tracked
    }

    struct connection_tracker *tracker = &trackers[index];

    switch (state) {
        case CONN_STATE_SYN_SENT:
            // Already counted in connection_limits_check()
            break;

        case CONN_STATE_ESTABLISHED:
            // Connection established
            break;

        case CONN_STATE_CLOSED:
            // Connection closed - decrement active count
            {
                uint32_t active = __atomic_load_n(&tracker->active_connections, __ATOMIC_ACQUIRE);
                if (active > 0) {
                    __atomic_sub_fetch(&tracker->active_connections, 1, __ATOMIC_RELAXED);
                }
            }
            break;
    }

    __atomic_store_n(&tracker->last_update_tsc, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
}

uint32_t connection_limits_cleanup_expired(void) {
    if (!initialized) {
        return 0;
    }

    uint64_t now_tsc = rte_get_tsc_cycles();
    uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t expire_tsc = config.cleanup_interval_sec * tsc_hz;
    uint32_t cleaned = 0;

    // Collect keys to delete (NEVER delete during iteration!)
    uint32_t keys_to_delete[256];
    uint32_t delete_count = 0;

    const void *next_key;
    void *next_data;
    uint32_t iter = 0;

    while (rte_hash_iterate(conn_hash, &next_key, &next_data, &iter) >= 0) {
        if (delete_count >= 256) {
            break;  // Process in batches
        }

        int32_t index = rte_hash_lookup(conn_hash, next_key);
        if (index < 0) {
            continue;
        }

        struct connection_tracker *tracker = &trackers[index];

        // Check if entry is old and has no active connections
        uint64_t last_update = __atomic_load_n(&tracker->last_update_tsc, __ATOMIC_ACQUIRE);
        uint32_t active = __atomic_load_n(&tracker->active_connections, __ATOMIC_ACQUIRE);
        uint64_t idle_time = now_tsc - last_update;

        if (idle_time > expire_tsc && active == 0) {
            keys_to_delete[delete_count++] = *(const uint32_t *)next_key;
        }
    }

    // Now delete collected keys
    for (uint32_t i = 0; i < delete_count; i++) {
        int32_t pos = rte_hash_del_key(conn_hash, &keys_to_delete[i]);
        if (pos >= 0) {
            memset(&trackers[pos], 0, sizeof(struct connection_tracker));
            cleaned++;
        }
    }

    if (cleaned > 0) {
        RTE_LOG(DEBUG, CONNLIMIT, "Cleaned up %u expired connection trackers\n", cleaned);
    }

    return cleaned;
}

// ==================== Statistics ====================

bool connection_limits_get_count(uint32_t ip, uint32_t *active, uint32_t *total) {
    if (!initialized) {
        return false;
    }

    int32_t index = rte_hash_lookup(conn_hash, &ip);
    if (index < 0) {
        return false;
    }

    struct connection_tracker *tracker = &trackers[index];

    if (active) {
        *active = __atomic_load_n(&tracker->active_connections, __ATOMIC_RELAXED);
    }
    if (total) {
        *total = __atomic_load_n(&tracker->total_connections, __ATOMIC_RELAXED);
    }

    return true;
}

void connection_limits_get_stats(uint32_t *tracked_ips,
                                 uint32_t *total_connections,
                                 uint64_t *limits_exceeded_out) {
    if (tracked_ips) {
        *tracked_ips = conn_hash ? rte_hash_count(conn_hash) : 0;
    }

    if (total_connections) {
        uint32_t total = 0;
        if (initialized) {
            const void *next_key;
            void *next_data;
            uint32_t iter = 0;

            while (rte_hash_iterate(conn_hash, &next_key, &next_data, &iter) >= 0) {
                int32_t index = rte_hash_lookup(conn_hash, next_key);
                if (index >= 0) {
                    total += __atomic_load_n(&trackers[index].active_connections, __ATOMIC_RELAXED);
                }
            }
        }
        *total_connections = total;
    }

    if (limits_exceeded_out) {
        *limits_exceeded_out = __atomic_load_n(&limits_exceeded, __ATOMIC_RELAXED);
    }
}