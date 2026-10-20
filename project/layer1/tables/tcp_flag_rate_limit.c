#include "tcp_flag_rate_limit.h"
#include "flow_table_internal.h"
#include "../config/layer1_config.h"
#include "../interlayer/shared_memory.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <string.h>
#include <stdio.h>

#define RTE_LOGTYPE_TCPFLAG RTE_LOGTYPE_USER5

/**
 * @file tcp_flag_rate_limit.c
 * @brief Per-TCP-flag-class rate limiting implementation
 *
 * Uses token bucket algorithm with millisecond-precision refill.
 * Each source IP has separate buckets for each TCP flag class.
 */

// ==================== Token Bucket Structure ====================

/**
 * Token bucket for a single source IP.
 * Contains tokens for all flag classes to minimize hash lookups.
 * A bucket is indexed by its source's position in g_bucket_hash.
 */
struct tcp_flag_bucket {
    uint32_t src_ip;                        // Source IP (network byte order)
    uint32_t live;                          // 1 once set up for src_ip (release), 0 again before its delete
    uint64_t last_refill_tsc;               // Last refill timestamp (TSC)
    uint32_t tokens[TCPF_MAX];              // Available tokens per class
    uint32_t packet_count[TCPF_MAX];        // Packets seen per class (for stats)
    uint64_t first_seen_tsc;                // When this IP first appeared
    uint64_t last_seen_tsc;                 // Last packet from this IP
} __rte_cache_aligned;

// ==================== Global State ====================

static struct rte_hash *g_bucket_hash = NULL;
static struct tcp_flag_bucket *g_buckets = NULL;
static uint32_t g_max_key_id = 0;           // Positions are below this (g_buckets has this many)
static struct tcp_flag_rate_config g_config;
static uint64_t g_tsc_hz = 0;
static bool g_initialized = false;

// Every writer of g_bucket_hash (each add, each delete and each release of a
// deleted source's position, from any lcore or thread) holds this lock;
// lookups do not take it. RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF makes
// lookups safe against one writer at a time, not writers against each
// other: without RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD the hash takes no
// lock of its own, and an add takes its key slot from a single-consumer
// ring, so two lcores adding at once could take the same slot (a source
// lost, or two sources on one bucket). MULTI_WRITER_ADD is not used: its
// per-lcore slot cache is indexed by rte_lcore_id(), which faults on
// non-EAL threads, and its positions run past the configured entries.
static rte_spinlock_t g_wlock = RTE_SPINLOCK_INITIALIZER;

// Deleted sources' positions waiting for the readers' grace period. With
// RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF the hash keeps a deleted key's
// position allocated (no_free_on_del) until rte_hash_free_key_with_position()
// releases it, so a position never released is lost for good. It is not
// released at once either: a packet lcore may still use the bucket after a
// lookup made before the delete. A position returns to the hash only once
// every registered flow table reader has reported a quiescent state since
// its delete. Each position is in one place at a time (the hash's free
// slots, a live key, or this limbo), so the limbo never refuses one.
static struct flow_limbo g_limbo;

// Most positions an add that finds the table full takes back (packet path)
#define TCPF_RECLAIM_ADD_MAX    64
// Expired sources one cleanup batch deletes before handing them over
#define TCPF_DELETE_BATCH       256
// Deleted positions have waited this long with none taken back: a
// registered reader has stopped reporting quiescent states
#define TCPF_STALL_SEC          2

// Per-lcore statistics (no atomics in fast path)
struct tcp_flag_lcore_stats {
    uint64_t packets_checked;
    uint64_t packets_accepted;
    uint64_t drops[TCPF_MAX];
    uint64_t table_full;
    uint64_t _pad[4];
} __rte_cache_aligned;

static struct tcp_flag_lcore_stats g_lcore_stats[RTE_MAX_LCORE];

// Global cleanup tracking
static uint64_t g_last_cleanup_tsc = 0;
static uint64_t g_cleanups_performed = 0;

// Stalled-reader warning (maintenance thread only)
static uint64_t g_stall_since_tsc = 0;
static uint64_t g_stall_log_tsc = 0;

// ==================== Helper Functions ====================

static inline uint64_t ms_to_tsc(uint64_t ms) {
    return (ms * g_tsc_hz) / 1000;
}

static inline uint64_t sec_to_tsc(uint64_t sec) {
    return sec * g_tsc_hz;
}

// Test seam (see tcp_flag_rate_limit.h): this weak default does nothing
__attribute__((weak)) void tcp_flag_rate_seam(enum tcp_flag_rate_seam_point point) {
    (void)point;
}

bool tcp_flag_rate_writer_lock_held(void) {
    return rte_spinlock_is_locked(&g_wlock) != 0;
}

/**
 * Return to the hash up to max (at most 256) positions whose grace period
 * is over, oldest first. Caller holds g_wlock: releasing a position is a
 * hash write.
 *
 * @return number of positions returned
 */
static uint32_t tcpf_reclaim_locked(uint32_t max) {
    uint32_t pos[256];
    uint32_t n = flow_limbo_take(&g_limbo, pos, RTE_MIN(max, (uint32_t)RTE_DIM(pos)));
    for (uint32_t i = 0; i < n; i++) {
        rte_hash_free_key_with_position(g_bucket_hash, (int32_t)pos[i]);
    }
    return n;
}

/**
 * Return to the hash every position whose grace period is over, taking the
 * writer lock for 256 at a time, so that new sources on other lcores wait
 * for one batch at most. Caller does not hold g_wlock.
 *
 * @return number of positions returned
 */
static uint32_t tcpf_reclaim_all(void) {
    uint32_t total = 0;
    uint32_t n;

    do {
        rte_spinlock_lock(&g_wlock);
        n = tcpf_reclaim_locked(256);
        rte_spinlock_unlock(&g_wlock);
        total += n;
    } while (n == 256);
    return total;
}

/**
 * Hand the n positions a cleanup batch deleted from the hash to the limbo,
 * which starts their grace period. Caller does not hold g_wlock.
 */
static void tcpf_retire(const uint32_t *pos, uint32_t n) {
    uint32_t refused = flow_limbo_push(&g_limbo, pos, n);
    if (unlikely(refused > 0)) {
        // Only without the readers' quiescent-state variable (then no
        // reader can register to be waited for): release them at once
        // rather than lose them
        static uint64_t refuse_log_count = 0;
        if (__atomic_fetch_add(&refuse_log_count, 1, __ATOMIC_RELAXED) < 10) {
            RTE_LOG(ERR, TCPFLAG, "Deferred reclamation unavailable: %u deleted positions released at once\n",
                    refused);
        }
        rte_spinlock_lock(&g_wlock);
        for (uint32_t i = n - refused; i < n; i++) {
            rte_hash_free_key_with_position(g_bucket_hash, (int32_t)pos[i]);
        }
        rte_spinlock_unlock(&g_wlock);
    }
}

/**
 * True if the bucket has seen no packet for longer than timeout_tsc as of
 * now_tsc. A packet on another lcore may stamp it after the caller read its
 * clock: that source is active, and now_tsc - last_seen would wrap.
 */
static inline bool tcpf_expired(const struct tcp_flag_bucket *bucket, uint64_t now_tsc,
                                uint64_t timeout_tsc) {
    uint64_t last_seen = __atomic_load_n(&bucket->last_seen_tsc, __ATOMIC_RELAXED);
    return last_seen <= now_tsc && now_tsc - last_seen > timeout_tsc;
}

// ==================== Initialization ====================

int tcp_flag_rate_init(const struct tcp_flag_rate_config *config) {
    if (g_initialized) {
        RTE_LOG(WARNING, TCPFLAG, "Already initialized\n");
        return 0;
    }

    g_tsc_hz = rte_get_tsc_hz();

    // Use provided config or defaults
    if (config) {
        memcpy(&g_config, config, sizeof(g_config));
    } else {
        // Set defaults
        memset(&g_config, 0, sizeof(g_config));
        g_config.enabled = true;
        g_config.max_entries = TCPF_DEFAULT_MAX_ENTRIES;
        g_config.cleanup_interval_sec = TCPF_DEFAULT_CLEANUP_SEC;
        g_config.report_violations = true;

        // Default PPS limits per class
        g_config.pps_limits[TCPF_SYN] = TCPF_DEFAULT_SYN_PPS;
        g_config.pps_limits[TCPF_SYN_ACK] = TCPF_DEFAULT_SYN_ACK_PPS;
        g_config.pps_limits[TCPF_ACK] = TCPF_DEFAULT_ACK_PPS;
        g_config.pps_limits[TCPF_RST] = TCPF_DEFAULT_RST_PPS;
        g_config.pps_limits[TCPF_FIN] = TCPF_DEFAULT_FIN_PPS;
        g_config.pps_limits[TCPF_PSH] = TCPF_DEFAULT_PSH_PPS;
        g_config.pps_limits[TCPF_URG] = TCPF_DEFAULT_URG_PPS;
        g_config.pps_limits[TCPF_OTHER] = TCPF_DEFAULT_OTHER_PPS;

        // Bucket capacity = 2x PPS (2 seconds of burst)
        for (int i = 0; i < TCPF_MAX; i++) {
            g_config.bucket_capacity[i] = g_config.pps_limits[i] * 2;
        }
    }

    if (!g_config.enabled) {
        RTE_LOG(INFO, TCPFLAG, "TCP flag rate limiting disabled\n");
        g_initialized = true;
        return 0;
    }

    // Create hash table
    char hash_name[64];
    snprintf(hash_name, sizeof(hash_name), "tcp_flag_hash_%lu",
             (unsigned long)rte_rdtsc());

    struct rte_hash_parameters hash_params = {
        .name = hash_name,
        .entries = g_config.max_entries,
        .key_len = sizeof(uint32_t),  // Key is just src_ip
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        // Lock-free lookups; writers are serialized by g_wlock
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
    };

    g_bucket_hash = rte_hash_create(&hash_params);
    if (!g_bucket_hash) {
        RTE_LOG(ERR, TCPFLAG, "Failed to create hash table\n");
        return -1;
    }

    // One bucket per position the hash can hand out
    int32_t max_key_id = rte_hash_max_key_id(g_bucket_hash);
    if (max_key_id <= 0) {
        RTE_LOG(ERR, TCPFLAG, "Invalid hash table size %d\n", max_key_id);
        rte_hash_free(g_bucket_hash);
        g_bucket_hash = NULL;
        return -1;
    }
    g_max_key_id = (uint32_t)max_key_id;

    // Allocate bucket array
    size_t bucket_size = sizeof(struct tcp_flag_bucket) * g_max_key_id;
    g_buckets = rte_zmalloc("tcp_flag_buckets", bucket_size, RTE_CACHE_LINE_SIZE);
    if (!g_buckets) {
        RTE_LOG(ERR, TCPFLAG, "Failed to allocate bucket array (%zu bytes)\n", bucket_size);
        rte_hash_free(g_bucket_hash);
        g_bucket_hash = NULL;
        return -1;
    }

    if (flow_limbo_init(&g_limbo, g_max_key_id, "tcp_flag_limbo") != 0 ||
        flow_table_readers() == NULL) {
        RTE_LOG(ERR, TCPFLAG, "Failed to set up deferred reclamation\n");
        flow_limbo_free(&g_limbo);
        rte_free(g_buckets);
        g_buckets = NULL;
        rte_hash_free(g_bucket_hash);
        g_bucket_hash = NULL;
        return -1;
    }
    rte_spinlock_init(&g_wlock);

    // Initialize per-lcore stats
    memset(g_lcore_stats, 0, sizeof(g_lcore_stats));

    g_last_cleanup_tsc = rte_rdtsc();
    g_stall_since_tsc = 0;
    g_stall_log_tsc = 0;
    g_initialized = true;

    RTE_LOG(INFO, TCPFLAG, "TCP flag rate limiting initialized: %u entries, "
            "limits SYN=%u ACK=%u RST=%u FIN=%u\n",
            g_config.max_entries,
            g_config.pps_limits[TCPF_SYN],
            g_config.pps_limits[TCPF_ACK],
            g_config.pps_limits[TCPF_RST],
            g_config.pps_limits[TCPF_FIN]);

    return 0;
}

void tcp_flag_rate_cleanup(void) {
    if (!g_initialized) return;

    if (g_bucket_hash) {
        rte_hash_free(g_bucket_hash);
        g_bucket_hash = NULL;
    }

    if (g_buckets) {
        rte_free(g_buckets);
        g_buckets = NULL;
    }

    // The table is gone: positions still waiting go with it
    flow_limbo_free(&g_limbo);
    g_max_key_id = 0;

    g_initialized = false;
    RTE_LOG(INFO, TCPFLAG, "TCP flag rate limiting cleaned up\n");
}

// ==================== Rate Check (Hot Path) ====================

/**
 * Add a source the lockless lookup missed, set up its bucket and publish it,
 * under the writer lock. Another lcore may have added the source since that
 * lookup: its bucket is then returned as it is (adding the key again would
 * return its position, and setting the bucket up again would refill it).
 *
 * @return the source's position, or a negative value if the table has no
 *         free position
 */
static int32_t tcpf_add_source(uint32_t src_ip, uint64_t now_tsc) {
    rte_spinlock_lock(&g_wlock);
    int32_t idx = rte_hash_lookup(g_bucket_hash, &src_ip);
    if (idx < 0) {
        tcp_flag_rate_seam(TCPF_SEAM_ADD);
        idx = rte_hash_add_key(g_bucket_hash, &src_ip);
        if (idx < 0 && tcpf_reclaim_locked(TCPF_RECLAIM_ADD_MAX) > 0) {
            // Positions deleted earlier whose grace period is over
            idx = rte_hash_add_key(g_bucket_hash, &src_ip);
        }
        if (idx >= 0) {
            // A position comes from the free slots, so no reader uses its
            // bucket: lookups of this key see live == 0 until it is set up
            struct tcp_flag_bucket *bucket = &g_buckets[idx];
            bucket->src_ip = src_ip;
            bucket->first_seen_tsc = now_tsc;
            bucket->last_refill_tsc = now_tsc;
            __atomic_store_n(&bucket->last_seen_tsc, now_tsc, __ATOMIC_RELAXED);
            for (int i = 0; i < TCPF_MAX; i++) {
                bucket->tokens[i] = g_config.bucket_capacity[i];
                bucket->packet_count[i] = 0;
            }
            tcp_flag_rate_seam(TCPF_SEAM_PUBLISH);
            __atomic_store_n(&bucket->live, 1, __ATOMIC_RELEASE);
        }
    }
    rte_spinlock_unlock(&g_wlock);
    return idx;
}

enum tcp_flag_rate_result tcp_flag_rate_check(uint32_t src_ip,
                                               uint8_t tcp_flags,
                                               uint16_t pkt_len __rte_unused) {
    // Fast path: disabled check
    if (!g_initialized || !g_config.enabled) {
        return TCPF_RATE_ACCEPT;
    }

    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= RTE_MAX_LCORE) {
        lcore_id = 0;
    }
    struct tcp_flag_lcore_stats *lstats = &g_lcore_stats[lcore_id];
    lstats->packets_checked++;

    // Classify TCP flags
    enum tcp_flag_class cls = tcp_flag_classify(tcp_flags);
    uint32_t limit = g_config.pps_limits[cls];

    // Skip if limit is 0 (unlimited)
    if (limit == 0) {
        lstats->packets_accepted++;
        return TCPF_RATE_ACCEPT;
    }

    // Lookup or create bucket
    int32_t idx = rte_hash_lookup(g_bucket_hash, &src_ip);
    struct tcp_flag_bucket *bucket;
    uint64_t now_tsc = rte_rdtsc();

    if (likely(idx >= 0)) {
        bucket = &g_buckets[idx];
        tcp_flag_rate_seam(TCPF_SEAM_HIT);
        if (unlikely(!__atomic_load_n(&bucket->live, __ATOMIC_ACQUIRE))) {
            // Another lcore is adding this source and has not set its
            // bucket up yet, or the cleanup is deleting it. Neither says
            // anything about the source (a new bucket starts full): accept,
            // and leave the bucket alone
            lstats->packets_accepted++;
            return TCPF_RATE_ACCEPT;
        }
    } else {
        // New IP - add it under the writer lock
        tcp_flag_rate_seam(TCPF_SEAM_MISSED);
        idx = tcpf_add_source(src_ip, now_tsc);
        if (unlikely(idx < 0)) {
            // Every position holds a source seen within the timeout (or
            // waits for its grace period). Fail OPEN: dropping here would
            // drop every new source, whatever it sends, until positions
            // free up, so filling the table would deny service to every new
            // TCP client. Sources already tracked stay rate limited.
            lstats->table_full++;
            lstats->packets_accepted++;
            static uint64_t full_log_count = 0;
            if (__atomic_fetch_add(&full_log_count, 1, __ATOMIC_RELAXED) < 10) {
                RTE_LOG(WARNING, TCPFLAG, "Table full (%u entries): new source accepted untracked\n",
                        g_config.max_entries);
            }
            return TCPF_RATE_ACCEPT;
        }
        bucket = &g_buckets[idx];
    }

    __atomic_store_n(&bucket->last_seen_tsc, now_tsc, __ATOMIC_RELAXED);

    // TF2 NOTE: Token bucket fields accessed without atomics. This relies on RSS
    // hashing same src_ip to same lcore. If not guaranteed, worst case is slightly
    // inaccurate rate limiting (double refill or double consume). Acceptable trade-off
    // vs cost of atomics on every packet.

    // Token bucket refill. Another lcore may have refilled the bucket after
    // this check read its clock: nothing has elapsed since (now_tsc minus
    // that refill would wrap and refill the bucket to capacity)
    uint64_t last_refill_tsc = bucket->last_refill_tsc;
    uint64_t elapsed_tsc = now_tsc > last_refill_tsc ? now_tsc - last_refill_tsc : 0;
    uint64_t elapsed_ms = (elapsed_tsc * 1000) / g_tsc_hz;

    if (elapsed_ms > 0) {
        // Refill tokens based on elapsed time
        for (int i = 0; i < TCPF_MAX; i++) {
            uint32_t refill = (g_config.pps_limits[i] * elapsed_ms) / 1000;
            uint32_t new_tokens = bucket->tokens[i] + refill;
            if (new_tokens > g_config.bucket_capacity[i]) {
                new_tokens = g_config.bucket_capacity[i];
            }
            bucket->tokens[i] = new_tokens;
        }
        bucket->last_refill_tsc = now_tsc;
    }

    // Check and consume token
    bucket->packet_count[cls]++;

    if (bucket->tokens[cls] > 0) {
        bucket->tokens[cls]--;
        lstats->packets_accepted++;
        return TCPF_RATE_ACCEPT;
    }

    // Rate limit exceeded - drop
    lstats->drops[cls]++;

    // Report violation to Layer 4 (feedback queue) if enabled
    if (g_config.report_violations) {
        // Push feedback event for Layer 4 reputation update
        // This will be integrated with shared_memory feedback queue
        // For now, just log the first few
        static uint64_t drop_log_count = 0;
        if (__atomic_fetch_add(&drop_log_count, 1, __ATOMIC_RELAXED) < 10) {
            RTE_LOG(DEBUG, TCPFLAG, "Rate limit exceeded: IP=0x%08x class=%s\n",
                    src_ip, tcp_flag_class_name(cls));
        }
    }

    // Return specific drop reason
    return (enum tcp_flag_rate_result)(TCPF_RATE_DROP_SYN + cls);
}

// ==================== Maintenance ====================

/**
 * Delete the n expired sources a cleanup scan collected (key and position)
 * and hand their positions to the limbo. Each is checked again under the
 * writer lock: since the scan, another lcore may have refreshed it, and the
 * key may have been deleted and added again at another position.
 *
 * @return number of sources deleted
 */
static uint32_t tcpf_delete_expired(const uint32_t *keys, const uint32_t *pos, uint32_t n,
                                    uint64_t now_tsc, uint64_t timeout_tsc) {
    uint32_t retired[TCPF_DELETE_BATCH];
    uint32_t nretired = 0;

    for (uint32_t i = 0; i < n; i++) {
        struct tcp_flag_bucket *bucket = &g_buckets[pos[i]];
        rte_spinlock_lock(&g_wlock);
        if (rte_hash_lookup(g_bucket_hash, &keys[i]) == (int32_t)pos[i] &&
            __atomic_load_n(&bucket->live, __ATOMIC_ACQUIRE) &&
            tcpf_expired(bucket, now_tsc, timeout_tsc)) {
            tcp_flag_rate_seam(TCPF_SEAM_CLEANUP_DELETE);
            // Lookups that find the key from now on leave the bucket alone
            __atomic_store_n(&bucket->live, 0, __ATOMIC_RELEASE);
            if (rte_hash_del_key(g_bucket_hash, &keys[i]) >= 0) {
                retired[nretired++] = pos[i];
            }
        }
        rte_spinlock_unlock(&g_wlock);
    }

    // Out of the hash, but a packet lcore may still use the bucket: the
    // positions wait for the readers' grace period
    tcpf_retire(retired, nretired);
    return nretired;
}

/**
 * Warn, at most once a minute, when deleted positions have waited
 * TCPF_STALL_SEC with none taken back: a registered reader has stopped
 * reporting quiescent states, and they are not reused meanwhile (new
 * sources are accepted untracked once the table is full).
 */
static void tcpf_check_stall(uint64_t now_tsc, uint32_t reclaimed) {
    uint32_t waiting = flow_limbo_waiting(&g_limbo);
    if (waiting == 0 || reclaimed > 0) {
        g_stall_since_tsc = 0;
        return;
    }
    if (g_stall_since_tsc == 0) {
        g_stall_since_tsc = now_tsc;
        return;
    }
    if (now_tsc - g_stall_since_tsc > sec_to_tsc(TCPF_STALL_SEC) &&
        (g_stall_log_tsc == 0 || now_tsc - g_stall_log_tsc > sec_to_tsc(60))) {
        g_stall_log_tsc = now_tsc;
        RTE_LOG(WARNING, TCPFLAG,
                "%u deleted positions wait for a quiescent report (%lu ms): a registered "
                "reader has stopped reporting, and they are not reused\n",
                waiting, (unsigned long)((now_tsc - g_stall_since_tsc) * 1000 / g_tsc_hz));
    }
}

uint32_t tcp_flag_rate_cleanup_expired(void) {
    if (!g_initialized || !g_config.enabled) {
        return 0;
    }

    // Positions deleted by earlier passes whose grace period is over go
    // back to the hash (an add that finds the table full takes them too)
    uint32_t reclaimed = tcpf_reclaim_all();

    uint64_t now_tsc = rte_rdtsc();
    uint64_t timeout_tsc = sec_to_tsc((uint64_t)g_config.cleanup_interval_sec * 2);
    tcp_flag_rate_seam(TCPF_SEAM_CLEANUP_SCAN);

    uint32_t cleaned = 0;
    uint32_t iter = 0;
    const void *key;
    void *data;
    int32_t pos;
    uint32_t keys[TCPF_DELETE_BATCH];
    uint32_t positions[TCPF_DELETE_BATCH];
    uint32_t n = 0;

    // rte_hash_iterate returns the position (index) as its return value.
    // The data pointer is NOT valid since we used rte_hash_add_key() (not _data).
    // Collect expired sources (the key value and its position) and delete
    // them a batch at a time: each delete takes the writer lock on its own,
    // so new sources on other lcores never wait for a whole batch.
    while ((pos = rte_hash_iterate(g_bucket_hash, &key, &data, &iter)) >= 0) {
        if ((uint32_t)pos >= g_max_key_id) {
            continue;
        }

        struct tcp_flag_bucket *bucket = &g_buckets[pos];
        if (__atomic_load_n(&bucket->live, __ATOMIC_ACQUIRE) &&
            tcpf_expired(bucket, now_tsc, timeout_tsc)) {
            keys[n] = *(const uint32_t *)key;
            positions[n] = (uint32_t)pos;
            if (++n == TCPF_DELETE_BATCH) {
                cleaned += tcpf_delete_expired(keys, positions, n, now_tsc, timeout_tsc);
                n = 0;
            }
        }
    }
    cleaned += tcpf_delete_expired(keys, positions, n, now_tsc, timeout_tsc);

    // With no reader registered, what this pass deleted is free at once
    reclaimed += tcpf_reclaim_all();
    tcpf_check_stall(now_tsc, reclaimed);

    g_cleanups_performed++;
    g_last_cleanup_tsc = now_tsc;

    if (cleaned > 0) {
        RTE_LOG(DEBUG, TCPFLAG, "Cleanup: removed %u expired entries\n", cleaned);
    }

    return cleaned;
}

// ==================== Statistics ====================

void tcp_flag_rate_get_stats(struct tcp_flag_rate_stats *stats) {
    if (!stats) return;

    memset(stats, 0, sizeof(*stats));

    // Aggregate per-lcore stats
    for (unsigned int i = 0; i < RTE_MAX_LCORE; i++) {
        stats->packets_checked += g_lcore_stats[i].packets_checked;
        stats->packets_accepted += g_lcore_stats[i].packets_accepted;
        stats->table_full += g_lcore_stats[i].table_full;
        for (int j = 0; j < TCPF_MAX; j++) {
            stats->drops_per_class[j] += g_lcore_stats[i].drops[j];
        }
    }

    // Get current entry count from hash
    if (g_bucket_hash) {
        stats->current_entries = rte_hash_count(g_bucket_hash);
        stats->positions_waiting = flow_limbo_waiting(&g_limbo);
    }

    stats->cleanups_performed = g_cleanups_performed;
}

void tcp_flag_rate_print_stats(void) {
    struct tcp_flag_rate_stats stats;
    tcp_flag_rate_get_stats(&stats);

    printf("=== TCP Flag Rate Limiter Statistics ===\n");
    printf("Enabled: %s\n", g_config.enabled ? "yes" : "no");
    printf("Packets checked:  %lu\n", stats.packets_checked);
    printf("Packets accepted: %lu\n", stats.packets_accepted);
    printf("Current entries:  %lu / %u\n", stats.current_entries, g_config.max_entries);
    printf("Cleanups:         %lu\n", stats.cleanups_performed);
    printf("\nDrops per flag class:\n");

    for (int i = 0; i < TCPF_MAX; i++) {
        printf("  %-8s: %10lu drops (limit: %6u pps)\n",
               tcp_flag_class_name((enum tcp_flag_class)i),
               stats.drops_per_class[i],
               g_config.pps_limits[i]);
    }
}

void tcp_flag_rate_reset_stats(void) {
    for (unsigned int i = 0; i < RTE_MAX_LCORE; i++) {
        memset(&g_lcore_stats[i], 0, sizeof(g_lcore_stats[i]));
    }
    g_cleanups_performed = 0;
}

// ==================== Runtime Configuration ====================

int tcp_flag_rate_set_limit(enum tcp_flag_class flag_class, uint32_t pps_limit) {
    if (flag_class >= TCPF_MAX) {
        return -1;
    }

    g_config.pps_limits[flag_class] = pps_limit;
    g_config.bucket_capacity[flag_class] = pps_limit * 2;

    RTE_LOG(INFO, TCPFLAG, "Updated %s limit to %u pps\n",
            tcp_flag_class_name(flag_class), pps_limit);

    return 0;
}

bool tcp_flag_rate_is_enabled(void) {
    return g_initialized && g_config.enabled;
}

int32_t tcp_flag_rate_position(uint32_t src_ip) {
    if (!g_initialized || !g_bucket_hash) {
        return -1;
    }
    int32_t pos = rte_hash_lookup(g_bucket_hash, &src_ip);
    return pos >= 0 ? pos : -1;
}

// ==================== Name Helpers ====================

const char* tcp_flag_class_name(enum tcp_flag_class cls) {
    static const char *names[] = {
        "SYN", "SYN-ACK", "ACK", "RST", "FIN", "PSH", "URG", "OTHER"
    };
    return (cls < TCPF_MAX) ? names[cls] : "UNKNOWN";
}

const char* tcp_flag_rate_result_name(enum tcp_flag_rate_result result) {
    static const char *names[] = {
        "ACCEPT",
        "DROP_SYN", "DROP_SYN_ACK", "DROP_ACK", "DROP_RST",
        "DROP_FIN", "DROP_PSH", "DROP_URG", "DROP_OTHER",
        "ERROR"
    };
    return (result <= TCPF_RATE_ERROR) ? names[result] : "UNKNOWN";
}
