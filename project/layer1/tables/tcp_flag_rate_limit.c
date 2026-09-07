#include "tcp_flag_rate_limit.h"
#include "../config/layer1_config.h"
#include "../interlayer/shared_memory.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_atomic.h>
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
 */
struct tcp_flag_bucket {
    uint32_t src_ip;                        // Source IP (network byte order)
    uint64_t last_refill_tsc;               // Last refill timestamp (TSC)
    uint32_t tokens[TCPF_MAX];              // Available tokens per class
    uint32_t packet_count[TCPF_MAX];        // Packets seen per class (for stats)
    uint64_t first_seen_tsc;                // When this IP first appeared
    uint64_t last_seen_tsc;                 // Last packet from this IP
} __rte_cache_aligned;

// ==================== Global State ====================

static struct rte_hash *g_bucket_hash = NULL;
static struct tcp_flag_bucket *g_buckets = NULL;
static struct tcp_flag_rate_config g_config;
static uint64_t g_tsc_hz = 0;
static bool g_initialized = false;

// Per-lcore statistics (no atomics in fast path)
struct tcp_flag_lcore_stats {
    uint64_t packets_checked;
    uint64_t packets_accepted;
    uint64_t drops[TCPF_MAX];
    uint64_t _pad[5];
} __rte_cache_aligned;

static struct tcp_flag_lcore_stats g_lcore_stats[RTE_MAX_LCORE];

// Global cleanup tracking
static uint64_t g_last_cleanup_tsc = 0;
static uint64_t g_cleanups_performed = 0;

// ==================== Helper Functions ====================

static inline uint64_t ms_to_tsc(uint64_t ms) {
    return (ms * g_tsc_hz) / 1000;
}

static inline uint64_t sec_to_tsc(uint64_t sec) {
    return sec * g_tsc_hz;
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

    // Allocate bucket array
    size_t bucket_size = sizeof(struct tcp_flag_bucket) * g_config.max_entries;
    g_buckets = rte_zmalloc("tcp_flag_buckets", bucket_size, RTE_CACHE_LINE_SIZE);
    if (!g_buckets) {
        RTE_LOG(ERR, TCPFLAG, "Failed to allocate bucket array (%zu bytes)\n", bucket_size);
        return -1;
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
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
    };

    g_bucket_hash = rte_hash_create(&hash_params);
    if (!g_bucket_hash) {
        RTE_LOG(ERR, TCPFLAG, "Failed to create hash table\n");
        rte_free(g_buckets);
        g_buckets = NULL;
        return -1;
    }

    // Initialize per-lcore stats
    memset(g_lcore_stats, 0, sizeof(g_lcore_stats));

    g_last_cleanup_tsc = rte_rdtsc();
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

    g_initialized = false;
    RTE_LOG(INFO, TCPFLAG, "TCP flag rate limiting cleaned up\n");
}

// ==================== Rate Check (Hot Path) ====================

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

    if (idx < 0) {
        // New IP - try to add
        idx = rte_hash_add_key(g_bucket_hash, &src_ip);
        if (idx < 0) {
            // Hash full - fail CLOSED (drop) to prevent bypass during floods
            lstats->drops[cls]++;
            return (enum tcp_flag_rate_result)(TCPF_RATE_DROP_SYN + cls);
        }

        bucket = &g_buckets[idx];

        // Only initialize if not already claimed by another lcore.
        // rte_hash_add_key returns existing index if key already exists.
        // Use CAS on src_ip to detect if another lcore beat us.
        uint32_t expected_ip = 0;
        if (__atomic_compare_exchange_n(&bucket->src_ip, &expected_ip, src_ip,
                                        false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ||
            expected_ip == src_ip) {
            // We won the init, or same IP already set -- safe to initialize only if we won
            if (expected_ip == 0) {
                bucket->first_seen_tsc = now_tsc;
                bucket->last_refill_tsc = now_tsc;
                for (int i = 0; i < TCPF_MAX; i++) {
                    bucket->tokens[i] = g_config.bucket_capacity[i];
                    bucket->packet_count[i] = 0;
                }
            }
        }
        // If different IP in slot (hash collision via add_key returning existing),
        // just use the bucket as-is -- benign
    } else {
        bucket = &g_buckets[idx];
    }

    bucket->last_seen_tsc = now_tsc;

    // TF2 NOTE: Token bucket fields accessed without atomics. This relies on RSS
    // hashing same src_ip to same lcore. If not guaranteed, worst case is slightly
    // inaccurate rate limiting (double refill or double consume). Acceptable trade-off
    // vs cost of atomics on every packet.

    // Token bucket refill
    uint64_t elapsed_tsc = now_tsc - bucket->last_refill_tsc;
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

uint32_t tcp_flag_rate_cleanup_expired(void) {
    if (!g_initialized || !g_config.enabled) {
        return 0;
    }

    uint64_t now_tsc = rte_rdtsc();
    uint64_t timeout_tsc = sec_to_tsc(g_config.cleanup_interval_sec * 2);

    uint32_t cleaned = 0;
    uint32_t iter = 0;
    const void *key;
    void *data;
    int32_t pos;

    // rte_hash_iterate returns the position (index) as its return value.
    // The data pointer is NOT valid since we used rte_hash_add_key() (not _data).
    while ((pos = rte_hash_iterate(g_bucket_hash, &key, &data, &iter)) >= 0) {
        if ((uint32_t)pos >= g_config.max_entries) {
            continue;
        }

        struct tcp_flag_bucket *bucket = &g_buckets[pos];

        // Clear bucket BEFORE deleting key, so data-path sees zeroed
        // data if it races with cleanup (zeroed bucket = full tokens = accept).
        if (now_tsc - bucket->last_seen_tsc > timeout_tsc) {
            memset(bucket, 0, sizeof(*bucket));
            rte_hash_del_key(g_bucket_hash, key);
            cleaned++;
        }
    }

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
        for (int j = 0; j < TCPF_MAX; j++) {
            stats->drops_per_class[j] += g_lcore_stats[i].drops[j];
        }
    }

    // Get current entry count from hash
    if (g_bucket_hash) {
        stats->current_entries = rte_hash_count(g_bucket_hash);
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
