/**
 * @file src_ip_stats.c
 * @brief Per-Source-IP Statistics Implementation
 */

#include "src_ip_stats.h"
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <string.h>

#define RTE_LOGTYPE_SRCIP RTE_LOGTYPE_USER1

// ==================== Global State ====================

static struct rte_hash *ip_hash = NULL;
static struct src_ip_entry *entries = NULL;
static struct src_ip_stats_table table_stats;
static bool initialized = false;
static uint64_t tsc_hz = 0;  // TSC frequency for time conversion

// Rate limiting for new entry creation (prevents hash explosion under random IP attacks)
#define MAX_NEW_ENTRIES_PER_SEC 10000  // Max 10K new IPs tracked per second
static uint64_t new_entry_window_start = 0;
static uint32_t new_entries_this_window = 0;

// ==================== Helper Functions ====================

// Fast time using DPDK TSC (no syscall)
static inline uint64_t get_time_ns(void) {
    uint64_t cycles = rte_get_tsc_cycles();
    // Convert cycles to nanoseconds: cycles * 1e9 / hz
    // Use pre-computed hz to avoid division in fast path
    return (cycles * 1000000000ULL) / tsc_hz;
}

// ==================== Initialization ====================

int src_ip_stats_init(void) {
    if (initialized) {
        RTE_LOG(WARNING, SRCIP, "Source IP stats already initialized\n");
        return 0;
    }

    // Get TSC frequency for time conversion (must be done before get_time_ns())
    tsc_hz = rte_get_tsc_hz();
    if (tsc_hz == 0) {
        RTE_LOG(ERR, SRCIP, "Failed to get TSC frequency\n");
        return -1;
    }

    // Allocate entry array
    entries = rte_zmalloc("src_ip_entries",
                          sizeof(struct src_ip_entry) * MAX_SRC_IP_ENTRIES,
                          RTE_CACHE_LINE_SIZE);
    if (entries == NULL) {
        RTE_LOG(ERR, SRCIP, "Failed to allocate source IP entries\n");
        return -1;
    }

    // Create hash table for IP lookup
    struct rte_hash_parameters hash_params = {
        .name = "src_ip_hash",
        .entries = MAX_SRC_IP_ENTRIES,
        .key_len = sizeof(uint32_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                      RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD,
    };

    ip_hash = rte_hash_create(&hash_params);
    if (ip_hash == NULL) {
        RTE_LOG(ERR, SRCIP, "Failed to create source IP hash table\n");
        rte_free(entries);
        entries = NULL;
        return -1;
    }

    // Initialize table stats
    memset(&table_stats, 0, sizeof(table_stats));
    table_stats.max_entries = MAX_SRC_IP_ENTRIES;
    table_stats.last_cleanup_ns = get_time_ns();

    initialized = true;

    RTE_LOG(INFO, SRCIP, "Source IP stats initialized:\n");
    RTE_LOG(INFO, SRCIP, "  Max entries: %u (%lu MB)\n",
            MAX_SRC_IP_ENTRIES,
            (MAX_SRC_IP_ENTRIES * sizeof(struct src_ip_entry)) / (1024 * 1024));
    RTE_LOG(INFO, SRCIP, "  Entry size: %lu bytes\n", sizeof(struct src_ip_entry));

    return 0;
}

void src_ip_stats_cleanup(void) {
    if (!initialized) return;

    if (ip_hash) {
        rte_hash_free(ip_hash);
        ip_hash = NULL;
    }

    if (entries) {
        rte_free(entries);
        entries = NULL;
    }

    initialized = false;
    RTE_LOG(INFO, SRCIP, "Source IP stats cleanup complete\n");
}

bool src_ip_stats_is_initialized(void) {
    return initialized;
}

// ==================== Update API ====================

struct src_ip_entry *src_ip_stats_update(const struct src_pkt_features *features) {
    if (!initialized || !features) return NULL;

    uint64_t now_ns = get_time_ns();
    uint32_t src_ip = features->src_ip;

    __atomic_fetch_add(&table_stats.total_updates, 1, __ATOMIC_RELAXED);

    // Lookup or create entry
    int ret = rte_hash_lookup(ip_hash, &src_ip);
    struct src_ip_entry *entry;

    if (ret >= 0) {
        // Existing entry - fast path
        entry = &entries[ret];
    } else {
        // New entry - check rate limit first
        // Reset window if needed
        if (now_ns - new_entry_window_start >= 1000000000ULL) {
            new_entry_window_start = now_ns;
            new_entries_this_window = 0;
        }

        // Rate limit new entries to prevent hash explosion
        if (new_entries_this_window >= MAX_NEW_ENTRIES_PER_SEC) {
            return NULL;  // Skip this IP - too many new IPs
        }

        // Add to hash
        ret = rte_hash_add_key(ip_hash, &src_ip);
        if (ret < 0) {
            // Hash table full - don't do expensive cleanup in fast path
            return NULL;
        }

        entry = &entries[ret];
        new_entries_this_window++;

        // Initialize new entry
        memset(entry, 0, sizeof(struct src_ip_entry));
        entry->src_ip = src_ip;
        entry->first_seen_ns = now_ns;
        entry->window_start_ns = now_ns;
        entry->min_pkt_size = 65535;
        entry->min_ttl = 255;
        entry->flags = SRC_IP_FLAG_ACTIVE | SRC_IP_FLAG_NEW;

        __atomic_fetch_add(&table_stats.entry_count, 1, __ATOMIC_RELAXED);
    }

    // Check if we need to rotate window -- use CAS to prevent multi-core race
    uint64_t old_start = __atomic_load_n(&entry->window_start_ns, __ATOMIC_RELAXED);
    if (now_ns - old_start >= SRC_IP_STATS_WINDOW_NS) {
        // CAS ensures only one core performs the rotation
        if (__atomic_compare_exchange_n(&entry->window_start_ns, &old_start,
                                         now_ns, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            // Calculate rates from previous window (atomic loads -- other lcores still counting)
            double window_sec = (now_ns - old_start) / 1000000000.0;
            if (window_sec > 0) {
                uint64_t pkts = __atomic_load_n(&entry->packets_window, __ATOMIC_RELAXED);
                uint64_t bytes = __atomic_load_n(&entry->bytes_window, __ATOMIC_RELAXED);
                entry->pps_current = (uint32_t)(pkts / window_sec);
                entry->bps_current = (uint32_t)(bytes / window_sec);
            }

            // Reset window counters (we won the CAS, safe to reset)
            __atomic_store_n(&entry->packets_window, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&entry->bytes_window, 0, __ATOMIC_RELAXED);
            entry->flows_window = 0;
            entry->tcp_pkt_count = 0;
            entry->udp_pkt_count = 0;
            entry->icmp_pkt_count = 0;
            entry->other_pkt_count = 0;
            entry->syn_count = 0;
            entry->syn_ack_count = 0;
            entry->ack_count = 0;
            entry->rst_count = 0;
            entry->fin_count = 0;
            entry->flags &= ~SRC_IP_FLAG_NEW;
        }
    }

    // Update counters atomically for multi-core safety
    entry->last_seen_ns = now_ns;
    __atomic_fetch_add(&entry->packets_window, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&entry->bytes_window, features->pkt_size, __ATOMIC_RELAXED);
    __atomic_fetch_add(&entry->packets_total, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&entry->bytes_total, features->pkt_size, __ATOMIC_RELAXED);

    if (features->is_new_flow) {
        __atomic_fetch_add(&entry->flows_window, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&entry->flows_total, 1, __ATOMIC_RELAXED);
    }

    // Protocol distribution
    switch (features->protocol) {
        case 6:   // TCP
            __atomic_fetch_add(&entry->tcp_pkt_count, 1, __ATOMIC_RELAXED);
            break;
        case 17:  // UDP
            __atomic_fetch_add(&entry->udp_pkt_count, 1, __ATOMIC_RELAXED);
            break;
        case 1:   // ICMP
            __atomic_fetch_add(&entry->icmp_pkt_count, 1, __ATOMIC_RELAXED);
            break;
        default:
            __atomic_fetch_add(&entry->other_pkt_count, 1, __ATOMIC_RELAXED);
            break;
    }

    // TCP flags (if TCP)
    if (features->protocol == 6) {
        uint8_t flags = features->tcp_flags;

        // SYN only (no ACK)
        if ((flags & 0x02) && !(flags & 0x10)) {
            __atomic_fetch_add(&entry->syn_count, 1, __ATOMIC_RELAXED);
        }
        // SYN-ACK
        if ((flags & 0x02) && (flags & 0x10)) {
            __atomic_fetch_add(&entry->syn_ack_count, 1, __ATOMIC_RELAXED);
        }
        // ACK only
        if ((flags & 0x10) && !(flags & 0x02)) {
            __atomic_fetch_add(&entry->ack_count, 1, __ATOMIC_RELAXED);
        }
        // RST
        if (flags & 0x04) {
            __atomic_fetch_add(&entry->rst_count, 1, __ATOMIC_RELAXED);
        }
        // FIN
        if (flags & 0x01) {
            __atomic_fetch_add(&entry->fin_count, 1, __ATOMIC_RELAXED);
        }

        // TCP options fingerprint (last-writer-wins for scalar fields is acceptable)
        if (features->tcp_mss > 0) {
            __atomic_store_n(&entry->tcp_mss_value, features->tcp_mss, __ATOMIC_RELAXED);
            __atomic_fetch_or(&entry->tcp_options_seen, TCP_OPT_MSS, __ATOMIC_RELAXED);
        }
        if (features->tcp_wscale != 0xFF) {
            __atomic_store_n(&entry->tcp_wscale_value, features->tcp_wscale, __ATOMIC_RELAXED);
            __atomic_fetch_or(&entry->tcp_options_seen, TCP_OPT_WSCALE, __ATOMIC_RELAXED);
        }
        __atomic_fetch_or(&entry->tcp_options_seen, features->tcp_options, __ATOMIC_RELAXED);
    }

    // Packet size range (CAS loops for atomic min/max)
    uint16_t old_min = __atomic_load_n(&entry->min_pkt_size, __ATOMIC_RELAXED);
    while (features->pkt_size < old_min) {
        if (__atomic_compare_exchange_n(&entry->min_pkt_size, &old_min,
                                        features->pkt_size, true,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            break;
    }
    uint16_t old_max = __atomic_load_n(&entry->max_pkt_size, __ATOMIC_RELAXED);
    while (features->pkt_size > old_max) {
        if (__atomic_compare_exchange_n(&entry->max_pkt_size, &old_max,
                                        features->pkt_size, true,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            break;
    }

    // Rolling average packet size (CAS loop for atomic EMA update)
    uint16_t old_avg = __atomic_load_n(&entry->avg_pkt_size, __ATOMIC_RELAXED);
    uint16_t new_avg;
    do {
        if (old_avg == 0) {
            new_avg = features->pkt_size;
        } else {
            // avg = 0.9 * avg + 0.1 * new (using fixed point: 230/256 + 26/256)
            new_avg = (uint16_t)((old_avg * 230 + features->pkt_size * 26) >> 8);
        }
    } while (!__atomic_compare_exchange_n(&entry->avg_pkt_size, &old_avg, new_avg,
                                          true, __ATOMIC_RELAXED, __ATOMIC_RELAXED));

    // TTL range (CAS loops for atomic min/max)
    uint8_t old_min_ttl = __atomic_load_n(&entry->min_ttl, __ATOMIC_RELAXED);
    while (features->ttl < old_min_ttl) {
        if (__atomic_compare_exchange_n(&entry->min_ttl, &old_min_ttl,
                                        features->ttl, true,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            break;
    }
    uint8_t old_max_ttl = __atomic_load_n(&entry->max_ttl, __ATOMIC_RELAXED);
    while (features->ttl > old_max_ttl) {
        if (__atomic_compare_exchange_n(&entry->max_ttl, &old_max_ttl,
                                        features->ttl, true,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            break;
    }

    // Increment version for readers
    __atomic_fetch_add(&entry->version, 1, __ATOMIC_RELEASE);

    return entry;
}

// ==================== Lookup API ====================

struct src_ip_entry *src_ip_stats_lookup(uint32_t src_ip) {
    if (!initialized) return NULL;

    __atomic_fetch_add(&table_stats.total_lookups, 1, __ATOMIC_RELAXED);

    int ret = rte_hash_lookup(ip_hash, &src_ip);
    if (ret < 0) return NULL;

    return &entries[ret];
}

bool src_ip_stats_snapshot(uint32_t src_ip, struct src_ip_entry *out) {
    if (!initialized || !out) return false;

    struct src_ip_entry *entry = src_ip_stats_lookup(src_ip);
    if (!entry) return false;

    // Read with version check for consistency
    uint64_t v1, v2;
    do {
        v1 = __atomic_load_n(&entry->version, __ATOMIC_ACQUIRE);
        memcpy(out, entry, sizeof(struct src_ip_entry));
        v2 = __atomic_load_n(&entry->version, __ATOMIC_ACQUIRE);
    } while (v1 != v2);  // Retry if concurrent modification

    return true;
}

uint32_t src_ip_stats_snapshot_active(struct src_ip_entry *out, uint32_t max_count) {
    if (!initialized || !out || max_count == 0) return 0;

    uint32_t count = 0;
    uint64_t now_ns = get_time_ns();

    // Iterate through hash table
    uint32_t iter = 0;
    const void *key;
    void *data;
    int32_t position;

    while ((position = rte_hash_iterate(ip_hash, &key, &data, &iter)) >= 0) {
        if (count >= max_count) break;

        struct src_ip_entry *entry = &entries[position];

        // Only include entries with recent activity
        if (entry->flags & SRC_IP_FLAG_ACTIVE &&
            now_ns - entry->last_seen_ns < SRC_IP_STATS_WINDOW_NS * 2) {

            // Snapshot with version check
            uint64_t v1, v2;
            do {
                v1 = __atomic_load_n(&entry->version, __ATOMIC_ACQUIRE);
                memcpy(&out[count], entry, sizeof(struct src_ip_entry));
                v2 = __atomic_load_n(&entry->version, __ATOMIC_ACQUIRE);
            } while (v1 != v2);

            count++;
        }
    }

    return count;
}

uint32_t src_ip_stats_get_top_talkers(struct src_ip_entry *out, uint32_t max_count) {
    if (!initialized || !out || max_count == 0) return 0;

    // Simple approach: collect all active entries, sort by pps
    // For production, use a heap or maintain a sorted list

    struct src_ip_entry *temp = rte_malloc("temp_entries",
                                            sizeof(struct src_ip_entry) * max_count * 4,
                                            0);
    if (!temp) return 0;

    uint32_t total = src_ip_stats_snapshot_active(temp, max_count * 4);

    // Simple selection sort for top N
    for (uint32_t i = 0; i < total && i < max_count; i++) {
        uint32_t max_idx = i;
        for (uint32_t j = i + 1; j < total; j++) {
            if (temp[j].pps_current > temp[max_idx].pps_current) {
                max_idx = j;
            }
        }
        if (max_idx != i) {
            struct src_ip_entry swap = temp[i];
            temp[i] = temp[max_idx];
            temp[max_idx] = swap;
        }
        out[i] = temp[i];
    }

    uint32_t result = (total < max_count) ? total : max_count;
    rte_free(temp);
    return result;
}

uint32_t src_ip_stats_get_attackers(struct src_ip_entry *out, uint32_t max_count) {
    if (!initialized || !out || max_count == 0) return 0;

    uint32_t count = 0;
    uint32_t iter = 0;
    const void *key;
    void *data;
    int32_t position;

    while ((position = rte_hash_iterate(ip_hash, &key, &data, &iter)) >= 0) {
        if (count >= max_count) break;

        struct src_ip_entry *entry = &entries[position];

        if (entry->flags & SRC_IP_FLAG_ATTACKER) {
            memcpy(&out[count], entry, sizeof(struct src_ip_entry));
            count++;
        }
    }

    return count;
}

// ==================== Action API ====================

void src_ip_stats_set_action(uint32_t src_ip, uint8_t action, uint8_t score) {
    struct src_ip_entry *entry = src_ip_stats_lookup(src_ip);
    if (!entry) return;

    entry->action = action;
    entry->score = score;

    if (action == POLICY_DROP) {
        entry->flags |= SRC_IP_FLAG_BLOCKED;
    } else if (action == POLICY_RATE_LIMIT) {
        entry->flags |= SRC_IP_FLAG_RATE_LIMITED;
    } else if (action == POLICY_CHALLENGE) {
        entry->flags |= SRC_IP_FLAG_CHALLENGED;
    }

    __atomic_fetch_add(&entry->version, 1, __ATOMIC_RELEASE);
}

void src_ip_stats_mark_attacker(uint32_t src_ip) {
    struct src_ip_entry *entry = src_ip_stats_lookup(src_ip);
    if (!entry) return;

    entry->flags |= SRC_IP_FLAG_ATTACKER;
    __atomic_fetch_add(&entry->version, 1, __ATOMIC_RELEASE);

    RTE_LOG(DEBUG, SRCIP, "Marked IP %u.%u.%u.%u as attacker\n",
            src_ip & 0xFF, (src_ip >> 8) & 0xFF,
            (src_ip >> 16) & 0xFF, (src_ip >> 24) & 0xFF);
}

void src_ip_stats_mark_trusted(uint32_t src_ip) {
    struct src_ip_entry *entry = src_ip_stats_lookup(src_ip);
    if (!entry) return;

    entry->flags |= SRC_IP_FLAG_TRUSTED;
    entry->flags &= ~(SRC_IP_FLAG_ATTACKER | SRC_IP_FLAG_BLOCKED);
    __atomic_fetch_add(&entry->version, 1, __ATOMIC_RELEASE);
}

void src_ip_stats_clear_flags(uint32_t src_ip, uint32_t flags) {
    struct src_ip_entry *entry = src_ip_stats_lookup(src_ip);
    if (!entry) return;

    entry->flags &= ~flags;
    __atomic_fetch_add(&entry->version, 1, __ATOMIC_RELEASE);
}

void src_ip_stats_clear_all(void) {
    if (!initialized || !ip_hash || !entries) return;
    rte_hash_reset(ip_hash);
    memset(entries, 0, MAX_SRC_IP_ENTRIES * sizeof(struct src_ip_entry));
    uint32_t max_ent = table_stats.max_entries;
    memset(&table_stats, 0, sizeof(table_stats));
    table_stats.max_entries = max_ent;
    table_stats.last_cleanup_ns = get_time_ns();
    new_entry_window_start = 0;
    new_entries_this_window = 0;
    RTE_LOG(INFO, SRCIP, "Source IP stats cleared (factory reset)\n");
}

// ==================== Maintenance ====================

uint32_t src_ip_stats_expire_old(void) {
    if (!initialized) return 0;

    uint64_t now_ns = get_time_ns();
    uint32_t expired = 0;

    /* Two-pass expiry: collect expired IPs during iteration, then delete.
     * rte_hash_iterate is not safe if the hash is modified mid-iteration
     * (deletions can corrupt the iterator state).  We batch up to 512 IPs
     * per pass and repeat until no more expired entries are found. */
#define EXPIRE_BATCH_SIZE 512
    uint32_t to_delete[EXPIRE_BATCH_SIZE];
    uint32_t batch_count;

    do {
        batch_count = 0;

        uint32_t iter = 0;
        const void *key;
        void *data;
        int32_t position;

        while ((position = rte_hash_iterate(ip_hash, &key, &data, &iter)) >= 0) {
            struct src_ip_entry *entry = &entries[position];
            if (now_ns - entry->last_seen_ns > SRC_IP_STATS_EXPIRE_NS) {
                to_delete[batch_count++] = entry->src_ip;
                if (batch_count == EXPIRE_BATCH_SIZE) break;
            }
        }

        for (uint32_t i = 0; i < batch_count; i++) {
            uint32_t src_ip = to_delete[i];
            int32_t pos = rte_hash_del_key(ip_hash, &src_ip);
            if (pos >= 0) {
                entries[pos].flags = 0;
                entries[pos].src_ip = 0;
                __atomic_fetch_sub(&table_stats.entry_count, 1, __ATOMIC_RELAXED);
                expired++;
            }
        }
    } while (batch_count == EXPIRE_BATCH_SIZE);
#undef EXPIRE_BATCH_SIZE

    if (expired > 0) {
        __atomic_fetch_add(&table_stats.total_expired, expired, __ATOMIC_RELAXED);
        table_stats.last_cleanup_ns = now_ns;
        RTE_LOG(DEBUG, SRCIP, "Expired %u source IP entries\n", expired);
    }

    return expired;
}

void src_ip_stats_reset_window(void) {
    if (!initialized) return;

    uint64_t now_ns = get_time_ns();

    uint32_t iter = 0;
    const void *key;
    void *data;
    int32_t position;

    while ((position = rte_hash_iterate(ip_hash, &key, &data, &iter)) >= 0) {
        struct src_ip_entry *entry = &entries[position];

        if (entry->flags & SRC_IP_FLAG_ACTIVE) {
            // Calculate rates before reset
            double window_sec = (now_ns - entry->window_start_ns) / 1000000000.0;
            if (window_sec > 0) {
                entry->pps_current = (uint32_t)(entry->packets_window / window_sec);
                entry->bps_current = (uint32_t)(entry->bytes_window / window_sec);
            }

            // Reset window counters
            entry->packets_window = 0;
            entry->bytes_window = 0;
            entry->flows_window = 0;
            entry->tcp_pkt_count = 0;
            entry->udp_pkt_count = 0;
            entry->icmp_pkt_count = 0;
            entry->other_pkt_count = 0;
            entry->syn_count = 0;
            entry->syn_ack_count = 0;
            entry->ack_count = 0;
            entry->rst_count = 0;
            entry->fin_count = 0;
            entry->window_start_ns = now_ns;
        }
    }

    __atomic_fetch_add(&table_stats.version, 1, __ATOMIC_RELAXED);
}

// ==================== Statistics ====================

void src_ip_stats_get_stats(struct src_ip_stats_table *out) {
    if (!out) return;
    memcpy(out, &table_stats, sizeof(struct src_ip_stats_table));
}

void src_ip_stats_print(void) {
    if (!initialized) {
        printf("Source IP stats not initialized\n");
        return;
    }

    printf("\nSource IP Statistics:\n");
    printf("  Entries: %u / %u\n",
           table_stats.entry_count, table_stats.max_entries);
    printf("  Total updates: %lu\n", table_stats.total_updates);
    printf("  Total lookups: %lu\n", table_stats.total_lookups);
    printf("  Total expired: %lu\n", table_stats.total_expired);

    // Count by flag
    uint32_t attackers = 0, trusted = 0, rate_limited = 0, blocked = 0;

    uint32_t iter = 0;
    const void *key;
    void *data;
    int32_t position;

    while ((position = rte_hash_iterate(ip_hash, &key, &data, &iter)) >= 0) {
        struct src_ip_entry *entry = &entries[position];
        if (entry->flags & SRC_IP_FLAG_ATTACKER) attackers++;
        if (entry->flags & SRC_IP_FLAG_TRUSTED) trusted++;
        if (entry->flags & SRC_IP_FLAG_RATE_LIMITED) rate_limited++;
        if (entry->flags & SRC_IP_FLAG_BLOCKED) blocked++;
    }

    printf("  Attackers: %u\n", attackers);
    printf("  Trusted: %u\n", trusted);
    printf("  Rate limited: %u\n", rate_limited);
    printf("  Blocked: %u\n", blocked);
}
