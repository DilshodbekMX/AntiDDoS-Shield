/**
 * @file src_ip_stats.c
 * @brief Per-Source-IP Statistics Implementation
 */

#include "src_ip_stats.h"
#include "../tables/flow_table_internal.h"
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>
#include <string.h>

#define RTE_LOGTYPE_SRCIP RTE_LOGTYPE_USER1

// ==================== Global State ====================

static struct rte_hash *ip_hash = NULL;
static struct src_ip_entry *entries = NULL;
static uint32_t entries_count = 0;  // Positions are below this (one entry each)
static struct src_ip_stats_table table_stats;
static bool initialized = false;
static uint64_t tsc_hz = 0;  // TSC frequency for time conversion

// Every writer of ip_hash (each add, each delete and each release of a
// deleted source's position, from any lcore or thread) holds this lock;
// lookups do not take it. RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY makes readers
// safe against one writer at a time, not writers against each other.
// RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD is not used: its positions run past
// the table's entries (by the per-lcore slot caches), and those caches are
// indexed by rte_lcore_id(), which faults on non-EAL threads.
static rte_spinlock_t ip_wlock = RTE_SPINLOCK_INITIALIZER;

// The control-path functions hold this lock (taken before ip_wlock, never
// after): the release of deleted entries happens only under it, so none of
// them meets an entry being cleared.
static rte_spinlock_t ip_ctl_lock = RTE_SPINLOCK_INITIALIZER;

// Deleted sources' positions waiting for the readers' grace period. The
// hash keeps a deleted key's position allocated
// (RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL) because a packet lcore may still
// update its entry after a lookup made before the delete; it is cleared and
// released once every registered flow table reader has reported a
// quiescent state since the delete. Each position is in one place at a
// time (the hash's free slots, a live key, or this limbo), so the limbo
// never refuses one.
static struct flow_limbo ip_limbo;

// Rate limiting for new entry creation (prevents hash explosion under random IP attacks)
// (updated under ip_wlock)
#define MAX_NEW_ENTRIES_PER_SEC 10000  // Max 10K new IPs tracked per second
static uint64_t new_entry_window_start = 0;
static uint32_t new_entries_this_window = 0;

// ==================== Helper Functions ====================

// Fast time using DPDK TSC (no syscall)
static inline uint64_t get_time_ns(void) {
    uint64_t cycles = rte_get_tsc_cycles();
    // Convert cycles to nanoseconds: cycles * 1e9 / hz. The product
    // overflows 64 bits once the TSC passes about 1.8e10 (seconds after
    // boot), and the clock then wraps every few seconds: convert whole
    // seconds and the remainder apart
    return (cycles / tsc_hz) * 1000000000ULL + ((cycles % tsc_hz) * 1000000000ULL) / tsc_hz;
}

// Test seam (see src_ip_stats.h): this weak default does nothing
__attribute__((weak)) void src_ip_stats_seam(enum src_ip_stats_seam_point point) {
    (void)point;
}

bool src_ip_stats_writer_lock_held(void) {
    return rte_spinlock_is_locked(&ip_wlock) != 0;
}

bool src_ip_stats_ctl_lock_held(void) {
    return rte_spinlock_is_locked(&ip_ctl_lock) != 0;
}

/**
 * Clear and release every deleted position whose grace period is over,
 * taking ip_wlock for 256 at a time. Caller holds ip_ctl_lock.
 */
static void srcip_reclaim_locked(void) {
    uint32_t pos[256];
    uint32_t n;

    do {
        rte_spinlock_lock(&ip_wlock);
        n = flow_limbo_take(&ip_limbo, pos, RTE_DIM(pos));
        for (uint32_t i = 0; i < n; i++) {
            // No packet lcore updates it any more: the next source at this
            // position starts from a clear entry
            memset(&entries[pos[i]], 0, sizeof(struct src_ip_entry));
            rte_hash_free_key_with_position(ip_hash, (int32_t)pos[i]);
        }
        rte_spinlock_unlock(&ip_wlock);
    } while (n == RTE_DIM(pos));
}

/**
 * Hand n deleted positions to the limbo, which starts their grace period.
 * Caller holds ip_ctl_lock, not ip_wlock.
 */
static void srcip_retire(const uint32_t *pos, uint32_t n) {
    uint32_t refused = flow_limbo_push(&ip_limbo, pos, n);
    if (unlikely(refused > 0)) {
        // Only without the readers' quiescent-state variable: release them
        // at once rather than lose them
        RTE_LOG(ERR, SRCIP, "Deferred reclamation unavailable: %u deleted positions released at once\n",
                refused);
        rte_spinlock_lock(&ip_wlock);
        for (uint32_t i = n - refused; i < n; i++) {
            memset(&entries[pos[i]], 0, sizeof(struct src_ip_entry));
            rte_hash_free_key_with_position(ip_hash, (int32_t)pos[i]);
        }
        rte_spinlock_unlock(&ip_wlock);
    }
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

    // Create hash table for IP lookup
    struct rte_hash_parameters hash_params = {
        .name = "src_ip_hash",
        .entries = MAX_SRC_IP_ENTRIES,
        .key_len = sizeof(uint32_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        // Writers are serialized by ip_wlock; a deleted key keeps its
        // position until its grace period is over (see ip_limbo)
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                      RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL,
    };

    ip_hash = rte_hash_create(&hash_params);
    if (ip_hash == NULL) {
        RTE_LOG(ERR, SRCIP, "Failed to create source IP hash table\n");
        return -1;
    }

    // Allocate entry array: one entry per position the hash can hand out
    int32_t max_key_id = rte_hash_max_key_id(ip_hash);
    entries_count = max_key_id > 0 ? (uint32_t)max_key_id : 0;
    entries = entries_count ? rte_zmalloc("src_ip_entries",
                                          sizeof(struct src_ip_entry) * entries_count,
                                          RTE_CACHE_LINE_SIZE) : NULL;
    if (entries == NULL ||
        flow_limbo_init(&ip_limbo, entries_count, "src_ip_limbo") != 0 ||
        flow_table_readers() == NULL) {
        RTE_LOG(ERR, SRCIP, "Failed to allocate source IP entries\n");
        flow_limbo_free(&ip_limbo);
        rte_free(entries);
        entries = NULL;
        entries_count = 0;
        rte_hash_free(ip_hash);
        ip_hash = NULL;
        return -1;
    }
    rte_spinlock_init(&ip_wlock);
    rte_spinlock_init(&ip_ctl_lock);

    // Initialize table stats
    memset(&table_stats, 0, sizeof(table_stats));
    table_stats.max_entries = MAX_SRC_IP_ENTRIES;
    table_stats.last_cleanup_ns = get_time_ns();
    new_entry_window_start = 0;
    new_entries_this_window = 0;

    initialized = true;

    RTE_LOG(INFO, SRCIP, "Source IP stats initialized:\n");
    RTE_LOG(INFO, SRCIP, "  Max entries: %u (%lu MB)\n",
            MAX_SRC_IP_ENTRIES,
            (entries_count * sizeof(struct src_ip_entry)) / (1024 * 1024));
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

    // The table is gone: positions still waiting go with it
    flow_limbo_free(&ip_limbo);
    entries_count = 0;

    initialized = false;
    RTE_LOG(INFO, SRCIP, "Source IP stats cleanup complete\n");
}

bool src_ip_stats_is_initialized(void) {
    return initialized;
}

uint32_t src_ip_stats_capacity(void) {
    return initialized ? entries_count : 0;
}

uint32_t src_ip_stats_max_position(void) {
    if (!initialized) return 0;
    int32_t max_key_id = rte_hash_max_key_id(ip_hash);
    return max_key_id > 0 ? (uint32_t)max_key_id : 0;
}

uint32_t src_ip_stats_positions_waiting(void) {
    return initialized ? flow_limbo_waiting(&ip_limbo) : 0;
}

// ==================== Update API ====================

/**
 * Add a source the lockless lookup missed and set up its entry, under the
 * writer lock. Another lcore may have added it since that lookup: its
 * position is then returned as it is (setting the entry up again would
 * wipe that lcore's counts).
 *
 * @return the source's position, or a negative value if the source is not
 *         tracked (new-entry rate limit, or table full)
 */
static int32_t srcip_add(uint32_t src_ip, uint64_t now_ns) {
    rte_spinlock_lock(&ip_wlock);
    int32_t ret = rte_hash_lookup(ip_hash, &src_ip);
    if (ret < 0) {
        // New entry - check rate limit first
        // Reset window if needed
        if (now_ns - new_entry_window_start >= 1000000000ULL) {
            new_entry_window_start = now_ns;
            new_entries_this_window = 0;
        }

        // Rate limit new entries to prevent hash explosion
        // (Hash table full - don't do expensive cleanup in fast path)
        if (new_entries_this_window < MAX_NEW_ENTRIES_PER_SEC) {
            src_ip_stats_seam(SRCIP_SEAM_ADD);
            ret = rte_hash_add_key(ip_hash, &src_ip);
            if (ret >= 0) {
                new_entries_this_window++;

                // Initialize new entry. It is clear (released clear, or
                // never used) and lookups on other lcores find it from the
                // add on: set the fields that do not start at zero, and
                // leave the counters to their atomic adds.
                struct src_ip_entry *entry = &entries[ret];
                uint64_t clear = 0;
                __atomic_compare_exchange_n(&entry->window_start_ns, &clear, now_ns,
                                            false, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
                __atomic_store_n(&entry->src_ip, src_ip, __ATOMIC_RELAXED);
                __atomic_store_n(&entry->first_seen_ns, now_ns, __ATOMIC_RELAXED);
                __atomic_store_n(&entry->min_pkt_size, 65535, __ATOMIC_RELAXED);
                __atomic_store_n(&entry->min_ttl, 255, __ATOMIC_RELAXED);
                __atomic_fetch_or(&entry->flags, SRC_IP_FLAG_ACTIVE | SRC_IP_FLAG_NEW, __ATOMIC_RELAXED);

                __atomic_fetch_add(&table_stats.entry_count, 1, __ATOMIC_RELAXED);
            }
        }
    }
    rte_spinlock_unlock(&ip_wlock);
    return ret;
}

struct src_ip_entry *src_ip_stats_update(const struct src_pkt_features *features) {
    if (!initialized || !features) return NULL;

    uint64_t now_ns = get_time_ns();
    uint32_t src_ip = features->src_ip;

    __atomic_fetch_add(&table_stats.total_updates, 1, __ATOMIC_RELAXED);

    // Lookup or create entry
    int ret = rte_hash_lookup(ip_hash, &src_ip);

    if (ret < 0) {
        // New entry - add it under the writer lock
        ret = srcip_add(src_ip, now_ns);
        if (ret < 0) {
            return NULL;  // Not tracked: too many new IPs, or table full
        }
    }
    // Existing entry - fast path
    struct src_ip_entry *entry = &entries[ret];

    // Check if we need to rotate window -- use CAS to prevent multi-core race
    uint64_t old_start = __atomic_load_n(&entry->window_start_ns, __ATOMIC_RELAXED);
    if (now_ns > old_start && now_ns - old_start >= SRC_IP_STATS_WINDOW_NS) {
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
            __atomic_fetch_and(&entry->flags, ~(uint32_t)SRC_IP_FLAG_NEW, __ATOMIC_RELAXED);
        }
    }

    // Update counters atomically for multi-core safety
    __atomic_store_n(&entry->last_seen_ns, now_ns, __ATOMIC_RELAXED);
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

    rte_spinlock_lock(&ip_ctl_lock);
    struct src_ip_entry *entry = src_ip_stats_lookup(src_ip);
    if (!entry) {
        rte_spinlock_unlock(&ip_ctl_lock);
        return false;
    }
    src_ip_stats_seam(SRCIP_SEAM_CONTROL);

    // Read with version check for consistency
    uint64_t v1, v2;
    do {
        v1 = __atomic_load_n(&entry->version, __ATOMIC_ACQUIRE);
        memcpy(out, entry, sizeof(struct src_ip_entry));
        v2 = __atomic_load_n(&entry->version, __ATOMIC_ACQUIRE);
    } while (v1 != v2);  // Retry if concurrent modification

    rte_spinlock_unlock(&ip_ctl_lock);
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

    rte_spinlock_lock(&ip_ctl_lock);
    while ((position = rte_hash_iterate(ip_hash, &key, &data, &iter)) >= 0) {
        if (count >= max_count) break;
        if ((uint32_t)position >= entries_count) continue;

        struct src_ip_entry *entry = &entries[position];
        src_ip_stats_seam(SRCIP_SEAM_CONTROL);

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
    rte_spinlock_unlock(&ip_ctl_lock);

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

    rte_spinlock_lock(&ip_ctl_lock);
    while ((position = rte_hash_iterate(ip_hash, &key, &data, &iter)) >= 0) {
        if (count >= max_count) break;
        if ((uint32_t)position >= entries_count) continue;

        struct src_ip_entry *entry = &entries[position];
        src_ip_stats_seam(SRCIP_SEAM_CONTROL);

        if (entry->flags & SRC_IP_FLAG_ATTACKER) {
            memcpy(&out[count], entry, sizeof(struct src_ip_entry));
            count++;
        }
    }
    rte_spinlock_unlock(&ip_ctl_lock);

    return count;
}

// ==================== Action API ====================

void src_ip_stats_set_action(uint32_t src_ip, uint8_t action, uint8_t score) {
    rte_spinlock_lock(&ip_ctl_lock);
    struct src_ip_entry *entry = src_ip_stats_lookup(src_ip);
    if (!entry) {
        rte_spinlock_unlock(&ip_ctl_lock);
        return;
    }
    src_ip_stats_seam(SRCIP_SEAM_CONTROL);

    entry->action = action;
    entry->score = score;

    if (action == POLICY_DROP) {
        __atomic_fetch_or(&entry->flags, SRC_IP_FLAG_BLOCKED, __ATOMIC_RELAXED);
    } else if (action == POLICY_RATE_LIMIT) {
        __atomic_fetch_or(&entry->flags, SRC_IP_FLAG_RATE_LIMITED, __ATOMIC_RELAXED);
    } else if (action == POLICY_CHALLENGE) {
        __atomic_fetch_or(&entry->flags, SRC_IP_FLAG_CHALLENGED, __ATOMIC_RELAXED);
    }

    __atomic_fetch_add(&entry->version, 1, __ATOMIC_RELEASE);
    rte_spinlock_unlock(&ip_ctl_lock);
}

void src_ip_stats_mark_attacker(uint32_t src_ip) {
    rte_spinlock_lock(&ip_ctl_lock);
    struct src_ip_entry *entry = src_ip_stats_lookup(src_ip);
    if (!entry) {
        rte_spinlock_unlock(&ip_ctl_lock);
        return;
    }
    src_ip_stats_seam(SRCIP_SEAM_CONTROL);

    __atomic_fetch_or(&entry->flags, SRC_IP_FLAG_ATTACKER, __ATOMIC_RELAXED);
    __atomic_fetch_add(&entry->version, 1, __ATOMIC_RELEASE);
    rte_spinlock_unlock(&ip_ctl_lock);

    RTE_LOG(DEBUG, SRCIP, "Marked IP %u.%u.%u.%u as attacker\n",
            src_ip & 0xFF, (src_ip >> 8) & 0xFF,
            (src_ip >> 16) & 0xFF, (src_ip >> 24) & 0xFF);
}

void src_ip_stats_mark_trusted(uint32_t src_ip) {
    rte_spinlock_lock(&ip_ctl_lock);
    struct src_ip_entry *entry = src_ip_stats_lookup(src_ip);
    if (!entry) {
        rte_spinlock_unlock(&ip_ctl_lock);
        return;
    }
    src_ip_stats_seam(SRCIP_SEAM_CONTROL);

    __atomic_fetch_or(&entry->flags, SRC_IP_FLAG_TRUSTED, __ATOMIC_RELAXED);
    __atomic_fetch_and(&entry->flags, ~(uint32_t)(SRC_IP_FLAG_ATTACKER | SRC_IP_FLAG_BLOCKED),
                       __ATOMIC_RELAXED);
    __atomic_fetch_add(&entry->version, 1, __ATOMIC_RELEASE);
    rte_spinlock_unlock(&ip_ctl_lock);
}

void src_ip_stats_clear_flags(uint32_t src_ip, uint32_t flags) {
    rte_spinlock_lock(&ip_ctl_lock);
    struct src_ip_entry *entry = src_ip_stats_lookup(src_ip);
    if (!entry) {
        rte_spinlock_unlock(&ip_ctl_lock);
        return;
    }
    src_ip_stats_seam(SRCIP_SEAM_CONTROL);

    __atomic_fetch_and(&entry->flags, ~flags, __ATOMIC_RELAXED);
    __atomic_fetch_add(&entry->version, 1, __ATOMIC_RELEASE);
    rte_spinlock_unlock(&ip_ctl_lock);
}

void src_ip_stats_clear_all(void) {
    if (!initialized || !ip_hash || !entries) return;

    // Delete every source key by key, as the expiry does, rather than reset
    // the hash: packet lcores may be updating entries, and positions that
    // still wait in the limbo would be released twice after a reset
    rte_spinlock_lock(&ip_ctl_lock);
    uint32_t keys[256];
    uint32_t pos[256];
    uint32_t n;
    do {
        n = 0;
        uint32_t iter = 0;
        const void *key;
        void *data;
        int32_t position;
        while (n < RTE_DIM(keys) &&
               (position = rte_hash_iterate(ip_hash, &key, &data, &iter)) >= 0) {
            keys[n] = *(const uint32_t *)key;
            pos[n] = (uint32_t)position;
            n++;
        }
        uint32_t deleted = 0;
        rte_spinlock_lock(&ip_wlock);
        for (uint32_t i = 0; i < n; i++) {
            int32_t p = rte_hash_del_key(ip_hash, &keys[i]);
            if (p >= 0) {
                pos[deleted++] = (uint32_t)p;
            }
        }
        rte_spinlock_unlock(&ip_wlock);
        srcip_retire(pos, deleted);
    } while (n == RTE_DIM(keys));
    srcip_reclaim_locked();

    uint32_t max_ent = table_stats.max_entries;
    memset(&table_stats, 0, sizeof(table_stats));
    table_stats.max_entries = max_ent;
    table_stats.last_cleanup_ns = get_time_ns();
    rte_spinlock_lock(&ip_wlock);
    new_entry_window_start = 0;
    new_entries_this_window = 0;
    rte_spinlock_unlock(&ip_wlock);
    rte_spinlock_unlock(&ip_ctl_lock);
    RTE_LOG(INFO, SRCIP, "Source IP stats cleared (factory reset)\n");
}

// ==================== Maintenance ====================

uint32_t src_ip_stats_expire_old(void) {
    if (!initialized) return 0;

    uint32_t expired = 0;

    rte_spinlock_lock(&ip_ctl_lock);

    // Entries deleted by earlier passes whose grace period is over are
    // cleared and released
    srcip_reclaim_locked();

    uint64_t now_ns = get_time_ns();

    /* Two-pass expiry: collect expired IPs during iteration, then delete.
     * rte_hash_iterate is not safe if the hash is modified mid-iteration
     * (deletions can corrupt the iterator state).  We batch up to 512 IPs
     * per pass and repeat until no more expired entries are found. */
#define EXPIRE_BATCH_SIZE 512
    uint32_t to_delete[EXPIRE_BATCH_SIZE];
    uint32_t positions[EXPIRE_BATCH_SIZE];
    uint32_t batch_count;

    do {
        batch_count = 0;

        uint32_t iter = 0;
        const void *key;
        void *data;
        int32_t position;

        while ((position = rte_hash_iterate(ip_hash, &key, &data, &iter)) >= 0) {
            if ((uint32_t)position >= entries_count) continue;
            struct src_ip_entry *entry = &entries[position];
            // A packet on another lcore may stamp the entry after this
            // pass read its clock (now_ns - last_seen would wrap)
            uint64_t last_seen = __atomic_load_n(&entry->last_seen_ns, __ATOMIC_RELAXED);
            if (last_seen <= now_ns && now_ns - last_seen > SRC_IP_STATS_EXPIRE_NS) {
                to_delete[batch_count] = *(const uint32_t *)key;
                positions[batch_count] = (uint32_t)position;
                batch_count++;
                if (batch_count == EXPIRE_BATCH_SIZE) break;
            }
        }

        // Each is checked again under the writer lock: a packet may have
        // refreshed it since the scan
        uint32_t deleted = 0;
        for (uint32_t i = 0; i < batch_count; i++) {
            struct src_ip_entry *entry = &entries[positions[i]];
            rte_spinlock_lock(&ip_wlock);
            uint64_t last_seen = __atomic_load_n(&entry->last_seen_ns, __ATOMIC_RELAXED);
            if (rte_hash_lookup(ip_hash, &to_delete[i]) == (int32_t)positions[i] &&
                last_seen <= now_ns && now_ns - last_seen > SRC_IP_STATS_EXPIRE_NS) {
                src_ip_stats_seam(SRCIP_SEAM_EXPIRE_DELETE);
                if (rte_hash_del_key(ip_hash, &to_delete[i]) >= 0) {
                    positions[deleted++] = positions[i];
                    __atomic_fetch_sub(&table_stats.entry_count, 1, __ATOMIC_RELAXED);
                    expired++;
                }
            }
            rte_spinlock_unlock(&ip_wlock);
        }
        // Out of the hash, but a packet lcore may still update the entry:
        // it is cleared and released after the readers' grace period
        srcip_retire(positions, deleted);
    } while (batch_count == EXPIRE_BATCH_SIZE);
#undef EXPIRE_BATCH_SIZE

    // With no reader registered, what this pass deleted is free at once
    srcip_reclaim_locked();
    rte_spinlock_unlock(&ip_ctl_lock);

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

    rte_spinlock_lock(&ip_ctl_lock);
    while ((position = rte_hash_iterate(ip_hash, &key, &data, &iter)) >= 0) {
        if ((uint32_t)position >= entries_count) continue;
        struct src_ip_entry *entry = &entries[position];
        src_ip_stats_seam(SRCIP_SEAM_CONTROL);

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
    rte_spinlock_unlock(&ip_ctl_lock);

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

    rte_spinlock_lock(&ip_ctl_lock);
    while ((position = rte_hash_iterate(ip_hash, &key, &data, &iter)) >= 0) {
        if ((uint32_t)position >= entries_count) continue;
        struct src_ip_entry *entry = &entries[position];
        if (entry->flags & SRC_IP_FLAG_ATTACKER) attackers++;
        if (entry->flags & SRC_IP_FLAG_TRUSTED) trusted++;
        if (entry->flags & SRC_IP_FLAG_RATE_LIMITED) rate_limited++;
        if (entry->flags & SRC_IP_FLAG_BLOCKED) blocked++;
    }
    rte_spinlock_unlock(&ip_ctl_lock);

    printf("  Attackers: %u\n", attackers);
    printf("  Trusted: %u\n", trusted);
    printf("  Rate limited: %u\n", rate_limited);
    printf("  Blocked: %u\n", blocked);
}
