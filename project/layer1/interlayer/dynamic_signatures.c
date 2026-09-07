/**
 * @file dynamic_signatures.c
 * @brief Dynamic Signature Table Implementation
 */

#include "dynamic_signatures.h"
#include <rte_malloc.h>
#include <rte_spinlock.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <string.h>
#include <time.h>

#define RTE_LOGTYPE_DYNSIG RTE_LOGTYPE_USER7

// ==================== Global State ====================

static struct dynamic_signature_table *sig_table = NULL;
static rte_spinlock_t sig_table_lock = RTE_SPINLOCK_INITIALIZER;
static bool initialized = false;

// Per-lcore statistics for lock-free updates
struct dynsig_lcore_stats {
    uint64_t matches;
    uint64_t drops;
} __rte_cache_aligned;

static struct dynsig_lcore_stats lcore_stats[RTE_MAX_LCORE];

// ==================== Helper Functions ====================

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint32_t allocate_sig_id(void) {
    static uint32_t next_id = 1;
    return __atomic_fetch_add(&next_id, 1, __ATOMIC_RELAXED);
}

// ==================== Signature Matching ====================

/**
 * Check if a packet matches a signature
 */
static inline bool signature_matches(const struct dynamic_signature *sig,
                                     const struct packet_features *pkt) {
    // Protocol check
    if (sig->protocol != 0 && sig->protocol != pkt->protocol) {
        return false;
    }

    // Destination IP check (for protecting specific servers)
    if (sig->dst_ip != 0) {
        if ((pkt->dst_ip & sig->dst_ip_mask) != (sig->dst_ip & sig->dst_ip_mask)) {
            return false;
        }
    }

    // Port checks
    if (!in_range_u16(pkt->dst_port, sig->dst_port_min, sig->dst_port_max)) {
        return false;
    }
    if (!in_range_u16(pkt->src_port, sig->src_port_min, sig->src_port_max)) {
        return false;
    }

    // Packet size check
    if (!in_range_u16(pkt->packet_size, sig->pkt_size_min, sig->pkt_size_max)) {
        return false;
    }

    // TTL check
    if (!in_range_u8(pkt->ttl, sig->ttl_min, sig->ttl_max)) {
        return false;
    }

    // TCP-specific checks
    if (pkt->protocol == 6) {  // TCP
        // TCP flags
        if (!tcp_flags_match(pkt->tcp_flags, sig->tcp_flags_mask, sig->tcp_flags_value)) {
            return false;
        }

        // TCP MSS (if SYN packet and signature specifies MSS)
        if (sig->tcp_mss_min != 0 || sig->tcp_mss_max != 0) {
            if (!in_range_u16(pkt->tcp_mss, sig->tcp_mss_min, sig->tcp_mss_max)) {
                return false;
            }
        }

        // TCP window scale
        if (sig->tcp_wscale_min != 255 || sig->tcp_wscale_max != 255) {
            if (!in_range_u8(pkt->tcp_wscale, sig->tcp_wscale_min, sig->tcp_wscale_max)) {
                return false;
            }
        }

        // TCP window
        if (sig->tcp_window_min != 0 || sig->tcp_window_max != 0) {
            if (!in_range_u16(pkt->tcp_window, sig->tcp_window_min, sig->tcp_window_max)) {
                return false;
            }
        }
    }

    // Payload pattern matching
    if (sig->payload_pattern_len > 0 && pkt->payload_len >= sig->payload_pattern_len) {
        // payload_sample contains first 16 bytes as uint16_t[8]
        // Compare with signature pattern
        uint8_t *pkt_payload = (uint8_t *)pkt->payload_sample;
        int offset = sig->payload_match_offset;

        if (offset + sig->payload_pattern_len <= 16) {
            if (memcmp(pkt_payload + offset, sig->payload_pattern,
                       sig->payload_pattern_len) != 0) {
                return false;
            }
        }
    }

    return true;
}

// ==================== Public API ====================

int dynamic_signatures_init(void) {
    if (initialized) {
        RTE_LOG(WARNING, DYNSIG, "Dynamic signatures already initialized\n");
        return 0;
    }

    // Allocate signature table
    sig_table = rte_zmalloc("dynsig_table",
                            sizeof(struct dynamic_signature_table),
                            RTE_CACHE_LINE_SIZE);
    if (sig_table == NULL) {
        RTE_LOG(ERR, DYNSIG, "Failed to allocate signature table\n");
        return -1;
    }

    // Initialize per-lcore stats
    memset(lcore_stats, 0, sizeof(lcore_stats));

    initialized = true;
    RTE_LOG(INFO, DYNSIG, "Dynamic signatures initialized (max %d signatures)\n",
            MAX_DYNAMIC_SIGNATURES);

    return 0;
}

void dynamic_signatures_cleanup(void) {
    if (!initialized) return;

    rte_spinlock_lock(&sig_table_lock);

    if (sig_table) {
        rte_free(sig_table);
        sig_table = NULL;
    }

    initialized = false;
    rte_spinlock_unlock(&sig_table_lock);

    RTE_LOG(INFO, DYNSIG, "Dynamic signatures cleanup complete\n");
}

enum policy_action dynamic_signatures_check(
    const struct packet_features *features,
    struct dynamic_signature **matched_sig) {

    if (!initialized || sig_table == NULL || sig_table->count == 0) {
        return POLICY_ALLOW;
    }

    unsigned lcore_id = rte_lcore_id();
    uint64_t now_ns = get_time_ns();

    // Iterate through signatures (sorted by priority)
    for (uint32_t i = 0; i < sig_table->count; i++) {
        struct dynamic_signature *sig = &sig_table->entries[i];

        // Skip disabled or expired signatures
        if (!sig->enabled) continue;
        if (sig->expires_ns != 0 && sig->expires_ns < now_ns) continue;

        // Check if packet matches
        if (signature_matches(sig, features)) {
            // Update statistics (lock-free)
            __atomic_fetch_add(&sig->match_count, 1, __ATOMIC_RELAXED);
            __atomic_store_n(&sig->last_match_ns, now_ns, __ATOMIC_RELAXED);

            if (lcore_id < RTE_MAX_LCORE) {
                lcore_stats[lcore_id].matches++;
                if (sig->action == POLICY_DROP) {
                    lcore_stats[lcore_id].drops++;
                }
            }

            if (matched_sig) {
                *matched_sig = sig;
            }

            return (enum policy_action)sig->action;
        }
    }

    return POLICY_ALLOW;
}

int dynamic_signatures_add(const struct dynamic_signature *sig) {
    if (!initialized || sig_table == NULL) {
        return -1;
    }

    rte_spinlock_lock(&sig_table_lock);

    if (sig_table->count >= MAX_DYNAMIC_SIGNATURES) {
        rte_spinlock_unlock(&sig_table_lock);
        RTE_LOG(WARNING, DYNSIG, "Signature table full\n");
        return -1;
    }

    // Find insertion point (sorted by priority, highest first)
    uint32_t insert_idx = sig_table->count;
    for (uint32_t i = 0; i < sig_table->count; i++) {
        if (sig->priority > sig_table->entries[i].priority) {
            insert_idx = i;
            break;
        }
    }

    // Shift entries down
    if (insert_idx < sig_table->count) {
        memmove(&sig_table->entries[insert_idx + 1],
                &sig_table->entries[insert_idx],
                (sig_table->count - insert_idx) * sizeof(struct dynamic_signature));
    }

    // Copy new signature
    memcpy(&sig_table->entries[insert_idx], sig, sizeof(struct dynamic_signature));

    // Assign ID if not set
    if (sig_table->entries[insert_idx].id == 0) {
        sig_table->entries[insert_idx].id = allocate_sig_id();
    }

    // Set creation time if not set
    if (sig_table->entries[insert_idx].created_ns == 0) {
        sig_table->entries[insert_idx].created_ns = get_time_ns();
    }

    sig_table->entries[insert_idx].enabled = 1;
    sig_table->entries[insert_idx].match_count = 0;

    sig_table->count++;
    sig_table->version++;
    sig_table->last_update_ns = get_time_ns();

    uint32_t new_id = sig_table->entries[insert_idx].id;

    rte_spinlock_unlock(&sig_table_lock);

    RTE_LOG(INFO, DYNSIG, "Added signature %u (priority %u, action %d)\n",
            new_id, sig->priority, sig->action);

    return (int)new_id;
}

int dynamic_signatures_remove(uint32_t sig_id) {
    if (!initialized || sig_table == NULL) {
        return -1;
    }

    rte_spinlock_lock(&sig_table_lock);

    int found_idx = -1;
    for (uint32_t i = 0; i < sig_table->count; i++) {
        if (sig_table->entries[i].id == sig_id) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx < 0) {
        rte_spinlock_unlock(&sig_table_lock);
        return -1;
    }

    // Shift entries up
    if ((uint32_t)found_idx < sig_table->count - 1) {
        memmove(&sig_table->entries[found_idx],
                &sig_table->entries[found_idx + 1],
                (sig_table->count - found_idx - 1) * sizeof(struct dynamic_signature));
    }

    sig_table->count--;
    sig_table->version++;
    sig_table->last_update_ns = get_time_ns();

    rte_spinlock_unlock(&sig_table_lock);

    RTE_LOG(INFO, DYNSIG, "Removed signature %u\n", sig_id);
    return 0;
}

void dynamic_signatures_clear_all(void) {
    if (!initialized || sig_table == NULL) return;

    rte_spinlock_lock(&sig_table_lock);

    uint32_t old_count = sig_table->count;
    sig_table->count = 0;
    sig_table->version++;
    sig_table->last_update_ns = get_time_ns();

    rte_spinlock_unlock(&sig_table_lock);

    RTE_LOG(INFO, DYNSIG, "Cleared %u signatures\n", old_count);
}

int dynamic_signatures_cleanup_expired(void) {
    if (!initialized || sig_table == NULL) return 0;

    rte_spinlock_lock(&sig_table_lock);

    uint64_t now_ns = get_time_ns();
    int removed = 0;

    // Iterate backwards to safely remove
    for (int i = (int)sig_table->count - 1; i >= 0; i--) {
        struct dynamic_signature *sig = &sig_table->entries[i];

        if (sig->expires_ns != 0 && sig->expires_ns < now_ns) {
            RTE_LOG(DEBUG, DYNSIG, "Expiring signature %u (matched %lu times)\n",
                    sig->id, sig->match_count);

            // Shift entries up
            if ((uint32_t)i < sig_table->count - 1) {
                memmove(&sig_table->entries[i],
                        &sig_table->entries[i + 1],
                        (sig_table->count - i - 1) * sizeof(struct dynamic_signature));
            }

            sig_table->count--;
            removed++;
        }
    }

    if (removed > 0) {
        sig_table->version++;
        sig_table->last_update_ns = now_ns;
        RTE_LOG(INFO, DYNSIG, "Expired %d signatures\n", removed);
    }

    rte_spinlock_unlock(&sig_table_lock);
    return removed;
}

struct dynamic_signature_table *dynamic_signatures_get_table(void) {
    return sig_table;
}

void dynamic_signatures_get_stats(uint64_t *total_matches,
                                  uint64_t *total_dropped,
                                  uint32_t *active_count) {
    uint64_t matches = 0, drops = 0;

    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        matches += lcore_stats[lcore_id].matches;
        drops += lcore_stats[lcore_id].drops;
    }

    if (total_matches) *total_matches = matches;
    if (total_dropped) *total_dropped = drops;
    if (active_count) *active_count = sig_table ? sig_table->count : 0;
}

void dynamic_signatures_print(void) {
    if (!initialized || sig_table == NULL) {
        printf("Dynamic signatures not initialized\n");
        return;
    }

    uint64_t matches, drops;
    uint32_t count;
    dynamic_signatures_get_stats(&matches, &drops, &count);

    printf("\nDynamic Signatures:\n");
    printf("  Active: %u / %d\n", count, MAX_DYNAMIC_SIGNATURES);
    printf("  Total matches: %lu\n", matches);
    printf("  Total drops: %lu\n", drops);
    printf("\n");

    if (count == 0) {
        printf("  (no signatures)\n");
        return;
    }

    printf("  ID      Pri  Proto  Port     Size     TTL    Flags  Action   Matches\n");
    printf("  ─────── ──── ────── ──────── ──────── ────── ────── ──────── ────────\n");

    for (uint32_t i = 0; i < sig_table->count; i++) {
        struct dynamic_signature *sig = &sig_table->entries[i];

        const char *action_str = "ALLOW";
        switch (sig->action) {
            case POLICY_DROP: action_str = "DROP"; break;
            case POLICY_RATE_LIMIT: action_str = "RATELIM"; break;
            case POLICY_CHALLENGE: action_str = "CHALLNG"; break;
            default: break;
        }

        const char *proto_str = "*";
        if (sig->protocol == 6) proto_str = "TCP";
        else if (sig->protocol == 17) proto_str = "UDP";
        else if (sig->protocol == 1) proto_str = "ICMP";

        printf("  %-7u %-4u %-6s %-8s %-8s %-6s 0x%02X   %-8s %lu\n",
               sig->id,
               sig->priority,
               proto_str,
               sig->dst_port_min == 0 && sig->dst_port_max == 0 ? "*" : "...",
               sig->pkt_size_min == 0 && sig->pkt_size_max == 0 ? "*" : "...",
               sig->ttl_min == 0 && sig->ttl_max == 0 ? "*" : "...",
               sig->tcp_flags_value,
               action_str,
               sig->match_count);
    }
}
