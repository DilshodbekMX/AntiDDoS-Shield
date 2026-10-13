#include "reputation_interface.h"
#include <rte_log.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <string.h>

#define RTE_LOGTYPE_REPUTATION RTE_LOGTYPE_USER8

// ==================== Global State ====================

static struct layer1_shared_memory *shmem = NULL;
static struct rte_hash *reputation_hash = NULL;  // Fast O(1) lookup
static uint64_t reputation_hits = 0;

// Overflow tracking statistics
static uint64_t reputation_overflow_count = 0;
static uint64_t reputation_expired_removed = 0;

// ==================== Helper Functions ====================

/**
 * Classify reputation score into level
 */
static enum reputation_level score_to_level(uint16_t score) {
    if (score <= 200) return REP_ATTACKER;
    if (score <= 500) return REP_SUSPICIOUS;
    if (score <= 700) return REP_NEUTRAL;
    if (score <= 900) return REP_GOOD;
    return REP_EXCELLENT;
}

// ==================== Initialization ====================

int reputation_interface_init(void) {
    shmem = shared_memory_get();
    if (!shmem) {
        RTE_LOG(ERR, REPUTATION, "Shared memory not initialized\n");
        return -1;
    }

    // Create hash table with thread safety
    // The hash table returns index directly - no manual index allocation needed
    struct rte_hash_parameters hash_params = {
        .name = "reputation_hash",
        .entries = MAX_REPUTATION_ENTRIES,
        .key_len = sizeof(uint32_t),  // IP address
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        // CRITICAL: Enable thread-safe concurrent access
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                      RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
    };

    reputation_hash = rte_hash_create(&hash_params);
    if (!reputation_hash) {
        RTE_LOG(ERR, REPUTATION, "Failed to create reputation hash table\n");
        return -1;
    }

    RTE_LOG(INFO, REPUTATION, "Reputation interface initialized (max %d entries, thread-safe)\n",
            MAX_REPUTATION_ENTRIES);
    return 0;
}

void reputation_interface_cleanup(void) {
    if (reputation_hash) {
        rte_hash_free(reputation_hash);
        reputation_hash = NULL;
    }
    shmem = NULL;
    RTE_LOG(INFO, REPUTATION, "Reputation interface cleanup complete\n");
}

// ==================== Fast Path (Layer 1) ====================

void reputation_lookup(uint32_t ip, struct reputation_result *result) {
    // Default: unknown reputation (neutral stance)
    result->found = false;
    result->score = 500;  // Neutral default
    result->level = REP_UNKNOWN;
    result->confidence = 0;
    result->attack_count = 0;

    if (!shmem || !reputation_hash) {
        return;  // Not initialized
    }

    // O(1) hash lookup - thread safe with RW_CONCURRENCY flag
    int32_t index = rte_hash_lookup(reputation_hash, &ip);
    if (index < 0) {
        return;  // IP not found in reputation table
    }

    // Found! Retrieve reputation data
    struct reputation_entry *entry = &shmem->reputation.entries[index];

    // Check if entry is expired or being built (atomic read)
    // REP_FLAG_IS_BUILDING prevents reading partially-initialized entries
    uint8_t flags = __atomic_load_n(&entry->flags, __ATOMIC_ACQUIRE);
    if (flags & (REP_FLAG_IS_EXPIRED | REP_FLAG_IS_BUILDING)) {
        return;  // Expired or being initialized - skip
    }

    result->found = true;
    result->score = __atomic_load_n(&entry->score, __ATOMIC_RELAXED);
    result->level = score_to_level(result->score);
    result->confidence = __atomic_load_n(&entry->confidence, __ATOMIC_RELAXED);
    result->attack_count = __atomic_load_n(&entry->attack_count, __ATOMIC_RELAXED);

    __atomic_add_fetch(&reputation_hits, 1, __ATOMIC_RELAXED);
}

void reputation_get_stats(uint32_t *total_entries, uint64_t *reputation_hits_out) {
    if (total_entries) {
        *total_entries = reputation_hash ? rte_hash_count(reputation_hash) : 0;
    }
    if (reputation_hits_out) {
        *reputation_hits_out = __atomic_load_n(&reputation_hits, __ATOMIC_RELAXED);
    }
}

// ==================== Control Plane (Layer 4) ====================

int reputation_update(uint32_t ip, uint16_t score, uint16_t confidence,
                      uint32_t packet_count, uint32_t attack_count) {
    if (!shmem || !reputation_hash) {
        return -1;
    }

    struct reputation_table *table = &shmem->reputation;

    // Try to find existing entry
    int32_t index = rte_hash_lookup(reputation_hash, &ip);

    if (index >= 0) {
        // Update existing entry atomically
        struct reputation_entry *entry = &table->entries[index];
        __atomic_store_n(&entry->score, score, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->confidence, confidence, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->packet_count, packet_count, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->attack_count, attack_count, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->last_updated_ns, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
        __atomic_fetch_and(&entry->flags, ~REP_FLAG_IS_EXPIRED, __ATOMIC_RELAXED);  // Clear expired flag
    } else {
        // Add new entry - hash table provides the index
        index = rte_hash_add_key(reputation_hash, &ip);
        if (index < 0) {
            uint64_t overflow_num = __atomic_add_fetch(&reputation_overflow_count, 1, __ATOMIC_RELAXED);
            if (overflow_num <= 10 || (overflow_num % 1000 == 0)) {
                RTE_LOG(ERR, REPUTATION, "Reputation table full, overflow #%lu\n",
                        (unsigned long)overflow_num);
            }
            return -1;
        }

        // Race condition during new entry initialization
        // Problem: A concurrent reader could see a partially-written entry between
        // the hash add and the final flags write.
        //
        // Solution: Use a "building" flag pattern:
        // 1. Set REP_FLAG_IS_BUILDING before filling (readers will skip)
        // 2. Fill all fields
        // 3. Clear REP_FLAG_IS_BUILDING with RELEASE to make all writes visible
        //
        // The reader in reputation_lookup() already checks flags with ACQUIRE,
        // so once we clear the building flag, all prior writes are visible.

        struct reputation_entry *entry = &table->entries[index];

        // Step 1: Mark entry as "building" - readers will skip this entry
        __atomic_store_n(&entry->flags, REP_FLAG_IS_BUILDING, __ATOMIC_RELEASE);

        // Step 2: Fill all entry fields (order doesn't matter, all protected by flag)
        __atomic_store_n(&entry->ip, ip, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->score, score, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->confidence, confidence, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->packet_count, packet_count, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->attack_count, attack_count, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->last_updated_ns, rte_get_tsc_cycles(), __ATOMIC_RELAXED);

        // Step 3: Clear building flag - RELEASE ensures all prior writes are visible
        // to any reader that sees this store
        __atomic_store_n(&entry->flags, 0, __ATOMIC_RELEASE);

        __atomic_add_fetch(&table->global_version, 1, __ATOMIC_RELEASE);
    }

    return 0;
}

int reputation_remove(uint32_t ip) {
    if (!shmem || !reputation_hash) {
        return -1;
    }

    int32_t index = rte_hash_lookup(reputation_hash, &ip);
    if (index < 0) {
        return -1;  // Not found
    }

    // Mark as expired atomically
    struct reputation_entry *entry = &shmem->reputation.entries[index];
    __atomic_fetch_or(&entry->flags, REP_FLAG_IS_EXPIRED, __ATOMIC_RELAXED);

    // Remove from hash
    rte_hash_del_key(reputation_hash, &ip);

    __atomic_add_fetch(&shmem->reputation.global_version, 1, __ATOMIC_RELEASE);

    RTE_LOG(INFO, REPUTATION, "Removed reputation for IP %u.%u.%u.%u\n",
            (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
            (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
            rte_be_to_cpu_32(ip) & 0xFF);

    return 0;
}

void reputation_clear_all(void) {
    if (!shmem || !reputation_hash) {
        return;
    }

    rte_hash_reset(reputation_hash);
    __atomic_add_fetch(&shmem->reputation.global_version, 1, __ATOMIC_RELEASE);

    RTE_LOG(INFO, REPUTATION, "All reputation data cleared\n");
}

int reputation_mark_attacker(uint32_t ip) {
    return reputation_update(ip, 0, 100, 0, 1);  // Score=0, confidence=100%
}

int reputation_mark_trusted(uint32_t ip) {
    return reputation_update(ip, 1000, 100, 0, 0);  // Score=1000, confidence=100%
}

// ==================== Layer 1 Event-Based Reputation Updates ====================

/**
 * Adjust reputation score for an IP, with bounds checking.
 * Creates a new entry if IP doesn't exist yet.
 *
 * @param ip       IP address (network byte order)
 * @param delta    Score adjustment (negative = penalty, positive = reward)
 * @param is_attack  Whether this is an attack indicator
 */
static void reputation_adjust(uint32_t ip, int32_t delta, bool is_attack) {
    if (!shmem || !reputation_hash) {
        return;
    }

    struct reputation_table *table = &shmem->reputation;
    int32_t index = rte_hash_lookup(reputation_hash, &ip);

    if (index >= 0) {
        // Existing entry - update atomically
        struct reputation_entry *entry = &table->entries[index];

        // Read current values
        uint16_t current_score = __atomic_load_n(&entry->score, __ATOMIC_RELAXED);
        uint32_t current_attacks = __atomic_load_n(&entry->attack_count, __ATOMIC_RELAXED);
        uint32_t current_packets = __atomic_load_n(&entry->packet_count, __ATOMIC_RELAXED);
        uint16_t current_confidence = __atomic_load_n(&entry->confidence, __ATOMIC_RELAXED);

        // Calculate new score with bounds
        int32_t new_score = (int32_t)current_score + delta;
        if (new_score < 0) new_score = 0;
        if (new_score > 1000) new_score = 1000;

        // Update entry
        __atomic_store_n(&entry->score, (uint16_t)new_score, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->packet_count, current_packets + 1, __ATOMIC_RELAXED);
        if (is_attack) {
            __atomic_store_n(&entry->attack_count, current_attacks + 1, __ATOMIC_RELAXED);
        }

        // Increase confidence (up to 100)
        if (current_confidence < 100) {
            __atomic_store_n(&entry->confidence, current_confidence + 1, __ATOMIC_RELAXED);
        }

        __atomic_store_n(&entry->last_updated_ns, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
        __atomic_fetch_and(&entry->flags, ~REP_FLAG_IS_EXPIRED, __ATOMIC_RELAXED);

    } else {
        // New entry - create with initial score
        uint16_t initial_score = 500;  // Neutral starting point
        int32_t adjusted = initial_score + delta;
        if (adjusted < 0) adjusted = 0;
        if (adjusted > 1000) adjusted = 1000;

        index = rte_hash_add_key(reputation_hash, &ip);
        if (index < 0) {
            return;  // Table full
        }

        struct reputation_entry *entry = &table->entries[index];
        __atomic_store_n(&entry->ip, ip, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->score, (uint16_t)adjusted, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->confidence, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->packet_count, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->attack_count, is_attack ? 1 : 0, __ATOMIC_RELAXED);
        __atomic_store_n(&entry->last_updated_ns, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
        __atomic_store_n(&entry->flags, 0, __ATOMIC_RELEASE);

        __atomic_add_fetch(&table->global_version, 1, __ATOMIC_RELEASE);
    }
}

void reputation_report_rate_limit(uint32_t ip) {
    reputation_adjust(ip, -REP_PENALTY_RATE_LIMIT, true);
}

void reputation_report_conn_limit(uint32_t ip) {
    reputation_adjust(ip, -REP_PENALTY_CONN_LIMIT, true);
}

void reputation_report_invalid_cookie(uint32_t ip) {
    reputation_adjust(ip, -REP_PENALTY_INVALID_COOKIE, true);
}

void reputation_report_validation_failure(uint32_t ip) {
    reputation_adjust(ip, -REP_PENALTY_VALIDATION, true);
}

void reputation_report_connection_established(uint32_t ip) {
    reputation_adjust(ip, REP_REWARD_ESTABLISHED, false);
}

void reputation_report_valid_cookie(uint32_t ip) {
    reputation_adjust(ip, REP_REWARD_VALID_COOKIE, false);
}

uint16_t reputation_get_attacker_threshold(void) {
    return 200;  // Score below this = attacker
}

uint32_t reputation_decay_scores(uint16_t decay_amount) {
    if (!shmem || !reputation_hash || decay_amount == 0) {
        return 0;
    }

    uint32_t decayed = 0;
    struct reputation_table *table = &shmem->reputation;

    // Iterate through all hash table entries
    uint32_t iter = 0;
    const void *key;
    void *data;
    int32_t index;

    while ((index = rte_hash_iterate(reputation_hash, &key, &data, &iter)) >= 0) {
        struct reputation_entry *entry = &table->entries[index];

        uint8_t flags = __atomic_load_n(&entry->flags, __ATOMIC_RELAXED);
        if (flags & REP_FLAG_IS_EXPIRED) {
            continue;
        }

        uint16_t score = __atomic_load_n(&entry->score, __ATOMIC_RELAXED);
        uint16_t confidence = __atomic_load_n(&entry->confidence, __ATOMIC_RELAXED);

        // Decay toward neutral (500)
        if (score < 500) {
            int32_t new_score = score + decay_amount;
            if (new_score > 500) new_score = 500;
            __atomic_store_n(&entry->score, (uint16_t)new_score, __ATOMIC_RELAXED);
            decayed++;
        } else if (score > 500) {
            int32_t new_score = score - decay_amount;
            if (new_score < 500) new_score = 500;
            __atomic_store_n(&entry->score, (uint16_t)new_score, __ATOMIC_RELAXED);
            decayed++;
        }

        // Also decay confidence slightly (if above 10)
        if (confidence > 10) {
            __atomic_store_n(&entry->confidence, confidence - 1, __ATOMIC_RELAXED);
        }
    }

    return decayed;
}

// ==================== Overflow Handling ====================

uint32_t reputation_cleanup_stale(uint64_t max_age_ns) {
    if (!shmem || !reputation_hash) {
        return 0;
    }

    uint64_t now_tsc = rte_get_tsc_cycles();
    uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t max_age_tsc = (max_age_ns * tsc_hz) / 1000000000ULL;

    struct reputation_table *table = &shmem->reputation;
    uint32_t removed = 0;

    // Collect IPs to remove (can't delete during iteration)
    uint32_t to_remove[256];
    uint32_t remove_count = 0;

    uint32_t iter = 0;
    const void *key;
    void *data;
    int32_t index;

    while ((index = rte_hash_iterate(reputation_hash, &key, &data, &iter)) >= 0) {
        struct reputation_entry *entry = &table->entries[index];

        uint64_t last_updated = __atomic_load_n(&entry->last_updated_ns, __ATOMIC_RELAXED);
        uint8_t flags = __atomic_load_n(&entry->flags, __ATOMIC_RELAXED);
        uint16_t confidence = __atomic_load_n(&entry->confidence, __ATOMIC_RELAXED);

        // Remove if:
        // 1. Already expired
        // 2. Not updated in max_age_ns
        // 3. Low confidence (< 5) and not explicitly marked as attacker/trusted
        bool should_remove = false;

        if (flags & REP_FLAG_IS_EXPIRED) {
            should_remove = true;
        } else if (now_tsc - last_updated > max_age_tsc) {
            should_remove = true;
        } else if (confidence < 5 && !(flags & (REP_FLAG_IS_ATTACKER | REP_FLAG_IS_TRUSTED))) {
            should_remove = true;
        }

        if (should_remove && remove_count < 256) {
            to_remove[remove_count++] = *(const uint32_t *)key;
        }
    }

    // Now remove collected entries
    for (uint32_t i = 0; i < remove_count; i++) {
        index = rte_hash_lookup(reputation_hash, &to_remove[i]);
        if (index >= 0) {
            __atomic_fetch_or(&table->entries[index].flags, REP_FLAG_IS_EXPIRED, __ATOMIC_RELAXED);
            rte_hash_del_key(reputation_hash, &to_remove[i]);
            removed++;
        }
    }

    if (removed > 0) {
        __atomic_add_fetch(&reputation_expired_removed, removed, __ATOMIC_RELAXED);
        __atomic_add_fetch(&table->global_version, 1, __ATOMIC_RELEASE);

        RTE_LOG(INFO, REPUTATION, "Cleaned up %u stale reputation entries, %u remaining\n",
                removed, rte_hash_count(reputation_hash));
    }

    return removed;
}

void reputation_get_overflow_stats(uint64_t *overflow_count, uint64_t *expired_removed) {
    if (overflow_count) {
        *overflow_count = __atomic_load_n(&reputation_overflow_count, __ATOMIC_RELAXED);
    }
    if (expired_removed) {
        *expired_removed = __atomic_load_n(&reputation_expired_removed, __ATOMIC_RELAXED);
    }
}