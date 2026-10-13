#ifndef LAYER1_POLICY_INTERFACE_H
#define LAYER1_POLICY_INTERFACE_H

#include "../../common/types.h"
#include "shared_memory.h"

/**
 * @file policy_interface.h
 * @brief Stage 6: Policy Enforcement
 */

// ==================== NOTE: enum policy_action is in types.h ====================

// ==================== Policy Lookup Results ====================

struct policy_result {
    bool matched;
    enum policy_action action;
    uint32_t rate_limit_pps;
    uint32_t rate_limit_bps;
};

// ==================== Public API ====================

int policy_interface_init(void);
void policy_interface_cleanup(void);

/**
 * Lookup policy for packet (lock-free, thread-safe)
 */
void policy_lookup(const struct packet_features *features,
                   struct policy_result *result);

void policy_get_stats(uint32_t *total_policies, uint64_t *policy_hits);

/**
 * Add policy at end of table
 */
int policy_add(const struct policy_entry *policy);

/**
 * Add policy at correct position based on priority (maintains sorted order)
 * Recommended for proper priority-based matching
 */
int policy_add_sorted(const struct policy_entry *policy);

int policy_remove(uint32_t index);
void policy_clear_all(void);
int policy_update_rate_limit(uint32_t index, uint32_t pps, uint32_t bps);

/**
 * Remove expired policies from the table.
 * Should be called periodically from maintenance thread.
 *
 * @return Number of expired policies removed
 */
uint32_t policy_cleanup_expired(void);

/**
 * Get overflow statistics
 *
 * @param overflow_count  Output: number of times table was full on add attempt
 * @param expired_removed Output: number of expired policies removed by cleanup
 */
void policy_get_overflow_stats(uint64_t *overflow_count, uint64_t *expired_removed);

#endif // LAYER1_POLICY_INTERFACE_H