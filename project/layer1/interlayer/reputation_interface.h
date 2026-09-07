#ifndef LAYER1_REPUTATION_INTERFACE_H
#define LAYER1_REPUTATION_INTERFACE_H

#include "../../common/types.h"
#include "shared_memory.h"
#include <stdint.h>
#include <stdbool.h>

/**
 * @file reputation_interface.h
 * @brief Stage 7: Reputation Check
 */

// ==================== NOTE: enum reputation_level is in types.h ====================

// ==================== Reputation Lookup Results ====================

struct reputation_result {
    bool found;
    uint16_t score;
    enum reputation_level level;
    uint16_t confidence;
    uint32_t attack_count;
};

// ==================== Public API ====================

int reputation_interface_init(void);
void reputation_interface_cleanup(void);

void reputation_lookup(uint32_t ip, struct reputation_result *result);
void reputation_get_stats(uint32_t *total_entries, uint64_t *reputation_hits);

int reputation_update(uint32_t ip, uint16_t score, uint16_t confidence,
                      uint32_t packet_count, uint32_t attack_count);
int reputation_remove(uint32_t ip);
void reputation_clear_all(void);
int reputation_mark_attacker(uint32_t ip);
int reputation_mark_trusted(uint32_t ip);

// ==================== Layer 1 Event-Based Reputation Updates ====================

/**
 * Reputation adjustment amounts for different events.
 * Scores range from 0 (attacker) to 1000 (excellent).
 * Starting score for unknown IPs is 500 (neutral).
 */
#define REP_PENALTY_RATE_LIMIT       50   // Rate limit exceeded
#define REP_PENALTY_CONN_LIMIT       75   // Connection limit exceeded
#define REP_PENALTY_SYN_FLOOD       100   // SYN flood detection
#define REP_PENALTY_INVALID_COOKIE  150   // Invalid SYN cookie
#define REP_PENALTY_VALIDATION       25   // Packet validation failure
#define REP_PENALTY_BLACKLIST       200   // Was blacklisted (severe)
#define REP_REWARD_ESTABLISHED        5   // Successfully established connection
#define REP_REWARD_VALID_COOKIE      10   // Valid SYN cookie response

/**
 * Report rate limit violation for an IP.
 * Decreases reputation and increments attack count.
 *
 * @param ip  IP address (network byte order)
 */
void reputation_report_rate_limit(uint32_t ip);

/**
 * Report connection limit violation for an IP.
 * More severe than rate limit - potential SYN flood.
 *
 * @param ip  IP address (network byte order)
 */
void reputation_report_conn_limit(uint32_t ip);

/**
 * Report invalid SYN cookie from an IP.
 * Strongest indicator of attack - major reputation hit.
 *
 * @param ip  IP address (network byte order)
 */
void reputation_report_invalid_cookie(uint32_t ip);

/**
 * Report packet validation failure from an IP.
 * Minor reputation penalty - could be misconfiguration.
 *
 * @param ip  IP address (network byte order)
 */
void reputation_report_validation_failure(uint32_t ip);

/**
 * Report successful connection establishment.
 * Small reputation boost - legitimate client behavior.
 *
 * @param ip  IP address (network byte order)
 */
void reputation_report_connection_established(uint32_t ip);

/**
 * Report valid SYN cookie response.
 * Small reputation boost - passed challenge.
 *
 * @param ip  IP address (network byte order)
 */
void reputation_report_valid_cookie(uint32_t ip);

/**
 * Get the reputation level threshold for automatic blocking.
 * IPs with reputation below this are treated as attackers.
 *
 * @return Score threshold (default: 200)
 */
uint16_t reputation_get_attacker_threshold(void);

/**
 * Decay reputation scores periodically.
 * Should be called from maintenance thread.
 * Moves scores toward neutral (500) over time.
 *
 * @param decay_amount  Amount to decay toward neutral (e.g., 10)
 * @return Number of entries decayed
 */
uint32_t reputation_decay_scores(uint16_t decay_amount);

/**
 * Clean up stale reputation entries.
 * Removes entries that haven't been updated in max_age_ns nanoseconds,
 * or have very low confidence and aren't explicitly marked.
 * Should be called periodically from maintenance thread.
 *
 * @param max_age_ns  Maximum age in nanoseconds before an entry is considered stale
 * @return Number of entries removed
 */
uint32_t reputation_cleanup_stale(uint64_t max_age_ns);

/**
 * Get overflow statistics.
 *
 * @param overflow_count  Output: number of times table was full on add attempt
 * @param expired_removed Output: number of stale entries removed by cleanup
 */
void reputation_get_overflow_stats(uint64_t *overflow_count, uint64_t *expired_removed);

#endif // LAYER1_REPUTATION_INTERFACE_H