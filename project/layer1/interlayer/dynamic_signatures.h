/**
 * @file dynamic_signatures.h
 * @brief Dynamic Signature Table for Layer 3 Integration
 *
 * This module allows Layer 3 (Python) to create and manage attack signatures
 * at runtime. Unlike static signatures in signatures.c, these are:
 *
 * - Created dynamically during attacks
 * - Written by Layer 3 via shared memory
 * - Automatically expired after TTL
 * - Matched in the fast path by Layer 1
 *
 * Flow:
 * 1. Layer 2 detects anomaly -> triggers Layer 3
 * 2. Layer 3 reads packet samples from ring buffer
 * 3. Layer 3 extracts common pattern -> creates signature
 * 4. Layer 3 writes signature to dynamic_signature_table
 * 5. Layer 1 matches packets against dynamic signatures
 */

#ifndef DYNAMIC_SIGNATURES_H
#define DYNAMIC_SIGNATURES_H

#include <stdint.h>
#include <stdbool.h>
#include "../../common/types.h"

// ==================== Constants ====================

#define MAX_DYNAMIC_SIGNATURES 256
#define SIGNATURE_PAYLOAD_MAX  16

// Signature matching modes
#define SIG_MATCH_EXACT        0  // Value must match exactly
#define SIG_MATCH_RANGE        1  // Value must be in [min, max] range
#define SIG_MATCH_MASK         2  // (value & mask) == expected
#define SIG_MATCH_ANY          3  // Wildcard - any value matches

// ==================== Signature Structure ====================

/**
 * Dynamic signature entry
 *
 * Each field has a match mode and value(s).
 * Match mode determines how the field is compared.
 *
 * Size: 128 bytes (cache-line aligned)
 */
struct dynamic_signature {
    // Signature metadata
    uint32_t id;                    // Unique signature ID
    uint32_t enabled;               // 1 = enabled, 0 = disabled
    uint64_t created_ns;            // Creation timestamp (nanoseconds)
    uint64_t expires_ns;            // Expiration timestamp (0 = never)

    // Protocol matching
    uint8_t  protocol;              // IP protocol (0 = any)
    uint8_t  protocol_match;        // Match mode (EXACT or ANY)
    uint16_t _pad1;

    // Destination IP matching (for protecting specific servers)
    uint32_t dst_ip;                // Destination IP (0 = any)
    uint32_t dst_ip_mask;           // Netmask (0xFFFFFFFF = exact match)

    // Port matching
    uint16_t dst_port_min;          // Min destination port (0 = any)
    uint16_t dst_port_max;          // Max destination port (0 = any)
    uint16_t src_port_min;          // Min source port (0 = any)
    uint16_t src_port_max;          // Max source port (0 = any)

    // Packet size matching
    uint16_t pkt_size_min;          // Min packet size (0 = any)
    uint16_t pkt_size_max;          // Max packet size (0 = any)

    // TTL matching
    uint8_t  ttl_min;               // Min TTL (0 = any)
    uint8_t  ttl_max;               // Max TTL (0 = any)

    // TCP flags matching
    uint8_t  tcp_flags_mask;        // Which flags to check
    uint8_t  tcp_flags_value;       // Expected flag values

    // TCP options matching (for fingerprinting)
    uint16_t tcp_mss_min;           // Min MSS (0 = any)
    uint16_t tcp_mss_max;           // Max MSS (0 = any)
    uint8_t  tcp_wscale_min;        // Min window scale (255 = any)
    uint8_t  tcp_wscale_max;        // Max window scale (255 = any)
    uint16_t tcp_window_min;        // Min TCP window
    uint16_t tcp_window_max;        // Max TCP window

    // Payload matching (first N bytes)
    uint8_t  payload_pattern[SIGNATURE_PAYLOAD_MAX];
    uint8_t  payload_pattern_len;   // Length of pattern (0 = don't check)
    uint8_t  payload_match_offset;  // Offset in payload to start match

    // Action
    uint8_t  action;                // enum policy_action (DROP, RATE_LIMIT, etc.)
    uint8_t  _pad2;
    uint32_t rate_limit_pps;        // For RATE_LIMIT action

    // Statistics (updated by Layer 1)
    uint64_t match_count;           // Packets matched
    uint64_t last_match_ns;         // Last match timestamp

    // Attack classification
    uint8_t  attack_type;           // enum l2_attack_type (from Layer 2)
    uint8_t  confidence;            // Confidence level (0-100)
    uint16_t priority;              // Higher = checked first

    // Padding to 128 bytes
    uint8_t  _pad3[6];
} __attribute__((aligned(64)));

// Verify size
_Static_assert(sizeof(struct dynamic_signature) == 128,
               "dynamic_signature must be 128 bytes");

// ==================== Signature Table ====================

/**
 * Dynamic signature table in shared memory
 *
 * Written by: Layer 3 (Python)
 * Read by: Layer 1 (C/DPDK)
 */
struct dynamic_signature_table {
    // Header
    uint64_t version;               // Incremented on any change
    uint32_t count;                 // Number of active signatures
    uint32_t _pad;

    // Signatures
    struct dynamic_signature entries[MAX_DYNAMIC_SIGNATURES];

    // Statistics
    uint64_t total_matches;         // Total packets matched
    uint64_t total_dropped;         // Total packets dropped
    uint64_t last_update_ns;        // Last table update
} __attribute__((aligned(64)));

// ==================== Public API ====================

/**
 * Initialize dynamic signature module
 */
int dynamic_signatures_init(void);

/**
 * Cleanup dynamic signature module
 */
void dynamic_signatures_cleanup(void);

/**
 * Check a packet against all dynamic signatures
 *
 * Called from fast path for every packet (when enabled).
 *
 * @param features  Parsed packet features
 * @param matched_sig  Output: matched signature (if any)
 * @return Action to take (ALLOW, DROP, RATE_LIMIT, etc.)
 */
enum policy_action dynamic_signatures_check(
    const struct packet_features *features,
    struct dynamic_signature **matched_sig);

/**
 * Add a new dynamic signature
 *
 * Called by Layer 3 via shared memory or control socket.
 *
 * @param sig  Signature to add
 * @return Signature ID on success, -1 on error
 */
int dynamic_signatures_add(const struct dynamic_signature *sig);

/**
 * Remove a dynamic signature by ID
 *
 * @param sig_id  Signature ID to remove
 * @return 0 on success, -1 if not found
 */
int dynamic_signatures_remove(uint32_t sig_id);

/**
 * Clear all dynamic signatures
 */
void dynamic_signatures_clear_all(void);

/**
 * Remove expired signatures
 *
 * Should be called periodically from control thread.
 *
 * @return Number of signatures removed
 */
int dynamic_signatures_cleanup_expired(void);

/**
 * Get signature table for shared memory access
 */
struct dynamic_signature_table *dynamic_signatures_get_table(void);

/**
 * Get statistics
 */
void dynamic_signatures_get_stats(uint64_t *total_matches,
                                  uint64_t *total_dropped,
                                  uint32_t *active_count);

/**
 * Print signature table for debugging
 */
void dynamic_signatures_print(void);

// ==================== Helper Functions ====================

/**
 * Check if a value is in range (inclusive)
 */
static inline bool in_range_u16(uint16_t val, uint16_t min, uint16_t max) {
    if (min == 0 && max == 0) return true;  // Wildcard
    return val >= min && val <= max;
}

static inline bool in_range_u8(uint8_t val, uint8_t min, uint8_t max) {
    if (min == 0 && max == 0) return true;  // Wildcard
    if (min == 255 && max == 255) return true;  // Wildcard for wscale
    return val >= min && val <= max;
}

/**
 * Check TCP flags match
 */
static inline bool tcp_flags_match(uint8_t pkt_flags, uint8_t mask, uint8_t expected) {
    if (mask == 0) return true;  // Wildcard
    return (pkt_flags & mask) == expected;
}

#endif // DYNAMIC_SIGNATURES_H
