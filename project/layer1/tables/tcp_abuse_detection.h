#ifndef LAYER1_TCP_ABUSE_DETECTION_H
#define LAYER1_TCP_ABUSE_DETECTION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * @file tcp_abuse_detection.h
 * @brief TCP Protocol Abuse Detection
 *
 * Detects malformed/abusive TCP behavior that indicates attacks:
 *
 * 1. Duplicate SEQ Flood: Same SEQ number repeated (>150/sec)
 *    - Attacker sends packets with identical sequence numbers
 *    - Legitimate traffic has incrementing SEQ numbers
 *
 * 2. Random SEQ Flood: Random SEQ jumps (>45 jumps in 10s)
 *    - Attacker sends packets with random sequence numbers
 *    - Legitimate traffic has predictable SEQ progression
 *
 * 3. Random ACK Flood: Random ACK jumps (>45 jumps in 10s)
 *    - Attacker sends ACKs with random acknowledgment numbers
 *    - Legitimate ACKs acknowledge received data predictably
 *
 * 4. Zero Window Attack: Window=0 flood (>5 in 10s)
 *    - Attacker sends zero-window probes to slow down server
 *    - Legitimate zero-window is rare (receiver buffer full)
 *
 * 5. Tiny Window Attack: Window<100 bytes
 *    - Attacker sends tiny window to slow down transmission
 *    - Legitimate small windows are rare
 *
 * 6. Small Window Attack: Window<2000 bytes (log only)
 *    - Attacker uses artificially small receive window
 *    - May indicate Slowloris-style attack
 *
 * 7. Same Window Flood: Same window value repeated (>150/sec)
 *    - Attacker uses static window value
 *    - Legitimate window sizes fluctuate with buffer state
 *
 * 8. Same ACK Flood: Same ACK number repeated (>150/sec)
 *    - Attacker uses static ACK number
 *    - Legitimate ACKs progress with received data
 *
 * Performance:
 * - ~10-20 cycles per TCP packet (state update + check)
 * - Integrated into flow table for zero-copy state access
 * - Per-flow tracking (~32 bytes additional per flow)
 *
 * Integration with Layer 4 (Continuous Reputation):
 * - Detected abuse is reported via feedback queue
 * - Layer 4 can increase suspicion score based on abuse type
 */

// ==================== Abuse Types ====================

/**
 * TCP abuse type bitmask
 * Multiple abuse types can be detected simultaneously
 */
enum tcp_abuse_type {
    TCP_ABUSE_NONE           = 0,
    TCP_ABUSE_DUP_SEQ        = (1 << 0),   // Duplicate SEQ flood
    TCP_ABUSE_RANDOM_SEQ     = (1 << 1),   // Random SEQ jumps
    TCP_ABUSE_RANDOM_ACK     = (1 << 2),   // Random ACK jumps
    TCP_ABUSE_ZERO_WINDOW    = (1 << 3),   // Zero window attack
    TCP_ABUSE_TINY_WINDOW    = (1 << 4),   // Tiny window (<100 bytes)
    TCP_ABUSE_SMALL_WINDOW   = (1 << 5),   // Small window (<2000 bytes)
    TCP_ABUSE_SAME_WINDOW    = (1 << 6),   // Same window flood
    TCP_ABUSE_SAME_ACK       = (1 << 7),   // Same ACK flood
};

// ==================== Detection Actions ====================

/**
 * Action to take when abuse is detected
 */
enum tcp_abuse_action {
    TCP_ABUSE_ACTION_LOG = 0,       // Log only, don't drop
    TCP_ABUSE_ACTION_DROP = 1,      // Drop packet
    TCP_ABUSE_ACTION_RATE_LIMIT = 2, // Apply rate limiting
};

// ==================== Detection Result ====================

/**
 * Result of TCP abuse check
 */
enum tcp_abuse_result {
    TCP_ABUSE_RESULT_ACCEPT = 0,    // Packet is clean
    TCP_ABUSE_RESULT_DROP,          // Drop packet (abuse detected)
    TCP_ABUSE_RESULT_RATE_LIMIT,    // Apply rate limiting
    TCP_ABUSE_RESULT_LOG,           // Log only (suspicious but not actionable)
};

// ==================== Per-Flow Abuse Tracking State ====================

/**
 * Per-flow TCP abuse detection state
 * This structure is embedded in flow_entry for zero-copy access
 * Size: 32 bytes (fits in single cache line with padding)
 */
struct tcp_abuse_state {
    // ===== Sequence Number Tracking =====
    uint32_t last_seq;              // Last seen SEQ number
    uint32_t dup_seq_count;         // Count of duplicate SEQ in current window
    uint16_t seq_jump_count;        // Count of large SEQ jumps (random SEQ)

    // ===== ACK Number Tracking =====
    uint32_t last_ack;              // Last seen ACK number
    uint32_t dup_ack_count;         // Count of duplicate ACK in current window
    uint16_t ack_jump_count;        // Count of large ACK jumps (random ACK)

    // ===== Window Tracking =====
    uint16_t last_window;           // Last seen window size
    uint32_t same_window_count;     // Count of same window value in window
    uint8_t  zero_window_count;     // Count of zero windows in time window
    uint8_t  tiny_window_count;     // Count of tiny windows in time window

    // ===== Timing =====
    uint64_t last_reset_tsc;        // TSC when counters were last reset

    // ===== Detected Abuse (bitmask) =====
    uint8_t  detected_abuse;        // Bitmask of tcp_abuse_type

    // ===== Padding for cache alignment =====
    uint8_t  _pad[3];
} __attribute__((packed));

// ==================== Configuration ====================

/**
 * TCP abuse detection configuration
 * Mirrors struct tcp_abuse_cfg from layer1_config.h
 */
struct tcp_abuse_config {
    bool     enabled;
    bool     report_to_layer4;

    // Detection thresholds
    uint32_t dup_seq_threshold;        // >150/sec
    uint32_t random_seq_threshold;     // >45 jumps in 10s
    uint32_t random_ack_threshold;     // >45 jumps in 10s
    uint32_t zero_window_threshold;    // >5 in 10s
    uint16_t tiny_window_bytes;        // <100 bytes
    uint16_t small_window_bytes;       // <2000 bytes
    uint32_t same_window_threshold;    // >150/sec
    uint32_t same_ack_threshold;       // >150/sec

    // Actions (tcp_abuse_action enum)
    uint8_t  action_dup_seq;
    uint8_t  action_random_seq;
    uint8_t  action_random_ack;
    uint8_t  action_zero_window;
    uint8_t  action_tiny_window;
    uint8_t  action_small_window;
    uint8_t  action_same_window;
    uint8_t  action_same_ack;
};

// ==================== Statistics ====================

/**
 * TCP abuse detection statistics
 */
struct tcp_abuse_stats {
    uint64_t packets_checked;          // Total TCP packets checked
    uint64_t packets_clean;            // Clean packets (no abuse)
    uint64_t abuse_detected[8];        // Counts per abuse type
    uint64_t drops[8];                 // Drops per abuse type
    uint64_t rate_limits[8];           // Rate limits applied per abuse type
};

// ==================== Public API ====================

/**
 * Initialize TCP abuse detection
 *
 * @param config  Configuration (NULL for defaults from layer1_config)
 * @return 0 on success, -1 on error
 */
int tcp_abuse_init(const struct tcp_abuse_config *config);

/**
 * Cleanup TCP abuse detection
 */
void tcp_abuse_cleanup(void);

/**
 * Check TCP packet for abuse patterns
 * Called after flow table lookup, uses per-flow state
 *
 * @param state       Per-flow abuse tracking state (from flow_entry)
 * @param src_ip      Source IP (for reputation reporting)
 * @param seq_num     TCP sequence number (network byte order)
 * @param ack_num     TCP acknowledgment number (network byte order)
 * @param window      TCP window size (host byte order)
 * @param tcp_flags   TCP flags byte
 * @param pkt_len     Packet length
 * @return tcp_abuse_result enum
 */
enum tcp_abuse_result tcp_abuse_check(struct tcp_abuse_state *state,
                                       uint32_t src_ip,
                                       uint32_t seq_num,
                                       uint32_t ack_num,
                                       uint16_t window,
                                       uint8_t tcp_flags,
                                       uint16_t pkt_len);

/**
 * Initialize per-flow abuse state
 * Called when a new flow is created
 *
 * @param state  State structure to initialize
 */
void tcp_abuse_state_init(struct tcp_abuse_state *state);

/**
 * Reset abuse counters (called periodically by aging)
 * Resets per-second counters, keeps per-10s counters until window expires
 *
 * @param state  State structure to reset
 */
void tcp_abuse_state_reset_counters(struct tcp_abuse_state *state);

/**
 * Check if TCP abuse detection is enabled
 */
bool tcp_abuse_is_enabled(void);

/**
 * Update configuration at runtime.
 * Safe to call while processing packets.
 *
 * @param config  New configuration values
 */
void tcp_abuse_update_config(const struct tcp_abuse_config *config);

/**
 * Get current statistics
 *
 * @param stats  Output statistics structure
 */
void tcp_abuse_get_stats(struct tcp_abuse_stats *stats);

/**
 * Print statistics to stdout
 */
void tcp_abuse_print_stats(void);

/**
 * Reset statistics counters
 */
void tcp_abuse_reset_stats(void);

/**
 * Get abuse type name for logging
 *
 * @param type  Abuse type enum
 * @return String name
 */
const char* tcp_abuse_type_name(enum tcp_abuse_type type);

/**
 * Get all abuse types as string (for multi-abuse)
 *
 * @param types   Bitmask of abuse types
 * @param buffer  Output buffer
 * @param size    Buffer size
 * @return Number of characters written
 */
int tcp_abuse_types_to_string(uint8_t types, char *buffer, size_t size);

// ==================== SEQ/ACK Jump Detection Helpers ====================

/**
 * Check if SEQ number is a "random jump"
 * Random jump = large, non-contiguous change that doesn't match expected progression
 *
 * @param old_seq  Previous sequence number
 * @param new_seq  New sequence number
 * @param pkt_len  Packet length (for expected progression)
 * @return true if this appears to be a random jump
 */
static inline bool tcp_abuse_is_seq_jump(uint32_t old_seq, uint32_t new_seq, uint16_t pkt_len) {
    // Handle wraparound with signed arithmetic
    int32_t diff = (int32_t)(new_seq - old_seq);

    // Expected progression: old_seq + pkt_len (approx)
    // Allow for retransmits (negative diff up to -64KB)
    // Allow for normal progression (positive diff up to 64KB + some slack)

    // If diff is within expected range, not a jump
    if (diff >= -65536 && diff <= 65536 + (int32_t)pkt_len) {
        return false;
    }

    // Large jump detected
    return true;
}

/**
 * Check if ACK number is a "random jump"
 *
 * @param old_ack  Previous ACK number
 * @param new_ack  New ACK number
 * @return true if this appears to be a random jump
 */
static inline bool tcp_abuse_is_ack_jump(uint32_t old_ack, uint32_t new_ack) {
    int32_t diff = (int32_t)(new_ack - old_ack);

    // ACKs should progress forward (received data) or stay same (duplicate ACK)
    // Allow negative diff up to -64KB (window scale, reordering)
    // Allow positive diff up to 128KB (received burst of data)

    if (diff >= -65536 && diff <= 131072) {
        return false;
    }

    return true;
}

#endif // LAYER1_TCP_ABUSE_DETECTION_H
