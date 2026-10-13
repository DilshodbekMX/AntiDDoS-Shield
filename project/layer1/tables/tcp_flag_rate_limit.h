#ifndef LAYER1_TCP_FLAG_RATE_LIMIT_H
#define LAYER1_TCP_FLAG_RATE_LIMIT_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_hash.h>

/**
 * @file tcp_flag_rate_limit.h
 * @brief Per-TCP-flag-class rate limiting
 *
 * Problem this solves:
 * - A single TCP rate limit blocks ALL TCP equally
 * - Legit client sending 900 ACKs + attacker sending 200 SYNs = client blocked!
 *
 * Solution:
 * - Separate rate limits per TCP flag class (SYN, ACK, RST, FIN, etc.)
 * - SYN limit: 100/sec, ACK limit: 50K/sec
 * - Attacker's SYNs blocked, client's ACKs pass through
 *
 * Performance:
 * - ~25 cycles per packet (hash lookup + token bucket check)
 * - 40K entries per flag class = 12.8 MB total memory
 *
 * Integration with Layer 4 (Continuous Reputation):
 * - Rate limit violations reported via feedback queue
 * - Layer 4 can boost suspicion score on repeated violations
 */

// ==================== TCP Flag Classes ====================

/**
 * TCP flag classification for independent rate limiting.
 * Each class has its own bucket with configurable limits.
 */
enum tcp_flag_class {
    TCPF_SYN = 0,           // SYN without ACK (connection initiation)
    TCPF_SYN_ACK = 1,       // SYN+ACK (server response)
    TCPF_ACK = 2,           // Pure ACK (data acknowledgment)
    TCPF_RST = 3,           // RST flag (connection reset)
    TCPF_FIN = 4,           // FIN flag (connection close)
    TCPF_PSH = 5,           // PSH flag (push data)
    TCPF_URG = 6,           // URG flag (urgent - rare)
    TCPF_OTHER = 7,         // Other combinations
    TCPF_MAX = 8
};

// ==================== Configuration ====================

/**
 * Per-flag-class rate limit configuration.
 * Limits are per source IP, per flag class.
 */
struct tcp_flag_rate_config {
    bool     enabled;                       // Enable TCP flag rate limiting
    uint32_t pps_limits[TCPF_MAX];          // Packets/sec limit per class
    uint32_t bucket_capacity[TCPF_MAX];     // Token bucket capacity per class
    uint32_t max_entries;                   // Maximum IPs to track (default: 40000)
    uint32_t cleanup_interval_sec;          // Cleanup interval (default: 60)
    bool     report_violations;             // Report to feedback queue for Layer 4
};

// ==================== Default Limits ====================

/**
 * Default rate limits per flag class.
 * Tuned based on typical legitimate traffic patterns.
 */
#define TCPF_DEFAULT_SYN_PPS        100     // Connection initiation: low limit
#define TCPF_DEFAULT_SYN_ACK_PPS    1000    // Server responses: moderate
#define TCPF_DEFAULT_ACK_PPS        50000   // Data ACKs: high (bulk transfers)
#define TCPF_DEFAULT_RST_PPS        500     // Resets: moderate
#define TCPF_DEFAULT_FIN_PPS        500     // Closes: moderate
#define TCPF_DEFAULT_PSH_PPS        10000   // Push data: high
#define TCPF_DEFAULT_URG_PPS        100     // Urgent: very rare
#define TCPF_DEFAULT_OTHER_PPS      5000    // Other: moderate

#define TCPF_DEFAULT_MAX_ENTRIES    40000
#define TCPF_DEFAULT_CLEANUP_SEC    60

// ==================== Result ====================

/**
 * Rate limit check result
 */
enum tcp_flag_rate_result {
    TCPF_RATE_ACCEPT = 0,       // Packet accepted
    TCPF_RATE_DROP_SYN,         // Dropped: SYN rate exceeded
    TCPF_RATE_DROP_SYN_ACK,     // Dropped: SYN-ACK rate exceeded
    TCPF_RATE_DROP_ACK,         // Dropped: ACK rate exceeded
    TCPF_RATE_DROP_RST,         // Dropped: RST rate exceeded
    TCPF_RATE_DROP_FIN,         // Dropped: FIN rate exceeded
    TCPF_RATE_DROP_PSH,         // Dropped: PSH rate exceeded
    TCPF_RATE_DROP_URG,         // Dropped: URG rate exceeded
    TCPF_RATE_DROP_OTHER,       // Dropped: Other flags rate exceeded
    TCPF_RATE_ERROR             // Internal error
};

// ==================== Statistics ====================

/**
 * Per-flag-class statistics
 */
struct tcp_flag_rate_stats {
    uint64_t packets_checked;               // Total packets checked
    uint64_t packets_accepted;              // Packets accepted
    uint64_t drops_per_class[TCPF_MAX];     // Drops per flag class
    uint64_t current_entries;               // Current entries in hash
    uint64_t cleanups_performed;            // Number of cleanup cycles
};

// ==================== Public API ====================

/**
 * Initialize TCP flag rate limiter.
 *
 * @param config  Configuration (NULL for defaults)
 * @return 0 on success, -1 on error
 */
int tcp_flag_rate_init(const struct tcp_flag_rate_config *config);

/**
 * Cleanup and free resources.
 */
void tcp_flag_rate_cleanup(void);

/**
 * Check rate limit for a TCP packet.
 * Must be called for every TCP packet in the pipeline.
 *
 * @param src_ip     Source IP (network byte order)
 * @param tcp_flags  TCP flags byte from packet header
 * @param pkt_len    Packet length (for future BPS limiting)
 * @return TCPF_RATE_ACCEPT if allowed, TCPF_RATE_DROP_* if rate exceeded
 */
enum tcp_flag_rate_result tcp_flag_rate_check(uint32_t src_ip,
                                               uint8_t tcp_flags,
                                               uint16_t pkt_len);

/**
 * Classify TCP flags into flag class.
 * Inline for use in other modules.
 *
 * @param tcp_flags  TCP flags byte
 * @return Flag class enum
 */
static inline enum tcp_flag_class tcp_flag_classify(uint8_t tcp_flags) {
    // Check specific combinations first
    bool has_syn = (tcp_flags & 0x02) != 0;  // SYN
    bool has_ack = (tcp_flags & 0x10) != 0;  // ACK
    bool has_rst = (tcp_flags & 0x04) != 0;  // RST
    bool has_fin = (tcp_flags & 0x01) != 0;  // FIN
    bool has_psh = (tcp_flags & 0x08) != 0;  // PSH
    bool has_urg = (tcp_flags & 0x20) != 0;  // URG

    // RST takes priority (connection termination)
    if (has_rst) {
        return TCPF_RST;
    }

    // SYN variants
    if (has_syn) {
        return has_ack ? TCPF_SYN_ACK : TCPF_SYN;
    }

    // FIN takes priority over ACK (close initiation)
    if (has_fin) {
        return TCPF_FIN;
    }

    // URG is rare
    if (has_urg) {
        return TCPF_URG;
    }

    // PSH with ACK is common for data
    if (has_psh) {
        return TCPF_PSH;
    }

    // Pure ACK
    if (has_ack) {
        return TCPF_ACK;
    }

    // Other (NULL flags, etc.)
    return TCPF_OTHER;
}

/**
 * Get name of flag class for logging.
 */
const char* tcp_flag_class_name(enum tcp_flag_class cls);

/**
 * Get result name for logging.
 */
const char* tcp_flag_rate_result_name(enum tcp_flag_rate_result result);

/**
 * Get current statistics.
 *
 * @param stats  Output statistics structure
 */
void tcp_flag_rate_get_stats(struct tcp_flag_rate_stats *stats);

/**
 * Print statistics to stdout.
 */
void tcp_flag_rate_print_stats(void);

/**
 * Reset statistics counters.
 */
void tcp_flag_rate_reset_stats(void);

/**
 * Cleanup expired entries.
 * Should be called periodically from maintenance thread.
 *
 * @return Number of entries cleaned up
 */
uint32_t tcp_flag_rate_cleanup_expired(void);

/**
 * Update rate limits at runtime.
 *
 * @param flag_class  Flag class to update
 * @param pps_limit   New PPS limit
 * @return 0 on success, -1 on error
 */
int tcp_flag_rate_set_limit(enum tcp_flag_class flag_class, uint32_t pps_limit);

/**
 * Check if rate limiting is enabled.
 */
bool tcp_flag_rate_is_enabled(void);

#endif // LAYER1_TCP_FLAG_RATE_LIMIT_H
