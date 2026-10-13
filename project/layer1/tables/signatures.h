#ifndef SIGNATURES_H
#define SIGNATURES_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @file signatures.h
 * @brief L3/L4 Attack Signature Detection
 *
 * Detects known attack patterns at the network/transport layer:
 *
 * 1. Amplification Attacks (DNS, NTP, SSDP, Memcached, CLDAP, etc.)
 *    - Spoofed source with amplification port
 *    - High response-to-request ratio
 *
 * 2. Scan Patterns
 *    - TCP SYN scan (rapid SYNs to different ports)
 *    - UDP scan (many ports, small packets)
 *    - ICMP sweep
 *
 * 3. Protocol Anomalies
 *    - Malformed packets
 *    - Invalid flag combinations
 *    - Unusual TTL patterns
 *
 * 4. Known Attack Tool Signatures
 *    - Common DDoS tool packet patterns
 *    - Bot traffic signatures
 */

// Maximum number of custom signatures
#define SIG_MAX_CUSTOM 256

// Signature categories
enum sig_category {
    SIG_CAT_AMPLIFICATION = 1,
    SIG_CAT_SCAN = 2,
    SIG_CAT_PROTOCOL_ANOMALY = 3,
    SIG_CAT_ATTACK_TOOL = 4,
    SIG_CAT_CUSTOM = 5
};

// Signature actions
enum sig_action {
    SIG_ACTION_LOG = 1,       // Log only
    SIG_ACTION_ALERT = 2,     // Log + alert
    SIG_ACTION_DROP = 3,      // Drop packet
    SIG_ACTION_RATE_LIMIT = 4 // Apply rate limiting
};

// Known amplification protocols (UDP source ports indicating reflection)
struct amplification_sig {
    uint16_t port;           // UDP source port
    const char *name;        // Protocol name
    uint16_t amplification_factor;  // Typical amplification ratio (up to 65535x)
    bool enabled;
};

// Signature match result
struct sig_match {
    uint32_t signature_id;
    enum sig_category category;
    enum sig_action action;
    const char *description;
    uint8_t severity;        // 1-10
};

// Configuration
struct signatures_config {
    bool enabled;
    bool log_matches;
    bool block_amplification;
    bool block_scans;
    bool block_anomalies;
    bool block_attack_tools;
};

// Statistics
struct signatures_stats {
    uint64_t packets_checked;
    uint64_t signatures_matched;
    uint64_t amplification_detected;
    uint64_t scans_detected;
    uint64_t anomalies_detected;
    uint64_t attack_tools_detected;
    uint64_t packets_dropped;
    uint64_t packets_rate_limited;
};

/**
 * Initialize signature detection
 *
 * @param config  Configuration settings
 * @return 0 on success, -1 on error
 */
int signatures_init(const struct signatures_config *config);

/**
 * Cleanup signature detection
 */
void signatures_cleanup(void);

/**
 * Check a packet against all signatures
 *
 * @param protocol   IP protocol number
 * @param src_ip     Source IP (network byte order)
 * @param dst_ip     Destination IP (network byte order)
 * @param src_port   Source port (host byte order)
 * @param dst_port   Destination port (host byte order)
 * @param tcp_flags  TCP flags (0 for non-TCP)
 * @param pkt_len    Packet length
 * @param ttl        TTL value
 * @param match      Output: matched signature info (if any)
 * @return true if signature matched and packet should be dropped
 */
bool signatures_check(uint8_t protocol,
                      uint32_t src_ip, uint32_t dst_ip,
                      uint16_t src_port, uint16_t dst_port,
                      uint8_t tcp_flags, uint16_t pkt_len,
                      uint8_t ttl,
                      struct sig_match *match);

/**
 * Check for amplification attack signature
 *
 * @param src_port  UDP source port
 * @param pkt_len   Packet length
 * @return Signature ID if matched, 0 if not
 */
uint32_t signatures_check_amplification(uint16_t src_port, uint16_t pkt_len);

/**
 * Enable or disable specific amplification signature
 *
 * @param port    UDP port
 * @param enable  true to enable, false to disable
 */
void signatures_set_amplification_enabled(uint16_t port, bool enable);

/**
 * Set blocking mode
 */
void signatures_set_block_amplification(bool enable);
void signatures_set_block_scans(bool enable);
void signatures_set_block_anomalies(bool enable);
void signatures_set_block_attack_tools(bool enable);

/**
 * Enable or disable
 */
void signatures_set_enabled(bool enabled);
bool signatures_is_enabled(void);

/**
 * Get statistics
 */
void signatures_get_stats(struct signatures_stats *stats);

/**
 * Reset statistics
 */
void signatures_reset_stats(void);

/**
 * Print statistics
 */
void signatures_print_stats(void);

/**
 * Get amplification signature list
 *
 * @param sigs  Output array
 * @param max   Maximum entries
 * @return Number of signatures
 */
uint32_t signatures_get_amplification_list(struct amplification_sig *sigs, uint32_t max);

/**
 * Get signature description
 *
 * @param sig_id  Signature ID
 * @return Description string or NULL
 */
const char* signatures_get_description(uint32_t sig_id);

#endif // SIGNATURES_H
