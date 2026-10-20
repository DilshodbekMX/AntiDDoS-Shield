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
 *    - TCP SYN scan (rapid SYNs to different ports): a SYN-only frame of
 *      60 bytes or less is only an indicator, see "SYN scan" below
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

/*
 * SYN scan (signature SIG_ID_SYN_SCAN)
 *
 * A SYN-only TCP frame of 60 bytes or less is what raw-socket scanners send:
 * no options (54 bytes) or MSS only (58 bytes), padded to the 60-byte Ethernet
 * minimum. Small TCP stacks such as lwIP send the same SYN, so the frame on
 * its own is weak evidence. signatures_check() counts every such frame
 * (syn_scan_indicators) and drops it only when its source also shows a scan
 * pattern in a per-source tracker of 1 s windows (SIG_SYN_SCAN_WINDOW_MS):
 *   - SYNs of this kind to destination ports that set SIG_SYN_SCAN_PORTS of
 *     the tracker's 16 port bits in one window, so at least that many
 *     distinct ports (a port scan), or
 *   - SIG_SYN_SCAN_SYNS or more of them in one window (a sweep, or a flood
 *     from one host; the rate of Stage 9b's default per-source SYN limit).
 * A source that meets either is dropped for the rest of that window and for
 * all of the next, so a scan that goes on is dropped from the first SYN of
 * each window, and a source that stops is admitted again within two windows.
 * Only these minimal SYNs are dropped: the same source's other traffic, and
 * any SYN with more options, is not affected.
 *
 * The tracker has SIG_SYN_SCAN_SLOTS fixed slots (no allocation, no growth).
 * A slot holds one source; another source that maps to a slot whose source
 * is scanning is not tracked (its SYN passes, counted in syn_scan_untracked),
 * so a source can never be dropped for another source's SYNs. (An IPv6 SYN
 * frame is at least 74 bytes and never matches, so only IPv4 sources, keyed
 * by their full address, are tracked.)
 *
 * signatures_config.strict_syn_scan (layer1 config signatures.strict_syn_scan)
 * restores the earlier rule, which dropped every such frame, and with it every
 * connection from a stack that sends such a SYN.
 */
#define SIG_ID_SYN_SCAN          2001   // "TCP SYN scan"
#define SIG_SYN_SCAN_WINDOW_MS   1000
#define SIG_SYN_SCAN_PORTS       8      // port bits per window (at least 8 distinct ports)
#define SIG_SYN_SCAN_SYNS        100    // SYNs per window
#define SIG_SYN_SCAN_SLOTS       4096   // tracker slots, 8 bytes each

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
    bool strict_syn_scan;    // drop every SIG_ID_SYN_SCAN frame (see above)
};

// Statistics
struct signatures_stats {
    uint64_t packets_checked;
    uint64_t signatures_matched;     // also the SIG_ID_SYN_SCAN frames that pass (SIG_ACTION_LOG)
    uint64_t amplification_detected;
    uint64_t scans_detected;         // scan matches acted on (dropped)
    uint64_t anomalies_detected;
    uint64_t attack_tools_detected;
    uint64_t packets_dropped;
    uint64_t packets_rate_limited;
    uint64_t syn_scan_indicators;    // SIG_ID_SYN_SCAN frames, dropped or not
    uint64_t syn_scan_dropped;       // of those, dropped (scan pattern, or strict_syn_scan)
    uint64_t syn_scan_untracked;     // of those, not tracked: they pass (see above)
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
 * @param match      Output: matched signature info (if any). A match that is
 *                   not acted on (a SIG_ID_SYN_SCAN frame whose source shows
 *                   no scan pattern) has action SIG_ACTION_LOG.
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

/**
 * Tracker slot of a source address (diagnostics and tests). Sources that
 * share a slot never share state: a slot records which one it holds.
 *
 * @param src_ip  Source IP (network byte order)
 * @return Slot index, below SIG_SYN_SCAN_SLOTS
 */
uint32_t signatures_syn_scan_slot(uint32_t src_ip);

/**
 * Port bit of a destination port in a tracker slot (diagnostics and tests):
 * the port rule counts the distinct bits a source's SYNs set in one window.
 *
 * @param dst_port  Destination port (host byte order)
 * @return Bit index, below 16
 */
uint32_t signatures_syn_scan_port_bit(uint16_t dst_port);

/**
 * Test seam: the TSC time that places a SYN in its tracker window. The
 * library's weak definition returns rte_get_tsc_cycles(); a unit test may
 * link its own to hold the clock or move it by whole windows.
 */
uint64_t signatures_scan_clock(void);

#endif // SIGNATURES_H
