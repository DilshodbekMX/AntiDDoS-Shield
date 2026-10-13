/**
 * @file src_ip_stats.h
 * @brief Per-Source-IP Statistics for Attack Attribution
 *
 * Tracks behavior metrics per source IP to enable Layer 3 to identify attackers.
 * Uses a hash table for O(1) lookup during packet processing.
 *
 * Thread Safety:
 * - WRITERS (Layer 1 data plane lcores): Per-entry atomic updates
 * - READERS (Layer 3 Python): Snapshot-based reads with version checking
 * - Hash table uses DPDK rte_hash with RW concurrency support
 */

#ifndef SRC_IP_STATS_H
#define SRC_IP_STATS_H

#include <stdint.h>
#include <stdbool.h>
#include "../../common/types.h"

// ==================== Constants ====================

// Maximum source IPs to track (power of 2)
#define MAX_SRC_IP_ENTRIES 262144  // 256K entries

// Stats entry expiration (nanoseconds)
#define SRC_IP_STATS_EXPIRE_NS (300ULL * 1000000000ULL)  // 5 minutes

// Window size for rate calculations (nanoseconds)
#define SRC_IP_STATS_WINDOW_NS (1ULL * 1000000000ULL)  // 1 second

// ==================== Per-Source-IP Entry ====================

/**
 * Statistics tracked per source IP
 *
 * These features are used by Layer 3 for:
 * 1. Signature generation (common patterns across attackers)
 * 2. Behavioral clustering (grouping similar IPs)
 * 3. ML scoring (attack probability)
 *
 * Size: 128 bytes (2 cache lines)
 */
struct src_ip_entry {
    // ===== Identification =====
    uint32_t src_ip;                 // Source IP (network byte order)
    uint32_t flags;                  // Status flags (SRC_IP_FLAG_*)

    // ===== Timing =====
    uint64_t first_seen_ns;          // First packet timestamp
    uint64_t last_seen_ns;           // Last packet timestamp
    uint64_t window_start_ns;        // Current stats window start

    // ===== Volume Counters (current window) =====
    uint32_t packets_window;         // Packets in current window
    uint32_t bytes_window;           // Bytes in current window
    uint32_t flows_window;           // New flows in current window

    // ===== Volume Counters (total) =====
    uint64_t packets_total;          // Total packets
    uint64_t bytes_total;            // Total bytes
    uint32_t flows_total;            // Total flows

    // ===== Protocol Distribution =====
    uint16_t tcp_pkt_count;          // TCP packets in window
    uint16_t udp_pkt_count;          // UDP packets in window
    uint16_t icmp_pkt_count;         // ICMP packets in window
    uint16_t other_pkt_count;        // Other protocol packets

    // ===== TCP Behavior (for SYN flood detection) =====
    uint16_t syn_count;              // SYN packets in window
    uint16_t syn_ack_count;          // SYN-ACK packets
    uint16_t ack_count;              // ACK packets
    uint16_t rst_count;              // RST packets
    uint16_t fin_count;              // FIN packets
    uint16_t incomplete_handshakes;  // SYN without completing handshake

    // ===== Destination Diversity =====
    uint8_t  unique_dst_ports;       // Unique dst ports seen (capped at 255)
    uint8_t  unique_dst_ips;         // Unique dst IPs seen (capped at 255)

    // ===== Packet Characteristics =====
    uint16_t min_pkt_size;           // Minimum packet size seen
    uint16_t max_pkt_size;           // Maximum packet size seen
    uint16_t avg_pkt_size;           // Rolling average packet size
    uint8_t  min_ttl;                // Minimum TTL seen
    uint8_t  max_ttl;                // Maximum TTL seen

    // ===== TCP Option Fingerprint =====
    uint16_t tcp_mss_value;          // Most common MSS
    uint8_t  tcp_wscale_value;       // Most common window scale
    uint8_t  tcp_options_seen;       // Bitmap of TCP options

    // ===== Rate Metrics (calculated) =====
    uint32_t pps_current;            // Current packets per second
    uint32_t bps_current;            // Current bytes per second

    // ===== Mitigation State =====
    uint8_t  action;                 // Current action (POLICY_*)
    uint8_t  score;                  // Attack score (0-100, 0=legitimate)
    uint8_t  rate_limited;           // 1 if currently rate limited
    uint8_t  challenged;             // 1 if under challenge

    // ===== Version for concurrent access =====
    uint64_t version;                // Incremented on each update

    // Padding for alignment
    uint8_t  _pad[4];
} __attribute__((packed, aligned(64)));

// Verify size
_Static_assert(sizeof(struct src_ip_entry) == 128,
               "src_ip_entry must be 128 bytes");

// ==================== Status Flags ====================

#define SRC_IP_FLAG_ACTIVE       0x0001  // Entry is active
#define SRC_IP_FLAG_ATTACKER     0x0002  // Flagged as attacker
#define SRC_IP_FLAG_TRUSTED      0x0004  // Whitelisted/trusted
#define SRC_IP_FLAG_RATE_LIMITED 0x0008  // Currently rate limited
#define SRC_IP_FLAG_CHALLENGED   0x0010  // Under SYN cookie challenge
#define SRC_IP_FLAG_BLOCKED      0x0020  // Hard blocked
#define SRC_IP_FLAG_NEW          0x0040  // Newly seen this window

// TCP options bitmap
#define TCP_OPT_MSS      0x01
#define TCP_OPT_WSCALE   0x02
#define TCP_OPT_SACK     0x04
#define TCP_OPT_TIMESTAMP 0x08

// ==================== Packet Features (for update function) ====================

/**
 * Packet features extracted during parsing
 * Passed to src_ip_stats_update()
 */
struct src_pkt_features {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t pkt_size;
    uint8_t  protocol;
    uint8_t  ttl;
    uint8_t  tcp_flags;
    uint8_t  tcp_wscale;
    uint16_t tcp_mss;
    uint16_t tcp_window;
    uint8_t  tcp_options;  // Bitmap of options present
    uint8_t  is_new_flow;  // 1 if this is a new flow
};

// ==================== Statistics Table ====================

/**
 * Global statistics table header
 * Stored at the beginning of the table memory region
 */
struct src_ip_stats_table {
    uint64_t version;                // Global version
    uint32_t entry_count;            // Number of active entries
    uint32_t max_entries;            // Maximum entries (MAX_SRC_IP_ENTRIES)
    uint64_t last_cleanup_ns;        // Last expiration cleanup
    uint64_t total_updates;          // Total update operations
    uint64_t total_lookups;          // Total lookup operations
    uint64_t total_expired;          // Total entries expired

    uint8_t  _pad[24];
} __attribute__((aligned(64)));

// ==================== Public API ====================

/**
 * Initialize per-source-IP statistics tracking
 * @return 0 on success, -1 on failure
 */
int src_ip_stats_init(void);

/**
 * Cleanup and free resources
 */
void src_ip_stats_cleanup(void);

/**
 * Check if initialized
 */
bool src_ip_stats_is_initialized(void);

/**
 * Update statistics for a packet
 * Called from data plane for every packet (fast path)
 *
 * @param features  Extracted packet features
 * @return Pointer to updated entry, or NULL on error
 */
struct src_ip_entry *src_ip_stats_update(const struct src_pkt_features *features);

/**
 * Lookup entry for a source IP (read-only)
 *
 * @param src_ip  Source IP to lookup
 * @return Pointer to entry, or NULL if not found
 */
struct src_ip_entry *src_ip_stats_lookup(uint32_t src_ip);

/**
 * Get snapshot of entry (thread-safe copy)
 *
 * @param src_ip  Source IP to snapshot
 * @param out     Output buffer for snapshot
 * @return true if entry found and copied, false otherwise
 */
bool src_ip_stats_snapshot(uint32_t src_ip, struct src_ip_entry *out);

/**
 * Get all entries with packets in current window
 * For Layer 3 batch processing
 *
 * @param out       Output array
 * @param max_count Maximum entries to return
 * @return Number of entries copied
 */
uint32_t src_ip_stats_snapshot_active(struct src_ip_entry *out,
                                       uint32_t max_count);

/**
 * Get top N source IPs by packet count
 *
 * @param out       Output array
 * @param max_count Maximum entries to return
 * @return Number of entries copied
 */
uint32_t src_ip_stats_get_top_talkers(struct src_ip_entry *out,
                                       uint32_t max_count);

/**
 * Get entries flagged as attackers
 *
 * @param out       Output array
 * @param max_count Maximum entries to return
 * @return Number of entries copied
 */
uint32_t src_ip_stats_get_attackers(struct src_ip_entry *out,
                                     uint32_t max_count);

/**
 * Set action for a source IP (called by Layer 3/4)
 *
 * @param src_ip  Source IP
 * @param action  POLICY_ALLOW, POLICY_DROP, etc.
 * @param score   Attack score (0-100)
 */
void src_ip_stats_set_action(uint32_t src_ip, uint8_t action, uint8_t score);

/**
 * Mark IP as attacker
 */
void src_ip_stats_mark_attacker(uint32_t src_ip);

/**
 * Mark IP as trusted (whitelist)
 */
void src_ip_stats_mark_trusted(uint32_t src_ip);

/**
 * Clear flags for an IP
 */
void src_ip_stats_clear_flags(uint32_t src_ip, uint32_t flags);

/**
 * Expire old entries (called periodically)
 * @return Number of entries expired
 */
uint32_t src_ip_stats_expire_old(void);

/**
 * Reset per-window counters (called every window period)
 */
void src_ip_stats_reset_window(void);

/**
 * Get table statistics
 */
void src_ip_stats_get_stats(struct src_ip_stats_table *out);

/**
 * Print statistics summary
 */
void src_ip_stats_print(void);

#endif // SRC_IP_STATS_H
