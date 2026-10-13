#ifndef LAYER1_UDP_GATEKEEPER_H
#define LAYER1_UDP_GATEKEEPER_H

#include <stdint.h>
#include <stdbool.h>

// Forward declaration for per_ip_anomaly_snapshot
struct per_ip_anomaly_snapshot;

/**
 * @file udp_gatekeeper.h
 * @brief UDP Admission Control - Protects flow table from UDP floods
 *
 * Problem: Unlike TCP, UDP has no handshake for admission control.
 * SYN cookies prevent TCP flood attacks from filling the flow table,
 * but UDP packets immediately create full flow state.
 *
 * Solution: Two-tier admission control using Count-Min Sketch:
 *
 * Tier 1 - Rate Limiting (this module):
 *   - Track per-IP packet rate using Count-Min Sketch (O(1) space per IP)
 *   - Drop packets from IPs exceeding threshold BEFORE flow table lookup
 *   - Probabilistic: May slightly over-count (false positives = dropped legit packets)
 *   - Never under-counts (no false negatives = no attacker bypassing)
 *
 * Tier 2 - Flow Table (existing flow_table.c):
 *   - Only reached by packets that pass gatekeeper
 *   - Full flow state for legitimate UDP streams
 *   - Protected from exhaustion by Tier 1
 *
 * Memory: ~1MB for 65K width x 4 depth Count-Min Sketch
 * Performance: ~20-30 cycles per packet (CRC32 hardware accelerated)
 *
 * Usage:
 *   // Before flow_table_lookup_or_create() for UDP packets:
 *   if (features->protocol == IPPROTO_UDP) {
 *       enum udp_gk_action action = udp_gatekeeper_check(features->src_ip, features->packet_size);
 *       if (action == UDP_GK_DROP) {
 *           drop_packet();
 *           return;
 *       }
 *       // action == UDP_GK_ACCEPT: proceed to flow table
 *   }
 */

// ==================== Actions ====================

enum udp_gk_action {
    UDP_GK_ACCEPT = 0,      // Packet allowed through to flow table
    UDP_GK_DROP_RATE,       // Dropped: PPS threshold exceeded
    UDP_GK_DROP_BPS,        // Dropped: BPS threshold exceeded
    UDP_GK_DROP_REPUTATION, // Dropped: Known bad reputation
    UDP_GK_DROP_BLACKLIST,  // Dropped: IP is blacklisted
};

// ==================== Configuration ====================

struct udp_gatekeeper_config {
    // Rate limits per source IP
    uint32_t pps_threshold;          // Packets per second (default: 10000)
    uint32_t bps_threshold;          // Bytes per second (default: 10MB/s)

    // Count-Min Sketch dimensions
    uint32_t cms_width;              // Width (default: 65536)
    uint32_t cms_depth;              // Depth/hash functions (default: 4)

    // Time window
    uint32_t window_sec;             // Window duration (default: 1 second)

    // Integration options
    bool check_reputation;           // Also check reputation system
    uint16_t reputation_threshold;   // Block if reputation below this (default: 200)
    bool check_blacklist;            // Check IP blacklist

    // Attack mode multipliers (applied when anomaly_active)
    uint32_t attack_pps_divisor;     // pps_threshold / divisor during attack (default: 4)
    uint32_t attack_bps_divisor;     // bps_threshold / divisor during attack (default: 4)
};

// ==================== Statistics ====================

struct udp_gatekeeper_stats {
    uint64_t packets_checked;        // Total UDP packets checked
    uint64_t packets_accepted;       // Packets allowed through
    uint64_t drops_pps;              // Dropped due to PPS
    uint64_t drops_bps;              // Dropped due to BPS
    uint64_t drops_reputation;       // Dropped due to bad reputation
    uint64_t drops_blacklist;        // Dropped due to blacklist
    uint64_t unique_ips_approx;      // Approximate unique IPs (from CMS stats)
    uint64_t cms_rotations;          // CMS window rotations
};

// ==================== Public API ====================

/**
 * Initialize UDP gatekeeper.
 *
 * @param config  Configuration (NULL for defaults)
 * @return 0 on success, -1 on error
 */
int udp_gatekeeper_init(const struct udp_gatekeeper_config *config);

/**
 * Cleanup UDP gatekeeper.
 */
void udp_gatekeeper_cleanup(void);

/**
 * Check if UDP packet should be admitted.
 * Call this BEFORE flow_table_lookup_or_create() for UDP packets.
 *
 * This is the hot path function - optimized for speed.
 *
 * @param src_ip       Source IP (network byte order)
 * @param packet_size  Packet size in bytes
 * @param ip_anom      Per-IP anomaly snapshot (may be NULL)
 * @return Action to take (UDP_GK_ACCEPT or UDP_GK_DROP_*)
 */
enum udp_gk_action udp_gatekeeper_check(uint32_t src_ip, uint16_t packet_size,
                                        const struct per_ip_anomaly_snapshot *ip_anom);

/**
 * Combined check and increment.
 * More efficient than separate check + manual counter update.
 *
 * @param src_ip       Source IP (network byte order)
 * @param packet_size  Packet size in bytes
 * @param pps_out      Output: current packets per second for this IP
 * @param bps_out      Output: current bytes per second for this IP
 * @return Action to take
 */
enum udp_gk_action udp_gatekeeper_check_detailed(uint32_t src_ip, uint16_t packet_size,
                                                  uint32_t *pps_out, uint32_t *bps_out);

/**
 * Get current rate for an IP without incrementing.
 * Useful for monitoring/debugging.
 *
 * @param src_ip   Source IP (network byte order)
 * @param pps_out  Output: estimated PPS
 * @param bps_out  Output: estimated BPS
 */
void udp_gatekeeper_get_rate(uint32_t src_ip, uint32_t *pps_out, uint32_t *bps_out);

/**
 * Get statistics.
 *
 * @param stats  Output statistics structure
 */
void udp_gatekeeper_get_stats(struct udp_gatekeeper_stats *stats);

/**
 * Print statistics to stdout.
 */
void udp_gatekeeper_print_stats(void);

/**
 * Force window rotation (for maintenance).
 */
void udp_gatekeeper_rotate(void);

/**
 * Clear all rate tracking.
 */
void udp_gatekeeper_clear(void);

/**
 * Update configuration dynamically.
 * Only rate thresholds can be changed after init.
 *
 * @param pps_threshold  New PPS threshold (0 = no change)
 * @param bps_threshold  New BPS threshold (0 = no change)
 */
void udp_gatekeeper_set_thresholds(uint32_t pps_threshold, uint32_t bps_threshold);

/**
 * Get current effective thresholds (accounting for attack mode).
 *
 * @param pps_out  Output: effective PPS threshold
 * @param bps_out  Output: effective BPS threshold
 */
void udp_gatekeeper_get_effective_thresholds(uint32_t *pps_out, uint32_t *bps_out);

// ==================== Default Configuration ====================

#define UDP_GK_DEFAULT_PPS_THRESHOLD     10000       // 10K pps per IP
#define UDP_GK_DEFAULT_BPS_THRESHOLD     (10 << 20)  // 10 MB/s per IP
#define UDP_GK_DEFAULT_CMS_WIDTH         65536       // 64K buckets
#define UDP_GK_DEFAULT_CMS_DEPTH         4           // 4 hash functions
#define UDP_GK_DEFAULT_WINDOW_SEC        1           // 1 second window
#define UDP_GK_DEFAULT_REP_THRESHOLD     200         // Block if rep < 200
#define UDP_GK_DEFAULT_ATTACK_DIVISOR    4           // 4x stricter during attack

#endif // LAYER1_UDP_GATEKEEPER_H
