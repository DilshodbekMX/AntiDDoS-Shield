#ifndef PER_IP_FEATURES_H
#define PER_IP_FEATURES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <rte_hash.h>
#include <rte_lcore.h>
#include <rte_spinlock.h>
#include "hyperloglog.h"

// Maximum lcores for per-IP tracking (use DPDK's RTE_MAX_LCORE)
#define PER_IP_MAX_LCORES RTE_MAX_LCORE

/**
 * @file per_ip_features.h
 * @brief Per-Protected-IP Feature Tracking with Full Layer 2 Features
 *
 * Unified feature extraction for per-IP anomaly detection.
 * Each protected destination IP gets its own complete set of features
 * including HyperLogLog cardinality and Count-Min Sketch concentration.
 *
 * Features per IP (20 features for EWMA/CUSUM anomaly detection):
 *
 * VOLUME (3):
 *   - packets_per_sec, bytes_per_sec, flows_per_sec
 *
 * TCP FLAGS (5):
 *   - syn_per_sec, syn_ack_per_sec, ack_per_sec, rst_per_sec, fin_per_sec
 *
 * PROTOCOL MIX (3):
 *   - tcp_ratio, udp_ratio, icmp_ratio
 *
 * RATIOS (3):
 *   - syn_ack_ratio, rst_syn_ratio, bytes_per_packet
 *
 * CARDINALITY (3) - HyperLogLog (using global hyperloglog module):
 *   - unique_src_ips, unique_dst_ports, unique_flows
 *
 * CHURN (1):
 *   - src_ip_churn
 *
 * CONCENTRATION (3) - Count-Min Sketch:
 *   - max_flow_fraction, topk_flow_share, heavy_hitter_count
 *
 * FLOW BEHAVIOR (2):
 *   - avg_packets_per_flow, flow_duration_avg_ms
 *
 * Memory per IP: ~100KB (3 HLLs @ 16KB + CMS ~50KB + counters)
 * With 100 protected IPs: ~10MB
 * With 1000 protected IPs: ~100MB
 *
 * Thread Safety:
 * - Fast path: Per-lcore counters (no atomics needed)
 * - Control path: Aggregates per-lcore counters
 * - HLL/CMS updates: Lock-free atomic operations
 */

// ==================== Configuration ====================

#define MAX_PROTECTED_IPS       1000

// CMS configuration per IP (smaller than global CMS)
#define PER_IP_CMS_WIDTH        16384   // 2^14 - good for per-IP tracking
#define PER_IP_CMS_DEPTH        4       // 4 hash functions
#define PER_IP_TOPK_COUNT       10      // Track top 10 flows
#define PER_IP_HEAVY_HITTER_PCT 5       // 5% threshold for heavy hitter

// ==================== Per-IP Counters (per-lcore) ====================

/**
 * Per-lcore counters for a single protected IP
 * These are incremented in the fast path without atomics
 */
struct per_ip_lcore_counters {
    // Volume
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t new_flows;

    // Protocol counters
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_packets;

    // TCP flag counters
    uint64_t syn_packets;       // Pure SYN (no ACK)
    uint64_t syn_ack_packets;   // SYN+ACK
    uint64_t ack_packets;       // Any ACK
    uint64_t rst_packets;       // RST
    uint64_t fin_packets;       // FIN

    uint64_t _pad[3];           // Pad to 128 bytes (2 cache lines)
} __attribute__((aligned(64)));

// ==================== Per-IP HLL Structure ====================

/**
 * HyperLogLog instances for a single protected IP
 * Uses the global hyperloglog module (not duplicate implementation)
 */
struct per_ip_hll {
    struct hyperloglog src_ip;      // Unique source IPs
    struct hyperloglog src_port;    // Unique source ports
    struct hyperloglog dst_port;    // Unique destination ports (carpet bomb detection)
    struct hyperloglog flows;       // Unique flows
};

// ==================== Per-IP CMS Structure ====================

/**
 * Count-Min Sketch for concentration metrics per IP
 * Tracks heavy hitters and flow distribution
 */
struct per_ip_cms {
    uint32_t *counters;             // Flat array [depth * width]
    uint32_t width;
    uint32_t depth;
    uint32_t seeds[PER_IP_CMS_DEPTH];
    uint64_t total_count;
    uint64_t window_count;

    // Top-K / heavy-hitter tracking for the concentration features
    // (max_flow_fraction, topk_flow_share, heavy_hitter_count). A Space-Saving
    // table over the K = PER_IP_TOPK_COUNT largest flows this window. The CMS
    // counters above are lock-free atomics; this small table is touched per
    // packet and read once per window, so it is guarded by its own spinlock
    // (per-destination -- contention only among lcores hitting the same dst IP).
    rte_spinlock_t topk_lock;
    uint32_t topk_keys[PER_IP_TOPK_COUNT];   // flow hashes of the K largest flows
    uint32_t topk_counts[PER_IP_TOPK_COUNT]; // their CMS-estimated counts
    uint32_t topk_n;                         // occupied slots (<= PER_IP_TOPK_COUNT)
    uint32_t max_flow_count;                 // largest single-flow estimate this window
};

// ==================== Per-IP Feature State ====================

/**
 * Complete feature state for a single protected IP
 * Contains per-lcore counters, HLL, and CMS
 */
struct per_ip_features {
    uint32_t dst_ip;                    // Protected IP (network byte order)
    uint32_t active;                    // 1 if registered, 0 if slot is free

    // Per-lcore counters (no contention in fast path)
    struct per_ip_lcore_counters lcore_counters[RTE_MAX_LCORE];

    // Aggregated counters (updated by control path)
    struct {
        uint64_t rx_packets;
        uint64_t rx_bytes;
        uint64_t new_flows;
        uint64_t tcp_packets;
        uint64_t udp_packets;
        uint64_t icmp_packets;
        uint64_t other_packets;
        uint64_t syn_packets;
        uint64_t syn_ack_packets;
        uint64_t ack_packets;
        uint64_t rst_packets;
        uint64_t fin_packets;
    } aggregated;

    // Previous aggregated (for rate calculation)
    struct {
        uint64_t rx_packets;
        uint64_t rx_bytes;
        uint64_t new_flows;
        uint64_t tcp_packets;
        uint64_t udp_packets;
        uint64_t icmp_packets;
        uint64_t other_packets;
        uint64_t syn_packets;
        uint64_t syn_ack_packets;
        uint64_t ack_packets;
        uint64_t rst_packets;
        uint64_t fin_packets;
        uint64_t timestamp_ns;
    } previous;

    // HyperLogLog for cardinality (uses global hyperloglog module)
    struct per_ip_hll hll;

    // Previous HLL cardinalities (for churn calculation)
    uint32_t prev_unique_src_ips;
    uint32_t prev_unique_src_ports;
    uint32_t prev_unique_dst_ports;
    uint32_t prev_unique_flows;

    // Count-Min Sketch for concentration metrics
    struct per_ip_cms cms;

    // Flow behavior tracking
    uint64_t total_flow_packets;        // Sum of packets across all flows
    uint64_t total_flow_duration_ms;    // Sum of flow durations
    uint32_t completed_flows;           // Flows that have ended
    uint32_t _pad2;

    // Metadata
    uint64_t created_ns;
    uint64_t last_packet_ns;
    uint64_t total_packets;

} __attribute__((aligned(64)));

// ==================== Exported Features (for Layer 2/3) ====================

/**
 * Feature snapshot for a single protected IP
 * This is what Layer 2/3 anomaly detection receives
 * Matches the structure in shared_memory.h (l2_features_export)
 */
struct per_ip_feature_snapshot {
    uint32_t dst_ip;                    // Protected IP (network byte order)

    // Timestamp
    uint64_t timestamp_ns;
    uint64_t window_duration_ns;

    // ===== VOLUME FEATURES =====
    uint64_t packets_per_sec;
    uint64_t bytes_per_sec;
    uint32_t flows_per_sec;

    // ===== TCP FLAG FEATURES =====
    uint32_t syn_per_sec;
    uint32_t syn_ack_per_sec;
    uint32_t ack_per_sec;
    uint32_t rst_per_sec;
    uint32_t fin_per_sec;

    // ===== PROTOCOL MIX FEATURES =====
    uint32_t tcp_packets;
    uint32_t udp_packets;
    uint32_t icmp_packets;
    uint32_t other_packets;
    uint8_t  tcp_ratio;                 // 0-100
    uint8_t  udp_ratio;                 // 0-100
    uint8_t  icmp_ratio;                // 0-100
    uint8_t  _pad1;

    // ===== RATIO FEATURES =====
    uint16_t syn_ack_ratio;             // SYN/ACK * 100
    uint16_t rst_syn_ratio;             // RST/SYN * 100
    uint16_t bytes_per_packet;
    uint16_t _pad2;

    // ===== CARDINALITY FEATURES (HyperLogLog) =====
    uint32_t unique_src_ips;
    uint32_t unique_src_ports;
    uint32_t unique_dst_ports;          // For carpet bomb / port scan detection
    uint32_t unique_flows;

    // ===== CHURN FEATURES =====
    int32_t  src_ip_churn;              // Change in unique IPs vs previous
    int32_t  dst_port_churn;            // Change in unique dst ports vs previous
    int32_t  expired_srcip_rate;        // Expired src IPs (placeholder)

    // ===== CONCENTRATION FEATURES (Count-Min Sketch) =====
    uint8_t  max_flow_fraction;         // Top flow as % of total (0-100)
    uint8_t  topk_flow_share;           // Top-K flows as % of total (0-100)
    uint16_t heavy_hitter_count;        // Number of heavy hitters detected

    // ===== FLOW BEHAVIOR FEATURES =====
    uint16_t avg_packets_per_flow;
    uint32_t flow_duration_avg_ms;

    // ===== METADATA =====
    uint32_t active_flows;              // Current active flows for this IP
    uint32_t sample_count;
    uint64_t total_packets;             // Total packets since creation

    // ===== EXTENDED FEATURES =====
    uint8_t small_pkt_ratio;
    uint8_t tcp_completion_rate;
    uint8_t fragment_ratio;
    uint8_t src_port_entropy;
    uint8_t ttl_mean;
} __attribute__((packed));

// ==================== Public API ====================

/**
 * Initialize per-IP feature tracking
 *
 * @param max_ips  Maximum number of protected IPs to track
 * @return 0 on success, -1 on error
 */
int per_ip_features_init(uint32_t max_ips);

/**
 * Cleanup per-IP feature tracking
 */
void per_ip_features_cleanup(void);

/**
 * Check if per-IP features are initialized
 */
bool per_ip_features_is_initialized(void);

/**
 * Enable/disable the CMS concentration export (max_flow_fraction, topk_flow_share,
 * heavy_hitter_count) that feeds the section 4.8 concentration THRESHOLD rule.
 *
 * Default: DISABLED. When disabled, the three concentration fields export as 0 and the
 * per-packet top-K maintenance is skipped entirely (zero added cost) -- i.e. the shipped
 * detector behaves exactly as before this feature existed. Enable it consciously after
 * validating false-positive behaviour on benign destinations dominated by a single
 * legitimate elephant flow (large download / backup / video), which can sit above the
 * 30 % threshold. This mirrors the opt-in gating of the conformal ensemble rule.
 */
void per_ip_features_set_concentration_export(bool enabled);

/**
 * Query whether the CMS concentration export is currently enabled.
 */
bool per_ip_features_concentration_export_enabled(void);

/**
 * Register a protected IP for tracking
 * Called when a protected IP is added
 *
 * @param dst_ip  Protected IP (network byte order)
 * @return 0 on success, -1 on error (table full or already exists)
 */
int per_ip_features_register(uint32_t dst_ip);

/**
 * Unregister a protected IP
 * Called when a protected IP is removed
 *
 * @param dst_ip  Protected IP (network byte order)
 * @return 0 on success, -1 if not found
 */
int per_ip_features_unregister(uint32_t dst_ip);

/**
 * Lookup per-IP features structure (fast path)
 * Returns pointer to per-IP features for updating counters
 *
 * @param dst_ip  Destination IP (network byte order)
 * @return Pointer to per_ip_features or NULL if not a protected IP
 */
struct per_ip_features* per_ip_features_lookup(uint32_t dst_ip);

// ==================== Fast Path API ====================

/**
 * Update per-IP counters from packet (call from fast path)
 * Extremely lightweight - just counter increments
 *
 * @param pif       Per-IP features structure (from lookup)
 * @param protocol  IP protocol (IPPROTO_TCP, etc.)
 * @param tcp_flags TCP flags (if TCP, 0 otherwise)
 * @param pkt_len   Packet length
 * @param src_ip    Source IP (for HLL, network byte order)
 * @param src_port  Source port (for HLL, host byte order)
 * @param dst_port  Destination port (for HLL, host byte order) - carpet bomb detection
 * @param flow_hash Flow hash (for HLL and CMS)
 * @param is_new_flow  True if this is a new flow
 */
void per_ip_features_update(struct per_ip_features *pif,
                            uint8_t protocol,
                            uint8_t tcp_flags,
                            uint16_t pkt_len,
                            uint32_t src_ip,
                            uint16_t src_port,
                            uint16_t dst_port,
                            uint32_t flow_hash,
                            bool is_new_flow);

/**
 * Inline version for maximum performance
 * Only updates counters, not HLL/CMS (call per_ip_hll_update separately if needed)
 */
static inline void per_ip_features_update_counters(
    struct per_ip_features *pif,
    unsigned int lcore_id,
    uint8_t protocol,
    uint8_t tcp_flags,
    uint16_t pkt_len,
    bool is_new_flow)
{
    struct per_ip_lcore_counters *c = &pif->lcore_counters[lcore_id];

    c->rx_packets++;
    c->rx_bytes += pkt_len;

    if (is_new_flow) {
        c->new_flows++;
    }

    // Protocol counters
    if (protocol == 6) {  // TCP
        c->tcp_packets++;

        // TCP flags (assuming standard flag positions)
        #define TCP_FLAG_FIN 0x01
        #define TCP_FLAG_SYN 0x02
        #define TCP_FLAG_RST 0x04
        #define TCP_FLAG_ACK 0x10

        if ((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN) {
            c->syn_packets++;
        }
        if ((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
            c->syn_ack_packets++;
        }
        if (tcp_flags & TCP_FLAG_ACK) {
            c->ack_packets++;
        }
        if (tcp_flags & TCP_FLAG_RST) {
            c->rst_packets++;
        }
        if (tcp_flags & TCP_FLAG_FIN) {
            c->fin_packets++;
        }
    } else if (protocol == 17) {  // UDP
        c->udp_packets++;
    } else if (protocol == 1) {  // ICMP
        c->icmp_packets++;
    } else {
        c->other_packets++;
    }
}

/**
 * Increment new_flows counter for a per-IP feature entry
 * Called AFTER flow_table_lookup_or_create() confirms flow_created == true
 *
 * @param pif       Per-IP features structure (may be NULL)
 * @param lcore_id  Current lcore ID
 */
static inline void per_ip_increment_new_flow(struct per_ip_features *pif,
                                              unsigned int lcore_id) {
    if (pif && lcore_id < PER_IP_MAX_LCORES) {
        pif->lcore_counters[lcore_id].new_flows++;
    }
}

/**
 * Update extended per-IP counters (small packets, fragments, TTL sum)
 * Called from fast path after per_ip_features_update_counters().
 *
 * @param pif        Per-IP features structure
 * @param lcore_id   Current lcore ID
 * @param ttl        IP TTL value
 * @param pkt_size   Packet size
 * @param ip_flags   IP flags/fragment offset field
 */
void per_ip_features_update_extended(struct per_ip_features *pif,
                                     unsigned int lcore_id,
                                     uint8_t ttl,
                                     uint16_t pkt_size,
                                     uint16_t ip_flags);

/**
 * Update HLL and CMS for cardinality and concentration tracking
 * Can be sampled for performance (e.g., 1:10 packets)
 *
 * @param pif       Per-IP features structure
 * @param src_ip    Source IP (network byte order)
 * @param src_port  Source port (host byte order)
 * @param dst_port  Destination port (host byte order) - for carpet bomb detection
 * @param flow_hash Flow hash
 */
void per_ip_hll_cms_update(struct per_ip_features *pif,
                           uint32_t src_ip,
                           uint16_t src_port,
                           uint16_t dst_port,
                           uint32_t flow_hash);

/**
 * Update flow behavior metrics when a flow ends
 *
 * @param pif           Per-IP features structure
 * @param flow_packets  Number of packets in the completed flow
 * @param flow_duration_ms  Duration of the flow in milliseconds
 */
void per_ip_flow_complete(struct per_ip_features *pif,
                          uint32_t flow_packets,
                          uint32_t flow_duration_ms);

// ==================== Control Path API ====================

/**
 * Aggregate per-lcore counters for a single IP
 * Call from control path only
 *
 * @param pif  Per-IP features structure
 */
void per_ip_features_aggregate(struct per_ip_features *pif);

/**
 * Get feature snapshot for a protected IP
 * Aggregates counters, computes rates, queries HLL/CMS
 *
 * @param dst_ip  Protected IP (network byte order)
 * @param out     Output feature snapshot
 * @return 0 on success, -1 if IP not found
 */
int per_ip_features_snapshot(uint32_t dst_ip, struct per_ip_feature_snapshot *out);

/**
 * Get feature snapshots for all protected IPs
 * Returns array of snapshots
 *
 * @param out       Output array of snapshots
 * @param max_count Maximum snapshots to return
 * @return Number of snapshots returned
 */
uint32_t per_ip_features_snapshot_all(struct per_ip_feature_snapshot *out, uint32_t max_count);

/**
 * Reset window counters (call after snapshot to start new window)
 * Saves current aggregated as "previous" for rate calculation
 * Resets CMS window counters
 *
 * @param pif  Per-IP features structure
 */
void per_ip_features_reset_window(struct per_ip_features *pif);

/**
 * Reset all per-IP feature windows
 * Call this every second after collecting snapshots
 */
void per_ip_features_reset_all_windows(void);

// ==================== CMS API ====================

/**
 * Check if a flow is a heavy hitter for a specific protected IP
 *
 * @param pif       Per-IP features structure
 * @param flow_hash Flow hash to check
 * @return true if flow exceeds heavy hitter threshold
 */
bool per_ip_is_heavy_hitter(struct per_ip_features *pif, uint32_t flow_hash);

/**
 * Get estimated packet count for a flow
 *
 * @param pif       Per-IP features structure
 * @param flow_hash Flow hash to query
 * @return Estimated packet count
 */
uint32_t per_ip_get_flow_count(struct per_ip_features *pif, uint32_t flow_hash);

// ==================== Statistics ====================

/**
 * Get number of registered protected IPs
 */
uint32_t per_ip_features_count(void);

/**
 * Print per-IP feature statistics
 */
void per_ip_features_print_stats(void);

/**
 * Get memory usage
 */
size_t per_ip_features_memory_usage(void);

#endif // PER_IP_FEATURES_H
