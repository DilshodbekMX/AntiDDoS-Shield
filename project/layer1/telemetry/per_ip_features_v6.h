/**
 * @file per_ip_features_v6.h
 * @brief IPv6 Per-Protected-IP Feature Tracking
 *
 * Extension of per_ip_features.h for IPv6 support.
 * Uses rte_hash with 16-byte keys for IPv6 address lookup.
 *
 * Features per IP are identical to IPv4:
 * - Volume: packets_per_sec, bytes_per_sec, flows_per_sec
 * - TCP Flags: syn, syn_ack, ack, rst, fin per second
 * - Protocol Mix: tcp_ratio, udp_ratio, icmp_ratio
 * - Cardinality: unique_src_ips, unique_dst_ports, unique_flows (HLL)
 * - Concentration: heavy_hitter_count, topk_flow_share (CMS)
 * - Flow Behavior: avg_packets_per_flow, flow_duration_avg_ms
 */

#ifndef PER_IP_FEATURES_V6_H
#define PER_IP_FEATURES_V6_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <rte_hash.h>
#include <rte_lcore.h>
#include "hyperloglog.h"
#include "per_ip_features.h"  /* Reuse structures and definitions */

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== IPv6 Configuration ==================== */

#define MAX_PROTECTED_IPS_V6    500     /* Fewer IPv6 entries (larger keys) */

/* ==================== IPv6 Per-IP Counters (per-lcore) ==================== */

/**
 * Per-lcore counters for a single protected IPv6
 * Same structure as IPv4 for consistency
 */
struct per_ip_lcore_counters_v6 {
    /* Volume */
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t new_flows;

    /* Protocol counters */
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmpv6_packets;    /* ICMPv6 instead of ICMP */
    uint64_t other_packets;

    /* TCP flag counters */
    uint64_t syn_packets;
    uint64_t syn_ack_packets;
    uint64_t ack_packets;
    uint64_t rst_packets;
    uint64_t fin_packets;

    uint64_t _pad[3];           /* Pad to 128 bytes (2 cache lines) */
} __attribute__((aligned(64)));

/* ==================== IPv6 HLL Structure ==================== */

/**
 * HyperLogLog instances for a single protected IPv6
 */
struct per_ip_hll_v6 {
    struct hyperloglog src_ip;      /* Unique source IPv6s (full 128-bit) */
    struct hyperloglog src_port;    /* Unique source ports */
    struct hyperloglog dst_port;    /* Unique destination ports */
    struct hyperloglog flows;       /* Unique flows */
};

/* ==================== IPv6 CMS Structure ==================== */

/**
 * Count-Min Sketch for concentration metrics per IPv6
 */
struct per_ip_cms_v6 {
    uint32_t *counters;
    uint32_t width;
    uint32_t depth;
    uint32_t seeds[PER_IP_CMS_DEPTH];
    uint64_t total_count;
    uint64_t window_count;
};

/* ==================== IPv6 Feature State ==================== */

/**
 * Complete feature state for a single protected IPv6
 */
struct per_ip_features_v6 {
    uint8_t  dst_ip6[16];           /* Protected IPv6 (network byte order) */
    uint32_t active;                /* 1 if registered, 0 if slot is free */
    uint32_t _pad0;

    /* Per-lcore counters (no contention in fast path) */
    struct per_ip_lcore_counters_v6 lcore_counters[RTE_MAX_LCORE];

    /* Aggregated counters (updated by control path) */
    struct {
        uint64_t rx_packets;
        uint64_t rx_bytes;
        uint64_t new_flows;
        uint64_t tcp_packets;
        uint64_t udp_packets;
        uint64_t icmpv6_packets;
        uint64_t other_packets;
        uint64_t syn_packets;
        uint64_t syn_ack_packets;
        uint64_t ack_packets;
        uint64_t rst_packets;
        uint64_t fin_packets;
    } aggregated;

    /* Previous aggregated (for rate calculation) */
    struct {
        uint64_t rx_packets;
        uint64_t rx_bytes;
        uint64_t new_flows;
        uint64_t tcp_packets;
        uint64_t udp_packets;
        uint64_t icmpv6_packets;
        uint64_t other_packets;
        uint64_t syn_packets;
        uint64_t syn_ack_packets;
        uint64_t ack_packets;
        uint64_t rst_packets;
        uint64_t fin_packets;
        uint64_t timestamp_ns;
    } previous;

    /* HyperLogLog for cardinality */
    struct per_ip_hll_v6 hll;

    /* Previous HLL cardinalities (for churn calculation) */
    uint32_t prev_unique_src_ips;
    uint32_t prev_unique_src_ports;
    uint32_t prev_unique_dst_ports;
    uint32_t prev_unique_flows;

    /* Count-Min Sketch for concentration metrics */
    struct per_ip_cms_v6 cms;

    /* Flow behavior tracking */
    uint64_t total_flow_packets;
    uint64_t total_flow_duration_ms;
    uint32_t completed_flows;
    uint32_t _pad1;

    /* Metadata */
    uint64_t created_ns;
    uint64_t last_packet_ns;
    uint64_t total_packets;

    /* Burst factor state (Phase 2) -- same protocol as the IPv4 struct: EWMA of the
     * per-window packet rate (burst_ewma.h), committed once per window in
     * per_ip_features_v6_reset_window(); the snapshot previews the ratio and parks
     * this window's rate for the commit. Not part of the shared-memory layout. */
    double   burst_ewma_pps;
    uint64_t burst_window_pps;
    uint32_t burst_window_valid;
    uint32_t _pad2;

} __attribute__((aligned(64)));

/* ==================== IPv6 Feature Snapshot ==================== */

/**
 * Feature snapshot for a single protected IPv6
 */
struct per_ip_feature_snapshot_v6 {
    uint8_t  dst_ip6[16];               /* Protected IPv6 (network byte order) */

    /* Timestamp */
    uint64_t timestamp_ns;
    uint64_t window_duration_ns;

    /* ===== VOLUME FEATURES ===== */
    uint64_t packets_per_sec;
    uint64_t bytes_per_sec;
    uint32_t flows_per_sec;

    /* ===== TCP FLAG FEATURES ===== */
    uint32_t syn_per_sec;
    uint32_t syn_ack_per_sec;
    uint32_t ack_per_sec;
    uint32_t rst_per_sec;
    uint32_t fin_per_sec;

    /* ===== PROTOCOL MIX FEATURES ===== */
    uint32_t tcp_packets;
    uint32_t udp_packets;
    uint32_t icmpv6_packets;
    uint32_t other_packets;
    uint8_t  tcp_ratio;                 /* 0-100 */
    uint8_t  udp_ratio;                 /* 0-100 */
    uint8_t  icmpv6_ratio;              /* 0-100 */
    uint8_t  _pad1;

    /* ===== RATIO FEATURES ===== */
    uint16_t syn_ack_ratio;             /* SYN/ACK * 100 */
    uint16_t rst_syn_ratio;             /* RST/SYN * 100 */
    uint16_t bytes_per_packet;
    uint16_t _pad2;

    /* ===== CARDINALITY FEATURES (HyperLogLog) ===== */
    uint32_t unique_src_ips;
    uint32_t unique_src_ports;
    uint32_t unique_dst_ports;
    uint32_t unique_flows;

    /* ===== CHURN FEATURES ===== */
    int32_t  src_ip_churn;
    int32_t  dst_port_churn;
    int32_t  expired_srcip_rate;

    /* ===== CONCENTRATION FEATURES (Count-Min Sketch) ===== */
    uint8_t  max_flow_fraction;
    uint8_t  topk_flow_share;
    uint16_t heavy_hitter_count;

    /* ===== FLOW BEHAVIOR FEATURES ===== */
    uint16_t avg_packets_per_flow;
    uint32_t flow_duration_avg_ms;

    /* ===== METADATA ===== */
    uint32_t active_flows;
    uint32_t sample_count;
    uint64_t total_packets;

    /* ===== BURST FEATURE (Phase 2) ===== */
    uint16_t burst_factor;              /* 100 * window_pps / post-update per-IP EWMA; <= 100/alpha */
} __attribute__((packed));

/* ==================== IPv6 Public API ==================== */

/**
 * Initialize IPv6 per-IP feature tracking
 *
 * @param max_ips  Maximum number of protected IPv6 addresses
 * @return 0 on success, -1 on error
 */
int per_ip_features_v6_init(uint32_t max_ips);

/**
 * Cleanup IPv6 per-IP feature tracking
 */
void per_ip_features_v6_cleanup(void);

/**
 * Check if IPv6 per-IP features are initialized
 */
bool per_ip_features_v6_is_initialized(void);

/**
 * Register a protected IPv6 for tracking
 *
 * @param dst_ip6  Protected IPv6 (16 bytes, network byte order)
 * @return 0 on success, -1 on error
 */
int per_ip_features_v6_register(const uint8_t dst_ip6[16]);

/**
 * Unregister a protected IPv6
 *
 * @param dst_ip6  Protected IPv6 (16 bytes, network byte order)
 * @return 0 on success, -1 if not found
 */
int per_ip_features_v6_unregister(const uint8_t dst_ip6[16]);

/**
 * Lookup per-IP features structure (fast path)
 *
 * @param dst_ip6  Destination IPv6 (16 bytes, network byte order)
 * @return Pointer to per_ip_features_v6 or NULL if not protected
 */
struct per_ip_features_v6* per_ip_features_v6_lookup(const uint8_t dst_ip6[16]);

/* ==================== IPv6 Fast Path API ==================== */

/**
 * Update per-IP counters from packet (call from fast path)
 *
 * @param pif       Per-IP features structure (from lookup)
 * @param protocol  IP protocol (IPPROTO_TCP, etc.)
 * @param tcp_flags TCP flags (if TCP, 0 otherwise)
 * @param pkt_len   Packet length
 * @param src_ip6   Source IPv6 (for HLL, network byte order)
 * @param src_port  Source port (host byte order)
 * @param dst_port  Destination port (host byte order)
 * @param flow_hash Flow hash
 * @param is_new_flow  True if this is a new flow
 */
void per_ip_features_v6_update(struct per_ip_features_v6 *pif,
                               uint8_t protocol,
                               uint8_t tcp_flags,
                               uint16_t pkt_len,
                               const uint8_t src_ip6[16],
                               uint16_t src_port,
                               uint16_t dst_port,
                               uint32_t flow_hash,
                               bool is_new_flow);

/**
 * Inline counter update for maximum performance
 */
static inline void per_ip_features_v6_update_counters(
    struct per_ip_features_v6 *pif,
    unsigned int lcore_id,
    uint8_t protocol,
    uint8_t tcp_flags,
    uint16_t pkt_len,
    bool is_new_flow)
{
    struct per_ip_lcore_counters_v6 *c = &pif->lcore_counters[lcore_id];

    c->rx_packets++;
    c->rx_bytes += pkt_len;

    if (is_new_flow) {
        c->new_flows++;
    }

    /* Protocol counters */
    if (protocol == 6) {  /* TCP */
        c->tcp_packets++;

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
    } else if (protocol == 17) {  /* UDP */
        c->udp_packets++;
    } else if (protocol == 58) {  /* ICMPv6 */
        c->icmpv6_packets++;
    } else {
        c->other_packets++;
    }
}

/**
 * Increment new_flows counter for IPv6
 */
static inline void per_ip_v6_increment_new_flow(struct per_ip_features_v6 *pif,
                                                 unsigned int lcore_id) {
    if (pif && lcore_id < RTE_MAX_LCORE) {
        pif->lcore_counters[lcore_id].new_flows++;
    }
}

/**
 * Update HLL and CMS for IPv6 cardinality tracking
 *
 * @param pif       Per-IP features structure
 * @param src_ip6   Source IPv6 (16 bytes)
 * @param src_port  Source port (host byte order)
 * @param dst_port  Destination port (host byte order)
 * @param flow_hash Flow hash
 */
void per_ip_hll_cms_v6_update(struct per_ip_features_v6 *pif,
                              const uint8_t src_ip6[16],
                              uint16_t src_port,
                              uint16_t dst_port,
                              uint32_t flow_hash);

/**
 * Update flow behavior metrics when a flow ends
 */
void per_ip_v6_flow_complete(struct per_ip_features_v6 *pif,
                             uint32_t flow_packets,
                             uint32_t flow_duration_ms);

/* ==================== IPv6 Control Path API ==================== */

/**
 * Aggregate per-lcore counters for a single IPv6
 */
void per_ip_features_v6_aggregate(struct per_ip_features_v6 *pif);

/**
 * Get feature snapshot for a protected IPv6
 *
 * @param dst_ip6  Protected IPv6 (16 bytes, network byte order)
 * @param out      Output feature snapshot
 * @return 0 on success, -1 if IP not found
 */
int per_ip_features_v6_snapshot(const uint8_t dst_ip6[16],
                                struct per_ip_feature_snapshot_v6 *out);

/**
 * Get feature snapshots for all protected IPv6s
 *
 * @param out       Output array of snapshots
 * @param max_count Maximum snapshots to return
 * @return Number of snapshots returned
 */
uint32_t per_ip_features_v6_snapshot_all(struct per_ip_feature_snapshot_v6 *out,
                                         uint32_t max_count);

/**
 * Reset window counters for IPv6
 */
void per_ip_features_v6_reset_window(struct per_ip_features_v6 *pif);

/**
 * Reset all IPv6 per-IP feature windows
 */
void per_ip_features_v6_reset_all_windows(void);

/* ==================== IPv6 CMS API ==================== */

/**
 * Check if a flow is a heavy hitter for a specific protected IPv6
 */
bool per_ip_v6_is_heavy_hitter(struct per_ip_features_v6 *pif, uint32_t flow_hash);

/**
 * Get estimated packet count for a flow
 */
uint32_t per_ip_v6_get_flow_count(struct per_ip_features_v6 *pif, uint32_t flow_hash);

/* ==================== IPv6 Statistics ==================== */

/**
 * Get number of registered protected IPv6s
 */
uint32_t per_ip_features_v6_count(void);

/**
 * Print IPv6 per-IP feature statistics
 */
void per_ip_features_v6_print_stats(void);

/**
 * Get IPv6 memory usage
 */
size_t per_ip_features_v6_memory_usage(void);

/* ==================== Dual-Stack Unified API ==================== */

/**
 * Lookup per-IP features for either IPv4 or IPv6
 *
 * @param ip       Pointer to IP address (4 bytes for v4, 16 for v6)
 * @param is_ipv6  true for IPv6, false for IPv4
 * @return Pointer to features structure or NULL if not protected
 *
 * Note: Return type is void* - caller must cast to appropriate type
 */
void* per_ip_features_lookup_unified(const void *ip, bool is_ipv6);

/**
 * Register a protected IP (v4 or v6)
 *
 * @param ip       Pointer to IP address
 * @param is_ipv6  true for IPv6, false for IPv4
 * @return 0 on success, -1 on error
 */
int per_ip_features_register_unified(const void *ip, bool is_ipv6);

/**
 * Unregister a protected IP (v4 or v6)
 *
 * @param ip       Pointer to IP address
 * @param is_ipv6  true for IPv6, false for IPv4
 * @return 0 on success, -1 if not found
 */
int per_ip_features_unregister_unified(const void *ip, bool is_ipv6);

/**
 * Print combined IPv4 + IPv6 statistics
 */
void per_ip_features_print_stats_all(void);

#ifdef __cplusplus
}
#endif

#endif /* PER_IP_FEATURES_V6_H */
