#include "layer1.h"
#include "config/layer1_config.h"
#include "datapath/packet_parser.h"
#include "datapath/packet_features.h"
#include "datapath/l7_validator.h"
#include "tables/flow_table.h"
#include "tables/flow_table_v6.h"
#include "tables/ip_lists.h"
#include "tables/ip_lists_v6.h"
#include "tables/syn_proxy.h"
#include "tables/syn_proxy_v6.h"
#include "tables/connection_limits.h"
#include "tables/udp_gatekeeper.h"
#include "tables/geo_blocking.h"
#include "tables/geo_blocking_v6.h"
#include "tables/other_protocols.h"
#include "tables/signatures.h"
#include "tables/tcp_flag_rate_limit.h"
#include "tables/tcp_abuse_detection.h"
#include "interlayer/shared_memory.h"
#include "interlayer/policy_interface.h"
#include "interlayer/reputation_interface.h"
#include "interlayer/dynamic_signatures.h"
#include "interlayer/src_ip_stats.h"
#include "telemetry/telemetry_exporter.h"
#include "telemetry/hyperloglog.h"
#include "telemetry/per_ip_features.h"
#include "telemetry/per_ip_features_v6.h"
#include "telemetry/dpdk_telemetry.h"
#include "telemetry/realtime_telemetry.h"
#include "telemetry/window_stats.h"
#include "telemetry/latency_histogram.h"
#include "telemetry/spike_detector.h"
#include "../core/dpdk_core.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_mbuf.h>
#include <rte_random.h>
#include <rte_lcore.h>
#include <rte_hash_crc.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_log.h>

#define RTE_LOGTYPE_L1 RTE_LOGTYPE_USER2

// ==================== Drop Reason Helpers ====================

/**
 * Static string table for drop reason names
 * Index matches DROP_REASON_* codes
 */
static const char* drop_reason_names[] = {
    // General (0-9)
    [DROP_REASON_NONE]              = "none",
    [DROP_REASON_PARSE_ERROR]       = "parse_error",
    [DROP_REASON_VALIDATION]        = "validation",
    [DROP_REASON_OTHER_PROTO]       = "other_protocol",
    [DROP_REASON_PORT_NOT_ALLOWED]  = "port_not_allowed",
    [DROP_REASON_PROTO_BLOCKED]     = "proto_blocked",
    [DROP_REASON_PROTO_RATE_LIMIT]  = "proto_rate_limit",
    [7] = "reserved_7", [8] = "reserved_8", [9] = "reserved_9",

    // IP List Based (10-19)
    [DROP_REASON_BLACKLIST]         = "blacklist",
    [DROP_REASON_GEO_BLOCKED]       = "geo_blocked",
    [DROP_REASON_REPUTATION]        = "reputation",
    [13] = "reserved_13", [14] = "reserved_14", [15] = "reserved_15",
    [16] = "reserved_16", [17] = "reserved_17", [18] = "reserved_18",
    [19] = "reserved_19",

    // Rate Limiting (20-29)
    [DROP_REASON_RATE_LIMIT]        = "rate_limit",
    [DROP_REASON_RATE_LIMIT_PPS]    = "rate_limit_pps",
    [DROP_REASON_RATE_LIMIT_BPS]    = "rate_limit_bps",
    [DROP_REASON_RATE_LIMIT_SYN]    = "rate_limit_syn",
    [DROP_REASON_RATE_LIMIT_ACK]    = "rate_limit_ack",
    [DROP_REASON_RATE_LIMIT_RST]    = "rate_limit_rst",
    [DROP_REASON_RATE_LIMIT_FIN]    = "rate_limit_fin",
    [DROP_REASON_RATE_LIMIT_UDP]    = "rate_limit_udp",
    [DROP_REASON_RATE_LIMIT_ICMP]   = "rate_limit_icmp",
    [29] = "reserved_29",

    // Connection/Flow Limits (30-39)
    [DROP_REASON_CONN_LIMIT]        = "conn_limit",
    [DROP_REASON_CONN_LIMIT_SRC]    = "conn_limit_src",
    [DROP_REASON_CONN_LIMIT_DST]    = "conn_limit_dst",
    [DROP_REASON_CONN_LIMIT_GLOBAL] = "conn_limit_global",
    [DROP_REASON_FLOW_TABLE_FULL]   = "flow_table_full",
    [DROP_REASON_UDP_GATEKEEPER]    = "udp_gatekeeper",
    [36] = "reserved_36", [37] = "reserved_37", [38] = "reserved_38",
    [39] = "reserved_39",

    // SYN Proxy (40-49)
    [DROP_REASON_SYN_FLOOD]         = "syn_flood",
    [DROP_REASON_COOKIE_INVALID]    = "cookie_invalid",
    [DROP_REASON_COOKIE_EXPIRED]    = "cookie_expired",
    [DROP_REASON_PROXY_ERROR]       = "proxy_error",
    [DROP_REASON_PROXY_NO_CONN]     = "proxy_no_conn",
    [DROP_REASON_SPOOFED_TCP]       = "spoofed_tcp",
    [46] = "reserved_46", [47] = "reserved_47", [48] = "reserved_48",
    [49] = "reserved_49",

    // TCP Abuse Detection (50-59)
    [DROP_REASON_TCP_ABUSE]         = "tcp_abuse",
    [DROP_REASON_TCP_DUP_SEQ]       = "tcp_dup_seq",
    [DROP_REASON_TCP_RANDOM_SEQ]    = "tcp_random_seq",
    [DROP_REASON_TCP_RANDOM_ACK]    = "tcp_random_ack",
    [DROP_REASON_TCP_ZERO_WINDOW]   = "tcp_zero_window",
    [DROP_REASON_TCP_TINY_WINDOW]   = "tcp_tiny_window",
    [DROP_REASON_TCP_SAME_WINDOW]   = "tcp_same_window",
    [DROP_REASON_TCP_SAME_ACK]      = "tcp_same_ack",
    [DROP_REASON_TCP_INVALID_FLAGS] = "tcp_invalid_flags",
    [59] = "reserved_59",

    // Signature/Policy (60-69)
    [DROP_REASON_SIGNATURE]         = "signature",
    [DROP_REASON_SIGNATURE_AMP]     = "signature_amp",
    [DROP_REASON_SIGNATURE_SCAN]    = "signature_scan",
    [DROP_REASON_SIGNATURE_TOOL]    = "signature_tool",
    [DROP_REASON_POLICY]            = "policy",
    [DROP_REASON_POLICY_CHALLENGE]  = "policy_challenge",
    [66] = "reserved_66", [67] = "reserved_67", [68] = "reserved_68",
    [69] = "reserved_69",

    // Protocol Validation (70-79)
    [DROP_REASON_IP_MALFORMED]      = "ip_malformed",
    [DROP_REASON_IP_TTL_ZERO]       = "ip_ttl_zero",
    [DROP_REASON_IP_CHECKSUM]       = "ip_checksum",
    [DROP_REASON_TCP_MALFORMED]     = "tcp_malformed",
    [DROP_REASON_TCP_CHECKSUM]      = "tcp_checksum",
    [DROP_REASON_UDP_MALFORMED]     = "udp_malformed",
    [DROP_REASON_UDP_CHECKSUM]      = "udp_checksum",
    [DROP_REASON_ICMP_MALFORMED]    = "icmp_malformed",
    [DROP_REASON_IPV6_UNSUPPORTED]  = "ipv6_unsupported",
    [79] = "reserved_79",

    // Table/Resource Limits (80-89)
    [DROP_REASON_TABLE_FULL]        = "table_full",
    [DROP_REASON_MEMPOOL_EMPTY]     = "mempool_empty",
    [DROP_REASON_RING_FULL]         = "ring_full",
    [83] = "reserved_83", [84] = "reserved_84", [85] = "reserved_85",
    [86] = "reserved_86", [87] = "reserved_87", [88] = "reserved_88",
    [89] = "reserved_89",
};

const char* drop_reason_to_string(uint8_t reason) {
    if (reason >= DROP_REASON_MAX) {
        return "unknown";
    }
    const char* name = drop_reason_names[reason];
    return name ? name : "unknown";
}

uint8_t drop_reason_to_category(uint8_t reason) {
    if (reason < 10) return DROP_CAT_GENERAL;
    if (reason < 20) return DROP_CAT_IP_LIST;
    if (reason < 30) return DROP_CAT_RATE_LIMIT;
    if (reason < 40) return DROP_CAT_CONN_LIMIT;
    if (reason < 50) return DROP_CAT_SYN_PROXY;
    if (reason < 60) return DROP_CAT_TCP_ABUSE;
    if (reason < 70) return DROP_CAT_SIGNATURE;
    if (reason < 80) return DROP_CAT_VALIDATION;
    if (reason < 90) return DROP_CAT_RESOURCE;
    return DROP_CAT_GENERAL;
}

// ==================== Global State ====================

// Use atomic operations for initialized flag to ensure cross-core visibility
// Plain bool with double-checked locking pattern is unsafe without atomics
static uint32_t initialized_atomic = 0;  // 0 = not initialized, 1 = initialized
static uint32_t max_flows_configured = 0;
static uint64_t validation_errors[32] = {0};  // Space for all VALIDATE_ERR_* codes
// Use atomic for should_decrement_ttl - written by control thread, read by worker lcores
// Plain bool can have torn reads and compiler may cache the value indefinitely
static uint32_t should_decrement_ttl_atomic = 0;  // 0 = don't decrement (L2 bridge), 1 = decrement (L3 router)
// Use atomic operations instead of volatile for cross-core visibility
// volatile does NOT provide atomicity guarantees across CPU cores
static uint32_t monitor_only_mode_atomic = 0;  // 0 = protection active, 1 = monitor-only
static uint32_t tap_mode_atomic = 0;           // 0 = inline mode, 1 = tap/mirror mode

// ==================== Runtime Config Update ====================
// Called by control_socket after config reload to refresh cached values
void layer1_refresh_cached_config(void) {
    const struct layer1_config *cfg = layer1_config_get();
    if (cfg) {
        // Use atomic load/store for cross-core safety
        uint32_t old_mode = __atomic_load_n(&monitor_only_mode_atomic, __ATOMIC_ACQUIRE);
        uint32_t new_mode = cfg->monitor_only ? 1 : 0;
        __atomic_store_n(&monitor_only_mode_atomic, new_mode, __ATOMIC_RELEASE);

        // Use atomic store for should_decrement_ttl
        uint32_t new_ttl_mode = cfg->validation.decrement_ttl ? 1 : 0;
        __atomic_store_n(&should_decrement_ttl_atomic, new_ttl_mode, __ATOMIC_RELEASE);

        if (old_mode != new_mode) {
            RTE_LOG(NOTICE, L1, "Monitor-only mode %s\n",
                    new_mode ? "ENABLED - all protection bypassed" : "DISABLED - protection active");
        }

        // Tap mode: all traffic is a mirror copy on port 0, no forwarding
        uint32_t old_tap = __atomic_load_n(&tap_mode_atomic, __ATOMIC_ACQUIRE);
        uint32_t new_tap = cfg->tap_mode ? 1 : 0;
        __atomic_store_n(&tap_mode_atomic, new_tap, __ATOMIC_RELEASE);
        if (old_tap != new_tap) {
            RTE_LOG(NOTICE, L1, "Tap mode %s\n",
                    new_tap ? "ENABLED - mirror/copy traffic, no forwarding" : "DISABLED - inline mode");
        }

        // Update protected IP enforcement setting from config
        ip_protected_set_enforcement(cfg->ip_lists.enforce_protected_ips);
    }
}

bool layer1_is_tap_mode(void) {
    return __atomic_load_n(&tap_mode_atomic, __ATOMIC_ACQUIRE) != 0;
}

// NOTE: Layer 1 stats are now maintained in per-lcore structures (lcore_statistics)
// in dpdk_core.c. The layer1_get_stats() function aggregates them on demand.
// This avoids atomic operations in the fast path.

// Maintenance timing
static uint64_t last_maintenance_tsc = 0;
static uint64_t last_secret_rotation_tsc = 0;
static uint64_t tsc_hz = 0;

// ==================== Direction Detection ====================

static inline int get_traffic_direction(uint16_t port_id) {
    return (port_id == PORT_FACING_CLIENTS) ? DIRECTION_INBOUND : DIRECTION_OUTBOUND;
}

static inline uint16_t get_opposite_port(uint16_t port_id) {
    return (port_id == PORT_FACING_CLIENTS) ? PORT_FACING_SERVERS : PORT_FACING_CLIENTS;
}

// ==================== Telemetry Helpers ====================

/**
 * Record an attack/drop event to telemetry
 * Always recorded (no sampling) - these are important security events
 */
static inline void record_attack_event(const struct packet_features *features,
                                       uint8_t event_type,
                                       uint8_t severity,
                                       uint8_t drop_reason,
                                       const char *description) {
    struct attack_event evt;
    memset(&evt, 0, sizeof(evt));
    
    /* Convert TSC to real nanoseconds for export */
    {
        static uint64_t cached_tsc_hz = 0;
        if (unlikely(cached_tsc_hz == 0))
            cached_tsc_hz = rte_get_tsc_hz();
        evt.timestamp_ns = (rte_get_tsc_cycles() * 1000000000ULL) / cached_tsc_hz;
    }
    evt.event_type = event_type;
    evt.severity = severity;
    evt.direction = features->direction;
    evt.src_ip = features->src_ip;
    evt.dst_ip = features->dst_ip;
    evt.src_port = features->src_port;
    evt.dst_port = features->dst_port;
    evt.protocol = features->protocol;
    evt.drop_reason = drop_reason;
    evt.packet_count = 1;
    evt.byte_count = features->packet_size;
    
    if (description) {
        strncpy(evt.description, description, sizeof(evt.description) - 1);
        evt.description[sizeof(evt.description) - 1] = '\0';
    }
    
    telemetry_record_attack(&evt);
}

/**
 * Record a new flow creation to telemetry
 * Subject to sampling rate configuration
 */

static inline void record_flow_created(const struct flow_entry *flow,
                                       const struct packet_features *features) {
    struct flow_record rec;
    memset(&rec, 0, sizeof(rec));
    
    // Use features for src/dst (actual packet direction)
    // flow->key uses canonical ordering (ip_lo <= ip_hi)
    rec.src_ip = features->src_ip;
    rec.dst_ip = features->dst_ip;
    rec.src_port = features->src_port;
    rec.dst_port = features->dst_port;
    rec.protocol = flow->key.protocol;
    rec.direction = features->direction;
    rec.first_seen_ns = flow->first_seen_tsc;
    rec.last_seen_ns = flow->last_seen_tsc;
    
    // Use helper functions for bidirectional totals
    rec.packet_count = flow_total_packets(flow);
    rec.byte_count = flow_total_bytes(flow);
    
    // Combine both direction flags
    rec.tcp_flags_seen = flow->tcp_flags_lo_to_hi | flow->tcp_flags_hi_to_lo;
    rec.tcp_state = flow->state;
    
    // Calculate average packet size
    uint64_t total_pkts = rec.packet_count;
    uint64_t total_bytes = rec.byte_count;
    rec.avg_packet_size = total_pkts ? (uint16_t)(total_bytes / total_pkts) : 0;
    rec.max_packet_size = features->packet_size;
    
    rec.avg_inter_arrival_us = 0;
    rec.avg_payload_entropy = features->payload_entropy;
    rec.avg_header_entropy = features->header_entropy;
    rec.retransmit_count = 0;
    rec.out_of_order_count = 0;
    rec.dropped = 0;
    rec.drop_reason = DROP_REASON_NONE;
    
    telemetry_record_flow(&rec);
}

/**
 * Record a dropped flow to telemetry (force record, bypass sampling)
 * Dropped flows are important for security analysis
 */
static inline void record_flow_dropped(const struct packet_features *features,
                                       uint8_t drop_reason) {
    struct flow_record rec;
    memset(&rec, 0, sizeof(rec));
    
    rec.src_ip = features->src_ip;
    rec.dst_ip = features->dst_ip;
    rec.src_port = features->src_port;
    rec.dst_port = features->dst_port;
    rec.protocol = features->protocol;
    rec.direction = features->direction;
    rec.first_seen_ns = features->timestamp_tsc;
    rec.last_seen_ns = features->timestamp_tsc;
    rec.packet_count = 1;
    rec.byte_count = features->packet_size;
    rec.tcp_flags_seen = features->tcp_flags;
    rec.tcp_state = 0;
    rec.avg_packet_size = features->packet_size;
    rec.max_packet_size = features->packet_size;
    rec.avg_payload_entropy = features->payload_entropy;
    rec.avg_header_entropy = features->header_entropy;
    rec.dropped = 1;
    rec.drop_reason = drop_reason;
    
    // Force record dropped flows (important for security)
    telemetry_record_flow_force(&rec);
}

// ==================== Inbound Processing ====================

static int process_inbound_packet(struct rte_mbuf *m, uint16_t port_id,
                                  uint16_t queue_id,
                                  struct packet_features *features,
                                  struct rte_mempool *mempool,
                                  struct layer1_result *result) {
  
    struct flow_entry *flow;
    bool flow_created;
    struct policy_result policy_result;
    struct reputation_result rep_result;
    enum rate_limit_action rl_action;

    // Initialize result
    result->action = L1_ACTION_ACCEPT;
    result->reply_pkt = NULL;
    result->forward_pkt = NULL;
    result->drop_reason = DROP_REASON_NONE;
    result->reply_queue = queue_id;
    result->forward_queue = queue_id;

    // Update direction-specific stats - per-lcore, no atomics
    struct lcore_stats *lstats = get_lcore_stats();
    lstats->l1_inbound_packets++;
    lstats->l1_inbound_bytes += features->packet_size;

    // Removed duplicate hll_global_add_src_ip() call
    // HLL update is now done ONLY in layer1_process_packet_ex() at Stage 3b
    // Previously it was called here AND in the parent function, wasting ~30 cycles

    // ========== Stage 4d: Protected Destination + Profile Lookup ==========
    // Always look up the profile for downstream stages (port filter, SYN proxy mode, rate limits).
    // Enforcement only controls whether non-protected IPs get dropped.
    const struct protection_profile *dst_profile = NULL;
    int32_t dst_profile_pos = -1;  // Hash position for per-protocol rate counter indexing
    bool is_protected = ip_protected_lookup_profile_pos(features->dst_ip,
                                                         &dst_profile, &dst_profile_pos);

    if (ip_protected_enforcement_enabled() && !is_protected) {
        lstats->l1_packets_dropped++;
        lstats->l1_drop_validation++;
        lstats->l1_drop_not_protected++;

        static uint64_t not_protected_log_count = 0;
        uint64_t prev_count = __atomic_fetch_add(&not_protected_log_count, 1, __ATOMIC_RELAXED);
        if (prev_count < 5) {
            RTE_LOG(WARNING, L1, "Packet to non-protected IP dropped: %u.%u.%u.%u\n",
                    (rte_be_to_cpu_32(features->dst_ip) >> 24) & 0xFF,
                    (rte_be_to_cpu_32(features->dst_ip) >> 16) & 0xFF,
                    (rte_be_to_cpu_32(features->dst_ip) >> 8) & 0xFF,
                    rte_be_to_cpu_32(features->dst_ip) & 0xFF);
        }

        result->action = L1_ACTION_DROP;
        result->drop_reason = DROP_REASON_VALIDATION;
        return 0;
    }
    result->dst_profile = dst_profile;

    // ========== Stage 4d+: Per-IP Anomaly Snapshot ==========
    // Read per-IP anomaly state once (O(1) via cached index) for all downstream stages.
    // When per_ip_mitigation_enabled, downstream stages use per-IP + protocol-scoped
    // decisions instead of global anomaly state.
    const struct layer1_config *l1cfg = layer1_config_get();
    struct per_ip_anomaly_snapshot ip_anom = {0};
    ip_anom.rate_limit_pct = 100;  // Default: no reduction

    if (l1cfg && l1cfg->per_ip_mitigation_enabled && dst_profile &&
        dst_profile->anomaly_slot_idx >= 0) {
        const struct per_ip_anomaly_state *astate =
            per_ip_anomaly_get_fast(dst_profile->anomaly_slot_idx);
        if (astate) {
            ip_anom.valid = true;
            ip_anom.anomaly_active = __atomic_load_n(&astate->anomaly_active,
                                                      __ATOMIC_ACQUIRE) != 0;
            ip_anom.anomaly_level = __atomic_load_n(&astate->anomaly_level,
                                                     __ATOMIC_RELAXED);
            ip_anom.anomaly_protocol = __atomic_load_n(&astate->anomaly_protocol,
                                                        __ATOMIC_RELAXED);
            ip_anom.attack_type = __atomic_load_n(&astate->attack_type,
                                                   __ATOMIC_RELAXED);
            ip_anom.spoofed_mode = __atomic_load_n(&astate->spoofed_mode,
                                                    __ATOMIC_RELAXED);
            ip_anom.rate_limit_pct = __atomic_load_n(&astate->rate_limit_pct,
                                                      __ATOMIC_RELAXED);
            if (ip_anom.rate_limit_pct == 0)
                ip_anom.rate_limit_pct = 100;  // Unset = no reduction
        }
    }

    // ========== Stage 4e: Protocol Action + Port/Proto Filter (Per-Profile) ==========
    //
    // Order matters:
    //   1. DROP action -> reject immediately (no counter cost)
    //   2. Allowlists -> reject disallowed ports/protos before counting rate
    //      - TCP/UDP: port allowlist (tcp_ports[], udp_ports[])
    //      - Other:   protocol allowlist (other_allowed_protos[])
    //   3. RATE_LIMIT action -> count only allowlist-valid packets against budget
    if (dst_profile) {
        uint8_t proto_act = profile_proto_action(dst_profile, features->protocol);

        // 1. Protocol entirely blocked for this IP
        if (proto_act == PROFILE_PROTO_DROP) {
            lstats->l1_packets_dropped++;
            lstats->l1_drop_validation++;
            lstats->l1_drop_proto_blocked++;

            record_attack_event(features, EVENT_PROTO_BLOCKED, SEVERITY_MEDIUM,
                               DROP_REASON_PROTO_BLOCKED,
                               "Protocol blocked by protection profile");

            result->action = L1_ACTION_DROP;
            result->drop_reason = DROP_REASON_PROTO_BLOCKED;
            return 0;
        }

        // 2a. Port allowlist (TCP/UDP)
        if (!profile_port_allowed(dst_profile, features->protocol,
                                   features->dst_port)) {
            lstats->l1_packets_dropped++;
            lstats->l1_drop_validation++;
            lstats->l1_drop_port_filter++;
            result->action = L1_ACTION_DROP;
            result->drop_reason = DROP_REASON_PORT_NOT_ALLOWED;
            return 0;
        }

        // 2b. "Other" protocol allowlist (non-TCP/UDP/ICMP)
        //     When other_proto_count > 0, only listed IP protocols pass
        if (features->protocol != IPPROTO_TCP &&
            features->protocol != IPPROTO_UDP &&
            features->protocol != IPPROTO_ICMP &&
            !profile_other_proto_allowed(dst_profile, features->protocol)) {
            lstats->l1_packets_dropped++;
            lstats->l1_drop_validation++;
            lstats->l1_drop_proto_blocked++;

            record_attack_event(features, EVENT_PROTO_BLOCKED, SEVERITY_MEDIUM,
                               DROP_REASON_PROTO_BLOCKED,
                               "IP protocol not in allowed list");

            result->action = L1_ACTION_DROP;
            result->drop_reason = DROP_REASON_PROTO_BLOCKED;
            return 0;
        }

        // 3. Protocol rate-limit (aggregate PPS per protected IP)
        //    Only reached for allowlist-valid packets
        if (proto_act == PROFILE_PROTO_RATE_LIMIT) {
            uint32_t limit = profile_proto_rate_limit(dst_profile, features->protocol);
            if (limit > 0 && !ip_protected_proto_rate_check(dst_profile_pos,
                                                             features->protocol, limit)) {
                lstats->l1_packets_dropped++;
                lstats->l1_drop_rate_limit++;
                lstats->l1_drop_proto_rate_limit++;

                record_attack_event(features, EVENT_PROTO_RATE_LIMITED, SEVERITY_LOW,
                                   DROP_REASON_PROTO_RATE_LIMIT,
                                   "Protocol rate limit exceeded");

                result->action = L1_ACTION_DROP;
                result->drop_reason = DROP_REASON_PROTO_RATE_LIMIT;
                return 0;
            }
        }
    }

    // ========== Stage 5: Whitelist (Bypass or Track-and-Allow) ==========
    {
        uint8_t wl_mode = 0;
        if (ip_whitelist_lookup(features->src_ip, &wl_mode)) {
            lstats->l1_whitelist_hits++;
            if (wl_mode == WL_MODE_TRACK) {
                // Track mode: continue through all stages, but never drop
                result->whitelist_track = true;
            } else {
                // Bypass mode: skip all remaining stages
                lstats->l1_packets_accepted++;
                result->action = L1_ACTION_ACCEPT;
                return 0;
            }
        }
    }

    // ========== Stage 6: Blacklist (Fast Reject) ==========
    if (ip_blacklist_lookup(features->src_ip)) {
        lstats->l1_packets_dropped++;
        lstats->l1_drop_blacklist++;

        // Record attack event
        record_attack_event(features, EVENT_BLACKLIST_DROP, SEVERITY_HIGH,
                           DROP_REASON_BLACKLIST, "Blacklisted source IP");

        result->action = L1_ACTION_DROP;
        result->drop_reason = DROP_REASON_BLACKLIST;
        return 0;
    }

    // ========== Stage 6b: Geo-Blocking ==========
    if (geo_should_block(features->src_ip)) {
        lstats->l1_packets_dropped++;
        lstats->l1_drop_geo++;

        record_attack_event(features, EVENT_GEO_BLOCKED, SEVERITY_MEDIUM,
                           DROP_REASON_GEO_BLOCKED, "Blocked by geo-location policy");

        result->action = L1_ACTION_DROP;
        result->drop_reason = DROP_REASON_GEO_BLOCKED;
        return 0;
    }

    // ========== Stage 6c: Attack Signature Detection ==========
    {
        struct sig_match sig_match;
        bool sig_drop = signatures_check(features->protocol,
                                         features->src_ip, features->dst_ip,
                                         features->src_port, features->dst_port,
                                         features->tcp_flags, features->packet_size,
                                         features->ttl,
                                         &sig_match);
        if (sig_drop) {
            lstats->l1_packets_dropped++;
            lstats->l1_drop_signature++;

            record_attack_event(features, EVENT_SIGNATURE_MATCH, sig_match.severity,
                               DROP_REASON_SIGNATURE, sig_match.description);

            result->action = L1_ACTION_DROP;
            result->drop_reason = DROP_REASON_SIGNATURE;
            return 0;
        }
    }

    // ========== Stage 7: Policy Enforcement ==========
    policy_lookup(features, &policy_result);
    if (policy_result.matched) {
        switch (policy_result.action) {
            case POLICY_DROP:
                lstats->l1_packets_dropped++;
                lstats->l1_drop_policy++;
                
                record_attack_event(features, EVENT_POLICY_DROP, SEVERITY_MEDIUM,
                                   DROP_REASON_POLICY, "Policy violation - DROP action");
                
                result->action = L1_ACTION_DROP;
                result->drop_reason = DROP_REASON_POLICY;
                return 0;
            case POLICY_CHALLENGE:
                // Handled by SYN proxy (syn_proxy_should_challenge checks policy)
                break;
            case POLICY_RATE_LIMIT:
                // Carry policy rate limits forward to Stage 12
                // Applied to flow entry after creation/lookup below
                break;
            case POLICY_ALLOW:
            default:
                break;
        }
    }

    // ========== Stage 8: Reputation Check ==========
    reputation_lookup(features->src_ip, &rep_result);
    if (rep_result.found && rep_result.level == REP_ATTACKER) {
        lstats->l1_packets_dropped++;
        lstats->l1_drop_reputation++;

        record_attack_event(features, EVENT_REPUTATION_DROP, SEVERITY_HIGH,
                           DROP_REASON_REPUTATION, "Known attacker IP (reputation system)");

        result->action = L1_ACTION_DROP;
        result->drop_reason = DROP_REASON_REPUTATION;
        return 0;
    }

    // ========== Per-IP Spoofed Mode Resolution ==========
    // Compute effective spoofed mode for this destination IP (used at Stages 8b, 9b, 10, 12).
    // Per-IP: only this IP in spoofed mode for its attack protocol.
    // Global fallback: when per-IP data unavailable or global circuit breaker active.
    bool eff_spoofed_tcp = false;
    if (ip_anom.valid && ip_anom.spoofed_mode) {
        eff_spoofed_tcp = protocol_matches_anomaly(IPPROTO_TCP, ip_anom.anomaly_protocol);
    } else if (!ip_anom.valid) {
        eff_spoofed_tcp = anomaly_is_spoofed_mode();  // Global fallback
    } else if (l1cfg->global_circuit_breaker && anomaly_is_spoofed_mode()) {
        eff_spoofed_tcp = true;  // Global circuit breaker override
    }

    // ========== Stage 8b: Spoofed TCP Flood Detection ==========
    // When spoofed mode is active for this IP, require all non-SYN TCP
    // to have an existing flow entry.
    if (features->protocol == IPPROTO_TCP && eff_spoofed_tcp) {
        uint8_t tcp_flags = features->tcp_flags;
        bool is_syn = (tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK);

        // SYN packets are handled by SYN proxy (Stage 9) - let them through
        if (!is_syn) {
            // All non-SYN TCP during spoofed mode: require existing flow
            struct flow_entry *existing_flow = flow_table_lookup(features);

            if (!existing_flow) {
                // No flow entry -- check if this is a SYN cookie handshake completion.
                // SYN cookie ACKs legitimately have no flow yet (created at Stage 9).
                // Only pure ACK or ACK+PSH can be handshake completions.
                bool has_valid_cookie = false;
                if (tcp_flags & TCP_FLAG_ACK) {
                    if (!(dst_profile && dst_profile->syn_proxy_mode == PROFILE_SYN_PROXY_DISABLED)) {
                        has_valid_cookie = syn_proxy_quick_cookie_check(
                            features->src_ip, features->dst_ip,
                            features->src_port, features->dst_port,
                            features->tcp_ack);
                    }
                }

                if (!has_valid_cookie) {
                    // No flow + no valid cookie = spoofed packet
                    lstats->l1_packets_dropped++;
                    lstats->l1_drop_spoofed_tcp++;

                    // Rate-limited logging per flag type
                    static uint64_t spoofed_drop_log = 0;
                    if (__atomic_fetch_add(&spoofed_drop_log, 1, __ATOMIC_RELAXED) < 10) {
                        RTE_LOG(WARNING, L1,
                            "Spoofed TCP dropped (flags=0x%02x, no flow, no cookie)\n",
                            tcp_flags);
                    }

                    result->action = L1_ACTION_DROP;
                    result->drop_reason = DROP_REASON_SPOOFED_TCP;
                    return 0;
                }
                // Valid cookie ACK -> let it pass through to Stage 9 for full processing
            }
            // Flow exists -> legitimate return traffic (SYN-ACK, data, RST, FIN) -- pass through
        }
    }

    // ========== Stage 9: SYN Proxy (TCP Only) ==========
    // Per-profile: DISABLED mode skips SYN proxy entirely (e.g., DNS servers)
    if (features->protocol == IPPROTO_TCP &&
        !(dst_profile && dst_profile->syn_proxy_mode == PROFILE_SYN_PROXY_DISABLED)) {
        struct syn_proxy_result proxy_result = {0};

        int ret = syn_proxy_process_packet(m, features, DIRECTION_INBOUND,
                                           mempool, &proxy_result, port_id,
                                           &ip_anom);
        if (ret < 0) {
            lstats->l1_packets_dropped++;
            lstats->l1_drop_proxy_error++;
            
            record_attack_event(features, EVENT_PROXY_ERROR, SEVERITY_LOW,
                               DROP_REASON_PROXY_ERROR, "SYN proxy processing error");
            
            result->action = L1_ACTION_DROP;
            result->drop_reason = DROP_REASON_PROXY_ERROR;
            return 0;
        }

        result->proxy_state = proxy_result.conn_state;

        switch (proxy_result.action) {
            case SYN_PROXY_DROP:
                lstats->l1_packets_dropped++;

                record_attack_event(features, EVENT_COOKIE_INVALID, SEVERITY_HIGH,
                                   DROP_REASON_COOKIE_INVALID, "Invalid SYN cookie - potential attack");


                result->action = L1_ACTION_DROP;
                result->drop_reason = DROP_REASON_COOKIE_INVALID;
                return 0;

            case SYN_PROXY_REPLY:
                lstats->l1_syn_proxy_challenges++;

                if (proxy_result.reply_pkt) {
                    if (proxy_result.conn_state == SYN_PROXY_SYN_SENT) {
                        // SYN-ACK reply goes back to client on same port
                        result->reply_pkt = proxy_result.reply_pkt;
                        result->reply_port = port_id;
                        result->reply_queue = queue_id;
                    } else if (proxy_result.conn_state == SYN_PROXY_CONNECTING) {
                        // SYN to server goes to opposite port
                        result->forward_pkt = proxy_result.reply_pkt;
                        result->forward_port = get_opposite_port(port_id);
                        result->forward_queue = queue_id;
                    } else if (proxy_result.conn_state == SYN_PROXY_ESTABLISHED) {
                        // ACK to server
                        result->forward_pkt = proxy_result.reply_pkt;
                        result->forward_port = get_opposite_port(port_id);
                        result->forward_queue = queue_id;
                    }
                }

                result->action = L1_ACTION_REPLY;
                return 0;

            case SYN_PROXY_REPLY_INPLACE:
                // ZERO-COPY path: original mbuf was transformed into SYN-ACK
                // Return special action to tell caller to send 'm' as reply
                lstats->l1_syn_proxy_challenges++;
                result->action = L1_ACTION_REPLY_INPLACE;
                result->reply_port = port_id;
                result->reply_queue = queue_id;
                return 0;

            case SYN_PROXY_FORWARD:
                if (proxy_result.packet_modified) {
                    result->action = L1_ACTION_ACCEPT_MODIFIED;
                } else {
                    result->action = L1_ACTION_ACCEPT;
                }
                lstats->l1_packets_accepted++;
                return 0;

            case SYN_PROXY_BYPASS:
                // Continue to normal processing
                break;

            case SYN_PROXY_ERROR:
                lstats->l1_packets_dropped++;
                lstats->l1_drop_proxy_error++;

                record_attack_event(features, EVENT_PROXY_ERROR, SEVERITY_LOW,
                                   DROP_REASON_PROXY_ERROR, "SYN proxy internal error");

                result->action = L1_ACTION_DROP;
                result->drop_reason = DROP_REASON_PROXY_ERROR;
                return 0;
        }
    }

    // ========== Stage 9b: TCP Flag Rate Limiting ==========
    // Per-flag-class rate limiting - separates SYN limit from ACK limit
    // This prevents legitimate ACKs from being blocked by SYN flood attacks
    // SKIP during spoofed mode: per-src-IP limits are useless when each
    // spoofed source sends ~1 packet. Aggregate limiting handles this at Stage 12.
    if (features->protocol == IPPROTO_TCP && !eff_spoofed_tcp) {
        enum tcp_flag_rate_result flag_result = tcp_flag_rate_check(
            features->src_ip, features->tcp_flags, features->packet_size);

        if (flag_result != TCPF_RATE_ACCEPT) {
            lstats->l1_packets_dropped++;
            lstats->l1_drop_rate_limit++;

            // Map specific flag result to proper drop reason
            uint8_t flag_drop_reason;
            switch (flag_result) {
                case TCPF_RATE_DROP_SYN:
                case TCPF_RATE_DROP_SYN_ACK:
                    flag_drop_reason = DROP_REASON_RATE_LIMIT_SYN;
                    break;
                case TCPF_RATE_DROP_ACK:
                    flag_drop_reason = DROP_REASON_RATE_LIMIT_ACK;
                    break;
                case TCPF_RATE_DROP_RST:
                    flag_drop_reason = DROP_REASON_RATE_LIMIT_RST;
                    break;
                case TCPF_RATE_DROP_FIN:
                    flag_drop_reason = DROP_REASON_RATE_LIMIT_FIN;
                    break;
                default:
                    flag_drop_reason = DROP_REASON_RATE_LIMIT;
            }

            const char *class_name = tcp_flag_rate_result_name(flag_result);
            record_attack_event(features, EVENT_RATE_LIMIT_EXCEEDED, SEVERITY_MEDIUM,
                               flag_drop_reason, class_name);

            result->action = L1_ACTION_DROP;
            result->drop_reason = flag_drop_reason;
            return 0;
        }
    }

    // ========== Stage 10: Connection Limits (Non-Proxied TCP) ==========
    // SKIP during spoofed mode: per-src-IP connection counting is useless when
    // each spoofed source sends ~1 SYN (always under the limit). Saves CPU.
    // Per-IP: skip only if THIS destination is in spoofed mode for TCP
    if (features->protocol == IPPROTO_TCP && !eff_spoofed_tcp) {
        uint8_t tcp_flags = features->tcp_flags;

        if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
            if (!syn_proxy_is_enabled() ||
                (dst_profile && dst_profile->syn_proxy_mode == PROFILE_SYN_PROXY_DISABLED)) {
                if (!connection_limits_check(features->src_ip, features->dst_port)) {
                    lstats->l1_packets_dropped++;
                    lstats->l1_drop_syn_flood++;

                    record_attack_event(features, EVENT_CONNECTION_LIMIT, SEVERITY_HIGH,
                                       DROP_REASON_SYN_FLOOD,
                                       "Connection limit exceeded - potential SYN flood");


                    result->action = L1_ACTION_DROP;
                    result->drop_reason = DROP_REASON_SYN_FLOOD;
                    return 0;
                }
            }
        }
    }

    // ========== Stage 10B: UDP Admission Control ==========
    // Protect flow table from UDP floods - check BEFORE creating flow state
    // TCP is protected by SYN cookies; UDP needs rate-based admission control
    if (features->protocol == IPPROTO_UDP) {
        enum udp_gk_action gk_action = udp_gatekeeper_check(features->src_ip,
                                                             features->packet_size,
                                                             &ip_anom);
        if (gk_action != UDP_GK_ACCEPT) {
            lstats->l1_packets_dropped++;

            // Map specific gatekeeper result to appropriate drop reason
            uint8_t udp_drop_reason;
            const char *reason_str;
            switch (gk_action) {
                case UDP_GK_DROP_RATE:
                    udp_drop_reason = DROP_REASON_RATE_LIMIT_UDP;
                    reason_str = "UDP rate limit exceeded (PPS)";
                    lstats->l1_drop_rate_limit++;
                    break;
                case UDP_GK_DROP_BPS:
                    udp_drop_reason = DROP_REASON_RATE_LIMIT_UDP;
                    reason_str = "UDP bandwidth limit exceeded (BPS)";
                    lstats->l1_drop_rate_limit++;
                    break;
                case UDP_GK_DROP_REPUTATION:
                    udp_drop_reason = DROP_REASON_UDP_GATEKEEPER;
                    reason_str = "UDP blocked due to bad reputation";
                    lstats->l1_drop_reputation++;
                    break;
                case UDP_GK_DROP_BLACKLIST:
                    udp_drop_reason = DROP_REASON_UDP_GATEKEEPER;
                    reason_str = "UDP blocked - IP blacklisted";
                    lstats->l1_drop_blacklist++;
                    break;
                default:
                    udp_drop_reason = DROP_REASON_UDP_GATEKEEPER;
                    reason_str = "UDP admission control denied";
                    lstats->l1_drop_rate_limit++;
            }

            record_attack_event(features, EVENT_RATE_LIMIT_EXCEEDED, SEVERITY_MEDIUM,
                               udp_drop_reason, reason_str);

            result->action = L1_ACTION_DROP;
            result->drop_reason = udp_drop_reason;
            return 0;
        }
    }

    // ========== Stage 11: Flow Tracking (CANONICAL) ==========
    flow = flow_table_lookup_or_create(features, &flow_created);
    if (!flow) {
        // Flow table full - apply reputation-aware emergency drop first,
        // then FALL THROUGH to Stage 12 for aggregate rate limiting.
        // Previously this returned early, letting an attacker fill the flow table
        // and then send unlimited traffic that bypassed all rate limiting.
        lstats->l1_drop_flow_table_full++;

        const struct layer1_config *cfg = layer1_config_get();
        uint8_t drop_pct;

        // Reputation-aware emergency rate limiting
        struct reputation_result rep_result;
        reputation_lookup(features->src_ip, &rep_result);

        if (!rep_result.found || rep_result.level == REP_UNKNOWN) {
            drop_pct = cfg->flow_table.emergency_drop_unknown_pct;
        } else if (rep_result.level >= REP_GOOD) {
            drop_pct = cfg->flow_table.emergency_drop_good_pct;
        } else if (rep_result.level == REP_NEUTRAL) {
            drop_pct = cfg->flow_table.emergency_drop_neutral_pct;
        } else {
            drop_pct = cfg->flow_table.emergency_drop_suspicious_pct;
        }

        uint32_t hash = rte_hash_crc(&features->src_ip, 4, features->dst_ip);
        uint8_t hash_pct = (hash & 0xFF) * 100 / 256;  // 0-99

        if (hash_pct < drop_pct) {
            lstats->l1_packets_dropped++;
            result->action = L1_ACTION_DROP;
            result->drop_reason = DROP_REASON_FLOW_TABLE_FULL;
            return 0;
        }

        result->flags |= L1_RESULT_FLAG_NO_FLOW_TRACKING;
        // Fall through to Stage 12 -- flow is NULL, has_flow=false
    }

    // Record new flow creation (subject to sampling)
    if (flow && flow_created) {
        record_flow_created(flow, features);
        // Layer 2 feature: track new flows per second
        lstats->l1_new_flows++;
        if (features->protocol == IPPROTO_UDP)
            lstats->l1_new_udp_flows++;

        // Update per-protected-IP new flow counter
        struct per_ip_features *pif = per_ip_features_lookup(features->dst_ip);
        per_ip_increment_new_flow(pif, rte_lcore_id());

        // Apply per-profile rate limits to the new flow.
        // Use attack limits when anomaly is active for this destination IP.
        if (dst_profile && (dst_profile->pps_limit || dst_profile->bps_limit)) {
            uint32_t eff_pps = dst_profile->pps_limit;
            uint32_t eff_bps = dst_profile->bps_limit;
            if (ip_anom.valid && ip_anom.anomaly_active) {
                if (dst_profile->attack_pps_limit)
                    eff_pps = dst_profile->attack_pps_limit;
                if (dst_profile->attack_bps_limit)
                    eff_bps = dst_profile->attack_bps_limit;
            }
            __atomic_store_n(&flow->pps_limit, eff_pps, __ATOMIC_RELAXED);
            __atomic_store_n(&flow->bps_limit, eff_bps, __ATOMIC_RELAXED);
        }

        // Apply policy rate limits (override profile if policy is stricter)
        if (policy_result.matched && policy_result.action == POLICY_RATE_LIMIT) {
            uint32_t cur_pps = __atomic_load_n(&flow->pps_limit, __ATOMIC_RELAXED);
            uint32_t cur_bps = __atomic_load_n(&flow->bps_limit, __ATOMIC_RELAXED);
            if (policy_result.rate_limit_pps &&
                (cur_pps == 0 || policy_result.rate_limit_pps < cur_pps)) {
                __atomic_store_n(&flow->pps_limit, policy_result.rate_limit_pps, __ATOMIC_RELAXED);
            }
            if (policy_result.rate_limit_bps &&
                (cur_bps == 0 || policy_result.rate_limit_bps < cur_bps)) {
                __atomic_store_n(&flow->bps_limit, policy_result.rate_limit_bps, __ATOMIC_RELAXED);
            }
        }
    }

    // ========== Stage 12: Rate Limiting ==========
    // During spoofed mode (or when flow is NULL): use per-destination aggregate limiting.
    // Per-source-IP limits are useless when each fake IP sends ~1 packet.
    // Normal mode with valid flow: use per-flow rate limiting as before.
    // Per-IP scoped: use spoofed rate check only if THIS dst IP is in spoofed mode
    // for the matching protocol, or if flow is NULL (table full fallback).
    bool eff_spoofed_stage12 = false;
    if (ip_anom.valid && ip_anom.spoofed_mode) {
        eff_spoofed_stage12 = protocol_matches_anomaly(features->protocol, ip_anom.anomaly_protocol);
    } else if (!ip_anom.valid) {
        eff_spoofed_stage12 = anomaly_is_spoofed_mode();  // Global fallback
    } else if (l1cfg->global_circuit_breaker && anomaly_is_spoofed_mode()) {
        eff_spoofed_stage12 = true;  // Global circuit breaker override
    }

    if (eff_spoofed_stage12 || !flow) {
        // has_flow=false for: NULL flow (table full), or newly created flow from
        // unvalidated source. has_flow=true only for pre-existing flows.
        rl_action = spoofed_rate_check(features, flow != NULL && !flow_created);
    } else {
        rl_action = flow_table_check_rate_limit(flow, features, &ip_anom);
    }
    if (rl_action != RL_ACCEPT) {
        lstats->l1_packets_dropped++;
        lstats->l1_drop_rate_limit++;

        const char *reason_str = (rl_action == RL_DROP_PPS) ?
                                 "Rate limit exceeded (PPS)" :
                                 "Rate limit exceeded (BPS)";
        record_attack_event(features, EVENT_RATE_LIMIT_EXCEEDED, SEVERITY_MEDIUM,
                           DROP_REASON_RATE_LIMIT, reason_str);


        result->action = L1_ACTION_DROP;
        result->drop_reason = DROP_REASON_RATE_LIMIT;
        return 0;
    }

    if (flow) {
        flow_table_update(flow, features);
    }

    // ========== Stage 11d: TCP Abuse Detection ==========
    // Detect malformed/abusive TCP patterns using flow state
    // Note: Uses simplified stateless check since tcp_abuse_state is not in flow_entry
    // Full per-flow tracking to be added when flow_entry is extended
    if (features->protocol == IPPROTO_TCP && tcp_abuse_is_enabled()) {
        // Per-lcore abuse state with per-IP isolation to prevent cross-flow contamination.
        // When src_ip changes, reset state so different flows don't pollute each other's
        // seq/ack/window tracking (RSS usually keeps same-IP packets on same lcore).
        static __thread struct tcp_abuse_state tls_abuse_state = {0};
        static __thread uint32_t tls_abuse_tracked_ip = 0;

        if (features->src_ip != tls_abuse_tracked_ip) {
            tcp_abuse_state_init(&tls_abuse_state);
            tls_abuse_tracked_ip = features->src_ip;
        }

        // Enforce time-window counter resets (per-second and per-10-second)
        tcp_abuse_state_reset_counters(&tls_abuse_state);

        enum tcp_abuse_result abuse_result = tcp_abuse_check(
            &tls_abuse_state,
            features->src_ip,
            features->tcp_seq,
            features->tcp_ack,
            features->tcp_window,
            features->tcp_flags,
            features->packet_size);

        if (abuse_result == TCP_ABUSE_RESULT_DROP) {
            lstats->l1_packets_dropped++;

            // Map specific abuse type to correct drop reason
            uint8_t abuse_detected = tls_abuse_state.detected_abuse;
            uint8_t abuse_drop_reason = DROP_REASON_TCP_ABUSE;
            const char *abuse_str = "TCP abuse detected";

            if (abuse_detected & TCP_ABUSE_DUP_SEQ) {
                abuse_drop_reason = DROP_REASON_TCP_DUP_SEQ;
                abuse_str = "TCP duplicate SEQ flood";
            } else if (abuse_detected & TCP_ABUSE_RANDOM_SEQ) {
                abuse_drop_reason = DROP_REASON_TCP_RANDOM_SEQ;
                abuse_str = "TCP random SEQ jumps";
            } else if (abuse_detected & TCP_ABUSE_RANDOM_ACK) {
                abuse_drop_reason = DROP_REASON_TCP_RANDOM_ACK;
                abuse_str = "TCP random ACK jumps";
            } else if (abuse_detected & TCP_ABUSE_ZERO_WINDOW) {
                abuse_drop_reason = DROP_REASON_TCP_ZERO_WINDOW;
                abuse_str = "TCP zero window attack";
            } else if (abuse_detected & TCP_ABUSE_SAME_WINDOW) {
                abuse_drop_reason = DROP_REASON_TCP_SAME_WINDOW;
                abuse_str = "TCP same window flood";
            } else if (abuse_detected & TCP_ABUSE_SAME_ACK) {
                abuse_drop_reason = DROP_REASON_TCP_SAME_ACK;
                abuse_str = "TCP same ACK flood";
            }

            record_attack_event(features, EVENT_TCP_ABUSE, SEVERITY_HIGH,
                               abuse_drop_reason, abuse_str);

            result->action = L1_ACTION_DROP;
            result->drop_reason = abuse_drop_reason;
            return 0;
        } else if (abuse_result == TCP_ABUSE_RESULT_RATE_LIMIT) {
            // Apply additional rate limiting for suspicious patterns
            // For now, just log - rate limiting is already applied per-flag-class
        }
    }

    // TTL check and decrement for forwarding
    if (!check_ttl_for_forwarding(m)) {
        lstats->l1_packets_dropped++;
        lstats->l1_drop_validation++;
        lstats->l1_drop_ttl++;

        result->action = L1_ACTION_DROP;
        result->drop_reason = DROP_REASON_IP_TTL_ZERO;
        return 0;
    }

    // Decrement TTL if configured (L3 router mode)
    // Default is L2 bridge mode where TTL is not decremented
    // Use atomic load for cross-core visibility
    if (__atomic_load_n(&should_decrement_ttl_atomic, __ATOMIC_ACQUIRE)) {
        decrement_ttl(m);
        result->action = L1_ACTION_ACCEPT_MODIFIED;  // Packet was modified (TTL decremented)
    } else {
        result->action = L1_ACTION_ACCEPT;  // L2 bridge mode - pass through unmodified
    }

    lstats->l1_packets_accepted++;
    return 0;
}

// ==================== Outbound Processing ====================

static int process_outbound_packet(struct rte_mbuf *m, uint16_t port_id,
                                   uint16_t queue_id,
                                   struct packet_features *features,
                                   struct rte_mempool *mempool,
                                   struct layer1_result *result) {
    // Initialize result
    result->action = L1_ACTION_ACCEPT;
    result->reply_pkt = NULL;
    result->forward_pkt = NULL;
    result->drop_reason = DROP_REASON_NONE;
    result->reply_queue = queue_id;
    result->forward_queue = queue_id;

    // Update direction-specific stats - per-lcore, no atomics
    struct lcore_stats *lstats = get_lcore_stats();
    lstats->l1_outbound_packets++;
    lstats->l1_outbound_bytes += features->packet_size;

    // ========== SYN Proxy Processing (TCP Only) ==========
    if (features->protocol == IPPROTO_TCP) {
        struct syn_proxy_result proxy_result = {0};
        
        int ret = syn_proxy_process_packet(m, features, DIRECTION_OUTBOUND,
                                           mempool, &proxy_result, port_id,
                                           NULL);
        if (ret < 0) {
            // Outbound errors are less critical - just accept
            lstats->l1_packets_accepted++;
            result->action = L1_ACTION_ACCEPT;
            return 0;
        }

        result->proxy_state = proxy_result.conn_state;

        switch (proxy_result.action) {
            case SYN_PROXY_DROP:
                lstats->l1_packets_dropped++;
                result->action = L1_ACTION_DROP;
                return 0;

            case SYN_PROXY_REPLY:
                if (proxy_result.reply_pkt) {
                    // ACK to server goes back to same port (server side)
                    result->forward_pkt = proxy_result.reply_pkt;
                    result->forward_port = port_id;
                    result->forward_queue = queue_id;
                }

                lstats->l1_syn_proxy_established++;
                result->action = L1_ACTION_REPLY;
                return 0;

            case SYN_PROXY_FORWARD:
                if (proxy_result.packet_modified) {
                    result->action = L1_ACTION_ACCEPT_MODIFIED;
                } else {
                    result->action = L1_ACTION_ACCEPT;
                }
                lstats->l1_packets_accepted++;
                return 0;

            case SYN_PROXY_BYPASS:
                // Continue to normal processing
                break;

            case SYN_PROXY_ERROR:
                // Outbound errors - just accept
                result->action = L1_ACTION_ACCEPT;
                lstats->l1_packets_accepted++;
                return 0;

            case SYN_PROXY_REPLY_INPLACE:
                // Not expected on outbound, but handle gracefully
                result->action = L1_ACTION_ACCEPT;
                lstats->l1_packets_accepted++;
                return 0;
        }
    }

    // ========== Flow Tracking (CANONICAL) ==========
    bool flow_created;
    struct flow_entry *flow = flow_table_lookup_or_create(features, &flow_created);

    if (flow) {
        // Record new outbound flow creation (subject to sampling)
        if (flow_created) {
            record_flow_created(flow, features);
            // Layer 2 feature: track new flows per second
            struct lcore_stats *lstats = get_lcore_stats();
            lstats->l1_new_flows++;
            if (features->protocol == IPPROTO_UDP)
                lstats->l1_new_udp_flows++;
        }
        flow_table_update(flow, features);
    }

    // TTL check and decrement for forwarding
    if (!check_ttl_for_forwarding(m)) {
        lstats->l1_packets_dropped++;
        lstats->l1_drop_validation++;
        lstats->l1_drop_ttl++;

        result->action = L1_ACTION_DROP;
        result->drop_reason = DROP_REASON_IP_TTL_ZERO;
        return 0;
    }

    // Decrement TTL if configured (L3 router mode)
    // Default is L2 bridge mode where TTL is not decremented
    // Use atomic load for cross-core visibility
    if (__atomic_load_n(&should_decrement_ttl_atomic, __ATOMIC_ACQUIRE)) {
        decrement_ttl(m);
        result->action = L1_ACTION_ACCEPT_MODIFIED;  // Packet was modified (TTL decremented)
    } else {
        result->action = L1_ACTION_ACCEPT;  // L2 bridge mode - pass through unmodified
    }

    lstats->l1_packets_accepted++;
    return 0;
}

// ==================== Main Entry Points ====================

int layer1_process_packet_ex(struct rte_mbuf *m, 
                             uint16_t port_id,
                             uint16_t queue_id,
                             struct rte_mempool *mempool,
                             struct layer1_result *result) {
    struct packet_features features;
    int parse_result, validation_result, feature_result;
    int direction;

    // Initialize result - explicit fields (compiler optimizes to fast stores)
    result->action = L1_ACTION_ACCEPT;
    result->reply_pkt = NULL;
    result->forward_pkt = NULL;
    result->reply_port = 0;
    result->reply_queue = queue_id;
    result->forward_port = 0;
    result->forward_queue = queue_id;
    result->drop_reason = 0;
    result->proxy_state = 0;
    result->whitelist_track = false;

    // Use atomic load for cross-core visibility
    if (unlikely(!__atomic_load_n(&initialized_atomic, __ATOMIC_ACQUIRE))) {
        return 0;
    }

    direction = get_traffic_direction(port_id);

    // Per-lcore stats - no atomics needed
    struct lcore_stats *lstats = get_lcore_stats();
    lstats->l1_total_packets++;
    lstats->l1_total_bytes += m->pkt_len;

    // ========== MONITOR-ONLY MODE: Fast passthrough for benchmarking ==========
    // When enabled, accept all packets without any protection processing
    // Only stats collection happens - ideal for measuring raw forwarding speed
    // Use atomic load with ACQUIRE ordering for cross-core visibility
    if (unlikely(__atomic_load_n(&monitor_only_mode_atomic, __ATOMIC_ACQUIRE))) {
        lstats->l1_packets_accepted++;
        if (direction == DIRECTION_INBOUND) {
            lstats->l1_inbound_packets++;
            lstats->l1_inbound_bytes += m->pkt_len;
        } else {
            lstats->l1_outbound_packets++;
            lstats->l1_outbound_bytes += m->pkt_len;
        }
        result->action = L1_ACTION_ACCEPT;
        return 0;
    }

    // ========== Stage 2: Parsing ==========
    parse_result = parse_packet(m, &features);

    if (parse_result == PARSE_NOT_IP) {
        lstats->l1_packets_accepted++;
        result->action = L1_ACTION_ACCEPT;
        return 0;
    }

    // ========== IPv6 Handling ==========
    // IPv6 protection using v6-specific tables and checks.
    // Policy options:
    //   0 = drop (safe default)
    //   1 = accept passthrough (no protection)
    //   2 = log and drop
    //   3 = protected mode (uses IPv6 tables for whitelist/blacklist/geo/syn-proxy)
    if (parse_result == PARSE_IPV6) {
        const struct layer1_config *cfg = layer1_config_get();
        uint8_t ipv6_policy = cfg ? cfg->validation.ipv6_policy : 0;

        lstats->l1_ipv6_packets++;  // Track IPv6 volume

        switch (ipv6_policy) {
        case 1:  // Accept (passthrough without protection)
            lstats->l1_packets_accepted++;
            result->action = L1_ACTION_ACCEPT;
            return 0;

        case 3: {
            // Protected mode with full pipeline
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(eth + 1);
            uint32_t pkt_len = m->pkt_len;

            // --- IPv6 extension header traversal ---
            // Walk extension headers to find the real transport protocol and offset
            uint8_t proto = ip6->proto;
            uint32_t ext_hdr_offset = sizeof(struct rte_ipv6_hdr);
            uint32_t remaining = rte_be_to_cpu_16(ip6->payload_len);
            uint32_t total_ext_len = 0;

            // Traverse extension headers (RFC 2460)
            // Known extension headers: Hop-by-Hop(0), Routing(43), Fragment(44),
            // Destination(60), AH(51), ESP(50)
            for (int i = 0; i < 8; i++) {  // Max 8 extension headers
                if (proto == IPPROTO_HOPOPTS || proto == IPPROTO_ROUTING ||
                    proto == IPPROTO_DSTOPTS) {
                    // Variable-length extension header
                    if (remaining < 2) break;
                    uint8_t *ext = (uint8_t *)ip6 + ext_hdr_offset;
                    uint8_t next_hdr = ext[0];
                    uint32_t ext_len = (ext[1] + 1) * 8;
                    if (ext_len > remaining) break;
                    proto = next_hdr;
                    ext_hdr_offset += ext_len;
                    remaining -= ext_len;
                    total_ext_len += ext_len;
                } else if (proto == IPPROTO_FRAGMENT) {
                    // Fragment header: fixed 8 bytes
                    if (remaining < 8) break;
                    uint8_t *ext = (uint8_t *)ip6 + ext_hdr_offset;
                    proto = ext[0];
                    ext_hdr_offset += 8;
                    remaining -= 8;
                    total_ext_len += 8;
                } else {
                    // Not an extension header -- proto is the transport protocol
                    break;
                }
            }

            // --- Basic validation ---
            // Drop zero hop limit
            if (ip6->hop_limits == 0) {
                lstats->l1_packets_dropped++;
                lstats->l1_drop_validation++;
                lstats->l1_drop_ttl++;
                result->action = L1_ACTION_DROP;
                result->drop_reason = DROP_REASON_IP_TTL_ZERO;
                return 0;
            }
            // Drop unspecified source (::)
            if (ip6_is_unspecified(ip6->src_addr.a)) {
                lstats->l1_packets_dropped++;
                lstats->l1_drop_validation++;
                lstats->l1_drop_proto_validation++;
                result->action = L1_ACTION_DROP;
                result->drop_reason = DROP_REASON_IP_MALFORMED;
                return 0;
            }

            // --- Stage 5: Whitelist (Bypass or Track-and-Allow) ---
            {
                uint8_t wl_v6_mode = 0;
                if (ip_whitelist_v6_lookup_mode(ip6->src_addr.a, &wl_v6_mode)) {
                    lstats->l1_whitelist_hits++;
                    if (wl_v6_mode == WL_MODE_V6_TRACK) {
                        // Track mode: run all stages for telemetry, never drop
                        result->whitelist_track = true;
                    } else {
                        // Bypass mode: skip all remaining stages
                        lstats->l1_packets_accepted++;
                        result->action = L1_ACTION_ACCEPT;
                        return 0;
                    }
                }
            }

            // --- Stage 4d: Protected Destination + Profile Lookup ---
            // Mirror IPv4 Stage 4d: look up the destination profile for downstream
            // stages (port filter, rate limits).  Enforcement only controls whether
            // non-protected destinations are dropped.
            const struct protection_profile *dst_profile_v6 = NULL;
            int32_t dst_profile_pos_v6 = -1;
            bool is_protected_v6 = ip_protected_v6_lookup_profile_pos(
                ip6->dst_addr.a, &dst_profile_v6, &dst_profile_pos_v6);

            // --- Stage 4: Blacklist ---
            if (ip_blacklist_v6_lookup(ip6->src_addr.a)) {
                lstats->l1_packets_dropped++;
                lstats->l1_drop_blacklist++;
                result->action = L1_ACTION_DROP;
                result->drop_reason = DROP_REASON_BLACKLIST;
                return 0;
            }

            // --- Stage 5: Geo-blocking ---
            if (geo_is_enabled()) {
                if (geo_should_block_v6(ip6->src_addr.a)) {
                    lstats->l1_packets_dropped++;
                    lstats->l1_drop_geo++;
                    result->action = L1_ACTION_DROP;
                    result->drop_reason = DROP_REASON_GEO_BLOCKED;
                    return 0;
                }
            }

            // --- Stage 4d: Protected Destination Enforcement ---
            if (ip_protected_v6_enforcement_enabled() && !is_protected_v6) {
                lstats->l1_packets_dropped++;
                lstats->l1_drop_validation++;
                lstats->l1_drop_not_protected++;
                result->action = L1_ACTION_DROP;
                result->drop_reason = DROP_REASON_VALIDATION;
                return 0;
            }

            // --- Build packet_features_v6 early for use by later stages ---
            struct packet_features_v6 pf6;
            memset(&pf6, 0, sizeof(pf6));
            pf6.ip_version = IP_VERSION_6;
            pf6.protocol = proto;
            pf6.ttl = ip6->hop_limits;
            pf6.packet_size = (uint16_t)pkt_len;
            pf6.ip_len = rte_be_to_cpu_16(ip6->payload_len) + sizeof(struct rte_ipv6_hdr);
            pf6.ipv6_flow_label = rte_be_to_cpu_32(ip6->vtc_flow) & 0xFFFFF;
            rte_memcpy(pf6.src_ip.v6, ip6->src_addr.a, 16);
            rte_memcpy(pf6.dst_ip.v6, ip6->dst_addr.a, 16);

            // Extract ports from TCP/UDP header
            uint8_t *l4_hdr = (uint8_t *)ip6 + ext_hdr_offset;
            if (proto == IPPROTO_TCP && remaining >= sizeof(struct rte_tcp_hdr)) {
                struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;
                pf6.src_port = rte_be_to_cpu_16(tcp->src_port);
                pf6.dst_port = rte_be_to_cpu_16(tcp->dst_port);
                pf6.tcp_flags = tcp->tcp_flags;
                pf6.tcp_header_len = (tcp->data_off >> 4) * 4;
                pf6.tcp_seq = rte_be_to_cpu_32(tcp->sent_seq);
                pf6.tcp_ack = rte_be_to_cpu_32(tcp->recv_ack);
                pf6.tcp_window = rte_be_to_cpu_16(tcp->rx_win);
            } else if (proto == IPPROTO_UDP && remaining >= 8) {
                struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
                pf6.src_port = rte_be_to_cpu_16(udp->src_port);
                pf6.dst_port = rte_be_to_cpu_16(udp->dst_port);
            }

            // --- Stage 4e: Port/Proto Filter (Per-Profile) ---
            // Apply protection profile port/protocol allowlists for IPv6.
            // dst_profile_v6 is NULL until per-IP profiles are stored for IPv6;
            // when NULL this block is skipped (fail-open, same as IPv4 with no profile).
            if (dst_profile_v6) {
                uint8_t proto_act_v6 = profile_proto_action(dst_profile_v6, proto);
                if (proto_act_v6 == PROFILE_PROTO_DROP) {
                    lstats->l1_packets_dropped++;
                    lstats->l1_drop_validation++;
                    lstats->l1_drop_proto_blocked++;
                    result->action = L1_ACTION_DROP;
                    result->drop_reason = DROP_REASON_PROTO_BLOCKED;
                    return 0;
                }
                if (!profile_port_allowed(dst_profile_v6, proto, pf6.dst_port)) {
                    lstats->l1_packets_dropped++;
                    lstats->l1_drop_validation++;
                    lstats->l1_drop_port_filter++;
                    result->action = L1_ACTION_DROP;
                    result->drop_reason = DROP_REASON_PORT_NOT_ALLOWED;
                    return 0;
                }
                if (proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
                    proto != IPPROTO_ICMPV6 &&
                    !profile_other_proto_allowed(dst_profile_v6, proto)) {
                    lstats->l1_packets_dropped++;
                    lstats->l1_drop_validation++;
                    lstats->l1_drop_proto_blocked++;
                    result->action = L1_ACTION_DROP;
                    result->drop_reason = DROP_REASON_PROTO_BLOCKED;
                    return 0;
                }
            }

            // --- Surrogate IPv4 keys for IPv6 security functions ---
            // All security functions below use uint32_t IPv4-keyed hash tables.
            // We derive 32-bit CRC hashes of the full 128-bit addresses as proxy
            // keys so the existing IPv4-keyed backends provide IPv6 coverage.
            // Hash collisions are astronomically rare and harmless (fail-open).
            uint32_t src_v6_hash = rte_hash_crc(ip6->src_addr.a, 16, 0x5a6b7c8d);
            uint32_t dst_v6_hash = rte_hash_crc(ip6->dst_addr.a, 16, 0x5a6b7c8d);

            // --- Stage 6c: Attack Signature Detection ---
            {
                struct sig_match sig_match;
                bool sig_drop = signatures_check(proto,
                                                 src_v6_hash, dst_v6_hash,
                                                 pf6.src_port, pf6.dst_port,
                                                 pf6.tcp_flags, pf6.packet_size,
                                                 pf6.ttl,
                                                 &sig_match);
                if (sig_drop) {
                    lstats->l1_packets_dropped++;
                    lstats->l1_drop_signature++;
                    result->action = L1_ACTION_DROP;
                    result->drop_reason = DROP_REASON_SIGNATURE;
                    return 0;
                }
            }

            // --- Stage 7: Policy Enforcement ---
            // Build a surrogate packet_features using CRC32 hashes of the IPv6
            // addresses as proxy keys.  Wildcard policies (src_ip/dst_ip == 0)
            // and port/protocol-based policies match correctly.  Policies keyed
            // on a specific IPv4 address will not match IPv6 traffic (correct
            // behaviour -- they are IPv4-only rules).
            struct policy_result policy_result_v6 = {0};
            {
                struct packet_features pf_surrogate = {0};
                pf_surrogate.src_ip   = src_v6_hash;
                pf_surrogate.dst_ip   = dst_v6_hash;
                pf_surrogate.src_port = pf6.src_port;
                pf_surrogate.dst_port = pf6.dst_port;
                pf_surrogate.protocol = proto;
                pf_surrogate.tcp_flags = pf6.tcp_flags;
                pf_surrogate.packet_size = pf6.packet_size;
                policy_lookup(&pf_surrogate, &policy_result_v6);
                if (policy_result_v6.matched &&
                    policy_result_v6.action == POLICY_DROP) {
                    lstats->l1_packets_dropped++;
                    lstats->l1_drop_policy++;
                    result->action = L1_ACTION_DROP;
                    result->drop_reason = DROP_REASON_POLICY;
                    return 0;
                }
            }

            // --- Stage 8: Reputation Check ---
            {
                struct reputation_result rep_v6 = {0};
                reputation_lookup(src_v6_hash, &rep_v6);
                if (rep_v6.found && rep_v6.level == REP_ATTACKER) {
                    lstats->l1_packets_dropped++;
                    lstats->l1_drop_reputation++;
                    result->action = L1_ACTION_DROP;
                    result->drop_reason = DROP_REASON_REPUTATION;
                    return 0;
                }
            }

            // --- Stage 8b: Spoofed TCP Flood Detection (IPv6) ---
            // IPv6 uses only global anomaly state -- no per-IP profile yet.
            // When in spoofed mode, non-SYN TCP packets with no existing flow
            // (and no valid SYN cookie) are dropped as likely spoofed source.
            if (proto == IPPROTO_TCP && anomaly_is_spoofed_mode() &&
                remaining >= sizeof(struct rte_tcp_hdr)) {
                bool is_syn_v6 = (pf6.tcp_flags & RTE_TCP_SYN_FLAG) &&
                                 !(pf6.tcp_flags & RTE_TCP_ACK_FLAG);
                if (!is_syn_v6) {
                    struct flow_entry_v6 *existing_v6 = flow_table_v6_lookup(&pf6);
                    if (!existing_v6) {
                        bool has_valid_cookie_v6 = false;
                        if (pf6.tcp_flags & RTE_TCP_ACK_FLAG) {
                            uint16_t mss_v6_out;
                            has_valid_cookie_v6 = syn_cookie_v6_validate(
                                ip6->src_addr.a, ip6->dst_addr.a,
                                pf6.src_port, pf6.dst_port,
                                pf6.tcp_seq - 1, pf6.tcp_ack, &mss_v6_out);
                        }
                        if (!has_valid_cookie_v6) {
                            lstats->l1_packets_dropped++;
                            lstats->l1_drop_spoofed_tcp++;
                            result->action = L1_ACTION_DROP;
                            result->drop_reason = DROP_REASON_SPOOFED_TCP;
                            return 0;
                        }
                    }
                }
            }

            // --- Stage 3c: Per-protected-IP features tracking ---
            // Skip tracking protocols/ports that the profile will DROP at Stage 4e
            // so Layer 2 baselines are not polluted by already-blocked traffic.
            struct per_ip_features_v6 *pif6 = per_ip_features_v6_lookup(ip6->dst_addr.a);
            if (pif6) {
                bool will_drop_v6 = false;
                if (dst_profile_v6) {
                    uint8_t pa = profile_proto_action(dst_profile_v6, proto);
                    if (pa == PROFILE_PROTO_DROP) {
                        will_drop_v6 = true;
                    } else if (!profile_port_allowed(dst_profile_v6, proto, pf6.dst_port)) {
                        will_drop_v6 = true;
                    }
                }
                if (!will_drop_v6) {
                    unsigned int lcore_id = rte_lcore_id();
                    per_ip_features_v6_update_counters(pif6, lcore_id, proto,
                        pf6.tcp_flags, pf6.packet_size, false);
                    // HLL/CMS: source-IP cardinality, port diversity, flow concentration
                    // (separate from counter update to avoid double-counting)
                    per_ip_hll_cms_v6_update(pif6, ip6->src_addr.a, pf6.src_port,
                        pf6.dst_port, src_v6_hash);
                }
            }

            // --- Stage 9b: TCP Flag Rate Limiting ---
            // SYN/ACK/RST/FIN flood detection per source (using surrogate hash key)
            if (proto == IPPROTO_TCP) {
                enum tcp_flag_rate_result flag_result = tcp_flag_rate_check(
                    src_v6_hash, pf6.tcp_flags, pf6.packet_size);
                if (flag_result != TCPF_RATE_ACCEPT) {
                    lstats->l1_packets_dropped++;
                    lstats->l1_drop_rate_limit++;
                    uint8_t flag_drop_reason;
                    switch (flag_result) {
                        case TCPF_RATE_DROP_SYN:
                        case TCPF_RATE_DROP_SYN_ACK:
                            flag_drop_reason = DROP_REASON_RATE_LIMIT_SYN; break;
                        case TCPF_RATE_DROP_ACK:
                            flag_drop_reason = DROP_REASON_RATE_LIMIT_ACK; break;
                        case TCPF_RATE_DROP_RST:
                            flag_drop_reason = DROP_REASON_RATE_LIMIT_RST; break;
                        case TCPF_RATE_DROP_FIN:
                            flag_drop_reason = DROP_REASON_RATE_LIMIT_FIN; break;
                        default:
                            flag_drop_reason = DROP_REASON_RATE_LIMIT;
                    }
                    result->action = L1_ACTION_DROP;
                    result->drop_reason = flag_drop_reason;
                    return 0;
                }
            }

            // --- Stage 10: Connection Limits (TCP SYN, non-proxied) ---
            if (proto == IPPROTO_TCP &&
                (pf6.tcp_flags & RTE_TCP_SYN_FLAG) && !(pf6.tcp_flags & RTE_TCP_ACK_FLAG) &&
                !syn_proxy_v6_is_enabled()) {
                if (!connection_limits_check(src_v6_hash, pf6.dst_port)) {
                    lstats->l1_packets_dropped++;
                    lstats->l1_drop_syn_flood++;
                    result->action = L1_ACTION_DROP;
                    result->drop_reason = DROP_REASON_SYN_FLOOD;
                    return 0;
                }
            }

            // --- Stage 10B: UDP Admission Control ---
            if (proto == IPPROTO_UDP) {
                enum udp_gk_action gk_action = udp_gatekeeper_check(
                    src_v6_hash, pf6.packet_size, NULL);
                if (gk_action != UDP_GK_ACCEPT) {
                    lstats->l1_packets_dropped++;
                    uint8_t udp_drop_reason;
                    switch (gk_action) {
                        case UDP_GK_DROP_RATE:
                        case UDP_GK_DROP_BPS:
                            udp_drop_reason = DROP_REASON_RATE_LIMIT_UDP;
                            lstats->l1_drop_rate_limit++;
                            break;
                        default:
                            udp_drop_reason = DROP_REASON_UDP_GATEKEEPER;
                            lstats->l1_drop_rate_limit++;
                    }
                    result->action = L1_ACTION_DROP;
                    result->drop_reason = udp_drop_reason;
                    return 0;
                }
            }

            // --- Stage 9: SYN Proxy (TCP only) ---
            if (proto == IPPROTO_TCP && remaining >= sizeof(struct rte_tcp_hdr)) {
                struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;

                // SYN packet -- challenge with SYN cookie
                if ((tcp->tcp_flags & RTE_TCP_SYN_FLAG) && !(tcp->tcp_flags & RTE_TCP_ACK_FLAG)) {
                    if (syn_proxy_v6_is_enabled()) {
                        uint32_t seq = rte_be_to_cpu_32(tcp->sent_seq);
                        uint16_t mss = extract_tcp_mss(tcp);
                        if (mss == 0) mss = 1440;

                        uint32_t cookie = syn_cookie_v6_generate(
                            ip6->src_addr.a, ip6->dst_addr.a,
                            pf6.src_port, pf6.dst_port, seq, mss
                        );

                        // Use proper transform function instead of inline hack
                        if (transform_syn_to_synack_v6_inplace(m, cookie)) {
                            lstats->l1_syn_proxy_challenges++;
                            result->action = L1_ACTION_REPLY_INPLACE;
                            return 0;
                        }
                        // Transform failed -- fall through to accept
                    }
                }

                // ACK packet -- validate SYN cookie
                if ((tcp->tcp_flags & RTE_TCP_ACK_FLAG) && !(tcp->tcp_flags & RTE_TCP_SYN_FLAG)) {
                    if (syn_proxy_v6_is_enabled()) {
                        uint32_t ack = rte_be_to_cpu_32(tcp->recv_ack);
                        uint32_t tcp_seq = rte_be_to_cpu_32(tcp->sent_seq);
                        uint16_t mss_out;

                        // Pass real client ISN and raw ack
                        if (syn_cookie_v6_validate(
                                ip6->src_addr.a, ip6->dst_addr.a,
                                pf6.src_port, pf6.dst_port, tcp_seq - 1, ack, &mss_out)) {
                            lstats->l1_syn_proxy_established++;
                            lstats->l1_packets_accepted++;
                            result->action = L1_ACTION_ACCEPT;
                            return 0;
                        }
                    }
                }
            }

            // --- Stage 11: Flow Table ---
            bool created = false;
            struct flow_entry_v6 *entry = flow_table_v6_lookup_or_create(&pf6, &created);
            if (entry) {
                entry->last_seen_tsc = rte_rdtsc();
                if (pf6.flow_direction == FLOW_DIR_LO_TO_HI) {
                    entry->packets_lo_to_hi++;
                    entry->bytes_lo_to_hi += pkt_len;
                } else {
                    entry->packets_hi_to_lo++;
                    entry->bytes_hi_to_lo += pkt_len;
                }
                flow_table_v6_update(entry, &pf6);

                if (created) {
                    lstats->l1_new_flows++;
                    if (proto == IPPROTO_UDP)
                        lstats->l1_new_udp_flows++;
                    per_ip_v6_increment_new_flow(pif6, rte_lcore_id());
                }

                // Apply policy rate limit from Stage 7 (override if stricter)
                if (policy_result_v6.matched &&
                    policy_result_v6.action == POLICY_RATE_LIMIT) {
                    uint32_t cur_pps = __atomic_load_n(&entry->pps_limit, __ATOMIC_RELAXED);
                    uint32_t cur_bps = __atomic_load_n(&entry->bps_limit, __ATOMIC_RELAXED);
                    if (policy_result_v6.rate_limit_pps &&
                        (cur_pps == 0 || policy_result_v6.rate_limit_pps < cur_pps)) {
                        __atomic_store_n(&entry->pps_limit,
                                         policy_result_v6.rate_limit_pps, __ATOMIC_RELAXED);
                    }
                    if (policy_result_v6.rate_limit_bps &&
                        (cur_bps == 0 || policy_result_v6.rate_limit_bps < cur_bps)) {
                        __atomic_store_n(&entry->bps_limit,
                                         policy_result_v6.rate_limit_bps, __ATOMIC_RELAXED);
                    }
                }

                // --- Stage 12: Per-flow rate limiting ---
                enum rate_limit_action rl = flow_table_v6_check_rate_limit(entry, &pf6);
                if (rl != RL_ACCEPT) {
                    lstats->l1_packets_dropped++;
                    lstats->l1_drop_rate_limit++;
                    result->action = L1_ACTION_DROP;
                    result->drop_reason = DROP_REASON_RATE_LIMIT;
                    return 0;
                }
            }

            // --- Stage 11d: TCP Abuse Detection ---
            if (proto == IPPROTO_TCP && tcp_abuse_is_enabled()) {
                static __thread struct tcp_abuse_state tls_v6_abuse_state = {0};
                static __thread uint32_t tls_v6_abuse_tracked_hash = 0;
                if (src_v6_hash != tls_v6_abuse_tracked_hash) {
                    tcp_abuse_state_init(&tls_v6_abuse_state);
                    tls_v6_abuse_tracked_hash = src_v6_hash;
                }
                tcp_abuse_state_reset_counters(&tls_v6_abuse_state);
                enum tcp_abuse_result abuse_result = tcp_abuse_check(
                    &tls_v6_abuse_state, src_v6_hash,
                    pf6.tcp_seq, pf6.tcp_ack, pf6.tcp_window,
                    pf6.tcp_flags, pf6.packet_size);
                if (abuse_result == TCP_ABUSE_RESULT_DROP) {
                    lstats->l1_packets_dropped++;
                    result->action = L1_ACTION_DROP;
                    result->drop_reason = DROP_REASON_TCP_ABUSE;
                    return 0;
                }
            }

            // Accept packet (passed all checks)
            lstats->l1_packets_accepted++;
            result->action = L1_ACTION_ACCEPT;
            return 0;
        }

        case 2:  // Log and drop
            RTE_LOG(DEBUG, L1, "IPv6 packet dropped (policy: log_and_drop)\n");
            // Fall through to drop

        case 0:  // Drop (default - safe)
        default:
            lstats->l1_packets_dropped++;
            lstats->l1_drop_ipv6++;
            result->action = L1_ACTION_DROP;
            result->drop_reason = DROP_REASON_IPV6_UNSUPPORTED;
            return 0;
        }
    }

    if (parse_result == PARSE_MALFORMED) {
        lstats->l1_packets_dropped++;
        lstats->l1_drop_validation++;
        lstats->l1_drop_parse_error++;
        // OPTIMIZATION: Skip telemetry for malformed packets (just count them)
        result->action = L1_ACTION_DROP;
        result->drop_reason = DROP_REASON_PARSE_ERROR;
        return 0;
    }

    features.direction = direction;

    // ========== Stage 3: Feature Extraction ==========
    feature_result = extract_features(m, &features);
    (void)feature_result;

    // ========== Stage 3b: Layer 2 Feature Counters (Protocol & TCP Flags) ==========
    // These counters are extremely cheap (~10 cycles total) and critical for
    // Layer 2 anomaly detection (SYN flood, UDP flood, protocol distribution)
    {
        uint8_t proto = features.protocol;
        if (proto == IPPROTO_TCP) {
            lstats->l1_tcp_packets++;
            uint8_t flags = features.tcp_flags;
            // Pure SYN (no ACK) - critical for SYN flood detection
            if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN) {
                lstats->l1_syn_packets++;
            }
            // SYN-ACK
            if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
                lstats->l1_syn_ack_packets++;
            }
            // ACK (any packet with ACK flag)
            if (flags & TCP_FLAG_ACK) {
                lstats->l1_ack_packets++;
            }
            // RST
            if (flags & TCP_FLAG_RST) {
                lstats->l1_rst_packets++;
            }
            // FIN
            if (flags & TCP_FLAG_FIN) {
                lstats->l1_fin_packets++;
            }
        } else if (proto == IPPROTO_UDP) {
            lstats->l1_udp_packets++;
        } else if (proto == IPPROTO_ICMP) {
            lstats->l1_icmp_packets++;
            if (features.icmp_type == 8)  // Echo request
                lstats->l1_icmp_echo_packets++;
        } else {
            lstats->l1_other_packets++;

            // ========== Stage 3d: Other Protocols Filter ==========
            // For non-TCP/UDP/ICMP protocols, check if allowed
            if (other_proto_should_drop(proto, features.src_ip)) {
                lstats->l1_packets_dropped++;
                lstats->l1_drop_other_proto++;
                result->action = L1_ACTION_DROP;
                result->drop_reason = DROP_REASON_OTHER_PROTO;
                return 0;
            }
        }

        // Update global HLL for unique source IPs (~30 cycles)
        hll_global_add_src_ip(features.src_ip);

        // Global counters for new L2 features
        lstats->l1_ttl_sum += features.ttl;
        if (features.packet_size <= 64)
            lstats->l1_small_packets++;
        if ((features.ip_flags & 0x2000) || (features.ip_flags & 0x1FFF))
            lstats->l1_fragment_packets++;

    }

    // ========== Stage 3c: Per-Protected-IP Feature Counters ==========
    // Lookup if dst_ip is a protected IP and update per-IP stats (~50 cycles)
    // This enables Layer 2 anomaly detection per victim with full features
    // (HLL for cardinality + CMS for concentration)
    //
    // IMPORTANT: Skip counting protocols that the profile will DROP at Stage 4e.
    // Otherwise Layer 2 baselines and anomaly detection react to traffic that's
    // already being blocked, causing false positives and misleading features.
    {
        // Exact protected /32 takes precedence (its own slot). If the dst isn't an
        // exact protected IP but falls inside a protected SUBNET, aggregate it into
        // that subnet's single slot (keyed by the subnet network) so a carpet-bomb
        // spread across many addresses in the subnet is visible as one destination.
        // The subnet LPM lookup only runs for non-exact IPs and only when subnets
        // exist, so the common path is unchanged.
        struct per_ip_features *exact_pif = per_ip_features_lookup(features.dst_ip);
        uint32_t subnet_net_be = 0;
        bool in_subnet = (!exact_pif && ip_protected_subnet_count() > 0 &&
                          ip_protected_subnet_lookup(features.dst_ip, &subnet_net_be));
        uint32_t track_key = l1_resolve_track_key(features.dst_ip, exact_pif != NULL,
                                                  in_subnet, subnet_net_be);
        struct per_ip_features *pif = exact_pif ? exact_pif
                                    : (in_subnet ? per_ip_features_lookup(track_key) : NULL);
        if (pif) {
            // Check if this protocol will be dropped by the profile.
            // NOTE: for a SUBNET-aggregated slot the dst is not an exact protected
            // IP, so ip_protected_lookup_profile() returns NULL -> profile_proto_action
            // = ALLOW and the port check is guarded out (early_prof &&). The will_drop
            // FP-suppression below is therefore a NO-OP for subnet traffic: subnets
            // carry no per-IP profile to drop against, so the baseline simply reflects
            // what passes. The suppression property still holds for exact /32 entries.
            const struct protection_profile *early_prof = NULL;
            ip_protected_lookup_profile(features.dst_ip, &early_prof);
            uint8_t proto_act = profile_proto_action(early_prof, features.protocol);

            // Also check port allowlist: if protocol is ALLOW but port is blocked,
            // the packet will still be dropped at Stage 4e
            bool will_drop = (proto_act == PROFILE_PROTO_DROP);
            if (!will_drop && early_prof &&
                !profile_port_allowed(early_prof, features.protocol, features.dst_port)) {
                will_drop = true;
            }

            if (!will_drop) {
                // Update per-IP counters and HLL/CMS (protocol, TCP flags, bytes, cardinality)
                unsigned int cur_lcore = rte_lcore_id();
                per_ip_features_update_counters(pif, cur_lcore,
                                                features.protocol,
                                                features.tcp_flags,
                                                features.packet_size,
                                                false);  // is_new_flow will be set later if flow is new

                // Update extended counters (small packets, fragments, TTL)
                per_ip_features_update_extended(pif, cur_lcore,
                                                features.ttl,
                                                features.packet_size,
                                                features.ip_flags);

                // Update HLL and CMS for this protected IP
                // (sampled: every 8th packet for performance)
                if ((lstats->l1_total_packets & 0x7) == 0) {
                    per_ip_hll_cms_update(pif, features.src_ip, features.src_port, features.dst_port, features.flow_hash);
                }
            }
        }
    }

    // ========== Stage 4: Validation ==========
    // 4a: Checksum validation (uses mbuf, must be before validate_packet)
    validation_result = validate_ip_checksum(m);
    if (validation_result != VALIDATE_OK) {
        __atomic_add_fetch(&validation_errors[VALIDATE_ERR_BAD_CHECKSUM], 1, __ATOMIC_RELAXED);
        lstats->l1_packets_dropped++;
        lstats->l1_drop_validation++;
        lstats->l1_drop_checksum++;
        // OPTIMIZATION: Skip telemetry for checksum failures (high volume during attacks)
        result->action = L1_ACTION_DROP;
        result->drop_reason = DROP_REASON_IP_CHECKSUM;
        return 0;
    }

    // 4b: UDP checksum validation (if UDP)
    if (features.protocol == IPPROTO_UDP) {
        validation_result = validate_udp_checksum(m);
        if (validation_result != VALIDATE_OK) {
            __atomic_add_fetch(&validation_errors[VALIDATE_ERR_UDP_CHECKSUM], 1, __ATOMIC_RELAXED);
            lstats->l1_packets_dropped++;
            lstats->l1_drop_validation++;
            lstats->l1_drop_checksum++;
            // OPTIMIZATION: Skip telemetry for checksum failures
            result->action = L1_ACTION_DROP;
            result->drop_reason = DROP_REASON_UDP_CHECKSUM;
            return 0;
        }
    }

    // 4b2: ICMP checksum validation (if ICMP)
    if (features.protocol == IPPROTO_ICMP) {
        const struct layer1_config *cfg = layer1_config_get();
        if (cfg && cfg->validation.validate_icmp_checksum) {
            validation_result = validate_icmp_checksum(m);
            if (validation_result != VALIDATE_OK) {
                __atomic_add_fetch(&validation_errors[VALIDATE_ERR_ICMP_CHECKSUM], 1, __ATOMIC_RELAXED);
                lstats->l1_packets_dropped++;
                lstats->l1_drop_validation++;
                lstats->l1_drop_checksum++;
                result->action = L1_ACTION_DROP;
                result->drop_reason = DROP_REASON_ICMP_MALFORMED;
                return 0;
            }
        }
    }

    // 4c: Protocol validation
    validation_result = validate_packet(&features);

    if (validation_result != VALIDATE_OK) {
        // Fast path: just update counters - no expensive logging/telemetry
        if (validation_result > 0 && validation_result < 32) {
            __atomic_add_fetch(&validation_errors[validation_result], 1, __ATOMIC_RELAXED);
        }

        lstats->l1_packets_dropped++;
        lstats->l1_drop_validation++;
        lstats->l1_drop_proto_validation++;

        // Rate-limited logging using atomic fetch_add to prevent race
        // Previously: check-then-act race could log more than 10 times
        static uint64_t error_log_count = 0;
        uint64_t prev_count = __atomic_fetch_add(&error_log_count, 1, __ATOMIC_RELAXED);
        if (unlikely(prev_count < 10)) {
            uint32_t src = rte_be_to_cpu_32(features.src_ip);
            uint32_t dst = rte_be_to_cpu_32(features.dst_ip);
            RTE_LOG(WARNING, L1, "Validation failed: %s (dir=%s src=%u.%u.%u.%u dst=%u.%u.%u.%u)\n",
                    validation_error_str(validation_result),
                    direction == DIRECTION_INBOUND ? "IN" : "OUT",
                    (src >> 24) & 0xFF, (src >> 16) & 0xFF,
                    (src >> 8) & 0xFF, src & 0xFF,
                    (dst >> 24) & 0xFF, (dst >> 16) & 0xFF,
                    (dst >> 8) & 0xFF, dst & 0xFF);
        }

        // OPTIMIZATION: Skip expensive telemetry/reputation for validation failures
        // These are typically bogon IPs that don't need tracking (wasted work)
        // Stats counters above are sufficient for monitoring

        result->action = L1_ACTION_DROP;
        result->drop_reason = DROP_REASON_VALIDATION;
        return 0;
    }

    // 4f: L7 Protocol Validation (DNS, NTP, HTTP)
    if (features.payload_len > 0) {
        int l7_result = validate_l7_packet(m, &features);
        if (l7_result != L7_VALIDATE_OK) {
            lstats->l1_packets_dropped++;
            lstats->l1_drop_validation++;
            lstats->l1_drop_l7_validation++;

            static uint64_t l7_log_count = 0;
            uint64_t prev = __atomic_fetch_add(&l7_log_count, 1, __ATOMIC_RELAXED);
            if (unlikely(prev < 10)) {
                uint32_t src = rte_be_to_cpu_32(features.src_ip);
                uint32_t dst = rte_be_to_cpu_32(features.dst_ip);
                RTE_LOG(WARNING, L1, "L7 validation failed: %s (src=%u.%u.%u.%u dst=%u.%u.%u.%u port=%u)\n",
                        l7_error_str(l7_result),
                        (src >> 24) & 0xFF, (src >> 16) & 0xFF,
                        (src >> 8) & 0xFF, src & 0xFF,
                        (dst >> 24) & 0xFF, (dst >> 16) & 0xFF,
                        (dst >> 8) & 0xFF, dst & 0xFF,
                        features.dst_port);
            }

            result->action = L1_ACTION_DROP;
            result->drop_reason = DROP_REASON_VALIDATION;
            return 0;
        }
    }

    // ========== Direction-Specific Processing ==========
    int rc;
    if (direction == DIRECTION_INBOUND) {
        rc = process_inbound_packet(m, port_id, queue_id, &features, mempool, result);

        // Track-and-Allow override: whitelisted IPs in track mode ran through all
        // stages for telemetry, but we override DROP -> ACCEPT so they're never dropped
        if (result->whitelist_track && result->action == L1_ACTION_DROP) {
            result->action = L1_ACTION_ACCEPT;
            struct lcore_stats *ls = get_lcore_stats();
            ls->l1_packets_accepted++;
            // Undo the dropped counter that was incremented in the stage
            if (ls->l1_packets_dropped > 0)
                ls->l1_packets_dropped--;
        }

        return rc;
    } else {
        return process_outbound_packet(m, port_id, queue_id, &features, mempool, result);
    }
}

/**
 * Simple API - DEPRECATED for SYN proxy use
 * Does NOT properly handle reply packets in multi-queue mode
 */
int layer1_process_packet(struct rte_mbuf *m, uint16_t port_id) {
    struct layer1_result result;
    struct rte_mempool *mempool = get_pktmbuf_pool();
    
    // Use queue 0 as fallback - this is why it's deprecated
    int ret = layer1_process_packet_ex(m, port_id, 0, mempool, &result);
    if (ret < 0) {
        return L1_DROP;
    }

    // WARNING: Reply packets cannot be safely sent without proper queue context
    // Free them to avoid memory leaks
    // Validate mbuf has valid pool before freeing to prevent pool corruption
    if (result.reply_pkt && result.reply_pkt->pool) {
        rte_pktmbuf_free(result.reply_pkt);
    }
    if (result.forward_pkt && result.forward_pkt->pool) {
        rte_pktmbuf_free(result.forward_pkt);
    }

    switch (result.action) {
        case L1_ACTION_ACCEPT:
        case L1_ACTION_ACCEPT_MODIFIED:
            return L1_ACCEPT;
        case L1_ACTION_DROP:
        case L1_ACTION_REPLY:
        default:
            return L1_DROP;
    }
}

// ==================== Maintenance ====================

uint32_t layer1_maintenance(void) {
    if (!__atomic_load_n(&initialized_atomic, __ATOMIC_ACQUIRE)) {
        return 0;
    }

    uint32_t cleaned = 0;
    uint64_t now = rte_get_tsc_cycles();

    if (tsc_hz > 0 && (now - last_maintenance_tsc) >= tsc_hz) {
        cleaned += flow_table_age_flows();
        cleaned += syn_proxy_cleanup_connections();
        cleaned += connection_limits_cleanup_expired();
        cleaned += legitimate_ip_cleanup();
        cleaned += tcp_flag_rate_cleanup_expired();
        // Add IPv6 maintenance
        cleaned += flow_table_v6_age_flows();
        cleaned += syn_proxy_v6_cleanup_connections();
        // Reset per-protocol aggregate rate counters (1Hz epoch)
        ip_protected_proto_counters_reset();
        last_maintenance_tsc = now;
    }

    if (tsc_hz > 0 && (now - last_secret_rotation_tsc) >= (60 * tsc_hz)) {
        syn_proxy_rotate_secret(rte_rand());
        // Rotate IPv6 SYN cookie secret too
        syn_proxy_v6_rotate_secret(rte_rand());
        last_secret_rotation_tsc = now;
    }

    // NOTE: Reputation decay is handled by L4 (reputation_maintenance -> reputation_decay_all)
    // L4 syncs decayed scores to L1 shmem via reputation_sync_to_shmem()

    return cleaned;
}

uint32_t layer1_age_flows(void) {
    if (!__atomic_load_n(&initialized_atomic, __ATOMIC_ACQUIRE)) {
        return 0;
    }
    return flow_table_age_flows();
}

// ==================== Initialization ====================

int layer1_init(uint32_t max_flows, const char *config_file) {
    struct layer1_config cfg;
    struct flow_table_config flow_cfg;
    struct ip_lists_config ip_cfg;

    if (__atomic_load_n(&initialized_atomic, __ATOMIC_ACQUIRE)) {
        RTE_LOG(WARNING, L1, "Layer 1 already initialized\n");
        return 0;
    }

    // Load configuration from file (or use defaults)
    if (layer1_config_load(config_file, &cfg) < 0) {
        RTE_LOG(ERR, L1, "Failed to load configuration\n");
        return -1;
    }

    // Validate configuration
    if (layer1_config_validate(&cfg) < 0) {
        RTE_LOG(ERR, L1, "Invalid configuration\n");
        return -1;
    }

    // Override max_flows if specified (backwards compatibility)
    if (max_flows > 0) {
        cfg.flow_table.max_flows = max_flows;
    }

    // Store active configuration
    layer1_config_set_active(&cfg);

    RTE_LOG(INFO, L1, "Initializing Layer 1 (Direction-Aware with SYN Proxy)\n");
    RTE_LOG(INFO, L1, "  Port %d: Client-facing (INBOUND)\n", cfg.ports.client_facing_port);
    RTE_LOG(INFO, L1, "  Port %d: Server-facing (OUTBOUND)\n", cfg.ports.server_facing_port);
    RTE_LOG(INFO, L1, "  Max flows: %u\n", cfg.flow_table.max_flows);

    if (config_file) {
        RTE_LOG(INFO, L1, "  Config: %s\n", config_file);
    }

    // Print configuration summary
    layer1_config_print(&cfg);

    max_flows_configured = cfg.flow_table.max_flows;
    // Use atomic store for should_decrement_ttl during init
    __atomic_store_n(&should_decrement_ttl_atomic, cfg.validation.decrement_ttl ? 1 : 0, __ATOMIC_RELEASE);
    // Use atomic store for cross-core visibility
    __atomic_store_n(&monitor_only_mode_atomic, cfg.monitor_only ? 1 : 0, __ATOMIC_RELEASE);
    __atomic_store_n(&tap_mode_atomic, cfg.tap_mode ? 1 : 0, __ATOMIC_RELEASE);
    tsc_hz = rte_get_tsc_hz();
    last_maintenance_tsc = rte_get_tsc_cycles();
    last_secret_rotation_tsc = last_maintenance_tsc;

    if (cfg.monitor_only) {
        RTE_LOG(WARNING, L1, "*** MONITOR-ONLY MODE ENABLED - NO PROTECTION ***\n");
    }
    if (cfg.tap_mode) {
        RTE_LOG(WARNING, L1, "*** TAP MODE ENABLED - MIRROR TRAFFIC ON PORT 0, NO FORWARDING ***\n");
    }

    // Initialize IP lists from config
    ip_cfg.max_whitelist_entries = cfg.ip_lists.max_whitelist_entries;
    ip_cfg.max_blacklist_entries = cfg.ip_lists.max_blacklist_entries;
    ip_cfg.max_protected_entries = cfg.ip_lists.max_protected_entries;
    ip_cfg.max_whitelist_cidrs = cfg.ip_lists.max_whitelist_cidrs;
    ip_cfg.enforce_protected_ips = cfg.ip_lists.enforce_protected_ips;
    if (ip_lists_init(&ip_cfg) < 0) {
        RTE_LOG(ERR, L1, "Failed to initialize IP lists\n");
        return -1;
    }

    // Initialize IPv6 IP lists (cleanup always calls ip_lists_v6_cleanup)
    {
        struct ip_lists_v6_config ip6_cfg = {
            .max_whitelist_entries = cfg.ip_lists.max_whitelist_entries,
            .max_blacklist_entries = cfg.ip_lists.max_blacklist_entries,
            .max_protected_entries = cfg.ip_lists.max_protected_entries,
            .max_whitelist_cidrs = cfg.ip_lists.max_whitelist_cidrs,
            .enforce_protected_ips = cfg.ip_lists.enforce_protected_ips,
        };
        if (ip_lists_v6_init(&ip6_cfg) < 0) {
            RTE_LOG(WARNING, L1, "IPv6 IP lists init failed - continuing without IPv6 IP lists\n");
        }
    }

    // NOTE: IP lists are loaded AFTER per_ip_features_init() to ensure
    // protected IPs get registered for per-IP feature tracking.
    // See below after per_ip_features_init() call.

    // Initialize flow table from config
    flow_cfg.max_flows = cfg.flow_table.max_flows;
    flow_cfg.idle_timeout_sec = cfg.flow_table.idle_timeout_sec;
    flow_cfg.syn_timeout_sec = cfg.flow_table.syn_timeout_sec;
    flow_cfg.default_pps_limit = cfg.flow_table.default_pps_limit;
    flow_cfg.default_bps_limit = cfg.flow_table.default_bps_limit;
    flow_cfg.enable_syn_protection = cfg.flow_table.enable_syn_protection;
    flow_cfg.aging_scan_limit = cfg.flow_table.aging_scan_limit;
    flow_cfg.aging_scan_limit_pressure = cfg.flow_table.aging_scan_limit_pressure;
    if (flow_table_init(&flow_cfg) < 0) {
        RTE_LOG(ERR, L1, "Failed to initialize flow table\n");
        ip_lists_cleanup();
        return -1;
    }

    // Initialize IPv6 flow table (cleanup always calls flow_table_v6_cleanup)
    {
        struct flow_table_v6_config flow6_cfg = {
            .max_flows = cfg.flow_table.max_flows / 4,  // IPv6 gets 1/4 of IPv4 capacity
            .idle_timeout_sec = cfg.flow_table.idle_timeout_sec,
            .syn_timeout_sec = cfg.flow_table.syn_timeout_sec,
            .default_pps_limit = cfg.flow_table.default_pps_limit,
            .default_bps_limit = cfg.flow_table.default_bps_limit,
            .enable_syn_protection = cfg.flow_table.enable_syn_protection,
            .aging_scan_limit = cfg.flow_table.aging_scan_limit,
        };
        if (flow_table_v6_init(&flow6_cfg) < 0) {
            RTE_LOG(WARNING, L1, "IPv6 flow table init failed - continuing without IPv6 flow tracking\n");
        }
    }

    // Initialize spoofed mode rate limiting (per-dst aggregate + legitimate IP table)
    if (spoofed_rate_init(cfg.rate_limits.legitimate_table_size) < 0) {
        RTE_LOG(WARNING, L1, "Failed to initialize spoofed rate limiting (non-fatal)\n");
    }

    // Initialize SYN Proxy from config
    struct syn_proxy_config proxy_cfg = {
        .max_connections = cfg.syn_proxy.max_connections,
        .connect_timeout_ms = cfg.syn_proxy.connect_timeout_ms,
        .idle_timeout_sec = cfg.syn_proxy.idle_timeout_sec,
        .secret = rte_rand(),
        .secret_rotation_sec = cfg.syn_proxy.secret_rotation_sec,
        .enabled = cfg.syn_proxy.enabled,
        .stateless_threshold_pps = cfg.syn_proxy.stateless_threshold_pps,
        .stateful_threshold_pps = cfg.syn_proxy.stateful_threshold_pps,
        .mode_switch_delay_ms = cfg.syn_proxy.mode_switch_delay_ms,
        .challenge_threshold = cfg.syn_cookie.challenge_threshold,
    };
    if (syn_proxy_init(&proxy_cfg) < 0) {
        RTE_LOG(ERR, L1, "Failed to initialize SYN proxy\n");
        flow_table_cleanup();
        ip_lists_cleanup();
        return -1;
    }

    // Initialize IPv6 SYN proxy (cleanup always calls syn_proxy_v6_cleanup)
    if (syn_proxy_v6_init(&proxy_cfg) < 0) {
        RTE_LOG(WARNING, L1, "IPv6 SYN proxy init failed - continuing without IPv6 SYN proxy\n");
    }

    // Initialize shared memory (POSIX for Python IPC access)
    if (shared_memory_init_posix() < 0) {
        RTE_LOG(ERR, L1, "Failed to initialize POSIX shared memory\n");
        syn_proxy_cleanup();
        flow_table_cleanup();
        ip_lists_cleanup();
        return -1;
    }

    // Initialize randomized hash seed for flow table (prevents collision DoS)
    packet_parser_init_hash_seed();

    // Initialize packet ring buffer (uses shared memory if available)
    if (packet_ring_init() < 0) {
        RTE_LOG(WARNING, L1, "Packet ring init failed - continuing without packet sampling\n");
    }

    // Initialize policy interface
    if (policy_interface_init() < 0) {
        RTE_LOG(ERR, L1, "Failed to initialize policy interface\n");
        shared_memory_cleanup();
        syn_proxy_cleanup();
        flow_table_cleanup();
        ip_lists_cleanup();
        return -1;
    }

    // Initialize reputation interface
    if (reputation_interface_init() < 0) {
        RTE_LOG(ERR, L1, "Failed to initialize reputation interface\n");
        policy_interface_cleanup();
        shared_memory_cleanup();
        syn_proxy_cleanup();
        flow_table_cleanup();
        ip_lists_cleanup();
        return -1;
    }

    // Initialize connection limits from config
    // GRACEFUL DEGRADATION: If init fails, connection_limits_check() returns true (fail-open)
    // This allows packet processing to continue without per-IP connection limiting
    struct connection_limits_config conn_cfg = {
        .max_ips = cfg.connection_limits.max_ips,
        .max_connections_per_ip = cfg.connection_limits.max_connections_per_ip,
        .time_window_sec = cfg.connection_limits.time_window_sec,
        .cleanup_interval_sec = cfg.connection_limits.cleanup_interval_sec,
    };
    if (connection_limits_init(&conn_cfg) < 0) {
        // If connection limits were explicitly configured (non-zero values),
        // treat initialization failure as an error, not just a warning
        if (cfg.connection_limits.max_connections_per_ip > 0) {
            RTE_LOG(ERR, L1, "Connection limits init failed but limits configured "
                    "(max_conn/ip=%u) - this is a configuration error!\n",
                    cfg.connection_limits.max_connections_per_ip);
            // Note: We don't fail completely, as fail-open is still safer than blocking startup
            // But the ERROR log level ensures monitoring picks this up
        } else {
            RTE_LOG(INFO, L1, "Connection limits not configured (max_conn/ip=0), skipping\n");
        }
    }

    // Initialize telemetry from config
    struct telemetry_config tele_cfg = {
        .db_path = cfg.telemetry.db_path,
        .export_interval_sec = cfg.telemetry.export_interval_sec,
        .max_flow_records = cfg.telemetry.max_flow_records,
        .export_packet_samples = cfg.telemetry.export_packet_samples,
        .flow_sample_rate = cfg.telemetry.flow_sample_rate,
        .events_enabled = cfg.telemetry.events_enabled,
    };
    if (telemetry_init(&tele_cfg) < 0) {
        RTE_LOG(WARNING, L1, "Telemetry init failed - continuing without telemetry\n");
    } else {
        RTE_LOG(INFO, L1, "Telemetry enabled (flow sampling 1:%u, events=%s)\n",
                tele_cfg.flow_sample_rate,
                tele_cfg.events_enabled ? "on" : "off");
    }

    // Initialize HyperLogLog for unique IP counting (Stage 11B)
    // Window duration matches anomaly detection window from config
    uint32_t hll_window = cfg.rate_limits.anomaly_detection_window;
    if (hll_window == 0) {
        hll_window = 60;  // Default 60 seconds
    }
    if (hll_global_init(hll_window) < 0) {
        RTE_LOG(WARNING, L1, "HyperLogLog init failed - continuing without HLL\n");
    }

    // Initialize UDP Gatekeeper (Stage 10B - UDP admission control)
    // Protects flow table from UDP floods using Count-Min Sketch
    struct udp_gatekeeper_config udp_gk_cfg = {
        .pps_threshold = cfg.udp_gatekeeper.pps_threshold,
        .bps_threshold = cfg.udp_gatekeeper.bps_threshold,
        .cms_width = cfg.udp_gatekeeper.cms_width,
        .cms_depth = cfg.udp_gatekeeper.cms_depth,
        .window_sec = cfg.udp_gatekeeper.window_sec,
        .check_reputation = cfg.udp_gatekeeper.check_reputation,
        .reputation_threshold = cfg.udp_gatekeeper.reputation_threshold,
        .check_blacklist = cfg.udp_gatekeeper.check_blacklist,
        .attack_pps_divisor = cfg.udp_gatekeeper.attack_pps_divisor,
        .attack_bps_divisor = cfg.udp_gatekeeper.attack_bps_divisor,
    };
    if (udp_gatekeeper_init(&udp_gk_cfg) < 0) {
        RTE_LOG(WARNING, L1, "UDP Gatekeeper init failed - continuing without UDP admission control\n");
    }

    // Initialize Per-Protected-IP Feature Tracking (Stage 3c)
    // Each protected IP gets its own set of counters, HLLs, and CMS
    // This provides full Layer 2 features per protected IP for anomaly detection
    if (per_ip_features_init(cfg.ip_lists.max_protected_entries) < 0) {
        RTE_LOG(WARNING, L1, "Per-IP features init failed - continuing without per-IP feature tracking\n");
    }

    // CMS concentration export (section 4.8: max_flow_fraction / topk_flow_share / heavy_hitter_count)
    // is opt-in and OFF by default so shipped behaviour is unchanged. Enabled by config
    // (telemetry.concentration_export_enabled) OR the environment override
    // ANTIDDOS_CONCENTRATION_EXPORT=1 (also accepts t/T/y/Y), the latter mirroring ANTIDDOS_CONFIG_DIR.
    // Validate FPR on benign single-elephant-flow destinations before enabling in production.
    {
        const char *cc_env = getenv("ANTIDDOS_CONCENTRATION_EXPORT");
        bool cc_on = cfg.telemetry.concentration_export_enabled ||
                     (cc_env && (cc_env[0] == '1' || cc_env[0] == 't' || cc_env[0] == 'T' ||
                                 cc_env[0] == 'y' || cc_env[0] == 'Y'));
        per_ip_features_set_concentration_export(cc_on);
    }

    // Initialize IPv6 per-IP features (cleanup always calls per_ip_features_v6_cleanup)
    if (per_ip_features_v6_init(cfg.ip_lists.max_protected_entries) < 0) {
        RTE_LOG(WARNING, L1, "IPv6 per-IP features init failed - continuing without IPv6 per-IP features\n");
    }

    // NOW load persisted IP lists (whitelist, blacklist, protected IPs)
    // This MUST be after per_ip_features_init() so that protected IPs
    // get automatically registered for per-IP feature tracking
    ip_lists_load(NULL);

    // Log how many protected IPs were registered
    uint32_t n_protected = ip_protected_count();
    if (n_protected > 0) {
        RTE_LOG(INFO, L1, "Per-IP features enabled for %u protected IPs\n", n_protected);
    }

    // Initialize DPDK Telemetry endpoints
    // This registers /antiddos/* commands for monitoring via dpdk-telemetry.py
    if (dpdk_telemetry_init() < 0) {
        RTE_LOG(WARNING, L1, "DPDK telemetry init failed - continuing without telemetry endpoints\n");
    }

    // Initialize real-time shared memory telemetry for Layer 2/3 integration
    // Creates /dev/shm/antiddos_realtime for zero-copy stats access
    if (realtime_telemetry_init() < 0) {
        RTE_LOG(WARNING, L1, "Real-time telemetry init failed - continuing without shared memory\n");
    }

    // Initialize multi-window statistics for Layer 2 anomaly detection
    // Creates /dev/shm/antiddos_windows for 1s, 10s, 60s sliding windows
    if (window_stats_init() < 0) {
        RTE_LOG(WARNING, L1, "Window stats init failed - continuing without window statistics\n");
    }

    // Initialize Geo-Blocking (Stage 6b)
    {
        struct geo_config geo_cfg = {
            .enabled = cfg.geo_blocking.enabled,
            .mode = (cfg.geo_blocking.mode == 1) ? GEO_MODE_BLACKLIST : GEO_MODE_WHITELIST,
            .log_blocked = cfg.geo_blocking.log_blocked,
            .block_unknown = cfg.geo_blocking.block_unknown,
            .country_count = 0,
        };
        // Load countries from config file
        for (uint32_t i = 0; i < cfg.geo_blocking.country_count && i < GEO_MAX_COUNTRIES; i++) {
            country_code_t cc = country_str_to_code(cfg.geo_blocking.countries[i]);
            if (cc != 0) {
                geo_cfg.countries[geo_cfg.country_count++] = cc;
            }
        }
        if (geo_blocking_init(&geo_cfg) < 0) {
            RTE_LOG(WARNING, L1, "Geo-blocking init failed - continuing without geo-blocking\n");
        } else {
            if (cfg.geo_blocking.enabled) {
                RTE_LOG(INFO, L1, "Geo-blocking enabled (mode=%s)\n",
                        geo_cfg.mode == GEO_MODE_BLACKLIST ? "blacklist" : "whitelist");
            }
            // Load GeoIP database for IP-to-country lookups
            if (cfg.geo_blocking.database_path[0] != '\0') {
                if (geo_reload_database(cfg.geo_blocking.database_path) == 0) {
                    RTE_LOG(INFO, L1, "GeoIP database loaded: %s\n",
                            cfg.geo_blocking.database_path);
                } else {
                    RTE_LOG(WARNING, L1, "Failed to load GeoIP database: %s - "
                            "geo-blocking will not resolve countries\n",
                            cfg.geo_blocking.database_path);
                }
            } else {
                RTE_LOG(WARNING, L1, "No GeoIP database path configured - "
                        "geo-blocking will not resolve countries\n");
            }
        }
    }

    // Initialize IPv6 geo-blocking (cleanup always calls geo_blocking_v6_cleanup)
    {
        struct geo_config geo6_cfg = {
            .enabled = cfg.geo_blocking.enabled,
            .mode = (cfg.geo_blocking.mode == 1) ? GEO_MODE_BLACKLIST : GEO_MODE_WHITELIST,
            .log_blocked = cfg.geo_blocking.log_blocked,
            .block_unknown = cfg.geo_blocking.block_unknown,
            .country_count = 0,
        };
        for (uint32_t i = 0; i < cfg.geo_blocking.country_count && i < GEO_MAX_COUNTRIES; i++) {
            country_code_t cc = country_str_to_code(cfg.geo_blocking.countries[i]);
            if (cc != 0) {
                geo6_cfg.countries[geo6_cfg.country_count++] = cc;
            }
        }
        if (geo_blocking_v6_init(&geo6_cfg) < 0) {
            RTE_LOG(WARNING, L1, "IPv6 geo-blocking init failed - continuing without IPv6 geo-blocking\n");
        }
    }

    // Initialize Other Protocols Filter (Stage 3d)
    {
        struct other_proto_config proto_cfg = {
            .enabled = cfg.other_protocols.enabled,
            .default_action = cfg.other_protocols.default_action,
            .rate_limit_pps = cfg.other_protocols.rate_limit_pps,
            .log_unknown = cfg.other_protocols.log_unknown,
            .allowed_count = cfg.other_protocols.allowed_count,
        };
        memcpy(proto_cfg.allowed_protocols, cfg.other_protocols.allowed_protocols,
               sizeof(proto_cfg.allowed_protocols));
        if (other_proto_init(&proto_cfg) < 0) {
            RTE_LOG(WARNING, L1, "Other protocols filter init failed - continuing\n");
        } else if (cfg.other_protocols.enabled) {
            RTE_LOG(INFO, L1, "Other protocols filter enabled (action=%s, allowed=%u)\n",
                    cfg.other_protocols.default_action == 0 ? "drop" :
                    (cfg.other_protocols.default_action == 1 ? "accept" : "rate_limit"),
                    cfg.other_protocols.allowed_count);
        }
    }

    // Initialize Attack Signatures Detection (Stage 6c)
    {
        struct signatures_config sig_cfg = {
            .enabled = cfg.signatures.enabled,
            .log_matches = cfg.signatures.log_matches,
            .block_amplification = cfg.signatures.block_amplification,
            .block_scans = cfg.signatures.block_scans,
            .block_anomalies = cfg.signatures.block_anomalies,
            .block_attack_tools = cfg.signatures.block_attack_tools,
        };
        if (signatures_init(&sig_cfg) < 0) {
            RTE_LOG(WARNING, L1, "Signatures init failed - continuing without signature detection\n");
        } else if (cfg.signatures.enabled) {
            RTE_LOG(INFO, L1, "Attack signatures enabled (amplification=%s, scans=%s, tools=%s)\n",
                    sig_cfg.block_amplification ? "block" : "log",
                    sig_cfg.block_scans ? "block" : "log",
                    sig_cfg.block_attack_tools ? "block" : "log");
        }
    }

    // Initialize TCP Abuse Detection
    // Detects malformed/abusive TCP patterns like duplicate SEQ, random jumps, etc.
    if (cfg.tcp_abuse.enabled) {
        struct tcp_abuse_config abuse_cfg = {
            .enabled = cfg.tcp_abuse.enabled,
            .report_to_layer4 = cfg.tcp_abuse.report_to_layer4,
            .dup_seq_threshold = cfg.tcp_abuse.dup_seq_threshold,
            .random_seq_threshold = cfg.tcp_abuse.random_seq_threshold,
            .random_ack_threshold = cfg.tcp_abuse.random_ack_threshold,
            .zero_window_threshold = cfg.tcp_abuse.zero_window_threshold,
            .tiny_window_bytes = cfg.tcp_abuse.tiny_window_bytes,
            .small_window_bytes = cfg.tcp_abuse.small_window_bytes,
            .same_window_threshold = cfg.tcp_abuse.same_window_threshold,
            .same_ack_threshold = cfg.tcp_abuse.same_ack_threshold,
            .action_dup_seq = cfg.tcp_abuse.action_dup_seq,
            .action_random_seq = cfg.tcp_abuse.action_random_seq,
            .action_random_ack = cfg.tcp_abuse.action_random_ack,
            .action_zero_window = cfg.tcp_abuse.action_zero_window,
            .action_tiny_window = cfg.tcp_abuse.action_tiny_window,
            .action_small_window = cfg.tcp_abuse.action_small_window,
            .action_same_window = cfg.tcp_abuse.action_same_window,
            .action_same_ack = cfg.tcp_abuse.action_same_ack,
        };
        if (tcp_abuse_init(&abuse_cfg) < 0) {
            RTE_LOG(WARNING, L1, "TCP abuse detection init failed - continuing without abuse detection\n");
        } else {
            RTE_LOG(INFO, L1, "TCP abuse detection enabled (dup_seq=%u, random=%u, zero_win=%u)\n",
                    cfg.tcp_abuse.dup_seq_threshold, cfg.tcp_abuse.random_seq_threshold,
                    cfg.tcp_abuse.zero_window_threshold);
        }
    }

    // Initialize TCP Flag Rate Limiting
    // Per-flag-class rate limiting to separate SYN limits from ACK limits
    if (cfg.tcp_flag_rate.enabled) {
        struct tcp_flag_rate_config tcpf_cfg = {
            .enabled = cfg.tcp_flag_rate.enabled,
            .max_entries = cfg.tcp_flag_rate.max_entries,
            .cleanup_interval_sec = cfg.tcp_flag_rate.cleanup_interval_sec,
            .report_violations = cfg.tcp_flag_rate.report_violations,
            .pps_limits = {
                [TCPF_SYN] = cfg.tcp_flag_rate.syn_pps,
                [TCPF_SYN_ACK] = cfg.tcp_flag_rate.syn_ack_pps,
                [TCPF_ACK] = cfg.tcp_flag_rate.ack_pps,
                [TCPF_RST] = cfg.tcp_flag_rate.rst_pps,
                [TCPF_FIN] = cfg.tcp_flag_rate.fin_pps,
                [TCPF_PSH] = cfg.tcp_flag_rate.psh_pps,
                [TCPF_URG] = cfg.tcp_flag_rate.urg_pps,
                [TCPF_OTHER] = cfg.tcp_flag_rate.other_pps,
            },
            .bucket_capacity = {
                [TCPF_SYN] = cfg.tcp_flag_rate.syn_pps * 2,
                [TCPF_SYN_ACK] = cfg.tcp_flag_rate.syn_ack_pps * 2,
                [TCPF_ACK] = cfg.tcp_flag_rate.ack_pps * 2,
                [TCPF_RST] = cfg.tcp_flag_rate.rst_pps * 2,
                [TCPF_FIN] = cfg.tcp_flag_rate.fin_pps * 2,
                [TCPF_PSH] = cfg.tcp_flag_rate.psh_pps * 2,
                [TCPF_URG] = cfg.tcp_flag_rate.urg_pps * 2,
                [TCPF_OTHER] = cfg.tcp_flag_rate.other_pps * 2,
            },
        };
        if (tcp_flag_rate_init(&tcpf_cfg) < 0) {
            RTE_LOG(WARNING, L1, "TCP flag rate limiting init failed - continuing without per-flag rate limiting\n");
        } else {
            RTE_LOG(INFO, L1, "TCP flag rate limiting enabled (SYN=%u, ACK=%u, RST=%u pps)\n",
                    cfg.tcp_flag_rate.syn_pps, cfg.tcp_flag_rate.ack_pps, cfg.tcp_flag_rate.rst_pps);
        }
    }

    __atomic_store_n(&initialized_atomic, 1, __ATOMIC_RELEASE);
    RTE_LOG(INFO, L1, "Layer 1 initialized successfully\n");
    return 0;
}

void layer1_cleanup(void) {
    if (!__atomic_load_n(&initialized_atomic, __ATOMIC_ACQUIRE)) {
        return;
    }

    RTE_LOG(INFO, L1, "Cleaning up Layer 1\n");

    // Cleanup TCP flag rate limiting
    tcp_flag_rate_cleanup();

    // Cleanup TCP abuse detection
    tcp_abuse_cleanup();

    signatures_cleanup();
    other_proto_cleanup();

    /* IPv4 and IPv6 geo-blocking */
    geo_blocking_cleanup();
    geo_blocking_v6_cleanup();

    window_stats_cleanup();
    realtime_telemetry_cleanup();
    dpdk_telemetry_cleanup();

    /* IPv4 and IPv6 per-IP features */
    per_ip_features_cleanup();
    per_ip_features_v6_cleanup();

    udp_gatekeeper_cleanup();
    hll_global_cleanup();
    telemetry_cleanup();
    connection_limits_cleanup();
    reputation_interface_cleanup();
    policy_interface_cleanup();
    packet_ring_cleanup();
    shared_memory_cleanup();

    /* IPv4 and IPv6 SYN proxy */
    syn_proxy_cleanup();
    syn_proxy_v6_cleanup();

    /* Spoofed mode rate limiting */
    spoofed_rate_cleanup();

    /* IPv4 and IPv6 flow tables */
    flow_table_cleanup();
    flow_table_v6_cleanup();

    /* IPv4 and IPv6 IP lists */
    ip_lists_cleanup();
    ip_lists_v6_cleanup();

    __atomic_store_n(&initialized_atomic, 0, __ATOMIC_RELEASE);
    RTE_LOG(INFO, L1, "Layer 1 cleanup complete\n");
}

bool layer1_is_initialized(void) {
    return __atomic_load_n(&initialized_atomic, __ATOMIC_ACQUIRE) != 0;
}

// ==================== Statistics ====================

void layer1_get_stats(struct layer1_stats *out_stats) {
    if (!out_stats) return;

    // Zero all fields first to prevent garbage in unpopulated fields
    memset(out_stats, 0, sizeof(*out_stats));

    // Expose monitor-only mode in stats for external visibility
    out_stats->monitor_only = __atomic_load_n(&monitor_only_mode_atomic, __ATOMIC_ACQUIRE) != 0;
    out_stats->tap_mode = __atomic_load_n(&tap_mode_atomic, __ATOMIC_ACQUIRE) != 0;

    // Aggregate from per-lcore stats
    struct aggregated_stats agg;
    aggregate_lcore_stats(&agg);

    // Map aggregated stats to layer1_stats structure
    out_stats->total_packets = agg.l1_total_packets;
    out_stats->total_bytes = agg.l1_total_bytes;
    out_stats->packets_accepted = agg.l1_packets_accepted;
    out_stats->packets_dropped = agg.l1_packets_dropped;

    out_stats->inbound_packets = agg.l1_inbound_packets;
    out_stats->inbound_bytes = agg.l1_inbound_bytes;
    out_stats->outbound_packets = agg.l1_outbound_packets;
    out_stats->outbound_bytes = agg.l1_outbound_bytes;

    out_stats->drop_validation = agg.l1_drop_validation;
    out_stats->drop_not_protected = agg.l1_drop_not_protected;
    out_stats->drop_port_filter = agg.l1_drop_port_filter;
    out_stats->drop_proto_blocked = agg.l1_drop_proto_blocked;
    out_stats->drop_proto_rate_limit = agg.l1_drop_proto_rate_limit;
    out_stats->drop_checksum = agg.l1_drop_checksum;
    out_stats->drop_parse_error = agg.l1_drop_parse_error;
    out_stats->drop_l7_validation = agg.l1_drop_l7_validation;
    out_stats->drop_ttl = agg.l1_drop_ttl;
    out_stats->drop_proto_validation = agg.l1_drop_proto_validation;
    out_stats->drop_blacklist = agg.l1_drop_blacklist;
    out_stats->drop_rate_limit = agg.l1_drop_rate_limit;
    out_stats->drop_syn_flood = agg.l1_drop_syn_flood;
    out_stats->drop_reputation = agg.l1_drop_reputation;
    out_stats->drop_policy = agg.l1_drop_policy;
    out_stats->drop_proxy_error = agg.l1_drop_proxy_error;
    out_stats->drop_spoofed_tcp = agg.l1_drop_spoofed_tcp;
    out_stats->drop_signature = agg.l1_drop_signature;

    // Map missing aggregated drop counters
    out_stats->geo_blocked = agg.l1_drop_geo;
    out_stats->drop_protocol = agg.l1_drop_other_proto;
    out_stats->drop_flow_table_full = agg.l1_drop_flow_table_full;  // aggregated drop counter
    out_stats->drop_ipv6 = agg.l1_drop_ipv6;                        // aggregated drop counter

    out_stats->whitelist_hits = agg.l1_whitelist_hits;
    out_stats->syn_proxy_challenges = agg.l1_syn_proxy_challenges;
    out_stats->syn_proxy_established = agg.l1_syn_proxy_established;

    // Get SYN proxy active connections from syn_proxy module
    struct syn_proxy_stats proxy_stats;
    syn_proxy_get_stats(&proxy_stats);
    out_stats->syn_proxy_active = proxy_stats.connections_active;
    out_stats->syn_proxy_validated = proxy_stats.cookies_valid;
    // Populate cookie invalid/expired stats
    out_stats->syn_proxy_cookie_invalid = proxy_stats.cookies_invalid;
    out_stats->syn_proxy_cookie_expired = proxy_stats.cookies_expired;

    // Flow table stats
    uint32_t active_flows, total_flows, aged_flows;
    flow_table_get_stats(&active_flows, &total_flows, &aged_flows);
    out_stats->active_flows = active_flows;
    out_stats->total_flows_created = total_flows;

    // Populate TCP abuse stats from module
    struct tcp_abuse_stats abuse_stats;
    tcp_abuse_get_stats(&abuse_stats);
    out_stats->drop_tcp_dup_seq = abuse_stats.drops[0];
    out_stats->drop_tcp_random_seq = abuse_stats.drops[1];
    out_stats->drop_tcp_random_ack = abuse_stats.drops[2];
    out_stats->drop_tcp_zero_window = abuse_stats.drops[3];
    out_stats->drop_tcp_same_window = abuse_stats.drops[6];
    out_stats->drop_tcp_same_ack = abuse_stats.drops[7];
    for (int i = 0; i < 8; i++)
        out_stats->drop_tcp_abuse += abuse_stats.drops[i];

    // Populate geo stats from module
    struct geo_stats geo_stats;
    geo_get_stats(&geo_stats);
    out_stats->cache_hits = geo_stats.cache_hits;

    // Populate UDP gatekeeper stats
    struct udp_gatekeeper_stats ugk_stats;
    udp_gatekeeper_get_stats(&ugk_stats);
    out_stats->drop_udp_gatekeeper = ugk_stats.drops_pps + ugk_stats.drops_bps +
                                      ugk_stats.drops_reputation + ugk_stats.drops_blacklist;
    out_stats->drop_rate_limit_udp = ugk_stats.drops_pps + ugk_stats.drops_bps;
}

void layer1_reset_stats(void) {
    // Reset per-lcore stats
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        memset(&lcore_statistics[lcore_id], 0, sizeof(struct lcore_stats));
    }
    memset(validation_errors, 0, sizeof(validation_errors));
    syn_proxy_reset_stats();
    RTE_LOG(INFO, L1, "Statistics reset\n");
}

void layer1_factory_reset(void) {
    RTE_LOG(WARNING, L1, "=== FACTORY RESET: clearing all Layer 1 runtime state ===\n");

    // 1. Clear flow tables (IPv4 + IPv6)
    flow_table_clear();
    flow_table_v6_clear();
    RTE_LOG(INFO, L1, "  Flow tables cleared\n");

    // 2. Clear SYN proxy state (IPv4 + IPv6)
    syn_proxy_clear_all();
    syn_proxy_v6_clear_all();
    RTE_LOG(INFO, L1, "  SYN proxy cleared (v4 + v6)\n");

    // 3. Clear connection limits
    connection_limits_clear_all();
    RTE_LOG(INFO, L1, "  Connection limits cleared\n");

    // 4. Clear IP reputation (CRITICAL -- stale attacker flags)
    reputation_clear_all();
    RTE_LOG(INFO, L1, "  IP reputation cleared\n");

    // 5. Clear source IP stats (attacker flags, scores)
    src_ip_stats_clear_all();
    RTE_LOG(INFO, L1, "  Source IP stats cleared\n");

    // 6. Clear dynamic signatures (attack-specific, from Layer 3)
    dynamic_signatures_clear_all();
    RTE_LOG(INFO, L1, "  Dynamic signatures cleared\n");

    // 7. Clear runtime policy table
    policy_clear_all();
    RTE_LOG(INFO, L1, "  Policy table cleared\n");

    // 8. Clear UDP gatekeeper (includes internal CMS)
    udp_gatekeeper_clear();
    RTE_LOG(INFO, L1, "  UDP gatekeeper cleared\n");

    // 9. Clear global anomaly state in shared memory
    anomaly_clear();
    RTE_LOG(INFO, L1, "  Global anomaly state cleared\n");

    // 10. Reset HyperLogLog (cardinality baselines)
    hll_global_reset();
    RTE_LOG(INFO, L1, "  HLL cardinality reset\n");

    // 11. Reset per-IP feature windows (IPv4 + IPv6)
    per_ip_features_reset_all_windows();
    per_ip_features_v6_reset_all_windows();
    RTE_LOG(INFO, L1, "  Per-IP features reset\n");

    // 12. Reset spike detector (per-IP baselines, spike counts)
    spike_detector_clear_all();
    RTE_LOG(INFO, L1, "  Spike detectors cleared\n");

    // 13. Reset window stats (shared memory counters, sample ring)
    window_stats_reset();
    RTE_LOG(INFO, L1, "  Window stats reset\n");

    // 14. Reset telemetry stats
    latency_histogram_reset();
    signatures_reset_stats();
    geo_reset_stats();
    geo_reset_stats_v6();
    other_proto_reset_stats();
    tcp_flag_rate_reset_stats();
    tcp_abuse_reset_stats();
    RTE_LOG(INFO, L1, "  Telemetry/stats counters reset\n");

    // 15. Reset L2 features export (prevents poisoned first-cycle delta)
    l2_features_export_reset();
    RTE_LOG(INFO, L1, "  L2 features export reset\n");

    // 16. Reset per-lcore packet counters
    layer1_reset_stats();

    RTE_LOG(WARNING, L1, "=== FACTORY RESET COMPLETE ===\n");
}

void layer1_print_stats(void) {
    // Aggregate per-lcore stats for display
    struct layer1_stats stats;
    layer1_get_stats(&stats);

    uint32_t active_flows, total_flows, aged_flows;
    flow_table_get_stats(&active_flows, &total_flows, &aged_flows);

    struct syn_proxy_stats proxy_stats;
    syn_proxy_get_stats(&proxy_stats);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║        Layer 1 Statistics (Per-Lcore Aggregated)     ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  Total Packets:    %-20lu             ║\n", stats.total_packets);
    printf("║  Total Bytes:      %-20lu             ║\n", stats.total_bytes);
    printf("║  Accepted:         %-20lu             ║\n", stats.packets_accepted);
    printf("║  Dropped:          %-20lu             ║\n", stats.packets_dropped);
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  INBOUND:          %-10lu pkts, %-10lu bytes ║\n",
           stats.inbound_packets, stats.inbound_bytes);
    printf("║  OUTBOUND:         %-10lu pkts, %-10lu bytes ║\n",
           stats.outbound_packets, stats.outbound_bytes);
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  Drop Reasons:                                       ║\n");
    printf("║    Not Protected:  %-20lu             ║\n", stats.drop_not_protected);
    printf("║    Port Filter:    %-20lu             ║\n", stats.drop_port_filter);
    printf("║    Checksum:       %-20lu             ║\n", stats.drop_checksum);
    printf("║    Parse Error:    %-20lu             ║\n", stats.drop_parse_error);
    printf("║    Proto Valid:    %-20lu             ║\n", stats.drop_proto_validation);
    printf("║    L7 Validation:  %-20lu             ║\n", stats.drop_l7_validation);
    printf("║    TTL/Hop Limit:  %-20lu             ║\n", stats.drop_ttl);
    printf("║    Blacklist:      %-20lu             ║\n", stats.drop_blacklist);
    printf("║    Rate Limit:     %-20lu             ║\n", stats.drop_rate_limit);
    printf("║    SYN Flood:      %-20lu             ║\n", stats.drop_syn_flood);
    printf("║    Reputation:     %-20lu             ║\n", stats.drop_reputation);
    printf("║    Policy:         %-20lu             ║\n", stats.drop_policy);
    printf("║    Proxy Error:    %-20lu             ║\n", stats.drop_proxy_error);
    printf("║    Spoofed TCP:    %-20lu             ║\n", stats.drop_spoofed_tcp);
    printf("║    Signature:      %-20lu             ║\n", stats.drop_signature);
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  SYN Proxy:                                          ║\n");
    printf("║    Active Conns:   %-20u             ║\n", proxy_stats.connections_active);
    printf("║    Cookies Sent:   %-20lu             ║\n", proxy_stats.cookies_sent);
    printf("║    Cookies Valid:  %-20lu             ║\n", proxy_stats.cookies_valid);
    printf("║    Cookies Invalid:%-20lu             ║\n", proxy_stats.cookies_invalid);
    printf("║    Cookies Expired:%-20lu             ║\n", proxy_stats.cookies_expired);
    printf("║    Bypassed:       %-20lu             ║\n", proxy_stats.packets_bypassed);
    printf("║    Established:    %-20lu             ║\n", proxy_stats.connections_established);
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  Flows: %-6u active, %-8u total, %-6u aged    ║\n",
           active_flows, total_flows, aged_flows);
    printf("║  Whitelist Hits:   %-20lu             ║\n", stats.whitelist_hits);
    printf("╚══════════════════════════════════════════════════════╝\n");

    // Print telemetry stats if available
    if (telemetry_is_initialized()) {
        telemetry_print_stats();
    }

    // Print HyperLogLog stats
    hll_print_stats();

    // Print UDP Gatekeeper stats
    udp_gatekeeper_print_stats();
}

// ==================== Configuration APIs ====================

int layer1_whitelist_add(uint32_t ip) {
    if (!__atomic_load_n(&initialized_atomic, __ATOMIC_ACQUIRE)) return -1;
    return ip_whitelist_add(rte_cpu_to_be_32(ip), WL_MODE_BYPASS);
}

int layer1_whitelist_remove(uint32_t ip) {
    if (!__atomic_load_n(&initialized_atomic, __ATOMIC_ACQUIRE)) return -1;
    return ip_whitelist_remove(rte_cpu_to_be_32(ip));
}

int layer1_blacklist_add(uint32_t ip) {
    if (!__atomic_load_n(&initialized_atomic, __ATOMIC_ACQUIRE)) return -1;
    return ip_blacklist_add(rte_cpu_to_be_32(ip));
}

int layer1_blacklist_remove(uint32_t ip) {
    if (!__atomic_load_n(&initialized_atomic, __ATOMIC_ACQUIRE)) return -1;
    return ip_blacklist_remove(rte_cpu_to_be_32(ip));
}

int layer1_set_rate_limit(uint32_t ip, uint32_t pps, uint64_t bps) {
    // Return -1 (not 0) to indicate this is not yet implemented.
    // Per-IP rate limiting requires a dedicated per-src-IP table, not per-flow.
    (void)ip; (void)pps; (void)bps;
    RTE_LOG(WARNING, L1, "Rate limit API not implemented: IP=0x%08x PPS=%u BPS=%lu\n",
            ip, pps, (unsigned long)bps);
    return -1;
}

void layer1_set_syn_proxy_enabled(bool enable) {
    // Actually call syn_proxy_set_enabled()
    syn_proxy_set_enabled(enable);
    RTE_LOG(INFO, L1, "SYN proxy %s\n", enable ? "enabled" : "disabled");
}

bool layer1_is_syn_proxy_enabled(void) {
    // Return actual state instead of hardcoded true
    return syn_proxy_is_enabled();
}

// ==================== Telemetry Configuration APIs ====================

void layer1_set_telemetry_sample_rate(uint32_t rate) {
    telemetry_set_flow_sample_rate(rate);
    RTE_LOG(INFO, L1, "Telemetry flow sample rate set to 1:%u\n", rate);
}

uint32_t layer1_get_telemetry_sample_rate(void) {
    return telemetry_get_flow_sample_rate();
}

void layer1_set_telemetry_events_enabled(bool enable) {
    telemetry_set_events_enabled(enable);
    RTE_LOG(INFO, L1, "Telemetry events %s\n", enable ? "enabled" : "disabled");
}

bool layer1_get_telemetry_events_enabled(void) {
    return telemetry_get_events_enabled();
}