#ifndef LAYER1_H
#define LAYER1_H

#include <rte_mbuf.h>
#include <stdint.h>
#include <stdbool.h>
#include "../common/types.h"

// ==================== Layer 1 Return Codes ====================

#define L1_ACTION_ACCEPT          0
#define L1_ACTION_DROP            1
#define L1_ACTION_REPLY           2
#define L1_ACTION_ACCEPT_MODIFIED 3
#define L1_ACTION_REPLY_INPLACE   4  // Zero-copy: original mbuf is now the reply

// For backward compatibility
#define L1_ACCEPT  L1_ACTION_ACCEPT
#define L1_DROP    L1_ACTION_DROP

/**
 * Result structure for extended packet processing API
 */
struct layer1_result {
    int action;  // L1_ACTION_*

    // For L1_ACTION_REPLY or when generating additional packets
    struct rte_mbuf *reply_pkt;      // Reply packet to send back (same port)
    struct rte_mbuf *forward_pkt;    // Additional packet to forward (opposite port)

    // Output port/queue hints
    uint16_t reply_port;             // Port for reply packet
    uint16_t reply_queue;            // Queue for reply packet
    uint16_t forward_port;           // Port for forward packet
    uint16_t forward_queue;          // Queue for forward packet

    // Debug info
    uint8_t  drop_reason;            // Why packet was dropped
    uint8_t  proxy_state;            // SYN proxy connection state
    uint8_t  flags;                  // L1_RESULT_FLAG_* flags
    uint8_t  _pad;                   // Padding for alignment

    // Per-destination profile (set during Stage 4d)
    const void *dst_profile;       // struct protection_profile * (typed as void* to avoid forward decl)
    bool        whitelist_track;   // True if src IP is in track-mode whitelist
};

// Drop reason codes -- organized by category, 10 slots per category
// General (0-9)
#define DROP_REASON_NONE              0
#define DROP_REASON_PARSE_ERROR       1
#define DROP_REASON_VALIDATION        2
#define DROP_REASON_OTHER_PROTO       3
#define DROP_REASON_PORT_NOT_ALLOWED  4
#define DROP_REASON_PROTO_BLOCKED     5
#define DROP_REASON_PROTO_RATE_LIMIT  6

// IP List Based (10-19)
#define DROP_REASON_BLACKLIST         10
#define DROP_REASON_GEO_BLOCKED       11
#define DROP_REASON_REPUTATION        12

// Rate Limiting (20-29)
#define DROP_REASON_RATE_LIMIT        20
#define DROP_REASON_RATE_LIMIT_PPS    21
#define DROP_REASON_RATE_LIMIT_BPS    22
#define DROP_REASON_RATE_LIMIT_SYN    23
#define DROP_REASON_RATE_LIMIT_ACK    24
#define DROP_REASON_RATE_LIMIT_RST    25
#define DROP_REASON_RATE_LIMIT_FIN    26
#define DROP_REASON_RATE_LIMIT_UDP    27
#define DROP_REASON_RATE_LIMIT_ICMP   28

// Connection/Flow Limits (30-39)
#define DROP_REASON_CONN_LIMIT        30
#define DROP_REASON_CONN_LIMIT_SRC    31
#define DROP_REASON_CONN_LIMIT_DST    32
#define DROP_REASON_CONN_LIMIT_GLOBAL 33
#define DROP_REASON_FLOW_TABLE_FULL   34
#define DROP_REASON_UDP_GATEKEEPER    35

// SYN Proxy (40-49)
#define DROP_REASON_SYN_FLOOD         40
#define DROP_REASON_COOKIE_INVALID    41
#define DROP_REASON_COOKIE_EXPIRED    42
#define DROP_REASON_PROXY_ERROR       43
#define DROP_REASON_PROXY_NO_CONN     44
#define DROP_REASON_SPOOFED_TCP       45

// TCP Abuse Detection (50-59)
#define DROP_REASON_TCP_ABUSE         50
#define DROP_REASON_TCP_DUP_SEQ       51
#define DROP_REASON_TCP_RANDOM_SEQ    52
#define DROP_REASON_TCP_RANDOM_ACK    53
#define DROP_REASON_TCP_ZERO_WINDOW   54
#define DROP_REASON_TCP_TINY_WINDOW   55
#define DROP_REASON_TCP_SAME_WINDOW   56
#define DROP_REASON_TCP_SAME_ACK      57
#define DROP_REASON_TCP_INVALID_FLAGS 58

// Signature/Policy (60-69)
#define DROP_REASON_SIGNATURE         60
#define DROP_REASON_SIGNATURE_AMP     61
#define DROP_REASON_SIGNATURE_SCAN    62
#define DROP_REASON_SIGNATURE_TOOL    63
#define DROP_REASON_POLICY            64
#define DROP_REASON_POLICY_CHALLENGE  65

// Protocol Validation (70-79)
#define DROP_REASON_IP_MALFORMED      70
#define DROP_REASON_IP_TTL_ZERO       71
#define DROP_REASON_IP_CHECKSUM       72
#define DROP_REASON_TCP_MALFORMED     73
#define DROP_REASON_TCP_CHECKSUM      74
#define DROP_REASON_UDP_MALFORMED     75
#define DROP_REASON_UDP_CHECKSUM      76
#define DROP_REASON_ICMP_MALFORMED    77
#define DROP_REASON_IPV6_UNSUPPORTED  78

// Table/Resource Limits (80-89)
#define DROP_REASON_TABLE_FULL        80
#define DROP_REASON_MEMPOOL_EMPTY     81
#define DROP_REASON_RING_FULL         82

#define DROP_REASON_MAX               90

// Drop reason categories
#define DROP_CAT_GENERAL    0
#define DROP_CAT_IP_LIST    1
#define DROP_CAT_RATE_LIMIT 2
#define DROP_CAT_CONN_LIMIT 3
#define DROP_CAT_SYN_PROXY  4
#define DROP_CAT_TCP_ABUSE  5
#define DROP_CAT_SIGNATURE  6
#define DROP_CAT_VALIDATION 7
#define DROP_CAT_RESOURCE   8

const char *drop_reason_to_string(uint8_t reason);
uint8_t drop_reason_to_category(uint8_t reason);

// Result flags
#define L1_RESULT_FLAG_NO_FLOW_TRACKING  0x01  // Packet accepted without flow tracking

// ==================== Layer 1 Statistics ====================

struct layer1_stats {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t packets_accepted;
    uint64_t packets_dropped;

    uint64_t inbound_packets;
    uint64_t inbound_bytes;
    uint64_t outbound_packets;
    uint64_t outbound_bytes;

    uint64_t drop_validation;
    uint64_t drop_blacklist;
    uint64_t drop_rate_limit;
    uint64_t drop_rate_limit_udp;
    uint64_t drop_syn_flood;
    uint64_t drop_protocol;
    uint64_t drop_reputation;
    uint64_t drop_policy;
    uint64_t drop_proxy_error;
    uint64_t drop_not_protected;

    // Granular drop reason counters
    uint64_t drop_port_filter;        // Port filter (blocked port)
    uint64_t drop_checksum;           // Bad checksum
    uint64_t drop_parse_error;        // Packet parse failure
    uint64_t drop_proto_validation;   // Protocol validation failure
    uint64_t drop_proto_blocked;      // Protocol blocked by policy
    uint64_t drop_proto_rate_limit;   // Protocol rate limited
    uint64_t drop_l7_validation;      // L7 validation failure
    uint64_t drop_ttl;                // TTL/hop-limit exceeded
    uint64_t drop_spoofed_tcp;        // Spoofed TCP source
    uint64_t drop_signature;          // Dynamic signature match
    uint64_t drop_flow_table_full;    // Flow table at capacity
    uint64_t drop_ipv6;               // IPv6 dropped
    uint64_t drop_udp_gatekeeper;     // UDP gatekeeper drop

    // TCP abuse detection counters
    uint64_t drop_tcp_abuse;
    uint64_t drop_tcp_dup_seq;
    uint64_t drop_tcp_random_seq;
    uint64_t drop_tcp_random_ack;
    uint64_t drop_tcp_zero_window;
    uint64_t drop_tcp_same_window;
    uint64_t drop_tcp_same_ack;

    // Geo-blocking
    uint64_t geo_blocked;

    uint64_t active_flows;
    uint64_t total_flows_created;

    uint64_t whitelist_hits;
    uint64_t cache_hits;

    uint64_t syn_proxy_challenges;
    uint64_t syn_proxy_validated;
    uint64_t syn_proxy_established;
    uint64_t syn_proxy_active;
    uint64_t syn_proxy_cookie_invalid;
    uint64_t syn_proxy_cookie_expired;

    // Mode flags
    bool monitor_only;
    bool tap_mode;

    uint64_t avg_latency_cycles;
};

// ==================== Initialization ====================

int layer1_init(uint32_t max_flows, const char *config_file);
void layer1_cleanup(void);
bool layer1_is_initialized(void);

// ==================== Packet Processing (Fast Path) ====================

/**
 * Process a single packet through Layer 1 pipeline (Extended API)
 * This is the PREFERRED API for multi-queue setups with SYN proxy
 *
 * @param m Packet mbuf (may be modified in place)
 * @param port_id Ingress port ID
 * @param queue_id Ingress queue ID (for proper TX queue selection)
 * @param mempool Mempool for allocating reply packets
 * @param result Output: detailed processing result
 * @return 0 on success, -1 on error
 */
int layer1_process_packet_ex(struct rte_mbuf *m, 
                             uint16_t port_id,
                             uint16_t queue_id,
                             struct rte_mempool *mempool,
                             struct layer1_result *result);

/**
 * Process a single packet (Simple API - DEPRECATED for SYN proxy)
 * Use layer1_process_packet_ex() instead for proper multi-queue support
 *
 * @param m Packet mbuf
 * @param port_id Ingress port ID
 * @return L1_ACCEPT or L1_DROP
 */
int layer1_process_packet(struct rte_mbuf *m, uint16_t port_id);

// ==================== Maintenance ====================

uint32_t layer1_maintenance(void);
uint32_t layer1_age_flows(void);

// ==================== Statistics (Control Path) ====================

void layer1_get_stats(struct layer1_stats *stats);
void layer1_reset_stats(void);
void layer1_print_stats(void);

// ==================== Configuration (Control Path) ====================

int layer1_whitelist_add(uint32_t ip);
int layer1_whitelist_remove(uint32_t ip);
int layer1_blacklist_add(uint32_t ip);
int layer1_blacklist_remove(uint32_t ip);
int layer1_set_rate_limit(uint32_t ip, uint32_t pps, uint64_t bps);
void layer1_set_syn_proxy_enabled(bool enable);
bool layer1_is_syn_proxy_enabled(void);

/**
 * Refresh cached config values after runtime config reload
 * Called by control_socket after CMD_RELOAD_CONFIG
 */
void layer1_refresh_cached_config(void);

// ==================== Telemetry Configuration APIs ====================

/**
 * Set telemetry flow sampling rate
 * @param rate  1 = all flows, 100 = 1:100, 0 = disable flow recording
 */
void layer1_set_telemetry_sample_rate(uint32_t rate);

/**
 * Get current telemetry flow sampling rate
 */
uint32_t layer1_get_telemetry_sample_rate(void);

/**
 * Enable/disable telemetry event recording
 */
void layer1_set_telemetry_events_enabled(bool enable);

/**
 * Check if telemetry events are enabled
 */
bool layer1_get_telemetry_events_enabled(void);


#endif // LAYER1_H