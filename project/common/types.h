#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <rte_ether.h>
#include <rte_ip.h>

// ==================== Traffic Direction ====================

#define DIRECTION_INBOUND   0
#define DIRECTION_OUTBOUND  1

#define PORT_FACING_CLIENTS  0
#define PORT_FACING_SERVERS  1

// ==================== Flow Direction (within connection) ====================
// Indicates packet direction relative to canonical flow key
#define FLOW_DIR_LO_TO_HI  0   // Packet from ip_lo toward ip_hi
#define FLOW_DIR_HI_TO_LO  1   // Packet from ip_hi toward ip_lo

// ==================== IP Address Types ====================

#define IP_VERSION_4  4
#define IP_VERSION_6  6

/**
 * Union type for IPv4/IPv6 addresses
 * Provides a common interface for dual-stack operations
 */
union ip_addr {
    uint32_t v4;          // IPv4 address (network byte order)
    uint8_t  v6[16];      // IPv6 address (network byte order)
    uint32_t v6_u32[4];   // IPv6 as 4 x 32-bit words (for comparison)
    uint64_t v6_u64[2];   // IPv6 as 2 x 64-bit words (for fast copy)
};

/**
 * Compare two IPv6 addresses
 * Returns: negative if a < b, 0 if a == b, positive if a > b
 */
static inline int ipv6_compare(const uint8_t a[16], const uint8_t b[16]) {
    return memcmp(a, b, 16);
}

/**
 * Check if IPv6 address is zero (unspecified)
 */
static inline bool ipv6_is_zero(const uint8_t addr[16]) {
    const uint64_t *p = (const uint64_t *)addr;
    return (p[0] == 0 && p[1] == 0);
}

/**
 * Copy IPv6 address
 */
static inline void ipv6_copy(uint8_t dst[16], const uint8_t src[16]) {
    const uint64_t *s = (const uint64_t *)src;
    uint64_t *d = (uint64_t *)dst;
    d[0] = s[0];
    d[1] = s[1];
}

// ==================== Canonical 3-Tuple Flow Key (IPv4) ====================
/**
 * CANONICAL flow key for IPv4: IPs are always ordered with lower IP first.
 * This ensures Client→Server and Server→Client map to the SAME key.
 *
 * Example:
 *   Client 192.168.1.100 (0xC0A80164) → Server 10.0.0.1 (0x0A000001)
 *   Since 0x0A000001 < 0xC0A80164:
 *     ip_lo = 10.0.0.1, ip_hi = 192.168.1.100
 *
 *   Server 10.0.0.1 → Client 192.168.1.100
 *     ip_lo = 10.0.0.1, ip_hi = 192.168.1.100  (SAME KEY!)
 */
struct flow_key {
    uint32_t ip_lo;       // Lower IP address (network byte order comparison)
    uint32_t ip_hi;       // Higher IP address (network byte order comparison)
    uint8_t  protocol;    // IP protocol (6=TCP, 17=UDP, 1=ICMP)
    uint8_t  _pad[3];     // Padding for alignment
} __attribute__((packed));  // 12 bytes total

// ==================== Canonical 3-Tuple Flow Key (IPv6) ====================
/**
 * CANONICAL flow key for IPv6: Same principle as IPv4.
 * IPs are compared byte-by-byte to determine ordering.
 *
 * This structure is 36 bytes (2x16 + 1 + 3 padding)
 */
struct flow_key_v6 {
    uint8_t  ip_lo[16];   // Lower IPv6 address
    uint8_t  ip_hi[16];   // Higher IPv6 address
    uint8_t  protocol;    // IP protocol (6=TCP, 17=UDP, 58=ICMPv6)
    uint8_t  _pad[3];     // Padding for alignment
} __attribute__((packed));  // 36 bytes total

/**
 * Unified flow key that can hold either IPv4 or IPv6
 * Uses a version field to distinguish between the two
 *
 * Layout (40 bytes, cache-aligned):
 *   - 1 byte: IP version (4 or 6)
 *   - 1 byte: protocol
 *   - 2 bytes: padding
 *   - 16 bytes: ip_lo (only first 4 used for IPv4)
 *   - 16 bytes: ip_hi (only first 4 used for IPv4)
 *   - 4 bytes: padding
 */
struct flow_key_unified {
    uint8_t  ip_version;  // IP_VERSION_4 or IP_VERSION_6
    uint8_t  protocol;    // IP protocol
    uint16_t _pad1;
    union ip_addr ip_lo;  // Lower IP address
    union ip_addr ip_hi;  // Higher IP address
    uint32_t _pad2;       // Align to 40 bytes
} __attribute__((packed));  // 40 bytes total

/**
 * Extract canonical unified flow key from source and destination
 * Works for both IPv4 and IPv6
 */
static inline void extract_flow_key_unified(
    uint8_t ip_version,
    const union ip_addr *src_ip,
    const union ip_addr *dst_ip,
    uint8_t protocol,
    struct flow_key_unified *key,
    uint8_t *flow_direction_out)
{
    key->ip_version = ip_version;
    key->protocol = protocol;
    key->_pad1 = 0;
    key->_pad2 = 0;

    int cmp;
    if (ip_version == IP_VERSION_4) {
        cmp = (int)(src_ip->v4 - dst_ip->v4);
    } else {
        cmp = memcmp(src_ip->v6, dst_ip->v6, 16);
    }

    if (cmp <= 0) {
        // src <= dst, so src is lo
        key->ip_lo = *src_ip;
        key->ip_hi = *dst_ip;
        if (flow_direction_out) *flow_direction_out = FLOW_DIR_LO_TO_HI;
    } else {
        // src > dst, so dst is lo
        key->ip_lo = *dst_ip;
        key->ip_hi = *src_ip;
        if (flow_direction_out) *flow_direction_out = FLOW_DIR_HI_TO_LO;
    }
}

// ==================== Packet Features ====================

/**
 * IPv4 packet features (128 bytes, cache-aligned)
 * Original structure for backwards compatibility
 */
struct packet_features {
    // Original 3-tuple as seen in packet (12 bytes)
    uint32_t src_ip;           // Source IP (network byte order)
    uint32_t dst_ip;           // Destination IP (network byte order)
    uint8_t  protocol;         // Protocol (6=TCP, 17=UDP, 1=ICMP)
    uint8_t  direction;        // DIRECTION_INBOUND or DIRECTION_OUTBOUND (port-based)
    uint8_t  flow_direction;   // FLOW_DIR_LO_TO_HI or FLOW_DIR_HI_TO_LO
    uint8_t  _pad1;

    // Layer 3/4 Headers (24 bytes)
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t packet_size;
    uint16_t payload_len;
    uint8_t  ttl;
    uint8_t  ip_tos;
    uint16_t ip_id;
    uint16_t ip_flags;
    uint16_t ip_len;

    // TCP-specific (20 bytes)
    uint8_t  tcp_flags;
    uint8_t  tcp_header_len;
    uint16_t tcp_window;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint16_t tcp_mss;
    uint8_t  tcp_wscale;
    uint8_t  tcp_sack_perm;

    // UDP-specific (4 bytes)
    uint16_t udp_len;
    uint16_t _pad3;

    // ICMP-specific (2 bytes)
    uint8_t  icmp_type;   // ICMP type (e.g., 8 = echo request)
    uint8_t  icmp_code;   // ICMP code

    // Timing & Hashing (16 bytes)
    uint64_t timestamp_tsc;
    uint32_t flow_hash;
    uint32_t inter_arrival_us;

    // Derived Features for ML (24 bytes)
    uint8_t  payload_entropy;
    uint8_t  header_entropy;
    uint8_t  is_retransmit;
    uint8_t  is_out_of_order;
    uint16_t fragment_offset;
    uint16_t _pad4;
    uint16_t payload_sample[8];

    // Padding to 128 bytes
    uint8_t  _pad5[2];
} __rte_cache_aligned;

/**
 * Dual-stack packet features (192 bytes, cache-aligned)
 * Supports both IPv4 and IPv6 packets
 */
struct packet_features_v6 {
    // IP Version indicator (4 bytes)
    uint8_t  ip_version;       // IP_VERSION_4 or IP_VERSION_6
    uint8_t  protocol;         // Protocol (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6)
    uint8_t  direction;        // DIRECTION_INBOUND or DIRECTION_OUTBOUND (port-based)
    uint8_t  flow_direction;   // FLOW_DIR_LO_TO_HI or FLOW_DIR_HI_TO_LO

    // IPv6 addresses (32 bytes) - for IPv4, first 4 bytes used
    union ip_addr src_ip;
    union ip_addr dst_ip;

    // Layer 3/4 Headers (16 bytes)
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t packet_size;
    uint16_t payload_len;
    uint8_t  ttl;              // Also used for IPv6 hop limit
    uint8_t  ip_tos;           // Also used for IPv6 traffic class
    uint16_t ip_len;

    // IPv6-specific fields (8 bytes)
    uint32_t ipv6_flow_label;  // IPv6 flow label (20 bits, zero for IPv4)
    uint16_t ip_id;            // Identification field (IPv4) / fragment ID (IPv6)
    uint16_t ip_flags;         // Fragment flags

    // TCP-specific (20 bytes)
    uint8_t  tcp_flags;
    uint8_t  tcp_header_len;
    uint16_t tcp_window;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint16_t tcp_mss;
    uint8_t  tcp_wscale;
    uint8_t  tcp_sack_perm;

    // UDP-specific (4 bytes)
    uint16_t udp_len;
    uint16_t _pad2;

    // Timing & Hashing (16 bytes)
    uint64_t timestamp_tsc;
    uint32_t flow_hash;
    uint32_t inter_arrival_us;

    // Derived Features for ML (24 bytes)
    uint8_t  payload_entropy;
    uint8_t  header_entropy;
    uint8_t  is_retransmit;
    uint8_t  is_out_of_order;
    uint16_t fragment_offset;
    uint16_t _pad3;
    uint16_t payload_sample[8];

    // IPv6 extension headers info (8 bytes)
    uint8_t  ext_hdr_count;    // Number of extension headers
    uint8_t  has_routing_hdr;  // Has Type 0 Routing Header (deprecated, suspicious)
    uint8_t  has_fragment_hdr; // Has Fragment Header
    uint8_t  has_hop_by_hop;   // Has Hop-by-Hop Options Header
    uint32_t ext_hdr_len;      // Total length of extension headers

    // Padding to 192 bytes (3 cache lines)
    uint8_t  _pad4[20];
} __rte_cache_aligned;

/**
 * Helper to check if packet_features_v6 is IPv4
 */
static inline bool is_ipv4_packet(const struct packet_features_v6 *f) {
    return f->ip_version == IP_VERSION_4;
}

/**
 * Helper to check if packet_features_v6 is IPv6
 */
static inline bool is_ipv6_packet(const struct packet_features_v6 *f) {
    return f->ip_version == IP_VERSION_6;
}

/**
 * Get source IP as 32-bit value (IPv4 only, for backward compat)
 * Returns 0 for IPv6 packets
 */
static inline uint32_t get_src_ip_v4(const struct packet_features_v6 *f) {
    return (f->ip_version == IP_VERSION_4) ? f->src_ip.v4 : 0;
}

/**
 * Get destination IP as 32-bit value (IPv4 only, for backward compat)
 * Returns 0 for IPv6 packets
 */
static inline uint32_t get_dst_ip_v4(const struct packet_features_v6 *f) {
    return (f->ip_version == IP_VERSION_4) ? f->dst_ip.v4 : 0;
}

// ==================== Protocol Constants ====================

#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20
#define TCP_FLAG_ECE    0x40
#define TCP_FLAG_CWR    0x80

#define TCP_FLAGS_SYN_ONLY      (TCP_FLAG_SYN)
#define TCP_FLAGS_SYN_ACK       (TCP_FLAG_SYN | TCP_FLAG_ACK)
#define TCP_FLAGS_ACK_ONLY      (TCP_FLAG_ACK)
#define TCP_FLAGS_FIN_ACK       (TCP_FLAG_FIN | TCP_FLAG_ACK)
#define TCP_FLAGS_RST_ACK       (TCP_FLAG_RST | TCP_FLAG_ACK)

// ==================== Simple Action Results ====================

#define VALID           0
#define INVALID         -1

#define WHITELIST_HIT   1
#define WHITELIST_MISS  0

#define BLACKLIST_HIT   1
#define BLACKLIST_MISS  0

#define CONN_OK         0
#define CONN_INVALID    -1

#define PROTOCOL_OK     0
#define PROTOCOL_VIOLATION  -1

#define REPUTATION_OK   0
#define REPUTATION_LOW  1

// ==================== SYN Proxy States ====================

enum syn_proxy_state {
    SYN_PROXY_NONE = 0,
    SYN_PROXY_SYN_SENT,
    SYN_PROXY_CONNECTING,
    SYN_PROXY_ESTABLISHED,
    SYN_PROXY_BYPASSED,      // Connection bypassed proxy - forward without translation
    SYN_PROXY_CLIENT_FIN,
    SYN_PROXY_SERVER_FIN,
    SYN_PROXY_CLOSING,
    SYN_PROXY_CLOSED,
};

// ==================== SYN Proxy Actions ====================

enum syn_proxy_action {
    SYN_PROXY_FORWARD,
    SYN_PROXY_DROP,
    SYN_PROXY_REPLY,
    SYN_PROXY_REPLY_INPLACE,  // Original mbuf was transformed to reply - send it, don't free
    SYN_PROXY_BYPASS,
    SYN_PROXY_ERROR,
    SYN_PROXY_CHALLENGE,      // Challenge packet with SYN cookie
    SYN_PROXY_CONNECT,        // Initiate proxied connection to server
};

// ==================== Reputation Levels ====================

enum reputation_level {
    REP_UNKNOWN = 0,
    REP_ATTACKER,
    REP_SUSPICIOUS,
    REP_NEUTRAL,
    REP_GOOD,
    REP_EXCELLENT,
};

// ==================== Policy Actions ====================

enum policy_action {
    POLICY_ALLOW = 0,
    POLICY_CHALLENGE,
    POLICY_RATE_LIMIT,
    POLICY_DROP,
};

// ==================== Rate Limit Actions ====================

enum rate_limit_action {
    RL_ACCEPT = 0,
    RL_DROP,
    RL_DROP_PPS,
    RL_DROP_BPS,
    RL_CHALLENGE,
};

#endif // COMMON_TYPES_H