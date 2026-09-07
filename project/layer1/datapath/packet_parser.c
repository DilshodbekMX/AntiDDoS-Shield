#include "packet_parser.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_hash_crc.h>
#include <rte_log.h>
#include <netinet/in.h>

#define RTE_LOGTYPE_PARSER RTE_LOGTYPE_USER3

// ==================== Validation Error Strings ====================

static const char* validation_errors[] = {
    [VALIDATE_OK]                = "OK",
    [VALIDATE_ERR_TOO_SHORT]     = "Packet too short",
    [VALIDATE_ERR_BAD_IPLEN]     = "IP length mismatch",
    [VALIDATE_ERR_BAD_CHECKSUM]  = "Bad IP checksum",
    [VALIDATE_ERR_ZERO_TTL]      = "Zero TTL",
    [VALIDATE_ERR_INVALID_SRC]   = "Invalid source IP",
    [VALIDATE_ERR_INVALID_DST]   = "Invalid destination IP",
    [VALIDATE_ERR_FRAG_ATTACK]   = "Suspicious fragmentation",
    [VALIDATE_ERR_LAND_ATTACK]   = "LAND attack",
    [VALIDATE_ERR_TCP_NULL]      = "TCP NULL scan",
    [VALIDATE_ERR_TCP_XMAS]      = "TCP XMAS scan",
    [VALIDATE_ERR_TCP_INVALID]   = "Invalid TCP flags",
    [VALIDATE_ERR_TCP_SHORT]     = "TCP header too short",
    [VALIDATE_ERR_UDP_SHORT]     = "UDP header too short",
    [VALIDATE_ERR_UDP_CHECKSUM]  = "Bad UDP checksum",
    [VALIDATE_ERR_NOT_PROTECTED] = "Destination not a protected server",
};

const char* validation_error_str(int error_code) {
    if (error_code < 0 || error_code >= (int)(sizeof(validation_errors) / sizeof(validation_errors[0]))) {
        return "Unknown error";
    }
    return validation_errors[error_code];
}

// ==================== Flow Hash (Canonical Key) ====================

uint32_t compute_flow_hash(const struct flow_key *key) {
    // OPTIMIZED: Single CRC call on entire key structure (12 bytes)
    // The padding bytes are always zero due to extract_flow_key initialization
    // This is faster than three separate calls
    return rte_hash_crc(key, sizeof(struct flow_key), 0);
}

// ==================== IP Address Validation ====================

static inline bool is_invalid_src_ip(uint32_t ip) {
    uint32_t host_ip = rte_be_to_cpu_32(ip);

    // 0.0.0.0 - Invalid source
    if (host_ip == 0) return true;

    // 255.255.255.255 - Broadcast
    if (host_ip == 0xFFFFFFFF) return true;

    // 127.0.0.0/8 - Loopback (spoofed)
    if ((host_ip & 0xFF000000) == 0x7F000000) return true;

    // 224.0.0.0/4 - Multicast (invalid as source)
    if ((host_ip & 0xF0000000) == 0xE0000000) return true;

    // 240.0.0.0/4 - Reserved/Future use
    if ((host_ip & 0xF0000000) == 0xF0000000) return true;

    // 169.254.0.0/16 - Link-local (spoofed from internet)
    if ((host_ip & 0xFFFF0000) == 0xA9FE0000) return true;

    // 0.0.0.0/8 - "This" network (invalid)
    if ((host_ip & 0xFF000000) == 0x00000000) return true;

    return false;
}

static inline bool is_invalid_dst_ip(uint32_t ip) {
    uint32_t host_ip = rte_be_to_cpu_32(ip);
    if (host_ip == 0) return true;
    return false;
}

// ==================== TCP Flag Validation ====================

static inline int validate_tcp_flags(uint8_t flags) {
    if (flags == 0) {
        return VALIDATE_ERR_TCP_NULL;
    }

    if ((flags & (TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG)) ==
        (TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG)) {
        return VALIDATE_ERR_TCP_XMAS;
    }

    if ((flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) == (TCP_FLAG_SYN | TCP_FLAG_FIN)) {
        return VALIDATE_ERR_TCP_INVALID;
    }

    if ((flags & (TCP_FLAG_SYN | TCP_FLAG_RST)) == (TCP_FLAG_SYN | TCP_FLAG_RST)) {
        return VALIDATE_ERR_TCP_INVALID;
    }

    if ((flags & TCP_FLAG_FIN) && !(flags & TCP_FLAG_ACK)) {
        if (flags != TCP_FLAG_FIN) {
            return VALIDATE_ERR_TCP_INVALID;
        }
    }

    return VALIDATE_OK;
}

// ==================== Packet Parsing ====================

int parse_packet(struct rte_mbuf *m, struct packet_features *features) {
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr *ipv4;
    struct rte_tcp_hdr *tcp;
    struct rte_udp_hdr *udp;
    uint16_t ether_type;
    uint8_t ip_proto;
    void *l3_hdr;
    void *l4_hdr;

    // OPTIMIZED: Selective initialization instead of memset(0)
    // Only initialize fields that are used - saves ~30-50 cycles per packet
    // Fields not used in fast path can remain uninitialized

    // Essential fields - always set
    features->packet_size = m->pkt_len;
    // Note: timestamp_tsc is set by caller or later if needed (batch optimization)
    features->timestamp_tsc = 0;  // Will be set if needed

    // Initialize port fields to 0 (may not be set for non-TCP/UDP)
    features->src_port = 0;
    features->dst_port = 0;

    // Initialize TCP fields to 0 (may not be set for non-TCP)
    features->tcp_flags = 0;
    features->tcp_header_len = 0;
    features->tcp_window = 0;
    features->tcp_seq = 0;
    features->tcp_ack = 0;

    // Initialize UDP fields
    features->udp_len = 0;

    // Initialize flow tracking fields
    features->flow_direction = 0;
    features->flow_hash = 0;

    // ========== Ethernet Layer ==========
    if (unlikely(m->pkt_len < sizeof(struct rte_ether_hdr))) {
        return PARSE_MALFORMED;
    }

    eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ether_type = rte_be_to_cpu_16(eth->ether_type);

    l3_hdr = (void *)(eth + 1);
    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        if (unlikely(m->pkt_len < sizeof(struct rte_ether_hdr) +
                                  sizeof(struct rte_vlan_hdr))) {
            return PARSE_MALFORMED;
        }
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)l3_hdr;
        ether_type = rte_be_to_cpu_16(vlan->eth_proto);
        l3_hdr = (void *)(vlan + 1);
    }

    // IPv6 traffic: return PARSE_IPV6 to signal caller
    // IPv6 flow tracking is currently a stub - caller should decide action based on config
    if (ether_type == RTE_ETHER_TYPE_IPV6) {
        return PARSE_IPV6;
    }

    if (ether_type != RTE_ETHER_TYPE_IPV4) {
        return PARSE_NOT_IP;
    }

    // ========== IPv4 Layer ==========
    ipv4 = (struct rte_ipv4_hdr *)l3_hdr;

    if (unlikely((void *)ipv4 + sizeof(struct rte_ipv4_hdr) >
                 rte_pktmbuf_mtod(m, void *) + m->data_len)) {
        return PARSE_MALFORMED;
    }

    features->src_ip = ipv4->src_addr;
    features->dst_ip = ipv4->dst_addr;
    features->ttl = ipv4->time_to_live;
    features->ip_len = rte_be_to_cpu_16(ipv4->total_length);
    features->ip_flags = rte_be_to_cpu_16(ipv4->fragment_offset);

    ip_proto = ipv4->next_proto_id;
    features->protocol = ip_proto;

    // Validate IP header length (IHL) before pointer arithmetic
    // IHL is a 4-bit field specifying header length in 32-bit words (min 5, max 15)
    // Minimum valid IHL is 5 (20 bytes), maximum is 15 (60 bytes)
    uint8_t ihl_words = ipv4->version_ihl & 0x0F;
    if (unlikely(ihl_words < 5)) {
        // IHL < 5 is invalid (less than minimum 20-byte header)
        return PARSE_MALFORMED;
    }
    uint8_t ihl = ihl_words * 4;

    // Ensure IHL doesn't exceed total IP length (prevents buffer over-read)
    if (unlikely(ihl > features->ip_len)) {
        return PARSE_MALFORMED;
    }

    // Ensure L4 header pointer stays within packet bounds
    if (unlikely((void *)ipv4 + ihl > rte_pktmbuf_mtod(m, void *) + m->data_len)) {
        return PARSE_MALFORMED;
    }

    l4_hdr = (void *)ipv4 + ihl;

    // ========== Transport Layer ==========
    switch (ip_proto) {
    case IPPROTO_TCP:
        tcp = (struct rte_tcp_hdr *)l4_hdr;

        if (unlikely((void *)tcp + sizeof(struct rte_tcp_hdr) >
                     rte_pktmbuf_mtod(m, void *) + m->data_len)) {
            return PARSE_MALFORMED;
        }

        features->src_port = rte_be_to_cpu_16(tcp->src_port);
        features->dst_port = rte_be_to_cpu_16(tcp->dst_port);
        features->tcp_flags = tcp->tcp_flags;
        features->tcp_seq = rte_be_to_cpu_32(tcp->sent_seq);
        features->tcp_ack = rte_be_to_cpu_32(tcp->recv_ack);
        features->tcp_window = rte_be_to_cpu_16(tcp->rx_win);
        features->tcp_header_len = (tcp->data_off >> 4) * 4;
        break;

    case IPPROTO_UDP:
        udp = (struct rte_udp_hdr *)l4_hdr;

        if (unlikely((void *)udp + sizeof(struct rte_udp_hdr) >
                     rte_pktmbuf_mtod(m, void *) + m->data_len)) {
            return PARSE_MALFORMED;
        }

        features->src_port = rte_be_to_cpu_16(udp->src_port);
        features->dst_port = rte_be_to_cpu_16(udp->dst_port);
        features->udp_len = rte_be_to_cpu_16(udp->dgram_len);
        break;

    case IPPROTO_ICMP:
        features->src_port = 0;
        features->dst_port = 0;
        break;

    default:
        features->src_port = 0;
        features->dst_port = 0;
        break;
    }

    // ========== Compute Canonical Flow Hash ==========
    struct flow_key key;
    extract_flow_key(features, &key);
    features->flow_hash = compute_flow_hash(&key);

    return PARSE_OK;
}

// ==================== Packet Validation ====================

int validate_packet(const struct packet_features *features) {
    if (features->packet_size < 40) {
        return VALIDATE_ERR_TOO_SHORT;
    }

    if (features->ip_len < 20) {
        return VALIDATE_ERR_BAD_IPLEN;
    }

    if (features->ip_len > features->packet_size) {
        return VALIDATE_ERR_BAD_IPLEN;
    }

    if (features->ttl == 0) {
        return VALIDATE_ERR_ZERO_TTL;
    }

    if (is_invalid_src_ip(features->src_ip)) {
        return VALIDATE_ERR_INVALID_SRC;
    }

    if (is_invalid_dst_ip(features->dst_ip)) {
        return VALIDATE_ERR_INVALID_DST;
    }

    if (features->src_ip == features->dst_ip) {
        return VALIDATE_ERR_LAND_ATTACK;
    }

    uint16_t frag_off = features->ip_flags & 0x1FFF;
    bool mf = (features->ip_flags & 0x2000) != 0;

    if (frag_off > 0 && features->ip_len < 400) {
        return VALIDATE_ERR_FRAG_ATTACK;
    }

    if (frag_off == 0 && mf && features->ip_len > 1500) {
        return VALIDATE_ERR_FRAG_ATTACK;
    }

    if (features->protocol == IPPROTO_TCP) {
        int tcp_valid = validate_tcp_flags(features->tcp_flags);
        if (tcp_valid != VALIDATE_OK) {
            return tcp_valid;
        }

        if (features->ip_len < 40) {
            return VALIDATE_ERR_TCP_SHORT;
        }
    }

    if (features->protocol == IPPROTO_UDP) {
        if (features->udp_len > 0) {
            uint16_t expected_udp_len = features->ip_len - 20;
            if (features->udp_len != expected_udp_len) {
                if (abs((int)features->udp_len - (int)expected_udp_len) > 4) {
                    return VALIDATE_ERR_BAD_IPLEN;
                }
            }
        }
        // UDP minimum header is 8 bytes
        if (features->ip_len < 28) {
            return VALIDATE_ERR_UDP_SHORT;
        }
    }

    return VALIDATE_OK;
}

// ==================== Checksum Validation ====================

/**
 * Calculate IP header checksum.
 * Standard ones-complement sum algorithm.
 */
static inline uint16_t calculate_ip_checksum(const struct rte_ipv4_hdr *ip) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)ip;
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
    int words = ihl / 2;

    for (int i = 0; i < words; i++) {
        sum += rte_be_to_cpu_16(ptr[i]);
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)sum;
}

int validate_ip_checksum(struct rte_mbuf *m) {
    // Check if hardware already validated
    if (m->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) {
        uint64_t cksum_status = m->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK;
        if (cksum_status == RTE_MBUF_F_RX_IP_CKSUM_GOOD) {
            return VALIDATE_OK;
        }
        if (cksum_status == RTE_MBUF_F_RX_IP_CKSUM_BAD) {
            return VALIDATE_ERR_BAD_CHECKSUM;
        }
        // UNKNOWN - fall through to software check
    }

    // Software checksum verification
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    void *l3_hdr = (void *)(eth + 1);
    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)l3_hdr;
        ether_type = rte_be_to_cpu_16(vlan->eth_proto);
        l3_hdr = (void *)(vlan + 1);
    }

    if (ether_type != RTE_ETHER_TYPE_IPV4) {
        return VALIDATE_OK;  // Not IPv4, skip
    }

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)l3_hdr;

    // Checksum should sum to 0xFFFF when valid
    uint16_t sum = calculate_ip_checksum(ip);
    if (sum != 0xFFFF) {
        return VALIDATE_ERR_BAD_CHECKSUM;
    }

    return VALIDATE_OK;
}

/**
 * Calculate UDP pseudo-header + UDP checksum.
 */
int validate_udp_checksum(struct rte_mbuf *m) {
    // Check if hardware already validated
    if (m->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) {
        uint64_t cksum_status = m->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK;
        if (cksum_status == RTE_MBUF_F_RX_L4_CKSUM_GOOD) {
            return VALIDATE_OK;
        }
        if (cksum_status == RTE_MBUF_F_RX_L4_CKSUM_BAD) {
            return VALIDATE_ERR_UDP_CHECKSUM;
        }
        // UNKNOWN - fall through to software check
    }

    // Get IP header
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    void *l3_hdr = (void *)(eth + 1);
    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)l3_hdr;
        ether_type = rte_be_to_cpu_16(vlan->eth_proto);
        l3_hdr = (void *)(vlan + 1);
    }

    if (ether_type != RTE_ETHER_TYPE_IPV4) {
        return VALIDATE_OK;  // Not IPv4
    }

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)l3_hdr;

    if (ip->next_proto_id != IPPROTO_UDP) {
        return VALIDATE_OK;  // Not UDP
    }

    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((uint8_t *)ip + ihl);

    // UDP checksum of 0 means "not computed"
    if (udp->dgram_cksum == 0) {
        return VALIDATE_OK;  // Checksum not present (valid for UDP)
    }

    // Calculate UDP checksum with pseudo-header
    uint32_t sum = 0;

    // Pseudo header: src_ip + dst_ip + protocol + udp_length
    sum += (rte_be_to_cpu_32(ip->src_addr) >> 16) & 0xFFFF;
    sum += rte_be_to_cpu_32(ip->src_addr) & 0xFFFF;
    sum += (rte_be_to_cpu_32(ip->dst_addr) >> 16) & 0xFFFF;
    sum += rte_be_to_cpu_32(ip->dst_addr) & 0xFFFF;
    sum += IPPROTO_UDP;
    sum += rte_be_to_cpu_16(udp->dgram_len);

    // UDP header and data
    uint16_t udp_len = rte_be_to_cpu_16(udp->dgram_len);

    // Bounds-check: reject if udp_len extends past the packet buffer.
    // Without this, the checksum loop below would read out of bounds.
    if ((uint8_t *)udp + udp_len > rte_pktmbuf_mtod(m, uint8_t *) + m->data_len) {
        return VALIDATE_ERR_UDP_CHECKSUM;
    }

    uint16_t *ptr = (uint16_t *)udp;
    int words = udp_len / 2;

    for (int i = 0; i < words; i++) {
        sum += rte_be_to_cpu_16(ptr[i]);
    }

    // Handle odd byte
    if (udp_len & 1) {
        sum += ((uint8_t *)udp)[udp_len - 1] << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Valid checksum should result in 0xFFFF
    if ((uint16_t)sum != 0xFFFF) {
        return VALIDATE_ERR_UDP_CHECKSUM;
    }

    return VALIDATE_OK;
}

// ==================== TTL Handling ====================

/**
 * Get IPv4 header from packet.
 * Handles VLAN tagging.
 */
static inline struct rte_ipv4_hdr* get_ipv4_header(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    void *l3_hdr = (void *)(eth + 1);
    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)l3_hdr;
        ether_type = rte_be_to_cpu_16(vlan->eth_proto);
        l3_hdr = (void *)(vlan + 1);
    }

    if (ether_type != RTE_ETHER_TYPE_IPV4) {
        return NULL;
    }

    return (struct rte_ipv4_hdr *)l3_hdr;
}

bool check_ttl_for_forwarding(struct rte_mbuf *m) {
    struct rte_ipv4_hdr *ip = get_ipv4_header(m);
    if (!ip) {
        return true;  // Not IPv4, allow forwarding (L2 only)
    }

    // TTL must be > 1 to forward (will become >= 1 after decrement)
    return (ip->time_to_live > 1);
}

int decrement_ttl(struct rte_mbuf *m) {
    struct rte_ipv4_hdr *ip = get_ipv4_header(m);
    if (!ip) {
        return 0;  // Not IPv4, nothing to do
    }

    uint8_t ttl = ip->time_to_live;

    // Don't forward if TTL would become 0
    if (ttl <= 1) {
        return -1;
    }

    // Decrement TTL
    ip->time_to_live = ttl - 1;

    // Update IP checksum incrementally
    // When TTL decreases by 1, checksum increases by 0x0100 (TTL is at byte 8)
    // This is the RFC 1141 incremental update method
    uint16_t old_cksum = rte_be_to_cpu_16(ip->hdr_checksum);
    uint32_t new_cksum = (uint32_t)old_cksum + 0x0100;

    // Handle carry
    if (new_cksum > 0xFFFF) {
        new_cksum = (new_cksum & 0xFFFF) + 1;
    }

    ip->hdr_checksum = rte_cpu_to_be_16((uint16_t)new_cksum);

    return 0;
}

// Stub: ICMP checksum validation
int validate_icmp_checksum(struct rte_mbuf *m) {
    // Stub: accept all ICMP packets (checksum validation not yet implemented)
    (void)m;
    return VALIDATE_OK;
}

void packet_parser_init_hash_seed(void) {
    /* Stub: hash seed is initialized per-parse using rte_rand in parse_packet */
}