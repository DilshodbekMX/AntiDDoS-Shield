/**
 * @file packet_parser_v6.c
 * @brief IPv6 packet parsing implementation
 *
 * Provides dual-stack (IPv4/IPv6) packet parsing with:
 * - Extension header chain traversal
 * - Security validation for IPv6-specific attacks
 * - Fragment handling
 * - TCP/UDP/ICMPv6 transport layer parsing
 */

#include "packet_parser.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash_crc.h>
#include <rte_log.h>
#include <netinet/in.h>

#define RTE_LOGTYPE_PARSER_V6 RTE_LOGTYPE_USER3

// ==================== IPv6 Header Structure ====================
// Note: DPDK provides struct rte_ipv6_hdr in rte_ip6.h
// We use the DPDK structure directly for compatibility

// Extension header structure (generic)
struct ipv6_ext_hdr {
    uint8_t next_header;
    uint8_t hdr_len;  // In 8-byte units, excluding first 8 bytes
    // Followed by options
} __attribute__((packed));

// Fragment header
struct ipv6_frag_hdr {
    uint8_t  next_header;
    uint8_t  reserved;
    uint16_t frag_offset;   // Fragment offset (13 bits) + reserved (2) + M flag (1)
    uint32_t identification;
} __attribute__((packed));

// ==================== Flow Hash (IPv6) ====================

uint32_t compute_flow_hash_v6(const struct flow_key_v6 *key) {
    // Hash entire 36-byte structure
    return rte_hash_crc(key, sizeof(struct flow_key_v6), 0);
}

// ==================== Extension Header Processing ====================

/**
 * Check if a protocol number is an extension header
 */
static inline bool is_extension_header(uint8_t proto) {
    switch (proto) {
        case IPV6_EXT_HOP_BY_HOP:    // 0
        case IPV6_EXT_ROUTING:       // 43
        case IPV6_EXT_FRAGMENT:      // 44
        case IPV6_EXT_ESP:           // 50
        case IPV6_EXT_AH:            // 51
        case IPV6_EXT_DEST_OPTIONS:  // 60
        case IPPROTO_MOBILITY:       // 135
            return true;
        default:
            return false;
    }
}

/**
 * Skip extension header chain and find transport layer
 *
 * @param data       Pointer to first extension header
 * @param data_len   Remaining packet length
 * @param first_hdr  First next_header value from IPv6 header
 * @param features   Output features (ext_hdr_* fields updated)
 * @return Transport protocol, or negative on error
 */
static int skip_extension_headers(const uint8_t *data, size_t data_len,
                                   uint8_t first_hdr,
                                   struct packet_features_v6 *features,
                                   const uint8_t **transport_hdr) {
    uint8_t next_hdr = first_hdr;
    const uint8_t *ptr = data;
    size_t remaining = data_len;
    int ext_count = 0;
    size_t total_ext_len = 0;

    // Maximum extension headers to prevent infinite loops
    const int MAX_EXT_HEADERS = 8;

    while (is_extension_header(next_hdr) && ext_count < MAX_EXT_HEADERS) {
        if (remaining < 8) {
            return -1;  // Truncated
        }

        const struct ipv6_ext_hdr *ext = (const struct ipv6_ext_hdr *)ptr;
        size_t hdr_len;

        if (next_hdr == IPV6_EXT_FRAGMENT) {
            // Fragment header is fixed 8 bytes
            hdr_len = 8;
            features->has_fragment_hdr = 1;

            const struct ipv6_frag_hdr *frag = (const struct ipv6_frag_hdr *)ptr;
            // Extract fragment offset (bits 0-12 of frag_offset field)
            uint16_t frag_off = rte_be_to_cpu_16(frag->frag_offset);
            features->fragment_offset = (frag_off >> 3) * 8;  // In bytes
            features->ip_id = (uint16_t)(rte_be_to_cpu_32(frag->identification) & 0xFFFF);

            next_hdr = frag->next_header;
        } else if (next_hdr == IPV6_EXT_HOP_BY_HOP) {
            features->has_hop_by_hop = 1;
            hdr_len = (ext->hdr_len + 1) * 8;
            next_hdr = ext->next_header;
        } else if (next_hdr == IPV6_EXT_ROUTING) {
            hdr_len = (ext->hdr_len + 1) * 8;

            // Check for deprecated Type 0 Routing Header (security issue)
            if (remaining >= 3 && ptr[2] == 0) {
                features->has_routing_hdr = 1;
            }

            next_hdr = ext->next_header;
        } else if (next_hdr == IPV6_EXT_AH) {
            // Authentication Header uses different length calculation
            hdr_len = (ext->hdr_len + 2) * 4;
            next_hdr = ext->next_header;
        } else {
            // Generic extension header
            hdr_len = (ext->hdr_len + 1) * 8;
            next_hdr = ext->next_header;
        }

        if (hdr_len > remaining) {
            return -1;  // Header extends beyond packet
        }

        ptr += hdr_len;
        remaining -= hdr_len;
        total_ext_len += hdr_len;
        ext_count++;
    }

    if (ext_count >= MAX_EXT_HEADERS) {
        return -2;  // Too many extension headers (potential attack)
    }

    features->ext_hdr_count = ext_count;
    features->ext_hdr_len = total_ext_len;
    *transport_hdr = ptr;

    return next_hdr;
}

// ==================== IPv6 Packet Parser ====================

int parse_packet_v6(struct rte_mbuf *m, struct packet_features_v6 *features) {
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr *ipv4;
    struct rte_ipv6_hdr *ipv6;
    struct rte_tcp_hdr *tcp;
    struct rte_udp_hdr *udp;
    uint16_t ether_type;
    void *l3_hdr;

    // Initialize features
    memset(features, 0, sizeof(struct packet_features_v6));
    features->packet_size = m->pkt_len;
    features->timestamp_tsc = 0;  // Set by caller if needed

    // ========== Ethernet Layer ==========
    if (unlikely(m->pkt_len < sizeof(struct rte_ether_hdr))) {
        return PARSE_MALFORMED;
    }

    eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ether_type = rte_be_to_cpu_16(eth->ether_type);

    l3_hdr = (void *)(eth + 1);

    // Handle VLAN tagging
    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)l3_hdr;
        ether_type = rte_be_to_cpu_16(vlan->eth_proto);
        l3_hdr = (void *)(vlan + 1);
    }

    // Double VLAN (Q-in-Q)
    if (ether_type == RTE_ETHER_TYPE_VLAN || ether_type == 0x88A8) {
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)l3_hdr;
        ether_type = rte_be_to_cpu_16(vlan->eth_proto);
        l3_hdr = (void *)(vlan + 1);
    }

    // ========== IPv4 Path ==========
    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        features->ip_version = IP_VERSION_4;

        ipv4 = (struct rte_ipv4_hdr *)l3_hdr;
        if (unlikely((void *)ipv4 + sizeof(struct rte_ipv4_hdr) >
                     rte_pktmbuf_mtod(m, void *) + m->data_len)) {
            return PARSE_MALFORMED;
        }

        // Validate IHL
        uint8_t ihl = (ipv4->version_ihl & 0x0F) * 4;
        if (unlikely(ihl < 20)) {
            return PARSE_MALFORMED;
        }

        features->src_ip.v4 = ipv4->src_addr;
        features->dst_ip.v4 = ipv4->dst_addr;
        features->ttl = ipv4->time_to_live;
        features->ip_tos = ipv4->type_of_service;
        features->ip_len = rte_be_to_cpu_16(ipv4->total_length);
        features->ip_id = rte_be_to_cpu_16(ipv4->packet_id);
        features->ip_flags = rte_be_to_cpu_16(ipv4->fragment_offset);
        features->protocol = ipv4->next_proto_id;
        features->ipv6_flow_label = 0;

        void *l4_hdr = (void *)ipv4 + ihl;

        // Parse transport layer
        switch (features->protocol) {
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

            default:
                features->src_port = 0;
                features->dst_port = 0;
                break;
        }

        // Compute flow hash
        struct flow_key_v6 key;
        extract_flow_key_v6(features, &key);
        features->flow_hash = compute_flow_hash_v6(&key);

        return PARSE_OK;
    }

    // ========== IPv6 Path ==========
    if (ether_type != RTE_ETHER_TYPE_IPV6) {
        return PARSE_NOT_IP;
    }

    features->ip_version = IP_VERSION_6;

    ipv6 = (struct rte_ipv6_hdr *)l3_hdr;
    if (unlikely((void *)ipv6 + sizeof(struct rte_ipv6_hdr) >
                 rte_pktmbuf_mtod(m, void *) + m->data_len)) {
        return PARSE_MALFORMED;
    }

    // Extract IPv6 header fields
    uint32_t vtc_flow = rte_be_to_cpu_32(ipv6->vtc_flow);
    features->ip_tos = (vtc_flow >> 20) & 0xFF;  // Traffic class
    features->ipv6_flow_label = vtc_flow & 0xFFFFF;  // Flow label
    features->ip_len = rte_be_to_cpu_16(ipv6->payload_len) + 40;  // Include header
    features->ttl = ipv6->hop_limits;

    // Copy addresses (rte_ipv6_addr has .a field for raw bytes)
    memcpy(features->src_ip.v6, &ipv6->src_addr, 16);
    memcpy(features->dst_ip.v6, &ipv6->dst_addr, 16);

    // Process extension headers
    const uint8_t *transport_hdr;
    uint8_t *pkt_base = rte_pktmbuf_mtod(m, uint8_t *);
    uint8_t *ipv6_end = (uint8_t *)ipv6 + sizeof(struct rte_ipv6_hdr);
    if (unlikely(ipv6_end < pkt_base ||
                 (size_t)(ipv6_end - pkt_base) > m->data_len)) {
        return PARSE_MALFORMED;
    }
    size_t l3_end = (size_t)(ipv6_end - pkt_base);
    size_t remaining = m->data_len - l3_end;

    int proto = skip_extension_headers(
        (const uint8_t *)(ipv6 + 1),
        remaining,
        ipv6->proto,
        features,
        &transport_hdr
    );

    if (proto < 0) {
        return PARSE_MALFORMED;
    }

    features->protocol = proto;

    // Parse transport layer
    size_t transport_offset = transport_hdr - rte_pktmbuf_mtod(m, const uint8_t *);
    size_t transport_remaining = m->data_len - transport_offset;

    switch (proto) {
        case IPPROTO_TCP:
            if (transport_remaining < sizeof(struct rte_tcp_hdr)) {
                return PARSE_MALFORMED;
            }
            tcp = (struct rte_tcp_hdr *)transport_hdr;
            features->src_port = rte_be_to_cpu_16(tcp->src_port);
            features->dst_port = rte_be_to_cpu_16(tcp->dst_port);
            features->tcp_flags = tcp->tcp_flags;
            features->tcp_seq = rte_be_to_cpu_32(tcp->sent_seq);
            features->tcp_ack = rte_be_to_cpu_32(tcp->recv_ack);
            features->tcp_window = rte_be_to_cpu_16(tcp->rx_win);
            features->tcp_header_len = (tcp->data_off >> 4) * 4;
            break;

        case IPPROTO_UDP:
            if (transport_remaining < sizeof(struct rte_udp_hdr)) {
                return PARSE_MALFORMED;
            }
            udp = (struct rte_udp_hdr *)transport_hdr;
            features->src_port = rte_be_to_cpu_16(udp->src_port);
            features->dst_port = rte_be_to_cpu_16(udp->dst_port);
            features->udp_len = rte_be_to_cpu_16(udp->dgram_len);
            break;

        case IPPROTO_ICMPV6:
            features->src_port = 0;
            features->dst_port = 0;
            break;

        default:
            features->src_port = 0;
            features->dst_port = 0;
            break;
    }

    // Compute flow hash
    struct flow_key_v6 key;
    extract_flow_key_v6(features, &key);
    features->flow_hash = compute_flow_hash_v6(&key);

    return PARSE_IPV6;
}

// ==================== IPv6 Packet Validation ====================

int validate_packet_v6(const struct packet_features_v6 *features) {
    // Common validations
    if (features->packet_size < 40) {
        return VALIDATE_ERR_TOO_SHORT;
    }

    if (features->ttl == 0) {
        return VALIDATE_ERR_ZERO_TTL;
    }

    if (features->ip_version == IP_VERSION_4) {
        // IPv4 validations
        uint32_t src = features->src_ip.v4;
        uint32_t dst = features->dst_ip.v4;
        uint32_t host_src = rte_be_to_cpu_32(src);

        // Invalid source checks
        if (host_src == 0) return VALIDATE_ERR_INVALID_SRC;
        if (host_src == 0xFFFFFFFF) return VALIDATE_ERR_INVALID_SRC;
        if ((host_src & 0xFF000000) == 0x7F000000) return VALIDATE_ERR_INVALID_SRC;
        if ((host_src & 0xF0000000) == 0xE0000000) return VALIDATE_ERR_INVALID_SRC;

        // LAND attack
        if (src == dst) return VALIDATE_ERR_LAND_ATTACK;

    } else {
        // IPv6 validations
        const uint8_t *src = features->src_ip.v6;
        const uint8_t *dst = features->dst_ip.v6;

        // Source cannot be multicast
        if (ipv6_is_multicast(src)) {
            return VALIDATE_ERR_IPV6_MULTICAST_SRC;
        }

        // Source cannot be loopback (from external)
        if (ipv6_is_loopback(src)) {
            return VALIDATE_ERR_IPV6_LOOPBACK;
        }

        // Source cannot be unspecified (except in certain contexts)
        if (ipv6_is_unspecified(src)) {
            return VALIDATE_ERR_INVALID_SRC;
        }

        // LAND attack check
        if (memcmp(src, dst, 16) == 0) {
            return VALIDATE_ERR_LAND_ATTACK;
        }

        // Deprecated Type 0 Routing Header (security vulnerability)
        if (features->has_routing_hdr) {
            return VALIDATE_ERR_IPV6_ROUTING_0;
        }

        // Too many extension headers (potential attack)
        if (features->ext_hdr_count > 6) {
            return VALIDATE_ERR_IPV6_EXT_LOOP;
        }
    }

    // TCP flag validations
    if (features->protocol == IPPROTO_TCP) {
        uint8_t flags = features->tcp_flags;

        // NULL scan
        if (flags == 0) {
            return VALIDATE_ERR_TCP_NULL;
        }

        // XMAS scan
        if ((flags & (TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG)) ==
            (TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG)) {
            return VALIDATE_ERR_TCP_XMAS;
        }

        // Invalid flag combinations
        if ((flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) == (TCP_FLAG_SYN | TCP_FLAG_FIN)) {
            return VALIDATE_ERR_TCP_INVALID;
        }
        if ((flags & (TCP_FLAG_SYN | TCP_FLAG_RST)) == (TCP_FLAG_SYN | TCP_FLAG_RST)) {
            return VALIDATE_ERR_TCP_INVALID;
        }
    }

    return VALIDATE_OK;
}
