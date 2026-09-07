#include "packet_features.h"
#include "types.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <string.h>

// ==================== Entropy Calculation ====================
// NOTE: Payload/header entropy calculation REMOVED from hot path
// Reason: ~20,000 cycles per packet for log2() calculations
// Source IP entropy is tracked efficiently via HyperLogLog instead
// Destination port entropy added to per-IP features (per_ip_features.h)

// ==================== TCP MSS Extraction ====================

/**
 * Parse TCP options to find MSS
 *
 * TCP options format:
 * - Kind (1 byte): 2 = MSS
 * - Length (1 byte): 4 for MSS
 * - Value (2 bytes): MSS value
 */
uint16_t extract_tcp_mss(const struct rte_tcp_hdr *tcp_hdr) {
    uint8_t tcp_hdr_len = (tcp_hdr->data_off >> 4) * 4;  // Header length in bytes
    if (tcp_hdr_len <= sizeof(struct rte_tcp_hdr)) {
        return 0;  // No options
    }

    const uint8_t *options = (const uint8_t *)tcp_hdr + sizeof(struct rte_tcp_hdr);
    uint8_t options_len = tcp_hdr_len - sizeof(struct rte_tcp_hdr);
    uint8_t i = 0;

    while (i < options_len) {
        uint8_t kind = options[i];

        if (kind == 0) {  // End of options
            break;
        }

        if (kind == 1) {  // NOP (No Operation)
            i++;
            continue;
        }

        if (i + 1 >= options_len) {
            break;  // Malformed options
        }

        uint8_t opt_len = options[i + 1];
        if (opt_len < 2 || i + opt_len > options_len) {
            break;  // Invalid option length
        }

        if (kind == 2 && opt_len == 4) {  // MSS option
            uint16_t mss = (options[i + 2] << 8) | options[i + 3];
            return mss;
        }

        i += opt_len;
    }

    return 0;  // MSS not found
}

// ==================== Feature Extraction ====================

/**
 * Extract extended features from packet
 *
 * Assumes basic parsing already done (parse_packet() called first)
 */
int extract_features(struct rte_mbuf *m, struct packet_features *features) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;
    const uint8_t *payload;
    uint16_t payload_len;

    // Get Ethernet header
    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
    void *l3_hdr_ptr = (void *)(eth_hdr + 1);

    // Handle VLAN tagging -- parse_packet() strips this, so we must too
    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        if (m->pkt_len < sizeof(struct rte_ether_hdr) +
                         sizeof(struct rte_vlan_hdr) +
                         sizeof(struct rte_ipv4_hdr)) {
            return -1;
        }
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)l3_hdr_ptr;
        ether_type = rte_be_to_cpu_16(vlan->eth_proto);
        l3_hdr_ptr = (void *)(vlan + 1);
    }

    if (ether_type != RTE_ETHER_TYPE_IPV4) {
        return -1;  // Not IPv4
    }

    // Get IP header
    ip_hdr = (struct rte_ipv4_hdr *)l3_hdr_ptr;
    uint8_t ip_hdr_len = (ip_hdr->version_ihl & 0x0F) * 4;
    if (ip_hdr_len < 20) return -1;  // Malformed IHL

    // Extract IP-level features
    features->ip_tos = ip_hdr->type_of_service;
    features->fragment_offset = rte_be_to_cpu_16(ip_hdr->fragment_offset) & 0x1FFF;
    features->fragment_offset *= 8;  // Convert to bytes

    // Protocol-specific extraction
    if (features->protocol == IPPROTO_TCP) {
        tcp_hdr = (struct rte_tcp_hdr *)((uint8_t *)ip_hdr + ip_hdr_len);
        if ((uint8_t *)tcp_hdr + sizeof(struct rte_tcp_hdr) >
            rte_pktmbuf_mtod(m, uint8_t *) + m->data_len) {
            return -1;
        }
        uint8_t tcp_hdr_len = (tcp_hdr->data_off >> 4) * 4;

        // Extract TCP MSS from options
        features->tcp_mss = extract_tcp_mss(tcp_hdr);

        // Calculate payload -- use IP total_length for stored payload_len so
        // higher layers know the true L4 payload size reported by the IP header.
        payload = (const uint8_t *)tcp_hdr + tcp_hdr_len;
        uint16_t ip_total_len = rte_be_to_cpu_16(ip_hdr->total_length);
        payload_len = (ip_total_len >= ip_hdr_len + tcp_hdr_len)
                      ? ip_total_len - ip_hdr_len - tcp_hdr_len : 0;
        features->payload_len = payload_len;

        // Sample first 16 bytes of payload (for signature matching).
        // Clamp to bytes actually present in the mbuf -- ip_total_len may exceed
        // m->data_len for truncated/malformed frames, which would read past valid data.
        const uint8_t *pkt_end = rte_pktmbuf_mtod(m, const uint8_t *) + m->data_len;
        uint16_t avail = (payload < pkt_end) ? (uint16_t)(pkt_end - payload) : 0;
        uint16_t sample_len = RTE_MIN(payload_len, RTE_MIN((uint16_t)16, avail));
        if (sample_len > 0) {
            memcpy(features->payload_sample, payload, sample_len);
        }
        if (sample_len < 16) {
            memset((uint8_t *)features->payload_sample + sample_len, 0, 16 - sample_len);
        }

        // Entropy REMOVED - too expensive (~20K cycles/pkt)
        // Destination port entropy tracked via HyperLogLog in per_ip_features instead
        features->payload_entropy = 0;
        features->header_entropy = 0;

    } else if (features->protocol == IPPROTO_UDP) {
        udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_len);
        if ((uint8_t *)udp_hdr + sizeof(struct rte_udp_hdr) >
            rte_pktmbuf_mtod(m, uint8_t *) + m->data_len) {
            return -1;
        }

        // Calculate payload
        payload = (const uint8_t *)(udp_hdr + 1);
        uint16_t udp_len = rte_be_to_cpu_16(udp_hdr->dgram_len);
        payload_len = (udp_len >= sizeof(struct rte_udp_hdr))
                      ? udp_len - (uint16_t)sizeof(struct rte_udp_hdr) : 0;
        features->payload_len = payload_len;

        // Sample first 16 bytes of payload -- clamp to mbuf data_len.
        const uint8_t *pkt_end_udp = rte_pktmbuf_mtod(m, const uint8_t *) + m->data_len;
        uint16_t avail_udp = (payload < pkt_end_udp) ? (uint16_t)(pkt_end_udp - payload) : 0;
        uint16_t sample_len = RTE_MIN(payload_len, RTE_MIN((uint16_t)16, avail_udp));
        if (sample_len > 0) {
            memcpy(features->payload_sample, payload, sample_len);
        }
        if (sample_len < 16) {
            memset((uint8_t *)features->payload_sample + sample_len, 0, 16 - sample_len);
        }

        // Entropy REMOVED - tracked via HyperLogLog instead
        features->payload_entropy = 0;
        features->header_entropy = 0;

    } else {
        // Other protocols (ICMP, etc.)
        payload = (const uint8_t *)ip_hdr + ip_hdr_len;
        uint16_t icmp_total_len = rte_be_to_cpu_16(ip_hdr->total_length);
        payload_len = (icmp_total_len >= ip_hdr_len)
                      ? icmp_total_len - ip_hdr_len : 0;
        features->payload_len = payload_len;

        // Sample payload -- clamp to mbuf data_len.
        const uint8_t *pkt_end_icmp = rte_pktmbuf_mtod(m, const uint8_t *) + m->data_len;
        uint16_t avail_icmp = (payload < pkt_end_icmp) ? (uint16_t)(pkt_end_icmp - payload) : 0;
        uint16_t sample_len = RTE_MIN(payload_len, RTE_MIN((uint16_t)16, avail_icmp));
        if (sample_len > 0) {
            memcpy(features->payload_sample, payload, sample_len);
        }
        if (sample_len < 16) {
            memset((uint8_t *)features->payload_sample + sample_len, 0, 16 - sample_len);
        }

        // Entropy REMOVED - tracked via HyperLogLog instead
        features->payload_entropy = 0;
        features->header_entropy = 0;
    }

    // Behavioral features (is_retransmit, is_out_of_order, inter_arrival_us)
    // are set by flow_table_update() which has access to per-flow history

    return 0;
}
