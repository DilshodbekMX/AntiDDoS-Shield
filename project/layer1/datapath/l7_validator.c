/**
 * L7 Protocol Validator
 *
 * Application-layer validation for DNS (UDP:53), NTP (UDP:123),
 * and HTTP (TCP:80/8080 first data packet).
 *
 * All checks are gated by per-protocol config toggles in l7_validation_cfg.
 */

#include "l7_validator.h"
#include "../config/layer1_config.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_log.h>
#include <netinet/in.h>

#define RTE_LOGTYPE_L7VAL RTE_LOGTYPE_USER4

// ==================== Error Strings ====================

static const struct {
    int code;
    const char *str;
} l7_error_table[] = {
    { L7_VALIDATE_OK,              "OK" },
    // DNS
    { L7_ERR_DNS_TOO_SHORT,        "DNS too short (<12 bytes)" },
    { L7_ERR_DNS_INVALID_OPCODE,   "DNS invalid opcode" },
    { L7_ERR_DNS_QR_MISMATCH,      "DNS QR bit direction mismatch" },
    { L7_ERR_DNS_QDCOUNT,          "DNS QDCOUNT != 1" },
    { L7_ERR_DNS_BOTH_PORT53,      "DNS both ports 53" },
    { L7_ERR_DNS_AXFR_UDP,         "DNS zone transfer over UDP" },
    { L7_ERR_DNS_LABEL_TOO_LONG,   "DNS label > 63 bytes" },
    { L7_ERR_DNS_NAME_TOO_LONG,    "DNS name > 255 bytes" },
    { L7_ERR_DNS_POINTER_LOOP,     "DNS compression pointer loop" },
    { L7_ERR_DNS_MSG_TOO_LONG,     "DNS UDP message too long" },
    // NTP
    { L7_ERR_NTP_TOO_SHORT,        "NTP too short" },
    { L7_ERR_NTP_INVALID_VERSION,  "NTP invalid version" },
    { L7_ERR_NTP_INVALID_MODE,     "NTP invalid mode" },
    { L7_ERR_NTP_INVALID_STRATUM,  "NTP invalid stratum" },
    { L7_ERR_NTP_MONLIST,          "NTP monlist (mode 7)" },
    { L7_ERR_NTP_CONTROL,          "NTP control (mode 6)" },
    { L7_ERR_NTP_SIZE_MISMATCH,    "NTP size mismatch" },
    // HTTP
    { L7_ERR_HTTP_INVALID_METHOD,  "HTTP invalid method" },
    { L7_ERR_HTTP_INVALID_VERSION, "HTTP invalid version" },
    { L7_ERR_HTTP_LINE_TOO_LONG,   "HTTP request line too long" },
    { L7_ERR_HTTP_NON_ASCII,       "HTTP non-ASCII in request line" },
    // ICMP
    { L7_ERR_ICMP_REDIRECT,        "ICMP redirect (type 5)" },
    { L7_ERR_ICMP_ROUTER_ADVERT,   "ICMP router advertisement (type 9)" },
    { L7_ERR_ICMP_ROUTER_SOLICIT,  "ICMP router solicitation (type 10)" },
    { L7_ERR_ICMP_TIMESTAMP,       "ICMP timestamp (type 13/14)" },
    { L7_ERR_ICMP_ADDRESS_MASK,    "ICMP address mask (type 17/18)" },
    { L7_ERR_ICMP_INFO,            "ICMP information (type 15/16)" },
    { L7_ERR_ICMP_SOURCE_QUENCH,   "ICMP source quench (type 4)" },
    { L7_ERR_ICMP_RATE_LIMITED,    "ICMP rate limited" },
    { 0, NULL },
};

const char *l7_error_str(int code) {
    for (int i = 0; l7_error_table[i].str != NULL; i++) {
        if (l7_error_table[i].code == code)
            return l7_error_table[i].str;
    }
    return "Unknown L7 error";
}

// ==================== Helpers ====================

/**
 * Get pointer to L7 payload and its length from an mbuf.
 * Returns NULL if payload is out of bounds.
 */
static inline const uint8_t *get_l7_payload(struct rte_mbuf *m,
                                             const struct packet_features *f,
                                             uint16_t *out_len) {
    const uint8_t *pkt = rte_pktmbuf_mtod(m, const uint8_t *);
    uint32_t pkt_len = m->data_len;

    /* Ethernet header: 14 bytes (or 18 with VLAN) */
    uint32_t eth_len = sizeof(struct rte_ether_hdr);
    if (pkt_len < eth_len + 20)
        return NULL;

    /* Check for VLAN tag */
    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)pkt;
    uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
    if (etype == RTE_ETHER_TYPE_VLAN)
        eth_len += sizeof(struct rte_vlan_hdr);

    /* IP header length from IHL field */
    const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(pkt + eth_len);
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;

    uint32_t l4_offset = eth_len + ihl;

    uint32_t l7_offset;
    if (f->protocol == IPPROTO_UDP) {
        l7_offset = l4_offset + 8;  /* UDP header = 8 bytes */
    } else if (f->protocol == IPPROTO_TCP) {
        l7_offset = l4_offset + f->tcp_header_len;
    } else {
        return NULL;
    }

    if (l7_offset >= pkt_len) {
        *out_len = 0;
        return NULL;
    }

    *out_len = (uint16_t)(pkt_len - l7_offset);
    return pkt + l7_offset;
}

// ==================== DNS Validation ====================

#define DNS_HDR_LEN     12
#define DNS_MAX_LABEL   63
#define DNS_MAX_NAME    255
#define DNS_PTR_DEPTH   16
#define DNS_QTYPE_AXFR  252

static int validate_dns(const uint8_t *payload, uint16_t len,
                         const struct packet_features *f,
                         const struct l7_validation_cfg *cfg) {
    /* Both ports 53 -- always suspicious */
    if (cfg->dns_drop_both_port53 && f->src_port == 53 && f->dst_port == 53)
        return L7_ERR_DNS_BOTH_PORT53;

    /* Too short for DNS header */
    if (cfg->dns_drop_too_short && len < DNS_HDR_LEN)
        return L7_ERR_DNS_TOO_SHORT;

    if (len < DNS_HDR_LEN)
        return L7_VALIDATE_OK;  /* Can't parse further without header */

    /* Parse DNS header fields (big-endian) */
    uint8_t  flags0  = payload[2];
    uint8_t  flags1  = payload[3];
    uint8_t  qr      = (flags0 >> 7) & 1;
    uint8_t  opcode  = (flags0 >> 3) & 0xF;
    uint16_t qdcount = (payload[4] << 8) | payload[5];

    (void)flags1;

    /* Invalid opcode (valid: 0=Query, 1=IQuery, 2=Status, 4=Notify, 5=Update) */
    if (cfg->dns_drop_invalid_opcode && opcode > 5)
        return L7_ERR_DNS_INVALID_OPCODE;

    /* QR bit direction mismatch:
     * - dst_port==53 means this is a query -> QR should be 0
     * - src_port==53 means this is a response -> QR should be 1 */
    if (cfg->dns_drop_qr_mismatch) {
        if (f->dst_port == 53 && qr == 1)
            return L7_ERR_DNS_QR_MISMATCH;
        if (f->src_port == 53 && f->dst_port != 53 && qr == 0)
            return L7_ERR_DNS_QR_MISMATCH;
    }

    /* Standard query (opcode 0) should have exactly 1 question */
    if (cfg->dns_drop_qdcount_invalid && opcode == 0 && qr == 0 && qdcount != 1)
        return L7_ERR_DNS_QDCOUNT;

    /* Message too long for UDP */
    if (cfg->dns_max_udp_size > 0 && len > cfg->dns_max_udp_size)
        return L7_ERR_DNS_MSG_TOO_LONG;

    /* Walk question section for label/name validation and AXFR check */
    if (qdcount > 0 && len > DNS_HDR_LEN) {
        uint16_t pos = DNS_HDR_LEN;
        uint16_t name_len = 0;
        uint8_t  ptr_count = 0;
        bool     following_ptr = false;
        uint16_t saved_pos = 0;  /* Position to return to after pointer */

        while (pos < len) {
            uint8_t label_len = payload[pos];

            /* Compression pointer (top 2 bits = 11) */
            if ((label_len & 0xC0) == 0xC0) {
                if (pos + 1 >= len)
                    break;
                ptr_count++;
                if (cfg->dns_drop_pointer_loop && ptr_count > DNS_PTR_DEPTH)
                    return L7_ERR_DNS_POINTER_LOOP;

                if (!following_ptr) {
                    saved_pos = pos + 2;  /* After the pointer */
                    following_ptr = true;
                }
                uint16_t ptr_offset = ((label_len & 0x3F) << 8) | payload[pos + 1];
                if (ptr_offset >= len || ptr_offset >= pos)
                    break;  /* Invalid pointer -- stop walking */
                pos = ptr_offset;
                continue;
            }

            /* End of name (zero-length label) */
            if (label_len == 0) {
                if (following_ptr)
                    pos = saved_pos;
                else
                    pos++;
                break;
            }

            /* Label length check */
            if (cfg->dns_drop_label_too_long && label_len > DNS_MAX_LABEL)
                return L7_ERR_DNS_LABEL_TOO_LONG;

            name_len += label_len + 1;  /* +1 for the length byte or dot */
            if (cfg->dns_drop_name_too_long && name_len > DNS_MAX_NAME)
                return L7_ERR_DNS_NAME_TOO_LONG;

            pos += 1 + label_len;
        }

        /* After name: QTYPE(2) + QCLASS(2) */
        if (pos + 4 <= len) {
            uint16_t qtype = (payload[pos] << 8) | payload[pos + 1];
            if (cfg->dns_drop_zone_transfer && qtype == DNS_QTYPE_AXFR)
                return L7_ERR_DNS_AXFR_UDP;
        }
    }

    return L7_VALIDATE_OK;
}

// ==================== NTP Validation ====================

#define NTP_STANDARD_LEN  48

static int validate_ntp(const uint8_t *payload, uint16_t len,
                         const struct l7_validation_cfg *cfg) {
    /* Need at least 1 byte for LI/VN/Mode */
    if (len < 1) {
        if (cfg->ntp_drop_too_short)
            return L7_ERR_NTP_TOO_SHORT;
        return L7_VALIDATE_OK;
    }

    uint8_t byte0   = payload[0];
    uint8_t version = (byte0 >> 3) & 0x7;
    uint8_t mode    = byte0 & 0x7;

    /* Invalid version (must be 1-4) */
    if (cfg->ntp_drop_invalid_version && (version == 0 || version > 4))
        return L7_ERR_NTP_INVALID_VERSION;

    /* Mode 7: private/monlist -- primary amplification vector (CVE-2013-5211) */
    if (cfg->ntp_drop_monlist && mode == 7)
        return L7_ERR_NTP_MONLIST;

    /* Mode 6: control -- management protocol, rarely needed from internet */
    if (cfg->ntp_drop_control && mode == 6)
        return L7_ERR_NTP_CONTROL;

    /* Size validation per mode */
    if (mode == 6 || mode == 7) {
        /* Control/private: minimum 4 bytes (header) */
        if (cfg->ntp_drop_too_short && len < 4)
            return L7_ERR_NTP_TOO_SHORT;
    } else if (mode >= 1 && mode <= 5) {
        /* Standard client/server/broadcast: 48 bytes */
        if (cfg->ntp_drop_too_short && len < NTP_STANDARD_LEN)
            return L7_ERR_NTP_TOO_SHORT;

        /* Stratum validation (byte 1) -- valid range 0-15 */
        if (cfg->ntp_drop_invalid_stratum && len >= 2 && payload[1] > 15)
            return L7_ERR_NTP_INVALID_STRATUM;

        /* Size mismatch: standard NTP should be exactly 48 or 68 (with auth) bytes */
        if (cfg->ntp_drop_size_mismatch &&
            len != 48 && len != 68 && len < 48) {
            return L7_ERR_NTP_SIZE_MISMATCH;
        }
    }

    return L7_VALIDATE_OK;
}

// ==================== HTTP Validation ====================

/* Known HTTP methods (sorted by frequency for fast-path) */
static const struct {
    const char *method;
    uint8_t    len;
} http_methods[] = {
    { "GET ",     4 },
    { "POST ",    5 },
    { "HEAD ",    5 },
    { "PUT ",     4 },
    { "DELETE ",  7 },
    { "PATCH ",   6 },
    { "OPTIONS ", 8 },
    { "CONNECT ", 8 },
    { "TRACE ",   6 },
    { NULL, 0 },
};

#define TCP_FLAG_PSH  0x08

static int validate_http(const uint8_t *payload, uint16_t len,
                          const struct packet_features *f,
                          const struct l7_validation_cfg *cfg) {
    /* Only inspect packets with PSH flag (carrying application data) */
    if (!(f->tcp_flags & TCP_FLAG_PSH))
        return L7_VALIDATE_OK;

    /* Need at least a few bytes to check method */
    if (len < 4)
        return L7_VALIDATE_OK;  /* Too small to be HTTP -- let it through */

    /* Check if first bytes match a known HTTP method */
    if (cfg->http_drop_invalid_method) {
        bool found = false;
        for (int i = 0; http_methods[i].method != NULL; i++) {
            if (len >= http_methods[i].len &&
                memcmp(payload, http_methods[i].method, http_methods[i].len) == 0) {
                found = true;
                break;
            }
        }
        if (!found)
            return L7_ERR_HTTP_INVALID_METHOD;
    }

    /* Scan request line for version, length, and non-ASCII */
    uint16_t max_scan = len;
    if (cfg->http_max_request_line > 0 && max_scan > cfg->http_max_request_line)
        max_scan = cfg->http_max_request_line;

    bool found_crlf = false;
    bool found_version = false;

    for (uint16_t i = 0; i < max_scan; i++) {
        uint8_t c = payload[i];

        /* Check for non-printable ASCII (except \r=0x0D, \n=0x0A, space, tab) */
        if (cfg->http_drop_non_ascii) {
            if (c < 0x20 && c != '\r' && c != '\n' && c != '\t')
                return L7_ERR_HTTP_NON_ASCII;
            if (c > 0x7E && c != 0xFF)  /* 0xFF sometimes in keep-alive */
                return L7_ERR_HTTP_NON_ASCII;
        }

        /* Look for end of request line */
        if (c == '\n') {
            found_crlf = true;
            break;
        }

        /* Look for "HTTP/" version marker */
        if (!found_version && c == 'H' && i + 8 <= max_scan) {
            if (memcmp(payload + i, "HTTP/", 5) == 0) {
                found_version = true;
                /* Validate version: 0.9, 1.0, 1.1 */
                if (cfg->http_drop_invalid_version && i + 8 <= len) {
                    char ver[4] = {0};
                    memcpy(ver, payload + i + 5, 3);
                    if (memcmp(ver, "0.9", 3) != 0 &&
                        memcmp(ver, "1.0", 3) != 0 &&
                        memcmp(ver, "1.1", 3) != 0) {
                        return L7_ERR_HTTP_INVALID_VERSION;
                    }
                }
            }
        }
    }

    /* Request line too long (no \n found within limit) */
    if (cfg->http_drop_line_too_long && !found_crlf &&
        cfg->http_max_request_line > 0 && len >= cfg->http_max_request_line) {
        return L7_ERR_HTTP_LINE_TOO_LONG;
    }

    return L7_VALIDATE_OK;
}

// ==================== ICMP Validation ====================

/* Atomic counter + timestamp for ICMP rate limiting */
static uint64_t icmp_counter __rte_cache_aligned;
static uint64_t icmp_last_reset_tsc __rte_cache_aligned;

static int validate_icmp(const struct packet_features *f,
                          const struct l7_validation_cfg *cfg) {
    /* Type-based filtering -- drop dangerous ICMP types */
    switch (f->icmp_type) {
    case 4:  /* Source Quench (obsolete per RFC 6633) */
        if (cfg->icmp_drop_source_quench)
            return L7_ERR_ICMP_SOURCE_QUENCH;
        break;
    case 5:  /* Redirect -- route injection attack vector */
        if (cfg->icmp_drop_redirect)
            return L7_ERR_ICMP_REDIRECT;
        break;
    case 9:  /* Router Advertisement */
        if (cfg->icmp_drop_router_advert)
            return L7_ERR_ICMP_ROUTER_ADVERT;
        break;
    case 10: /* Router Solicitation */
        if (cfg->icmp_drop_router_solicit)
            return L7_ERR_ICMP_ROUTER_SOLICIT;
        break;
    case 13: /* Timestamp Request */
    case 14: /* Timestamp Reply */
        if (cfg->icmp_drop_timestamp)
            return L7_ERR_ICMP_TIMESTAMP;
        break;
    case 15: /* Information Request (obsolete) */
    case 16: /* Information Reply (obsolete) */
        if (cfg->icmp_drop_info)
            return L7_ERR_ICMP_INFO;
        break;
    case 17: /* Address Mask Request */
    case 18: /* Address Mask Reply */
        if (cfg->icmp_drop_address_mask)
            return L7_ERR_ICMP_ADDRESS_MASK;
        break;
    default:
        break;
    }

    /* Rate limiting -- simple atomic counter reset per second */
    if (cfg->icmp_rate_limit_pps > 0) {
        uint64_t now = rte_rdtsc();
        uint64_t hz = rte_get_tsc_hz();
        uint64_t last = __atomic_load_n(&icmp_last_reset_tsc, __ATOMIC_RELAXED);

        if (now - last > hz) {
            /* Reset counter every second */
            __atomic_store_n(&icmp_counter, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&icmp_last_reset_tsc, now, __ATOMIC_RELAXED);
        }

        uint64_t count = __atomic_add_fetch(&icmp_counter, 1, __ATOMIC_RELAXED);
        if (count > cfg->icmp_rate_limit_pps)
            return L7_ERR_ICMP_RATE_LIMITED;
    }

    return L7_VALIDATE_OK;
}

// ==================== Main Dispatcher ====================

int validate_l7_packet(struct rte_mbuf *m, const struct packet_features *features) {
    const struct layer1_config *cfg = layer1_config_get();
    if (!cfg)
        return L7_VALIDATE_OK;

    const struct l7_validation_cfg *l7 = &cfg->l7_validation;

    /* ICMP: type/code filtering + rate limiting */
    if (l7->icmp_enabled && features->protocol == IPPROTO_ICMP) {
        int rc = validate_icmp(features, l7);
        if (rc != L7_VALIDATE_OK)
            return rc;
    }

    /* DNS: UDP port 53 */
    if (l7->dns_enabled && features->protocol == IPPROTO_UDP &&
        (features->dst_port == 53 || features->src_port == 53)) {
        uint16_t payload_len = 0;
        const uint8_t *payload = get_l7_payload(m, features, &payload_len);
        if (payload && payload_len > 0)
            return validate_dns(payload, payload_len, features, l7);
    }

    /* NTP: UDP port 123 */
    if (l7->ntp_enabled && features->protocol == IPPROTO_UDP &&
        (features->dst_port == 123 || features->src_port == 123)) {
        uint16_t payload_len = 0;
        const uint8_t *payload = get_l7_payload(m, features, &payload_len);
        if (payload && payload_len > 0)
            return validate_ntp(payload, payload_len, l7);
    }

    /* HTTP: TCP ports 80, 8080 (not 443 -- TLS encrypted) */
    if (l7->http_enabled && features->protocol == IPPROTO_TCP &&
        (features->dst_port == 80 || features->dst_port == 8080)) {
        uint16_t payload_len = 0;
        const uint8_t *payload = get_l7_payload(m, features, &payload_len);
        if (payload && payload_len > 0)
            return validate_http(payload, payload_len, features, l7);
    }

    return L7_VALIDATE_OK;
}
