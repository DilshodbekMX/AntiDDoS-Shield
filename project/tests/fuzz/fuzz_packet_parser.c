/**
 * @file fuzz_packet_parser.c
 * @brief Fuzz testing for packet parser using libFuzzer
 *
 * Compile with:
 *   clang -fsanitize=fuzzer,address -g -o fuzz_packet_parser fuzz_packet_parser.c \
 *     -I../../ -L../../builddir -llayer1 -ldpdk -lm
 *
 * Run with:
 *   ./fuzz_packet_parser corpus/ -max_len=2048 -jobs=4
 *
 * The fuzzer will test the packet parser with randomly mutated inputs,
 * looking for crashes, memory errors, and undefined behavior.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* Minimal mbuf simulation for fuzzing without full DPDK */
#ifndef RTE_MBUF_FUZZ_SHIM
#define RTE_MBUF_FUZZ_SHIM

struct rte_mbuf {
    char *buf_addr;
    uint16_t data_off;
    uint16_t data_len;
    uint32_t pkt_len;
    uint16_t buf_len;
    uint8_t nb_segs;
    /* Simplified for fuzzing */
};

static inline char *rte_pktmbuf_mtod(struct rte_mbuf *m, void *t) {
    (void)t;
    return m->buf_addr + m->data_off;
}

static inline uint16_t rte_pktmbuf_data_len(struct rte_mbuf *m) {
    return m->data_len;
}

#endif /* RTE_MBUF_FUZZ_SHIM */

/* Include packet features from types.h */
#include "../../common/types.h"

/* ==================== Simplified Parser for Fuzzing ==================== */

/* We replicate core parsing logic here for standalone fuzzing
 * without full DPDK dependency */

#define PARSE_OK            0
#define PARSE_NOT_IP       -1
#define PARSE_MALFORMED    -2
#define PARSE_UNSUPPORTED  -3
#define PARSE_IPV6          1

#define VALIDATE_OK                     0
#define VALIDATE_ERR_TOO_SHORT          1
#define VALIDATE_ERR_BAD_IPLEN          2
#define VALIDATE_ERR_BAD_CHECKSUM       3
#define VALIDATE_ERR_ZERO_TTL           4
#define VALIDATE_ERR_INVALID_SRC        5
#define VALIDATE_ERR_INVALID_DST        6
#define VALIDATE_ERR_FRAG_ATTACK        7
#define VALIDATE_ERR_LAND_ATTACK        8
#define VALIDATE_ERR_TCP_NULL           9
#define VALIDATE_ERR_TCP_XMAS           10
#define VALIDATE_ERR_TCP_INVALID        11
#define VALIDATE_ERR_TCP_SHORT          12
#define VALIDATE_ERR_UDP_SHORT          13

/* Ethernet header (14 bytes) */
struct eth_hdr {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} __attribute__((packed));

/* IPv4 header (variable length, minimum 20 bytes) */
struct ipv4_hdr {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed));

/* IPv6 header (40 bytes fixed) */
struct ipv6_hdr {
    uint32_t vtc_flow;       /* Version, traffic class, flow label */
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
} __attribute__((packed));

/* TCP header (variable length, minimum 20 bytes) */
struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;    /* Upper 4 bits */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed));

/* UDP header (8 bytes) */
struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

/* TCP flags */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

/* Simplified packet features for fuzzing */
struct fuzz_packet_features {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  tcp_flags;
    uint8_t  ip_version;
    uint8_t  ttl;
    uint16_t total_len;
    uint16_t ip_id;
    uint16_t frag_offset;
    bool     is_fragment;
    bool     more_fragments;
    uint8_t  ip_header_len;
    uint8_t  tcp_header_len;
    uint8_t  src_ip6[16];
    uint8_t  dst_ip6[16];
};

static inline uint16_t ntohs_safe(uint16_t n) {
    return ((n & 0xFF) << 8) | ((n >> 8) & 0xFF);
}

static inline uint32_t ntohl_safe(uint32_t n) {
    return ((n & 0xFF) << 24) |
           ((n & 0xFF00) << 8) |
           ((n >> 8) & 0xFF00) |
           ((n >> 24) & 0xFF);
}

/**
 * Parse packet - core fuzzing target
 */
static int fuzz_parse_packet(const uint8_t *data, size_t len,
                             struct fuzz_packet_features *features) {
    memset(features, 0, sizeof(*features));

    /* Check minimum Ethernet header */
    if (len < 14) {
        return PARSE_MALFORMED;
    }

    const struct eth_hdr *eth = (const struct eth_hdr *)data;
    uint16_t ethertype = ntohs_safe(eth->ethertype);

    /* Handle VLAN tag */
    size_t ip_offset = 14;
    if (ethertype == 0x8100) {  /* 802.1Q VLAN */
        if (len < 18) {
            return PARSE_MALFORMED;
        }
        ethertype = ntohs_safe(*(uint16_t *)(data + 16));
        ip_offset = 18;
    }

    /* Double VLAN (QinQ) */
    if (ethertype == 0x8100 || ethertype == 0x88A8) {
        if (len < ip_offset + 4) {
            return PARSE_MALFORMED;
        }
        ethertype = ntohs_safe(*(uint16_t *)(data + ip_offset + 2));
        ip_offset += 4;
    }

    /* Parse based on ethertype */
    if (ethertype == 0x0800) {  /* IPv4 */
        return fuzz_parse_ipv4(data + ip_offset, len - ip_offset, features);
    } else if (ethertype == 0x86DD) {  /* IPv6 */
        return fuzz_parse_ipv6(data + ip_offset, len - ip_offset, features);
    } else {
        return PARSE_NOT_IP;
    }
}

/**
 * Parse IPv4 packet
 */
static int fuzz_parse_ipv4(const uint8_t *data, size_t len,
                           struct fuzz_packet_features *features) {
    /* Minimum IPv4 header is 20 bytes */
    if (len < 20) {
        return PARSE_MALFORMED;
    }

    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)data;

    /* Version must be 4 */
    uint8_t version = (ip->version_ihl >> 4) & 0x0F;
    if (version != 4) {
        return PARSE_MALFORMED;
    }

    /* Header length (in 32-bit words) */
    uint8_t ihl = ip->version_ihl & 0x0F;
    if (ihl < 5) {
        return PARSE_MALFORMED;
    }
    size_t ip_header_len = ihl * 4;

    if (len < ip_header_len) {
        return PARSE_MALFORMED;
    }

    /* Total length check */
    uint16_t total_len = ntohs_safe(ip->total_length);
    if (total_len < ip_header_len || total_len > len) {
        /* Allow truncated captures but flag it */
        if (total_len < ip_header_len) {
            return PARSE_MALFORMED;
        }
    }

    /* Extract features */
    features->ip_version = 4;
    features->src_ip = ip->src_ip;
    features->dst_ip = ip->dst_ip;
    features->protocol = ip->protocol;
    features->ttl = ip->ttl;
    features->total_len = total_len;
    features->ip_id = ntohs_safe(ip->identification);
    features->ip_header_len = ip_header_len;

    /* Fragment handling */
    uint16_t flags_frag = ntohs_safe(ip->flags_fragment);
    features->frag_offset = (flags_frag & 0x1FFF) * 8;
    features->more_fragments = (flags_frag & 0x2000) != 0;
    features->is_fragment = features->frag_offset > 0 || features->more_fragments;

    /* Parse transport layer for non-fragments */
    if (!features->is_fragment || features->frag_offset == 0) {
        size_t transport_offset = ip_header_len;
        size_t transport_len = len - transport_offset;

        if (features->protocol == 6) {  /* TCP */
            return fuzz_parse_tcp(data + transport_offset, transport_len, features);
        } else if (features->protocol == 17) {  /* UDP */
            return fuzz_parse_udp(data + transport_offset, transport_len, features);
        }
    }

    return PARSE_OK;
}

/**
 * Parse IPv6 packet
 */
static int fuzz_parse_ipv6(const uint8_t *data, size_t len,
                           struct fuzz_packet_features *features) {
    /* Fixed IPv6 header is 40 bytes */
    if (len < 40) {
        return PARSE_MALFORMED;
    }

    const struct ipv6_hdr *ip6 = (const struct ipv6_hdr *)data;

    /* Version must be 6 */
    uint8_t version = (ntohl_safe(ip6->vtc_flow) >> 28) & 0x0F;
    if (version != 6) {
        return PARSE_MALFORMED;
    }

    features->ip_version = 6;
    memcpy(features->src_ip6, ip6->src_ip, 16);
    memcpy(features->dst_ip6, ip6->dst_ip, 16);
    features->ttl = ip6->hop_limit;

    /* Walk extension headers */
    uint8_t next_header = ip6->next_header;
    size_t offset = 40;
    int ext_count = 0;
    const int max_extensions = 10;

    while (ext_count < max_extensions) {
        if (next_header == 6 || next_header == 17 ||
            next_header == 58 || next_header == 59) {
            /* TCP, UDP, ICMPv6, or No Next Header */
            break;
        }

        /* Extension header */
        if (offset + 2 > len) {
            return PARSE_MALFORMED;
        }

        uint8_t ext_next = data[offset];
        uint8_t ext_len = data[offset + 1];

        /* Fragment header is 8 bytes fixed */
        if (next_header == 44) {
            if (offset + 8 > len) {
                return PARSE_MALFORMED;
            }
            offset += 8;
        } else {
            /* Other extension headers: length is (ext_len + 1) * 8 */
            size_t hdr_len = (ext_len + 1) * 8;
            if (offset + hdr_len > len) {
                return PARSE_MALFORMED;
            }
            offset += hdr_len;
        }

        next_header = ext_next;
        ext_count++;
    }

    if (ext_count >= max_extensions) {
        /* Too many extension headers - potential loop */
        return PARSE_MALFORMED;
    }

    features->protocol = next_header;

    /* Parse transport */
    if (next_header == 6) {  /* TCP */
        return fuzz_parse_tcp(data + offset, len - offset, features);
    } else if (next_header == 17) {  /* UDP */
        return fuzz_parse_udp(data + offset, len - offset, features);
    }

    return PARSE_IPV6;
}

/**
 * Parse TCP header
 */
static int fuzz_parse_tcp(const uint8_t *data, size_t len,
                          struct fuzz_packet_features *features) {
    if (len < 20) {
        return PARSE_MALFORMED;
    }

    const struct tcp_hdr *tcp = (const struct tcp_hdr *)data;

    /* Data offset (header length in 32-bit words) */
    uint8_t data_off = (tcp->data_offset >> 4) & 0x0F;
    if (data_off < 5) {
        return PARSE_MALFORMED;
    }
    size_t tcp_header_len = data_off * 4;

    if (tcp_header_len > len) {
        return PARSE_MALFORMED;
    }

    features->src_port = ntohs_safe(tcp->src_port);
    features->dst_port = ntohs_safe(tcp->dst_port);
    features->tcp_flags = tcp->flags;
    features->tcp_header_len = tcp_header_len;

    return PARSE_OK;
}

/**
 * Parse UDP header
 */
static int fuzz_parse_udp(const uint8_t *data, size_t len,
                          struct fuzz_packet_features *features) {
    if (len < 8) {
        return PARSE_MALFORMED;
    }

    const struct udp_hdr *udp = (const struct udp_hdr *)data;

    features->src_port = ntohs_safe(udp->src_port);
    features->dst_port = ntohs_safe(udp->dst_port);

    /* Check UDP length field */
    uint16_t udp_len = ntohs_safe(udp->length);
    if (udp_len < 8) {
        return PARSE_MALFORMED;
    }

    return PARSE_OK;
}

/**
 * Validate parsed packet
 */
static int fuzz_validate_packet(const struct fuzz_packet_features *features) {
    /* TTL check */
    if (features->ttl == 0) {
        return VALIDATE_ERR_ZERO_TTL;
    }

    /* IPv4-specific validations */
    if (features->ip_version == 4) {
        /* Invalid source: multicast or broadcast */
        uint32_t src = ntohl_safe(features->src_ip);
        if ((src & 0xF0000000) == 0xE0000000) {  /* Multicast */
            return VALIDATE_ERR_INVALID_SRC;
        }
        if (src == 0xFFFFFFFF) {  /* Broadcast */
            return VALIDATE_ERR_INVALID_SRC;
        }

        /* LAND attack: src == dst */
        if (features->src_ip == features->dst_ip) {
            return VALIDATE_ERR_LAND_ATTACK;
        }

        /* Fragment attack: small fragments */
        if (features->is_fragment && features->frag_offset > 0) {
            if (features->total_len < 20 + 8) {
                return VALIDATE_ERR_FRAG_ATTACK;
            }
        }
    }

    /* TCP validations */
    if (features->protocol == 6) {
        /* NULL scan: no flags set */
        if (features->tcp_flags == 0) {
            return VALIDATE_ERR_TCP_NULL;
        }

        /* XMAS scan: FIN+PSH+URG */
        if ((features->tcp_flags & (TCP_FIN | TCP_PSH | TCP_URG)) ==
            (TCP_FIN | TCP_PSH | TCP_URG)) {
            return VALIDATE_ERR_TCP_XMAS;
        }

        /* Invalid flag combinations */
        if ((features->tcp_flags & TCP_SYN) && (features->tcp_flags & TCP_FIN)) {
            return VALIDATE_ERR_TCP_INVALID;
        }
        if ((features->tcp_flags & TCP_SYN) && (features->tcp_flags & TCP_RST)) {
            return VALIDATE_ERR_TCP_INVALID;
        }
    }

    return VALIDATE_OK;
}

/* ==================== libFuzzer Entry Point ==================== */

/**
 * libFuzzer entry point
 *
 * Receives arbitrary byte data and tests the packet parser with it.
 * Returns 0 normally, crashes will be caught by libFuzzer.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Limit maximum size to reasonable packet length */
    if (size > 65535) {
        return 0;
    }

    struct fuzz_packet_features features;

    /* Test parsing */
    int parse_result = fuzz_parse_packet(data, size, &features);

    /* If parsing succeeded, test validation */
    if (parse_result == PARSE_OK || parse_result == PARSE_IPV6) {
        int validate_result = fuzz_validate_packet(&features);
        (void)validate_result;  /* Suppress unused warning */
    }

    return 0;
}

/* ==================== Optional: Standalone Test ==================== */

#ifdef FUZZ_STANDALONE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    uint8_t *data = malloc(st.st_size);
    if (!data) {
        perror("malloc");
        close(fd);
        return 1;
    }

    ssize_t n = read(fd, data, st.st_size);
    close(fd);

    if (n != st.st_size) {
        perror("read");
        free(data);
        return 1;
    }

    printf("Testing %s (%zu bytes)\n", argv[1], (size_t)n);
    int result = LLVMFuzzerTestOneInput(data, n);
    printf("Result: %d\n", result);

    free(data);
    return 0;
}
#endif
