/**
 * @file test_packet_parser.c
 * @brief Unit tests for Layer 1 packet parsing and validation
 *
 * Tests cover:
 * - IPv4 packet parsing
 * - TCP/UDP header extraction
 * - Validation error detection (malformed packets, attacks)
 * - Flow key generation (3-tuple canonical ordering)
 * - Flow hash: the CRC32-C of the canonical key (IPv4 and IPv6), per protocol,
 *   and the same in another process
 * - Checksum validation
 *
 * Build: Link with layer1 library and DPDK
 * Run:   ./test_packet_parser
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "../../layer1/datapath/packet_parser.h"
#include "../../common/types.h"

// ==================== Test Framework ====================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(expr, msg) do { \
    if (!(expr)) { \
        printf("  FAIL: %s\n", msg); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_EQ(expected, actual, msg) do { \
    if ((expected) != (actual)) { \
        printf("  FAIL: %s (expected=%lu, actual=%lu)\n", msg, \
               (unsigned long)(expected), (unsigned long)(actual)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define RUN_TEST(test_func) do { \
    printf("Running %s...\n", #test_func); \
    tests_run++; \
    test_func(); \
    if (tests_run - tests_failed - tests_passed == 1) { \
        tests_passed++; \
        printf("  PASS\n"); \
    } \
} while(0)

// ==================== Test Mempool ====================

static struct rte_mempool *test_pool = NULL;

static int setup_mempool(void) {
    test_pool = rte_pktmbuf_pool_create(
        "test_pool",
        1024,
        256,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id()
    );
    return test_pool ? 0 : -1;
}

static void cleanup_mempool(void) {
    if (test_pool) {
        rte_mempool_free(test_pool);
        test_pool = NULL;
    }
}

// ==================== Packet Builder Helpers ====================

static struct rte_mbuf *create_valid_tcp_packet(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    uint8_t tcp_flags
) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(test_pool);
    if (!m) return NULL;

    size_t pkt_len = sizeof(struct rte_ether_hdr) +
                     sizeof(struct rte_ipv4_hdr) +
                     sizeof(struct rte_tcp_hdr);

    char *data = rte_pktmbuf_append(m, pkt_len);
    if (!data) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memset(data, 0, pkt_len);

    // Ethernet header
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // IP header
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->src_addr = rte_cpu_to_be_32(src_ip);
    ip->dst_addr = rte_cpu_to_be_32(dst_ip);
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // TCP header
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(src_port);
    tcp->dst_port = rte_cpu_to_be_16(dst_port);
    tcp->data_off = 0x50;
    tcp->tcp_flags = tcp_flags;
    tcp->rx_win = rte_cpu_to_be_16(65535);

    return m;
}

static struct rte_mbuf *create_valid_udp_packet(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    size_t payload_len
) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(test_pool);
    if (!m) return NULL;

    size_t pkt_len = sizeof(struct rte_ether_hdr) +
                     sizeof(struct rte_ipv4_hdr) +
                     sizeof(struct rte_udp_hdr) +
                     payload_len;

    char *data = rte_pktmbuf_append(m, pkt_len);
    if (!data) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memset(data, 0, pkt_len);

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + payload_len);
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = rte_cpu_to_be_32(src_ip);
    ip->dst_addr = rte_cpu_to_be_32(dst_ip);
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
    udp->src_port = rte_cpu_to_be_16(src_port);
    udp->dst_port = rte_cpu_to_be_16(dst_port);
    udp->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + payload_len);
    udp->dgram_cksum = 0;

    return m;
}

// ==================== Tests ====================

void test_parse_valid_tcp_syn(void) {
    struct rte_mbuf *m = create_valid_tcp_packet(
        0x0A000001,  // 10.0.0.1
        0xC0A80101,  // 192.168.1.1
        12345,
        80,
        RTE_TCP_SYN_FLAG
    );
    TEST_ASSERT(m != NULL, "Failed to create packet");

    struct packet_features features;
    int result = parse_packet(m, &features);

    TEST_ASSERT_EQ(PARSE_OK, result, "Parse should succeed");
    TEST_ASSERT_EQ(IPPROTO_TCP, features.protocol, "Protocol should be TCP");
    TEST_ASSERT_EQ(rte_cpu_to_be_32(0x0A000001), features.src_ip, "Source IP mismatch");
    TEST_ASSERT_EQ(rte_cpu_to_be_32(0xC0A80101), features.dst_ip, "Dest IP mismatch");
    TEST_ASSERT_EQ(12345, features.src_port, "Source port mismatch");
    TEST_ASSERT_EQ(80, features.dst_port, "Dest port mismatch");
    TEST_ASSERT(features.tcp_flags & RTE_TCP_SYN_FLAG, "SYN flag should be set");
    TEST_ASSERT(!(features.tcp_flags & RTE_TCP_ACK_FLAG), "ACK flag should not be set");

    rte_pktmbuf_free(m);
}

void test_parse_valid_tcp_ack(void) {
    struct rte_mbuf *m = create_valid_tcp_packet(
        0x0A000001,
        0xC0A80101,
        12345,
        80,
        RTE_TCP_ACK_FLAG
    );
    TEST_ASSERT(m != NULL, "Failed to create packet");

    struct packet_features features;
    int result = parse_packet(m, &features);

    TEST_ASSERT_EQ(PARSE_OK, result, "Parse should succeed");
    TEST_ASSERT(!(features.tcp_flags & RTE_TCP_SYN_FLAG), "SYN flag should not be set");
    TEST_ASSERT(features.tcp_flags & RTE_TCP_ACK_FLAG, "ACK flag should be set");

    rte_pktmbuf_free(m);
}

void test_parse_valid_udp(void) {
    struct rte_mbuf *m = create_valid_udp_packet(
        0x0A000001,
        0xC0A80101,
        54321,
        53,
        64
    );
    TEST_ASSERT(m != NULL, "Failed to create packet");

    struct packet_features features;
    int result = parse_packet(m, &features);

    TEST_ASSERT_EQ(PARSE_OK, result, "Parse should succeed");
    TEST_ASSERT_EQ(IPPROTO_UDP, features.protocol, "Protocol should be UDP");
    TEST_ASSERT_EQ(54321, features.src_port, "Source port mismatch");
    TEST_ASSERT_EQ(53, features.dst_port, "Dest port mismatch");

    rte_pktmbuf_free(m);
}

void test_parse_non_ip_packet(void) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(test_pool);
    TEST_ASSERT(m != NULL, "Failed to allocate mbuf");

    size_t pkt_len = sizeof(struct rte_ether_hdr) + 64;
    char *data = rte_pktmbuf_append(m, pkt_len);
    TEST_ASSERT(data != NULL, "Failed to append data");
    memset(data, 0, pkt_len);

    // Set to ARP (non-IPv4)
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    struct packet_features features;
    int result = parse_packet(m, &features);

    TEST_ASSERT_EQ(PARSE_NOT_IP, result, "Non-IP packet should return PARSE_NOT_IP");

    rte_pktmbuf_free(m);
}

void test_canonical_flow_key_ordering(void) {
    // Test that flow key is canonical regardless of direction
    struct packet_features features1;
    memset(&features1, 0, sizeof(features1));
    features1.src_ip = rte_cpu_to_be_32(0x0A000001);  // 10.0.0.1 (lower)
    features1.dst_ip = rte_cpu_to_be_32(0xC0A80101);  // 192.168.1.1 (higher)
    features1.protocol = IPPROTO_TCP;

    struct flow_key key1;
    extract_flow_key(&features1, &key1);

    struct packet_features features2;
    memset(&features2, 0, sizeof(features2));
    features2.src_ip = rte_cpu_to_be_32(0xC0A80101);  // 192.168.1.1 (higher)
    features2.dst_ip = rte_cpu_to_be_32(0x0A000001);  // 10.0.0.1 (lower)
    features2.protocol = IPPROTO_TCP;

    struct flow_key key2;
    extract_flow_key(&features2, &key2);

    // Both keys should be identical (canonical ordering)
    TEST_ASSERT_EQ(key1.ip_lo, key2.ip_lo, "ip_lo should match");
    TEST_ASSERT_EQ(key1.ip_hi, key2.ip_hi, "ip_hi should match");
    TEST_ASSERT_EQ(key1.protocol, key2.protocol, "protocol should match");

    // Direction should be different
    TEST_ASSERT_EQ(FLOW_DIR_LO_TO_HI, features1.flow_direction, "features1 should be LO_TO_HI");
    TEST_ASSERT_EQ(FLOW_DIR_HI_TO_LO, features2.flow_direction, "features2 should be HI_TO_LO");
}

void test_validate_tcp_null_attack(void) {
    struct rte_mbuf *m = create_valid_tcp_packet(
        0x0A000001,
        0xC0A80101,
        12345,
        80,
        0  // No flags set = NULL attack
    );
    TEST_ASSERT(m != NULL, "Failed to create packet");

    struct packet_features features;
    int result = parse_packet(m, &features);
    TEST_ASSERT_EQ(PARSE_OK, result, "Parse should succeed");

    int validation = validate_packet(&features);
    TEST_ASSERT_EQ(VALIDATE_ERR_TCP_NULL, validation, "Should detect TCP NULL attack");

    rte_pktmbuf_free(m);
}

void test_validate_tcp_xmas_attack(void) {
    struct rte_mbuf *m = create_valid_tcp_packet(
        0x0A000001,
        0xC0A80101,
        12345,
        80,
        RTE_TCP_FIN_FLAG | RTE_TCP_URG_FLAG | RTE_TCP_PSH_FLAG  // XMAS tree
    );
    TEST_ASSERT(m != NULL, "Failed to create packet");

    struct packet_features features;
    int result = parse_packet(m, &features);
    TEST_ASSERT_EQ(PARSE_OK, result, "Parse should succeed");

    int validation = validate_packet(&features);
    TEST_ASSERT_EQ(VALIDATE_ERR_TCP_XMAS, validation, "Should detect TCP XMAS attack");

    rte_pktmbuf_free(m);
}

void test_validate_land_attack(void) {
    // LAND attack: src_ip == dst_ip
    struct rte_mbuf *m = create_valid_tcp_packet(
        0xC0A80101,  // Same IP
        0xC0A80101,  // Same IP
        80,
        80,
        RTE_TCP_SYN_FLAG
    );
    TEST_ASSERT(m != NULL, "Failed to create packet");

    struct packet_features features;
    int result = parse_packet(m, &features);
    TEST_ASSERT_EQ(PARSE_OK, result, "Parse should succeed");

    int validation = validate_packet(&features);
    TEST_ASSERT_EQ(VALIDATE_ERR_LAND_ATTACK, validation, "Should detect LAND attack");

    rte_pktmbuf_free(m);
}

void test_ip_checksum_validation(void) {
    struct rte_mbuf *m = create_valid_tcp_packet(
        0x0A000001,
        0xC0A80101,
        12345,
        80,
        RTE_TCP_SYN_FLAG
    );
    TEST_ASSERT(m != NULL, "Failed to create packet");

    // Valid packet should pass checksum
    int result = validate_ip_checksum(m);
    TEST_ASSERT_EQ(VALIDATE_OK, result, "Valid checksum should pass");

    // Corrupt the checksum
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->hdr_checksum = 0xDEAD;  // Wrong checksum

    result = validate_ip_checksum(m);
    TEST_ASSERT_EQ(VALIDATE_ERR_BAD_CHECKSUM, result, "Bad checksum should fail");

    rte_pktmbuf_free(m);
}

void test_flow_hash_consistency(void) {
    // Same flow key should always produce same hash
    struct flow_key key;
    key.ip_lo = rte_cpu_to_be_32(0x0A000001);
    key.ip_hi = rte_cpu_to_be_32(0xC0A80101);
    key.protocol = IPPROTO_TCP;
    key._pad[0] = key._pad[1] = key._pad[2] = 0;

    uint32_t hash1 = compute_flow_hash(&key);
    uint32_t hash2 = compute_flow_hash(&key);
    uint32_t hash3 = compute_flow_hash(&key);

    TEST_ASSERT_EQ(hash1, hash2, "Hash should be consistent");
    TEST_ASSERT_EQ(hash2, hash3, "Hash should be consistent");
}

// ==================== Flow Hash: Canonical Key ====================
//
// features.flow_hash is the CRC32-C (seed 0) of the canonical flow key: ip_lo,
// ip_hi (ordered as extract_flow_key() and extract_flow_key_v6() order them),
// the protocol and 3 zero bytes, 12 bytes for IPv4 and 36 for IPv6. That is
// the value rte_hash_crc(key, sizeof(key), 0) is meant to return. The
// subtests below compare it with a bitwise CRC32-C of that key, built byte by
// byte here.
//
// The defect they pin: with the key on the stack and rte_hash_crc() inlined,
// gcc -O2/-O3 dropped the protocol and padding stores under strict aliasing
// (rte_hash_crc() reads the key through uint64_t and uint32_t pointers), so
// the hash folded in 4 stale stack bytes. TCP and UDP between two hosts then
// shared a hash, and the value depended on the stack, so it changed between
// processes. parse_packet() returns PARSE_IPV6 before it hashes, so the IPv6
// key is checked through parse_packet_v6().

#define FRAME_BUF_LEN 256
#define FLOW_HASH_CHILD_ARG "--flow-hash-child"

static uint8_t *g_frame;      // aligned_alloc'd, so the header stores set its type
static char *g_argv0;

// CRC32-C (reflected polynomial 0x82F63B78) bit by bit, with no initial or
// final inversion: what rte_hash_crc() computes, without DPDK's code
static uint32_t ref_crc32c(const uint8_t *p, size_t len, uint32_t crc) {
    for (size_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0x82F63B78u & (0u - (crc & 1u)));
        }
    }
    return crc;
}

// Canonical IPv4 key: the lower of the two network-order values first, as
// extract_flow_key() compares them
static uint32_t ref_flow_hash_v4(uint32_t src_be, uint32_t dst_be, uint8_t proto) {
    uint32_t lo = src_be <= dst_be ? src_be : dst_be;
    uint32_t hi = src_be <= dst_be ? dst_be : src_be;
    uint8_t key[12] = { 0 };
    memcpy(key, &lo, 4);
    memcpy(key + 4, &hi, 4);
    key[8] = proto;
    return ref_crc32c(key, sizeof(key), 0);
}

// Canonical IPv6 key: the address that memcmp() orders first, then the other
static uint32_t ref_flow_hash_v6(const uint8_t src[16], const uint8_t dst[16], uint8_t proto) {
    bool src_first = memcmp(src, dst, 16) <= 0;
    uint8_t key[36] = { 0 };
    memcpy(key, src_first ? src : dst, 16);
    memcpy(key + 16, src_first ? dst : src, 16);
    key[32] = proto;
    return ref_crc32c(key, sizeof(key), 0);
}

// The 16 bytes parse_packet_v6() keys an IPv4 address by: the address, then zeros
static void v4_as_v6_key_bytes(uint32_t ip_be, uint8_t out[16]) {
    memset(out, 0, 16);
    memcpy(out, &ip_be, 4);
}

static uint64_t xorshift64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

// 20 L4 bytes: a TCP header, a UDP header and 12 zero bytes, or zeros. TCP and
// UDP use the same ports, so their keys differ only in the protocol.
static void fill_l4(uint8_t *l4, uint8_t proto, uint16_t l4_len) {
    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4;
        tcp->src_port = rte_cpu_to_be_16(40000);
        tcp->dst_port = rte_cpu_to_be_16(443);
        tcp->data_off = 0x50;
        tcp->tcp_flags = RTE_TCP_SYN_FLAG;
        tcp->rx_win = rte_cpu_to_be_16(65535);
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4;
        udp->src_port = rte_cpu_to_be_16(40000);
        udp->dst_port = rte_cpu_to_be_16(443);
        udp->dgram_len = rte_cpu_to_be_16(l4_len);
    }
}

// Ethernet, IPv4 without options, 20 L4 bytes; returns the frame length
static uint16_t build_frame_v4(uint8_t *frame, uint32_t src_be, uint32_t dst_be, uint8_t proto) {
    const uint16_t l4_len = sizeof(struct rte_tcp_hdr);
    const uint16_t len = (uint16_t)(sizeof(struct rte_ether_hdr) +
                                    sizeof(struct rte_ipv4_hdr) + l4_len);
    memset(frame, 0, len);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)frame;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->total_length = rte_cpu_to_be_16((uint16_t)(sizeof(struct rte_ipv4_hdr) + l4_len));
    ip->time_to_live = 64;
    ip->next_proto_id = proto;
    ip->src_addr = src_be;
    ip->dst_addr = dst_be;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    fill_l4((uint8_t *)(ip + 1), proto, l4_len);
    return len;
}

// Ethernet, IPv6 without extension headers, 20 L4 bytes
static uint16_t build_frame_v6(uint8_t *frame, const uint8_t src[16], const uint8_t dst[16],
                               uint8_t proto) {
    const uint16_t l4_len = sizeof(struct rte_tcp_hdr);
    const uint16_t len = (uint16_t)(sizeof(struct rte_ether_hdr) +
                                    sizeof(struct rte_ipv6_hdr) + l4_len);
    memset(frame, 0, len);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)frame;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(eth + 1);
    ip6->vtc_flow = rte_cpu_to_be_32(6u << 28);
    ip6->payload_len = rte_cpu_to_be_16(l4_len);
    ip6->proto = proto;
    ip6->hop_limits = 64;
    memcpy(&ip6->src_addr, src, 16);
    memcpy(&ip6->dst_addr, dst, 16);
    fill_l4((uint8_t *)(ip6 + 1), proto, l4_len);
    return len;
}

static struct rte_mbuf *mbuf_from_frame(const uint8_t *frame, uint16_t len) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(test_pool);
    if (!m) return NULL;
    char *data = rte_pktmbuf_append(m, len);
    if (!data) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memcpy(data, frame, len);
    return m;
}

// An mbuf header around a frame buffer, for the child process, which runs
// without EAL: the parsers read only buf_addr, data_off, pkt_len and data_len
static void fake_mbuf_wrap(struct rte_mbuf *m, uint8_t *frame, uint16_t len) {
    memset(m, 0, sizeof(*m));
    m->buf_addr = frame;
    m->buf_len = FRAME_BUF_LEN;
    m->data_off = 0;
    m->nb_segs = 1;
    m->pkt_len = len;
    m->data_len = len;
}

// Fill 16 KB of stack below the caller with 0xA5. Called just before one of
// the *_inlined functions, whose frame then starts at the same place, it
// makes most key bytes that nothing wrote read as 0xA5 rather than as
// whatever an earlier call left there (possibly the right bytes). It cannot
// fill the top few words of that area, which hold its own return address,
// canary and padding; a key slot placed there (the IPv4 wrappers' protocol
// and padding word, with gcc 11) keeps older bytes. So the poison makes a
// stale read less likely to be right by chance; it does not rule that out.
static __attribute__((noinline)) void poison_stack(void) {
    volatile uint8_t buf[16384];
    for (size_t i = 0; i < sizeof(buf); i++) {
        buf[i] = 0xA5;
    }
}

// The *_inlined functions run a parser, or a key helper and the hash, with
// everything they call inlined into one frame (flatten), as l2fwd inlines
// parse_packet() and compute_flow_hash() into layer1_process_packet_ex().
// This binary's own call graph would not: compute_flow_hash() has other
// callers here, so link-time inlining keeps it out of line, and a real call
// with the key's address keeps the key stores the miscompile drops.
static __attribute__((noinline, flatten)) int parse_v4_inlined(struct rte_mbuf *m,
                                                               uint32_t *flow_hash) {
    struct packet_features f;
    int rc = parse_packet(m, &f);
    *flow_hash = f.flow_hash;
    return rc;
}

static __attribute__((noinline, flatten)) int parse_v6_inlined(struct rte_mbuf *m,
                                                               uint32_t *flow_hash) {
    struct packet_features_v6 f;
    int rc = parse_packet_v6(m, &f);
    *flow_hash = f.flow_hash;
    return rc;
}

// Build the frame, wrap it in a pool mbuf, poison the stack, parse
static int parsed_hash_v4(uint32_t src_be, uint32_t dst_be, uint8_t proto, uint32_t *flow_hash) {
    struct rte_mbuf *m = mbuf_from_frame(g_frame, build_frame_v4(g_frame, src_be, dst_be, proto));
    if (!m) return -100;
    poison_stack();
    int rc = parse_v4_inlined(m, flow_hash);
    rte_pktmbuf_free(m);
    return rc;
}

static int parsed_hash_v6(const uint8_t *frame, uint16_t len, uint32_t *flow_hash) {
    struct rte_mbuf *m = mbuf_from_frame(frame, len);
    if (!m) return -100;
    poison_stack();
    int rc = parse_v6_inlined(m, flow_hash);
    rte_pktmbuf_free(m);
    return rc;
}

static void random_ipv6(uint64_t *seed, uint8_t out[16]) {
    uint64_t hi = xorshift64(seed), lo = xorshift64(seed);
    memcpy(out, &hi, 8);
    memcpy(out + 8, &lo, 8);
}

#define FH_PAIRS 1000

// parse_packet(): TCP, UDP and ICMP, both directions of each host pair
void test_flow_hash_canonical_crc_v4(void) {
    // The reference: CRC-32C of "123456789" with the usual inversions is 0xE3069283
    TEST_ASSERT_EQ(0xE3069283u,
                   ref_crc32c((const uint8_t *)"123456789", 9, 0xFFFFFFFFu) ^ 0xFFFFFFFFu,
                   "reference CRC32-C check value");

    static const uint8_t protos[] = { IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP };
    uint64_t seed = 0x9E3779B97F4A7C15ULL;
    uint32_t checked = 0, wrong = 0, bad_rc = 0;
    for (uint32_t i = 0; i < FH_PAIRS; i++) {
        uint32_t a = (uint32_t)xorshift64(&seed);
        uint32_t b = (uint32_t)xorshift64(&seed);
        if (a == b) b ^= 1;
        for (size_t p = 0; p < RTE_DIM(protos); p++) {
            for (int dir = 0; dir < 2; dir++) {
                uint32_t src = dir ? b : a, dst = dir ? a : b;
                uint32_t fh = 0;
                if (parsed_hash_v4(src, dst, protos[p], &fh) != PARSE_OK) {
                    bad_rc++;
                    continue;
                }
                uint32_t want = ref_flow_hash_v4(src, dst, protos[p]);
                checked++;
                if (fh != want && wrong++ < 3) {
                    printf("    %08x -> %08x proto %u: flow_hash %08x, canonical CRC %08x\n",
                           rte_be_to_cpu_32(src), rte_be_to_cpu_32(dst), protos[p], fh, want);
                }
            }
        }
    }
    printf("    %u IPv4 parses, %u flow hashes differ from the canonical CRC\n", checked, wrong);
    TEST_ASSERT_EQ(0, bad_rc, "every IPv4 frame parses with PARSE_OK");
    TEST_ASSERT_EQ(0, wrong, "parse_packet() flow_hash is the CRC32-C of the canonical key");
}

// parse_packet(): the protocol is part of the key, so TCP, UDP and ICMP
// between the same two hosts never share a flow hash
void test_flow_hash_tcp_udp_differ_v4(void) {
    uint64_t seed = 0xD1B54A32D192ED03ULL;
    uint32_t shared = 0, bad_rc = 0;
    for (uint32_t i = 0; i < FH_PAIRS; i++) {
        uint32_t a = (uint32_t)xorshift64(&seed);
        uint32_t b = (uint32_t)xorshift64(&seed);
        if (a == b) b ^= 1;
        uint32_t tcp = 0, udp = 0, icmp = 0;
        if (parsed_hash_v4(a, b, IPPROTO_TCP, &tcp) != PARSE_OK ||
            parsed_hash_v4(a, b, IPPROTO_UDP, &udp) != PARSE_OK ||
            parsed_hash_v4(a, b, IPPROTO_ICMP, &icmp) != PARSE_OK) {
            bad_rc++;
            continue;
        }
        if (tcp == udp || tcp == icmp || udp == icmp) {
            if (shared++ < 3) {
                printf("    %08x -> %08x: TCP %08x, UDP %08x, ICMP %08x\n",
                       rte_be_to_cpu_32(a), rte_be_to_cpu_32(b), tcp, udp, icmp);
            }
        }
    }
    printf("    %u of %u host pairs share a flow hash across protocols\n", shared, FH_PAIRS);
    TEST_ASSERT_EQ(0, bad_rc, "every IPv4 frame parses with PARSE_OK");
    TEST_ASSERT_EQ(0, shared, "TCP, UDP and ICMP between two hosts have distinct flow hashes");
}

// parse_packet_v6(): IPv6 TCP, UDP and ICMPv6, and IPv4 TCP and UDP (its IPv4
// path keys the address padded to 16 bytes), both directions
void test_flow_hash_canonical_crc_v6(void) {
    static const uint8_t protos6[] = { IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6 };
    static const uint8_t protos4[] = { IPPROTO_TCP, IPPROTO_UDP };
    uint64_t seed = 0xBF58476D1CE4E5B9ULL;
    uint32_t checked = 0, wrong = 0, bad_rc = 0;
    for (uint32_t i = 0; i < FH_PAIRS; i++) {
        uint8_t a[16], b[16];
        random_ipv6(&seed, a);
        random_ipv6(&seed, b);
        if (memcmp(a, b, 16) == 0) b[15] ^= 1;
        for (size_t p = 0; p < RTE_DIM(protos6); p++) {
            for (int dir = 0; dir < 2; dir++) {
                const uint8_t *src = dir ? b : a, *dst = dir ? a : b;
                uint32_t fh = 0;
                if (parsed_hash_v6(g_frame, build_frame_v6(g_frame, src, dst, protos6[p]),
                                   &fh) != PARSE_IPV6) {
                    bad_rc++;
                    continue;
                }
                uint32_t want = ref_flow_hash_v6(src, dst, protos6[p]);
                checked++;
                if (fh != want && wrong++ < 3) {
                    printf("    IPv6 proto %u: flow_hash %08x, canonical CRC %08x\n",
                           protos6[p], fh, want);
                }
            }
        }
        uint32_t a4 = (uint32_t)xorshift64(&seed);
        uint32_t b4 = (uint32_t)xorshift64(&seed);
        if (a4 == b4) b4 ^= 1;
        for (size_t p = 0; p < RTE_DIM(protos4); p++) {
            for (int dir = 0; dir < 2; dir++) {
                uint32_t src = dir ? b4 : a4, dst = dir ? a4 : b4;
                uint8_t s16[16], d16[16];
                v4_as_v6_key_bytes(src, s16);
                v4_as_v6_key_bytes(dst, d16);
                uint32_t fh = 0;
                if (parsed_hash_v6(g_frame, build_frame_v4(g_frame, src, dst, protos4[p]),
                                   &fh) != PARSE_OK) {
                    bad_rc++;
                    continue;
                }
                uint32_t want = ref_flow_hash_v6(s16, d16, protos4[p]);
                checked++;
                if (fh != want && wrong++ < 3) {
                    printf("    IPv4 in parse_packet_v6, proto %u: flow_hash %08x, canonical CRC %08x\n",
                           protos4[p], fh, want);
                }
            }
        }
    }
    printf("    %u dual-stack parses, %u flow hashes differ from the canonical CRC\n", checked, wrong);
    TEST_ASSERT_EQ(0, bad_rc, "every frame parses (PARSE_IPV6 for IPv6, PARSE_OK for IPv4)");
    TEST_ASSERT_EQ(0, wrong, "parse_packet_v6() flow_hash is the CRC32-C of the canonical key");
}

// parse_packet_v6(): TCP, UDP and ICMPv6 between the same two hosts never
// share a flow hash
void test_flow_hash_tcp_udp_differ_v6(void) {
    uint64_t seed = 0x94D049BB133111EBULL;
    uint32_t shared = 0, bad_rc = 0;
    for (uint32_t i = 0; i < FH_PAIRS; i++) {
        uint8_t a[16], b[16];
        random_ipv6(&seed, a);
        random_ipv6(&seed, b);
        if (memcmp(a, b, 16) == 0) b[15] ^= 1;
        uint32_t tcp = 0, udp = 0, icmp = 0;
        if (parsed_hash_v6(g_frame, build_frame_v6(g_frame, a, b, IPPROTO_TCP), &tcp) != PARSE_IPV6 ||
            parsed_hash_v6(g_frame, build_frame_v6(g_frame, a, b, IPPROTO_UDP), &udp) != PARSE_IPV6 ||
            parsed_hash_v6(g_frame, build_frame_v6(g_frame, a, b, IPPROTO_ICMPV6), &icmp) != PARSE_IPV6) {
            bad_rc++;
            continue;
        }
        if (tcp == udp || tcp == icmp || udp == icmp) {
            if (shared++ < 3) {
                printf("    TCP %08x, UDP %08x, ICMPv6 %08x\n", tcp, udp, icmp);
            }
        }
    }
    printf("    %u of %u IPv6 host pairs share a flow hash across protocols\n", shared, FH_PAIRS);
    TEST_ASSERT_EQ(0, bad_rc, "every IPv6 frame parses with PARSE_IPV6");
    TEST_ASSERT_EQ(0, shared, "TCP, UDP and ICMPv6 between two IPv6 hosts have distinct flow hashes");
}

// A key built on the caller's stack by the header's inline helpers, then
// hashed: the way the HLL test uses compute_flow_hash()
static __attribute__((noinline, flatten)) uint32_t hash_v4_key_inlined(uint32_t src_be,
                                                                       uint32_t dst_be,
                                                                       uint8_t proto,
                                                                       bool via_features) {
    struct flow_key key;
    if (via_features) {
        struct packet_features f;
        memset(&f, 0, sizeof(f));
        f.src_ip = src_be;
        f.dst_ip = dst_be;
        f.protocol = proto;
        extract_flow_key(&f, &key);
    } else {
        make_canonical_key(src_be, dst_be, proto, &key, NULL);
    }
    return compute_flow_hash(&key);
}

static __attribute__((noinline, flatten)) uint32_t hash_v6_key_inlined(const uint8_t src[16],
                                                                       const uint8_t dst[16],
                                                                       uint8_t proto) {
    struct packet_features_v6 f;
    struct flow_key_v6 key;
    memset(&f, 0, sizeof(f));
    memcpy(f.src_ip.v6, src, 16);
    memcpy(f.dst_ip.v6, dst, 16);
    f.protocol = proto;
    extract_flow_key_v6(&f, &key);
    return compute_flow_hash_v6(&key);
}

void test_flow_hash_stack_key(void) {
    uint64_t seed = 0x2545F4914F6CDD1DULL;
    uint32_t wrong4 = 0, wrong6 = 0;
    for (uint32_t i = 0; i < FH_PAIRS; i++) {
        uint32_t a = (uint32_t)xorshift64(&seed);
        uint32_t b = (uint32_t)xorshift64(&seed);
        uint8_t proto = (i & 1) ? IPPROTO_UDP : IPPROTO_TCP;
        uint32_t want4 = ref_flow_hash_v4(a, b, proto);
        poison_stack();
        wrong4 += hash_v4_key_inlined(a, b, proto, true) != want4;
        poison_stack();
        wrong4 += hash_v4_key_inlined(a, b, proto, false) != want4;

        uint8_t a6[16], b6[16];
        random_ipv6(&seed, a6);
        random_ipv6(&seed, b6);
        uint32_t want6 = ref_flow_hash_v6(a6, b6, proto);
        poison_stack();
        wrong6 += hash_v6_key_inlined(a6, b6, proto) != want6;
    }
    printf("    %u of %u IPv4 and %u of %u IPv6 stack keys hash to another value\n",
           wrong4, 2 * FH_PAIRS, wrong6, FH_PAIRS);
    TEST_ASSERT_EQ(0, wrong4, "compute_flow_hash() of a stack key is the CRC32-C of its 12 bytes");
    TEST_ASSERT_EQ(0, wrong6, "compute_flow_hash_v6() of a stack key is the CRC32-C of its 36 bytes");
}

// ---------- The same flow hashes in another process ----------

#define XPROC_V4_PAIRS 32
#define XPROC_V6_PAIRS 16
#define XPROC_HASHES (4 * XPROC_V4_PAIRS + 4 * XPROC_V6_PAIRS)

// Flow hashes of a fixed packet list (TCP and UDP, both directions; IPv4
// through parse_packet(), IPv6 through parse_packet_v6(), both inlined as in
// l2fwd), on an mbuf header that wraps a frame buffer, so it needs no EAL.
// ref[] gets the canonical CRCs. No stack poisoning: this is the stack as the
// process leaves it.
static int flow_hash_list(uint32_t out[XPROC_HASHES], uint32_t ref[XPROC_HASHES]) {
    static struct rte_mbuf m;
    static const uint8_t protos[] = { IPPROTO_TCP, IPPROTO_UDP };
    uint8_t *frame = aligned_alloc(64, FRAME_BUF_LEN);
    if (!frame) return -1;
    uint64_t seed = 0x6A09E667F3BCC909ULL;
    size_t n = 0;
    for (int i = 0; i < XPROC_V4_PAIRS; i++) {
        uint32_t a = (uint32_t)xorshift64(&seed);
        uint32_t b = (uint32_t)xorshift64(&seed);
        if (a == b) b ^= 1;
        for (size_t p = 0; p < RTE_DIM(protos); p++) {
            for (int dir = 0; dir < 2; dir++) {
                uint32_t src = dir ? b : a, dst = dir ? a : b;
                fake_mbuf_wrap(&m, frame, build_frame_v4(frame, src, dst, protos[p]));
                if (parse_v4_inlined(&m, &out[n]) != PARSE_OK) {
                    free(frame);
                    return -1;
                }
                ref[n] = ref_flow_hash_v4(src, dst, protos[p]);
                n++;
            }
        }
    }
    for (int i = 0; i < XPROC_V6_PAIRS; i++) {
        uint8_t a[16], b[16];
        random_ipv6(&seed, a);
        random_ipv6(&seed, b);
        if (memcmp(a, b, 16) == 0) b[15] ^= 1;
        for (size_t p = 0; p < RTE_DIM(protos); p++) {
            for (int dir = 0; dir < 2; dir++) {
                const uint8_t *src = dir ? b : a, *dst = dir ? a : b;
                fake_mbuf_wrap(&m, frame, build_frame_v6(frame, src, dst, protos[p]));
                if (parse_v6_inlined(&m, &out[n]) != PARSE_IPV6) {
                    free(frame);
                    return -1;
                }
                ref[n] = ref_flow_hash_v6(src, dst, protos[p]);
                n++;
            }
        }
    }
    free(frame);
    return n == XPROC_HASHES ? 0 : -1;
}

// Child mode (argv[1] is FLOW_HASH_CHILD_ARG): print the list, one hash per line
static int flow_hash_child_main(void) {
    uint32_t out[XPROC_HASHES], ref[XPROC_HASHES];
    if (flow_hash_list(out, ref) != 0) {
        return 2;
    }
    for (size_t i = 0; i < XPROC_HASHES; i++) {
        printf("%08x\n", out[i]);
    }
    return fflush(stdout) == 0 ? 0 : 3;
}

// Runs this binary again as a new process (its own address space layout and
// stack history) in child mode; returns the number of hashes read, or -1
static int run_flow_hash_child(uint32_t out[XPROC_HASHES]) {
    int fds[2];
    if (pipe(fds) != 0) return -1;
    posix_spawn_file_actions_t fa;
    if (posix_spawn_file_actions_init(&fa) != 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&fa, fds[0]);
    posix_spawn_file_actions_addclose(&fa, fds[1]);
    char *child_argv[] = { g_argv0, FLOW_HASH_CHILD_ARG, NULL };
    pid_t pid;
    int rc = posix_spawn(&pid, "/proc/self/exe", &fa, NULL, child_argv, environ);
    if (rc != 0 && strchr(g_argv0, '/') != NULL) {
        // No /proc: the path this process was started by
        rc = posix_spawn(&pid, g_argv0, &fa, NULL, child_argv, environ);
    }
    posix_spawn_file_actions_destroy(&fa);
    close(fds[1]);
    if (rc != 0) {
        close(fds[0]);
        return -1;
    }
    int n = 0;
    FILE *in = fdopen(fds[0], "r");
    if (in) {
        unsigned int v;
        while (fscanf(in, "%x", &v) == 1) {
            if (n < XPROC_HASHES) out[n] = v;
            n++;
        }
        fclose(in);
    } else {
        close(fds[0]);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return -1;
    }
    return n;
}

void test_flow_hash_stable_across_processes(void) {
    uint32_t mine[XPROC_HASHES], ref[XPROC_HASHES], child[XPROC_HASHES];
    TEST_ASSERT_EQ(0, flow_hash_list(mine, ref), "parse the fixed packet list");
    int n = run_flow_hash_child(child);
    TEST_ASSERT_EQ(XPROC_HASHES, n, "the child process prints one flow hash per packet");

    uint32_t differ = 0, child_wrong = 0, mine_wrong = 0;
    for (size_t i = 0; i < XPROC_HASHES; i++) {
        differ += child[i] != mine[i];
        child_wrong += child[i] != ref[i];
        mine_wrong += mine[i] != ref[i];
        if (child[i] != mine[i] && differ <= 3) {
            printf("    packet %zu: this process %08x, child %08x, canonical CRC %08x\n",
                   i, mine[i], child[i], ref[i]);
        }
    }
    printf("    %d packets: %u hashes differ between the processes; off the canonical CRC: "
           "%u in the child, %u here\n", XPROC_HASHES, differ, child_wrong, mine_wrong);
    TEST_ASSERT_EQ(0, differ, "another process computes the same flow hashes");
    TEST_ASSERT_EQ(0, child_wrong, "the child's flow hashes are the canonical CRCs");
    TEST_ASSERT_EQ(0, mine_wrong, "this process's flow hashes are the canonical CRCs");
}

// ==================== Main ====================

int main(int argc, char **argv) {
    int ret;

    // Child mode of test_flow_hash_stable_across_processes, before EAL init:
    // the parsers need none
    if (argc > 1 && strcmp(argv[1], FLOW_HASH_CHILD_ARG) == 0) {
        return flow_hash_child_main();
    }
    g_argv0 = argv[0];

    // Initialize EAL with minimal config
    char *eal_args[] = {
        argv[0],
        "-l", "0",
        "-n", "1",
        "--no-huge",
        "--no-pci",
        "-m", "256",
        "--no-shconf",
        "--no-telemetry",
        NULL
    };
    // The literal count 9 dropped the last option, so EAL took the shared
    // /tmp/dpdk/rte config and parallel tests skipped on its lock. --in-memory
    // is refused with --no-huge; --no-shconf creates no shared files.
    int eal_argc = (int)RTE_DIM(eal_args) - 1;

    ret = rte_eal_init(eal_argc, eal_args);
    if (ret < 0) {
        fprintf(stderr, "EAL init failed (missing DPDK permissions / runtime directory) -- skipping test\n");
        return 77;
    }

    if (setup_mempool() < 0) {
        fprintf(stderr, "Failed to create mempool -- skipping test\n");
        rte_eal_cleanup();
        return 77;
    }

    g_frame = aligned_alloc(64, FRAME_BUF_LEN);
    if (!g_frame) {
        fprintf(stderr, "Failed to allocate the frame buffer\n");
        cleanup_mempool();
        rte_eal_cleanup();
        return 1;
    }

    printf("\n========================================\n");
    printf("  Layer 1 Packet Parser Unit Tests\n");
    printf("========================================\n\n");

    // Run tests
    RUN_TEST(test_parse_valid_tcp_syn);
    RUN_TEST(test_parse_valid_tcp_ack);
    RUN_TEST(test_parse_valid_udp);
    RUN_TEST(test_parse_non_ip_packet);
    RUN_TEST(test_canonical_flow_key_ordering);
    RUN_TEST(test_validate_tcp_null_attack);
    RUN_TEST(test_validate_tcp_xmas_attack);
    RUN_TEST(test_validate_land_attack);
    RUN_TEST(test_ip_checksum_validation);
    RUN_TEST(test_flow_hash_consistency);
    RUN_TEST(test_flow_hash_canonical_crc_v4);
    RUN_TEST(test_flow_hash_tcp_udp_differ_v4);
    RUN_TEST(test_flow_hash_canonical_crc_v6);
    RUN_TEST(test_flow_hash_tcp_udp_differ_v6);
    RUN_TEST(test_flow_hash_stack_key);
    RUN_TEST(test_flow_hash_stable_across_processes);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_run);
    printf("========================================\n\n");

    free(g_frame);
    cleanup_mempool();
    rte_eal_cleanup();

    return tests_failed > 0 ? 1 : 0;
}
