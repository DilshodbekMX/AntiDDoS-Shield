/**
 * @file test_packet_parser.c
 * @brief Unit tests for Layer 1 packet parsing and validation
 *
 * Tests cover:
 * - IPv4 packet parsing
 * - TCP/UDP header extraction
 * - Validation error detection (malformed packets, attacks)
 * - Flow key generation (3-tuple canonical ordering)
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

// ==================== Main ====================

int main(int argc, char **argv) {
    int ret;

    // Initialize EAL with minimal config
    char *eal_args[] = {
        argv[0],
        "-l", "0",
        "-n", "1",
        "--no-huge",
        "--no-pci",
        "-m", "256",
        "--in-memory",
        NULL
    };
    int eal_argc = 9;

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

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_run);
    printf("========================================\n\n");

    cleanup_mempool();
    rte_eal_cleanup();

    return tests_failed > 0 ? 1 : 0;
}
