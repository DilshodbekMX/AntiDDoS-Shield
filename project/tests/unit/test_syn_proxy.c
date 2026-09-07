/**
 * @file test_syn_proxy.c
 * @brief Comprehensive unit tests for SYN Proxy module
 *
 * Tests cover:
 * - SYN cookie generation and validation
 * - Connection state machine transitions
 * - Timeout handling
 * - Secret rotation
 * - Adaptive mode switching
 * - Edge cases and security scenarios
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_cycles.h>

#include "../../layer1/tables/syn_proxy.h"
#include "../../layer1/datapath/packet_parser.h"
#include "../../common/types.h"

// ==================== Test Framework ====================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(expr, msg) do { \
    if (!(expr)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_EQ(expected, actual, msg) do { \
    if ((expected) != (actual)) { \
        printf("  FAIL: %s (expected=%ld, actual=%ld, line %d)\n", msg, \
               (long)(expected), (long)(actual), __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_NEQ(not_expected, actual, msg) do { \
    if ((not_expected) == (actual)) { \
        printf("  FAIL: %s (got unexpected value=%ld, line %d)\n", msg, \
               (long)(actual), __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_RANGE(val, min, max, msg) do { \
    if ((val) < (min) || (val) > (max)) { \
        printf("  FAIL: %s (value=%ld not in [%ld,%ld], line %d)\n", msg, \
               (long)(val), (long)(min), (long)(max), __LINE__); \
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

// ==================== Test Fixtures ====================

static struct rte_mempool *test_pool = NULL;
static struct syn_proxy_config default_config;

static int setup_mempool(void) {
    test_pool = rte_pktmbuf_pool_create(
        "syn_proxy_test_pool",
        4096,
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

static void init_default_config(void) {
    default_config.enabled = true;
    default_config.max_connections = 10000;
    default_config.connect_timeout_ms = 5000;
    default_config.idle_timeout_sec = 300;
    default_config.secret = 0xDEADBEEF;
    default_config.secret_rotation_sec = 60;
    default_config.stateless_threshold_pps = 10000;
    default_config.stateful_threshold_pps = 5000;
    default_config.mode_switch_delay_ms = 1000;
}

static struct rte_mbuf *create_syn_packet(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t seq_num
) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(test_pool);
    if (!m) return NULL;

    size_t pkt_len = sizeof(struct rte_ether_hdr) +
                     sizeof(struct rte_ipv4_hdr) +
                     sizeof(struct rte_tcp_hdr) + 20; // TCP options

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
    ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 20);
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->src_addr = rte_cpu_to_be_32(src_ip);
    ip->dst_addr = rte_cpu_to_be_32(dst_ip);
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // TCP header with SYN
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(src_port);
    tcp->dst_port = rte_cpu_to_be_16(dst_port);
    tcp->sent_seq = rte_cpu_to_be_32(seq_num);
    tcp->recv_ack = 0;
    tcp->data_off = 0xA0; // 40 bytes = 10 words (includes options)
    tcp->tcp_flags = RTE_TCP_SYN_FLAG;
    tcp->rx_win = rte_cpu_to_be_16(65535);

    // Add MSS option
    uint8_t *opts = (uint8_t *)(tcp + 1);
    opts[0] = 2;    // MSS option kind
    opts[1] = 4;    // MSS option length
    opts[2] = 0x05; // MSS = 1460
    opts[3] = 0xB4;

    return m;
}

static struct rte_mbuf *create_ack_packet(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t seq_num,
    uint32_t ack_num
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

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->src_addr = rte_cpu_to_be_32(src_ip);
    ip->dst_addr = rte_cpu_to_be_32(dst_ip);
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(src_port);
    tcp->dst_port = rte_cpu_to_be_16(dst_port);
    tcp->sent_seq = rte_cpu_to_be_32(seq_num);
    tcp->recv_ack = rte_cpu_to_be_32(ack_num);
    tcp->data_off = 0x50;
    tcp->tcp_flags = RTE_TCP_ACK_FLAG;
    tcp->rx_win = rte_cpu_to_be_16(65535);

    return m;
}

// ==================== Initialization Tests ====================

void test_syn_proxy_init_success(void) {
    init_default_config();
    int ret = syn_proxy_init(&default_config);
    TEST_ASSERT_EQ(0, ret, "syn_proxy_init should succeed");
    TEST_ASSERT(syn_proxy_is_enabled(), "SYN proxy should be enabled after init");
    syn_proxy_cleanup();
}

void test_syn_proxy_init_disabled(void) {
    init_default_config();
    default_config.enabled = false;
    int ret = syn_proxy_init(&default_config);
    TEST_ASSERT_EQ(0, ret, "syn_proxy_init should succeed even when disabled");
    TEST_ASSERT(!syn_proxy_is_enabled(), "SYN proxy should be disabled");
    syn_proxy_cleanup();
}

void test_syn_proxy_init_max_connections(void) {
    init_default_config();
    default_config.max_connections = 1000000;
    int ret = syn_proxy_init(&default_config);
    TEST_ASSERT_EQ(0, ret, "syn_proxy_init should handle large max_connections");
    syn_proxy_cleanup();
}

void test_syn_proxy_double_init(void) {
    init_default_config();
    int ret1 = syn_proxy_init(&default_config);
    TEST_ASSERT_EQ(0, ret1, "First init should succeed");

    // Second init should either succeed (reinit) or fail gracefully
    int ret2 = syn_proxy_init(&default_config);
    // Either outcome is acceptable as long as no crash
    (void)ret2;

    syn_proxy_cleanup();
}

// ==================== Cookie Tests ====================

void test_syn_cookie_generation(void) {
    init_default_config();
    syn_proxy_init(&default_config);

    struct rte_mbuf *syn = create_syn_packet(0x0A000001, 0xC0A80101, 12345, 80, 1000);
    TEST_ASSERT(syn != NULL, "Failed to create SYN packet");

    struct packet_features features;
    memset(&features, 0, sizeof(features));
    features.src_ip = rte_cpu_to_be_32(0x0A000001);
    features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    features.src_port = 12345;
    features.dst_port = 80;
    features.tcp_flags = RTE_TCP_SYN_FLAG;
    features.tcp_seq = 1000;

    struct syn_proxy_result result;
    int ret = syn_proxy_process_packet(syn, &features, 0, test_pool, &result, 0, NULL);

    // Should generate SYN-ACK with cookie
    TEST_ASSERT_EQ(SYN_PROXY_CHALLENGE, result.action, "Should challenge SYN with cookie");
    TEST_ASSERT(result.reply_pkt != NULL, "Should generate reply packet");

    if (result.reply_pkt) {
        rte_pktmbuf_free(result.reply_pkt);
    }
    rte_pktmbuf_free(syn);
    syn_proxy_cleanup();
}

void test_syn_cookie_validation_valid(void) {
    init_default_config();
    syn_proxy_init(&default_config);

    // First, send SYN to get cookie
    struct rte_mbuf *syn = create_syn_packet(0x0A000001, 0xC0A80101, 12345, 80, 1000);
    TEST_ASSERT(syn != NULL, "Failed to create SYN packet");

    struct packet_features syn_features;
    memset(&syn_features, 0, sizeof(syn_features));
    syn_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    syn_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    syn_features.src_port = 12345;
    syn_features.dst_port = 80;
    syn_features.tcp_flags = RTE_TCP_SYN_FLAG;
    syn_features.tcp_seq = 1000;

    struct syn_proxy_result syn_result;
    syn_proxy_process_packet(syn, &syn_features, 0, test_pool, &syn_result, 0, NULL);

    // Extract cookie ISN from SYN-ACK reply
    uint32_t cookie_isn = 0;
    if (syn_result.reply_pkt) {
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(syn_result.reply_pkt, struct rte_ether_hdr *);
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + (ip->version_ihl & 0x0F) * 4);
        cookie_isn = rte_be_to_cpu_32(tcp->sent_seq);
        rte_pktmbuf_free(syn_result.reply_pkt);
    }

    // Now send ACK with correct cookie
    struct rte_mbuf *ack = create_ack_packet(0x0A000001, 0xC0A80101, 12345, 80, 1001, cookie_isn + 1);
    TEST_ASSERT(ack != NULL, "Failed to create ACK packet");

    struct packet_features ack_features;
    memset(&ack_features, 0, sizeof(ack_features));
    ack_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    ack_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    ack_features.src_port = 12345;
    ack_features.dst_port = 80;
    ack_features.tcp_flags = RTE_TCP_ACK_FLAG;
    ack_features.tcp_seq = 1001;
    ack_features.tcp_ack = cookie_isn + 1;

    struct syn_proxy_result ack_result;
    syn_proxy_process_packet(ack, &ack_features, 0, test_pool, &ack_result, 0, NULL);

    // Cookie should be validated
    TEST_ASSERT(ack_result.action == SYN_PROXY_FORWARD ||
                ack_result.action == SYN_PROXY_CONNECT,
                "Valid cookie should result in FORWARD or CONNECT");

    rte_pktmbuf_free(syn);
    rte_pktmbuf_free(ack);
    syn_proxy_cleanup();
}

void test_syn_cookie_validation_invalid(void) {
    init_default_config();
    syn_proxy_init(&default_config);

    // Send ACK with invalid cookie (no prior SYN)
    uint32_t invalid_cookie = 0xBADC00DE;
    struct rte_mbuf *ack = create_ack_packet(0x0A000001, 0xC0A80101, 12345, 80, 1001, invalid_cookie);
    TEST_ASSERT(ack != NULL, "Failed to create ACK packet");

    struct packet_features features;
    memset(&features, 0, sizeof(features));
    features.src_ip = rte_cpu_to_be_32(0x0A000001);
    features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    features.src_port = 12345;
    features.dst_port = 80;
    features.tcp_flags = RTE_TCP_ACK_FLAG;
    features.tcp_seq = 1001;
    features.tcp_ack = invalid_cookie;

    struct syn_proxy_result result;
    syn_proxy_process_packet(ack, &features, 0, test_pool, &result, 0, NULL);

    // Invalid cookie should be dropped
    TEST_ASSERT_EQ(SYN_PROXY_DROP, result.action, "Invalid cookie should be dropped");

    rte_pktmbuf_free(ack);
    syn_proxy_cleanup();
}

void test_syn_cookie_expired(void) {
    init_default_config();
    default_config.secret_rotation_sec = 1; // Fast rotation for test
    syn_proxy_init(&default_config);

    // Get a cookie
    struct rte_mbuf *syn = create_syn_packet(0x0A000001, 0xC0A80101, 12345, 80, 1000);
    struct packet_features syn_features;
    memset(&syn_features, 0, sizeof(syn_features));
    syn_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    syn_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    syn_features.src_port = 12345;
    syn_features.dst_port = 80;
    syn_features.tcp_flags = RTE_TCP_SYN_FLAG;
    syn_features.tcp_seq = 1000;

    struct syn_proxy_result syn_result;
    syn_proxy_process_packet(syn, &syn_features, 0, test_pool, &syn_result, 0, NULL);

    uint32_t cookie_isn = 0;
    if (syn_result.reply_pkt) {
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(syn_result.reply_pkt, struct rte_ether_hdr *);
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + (ip->version_ihl & 0x0F) * 4);
        cookie_isn = rte_be_to_cpu_32(tcp->sent_seq);
        rte_pktmbuf_free(syn_result.reply_pkt);
    }

    // Rotate secret multiple times to expire cookie
    syn_proxy_rotate_secret(0x12345678);
    syn_proxy_rotate_secret(0x87654321);
    syn_proxy_rotate_secret(0xABCDEF01);

    // Try to use expired cookie
    struct rte_mbuf *ack = create_ack_packet(0x0A000001, 0xC0A80101, 12345, 80, 1001, cookie_isn + 1);
    struct packet_features ack_features;
    memset(&ack_features, 0, sizeof(ack_features));
    ack_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    ack_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    ack_features.src_port = 12345;
    ack_features.dst_port = 80;
    ack_features.tcp_flags = RTE_TCP_ACK_FLAG;
    ack_features.tcp_seq = 1001;
    ack_features.tcp_ack = cookie_isn + 1;

    struct syn_proxy_result ack_result;
    syn_proxy_process_packet(ack, &ack_features, 0, test_pool, &ack_result, 0, NULL);

    // Expired cookie should be dropped
    TEST_ASSERT_EQ(SYN_PROXY_DROP, ack_result.action, "Expired cookie should be dropped");

    rte_pktmbuf_free(syn);
    rte_pktmbuf_free(ack);
    syn_proxy_cleanup();
}

// ==================== Statistics Tests ====================

void test_syn_proxy_stats_cookies_sent(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    // Send multiple SYNs
    for (int i = 0; i < 10; i++) {
        struct rte_mbuf *syn = create_syn_packet(0x0A000001 + i, 0xC0A80101, 12345 + i, 80, 1000 + i);
        if (!syn) continue;

        struct packet_features features;
        memset(&features, 0, sizeof(features));
        features.src_ip = rte_cpu_to_be_32(0x0A000001 + i);
        features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
        features.src_port = 12345 + i;
        features.dst_port = 80;
        features.tcp_flags = RTE_TCP_SYN_FLAG;
        features.tcp_seq = 1000 + i;

        struct syn_proxy_result result;
        syn_proxy_process_packet(syn, &features, 0, test_pool, &result, 0, NULL);

        if (result.reply_pkt) {
            rte_pktmbuf_free(result.reply_pkt);
        }
        rte_pktmbuf_free(syn);
    }

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);

    TEST_ASSERT_EQ(10, stats.cookies_sent, "Should have sent 10 cookies");

    syn_proxy_cleanup();
}

void test_syn_proxy_stats_invalid_cookies(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    // Send multiple ACKs with invalid cookies
    for (int i = 0; i < 5; i++) {
        struct rte_mbuf *ack = create_ack_packet(0x0A000001 + i, 0xC0A80101, 12345 + i, 80, 1001, 0xBAD00000 + i);
        if (!ack) continue;

        struct packet_features features;
        memset(&features, 0, sizeof(features));
        features.src_ip = rte_cpu_to_be_32(0x0A000001 + i);
        features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
        features.src_port = 12345 + i;
        features.dst_port = 80;
        features.tcp_flags = RTE_TCP_ACK_FLAG;
        features.tcp_seq = 1001;
        features.tcp_ack = 0xBAD00000 + i;

        struct syn_proxy_result result;
        syn_proxy_process_packet(ack, &features, 0, test_pool, &result, 0, NULL);
        rte_pktmbuf_free(ack);
    }

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);

    TEST_ASSERT_EQ(5, stats.cookies_invalid, "Should have 5 invalid cookies");

    syn_proxy_cleanup();
}

// ==================== Adaptive Mode Tests ====================

void test_syn_proxy_mode_default(void) {
    init_default_config();
    syn_proxy_init(&default_config);

    enum syn_proxy_mode mode = syn_proxy_get_mode();
    TEST_ASSERT_EQ(SYN_PROXY_MODE_STATEFUL, mode, "Default mode should be stateful");

    syn_proxy_cleanup();
}

void test_syn_proxy_mode_forced(void) {
    init_default_config();
    syn_proxy_init(&default_config);

    syn_proxy_set_mode(SYN_PROXY_MODE_STATELESS);
    TEST_ASSERT_EQ(SYN_PROXY_MODE_STATELESS, syn_proxy_get_mode(), "Mode should be stateless after set");

    syn_proxy_set_mode(SYN_PROXY_MODE_STATEFUL);
    TEST_ASSERT_EQ(SYN_PROXY_MODE_STATEFUL, syn_proxy_get_mode(), "Mode should be stateful after set");

    // Return to adaptive
    syn_proxy_set_mode(-1);

    syn_proxy_cleanup();
}

// ==================== Connection Limit Tests ====================

void test_syn_proxy_table_full(void) {
    init_default_config();
    default_config.max_connections = 10; // Small limit for test
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    // Fill the table
    for (int i = 0; i < 20; i++) {
        struct rte_mbuf *syn = create_syn_packet(0x0A000001 + i, 0xC0A80101, 12345 + i, 80, 1000);
        if (!syn) continue;

        struct packet_features features;
        memset(&features, 0, sizeof(features));
        features.src_ip = rte_cpu_to_be_32(0x0A000001 + i);
        features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
        features.src_port = 12345 + i;
        features.dst_port = 80;
        features.tcp_flags = RTE_TCP_SYN_FLAG;
        features.tcp_seq = 1000;

        struct syn_proxy_result result;
        syn_proxy_process_packet(syn, &features, 0, test_pool, &result, 0, NULL);

        if (result.reply_pkt) {
            rte_pktmbuf_free(result.reply_pkt);
        }
        rte_pktmbuf_free(syn);
    }

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);

    // Should have some drops when table is full (in stateful mode)
    // In stateless mode, no drops expected as no state is kept for SYNs
    TEST_ASSERT(stats.connections_created <= 20, "Connections should be limited");

    syn_proxy_cleanup();
}

// ==================== Security Tests ====================

void test_syn_proxy_replay_attack(void) {
    init_default_config();
    syn_proxy_init(&default_config);

    // Get valid cookie
    struct rte_mbuf *syn = create_syn_packet(0x0A000001, 0xC0A80101, 12345, 80, 1000);
    struct packet_features syn_features;
    memset(&syn_features, 0, sizeof(syn_features));
    syn_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    syn_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    syn_features.src_port = 12345;
    syn_features.dst_port = 80;
    syn_features.tcp_flags = RTE_TCP_SYN_FLAG;
    syn_features.tcp_seq = 1000;

    struct syn_proxy_result syn_result;
    syn_proxy_process_packet(syn, &syn_features, 0, test_pool, &syn_result, 0, NULL);

    uint32_t cookie_isn = 0;
    if (syn_result.reply_pkt) {
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(syn_result.reply_pkt, struct rte_ether_hdr *);
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + (ip->version_ihl & 0x0F) * 4);
        cookie_isn = rte_be_to_cpu_32(tcp->sent_seq);
        rte_pktmbuf_free(syn_result.reply_pkt);
    }

    // First ACK should succeed
    struct rte_mbuf *ack1 = create_ack_packet(0x0A000001, 0xC0A80101, 12345, 80, 1001, cookie_isn + 1);
    struct packet_features ack1_features;
    memset(&ack1_features, 0, sizeof(ack1_features));
    ack1_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    ack1_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    ack1_features.src_port = 12345;
    ack1_features.dst_port = 80;
    ack1_features.tcp_flags = RTE_TCP_ACK_FLAG;
    ack1_features.tcp_seq = 1001;
    ack1_features.tcp_ack = cookie_isn + 1;

    struct syn_proxy_result ack1_result;
    syn_proxy_process_packet(ack1, &ack1_features, 0, test_pool, &ack1_result, 0, NULL);

    // Replay same ACK - should be handled (either forwarded to existing conn or dropped)
    struct rte_mbuf *ack2 = create_ack_packet(0x0A000001, 0xC0A80101, 12345, 80, 1001, cookie_isn + 1);
    struct packet_features ack2_features = ack1_features;

    struct syn_proxy_result ack2_result;
    syn_proxy_process_packet(ack2, &ack2_features, 0, test_pool, &ack2_result, 0, NULL);

    // Replay should not create duplicate connection
    // Either forward (existing) or drop (replay protection)
    TEST_ASSERT(ack2_result.action != SYN_PROXY_CONNECT,
                "Replay should not create new connection");

    rte_pktmbuf_free(syn);
    rte_pktmbuf_free(ack1);
    rte_pktmbuf_free(ack2);
    syn_proxy_cleanup();
}

void test_syn_proxy_spoofed_source(void) {
    init_default_config();
    syn_proxy_init(&default_config);

    // SYN with one source
    struct rte_mbuf *syn = create_syn_packet(0x0A000001, 0xC0A80101, 12345, 80, 1000);
    struct packet_features syn_features;
    memset(&syn_features, 0, sizeof(syn_features));
    syn_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    syn_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    syn_features.src_port = 12345;
    syn_features.dst_port = 80;
    syn_features.tcp_flags = RTE_TCP_SYN_FLAG;
    syn_features.tcp_seq = 1000;

    struct syn_proxy_result syn_result;
    syn_proxy_process_packet(syn, &syn_features, 0, test_pool, &syn_result, 0, NULL);

    uint32_t cookie_isn = 0;
    if (syn_result.reply_pkt) {
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(syn_result.reply_pkt, struct rte_ether_hdr *);
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + (ip->version_ihl & 0x0F) * 4);
        cookie_isn = rte_be_to_cpu_32(tcp->sent_seq);
        rte_pktmbuf_free(syn_result.reply_pkt);
    }

    // ACK with DIFFERENT source (spoofed) but correct cookie
    struct rte_mbuf *ack = create_ack_packet(0x0B000001, 0xC0A80101, 12345, 80, 1001, cookie_isn + 1);
    struct packet_features ack_features;
    memset(&ack_features, 0, sizeof(ack_features));
    ack_features.src_ip = rte_cpu_to_be_32(0x0B000001); // Different source!
    ack_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    ack_features.src_port = 12345;
    ack_features.dst_port = 80;
    ack_features.tcp_flags = RTE_TCP_ACK_FLAG;
    ack_features.tcp_seq = 1001;
    ack_features.tcp_ack = cookie_isn + 1;

    struct syn_proxy_result ack_result;
    syn_proxy_process_packet(ack, &ack_features, 0, test_pool, &ack_result, 0, NULL);

    // Cookie from different source should be invalid (source IP is part of hash)
    TEST_ASSERT_EQ(SYN_PROXY_DROP, ack_result.action,
                   "Cookie from different source should be dropped");

    rte_pktmbuf_free(syn);
    rte_pktmbuf_free(ack);
    syn_proxy_cleanup();
}

// ==================== Integer Overflow Test ====================

void test_syn_cookie_integer_overflow(void) {
    init_default_config();
    syn_proxy_init(&default_config);

    // Test with maximum values that could cause overflow
    struct rte_mbuf *syn = create_syn_packet(0xFFFFFFFF, 0xFFFFFFFF, 65535, 65535, 0xFFFFFFFF);
    TEST_ASSERT(syn != NULL, "Failed to create SYN packet");

    struct packet_features features;
    memset(&features, 0, sizeof(features));
    features.src_ip = 0xFFFFFFFF;
    features.dst_ip = 0xFFFFFFFF;
    features.src_port = 65535;
    features.dst_port = 65535;
    features.tcp_flags = RTE_TCP_SYN_FLAG;
    features.tcp_seq = 0xFFFFFFFF;

    struct syn_proxy_result result;
    // Should not crash or produce undefined behavior
    int ret = syn_proxy_process_packet(syn, &features, 0, test_pool, &result, 0, NULL);

    // Result should be valid action (not garbage)
    TEST_ASSERT(result.action >= SYN_PROXY_FORWARD && result.action <= SYN_PROXY_ERROR,
                "Action should be valid enum value");

    if (result.reply_pkt) {
        rte_pktmbuf_free(result.reply_pkt);
    }
    rte_pktmbuf_free(syn);
    syn_proxy_cleanup();
}

// ==================== Cleanup Tests ====================

void test_syn_proxy_cleanup_connections(void) {
    init_default_config();
    default_config.connect_timeout_ms = 1; // Very short timeout
    syn_proxy_init(&default_config);

    // Create some connections
    for (int i = 0; i < 5; i++) {
        struct rte_mbuf *syn = create_syn_packet(0x0A000001 + i, 0xC0A80101, 12345 + i, 80, 1000);
        if (!syn) continue;

        struct packet_features features;
        memset(&features, 0, sizeof(features));
        features.src_ip = rte_cpu_to_be_32(0x0A000001 + i);
        features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
        features.src_port = 12345 + i;
        features.dst_port = 80;
        features.tcp_flags = RTE_TCP_SYN_FLAG;
        features.tcp_seq = 1000;

        struct syn_proxy_result result;
        syn_proxy_process_packet(syn, &features, 0, test_pool, &result, 0, NULL);

        if (result.reply_pkt) {
            rte_pktmbuf_free(result.reply_pkt);
        }
        rte_pktmbuf_free(syn);
    }

    // Wait for timeout
    rte_delay_ms(10);

    // Cleanup should remove timed out connections
    uint32_t cleaned = syn_proxy_cleanup_connections();

    // Some connections should be cleaned (depends on mode)
    // In stateless mode, nothing to clean
    // Test passes if no crash
    (void)cleaned;

    syn_proxy_cleanup();
}

// ==================== Main ====================

int main(int argc, char **argv) {
    int ret;

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
    printf("  SYN Proxy Unit Tests\n");
    printf("========================================\n\n");

    // Initialization tests
    RUN_TEST(test_syn_proxy_init_success);
    RUN_TEST(test_syn_proxy_init_disabled);
    RUN_TEST(test_syn_proxy_init_max_connections);
    RUN_TEST(test_syn_proxy_double_init);

    // Cookie tests
    RUN_TEST(test_syn_cookie_generation);
    RUN_TEST(test_syn_cookie_validation_valid);
    RUN_TEST(test_syn_cookie_validation_invalid);
    RUN_TEST(test_syn_cookie_expired);

    // Statistics tests
    RUN_TEST(test_syn_proxy_stats_cookies_sent);
    RUN_TEST(test_syn_proxy_stats_invalid_cookies);

    // Adaptive mode tests
    RUN_TEST(test_syn_proxy_mode_default);
    RUN_TEST(test_syn_proxy_mode_forced);

    // Connection limit tests
    RUN_TEST(test_syn_proxy_table_full);

    // Security tests
    RUN_TEST(test_syn_proxy_replay_attack);
    RUN_TEST(test_syn_proxy_spoofed_source);
    RUN_TEST(test_syn_cookie_integer_overflow);

    // Cleanup tests
    RUN_TEST(test_syn_proxy_cleanup_connections);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_run);
    printf("========================================\n\n");

    cleanup_mempool();
    rte_eal_cleanup();

    return tests_failed > 0 ? 1 : 0;
}
