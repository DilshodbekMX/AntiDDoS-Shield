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
 * - TCP options the cookie path offers on both legs
 * - Spoofed-mode admission (Stage 8b) of connections the proxy handles
 * - Interleavings of two lcores, made deterministic by the race seams of
 *   syn_proxy.h, and a thread without an lcore id
 * - The close of proxied connections, and the cleanup's scan budget
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>

#include "../../layer1/layer1.h"
#include "../../layer1/tables/syn_proxy.h"
#include "../../layer1/tables/flow_table.h"
#include "../../layer1/datapath/packet_parser.h"
#include "../../layer1/config/layer1_config.h"
#include "../../common/types.h"

// syn_proxy.c and layer1.c call anomaly_is_spoofed_mode() through the
// prototype in shared_memory.h. Without one they called it as an implicit int
// function, the defect that broke syn_proxy_quick_cookie_check() in Stage 8b.
static_assert(__builtin_types_compatible_p(__typeof__(anomaly_is_spoofed_mode), bool (void)),
              "shared_memory.h must declare bool anomaly_is_spoofed_mode(void)");

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

// ==================== Seams ====================

// syn_proxy_race_seam() of this binary: at the armed point it runs the armed
// action once, as another lcore would run it between this lcore's read of an
// entry and its compare-and-swap. Unarmed, it does nothing, like the
// library's weak definition.
static enum syn_proxy_seam_point seam_point;
static void (*seam_action)(void) = NULL;
static int seam_calls = 0;

void syn_proxy_race_seam(enum syn_proxy_seam_point point) {
    void (*action)(void) = seam_action;
    if (action && point == seam_point) {
        seam_action = NULL;
        seam_calls++;
        action();
    }
}

static void arm_seam(enum syn_proxy_seam_point point, void (*action)(void)) {
    seam_point = point;
    seam_calls = 0;
    seam_action = action;
}

// syn_proxy_synack_clock() of this binary: the TSC, or a value a subtest holds
static uint64_t synack_clock_held = 0;

uint64_t syn_proxy_synack_clock(void) {
    return synack_clock_held ? synack_clock_held : rte_rdtsc();
}

// syn_proxy_cleanup_clock() of this binary: the TSC, or a time a subtest holds
// (later than now: entries look idle without waiting)
static uint64_t cleanup_clock_held = 0;

uint64_t syn_proxy_cleanup_clock(void) {
    return cleanup_clock_held ? cleanup_clock_held : rte_get_tsc_cycles();
}

// A failed assertion returns before the subtest's own cleanup call, which
// left the module initialized for the next subtest (its init then returns
// early on the stale state). Release it here so every subtest starts clean,
// and never leave a seam armed or a clock held.
#define RUN_TEST(test_func) do { \
    printf("Running %s...\n", #test_func); \
    tests_run++; \
    int failed_before = tests_failed; \
    test_func(); \
    seam_action = NULL; \
    synack_clock_held = 0; \
    cleanup_clock_held = 0; \
    if (tests_failed > failed_before) { \
        syn_proxy_cleanup(); \
    } \
    if (tests_run - tests_failed - tests_passed == 1) { \
        tests_passed++; \
        printf("  PASS\n"); \
    } \
} while(0)

// ==================== Test Fixtures ====================

static struct rte_mempool *test_pool = NULL;
static struct syn_proxy_config default_config;
static struct layer1_config l1_config;

// syn_proxy_should_challenge() answers a SYN with a cookie only under spoofed
// mode, a CHALLENGE policy, bad reputation, a TCP anomaly at MEDIUM or above, or
// a SYN rate above challenge_threshold. None holds in a unit test, so a SYN with
// no anomaly snapshot is bypassed. The cookie tests pass the per-IP snapshot that
// Layer 2 publishes for a destination under a TCP flood.
static const struct per_ip_anomaly_snapshot tcp_flood_anom = {
    .valid = true,
    .anomaly_active = true,
    .anomaly_level = ANOMALY_LEVEL_MEDIUM,
    .anomaly_protocol = PROTO_CAT_TCP,
};

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

// Created on first use by get_race_pool()
static struct rte_mempool *race_pool = NULL;

static void cleanup_mempool(void) {
    if (test_pool) {
        rte_mempool_free(test_pool);
        test_pool = NULL;
    }
    if (race_pool) {
        rte_mempool_free(race_pool);
        race_pool = NULL;
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
    default_config.challenge_threshold = 0;  // Default (1000 SYN/s)
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

static struct rte_tcp_hdr *reply_tcp_hdr(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    return (struct rte_tcp_hdr *)((uint8_t *)ip + (ip->version_ihl & 0x0F) * 4);
}

// Packet with a 20-byte TCP header (no options) and any TCP flags
static struct rte_mbuf *create_tcp_packet(uint32_t src_ip, uint32_t dst_ip,
                                          uint16_t src_port, uint16_t dst_port,
                                          uint8_t tcp_flags,
                                          uint32_t seq_num, uint32_t ack_num) {
    struct rte_mbuf *m = create_ack_packet(src_ip, dst_ip, src_port, dst_port,
                                           seq_num, ack_num);
    if (m) {
        reply_tcp_hdr(m)->tcp_flags = tcp_flags;
    }
    return m;
}

static struct packet_features tcp_features(uint32_t src_ip, uint32_t dst_ip,
                                           uint16_t src_port, uint16_t dst_port,
                                           uint8_t tcp_flags,
                                           uint32_t seq_num, uint32_t ack_num) {
    struct packet_features features;
    memset(&features, 0, sizeof(features));
    features.protocol = IPPROTO_TCP;
    features.src_ip = rte_cpu_to_be_32(src_ip);
    features.dst_ip = rte_cpu_to_be_32(dst_ip);
    features.src_port = src_port;
    features.dst_port = dst_port;
    features.tcp_flags = tcp_flags;
    features.tcp_seq = seq_num;
    features.tcp_ack = ack_num;
    return features;
}

// Run one packet (no TCP options) through the proxy, which allocates any
// packet it builds from proxy_pool, and free it. A reply packet is left in
// res->reply_pkt for the caller to read and free.
static void send_tcp_via(struct rte_mempool *proxy_pool, uint8_t direction,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint8_t tcp_flags, uint32_t seq_num, uint32_t ack_num,
                         const struct per_ip_anomaly_snapshot *ip_anom,
                         struct syn_proxy_result *res) {
    memset(res, 0, sizeof(*res));
    res->action = SYN_PROXY_ERROR;

    struct rte_mbuf *m = create_tcp_packet(src_ip, dst_ip, src_port, dst_port,
                                           tcp_flags, seq_num, ack_num);
    if (!m) return;

    struct packet_features features = tcp_features(src_ip, dst_ip, src_port, dst_port,
                                                   tcp_flags, seq_num, ack_num);
    syn_proxy_process_packet(m, &features, direction, proxy_pool, res, 0, ip_anom);
    rte_pktmbuf_free(m);
}

// send_tcp_via() with the test pool
static void send_tcp(uint8_t direction,
                     uint32_t src_ip, uint32_t dst_ip,
                     uint16_t src_port, uint16_t dst_port,
                     uint8_t tcp_flags, uint32_t seq_num, uint32_t ack_num,
                     const struct per_ip_anomaly_snapshot *ip_anom,
                     struct syn_proxy_result *res) {
    send_tcp_via(test_pool, direction, src_ip, dst_ip, src_port, dst_port,
                 tcp_flags, seq_num, ack_num, ip_anom, res);
}

// SYN under the TCP-flood snapshot; stores the cookie (the SYN-ACK's sequence
// number) in *cookie. Returns false if the SYN was not challenged.
static bool get_cookie(uint32_t src_ip, uint32_t dst_ip,
                       uint16_t src_port, uint16_t dst_port,
                       uint32_t isn, uint32_t *cookie) {
    struct syn_proxy_result res;
    send_tcp(DIRECTION_INBOUND, src_ip, dst_ip, src_port, dst_port,
             RTE_TCP_SYN_FLAG, isn, 0, &tcp_flood_anom, &res);
    if (!res.reply_pkt) return false;

    *cookie = rte_be_to_cpu_32(reply_tcp_hdr(res.reply_pkt)->sent_seq);
    rte_pktmbuf_free(res.reply_pkt);
    return res.action == SYN_PROXY_REPLY && res.conn_state == SYN_PROXY_SYN_SENT;
}

// The client's ACK that returns the cookie. A valid cookie opens the server
// connection: REPLY, state CONNECTING, the SYN to the server in res->reply_pkt.
static void send_cookie_ack(uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint32_t isn, uint32_t cookie,
                            struct syn_proxy_result *res) {
    send_tcp(DIRECTION_INBOUND, src_ip, dst_ip, src_port, dst_port,
             RTE_TCP_ACK_FLAG, isn + 1, cookie + 1, NULL, res);
}

// Client handshake through the cookie under attack. Returns the ACK's action
// (REPLY once the SYN to the server is sent, or DROP), or ERROR if the SYN was
// not challenged. *proxy_isn, if given, gets the sequence number of that SYN.
static enum syn_proxy_action cookie_handshake(uint32_t src_ip, uint32_t dst_ip,
                                              uint16_t src_port, uint16_t dst_port,
                                              uint32_t isn, uint32_t *proxy_isn) {
    uint32_t cookie;
    if (!get_cookie(src_ip, dst_ip, src_port, dst_port, isn, &cookie))
        return SYN_PROXY_ERROR;

    struct syn_proxy_result res;
    send_cookie_ack(src_ip, dst_ip, src_port, dst_port, isn, cookie, &res);
    if (res.reply_pkt) {
        if (proxy_isn)
            *proxy_isn = rte_be_to_cpu_32(reply_tcp_hdr(res.reply_pkt)->sent_seq);
        rte_pktmbuf_free(res.reply_pkt);
    }
    if (res.action == SYN_PROXY_REPLY && res.conn_state != SYN_PROXY_CONNECTING)
        return SYN_PROXY_ERROR;
    return res.action;
}

// TCP option of the given kind in a header, or NULL if absent
static const uint8_t *find_tcp_option(const struct rte_tcp_hdr *tcp, uint8_t kind) {
    const uint8_t *opt = (const uint8_t *)tcp + sizeof(*tcp);
    const uint8_t *end = (const uint8_t *)tcp + (tcp->data_off >> 4) * 4;

    while (opt < end && *opt != 0) {          // 0 = end of option list
        if (*opt == 1) {                      // NOP
            opt++;
            continue;
        }
        if (opt + 1 >= end || opt[1] < 2 || opt + opt[1] > end) break;
        if (*opt == kind) return opt;
        opt += opt[1];
    }
    return NULL;
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
    features.protocol = IPPROTO_TCP;
    features.src_ip = rte_cpu_to_be_32(0x0A000001);
    features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    features.src_port = 12345;
    features.dst_port = 80;
    features.tcp_flags = RTE_TCP_SYN_FLAG;
    features.tcp_seq = 1000;

    struct syn_proxy_result result;
    syn_proxy_process_packet(syn, &features, 0, test_pool, &result, 0, &tcp_flood_anom);

    // A challenged SYN is answered with a SYN-ACK carrying the cookie: action
    // REPLY with state SYN_SENT, which layer1.c sends back out of the arrival port.
    // (SYN_PROXY_CHALLENGE is declared in types.h but never returned.)
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, result.action, "Should challenge SYN with cookie");
    TEST_ASSERT_EQ(SYN_PROXY_SYN_SENT, result.conn_state, "Challenge should leave state SYN_SENT");
    TEST_ASSERT(result.reply_pkt != NULL, "Should generate reply packet");

    struct rte_tcp_hdr *tcp = reply_tcp_hdr(result.reply_pkt);
    uint8_t flags = tcp->tcp_flags;
    uint32_t ack = rte_be_to_cpu_32(tcp->recv_ack);
    rte_pktmbuf_free(result.reply_pkt);
    TEST_ASSERT_EQ(RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, flags, "Reply should be a SYN-ACK");
    TEST_ASSERT_EQ(1001, ack, "SYN-ACK should acknowledge the client ISN + 1");
    rte_pktmbuf_free(syn);
    syn_proxy_cleanup();
}

void test_syn_proxy_normal_load_bypass(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    // No anomaly, no policy, no reputation entry and a SYN rate below the
    // challenge threshold: the SYN goes to the server unchallenged and the
    // proxy records the connection as BYPASSED
    struct rte_mbuf *syn = create_syn_packet(0x0A000002, 0xC0A80101, 23456, 80, 5000);
    TEST_ASSERT(syn != NULL, "Failed to create SYN packet");

    struct packet_features syn_features;
    memset(&syn_features, 0, sizeof(syn_features));
    syn_features.protocol = IPPROTO_TCP;
    syn_features.src_ip = rte_cpu_to_be_32(0x0A000002);
    syn_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    syn_features.src_port = 23456;
    syn_features.dst_port = 80;
    syn_features.tcp_flags = RTE_TCP_SYN_FLAG;
    syn_features.tcp_seq = 5000;

    struct syn_proxy_result syn_result;
    syn_proxy_process_packet(syn, &syn_features, 0, test_pool, &syn_result, 0, NULL);
    rte_pktmbuf_free(syn);

    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, syn_result.action, "Unchallenged SYN should be bypassed");
    TEST_ASSERT(syn_result.reply_pkt == NULL, "Unchallenged SYN should get no SYN-ACK");

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, stats.cookies_sent, "Unchallenged SYN should send no cookie");
    TEST_ASSERT_EQ(1, stats.connections_created, "Bypass should record the connection");

    // Later packets of the bypassed connection are forwarded unmodified
    struct rte_mbuf *ack = create_ack_packet(0x0A000002, 0xC0A80101, 23456, 80, 5001, 777);
    TEST_ASSERT(ack != NULL, "Failed to create ACK packet");

    struct packet_features ack_features = syn_features;
    ack_features.tcp_flags = RTE_TCP_ACK_FLAG;
    ack_features.tcp_seq = 5001;
    ack_features.tcp_ack = 777;

    struct syn_proxy_result ack_result;
    syn_proxy_process_packet(ack, &ack_features, 0, test_pool, &ack_result, 0, NULL);
    rte_pktmbuf_free(ack);

    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, ack_result.action, "Bypassed connection should be forwarded");
    TEST_ASSERT(!ack_result.packet_modified, "Bypassed connection should not be translated");
    TEST_ASSERT_EQ(SYN_PROXY_BYPASSED, ack_result.conn_state, "Connection state should be BYPASSED");

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
    syn_features.protocol = IPPROTO_TCP;
    syn_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    syn_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    syn_features.src_port = 12345;
    syn_features.dst_port = 80;
    syn_features.tcp_flags = RTE_TCP_SYN_FLAG;
    syn_features.tcp_seq = 1000;

    struct syn_proxy_result syn_result;
    syn_proxy_process_packet(syn, &syn_features, 0, test_pool, &syn_result, 0, &tcp_flood_anom);
    TEST_ASSERT(syn_result.reply_pkt != NULL, "SYN should be challenged with a cookie");

    // Extract cookie ISN from SYN-ACK reply
    uint32_t cookie_isn = rte_be_to_cpu_32(reply_tcp_hdr(syn_result.reply_pkt)->sent_seq);
    rte_pktmbuf_free(syn_result.reply_pkt);

    // Now send ACK with correct cookie
    struct rte_mbuf *ack = create_ack_packet(0x0A000001, 0xC0A80101, 12345, 80, 1001, cookie_isn + 1);
    TEST_ASSERT(ack != NULL, "Failed to create ACK packet");

    struct packet_features ack_features;
    memset(&ack_features, 0, sizeof(ack_features));
    ack_features.protocol = IPPROTO_TCP;
    ack_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    ack_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    ack_features.src_port = 12345;
    ack_features.dst_port = 80;
    ack_features.tcp_flags = RTE_TCP_ACK_FLAG;
    ack_features.tcp_seq = 1001;
    ack_features.tcp_ack = cookie_isn + 1;

    syn_proxy_reset_stats();
    struct syn_proxy_result ack_result;
    syn_proxy_process_packet(ack, &ack_features, 0, test_pool, &ack_result, 0, NULL);

    // A valid cookie opens the proxied connection: action REPLY with state
    // CONNECTING and a SYN to the server, which layer1.c sends out of the
    // opposite port. (SYN_PROXY_CONNECT is declared in types.h but never returned.)
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, ack_result.action, "Valid cookie should open a server connection");
    TEST_ASSERT_EQ(SYN_PROXY_CONNECTING, ack_result.conn_state, "Valid cookie should leave state CONNECTING");
    TEST_ASSERT(ack_result.reply_pkt != NULL, "Valid cookie should produce the SYN to the server");

    struct rte_tcp_hdr *tcp = reply_tcp_hdr(ack_result.reply_pkt);
    uint8_t flags = tcp->tcp_flags;
    uint16_t dport = rte_be_to_cpu_16(tcp->dst_port);
    rte_pktmbuf_free(ack_result.reply_pkt);
    TEST_ASSERT_EQ(RTE_TCP_SYN_FLAG, flags, "Packet to the server should be a SYN");
    TEST_ASSERT_EQ(80, dport, "SYN should go to the server port");

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(1, stats.cookies_valid, "Should count one valid cookie");

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
    features.protocol = IPPROTO_TCP;
    features.src_ip = rte_cpu_to_be_32(0x0A000001);
    features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    features.src_port = 12345;
    features.dst_port = 80;
    features.tcp_flags = RTE_TCP_ACK_FLAG;
    features.tcp_seq = 1001;
    features.tcp_ack = invalid_cookie;

    syn_proxy_reset_stats();
    struct syn_proxy_result result;
    syn_proxy_process_packet(ack, &features, 0, test_pool, &result, 0, NULL);

    // An ACK with no connection and a bad cookie is not proxied: the proxy hands
    // it back to the pipeline (BYPASS, "might be normal traffic") and opens no
    // server connection. In spoofed mode, Stage 8b of layer1.c drops it before
    // Stage 9 because syn_proxy_quick_cookie_check() rejects the cookie.
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, result.action, "Invalid cookie must not be proxied");
    TEST_ASSERT(result.reply_pkt == NULL, "Invalid cookie must not open a server connection");

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, stats.cookies_valid, "Invalid cookie must not count as valid");
    TEST_ASSERT_EQ(1, stats.cookies_invalid, "Invalid cookie should be counted");
    TEST_ASSERT_EQ(0, stats.connections_created, "Invalid cookie must not create a connection");
    TEST_ASSERT(!syn_proxy_quick_cookie_check(features.src_ip, features.dst_ip,
                                              features.src_port, features.dst_port,
                                              features.tcp_ack),
                "Invalid cookie should fail the Stage 8b cookie check");

    rte_pktmbuf_free(ack);
    syn_proxy_cleanup();
}

void test_syn_cookie_quick_check_repeated_invalid(void) {
    init_default_config();
    syn_proxy_init(&default_config);

    // validate_cookie() logs the first 11 failures; later failures return
    // without logging, with the result only in the low byte of the return
    // register. layer1.c called syn_proxy_quick_cookie_check() with no
    // prototype, as int, and read those failures as valid cookies.
    for (int i = 0; i < 32; i++) {
        TEST_ASSERT(!syn_proxy_quick_cookie_check(rte_cpu_to_be_32(0x0A000001 + i),
                                                  rte_cpu_to_be_32(0xC0A80101),
                                                  12345, 80, 0xBAD00000 + i),
                    "Repeated invalid cookies should all fail the Stage 8b cookie check");
    }

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
    syn_features.protocol = IPPROTO_TCP;
    syn_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    syn_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    syn_features.src_port = 12345;
    syn_features.dst_port = 80;
    syn_features.tcp_flags = RTE_TCP_SYN_FLAG;
    syn_features.tcp_seq = 1000;

    struct syn_proxy_result syn_result;
    syn_proxy_process_packet(syn, &syn_features, 0, test_pool, &syn_result, 0, &tcp_flood_anom);
    TEST_ASSERT(syn_result.reply_pkt != NULL, "SYN should be challenged with a cookie");

    uint32_t cookie_isn = rte_be_to_cpu_32(reply_tcp_hdr(syn_result.reply_pkt)->sent_seq);
    rte_pktmbuf_free(syn_result.reply_pkt);

    // After one rotation the cookie still validates against the previous secret
    syn_proxy_rotate_secret(0x12345678);
    TEST_ASSERT(syn_proxy_quick_cookie_check(syn_features.src_ip, syn_features.dst_ip,
                                             syn_features.src_port, syn_features.dst_port,
                                             cookie_isn + 1),
                "Cookie should survive one secret rotation");

    // Rotate secret multiple times to expire cookie
    syn_proxy_rotate_secret(0x87654321);
    syn_proxy_rotate_secret(0xABCDEF01);

    // Try to use expired cookie
    struct rte_mbuf *ack = create_ack_packet(0x0A000001, 0xC0A80101, 12345, 80, 1001, cookie_isn + 1);
    struct packet_features ack_features;
    memset(&ack_features, 0, sizeof(ack_features));
    ack_features.protocol = IPPROTO_TCP;
    ack_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    ack_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    ack_features.src_port = 12345;
    ack_features.dst_port = 80;
    ack_features.tcp_flags = RTE_TCP_ACK_FLAG;
    ack_features.tcp_seq = 1001;
    ack_features.tcp_ack = cookie_isn + 1;

    syn_proxy_reset_stats();
    struct syn_proxy_result ack_result;
    syn_proxy_process_packet(ack, &ack_features, 0, test_pool, &ack_result, 0, NULL);

    // Expired cookie is rejected: not proxied, no server connection, and it
    // fails the Stage 8b check (see test_syn_cookie_validation_invalid)
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, ack_result.action, "Expired cookie must not be proxied");
    TEST_ASSERT(ack_result.reply_pkt == NULL, "Expired cookie must not open a server connection");

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, stats.cookies_valid, "Expired cookie must not count as valid");
    TEST_ASSERT(!syn_proxy_quick_cookie_check(ack_features.src_ip, ack_features.dst_ip,
                                              ack_features.src_port, ack_features.dst_port,
                                              ack_features.tcp_ack),
                "Expired cookie should fail the Stage 8b cookie check");

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
        features.protocol = IPPROTO_TCP;
        features.src_ip = rte_cpu_to_be_32(0x0A000001 + i);
        features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
        features.src_port = 12345 + i;
        features.dst_port = 80;
        features.tcp_flags = RTE_TCP_SYN_FLAG;
        features.tcp_seq = 1000 + i;

        struct syn_proxy_result result;
        syn_proxy_process_packet(syn, &features, 0, test_pool, &result, 0, &tcp_flood_anom);

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
        features.protocol = IPPROTO_TCP;
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

    // Under attack every SYN is answered with a cookie and keeps no state,
    // so a SYN flood cannot fill the table
    uint32_t cookies[20];
    for (int i = 0; i < 20; i++) {
        TEST_ASSERT(get_cookie(0x0A000001 + i, 0xC0A80101, 12345 + i, 80, 1000, &cookies[i]),
                    "SYN should be challenged with a cookie");
    }

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(20, stats.cookies_sent, "Should have sent 20 cookies");
    TEST_ASSERT_EQ(0, stats.connections_created, "Challenged SYNs should keep no state");
    TEST_ASSERT_EQ(0, stats.table_full_drops, "Challenged SYNs should not fill the table");

    // Each completed handshake needs an entry. The table holds at most
    // max_connections of them; the other valid cookies are dropped and counted.
    uint32_t connected = 0, dropped = 0;
    for (int i = 0; i < 20; i++) {
        struct syn_proxy_result res;
        send_cookie_ack(0x0A000001 + i, 0xC0A80101, 12345 + i, 80, 1000, cookies[i], &res);
        if (res.reply_pkt) {
            rte_pktmbuf_free(res.reply_pkt);
        }
        if (res.action == SYN_PROXY_REPLY && res.conn_state == SYN_PROXY_CONNECTING) {
            connected++;
        } else if (res.action == SYN_PROXY_DROP) {
            dropped++;
        }
    }

    syn_proxy_get_stats(&stats);
    TEST_ASSERT(stats.connections_created <= 20, "Connections should be limited");
    TEST_ASSERT_RANGE(connected, 1, 10, "Proxied connections should be limited to max_connections");
    TEST_ASSERT_EQ(20, connected + dropped, "Every valid cookie should be proxied or dropped");
    TEST_ASSERT_EQ(20, stats.cookies_valid, "All 20 cookies should validate");
    TEST_ASSERT_EQ(connected, stats.connections_active, "Each proxied connection should hold an entry");
    TEST_ASSERT_EQ(dropped, stats.table_full_drops, "Drops should be counted as table full");

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
    syn_features.protocol = IPPROTO_TCP;
    syn_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    syn_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    syn_features.src_port = 12345;
    syn_features.dst_port = 80;
    syn_features.tcp_flags = RTE_TCP_SYN_FLAG;
    syn_features.tcp_seq = 1000;

    struct syn_proxy_result syn_result;
    syn_proxy_process_packet(syn, &syn_features, 0, test_pool, &syn_result, 0, &tcp_flood_anom);
    TEST_ASSERT(syn_result.reply_pkt != NULL, "SYN should be challenged with a cookie");

    uint32_t cookie_isn = rte_be_to_cpu_32(reply_tcp_hdr(syn_result.reply_pkt)->sent_seq);
    rte_pktmbuf_free(syn_result.reply_pkt);

    // First ACK should succeed
    struct rte_mbuf *ack1 = create_ack_packet(0x0A000001, 0xC0A80101, 12345, 80, 1001, cookie_isn + 1);
    struct packet_features ack1_features;
    memset(&ack1_features, 0, sizeof(ack1_features));
    ack1_features.protocol = IPPROTO_TCP;
    ack1_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    ack1_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    ack1_features.src_port = 12345;
    ack1_features.dst_port = 80;
    ack1_features.tcp_flags = RTE_TCP_ACK_FLAG;
    ack1_features.tcp_seq = 1001;
    ack1_features.tcp_ack = cookie_isn + 1;

    struct syn_proxy_result ack1_result;
    syn_proxy_process_packet(ack1, &ack1_features, 0, test_pool, &ack1_result, 0, NULL);
    if (ack1_result.reply_pkt) {
        rte_pktmbuf_free(ack1_result.reply_pkt);
    }
    TEST_ASSERT_EQ(SYN_PROXY_CONNECTING, ack1_result.conn_state, "First ACK should open the connection");

    // Replay same ACK - should be handled (either forwarded to existing conn or dropped)
    struct rte_mbuf *ack2 = create_ack_packet(0x0A000001, 0xC0A80101, 12345, 80, 1001, cookie_isn + 1);
    struct packet_features ack2_features = ack1_features;

    struct syn_proxy_result ack2_result;
    syn_proxy_process_packet(ack2, &ack2_features, 0, test_pool, &ack2_result, 0, NULL);

    // Replay should not create duplicate connection: while the server
    // handshake is pending, client packets on the connection are dropped and
    // no second SYN goes to the server
    TEST_ASSERT_EQ(SYN_PROXY_DROP, ack2_result.action, "Replay should not create new connection");
    TEST_ASSERT(ack2_result.reply_pkt == NULL, "Replay should not send a second SYN to the server");

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
    syn_features.protocol = IPPROTO_TCP;
    syn_features.src_ip = rte_cpu_to_be_32(0x0A000001);
    syn_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    syn_features.src_port = 12345;
    syn_features.dst_port = 80;
    syn_features.tcp_flags = RTE_TCP_SYN_FLAG;
    syn_features.tcp_seq = 1000;

    struct syn_proxy_result syn_result;
    syn_proxy_process_packet(syn, &syn_features, 0, test_pool, &syn_result, 0, &tcp_flood_anom);
    TEST_ASSERT(syn_result.reply_pkt != NULL, "SYN should be challenged with a cookie");

    uint32_t cookie_isn = rte_be_to_cpu_32(reply_tcp_hdr(syn_result.reply_pkt)->sent_seq);
    rte_pktmbuf_free(syn_result.reply_pkt);

    // ACK with DIFFERENT source (spoofed) but correct cookie
    struct rte_mbuf *ack = create_ack_packet(0x0B000001, 0xC0A80101, 12345, 80, 1001, cookie_isn + 1);
    struct packet_features ack_features;
    memset(&ack_features, 0, sizeof(ack_features));
    ack_features.protocol = IPPROTO_TCP;
    ack_features.src_ip = rte_cpu_to_be_32(0x0B000001); // Different source!
    ack_features.dst_ip = rte_cpu_to_be_32(0xC0A80101);
    ack_features.src_port = 12345;
    ack_features.dst_port = 80;
    ack_features.tcp_flags = RTE_TCP_ACK_FLAG;
    ack_features.tcp_seq = 1001;
    ack_features.tcp_ack = cookie_isn + 1;

    syn_proxy_reset_stats();
    struct syn_proxy_result ack_result;
    syn_proxy_process_packet(ack, &ack_features, 0, test_pool, &ack_result, 0, NULL);

    // Cookie from different source should be invalid (source IP is part of hash):
    // not proxied, no server connection, rejected by the Stage 8b check, while
    // the same cookie still validates for the source it was issued to
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, ack_result.action,
                   "Cookie from different source must not be proxied");
    TEST_ASSERT(ack_result.reply_pkt == NULL,
                "Cookie from different source must not open a server connection");

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, stats.cookies_valid, "Spoofed cookie must not count as valid");
    TEST_ASSERT(!syn_proxy_quick_cookie_check(ack_features.src_ip, ack_features.dst_ip,
                                              ack_features.src_port, ack_features.dst_port,
                                              ack_features.tcp_ack),
                "Cookie from different source should fail the Stage 8b cookie check");
    TEST_ASSERT(syn_proxy_quick_cookie_check(syn_features.src_ip, syn_features.dst_ip,
                                             syn_features.src_port, syn_features.dst_port,
                                             cookie_isn + 1),
                "Cookie should still validate for its own source");

    rte_pktmbuf_free(syn);
    rte_pktmbuf_free(ack);
    syn_proxy_cleanup();
}

// ==================== Integer Overflow Test ====================

void test_syn_cookie_integer_overflow(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    // Test with maximum values that could cause overflow
    struct rte_mbuf *syn = create_syn_packet(0xFFFFFFFF, 0xFFFFFFFF, 65535, 65535, 0xFFFFFFFF);
    TEST_ASSERT(syn != NULL, "Failed to create SYN packet");

    struct packet_features features;
    memset(&features, 0, sizeof(features));
    features.protocol = IPPROTO_TCP;
    features.src_ip = 0xFFFFFFFF;
    features.dst_ip = 0xFFFFFFFF;
    features.src_port = 65535;
    features.dst_port = 65535;
    features.tcp_flags = RTE_TCP_SYN_FLAG;
    features.tcp_seq = 0xFFFFFFFF;

    struct syn_proxy_result result;
    // Should not crash or produce undefined behavior
    int ret = syn_proxy_process_packet(syn, &features, 0, test_pool, &result, 0, &tcp_flood_anom);
    rte_pktmbuf_free(syn);

    // Result should be valid action (not garbage)
    TEST_ASSERT(result.action >= SYN_PROXY_FORWARD && result.action <= SYN_PROXY_ERROR,
                "Action should be valid enum value");
    TEST_ASSERT_EQ(0, ret, "Challenge should not report an error");
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, result.action, "Should challenge SYN with cookie");
    TEST_ASSERT(result.reply_pkt != NULL, "Should generate reply packet");

    struct rte_tcp_hdr *tcp = reply_tcp_hdr(result.reply_pkt);
    uint32_t cookie = rte_be_to_cpu_32(tcp->sent_seq);
    uint32_t synack_ack = rte_be_to_cpu_32(tcp->recv_ack);
    uint16_t synack_dport = rte_be_to_cpu_16(tcp->dst_port);
    rte_pktmbuf_free(result.reply_pkt);
    TEST_ASSERT_EQ(0, synack_ack, "SYN-ACK should acknowledge ISN 0xFFFFFFFF + 1, wrapped to 0");
    TEST_ASSERT_EQ(65535, synack_dport, "SYN-ACK should go to client port 65535");

    // The client's ACK: sequence 0xFFFFFFFF + 1 wraps to 0
    struct syn_proxy_result res;
    send_cookie_ack(0xFFFFFFFF, 0xFFFFFFFF, 65535, 65535, 0xFFFFFFFF, cookie, &res);
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, res.action, "Valid cookie should open a server connection");
    TEST_ASSERT_EQ(SYN_PROXY_CONNECTING, res.conn_state, "Valid cookie should leave state CONNECTING");
    TEST_ASSERT(res.reply_pkt != NULL, "Valid cookie should produce the SYN to the server");
    uint32_t proxy_isn = rte_be_to_cpu_32(reply_tcp_hdr(res.reply_pkt)->sent_seq);
    uint16_t syn_dport = rte_be_to_cpu_16(reply_tcp_hdr(res.reply_pkt)->dst_port);
    rte_pktmbuf_free(res.reply_pkt);
    TEST_ASSERT_EQ(65535, syn_dport, "SYN should go to server port 65535");

    // Server SYN-ACK with ISN 0xFFFFFFFF: the proxy's ACK acknowledges 0
    send_tcp(DIRECTION_OUTBOUND, 0xFFFFFFFF, 0xFFFFFFFF, 65535, 65535,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 0xFFFFFFFF, proxy_isn + 1, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, res.action, "Server SYN-ACK should be answered");
    TEST_ASSERT_EQ(SYN_PROXY_ESTABLISHED, res.conn_state, "Server SYN-ACK should establish the connection");
    TEST_ASSERT(res.reply_pkt != NULL, "Proxy should send the ACK to the server");
    uint32_t ack_seq = rte_be_to_cpu_32(reply_tcp_hdr(res.reply_pkt)->sent_seq);
    uint32_t ack_ack = rte_be_to_cpu_32(reply_tcp_hdr(res.reply_pkt)->recv_ack);
    rte_pktmbuf_free(res.reply_pkt);
    TEST_ASSERT_EQ(proxy_isn + 1, ack_seq, "ACK to the server should follow the proxy ISN");
    TEST_ASSERT_EQ(0, ack_ack, "ACK to the server should acknowledge ISN 0xFFFFFFFF + 1, wrapped to 0");

    // Client data across the wrap: translated into the server's sequence space
    struct rte_mbuf *data = create_tcp_packet(0xFFFFFFFF, 0xFFFFFFFF, 65535, 65535,
                                              RTE_TCP_ACK_FLAG, 0, cookie + 1);
    TEST_ASSERT(data != NULL, "Failed to create ACK packet");
    struct packet_features data_features = tcp_features(0xFFFFFFFF, 0xFFFFFFFF, 65535, 65535,
                                                        RTE_TCP_ACK_FLAG, 0, cookie + 1);
    syn_proxy_process_packet(data, &data_features, 0, test_pool, &res, 0, NULL);
    uint32_t fwd_seq = rte_be_to_cpu_32(reply_tcp_hdr(data)->sent_seq);
    uint32_t fwd_ack = rte_be_to_cpu_32(reply_tcp_hdr(data)->recv_ack);
    rte_pktmbuf_free(data);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Established connection should be forwarded");
    TEST_ASSERT(res.packet_modified, "Established connection should be translated");
    TEST_ASSERT_EQ(proxy_isn + 1, fwd_seq, "Client sequence should map to the proxy ISN + 1");
    TEST_ASSERT_EQ(0, fwd_ack, "Client ACK should map to the server ISN + 1, wrapped to 0");

    syn_proxy_cleanup();
}

// ==================== Cleanup Tests ====================

void test_syn_proxy_cleanup_connections(void) {
    init_default_config();
    default_config.connect_timeout_ms = 1; // Very short timeout
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    // Create some connections: five proxied connections wait on the server
    // (CONNECTING) ...
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_EQ(SYN_PROXY_REPLY,
                       cookie_handshake(0x0A000001 + i, 0xC0A80101, 12345 + i, 80, 1000, NULL),
                       "Valid cookie should open a server connection");
    }

    // ... and a sixth completes the server handshake (ESTABLISHED)
    uint32_t proxy_isn = 0;
    TEST_ASSERT_EQ(SYN_PROXY_REPLY,
                   cookie_handshake(0x0A000006, 0xC0A80101, 12350, 80, 1000, &proxy_isn),
                   "Valid cookie should open a server connection");
    struct syn_proxy_result res;
    send_tcp(DIRECTION_OUTBOUND, 0xC0A80101, 0x0A000006, 80, 12350,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 5000, proxy_isn + 1, NULL, &res);
    if (res.reply_pkt) {
        rte_pktmbuf_free(res.reply_pkt);
    }
    TEST_ASSERT_EQ(SYN_PROXY_ESTABLISHED, res.conn_state, "Server SYN-ACK should establish the connection");

    // Wait for timeout
    rte_delay_ms(10);

    // Cleanup should remove timed out connections: the ones still waiting on
    // the server, not the established one (it ages by the idle timeout)
    uint32_t cleaned = syn_proxy_cleanup_connections();

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(5, cleaned, "Connections waiting on the server should time out");
    TEST_ASSERT_EQ(5, stats.server_timeout, "Each should count as a server timeout");
    TEST_ASSERT_EQ(1, stats.connections_active, "The established connection should stay");

    // A timed-out connection's tuple can be proxied again
    TEST_ASSERT_EQ(SYN_PROXY_REPLY,
                   cookie_handshake(0x0A000001, 0xC0A80101, 12345, 80, 1000, NULL),
                   "Timed-out tuple should open a new server connection");

    syn_proxy_cleanup();
}

// ==================== Connection Release Tests ====================

// Open count connections client:base_port+i -> server:80 under normal load,
// where the SYN is bypassed and leaves a BYPASSED entry (if there is room).
// Returns the number of SYNs bypassed.
static int fill_with_bypassed(uint32_t client, uint32_t server, uint16_t base_port, int count) {
    int bypassed = 0;
    for (int i = 0; i < count; i++) {
        struct syn_proxy_result res;
        send_tcp(DIRECTION_INBOUND, client, server, base_port + i, 80,
                 RTE_TCP_SYN_FLAG, 1000, 0, NULL, &res);
        if (res.reply_pkt) {
            rte_pktmbuf_free(res.reply_pkt);
        }
        if (res.action == SYN_PROXY_BYPASS) {
            bypassed++;
        }
    }
    return bypassed;
}

void test_syn_proxy_bypassed_released_on_close(void) {
    init_default_config();
    default_config.max_connections = 16;
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    const uint32_t client = 0x0A010001;
    const uint32_t server = 0xC0A80101;
    struct syn_proxy_result res;
    struct syn_proxy_stats stats;

    // Normal load: every SYN goes to the server unchallenged and leaves a
    // BYPASSED entry, until the table is full
    TEST_ASSERT_EQ(16, fill_with_bypassed(client, server, 40000, 16),
                   "Normal-load SYNs should be bypassed");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(16, stats.connections_active, "Bypassed connections should fill the table");

    // One more normal-load SYN finds no room. It still goes to the server
    // unchallenged, only without an entry, so nothing is dropped.
    send_tcp(DIRECTION_INBOUND, client, server, 40016, 80, RTE_TCP_SYN_FLAG, 1000, 0, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, res.action, "Normal-load SYN to a full table should be bypassed");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(16, stats.connections_active, "A full table should not grow");
    TEST_ASSERT_EQ(0, stats.table_full_drops, "A bypassed SYN should not count as a table-full drop");

    // While they are open, a valid cookie under attack finds no room
    TEST_ASSERT_EQ(SYN_PROXY_DROP, cookie_handshake(0x0A020001, server, 50000, 80, 7000, NULL),
                   "Valid cookie should be dropped while the table is full");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(1, stats.table_full_drops, "The dropped valid cookie should count as a table-full drop");

    // The bypassed connections end. Their packets are still forwarded
    // unmodified; the entry is released when the connection is over.
    // Ports 40000-40003: the client resets
    for (int i = 0; i < 4; i++) {
        send_tcp(DIRECTION_INBOUND, client, server, 40000 + i, 80,
                 RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG, 1001, 2001, NULL, &res);
        TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Client RST should be forwarded");
        TEST_ASSERT(!res.packet_modified, "Client RST should not be translated");
    }
    // Ports 40004-40007: the server resets
    for (int i = 4; i < 8; i++) {
        send_tcp(DIRECTION_OUTBOUND, server, client, 80, 40000 + i,
                 RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG, 2001, 1001, NULL, &res);
        TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Server RST should be forwarded");
        TEST_ASSERT(!res.packet_modified, "Server RST should not be translated");
    }
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(8, stats.connections_active, "RST should release the bypassed entry");

    // Ports 40008-40011: the client closes first. A half-closed connection and
    // one waiting for its last ACK keep their entry.
    for (int i = 8; i < 12; i++) {
        send_tcp(DIRECTION_INBOUND, client, server, 40000 + i, 80,
                 RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 1001, 2001, NULL, &res);
        TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Client FIN should be forwarded");
        TEST_ASSERT_EQ(SYN_PROXY_BYPASSED, res.conn_state, "Client FIN should find the bypassed entry");
        send_tcp(DIRECTION_OUTBOUND, server, client, 80, 40000 + i,
                 RTE_TCP_ACK_FLAG, 2001, 1002, NULL, &res);
        TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Server ACK of the client FIN should be forwarded");
        send_tcp(DIRECTION_OUTBOUND, server, client, 80, 40000 + i,
                 RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 2001, 1002, NULL, &res);
        TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Server FIN should be forwarded");
    }
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(8, stats.connections_active, "Entries should stay until the last ACK");
    for (int i = 8; i < 12; i++) {
        send_tcp(DIRECTION_INBOUND, client, server, 40000 + i, 80,
                 RTE_TCP_ACK_FLAG, 1002, 2002, NULL, &res);
        TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Last ACK should be forwarded");
        TEST_ASSERT(!res.packet_modified, "Last ACK should not be translated");
    }
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(4, stats.connections_active, "Last ACK after both FINs should release the entry");

    // Ports 40012-40015: the server closes first
    for (int i = 12; i < 16; i++) {
        send_tcp(DIRECTION_OUTBOUND, server, client, 80, 40000 + i,
                 RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 2001, 1001, NULL, &res);
        TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Server FIN should be forwarded");
        send_tcp(DIRECTION_INBOUND, client, server, 40000 + i, 80,
                 RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 1001, 2002, NULL, &res);
        TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Client FIN should be forwarded");
        send_tcp(DIRECTION_OUTBOUND, server, client, 80, 40000 + i,
                 RTE_TCP_ACK_FLAG, 2002, 1002, NULL, &res);
        TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Last ACK should be forwarded");
    }
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, stats.connections_active, "Every ended connection should release its entry");
    TEST_ASSERT_EQ(16, stats.connections_closed, "Each release should count as closed");

    // Under attack the valid cookie now gets a connection
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, cookie_handshake(0x0A020001, server, 50000, 80, 7000, NULL),
                   "Valid cookie should open a server connection once entries are released");

    // New bypassed connections fill the released entries again, including the
    // ones that saw both FINs. Each starts with no FIN seen, so its first ACK
    // does not release it.
    TEST_ASSERT_EQ(15, fill_with_bypassed(client, server, 41000, 15),
                   "Normal-load SYNs should be bypassed");
    for (int i = 0; i < 15; i++) {
        send_tcp(DIRECTION_INBOUND, client, server, 41000 + i, 80,
                 RTE_TCP_ACK_FLAG, 1001, 2001, NULL, &res);
        TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Bypassed connection should be forwarded");
    }
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(16, stats.connections_active, "Open connections should keep their entries");

    syn_proxy_cleanup();
}

void test_syn_proxy_bypassed_idle_aged(void) {
    init_default_config();
    default_config.max_connections = 16;
    default_config.idle_timeout_sec = 1;
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    const uint32_t client = 0x0A010002;
    const uint32_t server = 0xC0A80101;
    struct syn_proxy_result res;
    struct syn_proxy_stats stats;

    TEST_ASSERT_EQ(16, fill_with_bypassed(client, server, 40000, 16),
                   "Normal-load SYNs should be bypassed");
    TEST_ASSERT_EQ(SYN_PROXY_DROP, cookie_handshake(0x0A020002, server, 50000, 80, 7000, NULL),
                   "Valid cookie should be dropped while the table is full");

    // Bypassed connections that end unseen age by the idle timeout, like
    // proxied ones. One of them stays active.
    rte_delay_ms(1500);
    send_tcp(DIRECTION_INBOUND, client, server, 40000, 80, RTE_TCP_ACK_FLAG, 1001, 2001, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Bypassed connection should be forwarded");

    uint32_t cleaned = syn_proxy_cleanup_connections();
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(15, cleaned, "Idle bypassed connections should age out");
    TEST_ASSERT_EQ(15, stats.connections_timeout, "Each should count as an idle timeout");
    TEST_ASSERT_EQ(1, stats.connections_active, "The active bypassed connection should stay");

    TEST_ASSERT_EQ(SYN_PROXY_REPLY, cookie_handshake(0x0A020002, server, 50000, 80, 7000, NULL),
                   "Valid cookie should open a server connection once idle entries age out");

    syn_proxy_cleanup();
}

// ==================== Re-initialization and Options Tests ====================

void test_syn_proxy_reinit_resets_half_open(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    // One source opens proxied connections that all wait on the server,
    // until the per-source half-open limit drops the next one
    const uint32_t client = 0x0A050001;
    uint32_t opened = 0;
    enum syn_proxy_action action = SYN_PROXY_REPLY;
    while (opened < 256) {
        action = cookie_handshake(client, 0xC0A80101, 20000 + opened, 80, 1000, NULL);
        if (action != SYN_PROXY_REPLY) break;
        opened++;
    }

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(SYN_PROXY_DROP, action, "Half-open limit should drop the next connection");
    TEST_ASSERT(opened > 0, "Source should open some connections first");
    TEST_ASSERT_EQ(1, stats.table_full_drops, "Limit drop should be counted");
    TEST_ASSERT_EQ(opened, stats.connections_active, "Each open connection should hold an entry");

    // Re-init: the old table and its half-open connections are gone
    syn_proxy_cleanup();
    syn_proxy_init(&default_config);

    TEST_ASSERT_EQ(SYN_PROXY_REPLY, cookie_handshake(client, 0xC0A80101, 20000, 80, 1000, NULL),
                   "After re-init the source should have no half-open connections");

    syn_proxy_cleanup();
}

void test_syn_proxy_server_syn_without_options(void) {
    init_default_config();
    syn_proxy_init(&default_config);

    // Client SYN with no TCP options (send_tcp packets carry none)
    uint32_t cookie;
    TEST_ASSERT(get_cookie(0x0A060001, 0xC0A80101, 34567, 80, 3000, &cookie),
                "SYN should be challenged with a cookie");

    struct syn_proxy_result res;
    send_cookie_ack(0x0A060001, 0xC0A80101, 34567, 80, 3000, cookie, &res);
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, res.action, "Valid cookie should open a server connection");
    TEST_ASSERT(res.reply_pkt != NULL, "Valid cookie should produce the SYN to the server");

    // The SYN to the server carries the MSS from the cookie (the 536 default
    // for a SYN without MSS) and no option the client did not offer
    const struct rte_tcp_hdr *tcp = reply_tcp_hdr(res.reply_pkt);
    const uint8_t *mss_opt = find_tcp_option(tcp, 2);
    uint16_t mss = mss_opt ? (uint16_t)((mss_opt[2] << 8) | mss_opt[3]) : 0;
    bool has_wscale = find_tcp_option(tcp, 3) != NULL;
    bool has_sack = find_tcp_option(tcp, 4) != NULL;
    bool has_timestamp = find_tcp_option(tcp, 8) != NULL;
    rte_pktmbuf_free(res.reply_pkt);

    TEST_ASSERT_EQ(536, mss, "SYN to the server should carry the cookie MSS");
    TEST_ASSERT(!has_wscale, "SYN to the server must not offer window scaling the client did not offer");
    TEST_ASSERT(!has_sack, "SYN to the server must not offer SACK the client did not offer");
    TEST_ASSERT(!has_timestamp, "SYN to the server must not carry timestamps the client did not send");

    syn_proxy_cleanup();
}

void test_syn_cookie_ack_zero_counted_once(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    // ACK number 0 means cookie 0xFFFFFFFF, which validate_cookie() rejects
    // outright. Like any other bad cookie it counts once.
    TEST_ASSERT(!syn_proxy_quick_cookie_check(rte_cpu_to_be_32(0x0A040001),
                                              rte_cpu_to_be_32(0xC0A80101),
                                              12345, 80, 0),
                "ACK 0 should fail the Stage 8b cookie check");

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(1, stats.cookies_invalid, "ACK 0 should count one invalid cookie");
    TEST_ASSERT_EQ(0, stats.cookies_expired, "ACK 0 is not an expired cookie");

    // The same on the packet path: a pure ACK 0 with no connection
    struct syn_proxy_result res;
    send_tcp(DIRECTION_INBOUND, 0x0A040001, 0xC0A80101, 12345, 80,
             RTE_TCP_ACK_FLAG, 1001, 0, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, res.action, "ACK 0 must not be proxied");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(2, stats.cookies_invalid, "Each ACK 0 should count one invalid cookie");
    TEST_ASSERT_EQ(0, stats.cookies_valid, "ACK 0 must not count as valid");

    syn_proxy_cleanup();
}

// ==================== Configuration Tests ====================

// Runs before main() makes a Layer 1 config active
void test_syn_proxy_challenge_without_config(void) {
    TEST_ASSERT(layer1_config_get() == NULL, "No Layer 1 config should be active yet");
    init_default_config();
    syn_proxy_init(&default_config);

    // Global spoofed mode and anomaly are on. With a valid per-IP snapshot they
    // count only through the global circuit breaker, which is a config setting.
    TEST_ASSERT_EQ(0, shared_memory_init(), "Shared memory init should succeed");
    anomaly_set_spoofed_mode(1, 90);
    anomaly_set_level(ANOMALY_LEVEL_HIGH);

    // A destination with per-IP data and no anomaly of its own
    static const struct per_ip_anomaly_snapshot calm_anom = { .valid = true };
    struct packet_features syn = tcp_features(0x0A030001, 0xC0A80101, 45678, 80,
                                              RTE_TCP_SYN_FLAG, 4000, 0);

    // Decide in a child process, so that a crash fails this subtest only
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        _exit(syn_proxy_should_challenge(&syn, &calm_anom) ? 1 : 0);
    }
    int status = 0;
    bool reaped = pid > 0 && waitpid(pid, &status, 0) == pid;

    // With a config that enables the breaker, global spoofed mode trips it
    struct layer1_config breaker_config;
    layer1_config_defaults(&breaker_config);
    breaker_config.global_circuit_breaker = true;
    layer1_config_set_active(&breaker_config);
    bool tripped = syn_proxy_should_challenge(&syn, &calm_anom);

    anomaly_set_spoofed_mode(0, 0);
    anomaly_clear();
    shared_memory_cleanup();
    syn_proxy_cleanup();

    TEST_ASSERT(reaped, "Child process should run the challenge decision");
    TEST_ASSERT_EQ(0, WIFSIGNALED(status) ? WTERMSIG(status) : 0,
                   "Challenge decision must not crash (signal) without an active config");
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "No config: the circuit breaker must not trip");
    TEST_ASSERT(tripped, "Config with the breaker on: global spoofed mode should trip it");
}

// The same circuit breaker in the Layer 1 pipeline's spoofed-mode resolution
// (Stages 8b, 9b, 10 and 12), which reads the active config's breaker setting
void test_layer1_spoofed_mode_without_config(void) {
    TEST_ASSERT_EQ(0, shared_memory_init(), "Shared memory init should succeed");
    anomaly_set_spoofed_mode(1, 90);

    // A destination with per-IP data and no spoofed mode of its own, and one
    // without per-IP data
    static const struct per_ip_anomaly_snapshot calm_anom = { .valid = true };
    static const struct per_ip_anomaly_snapshot no_anom = { .valid = false };

    // No active config. Decide in a child process, so that a crash fails this
    // subtest only.
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        _exit(layer1_effective_spoofed_mode(&calm_anom, IPPROTO_TCP, NULL) ? 1 : 0);
    }
    int status = 0;
    bool reaped = pid > 0 && waitpid(pid, &status, 0) == pid;

    struct layer1_config breaker_config;
    layer1_config_defaults(&breaker_config);
    bool breaker_off = layer1_effective_spoofed_mode(&calm_anom, IPPROTO_TCP, &breaker_config);
    breaker_config.global_circuit_breaker = true;
    bool breaker_on = layer1_effective_spoofed_mode(&calm_anom, IPPROTO_TCP, &breaker_config);
    bool fallback = layer1_effective_spoofed_mode(&no_anom, IPPROTO_TCP, NULL);

    anomaly_set_spoofed_mode(0, 0);
    shared_memory_cleanup();

    TEST_ASSERT(reaped, "Child process should run the spoofed-mode resolution");
    TEST_ASSERT_EQ(0, WIFSIGNALED(status) ? WTERMSIG(status) : 0,
                   "Spoofed-mode resolution must not crash (signal) without an active config");
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "No config: the circuit breaker must not trip");
    TEST_ASSERT(!breaker_off, "Config with the breaker off: per-IP data should decide alone");
    TEST_ASSERT(breaker_on, "Config with the breaker on: global spoofed mode should trip it");
    TEST_ASSERT(fallback, "Without per-IP data the global spoofed mode should apply");
}

// ==================== TCP Option Tests (Cookie Path) ====================

// SYN with the options a Linux client offers: MSS 1460, SACK permitted,
// timestamps and window scale 7 (a 40-byte TCP header)
static struct rte_mbuf *create_syn_with_client_options(uint32_t src_ip, uint32_t dst_ip,
                                                       uint16_t src_port, uint16_t dst_port,
                                                       uint32_t seq_num, uint32_t tsval) {
    struct rte_mbuf *m = create_syn_packet(src_ip, dst_ip, src_port, dst_port, seq_num);
    if (!m) return NULL;

    const uint8_t opts[20] = {
        2, 4, 0x05, 0xB4,                       // MSS 1460
        4, 2,                                   // SACK permitted
        8, 10,                                  // Timestamps: TSval, TSecr 0
        (uint8_t)(tsval >> 24), (uint8_t)(tsval >> 16),
        (uint8_t)(tsval >> 8), (uint8_t)tsval,
        0, 0, 0, 0,
        1,                                      // NOP
        3, 3, 7,                                // Window scale, shift 7
    };
    memcpy(reply_tcp_hdr(m) + 1, opts, sizeof(opts));
    return m;
}

// The options of a SYN or SYN-ACK that the two legs of a cookie connection
// must agree on
struct option_offers {
    uint16_t mss;       // 0 if absent
    bool wscale;
    bool sack;
    bool timestamp;
};

static struct option_offers read_option_offers(const struct rte_tcp_hdr *tcp) {
    struct option_offers o;
    const uint8_t *mss_opt = find_tcp_option(tcp, 2);
    o.mss = mss_opt ? (uint16_t)((mss_opt[2] << 8) | mss_opt[3]) : 0;
    o.wscale = find_tcp_option(tcp, 3) != NULL;
    o.sack = find_tcp_option(tcp, 4) != NULL;
    o.timestamp = find_tcp_option(tcp, 8) != NULL;
    return o;
}

// A challenged handshake, in the given mode, of a client that offers window
// scaling, SACK and timestamps. *client_leg gets the options of the proxy's
// SYN-ACK, *server_leg those of its SYN to the server. Returns NULL, or what
// went wrong.
static const char *cookie_leg_offers(int mode, uint16_t client_port,
                                     struct option_offers *client_leg,
                                     struct option_offers *server_leg) {
    const uint32_t client = 0x0A080001, server = 0xC0A80101;
    struct syn_proxy_result res;

    syn_proxy_set_mode(mode);
    struct rte_mbuf *syn = create_syn_with_client_options(client, server, client_port, 80,
                                                          6000, 123456);
    if (!syn) return "Failed to create SYN packet";
    struct packet_features features = tcp_features(client, server, client_port, 80,
                                                   RTE_TCP_SYN_FLAG, 6000, 0);
    syn_proxy_process_packet(syn, &features, DIRECTION_INBOUND, test_pool, &res, 0,
                             &tcp_flood_anom);
    syn_proxy_set_mode(-1);

    // Stateful mode answers in a new mbuf; stateless mode turns the SYN itself
    // into the SYN-ACK
    struct rte_mbuf *synack = NULL;
    if (mode == SYN_PROXY_MODE_STATEFUL && res.action == SYN_PROXY_REPLY) {
        synack = res.reply_pkt;
    } else if (mode == SYN_PROXY_MODE_STATELESS && res.action == SYN_PROXY_REPLY_INPLACE) {
        synack = syn;
    }
    if (synack) {
        *client_leg = read_option_offers(reply_tcp_hdr(synack));
    }
    uint32_t cookie = synack ? rte_be_to_cpu_32(reply_tcp_hdr(synack)->sent_seq) : 0;
    if (res.reply_pkt) {
        rte_pktmbuf_free(res.reply_pkt);
    }
    rte_pktmbuf_free(syn);
    if (!synack) return "SYN should be challenged with a SYN-ACK";

    send_cookie_ack(client, server, client_port, 80, 6000, cookie, &res);
    if (res.action != SYN_PROXY_REPLY || res.conn_state != SYN_PROXY_CONNECTING ||
        !res.reply_pkt) {
        if (res.reply_pkt) {
            rte_pktmbuf_free(res.reply_pkt);
        }
        return "Valid cookie should produce the SYN to the server";
    }
    *server_leg = read_option_offers(reply_tcp_hdr(res.reply_pkt));
    rte_pktmbuf_free(res.reply_pkt);
    return NULL;
}

void test_syn_proxy_cookie_path_option_offers(void) {
    init_default_config();
    syn_proxy_init(&default_config);

    // The proxy rewrites only seq and ack of a proxied connection: windows,
    // timestamps and SACK blocks pass unchanged. So what its SYN-ACK grants
    // the client, its SYN must offer the server, and neither may offer an
    // option that would need translating.
    struct option_offers client_leg, server_leg;
    const char *err;

    // Stateless (attack) mode: the SYN turned into the SYN-ACK in place
    err = cookie_leg_offers(SYN_PROXY_MODE_STATELESS, 46001, &client_leg, &server_leg);
    TEST_ASSERT(err == NULL, err);
    TEST_ASSERT_EQ(1460, client_leg.mss, "Stateless: the SYN-ACK should offer MSS 1460");
    TEST_ASSERT_EQ(1460, server_leg.mss, "Stateless: the SYN to the server should carry the cookie MSS");
    TEST_ASSERT_EQ(client_leg.wscale, server_leg.wscale,
                   "Stateless: both legs should agree on window scaling");
    TEST_ASSERT_EQ(client_leg.sack, server_leg.sack,
                   "Stateless: SACK should be offered to the server exactly when granted to the client");
    TEST_ASSERT_EQ(client_leg.timestamp, server_leg.timestamp,
                   "Stateless: both legs should agree on timestamps");
    TEST_ASSERT(!client_leg.wscale && !client_leg.timestamp && !client_leg.sack,
                "Stateless: the cookie path should offer no option it cannot translate");

    // Stateful mode: the SYN-ACK built in a new mbuf from the parsed SYN options
    err = cookie_leg_offers(SYN_PROXY_MODE_STATEFUL, 46002, &client_leg, &server_leg);
    TEST_ASSERT(err == NULL, err);
    TEST_ASSERT_EQ(1460, client_leg.mss, "Stateful: the SYN-ACK should offer MSS 1460");
    TEST_ASSERT_EQ(1460, server_leg.mss, "Stateful: the SYN to the server should carry the cookie MSS");
    TEST_ASSERT_EQ(client_leg.wscale, server_leg.wscale,
                   "Stateful: both legs should agree on window scaling");
    TEST_ASSERT_EQ(client_leg.sack, server_leg.sack,
                   "Stateful: SACK should be offered to the server exactly when granted to the client");
    TEST_ASSERT_EQ(client_leg.timestamp, server_leg.timestamp,
                   "Stateful: both legs should agree on timestamps");
    TEST_ASSERT(!client_leg.wscale && !client_leg.timestamp && !client_leg.sack,
                "Stateful: the cookie path should offer no option it cannot translate");

    syn_proxy_cleanup();
}

// ==================== Connection Table Accounting Tests ====================

void test_syn_proxy_cleanup_drains_all_due(void) {
    init_default_config();
    default_config.max_connections = 1024;
    default_config.idle_timeout_sec = 1;
    // Keep all 600 SYNs below the rate that would get them challenged
    default_config.challenge_threshold = 1000000;
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    // 600 normal-load connections, more than one 256-key cleanup batch
    TEST_ASSERT_EQ(600, fill_with_bypassed(0x0A0A0001, 0xC0A80101, 20000, 600),
                   "Normal-load SYNs should be bypassed");
    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(600, stats.connections_active, "Each bypassed connection should hold an entry");

    // All of them go idle past the 1 s idle timeout
    rte_delay_ms(1500);

    uint32_t cleaned = syn_proxy_cleanup_connections();
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(600, cleaned, "One cleanup pass should delete every due entry");
    TEST_ASSERT_EQ(600, stats.connections_timeout, "Each deleted entry should count as one idle timeout");
    TEST_ASSERT_EQ(0, stats.connections_active, "No idle entry should remain");

    // Nothing is due any more, so a second pass deletes and counts nothing
    cleaned = syn_proxy_cleanup_connections();
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, cleaned, "A second pass should find nothing due");
    TEST_ASSERT_EQ(600, stats.connections_timeout, "A second pass should count no timeout");

    syn_proxy_cleanup();
}

// A mempool with no objects whose every allocation first runs the connection
// cleanup and then fails. Given to the proxy as its mempool, it makes one
// interleaving of the maintenance lcore and a worker lcore deterministic:
// syn_proxy_cleanup_connections() deletes a connection while
// syn_proxy_process_packet() holds it and builds a packet for it. The failed
// allocation then makes the packet path free the same connection.
// (race_pool is declared with the fixtures, which free it.)
static uint32_t race_cleaned = 0;

static int race_ops_alloc(struct rte_mempool *mp) {
    (void)mp;
    return 0;
}

static void race_ops_free(struct rte_mempool *mp) {
    (void)mp;
}

static int race_ops_enqueue(struct rte_mempool *mp, void * const *obj_table, unsigned int n) {
    (void)mp;
    (void)obj_table;
    (void)n;
    return 0;
}

static int race_ops_dequeue(struct rte_mempool *mp, void **obj_table, unsigned int n) {
    (void)mp;
    (void)obj_table;
    (void)n;
    rte_delay_ms(2);  // Past the subtest's timeouts
    race_cleaned += syn_proxy_cleanup_connections();
    return -ENOBUFS;
}

static unsigned int race_ops_get_count(const struct rte_mempool *mp) {
    (void)mp;
    return 0;
}

static struct rte_mempool_ops race_ops = {
    .name = "syn_proxy_test_race",
    .alloc = race_ops_alloc,
    .free = race_ops_free,
    .enqueue = race_ops_enqueue,
    .dequeue = race_ops_dequeue,
    .get_count = race_ops_get_count,
};

RTE_MEMPOOL_REGISTER_OPS(race_ops);

static struct rte_mempool *get_race_pool(void) {
    if (!race_pool) {
        race_pool = rte_mempool_create_empty("syn_proxy_race_pool", 64,
                                             sizeof(struct rte_mbuf) + RTE_MBUF_DEFAULT_BUF_SIZE,
                                             0, sizeof(struct rte_pktmbuf_pool_private),
                                             rte_socket_id(), 0);
        if (race_pool && rte_mempool_set_ops_byname(race_pool, race_ops.name, NULL) != 0) {
            rte_mempool_free(race_pool);
            race_pool = NULL;
        }
    }
    return race_pool;
}

void test_syn_proxy_free_after_cleanup_counts_once(void) {
    struct rte_mempool *pool = get_race_pool();
    TEST_ASSERT(pool != NULL, "Failed to create the interleaving mempool");
    const uint32_t server = 0xC0A80101;
    struct syn_proxy_result res;
    struct syn_proxy_stats stats;

    // 1. A valid cookie opens a CONNECTING entry. While the proxy builds the
    // SYN to the server, the cleanup deletes the entry for its 1 ms connect
    // timeout; the allocation fails and the packet path frees it as well.
    init_default_config();
    default_config.connect_timeout_ms = 1;
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    race_cleaned = 0;

    uint32_t cookie;
    TEST_ASSERT(get_cookie(0x0A0B0001, server, 42001, 80, 1000, &cookie),
                "SYN should be challenged with a cookie");
    send_tcp_via(pool, DIRECTION_INBOUND, 0x0A0B0001, server, 42001, 80,
                 RTE_TCP_ACK_FLAG, 1001, cookie + 1, NULL, &res);
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(SYN_PROXY_ERROR, res.action, "A failed SYN to the server should be an error");
    TEST_ASSERT_EQ(1, race_cleaned, "The cleanup should delete the connection first");
    TEST_ASSERT_EQ(1, stats.server_timeout, "The cleanup's delete should count as a server timeout");
    TEST_ASSERT_EQ(0, stats.connections_active,
                   "An entry deleted by the cleanup and then freed should be counted out once");
    TEST_ASSERT_EQ(0, stats.connections_closed, "The packet path's second delete should not count a close");

    // The tuple and its source's half-open slot are free again
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, cookie_handshake(0x0A0B0001, server, 42001, 80, 1000, NULL),
                   "The tuple should open a new server connection");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(1, stats.connections_active, "The new connection should be counted once");
    syn_proxy_cleanup();

    // 2. The server's SYN-ACK establishes an entry. While the proxy builds
    // its ACK to the server, the cleanup deletes the entry as idle (idle
    // timeout 0); the allocation fails and the packet path frees it as well.
    init_default_config();
    default_config.idle_timeout_sec = 0;
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    race_cleaned = 0;

    uint32_t proxy_isn = 0;
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, cookie_handshake(0x0A0B0002, server, 42002, 80, 1000, &proxy_isn),
                   "Valid cookie should open a server connection");
    send_tcp_via(pool, DIRECTION_OUTBOUND, server, 0x0A0B0002, 80, 42002,
                 RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 7000, proxy_isn + 1, NULL, &res);
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(SYN_PROXY_ERROR, res.action, "A failed ACK to the server should be an error");
    TEST_ASSERT_EQ(1, race_cleaned, "The cleanup should delete the connection first");
    TEST_ASSERT_EQ(1, stats.connections_timeout, "The cleanup's delete should count as an idle timeout");
    TEST_ASSERT_EQ(0, stats.connections_active,
                   "An entry deleted by the cleanup and then freed should be counted out once");
    TEST_ASSERT_EQ(0, stats.connections_closed, "The packet path's second delete should not count a close");

    syn_proxy_cleanup();
}

void test_syn_proxy_bypassed_tuple_reuse(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    const uint32_t client = 0x0A0C0001;
    const uint32_t server = 0xC0A80101;
    struct syn_proxy_result res;
    struct syn_proxy_stats stats;

    TEST_ASSERT_EQ(1, fill_with_bypassed(client, server, 43000, 1),
                   "Normal-load SYN should be bypassed");

    // Both sides send FIN, and the client's last ACK is lost
    send_tcp(DIRECTION_INBOUND, client, server, 43000, 80,
             RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 1001, 2001, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Client FIN should be forwarded");
    send_tcp(DIRECTION_OUTBOUND, server, client, 80, 43000,
             RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 2001, 1002, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Server FIN should be forwarded");

    // The client reuses the 4-tuple. Its SYN starts a new connection on the
    // entry, so the old connection's FINs must not end the new one.
    send_tcp(DIRECTION_INBOUND, client, server, 43000, 80, RTE_TCP_SYN_FLAG, 9000, 0, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "SYN reusing the tuple should be forwarded");
    send_tcp(DIRECTION_OUTBOUND, server, client, 80, 43000,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 30000, 9001, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Server SYN-ACK should be forwarded");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(1, stats.connections_active, "The new connection's SYN-ACK must not release the entry");
    uint64_t invalid_before = stats.cookies_invalid;

    send_tcp(DIRECTION_INBOUND, client, server, 43000, 80, RTE_TCP_ACK_FLAG, 9001, 30001, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The new connection's ACK should be forwarded");
    TEST_ASSERT_EQ(SYN_PROXY_BYPASSED, res.conn_state, "The new connection should keep the bypassed entry");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(invalid_before, stats.cookies_invalid,
                   "The new connection's ACK must not go to cookie validation");

    // The new connection's own close releases the entry
    send_tcp(DIRECTION_INBOUND, client, server, 43000, 80,
             RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 9001, 30001, NULL, &res);
    send_tcp(DIRECTION_OUTBOUND, server, client, 80, 43000,
             RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 30001, 9002, NULL, &res);
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(1, stats.connections_active, "Entry should stay until the last ACK");
    send_tcp(DIRECTION_INBOUND, client, server, 43000, 80, RTE_TCP_ACK_FLAG, 9002, 30002, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Last ACK should be forwarded");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, stats.connections_active, "Last ACK after both FINs should release the entry");

    syn_proxy_cleanup();
}

// ==================== Spoofed-Mode Admission Tests ====================

// Stage 8b of layer1.c in spoofed mode: a non-SYN TCP segment goes on to the
// SYN proxy (Stage 9) only if something vouches for its connection
void test_syn_proxy_spoofed_mode_admits_proxy_connections(void) {
    struct flow_table_config flow_cfg = {
        .max_flows = 1024,
        .idle_timeout_sec = 60,
        .syn_timeout_sec = 5,
        .enable_syn_protection = true,
    };
    TEST_ASSERT_EQ(0, flow_table_init(&flow_cfg), "Flow table init should succeed");
    init_default_config();
    syn_proxy_init(&default_config);

    const uint32_t client = 0x0A090001;
    const uint32_t server = 0xC0A80101;
    const uint32_t isn = 1000, server_isn = 50000, data_len = 1448;
    struct syn_proxy_result res;

    // A proxied connection under attack. The ACK that completes the cookie
    // handshake has no flow yet and passes on its cookie.
    uint32_t cookie, proxy_isn = 0;
    TEST_ASSERT(get_cookie(client, server, 41001, 80, isn, &cookie),
                "SYN should be challenged with a cookie");
    struct packet_features cookie_ack = tcp_features(client, server, 41001, 80,
                                                     RTE_TCP_ACK_FLAG, isn + 1, cookie + 1);
    TEST_ASSERT(layer1_spoofed_tcp_admit(&cookie_ack, true),
                "The ACK that returns the cookie should be admitted");
    send_cookie_ack(client, server, 41001, 80, isn, cookie, &res);
    TEST_ASSERT(res.reply_pkt != NULL, "Valid cookie should produce the SYN to the server");
    proxy_isn = rte_be_to_cpu_32(reply_tcp_hdr(res.reply_pkt)->sent_seq);
    rte_pktmbuf_free(res.reply_pkt);

    // The server completes its handshake and sends 1448 bytes
    send_tcp(DIRECTION_OUTBOUND, server, client, 80, 41001,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, server_isn, proxy_isn + 1, NULL, &res);
    if (res.reply_pkt) {
        rte_pktmbuf_free(res.reply_pkt);
    }
    TEST_ASSERT_EQ(SYN_PROXY_ESTABLISHED, res.conn_state, "Server SYN-ACK should establish the connection");
    send_tcp(DIRECTION_OUTBOUND, server, client, 80, 41001,
             RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, server_isn + 1, proxy_isn + 1, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Server data should be forwarded");

    // The client acknowledges the data. Its ACK number has moved past the
    // cookie, and the connection has no flow: Stage 9 returns before Stage 11
    // for every packet the proxy replies to or forwards.
    struct packet_features ack = tcp_features(client, server, 41001, 80, RTE_TCP_ACK_FLAG,
                                              isn + 1, cookie + 1 + data_len);
    TEST_ASSERT(flow_table_lookup(&ack) == NULL, "The proxied connection should have no flow entry");
    TEST_ASSERT(!syn_proxy_quick_cookie_check(ack.src_ip, ack.dst_ip, ack.src_port, ack.dst_port,
                                              ack.tcp_ack),
                "The client's ACK should no longer carry the cookie");
    TEST_ASSERT(layer1_spoofed_tcp_admit(&ack, true),
                "Spoofed mode should admit the client's ACK on an established proxied connection");

    // A SYN proxy disabled at runtime handles nothing at Stage 9, so its
    // entries vouch for nothing
    syn_proxy_set_enabled(false);
    bool admitted_while_disabled = layer1_spoofed_tcp_admit(&ack, true);
    syn_proxy_set_enabled(true);
    TEST_ASSERT(!admitted_while_disabled, "Entries of a disabled SYN proxy should not count");

    // Stage 9 then handles it from the proxy entry: translated and forwarded
    struct rte_mbuf *m = create_tcp_packet(client, server, 41001, 80, RTE_TCP_ACK_FLAG,
                                           isn + 1, cookie + 1 + data_len);
    TEST_ASSERT(m != NULL, "Failed to create ACK packet");
    syn_proxy_process_packet(m, &ack, DIRECTION_INBOUND, test_pool, &res, 0, NULL);
    uint32_t fwd_ack = rte_be_to_cpu_32(reply_tcp_hdr(m)->recv_ack);
    rte_pktmbuf_free(m);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The admitted ACK should be forwarded");
    TEST_ASSERT(res.packet_modified, "The admitted ACK should be translated");
    TEST_ASSERT_EQ(server_isn + 1 + data_len, fwd_ack, "The ACK should acknowledge the server's data");

    // The client's FIN is admitted the same way
    struct packet_features fin = tcp_features(client, server, 41001, 80,
                                              RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG,
                                              isn + 1, cookie + 1 + data_len);
    TEST_ASSERT(layer1_spoofed_tcp_admit(&fin, true),
                "Spoofed mode should admit the client's FIN on a proxied connection");

    // A connection that was bypassed under normal load has an entry too. It
    // vouches for the connection once the client acknowledges the server's
    // ISN + 1 (the blind cases are in
    // test_syn_proxy_spoofed_mode_bypassed_needs_handshake).
    send_tcp(DIRECTION_INBOUND, client, server, 41002, 80, RTE_TCP_SYN_FLAG, 3000, 0, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, res.action, "Normal-load SYN should be bypassed");
    send_tcp(DIRECTION_OUTBOUND, server, client, 80, 41002,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 7000, 3001, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The server's SYN-ACK should be forwarded");
    struct packet_features bypassed_ack = tcp_features(client, server, 41002, 80,
                                                       RTE_TCP_ACK_FLAG, 3001, 7001);
    TEST_ASSERT(layer1_spoofed_tcp_admit(&bypassed_ack, true),
                "Spoofed mode should admit the client's ACK on a bypassed connection");
    send_tcp(DIRECTION_INBOUND, client, server, 41002, 80, RTE_TCP_ACK_FLAG, 3001, 7001, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The admitted ACK should be forwarded");
    TEST_ASSERT(!res.packet_modified, "A bypassed connection's ACK should not be translated");

    // Nothing vouches for other segments
    struct packet_features stray = tcp_features(client, server, 41003, 80, RTE_TCP_ACK_FLAG,
                                                1, 0xBAD00001);
    TEST_ASSERT(!layer1_spoofed_tcp_admit(&stray, true),
                "An ACK with no flow, no proxy entry and no valid cookie should be dropped");
    struct packet_features stray_rst = tcp_features(client, server, 41003, 80, RTE_TCP_RST_FLAG,
                                                    1, 0);
    TEST_ASSERT(!layer1_spoofed_tcp_admit(&stray_rst, true),
                "A RST with no flow and no proxy entry should be dropped");
    TEST_ASSERT(!layer1_spoofed_tcp_admit(&ack, false),
                "With the SYN proxy disabled for the destination its entry should not count");

    // A flow vouches for its connection, whatever the SYN proxy
    struct packet_features flow_syn = tcp_features(0x0A090002, server, 41004, 80,
                                                   RTE_TCP_SYN_FLAG, 100, 0);
    bool created = false;
    TEST_ASSERT(flow_table_lookup_or_create(&flow_syn, &created) != NULL && created,
                "Flow should be created");
    struct packet_features flow_ack = tcp_features(0x0A090002, server, 41004, 80,
                                                   RTE_TCP_ACK_FLAG, 101, 9);
    TEST_ASSERT(layer1_spoofed_tcp_admit(&flow_ack, false), "A segment with a flow should be admitted");

    // A pure SYN always goes on to the SYN proxy, which challenges it
    struct packet_features syn = tcp_features(0x0A090003, server, 41005, 80,
                                              RTE_TCP_SYN_FLAG, 100, 0);
    TEST_ASSERT(layer1_spoofed_tcp_admit(&syn, true), "A SYN should be admitted");

    // Once the client resets the proxied connection, its entry is gone and
    // its later segments are no longer admitted. The RST itself carries no
    // ACK, so only the proxy entry admits it.
    struct packet_features rst = tcp_features(client, server, 41001, 80, RTE_TCP_RST_FLAG,
                                              isn + 1, 0);
    TEST_ASSERT(layer1_spoofed_tcp_admit(&rst, true),
                "Spoofed mode should admit the client's RST on a proxied connection");
    send_tcp(DIRECTION_INBOUND, client, server, 41001, 80, RTE_TCP_RST_FLAG,
             isn + 1, 0, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "Client RST should be forwarded");
    TEST_ASSERT(!layer1_spoofed_tcp_admit(&ack, true),
                "A reset connection's later ACK should not be admitted");

    syn_proxy_cleanup();
    flow_table_cleanup();
}

// Stage 8b in spoofed mode, for connections bypassed under normal load. A SYN
// that is not challenged leaves an entry, so a spoofed SYN in calm conditions
// can plant one. The entry vouches for a flowless segment only once the client
// has acknowledged the server's ISN + 1, or for the segment that does.
void test_syn_proxy_spoofed_mode_bypassed_needs_handshake(void) {
    // An empty flow table: nothing but the proxy vouches for these tuples
    struct flow_table_config flow_cfg = {
        .max_flows = 1024,
        .idle_timeout_sec = 60,
        .syn_timeout_sec = 5,
        .enable_syn_protection = true,
    };
    TEST_ASSERT_EQ(0, flow_table_init(&flow_cfg), "Flow table init should succeed");
    init_default_config();
    syn_proxy_init(&default_config);

    const uint32_t server = 0xC0A80101;
    const uint32_t planted = 0x0A110001, client = 0x0A110002, retry = 0x0A110003;
    struct syn_proxy_result res;
    struct packet_features seg;

    // 1. A spoofed SYN in calm conditions plants a BYPASSED entry
    send_tcp(DIRECTION_INBOUND, planted, server, 46001, 80, RTE_TCP_SYN_FLAG, 100, 0, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, res.action, "Normal-load SYN should be bypassed");
    seg = tcp_features(planted, server, 46001, 80, RTE_TCP_ACK_FLAG, 101, 0);
    TEST_ASSERT(syn_proxy_is_proxied(&seg, DIRECTION_INBOUND), "The SYN should leave a bypassed entry");

    // Its sender's data, FIN and RST: nothing vouches for them
    seg = tcp_features(planted, server, 46001, 80, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG,
                       101, 0x12345678);
    TEST_ASSERT(!layer1_spoofed_tcp_admit(&seg, true),
                "A planted entry must not admit data in spoofed mode");
    seg.tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
    TEST_ASSERT(!layer1_spoofed_tcp_admit(&seg, true), "A planted entry must not admit a FIN");
    seg.tcp_flags = RTE_TCP_RST_FLAG;
    TEST_ASSERT(!layer1_spoofed_tcp_admit(&seg, true), "A planted entry must not admit a RST");

    // Before the server answers, the entry holds no ISN: an ACK of 1 (the
    // unset ISN + 1) proves nothing, at Stage 8b or at Stage 9
    seg = tcp_features(planted, server, 46001, 80, RTE_TCP_ACK_FLAG, 101, 1);
    TEST_ASSERT(!layer1_spoofed_tcp_admit(&seg, true),
                "A planted entry must not admit an ACK of 1 before the server's SYN-ACK");
    send_tcp(DIRECTION_INBOUND, planted, server, 46001, 80, RTE_TCP_ACK_FLAG, 101, 1, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "A bypassed connection's ACK should be forwarded");
    seg = tcp_features(planted, server, 46001, 80, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 101, 1);
    TEST_ASSERT(!layer1_spoofed_tcp_admit(&seg, true),
                "An ACK before the server's SYN-ACK must not make the planted entry vouch for later data");

    // The server answers the spoofed SYN; its sender never sees the ISN
    send_tcp(DIRECTION_OUTBOUND, server, planted, 80, 46001,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 900000, 101, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The server's SYN-ACK should be forwarded");
    const uint32_t guesses[] = { 0, 1, 900000, 900002, 0xFFFFFFFF, 0x12345678 };
    for (size_t i = 0; i < RTE_DIM(guesses); i++) {
        seg = tcp_features(planted, server, 46001, 80, RTE_TCP_ACK_FLAG, 101, guesses[i]);
        TEST_ASSERT(!layer1_spoofed_tcp_admit(&seg, true),
                    "An ACK of anything but the server's ISN + 1 must not be admitted");
    }
    // Stage 9 forwards a guessed ACK that gets there (with a flow, say), but
    // it completes no handshake
    send_tcp(DIRECTION_INBOUND, planted, server, 46001, 80, RTE_TCP_ACK_FLAG, 101, 900002, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "A bypassed connection's ACK should be forwarded");
    seg = tcp_features(planted, server, 46001, 80, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 101, 900002);
    TEST_ASSERT(!layer1_spoofed_tcp_admit(&seg, true),
                "A guessed ACK must not make the planted entry vouch for later data");

    // 2. A real client completes the handshake with the server's ISN + 1
    send_tcp(DIRECTION_INBOUND, client, server, 46002, 80, RTE_TCP_SYN_FLAG, 200, 0, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, res.action, "Normal-load SYN should be bypassed");
    send_tcp(DIRECTION_OUTBOUND, server, client, 80, 46002,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 5000000, 201, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The server's SYN-ACK should be forwarded");
    TEST_ASSERT(!res.packet_modified, "A bypassed connection's SYN-ACK should not be translated");
    seg = tcp_features(client, server, 46002, 80, RTE_TCP_ACK_FLAG, 201, 5000001);
    TEST_ASSERT(layer1_spoofed_tcp_admit(&seg, true),
                "The client's ACK of the server's ISN + 1 should be admitted without a flow");
    send_tcp(DIRECTION_INBOUND, client, server, 46002, 80, RTE_TCP_ACK_FLAG, 201, 5000001, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The handshake ACK should be forwarded");
    TEST_ASSERT(!res.packet_modified, "The handshake ACK should not be translated");

    // From then on the entry vouches for the connection's segments
    seg = tcp_features(client, server, 46002, 80, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG,
                       201, 5000001 + 1448);
    TEST_ASSERT(layer1_spoofed_tcp_admit(&seg, true), "Data of a completed handshake should be admitted");
    // A retransmitted SYN-ACK changes nothing
    send_tcp(DIRECTION_OUTBOUND, server, client, 80, 46002,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 5000000, 201, NULL, &res);
    TEST_ASSERT(layer1_spoofed_tcp_admit(&seg, true),
                "A retransmitted SYN-ACK should not undo the completed handshake");
    seg.tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
    TEST_ASSERT(layer1_spoofed_tcp_admit(&seg, true), "The client's FIN should be admitted");
    seg.tcp_flags = RTE_TCP_RST_FLAG;
    TEST_ASSERT(layer1_spoofed_tcp_admit(&seg, true), "The client's RST should be admitted");
    send_tcp(DIRECTION_INBOUND, client, server, 46002, 80, RTE_TCP_RST_FLAG, 1649, 0, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The client's RST should be forwarded");
    seg = tcp_features(client, server, 46002, 80, RTE_TCP_ACK_FLAG, 1649, 5000001 + 1448);
    TEST_ASSERT(!layer1_spoofed_tcp_admit(&seg, true), "A reset connection's later ACK should not be admitted");

    // 3. The ISN of the latest SYN-ACK counts while the handshake is open
    send_tcp(DIRECTION_INBOUND, retry, server, 46003, 80, RTE_TCP_SYN_FLAG, 300, 0, NULL, &res);
    send_tcp(DIRECTION_OUTBOUND, server, retry, 80, 46003,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 7000, 301, NULL, &res);
    send_tcp(DIRECTION_OUTBOUND, server, retry, 80, 46003,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 8000, 301, NULL, &res);
    seg = tcp_features(retry, server, 46003, 80, RTE_TCP_ACK_FLAG, 301, 7001);
    TEST_ASSERT(!layer1_spoofed_tcp_admit(&seg, true), "An ACK of a replaced ISN should not be admitted");
    seg.tcp_ack = 8001;
    TEST_ASSERT(layer1_spoofed_tcp_admit(&seg, true), "An ACK of the latest ISN + 1 should be admitted");

    syn_proxy_cleanup();
    flow_table_cleanup();
}

// ==================== MSS Default Test ====================

// The SYN to the server for a client SYN, challenged in the given mode: its
// MSS option's value, or 0 if it has none or the handshake failed
static uint16_t server_syn_mss_for(int mode, struct rte_mbuf *syn, uint32_t client, uint16_t port) {
    struct syn_proxy_result res;
    struct packet_features features = tcp_features(client, 0xC0A80101, port, 80,
                                                   RTE_TCP_SYN_FLAG, 4000, 0);
    syn_proxy_set_mode(mode);
    syn_proxy_process_packet(syn, &features, DIRECTION_INBOUND, test_pool, &res, 0, &tcp_flood_anom);
    syn_proxy_set_mode(-1);

    struct rte_mbuf *synack = (res.action == SYN_PROXY_REPLY_INPLACE) ? syn : res.reply_pkt;
    uint32_t cookie = synack ? rte_be_to_cpu_32(reply_tcp_hdr(synack)->sent_seq) : 0;
    if (res.reply_pkt) {
        rte_pktmbuf_free(res.reply_pkt);
    }
    rte_pktmbuf_free(syn);
    if (!synack) return 0;

    send_cookie_ack(client, 0xC0A80101, port, 80, 4000, cookie, &res);
    if (!res.reply_pkt) return 0;
    const uint8_t *mss_opt = find_tcp_option(reply_tcp_hdr(res.reply_pkt), 2);
    uint16_t mss = mss_opt ? (uint16_t)((mss_opt[2] << 8) | mss_opt[3]) : 0;
    rte_pktmbuf_free(res.reply_pkt);
    return mss;
}

// A SYN without an MSS option announces the default send MSS, 536 (RFC 9293).
// The cookie keeps it, so the proxy's SYN to the server offers 536 in both
// modes: the stateless fast extraction used to assume 1460.
void test_syn_proxy_absent_mss_uses_default(void) {
    init_default_config();
    syn_proxy_init(&default_config);

    const int modes[2] = { SYN_PROXY_MODE_STATELESS, SYN_PROXY_MODE_STATEFUL };
    const char *names[2] = { "Stateless", "Stateful" };
    uint16_t no_options[2], no_mss[2], mss_1460[2];

    for (int i = 0; i < 2; i++) {
        uint32_t client = 0x0A120001 + (uint32_t)i;

        // No options at all (a 20-byte TCP header)
        no_options[i] = server_syn_mss_for(modes[i],
            create_tcp_packet(client, 0xC0A80101, 47001, 80, RTE_TCP_SYN_FLAG, 4000, 0),
            client, 47001);

        // Options, but no MSS: SACK permitted, NOP, NOP, end of list
        struct rte_mbuf *syn = create_syn_packet(client, 0xC0A80101, 47002, 80, 4000);
        if (syn) {
            uint8_t *opts = (uint8_t *)(reply_tcp_hdr(syn) + 1);
            memset(opts, 0, 20);
            opts[0] = 4; opts[1] = 2; opts[2] = 1; opts[3] = 1;
        }
        no_mss[i] = syn ? server_syn_mss_for(modes[i], syn, client, 47002) : 0;

        // Control: MSS 1460
        syn = create_syn_packet(client, 0xC0A80101, 47003, 80, 4000);
        mss_1460[i] = syn ? server_syn_mss_for(modes[i], syn, client, 47003) : 0;
    }
    syn_proxy_cleanup();

    for (int i = 0; i < 2; i++) {
        printf("  %s: no options %u, no MSS option %u, MSS 1460 %u\n",
               names[i], no_options[i], no_mss[i], mss_1460[i]);
    }
    TEST_ASSERT_EQ(536, no_options[0], "Stateless: a SYN without options should give MSS 536");
    TEST_ASSERT_EQ(536, no_mss[0], "Stateless: a SYN without an MSS option should give MSS 536");
    TEST_ASSERT_EQ(1460, mss_1460[0], "Stateless: a SYN offering MSS 1460 should give 1460");
    TEST_ASSERT_EQ(536, no_options[1], "Stateful: a SYN without options should give MSS 536");
    TEST_ASSERT_EQ(536, no_mss[1], "Stateful: a SYN without an MSS option should give MSS 536");
    TEST_ASSERT_EQ(1460, mss_1460[1], "Stateful: a SYN offering MSS 1460 should give 1460");
}

// ==================== Challenge Threshold 0 Test ====================

static int count_challenged(uint32_t client, uint16_t base_port, int count);

// syn_cookie.challenge_threshold 0: what the config validator tells the
// operator must be what syn_proxy_init() does with it (the default threshold)
void test_syn_proxy_zero_threshold_config_agrees(void) {
    struct layer1_config cfg;
    layer1_config_defaults(&cfg);
    cfg.syn_cookie.challenge_threshold = 0;

    char *log_text = NULL;
    size_t log_len = 0;
    FILE *log = open_memstream(&log_text, &log_len);
    TEST_ASSERT(log != NULL, "Failed to open a memory stream for the log");
    FILE *previous = rte_log_get_stream();
    rte_openlog_stream(log);
    int valid = layer1_config_validate(&cfg);
    rte_openlog_stream(previous);
    fclose(log);
    bool says_all = log_text && strstr(log_text, "ALL SYNs will be challenged") != NULL;
    bool says_default = log_text &&
        strstr(log_text, "syn_cookie.challenge_threshold is 0 - the default (1000 SYN/s) applies") != NULL;
    free(log_text);

    // layer1_init() hands the configured value to syn_proxy_init()
    init_default_config();
    default_config.challenge_threshold = cfg.syn_cookie.challenge_threshold;
    syn_proxy_init(&default_config);
    int up_to_default = count_challenged(0x0A130001, 20000, 990);
    int past_default = count_challenged(0x0A130002, 20000, 200);
    syn_proxy_cleanup();

    TEST_ASSERT_EQ(0, valid, "Threshold 0 should pass validation");
    TEST_ASSERT(!says_all, "The validator must not say that threshold 0 challenges every SYN");
    TEST_ASSERT(says_default, "The validator should say that threshold 0 selects the default");
    TEST_ASSERT_EQ(0, up_to_default, "Up to the default threshold no normal-load SYN should be challenged");
    TEST_ASSERT(past_default > 0, "Past the default threshold normal-load SYNs should be challenged");
}

// ==================== Cleanup Budget Test ====================

// Normal-load SYNs from n distinct 4-tuples (clients from client_base, 32768
// ports each); returns how many were bypassed
static uint32_t fill_tuples(uint32_t client_base, uint32_t n) {
    uint32_t bypassed = 0;
    for (uint32_t i = 0; i < n; i++) {
        struct syn_proxy_result res;
        send_tcp(DIRECTION_INBOUND, client_base + (i >> 15), 0xC0A80101,
                 (uint16_t)(1024 + (i & 0x7FFF)), 80, RTE_TCP_SYN_FLAG, 1000, 0, NULL, &res);
        if (res.reply_pkt) {
            rte_pktmbuf_free(res.reply_pkt);
        }
        if (res.action == SYN_PROXY_BYPASS) {
            bypassed++;
        }
    }
    return bypassed;
}

// How many of those n 4-tuples still have an entry
static uint32_t count_tuples(uint32_t client_base, uint32_t n) {
    uint32_t present = 0;
    for (uint32_t i = 0; i < n; i++) {
        struct packet_features f = tcp_features(client_base + (i >> 15), 0xC0A80101,
                                                (uint16_t)(1024 + (i & 0x7FFF)), 80,
                                                RTE_TCP_ACK_FLAG, 1001, 1);
        if (syn_proxy_is_proxied(&f, DIRECTION_INBOUND)) {
            present++;
        }
    }
    return present;
}

// One cleanup pass deletes at most 65536 due entries (CLEANUP_DELETE_BUDGET)
// and the next pass resumes its scan where that one stopped
void test_syn_proxy_cleanup_budget_carries_over(void) {
    const uint32_t budget = 65536, extra = 4096;
    const uint32_t old_base = 0x0B100000, new_base = 0x0B200000;

    init_default_config();
    default_config.max_connections = 1u << 17;
    default_config.idle_timeout_sec = 0;          // Every entry is due at the next pass
    default_config.challenge_threshold = UINT32_MAX;  // No SYN below is challenged
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    TEST_ASSERT_EQ(budget + extra, fill_tuples(old_base, budget + extra),
                   "Normal-load SYNs should be bypassed");

    // The first pass stops at the budget
    uint32_t first = syn_proxy_cleanup_connections();
    uint32_t old_left = count_tuples(old_base, budget + extra);

    // New due entries, spread over the whole table, arrive before the next
    // pass: now more than the budget is due. Resuming where the first pass
    // stopped, the second scans only the rest of the table and ends at its
    // end, well under the budget; a pass that started over would delete the
    // whole budget again. (Inserting moves some keys between their two
    // buckets, so a few old entries can land behind the saved position and
    // wait for the next sweep.)
    TEST_ASSERT_EQ(budget, fill_tuples(new_base, budget), "Normal-load SYNs should be bypassed");
    uint32_t second = syn_proxy_cleanup_connections();
    uint32_t old_after_second = count_tuples(old_base, budget + extra);

    // The third pass starts over at the beginning and drains the rest
    uint32_t third = syn_proxy_cleanup_connections();
    uint32_t old_after_third = count_tuples(old_base, budget + extra);
    uint32_t total = first + second + third;
    for (int pass = 0; pass < 8; pass++) {
        total += syn_proxy_cleanup_connections();
    }
    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    syn_proxy_cleanup();

    printf("  passes: %u, %u, %u; old entries left %u, %u, %u\n",
           first, second, third, old_left, old_after_second, old_after_third);
    TEST_ASSERT_EQ(budget, first, "One pass should delete at most the budget");
    TEST_ASSERT_EQ(extra, old_left, "The first pass should leave the entries past its budget");
    TEST_ASSERT(second > 0 && second < budget / 2,
                "The second pass should resume where the first stopped and end at the end of the table");
    TEST_ASSERT(old_after_second < extra / 2,
                "The second pass should delete most of the old entries the first left");
    TEST_ASSERT_EQ(2 * budget + extra - first - second, third,
                   "The third pass should start over and delete everything still due");
    TEST_ASSERT_EQ(0, old_after_third, "No old entry should be left after the third pass");
    TEST_ASSERT_EQ(2 * budget + extra, total, "Every entry should be deleted once");
    TEST_ASSERT_EQ(2 * budget + extra, stats.connections_timeout, "Each deletion should count one idle timeout");
    TEST_ASSERT_EQ(0, stats.connections_active, "No entry should remain");
}

// ==================== Interleaving Tests (race seams) ====================

#define RACE_SERVER     0xC0A80101
#define RACE_CLIENT     0x0A100001   // The source whose half-open slots are counted

// Proxied connections a source can open, each waiting on its server and
// holding one of the source's half-open slots, until the per-source limit
// drops the next one (ports base_port, base_port + 1, ...)
static int open_until_drop(uint32_t client, uint16_t base_port) {
    int opened = 0;
    while (opened < 256 &&
           cookie_handshake(client, RACE_SERVER, (uint16_t)(base_port + opened), 80,
                            1000, NULL) == SYN_PROXY_REPLY) {
        opened++;
    }
    return opened;
}

// The per-source half-open limit, measured on a fresh proxy
static int half_open_limit(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    int limit = open_until_drop(0x0A1000FF, 30000);
    syn_proxy_cleanup();
    return limit;
}

static uint32_t seam_cleaned;
static uint32_t seam_proxy_isn;
static struct syn_proxy_result seam_res;
static enum syn_proxy_action seam_second;

// The cleanup ends the connection the packet path holds; a new proxied
// connection then takes the slot it freed, in the same state
static void seam_time_out_and_reuse(void) {
    seam_cleaned = syn_proxy_cleanup_connections();
    seam_second = cookie_handshake(0x0A100002, RACE_SERVER, 44002, 80, 5000, NULL);
}

// An RST on the packet path must end only the connection it looked up. Here
// the cleanup ends that connection first and its slot is reused before the
// packet path deletes: once that delete took the key from the reused slot.
// The new occupant waits on its server like the old one, so only the slot's
// generation tells them apart.
void test_syn_proxy_stale_free_spares_new_occupant(void) {
    init_default_config();
    default_config.max_connections = 16;
    default_config.connect_timeout_ms = 0;  // A connection waiting on its server is due at once
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct syn_proxy_result res;
    struct syn_proxy_stats stats;

    // 15 bypassed connections and one proxied connection that waits on its
    // server fill the table, so the next SYN takes the slot freed first
    TEST_ASSERT_EQ(15, fill_with_bypassed(0x0A100003, RACE_SERVER, 45000, 15),
                   "Normal-load SYNs should be bypassed");
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, cookie_handshake(RACE_CLIENT, RACE_SERVER, 44001, 80, 1000, NULL),
                   "Valid cookie should open a server connection");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(16, stats.connections_active, "The table should be full");

    // The client resets the waiting connection
    arm_seam(SYN_PROXY_SEAM_FREE, seam_time_out_and_reuse);
    send_tcp(DIRECTION_INBOUND, RACE_CLIENT, RACE_SERVER, 44001, 80,
             RTE_TCP_RST_FLAG, 1001, 0, NULL, &res);
    TEST_ASSERT_EQ(1, seam_calls, "The RST should reach the packet path's delete");
    TEST_ASSERT_EQ(1, seam_cleaned, "The cleanup should time the connection out first");
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, seam_second, "The new connection's cookie should open it");

    struct packet_features new_conn = tcp_features(0x0A100002, RACE_SERVER, 44002, 80,
                                                   RTE_TCP_ACK_FLAG, 5001, 9001);
    TEST_ASSERT(syn_proxy_is_proxied(&new_conn, DIRECTION_INBOUND),
                "The RST of the old connection must not delete the new one in its slot");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(16, stats.connections_active, "The new connection should hold the freed entry");
    TEST_ASSERT_EQ(0, stats.connections_closed, "The stale RST should close nothing");
    TEST_ASSERT_EQ(1, stats.server_timeout, "Only the cleanup should count the old connection");
    send_tcp(DIRECTION_INBOUND, 0x0A100002, RACE_SERVER, 44002, 80,
             RTE_TCP_ACK_FLAG, 5001, 9001, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_DROP, res.action, "The new connection should still wait on its server");
    TEST_ASSERT_EQ(SYN_PROXY_CONNECTING, res.conn_state, "The new connection should keep its entry");

    syn_proxy_cleanup();
}

// The server's SYN-ACK for the connection the cleanup is about to time out,
// then a second proxied connection from the same source
static void seam_establish_then_open(void) {
    send_tcp(DIRECTION_OUTBOUND, RACE_SERVER, RACE_CLIENT, 80, 44011,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 7000, seam_proxy_isn + 1, NULL, &seam_res);
    if (seam_res.reply_pkt) {
        rte_pktmbuf_free(seam_res.reply_pkt);
        seam_res.reply_pkt = NULL;
    }
    seam_second = cookie_handshake(RACE_CLIENT, RACE_SERVER, 44012, 80, 1000, NULL);
}

// The end of CONNECTING releases the source's half-open slot exactly once.
// Here the cleanup finds the connection past its connect timeout, and the
// server's SYN-ACK establishes it before the cleanup ends it: once the
// cleanup deleted the established connection and released the slot again.
void test_syn_proxy_connecting_end_once_cleanup_first(void) {
    int limit = half_open_limit();
    TEST_ASSERT(limit > 1, "A source should be able to open several waiting connections");

    init_default_config();
    default_config.connect_timeout_ms = 0;  // Due at once
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct syn_proxy_stats stats;

    seam_proxy_isn = 0;
    TEST_ASSERT_EQ(SYN_PROXY_REPLY,
                   cookie_handshake(RACE_CLIENT, RACE_SERVER, 44011, 80, 1000, &seam_proxy_isn),
                   "Valid cookie should open a server connection");

    arm_seam(SYN_PROXY_SEAM_CLEANUP, seam_establish_then_open);
    uint32_t cleaned = syn_proxy_cleanup_connections();
    TEST_ASSERT_EQ(1, seam_calls, "The cleanup should reach the connection it found due");
    TEST_ASSERT_EQ(SYN_PROXY_ESTABLISHED, seam_res.conn_state,
                   "The server's SYN-ACK should establish the connection");
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, seam_second, "The source should open a second connection");
    TEST_ASSERT_EQ(0, cleaned, "The cleanup must not end a connection that is no longer waiting");

    struct packet_features first = tcp_features(RACE_CLIENT, RACE_SERVER, 44011, 80,
                                                RTE_TCP_ACK_FLAG, 1001, 1);
    TEST_ASSERT(syn_proxy_is_proxied(&first, DIRECTION_INBOUND),
                "The established connection should keep its entry");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, stats.server_timeout, "No connection should count as a server timeout");
    TEST_ASSERT_EQ(1, stats.connections_established, "One connection should be established");

    // The second connection holds one half-open slot
    TEST_ASSERT_EQ(limit - 1, open_until_drop(RACE_CLIENT, 44100),
                   "The first connection's half-open slot should be released once");

    // Ending the established connection releases no half-open slot: it
    // released its own when the server answered
    struct syn_proxy_result res;
    send_tcp(DIRECTION_INBOUND, RACE_CLIENT, RACE_SERVER, 44011, 80,
             RTE_TCP_RST_FLAG, 1001, 0, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The established connection's RST should be forwarded");
    TEST_ASSERT_EQ(0, open_until_drop(RACE_CLIENT, 44200),
                   "Ending an established connection should release no half-open slot");
    syn_proxy_cleanup();
}

// The cleanup times out the connection whose SYN-ACK the packet path holds,
// then the same source opens a second proxied connection, which may reuse the
// slot
static void seam_time_out_then_open(void) {
    seam_cleaned = syn_proxy_cleanup_connections();
    seam_second = cookie_handshake(RACE_CLIENT, RACE_SERVER, 44022, 80, 1000, NULL);
}

// The other order: the packet path holds the server's SYN-ACK while the
// cleanup times the connection out. Once the SYN-ACK still released the slot
// and established a deleted entry, or the second connection in its slot.
void test_syn_proxy_connecting_end_once_synack_first(void) {
    int limit = half_open_limit();
    TEST_ASSERT(limit > 1, "A source should be able to open several waiting connections");

    init_default_config();
    default_config.connect_timeout_ms = 0;  // Due at once
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct syn_proxy_result res;
    struct syn_proxy_stats stats;

    uint32_t proxy_isn = 0;
    TEST_ASSERT_EQ(SYN_PROXY_REPLY,
                   cookie_handshake(RACE_CLIENT, RACE_SERVER, 44021, 80, 1000, &proxy_isn),
                   "Valid cookie should open a server connection");

    arm_seam(SYN_PROXY_SEAM_SYNACK, seam_time_out_then_open);
    send_tcp(DIRECTION_OUTBOUND, RACE_SERVER, RACE_CLIENT, 80, 44021,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 7000, proxy_isn + 1, NULL, &res);
    bool ack_sent = res.reply_pkt != NULL;
    if (res.reply_pkt) {
        rte_pktmbuf_free(res.reply_pkt);
    }
    TEST_ASSERT_EQ(1, seam_calls, "The SYN-ACK should reach the end of CONNECTING");
    TEST_ASSERT_EQ(1, seam_cleaned, "The cleanup should time the connection out first");
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, seam_second, "The source should open a second connection");
    TEST_ASSERT_EQ(SYN_PROXY_DROP, res.action, "The SYN-ACK of a timed-out connection should be dropped");
    TEST_ASSERT(!ack_sent, "No ACK should go to the server for a timed-out connection");

    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, stats.connections_established, "The old SYN-ACK should establish nothing");
    TEST_ASSERT_EQ(1, stats.server_timeout, "The timeout should be counted once");
    TEST_ASSERT_EQ(1, stats.connections_active, "Only the second connection should remain");

    // The second connection still waits on its own server
    send_tcp(DIRECTION_INBOUND, RACE_CLIENT, RACE_SERVER, 44022, 80,
             RTE_TCP_ACK_FLAG, 1001, 1, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_DROP, res.action, "The second connection should still wait on its server");
    TEST_ASSERT_EQ(SYN_PROXY_CONNECTING, res.conn_state, "The second connection should still be CONNECTING");

    TEST_ASSERT_EQ(limit - 1, open_until_drop(RACE_CLIENT, 44100),
                   "The first connection's half-open slot should be released once");
    syn_proxy_cleanup();
}

// A worker lcore uses both connections the cleanup found idle, after the scan
static void seam_use_both(void) {
    struct syn_proxy_result res;
    send_tcp(DIRECTION_INBOUND, 0x0A100031, RACE_SERVER, 44031, 80,
             RTE_TCP_ACK_FLAG, 1001, 2001, NULL, &res);
    send_tcp(DIRECTION_INBOUND, 0x0A100031, RACE_SERVER, 44032, 80,
             RTE_TCP_ACK_FLAG, 1001, 2001, NULL, &res);
}

// An entry used after the cleanup's scan must not be deleted as idle. The
// cleanup checks each entry again just before it ends it, and an activity
// time after the pass began is not idle (the unsigned difference would wrap).
// The entry being ended at that moment (the first) is past that check.
void test_syn_proxy_cleanup_spares_connection_used_since_scan(void) {
    init_default_config();
    default_config.idle_timeout_sec = 0;  // Every entry is idle at the next pass
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct syn_proxy_stats stats;

    TEST_ASSERT_EQ(2, fill_with_bypassed(0x0A100031, RACE_SERVER, 44031, 2),
                   "Normal-load SYNs should be bypassed");

    arm_seam(SYN_PROXY_SEAM_CLEANUP, seam_use_both);
    uint32_t cleaned = syn_proxy_cleanup_connections();
    TEST_ASSERT_EQ(1, seam_calls, "The cleanup should reach the first idle connection");

    struct packet_features a = tcp_features(0x0A100031, RACE_SERVER, 44031, 80, RTE_TCP_ACK_FLAG, 1001, 1);
    struct packet_features b = tcp_features(0x0A100031, RACE_SERVER, 44032, 80, RTE_TCP_ACK_FLAG, 1001, 1);
    int present = (int)syn_proxy_is_proxied(&a, DIRECTION_INBOUND) +
                  (int)syn_proxy_is_proxied(&b, DIRECTION_INBOUND);
    syn_proxy_get_stats(&stats);
    syn_proxy_cleanup();

    TEST_ASSERT_EQ(1, cleaned, "The connection used since the scan must not be deleted");
    TEST_ASSERT_EQ(1, present, "The connection used since the scan should keep its entry");
    TEST_ASSERT_EQ(1, stats.connections_timeout, "One idle timeout should be counted");
    TEST_ASSERT_EQ(1, stats.connections_active, "One entry should remain");
}

// New connections while the cleanup deletes its first batch: 64 proxied ones
// that wait on their servers and 64 bypassed ones
static void seam_create_during_pass(void) {
    for (int i = 0; i < 64; i++) {
        cookie_handshake(0x0A100051, RACE_SERVER, (uint16_t)(48000 + i), 80, 1000, NULL);
    }
    fill_with_bypassed(0x0A100052, RACE_SERVER, 48100, 64);
}

// A pass samples the time once and then scans; entries created (or used)
// while it runs, which its scan then reaches, have later times. Taken as
// unsigned differences those would look long idle, or long past their
// connect timeout, and the pass would delete live connections.
void test_syn_proxy_cleanup_spares_entries_created_during_pass(void) {
    init_default_config();
    default_config.idle_timeout_sec = 0;    // Due at the next pass...
    default_config.connect_timeout_ms = 0;  // ... once created before it
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct syn_proxy_stats stats;

    // 512 due entries: the first batch of 256 is deleted mid-scan
    TEST_ASSERT_EQ(512, fill_with_bypassed(0x0A100050, RACE_SERVER, 20000, 512),
                   "Normal-load SYNs should be bypassed");

    arm_seam(SYN_PROXY_SEAM_CLEANUP, seam_create_during_pass);
    uint32_t cleaned = syn_proxy_cleanup_connections();
    TEST_ASSERT_EQ(1, seam_calls, "The cleanup should reach its first batch");

    int waiting = 0, bypassed = 0;
    for (int i = 0; i < 64; i++) {
        struct packet_features w = tcp_features(0x0A100051, RACE_SERVER, (uint16_t)(48000 + i), 80,
                                                RTE_TCP_ACK_FLAG, 1001, 1);
        struct packet_features b = tcp_features(0x0A100052, RACE_SERVER, (uint16_t)(48100 + i), 80,
                                                RTE_TCP_ACK_FLAG, 1001, 1);
        waiting += syn_proxy_is_proxied(&w, DIRECTION_INBOUND);
        bypassed += syn_proxy_is_proxied(&b, DIRECTION_INBOUND);
    }
    syn_proxy_get_stats(&stats);
    syn_proxy_cleanup();

    TEST_ASSERT_EQ(512, cleaned, "The pass should delete exactly the entries due when it began");
    TEST_ASSERT_EQ(64, waiting, "Connections opened during the pass must not time out in it");
    TEST_ASSERT_EQ(64, bypassed, "Connections created during the pass must not be idle in it");
    TEST_ASSERT_EQ(0, stats.server_timeout, "No connect timeout should be counted");
    TEST_ASSERT_EQ(128, stats.connections_active, "The new connections should remain");
}

// ==================== Thread Without an Lcore Id ====================

struct non_eal_job {
    unsigned int lcore;
    struct syn_proxy_result syn;
    struct syn_proxy_result rst;
    uint32_t cleaned;
};

static void *non_eal_job_run(void *arg) {
    struct non_eal_job *job = arg;
    job->lcore = rte_lcore_id();
    // A normal-load SYN, which an lcore would record as BYPASSED
    send_tcp(DIRECTION_INBOUND, 0x0A100041, RACE_SERVER, 44041, 80,
             RTE_TCP_SYN_FLAG, 100, 0, NULL, &job->syn);
    // An RST for a connection that lcore 0 recorded
    send_tcp(DIRECTION_INBOUND, 0x0A100042, RACE_SERVER, 44042, 80,
             RTE_TCP_RST_FLAG, 101, 0, NULL, &job->rst);
    job->cleaned = syn_proxy_cleanup_connections();
    return NULL;
}

// The hash keeps its free key slots in per-lcore caches indexed by
// rte_lcore_id(), which a thread without an lcore id would index past. Such a
// thread forwards as before but neither adds nor frees an entry.
void test_syn_proxy_non_eal_thread_changes_no_entry(void) {
    init_default_config();
    default_config.idle_timeout_sec = 0;  // lcore 0's entry is due for any cleanup
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct syn_proxy_result res;
    struct syn_proxy_stats stats;

    send_tcp(DIRECTION_INBOUND, 0x0A100042, RACE_SERVER, 44042, 80,
             RTE_TCP_SYN_FLAG, 100, 0, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, res.action, "Normal-load SYN should be bypassed");

    // In a child process, so that a crash fails this subtest only. With
    // --no-huge the child shares the DPDK memory: the table it sees is this
    // one, and the thread is not to write it.
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        struct non_eal_job job;
        memset(&job, 0, sizeof(job));
        pthread_t thread;
        if (pthread_create(&thread, NULL, non_eal_job_run, &job) != 0) {
            _exit(2);
        }
        pthread_join(thread, NULL);
        struct packet_features syn = tcp_features(0x0A100041, RACE_SERVER, 44041, 80,
                                                  RTE_TCP_ACK_FLAG, 101, 1);
        struct packet_features held = tcp_features(0x0A100042, RACE_SERVER, 44042, 80,
                                                   RTE_TCP_ACK_FLAG, 101, 1);
        struct syn_proxy_stats st;
        syn_proxy_get_stats(&st);
        int code = 0;
        if (job.lcore != LCORE_ID_ANY) code = 3;
        else if (job.syn.action != SYN_PROXY_BYPASS) code = 4;
        else if (syn_proxy_is_proxied(&syn, DIRECTION_INBOUND) || st.connections_created != 1) code = 5;
        else if (job.rst.action != SYN_PROXY_FORWARD) code = 6;
        else if (!syn_proxy_is_proxied(&held, DIRECTION_INBOUND) || st.connections_closed != 0) code = 7;
        else if (job.cleaned != 0) code = 8;
        _exit(code);
    }
    int status = 0;
    bool reaped = pid > 0 && waitpid(pid, &status, 0) == pid;

    // On lcore 0 the same RST ends the connection
    send_tcp(DIRECTION_INBOUND, 0x0A100042, RACE_SERVER, 44042, 80,
             RTE_TCP_RST_FLAG, 101, 0, NULL, &res);
    syn_proxy_get_stats(&stats);
    syn_proxy_cleanup();

    TEST_ASSERT(reaped, "Child process should run the thread");
    TEST_ASSERT_EQ(0, WIFSIGNALED(status) ? WTERMSIG(status) : 0,
                   "A thread without an lcore id must not crash the proxy (signal)");
    TEST_ASSERT_EQ(0, WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                   "A thread without an lcore id should forward but neither add nor free an entry (exit code)");
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "lcore 0 should forward the RST");
    TEST_ASSERT_EQ(1, stats.connections_closed, "lcore 0 should end the connection");
    TEST_ASSERT_EQ(0, stats.connections_active, "No entry should remain");
}

// ==================== Proxied Connection Close Tests ====================

// A proxied (challenged) connection to RACE_SERVER:80 and the numbering of its
// two legs: the client numbers its own bytes from isn and the server's from
// cookie (the proxy's SYN-ACK); the server numbers the client's bytes from
// proxy_isn (the proxy's SYN) and its own from server_isn
struct proxied_conn {
    uint32_t client;
    uint16_t port;
    uint32_t isn;
    uint32_t cookie;
    uint32_t proxy_isn;
    uint32_t server_isn;
};

// A client sequence number as the server numbers it, and a server sequence
// number as the client numbers it
static uint32_t c2s(const struct proxied_conn *pc, uint32_t client_seq) {
    return client_seq - pc->isn + pc->proxy_isn;
}

static uint32_t s2c(const struct proxied_conn *pc, uint32_t server_seq) {
    return server_seq - pc->server_isn + pc->cookie;
}

// One segment with payload_len bytes of payload through the proxy. *fwd_seq and
// *fwd_ack (if given) get the numbers the packet left with, translated or not.
static void send_seg(uint8_t direction, uint32_t src_ip, uint32_t dst_ip,
                     uint16_t src_port, uint16_t dst_port, uint8_t tcp_flags,
                     uint32_t seq, uint32_t ack, uint16_t payload_len,
                     struct syn_proxy_result *res, uint32_t *fwd_seq, uint32_t *fwd_ack) {
    memset(res, 0, sizeof(*res));
    res->action = SYN_PROXY_ERROR;
    struct rte_mbuf *m = create_tcp_packet(src_ip, dst_ip, src_port, dst_port,
                                           tcp_flags, seq, ack);
    if (!m) return;
    if (payload_len > 0) {
        char *p = rte_pktmbuf_append(m, payload_len);
        if (!p) {
            rte_pktmbuf_free(m);
            return;
        }
        memset(p, 0x5A, payload_len);
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(m, struct rte_ether_hdr *) + 1);
        ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
                                            sizeof(struct rte_tcp_hdr) + payload_len);
    }
    struct packet_features f = tcp_features(src_ip, dst_ip, src_port, dst_port,
                                            tcp_flags, seq, ack);
    syn_proxy_process_packet(m, &f, direction, test_pool, res, 0, NULL);
    if (fwd_seq) *fwd_seq = rte_be_to_cpu_32(reply_tcp_hdr(m)->sent_seq);
    if (fwd_ack) *fwd_ack = rte_be_to_cpu_32(reply_tcp_hdr(m)->recv_ack);
    if (res->reply_pkt) {
        rte_pktmbuf_free(res->reply_pkt);
        res->reply_pkt = NULL;
    }
    rte_pktmbuf_free(m);
}

// The client's and the server's segments, each numbered as its sender numbers
static void client_seg(const struct proxied_conn *pc, uint8_t tcp_flags, uint32_t seq,
                       uint32_t ack, uint16_t payload_len, struct syn_proxy_result *res,
                       uint32_t *fwd_seq, uint32_t *fwd_ack) {
    send_seg(DIRECTION_INBOUND, pc->client, RACE_SERVER, pc->port, 80, tcp_flags,
             seq, ack, payload_len, res, fwd_seq, fwd_ack);
}

static void server_seg(const struct proxied_conn *pc, uint8_t tcp_flags, uint32_t seq,
                       uint32_t ack, uint16_t payload_len, struct syn_proxy_result *res,
                       uint32_t *fwd_seq, uint32_t *fwd_ack) {
    send_seg(DIRECTION_OUTBOUND, RACE_SERVER, pc->client, 80, pc->port, tcp_flags,
             seq, ack, payload_len, res, fwd_seq, fwd_ack);
}

// A proxied connection under attack: the cookie handshake, the proxy's SYN to
// the server and the server's SYN-ACK. Returns NULL, or what went wrong.
static const char *open_proxied(struct proxied_conn *pc, uint32_t client, uint16_t port,
                                uint32_t isn, uint32_t server_isn) {
    memset(pc, 0, sizeof(*pc));
    pc->client = client;
    pc->port = port;
    pc->isn = isn;
    pc->server_isn = server_isn;
    if (!get_cookie(client, RACE_SERVER, port, 80, isn, &pc->cookie))
        return "SYN should be challenged with a cookie";

    struct syn_proxy_result res;
    send_cookie_ack(client, RACE_SERVER, port, 80, isn, pc->cookie, &res);
    if (!res.reply_pkt)
        return "Valid cookie should produce the SYN to the server";
    pc->proxy_isn = rte_be_to_cpu_32(reply_tcp_hdr(res.reply_pkt)->sent_seq);
    rte_pktmbuf_free(res.reply_pkt);
    if (res.action != SYN_PROXY_REPLY || res.conn_state != SYN_PROXY_CONNECTING)
        return "Valid cookie should open a server connection";

    send_tcp(DIRECTION_OUTBOUND, RACE_SERVER, client, 80, port,
             RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, server_isn, pc->proxy_isn + 1, NULL, &res);
    if (res.reply_pkt)
        rte_pktmbuf_free(res.reply_pkt);
    if (res.action != SYN_PROXY_REPLY || res.conn_state != SYN_PROXY_ESTABLISHED)
        return "Server SYN-ACK should establish the connection";
    return NULL;
}

// 100 bytes from the client and 200 from the server, each acknowledged. The
// client then sends from isn + 101 and acknowledges cookie + 201; the server
// sends from server_isn + 201 and acknowledges proxy_isn + 101.
static void exchange_data(const struct proxied_conn *pc) {
    struct syn_proxy_result res;
    client_seg(pc, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, pc->isn + 1, pc->cookie + 1, 100,
               &res, NULL, NULL);
    server_seg(pc, RTE_TCP_ACK_FLAG, pc->server_isn + 1, pc->proxy_isn + 101, 0, &res, NULL, NULL);
    server_seg(pc, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, pc->server_isn + 1, pc->proxy_isn + 101, 200,
               &res, NULL, NULL);
    client_seg(pc, RTE_TCP_ACK_FLAG, pc->isn + 101, pc->cookie + 201, 0, &res, NULL, NULL);
}

static bool has_entry(const struct proxied_conn *pc) {
    struct packet_features f = tcp_features(pc->client, RACE_SERVER, pc->port, 80,
                                            RTE_TCP_ACK_FLAG, 0, 0);
    return syn_proxy_is_proxied(&f, DIRECTION_INBOUND);
}

static uint32_t connections_active(void) {
    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    return stats.connections_active;
}

static uint64_t connections_closed(void) {
    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    return stats.connections_closed;
}

#define FIN_ACK  (RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG)
#define RST_ACK  (RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG)

// The client closes first: its FIN, the server's FIN with the ACK of the
// client's, and the client's last ACK. Each is translated and forwarded, and
// the last ACK releases the entry. Once the client's FIN+ACK went to the ACK
// branch, which forwarded it and kept the entry (SERVER_FIN after the server's
// FIN) until the idle timeout, 300 s shipped. This is the FIN+ACK case of the
// round-3 white-box check (proxied_close.c: open, exchange data, close, one
// cleanup pass), with the acknowledgement numbers a TCP stack sends.
void test_syn_proxy_proxied_client_closes_first(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct proxied_conn pc;
    struct syn_proxy_result res;
    uint32_t seq = 0, ack = 0;

    const char *err = open_proxied(&pc, 0x0A100071, 45001, 1000, 70000);
    TEST_ASSERT(err == NULL, err);
    exchange_data(&pc);

    struct syn_proxy_stats before;
    syn_proxy_get_stats(&before);
    client_seg(&pc, FIN_ACK, 1101, pc.cookie + 201, 0, &res, &seq, &ack);
    struct syn_proxy_stats after;
    syn_proxy_get_stats(&after);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The client's FIN should be forwarded");
    TEST_ASSERT(res.packet_modified, "The client's FIN should be translated");
    TEST_ASSERT_EQ(c2s(&pc, 1101), seq, "The client's FIN should carry the server's numbering");
    TEST_ASSERT_EQ(70201, ack, "The client's FIN should acknowledge the server's data");
    TEST_ASSERT(has_entry(&pc), "A half-closed connection should keep its entry");
    TEST_ASSERT_EQ(before.packets_proxied_c2s + 1, after.packets_proxied_c2s,
                   "A FIN+ACK of an established connection should count as a proxied segment");

    server_seg(&pc, FIN_ACK, 70201, c2s(&pc, 1102), 0, &res, &seq, &ack);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The server's FIN should be forwarded");
    TEST_ASSERT_EQ(s2c(&pc, 70201), seq, "The server's FIN should carry the client's numbering");
    TEST_ASSERT_EQ(1102, ack, "The server's FIN should acknowledge the client's FIN");
    TEST_ASSERT(has_entry(&pc), "The entry should stay until the last ACK");
    TEST_ASSERT_EQ(1, connections_active(), "The connection should still hold its entry");

    client_seg(&pc, RTE_TCP_ACK_FLAG, 1102, s2c(&pc, 70202), 0, &res, &seq, &ack);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The last ACK should be forwarded");
    TEST_ASSERT(res.packet_modified, "The last ACK should be translated");
    TEST_ASSERT_EQ(c2s(&pc, 1102), seq, "The last ACK should carry the server's numbering");
    TEST_ASSERT_EQ(70202, ack, "The last ACK should acknowledge the server's FIN");
    TEST_ASSERT(!has_entry(&pc), "The last ACK after both FINs should release the entry");
    TEST_ASSERT_EQ(0, connections_active(), "No entry should remain");
    TEST_ASSERT_EQ(1, connections_closed(), "The release should count as closed");

    // A cleanup pass has nothing left of it, and the 4-tuple can be proxied again
    TEST_ASSERT_EQ(0, syn_proxy_cleanup_connections(), "The cleanup should find nothing to delete");
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, cookie_handshake(0x0A100071, RACE_SERVER, 45001, 80, 9000, NULL),
                   "The released 4-tuple should open a new server connection");
    syn_proxy_cleanup();
}

// The server closes first: its last 50 bytes with its FIN, the client's FIN
// with the ACK of both, and the server's last ACK, which releases the entry
void test_syn_proxy_proxied_server_closes_first(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct proxied_conn pc;
    struct syn_proxy_result res;
    uint32_t seq = 0, ack = 0;

    const char *err = open_proxied(&pc, 0x0A100072, 45002, 2000, 80000);
    TEST_ASSERT(err == NULL, err);
    exchange_data(&pc);

    server_seg(&pc, FIN_ACK, 80201, c2s(&pc, 2101), 50, &res, &seq, &ack);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The server's FIN should be forwarded");
    TEST_ASSERT_EQ(s2c(&pc, 80201), seq, "The server's FIN should carry the client's numbering");
    TEST_ASSERT(has_entry(&pc), "A half-closed connection should keep its entry");

    // The FIN follows the 50 bytes: the client acknowledges 80201 + 50 + 1
    client_seg(&pc, FIN_ACK, 2101, s2c(&pc, 80252), 0, &res, &seq, &ack);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The client's FIN should be forwarded");
    TEST_ASSERT_EQ(c2s(&pc, 2101), seq, "The client's FIN should carry the server's numbering");
    TEST_ASSERT_EQ(80252, ack, "The client's FIN should acknowledge the server's data and FIN");
    TEST_ASSERT(has_entry(&pc), "The entry should stay until the last ACK");

    server_seg(&pc, RTE_TCP_ACK_FLAG, 80252, c2s(&pc, 2102), 0, &res, &seq, &ack);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The last ACK should be forwarded");
    TEST_ASSERT_EQ(s2c(&pc, 80252), seq, "The last ACK should carry the client's numbering");
    TEST_ASSERT_EQ(2102, ack, "The last ACK should acknowledge the client's FIN");
    TEST_ASSERT(!has_entry(&pc), "The last ACK after both FINs should release the entry");
    TEST_ASSERT_EQ(0, connections_active(), "No entry should remain");
    TEST_ASSERT_EQ(1, connections_closed(), "The release should count as closed");
    syn_proxy_cleanup();
}

// Both sides close at once: their FINs cross, each acknowledges the other's,
// and the second of those ACKs releases the entry. The client's FIN carries
// its last 30 bytes, so the server acknowledges 3101 + 30 + 1.
void test_syn_proxy_proxied_simultaneous_close(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct proxied_conn pc;
    struct syn_proxy_result res;

    const char *err = open_proxied(&pc, 0x0A100073, 45003, 3000, 90000);
    TEST_ASSERT(err == NULL, err);
    exchange_data(&pc);

    client_seg(&pc, FIN_ACK | RTE_TCP_PSH_FLAG, 3101, s2c(&pc, 90201), 30, &res, NULL, NULL);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The client's FIN should be forwarded");
    server_seg(&pc, FIN_ACK, 90201, c2s(&pc, 3101), 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The server's FIN should be forwarded");

    client_seg(&pc, RTE_TCP_ACK_FLAG, 3132, s2c(&pc, 90202), 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The client's ACK should be forwarded");
    TEST_ASSERT(has_entry(&pc), "The entry should stay while the client's FIN is unacknowledged");

    // Acknowledging the 30 bytes but not the FIN after them changes nothing
    server_seg(&pc, RTE_TCP_ACK_FLAG, 90202, c2s(&pc, 3131), 0, &res, NULL, NULL);
    TEST_ASSERT(has_entry(&pc), "An ACK short of the client's FIN should not release the entry");

    server_seg(&pc, RTE_TCP_ACK_FLAG, 90202, c2s(&pc, 3132), 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The server's ACK should be forwarded");
    TEST_ASSERT(!has_entry(&pc), "The ACK of the second FIN should release the entry");
    TEST_ASSERT_EQ(0, connections_active(), "No entry should remain");
    TEST_ASSERT_EQ(1, connections_closed(), "The release should count as closed");
    syn_proxy_cleanup();
}

// The server sends its FIN before it has the client's last data: the client's
// FIN is not acknowledged yet. The client's ACK of the server's FIN must not
// release the entry: the client's retransmitted data and FIN are still
// translated, and the server's ACK of them releases it.
void test_syn_proxy_proxied_close_waits_for_both_acks(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct proxied_conn pc;
    struct syn_proxy_result res;
    uint32_t seq = 0, ack = 0;

    const char *err = open_proxied(&pc, 0x0A100074, 45004, 4000, 100000);
    TEST_ASSERT(err == NULL, err);

    // 100 bytes and the FIN, which the server does not receive
    client_seg(&pc, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 4001, s2c(&pc, 100001), 100, &res, NULL, NULL);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The client's data should be forwarded");
    client_seg(&pc, FIN_ACK, 4101, s2c(&pc, 100001), 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The client's FIN should be forwarded");

    // The server closes, still acknowledging only the handshake
    server_seg(&pc, FIN_ACK, 100001, c2s(&pc, 4001), 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The server's FIN should be forwarded");
    client_seg(&pc, RTE_TCP_ACK_FLAG, 4102, s2c(&pc, 100002), 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The client's ACK should be forwarded");
    TEST_ASSERT(has_entry(&pc), "The entry should stay while the client's FIN is unacknowledged");

    // The client retransmits; both are still translated
    client_seg(&pc, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 4001, s2c(&pc, 100002), 100, &res, &seq, &ack);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The retransmitted data should be forwarded");
    TEST_ASSERT(res.packet_modified, "The retransmitted data should be translated");
    TEST_ASSERT_EQ(c2s(&pc, 4001), seq, "The retransmitted data should carry the server's numbering");
    TEST_ASSERT_EQ(100002, ack, "The retransmitted data should acknowledge the server's FIN");
    client_seg(&pc, FIN_ACK, 4101, s2c(&pc, 100002), 0, &res, &seq, NULL);
    TEST_ASSERT(res.packet_modified, "The retransmitted FIN should be translated");
    TEST_ASSERT_EQ(c2s(&pc, 4101), seq, "The retransmitted FIN should carry the server's numbering");
    TEST_ASSERT(has_entry(&pc), "The entry should stay until the client's FIN is acknowledged");

    // An ACK beyond the end of the client's FIN acknowledges nothing: the
    // client never sent that far (TCP drops such an ACK)
    server_seg(&pc, RTE_TCP_ACK_FLAG, 100002, c2s(&pc, 4102) + 1000, 0, &res, NULL, NULL);
    TEST_ASSERT(has_entry(&pc), "An ACK beyond the client's FIN should not acknowledge it");

    server_seg(&pc, RTE_TCP_ACK_FLAG, 100002, c2s(&pc, 4102), 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The server's ACK should be forwarded");
    TEST_ASSERT(!has_entry(&pc), "The ACK of the client's FIN should release the entry");
    TEST_ASSERT_EQ(1, connections_closed(), "The release should count as closed");

    // The other way round: the server's last data and its FIN do not reach
    // the client, which closes acknowledging only the handshake. The
    // server's ACK of the client's FIN must not release the entry.
    err = open_proxied(&pc, 0x0A10007C, 45012, 7000, 150000);
    TEST_ASSERT(err == NULL, err);
    server_seg(&pc, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 150001, c2s(&pc, 7001), 100, &res, NULL, NULL);
    server_seg(&pc, FIN_ACK, 150101, c2s(&pc, 7001), 0, &res, NULL, NULL);
    client_seg(&pc, FIN_ACK, 7001, s2c(&pc, 150001), 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The client's FIN should be forwarded");
    server_seg(&pc, RTE_TCP_ACK_FLAG, 150102, c2s(&pc, 7002), 0, &res, NULL, NULL);
    TEST_ASSERT(has_entry(&pc), "The entry should stay while the server's FIN is unacknowledged");
    server_seg(&pc, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 150001, c2s(&pc, 7002), 100, &res, &seq, NULL);
    TEST_ASSERT_EQ(s2c(&pc, 150001), seq, "The retransmitted data should carry the client's numbering");
    client_seg(&pc, RTE_TCP_ACK_FLAG, 7002, s2c(&pc, 150102), 0, &res, NULL, NULL);
    TEST_ASSERT(!has_entry(&pc), "The ACK of the server's FIN should release the entry");
    TEST_ASSERT_EQ(2, connections_closed(), "Each release should count as closed");
    syn_proxy_cleanup();
}

// The client aborts with RST+ACK: translated and forwarded, and the entry goes
// (the RST+ACK case of proxied_close.c, where it stayed ESTABLISHED). A
// connection still waiting on its server goes too, with its half-open slot;
// its RST passes untranslated, as an RST without ACK does.
void test_syn_proxy_proxied_reset_with_ack(void) {
    int limit = half_open_limit();
    TEST_ASSERT(limit > 1, "A source should be able to open several waiting connections");

    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct proxied_conn pc;
    struct syn_proxy_result res;
    uint32_t seq = 0, ack = 0;

    const char *err = open_proxied(&pc, 0x0A100075, 45005, 5000, 110000);
    TEST_ASSERT(err == NULL, err);
    exchange_data(&pc);
    struct syn_proxy_stats before;
    syn_proxy_get_stats(&before);
    client_seg(&pc, RST_ACK, 5101, s2c(&pc, 110201), 0, &res, &seq, &ack);
    struct syn_proxy_stats after;
    syn_proxy_get_stats(&after);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The client's RST+ACK should be forwarded");
    TEST_ASSERT(res.packet_modified, "The client's RST+ACK should be translated");
    TEST_ASSERT_EQ(before.packets_proxied_c2s + 1, after.packets_proxied_c2s,
                   "An RST+ACK of an established connection should count as a proxied segment");
    TEST_ASSERT_EQ(c2s(&pc, 5101), seq, "The RST should carry the server's numbering");
    TEST_ASSERT_EQ(110201, ack, "The RST should acknowledge the server's data");
    TEST_ASSERT(!has_entry(&pc), "RST+ACK should release the entry");
    TEST_ASSERT_EQ(0, connections_active(), "No entry should remain");
    TEST_ASSERT_EQ(1, connections_closed(), "The release should count as closed");

    // A connection waiting on its server, from a source at its half-open limit
    TEST_ASSERT_EQ(limit, open_until_drop(0x0A100076, 46000),
                   "The source should open waiting connections up to its limit");
    send_tcp(DIRECTION_INBOUND, 0x0A100076, RACE_SERVER, 46000, 80, RST_ACK, 1001, 1, NULL, &res);
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, res.action, "A waiting connection's RST+ACK should pass untranslated");
    TEST_ASSERT_EQ(limit - 1, (int)connections_active(), "The waiting connection's entry should go");
    TEST_ASSERT_EQ(1, open_until_drop(0x0A100076, 46500),
                   "Its half-open slot should be released");
    syn_proxy_cleanup();
}

// Under attack every new connection is proxied. Connections that end must free
// their entries: once each entry stayed for the idle timeout, so a table of
// max_connections filled after that many connections and valid cookies were
// then dropped (table_full_drops).
void test_syn_proxy_proxied_close_frees_table(void) {
    init_default_config();
    default_config.max_connections = 16;
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct proxied_conn pc;
    struct syn_proxy_result res;

    for (uint32_t i = 0; i < 64; i++) {
        uint32_t isn = 1000 + i * 1000, server_isn = 500000 + i * 1000;
        const char *err = open_proxied(&pc, 0x0A100077, (uint16_t)(47000 + i), isn, server_isn);
        TEST_ASSERT(err == NULL, err);
        exchange_data(&pc);
        if (i % 2 == 0) {
            // FINs and the last ACK, the client first
            client_seg(&pc, FIN_ACK, isn + 101, s2c(&pc, server_isn + 201), 0, &res, NULL, NULL);
            server_seg(&pc, FIN_ACK, server_isn + 201, c2s(&pc, isn + 102), 0, &res, NULL, NULL);
            client_seg(&pc, RTE_TCP_ACK_FLAG, isn + 102, s2c(&pc, server_isn + 202), 0, &res, NULL, NULL);
        } else {
            client_seg(&pc, RST_ACK, isn + 101, s2c(&pc, server_isn + 201), 0, &res, NULL, NULL);
        }
        TEST_ASSERT_EQ(0, connections_active(), "An ended connection should free its entry");
    }
    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(64, stats.connections_established, "Every connection should be established");
    TEST_ASSERT_EQ(64, stats.connections_closed, "Every connection should be released once");
    TEST_ASSERT_EQ(0, stats.table_full_drops, "No valid cookie should be dropped");
    syn_proxy_cleanup();
}

// Both sides sent FIN and the last ACK is missing: the entry stays CLOSING so
// that a late last ACK is still translated, and the cleanup releases it once no
// segment came for connect_timeout_ms (the cleanup clock seam stands in for
// the wait). The last case is the round-3 probe's close, whose ACKs carry
// acknowledgement numbers 0 and 1 and so acknowledge neither FIN.
void test_syn_proxy_proxied_closing_waits_for_last_ack(void) {
    init_default_config();
    syn_proxy_init(&default_config);   // connect_timeout_ms 5000
    syn_proxy_reset_stats();
    struct proxied_conn a, b, c, p;
    struct syn_proxy_result res;
    uint32_t seq = 0, ack = 0;
    const uint64_t hz = rte_get_tsc_hz();

    const char *err = open_proxied(&a, 0x0A100078, 45008, 8000, 120000);
    TEST_ASSERT(err == NULL, err);
    err = open_proxied(&b, 0x0A100079, 45009, 9000, 130000);
    TEST_ASSERT(err == NULL, err);
    err = open_proxied(&c, 0x0A10007B, 45011, 6000, 140000);
    TEST_ASSERT(err == NULL, err);
    err = open_proxied(&p, 0x0A10007A, 45010, 5000, 900000);
    TEST_ASSERT(err == NULL, err);
    exchange_data(&a);
    exchange_data(&b);
    exchange_data(&c);

    client_seg(&a, FIN_ACK, 8101, s2c(&a, 120201), 0, &res, NULL, NULL);
    server_seg(&a, FIN_ACK, 120201, c2s(&a, 8102), 0, &res, NULL, NULL);
    client_seg(&b, FIN_ACK, 9101, s2c(&b, 130201), 0, &res, NULL, NULL);
    server_seg(&b, FIN_ACK, 130201, c2s(&b, 9102), 0, &res, NULL, NULL);
    // The probe's close: client data, FIN+ACK, server FIN+ACK, last ACK
    client_seg(&p, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 5001, 0, 0, &res, NULL, NULL);
    client_seg(&p, FIN_ACK, 5001, 0, 0, &res, NULL, NULL);
    server_seg(&p, FIN_ACK, 900001, 1, 0, &res, NULL, NULL);
    client_seg(&p, RTE_TCP_ACK_FLAG, 5002, 0, 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The probe's last ACK should be forwarded");

    // A pass now finds no entry due: segments came less than 5 s ago
    TEST_ASSERT_EQ(0, syn_proxy_cleanup_connections(), "A closing entry should wait for its last ACK");
    TEST_ASSERT(has_entry(&a) && has_entry(&b) && has_entry(&p), "Closing entries should stay");

    // a's last ACK arrives: translated, and it releases the entry
    client_seg(&a, RTE_TCP_ACK_FLAG, 8102, s2c(&a, 120202), 0, &res, &seq, &ack);
    TEST_ASSERT(res.packet_modified, "A late last ACK should still be translated");
    TEST_ASSERT_EQ(c2s(&a, 8102), seq, "The late last ACK should carry the server's numbering");
    TEST_ASSERT_EQ(120202, ack, "The late last ACK should acknowledge the server's FIN");
    TEST_ASSERT(!has_entry(&a), "The late last ACK should release the entry");

    // c: both FINs, then the server resets: translated, and the entry goes
    client_seg(&c, FIN_ACK, 6101, s2c(&c, 140201), 0, &res, NULL, NULL);
    server_seg(&c, FIN_ACK, 140201, c2s(&c, 6102), 0, &res, NULL, NULL);
    server_seg(&c, RST_ACK, 140202, c2s(&c, 6102), 0, &res, &seq, &ack);
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "A closing connection's server RST should be forwarded");
    TEST_ASSERT(res.packet_modified, "A closing connection's server RST should be translated");
    TEST_ASSERT_EQ(s2c(&c, 140202), seq, "The server's RST should carry the client's numbering");
    TEST_ASSERT_EQ(6102, ack, "The server's RST should acknowledge the client's FIN");
    TEST_ASSERT(!has_entry(&c), "The server's RST should release the entry");

    // b's and the probe's never come: past connect_timeout_ms the cleanup releases them
    cleanup_clock_held = rte_get_tsc_cycles() + 3 * hz;
    TEST_ASSERT_EQ(0, syn_proxy_cleanup_connections(), "Within connect_timeout_ms the entries should stay");
    cleanup_clock_held = rte_get_tsc_cycles() + 7 * hz;
    TEST_ASSERT_EQ(2, syn_proxy_cleanup_connections(), "Past connect_timeout_ms the cleanup should release them");
    cleanup_clock_held = 0;
    TEST_ASSERT(!has_entry(&b) && !has_entry(&p), "Both closing entries should be gone");

    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, stats.connections_active, "No entry should remain");
    TEST_ASSERT_EQ(2, stats.connections_closed, "The last ACK's and the RST's releases should count as closed");
    TEST_ASSERT_EQ(0, stats.connections_timeout, "A closing entry is not an idle timeout");
    TEST_ASSERT_EQ(0, stats.server_timeout, "A closing entry is not a server timeout");
    syn_proxy_cleanup();
}

// The other lcore's segment, applied at SYN_PROXY_SEAM_CLOSE of this lcore's
static struct proxied_conn seam_pc;

static void seam_server_acks_client_fin(void) {
    struct syn_proxy_result r;
    server_seg(&seam_pc, RTE_TCP_ACK_FLAG, seam_pc.server_isn + 202, c2s(&seam_pc, seam_pc.isn + 102),
               0, &r, NULL, NULL);
}

static void seam_server_resets(void) {
    struct syn_proxy_result r;
    server_seg(&seam_pc, RST_ACK, seam_pc.server_isn + 202, c2s(&seam_pc, seam_pc.isn + 102),
               0, &r, NULL, NULL);
}

// The server resets the connection, and a new proxied connection takes the
// slot it freed (the retiring lcore's cache hands that slot out next)
static struct proxied_conn seam_next;
static const char *seam_next_err;

static void seam_server_resets_slot_reused(void) {
    struct syn_proxy_result r;
    server_seg(&seam_pc, RST_ACK, seam_pc.server_isn + 201, c2s(&seam_pc, seam_pc.isn + 101),
               0, &r, NULL, NULL);
    seam_next_err = open_proxied(&seam_next, 0x0A1000A4, 45024, 24000, 240000);
}

// The client's and the server's segments of one connection meet its entry on
// two lcores (SYN_PROXY_SEAM_CLOSE: the other lcore's segment runs between
// this lcore's read of the word and its swap)
void test_syn_proxy_proxied_close_acks_race(void) {
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct syn_proxy_result res;
    struct syn_proxy_stats stats;

    // 1. The FINs crossed; the client acknowledges the server's FIN while the
    //    server acknowledges the client's. The client's swap fails, it decides
    //    again from the new word, finds both FINs acknowledged and ends the
    //    entry. (A plain store would lose the server's acknowledgement.)
    const char *err = open_proxied(&seam_pc, 0x0A1000A1, 45021, 21000, 210000);
    TEST_ASSERT(err == NULL, err);
    exchange_data(&seam_pc);
    client_seg(&seam_pc, FIN_ACK, 21101, s2c(&seam_pc, 210201), 0, &res, NULL, NULL);
    server_seg(&seam_pc, FIN_ACK, 210201, c2s(&seam_pc, 21101), 0, &res, NULL, NULL);
    arm_seam(SYN_PROXY_SEAM_CLOSE, seam_server_acks_client_fin);
    client_seg(&seam_pc, RTE_TCP_ACK_FLAG, 21102, s2c(&seam_pc, 210202), 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(1, seam_calls, "The client's ACK should reach the close bookkeeping");
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The client's ACK should be forwarded");
    TEST_ASSERT(!has_entry(&seam_pc), "The second acknowledgement should end the entry");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, stats.connections_active, "No entry should remain");
    TEST_ASSERT_EQ(1, stats.connections_closed, "The close should count once");

    // 2. The client's last ACK is about to end the entry when the server's RST
    //    ends it on the other lcore: the RST counts it, the ACK does not
    err = open_proxied(&seam_pc, 0x0A1000A2, 45022, 22000, 220000);
    TEST_ASSERT(err == NULL, err);
    exchange_data(&seam_pc);
    client_seg(&seam_pc, FIN_ACK, 22101, s2c(&seam_pc, 220201), 0, &res, NULL, NULL);
    server_seg(&seam_pc, FIN_ACK, 220201, c2s(&seam_pc, 22102), 0, &res, NULL, NULL);
    arm_seam(SYN_PROXY_SEAM_CLOSE, seam_server_resets);
    client_seg(&seam_pc, RTE_TCP_ACK_FLAG, 22102, s2c(&seam_pc, 220202), 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(1, seam_calls, "The client's ACK should reach the close bookkeeping");
    TEST_ASSERT_EQ(SYN_PROXY_FORWARD, res.action, "The client's ACK should be forwarded");
    TEST_ASSERT(!has_entry(&seam_pc), "The RST should have ended the entry");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, stats.connections_active, "No entry should remain");
    TEST_ASSERT_EQ(2, stats.connections_closed, "Each connection should count once");

    // 3. The client's FIN is about to be recorded when the server's RST ends
    //    the connection on the other lcore and a new proxied connection takes
    //    its slot. The swap fails on the new generation, and the FIN must not
    //    be recorded on the new connection, which stays ESTABLISHED and closes
    //    on its own segments.
    err = open_proxied(&seam_pc, 0x0A1000A3, 45023, 23000, 230000);
    TEST_ASSERT(err == NULL, err);
    exchange_data(&seam_pc);
    seam_next_err = "not run";
    arm_seam(SYN_PROXY_SEAM_CLOSE, seam_server_resets_slot_reused);
    client_seg(&seam_pc, FIN_ACK, 23101, s2c(&seam_pc, 230201), 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(1, seam_calls, "The client's FIN should reach the close bookkeeping");
    TEST_ASSERT(seam_next_err == NULL, seam_next_err);
    TEST_ASSERT(!has_entry(&seam_pc), "The RST should have ended the old connection");
    TEST_ASSERT(has_entry(&seam_next), "The new connection should have its entry");
    client_seg(&seam_next, RTE_TCP_ACK_FLAG, 24001, seam_next.cookie + 1, 0, &res, NULL, NULL);
    TEST_ASSERT_EQ(SYN_PROXY_ESTABLISHED, res.conn_state,
                   "The old connection's FIN should not be recorded on the new one");
    client_seg(&seam_next, FIN_ACK, 24001, seam_next.cookie + 1, 0, &res, NULL, NULL);
    server_seg(&seam_next, FIN_ACK, 240001, c2s(&seam_next, 24002), 0, &res, NULL, NULL);
    client_seg(&seam_next, RTE_TCP_ACK_FLAG, 24002, s2c(&seam_next, 240002), 0, &res, NULL, NULL);
    TEST_ASSERT(!has_entry(&seam_next), "The new connection's own close should release it");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(0, stats.connections_active, "No entry should remain");
    TEST_ASSERT_EQ(4, stats.connections_closed, "Each connection should count once");
    syn_proxy_cleanup();
}

// ==================== Allocation Race Tests (race seams) ====================

// Another lcore's packets for the 4-tuple of the new entry this lcore is
// adding: its SYN creates an entry at SYN_PROXY_SEAM_ALLOC (after this
// lcore's lookup missed), and its RST retires that entry at
// SYN_PROXY_SEAM_CLAIM (after this lcore's add found the entry's key)
#define CLAIM_CLIENT    0x0A100081
#define CLAIM_PORT      44081
static int claim_seams_run = 0;
static bool claim_readd = false;

static void seam_other_resets_tuple(void) {
    struct syn_proxy_result r;
    send_tcp(DIRECTION_INBOUND, CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT, 80,
             RTE_TCP_RST_FLAG, 101, 0, NULL, &r);
    if (claim_readd) {
        // ... and a third lcore's SYN for the 4-tuple adds it again, on
        // another slot: another connection takes the freed slot first and
        // ends, so the slot is free again when this lcore reads it
        send_tcp(DIRECTION_INBOUND, CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT + 10, 80,
                 RTE_TCP_SYN_FLAG, 400, 0, NULL, &r);
        send_tcp(DIRECTION_INBOUND, CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT, 80,
                 RTE_TCP_SYN_FLAG, 300, 0, NULL, &r);
        send_tcp(DIRECTION_INBOUND, CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT + 10, 80,
                 RTE_TCP_RST_FLAG, 401, 0, NULL, &r);
    }
    claim_seams_run++;
}

static void seam_other_creates_tuple(void) {
    struct syn_proxy_result r;
    send_tcp(DIRECTION_INBOUND, CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT, 80,
             RTE_TCP_SYN_FLAG, 100, 0, NULL, &r);
    claim_seams_run++;
    arm_seam(SYN_PROXY_SEAM_CLAIM, seam_other_resets_tuple);
}

static bool claim_tuple_has_entry(void) {
    struct packet_features f = tcp_features(CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT, 80,
                                            RTE_TCP_ACK_FLAG, 101, 1);
    return syn_proxy_is_proxied(&f, DIRECTION_INBOUND);
}

// This lcore's add finds the key of another lcore's entry, which that lcore
// retires before this lcore claims the slot. Once the claim succeeded on the
// freed slot: this lcore's entry was live but the hash no longer mapped its
// key, and the next new connection, handed the same slot by the hash, got no
// entry at all. The claim must only take a slot its key maps to.
void test_syn_proxy_alloc_claim_spares_retired_key(void) {
    init_default_config();
    default_config.max_connections = 8;
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct syn_proxy_result res;

    // This lcore's SYN for the 4-tuple (normal load: bypassed, with an entry)
    claim_seams_run = 0;
    claim_readd = false;
    arm_seam(SYN_PROXY_SEAM_ALLOC, seam_other_creates_tuple);
    send_tcp(DIRECTION_INBOUND, CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT, 80,
             RTE_TCP_SYN_FLAG, 200, 0, NULL, &res);
    TEST_ASSERT_EQ(2, claim_seams_run, "The other lcore should create and reset the 4-tuple's entry");
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, res.action, "This lcore's SYN should be bypassed");
    TEST_ASSERT(claim_tuple_has_entry(), "This lcore's entry should be found by its 4-tuple");
    TEST_ASSERT_EQ(1, connections_active(), "One entry should be held");

    // The next new connection gets an entry
    send_tcp(DIRECTION_INBOUND, CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT + 1, 80,
             RTE_TCP_SYN_FLAG, 500, 0, NULL, &res);
    struct packet_features next = tcp_features(CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT + 1, 80,
                                               RTE_TCP_ACK_FLAG, 501, 1);
    TEST_ASSERT(syn_proxy_is_proxied(&next, DIRECTION_INBOUND), "The next new connection should get an entry");
    TEST_ASSERT_EQ(2, connections_active(), "Two entries should be held");

    // The 4-tuple's RST releases its entry, and the table takes max_connections again
    send_tcp(DIRECTION_INBOUND, CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT, 80,
             RTE_TCP_RST_FLAG, 201, 0, NULL, &res);
    TEST_ASSERT(!claim_tuple_has_entry(), "The RST should release this lcore's entry");
    TEST_ASSERT_EQ(7, fill_with_bypassed(CLAIM_CLIENT, RACE_SERVER, 30000, 7),
                   "Normal-load SYNs should be bypassed");
    TEST_ASSERT_EQ(8, connections_active(), "The table should hold max_connections entries");
    syn_proxy_cleanup();

    // The same with a third lcore adding the 4-tuple again after the reset, on
    // another slot: that entry is the third lcore's, and this lcore must not
    // take the free slot its add returned (a second entry for the 4-tuple,
    // which the hash does not map)
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    claim_seams_run = 0;
    claim_readd = true;
    arm_seam(SYN_PROXY_SEAM_ALLOC, seam_other_creates_tuple);
    send_tcp(DIRECTION_INBOUND, CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT, 80,
             RTE_TCP_SYN_FLAG, 200, 0, NULL, &res);
    claim_readd = false;
    TEST_ASSERT_EQ(2, claim_seams_run, "The other lcores should create, reset and re-create the entry");
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, res.action, "This lcore's SYN should be bypassed");
    TEST_ASSERT(claim_tuple_has_entry(), "The 4-tuple should keep the re-created entry");
    TEST_ASSERT_EQ(1, connections_active(), "Only one entry should be held for the 4-tuple");
    struct syn_proxy_stats st;
    syn_proxy_get_stats(&st);
    TEST_ASSERT_EQ(3, st.connections_created, "This lcore should create no entry of its own");
    syn_proxy_cleanup();
}

// The same race on a valid cookie: this lcore's waiting connection takes a
// half-open slot of its source, and must hold an entry the cleanup can reach,
// or the slot is never released
void test_syn_proxy_alloc_claim_cookie_path(void) {
    int limit = half_open_limit();
    TEST_ASSERT(limit > 1, "A source should be able to open several waiting connections");

    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct syn_proxy_result res;

    uint32_t cookie;
    TEST_ASSERT(get_cookie(CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT, 80, 1000, &cookie),
                "SYN should be challenged with a cookie");
    claim_seams_run = 0;
    claim_readd = false;
    arm_seam(SYN_PROXY_SEAM_ALLOC, seam_other_creates_tuple);
    send_cookie_ack(CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT, 80, 1000, cookie, &res);
    bool syn_sent = res.reply_pkt != NULL;
    if (res.reply_pkt) {
        rte_pktmbuf_free(res.reply_pkt);
    }
    TEST_ASSERT_EQ(2, claim_seams_run, "The other lcore should create and reset the 4-tuple's entry");
    TEST_ASSERT_EQ(SYN_PROXY_REPLY, res.action, "The valid cookie should open a server connection");
    TEST_ASSERT_EQ(SYN_PROXY_CONNECTING, res.conn_state, "The connection should wait on its server");
    TEST_ASSERT(syn_sent, "The SYN to the server should be sent");
    TEST_ASSERT(claim_tuple_has_entry(), "The waiting connection should be found by its 4-tuple");

    // It times out (the cleanup clock past connect_timeout_ms), and its source
    // gets its half-open slot back
    cleanup_clock_held = rte_get_tsc_cycles() + 6 * rte_get_tsc_hz();
    uint32_t cleaned = syn_proxy_cleanup_connections();
    cleanup_clock_held = 0;
    TEST_ASSERT_EQ(1, cleaned, "The waiting connection should time out");
    TEST_ASSERT_EQ(limit, open_until_drop(CLAIM_CLIENT, 30000),
                   "The timed-out connection's half-open slot should be released");
    syn_proxy_cleanup();
}

// The other lcore's SYN for the same new 4-tuple, between this lcore's lookup
// that found the key on the free slot and its claim of the slot
static void seam_other_claims_same_key(void) {
    struct syn_proxy_result r;
    send_tcp(DIRECTION_INBOUND, CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT, 80,
             RTE_TCP_SYN_FLAG, 100, 0, NULL, &r);
    claim_seams_run++;
}

// Two lcores add the same new 4-tuple at once: both find its key on the same
// free slot, and only the claim's compare-and-swap decides which one owns the
// entry. The other lcore claims first, so this lcore's swap fails and it takes
// no second entry (a plain store would count one connection twice and keep
// one of the max_connections entries reserved for nothing).
void test_syn_proxy_alloc_claim_swap_once(void) {
    init_default_config();
    default_config.max_connections = 8;
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct syn_proxy_result res;
    struct syn_proxy_stats stats;

    claim_seams_run = 0;
    arm_seam(SYN_PROXY_SEAM_CLAIM_SWAP, seam_other_claims_same_key);
    send_tcp(DIRECTION_INBOUND, CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT, 80,
             RTE_TCP_SYN_FLAG, 200, 0, NULL, &res);
    TEST_ASSERT_EQ(1, claim_seams_run, "The other lcore should add the 4-tuple at the claim");
    TEST_ASSERT_EQ(SYN_PROXY_BYPASS, res.action, "This lcore's SYN should still be bypassed");
    TEST_ASSERT(claim_tuple_has_entry(), "The 4-tuple should have the other lcore's entry");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(1, stats.connections_created, "Only one entry should be created");
    TEST_ASSERT_EQ(1, stats.connections_active, "Only one entry should be held");

    // The 4-tuple's RST releases it, and the table takes max_connections again
    send_tcp(DIRECTION_INBOUND, CLAIM_CLIENT, RACE_SERVER, CLAIM_PORT, 80,
             RTE_TCP_RST_FLAG, 101, 0, NULL, &res);
    TEST_ASSERT(!claim_tuple_has_entry(), "The RST should release the entry");
    TEST_ASSERT_EQ(8, fill_with_bypassed(CLAIM_CLIENT, RACE_SERVER, 30000, 8),
                   "Normal-load SYNs should be bypassed");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(8, stats.connections_active, "The table should hold max_connections entries");
    syn_proxy_cleanup();
}

// ==================== Cleanup Scan Budget Test ====================

// A pass that finds few entries due examines at most CLEANUP_SCAN_BUDGET
// (131072) entries, and the next pass resumes the scan where it stopped.
// Once a pass read every entry of the table whatever it found (about 49 ms
// on the main lcore for 900k entries).
void test_syn_proxy_cleanup_scan_budget_carries_over(void) {
    const uint32_t idle = 250000, due = 2000, scan_budget = 131072;

    init_default_config();
    default_config.max_connections = 1u << 18;
    default_config.connect_timeout_ms = 0;            // A waiting connection is due at once
    default_config.challenge_threshold = UINT32_MAX;  // Normal-load SYNs are bypassed
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();

    // 250000 bypassed connections, none due (idle timeout 300 s), and 2000
    // proxied ones waiting on their servers (due), spread among them by hash
    TEST_ASSERT_EQ(idle, fill_tuples(0x0B300000, idle), "Normal-load SYNs should be bypassed");
    for (uint32_t i = 0; i < due; i++) {
        TEST_ASSERT_EQ(SYN_PROXY_REPLY,
                       cookie_handshake(0x0B400000 + (i >> 5), RACE_SERVER,
                                        (uint16_t)(20000 + (i & 31)), 80, 1000, NULL),
                       "Valid cookie should open a server connection");
    }

    // The first pass stops at the scan budget, about half the table
    uint32_t first = syn_proxy_cleanup_connections();
    // The second resumes there and ends at the end of the table
    uint32_t second = syn_proxy_cleanup_connections();
    // The third starts over and finds nothing due
    uint32_t third = syn_proxy_cleanup_connections();
    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    uint32_t idle_left = count_tuples(0x0B300000, idle);
    syn_proxy_cleanup();

    printf("  passes: %u, %u, %u of %u due among %u entries (scan budget %u)\n",
           first, second, third, due, idle + due, scan_budget);
    TEST_ASSERT(first > 0 && first < due * 3 / 4,
                "The first pass should examine at most the scan budget, not the whole table");
    TEST_ASSERT(second > 0, "The second pass should resume where the first stopped");
    TEST_ASSERT_EQ(due, first + second, "The two passes together should cover the whole table");
    TEST_ASSERT_EQ(0, third, "The third pass should start over and find nothing due");
    TEST_ASSERT_EQ(due, stats.server_timeout, "Each waiting connection should time out once");
    TEST_ASSERT_EQ(idle, stats.connections_active, "The idle entries should all remain");
    TEST_ASSERT_EQ(idle, idle_left, "Every idle entry should still be found");
}

// ==================== Cleanup Generation Check Test ====================

// At the cleanup's first candidate (SYN_PROXY_SEAM_CLEANUP), both connections
// it found due are reset and two new ones take their slots
static void seam_reset_both_and_reuse(void) {
    struct syn_proxy_result r;
    send_tcp(DIRECTION_INBOUND, 0x0A100091, RACE_SERVER, 44091, 80, RTE_TCP_RST_FLAG, 101, 0, NULL, &r);
    send_tcp(DIRECTION_INBOUND, 0x0A100091, RACE_SERVER, 44092, 80, RTE_TCP_RST_FLAG, 101, 0, NULL, &r);
    fill_with_bypassed(0x0A100092, RACE_SERVER, 44093, 2);
}

// The cleanup checks each candidate again before it ends it: still the entry it
// scanned (the same generation), and still due. Here the candidate it reaches
// second was reset after the scan and its slot taken by a new connection that
// is due too (the cleanup's clock is held past every timestamp, as an lcore
// whose TSC lags would stamp them). Without the generation check the cleanup
// would end the new entry with the old key: the delete fails, and the new
// entry stays dead with its key in the hash.
void test_syn_proxy_cleanup_spares_new_occupant(void) {
    init_default_config();
    default_config.idle_timeout_sec = 0;  // Every entry is due once the clock passes it
    syn_proxy_init(&default_config);
    syn_proxy_reset_stats();
    struct syn_proxy_stats stats;

    TEST_ASSERT_EQ(2, fill_with_bypassed(0x0A100091, RACE_SERVER, 44091, 2),
                   "Normal-load SYNs should be bypassed");
    cleanup_clock_held = rte_get_tsc_cycles() + rte_get_tsc_hz();
    arm_seam(SYN_PROXY_SEAM_CLEANUP, seam_reset_both_and_reuse);
    uint32_t cleaned = syn_proxy_cleanup_connections();
    TEST_ASSERT_EQ(1, seam_calls, "The cleanup should reach its first candidate");
    TEST_ASSERT_EQ(0, cleaned, "The cleanup should end neither reset connection nor a new one");

    struct packet_features n1 = tcp_features(0x0A100092, RACE_SERVER, 44093, 80, RTE_TCP_ACK_FLAG, 1001, 1);
    struct packet_features n2 = tcp_features(0x0A100092, RACE_SERVER, 44094, 80, RTE_TCP_ACK_FLAG, 1001, 1);
    TEST_ASSERT(syn_proxy_is_proxied(&n1, DIRECTION_INBOUND) && syn_proxy_is_proxied(&n2, DIRECTION_INBOUND),
                "Both new connections should keep their entries");
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(2, stats.connections_active, "The two new entries should be held");
    TEST_ASSERT_EQ(2, stats.connections_closed, "The two resets should count as closed");

    // The next pass (clock still held) ends both, and nothing is left
    cleaned = syn_proxy_cleanup_connections();
    cleanup_clock_held = 0;
    syn_proxy_get_stats(&stats);
    TEST_ASSERT_EQ(2, cleaned, "The next pass should end both new entries");
    TEST_ASSERT_EQ(0, stats.connections_active, "No entry should remain");
    TEST_ASSERT_EQ(2, stats.connections_timeout, "Each should count as one idle timeout");
    syn_proxy_cleanup();
}

// ==================== Re-initialization Tests (Rate State) ====================

// Normal-load SYNs from one client to ports base_port + i (count of them);
// returns how many were challenged (answered with a SYN-ACK), not bypassed
static int count_challenged(uint32_t client, uint16_t base_port, int count) {
    int challenged = 0;
    for (int i = 0; i < count; i++) {
        struct syn_proxy_result res;
        send_tcp(DIRECTION_INBOUND, client, 0xC0A80101, base_port + i, 80,
                 RTE_TCP_SYN_FLAG, 1000, 0, NULL, &res);
        if (res.reply_pkt) {
            rte_pktmbuf_free(res.reply_pkt);
        }
        if (res.action == SYN_PROXY_REPLY || res.action == SYN_PROXY_REPLY_INPLACE) {
            challenged++;
        }
    }
    return challenged;
}

// The challenge threshold some subtests lower would otherwise outlive them
// where init keeps it: re-init with the default set explicitly
static void restore_challenge_threshold(void) {
    init_default_config();
    default_config.challenge_threshold = 1000;
    syn_proxy_init(&default_config);
    syn_proxy_cleanup();
}

void test_syn_proxy_reinit_default_challenge_threshold(void) {
    // Above a configured 50 SYN/s, normal-load SYNs are challenged
    init_default_config();
    default_config.challenge_threshold = 50;
    syn_proxy_init(&default_config);
    int challenged_low = count_challenged(0x0A0D0001, 20000, 60);
    syn_proxy_cleanup();

    // A config with no threshold gets the default (1000 SYN/s), not the
    // previous init's
    init_default_config();
    syn_proxy_init(&default_config);
    int challenged_default = count_challenged(0x0A0D0002, 20000, 60);
    syn_proxy_cleanup();

    restore_challenge_threshold();
    TEST_ASSERT(challenged_low > 0, "SYNs above the configured threshold should be challenged");
    TEST_ASSERT_EQ(0, challenged_default,
                   "After re-init without a threshold, 60 SYNs should stay under the default");
}

void test_syn_proxy_reinit_resets_syn_rate(void) {
    init_default_config();
    default_config.challenge_threshold = 50;
    syn_proxy_init(&default_config);
    int challenged_before = count_challenged(0x0A0E0001, 20000, 60);
    syn_proxy_cleanup();

    // Same threshold after re-init: the SYNs the previous init counted must
    // not count against the new one
    syn_proxy_init(&default_config);
    int challenged_after = count_challenged(0x0A0E0002, 20000, 1);
    syn_proxy_cleanup();

    restore_challenge_threshold();
    TEST_ASSERT(challenged_before > 0, "SYNs above the configured threshold should be challenged");
    TEST_ASSERT_EQ(0, challenged_after,
                   "After re-init the first normal-load SYN should not be challenged for the old rate");
}

void test_syn_proxy_reinit_resets_mode_windows(void) {
    init_default_config();
    default_config.stateless_threshold_pps = 10;
    default_config.stateful_threshold_pps = 5;
    default_config.mode_switch_delay_ms = 1;
    syn_proxy_init(&default_config);

    // Adaptive mode switches to stateless after 3 consecutive 1 s windows
    // with more challenged SYNs than stateless_threshold_pps. A window closes
    // on the first challenged SYN after its end. Two such windows:
    uint32_t cookie;
    for (int w = 0; w < 2; w++) {
        for (int i = 0; i < 20; i++) {
            get_cookie(0x0A0F0001, 0xC0A80101, 20000 + w * 100 + i, 80, 1000, &cookie);
        }
        rte_delay_ms(1050);
        get_cookie(0x0A0F0001, 0xC0A80101, 20050 + w * 100, 80, 1000, &cookie);
    }
    enum syn_proxy_mode mode_before = syn_proxy_get_mode();
    syn_proxy_cleanup();

    // ... and one more after a re-init, which must not complete the count
    syn_proxy_init(&default_config);
    for (int i = 0; i < 20; i++) {
        get_cookie(0x0A0F0002, 0xC0A80101, 20000 + i, 80, 1000, &cookie);
    }
    rte_delay_ms(1050);
    get_cookie(0x0A0F0002, 0xC0A80101, 20050, 80, 1000, &cookie);
    enum syn_proxy_mode mode_after = syn_proxy_get_mode();
    syn_proxy_cleanup();

    TEST_ASSERT_EQ(SYN_PROXY_MODE_STATEFUL, mode_before,
                   "Two windows above the threshold should not switch to stateless");
    TEST_ASSERT_EQ(SYN_PROXY_MODE_STATEFUL, mode_after,
                   "After re-init one window above the threshold should not switch to stateless");
}

// Challenged SYNs in stateless mode until the first is not answered; returns
// how many were answered. *last gets the action for that first one.
static uint32_t answer_until_limited(uint32_t src_base, enum syn_proxy_action *last) {
    struct syn_proxy_result res;
    uint32_t answered = 0;
    res.action = SYN_PROXY_REPLY_INPLACE;
    for (uint32_t i = 0; i < 1000000; i++) {
        send_tcp(DIRECTION_INBOUND, src_base + i, 0xC0A80101, 1024 + (i & 0x7FFF), 80,
                 RTE_TCP_SYN_FLAG, i, 0, &tcp_flood_anom, &res);
        if (res.action != SYN_PROXY_REPLY_INPLACE) break;
        answered++;
    }
    *last = res.action;
    return answered;
}

void test_syn_proxy_reinit_resets_synack_window(void) {
    // The SYN-ACK budget is per 1 s window of syn_proxy_synack_clock(). This
    // subtest holds that clock, so the window cannot roll over however slowly
    // the runner sends the SYNs below.
    const uint64_t t0 = rte_rdtsc();
    synack_clock_held = t0;
    init_default_config();
    syn_proxy_init(&default_config);
    syn_proxy_set_mode(SYN_PROXY_MODE_STATELESS);  // In-place SYN-ACKs, no allocation

    // Use up the SYN-ACK budget of one 1 s window (250000)
    struct syn_proxy_result res;
    enum syn_proxy_action exhausted;
    uint32_t answered = answer_until_limited(0x0B000000, &exhausted);
    struct syn_proxy_stats stats;
    syn_proxy_get_stats(&stats);
    syn_proxy_cleanup();

    // A new init starts with the whole budget
    syn_proxy_init(&default_config);
    syn_proxy_set_mode(SYN_PROXY_MODE_STATELESS);
    send_tcp(DIRECTION_INBOUND, 0x0C000001, 0xC0A80101, 50000, 80,
             RTE_TCP_SYN_FLAG, 1, 0, &tcp_flood_anom, &res);
    enum syn_proxy_action after = res.action;

    // Use it up again; the next window starts one second of the clock later
    enum syn_proxy_action exhausted_again;
    uint32_t answered_again = answer_until_limited(0x0D000000, &exhausted_again);
    synack_clock_held = t0 + rte_get_tsc_hz();
    send_tcp(DIRECTION_INBOUND, 0x0E000001, 0xC0A80101, 50001, 80,
             RTE_TCP_SYN_FLAG, 1, 0, &tcp_flood_anom, &res);
    enum syn_proxy_action next_window = res.action;
    syn_proxy_cleanup();
    synack_clock_held = 0;

    TEST_ASSERT_EQ(SYN_PROXY_DROP, exhausted, "SYN-ACKs over the budget should be dropped");
    TEST_ASSERT_EQ(250000, answered, "One window should answer 250000 SYN-ACKs");
    TEST_ASSERT_EQ(1, stats.synack_rate_limited, "One SYN-ACK should be over the budget");
    TEST_ASSERT_EQ(SYN_PROXY_REPLY_INPLACE, after,
                   "After re-init a challenged SYN should get its SYN-ACK");
    TEST_ASSERT_EQ(SYN_PROXY_DROP, exhausted_again, "SYN-ACKs over the new budget should be dropped");
    TEST_ASSERT_EQ(250000 - 1, answered_again, "The new budget should have room for the rest of its window");
    TEST_ASSERT_EQ(SYN_PROXY_REPLY_INPLACE, next_window,
                   "The next window should answer challenged SYNs again");
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
        "--no-shconf",
        "--no-telemetry",
        NULL
    };
    // The literal count 9 dropped the last option, so EAL took the shared
    // /tmp/dpdk/rte config and parallel tests skipped on its lock. --in-memory
    // is refused with --no-huge; --no-shconf creates no shared files, and
    // --no-telemetry no telemetry socket in the runtime directory.
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

    printf("\n========================================\n");
    printf("  SYN Proxy Unit Tests\n");
    printf("========================================\n\n");

    // Configuration tests (before any Layer 1 config is active)
    RUN_TEST(test_syn_proxy_challenge_without_config);
    RUN_TEST(test_layer1_spoofed_mode_without_config);

    // The challenge decision reads the active Layer 1 config whenever a per-IP
    // snapshot is present; the engine loads it before syn_proxy_init()
    layer1_config_defaults(&l1_config);
    layer1_config_set_active(&l1_config);

    // Initialization tests
    RUN_TEST(test_syn_proxy_init_success);
    RUN_TEST(test_syn_proxy_init_disabled);
    RUN_TEST(test_syn_proxy_init_max_connections);
    RUN_TEST(test_syn_proxy_double_init);
    RUN_TEST(test_syn_proxy_reinit_resets_half_open);

    // Cookie tests
    RUN_TEST(test_syn_cookie_generation);
    RUN_TEST(test_syn_proxy_normal_load_bypass);
    RUN_TEST(test_syn_cookie_validation_valid);
    RUN_TEST(test_syn_proxy_server_syn_without_options);
    RUN_TEST(test_syn_proxy_cookie_path_option_offers);
    RUN_TEST(test_syn_cookie_validation_invalid);
    RUN_TEST(test_syn_cookie_quick_check_repeated_invalid);
    RUN_TEST(test_syn_cookie_expired);

    // Statistics tests
    RUN_TEST(test_syn_proxy_stats_cookies_sent);
    RUN_TEST(test_syn_proxy_stats_invalid_cookies);
    RUN_TEST(test_syn_cookie_ack_zero_counted_once);

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
    RUN_TEST(test_syn_proxy_bypassed_released_on_close);
    RUN_TEST(test_syn_proxy_bypassed_idle_aged);
    RUN_TEST(test_syn_proxy_cleanup_drains_all_due);
    RUN_TEST(test_syn_proxy_free_after_cleanup_counts_once);
    RUN_TEST(test_syn_proxy_bypassed_tuple_reuse);

    // Spoofed-mode admission tests
    RUN_TEST(test_syn_proxy_spoofed_mode_admits_proxy_connections);
    RUN_TEST(test_syn_proxy_spoofed_mode_bypassed_needs_handshake);

    // Options and configuration
    RUN_TEST(test_syn_proxy_absent_mss_uses_default);
    RUN_TEST(test_syn_proxy_zero_threshold_config_agrees);

    // Cleanup budget and interleavings of two lcores
    RUN_TEST(test_syn_proxy_cleanup_budget_carries_over);
    RUN_TEST(test_syn_proxy_stale_free_spares_new_occupant);
    RUN_TEST(test_syn_proxy_connecting_end_once_cleanup_first);
    RUN_TEST(test_syn_proxy_connecting_end_once_synack_first);
    RUN_TEST(test_syn_proxy_cleanup_spares_connection_used_since_scan);
    RUN_TEST(test_syn_proxy_cleanup_spares_entries_created_during_pass);
    RUN_TEST(test_syn_proxy_non_eal_thread_changes_no_entry);

    // Close of proxied (challenged) connections
    RUN_TEST(test_syn_proxy_proxied_client_closes_first);
    RUN_TEST(test_syn_proxy_proxied_server_closes_first);
    RUN_TEST(test_syn_proxy_proxied_simultaneous_close);
    RUN_TEST(test_syn_proxy_proxied_close_waits_for_both_acks);
    RUN_TEST(test_syn_proxy_proxied_reset_with_ack);
    RUN_TEST(test_syn_proxy_proxied_close_frees_table);
    RUN_TEST(test_syn_proxy_proxied_closing_waits_for_last_ack);
    RUN_TEST(test_syn_proxy_proxied_close_acks_race);

    // Allocation race, cleanup scan budget and the cleanup's generation check
    RUN_TEST(test_syn_proxy_alloc_claim_spares_retired_key);
    RUN_TEST(test_syn_proxy_alloc_claim_cookie_path);
    RUN_TEST(test_syn_proxy_alloc_claim_swap_once);
    RUN_TEST(test_syn_proxy_cleanup_scan_budget_carries_over);
    RUN_TEST(test_syn_proxy_cleanup_spares_new_occupant);

    // Re-initialization tests (rate state). The SYN-ACK budget test sends
    // 500000 SYNs, so it runs last.
    RUN_TEST(test_syn_proxy_reinit_default_challenge_threshold);
    RUN_TEST(test_syn_proxy_reinit_resets_syn_rate);
    RUN_TEST(test_syn_proxy_reinit_resets_mode_windows);
    RUN_TEST(test_syn_proxy_reinit_resets_synack_window);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_run);
    printf("========================================\n\n");

    cleanup_mempool();
    rte_eal_cleanup();

    return tests_failed > 0 ? 1 : 0;
}
