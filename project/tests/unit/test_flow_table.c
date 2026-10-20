/**
 * @file test_flow_table.c
 * @brief Comprehensive unit tests for Flow Table module
 *
 * Tests cover:
 * - Flow creation and lookup
 * - Canonical key ordering
 * - Rate limiting
 * - Flow aging and timeout
 * - RST/FIN validation
 * - Emergency eviction
 * - Edge cases and concurrency scenarios
 * - IPv6 flow table siblings of the IPv4 fixes
 * - Concurrent writers on several lcores
 * - Deferred reuse of deleted entries (readers' quiescent states), the IPv6
 *   emergency eviction, the hash seed, and the writer-lock and publication
 *   guards pinned through seams
 *
 * FLOW_TEST_FILTER in the environment runs only the subtests whose name
 * contains it (for runs under a race detector or a mutation); unset, as
 * meson runs it, every subtest runs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>
#include <sched.h>

#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_random.h>
#include <rte_tcp.h>

#include "../../layer1/tables/flow_table.h"
#include "../../layer1/tables/flow_table_v6.h"
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

#define TEST_ASSERT_NULL(ptr, msg) do { \
    if ((ptr) != NULL) { \
        printf("  FAIL: %s (expected NULL, got %p, line %d)\n", msg, (void*)(ptr), __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_NOT_NULL(ptr, msg) do { \
    if ((ptr) == NULL) { \
        printf("  FAIL: %s (got NULL, line %d)\n", msg, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

// See the file header
static const char *test_filter = NULL;

// Undoes what a subtest that failed part-way may have left set: the seam
// actions, the hash seed mode and registered readers (defined with them below)
static void test_harness_reset(void);

// A failed assertion returns before the subtest's own cleanup call, which
// left the module initialized for the next subtest (its init then returns
// early on the stale state). Release both tables here so every subtest
// starts clean.
#define RUN_TEST(test_func) do { \
    if (test_filter != NULL && strstr(#test_func, test_filter) == NULL) { \
        break; \
    } \
    printf("Running %s...\n", #test_func); \
    tests_run++; \
    int failed_before = tests_failed; \
    test_func(); \
    if (tests_failed > failed_before) { \
        flow_table_cleanup(); \
        flow_table_v6_cleanup(); \
        test_harness_reset(); \
    } \
    if (tests_run - tests_failed - tests_passed == 1) { \
        tests_passed++; \
        printf("  PASS\n"); \
    } \
} while(0)

// ==================== Test Fixtures ====================

static struct flow_table_config default_config;

static void init_default_config(void) {
    default_config.max_flows = 10000;
    default_config.idle_timeout_sec = 60;
    default_config.syn_timeout_sec = 10;
    default_config.default_pps_limit = 0;  // Unlimited
    default_config.default_bps_limit = 0;  // Unlimited
    default_config.enable_syn_protection = true;
    default_config.aging_scan_limit = 4096;
    default_config.aging_scan_limit_pressure = 8192;
}

static void create_test_features(struct packet_features *features,
                                  uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t src_port, uint16_t dst_port,
                                  uint8_t protocol) {
    memset(features, 0, sizeof(*features));
    features->src_ip = rte_cpu_to_be_32(src_ip);
    features->dst_ip = rte_cpu_to_be_32(dst_ip);
    features->src_port = src_port;
    features->dst_port = dst_port;
    features->protocol = protocol;
    features->packet_size = 100;
    features->timestamp_tsc = rte_rdtsc();
}

// The flow key is (ip_lo, ip_hi, protocol) with no ports, so each helper
// flow below needs its own IP pair.

// Initial sequence numbers of the client and the server in the helpers
#define TEST_CLIENT_ISN 1000
#define TEST_SERVER_ISN 5000

// Three-way handshake: SYN and the final ACK from the client, SYN-ACK from
// the server. The flow ends ESTABLISHED with packets both ways. The final
// ACK acknowledges final_ack: a real client sends the server's ISN + 1
// (create_established_flow()), a blind spoofer that never saw the SYN-ACK
// can only guess.
static struct flow_entry *create_handshake_flow(uint32_t client_ip, uint32_t server_ip,
                                                uint32_t final_ack) {
    struct packet_features pkt;
    struct flow_entry *flow;
    bool created;

    create_test_features(&pkt, client_ip, server_ip, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN;
    flow = flow_table_lookup_or_create(&pkt, &created);
    if (!flow) {
        return NULL;
    }
    flow_table_update(flow, &pkt);

    create_test_features(&pkt, server_ip, client_ip, 80, 40000, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = TEST_SERVER_ISN;
    pkt.tcp_ack = TEST_CLIENT_ISN + 1;
    if (flow_table_lookup(&pkt) != flow) {
        return NULL;
    }
    flow_table_update(flow, &pkt);

    create_test_features(&pkt, client_ip, server_ip, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN + 1;
    pkt.tcp_ack = final_ack;
    if (flow_table_lookup(&pkt) != flow) {
        return NULL;
    }
    flow_table_update(flow, &pkt);

    return flow;
}

// Full three-way handshake: the final ACK acknowledges the server's ISN + 1.
// (With every sequence and ack number left 0 it did not, which is what a
// blind ACK looks like.)
static struct flow_entry *create_established_flow(uint32_t client_ip, uint32_t server_ip) {
    return create_handshake_flow(client_ip, server_ip, TEST_SERVER_ISN + 1);
}

// Half-open flow: the client's SYN with no reply (SYN_RECEIVED, one direction)
static struct flow_entry *create_half_open_flow(uint32_t client_ip, uint32_t server_ip) {
    struct packet_features pkt;
    bool created;

    create_test_features(&pkt, client_ip, server_ip, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN;
    struct flow_entry *flow = flow_table_lookup_or_create(&pkt, &created);
    if (flow) {
        flow_table_update(flow, &pkt);
    }
    return flow;
}

// The client's SYN and ACK with no reply seen: ESTABLISHED in one direction
// only. Eviction may take it, but it scores far above a half-open flow.
static struct flow_entry *create_one_way_established_flow(uint32_t client_ip, uint32_t server_ip) {
    struct packet_features pkt;
    bool created;

    create_test_features(&pkt, client_ip, server_ip, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN;
    struct flow_entry *flow = flow_table_lookup_or_create(&pkt, &created);
    if (!flow) {
        return NULL;
    }
    flow_table_update(flow, &pkt);

    pkt.tcp_flags = RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN + 1;
    flow_table_update(flow, &pkt);
    return flow;
}

static struct flow_entry *find_flow(uint32_t client_ip, uint32_t server_ip, uint8_t protocol) {
    struct packet_features pkt;
    create_test_features(&pkt, client_ip, server_ip, 40000, 80, protocol);
    return flow_table_lookup(&pkt);
}

static struct flow_entry *find_tcp_flow(uint32_t client_ip, uint32_t server_ip) {
    return find_flow(client_ip, server_ip, IPPROTO_TCP);
}

// ==================== Initialization Tests ====================

void test_flow_table_init_success(void) {
    init_default_config();
    int ret = flow_table_init(&default_config);
    TEST_ASSERT_EQ(0, ret, "flow_table_init should succeed");
    flow_table_cleanup();
}

void test_flow_table_init_large_capacity(void) {
    init_default_config();
    default_config.max_flows = 1000000;
    int ret = flow_table_init(&default_config);
    TEST_ASSERT_EQ(0, ret, "flow_table_init should handle 1M flows");
    flow_table_cleanup();
}

void test_flow_table_init_small_capacity(void) {
    init_default_config();
    default_config.max_flows = 100;
    int ret = flow_table_init(&default_config);
    TEST_ASSERT_EQ(0, ret, "flow_table_init should handle small capacity");
    flow_table_cleanup();
}

// ==================== Lookup and Create Tests ====================

void test_flow_table_create_new_flow(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct packet_features features;
    create_test_features(&features, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);

    bool created = false;
    struct flow_entry *flow = flow_table_lookup_or_create(&features, &created);

    TEST_ASSERT_NOT_NULL(flow, "Should create new flow");
    TEST_ASSERT(created, "created flag should be true");
    TEST_ASSERT_EQ(FLOW_STATE_NEW, flow->state, "New flow should be in NEW state");

    flow_table_cleanup();
}

void test_flow_table_lookup_existing_flow(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct packet_features features;
    create_test_features(&features, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);

    bool created1 = false;
    struct flow_entry *flow1 = flow_table_lookup_or_create(&features, &created1);
    TEST_ASSERT_NOT_NULL(flow1, "Should create flow");
    TEST_ASSERT(created1, "First lookup should create");

    // Second lookup with same key
    bool created2 = false;
    struct flow_entry *flow2 = flow_table_lookup_or_create(&features, &created2);
    TEST_ASSERT_NOT_NULL(flow2, "Should find existing flow");
    TEST_ASSERT(!created2, "Second lookup should not create");
    TEST_ASSERT(flow1 == flow2, "Should return same flow pointer");

    flow_table_cleanup();
}

void test_flow_table_lookup_only(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct packet_features features;
    create_test_features(&features, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);

    // Lookup without create - should return NULL
    struct flow_entry *flow1 = flow_table_lookup(&features);
    TEST_ASSERT_NULL(flow1, "Lookup-only should return NULL for non-existent flow");

    // Now create it
    bool created;
    struct flow_entry *flow2 = flow_table_lookup_or_create(&features, &created);
    TEST_ASSERT_NOT_NULL(flow2, "Should create flow");

    // Lookup again - should find it
    struct flow_entry *flow3 = flow_table_lookup(&features);
    TEST_ASSERT_NOT_NULL(flow3, "Lookup should find existing flow");
    TEST_ASSERT(flow2 == flow3, "Should return same flow");

    flow_table_cleanup();
}

// ==================== Canonical Key Tests ====================

void test_flow_table_canonical_key_same_direction(void) {
    init_default_config();
    flow_table_init(&default_config);

    // Packet from low IP to high IP
    struct packet_features features1;
    create_test_features(&features1, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);

    bool created1;
    struct flow_entry *flow1 = flow_table_lookup_or_create(&features1, &created1);
    TEST_ASSERT_NOT_NULL(flow1, "Should create flow");
    TEST_ASSERT(created1, "Should be new flow");

    // Verify direction
    TEST_ASSERT_EQ(FLOW_DIR_LO_TO_HI, features1.flow_direction, "Direction should be LO_TO_HI");

    flow_table_cleanup();
}

void test_flow_table_canonical_key_reverse_direction(void) {
    init_default_config();
    flow_table_init(&default_config);

    // Packet from high IP to low IP
    struct packet_features features1;
    create_test_features(&features1, 0xC0A80101, 0x0A000001, 80, 12345, IPPROTO_TCP);

    bool created1;
    struct flow_entry *flow1 = flow_table_lookup_or_create(&features1, &created1);
    TEST_ASSERT_NOT_NULL(flow1, "Should create flow");
    TEST_ASSERT(created1, "Should be new flow");

    // Verify direction is reverse
    TEST_ASSERT_EQ(FLOW_DIR_HI_TO_LO, features1.flow_direction, "Direction should be HI_TO_LO");

    flow_table_cleanup();
}

void test_flow_table_canonical_key_bidirectional(void) {
    init_default_config();
    flow_table_init(&default_config);

    // Packet from low IP to high IP
    struct packet_features features1;
    create_test_features(&features1, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);

    bool created1;
    struct flow_entry *flow1 = flow_table_lookup_or_create(&features1, &created1);
    TEST_ASSERT_NOT_NULL(flow1, "Should create flow");
    TEST_ASSERT(created1, "First packet should create");

    // Packet from high IP to low IP (reverse direction, same flow)
    struct packet_features features2;
    create_test_features(&features2, 0xC0A80101, 0x0A000001, 80, 12345, IPPROTO_TCP);

    bool created2;
    struct flow_entry *flow2 = flow_table_lookup_or_create(&features2, &created2);
    TEST_ASSERT_NOT_NULL(flow2, "Should find existing flow");
    TEST_ASSERT(!created2, "Reverse packet should NOT create new flow");
    TEST_ASSERT(flow1 == flow2, "Should be same flow for both directions");

    // Verify different directions
    TEST_ASSERT_EQ(FLOW_DIR_LO_TO_HI, features1.flow_direction, "features1 should be LO_TO_HI");
    TEST_ASSERT_EQ(FLOW_DIR_HI_TO_LO, features2.flow_direction, "features2 should be HI_TO_LO");

    flow_table_cleanup();
}

void test_flow_table_canonical_key_same_ip(void) {
    init_default_config();
    flow_table_init(&default_config);

    // Same source and destination IP (localhost scenario)
    struct packet_features features;
    create_test_features(&features, 0x7F000001, 0x7F000001, 12345, 80, IPPROTO_TCP);

    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&features, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow even with same IPs");

    flow_table_cleanup();
}

// ==================== Rate Limiting Tests ====================

void test_flow_table_rate_limit_pps(void) {
    init_default_config();
    default_config.default_pps_limit = 100; // 100 PPS
    flow_table_init(&default_config);

    struct packet_features features;
    create_test_features(&features, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);

    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&features, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");
    TEST_ASSERT_EQ(100, flow->pps_limit, "Should have PPS limit set");

    // Send packets and check rate limiting
    int accepted = 0;
    int dropped = 0;

    for (int i = 0; i < 200; i++) {
        features.timestamp_tsc = rte_rdtsc();
        enum rate_limit_action action = flow_table_check_rate_limit(flow, &features, NULL);
        if (action == RL_ACCEPT) {
            accepted++;
        } else {
            dropped++;
        }
    }

    // Some packets should be dropped due to rate limit
    // Note: exact numbers depend on timing
    TEST_ASSERT(dropped > 0, "Some packets should be dropped by rate limit");

    flow_table_cleanup();
}

void test_flow_table_rate_limit_bps(void) {
    init_default_config();
    default_config.default_bps_limit = 10000; // 10 KB/s
    flow_table_init(&default_config);

    struct packet_features features;
    create_test_features(&features, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    features.packet_size = 1000; // 1KB packets

    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&features, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");
    TEST_ASSERT_EQ(10000, flow->bps_limit, "Should have BPS limit set");

    flow_table_cleanup();
}

void test_flow_table_set_limits(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct packet_features features;
    create_test_features(&features, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);

    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&features, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");

    // Set custom limits
    int ret = flow_table_set_limits(&features, 500, 50000);
    TEST_ASSERT_EQ(0, ret, "set_limits should succeed");

    // Verify limits were set
    TEST_ASSERT_EQ(500, flow->pps_limit, "PPS limit should be 500");
    TEST_ASSERT_EQ(50000, flow->bps_limit, "BPS limit should be 50000");

    flow_table_cleanup();
}

// ==================== Flow Update Tests ====================

void test_flow_table_update_counters(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct packet_features features;
    create_test_features(&features, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    features.packet_size = 100;

    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&features, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");

    // Update flow multiple times
    for (int i = 0; i < 10; i++) {
        features.timestamp_tsc = rte_rdtsc();
        flow_table_update(flow, &features);
    }

    // Check counters (direction depends on canonical ordering)
    uint64_t total_packets = flow_total_packets(flow);
    uint64_t total_bytes = flow_total_bytes(flow);

    TEST_ASSERT_EQ(10, total_packets, "Should have 10 packets");
    TEST_ASSERT_EQ(1000, total_bytes, "Should have 1000 bytes");

    flow_table_cleanup();
}

void test_flow_table_update_bidirectional(void) {
    init_default_config();
    flow_table_init(&default_config);

    // Forward direction
    struct packet_features features1;
    create_test_features(&features1, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    features1.packet_size = 100;

    bool created1;
    struct flow_entry *flow = flow_table_lookup_or_create(&features1, &created1);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");

    for (int i = 0; i < 5; i++) {
        features1.timestamp_tsc = rte_rdtsc();
        flow_table_update(flow, &features1);
    }

    // Reverse direction
    struct packet_features features2;
    create_test_features(&features2, 0xC0A80101, 0x0A000001, 80, 12345, IPPROTO_TCP);
    features2.packet_size = 200;

    bool created2;
    struct flow_entry *flow2 = flow_table_lookup_or_create(&features2, &created2);
    TEST_ASSERT(flow == flow2, "Should be same flow");

    for (int i = 0; i < 3; i++) {
        features2.timestamp_tsc = rte_rdtsc();
        flow_table_update(flow2, &features2);
    }

    // Check bidirectional counters
    TEST_ASSERT_EQ(5, flow->packets_lo_to_hi, "Should have 5 packets lo->hi");
    TEST_ASSERT_EQ(3, flow->packets_hi_to_lo, "Should have 3 packets hi->lo");
    TEST_ASSERT_EQ(500, flow->bytes_lo_to_hi, "Should have 500 bytes lo->hi");
    TEST_ASSERT_EQ(600, flow->bytes_hi_to_lo, "Should have 600 bytes hi->lo");

    TEST_ASSERT(flow_is_bidirectional(flow), "Flow should be bidirectional");

    flow_table_cleanup();
}

// ==================== State Machine Tests ====================

void test_flow_table_tcp_state_syn(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct packet_features features;
    create_test_features(&features, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    features.tcp_flags = RTE_TCP_SYN_FLAG;

    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&features, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");

    flow_table_update(flow, &features);
    TEST_ASSERT_EQ(FLOW_STATE_SYN_RECEIVED, flow->state, "Should be in SYN_RECEIVED state");

    flow_table_cleanup();
}

void test_flow_table_tcp_state_established(void) {
    init_default_config();
    flow_table_init(&default_config);

    // SYN
    struct packet_features syn;
    create_test_features(&syn, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    syn.tcp_flags = RTE_TCP_SYN_FLAG;

    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&syn, &created);
    flow_table_update(flow, &syn);

    // SYN-ACK (reverse direction)
    struct packet_features synack;
    create_test_features(&synack, 0xC0A80101, 0x0A000001, 80, 12345, IPPROTO_TCP);
    synack.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;

    flow_table_lookup_or_create(&synack, &created);
    flow_table_update(flow, &synack);

    // ACK
    struct packet_features ack;
    create_test_features(&ack, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    ack.tcp_flags = RTE_TCP_ACK_FLAG;

    flow_table_update(flow, &ack);
    TEST_ASSERT_EQ(FLOW_STATE_ESTABLISHED, flow->state, "Should be ESTABLISHED after handshake");
    TEST_ASSERT(flow_is_established(flow), "flow_is_established should return true");

    flow_table_cleanup();
}

// ==================== Aging Tests ====================

void test_flow_table_aging_basic(void) {
    init_default_config();
    // TCP flows that never complete a handshake stay in FLOW_STATE_NEW, and
    // with SYN protection on they age by syn_timeout_sec, not idle_timeout_sec
    // (layer1_config_validate warns when syn_timeout_sec >= idle_timeout_sec)
    default_config.idle_timeout_sec = 1; // 1 second timeout
    default_config.syn_timeout_sec = 1;
    default_config.max_flows = 100;
    flow_table_init(&default_config);

    // Create some flows
    for (int i = 0; i < 10; i++) {
        struct packet_features features;
        create_test_features(&features, 0x0A000001 + i, 0xC0A80101, 12345 + i, 80, IPPROTO_TCP);

        bool created;
        flow_table_lookup_or_create(&features, &created);
    }

    uint32_t active, total, aged;
    flow_table_get_stats(&active, &total, &aged);
    TEST_ASSERT_EQ(10, active, "Should have 10 active flows");

    // Wait for timeout
    rte_delay_ms(1500);

    // Run aging
    uint32_t aged_count = flow_table_age_flows();

    flow_table_get_stats(&active, &total, &aged);
    TEST_ASSERT(active < 10, "Some flows should be aged out");
    TEST_ASSERT(aged_count > 0 || aged > 0, "Should have aged some flows");
    TEST_ASSERT_EQ(0, active, "All idle flows should be aged out");
    TEST_ASSERT_EQ(10, aged_count, "Should have aged all 10 flows");

    flow_table_cleanup();
}

void test_flow_table_aging_keeps_active(void) {
    init_default_config();
    // As in test_flow_table_aging_basic: without a 1 s SYN timeout this NEW-state
    // flow could not age within the 2 s loop and the test would pass vacuously
    default_config.idle_timeout_sec = 1;
    default_config.syn_timeout_sec = 1;
    flow_table_init(&default_config);

    struct packet_features features;
    create_test_features(&features, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);

    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&features, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");

    // Keep the flow active
    for (int i = 0; i < 20; i++) {
        rte_delay_ms(100);
        features.timestamp_tsc = rte_rdtsc();
        flow_table_update(flow, &features);
        flow_table_age_flows();
    }

    // Flow should still exist
    struct flow_entry *found = flow_table_lookup(&features);
    TEST_ASSERT_NOT_NULL(found, "Active flow should not be aged out");

    flow_table_cleanup();
}

void test_flow_table_aging_pressure_small_table(void) {
    init_default_config();
    // UDP flows age by idle_timeout_sec: 4 s normally, 1 s in pressure mode
    // (above 95% occupancy aging divides its timeouts by 4)
    default_config.max_flows = 10;
    default_config.idle_timeout_sec = 4;
    default_config.syn_timeout_sec = 4;
    flow_table_init(&default_config);

    // Flows stamped as last seen 1.5 s ago: only pressure timeouts expire them
    uint64_t idle_since = rte_rdtsc() - (rte_get_tsc_hz() * 3) / 2;

    // One flow in 10 slots is 10% occupancy. Free indices can sit off the
    // free ring in a per-lcore cache (before the caches were bounded, the
    // first allocation moved the other nine there), so aging must count
    // the flows in the hash. A 10-slot table now caches none:
    // test_flow_table_aging_pressure_cached_indices keeps a cache.
    struct packet_features features;
    bool created;
    create_test_features(&features, 0x0A000001, 0xC0A80101, 5000, 53, IPPROTO_UDP);
    struct flow_entry *flow = flow_table_lookup_or_create_tsc(&features, &created, idle_since);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");
    uint32_t occupancy = flow_table_get_occupancy_percent();
    TEST_ASSERT_EQ(10, occupancy, "One flow in 10 slots is 10%");

    // Results are taken into variables first: TEST_ASSERT_EQ evaluates its
    // actual argument again when it reports a failure
    uint32_t aged = flow_table_age_flows();
    TEST_ASSERT_EQ(0, aged, "A 10% full table should not use pressure timeouts");
    TEST_ASSERT_NOT_NULL(flow_table_lookup(&features), "The flow idle 1.5 s should survive aging");

    // A truly full table does enter pressure mode
    for (int i = 1; i < 10; i++) {
        create_test_features(&features, 0x0A000001 + i, 0xC0A80101, 5000, 53, IPPROTO_UDP);
        TEST_ASSERT_NOT_NULL(flow_table_lookup_or_create_tsc(&features, &created, idle_since),
                             "Should create flow");
    }
    occupancy = flow_table_get_occupancy_percent();
    TEST_ASSERT_EQ(100, occupancy, "Table should be full");
    aged = flow_table_age_flows();
    TEST_ASSERT_EQ(10, aged, "A full table should age flows idle 1.5 s");

    flow_table_cleanup();
}

// Creates count UDP flows last seen at last_seen_tsc
static int create_idle_udp_flows(uint32_t client_base, uint32_t count, uint64_t last_seen_tsc) {
    for (uint32_t i = 0; i < count; i++) {
        struct packet_features features;
        bool created;
        create_test_features(&features, client_base + i, 0xC0A80101, 5000, 53, IPPROTO_UDP);
        if (!flow_table_lookup_or_create_tsc(&features, &created, last_seen_tsc) || !created) {
            return -1;
        }
    }
    return 0;
}

void test_flow_table_aging_reinit_after_batch_limit(void) {
    init_default_config();
    // UDP flows idle 1.5 s against a 1 s idle timeout, in a table under half
    // full (no pressure mode): every flow is expired
    default_config.max_flows = 2048;
    default_config.idle_timeout_sec = 1;
    flow_table_init(&default_config);

    uint64_t idle_since = rte_rdtsc() - (rte_get_tsc_hz() * 3) / 2;
    TEST_ASSERT_EQ(0, create_idle_udp_flows(0x0A000001, 1000, idle_since), "Should create 1000 flows");

    // One pass ages at most 512 flows (the batch limit) and saves its position
    uint32_t aged = flow_table_age_flows();
    TEST_ASSERT_EQ(512, aged, "The pass should stop at the batch limit");
    flow_table_cleanup();

    // The saved position belongs to the old table. A new table's first pass
    // must start at its beginning and again fill a whole batch.
    flow_table_init(&default_config);
    idle_since = rte_rdtsc() - (rte_get_tsc_hz() * 3) / 2;
    TEST_ASSERT_EQ(0, create_idle_udp_flows(0x0B000001, 600, idle_since), "Should create 600 flows");
    aged = flow_table_age_flows();
    TEST_ASSERT_EQ(512, aged, "A new table's first pass should start at its beginning");

    flow_table_cleanup();
}

// ==================== RST/FIN Validation Tests ====================

void test_flow_table_rst_validation_valid(void) {
    init_default_config();
    flow_table_init(&default_config);

    // Create established flow
    struct packet_features syn;
    create_test_features(&syn, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    syn.tcp_flags = RTE_TCP_SYN_FLAG;
    syn.tcp_seq = 1000;

    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&syn, &created);
    flow_table_update(flow, &syn);

    // Enable sequence tracking
    flow->flags |= FLOW_FLAG_SEQ_TRACKING_ENABLED;
    flow->seq_lo_to_hi = 1001;
    flow->seq_hi_to_lo = 5000;

    // Valid RST with correct sequence
    struct packet_features rst;
    create_test_features(&rst, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    rst.tcp_flags = RTE_TCP_RST_FLAG;
    rst.tcp_seq = 1001;

    enum rst_fin_validation_result result = flow_table_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_VALID, result, "Valid RST should pass validation");

    flow_table_cleanup();
}

void test_flow_table_rst_validation_spoofed(void) {
    init_default_config();
    flow_table_init(&default_config);

    // Create flow with sequence tracking
    struct packet_features syn;
    create_test_features(&syn, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    syn.tcp_flags = RTE_TCP_SYN_FLAG;
    syn.tcp_seq = 1000;

    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&syn, &created);
    flow_table_update(flow, &syn);

    flow->flags |= FLOW_FLAG_SEQ_TRACKING_ENABLED;
    flow->seq_lo_to_hi = 1001;
    flow->seq_hi_to_lo = 5000;

    // Spoofed RST with wrong sequence. The accepted window is +/- 2^20 around
    // the expected sequence or, once the peer has sent an ACK, its last ACK
    // (RST_FIN_SEQ_WINDOW in flow_table.c), so 999999 was inside it; 2^30
    // past 1001 is not.
    struct packet_features rst;
    create_test_features(&rst, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    rst.tcp_flags = RTE_TCP_RST_FLAG;
    rst.tcp_seq = 1001 + 0x40000000; // Way out of window

    enum rst_fin_validation_result result = flow_table_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_SEQ_OUT_OF_WINDOW, result, "Spoofed RST should fail validation");

    flow_table_cleanup();
}

void test_flow_table_rst_validation_no_peer_ack(void) {
    init_default_config();
    flow_table_init(&default_config);

    // Client SYN with ISN 2^30 and no reply yet. The server has sent no ACK,
    // so the table's last-ACK field for the server is still 0.
    struct packet_features syn;
    create_test_features(&syn, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    syn.tcp_flags = RTE_TCP_SYN_FLAG;
    syn.tcp_seq = 0x40000000;

    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&syn, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");
    flow_table_update(flow, &syn);
    TEST_ASSERT(flow->flags & FLOW_FLAG_SEQ_TRACKING_ENABLED, "SYN should enable sequence tracking");

    // Client-side RSTs 4096 either side of 0 are about 2^30 from the expected
    // sequence; only a window around the never-sent server ACK covers them
    struct packet_features rst;
    enum rst_fin_validation_result result;
    create_test_features(&rst, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    rst.tcp_flags = RTE_TCP_RST_FLAG;
    rst.tcp_seq = 0x00001000;
    result = flow_table_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_SEQ_OUT_OF_WINDOW, result,
                   "RST near 0 should fail while the peer has sent no ACK");
    rst.tcp_seq = 0xFFFFF000;
    result = flow_table_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_SEQ_OUT_OF_WINDOW, result,
                   "RST just below 0 should fail while the peer has sent no ACK");

    // The expected sequence is still accepted
    rst.tcp_seq = 0x40000001;
    result = flow_table_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_VALID, result, "RST at the expected sequence should pass");

    // Complete the handshake
    struct packet_features pkt;
    create_test_features(&pkt, 0xC0A80101, 0x0A000001, 80, 12345, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = 5000;
    pkt.tcp_ack = 0x40000001;
    TEST_ASSERT(flow_table_lookup(&pkt) == flow, "SYN-ACK should map to the flow");
    flow_table_update(flow, &pkt);

    create_test_features(&pkt, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = 0x40000001;
    pkt.tcp_ack = 5001;
    TEST_ASSERT(flow_table_lookup(&pkt) == flow, "ACK should map to the flow");
    flow_table_update(flow, &pkt);
    TEST_ASSERT_EQ(FLOW_STATE_ESTABLISHED, flow->state, "Handshake should establish the flow");

    // The server then acknowledges 2^21 bytes of client data the table did
    // not see (another path). Its last ACK now opens the second window.
    create_test_features(&pkt, 0xC0A80101, 0x0A000001, 80, 12345, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = 5001;
    pkt.tcp_ack = 0x40000001 + 0x200000;
    TEST_ASSERT(flow_table_lookup(&pkt) == flow, "Server ACK should map to the flow");
    flow_table_update(flow, &pkt);

    rst.tcp_seq = 0x40000001 + 0x200000;
    result = flow_table_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_VALID, result,
                   "RST at the peer's last ACK should pass once an ACK was seen");
    rst.tcp_seq = 0x00001000;
    result = flow_table_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_SEQ_OUT_OF_WINDOW, result, "RST near 0 should still fail");

    flow_table_cleanup();
}

void test_flow_table_rst_no_flow(void) {
    init_default_config();
    flow_table_init(&default_config);

    // RST for non-existent flow
    struct packet_features rst;
    create_test_features(&rst, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    rst.tcp_flags = RTE_TCP_RST_FLAG;
    rst.tcp_seq = 1000;

    enum rst_fin_validation_result result = flow_table_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_NO_FLOW, result, "RST for non-existent flow should return NO_FLOW");

    flow_table_cleanup();
}

// flow_table_validate_rst_fin_flow(): Stage 11 validates against the flow its
// own lookup returned. The answers and the counts are those of
// flow_table_validate_rst_fin(), and the flow table sees no lookup.
void test_flow_table_rst_validation_given_flow(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct packet_features syn;
    create_test_features(&syn, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    syn.tcp_flags = RTE_TCP_SYN_FLAG;
    syn.tcp_seq = 1000;
    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&syn, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");
    flow_table_update(flow, &syn);
    TEST_ASSERT(flow->flags & FLOW_FLAG_SEQ_TRACKING_ENABLED, "SYN should enable sequence tracking");

    struct packet_features rst;
    create_test_features(&rst, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    rst.tcp_flags = RTE_TCP_RST_FLAG;
    TEST_ASSERT(flow_table_lookup(&rst) == flow, "The RST should map to the flow");

    struct flow_table_stats before, after;
    uint64_t valid_before, invalid_before, valid_after, invalid_after;
    flow_table_get_detailed_stats(&before);
    flow_table_get_rst_fin_stats(&valid_before, &invalid_before);

    rst.tcp_seq = 1001;
    TEST_ASSERT_EQ(RST_FIN_VALID, flow_table_validate_rst_fin_flow(flow, &rst),
                   "An RST at the expected sequence should pass");
    rst.tcp_seq = 1001 + 0x40000000;
    TEST_ASSERT_EQ(RST_FIN_SEQ_OUT_OF_WINDOW, flow_table_validate_rst_fin_flow(flow, &rst),
                   "An RST far outside the window should fail");
    TEST_ASSERT_EQ(RST_FIN_NO_FLOW, flow_table_validate_rst_fin_flow(NULL, &rst),
                   "An RST without a flow should return NO_FLOW");
    struct packet_features ack = rst;
    ack.tcp_flags = RTE_TCP_ACK_FLAG;
    TEST_ASSERT_EQ(RST_FIN_VALID, flow_table_validate_rst_fin_flow(flow, &ack),
                   "A segment without RST or FIN should pass unchecked");

    flow_table_get_detailed_stats(&after);
    flow_table_get_rst_fin_stats(&valid_after, &invalid_after);
    TEST_ASSERT_EQ(before.lookups, after.lookups, "Validating a given flow should look nothing up");
    TEST_ASSERT_EQ(valid_before + 1, valid_after, "One RST should count as valid");
    TEST_ASSERT_EQ(invalid_before + 2, invalid_after,
                   "The RST outside the window and the one without a flow should count as invalid");

    // The lookup variant agrees
    rst.tcp_seq = 1001;
    TEST_ASSERT_EQ(RST_FIN_VALID, flow_table_validate_rst_fin(&rst),
                   "flow_table_validate_rst_fin() should pass the same RST");
    rst.tcp_seq = 1001 + 0x40000000;
    TEST_ASSERT_EQ(RST_FIN_SEQ_OUT_OF_WINDOW, flow_table_validate_rst_fin(&rst),
                   "flow_table_validate_rst_fin() should fail the same RST");

    flow_table_cleanup();
}

// ==================== Statistics Tests ====================

void test_flow_table_stats_basic(void) {
    init_default_config();
    flow_table_init(&default_config);

    // Create some flows
    for (int i = 0; i < 5; i++) {
        struct packet_features features;
        create_test_features(&features, 0x0A000001 + i, 0xC0A80101, 12345 + i, 80, IPPROTO_TCP);

        bool created;
        flow_table_lookup_or_create(&features, &created);
    }

    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);

    TEST_ASSERT_EQ(5, stats.creates, "Should have 5 creates");
    TEST_ASSERT(stats.lookups >= 5, "Should have at least 5 lookups");

    flow_table_cleanup();
}

void test_flow_table_stats_lookup_hits(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct packet_features features;
    create_test_features(&features, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);

    bool created;
    flow_table_lookup_or_create(&features, &created); // Create

    // Multiple lookups
    for (int i = 0; i < 10; i++) {
        flow_table_lookup_or_create(&features, &created); // Lookup hit
    }

    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);

    TEST_ASSERT_EQ(1, stats.creates, "Should have 1 create");
    TEST_ASSERT_EQ(10, stats.lookup_hits, "Should have 10 lookup hits");

    flow_table_cleanup();
}

// ==================== Table Full Tests ====================

void test_flow_table_full(void) {
    init_default_config();
    default_config.max_flows = 10;
    flow_table_init(&default_config);

    int created_count = 0;
    int failed_count = 0;
    uint32_t max_active = 0;

    // Try to create more flows than capacity. When the table is full,
    // flow_table_lookup_or_create() runs flow_table_emergency_evict() (at most
    // once per 100 ms) and reuses the freed slots, so creates beyond capacity
    // are paid for by evictions; the table itself never exceeds max_flows.
    uint64_t start_tsc = rte_rdtsc();
    for (int i = 0; i < 30; i++) {
        struct packet_features features;
        create_test_features(&features, 0x0A000001 + i, 0xC0A80101, 12345 + i, 80, IPPROTO_TCP);

        bool created;
        struct flow_entry *flow = flow_table_lookup_or_create(&features, &created);

        if (flow && created) {
            created_count++;
        } else if (!flow) {
            failed_count++;
        }

        uint32_t active;
        flow_table_get_stats(&active, NULL, NULL);
        if (active > max_active) {
            max_active = active;
        }
    }
    uint64_t elapsed_tsc = rte_rdtsc() - start_tsc;

    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);
    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);

    // Should have created up to max_flows
    TEST_ASSERT(max_active <= 10, "Should not create more than max_flows");
    TEST_ASSERT_EQ((uint64_t)created_count, stats.creates, "Creates should be counted");
    TEST_ASSERT_EQ((uint64_t)failed_count, stats.create_failures, "Failed creates should be counted");
    TEST_ASSERT_EQ((uint64_t)created_count, stats.deletes + active,
                   "Every create beyond capacity should be paid for by an eviction");
    TEST_ASSERT(stats.deletes > 0, "A full table should evict to admit new flows");
    // With the eviction rate limit, one pass frees at most the 10 slots, so 30
    // attempts inside 100 ms must leave some creates failing
    if (elapsed_tsc < rte_get_tsc_hz() / 10) {
        TEST_ASSERT(failed_count > 0, "Some creates should fail when table is full");
    }

    flow_table_cleanup();
}

// ==================== Emergency Eviction Tests ====================

// lookup_or_create runs the emergency eviction at most once per 100 ms, and
// that limit is process-wide (a static in flow_table.c), so a create that
// must evict waits out the limit left by earlier subtests
#define EVICT_RATE_LIMIT_WAIT_MS 150

void test_flow_table_evict_spares_established(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // Full table: 10 established bidirectional flows, 6 half-open flows
    struct flow_entry *established[10];
    for (int i = 0; i < 10; i++) {
        established[i] = create_established_flow(0x0A000001 + i, 0xC0A80101);
        TEST_ASSERT_NOT_NULL(established[i], "Should create established flow");
        TEST_ASSERT(flow_is_established(established[i]) && flow_is_bidirectional(established[i]),
                    "Handshake should leave the flow established and bidirectional");
    }
    for (int i = 0; i < 6; i++) {
        TEST_ASSERT_NOT_NULL(create_half_open_flow(0x0B000001 + i, 0xC0A80101),
                             "Should create half-open flow");
    }
    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT_EQ(16, active, "Table should be full");

    // A 256 batch must not be filled from the established flows
    uint32_t evicted = flow_table_emergency_evict(256);
    TEST_ASSERT_EQ(6, evicted, "Only the 6 half-open flows should be evicted");

    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT_EQ(10, active, "The 10 established flows should remain");
    for (int i = 0; i < 10; i++) {
        struct flow_entry *found = find_tcp_flow(0x0A000001 + i, 0xC0A80101);
        TEST_ASSERT(found == established[i], "Established flow should survive eviction");
        TEST_ASSERT_EQ(FLOW_STATE_ESTABLISHED, found->state, "Survivor should still be ESTABLISHED");
    }
    for (int i = 0; i < 6; i++) {
        struct flow_entry *gone = find_tcp_flow(0x0B000001 + i, 0xC0A80101);
        TEST_ASSERT_NULL(gone, "Half-open flow should be evicted");
    }

    flow_table_cleanup();
}

void test_flow_table_full_create_spares_established(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    struct flow_entry *established[10];
    for (int i = 0; i < 10; i++) {
        established[i] = create_established_flow(0x0A000001 + i, 0xC0A80101);
        TEST_ASSERT_NOT_NULL(established[i], "Should create established flow");
    }
    for (int i = 0; i < 6; i++) {
        TEST_ASSERT_NOT_NULL(create_half_open_flow(0x0B000001 + i, 0xC0A80101),
                             "Should create half-open flow");
    }
    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT_EQ(16, active, "Table should be full");

    // The next create finds no free index and evicts through the reuse path
    rte_delay_ms(EVICT_RATE_LIMIT_WAIT_MS);
    struct packet_features syn;
    create_test_features(&syn, 0x0C000001, 0xC0A80101, 40000, 80, IPPROTO_TCP);
    syn.tcp_flags = RTE_TCP_SYN_FLAG;
    bool created = false;
    struct flow_entry *flow = flow_table_lookup_or_create(&syn, &created);
    TEST_ASSERT_NOT_NULL(flow, "New flow should get a slot freed by eviction");
    TEST_ASSERT(created, "created flag should be true");

    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);
    TEST_ASSERT_EQ(6, stats.deletes, "Eviction should free only the half-open slots");
    TEST_ASSERT_EQ(0, stats.create_failures, "The create should not fail");
    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT_EQ(11, active, "10 established flows plus the new one");
    for (int i = 0; i < 10; i++) {
        TEST_ASSERT(find_tcp_flow(0x0A000001 + i, 0xC0A80101) == established[i],
                    "Established flow should survive eviction");
    }

    flow_table_cleanup();
}

void test_flow_table_evict_only_established(void) {
    init_default_config();
    default_config.max_flows = 8;
    flow_table_init(&default_config);

    struct flow_entry *established[8];
    for (int i = 0; i < 8; i++) {
        established[i] = create_established_flow(0x0A000001 + i, 0xC0A80101);
        TEST_ASSERT_NOT_NULL(established[i], "Should create established flow");
    }
    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT_EQ(8, active, "Table should be full");

    // Nothing is evictable, so eviction frees nothing
    uint32_t evicted = flow_table_emergency_evict(256);
    TEST_ASSERT_EQ(0, evicted, "Established bidirectional flows should not be evicted");

    // A new flow is refused rather than displacing an established one
    rte_delay_ms(EVICT_RATE_LIMIT_WAIT_MS);
    struct packet_features syn;
    create_test_features(&syn, 0x0C000001, 0xC0A80101, 40000, 80, IPPROTO_TCP);
    syn.tcp_flags = RTE_TCP_SYN_FLAG;
    bool created = true;
    struct flow_entry *flow = flow_table_lookup_or_create(&syn, &created);
    TEST_ASSERT_NULL(flow, "A table full of established flows should refuse a new flow");
    TEST_ASSERT(!created, "created flag should be false");

    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);
    TEST_ASSERT_EQ(1, stats.create_failures, "The refused create should be counted");
    TEST_ASSERT_EQ(0, stats.deletes, "No flow should be deleted");
    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT_EQ(8, active, "All established flows should remain");
    for (int i = 0; i < 8; i++) {
        TEST_ASSERT(find_tcp_flow(0x0A000001 + i, 0xC0A80101) == established[i],
                    "Established flow should survive");
    }

    flow_table_cleanup();
}

void test_flow_table_evict_blind_ack_not_protected(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // A real handshake, and a spoofed SYN: the server's SYN-ACK goes to the
    // address's real owner (the table sees it outbound) and the spoofer sends
    // a blind ACK with a guessed ack number. Both flows look ESTABLISHED with
    // traffic both ways; only the real one acknowledged the server's ISN + 1.
    struct flow_entry *real = create_established_flow(0x0A000001, 0xC0A80101);
    struct flow_entry *blind = create_handshake_flow(0x0A000002, 0xC0A80101, 0x12345678);
    TEST_ASSERT_NOT_NULL(real, "Should create the real handshake");
    TEST_ASSERT_NOT_NULL(blind, "Should create the blind-ACK handshake");
    TEST_ASSERT(flow_is_established(real) && flow_is_bidirectional(real),
                "The real handshake should be established and bidirectional");
    TEST_ASSERT(flow_is_established(blind) && flow_is_bidirectional(blind),
                "The blind-ACK flow should look established and bidirectional");

    uint32_t evicted = flow_table_emergency_evict(256);
    TEST_ASSERT_EQ(1, evicted, "The blind-ACK flow should be evictable");
    TEST_ASSERT_NULL(find_tcp_flow(0x0A000002, 0xC0A80101), "The blind-ACK flow should be evicted");
    TEST_ASSERT(find_tcp_flow(0x0A000001, 0xC0A80101) == real,
                "The real handshake should be protected");

    flow_table_cleanup();
}

void test_flow_table_evict_scores_bidirectional_udp(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    struct packet_features pkt;
    bool created;

    // UDP with a reply (a DNS exchange)
    create_test_features(&pkt, 0x0A000001, 0xC0A80101, 5000, 53, IPPROTO_UDP);
    struct flow_entry *udp_reply = flow_table_lookup_or_create(&pkt, &created);
    TEST_ASSERT_NOT_NULL(udp_reply, "Should create the UDP flow");
    flow_table_update(udp_reply, &pkt);
    create_test_features(&pkt, 0xC0A80101, 0x0A000001, 53, 5000, IPPROTO_UDP);
    TEST_ASSERT(flow_table_lookup(&pkt) == udp_reply, "The reply should map to the UDP flow");
    flow_table_update(udp_reply, &pkt);
    TEST_ASSERT(flow_is_bidirectional(udp_reply), "The UDP flow should be bidirectional");

    // UDP with no reply
    create_test_features(&pkt, 0x0A000002, 0xC0A80101, 5000, 53, IPPROTO_UDP);
    struct flow_entry *udp_oneway = flow_table_lookup_or_create(&pkt, &created);
    TEST_ASSERT_NOT_NULL(udp_oneway, "Should create the one-way UDP flow");
    flow_table_update(udp_oneway, &pkt);

    // TCP handshake that stopped after the server's SYN-ACK
    create_test_features(&pkt, 0x0A000003, 0xC0A80101, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG;
    struct flow_entry *tcp_half = flow_table_lookup_or_create(&pkt, &created);
    TEST_ASSERT_NOT_NULL(tcp_half, "Should create the TCP flow");
    flow_table_update(tcp_half, &pkt);
    create_test_features(&pkt, 0xC0A80101, 0x0A000003, 80, 40000, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    TEST_ASSERT(flow_table_lookup(&pkt) == tcp_half, "The SYN-ACK should map to the TCP flow");
    flow_table_update(tcp_half, &pkt);
    TEST_ASSERT_EQ(FLOW_STATE_SYN_ACK_RECEIVED, tcp_half->state, "The TCP flow should be half-open");

    // UDP never leaves FLOW_STATE_NEW, which scored a UDP exchange as an
    // incomplete handshake and evicted it before the half-open TCP flow
    uint32_t evicted = flow_table_emergency_evict(1);
    TEST_ASSERT_EQ(1, evicted, "One flow should be evicted");
    TEST_ASSERT_NULL(find_flow(0x0A000002, 0xC0A80101, IPPROTO_UDP),
                     "One-way UDP should be evicted first");
    evicted = flow_table_emergency_evict(1);
    TEST_ASSERT_EQ(1, evicted, "One flow should be evicted");
    TEST_ASSERT(find_flow(0x0A000001, 0xC0A80101, IPPROTO_UDP) == udp_reply,
                "UDP with a reply should outlast a half-open TCP handshake");
    TEST_ASSERT_NULL(find_tcp_flow(0x0A000003, 0xC0A80101),
                     "The half-open TCP flow should be evicted next");

    // Traffic both ways proves no handshake (a spoofed query draws a reply
    // too), so the UDP exchange is not protected: it is evictable last
    evicted = flow_table_emergency_evict(1);
    TEST_ASSERT_EQ(1, evicted, "UDP with a reply should stay evictable");
    TEST_ASSERT_NULL(find_flow(0x0A000001, 0xC0A80101, IPPROTO_UDP),
                     "UDP with a reply should be evicted when nothing scores lower");

    flow_table_cleanup();
}

void test_flow_table_evict_keeps_lowest_scores(void) {
    // More evictable flows than the 1024-entry candidate buffer: 28 one-way
    // established flows among half-open flows, which score far lower. A 1024
    // eviction must take half-open flows only. Once the buffer was full, a
    // new candidate was compared with the buffer's last slot, not its worst:
    // when that slot held a half-open flow, every later half-open flow was
    // skipped and the established flows already in the buffer were evicted.
    // Which flow lands in that slot depends on the hash layout, so three
    // tables with different keys are checked. The tables are sized at twice
    // the flows: rte_hash may refuse a key before every slot is used.
    for (uint32_t table = 0; table < 3; table++) {
        init_default_config();
        default_config.max_flows = 8192;
        flow_table_init(&default_config);

        uint32_t client_base = 0x0A000000 + (table << 16);
        uint32_t established = 0;
        for (uint32_t i = 0; i < 4096; i++) {
            struct flow_entry *flow;
            if (i % 146 == 73) {
                flow = create_one_way_established_flow(client_base + i, 0xC0A80101);
                established++;
            } else {
                flow = create_half_open_flow(client_base + i, 0xC0A80101);
            }
            TEST_ASSERT_NOT_NULL(flow, "Should create flow");
        }
        uint32_t active;
        flow_table_get_stats(&active, NULL, NULL);
        TEST_ASSERT_EQ(4096, active, "Should hold 4096 flows");
        TEST_ASSERT_EQ(28, established, "28 one-way established flows");

        uint32_t evicted = flow_table_emergency_evict(1024);
        TEST_ASSERT_EQ(1024, evicted, "A full candidate buffer should be evicted");

        uint32_t established_left = 0;
        for (uint32_t i = 73; i < 4096; i += 146) {
            if (find_tcp_flow(client_base + i, 0xC0A80101) != NULL) {
                established_left++;
            }
        }
        printf("  table %u: %u of %u one-way established flows left\n",
               table, established_left, established);
        TEST_ASSERT_EQ(28, established_left,
                       "Only the lowest scores (half-open flows) should be evicted");

        flow_table_cleanup();
    }
}

// ==================== Eviction Seam ====================

// flow_table_emergency_evict() calls flow_table_evict_seam() after choosing
// its candidates and before deleting them. The library's definition is a
// weak no-op; this one counts the calls and runs, once, the action a subtest
// set, standing in for another lcore acting in that window. (Atomics: the
// stress subtests evict on several lcores at once.)
static void (*evict_seam_action)(void) = NULL;
static int evict_seam_calls = 0;

void flow_table_evict_seam(void) {
    void (*action)(void) = __atomic_exchange_n(&evict_seam_action, NULL, __ATOMIC_ACQ_REL);
    __atomic_fetch_add(&evict_seam_calls, 1, __ATOMIC_RELAXED);
    if (action) {
        action();
    }
}

#define SEAM_SERVER_IP 0xC0A80101
static uint32_t seam_client_ip;
static struct flow_entry *seam_new_flow;
static uint32_t seam_aged;

// The handshake of the half-open flow from seam_client_ip completes
static void seam_complete_handshake(void) {
    struct packet_features pkt;

    create_test_features(&pkt, SEAM_SERVER_IP, seam_client_ip, 80, 40000, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = TEST_SERVER_ISN;
    pkt.tcp_ack = TEST_CLIENT_ISN + 1;
    struct flow_entry *flow = flow_table_lookup(&pkt);
    if (!flow) {
        return;
    }
    flow_table_update(flow, &pkt);

    create_test_features(&pkt, seam_client_ip, SEAM_SERVER_IP, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN + 1;
    pkt.tcp_ack = TEST_SERVER_ISN + 1;
    if (flow_table_lookup(&pkt) == flow) {
        flow_table_update(flow, &pkt);
    }
}

// Aging (the maintenance lcore) expires the flow from seam_client_ip, and a
// new SYN (another lcore) creates the key again on a new entry
static void seam_age_and_recreate(void) {
    seam_aged = flow_table_age_flows();
    seam_new_flow = create_half_open_flow(seam_client_ip, SEAM_SERVER_IP);
}

void test_flow_table_evict_rechecks_handshake(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // Four half-open flows: a 256 batch chooses all of them
    for (uint32_t i = 0; i < 4; i++) {
        TEST_ASSERT_NOT_NULL(create_half_open_flow(0x0B000001 + i, SEAM_SERVER_IP),
                             "Should create half-open flow");
    }

    // After the choice and before the deletes, one handshake completes
    seam_client_ip = 0x0B000004;
    evict_seam_calls = 0;
    evict_seam_action = seam_complete_handshake;
    uint32_t evicted = flow_table_emergency_evict(256);
    evict_seam_action = NULL;

    TEST_ASSERT_EQ(1, evict_seam_calls, "The seam should run between choosing and deleting");
    struct flow_entry *flow = find_tcp_flow(0x0B000004, SEAM_SERVER_IP);
    TEST_ASSERT_NOT_NULL(flow, "A flow established after it was chosen should not be evicted");
    TEST_ASSERT(flow_is_established(flow) && flow_is_bidirectional(flow),
                "Its handshake should have completed");
    TEST_ASSERT_EQ(3, evicted, "The other three half-open flows should be evicted");
    for (uint32_t i = 0; i < 3; i++) {
        TEST_ASSERT_NULL(find_tcp_flow(0x0B000001 + i, SEAM_SERVER_IP),
                         "Half-open flow should be evicted");
    }

    flow_table_cleanup();
}

void test_flow_table_evict_rechecks_entry(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // Four half-open flows. The fourth was last seen 20 s ago, past the 10 s
    // SYN timeout, so aging expires it; the other three are fresh.
    for (uint32_t i = 0; i < 3; i++) {
        TEST_ASSERT_NOT_NULL(create_half_open_flow(0x0B000001 + i, SEAM_SERVER_IP),
                             "Should create half-open flow");
    }
    struct flow_entry *old_flow = create_half_open_flow(0x0B000004, SEAM_SERVER_IP);
    TEST_ASSERT_NOT_NULL(old_flow, "Should create half-open flow");
    old_flow->last_seen_tsc = rte_rdtsc() - 20 * rte_get_tsc_hz();

    // After the choice and before the deletes, aging deletes the fourth key
    // and a new SYN creates it again on another entry
    seam_client_ip = 0x0B000004;
    seam_new_flow = NULL;
    seam_aged = 0;
    evict_seam_calls = 0;
    evict_seam_action = seam_age_and_recreate;
    uint32_t evicted = flow_table_emergency_evict(256);
    evict_seam_action = NULL;

    TEST_ASSERT_EQ(1, evict_seam_calls, "The seam should run between choosing and deleting");
    TEST_ASSERT_EQ(1, seam_aged, "Aging should expire the stale flow");
    TEST_ASSERT_NOT_NULL(seam_new_flow, "The key should be created again");
    TEST_ASSERT(seam_new_flow != old_flow, "The new flow should be on another entry");
    TEST_ASSERT(find_tcp_flow(0x0B000004, SEAM_SERVER_IP) == seam_new_flow,
                "A flow created after the choice should not be evicted");
    TEST_ASSERT_EQ(3, evicted, "Only the flows still on their scanned entries should be evicted");

    // Index accounting: the new flow holds one entry and each of the other
    // 15 is free exactly once (a second free of the old index would hand it
    // out twice, and the new entry would never come back)
    struct flow_entry *fill[15];
    for (uint32_t i = 0; i < 15; i++) {
        fill[i] = create_half_open_flow(0x0C000001 + i, SEAM_SERVER_IP);
        TEST_ASSERT_NOT_NULL(fill[i], "Every free entry should be allocatable");
        TEST_ASSERT(fill[i] != seam_new_flow, "A live entry should not be handed out again");
        for (uint32_t j = 0; j < i; j++) {
            TEST_ASSERT(fill[i] != fill[j], "No entry should be handed out twice");
        }
    }
    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT_EQ(16, active, "Table should be full");

    flow_table_cleanup();
}

// ==================== Allocation Across Lcores ====================

struct registered_create {
    int rc;                     // rte_thread_register() result
    unsigned int lcore_id;
    struct flow_entry *flow;
};

// Runs on a pthread registered with EAL, so it has an lcore id and a free
// index cache of its own, like a second worker lcore
static void *registered_lcore_create(void *arg) {
    struct registered_create *res = arg;
    struct packet_features features;
    bool created;

    res->rc = rte_thread_register();
    res->lcore_id = rte_lcore_id();
    if (res->rc == 0) {
        create_test_features(&features, 0x0D000001, 0xC0A80101, 5000, 53, IPPROTO_UDP);
        res->flow = flow_table_lookup_or_create(&features, &created);
        rte_thread_unregister();
    }
    return NULL;
}

void test_flow_table_small_table_fills_across_lcores(void) {
    init_default_config();
    // 16 slots are 2 hash buckets, which take a key in every slot (larger
    // tables may refuse a key before they are full)
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // Another lcore creates one flow. Its first allocation moved up to 32
    // indices (here all 16) off the ring and kept the rest in its own cache,
    // out of lcore 0's reach.
    struct registered_create res;
    memset(&res, 0, sizeof(res));
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, registered_lcore_create, &res);
    TEST_ASSERT_EQ(0, rc, "pthread_create should succeed");
    rc = pthread_join(thread, NULL);
    TEST_ASSERT_EQ(0, rc, "pthread_join should succeed");
    TEST_ASSERT_EQ(0, res.rc, "rte_thread_register should succeed");
    TEST_ASSERT(res.lcore_id != 0 && res.lcore_id < RTE_MAX_LCORE,
                "The registered thread should have its own lcore id");
    TEST_ASSERT_NOT_NULL(res.flow, "The other lcore should create its flow");

    // lcore 0 fills the other 15 slots. An early "full" would run the
    // emergency eviction; wait out its rate limit so that it would.
    rte_delay_ms(EVICT_RATE_LIMIT_WAIT_MS);
    uint32_t failed = 0;
    for (uint32_t i = 0; i < 15; i++) {
        struct packet_features features;
        bool created = false;
        create_test_features(&features, 0x0E000001 + i, 0xC0A80101, 5000, 53, IPPROTO_UDP);
        if (flow_table_lookup_or_create(&features, &created) == NULL || !created) {
            failed++;
        }
    }

    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);
    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT_EQ(0, stats.deletes, "Filling a table that is not yet full should evict nothing");
    TEST_ASSERT_EQ(0, stats.create_failures, "Every create should find a free slot");
    TEST_ASSERT_EQ(0, failed, "lcore 0 should create all 15 flows");
    TEST_ASSERT_EQ(16, active, "All 16 slots should be in use");

    flow_table_cleanup();
}

// ==================== Clear Tests ====================

void test_flow_table_clear(void) {
    init_default_config();
    flow_table_init(&default_config);

    // Create flows
    for (int i = 0; i < 10; i++) {
        struct packet_features features;
        create_test_features(&features, 0x0A000001 + i, 0xC0A80101, 12345 + i, 80, IPPROTO_TCP);

        bool created;
        flow_table_lookup_or_create(&features, &created);
    }

    uint32_t active1, total1, aged1;
    flow_table_get_stats(&active1, &total1, &aged1);
    TEST_ASSERT_EQ(10, active1, "Should have 10 flows");

    // Clear all
    flow_table_clear();

    uint32_t active2, total2, aged2;
    flow_table_get_stats(&active2, &total2, &aged2);
    TEST_ASSERT_EQ(0, active2, "Should have 0 flows after clear");

    flow_table_cleanup();
}

// ==================== Utility Function Tests ====================

void test_flow_state_str(void) {
    TEST_ASSERT(strcmp(flow_state_str(FLOW_STATE_NEW), "NEW") == 0, "NEW state string");
    TEST_ASSERT(strcmp(flow_state_str(FLOW_STATE_ESTABLISHED), "ESTABLISHED") == 0, "ESTABLISHED state string");
    TEST_ASSERT(strcmp(flow_state_str(FLOW_STATE_RST), "RST") == 0, "RST state string");
    TEST_ASSERT(strcmp(flow_state_str(100), "UNKNOWN") == 0, "Unknown state string");
}

void test_flow_state_str_every_state(void) {
    // Every declared state needs its own name. The table had 12 names for
    // 13 states, so FLOW_STATE_INITIALIZING read past its end.
    for (int s = 0; s < FLOW_STATE_MAX; s++) {
        const char *name = flow_state_str((enum flow_state)s);
        TEST_ASSERT_NOT_NULL(name, "Every state should have a name");
        TEST_ASSERT(strcmp(name, "UNKNOWN") != 0, "A declared state should not read as UNKNOWN");
        for (int t = 0; t < s; t++) {
            TEST_ASSERT(strcmp(name, flow_state_str((enum flow_state)t)) != 0,
                        "State names should be distinct");
        }
    }
    TEST_ASSERT(strcmp(flow_state_str(FLOW_STATE_INITIALIZING), "INITIALIZING") == 0,
                "INITIALIZING state string");
    TEST_ASSERT(strcmp(flow_state_str(FLOW_STATE_MAX), "UNKNOWN") == 0,
                "FLOW_STATE_MAX is not a state");
}

// ==================== Non-EAL Thread Tests ====================

struct non_eal_result {
    unsigned int lcore_id;
    struct flow_entry *created_flow;
    bool created;
    struct flow_entry *found_flow;
};

// Runs on a plain pthread, which EAL never registered: rte_lcore_id() is
// LCORE_ID_ANY there, as on any control or management thread
static void *non_eal_flow_ops(void *arg) {
    struct non_eal_result *res = arg;
    struct packet_features features;

    res->lcore_id = rte_lcore_id();
    create_test_features(&features, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    features.tcp_flags = RTE_TCP_SYN_FLAG;

    res->created_flow = flow_table_lookup_or_create(&features, &res->created);
    if (res->created_flow) {
        flow_table_update(res->created_flow, &features);
    }
    res->found_flow = flow_table_lookup(&features);
    return NULL;
}

void test_flow_table_non_eal_thread(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct non_eal_result res;
    memset(&res, 0, sizeof(res));
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, non_eal_flow_ops, &res);
    TEST_ASSERT_EQ(0, rc, "pthread_create should succeed");
    rc = pthread_join(thread, NULL);
    TEST_ASSERT_EQ(0, rc, "pthread_join should succeed");

    TEST_ASSERT(res.lcore_id == LCORE_ID_ANY, "A plain pthread should have no lcore id");
    TEST_ASSERT_NOT_NULL(res.created_flow, "Non-EAL thread should create a flow");
    TEST_ASSERT(res.created, "created flag should be true");
    TEST_ASSERT(res.found_flow == res.created_flow, "Non-EAL thread should find its flow");
    TEST_ASSERT_EQ(FLOW_STATE_SYN_RECEIVED, res.created_flow->state,
                   "Update from the non-EAL thread should apply");

    // The thread's counters must land in a slot the aggregate reads (the
    // slot non-EAL threads share), not outside the per-lcore array
    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);
    TEST_ASSERT_EQ(2, stats.lookups, "Both lookups should be counted");
    TEST_ASSERT_EQ(1, stats.lookup_hits, "The lookup hit should be counted");
    TEST_ASSERT_EQ(1, stats.creates, "The create should be counted");
    TEST_ASSERT_EQ(1, stats.updates, "The update should be counted");

    flow_table_cleanup();
}

static struct flow_entry *create_udp_flow(uint32_t client_ip) {
    struct packet_features features;
    bool created = false;
    create_test_features(&features, client_ip, 0xC0A80101, 5000, 53, IPPROTO_UDP);
    struct flow_entry *flow = flow_table_lookup_or_create(&features, &created);
    return created ? flow : NULL;
}

struct non_eal_create {
    uint32_t client_ip;
    struct flow_entry *flow;
};

static void *non_eal_create_one(void *arg) {
    struct non_eal_create *job = arg;
    job->flow = create_udp_flow(job->client_ip);
    return NULL;
}

void test_flow_table_non_eal_leaves_lcore_cache(void) {
    init_default_config();
    // Large enough that lcore 0 keeps a per-lcore free cache: its first
    // create fills the cache from the ring, its next creates pop from it
    default_config.max_flows = 1 << 17;

    // Reference: the entries lcore 0 gets for two creates in a new table
    flow_table_init(&default_config);
    struct flow_entry *ref_first = create_udp_flow(0x0A000001);
    struct flow_entry *ref_second = create_udp_flow(0x0A000002);
    TEST_ASSERT_NOT_NULL(ref_first, "Should create flow");
    TEST_ASSERT_NOT_NULL(ref_second, "Should create flow");
    uint32_t ref_first_index = ref_first->entry_index;
    uint32_t ref_second_index = ref_second->entry_index;
    flow_table_cleanup();

    // The same creates with a non-EAL thread's create between them. That
    // thread owns no cache. When it used lcore 0's (a plain count, no lock),
    // the two could hand out the same index concurrently.
    flow_table_init(&default_config);
    struct flow_entry *first = create_udp_flow(0x0A000001);
    TEST_ASSERT_NOT_NULL(first, "Should create flow");
    struct non_eal_create job = { 0x0B000001, NULL };
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, non_eal_create_one, &job);
    TEST_ASSERT_EQ(0, rc, "pthread_create should succeed");
    rc = pthread_join(thread, NULL);
    TEST_ASSERT_EQ(0, rc, "pthread_join should succeed");
    TEST_ASSERT_NOT_NULL(job.flow, "The non-EAL thread should create its flow");
    struct flow_entry *second = create_udp_flow(0x0A000002);
    TEST_ASSERT_NOT_NULL(second, "Should create flow");

    TEST_ASSERT_EQ(ref_first_index, first->entry_index, "lcore 0's first create should match the reference");
    TEST_ASSERT_EQ(ref_second_index, second->entry_index,
                   "A non-EAL create should not take an index from lcore 0's cache");
    TEST_ASSERT(job.flow != first && job.flow != second, "The non-EAL flow should have its own entry");

    flow_table_cleanup();
}

// ==================== IPv6 Flow Table Tests ====================

static struct flow_table_v6_config default_config_v6;

static void init_default_config_v6(void) {
    memset(&default_config_v6, 0, sizeof(default_config_v6));
    default_config_v6.max_flows = 4096;
    default_config_v6.idle_timeout_sec = 60;
    default_config_v6.syn_timeout_sec = 10;
    default_config_v6.enable_syn_protection = true;
    default_config_v6.aging_scan_limit = 4096;
}

// 2001:db8::/96 with host in the last 32 bits
static void make_test_ip6(uint8_t ip6[16], uint32_t host) {
    memset(ip6, 0, 16);
    ip6[0] = 0x20;
    ip6[1] = 0x01;
    ip6[2] = 0x0d;
    ip6[3] = 0xb8;
    ip6[12] = (host >> 24) & 0xff;
    ip6[13] = (host >> 16) & 0xff;
    ip6[14] = (host >> 8) & 0xff;
    ip6[15] = host & 0xff;
}

static void create_test_features_v6(struct packet_features_v6 *features,
                                    uint32_t src_host, uint32_t dst_host,
                                    uint16_t src_port, uint16_t dst_port,
                                    uint8_t protocol) {
    memset(features, 0, sizeof(*features));
    features->ip_version = IP_VERSION_6;
    features->protocol = protocol;
    make_test_ip6(features->src_ip.v6, src_host);
    make_test_ip6(features->dst_ip.v6, dst_host);
    features->src_port = src_port;
    features->dst_port = dst_port;
    features->packet_size = 100;
    features->timestamp_tsc = rte_rdtsc();
}

// Creates count UDP flows last seen at last_seen_tsc
static int create_idle_udp_flows_v6(uint32_t client_base, uint32_t count, uint64_t last_seen_tsc) {
    for (uint32_t i = 0; i < count; i++) {
        struct packet_features_v6 features;
        bool created;
        create_test_features_v6(&features, client_base + i, 0x100, 5000, 53, IPPROTO_UDP);
        if (!flow_table_v6_lookup_or_create_tsc(&features, &created, last_seen_tsc) || !created) {
            return -1;
        }
    }
    return 0;
}

void test_flow_table_v6_aging_pressure_small_table(void) {
    init_default_config_v6();
    // As in test_flow_table_aging_pressure_small_table: UDP flows age by
    // idle_timeout_sec, 4 s normally and 1 s in pressure mode
    default_config_v6.max_flows = 10;
    default_config_v6.idle_timeout_sec = 4;
    default_config_v6.syn_timeout_sec = 4;
    flow_table_v6_init(&default_config_v6);

    // Flows stamped as last seen 1.5 s ago: only pressure timeouts expire them
    uint64_t idle_since = rte_rdtsc() - (rte_get_tsc_hz() * 3) / 2;

    // One flow in 10 slots is 10% occupancy. Before the IPv6 caches were
    // bounded, the first allocation moved the other nine free indices into
    // this lcore's cache, off the free ring (a 10-slot table now caches
    // none: test_flow_table_v6_aging_pressure_cached_indices keeps a cache).
    TEST_ASSERT_EQ(0, create_idle_udp_flows_v6(1, 1, idle_since), "Should create flow");
    uint32_t occupancy = flow_table_v6_get_occupancy_percent();
    TEST_ASSERT_EQ(10, occupancy, "One flow in 10 slots is 10%");
    uint32_t aged = flow_table_v6_age_flows();
    TEST_ASSERT_EQ(0, aged, "A 10% full IPv6 table should not use pressure timeouts");
    struct packet_features_v6 features;
    create_test_features_v6(&features, 1, 0x100, 5000, 53, IPPROTO_UDP);
    TEST_ASSERT_NOT_NULL(flow_table_v6_lookup(&features), "The flow idle 1.5 s should survive aging");

    // A truly full table does enter pressure mode
    TEST_ASSERT_EQ(0, create_idle_udp_flows_v6(2, 9, idle_since), "Should create flows");
    occupancy = flow_table_v6_get_occupancy_percent();
    TEST_ASSERT_EQ(100, occupancy, "Table should be full");
    aged = flow_table_v6_age_flows();
    TEST_ASSERT_EQ(10, aged, "A full IPv6 table should age flows idle 1.5 s");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_aging_reinit_after_batch_limit(void) {
    init_default_config_v6();
    // As in test_flow_table_aging_reinit_after_batch_limit
    default_config_v6.max_flows = 2048;
    default_config_v6.idle_timeout_sec = 1;
    flow_table_v6_init(&default_config_v6);

    uint64_t idle_since = rte_rdtsc() - (rte_get_tsc_hz() * 3) / 2;
    TEST_ASSERT_EQ(0, create_idle_udp_flows_v6(0x1000, 1000, idle_since), "Should create 1000 flows");
    uint32_t aged = flow_table_v6_age_flows();
    TEST_ASSERT_EQ(512, aged, "The pass should stop at the batch limit");
    flow_table_v6_cleanup();

    flow_table_v6_init(&default_config_v6);
    idle_since = rte_rdtsc() - (rte_get_tsc_hz() * 3) / 2;
    TEST_ASSERT_EQ(0, create_idle_udp_flows_v6(0x2000, 600, idle_since), "Should create 600 flows");
    aged = flow_table_v6_age_flows();
    TEST_ASSERT_EQ(512, aged, "A new IPv6 table's first pass should start at its beginning");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_rst_validation_no_peer_ack(void) {
    init_default_config_v6();
    flow_table_v6_init(&default_config_v6);

    // As in test_flow_table_rst_validation_no_peer_ack: client SYN with ISN
    // 2^30 and no reply yet
    struct packet_features_v6 syn;
    create_test_features_v6(&syn, 1, 0x100, 12345, 80, IPPROTO_TCP);
    syn.tcp_flags = RTE_TCP_SYN_FLAG;
    syn.tcp_seq = 0x40000000;

    bool created;
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&syn, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");
    flow_table_v6_update(flow, &syn);
    TEST_ASSERT(flow->flags & FLOW_FLAG_SEQ_TRACKING_ENABLED, "SYN should enable sequence tracking");

    struct packet_features_v6 rst;
    enum rst_fin_validation_result result;
    create_test_features_v6(&rst, 1, 0x100, 12345, 80, IPPROTO_TCP);
    rst.tcp_flags = RTE_TCP_RST_FLAG;
    rst.tcp_seq = 0x00001000;
    result = flow_table_v6_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_SEQ_OUT_OF_WINDOW, result,
                   "IPv6 RST near 0 should fail while the peer has sent no ACK");
    rst.tcp_seq = 0xFFFFF000;
    result = flow_table_v6_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_SEQ_OUT_OF_WINDOW, result,
                   "IPv6 RST just below 0 should fail while the peer has sent no ACK");
    rst.tcp_seq = 0x40000001;
    result = flow_table_v6_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_VALID, result, "IPv6 RST at the expected sequence should pass");

    // Complete the handshake
    struct packet_features_v6 pkt;
    create_test_features_v6(&pkt, 0x100, 1, 80, 12345, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = 5000;
    pkt.tcp_ack = 0x40000001;
    TEST_ASSERT(flow_table_v6_lookup(&pkt) == flow, "SYN-ACK should map to the flow");
    flow_table_v6_update(flow, &pkt);

    create_test_features_v6(&pkt, 1, 0x100, 12345, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = 0x40000001;
    pkt.tcp_ack = 5001;
    TEST_ASSERT(flow_table_v6_lookup(&pkt) == flow, "ACK should map to the flow");
    flow_table_v6_update(flow, &pkt);
    TEST_ASSERT_EQ(FLOW_STATE_ESTABLISHED, flow->state, "Handshake should establish the flow");

    // The server acknowledges 2^21 bytes the table did not see; its last
    // ACK now opens the second window
    create_test_features_v6(&pkt, 0x100, 1, 80, 12345, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = 5001;
    pkt.tcp_ack = 0x40000001 + 0x200000;
    TEST_ASSERT(flow_table_v6_lookup(&pkt) == flow, "Server ACK should map to the flow");
    flow_table_v6_update(flow, &pkt);

    rst.tcp_seq = 0x40000001 + 0x200000;
    result = flow_table_v6_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_VALID, result,
                   "IPv6 RST at the peer's last ACK should pass once an ACK was seen");
    rst.tcp_seq = 0x00001000;
    result = flow_table_v6_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_SEQ_OUT_OF_WINDOW, result, "IPv6 RST near 0 should still fail");

    flow_table_v6_cleanup();
}

// As test_flow_table_rst_validation_given_flow, for
// flow_table_v6_validate_rst_fin_flow()
void test_flow_table_v6_rst_validation_given_flow(void) {
    init_default_config_v6();
    flow_table_v6_init(&default_config_v6);

    struct packet_features_v6 syn;
    create_test_features_v6(&syn, 1, 0x100, 12345, 80, IPPROTO_TCP);
    syn.tcp_flags = RTE_TCP_SYN_FLAG;
    syn.tcp_seq = 1000;
    bool created;
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&syn, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");
    flow_table_v6_update(flow, &syn);

    struct packet_features_v6 rst;
    create_test_features_v6(&rst, 1, 0x100, 12345, 80, IPPROTO_TCP);
    rst.tcp_flags = RTE_TCP_RST_FLAG;
    TEST_ASSERT(flow_table_v6_lookup(&rst) == flow, "The IPv6 RST should map to the flow");

    struct flow_table_v6_stats before, after;
    flow_table_v6_get_stats(&before);
    rst.tcp_seq = 1001;
    TEST_ASSERT_EQ(RST_FIN_VALID, flow_table_v6_validate_rst_fin_flow(flow, &rst),
                   "An IPv6 RST at the expected sequence should pass");
    rst.tcp_seq = 1001 + 0x40000000;
    TEST_ASSERT_EQ(RST_FIN_SEQ_OUT_OF_WINDOW, flow_table_v6_validate_rst_fin_flow(flow, &rst),
                   "An IPv6 RST far outside the window should fail");
    TEST_ASSERT_EQ(RST_FIN_NO_FLOW, flow_table_v6_validate_rst_fin_flow(NULL, &rst),
                   "An IPv6 RST without a flow should return NO_FLOW");
    flow_table_v6_get_stats(&after);
    TEST_ASSERT_EQ(before.lookups, after.lookups,
                   "Validating a given IPv6 flow should look nothing up");

    rst.tcp_seq = 1001;
    TEST_ASSERT_EQ(RST_FIN_VALID, flow_table_v6_validate_rst_fin(&rst),
                   "flow_table_v6_validate_rst_fin() should pass the same RST");
    rst.tcp_seq = 1001 + 0x40000000;
    TEST_ASSERT_EQ(RST_FIN_SEQ_OUT_OF_WINDOW, flow_table_v6_validate_rst_fin(&rst),
                   "flow_table_v6_validate_rst_fin() should fail the same RST");

    flow_table_v6_cleanup();
}

// ==================== Round 3: Ageing and Eviction Rechecks ====================

// flow_table_age_flows() calls flow_table_age_seam() after choosing the
// expired flows of a pass and before deleting them, and
// flow_table_emergency_evict() calls flow_table_evict_claim_seam() for each
// chosen flow after its recheck and before its delete (with the writer lock
// held). As with flow_table_evict_seam(), the library's definitions are weak
// no-ops; these count the calls and run, once, the action a subtest set.
void flow_table_age_seam(void);
void flow_table_evict_claim_seam(void);

static void (*age_seam_action)(void) = NULL;
static int age_seam_calls = 0;
static void (*evict_claim_action)(void) = NULL;
static int evict_claim_calls = 0;

void flow_table_age_seam(void) {
    void (*action)(void) = __atomic_exchange_n(&age_seam_action, NULL, __ATOMIC_ACQ_REL);
    __atomic_fetch_add(&age_seam_calls, 1, __ATOMIC_RELAXED);
    if (action) {
        action();
    }
}

void flow_table_evict_claim_seam(void) {
    void (*action)(void) = __atomic_exchange_n(&evict_claim_action, NULL, __ATOMIC_ACQ_REL);
    __atomic_fetch_add(&evict_claim_calls, 1, __ATOMIC_RELAXED);
    if (action) {
        action();
    }
}

static uint32_t seam_evicted;

// An emergency eviction (a worker lcore) deletes the flow from
// seam_client_ip, and a new SYN (another lcore) creates the key again on a
// new entry
static void seam_evict_and_recreate(void) {
    seam_evicted = flow_table_emergency_evict(256);
    seam_new_flow = create_half_open_flow(seam_client_ip, SEAM_SERVER_IP);
}

void test_flow_table_aging_rechecks_entry(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // One half-open flow, last seen 20 s ago (past the 10 s SYN timeout):
    // aging chooses it, and it is the only eviction candidate
    struct flow_entry *old_flow = create_half_open_flow(0x0B000004, SEAM_SERVER_IP);
    TEST_ASSERT_NOT_NULL(old_flow, "Should create half-open flow");
    old_flow->last_seen_tsc = rte_rdtsc() - 20 * rte_get_tsc_hz();

    // After aging chose the key and before its delete, an eviction deletes
    // the flow and a new SYN creates the key again on another entry
    seam_client_ip = 0x0B000004;
    seam_new_flow = NULL;
    seam_evicted = 0;
    age_seam_calls = 0;
    age_seam_action = seam_evict_and_recreate;
    uint32_t aged = flow_table_age_flows();
    age_seam_action = NULL;

    TEST_ASSERT_EQ(1, age_seam_calls, "The seam should run between choosing and deleting");
    TEST_ASSERT_EQ(1, seam_evicted, "The eviction should delete the stale flow");
    TEST_ASSERT_NOT_NULL(seam_new_flow, "The key should be created again");
    TEST_ASSERT(seam_new_flow != old_flow, "The new flow should be on another entry");
    TEST_ASSERT(find_tcp_flow(0x0B000004, SEAM_SERVER_IP) == seam_new_flow,
                "A flow created after aging chose its key should not be aged");
    TEST_ASSERT_EQ(0, aged, "Aging should delete nothing: its key now maps to a new entry");

    // Index accounting: the new flow holds one entry and each of the other
    // 15 is free exactly once (a second free of the old index would hand it
    // out twice, and the new entry would never come back)
    struct flow_entry *fill[15];
    for (uint32_t i = 0; i < 15; i++) {
        fill[i] = create_half_open_flow(0x0C000001 + i, SEAM_SERVER_IP);
        TEST_ASSERT_NOT_NULL(fill[i], "Every free entry should be allocatable");
        TEST_ASSERT(fill[i] != seam_new_flow, "A live entry should not be handed out again");
        for (uint32_t j = 0; j < i; j++) {
            TEST_ASSERT(fill[i] != fill[j], "No entry should be handed out twice");
        }
    }
    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT_EQ(16, active, "Table should be full");

    flow_table_cleanup();
}

// A packet (another lcore) refreshes the flow from seam_client_ip
static void seam_refresh_flow(void) {
    struct packet_features pkt;
    create_test_features(&pkt, seam_client_ip, SEAM_SERVER_IP, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN;
    pkt.timestamp_tsc = 0;  // stamped now, after the pass read its clock
    struct flow_entry *flow = flow_table_lookup(&pkt);
    if (flow) {
        flow_table_update(flow, &pkt);
    }
}

void test_flow_table_aging_rechecks_expiry(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // One half-open flow last seen 20 s ago: aging chooses it
    struct flow_entry *flow = create_half_open_flow(0x0B000004, SEAM_SERVER_IP);
    TEST_ASSERT_NOT_NULL(flow, "Should create half-open flow");
    flow->last_seen_tsc = rte_rdtsc() - 20 * rte_get_tsc_hz();

    // After the choice and before the delete, a packet refreshes it
    seam_client_ip = 0x0B000004;
    age_seam_calls = 0;
    age_seam_action = seam_refresh_flow;
    uint32_t aged = flow_table_age_flows();
    age_seam_action = NULL;

    TEST_ASSERT_EQ(1, age_seam_calls, "The seam should run between choosing and deleting");
    TEST_ASSERT_EQ(0, aged, "A flow refreshed before its delete is no longer expired");
    TEST_ASSERT(find_tcp_flow(0x0B000004, SEAM_SERVER_IP) == flow, "The refreshed flow should survive");

    flow_table_cleanup();
}

void test_flow_table_evict_claim_spares_late_handshake(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // One half-open flow: the only candidate, evictable at its recheck
    struct flow_entry *flow = create_half_open_flow(0x0B000004, SEAM_SERVER_IP);
    TEST_ASSERT_NOT_NULL(flow, "Should create half-open flow");

    // After the recheck and before the delete, its handshake completes
    seam_client_ip = 0x0B000004;
    evict_claim_calls = 0;
    evict_claim_action = seam_complete_handshake;
    uint32_t evicted = flow_table_emergency_evict(256);
    evict_claim_action = NULL;

    TEST_ASSERT_EQ(1, evict_claim_calls, "The claim seam should run between the recheck and the delete");
    TEST_ASSERT(find_tcp_flow(0x0B000004, SEAM_SERVER_IP) == flow,
                "A flow whose handshake completed before its delete should be kept");
    TEST_ASSERT(flow_is_established(flow) && flow_is_bidirectional(flow) &&
                (flow->flags & FLOW_FLAG_HANDSHAKE_ACKED),
                "Its handshake should have completed");
    TEST_ASSERT_EQ(0, evicted, "Nothing should be evicted");

    flow_table_cleanup();
}

void test_flow_table_aging_spares_flow_seen_after_pass_start(void) {
    init_default_config();
    flow_table_init(&default_config);

    // A packet stamped by another lcore after this aging pass read its
    // clock: its timestamp is later than the pass's now. The test stamps
    // one second ahead so that the pass below is surely earlier.
    struct packet_features pkt;
    bool created;
    create_test_features(&pkt, 0x0A000001, 0xC0A80101, 5000, 53, IPPROTO_UDP);
    struct flow_entry *flow = flow_table_lookup_or_create(&pkt, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");
    pkt.timestamp_tsc = rte_rdtsc() + rte_get_tsc_hz();
    flow_table_update(flow, &pkt);

    uint32_t aged = flow_table_age_flows();
    TEST_ASSERT_EQ(0, aged, "A flow seen after the pass started is not idle");
    TEST_ASSERT(find_flow(0x0A000001, 0xC0A80101, IPPROTO_UDP) == flow,
                "The flow should survive aging");

    flow_table_cleanup();
}

// The rate-limit window of a flow is shared by every lcore that sees its
// packets (the key has no ports, and RSS spreads a host pair's connections
// over lcores), and each lcore stamps packets with its own clock reading.
// A packet stamped a little before another lcore's window start must not
// reset the window.
void test_flow_table_rate_limit_window_clock_skew(void) {
    init_default_config();
    default_config.default_pps_limit = 5;
    flow_table_init(&default_config);

    struct packet_features pkt;
    bool created;
    create_test_features(&pkt, 0x0A000001, 0xC0A80101, 5000, 53, IPPROTO_UDP);
    struct flow_entry *flow = flow_table_lookup_or_create(&pkt, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");

    // Another lcore opens the window and fills it (5 packets at t_late);
    // this lcore's packet was stamped 10 us earlier
    uint64_t t_early = rte_rdtsc() + rte_get_tsc_hz();
    uint64_t t_late = t_early + rte_get_tsc_hz() / 100000;
    for (int i = 0; i < 5; i++) {
        pkt.timestamp_tsc = t_late;
        TEST_ASSERT_EQ(RL_ACCEPT, flow_table_check_rate_limit(flow, &pkt, NULL),
                       "The window's first 5 packets should pass");
    }
    pkt.timestamp_tsc = t_early;
    enum rate_limit_action action = flow_table_check_rate_limit(flow, &pkt, NULL);
    TEST_ASSERT_EQ(RL_DROP_PPS, action, "A 6th packet in the same window should be limited");

    flow_table_cleanup();
}

// ==================== Round 3: Capacity ====================

void test_flow_table_fills_to_max_flows(void) {
    init_default_config();
    // 4096 slots are 512 hash buckets. Without extendable buckets the hash
    // refused a key once both its buckets were full, short of max_flows,
    // and the create failed without an eviction although entries were free.
    default_config.max_flows = 4096;
    flow_table_init(&default_config);

    uint32_t failed = 0;
    for (uint32_t i = 0; i < 4096; i++) {
        if (create_udp_flow(0x0A000000 + i) == NULL) {
            failed++;
        }
    }
    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);
    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);
    printf("  %u of 4096 creates failed, %u flows held\n", failed, active);
    fflush(stdout);
    TEST_ASSERT_EQ(0, failed, "Every create below max_flows should succeed");
    TEST_ASSERT_EQ(4096, active, "The table should hold max_flows flows");
    TEST_ASSERT_EQ(0, stats.deletes, "Filling the table should evict nothing");

    // Full: the next create evicts (one-way UDP flows are evictable)
    rte_delay_ms(EVICT_RATE_LIMIT_WAIT_MS);
    TEST_ASSERT_NOT_NULL(create_udp_flow(0x0B000001), "A full table should evict to admit a new flow");
    flow_table_get_detailed_stats(&stats);
    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT(stats.deletes > 0, "The create should be paid for by an eviction");
    TEST_ASSERT_EQ(4096 - stats.deletes + 1, active, "The evicted flows leave and the new one stays");

    flow_table_cleanup();
}

// ==================== Round 3: Mid-stream TCP Flows ====================

// A TCP exchange first seen mid-stream: client data with ACK, then (with
// reply) the server's ACK. The flow never saw the initiator's SYN, so it
// stays FLOW_STATE_NEW.
static struct flow_entry *create_midstream_tcp_flow(uint32_t client_ip, uint32_t server_ip,
                                                    bool reply) {
    struct packet_features pkt;
    bool created;

    create_test_features(&pkt, client_ip, server_ip, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
    pkt.tcp_seq = 7000;
    pkt.tcp_ack = 9000;
    pkt.payload_len = 100;
    struct flow_entry *flow = flow_table_lookup_or_create(&pkt, &created);
    if (!flow) {
        return NULL;
    }
    flow_table_update(flow, &pkt);

    if (reply) {
        create_test_features(&pkt, server_ip, client_ip, 80, 40000, IPPROTO_TCP);
        pkt.tcp_flags = RTE_TCP_ACK_FLAG;
        pkt.tcp_seq = 9000;
        pkt.tcp_ack = 7100;
        if (flow_table_lookup(&pkt) != flow) {
            return NULL;
        }
        flow_table_update(flow, &pkt);
    }
    return flow;
}

void test_flow_table_evict_scores_midstream_tcp(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    struct packet_features pkt;
    bool created;

    struct flow_entry *mid = create_midstream_tcp_flow(0x0A000001, 0xC0A80101, true);
    struct flow_entry *mid_oneway = create_midstream_tcp_flow(0x0A000002, 0xC0A80101, false);
    TEST_ASSERT_NOT_NULL(mid, "Should create the mid-stream exchange");
    TEST_ASSERT_NOT_NULL(mid_oneway, "Should create the one-way mid-stream flow");
    TEST_ASSERT_EQ(FLOW_STATE_NEW, mid->state, "A flow first seen mid-stream stays NEW");
    TEST_ASSERT(flow_is_bidirectional(mid), "The exchange should be bidirectional");

    // TCP handshake that stopped after the server's SYN-ACK
    create_test_features(&pkt, 0x0A000003, 0xC0A80101, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG;
    struct flow_entry *tcp_half = flow_table_lookup_or_create(&pkt, &created);
    TEST_ASSERT_NOT_NULL(tcp_half, "Should create the TCP flow");
    flow_table_update(tcp_half, &pkt);
    create_test_features(&pkt, 0xC0A80101, 0x0A000003, 80, 40000, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    TEST_ASSERT(flow_table_lookup(&pkt) == tcp_half, "The SYN-ACK should map to the TCP flow");
    flow_table_update(tcp_half, &pkt);
    TEST_ASSERT_EQ(FLOW_STATE_SYN_ACK_RECEIVED, tcp_half->state, "The TCP flow should be half-open");

    // NEW scored the exchange as an incomplete handshake, below the
    // half-open flow
    uint32_t evicted = flow_table_emergency_evict(1);
    TEST_ASSERT_EQ(1, evicted, "One flow should be evicted");
    TEST_ASSERT_NULL(find_tcp_flow(0x0A000002, 0xC0A80101), "The one-way mid-stream flow should go first");
    evicted = flow_table_emergency_evict(1);
    TEST_ASSERT_EQ(1, evicted, "One flow should be evicted");
    TEST_ASSERT(find_tcp_flow(0x0A000001, 0xC0A80101) == mid,
                "A mid-stream exchange should outlast a half-open handshake");
    TEST_ASSERT_NULL(find_tcp_flow(0x0A000003, 0xC0A80101), "The half-open flow should go next");

    // No handshake was verified, so it is not protected (the blind-ACK rule)
    evicted = flow_table_emergency_evict(1);
    TEST_ASSERT_EQ(1, evicted, "A mid-stream exchange should stay evictable");
    TEST_ASSERT_NULL(find_tcp_flow(0x0A000001, 0xC0A80101),
                     "The exchange should be evicted when nothing scores lower");

    flow_table_cleanup();
}

void test_flow_table_aging_keeps_midstream_tcp(void) {
    init_default_config();
    default_config.syn_timeout_sec = 2;
    default_config.idle_timeout_sec = 60;
    flow_table_init(&default_config);

    struct flow_entry *mid = create_midstream_tcp_flow(0x0A000001, 0xC0A80101, true);
    struct flow_entry *mid_oneway = create_midstream_tcp_flow(0x0A000002, 0xC0A80101, false);
    TEST_ASSERT_NOT_NULL(mid, "Should create the mid-stream exchange");
    TEST_ASSERT_NOT_NULL(mid_oneway, "Should create the one-way mid-stream flow");

    // Both idle 3 s: past the SYN timeout, well inside the idle timeout
    uint64_t idle_since = rte_rdtsc() - 3 * rte_get_tsc_hz();
    mid->last_seen_tsc = idle_since;
    mid_oneway->last_seen_tsc = idle_since;

    uint32_t aged = flow_table_age_flows();
    TEST_ASSERT_EQ(1, aged, "Only the one-way flow should age by the SYN timeout");
    TEST_ASSERT(find_tcp_flow(0x0A000001, 0xC0A80101) == mid,
                "A mid-stream exchange should age by the idle timeout");
    TEST_ASSERT_NULL(find_tcp_flow(0x0A000002, 0xC0A80101), "The one-way flow should be aged");

    flow_table_cleanup();
}

// ==================== Round 3: Pins for Earlier Fixes ====================

void test_flow_table_aging_pressure_cached_indices(void) {
    init_default_config();
    // 2^19 slots: a refill takes 32 indices and parks 31 in lcore 0's cache
    // (cache_refill_batch in flow_table.c). UDP flows age by the idle
    // timeout: 16 s, or 8 s above 90% occupancy.
    default_config.max_flows = 1 << 19;
    default_config.idle_timeout_sec = 16;
    flow_table_init(&default_config);

    // Flows last seen 10 s ago: only pressure timeouts expire them.
    // 471859 flows are 89.99996% of 2^19, just below the 90% tier.
    // 471859 = 32 * 14745 + 19, so lcore 0's cache holds 13 free indices,
    // and max_flows minus the free ring count reads 90.0025%.
    uint64_t idle_since = rte_rdtsc() - 10 * rte_get_tsc_hz();
    TEST_ASSERT_EQ(0, create_idle_udp_flows(0x10000000, 471859, idle_since),
                   "Should create 471859 flows");
    uint32_t aged = flow_table_age_flows();
    TEST_ASSERT_EQ(0, aged, "A table just below 90% should not use pressure timeouts");

    flow_table_cleanup();
}

// UDP exchange: a query and its reply
static struct flow_entry *create_udp_exchange(uint32_t client_ip) {
    struct packet_features pkt;
    bool created;

    create_test_features(&pkt, client_ip, 0xC0A80101, 5000, 53, IPPROTO_UDP);
    struct flow_entry *flow = flow_table_lookup_or_create(&pkt, &created);
    if (!flow) {
        return NULL;
    }
    flow_table_update(flow, &pkt);
    create_test_features(&pkt, 0xC0A80101, client_ip, 53, 5000, IPPROTO_UDP);
    if (flow_table_lookup(&pkt) != flow) {
        return NULL;
    }
    flow_table_update(flow, &pkt);
    return flow;
}

// The eviction takes each candidate's entry from the hash's pointer, not from
// the entry's entry_index field: a create recycling the entry (its memset,
// then the new fields) rewrites that field while a scan may read it, and a
// candidate read then would name another entry or none. Here the field holds
// what no entry has; the flow must still be evicted.
void test_flow_table_evict_takes_entry_from_pointer(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct flow_entry *flow = create_udp_flow(0x0B0000AA);
    TEST_ASSERT_NOT_NULL(flow, "Should create the flow");
    flow->entry_index = 0xFFFFFFF0u;
    TEST_ASSERT_EQ(1, flow_table_emergency_evict(1), "The eviction should delete the flow");
    uint32_t active = 0;
    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT_EQ(0, active, "No flow should remain");

    flow_table_cleanup();
}

void test_flow_table_evict_skips_protected_when_choosing(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // 4 protected flows (real handshakes) scoring 600, and 4 UDP exchanges
    // with good reputation scoring 900: evictable, yet above the protected
    // flows. A 4-flow batch must take the UDP exchanges. Had the protected
    // flows been collected as candidates, they would fill the batch, fail
    // the recheck before the delete, and nothing would be evicted.
    struct flow_entry *protected_flows[4];
    struct flow_entry *udp[4];
    for (uint32_t i = 0; i < 4; i++) {
        protected_flows[i] = create_established_flow(0x0A000001 + i, 0xC0A80101);
        TEST_ASSERT_NOT_NULL(protected_flows[i], "Should create established flow");
        udp[i] = create_udp_exchange(0x0B000001 + i);
        TEST_ASSERT_NOT_NULL(udp[i], "Should create UDP exchange");
        udp[i]->reputation_score = 3000;
    }

    uint32_t evicted = flow_table_emergency_evict(4);
    TEST_ASSERT_EQ(4, evicted, "The batch should be filled from evictable flows");
    for (uint32_t i = 0; i < 4; i++) {
        TEST_ASSERT(find_tcp_flow(0x0A000001 + i, 0xC0A80101) == protected_flows[i],
                    "Protected flows should survive");
        TEST_ASSERT_NULL(find_flow(0x0B000001 + i, 0xC0A80101, IPPROTO_UDP),
                         "The UDP exchanges should be evicted");
    }

    flow_table_cleanup();
}

// ==================== Round 3: Statistics of Every Thread Kind ====================

struct registered_ops {
    int rc;                     // rte_thread_register() result
    unsigned int lcore_id;
    struct flow_entry *flow;
    struct flow_entry *found;
    enum rst_fin_validation_result rst;
};

// A pthread registered with EAL (an lcore id of role ROLE_NON_EAL): a SYN,
// a lookup, and an RST at the expected sequence
static void *registered_lcore_ops(void *arg) {
    struct registered_ops *res = arg;
    struct packet_features pkt;
    bool created;

    res->rc = rte_thread_register();
    res->lcore_id = rte_lcore_id();
    if (res->rc == 0) {
        create_test_features(&pkt, 0x0A000001, 0xC0A80101, 40000, 80, IPPROTO_TCP);
        pkt.tcp_flags = RTE_TCP_SYN_FLAG;
        pkt.tcp_seq = TEST_CLIENT_ISN;
        res->flow = flow_table_lookup_or_create(&pkt, &created);
        if (res->flow) {
            flow_table_update(res->flow, &pkt);
        }
        res->found = flow_table_lookup(&pkt);
        pkt.tcp_flags = RTE_TCP_RST_FLAG;
        pkt.tcp_seq = TEST_CLIENT_ISN + 1;
        res->rst = flow_table_validate_rst_fin(&pkt);
        rte_thread_unregister();
    }
    return NULL;
}

void test_flow_table_registered_lcore_stats(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct registered_ops res;
    memset(&res, 0, sizeof(res));
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, registered_lcore_ops, &res);
    TEST_ASSERT_EQ(0, rc, "pthread_create should succeed");
    rc = pthread_join(thread, NULL);
    TEST_ASSERT_EQ(0, rc, "pthread_join should succeed");
    TEST_ASSERT_EQ(0, res.rc, "rte_thread_register should succeed");
    TEST_ASSERT(res.lcore_id < RTE_MAX_LCORE, "The registered thread should have an lcore id");
    TEST_ASSERT_NOT_NULL(res.flow, "The registered thread should create its flow");
    TEST_ASSERT(res.found == res.flow, "It should find its flow");
    TEST_ASSERT_EQ(RST_FIN_VALID, res.rst, "Its RST at the expected sequence should pass");

    // RTE_LCORE_FOREACH visits EAL lcores only, so the registered thread's
    // slot was never read
    uint32_t active, total;
    flow_table_get_stats(&active, &total, NULL);
    TEST_ASSERT_EQ(1, active, "One flow");
    TEST_ASSERT_EQ(1, total, "The registered thread's create should be counted");
    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);
    TEST_ASSERT_EQ(1, stats.creates, "The create should be counted");
    TEST_ASSERT_EQ(3, stats.lookups, "The three lookups should be counted");
    TEST_ASSERT_EQ(2, stats.lookup_hits, "The two hits should be counted");
    TEST_ASSERT_EQ(1, stats.updates, "The update should be counted");
    uint64_t valid, invalid;
    flow_table_get_rst_fin_stats(&valid, &invalid);
    TEST_ASSERT_EQ(1, valid, "The valid RST should be counted");
    TEST_ASSERT_EQ(0, invalid, "No invalid RST");

    flow_table_cleanup();
}

struct non_eal_totals {
    struct flow_entry *flow;
    enum rst_fin_validation_result valid_rst;
    enum rst_fin_validation_result stray_rst;
};

// A plain pthread (LCORE_ID_ANY): a SYN, an RST at the expected sequence
// and an RST for a flow that does not exist
static void *non_eal_totals_ops(void *arg) {
    struct non_eal_totals *res = arg;
    struct packet_features pkt;
    bool created;

    create_test_features(&pkt, 0x0A000001, 0xC0A80101, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN;
    res->flow = flow_table_lookup_or_create(&pkt, &created);
    if (res->flow) {
        flow_table_update(res->flow, &pkt);
    }
    pkt.tcp_flags = RTE_TCP_RST_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN + 1;
    res->valid_rst = flow_table_validate_rst_fin(&pkt);
    create_test_features(&pkt, 0x0A000002, 0xC0A80101, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_RST_FLAG;
    res->stray_rst = flow_table_validate_rst_fin(&pkt);
    return NULL;
}

void test_flow_table_non_eal_totals(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct non_eal_totals res;
    memset(&res, 0, sizeof(res));
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, non_eal_totals_ops, &res);
    TEST_ASSERT_EQ(0, rc, "pthread_create should succeed");
    rc = pthread_join(thread, NULL);
    TEST_ASSERT_EQ(0, rc, "pthread_join should succeed");
    TEST_ASSERT_NOT_NULL(res.flow, "The non-EAL thread should create its flow");
    TEST_ASSERT_EQ(RST_FIN_VALID, res.valid_rst, "The RST at the expected sequence should pass");
    TEST_ASSERT_EQ(RST_FIN_NO_FLOW, res.stray_rst, "The RST without a flow should fail");

    // The shared non-EAL slot must reach every total
    uint32_t total;
    flow_table_get_stats(NULL, &total, NULL);
    TEST_ASSERT_EQ(1, total, "The non-EAL create should reach total_flows");
    uint64_t valid, invalid;
    flow_table_get_rst_fin_stats(&valid, &invalid);
    TEST_ASSERT_EQ(1, valid, "The non-EAL valid RST should be counted");
    TEST_ASSERT_EQ(1, invalid, "The non-EAL invalid RST should be counted");

    flow_table_cleanup();
}

// ==================== Round 3: Worker CPUs ====================

// main() maps every lcore to a CPU of its own. A pthread inherits lcore 0's
// CPU, and two threads spinning on one CPU stall each other (in the free
// ring's tail update, for one); a pthread that must run alongside lcore 0
// is pinned to an idle worker lcore's CPU set instead (rte_lcore_to_cpu_id()
// gives the topology's core id, which is 0 for every CPU of some hosts).
// With no such worker it stays on lcore 0's CPU, and the subtest then shows
// no concurrency.
static void thread_attr_on_worker_cpu(pthread_attr_t *attr, unsigned int rank) {
    unsigned int lcore_id;
    unsigned int n = 0;

    pthread_attr_init(attr);
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (n++ == rank) {
            rte_cpuset_t set = rte_lcore_cpuset(lcore_id);
            pthread_attr_setaffinity_np(attr, sizeof(set), &set);
            return;
        }
    }
}

// ==================== Round 3: Concurrent Counters ====================

#define STATS_UPDATE_ROUNDS  1000000
#define STATS_LOOKUP_ROUNDS  200000
#define STATS_PARTIES        3        // lcore 0 and two non-EAL threads

struct stats_job {
    struct flow_entry *udp_flow;        // updated every round
    struct packet_features udp_pkt;
    struct packet_features rst;         // validated every round (a valid RST)
};
static struct stats_job stats_jobs[STATS_PARTIES];
static uint32_t stats_arrived;

static void stats_barrier(void) {
    __atomic_fetch_add(&stats_arrived, 1, __ATOMIC_ACQ_REL);
    while (__atomic_load_n(&stats_arrived, __ATOMIC_ACQUIRE) < STATS_PARTIES) {
        rte_pause();
    }
}

// Updates alone first, the tightest loop on the counters the parties
// share, then RST validations (a lookup each)
static void stats_run_rounds(struct stats_job *job) {
    for (uint32_t r = 0; r < STATS_UPDATE_ROUNDS; r++) {
        flow_table_update(job->udp_flow, &job->udp_pkt);
    }
    for (uint32_t r = 0; r < STATS_LOOKUP_ROUNDS; r++) {
        (void)flow_table_validate_rst_fin(&job->rst);
    }
}

static void *stats_thread(void *arg) {
    stats_barrier();
    stats_run_rounds(arg);
    return NULL;
}

void test_flow_table_non_eal_stats_concurrent(void) {
    init_default_config();
    flow_table_init(&default_config);

    // Each party: its own UDP flow to update, and its own TCP flow to
    // validate an RST against
    for (uint32_t k = 0; k < STATS_PARTIES; k++) {
        struct stats_job *job = &stats_jobs[k];
        bool created;
        create_test_features(&job->udp_pkt, 0x0A000001 + k, 0xC0A80101, 5000, 53, IPPROTO_UDP);
        job->udp_flow = flow_table_lookup_or_create(&job->udp_pkt, &created);
        TEST_ASSERT_NOT_NULL(job->udp_flow, "Should create UDP flow");
        TEST_ASSERT_NOT_NULL(create_half_open_flow(0x0B000001 + k, 0xC0A80101),
                             "Should create TCP flow");
        create_test_features(&job->rst, 0x0B000001 + k, 0xC0A80101, 40000, 80, IPPROTO_TCP);
        job->rst.tcp_flags = RTE_TCP_RST_FLAG;
        job->rst.tcp_seq = TEST_CLIENT_ISN + 1;
        TEST_ASSERT_EQ(RST_FIN_VALID, flow_table_validate_rst_fin(&job->rst),
                       "The RST should be valid");
    }
    struct flow_table_stats before, after;
    uint64_t valid_before, invalid_before, valid_after, invalid_after;
    flow_table_get_detailed_stats(&before);
    flow_table_get_rst_fin_stats(&valid_before, &invalid_before);

    // lcore 0 counts in its own slot with plain increments; the two
    // non-EAL threads share one slot and must increment it atomically
    __atomic_store_n(&stats_arrived, 0, __ATOMIC_RELEASE);
    pthread_t threads[STATS_PARTIES - 1];
    bool started[STATS_PARTIES - 1];
    uint32_t start_failures = 0;
    for (uint32_t k = 1; k < STATS_PARTIES; k++) {
        pthread_attr_t attr;
        thread_attr_on_worker_cpu(&attr, k - 1);
        started[k - 1] = pthread_create(&threads[k - 1], &attr, stats_thread, &stats_jobs[k]) == 0;
        pthread_attr_destroy(&attr);
        if (!started[k - 1]) {
            // Stand in at the barrier for the thread that did not start
            __atomic_fetch_add(&stats_arrived, 1, __ATOMIC_ACQ_REL);
            start_failures++;
        }
    }
    stats_barrier();
    stats_run_rounds(&stats_jobs[0]);
    for (uint32_t k = 1; k < STATS_PARTIES; k++) {
        if (started[k - 1]) {
            pthread_join(threads[k - 1], NULL);
        }
    }
    TEST_ASSERT_EQ(0, start_failures, "pthread_create should succeed");

    flow_table_get_detailed_stats(&after);
    flow_table_get_rst_fin_stats(&valid_after, &invalid_after);
    uint64_t expect_updates = (uint64_t)STATS_PARTIES * STATS_UPDATE_ROUNDS;
    uint64_t expect_lookups = (uint64_t)STATS_PARTIES * STATS_LOOKUP_ROUNDS;
    printf("  updates %lu of %lu, lookups %lu and valid RSTs %lu of %lu\n",
           (unsigned long)(after.updates - before.updates), (unsigned long)expect_updates,
           (unsigned long)(after.lookups - before.lookups),
           (unsigned long)(valid_after - valid_before), (unsigned long)expect_lookups);
    fflush(stdout);
    TEST_ASSERT_EQ(expect_updates, after.updates - before.updates, "Every update should be counted");
    TEST_ASSERT_EQ(expect_lookups, after.lookups - before.lookups, "Every lookup should be counted");
    TEST_ASSERT_EQ(expect_lookups, valid_after - valid_before, "Every valid RST should be counted");
    TEST_ASSERT_EQ(0, invalid_after - invalid_before, "No RST should be invalid");

    flow_table_cleanup();
}

// ==================== Round 3: Concurrent Writers (multi-lcore) ====================

// The jobs run on worker lcores (each on its own CPU, see main()). Start and
// end are signalled through atomics in this file, which a race detector
// sees (it does not see the launch and wait inside EAL).

#define STRESS_MAX_WORKERS  3
#define STRESS_OWN_KEYS     20000   // per worker, disjoint
#define STRESS_SHARED_KEYS  4000    // every worker creates each of them

static unsigned int stress_lcores[STRESS_MAX_WORKERS];
static uint32_t stress_go;
static uint32_t stress_done;

static void stress_start_wait(void) {
    while (!__atomic_load_n(&stress_go, __ATOMIC_ACQUIRE)) {
        rte_pause();
    }
}

static void stress_finish(void) {
    __atomic_fetch_add(&stress_done, 1, __ATOMIC_ACQ_REL);
}

// Runs fn(args[k]) on up to STRESS_MAX_WORKERS worker lcores at once, and
// main_step() on lcore 0 (if given) until they finish. With no worker
// lcore one job runs on lcore 0. Returns the number of jobs that ran.
static unsigned int stress_run(lcore_function_t *fn, void *args[STRESS_MAX_WORKERS],
                               void (*main_step)(void)) {
    unsigned int n = 0;
    unsigned int lcore_id;

    __atomic_store_n(&stress_go, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&stress_done, 0, __ATOMIC_RELEASE);
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (n == STRESS_MAX_WORKERS ||
            rte_eal_remote_launch(fn, args[n], lcore_id) != 0) {
            break;
        }
        stress_lcores[n++] = lcore_id;
    }
    __atomic_store_n(&stress_go, 1, __ATOMIC_RELEASE);

    if (n == 0) {
        printf("  NOTE: no worker lcore, one job runs alone (no concurrency)\n");
        fflush(stdout);
        fn(args[0]);
        return 1;
    }
    while (__atomic_load_n(&stress_done, __ATOMIC_ACQUIRE) < n) {
        if (main_step) {
            main_step();
        } else {
            rte_pause();
        }
    }
    for (unsigned int k = 0; k < n; k++) {
        rte_eal_wait_lcore(stress_lcores[k]);
    }
    return n;
}

static int compare_uintptr(const void *a, const void *b) {
    uintptr_t x = *(const uintptr_t *)a;
    uintptr_t y = *(const uintptr_t *)b;
    return (x > y) - (x < y);
}

// Number of repeated values in ptrs[0..n), sorted in place
static uint32_t count_duplicates(uintptr_t *ptrs, uint32_t n) {
    uint32_t dups = 0;
    qsort(ptrs, n, sizeof(*ptrs), compare_uintptr);
    for (uint32_t i = 1; i < n; i++) {
        if (ptrs[i] == ptrs[i - 1]) {
            dups++;
        }
    }
    return dups;
}

static inline uint32_t stress_own_ip(uint32_t worker, uint32_t i) {
    return 0x30000000 + (worker << 20) + i;
}

static inline uint32_t stress_shared_ip(uint32_t i) {
    return 0x40000000 + i;
}

struct stress_job {
    uint32_t worker;
    uint32_t failures;              // creates that returned no new flow
    struct flow_entry *own[STRESS_OWN_KEYS];
    struct flow_entry *shared[STRESS_SHARED_KEYS];
    uint8_t shared_created[STRESS_SHARED_KEYS];
};
static struct stress_job stress_jobs[STRESS_MAX_WORKERS];

static int stress_create_job(void *arg) {
    struct stress_job *job = arg;
    struct packet_features pkt;
    bool created;

    stress_start_wait();
    // The shared keys first, in the same order on every worker, so that
    // the workers race to create each of them
    for (uint32_t i = 0; i < STRESS_SHARED_KEYS; i++) {
        created = false;
        create_test_features(&pkt, stress_shared_ip(i), 0xC0A80101, 5000, 53, IPPROTO_UDP);
        job->shared[i] = flow_table_lookup_or_create(&pkt, &created);
        job->shared_created[i] = created;
        if (job->shared[i] == NULL) {
            job->failures++;
        }
    }
    for (uint32_t i = 0; i < STRESS_OWN_KEYS; i++) {
        created = false;
        create_test_features(&pkt, stress_own_ip(job->worker, i), 0xC0A80101, 5000, 53, IPPROTO_UDP);
        job->own[i] = flow_table_lookup_or_create(&pkt, &created);
        if (job->own[i] == NULL || !created) {
            job->failures++;
        }
    }
    stress_finish();
    return 0;
}

void test_flow_table_concurrent_creates(void) {
    init_default_config();
    // Under half full: no eviction, every create should succeed
    default_config.max_flows = 1 << 17;
    flow_table_init(&default_config);

    void *args[STRESS_MAX_WORKERS];
    for (uint32_t w = 0; w < STRESS_MAX_WORKERS; w++) {
        memset(&stress_jobs[w], 0, sizeof(stress_jobs[w]));
        stress_jobs[w].worker = w;
        args[w] = &stress_jobs[w];
    }
    unsigned int jobs = stress_run(stress_create_job, args, NULL);

    // Every key must map to the entry its creator got, and lcores racing on
    // a key must all get the one flow the table holds
    uint32_t failures = 0, broken_own = 0, broken_shared = 0, multi_created = 0;
    for (uint32_t w = 0; w < jobs; w++) {
        failures += stress_jobs[w].failures;
        for (uint32_t i = 0; i < STRESS_OWN_KEYS; i++) {
            if (find_flow(stress_own_ip(w, i), 0xC0A80101, IPPROTO_UDP) != stress_jobs[w].own[i]) {
                broken_own++;
            }
        }
    }
    for (uint32_t i = 0; i < STRESS_SHARED_KEYS; i++) {
        struct flow_entry *held = find_flow(stress_shared_ip(i), 0xC0A80101, IPPROTO_UDP);
        uint32_t created_count = 0;
        for (uint32_t w = 0; w < jobs; w++) {
            if (stress_jobs[w].shared[i] != held) {
                broken_shared++;
            }
            created_count += stress_jobs[w].shared_created[i];
        }
        if (created_count != 1) {
            multi_created++;
        }
    }

    // No entry handed out twice
    uint32_t expected = jobs * STRESS_OWN_KEYS + STRESS_SHARED_KEYS;
    uintptr_t *ptrs = malloc(expected * sizeof(*ptrs));
    TEST_ASSERT_NOT_NULL(ptrs, "malloc should succeed");
    uint32_t n = 0;
    for (uint32_t w = 0; w < jobs; w++) {
        for (uint32_t i = 0; i < STRESS_OWN_KEYS; i++) {
            ptrs[n++] = (uintptr_t)stress_jobs[w].own[i];
        }
    }
    for (uint32_t i = 0; i < STRESS_SHARED_KEYS; i++) {
        ptrs[n++] = (uintptr_t)stress_jobs[0].shared[i];
    }
    uint32_t dups = count_duplicates(ptrs, n);
    free(ptrs);

    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);
    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);
    printf("  %u workers: %u failed creates, %u own and %u shared keys off their entry, "
           "%u shared keys not created once, %u entries handed out twice, %u held, %lu creates\n",
           jobs, failures, broken_own, broken_shared, multi_created, dups, active,
           (unsigned long)stats.creates);
    fflush(stdout);
    TEST_ASSERT_EQ(0, failures, "Every create should succeed");
    TEST_ASSERT_EQ(0, broken_own, "Every flow should be found on the entry its creator got");
    TEST_ASSERT_EQ(0, broken_shared, "Lcores racing on a key should all get the flow the table holds");
    TEST_ASSERT_EQ(0, multi_created, "Each shared key should be created once");
    TEST_ASSERT_EQ(0, dups, "No entry should be handed out twice");
    TEST_ASSERT_EQ(expected, active, "Every key should be held once");
    TEST_ASSERT_EQ(expected, stats.creates, "Creates should count each new flow once");
    TEST_ASSERT_EQ(0, stats.create_failures, "No create should fail");

    flow_table_cleanup();
}

// Mixed writers: creates on every worker into a table too small for them,
// with emergency evictions on the workers and aging on lcore 0. The table
// is under 16384 slots, so no per-lcore cache holds a free index (see
// cache_refill_batch) and the leak check below can reach every index.

#define MIXED_TABLE    16000
#define MIXED_EXPIRED  4000
#define MIXED_KEYS     12000   // per worker

struct mixed_job {
    uint32_t worker;
    struct flow_entry *flows[MIXED_KEYS];   // NULL where the table was full
};
static struct mixed_job mixed_jobs[STRESS_MAX_WORKERS];
static uint32_t mixed_aged;

static int stress_mixed_job(void *arg) {
    struct mixed_job *job = arg;
    struct packet_features pkt;
    bool created;

    stress_start_wait();
    for (uint32_t i = 0; i < MIXED_KEYS; i++) {
        created = false;
        create_test_features(&pkt, stress_own_ip(job->worker, i), 0xC0A80101, 5000, 53, IPPROTO_UDP);
        struct flow_entry *flow = flow_table_lookup_or_create(&pkt, &created);
        job->flows[i] = created ? flow : NULL;
        if (i % 1000 == 999) {
            (void)flow_table_emergency_evict(256);
        }
    }
    stress_finish();
    return 0;
}

static void mixed_main_step(void) {
    mixed_aged += flow_table_age_flows();
}

void test_flow_table_concurrent_create_evict_age(void) {
    init_default_config();
    default_config.max_flows = MIXED_TABLE;
    default_config.idle_timeout_sec = 1;
    flow_table_init(&default_config);

    // Expired flows for aging to delete while the workers create
    uint64_t idle_since = rte_rdtsc() - 5 * rte_get_tsc_hz();
    TEST_ASSERT_EQ(0, create_idle_udp_flows(0x20000000, MIXED_EXPIRED, idle_since),
                   "Should create the expired flows");

    void *args[STRESS_MAX_WORKERS];
    for (uint32_t w = 0; w < STRESS_MAX_WORKERS; w++) {
        memset(&mixed_jobs[w], 0, sizeof(mixed_jobs[w]));
        mixed_jobs[w].worker = w;
        args[w] = &mixed_jobs[w];
    }
    mixed_aged = 0;
    unsigned int jobs = stress_run(stress_mixed_job, args, mixed_main_step);

    // A key still held must map to the entry its creator got (nothing
    // creates a key twice), and the counts must add up
    uint32_t created = 0, held = 0, broken = 0;
    for (uint32_t w = 0; w < jobs; w++) {
        for (uint32_t i = 0; i < MIXED_KEYS; i++) {
            struct flow_entry *flow = find_flow(stress_own_ip(w, i), 0xC0A80101, IPPROTO_UDP);
            created += (mixed_jobs[w].flows[i] != NULL);
            if (flow != NULL) {
                held++;
                if (flow != mixed_jobs[w].flows[i]) {
                    broken++;
                }
            }
        }
    }
    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);
    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);
    printf("  %u workers: %u created, %u held, %u off their entry; %lu creates, %lu deletes, "
           "%u active, %u aged by lcore 0\n",
           jobs, created, held, broken, (unsigned long)stats.creates,
           (unsigned long)stats.deletes, active, mixed_aged);
    fflush(stdout);
    TEST_ASSERT_EQ(0, broken, "A flow should be found on the entry its creator got");
    TEST_ASSERT_EQ((uint64_t)active, stats.creates - stats.deletes,
                   "Every create should be held or counted as deleted");

    // No index leaked or handed out twice: a cleared table takes
    // MIXED_TABLE new flows, each on its own entry
    flow_table_clear();
    uintptr_t *ptrs = malloc(MIXED_TABLE * sizeof(*ptrs));
    TEST_ASSERT_NOT_NULL(ptrs, "malloc should succeed");
    uint32_t n = 0;
    for (uint32_t i = 0; i < MIXED_TABLE; i++) {
        struct flow_entry *flow = create_udp_flow(0x50000000 + i);
        if (flow != NULL) {
            ptrs[n++] = (uintptr_t)flow;
        }
    }
    uint32_t dups = count_duplicates(ptrs, n);
    free(ptrs);
    TEST_ASSERT_EQ(MIXED_TABLE, n, "A cleared table should take max_flows flows");
    TEST_ASSERT_EQ(0, dups, "No entry should be handed out twice");

    flow_table_cleanup();
}

// The emergency eviction a full table runs from lookup_or_create is limited
// to once per 100 ms. Each round here, lcore 0 and the worker lcores find a
// full table at the same moment; the lcores that lost the race, or read the
// clock just before the winner stored its own, must not run a second
// eviction.

#define RATE_ROUNDS 20
#define RATE_LIMIT_LAPSE_MS 110    // just past the 100 ms limit (a busy wait)

static uint32_t rate_round;      // round lcore 0 released
static uint32_t rate_arrived;    // parties at the round's barrier, all rounds
static uint32_t rate_finished;   // parties done with their create, all rounds
static uint32_t rate_parties;    // the workers and lcore 0

// One round for one party: meet the others, then one create
static void rate_limit_round(uint32_t party, uint32_t r) {
    struct packet_features pkt;
    bool created;

    __atomic_fetch_add(&rate_arrived, 1, __ATOMIC_ACQ_REL);
    while (__atomic_load_n(&rate_arrived, __ATOMIC_ACQUIRE) <
           __atomic_load_n(&rate_parties, __ATOMIC_ACQUIRE) * r) {
        rte_pause();
    }
    create_test_features(&pkt, 0x70000000 + (r << 4) + party, 0xC0A80101, 5000, 53, IPPROTO_UDP);
    (void)flow_table_lookup_or_create(&pkt, &created);
    __atomic_fetch_add(&rate_finished, 1, __ATOMIC_ACQ_REL);
}

static int rate_limit_job(void *arg) {
    uint32_t party = (uint32_t)(uintptr_t)arg;
    for (uint32_t r = 1; r <= RATE_ROUNDS; r++) {
        while (__atomic_load_n(&rate_round, __ATOMIC_ACQUIRE) < r) {
            rte_pause();
        }
        rate_limit_round(party, r);
    }
    return 0;
}

void test_flow_table_evict_rate_limit_concurrent(void) {
    init_default_config();
    // 16 slots (2 hash buckets) fill completely, so the table reaches full
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    unsigned int lcores[STRESS_MAX_WORKERS];
    unsigned int lcore_id;
    uint32_t workers = 0;
    __atomic_store_n(&rate_round, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&rate_arrived, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&rate_finished, 0, __ATOMIC_RELEASE);
    uint32_t launch_failures = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (workers == STRESS_MAX_WORKERS) {
            break;
        }
        // Launched before rate_parties is final: a job waits for round 1
        if (rte_eal_remote_launch(rate_limit_job, (void *)(uintptr_t)(workers + 1), lcore_id) == 0) {
            lcores[workers++] = lcore_id;
        } else {
            launch_failures++;
        }
    }
    __atomic_store_n(&rate_parties, workers + 1, __ATOMIC_RELEASE);
    if (workers == 0) {
        printf("  NOTE: no worker lcore, lcore 0 races nobody\n");
        fflush(stdout);
    }

    uint32_t rounds_over = 0;
    for (uint32_t r = 1; r <= RATE_ROUNDS; r++) {
        // Fill the table with evictable one-way UDP flows (a create that
        // finds it full meanwhile is refused or evicts: either way it ends
        // full), then let the rate limit lapse
        for (uint32_t i = 0; i < 64; i++) {
            if (create_udp_flow(0x10000000 + (r << 8) + i) == NULL &&
                flow_table_get_occupancy_percent() == 100) {
                break;
            }
        }
        rte_delay_ms(RATE_LIMIT_LAPSE_MS);
        int before = __atomic_load_n(&evict_seam_calls, __ATOMIC_ACQUIRE);
        __atomic_store_n(&rate_round, r, __ATOMIC_RELEASE);
        rate_limit_round(0, r);
        while (__atomic_load_n(&rate_finished, __ATOMIC_ACQUIRE) <
               __atomic_load_n(&rate_parties, __ATOMIC_ACQUIRE) * r) {
            rte_pause();
        }
        int evictions = __atomic_load_n(&evict_seam_calls, __ATOMIC_ACQUIRE) - before;
        if (evictions > 1) {
            rounds_over++;
        }
    }
    for (uint32_t k = 0; k < workers; k++) {
        rte_eal_wait_lcore(lcores[k]);
    }
    printf("  %u lcores, %u of %u rounds ran more than one eviction\n",
           rate_parties, rounds_over, RATE_ROUNDS);
    fflush(stdout);
    TEST_ASSERT_EQ(0, launch_failures, "rte_eal_remote_launch should succeed");
    TEST_ASSERT_EQ(0, rounds_over, "A full table should run at most one eviction per 100 ms");

    flow_table_cleanup();
}

// ==================== Round 3: IPv6 Table ====================

static struct flow_entry_v6 *find_flow_v6(uint32_t client_host, uint32_t server_host, uint8_t protocol) {
    struct packet_features_v6 pkt;
    create_test_features_v6(&pkt, client_host, server_host, 40000, 80, protocol);
    return flow_table_v6_lookup(&pkt);
}

static struct flow_entry_v6 *create_udp_flow_v6(uint32_t client_host) {
    struct packet_features_v6 pkt;
    bool created = false;
    create_test_features_v6(&pkt, client_host, 0x100, 5000, 53, IPPROTO_UDP);
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&pkt, &created);
    return created ? flow : NULL;
}

void test_flow_table_v6_fills_to_max_flows(void) {
    init_default_config_v6();
    // As in test_flow_table_fills_to_max_flows
    default_config_v6.max_flows = 4096;
    flow_table_v6_init(&default_config_v6);

    uint32_t failed = 0;
    for (uint32_t i = 0; i < 4096; i++) {
        if (create_udp_flow_v6(0x1000 + i) == NULL) {
            failed++;
        }
    }
    struct flow_table_v6_stats stats;
    flow_table_v6_get_stats(&stats);
    uint32_t occupancy = flow_table_v6_get_occupancy_percent();
    printf("  %u of 4096 IPv6 creates failed\n", failed);
    fflush(stdout);
    TEST_ASSERT_EQ(0, failed, "Every IPv6 create below max_flows should succeed");
    TEST_ASSERT_EQ(100, occupancy, "The IPv6 table should hold max_flows flows");
    TEST_ASSERT_EQ(0, stats.create_failures, "No IPv6 create should fail");
    // The IPv6 table evicts now: a refused key would show as an eviction
    TEST_ASSERT_EQ(0, stats.deletes, "Filling the IPv6 table should evict nothing");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_aging_spares_flow_seen_after_pass_start(void) {
    init_default_config_v6();
    flow_table_v6_init(&default_config_v6);

    // As in test_flow_table_aging_spares_flow_seen_after_pass_start
    struct packet_features_v6 pkt;
    bool created;
    create_test_features_v6(&pkt, 1, 0x100, 5000, 53, IPPROTO_UDP);
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&pkt, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");
    pkt.timestamp_tsc = rte_rdtsc() + rte_get_tsc_hz();
    flow_table_v6_update(flow, &pkt);

    uint32_t aged = flow_table_v6_age_flows();
    TEST_ASSERT_EQ(0, aged, "An IPv6 flow seen after the pass started is not idle");
    TEST_ASSERT(find_flow_v6(1, 0x100, IPPROTO_UDP) == flow, "The IPv6 flow should survive aging");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_rate_limit_window_clock_skew(void) {
    init_default_config_v6();
    // As test_flow_table_rate_limit_window_clock_skew
    default_config_v6.default_pps_limit = 5;
    flow_table_v6_init(&default_config_v6);

    struct packet_features_v6 pkt;
    bool created;
    create_test_features_v6(&pkt, 1, 0x100, 5000, 53, IPPROTO_UDP);
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&pkt, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");

    uint64_t t_early = rte_rdtsc() + rte_get_tsc_hz();
    uint64_t t_late = t_early + rte_get_tsc_hz() / 100000;
    for (int i = 0; i < 5; i++) {
        pkt.timestamp_tsc = t_late;
        TEST_ASSERT_EQ(RL_ACCEPT, flow_table_v6_check_rate_limit(flow, &pkt),
                       "The IPv6 window's first 5 packets should pass");
    }
    pkt.timestamp_tsc = t_early;
    enum rate_limit_action action = flow_table_v6_check_rate_limit(flow, &pkt);
    TEST_ASSERT_EQ(RL_DROP_PPS, action, "A 6th IPv6 packet in the same window should be limited");

    flow_table_v6_cleanup();
}

// As create_midstream_tcp_flow()
static struct flow_entry_v6 *create_midstream_tcp_flow_v6(uint32_t client_host, uint32_t server_host,
                                                          bool reply) {
    struct packet_features_v6 pkt;
    bool created;

    create_test_features_v6(&pkt, client_host, server_host, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
    pkt.tcp_seq = 7000;
    pkt.tcp_ack = 9000;
    pkt.payload_len = 100;
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&pkt, &created);
    if (!flow) {
        return NULL;
    }
    flow_table_v6_update(flow, &pkt);

    if (reply) {
        create_test_features_v6(&pkt, server_host, client_host, 80, 40000, IPPROTO_TCP);
        pkt.tcp_flags = RTE_TCP_ACK_FLAG;
        pkt.tcp_seq = 9000;
        pkt.tcp_ack = 7100;
        if (flow_table_v6_lookup(&pkt) != flow) {
            return NULL;
        }
        flow_table_v6_update(flow, &pkt);
    }
    return flow;
}

void test_flow_table_v6_aging_keeps_midstream_tcp(void) {
    init_default_config_v6();
    default_config_v6.syn_timeout_sec = 2;
    default_config_v6.idle_timeout_sec = 60;
    flow_table_v6_init(&default_config_v6);

    struct flow_entry_v6 *mid = create_midstream_tcp_flow_v6(1, 0x100, true);
    struct flow_entry_v6 *mid_oneway = create_midstream_tcp_flow_v6(2, 0x100, false);
    TEST_ASSERT_NOT_NULL(mid, "Should create the IPv6 mid-stream exchange");
    TEST_ASSERT_NOT_NULL(mid_oneway, "Should create the one-way IPv6 mid-stream flow");
    TEST_ASSERT_EQ(FLOW_STATE_NEW, mid->state, "An IPv6 flow first seen mid-stream stays NEW");

    uint64_t idle_since = rte_rdtsc() - 3 * rte_get_tsc_hz();
    mid->last_seen_tsc = idle_since;
    mid_oneway->last_seen_tsc = idle_since;

    uint32_t aged = flow_table_v6_age_flows();
    TEST_ASSERT_EQ(1, aged, "Only the one-way IPv6 flow should age by the SYN timeout");
    TEST_ASSERT(find_flow_v6(1, 0x100, IPPROTO_TCP) == mid,
                "An IPv6 mid-stream exchange should age by the idle timeout");
    TEST_ASSERT_NULL(find_flow_v6(2, 0x100, IPPROTO_TCP), "The one-way IPv6 flow should be aged");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_aging_pressure_cached_indices(void) {
    init_default_config_v6();
    // As test_flow_table_aging_pressure_cached_indices: 2^19 slots, so a
    // refill parks 31 indices in lcore 0's cache; 471859 flows leave 13 there
    default_config_v6.max_flows = 1 << 19;
    default_config_v6.idle_timeout_sec = 16;
    flow_table_v6_init(&default_config_v6);

    uint64_t idle_since = rte_rdtsc() - 10 * rte_get_tsc_hz();
    TEST_ASSERT_EQ(0, create_idle_udp_flows_v6(0x100000, 471859, idle_since),
                   "Should create 471859 IPv6 flows");
    uint32_t aged = flow_table_v6_age_flows();
    TEST_ASSERT_EQ(0, aged, "An IPv6 table just below 90% should not use pressure timeouts");

    flow_table_v6_cleanup();
}

struct registered_create_v6 {
    int rc;
    unsigned int lcore_id;
    struct flow_entry_v6 *flow;
    struct flow_entry_v6 *found;
};

// A pthread registered with EAL creates and finds one IPv6 flow
static void *registered_lcore_create_v6(void *arg) {
    struct registered_create_v6 *res = arg;
    struct packet_features_v6 pkt;
    bool created;

    res->rc = rte_thread_register();
    res->lcore_id = rte_lcore_id();
    if (res->rc == 0) {
        create_test_features_v6(&pkt, 0xD000, 0x100, 5000, 53, IPPROTO_UDP);
        res->flow = flow_table_v6_lookup_or_create(&pkt, &created);
        if (res->flow) {
            flow_table_v6_update(res->flow, &pkt);
        }
        res->found = flow_table_v6_lookup(&pkt);
        rte_thread_unregister();
    }
    return NULL;
}

void test_flow_table_v6_small_table_fills_across_lcores(void) {
    init_default_config_v6();
    // As test_flow_table_small_table_fills_across_lcores
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    // Another lcore creates one flow. Its first allocation moved up to 32
    // indices (here all 16) off the ring into its own cache.
    struct registered_create_v6 res;
    memset(&res, 0, sizeof(res));
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, registered_lcore_create_v6, &res);
    TEST_ASSERT_EQ(0, rc, "pthread_create should succeed");
    rc = pthread_join(thread, NULL);
    TEST_ASSERT_EQ(0, rc, "pthread_join should succeed");
    TEST_ASSERT_EQ(0, res.rc, "rte_thread_register should succeed");
    TEST_ASSERT_NOT_NULL(res.flow, "The other lcore should create its IPv6 flow");

    // lcore 0 fills the other 15 slots. The IPv6 table evicts now: an early
    // "full" would run its eviction (wait out its rate limit so that it
    // would), which the delete count shows
    rte_delay_ms(EVICT_RATE_LIMIT_WAIT_MS);
    uint32_t failed = 0;
    for (uint32_t i = 0; i < 15; i++) {
        if (create_udp_flow_v6(0xE000 + i) == NULL) {
            failed++;
        }
    }
    struct flow_table_v6_stats stats;
    flow_table_v6_get_stats(&stats);
    TEST_ASSERT_EQ(0, failed, "lcore 0 should create all 15 IPv6 flows");
    TEST_ASSERT_EQ(0, stats.create_failures, "Every IPv6 create should find a free slot");
    TEST_ASSERT_EQ(0, stats.deletes, "Filling an IPv6 table that is not yet full should evict nothing");
    TEST_ASSERT_EQ(100, flow_table_v6_get_occupancy_percent(), "All 16 slots should be in use");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_registered_lcore_stats(void) {
    init_default_config_v6();
    flow_table_v6_init(&default_config_v6);

    struct registered_create_v6 res;
    memset(&res, 0, sizeof(res));
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, registered_lcore_create_v6, &res);
    TEST_ASSERT_EQ(0, rc, "pthread_create should succeed");
    rc = pthread_join(thread, NULL);
    TEST_ASSERT_EQ(0, rc, "pthread_join should succeed");
    TEST_ASSERT_EQ(0, res.rc, "rte_thread_register should succeed");
    TEST_ASSERT_NOT_NULL(res.flow, "The registered thread should create its IPv6 flow");
    TEST_ASSERT(res.found == res.flow, "It should find its IPv6 flow");

    // As in test_flow_table_registered_lcore_stats
    struct flow_table_v6_stats stats;
    flow_table_v6_get_stats(&stats);
    TEST_ASSERT_EQ(1, stats.creates, "The registered thread's IPv6 create should be counted");
    TEST_ASSERT_EQ(2, stats.lookups, "Both IPv6 lookups should be counted");
    TEST_ASSERT_EQ(1, stats.lookup_hits, "The IPv6 hit should be counted");
    TEST_ASSERT_EQ(1, stats.updates, "The IPv6 update should be counted");

    flow_table_v6_cleanup();
}

struct non_eal_create_v6 {
    uint32_t client_host;
    struct flow_entry_v6 *flow;
};

static void *non_eal_create_one_v6(void *arg) {
    struct non_eal_create_v6 *job = arg;
    job->flow = create_udp_flow_v6(job->client_host);
    return NULL;
}

void test_flow_table_v6_non_eal_leaves_lcore_cache(void) {
    init_default_config_v6();
    // As test_flow_table_non_eal_leaves_lcore_cache: large enough that
    // lcore 0 keeps a per-lcore free cache
    default_config_v6.max_flows = 1 << 17;

    flow_table_v6_init(&default_config_v6);
    struct flow_entry_v6 *ref_first = create_udp_flow_v6(0xA001);
    struct flow_entry_v6 *ref_second = create_udp_flow_v6(0xA002);
    TEST_ASSERT_NOT_NULL(ref_first, "Should create flow");
    TEST_ASSERT_NOT_NULL(ref_second, "Should create flow");
    uint32_t ref_first_index = ref_first->entry_index;
    uint32_t ref_second_index = ref_second->entry_index;
    flow_table_v6_cleanup();

    flow_table_v6_init(&default_config_v6);
    struct flow_entry_v6 *first = create_udp_flow_v6(0xA001);
    TEST_ASSERT_NOT_NULL(first, "Should create flow");
    struct non_eal_create_v6 job = { 0xB001, NULL };
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, non_eal_create_one_v6, &job);
    TEST_ASSERT_EQ(0, rc, "pthread_create should succeed");
    rc = pthread_join(thread, NULL);
    TEST_ASSERT_EQ(0, rc, "pthread_join should succeed");
    TEST_ASSERT_NOT_NULL(job.flow, "The non-EAL thread should create its IPv6 flow");
    struct flow_entry_v6 *second = create_udp_flow_v6(0xA002);
    TEST_ASSERT_NOT_NULL(second, "Should create flow");

    TEST_ASSERT_EQ(ref_first_index, first->entry_index, "lcore 0's first create should match the reference");
    TEST_ASSERT_EQ(ref_second_index, second->entry_index,
                   "A non-EAL IPv6 create should not take an index from lcore 0's cache");
    TEST_ASSERT(job.flow != first && job.flow != second, "The non-EAL flow should have its own entry");

    flow_table_v6_cleanup();
}

struct stats_job_v6 {
    struct flow_entry_v6 *flow;          // updated every round
    struct packet_features_v6 pkt;       // and looked up every round
};
static struct stats_job_v6 stats_jobs_v6[STATS_PARTIES];

// As stats_run_rounds()
static void stats_run_rounds_v6(struct stats_job_v6 *job) {
    for (uint32_t r = 0; r < STATS_UPDATE_ROUNDS; r++) {
        flow_table_v6_update(job->flow, &job->pkt);
    }
    for (uint32_t r = 0; r < STATS_LOOKUP_ROUNDS; r++) {
        (void)flow_table_v6_lookup(&job->pkt);
    }
}

static void *stats_thread_v6(void *arg) {
    stats_barrier();
    stats_run_rounds_v6(arg);
    return NULL;
}

void test_flow_table_v6_non_eal_stats_concurrent(void) {
    init_default_config_v6();
    flow_table_v6_init(&default_config_v6);

    // As test_flow_table_non_eal_stats_concurrent. Non-EAL threads counted
    // in lcore 0's slot with plain increments, racing lcore 0's own.
    for (uint32_t k = 0; k < STATS_PARTIES; k++) {
        struct stats_job_v6 *job = &stats_jobs_v6[k];
        bool created;
        create_test_features_v6(&job->pkt, 0xC001 + k, 0x100, 5000, 53, IPPROTO_UDP);
        job->flow = flow_table_v6_lookup_or_create(&job->pkt, &created);
        TEST_ASSERT_NOT_NULL(job->flow, "Should create IPv6 flow");
    }
    struct flow_table_v6_stats before, after;
    flow_table_v6_get_stats(&before);

    __atomic_store_n(&stats_arrived, 0, __ATOMIC_RELEASE);
    pthread_t threads[STATS_PARTIES - 1];
    bool started[STATS_PARTIES - 1];
    uint32_t start_failures = 0;
    for (uint32_t k = 1; k < STATS_PARTIES; k++) {
        pthread_attr_t attr;
        thread_attr_on_worker_cpu(&attr, k - 1);
        started[k - 1] = pthread_create(&threads[k - 1], &attr, stats_thread_v6, &stats_jobs_v6[k]) == 0;
        pthread_attr_destroy(&attr);
        if (!started[k - 1]) {
            // Stand in at the barrier for the thread that did not start
            __atomic_fetch_add(&stats_arrived, 1, __ATOMIC_ACQ_REL);
            start_failures++;
        }
    }
    stats_barrier();
    stats_run_rounds_v6(&stats_jobs_v6[0]);
    for (uint32_t k = 1; k < STATS_PARTIES; k++) {
        if (started[k - 1]) {
            pthread_join(threads[k - 1], NULL);
        }
    }
    TEST_ASSERT_EQ(0, start_failures, "pthread_create should succeed");

    flow_table_v6_get_stats(&after);
    uint64_t expect_updates = (uint64_t)STATS_PARTIES * STATS_UPDATE_ROUNDS;
    uint64_t expect_lookups = (uint64_t)STATS_PARTIES * STATS_LOOKUP_ROUNDS;
    printf("  IPv6 updates %lu of %lu, lookups %lu of %lu\n",
           (unsigned long)(after.updates - before.updates), (unsigned long)expect_updates,
           (unsigned long)(after.lookups - before.lookups), (unsigned long)expect_lookups);
    fflush(stdout);
    TEST_ASSERT_EQ(expect_updates, after.updates - before.updates, "Every IPv6 update should be counted");
    TEST_ASSERT_EQ(expect_lookups, after.lookups - before.lookups, "Every IPv6 lookup should be counted");
    TEST_ASSERT_EQ(expect_lookups, after.lookup_hits - before.lookup_hits, "Every IPv6 hit should be counted");

    flow_table_v6_cleanup();
}

struct stress_job_v6 {
    uint32_t worker;
    uint32_t failures;
    struct flow_entry_v6 *own[STRESS_OWN_KEYS];
    struct flow_entry_v6 *shared[STRESS_SHARED_KEYS];
    uint8_t shared_created[STRESS_SHARED_KEYS];
};
static struct stress_job_v6 stress_jobs_v6[STRESS_MAX_WORKERS];

static int stress_create_job_v6(void *arg) {
    struct stress_job_v6 *job = arg;
    struct packet_features_v6 pkt;
    bool created;

    stress_start_wait();
    for (uint32_t i = 0; i < STRESS_SHARED_KEYS; i++) {
        created = false;
        create_test_features_v6(&pkt, stress_shared_ip(i), 0x100, 5000, 53, IPPROTO_UDP);
        job->shared[i] = flow_table_v6_lookup_or_create(&pkt, &created);
        job->shared_created[i] = created;
        if (job->shared[i] == NULL) {
            job->failures++;
        }
    }
    for (uint32_t i = 0; i < STRESS_OWN_KEYS; i++) {
        created = false;
        create_test_features_v6(&pkt, stress_own_ip(job->worker, i), 0x100, 5000, 53, IPPROTO_UDP);
        job->own[i] = flow_table_v6_lookup_or_create(&pkt, &created);
        if (job->own[i] == NULL || !created) {
            job->failures++;
        }
    }
    stress_finish();
    return 0;
}

void test_flow_table_v6_concurrent_creates(void) {
    init_default_config_v6();
    // As test_flow_table_concurrent_creates
    default_config_v6.max_flows = 1 << 17;
    flow_table_v6_init(&default_config_v6);

    void *args[STRESS_MAX_WORKERS];
    for (uint32_t w = 0; w < STRESS_MAX_WORKERS; w++) {
        memset(&stress_jobs_v6[w], 0, sizeof(stress_jobs_v6[w]));
        stress_jobs_v6[w].worker = w;
        args[w] = &stress_jobs_v6[w];
    }
    unsigned int jobs = stress_run(stress_create_job_v6, args, NULL);

    uint32_t failures = 0, broken_own = 0, broken_shared = 0, multi_created = 0;
    for (uint32_t w = 0; w < jobs; w++) {
        failures += stress_jobs_v6[w].failures;
        for (uint32_t i = 0; i < STRESS_OWN_KEYS; i++) {
            if (find_flow_v6(stress_own_ip(w, i), 0x100, IPPROTO_UDP) != stress_jobs_v6[w].own[i]) {
                broken_own++;
            }
        }
    }
    for (uint32_t i = 0; i < STRESS_SHARED_KEYS; i++) {
        struct flow_entry_v6 *held = find_flow_v6(stress_shared_ip(i), 0x100, IPPROTO_UDP);
        uint32_t created_count = 0;
        for (uint32_t w = 0; w < jobs; w++) {
            if (stress_jobs_v6[w].shared[i] != held) {
                broken_shared++;
            }
            created_count += stress_jobs_v6[w].shared_created[i];
        }
        if (created_count != 1) {
            multi_created++;
        }
    }

    uint32_t expected = jobs * STRESS_OWN_KEYS + STRESS_SHARED_KEYS;
    uintptr_t *ptrs = malloc(expected * sizeof(*ptrs));
    TEST_ASSERT_NOT_NULL(ptrs, "malloc should succeed");
    uint32_t n = 0;
    for (uint32_t w = 0; w < jobs; w++) {
        for (uint32_t i = 0; i < STRESS_OWN_KEYS; i++) {
            ptrs[n++] = (uintptr_t)stress_jobs_v6[w].own[i];
        }
    }
    for (uint32_t i = 0; i < STRESS_SHARED_KEYS; i++) {
        ptrs[n++] = (uintptr_t)stress_jobs_v6[0].shared[i];
    }
    uint32_t dups = count_duplicates(ptrs, n);
    free(ptrs);

    struct flow_table_v6_stats stats;
    flow_table_v6_get_stats(&stats);
    printf("  %u workers: %u failed IPv6 creates, %u own and %u shared keys off their entry, "
           "%u shared keys not created once, %u entries handed out twice, %lu creates\n",
           jobs, failures, broken_own, broken_shared, multi_created, dups,
           (unsigned long)stats.creates);
    fflush(stdout);
    TEST_ASSERT_EQ(0, failures, "Every IPv6 create should succeed");
    TEST_ASSERT_EQ(0, broken_own, "Every IPv6 flow should be found on the entry its creator got");
    TEST_ASSERT_EQ(0, broken_shared, "Lcores racing on an IPv6 key should all get the flow the table holds");
    TEST_ASSERT_EQ(0, multi_created, "Each shared IPv6 key should be created once");
    TEST_ASSERT_EQ(0, dups, "No IPv6 entry should be handed out twice");
    TEST_ASSERT_EQ(expected, stats.creates, "IPv6 creates should count each new flow once");
    TEST_ASSERT_EQ(0, stats.create_failures, "No IPv6 create should fail");

    flow_table_v6_cleanup();
}

// ==================== Round 4: Seams ====================

// flow_table_hash_seed_seam(): the subtests keep the fixed seed 0 both tables
// used before their seed became random, so the hash layouts stay the ones
// the older subtests were written against; the seed subtests change it
static bool seed_fixed = true;
static uint32_t seed_value = 0;

bool flow_table_hash_seed_seam(uint32_t *seed) {
    if (!seed_fixed) {
        return false;
    }
    *seed = seed_value;
    return true;
}

// flow_table_race_seam(): while race_recording is set, counts the calls at
// each point and how many found the table's writer lock held, and runs, once,
// the action a subtest set for that point (standing in for another lcore).
// Atomics: creates on several lcores pass the create points.
static uint32_t race_recording = 0;
static void (*race_action[FLOW_SEAM_MAX])(void);
static uint32_t race_calls[FLOW_SEAM_MAX];
static uint32_t race_locked[FLOW_SEAM_MAX];

void flow_table_race_seam(enum flow_table_seam_point point) {
    if (!__atomic_load_n(&race_recording, __ATOMIC_ACQUIRE) ||
        (unsigned int)point >= FLOW_SEAM_MAX) {
        return;
    }
    bool locked = (point >= FLOW_SEAM_V6_CREATE_MISSED) ? flow_table_v6_writer_lock_held()
                                                        : flow_table_writer_lock_held();
    __atomic_fetch_add(&race_calls[point], 1, __ATOMIC_RELAXED);
    if (locked) {
        __atomic_fetch_add(&race_locked[point], 1, __ATOMIC_RELAXED);
    }
    void (*action)(void) = __atomic_exchange_n(&race_action[point], NULL, __ATOMIC_ACQ_REL);
    if (action) {
        action();
    }
}

static void race_start(void) {
    for (int p = 0; p < FLOW_SEAM_MAX; p++) {
        __atomic_store_n(&race_action[p], NULL, __ATOMIC_RELAXED);
        __atomic_store_n(&race_calls[p], 0, __ATOMIC_RELAXED);
        __atomic_store_n(&race_locked[p], 0, __ATOMIC_RELAXED);
    }
    __atomic_store_n(&race_recording, 1, __ATOMIC_RELEASE);
}

static void race_stop(void) {
    __atomic_store_n(&race_recording, 0, __ATOMIC_RELEASE);
    for (int p = 0; p < FLOW_SEAM_MAX; p++) {
        __atomic_store_n(&race_action[p], NULL, __ATOMIC_RELAXED);
    }
}

static inline uint32_t race_count(enum flow_table_seam_point point) {
    return __atomic_load_n(&race_calls[point], __ATOMIC_ACQUIRE);
}

static inline uint32_t race_count_locked(enum flow_table_seam_point point) {
    return __atomic_load_n(&race_locked[point], __ATOMIC_ACQUIRE);
}

static void test_harness_reset(void) {
    race_stop();
    seed_fixed = true;
    seed_value = 0;
    __atomic_store_n(&evict_seam_action, NULL, __ATOMIC_RELEASE);
    __atomic_store_n(&age_seam_action, NULL, __ATOMIC_RELEASE);
    __atomic_store_n(&evict_claim_action, NULL, __ATOMIC_RELEASE);
    for (unsigned int id = 0; id < RTE_MAX_LCORE; id++) {
        flow_table_reader_unregister(id);
    }
}

// ==================== Round 4: Deferred Reclamation ====================

// Reader ids for the subtests. A reader id names a registration (any value
// below RTE_MAX_LCORE), not an lcore; these stay clear of the test's lcores.
#define TEST_READER    (RTE_MAX_LCORE - 1)
#define TEST_READER_2  (RTE_MAX_LCORE - 2)

// IPv6 helpers defined with the IPv6 subtests below
static struct flow_entry_v6 *create_established_flow_v6(uint32_t client_host, uint32_t server_host);

void test_flow_table_reader_delays_reuse_after_aging(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // A packet lcore (a registered reader) holds a flow from a lookup
    TEST_ASSERT_EQ(0, flow_table_reader_register(TEST_READER), "Reader registration should succeed");
    struct flow_entry *held = create_udp_flow(0x0A000001);
    TEST_ASSERT_NOT_NULL(held, "Should create flow");

    // Aging deletes it: UDP idle 120 s against the 60 s idle timeout
    held->last_seen_tsc = rte_rdtsc() - 120 * rte_get_tsc_hz();
    uint32_t aged = flow_table_age_flows();
    TEST_ASSERT_EQ(1, aged, "Aging should delete the idle flow");
    TEST_ASSERT_NULL(find_flow(0x0A000001, SEAM_SERVER_IP, IPPROTO_UDP), "Its key should be gone");

    // The 15 other entries take protected flows (an eviction takes none)
    struct flow_entry *others[15];
    for (uint32_t i = 0; i < 15; i++) {
        others[i] = create_established_flow(0x0B000001 + i, SEAM_SERVER_IP);
        TEST_ASSERT_NOT_NULL(others[i], "Every free entry should be allocatable");
        TEST_ASSERT(others[i] != held,
                    "An entry a reader may hold should not be reused before it reports");
    }

    // Nothing else is free. With the eviction's rate limit lapsed (it would
    // evict if anything were evictable), a create fails rather than reuse
    // the held entry.
    rte_delay_ms(EVICT_RATE_LIMIT_WAIT_MS);
    struct flow_entry *refused = create_udp_flow(0x0C000001);
    TEST_ASSERT_NULL(refused, "A create should fail rather than reuse the held entry");
    uint32_t waiting = flow_table_limbo_count();
    TEST_ASSERT_EQ(1, waiting, "The deleted entry should wait for the reader");

    // A late write through the held pointer reaches no live flow
    uint64_t packets[15];
    for (uint32_t i = 0; i < 15; i++) {
        packets[i] = flow_total_packets(others[i]);
    }
    struct packet_features pkt;
    create_test_features(&pkt, 0x0A000001, SEAM_SERVER_IP, 5000, 53, IPPROTO_UDP);
    pkt.flow_direction = FLOW_DIR_LO_TO_HI;
    for (int k = 0; k < 10; k++) {
        flow_table_update(held, &pkt);
    }
    for (uint32_t i = 0; i < 15; i++) {
        uint64_t now_packets = flow_total_packets(others[i]);
        TEST_ASSERT_EQ(packets[i], now_packets, "A late write should not reach a live flow");
    }

    // The reader reports a quiescent state: the entry can be reused
    flow_table_reader_quiescent(TEST_READER);
    struct flow_entry *reused = create_udp_flow(0x0C000002);
    TEST_ASSERT(reused == held, "After the reader's report the entry should be reused");
    waiting = flow_table_limbo_count();
    TEST_ASSERT_EQ(0, waiting, "Nothing should wait any more");

    flow_table_reader_unregister(TEST_READER);
    flow_table_cleanup();
}

void test_flow_table_reader_delays_reuse_after_eviction(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // 15 protected flows, and one evictable flow that a reader holds
    TEST_ASSERT_EQ(0, flow_table_reader_register(TEST_READER), "Reader registration should succeed");
    for (uint32_t i = 0; i < 15; i++) {
        TEST_ASSERT_NOT_NULL(create_established_flow(0x0B000001 + i, SEAM_SERVER_IP),
                             "Should create established flow");
    }
    struct flow_entry *held = create_udp_flow(0x0A000001);
    TEST_ASSERT_NOT_NULL(held, "Should create flow");

    uint32_t evicted = flow_table_emergency_evict(1);
    TEST_ASSERT_EQ(1, evicted, "The one evictable flow should be evicted");

    // No free entry: creates fail until the reader reports
    struct flow_entry *refused = create_udp_flow(0x0C000001);
    TEST_ASSERT_NULL(refused, "A create should fail rather than reuse the evicted entry the reader holds");
    uint32_t waiting = flow_table_limbo_count();
    TEST_ASSERT_EQ(1, waiting, "The evicted entry should wait for the reader");

    flow_table_reader_quiescent(TEST_READER);
    struct flow_entry *reused = create_udp_flow(0x0C000002);
    TEST_ASSERT(reused == held, "After the reader's report the evicted entry should be reused");

    flow_table_reader_unregister(TEST_READER);
    flow_table_cleanup();
}

// A packet lcore on another thread: it looks a flow up and keeps the
// pointer while the main thread evicts that flow and fills the table, writes
// through the pointer late, and only then reports a quiescent state. Each
// step waits for the main thread's go-ahead (no timing involved).
struct held_reader {
    int rc;                      // flow_table_reader_register() result
    struct flow_entry *flow;     // the flow it looked up and holds
    uint32_t step;
};
static struct held_reader held_reader;

static void held_reader_wait(uint32_t step) {
    while (__atomic_load_n(&held_reader.step, __ATOMIC_ACQUIRE) < step) {
        rte_pause();
    }
}

static void held_reader_post(uint32_t step) {
    __atomic_store_n(&held_reader.step, step, __ATOMIC_RELEASE);
}

static void *held_reader_thread(void *arg) {
    (void)arg;
    struct packet_features pkt;

    held_reader.rc = flow_table_reader_register(TEST_READER_2);
    create_test_features(&pkt, 0x0A000001, SEAM_SERVER_IP, 5000, 53, IPPROTO_UDP);
    held_reader.flow = flow_table_lookup(&pkt);
    held_reader_post(1);            // holds the flow
    held_reader_wait(2);            // the main thread deleted it and refilled the table
    if (held_reader.flow) {
        for (int k = 0; k < 10; k++) {
            flow_table_update(held_reader.flow, &pkt);
        }
    }
    held_reader_post(3);            // wrote through the pointer
    held_reader_wait(4);
    flow_table_reader_quiescent(TEST_READER_2);
    held_reader_post(5);            // reported
    held_reader_wait(6);
    flow_table_reader_unregister(TEST_READER_2);
    return NULL;
}

void test_flow_table_reader_on_another_thread_delays_reuse(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // 15 protected flows, and the evictable flow the other thread will hold
    struct flow_entry *others[15];
    for (uint32_t i = 0; i < 15; i++) {
        others[i] = create_established_flow(0x0B000001 + i, SEAM_SERVER_IP);
        TEST_ASSERT_NOT_NULL(others[i], "Should create established flow");
    }
    struct flow_entry *target = create_udp_flow(0x0A000001);
    TEST_ASSERT_NOT_NULL(target, "Should create flow");
    uint64_t packets[15];
    for (uint32_t i = 0; i < 15; i++) {
        packets[i] = flow_total_packets(others[i]);
    }

    memset(&held_reader, 0, sizeof(held_reader));
    held_reader.rc = -1;
    pthread_t thread;
    pthread_attr_t attr;
    thread_attr_on_worker_cpu(&attr, 0);
    int rc = pthread_create(&thread, &attr, held_reader_thread, NULL);
    pthread_attr_destroy(&attr);
    TEST_ASSERT_EQ(0, rc, "pthread_create should succeed");

    // Every step runs before any assertion, so that the thread always ends
    held_reader_wait(1);
    uint32_t evicted = flow_table_emergency_evict(1);
    struct flow_entry *refused_before_write = create_udp_flow(0x0C000001);
    held_reader_post(2);
    held_reader_wait(3);
    uint32_t live_changed = 0;
    for (uint32_t i = 0; i < 15; i++) {
        if (flow_total_packets(others[i]) != packets[i]) {
            live_changed++;
        }
    }
    struct flow_entry *refused_after_write = create_udp_flow(0x0C000002);
    held_reader_post(4);
    held_reader_wait(5);
    struct flow_entry *reused = create_udp_flow(0x0C000003);
    held_reader_post(6);
    pthread_join(thread, NULL);

    TEST_ASSERT_EQ(0, held_reader.rc, "The other thread's reader registration should succeed");
    TEST_ASSERT(held_reader.flow == target, "The other thread should hold the flow");
    TEST_ASSERT_EQ(1, evicted, "The held flow should be evicted");
    TEST_ASSERT_NULL(refused_before_write,
                     "The entry should not be reused while the other thread holds it");
    TEST_ASSERT_EQ(0, live_changed, "The other thread's late writes should reach no live flow");
    TEST_ASSERT_NULL(refused_after_write,
                     "The entry should not be reused before the other thread reports");
    TEST_ASSERT(reused == target, "After the other thread's report the entry should be reused");

    flow_table_cleanup();
}

void test_flow_table_v6_reader_delays_reuse(void) {
    init_default_config_v6();
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    // As the IPv4 subtests: a registered reader holds two IPv6 flows; aging
    // deletes one and the eviction the other, while the 14 other entries
    // take protected flows
    TEST_ASSERT_EQ(0, flow_table_reader_register(TEST_READER), "Reader registration should succeed");
    struct flow_entry_v6 *aged_flow = create_udp_flow_v6(0x1001);
    struct flow_entry_v6 *evicted_flow = create_udp_flow_v6(0x1002);
    TEST_ASSERT_NOT_NULL(aged_flow, "Should create IPv6 flow");
    TEST_ASSERT_NOT_NULL(evicted_flow, "Should create IPv6 flow");
    for (uint32_t i = 0; i < 14; i++) {
        TEST_ASSERT_NOT_NULL(create_established_flow_v6(0x10 + i, 0x100), "Should create established IPv6 flow");
    }

    aged_flow->last_seen_tsc = rte_rdtsc() - 120 * rte_get_tsc_hz();
    uint32_t aged = flow_table_v6_age_flows();
    uint32_t evicted = flow_table_v6_emergency_evict(1);
    TEST_ASSERT_EQ(1, aged, "IPv6 aging should delete the idle flow");
    TEST_ASSERT_EQ(1, evicted, "The other evictable IPv6 flow should be evicted");

    // Nothing is free: creates fail rather than reuse the held entries
    struct flow_entry_v6 *refused = create_udp_flow_v6(0x2001);
    TEST_ASSERT_NULL(refused, "An IPv6 create should fail rather than reuse an entry the reader holds");
    uint32_t waiting = flow_table_v6_limbo_count();
    TEST_ASSERT_EQ(2, waiting, "Both deleted IPv6 entries should wait for the reader");

    // After the reader's report both come back
    flow_table_reader_quiescent(TEST_READER);
    struct flow_entry_v6 *first = create_udp_flow_v6(0x2002);
    struct flow_entry_v6 *second = create_udp_flow_v6(0x2003);
    TEST_ASSERT(first != NULL && second != NULL && first != second,
                "After the reader's report both IPv6 entries should be reused");
    TEST_ASSERT((first == aged_flow || first == evicted_flow) &&
                (second == aged_flow || second == evicted_flow),
                "The reused IPv6 entries should be the two deleted ones");

    flow_table_reader_unregister(TEST_READER);
    flow_table_v6_cleanup();
}

void test_flow_table_no_eviction_while_deleted_entries_wait(void) {
    init_default_config();
    // 512 slots: under 16384, so no per-lcore cache parks a free index
    default_config.max_flows = 512;
    flow_table_init(&default_config);
    TEST_ASSERT_EQ(0, flow_table_reader_register(TEST_READER), "Reader registration should succeed");

    // Aging deletes 300 idle flows while the reader has not reported
    uint64_t idle_since = rte_rdtsc() - 120 * rte_get_tsc_hz();
    TEST_ASSERT_EQ(0, create_idle_udp_flows(0x0A000001, 300, idle_since), "Should create 300 idle flows");
    uint32_t aged = flow_table_age_flows();
    TEST_ASSERT_EQ(300, aged, "Aging should delete the 300 idle flows");

    // The 212 free entries take evictable flows (fresh one-way UDP)
    uint32_t created = 0;
    while (created < 1024 && create_udp_flow(0x0B000001 + created) != NULL) {
        created++;
    }
    TEST_ASSERT_EQ(212, created, "Only the free entries should be taken while 300 deleted entries wait");

    // With the rate limit lapsed, a create that finds nothing free must not
    // evict live flows: 300 deleted entries already wait for the reader
    rte_delay_ms(EVICT_RATE_LIMIT_WAIT_MS);
    struct flow_entry *refused = create_udp_flow(0x0C000001);
    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);
    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT_NULL(refused, "A create should fail while the deleted entries wait");
    TEST_ASSERT_EQ(300, stats.deletes, "No live flow should be evicted while 300 deleted entries wait");
    TEST_ASSERT_EQ(212, active, "The evictable flows should all remain");

    // Once the reader reports, creates take the deleted entries, still
    // without evicting anything
    flow_table_reader_quiescent(TEST_READER);
    struct flow_entry *after_report = create_udp_flow(0x0C000002);
    TEST_ASSERT_NOT_NULL(after_report, "A create should succeed once the reader has reported");
    flow_table_get_detailed_stats(&stats);
    TEST_ASSERT_EQ(300, stats.deletes, "Taking deleted entries back should evict nothing");

    flow_table_reader_unregister(TEST_READER);
    flow_table_cleanup();
}

void test_flow_table_limbo_returns_every_index(void) {
    init_default_config();
    default_config.max_flows = 64;
    flow_table_init(&default_config);
    TEST_ASSERT_EQ(0, flow_table_reader_register(TEST_READER), "Reader registration should succeed");

    // The whole table deleted while the reader has not reported: the limbo
    // holds every index, and creates fail meanwhile
    uint64_t idle_since = rte_rdtsc() - 120 * rte_get_tsc_hz();
    TEST_ASSERT_EQ(0, create_idle_udp_flows(0x0A000001, 64, idle_since), "Should create 64 idle flows");
    uint32_t aged = flow_table_age_flows();
    TEST_ASSERT_EQ(64, aged, "Aging should delete all 64 flows");
    struct flow_entry *refused = create_udp_flow(0x0B000001);
    TEST_ASSERT_NULL(refused, "No entry should be reused before the reader reports");
    uint32_t waiting = flow_table_limbo_count();
    TEST_ASSERT_EQ(64, waiting, "Every deleted entry should wait, and the limbo holds max_flows");

    // After the report every index comes back exactly once
    flow_table_reader_quiescent(TEST_READER);
    uintptr_t ptrs[64];
    uint32_t n = 0;
    for (uint32_t i = 0; i < 64; i++) {
        struct flow_entry *flow = create_udp_flow(0x0C000001 + i);
        if (flow != NULL) {
            ptrs[n++] = (uintptr_t)flow;
        }
    }
    uint32_t dups = count_duplicates(ptrs, n);
    waiting = flow_table_limbo_count();
    TEST_ASSERT_EQ(64, n, "All 64 entries should come back");
    TEST_ASSERT_EQ(0, dups, "No entry should be handed out twice");
    TEST_ASSERT_EQ(0, waiting, "Nothing should wait any more");

    flow_table_reader_unregister(TEST_READER);
    flow_table_cleanup();
}

// Stress: worker lcores are readers that hold each flow they look up for a
// while, checking that its entry keeps its key, write through it, and only
// then report a quiescent state; meanwhile they evict, and lcore 0 (a reader
// too) ages. A deleted entry reused while a holder still has it shows as a
// changed key. FLOW_STRESS_MS sets the run time (default 400 ms).

#define READERS_TABLE   64
#define READERS_KEYS    48

struct readers_job {
    uint32_t worker;
    uint64_t holds;
    uint64_t changed;        // held entries whose key changed before the report
    uint64_t seed;
};
static struct readers_job readers_jobs[STRESS_MAX_WORKERS];
static uint32_t readers_stop;
static uint64_t readers_aged;

static inline uint64_t readers_rand(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return *s = x;
}

static int readers_job_fn(void *arg) {
    struct readers_job *job = arg;
    unsigned int me = rte_lcore_id();
    struct packet_features pkt;
    bool created;

    if (flow_table_reader_register(me) != 0) {
        job->changed = UINT64_MAX;
        stress_finish();
        return 0;
    }
    stress_start_wait();
    while (!__atomic_load_n(&readers_stop, __ATOMIC_ACQUIRE)) {
        uint32_t k = (uint32_t)(readers_rand(&job->seed) % READERS_KEYS);
        create_test_features(&pkt, 0x60000000 + k, SEAM_SERVER_IP, 5000, 53, IPPROTO_UDP);
        struct flow_key expect;
        extract_flow_key(&pkt, &expect);
        struct flow_entry *flow = flow_table_lookup_or_create(&pkt, &created);
        if (flow != NULL) {
            if (created || (readers_rand(&job->seed) & 1)) {
                // Expired at once: lcore 0's aging deletes it soon
                __atomic_store_n(&flow->last_seen_tsc, 1, __ATOMIC_RELEASE);
            }
            job->holds++;
            uint64_t spin_until = rte_rdtsc() + (readers_rand(&job->seed) % 4000);
            bool changed = memcmp(&flow->key, &expect, sizeof(expect)) != 0;
            while (!changed && rte_rdtsc() < spin_until) {
                rte_pause();
                changed = memcmp(&flow->key, &expect, sizeof(expect)) != 0;
            }
            if (changed) {
                job->changed++;
            }
            flow_table_update(flow, &pkt);
        }
        if ((readers_rand(&job->seed) & 31) == 0) {
            (void)flow_table_emergency_evict(4);
        }
        flow_table_reader_quiescent(me);
    }
    flow_table_reader_unregister(me);
    stress_finish();
    return 0;
}

static void readers_main_step(void) {
    readers_aged += flow_table_age_flows();
    flow_table_reader_quiescent(rte_lcore_id());
}

void test_flow_table_concurrent_readers_keep_held_entries(void) {
    init_default_config();
    default_config.max_flows = READERS_TABLE;
    default_config.idle_timeout_sec = 1;
    flow_table_init(&default_config);

    const char *ms_env = getenv("FLOW_STRESS_MS");
    uint64_t run_ms = (ms_env && atoi(ms_env) > 0) ? (uint64_t)atoi(ms_env) : 400;

    void *args[STRESS_MAX_WORKERS];
    for (uint32_t w = 0; w < STRESS_MAX_WORKERS; w++) {
        memset(&readers_jobs[w], 0, sizeof(readers_jobs[w]));
        readers_jobs[w].worker = w;
        readers_jobs[w].seed = 0x9E3779B97F4A7C15ULL * (w + 1);
        args[w] = &readers_jobs[w];
    }
    readers_aged = 0;
    __atomic_store_n(&readers_stop, 0, __ATOMIC_RELEASE);
    TEST_ASSERT_EQ(0, flow_table_reader_register(rte_lcore_id()), "lcore 0 reader registration should succeed");

    // stress_run() needs the jobs to end by themselves: lcore 0's step stops
    // them once the run time is over
    unsigned int n = 0;
    unsigned int lcore_id;
    __atomic_store_n(&stress_go, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&stress_done, 0, __ATOMIC_RELEASE);
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (n == STRESS_MAX_WORKERS || rte_eal_remote_launch(readers_job_fn, args[n], lcore_id) != 0) {
            break;
        }
        stress_lcores[n++] = lcore_id;
    }
    __atomic_store_n(&stress_go, 1, __ATOMIC_RELEASE);
    uint64_t end = rte_rdtsc() + run_ms * rte_get_tsc_hz() / 1000;
    while (rte_rdtsc() < end) {
        readers_main_step();
    }
    __atomic_store_n(&readers_stop, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&stress_done, __ATOMIC_ACQUIRE) < n) {
        readers_main_step();
    }
    for (unsigned int k = 0; k < n; k++) {
        rte_eal_wait_lcore(stress_lcores[k]);
    }
    flow_table_reader_unregister(rte_lcore_id());

    uint64_t holds = 0, changed = 0;
    for (unsigned int w = 0; w < n; w++) {
        holds += readers_jobs[w].holds;
        changed += readers_jobs[w].changed;
    }
    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);
    struct flow_table_stats stats;
    flow_table_get_detailed_stats(&stats);
    printf("  %u reader lcores, %lu ms: %lu holds, %lu held entries changed under their holder; "
           "%lu creates, %lu deletes (%lu aged by lcore 0), %u active\n",
           n, (unsigned long)run_ms, (unsigned long)holds, (unsigned long)changed,
           (unsigned long)stats.creates, (unsigned long)stats.deletes,
           (unsigned long)readers_aged, active);
    fflush(stdout);
    if (n == 0) {
        printf("  NOTE: no worker lcore, nothing ran concurrently\n");
    }
    TEST_ASSERT_EQ(0, changed, "No entry should be reused while a reader still holds it");
    TEST_ASSERT_EQ((uint64_t)active, stats.creates - stats.deletes,
                   "Every create should be held or counted as deleted");

    // No index leaked or handed out twice
    flow_table_clear();
    uintptr_t ptrs[READERS_TABLE];
    uint32_t got = 0;
    for (uint32_t i = 0; i < READERS_TABLE; i++) {
        struct flow_entry *flow = create_udp_flow(0x61000000 + i);
        if (flow != NULL) {
            ptrs[got++] = (uintptr_t)flow;
        }
    }
    uint32_t dups = count_duplicates(ptrs, got);
    TEST_ASSERT_EQ(READERS_TABLE, got, "A cleared table should take max_flows flows");
    TEST_ASSERT_EQ(0, dups, "No entry should be handed out twice");

    flow_table_cleanup();
}

// ==================== Round 4: Aging Walk ====================

void test_flow_table_aging_walk_resumes_after_last_flow(void) {
    init_default_config();
    // One flow looked at per call: two fresh flows, then an idle one, all in
    // the first word of the occupancy bitmap aging walks. Each call must
    // resume after the last flow it looked at, or the idle flow behind the
    // fresh ones is never reached.
    default_config.max_flows = 64;
    default_config.aging_scan_limit = 1;
    default_config.aging_scan_limit_pressure = 1;
    flow_table_init(&default_config);

    TEST_ASSERT_NOT_NULL(create_udp_flow(0x0A000001), "Should create flow");
    TEST_ASSERT_NOT_NULL(create_udp_flow(0x0A000002), "Should create flow");
    struct flow_entry *idle = create_udp_flow(0x0A000003);
    TEST_ASSERT_NOT_NULL(idle, "Should create flow");
    idle->last_seen_tsc = rte_rdtsc() - 120 * rte_get_tsc_hz();

    uint32_t aged = 0;
    for (int call = 0; call < 3; call++) {
        aged += flow_table_age_flows();
    }
    TEST_ASSERT_EQ(1, aged, "Three calls of one flow each should reach the idle flow");
    TEST_ASSERT_NULL(find_flow(0x0A000003, 0xC0A80101, IPPROTO_UDP), "The idle flow should be aged");
    TEST_ASSERT_NOT_NULL(find_flow(0x0A000001, 0xC0A80101, IPPROTO_UDP), "Fresh flows should stay");
    TEST_ASSERT_NOT_NULL(find_flow(0x0A000002, 0xC0A80101, IPPROTO_UDP), "Fresh flows should stay");

    flow_table_cleanup();
}

// ==================== Round 4: Guards Pinned Through Seams ====================

void test_flow_table_aging_rechecks_entry_long_idle(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // As test_flow_table_aging_rechecks_entry, with the flow idle 120 s, past
    // the SYN and the idle timeout. A deleted entry is no longer cleared at
    // its delete (it waits in the limbo as it was), and an entry the
    // eviction claimed reads as FLOW_STATE_INITIALIZING, which ages by the
    // idle timeout: idle only 20 s, the stale entry no longer looks expired,
    // and the expiry recheck alone keeps aging off the key's new entry. Idle
    // 120 s, only the check that the key still maps to the scanned entry does.
    struct flow_entry *old_flow = create_half_open_flow(0x0B000004, SEAM_SERVER_IP);
    TEST_ASSERT_NOT_NULL(old_flow, "Should create half-open flow");
    old_flow->last_seen_tsc = rte_rdtsc() - 120 * rte_get_tsc_hz();

    seam_client_ip = 0x0B000004;
    seam_new_flow = NULL;
    seam_evicted = 0;
    age_seam_calls = 0;
    age_seam_action = seam_evict_and_recreate;
    uint32_t aged = flow_table_age_flows();
    age_seam_action = NULL;

    TEST_ASSERT_EQ(1, age_seam_calls, "The seam should run between choosing and deleting");
    TEST_ASSERT_EQ(1, seam_evicted, "The eviction should delete the stale flow");
    TEST_ASSERT_NOT_NULL(seam_new_flow, "The key should be created again");
    TEST_ASSERT(seam_new_flow != old_flow, "The new flow should be on another entry");
    TEST_ASSERT(find_tcp_flow(0x0B000004, SEAM_SERVER_IP) == seam_new_flow,
                "A flow created after aging chose its key should not be aged");
    TEST_ASSERT_EQ(0, aged, "Aging should delete nothing: its key now maps to a new entry");

    struct flow_entry *fill[15];
    for (uint32_t i = 0; i < 15; i++) {
        fill[i] = create_half_open_flow(0x0C000001 + i, SEAM_SERVER_IP);
        TEST_ASSERT_NOT_NULL(fill[i], "Every free entry should be allocatable");
        TEST_ASSERT(fill[i] != seam_new_flow, "A live entry should not be handed out again");
        for (uint32_t j = 0; j < i; j++) {
            TEST_ASSERT(fill[i] != fill[j], "No entry should be handed out twice");
        }
    }
    uint32_t active;
    flow_table_get_stats(&active, NULL, NULL);
    TEST_ASSERT_EQ(16, active, "Table should be full");

    flow_table_cleanup();
}

void test_flow_table_aging_deletes_under_writer_lock(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    struct flow_entry *flow = create_udp_flow(0x0A000001);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");
    flow->last_seen_tsc = rte_rdtsc() - 120 * rte_get_tsc_hz();

    race_start();
    uint32_t aged = flow_table_age_flows();
    uint32_t calls = race_count(FLOW_SEAM_AGE_DELETE);
    uint32_t locked = race_count_locked(FLOW_SEAM_AGE_DELETE);
    race_stop();

    TEST_ASSERT_EQ(1, aged, "Aging should delete the idle flow");
    TEST_ASSERT_EQ(1, calls, "The delete seam should run once, after the recheck");
    TEST_ASSERT_EQ(1, locked, "Aging should recheck and delete with the writer lock held");

    flow_table_cleanup();
}

static bool claim_lock_held;

static void seam_record_claim_lock(void) {
    claim_lock_held = flow_table_writer_lock_held();
}

void test_flow_table_evict_claims_under_writer_lock(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    TEST_ASSERT_NOT_NULL(create_half_open_flow(0x0B000004, SEAM_SERVER_IP), "Should create half-open flow");

    claim_lock_held = false;
    evict_claim_calls = 0;
    evict_claim_action = seam_record_claim_lock;
    uint32_t evicted = flow_table_emergency_evict(1);
    evict_claim_action = NULL;

    TEST_ASSERT_EQ(1, evicted, "The half-open flow should be evicted");
    TEST_ASSERT_EQ(1, evict_claim_calls, "The claim seam should run between the recheck and the delete");
    TEST_ASSERT(claim_lock_held, "The eviction should recheck, claim and delete with the writer lock held");

    flow_table_cleanup();
}

void test_flow_table_clear_deletes_under_writer_lock(void) {
    init_default_config();
    flow_table_init(&default_config);

    for (uint32_t i = 0; i < 3; i++) {
        TEST_ASSERT_NOT_NULL(create_udp_flow(0x0A000001 + i), "Should create flow");
    }

    race_start();
    flow_table_clear();
    uint32_t calls = race_count(FLOW_SEAM_CLEAR_DELETE);
    uint32_t locked = race_count_locked(FLOW_SEAM_CLEAR_DELETE);
    race_stop();

    TEST_ASSERT_EQ(3, calls, "The clear's delete seam should run for each flow");
    TEST_ASSERT_EQ(3, locked, "Clear should look up and delete each key with the writer lock held");

    flow_table_cleanup();
}

// Another lcore creates the same key in the window between this create's
// lockless lookup and its add, and has added its flow but not yet published
// it: the state it leaves between its add and its publish. It publishes once
// this create waits for it.
static struct flow_entry *pub_other;
static struct packet_features pub_other_pkt;

static void seam_other_creator_adds(void) {
    bool created = false;
    pub_other = flow_table_lookup_or_create(&pub_other_pkt, &created);
    if (pub_other != NULL && created) {
        __atomic_store_n(&pub_other->state, FLOW_STATE_INITIALIZING, __ATOMIC_RELEASE);
    } else {
        pub_other = NULL;
    }
}

static void seam_other_creator_publishes(void) {
    if (pub_other != NULL) {
        __atomic_store_n(&pub_other->state, FLOW_STATE_NEW, __ATOMIC_RELEASE);
    }
}

void test_flow_table_create_waits_for_publication(void) {
    init_default_config();
    flow_table_init(&default_config);

    // Both lcores see the client's SYN
    struct packet_features syn;
    create_test_features(&syn, 0x0A000001, SEAM_SERVER_IP, 40000, 80, IPPROTO_TCP);
    syn.tcp_flags = RTE_TCP_SYN_FLAG;
    syn.tcp_seq = TEST_CLIENT_ISN;
    pub_other_pkt = syn;
    pub_other = NULL;

    race_start();
    race_action[FLOW_SEAM_CREATE_MISSED] = seam_other_creator_adds;
    race_action[FLOW_SEAM_PUBLISH_WAIT] = seam_other_creator_publishes;
    bool created = true;
    struct flow_entry *flow = flow_table_lookup_or_create(&syn, &created);
    uint8_t state_at_return = flow ? __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE) : 0xFF;
    uint32_t waits = race_count(FLOW_SEAM_PUBLISH_WAIT);
    if (flow != NULL) {
        flow_table_update(flow, &syn);
    }
    // However this create returned, the other creator publishes by now
    if (pub_other != NULL &&
        __atomic_load_n(&pub_other->state, __ATOMIC_ACQUIRE) == FLOW_STATE_INITIALIZING) {
        __atomic_store_n(&pub_other->state, FLOW_STATE_NEW, __ATOMIC_RELEASE);
    }
    uint8_t final_state = flow ? __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE) : 0xFF;
    race_stop();

    TEST_ASSERT_NOT_NULL(pub_other, "The other lcore's create should add the key");
    TEST_ASSERT(flow == pub_other, "Both creates should get the one flow");
    TEST_ASSERT(!created, "Only the other lcore created the flow");
    TEST_ASSERT_EQ(1, waits, "The create should wait for the other creator to publish");
    TEST_ASSERT_EQ(FLOW_STATE_NEW, state_at_return, "A create should return the flow only once it is published");
    TEST_ASSERT_EQ(FLOW_STATE_SYN_RECEIVED, final_state,
                   "The SYN should move the flow, not be lost on an unpublished one");

    flow_table_cleanup();
}

// ==================== Round 4: Hash Seed ====================

void test_flow_table_hash_seed_random(void) {
    // Each table draws its own seed: four in a row should not all be equal
    // (the seed was the fixed 0)
    seed_fixed = false;
    uint32_t seeds[4];
    uint32_t working = 0;
    for (int i = 0; i < 4; i++) {
        init_default_config();
        flow_table_init(&default_config);
        seeds[i] = flow_table_get_hash_seed();
        struct flow_entry *flow = create_udp_flow(0x0A000001);
        if (flow != NULL && find_flow(0x0A000001, 0xC0A80101, IPPROTO_UDP) == flow) {
            working++;
        }
        flow_table_cleanup();
    }
    seed_fixed = true;
    printf("  seeds %08x %08x %08x %08x\n", seeds[0], seeds[1], seeds[2], seeds[3]);
    fflush(stdout);
    TEST_ASSERT_EQ(4, working, "Every table should find the flows it creates");
    TEST_ASSERT(!(seeds[0] == seeds[1] && seeds[1] == seeds[2] && seeds[2] == seeds[3]),
                "Each table should draw a random hash seed");
}

void test_flow_table_hash_seed_seam_sets_hash(void) {
    // The seam's seed is the one the table hashes with: a lookup with the
    // hash computed with that seed finds the flow, one with seed 0 does not
    const uint32_t seed = 0x9E3779B9;
    seed_fixed = true;
    seed_value = seed;
    init_default_config();
    flow_table_init(&default_config);
    uint32_t table_seed = flow_table_get_hash_seed();
    seed_value = 0;

    struct packet_features pkt;
    create_test_features(&pkt, 0x0A000001, 0xC0A80101, 5000, 53, IPPROTO_UDP);
    bool created;
    struct flow_entry *flow = flow_table_lookup_or_create(&pkt, &created);
    TEST_ASSERT_NOT_NULL(flow, "Should create flow");

    struct flow_key key;
    extract_flow_key(&pkt, &key);
    uint32_t hash_seeded = rte_jhash(&key, sizeof(key), seed);
    uint32_t hash_zero = rte_jhash(&key, sizeof(key), 0);
    struct flow_entry *found_seeded = flow_table_lookup_with_hash(&key, hash_seeded);
    struct flow_entry *found_zero = flow_table_lookup_with_hash(&key, hash_zero);

    TEST_ASSERT_EQ(seed, table_seed, "The table should take the seam's seed");
    TEST_ASSERT(hash_seeded != hash_zero, "The two seeds should hash the key differently");
    TEST_ASSERT(found_seeded == flow, "The table should hash with the seam's seed");
    TEST_ASSERT_NULL(found_zero, "The table should not hash with seed 0");

    flow_table_cleanup();
}

void test_flow_table_v6_hash_seed_random(void) {
    // As test_flow_table_hash_seed_random, for the IPv6 table
    seed_fixed = false;
    uint32_t seeds[4];
    uint32_t working = 0;
    for (int i = 0; i < 4; i++) {
        init_default_config_v6();
        flow_table_v6_init(&default_config_v6);
        seeds[i] = flow_table_v6_get_hash_seed();
        struct flow_entry_v6 *flow = create_udp_flow_v6(0x1001);
        if (flow != NULL && find_flow_v6(0x1001, 0x100, IPPROTO_UDP) == flow) {
            working++;
        }
        flow_table_v6_cleanup();
    }
    seed_fixed = true;

    // The seam's seed is the one it takes
    seed_value = 0x7F4A7C15;
    init_default_config_v6();
    flow_table_v6_init(&default_config_v6);
    uint32_t table_seed = flow_table_v6_get_hash_seed();
    seed_value = 0;
    flow_table_v6_cleanup();

    printf("  IPv6 seeds %08x %08x %08x %08x\n", seeds[0], seeds[1], seeds[2], seeds[3]);
    fflush(stdout);
    TEST_ASSERT_EQ(4, working, "Every IPv6 table should find the flows it creates");
    TEST_ASSERT(!(seeds[0] == seeds[1] && seeds[1] == seeds[2] && seeds[2] == seeds[3]),
                "Each IPv6 table should draw a random hash seed");
    TEST_ASSERT_EQ(0x7F4A7C15, table_seed, "The IPv6 table should take the seam's seed");
}

// ==================== Round 4: Counting Without Trust ====================

void test_flow_table_count_packet_keeps_tcp_view(void) {
    init_default_config();
    flow_table_init(&default_config);

    struct flow_entry *flow = create_established_flow(0x0A000001, SEAM_SERVER_IP);
    TEST_ASSERT_NOT_NULL(flow, "Should create established flow");
    uint8_t state = flow->state;
    uint8_t flags = flow->flags;
    uint8_t flags_lo = flow->tcp_flags_lo_to_hi, flags_hi = flow->tcp_flags_hi_to_lo;
    uint32_t seq_lo = flow->seq_lo_to_hi, seq_hi = flow->seq_hi_to_lo;
    uint32_t ack_lo = flow->ack_lo_to_hi, ack_hi = flow->ack_hi_to_lo;
    uint64_t packets = flow_total_packets(flow), bytes = flow_total_bytes(flow);

    // A blind RST from the client, far out of window, stamped 1 s ahead
    struct packet_features rst;
    create_test_features(&rst, 0x0A000001, SEAM_SERVER_IP, 40000, 80, IPPROTO_TCP);
    rst.tcp_flags = RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG;
    rst.tcp_seq = TEST_CLIENT_ISN + 0x40000000;
    rst.tcp_ack = 0x12345678;
    rst.packet_size = 60;
    rst.timestamp_tsc = rte_rdtsc() + rte_get_tsc_hz();
    TEST_ASSERT(flow_table_lookup(&rst) == flow, "The RST should map to the flow");
    flow_table_count_packet(flow, &rst);

    uint64_t packets_after = flow_total_packets(flow), bytes_after = flow_total_bytes(flow);
    TEST_ASSERT_EQ(packets + 1, packets_after, "The packet should be counted");
    TEST_ASSERT_EQ(bytes + 60, bytes_after, "Its bytes should be counted");
    TEST_ASSERT(flow->last_seen_tsc == rst.timestamp_tsc, "Its time should be recorded");
    TEST_ASSERT_EQ(state, flow->state, "The state should not change");
    TEST_ASSERT_EQ(flags, flow->flags, "The flow flags should not change");
    TEST_ASSERT_EQ(flags_lo, flow->tcp_flags_lo_to_hi, "The TCP flags seen should not change");
    TEST_ASSERT_EQ(flags_hi, flow->tcp_flags_hi_to_lo, "The TCP flags seen should not change");
    TEST_ASSERT_EQ(seq_lo, flow->seq_lo_to_hi, "The sequence tracking should not change");
    TEST_ASSERT_EQ(seq_hi, flow->seq_hi_to_lo, "The sequence tracking should not change");
    TEST_ASSERT_EQ(ack_lo, flow->ack_lo_to_hi, "The ACK tracking should not change");
    TEST_ASSERT_EQ(ack_hi, flow->ack_hi_to_lo, "The ACK tracking should not change");

    flow_table_cleanup();
}

static struct flow_entry_v6 *create_handshake_flow_v6(uint32_t client_host, uint32_t server_host,
                                                      uint32_t final_ack) {
    struct packet_features_v6 pkt;
    bool created;

    create_test_features_v6(&pkt, client_host, server_host, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN;
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&pkt, &created);
    if (!flow) {
        return NULL;
    }
    flow_table_v6_update(flow, &pkt);

    create_test_features_v6(&pkt, server_host, client_host, 80, 40000, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = TEST_SERVER_ISN;
    pkt.tcp_ack = TEST_CLIENT_ISN + 1;
    if (flow_table_v6_lookup(&pkt) != flow) {
        return NULL;
    }
    flow_table_v6_update(flow, &pkt);

    create_test_features_v6(&pkt, client_host, server_host, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN + 1;
    pkt.tcp_ack = final_ack;
    if (flow_table_v6_lookup(&pkt) != flow) {
        return NULL;
    }
    flow_table_v6_update(flow, &pkt);
    return flow;
}

static struct flow_entry_v6 *create_established_flow_v6(uint32_t client_host, uint32_t server_host) {
    return create_handshake_flow_v6(client_host, server_host, TEST_SERVER_ISN + 1);
}

static struct flow_entry_v6 *create_half_open_flow_v6(uint32_t client_host, uint32_t server_host) {
    struct packet_features_v6 pkt;
    bool created;

    create_test_features_v6(&pkt, client_host, server_host, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN;
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&pkt, &created);
    if (flow) {
        flow_table_v6_update(flow, &pkt);
    }
    return flow;
}

static struct flow_entry_v6 *find_tcp_flow_v6(uint32_t client_host, uint32_t server_host) {
    return find_flow_v6(client_host, server_host, IPPROTO_TCP);
}

void test_flow_table_v6_count_packet_keeps_tcp_view(void) {
    init_default_config_v6();
    flow_table_v6_init(&default_config_v6);

    struct flow_entry_v6 *flow = create_established_flow_v6(1, 0x100);
    TEST_ASSERT_NOT_NULL(flow, "Should create established IPv6 flow");
    uint8_t state = flow->state;
    uint8_t flags = flow->flags;
    uint8_t flags_lo = flow->tcp_flags_lo_to_hi, flags_hi = flow->tcp_flags_hi_to_lo;
    uint32_t seq_lo = flow->seq_lo_to_hi, seq_hi = flow->seq_hi_to_lo;
    uint32_t ack_lo = flow->ack_lo_to_hi, ack_hi = flow->ack_hi_to_lo;
    uint64_t packets = flow_v6_total_packets(flow), bytes = flow_v6_total_bytes(flow);

    struct packet_features_v6 rst;
    create_test_features_v6(&rst, 1, 0x100, 40000, 80, IPPROTO_TCP);
    rst.tcp_flags = RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG;
    rst.tcp_seq = TEST_CLIENT_ISN + 0x40000000;
    rst.tcp_ack = 0x12345678;
    rst.packet_size = 80;
    TEST_ASSERT(flow_table_v6_lookup(&rst) == flow, "The RST should map to the IPv6 flow");
    flow_table_v6_count_packet(flow, &rst);

    uint64_t packets_after = flow_v6_total_packets(flow), bytes_after = flow_v6_total_bytes(flow);
    TEST_ASSERT_EQ(packets + 1, packets_after, "The IPv6 packet should be counted");
    TEST_ASSERT_EQ(bytes + 80, bytes_after, "Its bytes should be counted");
    TEST_ASSERT_EQ(state, flow->state, "The IPv6 state should not change");
    TEST_ASSERT_EQ(flags, flow->flags, "The IPv6 flow flags should not change");
    TEST_ASSERT_EQ(flags_lo, flow->tcp_flags_lo_to_hi, "The IPv6 TCP flags seen should not change");
    TEST_ASSERT_EQ(flags_hi, flow->tcp_flags_hi_to_lo, "The IPv6 TCP flags seen should not change");
    TEST_ASSERT_EQ(seq_lo, flow->seq_lo_to_hi, "The IPv6 sequence tracking should not change");
    TEST_ASSERT_EQ(seq_hi, flow->seq_hi_to_lo, "The IPv6 sequence tracking should not change");
    TEST_ASSERT_EQ(ack_lo, flow->ack_lo_to_hi, "The IPv6 ACK tracking should not change");
    TEST_ASSERT_EQ(ack_hi, flow->ack_hi_to_lo, "The IPv6 ACK tracking should not change");

    flow_table_v6_cleanup();
}

void test_flow_table_mark_handshake_verified(void) {
    init_default_config();
    default_config.max_flows = 16;
    flow_table_init(&default_config);

    // A flow first seen mid-stream (NEW), a half-open one (SYN_RECEIVED)
    // and one past the server's SYN-ACK (SYN_ACK_RECEIVED): the proxy
    // verified each handshake
    struct packet_features pkt;
    bool created;
    struct flow_entry *mid = create_midstream_tcp_flow(0x0A000001, SEAM_SERVER_IP, true);
    struct flow_entry *half = create_half_open_flow(0x0A000002, SEAM_SERVER_IP);
    TEST_ASSERT_NOT_NULL(mid, "Should create the mid-stream flow");
    TEST_ASSERT_NOT_NULL(half, "Should create the half-open flow");

    create_test_features(&pkt, 0x0A000003, SEAM_SERVER_IP, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN;
    struct flow_entry *synack = flow_table_lookup_or_create(&pkt, &created);
    TEST_ASSERT_NOT_NULL(synack, "Should create the handshake flow");
    flow_table_update(synack, &pkt);
    create_test_features(&pkt, SEAM_SERVER_IP, 0x0A000003, 80, 40000, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = TEST_SERVER_ISN;
    pkt.tcp_ack = TEST_CLIENT_ISN + 1;
    TEST_ASSERT(flow_table_lookup(&pkt) == synack, "The SYN-ACK should map to the flow");
    flow_table_update(synack, &pkt);
    TEST_ASSERT_EQ(FLOW_STATE_SYN_ACK_RECEIVED, synack->state, "The flow should be past the SYN-ACK");

    // A closing flow: a real handshake, then the client's FIN
    struct flow_entry *closing = create_established_flow(0x0A000004, SEAM_SERVER_IP);
    TEST_ASSERT_NOT_NULL(closing, "Should create the closing flow");
    create_test_features(&pkt, 0x0A000004, SEAM_SERVER_IP, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN + 1;
    pkt.tcp_ack = TEST_SERVER_ISN + 1;
    TEST_ASSERT(flow_table_lookup(&pkt) == closing, "The FIN should map to the flow");
    flow_table_update(closing, &pkt);
    TEST_ASSERT_EQ(FLOW_STATE_FIN_WAIT_1, closing->state, "The client's FIN should start the close");

    flow_table_mark_handshake_verified(mid);
    flow_table_mark_handshake_verified(half);
    flow_table_mark_handshake_verified(synack);
    flow_table_mark_handshake_verified(closing);

    TEST_ASSERT_EQ(FLOW_STATE_ESTABLISHED, mid->state, "A NEW flow should become ESTABLISHED");
    TEST_ASSERT_EQ(FLOW_STATE_ESTABLISHED, half->state, "A SYN_RECEIVED flow should become ESTABLISHED");
    TEST_ASSERT_EQ(FLOW_STATE_ESTABLISHED, synack->state, "A SYN_ACK_RECEIVED flow should become ESTABLISHED");
    TEST_ASSERT_EQ(FLOW_STATE_FIN_WAIT_1, closing->state, "A closing flow should keep its state");
    TEST_ASSERT(mid->flags & FLOW_FLAG_HANDSHAKE_ACKED, "The verified handshake should be recorded");
    TEST_ASSERT(half->flags & FLOW_FLAG_HANDSHAKE_ACKED, "The verified handshake should be recorded");
    TEST_ASSERT(synack->flags & FLOW_FLAG_HANDSHAKE_ACKED, "The verified handshake should be recorded");

    // With traffic both ways a verified flow is protected; the half-open
    // one, one-way, stays evictable
    uint32_t evicted = flow_table_emergency_evict(256);
    TEST_ASSERT_EQ(2, evicted, "Only the one-way and the closing flows should be evicted");
    TEST_ASSERT(find_tcp_flow(0x0A000001, SEAM_SERVER_IP) == mid, "The verified mid-stream exchange should be protected");
    TEST_ASSERT(find_tcp_flow(0x0A000003, SEAM_SERVER_IP) == synack, "The verified handshake should be protected");
    TEST_ASSERT_NULL(find_tcp_flow(0x0A000002, SEAM_SERVER_IP), "A one-way flow should stay evictable");

    flow_table_cleanup();
}

// ==================== Round 4: IPv6 Emergency Eviction ====================

// The IPv6 eviction's rate limit is its own (a static in flow_table_v6.c),
// also process-wide: a create that must evict waits it out first
void test_flow_table_v6_full_table_evicts(void) {
    init_default_config_v6();
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    for (uint32_t i = 0; i < 16; i++) {
        TEST_ASSERT_NOT_NULL(create_udp_flow_v6(0x1000 + i), "Should create IPv6 flow");
    }
    uint32_t occupancy = flow_table_v6_get_occupancy_percent();
    TEST_ASSERT_EQ(100, occupancy, "The IPv6 table should be full");

    // A full IPv6 table refused every new flow: it had no eviction
    rte_delay_ms(EVICT_RATE_LIMIT_WAIT_MS);
    struct flow_entry_v6 *flow = create_udp_flow_v6(0x2000);
    struct flow_table_v6_stats stats;
    flow_table_v6_get_stats(&stats);
    TEST_ASSERT_NOT_NULL(flow, "A full IPv6 table should evict to admit a new flow");
    TEST_ASSERT(stats.deletes > 0, "The create should be paid for by an eviction");
    TEST_ASSERT_EQ(0, stats.create_failures, "The create should not fail");
    TEST_ASSERT(find_flow_v6(0x2000, 0x100, IPPROTO_UDP) == flow, "The new IPv6 flow should be held");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_evict_spares_established(void) {
    init_default_config_v6();
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    // As test_flow_table_evict_spares_established: 10 real handshakes, 6
    // half-open flows
    struct flow_entry_v6 *established[10];
    for (uint32_t i = 0; i < 10; i++) {
        established[i] = create_established_flow_v6(0x10 + i, 0x100);
        TEST_ASSERT_NOT_NULL(established[i], "Should create established IPv6 flow");
        TEST_ASSERT(flow_v6_is_established(established[i]) && flow_v6_is_bidirectional(established[i]) &&
                    (established[i]->flags & FLOW_FLAG_HANDSHAKE_ACKED),
                    "A real IPv6 handshake should acknowledge the server's ISN + 1");
    }
    for (uint32_t i = 0; i < 6; i++) {
        TEST_ASSERT_NOT_NULL(create_half_open_flow_v6(0x20 + i, 0x100), "Should create half-open IPv6 flow");
    }

    uint32_t evicted = flow_table_v6_emergency_evict(256);
    TEST_ASSERT_EQ(6, evicted, "Only the 6 half-open IPv6 flows should be evicted");
    for (uint32_t i = 0; i < 10; i++) {
        struct flow_entry_v6 *found = find_tcp_flow_v6(0x10 + i, 0x100);
        TEST_ASSERT(found == established[i], "An established IPv6 flow should survive eviction");
        TEST_ASSERT_EQ(FLOW_STATE_ESTABLISHED, found->state, "It should still be ESTABLISHED");
    }
    for (uint32_t i = 0; i < 6; i++) {
        TEST_ASSERT_NULL(find_tcp_flow_v6(0x20 + i, 0x100), "A half-open IPv6 flow should be evicted");
    }

    flow_table_v6_cleanup();
}

void test_flow_table_v6_evict_blind_ack_not_protected(void) {
    init_default_config_v6();
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    // As test_flow_table_evict_blind_ack_not_protected: both look ESTABLISHED
    // with traffic both ways; only the real handshake acknowledged ISN + 1
    struct flow_entry_v6 *real = create_established_flow_v6(1, 0x100);
    struct flow_entry_v6 *blind = create_handshake_flow_v6(2, 0x100, 0x12345678);
    TEST_ASSERT_NOT_NULL(real, "Should create the real IPv6 handshake");
    TEST_ASSERT_NOT_NULL(blind, "Should create the blind-ACK IPv6 handshake");
    TEST_ASSERT(flow_v6_is_established(blind) && flow_v6_is_bidirectional(blind),
                "The blind-ACK IPv6 flow should look established and bidirectional");
    TEST_ASSERT(!(blind->flags & FLOW_FLAG_HANDSHAKE_ACKED), "A blind ACK should not verify the handshake");

    uint32_t evicted = flow_table_v6_emergency_evict(256);
    TEST_ASSERT_EQ(1, evicted, "The blind-ACK IPv6 flow should be evictable");
    TEST_ASSERT_NULL(find_tcp_flow_v6(2, 0x100), "The blind-ACK IPv6 flow should be evicted");
    TEST_ASSERT(find_tcp_flow_v6(1, 0x100) == real, "The real IPv6 handshake should be protected");

    flow_table_v6_cleanup();
}

static uint32_t v6_seam_client;
static struct flow_entry_v6 *v6_seam_new_flow;
static uint32_t v6_seam_aged;
static uint32_t v6_seam_evicted;

// IPv6 aging (the maintenance lcore) expires the flow from v6_seam_client,
// and a new SYN (another lcore) creates the key again on a new entry
static void seam_v6_age_and_recreate(void) {
    v6_seam_aged = flow_table_v6_age_flows();
    v6_seam_new_flow = create_half_open_flow_v6(v6_seam_client, 0x100);
}

// An IPv6 eviction (a worker lcore) deletes the flow from v6_seam_client, and
// a new SYN creates the key again on a new entry
static void seam_v6_evict_and_recreate(void) {
    v6_seam_evicted = flow_table_v6_emergency_evict(256);
    v6_seam_new_flow = create_half_open_flow_v6(v6_seam_client, 0x100);
}

// The handshake of the half-open IPv6 flow from v6_seam_client completes
static void seam_v6_complete_handshake(void) {
    struct packet_features_v6 pkt;

    create_test_features_v6(&pkt, 0x100, v6_seam_client, 80, 40000, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = TEST_SERVER_ISN;
    pkt.tcp_ack = TEST_CLIENT_ISN + 1;
    struct flow_entry_v6 *flow = flow_table_v6_lookup(&pkt);
    if (!flow) {
        return;
    }
    flow_table_v6_update(flow, &pkt);

    create_test_features_v6(&pkt, v6_seam_client, 0x100, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN + 1;
    pkt.tcp_ack = TEST_SERVER_ISN + 1;
    if (flow_table_v6_lookup(&pkt) == flow) {
        flow_table_v6_update(flow, &pkt);
    }
}

// A packet (another lcore) refreshes the IPv6 flow from v6_seam_client
static void seam_v6_refresh_flow(void) {
    struct packet_features_v6 pkt;
    create_test_features_v6(&pkt, v6_seam_client, 0x100, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN;
    pkt.timestamp_tsc = 0;  // stamped now, after the pass read its clock
    struct flow_entry_v6 *flow = flow_table_v6_lookup(&pkt);
    if (flow) {
        flow_table_v6_update(flow, &pkt);
    }
}

// Each of the 15 other entries is allocatable exactly once and is not the
// live new flow (an index freed twice would be handed out twice)
static int v6_fill_rest_checks(struct flow_entry_v6 *live, uint32_t client_base) {
    struct flow_entry_v6 *fill[15];
    for (uint32_t i = 0; i < 15; i++) {
        fill[i] = create_half_open_flow_v6(client_base + i, 0x100);
        if (fill[i] == NULL || fill[i] == live) {
            return -1;
        }
        for (uint32_t j = 0; j < i; j++) {
            if (fill[i] == fill[j]) {
                return -1;
            }
        }
    }
    return 0;
}

void test_flow_table_v6_evict_rechecks_entry(void) {
    init_default_config_v6();
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    // As test_flow_table_evict_rechecks_entry: four half-open flows; the
    // fourth was last seen 20 s ago, past the 10 s SYN timeout
    for (uint32_t i = 0; i < 3; i++) {
        TEST_ASSERT_NOT_NULL(create_half_open_flow_v6(0x31 + i, 0x100), "Should create half-open IPv6 flow");
    }
    struct flow_entry_v6 *old_flow = create_half_open_flow_v6(0x34, 0x100);
    TEST_ASSERT_NOT_NULL(old_flow, "Should create half-open IPv6 flow");
    old_flow->last_seen_tsc = rte_rdtsc() - 20 * rte_get_tsc_hz();

    // After the choice and before the deletes, aging deletes the fourth key
    // and a new SYN creates it again on another entry
    v6_seam_client = 0x34;
    v6_seam_new_flow = NULL;
    v6_seam_aged = 0;
    race_start();
    race_action[FLOW_SEAM_V6_EVICT] = seam_v6_age_and_recreate;
    uint32_t evicted = flow_table_v6_emergency_evict(256);
    uint32_t calls = race_count(FLOW_SEAM_V6_EVICT);
    race_stop();

    TEST_ASSERT_EQ(1, calls, "The IPv6 seam should run between choosing and deleting");
    TEST_ASSERT_EQ(1, v6_seam_aged, "IPv6 aging should expire the stale flow");
    TEST_ASSERT_NOT_NULL(v6_seam_new_flow, "The key should be created again");
    TEST_ASSERT(v6_seam_new_flow != old_flow, "The new IPv6 flow should be on another entry");
    TEST_ASSERT(find_tcp_flow_v6(0x34, 0x100) == v6_seam_new_flow,
                "An IPv6 flow created after the choice should not be evicted");
    TEST_ASSERT_EQ(3, evicted, "Only the IPv6 flows still on their scanned entries should be evicted");

    // Index accounting: the new flow holds one entry, each of the other 15
    // is free exactly once
    TEST_ASSERT_EQ(0, v6_fill_rest_checks(v6_seam_new_flow, 0x40),
                   "Every other IPv6 entry should be allocatable exactly once");
    uint32_t occupancy = flow_table_v6_get_occupancy_percent();
    TEST_ASSERT_EQ(100, occupancy, "The IPv6 table should be full");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_evict_claim_spares_late_handshake(void) {
    init_default_config_v6();
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    // As test_flow_table_evict_claim_spares_late_handshake
    struct flow_entry_v6 *flow = create_half_open_flow_v6(0x34, 0x100);
    TEST_ASSERT_NOT_NULL(flow, "Should create half-open IPv6 flow");

    v6_seam_client = 0x34;
    race_start();
    race_action[FLOW_SEAM_V6_EVICT_CLAIM] = seam_v6_complete_handshake;
    uint32_t evicted = flow_table_v6_emergency_evict(256);
    uint32_t calls = race_count(FLOW_SEAM_V6_EVICT_CLAIM);
    uint32_t locked = race_count_locked(FLOW_SEAM_V6_EVICT_CLAIM);
    race_stop();

    TEST_ASSERT_EQ(1, calls, "The IPv6 claim seam should run between the recheck and the delete");
    TEST_ASSERT_EQ(1, locked, "The IPv6 eviction should recheck and claim with the writer lock held");
    TEST_ASSERT(find_tcp_flow_v6(0x34, 0x100) == flow,
                "An IPv6 flow whose handshake completed before its claim should be kept");
    TEST_ASSERT(flow_v6_is_established(flow) && flow_v6_is_bidirectional(flow) &&
                (flow->flags & FLOW_FLAG_HANDSHAKE_ACKED),
                "Its handshake should have completed");
    TEST_ASSERT_EQ(0, evicted, "Nothing should be evicted");

    flow_table_v6_cleanup();
}

// UDP exchange over IPv6: a query and its reply
static struct flow_entry_v6 *create_udp_exchange_v6(uint32_t client_host) {
    struct packet_features_v6 pkt;
    bool created;

    create_test_features_v6(&pkt, client_host, 0x100, 5000, 53, IPPROTO_UDP);
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&pkt, &created);
    if (!flow) {
        return NULL;
    }
    flow_table_v6_update(flow, &pkt);
    create_test_features_v6(&pkt, 0x100, client_host, 53, 5000, IPPROTO_UDP);
    if (flow_table_v6_lookup(&pkt) != flow) {
        return NULL;
    }
    flow_table_v6_update(flow, &pkt);
    return flow;
}

void test_flow_table_v6_evict_skips_protected_when_choosing(void) {
    init_default_config_v6();
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    // As test_flow_table_evict_skips_protected_when_choosing: 4 protected
    // flows scoring 600, 4 UDP exchanges with good reputation scoring 900
    struct flow_entry_v6 *protected_flows[4];
    struct flow_entry_v6 *udp[4];
    for (uint32_t i = 0; i < 4; i++) {
        protected_flows[i] = create_established_flow_v6(0x10 + i, 0x100);
        TEST_ASSERT_NOT_NULL(protected_flows[i], "Should create established IPv6 flow");
        udp[i] = create_udp_exchange_v6(0x20 + i);
        TEST_ASSERT_NOT_NULL(udp[i], "Should create IPv6 UDP exchange");
        udp[i]->reputation_score = 3000;
    }

    uint32_t evicted = flow_table_v6_emergency_evict(4);
    TEST_ASSERT_EQ(4, evicted, "The IPv6 batch should be filled from evictable flows");
    for (uint32_t i = 0; i < 4; i++) {
        TEST_ASSERT(find_tcp_flow_v6(0x10 + i, 0x100) == protected_flows[i],
                    "Protected IPv6 flows should survive");
        TEST_ASSERT_NULL(find_flow_v6(0x20 + i, 0x100, IPPROTO_UDP), "The IPv6 UDP exchanges should be evicted");
    }

    flow_table_v6_cleanup();
}

// As create_one_way_established_flow(): SYN and ACK, no reply seen
static struct flow_entry_v6 *create_one_way_established_flow_v6(uint32_t client_host, uint32_t server_host) {
    struct packet_features_v6 pkt;
    bool created;

    create_test_features_v6(&pkt, client_host, server_host, 40000, 80, IPPROTO_TCP);
    pkt.tcp_flags = RTE_TCP_SYN_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN;
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&pkt, &created);
    if (!flow) {
        return NULL;
    }
    flow_table_v6_update(flow, &pkt);
    pkt.tcp_flags = RTE_TCP_ACK_FLAG;
    pkt.tcp_seq = TEST_CLIENT_ISN + 1;
    flow_table_v6_update(flow, &pkt);
    return flow;
}

void test_flow_table_v6_evict_keeps_lowest_scores(void) {
    // As test_flow_table_evict_keeps_lowest_scores: more evictable flows than
    // the 1024-entry candidate buffer, 28 one-way established among half-open
    // flows; a 1024 eviction must take half-open flows only
    for (uint32_t table = 0; table < 3; table++) {
        init_default_config_v6();
        default_config_v6.max_flows = 8192;
        flow_table_v6_init(&default_config_v6);

        uint32_t client_base = 0x100000 + (table << 16);
        uint32_t established = 0;
        for (uint32_t i = 0; i < 4096; i++) {
            struct flow_entry_v6 *flow;
            if (i % 146 == 73) {
                flow = create_one_way_established_flow_v6(client_base + i, 0x100);
                established++;
            } else {
                flow = create_half_open_flow_v6(client_base + i, 0x100);
            }
            TEST_ASSERT_NOT_NULL(flow, "Should create IPv6 flow");
        }
        TEST_ASSERT_EQ(28, established, "28 one-way established IPv6 flows");

        uint32_t evicted = flow_table_v6_emergency_evict(1024);
        TEST_ASSERT_EQ(1024, evicted, "A full IPv6 candidate buffer should be evicted");

        uint32_t established_left = 0;
        for (uint32_t i = 73; i < 4096; i += 146) {
            if (find_tcp_flow_v6(client_base + i, 0x100) != NULL) {
                established_left++;
            }
        }
        printf("  IPv6 table %u: %u of %u one-way established flows left\n",
               table, established_left, established);
        TEST_ASSERT_EQ(28, established_left,
                       "Only the lowest IPv6 scores (half-open flows) should be evicted");

        flow_table_v6_cleanup();
    }
}

void test_flow_table_v6_evict_rate_limited(void) {
    init_default_config_v6();
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    for (uint32_t i = 0; i < 16; i++) {
        TEST_ASSERT_NOT_NULL(create_udp_flow_v6(0x1000 + i), "Should create IPv6 flow");
    }

    // The first create on the full table evicts; the table is filled again
    // and the next create, inside the same 100 ms, must not evict again
    rte_delay_ms(EVICT_RATE_LIMIT_WAIT_MS);
    race_start();
    uint64_t start = rte_rdtsc();
    struct flow_entry_v6 *first = create_udp_flow_v6(0x2000);
    uint32_t refilled = 0;
    while (refilled < 64 && create_udp_flow_v6(0x3000 + refilled) != NULL) {
        refilled++;
    }
    uint32_t evictions_before = race_count(FLOW_SEAM_V6_EVICT);
    struct flow_entry_v6 *second = create_udp_flow_v6(0x4000);
    uint32_t evictions = race_count(FLOW_SEAM_V6_EVICT);
    uint64_t elapsed = rte_rdtsc() - start;
    race_stop();

    TEST_ASSERT_NOT_NULL(first, "The first create should evict and succeed");
    TEST_ASSERT_EQ(1, evictions_before, "One eviction should make room");
    if (elapsed < rte_get_tsc_hz() / 10) {
        TEST_ASSERT_NULL(second, "A second full-table create within 100 ms should fail");
        TEST_ASSERT_EQ(1, evictions, "The IPv6 eviction should run at most once per 100 ms");
    }

    flow_table_v6_cleanup();
}

// ==================== Round 4: IPv6 Guards Pinned Through Seams ====================

void test_flow_table_v6_aging_rechecks_entry(void) {
    init_default_config_v6();
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    // As test_flow_table_aging_rechecks_entry_long_idle: one half-open IPv6
    // flow last seen 120 s ago, past the SYN and the idle timeout, so that it
    // still looks expired once the eviction has claimed it; the only
    // eviction candidate
    struct flow_entry_v6 *old_flow = create_half_open_flow_v6(0x34, 0x100);
    TEST_ASSERT_NOT_NULL(old_flow, "Should create half-open IPv6 flow");
    old_flow->last_seen_tsc = rte_rdtsc() - 120 * rte_get_tsc_hz();

    // After aging chose the key and before its delete, an eviction deletes
    // the flow and a new SYN creates the key again on another entry
    v6_seam_client = 0x34;
    v6_seam_new_flow = NULL;
    v6_seam_evicted = 0;
    race_start();
    race_action[FLOW_SEAM_V6_AGE] = seam_v6_evict_and_recreate;
    uint32_t aged = flow_table_v6_age_flows();
    uint32_t calls = race_count(FLOW_SEAM_V6_AGE);
    race_stop();

    TEST_ASSERT_EQ(1, calls, "The IPv6 aging seam should run between choosing and deleting");
    TEST_ASSERT_EQ(1, v6_seam_evicted, "The IPv6 eviction should delete the stale flow");
    TEST_ASSERT_NOT_NULL(v6_seam_new_flow, "The key should be created again");
    TEST_ASSERT(v6_seam_new_flow != old_flow, "The new IPv6 flow should be on another entry");
    TEST_ASSERT(find_tcp_flow_v6(0x34, 0x100) == v6_seam_new_flow,
                "An IPv6 flow created after aging chose its key should not be aged");
    TEST_ASSERT_EQ(0, aged, "IPv6 aging should delete nothing: its key now maps to a new entry");

    TEST_ASSERT_EQ(0, v6_fill_rest_checks(v6_seam_new_flow, 0x40),
                   "Every other IPv6 entry should be allocatable exactly once");
    uint32_t occupancy = flow_table_v6_get_occupancy_percent();
    TEST_ASSERT_EQ(100, occupancy, "The IPv6 table should be full");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_aging_rechecks_expiry(void) {
    init_default_config_v6();
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    // As test_flow_table_aging_rechecks_expiry
    struct flow_entry_v6 *flow = create_half_open_flow_v6(0x34, 0x100);
    TEST_ASSERT_NOT_NULL(flow, "Should create half-open IPv6 flow");
    flow->last_seen_tsc = rte_rdtsc() - 20 * rte_get_tsc_hz();

    v6_seam_client = 0x34;
    race_start();
    race_action[FLOW_SEAM_V6_AGE] = seam_v6_refresh_flow;
    uint32_t aged = flow_table_v6_age_flows();
    uint32_t calls = race_count(FLOW_SEAM_V6_AGE);
    race_stop();

    TEST_ASSERT_EQ(1, calls, "The IPv6 aging seam should run between choosing and deleting");
    TEST_ASSERT_EQ(0, aged, "An IPv6 flow refreshed before its delete is no longer expired");
    TEST_ASSERT(find_tcp_flow_v6(0x34, 0x100) == flow, "The refreshed IPv6 flow should survive");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_aging_deletes_under_writer_lock(void) {
    init_default_config_v6();
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    struct flow_entry_v6 *flow = create_udp_flow_v6(0x1001);
    TEST_ASSERT_NOT_NULL(flow, "Should create IPv6 flow");
    flow->last_seen_tsc = rte_rdtsc() - 120 * rte_get_tsc_hz();

    race_start();
    uint32_t aged = flow_table_v6_age_flows();
    uint32_t calls = race_count(FLOW_SEAM_V6_AGE_DELETE);
    uint32_t locked = race_count_locked(FLOW_SEAM_V6_AGE_DELETE);
    race_stop();

    TEST_ASSERT_EQ(1, aged, "IPv6 aging should delete the idle flow");
    TEST_ASSERT_EQ(1, calls, "The IPv6 delete seam should run once, after the recheck");
    TEST_ASSERT_EQ(1, locked, "IPv6 aging should recheck and delete with the writer lock held");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_clear_deletes_under_writer_lock(void) {
    init_default_config_v6();
    flow_table_v6_init(&default_config_v6);

    for (uint32_t i = 0; i < 3; i++) {
        TEST_ASSERT_NOT_NULL(create_udp_flow_v6(0x1001 + i), "Should create IPv6 flow");
    }

    race_start();
    flow_table_v6_clear();
    uint32_t calls = race_count(FLOW_SEAM_V6_CLEAR_DELETE);
    uint32_t locked = race_count_locked(FLOW_SEAM_V6_CLEAR_DELETE);
    race_stop();

    TEST_ASSERT_EQ(3, calls, "The IPv6 clear's delete seam should run for each flow");
    TEST_ASSERT_EQ(3, locked, "IPv6 clear should look up and delete each key with the writer lock held");

    flow_table_v6_cleanup();
}

static struct flow_entry_v6 *pub_other_v6;
static struct packet_features_v6 pub_other_pkt_v6;

static void seam_other_creator_adds_v6(void) {
    bool created = false;
    pub_other_v6 = flow_table_v6_lookup_or_create(&pub_other_pkt_v6, &created);
    if (pub_other_v6 != NULL && created) {
        __atomic_store_n(&pub_other_v6->state, FLOW_STATE_INITIALIZING, __ATOMIC_RELEASE);
    } else {
        pub_other_v6 = NULL;
    }
}

static void seam_other_creator_publishes_v6(void) {
    if (pub_other_v6 != NULL) {
        __atomic_store_n(&pub_other_v6->state, FLOW_STATE_NEW, __ATOMIC_RELEASE);
    }
}

void test_flow_table_v6_create_waits_for_publication(void) {
    init_default_config_v6();
    flow_table_v6_init(&default_config_v6);

    // As test_flow_table_create_waits_for_publication
    struct packet_features_v6 syn;
    create_test_features_v6(&syn, 1, 0x100, 40000, 80, IPPROTO_TCP);
    syn.tcp_flags = RTE_TCP_SYN_FLAG;
    syn.tcp_seq = TEST_CLIENT_ISN;
    pub_other_pkt_v6 = syn;
    pub_other_v6 = NULL;

    race_start();
    race_action[FLOW_SEAM_V6_CREATE_MISSED] = seam_other_creator_adds_v6;
    race_action[FLOW_SEAM_V6_PUBLISH_WAIT] = seam_other_creator_publishes_v6;
    bool created = true;
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&syn, &created);
    uint8_t state_at_return = flow ? __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE) : 0xFF;
    uint32_t waits = race_count(FLOW_SEAM_V6_PUBLISH_WAIT);
    if (flow != NULL) {
        flow_table_v6_update(flow, &syn);
    }
    if (pub_other_v6 != NULL &&
        __atomic_load_n(&pub_other_v6->state, __ATOMIC_ACQUIRE) == FLOW_STATE_INITIALIZING) {
        __atomic_store_n(&pub_other_v6->state, FLOW_STATE_NEW, __ATOMIC_RELEASE);
    }
    uint8_t final_state = flow ? __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE) : 0xFF;
    race_stop();

    TEST_ASSERT_NOT_NULL(pub_other_v6, "The other lcore's IPv6 create should add the key");
    TEST_ASSERT(flow == pub_other_v6, "Both IPv6 creates should get the one flow");
    TEST_ASSERT(!created, "Only the other lcore created the IPv6 flow");
    TEST_ASSERT_EQ(1, waits, "The IPv6 create should wait for the other creator to publish");
    TEST_ASSERT_EQ(FLOW_STATE_NEW, state_at_return,
                   "An IPv6 create should return the flow only once it is published");
    TEST_ASSERT_EQ(FLOW_STATE_SYN_RECEIVED, final_state,
                   "The SYN should move the IPv6 flow, not be lost on an unpublished one");

    flow_table_v6_cleanup();
}

// ==================== Round 4: IPv6 Concurrent Writers ====================

// As the IPv4 mixed stress (test_flow_table_concurrent_create_evict_age): the
// IPv6 table now evicts on every lcore while lcore 0 ages
struct mixed_job_v6 {
    uint32_t worker;
    struct flow_entry_v6 *flows[MIXED_KEYS];   // NULL where the table was full
};
static struct mixed_job_v6 mixed_jobs_v6[STRESS_MAX_WORKERS];
static uint32_t mixed_aged_v6;

static int stress_mixed_job_v6(void *arg) {
    struct mixed_job_v6 *job = arg;
    struct packet_features_v6 pkt;
    bool created;

    stress_start_wait();
    for (uint32_t i = 0; i < MIXED_KEYS; i++) {
        created = false;
        create_test_features_v6(&pkt, stress_own_ip(job->worker, i), 0x100, 5000, 53, IPPROTO_UDP);
        struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&pkt, &created);
        job->flows[i] = created ? flow : NULL;
        if (i % 1000 == 999) {
            (void)flow_table_v6_emergency_evict(256);
        }
    }
    stress_finish();
    return 0;
}

static void mixed_main_step_v6(void) {
    mixed_aged_v6 += flow_table_v6_age_flows();
}

void test_flow_table_v6_concurrent_create_evict_age(void) {
    init_default_config_v6();
    default_config_v6.max_flows = MIXED_TABLE;
    default_config_v6.idle_timeout_sec = 1;
    flow_table_v6_init(&default_config_v6);

    // Expired flows for aging to delete while the workers create
    uint64_t idle_since = rte_rdtsc() - 5 * rte_get_tsc_hz();
    TEST_ASSERT_EQ(0, create_idle_udp_flows_v6(0x20000000, MIXED_EXPIRED, idle_since),
                   "Should create the expired IPv6 flows");

    void *args[STRESS_MAX_WORKERS];
    for (uint32_t w = 0; w < STRESS_MAX_WORKERS; w++) {
        memset(&mixed_jobs_v6[w], 0, sizeof(mixed_jobs_v6[w]));
        mixed_jobs_v6[w].worker = w;
        args[w] = &mixed_jobs_v6[w];
    }
    mixed_aged_v6 = 0;
    unsigned int jobs = stress_run(stress_mixed_job_v6, args, mixed_main_step_v6);

    // A key still held must map to the entry its creator got (nothing
    // creates a key twice), and the counts must add up
    uint32_t created = 0, held = 0, broken = 0, expired_held = 0;
    for (uint32_t w = 0; w < jobs; w++) {
        for (uint32_t i = 0; i < MIXED_KEYS; i++) {
            struct flow_entry_v6 *flow = find_flow_v6(stress_own_ip(w, i), 0x100, IPPROTO_UDP);
            created += (mixed_jobs_v6[w].flows[i] != NULL);
            if (flow != NULL) {
                held++;
                if (flow != mixed_jobs_v6[w].flows[i]) {
                    broken++;
                }
            }
        }
    }
    for (uint32_t i = 0; i < MIXED_EXPIRED; i++) {
        if (find_flow_v6(0x20000000 + i, 0x100, IPPROTO_UDP) != NULL) {
            expired_held++;
        }
    }
    struct flow_table_v6_stats stats;
    flow_table_v6_get_stats(&stats);
    printf("  %u workers: %u IPv6 created, %u held (and %u of the expired), %u off their entry; "
           "%lu creates, %lu deletes, %u aged by lcore 0\n",
           jobs, created, held, expired_held, broken, (unsigned long)stats.creates,
           (unsigned long)stats.deletes, mixed_aged_v6);
    fflush(stdout);
    TEST_ASSERT_EQ(0, broken, "An IPv6 flow should be found on the entry its creator got");
    TEST_ASSERT_EQ((uint64_t)(held + expired_held), stats.creates - stats.deletes,
                   "Every IPv6 create should be held or counted as deleted");

    // Aging still reaches every flow held: the occupancy bitmap it walks
    // covers every flow in the hash
    rte_delay_ms(1100);
    uint32_t aged_after = 0;
    for (int pass = 0; pass < 64; pass++) {
        aged_after += flow_table_v6_age_flows();
    }
    uint32_t occupancy = flow_table_v6_get_occupancy_percent();
    TEST_ASSERT_EQ(held + expired_held, aged_after, "IPv6 aging should reach every flow still held");
    TEST_ASSERT_EQ(0, occupancy, "No IPv6 flow should be left once all are idle");

    // No index leaked or handed out twice
    flow_table_v6_clear();
    uintptr_t *ptrs = malloc(MIXED_TABLE * sizeof(*ptrs));
    TEST_ASSERT_NOT_NULL(ptrs, "malloc should succeed");
    uint32_t n = 0;
    for (uint32_t i = 0; i < MIXED_TABLE; i++) {
        struct flow_entry_v6 *flow = create_udp_flow_v6(0x50000000 + i);
        if (flow != NULL) {
            ptrs[n++] = (uintptr_t)flow;
        }
    }
    uint32_t dups = count_duplicates(ptrs, n);
    free(ptrs);
    TEST_ASSERT_EQ(MIXED_TABLE, n, "A cleared IPv6 table should take max_flows flows");
    TEST_ASSERT_EQ(0, dups, "No IPv6 entry should be handed out twice");

    flow_table_v6_cleanup();
}

// As test_flow_table_evict_rate_limit_concurrent, for the IPv6 table: each
// round lcore 0 and the worker lcores find a full table at the same moment,
// and at most one of them may run the eviction
#define RATE_ROUNDS_V6 10

static void rate_limit_round_v6(uint32_t party, uint32_t r) {
    struct packet_features_v6 pkt;
    bool created;

    __atomic_fetch_add(&rate_arrived, 1, __ATOMIC_ACQ_REL);
    while (__atomic_load_n(&rate_arrived, __ATOMIC_ACQUIRE) <
           __atomic_load_n(&rate_parties, __ATOMIC_ACQUIRE) * r) {
        rte_pause();
    }
    create_test_features_v6(&pkt, 0x70000000 + (r << 4) + party, 0x100, 5000, 53, IPPROTO_UDP);
    (void)flow_table_v6_lookup_or_create(&pkt, &created);
    __atomic_fetch_add(&rate_finished, 1, __ATOMIC_ACQ_REL);
}

static int rate_limit_job_v6(void *arg) {
    uint32_t party = (uint32_t)(uintptr_t)arg;
    for (uint32_t r = 1; r <= RATE_ROUNDS_V6; r++) {
        while (__atomic_load_n(&rate_round, __ATOMIC_ACQUIRE) < r) {
            rte_pause();
        }
        rate_limit_round_v6(party, r);
    }
    return 0;
}

void test_flow_table_v6_evict_rate_limit_concurrent(void) {
    init_default_config_v6();
    default_config_v6.max_flows = 16;
    flow_table_v6_init(&default_config_v6);

    unsigned int lcores[STRESS_MAX_WORKERS];
    unsigned int lcore_id;
    uint32_t workers = 0;
    __atomic_store_n(&rate_round, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&rate_arrived, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&rate_finished, 0, __ATOMIC_RELEASE);
    uint32_t launch_failures = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (workers == STRESS_MAX_WORKERS) {
            break;
        }
        if (rte_eal_remote_launch(rate_limit_job_v6, (void *)(uintptr_t)(workers + 1), lcore_id) == 0) {
            lcores[workers++] = lcore_id;
        } else {
            launch_failures++;
        }
    }
    __atomic_store_n(&rate_parties, workers + 1, __ATOMIC_RELEASE);
    if (workers == 0) {
        printf("  NOTE: no worker lcore, lcore 0 races nobody\n");
        fflush(stdout);
    }

    race_start();
    uint32_t rounds_over = 0;
    for (uint32_t r = 1; r <= RATE_ROUNDS_V6; r++) {
        for (uint32_t i = 0; i < 64; i++) {
            if (create_udp_flow_v6(0x10000000 + (r << 8) + i) == NULL &&
                flow_table_v6_get_occupancy_percent() == 100) {
                break;
            }
        }
        rte_delay_ms(RATE_LIMIT_LAPSE_MS);
        uint32_t before = race_count(FLOW_SEAM_V6_EVICT);
        __atomic_store_n(&rate_round, r, __ATOMIC_RELEASE);
        rate_limit_round_v6(0, r);
        while (__atomic_load_n(&rate_finished, __ATOMIC_ACQUIRE) <
               __atomic_load_n(&rate_parties, __ATOMIC_ACQUIRE) * r) {
            rte_pause();
        }
        uint32_t evictions = race_count(FLOW_SEAM_V6_EVICT) - before;
        if (evictions > 1) {
            rounds_over++;
        }
    }
    race_stop();
    for (uint32_t k = 0; k < workers; k++) {
        rte_eal_wait_lcore(lcores[k]);
    }
    printf("  %u lcores, %u of %u rounds ran more than one IPv6 eviction\n",
           rate_parties, rounds_over, RATE_ROUNDS_V6);
    fflush(stdout);
    TEST_ASSERT_EQ(0, launch_failures, "rte_eal_remote_launch should succeed");
    TEST_ASSERT_EQ(0, rounds_over, "A full IPv6 table should run at most one eviction per 100 ms");

    flow_table_v6_cleanup();
}

// ==================== Main ====================

// Up to four lcores, each on its own CPU from this process's affinity mask
// (lcore 0 on the first, as "-l 0" had it). Lcore 0 runs every subtest; the
// others run only the multi-lcore subtests, on CPUs no thread shares.
static void build_lcore_map(char *buf, size_t len) {
    cpu_set_t set;
    unsigned int n = 0;
    size_t off = 0;

    if (sched_getaffinity(0, sizeof(set), &set) == 0) {
        for (int cpu = 0; cpu < CPU_SETSIZE && n < 4; cpu++) {
            if (!CPU_ISSET(cpu, &set)) {
                continue;
            }
            int w = snprintf(buf + off, len - off, "%s%u@%d", n ? "," : "", n, cpu);
            if (w < 0 || (size_t)w >= len - off) {
                break;
            }
            off += (size_t)w;
            n++;
        }
    }
    if (n == 0) {
        snprintf(buf, len, "0@0");
    }
}

int main(int argc, char **argv) {
    int ret;
    char lcore_map[64];

    build_lcore_map(lcore_map, sizeof(lcore_map));
    char *eal_args[] = {
        argv[0],
        "--lcores", lcore_map,
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

    test_filter = getenv("FLOW_TEST_FILTER");
    if (test_filter != NULL && test_filter[0] == '\0') {
        test_filter = NULL;
    }

    printf("\n========================================\n");
    printf("  Flow Table Unit Tests\n");
    printf("========================================\n\n");

    // Initialization tests
    RUN_TEST(test_flow_table_init_success);
    RUN_TEST(test_flow_table_init_large_capacity);
    RUN_TEST(test_flow_table_init_small_capacity);

    // Lookup and create tests
    RUN_TEST(test_flow_table_create_new_flow);
    RUN_TEST(test_flow_table_lookup_existing_flow);
    RUN_TEST(test_flow_table_lookup_only);

    // Canonical key tests
    RUN_TEST(test_flow_table_canonical_key_same_direction);
    RUN_TEST(test_flow_table_canonical_key_reverse_direction);
    RUN_TEST(test_flow_table_canonical_key_bidirectional);
    RUN_TEST(test_flow_table_canonical_key_same_ip);

    // Rate limiting tests
    RUN_TEST(test_flow_table_rate_limit_pps);
    RUN_TEST(test_flow_table_rate_limit_bps);
    RUN_TEST(test_flow_table_set_limits);

    // Flow update tests
    RUN_TEST(test_flow_table_update_counters);
    RUN_TEST(test_flow_table_update_bidirectional);

    // State machine tests
    RUN_TEST(test_flow_table_tcp_state_syn);
    RUN_TEST(test_flow_table_tcp_state_established);

    // Aging tests
    RUN_TEST(test_flow_table_aging_basic);
    RUN_TEST(test_flow_table_aging_keeps_active);
    RUN_TEST(test_flow_table_aging_pressure_small_table);
    RUN_TEST(test_flow_table_aging_reinit_after_batch_limit);

    // RST/FIN validation tests
    RUN_TEST(test_flow_table_rst_validation_valid);
    RUN_TEST(test_flow_table_rst_validation_spoofed);
    RUN_TEST(test_flow_table_rst_validation_no_peer_ack);
    RUN_TEST(test_flow_table_rst_no_flow);
    RUN_TEST(test_flow_table_rst_validation_given_flow);

    // Statistics tests
    RUN_TEST(test_flow_table_stats_basic);
    RUN_TEST(test_flow_table_stats_lookup_hits);

    // Table full tests
    RUN_TEST(test_flow_table_full);

    // Emergency eviction tests (after test_flow_table_full: see
    // EVICT_RATE_LIMIT_WAIT_MS)
    RUN_TEST(test_flow_table_evict_spares_established);
    RUN_TEST(test_flow_table_full_create_spares_established);
    RUN_TEST(test_flow_table_evict_only_established);
    RUN_TEST(test_flow_table_evict_blind_ack_not_protected);
    RUN_TEST(test_flow_table_evict_scores_bidirectional_udp);
    RUN_TEST(test_flow_table_evict_keeps_lowest_scores);
    RUN_TEST(test_flow_table_evict_rechecks_handshake);
    RUN_TEST(test_flow_table_evict_rechecks_entry);

    // Allocation across lcores
    RUN_TEST(test_flow_table_small_table_fills_across_lcores);

    // Clear tests
    RUN_TEST(test_flow_table_clear);

    // Utility tests
    RUN_TEST(test_flow_state_str);
    RUN_TEST(test_flow_state_str_every_state);

    // Non-EAL thread tests
    RUN_TEST(test_flow_table_non_eal_thread);
    RUN_TEST(test_flow_table_non_eal_leaves_lcore_cache);

    // IPv6 flow table tests
    RUN_TEST(test_flow_table_v6_aging_pressure_small_table);
    RUN_TEST(test_flow_table_v6_aging_reinit_after_batch_limit);
    RUN_TEST(test_flow_table_v6_rst_validation_no_peer_ack);
    RUN_TEST(test_flow_table_v6_rst_validation_given_flow);

    // Round 3: rechecks, capacity, mid-stream flows and pins (after the
    // eviction tests: see EVICT_RATE_LIMIT_WAIT_MS)
    RUN_TEST(test_flow_table_aging_rechecks_entry);
    RUN_TEST(test_flow_table_aging_rechecks_expiry);
    RUN_TEST(test_flow_table_evict_claim_spares_late_handshake);
    RUN_TEST(test_flow_table_aging_spares_flow_seen_after_pass_start);
    RUN_TEST(test_flow_table_rate_limit_window_clock_skew);
    RUN_TEST(test_flow_table_fills_to_max_flows);
    RUN_TEST(test_flow_table_evict_scores_midstream_tcp);
    RUN_TEST(test_flow_table_aging_keeps_midstream_tcp);
    RUN_TEST(test_flow_table_aging_pressure_cached_indices);
    RUN_TEST(test_flow_table_evict_skips_protected_when_choosing);
    RUN_TEST(test_flow_table_evict_takes_entry_from_pointer);

    // Round 3: statistics of registered and non-EAL threads
    RUN_TEST(test_flow_table_registered_lcore_stats);
    RUN_TEST(test_flow_table_non_eal_totals);
    RUN_TEST(test_flow_table_non_eal_stats_concurrent);

    // Round 3: IPv6 table
    RUN_TEST(test_flow_table_v6_fills_to_max_flows);
    RUN_TEST(test_flow_table_v6_aging_spares_flow_seen_after_pass_start);
    RUN_TEST(test_flow_table_v6_rate_limit_window_clock_skew);
    RUN_TEST(test_flow_table_v6_aging_keeps_midstream_tcp);
    RUN_TEST(test_flow_table_v6_aging_pressure_cached_indices);
    RUN_TEST(test_flow_table_v6_small_table_fills_across_lcores);
    RUN_TEST(test_flow_table_v6_registered_lcore_stats);
    RUN_TEST(test_flow_table_v6_non_eal_leaves_lcore_cache);
    RUN_TEST(test_flow_table_v6_non_eal_stats_concurrent);

    // Round 3: concurrent writers on several lcores
    RUN_TEST(test_flow_table_concurrent_creates);
    RUN_TEST(test_flow_table_concurrent_create_evict_age);
    RUN_TEST(test_flow_table_evict_rate_limit_concurrent);
    RUN_TEST(test_flow_table_v6_concurrent_creates);

    // Round 4: deferred reuse of deleted entries (readers' quiescent states)
    RUN_TEST(test_flow_table_reader_delays_reuse_after_aging);
    RUN_TEST(test_flow_table_reader_delays_reuse_after_eviction);
    RUN_TEST(test_flow_table_reader_on_another_thread_delays_reuse);
    RUN_TEST(test_flow_table_v6_reader_delays_reuse);
    RUN_TEST(test_flow_table_no_eviction_while_deleted_entries_wait);
    RUN_TEST(test_flow_table_limbo_returns_every_index);
    RUN_TEST(test_flow_table_concurrent_readers_keep_held_entries);

    // Round 4: the aging walk over the occupancy bitmap
    RUN_TEST(test_flow_table_aging_walk_resumes_after_last_flow);

    // Round 4: guards pinned through seams
    RUN_TEST(test_flow_table_aging_rechecks_entry_long_idle);
    RUN_TEST(test_flow_table_aging_deletes_under_writer_lock);
    RUN_TEST(test_flow_table_evict_claims_under_writer_lock);
    RUN_TEST(test_flow_table_clear_deletes_under_writer_lock);
    RUN_TEST(test_flow_table_create_waits_for_publication);
    RUN_TEST(test_flow_table_v6_aging_rechecks_entry);
    RUN_TEST(test_flow_table_v6_aging_rechecks_expiry);
    RUN_TEST(test_flow_table_v6_aging_deletes_under_writer_lock);
    RUN_TEST(test_flow_table_v6_clear_deletes_under_writer_lock);
    RUN_TEST(test_flow_table_v6_create_waits_for_publication);

    // Round 4: hash seed
    RUN_TEST(test_flow_table_hash_seed_random);
    RUN_TEST(test_flow_table_hash_seed_seam_sets_hash);
    RUN_TEST(test_flow_table_v6_hash_seed_random);

    // Round 4: counting a packet without trusting it, verified handshakes
    RUN_TEST(test_flow_table_count_packet_keeps_tcp_view);
    RUN_TEST(test_flow_table_v6_count_packet_keeps_tcp_view);
    RUN_TEST(test_flow_table_mark_handshake_verified);

    // Round 4: IPv6 emergency eviction
    RUN_TEST(test_flow_table_v6_full_table_evicts);
    RUN_TEST(test_flow_table_v6_evict_spares_established);
    RUN_TEST(test_flow_table_v6_evict_blind_ack_not_protected);
    RUN_TEST(test_flow_table_v6_evict_rechecks_entry);
    RUN_TEST(test_flow_table_v6_evict_claim_spares_late_handshake);
    RUN_TEST(test_flow_table_v6_evict_skips_protected_when_choosing);
    RUN_TEST(test_flow_table_v6_evict_keeps_lowest_scores);
    RUN_TEST(test_flow_table_v6_evict_rate_limited);
    RUN_TEST(test_flow_table_v6_concurrent_create_evict_age);
    RUN_TEST(test_flow_table_v6_evict_rate_limit_concurrent);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_run);
    printf("========================================\n\n");

    rte_eal_cleanup();

    return tests_failed > 0 ? 1 : 0;
}
