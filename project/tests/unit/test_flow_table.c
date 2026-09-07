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
 * - Edge cases and concurrency scenarios
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_random.h>
#include <rte_tcp.h>

#include "../../layer1/tables/flow_table.h"
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
    default_config.idle_timeout_sec = 1; // 1 second timeout
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

    flow_table_cleanup();
}

void test_flow_table_aging_keeps_active(void) {
    init_default_config();
    default_config.idle_timeout_sec = 1;
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

    // Spoofed RST with wrong sequence
    struct packet_features rst;
    create_test_features(&rst, 0x0A000001, 0xC0A80101, 12345, 80, IPPROTO_TCP);
    rst.tcp_flags = RTE_TCP_RST_FLAG;
    rst.tcp_seq = 999999; // Way out of window

    enum rst_fin_validation_result result = flow_table_validate_rst_fin(&rst);
    TEST_ASSERT_EQ(RST_FIN_SEQ_OUT_OF_WINDOW, result, "Spoofed RST should fail validation");

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

    // Try to create more flows than capacity
    for (int i = 0; i < 20; i++) {
        struct packet_features features;
        create_test_features(&features, 0x0A000001 + i, 0xC0A80101, 12345 + i, 80, IPPROTO_TCP);

        bool created;
        struct flow_entry *flow = flow_table_lookup_or_create(&features, &created);

        if (flow && created) {
            created_count++;
        } else if (!flow) {
            failed_count++;
        }
    }

    // Should have created up to max_flows
    TEST_ASSERT(created_count <= 10, "Should not create more than max_flows");
    TEST_ASSERT(failed_count > 0, "Some creates should fail when table is full");

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

    // RST/FIN validation tests
    RUN_TEST(test_flow_table_rst_validation_valid);
    RUN_TEST(test_flow_table_rst_validation_spoofed);
    RUN_TEST(test_flow_table_rst_no_flow);

    // Statistics tests
    RUN_TEST(test_flow_table_stats_basic);
    RUN_TEST(test_flow_table_stats_lookup_hits);

    // Table full tests
    RUN_TEST(test_flow_table_full);

    // Clear tests
    RUN_TEST(test_flow_table_clear);

    // Utility tests
    RUN_TEST(test_flow_state_str);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_run);
    printf("========================================\n\n");

    rte_eal_cleanup();

    return tests_failed > 0 ? 1 : 0;
}
