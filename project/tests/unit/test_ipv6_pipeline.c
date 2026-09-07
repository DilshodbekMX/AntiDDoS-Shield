/**
 * @file test_ipv6_pipeline.c
 * @brief Unit tests for Layer 1 IPv6 pipeline modules
 *
 * Tests cover:
 * 1. IPv6 whitelist/blacklist lookup (ip_lists_v6)
 * 2. IPv6 SYN cookie generate + validate round-trip (syn_proxy_v6)
 * 3. IPv6 geo-block lookup (geo_blocking_v6)
 * 4. IPv6 flow table create + lookup (flow_table_v6)
 *
 * ANT-25
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_cycles.h>

#include "../../layer1/tables/ip_lists_v6.h"
#include "../../layer1/tables/syn_proxy_v6.h"
#include "../../layer1/tables/geo_blocking_v6.h"
#include "../../layer1/tables/flow_table_v6.h"
#include "../../common/types.h"

// ==================== Test Framework ====================

static int tests_run    = 0;
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

#define TEST_ASSERT_NOT_NULL(ptr, msg) do { \
    if ((ptr) == NULL) { \
        printf("  FAIL: %s (got NULL, line %d)\n", msg, __LINE__); \
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

#define RUN_TEST(test_func) do { \
    printf("Running %s...\n", #test_func); \
    tests_run++; \
    test_func(); \
    if (tests_run - tests_failed - tests_passed == 1) { \
        tests_passed++; \
        printf("  PASS\n"); \
    } \
} while(0)

// ==================== Helper: IPv6 address construction ====================

/* Build an IPv6 byte array from 8 16-bit groups (host byte order input). */
static void make_ip6(uint8_t ip6[16],
                     uint16_t g0, uint16_t g1, uint16_t g2, uint16_t g3,
                     uint16_t g4, uint16_t g5, uint16_t g6, uint16_t g7)
{
    ip6[0]  = (g0 >> 8) & 0xff; ip6[1]  = g0 & 0xff;
    ip6[2]  = (g1 >> 8) & 0xff; ip6[3]  = g1 & 0xff;
    ip6[4]  = (g2 >> 8) & 0xff; ip6[5]  = g2 & 0xff;
    ip6[6]  = (g3 >> 8) & 0xff; ip6[7]  = g3 & 0xff;
    ip6[8]  = (g4 >> 8) & 0xff; ip6[9]  = g4 & 0xff;
    ip6[10] = (g5 >> 8) & 0xff; ip6[11] = g5 & 0xff;
    ip6[12] = (g6 >> 8) & 0xff; ip6[13] = g6 & 0xff;
    ip6[14] = (g7 >> 8) & 0xff; ip6[15] = g7 & 0xff;
}

/* Build a packet_features_v6 for an IPv6 TCP packet. */
static void make_features_v6(struct packet_features_v6 *f,
                              const uint8_t src[16], const uint8_t dst[16],
                              uint16_t sport, uint16_t dport, uint8_t proto)
{
    memset(f, 0, sizeof(*f));
    f->ip_version  = IP_VERSION_6;
    f->protocol    = proto;
    f->src_port    = sport;
    f->dst_port    = dport;
    f->packet_size = 100;
    f->timestamp_tsc = rte_rdtsc();
    memcpy(f->src_ip.v6, src, 16);
    memcpy(f->dst_ip.v6, dst, 16);
}

// ==================== 1. ip_lists_v6 tests ====================

static struct ip_lists_v6_config ip_lists_cfg = {
    .max_whitelist_entries = 1000,
    .max_blacklist_entries = 10000,
    .max_protected_entries = 100,
    .max_whitelist_cidrs   = 1000,
    .lpm6_rules  = 4096,
    .lpm6_tbl8s  = 512,
    .enforce_protected_ips = false,
};

void test_ip_lists_v6_whitelist_add_lookup(void)
{
    int ret = ip_lists_v6_init(&ip_lists_cfg);
    TEST_ASSERT_EQ(0, ret, "ip_lists_v6_init should succeed");

    uint8_t ip[16];
    make_ip6(ip, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);  /* 2001:db8::1 */

    /* Not in whitelist yet */
    TEST_ASSERT(!ip_whitelist_v6_lookup(ip), "IP should not be whitelisted yet");

    ret = ip_whitelist_v6_add(ip);
    TEST_ASSERT_EQ(0, ret, "ip_whitelist_v6_add should succeed");

    TEST_ASSERT(ip_whitelist_v6_lookup(ip), "IP should be whitelisted after add");
    TEST_ASSERT_EQ(1, (long)ip_whitelist_v6_count(), "Whitelist count should be 1");

    ip_lists_v6_cleanup();
}

void test_ip_lists_v6_whitelist_remove(void)
{
    ip_lists_v6_init(&ip_lists_cfg);

    uint8_t ip[16];
    make_ip6(ip, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);

    ip_whitelist_v6_add(ip);
    TEST_ASSERT(ip_whitelist_v6_lookup(ip), "IP should be whitelisted");

    int ret = ip_whitelist_v6_remove(ip);
    TEST_ASSERT_EQ(0, ret, "ip_whitelist_v6_remove should succeed");
    TEST_ASSERT(!ip_whitelist_v6_lookup(ip), "IP should not be whitelisted after remove");

    ip_lists_v6_cleanup();
}

void test_ip_lists_v6_blacklist_add_lookup(void)
{
    ip_lists_v6_init(&ip_lists_cfg);

    uint8_t ip[16];
    make_ip6(ip, 0xfe80, 0, 0, 0, 0, 0, 0, 1);  /* fe80::1 */

    TEST_ASSERT(!ip_blacklist_v6_lookup(ip), "IP should not be blacklisted yet");

    int ret = ip_blacklist_v6_add(ip);
    TEST_ASSERT_EQ(0, ret, "ip_blacklist_v6_add should succeed");

    TEST_ASSERT(ip_blacklist_v6_lookup(ip), "IP should be blacklisted after add");
    TEST_ASSERT_EQ(1, (long)ip_blacklist_v6_count(), "Blacklist count should be 1");

    ip_lists_v6_cleanup();
}

void test_ip_lists_v6_blacklist_remove(void)
{
    ip_lists_v6_init(&ip_lists_cfg);

    uint8_t ip[16];
    make_ip6(ip, 0xfe80, 0, 0, 0, 0, 0, 0, 2);

    ip_blacklist_v6_add(ip);
    ip_blacklist_v6_remove(ip);
    TEST_ASSERT(!ip_blacklist_v6_lookup(ip), "IP should not be blacklisted after remove");

    ip_lists_v6_cleanup();
}

void test_ip_lists_v6_distinct_whitelist_blacklist(void)
{
    ip_lists_v6_init(&ip_lists_cfg);

    uint8_t wl_ip[16], bl_ip[16];
    make_ip6(wl_ip, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 0xa);
    make_ip6(bl_ip, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 0xb);

    ip_whitelist_v6_add(wl_ip);
    ip_blacklist_v6_add(bl_ip);

    TEST_ASSERT( ip_whitelist_v6_lookup(wl_ip), "wl_ip should be in whitelist");
    TEST_ASSERT(!ip_blacklist_v6_lookup(wl_ip), "wl_ip should NOT be in blacklist");
    TEST_ASSERT(!ip_whitelist_v6_lookup(bl_ip), "bl_ip should NOT be in whitelist");
    TEST_ASSERT( ip_blacklist_v6_lookup(bl_ip), "bl_ip should be in blacklist");

    ip_lists_v6_cleanup();
}

void test_ip_lists_v6_clear(void)
{
    ip_lists_v6_init(&ip_lists_cfg);

    uint8_t ip1[16], ip2[16];
    make_ip6(ip1, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    make_ip6(ip2, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);

    ip_whitelist_v6_add(ip1);
    ip_whitelist_v6_add(ip2);
    TEST_ASSERT_EQ(2, (long)ip_whitelist_v6_count(), "Should have 2 whitelist entries");

    ip_whitelist_v6_clear();
    TEST_ASSERT_EQ(0, (long)ip_whitelist_v6_count(), "Whitelist should be empty after clear");
    TEST_ASSERT(!ip_whitelist_v6_lookup(ip1), "ip1 should not be whitelisted after clear");

    ip_lists_v6_cleanup();
}

// ==================== 2. syn_proxy_v6 cookie tests ====================

static struct syn_proxy_config syn_cfg = {
    .max_connections      = 4096,
    .connect_timeout_ms   = 5000,
    .idle_timeout_sec     = 60,
    .secret               = 0xDEADBEEF,
    .secret_rotation_sec  = 300,
    .enabled              = true,
    .stateless_threshold_pps = 100000,
    .stateful_threshold_pps  = 10000,
    .mode_switch_delay_ms    = 1000,
};

void test_syn_cookie_v6_generate_validate(void)
{
    int ret = syn_proxy_v6_init(&syn_cfg);
    TEST_ASSERT_EQ(0, ret, "syn_proxy_v6_init should succeed");

    uint8_t client_ip[16], server_ip[16];
    make_ip6(client_ip, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    make_ip6(server_ip, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);

    uint16_t client_port = 12345;
    uint16_t server_port = 80;
    uint32_t client_isn  = 0x12345678;
    uint16_t mss         = 1460;

    uint32_t cookie = syn_cookie_v6_generate(client_ip, server_ip,
                                             client_port, server_port,
                                             client_isn, mss);

    /* cookie_ack = cookie + 1 (client echoes back in ACK) */
    uint32_t cookie_ack = cookie + 1;
    uint16_t mss_out    = 0;

    bool valid = syn_cookie_v6_validate(client_ip, server_ip,
                                        client_port, server_port,
                                        client_isn, cookie_ack, &mss_out);

    TEST_ASSERT(valid, "SYN cookie should be valid for correct ACK");
    TEST_ASSERT(mss_out > 0, "Decoded MSS should be non-zero");

    syn_proxy_v6_cleanup();
}

void test_syn_cookie_v6_wrong_ack_fails(void)
{
    syn_proxy_v6_init(&syn_cfg);

    uint8_t client_ip[16], server_ip[16];
    make_ip6(client_ip, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 3);
    make_ip6(server_ip, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 4);

    uint32_t client_isn = 0xAABBCCDD;
    uint16_t mss_out    = 0;

    uint32_t cookie = syn_cookie_v6_generate(client_ip, server_ip,
                                             54321, 443, client_isn, 1460);

    /* Wrong ack: off by 2 instead of 1 */
    bool valid = syn_cookie_v6_validate(client_ip, server_ip,
                                        54321, 443, client_isn,
                                        cookie + 2, &mss_out);
    TEST_ASSERT(!valid, "Cookie with wrong ACK number should be invalid");

    syn_proxy_v6_cleanup();
}

void test_syn_cookie_v6_wrong_ip_fails(void)
{
    syn_proxy_v6_init(&syn_cfg);

    uint8_t client_ip[16], server_ip[16], attacker_ip[16];
    make_ip6(client_ip,   0x2001, 0x0db8, 0, 0, 0, 0, 0, 5);
    make_ip6(server_ip,   0x2001, 0x0db8, 0, 0, 0, 0, 0, 6);
    make_ip6(attacker_ip, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 7);

    uint32_t client_isn = 0x11223344;
    uint16_t mss_out    = 0;

    uint32_t cookie = syn_cookie_v6_generate(client_ip, server_ip,
                                             9999, 80, client_isn, 1460);

    /* Replay cookie from a different source IP */
    bool valid = syn_cookie_v6_validate(attacker_ip, server_ip,
                                        9999, 80, client_isn,
                                        cookie + 1, &mss_out);
    TEST_ASSERT(!valid, "Cookie replayed from different IP should be invalid");

    syn_proxy_v6_cleanup();
}

void test_syn_proxy_v6_enabled(void)
{
    syn_proxy_v6_init(&syn_cfg);
    TEST_ASSERT(syn_proxy_v6_is_enabled(), "SYN proxy should be enabled after init");
    syn_proxy_v6_cleanup();
}

// ==================== 3. geo_blocking_v6 tests ====================

/* country_code_t is uint16_t, e.g. "CN" = ('C'<<8)|'N' = 0x434E */
#define CC(a, b) ((country_code_t)(((uint16_t)(a) << 8) | (uint16_t)(b)))

static struct geo_config geo_cfg_cn_block = {
    .enabled       = true,
    .mode          = GEO_MODE_BLACKLIST,
    .log_blocked   = false,
    .country_count = 1,
    .countries     = { CC('C','N') },
};

void test_geo_blocking_v6_init_cleanup(void)
{
    int ret = geo_blocking_v6_init(&geo_cfg_cn_block);
    TEST_ASSERT_EQ(0, ret, "geo_blocking_v6_init should succeed");
    geo_blocking_v6_cleanup();
}

void test_geo_blocking_v6_blocked_prefix(void)
{
    geo_blocking_v6_init(&geo_cfg_cn_block);

    /* Add a test prefix: 2001:db8::/32 -> CN */
    int ret = geo_add_prefix_v6_str("2001:db8::/32", "CN");
    TEST_ASSERT_EQ(0, ret, "geo_add_prefix_v6_str should succeed");

    /* An IP inside 2001:db8::/32 should be blocked */
    uint8_t cn_ip[16];
    make_ip6(cn_ip, 0x2001, 0x0db8, 0x1234, 0, 0, 0, 0, 1);
    TEST_ASSERT(geo_should_block_v6(cn_ip), "IP in CN prefix should be blocked");

    geo_blocking_v6_cleanup();
}

void test_geo_blocking_v6_allowed_ip(void)
{
    geo_blocking_v6_init(&geo_cfg_cn_block);

    /* Add CN prefix */
    geo_add_prefix_v6_str("2001:db8::/32", "CN");

    /* An IP outside the CN prefix should not be blocked */
    uint8_t us_ip[16];
    make_ip6(us_ip, 0x2607, 0xf8b0, 0, 0, 0, 0, 0, 1);  /* Google-ish: 2607:f8b0::1 */
    TEST_ASSERT(!geo_should_block_v6(us_ip), "IP outside blocked prefix should be allowed");

    geo_blocking_v6_cleanup();
}

void test_geo_blocking_v6_get_country(void)
{
    geo_blocking_v6_init(&geo_cfg_cn_block);
    geo_add_prefix_v6_str("2001:db8::/32", "CN");

    uint8_t cn_ip[16];
    make_ip6(cn_ip, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 42);

    country_code_t cc = geo_get_country_v6(cn_ip);
    TEST_ASSERT_EQ(CC('C','N'), cc, "Country should be CN for prefix 2001:db8::/32");

    geo_blocking_v6_cleanup();
}

// ==================== 4. flow_table_v6 tests ====================

static struct flow_table_v6_config ft6_cfg = {
    .max_flows          = 4096,
    .idle_timeout_sec   = 60,
    .syn_timeout_sec    = 10,
    .default_pps_limit  = 0,
    .default_bps_limit  = 0,
    .enable_syn_protection = true,
    .aging_scan_limit   = 1024,
};

void test_flow_table_v6_init(void)
{
    int ret = flow_table_v6_init(&ft6_cfg);
    TEST_ASSERT_EQ(0, ret, "flow_table_v6_init should succeed");
    flow_table_v6_cleanup();
}

void test_flow_table_v6_create_new_flow(void)
{
    flow_table_v6_init(&ft6_cfg);

    uint8_t src[16], dst[16];
    make_ip6(src, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    make_ip6(dst, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);

    struct packet_features_v6 features;
    make_features_v6(&features, src, dst, 12345, 80, IPPROTO_TCP);

    bool created = false;
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&features, &created);

    TEST_ASSERT_NOT_NULL(flow, "Should create new IPv6 flow");
    TEST_ASSERT(created, "created flag should be true for new flow");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_lookup_existing_flow(void)
{
    flow_table_v6_init(&ft6_cfg);

    uint8_t src[16], dst[16];
    make_ip6(src, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 3);
    make_ip6(dst, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 4);

    struct packet_features_v6 f1, f2;
    make_features_v6(&f1, src, dst, 54321, 443, IPPROTO_TCP);
    make_features_v6(&f2, src, dst, 54321, 443, IPPROTO_TCP);

    bool created1 = false, created2 = false;
    struct flow_entry_v6 *flow1 = flow_table_v6_lookup_or_create(&f1, &created1);
    struct flow_entry_v6 *flow2 = flow_table_v6_lookup_or_create(&f2, &created2);

    TEST_ASSERT_NOT_NULL(flow1, "First lookup should create a flow");
    TEST_ASSERT(created1, "First lookup should set created=true");
    TEST_ASSERT_NOT_NULL(flow2, "Second lookup should find the flow");
    TEST_ASSERT(!created2, "Second lookup should set created=false");
    TEST_ASSERT(flow1 == flow2, "Both lookups should return the same flow pointer");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_lookup_only(void)
{
    flow_table_v6_init(&ft6_cfg);

    uint8_t src[16], dst[16];
    make_ip6(src, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 5);
    make_ip6(dst, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 6);

    struct packet_features_v6 features;
    make_features_v6(&features, src, dst, 11111, 8080, IPPROTO_TCP);

    /* Lookup without create -- should return NULL */
    struct flow_entry_v6 *missing = flow_table_v6_lookup(&features);
    TEST_ASSERT_NULL(missing, "Lookup of non-existent flow should return NULL");

    /* Create, then lookup should succeed */
    bool created = false;
    flow_table_v6_lookup_or_create(&features, &created);
    struct flow_entry_v6 *found = flow_table_v6_lookup(&features);
    TEST_ASSERT_NOT_NULL(found, "Lookup should find flow after creation");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_bidirectional(void)
{
    flow_table_v6_init(&ft6_cfg);

    uint8_t lo[16], hi[16];
    /* lo < hi lexicographically */
    make_ip6(lo, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    make_ip6(hi, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);

    /* Forward: lo -> hi */
    struct packet_features_v6 fwd, rev;
    make_features_v6(&fwd, lo, hi, 22222, 80, IPPROTO_TCP);
    /* Reverse: hi -> lo */
    make_features_v6(&rev, hi, lo, 80, 22222, IPPROTO_TCP);

    bool c1, c2;
    struct flow_entry_v6 *flow_fwd = flow_table_v6_lookup_or_create(&fwd, &c1);
    struct flow_entry_v6 *flow_rev = flow_table_v6_lookup_or_create(&rev, &c2);

    TEST_ASSERT_NOT_NULL(flow_fwd, "Forward flow should be created");
    TEST_ASSERT(c1, "Forward flow should be new");
    TEST_ASSERT_NOT_NULL(flow_rev, "Reverse packet should find the same flow");
    TEST_ASSERT(!c2, "Reverse packet should NOT create a new flow");
    TEST_ASSERT(flow_fwd == flow_rev, "Forward and reverse should map to the same flow entry");

    flow_table_v6_cleanup();
}

void test_flow_table_v6_stats(void)
{
    flow_table_v6_init(&ft6_cfg);

    uint8_t src[16], dst[16];
    make_ip6(src, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 9);
    make_ip6(dst, 0x2001, 0x0db8, 0, 0, 0, 0, 0, 10);

    struct packet_features_v6 features;
    make_features_v6(&features, src, dst, 33333, 53, IPPROTO_UDP);

    bool created = false;
    flow_table_v6_lookup_or_create(&features, &created);  /* create */
    flow_table_v6_lookup_or_create(&features, &created);  /* hit */
    flow_table_v6_lookup_or_create(&features, &created);  /* hit */

    struct flow_table_v6_stats stats;
    flow_table_v6_get_stats(&stats);

    TEST_ASSERT(stats.creates >= 1,     "Should have at least 1 create");
    TEST_ASSERT(stats.lookup_hits >= 2, "Should have at least 2 lookup hits");

    flow_table_v6_cleanup();
}

// ==================== Main ====================

int main(int argc __attribute__((unused)), char **argv)
{
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

    int ret = rte_eal_init(eal_argc, eal_args);
    if (ret < 0) {
        fprintf(stderr, "EAL init failed (missing DPDK permissions / runtime directory) -- skipping test\n");
        return 77;
    }

    printf("\n========================================\n");
    printf("  IPv6 Pipeline Unit Tests (ANT-25)\n");
    printf("========================================\n\n");

    /* --- ip_lists_v6 --- */
    printf("--- ip_lists_v6 ---\n");
    RUN_TEST(test_ip_lists_v6_whitelist_add_lookup);
    RUN_TEST(test_ip_lists_v6_whitelist_remove);
    RUN_TEST(test_ip_lists_v6_blacklist_add_lookup);
    RUN_TEST(test_ip_lists_v6_blacklist_remove);
    RUN_TEST(test_ip_lists_v6_distinct_whitelist_blacklist);
    RUN_TEST(test_ip_lists_v6_clear);

    /* --- syn_proxy_v6 --- */
    printf("\n--- syn_proxy_v6 cookie round-trip ---\n");
    RUN_TEST(test_syn_proxy_v6_enabled);
    RUN_TEST(test_syn_cookie_v6_generate_validate);
    RUN_TEST(test_syn_cookie_v6_wrong_ack_fails);
    RUN_TEST(test_syn_cookie_v6_wrong_ip_fails);

    /* --- geo_blocking_v6 --- */
    printf("\n--- geo_blocking_v6 ---\n");
    RUN_TEST(test_geo_blocking_v6_init_cleanup);
    RUN_TEST(test_geo_blocking_v6_blocked_prefix);
    RUN_TEST(test_geo_blocking_v6_allowed_ip);
    RUN_TEST(test_geo_blocking_v6_get_country);

    /* --- flow_table_v6 --- */
    printf("\n--- flow_table_v6 ---\n");
    RUN_TEST(test_flow_table_v6_init);
    RUN_TEST(test_flow_table_v6_create_new_flow);
    RUN_TEST(test_flow_table_v6_lookup_existing_flow);
    RUN_TEST(test_flow_table_v6_lookup_only);
    RUN_TEST(test_flow_table_v6_bidirectional);
    RUN_TEST(test_flow_table_v6_stats);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_run);
    printf("========================================\n\n");

    rte_eal_cleanup();

    return tests_failed > 0 ? 1 : 0;
}
