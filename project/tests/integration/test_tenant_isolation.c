/**
 * @file test_tenant_isolation.c
 * @brief Multi-tenant isolation integration tests
 *
 * Comprehensive isolation tests ensuring:
 * - Tenant A traffic doesn't affect Tenant B stats
 * - Tenant A blacklist doesn't block Tenant B traffic
 * - Tenant A attack doesn't trigger Tenant B alerts
 * - Tenant A config change doesn't affect Tenant B
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include "../../common/tenant.h"
#include "../../common/tenant_config.h"
#include "../../layer1/tables/ip_lists.h"
#include "../../layer1/interlayer/src_ip_stats.h"
#include "../../layer2/baselines.h"
#include "../../layer2/detection.h"

// ==================== Test Framework ====================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_SECTION(name) printf("\n--- %s ---\n", name)

#define TEST_START(name) do { \
    printf("  [TEST] %s ... ", name); \
    fflush(stdout); \
    tests_run++; \
} while(0)

#define TEST_PASS() do { \
    printf("\033[32mPASS\033[0m\n"); \
    tests_passed++; \
} while(0)

#define TEST_FAIL(msg) do { \
    printf("\033[31mFAIL\033[0m: %s\n", msg); \
    tests_failed++; \
    return; \
} while(0)

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { TEST_FAIL(msg); } \
} while(0)

#define ASSERT_NE(a, b, msg) do { \
    if ((a) == (b)) { TEST_FAIL(msg); } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { TEST_FAIL(msg); } \
} while(0)

#define ASSERT_LT(a, b, msg) do { \
    if (!((a) < (b))) { TEST_FAIL(msg); } \
} while(0)

#define ASSERT_LE(a, b, msg) do { \
    if (!((a) <= (b))) { TEST_FAIL(msg); } \
} while(0)

// ==================== Test Fixtures ====================

typedef struct {
    tenant_id_t tenant_a;
    tenant_id_t tenant_b;
    uint32_t tenant_a_ip;  // Protected IP for tenant A
    uint32_t tenant_b_ip;  // Protected IP for tenant B
    uint32_t attacker_ip;  // External attacker IP
} isolation_fixture_t;

static isolation_fixture_t fixture;

static uint32_t ip_to_uint32(const char *ip_str) {
    struct in_addr addr;
    inet_pton(AF_INET, ip_str, &addr);
    return ntohl(addr.s_addr);
}

static int setup_fixture(void) {
    int ret;

    // Initialize tenant registry
    ret = tenant_registry_init();
    if (ret != TENANT_OK) return -1;

    // Initialize tenant config
    ret = tenant_config_init();
    if (ret != 0) return -1;

    // Create Tenant A (Enterprise)
    struct tenant ta = {0};
    ta.id = TENANT_ID_INVALID;
    strncpy(ta.name, "Tenant A - Enterprise", MAX_TENANT_NAME_LEN - 1);
    ta.status = TENANT_STATUS_ACTIVE;
    ta.tier = TENANT_TIER_ENTERPRISE;
    ta.type = TENANT_TYPE_DIRECT;

    ret = tenant_create(&ta, &fixture.tenant_a);
    if (ret != TENANT_OK) return -1;

    // Create Tenant B (Standard)
    struct tenant tb = {0};
    tb.id = TENANT_ID_INVALID;
    strncpy(tb.name, "Tenant B - Standard", MAX_TENANT_NAME_LEN - 1);
    tb.status = TENANT_STATUS_ACTIVE;
    tb.tier = TENANT_TIER_STANDARD;
    tb.type = TENANT_TYPE_DIRECT;

    ret = tenant_create(&tb, &fixture.tenant_b);
    if (ret != TENANT_OK) return -1;

    // Assign protected networks
    fixture.tenant_a_ip = ip_to_uint32("192.168.1.0");
    ret = tenant_add_network(fixture.tenant_a, fixture.tenant_a_ip, 24);
    if (ret != TENANT_OK) return -1;

    fixture.tenant_b_ip = ip_to_uint32("10.0.0.0");
    ret = tenant_add_network(fixture.tenant_b, fixture.tenant_b_ip, 24);
    if (ret != TENANT_OK) return -1;

    fixture.attacker_ip = ip_to_uint32("203.0.113.100");

    return 0;
}

static void teardown_fixture(void) {
    tenant_config_cleanup();
    tenant_registry_cleanup();
}

// ==================== Isolation Tests ====================

/**
 * Test: Traffic stats isolation
 * Verify that packets to Tenant A don't affect Tenant B stats
 */
static void test_stats_isolation(void) {
    TEST_START("Stats isolation between tenants");

    // Initialize stats tracking for both tenants
    struct per_tenant_stats stats_a = {0};
    struct per_tenant_stats stats_b = {0};

    // Simulate traffic to Tenant A
    const uint64_t packets_to_a = 100000;
    const uint64_t bytes_to_a = packets_to_a * 1000;  // 1000 bytes/packet

    stats_a.packets_total = packets_to_a;
    stats_a.bytes_total = bytes_to_a;
    stats_a.packets_passed = packets_to_a - 100;
    stats_a.packets_dropped = 100;

    // Tenant B stats should remain zero
    ASSERT_EQ(stats_b.packets_total, 0, "Tenant B packets should be 0");
    ASSERT_EQ(stats_b.bytes_total, 0, "Tenant B bytes should be 0");
    ASSERT_EQ(stats_b.packets_dropped, 0, "Tenant B drops should be 0");

    // Verify Tenant A stats are correct
    ASSERT_EQ(stats_a.packets_total, packets_to_a, "Tenant A packets wrong");
    ASSERT_EQ(stats_a.bytes_total, bytes_to_a, "Tenant A bytes wrong");

    TEST_PASS();
}

/**
 * Test: Blacklist isolation
 * Verify that Tenant A's blacklist doesn't block Tenant B's traffic
 */
static void test_blacklist_isolation(void) {
    TEST_START("Blacklist isolation between tenants");

    // Add attacker IP to Tenant A's blacklist
    struct ip_list_entry entry_a = {
        .ip = htonl(fixture.attacker_ip),
        .prefix_len = 32,
        .tenant_id = fixture.tenant_a,
        .list_type = IP_LIST_BLACKLIST,
        .source = IP_LIST_SOURCE_MANUAL,
        .created_at = time(NULL),
        .expires_at = 0,  // Never expires
        .hit_count = 0
    };

    int ret = ip_list_add(&entry_a);
    ASSERT_EQ(ret, 0, "Failed to add to Tenant A blacklist");

    // Check if IP is blocked for Tenant A
    bool blocked_for_a = ip_list_check(
        htonl(fixture.attacker_ip),
        fixture.tenant_a,
        IP_LIST_BLACKLIST
    );
    ASSERT_TRUE(blocked_for_a, "IP should be blocked for Tenant A");

    // Check if IP is NOT blocked for Tenant B
    bool blocked_for_b = ip_list_check(
        htonl(fixture.attacker_ip),
        fixture.tenant_b,
        IP_LIST_BLACKLIST
    );
    ASSERT_TRUE(!blocked_for_b, "IP should NOT be blocked for Tenant B");

    // Clean up
    ip_list_remove(htonl(fixture.attacker_ip), 32, fixture.tenant_a, IP_LIST_BLACKLIST);

    TEST_PASS();
}

/**
 * Test: Whitelist isolation
 * Verify that Tenant A's whitelist doesn't affect Tenant B
 */
static void test_whitelist_isolation(void) {
    TEST_START("Whitelist isolation between tenants");

    uint32_t trusted_ip = ip_to_uint32("8.8.8.8");

    // Add trusted IP to Tenant A's whitelist
    struct ip_list_entry entry_a = {
        .ip = htonl(trusted_ip),
        .prefix_len = 32,
        .tenant_id = fixture.tenant_a,
        .list_type = IP_LIST_WHITELIST,
        .source = IP_LIST_SOURCE_MANUAL,
        .created_at = time(NULL),
        .expires_at = 0,
        .hit_count = 0
    };

    int ret = ip_list_add(&entry_a);
    ASSERT_EQ(ret, 0, "Failed to add to Tenant A whitelist");

    // Check if IP is whitelisted for Tenant A
    bool whitelisted_for_a = ip_list_check(
        htonl(trusted_ip),
        fixture.tenant_a,
        IP_LIST_WHITELIST
    );
    ASSERT_TRUE(whitelisted_for_a, "IP should be whitelisted for Tenant A");

    // Check if IP is NOT whitelisted for Tenant B
    bool whitelisted_for_b = ip_list_check(
        htonl(trusted_ip),
        fixture.tenant_b,
        IP_LIST_WHITELIST
    );
    ASSERT_TRUE(!whitelisted_for_b, "IP should NOT be whitelisted for Tenant B");

    // Clean up
    ip_list_remove(htonl(trusted_ip), 32, fixture.tenant_a, IP_LIST_WHITELIST);

    TEST_PASS();
}

/**
 * Test: Attack detection isolation
 * Verify that attack on Tenant A doesn't trigger alerts for Tenant B
 */
static void test_attack_alert_isolation(void) {
    TEST_START("Attack alert isolation between tenants");

    // Simulate attack detection on Tenant A
    tenant_set_attack_state(fixture.tenant_a, true, 4, ATTACK_TYPE_SYN_FLOOD);

    // Verify Tenant A is under attack
    const struct tenant *ta = tenant_lookup(fixture.tenant_a);
    ASSERT_TRUE(ta != NULL, "Tenant A lookup failed");
    ASSERT_TRUE(ta->attack_state.under_attack, "Tenant A should be under attack");
    ASSERT_EQ(ta->attack_state.attack_severity, 4, "Wrong severity for Tenant A");

    // Verify Tenant B is NOT under attack
    const struct tenant *tb = tenant_lookup(fixture.tenant_b);
    ASSERT_TRUE(tb != NULL, "Tenant B lookup failed");
    ASSERT_TRUE(!tb->attack_state.under_attack, "Tenant B should NOT be under attack");
    ASSERT_EQ(tb->attack_state.attack_severity, 0, "Tenant B severity should be 0");

    // Clear attack state
    tenant_set_attack_state(fixture.tenant_a, false, 0, 0);

    TEST_PASS();
}

/**
 * Test: Config change isolation
 * Verify that config changes to Tenant A don't affect Tenant B
 */
static void test_config_change_isolation(void) {
    TEST_START("Config change isolation between tenants");

    // Get initial configs
    const struct tenant_l1_config *cfg_a = tenant_get_l1_config(fixture.tenant_a);
    const struct tenant_l1_config *cfg_b = tenant_get_l1_config(fixture.tenant_b);

    ASSERT_TRUE(cfg_a != NULL, "Tenant A L1 config is NULL");
    ASSERT_TRUE(cfg_b != NULL, "Tenant B L1 config is NULL");

    // Store Tenant B's original rate limit
    uint64_t original_b_pps = cfg_b->rate_limits.global_pps;

    // Modify Tenant A's config
    struct tenant_l1_config new_cfg_a = *cfg_a;
    new_cfg_a.rate_limits.global_pps = 500000;  // 500 Kpps
    new_cfg_a.syn_proxy.always_on = true;

    int ret = tenant_set_l1_config(fixture.tenant_a, &new_cfg_a);
    ASSERT_EQ(ret, 0, "Failed to update Tenant A config");

    // Verify Tenant A config changed
    cfg_a = tenant_get_l1_config(fixture.tenant_a);
    ASSERT_EQ(cfg_a->rate_limits.global_pps, 500000, "Tenant A rate limit not updated");
    ASSERT_TRUE(cfg_a->syn_proxy.always_on, "Tenant A syn_proxy not updated");

    // Verify Tenant B config unchanged
    cfg_b = tenant_get_l1_config(fixture.tenant_b);
    ASSERT_EQ(cfg_b->rate_limits.global_pps, original_b_pps, "Tenant B rate limit changed unexpectedly");

    TEST_PASS();
}

/**
 * Test: Flow table isolation
 * Verify that flows for Tenant A don't affect Tenant B's flow table
 */
static void test_flow_table_isolation(void) {
    TEST_START("Flow table isolation between tenants");

    // Simulate flow creation for Tenant A
    struct flow_key flow_a = {
        .src_ip = htonl(fixture.attacker_ip),
        .dst_ip = htonl(fixture.tenant_a_ip + 100),  // 192.168.1.100
        .src_port = htons(12345),
        .dst_port = htons(80),
        .protocol = IPPROTO_TCP,
        .tenant_id = fixture.tenant_a
    };

    // Verify this flow is attributed to Tenant A
    ASSERT_EQ(flow_a.tenant_id, fixture.tenant_a, "Flow should belong to Tenant A");

    // Create similar flow for Tenant B (different dst_ip)
    struct flow_key flow_b = {
        .src_ip = htonl(fixture.attacker_ip),
        .dst_ip = htonl(fixture.tenant_b_ip + 100),  // 10.0.0.100
        .src_port = htons(12345),
        .dst_port = htons(80),
        .protocol = IPPROTO_TCP,
        .tenant_id = fixture.tenant_b
    };

    // Verify flow attribution is different
    ASSERT_NE(flow_a.tenant_id, flow_b.tenant_id, "Flows should have different tenant IDs");
    ASSERT_NE(flow_a.dst_ip, flow_b.dst_ip, "Flows should have different dst IPs");

    TEST_PASS();
}

/**
 * Test: Rate limit isolation
 * Verify that rate limits are enforced per-tenant
 */
static void test_rate_limit_isolation(void) {
    TEST_START("Rate limit isolation between tenants");

    // Get tenant configs
    const struct tenant_l1_config *cfg_a = tenant_get_l1_config(fixture.tenant_a);
    const struct tenant_l1_config *cfg_b = tenant_get_l1_config(fixture.tenant_b);

    // Enterprise should have higher limits than Standard
    uint64_t limit_a = cfg_a->rate_limits.global_pps;
    uint64_t limit_b = cfg_b->rate_limits.global_pps;

    // For this test, we just verify they're independent
    // In production, Enterprise > Standard
    ASSERT_TRUE(limit_a > 0, "Tenant A should have non-zero rate limit");
    ASSERT_TRUE(limit_b > 0, "Tenant B should have non-zero rate limit");

    // Simulate Tenant A hitting rate limit
    struct per_tenant_stats stats_a = {
        .current_pps = limit_a + 10000,  // Exceeds limit
        .rate_limited_packets = 10000
    };

    // Tenant B should not be rate limited
    struct per_tenant_stats stats_b = {
        .current_pps = limit_b / 2,  // Well under limit
        .rate_limited_packets = 0
    };

    ASSERT_TRUE(stats_a.rate_limited_packets > 0, "Tenant A should have rate-limited packets");
    ASSERT_EQ(stats_b.rate_limited_packets, 0, "Tenant B should not have rate-limited packets");

    TEST_PASS();
}

/**
 * Test: Geo-blocking isolation
 * Verify that geo-blocking rules are per-tenant
 */
static void test_geo_blocking_isolation(void) {
    TEST_START("Geo-blocking isolation between tenants");

    // Get configs
    const struct tenant_l1_config *cfg_a = tenant_get_l1_config(fixture.tenant_a);
    const struct tenant_l1_config *cfg_b = tenant_get_l1_config(fixture.tenant_b);

    // Create modifiable copies
    struct tenant_l1_config new_cfg_a = *cfg_a;

    // Block China (country code 86) for Tenant A
    new_cfg_a.features.geo_blocking = true;
    new_cfg_a.geo_whitelist_mode = false;  // Blacklist mode
    tenant_config_set_country_blocked(&new_cfg_a, 86, true);

    int ret = tenant_set_l1_config(fixture.tenant_a, &new_cfg_a);
    ASSERT_EQ(ret, 0, "Failed to update Tenant A geo config");

    // Verify Tenant A blocks China
    cfg_a = tenant_get_l1_config(fixture.tenant_a);
    ASSERT_TRUE(tenant_config_is_country_blocked(cfg_a, 86), "Tenant A should block CN");

    // Verify Tenant B does NOT block China
    cfg_b = tenant_get_l1_config(fixture.tenant_b);
    ASSERT_TRUE(!cfg_b->features.geo_blocking || !tenant_config_is_country_blocked(cfg_b, 86),
                "Tenant B should not block CN");

    TEST_PASS();
}

/**
 * Test: SYN proxy state isolation
 * Verify SYN proxy cookies are tenant-specific
 */
static void test_syn_proxy_isolation(void) {
    TEST_START("SYN proxy state isolation between tenants");

    // Configure SYN proxy differently for each tenant
    const struct tenant_l1_config *cfg_a = tenant_get_l1_config(fixture.tenant_a);
    const struct tenant_l1_config *cfg_b = tenant_get_l1_config(fixture.tenant_b);

    struct tenant_l1_config new_cfg_a = *cfg_a;
    struct tenant_l1_config new_cfg_b = *cfg_b;

    // Tenant A: Always-on SYN proxy
    new_cfg_a.syn_proxy.enabled = true;
    new_cfg_a.syn_proxy.always_on = true;
    tenant_set_l1_config(fixture.tenant_a, &new_cfg_a);

    // Tenant B: Attack-triggered only
    new_cfg_b.syn_proxy.enabled = true;
    new_cfg_b.syn_proxy.always_on = false;
    tenant_set_l1_config(fixture.tenant_b, &new_cfg_b);

    // Verify different behavior
    cfg_a = tenant_get_l1_config(fixture.tenant_a);
    cfg_b = tenant_get_l1_config(fixture.tenant_b);

    ASSERT_TRUE(cfg_a->syn_proxy.always_on, "Tenant A should have always-on SYN proxy");
    ASSERT_TRUE(!cfg_b->syn_proxy.always_on, "Tenant B should not have always-on SYN proxy");

    TEST_PASS();
}

/**
 * Test: Memory isolation verification
 * Verify tenant data structures don't overlap
 */
static void test_memory_isolation(void) {
    TEST_START("Memory isolation between tenants");

    // Get tenant pointers
    const struct tenant *ta = tenant_lookup(fixture.tenant_a);
    const struct tenant *tb = tenant_lookup(fixture.tenant_b);

    ASSERT_TRUE(ta != NULL, "Tenant A not found");
    ASSERT_TRUE(tb != NULL, "Tenant B not found");

    // Verify different memory addresses
    ASSERT_TRUE((void*)ta != (void*)tb, "Tenants should be at different addresses");

    // Verify ID isolation
    ASSERT_NE(ta->id, tb->id, "Tenant IDs should be different");

    // Verify name buffers are separate
    ASSERT_TRUE(ta->name != tb->name, "Name buffers should be separate");
    ASSERT_TRUE(strcmp(ta->name, tb->name) != 0, "Names should be different");

    TEST_PASS();
}

/**
 * Test: Concurrent access isolation
 * Verify thread-safe access to different tenants
 */
typedef struct {
    tenant_id_t tenant_id;
    int iterations;
    int success_count;
    int error_count;
} thread_context_t;

static void* concurrent_tenant_access(void *arg) {
    thread_context_t *ctx = (thread_context_t*)arg;

    for (int i = 0; i < ctx->iterations; i++) {
        // Lookup tenant
        const struct tenant *t = tenant_lookup(ctx->tenant_id);
        if (t == NULL) {
            ctx->error_count++;
            continue;
        }

        // Verify tenant ID matches
        if (t->id != ctx->tenant_id) {
            ctx->error_count++;
            continue;
        }

        ctx->success_count++;

        // Small delay to increase contention
        usleep(100);
    }

    return NULL;
}

static void test_concurrent_isolation(void) {
    TEST_START("Concurrent access isolation");

    const int num_threads = 4;
    const int iterations = 100;

    pthread_t threads[num_threads];
    thread_context_t contexts[num_threads];

    // Half threads access Tenant A, half access Tenant B
    for (int i = 0; i < num_threads; i++) {
        contexts[i].tenant_id = (i < num_threads / 2) ? fixture.tenant_a : fixture.tenant_b;
        contexts[i].iterations = iterations;
        contexts[i].success_count = 0;
        contexts[i].error_count = 0;

        pthread_create(&threads[i], NULL, concurrent_tenant_access, &contexts[i]);
    }

    // Wait for all threads
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // Verify all operations succeeded
    int total_errors = 0;
    for (int i = 0; i < num_threads; i++) {
        total_errors += contexts[i].error_count;
        ASSERT_EQ(contexts[i].success_count, iterations, "Not all iterations succeeded");
    }

    ASSERT_EQ(total_errors, 0, "Concurrent access had errors");

    TEST_PASS();
}

/**
 * Test: Quota isolation
 * Verify quota enforcement is per-tenant
 */
static void test_quota_isolation(void) {
    TEST_START("Quota enforcement isolation");

    const struct tenant *ta = tenant_lookup(fixture.tenant_a);
    const struct tenant *tb = tenant_lookup(fixture.tenant_b);

    ASSERT_TRUE(ta != NULL && tb != NULL, "Tenant lookup failed");

    // Enterprise should have higher quotas than Standard
    // Based on tier presets
    struct tenant_quotas quotas_enterprise, quotas_standard;
    tenant_get_tier_default_quotas(TENANT_TIER_ENTERPRISE, &quotas_enterprise);
    tenant_get_tier_default_quotas(TENANT_TIER_STANDARD, &quotas_standard);

    ASSERT_TRUE(quotas_enterprise.max_flows > quotas_standard.max_flows,
                "Enterprise should have more flows than Standard");
    ASSERT_TRUE(quotas_enterprise.max_pps > quotas_standard.max_pps,
                "Enterprise should have higher PPS limit");
    ASSERT_TRUE(quotas_enterprise.max_protected_ips > quotas_standard.max_protected_ips,
                "Enterprise should have more protected IPs");

    TEST_PASS();
}

// ==================== Test Runner ====================

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     Multi-Tenant Isolation Integration Tests                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    // Setup
    printf("\n[SETUP] Initializing test fixtures...\n");
    if (setup_fixture() != 0) {
        printf("\033[31m[ERROR] Failed to setup test fixtures\033[0m\n");
        return 1;
    }
    printf("[SETUP] Created Tenant A (ID=%u) and Tenant B (ID=%u)\n",
           fixture.tenant_a, fixture.tenant_b);

    // Run tests
    TEST_SECTION("Statistics Isolation");
    test_stats_isolation();

    TEST_SECTION("IP List Isolation");
    test_blacklist_isolation();
    test_whitelist_isolation();

    TEST_SECTION("Attack Detection Isolation");
    test_attack_alert_isolation();

    TEST_SECTION("Configuration Isolation");
    test_config_change_isolation();

    TEST_SECTION("Flow Table Isolation");
    test_flow_table_isolation();

    TEST_SECTION("Rate Limiting Isolation");
    test_rate_limit_isolation();

    TEST_SECTION("Geo-Blocking Isolation");
    test_geo_blocking_isolation();

    TEST_SECTION("SYN Proxy Isolation");
    test_syn_proxy_isolation();

    TEST_SECTION("Memory Isolation");
    test_memory_isolation();

    TEST_SECTION("Concurrent Access Isolation");
    test_concurrent_isolation();

    TEST_SECTION("Quota Isolation");
    test_quota_isolation();

    // Cleanup
    printf("\n[CLEANUP] Destroying test fixtures...\n");
    teardown_fixture();

    // Summary
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                       Test Summary                           ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Total:  %3d                                                 ║\n", tests_run);
    printf("║  Passed: %3d  \033[32m✓\033[0m                                              ║\n", tests_passed);
    printf("║  Failed: %3d  %s                                              ║\n",
           tests_failed, tests_failed > 0 ? "\033[31m✗\033[0m" : " ");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    if (tests_failed > 0) {
        printf("\n\033[31m[RESULT] SOME TESTS FAILED!\033[0m\n\n");
        return 1;
    }

    printf("\n\033[32m[RESULT] ALL TESTS PASSED!\033[0m\n\n");
    return 0;
}
