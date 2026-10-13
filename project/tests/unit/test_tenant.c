/**
 * @file test_tenant.c
 * @brief Unit tests for tenant registry and configuration
 *
 * Tests cover:
 * - Tenant registry initialization and cleanup
 * - Tenant CRUD operations
 * - LPM-based IP-to-tenant lookup
 * - Protected network management
 * - Tier presets and feature flags
 * - Thread safety (basic)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "../../common/tenant.h"
#include "../../common/tenant_config.h"
#include "../../common/tenant_stats.h"

// ==================== Test Counters ====================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_START(name) do { \
    printf("  Testing: %s ... ", name); \
    tests_run++; \
} while(0)

#define TEST_PASS() do { \
    printf("PASS\n"); \
    tests_passed++; \
} while(0)

#define TEST_FAIL(msg) do { \
    printf("FAIL: %s\n", msg); \
    tests_failed++; \
} while(0)

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        TEST_FAIL(msg); \
        return; \
    } \
} while(0)

#define ASSERT_NE(a, b, msg) do { \
    if ((a) == (b)) { \
        TEST_FAIL(msg); \
        return; \
    } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { \
        TEST_FAIL(msg); \
        return; \
    } \
} while(0)

#define ASSERT_NULL(ptr, msg) do { \
    if ((ptr) != NULL) { \
        TEST_FAIL(msg); \
        return; \
    } \
} while(0)

#define ASSERT_NOT_NULL(ptr, msg) do { \
    if ((ptr) == NULL) { \
        TEST_FAIL(msg); \
        return; \
    } \
} while(0)

// ==================== Helper Functions ====================

static uint32_t ip_to_uint32(const char *ip_str) {
    struct in_addr addr;
    inet_pton(AF_INET, ip_str, &addr);
    return ntohl(addr.s_addr);
}

static struct tenant create_test_tenant(const char *name, tenant_tier_t tier) {
    struct tenant t = {0};
    t.id = TENANT_ID_INVALID; // Auto-assign
    strncpy(t.name, name, MAX_TENANT_NAME_LEN - 1);
    t.status = TENANT_STATUS_ACTIVE;
    t.tier = tier;
    t.type = TENANT_TYPE_DIRECT;
    return t;
}

// ==================== Test Cases ====================

/**
 * Test registry initialization and cleanup
 */
static void test_registry_init(void) {
    TEST_START("registry init/cleanup");

    int ret = tenant_registry_init();
    ASSERT_EQ(ret, TENANT_OK, "registry init failed");

    // Verify empty state
    ASSERT_EQ(tenant_get_active_count(), 0, "registry should be empty");

    // Cleanup and verify
    tenant_registry_cleanup();

    TEST_PASS();
}

/**
 * Test tenant creation
 */
static void test_tenant_create(void) {
    TEST_START("tenant create");

    int ret = tenant_registry_init();
    ASSERT_EQ(ret, TENANT_OK, "registry init failed");

    // Create tenant
    struct tenant t = create_test_tenant("Test Tenant", TENANT_TIER_STANDARD);
    tenant_id_t id;

    ret = tenant_create(&t, &id);
    ASSERT_EQ(ret, TENANT_OK, "tenant create failed");
    ASSERT_TRUE(id >= TENANT_ID_MIN_USER, "invalid tenant ID assigned");
    ASSERT_EQ(tenant_get_active_count(), 1, "active count wrong");

    // Lookup and verify
    const struct tenant *found = tenant_lookup(id);
    ASSERT_NOT_NULL(found, "tenant not found");
    ASSERT_EQ(strcmp(found->name, "Test Tenant"), 0, "name mismatch");
    ASSERT_EQ(found->tier, TENANT_TIER_STANDARD, "tier mismatch");
    ASSERT_EQ(found->status, TENANT_STATUS_ACTIVE, "status mismatch");

    tenant_registry_cleanup();
    TEST_PASS();
}

/**
 * Test tenant creation with specific ID
 */
static void test_tenant_create_with_id(void) {
    TEST_START("tenant create with specific ID");

    int ret = tenant_registry_init();
    ASSERT_EQ(ret, TENANT_OK, "registry init failed");

    // Create tenant with specific ID
    struct tenant t = create_test_tenant("Specific ID Tenant", TENANT_TIER_ENTERPRISE);
    t.id = 42;
    tenant_id_t id;

    ret = tenant_create(&t, &id);
    ASSERT_EQ(ret, TENANT_OK, "tenant create failed");
    ASSERT_EQ(id, 42, "wrong ID assigned");

    // Try to create duplicate ID
    struct tenant t2 = create_test_tenant("Duplicate Tenant", TENANT_TIER_BASIC);
    t2.id = 42;
    tenant_id_t id2;

    ret = tenant_create(&t2, &id2);
    ASSERT_EQ(ret, TENANT_ERR_EXISTS, "should fail on duplicate ID");

    tenant_registry_cleanup();
    TEST_PASS();
}

/**
 * Test tenant lookup by name
 */
static void test_tenant_lookup_by_name(void) {
    TEST_START("tenant lookup by name");

    int ret = tenant_registry_init();
    ASSERT_EQ(ret, TENANT_OK, "registry init failed");

    // Create tenant
    struct tenant t = create_test_tenant("Named Tenant", TENANT_TIER_PREMIUM);
    tenant_id_t id;
    ret = tenant_create(&t, &id);
    ASSERT_EQ(ret, TENANT_OK, "tenant create failed");

    // Lookup by name
    const struct tenant *found = tenant_lookup_by_name("Named Tenant");
    ASSERT_NOT_NULL(found, "tenant not found by name");
    ASSERT_EQ(found->id, id, "ID mismatch");

    // Lookup non-existent name
    const struct tenant *not_found = tenant_lookup_by_name("Non Existent");
    ASSERT_NULL(not_found, "should not find non-existent tenant");

    tenant_registry_cleanup();
    TEST_PASS();
}

/**
 * Test tenant deletion
 */
static void test_tenant_delete(void) {
    TEST_START("tenant delete");

    int ret = tenant_registry_init();
    ASSERT_EQ(ret, TENANT_OK, "registry init failed");

    // Create tenant
    struct tenant t = create_test_tenant("Delete Me", TENANT_TIER_BASIC);
    tenant_id_t id;
    ret = tenant_create(&t, &id);
    ASSERT_EQ(ret, TENANT_OK, "tenant create failed");
    ASSERT_EQ(tenant_get_active_count(), 1, "active count wrong");

    // Delete
    ret = tenant_delete(id);
    ASSERT_EQ(ret, TENANT_OK, "tenant delete failed");
    ASSERT_EQ(tenant_get_active_count(), 0, "active count should be 0");

    // Verify deleted
    const struct tenant *found = tenant_lookup(id);
    ASSERT_NULL(found, "deleted tenant should not be found");

    tenant_registry_cleanup();
    TEST_PASS();
}

/**
 * Test protected network management
 */
static void test_protected_networks(void) {
    TEST_START("protected networks");

    int ret = tenant_registry_init();
    ASSERT_EQ(ret, TENANT_OK, "registry init failed");

    // Create tenant
    struct tenant t = create_test_tenant("Network Tenant", TENANT_TIER_STANDARD);
    tenant_id_t id;
    ret = tenant_create(&t, &id);
    ASSERT_EQ(ret, TENANT_OK, "tenant create failed");

    // Add network
    uint32_t ip1 = ip_to_uint32("192.168.1.0");
    ret = tenant_add_network(id, ip1, 24);
    ASSERT_EQ(ret, TENANT_OK, "add network failed");

    // Add second network
    uint32_t ip2 = ip_to_uint32("10.0.0.0");
    ret = tenant_add_network(id, ip2, 8);
    ASSERT_EQ(ret, TENANT_OK, "add second network failed");

    // Verify tenant has networks
    const struct tenant *found = tenant_lookup(id);
    ASSERT_NOT_NULL(found, "tenant not found");
    ASSERT_EQ(found->protected_count, 2, "wrong network count");

    // Add duplicate should fail
    ret = tenant_add_network(id, ip1, 24);
    ASSERT_EQ(ret, TENANT_ERR_EXISTS, "duplicate network should fail");

    // Remove network
    ret = tenant_remove_network(id, ip1, 24);
    ASSERT_EQ(ret, TENANT_OK, "remove network failed");

    found = tenant_lookup(id);
    ASSERT_EQ(found->protected_count, 1, "wrong network count after remove");

    tenant_registry_cleanup();
    TEST_PASS();
}

/**
 * Test IP-to-tenant LPM lookup
 */
static void test_ip_to_tenant_lookup(void) {
    TEST_START("IP-to-tenant LPM lookup");

    int ret = tenant_registry_init();
    ASSERT_EQ(ret, TENANT_OK, "registry init failed");

    // Create tenant 1 with network 192.168.1.0/24
    struct tenant t1 = create_test_tenant("Tenant 1", TENANT_TIER_STANDARD);
    tenant_id_t id1;
    ret = tenant_create(&t1, &id1);
    ASSERT_EQ(ret, TENANT_OK, "tenant 1 create failed");

    uint32_t ip1 = ip_to_uint32("192.168.1.0");
    ret = tenant_add_network(id1, ip1, 24);
    ASSERT_EQ(ret, TENANT_OK, "add network 1 failed");

    // Create tenant 2 with network 10.0.0.0/8
    struct tenant t2 = create_test_tenant("Tenant 2", TENANT_TIER_PREMIUM);
    tenant_id_t id2;
    ret = tenant_create(&t2, &id2);
    ASSERT_EQ(ret, TENANT_OK, "tenant 2 create failed");

    uint32_t ip2 = ip_to_uint32("10.0.0.0");
    ret = tenant_add_network(id2, ip2, 8);
    ASSERT_EQ(ret, TENANT_OK, "add network 2 failed");

    // Test lookup - IP in tenant 1's network
    uint32_t test_ip1 = htonl(ip_to_uint32("192.168.1.100")); // Network byte order for lookup
    tenant_id_t found_id = tenant_ip_to_id(test_ip1);
    ASSERT_EQ(found_id, id1, "lookup for 192.168.1.100 failed");

    // Test lookup - IP in tenant 2's network
    uint32_t test_ip2 = htonl(ip_to_uint32("10.50.100.200"));
    found_id = tenant_ip_to_id(test_ip2);
    ASSERT_EQ(found_id, id2, "lookup for 10.50.100.200 failed");

    // Test lookup - IP not in any network
    uint32_t test_ip3 = htonl(ip_to_uint32("172.16.0.1"));
    found_id = tenant_ip_to_id(test_ip3);
    ASSERT_EQ(found_id, TENANT_ID_INVALID, "lookup for 172.16.0.1 should fail");

    tenant_registry_cleanup();
    TEST_PASS();
}

/**
 * Test feature flags
 */
static void test_feature_flags(void) {
    TEST_START("feature flags");

    int ret = tenant_registry_init();
    ASSERT_EQ(ret, TENANT_OK, "registry init failed");

    // Create tenant with specific features
    struct tenant t = create_test_tenant("Feature Tenant", TENANT_TIER_ENTERPRISE);
    t.quotas.features_enabled = TENANT_FEATURES_ENTERPRISE;
    tenant_id_t id;
    ret = tenant_create(&t, &id);
    ASSERT_EQ(ret, TENANT_OK, "tenant create failed");

    // Test enterprise features
    ASSERT_TRUE(tenant_has_feature(id, TENANT_FEATURE_L1_BASIC), "should have L1 basic");
    ASSERT_TRUE(tenant_has_feature(id, TENANT_FEATURE_L5_INTEL), "should have L5 intel");
    ASSERT_TRUE(tenant_has_feature(id, TENANT_FEATURE_WAF), "should have WAF");

    // Create free tier tenant
    struct tenant t2 = create_test_tenant("Free Tenant", TENANT_TIER_FREE);
    t2.quotas.features_enabled = TENANT_FEATURES_FREE;
    tenant_id_t id2;
    ret = tenant_create(&t2, &id2);
    ASSERT_EQ(ret, TENANT_OK, "free tenant create failed");

    // Test free tier features (limited)
    ASSERT_TRUE(tenant_has_feature(id2, TENANT_FEATURE_L1_BASIC), "should have L1 basic");
    ASSERT_TRUE(!tenant_has_feature(id2, TENANT_FEATURE_L5_INTEL), "should not have L5 intel");
    ASSERT_TRUE(!tenant_has_feature(id2, TENANT_FEATURE_WAF), "should not have WAF");

    tenant_registry_cleanup();
    TEST_PASS();
}

/**
 * Test tenant status management
 */
static void test_tenant_status(void) {
    TEST_START("tenant status");

    int ret = tenant_registry_init();
    ASSERT_EQ(ret, TENANT_OK, "registry init failed");

    // Create active tenant
    struct tenant t = create_test_tenant("Status Tenant", TENANT_TIER_STANDARD);
    tenant_id_t id;
    ret = tenant_create(&t, &id);
    ASSERT_EQ(ret, TENANT_OK, "tenant create failed");

    // Verify active
    ASSERT_TRUE(tenant_is_active(id), "tenant should be active");

    // Suspend tenant
    ret = tenant_set_status(id, TENANT_STATUS_SUSPENDED);
    ASSERT_EQ(ret, TENANT_OK, "set status failed");
    ASSERT_TRUE(!tenant_is_active(id), "suspended tenant should not be active");

    // Set to attack mode
    ret = tenant_set_status(id, TENANT_STATUS_ATTACK_MODE);
    ASSERT_EQ(ret, TENANT_OK, "set attack mode failed");
    ASSERT_TRUE(tenant_is_active(id), "attack mode tenant should be active");

    tenant_registry_cleanup();
    TEST_PASS();
}

/**
 * Test attack state management
 */
static void test_attack_state(void) {
    TEST_START("attack state");

    int ret = tenant_registry_init();
    ASSERT_EQ(ret, TENANT_OK, "registry init failed");

    // Create tenant
    struct tenant t = create_test_tenant("Attack Tenant", TENANT_TIER_PREMIUM);
    tenant_id_t id;
    ret = tenant_create(&t, &id);
    ASSERT_EQ(ret, TENANT_OK, "tenant create failed");

    // Set under attack
    tenant_set_attack_state(id, true, 3, ATTACK_TYPE_SYN_FLOOD);

    // Verify attack state
    const struct tenant *found = tenant_lookup(id);
    ASSERT_NOT_NULL(found, "tenant not found");
    ASSERT_TRUE(found->attack_state.under_attack, "should be under attack");
    ASSERT_EQ(found->attack_state.attack_severity, 3, "wrong severity");
    ASSERT_EQ(found->attack_state.attacks_24h, 1, "wrong attack count");

    // Clear attack
    tenant_set_attack_state(id, false, 0, 0);
    found = tenant_lookup(id);
    ASSERT_TRUE(!found->attack_state.under_attack, "should not be under attack");

    tenant_registry_cleanup();
    TEST_PASS();
}

/**
 * Test tier default quotas
 */
static void test_tier_quotas(void) {
    TEST_START("tier quotas");

    struct tenant_quotas quotas;

    // Test free tier
    tenant_get_tier_default_quotas(TENANT_TIER_FREE, &quotas);
    ASSERT_EQ(quotas.max_flows, 10000, "free tier wrong max_flows");
    ASSERT_EQ(quotas.features_enabled, TENANT_FEATURES_FREE, "free tier wrong features");

    // Test enterprise tier
    tenant_get_tier_default_quotas(TENANT_TIER_ENTERPRISE, &quotas);
    ASSERT_EQ(quotas.max_flows, 2000000, "enterprise tier wrong max_flows");
    ASSERT_EQ(quotas.features_enabled, TENANT_FEATURES_ENTERPRISE, "enterprise tier wrong features");

    TEST_PASS();
}

/**
 * Test tenant config initialization
 */
static void test_config_init(void) {
    TEST_START("config init");

    int ret = tenant_config_init();
    ASSERT_EQ(ret, 0, "config init failed");

    tenant_config_cleanup();
    TEST_PASS();
}

/**
 * Test tier presets
 */
static void test_tier_presets(void) {
    TEST_START("tier presets");

    int ret = tenant_config_init();
    ASSERT_EQ(ret, 0, "config init failed");

    // Get enterprise preset
    const struct tenant_full_config *preset = tenant_config_get_tier_preset(TENANT_TIER_ENTERPRISE);
    ASSERT_NOT_NULL(preset, "enterprise preset is NULL");
    ASSERT_TRUE(preset->l1.syn_proxy.always_on, "enterprise should have always-on SYN proxy");
    ASSERT_TRUE(preset->l4.challenge.proof_of_work_enabled, "enterprise should have PoW");

    // Get free preset
    preset = tenant_config_get_tier_preset(TENANT_TIER_FREE);
    ASSERT_NOT_NULL(preset, "free preset is NULL");
    ASSERT_TRUE(!preset->l1.features.geo_blocking, "free should not have geo blocking");

    tenant_config_cleanup();
    TEST_PASS();
}

/**
 * Test config getter with inheritance
 */
static void test_config_inheritance(void) {
    TEST_START("config inheritance");

    int ret = tenant_registry_init();
    ASSERT_EQ(ret, TENANT_OK, "registry init failed");

    ret = tenant_config_init();
    ASSERT_EQ(ret, 0, "config init failed");

    // Create tenant without custom config
    struct tenant t = create_test_tenant("Inherit Tenant", TENANT_TIER_STANDARD);
    tenant_id_t id;
    ret = tenant_create(&t, &id);
    ASSERT_EQ(ret, TENANT_OK, "tenant create failed");

    // Get L1 config - should inherit from tier preset
    const struct tenant_l1_config *l1_cfg = tenant_get_l1_config(id);
    ASSERT_NOT_NULL(l1_cfg, "L1 config is NULL");

    // Verify it matches standard tier
    const struct tenant_full_config *preset = tenant_config_get_tier_preset(TENANT_TIER_STANDARD);
    ASSERT_EQ(l1_cfg->rate_limits.global_pps, preset->l1.rate_limits.global_pps,
              "rate limit should match tier preset");

    tenant_config_cleanup();
    tenant_registry_cleanup();
    TEST_PASS();
}

/**
 * Test validation
 */
static void test_tenant_validation(void) {
    TEST_START("tenant validation");

    struct tenant t = {0};
    char errors[256];

    // Missing name should fail
    int ret = tenant_validate(&t, errors, sizeof(errors));
    ASSERT_EQ(ret, TENANT_ERR_INVALID, "empty tenant should fail validation");

    // Valid tenant
    t = create_test_tenant("Valid Tenant", TENANT_TIER_STANDARD);
    ret = tenant_validate(&t, errors, sizeof(errors));
    ASSERT_EQ(ret, TENANT_OK, "valid tenant should pass validation");

    // Invalid tier
    t.tier = 99;
    ret = tenant_validate(&t, errors, sizeof(errors));
    ASSERT_EQ(ret, TENANT_ERR_INVALID, "invalid tier should fail validation");

    TEST_PASS();
}

/**
 * Test utility string functions
 */
static void test_string_utilities(void) {
    TEST_START("string utilities");

    // Status names
    ASSERT_EQ(strcmp(tenant_status_to_string(TENANT_STATUS_ACTIVE), "active"), 0,
              "wrong status string");
    ASSERT_EQ(strcmp(tenant_status_to_string(TENANT_STATUS_SUSPENDED), "suspended"), 0,
              "wrong status string");
    ASSERT_EQ(strcmp(tenant_status_to_string(99), "unknown"), 0,
              "invalid status should be unknown");

    // Tier names
    ASSERT_EQ(strcmp(tenant_tier_to_string(TENANT_TIER_ENTERPRISE), "enterprise"), 0,
              "wrong tier string");
    ASSERT_EQ(strcmp(tenant_tier_to_string(TENANT_TIER_FREE), "free"), 0,
              "wrong tier string");

    // Type names
    ASSERT_EQ(strcmp(tenant_type_to_string(TENANT_TYPE_RESELLER), "reseller"), 0,
              "wrong type string");

    TEST_PASS();
}

/**
 * Test multiple tenants
 */
static void test_multiple_tenants(void) {
    TEST_START("multiple tenants");

    int ret = tenant_registry_init();
    ASSERT_EQ(ret, TENANT_OK, "registry init failed");

    // Create 10 tenants
    tenant_id_t ids[10];
    for (int i = 0; i < 10; i++) {
        char name[64];
        snprintf(name, sizeof(name), "Tenant %d", i);
        struct tenant t = create_test_tenant(name, (tenant_tier_t)(i % TENANT_TIER_COUNT));
        ret = tenant_create(&t, &ids[i]);
        ASSERT_EQ(ret, TENANT_OK, "tenant create failed");
    }

    ASSERT_EQ(tenant_get_active_count(), 10, "wrong active count");

    // Verify all exist
    for (int i = 0; i < 10; i++) {
        const struct tenant *found = tenant_lookup(ids[i]);
        ASSERT_NOT_NULL(found, "tenant not found");
    }

    // Delete half
    for (int i = 0; i < 5; i++) {
        ret = tenant_delete(ids[i]);
        ASSERT_EQ(ret, TENANT_OK, "delete failed");
    }

    ASSERT_EQ(tenant_get_active_count(), 5, "wrong active count after delete");

    tenant_registry_cleanup();
    TEST_PASS();
}

/**
 * Test geo-blocking helpers
 */
static void test_geo_blocking(void) {
    TEST_START("geo-blocking helpers");

    struct tenant_l1_config cfg = {0};

    // Set countries as blocked (blacklist mode)
    cfg.geo_whitelist_mode = false;
    tenant_config_set_country_blocked(&cfg, 86, true);  // CN
    tenant_config_set_country_blocked(&cfg, 7, true);   // RU

    ASSERT_TRUE(tenant_config_is_country_blocked(&cfg, 86), "CN should be blocked");
    ASSERT_TRUE(tenant_config_is_country_blocked(&cfg, 7), "RU should be blocked");
    ASSERT_TRUE(!tenant_config_is_country_blocked(&cfg, 1), "US should not be blocked");

    // Unblock CN
    tenant_config_set_country_blocked(&cfg, 86, false);
    ASSERT_TRUE(!tenant_config_is_country_blocked(&cfg, 86), "CN should not be blocked");

    // Test whitelist mode
    memset(&cfg, 0, sizeof(cfg));
    cfg.geo_whitelist_mode = true;
    tenant_config_set_country_blocked(&cfg, 1, true);  // Allow US in allowed_countries

    ASSERT_TRUE(tenant_config_is_country_blocked(&cfg, 86), "CN should be blocked in whitelist mode");

    TEST_PASS();
}

// ==================== Test Runner ====================

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("\n=== Tenant Module Unit Tests ===\n\n");

    // Run tests
    test_registry_init();
    test_tenant_create();
    test_tenant_create_with_id();
    test_tenant_lookup_by_name();
    test_tenant_delete();
    test_protected_networks();
    test_ip_to_tenant_lookup();
    test_feature_flags();
    test_tenant_status();
    test_attack_state();
    test_tier_quotas();
    test_config_init();
    test_tier_presets();
    test_config_inheritance();
    test_tenant_validation();
    test_string_utilities();
    test_multiple_tenants();
    test_geo_blocking();

    // Summary
    printf("\n=== Test Summary ===\n");
    printf("Total:  %d\n", tests_run);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    if (tests_failed > 0) {
        printf("\nSOME TESTS FAILED!\n");
        return 1;
    }

    printf("\nALL TESTS PASSED!\n");
    return 0;
}
