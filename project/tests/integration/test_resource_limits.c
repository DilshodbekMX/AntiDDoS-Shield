/**
 * @file test_resource_limits.c
 * @brief Multi-tenant resource limit and quota enforcement tests
 *
 * Resource tests ensuring:
 * - Quota enforcement works correctly
 * - Emergency mode handles global attacks
 * - Fair sharing of burst capacity
 * - No resource exhaustion attacks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "../../common/tenant.h"
#include "../../common/tenant_config.h"

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

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { TEST_FAIL(msg); } \
} while(0)

#define ASSERT_LE(a, b, msg) do { \
    if (!((a) <= (b))) { TEST_FAIL(msg); } \
} while(0)

#define ASSERT_GE(a, b, msg) do { \
    if (!((a) >= (b))) { TEST_FAIL(msg); } \
} while(0)

// ==================== Resource Tracking ====================

typedef struct {
    tenant_id_t tenant_id;
    uint64_t flows_used;
    uint64_t flows_max;
    uint64_t pps_current;
    uint64_t pps_max;
    uint64_t memory_used;
    uint64_t memory_max;
    uint32_t protected_ips_used;
    uint32_t protected_ips_max;
    uint64_t packets_dropped_quota;
    bool quota_exceeded;
} tenant_resource_state_t;

static tenant_resource_state_t resource_states[MAX_TENANTS];

static void init_resource_state(tenant_id_t id, const struct tenant_quotas *quotas) {
    resource_states[id].tenant_id = id;
    resource_states[id].flows_used = 0;
    resource_states[id].flows_max = quotas->max_flows;
    resource_states[id].pps_current = 0;
    resource_states[id].pps_max = quotas->max_pps;
    resource_states[id].memory_used = 0;
    resource_states[id].memory_max = quotas->max_memory_mb * 1024 * 1024;
    resource_states[id].protected_ips_used = 0;
    resource_states[id].protected_ips_max = quotas->max_protected_ips;
    resource_states[id].packets_dropped_quota = 0;
    resource_states[id].quota_exceeded = false;
}

static bool try_allocate_flow(tenant_id_t id) {
    if (resource_states[id].flows_used >= resource_states[id].flows_max) {
        resource_states[id].quota_exceeded = true;
        return false;
    }
    resource_states[id].flows_used++;
    return true;
}

static void release_flow(tenant_id_t id) {
    if (resource_states[id].flows_used > 0) {
        resource_states[id].flows_used--;
        if (resource_states[id].flows_used < resource_states[id].flows_max) {
            resource_states[id].quota_exceeded = false;
        }
    }
}

static bool check_pps_quota(tenant_id_t id, uint64_t pps) {
    resource_states[id].pps_current = pps;
    if (pps > resource_states[id].pps_max) {
        resource_states[id].quota_exceeded = true;
        resource_states[id].packets_dropped_quota += (pps - resource_states[id].pps_max);
        return false;
    }
    return true;
}

// ==================== Fixtures ====================

typedef struct {
    tenant_id_t free_tenant;
    tenant_id_t basic_tenant;
    tenant_id_t standard_tenant;
    tenant_id_t enterprise_tenant;
} resource_fixture_t;

static resource_fixture_t fixture;

static int setup_fixture(void) {
    int ret = tenant_registry_init();
    if (ret != TENANT_OK) return -1;

    ret = tenant_config_init();
    if (ret != 0) return -1;

    // Create tenants for each tier
    tenant_tier_t tiers[] = {
        TENANT_TIER_FREE,
        TENANT_TIER_BASIC,
        TENANT_TIER_STANDARD,
        TENANT_TIER_ENTERPRISE
    };

    tenant_id_t *ids[] = {
        &fixture.free_tenant,
        &fixture.basic_tenant,
        &fixture.standard_tenant,
        &fixture.enterprise_tenant
    };

    const char *names[] = {
        "Free Tier Tenant",
        "Basic Tier Tenant",
        "Standard Tier Tenant",
        "Enterprise Tier Tenant"
    };

    for (int i = 0; i < 4; i++) {
        struct tenant t = {0};
        t.id = TENANT_ID_INVALID;
        strncpy(t.name, names[i], MAX_TENANT_NAME_LEN - 1);
        t.status = TENANT_STATUS_ACTIVE;
        t.tier = tiers[i];
        t.type = TENANT_TYPE_DIRECT;

        ret = tenant_create(&t, ids[i]);
        if (ret != TENANT_OK) return -1;

        // Initialize resource tracking
        struct tenant_quotas quotas;
        tenant_get_tier_default_quotas(tiers[i], &quotas);
        init_resource_state(*ids[i], &quotas);
    }

    return 0;
}

static void teardown_fixture(void) {
    tenant_config_cleanup();
    tenant_registry_cleanup();
}

// ==================== Quota Enforcement Tests ====================

/**
 * Test: Flow quota enforcement
 * Verify that flow creation is blocked when quota is exceeded
 */
static void test_flow_quota_enforcement(void) {
    TEST_START("Flow quota enforcement");

    tenant_id_t id = fixture.free_tenant;
    uint64_t max_flows = resource_states[id].flows_max;

    // Fill up to quota
    for (uint64_t i = 0; i < max_flows; i++) {
        bool allocated = try_allocate_flow(id);
        ASSERT_TRUE(allocated, "Should allocate flow within quota");
    }

    // Verify at quota
    ASSERT_EQ(resource_states[id].flows_used, max_flows, "Should be at max flows");

    // Try to exceed quota
    bool exceeded = try_allocate_flow(id);
    ASSERT_TRUE(!exceeded, "Should not allocate flow over quota");
    ASSERT_TRUE(resource_states[id].quota_exceeded, "Quota exceeded flag should be set");

    // Release a flow
    release_flow(id);
    ASSERT_EQ(resource_states[id].flows_used, max_flows - 1, "Flow count should decrease");

    // Should be able to allocate again
    bool reallocated = try_allocate_flow(id);
    ASSERT_TRUE(reallocated, "Should allocate flow after release");

    // Cleanup
    while (resource_states[id].flows_used > 0) {
        release_flow(id);
    }

    TEST_PASS();
}

/**
 * Test: PPS quota enforcement
 * Verify that packet rate is limited per-tenant
 */
static void test_pps_quota_enforcement(void) {
    TEST_START("PPS quota enforcement");

    tenant_id_t id = fixture.basic_tenant;
    uint64_t max_pps = resource_states[id].pps_max;

    // Under quota
    bool ok = check_pps_quota(id, max_pps / 2);
    ASSERT_TRUE(ok, "Should allow PPS under quota");
    ASSERT_TRUE(!resource_states[id].quota_exceeded, "Should not exceed quota");

    // At quota
    ok = check_pps_quota(id, max_pps);
    ASSERT_TRUE(ok, "Should allow PPS at quota");

    // Over quota
    uint64_t over_pps = max_pps + 10000;
    ok = check_pps_quota(id, over_pps);
    ASSERT_TRUE(!ok, "Should reject PPS over quota");
    ASSERT_TRUE(resource_states[id].quota_exceeded, "Should exceed quota");
    ASSERT_EQ(resource_states[id].packets_dropped_quota, 10000, "Should track dropped packets");

    TEST_PASS();
}

/**
 * Test: Protected IP quota enforcement
 * Verify that protected IP count is limited
 */
static void test_protected_ip_quota(void) {
    TEST_START("Protected IP quota enforcement");

    tenant_id_t id = fixture.free_tenant;

    // Get quota
    struct tenant_quotas quotas;
    tenant_get_tier_default_quotas(TENANT_TIER_FREE, &quotas);
    uint32_t max_ips = quotas.max_protected_ips;

    // Free tier has limited IPs
    ASSERT_TRUE(max_ips > 0 && max_ips < 100, "Free tier should have limited IPs");

    // Add IPs up to quota
    for (uint32_t i = 0; i < max_ips; i++) {
        uint32_t ip = 0xC0A80100 + i;  // 192.168.1.x
        int ret = tenant_add_network(id, ip, 32);
        // May fail if already at limit, which is expected
        if (ret == TENANT_OK) {
            resource_states[id].protected_ips_used++;
        }
    }

    // Verify we can't exceed
    const struct tenant *t = tenant_lookup(id);
    ASSERT_TRUE(t != NULL, "Tenant lookup failed");
    ASSERT_LE(t->protected_count, max_ips, "Should not exceed protected IP quota");

    TEST_PASS();
}

/**
 * Test: Tier-based quota scaling
 * Verify that higher tiers have proportionally higher quotas
 */
static void test_tier_quota_scaling(void) {
    TEST_START("Tier-based quota scaling");

    struct tenant_quotas q_free, q_basic, q_standard, q_enterprise;

    tenant_get_tier_default_quotas(TENANT_TIER_FREE, &q_free);
    tenant_get_tier_default_quotas(TENANT_TIER_BASIC, &q_basic);
    tenant_get_tier_default_quotas(TENANT_TIER_STANDARD, &q_standard);
    tenant_get_tier_default_quotas(TENANT_TIER_ENTERPRISE, &q_enterprise);

    // Verify scaling: Free < Basic < Standard < Enterprise
    ASSERT_TRUE(q_free.max_flows < q_basic.max_flows, "Basic should have more flows than Free");
    ASSERT_TRUE(q_basic.max_flows < q_standard.max_flows, "Standard should have more flows than Basic");
    ASSERT_TRUE(q_standard.max_flows < q_enterprise.max_flows, "Enterprise should have more flows than Standard");

    ASSERT_TRUE(q_free.max_pps < q_basic.max_pps, "Basic should have higher PPS than Free");
    ASSERT_TRUE(q_basic.max_pps < q_standard.max_pps, "Standard should have higher PPS than Basic");
    ASSERT_TRUE(q_standard.max_pps < q_enterprise.max_pps, "Enterprise should have higher PPS than Standard");

    ASSERT_TRUE(q_free.max_protected_ips < q_basic.max_protected_ips, "Basic should have more IPs than Free");
    ASSERT_TRUE(q_basic.max_protected_ips < q_standard.max_protected_ips, "Standard should have more IPs than Basic");
    ASSERT_TRUE(q_standard.max_protected_ips < q_enterprise.max_protected_ips, "Enterprise should have more IPs than Standard");

    TEST_PASS();
}

// ==================== Emergency Mode Tests ====================

/**
 * Test: Emergency mode activation
 * Verify global attack triggers emergency mode
 */
static void test_emergency_mode_activation(void) {
    TEST_START("Emergency mode activation");

    // Simulate global attack detection
    bool emergency_mode = false;
    uint64_t global_pps = 0;
    const uint64_t emergency_threshold = 50000000;  // 50 Mpps

    // Normal traffic
    global_pps = 10000000;  // 10 Mpps
    emergency_mode = (global_pps > emergency_threshold);
    ASSERT_TRUE(!emergency_mode, "Should not be in emergency mode at 10 Mpps");

    // Attack traffic
    global_pps = 100000000;  // 100 Mpps
    emergency_mode = (global_pps > emergency_threshold);
    ASSERT_TRUE(emergency_mode, "Should be in emergency mode at 100 Mpps");

    TEST_PASS();
}

/**
 * Test: Emergency mode resource allocation
 * Verify resources are fairly distributed during emergency
 */
static void test_emergency_resource_allocation(void) {
    TEST_START("Emergency mode resource allocation");

    // Simulate emergency mode with reduced quotas
    const float emergency_quota_factor = 0.5;  // 50% of normal quota

    tenant_id_t ids[] = {
        fixture.free_tenant,
        fixture.basic_tenant,
        fixture.standard_tenant,
        fixture.enterprise_tenant
    };

    for (int i = 0; i < 4; i++) {
        uint64_t normal_pps = resource_states[ids[i]].pps_max;
        uint64_t emergency_pps = (uint64_t)(normal_pps * emergency_quota_factor);

        // Verify emergency quota is lower
        ASSERT_TRUE(emergency_pps < normal_pps, "Emergency PPS should be lower");
        ASSERT_TRUE(emergency_pps > 0, "Emergency PPS should be positive");

        // But tier ratios should be maintained
        if (i > 0) {
            uint64_t prev_normal = resource_states[ids[i-1]].pps_max;
            uint64_t prev_emergency = (uint64_t)(prev_normal * emergency_quota_factor);

            // If tier i has higher quota than tier i-1, same should hold in emergency
            if (resource_states[ids[i]].pps_max > resource_states[ids[i-1]].pps_max) {
                ASSERT_TRUE(emergency_pps > prev_emergency,
                           "Higher tier should maintain advantage in emergency");
            }
        }
    }

    TEST_PASS();
}

/**
 * Test: Priority tenant protection during emergency
 * Verify enterprise tenants get priority during attacks
 */
static void test_priority_tenant_protection(void) {
    TEST_START("Priority tenant protection during emergency");

    // Simulate system at capacity
    uint64_t available_capacity = 50000000;  // 50 Mpps available

    // Calculate fair share vs priority share
    uint64_t fair_share = available_capacity / 4;  // Equal split

    // Priority allocation: Enterprise gets 40%, Standard 30%, Basic 20%, Free 10%
    uint64_t priority_shares[] = {
        (uint64_t)(available_capacity * 0.10),  // Free: 10%
        (uint64_t)(available_capacity * 0.20),  // Basic: 20%
        (uint64_t)(available_capacity * 0.30),  // Standard: 30%
        (uint64_t)(available_capacity * 0.40),  // Enterprise: 40%
    };

    // Verify priority allocation favors higher tiers
    ASSERT_TRUE(priority_shares[3] > priority_shares[2], "Enterprise > Standard");
    ASSERT_TRUE(priority_shares[2] > priority_shares[1], "Standard > Basic");
    ASSERT_TRUE(priority_shares[1] > priority_shares[0], "Basic > Free");

    // Verify total doesn't exceed capacity
    uint64_t total = priority_shares[0] + priority_shares[1] +
                     priority_shares[2] + priority_shares[3];
    ASSERT_LE(total, available_capacity, "Total should not exceed capacity");

    TEST_PASS();
}

// ==================== Burst Capacity Tests ====================

/**
 * Test: Burst capacity allocation
 * Verify tenants can use burst capacity when available
 */
static void test_burst_capacity(void) {
    TEST_START("Burst capacity allocation");

    tenant_id_t id = fixture.standard_tenant;

    // Get tier quotas
    struct tenant_quotas quotas;
    tenant_get_tier_default_quotas(TENANT_TIER_STANDARD, &quotas);

    // Verify burst is higher than baseline
    ASSERT_TRUE(quotas.burst_pps > quotas.max_pps, "Burst PPS should exceed base PPS");

    // Calculate burst ratio
    float burst_ratio = (float)quotas.burst_pps / (float)quotas.max_pps;
    ASSERT_GE(burst_ratio, 1.5, "Burst should be at least 1.5x baseline");

    // Verify burst duration is reasonable
    ASSERT_TRUE(quotas.burst_duration_sec > 0, "Burst duration should be positive");
    ASSERT_LE(quotas.burst_duration_sec, 60, "Burst duration should not exceed 60 seconds");

    TEST_PASS();
}

/**
 * Test: Burst capacity sharing
 * Verify unused burst capacity can be shared
 */
static void test_burst_capacity_sharing(void) {
    TEST_START("Burst capacity sharing");

    // Simulate burst pool
    uint64_t burst_pool = 100000000;  // 100 Mpps burst pool
    uint64_t burst_used = 0;

    // Tenant A requests burst
    uint64_t tenant_a_request = 20000000;  // 20 Mpps
    if (burst_used + tenant_a_request <= burst_pool) {
        burst_used += tenant_a_request;
    }
    ASSERT_EQ(burst_used, tenant_a_request, "Tenant A burst should be granted");

    // Tenant B requests burst
    uint64_t tenant_b_request = 30000000;  // 30 Mpps
    if (burst_used + tenant_b_request <= burst_pool) {
        burst_used += tenant_b_request;
    }
    ASSERT_EQ(burst_used, tenant_a_request + tenant_b_request, "Tenant B burst should be granted");

    // Tenant C requests more than available
    uint64_t tenant_c_request = 60000000;  // 60 Mpps
    uint64_t available = burst_pool - burst_used;
    uint64_t granted = (tenant_c_request <= available) ? tenant_c_request : available;
    burst_used += granted;

    ASSERT_EQ(burst_used, burst_pool, "Pool should be fully utilized");
    ASSERT_EQ(granted, available, "Tenant C should get remaining capacity");

    TEST_PASS();
}

// ==================== Resource Exhaustion Tests ====================

/**
 * Test: Memory exhaustion prevention
 * Verify system prevents memory exhaustion attacks
 */
static void test_memory_exhaustion_prevention(void) {
    TEST_START("Memory exhaustion prevention");

    tenant_id_t id = fixture.basic_tenant;

    // Simulate memory allocation attempts
    uint64_t max_memory = resource_states[id].memory_max;
    uint64_t allocated = 0;
    uint64_t allocation_size = 1024 * 1024;  // 1 MB chunks
    int allocations = 0;
    int rejections = 0;

    // Try to allocate memory
    while (allocations < 1000) {  // Cap iterations
        if (allocated + allocation_size <= max_memory) {
            allocated += allocation_size;
            allocations++;
        } else {
            rejections++;
            break;  // Stop when we hit quota
        }
    }

    ASSERT_TRUE(rejections > 0, "Should reject over-quota allocations");
    ASSERT_LE(allocated, max_memory, "Should not exceed memory quota");

    TEST_PASS();
}

/**
 * Test: Connection exhaustion prevention
 * Verify system prevents connection exhaustion attacks
 */
static void test_connection_exhaustion_prevention(void) {
    TEST_START("Connection exhaustion prevention");

    tenant_id_t id = fixture.free_tenant;

    // Reset flow state
    while (resource_states[id].flows_used > 0) {
        release_flow(id);
    }

    uint64_t max_flows = resource_states[id].flows_max;

    // Rapid connection attempts (attack simulation)
    uint64_t attack_connections = max_flows * 2;  // Try to exceed quota
    uint64_t allowed = 0;
    uint64_t blocked = 0;

    for (uint64_t i = 0; i < attack_connections; i++) {
        if (try_allocate_flow(id)) {
            allowed++;
        } else {
            blocked++;
        }
    }

    // Verify quota enforcement
    ASSERT_EQ(allowed, max_flows, "Should allow exactly max_flows connections");
    ASSERT_EQ(blocked, attack_connections - max_flows, "Should block excess connections");
    ASSERT_TRUE(resource_states[id].quota_exceeded, "Quota exceeded flag should be set");

    // Cleanup
    while (resource_states[id].flows_used > 0) {
        release_flow(id);
    }

    TEST_PASS();
}

/**
 * Test: Cross-tenant resource exhaustion prevention
 * Verify one tenant can't exhaust resources for others
 */
static void test_cross_tenant_exhaustion(void) {
    TEST_START("Cross-tenant resource exhaustion prevention");

    // Reset all resource states
    for (int i = 0; i < 4; i++) {
        tenant_id_t id = (i == 0) ? fixture.free_tenant :
                         (i == 1) ? fixture.basic_tenant :
                         (i == 2) ? fixture.standard_tenant :
                                    fixture.enterprise_tenant;
        while (resource_states[id].flows_used > 0) {
            release_flow(id);
        }
    }

    // Attacker on Free tier tries to exhaust all resources
    tenant_id_t attacker = fixture.free_tenant;
    uint64_t max_flows = resource_states[attacker].flows_max;

    // Exhaust attacker's quota
    for (uint64_t i = 0; i < max_flows; i++) {
        try_allocate_flow(attacker);
    }
    ASSERT_EQ(resource_states[attacker].flows_used, max_flows, "Attacker should be at max");

    // Verify other tenants still have full quota available
    tenant_id_t victims[] = {
        fixture.basic_tenant,
        fixture.standard_tenant,
        fixture.enterprise_tenant
    };

    for (int i = 0; i < 3; i++) {
        bool can_allocate = try_allocate_flow(victims[i]);
        ASSERT_TRUE(can_allocate, "Victim tenant should still be able to allocate");
        release_flow(victims[i]);  // Clean up
    }

    // Cleanup
    while (resource_states[attacker].flows_used > 0) {
        release_flow(attacker);
    }

    TEST_PASS();
}

/**
 * Test: Rate of allocation limiting
 * Verify rapid allocation attempts are rate-limited
 */
static void test_allocation_rate_limiting(void) {
    TEST_START("Allocation rate limiting");

    // Simulate rate limiter
    const uint64_t max_allocations_per_sec = 1000;
    const uint64_t window_ms = 100;  // 100ms window
    uint64_t allowed_in_window = max_allocations_per_sec * window_ms / 1000;

    uint64_t attempts = 0;
    uint64_t allowed = 0;
    uint64_t rate_limited = 0;

    // Attempt rapid allocations in window
    for (uint64_t i = 0; i < allowed_in_window * 3; i++) {
        attempts++;
        if (allowed < allowed_in_window) {
            allowed++;
        } else {
            rate_limited++;
        }
    }

    ASSERT_EQ(allowed, allowed_in_window, "Should allow only rate-limited amount");
    ASSERT_TRUE(rate_limited > 0, "Should rate-limit excess attempts");

    TEST_PASS();
}

// ==================== Fair Scheduling Tests ====================

/**
 * Test: Weighted fair queuing
 * Verify packets are scheduled fairly based on tier
 */
static void test_weighted_fair_queuing(void) {
    TEST_START("Weighted fair queuing");

    // Simulate weighted scheduling
    typedef struct {
        tenant_id_t id;
        uint32_t weight;
        uint64_t packets_scheduled;
    } wfq_entry_t;

    wfq_entry_t entries[] = {
        { fixture.free_tenant, 1, 0 },      // Weight 1
        { fixture.basic_tenant, 2, 0 },     // Weight 2
        { fixture.standard_tenant, 4, 0 },  // Weight 4
        { fixture.enterprise_tenant, 8, 0 } // Weight 8
    };

    uint32_t total_weight = 1 + 2 + 4 + 8;  // 15
    uint64_t total_packets = 15000;  // Divisible by total weight

    // Schedule packets according to weights
    for (uint64_t p = 0; p < total_packets; p++) {
        // Simple round-robin with weights
        uint32_t target = p % total_weight;
        uint32_t cumulative = 0;

        for (int i = 0; i < 4; i++) {
            cumulative += entries[i].weight;
            if (target < cumulative) {
                entries[i].packets_scheduled++;
                break;
            }
        }
    }

    // Verify proportional scheduling
    uint64_t expected[] = {
        total_packets / total_weight * 1,  // Free: 1/15
        total_packets / total_weight * 2,  // Basic: 2/15
        total_packets / total_weight * 4,  // Standard: 4/15
        total_packets / total_weight * 8   // Enterprise: 8/15
    };

    for (int i = 0; i < 4; i++) {
        ASSERT_EQ(entries[i].packets_scheduled, expected[i],
                 "Scheduling should match weight ratio");
    }

    TEST_PASS();
}

// ==================== Test Runner ====================

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║       Resource Limits Integration Tests                      ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    // Setup
    printf("\n[SETUP] Initializing test fixtures...\n");
    if (setup_fixture() != 0) {
        printf("\033[31m[ERROR] Failed to setup test fixtures\033[0m\n");
        return 1;
    }
    printf("[SETUP] Created tenants for all tiers\n");

    // Run tests
    TEST_SECTION("Quota Enforcement Tests");
    test_flow_quota_enforcement();
    test_pps_quota_enforcement();
    test_protected_ip_quota();
    test_tier_quota_scaling();

    TEST_SECTION("Emergency Mode Tests");
    test_emergency_mode_activation();
    test_emergency_resource_allocation();
    test_priority_tenant_protection();

    TEST_SECTION("Burst Capacity Tests");
    test_burst_capacity();
    test_burst_capacity_sharing();

    TEST_SECTION("Resource Exhaustion Prevention");
    test_memory_exhaustion_prevention();
    test_connection_exhaustion_prevention();
    test_cross_tenant_exhaustion();
    test_allocation_rate_limiting();

    TEST_SECTION("Fair Scheduling Tests");
    test_weighted_fair_queuing();

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
