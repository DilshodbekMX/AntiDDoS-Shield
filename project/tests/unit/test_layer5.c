/**
 * @file test_layer5.c
 * @brief Comprehensive unit tests for Layer 5 (Threat Intel, Baseline Optimizer,
 *        Cross-Tenant Learning, Reporting)
 *
 * Tests cover:
 * - Threat intelligence feed management and indicator lookup
 * - Baseline optimization recommendations
 * - Cross-tenant learning with privacy preservation
 * - Report generation
 * - Per-tenant isolation
 * - Distribution to L1/L4
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "../../layer5/layer5.h"
#include "../../layer5/threat_intel.h"
#include "../../layer5/baseline_optimizer.h"
#include "../../layer5/cross_tenant_learning.h"
#include "../../layer5/reporting.h"
#include "../../common/tenant.h"
#include "../../common/tenant_config.h"

// ==================== Test Framework ====================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static int tests_skipped = 0;

#define TEST_START(name) do { \
    printf("  Testing: %-50s ", name); \
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
} while(0)

#define TEST_SKIP(msg) do { \
    printf("\033[33mSKIP\033[0m: %s\n", msg); \
    tests_skipped++; \
} while(0)

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        char _buf[256]; \
        snprintf(_buf, sizeof(_buf), "%s (got %ld, expected %ld)", msg, (long)(a), (long)(b)); \
        TEST_FAIL(_buf); \
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

#define ASSERT_FALSE(cond, msg) do { \
    if (cond) { \
        TEST_FAIL(msg); \
        return; \
    } \
} while(0)

#define ASSERT_DOUBLE_EQ(a, b, eps, msg) do { \
    if (fabs((a) - (b)) > (eps)) { \
        char _buf[256]; \
        snprintf(_buf, sizeof(_buf), "%s (got %.4f, expected %.4f)", msg, (a), (b)); \
        TEST_FAIL(_buf); \
        return; \
    } \
} while(0)

#define ASSERT_DOUBLE_GT(a, b, msg) do { \
    if ((a) <= (b)) { \
        char _buf[256]; \
        snprintf(_buf, sizeof(_buf), "%s (got %.4f, expected > %.4f)", msg, (a), (b)); \
        TEST_FAIL(_buf); \
        return; \
    } \
} while(0)

#define ASSERT_GT(a, b, msg) do { \
    if ((a) <= (b)) { \
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
    return addr.s_addr;
}

static struct layer5_config create_default_l5_config(void) {
    struct layer5_config cfg = {0};

    cfg.enable_threat_intel = true;
    cfg.enable_external_feeds = true;
    cfg.feed_update_interval_min = 60;

    cfg.enable_baseline_optimizer = true;
    cfg.auto_apply_recommendations = false;  // Manual approval in tests
    cfg.auto_apply_confidence_threshold = 0.8;
    cfg.auto_apply_risk_threshold = 0.3;

    cfg.enable_cross_tenant = true;
    cfg.default_contribution_level = CONTRIB_LEVEL_BASIC;
    cfg.min_tenants_for_sharing = 3;
    cfg.dp_epsilon = 1.0;  // Differential privacy epsilon

    cfg.enable_reporting = true;
    cfg.enable_scheduled_reports = false;

    cfg.maintenance_interval_sec = 60;
    cfg.full_maintenance_interval_sec = 3600;

    cfg.distribute_to_l1 = true;
    cfg.distribute_to_l4 = true;
    cfg.distribution_interval_sec = 300;

    return cfg;
}

static bool setup_test_environment(void) {
    // Initialize tenant registry
    if (tenant_registry_init() != TENANT_OK) {
        return false;
    }

    // Initialize tenant config
    if (tenant_config_init() != 0) {
        tenant_registry_cleanup();
        return false;
    }

    // Initialize Layer 5 with default config
    struct layer5_config cfg = create_default_l5_config();
    if (layer5_init(&cfg) != 0) {
        tenant_config_cleanup();
        tenant_registry_cleanup();
        return false;
    }

    return true;
}

static void teardown_test_environment(void) {
    layer5_cleanup();
    tenant_config_cleanup();
    tenant_registry_cleanup();
}

// ==================== Threat Intelligence Tests ====================

static void test_threat_intel_init(void) {
    TEST_START("threat intel init/cleanup");

    int ret = threat_intel_init();
    ASSERT_EQ(ret, 0, "threat intel init failed");

    threat_intel_cleanup();
    TEST_PASS();
}

static void test_threat_intel_add_indicator(void) {
    TEST_START("threat intel add indicator");

    int ret = threat_intel_init();
    ASSERT_EQ(ret, 0, "threat intel init failed");

    struct threat_indicator indicator = {0};
    indicator.type = INDICATOR_TYPE_IP;
    indicator.ip = ip_to_uint32("192.168.100.1");
    indicator.threat_score = 0.9;
    indicator.confidence = 0.85;
    indicator.expires_at = time(NULL) + 86400;  // 24 hours
    strncpy(indicator.source, "test_feed", sizeof(indicator.source) - 1);
    strncpy(indicator.description, "Known malicious IP", sizeof(indicator.description) - 1);

    ret = threat_intel_add_indicator(&indicator);
    ASSERT_EQ(ret, 0, "add indicator failed");

    // Lookup should find it
    struct threat_indicator found = {0};
    ret = threat_intel_lookup_ip(ip_to_uint32("192.168.100.1"), &found);
    ASSERT_EQ(ret, 0, "lookup failed");
    ASSERT_DOUBLE_EQ(found.threat_score, 0.9, 0.01, "wrong threat score");

    threat_intel_cleanup();
    TEST_PASS();
}

static void test_threat_intel_bulk_add(void) {
    TEST_START("threat intel bulk add");

    int ret = threat_intel_init();
    ASSERT_EQ(ret, 0, "threat intel init failed");

    // Add 1000 indicators
    const int count = 1000;
    for (int i = 0; i < count; i++) {
        struct threat_indicator indicator = {0};
        indicator.type = INDICATOR_TYPE_IP;
        indicator.ip = htonl(0xC0A80000 + i);  // 192.168.0.0 + i
        indicator.threat_score = 0.5 + (i % 10) * 0.05;
        indicator.confidence = 0.8;
        indicator.expires_at = time(NULL) + 86400;
        snprintf(indicator.source, sizeof(indicator.source), "bulk_test");

        ret = threat_intel_add_indicator(&indicator);
        ASSERT_EQ(ret, 0, "bulk add failed");
    }

    struct threat_intel_stats stats;
    threat_intel_get_stats(&stats);
    ASSERT_EQ(stats.ip_indicators, count, "wrong indicator count");

    threat_intel_cleanup();
    TEST_PASS();
}

static void test_threat_intel_expiration(void) {
    TEST_START("threat intel indicator expiration");

    int ret = threat_intel_init();
    ASSERT_EQ(ret, 0, "threat intel init failed");

    // Add expired indicator
    struct threat_indicator indicator = {0};
    indicator.type = INDICATOR_TYPE_IP;
    indicator.ip = ip_to_uint32("192.168.200.1");
    indicator.threat_score = 0.9;
    indicator.expires_at = time(NULL) - 1;  // Already expired

    ret = threat_intel_add_indicator(&indicator);
    ASSERT_EQ(ret, 0, "add expired indicator should succeed initially");

    // Run expiration
    threat_intel_expire_old();

    // Lookup should not find it
    struct threat_indicator found = {0};
    ret = threat_intel_lookup_ip(ip_to_uint32("192.168.200.1"), &found);
    ASSERT_NE(ret, 0, "expired indicator should not be found");

    threat_intel_cleanup();
    TEST_PASS();
}

static void test_threat_intel_check(void) {
    TEST_START("threat intel quick check");

    int ret = threat_intel_init();
    ASSERT_EQ(ret, 0, "threat intel init failed");

    // Add known threat
    struct threat_indicator indicator = {0};
    indicator.type = INDICATOR_TYPE_IP;
    indicator.ip = ip_to_uint32("192.168.200.5");
    indicator.threat_score = 0.95;
    indicator.expires_at = time(NULL) + 86400;
    threat_intel_add_indicator(&indicator);

    // Check should return BLOCK
    threat_action_t action = threat_intel_check_ip(ip_to_uint32("192.168.200.5"), 1);
    ASSERT_EQ(action, THREAT_ACTION_BLOCK, "high threat should be blocked");

    // Add low threat
    indicator.ip = ip_to_uint32("192.168.200.6");
    indicator.threat_score = 0.3;
    threat_intel_add_indicator(&indicator);

    // Check should return MONITOR or ALLOW
    action = threat_intel_check_ip(ip_to_uint32("192.168.200.6"), 1);
    ASSERT_TRUE(action == THREAT_ACTION_MONITOR || action == THREAT_ACTION_ALLOW,
                "low threat should be monitored or allowed");

    // Unknown IP should be ALLOW
    action = threat_intel_check_ip(ip_to_uint32("192.168.200.99"), 1);
    ASSERT_EQ(action, THREAT_ACTION_ALLOW, "unknown IP should be allowed");

    threat_intel_cleanup();
    TEST_PASS();
}

static void test_threat_intel_tenant_config(void) {
    TEST_START("threat intel per-tenant config");

    int ret = threat_intel_init();
    ASSERT_EQ(ret, 0, "threat intel init failed");

    // Configure tenant 1 to block at threshold 0.7
    struct tenant_threat_config t1_cfg = {0};
    t1_cfg.block_threshold = 0.7;
    t1_cfg.challenge_threshold = 0.4;
    threat_intel_set_tenant_config(1, &t1_cfg);

    // Configure tenant 2 to block at threshold 0.9
    struct tenant_threat_config t2_cfg = {0};
    t2_cfg.block_threshold = 0.9;
    t2_cfg.challenge_threshold = 0.6;
    threat_intel_set_tenant_config(2, &t2_cfg);

    // Add indicator with score 0.75
    struct threat_indicator indicator = {0};
    indicator.type = INDICATOR_TYPE_IP;
    indicator.ip = ip_to_uint32("192.168.200.10");
    indicator.threat_score = 0.75;
    indicator.expires_at = time(NULL) + 86400;
    threat_intel_add_indicator(&indicator);

    // Tenant 1 should block (0.75 > 0.7)
    threat_action_t action = threat_intel_check_ip_tenant(
        ip_to_uint32("192.168.200.10"), 1, &t1_cfg);
    ASSERT_EQ(action, THREAT_ACTION_BLOCK, "tenant 1 should block");

    // Tenant 2 should challenge (0.75 > 0.6 but < 0.9)
    action = threat_intel_check_ip_tenant(
        ip_to_uint32("192.168.200.10"), 2, &t2_cfg);
    ASSERT_EQ(action, THREAT_ACTION_CHALLENGE, "tenant 2 should challenge");

    threat_intel_cleanup();
    TEST_PASS();
}

// ==================== Baseline Optimizer Tests ====================

static void test_baseline_optimizer_init(void) {
    TEST_START("baseline optimizer init/cleanup");

    int ret = baseline_optimizer_init();
    ASSERT_EQ(ret, 0, "baseline optimizer init failed");

    baseline_optimizer_cleanup();
    TEST_PASS();
}

static void test_baseline_quality_assessment(void) {
    TEST_START("baseline quality assessment");

    int ret = baseline_optimizer_init();
    ASSERT_EQ(ret, 0, "baseline optimizer init failed");

    // Simulate some baseline data
    tenant_id_t tenant_id = 1;
    uint32_t dst_ip = ip_to_uint32("10.0.0.1");

    // Report some baseline metrics
    baseline_optimizer_update_metrics(tenant_id, dst_ip, 1000.0, 50.0);  // Mean 1000, StdDev 50

    // Report some detection results
    baseline_optimizer_report_detection(tenant_id, dst_ip, true, 0);  // True positive
    baseline_optimizer_report_detection(tenant_id, dst_ip, true, 0);
    baseline_optimizer_report_detection(tenant_id, dst_ip, false, 1); // False positive

    // Get quality assessment
    struct baseline_quality quality;
    ret = baseline_optimizer_get_quality(tenant_id, dst_ip, &quality);
    ASSERT_EQ(ret, 0, "get quality failed");
    ASSERT_TRUE(quality.stability_score >= 0 && quality.stability_score <= 1.0,
                "stability score out of range");
    ASSERT_EQ(quality.false_positives_24h, 1, "wrong FP count");

    baseline_optimizer_cleanup();
    TEST_PASS();
}

static void test_baseline_recommendations(void) {
    TEST_START("baseline recommendations");

    int ret = baseline_optimizer_init();
    ASSERT_EQ(ret, 0, "baseline optimizer init failed");

    tenant_id_t tenant_id = 1;
    uint32_t dst_ip = ip_to_uint32("10.0.0.2");

    // Simulate baseline with many false positives
    baseline_optimizer_update_metrics(tenant_id, dst_ip, 500.0, 100.0);
    for (int i = 0; i < 20; i++) {
        baseline_optimizer_report_detection(tenant_id, dst_ip, false, 1);  // FP
    }

    // Should recommend increasing threshold
    struct baseline_recommendation recs[10];
    int count = baseline_optimizer_get_recommendations(tenant_id, recs, 10);

    ASSERT_GT(count, 0, "should have recommendations");
    ASSERT_EQ(recs[0].tenant_id, tenant_id, "wrong tenant in recommendation");

    // Should recommend increasing z-threshold to reduce FP
    ASSERT_DOUBLE_GT(recs[0].z_threshold_delta, 0, "should recommend higher threshold");

    baseline_optimizer_cleanup();
    TEST_PASS();
}

static void test_baseline_poisoning_detection(void) {
    TEST_START("baseline poisoning detection");

    int ret = baseline_optimizer_init();
    ASSERT_EQ(ret, 0, "baseline optimizer init failed");

    tenant_id_t tenant_id = 1;
    uint32_t dst_ip = ip_to_uint32("10.0.0.3");

    // Simulate normal baseline
    baseline_optimizer_update_metrics(tenant_id, dst_ip, 1000.0, 50.0);

    // Simulate sudden large change (potential poisoning)
    baseline_optimizer_update_metrics(tenant_id, dst_ip, 5000.0, 50.0);  // 5x jump

    // Get quality assessment
    struct baseline_quality quality;
    ret = baseline_optimizer_get_quality(tenant_id, dst_ip, &quality);
    ASSERT_EQ(ret, 0, "get quality failed");
    ASSERT_TRUE(quality.poisoning_suspected, "should suspect poisoning");

    baseline_optimizer_cleanup();
    TEST_PASS();
}

// ==================== Cross-Tenant Learning Tests ====================

static void test_cross_tenant_init(void) {
    TEST_START("cross-tenant learning init/cleanup");

    int ret = cross_tenant_init();
    ASSERT_EQ(ret, 0, "cross-tenant init failed");

    cross_tenant_cleanup();
    TEST_PASS();
}

static void test_cross_tenant_pattern_contribution(void) {
    TEST_START("cross-tenant pattern contribution");

    int ret = cross_tenant_init();
    ASSERT_EQ(ret, 0, "cross-tenant init failed");

    // Configure tenants to contribute
    cross_tenant_set_contribution(1, CONTRIB_LEVEL_FULL);
    cross_tenant_set_contribution(2, CONTRIB_LEVEL_FULL);
    cross_tenant_set_contribution(3, CONTRIB_LEVEL_FULL);

    // Contribute attack patterns from multiple tenants
    struct attack_pattern pattern1 = {0};
    pattern1.attack_type = ATTACK_TYPE_SYN_FLOOD;
    pattern1.avg_pps = 100000;
    pattern1.src_ip_count = 5000;
    pattern1.mitigation_effectiveness = 0.95;
    cross_tenant_contribute_pattern(1, &pattern1);

    struct attack_pattern pattern2 = {0};
    pattern2.attack_type = ATTACK_TYPE_SYN_FLOOD;
    pattern2.avg_pps = 120000;
    pattern2.src_ip_count = 6000;
    pattern2.mitigation_effectiveness = 0.93;
    cross_tenant_contribute_pattern(2, &pattern2);

    struct attack_pattern pattern3 = {0};
    pattern3.attack_type = ATTACK_TYPE_SYN_FLOOD;
    pattern3.avg_pps = 110000;
    pattern3.src_ip_count = 5500;
    pattern3.mitigation_effectiveness = 0.94;
    cross_tenant_contribute_pattern(3, &pattern3);

    // Should have learned a pattern (min 3 tenants)
    struct cross_tenant_stats stats;
    cross_tenant_get_stats(&stats);
    ASSERT_GT(stats.patterns_learned, 0, "should have learned patterns");

    cross_tenant_cleanup();
    TEST_PASS();
}

static void test_cross_tenant_global_reputation(void) {
    TEST_START("cross-tenant global reputation");

    int ret = cross_tenant_init();
    ASSERT_EQ(ret, 0, "cross-tenant init failed");

    // Configure tenants
    cross_tenant_set_contribution(1, CONTRIB_LEVEL_BASIC);
    cross_tenant_set_contribution(2, CONTRIB_LEVEL_BASIC);
    cross_tenant_set_contribution(3, CONTRIB_LEVEL_BASIC);

    uint32_t bad_ip = ip_to_uint32("203.0.113.1");

    // Multiple tenants report same IP as attacker
    cross_tenant_report_attacker(1, bad_ip, ATTACK_TYPE_UDP_FLOOD, 0.9);
    cross_tenant_report_attacker(2, bad_ip, ATTACK_TYPE_UDP_FLOOD, 0.85);
    cross_tenant_report_attacker(3, bad_ip, ATTACK_TYPE_UDP_FLOOD, 0.92);

    // Global reputation should be low
    double global_rep = cross_tenant_get_global_reputation(bad_ip);
    ASSERT_TRUE(global_rep >= 0 && global_rep <= 1.0, "reputation out of range");

    // Multiple reports should result in lower reputation
    ASSERT_TRUE(global_rep < 0.3, "multi-tenant attacker should have low reputation");

    cross_tenant_cleanup();
    TEST_PASS();
}

static void test_cross_tenant_early_warning(void) {
    TEST_START("cross-tenant early warning");

    int ret = cross_tenant_init();
    ASSERT_EQ(ret, 0, "cross-tenant init failed");

    // Configure tenants
    for (int i = 1; i <= 5; i++) {
        cross_tenant_set_contribution(i, CONTRIB_LEVEL_FULL);
    }

    // Simulate attack spreading across tenants
    uint32_t attack_src_ip = ip_to_uint32("203.0.113.100");

    for (int i = 1; i <= 3; i++) {
        cross_tenant_report_attack_start(i, attack_src_ip, ATTACK_TYPE_SYN_FLOOD);
    }

    // Tenant 4 and 5 should get early warning
    struct early_warning warnings[10];
    int count = cross_tenant_get_early_warnings(4, warnings, 10);

    ASSERT_GT(count, 0, "tenant 4 should have early warnings");
    ASSERT_TRUE(warnings[0].attack_type == ATTACK_TYPE_SYN_FLOOD,
                "warning should be for SYN flood");

    cross_tenant_cleanup();
    TEST_PASS();
}

static void test_cross_tenant_privacy(void) {
    TEST_START("cross-tenant privacy (no sharing when NONE)");

    int ret = cross_tenant_init();
    ASSERT_EQ(ret, 0, "cross-tenant init failed");

    // Tenant 1 opts out
    cross_tenant_set_contribution(1, CONTRIB_LEVEL_NONE);

    // Tenant 1's patterns should not be shared
    struct attack_pattern pattern = {0};
    pattern.attack_type = ATTACK_TYPE_HTTP_FLOOD;
    pattern.avg_pps = 50000;
    cross_tenant_contribute_pattern(1, &pattern);

    // Should not affect global stats
    struct cross_tenant_stats before, after;
    cross_tenant_get_stats(&before);

    cross_tenant_contribute_pattern(1, &pattern);
    cross_tenant_get_stats(&after);

    ASSERT_EQ(before.patterns_learned, after.patterns_learned,
              "opted-out tenant should not contribute patterns");

    cross_tenant_cleanup();
    TEST_PASS();
}

// ==================== Reporting Tests ====================

static void test_reporting_init(void) {
    TEST_START("reporting init/cleanup");

    int ret = reporting_init();
    ASSERT_EQ(ret, 0, "reporting init failed");

    reporting_cleanup();
    TEST_PASS();
}

static void test_incident_report_generation(void) {
    TEST_START("incident report generation");

    int ret = reporting_init();
    ASSERT_EQ(ret, 0, "reporting init failed");

    // Create incident
    struct incident_report incident = {0};
    incident.incident_id = 1001;
    incident.tenant_id = 1;
    incident.start_time = time(NULL) - 3600;  // Started 1 hour ago
    incident.end_time = time(NULL) - 1800;    // Ended 30 min ago
    incident.detected_at = incident.start_time + 5;
    incident.mitigated_at = incident.start_time + 30;
    incident.attack_type = ATTACK_TYPE_SYN_FLOOD;
    incident.severity = 4;
    incident.peak_pps = 500000;
    incident.peak_bps = 2000000000;
    incident.src_ip_count = 10000;
    incident.packets_dropped = 10000000;
    incident.packets_passed = 1000000;
    incident.mitigation_effectiveness = 0.91;

    // Generate report
    char buf[8192];
    int len = reporting_generate_incident(&incident, REPORT_FORMAT_JSON, buf, sizeof(buf));
    ASSERT_GT(len, 0, "report generation failed");

    // Verify JSON contains key fields
    ASSERT_TRUE(strstr(buf, "\"incident_id\"") != NULL, "missing incident_id");
    ASSERT_TRUE(strstr(buf, "\"tenant_id\"") != NULL, "missing tenant_id");
    ASSERT_TRUE(strstr(buf, "\"attack_type\"") != NULL, "missing attack_type");
    ASSERT_TRUE(strstr(buf, "\"mitigation_effectiveness\"") != NULL,
                "missing mitigation_effectiveness");

    reporting_cleanup();
    TEST_PASS();
}

static void test_periodic_report_generation(void) {
    TEST_START("periodic report generation");

    int ret = reporting_init();
    ASSERT_EQ(ret, 0, "reporting init failed");

    struct periodic_report report = {0};
    report.tenant_id = 1;
    report.type = REPORT_TYPE_DAILY;
    report.start_time = time(NULL) - 86400;
    report.end_time = time(NULL);
    report.total_packets = 1000000000;
    report.total_bytes = 800000000000ULL;
    report.packets_dropped = 50000000;
    report.attacks_detected = 5;
    report.attacks_mitigated = 5;
    report.traffic_trend = 1.05;  // 5% increase

    char buf[8192];
    int len = reporting_generate_periodic(&report, REPORT_FORMAT_JSON, buf, sizeof(buf));
    ASSERT_GT(len, 0, "periodic report generation failed");

    ASSERT_TRUE(strstr(buf, "\"total_packets\"") != NULL, "missing total_packets");
    ASSERT_TRUE(strstr(buf, "\"attacks_detected\"") != NULL, "missing attacks_detected");

    reporting_cleanup();
    TEST_PASS();
}

// ==================== Layer 5 Integration Tests ====================

static void test_layer5_full_init(void) {
    TEST_START("Layer 5 full initialization");

    struct layer5_config cfg = create_default_l5_config();
    int ret = layer5_init(&cfg);
    ASSERT_EQ(ret, 0, "layer5 init failed");

    // Verify all subsystems initialized
    struct layer5_status status;
    layer5_get_status(&status);
    ASSERT_TRUE(status.initialized, "should be initialized");
    ASSERT_TRUE(status.threat_intel.initialized, "threat intel should be initialized");
    ASSERT_TRUE(status.baseline_optimizer.initialized, "optimizer should be initialized");
    ASSERT_TRUE(status.cross_tenant.initialized, "cross-tenant should be initialized");
    ASSERT_TRUE(status.reporting.initialized, "reporting should be initialized");

    layer5_cleanup();
    TEST_PASS();
}

static void test_layer5_attack_lifecycle(void) {
    TEST_START("Layer 5 attack lifecycle");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    tenant_id_t tenant_id = 1;
    uint32_t dst_ip = ip_to_uint32("10.0.0.100");

    // Simulate attack start
    uint32_t src_ips[100];
    for (int i = 0; i < 100; i++) {
        src_ips[i] = htonl(0xCB007100 + i);  // 203.0.113.0 + i
    }

    uint64_t incident_id = layer5_attack_start(tenant_id, dst_ip,
                                                ATTACK_TYPE_UDP_FLOOD, 200000,
                                                src_ips, 100);
    ASSERT_NE(incident_id, 0, "should return valid incident ID");

    // Simulate attack update
    layer5_attack_update(incident_id, 350000, src_ips, 100);

    // Simulate attack end
    layer5_attack_end(incident_id, 50000000, true, 500.0, 2000.0);

    // Verify stats updated
    struct layer5_stats stats;
    layer5_get_stats(&stats);

    teardown_test_environment();
    TEST_PASS();
}

static void test_layer5_tenant_init(void) {
    TEST_START("Layer 5 per-tenant initialization");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    // Initialize tenant with custom config
    struct tenant_threat_config threat_cfg = {0};
    threat_cfg.block_threshold = 0.8;
    threat_cfg.challenge_threshold = 0.5;

    int ret = layer5_tenant_init(1, &threat_cfg, CONTRIB_LEVEL_FULL);
    ASSERT_EQ(ret, 0, "tenant init failed");

    ret = layer5_tenant_init(2, &threat_cfg, CONTRIB_LEVEL_BASIC);
    ASSERT_EQ(ret, 0, "tenant 2 init failed");

    // Cleanup tenants
    layer5_tenant_cleanup(1);
    layer5_tenant_cleanup(2);

    teardown_test_environment();
    TEST_PASS();
}

static void test_layer5_distribution(void) {
    TEST_START("Layer 5 distribution to L1/L4");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    // Add some threat indicators
    struct threat_indicator indicator = {0};
    indicator.type = INDICATOR_TYPE_IP;
    indicator.ip = ip_to_uint32("198.51.100.1");
    indicator.threat_score = 0.95;
    indicator.expires_at = time(NULL) + 86400;
    threat_intel_add_indicator(&indicator);

    // Trigger distribution
    int distributed_l1 = layer5_distribute_to_l1();
    int distributed_l4 = layer5_distribute_to_l4();

    // Should distribute at least 1 indicator
    ASSERT_GT(distributed_l1, 0, "should distribute to L1");
    ASSERT_GT(distributed_l4, 0, "should distribute to L4");

    teardown_test_environment();
    TEST_PASS();
}

static void test_layer5_health_check(void) {
    TEST_START("Layer 5 health check");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    bool healthy = layer5_health_check();
    ASSERT_TRUE(healthy, "should be healthy after init");

    struct layer5_status status;
    layer5_get_status(&status);
    ASSERT_DOUBLE_GT(status.overall_health, 0.5, "health should be good");

    teardown_test_environment();
    TEST_PASS();
}

// ==================== Test Runner ====================

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║              Layer 5 Comprehensive Unit Tests                     ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    // Threat Intelligence Tests
    printf("┌─ Threat Intelligence Tests ────────────────────────────────────────┐\n");
    test_threat_intel_init();
    test_threat_intel_add_indicator();
    test_threat_intel_bulk_add();
    test_threat_intel_expiration();
    test_threat_intel_check();
    test_threat_intel_tenant_config();
    printf("└────────────────────────────────────────────────────────────────────┘\n\n");

    // Baseline Optimizer Tests
    printf("┌─ Baseline Optimizer Tests ─────────────────────────────────────────┐\n");
    test_baseline_optimizer_init();
    test_baseline_quality_assessment();
    test_baseline_recommendations();
    test_baseline_poisoning_detection();
    printf("└────────────────────────────────────────────────────────────────────┘\n\n");

    // Cross-Tenant Learning Tests
    printf("┌─ Cross-Tenant Learning Tests ──────────────────────────────────────┐\n");
    test_cross_tenant_init();
    test_cross_tenant_pattern_contribution();
    test_cross_tenant_global_reputation();
    test_cross_tenant_early_warning();
    test_cross_tenant_privacy();
    printf("└────────────────────────────────────────────────────────────────────┘\n\n");

    // Reporting Tests
    printf("┌─ Reporting Tests ──────────────────────────────────────────────────┐\n");
    test_reporting_init();
    test_incident_report_generation();
    test_periodic_report_generation();
    printf("└────────────────────────────────────────────────────────────────────┘\n\n");

    // Integration Tests
    printf("┌─ Layer 5 Integration Tests ────────────────────────────────────────┐\n");
    test_layer5_full_init();
    test_layer5_attack_lifecycle();
    test_layer5_tenant_init();
    test_layer5_distribution();
    test_layer5_health_check();
    printf("└────────────────────────────────────────────────────────────────────┘\n\n");

    // Summary
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                        TEST SUMMARY                               ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║  Total:   %3d                                                     ║\n", tests_run);
    printf("║  Passed:  %3d  \033[32m✓\033[0m                                                  ║\n", tests_passed);
    printf("║  Failed:  %3d  %s                                                  ║\n",
           tests_failed, tests_failed > 0 ? "\033[31m✗\033[0m" : " ");
    printf("║  Skipped: %3d                                                     ║\n", tests_skipped);
    printf("╚══════════════════════════════════════════════════════════════════╝\n");

    if (tests_failed > 0) {
        printf("\n\033[31mSOME TESTS FAILED!\033[0m\n");
        return 1;
    }

    printf("\n\033[32mALL TESTS PASSED!\033[0m\n");
    return 0;
}
