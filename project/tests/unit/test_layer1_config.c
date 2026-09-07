/**
 * @file test_layer1_config.c
 * @brief Unit tests for Layer 1 configuration
 *
 * Tests cover:
 * - Emergency drop percentage configuration
 * - Progressive rate limiting
 * - Config defaults
 *
 * Build: Link with layer1 library
 * Run:   ./test_layer1_config
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "../../layer1/config/layer1_config.h"

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

// ==================== Test: Config Defaults ====================

void test_flow_table_defaults(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    TEST_ASSERT_EQ(1000000, config.flow_table.max_flows, "Default max_flows should be 1M");
    TEST_ASSERT_EQ(60, config.flow_table.idle_timeout_sec, "Default idle_timeout should be 60s");
    TEST_ASSERT_EQ(5, config.flow_table.syn_timeout_sec, "Default syn_timeout should be 5s");
    TEST_ASSERT_EQ(true, config.flow_table.enable_syn_protection, "SYN protection should be enabled by default");
}

void test_aging_scan_limit_defaults(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    TEST_ASSERT_EQ(4096, config.flow_table.aging_scan_limit,
                   "Default aging_scan_limit should be 4096");
    TEST_ASSERT_EQ(8192, config.flow_table.aging_scan_limit_pressure,
                   "Default aging_scan_limit_pressure should be 8192");
}

void test_emergency_drop_defaults(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    TEST_ASSERT_EQ(90, config.flow_table.emergency_drop_unknown_pct,
                   "Default emergency_drop_unknown_pct should be 90");
    TEST_ASSERT_EQ(25, config.flow_table.emergency_drop_good_pct,
                   "Default emergency_drop_good_pct should be 25");
    TEST_ASSERT_EQ(75, config.flow_table.emergency_drop_neutral_pct,
                   "Default emergency_drop_neutral_pct should be 75");
    TEST_ASSERT_EQ(95, config.flow_table.emergency_drop_suspicious_pct,
                   "Default emergency_drop_suspicious_pct should be 95");
}

// ==================== Test: Emergency Drop Logic ====================

void test_emergency_drop_unknown_highest(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    // Unknown IPs should have high drop rate (but not the highest)
    TEST_ASSERT(config.flow_table.emergency_drop_unknown_pct >= 80,
                "Unknown IPs should have high drop rate");
    TEST_ASSERT(config.flow_table.emergency_drop_unknown_pct <=
                config.flow_table.emergency_drop_suspicious_pct,
                "Suspicious IPs should have highest drop rate");
}

void test_emergency_drop_good_lowest(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    // Good reputation IPs should have the lowest drop rate
    TEST_ASSERT(config.flow_table.emergency_drop_good_pct <
                config.flow_table.emergency_drop_neutral_pct,
                "Good IPs should have lower drop rate than neutral");
    TEST_ASSERT(config.flow_table.emergency_drop_good_pct <
                config.flow_table.emergency_drop_unknown_pct,
                "Good IPs should have lower drop rate than unknown");
}

void test_emergency_drop_ordering(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    // Drop rates should follow: good < neutral < unknown <= suspicious
    TEST_ASSERT(config.flow_table.emergency_drop_good_pct <
                config.flow_table.emergency_drop_neutral_pct,
                "Good < Neutral");
    TEST_ASSERT(config.flow_table.emergency_drop_neutral_pct <
                config.flow_table.emergency_drop_unknown_pct,
                "Neutral < Unknown");
    TEST_ASSERT(config.flow_table.emergency_drop_unknown_pct <=
                config.flow_table.emergency_drop_suspicious_pct,
                "Unknown <= Suspicious");
}

// ==================== Test: Progressive Rate Limiting ====================

void test_progressive_rate_limit_none(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    // At NONE level, should get 100% of normal limit
    uint32_t limit = layer1_get_progressive_pps_limit(&config.rate_limits, 0);
    TEST_ASSERT_EQ(config.rate_limits.normal_pps_per_ip, limit,
                   "NONE level should allow full normal rate");
}

void test_progressive_rate_limit_low(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    // At LOW level (1), should get level_low_percent (80%) of normal
    uint32_t limit = layer1_get_progressive_pps_limit(&config.rate_limits, 1);
    uint32_t expected = (config.rate_limits.normal_pps_per_ip * 80) / 100;
    TEST_ASSERT_EQ(expected, limit, "LOW level should allow 80% of normal rate");
}

void test_progressive_rate_limit_medium(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    // At MEDIUM level (2), should get level_medium_percent (50%) of normal
    uint32_t limit = layer1_get_progressive_pps_limit(&config.rate_limits, 2);
    uint32_t expected = (config.rate_limits.normal_pps_per_ip * 50) / 100;
    TEST_ASSERT_EQ(expected, limit, "MEDIUM level should allow 50% of normal rate");
}

void test_progressive_rate_limit_high(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    // At HIGH level (3), should get level_high_percent (25%) of normal
    uint32_t limit = layer1_get_progressive_pps_limit(&config.rate_limits, 3);
    uint32_t expected = (config.rate_limits.normal_pps_per_ip * 25) / 100;
    TEST_ASSERT_EQ(expected, limit, "HIGH level should allow 25% of normal rate");
}

void test_progressive_rate_limit_critical(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    // At CRITICAL level (4), should get level_critical_percent (10%) of normal
    uint32_t limit = layer1_get_progressive_pps_limit(&config.rate_limits, 4);
    uint32_t expected = (config.rate_limits.normal_pps_per_ip * 10) / 100;
    TEST_ASSERT_EQ(expected, limit, "CRITICAL level should allow 10% of normal rate");
}

void test_progressive_rate_limit_floor(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    // Progressive limit should never go below attack_pps_per_ip
    // Set up scenario where percentage would be below attack limit
    config.rate_limits.normal_pps_per_ip = 100;
    config.rate_limits.attack_pps_per_ip = 50;
    config.rate_limits.level_critical_percent = 10;  // 10% of 100 = 10, but floor is 50

    uint32_t limit = layer1_get_progressive_pps_limit(&config.rate_limits, 4);
    TEST_ASSERT(limit >= config.rate_limits.attack_pps_per_ip,
                "Progressive limit should not go below attack limit");
}

void test_progressive_disabled_fallback(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    // When progressive is disabled, should use binary normal/attack
    config.rate_limits.progressive_enabled = false;

    uint32_t limit_none = layer1_get_progressive_pps_limit(&config.rate_limits, 0);
    TEST_ASSERT_EQ(config.rate_limits.normal_pps_per_ip, limit_none,
                   "When disabled, NONE should get normal rate");

    uint32_t limit_any = layer1_get_progressive_pps_limit(&config.rate_limits, 1);
    TEST_ASSERT_EQ(config.rate_limits.attack_pps_per_ip, limit_any,
                   "When disabled, any anomaly should get attack rate");
}

// ==================== Test: Rate Limits Defaults ====================

void test_rate_limit_defaults(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    TEST_ASSERT_EQ(10000, config.rate_limits.normal_pps_per_ip,
                   "Default normal_pps_per_ip should be 10000");
    TEST_ASSERT_EQ(1000, config.rate_limits.attack_pps_per_ip,
                   "Default attack_pps_per_ip should be 1000");
    TEST_ASSERT_EQ(true, config.rate_limits.progressive_enabled,
                   "Progressive rate limiting should be enabled by default");
}

void test_progressive_percent_defaults(void) {
    struct layer1_config config;
    layer1_config_defaults(&config);

    TEST_ASSERT_EQ(80, config.rate_limits.level_low_percent, "LOW should be 80%");
    TEST_ASSERT_EQ(50, config.rate_limits.level_medium_percent, "MEDIUM should be 50%");
    TEST_ASSERT_EQ(25, config.rate_limits.level_high_percent, "HIGH should be 25%");
    TEST_ASSERT_EQ(10, config.rate_limits.level_critical_percent, "CRITICAL should be 10%");
}

// ==================== Main ====================

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("\n========================================\n");
    printf("  Layer 1 Configuration Unit Tests\n");
    printf("========================================\n\n");

    // Config defaults tests
    printf("--- Config Defaults ---\n");
    RUN_TEST(test_flow_table_defaults);
    RUN_TEST(test_aging_scan_limit_defaults);
    RUN_TEST(test_emergency_drop_defaults);

    // Emergency drop logic tests
    printf("\n--- Emergency Drop Logic ---\n");
    RUN_TEST(test_emergency_drop_unknown_highest);
    RUN_TEST(test_emergency_drop_good_lowest);
    RUN_TEST(test_emergency_drop_ordering);

    // Progressive rate limiting tests
    printf("\n--- Progressive Rate Limiting ---\n");
    RUN_TEST(test_progressive_rate_limit_none);
    RUN_TEST(test_progressive_rate_limit_low);
    RUN_TEST(test_progressive_rate_limit_medium);
    RUN_TEST(test_progressive_rate_limit_high);
    RUN_TEST(test_progressive_rate_limit_critical);
    RUN_TEST(test_progressive_rate_limit_floor);
    RUN_TEST(test_progressive_disabled_fallback);

    // Rate limit defaults
    printf("\n--- Rate Limit Defaults ---\n");
    RUN_TEST(test_rate_limit_defaults);
    RUN_TEST(test_progressive_percent_defaults);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_run);
    printf("========================================\n\n");

    return tests_failed > 0 ? 1 : 0;
}
