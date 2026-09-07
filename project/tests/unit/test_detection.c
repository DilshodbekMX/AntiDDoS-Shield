/**
 * @file test_detection.c
 * @brief Unit tests for Layer 2 detection system
 *
 * Tests cover:
 * - Configurable Z-score thresholds for anomaly levels
 * - Baseline poisoning detection
 * - Detection result computation
 *
 * Build: Link with layer2 library
 * Run:   ./test_detection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

#include "../../layer2/detection.h"
#include "../../layer2/baselines.h"
#include "../../layer2/config/layer2_config.h"

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
        printf("  FAIL: %s (expected=%d, actual=%d)\n", msg, \
               (int)(expected), (int)(actual)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_DOUBLE_EQ(expected, actual, epsilon, msg) do { \
    if (fabs((expected) - (actual)) > (epsilon)) { \
        printf("  FAIL: %s (expected=%.2f, actual=%.2f)\n", msg, \
               (double)(expected), (double)(actual)); \
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

// ==================== Test: Configurable Z-Score Thresholds ====================

void test_z_score_level_critical_3tier(void) {
    // With 3-tier agreement, z >= 12.0 should be CRITICAL
    enum l2_anomaly_level level = l2_compute_anomaly_level(12.0, 3);
    TEST_ASSERT_EQ(L2_ANOMALY_CRITICAL, level, "z=12.0, 3 tiers should be CRITICAL");

    level = l2_compute_anomaly_level(15.0, 3);
    TEST_ASSERT_EQ(L2_ANOMALY_CRITICAL, level, "z=15.0, 3 tiers should be CRITICAL");

    level = l2_compute_anomaly_level(11.9, 3);
    TEST_ASSERT_EQ(L2_ANOMALY_HIGH, level, "z=11.9, 3 tiers should be HIGH (not CRITICAL)");
}

void test_z_score_level_high_3tier(void) {
    // With 3-tier agreement, z >= 9.0 but < 12.0 should be HIGH
    enum l2_anomaly_level level = l2_compute_anomaly_level(9.0, 3);
    TEST_ASSERT_EQ(L2_ANOMALY_HIGH, level, "z=9.0, 3 tiers should be HIGH");

    level = l2_compute_anomaly_level(11.0, 3);
    TEST_ASSERT_EQ(L2_ANOMALY_HIGH, level, "z=11.0, 3 tiers should be HIGH");
}

void test_z_score_level_medium_3tier(void) {
    // With 3-tier agreement, z >= 6.0 but < 9.0 should be MEDIUM
    enum l2_anomaly_level level = l2_compute_anomaly_level(6.0, 3);
    TEST_ASSERT_EQ(L2_ANOMALY_MEDIUM, level, "z=6.0, 3 tiers should be MEDIUM");

    level = l2_compute_anomaly_level(8.5, 3);
    TEST_ASSERT_EQ(L2_ANOMALY_MEDIUM, level, "z=8.5, 3 tiers should be MEDIUM");
}

void test_z_score_level_low_3tier(void) {
    // With 3-tier agreement, z < 6.0 should be LOW
    enum l2_anomaly_level level = l2_compute_anomaly_level(5.9, 3);
    TEST_ASSERT_EQ(L2_ANOMALY_LOW, level, "z=5.9, 3 tiers should be LOW");

    level = l2_compute_anomaly_level(4.0, 3);
    TEST_ASSERT_EQ(L2_ANOMALY_LOW, level, "z=4.0, 3 tiers should be LOW");
}

void test_z_score_level_2tier(void) {
    // With 2-tier agreement, thresholds are higher
    enum l2_anomaly_level level = l2_compute_anomaly_level(15.0, 2);
    TEST_ASSERT_EQ(L2_ANOMALY_HIGH, level, "z=15.0, 2 tiers should be HIGH");

    level = l2_compute_anomaly_level(10.0, 2);
    TEST_ASSERT_EQ(L2_ANOMALY_MEDIUM, level, "z=10.0, 2 tiers should be MEDIUM");

    level = l2_compute_anomaly_level(9.0, 2);
    TEST_ASSERT_EQ(L2_ANOMALY_LOW, level, "z=9.0, 2 tiers should be LOW");
}

void test_z_score_level_1tier(void) {
    // With 1-tier agreement, only very high z gets MEDIUM
    enum l2_anomaly_level level = l2_compute_anomaly_level(15.0, 1);
    TEST_ASSERT_EQ(L2_ANOMALY_MEDIUM, level, "z=15.0, 1 tier should be MEDIUM");

    level = l2_compute_anomaly_level(14.0, 1);
    TEST_ASSERT_EQ(L2_ANOMALY_LOW, level, "z=14.0, 1 tier should be LOW");

    level = l2_compute_anomaly_level(5.0, 1);
    TEST_ASSERT_EQ(L2_ANOMALY_LOW, level, "z=5.0, 1 tier should be LOW");
}

// ==================== Test: Confidence Calculation ====================

void test_confidence_3tier_agreement(void) {
    // 3 tiers should give highest base confidence (0.99)
    double conf = l2_compute_confidence(10.0, 3, 4.0);
    TEST_ASSERT(conf >= 0.99, "3-tier agreement should have >= 0.99 base confidence");
    TEST_ASSERT(conf <= 1.0, "Confidence should not exceed 1.0");
}

void test_confidence_2tier_agreement(void) {
    // 2 tiers should give 0.90 base confidence
    double conf = l2_compute_confidence(10.0, 2, 4.0);
    TEST_ASSERT(conf >= 0.90 && conf <= 1.0, "2-tier agreement should have ~0.90 confidence");
}

void test_confidence_1tier_agreement(void) {
    // 1 tier should give 0.75 base confidence
    double conf = l2_compute_confidence(4.5, 1, 4.0);
    TEST_ASSERT(conf >= 0.75 && conf < 0.90, "1-tier agreement should have ~0.75 confidence");
}

void test_confidence_increases_with_z(void) {
    // Higher Z-score should increase confidence
    double conf_low = l2_compute_confidence(4.5, 2, 4.0);
    double conf_high = l2_compute_confidence(10.0, 2, 4.0);
    TEST_ASSERT(conf_high > conf_low, "Higher z-score should increase confidence");
}

// ==================== Test: Anomaly State Management ====================

void test_anomaly_state_init(void) {
    struct l2_anomaly_state state;
    l2_anomaly_state_init(&state);

    TEST_ASSERT_EQ(false, state.active, "Initial state should not be active");
    TEST_ASSERT_EQ(L2_ANOMALY_NONE, state.level, "Initial level should be NONE");
    TEST_ASSERT_EQ(0, state.detection_count, "Initial detection count should be 0");
}

void test_anomaly_level_name(void) {
    TEST_ASSERT(strcmp(l2_anomaly_level_name(L2_ANOMALY_NONE), "NONE") == 0,
                "L2_ANOMALY_NONE should return 'NONE'");
    TEST_ASSERT(strcmp(l2_anomaly_level_name(L2_ANOMALY_CRITICAL), "CRITICAL") == 0,
                "L2_ANOMALY_CRITICAL should return 'CRITICAL'");
}

// ==================== Test: Baseline Poisoning Detection ====================

void test_baseline_poison_tracker_init(void) {
    struct three_tier_baseline baselines;
    memset(&baselines, 0, sizeof(baselines));

    // Poison tracker should start clean
    TEST_ASSERT_EQ(false, baselines.poison_tracker.poison_detected,
                   "Poison should not be detected initially");
    TEST_ASSERT_EQ(0, baselines.poison_tracker.large_change_count,
                   "Change count should be 0 initially");
}

void test_baseline_poison_check_disabled(void) {
    // When protection is disabled, should always return false
    struct three_tier_baseline baselines;
    memset(&baselines, 0, sizeof(baselines));

    struct l2_feature_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.timestamp_ns = 1000000000ULL;  // 1 second

    // Note: This test requires protection to be disabled in config
    // For now, just verify the function exists and returns bool
    bool poisoned = baseline_is_poisoned(&baselines);
    TEST_ASSERT_EQ(false, poisoned, "Fresh baselines should not be poisoned");
}

void test_baseline_poison_reset(void) {
    struct three_tier_baseline baselines;
    memset(&baselines, 0, sizeof(baselines));

    // Simulate poisoning
    baselines.poison_tracker.poison_detected = true;
    baselines.poison_tracker.large_change_count = 100;

    // Reset
    baseline_poison_tracker_reset(&baselines);

    TEST_ASSERT_EQ(false, baselines.poison_tracker.poison_detected,
                   "Poison flag should be cleared after reset");
    TEST_ASSERT_EQ(0, baselines.poison_tracker.large_change_count,
                   "Change count should be 0 after reset");
}

// ==================== Test: Rate Limit Percentage ====================

void test_rate_limit_pct_none(void) {
    uint32_t pct = l2_get_rate_limit_pct(L2_ANOMALY_NONE);
    TEST_ASSERT_EQ(100, pct, "NONE should allow 100%");
}

void test_rate_limit_pct_low(void) {
    uint32_t pct = l2_get_rate_limit_pct(L2_ANOMALY_LOW);
    TEST_ASSERT_EQ(80, pct, "LOW should allow 80%");
}

void test_rate_limit_pct_medium(void) {
    uint32_t pct = l2_get_rate_limit_pct(L2_ANOMALY_MEDIUM);
    TEST_ASSERT_EQ(50, pct, "MEDIUM should allow 50%");
}

void test_rate_limit_pct_high(void) {
    uint32_t pct = l2_get_rate_limit_pct(L2_ANOMALY_HIGH);
    TEST_ASSERT_EQ(25, pct, "HIGH should allow 25%");
}

void test_rate_limit_pct_critical(void) {
    uint32_t pct = l2_get_rate_limit_pct(L2_ANOMALY_CRITICAL);
    TEST_ASSERT_EQ(10, pct, "CRITICAL should allow 10%");
}

// ==================== Main ====================

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    // Initialize config with defaults
    struct layer2_config *cfg = layer2_config_get_buffer();
    layer2_config_init_defaults(cfg);

    printf("\n========================================\n");
    printf("  Layer 2 Detection Unit Tests\n");
    printf("========================================\n\n");

    // Z-score level tests
    printf("--- Z-Score Level Classification ---\n");
    RUN_TEST(test_z_score_level_critical_3tier);
    RUN_TEST(test_z_score_level_high_3tier);
    RUN_TEST(test_z_score_level_medium_3tier);
    RUN_TEST(test_z_score_level_low_3tier);
    RUN_TEST(test_z_score_level_2tier);
    RUN_TEST(test_z_score_level_1tier);

    // Confidence tests
    printf("\n--- Confidence Calculation ---\n");
    RUN_TEST(test_confidence_3tier_agreement);
    RUN_TEST(test_confidence_2tier_agreement);
    RUN_TEST(test_confidence_1tier_agreement);
    RUN_TEST(test_confidence_increases_with_z);

    // Anomaly state tests
    printf("\n--- Anomaly State Management ---\n");
    RUN_TEST(test_anomaly_state_init);
    RUN_TEST(test_anomaly_level_name);

    // Baseline poisoning tests
    printf("\n--- Baseline Poisoning Detection ---\n");
    RUN_TEST(test_baseline_poison_tracker_init);
    RUN_TEST(test_baseline_poison_check_disabled);
    RUN_TEST(test_baseline_poison_reset);

    // Rate limit percentage tests
    printf("\n--- Rate Limit Percentages ---\n");
    RUN_TEST(test_rate_limit_pct_none);
    RUN_TEST(test_rate_limit_pct_low);
    RUN_TEST(test_rate_limit_pct_medium);
    RUN_TEST(test_rate_limit_pct_high);
    RUN_TEST(test_rate_limit_pct_critical);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_run);
    printf("========================================\n\n");

    return tests_failed > 0 ? 1 : 0;
}
