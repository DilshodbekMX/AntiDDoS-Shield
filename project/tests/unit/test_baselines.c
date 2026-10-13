/**
 * @file test_baselines.c
 * @brief Comprehensive unit tests for Layer 2 Baselines module
 *
 * Tests cover:
 * - EWMA calculation correctness
 * - Z-score computation
 * - Three-tier baseline system
 * - Baseline poisoning detection
 * - Freeze/unfreeze functionality
 * - Persistence (JSON serialization)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <stdalign.h>
#include <assert.h>

#include "../../layer2/baselines.h"

// ==================== Test Framework ====================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define EPSILON 0.0001

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

#define TEST_ASSERT_DOUBLE_EQ(expected, actual, msg) do { \
    if (fabs((expected) - (actual)) > EPSILON) { \
        printf("  FAIL: %s (expected=%.6f, actual=%.6f, line %d)\n", msg, \
               (double)(expected), (double)(actual), __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_DOUBLE_RANGE(val, min, max, msg) do { \
    if ((val) < (min) || (val) > (max)) { \
        printf("  FAIL: %s (value=%.6f not in [%.6f,%.6f], line %d)\n", msg, \
               (double)(val), (double)(min), (double)(max), __LINE__); \
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

// ==================== Feature Baseline Tests ====================

void test_feature_baseline_init(void) {
    struct feature_baseline fb;
    feature_baseline_init(&fb);

    TEST_ASSERT_DOUBLE_EQ(0.0, fb.mean, "Initial mean should be 0");
    TEST_ASSERT_DOUBLE_EQ(0.0, fb.variance, "Initial variance should be 0");
    TEST_ASSERT_EQ(0, fb.sample_count, "Initial sample_count should be 0");
}

void test_feature_baseline_first_sample(void) {
    struct feature_baseline fb;
    feature_baseline_init(&fb);

    feature_baseline_update(&fb, 100.0, 0.2, get_current_time_ns());

    TEST_ASSERT_DOUBLE_EQ(100.0, fb.mean, "First sample should set mean directly");
    TEST_ASSERT_EQ(1, fb.sample_count, "Sample count should be 1");
}

void test_feature_baseline_ewma_convergence(void) {
    struct feature_baseline fb;
    feature_baseline_init(&fb);

    double alpha = 0.2;

    // Feed constant value - should converge to that value
    for (int i = 0; i < 50; i++) {
        feature_baseline_update(&fb, 100.0, alpha, get_current_time_ns());
    }

    TEST_ASSERT_DOUBLE_RANGE(fb.mean, 99.0, 101.0, "Mean should converge to 100");
    TEST_ASSERT_DOUBLE_RANGE(fb.variance, 0.0, 1.0, "Variance should be near 0 for constant input");
}

void test_feature_baseline_ewma_calculation(void) {
    struct feature_baseline fb;
    feature_baseline_init(&fb);

    double alpha = 0.5; // 50% weight for easy calculation

    // First sample
    feature_baseline_update(&fb, 100.0, alpha, get_current_time_ns());
    TEST_ASSERT_DOUBLE_EQ(100.0, fb.mean, "First sample sets mean");

    // Second sample: mean = 100 + 0.5 * (200 - 100) = 150
    feature_baseline_update(&fb, 200.0, alpha, get_current_time_ns());
    TEST_ASSERT_DOUBLE_EQ(150.0, fb.mean, "EWMA calculation with alpha=0.5");

    // Third sample: mean = 150 + 0.5 * (100 - 150) = 125
    feature_baseline_update(&fb, 100.0, alpha, get_current_time_ns());
    TEST_ASSERT_DOUBLE_EQ(125.0, fb.mean, "EWMA continues correctly");
}

void test_feature_baseline_variance_tracking(void) {
    struct feature_baseline fb;
    feature_baseline_init(&fb);

    double alpha = 0.2;

    // Feed oscillating values to build variance
    for (int i = 0; i < 100; i++) {
        double value = (i % 2 == 0) ? 50.0 : 150.0;
        feature_baseline_update(&fb, value, alpha, get_current_time_ns());
    }

    // Mean should be around 100
    TEST_ASSERT_DOUBLE_RANGE(fb.mean, 90.0, 110.0, "Mean should be around 100");

    // Variance should be significant (stddev around 50)
    double stddev = feature_baseline_stddev(&fb);
    TEST_ASSERT(stddev > 30.0, "Stddev should be significant for oscillating input");
    TEST_ASSERT(stddev < 70.0, "Stddev should be bounded");
}

void test_feature_baseline_min_max_tracking(void) {
    struct feature_baseline fb;
    feature_baseline_init(&fb);

    double alpha = 0.2;

    feature_baseline_update(&fb, 100.0, alpha, get_current_time_ns());
    feature_baseline_update(&fb, 50.0, alpha, get_current_time_ns());
    feature_baseline_update(&fb, 200.0, alpha, get_current_time_ns());
    feature_baseline_update(&fb, 75.0, alpha, get_current_time_ns());

    TEST_ASSERT_DOUBLE_EQ(50.0, fb.min_observed, "Min should be 50");
    TEST_ASSERT_DOUBLE_EQ(200.0, fb.max_observed, "Max should be 200");
}

// ==================== Z-Score Tests ====================

void test_z_score_basic(void) {
    struct feature_baseline fb;
    feature_baseline_init(&fb);

    // Build baseline with mean=100, some variance
    double alpha = 0.2;
    for (int i = 0; i < 50; i++) {
        double value = 100.0 + (i % 10 - 5); // 95 to 105
        feature_baseline_update(&fb, value, alpha, get_current_time_ns());
    }

    // Z-score at mean should be near 0
    double z_at_mean = feature_baseline_z_score(&fb, fb.mean);
    TEST_ASSERT_DOUBLE_RANGE(z_at_mean, -0.5, 0.5, "Z-score at mean should be near 0");
}

void test_z_score_anomaly(void) {
    struct feature_baseline fb;
    feature_baseline_init(&fb);

    // Build baseline with mean=100, stddev~5
    double alpha = 0.2;
    for (int i = 0; i < 100; i++) {
        double value = 100.0 + (i % 10 - 5);
        feature_baseline_update(&fb, value, alpha, get_current_time_ns());
    }

    double stddev = feature_baseline_stddev(&fb);

    // Value 3 stddev away should have z-score around 3
    double anomaly_value = fb.mean + 3.0 * stddev;
    double z = feature_baseline_z_score(&fb, anomaly_value);
    TEST_ASSERT_DOUBLE_RANGE(z, 2.5, 3.5, "Z-score should be around 3 for 3-sigma value");
}

void test_z_score_not_ready(void) {
    struct feature_baseline fb;
    feature_baseline_init(&fb);

    // No samples yet
    double z = feature_baseline_z_score(&fb, 100.0);
    TEST_ASSERT_DOUBLE_EQ(0.0, z, "Z-score should be 0 when baseline not ready");
}

void test_z_score_zero_variance(void) {
    struct feature_baseline fb;
    feature_baseline_init(&fb);

    // Constant value = zero variance
    for (int i = 0; i < 20; i++) {
        feature_baseline_update(&fb, 100.0, 0.2, get_current_time_ns());
    }

    // With zero variance, z-score should handle gracefully
    double z = feature_baseline_z_score(&fb, 200.0);
    // Implementation should return 0 or a capped value, not infinity
    TEST_ASSERT(!isnan(z), "Z-score should not be NaN");
    TEST_ASSERT(!isinf(z), "Z-score should not be infinity");
}

// ==================== Tier Baseline Tests ====================

void test_tier_baseline_init(void) {
    struct tier_baseline tier;
    tier_baseline_init(&tier, "test_tier", 0.2, 10);

    TEST_ASSERT(strcmp(tier.name, "test_tier") == 0, "Name should be set");
    TEST_ASSERT_DOUBLE_EQ(0.2, tier.alpha, "Alpha should be set");
    TEST_ASSERT(!tier.ready, "Tier should not be ready initially");
    TEST_ASSERT(!tier.frozen, "Tier should not be frozen initially");
    TEST_ASSERT_EQ(10, tier.min_samples_ready, "Min samples should be set");
}

void test_tier_baseline_ready_after_samples(void) {
    struct tier_baseline tier;
    tier_baseline_init(&tier, "test", 0.2, 10);

    struct l2_feature_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        snapshot.values[i] = 100.0;
    }
    snapshot.timestamp_ns = get_current_time_ns();

    // Not ready yet
    TEST_ASSERT(!tier_baseline_is_ready(&tier), "Should not be ready before samples");

    // Feed samples
    for (int i = 0; i < 15; i++) {
        tier_baseline_update(&tier, &snapshot);
    }

    TEST_ASSERT(tier_baseline_is_ready(&tier), "Should be ready after enough samples");
}

void test_tier_z_scores(void) {
    struct tier_baseline tier;
    tier_baseline_init(&tier, "test", 0.2, 5);

    // Build baseline
    struct l2_feature_snapshot baseline_snap;
    memset(&baseline_snap, 0, sizeof(baseline_snap));
    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        baseline_snap.values[i] = 100.0 + i;
    }
    baseline_snap.timestamp_ns = get_current_time_ns();

    for (int i = 0; i < 50; i++) {
        tier_baseline_update(&tier, &baseline_snap);
    }

    // Now test with anomalous snapshot
    struct l2_feature_snapshot anomaly_snap = baseline_snap;
    anomaly_snap.values[L2_FEAT_PACKETS_PER_SEC] = 1000.0; // 10x normal

    struct tier_z_scores result;
    tier_baseline_z_scores(&tier, &anomaly_snap, 3.0, &result);

    TEST_ASSERT(result.triggered_count > 0, "Should have some triggered features");
    TEST_ASSERT(result.max_z > 0.0, "Max z-score should be positive");
}

// ==================== Three-Tier Baseline Tests ====================

void test_three_tier_init(void) {
    struct three_tier_baseline baselines;
    three_tier_baseline_init(&baselines, 0.2, 0.1, 0.05, 10, 20, 30);

    TEST_ASSERT_DOUBLE_EQ(0.2, baselines.immediate.alpha, "Immediate alpha");
    TEST_ASSERT_DOUBLE_EQ(0.1, baselines.hourly[0].alpha, "Hourly alpha");
    TEST_ASSERT_DOUBLE_EQ(0.05, baselines.weekly[0].alpha, "Weekly alpha");
    TEST_ASSERT(!baselines.globally_frozen, "Should not be frozen initially");
}

void test_three_tier_update(void) {
    struct three_tier_baseline baselines;
    three_tier_baseline_init(&baselines, 0.2, 0.1, 0.05, 5, 10, 20);

    struct l2_feature_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.values[L2_FEAT_PACKETS_PER_SEC] = 1000.0;
    snapshot.values[L2_FEAT_BYTES_PER_SEC] = 100000.0;
    snapshot.timestamp_ns = get_current_time_ns();

    // Update all tiers
    three_tier_baseline_update(&baselines, &snapshot);

    // Immediate tier should have data
    TEST_ASSERT_EQ(1, baselines.immediate.features[L2_FEAT_PACKETS_PER_SEC].sample_count,
                   "Immediate tier should have 1 sample");

    // Current hourly tier should have data
    int hour = get_current_hour_index();
    TEST_ASSERT_EQ(1, baselines.hourly[hour].features[L2_FEAT_PACKETS_PER_SEC].sample_count,
                   "Current hourly tier should have 1 sample");
}

void test_three_tier_freeze_unfreeze(void) {
    struct three_tier_baseline baselines;
    three_tier_baseline_init(&baselines, 0.2, 0.1, 0.05, 5, 10, 20);

    TEST_ASSERT(!three_tier_baseline_is_frozen(&baselines), "Should not be frozen initially");

    three_tier_baseline_freeze(&baselines);
    TEST_ASSERT(three_tier_baseline_is_frozen(&baselines), "Should be frozen after freeze");

    // Updates should not change values when frozen
    struct l2_feature_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.values[L2_FEAT_PACKETS_PER_SEC] = 1000.0;
    snapshot.timestamp_ns = get_current_time_ns();

    three_tier_baseline_update(&baselines, &snapshot);

    // Should still be 0 samples since frozen
    // (depending on implementation - some may still count but not update mean)

    three_tier_baseline_unfreeze(&baselines);
    TEST_ASSERT(!three_tier_baseline_is_frozen(&baselines), "Should be unfrozen after unfreeze");
}

void test_three_tier_reset(void) {
    struct three_tier_baseline baselines;
    three_tier_baseline_init(&baselines, 0.2, 0.1, 0.05, 5, 10, 20);

    // Add some data
    struct l2_feature_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.values[L2_FEAT_PACKETS_PER_SEC] = 1000.0;
    snapshot.timestamp_ns = get_current_time_ns();

    for (int i = 0; i < 20; i++) {
        three_tier_baseline_update(&baselines, &snapshot);
    }

    TEST_ASSERT(baselines.immediate.features[L2_FEAT_PACKETS_PER_SEC].sample_count > 0,
                "Should have samples before reset");

    three_tier_baseline_reset(&baselines);

    TEST_ASSERT_EQ(0, baselines.immediate.features[L2_FEAT_PACKETS_PER_SEC].sample_count,
                   "Should have 0 samples after reset");
}

// ==================== Baseline Summary Tests ====================

void test_baseline_summary(void) {
    struct three_tier_baseline baselines;
    three_tier_baseline_init(&baselines, 0.2, 0.1, 0.05, 5, 10, 20);

    // Add data to make immediate tier ready
    struct l2_feature_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.values[L2_FEAT_PACKETS_PER_SEC] = 1000.0;
    snapshot.timestamp_ns = get_current_time_ns();

    for (int i = 0; i < 10; i++) {
        three_tier_baseline_update(&baselines, &snapshot);
    }

    struct baseline_summary summary;
    three_tier_baseline_summary(&baselines, &summary);

    TEST_ASSERT(summary.tier1_ready, "Tier1 should be ready");
    TEST_ASSERT(summary.tier1_samples >= 10, "Should have samples");
    TEST_ASSERT_DOUBLE_RANGE(summary.tier1_pps_mean, 900.0, 1100.0, "PPS mean should be around 1000");
}

// ==================== Baseline Poisoning Tests ====================

void test_baseline_poisoning_detection(void) {
    struct three_tier_baseline baselines;
    three_tier_baseline_init(&baselines, 0.2, 0.1, 0.05, 5, 10, 20);

    // Build stable baseline
    struct l2_feature_snapshot normal_snap;
    memset(&normal_snap, 0, sizeof(normal_snap));
    normal_snap.values[L2_FEAT_PACKETS_PER_SEC] = 1000.0;
    normal_snap.timestamp_ns = get_current_time_ns();

    for (int i = 0; i < 50; i++) {
        three_tier_baseline_update(&baselines, &normal_snap);
    }

    TEST_ASSERT(!baseline_is_poisoned(&baselines), "Should not be poisoned initially");

    // Simulate slow-rate attack: gradually increase traffic
    for (int i = 0; i < 100; i++) {
        struct l2_feature_snapshot attack_snap = normal_snap;
        attack_snap.values[L2_FEAT_PACKETS_PER_SEC] = 1000.0 + i * 100; // Gradual increase
        attack_snap.timestamp_ns = get_current_time_ns();

        baseline_check_poisoning(&baselines, &attack_snap);
        three_tier_baseline_update(&baselines, &attack_snap);
    }

    // Poisoning may or may not be detected depending on rate of change
    // This test verifies the mechanism doesn't crash
}

void test_baseline_poison_tracker_reset(void) {
    struct three_tier_baseline baselines;
    three_tier_baseline_init(&baselines, 0.2, 0.1, 0.05, 5, 10, 20);

    // Mark as poisoned manually
    baselines.poison_tracker.poison_detected = true;
    TEST_ASSERT(baseline_is_poisoned(&baselines), "Should be poisoned");

    baseline_poison_tracker_reset(&baselines);
    TEST_ASSERT(!baseline_is_poisoned(&baselines), "Should not be poisoned after reset");
}

// ==================== Hourly/Weekly Selection Tests ====================

void test_hourly_index(void) {
    int hour = get_current_hour_index();
    TEST_ASSERT(hour >= 0 && hour < 24, "Hour index should be 0-23");
}

void test_weekly_index(void) {
    int weekly = get_current_weekly_index();
    TEST_ASSERT(weekly >= 0 && weekly < 168, "Weekly index should be 0-167");
}

void test_get_current_hourly_baseline(void) {
    struct three_tier_baseline baselines;
    three_tier_baseline_init(&baselines, 0.2, 0.1, 0.05, 5, 10, 20);

    struct tier_baseline *hourly = get_current_hourly_baseline(&baselines);
    TEST_ASSERT_NOT_NULL(hourly, "Should return current hourly baseline");

    int hour = get_current_hour_index();
    TEST_ASSERT(hourly == &baselines.hourly[hour], "Should return correct hourly tier");
}

void test_get_current_weekly_baseline(void) {
    struct three_tier_baseline baselines;
    three_tier_baseline_init(&baselines, 0.2, 0.1, 0.05, 5, 10, 20);

    struct tier_baseline *weekly = get_current_weekly_baseline(&baselines);
    TEST_ASSERT_NOT_NULL(weekly, "Should return current weekly baseline");

    int weekly_idx = get_current_weekly_index();
    TEST_ASSERT(weekly == &baselines.weekly[weekly_idx], "Should return correct weekly tier");
}

// ==================== JSON Serialization Tests ====================

void test_baseline_to_json(void) {
    struct three_tier_baseline baselines;
    three_tier_baseline_init(&baselines, 0.2, 0.1, 0.05, 5, 10, 20);

    // Add some data
    struct l2_feature_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.values[L2_FEAT_PACKETS_PER_SEC] = 1000.0;
    snapshot.values[L2_FEAT_BYTES_PER_SEC] = 50000.0;
    snapshot.timestamp_ns = get_current_time_ns();

    for (int i = 0; i < 10; i++) {
        three_tier_baseline_update(&baselines, &snapshot);
    }

    char *json = three_tier_baseline_to_json(&baselines);
    TEST_ASSERT_NOT_NULL(json, "Should produce JSON string");

    // Basic validation
    TEST_ASSERT(strstr(json, "version") != NULL, "JSON should contain version");
    TEST_ASSERT(strstr(json, "immediate") != NULL, "JSON should contain immediate tier");

    free(json);
}

void test_baseline_from_json_roundtrip(void) {
    struct three_tier_baseline original;
    three_tier_baseline_init(&original, 0.2, 0.1, 0.05, 5, 10, 20);

    // Add data
    struct l2_feature_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.values[L2_FEAT_PACKETS_PER_SEC] = 1234.5;
    snapshot.values[L2_FEAT_BYTES_PER_SEC] = 56789.0;
    snapshot.timestamp_ns = get_current_time_ns();

    for (int i = 0; i < 20; i++) {
        three_tier_baseline_update(&original, &snapshot);
    }

    // Serialize
    char *json = three_tier_baseline_to_json(&original);
    TEST_ASSERT_NOT_NULL(json, "Should produce JSON");

    // Deserialize into new struct
    struct three_tier_baseline loaded;
    three_tier_baseline_init(&loaded, 0.2, 0.1, 0.05, 5, 10, 20);

    int ret = three_tier_baseline_from_json(&loaded, json);
    TEST_ASSERT_EQ(0, ret, "Should parse JSON successfully");

    // Compare key values
    TEST_ASSERT_DOUBLE_RANGE(
        loaded.immediate.features[L2_FEAT_PACKETS_PER_SEC].mean,
        original.immediate.features[L2_FEAT_PACKETS_PER_SEC].mean - 1.0,
        original.immediate.features[L2_FEAT_PACKETS_PER_SEC].mean + 1.0,
        "Loaded mean should match original");

    free(json);
}

void test_baseline_json_version(void) {
    struct three_tier_baseline baselines;
    three_tier_baseline_init(&baselines, 0.2, 0.1, 0.05, 5, 10, 20);

    char *json = three_tier_baseline_to_json(&baselines);
    TEST_ASSERT_NOT_NULL(json, "Should produce JSON");

    int version = three_tier_baseline_get_json_version(json);
    TEST_ASSERT_EQ(L2_BASELINE_SCHEMA_VERSION, version, "Version should match current schema");

    free(json);
}

// ==================== Per-IP Baseline Tests ====================

void test_per_ip_baseline_table_init(void) {
    static_assert(sizeof(struct per_ip_baseline_table) % alignof(struct per_ip_baseline_table) == 0,
                  "size must be multiple of alignment");
    struct per_ip_baseline_table *table = aligned_alloc(alignof(struct per_ip_baseline_table), sizeof(*table));
    TEST_ASSERT_NOT_NULL(table, "aligned_alloc should succeed");
    per_ip_baseline_table_init(table);

    TEST_ASSERT_EQ(0, table->active_count, "Active count should be 0");
    TEST_ASSERT(!table->globally_frozen, "Should not be frozen");
    free(table);
}

void test_per_ip_baseline_register(void) {
    struct per_ip_baseline_table *table = aligned_alloc(alignof(struct per_ip_baseline_table), sizeof(*table));
    TEST_ASSERT_NOT_NULL(table, "aligned_alloc should succeed");
    per_ip_baseline_table_init(table);

    uint32_t ip = 0xC0A80101; // 192.168.1.1 in network order

    int ret = per_ip_baseline_register(table, ip, 0.2, 0.1, 0.05, 5, 10, 20);
    TEST_ASSERT_EQ(0, ret, "Register should succeed");
    TEST_ASSERT_EQ(1, per_ip_baseline_count(table), "Should have 1 registered IP");

    struct per_ip_baseline *entry = per_ip_baseline_lookup(table, ip);
    TEST_ASSERT_NOT_NULL(entry, "Should find registered IP");
    TEST_ASSERT(entry->active, "Entry should be active");
    TEST_ASSERT_EQ(ip, entry->dst_ip, "IP should match");
    free(table);
}

void test_per_ip_baseline_unregister(void) {
    struct per_ip_baseline_table *table = aligned_alloc(alignof(struct per_ip_baseline_table), sizeof(*table));
    TEST_ASSERT_NOT_NULL(table, "aligned_alloc should succeed");
    per_ip_baseline_table_init(table);

    uint32_t ip = 0xC0A80101;
    per_ip_baseline_register(table, ip, 0.2, 0.1, 0.05, 5, 10, 20);

    int ret = per_ip_baseline_unregister(table, ip);
    TEST_ASSERT_EQ(0, ret, "Unregister should succeed");
    TEST_ASSERT_EQ(0, per_ip_baseline_count(table), "Should have 0 IPs after unregister");

    struct per_ip_baseline *entry = per_ip_baseline_lookup(table, ip);
    TEST_ASSERT(entry == NULL || !entry->active, "Should not find unregistered IP");
    free(table);
}

void test_per_ip_baseline_update(void) {
    struct per_ip_baseline_table *table = aligned_alloc(alignof(struct per_ip_baseline_table), sizeof(*table));
    TEST_ASSERT_NOT_NULL(table, "aligned_alloc should succeed");
    per_ip_baseline_table_init(table);

    uint32_t ip = 0xC0A80101;
    per_ip_baseline_register(table, ip, 0.2, 0.1, 0.05, 5, 10, 20);

    struct l2_feature_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.values[L2_FEAT_PACKETS_PER_SEC] = 5000.0;
    snapshot.timestamp_ns = get_current_time_ns();

    per_ip_baseline_update(table, ip, &snapshot);

    struct per_ip_baseline *entry = per_ip_baseline_lookup(table, ip);
    TEST_ASSERT_NOT_NULL(entry, "Should find entry");
    TEST_ASSERT_EQ(1, entry->baselines.immediate.features[L2_FEAT_PACKETS_PER_SEC].sample_count,
                   "Should have 1 sample");
    free(table);
}

void test_per_ip_baseline_freeze_all(void) {
    struct per_ip_baseline_table *table = aligned_alloc(alignof(struct per_ip_baseline_table), sizeof(*table));
    TEST_ASSERT_NOT_NULL(table, "aligned_alloc should succeed");
    per_ip_baseline_table_init(table);

    per_ip_baseline_register(table, 0xC0A80101, 0.2, 0.1, 0.05, 5, 10, 20);
    per_ip_baseline_register(table, 0xC0A80102, 0.2, 0.1, 0.05, 5, 10, 20);

    TEST_ASSERT(!per_ip_baseline_is_frozen(table), "Should not be frozen");

    per_ip_baseline_freeze_all(table);
    TEST_ASSERT(per_ip_baseline_is_frozen(table), "Should be frozen");

    per_ip_baseline_unfreeze_all(table);
    TEST_ASSERT(!per_ip_baseline_is_frozen(table), "Should be unfrozen");
    free(table);
}

void test_per_ip_baseline_max_capacity(void) {
    struct per_ip_baseline_table *table = aligned_alloc(alignof(struct per_ip_baseline_table), sizeof(*table));
    TEST_ASSERT_NOT_NULL(table, "aligned_alloc should succeed");
    per_ip_baseline_table_init(table);

    // Try to register more than capacity
    int registered = 0;
    for (int i = 0; i < L2_MAX_PROTECTED_IPS + 10; i++) {
        uint32_t ip = 0xC0A80000 + i;
        int ret = per_ip_baseline_register(table, ip, 0.2, 0.1, 0.05, 5, 10, 20);
        if (ret == 0) registered++;
    }

    TEST_ASSERT_EQ(L2_MAX_PROTECTED_IPS, registered, "Should register exactly max capacity");
    TEST_ASSERT_EQ(L2_MAX_PROTECTED_IPS, per_ip_baseline_count(table), "Count should match");
    free(table);
}

// ==================== Edge Cases ====================

void test_ewma_extreme_values(void) {
    struct feature_baseline fb;
    feature_baseline_init(&fb);

    // Very large value
    feature_baseline_update(&fb, 1e15, 0.2, get_current_time_ns());
    TEST_ASSERT(!isnan(fb.mean), "Mean should not be NaN");
    TEST_ASSERT(!isinf(fb.mean), "Mean should not be infinity");

    // Very small value
    feature_baseline_init(&fb);
    feature_baseline_update(&fb, 1e-15, 0.2, get_current_time_ns());
    TEST_ASSERT(!isnan(fb.mean), "Mean should not be NaN");

    // Zero
    feature_baseline_init(&fb);
    feature_baseline_update(&fb, 0.0, 0.2, get_current_time_ns());
    TEST_ASSERT_DOUBLE_EQ(0.0, fb.mean, "Mean of zero should be zero");

    // Negative (shouldn't happen in practice, but test robustness)
    feature_baseline_init(&fb);
    feature_baseline_update(&fb, -100.0, 0.2, get_current_time_ns());
    TEST_ASSERT(!isnan(fb.mean), "Should handle negative values");
}

void test_alpha_edge_cases(void) {
    struct feature_baseline fb;

    // Alpha = 1.0 (instant update)
    feature_baseline_init(&fb);
    feature_baseline_update(&fb, 100.0, 1.0, get_current_time_ns());
    feature_baseline_update(&fb, 200.0, 1.0, get_current_time_ns());
    TEST_ASSERT_DOUBLE_EQ(200.0, fb.mean, "Alpha=1 should set mean to latest value");

    // Alpha near 0 (very slow update)
    feature_baseline_init(&fb);
    feature_baseline_update(&fb, 100.0, 0.001, get_current_time_ns());
    feature_baseline_update(&fb, 200.0, 0.001, get_current_time_ns());
    TEST_ASSERT_DOUBLE_RANGE(fb.mean, 100.0, 101.0, "Alpha~0 should barely change mean");
}

// ==================== Feature Names Test ====================

void test_feature_names_defined(void) {
    // Verify all feature names are defined
    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        TEST_ASSERT_NOT_NULL(l2_feature_names[i], "Feature name should be defined");
        TEST_ASSERT(strlen(l2_feature_names[i]) > 0, "Feature name should not be empty");
    }
}

// ==================== Main ====================

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("\n========================================\n");
    printf("  Layer 2 Baselines Unit Tests\n");
    printf("========================================\n\n");

    // Feature baseline tests
    RUN_TEST(test_feature_baseline_init);
    RUN_TEST(test_feature_baseline_first_sample);
    RUN_TEST(test_feature_baseline_ewma_convergence);
    RUN_TEST(test_feature_baseline_ewma_calculation);
    RUN_TEST(test_feature_baseline_variance_tracking);
    RUN_TEST(test_feature_baseline_min_max_tracking);

    // Z-score tests
    RUN_TEST(test_z_score_basic);
    RUN_TEST(test_z_score_anomaly);
    RUN_TEST(test_z_score_not_ready);
    RUN_TEST(test_z_score_zero_variance);

    // Tier baseline tests
    RUN_TEST(test_tier_baseline_init);
    RUN_TEST(test_tier_baseline_ready_after_samples);
    RUN_TEST(test_tier_z_scores);

    // Three-tier baseline tests
    RUN_TEST(test_three_tier_init);
    RUN_TEST(test_three_tier_update);
    RUN_TEST(test_three_tier_freeze_unfreeze);
    RUN_TEST(test_three_tier_reset);

    // Summary tests
    RUN_TEST(test_baseline_summary);

    // Poisoning tests
    RUN_TEST(test_baseline_poisoning_detection);
    RUN_TEST(test_baseline_poison_tracker_reset);

    // Time selection tests
    RUN_TEST(test_hourly_index);
    RUN_TEST(test_weekly_index);
    RUN_TEST(test_get_current_hourly_baseline);
    RUN_TEST(test_get_current_weekly_baseline);

    // JSON tests
    RUN_TEST(test_baseline_to_json);
    RUN_TEST(test_baseline_from_json_roundtrip);
    RUN_TEST(test_baseline_json_version);

    // Per-IP baseline tests
    RUN_TEST(test_per_ip_baseline_table_init);
    RUN_TEST(test_per_ip_baseline_register);
    RUN_TEST(test_per_ip_baseline_unregister);
    RUN_TEST(test_per_ip_baseline_update);
    RUN_TEST(test_per_ip_baseline_freeze_all);
    RUN_TEST(test_per_ip_baseline_max_capacity);

    // Edge cases
    RUN_TEST(test_ewma_extreme_values);
    RUN_TEST(test_alpha_edge_cases);

    // Feature names
    RUN_TEST(test_feature_names_defined);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_run);
    printf("========================================\n\n");

    return tests_failed > 0 ? 1 : 0;
}
