/**
 * @file test_burst_ewma.c
 * @brief Unit tests for the shared burst_factor EWMA (layer1/telemetry/burst_ewma.h)
 *
 * Pure C, no DPDK. Feeds synthetic sequences of per-window packet rates and checks:
 * - the seed (first window becomes the mean, ratio 100)
 * - the steady state (constant rate -> ratio exactly 100)
 * - a 4x burst -> ratio 100*4/(1 + alpha*3) = 363 at alpha = 0.033 (post-update mean)
 * - the saturation bound 100/alpha (3030): monotone in x, never exceeded, no uint16 overflow
 * - re-seeding after the mean decays below the seed floor
 * - bit-for-bit equivalence with the historical aggregate-path literal code that
 *   burst_ewma_update() replaced in shared_memory.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

#include "../../layer1/telemetry/burst_ewma.h"

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

#define TEST_ASSERT_DOUBLE_EQ(expected, actual, msg) do { \
    if (fabs((expected) - (actual)) > 1e-9) { \
        printf("  FAIL: %s (expected=%.9f, actual=%.9f, line %d)\n", msg, \
               (double)(expected), (double)(actual), __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define RUN_TEST(test_func) do { \
    printf("Running %s...\n", #test_func); \
    tests_run++; \
    int before = tests_failed; \
    test_func(); \
    if (tests_failed == before) { tests_passed++; printf("  PASS\n"); } \
} while(0)

// ==================== Tests ====================

static void test_constant_is_the_aggregate_alpha(void) {
    // The task's contract: alpha is the aggregate path's 0.033 and is defined exactly once.
    TEST_ASSERT_DOUBLE_EQ(0.033, BURST_EWMA_ALPHA, "alpha is 0.033");
    TEST_ASSERT_EQ(3030, BURST_FACTOR_SATURATION, "saturation bound is floor(100/alpha) = 3030");
    TEST_ASSERT_EQ(100, BURST_FACTOR_NORMAL, "normal ratio is 100");
}

static void test_seed_first_window(void) {
    double mean = 0.0;   // freshly registered slot: memset -> 0.0 -> unseeded
    uint16_t r = burst_ewma_update(&mean, 1000.0);
    TEST_ASSERT_DOUBLE_EQ(1000.0, mean, "first window seeds the mean");
    TEST_ASSERT_EQ(100, r, "seed window reports 100");
}

static void test_no_traffic_then_seed(void) {
    double mean = 0.0;
    uint16_t r = burst_ewma_update(&mean, 0.0);
    TEST_ASSERT_DOUBLE_EQ(0.0, mean, "zero window on an unseeded mean leaves it unseeded");
    TEST_ASSERT_EQ(BURST_FACTOR_NORMAL, r, "no mean to divide by -> 100");
    r = burst_ewma_update(&mean, 500.0);
    TEST_ASSERT_DOUBLE_EQ(500.0, mean, "first non-zero window seeds");
    TEST_ASSERT_EQ(100, r, "seed reports 100");
}

static void test_steady_state_is_100(void) {
    double mean = 0.0;
    burst_ewma_update(&mean, 1000.0);
    for (int w = 0; w < 200; w++) {
        uint16_t r = burst_ewma_update(&mean, 1000.0);
        TEST_ASSERT_EQ(100, r, "constant rate -> ratio 100 every window");
        TEST_ASSERT_DOUBLE_EQ(1000.0, mean, "constant rate -> mean unchanged");
    }
}

static void test_burst_4x(void) {
    double mean = 0.0;
    burst_ewma_update(&mean, 1000.0);
    for (int w = 0; w < 50; w++) burst_ewma_update(&mean, 1000.0);

    uint16_t r = burst_ewma_update(&mean, 4000.0);

    // Post-update mean: 1000 + 0.033 * (4000 - 1000) = 1099
    TEST_ASSERT_DOUBLE_EQ(1099.0, mean, "post-update mean 1000 + alpha*3000");
    // Ratio against the POST-update mean: 4000*100/1099 = 363.97 -> 363 (not 400)
    uint16_t expected = (uint16_t)(4000.0 * 100.0 / (1000.0 + BURST_EWMA_ALPHA * 3000.0));
    TEST_ASSERT_EQ(363, expected, "arithmetic check of the expected 4x ratio");
    TEST_ASSERT_EQ(expected, r, "4x burst -> 363 (divides by the post-update mean)");

    // The mean has moved: a second identical window ratios lower still.
    uint16_t r2 = burst_ewma_update(&mean, 4000.0);
    TEST_ASSERT(r2 < r, "sustained burst decays as the mean catches up");
}

static void test_saturation_bound(void) {
    const uint16_t bound = BURST_FACTOR_SATURATION;

    // Monotone in x for a fixed seeded mean, never above floor(100/alpha).
    uint16_t prev = 0;
    for (int k = 0; k <= 40; k++) {
        double mean = 1000.0;
        double x = 1000.0 * (double)(1ULL << k);
        uint16_t r = burst_ewma_update(&mean, x);
        TEST_ASSERT(r <= bound, "ratio never exceeds 100/alpha");
        TEST_ASSERT(r >= prev, "ratio is monotone non-decreasing in x");
        prev = r;
    }

    // A 10^6 x burst sits at the bound, not at 10^8.
    double mean = 1000.0;
    uint16_t r = burst_ewma_update(&mean, 1e9);
    TEST_ASSERT(r >= bound - 1 && r <= bound, "1e6x burst saturates at ~3030");

    // Even an absurd input stays in uint16 range and at the bound.
    mean = 1.0;   // smallest seeded mean
    r = burst_ewma_update(&mean, 1e15);
    TEST_ASSERT_EQ(bound, r, "smallest seeded mean + huge x = exactly floor(100/alpha)");
}

static void test_reseed_after_quiet(void) {
    double mean = 0.0;
    burst_ewma_update(&mean, 1000.0);

    // Traffic stops: ratio 0, mean decays geometrically.
    for (int w = 0; w < 300; w++) {
        uint16_t r = burst_ewma_update(&mean, 0.0);
        if (mean >= BURST_EWMA_SEED_FLOOR) {
            TEST_ASSERT_EQ(0, r, "no packets against a seeded mean -> 0");
        }
    }
    TEST_ASSERT(mean < BURST_EWMA_SEED_FLOOR, "300 quiet windows decay the mean below the seed floor");

    // Traffic returns: re-seed, report 100 -- not 1000*100/0.04.
    uint16_t r = burst_ewma_update(&mean, 1000.0);
    TEST_ASSERT_DOUBLE_EQ(1000.0, mean, "returning traffic re-seeds");
    TEST_ASSERT_EQ(100, r, "re-seed window reports 100");
}

/* The literal code that lived in shared_memory.c:l2_features_export_update() before the
 * refactor, kept verbatim so the replacement is provably behaviour-preserving. */
static uint16_t legacy_aggregate_step(double *ewma_pps, double current_pps_d) {
    if (*ewma_pps < 1.0)
        *ewma_pps = current_pps_d;  // Seed on first call
    else
        *ewma_pps = *ewma_pps + 0.033 * (current_pps_d - *ewma_pps);  // ~30s EWMA
    return (*ewma_pps > 0.0) ? (uint16_t)(current_pps_d * 100.0 / *ewma_pps) : 100;
}

static void test_bit_identical_to_legacy_aggregate_code(void) {
    double m_new = 0.0, m_old = 0.0;
    uint64_t lcg = 0x9E3779B97F4A7C15ULL;
    for (int w = 0; w < 20000; w++) {
        lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
        uint64_t u = lcg >> 33;
        // Mixed regime: mostly ~1000 pps, occasional bursts, occasional silence.
        double x;
        if ((u % 17) == 0)      x = 0.0;
        else if ((u % 23) == 0) x = (double)(u % 1000000);
        else                    x = (double)(900 + (u % 200));
        uint16_t a = burst_ewma_update(&m_new, x);
        uint16_t b = legacy_aggregate_step(&m_old, x);
        TEST_ASSERT_EQ(b, a, "ratio identical to the legacy literal code");
        TEST_ASSERT(m_new == m_old, "mean bit-identical to the legacy literal code");
    }
}

// ==================== Main ====================

int main(void) {
    printf("\n========================================\n");
    printf("  burst_factor EWMA Unit Tests\n");
    printf("========================================\n\n");

    RUN_TEST(test_constant_is_the_aggregate_alpha);
    RUN_TEST(test_seed_first_window);
    RUN_TEST(test_no_traffic_then_seed);
    RUN_TEST(test_steady_state_is_100);
    RUN_TEST(test_burst_4x);
    RUN_TEST(test_saturation_bound);
    RUN_TEST(test_reseed_after_quiet);
    RUN_TEST(test_bit_identical_to_legacy_aggregate_code);

    printf("\n========================================\n");
    printf("  Results: %d/%d passed, %d failed\n", tests_passed, tests_run, tests_failed);
    printf("========================================\n\n");

    return tests_failed ? 1 : 0;
}
