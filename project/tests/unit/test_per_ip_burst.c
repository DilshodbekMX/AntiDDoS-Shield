/**
 * @file test_per_ip_burst.c
 * @brief Wiring test for the per-IP burst_factor (Phase 2) in per_ip_features.c and
 *        per_ip_features_v6.c: the snapshot previews 100 * window_pps / post-update EWMA
 *        and the window roll (reset_window) commits the same rate, once per window.
 *
 * Requires DPDK EAL (rte_hash / rte_malloc) -- runs with --no-huge --in-memory like the
 * other per-module tests and exits 77 (skip) if EAL cannot initialise.
 *
 * Each synthetic window forces previous.timestamp_ns = 0 so the snapshot uses its 1-second
 * default window and packets_per_sec equals the injected packet count exactly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <arpa/inet.h>

#include <rte_eal.h>

#include "../../layer1/telemetry/per_ip_features.h"
#include "../../layer1/telemetry/per_ip_features_v6.h"
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

// ==================== Helpers ====================

static const uint32_t TEST_IP4 = 0x0100000A;  // 10.0.0.1 in network byte order (LE host)
static const uint8_t  TEST_IP6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0x01 };

/* One synthetic window on a v4 slot: inject pkts, snapshot (export), roll the window. */
static int window_v4(struct per_ip_features *pif, uint64_t pkts,
                     struct per_ip_feature_snapshot *snap) {
    pif->previous.timestamp_ns = 0;               // 1-second default window -> pps == pkts
    pif->lcore_counters[0].rx_packets += pkts;
    int rc = per_ip_features_snapshot(pif->dst_ip, snap);
    per_ip_features_reset_window(pif);
    return rc;
}

static int window_v6(struct per_ip_features_v6 *pif, uint64_t pkts,
                     struct per_ip_feature_snapshot_v6 *snap) {
    pif->previous.timestamp_ns = 0;
    pif->lcore_counters[0].rx_packets += pkts;
    int rc = per_ip_features_v6_snapshot(pif->dst_ip6, snap);
    per_ip_features_v6_reset_window(pif);
    return rc;
}

// ==================== Tests (IPv4) ====================

static void test_v4_seed_steady_burst_saturation(void) {
    TEST_ASSERT_EQ(0, per_ip_features_register(TEST_IP4), "register v4");
    struct per_ip_features *pif = per_ip_features_lookup(TEST_IP4);
    TEST_ASSERT(pif != NULL, "lookup v4");
    TEST_ASSERT_DOUBLE_EQ(0.0, pif->burst_ewma_pps, "fresh slot is unseeded (0.0)");
    TEST_ASSERT_EQ(0, pif->burst_window_valid, "fresh slot has no parked window rate");

    struct per_ip_feature_snapshot snap;

    // Seed: first window becomes the mean, ratio 100.
    TEST_ASSERT_EQ(0, window_v4(pif, 1000, &snap), "snapshot ok");
    TEST_ASSERT_EQ(1000, snap.packets_per_sec, "pps equals injected count (1 s window)");
    TEST_ASSERT_EQ(100, snap.burst_factor, "seed window -> 100");
    TEST_ASSERT_DOUBLE_EQ(1000.0, pif->burst_ewma_pps, "reset committed the seed");
    TEST_ASSERT_EQ(0, pif->burst_window_valid, "reset consumed the parked rate");

    // Steady state: ratio exactly 100, mean unchanged.
    for (int w = 0; w < 30; w++) {
        window_v4(pif, 1000, &snap);
        TEST_ASSERT_EQ(100, snap.burst_factor, "steady state -> 100");
        TEST_ASSERT_DOUBLE_EQ(1000.0, pif->burst_ewma_pps, "steady state mean stays 1000");
    }

    // 4x burst: ratio against the post-update mean 1000 + 0.033*3000 = 1099 -> 363.
    window_v4(pif, 4000, &snap);
    TEST_ASSERT_EQ(4000, snap.packets_per_sec, "burst pps");
    TEST_ASSERT_EQ(363, snap.burst_factor, "4x burst -> 363");
    TEST_ASSERT_DOUBLE_EQ(1099.0, pif->burst_ewma_pps, "reset committed the SAME rate the snapshot exported");

    // Saturation: a 10^6x window is bounded by floor(100/alpha) = 3030.
    window_v4(pif, 1000000000ULL, &snap);
    TEST_ASSERT(snap.burst_factor <= BURST_FACTOR_SATURATION, "bounded by 100/alpha");
    TEST_ASSERT(snap.burst_factor >= BURST_FACTOR_SATURATION - 1, "sits at the bound");
}

static void test_v4_snapshot_is_a_preview_not_a_commit(void) {
    struct per_ip_features *pif = per_ip_features_lookup(TEST_IP4);
    TEST_ASSERT(pif != NULL, "lookup v4");

    // Bring the mean to a known value first.
    struct per_ip_feature_snapshot snap;
    pif->burst_ewma_pps = 1000.0;
    window_v4(pif, 1000, &snap);
    TEST_ASSERT_DOUBLE_EQ(1000.0, pif->burst_ewma_pps, "known mean");

    // Two snapshots in the same window (global aggregate + per-IP export) must not
    // double-update the EWMA: the mean only moves at the window roll.
    pif->previous.timestamp_ns = 0;
    pif->lcore_counters[0].rx_packets += 4000;
    per_ip_features_snapshot(TEST_IP4, &snap);
    TEST_ASSERT_EQ(363, snap.burst_factor, "first snapshot previews 363");
    TEST_ASSERT_DOUBLE_EQ(1000.0, pif->burst_ewma_pps, "mean untouched by snapshot #1");
    pif->previous.timestamp_ns = 0;
    per_ip_features_snapshot(TEST_IP4, &snap);
    TEST_ASSERT_EQ(363, snap.burst_factor, "second snapshot previews the same 363");
    TEST_ASSERT_DOUBLE_EQ(1000.0, pif->burst_ewma_pps, "mean untouched by snapshot #2");
    TEST_ASSERT_EQ(1, pif->burst_window_valid, "window rate parked for the commit");

    per_ip_features_reset_window(pif);
    TEST_ASSERT_DOUBLE_EQ(1099.0, pif->burst_ewma_pps, "one commit at the roll: 1000 + alpha*3000");
    TEST_ASSERT_EQ(0, pif->burst_window_valid, "parked rate consumed");
}

static void test_v4_reset_without_snapshot_derives_rate(void) {
    struct per_ip_features *pif = per_ip_features_lookup(TEST_IP4);
    TEST_ASSERT(pif != NULL, "lookup v4");

    struct per_ip_feature_snapshot snap;
    pif->burst_ewma_pps = 1000.0;
    window_v4(pif, 1000, &snap);
    TEST_ASSERT_EQ(0, pif->burst_window_valid, "start with nothing parked");

    // A slot outside the export selection: the selection path aggregates it
    // (per_ip_window_volume) but never snapshots it. The roll must still commit
    // this window's rate, derived from the counters with the snapshot's delta rule.
    pif->previous.timestamp_ns = 0;
    pif->lcore_counters[0].rx_packets += 500;
    per_ip_features_aggregate(pif);
    per_ip_features_reset_window(pif);
    TEST_ASSERT_DOUBLE_EQ(burst_ewma_step(1000.0, 500.0), pif->burst_ewma_pps,
                          "fallback commits 1000 + alpha*(500-1000)");
}

// ==================== Tests (IPv6) ====================

static void test_v6_seed_steady_burst_saturation(void) {
    TEST_ASSERT_EQ(0, per_ip_features_v6_register(TEST_IP6), "register v6");
    struct per_ip_features_v6 *pif = per_ip_features_v6_lookup(TEST_IP6);
    TEST_ASSERT(pif != NULL, "lookup v6");
    TEST_ASSERT_DOUBLE_EQ(0.0, pif->burst_ewma_pps, "fresh v6 slot is unseeded");

    struct per_ip_feature_snapshot_v6 snap;

    window_v6(pif, 2000, &snap);
    TEST_ASSERT_EQ(2000, snap.packets_per_sec, "v6 pps equals injected count");
    TEST_ASSERT_EQ(100, snap.burst_factor, "v6 seed -> 100");
    TEST_ASSERT_DOUBLE_EQ(2000.0, pif->burst_ewma_pps, "v6 seed committed");

    for (int w = 0; w < 30; w++) {
        window_v6(pif, 2000, &snap);
        TEST_ASSERT_EQ(100, snap.burst_factor, "v6 steady -> 100");
    }

    window_v6(pif, 8000, &snap);
    TEST_ASSERT_EQ(363, snap.burst_factor, "v6 4x burst -> 363");
    TEST_ASSERT_DOUBLE_EQ(2198.0, pif->burst_ewma_pps, "v6 committed 2000 + alpha*6000");

    window_v6(pif, 2000000000ULL, &snap);
    TEST_ASSERT(snap.burst_factor <= BURST_FACTOR_SATURATION, "v6 bounded by 100/alpha");
    TEST_ASSERT(snap.burst_factor >= BURST_FACTOR_SATURATION - 1, "v6 sits at the bound");
}

// ==================== Main ====================

int main(int argc __attribute__((unused)), char **argv) {
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
    printf("  Per-IP burst_factor Wiring Tests\n");
    printf("========================================\n\n");

    if (per_ip_features_init(16) != 0 || per_ip_features_v6_init(8) != 0) {
        fprintf(stderr, "per_ip_features init failed\n");
        return 1;
    }

    RUN_TEST(test_v4_seed_steady_burst_saturation);
    RUN_TEST(test_v4_snapshot_is_a_preview_not_a_commit);
    RUN_TEST(test_v4_reset_without_snapshot_derives_rate);
    RUN_TEST(test_v6_seed_steady_burst_saturation);

    per_ip_features_v6_cleanup();
    per_ip_features_cleanup();

    printf("\n========================================\n");
    printf("  Results: %d/%d passed, %d failed\n", tests_passed, tests_run, tests_failed);
    printf("========================================\n\n");

    return tests_failed ? 1 : 0;
}
