/*
 * Layer 2 per-window detection microbenchmark (no DPDK runtime / no hugepages).
 *
 * Measures the CPU cost of ONE per-(IP,second) detection cycle on the production
 * C engine: three-tier EWMA baseline update + z-score tier-agreement detection +
 * CUSUM detection over all 39 features. (JSD over the 4-component protocol
 * distribution is a small constant on top and is omitted here.) This is the
 * 1 Hz per-IP work the shipped engine does; it bounds how many protected IPs a
 * single core can sustain.
 *
 * Build (liblayer2.a already compiled in build/):
 *   see compile command in the runner.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "baselines.h"
#include "detection.h"
#include "advanced_detection.h"

static inline uint64_t now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

int main(void) {
    static struct three_tier_baseline bl;     // ~1.5 MB (193 tiers) -> static
    struct cusum_detector cusum;
    struct l2_feature_snapshot snap;
    struct detection_result res;
    uint64_t triggered = 0;

    three_tier_baseline_init(&bl, 0.2, 0.1, 0.05, 10, 20, 40);
    cusum_detector_init(&cusum, 0.25, 5.0);

    /* synthetic benign-ish feature vector */
    for (int i = 0; i < L2_MAX_FEATURES; i++) snap.values[i] = 10.0 + (i % 7);
    snap.timestamp_ns = now_ns();

    /* warm the baselines so we time the steady-state cost */
    for (int w = 0; w < 200; w++) {
        snap.timestamp_ns += 1000000000ull;
        for (int i = 0; i < L2_MAX_FEATURES; i++)
            snap.values[i] = 10.0 + (i % 7) + ((w * 13 + i) % 5) * 0.5;
        three_tier_baseline_update(&bl, &snap);
    }

    const int ITERS = 2000000;
    volatile int sink = 0;
    uint64_t t0 = now_ns();
    for (int it = 0; it < ITERS; it++) {
        snap.timestamp_ns += 1000000000ull;
        /* vary one feature so the work isn't constant-folded */
        snap.values[it % L2_MAX_FEATURES] = 10.0 + (double)(it % 23);
        three_tier_baseline_update(&bl, &snap);
        l2_detect_anomaly(&bl, &snap, 6.0, 2, &res);
        sink += (int)cusum_detect(&cusum, &snap, &bl.immediate, &triggered);
        sink += res.detected;
    }
    uint64_t t1 = now_ns();

    double ns_total = (double)(t1 - t0);
    double ns_per = ns_total / ITERS;
    double wps = 1e9 / ns_per;
    printf("L2 per-window detection cycle (update + z-detect + CUSUM, 39 features):\n");
    printf("  iterations      : %d\n", ITERS);
    printf("  ns / window     : %.1f ns\n", ns_per);
    printf("  windows / sec   : %.0f  (per core)\n", wps);
    printf("  => one core sustains the 1 Hz per-IP cycle for ~%.0f protected IPs\n", wps);
    printf("  (sink=%d)\n", sink);
    return 0;
}
