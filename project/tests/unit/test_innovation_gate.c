/* Unit tests for the innovation-gated z-path latch (layer2/innovation_gate.c).
 * Pure C, no DPDK. The gate now scores the AnEWMA one-step forecast error on the RAW feature
 * values (slow forecast, lambda=0.01), standardized by the benign residual mean/std. Verifies
 * the core latch invariant AND the "calibrate over the FULL benign warmup, then arm" semantics:
 * the latch stays FAIL-OPEN for the ENTIRE benign warmup (never suppressing the z-path) even
 * after MIN_CALIB benign windows have been seen; it ARMS only when the caller signals the benign
 * baseline warmup is COMPLETE (`warm_complete`), at which point the benign stats FREEZE and the
 * latch begins gating from a CLOSED state. Once armed, a STEADY benign feature is UNSURPRISING
 * so the latch stays CLOSED (z-path gated off on benign cross-day drift), while a SHARP RAW JUMP
 * is SURPRISING and OPENS the latch (a real onset is never suppressed). Also checks NULL /
 * uninitialized fail-open safety.
 *
 * NB: with the SLOW lambda=0.01 forecast a SUSTAINED high level stays surprising for a long
 * time (the forecast does not "catch up" to it -- the whole point of AnEWMA). Re-closing is
 * therefore tested by RETURNING TO THE BENIGN LEVEL, not by holding the new high level. */
#include "layer2/innovation_gate.h"
#include <stdio.h>
#include <string.h>

static int passed = 0, total = 0;
#define CHECK(cond, name) do { total++; if (cond) { passed++; } \
    else { printf("  FAIL: %s\n", name); } } while (0)

/* Build a raw feature vector that is `val` on feature 0 (packets_per_sec, a NON-log feature)
 * and 0 elsewhere. */
static void set_feat(double *x, size_t n, double val) {
    for (size_t i = 0; i < n; i++) x[i] = 0.0;
    if (n > 0) x[0] = val;
}

int main(void) {
    printf("=== innovation_gate unit tests ===\n");

    struct innovation_gate ig;
    l2_innovation_gate_init(&ig, 3.0 /* kappa */, 30 /* hysteresis_w */, 10 /* min_calib */);
    CHECK(ig.initialized, "initialized");
    CHECK(ig.latch_open, "latch defaults OPEN before arming");
    CHECK(!ig.armed, "gate is not armed at init");

    double x[L2_MAX_FEATURES];

    /* 1. Warm-up: the very first benign window only seeds the forecast and the latch stays OPEN
     *    (never suppress the z-path before the latch is armed). warm_complete=false throughout
     *    the whole warmup. */
    set_feat(x, L2_MAX_FEATURES, 5.0);
    bool first = l2_innovation_gate_update(&ig, x, L2_MAX_FEATURES, true /*calibrate*/,
                                           false /*warm_complete*/);
    CHECK(first == true, "first (seed) window keeps latch OPEN");

    /* 2. Calibrate over the FULL benign warmup: feed a long run of STEADY benign windows with
     *    warm_complete STILL false. The gate keeps calibrating and stays FAIL-OPEN the whole
     *    time -- crucially, EVEN AFTER calib_count passes MIN_CALIB. This is the regression guard
     *    for the fix: reaching the floor is NOT enough to arm; only warm_complete arms the gate. */
    bool warm_latch = true;
    for (int i = 0; i < 40; i++) {
        set_feat(x, L2_MAX_FEATURES, 5.0);
        warm_latch = l2_innovation_gate_update(&ig, x, L2_MAX_FEATURES, true /*calibrate*/,
                                               false /*warm_complete*/);
    }
    CHECK(warm_latch == true, "fail-open: latch stays OPEN for the ENTIRE benign warmup");
    CHECK(ig.calib_count >= ig.min_calib, "calibrated past MIN_CALIB during warmup");
    CHECK(!ig.armed, "still NOT armed while warm_complete is false (past MIN_CALIB)");

    /* 3. ARM the latch: signal warm_complete=true on a STEADY benign window. The gate freezes the
     *    benign stats and starts gating from a CLOSED state; a steady benign feature is perfectly
     *    predicted -> zero surprise -> the latch is CLOSED immediately after arming. calibrate is
     *    false now (mirrors the caller: once warm_complete, calibration stops / freezes). */
    bool armed_latch = true;
    for (int i = 0; i < 3; i++) {
        set_feat(x, L2_MAX_FEATURES, 5.0);
        armed_latch = l2_innovation_gate_update(&ig, x, L2_MAX_FEATURES, false /*calibrate*/,
                                                true /*warm_complete*/);
    }
    CHECK(ig.armed, "latch is ARMED once warmup is complete");
    CHECK(armed_latch == false, "steady benign feature is UNSURPRISING -> latch CLOSED after arming");

    /* 4. A sharp RAW JUMP (raw=50) is SURPRISING vs the slow forecast -> latch OPENS immediately.
     *    calibrate=false: an onset window is not benign, so it must not poison the calibration. */
    set_feat(x, L2_MAX_FEATURES, 50.0);
    bool jump = l2_innovation_gate_update(&ig, x, L2_MAX_FEATURES, false /*calibrate*/,
                                          true /*warm_complete*/);
    CHECK(jump == true, "sharp raw jump is SURPRISING -> latch OPENS");

    /* 5. A RETURN TO THE BENIGN LEVEL (raw back to 5) is low-surprise, so the hysteresis
     *    counts down and the latch re-CLOSES -- confirming the latch is not stuck open. */
    bool reclose = true;
    for (int i = 0; i < 40; i++) {
        set_feat(x, L2_MAX_FEATURES, 5.0);
        reclose = l2_innovation_gate_update(&ig, x, L2_MAX_FEATURES, false /*calibrate*/,
                                            true /*warm_complete*/);
    }
    CHECK(reclose == false, "return to benign level re-CLOSES the latch (hysteresis works)");

    /* 6. Short feature vector (n < L2_MAX_FEATURES) is handled without reading past the end. */
    struct innovation_gate ig2;
    l2_innovation_gate_init(&ig2, 3.0, 30, 10);
    double xshort[3] = { 1.0, 2.0, 3.0 };
    bool s = l2_innovation_gate_update(&ig2, xshort, 3, true /*calibrate*/, false /*warm_complete*/);
    CHECK(s == true, "short vector: seed window OK, latch OPEN");

    /* 7. NULL / uninitialized fail OPEN (never silently suppress the z-path). */
    struct innovation_gate zero;
    memset(&zero, 0, sizeof(zero));
    CHECK(l2_innovation_gate_update(&zero, x, L2_MAX_FEATURES, false, true) == true,
          "uninitialized -> fail OPEN");
    CHECK(l2_innovation_gate_update(NULL, x, L2_MAX_FEATURES, false, true) == true,
          "NULL -> fail OPEN");

    printf("=== %d/%d passed ===\n", passed, total);
    return (passed == total) ? 0 : 1;
}
