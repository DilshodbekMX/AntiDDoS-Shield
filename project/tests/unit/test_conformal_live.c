/* Unit tests for the conformal live-wiring (layer2/conformal_live.c).
 * Pure C, no DPDK. Verifies warm-up gating, benign calibration, the decision,
 * capacity auto-sizing to >= K/alpha, and K-path parameterization / buffer floor guards. */
#include "layer2/conformal_live.h"
#include <stdio.h>
#include <math.h>

static int passed = 0, total = 0;
#define CHECK(cond, name) do { total++; if (cond) { passed++; } \
    else { printf("  FAIL: %s\n", name); } } while (0)

int main(void) {
    printf("=== conformal_live unit tests ===\n");

    /* 1. capacity auto-sizes up to >= 3/alpha even when configured smaller */
    struct conformal_live cl;
    l2_conformal_live_init(&cl, 0.001, 256, 1 /* Bonferroni */);
    CHECK(cl.initialized, "initialized (K=3)");
    CHECK(cl.warmup_min == (size_t)ceil(3.0 / 0.001), "warmup_min == ceil(3/alpha) = 3000");

    /* 2. before warm-up the combiner is NOT READY (-1 => caller uses OR) */
    int early = l2_conformal_live_decide(&cl, 50.0, 50.0, 0.9, false);
    CHECK(early == -1, "cold context returns NOT_READY (-1)");

    /* 3. feed benign calibration windows, then a benign window scores 0 and an
     *    extreme anomaly scores 1 */
    int last = -1;
    for (int i = 0; i < 3500; i++) last = l2_conformal_live_decide(&cl, 0.1, 0.1, 0.01, true);
    CHECK(last == 0, "warmed: benign window -> 0");
    int benign = l2_conformal_live_decide(&cl, 0.1, 0.1, 0.01, false);
    int anomaly = l2_conformal_live_decide(&cl, 50.0, 50.0, 0.9, false);
    CHECK(benign == 0, "benign window not flagged");
    CHECK(anomaly == 1, "extreme anomaly flagged");

    /* 4. K=4 live wiring at alpha=0.01: warmup is 400 */
    struct conformal_live cl4;
    bool ok4 = l2_conformal_live_init_k(&cl4, 0.01, 128, 1, 4);
    CHECK(ok4 == true, "K=4 live init succeeds");
    CHECK(cl4.warmup_min == 400, "K=4 warmup_min == 400");
    double b4[4] = { 0.1, 0.1, 0.1, 0.1 };
    for (int i = 0; i < 400; i++) l2_conformal_live_decide_k(&cl4, b4, 4, true);
    double ext4[4] = { 500.0, 0.0, 0.0, 0.0 };
    int anom4 = l2_conformal_live_decide_k(&cl4, ext4, 4, false);
    CHECK(anom4 == 1, "K=4 live anomaly detected post-warmup");

    /* 5. K=5 at alpha=0.001 buffer floor refusal guard */
    struct conformal_live cl5;
    bool ok5 = l2_conformal_live_init_k(&cl5, 0.001, 4096, 1, 5);
    CHECK(ok5 == false, "K=5, alpha=0.001 refused at live init");
    CHECK(cl5.initialized == false, "cl5 initialized is false");
    CHECK(l2_conformal_live_decide_k(&cl5, ext4, 4, false) == -1, "refused context returns -1 NOT_READY");

    /* 6. NULL / uninitialized safety */
    struct conformal_live z = {0};
    CHECK(l2_conformal_live_decide(&z, 1, 1, 1, false) == -1, "uninitialized -> NOT_READY");
    CHECK(l2_conformal_live_decide(NULL, 1, 1, 1, false) == -1, "NULL -> NOT_READY");

    printf("=== %d/%d passed ===\n", passed, total);
    return (passed == total) ? 0 : 1;
}
