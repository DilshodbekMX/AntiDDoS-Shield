/* Unit tests for the routed-FDR live wiring (layer2/routed_live.c). Pure C, no DPDK.
 * Verifies channel registration, warm-up gating, benign calibration, and BH-FDR decision. */
#include "layer2/routed_live.h"
#include <stdio.h>
#include <math.h>
#include <string.h>

static int passed = 0, total = 0;
#define CHECK(cond, name) do { total++; if (cond) { passed++; } \
    else { printf("  FAIL: %s\n", name); } } while (0)

int main(void) {
    printf("=== routed_live unit tests ===\n");
    enum { NF = 8 };
    double alpha = 0.1;               /* BH-FDR level; need ~ (NF+1)/alpha = 90 calib windows */
    struct routed_live rl;
    l2_routed_live_init(&rl, alpha, NF, 256);
    CHECK(rl.initialized, "initialized");
    CHECK(rl.n_scalar == NF, "registered one scalar channel per feature");
    CHECK(rl.warmup_min == (size_t)ceil((double)(NF + 1) / alpha), "warmup_min == (m)/alpha");

    double z[NF], c[NF];
    for (int i = 0; i < NF; i++) { z[i] = 0.1; c[i] = 0.1; }

    /* cold context: NOT READY */
    size_t attr = 999;
    CHECK(l2_routed_live_decide(&rl, z, c, NF, 0.01, false, &attr) == -1, "cold -> NOT_READY");

    /* calibrate with benign windows */
    int last = -1;
    for (int k = 0; k < 400; k++) last = l2_routed_live_decide(&rl, z, c, NF, 0.01, true, &attr);
    CHECK(last == 0, "warmed: benign window -> 0");

    /* extreme anomaly on one feature (both z and CUSUM spike -- the routed channel
     * ACAT-collapses the two, so both must be extreme) should be rejected + attributed */
    double za[NF], ca[NF]; memcpy(za, z, sizeof za); memcpy(ca, c, sizeof ca);
    za[3] = 60.0; ca[3] = 60.0;   /* feature 3 spikes on both paths */
    int hit = l2_routed_live_decide(&rl, za, ca, NF, 0.01, false, &attr);
    CHECK(hit == 1, "extreme single-feature anomaly flagged");
    CHECK(attr == 3, "BH attributes the rejection to feature 3");

    /* NULL safety */
    CHECK(l2_routed_live_decide(NULL, z, c, NF, 0.01, false, NULL) == -1, "NULL -> NOT_READY");

    printf("=== %d/%d passed ===\n", passed, total);
    return (passed == total) ? 0 : 1;
}
