/**
 * @file test_conformal_combine.c
 * @brief Unit tests for the Layer-2 conformal combiner (calibrated false-alarm control).
 *
 * Validates that the C mirror reproduces experiment/run_fpr_conformal.py:
 *  - split-conformal p-value  p(s) = (1 + #{buf >= s}) / (n + 1)
 *  - Bonferroni family-wise rule (min p <= alpha/K)
 *  - e-value averaging rule (mean(1/p) >= 1/alpha)
 *  - ring-buffer calibration (capacity bound, finite-sample p-value floor)
 *  - parameterized K paths and buffer floor guards (K=3, K=4, K=5 refusal)
 */
#include <stdio.h>
#include <math.h>
#include <stdbool.h>
#include "../../layer2/conformal_combine.h"

static int tests_run = 0, tests_passed = 0;
#define CHECK(cond, msg) do { \
    tests_run++; \
    if (cond) { tests_passed++; } \
    else { printf("  FAIL: %s\n", msg); } \
} while (0)

static int approx(double a, double b) { return fabs(a - b) < 1e-9; }

int main(void)
{
    printf("=== conformal_combine unit tests ===\n");

    /* 1. p-value formula: buffer {1,2,3,4,5}, score=3 -> #{>=3}=3 -> (1+3)/(5+1)=4/6 */
    struct conformal_path p = {0};
    p.capacity = 8; p.count = 0; p.head = 0;
    for (double v = 1.0; v <= 5.0; v += 1.0) conformal_path_observe(&p, v);
    CHECK(approx(conformal_pvalue(&p, 3.0), 4.0 / 6.0), "p-value mid score");
    CHECK(approx(conformal_pvalue(&p, 5.0), 2.0 / 6.0), "p-value max score (tie counts)");
    CHECK(approx(conformal_pvalue(&p, 6.0), 1.0 / 6.0), "p-value above max -> 1/(n+1)");
    CHECK(approx(conformal_pvalue(&p, 0.0), 6.0 / 6.0), "p-value below min -> 1.0");

    /* empty buffer -> conservative 1.0 */
    struct conformal_path empty = {0};
    empty.capacity = 8;
    CHECK(approx(conformal_pvalue(&empty, 99.0), 1.0), "empty buffer p-value = 1.0");

    /* ring-buffer overwrite: capacity 3, push 5 values -> only last 3 retained */
    struct conformal_path ring = {0};
    ring.capacity = 3;
    for (double v = 1.0; v <= 5.0; v += 1.0) conformal_path_observe(&ring, v); /* keeps {3,4,5} */
    CHECK(ring.count == 3, "ring buffer count capped at capacity");
    CHECK(approx(conformal_pvalue(&ring, 3.0), 4.0 / 4.0), "ring keeps most recent (min=3)");

    /* 2. Existing K=3 tests reproduce current behaviour exactly */
    struct conformal_combiner cc;
    conformal_combiner_init(&cc, 128, 0.06);
    CHECK(cc.n_paths == 3, "default init sets n_paths == 3");
    for (int i = 0; i < 99; i++)
        conformal_combiner_observe(&cc, (double)i / 99.0, (double)i / 99.0, (double)i / 99.0);
    CHECK(conformal_decide_bonferroni(&cc, 10.0, 0.0, 0.0) == true,
          "Bonferroni fires on one extreme path");
    CHECK(conformal_decide_bonferroni(&cc, 0.5, 0.5, 0.5) == false,
          "Bonferroni quiet on mid scores");

    /* e-value: extreme path -> 1/p large -> mean >= 1/alpha fires */
    CHECK(conformal_decide_evalue(&cc, 10.0, 10.0, 10.0) == true,
          "e-value fires on extreme scores");
    CHECK(conformal_decide_evalue(&cc, 0.4, 0.4, 0.4) == false,
          "e-value quiet on mid scores");

    /* finite-sample floor: with n calib, min p-value = 1/(n+1); alpha/3 below that cannot fire */
    struct conformal_combiner tiny;
    conformal_combiner_init(&tiny, 16, 0.001); /* alpha/3 ~ 0.00033 */
    for (int i = 0; i < 10; i++) conformal_combiner_observe(&tiny, i, i, i); /* min p = 1/11 ~ 0.09 */
    CHECK(conformal_decide_bonferroni(&tiny, 1e9, 1e9, 1e9) == false,
          "finite-sample floor blocks unreachable alpha");

    /* 3. K=4 at alpha=0.01 warms at 400 and rejects at alpha/4 = 0.0025 */
    struct conformal_combiner k4_01;
    bool ok_k4_01 = conformal_combiner_init_k(&k4_01, 512, 0.01, 4);
    CHECK(ok_k4_01 == true, "K=4, alpha=0.01 init succeeds");
    CHECK(k4_01.n_paths == 4, "K=4 active paths");
    CHECK(k4_01.paths[0].capacity >= 400, "capacity auto-bumped to >= 400");
    /* Observe 400 benign windows on all 4 paths */
    for (int i = 0; i < 400; i++) {
        double s[4] = { (double)i, (double)i, (double)i, (double)i };
        conformal_combiner_observe_k(&k4_01, s, 4);
    }
    /* An extreme score (above all 400) gives p = 1/401 = 0.0024938 <= 0.01/4 = 0.0025 -> fires */
    double ext_s[4] = { 500.0, 0.0, 0.0, 0.0 };
    CHECK(conformal_decide_bonferroni_k(&k4_01, ext_s, 4) == true,
          "K=4 at alpha=0.01 fires on extreme score (p=1/401 <= alpha/4)");
    /* A score at index 398 gives #{>=398}=2 -> p = 3/401 = 0.00748 > 0.0025 -> quiet */
    double quiet_s[4] = { 398.0, 0.0, 0.0, 0.0 };
    CHECK(conformal_decide_bonferroni_k(&k4_01, quiet_s, 4) == false,
          "K=4 at alpha=0.01 quiet when p > alpha/4");

    /* 4. K=4 at alpha=0.001 warms at 4000 and rejects at alpha/4 = 2.5e-4 */
    struct conformal_combiner k4_001;
    bool ok_k4_001 = conformal_combiner_init_k(&k4_001, 1024, 0.001, 4);
    CHECK(ok_k4_001 == true, "K=4, alpha=0.001 init succeeds");
    CHECK(k4_001.paths[0].capacity == 4000, "capacity auto-bumped to 4000");
    for (int i = 0; i < 4000; i++) {
        double s[4] = { (double)i, (double)i, (double)i, (double)i };
        conformal_combiner_observe_k(&k4_001, s, 4);
    }
    /* Extreme score (above all 4000): p = 1/4001 = 2.499375e-4 <= 2.500000e-4 -> fires */
    double ext_s4000[4] = { 5000.0, 0.0, 0.0, 0.0 };
    CHECK(conformal_decide_bonferroni_k(&k4_001, ext_s4000, 4) == true,
          "K=4 at alpha=0.001 fires on extreme score (p=1/4001 <= 2.5e-4)");

    /* 5. K=5 at alpha=0.001 is refused at init (need = ceil(5/0.001) = 5000 > 4096) */
    struct conformal_combiner k5_001;
    bool ok_k5_001 = conformal_combiner_init_k(&k5_001, 4096, 0.001, 5);
    CHECK(ok_k5_001 == false, "K=5 at alpha=0.001 refused at init (buffer floor guard)");
    CHECK(k5_001.n_paths == 0, "refused combiner has n_paths == 0");

    /* 6. Matched decision equivalence: K=4 fed identical scores vs K=3 at matched alpha/K */
    /* Target per-path threshold: beta = 0.005.
     * For K=3: alpha_3 = 3 * beta = 0.015 -> alpha_3 / 3 = 0.005.
     * For K=4: alpha_4 = 4 * beta = 0.020 -> alpha_4 / 4 = 0.005. */
    struct conformal_combiner c3, c4;
    conformal_combiner_init_k(&c3, 256, 0.015, 3);
    conformal_combiner_init_k(&c4, 256, 0.020, 4);
    for (int i = 0; i < 200; i++) {
        double val = (double)i * 1.5;
        double s3[3] = { val, val + 0.1, val + 0.2 };
        double s4[4] = { val, val + 0.1, val + 0.2, val + 0.3 };
        conformal_combiner_observe_k(&c3, s3, 3);
        conformal_combiner_observe_k(&c4, s4, 4);
    }
    /* Query test points */
    for (double q = 0.0; q <= 350.0; q += 25.0) {
        double q3[3] = { q, q * 0.5, q * 0.2 };
        double q4[4] = { q, q * 0.5, q * 0.2, q * 0.1 };
        bool dec3 = conformal_decide_bonferroni_k(&c3, q3, 3);
        bool dec4 = conformal_decide_bonferroni_k(&c4, q4, 4);
        CHECK(dec3 == dec4, "Matched alpha/K: K=3 and K=4 decisions agree");
    }

    printf("=== %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
