#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include "../../layer2/subspace_q.h"

#define MAX_ROWS 10000
#define MAX_COLS 64
#define FIXTURE_DIR "/home/detector/Projects/antiddos/AntiDDOS_Shield/experiments_copy/results/cport_fixture"

static int load_csv(const char *path, double *mat, size_t *out_rows, size_t *out_cols) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open CSV: %s\n", path);
        return -1;
    }

    char line[65536];
    size_t rows = 0;
    size_t cols = 0;

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == 'a' || line[0] == 's') {
            // Header or comment line
            continue;
        }

        if (cols == 0) {
            char tmp[65536];
            strcpy(tmp, line);
            char *tok = strtok(tmp, ",\r\n");
            while (tok) {
                cols++;
                tok = strtok(NULL, ",\r\n");
            }
        }

        char *p = line;
        for (size_t j = 0; j < cols; j++) {
            char *next = NULL;
            double val = strtod(p, &next);
            mat[rows * cols + j] = val;
            if (next && (*next == ',' || *next == '\r' || *next == '\n')) {
                p = next + 1;
            } else {
                break;
            }
        }
        rows++;
        if (rows >= MAX_ROWS) break;
    }

    fclose(f);
    *out_rows = rows;
    *out_cols = cols;
    return 0;
}

static int load_expected_csv(const char *path, double *scores, size_t *out_n) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open expected CSV: %s\n", path);
        return -1;
    }

    char line[4096];
    size_t n = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == 's' || line[0] == 'a') {
            // Header line
            continue;
        }
        double s = atof(line);
        scores[n++] = s;
        if (n >= MAX_ROWS) break;
    }

    fclose(f);
    *out_n = n;
    return 0;
}

static double *mat_train;
static double *mat_test;
static double *expected_scores;

int main(void) {
    printf("=================================================================\n");
    printf("STEP 0 — C-PORT PARITY GATE (Subspace-Q + EWMA)\n");
    printf("=================================================================\n");

    mat_train = (double *)malloc(MAX_ROWS * MAX_COLS * sizeof(double));
    mat_test = (double *)malloc(MAX_ROWS * MAX_COLS * sizeof(double));
    expected_scores = (double *)malloc(MAX_ROWS * sizeof(double));
    assert(mat_train && mat_test && expected_scores);

    const char *slugs[4] = {
        "CIC-IDS-2017_Fri-07-07_DDoS-LOIT",
        "CIC-DDoS2019_cicddos_03-11_192-168-50-4_UDPLag",
        "CIC-IoT-2023_DDoS-UDP_Flood",
        "EDGE_N_lt_2D_fallback"
    };

    bool all_passed = true;

    for (int c = 0; c < 4; c++) {
        char path_tr[512], path_te[512], path_exp[512];
        snprintf(path_tr, sizeof(path_tr), "%s/%s.train.csv", FIXTURE_DIR, slugs[c]);
        snprintf(path_te, sizeof(path_te), "%s/%s.test.csv", FIXTURE_DIR, slugs[c]);
        snprintf(path_exp, sizeof(path_exp), "%s/%s.expected.csv", FIXTURE_DIR, slugs[c]);

        size_t n_tr, d_tr, n_te, d_te, n_exp;
        int err_tr = load_csv(path_tr, mat_train, &n_tr, &d_tr);
        int err_te = load_csv(path_te, mat_test, &n_te, &d_te);
        int err_exp = load_expected_csv(path_exp, expected_scores, &n_exp);

        assert(err_tr == 0 && err_te == 0 && err_exp == 0);
        assert(d_tr == d_te);
        assert(n_te == n_exp);

        struct subspace_q_detector sq;
        l2_subspace_q_init(&sq, d_tr, 8, 0.5);

        bool fit_ok = l2_subspace_q_fit(&sq, mat_train, n_tr);
        assert(fit_ok);

        double max_rel_err = 0.0;
        double max_abs_err = 0.0;

        for (size_t i = 0; i < n_te; i++) {
            double c_score = l2_subspace_q_step(&sq, &mat_test[i * d_tr]);
            double py_score = expected_scores[i];

            double abs_err = fabs(c_score - py_score);
            double rel_err = abs_err / (fabs(py_score) + 1e-12);

            if (rel_err > max_rel_err) max_rel_err = rel_err;
            if (abs_err > max_abs_err) max_abs_err = abs_err;
        }

        l2_subspace_q_free(&sq);

        bool pass = (max_rel_err <= 1e-9);
        if (!pass) all_passed = false;

        printf("Case %d: %-48s\n", c + 1, slugs[c]);
        printf("  N_train=%zu, D=%zu, N_test=%zu | Fallback=%s\n",
               n_tr, d_tr, n_te, sq.spot_fallback ? "YES" : "NO");
        printf("  Max Relative Error: %.2e | Max Abs Error: %.2e -> %s\n\n",
               max_rel_err, max_abs_err, pass ? "PASSED [1e-9 relative]" : "FAILED");
    }

    free(mat_train);
    free(mat_test);
    free(expected_scores);

    printf("=================================================================\n");
    if (all_passed) {
        printf("PARITY GATE RESULT: ALL 4 FIXTURE CASES PASSED PERFECTLY!\n");
    } else {
        printf("PARITY GATE RESULT: FAILED!\n");
    }
    printf("=================================================================\n");

    return all_passed ? 0 : 1;
}
