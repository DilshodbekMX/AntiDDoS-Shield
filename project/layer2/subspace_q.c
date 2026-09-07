#include "subspace_q.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static int cmp_double_asc(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

void l2_subspace_q_init(struct subspace_q_detector *sq,
                        size_t n_features,
                        size_t n_components,
                        double alpha_ewma) {
    if (!sq) return;
    memset(sq, 0, sizeof(*sq));
    sq->n_features = (n_features > L2_SUBSPACE_Q_MAX_FEATURES) ? L2_SUBSPACE_Q_MAX_FEATURES : n_features;
    sq->n_components = (n_components > L2_SUBSPACE_Q_MAX_COMPONENTS) ? L2_SUBSPACE_Q_MAX_COMPONENTS : n_components;
    sq->alpha_ewma = (alpha_ewma <= 0.0 || alpha_ewma > 1.0) ? 0.5 : alpha_ewma;
    sq->spot_fallback = false;
    sq->q_sorted = NULL;
    sq->n_train = 0;
    sq->ewma_state = 0.0;
    sq->is_initialized = true;
}

void l2_subspace_q_free(struct subspace_q_detector *sq) {
    if (!sq) return;
    if (sq->q_sorted) {
        free(sq->q_sorted);
        sq->q_sorted = NULL;
    }
    sq->n_train = 0;
    sq->is_initialized = false;
}

void l2_subspace_q_reset_stream(struct subspace_q_detector *sq) {
    if (!sq) return;
    sq->ewma_state = 0.0;
}

/*
 * Numpy-identical percentile with linear interpolation:
 * idx = q * (N - 1)
 */
static double numpy_percentile(double *sorted_col, size_t N, double q) {
    if (N == 0) return 0.0;
    if (N == 1) return sorted_col[0];
    double idx = q * (double)(N - 1);
    if (idx <= 0.0) return sorted_col[0];
    if (idx >= (double)(N - 1)) return sorted_col[N - 1];
    size_t i = (size_t)idx;
    double f = idx - (double)i;
    return (1.0 - f) * sorted_col[i] + f * sorted_col[i + 1];
}

static void fit_spot_params(struct subspace_q_detector *sq,
                            const double *train_matrix,
                            const double *raw_stds,
                            size_t N,
                            size_t D) {
    double *col = (double *)malloc(N * sizeof(double));
    double *ex = (double *)malloc(N * sizeof(double));
    if (!col || !ex) {
        if (col) free(col);
        if (ex) free(ex);
        return;
    }

    for (size_t j = 0; j < D; j++) {
        for (size_t i = 0; i < N; i++) {
            col[i] = train_matrix[i * D + j];
        }
        qsort(col, N, sizeof(double), cmp_double_asc);
        double tu = numpy_percentile(col, N, 0.98);
        sq->spot_threshold[j] = tu;

        size_t n_ex = 0;
        for (size_t i = 0; i < N; i++) {
            if (train_matrix[i * D + j] > tu) {
                ex[n_ex++] = train_matrix[i * D + j] - tu;
            }
        }

        if (n_ex > 2) {
            double sum_ex = 0.0;
            for (size_t i = 0; i < n_ex; i++) sum_ex += ex[i];
            double m = sum_ex / (double)n_ex;
            double sq_sum = 0.0;
            for (size_t i = 0; i < n_ex; i++) {
                double diff = ex[i] - m;
                sq_sum += diff * diff;
            }
            double v = sq_sum / (double)n_ex; /* population var ddof=0 */
            double s = 0.5 * m * ((m * m) / (v + 1e-8) + 1.0);
            sq->spot_scale[j] = (s > 0.01) ? s : 0.01;
        } else {
            double raw_sd = raw_stds[j];
            sq->spot_scale[j] = (raw_sd > 0.1) ? raw_sd : 0.1;
        }
    }
    free(col);
    free(ex);
}

/*
 * Cyclic Jacobi Eigensolver for symmetric matrix C (D x D).
 * Computes all eigenvalues and eigenvectors to machine precision (~1e-15).
 */
static void cyclic_jacobi_eig(const double *C_in, size_t D, double *evals_out, double *V_out) {
    double *D_mat = (double *)malloc(D * D * sizeof(double));
    double *V = (double *)malloc(D * D * sizeof(double));
    if (!D_mat || !V) {
        if (D_mat) free(D_mat);
        if (V) free(V);
        return;
    }
    memcpy(D_mat, C_in, D * D * sizeof(double));

    for (size_t i = 0; i < D; i++) {
        for (size_t j = 0; j < D; j++) {
            V[i * D + j] = (i == j) ? 1.0 : 0.0;
        }
    }

    double tr = 0.0;
    for (size_t i = 0; i < D; i++) tr += fabs(D_mat[i * D + i]);
    double tol = 1e-14 * (tr + 1.0);

    for (int sweep = 0; sweep < 50; sweep++) {
        double max_off = 0.0;
        for (size_t p = 0; p < D - 1; p++) {
            for (size_t q = p + 1; q < D; q++) {
                double app = D_mat[p * D + p];
                double aqq = D_mat[q * D + q];
                double apq = D_mat[p * D + q];
                if (fabs(apq) < 1e-18) continue;
                if (fabs(apq) > max_off) max_off = fabs(apq);

                double tau = (aqq - app) / (2.0 * apq);
                double t;
                if (tau >= 0.0) {
                    t = 1.0 / (tau + sqrt(1.0 + tau * tau));
                } else {
                    t = -1.0 / (-tau + sqrt(1.0 + tau * tau));
                }
                double c = 1.0 / sqrt(1.0 + t * t);
                double s = t * c;

                double h = t * apq;
                D_mat[p * D + p] -= h;
                D_mat[q * D + q] += h;
                D_mat[p * D + q] = 0.0;
                D_mat[q * D + p] = 0.0;

                for (size_t r = 0; r < D; r++) {
                    if (r != p && r != q) {
                        double arp = D_mat[r * D + p];
                        double arq = D_mat[r * D + q];
                        D_mat[r * D + p] = D_mat[p * D + r] = c * arp - s * arq;
                        D_mat[r * D + q] = D_mat[q * D + r] = s * arp + c * arq;
                    }
                }

                for (size_t r = 0; r < D; r++) {
                    double vrp = V[r * D + p];
                    double vrq = V[r * D + q];
                    V[r * D + p] = c * vrp - s * vrq;
                    V[r * D + q] = s * vrp + c * vrq;
                }
            }
        }
        if (max_off < tol) break;
    }

    struct eig_pair {
        double val;
        size_t idx;
    };
    struct eig_pair *pairs = (struct eig_pair *)malloc(D * sizeof(struct eig_pair));
    for (size_t i = 0; i < D; i++) {
        pairs[i].val = D_mat[i * D + i];
        pairs[i].idx = i;
    }
    for (size_t i = 0; i < D; i++) {
        for (size_t j = i + 1; j < D; j++) {
            if (pairs[j].val > pairs[i].val) {
                struct eig_pair tmp = pairs[i];
                pairs[i] = pairs[j];
                pairs[j] = tmp;
            }
        }
    }

    for (size_t comp = 0; comp < D; comp++) {
        evals_out[comp] = pairs[comp].val;
        size_t orig = pairs[comp].idx;
        for (size_t r = 0; r < D; r++) {
            V_out[r * D + comp] = V[r * D + orig];
        }
    }

    free(pairs);
    free(D_mat);
    free(V);
}

bool l2_subspace_q_fit(struct subspace_q_detector *sq,
                       const double *train_matrix,
                       size_t n_samples) {
    if (!sq || !train_matrix || n_samples < 10) return false;
    size_t D = sq->n_features;
    size_t N = n_samples;

    double raw_stds[L2_SUBSPACE_Q_MAX_FEATURES];

    // 1. Standarise (population mean and std, ddof=0)
    for (size_t j = 0; j < D; j++) {
        double sum = 0.0;
        for (size_t i = 0; i < N; i++) {
            sum += train_matrix[i * D + j];
        }
        sq->mu[j] = sum / (double)N;

        double sq_sum = 0.0;
        for (size_t i = 0; i < N; i++) {
            double diff = train_matrix[i * D + j] - sq->mu[j];
            sq_sum += diff * diff;
        }
        double sd = sqrt(sq_sum / (double)N);
        raw_stds[j] = sd;
        sq->std[j] = (sd < 1e-9) ? 1.0 : sd;
    }

    // Always precompute SPOT parameters (needed for fallback)
    fit_spot_params(sq, train_matrix, raw_stds, N, D);

    // 2. Guard: if N < 2*D -> arm SPOT fallback
    if (N < 2 * D) {
        sq->spot_fallback = true;
        sq->k_effective = 0;
        sq->n_train = N;
        sq->ewma_state = 0.0;
        return true;
    }

    sq->spot_fallback = false;

    // 3. Subspace: Standardized training covariance C = Z_tr^T Z_tr
    double *C = (double *)calloc(D * D, sizeof(double));
    if (!C) return false;

    for (size_t i = 0; i < N; i++) {
        double z[L2_SUBSPACE_Q_MAX_FEATURES];
        for (size_t j = 0; j < D; j++) {
            z[j] = (train_matrix[i * D + j] - sq->mu[j]) / sq->std[j];
        }
        for (size_t r = 0; r < D; r++) {
            for (size_t c = 0; c < D; c++) {
                C[r * D + c] += z[r] * z[c];
            }
        }
    }

    double *evals = (double *)malloc(D * sizeof(double));
    double *V_full = (double *)malloc(D * D * sizeof(double));
    if (!evals || !V_full) {
        free(C);
        if (evals) free(evals);
        if (V_full) free(V_full);
        return false;
    }

    cyclic_jacobi_eig(C, D, evals, V_full);
    free(C);
    free(evals);

    size_t k = sq->n_components;
    if (k > D) k = D;
    sq->k_effective = k;

    // Copy top k eigenvectors into Vk[comp][j] (transposed so rows are orthonormal)
    for (size_t comp = 0; comp < k; comp++) {
        for (size_t j = 0; j < D; j++) {
            sq->Vk[comp][j] = V_full[j * D + comp];
        }
    }
    free(V_full);

    // 4. Precompute and sort Q_tr for the N training rows
    if (sq->q_sorted) free(sq->q_sorted);
    sq->q_sorted = (double *)malloc(N * sizeof(double));
    if (!sq->q_sorted) return false;

    for (size_t i = 0; i < N; i++) {
        double z[L2_SUBSPACE_Q_MAX_FEATURES];
        double norm_sq = 0.0;
        for (size_t j = 0; j < D; j++) {
            z[j] = (train_matrix[i * D + j] - sq->mu[j]) / sq->std[j];
            norm_sq += z[j] * z[j];
        }

        double proj_sq = 0.0;
        for (size_t comp = 0; comp < sq->k_effective; comp++) {
            double dot = 0.0;
            for (size_t j = 0; j < D; j++) {
                dot += z[j] * sq->Vk[comp][j];
            }
            proj_sq += dot * dot;
        }

        double q_val = norm_sq - proj_sq;
        sq->q_sorted[i] = (q_val > 0.0) ? q_val : 0.0;
    }

    qsort(sq->q_sorted, N, sizeof(double), cmp_double_asc);
    sq->n_train = N;
    sq->ewma_state = 0.0;
    return true;
}

double l2_subspace_q_score_raw(const struct subspace_q_detector *sq,
                               const double *features) {
    if (!sq || !features) return 0.0;

    // SPOT Fallback branch
    if (sq->spot_fallback) {
        double max_s = 0.0;
        for (size_t j = 0; j < sq->n_features; j++) {
            double val = features[j];
            double tu = sq->spot_threshold[j];
            if (val > tu) {
                double exc = (val - tu) / sq->spot_scale[j];
                if (exc > max_s) max_s = exc;
            }
        }
        return max_s;
    }

    if (!sq->q_sorted || sq->n_train == 0) return 0.0;

    size_t D = sq->n_features;
    double z[L2_SUBSPACE_Q_MAX_FEATURES];
    double norm_sq = 0.0;

    for (size_t j = 0; j < D; j++) {
        z[j] = (features[j] - sq->mu[j]) / sq->std[j];
        norm_sq += z[j] * z[j];
    }

    double proj_sq = 0.0;
    for (size_t comp = 0; comp < sq->k_effective; comp++) {
        double dot = 0.0;
        for (size_t j = 0; j < D; j++) {
            dot += z[j] * sq->Vk[comp][j];
        }
        proj_sq += dot * dot;
    }

    double Q = norm_sq - proj_sq;
    if (Q < 0.0) Q = 0.0;

    // Epsilon-tolerant lower_bound (1e-12 relative tolerance on tied clusters)
    double Q_adj = Q - 1e-12 * ((Q > 1.0) ? Q : 1.0);
    if (Q_adj < 0.0) Q_adj = 0.0;

    size_t left = 0, right = sq->n_train;
    while (left < right) {
        size_t mid = left + (right - left) / 2;
        if (sq->q_sorted[mid] < Q_adj) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    size_t ge = sq->n_train - left;
    double p = ((double)ge + 1.0) / ((double)sq->n_train + 1.0);
    if (p < 1e-12) p = 1e-12;

    return -log(p);
}

double l2_subspace_q_step(struct subspace_q_detector *sq,
                          const double *features) {
    if (!sq || !features) return 0.0;

    double raw = l2_subspace_q_score_raw(sq, features);

    // If SPOT fallback, return raw score without EWMA (matching reference)
    if (sq->spot_fallback) {
        return raw;
    }

    // Causal EWMA: s_t = alpha * O_t + (1 - alpha) * s_{t-1}
    sq->ewma_state = sq->alpha_ewma * raw + (1.0 - sq->alpha_ewma) * sq->ewma_state;
    return sq->ewma_state;
}
