#ifndef L2_SUBSPACE_Q_H
#define L2_SUBSPACE_Q_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <math.h>

#define L2_SUBSPACE_Q_MAX_FEATURES   64
#define L2_SUBSPACE_Q_MAX_COMPONENTS 16
#define L2_SUBSPACE_Q_MAX_CALIB      8192

/*
 * Subspace-Q + EWMA Anomaly Detector (Pure Detector, C-Engine Implementation).
 *
 * Implements:
 *   score(x_t) = EWMA_{alpha=0.5} ( -ln P_hat( Q_benign >= Q(x_t) ) )
 *
 * where:
 *   Q(x) = ||Z||^2 - ||V_k Z||^2,  Z = (x - mu) / sigma  (standardised on TRAIN)
 *   V_k  = top k=8 right singular vectors of standardized TRAIN matrix Z_tr.
 *
 * Guard: If N < 2*D, falls back to SPOT (Peaks-Over-Threshold) scoring.
 *
 * No SPOT fusion in standard mode (Pure detector).
 * EWMA is causal with alpha = 0.5 and initialized to 0.0.
 */
struct subspace_q_detector {
    size_t n_features;               /* D: number of active features */
    size_t n_components;             /* k: number of principal components (default 8) */
    double alpha_ewma;               /* EWMA alpha parameter (default 0.5) */
    bool   spot_fallback;            /* true if N < 2*D fallback triggered */

    /* Feature standardization statistics (population ddof=0) */
    double mu[L2_SUBSPACE_Q_MAX_FEATURES];
    double std[L2_SUBSPACE_Q_MAX_FEATURES];

    /* Subspace basis V_k: [k][D], rows are orthonormal */
    double Vk[L2_SUBSPACE_Q_MAX_COMPONENTS][L2_SUBSPACE_Q_MAX_FEATURES];
    size_t k_effective;

    /* Precomputed and sorted Q values from training slice */
    double *q_sorted;
    size_t n_train;

    /* SPOT fallback parameters (used when spot_fallback == true) */
    double spot_threshold[L2_SUBSPACE_Q_MAX_FEATURES];
    double spot_scale[L2_SUBSPACE_Q_MAX_FEATURES];

    /* Streaming state */
    double ewma_state;
    bool   is_initialized;
};

/*
 * Initialize the Subspace-Q detector structure.
 */
void l2_subspace_q_init(struct subspace_q_detector *sq,
                        size_t n_features,
                        size_t n_components,
                        double alpha_ewma);

/*
 * Free any dynamically allocated memory in the detector.
 */
void l2_subspace_q_free(struct subspace_q_detector *sq);

/*
 * Fit the detector from a row-major training matrix of shape [n_samples * n_features].
 * If n_samples < 2 * n_features, automatically arms the SPOT fallback.
 */
bool l2_subspace_q_fit(struct subspace_q_detector *sq,
                       const double *train_matrix,
                       size_t n_samples);

/*
 * Reset streaming EWMA state to 0.0 (e.g. at stream start or per-host reinitialization).
 */
void l2_subspace_q_reset_stream(struct subspace_q_detector *sq);

/*
 * Compute raw un-smoothed anomaly score for a single feature vector:
 *   - If spot_fallback: returns SPOT raw score
 *   - Otherwise: returns ECOD surprise O(Q) = -ln((ge + 1) / (N + 1))
 */
double l2_subspace_q_score_raw(const struct subspace_q_detector *sq,
                               const double *features);

/*
 * Process a single test window in stream order:
 *   - Computes raw score
 *   - If spot_fallback: returns raw SPOT score (no EWMA, matching reference)
 *   - Otherwise: updates ewma_state = alpha * O_t + (1 - alpha) * ewma_state
 *     and returns ewma_state.
 */
double l2_subspace_q_step(struct subspace_q_detector *sq,
                          const double *features);

#endif /* L2_SUBSPACE_Q_H */
