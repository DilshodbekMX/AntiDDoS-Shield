#ifndef LAYER1_TELEMETRY_BURST_EWMA_H
#define LAYER1_TELEMETRY_BURST_EWMA_H

#include <stdint.h>

/**
 * @file burst_ewma.h
 * @brief burst_factor = 100 * window_pps / EWMA(window_pps): the single definition used by
 *        both the aggregate path (shared_memory.c, l2_features_export_update -- one global
 *        EWMA) and the per-IP path (per_ip_features.c / per_ip_features_v6.c -- one EWMA per
 *        protected IP, Phase 2).
 *
 * Pure C, no DPDK; unit-tested by tests/unit/test_burst_ewma.c.
 *
 * Semantics (identical to the historical aggregate implementation, which this replaces
 * bit-for-bit):
 *   - the mean is seeded with the first window's rate. A mean below BURST_EWMA_SEED_FLOOR
 *     counts as unseeded and re-seeds on the next window, so a slot whose mean decayed to
 *     ~0 during a quiet spell re-seeds instead of reporting a huge ratio on the first
 *     window of returning traffic;
 *   - each window: mean' = mean + alpha * (x - mean);
 *   - the ratio divides by the POST-update mean: 100 * x / mean'. Because mean' already
 *     contains alpha * x, for a seeded mean the ratio is strictly below 100 / alpha
 *     (~3030.3 at alpha = 0.033): the feature saturates instead of scaling with the burst,
 *     and the uint16 conversion cannot overflow;
 *   - mean' == 0 (no traffic seen yet) reports BURST_FACTOR_NORMAL.
 */

/* EWMA smoothing factor. 1/alpha ~ 30 windows of memory at the 1 Hz export cadence.
 * The only definition of this constant -- both paths must use it. */
#define BURST_EWMA_ALPHA        0.033

/* A mean below this is treated as unseeded: the next window's rate becomes the mean. */
#define BURST_EWMA_SEED_FLOOR   1.0

/* Ratio reported when there is no mean to divide by (never any traffic). */
#define BURST_FACTOR_NORMAL     100

/* Every ratio produced by burst_factor_from() on a seeded mean is <= this value
 * (floor(100 / alpha) = 3030 at alpha = 0.033). */
#define BURST_FACTOR_SATURATION ((uint16_t)(100.0 / BURST_EWMA_ALPHA))

/**
 * One EWMA step. Seeds when the mean is unseeded, otherwise mean + alpha * (x - mean).
 * Pure: returns the post-update mean without touching any state.
 */
static inline double burst_ewma_step(double mean, double x) {
    return (mean < BURST_EWMA_SEED_FLOOR) ? x : mean + BURST_EWMA_ALPHA * (x - mean);
}

/**
 * Ratio against the post-update mean: 100 * x / mean_post, as uint16.
 * mean_post == 0 (no traffic yet) reports BURST_FACTOR_NORMAL.
 */
static inline uint16_t burst_factor_from(double mean_post, double x) {
    return (mean_post > 0.0) ? (uint16_t)(x * 100.0 / mean_post)
                             : (uint16_t)BURST_FACTOR_NORMAL;
}

/**
 * Commit one window: updates *mean in place and returns this window's burst factor.
 * This is the aggregate path's operation; the per-IP path splits it into a preview
 * (burst_factor_from(burst_ewma_step(mean, x), x) in the snapshot) and a commit
 * (mean = burst_ewma_step(mean, x) at the window roll) because its snapshot can run
 * more than once per window.
 */
static inline uint16_t burst_ewma_update(double *mean, double x) {
    *mean = burst_ewma_step(*mean, x);
    return burst_factor_from(*mean, x);
}

#endif /* LAYER1_TELEMETRY_BURST_EWMA_H */
