#ifndef L2_INNOVATION_GATE_H
#define L2_INNOVATION_GATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "baselines.h"   /* L2_MAX_FEATURES + the L2_FEAT_* enum (for the log-transform set) */

/*
 * Innovation-gated z-path latch (the innovation-gate prototype, parametric-z variant). Faithful port of the
 * offline A/B winner (experiment/negatives/innovation_path.py `InnovationPath` +
 * the offline latch prototype): a bounded, strictly
 * training-free reduction of the cross-day per-window false-alarm floor.
 *
 * Motivation. The shipped ensemble is (z-path) OR CUSUM OR JSD. Benign cross-day drift pushes
 * the level z-path high but UNSURPRISING -- the level is elevated versus a stale reference, yet
 * it moves smoothly and is well predicted by a slow forecast. A real attack onset makes the
 * traffic SURPRISINGLY different (an abrupt jump the forecast did not anticipate). This module
 * gates ONLY the z-path on a per-context "surprise" latch: the z-path contributes to detection
 * only on windows where a training-free innovation statistic is elevated. CUSUM and JSD stay
 * ungated, so CUSUM's memory still carries sustained-flood detection. The caller's decision
 * becomes (z AND latch_open) OR CUSUM OR JSD.
 *
 * Statistic (THE fidelity-critical part -- matches InnovationPath EXACTLY). Each window ingests
 * the RAW per-feature values (NOT z-scores). Per feature f:
 *   - the cardinality features (unique_src_ips / unique_dst_ports / unique_flows) are
 *     log-transformed x = log(raw+1); all others pass through (identical to baselines.c
 *     feature_uses_log_transform / the harness `_log_xform`);
 *   - a SLOW AnEWMA forecast Z_f is maintained, predict-THEN-update, lambda = ANEWMA_LAMBDA =
 *     0.01 (a slow forecast does NOT "catch up" to a sustained attack);
 *   - the one-step forecast error gamma_f = |x_f - Z_f_prev| is standardized by the benign
 *     residual mean/std: surprise_f = (gamma_f - gbar_f)/gstd_f, with gbar_f/gstd_f fit on
 *     benign windows only and gstd_f variance-floored (2% of the benign |x| scale when the
 *     scale exceeds 50, else 1.0 -- identical to anewma.py / baselines.py);
 *   - the window surprise score is S = max_f surprise_f.
 *
 * Latch. A benign mean/std of S (mu_S, sigma_S) is calibrated from benign windows; the latch
 * opens when the standardized latch statistic L = (S - mu_S)/max(sigma_S, SIGMA_FLOOR) exceeds
 * kappa (SIGMA_FLOOR = 1.0, matching the prototype's SIGMA_FLOOR) and closes only after W
 * consecutive windows at/below kappa (hysteresis, W = 30). The gate calibrates over the ENTIRE
 * benign warmup and stays OPEN (fail-open, z-path never suppressed) the whole time; the caller
 * ARMS it once the benign baseline warmup is COMPLETE (`warm_complete`), at which point the
 * benign statistics FREEZE and the latch begins gating from a CLOSED state (matching the harness
 * the innovation-gate prototype "state starts CLOSED at test start"). A small MIN_CALIB floor keeps a degenerate
 * near-zero-benign context fail-open (it never arms), so the z-path is never suppressed there.
 *
 * Per-destination. The authoritative wiring is PER protected-IP: layer2.c allocates one gate
 * per per_ip_baseline and gates that IP's own z-path (see layer2_per_ip_detection_cycle). A
 * single global gate is also consulted on the aggregate path as a coarse fallback.
 *
 * Streaming-vs-harness note (calibration). The harness fits gbar_f/gstd_f + mu_S/sigma_S in a
 * two-pass BATCH over the benign-train rows, then freezes them for test scoring. This C engine
 * has no discrete warm/test boundary, so it fits the same quantities PREQUENTIALLY (online,
 * running mean/variance) over the per-IP benign-warmup windows and freezes when the caller
 * signals warmup complete. Calibration runs over the FULL benign warmup (the caller drives this
 * off the baseline: Tier-2 hourly fully ready), NOT a fixed short prefix: a harness sweep
 * (the full-warmup calibration arms) showed a fixed 10-window calibration recovers only
 * ~22% of the prototype's cross-day FPR cut and finite windows are non-monotonic (N=200/500 give -9.85 /
 * -7.59pp), while calibrating over the full benign warmup recovers 100% (full-warmup calibration reproduces the prototype,
 * -11.37pp). The LIVE update (score S + latch step) is byte-identical to the harness given the
 * same frozen gbar_f/gstd_f/mu_S/sigma_S; only the calibration transient differs. The update is
 * pure and deterministic (fixed arrays, O(features), no wall-clock/rand) so it can be mirrored
 * and diffed in Python.
 *
 * Engine-internal state only -- no shared-memory ABI impact. Selected via
 * config.ensemble_rule == L2_ENSEMBLE_RULE_INNOVATION_GATE (4); OFF by default (default OR).
 */
struct innovation_gate {
    /* Per-feature SLOW AnEWMA forecast of the (log-)feature (predict-then-update, lambda=0.01). */
    double forecast[L2_MAX_FEATURES];   /* Z_f: forecast of the log-transformed feature */
    bool   have_prev;                   /* false until the first window seeds the forecasts */

    /* Per-feature benign residual statistics, fit online (Welford) over benign windows.
     * gbar_f = resid_mean[f]; gstd_f = max(sqrt(resid_M2[f]/(n-1)), variance_floor). The
     * variance floor uses the benign |x| scale accumulated in abs_sum/abs_n. */
    double   resid_mean[L2_MAX_FEATURES];  /* running mean of gamma_f (= gbar_f) */
    double   resid_M2[L2_MAX_FEATURES];    /* running sum of squared deviations of gamma_f */
    uint32_t resid_n[L2_MAX_FEATURES];     /* residual count per feature */
    double   abs_sum[L2_MAX_FEATURES];     /* sum of |x_f| over benign windows (feat_scale) */
    uint32_t abs_n[L2_MAX_FEATURES];       /* count for feat_scale */

    /* Online calibration of the benign window-surprise distribution S (Welford). */
    double mu_S;                        /* running mean of the window surprise score S */
    double M2;                          /* running sum of squares of differences from mu_S */
    size_t calib_count;                 /* benign calibration windows observed */

    /* Latch state (hysteresis). */
    bool latch_open;                    /* current gate state (true = z-path may fire) */
    int  below_count;                   /* consecutive windows with L <= kappa while open */
    bool armed;                         /* false during warmup (fail-open, never suppress the
                                         * z-path); true once warm_complete arms + freezes it */

    /* Configuration. */
    double kappa;                       /* open threshold on the standardized latch statistic */
    int    hysteresis_w;                /* consecutive quiet windows required to close */
    size_t min_calib;                   /* FLOOR: min benign windows before arming is possible */

    bool initialized;
};

/*
 * Initialize the gate. kappa (open threshold, default 3.0), hysteresis_w (windows required to
 * close, default 30), min_calib (FLOOR on benign windows before arming is possible -- arming is
 * driven by the caller's `warm_complete` signal, and this floor only keeps a degenerate
 * near-zero-benign context fail-open, default 10). Non-positive arguments fall back to those
 * defaults.
 */
void l2_innovation_gate_init(struct innovation_gate *ig, double kappa,
                             int hysteresis_w, size_t min_calib);

/*
 * Advance the gate by one window from the RAW per-feature values (raw_features[i] is the raw
 * feature value for feature i, e.g. a struct l2_feature_snapshot's `values`; n = #features
 * supplied, a short vector is handled). The gate log-transforms the cardinality features
 * internally. When `calibrate` is true (a benign window) AND the gate is not yet armed, the
 * window feeds gbar_f/gstd_f and the benign mu_S/sigma_S estimate. `warm_complete` is the
 * caller's "benign baseline warmup is complete" signal (e.g. Tier-2 hourly fully ready): the
 * FIRST window on which it is true -- provided at least min_calib benign windows have been
 * calibrated -- ARMS the latch, FREEZES the benign statistics, and starts gating from a CLOSED
 * state. Until then the latch stays OPEN (fail-open) so the z-path is never suppressed during
 * warm-up. Returns the latch state AFTER the update: true = OPEN (z-path may contribute),
 * false = CLOSED (z-path suppressed for this window). Fails OPEN (returns true) on a NULL or
 * uninitialized gate so a misconfiguration can never silently suppress the z-path.
 */
bool l2_innovation_gate_update(struct innovation_gate *ig, const double *raw_features,
                               size_t n, bool calibrate, bool warm_complete);

#endif /* L2_INNOVATION_GATE_H */
