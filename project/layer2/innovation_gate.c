#include "innovation_gate.h"
#include <math.h>

/* SLOW AnEWMA forecast smoothing (ANEWMA_LAMBDA in innovation_path.py / anewma.py). A LOW
 * lambda keeps the forecast from "catching up" to a sustained shift, so an abrupt onset stays
 * surprising for many windows while a smooth benign ramp is well predicted. */
#define IG_LAMBDA          0.01
/* Per-feature residual variance floor (identical to InnovationPath.fit / baselines.py): 2% of
 * the benign |x| scale when that scale exceeds 50, else an absolute floor of 1.0. */
#define IG_VAR_FLOOR_SCALE 50.0
#define IG_VAR_FLOOR_FRAC  0.02
#define IG_VAR_FLOOR_MIN   1.0
/* Floor on sigma_S in the standardized latch statistic (the prototype's SIGMA_FLOOR=1.0:
 * the innovation score is already a standardized residual, so a 1.0 floor guards a degenerate
 * near-constant benign sigma from opening the latch on trivial fluctuations). */
#define IG_SIGMA_S_FLOOR   1.0

/* Log-transform the three cardinality features exactly like baselines.c
 * feature_uses_log_transform() and the harness `_log_xform`; all other features pass through. */
static inline double ig_log_xform(size_t f, double x)
{
    if (f == (size_t)L2_FEAT_UNIQUE_SRC_IPS ||
        f == (size_t)L2_FEAT_UNIQUE_DST_PORTS ||
        f == (size_t)L2_FEAT_UNIQUE_FLOWS) {
        return log(x + 1.0);
    }
    return x;
}

/* Benign residual mean/std for one feature from the (frozen or in-progress) accumulators.
 * gbar = running mean; gstd = max(sample-std, variance-floor). Features with no residual yet
 * report gstd = 0.0 so the caller skips them (mirrors the harness gvec[f] = None). */
static void ig_feature_stats(const struct innovation_gate *ig, size_t f,
                             double *gbar, double *gstd)
{
    uint32_t n = ig->resid_n[f];
    if (n == 0) {
        *gbar = 0.0;
        *gstd = 0.0;
        return;
    }
    double m = ig->resid_mean[f];
    double sd = 0.0;
    if (n > 1) {
        double var = ig->resid_M2[f] / (double)(n - 1);   /* == sum((v-m)^2)/(n-1) */
        if (var < 0.0) var = 0.0;                          /* numerical guard */
        sd = sqrt(var);
    }
    double feat_scale = (ig->abs_n[f] > 0) ? ig->abs_sum[f] / (double)ig->abs_n[f] : 0.0;
    double floor = (feat_scale > IG_VAR_FLOOR_SCALE)
                       ? (feat_scale * IG_VAR_FLOOR_FRAC)
                       : IG_VAR_FLOOR_MIN;
    *gbar = m;
    *gstd = (sd > floor) ? sd : floor;
}

void l2_innovation_gate_init(struct innovation_gate *ig, double kappa,
                             int hysteresis_w, size_t min_calib)
{
    if (!ig) return;
    for (size_t f = 0; f < L2_MAX_FEATURES; f++) {
        ig->forecast[f]   = 0.0;
        ig->resid_mean[f] = 0.0;
        ig->resid_M2[f]   = 0.0;
        ig->resid_n[f]    = 0;
        ig->abs_sum[f]    = 0.0;
        ig->abs_n[f]      = 0;
    }
    ig->have_prev = false;
    ig->mu_S = 0.0;
    ig->M2 = 0.0;
    ig->calib_count = 0;
    ig->armed = false;
    /* Default OPEN: until the latch ARMS (the caller's warm_complete, with >= min_calib benign
     * windows) the z-path must never be suppressed. */
    ig->latch_open = true;
    ig->below_count = 0;
    ig->kappa = (kappa > 0.0) ? kappa : 3.0;
    ig->hysteresis_w = (hysteresis_w > 0) ? hysteresis_w : 30;
    ig->min_calib = (min_calib > 0) ? min_calib : 10;
    ig->initialized = true;
}

bool l2_innovation_gate_update(struct innovation_gate *ig, const double *raw_features,
                               size_t n, bool calibrate, bool warm_complete)
{
    /* Fail OPEN on any misuse so the z-path is never silently gated off. */
    if (!ig || !ig->initialized || !raw_features) return true;

    /* ARM on the FIRST window where the benign baseline warmup is COMPLETE (the caller's
     * warm_complete) AND at least min_calib benign windows have been calibrated. The floor keeps
     * a degenerate near-zero-benign context fail-open -- it never arms. Arming latches once set;
     * from then on the benign statistics are FROZEN and the latch gates from a CLOSED start
     * (matching the harness the innovation-gate prototype "state starts CLOSED at test start"). Calibrating over the FULL
     * benign warmup -- not a fixed 10-window prefix -- is what recovers the prototype's cross-day FPR cut
     * (full-warmup calibration reproduces the prototype; a fixed window recovers only ~22% and is non-monotonic). */
    if (!ig->armed && warm_complete && ig->calib_count >= ig->min_calib) {
        ig->armed = true;
        ig->latch_open = false;   /* start CLOSED at the warm/test boundary (innovation-gate prototype) */
        ig->below_count = 0;
    }
    /* Freeze the benign statistics the moment we arm: only calibrate while still warming up. */
    bool do_calib = calibrate && !ig->armed;

    size_t nf = (n < L2_MAX_FEATURES) ? n : L2_MAX_FEATURES;

    /* First window per gate: seed the forecasts from the log-xformed features, emit no
     * residual/surprise this window (mirrors the harness Z_0 = first observation, no gamma).
     * The benign |x| scale is still accumulated on this window (as in InnovationPath.fit). */
    if (!ig->have_prev) {
        for (size_t f = 0; f < nf; f++) {
            double x = ig_log_xform(f, raw_features[f]);
            ig->forecast[f] = x;
            if (do_calib) {
                ig->abs_sum[f] += fabs(x);
                ig->abs_n[f]   += 1;
            }
        }
        ig->have_prev = true;
        return ig->latch_open;   /* still OPEN (not yet armed) */
    }

    /* Per-feature one-step forecast error, standardized by the benign residual mean/std;
     * window surprise score S = max over active features. Predict-then-update: the residual
     * uses the PREVIOUS forecast, then the forecast advances (lambda = 0.01). */
    double S = 0.0;
    bool have_S = false;
    for (size_t f = 0; f < nf; f++) {
        double x = ig_log_xform(f, raw_features[f]);
        double pred = ig->forecast[f];             /* Z_{t-1} */
        double gamma = fabs(x - pred);             /* one-step forecast error (BEFORE update) */

        if (do_calib) {
            /* Welford update of the benign residual mean/variance (== the harness two-pass
             * gbar/gstd once enough benign windows accumulate); plus the |x| scale. */
            ig->resid_n[f] += 1;
            double d = gamma - ig->resid_mean[f];
            ig->resid_mean[f] += d / (double)ig->resid_n[f];
            ig->resid_M2[f]   += d * (gamma - ig->resid_mean[f]);
            ig->abs_sum[f]    += fabs(x);
            ig->abs_n[f]      += 1;
        }

        ig->forecast[f] = IG_LAMBDA * x + (1.0 - IG_LAMBDA) * pred;   /* advance the forecast */

        if (ig->resid_n[f] > 0) {
            double gbar, gstd;
            ig_feature_stats(ig, f, &gbar, &gstd);
            if (gstd > 0.0) {
                double surprise = (gamma - gbar) / gstd;
                if (!have_S || surprise > S) {
                    S = surprise;
                    have_S = true;
                }
            }
        }
    }
    if (!have_S) S = 0.0;

    /* Online benign calibration of the surprise-score distribution (Welford mean/variance).
     * Frozen once armed (do_calib is false), so this runs over the FULL benign warmup. */
    if (do_calib) {
        ig->calib_count++;
        double delta = S - ig->mu_S;
        ig->mu_S += delta / (double)ig->calib_count;
        double delta2 = S - ig->mu_S;
        ig->M2 += delta * delta2;
    }

    /* Not yet armed -> keep the gate OPEN (fail-open for the ENTIRE benign warmup; never
     * suppress the z-path while calibrating). */
    if (!ig->armed) {
        ig->latch_open = true;
        ig->below_count = 0;
        return ig->latch_open;
    }

    double variance = (ig->calib_count > 1) ? (ig->M2 / (double)(ig->calib_count - 1)) : 0.0;
    double sigma_S = sqrt(variance > 0.0 ? variance : 0.0);
    double denom = (sigma_S > IG_SIGMA_S_FLOOR) ? sigma_S : IG_SIGMA_S_FLOOR;
    double L = (S - ig->mu_S) / denom;

    if (L > ig->kappa) {
        /* Surprising window: (re)open and reset the quiet-window counter. */
        ig->latch_open = true;
        ig->below_count = 0;
    } else if (ig->latch_open) {
        /* Quiet window while open: advance hysteresis; close only after W in a row. */
        ig->below_count++;
        if (ig->below_count >= ig->hysteresis_w) {
            ig->latch_open = false;
            ig->below_count = 0;
        }
    }
    return ig->latch_open;
}
