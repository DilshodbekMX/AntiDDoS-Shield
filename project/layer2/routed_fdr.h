/*
 * routed_fdr.h -- type-routed per-feature conformal p-values + ACAT / BH-FDR.
 *
 * Faithful C port of experiment/routed_fdr/routed_detector.py (the section5.8 winner).
 * This is the OFFLINE math port only; it is NOT wired into the live online
 * detection path. The online benign-calibration buffer + scoring loop are a
 * separate later step.
 *
 * Reuses struct conformal_path (conformal_combine.h) for the per-channel benign
 * calibration ring buffers. The split-conformal right-tail p-value here matches
 * the Python `conformal_p` EXACTLY, including the [1e-12, 1-1e-12] clamp:
 *
 *     p = (1 + #{calib >= score}) / (n + 1),  clamped to [EPS, 1-EPS]
 *
 * Channel structure (route_features):
 *   - SIMPLEX group A {tcp,udp,icmp,other}_ratio  -> ONE JSD channel (one buffer)
 *   - SIMPLEX group B {syn,synack,ack,rst,fin}_tcp_ratio -> ONE JSD channel
 *     (each group needs >=2 present members)
 *   - every OTHER active scalar -> a z channel AND a CUSUM channel collapsed by
 *     acat_pair into ONE channel p-value (two buffers per scalar channel).
 *
 * Window decision: BH-FDR over all channel p-values (the section5.8 winner). The
 * ACAT-combine decision is also exposed.
 */
#ifndef ROUTED_FDR_H
#define ROUTED_FDR_H

#include <stdbool.h>
#include <stddef.h>

#include "conformal_combine.h"   /* struct conformal_path, CONFORMAL_MAX_BUFFER */

#ifdef __cplusplus
extern "C" {
#endif

#define ROUTED_FDR_EPS 1e-12

/* -------------------------------------------------------------------------
 * Core p-value math (matches routed_detector.py exactly).
 * ------------------------------------------------------------------------- */

/* Right-tail split-conformal p-value of `score` against a calibration buffer:
 *     p = (1 + #{calib >= score}) / (n + 1)
 * Clamped to [EPS, 1-EPS]. Empty buffer (count==0) or NaN score -> 1.0.
 * Mirrors routed_detector.py:conformal_p (with the clamp). */
double routed_conformal_p(const struct conformal_path *p, double score);

/* ACAT collapse of a correlated (p_z, p_c) pair with EQUAL 0.5 weights (NO
 * /len averaging), per routed_detector.py:acat_pair:
 *     T = 0.5*tan((0.5-p_z)*pi) + 0.5*tan((0.5-p_c)*pi)
 *     p = 0.5 - atan(T)/pi,  clamped to [EPS, 1-EPS]. */
double routed_acat_pair(double p_z, double p_c);

/* Aggregated Cauchy across `n` channel p-values (routed_detector.py:acat_combine):
 *     T = mean over channels of 0.5*tan((0.5-p)*pi)
 *     p = 0.5 - atan(T)/pi,  clamped to [EPS, 1-EPS].
 * Empty (n==0) -> 1.0. Each input clamped to [EPS, 1-EPS] first. */
double routed_acat_combine(const double *pvals, size_t n);

/* Benjamini-Hochberg step-up (routed_detector.py:bh_reject).
 *   Sort p ascending; for rank k=1..m reject-set if p_(k) <= alpha*k/m; alarm
 *   iff any k qualifies. Returns true on alarm. When attr_index != NULL it is
 *   set to the index (into pvals) of the smallest-p channel (the attribution),
 *   or (size_t)-1 if no usable p-values. */
bool routed_bh_reject(const double *pvals, size_t n, double alpha, size_t *attr_index);

/* Smallest FDR level alpha at which BH rejects >=1 hypothesis
 * (routed_detector.py:bh_alpha_star):
 *     alpha* = min_k ( m * p_(k) / k ).
 * Returns alpha* (HUGE_VAL if no usable p-values); when attr_index != NULL it
 * is set to the smallest-p channel index (or (size_t)-1). */
double routed_bh_alpha_star(const double *pvals, size_t n, size_t *attr_index);

/* -------------------------------------------------------------------------
 * Routed multi-channel combiner (offline / fidelity scaffold).
 *
 * Each channel is either:
 *   - SCALAR: a z-buffer + a c(usum)-buffer; the channel p-value is
 *     acat_pair(conformal_p(z), conformal_p(c)).
 *   - JSD:    a single buffer; the channel p-value is conformal_p(jsd).
 * ------------------------------------------------------------------------- */

#define ROUTED_FDR_MAX_CHANNELS 64

enum routed_channel_kind {
    ROUTED_CH_SCALAR = 0,   /* z + cusum, collapsed by acat_pair */
    ROUTED_CH_JSD    = 1,   /* single jsd buffer                 */
};

struct routed_channel {
    enum routed_channel_kind kind;
    struct conformal_path    a;   /* SCALAR: z-buffer ; JSD: the jsd buffer */
    struct conformal_path    b;   /* SCALAR: cusum-buffer ; JSD: unused     */
};

struct routed_combiner {
    struct routed_channel channels[ROUTED_FDR_MAX_CHANNELS];
    size_t                n_channels;
    double                alpha;
};

/* Initialize a combiner with `alpha` (clamped to (0,1)) and zero channels. */
void routed_combiner_init(struct routed_combiner *rc, double alpha);

/* Append a channel; returns its index, or (size_t)-1 if full. capacity is the
 * per-buffer ring capacity (clamped like conformal_path). */
size_t routed_combiner_add_scalar(struct routed_combiner *rc, size_t capacity);
size_t routed_combiner_add_jsd(struct routed_combiner *rc, size_t capacity);

/* Observe one benign calibration score into a channel's buffer(s). For SCALAR
 * channels both z and cusum scores are supplied; for JSD channels only the
 * first (jsd) score is used. */
void routed_channel_observe_scalar(struct routed_combiner *rc, size_t ch,
                                   double z_score, double cusum_score);
void routed_channel_observe_jsd(struct routed_combiner *rc, size_t ch,
                                double jsd_score);

/* Compute the per-channel p-value for a test score (SCALAR uses both scores;
 * JSD uses jsd_score). */
double routed_channel_pvalue_scalar(const struct routed_combiner *rc, size_t ch,
                                    double z_score, double cusum_score);
double routed_channel_pvalue_jsd(const struct routed_combiner *rc, size_t ch,
                                 double jsd_score);

#ifdef __cplusplus
}
#endif

#endif /* ROUTED_FDR_H */
