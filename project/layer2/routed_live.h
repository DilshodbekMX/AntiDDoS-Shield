#ifndef L2_ROUTED_LIVE_H
#define L2_ROUTED_LIVE_H

#include <stdbool.h>
#include <stddef.h>
#include "routed_fdr.h"

/*
 * Live wiring of the routed per-feature FDR combiner (routed_fdr.{c,h}) into the
 * Layer-2 decision path (paper section6.15). One scalar channel per monitored feature
 * (its z and CUSUM scores, ACAT-collapsed) plus one JSD channel; per-channel
 * split-conformal p-values are rejected under Benjamini-Hochberg FDR control.
 * Selected via config.ensemble_rule == 3. A warm-up guard keeps a cold context on
 * the OR rule until the calibration buffers hold ~3/alpha benign windows.
 */
struct routed_live {
    struct routed_combiner rc;
    size_t n_scalar;       /* scalar channels registered (= #features, capped) */
    size_t jsd_ch;         /* index of the JSD channel */
    size_t observed;       /* benign calibration windows appended */
    size_t warmup_min;     /* ceil(3/alpha) */
    double alpha;
    bool initialized;
};

void l2_routed_live_init(struct routed_live *rl, double alpha,
                         size_t n_features, size_t capacity);

/*
 * Decide for one window from the per-feature z and CUSUM score vectors and the JSD score.
 * Returns: 1 = anomaly, 0 = benign, -1 = NOT READY (caller must use the OR rule). When
 * `calibrate` is true the scores are appended to the per-channel calibration buffers first.
 * The attributed feature index (BH rejection) is written to *attr_index when non-NULL.
 */
int l2_routed_live_decide(struct routed_live *rl,
                          const double *z, const double *cusum, size_t n_features,
                          double jsd, bool calibrate, size_t *attr_index);

#endif /* L2_ROUTED_LIVE_H */
