#ifndef L2_CONFORMAL_LIVE_H
#define L2_CONFORMAL_LIVE_H

#include <stdbool.h>
#include <stddef.h>
#include "conformal_combine.h"

/*
 * Live wiring of the split-conformal combiner (conformal_combine.{c,h}) into the
 * Layer-2 decision path. The shipped default remains the disjunctive OR rule; this
 * path is selected via config.ensemble_rule != 0. A warm-up guard keeps a cold
 * context on the OR rule until the calibration buffers hold ~K/alpha benign windows
 * (below that a conformal p-value cannot reach the nominal level). The calibration
 * buffers are populated from the training-free benign stream and frozen while the
 * baseline poisoning guard / on-attack freeze is active (paper section4.7, section4.11).
 */
struct conformal_live {
    struct conformal_combiner cc;
    size_t observed;       /* benign calibration windows appended so far */
    size_t warmup_min;     /* ceil(n_paths/alpha): below this, NOT READY */
    int rule;              /* 1 = Bonferroni (section4.10), 2 = e-value */
    bool initialized;
};

/*
 * Initialize live conformal wrapper with K paths.
 * Returns true on success, false if the configuration violates the buffer floor.
 */
bool l2_conformal_live_init_k(struct conformal_live *cl, double alpha,
                              size_t capacity, int rule, size_t n_paths);

/*
 * Default 3-path initialization for backwards compatibility.
 */
void l2_conformal_live_init(struct conformal_live *cl, double alpha,
                            size_t capacity, int rule);

/*
 * Decide for one window from the three per-path anomaly scores.
 * Returns: 1 = anomaly, 0 = benign, -1 = NOT READY (caller must use the OR rule).
 * When `calibrate` is true (window deemed benign by the training-free gate AND the
 * baseline is not frozen), the scores are appended to the calibration buffers first.
 */
int l2_conformal_live_decide(struct conformal_live *cl,
                             double z, double cusum_norm, double jsd,
                             bool calibrate);

/*
 * Decide for one window from K per-path anomaly scores.
 * Returns: 1 = anomaly, 0 = benign, -1 = NOT READY (caller must use the OR rule).
 */
int l2_conformal_live_decide_k(struct conformal_live *cl,
                               const double *scores, size_t count,
                               bool calibrate);

#endif /* L2_CONFORMAL_LIVE_H */
