/*
 * conformal_combine.h -- calibrated false-alarm control for the Layer-2 ensemble.
 *
 * Mirrors experiment/run_fpr_conformal.py. Replaces the disjunctive (OR) combination of the
 * K detection paths with a multiplicity-corrected combination of split-conformal p-values,
 * so the per-window false-positive rate is controlled at a target alpha instead of compounding
 * across paths (see paper section4.10, section6.10).
 *
 * Per path p, from a benign calibration buffer of size n, the split-conformal right-tail p-value
 * of a score s is:   p(s) = (1 + #{buf >= s}) / (n + 1)
 * which is super-uniform on [0,1] under exchangeability of benign windows. The paths are then
 * combined under family-wise control:
 *   Bonferroni:  alarm if min(p_1 ... p_K) <= alpha/K                     (valid FWER control, union bound)
 *   e-value:     alarm if mean(1/p_1 ... 1/p_K) >= 1/alpha                (reciprocal-p HEURISTIC -- 1/p is
 *                NOT a calibrated e-value (E[1/p] ~ ln(n+1) >> 1), so Vovk & Wang's arbitrary-dependence
 *                guarantee does NOT transfer; secondary combiner, Bonferroni carries the headline; section4.10)
 *
 * Calibration uses only benign-window scores (no attack labels), preserving the training-free
 * posture. A finite buffer of size n floors the smallest reachable target at alpha ~= K/(n+1).
 */
#ifndef CONFORMAL_COMBINE_H
#define CONFORMAL_COMBINE_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONFORMAL_MAX_BUFFER    4096   /* upper bound on per-path calibration window */
#define CONFORMAL_MAX_PATHS     8      /* upper bound on number of combined detection paths */
#define CONFORMAL_DEFAULT_PATHS 3      /* default 3 paths: tier-Z, CUSUM, JSD */

/* One detection path's rolling benign-score calibration buffer (ring buffer). */
struct conformal_path {
    double  scores[CONFORMAL_MAX_BUFFER];
    size_t  capacity;   /* active capacity (<= CONFORMAL_MAX_BUFFER) */
    size_t  count;      /* number of valid scores (<= capacity)      */
    size_t  head;       /* next write index (ring)                   */
};

/* Multi-path combiner: supports up to CONFORMAL_MAX_PATHS paths (default 3: tier-Z, CUSUM, JSD). */
struct conformal_combiner {
    struct conformal_path paths[CONFORMAL_MAX_PATHS];
    size_t  n_paths;    /* active number of paths (<= CONFORMAL_MAX_PATHS) */
    double  alpha;      /* target per-window false-alarm rate */
};

/* Initialize a combiner with K paths. capacity is clamped to [1, CONFORMAL_MAX_BUFFER]; alpha to (0,1).
 * Returns true on success, false if the configuration violates the finite calibration buffer floor
 * (i.e. ceil(n_paths / alpha) > CONFORMAL_MAX_BUFFER or alpha/n_paths <= 1/(capacity+1)). */
bool conformal_combiner_init_k(struct conformal_combiner *cc, size_t capacity, double alpha, size_t n_paths);

/* Initialize a default 3-path combiner (tier-Z, CUSUM, JSD). */
void conformal_combiner_init(struct conformal_combiner *cc, size_t capacity, double alpha);

/* Add one benign calibration score to a path's buffer (ring overwrite when full). */
void conformal_path_observe(struct conformal_path *p, double score);

/* Convenience: observe one benign window's three path scores at once (paths[0..2]). */
void conformal_combiner_observe(struct conformal_combiner *cc,
                                double z_score, double cusum_score, double jsd_score);

/* Observe arbitrary K path scores at once. */
void conformal_combiner_observe_k(struct conformal_combiner *cc,
                                  const double *scores, size_t count);

/* Split-conformal right-tail p-value of `score` against the buffer. Empty buffer -> 1.0. */
double conformal_pvalue(const struct conformal_path *p, double score);

/* Bonferroni family-wise rule across 3 paths: alarm if min p-value <= alpha / n_paths. */
bool conformal_decide_bonferroni(const struct conformal_combiner *cc,
                                 double z_score, double cusum_score, double jsd_score);

/* Bonferroni family-wise rule across K paths: alarm if min(p_1 .. p_K) <= alpha / n_paths. */
bool conformal_decide_bonferroni_k(const struct conformal_combiner *cc,
                                   const double *scores, size_t count);

/* e-value averaging rule across 3 paths: alarm if mean(1/p) >= 1/alpha. */
bool conformal_decide_evalue(const struct conformal_combiner *cc,
                             double z_score, double cusum_score, double jsd_score);

/* e-value averaging rule across K paths: alarm if mean(1/p_1 .. 1/p_K) >= 1/alpha. */
bool conformal_decide_evalue_k(const struct conformal_combiner *cc,
                               const double *scores, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* CONFORMAL_COMBINE_H */
