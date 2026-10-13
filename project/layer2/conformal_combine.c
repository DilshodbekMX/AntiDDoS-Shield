/*
 * conformal_combine.c -- see conformal_combine.h.
 *
 * Faithful C mirror of experiment/run_fpr_conformal.py: pval() and the Bonferroni / e-value
 * combiners parameterized by K paths. Counting #{buf >= s} is O(n) per query with no sort,
 * matching the harness result exactly (ties counted with >=, denominator n+1).
 */
#include "conformal_combine.h"
#include <stdio.h>
#include <math.h>

static void path_init(struct conformal_path *p, size_t capacity)
{
    if (capacity < 1) capacity = 1;
    if (capacity > CONFORMAL_MAX_BUFFER) capacity = CONFORMAL_MAX_BUFFER;
    p->capacity = capacity;
    p->count = 0;
    p->head = 0;
}

bool conformal_combiner_init_k(struct conformal_combiner *cc, size_t capacity, double alpha, size_t n_paths)
{
    if (!cc) return false;
    if (n_paths < 1 || n_paths > CONFORMAL_MAX_PATHS) {
        fprintf(stderr, "[Conformal] ERROR: Invalid n_paths=%zu (must be in [1, %d])\n",
                n_paths, CONFORMAL_MAX_PATHS);
        cc->n_paths = 0;
        return false;
    }
    if (!(alpha > 0.0 && alpha < 1.0)) {
        alpha = 0.001;
    }

    /* Calibration floor validation:
     * To ever achieve a Bonferroni threshold of alpha / n_paths, the minimum reachable
     * split-conformal p-value 1 / (n + 1) must be <= alpha / n_paths.
     * This requires n >= ceil(n_paths / alpha).
     * If ceil(n_paths / alpha) > CONFORMAL_MAX_BUFFER, the rule would go permanently silent. */
    size_t need = (size_t)ceil((double)n_paths / alpha);
    if (need > CONFORMAL_MAX_BUFFER || (alpha / (double)n_paths) <= (1.0 / ((double)CONFORMAL_MAX_BUFFER + 1.0))) {
        fprintf(stderr, "[Conformal] ERROR: Buffer floor violation: K=%zu, alpha=%f requires capacity >= %zu > %d (min p=1/%d > alpha/K=%e). Refusing to arm.\n",
                n_paths, alpha, need, CONFORMAL_MAX_BUFFER, CONFORMAL_MAX_BUFFER + 1, alpha / (double)n_paths);
        cc->n_paths = 0;
        return false;
    }

    if (capacity < need) capacity = need;
    if (capacity > CONFORMAL_MAX_BUFFER) capacity = CONFORMAL_MAX_BUFFER;

    for (size_t i = 0; i < n_paths; i++) {
        path_init(&cc->paths[i], capacity);
    }
    for (size_t i = n_paths; i < CONFORMAL_MAX_PATHS; i++) {
        path_init(&cc->paths[i], 0);
    }
    cc->n_paths = n_paths;
    cc->alpha = alpha;
    return true;
}

void conformal_combiner_init(struct conformal_combiner *cc, size_t capacity, double alpha)
{
    conformal_combiner_init_k(cc, capacity, alpha, CONFORMAL_DEFAULT_PATHS);
}

void conformal_path_observe(struct conformal_path *p, double score)
{
    if (!p || p->capacity == 0) return;
    p->scores[p->head] = score;
    p->head = (p->head + 1) % p->capacity;
    if (p->count < p->capacity)
        p->count++;
}

void conformal_combiner_observe_k(struct conformal_combiner *cc,
                                  const double *scores, size_t count)
{
    if (!cc || !scores) return;
    size_t k = (count < cc->n_paths) ? count : cc->n_paths;
    for (size_t i = 0; i < k; i++) {
        conformal_path_observe(&cc->paths[i], scores[i]);
    }
}

void conformal_combiner_observe(struct conformal_combiner *cc,
                                double z_score, double cusum_score, double jsd_score)
{
    double scores[3] = { z_score, cusum_score, jsd_score };
    conformal_combiner_observe_k(cc, scores, 3);
}

double conformal_pvalue(const struct conformal_path *p, double score)
{
    if (!p || p->count == 0)
        return 1.0;   /* no calibration -> most conservative p-value */
    size_t ge = 0;
    for (size_t i = 0; i < p->count; i++) {
        if (p->scores[i] >= score)
            ge++;
    }
    return (1.0 + (double)ge) / ((double)p->count + 1.0);
}

bool conformal_decide_bonferroni_k(const struct conformal_combiner *cc,
                                   const double *scores, size_t count)
{
    if (!cc || cc->n_paths == 0 || !scores || count == 0) return false;
    size_t k = (count < cc->n_paths) ? count : cc->n_paths;
    double pmin = 1.0;
    for (size_t i = 0; i < k; i++) {
        double p = conformal_pvalue(&cc->paths[i], scores[i]);
        if (p < pmin) pmin = p;
    }
    return pmin <= cc->alpha / (double)cc->n_paths;
}

bool conformal_decide_bonferroni(const struct conformal_combiner *cc,
                                 double z_score, double cusum_score, double jsd_score)
{
    double scores[3] = { z_score, cusum_score, jsd_score };
    return conformal_decide_bonferroni_k(cc, scores, 3);
}

bool conformal_decide_evalue_k(const struct conformal_combiner *cc,
                               const double *scores, size_t count)
{
    if (!cc || cc->n_paths == 0 || !scores || count == 0) return false;
    size_t k = (count < cc->n_paths) ? count : cc->n_paths;
    const double floor_p = 1e-12;   /* guard against division by zero */
    double sum_recip = 0.0;
    for (size_t i = 0; i < k; i++) {
        double p = conformal_pvalue(&cc->paths[i], scores[i]);
        if (p < floor_p) p = floor_p;
        sum_recip += 1.0 / p;
    }
    double e_mean = sum_recip / (double)cc->n_paths;
    return e_mean >= 1.0 / cc->alpha;
}

bool conformal_decide_evalue(const struct conformal_combiner *cc,
                             double z_score, double cusum_score, double jsd_score)
{
    double scores[3] = { z_score, cusum_score, jsd_score };
    return conformal_decide_evalue_k(cc, scores, 3);
}
