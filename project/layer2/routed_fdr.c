/*
 * routed_fdr.c -- see routed_fdr.h.
 *
 * Faithful C port of experiment/routed_fdr/routed_detector.py. Every formula,
 * clamp, tie-rule and attribution choice mirrors the Python reference so the
 * bit-level fidelity test (tests/unit/test_routed_fdr.c) reproduces it to <1e-9.
 *
 * NOT wired into the live detection path -- offline math + fidelity proof only.
 */
#include "routed_fdr.h"

#include <math.h>
#include <stddef.h>

#define EPS ROUTED_FDR_EPS

static double clamp_p(double p)
{
    if (p < EPS)        return EPS;
    if (p > 1.0 - EPS)  return 1.0 - EPS;
    return p;
}

/* -------------------------------------------------------------------------
 * conformal_p -- right-tail split-conformal p-value with the [EPS,1-EPS] clamp.
 *
 * Python `conformal_p`: score is None (no channel) -> 1.0; n==0 -> 1.0; else
 * p = (1 + #{calib >= score})/(n+1), clamped. We use NaN as the C analogue of
 * a None score (channel not ready).
 * ------------------------------------------------------------------------- */
double routed_conformal_p(const struct conformal_path *p, double score)
{
    if (!p || p->count == 0)
        return 1.0;
    if (isnan(score))
        return 1.0;
    size_t ge = 0;
    for (size_t i = 0; i < p->count; i++) {
        if (p->scores[i] >= score)
            ge++;
    }
    double pv = (1.0 + (double)ge) / ((double)p->count + 1.0);
    return clamp_p(pv);
}

/* -------------------------------------------------------------------------
 * ACAT -- Aggregated Cauchy.
 * ------------------------------------------------------------------------- */
double routed_acat_pair(double p_z, double p_c)
{
    p_z = clamp_p(p_z);
    p_c = clamp_p(p_c);
    double T = 0.5 * tan((0.5 - p_z) * M_PI) + 0.5 * tan((0.5 - p_c) * M_PI);
    double p = 0.5 - atan(T) / M_PI;
    return clamp_p(p);
}

double routed_acat_combine(const double *pvals, size_t n)
{
    if (!pvals || n == 0)
        return 1.0;
    double T = 0.0;
    for (size_t i = 0; i < n; i++) {
        double p = clamp_p(pvals[i]);
        T += 0.5 * tan((0.5 - p) * M_PI);
    }
    T /= (double)n;
    double p = 0.5 - atan(T) / M_PI;
    return clamp_p(p);
}

/* -------------------------------------------------------------------------
 * BH-FDR step-up.
 *
 * Python sorts (p, original_index) ascending with a STABLE sort keyed on p
 * alone, so ties keep original (input) order. Attribution = first element of
 * the sorted list (smallest p; ties -> smallest original index). We reproduce
 * the stable ascending order with an index permutation + stable insertion-style
 * selection. m and n are tiny (~21-26 channels), so an O(m^2) stable sort is
 * fine and avoids qsort's comparator-tie ambiguity.
 * ------------------------------------------------------------------------- */

/* Build a stable-ascending permutation `order` of the indices i where
 * pvals[i] is usable (finite). Returns the count m. Ties keep input order. */
static size_t stable_argsort(const double *pvals, size_t n, size_t *order)
{
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        if (isnan(pvals[i]))   /* None-channel: dropped, as in Python */
            continue;
        /* insert i into order keeping ascending-by-p, stable on ties */
        size_t pos = m;
        while (pos > 0 && pvals[order[pos - 1]] > pvals[i])
            pos--;
        for (size_t j = m; j > pos; j--)
            order[j] = order[j - 1];
        order[pos] = i;
        m++;
    }
    return m;
}

bool routed_bh_reject(const double *pvals, size_t n, double alpha, size_t *attr_index)
{
    if (attr_index) *attr_index = (size_t)-1;
    if (!pvals || n == 0)
        return false;

    size_t order[ROUTED_FDR_MAX_CHANNELS];
    size_t cap = (n <= ROUTED_FDR_MAX_CHANNELS) ? n : ROUTED_FDR_MAX_CHANNELS;
    size_t m = stable_argsort(pvals, cap, order);
    if (m == 0)
        return false;

    /* attribution = smallest-p channel (sorted-list head), regardless of reject */
    if (attr_index) *attr_index = order[0];

    int k_max = -1;
    for (size_t rank = 1; rank <= m; rank++) {
        double p = pvals[order[rank - 1]];
        if (p <= alpha * (double)rank / (double)m)
            k_max = (int)rank;
    }
    if (k_max < 0) {
        /* Python returns (False, None): no rejection => no attribution */
        if (attr_index) *attr_index = (size_t)-1;
        return false;
    }
    return true;
}

double routed_bh_alpha_star(const double *pvals, size_t n, size_t *attr_index)
{
    if (attr_index) *attr_index = (size_t)-1;
    if (!pvals || n == 0)
        return HUGE_VAL;

    size_t order[ROUTED_FDR_MAX_CHANNELS];
    size_t cap = (n <= ROUTED_FDR_MAX_CHANNELS) ? n : ROUTED_FDR_MAX_CHANNELS;
    size_t m = stable_argsort(pvals, cap, order);
    if (m == 0)
        return HUGE_VAL;

    if (attr_index) *attr_index = order[0];

    double a_star = HUGE_VAL;
    for (size_t rank = 1; rank <= m; rank++) {
        double cand = (double)m * pvals[order[rank - 1]] / (double)rank;
        if (cand < a_star)
            a_star = cand;
    }
    return a_star;
}

/* -------------------------------------------------------------------------
 * Routed multi-channel combiner.
 * ------------------------------------------------------------------------- */
void routed_combiner_init(struct routed_combiner *rc, double alpha)
{
    if (!rc) return;
    rc->n_channels = 0;
    if (alpha <= 0.0)  alpha = 1e-6;
    if (alpha >= 1.0)  alpha = 1.0 - 1e-9;
    rc->alpha = alpha;
}

/* path_init clone (conformal_path is opaque-by-reuse; replicate the clamp). */
static void rf_path_init(struct conformal_path *p, size_t capacity)
{
    if (capacity < 1) capacity = 1;
    if (capacity > CONFORMAL_MAX_BUFFER) capacity = CONFORMAL_MAX_BUFFER;
    p->capacity = capacity;
    p->count = 0;
    p->head = 0;
}

size_t routed_combiner_add_scalar(struct routed_combiner *rc, size_t capacity)
{
    if (!rc || rc->n_channels >= ROUTED_FDR_MAX_CHANNELS)
        return (size_t)-1;
    size_t i = rc->n_channels++;
    rc->channels[i].kind = ROUTED_CH_SCALAR;
    rf_path_init(&rc->channels[i].a, capacity);
    rf_path_init(&rc->channels[i].b, capacity);
    return i;
}

size_t routed_combiner_add_jsd(struct routed_combiner *rc, size_t capacity)
{
    if (!rc || rc->n_channels >= ROUTED_FDR_MAX_CHANNELS)
        return (size_t)-1;
    size_t i = rc->n_channels++;
    rc->channels[i].kind = ROUTED_CH_JSD;
    rf_path_init(&rc->channels[i].a, capacity);
    rf_path_init(&rc->channels[i].b, 1);   /* unused */
    return i;
}

void routed_channel_observe_scalar(struct routed_combiner *rc, size_t ch,
                                   double z_score, double cusum_score)
{
    if (!rc || ch >= rc->n_channels) return;
    conformal_path_observe(&rc->channels[ch].a, z_score);
    conformal_path_observe(&rc->channels[ch].b, cusum_score);
}

void routed_channel_observe_jsd(struct routed_combiner *rc, size_t ch,
                                double jsd_score)
{
    if (!rc || ch >= rc->n_channels) return;
    conformal_path_observe(&rc->channels[ch].a, jsd_score);
}

double routed_channel_pvalue_scalar(const struct routed_combiner *rc, size_t ch,
                                    double z_score, double cusum_score)
{
    if (!rc || ch >= rc->n_channels) return 1.0;
    double p_z = routed_conformal_p(&rc->channels[ch].a, z_score);
    double p_c = routed_conformal_p(&rc->channels[ch].b, cusum_score);
    return routed_acat_pair(p_z, p_c);
}

double routed_channel_pvalue_jsd(const struct routed_combiner *rc, size_t ch,
                                 double jsd_score)
{
    if (!rc || ch >= rc->n_channels) return 1.0;
    return routed_conformal_p(&rc->channels[ch].a, jsd_score);
}
