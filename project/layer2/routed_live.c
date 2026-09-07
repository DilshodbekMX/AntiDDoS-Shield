#include "routed_live.h"
#include <math.h>

void l2_routed_live_init(struct routed_live *rl, double alpha,
                         size_t n_features, size_t capacity)
{
    if (!rl) return;
    if (!(alpha > 0.0 && alpha < 1.0)) alpha = 0.001;
    /* Under BH-FDR over m channels the rank-1 threshold is alpha/m, so the p-value floor
     * 1/(n+1) must reach alpha/m, i.e. n >= m/alpha (m = #features + 1 JSD channel). */
    size_t m = n_features + 1;
    size_t need = (size_t)ceil((double)m / alpha);
    if (capacity < need) capacity = need;

    routed_combiner_init(&rl->rc, alpha);
    rl->n_scalar = 0;
    /* One scalar channel per feature, leaving room for the JSD channel. */
    for (size_t i = 0; i < n_features && rl->n_scalar + 1 < ROUTED_FDR_MAX_CHANNELS; i++) {
        if (routed_combiner_add_scalar(&rl->rc, capacity) == (size_t)-1) break;
        rl->n_scalar++;
    }
    rl->jsd_ch = routed_combiner_add_jsd(&rl->rc, capacity);
    rl->observed = 0;
    rl->warmup_min = need;
    rl->alpha = alpha;
    rl->initialized = true;
}

int l2_routed_live_decide(struct routed_live *rl,
                          const double *z, const double *cusum, size_t n_features,
                          double jsd, bool calibrate, size_t *attr_index)
{
    if (!rl || !rl->initialized || !z || !cusum) return -1;
    size_t n = (n_features < rl->n_scalar) ? n_features : rl->n_scalar;

    if (calibrate) {
        for (size_t i = 0; i < n; i++)
            routed_channel_observe_scalar(&rl->rc, i, fabs(z[i]), cusum[i]);
        if (rl->jsd_ch != (size_t)-1)
            routed_channel_observe_jsd(&rl->rc, rl->jsd_ch, jsd);
        rl->observed++;
    }
    if (rl->observed < rl->warmup_min) return -1;

    double pvals[ROUTED_FDR_MAX_CHANNELS];
    size_t m = 0;
    for (size_t i = 0; i < n; i++)
        pvals[m++] = routed_channel_pvalue_scalar(&rl->rc, i, fabs(z[i]), cusum[i]);
    if (rl->jsd_ch != (size_t)-1)
        pvals[m++] = routed_channel_pvalue_jsd(&rl->rc, rl->jsd_ch, jsd);

    size_t attr = (size_t)-1;
    bool hit = routed_bh_reject(pvals, m, rl->alpha, &attr);
    if (attr_index) *attr_index = attr;
    return hit ? 1 : 0;
}
