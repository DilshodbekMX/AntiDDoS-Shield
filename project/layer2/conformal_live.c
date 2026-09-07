#include "conformal_live.h"
#include <math.h>
#include <stdio.h>

bool l2_conformal_live_init_k(struct conformal_live *cl, double alpha,
                              size_t capacity, int rule, size_t n_paths)
{
    if (!cl) return false;
    cl->initialized = false;
    cl->observed = 0;
    cl->warmup_min = (size_t)-1;

    if (n_paths < 1 || n_paths > CONFORMAL_MAX_PATHS) {
        fprintf(stderr, "[ConformalLive] ERROR: Invalid n_paths=%zu (must be in [1, %d])\n",
                n_paths, CONFORMAL_MAX_PATHS);
        return false;
    }
    if (!(alpha > 0.0 && alpha < 1.0)) alpha = 0.001;   /* default alpha = 0.1% */

    /* The Bonferroni p-value floor is 1/(n+1); to ever reach alpha/K the buffer must hold
     * n >= K/alpha samples (the calibration floor alpha ~= K/(n+1)).
     * If ceil(n_paths / alpha) > CONFORMAL_MAX_BUFFER, reject init so rule cannot silently go dead. */
    size_t need = (size_t)ceil((double)n_paths / alpha);
    if (need > CONFORMAL_MAX_BUFFER || (alpha / (double)n_paths) <= (1.0 / ((double)CONFORMAL_MAX_BUFFER + 1.0))) {
        fprintf(stderr, "[ConformalLive] ERROR: Buffer floor violation for K=%zu, alpha=%f (need=%zu > %d). Refusing to arm.\n",
                n_paths, alpha, need, CONFORMAL_MAX_BUFFER);
        return false;
    }

    if (capacity < need) capacity = need;
    if (capacity > CONFORMAL_MAX_BUFFER) capacity = CONFORMAL_MAX_BUFFER;

    if (!conformal_combiner_init_k(&cl->cc, capacity, alpha, n_paths)) {
        return false;
    }

    cl->observed = 0;
    cl->warmup_min = need;
    cl->rule = (rule == 2) ? 2 : 1;
    cl->initialized = true;
    return true;
}

void l2_conformal_live_init(struct conformal_live *cl, double alpha,
                            size_t capacity, int rule)
{
    l2_conformal_live_init_k(cl, alpha, capacity, rule, CONFORMAL_DEFAULT_PATHS);
}

int l2_conformal_live_decide_k(struct conformal_live *cl,
                               const double *scores, size_t count,
                               bool calibrate)
{
    if (!cl || !cl->initialized || !scores || count == 0) return -1;

    if (calibrate) {
        conformal_combiner_observe_k(&cl->cc, scores, count);
        cl->observed++;
    }
    if (cl->observed < cl->warmup_min) return -1;   /* not warmed -> OR rule */

    bool hit = (cl->rule == 2)
        ? conformal_decide_evalue_k(&cl->cc, scores, count)
        : conformal_decide_bonferroni_k(&cl->cc, scores, count);
    return hit ? 1 : 0;
}

int l2_conformal_live_decide(struct conformal_live *cl,
                             double z, double cusum_norm, double jsd,
                             bool calibrate)
{
    double scores[3] = { z, cusum_norm, jsd };
    return l2_conformal_live_decide_k(cl, scores, 3, calibrate);
}
