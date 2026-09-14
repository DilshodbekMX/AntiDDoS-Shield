/* l2driver.c -- thin flat-API shim over the SHIPPED Layer 2 detection path.
 *
 * No logic of its own: it allocates the engine's own structs, calls the engine's
 * own three_tier_baseline_init/update and l2_detect_anomaly, and hands back the
 * fields of the engine's own struct detection_result. Every decision is the C
 * engine's; this file only marshals.
 */
#include "baselines.h"
#include "detection.h"
#include "advanced_detection.h"
#include "config/layer2_config.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct l2drv {
    struct three_tier_baseline base;
    struct cusum_detector      cusum;
    struct jsd_baseline        jsd;
    struct l2_feature_weights  weights;
    struct l2_anomaly_state    st;
};

struct l2drv *l2drv_new(double a1, double a2, double a3,
                        unsigned m1, unsigned m2, unsigned m3) {
    struct l2drv *h = calloc(1, sizeof *h);
    if (!h) return NULL;
    three_tier_baseline_init(&h->base, a1, a2, a3, m1, m2, m3);
    cusum_detector_init(&h->cusum, 0.25, 5.0);      /* shipped k=0.25s, h=5.0s */
    /* layer2.c:940 applies the configured decay right after init; mirror that so the
     * replayed engine matches the shipped configuration rather than the module default. */
    cusum_detector_set_decay(&h->cusum, L2_DEFAULT_CUSUM_DECAY);
    jsd_baseline_init(&h->jsd, 0.1, 30);            /* shipped alpha=0.1, min=30 */
    l2_feature_weights_init(&h->weights);
    l2_anomaly_state_init(&h->st);
    return h;
}
void l2drv_free(struct l2drv *h) { free(h); }

int         l2drv_n_features(void)      { return L2_MAX_FEATURES; }
const char *l2drv_feature_name(int i)   { return (i >= 0 && i < L2_MAX_FEATURES) ? l2_feature_names[i] : 0; }

static void fill(struct l2_feature_snapshot *s, const double *v, unsigned long long ts) {
    memset(s, 0, sizeof *s);
    memcpy(s->values, v, sizeof(double) * L2_MAX_FEATURES);
    s->timestamp_ns = ts;
}



static void set_slot(unsigned long long ts) {
    if (!ts) { l2_clear_replay_slot(); return; }
    time_t sec = (time_t)(ts / 1000000000ULL);
    struct tm t; gmtime_r(&sec, &t);
    int wd = (t.tm_wday + 6) % 7;           /* Python weekday(): Monday = 0 */
    l2_set_replay_slot(t.tm_hour, wd * 24 + t.tm_hour);
}

void l2drv_update(struct l2drv *h, const double *v, unsigned long long ts) {
    set_slot(ts);
    struct l2_feature_snapshot s; fill(&s, v, ts);
    three_tier_baseline_update(&h->base, &s);
}

void l2drv_detect(struct l2drv *h, const double *v, unsigned long long ts,
                  double threshold, int min_agree,
                  double *out_maxz, int *out_detected, int *out_agree, double *out_conf) {
    set_slot(ts);
    struct l2_feature_snapshot s; fill(&s, v, ts);
    struct detection_result r; memset(&r, 0, sizeof r);
    l2_detect_anomaly(&h->base, &s, threshold, min_agree, &r);
    *out_maxz     = r.max_z_score;
    *out_detected = r.detected ? 1 : 0;
    *out_agree    = r.tier_agreement;
    *out_conf     = r.confidence;
}


/* ---- full five-term OR: z-path (l2_detect_anomaly) OR CUSUM OR JSD ---- */
static void protodist(const double *v, struct protocol_distribution *d) {
    /* The engine's native ratio scale is percent (shared_memory.h:245 uint8_t,
     * attack_classification.c:148 compares > 80.0). The replay corpus stores
     * 0..1 fractions, so scale before the uint8_t cast the engine performs. */
    protocol_dist_from_ratios(d,
        (unsigned char)(v[L2_FEAT_TCP_RATIO]   * 100.0 + 0.5),
        (unsigned char)(v[L2_FEAT_UDP_RATIO]   * 100.0 + 0.5),
        (unsigned char)(v[L2_FEAT_ICMP_RATIO]  * 100.0 + 0.5),
        (unsigned char)(v[L2_FEAT_OTHER_RATIO] * 100.0 + 0.5));
}

/* Drive the engine's own decay API (advanced_detection.h). */
void l2drv_set_decay(struct l2drv *h, double lambda) {
    if (h) cusum_detector_set_decay(&h->cusum, lambda);
}

void l2drv_set_reset(struct l2drv *h, int on) {
    if (h) cusum_detector_set_reset_on_alarm(&h->cusum, on);
}

void l2drv_update_adv(struct l2drv *h, const double *v, unsigned long long ts) {
    struct protocol_distribution pd; protodist(v, &pd);
    jsd_baseline_update_timed(&h->jsd, &pd, ts);
}

void l2drv_detect_full(struct l2drv *h, const double *v, unsigned long long ts,
                       double threshold, int min_agree, double jsd_threshold,
                       double *out_maxz, int *out_z_alarm,
                       int *out_cusum_alarm, int *out_jsd_alarm,
                       double *out_cusum_norm, double *out_jsd) {
    set_slot(ts);
    struct l2_feature_snapshot s; fill(&s, v, ts);
    struct detection_result r; memset(&r, 0, sizeof r);
    l2_detect_anomaly(&h->base, &s, threshold, min_agree, &r);
    struct advanced_detection_result a; memset(&a, 0, sizeof a);
    l2_advanced_detect(&h->base.immediate, &s, &h->cusum, &h->jsd, &h->weights,
                       threshold, jsd_threshold, &a);
    /* layer2.c:571 -- baseline updated every cycle, and frozen while an anomaly is active */
    if (!h->st.active) {
        struct protocol_distribution pd; protodist(v, &pd);
        jsd_baseline_update_timed(&h->jsd, &pd, ts);
    }
    *out_maxz = r.max_z_score;
    *out_z_alarm = r.detected ? 1 : 0;
    *out_cusum_alarm = a.cusum_triggered_count > 0 ? 1 : 0;
    *out_jsd_alarm = a.jsd_triggered ? 1 : 0;
    *out_cusum_norm = a.cusum_max_norm;
    *out_jsd = a.jsd_score;
}


/* Operator-visible path: the same OR decision, then the shipped anomaly state
 * machine with its cool-down and K-consecutive persistence gate. Returns the
 * state machine's ACTIVE flag -- what a console would show. */
void l2drv_set_persistence(struct l2drv *h, unsigned k) { h->st.persistence_windows = k; }

void l2drv_detect_state(struct l2drv *h, const double *v, unsigned long long ts,
                        double threshold, int min_agree, double jsd_threshold,
                        double cool_down_s,
                        int *out_raw_or, int *out_active, int *out_level) {
    set_slot(ts);
    struct l2_feature_snapshot s; fill(&s, v, ts);
    struct detection_result r; memset(&r, 0, sizeof r);
    l2_detect_anomaly(&h->base, &s, threshold, min_agree, &r);
    struct advanced_detection_result a; memset(&a, 0, sizeof a);
    l2_advanced_detect(&h->base.immediate, &s, &h->cusum, &h->jsd, &h->weights,
                       threshold, jsd_threshold, &a);
    /* layer2.c:650 -- OR override when the z-path did not fire */
    if (!r.detected && (a.cusum_triggered_count > 0 || a.jsd_triggered)) {
        r.detected = true;
        if (r.tier_agreement == 0) r.tier_agreement = 1;
    }
    *out_raw_or = r.detected ? 1 : 0;
    l2_update_anomaly_state(&h->st, &r, &s, cool_down_s);
    *out_active = h->st.active ? 1 : 0;
    *out_level  = (int)h->st.level;
}


/* Expose one feature's CUSUM internals so the trajectory can be inspected directly. */
void l2drv_probe_cusum(struct l2drv *h, int feat_idx,
                       double *S_high, double *S_low, double *k, double *hh,
                       double *mean, double *sd) {
    struct cusum_state *st = &h->cusum.states[feat_idx];
    const struct feature_baseline *fb = &h->base.immediate.features[feat_idx];
    *S_high = st->S_high; *S_low = st->S_low; *k = st->k; *hh = st->h;
    *mean = fb->mean; *sd = feature_baseline_stddev(fb);
}


/* Production-faithful cycle: detect, run the anomaly state machine, then update the
 * baseline ONLY while no anomaly is active -- mirroring layer2.c, which freezes the
 * baselines for the duration of an attack so the attack cannot poison the reference. */
void l2drv_cycle(struct l2drv *h, const double *v, unsigned long long ts,
                 double threshold, int min_agree, double jsd_threshold, double cool_down_s,
                 int *out_or, int *out_active, double *out_cusum_norm) {
    set_slot(ts);
    struct l2_feature_snapshot s; fill(&s, v, ts);
    struct detection_result r; memset(&r, 0, sizeof r);
    l2_detect_anomaly(&h->base, &s, threshold, min_agree, &r);
    struct advanced_detection_result a; memset(&a, 0, sizeof a);
    l2_advanced_detect(&h->base.immediate, &s, &h->cusum, &h->jsd, &h->weights,
                       threshold, jsd_threshold, &a);
    if (!r.detected && (a.cusum_triggered_count > 0 || a.jsd_triggered)) {
        r.detected = true;
        if (r.tier_agreement == 0) r.tier_agreement = 1;
    }
    *out_or = r.detected ? 1 : 0;
    *out_cusum_norm = a.cusum_max_norm;
    l2_update_anomaly_state(&h->st, &r, &s, cool_down_s);
    *out_active = h->st.active ? 1 : 0;
    if (!h->st.active) {                       /* layer2.c: baselines frozen while attacking */
        three_tier_baseline_update(&h->base, &s);
        struct protocol_distribution pd; protodist(v, &pd);
        jsd_baseline_update_timed(&h->jsd, &pd, ts);
    }
}


/* Same production-faithful cycle, but returns each OR term separately so alternative
 * fusion rules can be scored without changing the engine. */
void l2drv_cycle_terms(struct l2drv *h, const double *v, unsigned long long ts,
                       double threshold, int min_agree, double jsd_threshold, double cool_down_s,
                       int fuse,   /* 0 = shipped OR, 1 = z||jsd, 2 = 2-of-3, 3 = z only */
                       int *out_z, int *out_c, int *out_j, int *out_dec, int *out_active) {
    set_slot(ts);
    struct l2_feature_snapshot s; fill(&s, v, ts);
    struct detection_result r; memset(&r, 0, sizeof r);
    l2_detect_anomaly(&h->base, &s, threshold, min_agree, &r);
    struct advanced_detection_result a; memset(&a, 0, sizeof a);
    l2_advanced_detect(&h->base.immediate, &s, &h->cusum, &h->jsd, &h->weights,
                       threshold, jsd_threshold, &a);
    int zt = r.detected ? 1 : 0;
    int ct = a.cusum_triggered_count > 0 ? 1 : 0;
    int jt = a.jsd_triggered ? 1 : 0;
    int dec;
    switch (fuse) {
        case 1:  dec = zt || jt; break;
        case 2:  dec = (zt + ct + jt) >= 2; break;
        case 3:  dec = zt; break;
        default: dec = zt || ct || jt; break;
    }
    *out_z = zt; *out_c = ct; *out_j = jt; *out_dec = dec;
    r.detected = dec ? true : false;
    if (dec && r.tier_agreement == 0) r.tier_agreement = 1;
    l2_update_anomaly_state(&h->st, &r, &s, cool_down_s);
    *out_active = h->st.active ? 1 : 0;
    if (!h->st.active) {
        three_tier_baseline_update(&h->base, &s);
        struct protocol_distribution pd; protodist(v, &pd);
        jsd_baseline_update_timed(&h->jsd, &pd, ts);
    }
}
