#include "advanced_detection.h"
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>

// ==================== Default Feature Configurations ====================

/**
 * Default configuration for each feature:
 * - VOLUME (0-2): CUSUM for slow-ramp detection
 * - TCP FLAGS (3-7): EWMA+Z-score, with lower weights for ack/fin
 * - PROTOCOL MIX (8-11): JSD (computed as group)
 * - RATIOS (12-14): EWMA+Z-score
 * - CARDINALITY (15-17): Log-transform + bidirectional
 * - CHURN (18): CUSUM
 * - CONCENTRATION (19-21): Threshold
 * - FLOW BEHAVIOR (22-23): EWMA+Z-score
 */
// Make concentration thresholds modifiable at runtime
// These are initialized to defaults but can be updated via l2_set_concentration_thresholds()
static struct l2_feature_config l2_feature_configs[L2_MAX_FEATURES];
static bool l2_feature_configs_initialized = false;

// Forward declaration of defaults array (defined below)
static const struct l2_feature_config l2_default_feature_configs_const[L2_MAX_FEATURES];

// Initialize from const defaults
static void ensure_feature_configs_initialized(void) {
    if (l2_feature_configs_initialized) return;
    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        l2_feature_configs[i] = l2_default_feature_configs_const[i];
    }
    l2_feature_configs_initialized = true;
}

// Public function to update concentration thresholds from config
void l2_set_concentration_thresholds(double max_flow_fraction, double topk_flow_share) {
    ensure_feature_configs_initialized();
    l2_feature_configs[L2_FEAT_MAX_FLOW_FRACTION].threshold = max_flow_fraction;
    l2_feature_configs[L2_FEAT_TOPK_FLOW_SHARE].threshold = topk_flow_share;
}

// Get the current (possibly modified) feature configs
const struct l2_feature_config *l2_get_feature_configs(void) {
    ensure_feature_configs_initialized();
    return l2_feature_configs;
}

// Const defaults for initialization (internal use only)
static const struct l2_feature_config l2_default_feature_configs_const[L2_MAX_FEATURES] = {
    // ===== VOLUME FEATURES (3) - Use CUSUM =====
    [L2_FEAT_PACKETS_PER_SEC]  = { L2_METHOD_EWMA_CUSUM, 1.0, 0.0, false },
    [L2_FEAT_BYTES_PER_SEC]    = { L2_METHOD_EWMA_CUSUM, 1.0, 0.0, false },
    [L2_FEAT_FLOWS_PER_SEC]    = { L2_METHOD_EWMA_CUSUM, 1.0, 0.0, false },

    // ===== TCP FLAG FEATURES (5) - EWMA+Z-score, downweight ack/fin =====
    [L2_FEAT_SYN_PER_SEC]      = { L2_METHOD_EWMA_ZSCORE, 1.0, 0.0, false },
    [L2_FEAT_SYN_ACK_PER_SEC]  = { L2_METHOD_EWMA_ZSCORE, 0.8, 0.0, false },
    [L2_FEAT_ACK_PER_SEC]      = { L2_METHOD_EWMA_ZSCORE, 0.3, 0.0, false },  // Downweighted
    [L2_FEAT_RST_PER_SEC]      = { L2_METHOD_EWMA_ZSCORE, 0.7, 0.0, false },
    [L2_FEAT_FIN_PER_SEC]      = { L2_METHOD_EWMA_ZSCORE, 0.3, 0.0, false },  // Downweighted

    // ===== PROTOCOL MIX (4) - JSD (computed as group, weight only for individual Z) =====
    [L2_FEAT_TCP_RATIO]        = { L2_METHOD_JSD, 0.5, 0.0, false },
    [L2_FEAT_UDP_RATIO]        = { L2_METHOD_JSD, 0.5, 0.0, false },
    [L2_FEAT_ICMP_RATIO]       = { L2_METHOD_JSD, 0.5, 0.0, false },
    [L2_FEAT_OTHER_RATIO]      = { L2_METHOD_JSD, 0.5, 0.0, false },

    // ===== RATIO FEATURES (3) - EWMA+Z-score =====
    [L2_FEAT_SYN_ACK_RATIO]    = { L2_METHOD_EWMA_ZSCORE, 1.0, 0.0, false },
    [L2_FEAT_RST_SYN_RATIO]    = { L2_METHOD_EWMA_ZSCORE, 1.0, 0.0, false },
    [L2_FEAT_BYTES_PER_PACKET] = { L2_METHOD_EWMA_ZSCORE, 0.8, 0.0, true },   // Bidirectional

    // ===== CARDINALITY FEATURES (3) - Log-transform + bidirectional =====
    [L2_FEAT_UNIQUE_SRC_IPS]   = { L2_METHOD_LOG_ZSCORE, 1.0, 0.0, true },
    [L2_FEAT_UNIQUE_DST_PORTS] = { L2_METHOD_LOG_ZSCORE, 0.8, 0.0, true },
    [L2_FEAT_UNIQUE_FLOWS]     = { L2_METHOD_LOG_ZSCORE, 1.0, 0.0, true },

    // ===== CHURN FEATURES (1) - CUSUM =====
    [L2_FEAT_NEW_SRCIP_RATE]   = { L2_METHOD_EWMA_CUSUM, 1.0, 0.0, false },

    // ===== CONCENTRATION FEATURES (3) - Threshold =====
    // E7 FIX: Lower thresholds to catch single-source floods
    // Old: 30% / 50% - too high, allowed large single-flow attacks
    // New: 15% / 30% - catches concentration attacks earlier
    [L2_FEAT_MAX_FLOW_FRACTION]  = { L2_METHOD_THRESHOLD, 0.8, 15.0, false },  // >15% = anomaly (was 30%)
    [L2_FEAT_TOPK_FLOW_SHARE]    = { L2_METHOD_THRESHOLD, 0.6, 30.0, false },  // >30% = anomaly (was 50%)
    [L2_FEAT_HEAVY_HITTER_COUNT] = { L2_METHOD_EWMA_ZSCORE, 0.7, 0.0, false },

    // ===== FLOW BEHAVIOR FEATURES (2) - EWMA+Z-score =====
    [L2_FEAT_AVG_PACKETS_PER_FLOW] = { L2_METHOD_EWMA_ZSCORE, 0.8, 0.0, true },
    [L2_FEAT_FLOW_DURATION_AVG]    = { L2_METHOD_EWMA_ZSCORE, 0.8, 0.0, true },

    // ===== TCP FLAG RATIO FEATURES (5) - EWMA+Z-score =====
    // These ratios reveal attack type composition within TCP traffic
    [L2_FEAT_SYN_TCP_RATIO]        = { L2_METHOD_EWMA_ZSCORE, 1.0, 0.0, false },
    [L2_FEAT_SYNACK_TCP_RATIO]     = { L2_METHOD_EWMA_ZSCORE, 0.8, 0.0, true },  // Bidirectional (drop = attack signal)
    [L2_FEAT_ACK_TCP_RATIO]        = { L2_METHOD_EWMA_ZSCORE, 0.4, 0.0, true },  // Downweighted + bidirectional
    [L2_FEAT_RST_TCP_RATIO]        = { L2_METHOD_EWMA_ZSCORE, 0.7, 0.0, false },
    [L2_FEAT_FIN_TCP_RATIO]        = { L2_METHOD_EWMA_ZSCORE, 0.4, 0.0, false },  // Downweighted

    // ===== VOLUME EXTENDED (1) - CUSUM for burst detection =====
    [L2_FEAT_BURST_FACTOR]         = { L2_METHOD_EWMA_CUSUM, 1.0, 0.0, false },

    // ===== FLOW BEHAVIOR EXTENDED (1) - EWMA+Z-score =====
    [L2_FEAT_UDP_FLOW_RATIO]       = { L2_METHOD_EWMA_ZSCORE, 0.7, 0.0, true },

    // ===== PROTOCOL MIX EXTENDED (1) - EWMA+Z-score (unidirectional high) =====
    // Was L2_METHOD_JSD but JSD path zeroes all JSD-tagged features and
    // protocol_dist_from_ratios does not include icmp_echo_ratio -- so it
    // produced no score. Moved to Z-score: elevated echo ratio = ping flood.
    [L2_FEAT_ICMP_ECHO_RATIO]      = { L2_METHOD_EWMA_ZSCORE, 0.5, 0.0, false },

    // ===== CARDINALITY EXTENDED (1) - EWMA+Z-score, bidirectional =====
    // dst_port_density is NOT in feature_uses_log_transform() (baselines.c:260-263), so its
    // tier baseline is trained on LINEAR values. Routing it to LOG_ZSCORE here computed
    // log(x+1) against that linear baseline -- a latent inconsistency. The resulting z never
    // gates detection (only adv_result's cusum/jsd flags feed the ensemble OR; layer2.c:553-560),
    // so this changes no detection decision or evaluated FPR/DR; it only removes a garbage z that
    // could perturb adv_result.combined_score severity metadata. Scored linearly to match baseline.
    [L2_FEAT_DST_PORT_DENSITY]     = { L2_METHOD_EWMA_ZSCORE, 0.8, 0.0, true },

    // ===== ENTROPY FEATURES (2) - EWMA+Z-score, bidirectional =====
    // Both abnormally low entropy (single-source flood) and high entropy (spoofed flood) are anomalous
    [L2_FEAT_SRC_IP_ENTROPY]       = { L2_METHOD_EWMA_ZSCORE, 1.0, 0.0, true },
    [L2_FEAT_SRC_PORT_ENTROPY]     = { L2_METHOD_EWMA_ZSCORE, 0.8, 0.0, true },

    // ===== PACKET CHARACTERISTICS (3) - EWMA+Z-score =====
    [L2_FEAT_SMALL_PKT_RATIO]      = { L2_METHOD_EWMA_ZSCORE, 0.9, 0.0, false },  // High = fragmentation/flood
    [L2_FEAT_FRAGMENT_RATIO]       = { L2_METHOD_EWMA_ZSCORE, 1.0, 0.0, false },  // High = frag attack
    [L2_FEAT_TTL_MEAN]             = { L2_METHOD_EWMA_ZSCORE, 0.6, 0.0, true },   // Bidirectional (TTL anomaly)

    // ===== RATIO EXTENDED (1) - EWMA+Z-score, bidirectional =====
    // Low = incomplete handshakes (SYN flood); high = amplification
    [L2_FEAT_TCP_COMPLETION_RATE]  = { L2_METHOD_EWMA_ZSCORE, 1.0, 0.0, true },
};

// ==================== CUSUM Implementation ====================

void cusum_detector_init(struct cusum_detector *det, double k_factor, double h_factor) {
    if (!det) return;

    memset(det, 0, sizeof(*det));
    // E2 FIX: Lower k-factor from 0.5 to 0.25 to catch slow-ramp attacks
    // Lower k = less slack = more sensitive to sustained mean shifts
    det->k_factor = (k_factor > 0) ? k_factor : 0.25;
    det->h_factor = (h_factor > 0) ? h_factor : 5.0;
    det->min_samples = 30;  // Need 30 samples before CUSUM triggers

    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        cusum_reset(&det->states[i]);
    }
}

void cusum_reset(struct cusum_state *state) {
    if (!state) return;

    state->S_high = 0.0;
    state->S_low = 0.0;
    state->alarm_high = false;
    state->alarm_low = false;
    state->samples_since_reset = 0;
}

bool cusum_update(struct cusum_state *state, double value, double mean, double stddev,
                  double k_factor, double h_factor) {
    if (!state) return false;

    state->mean = mean;
    state->stddev = stddev;
    state->samples_since_reset++;

    // Calculate parameters
    double k = k_factor * stddev;  // Slack parameter
    double h = h_factor * stddev;  // Decision threshold

    if (stddev < 1e-10 || h < 1e-10) {
        // No variance yet, can't compute CUSUM
        return false;
    }

    state->k = k;
    state->h = h;

    // Compute deviation from mean
    double deviation = value - mean;

    // Update high-side CUSUM (detecting increases)
    state->S_high = fmax(0.0, state->S_high + deviation - k);

    // Update low-side CUSUM (detecting decreases)
    state->S_low = fmax(0.0, state->S_low - deviation - k);

    // Check for alarms
    state->alarm_high = (state->S_high > h);
    state->alarm_low = (state->S_low > h);

    return state->alarm_high || state->alarm_low;
}

int cusum_detect(struct cusum_detector *det,
                 const struct l2_feature_snapshot *snapshot,
                 const struct tier_baseline *baseline,
                 uint64_t *triggered_features) {
    if (!det || !snapshot || !baseline || !triggered_features) return 0;

    *triggered_features = 0;
    int count = 0;
    double max_norm = 0.0;   // max over features of max(S_high,S_low)/h (continuous score)
    for (int i = 0; i < L2_MAX_FEATURES; i++) det->last_norms[i] = 0.0;

    // Only check features that use CUSUM
    static const int cusum_features[] = {
        L2_FEAT_PACKETS_PER_SEC,
        L2_FEAT_BYTES_PER_SEC,
        L2_FEAT_FLOWS_PER_SEC,
        L2_FEAT_NEW_SRCIP_RATE,
        L2_FEAT_BURST_FACTOR,
        -1  // Sentinel
    };

    for (int i = 0; cusum_features[i] >= 0; i++) {
        int feat_idx = cusum_features[i];
        const struct feature_baseline *fb = &baseline->features[feat_idx];

        if (fb->sample_count < det->min_samples) {
            continue;  // Not enough samples yet
        }

        double value = snapshot->values[feat_idx];
        double mean = fb->mean;
        double stddev = feature_baseline_stddev(fb);

        bool triggered = cusum_update(&det->states[feat_idx], value, mean, stddev,
                                      det->k_factor, det->h_factor);

        // Continuous normalized statistic: S/h, where h = h_factor * stddev (alarm at >1).
        double h = det->h_factor * stddev;
        if (h > 1e-9) {
            double s = fmax(det->states[feat_idx].S_high, det->states[feat_idx].S_low);
            double norm = s / h;
            det->last_norms[feat_idx] = norm;
            if (norm > max_norm) max_norm = norm;
        }

        if (triggered) {
            *triggered_features |= (1ULL << feat_idx);
            count++;
        }
    }

    det->last_max_norm = max_norm;
    return count;
}

// ==================== Jensen-Shannon Divergence Implementation ====================

void jsd_baseline_init(struct jsd_baseline *jsd, double alpha, uint32_t min_samples) {
    if (!jsd) return;

    memset(jsd, 0, sizeof(*jsd));
    jsd->ewma_alpha = (alpha > 0 && alpha <= 1.0) ? alpha : 0.1;
    jsd->min_samples = (min_samples > 0) ? min_samples : 30;
    jsd->ready = false;
    jsd->sample_count = 0;

    // Initialize with uniform distribution
    jsd->baseline_dist.tcp = 0.25;
    jsd->baseline_dist.udp = 0.25;
    jsd->baseline_dist.icmp = 0.25;
    jsd->baseline_dist.other = 0.25;

    // E4 FIX: Initialize rate limiting (5 second minimum between updates)
    jsd->last_update_ns = 0;
    jsd->update_interval_ms = 5000;  // 5 seconds
    jsd->updates_this_minute = 0;
    jsd->minute_start_ns = 0;
}

void protocol_dist_from_ratios(struct protocol_distribution *dist,
                               uint8_t tcp_pct, uint8_t udp_pct,
                               uint8_t icmp_pct, uint8_t other_pct) {
    if (!dist) return;

    // Convert percentages to probabilities
    double total = tcp_pct + udp_pct + icmp_pct + other_pct;
    if (total < 1.0) total = 100.0;  // Assume 100% if sum is 0

    dist->tcp = tcp_pct / total;
    dist->udp = udp_pct / total;
    dist->icmp = icmp_pct / total;
    dist->other = other_pct / total;

    // Ensure valid probabilities (avoid 0 for KL divergence)
    const double epsilon = 1e-10;
    if (dist->tcp < epsilon) dist->tcp = epsilon;
    if (dist->udp < epsilon) dist->udp = epsilon;
    if (dist->icmp < epsilon) dist->icmp = epsilon;
    if (dist->other < epsilon) dist->other = epsilon;

    // Renormalize
    total = dist->tcp + dist->udp + dist->icmp + dist->other;
    dist->tcp /= total;
    dist->udp /= total;
    dist->icmp /= total;
    dist->other /= total;
}

// E4 FIX: Maximum updates per minute to prevent oscillation abuse
#define JSD_MAX_UPDATES_PER_MINUTE 12

void jsd_baseline_update(struct jsd_baseline *jsd, const struct protocol_distribution *current) {
    jsd_baseline_update_timed(jsd, current, 0);  // Use current time
}

void jsd_baseline_update_timed(struct jsd_baseline *jsd, const struct protocol_distribution *current,
                                uint64_t now_ns) {
    if (!jsd || !current) return;

    // Get current time if not provided
    if (now_ns == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    }

    // E4 FIX: Rate limit baseline updates to prevent protocol oscillation evasion
    if (jsd->ready && jsd->update_interval_ms > 0) {
        uint64_t interval_ns = (uint64_t)jsd->update_interval_ms * 1000000ULL;
        if (now_ns - jsd->last_update_ns < interval_ns) {
            return;  // Too soon since last update, skip
        }

        // Track updates per minute for abuse detection
        uint64_t one_minute_ns = 60ULL * 1000000000ULL;
        if (now_ns - jsd->minute_start_ns >= one_minute_ns) {
            // New minute, reset counter
            jsd->minute_start_ns = now_ns;
            jsd->updates_this_minute = 0;
        }

        if (jsd->updates_this_minute >= JSD_MAX_UPDATES_PER_MINUTE) {
            return;  // Too many updates this minute
        }

        jsd->updates_this_minute++;
    }

    jsd->last_update_ns = now_ns;

    double alpha = jsd->ewma_alpha;

    if (jsd->sample_count == 0) {
        // First sample - initialize directly
        jsd->baseline_dist = *current;
    } else {
        // EWMA update for each probability
        jsd->baseline_dist.tcp += alpha * (current->tcp - jsd->baseline_dist.tcp);
        jsd->baseline_dist.udp += alpha * (current->udp - jsd->baseline_dist.udp);
        jsd->baseline_dist.icmp += alpha * (current->icmp - jsd->baseline_dist.icmp);
        jsd->baseline_dist.other += alpha * (current->other - jsd->baseline_dist.other);

        // Renormalize to ensure sum = 1.0
        double total = jsd->baseline_dist.tcp + jsd->baseline_dist.udp +
                       jsd->baseline_dist.icmp + jsd->baseline_dist.other;
        if (total > 0) {
            jsd->baseline_dist.tcp /= total;
            jsd->baseline_dist.udp /= total;
            jsd->baseline_dist.icmp /= total;
            jsd->baseline_dist.other /= total;
        }
    }

    jsd->sample_count++;
    if (jsd->sample_count >= jsd->min_samples) {
        jsd->ready = true;
    }
}

double kl_divergence(const struct protocol_distribution *p,
                     const struct protocol_distribution *q) {
    if (!p || !q) return 0.0;

    // KL(P||Q) = sum(P[i] * log(P[i] / Q[i]))
    double kl = 0.0;

    // Only compute for non-zero probabilities
    if (p->tcp > 1e-10 && q->tcp > 1e-10) {
        kl += p->tcp * log(p->tcp / q->tcp);
    }
    if (p->udp > 1e-10 && q->udp > 1e-10) {
        kl += p->udp * log(p->udp / q->udp);
    }
    if (p->icmp > 1e-10 && q->icmp > 1e-10) {
        kl += p->icmp * log(p->icmp / q->icmp);
    }
    if (p->other > 1e-10 && q->other > 1e-10) {
        kl += p->other * log(p->other / q->other);
    }

    return kl;
}

double jsd_compute(const struct protocol_distribution *baseline,
                   const struct protocol_distribution *current) {
    if (!baseline || !current) return 0.0;

    // Compute midpoint distribution M = 0.5 * (P + Q)
    struct protocol_distribution m;
    m.tcp = 0.5 * (baseline->tcp + current->tcp);
    m.udp = 0.5 * (baseline->udp + current->udp);
    m.icmp = 0.5 * (baseline->icmp + current->icmp);
    m.other = 0.5 * (baseline->other + current->other);

    // JSD = 0.5 * KL(P||M) + 0.5 * KL(Q||M)
    double jsd = 0.5 * kl_divergence(baseline, &m) +
                 0.5 * kl_divergence(current, &m);

    // JSD is bounded [0, log(2)] for base-e logarithm
    // Normalize to [0, 1] by dividing by log(2)
    jsd /= log(2.0);

    // Clamp to [0, 1] in case of numerical errors
    if (jsd < 0.0) jsd = 0.0;
    if (jsd > 1.0) jsd = 1.0;

    return jsd;
}

bool jsd_is_anomalous(const struct jsd_baseline *baseline,
                      const struct protocol_distribution *current,
                      double threshold) {
    if (!baseline || !current || !baseline->ready) return false;

    double jsd = jsd_compute(&baseline->baseline_dist, current);
    return jsd >= threshold;
}

// ==================== Log-Transform Detection ====================

double log_transform_z_score(const struct feature_baseline *baseline,
                             double value, bool bidirectional) {
    if (!baseline) return 0.0;

    // Not ready if insufficient samples
    if (baseline->sample_count < 10) {
        return 0.0;
    }

    // Transform value: log(value + 1)
    double log_value = safe_log(value);

    // Baseline stores log-transformed mean and variance
    double stddev = feature_baseline_stddev(baseline);

    if (stddev < 1e-10) {
        return 0.0;
    }

    double z = (log_value - baseline->mean) / stddev;

    if (bidirectional) {
        return fabs(z);  // Detect both increases and decreases
    } else {
        return z;  // Only detect increases (positive Z)
    }
}

void log_transform_baseline_update(struct feature_baseline *fb,
                                   double raw_value,
                                   double alpha,
                                   uint64_t timestamp_ns) {
    if (!fb) return;

    // Transform before updating baseline
    double log_value = safe_log(raw_value);

    // Use standard EWMA update on log-transformed value
    feature_baseline_update(fb, log_value, alpha, timestamp_ns);
}

// ==================== Feature Weight System ====================

void l2_feature_weights_init(struct l2_feature_weights *fw) {
    if (!fw) return;

    fw->enabled = true;

    // Copy weights from feature configs
    const struct l2_feature_config *configs = l2_get_feature_configs();
    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        fw->weights[i] = configs[i].weight;
    }
}

// MF6 FIX: Hot reload feature weights
void l2_feature_weights_reload(struct l2_feature_weights *fw,
                               const double *new_weights,
                               int count,
                               bool enabled) {
    if (!fw) return;

    fw->enabled = enabled;

    // Update weights from provided array
    int limit = (count < L2_MAX_FEATURES) ? count : L2_MAX_FEATURES;
    for (int i = 0; i < limit; i++) {
        if (new_weights) {
            fw->weights[i] = new_weights[i];
        }
    }

    // Fill remaining with defaults if count is less than features
    if (count < L2_MAX_FEATURES) {
        const struct l2_feature_config *configs = l2_get_feature_configs();
        for (int i = count; i < L2_MAX_FEATURES; i++) {
            fw->weights[i] = configs[i].weight;
        }
    }

    printf("[Layer2] Feature weights reloaded (%d weights, %s)\n",
           limit, enabled ? "enabled" : "disabled");
}

// MF6 FIX: Set single feature weight
int l2_feature_weights_set(struct l2_feature_weights *fw,
                           int feature_idx,
                           double weight) {
    if (!fw || feature_idx < 0 || feature_idx >= L2_MAX_FEATURES) {
        return -1;
    }

    // Clamp weight to valid range
    if (weight < 0.0) weight = 0.0;
    if (weight > 1.0) weight = 1.0;

    fw->weights[feature_idx] = weight;
    return 0;
}

// E3 FIX: Minimum weight floor to prevent evasion via weight manipulation
#define L2_MIN_WEIGHT_FLOOR 0.1

double l2_weighted_detection_score(const double z_scores[L2_MAX_FEATURES],
                                   const struct l2_feature_weights *weights,
                                   double threshold,
                                   int *triggered_count) {
    if (!z_scores) {
        if (triggered_count) *triggered_count = 0;
        return 0.0;
    }

    double max_weighted_z = 0.0;
    int count = 0;

    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        double abs_z = fabs(z_scores[i]);
        double weight = (weights && weights->enabled) ? weights->weights[i] : 1.0;

        // E3 FIX: Enforce minimum weight floor - no feature can be below 0.1
        // This prevents attackers from setting weight=0 to blind specific features
        if (weight < L2_MIN_WEIGHT_FLOOR) weight = L2_MIN_WEIGHT_FLOOR;

        double weighted_z = abs_z * weight;

        if (weighted_z > max_weighted_z) {
            max_weighted_z = weighted_z;
        }

        // Count triggered features using weighted z
        if (weighted_z >= threshold) {
            count++;
        }
    }

    if (triggered_count) *triggered_count = count;
    return max_weighted_z;
}

// ==================== Advanced Detection ====================

void l2_advanced_detect(const struct tier_baseline *baseline,
                        const struct l2_feature_snapshot *snapshot,
                        struct cusum_detector *cusum,
                        struct jsd_baseline *jsd,
                        const struct l2_feature_weights *weights,
                        double z_threshold,
                        double jsd_threshold,
                        struct advanced_detection_result *result) {
    if (!baseline || !snapshot || !result) return;

    memset(result, 0, sizeof(*result));
    result->primary_feature_idx = -1;
    result->primary_feature_name = "unknown";

    if (!baseline->ready) {
        return;  // Not ready yet
    }

    // ===== Step 1: Compute Z-scores for all features =====
    // Use runtime-configurable feature configs
    const struct l2_feature_config *configs = l2_get_feature_configs();

    double max_z = 0.0;
    int max_z_idx = -1;

    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        const struct feature_baseline *fb = &baseline->features[i];
        double value = snapshot->values[i];
        double z = 0.0;

        enum l2_detection_method method = configs[i].method;
        bool bidirectional = configs[i].bidirectional;

        switch (method) {
            case L2_METHOD_LOG_ZSCORE:
                // Cardinality features - use log transform
                z = log_transform_z_score(fb, value, bidirectional);
                break;

            case L2_METHOD_THRESHOLD:
                // Concentration features - simple threshold check
                {
                    double thresh = configs[i].threshold;
                    if (value > thresh) {
                        // Convert to Z-score equivalent for consistency
                        z = (value - thresh) / 10.0 + z_threshold;
                    }
                }
                break;

            case L2_METHOD_JSD:
                // Protocol mix - handled separately, store 0 here
                z = 0.0;
                break;

            case L2_METHOD_EWMA_CUSUM:
                // Volume/churn - compute standard Z for comparison
                // CUSUM is handled separately below
                z = feature_baseline_z_score(fb, value);
                if (bidirectional) z = fabs(z);
                break;

            case L2_METHOD_EWMA_ZSCORE:
            default:
                // Standard Z-score
                z = feature_baseline_z_score(fb, value);
                if (bidirectional) z = fabs(z);
                break;
        }

        result->z_scores[i] = z;

        // Track maximum (weighted)
        double weight = (weights && weights->enabled) ? weights->weights[i] : 1.0;
        // E3 FIX: Enforce minimum weight floor
        if (weight < L2_MIN_WEIGHT_FLOOR) weight = L2_MIN_WEIGHT_FLOOR;
        double weighted_z = fabs(z) * weight;

        if (weighted_z > max_z) {
            max_z = weighted_z;
            max_z_idx = i;
        }
    }

    // ===== Step 2: Run CUSUM detection =====
    if (cusum) {
        uint64_t cusum_triggered = 0;
        result->cusum_triggered_count = cusum_detect(cusum, snapshot, baseline, &cusum_triggered);
        result->cusum_max_norm = cusum->last_max_norm;   // continuous score for the conformal path
        memcpy(result->cusum_norms, cusum->last_norms, sizeof(result->cusum_norms));  // per-feature (routed)

        for (int i = 0; i < L2_MAX_FEATURES; i++) {
            result->cusum_triggered[i] = (cusum_triggered & (1ULL << i)) != 0;
        }
    }

    // ===== Step 3: Compute JSD for protocol mix =====
    if (jsd && jsd->ready) {
        struct protocol_distribution current_dist;
        protocol_dist_from_ratios(&current_dist,
                                  (uint8_t)snapshot->values[L2_FEAT_TCP_RATIO],
                                  (uint8_t)snapshot->values[L2_FEAT_UDP_RATIO],
                                  (uint8_t)snapshot->values[L2_FEAT_ICMP_RATIO],
                                  (uint8_t)snapshot->values[L2_FEAT_OTHER_RATIO]);

        result->jsd_score = jsd_compute(&jsd->baseline_dist, &current_dist);
        result->jsd_triggered = (result->jsd_score >= jsd_threshold);
    }

    // ===== Step 4: Combine results =====
    result->total_triggered = 0;

    // D4 FIX: Track which features triggered by Z-score to avoid double-counting
    uint64_t zscore_triggered_mask = 0;

    // Count Z-score triggers using weighted ẑ_i = w_i * z_i
    // A downweighted feature needs a proportionally larger raw z to trigger,
    // matching the paper's "ẑ_i = w_i * z_i before the tier-agreement vote".
    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        double weight = (weights && weights->enabled) ? weights->weights[i] : 1.0;
        // E3 FIX: Enforce minimum weight floor - never skip features entirely
        if (weight < L2_MIN_WEIGHT_FLOOR) weight = L2_MIN_WEIGHT_FLOOR;

        double weighted_z = fabs(result->z_scores[i]) * weight;
        if (weighted_z >= z_threshold) {
            result->total_triggered++;
            zscore_triggered_mask |= (1ULL << i);
        }
    }

    // D4 FIX: Only count CUSUM triggers for features NOT already counted by Z-score
    // This prevents double-counting when both methods trigger on same feature
    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        if (result->cusum_triggered[i]) {
            bool already_counted = (zscore_triggered_mask & (1ULL << i)) != 0;
            if (!already_counted) {
                result->total_triggered++;
            }
        }
    }

    // Add JSD trigger (protocol mix is computed separately, no overlap)
    if (result->jsd_triggered) {
        result->total_triggered++;
    }

    // Compute combined score
    // JSD contributes equivalent of 2 * z_threshold if triggered
    double jsd_contribution = result->jsd_triggered ? (result->jsd_score * z_threshold * 3.0) : 0.0;

    // CUSUM contributes additional weight
    double cusum_contribution = result->cusum_triggered_count * z_threshold * 0.5;

    result->combined_score = max_z + jsd_contribution + cusum_contribution;

    // Set primary detection source
    if (max_z_idx >= 0) {
        result->primary_feature_idx = max_z_idx;
        result->primary_feature_name = l2_feature_names[max_z_idx];
        result->primary_method = configs[max_z_idx].method;
    }

    // Override if JSD is the strongest signal
    if (result->jsd_triggered && jsd_contribution > max_z) {
        result->primary_method = L2_METHOD_JSD;
        result->primary_feature_name = "protocol_mix";
        result->primary_feature_idx = L2_FEAT_TCP_RATIO;  // Representative
    }
}
