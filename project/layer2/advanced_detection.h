#ifndef LAYER2_ADVANCED_DETECTION_H
#define LAYER2_ADVANCED_DETECTION_H

#include "baselines.h"
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

/**
 * @file advanced_detection.h
 * @brief Advanced Statistical Detection Methods for DDoS Anomaly Detection
 *
 * Implements feature-specific detection methods beyond simple Z-score:
 *
 * 1. CUSUM (Cumulative Sum) - For volume and churn features
 *    - Catches slow-ramp attacks that Z-score misses
 *    - Detects sustained mean shifts
 *
 * 2. Jensen-Shannon Divergence (JSD) - For protocol mix
 *    - Computes distribution distance between current and baseline
 *    - Single score for entire protocol distribution
 *
 * 3. Log-Transform - For cardinality features
 *    - Handles multiplicative/exponential growth
 *    - 100->1000 IPs has same significance as 1000->10000
 *
 * 4. Bidirectional Detection - For cardinality features
 *    - Detects both increases (spoofing) and decreases (single-source flood)
 *
 * 5. Feature Weights - Prioritize critical features
 *    - Downweight noisy features (ack_per_sec, fin_per_sec)
 *    - Upweight ratio features
 */

// ==================== Feature Categories ====================

/**
 * Feature detection method types
 */
enum l2_detection_method {
    L2_METHOD_EWMA_ZSCORE = 0,   // Standard EWMA + Z-score (TCP flags, ratios)
    L2_METHOD_EWMA_CUSUM,        // EWMA + CUSUM (volume, churn)
    L2_METHOD_LOG_ZSCORE,        // Log-transform + Z-score (cardinality)
    L2_METHOD_THRESHOLD,         // Simple threshold (concentration)
    L2_METHOD_JSD,               // Jensen-Shannon Divergence (protocol mix - computed as group)
    L2_METHOD_DISABLED           // Feature disabled from detection
};

/**
 * Feature configuration for detection
 */
struct l2_feature_config {
    enum l2_detection_method method;
    double weight;               // 0.0-1.0 weight in detection (0 = ignored)
    double threshold;            // Custom threshold (0 = use global)
    bool bidirectional;          // Detect both increases and decreases
};

/**
 * Get feature configurations (may be modified from defaults)
 * Returns runtime-modifiable configs
 */
const struct l2_feature_config *l2_get_feature_configs(void);

/**
 * Set concentration thresholds at runtime
 * @param max_flow_fraction Threshold for L2_FEAT_MAX_FLOW_FRACTION (default: 15.0%)
 * @param topk_flow_share Threshold for L2_FEAT_TOPK_FLOW_SHARE (default: 30.0%)
 */
void l2_set_concentration_thresholds(double max_flow_fraction, double topk_flow_share);

// ==================== CUSUM Detector ====================

/**
 * CUSUM (Cumulative Sum) state for detecting sustained mean shifts
 *
 * Algorithm:
 *   S[n] = max(0, S[n-1] + (x[n] - mean - k))
 *   Alarm if S[n] > h
 *
 * Where:
 *   k = allowance/slack (typically 0.5 * expected_shift)
 *   h = threshold (typically 4-5 * stddev)
 *
 * Advantages over Z-score:
 *   - Catches slow-ramp attacks (20% increase sustained over 5 minutes)
 *   - Accumulates evidence over time
 *   - Lower false positive rate for bursty traffic
 */
struct cusum_state {
    double S_high;               // Cumulative sum for increase detection
    double S_low;                // Cumulative sum for decrease detection
    double k;                    // Slack/allowance parameter
    double h;                    // Decision threshold
    double mean;                 // Current mean (from EWMA)
    double stddev;               // Current stddev (from EWMA)
    bool alarm_high;             // High alarm triggered
    bool alarm_low;              // Low alarm triggered
    uint32_t samples_since_reset; // Samples since last reset
} __attribute__((aligned(64)));

/**
 * CUSUM detector for multiple features
 */
struct cusum_detector {
    struct cusum_state states[L2_MAX_FEATURES];
    double k_factor;             // k = k_factor * stddev (default: 0.5)
    double h_factor;             // h = h_factor * stddev (default: 5.0)
    uint32_t min_samples;        // Minimum samples before triggering
    double last_max_norm;        // max_f max(S_high,S_low)/h from the last cusum_detect (for conformal)
    double last_norms[L2_MAX_FEATURES];  // per-feature normalized CUSUM stat (for routed FDR)
} __attribute__((aligned(64)));

/**
 * Initialize CUSUM detector
 */
void cusum_detector_init(struct cusum_detector *det, double k_factor, double h_factor);

/**
 * Update CUSUM state with new value
 * @return true if alarm triggered
 */
bool cusum_update(struct cusum_state *state, double value, double mean, double stddev,
                  double k_factor, double h_factor);

/**
 * Reset CUSUM state (after alarm or periodically)
 */
void cusum_reset(struct cusum_state *state);

/**
 * Run CUSUM detection on features that use it
 * @param det CUSUM detector
 * @param snapshot Current feature values
 * @param baselines Current baselines (for mean/stddev)
 * @param triggered_features Output: bitmap of triggered features
 * @return Number of features that triggered
 */
int cusum_detect(struct cusum_detector *det,
                 const struct l2_feature_snapshot *snapshot,
                 const struct tier_baseline *baseline,
                 uint64_t *triggered_features);

// ==================== Jensen-Shannon Divergence ====================

/**
 * Protocol distribution for JSD calculation
 * Normalized probabilities that sum to 1.0
 */
struct protocol_distribution {
    double tcp;                  // TCP probability (0.0-1.0)
    double udp;                  // UDP probability (0.0-1.0)
    double icmp;                 // ICMP probability (0.0-1.0)
    double other;                // Other probability (0.0-1.0)
};

/**
 * JSD baseline for protocol mix
 */
struct jsd_baseline {
    struct protocol_distribution baseline_dist;  // Learned baseline distribution
    double ewma_alpha;           // EWMA smoothing factor
    uint32_t sample_count;       // Samples processed
    bool ready;                  // Has enough samples
    uint32_t min_samples;        // Minimum samples before ready

    // E4 FIX: Rate limiting to prevent protocol oscillation evasion
    uint64_t last_update_ns;     // When baseline was last updated
    uint32_t update_interval_ms; // Minimum time between updates (default: 5000ms)
    uint32_t updates_this_minute; // Updates in current minute (for abuse detection)
    uint64_t minute_start_ns;    // Start of current counting minute
} __attribute__((aligned(64)));

/**
 * Initialize JSD baseline
 */
void jsd_baseline_init(struct jsd_baseline *jsd, double alpha, uint32_t min_samples);

/**
 * Update JSD baseline with new distribution
 */
void jsd_baseline_update(struct jsd_baseline *jsd, const struct protocol_distribution *current);

/**
 * Update JSD baseline with rate limiting (E4 FIX)
 * @param now_ns Current time in nanoseconds (0 = use clock_gettime)
 */
void jsd_baseline_update_timed(struct jsd_baseline *jsd, const struct protocol_distribution *current,
                                uint64_t now_ns);

/**
 * Compute Jensen-Shannon Divergence between current and baseline
 *
 * JSD = 0.5 * KL(P||M) + 0.5 * KL(Q||M)
 * where M = 0.5 * (P + Q)
 *
 * @param baseline Learned baseline distribution
 * @param current Current distribution
 * @return JSD value (0.0 = identical, 1.0 = completely different)
 */
double jsd_compute(const struct protocol_distribution *baseline,
                   const struct protocol_distribution *current);

/**
 * Kullback-Leibler divergence (helper for JSD)
 * KL(P||Q) = sum(P[i] * log(P[i] / Q[i]))
 */
double kl_divergence(const struct protocol_distribution *p,
                     const struct protocol_distribution *q);

/**
 * Create distribution from raw percentages
 */
void protocol_dist_from_ratios(struct protocol_distribution *dist,
                               uint8_t tcp_pct, uint8_t udp_pct,
                               uint8_t icmp_pct, uint8_t other_pct);

/**
 * Check if JSD exceeds threshold (typical: 0.1-0.2)
 */
bool jsd_is_anomalous(const struct jsd_baseline *baseline,
                      const struct protocol_distribution *current,
                      double threshold);

// ==================== Log-Transform Detection ====================

/**
 * Compute log-transformed Z-score for cardinality features
 *
 * Transform: z = (log(value + 1) - log_mean) / log_stddev
 *
 * This handles multiplicative growth properly:
 * - 100 -> 1000 IPs has same Z-score significance as 1000 -> 10000
 *
 * @param baseline Feature baseline (mean/variance of log values)
 * @param value Current raw value
 * @param bidirectional If true, use |z|; if false, only detect increases
 * @return Z-score of log-transformed value
 */
double log_transform_z_score(const struct feature_baseline *baseline,
                             double value, bool bidirectional);

/**
 * Update baseline with log-transformed value
 * Call this instead of feature_baseline_update for cardinality features
 */
void log_transform_baseline_update(struct feature_baseline *fb,
                                   double raw_value,
                                   double alpha,
                                   uint64_t timestamp_ns);

// ==================== Feature Weight System ====================

/**
 * Feature weights for detection priority
 * Higher weight = more influence on detection decision
 */
struct l2_feature_weights {
    double weights[L2_MAX_FEATURES];
    bool enabled;                // Use weights if true
};

/**
 * Initialize with default weights
 */
void l2_feature_weights_init(struct l2_feature_weights *fw);

/**
 * MF6 FIX: Hot reload feature weights from config
 * Call this after config reload to update weights without restart
 *
 * @param fw Feature weights to update
 * @param new_weights Array of new weight values
 * @param count Number of weights in array
 * @param enabled Whether weighted detection is enabled
 */
void l2_feature_weights_reload(struct l2_feature_weights *fw,
                               const double *new_weights,
                               int count,
                               bool enabled);

/**
 * MF6 FIX: Set a single feature weight at runtime
 *
 * @param fw Feature weights
 * @param feature_idx Feature index (0 to L2_MAX_FEATURES-1)
 * @param weight New weight value (0.0 - 1.0)
 * @return 0 on success, -1 on invalid index
 */
int l2_feature_weights_set(struct l2_feature_weights *fw,
                           int feature_idx,
                           double weight);

/**
 * Get weighted detection score
 * @param z_scores Z-scores for all features
 * @param weights Feature weights
 * @param triggered_count Output: count of features exceeding threshold
 * @return Weighted maximum Z-score
 */
double l2_weighted_detection_score(const double z_scores[L2_MAX_FEATURES],
                                   const struct l2_feature_weights *weights,
                                   double threshold,
                                   int *triggered_count);

// ==================== Advanced Detection Result ====================

/**
 * Extended detection result with method-specific details
 */
struct advanced_detection_result {
    // Standard Z-score results (per feature)
    double z_scores[L2_MAX_FEATURES];

    // CUSUM results
    bool cusum_triggered[L2_MAX_FEATURES];
    int cusum_triggered_count;

    // JSD result (single score for protocol mix)
    double jsd_score;
    bool jsd_triggered;

    // Normalized CUSUM statistic (max over features of max(S_high,S_low)/h); the
    // continuous per-path score the conformal combiner consumes (paper section4.10).
    double cusum_max_norm;
    double cusum_norms[L2_MAX_FEATURES];  // per-feature normalized CUSUM (for routed FDR, section6.15)

    // Combined result
    double combined_score;       // Weighted combination of all methods
    int total_triggered;         // Total features/methods triggered

    // Primary detection source
    enum l2_detection_method primary_method;
    int primary_feature_idx;
    const char *primary_feature_name;
};

/**
 * Run advanced detection using feature-specific methods
 */
void l2_advanced_detect(const struct tier_baseline *baseline,
                        const struct l2_feature_snapshot *snapshot,
                        struct cusum_detector *cusum,
                        struct jsd_baseline *jsd,
                        const struct l2_feature_weights *weights,
                        double z_threshold,
                        double jsd_threshold,
                        struct advanced_detection_result *result);

// ==================== Inline Helpers ====================

/**
 * Safe log with minimum value to avoid log(0)
 */
static inline double safe_log(double x) {
    return log(x + 1.0);  // log(x+1) so log(0) = 0
}

/**
 * Safe division to avoid NaN
 */
static inline double safe_div(double a, double b) {
    return (b > 1e-10) ? (a / b) : 0.0;
}

/**
 * Clamp value to range
 */
static inline double clamp(double x, double min_val, double max_val) {
    if (x < min_val) return min_val;
    if (x > max_val) return max_val;
    return x;
}

#endif // LAYER2_ADVANCED_DETECTION_H
