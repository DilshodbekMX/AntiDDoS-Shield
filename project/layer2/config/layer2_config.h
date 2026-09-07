#ifndef LAYER2_CONFIG_H
#define LAYER2_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include "../baselines.h"  // For L2_MAX_FEATURES

/**
 * @file layer2_config.h
 * @brief Layer 2 Behavioral Monitor Configuration
 *
 * Configuration structures and defaults for the Layer 2 anomaly detection
 * engine. Supports loading from JSON config file.
 */

// ==================== Default Values ====================

// Lowered from 6.0 to 4.0 - Z=6 was too conservative (p < 2e-9)
// Z=4.0 corresponds to p < 3.2e-5 which catches subtle attacks while
// tier agreement requirement prevents false positives
#define L2_DEFAULT_Z_SCORE_THRESHOLD      4.0
#define L2_DEFAULT_MIN_TIER_AGREEMENT     2

// EWMA smoothing factors retuned 2026-06 (0.2/0.1/0.05 -> 0.15/0.05/0.01): a slower immediate tier
// de-twitches the baseline on benign bursts, cutting cross-day per-window FPR ~2 pp mean across all
// five corpora at <=1 pp DR loss on every attack class. Validated multi-corpus (DR-at-fixed-FPR),
// Pareto-robust + leave-one-corpus-out + CESNET regression + per-attack-type DR. See paper design-
// justification; a slower immediate tier (0.10) cuts more FPR but loses gradual-attack DR (Slowloris,
// Mirai) -- 0.15 is the validated safe knee.
#define L2_DEFAULT_ALPHA_IMMEDIATE        0.15
#define L2_DEFAULT_ALPHA_HOURLY           0.05
#define L2_DEFAULT_ALPHA_WEEKLY           0.01

#define L2_DEFAULT_MIN_SAMPLES_IMMEDIATE  10
// Lowered from 60/180 to 20/40 - old values meant months to maturity
// New values allow Tier 2/3 to contribute within reasonable timeframes
#define L2_DEFAULT_MIN_SAMPLES_HOURLY     20
#define L2_DEFAULT_MIN_SAMPLES_WEEKLY     40

// Detection interval jitter to prevent predictable timing attacks
// Attackers could time 900ms bursts between 1Hz detection cycles
#define L2_DEFAULT_JITTER_MS              100

#define L2_DEFAULT_COOL_DOWN_SECONDS      30.0
#define L2_DEFAULT_DETECTION_INTERVAL_MS  1000

// FAST DETECTION: 100ms fast tier for pulse attack detection
// The fast tier runs at 100ms intervals with simpler threshold checks
// to catch sub-second pulse attacks that evade the 1Hz detection
#define L2_DEFAULT_FAST_DETECTION_ENABLED     true
#define L2_DEFAULT_FAST_DETECTION_INTERVAL_MS 100
#define L2_DEFAULT_FAST_THRESHOLD_MULTIPLIER  1.5   // Trigger at 1.5x normal threshold
#define L2_DEFAULT_FAST_MIN_PPS_SPIKE         10000 // Minimum PPS to consider a spike
#define L2_DEFAULT_FAST_SYN_SPIKE_THRESHOLD   5000  // SYN/s spike threshold
#define L2_DEFAULT_FAST_CONSECUTIVE_REQUIRED  2     // Consecutive fast detections to confirm

// Minimum traffic threshold for meaningful detection
// Below this rate, detection is suppressed to avoid false positives from idle periods
#define L2_DEFAULT_MIN_PPS_FOR_DETECTION  100

// Configurable thresholds (were hardcoded)
#define L2_DEFAULT_JSD_THRESHOLD          0.15

// Ensemble decision rule (paper section4.10): 0 = disjunctive OR (shipped default),
// 1 = split-conformal Bonferroni, 2 = split-conformal e-value. The conformal paths
// are offline-validated (bit-level unit tests) and selectable here for production rollout.
#define L2_ENSEMBLE_RULE_OR               0
#define L2_ENSEMBLE_RULE_CONFORMAL_BONF   1
#define L2_ENSEMBLE_RULE_CONFORMAL_EVALUE 2
#define L2_ENSEMBLE_RULE_ROUTED_FDR       3    // per-feature routing under BH-FDR (paper section6.15)
#define L2_ENSEMBLE_RULE_INNOVATION_GATE  4    // innovation-gated z-path latch (the innovation-gate prototype)
#define L2_DEFAULT_ENSEMBLE_RULE          L2_ENSEMBLE_RULE_OR
#define L2_DEFAULT_CONFORMAL_ALPHA        0.001    // family-wise target alpha = 0.1%
#define L2_DEFAULT_ROUTED_FDR_ALPHA       0.1      // BH-FDR level (routed needs n >= m/alpha calib)
// Innovation-gate (innovation-gate prototype) latch: gate the z-path on a training-free surprise statistic while
// CUSUM/JSD stay ungated (decision = (z AND latch) OR CUSUM OR JSD). Cuts stale-reference
// cross-day false alarms; the latch defaults OPEN until armed so the z-path is never wrongly
// suppressed during warm-up (harness experiment/negatives/innovation_path.py + the offline prototype).
#define L2_DEFAULT_INNOVATION_GATE_KAPPA       3.0   // open when standardized surprise > kappa
#define L2_DEFAULT_INNOVATION_GATE_HYSTERESIS  30    // quiet windows required to close the latch
// Buffer must be >= 3/alpha for the Bonferroni p-value floor 1/(n+1) to reach alpha/3
// (the calibration floor alpha ~= 3/(n+1), paper section4.11). 4096 supports alpha down to ~7e-4.
#define L2_DEFAULT_CONFORMAL_CAPACITY     4096     // per-path calibration buffer size
#define L2_DEFAULT_MAX_FLOW_FRACTION_THRESHOLD  15.0
#define L2_DEFAULT_TOPK_FLOW_SHARE_THRESHOLD    30.0

// FIX #4: Warmup emergency thresholds (were hardcoded 50K/5K)
// During warmup (no baselines ready), use absolute rate thresholds
#define L2_DEFAULT_WARMUP_PPS_THRESHOLD   50000   // Packets per second
#define L2_DEFAULT_WARMUP_SYN_THRESHOLD   5000    // SYN packets per second

// ADAPTIVE WARMUP: Dynamic threshold adjustment during baseline learning
// Instead of static thresholds, track traffic shape and adjust thresholds
// based on observed patterns to prevent both false positives and missed attacks
#define L2_DEFAULT_ADAPTIVE_WARMUP_ENABLED      true
#define L2_DEFAULT_WARMUP_LEARNING_WINDOW_SEC   30    // Window to learn traffic shape
#define L2_DEFAULT_WARMUP_SPIKE_FACTOR          3.0   // Spike = 3x observed average
#define L2_DEFAULT_WARMUP_MIN_OBSERVATIONS      5     // Minimum samples before adaptation
#define L2_DEFAULT_WARMUP_PERCENTILE_THRESHOLD  95    // Use 95th percentile for threshold

// Configurable Z-score level thresholds (were hardcoded in detection.c)
// These define the max_z thresholds for anomaly level classification
#define L2_DEFAULT_Z_CRITICAL_3TIER       12.0    // CRITICAL when 3 tiers agree
#define L2_DEFAULT_Z_HIGH_3TIER           9.0     // HIGH when 3 tiers agree
#define L2_DEFAULT_Z_MEDIUM_3TIER         6.0     // MEDIUM when 3 tiers agree
#define L2_DEFAULT_Z_HIGH_2TIER           15.0    // HIGH when 2 tiers agree
#define L2_DEFAULT_Z_MEDIUM_2TIER         10.0    // MEDIUM when 2 tiers agree
#define L2_DEFAULT_Z_MEDIUM_1TIER         15.0    // MEDIUM when 1 tier only

// Baseline poisoning protection (new)
// Detect if baseline is changing too fast (potential attack adaptation)
#define L2_DEFAULT_BASELINE_CHANGE_RATE_THRESHOLD  2.0   // Max baseline change per cycle
#define L2_DEFAULT_BASELINE_POISON_WINDOW_SEC      300   // Window for detecting sustained changes
#define L2_DEFAULT_BASELINE_POISON_COUNT_THRESHOLD 10    // Number of large changes to trigger freeze
#define L2_DEFAULT_BASELINE_POISON_RECOVERY_SEC    900   // Auto-unfreeze after 15 min (0 = never)

// Adaptive threshold configuration
// MF2 FIX: Configurable parameters for automatic FP/TP-based threshold tuning
#define L2_DEFAULT_ADAPTIVE_ENABLED          true
#define L2_DEFAULT_ADAPTIVE_MIN_THRESHOLD    4.0     // Never go below 4.0 Z-score
#define L2_DEFAULT_ADAPTIVE_MAX_THRESHOLD    10.0    // Never go above 10.0 Z-score
#define L2_DEFAULT_ADAPTIVE_STEP             0.25    // Adjustment step size
#define L2_DEFAULT_ADAPTIVE_FP_THRESHOLD     0.30    // If >30% FP, increase threshold
#define L2_DEFAULT_ADAPTIVE_TP_MIN           0.50    // If <50% TP, maybe too sensitive
#define L2_DEFAULT_ADAPTIVE_EVAL_INTERVAL_S  300     // Evaluate every 5 minutes
#define L2_DEFAULT_ADAPTIVE_MIN_SAMPLES      10      // Need at least 10 events to evaluate
#define L2_DEFAULT_FP_DURATION_THRESHOLD_S   10.0    // Detection < 10s = likely FP
#define L2_DEFAULT_TP_DURATION_THRESHOLD_S   30.0    // Detection > 30s = likely TP

// Use relative paths from project root (configurable at runtime)
#define L2_DEFAULT_BASELINE_FILE          "data/layer2_baselines.json"
#define L2_DEFAULT_CONFIG_FILE            "layer2/config/layer2_config.json"

// ==================== Configuration Structure ====================

/**
 * Layer 2 configuration parameters
 */
struct layer2_config {
    // Detection thresholds
    double z_score_threshold;           // Z-score threshold for anomaly (default: 4.0, L2_DEFAULT_Z_SCORE_THRESHOLD)
    int min_tier_agreement;             // Minimum tiers that must agree (default: 2)

    // JSD threshold (was hardcoded 0.15)
    double jsd_threshold;               // JSD threshold for protocol mix anomaly (default: 0.15)

    // Ensemble decision rule selector (paper section4.10): OR (default) vs split-conformal.
    int ensemble_rule;                  // L2_ENSEMBLE_RULE_* (default: OR)
    double conformal_alpha;             // family-wise alpha for the conformal path (default: 0.001)
    double routed_fdr_alpha;            // BH-FDR level for the routed path (default: 0.1)
    uint32_t conformal_capacity;        // per-path calibration buffer size (default: 4096, >=3/alpha)
    double innovation_gate_kappa;       // the innovation-gate prototype latch open threshold on standardized surprise (default: 3.0)
    int    innovation_gate_hysteresis;  // the innovation-gate prototype quiet windows required to close the latch (default: 30)

    // Concentration thresholds (were hardcoded 15.0/30.0)
    double max_flow_fraction_threshold; // Single flow fraction threshold % (default: 15.0)
    double topk_flow_share_threshold;   // Top-K flow share threshold % (default: 30.0)

    // EWMA smoothing factors (alpha)
    double alpha_immediate;             // Tier 1: Fast adaptation (default: 0.15, retuned from 0.2)
    double alpha_hourly;                // Tier 2: Medium adaptation (default: 0.05, retuned from 0.1)
    double alpha_weekly;                // Tier 3: Slow adaptation (default: 0.01, retuned from 0.05)

    // Minimum samples before tier is ready
    uint32_t min_samples_immediate;     // Tier 1: 10 samples (~10 seconds)
    uint32_t min_samples_hourly;        // Tier 2: 20 samples (CVA fix; was 60)
    uint32_t min_samples_weekly;        // Tier 3: 40 samples (CVA fix; was 180)

    // Attack handling
    double cool_down_seconds;           // Seconds to wait after anomaly clears
    bool baseline_freeze_enabled;       // Freeze baselines during attack

    // Timing
    uint32_t detection_interval_ms;     // Detection loop interval (default: 1000ms)
    uint32_t jitter_ms;                 // Random jitter +/-N ms (default: 100)

    // Minimum traffic threshold
    uint64_t min_pps_for_detection;     // Skip detection below this pps (default: 100)

    // Fast detection tier (100ms for pulse attacks)
    bool     fast_detection_enabled;        // Enable 100ms fast detection
    uint32_t fast_detection_interval_ms;    // Fast tier interval (default: 100ms)
    double   fast_threshold_multiplier;     // Trigger at N*baseline (default: 1.5)
    uint64_t fast_min_pps_spike;            // Minimum PPS spike (default: 10000)
    uint64_t fast_syn_spike_threshold;      // SYN/s spike threshold (default: 5000)
    uint32_t fast_consecutive_required;     // Consecutive detections to confirm (default: 2)

    // Adaptive warmup thresholds
    bool     adaptive_warmup_enabled;       // Enable adaptive warmup
    uint32_t warmup_learning_window_sec;    // Window to learn traffic shape
    double   warmup_spike_factor;           // Spike = N*observed average
    uint32_t warmup_min_observations;       // Min samples before adaptation
    uint32_t warmup_percentile_threshold;   // Use Nth percentile for threshold

    // FIX #4: Warmup emergency thresholds (configurable)
    uint64_t warmup_pps_threshold;      // PPS threshold during warmup (default: 50000)
    uint64_t warmup_syn_threshold;      // SYN/s threshold during warmup (default: 5000)

    // Configurable Z-score level thresholds for anomaly classification
    // These replace the hardcoded values in l2_compute_anomaly_level()
    double z_critical_3tier;            // CRITICAL when 3 tiers agree (default: 12.0)
    double z_high_3tier;                // HIGH when 3 tiers agree (default: 9.0)
    double z_medium_3tier;              // MEDIUM when 3 tiers agree (default: 6.0)
    double z_high_2tier;                // HIGH when 2 tiers agree (default: 15.0)
    double z_medium_2tier;              // MEDIUM when 2 tiers agree (default: 10.0)
    double z_medium_1tier;              // MEDIUM when 1 tier only (default: 15.0)

    // Baseline poisoning protection
    // Prevents attackers from slowly ramping up to poison baselines
    bool     baseline_poison_protection_enabled;  // Enable protection (default: true)
    double   baseline_change_rate_threshold;      // Max mean change rate per cycle (default: 2.0)
    uint32_t baseline_poison_window_sec;          // Detection window (default: 300)
    uint32_t baseline_poison_count_threshold;     // Triggers after N large changes (default: 10)
    uint32_t baseline_poison_recovery_sec;        // Auto-unfreeze after N sec (0 = manual only, default: 900)

    // Persistence
    char baseline_file[256];            // Path for baseline persistence
    uint32_t baseline_save_interval_sec; // Auto-save interval (0 = disabled)

    // Feature weights (optional, for weighted detection)
    bool use_feature_weights;
    double feature_weights[L2_MAX_FEATURES];  // Weights per feature (L2_MAX_FEATURES features)
    bool feature_auto_select;                 // Auto-select features based on quality scoring

    // Logging
    bool log_detections;                // Log each detection event
    bool log_baseline_updates;          // Log baseline updates (verbose)
    uint32_t log_interval_sec;          // Periodic status log interval

    // Adaptive threshold tuning configuration
    // MF2 FIX: Configurable via backend UI
    bool     adaptive_enabled;              // Enable adaptive threshold tuning
    double   adaptive_min_threshold;        // Minimum threshold (default: 4.0)
    double   adaptive_max_threshold;        // Maximum threshold (default: 10.0)
    double   adaptive_step;                 // Adjustment step size (default: 0.25)
    double   adaptive_fp_threshold;         // FP rate trigger (default: 0.30 = 30%)
    double   adaptive_tp_min;               // Minimum TP rate (default: 0.50 = 50%)
    uint32_t adaptive_eval_interval_sec;    // Evaluation interval (default: 300s)
    uint32_t adaptive_min_samples;          // Min events for evaluation (default: 10)
    double   fp_duration_threshold_sec;     // Detection < this = FP (default: 10.0s)
    double   tp_duration_threshold_sec;     // Detection > this = TP (default: 30.0s)
};

// ==================== API ====================

/**
 * Initialize configuration with default values
 */
void layer2_config_init_defaults(struct layer2_config *config);

/**
 * Load configuration from JSON file
 * @param config Output configuration structure
 * @param filepath Path to JSON config file
 * @return 0 on success, -1 on error
 */
int layer2_config_load(struct layer2_config *config, const char *filepath);

/**
 * Save configuration to JSON file
 * @param config Configuration to save
 * @param filepath Path to save to
 * @return 0 on success, -1 on error
 */
int layer2_config_save(const struct layer2_config *config, const char *filepath);

/**
 * Validate configuration parameters
 * @param config Configuration to validate
 * @return 0 if valid, -1 if invalid (logs errors)
 */
int layer2_config_validate(const struct layer2_config *config);

/**
 * Get global configuration pointer
 * Lock-free read via atomic pointer - safe to call from any thread
 * @return Pointer to current configuration (read-only during runtime)
 */
const struct layer2_config *layer2_config_get(void);

/**
 * Get pointer to primary config buffer for initial loading
 * Used by layer2_init() to load directly into double-buffer
 * @return Pointer to config buffer (writable for initialization only)
 */
struct layer2_config *layer2_config_get_buffer(void);

/**
 * Reload configuration from file at runtime
 * Uses atomic pointer swap for lock-free reads
 * @return 0 on success, -1 on error
 */
int layer2_config_reload(void);

#endif // LAYER2_CONFIG_H
