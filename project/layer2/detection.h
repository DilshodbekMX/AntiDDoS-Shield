#ifndef LAYER2_DETECTION_H
#define LAYER2_DETECTION_H

#include "baselines.h"
#include <stdint.h>
#include <stdbool.h>

// Forward declaration for attack classification
struct attack_classification;

/**
 * @file detection.h
 * @brief Multi-Tier Z-Score Anomaly Detection
 *
 * Implements the core detection logic for Layer 2:
 *
 * 1. Collects Z-scores from all three tiers
 * 2. Counts how many tiers agree on anomaly
 * 3. Determines anomaly level based on severity and confidence
 * 4. Handles attack state transitions and cool-down
 *
 * Detection Logic:
 *   - Anomaly detected if 2+ tiers agree (features > threshold)
 *   - OR 1 tier agrees AND max_z >= 1.5 * threshold
 *
 * Severity Levels:
 *   - CRITICAL: 3 tiers agree, max_z >= 12.0
 *   - HIGH:     3 tiers agree, max_z >= 9.0, OR 2 tiers and max_z >= 15.0
 *   - MEDIUM:   3 tiers agree, max_z >= 6.0, OR 2 tiers and max_z >= 10.0
 *   - LOW:      Otherwise when detected
 */

// ==================== Anomaly Levels ====================

/**
 * Anomaly severity levels
 * Must match ANOMALY_LEVEL_* in shared_memory.h
 */
enum l2_anomaly_level {
    L2_ANOMALY_NONE = 0,
    L2_ANOMALY_LOW = 1,
    L2_ANOMALY_MEDIUM = 2,
    L2_ANOMALY_HIGH = 3,
    L2_ANOMALY_CRITICAL = 4
};

/**
 * Get string name for anomaly level
 */
const char *l2_anomaly_level_name(enum l2_anomaly_level level);

// ==================== Detection Result ====================

/**
 * MF4 FIX: Per-feature anomaly info for multi-vector reporting
 */
struct feature_anomaly_info {
    int feature_idx;                    // Feature index
    const char *feature_name;           // Feature name
    double z_score;                     // Z-score for this feature
    double value;                       // Raw value
    bool triggered;                     // Whether it exceeded threshold
};

/**
 * Result of a single detection cycle
 */
struct detection_result {
    // Detection outcome
    bool detected;                      // True if anomaly detected
    enum l2_anomaly_level level;        // Severity level
    bool level_changed;                 // True if level changed from previous

    // Multi-tier analysis
    int tier_agreement;                 // Number of tiers that agree (0-3)
    bool tier1_triggered;               // Tier 1 (immediate) triggered
    bool tier2_triggered;               // Tier 2 (hourly) triggered
    bool tier3_triggered;               // Tier 3 (weekly) triggered

    // Z-score details
    double max_z_score;                 // Maximum Z-score across all tiers
    int primary_feature_idx;            // Feature with highest Z-score
    const char *primary_feature_name;   // Name of primary feature

    // Confidence
    double confidence;                  // 0.0 - 1.0 confidence score

    // Per-tier Z-scores (for detailed analysis)
    struct tier_z_scores z_tier1;
    struct tier_z_scores z_tier2;
    struct tier_z_scores z_tier3;

    // MF4 FIX: Per-feature anomaly reporting for multi-vector attacks
    int triggered_feature_count;        // Number of features that triggered
    struct feature_anomaly_info triggered_features[8];  // Top 8 triggered features
    uint32_t triggered_feature_mask;    // Bitmask of triggered features

    // Timestamp
    uint64_t timestamp_ns;
};

// ==================== Anomaly State ====================

/**
 * Current anomaly state machine
 */
struct l2_anomaly_state {
    // Current state
    volatile bool active;               // True if anomaly is active
    enum l2_anomaly_level level;        // Current severity level
    enum l2_anomaly_level previous_level; // Previous level (for change detection)

    // Timing
    uint64_t start_time_ns;             // When anomaly was first detected
    uint64_t last_update_ns;            // Last state update time
    double duration_sec;                // Current attack duration
    double cool_down_remaining_sec;     // Cool-down seconds remaining

    // Detection details
    int tier_agreement;                 // How many tiers agree
    double max_z_score;                 // Current max Z-score
    int primary_feature_idx;            // Primary feature index
    double confidence;                  // Detection confidence

    // Statistics
    uint64_t detection_count;           // Total detections (lifetime)
    uint64_t cycle_count;               // Total detection cycles
    uint64_t false_positive_corrections; // Cool-down prevented false triggers

    // Attack frequency tracking (for E6: cool-down abuse prevention)
    uint32_t recent_attack_count;       // Attacks in last N minutes
    uint64_t attack_window_start_ns;    // Start of attack counting window
    uint64_t last_attack_end_ns;        // When last attack ended

    // De-escalation tracking (for D2: gradual severity reduction)
    uint32_t cycles_at_current_level;   // How long at current severity
    double peak_z_score;                // Peak Z-score during this attack

    // Cool-down trigger tracking (for stuck anomaly fix)
    uint32_t low_traffic_cycles;        // Consecutive cycles with low traffic
    double peak_pps;                    // Peak packets per second during attack
    double current_pps;                 // Current packets per second (for comparison)

    // Temporal persistence (operating-point FPR reduction): require K consecutive detections
    // before the Normal->Attack transition. Transient benign bursts clear before K; sustained
    // attacks survive (at the cost of up to K-1 cycles of latency). Matches the offline debounce
    // rule (experiment/, section6.10) exactly -- no severity bypass.
    uint32_t consecutive_detect;        // Consecutive raw-detected cycles (reset on clear)
    uint32_t persistence_windows;       // K (1 = no gate; set 3 in production)
} __attribute__((aligned(64)));

// ==================== Detection API ====================

/**
 * Initialize anomaly state
 */
void l2_anomaly_state_init(struct l2_anomaly_state *state);

/**
 * Run a detection cycle
 *
 * This is the main detection function called once per second (1 Hz).
 * It analyzes Z-scores from all three tiers and determines if an
 * anomaly should be triggered.
 *
 * @param baselines Three-tier baseline system
 * @param snapshot Current feature values
 * @param threshold Z-score threshold (default: 6.0)
 * @param min_tier_agreement Minimum tiers that must agree (default: 2)
 * @param result Output: detection result
 */
void l2_detect_anomaly(const struct three_tier_baseline *baselines,
                       const struct l2_feature_snapshot *snapshot,
                       double threshold,
                       int min_tier_agreement,
                       struct detection_result *result);

/* Multi-window immediate-tier signals (1s/10s/60s; window_stats pps_variance / pps_trend_slope)
 * are consumed through the calibrated conformal path (conformal_combine.{c,h}), not a fixed-
 * threshold rule. A std_10s > k*mean rule is a coefficient-of-variation test that fires on bursty-
 * benign hosts (paper section6.8, [34]); the prior l2_detect_window_signals() fixed-k helper was removed
 * to prevent that uncalibrated path from entering the ensemble. */

/**
 * Update anomaly state based on detection result
 *
 * Handles state transitions:
 * - Normal -> Attack: Start tracking, freeze baselines
 * - Attack -> Attack: Update severity if higher
 * - Attack -> Cool-down: Start cool-down timer (traffic-based)
 * - Cool-down -> Normal: Clear attack state
 *
 * Traffic-based cool-down: When attack is active but current traffic
 * drops significantly below peak attack traffic (< 30% of peak for
 * 3+ consecutive cycles), cool-down is triggered even if z-scores
 * remain high due to frozen baselines.
 *
 * @param state Anomaly state to update
 * @param result Detection result from l2_detect_anomaly()
 * @param snapshot Current feature snapshot (for traffic comparison)
 * @param cool_down_seconds Cool-down period after anomaly clears
 * @return True if state changed (for logging)
 */
bool l2_update_anomaly_state(struct l2_anomaly_state *state,
                             const struct detection_result *result,
                             const struct l2_feature_snapshot *snapshot,
                             double cool_down_seconds);

/**
 * Compute anomaly level from Z-score and tier agreement
 *
 * @param max_z Maximum Z-score
 * @param tier_agreement Number of tiers that agree (1-3)
 * @return Anomaly level
 */
enum l2_anomaly_level l2_compute_anomaly_level(double max_z, int tier_agreement);

/**
 * Compute confidence score from detection result
 *
 * @param max_z Maximum Z-score
 * @param tier_agreement Number of tiers that agree
 * @param threshold Z-score threshold
 * @return Confidence score (0.0 - 1.0)
 */
double l2_compute_confidence(double max_z, int tier_agreement, double threshold);

// ==================== State Queries ====================

/**
 * Check if anomaly is currently active
 */
bool l2_is_anomaly_active(const struct l2_anomaly_state *state);

/**
 * Get current anomaly level
 */
enum l2_anomaly_level l2_get_anomaly_level(const struct l2_anomaly_state *state);

/**
 * Get attack duration in seconds
 */
double l2_get_attack_duration(const struct l2_anomaly_state *state);

/**
 * Get rate limit percentage for current anomaly level
 * Returns: 100 (normal), 80 (low), 50 (medium), 25 (high), 10 (critical)
 */
uint32_t l2_get_rate_limit_pct(enum l2_anomaly_level level);

// ==================== Manual Control ====================

/**
 * Force anomaly state (for testing or manual override)
 */
void l2_force_anomaly(struct l2_anomaly_state *state, enum l2_anomaly_level level);

/**
 * Clear anomaly state (manual reset)
 */
void l2_clear_anomaly(struct l2_anomaly_state *state);

// ==================== Logging ====================

/**
 * Log detection result (if detection occurred)
 */
void l2_log_detection(const struct detection_result *result);

/**
 * Log anomaly state change
 */
void l2_log_state_change(const struct l2_anomaly_state *state,
                         enum l2_anomaly_level old_level,
                         enum l2_anomaly_level new_level);

/**
 * Log periodic status summary
 */
void l2_log_status(const struct l2_anomaly_state *state,
                   const struct baseline_summary *baseline_summary);

#endif // LAYER2_DETECTION_H
