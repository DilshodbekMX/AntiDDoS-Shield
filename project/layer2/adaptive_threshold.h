#ifndef LAYER2_ADAPTIVE_THRESHOLD_H
#define LAYER2_ADAPTIVE_THRESHOLD_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @file adaptive_threshold.h
 * @brief Adaptive Threshold Tuning for DDoS Detection
 *
 * MF2 FIX: Implements automatic threshold adjustment based on:
 * - False positive rate (detections that were quickly cleared)
 * - True positive rate (sustained attacks)
 * - Time-of-day patterns
 *
 * Algorithm:
 * - Track detection outcomes over sliding window
 * - If FP rate too high: increase threshold
 * - If TP rate low with sustained anomalies: decrease threshold
 * - Bounded adjustments to prevent runaway tuning
 *
 * Key metrics:
 * - FP = detection cleared in < 10 seconds (likely false positive)
 * - TP = detection sustained > 30 seconds (likely true positive)
 * - Adjustment step = 0.5 Z-score units
 * - Min threshold = 4.0, Max threshold = 10.0
 */

// ==================== Configuration ====================

#define L2_ADAPTIVE_WINDOW_SIZE      60      // Track last 60 detection events
#define L2_ADAPTIVE_MIN_THRESHOLD    4.0     // Never go below 4.0 Z-score
#define L2_ADAPTIVE_MAX_THRESHOLD    10.0    // Never go above 10.0 Z-score
#define L2_ADAPTIVE_STEP             0.25    // Adjustment step size
#define L2_ADAPTIVE_FP_THRESHOLD     0.30    // If >30% FP, increase threshold
#define L2_ADAPTIVE_TP_MIN           0.50    // If <50% TP, maybe too sensitive
#define L2_ADAPTIVE_EVAL_INTERVAL_S  300     // Evaluate every 5 minutes
#define L2_ADAPTIVE_MIN_SAMPLES      10      // Need at least 10 events to evaluate

#define L2_FP_DURATION_THRESHOLD_S   10.0    // Detection < 10s = likely FP
#define L2_TP_DURATION_THRESHOLD_S   30.0    // Detection > 30s = likely TP

// ==================== Structures ====================

/**
 * Single detection event for tracking
 */
struct detection_event {
    uint64_t start_time_ns;         // When detection started
    uint64_t end_time_ns;           // When detection ended (0 if ongoing)
    double duration_sec;            // Duration in seconds
    double max_z_score;             // Peak Z-score
    int tier_agreement;             // Peak tier agreement
    bool is_false_positive;         // Classified as FP (short duration)
    bool is_true_positive;          // Classified as TP (sustained)
    bool is_ongoing;                // Still active
};

/**
 * Adaptive threshold state
 */
struct adaptive_threshold_state {
    // Current threshold
    double current_threshold;       // Current Z-score threshold
    double initial_threshold;       // Starting threshold (for reset)

    // Event tracking (circular buffer)
    struct detection_event events[L2_ADAPTIVE_WINDOW_SIZE];
    int event_head;                 // Next write position
    int event_count;                // Total events in buffer

    // Statistics
    uint32_t total_detections;      // Lifetime detection count
    uint32_t total_false_positives; // Lifetime FP count
    uint32_t total_true_positives;  // Lifetime TP count

    // Current window stats
    uint32_t window_detections;     // Detections in current window
    uint32_t window_fp;             // FP in current window
    uint32_t window_tp;             // TP in current window
    double window_fp_rate;          // Current FP rate
    double window_tp_rate;          // Current TP rate

    // Timing
    uint64_t last_eval_time_ns;     // Last evaluation time
    uint64_t last_adjustment_ns;    // Last threshold change

    // Adjustment history
    int adjustments_up;             // Times threshold increased
    int adjustments_down;           // Times threshold decreased
    double adjustment_total;        // Net adjustment from initial

    // Enabled state
    bool enabled;                   // Adaptive tuning enabled
    bool frozen;                    // Temporarily frozen (manual override)
} __attribute__((aligned(64)));

// ==================== API ====================

/**
 * Initialize adaptive threshold state
 * @param state State to initialize
 * @param initial_threshold Starting threshold (e.g., 6.0)
 */
void l2_adaptive_init(struct adaptive_threshold_state *state,
                      double initial_threshold);

/**
 * Record a detection event starting
 * Call when anomaly state transitions to active
 *
 * @param state Adaptive state
 * @param timestamp_ns Current time
 * @param max_z Initial Z-score
 * @param tier_agreement Initial tier agreement
 */
void l2_adaptive_detection_start(struct adaptive_threshold_state *state,
                                  uint64_t timestamp_ns,
                                  double max_z,
                                  int tier_agreement);

/**
 * Record a detection event ending
 * Call when anomaly state transitions to inactive
 *
 * @param state Adaptive state
 * @param timestamp_ns Current time
 * @param duration_sec Total detection duration
 * @param peak_z Peak Z-score during detection
 * @param peak_tiers Peak tier agreement
 */
void l2_adaptive_detection_end(struct adaptive_threshold_state *state,
                                uint64_t timestamp_ns,
                                double duration_sec,
                                double peak_z,
                                int peak_tiers);

/**
 * Periodic evaluation - adjusts threshold if needed
 * Call periodically (e.g., every minute)
 *
 * @param state Adaptive state
 * @param now_ns Current time
 * @return New threshold (may be unchanged)
 */
double l2_adaptive_evaluate(struct adaptive_threshold_state *state,
                            uint64_t now_ns);

/**
 * Get current threshold
 */
double l2_adaptive_get_threshold(const struct adaptive_threshold_state *state);

/**
 * Set threshold manually (overrides adaptive tuning temporarily)
 */
void l2_adaptive_set_threshold(struct adaptive_threshold_state *state,
                               double threshold);

/**
 * Enable/disable adaptive tuning
 */
void l2_adaptive_set_enabled(struct adaptive_threshold_state *state, bool enabled);

/**
 * Freeze/unfreeze adaptive tuning (manual override)
 */
void l2_adaptive_freeze(struct adaptive_threshold_state *state, bool freeze);

/**
 * Reset to initial threshold
 */
void l2_adaptive_reset(struct adaptive_threshold_state *state);

/**
 * Get adaptive threshold statistics
 */
void l2_adaptive_get_stats(const struct adaptive_threshold_state *state,
                           double *current_threshold,
                           double *fp_rate,
                           double *tp_rate,
                           int *adjustments);

/**
 * Log adaptive threshold status
 */
void l2_adaptive_log_status(const struct adaptive_threshold_state *state);

#endif // LAYER2_ADAPTIVE_THRESHOLD_H
