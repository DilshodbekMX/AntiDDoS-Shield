#ifndef LAYER2_FAST_DETECTION_H
#define LAYER2_FAST_DETECTION_H

/**
 * @file fast_detection.h
 * @brief Fast Detection Tier (100ms) for Pulse Attack Detection
 *
 * The fast detection tier runs at 100ms intervals to catch sub-second
 * pulse attacks that evade the standard 1Hz detection cycle.
 *
 * Key features:
 * - 100ms sampling interval (10x faster than standard detection)
 * - Simple threshold-based detection (no Z-score computation)
 * - Rolling window for spike detection
 * - Adaptive thresholds during warmup
 *
 * Detection triggers:
 * - PPS spike > fast_threshold_multiplier * baseline
 * - SYN rate spike > fast_syn_spike_threshold
 * - Consecutive spike detection for confirmation
 */

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==================== Constants ====================

#define FAST_WINDOW_SIZE       10    // 10 samples = 1 second history at 100ms
#define FAST_WARMUP_SAMPLES    30    // 3 seconds to establish baseline

// ==================== Structures ====================

/**
 * Fast detection sample (one 100ms window)
 */
struct fast_sample {
    uint64_t timestamp_ns;
    uint64_t packets;
    uint64_t bytes;
    uint64_t syn_packets;
    uint64_t new_flows;
    uint64_t unique_src_ips;    // Estimated from HLL
};

/**
 * Fast detection rolling statistics
 */
struct fast_rolling_stats {
    // Rolling averages (EWMA, alpha=0.3 for fast adaptation)
    double avg_pps;
    double avg_bps;
    double avg_syn_pps;
    double avg_new_flow_rate;

    // Peak values in current window
    uint64_t peak_pps;
    uint64_t peak_syn_pps;

    // 95th percentile estimates (for adaptive warmup)
    double p95_pps;
    double p95_syn_pps;

    // Sample count
    uint32_t sample_count;
    bool warmup_complete;
};

/**
 * Fast detection state
 */
struct fast_detection_state {
    // Configuration (cached from layer2_config)
    bool enabled;
    uint32_t interval_ms;
    double threshold_multiplier;
    uint64_t min_pps_spike;
    uint64_t syn_spike_threshold;
    uint32_t consecutive_required;

    // Rolling window of samples
    struct fast_sample samples[FAST_WINDOW_SIZE];
    uint32_t sample_idx;
    uint32_t sample_count;

    // Rolling statistics
    struct fast_rolling_stats stats;

    // Detection state
    uint32_t consecutive_detections;
    bool spike_active;
    uint64_t spike_start_ns;

    // Warmup tracking (adaptive thresholds)
    uint64_t warmup_pps_values[FAST_WARMUP_SAMPLES];
    uint64_t warmup_syn_values[FAST_WARMUP_SAMPLES];
    uint32_t warmup_idx;
    uint64_t adaptive_pps_threshold;
    uint64_t adaptive_syn_threshold;

    // Statistics
    uint64_t total_samples;
    uint64_t spikes_detected;
    uint64_t confirmed_attacks;
    uint64_t false_positives;   // Spike that didn't confirm

    // Timing
    uint64_t last_sample_ns;
    uint64_t last_detection_ns;
};

/**
 * Fast detection result
 */
struct fast_detection_result {
    bool spike_detected;        // Single sample spike
    bool attack_confirmed;      // Consecutive spikes confirmed attack
    uint32_t consecutive_count; // How many consecutive spikes

    // Spike details
    uint64_t current_pps;
    uint64_t baseline_pps;
    double spike_ratio;         // current / baseline

    uint64_t current_syn_pps;
    uint64_t baseline_syn_pps;
    double syn_spike_ratio;

    // What triggered
    bool pps_spike;
    bool syn_spike;
    bool flow_spike;

    // Timing
    uint64_t timestamp_ns;
    uint64_t spike_duration_ms;
};

// ==================== API ====================

/**
 * Initialize fast detection state
 */
void fast_detection_init(struct fast_detection_state *state);

/**
 * Reset fast detection state
 */
void fast_detection_reset(struct fast_detection_state *state);

/**
 * Update configuration from layer2_config
 */
void fast_detection_update_config(struct fast_detection_state *state);

/**
 * Process a 100ms sample
 *
 * @param state     Fast detection state
 * @param sample    Current 100ms sample
 * @param result    Output: detection result
 * @return true if attack confirmed (consecutive spikes)
 */
bool fast_detection_process(struct fast_detection_state *state,
                            const struct fast_sample *sample,
                            struct fast_detection_result *result);

/**
 * Get current fast detection statistics
 */
void fast_detection_get_stats(const struct fast_detection_state *state,
                              uint64_t *total_samples,
                              uint64_t *spikes_detected,
                              uint64_t *attacks_confirmed);

/**
 * Check if fast detection is in warmup mode
 */
bool fast_detection_is_warmup(const struct fast_detection_state *state);

/**
 * Get adaptive threshold (for monitoring)
 */
uint64_t fast_detection_get_adaptive_threshold(const struct fast_detection_state *state);

/**
 * Manual spike acknowledgment (to reset consecutive counter)
 * Call this when Layer 2 main detection handles an attack
 */
void fast_detection_acknowledge_attack(struct fast_detection_state *state);

#ifdef __cplusplus
}
#endif

#endif // LAYER2_FAST_DETECTION_H
