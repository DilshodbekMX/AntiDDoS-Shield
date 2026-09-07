#include "fast_detection.h"
#include "config/layer2_config.h"
#include "baselines.h"  // For get_current_time_ns()

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// ==================== Constants ====================

#define FAST_EWMA_ALPHA 0.3  // Fast adaptation for 100ms samples

// ==================== Helper Functions ====================

static int compare_uint64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

/**
 * Calculate percentile from array (modifies array via qsort)
 */
static uint64_t calculate_percentile(uint64_t *values, uint32_t count, uint32_t percentile) {
    if (count == 0) return 0;
    if (count == 1) return values[0];

    // Sort values
    qsort(values, count, sizeof(uint64_t), compare_uint64);

    // Calculate index for percentile
    uint32_t idx = (count * percentile) / 100;
    if (idx >= count) idx = count - 1;

    return values[idx];
}

// ==================== Initialization ====================

void fast_detection_init(struct fast_detection_state *state) {
    if (!state) return;

    memset(state, 0, sizeof(*state));

    // Load configuration
    fast_detection_update_config(state);

    // Initialize state
    state->sample_idx = 0;
    state->sample_count = 0;
    state->consecutive_detections = 0;
    state->spike_active = false;
    state->warmup_idx = 0;

    // Initialize adaptive thresholds to config defaults
    const struct layer2_config *cfg = layer2_config_get();
    state->adaptive_pps_threshold = cfg->fast_min_pps_spike;
    state->adaptive_syn_threshold = cfg->fast_syn_spike_threshold;

    printf("[FastDet] Initialized (interval=%ums, multiplier=%.1fx, min_pps=%lu)\n",
           state->interval_ms, state->threshold_multiplier,
           (unsigned long)state->min_pps_spike);
}

void fast_detection_reset(struct fast_detection_state *state) {
    if (!state) return;

    // Preserve config
    bool enabled = state->enabled;
    uint32_t interval_ms = state->interval_ms;
    double threshold_multiplier = state->threshold_multiplier;
    uint64_t min_pps_spike = state->min_pps_spike;
    uint64_t syn_spike_threshold = state->syn_spike_threshold;
    uint32_t consecutive_required = state->consecutive_required;

    // Clear everything
    memset(state, 0, sizeof(*state));

    // Restore config
    state->enabled = enabled;
    state->interval_ms = interval_ms;
    state->threshold_multiplier = threshold_multiplier;
    state->min_pps_spike = min_pps_spike;
    state->syn_spike_threshold = syn_spike_threshold;
    state->consecutive_required = consecutive_required;
    state->adaptive_pps_threshold = min_pps_spike;
    state->adaptive_syn_threshold = syn_spike_threshold;
}

void fast_detection_update_config(struct fast_detection_state *state) {
    if (!state) return;

    const struct layer2_config *cfg = layer2_config_get();

    state->enabled = cfg->fast_detection_enabled;
    state->interval_ms = cfg->fast_detection_interval_ms;
    state->threshold_multiplier = cfg->fast_threshold_multiplier;
    state->min_pps_spike = cfg->fast_min_pps_spike;
    state->syn_spike_threshold = cfg->fast_syn_spike_threshold;
    state->consecutive_required = cfg->fast_consecutive_required;

    // Update adaptive thresholds if not yet warmed up
    if (!state->stats.warmup_complete) {
        state->adaptive_pps_threshold = state->min_pps_spike;
        state->adaptive_syn_threshold = state->syn_spike_threshold;
    }
}

// ==================== Core Detection ====================

bool fast_detection_process(struct fast_detection_state *state,
                            const struct fast_sample *sample,
                            struct fast_detection_result *result) {
    if (!state || !sample || !result) return false;

    memset(result, 0, sizeof(*result));
    result->timestamp_ns = sample->timestamp_ns;

    if (!state->enabled) {
        return false;
    }

    // Store sample in rolling window
    state->samples[state->sample_idx] = *sample;
    state->sample_idx = (state->sample_idx + 1) % FAST_WINDOW_SIZE;
    if (state->sample_count < FAST_WINDOW_SIZE) {
        state->sample_count++;
    }
    state->total_samples++;
    state->last_sample_ns = sample->timestamp_ns;

    // Calculate rates from sample
    // Assuming sample contains counts for the 100ms interval
    uint64_t pps = sample->packets * 10;  // Scale to per-second
    uint64_t syn_pps = sample->syn_packets * 10;
    uint64_t new_flow_rate = sample->new_flows * 10;

    // Warmup: collect samples to establish baseline
    if (!state->stats.warmup_complete) {
        if (state->warmup_idx < FAST_WARMUP_SAMPLES) {
            state->warmup_pps_values[state->warmup_idx] = pps;
            state->warmup_syn_values[state->warmup_idx] = syn_pps;
            state->warmup_idx++;
        }

        if (state->warmup_idx >= FAST_WARMUP_SAMPLES) {
            // Calculate adaptive thresholds using percentile method
            const struct layer2_config *cfg = layer2_config_get();

            if (cfg->adaptive_warmup_enabled) {
                // Use spike_factor * 95th percentile as threshold
                uint64_t p95_pps = calculate_percentile(
                    state->warmup_pps_values, FAST_WARMUP_SAMPLES,
                    cfg->warmup_percentile_threshold);
                uint64_t p95_syn = calculate_percentile(
                    state->warmup_syn_values, FAST_WARMUP_SAMPLES,
                    cfg->warmup_percentile_threshold);

                state->adaptive_pps_threshold = (uint64_t)(p95_pps * cfg->warmup_spike_factor);
                state->adaptive_syn_threshold = (uint64_t)(p95_syn * cfg->warmup_spike_factor);

                // Ensure minimums
                if (state->adaptive_pps_threshold < state->min_pps_spike) {
                    state->adaptive_pps_threshold = state->min_pps_spike;
                }
                if (state->adaptive_syn_threshold < state->syn_spike_threshold / 2) {
                    state->adaptive_syn_threshold = state->syn_spike_threshold / 2;
                }

                printf("[FastDet] Adaptive warmup complete: pps_threshold=%lu, syn_threshold=%lu\n",
                       (unsigned long)state->adaptive_pps_threshold,
                       (unsigned long)state->adaptive_syn_threshold);
            }

            state->stats.warmup_complete = true;
        }

        // During warmup, still apply absolute thresholds
        // This catches obvious attacks even during warmup
        if (pps > state->min_pps_spike * 2 || syn_pps > state->syn_spike_threshold * 2) {
            result->spike_detected = true;
            result->pps_spike = (pps > state->min_pps_spike * 2);
            result->syn_spike = (syn_pps > state->syn_spike_threshold * 2);
            state->spikes_detected++;
        }
    }

    // Update rolling statistics (EWMA)
    if (state->stats.sample_count == 0) {
        // First sample - initialize
        state->stats.avg_pps = (double)pps;
        state->stats.avg_syn_pps = (double)syn_pps;
        state->stats.avg_new_flow_rate = (double)new_flow_rate;
    } else {
        // EWMA update
        state->stats.avg_pps = FAST_EWMA_ALPHA * pps +
                               (1.0 - FAST_EWMA_ALPHA) * state->stats.avg_pps;
        state->stats.avg_syn_pps = FAST_EWMA_ALPHA * syn_pps +
                                   (1.0 - FAST_EWMA_ALPHA) * state->stats.avg_syn_pps;
        state->stats.avg_new_flow_rate = FAST_EWMA_ALPHA * new_flow_rate +
                                         (1.0 - FAST_EWMA_ALPHA) * state->stats.avg_new_flow_rate;
    }
    state->stats.sample_count++;

    // Track peaks
    if (pps > state->stats.peak_pps) {
        state->stats.peak_pps = pps;
    }
    if (syn_pps > state->stats.peak_syn_pps) {
        state->stats.peak_syn_pps = syn_pps;
    }

    // Fill result with current values
    result->current_pps = pps;
    result->current_syn_pps = syn_pps;
    result->baseline_pps = (uint64_t)state->stats.avg_pps;
    result->baseline_syn_pps = (uint64_t)state->stats.avg_syn_pps;

    // Calculate ratios
    if (state->stats.avg_pps > 0) {
        result->spike_ratio = (double)pps / state->stats.avg_pps;
    }
    if (state->stats.avg_syn_pps > 0) {
        result->syn_spike_ratio = (double)syn_pps / state->stats.avg_syn_pps;
    }

    // Skip detection if still warming up
    if (!state->stats.warmup_complete) {
        return result->spike_detected;
    }

    // ==================== Spike Detection ====================

    bool pps_spike = false;
    bool syn_spike = false;
    bool flow_spike = false;

    // Method 1: Relative spike (vs baseline)
    if (state->stats.avg_pps > 100) {  // Only if baseline is meaningful
        if ((double)pps > state->stats.avg_pps * state->threshold_multiplier) {
            pps_spike = true;
        }
    }

    // Method 2: Absolute spike (adaptive threshold)
    if (pps > state->adaptive_pps_threshold) {
        pps_spike = true;
    }

    // Method 3: SYN spike detection
    if (syn_pps > state->adaptive_syn_threshold) {
        syn_spike = true;
    }
    if (state->stats.avg_syn_pps > 10) {
        if ((double)syn_pps > state->stats.avg_syn_pps * state->threshold_multiplier * 1.5) {
            syn_spike = true;
        }
    }

    // Method 4: New flow spike (rapid connection creation)
    if (state->stats.avg_new_flow_rate > 10) {
        if ((double)new_flow_rate > state->stats.avg_new_flow_rate * state->threshold_multiplier * 2.0) {
            flow_spike = true;
        }
    }

    // Spike detected if any method triggered
    result->spike_detected = pps_spike || syn_spike || flow_spike;
    result->pps_spike = pps_spike;
    result->syn_spike = syn_spike;
    result->flow_spike = flow_spike;

    // ==================== Consecutive Spike Tracking ====================

    if (result->spike_detected) {
        state->spikes_detected++;

        if (!state->spike_active) {
            // Start of new spike
            state->spike_active = true;
            state->spike_start_ns = sample->timestamp_ns;
            state->consecutive_detections = 1;
        } else {
            // Continuing spike
            state->consecutive_detections++;
        }

        // Calculate spike duration
        result->spike_duration_ms = (sample->timestamp_ns - state->spike_start_ns) / 1000000;

        // Check if confirmed (enough consecutive spikes)
        if (state->consecutive_detections >= state->consecutive_required) {
            result->attack_confirmed = true;
            result->consecutive_count = state->consecutive_detections;

            // Only count as new confirmed attack on first confirmation
            if (state->consecutive_detections == state->consecutive_required) {
                state->confirmed_attacks++;
                state->last_detection_ns = sample->timestamp_ns;

                printf("[FastDet] ATTACK CONFIRMED: %u consecutive spikes "
                       "(pps=%lu, syn=%lu, baseline_pps=%.0f)\n",
                       state->consecutive_detections,
                       (unsigned long)pps, (unsigned long)syn_pps,
                       state->stats.avg_pps);
            }
        }
    } else {
        // No spike this sample
        if (state->spike_active) {
            // Spike ended
            if (state->consecutive_detections > 0 &&
                state->consecutive_detections < state->consecutive_required) {
                // Spike didn't confirm - likely false positive
                state->false_positives++;
            }
            state->spike_active = false;
            state->consecutive_detections = 0;
        }
    }

    result->consecutive_count = state->consecutive_detections;
    return result->attack_confirmed;
}

// ==================== Statistics ====================

void fast_detection_get_stats(const struct fast_detection_state *state,
                              uint64_t *total_samples,
                              uint64_t *spikes_detected,
                              uint64_t *attacks_confirmed) {
    if (!state) return;

    if (total_samples) *total_samples = state->total_samples;
    if (spikes_detected) *spikes_detected = state->spikes_detected;
    if (attacks_confirmed) *attacks_confirmed = state->confirmed_attacks;
}

bool fast_detection_is_warmup(const struct fast_detection_state *state) {
    if (!state) return true;
    return !state->stats.warmup_complete;
}

uint64_t fast_detection_get_adaptive_threshold(const struct fast_detection_state *state) {
    if (!state) return 0;
    return state->adaptive_pps_threshold;
}

void fast_detection_acknowledge_attack(struct fast_detection_state *state) {
    if (!state) return;

    // Reset consecutive counter and spike state
    // This is called when Layer 2 main detection handles an attack
    state->spike_active = false;
    state->consecutive_detections = 0;
}
