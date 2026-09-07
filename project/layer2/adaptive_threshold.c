#include "adaptive_threshold.h"
#include "config/layer2_config.h"
#include <string.h>
#include <stdio.h>
#include <math.h>

// Helper to get config values with fallback to header defaults
static inline double get_adaptive_min_threshold(void) {
    const struct layer2_config *cfg = layer2_config_get();
    return cfg ? cfg->adaptive_min_threshold : L2_ADAPTIVE_MIN_THRESHOLD;
}

static inline double get_adaptive_max_threshold(void) {
    const struct layer2_config *cfg = layer2_config_get();
    return cfg ? cfg->adaptive_max_threshold : L2_ADAPTIVE_MAX_THRESHOLD;
}

static inline double get_adaptive_step(void) {
    const struct layer2_config *cfg = layer2_config_get();
    return cfg ? cfg->adaptive_step : L2_ADAPTIVE_STEP;
}

static inline double get_adaptive_fp_threshold(void) {
    const struct layer2_config *cfg = layer2_config_get();
    return cfg ? cfg->adaptive_fp_threshold : L2_ADAPTIVE_FP_THRESHOLD;
}

static inline double get_adaptive_tp_min(void) {
    const struct layer2_config *cfg = layer2_config_get();
    return cfg ? cfg->adaptive_tp_min : L2_ADAPTIVE_TP_MIN;
}

static inline uint32_t get_adaptive_eval_interval_sec(void) {
    const struct layer2_config *cfg = layer2_config_get();
    return cfg ? cfg->adaptive_eval_interval_sec : L2_ADAPTIVE_EVAL_INTERVAL_S;
}

static inline uint32_t get_adaptive_min_samples(void) {
    const struct layer2_config *cfg = layer2_config_get();
    return cfg ? cfg->adaptive_min_samples : L2_ADAPTIVE_MIN_SAMPLES;
}

static inline double get_fp_duration_threshold_sec(void) {
    const struct layer2_config *cfg = layer2_config_get();
    return cfg ? cfg->fp_duration_threshold_sec : L2_FP_DURATION_THRESHOLD_S;
}

static inline double get_tp_duration_threshold_sec(void) {
    const struct layer2_config *cfg = layer2_config_get();
    return cfg ? cfg->tp_duration_threshold_sec : L2_TP_DURATION_THRESHOLD_S;
}

static inline bool get_adaptive_enabled(void) {
    const struct layer2_config *cfg = layer2_config_get();
    return cfg ? cfg->adaptive_enabled : true;
}

// ==================== Initialization ====================

void l2_adaptive_init(struct adaptive_threshold_state *state,
                      double initial_threshold) {
    if (!state) return;

    memset(state, 0, sizeof(*state));

    // Clamp initial threshold to valid range (from config)
    double min_thresh = get_adaptive_min_threshold();
    double max_thresh = get_adaptive_max_threshold();

    if (initial_threshold < min_thresh) {
        initial_threshold = min_thresh;
    }
    if (initial_threshold > max_thresh) {
        initial_threshold = max_thresh;
    }

    state->current_threshold = initial_threshold;
    state->initial_threshold = initial_threshold;
    state->enabled = get_adaptive_enabled();
    state->frozen = false;
    state->event_head = 0;
    state->event_count = 0;
}

// ==================== Event Tracking ====================

void l2_adaptive_detection_start(struct adaptive_threshold_state *state,
                                  uint64_t timestamp_ns,
                                  double max_z,
                                  int tier_agreement) {
    if (!state) return;

    // Add new event to circular buffer
    struct detection_event *event = &state->events[state->event_head];

    event->start_time_ns = timestamp_ns;
    event->end_time_ns = 0;
    event->duration_sec = 0.0;
    event->max_z_score = max_z;
    event->tier_agreement = tier_agreement;
    event->is_false_positive = false;
    event->is_true_positive = false;
    event->is_ongoing = true;

    state->event_head = (state->event_head + 1) % L2_ADAPTIVE_WINDOW_SIZE;
    if (state->event_count < L2_ADAPTIVE_WINDOW_SIZE) {
        state->event_count++;
    }

    state->total_detections++;
    state->window_detections++;
}

void l2_adaptive_detection_end(struct adaptive_threshold_state *state,
                                uint64_t timestamp_ns,
                                double duration_sec,
                                double peak_z,
                                int peak_tiers) {
    if (!state) return;

    // Find the ongoing event (should be the most recent)
    // Search backwards from head
    for (int i = 0; i < state->event_count; i++) {
        int idx = (state->event_head - 1 - i + L2_ADAPTIVE_WINDOW_SIZE) % L2_ADAPTIVE_WINDOW_SIZE;
        struct detection_event *event = &state->events[idx];

        if (event->is_ongoing) {
            event->end_time_ns = timestamp_ns;
            event->duration_sec = duration_sec;
            event->is_ongoing = false;

            // Update peak values
            if (peak_z > event->max_z_score) {
                event->max_z_score = peak_z;
            }
            if (peak_tiers > event->tier_agreement) {
                event->tier_agreement = peak_tiers;
            }

            // Classify as FP or TP (thresholds from config)
            double fp_thresh = get_fp_duration_threshold_sec();
            double tp_thresh = get_tp_duration_threshold_sec();

            if (duration_sec < fp_thresh) {
                event->is_false_positive = true;
                state->total_false_positives++;
                state->window_fp++;
            } else if (duration_sec >= tp_thresh) {
                event->is_true_positive = true;
                state->total_true_positives++;
                state->window_tp++;
            }
            // Else: ambiguous, not counted as either

            break;
        }
    }
}

// ==================== Threshold Evaluation ====================

static void update_window_stats(struct adaptive_threshold_state *state) {
    // Recalculate window statistics from events
    state->window_detections = 0;
    state->window_fp = 0;
    state->window_tp = 0;

    for (int i = 0; i < state->event_count; i++) {
        struct detection_event *event = &state->events[i];
        if (!event->is_ongoing) {
            state->window_detections++;
            if (event->is_false_positive) {
                state->window_fp++;
            }
            if (event->is_true_positive) {
                state->window_tp++;
            }
        }
    }

    // Calculate rates
    if (state->window_detections > 0) {
        state->window_fp_rate = (double)state->window_fp / state->window_detections;
        state->window_tp_rate = (double)state->window_tp / state->window_detections;
    } else {
        state->window_fp_rate = 0.0;
        state->window_tp_rate = 0.0;
    }
}

double l2_adaptive_evaluate(struct adaptive_threshold_state *state,
                            uint64_t now_ns) {
    // Check config-based enabled state as well as instance state
    if (!state || !state->enabled || state->frozen || !get_adaptive_enabled()) {
        return state ? state->current_threshold : 6.0;
    }

    // Check if enough time has passed since last evaluation (from config)
    uint32_t eval_interval = get_adaptive_eval_interval_sec();
    uint64_t interval_ns = (uint64_t)eval_interval * 1000000000ULL;
    if (now_ns - state->last_eval_time_ns < interval_ns) {
        return state->current_threshold;
    }

    state->last_eval_time_ns = now_ns;

    // Update statistics
    update_window_stats(state);

    // Need minimum samples to make decisions (from config)
    uint32_t min_samples = get_adaptive_min_samples();
    if (state->window_detections < min_samples) {
        return state->current_threshold;
    }

    double old_threshold = state->current_threshold;
    bool adjusted = false;

    // Get config values
    double fp_threshold = get_adaptive_fp_threshold();
    double tp_min = get_adaptive_tp_min();
    double step = get_adaptive_step();
    double min_thresh = get_adaptive_min_threshold();
    double max_thresh = get_adaptive_max_threshold();

    // Decision logic:
    // 1. If FP rate too high -> increase threshold (less sensitive)
    // 2. If FP rate very low AND we haven't detected much -> maybe decrease threshold
    // 3. Otherwise, stay the same

    if (state->window_fp_rate > fp_threshold) {
        // Too many false positives - increase threshold
        double increase = step;

        // Scale by how bad the FP rate is
        if (state->window_fp_rate > 0.5) {
            increase *= 2.0;  // Double step for very high FP
        }

        state->current_threshold += increase;
        if (state->current_threshold > max_thresh) {
            state->current_threshold = max_thresh;
        }

        state->adjustments_up++;
        adjusted = true;

    } else if (state->window_fp_rate < 0.1 && state->window_tp_rate > tp_min + 0.2) {
        // Very low FP rate with high TP rate - system is working well
        // We could try being more sensitive, but only if threshold is above default

        if (state->current_threshold > state->initial_threshold) {
            // Slowly reduce back towards initial
            state->current_threshold -= step * 0.5;
            if (state->current_threshold < state->initial_threshold) {
                state->current_threshold = state->initial_threshold;
            }
            state->adjustments_down++;
            adjusted = true;
        }
    }

    // Enforce bounds (from config)
    if (state->current_threshold < min_thresh) {
        state->current_threshold = min_thresh;
    }
    if (state->current_threshold > max_thresh) {
        state->current_threshold = max_thresh;
    }

    if (adjusted) {
        state->last_adjustment_ns = now_ns;
        state->adjustment_total = state->current_threshold - state->initial_threshold;

        printf("[Layer2] Adaptive threshold: %.2f -> %.2f (FP rate: %.1f%%, TP rate: %.1f%%)\n",
               old_threshold, state->current_threshold,
               state->window_fp_rate * 100.0, state->window_tp_rate * 100.0);
    }

    return state->current_threshold;
}

// ==================== Accessors ====================

double l2_adaptive_get_threshold(const struct adaptive_threshold_state *state) {
    return state ? state->current_threshold : 6.0;
}

void l2_adaptive_set_threshold(struct adaptive_threshold_state *state,
                               double threshold) {
    if (!state) return;

    // Clamp to valid range (from config)
    double min_thresh = get_adaptive_min_threshold();
    double max_thresh = get_adaptive_max_threshold();

    if (threshold < min_thresh) {
        threshold = min_thresh;
    }
    if (threshold > max_thresh) {
        threshold = max_thresh;
    }

    state->current_threshold = threshold;
    state->frozen = true;  // Manual set freezes adaptive tuning
}

void l2_adaptive_set_enabled(struct adaptive_threshold_state *state, bool enabled) {
    if (state) {
        state->enabled = enabled;
    }
}

void l2_adaptive_freeze(struct adaptive_threshold_state *state, bool freeze) {
    if (state) {
        state->frozen = freeze;
    }
}

void l2_adaptive_reset(struct adaptive_threshold_state *state) {
    if (!state) return;

    double initial = state->initial_threshold;
    l2_adaptive_init(state, initial);
}

void l2_adaptive_get_stats(const struct adaptive_threshold_state *state,
                           double *current_threshold,
                           double *fp_rate,
                           double *tp_rate,
                           int *adjustments) {
    if (!state) return;

    if (current_threshold) *current_threshold = state->current_threshold;
    if (fp_rate) *fp_rate = state->window_fp_rate;
    if (tp_rate) *tp_rate = state->window_tp_rate;
    if (adjustments) *adjustments = state->adjustments_up + state->adjustments_down;
}

void l2_adaptive_log_status(const struct adaptive_threshold_state *state) {
    if (!state) return;

    printf("[Layer2] Adaptive Threshold Status:\n");
    printf("[Layer2]   Current threshold: %.2f (initial: %.2f, change: %+.2f)\n",
           state->current_threshold, state->initial_threshold, state->adjustment_total);
    printf("[Layer2]   Window stats: %u detections, %.1f%% FP, %.1f%% TP\n",
           state->window_detections,
           state->window_fp_rate * 100.0,
           state->window_tp_rate * 100.0);
    printf("[Layer2]   Lifetime: %u detections, %u FP, %u TP\n",
           state->total_detections, state->total_false_positives, state->total_true_positives);
    printf("[Layer2]   Adjustments: %d up, %d down\n",
           state->adjustments_up, state->adjustments_down);
    printf("[Layer2]   Status: %s%s\n",
           state->enabled ? "enabled" : "disabled",
           state->frozen ? " (frozen)" : "");
}
