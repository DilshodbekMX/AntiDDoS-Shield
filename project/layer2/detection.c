#include "detection.h"
#include "config/layer2_config.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>

// ==================== Level Names ====================

static const char *level_names[] = {
    [L2_ANOMALY_NONE]     = "NONE",
    [L2_ANOMALY_LOW]      = "LOW",
    [L2_ANOMALY_MEDIUM]   = "MEDIUM",
    [L2_ANOMALY_HIGH]     = "HIGH",
    [L2_ANOMALY_CRITICAL] = "CRITICAL"
};

const char *l2_anomaly_level_name(enum l2_anomaly_level level) {
    if (level > L2_ANOMALY_CRITICAL) {
        return "UNKNOWN";
    }
    return level_names[level];
}

// ==================== Helper Functions ====================
// P2 FIX: get_current_time_ns() now in baselines.h as inline

// ==================== Initialization ====================

void l2_anomaly_state_init(struct l2_anomaly_state *state) {
    if (!state) return;

    memset(state, 0, sizeof(*state));
    state->active = false;
    state->level = L2_ANOMALY_NONE;
    state->previous_level = L2_ANOMALY_NONE;
    state->primary_feature_idx = -1;
    state->consecutive_detect = 0;
    state->persistence_windows = 1;   // default: no gate; production sets 3 (see layer2.c)
}

// ==================== Core Detection ====================

void l2_detect_anomaly(const struct three_tier_baseline *baselines,
                       const struct l2_feature_snapshot *snapshot,
                       double threshold,
                       int min_tier_agreement,
                       struct detection_result *result) {
    if (!baselines || !snapshot || !result) return;

    memset(result, 0, sizeof(*result));
    result->timestamp_ns = snapshot->timestamp_ns;
    if (result->timestamp_ns == 0) {
        result->timestamp_ns = get_current_time_ns();
    }

    // Get current baselines for each tier
    const struct tier_baseline *t1 = &baselines->immediate;
    const struct tier_baseline *t2 = NULL;
    const struct tier_baseline *t3 = NULL;

    // Get current hourly and weekly (need to cast away const temporarily)
    int hour_idx = get_current_hour_index();
    int week_idx = get_current_weekly_index();
    t2 = &baselines->hourly[hour_idx];
    t3 = &baselines->weekly[week_idx];

    // Calculate Z-scores for each tier
    tier_baseline_z_scores(t1, snapshot, threshold, &result->z_tier1);
    tier_baseline_z_scores(t2, snapshot, threshold, &result->z_tier2);
    tier_baseline_z_scores(t3, snapshot, threshold, &result->z_tier3);

    // Determine which tiers triggered
    result->tier1_triggered = (result->z_tier1.triggered_count > 0) && t1->ready;
    result->tier2_triggered = (result->z_tier2.triggered_count > 0) && t2->ready;
    result->tier3_triggered = (result->z_tier3.triggered_count > 0) && t3->ready;

    result->tier_agreement = result->tier1_triggered +
                             result->tier2_triggered +
                             result->tier3_triggered;

    // Find maximum Z-score across all tiers
    result->max_z_score = 0.0;
    result->primary_feature_idx = -1;

    if (result->z_tier1.max_z > result->max_z_score) {
        result->max_z_score = result->z_tier1.max_z;
        result->primary_feature_idx = result->z_tier1.max_feature_idx;
    }
    if (result->z_tier2.max_z > result->max_z_score) {
        result->max_z_score = result->z_tier2.max_z;
        result->primary_feature_idx = result->z_tier2.max_feature_idx;
    }
    if (result->z_tier3.max_z > result->max_z_score) {
        result->max_z_score = result->z_tier3.max_z;
        result->primary_feature_idx = result->z_tier3.max_feature_idx;
    }

    // Set feature name
    if (result->primary_feature_idx >= 0 &&
        result->primary_feature_idx < L2_MAX_FEATURES) {
        result->primary_feature_name = l2_feature_names[result->primary_feature_idx];
    } else {
        result->primary_feature_name = "unknown";
    }

    // Detection decision with improved logic:
    //
    // E1 FIX: Warm-up emergency detection
    // During warm-up (no tiers ready), use absolute thresholds on raw values
    bool warmup_mode = !t1->ready && !t2->ready && !t3->ready;
    bool warmup_emergency = false;
    enum l2_anomaly_level warmup_level = L2_ANOMALY_NONE;
    double warmup_synthetic_z = 0.0;

    if (warmup_mode) {
        // FIX: Improved warmup detection with proper severity classification
        // During warmup (no baselines ready), use absolute rate thresholds
        // and compute a "synthetic" Z-score based on how far above thresholds we are
        const struct layer2_config *cfg = layer2_config_get();
        double pps = snapshot->values[L2_FEAT_PACKETS_PER_SEC];
        double syn_pps = snapshot->values[L2_FEAT_SYN_PER_SEC];
        uint64_t unique_src_ips = (uint64_t)snapshot->values[L2_FEAT_UNIQUE_SRC_IPS];

        // Calculate how many times over the threshold we are
        double pps_ratio = (cfg->warmup_pps_threshold > 0) ?
                           pps / (double)cfg->warmup_pps_threshold : 0.0;
        double syn_ratio = (cfg->warmup_syn_threshold > 0) ?
                           syn_pps / (double)cfg->warmup_syn_threshold : 0.0;
        double max_ratio = (pps_ratio > syn_ratio) ? pps_ratio : syn_ratio;

        if (max_ratio > 1.0) {
            warmup_emergency = true;

            // FIX: Compute synthetic Z-score based on ratio over threshold
            // This gives proper severity classification during warmup
            // ratio 2x = Z ~4, ratio 5x = Z ~8, ratio 10x = Z ~12, ratio 20x = Z ~15
            warmup_synthetic_z = 4.0 * log2(max_ratio + 1.0);
            if (warmup_synthetic_z > 20.0) warmup_synthetic_z = 20.0;

            // FIX: Also consider source IP count for attack classification
            // High unique source IPs + high PPS = likely DDoS, not flash crowd
            if (unique_src_ips > 10000 && pps > 100000) {
                // Boost Z-score for high-source attacks
                warmup_synthetic_z *= 1.2;
            }

            // FIX: Classify severity based on absolute rates during warmup
            // These thresholds are more aggressive for obvious attacks
            if (pps > 500000 || syn_pps > 50000) {
                warmup_level = L2_ANOMALY_CRITICAL;
            } else if (pps > 200000 || syn_pps > 20000) {
                warmup_level = L2_ANOMALY_HIGH;
            } else if (pps > 100000 || syn_pps > 10000) {
                warmup_level = L2_ANOMALY_MEDIUM;
            } else {
                warmup_level = L2_ANOMALY_LOW;
            }
        }
    }

    // FIX: Reduced single-tier threshold multiplier from 1.5x to 1.25x
    // Z=6.0 (1.5x of 4.0) was too high, missing attacks with Z-scores 5.0-5.9
    // New Z=5.0 (1.25x of 4.0) catches these while maintaining statistical significance
    bool single_tier_high_z = (result->tier_agreement >= 1 &&
                               result->max_z_score >= threshold * 1.25);

    // Standard detection
    result->detected = warmup_emergency ||
                       (result->tier_agreement >= min_tier_agreement) ||
                       single_tier_high_z;

    // Compute level and confidence
    if (result->detected) {
        if (warmup_mode && warmup_emergency) {
            // FIX: Use warmup-derived level and synthetic Z-score
            result->level = warmup_level;
            result->max_z_score = warmup_synthetic_z;
            // Confidence is lower during warmup since we don't have baselines
            result->confidence = 0.6 + 0.3 * (warmup_synthetic_z / 15.0);
            if (result->confidence > 0.95) result->confidence = 0.95;
        } else {
            result->level = l2_compute_anomaly_level(result->max_z_score,
                                                      result->tier_agreement);
            result->confidence = l2_compute_confidence(result->max_z_score,
                                                        result->tier_agreement,
                                                        threshold);
        }
    } else {
        result->level = L2_ANOMALY_NONE;
        result->confidence = 0.0;
    }

    // MF4 FIX: Populate per-feature anomaly info for multi-vector reporting
    result->triggered_feature_count = 0;
    result->triggered_feature_mask = 0;
    memset(result->triggered_features, 0, sizeof(result->triggered_features));

    if (result->detected) {
        // FIX #8: Collect triggered features from ALL tiers, not just tier1
        // A feature can trigger on tier2/3 (time-of-day deviation) but not tier1
        struct {
            int idx;
            double z;
            double val;
        } triggered[L2_MAX_FEATURES];
        int num_triggered = 0;

        for (int i = 0; i < L2_MAX_FEATURES; i++) {
            // FIX #8: Take max Z-score across all tiers for this feature
            double z1 = fabs(result->z_tier1.z[i]);
            double z2 = fabs(result->z_tier2.z[i]);
            double z3 = fabs(result->z_tier3.z[i]);
            double max_z = z1;
            if (z2 > max_z) max_z = z2;
            if (z3 > max_z) max_z = z3;

            if (max_z >= threshold) {
                triggered[num_triggered].idx = i;
                triggered[num_triggered].z = max_z;
                triggered[num_triggered].val = snapshot->values[i];
                num_triggered++;
                /* triggered_feature_mask is uint32_t -- guard against shift overflow
                 * for feature indices >= 32 (matches layer2.c:293). */
                if (i < 32) result->triggered_feature_mask |= (1U << i);
            }
        }

        // Sort by Z-score (descending) - simple bubble sort for small array
        for (int i = 0; i < num_triggered - 1; i++) {
            for (int j = i + 1; j < num_triggered; j++) {
                if (triggered[j].z > triggered[i].z) {
                    int ti = triggered[i].idx;
                    double tz = triggered[i].z;
                    double tv = triggered[i].val;
                    triggered[i].idx = triggered[j].idx;
                    triggered[i].z = triggered[j].z;
                    triggered[i].val = triggered[j].val;
                    triggered[j].idx = ti;
                    triggered[j].z = tz;
                    triggered[j].val = tv;
                }
            }
        }

        // Store top 8 triggered features
        result->triggered_feature_count = (num_triggered > 8) ? 8 : num_triggered;
        for (int i = 0; i < result->triggered_feature_count; i++) {
            result->triggered_features[i].feature_idx = triggered[i].idx;
            result->triggered_features[i].feature_name = l2_feature_names[triggered[i].idx];
            result->triggered_features[i].z_score = triggered[i].z;
            result->triggered_features[i].value = triggered[i].val;
            result->triggered_features[i].triggered = true;
        }
    }
}

// ==================== State Management ====================

// Attack frequency window (5 minutes)
#define ATTACK_FREQ_WINDOW_NS (5ULL * 60 * 1000000000ULL)
// If more than 3 attacks in 5 minutes, extend cool-down
#define ATTACK_FREQ_THRESHOLD 3
// Extended cool-down multiplier for frequent attackers
#define EXTENDED_COOLDOWN_MULTIPLIER 3.0
// De-escalation: reduce severity after this many cycles at current level
#define DEESCALATION_CYCLES 30  // 30 seconds at same level triggers de-escalation

// Traffic-based cool-down thresholds
#define TRAFFIC_DROP_THRESHOLD 0.30     // Trigger cool-down if current < 30% of peak
#define TRAFFIC_DROP_CYCLES 3           // Must see low traffic for 3 consecutive cycles
#define MIN_PEAK_PPS_FOR_TRACKING 1000.0  // Only track if peak > 1000 pps
// If traffic is above this ratio of peak, consider attack still ongoing (even if z-score drops)
#define TRAFFIC_HIGH_THRESHOLD 0.50     // 50% of peak = still under attack

bool l2_update_anomaly_state(struct l2_anomaly_state *state,
                             const struct detection_result *result,
                             const struct l2_feature_snapshot *snapshot,
                             double cool_down_seconds) {
    if (!state || !result) return false;

    uint64_t now_ns = result->timestamp_ns;
    if (now_ns == 0) {
        now_ns = get_current_time_ns();
    }

    state->cycle_count++;
    state->previous_level = state->level;

    bool state_changed = false;

    // Get current packets per second from snapshot (feature index 0)
    double current_pps = 0.0;
    if (snapshot) {
        current_pps = snapshot->values[0];  // packets_per_sec is index 0
    }
    state->current_pps = current_pps;

    // E6 FIX: Reset attack frequency window if expired
    if (state->attack_window_start_ns == 0 ||
        now_ns - state->attack_window_start_ns > ATTACK_FREQ_WINDOW_NS) {
        state->attack_window_start_ns = now_ns;
        state->recent_attack_count = 0;
    }

    // FIX: If we're in cool-down period, ignore detections and continue cool-down
    bool in_cooldown = (state->active && state->cool_down_remaining_sec > 0.0);

    // TRAFFIC-BASED STATE MANAGEMENT:
    // Track peak traffic during attack and use it to determine when attack actually stops.
    // This is necessary because z-scores can fluctuate or remain high due to frozen baselines.
    bool traffic_dropped = false;
    bool traffic_still_high = false;

    if (state->active && !in_cooldown && snapshot) {
        // Update peak traffic during attack
        if (current_pps > state->peak_pps) {
            state->peak_pps = current_pps;
            state->low_traffic_cycles = 0;  // Reset counter when traffic increases
        }

        // Check traffic level relative to peak
        if (state->peak_pps > MIN_PEAK_PPS_FOR_TRACKING) {
            double traffic_ratio = current_pps / state->peak_pps;

            if (traffic_ratio >= TRAFFIC_HIGH_THRESHOLD) {
                // Traffic is still >= 50% of peak = attack is still ongoing
                // Even if z-score drops, don't trigger cool-down
                traffic_still_high = true;
                state->low_traffic_cycles = 0;
            } else if (traffic_ratio < TRAFFIC_DROP_THRESHOLD) {
                // Traffic is < 30% of peak = attack has likely stopped
                state->low_traffic_cycles++;

                if (state->low_traffic_cycles >= TRAFFIC_DROP_CYCLES) {
                    traffic_dropped = true;
                    state->cool_down_remaining_sec = cool_down_seconds;
                    printf("[Layer2] Traffic dropped: current=%.0f pps, peak=%.0f pps (%.1f%%), "
                           "triggering cool-down after %u low-traffic cycles\n",
                           current_pps, state->peak_pps, traffic_ratio * 100.0,
                           state->low_traffic_cycles);
                }
            } else {
                // Traffic is between 30-50% of peak = uncertain, increment slowly
                state->low_traffic_cycles++;
            }
        }
    }

    // Effective detection logic:
    // 1. If in cool-down: ignore detections, let cool-down complete
    // 2. If traffic dropped significantly: trigger cool-down
    // 3. If traffic still high: maintain attack state even if z-score drops
    bool effective_detected = (result->detected || traffic_still_high) && !in_cooldown && !traffic_dropped;

    // Temporal persistence: require K consecutive raw detections before first activation, so a
    // transient benign burst (clears before K) does not raise an alarm while a sustained attack
    // (survives K) does. This matches the debounce rule measured offline (experiment/, section6.10);
    // the cost is up to K-1 cycles of added detection latency. No severity bypass -- a bypass would
    // desynchronize the shipped rule from the measured one.
    if (result->detected) {
        if (state->consecutive_detect < UINT32_MAX) state->consecutive_detect++;
    } else {
        state->consecutive_detect = 0;
    }
    uint32_t persist_k = state->persistence_windows ? state->persistence_windows : 1;
    bool persist_ok = state->active || (state->consecutive_detect >= persist_k);

    if (effective_detected && persist_ok && !state->active) {
        // Transition: Normal -> Attack
        state->active = true;
        state->level = result->level;
        state->start_time_ns = now_ns;
        state->tier_agreement = result->tier_agreement;
        state->max_z_score = result->max_z_score;
        state->primary_feature_idx = result->primary_feature_idx;
        state->confidence = result->confidence;
        state->cool_down_remaining_sec = 0.0;
        state->detection_count++;
        state->cycles_at_current_level = 0;  // D2: Reset de-escalation counter
        state->peak_z_score = result->max_z_score;  // D2: Track peak
        state->low_traffic_cycles = 0;  // Reset traffic tracking
        state->peak_pps = current_pps;  // Initialize peak with first attack traffic
        state_changed = true;

        // E6 FIX: Track attack frequency
        state->recent_attack_count++;

    } else if (effective_detected && state->active) {
        // Transition: Attack -> Attack (continuing attack state)

        // Check if this is z-score based or traffic-based detection
        bool zscore_detected = result->detected;

        if (zscore_detected) {
            // Z-score based: update all values from detection result
            // D2 FIX: Track time at current level and allow de-escalation
            if (result->level == state->level) {
                state->cycles_at_current_level++;
            } else if (result->level > state->level) {
                // Escalation
                state->level = result->level;
                state->cycles_at_current_level = 0;
                state_changed = true;
            } else {
                // result->level < state->level: potential de-escalation
                state->cycles_at_current_level++;
                if (state->cycles_at_current_level >= DEESCALATION_CYCLES &&
                    state->level > L2_ANOMALY_LOW) {
                    state->level = (enum l2_anomaly_level)(state->level - 1);
                    state->cycles_at_current_level = 0;
                    state_changed = true;
                }
            }

            state->tier_agreement = result->tier_agreement;
            state->max_z_score = result->max_z_score;
            state->primary_feature_idx = result->primary_feature_idx;
            state->confidence = result->confidence;

            // D2: Track peak Z-score
            if (result->max_z_score > state->peak_z_score) {
                state->peak_z_score = result->max_z_score;
            }
        } else {
            // Traffic-based: z-score dropped but traffic still high
            // Maintain attack state but show traffic-based confidence
            // Calculate confidence based on traffic ratio
            double traffic_ratio = (state->peak_pps > 0) ? (current_pps / state->peak_pps) : 0;
            state->confidence = traffic_ratio * 100.0;  // e.g., 80% of peak = 80% confidence
            if (state->confidence > 100.0) state->confidence = 100.0;

            // Keep max_z_score from last detection, don't zero it
            // tier_agreement stays at last value
            printf("[Layer2] Traffic-based: pps=%.0f, peak=%.0f, ratio=%.1f%%, "
                   "preserved z=%.2f, tiers=%d, conf=%.0f%%\n",
                   current_pps, state->peak_pps, traffic_ratio * 100.0,
                   state->max_z_score, state->tier_agreement, state->confidence);

            // Gradual de-escalation when only traffic-based
            state->cycles_at_current_level++;
            if (state->cycles_at_current_level >= DEESCALATION_CYCLES / 2 &&
                state->level > L2_ANOMALY_LOW) {
                state->level = (enum l2_anomaly_level)(state->level - 1);
                state->cycles_at_current_level = 0;
                state_changed = true;
            }
        }

        state->cool_down_remaining_sec = 0.0;  // Reset cool-down while attack continues

        // Update duration
        state->duration_sec = (double)(now_ns - state->start_time_ns) / 1e9;

    } else if (!effective_detected && state->active) {
        // Transition: Attack -> Cool-down OR Cool-down -> Normal
        // MF3 FIX: Gradual de-escalation during cool-down
        // Instead of CRITICAL->NONE, go CRITICAL->HIGH->MEDIUM->LOW->NONE

        if (state->cool_down_remaining_sec <= 0.0) {
            // Start cool-down
            // E6 FIX: Extend cool-down if frequent attacks detected
            double effective_cooldown = cool_down_seconds;
            if (state->recent_attack_count >= ATTACK_FREQ_THRESHOLD) {
                effective_cooldown *= EXTENDED_COOLDOWN_MULTIPLIER;
            }
            state->cool_down_remaining_sec = effective_cooldown;

            // MF3: Start de-escalation by one level when entering cool-down
            if (state->level > L2_ANOMALY_LOW) {
                state->level = (enum l2_anomaly_level)(state->level - 1);
                state->cycles_at_current_level = 0;
                state_changed = true;
            }
        } else {
            // Decrement cool-down (1 second per cycle)
            state->cool_down_remaining_sec -= 1.0;

            // MF3: Gradual de-escalation during cool-down
            // De-escalate one level per (cool_down / 4) seconds
            double level_duration = cool_down_seconds / 4.0;
            if (level_duration < 2.0) level_duration = 2.0;  // Minimum 2 seconds per level

            state->cycles_at_current_level++;
            if (state->cycles_at_current_level >= (uint32_t)level_duration) {
                if (state->level > L2_ANOMALY_LOW) {
                    // De-escalate by one level
                    state->level = (enum l2_anomaly_level)(state->level - 1);
                    state->cycles_at_current_level = 0;
                    state_changed = true;
                }
            }

            if (state->cool_down_remaining_sec <= 0.0) {
                // Cool-down complete -> Normal
                state->active = false;
                state->level = L2_ANOMALY_NONE;
                state->cool_down_remaining_sec = 0.0;
                state->last_attack_end_ns = now_ns;  // E6: Track when attack ended
                state->cycles_at_current_level = 0;
                state->peak_z_score = 0.0;
                // FIX: Reset all displayed metrics when attack ends
                state->max_z_score = 0.0;
                state->confidence = 0.0;
                state->tier_agreement = 0;
                state->peak_pps = 0.0;
                state->low_traffic_cycles = 0;
                state_changed = true;
            }
        }
    }
    // else: Normal -> Normal (no change)

    state->last_update_ns = now_ns;
    // Note: level_changed is computed externally by comparing state->level with state->previous_level

    return state_changed;
}

// ==================== Level and Confidence ====================

enum l2_anomaly_level l2_compute_anomaly_level(double max_z, int tier_agreement) {
    // Use configurable thresholds instead of hardcoded values
    const struct layer2_config *cfg = layer2_config_get();

    if (tier_agreement == 3) {
        // All tiers agree - higher severity
        if (max_z >= cfg->z_critical_3tier) return L2_ANOMALY_CRITICAL;
        if (max_z >= cfg->z_high_3tier)     return L2_ANOMALY_HIGH;
        if (max_z >= cfg->z_medium_3tier)   return L2_ANOMALY_MEDIUM;
        return L2_ANOMALY_LOW;
    } else if (tier_agreement == 2) {
        // Two tiers agree
        if (max_z >= cfg->z_high_2tier)   return L2_ANOMALY_HIGH;
        if (max_z >= cfg->z_medium_2tier) return L2_ANOMALY_MEDIUM;
        return L2_ANOMALY_LOW;
    } else {
        // One tier only
        if (max_z >= cfg->z_medium_1tier) return L2_ANOMALY_MEDIUM;
        return L2_ANOMALY_LOW;
    }
}

double l2_compute_confidence(double max_z, int tier_agreement, double threshold) {
    // Base confidence from tier agreement
    double tier_conf = 0.0;
    switch (tier_agreement) {
        case 3: tier_conf = 0.99; break;  // Very high
        case 2: tier_conf = 0.90; break;  // High
        case 1: tier_conf = 0.75; break;  // Medium
        default: tier_conf = 0.0; break;
    }

    // Adjust by how much Z-score exceeds threshold
    double z_factor = 1.0;
    if (max_z > threshold) {
        // Increase confidence as Z-score increases beyond threshold
        z_factor = 1.0 + 0.1 * (max_z - threshold) / threshold;
        if (z_factor > 1.5) z_factor = 1.5;
    }

    double confidence = tier_conf * z_factor;
    if (confidence > 1.0) confidence = 1.0;

    return confidence;
}

// Multi-window pulsing/ramping detection is handled by the calibrated conformal path
// (conformal_combine.{c,h}), not a fixed-threshold rule: std_10s > k*mean is a coefficient-of-
// variation test, which fires on bursty-benign hosts and shows negative transfer in evaluation
// (paper section6.8, [34]). The 10s-variance and 60s-slope statistics are exported by window_stats as
// telemetry; their split-conformal p-values feed conformal_combine when that path is wired in.

// ==================== State Queries ====================

bool l2_is_anomaly_active(const struct l2_anomaly_state *state) {
    return state && state->active;
}

enum l2_anomaly_level l2_get_anomaly_level(const struct l2_anomaly_state *state) {
    if (!state) return L2_ANOMALY_NONE;
    return state->level;
}

double l2_get_attack_duration(const struct l2_anomaly_state *state) {
    if (!state || !state->active) return 0.0;

    uint64_t now_ns = get_current_time_ns();
    return (double)(now_ns - state->start_time_ns) / 1e9;
}

uint32_t l2_get_rate_limit_pct(enum l2_anomaly_level level) {
    switch (level) {
        case L2_ANOMALY_NONE:     return 100;
        case L2_ANOMALY_LOW:      return 80;
        case L2_ANOMALY_MEDIUM:   return 50;
        case L2_ANOMALY_HIGH:     return 25;
        case L2_ANOMALY_CRITICAL: return 10;
        default:                  return 100;
    }
}

// ==================== Manual Control ====================

void l2_force_anomaly(struct l2_anomaly_state *state, enum l2_anomaly_level level) {
    if (!state) return;

    state->active = (level != L2_ANOMALY_NONE);
    state->level = level;
    state->start_time_ns = get_current_time_ns();
    state->cool_down_remaining_sec = 0.0;

    printf("[Layer2] Anomaly forced to level %s\n",
           l2_anomaly_level_name(level));
}

void l2_clear_anomaly(struct l2_anomaly_state *state) {
    if (!state) return;

    state->active = false;
    state->level = L2_ANOMALY_NONE;
    state->cool_down_remaining_sec = 0.0;

    printf("[Layer2] Anomaly cleared manually\n");
}

// ==================== Logging ====================

void l2_log_detection(const struct detection_result *result) {
    if (!result || !result->detected) return;

    printf("[Layer2] ANOMALY DETECTED: level=%s z=%.2f feature=%s "
           "tiers=%d conf=%.0f%%\n",
           l2_anomaly_level_name(result->level),
           result->max_z_score,
           result->primary_feature_name,
           result->tier_agreement,
           result->confidence * 100.0);

    // Log per-tier details if significant
    if (result->tier1_triggered) {
        printf("  Tier1 (immediate): max_z=%.2f triggered=%d\n",
               result->z_tier1.max_z, result->z_tier1.triggered_count);
    }
    if (result->tier2_triggered) {
        printf("  Tier2 (hourly):    max_z=%.2f triggered=%d\n",
               result->z_tier2.max_z, result->z_tier2.triggered_count);
    }
    if (result->tier3_triggered) {
        printf("  Tier3 (weekly):    max_z=%.2f triggered=%d\n",
               result->z_tier3.max_z, result->z_tier3.triggered_count);
    }
}

void l2_log_state_change(const struct l2_anomaly_state *state,
                         enum l2_anomaly_level old_level,
                         enum l2_anomaly_level new_level) {
    if (!state) return;

    if (old_level == L2_ANOMALY_NONE && new_level != L2_ANOMALY_NONE) {
        printf("[Layer2] ATTACK STARTED: level=%s\n",
               l2_anomaly_level_name(new_level));
    } else if (old_level != L2_ANOMALY_NONE && new_level == L2_ANOMALY_NONE) {
        printf("[Layer2] ATTACK ENDED: duration=%.1fs\n", state->duration_sec);
    } else if (new_level > old_level) {
        printf("[Layer2] ATTACK ESCALATED: %s -> %s\n",
               l2_anomaly_level_name(old_level),
               l2_anomaly_level_name(new_level));
    } else if (new_level < old_level && new_level != L2_ANOMALY_NONE) {
        printf("[Layer2] ATTACK DE-ESCALATED: %s -> %s\n",
               l2_anomaly_level_name(old_level),
               l2_anomaly_level_name(new_level));
    }
}

void l2_log_status(const struct l2_anomaly_state *state,
                   const struct baseline_summary *baseline_summary) {
    if (!state || !baseline_summary) return;

    printf("[Layer2] Status: active=%s level=%s cycles=%lu detections=%lu\n",
           state->active ? "YES" : "no",
           l2_anomaly_level_name(state->level),
           (unsigned long)state->cycle_count,
           (unsigned long)state->detection_count);

    printf("  Baselines: T1=%s (samples=%u pps=%.0f±%.0f) "
           "T2=%u/24 T3=%u/168 frozen=%s\n",
           baseline_summary->tier1_ready ? "ready" : "learning",
           baseline_summary->tier1_samples,
           baseline_summary->tier1_pps_mean,
           baseline_summary->tier1_pps_stddev,
           baseline_summary->tier2_ready_count,
           baseline_summary->tier3_ready_count,
           baseline_summary->any_frozen ? "YES" : "no");
}
