#include "layer2.h"
#include "advanced_detection.h"
#include "conformal_live.h"
#include "routed_live.h"
#include "innovation_gate.h"
#include "attack_classification.h"
#include "../layer1/interlayer/shared_memory.h"
#include "../layer1/telemetry/window_stats.h"
#include "../common/config_path.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

// cJSON (bundled in external/)
#include "cJSON.h"

// ==================== Global State ====================

static struct {
    bool initialized;
    bool running;

    // Configuration
    struct layer2_config config;
    char config_filepath[256];

    // Baselines
    struct three_tier_baseline baselines;

    // Detection state
    struct l2_anomaly_state anomaly_state;

    // Advanced detection components
    struct cusum_detector cusum;          // CUSUM for volume/churn
    struct jsd_baseline jsd;              // JSD for protocol mix
    struct l2_feature_weights weights;    // Feature weights

    // Thread
    pthread_t thread;
    pthread_mutex_t lock;

    // Feature input
    layer2_feature_callback_t feature_callback;

    // Last known good features for seqlock contention
    // When seqlock retries exhaust, use this instead of zeroing
    struct layer2_features last_good_features;
    bool has_last_good_features;

    // Statistics
    uint64_t start_time_ns;
    uint64_t last_save_time_ns;
    uint64_t last_log_time_ns;

    // Log level
    int log_level;

    // Advanced detection enabled
    bool use_advanced_detection;
    // enables CUSUM + JSD inside the per-IP
    // detection loop. Defaults true so the per-IP path runs the same
    // ensemble as detection_cycle_advanced. Set to false to revert to the
    // pre-fix z-tier-only per-IP behaviour for A/B comparison.
    bool use_per_ip_advanced_detection;
} g_layer2;

// Live split-conformal combiner for the main detection path (paper section4.10).
// Shipped default is disjunctive OR (config.ensemble_rule == 0); this is consulted
// only when a conformal rule is selected. Engine-internal state -- no shared-memory ABI impact.
static struct conformal_live g_conformal_live;
// Live routed per-feature FDR combiner (paper section6.15), selected by ensemble_rule == 3.
static struct routed_live g_routed_live;
// Live innovation-gated z-path latch (the innovation-gate prototype), selected by ensemble_rule == 4. Gates only the
// z-path on a training-free surprise statistic; CUSUM/JSD stay ungated. Engine-internal state.
static struct innovation_gate g_innovation_gate;

// WARM-COMPLETE signal for the innovation gate (the innovation-gate prototype fidelity). The benign baseline
// warmup is complete once the Tier-2 (hourly) baseline is FULLY ready -- all 24 hourly slots have
// their min_samples (a full day-of-week hourly cycle of benign warmup). This is the streaming
// deployment analog of the harness "calibrate over the FULL benign-train then freeze": a fixed
// 10-window calibration recovered only ~22% of the cross-day per-window FPR cut and finite
// windows are non-monotonic (N=200/500), while calibrating over the full benign warmup recovers
// 100% (full-warmup calibration reproduces the prototype). Tier-3 (168 slots,
// ~6720 windows) is deliberately NOT required so short corpora still arm; a small min_calib floor
// in the gate keeps a degenerate near-zero-benign context fail-open. Monotonic under normal
// operation (a hourly tier's `ready` flag only clears on an explicit baseline reset), so once
// this returns true the gate arms and freezes.
static bool ig_baseline_warm_complete(const struct three_tier_baseline *b) {
    if (!b) return false;
    for (int h = 0; h < 24; h++) {
        if (!b->hourly[h].ready) return false;   // Tier-2 not yet fully warm
    }
    return true;
}

// ==================== Per-IP Feature Weights Table ====================

#define PER_IP_WEIGHTS_JSON_PATH "data/per_ip_l2_config.json"

typedef struct {
    uint32_t ip_net;                        // IP in network byte order
    double   weights[L2_MAX_FEATURES];      // 0.0 = disabled
    bool     active;
} per_ip_weight_entry_t;

static per_ip_weight_entry_t g_per_ip_weights[L2_MAX_PROTECTED_IPS];
static uint32_t              g_per_ip_weights_count = 0;
static pthread_mutex_t       g_per_ip_weights_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * Reload per-IP feature weights from data/per_ip_l2_config.json.
 * Called on CMD_L2_RELOAD_PER_IP_CONFIG.
 */
void layer2_load_per_ip_feature_weights(void) {
    char path_buf[512];
    const char *path = resolve_config_path(PER_IP_WEIGHTS_JSON_PATH,
                                           path_buf, sizeof(path_buf));

    FILE *f = fopen(path, "r");
    if (!f) {
        /* No file yet -- clear any stale entries */
        pthread_mutex_lock(&g_per_ip_weights_lock);
        memset(g_per_ip_weights, 0, sizeof(g_per_ip_weights));
        g_per_ip_weights_count = 0;
        pthread_mutex_unlock(&g_per_ip_weights_lock);
        return;
    }

    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsz <= 0 || fsz > 4 * 1024 * 1024) {
        fclose(f);
        return;
    }

    char *buf = malloc((size_t)fsz + 1);
    if (!buf) { fclose(f); return; }
    size_t rd = fread(buf, 1, (size_t)fsz, f);
    fclose(f);
    buf[rd] = '\0';

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) return;

    cJSON *configs = cJSON_GetObjectItem(root, "configs");
    if (!configs || !cJSON_IsArray(configs)) {
        cJSON_Delete(root);
        return;
    }

    /* Static to avoid ~20KB stack frame; safe because we hold no lock here yet. */
    static per_ip_weight_entry_t new_table[L2_MAX_PROTECTED_IPS];
    uint32_t new_count = 0;
    memset(new_table, 0, sizeof(new_table));

    int n = cJSON_GetArraySize(configs);
    for (int i = 0; i < n && new_count < L2_MAX_PROTECTED_IPS; i++) {
        cJSON *entry = cJSON_GetArrayItem(configs, i);
        if (!entry) continue;

        cJSON *use_fw = cJSON_GetObjectItem(entry, "use_feature_weights");
        if (!use_fw || !cJSON_IsTrue(use_fw)) continue;  /* skip if no weights */

        cJSON *ip_net = cJSON_GetObjectItem(entry, "ip_net");
        if (!ip_net || !cJSON_IsNumber(ip_net)) continue;

        cJSON *fw = cJSON_GetObjectItem(entry, "feature_weights");
        if (!fw || !cJSON_IsArray(fw) || cJSON_GetArraySize(fw) != L2_MAX_FEATURES) continue;

        per_ip_weight_entry_t *e = &new_table[new_count];
        e->ip_net = (uint32_t)ip_net->valuedouble;
        e->active = true;
        for (int j = 0; j < L2_MAX_FEATURES; j++) {
            cJSON *w = cJSON_GetArrayItem(fw, j);
            e->weights[j] = (w && cJSON_IsNumber(w)) ? w->valuedouble : 1.0;
        }
        new_count++;
    }

    cJSON_Delete(root);

    pthread_mutex_lock(&g_per_ip_weights_lock);
    memcpy(g_per_ip_weights, new_table, sizeof(new_table));
    g_per_ip_weights_count = new_count;
    pthread_mutex_unlock(&g_per_ip_weights_lock);

    printf("[Layer2] Loaded per-IP feature weights for %u IPs\n", new_count);
}

/**
 * Look up per-IP feature weights.  Returns NULL if this IP uses global weights.
 * Caller must hold g_per_ip_weights_lock or work on a local copy.
 */
static const double *lookup_per_ip_weights(uint32_t ip_net) {
    for (uint32_t i = 0; i < g_per_ip_weights_count; i++) {
        if (g_per_ip_weights[i].active && g_per_ip_weights[i].ip_net == ip_net) {
            return g_per_ip_weights[i].weights;
        }
    }
    return NULL;
}

/**
 * Post-filter a detection_result to suppress features disabled by per-IP weights.
 *
 * Zeroes z-scores for disabled features, re-derives tier agreement, detection
 * decision, level, confidence, and triggered_features[].
 *
 * Warmup-emergency detections (tier_agreement==0 but detected==true) are
 * passed through untouched: warmup uses absolute rate thresholds, not
 * per-feature z-scores, so feature masking doesn't apply.
 */
static void apply_feature_mask_to_result(struct detection_result *result,
                                         const double *weights,
                                         double threshold,
                                         int min_tier_agreement) {
    if (!result || !weights) return;

    /* Warmup-emergency: tier_agreement==0 yet detected. Don't touch it. */
    if (result->detected && result->tier_agreement == 0) return;

    struct tier_z_scores *tiers[3] = {
        &result->z_tier1, &result->z_tier2, &result->z_tier3
    };
    /* Preserve whether each tier was originally ready (triggered can only stay
     * true if it was already true before masking -- we AND with the old flag). */
    bool was_triggered[3] = {
        result->tier1_triggered,
        result->tier2_triggered,
        result->tier3_triggered,
    };

    for (int t = 0; t < 3; t++) {
        struct tier_z_scores *tz = tiers[t];
        tz->triggered_count = 0;
        tz->max_z           = 0.0;
        tz->max_feature_idx = -1;

        for (int i = 0; i < L2_MAX_FEATURES; i++) {
            if (weights[i] == 0.0) {
                tz->z[i] = 0.0;
                continue;
            }
            double abs_z = (tz->z[i] >= 0.0) ? tz->z[i] : -tz->z[i];
            if (abs_z >= threshold) tz->triggered_count++;
            if (abs_z > tz->max_z) {
                tz->max_z           = abs_z;
                tz->max_feature_idx = i;
            }
        }
    }

    result->tier1_triggered = was_triggered[0] && (result->z_tier1.triggered_count > 0);
    result->tier2_triggered = was_triggered[1] && (result->z_tier2.triggered_count > 0);
    result->tier3_triggered = was_triggered[2] && (result->z_tier3.triggered_count > 0);
    result->tier_agreement  = result->tier1_triggered + result->tier2_triggered +
                              result->tier3_triggered;

    result->max_z_score         = 0.0;
    result->primary_feature_idx = -1;
    for (int t = 0; t < 3; t++) {
        if (tiers[t]->max_z > result->max_z_score) {
            result->max_z_score         = tiers[t]->max_z;
            result->primary_feature_idx = tiers[t]->max_feature_idx;
        }
    }
    result->primary_feature_name =
        (result->primary_feature_idx >= 0 &&
         result->primary_feature_idx < L2_MAX_FEATURES)
        ? l2_feature_names[result->primary_feature_idx]
        : "unknown";

    bool single_tier_high_z = (result->tier_agreement >= 1 &&
                               result->max_z_score >= threshold * 1.25);
    result->detected = (result->tier_agreement >= min_tier_agreement) || single_tier_high_z;

    if (result->detected) {
        result->level      = l2_compute_anomaly_level(result->max_z_score,
                                                       result->tier_agreement);
        result->confidence = l2_compute_confidence(result->max_z_score,
                                                    result->tier_agreement, threshold);
    } else {
        result->level      = L2_ANOMALY_NONE;
        result->confidence = 0.0;
    }

    /* Rebuild triggered_features[] -- top-8 enabled features that exceeded threshold */
    result->triggered_feature_count = 0;
    result->triggered_feature_mask  = 0;
    memset(result->triggered_features, 0, sizeof(result->triggered_features));

    if (result->detected) {
        for (int i = 0; i < L2_MAX_FEATURES &&
             result->triggered_feature_count < 8; i++) {
            if (weights[i] == 0.0) continue;
            double max_abs_z = 0.0;
            for (int t = 0; t < 3; t++) {
                double az = tiers[t]->z[i];
                if (az < 0.0) az = -az;
                if (az > max_abs_z) max_abs_z = az;
            }
            if (max_abs_z >= threshold) {
                int idx = result->triggered_feature_count++;
                result->triggered_features[idx].feature_idx  = i;
                result->triggered_features[idx].feature_name = l2_feature_names[i];
                result->triggered_features[idx].z_score      = max_abs_z;
                result->triggered_features[idx].triggered    = true;
                /* triggered_feature_mask is uint32_t -- guard against shift overflow */
                if (i < 32) result->triggered_feature_mask |= (1U << i);
            }
        }
    }
}

// ==================== Forward Declarations ====================

// Per-IP detection cycle (defined at end of file)
void layer2_per_ip_detection_cycle(void);

// ==================== Helper Functions ====================
// P2 FIX: get_current_time_ns() now in baselines.h as inline

static void features_to_snapshot(const struct layer2_features *in,
                                  struct l2_feature_snapshot *out) {
    out->timestamp_ns = in->timestamp_ns;

    // ===== VOLUME FEATURES (3) =====
    out->values[L2_FEAT_PACKETS_PER_SEC] = (double)in->packets_per_sec;
    out->values[L2_FEAT_BYTES_PER_SEC] = (double)in->bytes_per_sec;
    out->values[L2_FEAT_FLOWS_PER_SEC] = (double)in->flows_per_sec;

    // ===== TCP FLAG FEATURES (5) =====
    out->values[L2_FEAT_SYN_PER_SEC] = (double)in->syn_per_sec;
    out->values[L2_FEAT_SYN_ACK_PER_SEC] = (double)in->syn_ack_per_sec;
    out->values[L2_FEAT_ACK_PER_SEC] = (double)in->ack_per_sec;
    out->values[L2_FEAT_RST_PER_SEC] = (double)in->rst_per_sec;
    out->values[L2_FEAT_FIN_PER_SEC] = (double)in->fin_per_sec;

    // ===== PROTOCOL MIX FEATURES (4) =====
    out->values[L2_FEAT_TCP_RATIO] = (double)in->tcp_ratio;
    out->values[L2_FEAT_UDP_RATIO] = (double)in->udp_ratio;
    out->values[L2_FEAT_ICMP_RATIO] = (double)in->icmp_ratio;
    out->values[L2_FEAT_OTHER_RATIO] = (double)in->other_ratio;

    // ===== RATIO FEATURES (3) =====
    out->values[L2_FEAT_SYN_ACK_RATIO] = (double)in->syn_ack_ratio;
    out->values[L2_FEAT_RST_SYN_RATIO] = (double)in->rst_syn_ratio;
    out->values[L2_FEAT_BYTES_PER_PACKET] = (double)in->bytes_per_packet;

    // ===== CARDINALITY FEATURES (3) =====
    out->values[L2_FEAT_UNIQUE_SRC_IPS] = (double)in->unique_src_ips;
    out->values[L2_FEAT_UNIQUE_DST_PORTS] = (double)in->unique_dst_ports;
    out->values[L2_FEAT_UNIQUE_FLOWS] = (double)in->unique_flows;

    // ===== CHURN FEATURES (1) =====
    out->values[L2_FEAT_NEW_SRCIP_RATE] = (double)in->new_srcip_rate;

    // ===== CONCENTRATION FEATURES (3) =====
    out->values[L2_FEAT_MAX_FLOW_FRACTION] = (double)in->max_flow_fraction;
    out->values[L2_FEAT_TOPK_FLOW_SHARE] = (double)in->topk_flow_share;
    out->values[L2_FEAT_HEAVY_HITTER_COUNT] = (double)in->heavy_hitter_count;

    // ===== FLOW BEHAVIOR FEATURES (2) =====
    out->values[L2_FEAT_AVG_PACKETS_PER_FLOW] = (double)in->avg_packets_per_flow;
    out->values[L2_FEAT_FLOW_DURATION_AVG] = (double)in->flow_duration_avg_ms;

    // ===== TCP FLAG RATIO FEATURES (5) =====
    out->values[L2_FEAT_SYN_TCP_RATIO]    = (double)in->syn_tcp_ratio;
    out->values[L2_FEAT_SYNACK_TCP_RATIO] = (double)in->synack_tcp_ratio;
    out->values[L2_FEAT_ACK_TCP_RATIO]    = (double)in->ack_tcp_ratio;
    out->values[L2_FEAT_RST_TCP_RATIO]    = (double)in->rst_tcp_ratio;
    out->values[L2_FEAT_FIN_TCP_RATIO]    = (double)in->fin_tcp_ratio;

    // ===== VOLUME EXTENDED (1) =====
    out->values[L2_FEAT_BURST_FACTOR] = (double)in->burst_factor;

    // ===== FLOW BEHAVIOR EXTENDED (1) =====
    out->values[L2_FEAT_UDP_FLOW_RATIO] = (double)in->udp_flow_ratio;

    // ===== PROTOCOL MIX EXTENDED (1) =====
    out->values[L2_FEAT_ICMP_ECHO_RATIO] = (double)in->icmp_echo_ratio;

    // ===== CARDINALITY EXTENDED (1) =====
    out->values[L2_FEAT_DST_PORT_DENSITY] = (double)in->dst_port_density;

    // ===== ENTROPY FEATURES (2) =====
    // Scale from 0-255 to 0.0-8.0 bits for proper analysis
    out->values[L2_FEAT_SRC_IP_ENTROPY]   = (double)in->src_ip_entropy  * 8.0 / 255.0;
    out->values[L2_FEAT_SRC_PORT_ENTROPY] = (double)in->src_port_entropy * 8.0 / 255.0;

    // ===== PACKET CHARACTERISTICS (3) =====
    out->values[L2_FEAT_SMALL_PKT_RATIO] = (double)in->small_pkt_ratio;
    out->values[L2_FEAT_FRAGMENT_RATIO]  = (double)in->fragment_ratio;
    out->values[L2_FEAT_TTL_MEAN]        = (double)in->ttl_mean;

    // ===== RATIO EXTENDED (1) =====
    out->values[L2_FEAT_TCP_COMPLETION_RATE] = (double)in->tcp_completion_rate;
}

static void read_features_from_shmem(struct layer2_features *features) {
    struct l2_features_export *exp = l2_features_export_get();
    if (!exp) {
        memset(features, 0, sizeof(*features));
        return;
    }

    // Proper seqlock read pattern with retry loop
    // Writer increments version to odd before write, even after write
    // Init so the first do-while condition is deterministic even on the
    // odd-version early-continue path (odd 1 != even 0 -> retry/last-good).
    uint64_t version_before = 1, version_after = 0;
    int retry_count = 0;
    const int max_retries = 3;

    do {
        // Read version with acquire semantics
        version_before = __atomic_load_n(&exp->version, __ATOMIC_ACQUIRE);

        // If write in progress (odd version), retry
        if (version_before & 1) {
            if (++retry_count > max_retries) {
                // Use last known good features instead of zeroing
                // Zeroing caused detection to skip cycles during contention
                // which allowed timed attacks to slip through
                if (g_layer2.has_last_good_features) {
                    *features = g_layer2.last_good_features;
                } else {
                    memset(features, 0, sizeof(*features));
                }
                return;
            }
            continue;
        }

        // Memory barrier before reading data
        __atomic_thread_fence(__ATOMIC_ACQUIRE);

        // Read all fields
        features->timestamp_ns = exp->timestamp_ns;

        // ===== VOLUME FEATURES (3) =====
        features->packets_per_sec = exp->packets_per_sec;
        features->bytes_per_sec = exp->bytes_per_sec;
        features->flows_per_sec = exp->flows_per_sec;

        // ===== TCP FLAG FEATURES (5) =====
        features->syn_per_sec = exp->syn_per_sec;
        features->syn_ack_per_sec = exp->syn_ack_per_sec;
        features->ack_per_sec = exp->ack_per_sec;
        features->rst_per_sec = exp->rst_per_sec;
        features->fin_per_sec = exp->fin_per_sec;

        // ===== PROTOCOL MIX FEATURES (4) =====
        features->tcp_ratio = exp->tcp_ratio;
        features->udp_ratio = exp->udp_ratio;
        features->icmp_ratio = exp->icmp_ratio;
        // Compute other_ratio (100 - tcp - udp - icmp, clamped to 0-100)
        int other = 100 - (int)exp->tcp_ratio - (int)exp->udp_ratio - (int)exp->icmp_ratio;
        features->other_ratio = (other > 0 && other <= 100) ? (uint8_t)other : 0;

        // ===== RATIO FEATURES (3) =====
        features->syn_ack_ratio = exp->syn_ack_ratio;
        features->rst_syn_ratio = exp->rst_syn_ratio;
        features->bytes_per_packet = exp->bytes_per_packet;

        // ===== CARDINALITY FEATURES (3) =====
        features->unique_src_ips = exp->unique_src_ips;
        features->unique_dst_ports = exp->unique_dst_ports;
        features->unique_flows = exp->unique_flows;

        // ===== CHURN FEATURES (1) =====
        features->new_srcip_rate = exp->new_srcip_rate;

        // ===== CONCENTRATION FEATURES (3) =====
        features->max_flow_fraction = exp->max_flow_fraction;
        features->topk_flow_share = exp->topk_flow_share;
        features->heavy_hitter_count = exp->heavy_hitter_count;

        // ===== FLOW BEHAVIOR FEATURES (2) =====
        features->avg_packets_per_flow = exp->avg_packets_per_flow;
        features->flow_duration_avg_ms = exp->flow_duration_avg_ms;

        // ===== TCP FLAG RATIO FEATURES (5) =====
        features->syn_tcp_ratio    = exp->syn_tcp_ratio;
        features->synack_tcp_ratio = exp->synack_tcp_ratio;
        features->ack_tcp_ratio    = exp->ack_tcp_ratio;
        features->rst_tcp_ratio    = exp->rst_tcp_ratio;
        features->fin_tcp_ratio    = exp->fin_tcp_ratio;

        // ===== VOLUME EXTENDED (1) =====
        features->burst_factor = exp->burst_factor;

        // ===== FLOW BEHAVIOR EXTENDED (1) =====
        features->udp_flow_ratio = exp->udp_flow_ratio;

        // ===== PROTOCOL MIX EXTENDED (1) =====
        features->icmp_echo_ratio = exp->icmp_echo_ratio;

        // ===== CARDINALITY EXTENDED (1) =====
        features->dst_port_density = exp->dst_port_density;

        // ===== ENTROPY FEATURES (2) =====
        features->src_ip_entropy   = exp->src_ip_entropy;
        features->src_port_entropy = exp->src_port_entropy;

        // ===== PACKET CHARACTERISTICS (3) =====
        features->small_pkt_ratio = exp->small_pkt_ratio;
        features->fragment_ratio  = exp->fragment_ratio;
        features->ttl_mean        = exp->ttl_mean;

        // ===== RATIO EXTENDED (1) =====
        features->tcp_completion_rate = exp->tcp_completion_rate;

        // ===== METADATA =====
        features->active_flows = exp->active_flows;

        // Memory barrier after reading data
        __atomic_thread_fence(__ATOMIC_ACQUIRE);

        // Read version again to check for concurrent write
        version_after = __atomic_load_n(&exp->version, __ATOMIC_ACQUIRE);

    } while (version_before != version_after && ++retry_count <= max_retries);

    // If versions don't match after retries, data may be inconsistent
    if (version_before != version_after) {
        // Use last known good features instead of zeroing
        if (g_layer2.has_last_good_features) {
            *features = g_layer2.last_good_features;
        } else {
            memset(features, 0, sizeof(*features));
        }
    } else {
        // Save successful read as last known good
        g_layer2.last_good_features = *features;
        g_layer2.has_last_good_features = true;
    }
}

// ==================== Detection Loop ====================

/**
 * Run advanced detection using CUSUM, JSD, and feature weights
 */
static void detection_cycle_advanced(struct l2_feature_snapshot *snapshot,
                                     struct detection_result *result) {
    // Run advanced detection
    struct advanced_detection_result adv_result;
    const struct tier_baseline *t1 = &g_layer2.baselines.immediate;

    // Use configurable JSD threshold (was hardcoded 0.15)
    double jsd_threshold = g_layer2.config.jsd_threshold;

    l2_advanced_detect(t1, snapshot,
                       &g_layer2.cusum,
                       &g_layer2.jsd,
                       &g_layer2.weights,
                       g_layer2.config.z_score_threshold,
                       jsd_threshold,
                       &adv_result);

    // Update JSD baseline (if not in attack)
    if (!g_layer2.anomaly_state.active) {
        struct protocol_distribution current_dist;
        protocol_dist_from_ratios(&current_dist,
                                  (uint8_t)snapshot->values[L2_FEAT_TCP_RATIO],
                                  (uint8_t)snapshot->values[L2_FEAT_UDP_RATIO],
                                  (uint8_t)snapshot->values[L2_FEAT_ICMP_RATIO],
                                  (uint8_t)snapshot->values[L2_FEAT_OTHER_RATIO]);
        jsd_baseline_update(&g_layer2.jsd, &current_dist);
    }

    // Also run standard multi-tier detection for tier agreement
    l2_detect_anomaly(&g_layer2.baselines, snapshot,
                      g_layer2.config.z_score_threshold,
                      g_layer2.config.min_tier_agreement,
                      result);

    // Enhance result with advanced detection signals
    bool cusum_triggered = (adv_result.cusum_triggered_count > 0);
    bool jsd_triggered = adv_result.jsd_triggered;

    // Ensemble decision rule. Shipped default (ensemble_rule == OR) keeps the disjunctive
    // OR override below. When a conformal rule is selected (paper section4.10), the per-path
    // continuous scores (z, normalized CUSUM, JSD) are combined under family-wise control;
    // a cold context falls back to OR until the calibration buffers warm (~3/alpha benign windows).
    bool use_or_override = true;
    bool calibrate = !result->detected && !three_tier_baseline_is_frozen(&g_layer2.baselines);
    if (g_layer2.config.ensemble_rule == L2_ENSEMBLE_RULE_INNOVATION_GATE) {
        // the innovation-gate prototype: gate ONLY the z/tier-path on a training-free surprise latch computed from the
        // RAW feature values (the AnEWMA one-step forecast error, NOT the z-scores). At this
        // point result->detected reflects the z/tier-path (CUSUM/JSD are OR-ed in below), so a
        // z-path alarm on an UNSURPRISING window (benign cross-day drift) is suppressed while
        // CUSUM/JSD can still OR-in. Decision = (z AND latch) OR CUSUM OR JSD.
        //
        // NOTE: this global gate is a COARSE aggregate fallback (one latch over the whole
        // protected aggregate). The AUTHORITATIVE the innovation-gate prototype wiring is PER protected-IP in
        // layer2_per_ip_detection_cycle() (one latch per destination, matching the harness).
        // The per-IP path is where the cross-day FPR floor actually lives; this aggregate gate
        // only backstops the global detection_cycle. Calibrate over the FULL benign warmup, then
        // FREEZE + ARM once the aggregate Tier-2 baseline is fully warm (the innovation-gate prototype fidelity): the gate
        // keeps calibrating (and stays fail-open) until warm_complete, not just the first ~10
        // benign windows. `calibrate` is the benign, non-frozen guard shared with the conformal
        // paths; gate_calibrate additionally stops at warm_complete so the stats freeze on arming.
        bool warm_complete = ig_baseline_warm_complete(&g_layer2.baselines);
        bool gate_calibrate = calibrate && !warm_complete;
        bool latch_open = l2_innovation_gate_update(&g_innovation_gate, snapshot->values,
                                                    L2_MAX_FEATURES, gate_calibrate, warm_complete);
        if (result->detected && !latch_open) {
            result->detected = false;   // z-path fired but unsurprising -> suppress
        }
        // Leave use_or_override = true so CUSUM/JSD still contribute below.
    } else if (g_layer2.config.ensemble_rule == L2_ENSEMBLE_RULE_ROUTED_FDR) {
        size_t attr_idx = (size_t)-1;
        int cd = l2_routed_live_decide(&g_routed_live,
                                       adv_result.z_scores, adv_result.cusum_norms,
                                       L2_MAX_FEATURES, adv_result.jsd_score,
                                       calibrate, &attr_idx);
        if (cd >= 0) {                       // warmed -> routed FDR makes the call
            result->detected = (cd == 1);
            if (result->detected) {
                if (result->tier_agreement == 0) result->tier_agreement = 1;
                if (attr_idx != (size_t)-1 && attr_idx < L2_MAX_FEATURES)
                    result->primary_feature_idx = (int)attr_idx;   // BH-attributed feature
            }
            use_or_override = false;
        }
    } else if (g_layer2.config.ensemble_rule != L2_ENSEMBLE_RULE_OR) {
        int cd = l2_conformal_live_decide(&g_conformal_live,
                                          result->max_z_score,
                                          adv_result.cusum_max_norm,
                                          adv_result.jsd_score,
                                          calibrate);
        if (cd >= 0) {                       // warmed -> conformal makes the call
            result->detected = (cd == 1);
            if (result->detected && result->tier_agreement == 0) result->tier_agreement = 1;
            use_or_override = false;
        }
        // cd < 0 (warming up) -> fall through to the OR override
    }

    // Override detection if CUSUM or JSD triggered but Z-score didn't
    if (use_or_override && !result->detected && (cusum_triggered || jsd_triggered)) {
        // CUSUM or JSD detected something Z-score missed
        result->detected = true;
        result->tier_agreement = (result->tier_agreement > 0) ? result->tier_agreement : 1;

        if (g_layer2.log_level >= 2) {
            if (cusum_triggered && !jsd_triggered) {
                printf("[Layer2] CUSUM triggered (slow-ramp detected)\n");
            } else if (jsd_triggered && !cusum_triggered) {
                printf("[Layer2] JSD triggered (protocol shift detected, jsd=%.3f)\n",
                       adv_result.jsd_score);
            } else {
                printf("[Layer2] CUSUM+JSD triggered\n");
            }
        }
    }

    // Multi-window immediate-tier signals (1s/10s/60s; window_stats pps_variance / pps_trend_slope)
    // are NOT wired into the production ensemble decision. A fixed-threshold OR rule on these
    // statistics is unsound: std_10s > k*mean is a coefficient-of-variation test, and CV fires on
    // the bursty-benign hosts that already dominate the per-window FPR floor (section6.8), reproducing the
    // negative transfer the paper measures for the CV onset detector [34]. The signals are exported
    // as telemetry only; the calibrated path that consumes them (split-conformal per-window p-values
    // combined under family-wise control, `conformal_combine.{c,h}`) is evaluated in the offline
    // harness as a proposed extension (paper section6.10) and is the remaining production-wiring step.
    // l2_detect_window_signals() remains available for that wiring but is intentionally uncalled.

    // Use weighted score if higher
    if (adv_result.combined_score > result->max_z_score) {
        result->max_z_score = adv_result.combined_score;
        result->primary_feature_idx = adv_result.primary_feature_idx;
        result->primary_feature_name = adv_result.primary_feature_name;
    }

    // Recompute level with enhanced score
    if (result->detected) {
        result->level = l2_compute_anomaly_level(result->max_z_score, result->tier_agreement);
        result->confidence = l2_compute_confidence(result->max_z_score,
                                                    result->tier_agreement,
                                                    g_layer2.config.z_score_threshold);
    }
}

static void detection_cycle(void) {
    // Step 1: Read features
    struct layer2_features raw_features;

    if (g_layer2.feature_callback) {
        g_layer2.feature_callback(&raw_features);
    } else {
        read_features_from_shmem(&raw_features);
    }

    // Still update baselines during low traffic, but skip detection
    // Old behavior skipped both, which meant:
    // - Low-and-slow attacks during quiet hours were invisible
    // - Baselines didn't adapt to off-peak patterns
    uint64_t min_pps = g_layer2.config.min_pps_for_detection;
    bool low_traffic = (raw_features.packets_per_sec < min_pps);

    // Step 2: Convert to snapshot
    struct l2_feature_snapshot snapshot;
    features_to_snapshot(&raw_features, &snapshot);
    if (snapshot.timestamp_ns == 0) {
        snapshot.timestamp_ns = get_current_time_ns();
    }

    // Step 3: Run detection (skip if low traffic)
    struct detection_result result;
    memset(&result, 0, sizeof(result));

    if (!low_traffic) {
        if (g_layer2.use_advanced_detection) {
            // Use advanced detection with CUSUM, JSD, feature weights
            detection_cycle_advanced(&snapshot, &result);
        } else {
            // Standard detection
            l2_detect_anomaly(&g_layer2.baselines,
                              &snapshot,
                              g_layer2.config.z_score_threshold,
                              g_layer2.config.min_tier_agreement,
                              &result);
        }
    }

    // Step 4: Update anomaly state
    // FIX: Always update when anomaly is active (to allow cool-down to complete)
    // Only skip detection/state-update when low_traffic AND no active anomaly
    pthread_mutex_lock(&g_layer2.lock);

    enum l2_anomaly_level old_level = g_layer2.anomaly_state.level;
    bool state_changed = false;

    // Update state if: (1) traffic is sufficient for detection, OR
    //                  (2) anomaly is currently active (to allow cool-down to decrement)
    if (!low_traffic || g_layer2.anomaly_state.active) {
        state_changed = l2_update_anomaly_state(&g_layer2.anomaly_state,
                                                  &result,
                                                  &snapshot,
                                                  g_layer2.config.cool_down_seconds);
    }

    // Step 5: Freeze/unfreeze baselines based on attack state and poisoning
    if (g_layer2.config.baseline_freeze_enabled) {
        if (g_layer2.anomaly_state.active && !three_tier_baseline_is_frozen(&g_layer2.baselines)) {
            three_tier_baseline_freeze(&g_layer2.baselines);
            if (g_layer2.log_level >= 2) {
                printf("[Layer2] Baselines frozen (anomaly active)\n");
            }
        } else if (!g_layer2.anomaly_state.active && three_tier_baseline_is_frozen(&g_layer2.baselines)
                   && !baseline_is_poisoned(&g_layer2.baselines)) {
            // Only unfreeze if NOT poisoned -- poison freeze persists independently
            three_tier_baseline_unfreeze(&g_layer2.baselines);
            if (g_layer2.log_level >= 2) {
                printf("[Layer2] Baselines unfrozen\n");
            }
        }
    }

    // Step 5b: Poison recovery -- auto-unfreeze after recovery period
    if (baseline_is_poisoned(&g_layer2.baselines) && !g_layer2.anomaly_state.active) {
        uint32_t recovery_sec = g_layer2.config.baseline_poison_recovery_sec;
        if (recovery_sec > 0) {
            uint64_t poison_ns = g_layer2.baselines.poison_tracker.poison_detected_ns;
            uint64_t elapsed_ns = snapshot.timestamp_ns - poison_ns;
            uint64_t recovery_ns = (uint64_t)recovery_sec * 1000000000ULL;
            if (elapsed_ns >= recovery_ns) {
                baseline_poison_tracker_reset(&g_layer2.baselines);
                three_tier_baseline_unfreeze(&g_layer2.baselines);
                printf("[Layer2] Poison recovery: baselines unfrozen after %u s\n", recovery_sec);
            }
        }
    }

    // Step 6: Update baselines (if not frozen)
    if (!three_tier_baseline_is_frozen(&g_layer2.baselines)) {
        three_tier_baseline_update(&g_layer2.baselines, &snapshot);
    }

    // Step 6b: Check for baseline poisoning (after baseline update)
    // Runs every cycle on the updated Tier-1 means; freezes if 10 qualifying
    // cycles with >200% mean jump occur within a 300 s window.
    if (g_layer2.config.baseline_poison_protection_enabled) {
        baseline_check_poisoning(&g_layer2.baselines, &snapshot);
    }

    pthread_mutex_unlock(&g_layer2.lock);

    // Step 7: Write anomaly state to shared memory
    if (state_changed || result.level_changed) {
        anomaly_set_level((uint32_t)g_layer2.anomaly_state.level);

        // Log state change
        if (g_layer2.config.log_detections && g_layer2.log_level >= 1) {
            l2_log_state_change(&g_layer2.anomaly_state, old_level,
                               g_layer2.anomaly_state.level);
        }
    }

    // Step 8: Log detection only on NEW detections (state change), not every cycle
    // This prevents log spam during sustained attacks
    if (state_changed && result.detected && g_layer2.config.log_detections && g_layer2.log_level >= 2) {
        l2_log_detection(&result);
    }

    // Step 9: Run per-IP detection cycle
    // This detects anomalies per protected destination IP
    layer2_per_ip_detection_cycle();
}

static void *detection_thread(void *arg) {
    (void)arg;

    uint64_t interval_ns = (uint64_t)g_layer2.config.detection_interval_ms * 1000000ULL;
    uint32_t jitter_ms = g_layer2.config.jitter_ms;
    uint64_t next_tick = get_current_time_ns() + interval_ns;

    // Seed random for jitter - use thread ID and time for uniqueness
    unsigned int seed = (unsigned int)(get_current_time_ns() ^ (uint64_t)pthread_self());
    srand(seed);

    printf("[Layer2] Detection thread started (interval=%ums, jitter=±%ums)\n",
           g_layer2.config.detection_interval_ms, jitter_ms);

    while (g_layer2.running) {
        // Run detection cycle
        detection_cycle();

        // Periodic save
        uint64_t now_ns = get_current_time_ns();
        if (g_layer2.config.baseline_save_interval_sec > 0) {
            uint64_t save_interval_ns = (uint64_t)g_layer2.config.baseline_save_interval_sec * 1000000000ULL;
            if (now_ns - g_layer2.last_save_time_ns >= save_interval_ns) {
                if (!g_layer2.anomaly_state.active) {
                    layer2_save_baselines();
                    g_layer2.last_save_time_ns = now_ns;
                }
            }
        }

        // Periodic status log
        if (g_layer2.config.log_interval_sec > 0 && g_layer2.log_level >= 2) {
            uint64_t log_interval_ns = (uint64_t)g_layer2.config.log_interval_sec * 1000000000ULL;
            if (now_ns - g_layer2.last_log_time_ns >= log_interval_ns) {
                struct baseline_summary summary;
                layer2_get_baseline_summary(&summary);
                l2_log_status(&g_layer2.anomaly_state, &summary);
                g_layer2.last_log_time_ns = now_ns;
            }
        }

        // Sleep until next tick with jitter
        // Add random jitter to prevent attackers from timing 900ms bursts
        // between predictable 1Hz detection cycles
        int64_t jitter_ns = 0;
        if (jitter_ms > 0) {
            // Random value in range [-jitter_ms, +jitter_ms]
            int jitter_range = (int)(jitter_ms * 2);
            int random_offset = (rand() % (jitter_range + 1)) - (int)jitter_ms;
            jitter_ns = (int64_t)random_offset * 1000000LL;
        }

        next_tick += interval_ns + jitter_ns;
        int64_t sleep_ns = (int64_t)(next_tick - get_current_time_ns());
        if (sleep_ns > 0) {
            struct timespec ts;
            ts.tv_sec = sleep_ns / 1000000000;
            ts.tv_nsec = sleep_ns % 1000000000;
            nanosleep(&ts, NULL);
        } else {
            // Missed deadline, reset
            next_tick = get_current_time_ns() + interval_ns;
        }
    }

    printf("[Layer2] Detection thread stopped\n");
    return NULL;
}

// ==================== Public API: Initialization ====================

int layer2_init(const char *config_file) {
    if (g_layer2.initialized) {
        fprintf(stderr, "[Layer2] Already initialized\n");
        return -1;
    }

    memset(&g_layer2, 0, sizeof(g_layer2));
    pthread_mutex_init(&g_layer2.lock, NULL);

    // Load configuration
    // Load into global double-buffer first, then copy to local
    // This sets up the atomic infrastructure for lock-free config reloads
    const char *cfg_path = config_file ? config_file : L2_DEFAULT_CONFIG_FILE;
    struct layer2_config *config_buf = layer2_config_get_buffer();
    if (layer2_config_load(config_buf, cfg_path) < 0) {
        // Continue with defaults
        layer2_config_init_defaults(config_buf);
    }
    // Copy to local for fast access (detection loop uses this copy)
    memcpy(&g_layer2.config, config_buf, sizeof(g_layer2.config));
    strncpy(g_layer2.config_filepath, cfg_path, sizeof(g_layer2.config_filepath) - 1);
    g_layer2.config_filepath[sizeof(g_layer2.config_filepath) - 1] = '\0';  // Ensure null termination

    // Initialize baselines
    three_tier_baseline_init(&g_layer2.baselines,
                            g_layer2.config.alpha_immediate,
                            g_layer2.config.alpha_hourly,
                            g_layer2.config.alpha_weekly,
                            g_layer2.config.min_samples_immediate,
                            g_layer2.config.min_samples_hourly,
                            g_layer2.config.min_samples_weekly);

    // Try to load saved baselines
    if (g_layer2.config.baseline_file[0] != '\0') {
        three_tier_baseline_load(&g_layer2.baselines, g_layer2.config.baseline_file);
    }

    // Initialize anomaly state
    l2_anomaly_state_init(&g_layer2.anomaly_state);
    // Temporal persistence gate: require 3 consecutive detections before activating. Lowers
    // per-window false positives on bursty-benign traffic at a flat-to-small detection cost and
    // up to 2 cycles of latency; matches the offline debounce rule measured in section6.10 (experiment/).
    g_layer2.anomaly_state.persistence_windows = 3;

    // Initialize advanced detection components
    // CUSUM: k_factor=0.25 (slack), h_factor=5.0 (threshold in stddevs)
    // k=0.25 matches the E2 FIX in cusum_detector_init (lower slack catches slow-ramp
    // attacks) and the paper section4.3.2 specification. Prior call-site used 0.5, which
    // overrode the E2 FIX and made the deployed engine less sensitive than documented.
    cusum_detector_init(&g_layer2.cusum, 0.25, 5.0);
    /* Bound the CUSUM accumulator so it cannot latch permanently on benign drift.
     * See L2_DEFAULT_CUSUM_DECAY in layer2/config/layer2_config.h. */
    cusum_detector_set_decay(&g_layer2.cusum, g_layer2.config.cusum_decay);

    // JSD: alpha=0.1 (same as tier 2), min_samples=30
    jsd_baseline_init(&g_layer2.jsd, 0.1, 30);

    // Live conformal combiner (opt-in; shipped default is disjunctive OR, paper section4.10/section7.1).
    l2_conformal_live_init(&g_conformal_live, g_layer2.config.conformal_alpha,
                           (size_t)g_layer2.config.conformal_capacity,
                           g_layer2.config.ensemble_rule);
    // Live routed per-feature FDR combiner (opt-in; one channel per feature, paper section6.15).
    l2_routed_live_init(&g_routed_live, g_layer2.config.routed_fdr_alpha,
                        L2_MAX_FEATURES, (size_t)g_layer2.config.conformal_capacity);
    // Live innovation-gated z-path latch (opt-in; the innovation-gate prototype, selected by ensemble_rule == 4).
    // MIN_CALIB=10 is a FLOOR (degenerate-context guard); arming is driven by warm_complete.
    l2_innovation_gate_init(&g_innovation_gate, g_layer2.config.innovation_gate_kappa,
                            g_layer2.config.innovation_gate_hysteresis, 10 /* MIN_CALIB floor */);

    // Feature weights
    l2_feature_weights_init(&g_layer2.weights);

    // Enable advanced detection by default
    g_layer2.use_advanced_detection = true;
    // per-IP advanced detection on by default
    // (CUSUM + JSD in the per-IP loop).
    g_layer2.use_per_ip_advanced_detection = true;

    // Apply concentration thresholds from config
    l2_set_concentration_thresholds(g_layer2.config.max_flow_fraction_threshold,
                                    g_layer2.config.topk_flow_share_threshold);

    g_layer2.log_level = 2;  // Default: info level
    g_layer2.start_time_ns = get_current_time_ns();
    g_layer2.last_save_time_ns = g_layer2.start_time_ns;
    g_layer2.last_log_time_ns = g_layer2.start_time_ns;
    g_layer2.initialized = true;

    printf("[Layer2] Initialized (threshold=%.1f tiers=%d advanced=%s)\n",
           g_layer2.config.z_score_threshold,
           g_layer2.config.min_tier_agreement,
           g_layer2.use_advanced_detection ? "yes" : "no");

    return 0;
}

void layer2_cleanup(void) {
    if (!g_layer2.initialized) return;

    layer2_stop();

    // Save baselines before exit
    if (!g_layer2.anomaly_state.active) {
        layer2_save_baselines();
    }

    pthread_mutex_destroy(&g_layer2.lock);
    g_layer2.initialized = false;

    printf("[Layer2] Cleanup complete\n");
}

bool layer2_is_initialized(void) {
    return g_layer2.initialized;
}

// ==================== Public API: Thread Control ====================

int layer2_start(void) {
    if (!g_layer2.initialized) {
        fprintf(stderr, "[Layer2] Not initialized\n");
        return -1;
    }

    pthread_mutex_lock(&g_layer2.lock);

    if (g_layer2.running) {
        pthread_mutex_unlock(&g_layer2.lock);
        return 0;  // Already running
    }

    // Create thread first, only set running=true after success
    int rc = pthread_create(&g_layer2.thread, NULL, detection_thread, NULL);
    if (rc != 0) {
        pthread_mutex_unlock(&g_layer2.lock);
        fprintf(stderr, "[Layer2] Failed to create thread: %d\n", rc);
        return -1;
    }

    g_layer2.running = true;
    pthread_mutex_unlock(&g_layer2.lock);

    return 0;
}

void layer2_stop(void) {
    if (!g_layer2.running) return;

    g_layer2.running = false;
    pthread_join(g_layer2.thread, NULL);
}

bool layer2_is_running(void) {
    return g_layer2.running;
}

int layer2_lcore_main(void *arg) {
    (void)arg;

    if (!g_layer2.initialized) {
        fprintf(stderr, "[Layer2] Not initialized\n");
        return -1;
    }

    g_layer2.running = true;

    uint64_t interval_ns = (uint64_t)g_layer2.config.detection_interval_ms * 1000000ULL;
    uint64_t next_tick = get_current_time_ns() + interval_ns;

    printf("[Layer2] Detection lcore started\n");

    while (g_layer2.running) {
        detection_cycle();

        // P4 FIX: Timing with exponential backoff instead of tight busy-wait
        // Reduces CPU usage dramatically while maintaining timing accuracy
        next_tick += interval_ns;
        uint64_t now_ns = get_current_time_ns();
        int64_t remaining_ns = (int64_t)(next_tick - now_ns);

        if (remaining_ns > 0) {
            // Phase 1: Sleep for bulk of remaining time (90%)
            // This releases CPU for other work
            if (remaining_ns > 10000000) {  // > 10ms remaining
                struct timespec sleep_ts;
                int64_t sleep_ns = (remaining_ns * 9) / 10;  // Sleep 90%
                sleep_ts.tv_sec = sleep_ns / 1000000000;
                sleep_ts.tv_nsec = sleep_ns % 1000000000;
                nanosleep(&sleep_ts, NULL);
            }

            // Phase 2: Busy-wait with backoff for final precision
            int backoff = 1;
            while (get_current_time_ns() < next_tick && g_layer2.running) {
                // Pause with increasing iterations for exponential backoff
                for (int i = 0; i < backoff; i++) {
                    __asm__ volatile("pause" ::: "memory");
                }
                // Cap backoff at 64 iterations (~1mus on modern CPUs)
                if (backoff < 64) backoff <<= 1;
            }
        }
    }

    printf("[Layer2] Detection lcore stopped\n");
    return 0;
}

// ==================== Public API: Feature Input ====================

void layer2_set_feature_callback(layer2_feature_callback_t callback) {
    g_layer2.feature_callback = callback;
}

// ==================== Public API: Status ====================

void layer2_get_anomaly_state(struct l2_anomaly_state *state) {
    if (!state) return;

    pthread_mutex_lock(&g_layer2.lock);
    memcpy(state, &g_layer2.anomaly_state, sizeof(*state));
    pthread_mutex_unlock(&g_layer2.lock);
}

bool layer2_is_anomaly_active(void) {
    pthread_mutex_lock(&g_layer2.lock);
    bool active = g_layer2.anomaly_state.active;
    pthread_mutex_unlock(&g_layer2.lock);
    return active;
}

enum l2_anomaly_level layer2_get_anomaly_level(void) {
    pthread_mutex_lock(&g_layer2.lock);
    enum l2_anomaly_level level = g_layer2.anomaly_state.level;
    pthread_mutex_unlock(&g_layer2.lock);
    return level;
}

void layer2_get_baseline_summary(struct baseline_summary *summary) {
    if (!summary) return;

    pthread_mutex_lock(&g_layer2.lock);
    three_tier_baseline_summary(&g_layer2.baselines, summary);
    pthread_mutex_unlock(&g_layer2.lock);
}

void layer2_get_stats(struct layer2_stats *stats) {
    if (!stats) return;

    pthread_mutex_lock(&g_layer2.lock);
    stats->cycles = g_layer2.anomaly_state.cycle_count;
    stats->detections = g_layer2.anomaly_state.detection_count;
    stats->false_positive_corrections = g_layer2.anomaly_state.false_positive_corrections;
    stats->baseline_updates = g_layer2.baselines.total_updates;
    stats->uptime_sec = (double)(get_current_time_ns() - g_layer2.start_time_ns) / 1e9;
    pthread_mutex_unlock(&g_layer2.lock);
}

// ==================== Public API: Configuration ====================

const struct layer2_config *layer2_get_config(void) {
    return &g_layer2.config;
}

int layer2_reload_config(void) {
    int rc = layer2_config_reload();
    if (rc == 0) {
        // MF6 FIX: Also reload weights after config reload
        layer2_reload_weights();
    }
    return rc;
}

// MF6 FIX: Hot reload feature weights
int layer2_reload_weights(void) {
    if (!g_layer2.initialized) return -1;

    pthread_mutex_lock(&g_layer2.lock);

    // Get current config (may have been updated)
    const struct layer2_config *cfg = layer2_config_get();

    // Reload weights from config
    l2_feature_weights_reload(&g_layer2.weights,
                              cfg->feature_weights,
                              L2_MAX_FEATURES,
                              cfg->use_feature_weights);

    pthread_mutex_unlock(&g_layer2.lock);
    return 0;
}

int layer2_set_config(const char *key, const char *value) {
    if (!key || !value) return -1;

    pthread_mutex_lock(&g_layer2.lock);

    int rc = 0;
    char *endptr;

    if (strcmp(key, "z_score_threshold") == 0) {
        double val = strtod(value, &endptr);
        if (endptr == value || *endptr != '\0' || val < 1.0 || val > 15.0) {
            rc = -1;  // Invalid: not a number, or out of range
        } else {
            g_layer2.config.z_score_threshold = val;
        }
    } else if (strcmp(key, "min_tier_agreement") == 0) {
        long val = strtol(value, &endptr, 10);
        if (endptr == value || *endptr != '\0' || val < 1 || val > 3) {
            rc = -1;  // Invalid: not a number, or out of range
        } else {
            g_layer2.config.min_tier_agreement = (int)val;
        }
    } else if (strcmp(key, "cool_down_seconds") == 0) {
        double val = strtod(value, &endptr);
        if (endptr == value || *endptr != '\0' || val < 0.0 || val > 300.0) {
            rc = -1;  // Invalid: not a number, or out of range
        } else {
            g_layer2.config.cool_down_seconds = val;
        }
    } else if (strcmp(key, "log_detections") == 0) {
        if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) {
            g_layer2.config.log_detections = true;
        } else if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0) {
            g_layer2.config.log_detections = false;
        } else {
            rc = -1;  // Invalid: must be true/false/0/1
        }
    } else {
        rc = -1;
    }

    pthread_mutex_unlock(&g_layer2.lock);

    if (rc == 0) {
        printf("[Layer2] Config updated: %s = %s\n", key, value);
    }

    return rc;
}

// ==================== Public API: Baselines ====================

// P1 FIX: Use async save to avoid blocking detection thread
int layer2_save_baselines(void) {
    if (g_layer2.config.baseline_file[0] == '\0') {
        return -1;
    }

    pthread_mutex_lock(&g_layer2.lock);
    int rc = three_tier_baseline_save_async(&g_layer2.baselines, g_layer2.config.baseline_file);
    pthread_mutex_unlock(&g_layer2.lock);

    return rc;
}

// Synchronous save for shutdown (ensures data is written before exit)
int layer2_save_baselines_sync(void) {
    if (g_layer2.config.baseline_file[0] == '\0') {
        return -1;
    }

    pthread_mutex_lock(&g_layer2.lock);
    int rc = three_tier_baseline_save(&g_layer2.baselines, g_layer2.config.baseline_file);
    pthread_mutex_unlock(&g_layer2.lock);

    return rc;
}

int layer2_load_baselines(void) {
    if (g_layer2.config.baseline_file[0] == '\0') {
        return -1;
    }

    pthread_mutex_lock(&g_layer2.lock);
    int rc = three_tier_baseline_load(&g_layer2.baselines, g_layer2.config.baseline_file);
    pthread_mutex_unlock(&g_layer2.lock);

    return rc;
}

void layer2_reset_baselines(void) {
    pthread_mutex_lock(&g_layer2.lock);
    three_tier_baseline_reset(&g_layer2.baselines);
    pthread_mutex_unlock(&g_layer2.lock);

    printf("[Layer2] Baselines reset\n");
}

// ==================== Public API: Manual Control ====================

void layer2_force_anomaly(enum l2_anomaly_level level) {
    pthread_mutex_lock(&g_layer2.lock);
    l2_force_anomaly(&g_layer2.anomaly_state, level);
    pthread_mutex_unlock(&g_layer2.lock);

    anomaly_set_level((uint32_t)level);
}

void layer2_clear_anomaly(void) {
    pthread_mutex_lock(&g_layer2.lock);
    l2_clear_anomaly(&g_layer2.anomaly_state);
    pthread_mutex_unlock(&g_layer2.lock);

    anomaly_clear();
}

void layer2_freeze_baselines(void) {
    pthread_mutex_lock(&g_layer2.lock);
    three_tier_baseline_freeze(&g_layer2.baselines);
    pthread_mutex_unlock(&g_layer2.lock);

    printf("[Layer2] Baselines frozen manually\n");
}

void layer2_unfreeze_baselines(void) {
    pthread_mutex_lock(&g_layer2.lock);
    three_tier_baseline_unfreeze(&g_layer2.baselines);
    pthread_mutex_unlock(&g_layer2.lock);

    printf("[Layer2] Baselines unfrozen manually\n");
}

// ==================== Public API: Logging ====================

void layer2_print_status(void) {
    struct baseline_summary summary;
    layer2_get_baseline_summary(&summary);

    struct layer2_stats stats;
    layer2_get_stats(&stats);

    printf("\n=== Layer 2 Status ===\n");
    printf("Running: %s\n", g_layer2.running ? "yes" : "no");
    printf("Uptime: %.1f seconds\n", stats.uptime_sec);
    printf("Cycles: %lu\n", (unsigned long)stats.cycles);
    printf("Detections: %lu\n", (unsigned long)stats.detections);
    printf("\nAnomaly:\n");
    printf("  Active: %s\n", g_layer2.anomaly_state.active ? "YES" : "no");
    printf("  Level: %s\n", l2_anomaly_level_name(g_layer2.anomaly_state.level));
    printf("  Max Z-score: %.2f\n", g_layer2.anomaly_state.max_z_score);
    printf("\nBaselines:\n");
    printf("  Tier 1: %s (samples=%u mean=%.0f stddev=%.0f)\n",
           summary.tier1_ready ? "ready" : "learning",
           summary.tier1_samples,
           summary.tier1_pps_mean,
           summary.tier1_pps_stddev);
    printf("  Tier 2: %u/24 ready (current hour=%d)\n",
           summary.tier2_ready_count, summary.current_hour);
    printf("  Tier 3: %u/168 ready (current day=%d)\n",
           summary.tier3_ready_count, summary.current_day);
    printf("  Frozen: %s\n", summary.any_frozen ? "yes" : "no");
    printf("  Total updates: %u\n", summary.total_updates);
    printf("=====================\n\n");
}

void layer2_set_log_level(int level) {
    g_layer2.log_level = level;
}

// ==================== Per-IP Detection Implementation ====================

// Per-IP baseline table (global state)
static struct per_ip_baseline_table g_per_ip_baselines;
static bool g_per_ip_initialized = false;

/**
 * Initialize per-IP detection (lazy-initialized under g_layer2.lock on first
 * layer2_register_protected_ip() / layer2_load_per_ip_baselines(); per-destination
 * detection activates only for registered assets).
 */
static void per_ip_detection_init(void) {
    if (g_per_ip_initialized) return;

    per_ip_baseline_table_init(&g_per_ip_baselines);
    g_per_ip_initialized = true;

    // Try to load saved per-IP baselines
    char per_ip_baseline_file[512];
    snprintf(per_ip_baseline_file, sizeof(per_ip_baseline_file),
             "%s.per_ip", g_layer2.config.baseline_file);
    per_ip_baseline_load(&g_per_ip_baselines, per_ip_baseline_file);

    printf("[Layer2] Per-IP detection initialized (max_ips=%d)\n", L2_MAX_PROTECTED_IPS);
}

int layer2_register_protected_ip(uint32_t dst_ip) {
    if (!g_layer2.initialized) return -1;

    pthread_mutex_lock(&g_layer2.lock);
    /* lazy-init under the lock so concurrent registers cannot double-init. */
    if (!g_per_ip_initialized) per_ip_detection_init();

    int rc = per_ip_baseline_register(&g_per_ip_baselines, dst_ip,
                                      g_layer2.config.alpha_immediate,
                                      g_layer2.config.alpha_hourly,
                                      g_layer2.config.alpha_weekly,
                                      g_layer2.config.min_samples_immediate,
                                      g_layer2.config.min_samples_hourly,
                                      g_layer2.config.min_samples_weekly);

    pthread_mutex_unlock(&g_layer2.lock);
    return rc;
}

int layer2_unregister_protected_ip(uint32_t dst_ip) {
    if (!g_layer2.initialized || !g_per_ip_initialized) return -1;

    pthread_mutex_lock(&g_layer2.lock);
    int rc = per_ip_baseline_unregister(&g_per_ip_baselines, dst_ip);
    pthread_mutex_unlock(&g_layer2.lock);

    return rc;
}

int layer2_get_per_ip_anomaly_state(uint32_t dst_ip, struct l2_anomaly_state *state) {
    if (!state || !g_layer2.initialized || !g_per_ip_initialized) return -1;

    pthread_mutex_lock(&g_layer2.lock);

    struct per_ip_anomaly_result *result = per_ip_anomaly_lookup(&g_per_ip_baselines, dst_ip);
    if (!result) {
        pthread_mutex_unlock(&g_layer2.lock);
        return -1;
    }

    // Convert per_ip_anomaly_result to l2_anomaly_state
    memset(state, 0, sizeof(*state));
    state->active = result->anomaly_detected;
    state->level = (enum l2_anomaly_level)result->anomaly_level;
    state->max_z_score = result->max_z_score;
    state->start_time_ns = result->anomaly_start_ns;

    pthread_mutex_unlock(&g_layer2.lock);
    return 0;
}

bool layer2_is_per_ip_anomaly_active(uint32_t dst_ip) {
    if (!g_layer2.initialized || !g_per_ip_initialized) return false;

    pthread_mutex_lock(&g_layer2.lock);

    struct per_ip_anomaly_result *result = per_ip_anomaly_lookup(&g_per_ip_baselines, dst_ip);
    bool active = result ? result->anomaly_detected : false;

    pthread_mutex_unlock(&g_layer2.lock);
    return active;
}

enum l2_anomaly_level layer2_get_per_ip_anomaly_level(uint32_t dst_ip) {
    if (!g_layer2.initialized || !g_per_ip_initialized) return L2_ANOMALY_NONE;

    pthread_mutex_lock(&g_layer2.lock);

    struct per_ip_anomaly_result *result = per_ip_anomaly_lookup(&g_per_ip_baselines, dst_ip);
    enum l2_anomaly_level level = result ? (enum l2_anomaly_level)result->anomaly_level : L2_ANOMALY_NONE;

    pthread_mutex_unlock(&g_layer2.lock);
    return level;
}

uint32_t layer2_get_protected_ip_count(void) {
    if (!g_per_ip_initialized) return 0;
    return per_ip_baseline_count(&g_per_ip_baselines);
}

uint32_t layer2_get_all_per_ip_anomaly_states(struct per_ip_anomaly_result *out,
                                              uint32_t max_count) {
    if (!out || !g_per_ip_initialized) return 0;

    pthread_mutex_lock(&g_layer2.lock);

    uint32_t count = 0;
    for (uint32_t i = 0; i < L2_MAX_PROTECTED_IPS && count < max_count; i++) {
        if (g_per_ip_baselines.anomaly[i].active) {
            memcpy(&out[count], &g_per_ip_baselines.anomaly[i], sizeof(out[count]));
            count++;
        }
    }

    pthread_mutex_unlock(&g_layer2.lock);
    return count;
}

void layer2_force_per_ip_anomaly(uint32_t dst_ip, enum l2_anomaly_level level) {
    if (!g_layer2.initialized || !g_per_ip_initialized) return;

    pthread_mutex_lock(&g_layer2.lock);

    struct per_ip_anomaly_result *result = per_ip_anomaly_lookup(&g_per_ip_baselines, dst_ip);
    if (result) {
        result->anomaly_detected = (level != L2_ANOMALY_NONE);
        result->anomaly_level = (uint32_t)level;
        result->last_update_ns = get_current_time_ns();
        if (result->anomaly_detected && result->anomaly_start_ns == 0) {
            result->anomaly_start_ns = get_current_time_ns();
        }
    }

    pthread_mutex_unlock(&g_layer2.lock);

    // Also update shared memory
    per_ip_anomaly_set(dst_ip, (uint32_t)level, 0.0, 0, 0);
}

void layer2_clear_per_ip_anomaly(uint32_t dst_ip) {
    if (!g_layer2.initialized || !g_per_ip_initialized) return;

    pthread_mutex_lock(&g_layer2.lock);

    struct per_ip_anomaly_result *result = per_ip_anomaly_lookup(&g_per_ip_baselines, dst_ip);
    if (result) {
        result->anomaly_detected = false;
        result->anomaly_level = L2_ANOMALY_NONE;
        result->max_z_score = 0.0;
        result->tier_agreement = 0;
        result->anomalous_feature_count = 0;
        result->anomaly_start_ns = 0;
        result->last_update_ns = get_current_time_ns();
    }

    pthread_mutex_unlock(&g_layer2.lock);

    // Also update shared memory
    per_ip_anomaly_clear(dst_ip);
}

void layer2_freeze_per_ip_baselines(uint32_t dst_ip) {
    if (!g_layer2.initialized || !g_per_ip_initialized) return;

    pthread_mutex_lock(&g_layer2.lock);

    struct per_ip_baseline *entry = per_ip_baseline_lookup(&g_per_ip_baselines, dst_ip);
    if (entry) {
        three_tier_baseline_freeze(&entry->baselines);
    }

    pthread_mutex_unlock(&g_layer2.lock);
}

void layer2_unfreeze_per_ip_baselines(uint32_t dst_ip) {
    if (!g_layer2.initialized || !g_per_ip_initialized) return;

    pthread_mutex_lock(&g_layer2.lock);

    struct per_ip_baseline *entry = per_ip_baseline_lookup(&g_per_ip_baselines, dst_ip);
    if (entry) {
        three_tier_baseline_unfreeze(&entry->baselines);
    }

    pthread_mutex_unlock(&g_layer2.lock);
}

int layer2_save_per_ip_baselines(void) {
    if (!g_per_ip_initialized) return -1;
    if (g_layer2.config.baseline_file[0] == '\0') return -1;

    char per_ip_baseline_file[512];
    snprintf(per_ip_baseline_file, sizeof(per_ip_baseline_file),
             "%s.per_ip", g_layer2.config.baseline_file);

    pthread_mutex_lock(&g_layer2.lock);
    int rc = per_ip_baseline_save(&g_per_ip_baselines, per_ip_baseline_file);
    pthread_mutex_unlock(&g_layer2.lock);

    return rc;
}

int layer2_load_per_ip_baselines(void) {
    if (g_layer2.config.baseline_file[0] == '\0') return -1;

    char per_ip_baseline_file[512];
    snprintf(per_ip_baseline_file, sizeof(per_ip_baseline_file),
             "%s.per_ip", g_layer2.config.baseline_file);

    pthread_mutex_lock(&g_layer2.lock);
    /* lazy-init under the lock so concurrent callers cannot double-init. */
    if (!g_per_ip_initialized) per_ip_detection_init();
    int rc = per_ip_baseline_load(&g_per_ip_baselines, per_ip_baseline_file);
    pthread_mutex_unlock(&g_layer2.lock);

    return rc;
}

void layer2_reset_per_ip_baselines(void) {
    if (!g_per_ip_initialized) return;

    pthread_mutex_lock(&g_layer2.lock);
    per_ip_baseline_table_reset(&g_per_ip_baselines);
    pthread_mutex_unlock(&g_layer2.lock);

    printf("[Layer2] Per-IP baselines reset\n");
}

// ==================== Per-IP Detection Cycle ====================

/**
 * Convert l2_per_ip_features_export to l2_feature_snapshot
 */
static void per_ip_features_to_snapshot(const struct l2_per_ip_features_export *in,
                                         struct l2_feature_snapshot *out) {
    out->timestamp_ns = in->timestamp_ns;

    // ===== VOLUME FEATURES (3) =====
    out->values[L2_FEAT_PACKETS_PER_SEC] = (double)in->packets_per_sec;
    out->values[L2_FEAT_BYTES_PER_SEC] = (double)in->bytes_per_sec;
    out->values[L2_FEAT_FLOWS_PER_SEC] = (double)in->flows_per_sec;

    // ===== TCP FLAG FEATURES (5) =====
    out->values[L2_FEAT_SYN_PER_SEC] = (double)in->syn_per_sec;
    out->values[L2_FEAT_SYN_ACK_PER_SEC] = (double)in->syn_ack_per_sec;
    out->values[L2_FEAT_ACK_PER_SEC] = (double)in->ack_per_sec;
    out->values[L2_FEAT_RST_PER_SEC] = (double)in->rst_per_sec;
    out->values[L2_FEAT_FIN_PER_SEC] = (double)in->fin_per_sec;

    // ===== PROTOCOL MIX FEATURES (4) =====
    out->values[L2_FEAT_TCP_RATIO] = (double)in->tcp_ratio;
    out->values[L2_FEAT_UDP_RATIO] = (double)in->udp_ratio;
    out->values[L2_FEAT_ICMP_RATIO] = (double)in->icmp_ratio;
    // Compute other_ratio
    int other = 100 - (int)in->tcp_ratio - (int)in->udp_ratio - (int)in->icmp_ratio;
    out->values[L2_FEAT_OTHER_RATIO] = (other > 0 && other <= 100) ? (double)other : 0.0;

    // ===== RATIO FEATURES (3) =====
    out->values[L2_FEAT_SYN_ACK_RATIO] = (double)in->syn_ack_ratio;
    out->values[L2_FEAT_RST_SYN_RATIO] = (double)in->rst_syn_ratio;
    out->values[L2_FEAT_BYTES_PER_PACKET] = (double)in->bytes_per_packet;

    // ===== CARDINALITY FEATURES (3) =====
    out->values[L2_FEAT_UNIQUE_SRC_IPS] = (double)in->unique_src_ips;
    out->values[L2_FEAT_UNIQUE_DST_PORTS] = (double)in->unique_dst_ports;
    out->values[L2_FEAT_UNIQUE_FLOWS] = (double)in->unique_flows;

    // ===== CHURN FEATURES (1) =====
    out->values[L2_FEAT_NEW_SRCIP_RATE] = (double)in->src_ip_churn;

    // ===== CONCENTRATION FEATURES (3) =====
    out->values[L2_FEAT_MAX_FLOW_FRACTION] = (double)in->max_flow_fraction;
    out->values[L2_FEAT_TOPK_FLOW_SHARE] = (double)in->topk_flow_share;
    out->values[L2_FEAT_HEAVY_HITTER_COUNT] = (double)in->heavy_hitter_count;

    // ===== FLOW BEHAVIOR FEATURES (2) =====
    out->values[L2_FEAT_AVG_PACKETS_PER_FLOW] = (double)in->avg_packets_per_flow;
    out->values[L2_FEAT_FLOW_DURATION_AVG] = (double)in->flow_duration_avg_ms;

    // ===== TCP FLAG RATIO FEATURES (5) =====
    // Derive from flag rates and tcp_packets window count using window duration
    {
        double window_sec = (in->window_duration_ns > 0)
                            ? (double)in->window_duration_ns / 1e9 : 1.0;
        double tcp_count = (double)in->tcp_packets;
        if (tcp_count > 0.0) {
            out->values[L2_FEAT_SYN_TCP_RATIO]    = fmin(100.0, (double)in->syn_per_sec    * window_sec * 100.0 / tcp_count);
            out->values[L2_FEAT_SYNACK_TCP_RATIO]  = fmin(100.0, (double)in->syn_ack_per_sec * window_sec * 100.0 / tcp_count);
            out->values[L2_FEAT_ACK_TCP_RATIO]     = fmin(100.0, (double)in->ack_per_sec    * window_sec * 100.0 / tcp_count);
            out->values[L2_FEAT_RST_TCP_RATIO]     = fmin(100.0, (double)in->rst_per_sec    * window_sec * 100.0 / tcp_count);
            out->values[L2_FEAT_FIN_TCP_RATIO]     = fmin(100.0, (double)in->fin_per_sec    * window_sec * 100.0 / tcp_count);
        } else {
            out->values[L2_FEAT_SYN_TCP_RATIO]    = 0.0;
            out->values[L2_FEAT_SYNACK_TCP_RATIO]  = 0.0;
            out->values[L2_FEAT_ACK_TCP_RATIO]     = 0.0;
            out->values[L2_FEAT_RST_TCP_RATIO]     = 0.0;
            out->values[L2_FEAT_FIN_TCP_RATIO]     = 0.0;
        }
    }

    // ===== VOLUME EXTENDED (1) =====
    // burst_factor (Phase 2): per-IP EWMA ratio exported by Layer 1 --
    // 100 * window_pps / post-update per-IP EWMA, bounded by 100/alpha (burst_ewma.h).
    out->values[L2_FEAT_BURST_FACTOR] = (double)in->burst_factor;

    // ===== FLOW BEHAVIOR EXTENDED (1) =====
    // udp_flow_ratio not tracked per-IP; zero until Phase 2
    out->values[L2_FEAT_UDP_FLOW_RATIO] = 0.0;

    // ===== PROTOCOL MIX EXTENDED (1) =====
    // icmp_echo_ratio not tracked per-IP; zero until Phase 2
    out->values[L2_FEAT_ICMP_ECHO_RATIO] = 0.0;

    // ===== CARDINALITY EXTENDED (1) =====
    // dst_port_density: unique_dst_ports / PPS * 1000
    out->values[L2_FEAT_DST_PORT_DENSITY] = (in->packets_per_sec > 0)
        ? fmin(65535.0, (double)in->unique_dst_ports * 1000.0 / (double)in->packets_per_sec)
        : 0.0;

    // ===== ENTROPY FEATURES (2) =====
    // src_ip_entropy and src_port_entropy not in per-IP export; zero until Phase 2
    out->values[L2_FEAT_SRC_IP_ENTROPY]   = 0.0;
    out->values[L2_FEAT_SRC_PORT_ENTROPY] = 0.0;

    // ===== PACKET CHARACTERISTICS (3) =====
    // Not tracked in per-IP shared memory export; zero until Phase 2
    out->values[L2_FEAT_SMALL_PKT_RATIO] = 0.0;
    out->values[L2_FEAT_FRAGMENT_RATIO]  = 0.0;
    out->values[L2_FEAT_TTL_MEAN]        = 0.0;

    // ===== RATIO EXTENDED (1) =====
    // tcp_completion_rate: SYN-ACK / SYN * 100
    out->values[L2_FEAT_TCP_COMPLETION_RATE] = (in->syn_per_sec > 0)
        ? fmin(100.0, (double)in->syn_ack_per_sec * 100.0 / (double)in->syn_per_sec)
        : 100.0;
}

/**
 * Run per-IP detection cycle for all protected IPs
 * Call this from the main detection cycle
 */
void layer2_per_ip_detection_cycle(void) {
    if (!g_per_ip_initialized) return;

    // Read per-IP features from shared memory
    struct l2_per_ip_export *per_ip_export = l2_per_ip_export_get();
    if (!per_ip_export) return;

    // Consistent snapshot of the per-IP feature export via a full seqlock retry.
    // The detection loop below has side effects (baseline updates, anomaly writes)
    // and cannot be safely replayed, so we copy the features into a stable local
    // buffer FIRST, then process the copy. The previous odd-check-only read could
    // still observe a half-written export (a torn record while Layer 1 writes it),
    // so we re-check the version AFTER the copy and retry if it changed. Single
    // detection thread + g_layer2.lock means the static buffer is safe and avoids
    // a 16 KB stack frame.
    static struct l2_per_ip_features_export snap_features[MAX_PROTECTED_IPS_EXPORT];
    uint32_t active_count = 0;
    bool snap_ok = false;
    for (int attempt = 0; attempt < 4; attempt++) {
        uint64_t v0 = __atomic_load_n(&per_ip_export->version, __ATOMIC_ACQUIRE);
        if (v0 & 1) continue;  // writer mid-update; retry
        uint32_t cnt = per_ip_export->active_count;
        if (cnt > MAX_PROTECTED_IPS_EXPORT) cnt = MAX_PROTECTED_IPS_EXPORT;
        memcpy(snap_features, per_ip_export->features, sizeof(snap_features));
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&per_ip_export->version, __ATOMIC_ACQUIRE) == v0) {
            active_count = cnt;
            snap_ok = true;
            break;
        }
    }
    if (!snap_ok) return;  // no stable snapshot this cycle; skip rather than act on torn data

    pthread_mutex_lock(&g_layer2.lock);

    // Process each active protected IP
    for (uint32_t i = 0; i < active_count && i < MAX_PROTECTED_IPS_EXPORT; i++) {
        const struct l2_per_ip_features_export *features = &snap_features[i];
        if (!features->active) continue;

        uint32_t dst_ip = features->dst_ip;

        // Get or register this IP's baseline
        struct per_ip_baseline *baseline = per_ip_baseline_lookup(&g_per_ip_baselines, dst_ip);
        if (!baseline) {
            // Auto-register new protected IPs from Layer 1
            per_ip_baseline_register(&g_per_ip_baselines, dst_ip,
                                     g_layer2.config.alpha_immediate,
                                     g_layer2.config.alpha_hourly,
                                     g_layer2.config.alpha_weekly,
                                     g_layer2.config.min_samples_immediate,
                                     g_layer2.config.min_samples_hourly,
                                     g_layer2.config.min_samples_weekly);
            baseline = per_ip_baseline_lookup(&g_per_ip_baselines, dst_ip);
            if (!baseline) continue;
        }

        // Convert to snapshot
        struct l2_feature_snapshot snapshot;
        per_ip_features_to_snapshot(features, &snapshot);
        if (snapshot.timestamp_ns == 0) {
            snapshot.timestamp_ns = get_current_time_ns();
        }

        // Run detection for this IP
        struct detection_result result;
        memset(&result, 0, sizeof(result));

        l2_detect_anomaly(&baseline->baselines, &snapshot,
                          g_layer2.config.z_score_threshold,
                          g_layer2.config.min_tier_agreement,
                          &result);

        // also run CUSUM + JSD on this IP's own
        // detector state, mirroring detection_cycle_advanced (layer2.c:516)
        // which the global path uses. Pre-fix the per-IP path ran z-tier
        // voting only, so slow-rate and protocol-mix attacks (Slowloris,
        // GoldenEye, application-layer DoS on individual victims) escaped
        // until the global aggregate tripped -- too coarse for per-IP
        // mitigation. We OR-merge the advanced-detection alarms into the
        // z-tier result so a CUSUM or JSD alarm on this IP elevates it
        // to detected even when z-tier voting wouldn't.
        if (g_layer2.use_per_ip_advanced_detection &&
            baseline->cusum && baseline->jsd) {
            struct advanced_detection_result adv;
            memset(&adv, 0, sizeof(adv));
            const struct tier_baseline *t1 = &baseline->baselines.immediate;
            l2_advanced_detect(t1, &snapshot,
                               baseline->cusum,
                               baseline->jsd,
                               &g_layer2.weights,
                               g_layer2.config.z_score_threshold,
                               g_layer2.config.jsd_threshold,
                               &adv);
            bool cusum_trig = (adv.cusum_triggered_count > 0);
            bool jsd_trig   = adv.jsd_triggered;

            // AUTHORITATIVE the innovation-gate prototype PER-DESTINATION innovation gate (off by default). Gate ONLY
            // this IP's z-path on this IP's OWN surprise latch; CUSUM/JSD stay ungated. The
            // decision below becomes (z AND latch) OR CUSUM OR JSD, exactly the harness the innovation-gate prototype
            // (the offline prototype). At this point result.detected is the
            // pure z-tier decision (the CUSUM/JSD OR-merge happens just below), so suppressing
            // it here gates the z-path alone.
            if (g_layer2.config.ensemble_rule == L2_ENSEMBLE_RULE_INNOVATION_GATE) {
                // Lazily allocate + init this IP's gate on first use (config-driven kappa /
                // hysteresis; MIN_CALIB=10 is a FLOOR -- arming is driven by warm_complete below).
                if (!baseline->innovation) {
                    baseline->innovation =
                        (struct innovation_gate *)calloc(1, sizeof(struct innovation_gate));
                    if (baseline->innovation) {
                        l2_innovation_gate_init(baseline->innovation,
                                                g_layer2.config.innovation_gate_kappa,
                                                g_layer2.config.innovation_gate_hysteresis,
                                                10 /* MIN_CALIB floor */);
                    }
                }
                if (baseline->innovation) {
                    struct innovation_gate *ig = baseline->innovation;
                    // Calibration is hooked into this IP's baseline WARMUP (the innovation-gate prototype fidelity): fit
                    // gbar/gstd + mu_S/sigma_S on benign windows over the FULL benign warmup, then
                    // FREEZE + ARM once the warmup is complete. "benign" = the shipped B0 rule
                    // found nothing (z OR CUSUM OR JSD) and the baseline is not frozen -- the same
                    // label-free benign proxy the baseline update gate uses below. WARM-COMPLETE =
                    // this IP's Tier-2 (hourly) baseline fully ready (a full day-of-week benign
                    // cycle), the deployment analog of the harness "full benign-train" calibration
                    // -- a fixed ~10-window calibration recovered only ~22% of the FPR cut,
                    // calibrating over the full warmup recovers 100%. The gate stays FAIL-OPEN the
                    // whole warmup; the min_calib floor keeps a degenerate near-zero-benign IP
                    // fail-open (it never arms).
                    bool frozen = per_ip_baseline_is_frozen(&g_per_ip_baselines);
                    bool b0_benign = !frozen &&
                                     !(result.detected || cusum_trig || jsd_trig);
                    bool warm_complete =
                        ig_baseline_warm_complete(&baseline->baselines);
                    bool calibrate = b0_benign && !warm_complete;
                    bool latch_open = l2_innovation_gate_update(ig, snapshot.values,
                                                                L2_MAX_FEATURES,
                                                                calibrate, warm_complete);
                    if (result.detected && !latch_open) {
                        result.detected = false;  // z-path fired but unsurprising -> suppress
                    }
                }
            }

            // Promote CUSUM / JSD alarms into result.detected so the per-IP
            // anomaly state machine downstream can act on them. CUSUM/JSD are
            // UNGATED under the innovation-gate prototype, so this OR-merge completes (z AND latch) OR CUSUM OR JSD.
            if (cusum_trig || jsd_trig) {
                result.detected = true;
                if (result.level < L2_ANOMALY_MEDIUM) {
                    result.level = L2_ANOMALY_MEDIUM;
                }
            }
            // Update per-IP JSD baseline on benign traffic only (skip while
            // this IP is in an active anomaly state). Mirrors layer2.c:530-537
            // for the global path.
            struct per_ip_anomaly_result *anom_for_jsd =
                per_ip_anomaly_lookup(&g_per_ip_baselines, dst_ip);
            if (!anom_for_jsd || !anom_for_jsd->anomaly_detected) {
                struct protocol_distribution current_dist;
                protocol_dist_from_ratios(&current_dist,
                                          (uint8_t)snapshot.values[L2_FEAT_TCP_RATIO],
                                          (uint8_t)snapshot.values[L2_FEAT_UDP_RATIO],
                                          (uint8_t)snapshot.values[L2_FEAT_ICMP_RATIO],
                                          (uint8_t)snapshot.values[L2_FEAT_OTHER_RATIO]);
                jsd_baseline_update(baseline->jsd, &current_dist);
            }
        }

        // Apply per-IP feature mask if configured
        pthread_mutex_lock(&g_per_ip_weights_lock);
        const double *ip_weights = lookup_per_ip_weights(dst_ip);
        if (ip_weights) {
            double weights_copy[L2_MAX_FEATURES];
            memcpy(weights_copy, ip_weights, sizeof(weights_copy));
            pthread_mutex_unlock(&g_per_ip_weights_lock);
            apply_feature_mask_to_result(&result, weights_copy,
                                         g_layer2.config.z_score_threshold,
                                         g_layer2.config.min_tier_agreement);
        } else {
            pthread_mutex_unlock(&g_per_ip_weights_lock);
        }

        // Update per-IP anomaly state
        struct per_ip_anomaly_result *anom = per_ip_anomaly_lookup(&g_per_ip_baselines, dst_ip);
        if (anom) {
            bool was_active = anom->anomaly_detected;

            anom->anomaly_detected = result.detected;
            anom->anomaly_level = (uint32_t)result.level;
            anom->max_z_score = result.max_z_score;
            anom->tier_agreement = result.tier_agreement;
            anom->anomalous_feature_count = result.triggered_feature_count;
            anom->last_update_ns = get_current_time_ns();

            if (result.detected && !was_active) {
                anom->anomaly_start_ns = get_current_time_ns();
            }

            // Update shared memory with protocol-specific info
            if (result.detected) {
                // Classify attack type and extract protocol info
                struct attack_classification classification;
                l2_classify_attack(&snapshot, result.z_tier1.z, &result, &classification);

                // Get protocol category and attack type for Layer 3
                uint8_t proto_cat;
                uint8_t attack_type;
                uint16_t dst_port;
                uint8_t secondary_proto_cat;

                l2_get_protocol_info(&classification, &snapshot,
                                     &proto_cat, &attack_type,
                                     &dst_port, &secondary_proto_cat);

                // Use extended function with protocol info
                per_ip_anomaly_set_ex(dst_ip, (uint32_t)result.level, result.max_z_score,
                                      result.tier_agreement, result.triggered_feature_count,
                                      proto_cat, attack_type, dst_port);

                // For hybrid/multi-protocol attacks (PROTO_CAT_ALL),
                // Layer 3 will analyze all protocols.
                // Log hybrid detection for visibility
                if (classification.is_multi_vector) {
                    char types_str[128];
                    l2_attack_types_to_string(classification.detected_types, types_str, sizeof(types_str));
                    printf("[Layer2] Hybrid attack on IP %08x: %s\n", dst_ip, types_str);
                }
            } else if (was_active) {
                per_ip_anomaly_clear(dst_ip);
            }
        }

        // Update baselines unless globally frozen or this IP is per-IP anomalous.
        if (!per_ip_baseline_is_frozen(&g_per_ip_baselines) &&
            (!anom || !anom->anomaly_detected)) {
            per_ip_baseline_update(&g_per_ip_baselines, dst_ip, &snapshot);
        }
    }

    pthread_mutex_unlock(&g_layer2.lock);
}
