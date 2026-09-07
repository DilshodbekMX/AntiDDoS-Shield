#include "baselines.h"
#include "config/layer2_config.h"
#include "advanced_detection.h"  /* cusum_detector_init + jsd_baseline_init for per-IP state */
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <float.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

// ==================== P1 FIX: Async Save ====================
// Background thread for JSON serialization to avoid blocking detection thread

struct async_save_context {
    char *json;         // Serialized JSON (caller allocates)
    char filepath[512]; // Destination path
    uint32_t updates;   // For logging
};

static void *async_save_thread(void *arg) {
    struct async_save_context *ctx = (struct async_save_context *)arg;
    if (!ctx || !ctx->json) {
        free(ctx);
        return NULL;
    }

    // Perform file write in background
    char temp_filepath[512];
    int n = snprintf(temp_filepath, sizeof(temp_filepath), "%s.tmp.%d",
                     ctx->filepath, (int)getpid());
    if (n < 0 || (size_t)n >= sizeof(temp_filepath)) {
        free(ctx->json);
        free(ctx);
        return NULL;
    }

    FILE *f = fopen(temp_filepath, "w");
    if (!f) {
        free(ctx->json);
        free(ctx);
        return NULL;
    }

    size_t len = strlen(ctx->json);
    size_t written = fwrite(ctx->json, 1, len, f);

    if (fflush(f) != 0 || fsync(fileno(f)) != 0 || written != len) {
        fclose(f);
        unlink(temp_filepath);
        free(ctx->json);
        free(ctx);
        return NULL;
    }

    fclose(f);
    free(ctx->json);

    // Atomic rename
    if (rename(temp_filepath, ctx->filepath) != 0) {
        fprintf(stderr, "[Layer2] Async save failed: %s\n", strerror(errno));
        unlink(temp_filepath);
    } else {
        printf("[Layer2] Baselines saved async to %s (%u updates)\n",
               ctx->filepath, ctx->updates);
    }

    free(ctx);
    return NULL;
}

// ==================== Feature Names (39 features) ====================

const char *l2_feature_names[L2_MAX_FEATURES] = {
    // Volume (3)
    [L2_FEAT_PACKETS_PER_SEC]      = "packets_per_sec",
    [L2_FEAT_BYTES_PER_SEC]        = "bytes_per_sec",
    [L2_FEAT_FLOWS_PER_SEC]        = "flows_per_sec",

    // TCP Flags (5)
    [L2_FEAT_SYN_PER_SEC]          = "syn_per_sec",
    [L2_FEAT_SYN_ACK_PER_SEC]      = "syn_ack_per_sec",
    [L2_FEAT_ACK_PER_SEC]          = "ack_per_sec",
    [L2_FEAT_RST_PER_SEC]          = "rst_per_sec",
    [L2_FEAT_FIN_PER_SEC]          = "fin_per_sec",

    // Protocol Mix (4)
    [L2_FEAT_TCP_RATIO]            = "tcp_ratio",
    [L2_FEAT_UDP_RATIO]            = "udp_ratio",
    [L2_FEAT_ICMP_RATIO]           = "icmp_ratio",
    [L2_FEAT_OTHER_RATIO]          = "other_ratio",

    // Ratios (3)
    [L2_FEAT_SYN_ACK_RATIO]        = "syn_ack_ratio",
    [L2_FEAT_RST_SYN_RATIO]        = "rst_syn_ratio",
    [L2_FEAT_BYTES_PER_PACKET]     = "bytes_per_packet",

    // Cardinality (3)
    [L2_FEAT_UNIQUE_SRC_IPS]       = "unique_src_ips",
    [L2_FEAT_UNIQUE_DST_PORTS]     = "unique_dst_ports",
    [L2_FEAT_UNIQUE_FLOWS]         = "unique_flows",

    // Churn (1)
    [L2_FEAT_NEW_SRCIP_RATE]       = "new_srcip_rate",

    // Concentration (3)
    [L2_FEAT_MAX_FLOW_FRACTION]    = "max_flow_fraction",
    [L2_FEAT_TOPK_FLOW_SHARE]      = "topk_flow_share",
    [L2_FEAT_HEAVY_HITTER_COUNT]   = "heavy_hitter_count",

    // Flow Behavior (2)
    [L2_FEAT_AVG_PACKETS_PER_FLOW] = "avg_packets_per_flow",
    [L2_FEAT_FLOW_DURATION_AVG]    = "flow_duration_avg",

    // TCP Flag Ratios (5)
    [L2_FEAT_SYN_TCP_RATIO]        = "syn_tcp_ratio",
    [L2_FEAT_SYNACK_TCP_RATIO]     = "synack_tcp_ratio",
    [L2_FEAT_ACK_TCP_RATIO]        = "ack_tcp_ratio",
    [L2_FEAT_RST_TCP_RATIO]        = "rst_tcp_ratio",
    [L2_FEAT_FIN_TCP_RATIO]        = "fin_tcp_ratio",

    // Volume Extended (1)
    [L2_FEAT_BURST_FACTOR]         = "burst_factor",

    // Flow Behavior Extended (1)
    [L2_FEAT_UDP_FLOW_RATIO]       = "udp_flow_ratio",

    // Protocol Mix Extended (1)
    [L2_FEAT_ICMP_ECHO_RATIO]      = "icmp_echo_ratio",

    // Cardinality Extended (1)
    [L2_FEAT_DST_PORT_DENSITY]     = "dst_port_density",

    // Entropy (2)
    [L2_FEAT_SRC_IP_ENTROPY]       = "src_ip_entropy",
    [L2_FEAT_SRC_PORT_ENTROPY]     = "src_port_entropy",

    // Packet Characteristics (3)
    [L2_FEAT_SMALL_PKT_RATIO]      = "small_pkt_ratio",
    [L2_FEAT_FRAGMENT_RATIO]       = "fragment_ratio",
    [L2_FEAT_TTL_MEAN]             = "ttl_mean",

    // Ratio Extended (1)
    [L2_FEAT_TCP_COMPLETION_RATE]  = "tcp_completion_rate",
};

// ==================== Helper Functions ====================
// P2 FIX: get_current_time_ns() now in baselines.h as inline

// ==================== Initialization ====================

void feature_baseline_init(struct feature_baseline *fb) {
    if (!fb) return;

    fb->mean = 0.0;
    fb->variance = 0.0;
    fb->min_observed = DBL_MAX;
    fb->max_observed = -DBL_MAX;
    fb->sample_count = 0;
    fb->last_update_ns = 0;
}

void tier_baseline_init(struct tier_baseline *tier, const char *name,
                        double alpha, uint32_t min_samples) {
    if (!tier) return;

    memset(tier, 0, sizeof(*tier));
    strncpy(tier->name, name, sizeof(tier->name) - 1);
    tier->name[sizeof(tier->name) - 1] = '\0';  // Ensure null termination
    tier->alpha = alpha;
    tier->frozen = false;
    tier->ready = false;
    tier->min_samples_ready = min_samples;

    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        feature_baseline_init(&tier->features[i]);
    }
}

void three_tier_baseline_init(struct three_tier_baseline *baselines,
                              double alpha_immediate,
                              double alpha_hourly,
                              double alpha_weekly,
                              uint32_t min_samples_immediate,
                              uint32_t min_samples_hourly,
                              uint32_t min_samples_weekly) {
    if (!baselines) return;

    memset(baselines, 0, sizeof(*baselines));

    // Tier 1: Immediate
    tier_baseline_init(&baselines->immediate, "immediate",
                       alpha_immediate, min_samples_immediate);

    // Tier 2: Hourly (24 baselines)
    for (int h = 0; h < 24; h++) {
        char name[32];
        snprintf(name, sizeof(name), "hourly_%02d", h);
        tier_baseline_init(&baselines->hourly[h], name,
                          alpha_hourly, min_samples_hourly);
    }

    // Tier 3: Weekly (168 baselines = 7 days x 24 hours)
    for (int d = 0; d < 7; d++) {
        for (int h = 0; h < 24; h++) {
            int idx = d * 24 + h;
            char name[32];
            snprintf(name, sizeof(name), "weekly_%d_%02d", d, h);
            tier_baseline_init(&baselines->weekly[idx], name,
                              alpha_weekly, min_samples_weekly);
        }
    }

    baselines->creation_time_ns = get_current_time_ns();
    baselines->last_save_time_ns = 0;
    baselines->total_updates = 0;
}

// ==================== EWMA Update ====================

void feature_baseline_update(struct feature_baseline *fb,
                             double value,
                             double alpha,
                             uint64_t timestamp_ns) {
    if (!fb) return;

    if (fb->sample_count == 0) {
        // First sample - initialize
        fb->mean = value;
        fb->variance = 0.0;
    } else {
        // EWMA update
        double delta = value - fb->mean;
        fb->mean += alpha * delta;

        // Welford's method adapted for EWMA
        // variance = (1 - alpha) * (variance + alpha * delta^2)
        fb->variance = (1.0 - alpha) * (fb->variance + alpha * delta * delta);
    }

    // Update min/max
    if (value < fb->min_observed) {
        fb->min_observed = value;
    }
    if (value > fb->max_observed) {
        fb->max_observed = value;
    }

    fb->sample_count++;
    fb->last_update_ns = timestamp_ns;
}

/**
 * Check if feature should use log-transform for baseline updates
 * Cardinality features have multiplicative growth patterns
 */
static inline bool feature_uses_log_transform(int feature_idx) {
    return (feature_idx == L2_FEAT_UNIQUE_SRC_IPS ||
            feature_idx == L2_FEAT_UNIQUE_DST_PORTS ||
            feature_idx == L2_FEAT_UNIQUE_FLOWS);
}

void tier_baseline_update(struct tier_baseline *tier,
                          const struct l2_feature_snapshot *snapshot) {
    if (!tier || !snapshot || tier->frozen) return;

    uint64_t now_ns = snapshot->timestamp_ns;
    if (now_ns == 0) {
        now_ns = get_current_time_ns();
    }

    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        double value = snapshot->values[i];

        // Apply log-transform for cardinality features
        // This ensures 100->1000 has same significance as 1000->10000
        if (feature_uses_log_transform(i)) {
            value = log(value + 1.0);  // log(x+1) so log(0) = 0
        }

        feature_baseline_update(&tier->features[i],
                               value,
                               tier->alpha,
                               now_ns);
    }

    // Check if tier is now ready (all features have enough samples)
    if (!tier->ready) {
        bool all_ready = true;
        for (int i = 0; i < L2_MAX_FEATURES; i++) {
            if (tier->features[i].sample_count < tier->min_samples_ready) {
                all_ready = false;
                break;
            }
        }
        tier->ready = all_ready;
    }
}

void three_tier_baseline_update(struct three_tier_baseline *baselines,
                                const struct l2_feature_snapshot *snapshot) {
    if (!baselines || !snapshot) return;

    // Update Tier 1 (always)
    tier_baseline_update(&baselines->immediate, snapshot);

    // Update Tier 2 (current hour)
    struct tier_baseline *hourly = get_current_hourly_baseline(baselines);
    if (hourly) {
        tier_baseline_update(hourly, snapshot);
    }

    // Update Tier 3 (current day/hour)
    struct tier_baseline *weekly = get_current_weekly_baseline(baselines);
    if (weekly) {
        tier_baseline_update(weekly, snapshot);
    }

    baselines->total_updates++;
}

// ==================== Z-Score Calculation ====================

// Maximum reasonable Z-score to prevent display issues
// A Z-score of 100 already represents an astronomically rare event (beyond measurement)
#define MAX_ZSCORE_CAP 100.0

double feature_baseline_z_score(const struct feature_baseline *fb, double value) {
    if (!fb) return 0.0;

    // Not ready if insufficient samples
    if (fb->sample_count < 10) {
        return 0.0;
    }

    double stddev = feature_baseline_stddev(fb);

    // ANT-11 FIX: Variance bootstrap floor to prevent cold-start false positives.
    //
    // During the first learning window, EWMA variance is underestimated when traffic
    // is steady: if all N warm-up samples are identical, variance remains 0. Any
    // first deviation then produces an enormous z-score (or MAX_ZSCORE_CAP), causing
    // false-positive anomaly alerts the moment the baseline becomes "ready".
    //
    // Fix: enforce a minimum effective stddev of 2% of the current mean (or an
    // absolute floor of 1.0 for near-zero-mean features). This bounds the maximum
    // cold-start z-score to ~50 (well below MAX_ZSCORE_CAP), while still allowing
    // genuine large spikes to register as significant anomalies.
    //
    // The floor is self-removing: once the baseline has observed real traffic
    // variation (typically after 20-30 samples), the natural stddev grows above
    // the floor and the floor has no further effect.
    {
        double min_stddev = (fb->mean > 50.0) ? fb->mean * 0.02 : 1.0;
        if (stddev < min_stddev) {
            stddev = min_stddev;
        }
    }

    double z = (value - fb->mean) / stddev;

    // Cap Z-score to reasonable range to prevent overflow in display/calculations
    // A Z of 100 is already beyond any practical significance
    if (z > MAX_ZSCORE_CAP) z = MAX_ZSCORE_CAP;
    if (z < -MAX_ZSCORE_CAP) z = -MAX_ZSCORE_CAP;

    return z;
}

void tier_baseline_z_scores(const struct tier_baseline *tier,
                            const struct l2_feature_snapshot *snapshot,
                            double threshold,
                            struct tier_z_scores *result) {
    if (!tier || !snapshot || !result) return;

    memset(result, 0, sizeof(*result));
    result->max_z = 0.0;
    result->max_feature_idx = -1;
    result->triggered_count = 0;

    if (!tier->ready) {
        return;
    }

    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        double value = snapshot->values[i];

        // Apply same log-transform used during baseline update
        if (feature_uses_log_transform(i)) {
            value = log(value + 1.0);
        }

        double z = feature_baseline_z_score(&tier->features[i], value);
        result->z[i] = z;

        double abs_z = (z >= 0.0) ? z : -z;

        // Track maximum
        if (abs_z > result->max_z) {
            result->max_z = abs_z;
            result->max_feature_idx = i;
        }

        // Count triggered
        if (abs_z >= threshold) {
            result->triggered_count++;
        }
    }
}

// ==================== Tier Selection ====================

int get_current_hour_index(void) {
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);  // Thread-safe version
    return tm_info.tm_hour;  // 0-23
}

int get_current_weekly_index(void) {
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);  // Thread-safe version
    // tm_wday: 0 = Sunday, we want Monday = 0
    int day = (tm_info.tm_wday + 6) % 7;  // Convert to Monday=0
    return day * 24 + tm_info.tm_hour;    // 0-167
}

struct tier_baseline *get_current_hourly_baseline(struct three_tier_baseline *baselines) {
    if (!baselines) return NULL;
    int hour = get_current_hour_index();
    return &baselines->hourly[hour];
}

struct tier_baseline *get_current_weekly_baseline(struct three_tier_baseline *baselines) {
    if (!baselines) return NULL;
    int idx = get_current_weekly_index();
    return &baselines->weekly[idx];
}

// ==================== Freeze Control ====================

// Use single global frozen flag for O(1) freeze/unfreeze
// Old implementation looped through 193 tiers (1+24+168) for each operation
// Also set per-tier frozen for backward compatibility with code that checks individual tiers
void three_tier_baseline_freeze(struct three_tier_baseline *baselines) {
    if (!baselines) return;

    // Single atomic store -- visible to Layer 1 lcores without mutex
    __atomic_store_n(&baselines->globally_frozen, true, __ATOMIC_RELEASE);

    // Also set per-tier for backward compatibility
    baselines->immediate.frozen = true;
    for (int i = 0; i < 24; i++) {
        baselines->hourly[i].frozen = true;
    }
    for (int i = 0; i < 168; i++) {
        baselines->weekly[i].frozen = true;
    }
}

void three_tier_baseline_unfreeze(struct three_tier_baseline *baselines) {
    if (!baselines) return;

    // Single atomic store -- visible to Layer 1 lcores without mutex
    __atomic_store_n(&baselines->globally_frozen, false, __ATOMIC_RELEASE);

    // Also clear per-tier for backward compatibility
    baselines->immediate.frozen = false;
    for (int i = 0; i < 24; i++) {
        baselines->hourly[i].frozen = false;
    }
    for (int i = 0; i < 168; i++) {
        baselines->weekly[i].frozen = false;
    }
}

bool three_tier_baseline_is_frozen(const struct three_tier_baseline *baselines) {
    if (!baselines) return false;
    // Check global flag first (faster), fall back to tier check
    return __atomic_load_n(&baselines->globally_frozen, __ATOMIC_ACQUIRE)
           || baselines->immediate.frozen;
}

// ==================== Status ====================

bool tier_baseline_is_ready(const struct tier_baseline *tier) {
    return tier && tier->ready;
}

void three_tier_baseline_summary(const struct three_tier_baseline *baselines,
                                 struct baseline_summary *summary) {
    if (!baselines || !summary) return;

    memset(summary, 0, sizeof(*summary));

    // Tier 1
    summary->tier1_ready = baselines->immediate.ready;
    summary->tier1_samples = baselines->immediate.features[L2_FEAT_PACKETS_PER_SEC].sample_count;
    summary->tier1_pps_mean = baselines->immediate.features[L2_FEAT_PACKETS_PER_SEC].mean;
    summary->tier1_pps_stddev = feature_baseline_stddev(
        &baselines->immediate.features[L2_FEAT_PACKETS_PER_SEC]);

    // Tier 2
    summary->tier2_ready_count = 0;
    for (int i = 0; i < 24; i++) {
        if (baselines->hourly[i].ready) {
            summary->tier2_ready_count++;
        }
    }
    summary->current_hour = get_current_hour_index();

    // Tier 3
    summary->tier3_ready_count = 0;
    for (int i = 0; i < 168; i++) {
        if (baselines->weekly[i].ready) {
            summary->tier3_ready_count++;
        }
    }
    summary->current_day = get_current_weekly_index() / 24;

    // Global
    summary->any_frozen = three_tier_baseline_is_frozen(baselines);
    summary->total_updates = baselines->total_updates;
}

void three_tier_baseline_reset(struct three_tier_baseline *baselines) {
    if (!baselines) return;

    // Reinitialize with current alpha values
    double alpha_imm = baselines->immediate.alpha;
    double alpha_hr = baselines->hourly[0].alpha;
    double alpha_wk = baselines->weekly[0].alpha;
    uint32_t min_imm = baselines->immediate.min_samples_ready;
    uint32_t min_hr = baselines->hourly[0].min_samples_ready;
    uint32_t min_wk = baselines->weekly[0].min_samples_ready;

    three_tier_baseline_init(baselines,
                            alpha_imm, alpha_hr, alpha_wk,
                            min_imm, min_hr, min_wk);
}

// ==================== Persistence ====================

static cJSON *feature_baseline_to_json(const struct feature_baseline *fb) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "mean", fb->mean);
    cJSON_AddNumberToObject(obj, "variance", fb->variance);
    cJSON_AddNumberToObject(obj, "min", fb->min_observed);
    cJSON_AddNumberToObject(obj, "max", fb->max_observed);
    cJSON_AddNumberToObject(obj, "samples", fb->sample_count);
    return obj;
}

static void feature_baseline_from_json(struct feature_baseline *fb, cJSON *obj) {
    cJSON *item;
    if ((item = cJSON_GetObjectItem(obj, "mean"))) fb->mean = item->valuedouble;
    if ((item = cJSON_GetObjectItem(obj, "variance"))) fb->variance = item->valuedouble;
    if ((item = cJSON_GetObjectItem(obj, "min"))) fb->min_observed = item->valuedouble;
    if ((item = cJSON_GetObjectItem(obj, "max"))) fb->max_observed = item->valuedouble;
    if ((item = cJSON_GetObjectItem(obj, "samples"))) fb->sample_count = item->valueint;
}

static cJSON *tier_baseline_to_json(const struct tier_baseline *tier) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "name", tier->name);
    cJSON_AddNumberToObject(obj, "alpha", tier->alpha);
    cJSON_AddBoolToObject(obj, "ready", tier->ready);
    cJSON_AddNumberToObject(obj, "min_samples", tier->min_samples_ready);

    cJSON *features = cJSON_CreateObject();
    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        cJSON_AddItemToObject(features, l2_feature_names[i],
                              feature_baseline_to_json(&tier->features[i]));
    }
    cJSON_AddItemToObject(obj, "features", features);

    return obj;
}

static void tier_baseline_from_json(struct tier_baseline *tier, cJSON *obj) {
    cJSON *item;
    if ((item = cJSON_GetObjectItem(obj, "name"))) {
        strncpy(tier->name, item->valuestring, sizeof(tier->name) - 1);
        tier->name[sizeof(tier->name) - 1] = '\0';  // Ensure null termination
    }
    if ((item = cJSON_GetObjectItem(obj, "alpha"))) tier->alpha = item->valuedouble;
    if ((item = cJSON_GetObjectItem(obj, "ready"))) tier->ready = cJSON_IsTrue(item);
    if ((item = cJSON_GetObjectItem(obj, "min_samples"))) tier->min_samples_ready = item->valueint;

    cJSON *features = cJSON_GetObjectItem(obj, "features");
    if (features) {
        for (int i = 0; i < L2_MAX_FEATURES; i++) {
            cJSON *feat = cJSON_GetObjectItem(features, l2_feature_names[i]);
            if (feat) {
                feature_baseline_from_json(&tier->features[i], feat);
            }
        }
    }
}

// MF5 FIX: Get schema version from JSON string
int three_tier_baseline_get_json_version(const char *json) {
    if (!json) return -1;

    cJSON *root = cJSON_Parse(json);
    if (!root) return -1;

    cJSON *ver = cJSON_GetObjectItem(root, "version");
    int version = ver ? ver->valueint : 1;  // Default to v1 if missing

    cJSON_Delete(root);
    return version;
}

char *three_tier_baseline_to_json(const struct three_tier_baseline *baselines) {
    if (!baselines) return NULL;

    cJSON *root = cJSON_CreateObject();
    // MF5 FIX: Include schema version and feature count for compatibility
    cJSON_AddNumberToObject(root, "version", L2_BASELINE_SCHEMA_VERSION);
    cJSON_AddNumberToObject(root, "feature_count", L2_MAX_FEATURES);
    cJSON_AddNumberToObject(root, "total_updates", baselines->total_updates);

    // Tier 1
    cJSON_AddItemToObject(root, "immediate",
                          tier_baseline_to_json(&baselines->immediate));

    // Tier 2
    cJSON *hourly = cJSON_CreateArray();
    for (int i = 0; i < 24; i++) {
        cJSON_AddItemToArray(hourly, tier_baseline_to_json(&baselines->hourly[i]));
    }
    cJSON_AddItemToObject(root, "hourly", hourly);

    // Tier 3
    cJSON *weekly = cJSON_CreateArray();
    for (int i = 0; i < 168; i++) {
        cJSON_AddItemToArray(weekly, tier_baseline_to_json(&baselines->weekly[i]));
    }
    cJSON_AddItemToObject(root, "weekly", weekly);

    char *json = cJSON_Print(root);
    cJSON_Delete(root);

    return json;
}

int three_tier_baseline_from_json(struct three_tier_baseline *baselines,
                                  const char *json) {
    if (!baselines || !json) return -1;

    cJSON *root = cJSON_Parse(json);
    if (!root) return -1;

    // MF5 FIX: Version validation and migration
    cJSON *ver = cJSON_GetObjectItem(root, "version");
    int file_version = ver ? ver->valueint : 1;  // Default to v1 if missing

    if (file_version < L2_BASELINE_MIN_COMPATIBLE_VERSION) {
        fprintf(stderr, "[Layer2] Baseline file version %d too old (min: %d)\n",
                file_version, L2_BASELINE_MIN_COMPATIBLE_VERSION);
        cJSON_Delete(root);
        return -2;  // Incompatible version
    }

    if (file_version > L2_BASELINE_SCHEMA_VERSION) {
        printf("[Layer2] Baseline file version %d newer than code version %d, may lose data\n",
               file_version, L2_BASELINE_SCHEMA_VERSION);
        // Continue anyway - we'll just ignore unknown fields
    }

    // Check feature count for compatibility
    cJSON *fc = cJSON_GetObjectItem(root, "feature_count");
    int file_features = fc ? fc->valueint : 24;  // v1 had 24 features
    if (file_features != L2_MAX_FEATURES) {
        printf("[Layer2] Feature count mismatch: file=%d, code=%d\n",
               file_features, L2_MAX_FEATURES);
        // Continue - will handle missing/extra features in tier parsing
    }

    cJSON *item;
    if ((item = cJSON_GetObjectItem(root, "total_updates"))) {
        baselines->total_updates = item->valueint;
    }

    // Tier 1 - handle both object (C format) and array (Python format)
    cJSON *immediate = cJSON_GetObjectItem(root, "immediate");
    if (immediate) {
        if (cJSON_IsArray(immediate)) {
            // Python backend saves 3 sub-tiers [1s, 10s, 60s] -- use 1s
            cJSON *first = cJSON_GetArrayItem(immediate, 0);
            if (first) {
                tier_baseline_from_json(&baselines->immediate, first);
            }
        } else {
            tier_baseline_from_json(&baselines->immediate, immediate);
        }
    }

    // Tier 2
    cJSON *hourly = cJSON_GetObjectItem(root, "hourly");
    if (hourly && cJSON_IsArray(hourly)) {
        int count = cJSON_GetArraySize(hourly);
        if (count > 24) count = 24;
        for (int i = 0; i < count; i++) {
            tier_baseline_from_json(&baselines->hourly[i], cJSON_GetArrayItem(hourly, i));
        }
    }

    // Tier 3
    cJSON *weekly = cJSON_GetObjectItem(root, "weekly");
    if (weekly && cJSON_IsArray(weekly)) {
        int count = cJSON_GetArraySize(weekly);
        if (count > 168) count = 168;
        for (int i = 0; i < count; i++) {
            tier_baseline_from_json(&baselines->weekly[i], cJSON_GetArrayItem(weekly, i));
        }
    }

    cJSON_Delete(root);
    return 0;
}

int three_tier_baseline_save(const struct three_tier_baseline *baselines,
                             const char *filepath) {
    if (!baselines || !filepath) return -1;

    char *json = three_tier_baseline_to_json(baselines);
    if (!json) return -1;

    // Atomic file write: write to temp file, then rename
    // This prevents corruption if crash occurs mid-write
    char temp_filepath[512];
    int n = snprintf(temp_filepath, sizeof(temp_filepath), "%s.tmp.%d", filepath, (int)getpid());
    if (n < 0 || (size_t)n >= sizeof(temp_filepath)) {
        free(json);
        return -1;
    }

    FILE *f = fopen(temp_filepath, "w");
    if (!f) {
        free(json);
        return -1;
    }

    size_t len = strlen(json);
    size_t written = fwrite(json, 1, len, f);

    // Flush and sync to ensure data is on disk before rename
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        unlink(temp_filepath);
        free(json);
        return -1;
    }

    fclose(f);
    free(json);

    if (written != len) {
        unlink(temp_filepath);
        return -1;
    }

    // Atomic rename - this is the commit point
    if (rename(temp_filepath, filepath) != 0) {
        fprintf(stderr, "[Layer2] Failed to rename temp file: %s\n", strerror(errno));
        unlink(temp_filepath);
        return -1;
    }

    printf("[Layer2] Baselines saved to %s (%u updates)\n",
           filepath, baselines->total_updates);
    return 0;
}

/**
 * P1 FIX: Async save - performs JSON serialization in calling thread
 * but writes to disk in a background thread to avoid blocking detection
 */
int three_tier_baseline_save_async(const struct three_tier_baseline *baselines,
                                   const char *filepath) {
    if (!baselines || !filepath) return -1;

    // Serialize JSON in current thread (this is CPU-bound, cannot avoid)
    // but file I/O (the slow part) happens in background
    char *json = three_tier_baseline_to_json(baselines);
    if (!json) return -1;

    // Allocate context for background thread
    struct async_save_context *ctx = malloc(sizeof(*ctx));
    if (!ctx) {
        free(json);
        return -1;
    }

    ctx->json = json;
    ctx->updates = baselines->total_updates;
    int n = snprintf(ctx->filepath, sizeof(ctx->filepath), "%s", filepath);
    if (n < 0 || (size_t)n >= sizeof(ctx->filepath)) {
        free(json);
        free(ctx);
        return -1;
    }

    // Launch detached background thread
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    int rc = pthread_create(&thread, &attr, async_save_thread, ctx);
    pthread_attr_destroy(&attr);

    if (rc != 0) {
        fprintf(stderr, "[Layer2] Failed to create async save thread: %d\n", rc);
        free(json);
        free(ctx);
        return -1;
    }

    return 0;  // Success - write happening in background
}

int three_tier_baseline_load(struct three_tier_baseline *baselines,
                             const char *filepath) {
    if (!baselines || !filepath) return -1;

    FILE *f = fopen(filepath, "rb");
    if (!f) {
        return -1;  // File doesn't exist (not an error)
    }

    // Use fseeko/ftello for proper 64-bit file size support
    if (fseeko(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    off_t size = ftello(f);
    if (fseeko(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    // Validate file size (max 10MB, must be positive)
    if (size <= 0 || size > 10 * 1024 * 1024) {
        fclose(f);
        return -1;
    }

    char *json = malloc((size_t)size + 1);
    if (!json) {
        fclose(f);
        return -1;
    }

    size_t read_size = fread(json, 1, (size_t)size, f);
    fclose(f);

    if ((off_t)read_size != size) {
        free(json);
        return -1;
    }
    json[size] = '\0';

    int result = three_tier_baseline_from_json(baselines, json);
    free(json);

    if (result == 0) {
        printf("[Layer2] Baselines loaded from %s (%u updates)\n",
               filepath, baselines->total_updates);
    }

    return result;
}

// ==================== Per-IP Baseline Implementation ====================

void per_ip_baseline_table_init(struct per_ip_baseline_table *table) {
    if (!table) return;
    memset(table, 0, sizeof(*table));
    table->active_count = 0;
}

/**
 * Find slot index for a given protected IP
 * Returns -1 if not found
 */
static int per_ip_baseline_find_slot(const struct per_ip_baseline_table *table,
                                     uint32_t dst_ip) {
    if (!table) return -1;

    for (uint32_t i = 0; i < L2_MAX_PROTECTED_IPS; i++) {
        if (table->entries[i].active && table->entries[i].dst_ip == dst_ip) {
            return (int)i;
        }
    }
    return -1;
}

int per_ip_baseline_register(struct per_ip_baseline_table *table,
                             uint32_t dst_ip,
                             double alpha_immediate,
                             double alpha_hourly,
                             double alpha_weekly,
                             uint32_t min_samples_immediate,
                             uint32_t min_samples_hourly,
                             uint32_t min_samples_weekly) {
    if (!table) return -1;

    // Check if already registered
    if (per_ip_baseline_find_slot(table, dst_ip) >= 0) {
        return 0;  // Already exists
    }

    // Find free slot
    int idx = -1;
    for (uint32_t i = 0; i < L2_MAX_PROTECTED_IPS; i++) {
        if (!table->entries[i].active) {
            idx = (int)i;
            break;
        }
    }

    if (idx < 0) {
        return -1;  // Table full
    }

    // Initialize the per-IP baseline
    struct per_ip_baseline *entry = &table->entries[idx];
    entry->dst_ip = dst_ip;
    entry->active = true;

    // Initialize three-tier baselines for this IP
    three_tier_baseline_init(&entry->baselines,
                            alpha_immediate, alpha_hourly, alpha_weekly,
                            min_samples_immediate, min_samples_hourly, min_samples_weekly);

    // allocate and initialize per-IP CUSUM + JSD
    // state so layer2_per_ip_detection_cycle can call l2_advanced_detect with
    // this IP's own detector state. Pre-fix the per-IP path called only
    // l2_detect_anomaly (z-tier voting) and never ran the CUSUM / JSD
    // ensemble. Allocation is lazy (calloc) so unused per-IP slots cost only
    // a NULL pointer until they're registered. Cleanup in unregister.
    entry->cusum = (struct cusum_detector *)aligned_alloc(64, sizeof(struct cusum_detector));
    if (entry->cusum) memset(entry->cusum, 0, sizeof(struct cusum_detector));
    entry->jsd   = (struct jsd_baseline   *)aligned_alloc(64, sizeof(struct jsd_baseline));
    if (entry->jsd) memset(entry->jsd, 0, sizeof(struct jsd_baseline));
    if (!entry->cusum || !entry->jsd) {
        // OOM -- free what we got and back out. Returning -1 here leaves the
        // slot inactive so subsequent registers can retry.
        free(entry->cusum); entry->cusum = NULL;
        free(entry->jsd);   entry->jsd   = NULL;
        entry->active = false;
        return -1;
    }
    cusum_detector_init(entry->cusum, 0.25, 5.0);  // k_factor, h_factor (mirrors global init)
    jsd_baseline_init  (entry->jsd,   0.1, 30);    // alpha, min_samples (mirrors global init)

    // Per-IP innovation gate (the innovation-gate prototype) is allocated LAZILY on first use by
    // layer2_per_ip_detection_cycle (only when the innovation-gate ensemble rule
    // is active), so it stays NULL -- and cost-free -- for the default OR rule.
    entry->innovation = NULL;

    // Initialize anomaly result
    struct per_ip_anomaly_result *anom = &table->anomaly[idx];
    memset(anom, 0, sizeof(*anom));
    anom->dst_ip = dst_ip;
    anom->active = true;

    table->active_count++;

    printf("[Layer2] Registered per-IP baseline for %08x (slot %d, total %u)\n",
           dst_ip, idx, table->active_count);

    return 0;
}

int per_ip_baseline_unregister(struct per_ip_baseline_table *table,
                               uint32_t dst_ip) {
    if (!table) return -1;

    int idx = per_ip_baseline_find_slot(table, dst_ip);
    if (idx < 0) {
        return -1;  // Not found
    }

    // First mark as inactive to prevent concurrent access
    table->entries[idx].active = false;
    table->anomaly[idx].active = false;

    // Memory barrier to ensure active=false is visible before zeroing
    __atomic_thread_fence(__ATOMIC_RELEASE);

    // free per-IP CUSUM + JSD state allocated in register.
    // NULL-check defends against the OOM-rollback path in register.
    free(table->entries[idx].cusum); table->entries[idx].cusum = NULL;
    free(table->entries[idx].jsd);   table->entries[idx].jsd   = NULL;
    // Per-IP innovation-gate state (lazily allocated in the detection cycle; NULL if unused).
    // free(NULL) is a no-op, so no guard is needed for the default-OR path.
    free(table->entries[idx].innovation); table->entries[idx].innovation = NULL;

    // Zero out all data to prevent use-after-free of stale data
    memset(&table->entries[idx].baselines, 0, sizeof(table->entries[idx].baselines));
    table->entries[idx].dst_ip = 0;

    memset(&table->anomaly[idx], 0, sizeof(table->anomaly[idx]));

    if (table->active_count > 0) {
        table->active_count--;
    }

    printf("[Layer2] Unregistered per-IP baseline for %08x (remaining %u)\n",
           dst_ip, table->active_count);

    return 0;
}

struct per_ip_baseline *per_ip_baseline_lookup(struct per_ip_baseline_table *table,
                                               uint32_t dst_ip) {
    if (!table) return NULL;

    int idx = per_ip_baseline_find_slot(table, dst_ip);
    if (idx < 0) return NULL;

    return &table->entries[idx];
}

struct per_ip_anomaly_result *per_ip_anomaly_lookup(struct per_ip_baseline_table *table,
                                                    uint32_t dst_ip) {
    if (!table) return NULL;

    int idx = per_ip_baseline_find_slot(table, dst_ip);
    if (idx < 0) return NULL;

    return &table->anomaly[idx];
}

void per_ip_baseline_update(struct per_ip_baseline_table *table,
                            uint32_t dst_ip,
                            const struct l2_feature_snapshot *snapshot) {
    if (!table || !snapshot) return;

    // Global freeze takes priority
    if (__atomic_load_n(&table->globally_frozen, __ATOMIC_ACQUIRE)) return;

    struct per_ip_baseline *entry = per_ip_baseline_lookup(table, dst_ip);
    if (!entry) return;

    // Update the three-tier baselines for this IP
    three_tier_baseline_update(&entry->baselines, snapshot);
}

void per_ip_baseline_freeze_all(struct per_ip_baseline_table *table) {
    if (!table) return;
    __atomic_store_n(&table->globally_frozen, true, __ATOMIC_RELEASE);

    // Also freeze individual baselines
    for (uint32_t i = 0; i < L2_MAX_PROTECTED_IPS; i++) {
        if (table->entries[i].active) {
            three_tier_baseline_freeze(&table->entries[i].baselines);
        }
    }
}

void per_ip_baseline_unfreeze_all(struct per_ip_baseline_table *table) {
    if (!table) return;
    __atomic_store_n(&table->globally_frozen, false, __ATOMIC_RELEASE);

    // Also unfreeze individual baselines
    for (uint32_t i = 0; i < L2_MAX_PROTECTED_IPS; i++) {
        if (table->entries[i].active) {
            three_tier_baseline_unfreeze(&table->entries[i].baselines);
        }
    }
}

bool per_ip_baseline_is_frozen(const struct per_ip_baseline_table *table) {
    if (!table) return false;
    return __atomic_load_n(&table->globally_frozen, __ATOMIC_ACQUIRE);
}

void per_ip_baseline_table_reset(struct per_ip_baseline_table *table) {
    if (!table) return;

    // Reset all active baselines
    for (uint32_t i = 0; i < L2_MAX_PROTECTED_IPS; i++) {
        if (table->entries[i].active) {
            three_tier_baseline_reset(&table->entries[i].baselines);
            memset(&table->anomaly[i], 0, sizeof(table->anomaly[i]));
            table->anomaly[i].dst_ip = table->entries[i].dst_ip;
            table->anomaly[i].active = true;
        }
    }
}

uint32_t per_ip_baseline_count(const struct per_ip_baseline_table *table) {
    if (!table) return 0;
    return table->active_count;
}

// ==================== Per-IP Persistence ====================

int per_ip_baseline_save(const struct per_ip_baseline_table *table,
                         const char *filepath) {
    if (!table || !filepath) return -1;

    // Validate filepath length to prevent buffer overflow
    size_t filepath_len = strlen(filepath);
    if (filepath_len == 0 || filepath_len > 400) {
        fprintf(stderr, "[Layer2] Invalid filepath length: %zu\n", filepath_len);
        return -1;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "version", L2_BASELINE_SCHEMA_VERSION);
    cJSON_AddNumberToObject(root, "active_count", table->active_count);

    cJSON *entries = cJSON_CreateArray();
    if (!entries) {
        cJSON_Delete(root);
        return -1;
    }

    for (uint32_t i = 0; i < L2_MAX_PROTECTED_IPS; i++) {
        if (table->entries[i].active) {
            cJSON *entry = cJSON_CreateObject();
            if (!entry) continue;

            cJSON_AddNumberToObject(entry, "dst_ip", table->entries[i].dst_ip);

            // Serialize the baselines for this IP
            char *baseline_json = three_tier_baseline_to_json(&table->entries[i].baselines);
            if (baseline_json) {
                cJSON *baseline_obj = cJSON_Parse(baseline_json);
                if (baseline_obj) {
                    cJSON_AddItemToObject(entry, "baselines", baseline_obj);
                }
                free(baseline_json);
            }

            cJSON_AddItemToArray(entries, entry);
        }
    }
    cJSON_AddItemToObject(root, "entries", entries);

    char *json = cJSON_Print(root);
    cJSON_Delete(root);

    if (!json) return -1;

    // Validate output size (max 100MB to prevent runaway serialization)
    size_t json_len = strlen(json);
    if (json_len > 100 * 1024 * 1024) {
        fprintf(stderr, "[Layer2] JSON output too large: %zu bytes\n", json_len);
        free(json);
        return -1;
    }

    // Write to file - use dynamic allocation for temp path
    char *temp_filepath = malloc(filepath_len + 32);
    if (!temp_filepath) {
        free(json);
        return -1;
    }
    int n = snprintf(temp_filepath, filepath_len + 32, "%s.tmp.%d", filepath, (int)getpid());
    if (n < 0 || (size_t)n >= filepath_len + 32) {
        free(temp_filepath);
        free(json);
        return -1;
    }

    FILE *f = fopen(temp_filepath, "w");
    if (!f) {
        free(temp_filepath);
        free(json);
        return -1;
    }

    size_t written = fwrite(json, 1, json_len, f);

    if (fflush(f) != 0 || fsync(fileno(f)) != 0 || written != json_len) {
        fclose(f);
        unlink(temp_filepath);
        free(temp_filepath);
        free(json);
        return -1;
    }

    fclose(f);
    free(json);

    if (rename(temp_filepath, filepath) != 0) {
        unlink(temp_filepath);
        free(temp_filepath);
        return -1;
    }

    free(temp_filepath);

    printf("[Layer2] Per-IP baselines saved to %s (%u entries)\n",
           filepath, table->active_count);
    return 0;
}

int per_ip_baseline_load(struct per_ip_baseline_table *table,
                         const char *filepath) {
    if (!table || !filepath) return -1;

    FILE *f = fopen(filepath, "rb");
    if (!f) {
        return -1;
    }

    if (fseeko(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    off_t size = ftello(f);
    if (fseeko(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    if (size <= 0 || size > 50 * 1024 * 1024) {  // Max 50MB for per-IP baselines
        fclose(f);
        return -1;
    }

    char *json = malloc((size_t)size + 1);
    if (!json) {
        fclose(f);
        return -1;
    }

    size_t read_size = fread(json, 1, (size_t)size, f);
    fclose(f);

    if ((off_t)read_size != size) {
        free(json);
        return -1;
    }
    json[size] = '\0';

    cJSON *root = cJSON_Parse(json);
    free(json);

    if (!root) return -1;

    // Clear current table
    per_ip_baseline_table_init(table);

    cJSON *entries = cJSON_GetObjectItem(root, "entries");
    if (entries && cJSON_IsArray(entries)) {
        int count = cJSON_GetArraySize(entries);
        for (int i = 0; i < count && i < L2_MAX_PROTECTED_IPS; i++) {
            cJSON *entry = cJSON_GetArrayItem(entries, i);
            if (!entry) continue;

            cJSON *dst_ip_item = cJSON_GetObjectItem(entry, "dst_ip");
            if (!dst_ip_item) continue;

            uint32_t dst_ip = (uint32_t)dst_ip_item->valuedouble;

            // Register with default parameters (will be overwritten by loaded data)
            per_ip_baseline_register(table, dst_ip, 0.2, 0.1, 0.05, 10, 20, 40);

            // Load baselines
            cJSON *baselines_obj = cJSON_GetObjectItem(entry, "baselines");
            if (baselines_obj) {
                struct per_ip_baseline *pip = per_ip_baseline_lookup(table, dst_ip);
                if (pip) {
                    char *baseline_json = cJSON_Print(baselines_obj);
                    if (baseline_json) {
                        three_tier_baseline_from_json(&pip->baselines, baseline_json);
                        free(baseline_json);
                    }
                }
            }
        }
    }

    cJSON_Delete(root);

    printf("[Layer2] Per-IP baselines loaded from %s (%u entries)\n",
           filepath, table->active_count);

    return 0;
}

// ==================== Baseline Poisoning Protection ====================

bool baseline_check_poisoning(struct three_tier_baseline *baselines,
                              const struct l2_feature_snapshot *snapshot) {
    if (!baselines || !snapshot) return false;

    const struct layer2_config *cfg = layer2_config_get();

    // Check if protection is enabled
    if (!cfg->baseline_poison_protection_enabled) {
        return false;
    }

    struct baseline_poison_tracker *tracker = &baselines->poison_tracker;
    uint64_t now_ns = snapshot->timestamp_ns;
    if (now_ns == 0) {
        now_ns = get_current_time_ns();
    }

    // Convert window config from seconds to nanoseconds
    uint64_t window_ns = (uint64_t)cfg->baseline_poison_window_sec * 1000000000ULL;

    // Reset window if expired
    if (tracker->window_start_ns == 0 || (now_ns - tracker->window_start_ns) > window_ns) {
        tracker->window_start_ns = now_ns;
        tracker->large_change_count = 0;
        // Store current means for next comparison
        for (int i = 0; i < L2_MAX_FEATURES; i++) {
            tracker->last_mean[i] = baselines->immediate.features[i].mean;
        }
    }

    // Check if already poisoned - stay frozen until manual reset
    if (tracker->poison_detected) {
        return true;
    }

    // Don't check during warmup (baseline not ready)
    if (!baselines->immediate.ready) {
        // Initialize tracking with first snapshot
        for (int i = 0; i < L2_MAX_FEATURES; i++) {
            tracker->last_mean[i] = snapshot->values[i];
        }
        return false;
    }

    // Check for large changes in key volume features
    // Focus on features most likely to be manipulated: PPS, BPS, SYN rate
    int key_features[] = {
        L2_FEAT_PACKETS_PER_SEC,
        L2_FEAT_BYTES_PER_SEC,
        L2_FEAT_SYN_PER_SEC,
        L2_FEAT_FLOWS_PER_SEC
    };
    int num_key_features = sizeof(key_features) / sizeof(key_features[0]);

    bool large_change_this_cycle = false;

    for (int k = 0; k < num_key_features; k++) {
        int i = key_features[k];
        double current_mean = baselines->immediate.features[i].mean;
        double previous_mean = tracker->last_mean[i];

        // Always advance the reference point so we measure cycle-to-cycle delta,
        // not cumulative drift from a stale snapshot
        tracker->last_mean[i] = current_mean;

        // Skip if previous mean is too small (avoid division by zero)
        if (previous_mean < 1.0) {
            continue;
        }

        // Calculate change rate (how much the mean changed relative to previous)
        double change_rate = fabs(current_mean - previous_mean) / previous_mean;

        // If change rate exceeds threshold on ANY volume feature, flag this cycle
        if (change_rate > cfg->baseline_change_rate_threshold) {
            large_change_this_cycle = true;
            // Don't break -- continue updating last_mean for remaining features
        }
    }

    if (large_change_this_cycle) {
        tracker->large_change_count++;

        // Check if threshold exceeded
        if (tracker->large_change_count >= cfg->baseline_poison_count_threshold) {
            tracker->poison_detected = true;
            tracker->poison_detected_ns = now_ns;
            printf("[Layer2] BASELINE POISONING DETECTED: %u large changes in %u sec window\n",
                   tracker->large_change_count, cfg->baseline_poison_window_sec);
            printf("[Layer2] Baselines frozen to prevent attack adaptation\n");
            three_tier_baseline_freeze(baselines);
            return true;
        }
    }

    return false;
}

void baseline_poison_tracker_reset(struct three_tier_baseline *baselines) {
    if (!baselines) return;

    struct baseline_poison_tracker *tracker = &baselines->poison_tracker;
    tracker->window_start_ns = 0;
    tracker->large_change_count = 0;
    tracker->poison_detected = false;
    tracker->poison_detected_ns = 0;
    memset(tracker->last_mean, 0, sizeof(tracker->last_mean));

    printf("[Layer2] Baseline poisoning tracker reset\n");
}

bool baseline_is_poisoned(const struct three_tier_baseline *baselines) {
    if (!baselines) return false;
    return baselines->poison_tracker.poison_detected;
}
