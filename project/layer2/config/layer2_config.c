#include "layer2_config.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

// ==================== Global Configuration ====================

// Use double-buffering with atomic pointer swap for lock-free reads
// Two config buffers - one active, one for loading new config
static struct layer2_config g_config_buffers[2];
static _Atomic(struct layer2_config *) g_active_config = NULL;
static int g_active_index = 0;  // Protected by g_config_lock during writes

static char g_config_filepath[256] = L2_DEFAULT_CONFIG_FILE;
static pthread_mutex_t g_config_lock = PTHREAD_MUTEX_INITIALIZER;

// ==================== Helper Functions ====================

static char *read_file_contents(const char *filepath) {
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > 1024 * 1024) {  // Max 1MB
        fclose(f);
        return NULL;
    }

    char *content = malloc(size + 1);
    if (!content) {
        fclose(f);
        return NULL;
    }

    size_t read_size = fread(content, 1, size, f);
    fclose(f);

    if ((long)read_size != size) {
        free(content);
        return NULL;
    }

    content[size] = '\0';
    return content;
}

static int write_file_contents(const char *filepath, const char *content) {
    // Write via temp file + fsync + rename for crash safety
    char temp[512];
    int n = snprintf(temp, sizeof(temp), "%s.tmp.%d", filepath, (int)getpid());
    if (n < 0 || (size_t)n >= sizeof(temp)) return -1;

    FILE *f = fopen(temp, "w");
    if (!f) return -1;

    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, f);

    if (written != len || fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        unlink(temp);
        return -1;
    }
    fclose(f);

    if (rename(temp, filepath) != 0) {
        unlink(temp);
        return -1;
    }
    return 0;
}

// ==================== Configuration API ====================

void layer2_config_init_defaults(struct layer2_config *config) {
    if (!config) return;

    memset(config, 0, sizeof(*config));

    // Detection thresholds
    config->z_score_threshold = L2_DEFAULT_Z_SCORE_THRESHOLD;
    config->min_tier_agreement = L2_DEFAULT_MIN_TIER_AGREEMENT;

    // Ensemble decision rule (OR default; conformal selectable, paper section4.10)
    config->ensemble_rule = L2_DEFAULT_ENSEMBLE_RULE;
    config->conformal_alpha = L2_DEFAULT_CONFORMAL_ALPHA;
    config->cusum_decay = L2_DEFAULT_CUSUM_DECAY;
    config->routed_fdr_alpha = L2_DEFAULT_ROUTED_FDR_ALPHA;
    config->conformal_capacity = L2_DEFAULT_CONFORMAL_CAPACITY;
    config->innovation_gate_kappa = L2_DEFAULT_INNOVATION_GATE_KAPPA;
    config->innovation_gate_hysteresis = L2_DEFAULT_INNOVATION_GATE_HYSTERESIS;

    // JSD and concentration thresholds
    config->jsd_threshold = L2_DEFAULT_JSD_THRESHOLD;
    config->max_flow_fraction_threshold = L2_DEFAULT_MAX_FLOW_FRACTION_THRESHOLD;
    config->topk_flow_share_threshold = L2_DEFAULT_TOPK_FLOW_SHARE_THRESHOLD;

    // EWMA smoothing factors
    config->alpha_immediate = L2_DEFAULT_ALPHA_IMMEDIATE;
    config->alpha_hourly = L2_DEFAULT_ALPHA_HOURLY;
    config->alpha_weekly = L2_DEFAULT_ALPHA_WEEKLY;

    // Minimum samples
    config->min_samples_immediate = L2_DEFAULT_MIN_SAMPLES_IMMEDIATE;
    config->min_samples_hourly = L2_DEFAULT_MIN_SAMPLES_HOURLY;
    config->min_samples_weekly = L2_DEFAULT_MIN_SAMPLES_WEEKLY;

    // Attack handling
    config->cool_down_seconds = L2_DEFAULT_COOL_DOWN_SECONDS;
    config->baseline_freeze_enabled = true;

    // Timing
    config->detection_interval_ms = L2_DEFAULT_DETECTION_INTERVAL_MS;
    config->jitter_ms = L2_DEFAULT_JITTER_MS;  // Add jitter to prevent timing attacks

    // Minimum traffic threshold for detection
    config->min_pps_for_detection = L2_DEFAULT_MIN_PPS_FOR_DETECTION;

    // Fast detection tier (100ms for pulse attacks)
    config->fast_detection_enabled = L2_DEFAULT_FAST_DETECTION_ENABLED;
    config->fast_detection_interval_ms = L2_DEFAULT_FAST_DETECTION_INTERVAL_MS;
    config->fast_threshold_multiplier = L2_DEFAULT_FAST_THRESHOLD_MULTIPLIER;
    config->fast_min_pps_spike = L2_DEFAULT_FAST_MIN_PPS_SPIKE;
    config->fast_syn_spike_threshold = L2_DEFAULT_FAST_SYN_SPIKE_THRESHOLD;
    config->fast_consecutive_required = L2_DEFAULT_FAST_CONSECUTIVE_REQUIRED;

    // Adaptive warmup thresholds
    config->adaptive_warmup_enabled = L2_DEFAULT_ADAPTIVE_WARMUP_ENABLED;
    config->warmup_learning_window_sec = L2_DEFAULT_WARMUP_LEARNING_WINDOW_SEC;
    config->warmup_spike_factor = L2_DEFAULT_WARMUP_SPIKE_FACTOR;
    config->warmup_min_observations = L2_DEFAULT_WARMUP_MIN_OBSERVATIONS;
    config->warmup_percentile_threshold = L2_DEFAULT_WARMUP_PERCENTILE_THRESHOLD;

    // FIX #4: Warmup emergency thresholds
    config->warmup_pps_threshold = L2_DEFAULT_WARMUP_PPS_THRESHOLD;
    config->warmup_syn_threshold = L2_DEFAULT_WARMUP_SYN_THRESHOLD;

    // Configurable Z-score level thresholds for anomaly classification
    config->z_critical_3tier = L2_DEFAULT_Z_CRITICAL_3TIER;
    config->z_high_3tier = L2_DEFAULT_Z_HIGH_3TIER;
    config->z_medium_3tier = L2_DEFAULT_Z_MEDIUM_3TIER;
    config->z_high_2tier = L2_DEFAULT_Z_HIGH_2TIER;
    config->z_medium_2tier = L2_DEFAULT_Z_MEDIUM_2TIER;
    config->z_medium_1tier = L2_DEFAULT_Z_MEDIUM_1TIER;

    // Baseline poisoning protection
    config->baseline_poison_protection_enabled = true;
    config->baseline_change_rate_threshold = L2_DEFAULT_BASELINE_CHANGE_RATE_THRESHOLD;
    config->baseline_poison_window_sec = L2_DEFAULT_BASELINE_POISON_WINDOW_SEC;
    config->baseline_poison_count_threshold = L2_DEFAULT_BASELINE_POISON_COUNT_THRESHOLD;
    config->baseline_poison_recovery_sec = L2_DEFAULT_BASELINE_POISON_RECOVERY_SEC;

    // Persistence
    strncpy(config->baseline_file, L2_DEFAULT_BASELINE_FILE,
            sizeof(config->baseline_file) - 1);
    config->baseline_file[sizeof(config->baseline_file) - 1] = '\0';  // Ensure null termination
    config->baseline_save_interval_sec = 300;  // Auto-save every 5 minutes

    // Feature weights (disabled by default)
    config->use_feature_weights = false;
    config->feature_auto_select = false;
    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        config->feature_weights[i] = 1.0;
    }

    // Logging
    config->log_detections = true;
    config->log_baseline_updates = false;
    config->log_interval_sec = 60;

    // Adaptive threshold tuning
    config->adaptive_enabled = L2_DEFAULT_ADAPTIVE_ENABLED;
    config->adaptive_min_threshold = L2_DEFAULT_ADAPTIVE_MIN_THRESHOLD;
    config->adaptive_max_threshold = L2_DEFAULT_ADAPTIVE_MAX_THRESHOLD;
    config->adaptive_step = L2_DEFAULT_ADAPTIVE_STEP;
    config->adaptive_fp_threshold = L2_DEFAULT_ADAPTIVE_FP_THRESHOLD;
    config->adaptive_tp_min = L2_DEFAULT_ADAPTIVE_TP_MIN;
    config->adaptive_eval_interval_sec = L2_DEFAULT_ADAPTIVE_EVAL_INTERVAL_S;
    config->adaptive_min_samples = L2_DEFAULT_ADAPTIVE_MIN_SAMPLES;
    config->fp_duration_threshold_sec = L2_DEFAULT_FP_DURATION_THRESHOLD_S;
    config->tp_duration_threshold_sec = L2_DEFAULT_TP_DURATION_THRESHOLD_S;
}

int layer2_config_load(struct layer2_config *config, const char *filepath) {
    if (!config || !filepath) {
        return -1;
    }

    // Start with defaults
    layer2_config_init_defaults(config);

    // Read JSON file
    char *json_content = read_file_contents(filepath);
    if (!json_content) {
        fprintf(stderr, "[Layer2] Config file not found: %s (using defaults)\n", filepath);
        return 0;  // Not an error, just use defaults
    }

    // Parse JSON
    cJSON *root = cJSON_Parse(json_content);
    free(json_content);

    if (!root) {
        fprintf(stderr, "[Layer2] Failed to parse config JSON: %s\n", filepath);
        return -1;
    }

    // Extract values (with fallback to defaults)
    cJSON *item;

    // Detection thresholds
    if ((item = cJSON_GetObjectItem(root, "z_score_threshold")) && cJSON_IsNumber(item)) {
        config->z_score_threshold = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "min_tier_agreement")) && cJSON_IsNumber(item)) {
        config->min_tier_agreement = item->valueint;
    }

    // JSD and concentration thresholds
    if ((item = cJSON_GetObjectItem(root, "jsd_threshold")) && cJSON_IsNumber(item)) {
        config->jsd_threshold = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "max_flow_fraction_threshold")) && cJSON_IsNumber(item)) {
        config->max_flow_fraction_threshold = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "topk_flow_share_threshold")) && cJSON_IsNumber(item)) {
        config->topk_flow_share_threshold = item->valuedouble;
    }

    // EWMA parameters
    if ((item = cJSON_GetObjectItem(root, "alpha_immediate")) && cJSON_IsNumber(item)) {
        config->alpha_immediate = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "alpha_hourly")) && cJSON_IsNumber(item)) {
        config->alpha_hourly = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "alpha_weekly")) && cJSON_IsNumber(item)) {
        config->alpha_weekly = item->valuedouble;
    }

    // Minimum samples
    if ((item = cJSON_GetObjectItem(root, "min_samples_immediate")) && cJSON_IsNumber(item)) {
        config->min_samples_immediate = (uint32_t)item->valueint;
    }
    if ((item = cJSON_GetObjectItem(root, "min_samples_hourly")) && cJSON_IsNumber(item)) {
        config->min_samples_hourly = (uint32_t)item->valueint;
    }
    if ((item = cJSON_GetObjectItem(root, "min_samples_weekly")) && cJSON_IsNumber(item)) {
        config->min_samples_weekly = (uint32_t)item->valueint;
    }

    // Attack handling
    if ((item = cJSON_GetObjectItem(root, "cool_down_seconds")) && cJSON_IsNumber(item)) {
        config->cool_down_seconds = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "baseline_freeze_enabled")) && cJSON_IsBool(item)) {
        config->baseline_freeze_enabled = cJSON_IsTrue(item);
    }

    // Timing
    if ((item = cJSON_GetObjectItem(root, "detection_interval_ms")) && cJSON_IsNumber(item)) {
        config->detection_interval_ms = (uint32_t)item->valueint;
    }
    // Jitter for timing attack prevention
    if ((item = cJSON_GetObjectItem(root, "jitter_ms")) && cJSON_IsNumber(item)) {
        config->jitter_ms = (uint32_t)item->valueint;
    }

    // Minimum traffic threshold
    if ((item = cJSON_GetObjectItem(root, "min_pps_for_detection")) && cJSON_IsNumber(item)) {
        config->min_pps_for_detection = (uint64_t)item->valuedouble;
    }

    // FIX #4: Warmup emergency thresholds
    if ((item = cJSON_GetObjectItem(root, "warmup_pps_threshold")) && cJSON_IsNumber(item)) {
        config->warmup_pps_threshold = (uint64_t)item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "warmup_syn_threshold")) && cJSON_IsNumber(item)) {
        config->warmup_syn_threshold = (uint64_t)item->valuedouble;
    }

    // Configurable Z-score level thresholds
    if ((item = cJSON_GetObjectItem(root, "z_critical_3tier")) && cJSON_IsNumber(item)) {
        config->z_critical_3tier = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "z_high_3tier")) && cJSON_IsNumber(item)) {
        config->z_high_3tier = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "z_medium_3tier")) && cJSON_IsNumber(item)) {
        config->z_medium_3tier = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "z_high_2tier")) && cJSON_IsNumber(item)) {
        config->z_high_2tier = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "z_medium_2tier")) && cJSON_IsNumber(item)) {
        config->z_medium_2tier = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "z_medium_1tier")) && cJSON_IsNumber(item)) {
        config->z_medium_1tier = item->valuedouble;
    }

    // Ensemble decision rule (paper section4.10 / section5.6). 0 = disjunctive OR (shipped default),
    // 1 = conformal Bonferroni, 2 = conformal e-value, 3 = routed per-feature FDR. Out-of-range
    // values fall back to the disjunctive OR default. The conformal rules warm up from the benign
    // stream and fall back to OR until calibrated; selecting them does not change the paper's
    // evaluated default, which remains OR.
    if ((item = cJSON_GetObjectItem(root, "ensemble_rule")) && cJSON_IsNumber(item)) {
        int rule = item->valueint;
        config->ensemble_rule = (rule >= L2_ENSEMBLE_RULE_OR && rule <= L2_ENSEMBLE_RULE_INNOVATION_GATE)
                                ? rule : L2_ENSEMBLE_RULE_OR;
    }
    if ((item = cJSON_GetObjectItem(root, "conformal_alpha")) && cJSON_IsNumber(item)) {
        if (item->valuedouble > 0.0 && item->valuedouble < 1.0)
            config->conformal_alpha = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "cusum_decay")) && cJSON_IsNumber(item)) {
        if (item->valuedouble > 0.0 && item->valuedouble <= 1.0)
            config->cusum_decay = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "routed_fdr_alpha")) && cJSON_IsNumber(item)) {
        if (item->valuedouble > 0.0 && item->valuedouble < 1.0)
            config->routed_fdr_alpha = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "conformal_capacity")) && cJSON_IsNumber(item)) {
        if (item->valueint > 0)
            config->conformal_capacity = (uint32_t)item->valueint;
    }
    if ((item = cJSON_GetObjectItem(root, "innovation_gate_kappa")) && cJSON_IsNumber(item)) {
        if (item->valuedouble > 0.0)
            config->innovation_gate_kappa = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "innovation_gate_hysteresis")) && cJSON_IsNumber(item)) {
        if (item->valueint > 0)
            config->innovation_gate_hysteresis = item->valueint;
    }

    // Baseline poisoning protection
    if ((item = cJSON_GetObjectItem(root, "baseline_poison_protection_enabled")) && cJSON_IsBool(item)) {
        config->baseline_poison_protection_enabled = cJSON_IsTrue(item);
    }
    if ((item = cJSON_GetObjectItem(root, "baseline_change_rate_threshold")) && cJSON_IsNumber(item)) {
        config->baseline_change_rate_threshold = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "baseline_poison_window_sec")) && cJSON_IsNumber(item)) {
        config->baseline_poison_window_sec = (uint32_t)item->valueint;
    }
    if ((item = cJSON_GetObjectItem(root, "baseline_poison_count_threshold")) && cJSON_IsNumber(item)) {
        config->baseline_poison_count_threshold = (uint32_t)item->valueint;
    }

    // Persistence
    if ((item = cJSON_GetObjectItem(root, "baseline_file")) && cJSON_IsString(item)) {
        strncpy(config->baseline_file, item->valuestring,
                sizeof(config->baseline_file) - 1);
        config->baseline_file[sizeof(config->baseline_file) - 1] = '\0';  // Ensure null termination
    }
    if ((item = cJSON_GetObjectItem(root, "baseline_save_interval_sec")) && cJSON_IsNumber(item)) {
        config->baseline_save_interval_sec = (uint32_t)item->valueint;
    }

    // Feature weights
    if ((item = cJSON_GetObjectItem(root, "use_feature_weights")) && cJSON_IsBool(item)) {
        config->use_feature_weights = cJSON_IsTrue(item);
    }
    if ((item = cJSON_GetObjectItem(root, "feature_auto_select")) && cJSON_IsBool(item)) {
        config->feature_auto_select = cJSON_IsTrue(item);
    }
    cJSON *weights = cJSON_GetObjectItem(root, "feature_weights");
    if (weights && cJSON_IsArray(weights)) {
        int count = cJSON_GetArraySize(weights);
        if (count > L2_MAX_FEATURES) count = L2_MAX_FEATURES;  // Prevent buffer overflow
        for (int i = 0; i < count; i++) {
            cJSON *w = cJSON_GetArrayItem(weights, i);
            if (w && cJSON_IsNumber(w)) {
                config->feature_weights[i] = w->valuedouble;
            }
        }
    }

    // Logging
    if ((item = cJSON_GetObjectItem(root, "log_detections")) && cJSON_IsBool(item)) {
        config->log_detections = cJSON_IsTrue(item);
    }
    if ((item = cJSON_GetObjectItem(root, "log_baseline_updates")) && cJSON_IsBool(item)) {
        config->log_baseline_updates = cJSON_IsTrue(item);
    }
    if ((item = cJSON_GetObjectItem(root, "log_interval_sec")) && cJSON_IsNumber(item)) {
        config->log_interval_sec = (uint32_t)item->valueint;
    }

    // Adaptive threshold tuning
    if ((item = cJSON_GetObjectItem(root, "adaptive_enabled")) && cJSON_IsBool(item)) {
        config->adaptive_enabled = cJSON_IsTrue(item);
    }
    if ((item = cJSON_GetObjectItem(root, "adaptive_min_threshold")) && cJSON_IsNumber(item)) {
        config->adaptive_min_threshold = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "adaptive_max_threshold")) && cJSON_IsNumber(item)) {
        config->adaptive_max_threshold = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "adaptive_step")) && cJSON_IsNumber(item)) {
        config->adaptive_step = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "adaptive_fp_threshold")) && cJSON_IsNumber(item)) {
        config->adaptive_fp_threshold = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "adaptive_tp_min")) && cJSON_IsNumber(item)) {
        config->adaptive_tp_min = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "adaptive_eval_interval_sec")) && cJSON_IsNumber(item)) {
        config->adaptive_eval_interval_sec = (uint32_t)item->valueint;
    }
    if ((item = cJSON_GetObjectItem(root, "adaptive_min_samples")) && cJSON_IsNumber(item)) {
        config->adaptive_min_samples = (uint32_t)item->valueint;
    }
    if ((item = cJSON_GetObjectItem(root, "fp_duration_threshold_sec")) && cJSON_IsNumber(item)) {
        config->fp_duration_threshold_sec = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "tp_duration_threshold_sec")) && cJSON_IsNumber(item)) {
        config->tp_duration_threshold_sec = item->valuedouble;
    }

    cJSON_Delete(root);

    // Validate loaded config
    if (layer2_config_validate(config) < 0) {
        fprintf(stderr, "[Layer2] Invalid configuration, using defaults\n");
        layer2_config_init_defaults(config);
        return -1;
    }

    // Save filepath for reload
    strncpy(g_config_filepath, filepath, sizeof(g_config_filepath) - 1);
    g_config_filepath[sizeof(g_config_filepath) - 1] = '\0';  // Ensure null termination

    // If this is the first load into a buffer, set up the atomic pointer
    // Check if config points to one of our double-buffers
    if (config == &g_config_buffers[0] || config == &g_config_buffers[1]) {
        struct layer2_config *expected = NULL;
        // Only set if not already initialized (first load)
        atomic_compare_exchange_strong(&g_active_config, &expected, config);
        if (config == &g_config_buffers[0]) {
            g_active_index = 0;
        } else {
            g_active_index = 1;
        }
    }

    printf("[Layer2] Configuration loaded from %s\n", filepath);
    return 0;
}

int layer2_config_save(const struct layer2_config *config, const char *filepath) {
    if (!config || !filepath) {
        return -1;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return -1;
    }

    // Detection thresholds
    cJSON_AddNumberToObject(root, "z_score_threshold", config->z_score_threshold);
    cJSON_AddNumberToObject(root, "min_tier_agreement", config->min_tier_agreement);

    // Ensemble decision rule + conformal params (round-trips with the parse block above)
    cJSON_AddNumberToObject(root, "ensemble_rule", config->ensemble_rule);
    cJSON_AddNumberToObject(root, "conformal_alpha", config->conformal_alpha);
    cJSON_AddNumberToObject(root, "cusum_decay", config->cusum_decay);
    cJSON_AddNumberToObject(root, "routed_fdr_alpha", config->routed_fdr_alpha);
    cJSON_AddNumberToObject(root, "conformal_capacity", (double)config->conformal_capacity);
    cJSON_AddNumberToObject(root, "innovation_gate_kappa", config->innovation_gate_kappa);
    cJSON_AddNumberToObject(root, "innovation_gate_hysteresis", config->innovation_gate_hysteresis);

    // JSD and concentration thresholds
    cJSON_AddNumberToObject(root, "jsd_threshold", config->jsd_threshold);
    cJSON_AddNumberToObject(root, "max_flow_fraction_threshold", config->max_flow_fraction_threshold);
    cJSON_AddNumberToObject(root, "topk_flow_share_threshold", config->topk_flow_share_threshold);

    // EWMA parameters
    cJSON_AddNumberToObject(root, "alpha_immediate", config->alpha_immediate);
    cJSON_AddNumberToObject(root, "alpha_hourly", config->alpha_hourly);
    cJSON_AddNumberToObject(root, "alpha_weekly", config->alpha_weekly);

    // Minimum samples
    cJSON_AddNumberToObject(root, "min_samples_immediate", config->min_samples_immediate);
    cJSON_AddNumberToObject(root, "min_samples_hourly", config->min_samples_hourly);
    cJSON_AddNumberToObject(root, "min_samples_weekly", config->min_samples_weekly);

    // Attack handling
    cJSON_AddNumberToObject(root, "cool_down_seconds", config->cool_down_seconds);
    cJSON_AddBoolToObject(root, "baseline_freeze_enabled", config->baseline_freeze_enabled);

    // Timing
    cJSON_AddNumberToObject(root, "detection_interval_ms", config->detection_interval_ms);
    cJSON_AddNumberToObject(root, "jitter_ms", config->jitter_ms);

    // Minimum traffic threshold
    cJSON_AddNumberToObject(root, "min_pps_for_detection", (double)config->min_pps_for_detection);

    // FIX #4: Warmup emergency thresholds
    cJSON_AddNumberToObject(root, "warmup_pps_threshold", (double)config->warmup_pps_threshold);
    cJSON_AddNumberToObject(root, "warmup_syn_threshold", (double)config->warmup_syn_threshold);

    // Persistence
    cJSON_AddStringToObject(root, "baseline_file", config->baseline_file);
    cJSON_AddNumberToObject(root, "baseline_save_interval_sec", config->baseline_save_interval_sec);

    // Feature weights
    cJSON_AddBoolToObject(root, "use_feature_weights", config->use_feature_weights);
    cJSON *weights = cJSON_CreateArray();
    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        cJSON_AddItemToArray(weights, cJSON_CreateNumber(config->feature_weights[i]));
    }
    cJSON_AddItemToObject(root, "feature_weights", weights);

    // Logging
    cJSON_AddBoolToObject(root, "log_detections", config->log_detections);
    cJSON_AddBoolToObject(root, "log_baseline_updates", config->log_baseline_updates);
    cJSON_AddNumberToObject(root, "log_interval_sec", config->log_interval_sec);

    // Adaptive threshold tuning
    cJSON_AddBoolToObject(root, "adaptive_enabled", config->adaptive_enabled);
    cJSON_AddNumberToObject(root, "adaptive_min_threshold", config->adaptive_min_threshold);
    cJSON_AddNumberToObject(root, "adaptive_max_threshold", config->adaptive_max_threshold);
    cJSON_AddNumberToObject(root, "adaptive_step", config->adaptive_step);
    cJSON_AddNumberToObject(root, "adaptive_fp_threshold", config->adaptive_fp_threshold);
    cJSON_AddNumberToObject(root, "adaptive_tp_min", config->adaptive_tp_min);
    cJSON_AddNumberToObject(root, "adaptive_eval_interval_sec", config->adaptive_eval_interval_sec);
    cJSON_AddNumberToObject(root, "adaptive_min_samples", config->adaptive_min_samples);
    cJSON_AddNumberToObject(root, "fp_duration_threshold_sec", config->fp_duration_threshold_sec);
    cJSON_AddNumberToObject(root, "tp_duration_threshold_sec", config->tp_duration_threshold_sec);

    // Write to file
    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    if (!json_str) {
        return -1;
    }

    int result = write_file_contents(filepath, json_str);
    free(json_str);

    return result;
}

int layer2_config_validate(const struct layer2_config *config) {
    if (!config) {
        return -1;
    }

    // Validate Z-score threshold (tightened: 3.0-12.0 is practical range)
    // Values below 3.0 cause too many false positives
    // Values above 12.0 essentially disable detection (extremely rare)
    if (config->z_score_threshold < 3.0 || config->z_score_threshold > 12.0) {
        fprintf(stderr, "[Layer2] Invalid z_score_threshold: %.2f (must be 3.0-12.0)\n",
                config->z_score_threshold);
        return -1;
    }

    // Validate tier agreement
    if (config->min_tier_agreement < 1 || config->min_tier_agreement > 3) {
        fprintf(stderr, "[Layer2] Invalid min_tier_agreement: %d (must be 1-3)\n",
                config->min_tier_agreement);
        return -1;
    }


    // Validate alpha values (EWMA smoothing factors)
    if (config->alpha_immediate <= 0.0 || config->alpha_immediate > 1.0) {
        fprintf(stderr, "[Layer2] Invalid alpha_immediate: %.3f (must be 0.0-1.0)\n",
                config->alpha_immediate);
        return -1;
    }
    if (config->alpha_hourly <= 0.0 || config->alpha_hourly > 1.0) {
        fprintf(stderr, "[Layer2] Invalid alpha_hourly: %.3f (must be 0.0-1.0)\n",
                config->alpha_hourly);
        return -1;
    }
    if (config->alpha_weekly <= 0.0 || config->alpha_weekly > 1.0) {
        fprintf(stderr, "[Layer2] Invalid alpha_weekly: %.3f (must be 0.0-1.0)\n",
                config->alpha_weekly);
        return -1;
    }

    // Validate minimum samples
    if (config->min_samples_immediate < 1) {
        fprintf(stderr, "[Layer2] Invalid min_samples_immediate: %u (must be >= 1)\n",
                config->min_samples_immediate);
        return -1;
    }

    // Validate cool-down (max 5 minutes is reasonable)
    if (config->cool_down_seconds < 0.0 || config->cool_down_seconds > 300.0) {
        fprintf(stderr, "[Layer2] Invalid cool_down_seconds: %.2f (must be 0-300)\n",
                config->cool_down_seconds);
        return -1;
    }

    // Validate detection interval (tightened: 100-10000ms)
    // Values above 10000ms (10 seconds) mean very slow detection response
    if (config->detection_interval_ms < 100 || config->detection_interval_ms > 10000) {
        fprintf(stderr, "[Layer2] Invalid detection_interval_ms: %u (must be 100-10000)\n",
                config->detection_interval_ms);
        return -1;
    }

    // Warn about suboptimal but valid configurations
    if (config->z_score_threshold > 8.0) {
        fprintf(stderr, "[Layer2] Warning: z_score_threshold=%.1f is high, may miss subtle attacks\n",
                config->z_score_threshold);
    }
    if (config->detection_interval_ms > 5000) {
        fprintf(stderr, "[Layer2] Warning: detection_interval_ms=%u is slow, consider lowering\n",
                config->detection_interval_ms);
    }

    return 0;
}

const struct layer2_config *layer2_config_get(void) {
    // Lock-free read using atomic load
    struct layer2_config *config = atomic_load_explicit(&g_active_config, memory_order_acquire);
    if (config == NULL) {
        // Not yet initialized - return first buffer with defaults
        return &g_config_buffers[0];
    }
    return config;
}

struct layer2_config *layer2_config_get_buffer(void) {
    // Return primary buffer for initial loading
    // This allows layer2_init() to load directly into the double-buffer
    return &g_config_buffers[0];
}

int layer2_config_reload(void) {
    // Use double-buffering with atomic pointer swap
    // 1. Load into inactive buffer
    // 2. Atomically swap pointer
    // This provides lock-free reads for layer2_config_get()

    pthread_mutex_lock(&g_config_lock);

    // Determine which buffer to load into (the inactive one)
    int new_index = 1 - g_active_index;
    struct layer2_config *new_config = &g_config_buffers[new_index];

    // Load config into inactive buffer (outside critical path for readers)
    if (layer2_config_load(new_config, g_config_filepath) < 0) {
        pthread_mutex_unlock(&g_config_lock);
        return -1;
    }

    // Atomic pointer swap - makes new config visible to all readers instantly
    atomic_store_explicit(&g_active_config, new_config, memory_order_release);
    g_active_index = new_index;

    pthread_mutex_unlock(&g_config_lock);

    printf("[Layer2] Configuration reloaded\n");
    return 0;
}
