/**
 * @file tenant_config.c
 * @brief Per-Tenant Configuration Implementation
 *
 * Implements hierarchical configuration with:
 * - Tier-based presets
 * - Per-tenant overrides
 * - Per-lcore caching for lock-free fast path
 */

#include "tenant_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

#include <rte_cycles.h>
#include <rte_lcore.h>

// ==================== Thread-Local Cache ====================

__thread struct lcore_tenant_config_cache g_lcore_config_cache = {0};

// ==================== Global Config Storage ====================

static struct {
    // Tier presets
    struct tenant_full_config tier_presets[TENANT_TIER_COUNT];

    // Per-tenant config storage
    struct tenant_full_config tenant_configs[MAX_TENANTS];
    bool                      tenant_has_config[MAX_TENANTS];
    // Per-tenant generation counters for race-free cache validation
    _Atomic uint64_t          tenant_generations[MAX_TENANTS];

    // Global defaults (for TENANT_ID_GLOBAL)
    struct tenant_full_config global_defaults;

    // Version for cache invalidation
    uint64_t version;

    // Lock for config updates
    pthread_rwlock_t lock;

    // Initialized flag
    bool initialized;
} g_config;

// ==================== Default Configuration Values ====================

// Initialize L1 defaults
static void init_l1_defaults(struct tenant_l1_config *cfg, tenant_tier_t tier) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->version = 1;

    // Rate limits vary by tier
    switch (tier) {
        case TENANT_TIER_FREE:
            cfg->rate_limits.global_pps = 100000;
            cfg->rate_limits.global_bps = 100000000;
            cfg->rate_limits.per_src_pps = 1000;
            cfg->rate_limits.syn_pps = 500;
            cfg->rate_limits.udp_pps = 5000;
            cfg->rate_limits.icmp_pps = 100;
            cfg->conn_limits.max_conn_per_src = 100;
            cfg->conn_limits.max_half_open_per_src = 10;
            cfg->conn_limits.max_conn_global = 10000;
            break;

        case TENANT_TIER_BASIC:
            cfg->rate_limits.global_pps = 500000;
            cfg->rate_limits.global_bps = 1000000000;
            cfg->rate_limits.per_src_pps = 5000;
            cfg->rate_limits.syn_pps = 2000;
            cfg->rate_limits.udp_pps = 20000;
            cfg->rate_limits.icmp_pps = 500;
            cfg->conn_limits.max_conn_per_src = 500;
            cfg->conn_limits.max_half_open_per_src = 50;
            cfg->conn_limits.max_conn_global = 50000;
            break;

        case TENANT_TIER_STANDARD:
            cfg->rate_limits.global_pps = 2000000;
            cfg->rate_limits.global_bps = 5000000000;
            cfg->rate_limits.per_src_pps = 10000;
            cfg->rate_limits.syn_pps = 5000;
            cfg->rate_limits.udp_pps = 50000;
            cfg->rate_limits.icmp_pps = 1000;
            cfg->conn_limits.max_conn_per_src = 1000;
            cfg->conn_limits.max_half_open_per_src = 100;
            cfg->conn_limits.max_conn_global = 200000;
            break;

        case TENANT_TIER_PREMIUM:
            cfg->rate_limits.global_pps = 10000000;
            cfg->rate_limits.global_bps = 20000000000;
            cfg->rate_limits.per_src_pps = 20000;
            cfg->rate_limits.syn_pps = 10000;
            cfg->rate_limits.udp_pps = 100000;
            cfg->rate_limits.icmp_pps = 2000;
            cfg->conn_limits.max_conn_per_src = 2000;
            cfg->conn_limits.max_half_open_per_src = 200;
            cfg->conn_limits.max_conn_global = 500000;
            break;

        case TENANT_TIER_ENTERPRISE:
        case TENANT_TIER_CUSTOM:
        default:
            cfg->rate_limits.global_pps = 50000000;
            cfg->rate_limits.global_bps = 100000000000;
            cfg->rate_limits.per_src_pps = 50000;
            cfg->rate_limits.syn_pps = 25000;
            cfg->rate_limits.udp_pps = 200000;
            cfg->rate_limits.icmp_pps = 5000;
            cfg->conn_limits.max_conn_per_src = 5000;
            cfg->conn_limits.max_half_open_per_src = 500;
            cfg->conn_limits.max_conn_global = 2000000;
            break;
    }

    // Common settings
    cfg->rate_limits.dns_qps = cfg->rate_limits.udp_pps / 10;
    cfg->rate_limits.ntp_qps = 100;

    cfg->per_src_rate_limits.syn_pps = 10;
    cfg->per_src_rate_limits.ack_pps = 1000;
    cfg->per_src_rate_limits.udp_pps = 500;
    cfg->per_src_rate_limits.icmp_pps = 10;

    cfg->conn_limits.max_new_conn_per_sec = cfg->conn_limits.max_conn_global / 100;
    cfg->conn_limits.max_half_open_global = cfg->conn_limits.max_conn_global / 10;

    // SYN proxy settings
    cfg->syn_proxy.enabled = true;
    cfg->syn_proxy.always_on = (tier >= TENANT_TIER_ENTERPRISE);
    cfg->syn_proxy.challenge_threshold_pps = 1000;
    cfg->syn_proxy.max_half_open = cfg->conn_limits.max_half_open_global;
    cfg->syn_proxy.challenge_method = 0; // cookie
    cfg->syn_proxy.cookie_ttl_sec = 30;

    // UDP gatekeeper
    cfg->udp_gatekeeper.enabled = (tier >= TENANT_TIER_STANDARD);
    cfg->udp_gatekeeper.grace_period_sec = 5;
    cfg->udp_gatekeeper.validation_timeout = 30;

    // Feature toggles
    cfg->features.geo_blocking = (tier >= TENANT_TIER_STANDARD);
    cfg->features.reputation_filtering = (tier >= TENANT_TIER_STANDARD);
    cfg->features.tcp_abuse_detection = (tier >= TENANT_TIER_BASIC);
    cfg->features.signature_detection = true;
    cfg->features.udp_gatekeeper = (tier >= TENANT_TIER_STANDARD);
    cfg->features.icmp_filtering = true;
    cfg->features.dns_protection = (tier >= TENANT_TIER_PREMIUM);
    cfg->features.ntp_protection = (tier >= TENANT_TIER_PREMIUM);

    // TCP abuse detection thresholds
    cfg->tcp_abuse.dup_seq_threshold = 150;
    cfg->tcp_abuse.random_seq_threshold = 45;
    cfg->tcp_abuse.random_ack_threshold = 45;
    cfg->tcp_abuse.zero_window_threshold = 5;
    cfg->tcp_abuse.tiny_window_bytes = 100;
    cfg->tcp_abuse.small_window_bytes = 2000;
}

// Initialize L2 defaults
static void init_l2_defaults(struct tenant_l2_config *cfg, tenant_tier_t tier) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->version = 1;

    // Thresholds
    cfg->thresholds.z_score_threshold = (tier >= TENANT_TIER_ENTERPRISE) ? 2.5 : 3.0;
    cfg->thresholds.jsd_threshold = 0.3;
    cfg->thresholds.flow_concentration_threshold = 0.5;
    cfg->thresholds.sensitivity_multiplier = 1.0;
    cfg->thresholds.entropy_deviation_threshold = 0.4;

    // Baseline settings
    cfg->baseline.alpha_immediate = 0.3;
    cfg->baseline.alpha_hourly = 0.1;
    cfg->baseline.alpha_weekly = 0.05;
    cfg->baseline.min_samples_immediate = 100;
    cfg->baseline.min_samples_hourly = 1000;
    cfg->baseline.min_samples_weekly = 10000;
    cfg->baseline.auto_freeze_on_attack = true;
    cfg->baseline.use_adaptive_threshold = (tier >= TENANT_TIER_PREMIUM);

    // Response settings
    cfg->response.escalation_delay_sec = 10;
    cfg->response.deescalation_delay_sec = 60;
    cfg->response.auto_mitigation = (tier >= TENANT_TIER_STANDARD);
    cfg->response.notify_layer3 = true;
    cfg->response.notify_layer4 = (tier >= TENANT_TIER_STANDARD);
    cfg->response.min_severity_for_action = 2;

    // Per-IP settings
    cfg->per_ip.inherit_tenant_settings = true;
    cfg->per_ip.sensitivity_multiplier = 1.0;

    // Carpet bomb attack detection settings
    cfg->carpet_bomb.enabled = (tier >= TENANT_TIER_STANDARD);
    cfg->carpet_bomb.prefix_len = 24;
}

// Initialize L3 defaults
static void init_l3_defaults(struct tenant_l3_config *cfg, tenant_tier_t tier) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->version = 1;

    // Model settings
    cfg->model.model_path[0] = '\0'; // Use default model
    cfg->model.confidence_threshold = 0.7;
    cfg->model.inference_interval_ms = 1000;
    cfg->model.enable_online_learning = (tier >= TENANT_TIER_ENTERPRISE);
    cfg->model.use_ensemble = (tier >= TENANT_TIER_PREMIUM);
    cfg->model.enable_autoencoder = (tier >= TENANT_TIER_STANDARD);
    cfg->model.enable_isolation_forest = true;

    // Attribution settings
    cfg->attribution.min_packets_for_attribution = 1000;
    cfg->attribution.attribution_confidence = 0.8;
    cfg->attribution.enable_clustering = (tier >= TENANT_TIER_PREMIUM);
    cfg->attribution.enable_fingerprinting = (tier >= TENANT_TIER_STANDARD);

    // Policy generation
    cfg->policy.max_policies = (tier >= TENANT_TIER_ENTERPRISE) ? 2000 :
                               (tier >= TENANT_TIER_PREMIUM) ? 500 : 100;
    cfg->policy.policy_ttl_sec = 3600; // 1 hour default
    cfg->policy.require_confirmation = (tier < TENANT_TIER_STANDARD);
    cfg->policy.auto_propagate_to_l1 = (tier >= TENANT_TIER_STANDARD);
    cfg->policy.learn_from_feedback = (tier >= TENANT_TIER_PREMIUM);

    // Feature extraction
    cfg->features.extract_payload_features = (tier >= TENANT_TIER_PREMIUM);
    cfg->features.extract_timing_features = true;
    cfg->features.extract_flow_features = true;
    cfg->features.payload_sample_bytes = 64;
}

// Initialize L4 defaults
static void init_l4_defaults(struct tenant_l4_config *cfg, tenant_tier_t tier) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->version = 1;

    // Reputation settings
    cfg->reputation.initial_score = 0.5;
    cfg->reputation.decay_rate_per_hour = 0.01;
    cfg->reputation.block_threshold = 0.1;
    cfg->reputation.challenge_threshold = 0.3;
    cfg->reputation.trust_threshold = 0.9;
    cfg->reputation.history_window_hours = (tier >= TENANT_TIER_ENTERPRISE) ? 720 : 168; // 30 days or 7 days
    cfg->reputation.share_with_global = (tier >= TENANT_TIER_STANDARD);
    cfg->reputation.use_global_reputation = (tier >= TENANT_TIER_STANDARD);

    // Challenge settings
    cfg->challenge.js_challenge_enabled = (tier >= TENANT_TIER_PREMIUM);
    cfg->challenge.captcha_enabled = (tier >= TENANT_TIER_PREMIUM);
    cfg->challenge.proof_of_work_enabled = (tier >= TENANT_TIER_ENTERPRISE);
    cfg->challenge.challenge_difficulty = 5; // Medium
    cfg->challenge.challenge_validity_sec = 300;
    cfg->challenge.max_challenge_attempts = 3;
    cfg->challenge.challenge_cooldown_sec = 60;

    // Bot management
    cfg->bot_management.enabled = (tier >= TENANT_TIER_PREMIUM);
    cfg->bot_management.block_known_bots = true;
    cfg->bot_management.block_headless_browsers = true;
    cfg->bot_management.block_automation_tools = true;
    cfg->bot_management.allow_good_bots = true;
    strncpy(cfg->bot_management.good_bot_list,
            "Googlebot,Bingbot,Slurp,DuckDuckBot,Baiduspider,YandexBot",
            MAX_GOOD_BOT_LIST_LEN - 1);

    // App rate limits
    cfg->app_rate_limits.http_req_per_sec = (tier >= TENANT_TIER_ENTERPRISE) ? 10000 : 1000;
    cfg->app_rate_limits.http_req_per_min = cfg->app_rate_limits.http_req_per_sec * 60;
    cfg->app_rate_limits.api_req_per_sec = cfg->app_rate_limits.http_req_per_sec / 10;
    cfg->app_rate_limits.login_attempts_per_min = 10;
    cfg->app_rate_limits.form_submits_per_min = 30;

    // Behavioral analysis
    cfg->behavior.track_session_behavior = (tier >= TENANT_TIER_PREMIUM);
    cfg->behavior.detect_credential_stuffing = (tier >= TENANT_TIER_PREMIUM);
    cfg->behavior.detect_scraping = (tier >= TENANT_TIER_PREMIUM);
    cfg->behavior.detect_api_abuse = (tier >= TENANT_TIER_PREMIUM);
    cfg->behavior.session_timeout_sec = 3600;
}

// Initialize L5 defaults
static void init_l5_defaults(struct tenant_l5_config *cfg, tenant_tier_t tier) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->version = 1;

    // Threat intelligence
    cfg->intel.enable_global_intel = (tier >= TENANT_TIER_STANDARD);
    cfg->intel.enable_custom_feeds = (tier >= TENANT_TIER_ENTERPRISE);
    cfg->intel.enable_real_time_intel = (tier >= TENANT_TIER_ENTERPRISE);
    cfg->intel.feed_update_interval_min = 15;
    cfg->intel.intel_ttl_hours = 24;

    // Learning settings
    cfg->learning.contribute_to_global = (tier >= TENANT_TIER_STANDARD);
    cfg->learning.receive_global_updates = (tier >= TENANT_TIER_STANDARD);
    cfg->learning.enable_peer_learning = (tier >= TENANT_TIER_ENTERPRISE);
    cfg->learning.privacy_level = (tier >= TENANT_TIER_ENTERPRISE) ? 1 : 2;
    cfg->learning.learning_rate = 0.1;
    cfg->learning.min_confidence_to_share = 80;

    // Baseline optimization
    cfg->baseline_optimization.auto_tune_baselines = (tier >= TENANT_TIER_PREMIUM);
    cfg->baseline_optimization.seasonal_adjustment = (tier >= TENANT_TIER_ENTERPRISE);
    cfg->baseline_optimization.event_calendar = (tier >= TENANT_TIER_ENTERPRISE);
    cfg->baseline_optimization.optimization_interval_hours = 24;

    // Reporting
    cfg->reporting.weekly_report_enabled = (tier >= TENANT_TIER_BASIC);
    cfg->reporting.attack_report_enabled = (tier >= TENANT_TIER_STANDARD);
    cfg->reporting.real_time_alerts = (tier >= TENANT_TIER_PREMIUM);
    cfg->reporting.report_retention_days = (tier >= TENANT_TIER_ENTERPRISE) ? 365 : 90;
}

// Initialize full config for a tier
static void init_tier_preset(struct tenant_full_config *cfg, tenant_tier_t tier) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->tenant_id = TENANT_ID_GLOBAL;
    cfg->version = 1;

    init_l1_defaults(&cfg->l1, tier);
    init_l2_defaults(&cfg->l2, tier);
    init_l3_defaults(&cfg->l3, tier);
    init_l4_defaults(&cfg->l4, tier);
    init_l5_defaults(&cfg->l5, tier);
}

// ==================== Initialization API ====================

int tenant_config_init(void) {
    if (g_config.initialized) {
        return 0;
    }

    memset(&g_config, 0, sizeof(g_config));

    // Initialize lock
    if (pthread_rwlock_init(&g_config.lock, NULL) != 0) {
        fprintf(stderr, "Failed to initialize tenant config lock\n");
        return -1;
    }

    // Initialize tier presets
    for (int tier = 0; tier < TENANT_TIER_COUNT; tier++) {
        init_tier_preset(&g_config.tier_presets[tier], (tenant_tier_t)tier);
    }

    // Initialize global defaults (use STANDARD tier)
    init_tier_preset(&g_config.global_defaults, TENANT_TIER_STANDARD);

    g_config.version = 1;
    g_config.initialized = true;

    printf("Tenant config system initialized with %d tier presets\n", TENANT_TIER_COUNT);
    return 0;
}

void tenant_config_cleanup(void) {
    if (!g_config.initialized) return;

    pthread_rwlock_destroy(&g_config.lock);
    g_config.initialized = false;

    printf("Tenant config system cleaned up\n");
}

int tenant_config_load_all(const char *config_dir) {
    // TODO: Implement JSON config loading
    (void)config_dir;
    return 0;
}

int tenant_config_reload(tenant_id_t id) {
    if (!g_config.initialized) return -1;

    pthread_rwlock_wrlock(&g_config.lock);
    g_config.version++;
    pthread_rwlock_unlock(&g_config.lock);

    tenant_config_cache_invalidate();
    return 0;

    (void)id;
}

int tenant_config_reload_all(void) {
    if (!g_config.initialized) return -1;

    pthread_rwlock_wrlock(&g_config.lock);
    g_config.version++;
    pthread_rwlock_unlock(&g_config.lock);

    tenant_config_cache_invalidate();
    return 0;
}

// ==================== Config Getter API ====================

const struct tenant_l1_config* tenant_get_l1_config(tenant_id_t id) {
    if (!g_config.initialized) return NULL;

    // Global defaults
    if (id == TENANT_ID_GLOBAL) {
        return &g_config.global_defaults.l1;
    }

    // Check for tenant-specific config
    if (id < MAX_TENANTS && g_config.tenant_has_config[id]) {
        return &g_config.tenant_configs[id].l1;
    }

    // Fall back to tenant's tier preset
    const struct tenant *t = tenant_lookup(id);
    if (t && t->tier < TENANT_TIER_COUNT) {
        return &g_config.tier_presets[t->tier].l1;
    }

    // Fall back to global defaults
    return &g_config.global_defaults.l1;
}

const struct tenant_l2_config* tenant_get_l2_config(tenant_id_t id) {
    if (!g_config.initialized) return NULL;

    if (id == TENANT_ID_GLOBAL) {
        return &g_config.global_defaults.l2;
    }

    if (id < MAX_TENANTS && g_config.tenant_has_config[id]) {
        return &g_config.tenant_configs[id].l2;
    }

    const struct tenant *t = tenant_lookup(id);
    if (t && t->tier < TENANT_TIER_COUNT) {
        return &g_config.tier_presets[t->tier].l2;
    }

    return &g_config.global_defaults.l2;
}

const struct tenant_l3_config* tenant_get_l3_config(tenant_id_t id) {
    if (!g_config.initialized) return NULL;

    if (id == TENANT_ID_GLOBAL) {
        return &g_config.global_defaults.l3;
    }

    if (id < MAX_TENANTS && g_config.tenant_has_config[id]) {
        return &g_config.tenant_configs[id].l3;
    }

    const struct tenant *t = tenant_lookup(id);
    if (t && t->tier < TENANT_TIER_COUNT) {
        return &g_config.tier_presets[t->tier].l3;
    }

    return &g_config.global_defaults.l3;
}

const struct tenant_l4_config* tenant_get_l4_config(tenant_id_t id) {
    if (!g_config.initialized) return NULL;

    if (id == TENANT_ID_GLOBAL) {
        return &g_config.global_defaults.l4;
    }

    if (id < MAX_TENANTS && g_config.tenant_has_config[id]) {
        return &g_config.tenant_configs[id].l4;
    }

    const struct tenant *t = tenant_lookup(id);
    if (t && t->tier < TENANT_TIER_COUNT) {
        return &g_config.tier_presets[t->tier].l4;
    }

    return &g_config.global_defaults.l4;
}

const struct tenant_l5_config* tenant_get_l5_config(tenant_id_t id) {
    if (!g_config.initialized) return NULL;

    if (id == TENANT_ID_GLOBAL) {
        return &g_config.global_defaults.l5;
    }

    if (id < MAX_TENANTS && g_config.tenant_has_config[id]) {
        return &g_config.tenant_configs[id].l5;
    }

    const struct tenant *t = tenant_lookup(id);
    if (t && t->tier < TENANT_TIER_COUNT) {
        return &g_config.tier_presets[t->tier].l5;
    }

    return &g_config.global_defaults.l5;
}

const struct tenant_full_config* tenant_get_full_config(tenant_id_t id) {
    if (!g_config.initialized) return NULL;

    if (id == TENANT_ID_GLOBAL) {
        return &g_config.global_defaults;
    }

    if (id < MAX_TENANTS && g_config.tenant_has_config[id]) {
        return &g_config.tenant_configs[id];
    }

    const struct tenant *t = tenant_lookup(id);
    if (t && t->tier < TENANT_TIER_COUNT) {
        return &g_config.tier_presets[t->tier];
    }

    return &g_config.global_defaults;
}

// ==================== Config Setter API ====================

int tenant_set_l1_config(tenant_id_t id, const struct tenant_l1_config *cfg) {
    if (!g_config.initialized || !cfg || id >= MAX_TENANTS) return -1;

    pthread_rwlock_wrlock(&g_config.lock);

    // Increment generation BEFORE config update to invalidate caches
    atomic_fetch_add(&g_config.tenant_generations[id], 1);

    // Copy config
    memcpy(&g_config.tenant_configs[id].l1, cfg, sizeof(*cfg));
    g_config.tenant_configs[id].l1.tenant_id = id;
    g_config.tenant_configs[id].l1.version = g_config.version + 1;
    g_config.tenant_has_config[id] = true;
    g_config.version++;

    pthread_rwlock_unlock(&g_config.lock);

    return 0;
}

int tenant_set_l2_config(tenant_id_t id, const struct tenant_l2_config *cfg) {
    if (!g_config.initialized || !cfg || id >= MAX_TENANTS) return -1;

    pthread_rwlock_wrlock(&g_config.lock);

    memcpy(&g_config.tenant_configs[id].l2, cfg, sizeof(*cfg));
    g_config.tenant_configs[id].l2.tenant_id = id;
    g_config.tenant_configs[id].l2.version = g_config.version + 1;
    g_config.tenant_has_config[id] = true;
    g_config.version++;

    pthread_rwlock_unlock(&g_config.lock);

    return 0;
}

int tenant_set_l3_config(tenant_id_t id, const struct tenant_l3_config *cfg) {
    if (!g_config.initialized || !cfg || id >= MAX_TENANTS) return -1;

    pthread_rwlock_wrlock(&g_config.lock);

    memcpy(&g_config.tenant_configs[id].l3, cfg, sizeof(*cfg));
    g_config.tenant_configs[id].l3.tenant_id = id;
    g_config.tenant_configs[id].l3.version = g_config.version + 1;
    g_config.tenant_has_config[id] = true;
    g_config.version++;

    pthread_rwlock_unlock(&g_config.lock);

    return 0;
}

int tenant_set_l4_config(tenant_id_t id, const struct tenant_l4_config *cfg) {
    if (!g_config.initialized || !cfg || id >= MAX_TENANTS) return -1;

    pthread_rwlock_wrlock(&g_config.lock);

    memcpy(&g_config.tenant_configs[id].l4, cfg, sizeof(*cfg));
    g_config.tenant_configs[id].l4.tenant_id = id;
    g_config.tenant_configs[id].l4.version = g_config.version + 1;
    g_config.tenant_has_config[id] = true;
    g_config.version++;

    pthread_rwlock_unlock(&g_config.lock);

    return 0;
}

int tenant_set_l5_config(tenant_id_t id, const struct tenant_l5_config *cfg) {
    if (!g_config.initialized || !cfg || id >= MAX_TENANTS) return -1;

    pthread_rwlock_wrlock(&g_config.lock);

    memcpy(&g_config.tenant_configs[id].l5, cfg, sizeof(*cfg));
    g_config.tenant_configs[id].l5.tenant_id = id;
    g_config.tenant_configs[id].l5.version = g_config.version + 1;
    g_config.tenant_has_config[id] = true;
    g_config.version++;

    pthread_rwlock_unlock(&g_config.lock);

    return 0;
}

// ==================== Tier Presets API ====================

int tenant_config_apply_tier_preset(tenant_id_t id, tenant_tier_t tier) {
    if (!g_config.initialized || id >= MAX_TENANTS || tier >= TENANT_TIER_COUNT) {
        return -1;
    }

    pthread_rwlock_wrlock(&g_config.lock);

    // Increment generation BEFORE config update to invalidate caches
    atomic_fetch_add(&g_config.tenant_generations[id], 1);

    // Copy tier preset to tenant config
    memcpy(&g_config.tenant_configs[id], &g_config.tier_presets[tier],
           sizeof(struct tenant_full_config));
    g_config.tenant_configs[id].tenant_id = id;
    g_config.tenant_configs[id].version = g_config.version + 1;
    g_config.tenant_has_config[id] = true;
    g_config.version++;

    pthread_rwlock_unlock(&g_config.lock);

    return 0;
}

const struct tenant_full_config* tenant_config_get_tier_preset(tenant_tier_t tier) {
    if (!g_config.initialized || tier >= TENANT_TIER_COUNT) {
        return &g_config.global_defaults;
    }

    return &g_config.tier_presets[tier];
}

// ==================== Validation API ====================

int tenant_config_validate(const struct tenant_full_config *cfg,
                           char *errors, size_t errors_size) {
    if (!cfg) {
        if (errors && errors_size > 0) {
            snprintf(errors, errors_size, "config is NULL");
        }
        return -1;
    }

    // Validate L1
    int ret = tenant_config_validate_l1(&cfg->l1, errors, errors_size);
    if (ret != 0) return ret;

    // TODO: Validate other layers

    return 0;
}

int tenant_config_validate_l1(const struct tenant_l1_config *cfg,
                              char *errors, size_t errors_size) {
    if (!cfg) {
        if (errors && errors_size > 0) {
            snprintf(errors, errors_size, "L1 config is NULL");
        }
        return -1;
    }

    // Validate rate limits
    if (cfg->rate_limits.global_pps > 0 &&
        cfg->rate_limits.per_src_pps > cfg->rate_limits.global_pps) {
        if (errors && errors_size > 0) {
            snprintf(errors, errors_size,
                     "per_src_pps (%u) cannot exceed global_pps (%lu)",
                     cfg->rate_limits.per_src_pps,
                     (unsigned long)cfg->rate_limits.global_pps);
        }
        return -1;
    }

    // Validate SYN proxy
    if (cfg->syn_proxy.challenge_method > 2) {
        if (errors && errors_size > 0) {
            snprintf(errors, errors_size,
                     "invalid challenge_method: %u (must be 0-2)",
                     cfg->syn_proxy.challenge_method);
        }
        return -1;
    }

    return 0;
}

// ==================== Cache Management ====================

bool tenant_config_cache_update(void) {
    if (!g_config.initialized) return false;

    uint64_t current_version = __atomic_load_n(&g_config.version, __ATOMIC_ACQUIRE);

    if (g_lcore_config_cache.version == current_version) {
        return false; // No update needed
    }

    // Update cache
    pthread_rwlock_rdlock(&g_config.lock);

    for (int i = 0; i < MAX_TENANTS; i++) {
        if (g_config.tenant_has_config[i]) {
            g_lcore_config_cache.l1_configs[i] = &g_config.tenant_configs[i].l1;
        } else {
            // Will fall back to tier preset at lookup time
            g_lcore_config_cache.l1_configs[i] = NULL;
        }
        // Capture generation for race detection
        g_lcore_config_cache.l1_generations[i] =
            atomic_load(&g_config.tenant_generations[i]);
    }

    g_lcore_config_cache.version = current_version;
    g_lcore_config_cache.last_update_tsc = rte_rdtsc();

    pthread_rwlock_unlock(&g_config.lock);

    return true;
}

void tenant_config_cache_invalidate(void) {
    if (!g_config.initialized) return;

    pthread_rwlock_wrlock(&g_config.lock);
    g_config.version++;
    pthread_rwlock_unlock(&g_config.lock);
}

// Get tenant generation counter for cache validation
uint64_t tenant_get_generation(tenant_id_t id) {
    if (!g_config.initialized || id >= MAX_TENANTS) {
        return 0;
    }
    return atomic_load(&g_config.tenant_generations[id]);
}

// Safe cached config accessor with generation check
const struct tenant_l1_config* tenant_get_l1_config_cached_safe(tenant_id_t id,
                                                                  uint64_t *out_gen) {
    if (!g_config.initialized || id >= MAX_TENANTS) {
        if (out_gen) *out_gen = 0;
        return NULL;
    }

    // Get cached pointer and generation
    const struct tenant_l1_config *cached = g_lcore_config_cache.l1_configs[id];
    uint64_t cached_gen = g_lcore_config_cache.l1_generations[id];

    if (out_gen) *out_gen = cached_gen;

    // Validate against current global generation
    uint64_t current_gen = atomic_load(&g_config.tenant_generations[id]);
    if (cached_gen != current_gen) {
        // Cache is stale - caller should refresh
        return NULL;
    }

    return cached;
}

// ==================== Serialization ====================

int tenant_config_to_json(const struct tenant_full_config *cfg,
                          char *buf, size_t buf_size) {
    if (!cfg || !buf || buf_size < 512) {
        return -1;
    }

    // Simplified JSON output
    int len = snprintf(buf, buf_size,
        "{"
        "\"tenant_id\":%u,"
        "\"version\":%lu,"
        "\"l1\":{\"global_pps\":%lu,\"global_bps\":%lu,\"syn_proxy_enabled\":%s},"
        "\"l2\":{\"z_score_threshold\":%.2f},"
        "\"l3\":{\"confidence_threshold\":%.2f},"
        "\"l4\":{\"initial_score\":%.2f,\"block_threshold\":%.2f},"
        "\"l5\":{\"enable_global_intel\":%s}"
        "}",
        cfg->tenant_id,
        (unsigned long)cfg->version,
        (unsigned long)cfg->l1.rate_limits.global_pps,
        (unsigned long)cfg->l1.rate_limits.global_bps,
        cfg->l1.syn_proxy.enabled ? "true" : "false",
        cfg->l2.thresholds.z_score_threshold,
        cfg->l3.model.confidence_threshold,
        cfg->l4.reputation.initial_score,
        cfg->l4.reputation.block_threshold,
        cfg->l5.intel.enable_global_intel ? "true" : "false"
    );

    // Detect truncation - snprintf returns what WOULD have been written
    if (len < 0 || (size_t)len >= buf_size) {
        // Truncation occurred or encoding error
        return -2;  // Return distinct error code for truncation
    }

    return len;
}

int tenant_config_from_json(const char *json, struct tenant_full_config *cfg) {
    // TODO: Implement JSON parsing
    (void)json;
    (void)cfg;
    return -1;
}

// ==================== Debugging ====================

void tenant_config_print_l1(const struct tenant_l1_config *cfg) {
    if (!cfg) return;

    printf("Layer 1 Config (tenant %u, version %lu):\n", cfg->tenant_id, (unsigned long)cfg->version);
    printf("  Rate Limits:\n");
    printf("    Global: %lu PPS, %lu BPS\n",
           (unsigned long)cfg->rate_limits.global_pps,
           (unsigned long)cfg->rate_limits.global_bps);
    printf("    Per-Src: %u PPS\n", cfg->rate_limits.per_src_pps);
    printf("    SYN: %u PPS, UDP: %u PPS, ICMP: %u PPS\n",
           cfg->rate_limits.syn_pps,
           cfg->rate_limits.udp_pps,
           cfg->rate_limits.icmp_pps);
    printf("  Connection Limits:\n");
    printf("    Per-Src: %u, Half-Open/Src: %u, Global: %u\n",
           cfg->conn_limits.max_conn_per_src,
           cfg->conn_limits.max_half_open_per_src,
           cfg->conn_limits.max_conn_global);
    printf("  SYN Proxy: %s (threshold: %u PPS)\n",
           cfg->syn_proxy.enabled ? "enabled" : "disabled",
           cfg->syn_proxy.challenge_threshold_pps);
    printf("  Features: geo=%d, reputation=%d, tcp_abuse=%d, sigs=%d\n",
           cfg->features.geo_blocking,
           cfg->features.reputation_filtering,
           cfg->features.tcp_abuse_detection,
           cfg->features.signature_detection);
}

void tenant_config_print_full(const struct tenant_full_config *cfg) {
    if (!cfg) return;

    printf("=== Full Tenant Config (ID: %u, Version: %lu) ===\n",
           cfg->tenant_id, (unsigned long)cfg->version);

    tenant_config_print_l1(&cfg->l1);

    printf("  Layer 2: z_score=%.2f, sensitivity=%.2f\n",
           cfg->l2.thresholds.z_score_threshold,
           cfg->l2.thresholds.sensitivity_multiplier);

    printf("  Layer 3: confidence=%.2f, ensemble=%d\n",
           cfg->l3.model.confidence_threshold,
           cfg->l3.model.use_ensemble);

    printf("  Layer 4: initial_score=%.2f, block=%.2f, challenge=%.2f\n",
           cfg->l4.reputation.initial_score,
           cfg->l4.reputation.block_threshold,
           cfg->l4.reputation.challenge_threshold);

    printf("  Layer 5: global_intel=%d, contribute=%d\n",
           cfg->l5.intel.enable_global_intel,
           cfg->l5.learning.contribute_to_global);
}
