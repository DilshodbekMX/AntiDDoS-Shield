/**
 * @file tenant_config.h
 * @brief Per-Tenant Configuration for All Layers
 *
 * Provides hierarchical configuration with:
 * - System defaults (compiled-in)
 * - Global config (layer*_config.json)
 * - Tier presets (tier_presets.json)
 * - Tenant overrides (tenants/{id}/config.json)
 *
 * Configuration inheritance:
 *   System Defaults -> Global Config -> Tier Presets -> Tenant Overrides
 *
 * Performance:
 * - Per-lcore config caching for lock-free fast path
 * - Hot reload support (SIGHUP handler)
 * - Cache invalidation via version numbers
 */

#ifndef TENANT_CONFIG_H
#define TENANT_CONFIG_H

#include "tenant.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==================== Configuration Limits ====================

#define MAX_GEO_COUNTRIES           256
#define MAX_CUSTOM_FEED_URLS        4
#define MAX_CUSTOM_FEED_URL_LEN     256
#define MAX_GOOD_BOT_LIST_LEN       1024
#define MAX_REPORT_RECIPIENTS_LEN   512
#define MAX_MODEL_PATH_LEN          256

// Country code bitmap size (256 countries / 64 bits per uint64)
#define GEO_BITMAP_SIZE             4

// ==================== Layer 1 Tenant Config ====================

/**
 * Per-tenant Layer 1 (DPDK Packet Processing) configuration
 */
struct tenant_l1_config {
    tenant_id_t tenant_id;
    uint64_t    version;             // For cache invalidation

    // Rate limits (0 = use tier default)
    struct {
        uint64_t    global_pps;      // Max packets per second (tenant aggregate)
        uint64_t    global_bps;      // Max bits per second (tenant aggregate)
        uint32_t    per_src_pps;     // Per source IP packets/sec
        uint32_t    per_src_bps;     // Per source IP bits/sec
        uint32_t    syn_pps;         // SYN packets/sec (total for tenant)
        uint32_t    ack_pps;         // ACK packets/sec
        uint32_t    rst_pps;         // RST packets/sec
        uint32_t    fin_pps;         // FIN packets/sec
        uint32_t    udp_pps;         // UDP packets/sec
        uint32_t    icmp_pps;        // ICMP packets/sec
        uint32_t    dns_qps;         // DNS queries per second
        uint32_t    ntp_qps;         // NTP queries per second (for amplification)
    } rate_limits;

    // Per-source rate limits
    struct {
        uint32_t    syn_pps;         // SYN per source IP
        uint32_t    ack_pps;         // ACK per source IP
        uint32_t    udp_pps;         // UDP per source IP
        uint32_t    icmp_pps;        // ICMP per source IP
    } per_src_rate_limits;

    // Connection limits
    struct {
        uint32_t    max_conn_per_src;        // Max connections per source IP
        uint32_t    max_half_open_per_src;   // Max half-open per source IP
        uint32_t    max_conn_global;         // Max total connections
        uint32_t    max_new_conn_per_sec;    // Max new connections/sec
        uint32_t    max_half_open_global;    // Max total half-open
    } conn_limits;

    // SYN proxy settings
    struct {
        bool        enabled;              // SYN proxy enabled
        bool        always_on;            // Force even without attack
        uint32_t    challenge_threshold_pps; // Enable when SYN rate exceeds
        uint32_t    max_half_open;        // Max half-open proxy connections
        uint8_t     challenge_method;     // 0=cookie, 1=puzzle, 2=hybrid
        uint8_t     cookie_ttl_sec;       // Cookie validity period
        uint16_t    _pad;
    } syn_proxy;

    // UDP gatekeeper settings
    struct {
        bool        enabled;
        uint32_t    grace_period_sec;     // Time to allow UDP before validation
        uint32_t    validation_timeout;   // Validation timeout
    } udp_gatekeeper;

    // Feature toggles
    struct {
        bool        geo_blocking;         // Geo-IP blocking enabled
        bool        reputation_filtering; // Use reputation scores
        bool        tcp_abuse_detection;  // TCP protocol abuse detection
        bool        signature_detection;  // Attack signature matching
        bool        udp_gatekeeper;       // UDP admission control
        bool        icmp_filtering;       // ICMP rate limiting
        bool        dns_protection;       // DNS amplification protection
        bool        ntp_protection;       // NTP amplification protection
    } features;

    // Geo-blocking configuration (bitmask for 256 country codes)
    // Each bit corresponds to a country code (0-255)
    uint64_t    blocked_countries[GEO_BITMAP_SIZE];
    uint64_t    allowed_countries[GEO_BITMAP_SIZE]; // If set, only these allowed
    bool        geo_whitelist_mode;   // false=blacklist, true=whitelist

    // TCP abuse detection thresholds (override global defaults)
    struct {
        uint32_t    dup_seq_threshold;        // >150/sec = drop
        uint32_t    random_seq_threshold;     // >45 jumps in 10s
        uint32_t    random_ack_threshold;     // >45 jumps in 10s
        uint32_t    zero_window_threshold;    // >5 in 10s
        uint16_t    tiny_window_bytes;        // <100 bytes
        uint16_t    small_window_bytes;       // <2000 bytes
    } tcp_abuse;

    // Padding for cache alignment
    uint8_t     _pad[4];
};

// ==================== Layer 2 Tenant Config ====================

/**
 * Per-tenant Layer 2 (Anomaly Detection) configuration
 */
struct tenant_l2_config {
    tenant_id_t tenant_id;
    uint64_t    version;

    // Anomaly thresholds
    struct {
        double      z_score_threshold;            // Default: 3.0
        double      jsd_threshold;                // Protocol distribution deviation
        double      flow_concentration_threshold; // Per-source flow concentration
        double      sensitivity_multiplier;       // <1.0 = less sensitive, >1.0 = more
        double      entropy_deviation_threshold;  // Payload entropy anomaly
    } thresholds;

    // Baseline settings
    struct {
        double      alpha_immediate;         // EWMA factor for immediate baseline (0.1-0.5)
        double      alpha_hourly;            // EWMA factor for hourly baseline
        double      alpha_weekly;            // EWMA factor for weekly baseline
        uint32_t    min_samples_immediate;   // Min samples before immediate baseline valid
        uint32_t    min_samples_hourly;      // Min samples for hourly baseline
        uint32_t    min_samples_weekly;      // Min samples for weekly baseline
        bool        auto_freeze_on_attack;   // Freeze baselines during attack
        bool        use_adaptive_threshold;  // Dynamically adjust thresholds
        uint16_t    _pad;
    } baseline;

    // Response settings
    struct {
        uint32_t    escalation_delay_sec;    // Time before escalating severity
        uint32_t    deescalation_delay_sec;  // Time before deescalating
        bool        auto_mitigation;         // Auto-apply L1 mitigations
        bool        notify_layer3;           // Notify L3 for ML analysis
        bool        notify_layer4;           // Notify L4 for reputation update
        uint8_t     min_severity_for_action; // Min severity to take action (0-5)
    } response;

    // Per-protected-IP baseline override
    struct {
        bool        inherit_tenant_settings; // Use tenant settings vs per-IP
        double      sensitivity_multiplier;  // Per-IP sensitivity override
    } per_ip;

    // Carpet bomb attack detection settings
    struct {
        bool        enabled;                 // Enable /24 subnet aggregation for carpet-bomb detection
        uint8_t     prefix_len;              // Prefix length (default 24)
        uint16_t    _pad;
    } carpet_bomb;

    // Padding
    uint8_t     _pad[4];
};

// ==================== Layer 3 Tenant Config ====================

/**
 * Per-tenant Layer 3 (ML Attribution) configuration
 */
struct tenant_l3_config {
    tenant_id_t tenant_id;
    uint64_t    version;

    // ML model settings
    struct {
        char        model_path[MAX_MODEL_PATH_LEN]; // Custom model (empty = default)
        double      confidence_threshold;    // Min confidence for action (0.0-1.0)
        uint32_t    inference_interval_ms;   // How often to run inference
        bool        enable_online_learning;  // Update model with tenant data
        bool        use_ensemble;            // Use ensemble of models
        bool        enable_autoencoder;      // Use autoencoder for anomaly
        bool        enable_isolation_forest; // Use isolation forest
    } model;

    // Attribution settings
    struct {
        uint32_t    min_packets_for_attribution; // Min packets before attribution
        double      attribution_confidence;      // Min confidence for attribution
        bool        enable_clustering;           // Cluster similar attacks
        bool        enable_fingerprinting;       // TCP/HTTP fingerprinting
        uint16_t    _pad;
    } attribution;

    // Policy generation
    struct {
        uint32_t    max_policies;            // Max auto-generated policies
        uint32_t    policy_ttl_sec;          // Auto-expire policies
        bool        require_confirmation;    // Human approval needed
        bool        auto_propagate_to_l1;    // Auto-push to Layer 1
        bool        learn_from_feedback;     // Learn from policy effectiveness
        uint8_t     _pad;
    } policy;

    // Feature extraction
    struct {
        bool        extract_payload_features; // Analyze packet payloads
        bool        extract_timing_features;  // Inter-arrival analysis
        bool        extract_flow_features;    // Flow-level features
        uint8_t     payload_sample_bytes;     // Bytes to sample from payload
    } features;

    // Padding
    uint8_t     _pad[4];
};

// ==================== Layer 4 Tenant Config ====================

/**
 * Per-tenant Layer 4 (Reputation Engine) configuration
 */
struct tenant_l4_config {
    tenant_id_t tenant_id;
    uint64_t    version;

    // Reputation settings
    struct {
        double      initial_score;           // New IP score (0.0-1.0, default 0.5)
        double      decay_rate_per_hour;     // Score decay toward neutral
        double      block_threshold;         // Block if score below this
        double      challenge_threshold;     // Challenge if below this
        double      trust_threshold;         // Trust (bypass checks) if above this
        uint32_t    history_window_hours;    // How long to remember IPs
        bool        share_with_global;       // Contribute to global reputation
        bool        use_global_reputation;   // Use global reputation data
        uint16_t    _pad;
    } reputation;

    // Challenge settings
    struct {
        bool        js_challenge_enabled;    // JavaScript challenge
        bool        captcha_enabled;         // CAPTCHA challenge
        bool        proof_of_work_enabled;   // Proof-of-work challenge
        uint8_t     challenge_difficulty;    // 1-10 scale
        uint32_t    challenge_validity_sec;  // How long challenge solution valid
        uint32_t    max_challenge_attempts;  // Max attempts before block
        uint32_t    challenge_cooldown_sec;  // Time between challenges
    } challenge;

    // Bot management
    struct {
        bool        enabled;                 // Bot management enabled
        bool        block_known_bots;        // Block known bad bots
        bool        block_headless_browsers; // Block headless browsers
        bool        block_automation_tools;  // Block automation (Selenium, etc.)
        bool        allow_good_bots;         // Allow search engines, etc.
        uint8_t     _pad[3];
        char        good_bot_list[MAX_GOOD_BOT_LIST_LEN]; // Comma-separated bot names
    } bot_management;

    // Application-layer rate limiting
    struct {
        uint32_t    http_req_per_sec;        // HTTP requests/sec
        uint32_t    http_req_per_min;        // HTTP requests/min
        uint32_t    api_req_per_sec;         // API requests/sec
        uint32_t    login_attempts_per_min;  // Login attempts/min
        uint32_t    form_submits_per_min;    // Form submissions/min
    } app_rate_limits;

    // Behavioral analysis
    struct {
        bool        track_session_behavior;  // Track user session patterns
        bool        detect_credential_stuffing; // Detect login attacks
        bool        detect_scraping;         // Detect content scraping
        bool        detect_api_abuse;        // Detect API abuse patterns
        uint32_t    session_timeout_sec;     // Session tracking timeout
    } behavior;

    // Padding
    uint8_t     _pad[4];
};

// ==================== Layer 5 Tenant Config ====================

/**
 * Per-tenant Layer 5 (Strategic Intelligence) configuration
 */
struct tenant_l5_config {
    tenant_id_t tenant_id;
    uint64_t    version;

    // Threat intelligence
    struct {
        bool        enable_global_intel;     // Use global threat feeds
        bool        enable_custom_feeds;     // Tenant-specific feeds
        bool        enable_real_time_intel;  // Real-time threat updates
        uint8_t     _pad;
        char        custom_feed_urls[MAX_CUSTOM_FEED_URLS][MAX_CUSTOM_FEED_URL_LEN];
        uint32_t    feed_update_interval_min; // Feed refresh interval
        uint32_t    intel_ttl_hours;         // How long intel is valid
    } intel;

    // Cross-tenant learning settings
    struct {
        bool        contribute_to_global;    // Share anonymized data
        bool        receive_global_updates;  // Receive global learnings
        bool        enable_peer_learning;    // Learn from similar tenants
        uint8_t     privacy_level;           // 0=full sharing, 3=minimal
        double      learning_rate;           // How fast to adapt (0.0-1.0)
        uint32_t    min_confidence_to_share; // Min confidence to share intel
    } learning;

    // Baseline optimization
    struct {
        bool        auto_tune_baselines;     // Auto-optimize L2 baselines
        bool        seasonal_adjustment;     // Adjust for time patterns
        bool        event_calendar;          // Adjust for known events
        uint8_t     _pad;
        uint32_t    optimization_interval_hours; // How often to optimize
    } baseline_optimization;

    // Reporting
    struct {
        bool        weekly_report_enabled;   // Weekly summary report
        bool        attack_report_enabled;   // Per-attack reports
        bool        real_time_alerts;        // Real-time attack alerts
        uint8_t     _pad;
        char        report_recipients[MAX_REPORT_RECIPIENTS_LEN];
        uint32_t    report_retention_days;   // How long to keep reports
    } reporting;

    // Padding
    uint8_t     _pad[4];
};

// ==================== Unified Tenant Config ====================

/**
 * Complete tenant configuration across all layers
 */
struct tenant_full_config {
    tenant_id_t             tenant_id;
    uint64_t                version;
    struct tenant_l1_config l1;
    struct tenant_l2_config l2;
    struct tenant_l3_config l3;
    struct tenant_l4_config l4;
    struct tenant_l5_config l5;
};

// ==================== Per-Lcore Config Cache ====================

/**
 * Per-lcore cached configuration for lock-free fast path
 * Updated periodically (every ~100ms) from main config
 *
 * Added per-tenant generation counters to detect stale pointers.
 * When a tenant config is deleted/modified, its generation increments.
 * Before using cached pointer, compare cached vs current generation.
 */
struct lcore_tenant_config_cache {
    uint64_t                            version;
    const struct tenant_l1_config      *l1_configs[MAX_TENANTS];
    uint64_t                            l1_generations[MAX_TENANTS];  // Per-tenant generation
    uint64_t                            last_update_tsc;
    uint32_t                            update_interval_cycles;
};

// Thread-local cache declaration (defined in tenant_config.c)
extern __thread struct lcore_tenant_config_cache g_lcore_config_cache;

// ==================== Configuration API ====================

/**
 * Initialize tenant configuration system
 *
 * @return 0 on success, negative error code on failure
 */
int tenant_config_init(void);

/**
 * Cleanup tenant configuration system
 */
void tenant_config_cleanup(void);

/**
 * Load all tenant configurations from directory
 *
 * @param config_dir  Path to configuration directory
 * @return 0 on success, negative error code on failure
 */
int tenant_config_load_all(const char *config_dir);

/**
 * Reload configuration for a single tenant (hot reload)
 *
 * @param id  Tenant ID
 * @return 0 on success, negative error code on failure
 */
int tenant_config_reload(tenant_id_t id);

/**
 * Reload all tenant configurations (hot reload)
 *
 * @return 0 on success, negative error code on failure
 */
int tenant_config_reload_all(void);

// ==================== Config Getter API (with inheritance) ====================

/**
 * Get effective Layer 1 config (with inheritance resolution)
 * Returns tier default if no tenant-specific config
 *
 * @param id  Tenant ID (TENANT_ID_GLOBAL for global defaults)
 * @return Pointer to config (READ-ONLY), never NULL
 */
const struct tenant_l1_config* tenant_get_l1_config(tenant_id_t id);

/**
 * Get effective Layer 2 config
 */
const struct tenant_l2_config* tenant_get_l2_config(tenant_id_t id);

/**
 * Get effective Layer 3 config
 */
const struct tenant_l3_config* tenant_get_l3_config(tenant_id_t id);

/**
 * Get effective Layer 4 config
 */
const struct tenant_l4_config* tenant_get_l4_config(tenant_id_t id);

/**
 * Get effective Layer 5 config
 */
const struct tenant_l5_config* tenant_get_l5_config(tenant_id_t id);

/**
 * Get complete tenant config (all layers)
 */
const struct tenant_full_config* tenant_get_full_config(tenant_id_t id);

// ==================== Config Setter API ====================

/**
 * Set tenant-specific Layer 1 config override
 *
 * @param id   Tenant ID
 * @param cfg  Configuration to set
 * @return 0 on success, negative error code on failure
 */
int tenant_set_l1_config(tenant_id_t id, const struct tenant_l1_config *cfg);

/**
 * Set tenant-specific Layer 2 config override
 */
int tenant_set_l2_config(tenant_id_t id, const struct tenant_l2_config *cfg);

/**
 * Set tenant-specific Layer 3 config override
 */
int tenant_set_l3_config(tenant_id_t id, const struct tenant_l3_config *cfg);

/**
 * Set tenant-specific Layer 4 config override
 */
int tenant_set_l4_config(tenant_id_t id, const struct tenant_l4_config *cfg);

/**
 * Set tenant-specific Layer 5 config override
 */
int tenant_set_l5_config(tenant_id_t id, const struct tenant_l5_config *cfg);

// ==================== Tier Presets API ====================

/**
 * Apply tier preset to a tenant
 * Resets all config to tier defaults
 *
 * @param id    Tenant ID
 * @param tier  Tier to apply
 * @return 0 on success, negative error code on failure
 */
int tenant_config_apply_tier_preset(tenant_id_t id, tenant_tier_t tier);

/**
 * Get tier preset configuration (read-only)
 *
 * @param tier  Tier level
 * @return Pointer to preset config, never NULL
 */
const struct tenant_full_config* tenant_config_get_tier_preset(tenant_tier_t tier);

// ==================== Validation API ====================

/**
 * Validate tenant configuration
 *
 * @param cfg         Configuration to validate
 * @param errors      Output buffer for error messages
 * @param errors_size Buffer size
 * @return 0 if valid, negative error code if invalid
 */
int tenant_config_validate(const struct tenant_full_config *cfg,
                           char *errors, size_t errors_size);

/**
 * Validate Layer 1 configuration only
 */
int tenant_config_validate_l1(const struct tenant_l1_config *cfg,
                              char *errors, size_t errors_size);

// ==================== Cache Management ====================

/**
 * Update per-lcore config cache
 * Called periodically by each lcore worker
 *
 * @return true if cache was updated
 */
bool tenant_config_cache_update(void);

/**
 * Force cache invalidation
 * Called after config changes
 */
void tenant_config_cache_invalidate(void);

/**
 * Get cached L1 config for tenant (fast path)
 * Must call tenant_config_cache_update() periodically
 *
 * This returns the cached pointer directly. For safety,
 * use tenant_get_l1_config_cached_safe() which validates generation.
 *
 * @param id  Tenant ID
 * @return Cached config pointer or NULL
 */
static inline const struct tenant_l1_config* tenant_get_l1_config_cached(tenant_id_t id) {
    if (id >= MAX_TENANTS) return NULL;
    return g_lcore_config_cache.l1_configs[id];
}

/**
 * Get current generation for a tenant
 * Used to validate cached pointers are still valid
 */
uint64_t tenant_get_generation(tenant_id_t id);

/**
 * Get cached L1 config with generation validation (safe fast path)
 *
 * Returns the cached config only if its generation matches the current
 * global generation, otherwise returns NULL (caller should refresh cache).
 *
 * @param id          Tenant ID
 * @param out_gen     Output: cached generation (for later comparison)
 * @return Cached config pointer or NULL if stale/invalid
 */
const struct tenant_l1_config* tenant_get_l1_config_cached_safe(tenant_id_t id,
                                                                  uint64_t *out_gen);

// ==================== Geo-blocking Helpers ====================

/**
 * Set country in blocked countries bitmap
 *
 * @param cfg          L1 config to modify
 * @param country_code Country code (0-255)
 * @param blocked      true to block, false to allow
 */
static inline void tenant_config_set_country_blocked(
    struct tenant_l1_config *cfg,
    uint8_t country_code,
    bool blocked)
{
    uint8_t idx = country_code / 64;
    uint8_t bit = country_code % 64;

    if (blocked) {
        cfg->blocked_countries[idx] |= (1ULL << bit);
    } else {
        cfg->blocked_countries[idx] &= ~(1ULL << bit);
    }
}

/**
 * Check if country is blocked
 *
 * @param cfg          L1 config to check
 * @param country_code Country code (0-255)
 * @return true if country is blocked
 */
static inline bool tenant_config_is_country_blocked(
    const struct tenant_l1_config *cfg,
    uint8_t country_code)
{
    uint8_t idx = country_code / 64;
    uint8_t bit = country_code % 64;

    if (cfg->geo_whitelist_mode) {
        // Whitelist mode: blocked if NOT in allowed list
        return !(cfg->allowed_countries[idx] & (1ULL << bit));
    } else {
        // Blacklist mode: blocked if in blocked list
        return (cfg->blocked_countries[idx] & (1ULL << bit)) != 0;
    }
}

// ==================== Serialization ====================

/**
 * Serialize full config to JSON
 *
 * @param cfg       Config to serialize
 * @param buf       Output buffer
 * @param buf_size  Buffer size
 * @return Number of bytes written, or negative error code
 */
int tenant_config_to_json(const struct tenant_full_config *cfg,
                          char *buf, size_t buf_size);

/**
 * Deserialize config from JSON
 *
 * @param json  JSON string
 * @param cfg   Output config structure
 * @return 0 on success, negative error code on failure
 */
int tenant_config_from_json(const char *json, struct tenant_full_config *cfg);

// ==================== Hot Reload Support ====================

/**
 * Callback for config change notification
 */
typedef void (*tenant_config_change_callback_t)(tenant_id_t tenant_id,
                                                 uint8_t layer_mask,
                                                 void *ctx);

/**
 * Register config change callback
 *
 * @param cb   Callback function
 * @param ctx  User context
 */
void tenant_config_set_change_callback(tenant_config_change_callback_t cb, void *ctx);

/**
 * Signal config change (triggers callbacks)
 *
 * @param tenant_id  Tenant ID (TENANT_ID_GLOBAL for all)
 * @param layer_mask Bitmask of changed layers (1<<0=L1, 1<<1=L2, etc.)
 */
void tenant_config_notify_change(tenant_id_t tenant_id, uint8_t layer_mask);

/**
 * Get config version for change detection
 */
uint64_t tenant_config_get_global_version(void);

// Layer mask bits
#define TENANT_CONFIG_L1_CHANGED   (1 << 0)
#define TENANT_CONFIG_L2_CHANGED   (1 << 1)
#define TENANT_CONFIG_L3_CHANGED   (1 << 2)
#define TENANT_CONFIG_L4_CHANGED   (1 << 3)
#define TENANT_CONFIG_L5_CHANGED   (1 << 4)
#define TENANT_CONFIG_ALL_CHANGED  (0x1F)

// ==================== Debugging ====================

/**
 * Print L1 config summary
 */
void tenant_config_print_l1(const struct tenant_l1_config *cfg);

/**
 * Print full config summary
 */
void tenant_config_print_full(const struct tenant_full_config *cfg);

/**
 * Dump all active tenant configs to stdout
 */
void tenant_config_dump_all(void);

/**
 * Compare two configs and return bitmask of differences
 *
 * @param a First config
 * @param b Second config
 * @return Bitmask of differing layers
 */
uint8_t tenant_config_diff(const struct tenant_full_config *a,
                           const struct tenant_full_config *b);

#ifdef __cplusplus
}
#endif

#endif // TENANT_CONFIG_H
