#ifndef LAYER1_CONFIG_H
#define LAYER1_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @file layer1_config.h
 * @brief Centralized configuration for Layer 1 DDoS Protection
 *
 * All hardcoded values are now configurable via JSON config file.
 * This allows runtime customization based on network capability/structure.
 */

// ==================== Default Config Paths ====================

// Use relative paths from project root (configurable at runtime)
#define L1_DEFAULT_CONFIG_FILE  "layer1/config/layer1_config.json"

// ==================== IP Lists Configuration ====================

struct ip_lists_cfg {
    uint32_t max_whitelist_entries;    // Maximum exact IP whitelist entries (default: 10000)
    uint32_t max_blacklist_entries;    // Maximum blacklist entries (default: 100000)
    uint32_t max_protected_entries;    // Maximum protected server entries (default: 1000)
    uint32_t max_whitelist_cidrs;      // Maximum CIDR whitelist entries (default: 1000)
    bool     enforce_protected_ips;    // Only allow traffic to protected IPs (default: false)
};

// ==================== Flow Table Configuration ====================

struct flow_table_cfg {
    uint32_t max_flows;                // Maximum concurrent flows (default: 1000000)
    uint32_t idle_timeout_sec;         // Timeout for established flows (default: 60)
    uint32_t syn_timeout_sec;          // Timeout for half-open connections (default: 5)
    uint32_t default_pps_limit;        // Default packets/sec per flow (0=unlimited)
    uint32_t default_bps_limit;        // Default bytes/sec per flow (0=unlimited)
    bool     enable_syn_protection;    // Enable aggressive SYN timeout (default: true)
    uint32_t aging_scan_limit;         // Max entries to scan per aging cycle (default: 4096)
    uint32_t aging_scan_limit_pressure; // Scan limit when under pressure (default: 8192)

    // Emergency rate limiting when flow table is full
    // Instead of random 75% drop, use reputation-aware probabilistic drop
    uint8_t  emergency_drop_unknown_pct;   // Drop % for unknown IPs when full (default: 90)
    uint8_t  emergency_drop_good_pct;      // Drop % for good reputation IPs (default: 25)
    uint8_t  emergency_drop_neutral_pct;   // Drop % for neutral IPs (default: 75)
    uint8_t  emergency_drop_suspicious_pct; // Drop % for suspicious IPs (default: 95)
};

// ==================== SYN Proxy Configuration ====================

struct syn_proxy_cfg {
    bool     enabled;                  // Enable SYN proxy (default: true)
    uint32_t max_connections;          // Maximum tracked connections (default: 1000000)
    uint32_t connect_timeout_ms;       // Timeout waiting for server (default: 5000)
    uint32_t idle_timeout_sec;         // Connection idle timeout (default: 300)
    uint32_t secret_rotation_sec;      // Secret rotation interval (default: 60)

    // Adaptive mode thresholds
    uint32_t stateless_threshold_pps;  // Switch to stateless above this SYN rate (default: 10000)
    uint32_t stateful_threshold_pps;   // Switch back to stateful below this rate (default: 5000)
    uint32_t mode_switch_delay_ms;     // Hysteresis delay before switching modes (default: 5000)
};

// ==================== SYN Cookie Configuration ====================

struct syn_cookie_cfg {
    bool     enabled;                  // Enable SYN cookies (default: true)
    uint32_t challenge_threshold;      // PPS threshold to start challenging (default: 1000)
};

// ==================== Connection Limits Configuration ====================

struct connection_limits_cfg {
    uint32_t max_ips;                  // Maximum IPs to track (default: 100000)
    uint32_t max_connections_per_ip;   // Max connections per IP (default: 1000)
    uint32_t time_window_sec;          // Time window for limits (default: 60)
    uint32_t cleanup_interval_sec;     // Cleanup interval (default: 30)
};

// ==================== Telemetry Configuration ====================

struct telemetry_cfg {
    char     db_path[256];             // SQLite database path (default: /tmp/layer1_telemetry.db)
    uint32_t export_interval_sec;      // Export interval (default: 5)
    uint32_t max_flow_records;         // Ring buffer size (default: 4096)
    uint32_t flow_sample_rate;         // 1:N sampling (default: 100)
    bool     export_packet_samples;    // Export individual samples (default: false)
    bool     events_enabled;           // Record attack events (default: true)
    bool     concentration_export_enabled; // section 4.8 CMS concentration export: max_flow_fraction,
                                       // topk_flow_share, heavy_hitter_count (default: false --
                                       // opt-in; validate elephant-flow FPR before enabling)
};

// ==================== Validation Configuration ====================

struct validation_cfg {
    bool     validate_ip_checksum;     // Validate IP header checksum (default: true)
    bool     validate_udp_checksum;    // Validate UDP checksum (default: true)
    bool     validate_tcp_checksum;    // Validate TCP checksum (default: false - NIC offload)
    bool     validate_icmp_checksum;   // Validate ICMP checksum (default: false)
    bool     drop_invalid_src_ip;      // Drop packets from invalid source IPs (default: true)
    bool     drop_land_attack;         // Drop LAND attack packets (default: true)
    bool     drop_tcp_null;            // Drop TCP NULL flag packets (default: true)
    bool     drop_tcp_xmas;            // Drop XMAS tree packets (default: true)
    bool     drop_zero_ttl;            // Drop zero TTL packets (default: true)
    bool     drop_fragments;           // Drop fragmented packets (default: false)
    bool     decrement_ttl;            // Decrement TTL on forwarding (default: false for L2 bridge mode)

    // IPv6 handling policy (IPv6 flow tracking is not yet implemented)
    // 0 = drop (safe default - IPv6 attacks bypass protection)
    // 1 = accept (passthrough without protection)
    // 2 = log and drop (drop with logging for visibility)
    uint8_t  ipv6_policy;              // IPv6 traffic policy (default: 0 = drop)
};

// ==================== UDP Gatekeeper Configuration ====================

struct udp_gatekeeper_cfg {
    uint32_t pps_threshold;            // UDP packets/sec per IP (default: 10000)
    uint32_t bps_threshold;            // UDP bytes/sec per IP (default: 10485760 = 10MB/s)
    uint32_t cms_width;                // Count-Min Sketch width (default: 65536)
    uint32_t cms_depth;                // Count-Min Sketch depth (default: 4)
    uint32_t window_sec;               // Time window in seconds (default: 1)
    bool     check_reputation;         // Check reputation before rate check (default: true)
    uint16_t reputation_threshold;     // Block if reputation below this (default: 200)
    bool     check_blacklist;          // Check blacklist (default: true)
    uint32_t attack_pps_divisor;       // Threshold divisor during attack (default: 4)
    uint32_t attack_bps_divisor;       // Threshold divisor during attack (default: 4)
};

// ==================== Rate Limiting Configuration ====================

struct rate_limit_cfg {
    // Global rate limits
    uint64_t global_pps_limit;         // Global packets/sec limit (0=unlimited)
    uint64_t global_bps_limit;         // Global bytes/sec limit (0=unlimited)

    // Per-IP rate limits (during normal operation)
    uint32_t normal_pps_per_ip;        // Normal PPS per IP (default: 10000)
    uint32_t normal_bps_per_ip;        // Normal BPS per IP (default: 100000000 = 100Mbps)

    // Per-IP rate limits (during attack/anomaly)
    uint32_t attack_pps_per_ip;        // Attack mode PPS per IP (default: 1000)
    uint32_t attack_bps_per_ip;        // Attack mode BPS per IP (default: 10000000 = 10Mbps)

    // Dynamic rate limiting
    bool     dynamic_enabled;          // Enable dynamic rate adjustment (default: true)
    uint32_t anomaly_detection_window; // Window for anomaly detection in seconds (default: 10)

    // Spoofed mode: legitimate IP table size
    uint32_t legitimate_table_size;    // Max IPs in legitimate-source table (default: 100000)

    // Progressive rate limiting based on anomaly level
    // Limits are interpolated between normal and attack based on severity
    bool     progressive_enabled;      // Enable progressive rate limiting (default: true)
    uint8_t  level_low_percent;        // % of normal limit at LOW anomaly (default: 80)
    uint8_t  level_medium_percent;     // % of normal limit at MEDIUM anomaly (default: 50)
    uint8_t  level_high_percent;       // % of normal limit at HIGH anomaly (default: 25)
    uint8_t  level_critical_percent;   // % of normal limit at CRITICAL anomaly (default: 10)
};

// ==================== Network Ports Configuration ====================

struct port_cfg {
    uint16_t client_facing_port;       // Port facing clients (default: 0)
    uint16_t server_facing_port;       // Port facing servers (default: 1)
};

// ==================== Maintenance Configuration ====================

struct maintenance_cfg {
    uint32_t flow_age_interval_sec;    // How often to age flows (default: 1)
    uint32_t secret_rotation_sec;      // Secret rotation interval (default: 60)
    uint32_t stats_print_interval_sec; // Stats print interval, 0=disabled (default: 0)
};

// ==================== Geo-Blocking Configuration ====================

struct geo_blocking_cfg {
    bool     enabled;                  // Enable geo-blocking (default: false)
    uint8_t  mode;                     // 1=blacklist, 2=whitelist (default: 1)
    char     database_path[256];       // Path to GeoIP database
    bool     log_blocked;              // Log blocked packets (default: true)
    bool     block_unknown;            // Block IPs with unknown country (default: false)
    // Countries configured statically (complement to dynamic API management)
    uint32_t country_count;            // Number of countries in static list
    char     countries[256][3];        // Array of 2-letter country codes (null-terminated)
};

// ==================== Other Protocols Configuration ====================

struct other_protocols_cfg {
    bool     enabled;                  // Enable other protocols filter (default: true)
    uint8_t  default_action;           // 0=drop, 1=accept, 2=rate_limit (default: 0)
    uint8_t  allowed_protocols[32];    // List of allowed protocol numbers
    uint32_t allowed_count;            // Number of allowed protocols
    uint32_t rate_limit_pps;           // Rate limit for other protocols (default: 1000)
    bool     log_unknown;              // Log unknown protocols (default: true)
};

// ==================== TCP Abuse Detection Configuration ====================

struct tcp_abuse_cfg {
    bool     enabled;                  // Enable TCP abuse detection (default: false)
    bool     report_to_layer4;         // Report detected abuse to Layer 4 (default: true)

    // Detection thresholds
    uint32_t dup_seq_threshold;        // Duplicate SEQ count threshold (default: 150)
    uint32_t random_seq_threshold;     // Random SEQ jump threshold in 10s (default: 45)
    uint32_t random_ack_threshold;     // Random ACK jump threshold in 10s (default: 45)
    uint32_t zero_window_threshold;    // Zero window count threshold in 10s (default: 5)
    uint16_t tiny_window_bytes;        // Tiny window threshold bytes (default: 100)
    uint16_t small_window_bytes;       // Small window threshold bytes (default: 2000)
    uint32_t same_window_threshold;    // Same window count threshold (default: 150)
    uint32_t same_ack_threshold;       // Same ACK count threshold (default: 150)

    // Actions per abuse type (0=log, 1=drop, 2=rate_limit)
    uint8_t  action_dup_seq;
    uint8_t  action_random_seq;
    uint8_t  action_random_ack;
    uint8_t  action_zero_window;
    uint8_t  action_tiny_window;
    uint8_t  action_small_window;
    uint8_t  action_same_window;
    uint8_t  action_same_ack;
};

// ==================== TCP Flag Rate Limiting Configuration ====================

struct tcp_flag_rate_cfg {
    bool     enabled;                  // Enable per-flag rate limiting (default: false)
    uint32_t max_entries;              // Maximum IPs to track (default: 40000)
    uint32_t cleanup_interval_sec;     // Cleanup interval (default: 60)
    bool     report_violations;        // Report violations to Layer 4 (default: true)

    // Per-flag-class PPS limits (0 = use default)
    uint32_t syn_pps;                  // SYN rate limit (default: 100)
    uint32_t syn_ack_pps;              // SYN-ACK rate limit (default: 1000)
    uint32_t ack_pps;                  // ACK rate limit (default: 50000)
    uint32_t rst_pps;                  // RST rate limit (default: 500)
    uint32_t fin_pps;                  // FIN rate limit (default: 500)
    uint32_t psh_pps;                  // PSH rate limit (default: 10000)
    uint32_t urg_pps;                  // URG rate limit (default: 100)
    uint32_t other_pps;                // Other flags rate limit (default: 5000)
};

// ==================== L7 Validation Configuration ====================

struct l7_validation_cfg {
    // Per-protocol enable flags
    bool     dns_enabled;              // Enable DNS validation (default: false)
    bool     ntp_enabled;              // Enable NTP validation (default: false)
    bool     http_enabled;             // Enable HTTP validation (default: false)
    bool     icmp_enabled;             // Enable ICMP filtering (default: false)

    // DNS checks
    bool     dns_drop_both_port53;     // Drop if both src and dst port are 53
    bool     dns_drop_too_short;       // Drop if payload < 12 bytes
    bool     dns_drop_invalid_opcode;  // Drop if opcode > 5
    bool     dns_drop_qr_mismatch;     // Drop if QR bit direction mismatch
    bool     dns_drop_qdcount_invalid; // Drop if standard query QDCOUNT != 1
    bool     dns_drop_pointer_loop;    // Drop if compression pointer loop
    bool     dns_drop_label_too_long;  // Drop if label > 63 bytes
    bool     dns_drop_name_too_long;   // Drop if name > 255 bytes
    bool     dns_drop_zone_transfer;   // Drop DNS AXFR over UDP
    uint16_t dns_max_udp_size;         // Max DNS UDP message size (0=no limit)

    // NTP checks
    bool     ntp_drop_too_short;       // Drop if too short
    bool     ntp_drop_invalid_version; // Drop if version 0 or > 4
    bool     ntp_drop_monlist;         // Drop mode 7 (monlist amplification)
    bool     ntp_drop_control;         // Drop mode 6 (control)
    bool     ntp_drop_invalid_stratum; // Drop if stratum > 15
    bool     ntp_drop_size_mismatch;   // Drop if size doesn't match mode

    // HTTP checks
    bool     http_drop_invalid_method; // Drop if unknown HTTP method
    bool     http_drop_invalid_version; // Drop if invalid HTTP version
    bool     http_drop_line_too_long;  // Drop if request line too long
    bool     http_drop_non_ascii;      // Drop if non-ASCII characters
    uint16_t http_max_request_line;    // Max request line length (0=no limit)

    // ICMP filtering
    bool     icmp_drop_source_quench;  // Drop source quench (type 4)
    bool     icmp_drop_redirect;       // Drop redirect (type 5)
    bool     icmp_drop_router_advert;  // Drop router advertisement (type 9)
    bool     icmp_drop_router_solicit; // Drop router solicitation (type 10)
    bool     icmp_drop_timestamp;      // Drop timestamp (type 13)
    bool     icmp_drop_info;           // Drop info request/reply (type 15/16)
    bool     icmp_drop_address_mask;   // Drop address mask (type 17/18)
    uint32_t icmp_rate_limit_pps;      // ICMP echo rate limit PPS (0=no limit)
};

// ==================== Attack Signatures Configuration ====================

struct signatures_cfg {
    bool     enabled;                  // Enable signature detection (default: true)
    bool     log_matches;              // Log signature matches (default: true)
    bool     block_amplification;      // Block amplification attacks (default: true)
    bool     block_scans;              // Block scan patterns (default: true)
    bool     block_anomalies;          // Block protocol anomalies (default: false - handled by validation)
    bool     block_attack_tools;       // Block attack tool signatures (default: true)
};

// ==================== Master Configuration ====================

struct layer1_config {
    // Module configurations
    struct ip_lists_cfg         ip_lists;
    struct flow_table_cfg       flow_table;
    struct syn_proxy_cfg        syn_proxy;
    struct syn_cookie_cfg       syn_cookie;
    struct connection_limits_cfg connection_limits;
    struct udp_gatekeeper_cfg   udp_gatekeeper;
    struct telemetry_cfg        telemetry;
    struct validation_cfg       validation;
    struct rate_limit_cfg       rate_limits;
    struct port_cfg             ports;
    struct maintenance_cfg      maintenance;
    struct geo_blocking_cfg     geo_blocking;
    struct other_protocols_cfg  other_protocols;
    struct signatures_cfg       signatures;
    struct tcp_abuse_cfg        tcp_abuse;
    struct tcp_flag_rate_cfg    tcp_flag_rate;
    struct l7_validation_cfg    l7_validation;

    // Global settings
    uint32_t log_level;                // DPDK log level (default: RTE_LOG_INFO = 7)
    bool     stats_enabled;            // Enable statistics collection (default: true)
    bool     monitor_only;             // Monitor-only mode: accept all packets, no protection (default: false)
    bool     tap_mode;                  // Mirror mode: receive traffic copy, no forwarding
    bool     per_ip_mitigation_enabled; // Enable per-IP mitigation decisions
    bool     global_circuit_breaker;    // Global circuit breaker for spoofed mode
};

// ==================== Public API ====================

/**
 * Load configuration from JSON file
 *
 * @param config_path  Path to JSON config file
 * @param config       Output configuration structure
 * @return 0 on success, -1 on error
 */
int layer1_config_load(const char *config_path, struct layer1_config *config);

/**
 * Save configuration to JSON file
 *
 * @param config_path  Path to JSON config file
 * @param config       Configuration to save
 * @return 0 on success, -1 on error
 */
int layer1_config_save(const char *config_path, const struct layer1_config *config);

/**
 * Initialize configuration with default values
 *
 * @param config  Configuration structure to initialize
 */
void layer1_config_defaults(struct layer1_config *config);

/**
 * Validate configuration values
 *
 * @param config  Configuration to validate
 * @return 0 if valid, -1 if invalid (with error logged)
 */
int layer1_config_validate(const struct layer1_config *config);

/**
 * Print configuration to stdout
 *
 * @param config  Configuration to print
 */
void layer1_config_print(const struct layer1_config *config);

/**
 * Get current active configuration
 *
 * @return Pointer to active config (read-only) or NULL if not initialized
 */
const struct layer1_config* layer1_config_get(void);

/**
 * Reload configuration from file (runtime hot-reload)
 * Only safe values are reloaded (not table sizes)
 *
 * @param config_path  Path to JSON config file
 * @return 0 on success, -1 on error
 */
int layer1_config_reload(const char *config_path);

/**
 * Set active configuration (internal use by layer1_init)
 *
 * @param config  Configuration to make active
 */
void layer1_config_set_active(const struct layer1_config *config);

// ==================== Progressive Rate Limiting API ====================

/**
 * Calculate progressive rate limit based on anomaly level
 *
 * Returns a rate limit that scales between normal and attack limits
 * based on the current anomaly severity level.
 *
 * @param cfg         Rate limit configuration
 * @param anomaly_level  Current anomaly level (0=none, 1=low, 2=medium, 3=high, 4=critical)
 * @return Effective PPS limit for the current anomaly level
 */
static inline uint32_t layer1_get_progressive_pps_limit(
    const struct rate_limit_cfg *cfg,
    int anomaly_level)
{
    if (!cfg || !cfg->progressive_enabled) {
        // Fall back to binary normal/attack mode
        return (anomaly_level > 0) ? cfg->attack_pps_per_ip : cfg->normal_pps_per_ip;
    }

    uint8_t percent;
    switch (anomaly_level) {
        case 0:  // NONE
            percent = 100;
            break;
        case 1:  // LOW
            percent = cfg->level_low_percent;
            break;
        case 2:  // MEDIUM
            percent = cfg->level_medium_percent;
            break;
        case 3:  // HIGH
            percent = cfg->level_high_percent;
            break;
        case 4:  // CRITICAL
        default:
            percent = cfg->level_critical_percent;
            break;
    }

    // Calculate limit as percentage of normal
    // Ensure we don't go below attack limit
    uint32_t progressive_limit = (cfg->normal_pps_per_ip * percent) / 100;
    if (progressive_limit < cfg->attack_pps_per_ip) {
        progressive_limit = cfg->attack_pps_per_ip;
    }

    return progressive_limit;
}

/**
 * Calculate progressive BPS limit based on anomaly level
 * Same logic as PPS but for bytes per second
 */
static inline uint32_t layer1_get_progressive_bps_limit(
    const struct rate_limit_cfg *cfg,
    int anomaly_level)
{
    if (!cfg || !cfg->progressive_enabled) {
        return (anomaly_level > 0) ? cfg->attack_bps_per_ip : cfg->normal_bps_per_ip;
    }

    uint8_t percent;
    switch (anomaly_level) {
        case 0:  percent = 100; break;
        case 1:  percent = cfg->level_low_percent; break;
        case 2:  percent = cfg->level_medium_percent; break;
        case 3:  percent = cfg->level_high_percent; break;
        case 4:
        default: percent = cfg->level_critical_percent; break;
    }

    uint32_t progressive_limit = (cfg->normal_bps_per_ip * percent) / 100;
    if (progressive_limit < cfg->attack_bps_per_ip) {
        progressive_limit = cfg->attack_bps_per_ip;
    }

    return progressive_limit;
}

#endif // LAYER1_CONFIG_H
