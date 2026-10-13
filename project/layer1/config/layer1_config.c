#include "layer1_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include <rte_log.h>

#define RTE_LOGTYPE_CFG RTE_LOGTYPE_USER3

// ==================== Global State ====================

static struct layer1_config active_config;
static bool config_initialized = false;

// ==================== Default Values ====================

void layer1_config_defaults(struct layer1_config *config) {
    if (!config) return;

    memset(config, 0, sizeof(*config));

    // IP Lists defaults
    config->ip_lists.max_whitelist_entries = 10000;
    config->ip_lists.max_blacklist_entries = 100000;
    config->ip_lists.max_protected_entries = 1000;
    config->ip_lists.max_whitelist_cidrs = 1000;
    config->ip_lists.enforce_protected_ips = false;

    // Flow Table defaults
    config->flow_table.max_flows = 1000000;
    config->flow_table.idle_timeout_sec = 60;
    config->flow_table.syn_timeout_sec = 5;
    config->flow_table.default_pps_limit = 0;
    config->flow_table.default_bps_limit = 0;
    config->flow_table.enable_syn_protection = true;
    config->flow_table.aging_scan_limit = 4096;         // P-001: Incremental aging
    config->flow_table.aging_scan_limit_pressure = 8192; // 2x when under pressure
    // Emergency rate limiting (reputation-aware instead of random 75% drop)
    config->flow_table.emergency_drop_unknown_pct = 90;     // Unknown IPs: 90% drop
    config->flow_table.emergency_drop_good_pct = 25;        // Good rep: only 25% drop
    config->flow_table.emergency_drop_neutral_pct = 75;     // Neutral: 75% drop
    config->flow_table.emergency_drop_suspicious_pct = 95;  // Suspicious: 95% drop

    // SYN Proxy defaults
    config->syn_proxy.enabled = true;
    config->syn_proxy.max_connections = 1000000;
    config->syn_proxy.connect_timeout_ms = 5000;
    config->syn_proxy.idle_timeout_sec = 300;
    config->syn_proxy.secret_rotation_sec = 60;

    // SYN Cookie defaults
    config->syn_cookie.enabled = true;
    config->syn_cookie.challenge_threshold = 1000;

    // Connection Limits defaults
    config->connection_limits.max_ips = 100000;
    config->connection_limits.max_connections_per_ip = 1000;
    config->connection_limits.time_window_sec = 60;
    config->connection_limits.cleanup_interval_sec = 30;

    // UDP Gatekeeper defaults
    config->udp_gatekeeper.pps_threshold = 10000;
    config->udp_gatekeeper.bps_threshold = 10485760;  // 10 MB/s
    config->udp_gatekeeper.cms_width = 65536;
    config->udp_gatekeeper.cms_depth = 4;
    config->udp_gatekeeper.window_sec = 1;
    config->udp_gatekeeper.check_reputation = true;
    config->udp_gatekeeper.reputation_threshold = 200;
    config->udp_gatekeeper.check_blacklist = true;
    config->udp_gatekeeper.attack_pps_divisor = 4;
    config->udp_gatekeeper.attack_bps_divisor = 4;

    // Telemetry defaults
    strncpy(config->telemetry.db_path, "/tmp/layer1_telemetry.db",
            sizeof(config->telemetry.db_path) - 1);
    config->telemetry.export_interval_sec = 5;
    config->telemetry.max_flow_records = 4096;
    config->telemetry.flow_sample_rate = 100;
    config->telemetry.export_packet_samples = false;
    config->telemetry.events_enabled = true;
    config->telemetry.concentration_export_enabled = false;  // opt-in (section 4.8); off preserves behaviour

    // Validation defaults
    config->validation.validate_ip_checksum = true;
    config->validation.validate_udp_checksum = true;
    config->validation.validate_tcp_checksum = false;
    config->validation.drop_invalid_src_ip = true;
    config->validation.drop_land_attack = true;
    config->validation.drop_tcp_null = true;
    config->validation.drop_tcp_xmas = true;
    config->validation.drop_zero_ttl = true;
    config->validation.drop_fragments = false;
    config->validation.decrement_ttl = false;  // Default: L2 bridge mode (no TTL decrement)
    // IPv6 policy: drop by default since IPv6 flow tracking is not implemented
    // This prevents IPv6 DDoS attacks from bypassing protection entirely
    config->validation.ipv6_policy = 0;  // 0=drop, 1=accept, 2=log_and_drop

    // Rate Limit defaults
    config->rate_limits.global_pps_limit = 0;
    config->rate_limits.global_bps_limit = 0;
    config->rate_limits.normal_pps_per_ip = 10000;
    config->rate_limits.normal_bps_per_ip = 100000000;  // 100 Mbps
    config->rate_limits.attack_pps_per_ip = 1000;
    config->rate_limits.attack_bps_per_ip = 10000000;   // 10 Mbps
    config->rate_limits.dynamic_enabled = true;
    config->rate_limits.anomaly_detection_window = 10;

    // Progressive rate limiting defaults
    config->rate_limits.progressive_enabled = true;
    config->rate_limits.level_low_percent = 80;         // 80% at LOW
    config->rate_limits.level_medium_percent = 50;      // 50% at MEDIUM
    config->rate_limits.level_high_percent = 25;        // 25% at HIGH
    config->rate_limits.level_critical_percent = 10;    // 10% at CRITICAL

    // Port defaults
    config->ports.client_facing_port = 0;
    config->ports.server_facing_port = 1;

    // Maintenance defaults
    config->maintenance.flow_age_interval_sec = 1;
    config->maintenance.secret_rotation_sec = 60;
    config->maintenance.stats_print_interval_sec = 0;

    // Geo-blocking defaults
    config->geo_blocking.enabled = false;
    config->geo_blocking.mode = 1;  // Blacklist mode
    strncpy(config->geo_blocking.database_path, "/var/lib/antiddos/geoip/GeoLite2-Country.mmdb",
            sizeof(config->geo_blocking.database_path) - 1);
    config->geo_blocking.log_blocked = true;

    // Other protocols defaults
    config->other_protocols.enabled = true;
    config->other_protocols.default_action = 0;  // Drop unknown protocols
    config->other_protocols.allowed_protocols[0] = 47;  // GRE
    config->other_protocols.allowed_protocols[1] = 50;  // ESP
    config->other_protocols.allowed_protocols[2] = 51;  // AH
    config->other_protocols.allowed_count = 3;
    config->other_protocols.rate_limit_pps = 1000;
    config->other_protocols.log_unknown = true;

    // Attack signatures defaults
    config->signatures.enabled = true;
    config->signatures.log_matches = true;
    config->signatures.block_amplification = true;
    config->signatures.block_scans = true;
    config->signatures.block_anomalies = false;  // Handled by validation stage
    config->signatures.block_attack_tools = true;

    // Global defaults
    config->log_level = 7;  // RTE_LOG_INFO
    config->stats_enabled = true;
    config->monitor_only = false;  // Protection enabled by default
}

// ==================== JSON Parsing Helpers ====================

static inline uint32_t json_get_uint32(const cJSON *obj, const char *name, uint32_t def) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, name);
    if (cJSON_IsNumber(item)) {
        return (uint32_t)item->valuedouble;
    }
    return def;
}

static inline uint64_t json_get_uint64(const cJSON *obj, const char *name, uint64_t def) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, name);
    if (cJSON_IsNumber(item)) {
        return (uint64_t)item->valuedouble;
    }
    return def;
}

static inline bool json_get_bool(const cJSON *obj, const char *name, bool def) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, name);
    if (cJSON_IsBool(item)) {
        return cJSON_IsTrue(item);
    }
    return def;
}

static inline void json_get_string(const cJSON *obj, const char *name,
                                   char *out, size_t out_size, const char *def) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, name);
    if (cJSON_IsString(item) && item->valuestring) {
        strncpy(out, item->valuestring, out_size - 1);
        out[out_size - 1] = '\0';
    } else if (def) {
        strncpy(out, def, out_size - 1);
        out[out_size - 1] = '\0';
    }
}

// ==================== Section Parsers ====================

static void parse_ip_lists(const cJSON *obj, struct ip_lists_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->max_whitelist_entries = json_get_uint32(obj, "max_whitelist_entries", cfg->max_whitelist_entries);
    cfg->max_blacklist_entries = json_get_uint32(obj, "max_blacklist_entries", cfg->max_blacklist_entries);
    cfg->max_protected_entries = json_get_uint32(obj, "max_protected_entries", cfg->max_protected_entries);
    cfg->max_whitelist_cidrs = json_get_uint32(obj, "max_whitelist_cidrs", cfg->max_whitelist_cidrs);
    cfg->enforce_protected_ips = json_get_bool(obj, "enforce_protected_ips", cfg->enforce_protected_ips);
}

static void parse_flow_table(const cJSON *obj, struct flow_table_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->max_flows = json_get_uint32(obj, "max_flows", cfg->max_flows);
    cfg->idle_timeout_sec = json_get_uint32(obj, "idle_timeout_sec", cfg->idle_timeout_sec);
    cfg->syn_timeout_sec = json_get_uint32(obj, "syn_timeout_sec", cfg->syn_timeout_sec);
    cfg->default_pps_limit = json_get_uint32(obj, "default_pps_limit", cfg->default_pps_limit);
    cfg->default_bps_limit = json_get_uint32(obj, "default_bps_limit", cfg->default_bps_limit);
    cfg->enable_syn_protection = json_get_bool(obj, "enable_syn_protection", cfg->enable_syn_protection);
    cfg->aging_scan_limit = json_get_uint32(obj, "aging_scan_limit", cfg->aging_scan_limit);
    cfg->aging_scan_limit_pressure = json_get_uint32(obj, "aging_scan_limit_pressure", cfg->aging_scan_limit_pressure);
    // Emergency rate limiting (reputation-aware)
    cfg->emergency_drop_unknown_pct = (uint8_t)json_get_uint32(obj, "emergency_drop_unknown_pct", cfg->emergency_drop_unknown_pct);
    cfg->emergency_drop_good_pct = (uint8_t)json_get_uint32(obj, "emergency_drop_good_pct", cfg->emergency_drop_good_pct);
    cfg->emergency_drop_neutral_pct = (uint8_t)json_get_uint32(obj, "emergency_drop_neutral_pct", cfg->emergency_drop_neutral_pct);
    cfg->emergency_drop_suspicious_pct = (uint8_t)json_get_uint32(obj, "emergency_drop_suspicious_pct", cfg->emergency_drop_suspicious_pct);
}

static void parse_syn_proxy(const cJSON *obj, struct syn_proxy_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->enabled = json_get_bool(obj, "enabled", cfg->enabled);
    cfg->max_connections = json_get_uint32(obj, "max_connections", cfg->max_connections);
    cfg->connect_timeout_ms = json_get_uint32(obj, "connect_timeout_ms", cfg->connect_timeout_ms);
    cfg->idle_timeout_sec = json_get_uint32(obj, "idle_timeout_sec", cfg->idle_timeout_sec);
    cfg->secret_rotation_sec = json_get_uint32(obj, "secret_rotation_sec", cfg->secret_rotation_sec);
}

static void parse_syn_cookie(const cJSON *obj, struct syn_cookie_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->enabled = json_get_bool(obj, "enabled", cfg->enabled);
    cfg->challenge_threshold = json_get_uint32(obj, "challenge_threshold", cfg->challenge_threshold);
}

static void parse_connection_limits(const cJSON *obj, struct connection_limits_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->max_ips = json_get_uint32(obj, "max_ips", cfg->max_ips);
    cfg->max_connections_per_ip = json_get_uint32(obj, "max_connections_per_ip", cfg->max_connections_per_ip);
    cfg->time_window_sec = json_get_uint32(obj, "time_window_sec", cfg->time_window_sec);
    cfg->cleanup_interval_sec = json_get_uint32(obj, "cleanup_interval_sec", cfg->cleanup_interval_sec);
}

static void parse_udp_gatekeeper(const cJSON *obj, struct udp_gatekeeper_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->pps_threshold = json_get_uint32(obj, "pps_threshold", cfg->pps_threshold);
    cfg->bps_threshold = json_get_uint32(obj, "bps_threshold", cfg->bps_threshold);
    cfg->cms_width = json_get_uint32(obj, "cms_width", cfg->cms_width);
    cfg->cms_depth = json_get_uint32(obj, "cms_depth", cfg->cms_depth);
    cfg->window_sec = json_get_uint32(obj, "window_sec", cfg->window_sec);
    cfg->check_reputation = json_get_bool(obj, "check_reputation", cfg->check_reputation);
    cfg->reputation_threshold = (uint16_t)json_get_uint32(obj, "reputation_threshold", cfg->reputation_threshold);
    cfg->check_blacklist = json_get_bool(obj, "check_blacklist", cfg->check_blacklist);
    cfg->attack_pps_divisor = json_get_uint32(obj, "attack_pps_divisor", cfg->attack_pps_divisor);
    cfg->attack_bps_divisor = json_get_uint32(obj, "attack_bps_divisor", cfg->attack_bps_divisor);
}

static void parse_telemetry(const cJSON *obj, struct telemetry_cfg *cfg) {
    if (!obj || !cfg) return;

    json_get_string(obj, "db_path", cfg->db_path, sizeof(cfg->db_path), cfg->db_path);
    cfg->export_interval_sec = json_get_uint32(obj, "export_interval_sec", cfg->export_interval_sec);
    cfg->max_flow_records = json_get_uint32(obj, "max_flow_records", cfg->max_flow_records);
    cfg->flow_sample_rate = json_get_uint32(obj, "flow_sample_rate", cfg->flow_sample_rate);
    cfg->export_packet_samples = json_get_bool(obj, "export_packet_samples", cfg->export_packet_samples);
    cfg->events_enabled = json_get_bool(obj, "events_enabled", cfg->events_enabled);
    cfg->concentration_export_enabled = json_get_bool(obj, "concentration_export_enabled", cfg->concentration_export_enabled);
}

static void parse_validation(const cJSON *obj, struct validation_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->validate_ip_checksum = json_get_bool(obj, "validate_ip_checksum", cfg->validate_ip_checksum);
    cfg->validate_udp_checksum = json_get_bool(obj, "validate_udp_checksum", cfg->validate_udp_checksum);
    cfg->validate_tcp_checksum = json_get_bool(obj, "validate_tcp_checksum", cfg->validate_tcp_checksum);
    cfg->drop_invalid_src_ip = json_get_bool(obj, "drop_invalid_src_ip", cfg->drop_invalid_src_ip);
    cfg->drop_land_attack = json_get_bool(obj, "drop_land_attack", cfg->drop_land_attack);
    cfg->drop_tcp_null = json_get_bool(obj, "drop_tcp_null", cfg->drop_tcp_null);
    cfg->drop_tcp_xmas = json_get_bool(obj, "drop_tcp_xmas", cfg->drop_tcp_xmas);
    cfg->drop_zero_ttl = json_get_bool(obj, "drop_zero_ttl", cfg->drop_zero_ttl);
    cfg->drop_fragments = json_get_bool(obj, "drop_fragments", cfg->drop_fragments);
    cfg->decrement_ttl = json_get_bool(obj, "decrement_ttl", cfg->decrement_ttl);
}

static void parse_rate_limits(const cJSON *obj, struct rate_limit_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->global_pps_limit = json_get_uint64(obj, "global_pps_limit", cfg->global_pps_limit);
    cfg->global_bps_limit = json_get_uint64(obj, "global_bps_limit", cfg->global_bps_limit);
    cfg->normal_pps_per_ip = json_get_uint32(obj, "normal_pps_per_ip", cfg->normal_pps_per_ip);
    cfg->normal_bps_per_ip = json_get_uint32(obj, "normal_bps_per_ip", cfg->normal_bps_per_ip);
    cfg->attack_pps_per_ip = json_get_uint32(obj, "attack_pps_per_ip", cfg->attack_pps_per_ip);
    cfg->attack_bps_per_ip = json_get_uint32(obj, "attack_bps_per_ip", cfg->attack_bps_per_ip);
    cfg->dynamic_enabled = json_get_bool(obj, "dynamic_enabled", cfg->dynamic_enabled);
    cfg->anomaly_detection_window = json_get_uint32(obj, "anomaly_detection_window", cfg->anomaly_detection_window);

    // Progressive rate limiting
    cfg->progressive_enabled = json_get_bool(obj, "progressive_enabled", cfg->progressive_enabled);
    cfg->level_low_percent = (uint8_t)json_get_uint32(obj, "level_low_percent", cfg->level_low_percent);
    cfg->level_medium_percent = (uint8_t)json_get_uint32(obj, "level_medium_percent", cfg->level_medium_percent);
    cfg->level_high_percent = (uint8_t)json_get_uint32(obj, "level_high_percent", cfg->level_high_percent);
    cfg->level_critical_percent = (uint8_t)json_get_uint32(obj, "level_critical_percent", cfg->level_critical_percent);
}

static void parse_ports(const cJSON *obj, struct port_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->client_facing_port = (uint16_t)json_get_uint32(obj, "client_facing_port", cfg->client_facing_port);
    cfg->server_facing_port = (uint16_t)json_get_uint32(obj, "server_facing_port", cfg->server_facing_port);
}

static void parse_maintenance(const cJSON *obj, struct maintenance_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->flow_age_interval_sec = json_get_uint32(obj, "flow_age_interval_sec", cfg->flow_age_interval_sec);
    cfg->secret_rotation_sec = json_get_uint32(obj, "secret_rotation_sec", cfg->secret_rotation_sec);
    cfg->stats_print_interval_sec = json_get_uint32(obj, "stats_print_interval_sec", cfg->stats_print_interval_sec);
}

static void parse_geo_blocking(const cJSON *obj, struct geo_blocking_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->enabled = json_get_bool(obj, "enabled", cfg->enabled);
    cfg->mode = (uint8_t)json_get_uint32(obj, "mode", cfg->mode);
    json_get_string(obj, "database_path", cfg->database_path, sizeof(cfg->database_path), cfg->database_path);
    cfg->log_blocked = json_get_bool(obj, "log_blocked", cfg->log_blocked);
}

static void parse_other_protocols(const cJSON *obj, struct other_protocols_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->enabled = json_get_bool(obj, "enabled", cfg->enabled);
    cfg->default_action = (uint8_t)json_get_uint32(obj, "default_action", cfg->default_action);
    cfg->rate_limit_pps = json_get_uint32(obj, "rate_limit_pps", cfg->rate_limit_pps);
    cfg->log_unknown = json_get_bool(obj, "log_unknown", cfg->log_unknown);

    // Parse allowed protocols array
    const cJSON *allowed = cJSON_GetObjectItemCaseSensitive(obj, "allowed_protocols");
    if (cJSON_IsArray(allowed)) {
        cfg->allowed_count = 0;
        const cJSON *item;
        cJSON_ArrayForEach(item, allowed) {
            if (cJSON_IsNumber(item) && cfg->allowed_count < 32) {
                cfg->allowed_protocols[cfg->allowed_count++] = (uint8_t)item->valueint;
            }
        }
    }
}

static void parse_signatures(const cJSON *obj, struct signatures_cfg *cfg) {
    if (!obj || !cfg) return;

    cfg->enabled = json_get_bool(obj, "enabled", cfg->enabled);
    cfg->log_matches = json_get_bool(obj, "log_matches", cfg->log_matches);
    cfg->block_amplification = json_get_bool(obj, "block_amplification", cfg->block_amplification);
    cfg->block_scans = json_get_bool(obj, "block_scans", cfg->block_scans);
    cfg->block_anomalies = json_get_bool(obj, "block_anomalies", cfg->block_anomalies);
    cfg->block_attack_tools = json_get_bool(obj, "block_attack_tools", cfg->block_attack_tools);
}

// ==================== Load Configuration ====================

int layer1_config_load(const char *config_path, struct layer1_config *config) {
    if (!config) {
        RTE_LOG(ERR, CFG, "NULL config pointer\n");
        return -1;
    }

    // Start with defaults
    layer1_config_defaults(config);

    if (!config_path) {
        RTE_LOG(INFO, CFG, "No config file specified, using defaults\n");
        return 0;
    }

    // Read file
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        RTE_LOG(WARNING, CFG, "Cannot open config file '%s', using defaults\n", config_path);
        return 0;  // Not an error - just use defaults
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 1024 * 1024) {  // Max 1MB
        RTE_LOG(ERR, CFG, "Invalid config file size: %ld\n", file_size);
        fclose(fp);
        return -1;
    }

    char *json_str = malloc(file_size + 1);
    if (!json_str) {
        RTE_LOG(ERR, CFG, "Failed to allocate memory for config\n");
        fclose(fp);
        return -1;
    }

    size_t read_size = fread(json_str, 1, file_size, fp);
    fclose(fp);

    if (read_size != (size_t)file_size) {
        RTE_LOG(ERR, CFG, "Failed to read config file\n");
        free(json_str);
        return -1;
    }
    json_str[file_size] = '\0';

    // Parse JSON
    cJSON *root = cJSON_Parse(json_str);
    free(json_str);

    if (!root) {
        const char *error_ptr = cJSON_GetErrorPtr();
        RTE_LOG(ERR, CFG, "JSON parse error: %s\n", error_ptr ? error_ptr : "unknown");
        return -1;
    }

    // Parse each section
    parse_ip_lists(cJSON_GetObjectItemCaseSensitive(root, "ip_lists"), &config->ip_lists);
    parse_flow_table(cJSON_GetObjectItemCaseSensitive(root, "flow_table"), &config->flow_table);
    parse_syn_proxy(cJSON_GetObjectItemCaseSensitive(root, "syn_proxy"), &config->syn_proxy);
    parse_syn_cookie(cJSON_GetObjectItemCaseSensitive(root, "syn_cookie"), &config->syn_cookie);
    parse_connection_limits(cJSON_GetObjectItemCaseSensitive(root, "connection_limits"), &config->connection_limits);
    parse_udp_gatekeeper(cJSON_GetObjectItemCaseSensitive(root, "udp_gatekeeper"), &config->udp_gatekeeper);
    parse_telemetry(cJSON_GetObjectItemCaseSensitive(root, "telemetry"), &config->telemetry);
    parse_validation(cJSON_GetObjectItemCaseSensitive(root, "validation"), &config->validation);
    parse_rate_limits(cJSON_GetObjectItemCaseSensitive(root, "rate_limits"), &config->rate_limits);
    parse_ports(cJSON_GetObjectItemCaseSensitive(root, "ports"), &config->ports);
    parse_maintenance(cJSON_GetObjectItemCaseSensitive(root, "maintenance"), &config->maintenance);
    parse_geo_blocking(cJSON_GetObjectItemCaseSensitive(root, "geo_blocking"), &config->geo_blocking);
    parse_other_protocols(cJSON_GetObjectItemCaseSensitive(root, "other_protocols"), &config->other_protocols);
    parse_signatures(cJSON_GetObjectItemCaseSensitive(root, "signatures"), &config->signatures);

    // Parse global settings
    config->log_level = json_get_uint32(root, "log_level", config->log_level);
    config->stats_enabled = json_get_bool(root, "stats_enabled", config->stats_enabled);
    config->monitor_only = json_get_bool(root, "monitor_only", config->monitor_only);

    cJSON_Delete(root);

    RTE_LOG(INFO, CFG, "Configuration loaded from '%s'\n", config_path);
    return 0;
}

// ==================== Save Configuration ====================

static cJSON* create_ip_lists_json(const struct ip_lists_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "max_whitelist_entries", cfg->max_whitelist_entries);
    cJSON_AddNumberToObject(obj, "max_blacklist_entries", cfg->max_blacklist_entries);
    cJSON_AddNumberToObject(obj, "max_protected_entries", cfg->max_protected_entries);
    cJSON_AddNumberToObject(obj, "max_whitelist_cidrs", cfg->max_whitelist_cidrs);
    cJSON_AddBoolToObject(obj, "enforce_protected_ips", cfg->enforce_protected_ips);
    return obj;
}

static cJSON* create_flow_table_json(const struct flow_table_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "max_flows", cfg->max_flows);
    cJSON_AddNumberToObject(obj, "idle_timeout_sec", cfg->idle_timeout_sec);
    cJSON_AddNumberToObject(obj, "syn_timeout_sec", cfg->syn_timeout_sec);
    cJSON_AddNumberToObject(obj, "default_pps_limit", cfg->default_pps_limit);
    cJSON_AddNumberToObject(obj, "default_bps_limit", cfg->default_bps_limit);
    cJSON_AddBoolToObject(obj, "enable_syn_protection", cfg->enable_syn_protection);
    return obj;
}

static cJSON* create_syn_proxy_json(const struct syn_proxy_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddBoolToObject(obj, "enabled", cfg->enabled);
    cJSON_AddNumberToObject(obj, "max_connections", cfg->max_connections);
    cJSON_AddNumberToObject(obj, "connect_timeout_ms", cfg->connect_timeout_ms);
    cJSON_AddNumberToObject(obj, "idle_timeout_sec", cfg->idle_timeout_sec);
    cJSON_AddNumberToObject(obj, "secret_rotation_sec", cfg->secret_rotation_sec);
    return obj;
}

static cJSON* create_syn_cookie_json(const struct syn_cookie_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddBoolToObject(obj, "enabled", cfg->enabled);
    cJSON_AddNumberToObject(obj, "challenge_threshold", cfg->challenge_threshold);
    return obj;
}

static cJSON* create_connection_limits_json(const struct connection_limits_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "max_ips", cfg->max_ips);
    cJSON_AddNumberToObject(obj, "max_connections_per_ip", cfg->max_connections_per_ip);
    cJSON_AddNumberToObject(obj, "time_window_sec", cfg->time_window_sec);
    cJSON_AddNumberToObject(obj, "cleanup_interval_sec", cfg->cleanup_interval_sec);
    return obj;
}

static cJSON* create_udp_gatekeeper_json(const struct udp_gatekeeper_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "pps_threshold", cfg->pps_threshold);
    cJSON_AddNumberToObject(obj, "bps_threshold", cfg->bps_threshold);
    cJSON_AddNumberToObject(obj, "cms_width", cfg->cms_width);
    cJSON_AddNumberToObject(obj, "cms_depth", cfg->cms_depth);
    cJSON_AddNumberToObject(obj, "window_sec", cfg->window_sec);
    cJSON_AddBoolToObject(obj, "check_reputation", cfg->check_reputation);
    cJSON_AddNumberToObject(obj, "reputation_threshold", cfg->reputation_threshold);
    cJSON_AddBoolToObject(obj, "check_blacklist", cfg->check_blacklist);
    cJSON_AddNumberToObject(obj, "attack_pps_divisor", cfg->attack_pps_divisor);
    cJSON_AddNumberToObject(obj, "attack_bps_divisor", cfg->attack_bps_divisor);
    return obj;
}

static cJSON* create_telemetry_json(const struct telemetry_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "db_path", cfg->db_path);
    cJSON_AddNumberToObject(obj, "export_interval_sec", cfg->export_interval_sec);
    cJSON_AddNumberToObject(obj, "max_flow_records", cfg->max_flow_records);
    cJSON_AddNumberToObject(obj, "flow_sample_rate", cfg->flow_sample_rate);
    cJSON_AddBoolToObject(obj, "export_packet_samples", cfg->export_packet_samples);
    cJSON_AddBoolToObject(obj, "events_enabled", cfg->events_enabled);
    cJSON_AddBoolToObject(obj, "concentration_export_enabled", cfg->concentration_export_enabled);
    return obj;
}

static cJSON* create_validation_json(const struct validation_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddBoolToObject(obj, "validate_ip_checksum", cfg->validate_ip_checksum);
    cJSON_AddBoolToObject(obj, "validate_udp_checksum", cfg->validate_udp_checksum);
    cJSON_AddBoolToObject(obj, "validate_tcp_checksum", cfg->validate_tcp_checksum);
    cJSON_AddBoolToObject(obj, "drop_invalid_src_ip", cfg->drop_invalid_src_ip);
    cJSON_AddBoolToObject(obj, "drop_land_attack", cfg->drop_land_attack);
    cJSON_AddBoolToObject(obj, "drop_tcp_null", cfg->drop_tcp_null);
    cJSON_AddBoolToObject(obj, "drop_tcp_xmas", cfg->drop_tcp_xmas);
    cJSON_AddBoolToObject(obj, "drop_zero_ttl", cfg->drop_zero_ttl);
    cJSON_AddBoolToObject(obj, "drop_fragments", cfg->drop_fragments);
    cJSON_AddBoolToObject(obj, "decrement_ttl", cfg->decrement_ttl);
    return obj;
}

static cJSON* create_rate_limits_json(const struct rate_limit_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "global_pps_limit", (double)cfg->global_pps_limit);
    cJSON_AddNumberToObject(obj, "global_bps_limit", (double)cfg->global_bps_limit);
    cJSON_AddNumberToObject(obj, "normal_pps_per_ip", cfg->normal_pps_per_ip);
    cJSON_AddNumberToObject(obj, "normal_bps_per_ip", cfg->normal_bps_per_ip);
    cJSON_AddNumberToObject(obj, "attack_pps_per_ip", cfg->attack_pps_per_ip);
    cJSON_AddNumberToObject(obj, "attack_bps_per_ip", cfg->attack_bps_per_ip);
    cJSON_AddBoolToObject(obj, "dynamic_enabled", cfg->dynamic_enabled);
    cJSON_AddNumberToObject(obj, "anomaly_detection_window", cfg->anomaly_detection_window);

    // Progressive rate limiting
    cJSON_AddBoolToObject(obj, "progressive_enabled", cfg->progressive_enabled);
    cJSON_AddNumberToObject(obj, "level_low_percent", cfg->level_low_percent);
    cJSON_AddNumberToObject(obj, "level_medium_percent", cfg->level_medium_percent);
    cJSON_AddNumberToObject(obj, "level_high_percent", cfg->level_high_percent);
    cJSON_AddNumberToObject(obj, "level_critical_percent", cfg->level_critical_percent);
    return obj;
}

static cJSON* create_ports_json(const struct port_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "client_facing_port", cfg->client_facing_port);
    cJSON_AddNumberToObject(obj, "server_facing_port", cfg->server_facing_port);
    return obj;
}

static cJSON* create_maintenance_json(const struct maintenance_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "flow_age_interval_sec", cfg->flow_age_interval_sec);
    cJSON_AddNumberToObject(obj, "secret_rotation_sec", cfg->secret_rotation_sec);
    cJSON_AddNumberToObject(obj, "stats_print_interval_sec", cfg->stats_print_interval_sec);
    return obj;
}

static cJSON* create_geo_blocking_json(const struct geo_blocking_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddBoolToObject(obj, "enabled", cfg->enabled);
    cJSON_AddNumberToObject(obj, "mode", cfg->mode);
    cJSON_AddStringToObject(obj, "database_path", cfg->database_path);
    cJSON_AddBoolToObject(obj, "log_blocked", cfg->log_blocked);
    return obj;
}

static cJSON* create_other_protocols_json(const struct other_protocols_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddBoolToObject(obj, "enabled", cfg->enabled);
    cJSON_AddNumberToObject(obj, "default_action", cfg->default_action);
    cJSON_AddNumberToObject(obj, "rate_limit_pps", cfg->rate_limit_pps);
    cJSON_AddBoolToObject(obj, "log_unknown", cfg->log_unknown);

    cJSON *allowed = cJSON_CreateArray();
    for (uint32_t i = 0; i < cfg->allowed_count; i++) {
        cJSON_AddItemToArray(allowed, cJSON_CreateNumber(cfg->allowed_protocols[i]));
    }
    cJSON_AddItemToObject(obj, "allowed_protocols", allowed);

    return obj;
}

static cJSON* create_signatures_json(const struct signatures_cfg *cfg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddBoolToObject(obj, "enabled", cfg->enabled);
    cJSON_AddBoolToObject(obj, "log_matches", cfg->log_matches);
    cJSON_AddBoolToObject(obj, "block_amplification", cfg->block_amplification);
    cJSON_AddBoolToObject(obj, "block_scans", cfg->block_scans);
    cJSON_AddBoolToObject(obj, "block_anomalies", cfg->block_anomalies);
    cJSON_AddBoolToObject(obj, "block_attack_tools", cfg->block_attack_tools);
    return obj;
}

int layer1_config_save(const char *config_path, const struct layer1_config *config) {
    if (!config_path || !config) {
        RTE_LOG(ERR, CFG, "Invalid arguments to config_save\n");
        return -1;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        RTE_LOG(ERR, CFG, "Failed to create JSON object\n");
        return -1;
    }

    // Add all sections
    cJSON_AddItemToObject(root, "ip_lists", create_ip_lists_json(&config->ip_lists));
    cJSON_AddItemToObject(root, "flow_table", create_flow_table_json(&config->flow_table));
    cJSON_AddItemToObject(root, "syn_proxy", create_syn_proxy_json(&config->syn_proxy));
    cJSON_AddItemToObject(root, "syn_cookie", create_syn_cookie_json(&config->syn_cookie));
    cJSON_AddItemToObject(root, "connection_limits", create_connection_limits_json(&config->connection_limits));
    cJSON_AddItemToObject(root, "udp_gatekeeper", create_udp_gatekeeper_json(&config->udp_gatekeeper));
    cJSON_AddItemToObject(root, "telemetry", create_telemetry_json(&config->telemetry));
    cJSON_AddItemToObject(root, "validation", create_validation_json(&config->validation));
    cJSON_AddItemToObject(root, "rate_limits", create_rate_limits_json(&config->rate_limits));
    cJSON_AddItemToObject(root, "ports", create_ports_json(&config->ports));
    cJSON_AddItemToObject(root, "maintenance", create_maintenance_json(&config->maintenance));
    cJSON_AddItemToObject(root, "geo_blocking", create_geo_blocking_json(&config->geo_blocking));
    cJSON_AddItemToObject(root, "other_protocols", create_other_protocols_json(&config->other_protocols));
    cJSON_AddItemToObject(root, "signatures", create_signatures_json(&config->signatures));

    // Global settings
    cJSON_AddNumberToObject(root, "log_level", config->log_level);
    cJSON_AddBoolToObject(root, "stats_enabled", config->stats_enabled);
    cJSON_AddBoolToObject(root, "monitor_only", config->monitor_only);

    // Write to file
    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    if (!json_str) {
        RTE_LOG(ERR, CFG, "Failed to serialize JSON\n");
        return -1;
    }

    FILE *fp = fopen(config_path, "w");
    if (!fp) {
        RTE_LOG(ERR, CFG, "Cannot open config file '%s' for writing\n", config_path);
        free(json_str);
        return -1;
    }

    fprintf(fp, "%s\n", json_str);
    fclose(fp);
    free(json_str);

    RTE_LOG(INFO, CFG, "Configuration saved to '%s'\n", config_path);
    return 0;
}

// ==================== Validation ====================

/**
 * Enhanced configuration validation
 * Comprehensive validation with:
 * - Range checks
 * - Relationship validation between settings
 * - Memory usage estimation and warnings
 * - Security best practice warnings
 */

// Helper to check if value is power of 2
static inline bool is_power_of_2(uint32_t n) {
    return n > 0 && (n & (n - 1)) == 0;
}

// Estimate memory usage for given configuration
static uint64_t estimate_memory_usage(const struct layer1_config *config) {
    uint64_t mem = 0;

    // Flow table: ~128 bytes per entry
    mem += (uint64_t)config->flow_table.max_flows * 128;

    // SYN proxy connections: ~64 bytes per entry
    mem += (uint64_t)config->syn_proxy.max_connections * 64;

    // Connection limits table: ~32 bytes per IP
    mem += (uint64_t)config->connection_limits.max_ips * 32;

    // IP lists: ~4 bytes per entry
    mem += (uint64_t)config->ip_lists.max_whitelist_entries * 4;
    mem += (uint64_t)config->ip_lists.max_blacklist_entries * 4;

    // CMS: width * depth * 8 bytes
    mem += (uint64_t)config->udp_gatekeeper.cms_width * config->udp_gatekeeper.cms_depth * 8;

    return mem;
}

int layer1_config_validate(const struct layer1_config *config) {
    int warnings = 0;  // Count non-fatal warnings

    if (!config) {
        RTE_LOG(ERR, CFG, "NULL config pointer\n");
        return -1;
    }

    RTE_LOG(INFO, CFG, "Validating configuration...\n");

    // ===== IP Lists Validation =====
    if (config->ip_lists.max_whitelist_entries == 0) {
        RTE_LOG(ERR, CFG, "max_whitelist_entries must be > 0\n");
        return -1;
    }
    if (config->ip_lists.max_blacklist_entries == 0) {
        RTE_LOG(ERR, CFG, "max_blacklist_entries must be > 0\n");
        return -1;
    }
    // Warn if protected list is small relative to attack surface
    if (config->ip_lists.enforce_protected_ips &&
        config->ip_lists.max_protected_entries < 10) {
        RTE_LOG(WARNING, CFG, "enforce_protected_ips enabled with only %u entries\n",
                config->ip_lists.max_protected_entries);
        warnings++;
    }

    // ===== Flow Table Validation =====
    if (config->flow_table.max_flows == 0) {
        RTE_LOG(ERR, CFG, "max_flows must be > 0\n");
        return -1;
    }
    if (config->flow_table.max_flows > 100000000) {
        RTE_LOG(ERR, CFG, "max_flows exceeds maximum limit (100M)\n");
        return -1;
    }
    if (config->flow_table.idle_timeout_sec == 0) {
        RTE_LOG(ERR, CFG, "idle_timeout_sec must be > 0\n");
        return -1;
    }
    if (config->flow_table.syn_timeout_sec == 0) {
        RTE_LOG(ERR, CFG, "syn_timeout_sec must be > 0\n");
        return -1;
    }
    if (config->flow_table.syn_timeout_sec >= config->flow_table.idle_timeout_sec) {
        RTE_LOG(WARNING, CFG, "syn_timeout_sec (%u) >= idle_timeout_sec (%u) - SYN protection may be ineffective\n",
                config->flow_table.syn_timeout_sec, config->flow_table.idle_timeout_sec);
        warnings++;
    }
    // Check for power of 2 (helps hash table performance)
    if (!is_power_of_2(config->flow_table.max_flows)) {
        RTE_LOG(WARNING, CFG, "max_flows (%u) is not a power of 2 - may reduce hash efficiency\n",
                config->flow_table.max_flows);
        warnings++;
    }

    // ===== SYN Proxy Validation =====
    if (config->syn_proxy.enabled) {
        if (config->syn_proxy.max_connections == 0) {
            RTE_LOG(ERR, CFG, "syn_proxy.max_connections must be > 0 when enabled\n");
            return -1;
        }
        if (config->syn_proxy.connect_timeout_ms == 0) {
            RTE_LOG(ERR, CFG, "syn_proxy.connect_timeout_ms must be > 0\n");
            return -1;
        }
        if (config->syn_proxy.connect_timeout_ms > 30000) {
            RTE_LOG(WARNING, CFG, "syn_proxy.connect_timeout_ms (%u) > 30s - may cause slow connection establishment\n",
                    config->syn_proxy.connect_timeout_ms);
            warnings++;
        }
        if (config->syn_proxy.secret_rotation_sec < 30) {
            RTE_LOG(WARNING, CFG, "syn_proxy.secret_rotation_sec (%u) < 30s - may impact performance\n",
                    config->syn_proxy.secret_rotation_sec);
            warnings++;
        }
    }

    // ===== SYN Cookie Validation =====
    if (config->syn_cookie.enabled) {
        if (config->syn_cookie.challenge_threshold == 0) {
            RTE_LOG(WARNING, CFG, "syn_cookie.challenge_threshold is 0 - ALL SYNs will be challenged\n");
            warnings++;
        }
        // Warn if both SYN proxy and SYN cookie disabled
    }
    if (!config->syn_proxy.enabled && !config->syn_cookie.enabled) {
        RTE_LOG(WARNING, CFG, "Both SYN proxy and SYN cookie disabled - no SYN flood protection!\n");
        warnings++;
    }

    // ===== Connection Limits Validation =====
    if (config->connection_limits.max_ips == 0) {
        RTE_LOG(ERR, CFG, "connection_limits.max_ips must be > 0\n");
        return -1;
    }
    if (config->connection_limits.max_connections_per_ip == 0) {
        RTE_LOG(ERR, CFG, "max_connections_per_ip must be > 0\n");
        return -1;
    }
    if (config->connection_limits.max_connections_per_ip > 100000) {
        RTE_LOG(WARNING, CFG, "max_connections_per_ip (%u) is very high - may allow resource exhaustion\n",
                config->connection_limits.max_connections_per_ip);
        warnings++;
    }
    if (config->connection_limits.cleanup_interval_sec >= config->connection_limits.time_window_sec) {
        RTE_LOG(WARNING, CFG, "cleanup_interval >= time_window - limits may not be enforced correctly\n");
        warnings++;
    }

    // ===== UDP Gatekeeper Validation =====
    if (config->udp_gatekeeper.pps_threshold == 0) {
        RTE_LOG(ERR, CFG, "udp_gatekeeper.pps_threshold must be > 0\n");
        return -1;
    }
    if (config->udp_gatekeeper.bps_threshold == 0) {
        RTE_LOG(ERR, CFG, "udp_gatekeeper.bps_threshold must be > 0\n");
        return -1;
    }
    if (config->udp_gatekeeper.cms_width == 0 || config->udp_gatekeeper.cms_depth == 0) {
        RTE_LOG(ERR, CFG, "udp_gatekeeper CMS dimensions must be > 0\n");
        return -1;
    }
    if (config->udp_gatekeeper.attack_pps_divisor == 0 || config->udp_gatekeeper.attack_bps_divisor == 0) {
        RTE_LOG(ERR, CFG, "udp_gatekeeper attack divisors must be > 0\n");
        return -1;
    }
    if (!is_power_of_2(config->udp_gatekeeper.cms_width)) {
        RTE_LOG(WARNING, CFG, "udp_gatekeeper.cms_width (%u) is not a power of 2\n",
                config->udp_gatekeeper.cms_width);
        warnings++;
    }
    if (config->udp_gatekeeper.cms_depth < 3 || config->udp_gatekeeper.cms_depth > 8) {
        RTE_LOG(WARNING, CFG, "udp_gatekeeper.cms_depth (%u) outside recommended range [3,8]\n",
                config->udp_gatekeeper.cms_depth);
        warnings++;
    }

    // ===== Telemetry Validation =====
    if (config->telemetry.db_path[0] == '\0') {
        RTE_LOG(ERR, CFG, "telemetry.db_path cannot be empty\n");
        return -1;
    }
    if (config->telemetry.export_interval_sec == 0) {
        RTE_LOG(WARNING, CFG, "telemetry.export_interval_sec is 0 - telemetry export disabled\n");
        warnings++;
    }
    if (config->telemetry.flow_sample_rate == 0) {
        RTE_LOG(WARNING, CFG, "telemetry.flow_sample_rate is 0 - flow sampling disabled\n");
        warnings++;
    }

    // ===== Validation Module Validation =====
    if (!config->validation.drop_invalid_src_ip) {
        RTE_LOG(WARNING, CFG, "drop_invalid_src_ip disabled - spoofed source IPs allowed!\n");
        warnings++;
    }
    if (!config->validation.drop_land_attack) {
        RTE_LOG(WARNING, CFG, "drop_land_attack disabled - LAND attacks allowed!\n");
        warnings++;
    }

    // ===== Port Validation =====
    if (config->ports.client_facing_port == config->ports.server_facing_port) {
        RTE_LOG(ERR, CFG, "client_facing_port and server_facing_port must be different\n");
        return -1;
    }
    if (config->ports.client_facing_port > 15 || config->ports.server_facing_port > 15) {
        RTE_LOG(WARNING, CFG, "Port numbers > 15 may not be valid DPDK port IDs\n");
        warnings++;
    }

    // ===== Rate Limits Validation =====
    if (config->rate_limits.normal_pps_per_ip == 0 && config->rate_limits.dynamic_enabled) {
        RTE_LOG(ERR, CFG, "normal_pps_per_ip must be > 0 when dynamic_enabled\n");
        return -1;
    }
    if (config->rate_limits.attack_pps_per_ip == 0 && config->rate_limits.dynamic_enabled) {
        RTE_LOG(ERR, CFG, "attack_pps_per_ip must be > 0 when dynamic_enabled\n");
        return -1;
    }
    if (config->rate_limits.attack_pps_per_ip > config->rate_limits.normal_pps_per_ip) {
        RTE_LOG(WARNING, CFG, "attack_pps_per_ip (%u) > normal_pps_per_ip (%u) - limits inverted!\n",
                config->rate_limits.attack_pps_per_ip, config->rate_limits.normal_pps_per_ip);
        warnings++;
    }
    if (config->rate_limits.attack_bps_per_ip > config->rate_limits.normal_bps_per_ip) {
        RTE_LOG(WARNING, CFG, "attack_bps_per_ip > normal_bps_per_ip - limits inverted!\n");
        warnings++;
    }

    // Progressive rate limiting validation
    if (config->rate_limits.progressive_enabled) {
        if (config->rate_limits.level_low_percent > 100) {
            RTE_LOG(ERR, CFG, "level_low_percent (%u) must be <= 100\n",
                    config->rate_limits.level_low_percent);
            return -1;
        }
        if (config->rate_limits.level_medium_percent > config->rate_limits.level_low_percent) {
            RTE_LOG(WARNING, CFG, "level_medium_percent > level_low_percent - progression inverted\n");
            warnings++;
        }
        if (config->rate_limits.level_high_percent > config->rate_limits.level_medium_percent) {
            RTE_LOG(WARNING, CFG, "level_high_percent > level_medium_percent - progression inverted\n");
            warnings++;
        }
        if (config->rate_limits.level_critical_percent > config->rate_limits.level_high_percent) {
            RTE_LOG(WARNING, CFG, "level_critical_percent > level_high_percent - progression inverted\n");
            warnings++;
        }
        if (config->rate_limits.level_critical_percent == 0) {
            RTE_LOG(WARNING, CFG, "level_critical_percent is 0 - critical mode will drop all traffic\n");
            warnings++;
        }
    }

    // ===== Maintenance Validation =====
    if (config->maintenance.flow_age_interval_sec == 0) {
        RTE_LOG(ERR, CFG, "flow_age_interval_sec must be > 0\n");
        return -1;
    }
    if (config->maintenance.secret_rotation_sec == 0) {
        RTE_LOG(ERR, CFG, "secret_rotation_sec must be > 0\n");
        return -1;
    }
    if (config->maintenance.flow_age_interval_sec > config->flow_table.syn_timeout_sec) {
        RTE_LOG(WARNING, CFG, "flow_age_interval (%u) > syn_timeout (%u) - SYN flood cleanup may be slow\n",
                config->maintenance.flow_age_interval_sec, config->flow_table.syn_timeout_sec);
        warnings++;
    }

    // ===== Geo-blocking Validation =====
    if (config->geo_blocking.enabled) {
        if (config->geo_blocking.database_path[0] == '\0') {
            RTE_LOG(ERR, CFG, "geo_blocking.database_path cannot be empty when enabled\n");
            return -1;
        }
        if (config->geo_blocking.mode != 1 && config->geo_blocking.mode != 2) {
            RTE_LOG(ERR, CFG, "geo_blocking.mode must be 1 (blacklist) or 2 (whitelist)\n");
            return -1;
        }
    }

    // ===== Other Protocols Validation =====
    if (config->other_protocols.default_action > 2) {
        RTE_LOG(ERR, CFG, "other_protocols.default_action must be 0, 1, or 2\n");
        return -1;
    }

    // ===== Memory Usage Warning =====
    uint64_t mem_bytes = estimate_memory_usage(config);
    uint64_t mem_mb = mem_bytes / (1024 * 1024);
    if (mem_mb > 16384) {  // > 16 GB
        RTE_LOG(WARNING, CFG, "Estimated memory usage: %lu MB - may exceed available memory!\n", mem_mb);
        warnings++;
    } else if (mem_mb > 4096) {  // > 4 GB
        RTE_LOG(INFO, CFG, "Estimated memory usage: %lu MB\n", mem_mb);
    }

    // ===== Monitor-only Mode Warning =====
    if (config->monitor_only) {
        RTE_LOG(WARNING, CFG, "monitor_only mode enabled - NO PACKETS WILL BE DROPPED!\n");
        warnings++;
    }

    // ===== Summary =====
    if (warnings > 0) {
        RTE_LOG(WARNING, CFG, "Configuration validation complete with %d warning(s)\n", warnings);
    } else {
        RTE_LOG(INFO, CFG, "Configuration validation passed\n");
    }

    return 0;
}

// ==================== Print Configuration ====================

void layer1_config_print(const struct layer1_config *config) {
    if (!config) return;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                   Layer 1 Configuration                      ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");

    printf("║ IP Lists:                                                    ║\n");
    printf("║   Max Whitelist:     %-10u  Max Blacklist: %-10u   ║\n",
           config->ip_lists.max_whitelist_entries, config->ip_lists.max_blacklist_entries);
    printf("║   Max Protected:     %-10u  Max CIDRs:     %-10u   ║\n",
           config->ip_lists.max_protected_entries, config->ip_lists.max_whitelist_cidrs);
    printf("║   Enforce Protected: %-10s                              ║\n",
           config->ip_lists.enforce_protected_ips ? "yes" : "no");

    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Flow Table:                                                  ║\n");
    printf("║   Max Flows:         %-10u  Idle Timeout:  %-5u sec    ║\n",
           config->flow_table.max_flows, config->flow_table.idle_timeout_sec);
    printf("║   SYN Timeout:       %-5u sec   SYN Protection: %-10s   ║\n",
           config->flow_table.syn_timeout_sec,
           config->flow_table.enable_syn_protection ? "yes" : "no");

    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ SYN Proxy:           %-10s  Max Connections: %-10u ║\n",
           config->syn_proxy.enabled ? "enabled" : "disabled",
           config->syn_proxy.max_connections);
    printf("║   Connect Timeout:   %-5u ms   Idle Timeout:  %-5u sec    ║\n",
           config->syn_proxy.connect_timeout_ms, config->syn_proxy.idle_timeout_sec);

    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Connection Limits:                                           ║\n");
    printf("║   Max IPs:           %-10u  Max Conn/IP:   %-10u   ║\n",
           config->connection_limits.max_ips, config->connection_limits.max_connections_per_ip);
    printf("║   Time Window:       %-5u sec   Cleanup:       %-5u sec    ║\n",
           config->connection_limits.time_window_sec, config->connection_limits.cleanup_interval_sec);

    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ UDP Gatekeeper:                                              ║\n");
    printf("║   PPS Threshold:     %-10u  BPS Threshold: %-10u   ║\n",
           config->udp_gatekeeper.pps_threshold, config->udp_gatekeeper.bps_threshold);
    printf("║   CMS Width:         %-10u  CMS Depth:     %-10u   ║\n",
           config->udp_gatekeeper.cms_width, config->udp_gatekeeper.cms_depth);
    printf("║   Check Reputation:  %-5s       Rep Threshold: %-10u   ║\n",
           config->udp_gatekeeper.check_reputation ? "yes" : "no",
           config->udp_gatekeeper.reputation_threshold);
    printf("║   Attack Divisors:   PPS/%-5u   BPS/%-5u                   ║\n",
           config->udp_gatekeeper.attack_pps_divisor, config->udp_gatekeeper.attack_bps_divisor);

    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Rate Limits:                                                 ║\n");
    printf("║   Normal PPS/IP:     %-10u  Normal BPS/IP: %-10u   ║\n",
           config->rate_limits.normal_pps_per_ip, config->rate_limits.normal_bps_per_ip);
    printf("║   Attack PPS/IP:     %-10u  Attack BPS/IP: %-10u   ║\n",
           config->rate_limits.attack_pps_per_ip, config->rate_limits.attack_bps_per_ip);
    printf("║   Dynamic Limits:    %-10s                              ║\n",
           config->rate_limits.dynamic_enabled ? "yes" : "no");

    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Validation:                                                  ║\n");
    printf("║   IP Checksum:       %-5s       UDP Checksum:  %-5s        ║\n",
           config->validation.validate_ip_checksum ? "yes" : "no",
           config->validation.validate_udp_checksum ? "yes" : "no");
    printf("║   Drop Invalid Src:  %-5s       Drop LAND:     %-5s        ║\n",
           config->validation.drop_invalid_src_ip ? "yes" : "no",
           config->validation.drop_land_attack ? "yes" : "no");

    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Telemetry:                                                   ║\n");
    printf("║   Sample Rate:       1:%-8u Events:        %-10s   ║\n",
           config->telemetry.flow_sample_rate,
           config->telemetry.events_enabled ? "enabled" : "disabled");

    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Ports:  Client: %-5u  Server: %-5u                        ║\n",
           config->ports.client_facing_port, config->ports.server_facing_port);

    printf("╚══════════════════════════════════════════════════════════════╝\n");
}

// ==================== Global Config Access ====================

const struct layer1_config* layer1_config_get(void) {
    if (!config_initialized) {
        return NULL;
    }
    return &active_config;
}

int layer1_config_reload(const char *config_path) {
    struct layer1_config new_config;

    if (layer1_config_load(config_path, &new_config) < 0) {
        RTE_LOG(ERR, CFG, "Failed to load config for reload\n");
        return -1;
    }

    if (layer1_config_validate(&new_config) < 0) {
        RTE_LOG(ERR, CFG, "Invalid config, reload aborted\n");
        return -1;
    }

    // Only reload safe-to-change values (not table sizes)
    // Table sizes cannot be changed at runtime

    // Rate limits - safe to change
    active_config.rate_limits = new_config.rate_limits;

    // Validation flags - safe to change
    active_config.validation = new_config.validation;

    // Telemetry sampling - safe to change
    active_config.telemetry.flow_sample_rate = new_config.telemetry.flow_sample_rate;
    active_config.telemetry.events_enabled = new_config.telemetry.events_enabled;

    // Timeouts - safe to change
    active_config.flow_table.idle_timeout_sec = new_config.flow_table.idle_timeout_sec;
    active_config.flow_table.syn_timeout_sec = new_config.flow_table.syn_timeout_sec;
    active_config.syn_proxy.idle_timeout_sec = new_config.syn_proxy.idle_timeout_sec;
    active_config.syn_proxy.connect_timeout_ms = new_config.syn_proxy.connect_timeout_ms;

    // Maintenance intervals - safe to change
    active_config.maintenance = new_config.maintenance;

    // Monitor-only mode - safe to change
    active_config.monitor_only = new_config.monitor_only;

    // IP lists enforcement flag - safe to change at runtime
    // Note: max entry sizes cannot be changed (hash tables already allocated)
    active_config.ip_lists.enforce_protected_ips = new_config.ip_lists.enforce_protected_ips;

    RTE_LOG(INFO, CFG, "Configuration reloaded (runtime-safe values only)\n");
    RTE_LOG(INFO, CFG, "  enforce_protected_ips = %s\n",
            active_config.ip_lists.enforce_protected_ips ? "true" : "false");
    return 0;
}

// ==================== Internal: Set Active Config ====================

// Declared in header but not exposed in public API
void layer1_config_set_active(const struct layer1_config *config);

void layer1_config_set_active(const struct layer1_config *config) {
    if (config) {
        memcpy(&active_config, config, sizeof(active_config));
        config_initialized = true;
    }
}
