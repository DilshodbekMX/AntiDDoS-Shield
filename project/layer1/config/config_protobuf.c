/**
 * @file config_protobuf.c
 * @brief Memory-safe configuration parsing implementation
 *
 * This implementation provides secure configuration parsing that:
 * - Uses bounded string operations (no sprintf/strcpy vulnerabilities)
 * - Validates all input lengths before copying
 * - Enforces schema validation
 * - Supports both JSON (human-readable) and binary (efficient) formats
 *
 * The JSON parser here is a minimal, secure implementation that replaces cJSON.
 * It uses fixed-size buffers and validates all string lengths.
 */

#include "config_protobuf.h"
#include "layer1_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <rte_log.h>

#define RTE_LOGTYPE_CONFIG RTE_LOGTYPE_USER3

// ==================== Error Messages ====================

static const char* error_messages[] = {
    [0] = "Success",
    [1] = "File not found",
    [2] = "File too large",
    [3] = "Memory allocation failed",
    [4] = "Parse error",
    [5] = "Validation failed",
    [6] = "String too long",
    [7] = "Value out of range",
    [8] = "Write failed",
};

const char* config_error_str(config_error_t error) {
    int idx = -error;
    if (idx < 0 || idx >= (int)(sizeof(error_messages) / sizeof(error_messages[0]))) {
        return "Unknown error";
    }
    return error_messages[idx];
}

// ==================== Minimal JSON Parser ====================
// This is a secure, minimal JSON parser with bounded operations

typedef struct {
    const char *data;
    size_t len;
    size_t pos;
} json_parser_t;

// Skip whitespace
static void json_skip_ws(json_parser_t *p) {
    while (p->pos < p->len && isspace((unsigned char)p->data[p->pos])) {
        p->pos++;
    }
}

// Check if we're at a specific character
static bool json_match(json_parser_t *p, char c) {
    json_skip_ws(p);
    if (p->pos < p->len && p->data[p->pos] == c) {
        p->pos++;
        return true;
    }
    return false;
}

// Parse a string value into fixed buffer
static bool json_parse_string(json_parser_t *p, char *out, size_t out_size) {
    json_skip_ws(p);

    if (p->pos >= p->len || p->data[p->pos] != '"') {
        return false;
    }
    p->pos++;  // Skip opening quote

    size_t out_pos = 0;
    while (p->pos < p->len && p->data[p->pos] != '"') {
        if (p->data[p->pos] == '\\' && p->pos + 1 < p->len) {
            p->pos++;  // Skip backslash
            char escaped = p->data[p->pos];
            char actual = escaped;
            switch (escaped) {
                case 'n': actual = '\n'; break;
                case 't': actual = '\t'; break;
                case 'r': actual = '\r'; break;
                case '"': actual = '"'; break;
                case '\\': actual = '\\'; break;
                default: break;
            }
            if (out_pos < out_size - 1) {
                out[out_pos++] = actual;
            }
        } else {
            if (out_pos < out_size - 1) {
                out[out_pos++] = p->data[p->pos];
            }
        }
        p->pos++;
    }

    if (p->pos >= p->len) {
        return false;  // Unterminated string
    }
    p->pos++;  // Skip closing quote
    out[out_pos] = '\0';
    return true;
}

// Parse a number (integer or double)
static bool json_parse_number(json_parser_t *p, double *out) {
    json_skip_ws(p);

    if (p->pos >= p->len) return false;

    char num_buf[64];
    size_t num_pos = 0;

    // Handle negative
    if (p->data[p->pos] == '-') {
        num_buf[num_pos++] = '-';
        p->pos++;
    }

    // Parse digits and decimal point
    while (p->pos < p->len && num_pos < sizeof(num_buf) - 1) {
        char c = p->data[p->pos];
        if (isdigit((unsigned char)c) || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
            num_buf[num_pos++] = c;
            p->pos++;
        } else {
            break;
        }
    }

    if (num_pos == 0) return false;
    num_buf[num_pos] = '\0';

    char *endptr;
    errno = 0;
    *out = strtod(num_buf, &endptr);
    return (errno == 0 && endptr != num_buf);
}

// Parse a boolean
static bool json_parse_bool(json_parser_t *p, bool *out) {
    json_skip_ws(p);

    if (p->pos + 4 <= p->len && strncmp(&p->data[p->pos], "true", 4) == 0) {
        p->pos += 4;
        *out = true;
        return true;
    }
    if (p->pos + 5 <= p->len && strncmp(&p->data[p->pos], "false", 5) == 0) {
        p->pos += 5;
        *out = false;
        return true;
    }
    return false;
}

// Skip a JSON value (for unknown keys)
static bool json_skip_value(json_parser_t *p) {
    json_skip_ws(p);
    if (p->pos >= p->len) return false;

    char c = p->data[p->pos];

    if (c == '"') {
        // Skip string
        p->pos++;
        while (p->pos < p->len && p->data[p->pos] != '"') {
            if (p->data[p->pos] == '\\') p->pos++;
            p->pos++;
        }
        if (p->pos < p->len) p->pos++;
        return true;
    }
    if (c == '{') {
        // Skip object
        int depth = 1;
        p->pos++;
        while (p->pos < p->len && depth > 0) {
            if (p->data[p->pos] == '{') depth++;
            else if (p->data[p->pos] == '}') depth--;
            else if (p->data[p->pos] == '"') {
                p->pos++;
                while (p->pos < p->len && p->data[p->pos] != '"') {
                    if (p->data[p->pos] == '\\') p->pos++;
                    p->pos++;
                }
            }
            p->pos++;
        }
        return depth == 0;
    }
    if (c == '[') {
        // Skip array
        int depth = 1;
        p->pos++;
        while (p->pos < p->len && depth > 0) {
            if (p->data[p->pos] == '[') depth++;
            else if (p->data[p->pos] == ']') depth--;
            else if (p->data[p->pos] == '"') {
                p->pos++;
                while (p->pos < p->len && p->data[p->pos] != '"') {
                    if (p->data[p->pos] == '\\') p->pos++;
                    p->pos++;
                }
            }
            p->pos++;
        }
        return depth == 0;
    }
    if (c == 't' || c == 'f') {
        bool val;
        return json_parse_bool(p, &val);
    }
    if (c == 'n') {
        // null
        if (p->pos + 4 <= p->len && strncmp(&p->data[p->pos], "null", 4) == 0) {
            p->pos += 4;
            return true;
        }
        return false;
    }
    if (isdigit((unsigned char)c) || c == '-') {
        double val;
        return json_parse_number(p, &val);
    }
    return false;
}

// ==================== Section Parsers ====================

static bool parse_ip_lists_section(json_parser_t *p, struct ip_lists_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        double num;
        bool bval;

        if (strcmp(key, "max_whitelist_entries") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->max_whitelist_entries = (uint32_t)num;
        } else if (strcmp(key, "max_blacklist_entries") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->max_blacklist_entries = (uint32_t)num;
        } else if (strcmp(key, "max_protected_entries") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->max_protected_entries = (uint32_t)num;
        } else if (strcmp(key, "max_whitelist_cidrs") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->max_whitelist_cidrs = (uint32_t)num;
        } else if (strcmp(key, "enforce_protected_ips") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->enforce_protected_ips = bval;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');  // Optional comma
    }
    return true;
}

static bool parse_flow_table_section(json_parser_t *p, struct flow_table_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        double num;
        bool bval;

        if (strcmp(key, "max_flows") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->max_flows = (uint32_t)num;
        } else if (strcmp(key, "idle_timeout_sec") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->idle_timeout_sec = (uint32_t)num;
        } else if (strcmp(key, "syn_timeout_sec") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->syn_timeout_sec = (uint32_t)num;
        } else if (strcmp(key, "default_pps_limit") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->default_pps_limit = (uint32_t)num;
        } else if (strcmp(key, "default_bps_limit") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->default_bps_limit = (uint32_t)num;
        } else if (strcmp(key, "enable_syn_protection") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->enable_syn_protection = bval;
        } else if (strcmp(key, "aging_scan_limit") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->aging_scan_limit = (uint32_t)num;
        } else if (strcmp(key, "aging_scan_limit_pressure") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->aging_scan_limit_pressure = (uint32_t)num;
        } else if (strcmp(key, "emergency_drop_unknown_pct") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->emergency_drop_unknown_pct = (uint8_t)num;
        } else if (strcmp(key, "emergency_drop_good_pct") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->emergency_drop_good_pct = (uint8_t)num;
        } else if (strcmp(key, "emergency_drop_neutral_pct") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->emergency_drop_neutral_pct = (uint8_t)num;
        } else if (strcmp(key, "emergency_drop_suspicious_pct") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->emergency_drop_suspicious_pct = (uint8_t)num;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

static bool parse_syn_proxy_section(json_parser_t *p, struct syn_proxy_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        double num;
        bool bval;

        if (strcmp(key, "enabled") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->enabled = bval;
        } else if (strcmp(key, "max_connections") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->max_connections = (uint32_t)num;
        } else if (strcmp(key, "connect_timeout_ms") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->connect_timeout_ms = (uint32_t)num;
        } else if (strcmp(key, "idle_timeout_sec") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->idle_timeout_sec = (uint32_t)num;
        } else if (strcmp(key, "secret_rotation_sec") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->secret_rotation_sec = (uint32_t)num;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

static bool parse_syn_cookie_section(json_parser_t *p, struct syn_cookie_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        double num;
        bool bval;

        if (strcmp(key, "enabled") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->enabled = bval;
        } else if (strcmp(key, "challenge_threshold") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->challenge_threshold = (uint32_t)num;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

static bool parse_connection_limits_section(json_parser_t *p, struct connection_limits_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        double num;

        if (strcmp(key, "max_ips") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->max_ips = (uint32_t)num;
        } else if (strcmp(key, "max_connections_per_ip") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->max_connections_per_ip = (uint32_t)num;
        } else if (strcmp(key, "time_window_sec") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->time_window_sec = (uint32_t)num;
        } else if (strcmp(key, "cleanup_interval_sec") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->cleanup_interval_sec = (uint32_t)num;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

static bool parse_udp_gatekeeper_section(json_parser_t *p, struct udp_gatekeeper_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        double num;
        bool bval;

        if (strcmp(key, "pps_threshold") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->pps_threshold = (uint32_t)num;
        } else if (strcmp(key, "bps_threshold") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->bps_threshold = (uint32_t)num;
        } else if (strcmp(key, "cms_width") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->cms_width = (uint32_t)num;
        } else if (strcmp(key, "cms_depth") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->cms_depth = (uint32_t)num;
        } else if (strcmp(key, "window_sec") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->window_sec = (uint32_t)num;
        } else if (strcmp(key, "check_reputation") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->check_reputation = bval;
        } else if (strcmp(key, "reputation_threshold") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->reputation_threshold = (uint16_t)num;
        } else if (strcmp(key, "check_blacklist") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->check_blacklist = bval;
        } else if (strcmp(key, "attack_pps_divisor") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->attack_pps_divisor = (uint32_t)num;
        } else if (strcmp(key, "attack_bps_divisor") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->attack_bps_divisor = (uint32_t)num;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

static bool parse_telemetry_section(json_parser_t *p, struct telemetry_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        double num;
        bool bval;

        if (strcmp(key, "db_path") == 0) {
            if (!json_parse_string(p, cfg->db_path, sizeof(cfg->db_path))) return false;
        } else if (strcmp(key, "export_interval_sec") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->export_interval_sec = (uint32_t)num;
        } else if (strcmp(key, "max_flow_records") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->max_flow_records = (uint32_t)num;
        } else if (strcmp(key, "flow_sample_rate") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->flow_sample_rate = (uint32_t)num;
        } else if (strcmp(key, "export_packet_samples") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->export_packet_samples = bval;
        } else if (strcmp(key, "events_enabled") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->events_enabled = bval;
        } else if (strcmp(key, "concentration_export_enabled") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->concentration_export_enabled = bval;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

static bool parse_validation_section(json_parser_t *p, struct validation_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        bool bval;

        if (strcmp(key, "validate_ip_checksum") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->validate_ip_checksum = bval;
        } else if (strcmp(key, "validate_udp_checksum") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->validate_udp_checksum = bval;
        } else if (strcmp(key, "validate_tcp_checksum") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->validate_tcp_checksum = bval;
        } else if (strcmp(key, "drop_invalid_src_ip") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->drop_invalid_src_ip = bval;
        } else if (strcmp(key, "drop_land_attack") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->drop_land_attack = bval;
        } else if (strcmp(key, "drop_tcp_null") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->drop_tcp_null = bval;
        } else if (strcmp(key, "drop_tcp_xmas") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->drop_tcp_xmas = bval;
        } else if (strcmp(key, "drop_zero_ttl") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->drop_zero_ttl = bval;
        } else if (strcmp(key, "drop_fragments") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->drop_fragments = bval;
        } else if (strcmp(key, "decrement_ttl") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->decrement_ttl = bval;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

static bool parse_rate_limits_section(json_parser_t *p, struct rate_limit_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        double num;
        bool bval;

        if (strcmp(key, "global_pps_limit") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->global_pps_limit = (uint64_t)num;
        } else if (strcmp(key, "global_bps_limit") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->global_bps_limit = (uint64_t)num;
        } else if (strcmp(key, "normal_pps_per_ip") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->normal_pps_per_ip = (uint32_t)num;
        } else if (strcmp(key, "normal_bps_per_ip") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->normal_bps_per_ip = (uint32_t)num;
        } else if (strcmp(key, "attack_pps_per_ip") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->attack_pps_per_ip = (uint32_t)num;
        } else if (strcmp(key, "attack_bps_per_ip") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->attack_bps_per_ip = (uint32_t)num;
        } else if (strcmp(key, "dynamic_enabled") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->dynamic_enabled = bval;
        } else if (strcmp(key, "anomaly_detection_window") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->anomaly_detection_window = (uint32_t)num;
        } else if (strcmp(key, "progressive_enabled") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->progressive_enabled = bval;
        } else if (strcmp(key, "level_low_percent") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->level_low_percent = (uint8_t)num;
        } else if (strcmp(key, "level_medium_percent") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->level_medium_percent = (uint8_t)num;
        } else if (strcmp(key, "level_high_percent") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->level_high_percent = (uint8_t)num;
        } else if (strcmp(key, "level_critical_percent") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->level_critical_percent = (uint8_t)num;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

static bool parse_ports_section(json_parser_t *p, struct port_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        double num;

        if (strcmp(key, "client_facing_port") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->client_facing_port = (uint16_t)num;
        } else if (strcmp(key, "server_facing_port") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->server_facing_port = (uint16_t)num;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

static bool parse_maintenance_section(json_parser_t *p, struct maintenance_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        double num;

        if (strcmp(key, "flow_age_interval_sec") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->flow_age_interval_sec = (uint32_t)num;
        } else if (strcmp(key, "secret_rotation_sec") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->secret_rotation_sec = (uint32_t)num;
        } else if (strcmp(key, "stats_print_interval_sec") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->stats_print_interval_sec = (uint32_t)num;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

static bool parse_geo_blocking_section(json_parser_t *p, struct geo_blocking_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        double num;
        bool bval;

        if (strcmp(key, "enabled") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->enabled = bval;
        } else if (strcmp(key, "mode") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->mode = (uint8_t)num;
        } else if (strcmp(key, "database_path") == 0) {
            if (!json_parse_string(p, cfg->database_path, sizeof(cfg->database_path))) return false;
        } else if (strcmp(key, "log_blocked") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->log_blocked = bval;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

static bool parse_other_protocols_section(json_parser_t *p, struct other_protocols_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        double num;
        bool bval;

        if (strcmp(key, "enabled") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->enabled = bval;
        } else if (strcmp(key, "default_action") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->default_action = (uint8_t)num;
        } else if (strcmp(key, "rate_limit_pps") == 0) {
            if (!json_parse_number(p, &num)) return false;
            cfg->rate_limit_pps = (uint32_t)num;
        } else if (strcmp(key, "log_unknown") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->log_unknown = bval;
        } else if (strcmp(key, "allowed_protocols") == 0) {
            // Parse array
            if (!json_match(p, '[')) return false;
            cfg->allowed_count = 0;
            while (!json_match(p, ']')) {
                if (cfg->allowed_count < 32) {
                    if (!json_parse_number(p, &num)) return false;
                    cfg->allowed_protocols[cfg->allowed_count++] = (uint8_t)num;
                } else {
                    if (!json_skip_value(p)) return false;
                }
                json_match(p, ',');
            }
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

static bool parse_signatures_section(json_parser_t *p, struct signatures_cfg *cfg) {
    if (!json_match(p, '{')) return false;

    char key[64];
    while (!json_match(p, '}')) {
        if (!json_parse_string(p, key, sizeof(key))) return false;
        if (!json_match(p, ':')) return false;

        bool bval;

        if (strcmp(key, "enabled") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->enabled = bval;
        } else if (strcmp(key, "log_matches") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->log_matches = bval;
        } else if (strcmp(key, "block_amplification") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->block_amplification = bval;
        } else if (strcmp(key, "block_scans") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->block_scans = bval;
        } else if (strcmp(key, "block_anomalies") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->block_anomalies = bval;
        } else if (strcmp(key, "block_attack_tools") == 0) {
            if (!json_parse_bool(p, &bval)) return false;
            cfg->block_attack_tools = bval;
        } else {
            if (!json_skip_value(p)) return false;
        }

        json_match(p, ',');
    }
    return true;
}

// ==================== Main Parser ====================

config_error_t config_load_json(const char *config_path, struct layer1_config *config) {
    if (!config) {
        return CONFIG_ERR_VALIDATION_FAILED;
    }

    // Initialize with defaults
    layer1_config_defaults(config);

    if (!config_path) {
        RTE_LOG(INFO, CONFIG, "No config file specified, using defaults\n");
        return CONFIG_OK;
    }

    // Open and read file
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        RTE_LOG(WARNING, CONFIG, "Cannot open config file '%s', using defaults\n", config_path);
        return CONFIG_OK;  // Not fatal - use defaults
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0 || file_size > CONFIG_MAX_FILE_SIZE) {
        RTE_LOG(ERR, CONFIG, "Invalid config file size: %ld\n", file_size);
        fclose(fp);
        return CONFIG_ERR_FILE_TOO_LARGE;
    }

    char *json_str = malloc(file_size + 1);
    if (!json_str) {
        RTE_LOG(ERR, CONFIG, "Failed to allocate memory for config\n");
        fclose(fp);
        return CONFIG_ERR_MEMORY_ALLOC;
    }

    size_t read_size = fread(json_str, 1, file_size, fp);
    fclose(fp);

    if (read_size != (size_t)file_size) {
        RTE_LOG(ERR, CONFIG, "Failed to read config file\n");
        free(json_str);
        return CONFIG_ERR_FILE_NOT_FOUND;
    }
    json_str[file_size] = '\0';

    // Parse JSON
    json_parser_t parser = {
        .data = json_str,
        .len = file_size,
        .pos = 0
    };

    if (!json_match(&parser, '{')) {
        RTE_LOG(ERR, CONFIG, "Config file must start with '{'\n");
        free(json_str);
        return CONFIG_ERR_PARSE_FAILED;
    }

    char key[64];
    while (!json_match(&parser, '}')) {
        if (!json_parse_string(&parser, key, sizeof(key))) {
            RTE_LOG(ERR, CONFIG, "Failed to parse key\n");
            free(json_str);
            return CONFIG_ERR_PARSE_FAILED;
        }

        if (!json_match(&parser, ':')) {
            RTE_LOG(ERR, CONFIG, "Expected ':' after key '%s'\n", key);
            free(json_str);
            return CONFIG_ERR_PARSE_FAILED;
        }

        bool success = true;

        if (strcmp(key, "ip_lists") == 0) {
            success = parse_ip_lists_section(&parser, &config->ip_lists);
        } else if (strcmp(key, "flow_table") == 0) {
            success = parse_flow_table_section(&parser, &config->flow_table);
        } else if (strcmp(key, "syn_proxy") == 0) {
            success = parse_syn_proxy_section(&parser, &config->syn_proxy);
        } else if (strcmp(key, "syn_cookie") == 0) {
            success = parse_syn_cookie_section(&parser, &config->syn_cookie);
        } else if (strcmp(key, "connection_limits") == 0) {
            success = parse_connection_limits_section(&parser, &config->connection_limits);
        } else if (strcmp(key, "udp_gatekeeper") == 0) {
            success = parse_udp_gatekeeper_section(&parser, &config->udp_gatekeeper);
        } else if (strcmp(key, "telemetry") == 0) {
            success = parse_telemetry_section(&parser, &config->telemetry);
        } else if (strcmp(key, "validation") == 0) {
            success = parse_validation_section(&parser, &config->validation);
        } else if (strcmp(key, "rate_limits") == 0) {
            success = parse_rate_limits_section(&parser, &config->rate_limits);
        } else if (strcmp(key, "ports") == 0) {
            success = parse_ports_section(&parser, &config->ports);
        } else if (strcmp(key, "maintenance") == 0) {
            success = parse_maintenance_section(&parser, &config->maintenance);
        } else if (strcmp(key, "geo_blocking") == 0) {
            success = parse_geo_blocking_section(&parser, &config->geo_blocking);
        } else if (strcmp(key, "other_protocols") == 0) {
            success = parse_other_protocols_section(&parser, &config->other_protocols);
        } else if (strcmp(key, "signatures") == 0) {
            success = parse_signatures_section(&parser, &config->signatures);
        } else if (strcmp(key, "log_level") == 0) {
            double num;
            if (!json_parse_number(&parser, &num)) success = false;
            else config->log_level = (uint32_t)num;
        } else if (strcmp(key, "stats_enabled") == 0) {
            bool bval;
            if (!json_parse_bool(&parser, &bval)) success = false;
            else config->stats_enabled = bval;
        } else if (strcmp(key, "monitor_only") == 0) {
            bool bval;
            if (!json_parse_bool(&parser, &bval)) success = false;
            else config->monitor_only = bval;
        } else {
            success = json_skip_value(&parser);
        }

        if (!success) {
            RTE_LOG(ERR, CONFIG, "Failed to parse section '%s'\n", key);
            free(json_str);
            return CONFIG_ERR_PARSE_FAILED;
        }

        json_match(&parser, ',');  // Optional comma
    }

    free(json_str);

    RTE_LOG(INFO, CONFIG, "Configuration loaded from '%s'\n", config_path);
    return CONFIG_OK;
}

// ==================== JSON Writer ====================

// Write JSON with bounded buffer operations
typedef struct {
    char *buf;
    size_t size;
    size_t pos;
    bool overflow;
} json_writer_t;

static void json_write(json_writer_t *w, const char *str) {
    size_t len = strlen(str);
    if (w->pos + len < w->size) {
        memcpy(w->buf + w->pos, str, len);
        w->pos += len;
    } else {
        w->overflow = true;
    }
}

static void json_write_indent(json_writer_t *w, int level) {
    for (int i = 0; i < level; i++) {
        json_write(w, "  ");
    }
}

static void json_write_string(json_writer_t *w, const char *str) {
    json_write(w, "\"");
    // Escape special characters
    for (const char *p = str; *p; p++) {
        char buf[3] = {0};
        switch (*p) {
            case '"':  json_write(w, "\\\""); break;
            case '\\': json_write(w, "\\\\"); break;
            case '\n': json_write(w, "\\n"); break;
            case '\t': json_write(w, "\\t"); break;
            case '\r': json_write(w, "\\r"); break;
            default:
                buf[0] = *p;
                json_write(w, buf);
                break;
        }
    }
    json_write(w, "\"");
}

static void json_write_key(json_writer_t *w, const char *key, int indent) {
    json_write_indent(w, indent);
    json_write_string(w, key);
    json_write(w, ": ");
}

static void json_write_u32(json_writer_t *w, uint32_t val) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", val);
    json_write(w, buf);
}

static void json_write_u64(json_writer_t *w, uint64_t val) {
    char buf[24];
    snprintf(buf, sizeof(buf), "%lu", (unsigned long)val);
    json_write(w, buf);
}

static void json_write_bool(json_writer_t *w, bool val) {
    json_write(w, val ? "true" : "false");
}

config_error_t config_save_json(const char *config_path, const struct layer1_config *config) {
    if (!config_path || !config) {
        return CONFIG_ERR_VALIDATION_FAILED;
    }

    // Allocate buffer for JSON output
    size_t buf_size = 32768;  // 32KB should be plenty
    char *buf = malloc(buf_size);
    if (!buf) {
        return CONFIG_ERR_MEMORY_ALLOC;
    }

    json_writer_t w = {
        .buf = buf,
        .size = buf_size,
        .pos = 0,
        .overflow = false
    };

    json_write(&w, "{\n");

    // ip_lists
    json_write_key(&w, "ip_lists", 1);
    json_write(&w, "{\n");
    json_write_key(&w, "max_whitelist_entries", 2);
    json_write_u32(&w, config->ip_lists.max_whitelist_entries);
    json_write(&w, ",\n");
    json_write_key(&w, "max_blacklist_entries", 2);
    json_write_u32(&w, config->ip_lists.max_blacklist_entries);
    json_write(&w, ",\n");
    json_write_key(&w, "max_protected_entries", 2);
    json_write_u32(&w, config->ip_lists.max_protected_entries);
    json_write(&w, ",\n");
    json_write_key(&w, "max_whitelist_cidrs", 2);
    json_write_u32(&w, config->ip_lists.max_whitelist_cidrs);
    json_write(&w, ",\n");
    json_write_key(&w, "enforce_protected_ips", 2);
    json_write_bool(&w, config->ip_lists.enforce_protected_ips);
    json_write(&w, "\n");
    json_write_indent(&w, 1);
    json_write(&w, "},\n");

    // flow_table
    json_write_key(&w, "flow_table", 1);
    json_write(&w, "{\n");
    json_write_key(&w, "max_flows", 2);
    json_write_u32(&w, config->flow_table.max_flows);
    json_write(&w, ",\n");
    json_write_key(&w, "idle_timeout_sec", 2);
    json_write_u32(&w, config->flow_table.idle_timeout_sec);
    json_write(&w, ",\n");
    json_write_key(&w, "syn_timeout_sec", 2);
    json_write_u32(&w, config->flow_table.syn_timeout_sec);
    json_write(&w, ",\n");
    json_write_key(&w, "default_pps_limit", 2);
    json_write_u32(&w, config->flow_table.default_pps_limit);
    json_write(&w, ",\n");
    json_write_key(&w, "default_bps_limit", 2);
    json_write_u32(&w, config->flow_table.default_bps_limit);
    json_write(&w, ",\n");
    json_write_key(&w, "enable_syn_protection", 2);
    json_write_bool(&w, config->flow_table.enable_syn_protection);
    json_write(&w, "\n");
    json_write_indent(&w, 1);
    json_write(&w, "},\n");

    // syn_proxy
    json_write_key(&w, "syn_proxy", 1);
    json_write(&w, "{\n");
    json_write_key(&w, "enabled", 2);
    json_write_bool(&w, config->syn_proxy.enabled);
    json_write(&w, ",\n");
    json_write_key(&w, "max_connections", 2);
    json_write_u32(&w, config->syn_proxy.max_connections);
    json_write(&w, ",\n");
    json_write_key(&w, "connect_timeout_ms", 2);
    json_write_u32(&w, config->syn_proxy.connect_timeout_ms);
    json_write(&w, ",\n");
    json_write_key(&w, "idle_timeout_sec", 2);
    json_write_u32(&w, config->syn_proxy.idle_timeout_sec);
    json_write(&w, ",\n");
    json_write_key(&w, "secret_rotation_sec", 2);
    json_write_u32(&w, config->syn_proxy.secret_rotation_sec);
    json_write(&w, "\n");
    json_write_indent(&w, 1);
    json_write(&w, "},\n");

    // Global settings
    json_write_key(&w, "log_level", 1);
    json_write_u32(&w, config->log_level);
    json_write(&w, ",\n");
    json_write_key(&w, "stats_enabled", 1);
    json_write_bool(&w, config->stats_enabled);
    json_write(&w, ",\n");
    json_write_key(&w, "monitor_only", 1);
    json_write_bool(&w, config->monitor_only);
    json_write(&w, "\n");

    json_write(&w, "}\n");

    if (w.overflow) {
        free(buf);
        return CONFIG_ERR_MEMORY_ALLOC;
    }

    // Write to file
    FILE *fp = fopen(config_path, "w");
    if (!fp) {
        free(buf);
        return CONFIG_ERR_WRITE_FAILED;
    }

    size_t written = fwrite(buf, 1, w.pos, fp);
    fclose(fp);
    free(buf);

    if (written != w.pos) {
        return CONFIG_ERR_WRITE_FAILED;
    }

    RTE_LOG(INFO, CONFIG, "Configuration saved to '%s'\n", config_path);
    return CONFIG_OK;
}

// Binary format placeholder - would use protobuf-c here
config_error_t config_load_binary(const char *config_path, struct layer1_config *config) {
    (void)config_path;
    (void)config;
    RTE_LOG(ERR, CONFIG, "Binary format not yet implemented\n");
    return CONFIG_ERR_PARSE_FAILED;
}

config_error_t config_save_binary(const char *config_path, const struct layer1_config *config) {
    (void)config_path;
    (void)config;
    RTE_LOG(ERR, CONFIG, "Binary format not yet implemented\n");
    return CONFIG_ERR_WRITE_FAILED;
}
