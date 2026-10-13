/**
 * @file layer1_config_simple.h
 * @brief Simplified Layer 1 configuration for single-organization deployment
 *
 * This replaces the multi-tenant layer1_config.h with a single global
 * configuration. No tenant lookups, no per-tenant overrides - just one
 * set of settings for the entire organization.
 */

#ifndef LAYER1_CONFIG_SIMPLE_H
#define LAYER1_CONFIG_SIMPLE_H

#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * Rate Limiting Configuration
 * ============================================================================ */

struct l1_rate_limit_config {
    /* Global limits */
    uint64_t    global_pps;             /* Max packets per second (0 = unlimited) */
    uint64_t    global_bps;             /* Max bits per second (0 = unlimited) */

    /* Per-source-IP limits */
    uint32_t    per_src_pps;            /* Max PPS from single source */
    uint32_t    per_src_bps;            /* Max BPS from single source */

    /* Per-protocol limits */
    uint32_t    syn_pps;                /* SYN packets per second */
    uint32_t    ack_pps;                /* ACK packets per second */
    uint32_t    rst_pps;                /* RST packets per second */
    uint32_t    fin_pps;                /* FIN packets per second */
    uint32_t    udp_pps;                /* UDP packets per second */
    uint32_t    icmp_pps;               /* ICMP packets per second */
    uint32_t    dns_qps;                /* DNS queries per second */
    uint32_t    ntp_pps;                /* NTP packets per second */

    /* Progressive rate limiting (during attack) */
    bool        progressive_enabled;
    uint8_t     progressive_levels;     /* Number of escalation levels (1-4) */
    float       progressive_factors[4]; /* Multipliers: [0.8, 0.5, 0.25, 0.1] */
};

/* ============================================================================
 * Connection Limiting Configuration
 * ============================================================================ */

struct l1_conn_limit_config {
    uint32_t    max_conn_per_src;       /* Max connections per source IP */
    uint32_t    max_half_open_per_src;  /* Max half-open connections per src */
    uint32_t    max_conn_global;        /* Max total connections */
    uint32_t    max_new_conn_per_sec;   /* Max new connections per second */
    uint32_t    conn_window_sec;        /* Time window for counting (default: 10s) */
};

/* ============================================================================
 * SYN Proxy Configuration
 * ============================================================================ */

struct l1_syn_proxy_config {
    bool        enabled;                /* Enable SYN proxy */
    bool        always_on;              /* Force proxy even without attack */

    /* Activation thresholds */
    uint32_t    threshold_pps;          /* SYN rate to activate (0 = auto) */
    uint32_t    threshold_half_open;    /* Half-open count to activate */

    /* Capacity */
    uint32_t    max_connections;        /* Max proxy connections */

    /* Timeouts */
    uint32_t    cookie_ttl_sec;         /* SYN cookie validity (default: 60) */
    uint32_t    half_open_timeout_sec;  /* Half-open connection timeout */
    uint32_t    secret_rotation_sec;    /* Secret rotation interval */

    /* Challenge method */
    uint8_t     challenge_method;       /* 0=cookie, 1=puzzle, 2=hybrid */
};

/* ============================================================================
 * Flow Table Configuration
 * ============================================================================ */

struct l1_flow_table_config {
    uint32_t    max_flows;              /* Max concurrent flows */
    uint32_t    idle_timeout_sec;       /* Idle flow timeout */
    uint32_t    established_timeout_sec;/* Established connection timeout */
    uint32_t    aging_scan_limit;       /* Max flows to scan per aging cycle */

    /* Emergency eviction */
    uint8_t     emergency_threshold_pct;/* % full to trigger emergency (95) */
    bool        emergency_reputation_aware; /* Consider reputation when evicting */
};

/* ============================================================================
 * IP Lists Configuration
 * ============================================================================ */

struct l1_ip_lists_config {
    /* File paths */
    char        whitelist_path[256];
    char        blacklist_path[256];

    /* Capacity limits */
    uint32_t    max_whitelist_entries;  /* Max whitelist entries */
    uint32_t    max_blacklist_entries;  /* Max blacklist entries */
    uint32_t    max_whitelist_cidr;     /* Max whitelist CIDR entries */
    uint32_t    max_blacklist_cidr;     /* Max blacklist CIDR entries */

    /* Behavior */
    bool        whitelist_bypass_all;   /* Whitelist bypasses all checks */
    bool        hw_offload_blacklist;   /* Offload permanent blacklist to NIC */
};

/* ============================================================================
 * Packet Validation Configuration
 * ============================================================================ */

struct l1_validation_config {
    /* Checksum validation (usually offloaded to NIC) */
    bool        check_ip_checksum;
    bool        check_tcp_checksum;
    bool        check_udp_checksum;

    /* TTL validation */
    uint8_t     min_ttl;                /* Drop if TTL below this (default: 1) */

    /* Flag validation */
    bool        drop_invalid_flags;     /* Drop NULL, XMAS, etc. */
    bool        drop_fragments;         /* Drop fragmented packets */

    /* Size validation */
    uint16_t    min_packet_size;        /* Minimum packet size */
    uint16_t    max_packet_size;        /* Maximum packet size (0 = MTU) */
};

/* ============================================================================
 * TCP Abuse Detection Configuration
 * ============================================================================ */

struct l1_tcp_abuse_config {
    bool        enabled;

    /* Detection thresholds (per source IP per time window) */
    uint32_t    dup_seq_threshold;      /* Duplicate SEQ floods (150) */
    uint32_t    random_seq_threshold;   /* Random SEQ jumps (45) */
    uint32_t    random_ack_threshold;   /* Random ACK jumps (45) */
    uint32_t    zero_window_threshold;  /* Zero window attacks (5) */
    uint32_t    tiny_window_bytes;      /* Tiny window threshold (100) */
    uint32_t    small_window_bytes;     /* Small window threshold (2000) */
    uint32_t    same_window_threshold;  /* Same window flood (150) */
    uint32_t    same_ack_threshold;     /* Same ACK flood (150) */

    /* Time window */
    uint32_t    window_sec;             /* Detection window (10s) */
};

/* ============================================================================
 * UDP Gatekeeper Configuration
 * ============================================================================ */

struct l1_udp_gatekeeper_config {
    bool        enabled;

    /* Admission thresholds (per source IP) */
    uint32_t    pps_threshold;          /* Max UDP PPS from source */
    uint32_t    bps_threshold;          /* Max UDP BPS from source */

    /* Attack mode thresholds (stricter) */
    uint32_t    attack_pps_divisor;     /* Divide threshold by this (4) */

    /* Grace period for new sources */
    uint32_t    grace_period_sec;
    uint32_t    grace_pps;              /* Allowed PPS during grace */
};

/* ============================================================================
 * Geo-blocking Configuration
 * ============================================================================ */

struct l1_geo_config {
    bool        enabled;
    bool        whitelist_mode;         /* true = allow only listed countries */

    /* Country bitmaps (256 bits each for country codes 0-255) */
    uint64_t    blocked_countries[4];
    uint64_t    allowed_countries[4];

    /* GeoIP database */
    char        geoip_db_path[256];
};

/* ============================================================================
 * Signature Detection Configuration
 * ============================================================================ */

struct l1_signature_config {
    bool        enabled;
    bool        dynamic_signatures;     /* Allow L3 to add signatures */

    /* Capacity */
    uint32_t    max_signatures;         /* Max concurrent signatures */

    /* Matching */
    bool        match_payload;          /* Match packet payload patterns */
    uint32_t    max_payload_depth;      /* How deep to inspect (64 bytes) */
};

/* ============================================================================
 * Master Layer 1 Configuration
 * ============================================================================ */

struct layer1_config {
    uint64_t    version;                /* Config version (for hot-reload) */

    struct l1_rate_limit_config     rate_limits;
    struct l1_conn_limit_config     conn_limits;
    struct l1_syn_proxy_config      syn_proxy;
    struct l1_flow_table_config     flow_table;
    struct l1_ip_lists_config       ip_lists;
    struct l1_validation_config     validation;
    struct l1_tcp_abuse_config      tcp_abuse;
    struct l1_udp_gatekeeper_config udp_gatekeeper;
    struct l1_geo_config            geo;
    struct l1_signature_config      signatures;
};

/* ============================================================================
 * Global Configuration Instance
 * ============================================================================ */

/* Single global Layer 1 config - no tenant lookup needed */
extern struct layer1_config g_l1_config;

/* ============================================================================
 * API Functions
 * ============================================================================ */

/**
 * Initialize Layer 1 configuration with defaults
 */
void l1_config_defaults(struct layer1_config *cfg);

/**
 * Load configuration from JSON file
 * @param config_path Path to configuration file
 * @return 0 on success, -1 on error
 */
int l1_config_load(const char *config_path);

/**
 * Reload configuration (hot-reload)
 * @return 0 on success, -1 on error
 */
int l1_config_reload(void);

/**
 * Validate configuration
 * @param cfg Configuration to validate
 * @param errors Buffer for error messages (optional)
 * @param errors_size Size of error buffer
 * @return 0 if valid, number of errors otherwise
 */
int l1_config_validate(const struct layer1_config *cfg, char *errors, size_t errors_size);

/**
 * Get current configuration version
 * Used for cache invalidation
 */
uint64_t l1_config_get_version(void);

/* ============================================================================
 * Convenience Macros
 * ============================================================================ */

/* Direct access to global config (no function call overhead) */
#define L1_CFG              (g_l1_config)
#define L1_RATE_CFG         (g_l1_config.rate_limits)
#define L1_CONN_CFG         (g_l1_config.conn_limits)
#define L1_SYN_PROXY_CFG    (g_l1_config.syn_proxy)
#define L1_FLOW_CFG         (g_l1_config.flow_table)
#define L1_IP_LISTS_CFG     (g_l1_config.ip_lists)
#define L1_VALIDATION_CFG   (g_l1_config.validation)
#define L1_TCP_ABUSE_CFG    (g_l1_config.tcp_abuse)
#define L1_UDP_GK_CFG       (g_l1_config.udp_gatekeeper)
#define L1_GEO_CFG          (g_l1_config.geo)
#define L1_SIG_CFG          (g_l1_config.signatures)

/* ============================================================================
 * Default Values
 * ============================================================================ */

#define L1_DEFAULT_GLOBAL_PPS           10000000    /* 10 Mpps */
#define L1_DEFAULT_GLOBAL_BPS           10000000000 /* 10 Gbps */
#define L1_DEFAULT_PER_SRC_PPS          10000
#define L1_DEFAULT_PER_SRC_BPS          10000000    /* 10 Mbps */
#define L1_DEFAULT_SYN_PPS              5000
#define L1_DEFAULT_ACK_PPS              50000
#define L1_DEFAULT_RST_PPS              500
#define L1_DEFAULT_FIN_PPS              500
#define L1_DEFAULT_UDP_PPS              50000
#define L1_DEFAULT_ICMP_PPS             1000
#define L1_DEFAULT_DNS_QPS              10000
#define L1_DEFAULT_NTP_PPS              1000

#define L1_DEFAULT_MAX_CONN_PER_SRC     1000
#define L1_DEFAULT_MAX_HALF_OPEN        100
#define L1_DEFAULT_MAX_CONN_GLOBAL      2000000
#define L1_DEFAULT_NEW_CONN_PER_SEC     50000

#define L1_DEFAULT_MAX_FLOWS            4000000
#define L1_DEFAULT_IDLE_TIMEOUT         60
#define L1_DEFAULT_ESTABLISHED_TIMEOUT  300

#define L1_DEFAULT_SYN_PROXY_THRESHOLD  5000
#define L1_DEFAULT_SYN_PROXY_MAX        2000000
#define L1_DEFAULT_COOKIE_TTL           60

#define L1_DEFAULT_MAX_WHITELIST        10000
#define L1_DEFAULT_MAX_BLACKLIST        100000
#define L1_DEFAULT_MAX_SIGNATURES       256

#endif /* LAYER1_CONFIG_SIMPLE_H */
