/**
 * @file organization.h
 * @brief Single-organization configuration for on-premises deployment
 *
 * This replaces the multi-tenant system (tenant.h) with a simplified
 * single-organization model. All protected IPs belong to one organization.
 */

#ifndef ORGANIZATION_H
#define ORGANIZATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

#define MAX_PROTECTED_NETWORKS      256     /* Max CIDR ranges to protect */
#define MAX_ORG_NAME_LEN            64
#define MAX_DESCRIPTION_LEN         128

/* ============================================================================
 * Protected Network
 * ============================================================================ */

struct protected_network {
    uint32_t    network;            /* Network address (host byte order) */
    uint8_t     prefix_len;         /* CIDR prefix (0-32) */
    bool        active;             /* Currently active */
    char        description[MAX_DESCRIPTION_LEN];
};

struct protected_network_v6 {
    uint8_t     network[16];        /* IPv6 network address */
    uint8_t     prefix_len;         /* CIDR prefix (0-128) */
    bool        active;
    char        description[MAX_DESCRIPTION_LEN];
};

/* ============================================================================
 * Organization Configuration
 * ============================================================================ */

struct organization_config {
    /* Identity */
    char        name[MAX_ORG_NAME_LEN];
    char        contact_email[128];
    char        alert_webhook[256];

    /* Protected networks (IPv4) */
    struct protected_network networks[MAX_PROTECTED_NETWORKS];
    uint32_t    network_count;

    /* Protected networks (IPv6) */
    struct protected_network_v6 networks_v6[MAX_PROTECTED_NETWORKS];
    uint32_t    network_count_v6;

    /* Global resource limits */
    struct {
        uint64_t    max_bps;            /* Max bandwidth */
        uint32_t    max_pps;            /* Max packet rate */
        uint32_t    max_flows;          /* Max concurrent flows */
        uint32_t    max_connections;    /* Max SYN proxy connections */
        uint32_t    max_blacklist;      /* Max blacklist entries */
        uint32_t    max_whitelist;      /* Max whitelist entries */
        uint32_t    max_policies;       /* Max active policies */
        uint32_t    max_signatures;     /* Max dynamic signatures */
    } limits;

    /* Current usage (updated by stats collector) */
    struct {
        uint64_t    current_bps;
        uint32_t    current_pps;
        uint32_t    active_flows;
        uint32_t    active_connections;
    } usage;

    /* Attack state */
    struct {
        bool        under_attack;
        uint8_t     attack_severity;    /* 0-5 */
        uint8_t     attack_type;
        uint64_t    attack_start_ns;
        uint64_t    attack_peak_pps;
        uint64_t    attack_peak_bps;
        uint32_t    attacks_24h;
    } attack_state;

    /* Timestamps */
    uint64_t    config_loaded_at;
    uint64_t    last_attack_at;
};

/* ============================================================================
 * Global Instance
 * ============================================================================ */

/* Single global organization config - no need for registry/lookup */
extern struct organization_config g_org_config;

/* ============================================================================
 * Initialization
 * ============================================================================ */

/**
 * Initialize organization config from JSON file
 * @param config_path Path to config JSON file
 * @return 0 on success, -1 on error
 */
int org_config_init(const char *config_path);

/**
 * Cleanup organization config
 */
void org_config_cleanup(void);

/**
 * Reload configuration (hot-reload)
 * @return 0 on success, -1 on error
 */
int org_config_reload(void);

/* ============================================================================
 * Protected Network Management
 * ============================================================================ */

/**
 * Check if an IP is protected (belongs to organization)
 * @param ip IPv4 address (host byte order)
 * @return true if protected, false otherwise
 */
bool org_is_protected_ip(uint32_t ip);

/**
 * Check if an IPv6 is protected
 * @param ip IPv6 address (network byte order)
 * @return true if protected, false otherwise
 */
bool org_is_protected_ip_v6(const uint8_t *ip);

/**
 * Add a protected network
 * @param network Network address (host byte order)
 * @param prefix_len CIDR prefix length
 * @param description Optional description
 * @return 0 on success, -1 on error
 */
int org_add_network(uint32_t network, uint8_t prefix_len, const char *description);

/**
 * Remove a protected network
 * @param network Network address
 * @param prefix_len CIDR prefix length
 * @return 0 on success, -1 if not found
 */
int org_remove_network(uint32_t network, uint8_t prefix_len);

/**
 * Get count of protected networks
 */
uint32_t org_get_network_count(void);

/* ============================================================================
 * Usage & Attack State
 * ============================================================================ */

/**
 * Update current usage statistics
 * Called periodically by stats collector
 */
void org_update_usage(uint64_t bps, uint32_t pps, uint32_t flows, uint32_t connections);

/**
 * Set attack state
 * @param under_attack Whether attack is active
 * @param severity Attack severity (0-5)
 * @param attack_type Attack classification
 */
void org_set_attack_state(bool under_attack, uint8_t severity, uint8_t attack_type);

/**
 * Check if organization is under attack
 */
bool org_is_under_attack(void);

/**
 * Get current attack severity (0 if not under attack)
 */
uint8_t org_get_attack_severity(void);

/* ============================================================================
 * Serialization
 * ============================================================================ */

/**
 * Serialize organization config to JSON
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return Number of bytes written, -1 on error
 */
int org_config_to_json(char *buf, size_t buf_size);

/**
 * Load organization config from JSON
 * @param json JSON string
 * @return 0 on success, -1 on error
 */
int org_config_from_json(const char *json);

#endif /* ORGANIZATION_H */
