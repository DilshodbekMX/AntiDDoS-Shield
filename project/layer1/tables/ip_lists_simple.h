/**
 * @file ip_lists_simple.h
 * @brief Simplified global IP whitelist/blacklist for single-organization deployment
 *
 * This replaces the per-tenant IP lists with a single global whitelist and blacklist.
 * No tenant lookups, just fast IP matching.
 */

#ifndef IP_LISTS_SIMPLE_H
#define IP_LISTS_SIMPLE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

#define IP_LIST_MAX_ENTRIES         100000  /* Max individual IPs */
#define IP_LIST_MAX_CIDR            10000   /* Max CIDR ranges */
#define IP_LIST_MAX_DESCRIPTION     64

/* ============================================================================
 * List Entry Types
 * ============================================================================ */

typedef enum {
    IP_LIST_TYPE_WHITELIST = 0,
    IP_LIST_TYPE_BLACKLIST,
} ip_list_type_t;

typedef enum {
    IP_ENTRY_PERMANENT = 0,     /* Never expires */
    IP_ENTRY_TEMPORARY,         /* Has expiration time */
    IP_ENTRY_DYNAMIC,           /* Added by Layer 3 ML */
} ip_entry_source_t;

/* IPv4 entry */
struct ip_list_entry {
    uint32_t    ip;                         /* IP address (host byte order) */
    uint32_t    added_time;                 /* Unix timestamp when added */
    uint32_t    expire_time;                /* 0 = permanent, else Unix timestamp */
    uint8_t     source;                     /* ip_entry_source_t */
    uint8_t     hit_count;                  /* Saturating counter for stats */
    uint8_t     _pad[2];
    char        description[IP_LIST_MAX_DESCRIPTION];
};

/* IPv4 CIDR entry */
struct ip_list_cidr_entry {
    uint32_t    network;                    /* Network address */
    uint8_t     prefix_len;                 /* CIDR prefix (0-32) */
    uint8_t     source;
    uint8_t     _pad[2];
    uint32_t    added_time;
    uint32_t    expire_time;
    char        description[IP_LIST_MAX_DESCRIPTION];
};

/* IPv6 entry */
struct ip_list_entry_v6 {
    uint8_t     ip[16];                     /* IPv6 address */
    uint32_t    added_time;
    uint32_t    expire_time;
    uint8_t     source;
    uint8_t     hit_count;
    uint8_t     _pad[2];
    char        description[IP_LIST_MAX_DESCRIPTION];
};

/* IPv6 CIDR entry */
struct ip_list_cidr_entry_v6 {
    uint8_t     network[16];
    uint8_t     prefix_len;                 /* CIDR prefix (0-128) */
    uint8_t     source;
    uint8_t     _pad[2];
    uint32_t    added_time;
    uint32_t    expire_time;
    char        description[IP_LIST_MAX_DESCRIPTION];
};

/* ============================================================================
 * Statistics
 * ============================================================================ */

struct ip_list_stats {
    uint32_t    whitelist_count;
    uint32_t    whitelist_cidr_count;
    uint32_t    blacklist_count;
    uint32_t    blacklist_cidr_count;
    uint64_t    whitelist_hits;
    uint64_t    blacklist_hits;
    uint64_t    whitelist_bypasses;         /* Packets that bypassed all checks */
    uint64_t    blacklist_drops;
};

/* ============================================================================
 * Initialization & Cleanup
 * ============================================================================ */

/**
 * Initialize IP lists subsystem
 * @param whitelist_path Path to whitelist JSON file (NULL for empty)
 * @param blacklist_path Path to blacklist JSON file (NULL for empty)
 * @return 0 on success, -1 on error
 */
int ip_lists_init(const char *whitelist_path, const char *blacklist_path);

/**
 * Cleanup IP lists subsystem
 */
void ip_lists_cleanup(void);

/**
 * Reload lists from files
 * @return 0 on success, -1 on error
 */
int ip_lists_reload(void);

/* ============================================================================
 * Lookup Functions (Hot Path)
 * ============================================================================ */

/**
 * Check if IPv4 is in whitelist
 * Uses LPM for fast CIDR matching when DPDK available
 * @param ip IPv4 address (host byte order)
 * @return true if whitelisted
 */
bool ip_is_whitelisted(uint32_t ip);

/**
 * Check if IPv4 is in blacklist
 * @param ip IPv4 address (host byte order)
 * @return true if blacklisted
 */
bool ip_is_blacklisted(uint32_t ip);

/**
 * Check if IPv6 is in whitelist
 * @param ip IPv6 address (network byte order)
 * @return true if whitelisted
 */
bool ip_is_whitelisted_v6(const uint8_t *ip);

/**
 * Check if IPv6 is in blacklist
 * @param ip IPv6 address (network byte order)
 * @return true if blacklisted
 */
bool ip_is_blacklisted_v6(const uint8_t *ip);

/**
 * Combined check - returns action for IP
 * @param ip IPv4 address (host byte order)
 * @return 1 = whitelist (bypass), 0 = neutral, -1 = blacklist (drop)
 */
int ip_list_check(uint32_t ip);

/**
 * Combined check for IPv6
 * @param ip IPv6 address (network byte order)
 * @return 1 = whitelist (bypass), 0 = neutral, -1 = blacklist (drop)
 */
int ip_list_check_v6(const uint8_t *ip);

/* ============================================================================
 * Management Functions
 * ============================================================================ */

/**
 * Add IP to whitelist
 * @param ip IPv4 address (host byte order)
 * @param description Optional description
 * @param expire_sec Seconds until expiration (0 = permanent)
 * @param source Entry source type
 * @return 0 on success, -1 on error
 */
int ip_whitelist_add(uint32_t ip, const char *description,
                     uint32_t expire_sec, ip_entry_source_t source);

/**
 * Add CIDR to whitelist
 * @param network Network address (host byte order)
 * @param prefix_len CIDR prefix length
 * @param description Optional description
 * @param expire_sec Seconds until expiration (0 = permanent)
 * @param source Entry source type
 * @return 0 on success, -1 on error
 */
int ip_whitelist_add_cidr(uint32_t network, uint8_t prefix_len,
                          const char *description, uint32_t expire_sec,
                          ip_entry_source_t source);

/**
 * Remove IP from whitelist
 * @param ip IPv4 address
 * @return 0 on success, -1 if not found
 */
int ip_whitelist_remove(uint32_t ip);

/**
 * Remove CIDR from whitelist
 * @param network Network address
 * @param prefix_len CIDR prefix length
 * @return 0 on success, -1 if not found
 */
int ip_whitelist_remove_cidr(uint32_t network, uint8_t prefix_len);

/**
 * Add IP to blacklist
 * @param ip IPv4 address (host byte order)
 * @param description Optional description
 * @param expire_sec Seconds until expiration (0 = permanent)
 * @param source Entry source type
 * @return 0 on success, -1 on error
 */
int ip_blacklist_add(uint32_t ip, const char *description,
                     uint32_t expire_sec, ip_entry_source_t source);

/**
 * Add CIDR to blacklist
 * @param network Network address (host byte order)
 * @param prefix_len CIDR prefix length
 * @param description Optional description
 * @param expire_sec Seconds until expiration (0 = permanent)
 * @param source Entry source type
 * @return 0 on success, -1 on error
 */
int ip_blacklist_add_cidr(uint32_t network, uint8_t prefix_len,
                          const char *description, uint32_t expire_sec,
                          ip_entry_source_t source);

/**
 * Remove IP from blacklist
 * @param ip IPv4 address
 * @return 0 on success, -1 if not found
 */
int ip_blacklist_remove(uint32_t ip);

/**
 * Remove CIDR from blacklist
 * @param network Network address
 * @param prefix_len CIDR prefix length
 * @return 0 on success, -1 if not found
 */
int ip_blacklist_remove_cidr(uint32_t network, uint8_t prefix_len);

/* ============================================================================
 * IPv6 Management
 * ============================================================================ */

int ip_whitelist_add_v6(const uint8_t *ip, const char *description,
                        uint32_t expire_sec, ip_entry_source_t source);
int ip_blacklist_add_v6(const uint8_t *ip, const char *description,
                        uint32_t expire_sec, ip_entry_source_t source);
int ip_whitelist_remove_v6(const uint8_t *ip);
int ip_blacklist_remove_v6(const uint8_t *ip);

/* ============================================================================
 * Maintenance
 * ============================================================================ */

/**
 * Remove expired entries from both lists
 * @return Number of entries removed
 */
uint32_t ip_lists_expire_old(void);

/**
 * Clear all dynamic entries (added by Layer 3)
 * @return Number of entries removed
 */
uint32_t ip_lists_clear_dynamic(void);

/**
 * Clear all temporary entries
 * @return Number of entries removed
 */
uint32_t ip_lists_clear_temporary(void);

/* ============================================================================
 * Statistics & Serialization
 * ============================================================================ */

/**
 * Get IP list statistics
 */
void ip_lists_get_stats(struct ip_list_stats *stats);

/**
 * Export whitelist to JSON
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return Bytes written, -1 on error
 */
int ip_whitelist_to_json(char *buf, size_t buf_size);

/**
 * Export blacklist to JSON
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return Bytes written, -1 on error
 */
int ip_blacklist_to_json(char *buf, size_t buf_size);

/**
 * Import whitelist from JSON
 * @param json JSON string
 * @param clear_first Clear existing entries first
 * @return Number of entries imported, -1 on error
 */
int ip_whitelist_from_json(const char *json, bool clear_first);

/**
 * Import blacklist from JSON
 * @param json JSON string
 * @param clear_first Clear existing entries first
 * @return Number of entries imported, -1 on error
 */
int ip_blacklist_from_json(const char *json, bool clear_first);

/* ============================================================================
 * Bulk Operations
 * ============================================================================ */

/**
 * Bulk add IPs to blacklist
 * Used by Layer 3 to efficiently add multiple IPs at once
 * @param ips Array of IPv4 addresses
 * @param count Number of IPs
 * @param description Description for all entries
 * @param expire_sec Expiration (0 = permanent)
 * @param source Entry source type
 * @return Number of IPs added
 */
int ip_blacklist_bulk_add(const uint32_t *ips, uint32_t count,
                          const char *description, uint32_t expire_sec,
                          ip_entry_source_t source);

/**
 * Bulk remove IPs from blacklist
 * @param ips Array of IPv4 addresses
 * @param count Number of IPs
 * @return Number of IPs removed
 */
int ip_blacklist_bulk_remove(const uint32_t *ips, uint32_t count);

#endif /* IP_LISTS_SIMPLE_H */
