/**
 * @file tenant_ip_lists.h
 * @brief Per-Tenant IP Allow/Block List Management
 *
 * Provides hierarchical IP list checking:
 * 1. Global blacklist (applies to all tenants)
 * 2. Per-tenant blacklist (tenant-specific blocks)
 * 3. Per-tenant whitelist (tenant-specific allows)
 * 4. Global whitelist (applies to all tenants)
 *
 * Evaluation order (first match wins):
 * 1. Global blacklist -> DROP
 * 2. Tenant whitelist -> ALLOW (skip further checks)
 * 3. Tenant blacklist -> DROP
 * 4. Global whitelist -> ALLOW (skip further checks)
 * 5. Continue to normal processing
 *
 * Performance Target: <30 cycles per IP lookup using DPDK LPM
 */

#ifndef TENANT_IP_LISTS_H
#define TENANT_IP_LISTS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <netinet/in.h>

#include "../../common/tenant.h"

#ifdef __cplusplus
extern "C" {
#endif

// ==================== Configuration ====================

// Maximum entries per list type
#define TENANT_IP_MAX_GLOBAL_BLACKLIST   100000   // 100K global blacklist entries
#define TENANT_IP_MAX_GLOBAL_WHITELIST   10000    // 10K global whitelist entries
#define TENANT_IP_MAX_TENANT_BLACKLIST   10000    // 10K per tenant blacklist
#define TENANT_IP_MAX_TENANT_WHITELIST   1000     // 1K per tenant whitelist

// LPM table configuration
#define TENANT_IP_LPM_MAX_RULES          (TENANT_IP_MAX_GLOBAL_BLACKLIST + \
                                          TENANT_IP_MAX_GLOBAL_WHITELIST + \
                                          (MAX_TENANTS * TENANT_IP_MAX_TENANT_BLACKLIST / 10))
#define TENANT_IP_LPM_TBL8S              (1 << 16)  // 64K TBL8 entries

// IPv6 support
#define TENANT_IP_LPM6_MAX_RULES         (TENANT_IP_LPM_MAX_RULES / 2)
#define TENANT_IP_LPM6_TBL8S             (1 << 16)

// ==================== IP List Types ====================

/**
 * IP list types
 */
typedef enum {
    IP_LIST_GLOBAL_BLACKLIST = 0,  // Global block list (checked first)
    IP_LIST_GLOBAL_WHITELIST,      // Global allow list
    IP_LIST_TENANT_BLACKLIST,      // Per-tenant block list
    IP_LIST_TENANT_WHITELIST,      // Per-tenant allow list
    IP_LIST_TYPE_COUNT
} ip_list_type_t;

/**
 * IP list entry metadata (stored in LPM next-hop field)
 * Packed into 24 bits for LPM compatibility
 *
 * Bit layout:
 * [23:22] - list_type (2 bits, 0-3)
 * [21:12] - tenant_id (10 bits, 0-1023)
 * [11:0]  - entry_index (12 bits, for dedup/management)
 */
#define IP_LIST_PACK_NEXTHOP(list_type, tenant_id, entry_idx) \
    (((uint32_t)(list_type) << 22) | (((uint32_t)(tenant_id) & 0x3FF) << 12) | ((entry_idx) & 0xFFF))

#define IP_LIST_UNPACK_TYPE(nexthop)     (((nexthop) >> 22) & 0x3)
#define IP_LIST_UNPACK_TENANT(nexthop)   (((nexthop) >> 12) & 0x3FF)
#define IP_LIST_UNPACK_INDEX(nexthop)    ((nexthop) & 0xFFF)

// ==================== IP Entry Structure ====================

/**
 * IP list entry for management (not used in fast path)
 */
struct ip_list_entry {
    union {
        uint32_t ipv4;
        uint8_t  ipv6[16];
    } addr;
    uint8_t      prefix_len;     // CIDR prefix (0-32 for IPv4, 0-128 for IPv6)
    uint8_t      is_ipv6;        // 0 for IPv4, 1 for IPv6
    ip_list_type_t list_type;
    tenant_id_t  tenant_id;      // TENANT_ID_NONE for global lists

    // Metadata
    uint64_t     added_at;       // Timestamp when added
    uint64_t     expires_at;     // Expiration timestamp (0 = never)
    uint64_t     hit_count;      // Number of times matched
    char         comment[64];    // Optional description
};

// ==================== Lookup Result ====================

/**
 * Result of IP list lookup
 */
struct ip_list_result {
    bool         matched;        // true if IP matched any list
    ip_list_type_t list_type;    // Which list matched
    tenant_id_t  tenant_id;      // Tenant that owns the list (or TENANT_ID_NONE)
    uint8_t      action;         // IP_LIST_ACTION_*
    uint8_t      prefix_len;     // Matched prefix length (for specificity)
};

// Actions
#define IP_LIST_ACTION_NONE      0   // No match, continue processing
#define IP_LIST_ACTION_ALLOW     1   // Whitelist match, allow packet
#define IP_LIST_ACTION_BLOCK     2   // Blacklist match, drop packet

// ==================== Statistics ====================

/**
 * Per-list-type statistics
 */
struct ip_list_stats {
    _Atomic uint64_t lookups;          // Total lookups
    _Atomic uint64_t hits;             // Successful matches
    _Atomic uint64_t blocks;           // Block actions taken
    _Atomic uint64_t allows;           // Allow actions taken
    _Atomic uint64_t entry_count;      // Current entries in list
};

/**
 * Per-tenant IP list statistics
 */
struct tenant_ip_list_stats {
    struct ip_list_stats blacklist;
    struct ip_list_stats whitelist;
};

// ==================== Initialization API ====================

/**
 * Initialize tenant IP lists subsystem
 *
 * @return 0 on success, -1 on failure
 */
int tenant_ip_lists_init(void);

/**
 * Cleanup tenant IP lists subsystem
 */
void tenant_ip_lists_cleanup(void);

/**
 * Initialize IP lists for a tenant
 *
 * @param tenant_id  Tenant ID
 * @return 0 on success, -1 on failure
 */
int tenant_ip_lists_tenant_init(tenant_id_t tenant_id);

/**
 * Cleanup IP lists for a tenant
 * Removes all tenant-specific entries
 *
 * @param tenant_id  Tenant ID
 */
void tenant_ip_lists_tenant_cleanup(tenant_id_t tenant_id);

// ==================== Fast Path API ====================

/**
 * Check IP against all applicable lists (FAST PATH)
 * Evaluates in order: global blacklist, tenant whitelist, tenant blacklist, global whitelist
 *
 * @param tenant_id   Resolved tenant ID (or TENANT_ID_NONE if unknown)
 * @param src_ip      Source IP address (network byte order)
 * @param result      Output: lookup result with action
 * @return Action to take: IP_LIST_ACTION_*
 */
uint8_t tenant_ip_check(tenant_id_t tenant_id, uint32_t src_ip,
                        struct ip_list_result *result);

/**
 * Check IPv6 address against all applicable lists
 *
 * @param tenant_id   Tenant ID
 * @param src_ip6     Source IPv6 address (16 bytes, network byte order)
 * @param result      Output: lookup result
 * @return Action to take
 */
uint8_t tenant_ip6_check(tenant_id_t tenant_id, const uint8_t *src_ip6,
                         struct ip_list_result *result);

/**
 * Simple check returning only action (fastest)
 *
 * @param tenant_id  Tenant ID
 * @param src_ip     Source IP
 * @return IP_LIST_ACTION_*
 */
static inline uint8_t tenant_ip_check_simple(tenant_id_t tenant_id, uint32_t src_ip);

// ==================== List Management API ====================

/**
 * Add IP/prefix to a list
 *
 * @param list_type   Which list to add to
 * @param tenant_id   Tenant ID (or TENANT_ID_NONE for global lists)
 * @param ip          IP address (network byte order)
 * @param prefix_len  CIDR prefix length
 * @param expires_sec Expiration in seconds (0 = never)
 * @param comment     Optional description
 * @return 0 on success, -1 on failure
 */
int tenant_ip_list_add(ip_list_type_t list_type,
                       tenant_id_t tenant_id,
                       uint32_t ip,
                       uint8_t prefix_len,
                       uint32_t expires_sec,
                       const char *comment);

/**
 * Add IPv6 prefix to a list
 */
int tenant_ip6_list_add(ip_list_type_t list_type,
                        tenant_id_t tenant_id,
                        const uint8_t *ip6,
                        uint8_t prefix_len,
                        uint32_t expires_sec,
                        const char *comment);

/**
 * Remove IP/prefix from a list
 *
 * @param list_type  Which list to remove from
 * @param tenant_id  Tenant ID (or TENANT_ID_NONE for global)
 * @param ip         IP address
 * @param prefix_len Prefix length
 * @return 0 on success, -1 if not found
 */
int tenant_ip_list_remove(ip_list_type_t list_type,
                          tenant_id_t tenant_id,
                          uint32_t ip,
                          uint8_t prefix_len);

/**
 * Remove IPv6 prefix from a list
 */
int tenant_ip6_list_remove(ip_list_type_t list_type,
                           tenant_id_t tenant_id,
                           const uint8_t *ip6,
                           uint8_t prefix_len);

/**
 * Check if IP/prefix exists in a list
 *
 * @param list_type  Which list to check
 * @param tenant_id  Tenant ID
 * @param ip         IP address
 * @param prefix_len Prefix length
 * @return true if exists
 */
bool tenant_ip_list_exists(ip_list_type_t list_type,
                           tenant_id_t tenant_id,
                           uint32_t ip,
                           uint8_t prefix_len);

/**
 * Clear all entries from a list
 *
 * @param list_type  Which list to clear
 * @param tenant_id  Tenant ID (or TENANT_ID_NONE for global)
 * @return Number of entries removed
 */
uint32_t tenant_ip_list_clear(ip_list_type_t list_type, tenant_id_t tenant_id);

// ==================== Bulk Operations ====================

/**
 * Bulk add IPs to a list (more efficient than individual adds)
 *
 * @param list_type   Which list
 * @param tenant_id   Tenant ID
 * @param ips         Array of IPs (network byte order)
 * @param prefix_lens Array of prefix lengths
 * @param count       Number of entries
 * @param expires_sec Expiration for all entries
 * @return Number of entries successfully added
 */
uint32_t tenant_ip_list_add_bulk(ip_list_type_t list_type,
                                 tenant_id_t tenant_id,
                                 const uint32_t *ips,
                                 const uint8_t *prefix_lens,
                                 uint32_t count,
                                 uint32_t expires_sec);

/**
 * Load IP list from file
 * File format: one IP/CIDR per line, # comments allowed
 *
 * @param list_type  Which list
 * @param tenant_id  Tenant ID
 * @param filepath   Path to file
 * @return Number of entries loaded, -1 on error
 */
int tenant_ip_list_load_file(ip_list_type_t list_type,
                             tenant_id_t tenant_id,
                             const char *filepath);

/**
 * Save IP list to file
 *
 * @param list_type  Which list
 * @param tenant_id  Tenant ID
 * @param filepath   Output file path
 * @return 0 on success, -1 on error
 */
int tenant_ip_list_save_file(ip_list_type_t list_type,
                             tenant_id_t tenant_id,
                             const char *filepath);

// ==================== Statistics API ====================

/**
 * Get statistics for a list
 *
 * @param list_type  Which list
 * @param tenant_id  Tenant ID (or TENANT_ID_NONE for global)
 * @param out_stats  Output: statistics
 * @return 0 on success
 */
int tenant_ip_list_get_stats(ip_list_type_t list_type,
                             tenant_id_t tenant_id,
                             struct ip_list_stats *out_stats);

/**
 * Get combined IP list stats for a tenant
 */
int tenant_ip_list_get_tenant_stats(tenant_id_t tenant_id,
                                    struct tenant_ip_list_stats *out_stats);

/**
 * Reset statistics for a list
 */
void tenant_ip_list_reset_stats(ip_list_type_t list_type, tenant_id_t tenant_id);

/**
 * Get entry count for a list
 */
uint32_t tenant_ip_list_count(ip_list_type_t list_type, tenant_id_t tenant_id);

// ==================== Iteration API ====================

/**
 * Iterate over entries in a list
 * Callback returns false to stop iteration
 *
 * @param list_type  Which list
 * @param tenant_id  Tenant ID
 * @param callback   Function to call for each entry
 * @param user_data  Passed to callback
 * @return Number of entries iterated
 */
typedef bool (*ip_list_iter_fn)(const struct ip_list_entry *entry, void *user_data);

uint32_t tenant_ip_list_iterate(ip_list_type_t list_type,
                                tenant_id_t tenant_id,
                                ip_list_iter_fn callback,
                                void *user_data);

// ==================== Maintenance API ====================

/**
 * Expire old entries (call periodically, e.g., every minute)
 *
 * @return Number of entries expired
 */
uint32_t tenant_ip_list_expire_entries(void);

/**
 * Rebuild LPM tables after many modifications
 * Optimizes table structure for better performance
 */
void tenant_ip_list_rebuild(void);

// ==================== Utility Functions ====================

/**
 * Get list type name
 */
const char* ip_list_type_to_string(ip_list_type_t list_type);

/**
 * Parse IP/CIDR string
 *
 * @param str        String like "192.168.1.0/24" or "10.0.0.1"
 * @param out_ip     Output: IP address (network byte order)
 * @param out_prefix Output: Prefix length
 * @return 0 on success, -1 on parse error
 */
int parse_ip_cidr(const char *str, uint32_t *out_ip, uint8_t *out_prefix);

/**
 * Format IP/CIDR to string
 *
 * @param ip         IP address (network byte order)
 * @param prefix     Prefix length
 * @param buf        Output buffer
 * @param buf_len    Buffer size
 * @return Pointer to buf, or NULL on error
 */
char* format_ip_cidr(uint32_t ip, uint8_t prefix, char *buf, size_t buf_len);

// ==================== Inline Implementation ====================

// Forward declaration for internal LPM lookup
uint8_t __tenant_ip_check_internal(tenant_id_t tenant_id, uint32_t src_ip,
                                   struct ip_list_result *result);

static inline uint8_t tenant_ip_check_simple(tenant_id_t tenant_id, uint32_t src_ip) {
    struct ip_list_result result;
    return __tenant_ip_check_internal(tenant_id, src_ip, &result);
}

#ifdef __cplusplus
}
#endif

#endif // TENANT_IP_LISTS_H
