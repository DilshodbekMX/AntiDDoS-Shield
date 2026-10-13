/**
 * @file ip_lists_v6.h
 * @brief IPv6 whitelist and blacklist using DPDK hash tables and LPM6
 *
 * IPv6 extension of ip_lists.h providing:
 * - Lock-free lookups for multi-core safety
 * - Hash-based O(1) lookup for exact IPv6 matches
 * - LPM6 (Longest Prefix Match) for IPv6 CIDR ranges
 * - Unified dual-stack support with ip_addr union
 *
 * Uses rte_hash with 128-bit keys for exact match and rte_lpm6 for prefix matching.
 */

#ifndef LAYER1_IP_LISTS_V6_H
#define LAYER1_IP_LISTS_V6_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_hash.h>
#include <rte_lpm6.h>

// Forward declaration for protection_profile (defined in ip_lists.h)
struct protection_profile;

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== IPv6 Whitelist Modes ==================== */

/**
 * IPv6 whitelist mode (mirrors IPv4 wl_mode)
 */
#define WL_MODE_V6_BYPASS  0   // Accept immediately, skip all checks
#define WL_MODE_V6_TRACK   1   // Pass through pipeline, never drop (track-mode)

/* ==================== Configuration ==================== */

struct ip_lists_v6_config {
    uint32_t max_whitelist_entries;   /* Maximum IPv6 whitelist entries (default: 10000) */
    uint32_t max_blacklist_entries;   /* Maximum IPv6 blacklist entries (default: 100000) */
    uint32_t max_protected_entries;   /* Maximum IPv6 protected server entries (default: 1000) */
    uint32_t max_whitelist_cidrs;     /* Maximum IPv6 CIDR whitelist entries (default: 10000) */
    uint32_t lpm6_rules;              /* Max LPM6 rules (default: 65536) */
    uint32_t lpm6_tbl8s;              /* LPM6 TBL8s (default: 4096) */
    bool     enforce_protected_ips;   /* If true, only allow traffic to protected IPv6 IPs */
};

/* Default LPM6 configuration */
#define IP_LISTS_V6_DEFAULT_LPM6_RULES  65536
#define IP_LISTS_V6_DEFAULT_LPM6_TBL8S  4096

/* ==================== Public API ==================== */

/**
 * Initialize IPv6 IP lists
 *
 * @param config  Configuration parameters (NULL for defaults)
 * @return 0 on success, -1 on error
 */
int ip_lists_v6_init(const struct ip_lists_v6_config *config);

/**
 * Cleanup IPv6 IP lists and free resources
 */
void ip_lists_v6_cleanup(void);

/* ==================== IPv6 Whitelist Operations ==================== */

/**
 * Add IPv6 address to whitelist
 *
 * Whitelisted IPs bypass all checks (validation, rate limiting, blacklist).
 *
 * @param ip6  IPv6 address (16 bytes, network byte order)
 * @return 0 on success, -1 on error
 */
int ip_whitelist_v6_add(const uint8_t ip6[16]);

/**
 * Remove IPv6 address from whitelist
 *
 * @param ip6  IPv6 address (16 bytes, network byte order)
 * @return 0 on success, -1 if not found
 */
int ip_whitelist_v6_remove(const uint8_t ip6[16]);

/**
 * Check if IPv6 address is whitelisted (exact match)
 *
 * @param ip6  IPv6 address (16 bytes, network byte order)
 * @return true if whitelisted, false otherwise
 */
bool ip_whitelist_v6_lookup(const uint8_t ip6[16]);

/**
 * Check if IPv6 address is whitelisted and return its mode.
 *
 * @param ip6   IPv6 address (16 bytes, network byte order)
 * @param mode  Output: WL_MODE_V6_BYPASS or WL_MODE_V6_TRACK (may be NULL)
 * @return true if whitelisted, false otherwise
 */
bool ip_whitelist_v6_lookup_mode(const uint8_t ip6[16], uint8_t *mode);

/**
 * Clear all IPv6 whitelist entries
 */
void ip_whitelist_v6_clear(void);

/**
 * Get number of IPv6 whitelist entries
 *
 * @return Number of entries
 */
uint32_t ip_whitelist_v6_count(void);

/* ==================== IPv6 CIDR Whitelist Operations (LPM6) ==================== */

/**
 * Add IPv6 CIDR prefix to whitelist
 *
 * Uses DPDK LPM6 for fast prefix matching. All IPs within the prefix
 * will be treated as whitelisted.
 *
 * Example: ip_whitelist_cidr_v6_add(cloudflare_ipv6, 48) for 2606:4700::/48
 *
 * @param ip6_prefix  IPv6 prefix (16 bytes, network byte order)
 * @param depth       Prefix length (1-128)
 * @return 0 on success, -1 on error
 */
int ip_whitelist_cidr_v6_add(const uint8_t ip6_prefix[16], uint8_t depth);

/**
 * Remove IPv6 CIDR prefix from whitelist
 *
 * @param ip6_prefix  IPv6 prefix (16 bytes, network byte order)
 * @param depth       Prefix length (1-128)
 * @return 0 on success, -1 if not found
 */
int ip_whitelist_cidr_v6_remove(const uint8_t ip6_prefix[16], uint8_t depth);

/**
 * Check if IPv6 address matches any whitelisted CIDR prefix
 *
 * @param ip6  IPv6 address (16 bytes, network byte order)
 * @return true if IP is within a whitelisted prefix, false otherwise
 */
bool ip_whitelist_cidr_v6_lookup(const uint8_t ip6[16]);

/**
 * Clear all IPv6 CIDR whitelist entries
 */
void ip_whitelist_cidr_v6_clear(void);

/**
 * Get number of IPv6 CIDR whitelist entries
 *
 * @return Number of CIDR prefixes
 */
uint32_t ip_whitelist_cidr_v6_count(void);

/* ==================== IPv6 Blacklist Operations ==================== */

/**
 * Add IPv6 address to blacklist
 *
 * Blacklisted IPs are dropped immediately.
 *
 * @param ip6  IPv6 address (16 bytes, network byte order)
 * @return 0 on success, -1 on error
 */
int ip_blacklist_v6_add(const uint8_t ip6[16]);

/**
 * Remove IPv6 address from blacklist
 *
 * @param ip6  IPv6 address (16 bytes, network byte order)
 * @return 0 on success, -1 if not found
 */
int ip_blacklist_v6_remove(const uint8_t ip6[16]);

/**
 * Check if IPv6 address is blacklisted
 *
 * @param ip6  IPv6 address (16 bytes, network byte order)
 * @return true if blacklisted, false otherwise
 */
bool ip_blacklist_v6_lookup(const uint8_t ip6[16]);

/**
 * Clear all IPv6 blacklist entries
 */
void ip_blacklist_v6_clear(void);

/**
 * Get number of IPv6 blacklist entries
 *
 * @return Number of entries
 */
uint32_t ip_blacklist_v6_count(void);

/* ==================== IPv6 Protected Server IPs ==================== */

/**
 * Add IPv6 address to protected servers list
 *
 * @param ip6  IPv6 address (16 bytes, network byte order)
 * @return 0 on success, -1 on error
 */
int ip_protected_v6_add(const uint8_t ip6[16]);

/**
 * Remove IPv6 address from protected servers list
 *
 * @param ip6  IPv6 address (16 bytes, network byte order)
 * @return 0 on success, -1 if not found
 */
int ip_protected_v6_remove(const uint8_t ip6[16]);

/**
 * Check if IPv6 address is a protected server
 *
 * @param ip6  IPv6 address (16 bytes, network byte order)
 * @return true if protected, false otherwise
 */
bool ip_protected_v6_lookup(const uint8_t ip6[16]);

/**
 * Clear all IPv6 protected server entries
 */
void ip_protected_v6_clear(void);

/**
 * Get number of IPv6 protected server entries
 *
 * @return Number of entries
 */
uint32_t ip_protected_v6_count(void);

/* ==================== Dual-Stack Combined Lookup ==================== */

/**
 * Check if IP (v4 or v6) is whitelisted
 *
 * Checks both exact match and CIDR prefix tables.
 *
 * @param ip        Pointer to IP address
 * @param is_ipv6   true for IPv6, false for IPv4
 * @return true if whitelisted, false otherwise
 */
bool ip_whitelist_lookup_unified(const void *ip, bool is_ipv6);

/**
 * Check if IP (v4 or v6) is blacklisted
 *
 * @param ip        Pointer to IP address
 * @param is_ipv6   true for IPv6, false for IPv4
 * @return true if blacklisted, false otherwise
 */
bool ip_blacklist_lookup_unified(const void *ip, bool is_ipv6);

/**
 * Check if IP (v4 or v6) is a protected server
 *
 * @param ip        Pointer to IP address
 * @param is_ipv6   true for IPv6, false for IPv4
 * @return true if protected, false otherwise
 */
bool ip_protected_lookup_unified(const void *ip, bool is_ipv6);

/* ==================== Statistics ==================== */

/**
 * Get IPv6 IP lists statistics
 *
 * @param whitelist_count  Output: current whitelist entries
 * @param blacklist_count  Output: current blacklist entries
 * @param protected_count  Output: current protected entries
 * @param whitelist_hits   Output: total whitelist hits
 * @param blacklist_hits   Output: total blacklist hits
 */
void ip_lists_v6_get_stats(uint32_t *whitelist_count, uint32_t *blacklist_count,
                           uint32_t *protected_count,
                           uint64_t *whitelist_hits, uint64_t *blacklist_hits);

/**
 * Print IPv6 IP lists statistics
 */
void ip_lists_v6_print_stats(void);

/* ==================== Persistence ==================== */

/**
 * Save all IPv6 IP lists to JSON file
 *
 * @param path  Path to JSON file (NULL = default path)
 * @return 0 on success, -1 on error
 */
int ip_lists_v6_save(const char *path);

/**
 * Load IPv6 IP lists from JSON file
 *
 * @param path  Path to JSON file (NULL = default path)
 * @return 0 on success, -1 on error
 */
int ip_lists_v6_load(const char *path);

/* ==================== Utility Functions ==================== */

/**
 * Convert IPv6 address to string
 *
 * @param ip6     IPv6 address (16 bytes)
 * @param buf     Output buffer (must be at least 46 bytes)
 * @param buflen  Buffer length
 * @return Pointer to buf on success, NULL on error
 */
const char *ip6_to_str(const uint8_t ip6[16], char *buf, size_t buflen);

/**
 * Parse IPv6 address from string
 *
 * @param str  IPv6 address string (e.g., "2001:db8::1")
 * @param ip6  Output: IPv6 address (16 bytes, network byte order)
 * @return 0 on success, -1 on error
 */
int ip6_from_str(const char *str, uint8_t ip6[16]);

/**
 * Check if IPv6 address is link-local (fe80::/10)
 */
static inline bool ip6_is_link_local(const uint8_t ip6[16])
{
    return (ip6[0] == 0xfe) && ((ip6[1] & 0xc0) == 0x80);
}

/**
 * Check if IPv6 address is multicast (ff00::/8)
 */
static inline bool ip6_is_multicast(const uint8_t ip6[16])
{
    return ip6[0] == 0xff;
}

/**
 * Check if IPv6 address is loopback (::1)
 */
static inline bool ip6_is_loopback(const uint8_t ip6[16])
{
    static const uint8_t loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    return memcmp(ip6, loopback, 16) == 0;
}

/**
 * Check if IPv6 address is unspecified (::)
 */
static inline bool ip6_is_unspecified(const uint8_t ip6[16])
{
    static const uint8_t unspec[16] = {0};
    return memcmp(ip6, unspec, 16) == 0;
}

/**
 * Check if IPv6 protected IP enforcement is enabled.
 * When enabled, traffic to non-protected IPv6 destinations is dropped.
 *
 * @return true if enforcement is active
 */
bool ip_protected_v6_enforcement_enabled(void);

/**
 * Look up protected IPv6 IP and return its profile and hash position.
 * Returns true if IP is protected.
 *
 * @param ip6     IPv6 address (16 bytes, network byte order)
 * @param profile Output: profile pointer (may be NULL if no profile assigned)
 * @param pos     Output: position index for rate counter indexing (-1 if none)
 * @return true if IP is in protected list
 */
bool ip_protected_v6_lookup_profile_pos(const uint8_t ip6[16],
                                         const struct protection_profile **profile,
                                         int32_t *pos);

#ifdef __cplusplus
}
#endif

#endif /* LAYER1_IP_LISTS_V6_H */
