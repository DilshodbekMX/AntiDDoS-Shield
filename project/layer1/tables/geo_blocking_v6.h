/**
 * @file geo_blocking_v6.h
 * @brief IPv6 Geo-blocking for Layer 1 DDoS Protection
 *
 * Extension of geo_blocking.h for IPv6 support.
 * Uses MaxMind GeoIP2 format for IPv6 lookups.
 */

#ifndef GEO_BLOCKING_V6_H
#define GEO_BLOCKING_V6_H

#include <stdint.h>
#include <stdbool.h>
#include "geo_blocking.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== IPv6 API ==================== */

/**
 * Initialize IPv6 geo-blocking subsystem
 *
 * @param config  Configuration settings (same as IPv4)
 * @return 0 on success, -1 on error
 */
int geo_blocking_v6_init(const struct geo_config *config);

/**
 * Cleanup IPv6 geo-blocking subsystem
 */
void geo_blocking_v6_cleanup(void);

/**
 * Check if an IPv6 address should be blocked based on geo-location
 *
 * @param ip6  IPv6 address (16 bytes, network byte order)
 * @return true if packet should be dropped, false if allowed
 */
bool geo_should_block_v6(const uint8_t ip6[16]);

/**
 * Get the country code for an IPv6 address
 *
 * @param ip6  IPv6 address (16 bytes, network byte order)
 * @return country_code_t or 0 if unknown
 */
country_code_t geo_get_country_v6(const uint8_t ip6[16]);

/**
 * Reload IPv6 geo database from file
 *
 * Supports CSV format: ipv6_prefix/depth,country_code
 * Example: 2607:f8b0::/32,US
 *
 * To generate from MaxMind GeoLite2:
 *   mmdbctl export GeoLite2-Country.mmdb | grep -E '^[0-9a-f:]+/' > geo_ipv6.csv
 *
 * @param db_path  Path to CSV database (NULL for built-in fallback)
 * @return Number of entries loaded, or -1 on error
 */
int geo_reload_database_v6(const char *db_path);

/**
 * Add a single IPv6 prefix to the geo database
 *
 * @param ip6_prefix  IPv6 prefix (16 bytes, network byte order)
 * @param depth       Prefix length (1-128)
 * @param country     2-letter country code (e.g., "US")
 * @return 0 on success, -1 on error
 */
int geo_add_prefix_v6(const uint8_t ip6_prefix[16], uint8_t depth, const char *country);

/**
 * Add an IPv6 prefix using CIDR string notation
 *
 * @param cidr_str  CIDR string (e.g., "2001:db8::/32")
 * @param country   2-letter country code
 * @return 0 on success, -1 on error
 */
int geo_add_prefix_v6_str(const char *cidr_str, const char *country);

/* ==================== Dual-Stack API ==================== */

/**
 * Check if an IP (v4 or v6) should be blocked based on geo-location
 *
 * @param ip       Pointer to IP address
 * @param is_ipv6  true for IPv6, false for IPv4
 * @return true if packet should be dropped, false if allowed
 */
bool geo_should_block_unified(const void *ip, bool is_ipv6);

/**
 * Get the country code for an IP (v4 or v6)
 *
 * @param ip       Pointer to IP address
 * @param is_ipv6  true for IPv6, false for IPv4
 * @return country_code_t or 0 if unknown
 */
country_code_t geo_get_country_unified(const void *ip, bool is_ipv6);

/* ==================== IPv6 Statistics ==================== */

/**
 * Get IPv6 geo-blocking statistics
 */
void geo_get_stats_v6(struct geo_stats *stats);

/**
 * Reset IPv6 statistics
 */
void geo_reset_stats_v6(void);

/**
 * Print combined IPv4+IPv6 statistics
 */
void geo_print_stats_all(void);

/* ==================== IPv6 Utilities ==================== */

/**
 * Check if IPv6 address is in a specific country
 *
 * @param ip6   IPv6 address
 * @param code  Country code string (e.g., "US")
 * @return true if IP is in specified country
 */
bool geo_is_country_v6(const uint8_t ip6[16], const char *code);

/**
 * Check if IPv6 address is from a list of countries
 *
 * @param ip6     IPv6 address
 * @param codes   Array of country codes
 * @param count   Number of country codes
 * @return true if IP is from any of the specified countries
 */
bool geo_is_any_country_v6(const uint8_t ip6[16],
                           const country_code_t *codes,
                           uint32_t count);

#ifdef __cplusplus
}
#endif

#endif /* GEO_BLOCKING_V6_H */
