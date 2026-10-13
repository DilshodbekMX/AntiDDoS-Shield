#ifndef GEO_BLOCKING_H
#define GEO_BLOCKING_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @file geo_blocking.h
 * @brief Geo-blocking for Layer 1 DDoS Protection
 *
 * Provides country-based IP filtering using a preloaded lookup table.
 * Country codes use ISO 3166-1 alpha-2 (2-letter codes like "US", "CN", "RU").
 *
 * Two modes:
 * - BLACKLIST: Block traffic from specified countries, allow all others
 * - WHITELIST: Only allow traffic from specified countries, block all others
 */

// Maximum number of countries that can be configured
#define GEO_MAX_COUNTRIES 256

// Country code is stored as 2 bytes (e.g., "US" = 0x5553)
typedef uint16_t country_code_t;

// Geo-blocking modes
enum geo_mode {
    GEO_MODE_DISABLED = 0,
    GEO_MODE_BLACKLIST = 1,  // Block listed countries
    GEO_MODE_WHITELIST = 2   // Only allow listed countries
};

// Statistics
struct geo_stats {
    uint64_t lookups;
    uint64_t cache_hits;
    uint64_t blocked;
    uint64_t allowed;
    uint64_t unknown_country;
};

// Configuration
struct geo_config {
    bool enabled;
    enum geo_mode mode;
    bool log_blocked;
    bool block_unknown;     // Block IPs with unknown country
    uint32_t country_count;
    country_code_t countries[GEO_MAX_COUNTRIES];  // List of countries for mode
};

/**
 * Convert 2-letter country code string to uint16_t
 * @param code  2-letter country code (e.g., "US")
 * @return country_code_t value or 0 if invalid
 */
static inline country_code_t country_str_to_code(const char *code) {
    if (!code || code[0] == '\0' || code[1] == '\0') {
        return 0;
    }
    // Convert to uppercase and pack into uint16_t
    uint8_t c1 = (code[0] >= 'a' && code[0] <= 'z') ? code[0] - 32 : code[0];
    uint8_t c2 = (code[1] >= 'a' && code[1] <= 'z') ? code[1] - 32 : code[1];
    return ((uint16_t)c1 << 8) | c2;
}

/**
 * Convert country_code_t to string
 * @param code  Country code
 * @param out   Output buffer (must be at least 3 bytes)
 */
static inline void country_code_to_str(country_code_t code, char *out) {
    out[0] = (code >> 8) & 0xFF;
    out[1] = code & 0xFF;
    out[2] = '\0';
}

/**
 * Initialize geo-blocking subsystem
 * Must be called before any other geo functions.
 *
 * @param config  Configuration settings
 * @return 0 on success, -1 on error
 */
int geo_blocking_init(const struct geo_config *config);

/**
 * Cleanup geo-blocking subsystem
 */
void geo_blocking_cleanup(void);

/**
 * Check if an IP should be blocked based on geo-location
 *
 * @param ip  IPv4 address in network byte order
 * @return true if packet should be dropped, false if allowed
 */
bool geo_should_block(uint32_t ip);

/**
 * Get the country code for an IP address
 *
 * @param ip  IPv4 address in network byte order
 * @return country_code_t or 0 if unknown
 */
country_code_t geo_get_country(uint32_t ip);

/**
 * Add a country to the filter list
 *
 * @param code  2-letter country code (e.g., "US")
 * @return 0 on success, -1 on error
 */
int geo_add_country(const char *code);

/**
 * Remove a country from the filter list
 *
 * @param code  2-letter country code
 * @return 0 on success, -1 if not found
 */
int geo_remove_country(const char *code);

/**
 * Clear all countries from the filter list
 */
void geo_clear_countries(void);

/**
 * Set geo-blocking mode
 *
 * @param mode  GEO_MODE_BLACKLIST or GEO_MODE_WHITELIST
 */
void geo_set_mode(enum geo_mode mode);

/**
 * Get current mode
 */
enum geo_mode geo_get_mode(void);

/**
 * Enable or disable geo-blocking
 */
void geo_set_enabled(bool enabled);

/**
 * Check if geo-blocking is enabled
 */
bool geo_is_enabled(void);

/**
 * Get geo-blocking statistics
 */
void geo_get_stats(struct geo_stats *stats);

/**
 * Reset statistics
 */
void geo_reset_stats(void);

/**
 * Print statistics
 */
void geo_print_stats(void);

/**
 * Get list of configured countries
 *
 * @param codes   Output array for country codes
 * @param max     Maximum entries to return
 * @return Number of countries in list
 */
uint32_t geo_get_countries(country_code_t *codes, uint32_t max);

/**
 * Reload geo database from file
 * This reloads the IP-to-country mapping data.
 *
 * @param db_path  Path to GeoIP database (MaxMind format)
 * @return 0 on success, -1 on error
 */
int geo_reload_database(const char *db_path);

#endif // GEO_BLOCKING_H
