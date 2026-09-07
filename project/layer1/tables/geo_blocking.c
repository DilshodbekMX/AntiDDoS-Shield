#include "geo_blocking.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <string.h>
#include <stdio.h>

#define RTE_LOGTYPE_GEO RTE_LOGTYPE_USER4

/**
 * Geo-blocking implementation using IP range tables.
 *
 * For high-performance lookups, we use a two-level approach:
 * 1. A hash table cache for recently looked-up IPs
 * 2. A sorted array of IP ranges for full lookups
 *
 * The IP range data is loaded from a simplified CSV format or via API.
 * Format: start_ip,end_ip,country_code
 *
 * For production use with MaxMind, you would add libmaxminddb integration.
 */

// ==================== IP Range Entry ====================

struct ip_range {
    uint32_t start_ip;    // Network byte order
    uint32_t end_ip;      // Network byte order
    country_code_t country;
    uint16_t pad;
};

// ==================== Cache Entry ====================

struct geo_cache_entry {
    uint32_t ip;          // Network byte order
    country_code_t country;
    uint16_t pad;
};

// ==================== Global State ====================

#define GEO_CACHE_SIZE 65536
#define GEO_MAX_RANGES 1000000

static bool geo_initialized = false;
static struct geo_config geo_cfg;
static rte_spinlock_t geo_lock = RTE_SPINLOCK_INITIALIZER;

// IP range database (sorted by start_ip for binary search)
static struct ip_range *ip_ranges = NULL;
static uint32_t num_ranges = 0;

// Fast lookup cache (direct-mapped by IP hash)
static struct geo_cache_entry *geo_cache = NULL;

// Country filter set (bitmap for O(1) lookup)
static uint8_t country_filter[65536 / 8];  // Bitmap for all possible country codes

// Statistics (per-lcore to avoid atomics)
struct geo_lcore_stats {
    uint64_t lookups;
    uint64_t cache_hits;
    uint64_t blocked;
    uint64_t allowed;
    uint64_t unknown_country;
} __rte_cache_aligned;

static struct geo_lcore_stats lcore_geo_stats[RTE_MAX_LCORE];

// ==================== Country Filter Bitmap ====================

static inline void country_filter_set(country_code_t code) {
    uint32_t idx = code / 8;
    uint8_t bit = 1 << (code % 8);
    country_filter[idx] |= bit;
}

static inline void country_filter_clear(country_code_t code) {
    uint32_t idx = code / 8;
    uint8_t bit = 1 << (code % 8);
    country_filter[idx] &= ~bit;
}

static inline bool country_filter_test(country_code_t code) {
    uint32_t idx = code / 8;
    uint8_t bit = 1 << (code % 8);
    return (country_filter[idx] & bit) != 0;
}

// ==================== Binary Search for IP Range ====================

static country_code_t lookup_ip_range(uint32_t ip) {
    if (num_ranges == 0 || ip_ranges == NULL) {
        return 0;
    }

    // Convert to host byte order for comparison
    uint32_t host_ip = rte_be_to_cpu_32(ip);

    // Binary search
    uint32_t left = 0;
    uint32_t right = num_ranges;

    while (left < right) {
        uint32_t mid = left + (right - left) / 2;
        uint32_t range_start = rte_be_to_cpu_32(ip_ranges[mid].start_ip);
        uint32_t range_end = rte_be_to_cpu_32(ip_ranges[mid].end_ip);

        if (host_ip < range_start) {
            right = mid;
        } else if (host_ip > range_end) {
            left = mid + 1;
        } else {
            // Found matching range
            return ip_ranges[mid].country;
        }
    }

    return 0;  // Not found
}

// ==================== Cache Operations ====================

static inline uint32_t cache_index(uint32_t ip) {
    return rte_jhash_1word(ip, 0) & (GEO_CACHE_SIZE - 1);
}

static inline country_code_t cache_lookup(uint32_t ip) {
    if (!geo_cache) return 0;

    uint32_t idx = cache_index(ip);
    if (geo_cache[idx].ip == ip) {
        return geo_cache[idx].country;
    }
    return 0;
}

static inline void cache_insert(uint32_t ip, country_code_t country) {
    if (!geo_cache) return;

    uint32_t idx = cache_index(ip);
    geo_cache[idx].ip = ip;
    geo_cache[idx].country = country;
}

// ==================== Public API ====================

int geo_blocking_init(const struct geo_config *config) {
    if (geo_initialized) {
        RTE_LOG(WARNING, GEO, "Geo-blocking already initialized\n");
        return 0;
    }

    rte_spinlock_lock(&geo_lock);

    // Copy configuration
    memcpy(&geo_cfg, config, sizeof(geo_cfg));

    // Initialize country filter bitmap
    memset(country_filter, 0, sizeof(country_filter));
    for (uint32_t i = 0; i < config->country_count && i < GEO_MAX_COUNTRIES; i++) {
        country_filter_set(config->countries[i]);
    }

    // Allocate cache
    geo_cache = rte_zmalloc("geo_cache",
                            GEO_CACHE_SIZE * sizeof(struct geo_cache_entry),
                            RTE_CACHE_LINE_SIZE);
    if (!geo_cache) {
        RTE_LOG(ERR, GEO, "Failed to allocate geo cache\n");
        rte_spinlock_unlock(&geo_lock);
        return -1;
    }

    // Allocate IP range storage (empty initially, populated via API or file)
    ip_ranges = rte_zmalloc("geo_ranges",
                            GEO_MAX_RANGES * sizeof(struct ip_range),
                            RTE_CACHE_LINE_SIZE);
    if (!ip_ranges) {
        RTE_LOG(ERR, GEO, "Failed to allocate geo ranges\n");
        rte_free(geo_cache);
        geo_cache = NULL;
        rte_spinlock_unlock(&geo_lock);
        return -1;
    }
    num_ranges = 0;

    // Initialize per-lcore stats
    memset(lcore_geo_stats, 0, sizeof(lcore_geo_stats));

    geo_initialized = true;

    RTE_LOG(INFO, GEO, "Geo-blocking initialized (mode=%s, countries=%u)\n",
            geo_cfg.mode == GEO_MODE_BLACKLIST ? "blacklist" :
            (geo_cfg.mode == GEO_MODE_WHITELIST ? "whitelist" : "disabled"),
            geo_cfg.country_count);

    rte_spinlock_unlock(&geo_lock);
    return 0;
}

void geo_blocking_cleanup(void) {
    if (!geo_initialized) return;

    rte_spinlock_lock(&geo_lock);

    if (geo_cache) {
        rte_free(geo_cache);
        geo_cache = NULL;
    }

    if (ip_ranges) {
        rte_free(ip_ranges);
        ip_ranges = NULL;
    }
    num_ranges = 0;

    geo_initialized = false;

    RTE_LOG(INFO, GEO, "Geo-blocking cleanup complete\n");

    rte_spinlock_unlock(&geo_lock);
}

country_code_t geo_get_country(uint32_t ip) {
    if (!geo_initialized) return 0;

    unsigned lcore_id = rte_lcore_id();
    if (lcore_id < RTE_MAX_LCORE) {
        lcore_geo_stats[lcore_id].lookups++;
    }

    // Check cache first
    country_code_t country = cache_lookup(ip);
    if (country != 0) {
        if (lcore_id < RTE_MAX_LCORE) {
            lcore_geo_stats[lcore_id].cache_hits++;
        }
        return country;
    }

    // Full lookup
    country = lookup_ip_range(ip);

    // Update cache
    if (country != 0) {
        cache_insert(ip, country);
    }

    return country;
}

bool geo_should_block(uint32_t ip) {
    if (!geo_initialized || !geo_cfg.enabled) {
        return false;
    }

    unsigned lcore_id = rte_lcore_id();
    country_code_t country = geo_get_country(ip);

    if (country == 0) {
        // Unknown country
        if (lcore_id < RTE_MAX_LCORE) {
            lcore_geo_stats[lcore_id].unknown_country++;
        }
        // In whitelist mode, unknown = block; in blacklist mode, unknown = allow
        bool block = (geo_cfg.mode == GEO_MODE_WHITELIST);
        if (block && lcore_id < RTE_MAX_LCORE) {
            lcore_geo_stats[lcore_id].blocked++;
        } else if (!block && lcore_id < RTE_MAX_LCORE) {
            lcore_geo_stats[lcore_id].allowed++;
        }
        return block;
    }

    bool in_list = country_filter_test(country);
    bool block = false;

    switch (geo_cfg.mode) {
        case GEO_MODE_BLACKLIST:
            // Block if country is in the list
            block = in_list;
            break;
        case GEO_MODE_WHITELIST:
            // Block if country is NOT in the list
            block = !in_list;
            break;
        default:
            block = false;
    }

    if (lcore_id < RTE_MAX_LCORE) {
        if (block) {
            lcore_geo_stats[lcore_id].blocked++;
        } else {
            lcore_geo_stats[lcore_id].allowed++;
        }
    }

    return block;
}

int geo_add_country(const char *code) {
    if (!geo_initialized) return -1;

    country_code_t cc = country_str_to_code(code);
    if (cc == 0) return -1;

    rte_spinlock_lock(&geo_lock);

    // Check if already in list
    if (!country_filter_test(cc)) {
        if (geo_cfg.country_count < GEO_MAX_COUNTRIES) {
            geo_cfg.countries[geo_cfg.country_count++] = cc;
            country_filter_set(cc);
            RTE_LOG(INFO, GEO, "Added country %s to geo filter\n", code);
        }
    }

    rte_spinlock_unlock(&geo_lock);
    return 0;
}

int geo_remove_country(const char *code) {
    if (!geo_initialized) return -1;

    country_code_t cc = country_str_to_code(code);
    if (cc == 0) return -1;

    rte_spinlock_lock(&geo_lock);

    country_filter_clear(cc);

    // Remove from config array
    for (uint32_t i = 0; i < geo_cfg.country_count; i++) {
        if (geo_cfg.countries[i] == cc) {
            // Shift remaining countries
            for (uint32_t j = i; j < geo_cfg.country_count - 1; j++) {
                geo_cfg.countries[j] = geo_cfg.countries[j + 1];
            }
            geo_cfg.country_count--;
            RTE_LOG(INFO, GEO, "Removed country %s from geo filter\n", code);
            rte_spinlock_unlock(&geo_lock);
            return 0;
        }
    }

    rte_spinlock_unlock(&geo_lock);
    return -1;
}

void geo_clear_countries(void) {
    if (!geo_initialized) return;

    rte_spinlock_lock(&geo_lock);

    memset(country_filter, 0, sizeof(country_filter));
    geo_cfg.country_count = 0;

    RTE_LOG(INFO, GEO, "Cleared all countries from geo filter\n");

    rte_spinlock_unlock(&geo_lock);
}

void geo_set_mode(enum geo_mode mode) {
    if (!geo_initialized) return;

    rte_spinlock_lock(&geo_lock);
    geo_cfg.mode = mode;
    RTE_LOG(INFO, GEO, "Geo mode set to %s\n",
            mode == GEO_MODE_BLACKLIST ? "blacklist" :
            (mode == GEO_MODE_WHITELIST ? "whitelist" : "disabled"));
    rte_spinlock_unlock(&geo_lock);
}

enum geo_mode geo_get_mode(void) {
    return geo_cfg.mode;
}

void geo_set_enabled(bool enabled) {
    if (!geo_initialized) return;

    rte_spinlock_lock(&geo_lock);
    geo_cfg.enabled = enabled;
    RTE_LOG(INFO, GEO, "Geo-blocking %s\n", enabled ? "enabled" : "disabled");
    rte_spinlock_unlock(&geo_lock);
}

bool geo_is_enabled(void) {
    return geo_initialized && geo_cfg.enabled;
}

void geo_get_stats(struct geo_stats *stats) {
    if (!stats) return;

    memset(stats, 0, sizeof(*stats));

    // Aggregate per-lcore stats
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        stats->lookups += lcore_geo_stats[lcore_id].lookups;
        stats->cache_hits += lcore_geo_stats[lcore_id].cache_hits;
        stats->blocked += lcore_geo_stats[lcore_id].blocked;
        stats->allowed += lcore_geo_stats[lcore_id].allowed;
        stats->unknown_country += lcore_geo_stats[lcore_id].unknown_country;
    }
}

void geo_reset_stats(void) {
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        memset(&lcore_geo_stats[lcore_id], 0, sizeof(lcore_geo_stats[0]));
    }
}

void geo_print_stats(void) {
    struct geo_stats stats;
    geo_get_stats(&stats);

    printf("\n");
    printf("Geo-Blocking Statistics:\n");
    printf("  Enabled: %s\n", geo_cfg.enabled ? "yes" : "no");
    printf("  Mode: %s\n",
           geo_cfg.mode == GEO_MODE_BLACKLIST ? "blacklist" :
           (geo_cfg.mode == GEO_MODE_WHITELIST ? "whitelist" : "disabled"));
    printf("  Countries configured: %u\n", geo_cfg.country_count);
    printf("  IP ranges loaded: %u\n", num_ranges);
    printf("  Lookups: %lu\n", stats.lookups);
    printf("  Cache hits: %lu (%.1f%%)\n",
           stats.cache_hits,
           stats.lookups > 0 ? (100.0 * stats.cache_hits / stats.lookups) : 0);
    printf("  Blocked: %lu\n", stats.blocked);
    printf("  Allowed: %lu\n", stats.allowed);
    printf("  Unknown country: %lu\n", stats.unknown_country);
}

uint32_t geo_get_countries(country_code_t *codes, uint32_t max) {
    if (!geo_initialized || !codes) return 0;

    rte_spinlock_lock(&geo_lock);
    uint32_t count = (geo_cfg.country_count < max) ? geo_cfg.country_count : max;
    memcpy(codes, geo_cfg.countries, count * sizeof(country_code_t));
    rte_spinlock_unlock(&geo_lock);

    return count;
}

// ==================== IP Range Loading ====================

/**
 * Add an IP range to the database.
 * This is called by the backend or during database loading.
 *
 * @param start_ip  Start IP in network byte order
 * @param end_ip    End IP in network byte order
 * @param country   Country code
 * @return 0 on success, -1 on error
 */
int geo_add_ip_range(uint32_t start_ip, uint32_t end_ip, country_code_t country) {
    if (!geo_initialized) return -1;

    rte_spinlock_lock(&geo_lock);

    if (num_ranges >= GEO_MAX_RANGES) {
        RTE_LOG(WARNING, GEO, "IP range database full (%u entries)\n", num_ranges);
        rte_spinlock_unlock(&geo_lock);
        return -1;
    }

    // Insert in sorted order (by start_ip)
    uint32_t host_start = rte_be_to_cpu_32(start_ip);
    uint32_t insert_pos = num_ranges;

    // Find insertion point
    for (uint32_t i = 0; i < num_ranges; i++) {
        if (host_start < rte_be_to_cpu_32(ip_ranges[i].start_ip)) {
            insert_pos = i;
            break;
        }
    }

    // Shift elements to make room
    if (insert_pos < num_ranges) {
        memmove(&ip_ranges[insert_pos + 1],
                &ip_ranges[insert_pos],
                (num_ranges - insert_pos) * sizeof(struct ip_range));
    }

    // Insert new range
    ip_ranges[insert_pos].start_ip = start_ip;
    ip_ranges[insert_pos].end_ip = end_ip;
    ip_ranges[insert_pos].country = country;
    num_ranges++;

    rte_spinlock_unlock(&geo_lock);
    return 0;
}

/**
 * Clear all IP ranges
 */
void geo_clear_ip_ranges(void) {
    if (!geo_initialized) return;

    rte_spinlock_lock(&geo_lock);
    num_ranges = 0;
    // Also clear cache since it's now invalid
    if (geo_cache) {
        memset(geo_cache, 0, GEO_CACHE_SIZE * sizeof(struct geo_cache_entry));
    }
    rte_spinlock_unlock(&geo_lock);

    RTE_LOG(INFO, GEO, "Cleared all IP ranges\n");
}

/**
 * Load IP ranges from a CSV file.
 * Format: start_ip,end_ip,country_code
 * Example: 1.0.0.0,1.0.0.255,AU
 *
 * @param path  Path to CSV file
 * @return 0 on success, -1 on error
 */
int geo_load_ranges_csv(const char *path) {
    if (!geo_initialized || !path) return -1;

    FILE *f = fopen(path, "r");
    if (!f) {
        RTE_LOG(ERR, GEO, "Failed to open geo ranges file: %s\n", path);
        return -1;
    }

    // Clear existing ranges
    geo_clear_ip_ranges();

    char line[256];
    uint32_t loaded = 0;
    uint32_t errors = 0;

    while (fgets(line, sizeof(line), f)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;

        char start_str[32], end_str[32], country_str[8];
        if (sscanf(line, "%31[^,],%31[^,],%7s", start_str, end_str, country_str) != 3) {
            errors++;
            continue;
        }

        // Parse IPs
        uint32_t a, b, c, d;
        uint32_t start_ip, end_ip;

        if (sscanf(start_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
            errors++;
            continue;
        }
        start_ip = rte_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);

        if (sscanf(end_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
            errors++;
            continue;
        }
        end_ip = rte_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);

        country_code_t country = country_str_to_code(country_str);
        if (country == 0) {
            errors++;
            continue;
        }

        if (geo_add_ip_range(start_ip, end_ip, country) == 0) {
            loaded++;
        }

        if (loaded >= GEO_MAX_RANGES) {
            RTE_LOG(WARNING, GEO, "Reached max IP ranges limit (%u)\n", GEO_MAX_RANGES);
            break;
        }
    }

    fclose(f);

    RTE_LOG(INFO, GEO, "Loaded %u IP ranges from %s (%u errors)\n", loaded, path, errors);
    return 0;
}

int geo_reload_database(const char *db_path) {
    if (!db_path) return -1;

    // For now, we support CSV format
    // In production, you would add MaxMind MMDB support here
    return geo_load_ranges_csv(db_path);
}

/**
 * Get number of loaded IP ranges
 */
uint32_t geo_get_range_count(void) {
    return num_ranges;
}
