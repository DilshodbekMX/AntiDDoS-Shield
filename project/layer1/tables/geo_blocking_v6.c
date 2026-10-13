/**
 * @file geo_blocking_v6.c
 * @brief IPv6 Geo-blocking implementation
 *
 * Uses a simplified trie structure for IPv6 prefix-to-country mapping.
 * For production, integrate with MaxMind GeoIP2 database.
 */

#include "geo_blocking_v6.h"
#include "geo_blocking.h"

#include <string.h>
#include <arpa/inet.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_lpm6.h>
#include <rte_ip6.h>

#define RTE_LOGTYPE_GEO_V6 RTE_LOGTYPE_USER5

/* Configuration and state */
static struct geo_config g_config_v6;
static bool g_initialized_v6 = false;

/* LPM6 table for IPv6 prefix-to-country mapping */
static struct rte_lpm6 *g_geo_lpm6 = NULL;

/* Country code lookup table (next-hop value -> country code) */
#define GEO_MAX_PREFIXES 65536
static country_code_t g_country_map[GEO_MAX_PREFIXES];
static uint32_t g_next_country_idx = 1;  /* 0 = unknown */

/* IPv6 Statistics */
static struct geo_stats g_stats_v6;

/* LPM6 configuration */
#define GEO_LPM6_MAX_RULES  (1 << 16)  /* 64K rules */
#define GEO_LPM6_TBL8S      (1 << 12)  /* 4K TBL8s */

int geo_blocking_v6_init(const struct geo_config *config)
{
    if (g_initialized_v6) {
        RTE_LOG(WARNING, GEO_V6, "Already initialized\n");
        return 0;
    }

    if (config) {
        g_config_v6 = *config;
    } else {
        memset(&g_config_v6, 0, sizeof(g_config_v6));
    }

    /* Create LPM6 table */
    struct rte_lpm6_config lpm6_config = {
        .max_rules = GEO_LPM6_MAX_RULES,
        .number_tbl8s = GEO_LPM6_TBL8S,
        .flags = 0,
    };

    g_geo_lpm6 = rte_lpm6_create("geo_lpm6", rte_socket_id(), &lpm6_config);
    if (!g_geo_lpm6) {
        RTE_LOG(ERR, GEO_V6, "Failed to create LPM6 table\n");
        return -1;
    }

    /* Initialize country map */
    memset(g_country_map, 0, sizeof(g_country_map));
    g_next_country_idx = 1;

    /* Reset stats */
    memset(&g_stats_v6, 0, sizeof(g_stats_v6));

    g_initialized_v6 = true;
    RTE_LOG(INFO, GEO_V6, "IPv6 geo-blocking initialized\n");

    return 0;
}

void geo_blocking_v6_cleanup(void)
{
    if (g_geo_lpm6) {
        rte_lpm6_free(g_geo_lpm6);
        g_geo_lpm6 = NULL;
    }

    g_initialized_v6 = false;
    RTE_LOG(INFO, GEO_V6, "IPv6 geo-blocking cleaned up\n");
}

/**
 * Get or allocate a next-hop index for a country code
 */
static uint32_t get_country_index(country_code_t code)
{
    /* Search existing mappings */
    for (uint32_t i = 1; i < g_next_country_idx; i++) {
        if (g_country_map[i] == code) {
            return i;
        }
    }

    /* Allocate new index */
    if (g_next_country_idx >= GEO_MAX_PREFIXES) {
        return 0;  /* Table full */
    }

    uint32_t idx = g_next_country_idx++;
    g_country_map[idx] = code;
    return idx;
}

country_code_t geo_get_country_v6(const uint8_t ip6[16])
{
    if (!g_geo_lpm6) {
        __atomic_add_fetch(&g_stats_v6.unknown_country, 1, __ATOMIC_RELAXED);
        return 0;
    }

    __atomic_add_fetch(&g_stats_v6.lookups, 1, __ATOMIC_RELAXED);

    uint32_t next_hop;
    /* Cast uint8_t[16] to struct rte_ipv6_addr* for newer DPDK API */
    int ret = rte_lpm6_lookup(g_geo_lpm6,
                               (const struct rte_ipv6_addr *)ip6, &next_hop);

    if (ret == 0 && next_hop > 0 && next_hop < GEO_MAX_PREFIXES) {
        __atomic_add_fetch(&g_stats_v6.cache_hits, 1, __ATOMIC_RELAXED);
        return g_country_map[next_hop];
    }

    __atomic_add_fetch(&g_stats_v6.unknown_country, 1, __ATOMIC_RELAXED);
    return 0;
}

/**
 * Check if country code is in the configured list
 */
static bool is_country_in_list(country_code_t code)
{
    for (uint32_t i = 0; i < g_config_v6.country_count; i++) {
        if (g_config_v6.countries[i] == code) {
            return true;
        }
    }
    return false;
}

bool geo_should_block_v6(const uint8_t ip6[16])
{
    if (!g_config_v6.enabled || g_config_v6.mode == GEO_MODE_DISABLED) {
        return false;
    }

    country_code_t code = geo_get_country_v6(ip6);

    bool in_list = is_country_in_list(code);
    bool should_block = false;

    switch (g_config_v6.mode) {
    case GEO_MODE_BLACKLIST:
        /* Block if country is in the list */
        should_block = in_list;
        break;

    case GEO_MODE_WHITELIST:
        /* Block if country is NOT in the list (and is known) */
        should_block = (code != 0) && !in_list;
        break;

    default:
        should_block = false;
        break;
    }

    if (should_block) {
        __atomic_add_fetch(&g_stats_v6.blocked, 1, __ATOMIC_RELAXED);
    } else {
        __atomic_add_fetch(&g_stats_v6.allowed, 1, __ATOMIC_RELAXED);
    }

    return should_block;
}

/**
 * Add a single IPv6 prefix to the geo-blocking database.
 *
 * @param ip6_prefix  IPv6 prefix (network byte order, 16 bytes)
 * @param depth       Prefix length (1-128)
 * @param country     2-letter country code (e.g., "US", "CN", "RU")
 * @return 0 on success, -1 on error
 */
int geo_add_prefix_v6(const uint8_t ip6_prefix[16], uint8_t depth, const char *country)
{
    if (!g_geo_lpm6 || !country || depth == 0 || depth > 128) {
        return -1;
    }

    country_code_t code = country_str_to_code(country);
    if (code == 0) {
        RTE_LOG(WARNING, GEO_V6, "Invalid country code: %s\n", country);
        return -1;
    }

    uint32_t idx = get_country_index(code);
    if (idx == 0) {
        RTE_LOG(ERR, GEO_V6, "Country map full\n");
        return -1;
    }

    int ret = rte_lpm6_add(g_geo_lpm6,
                            (const struct rte_ipv6_addr *)ip6_prefix,
                            depth, idx);
    if (ret < 0) {
        RTE_LOG(WARNING, GEO_V6, "Failed to add IPv6 prefix (depth=%u)\n", depth);
        return -1;
    }

    return 0;
}

/**
 * Add an IPv6 prefix using string notation.
 *
 * @param cidr_str  CIDR notation string (e.g., "2001:db8::/32")
 * @param country   2-letter country code
 * @return 0 on success, -1 on error
 */
int geo_add_prefix_v6_str(const char *cidr_str, const char *country)
{
    if (!cidr_str || !country) {
        return -1;
    }

    char ip_part[INET6_ADDRSTRLEN];
    strncpy(ip_part, cidr_str, sizeof(ip_part) - 1);
    ip_part[sizeof(ip_part) - 1] = '\0';

    char *slash = strchr(ip_part, '/');
    if (!slash) {
        return -1;  /* No prefix length */
    }

    *slash = '\0';
    int depth = atoi(slash + 1);

    if (depth <= 0 || depth > 128) {
        return -1;
    }

    uint8_t ip6[16];
    if (inet_pton(AF_INET6, ip_part, ip6) != 1) {
        return -1;
    }

    return geo_add_prefix_v6(ip6, (uint8_t)depth, country);
}

/**
 * Load IPv6 geo database from CSV file.
 *
 * CSV format: ipv6_prefix/depth,country_code
 * Example: 2607:f8b0::/32,US
 *
 * This format can be generated from MaxMind GeoLite2 Country database.
 * To convert MaxMind MMDB to CSV:
 *   mmdbctl export GeoLite2-Country.mmdb | grep -E '^[0-9a-f:]+/' > geo_ipv6.csv
 *
 * @param path  Path to CSV file
 * @return Number of entries loaded, or -1 on error
 */
static int geo_load_csv_v6(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        RTE_LOG(WARNING, GEO_V6, "Cannot open geo CSV: %s\n", path);
        return -1;
    }

    char line[256];
    uint32_t loaded = 0;
    uint32_t errors = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

        /* Remove newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        nl = strchr(line, '\r');
        if (nl) *nl = '\0';

        /* Parse: prefix/depth,country */
        char *comma = strchr(line, ',');
        if (!comma) {
            errors++;
            continue;
        }

        *comma = '\0';
        char *cidr = line;
        char *country = comma + 1;

        /* Trim whitespace from country code */
        while (*country == ' ') country++;
        char *end = country + strlen(country) - 1;
        while (end > country && *end == ' ') {
            *end = '\0';
            end--;
        }

        /* Skip IPv4 entries (no colons) */
        if (!strchr(cidr, ':')) {
            continue;
        }

        if (geo_add_prefix_v6_str(cidr, country) == 0) {
            loaded++;
        } else {
            errors++;
        }
    }

    fclose(fp);

    RTE_LOG(INFO, GEO_V6, "Loaded %u IPv6 geo entries from %s (%u errors)\n",
            loaded, path, errors);

    return (int)loaded;
}

/**
 * Add well-known IPv6 prefixes for major providers.
 * Used as fallback when no database file is available.
 */
static void geo_add_wellknown_prefixes_v6(void)
{
    /* US providers */
    geo_add_prefix_v6_str("2607:f8b0::/32", "US");   /* Google */
    geo_add_prefix_v6_str("2606:4700::/32", "US");   /* Cloudflare */
    geo_add_prefix_v6_str("2600:1f00::/24", "US");   /* AWS */
    geo_add_prefix_v6_str("2600:9000::/28", "US");   /* AWS CloudFront */
    geo_add_prefix_v6_str("2620:fe::/48", "US");     /* Facebook */
    geo_add_prefix_v6_str("2a03:2880::/29", "US");   /* Facebook */
    geo_add_prefix_v6_str("2620:1ec::/36", "US");    /* Akamai */

    /* CN (China) */
    geo_add_prefix_v6_str("240e::/20", "CN");        /* CHINANET */
    geo_add_prefix_v6_str("2408::/22", "CN");        /* UNICOM */
    geo_add_prefix_v6_str("2409::/22", "CN");        /* CMCC */

    /* RU (Russia) */
    geo_add_prefix_v6_str("2a00:5880::/29", "RU");   /* Rostelecom */
    geo_add_prefix_v6_str("2a02:6b8::/32", "RU");    /* Yandex */

    /* EU */
    geo_add_prefix_v6_str("2a00:1450::/32", "US");   /* Google EU */
    geo_add_prefix_v6_str("2a01:4f8::/32", "DE");    /* Hetzner */
    geo_add_prefix_v6_str("2a01:7e00::/32", "DE");   /* Hetzner */
    geo_add_prefix_v6_str("2001:41d0::/32", "FR");   /* OVH */

    /* Other */
    geo_add_prefix_v6_str("2400:cb00::/32", "US");   /* Cloudflare APAC */
    geo_add_prefix_v6_str("2404:6800::/32", "AU");   /* Google APAC */
    geo_add_prefix_v6_str("2a0d:2406::/32", "NL");   /* BuyVM */

    RTE_LOG(INFO, GEO_V6, "Added well-known IPv6 geo prefixes\n");
}

int geo_reload_database_v6(const char *db_path)
{
    if (!g_geo_lpm6) {
        RTE_LOG(ERR, GEO_V6, "LPM6 not initialized\n");
        return -1;
    }

    /* Clear existing entries */
    rte_lpm6_delete_all(g_geo_lpm6);
    memset(g_country_map, 0, sizeof(g_country_map));
    g_next_country_idx = 1;

    RTE_LOG(INFO, GEO_V6, "IPv6 geo database reload requested: %s\n",
            db_path ? db_path : "(default)");

    int loaded = 0;

    /* Try to load CSV database */
    if (db_path && db_path[0] != '\0') {
        loaded = geo_load_csv_v6(db_path);
        if (loaded < 0) {
            RTE_LOG(WARNING, GEO_V6, "Failed to load CSV, using fallback prefixes\n");
        }
    }

    /* If no entries loaded, add well-known prefixes as fallback */
    if (loaded <= 0) {
        geo_add_wellknown_prefixes_v6();
        loaded = 0;  /* Reset to indicate fallback was used */
    }

    return loaded;
}

/* ==================== Dual-Stack API ==================== */

bool geo_should_block_unified(const void *ip, bool is_ipv6)
{
    if (is_ipv6) {
        return geo_should_block_v6((const uint8_t *)ip);
    } else {
        return geo_should_block(*(const uint32_t *)ip);
    }
}

country_code_t geo_get_country_unified(const void *ip, bool is_ipv6)
{
    if (is_ipv6) {
        return geo_get_country_v6((const uint8_t *)ip);
    } else {
        return geo_get_country(*(const uint32_t *)ip);
    }
}

/* ==================== Statistics ==================== */

void geo_get_stats_v6(struct geo_stats *stats)
{
    if (stats) {
        rte_memcpy(stats, &g_stats_v6, sizeof(*stats));
    }
}

void geo_reset_stats_v6(void)
{
    memset(&g_stats_v6, 0, sizeof(g_stats_v6));
}

void geo_print_stats_all(void)
{
    struct geo_stats stats_v4;
    geo_get_stats(&stats_v4);

    RTE_LOG(INFO, GEO_V6,
            "Geo Stats (IPv4): lookups=%"PRIu64" blocked=%"PRIu64" allowed=%"PRIu64"\n",
            stats_v4.lookups, stats_v4.blocked, stats_v4.allowed);

    RTE_LOG(INFO, GEO_V6,
            "Geo Stats (IPv6): lookups=%"PRIu64" blocked=%"PRIu64" allowed=%"PRIu64"\n",
            g_stats_v6.lookups, g_stats_v6.blocked, g_stats_v6.allowed);
}

/* ==================== Utility Functions ==================== */

bool geo_is_country_v6(const uint8_t ip6[16], const char *code)
{
    country_code_t expected = country_str_to_code(code);
    country_code_t actual = geo_get_country_v6(ip6);
    return (actual != 0) && (actual == expected);
}

bool geo_is_any_country_v6(const uint8_t ip6[16],
                           const country_code_t *codes,
                           uint32_t count)
{
    country_code_t actual = geo_get_country_v6(ip6);
    if (actual == 0) {
        return false;
    }

    for (uint32_t i = 0; i < count; i++) {
        if (codes[i] == actual) {
            return true;
        }
    }

    return false;
}
