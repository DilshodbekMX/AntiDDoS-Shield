/**
 * @file ip_lists_v6.c
 * @brief IPv6 whitelist and blacklist implementation using DPDK LPM6
 *
 * Uses rte_hash with 128-bit keys for exact IPv6 matching and
 * rte_lpm6 for IPv6 CIDR prefix matching.
 */

#include "ip_lists_v6.h"
#include "ip_lists.h"  /* For IPv4 unified lookups */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <rte_hash.h>
#include <rte_lpm6.h>
#include <rte_ip6.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>

#define RTE_LOGTYPE_IP_LISTS_V6 RTE_LOGTYPE_USER3

/* Hash tables for exact match */
static struct rte_hash *g_whitelist_v6 = NULL;
static struct rte_hash *g_blacklist_v6 = NULL;
static struct rte_hash *g_protected_v6 = NULL;

/* LPM6 for CIDR whitelist */
static struct rte_lpm6 *g_whitelist_lpm6 = NULL;

/* Configuration */
static struct ip_lists_v6_config g_config;
static bool g_initialized = false;

/* Statistics */
static uint64_t g_whitelist_v6_hits = 0;
static uint64_t g_blacklist_v6_hits = 0;
static uint64_t g_whitelist_cidr_v6_hits = 0;
static uint32_t g_whitelist_cidr_v6_count = 0;

/* LPM6 next-hop value (we only care about hit/miss, not the value) */
#define LPM6_NEXT_HOP_WHITELISTED 1

/* Default configuration */
static const struct ip_lists_v6_config DEFAULT_CONFIG = {
    .max_whitelist_entries = 10000,
    .max_blacklist_entries = 100000,
    .max_protected_entries = 1000,
    .max_whitelist_cidrs = 10000,
    .lpm6_rules = IP_LISTS_V6_DEFAULT_LPM6_RULES,
    .lpm6_tbl8s = IP_LISTS_V6_DEFAULT_LPM6_TBL8S,
    .enforce_protected_ips = false,
};

/* Hash function for 128-bit IPv6 addresses */
static inline uint32_t ipv6_hash(const void *key, uint32_t key_len __rte_unused,
                                  uint32_t init_val)
{
    const uint32_t *k = (const uint32_t *)key;
    return rte_jhash_32b(k, 4, init_val);
}

int ip_lists_v6_init(const struct ip_lists_v6_config *config)
{
    if (g_initialized) {
        RTE_LOG(WARNING, IP_LISTS_V6, "Already initialized\n");
        return 0;
    }

    /* Use provided config or defaults */
    if (config) {
        g_config = *config;
    } else {
        g_config = DEFAULT_CONFIG;
    }

    /* Create whitelist hash table */
    struct rte_hash_parameters whitelist_params = {
        .name = "ipv6_whitelist",
        .entries = g_config.max_whitelist_entries,
        .key_len = 16,  /* 128-bit IPv6 address */
        .hash_func = ipv6_hash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };

    g_whitelist_v6 = rte_hash_create(&whitelist_params);
    if (!g_whitelist_v6) {
        RTE_LOG(ERR, IP_LISTS_V6, "Failed to create IPv6 whitelist hash\n");
        goto error;
    }

    /* Create blacklist hash table */
    struct rte_hash_parameters blacklist_params = {
        .name = "ipv6_blacklist",
        .entries = g_config.max_blacklist_entries,
        .key_len = 16,
        .hash_func = ipv6_hash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };

    g_blacklist_v6 = rte_hash_create(&blacklist_params);
    if (!g_blacklist_v6) {
        RTE_LOG(ERR, IP_LISTS_V6, "Failed to create IPv6 blacklist hash\n");
        goto error;
    }

    /* Create protected hash table */
    struct rte_hash_parameters protected_params = {
        .name = "ipv6_protected",
        .entries = g_config.max_protected_entries,
        .key_len = 16,
        .hash_func = ipv6_hash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };

    g_protected_v6 = rte_hash_create(&protected_params);
    if (!g_protected_v6) {
        RTE_LOG(ERR, IP_LISTS_V6, "Failed to create IPv6 protected hash\n");
        goto error;
    }

    /* Create LPM6 for CIDR whitelist */
    struct rte_lpm6_config lpm6_config = {
        .max_rules = g_config.lpm6_rules,
        .number_tbl8s = g_config.lpm6_tbl8s,
        .flags = 0,
    };

    g_whitelist_lpm6 = rte_lpm6_create("ipv6_whitelist_lpm6",
                                        rte_socket_id(), &lpm6_config);
    if (!g_whitelist_lpm6) {
        RTE_LOG(ERR, IP_LISTS_V6, "Failed to create IPv6 whitelist LPM6\n");
        goto error;
    }

    g_initialized = true;
    RTE_LOG(INFO, IP_LISTS_V6,
            "IPv6 IP lists initialized (whitelist=%u, blacklist=%u, "
            "protected=%u, lpm6_rules=%u)\n",
            g_config.max_whitelist_entries, g_config.max_blacklist_entries,
            g_config.max_protected_entries, g_config.lpm6_rules);

    return 0;

error:
    ip_lists_v6_cleanup();
    return -1;
}

void ip_lists_v6_cleanup(void)
{
    if (g_whitelist_v6) {
        rte_hash_free(g_whitelist_v6);
        g_whitelist_v6 = NULL;
    }
    if (g_blacklist_v6) {
        rte_hash_free(g_blacklist_v6);
        g_blacklist_v6 = NULL;
    }
    if (g_protected_v6) {
        rte_hash_free(g_protected_v6);
        g_protected_v6 = NULL;
    }
    if (g_whitelist_lpm6) {
        rte_lpm6_free(g_whitelist_lpm6);
        g_whitelist_lpm6 = NULL;
    }

    g_initialized = false;
    RTE_LOG(INFO, IP_LISTS_V6, "IPv6 IP lists cleaned up\n");
}

/* ==================== Whitelist Operations ==================== */

int ip_whitelist_v6_add(const uint8_t ip6[16])
{
    if (!g_whitelist_v6) return -1;

    int ret = rte_hash_add_key(g_whitelist_v6, ip6);
    if (ret < 0) {
        RTE_LOG(WARNING, IP_LISTS_V6, "Failed to add IPv6 to whitelist\n");
        return -1;
    }

    return 0;
}

int ip_whitelist_v6_remove(const uint8_t ip6[16])
{
    if (!g_whitelist_v6) return -1;

    int ret = rte_hash_del_key(g_whitelist_v6, ip6);
    return (ret >= 0) ? 0 : -1;
}

bool ip_whitelist_v6_lookup(const uint8_t ip6[16])
{
    if (!g_whitelist_v6) return false;

    int ret = rte_hash_lookup(g_whitelist_v6, ip6);
    if (ret >= 0) {
        __atomic_add_fetch(&g_whitelist_v6_hits, 1, __ATOMIC_RELAXED);
        return true;
    }

    return false;
}

bool ip_whitelist_v6_lookup_mode(const uint8_t ip6[16], uint8_t *mode)
{
    // Stub: all IPv6 whitelist entries use BYPASS mode (no per-entry mode storage yet)
    bool found = ip_whitelist_v6_lookup(ip6);
    if (found && mode) *mode = WL_MODE_V6_BYPASS;
    return found;
}

void ip_whitelist_v6_clear(void)
{
    if (g_whitelist_v6) {
        rte_hash_reset(g_whitelist_v6);
    }
}

uint32_t ip_whitelist_v6_count(void)
{
    if (!g_whitelist_v6) return 0;
    int32_t count = rte_hash_count(g_whitelist_v6);
    return (count >= 0) ? (uint32_t)count : 0;
}

/* ==================== CIDR Whitelist Operations ==================== */

int ip_whitelist_cidr_v6_add(const uint8_t ip6_prefix[16], uint8_t depth)
{
    if (!g_whitelist_lpm6 || depth == 0 || depth > 128) return -1;

    /* Cast uint8_t[16] to struct rte_ipv6_addr* for newer DPDK API */
    int ret = rte_lpm6_add(g_whitelist_lpm6,
                            (const struct rte_ipv6_addr *)ip6_prefix, depth,
                            LPM6_NEXT_HOP_WHITELISTED);
    if (ret < 0) {
        RTE_LOG(WARNING, IP_LISTS_V6,
                "Failed to add IPv6 CIDR to whitelist (depth=%u)\n", depth);
        return -1;
    }

    __atomic_add_fetch(&g_whitelist_cidr_v6_count, 1, __ATOMIC_RELAXED);
    return 0;
}

int ip_whitelist_cidr_v6_remove(const uint8_t ip6_prefix[16], uint8_t depth)
{
    if (!g_whitelist_lpm6 || depth == 0 || depth > 128) return -1;

    /* Cast uint8_t[16] to struct rte_ipv6_addr* for newer DPDK API */
    int ret = rte_lpm6_delete(g_whitelist_lpm6,
                               (const struct rte_ipv6_addr *)ip6_prefix, depth);
    if (ret == 0) {
        __atomic_sub_fetch(&g_whitelist_cidr_v6_count, 1, __ATOMIC_RELAXED);
    }
    return (ret == 0) ? 0 : -1;
}

bool ip_whitelist_cidr_v6_lookup(const uint8_t ip6[16])
{
    if (!g_whitelist_lpm6) return false;

    uint32_t next_hop;
    /* Cast uint8_t[16] to struct rte_ipv6_addr* for newer DPDK API */
    int ret = rte_lpm6_lookup(g_whitelist_lpm6,
                               (const struct rte_ipv6_addr *)ip6, &next_hop);
    if (ret == 0) {
        __atomic_add_fetch(&g_whitelist_cidr_v6_hits, 1, __ATOMIC_RELAXED);
        return true;
    }

    return false;
}

void ip_whitelist_cidr_v6_clear(void)
{
    if (g_whitelist_lpm6) {
        rte_lpm6_delete_all(g_whitelist_lpm6);
        __atomic_store_n(&g_whitelist_cidr_v6_count, 0, __ATOMIC_RELAXED);
    }
}

uint32_t ip_whitelist_cidr_v6_count(void)
{
    return __atomic_load_n(&g_whitelist_cidr_v6_count, __ATOMIC_RELAXED);
}

/* ==================== Blacklist Operations ==================== */

int ip_blacklist_v6_add(const uint8_t ip6[16])
{
    if (!g_blacklist_v6) return -1;

    int ret = rte_hash_add_key(g_blacklist_v6, ip6);
    if (ret < 0) {
        RTE_LOG(WARNING, IP_LISTS_V6, "Failed to add IPv6 to blacklist\n");
        return -1;
    }

    return 0;
}

int ip_blacklist_v6_remove(const uint8_t ip6[16])
{
    if (!g_blacklist_v6) return -1;

    int ret = rte_hash_del_key(g_blacklist_v6, ip6);
    return (ret >= 0) ? 0 : -1;
}

bool ip_blacklist_v6_lookup(const uint8_t ip6[16])
{
    if (!g_blacklist_v6) return false;

    int ret = rte_hash_lookup(g_blacklist_v6, ip6);
    if (ret >= 0) {
        __atomic_add_fetch(&g_blacklist_v6_hits, 1, __ATOMIC_RELAXED);
        return true;
    }

    return false;
}

void ip_blacklist_v6_clear(void)
{
    if (g_blacklist_v6) {
        rte_hash_reset(g_blacklist_v6);
    }
}

uint32_t ip_blacklist_v6_count(void)
{
    if (!g_blacklist_v6) return 0;
    int32_t count = rte_hash_count(g_blacklist_v6);
    return (count >= 0) ? (uint32_t)count : 0;
}

/* ==================== Protected Server Operations ==================== */

int ip_protected_v6_add(const uint8_t ip6[16])
{
    if (!g_protected_v6) return -1;

    int ret = rte_hash_add_key(g_protected_v6, ip6);
    if (ret < 0) {
        RTE_LOG(WARNING, IP_LISTS_V6, "Failed to add IPv6 to protected\n");
        return -1;
    }

    return 0;
}

int ip_protected_v6_remove(const uint8_t ip6[16])
{
    if (!g_protected_v6) return -1;

    int ret = rte_hash_del_key(g_protected_v6, ip6);
    return (ret >= 0) ? 0 : -1;
}

bool ip_protected_v6_lookup(const uint8_t ip6[16])
{
    if (!g_protected_v6) return false;
    return rte_hash_lookup(g_protected_v6, ip6) >= 0;
}

void ip_protected_v6_clear(void)
{
    if (g_protected_v6) {
        rte_hash_reset(g_protected_v6);
    }
}

uint32_t ip_protected_v6_count(void)
{
    if (!g_protected_v6) return 0;
    int32_t count = rte_hash_count(g_protected_v6);
    return (count >= 0) ? (uint32_t)count : 0;
}

/* ==================== Dual-Stack Unified Lookups ==================== */

bool ip_whitelist_lookup_unified(const void *ip, bool is_ipv6)
{
    if (is_ipv6) {
        const uint8_t *ip6 = (const uint8_t *)ip;

        /* Check exact match first */
        if (ip_whitelist_v6_lookup(ip6)) {
            return true;
        }

        /* Check CIDR match */
        return ip_whitelist_cidr_v6_lookup(ip6);
    } else {
        const uint32_t *ip4 = (const uint32_t *)ip;

        /* Use IPv4 functions */
        if (ip_whitelist_lookup(*ip4, NULL)) {
            return true;
        }

        /* Check IPv4 CIDR (convert to host byte order) */
        return ip_whitelist_cidr_lookup(ntohl(*ip4));
    }
}

bool ip_blacklist_lookup_unified(const void *ip, bool is_ipv6)
{
    if (is_ipv6) {
        return ip_blacklist_v6_lookup((const uint8_t *)ip);
    } else {
        return ip_blacklist_lookup(*(const uint32_t *)ip);
    }
}

bool ip_protected_lookup_unified(const void *ip, bool is_ipv6)
{
    if (is_ipv6) {
        return ip_protected_v6_lookup((const uint8_t *)ip);
    } else {
        return ip_protected_lookup(*(const uint32_t *)ip);
    }
}

/* ==================== Statistics ==================== */

void ip_lists_v6_get_stats(uint32_t *whitelist_count, uint32_t *blacklist_count,
                           uint32_t *protected_count,
                           uint64_t *whitelist_hits, uint64_t *blacklist_hits)
{
    if (whitelist_count) {
        *whitelist_count = ip_whitelist_v6_count() + ip_whitelist_cidr_v6_count();
    }
    if (blacklist_count) {
        *blacklist_count = ip_blacklist_v6_count();
    }
    if (protected_count) {
        *protected_count = ip_protected_v6_count();
    }
    if (whitelist_hits) {
        *whitelist_hits = __atomic_load_n(&g_whitelist_v6_hits, __ATOMIC_RELAXED) +
                          __atomic_load_n(&g_whitelist_cidr_v6_hits, __ATOMIC_RELAXED);
    }
    if (blacklist_hits) {
        *blacklist_hits = __atomic_load_n(&g_blacklist_v6_hits, __ATOMIC_RELAXED);
    }
}

void ip_lists_v6_print_stats(void)
{
    uint32_t wl_count, bl_count, prot_count;
    uint64_t wl_hits, bl_hits;

    ip_lists_v6_get_stats(&wl_count, &bl_count, &prot_count, &wl_hits, &bl_hits);

    RTE_LOG(INFO, IP_LISTS_V6,
            "IPv6 Lists: whitelist=%u (hits=%"PRIu64"), "
            "blacklist=%u (hits=%"PRIu64"), protected=%u\n",
            wl_count, wl_hits, bl_count, bl_hits, prot_count);
}

/* ==================== Utility Functions ==================== */

const char *ip6_to_str(const uint8_t ip6[16], char *buf, size_t buflen)
{
    if (buflen < INET6_ADDRSTRLEN) return NULL;
    return inet_ntop(AF_INET6, ip6, buf, (socklen_t)buflen);
}

int ip6_from_str(const char *str, uint8_t ip6[16])
{
    if (!str || !ip6) return -1;
    return (inet_pton(AF_INET6, str, ip6) == 1) ? 0 : -1;
}

/* ==================== Persistence ==================== */

#include <cJSON.h>

/* Helper: iterate hash table and collect IPv6 addresses as strings */
static cJSON *hash_to_json_array_v6(struct rte_hash *hash)
{
    cJSON *array = cJSON_CreateArray();
    if (!array || !hash) return array;

    const void *key;
    void *data;
    uint32_t iter = 0;
    char ip_str[INET6_ADDRSTRLEN];

    while (rte_hash_iterate(hash, &key, &data, &iter) >= 0) {
        const uint8_t *ip6 = (const uint8_t *)key;
        if (inet_ntop(AF_INET6, ip6, ip_str, sizeof(ip_str))) {
            cJSON_AddItemToArray(array, cJSON_CreateString(ip_str));
        }
    }

    return array;
}

/* Helper: Structure to track CIDR entries for iteration */
struct cidr_entry_v6 {
    uint8_t prefix[16];
    uint8_t depth;
};

/* Track CIDR entries separately since LPM6 doesn't have iteration */
#define MAX_CIDR_TRACK_V6 10000
static struct cidr_entry_v6 g_cidr_entries_v6[MAX_CIDR_TRACK_V6];
static uint32_t g_cidr_entry_count_v6 = 0;

/* Wrapper to track CIDR additions */
int ip_whitelist_cidr_v6_add_tracked(const uint8_t ip6_prefix[16], uint8_t depth)
{
    int ret = ip_whitelist_cidr_v6_add(ip6_prefix, depth);
    if (ret == 0 && g_cidr_entry_count_v6 < MAX_CIDR_TRACK_V6) {
        rte_memcpy(g_cidr_entries_v6[g_cidr_entry_count_v6].prefix, ip6_prefix, 16);
        g_cidr_entries_v6[g_cidr_entry_count_v6].depth = depth;
        g_cidr_entry_count_v6++;
    }
    return ret;
}

int ip_lists_v6_save(const char *path)
{
    if (!path) {
        RTE_LOG(ERR, IP_LISTS_V6, "NULL path for save\n");
        return -1;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        RTE_LOG(ERR, IP_LISTS_V6, "Failed to create JSON object\n");
        return -1;
    }

    /* Save whitelist */
    cJSON *whitelist = hash_to_json_array_v6(g_whitelist_v6);
    cJSON_AddItemToObject(root, "whitelist_v6", whitelist);

    /* Save blacklist */
    cJSON *blacklist = hash_to_json_array_v6(g_blacklist_v6);
    cJSON_AddItemToObject(root, "blacklist_v6", blacklist);

    /* Save protected list */
    cJSON *protected = hash_to_json_array_v6(g_protected_v6);
    cJSON_AddItemToObject(root, "protected_v6", protected);

    /* Save CIDR whitelist */
    cJSON *cidr_array = cJSON_CreateArray();
    if (cidr_array) {
        char ip_str[INET6_ADDRSTRLEN];
        char cidr_str[INET6_ADDRSTRLEN + 8];  /* IP + /128 */

        for (uint32_t i = 0; i < g_cidr_entry_count_v6; i++) {
            if (inet_ntop(AF_INET6, g_cidr_entries_v6[i].prefix, ip_str, sizeof(ip_str))) {
                snprintf(cidr_str, sizeof(cidr_str), "%s/%u", ip_str, g_cidr_entries_v6[i].depth);
                cJSON_AddItemToArray(cidr_array, cJSON_CreateString(cidr_str));
            }
        }
        cJSON_AddItemToObject(root, "whitelist_cidr_v6", cidr_array);
    }

    /* Write to file */
    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    if (!json_str) {
        RTE_LOG(ERR, IP_LISTS_V6, "Failed to serialize JSON\n");
        return -1;
    }

    FILE *fp = fopen(path, "w");
    if (!fp) {
        RTE_LOG(ERR, IP_LISTS_V6, "Failed to open %s for writing\n", path);
        free(json_str);
        return -1;
    }

    size_t len = strlen(json_str);
    size_t written = fwrite(json_str, 1, len, fp);
    fclose(fp);
    free(json_str);

    if (written != len) {
        RTE_LOG(ERR, IP_LISTS_V6, "Failed to write all data to %s\n", path);
        return -1;
    }

    uint32_t wl_count = ip_whitelist_v6_count();
    uint32_t bl_count = ip_blacklist_v6_count();
    uint32_t prot_count = ip_protected_v6_count();
    uint32_t cidr_count = g_cidr_entry_count_v6;

    RTE_LOG(INFO, IP_LISTS_V6,
            "IPv6 lists saved to %s (whitelist=%u, blacklist=%u, protected=%u, cidr=%u)\n",
            path, wl_count, bl_count, prot_count, cidr_count);

    return 0;
}

int ip_lists_v6_load(const char *path)
{
    if (!path) {
        RTE_LOG(ERR, IP_LISTS_V6, "NULL path for load\n");
        return -1;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        RTE_LOG(INFO, IP_LISTS_V6, "No IPv6 lists file at %s (starting fresh)\n", path);
        return 0;  /* Not an error - file may not exist yet */
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 100 * 1024 * 1024) {  /* Max 100MB */
        RTE_LOG(ERR, IP_LISTS_V6, "Invalid file size: %ld\n", fsize);
        fclose(fp);
        return -1;
    }

    char *json_str = rte_malloc("ip_lists_v6_json", (size_t)fsize + 1, 0);
    if (!json_str) {
        RTE_LOG(ERR, IP_LISTS_V6, "Failed to allocate JSON buffer\n");
        fclose(fp);
        return -1;
    }

    size_t read_bytes = fread(json_str, 1, (size_t)fsize, fp);
    fclose(fp);
    json_str[read_bytes] = '\0';

    cJSON *root = cJSON_Parse(json_str);
    rte_free(json_str);

    if (!root) {
        RTE_LOG(ERR, IP_LISTS_V6, "Failed to parse JSON from %s\n", path);
        return -1;
    }

    uint32_t wl_loaded = 0, bl_loaded = 0, prot_loaded = 0, cidr_loaded = 0;
    uint8_t ip6[16];

    /* Load whitelist */
    cJSON *whitelist = cJSON_GetObjectItem(root, "whitelist_v6");
    if (cJSON_IsArray(whitelist)) {
        cJSON *item;
        cJSON_ArrayForEach(item, whitelist) {
            if (cJSON_IsString(item) && item->valuestring) {
                if (inet_pton(AF_INET6, item->valuestring, ip6) == 1) {
                    if (ip_whitelist_v6_add(ip6) == 0) {
                        wl_loaded++;
                    }
                }
            }
        }
    }

    /* Load blacklist */
    cJSON *blacklist = cJSON_GetObjectItem(root, "blacklist_v6");
    if (cJSON_IsArray(blacklist)) {
        cJSON *item;
        cJSON_ArrayForEach(item, blacklist) {
            if (cJSON_IsString(item) && item->valuestring) {
                if (inet_pton(AF_INET6, item->valuestring, ip6) == 1) {
                    if (ip_blacklist_v6_add(ip6) == 0) {
                        bl_loaded++;
                    }
                }
            }
        }
    }

    /* Load protected list */
    cJSON *protected = cJSON_GetObjectItem(root, "protected_v6");
    if (cJSON_IsArray(protected)) {
        cJSON *item;
        cJSON_ArrayForEach(item, protected) {
            if (cJSON_IsString(item) && item->valuestring) {
                if (inet_pton(AF_INET6, item->valuestring, ip6) == 1) {
                    if (ip_protected_v6_add(ip6) == 0) {
                        prot_loaded++;
                    }
                }
            }
        }
    }

    /* Load CIDR whitelist */
    cJSON *cidr_list = cJSON_GetObjectItem(root, "whitelist_cidr_v6");
    if (cJSON_IsArray(cidr_list)) {
        cJSON *item;
        cJSON_ArrayForEach(item, cidr_list) {
            if (cJSON_IsString(item) && item->valuestring) {
                /* Parse CIDR notation: "2001:db8::/32" */
                char cidr_copy[INET6_ADDRSTRLEN + 8];
                strncpy(cidr_copy, item->valuestring, sizeof(cidr_copy) - 1);
                cidr_copy[sizeof(cidr_copy) - 1] = '\0';

                char *slash = strchr(cidr_copy, '/');
                if (slash) {
                    *slash = '\0';
                    uint8_t depth = (uint8_t)atoi(slash + 1);

                    if (depth > 0 && depth <= 128) {
                        if (inet_pton(AF_INET6, cidr_copy, ip6) == 1) {
                            if (ip_whitelist_cidr_v6_add(ip6, depth) == 0) {
                                /* Track for persistence */
                                if (g_cidr_entry_count_v6 < MAX_CIDR_TRACK_V6) {
                                    rte_memcpy(g_cidr_entries_v6[g_cidr_entry_count_v6].prefix, ip6, 16);
                                    g_cidr_entries_v6[g_cidr_entry_count_v6].depth = depth;
                                    g_cidr_entry_count_v6++;
                                }
                                cidr_loaded++;
                            }
                        }
                    }
                }
            }
        }
    }

    cJSON_Delete(root);

    RTE_LOG(INFO, IP_LISTS_V6,
            "IPv6 lists loaded from %s (whitelist=%u, blacklist=%u, protected=%u, cidr=%u)\n",
            path, wl_loaded, bl_loaded, prot_loaded, cidr_loaded);

    return 0;
}

// ==================== Protection Profile Stubs for IPv6 ====================

bool ip_protected_v6_lookup_profile_pos(const uint8_t ip6[16],
                                         const struct protection_profile **profile,
                                         int32_t *pos) {
    // Stub: no per-profile storage yet for IPv6
    if (profile) *profile = NULL;
    if (pos) *pos = -1;
    return ip_protected_v6_lookup(ip6);
}

bool ip_protected_v6_enforcement_enabled(void) {
    // Stub: delegate to the IPv6 config flag
    // Full implementation would check ip_lists_v6 config enforce_protected_ips
    return false;
}
