/**
 * @file ip_lists_simple.c
 * @brief Simplified global IP whitelist/blacklist implementation
 *
 * Uses hash tables for individual IPs and LPM for CIDR ranges.
 * No tenant overhead - just fast global lookups.
 */

#include "ip_lists_simple.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdatomic.h>

#ifdef USE_DPDK
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#else
/* Non-DPDK fallbacks */
#endif

/* ============================================================================
 * Internal Storage
 * ============================================================================ */

#define HASH_SIZE           (1 << 17)   /* 128K buckets */
#define LPM_MAX_RULES       10000

/* Simple hash table entry for individual IPs */
struct ip_hash_entry {
    uint32_t    ip;
    uint32_t    added_time;
    uint32_t    expire_time;
    uint8_t     source;
    uint8_t     valid;
    uint8_t     hit_count;
    uint8_t     _pad;
};

/* CIDR entry storage (for non-DPDK or export) */
struct cidr_storage {
    struct ip_list_cidr_entry entries[IP_LIST_MAX_CIDR];
    uint32_t count;
};

/* Global state */
static struct {
    /* Whitelist */
    struct ip_hash_entry *whitelist_hash;
    struct cidr_storage whitelist_cidr;
#ifdef USE_DPDK
    struct rte_lpm *whitelist_lpm;
    struct rte_lpm6 *whitelist_lpm6;
#endif

    /* Blacklist */
    struct ip_hash_entry *blacklist_hash;
    struct cidr_storage blacklist_cidr;
#ifdef USE_DPDK
    struct rte_lpm *blacklist_lpm;
    struct rte_lpm6 *blacklist_lpm6;
#endif

    /* Statistics */
    _Atomic uint64_t whitelist_hits;
    _Atomic uint64_t blacklist_hits;
    _Atomic uint64_t whitelist_bypasses;
    _Atomic uint64_t blacklist_drops;

    /* Counts */
    _Atomic uint32_t whitelist_count;
    _Atomic uint32_t blacklist_count;

    /* Config */
    char whitelist_path[256];
    char blacklist_path[256];
    bool initialized;
} g_ip_lists;

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static inline uint32_t ip_hash(uint32_t ip)
{
    uint32_t h = ip;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h & (HASH_SIZE - 1);
}

static inline uint32_t get_unix_time(void)
{
    return (uint32_t)time(NULL);
}

static inline bool ip_matches_cidr(uint32_t ip, uint32_t network, uint8_t prefix_len)
{
    if (prefix_len == 0) return true;
    if (prefix_len >= 32) return ip == network;

    uint32_t mask = ~((1U << (32 - prefix_len)) - 1);
    return (ip & mask) == (network & mask);
}

static bool hash_lookup(struct ip_hash_entry *table, uint32_t ip,
                        uint32_t now, bool update_hit)
{
    uint32_t idx = ip_hash(ip);
    struct ip_hash_entry *entry = &table[idx];

    if (!entry->valid || entry->ip != ip) {
        return false;
    }

    /* Check expiration */
    if (entry->expire_time != 0 && entry->expire_time < now) {
        entry->valid = 0;
        return false;
    }

    if (update_hit && entry->hit_count < 255) {
        entry->hit_count++;
    }

    return true;
}

static bool hash_insert(struct ip_hash_entry *table, uint32_t ip,
                        uint32_t expire_time, uint8_t source,
                        _Atomic uint32_t *count)
{
    uint32_t idx = ip_hash(ip);
    struct ip_hash_entry *entry = &table[idx];

    bool was_empty = !entry->valid;

    entry->ip = ip;
    entry->added_time = get_unix_time();
    entry->expire_time = expire_time;
    entry->source = source;
    entry->valid = 1;
    entry->hit_count = 0;

    if (was_empty) {
        atomic_fetch_add(count, 1);
    }

    return true;
}

static bool hash_remove(struct ip_hash_entry *table, uint32_t ip,
                        _Atomic uint32_t *count)
{
    uint32_t idx = ip_hash(ip);
    struct ip_hash_entry *entry = &table[idx];

    if (!entry->valid || entry->ip != ip) {
        return false;
    }

    entry->valid = 0;
    atomic_fetch_sub(count, 1);
    return true;
}

#ifndef USE_DPDK
/* Linear CIDR search for non-DPDK builds */
static bool cidr_lookup(struct cidr_storage *storage, uint32_t ip)
{
    for (uint32_t i = 0; i < storage->count; i++) {
        struct ip_list_cidr_entry *entry = &storage->entries[i];
        uint32_t now = get_unix_time();

        /* Check expiration */
        if (entry->expire_time != 0 && entry->expire_time < now) {
            continue;
        }

        if (ip_matches_cidr(ip, entry->network, entry->prefix_len)) {
            return true;
        }
    }
    return false;
}
#endif

/* ============================================================================
 * Initialization
 * ============================================================================ */

int ip_lists_init(const char *whitelist_path, const char *blacklist_path)
{
    memset(&g_ip_lists, 0, sizeof(g_ip_lists));

    /* Store paths */
    if (whitelist_path) {
        strncpy(g_ip_lists.whitelist_path, whitelist_path,
                sizeof(g_ip_lists.whitelist_path) - 1);
    }
    if (blacklist_path) {
        strncpy(g_ip_lists.blacklist_path, blacklist_path,
                sizeof(g_ip_lists.blacklist_path) - 1);
    }

    /* Allocate hash tables */
#ifdef USE_DPDK
    g_ip_lists.whitelist_hash = rte_zmalloc("whitelist_hash",
                                            HASH_SIZE * sizeof(struct ip_hash_entry),
                                            RTE_CACHE_LINE_SIZE);
    g_ip_lists.blacklist_hash = rte_zmalloc("blacklist_hash",
                                            HASH_SIZE * sizeof(struct ip_hash_entry),
                                            RTE_CACHE_LINE_SIZE);
#else
    g_ip_lists.whitelist_hash = calloc(HASH_SIZE, sizeof(struct ip_hash_entry));
    g_ip_lists.blacklist_hash = calloc(HASH_SIZE, sizeof(struct ip_hash_entry));
#endif

    if (!g_ip_lists.whitelist_hash || !g_ip_lists.blacklist_hash) {
        ip_lists_cleanup();
        return -1;
    }

#ifdef USE_DPDK
    /* Create LPM tables for CIDR matching */
    struct rte_lpm_config lpm_cfg = {
        .max_rules = LPM_MAX_RULES,
        .number_tbl8s = 256,
        .flags = 0
    };

    g_ip_lists.whitelist_lpm = rte_lpm_create("whitelist_lpm", 0, &lpm_cfg);
    g_ip_lists.blacklist_lpm = rte_lpm_create("blacklist_lpm", 0, &lpm_cfg);

    /* LPM6 for IPv6 */
    struct rte_lpm6_config lpm6_cfg = {
        .max_rules = LPM_MAX_RULES,
        .number_tbl8s = 256,
        .flags = 0
    };

    g_ip_lists.whitelist_lpm6 = rte_lpm6_create("whitelist_lpm6", 0, &lpm6_cfg);
    g_ip_lists.blacklist_lpm6 = rte_lpm6_create("blacklist_lpm6", 0, &lpm6_cfg);
#endif

    g_ip_lists.initialized = true;

    /* Load from files if provided */
    if (whitelist_path && whitelist_path[0]) {
        /* TODO: Load whitelist JSON */
    }
    if (blacklist_path && blacklist_path[0]) {
        /* TODO: Load blacklist JSON */
    }

    return 0;
}

void ip_lists_cleanup(void)
{
    if (g_ip_lists.whitelist_hash) {
#ifdef USE_DPDK
        rte_free(g_ip_lists.whitelist_hash);
#else
        free(g_ip_lists.whitelist_hash);
#endif
        g_ip_lists.whitelist_hash = NULL;
    }

    if (g_ip_lists.blacklist_hash) {
#ifdef USE_DPDK
        rte_free(g_ip_lists.blacklist_hash);
#else
        free(g_ip_lists.blacklist_hash);
#endif
        g_ip_lists.blacklist_hash = NULL;
    }

#ifdef USE_DPDK
    if (g_ip_lists.whitelist_lpm) {
        rte_lpm_free(g_ip_lists.whitelist_lpm);
        g_ip_lists.whitelist_lpm = NULL;
    }
    if (g_ip_lists.blacklist_lpm) {
        rte_lpm_free(g_ip_lists.blacklist_lpm);
        g_ip_lists.blacklist_lpm = NULL;
    }
    if (g_ip_lists.whitelist_lpm6) {
        rte_lpm6_free(g_ip_lists.whitelist_lpm6);
        g_ip_lists.whitelist_lpm6 = NULL;
    }
    if (g_ip_lists.blacklist_lpm6) {
        rte_lpm6_free(g_ip_lists.blacklist_lpm6);
        g_ip_lists.blacklist_lpm6 = NULL;
    }
#endif

    g_ip_lists.initialized = false;
}

int ip_lists_reload(void)
{
    /* Clear and reload from configured paths */
    atomic_store(&g_ip_lists.whitelist_count, 0);
    atomic_store(&g_ip_lists.blacklist_count, 0);
    g_ip_lists.whitelist_cidr.count = 0;
    g_ip_lists.blacklist_cidr.count = 0;

    memset(g_ip_lists.whitelist_hash, 0, HASH_SIZE * sizeof(struct ip_hash_entry));
    memset(g_ip_lists.blacklist_hash, 0, HASH_SIZE * sizeof(struct ip_hash_entry));

    /* TODO: Reload from files */
    return 0;
}

/* ============================================================================
 * Lookup Functions (Hot Path)
 * ============================================================================ */

bool ip_is_whitelisted(uint32_t ip)
{
    if (!g_ip_lists.initialized) return false;

    uint32_t now = get_unix_time();

    /* Check hash table first (individual IPs) */
    if (hash_lookup(g_ip_lists.whitelist_hash, ip, now, true)) {
        atomic_fetch_add(&g_ip_lists.whitelist_hits, 1);
        return true;
    }

    /* Check CIDR ranges */
#ifdef USE_DPDK
    if (g_ip_lists.whitelist_lpm) {
        uint32_t next_hop;
        if (rte_lpm_lookup(g_ip_lists.whitelist_lpm, ip, &next_hop) == 0) {
            atomic_fetch_add(&g_ip_lists.whitelist_hits, 1);
            return true;
        }
    }
#else
    if (cidr_lookup(&g_ip_lists.whitelist_cidr, ip)) {
        atomic_fetch_add(&g_ip_lists.whitelist_hits, 1);
        return true;
    }
#endif

    return false;
}

bool ip_is_blacklisted(uint32_t ip)
{
    if (!g_ip_lists.initialized) return false;

    uint32_t now = get_unix_time();

    /* Check hash table first */
    if (hash_lookup(g_ip_lists.blacklist_hash, ip, now, true)) {
        atomic_fetch_add(&g_ip_lists.blacklist_hits, 1);
        return true;
    }

    /* Check CIDR ranges */
#ifdef USE_DPDK
    if (g_ip_lists.blacklist_lpm) {
        uint32_t next_hop;
        if (rte_lpm_lookup(g_ip_lists.blacklist_lpm, ip, &next_hop) == 0) {
            atomic_fetch_add(&g_ip_lists.blacklist_hits, 1);
            return true;
        }
    }
#else
    if (cidr_lookup(&g_ip_lists.blacklist_cidr, ip)) {
        atomic_fetch_add(&g_ip_lists.blacklist_hits, 1);
        return true;
    }
#endif

    return false;
}

bool ip_is_whitelisted_v6(const uint8_t *ip)
{
    if (!g_ip_lists.initialized || !ip) return false;

#ifdef USE_DPDK
    if (g_ip_lists.whitelist_lpm6) {
        uint32_t next_hop;
        if (rte_lpm6_lookup(g_ip_lists.whitelist_lpm6, ip, &next_hop) == 0) {
            atomic_fetch_add(&g_ip_lists.whitelist_hits, 1);
            return true;
        }
    }
#endif
    /* TODO: Non-DPDK IPv6 lookup */
    return false;
}

bool ip_is_blacklisted_v6(const uint8_t *ip)
{
    if (!g_ip_lists.initialized || !ip) return false;

#ifdef USE_DPDK
    if (g_ip_lists.blacklist_lpm6) {
        uint32_t next_hop;
        if (rte_lpm6_lookup(g_ip_lists.blacklist_lpm6, ip, &next_hop) == 0) {
            atomic_fetch_add(&g_ip_lists.blacklist_hits, 1);
            return true;
        }
    }
#endif
    /* TODO: Non-DPDK IPv6 lookup */
    return false;
}

int ip_list_check(uint32_t ip)
{
    /* Whitelist takes priority */
    if (ip_is_whitelisted(ip)) {
        atomic_fetch_add(&g_ip_lists.whitelist_bypasses, 1);
        return 1;  /* Bypass all checks */
    }

    if (ip_is_blacklisted(ip)) {
        atomic_fetch_add(&g_ip_lists.blacklist_drops, 1);
        return -1; /* Drop */
    }

    return 0; /* Neutral - continue normal processing */
}

int ip_list_check_v6(const uint8_t *ip)
{
    if (ip_is_whitelisted_v6(ip)) {
        atomic_fetch_add(&g_ip_lists.whitelist_bypasses, 1);
        return 1;
    }

    if (ip_is_blacklisted_v6(ip)) {
        atomic_fetch_add(&g_ip_lists.blacklist_drops, 1);
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Management Functions
 * ============================================================================ */

int ip_whitelist_add(uint32_t ip, const char *description,
                     uint32_t expire_sec, ip_entry_source_t source)
{
    if (!g_ip_lists.initialized) return -1;

    uint32_t expire_time = expire_sec ? get_unix_time() + expire_sec : 0;

    if (!hash_insert(g_ip_lists.whitelist_hash, ip, expire_time,
                     source, &g_ip_lists.whitelist_count)) {
        return -1;
    }

    (void)description; /* TODO: Store description */
    return 0;
}

int ip_whitelist_add_cidr(uint32_t network, uint8_t prefix_len,
                          const char *description, uint32_t expire_sec,
                          ip_entry_source_t source)
{
    if (!g_ip_lists.initialized) return -1;
    if (g_ip_lists.whitelist_cidr.count >= IP_LIST_MAX_CIDR) return -1;

#ifdef USE_DPDK
    if (g_ip_lists.whitelist_lpm) {
        if (rte_lpm_add(g_ip_lists.whitelist_lpm, network, prefix_len, 1) < 0) {
            return -1;
        }
    }
#endif

    /* Store in array for export/non-DPDK */
    struct ip_list_cidr_entry *entry =
        &g_ip_lists.whitelist_cidr.entries[g_ip_lists.whitelist_cidr.count];

    entry->network = network;
    entry->prefix_len = prefix_len;
    entry->source = source;
    entry->added_time = get_unix_time();
    entry->expire_time = expire_sec ? entry->added_time + expire_sec : 0;

    if (description) {
        strncpy(entry->description, description, IP_LIST_MAX_DESCRIPTION - 1);
    }

    g_ip_lists.whitelist_cidr.count++;
    return 0;
}

int ip_whitelist_remove(uint32_t ip)
{
    if (!g_ip_lists.initialized) return -1;
    return hash_remove(g_ip_lists.whitelist_hash, ip,
                       &g_ip_lists.whitelist_count) ? 0 : -1;
}

int ip_whitelist_remove_cidr(uint32_t network, uint8_t prefix_len)
{
    if (!g_ip_lists.initialized) return -1;

#ifdef USE_DPDK
    if (g_ip_lists.whitelist_lpm) {
        rte_lpm_delete(g_ip_lists.whitelist_lpm, network, prefix_len);
    }
#endif

    /* Remove from array */
    for (uint32_t i = 0; i < g_ip_lists.whitelist_cidr.count; i++) {
        struct ip_list_cidr_entry *entry = &g_ip_lists.whitelist_cidr.entries[i];
        if (entry->network == network && entry->prefix_len == prefix_len) {
            /* Shift remaining entries */
            memmove(entry, entry + 1,
                    (g_ip_lists.whitelist_cidr.count - i - 1) * sizeof(*entry));
            g_ip_lists.whitelist_cidr.count--;
            return 0;
        }
    }

    return -1;
}

int ip_blacklist_add(uint32_t ip, const char *description,
                     uint32_t expire_sec, ip_entry_source_t source)
{
    if (!g_ip_lists.initialized) return -1;

    uint32_t expire_time = expire_sec ? get_unix_time() + expire_sec : 0;

    if (!hash_insert(g_ip_lists.blacklist_hash, ip, expire_time,
                     source, &g_ip_lists.blacklist_count)) {
        return -1;
    }

    (void)description;
    return 0;
}

int ip_blacklist_add_cidr(uint32_t network, uint8_t prefix_len,
                          const char *description, uint32_t expire_sec,
                          ip_entry_source_t source)
{
    if (!g_ip_lists.initialized) return -1;
    if (g_ip_lists.blacklist_cidr.count >= IP_LIST_MAX_CIDR) return -1;

#ifdef USE_DPDK
    if (g_ip_lists.blacklist_lpm) {
        if (rte_lpm_add(g_ip_lists.blacklist_lpm, network, prefix_len, 1) < 0) {
            return -1;
        }
    }
#endif

    struct ip_list_cidr_entry *entry =
        &g_ip_lists.blacklist_cidr.entries[g_ip_lists.blacklist_cidr.count];

    entry->network = network;
    entry->prefix_len = prefix_len;
    entry->source = source;
    entry->added_time = get_unix_time();
    entry->expire_time = expire_sec ? entry->added_time + expire_sec : 0;

    if (description) {
        strncpy(entry->description, description, IP_LIST_MAX_DESCRIPTION - 1);
    }

    g_ip_lists.blacklist_cidr.count++;
    return 0;
}

int ip_blacklist_remove(uint32_t ip)
{
    if (!g_ip_lists.initialized) return -1;
    return hash_remove(g_ip_lists.blacklist_hash, ip,
                       &g_ip_lists.blacklist_count) ? 0 : -1;
}

int ip_blacklist_remove_cidr(uint32_t network, uint8_t prefix_len)
{
    if (!g_ip_lists.initialized) return -1;

#ifdef USE_DPDK
    if (g_ip_lists.blacklist_lpm) {
        rte_lpm_delete(g_ip_lists.blacklist_lpm, network, prefix_len);
    }
#endif

    for (uint32_t i = 0; i < g_ip_lists.blacklist_cidr.count; i++) {
        struct ip_list_cidr_entry *entry = &g_ip_lists.blacklist_cidr.entries[i];
        if (entry->network == network && entry->prefix_len == prefix_len) {
            memmove(entry, entry + 1,
                    (g_ip_lists.blacklist_cidr.count - i - 1) * sizeof(*entry));
            g_ip_lists.blacklist_cidr.count--;
            return 0;
        }
    }

    return -1;
}

/* ============================================================================
 * Maintenance
 * ============================================================================ */

uint32_t ip_lists_expire_old(void)
{
    if (!g_ip_lists.initialized) return 0;

    uint32_t now = get_unix_time();
    uint32_t expired = 0;

    /* Expire from hash tables */
    for (uint32_t i = 0; i < HASH_SIZE; i++) {
        struct ip_hash_entry *entry = &g_ip_lists.whitelist_hash[i];
        if (entry->valid && entry->expire_time != 0 && entry->expire_time < now) {
            entry->valid = 0;
            atomic_fetch_sub(&g_ip_lists.whitelist_count, 1);
            expired++;
        }

        entry = &g_ip_lists.blacklist_hash[i];
        if (entry->valid && entry->expire_time != 0 && entry->expire_time < now) {
            entry->valid = 0;
            atomic_fetch_sub(&g_ip_lists.blacklist_count, 1);
            expired++;
        }
    }

    /* Note: CIDR expiration checked at lookup time to avoid LPM rebuild */

    return expired;
}

uint32_t ip_lists_clear_dynamic(void)
{
    if (!g_ip_lists.initialized) return 0;

    uint32_t cleared = 0;

    for (uint32_t i = 0; i < HASH_SIZE; i++) {
        struct ip_hash_entry *entry = &g_ip_lists.whitelist_hash[i];
        if (entry->valid && entry->source == IP_ENTRY_DYNAMIC) {
            entry->valid = 0;
            atomic_fetch_sub(&g_ip_lists.whitelist_count, 1);
            cleared++;
        }

        entry = &g_ip_lists.blacklist_hash[i];
        if (entry->valid && entry->source == IP_ENTRY_DYNAMIC) {
            entry->valid = 0;
            atomic_fetch_sub(&g_ip_lists.blacklist_count, 1);
            cleared++;
        }
    }

    return cleared;
}

uint32_t ip_lists_clear_temporary(void)
{
    if (!g_ip_lists.initialized) return 0;

    uint32_t cleared = 0;

    for (uint32_t i = 0; i < HASH_SIZE; i++) {
        struct ip_hash_entry *entry = &g_ip_lists.whitelist_hash[i];
        if (entry->valid && entry->source == IP_ENTRY_TEMPORARY) {
            entry->valid = 0;
            atomic_fetch_sub(&g_ip_lists.whitelist_count, 1);
            cleared++;
        }

        entry = &g_ip_lists.blacklist_hash[i];
        if (entry->valid && entry->source == IP_ENTRY_TEMPORARY) {
            entry->valid = 0;
            atomic_fetch_sub(&g_ip_lists.blacklist_count, 1);
            cleared++;
        }
    }

    return cleared;
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

void ip_lists_get_stats(struct ip_list_stats *stats)
{
    if (!stats) return;

    stats->whitelist_count = atomic_load(&g_ip_lists.whitelist_count);
    stats->whitelist_cidr_count = g_ip_lists.whitelist_cidr.count;
    stats->blacklist_count = atomic_load(&g_ip_lists.blacklist_count);
    stats->blacklist_cidr_count = g_ip_lists.blacklist_cidr.count;
    stats->whitelist_hits = atomic_load(&g_ip_lists.whitelist_hits);
    stats->blacklist_hits = atomic_load(&g_ip_lists.blacklist_hits);
    stats->whitelist_bypasses = atomic_load(&g_ip_lists.whitelist_bypasses);
    stats->blacklist_drops = atomic_load(&g_ip_lists.blacklist_drops);
}

/* ============================================================================
 * Bulk Operations
 * ============================================================================ */

int ip_blacklist_bulk_add(const uint32_t *ips, uint32_t count,
                          const char *description, uint32_t expire_sec,
                          ip_entry_source_t source)
{
    if (!g_ip_lists.initialized || !ips) return 0;

    int added = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (ip_blacklist_add(ips[i], description, expire_sec, source) == 0) {
            added++;
        }
    }

    return added;
}

int ip_blacklist_bulk_remove(const uint32_t *ips, uint32_t count)
{
    if (!g_ip_lists.initialized || !ips) return 0;

    int removed = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (ip_blacklist_remove(ips[i]) == 0) {
            removed++;
        }
    }

    return removed;
}

/* ============================================================================
 * IPv6 Management (Stubs)
 * ============================================================================ */

int ip_whitelist_add_v6(const uint8_t *ip, const char *description,
                        uint32_t expire_sec, ip_entry_source_t source)
{
    (void)ip; (void)description; (void)expire_sec; (void)source;
    /* TODO: Implement IPv6 hash table */
    return -1;
}

int ip_blacklist_add_v6(const uint8_t *ip, const char *description,
                        uint32_t expire_sec, ip_entry_source_t source)
{
    (void)ip; (void)description; (void)expire_sec; (void)source;
    return -1;
}

int ip_whitelist_remove_v6(const uint8_t *ip)
{
    (void)ip;
    return -1;
}

int ip_blacklist_remove_v6(const uint8_t *ip)
{
    (void)ip;
    return -1;
}

/* ============================================================================
 * JSON Serialization (Stubs)
 * ============================================================================ */

int ip_whitelist_to_json(char *buf, size_t buf_size)
{
    (void)buf; (void)buf_size;
    /* TODO: Implement JSON export */
    return -1;
}

int ip_blacklist_to_json(char *buf, size_t buf_size)
{
    (void)buf; (void)buf_size;
    return -1;
}

int ip_whitelist_from_json(const char *json, bool clear_first)
{
    (void)json; (void)clear_first;
    /* TODO: Implement JSON import */
    return -1;
}

int ip_blacklist_from_json(const char *json, bool clear_first)
{
    (void)json; (void)clear_first;
    return -1;
}
