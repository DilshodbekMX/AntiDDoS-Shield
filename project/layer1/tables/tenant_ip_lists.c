/**
 * @file tenant_ip_lists.c
 * @brief Per-Tenant IP Allow/Block List Implementation
 *
 * Uses DPDK LPM (Longest Prefix Match) for fast IP lookups.
 * Supports IPv4 and IPv6 with hierarchical tenant isolation.
 */

#include "tenant_ip_lists.h"
#include "../../common/tenant.h"

#include <rte_common.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ip6.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>

#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

// ==================== Internal State ====================

// Global LPM tables (combined for all lists)
static struct rte_lpm *g_lpm_v4;
static struct rte_lpm6 *g_lpm_v6;

// Per-list statistics
static struct ip_list_stats g_global_stats[IP_LIST_TYPE_COUNT];

// Per-tenant statistics
static struct tenant_ip_list_stats *g_tenant_stats[MAX_TENANTS];

// Entry storage for management (not used in fast path)
#define MAX_ENTRIES_TOTAL  500000
static struct ip_list_entry *g_entries;
static uint32_t g_entry_count;
static uint32_t g_entry_next_index;

// Lock for modifications
static rte_spinlock_t g_list_lock = RTE_SPINLOCK_INITIALIZER;

// Initialization flag
static bool g_initialized = false;

// TSC frequency
static uint64_t g_tsc_hz;

// ==================== List Type Names ====================

static const char *list_type_names[] = {
    "GLOBAL_BLACKLIST",
    "GLOBAL_WHITELIST",
    "TENANT_BLACKLIST",
    "TENANT_WHITELIST"
};

const char* ip_list_type_to_string(ip_list_type_t list_type) {
    if (list_type >= IP_LIST_TYPE_COUNT) {
        return "UNKNOWN";
    }
    return list_type_names[list_type];
}

// ==================== Initialization ====================

int tenant_ip_lists_init(void) {
    if (g_initialized) {
        return 0;
    }

    g_tsc_hz = rte_get_tsc_hz();

    // Create IPv4 LPM table
    struct rte_lpm_config lpm_config = {
        .max_rules = TENANT_IP_LPM_MAX_RULES,
        .number_tbl8s = TENANT_IP_LPM_TBL8S,
        .flags = 0,
    };

    g_lpm_v4 = rte_lpm_create("tenant_ip_lpm4", rte_socket_id(), &lpm_config);
    if (!g_lpm_v4) {
        RTE_LOG(ERR, USER1, "Failed to create IPv4 LPM table\n");
        return -1;
    }

    // Create IPv6 LPM table
    struct rte_lpm6_config lpm6_config = {
        .max_rules = TENANT_IP_LPM6_MAX_RULES,
        .number_tbl8s = TENANT_IP_LPM6_TBL8S,
        .flags = 0,
    };

    g_lpm_v6 = rte_lpm6_create("tenant_ip_lpm6", rte_socket_id(), &lpm6_config);
    if (!g_lpm_v6) {
        RTE_LOG(ERR, USER1, "Failed to create IPv6 LPM table\n");
        rte_lpm_free(g_lpm_v4);
        g_lpm_v4 = NULL;
        return -1;
    }

    // Allocate entry storage
    g_entries = rte_zmalloc("tenant_ip_entries",
                            sizeof(struct ip_list_entry) * MAX_ENTRIES_TOTAL,
                            RTE_CACHE_LINE_SIZE);
    if (!g_entries) {
        RTE_LOG(ERR, USER1, "Failed to allocate IP list entries\n");
        rte_lpm_free(g_lpm_v4);
        rte_lpm6_free(g_lpm_v6);
        return -1;
    }

    g_entry_count = 0;
    g_entry_next_index = 0;

    // Initialize global statistics
    memset(g_global_stats, 0, sizeof(g_global_stats));

    // Initialize per-tenant stats pointers
    memset(g_tenant_stats, 0, sizeof(g_tenant_stats));

    g_initialized = true;
    RTE_LOG(INFO, USER1, "Tenant IP lists initialized: %u IPv4 rules, %u IPv6 rules\n",
            TENANT_IP_LPM_MAX_RULES, TENANT_IP_LPM6_MAX_RULES);

    return 0;
}

void tenant_ip_lists_cleanup(void) {
    if (!g_initialized) {
        return;
    }

    rte_spinlock_lock(&g_list_lock);

    if (g_lpm_v4) {
        rte_lpm_free(g_lpm_v4);
        g_lpm_v4 = NULL;
    }

    if (g_lpm_v6) {
        rte_lpm6_free(g_lpm_v6);
        g_lpm_v6 = NULL;
    }

    if (g_entries) {
        rte_free(g_entries);
        g_entries = NULL;
    }

    // Free per-tenant stats
    for (uint32_t i = 0; i < MAX_TENANTS; i++) {
        if (g_tenant_stats[i]) {
            rte_free(g_tenant_stats[i]);
            g_tenant_stats[i] = NULL;
        }
    }

    g_initialized = false;
    rte_spinlock_unlock(&g_list_lock);

    RTE_LOG(INFO, USER1, "Tenant IP lists cleaned up\n");
}

int tenant_ip_lists_tenant_init(tenant_id_t tenant_id) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return -1;
    }

    rte_spinlock_lock(&g_list_lock);

    if (!g_tenant_stats[tenant_id]) {
        g_tenant_stats[tenant_id] = rte_zmalloc("tenant_ip_stats",
                                                 sizeof(struct tenant_ip_list_stats),
                                                 RTE_CACHE_LINE_SIZE);
        if (!g_tenant_stats[tenant_id]) {
            rte_spinlock_unlock(&g_list_lock);
            return -1;
        }
    }

    rte_spinlock_unlock(&g_list_lock);
    return 0;
}

void tenant_ip_lists_tenant_cleanup(tenant_id_t tenant_id) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return;
    }

    // Remove all entries for this tenant
    tenant_ip_list_clear(IP_LIST_TENANT_BLACKLIST, tenant_id);
    tenant_ip_list_clear(IP_LIST_TENANT_WHITELIST, tenant_id);

    rte_spinlock_lock(&g_list_lock);

    if (g_tenant_stats[tenant_id]) {
        rte_free(g_tenant_stats[tenant_id]);
        g_tenant_stats[tenant_id] = NULL;
    }

    rte_spinlock_unlock(&g_list_lock);
}

// ==================== Fast Path: IP Lookup ====================

uint8_t __tenant_ip_check_internal(tenant_id_t tenant_id, uint32_t src_ip,
                                   struct ip_list_result *result) {
    result->matched = false;
    result->list_type = IP_LIST_GLOBAL_BLACKLIST;
    result->tenant_id = TENANT_ID_INVALID;
    result->action = IP_LIST_ACTION_NONE;
    result->prefix_len = 0;

    if (!g_lpm_v4) {
        return IP_LIST_ACTION_NONE;
    }

    // Convert to host byte order for LPM lookup
    uint32_t ip_host = rte_be_to_cpu_32(src_ip);
    uint32_t nexthop;

    // Single LPM lookup returns longest matching prefix
    int ret = rte_lpm_lookup(g_lpm_v4, ip_host, &nexthop);

    if (ret != 0) {
        // No match in any list
        return IP_LIST_ACTION_NONE;
    }

    // Decode nexthop to determine list type and tenant
    ip_list_type_t list_type = IP_LIST_UNPACK_TYPE(nexthop);
    tenant_id_t entry_tenant = IP_LIST_UNPACK_TENANT(nexthop);

    result->matched = true;
    result->list_type = list_type;
    result->tenant_id = entry_tenant;

    // Determine action based on list type and tenant matching
    switch (list_type) {
        case IP_LIST_GLOBAL_BLACKLIST:
            // Global blacklist always blocks
            result->action = IP_LIST_ACTION_BLOCK;
            atomic_fetch_add(&g_global_stats[IP_LIST_GLOBAL_BLACKLIST].hits, 1);
            atomic_fetch_add(&g_global_stats[IP_LIST_GLOBAL_BLACKLIST].blocks, 1);
            break;

        case IP_LIST_GLOBAL_WHITELIST:
            // Global whitelist always allows
            result->action = IP_LIST_ACTION_ALLOW;
            atomic_fetch_add(&g_global_stats[IP_LIST_GLOBAL_WHITELIST].hits, 1);
            atomic_fetch_add(&g_global_stats[IP_LIST_GLOBAL_WHITELIST].allows, 1);
            break;

        case IP_LIST_TENANT_BLACKLIST:
            // Tenant blacklist only applies to that tenant
            if (entry_tenant == tenant_id) {
                result->action = IP_LIST_ACTION_BLOCK;
                // Bounds check tenant_id before array access
                if (tenant_id < MAX_TENANTS && g_tenant_stats[tenant_id]) {
                    atomic_fetch_add(&g_tenant_stats[tenant_id]->blacklist.hits, 1);
                    atomic_fetch_add(&g_tenant_stats[tenant_id]->blacklist.blocks, 1);
                }
            } else {
                // Entry belongs to different tenant, no match
                result->matched = false;
                result->action = IP_LIST_ACTION_NONE;
            }
            break;

        case IP_LIST_TENANT_WHITELIST:
            // Tenant whitelist only applies to that tenant
            if (entry_tenant == tenant_id) {
                result->action = IP_LIST_ACTION_ALLOW;
                // Bounds check tenant_id before array access
                if (tenant_id < MAX_TENANTS && g_tenant_stats[tenant_id]) {
                    atomic_fetch_add(&g_tenant_stats[tenant_id]->whitelist.hits, 1);
                    atomic_fetch_add(&g_tenant_stats[tenant_id]->whitelist.allows, 1);
                }
            } else {
                result->matched = false;
                result->action = IP_LIST_ACTION_NONE;
            }
            break;

        default:
            result->action = IP_LIST_ACTION_NONE;
            break;
    }

    return result->action;
}

uint8_t tenant_ip_check(tenant_id_t tenant_id, uint32_t src_ip,
                        struct ip_list_result *result) {
    // Update lookup stats
    // Bounds check tenant_id before array access
    if (tenant_id != TENANT_ID_INVALID && tenant_id < MAX_TENANTS && g_tenant_stats[tenant_id]) {
        atomic_fetch_add(&g_tenant_stats[tenant_id]->blacklist.lookups, 1);
    }

    return __tenant_ip_check_internal(tenant_id, src_ip, result);
}

uint8_t tenant_ip6_check(tenant_id_t tenant_id, const uint8_t *src_ip6,
                         struct ip_list_result *result) {
    result->matched = false;
    result->list_type = IP_LIST_GLOBAL_BLACKLIST;
    result->tenant_id = TENANT_ID_INVALID;
    result->action = IP_LIST_ACTION_NONE;
    result->prefix_len = 0;

    if (!g_lpm_v6 || !src_ip6) {
        return IP_LIST_ACTION_NONE;
    }

    uint32_t nexthop;
    int ret = rte_lpm6_lookup(g_lpm_v6, (const struct rte_ipv6_addr *)src_ip6, &nexthop);

    if (ret != 0) {
        return IP_LIST_ACTION_NONE;
    }

    // Decode and process (same logic as IPv4)
    ip_list_type_t list_type = IP_LIST_UNPACK_TYPE(nexthop);
    tenant_id_t entry_tenant = IP_LIST_UNPACK_TENANT(nexthop);

    result->matched = true;
    result->list_type = list_type;
    result->tenant_id = entry_tenant;

    switch (list_type) {
        case IP_LIST_GLOBAL_BLACKLIST:
            result->action = IP_LIST_ACTION_BLOCK;
            break;
        case IP_LIST_GLOBAL_WHITELIST:
            result->action = IP_LIST_ACTION_ALLOW;
            break;
        case IP_LIST_TENANT_BLACKLIST:
            if (entry_tenant == tenant_id) {
                result->action = IP_LIST_ACTION_BLOCK;
            }
            break;
        case IP_LIST_TENANT_WHITELIST:
            if (entry_tenant == tenant_id) {
                result->action = IP_LIST_ACTION_ALLOW;
            }
            break;
        default:
            break;
    }

    return result->action;
}

// ==================== List Management ====================

/**
 * Find entry slot for new entry
 */
static int find_entry_slot(void) {
    if (g_entry_count >= MAX_ENTRIES_TOTAL) {
        return -1;
    }

    // Simple linear allocation (could optimize with free list)
    while (g_entry_next_index < MAX_ENTRIES_TOTAL) {
        if (g_entries[g_entry_next_index].prefix_len == 0 &&
            g_entries[g_entry_next_index].added_at == 0) {
            return g_entry_next_index++;
        }
        g_entry_next_index++;
    }

    // Wrap around and search from beginning
    for (uint32_t i = 0; i < MAX_ENTRIES_TOTAL; i++) {
        if (g_entries[i].prefix_len == 0 && g_entries[i].added_at == 0) {
            g_entry_next_index = i + 1;
            return i;
        }
    }

    return -1;
}

int tenant_ip_list_add(ip_list_type_t list_type,
                       tenant_id_t tenant_id,
                       uint32_t ip,
                       uint8_t prefix_len,
                       uint32_t expires_sec,
                       const char *comment) {
    if (!g_initialized || list_type >= IP_LIST_TYPE_COUNT) {
        return -1;
    }

    // Validate tenant for tenant-specific lists
    if ((list_type == IP_LIST_TENANT_BLACKLIST || list_type == IP_LIST_TENANT_WHITELIST) &&
        tenant_id == TENANT_ID_INVALID) {
        return -1;
    }

    // For global lists, tenant_id should be TENANT_ID_INVALID
    if ((list_type == IP_LIST_GLOBAL_BLACKLIST || list_type == IP_LIST_GLOBAL_WHITELIST) &&
        tenant_id != TENANT_ID_INVALID) {
        tenant_id = TENANT_ID_INVALID;
    }

    if (prefix_len > 32) {
        prefix_len = 32;
    }

    rte_spinlock_lock(&g_list_lock);

    // Find entry slot
    int slot = find_entry_slot();
    if (slot < 0) {
        rte_spinlock_unlock(&g_list_lock);
        RTE_LOG(ERR, USER1, "IP list full, cannot add entry\n");
        return -1;
    }

    // Pack nexthop value
    uint32_t nexthop = IP_LIST_PACK_NEXTHOP(list_type, tenant_id, slot & 0xFFF);

    // Convert to host byte order for LPM
    uint32_t ip_host = rte_be_to_cpu_32(ip);

    // Add to LPM
    int ret = rte_lpm_add(g_lpm_v4, ip_host, prefix_len, nexthop);
    if (ret < 0) {
        rte_spinlock_unlock(&g_list_lock);
        RTE_LOG(ERR, USER1, "Failed to add IP to LPM: %d\n", ret);
        return -1;
    }

    // Store entry metadata
    struct ip_list_entry *entry = &g_entries[slot];
    entry->addr.ipv4 = ip;
    entry->prefix_len = prefix_len;
    entry->is_ipv6 = 0;
    entry->list_type = list_type;
    entry->tenant_id = tenant_id;
    entry->added_at = rte_rdtsc();
    entry->expires_at = expires_sec > 0 ? (entry->added_at + expires_sec * g_tsc_hz) : 0;
    entry->hit_count = 0;

    if (comment && comment[0]) {
        strncpy(entry->comment, comment, sizeof(entry->comment) - 1);
        entry->comment[sizeof(entry->comment) - 1] = '\0';
    } else {
        entry->comment[0] = '\0';
    }

    g_entry_count++;

    // Update stats
    if (list_type == IP_LIST_GLOBAL_BLACKLIST || list_type == IP_LIST_GLOBAL_WHITELIST) {
        atomic_fetch_add(&g_global_stats[list_type].entry_count, 1);
    } else if (tenant_id < MAX_TENANTS && g_tenant_stats[tenant_id]) {
        if (list_type == IP_LIST_TENANT_BLACKLIST) {
            atomic_fetch_add(&g_tenant_stats[tenant_id]->blacklist.entry_count, 1);
        } else {
            atomic_fetch_add(&g_tenant_stats[tenant_id]->whitelist.entry_count, 1);
        }
    }

    rte_spinlock_unlock(&g_list_lock);

    return 0;
}

int tenant_ip6_list_add(ip_list_type_t list_type,
                        tenant_id_t tenant_id,
                        const uint8_t *ip6,
                        uint8_t prefix_len,
                        uint32_t expires_sec,
                        const char *comment) {
    if (!g_initialized || !ip6 || list_type >= IP_LIST_TYPE_COUNT) {
        return -1;
    }

    if (prefix_len > 128) {
        prefix_len = 128;
    }

    rte_spinlock_lock(&g_list_lock);

    int slot = find_entry_slot();
    if (slot < 0) {
        rte_spinlock_unlock(&g_list_lock);
        return -1;
    }

    uint32_t nexthop = IP_LIST_PACK_NEXTHOP(list_type, tenant_id, slot & 0xFFF);

    int ret = rte_lpm6_add(g_lpm_v6, (const struct rte_ipv6_addr *)ip6, prefix_len, nexthop);
    if (ret < 0) {
        rte_spinlock_unlock(&g_list_lock);
        return -1;
    }

    struct ip_list_entry *entry = &g_entries[slot];
    memcpy(entry->addr.ipv6, ip6, 16);
    entry->prefix_len = prefix_len;
    entry->is_ipv6 = 1;
    entry->list_type = list_type;
    entry->tenant_id = tenant_id;
    entry->added_at = rte_rdtsc();
    entry->expires_at = expires_sec > 0 ? (entry->added_at + expires_sec * g_tsc_hz) : 0;

    if (comment) {
        strncpy(entry->comment, comment, sizeof(entry->comment) - 1);
    }

    g_entry_count++;

    rte_spinlock_unlock(&g_list_lock);

    return 0;
}

int tenant_ip_list_remove(ip_list_type_t list_type,
                          tenant_id_t tenant_id,
                          uint32_t ip,
                          uint8_t prefix_len) {
    if (!g_initialized) {
        return -1;
    }

    rte_spinlock_lock(&g_list_lock);

    uint32_t ip_host = rte_be_to_cpu_32(ip);

    // Remove from LPM
    int ret = rte_lpm_delete(g_lpm_v4, ip_host, prefix_len);
    if (ret < 0) {
        rte_spinlock_unlock(&g_list_lock);
        return -1;
    }

    // Find and clear entry
    for (uint32_t i = 0; i < MAX_ENTRIES_TOTAL; i++) {
        struct ip_list_entry *entry = &g_entries[i];
        if (!entry->is_ipv6 &&
            entry->addr.ipv4 == ip &&
            entry->prefix_len == prefix_len &&
            entry->list_type == list_type &&
            entry->tenant_id == tenant_id) {
            memset(entry, 0, sizeof(*entry));
            g_entry_count--;

            // Update stats
            if (list_type == IP_LIST_GLOBAL_BLACKLIST || list_type == IP_LIST_GLOBAL_WHITELIST) {
                atomic_fetch_sub(&g_global_stats[list_type].entry_count, 1);
            } else if (tenant_id < MAX_TENANTS && g_tenant_stats[tenant_id]) {
                if (list_type == IP_LIST_TENANT_BLACKLIST) {
                    atomic_fetch_sub(&g_tenant_stats[tenant_id]->blacklist.entry_count, 1);
                } else {
                    atomic_fetch_sub(&g_tenant_stats[tenant_id]->whitelist.entry_count, 1);
                }
            }

            break;
        }
    }

    rte_spinlock_unlock(&g_list_lock);

    return 0;
}

int tenant_ip6_list_remove(ip_list_type_t list_type,
                           tenant_id_t tenant_id,
                           const uint8_t *ip6,
                           uint8_t prefix_len) {
    if (!g_initialized || !ip6) {
        return -1;
    }

    rte_spinlock_lock(&g_list_lock);

    int ret = rte_lpm6_delete(g_lpm_v6, (const struct rte_ipv6_addr *)ip6, prefix_len);
    if (ret < 0) {
        rte_spinlock_unlock(&g_list_lock);
        return -1;
    }

    // Find and clear entry
    for (uint32_t i = 0; i < MAX_ENTRIES_TOTAL; i++) {
        struct ip_list_entry *entry = &g_entries[i];
        if (entry->is_ipv6 &&
            memcmp(entry->addr.ipv6, ip6, 16) == 0 &&
            entry->prefix_len == prefix_len &&
            entry->list_type == list_type &&
            entry->tenant_id == tenant_id) {
            memset(entry, 0, sizeof(*entry));
            g_entry_count--;
            break;
        }
    }

    rte_spinlock_unlock(&g_list_lock);

    return 0;
}

bool tenant_ip_list_exists(ip_list_type_t list_type,
                           tenant_id_t tenant_id,
                           uint32_t ip,
                           uint8_t prefix_len) {
    if (!g_initialized) {
        return false;
    }

    rte_spinlock_lock(&g_list_lock);

    for (uint32_t i = 0; i < MAX_ENTRIES_TOTAL; i++) {
        struct ip_list_entry *entry = &g_entries[i];
        if (!entry->is_ipv6 &&
            entry->addr.ipv4 == ip &&
            entry->prefix_len == prefix_len &&
            entry->list_type == list_type &&
            entry->tenant_id == tenant_id) {
            rte_spinlock_unlock(&g_list_lock);
            return true;
        }
    }

    rte_spinlock_unlock(&g_list_lock);
    return false;
}

uint32_t tenant_ip_list_clear(ip_list_type_t list_type, tenant_id_t tenant_id) {
    if (!g_initialized) {
        return 0;
    }

    rte_spinlock_lock(&g_list_lock);

    uint32_t removed = 0;

    for (uint32_t i = 0; i < MAX_ENTRIES_TOTAL; i++) {
        struct ip_list_entry *entry = &g_entries[i];
        if (entry->list_type == list_type && entry->tenant_id == tenant_id && entry->added_at > 0) {
            // Remove from LPM
            if (entry->is_ipv6) {
                rte_lpm6_delete(g_lpm_v6, (const struct rte_ipv6_addr *)entry->addr.ipv6, entry->prefix_len);
            } else {
                uint32_t ip_host = rte_be_to_cpu_32(entry->addr.ipv4);
                rte_lpm_delete(g_lpm_v4, ip_host, entry->prefix_len);
            }

            memset(entry, 0, sizeof(*entry));
            removed++;
        }
    }

    g_entry_count -= removed;

    // Update stats
    if (list_type == IP_LIST_GLOBAL_BLACKLIST || list_type == IP_LIST_GLOBAL_WHITELIST) {
        atomic_store(&g_global_stats[list_type].entry_count, 0);
    } else if (tenant_id < MAX_TENANTS && g_tenant_stats[tenant_id]) {
        if (list_type == IP_LIST_TENANT_BLACKLIST) {
            atomic_store(&g_tenant_stats[tenant_id]->blacklist.entry_count, 0);
        } else {
            atomic_store(&g_tenant_stats[tenant_id]->whitelist.entry_count, 0);
        }
    }

    rte_spinlock_unlock(&g_list_lock);

    RTE_LOG(INFO, USER1, "Cleared %u entries from %s (tenant %u)\n",
            removed, ip_list_type_to_string(list_type), tenant_id);

    return removed;
}

// ==================== Bulk Operations ====================

uint32_t tenant_ip_list_add_bulk(ip_list_type_t list_type,
                                 tenant_id_t tenant_id,
                                 const uint32_t *ips,
                                 const uint8_t *prefix_lens,
                                 uint32_t count,
                                 uint32_t expires_sec) {
    if (!g_initialized || !ips || !prefix_lens) {
        return 0;
    }

    uint32_t added = 0;

    for (uint32_t i = 0; i < count; i++) {
        if (tenant_ip_list_add(list_type, tenant_id, ips[i], prefix_lens[i],
                               expires_sec, NULL) == 0) {
            added++;
        }
    }

    return added;
}

int tenant_ip_list_load_file(ip_list_type_t list_type,
                             tenant_id_t tenant_id,
                             const char *filepath) {
    if (!g_initialized || !filepath) {
        return -1;
    }

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        RTE_LOG(ERR, USER1, "Failed to open IP list file: %s\n", filepath);
        return -1;
    }

    char line[256];
    int loaded = 0;

    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') {
            continue;
        }

        // Remove newline
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';

        // Parse IP/CIDR
        uint32_t ip;
        uint8_t prefix;
        if (parse_ip_cidr(p, &ip, &prefix) == 0) {
            if (tenant_ip_list_add(list_type, tenant_id, ip, prefix, 0, NULL) == 0) {
                loaded++;
            }
        }
    }

    fclose(fp);

    RTE_LOG(INFO, USER1, "Loaded %d entries from %s into %s\n",
            loaded, filepath, ip_list_type_to_string(list_type));

    return loaded;
}

int tenant_ip_list_save_file(ip_list_type_t list_type,
                             tenant_id_t tenant_id,
                             const char *filepath) {
    if (!g_initialized || !filepath) {
        return -1;
    }

    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        return -1;
    }

    fprintf(fp, "# %s for tenant %u\n", ip_list_type_to_string(list_type), tenant_id);
    fprintf(fp, "# Generated at TSC: %lu\n\n", rte_rdtsc());

    rte_spinlock_lock(&g_list_lock);

    for (uint32_t i = 0; i < MAX_ENTRIES_TOTAL; i++) {
        struct ip_list_entry *entry = &g_entries[i];
        if (entry->list_type == list_type &&
            entry->tenant_id == tenant_id &&
            entry->added_at > 0 &&
            !entry->is_ipv6) {
            char buf[32];
            if (format_ip_cidr(entry->addr.ipv4, entry->prefix_len, buf, sizeof(buf))) {
                fprintf(fp, "%s", buf);
                if (entry->comment[0]) {
                    fprintf(fp, " # %s", entry->comment);
                }
                fprintf(fp, "\n");
            }
        }
    }

    rte_spinlock_unlock(&g_list_lock);

    fclose(fp);
    return 0;
}

// ==================== Statistics ====================

int tenant_ip_list_get_stats(ip_list_type_t list_type,
                             tenant_id_t tenant_id,
                             struct ip_list_stats *out_stats) {
    if (!out_stats || list_type >= IP_LIST_TYPE_COUNT) {
        return -1;
    }

    if (list_type == IP_LIST_GLOBAL_BLACKLIST || list_type == IP_LIST_GLOBAL_WHITELIST) {
        out_stats->lookups = atomic_load(&g_global_stats[list_type].lookups);
        out_stats->hits = atomic_load(&g_global_stats[list_type].hits);
        out_stats->blocks = atomic_load(&g_global_stats[list_type].blocks);
        out_stats->allows = atomic_load(&g_global_stats[list_type].allows);
        out_stats->entry_count = atomic_load(&g_global_stats[list_type].entry_count);
    } else if (tenant_id < MAX_TENANTS && g_tenant_stats[tenant_id]) {
        struct ip_list_stats *src = (list_type == IP_LIST_TENANT_BLACKLIST)
            ? &g_tenant_stats[tenant_id]->blacklist
            : &g_tenant_stats[tenant_id]->whitelist;
        out_stats->lookups = atomic_load(&src->lookups);
        out_stats->hits = atomic_load(&src->hits);
        out_stats->blocks = atomic_load(&src->blocks);
        out_stats->allows = atomic_load(&src->allows);
        out_stats->entry_count = atomic_load(&src->entry_count);
    } else {
        memset(out_stats, 0, sizeof(*out_stats));
    }

    return 0;
}

int tenant_ip_list_get_tenant_stats(tenant_id_t tenant_id,
                                    struct tenant_ip_list_stats *out_stats) {
    if (!out_stats || tenant_id >= MAX_TENANTS) {
        return -1;
    }

    if (g_tenant_stats[tenant_id]) {
        tenant_ip_list_get_stats(IP_LIST_TENANT_BLACKLIST, tenant_id, &out_stats->blacklist);
        tenant_ip_list_get_stats(IP_LIST_TENANT_WHITELIST, tenant_id, &out_stats->whitelist);
    } else {
        memset(out_stats, 0, sizeof(*out_stats));
    }

    return 0;
}

void tenant_ip_list_reset_stats(ip_list_type_t list_type, tenant_id_t tenant_id) {
    if (list_type == IP_LIST_GLOBAL_BLACKLIST || list_type == IP_LIST_GLOBAL_WHITELIST) {
        atomic_store(&g_global_stats[list_type].lookups, 0);
        atomic_store(&g_global_stats[list_type].hits, 0);
        atomic_store(&g_global_stats[list_type].blocks, 0);
        atomic_store(&g_global_stats[list_type].allows, 0);
    } else if (tenant_id < MAX_TENANTS && g_tenant_stats[tenant_id]) {
        struct ip_list_stats *stats = (list_type == IP_LIST_TENANT_BLACKLIST)
            ? &g_tenant_stats[tenant_id]->blacklist
            : &g_tenant_stats[tenant_id]->whitelist;
        atomic_store(&stats->lookups, 0);
        atomic_store(&stats->hits, 0);
        atomic_store(&stats->blocks, 0);
        atomic_store(&stats->allows, 0);
    }
}

uint32_t tenant_ip_list_count(ip_list_type_t list_type, tenant_id_t tenant_id) {
    if (list_type == IP_LIST_GLOBAL_BLACKLIST || list_type == IP_LIST_GLOBAL_WHITELIST) {
        return atomic_load(&g_global_stats[list_type].entry_count);
    } else if (tenant_id < MAX_TENANTS && g_tenant_stats[tenant_id]) {
        if (list_type == IP_LIST_TENANT_BLACKLIST) {
            return atomic_load(&g_tenant_stats[tenant_id]->blacklist.entry_count);
        } else {
            return atomic_load(&g_tenant_stats[tenant_id]->whitelist.entry_count);
        }
    }
    return 0;
}

// ==================== Iteration ====================

uint32_t tenant_ip_list_iterate(ip_list_type_t list_type,
                                tenant_id_t tenant_id,
                                ip_list_iter_fn callback,
                                void *user_data) {
    if (!g_initialized || !callback) {
        return 0;
    }

    rte_spinlock_lock(&g_list_lock);

    uint32_t count = 0;
    for (uint32_t i = 0; i < MAX_ENTRIES_TOTAL; i++) {
        struct ip_list_entry *entry = &g_entries[i];
        if (entry->list_type == list_type &&
            entry->tenant_id == tenant_id &&
            entry->added_at > 0) {
            count++;
            if (!callback(entry, user_data)) {
                break;
            }
        }
    }

    rte_spinlock_unlock(&g_list_lock);

    return count;
}

// ==================== Maintenance ====================

uint32_t tenant_ip_list_expire_entries(void) {
    if (!g_initialized) {
        return 0;
    }

    uint64_t now = rte_rdtsc();
    uint32_t expired = 0;

    rte_spinlock_lock(&g_list_lock);

    for (uint32_t i = 0; i < MAX_ENTRIES_TOTAL; i++) {
        struct ip_list_entry *entry = &g_entries[i];
        if (entry->expires_at > 0 && entry->expires_at < now) {
            // Remove from LPM
            if (entry->is_ipv6) {
                rte_lpm6_delete(g_lpm_v6, (const struct rte_ipv6_addr *)entry->addr.ipv6, entry->prefix_len);
            } else {
                uint32_t ip_host = rte_be_to_cpu_32(entry->addr.ipv4);
                rte_lpm_delete(g_lpm_v4, ip_host, entry->prefix_len);
            }

            // Update stats
            ip_list_type_t lt = entry->list_type;
            tenant_id_t tid = entry->tenant_id;
            if (lt == IP_LIST_GLOBAL_BLACKLIST || lt == IP_LIST_GLOBAL_WHITELIST) {
                atomic_fetch_sub(&g_global_stats[lt].entry_count, 1);
            } else if (tid < MAX_TENANTS && g_tenant_stats[tid]) {
                if (lt == IP_LIST_TENANT_BLACKLIST) {
                    atomic_fetch_sub(&g_tenant_stats[tid]->blacklist.entry_count, 1);
                } else {
                    atomic_fetch_sub(&g_tenant_stats[tid]->whitelist.entry_count, 1);
                }
            }

            memset(entry, 0, sizeof(*entry));
            expired++;
        }
    }

    if (expired > 0) {
        g_entry_count -= expired;
        RTE_LOG(DEBUG, USER1, "Expired %u IP list entries\n", expired);
    }

    rte_spinlock_unlock(&g_list_lock);

    return expired;
}

void tenant_ip_list_rebuild(void) {
    // LPM tables are self-optimizing, no explicit rebuild needed
    RTE_LOG(DEBUG, USER1, "IP list rebuild requested (no-op for LPM)\n");
}

// ==================== Utility Functions ====================

int parse_ip_cidr(const char *str, uint32_t *out_ip, uint8_t *out_prefix) {
    if (!str || !out_ip || !out_prefix) {
        return -1;
    }

    char buf[64];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    uint8_t prefix = 32;

    if (slash) {
        *slash = '\0';
        prefix = (uint8_t)atoi(slash + 1);
        if (prefix > 32) {
            prefix = 32;
        }
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        return -1;
    }

    *out_ip = addr.s_addr;  // Already in network byte order
    *out_prefix = prefix;

    return 0;
}

char* format_ip_cidr(uint32_t ip, uint8_t prefix, char *buf, size_t buf_len) {
    if (!buf || buf_len < 20) {
        return NULL;
    }

    struct in_addr addr;
    addr.s_addr = ip;
    char ip_str[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)) == NULL) {
        return NULL;
    }

    snprintf(buf, buf_len, "%s/%u", ip_str, prefix);
    return buf;
}
