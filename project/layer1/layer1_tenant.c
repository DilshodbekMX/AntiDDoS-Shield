/**
 * @file layer1_tenant.c
 * @brief Multi-Tenant Support for Layer 1 Packet Processing
 *
 * Implements tenant-aware packet processing with:
 * - Fast IP-to-tenant resolution using LPM
 * - Per-lcore config caching for lock-free fast path
 * - Hierarchical rate limiting (global -> tenant -> protocol -> source)
 * - Per-tenant IP allow/block lists
 * - Tenant isolation and quota enforcement
 *
 * Performance Target: <20 cycles overhead for tenant resolution
 */

#include "layer1.h"
#include "tables/tenant_rate_limit.h"
#include "tables/tenant_ip_lists.h"
#include "../common/tenant.h"
#include "../common/tenant_config.h"

#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include <string.h>

// ==================== Per-lcore Config Cache ====================

/**
 * Per-lcore cached tenant configuration
 * Updated periodically from main config
 */
struct lcore_tenant_cache {
    uint64_t version;                                    // Config version
    uint64_t last_update_tsc;                           // Last update time
    const struct tenant_l1_config *configs[MAX_TENANTS]; // Cached config pointers
    uint8_t tenant_status[MAX_TENANTS];                 // Cached tenant status
    bool initialized;
};

// Per-lcore cache (one per lcore)
static struct lcore_tenant_cache *g_lcore_cache[RTE_MAX_LCORE];

// Global config version (incremented on any config change)
static _Atomic uint64_t g_config_version = 1;

// Tenant stats aggregation
static struct layer1_tenant_stats g_tenant_stats[MAX_TENANTS];

// Global stats
static _Atomic uint64_t g_tenant_lookups = 0;
static _Atomic uint64_t g_tenant_lookup_hits = 0;
static _Atomic uint64_t g_tenant_lookup_misses = 0;

// Initialization state
static _Atomic bool g_tenant_system_initialized = false;

// ==================== Initialization ====================

int layer1_tenant_init(void) {
    if (atomic_load(&g_tenant_system_initialized)) {
        return 0;
    }

    // Initialize tenant registry
    if (tenant_registry_init() != 0) {
        RTE_LOG(ERR, USER1, "Failed to initialize tenant registry\n");
        return -1;
    }

    // Initialize tenant config system
    if (tenant_config_init() != 0) {
        RTE_LOG(ERR, USER1, "Failed to initialize tenant config\n");
        tenant_registry_cleanup();
        return -1;
    }

    // Initialize rate limiting subsystem
    if (tenant_rate_limit_init() != 0) {
        RTE_LOG(ERR, USER1, "Failed to initialize tenant rate limiting\n");
        tenant_config_cleanup();
        tenant_registry_cleanup();
        return -1;
    }

    // Initialize IP lists subsystem
    if (tenant_ip_lists_init() != 0) {
        RTE_LOG(ERR, USER1, "Failed to initialize tenant IP lists\n");
        tenant_rate_limit_cleanup();
        tenant_config_cleanup();
        tenant_registry_cleanup();
        return -1;
    }

    // Initialize per-lcore caches
    memset(g_lcore_cache, 0, sizeof(g_lcore_cache));

    // Initialize per-tenant stats
    memset(g_tenant_stats, 0, sizeof(g_tenant_stats));

    atomic_store(&g_tenant_system_initialized, true);

    RTE_LOG(INFO, USER1, "Layer 1 multi-tenant system initialized\n");
    return 0;
}

void layer1_tenant_cleanup(void) {
    if (!atomic_load(&g_tenant_system_initialized)) {
        return;
    }

    // Set initialized flag to false FIRST with release semantics
    // This prevents new packet processing from starting while we cleanup
    atomic_store_explicit(&g_tenant_system_initialized, false, memory_order_release);

    // Memory barrier to ensure flag is visible to all lcores before cleanup
    rte_mb();

    // Brief wait to allow in-flight packet processing to complete
    // In production, this should coordinate with lcore shutdown
    rte_delay_us_block(1000);  // 1ms grace period

    // Now safe to cleanup per-lcore caches
    for (unsigned i = 0; i < RTE_MAX_LCORE; i++) {
        if (g_lcore_cache[i]) {
            rte_free(g_lcore_cache[i]);
            g_lcore_cache[i] = NULL;
        }
    }

    // Cleanup subsystems in reverse order
    tenant_ip_lists_cleanup();
    tenant_rate_limit_cleanup();
    tenant_config_cleanup();
    tenant_registry_cleanup();

    RTE_LOG(INFO, USER1, "Layer 1 multi-tenant system cleaned up\n");
}

// ==================== Per-lcore Cache Management ====================

/**
 * Initialize per-lcore cache for current lcore
 */
static int init_lcore_cache(void) {
    unsigned lcore_id = rte_lcore_id();

    if (g_lcore_cache[lcore_id]) {
        return 0;  // Already initialized
    }

    struct lcore_tenant_cache *cache = rte_zmalloc_socket(
        "lcore_tenant_cache",
        sizeof(struct lcore_tenant_cache),
        RTE_CACHE_LINE_SIZE,
        rte_lcore_to_socket_id(lcore_id)
    );

    if (!cache) {
        RTE_LOG(ERR, USER1, "Failed to allocate lcore cache for lcore %u\n", lcore_id);
        return -1;
    }

    cache->initialized = true;
    cache->version = 0;  // Force update on first access
    g_lcore_cache[lcore_id] = cache;

    return 0;
}

/**
 * Update per-lcore cache from global config
 * Called periodically or when version mismatch detected
 */
static void update_lcore_cache(struct lcore_tenant_cache *cache) {
    uint64_t global_version = atomic_load(&g_config_version);

    if (cache->version == global_version) {
        return;  // Already up to date
    }

    // Update all tenant configs
    for (tenant_id_t tid = 0; tid < MAX_TENANTS; tid++) {
        const struct tenant *tenant = tenant_lookup(tid);
        if (tenant && tenant->status == TENANT_STATUS_ACTIVE) {
            cache->configs[tid] = tenant_get_l1_config(tid);
            cache->tenant_status[tid] = tenant->status;
        } else {
            cache->configs[tid] = NULL;
            cache->tenant_status[tid] = tenant ? tenant->status : TENANT_STATUS_DISABLED;
        }
    }

    cache->version = global_version;
    cache->last_update_tsc = rte_rdtsc();
}

bool layer1_tenant_cache_update(void) {
    // Increment global version to trigger cache updates
    atomic_fetch_add(&g_config_version, 1);
    return true;
}

// ==================== Tenant Resolution ====================

tenant_id_t layer1_resolve_tenant(uint32_t dst_ip,
                                  uint8_t *out_tier,
                                  uint8_t *out_status) {
    atomic_fetch_add(&g_tenant_lookups, 1);

    tenant_id_t tenant_id = tenant_ip_to_id(dst_ip);

    if (tenant_id != TENANT_ID_INVALID) {
        atomic_fetch_add(&g_tenant_lookup_hits, 1);
        // Get tier and status from tenant if requested
        if (out_tier || out_status) {
            const struct tenant *t = tenant_lookup(tenant_id);
            if (t) {
                if (out_tier) *out_tier = (uint8_t)t->tier;
                if (out_status) *out_status = (uint8_t)t->status;
            }
        }
    } else {
        atomic_fetch_add(&g_tenant_lookup_misses, 1);
        if (out_tier) *out_tier = 0;
        if (out_status) *out_status = 0;
    }

    return tenant_id;
}

// ==================== Fast Path: Tenant-Aware Packet Processing ====================

/**
 * Apply tenant-specific checks to packet
 *
 * @param tenant_id  Resolved tenant ID
 * @param src_ip     Source IP (network byte order)
 * @param dst_ip     Destination IP (network byte order)
 * @param protocol   IP protocol
 * @param pkt_len    Packet length
 * @param tcp_flags  TCP flags (0 for non-TCP)
 * @param result     Output: L1 result with tenant context
 * @return true if packet allowed, false if dropped
 */
static bool apply_tenant_checks(tenant_id_t tenant_id,
                                uint32_t src_ip,
                                uint32_t dst_ip __rte_unused,
                                uint8_t protocol,
                                uint16_t pkt_len,
                                uint8_t tcp_flags,
                                struct layer1_result *result) {
    // Bounds check on tenant_id before any array access
    if (unlikely(tenant_id >= MAX_TENANTS)) {
        result->drop_reason = DROP_REASON_NOT_PROTECTED;
        return false;
    }

    unsigned lcore_id = rte_lcore_id();
    struct lcore_tenant_cache *cache = g_lcore_cache[lcore_id];

    // Ensure cache is initialized
    if (!cache) {
        if (init_lcore_cache() != 0) {
            result->drop_reason = DROP_REASON_NOT_PROTECTED;
            return false;
        }
        cache = g_lcore_cache[lcore_id];
    }

    // Check if cache needs update (every ~1ms or 1M cycles)
    uint64_t now_tsc = rte_rdtsc();
    if ((now_tsc - cache->last_update_tsc) > 1000000 ||
        cache->version != atomic_load(&g_config_version)) {
        update_lcore_cache(cache);
    }

    // Fill in tenant context
    result->tenant_id = tenant_id;
    result->flags |= L1_RESULT_FLAG_TENANT_RESOLVED;

    // Check tenant status (bounds already validated above)
    uint8_t status = cache->tenant_status[tenant_id];
    result->tenant_status = status;

    if (status == TENANT_STATUS_SUSPENDED) {
        result->drop_reason = DROP_REASON_TENANT_SUSPENDED;
        atomic_fetch_add(&g_tenant_stats[tenant_id].drop_other, 1);
        return false;
    }

    if (status != TENANT_STATUS_ACTIVE) {
        result->drop_reason = DROP_REASON_TENANT_DISABLED;
        return false;
    }

    // Get tenant config (from cache)
    const struct tenant_l1_config *config = cache->configs[tenant_id];
    if (!config) {
        // No config, use defaults (or reject if strict)
        result->drop_reason = DROP_REASON_NOT_PROTECTED;
        return false;
    }

    result->flags |= L1_RESULT_FLAG_TENANT_CONFIG;
    // Get tier from cached tenant status in result (set by caller)

    // ===== Check 1: IP Lists =====
    struct ip_list_result ip_result;
    uint8_t ip_action = tenant_ip_check(tenant_id, src_ip, &ip_result);

    if (ip_action == IP_LIST_ACTION_BLOCK) {
        result->drop_reason = DROP_REASON_TENANT_BLACKLIST;
        atomic_fetch_add(&g_tenant_stats[tenant_id].drop_blacklist, 1);
        return false;
    }

    if (ip_action == IP_LIST_ACTION_ALLOW) {
        // Whitelisted, skip rate limiting
        return true;
    }

    // ===== Check 2: Rate Limiting =====
    struct rate_check_result rate_result;
    if (!tenant_rate_check(tenant_id, src_ip, protocol, pkt_len, tcp_flags, &rate_result)) {
        result->drop_reason = DROP_REASON_TENANT_RATE_LIMIT;
        atomic_fetch_add(&g_tenant_stats[tenant_id].drop_rate_limit, 1);
        return false;
    }

    // Don't increment packets_accepted here - that happens only
    // after ALL checks pass (including layer1_process_packet). Counting here
    // causes double-counting when layer1_process_packet drops the packet.
    // We only track bytes_total for bandwidth accounting (consumed even if dropped later)
    atomic_fetch_add(&g_tenant_stats[tenant_id].bytes_total, pkt_len);

    return true;
}

int layer1_process_packet_tenant(struct rte_mbuf *pkt,
                                 uint16_t port_id,
                                 uint16_t queue_id __rte_unused,
                                 struct rte_mempool *mempool __rte_unused,
                                 struct layer1_result *result) {
    if (!atomic_load(&g_tenant_system_initialized)) {
        // Multi-tenant not initialized, process normally
        return layer1_process_packet(pkt, port_id);
    }

    // Parse IP header to get addresses
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

    // Only handle IPv4 for now
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        // Non-IPv4, process normally (tenant = none)
        result->tenant_id = TENANT_ID_INVALID;
        return layer1_process_packet(pkt, port_id);
    }

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    uint32_t src_ip = ip->src_addr;
    uint32_t dst_ip = ip->dst_addr;
    uint8_t protocol = ip->next_proto_id;
    uint16_t pkt_len = rte_pktmbuf_pkt_len(pkt);

    // Extract TCP flags if applicable
    uint8_t tcp_flags = 0;
    if (protocol == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + (ip->ihl * 4));
        tcp_flags = tcp->tcp_flags;
    }

    // ===== Step 1: Resolve tenant from destination IP =====
    tenant_id_t tenant_id;

    // Single-tenant optimization: when only 1 tenant exists, we can skip
    // the tenant_lookup() call after LPM validation since we already know
    // the tenant. We MUST still validate dst_ip via LPM to ensure it's
    // in the tenant's protected networks (previously this validation was skipped)
    if (likely(tenant_is_single_mode())) {
        tenant_id_t default_tid = tenant_get_default_id();
        // Still validate dst_ip is protected - use LPM lookup
        tenant_id = tenant_ip_to_id(dst_ip);
        atomic_fetch_add(&g_tenant_lookups, 1);

        if (tenant_id != TENANT_ID_INVALID) {
            // Verify it matches expected tenant (should always match in single-tenant mode)
            if (tenant_id == default_tid) {
                const struct tenant *t = tenant_lookup(tenant_id);
                if (t) {
                    result->tenant_tier = (uint8_t)t->tier;
                    result->tenant_status = (uint8_t)t->status;
                }
                atomic_fetch_add(&g_tenant_lookup_hits, 1);
            } else {
                // Unexpected: IP belongs to different tenant than default
                // This shouldn't happen in single-tenant mode
                tenant_id = TENANT_ID_INVALID;
                atomic_fetch_add(&g_tenant_lookup_misses, 1);
            }
        } else {
            atomic_fetch_add(&g_tenant_lookup_misses, 1);
        }
    } else {
        // Multi-tenant mode: full LPM-based resolution
        tenant_id = layer1_resolve_tenant(dst_ip,
                                          &result->tenant_tier,
                                          &result->tenant_status);
    }

    if (tenant_id == TENANT_ID_INVALID) {
        // Not a protected IP, drop or forward based on config
        result->drop_reason = DROP_REASON_NOT_PROTECTED;
        result->action = L1_ACTION_DROP;
        result->tenant_id = TENANT_ID_INVALID;
        atomic_fetch_add(&g_tenant_lookup_misses, 1);
        return -1;
    }

    // ===== Step 2: Apply tenant-specific checks =====
    if (!apply_tenant_checks(tenant_id, src_ip, dst_ip, protocol,
                            pkt_len, tcp_flags, result)) {
        result->action = L1_ACTION_DROP;
        atomic_fetch_add(&g_tenant_stats[tenant_id].packets_dropped, 1);
        return -1;
    }

    // ===== Step 3: Continue with normal L1 processing =====
    // The standard layer1_process_packet will apply:
    // - SYN proxy/cookie validation
    // - Flow table checks
    // - Signature matching
    // - Geo blocking
    // - etc.
    int ret = layer1_process_packet(pkt, port_id);
    result->action = ret;  // Set the result action from return value

    // Track per-tenant stats from standard processing
    if (ret == L1_ACTION_DROP) {
        atomic_fetch_add(&g_tenant_stats[tenant_id].packets_dropped, 1);
        // Categorize the drop
        switch (result->drop_reason) {
            case DROP_REASON_BLACKLIST:
            case DROP_REASON_TENANT_BLACKLIST:
                atomic_fetch_add(&g_tenant_stats[tenant_id].drop_blacklist, 1);
                break;
            case DROP_REASON_GEO_BLOCKED:
                atomic_fetch_add(&g_tenant_stats[tenant_id].drop_other, 1);
                break;
            case DROP_REASON_RATE_LIMIT_SYN:
            case DROP_REASON_RATE_LIMIT_UDP:
            case DROP_REASON_RATE_LIMIT_ICMP:
            case DROP_REASON_RATE_LIMIT_PPS:
            case DROP_REASON_RATE_LIMIT_BPS:
            case DROP_REASON_TENANT_RATE_LIMIT:
                atomic_fetch_add(&g_tenant_stats[tenant_id].drop_rate_limit, 1);
                break;
            case DROP_REASON_CONN_LIMIT:
            case DROP_REASON_CONN_LIMIT_SRC:
            case DROP_REASON_CONN_LIMIT_DST:
            case DROP_REASON_CONN_LIMIT_GLOBAL:
            case DROP_REASON_TENANT_CONN_LIMIT:
                atomic_fetch_add(&g_tenant_stats[tenant_id].drop_conn_limit, 1);
                break;
            // Track SYN flood related drops separately
            case DROP_REASON_SYN_FLOOD:
            case DROP_REASON_COOKIE_INVALID:
            case DROP_REASON_COOKIE_EXPIRED:
            case DROP_REASON_PROXY_ERROR:
            case DROP_REASON_PROXY_NO_CONN:
            case DROP_REASON_SPOOFED_TCP:
                atomic_fetch_add(&g_tenant_stats[tenant_id].drop_syn_flood, 1);
                break;
            default:
                break;
        }
    } else {
        // Only count packets_accepted here, after ALL checks passed
        atomic_fetch_add(&g_tenant_stats[tenant_id].packets_accepted, 1);
    }

    return ret;
}

// ==================== Batch Processing ====================

int layer1_process_packets_tenant_batch(struct rte_mbuf **pkts,
                                        uint16_t nb_pkts,
                                        uint16_t port_id,
                                        struct layer1_result *results) {
    int processed = 0;

    // Process each packet
    for (uint16_t i = 0; i < nb_pkts; i++) {
        int ret = layer1_process_packet_tenant(pkts[i], port_id, 0, NULL, &results[i]);
        if (ret >= 0) {
            processed++;
        }
    }

    return processed;
}

// ==================== Statistics API ====================

int layer1_get_tenant_stats(tenant_id_t tenant_id,
                            struct layer1_tenant_stats *out_stats) {
    if (tenant_id >= MAX_TENANTS || !out_stats) {
        return -1;
    }

    // Copy stats atomically
    out_stats->tenant_id = tenant_id;
    out_stats->packets_accepted = atomic_load(&g_tenant_stats[tenant_id].packets_accepted);
    out_stats->packets_dropped = atomic_load(&g_tenant_stats[tenant_id].packets_dropped);
    out_stats->bytes_total = atomic_load(&g_tenant_stats[tenant_id].bytes_total);
    out_stats->packets_total = out_stats->packets_accepted + out_stats->packets_dropped;
    out_stats->drop_rate_limit = atomic_load(&g_tenant_stats[tenant_id].drop_rate_limit);
    out_stats->drop_blacklist = atomic_load(&g_tenant_stats[tenant_id].drop_blacklist);
    out_stats->drop_conn_limit = atomic_load(&g_tenant_stats[tenant_id].drop_conn_limit);
    out_stats->drop_syn_flood = atomic_load(&g_tenant_stats[tenant_id].drop_syn_flood);
    out_stats->drop_other = atomic_load(&g_tenant_stats[tenant_id].drop_other);

    // Get rate info
    tenant_rate_get_current(tenant_id, &out_stats->current_pps, &out_stats->current_bps);
    tenant_rate_get_peak(tenant_id, &out_stats->peak_pps, &out_stats->peak_bps);

    return 0;
}

void layer1_reset_tenant_stats(tenant_id_t tenant_id) {
    if (tenant_id >= MAX_TENANTS) {
        return;
    }

    atomic_store(&g_tenant_stats[tenant_id].packets_accepted, 0);
    atomic_store(&g_tenant_stats[tenant_id].packets_dropped, 0);
    atomic_store(&g_tenant_stats[tenant_id].packets_total, 0);
    atomic_store(&g_tenant_stats[tenant_id].bytes_total, 0);
    atomic_store(&g_tenant_stats[tenant_id].drop_rate_limit, 0);
    atomic_store(&g_tenant_stats[tenant_id].drop_blacklist, 0);
    atomic_store(&g_tenant_stats[tenant_id].drop_conn_limit, 0);
    atomic_store(&g_tenant_stats[tenant_id].drop_syn_flood, 0);
    atomic_store(&g_tenant_stats[tenant_id].drop_other, 0);

    tenant_rate_reset_stats(tenant_id);
}

// ==================== Per-Tenant IP List Wrappers ====================

int layer1_tenant_blacklist_add(tenant_id_t tenant_id,
                                uint32_t ip, uint8_t prefix_len,
                                uint64_t ttl_sec, const char *reason) {
    return tenant_ip_list_add(IP_LIST_TENANT_BLACKLIST, tenant_id,
                              ip, prefix_len, (uint32_t)ttl_sec, reason);
}

int layer1_tenant_blacklist_remove(tenant_id_t tenant_id,
                                   uint32_t ip, uint8_t prefix_len) {
    return tenant_ip_list_remove(IP_LIST_TENANT_BLACKLIST, tenant_id, ip, prefix_len);
}

int layer1_tenant_whitelist_add(tenant_id_t tenant_id,
                                uint32_t ip, uint8_t prefix_len,
                                uint64_t ttl_sec) {
    return tenant_ip_list_add(IP_LIST_TENANT_WHITELIST, tenant_id,
                              ip, prefix_len, (uint32_t)ttl_sec, NULL);
}

int layer1_tenant_whitelist_remove(tenant_id_t tenant_id,
                                   uint32_t ip, uint8_t prefix_len) {
    return tenant_ip_list_remove(IP_LIST_TENANT_WHITELIST, tenant_id, ip, prefix_len);
}

// ==================== Per-Tenant Rate Limit Wrappers ====================

int layer1_tenant_rate_set(tenant_id_t tenant_id, uint64_t pps, uint64_t bps) {
    return tenant_rate_set_limits(tenant_id, pps, bps);
}

int layer1_tenant_rate_get(tenant_id_t tenant_id,
                           uint64_t *out_pps, uint64_t *out_bps) {
    return tenant_rate_get_current(tenant_id, out_pps, out_bps);
}

// ==================== Global Statistics ====================

void layer1_get_tenant_global_stats(uint64_t *lookups,
                                    uint64_t *hits,
                                    uint64_t *misses) {
    if (lookups) {
        *lookups = atomic_load(&g_tenant_lookups);
    }
    if (hits) {
        *hits = atomic_load(&g_tenant_lookup_hits);
    }
    if (misses) {
        *misses = atomic_load(&g_tenant_lookup_misses);
    }
}

// ==================== Maintenance ====================

void layer1_tenant_maintenance(void) {
    if (!atomic_load(&g_tenant_system_initialized)) {
        return;
    }

    // Run rate limiting maintenance
    tenant_rate_maintenance();

    // Expire old IP list entries
    tenant_ip_list_expire_entries();

    // Age out per-source rate entries
    tenant_rate_age_src_entries();
}
