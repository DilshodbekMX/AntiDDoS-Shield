#include "per_ip_features.h"
#include "hyperloglog.h"
#include "burst_ewma.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_hash_crc.h>
#include <rte_spinlock.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define RTE_LOGTYPE_PERIP RTE_LOGTYPE_USER7

// ==================== Global State ====================

static struct rte_hash *g_perip_hash = NULL;
static struct per_ip_features *g_perip_pool = NULL;
static uint32_t g_max_ips = 0;
static uint32_t g_registered_count = 0;
static bool g_initialized = false;

// Free list for per-IP feature slots
static uint32_t *g_free_slots = NULL;
static uint32_t g_free_count = 0;

// CMS concentration export gate (max_flow_fraction / topk_flow_share / heavy_hitter_count).
// DISABLED by default so the shipped detector is byte-for-byte unchanged: when off, the export
// returns 0 and the per-packet top-K maintenance is skipped (zero cost). Mirrors the opt-in
// gating of the conformal ensemble rule. Toggle via per_ip_features_set_concentration_export().
static bool g_concentration_export_enabled = false;

// ==================== CMS Helper Functions ====================

/**
 * Hash function for CMS using CRC32 with different seeds
 */
static inline uint32_t cms_hash(uint32_t key, uint32_t seed) {
    return rte_hash_crc_4byte(key, seed);
}

/**
 * Initialize CMS for a per-IP structure
 */
static int per_ip_cms_init(struct per_ip_cms *cms) {
    if (!cms) return -1;

    cms->width = PER_IP_CMS_WIDTH;
    cms->depth = PER_IP_CMS_DEPTH;

    // Allocate flat counter array
    size_t counter_size = cms->width * cms->depth * sizeof(uint32_t);
    cms->counters = rte_zmalloc("perip_cms", counter_size, 64);
    if (!cms->counters) {
        return -1;
    }

    // Initialize seeds
    for (uint32_t i = 0; i < cms->depth; i++) {
        cms->seeds[i] = 0x12345678 + i * 0x87654321;
    }

    cms->total_count = 0;
    cms->window_count = 0;

    // Top-K / heavy-hitter concentration tracking
    rte_spinlock_init(&cms->topk_lock);
    cms->topk_n = 0;
    cms->max_flow_count = 0;
    memset(cms->topk_keys, 0, sizeof(cms->topk_keys));
    memset(cms->topk_counts, 0, sizeof(cms->topk_counts));

    return 0;
}

/**
 * Cleanup CMS
 */
static void per_ip_cms_cleanup(struct per_ip_cms *cms) {
    if (cms && cms->counters) {
        rte_free(cms->counters);
        cms->counters = NULL;
    }
}

/**
 * Update the per-window Space-Saving top-K table with a flow's current
 * CMS estimate. O(PER_IP_TOPK_COUNT) under the per-CMS spinlock. Feeds the
 * max_flow_fraction / topk_flow_share / heavy_hitter_count concentration
 * features (section 4.8). Best-effort: the count it stores is the (over-)estimate
 * from the sketch, so downstream shares are clamped to 100%.
 */
static void cms_topk_update(struct per_ip_cms *cms, uint32_t key, uint32_t est) {
    rte_spinlock_lock(&cms->topk_lock);

    if (est > cms->max_flow_count) {
        cms->max_flow_count = est;
    }

    uint32_t min_i = 0;
    uint32_t min_v = UINT32_MAX;
    for (uint32_t i = 0; i < cms->topk_n; i++) {
        if (cms->topk_keys[i] == key) {       // already tracked -> refresh estimate
            cms->topk_counts[i] = est;
            rte_spinlock_unlock(&cms->topk_lock);
            return;
        }
        if (cms->topk_counts[i] < min_v) {
            min_v = cms->topk_counts[i];
            min_i = i;
        }
    }

    if (cms->topk_n < PER_IP_TOPK_COUNT) {    // room -> insert
        cms->topk_keys[cms->topk_n] = key;
        cms->topk_counts[cms->topk_n] = est;
        cms->topk_n++;
    } else if (est > min_v) {                 // full -> evict the smallest slot
        cms->topk_keys[min_i] = key;
        cms->topk_counts[min_i] = est;
    }

    rte_spinlock_unlock(&cms->topk_lock);
}

/**
 * Add to CMS and return estimated count
 */
static uint32_t cms_add_and_query(struct per_ip_cms *cms, uint32_t key, uint32_t count) {
    if (!cms || !cms->counters) return 0;

    uint32_t min_count = UINT32_MAX;

    for (uint32_t d = 0; d < cms->depth; d++) {
        uint32_t idx = cms_hash(key, cms->seeds[d]) % cms->width;
        uint32_t offset = d * cms->width + idx;

        uint32_t new_val = __atomic_add_fetch(&cms->counters[offset], count, __ATOMIC_RELAXED);
        if (new_val < min_count) {
            min_count = new_val;
        }
    }

    __atomic_add_fetch(&cms->total_count, count, __ATOMIC_RELAXED);
    __atomic_add_fetch(&cms->window_count, count, __ATOMIC_RELAXED);

    // Track the largest flows of this window for the concentration features.
    // Gated: skipped entirely (zero cost) unless the concentration export is enabled.
    if (__atomic_load_n(&g_concentration_export_enabled, __ATOMIC_RELAXED)) {
        cms_topk_update(cms, key, min_count);
    }

    return min_count;
}

/**
 * Query CMS for estimated count
 */
static uint32_t cms_query(const struct per_ip_cms *cms, uint32_t key) {
    if (!cms || !cms->counters) return 0;

    uint32_t min_count = UINT32_MAX;

    for (uint32_t d = 0; d < cms->depth; d++) {
        uint32_t idx = cms_hash(key, cms->seeds[d]) % cms->width;
        uint32_t offset = d * cms->width + idx;

        uint32_t val = __atomic_load_n(&cms->counters[offset], __ATOMIC_RELAXED);
        if (val < min_count) {
            min_count = val;
        }
    }

    return min_count;
}

/**
 * Reset CMS window counters (decay by 50%)
 */
static void cms_reset_window(struct per_ip_cms *cms) {
    if (!cms || !cms->counters) return;

    // Decay all counters by 50%
    for (uint32_t i = 0; i < cms->width * cms->depth; i++) {
        uint32_t val = __atomic_load_n(&cms->counters[i], __ATOMIC_RELAXED);
        __atomic_store_n(&cms->counters[i], val / 2, __ATOMIC_RELAXED);
    }

    cms->window_count = 0;

    // Concentration features are window-relative (shares of window_count), so the
    // top-K table starts fresh each window alongside the window_count reset.
    rte_spinlock_lock(&cms->topk_lock);
    cms->topk_n = 0;
    cms->max_flow_count = 0;
    memset(cms->topk_keys, 0, sizeof(cms->topk_keys));
    memset(cms->topk_counts, 0, sizeof(cms->topk_counts));
    rte_spinlock_unlock(&cms->topk_lock);
}

// ==================== Initialization ====================

int per_ip_features_init(uint32_t max_ips) {
    if (g_initialized) {
        RTE_LOG(WARNING, PERIP, "Per-IP features already initialized\n");
        return 0;
    }

    if (max_ips == 0 || max_ips > MAX_PROTECTED_IPS) {
        max_ips = MAX_PROTECTED_IPS;
    }

    g_max_ips = max_ips;

    // Create hash table for IP -> slot lookup
    char hash_name[64];
    snprintf(hash_name, sizeof(hash_name), "perip_hash_%u", (unsigned)rte_lcore_id());

    struct rte_hash_parameters hash_params = {
        .name = hash_name,
        .entries = max_ips * 2,  // 50% load factor
        .key_len = sizeof(uint32_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
    };

    g_perip_hash = rte_hash_create(&hash_params);
    if (!g_perip_hash) {
        RTE_LOG(ERR, PERIP, "Failed to create per-IP hash table\n");
        return -1;
    }

    // Allocate pool of per-IP feature structures
    size_t pool_size = max_ips * sizeof(struct per_ip_features);
    g_perip_pool = rte_zmalloc_socket("perip_pool", pool_size, 64, rte_socket_id());
    if (!g_perip_pool) {
        RTE_LOG(ERR, PERIP, "Failed to allocate per-IP pool (%zu bytes)\n", pool_size);
        rte_hash_free(g_perip_hash);
        g_perip_hash = NULL;
        return -1;
    }

    // Initialize free list
    g_free_slots = rte_malloc("perip_freelist", max_ips * sizeof(uint32_t), 0);
    if (!g_free_slots) {
        RTE_LOG(ERR, PERIP, "Failed to allocate free list\n");
        rte_free(g_perip_pool);
        rte_hash_free(g_perip_hash);
        g_perip_pool = NULL;
        g_perip_hash = NULL;
        return -1;
    }

    // Fill free list (all slots available)
    for (uint32_t i = 0; i < max_ips; i++) {
        g_free_slots[i] = i;
    }
    g_free_count = max_ips;

    g_initialized = true;

    RTE_LOG(INFO, PERIP, "Per-IP features initialized: max_ips=%u, memory=%.2f MB\n",
            max_ips, pool_size / (1024.0 * 1024.0));
    RTE_LOG(INFO, PERIP, "  Using global hyperloglog module for cardinality\n");
    RTE_LOG(INFO, PERIP, "  CMS per IP: %ux%u (~%zu KB)\n",
            PER_IP_CMS_WIDTH, PER_IP_CMS_DEPTH,
            (PER_IP_CMS_WIDTH * PER_IP_CMS_DEPTH * sizeof(uint32_t)) / 1024);

    return 0;
}

void per_ip_features_cleanup(void) {
    if (!g_initialized) {
        return;
    }

    // Cleanup CMS for each registered IP
    for (uint32_t i = 0; i < g_max_ips; i++) {
        if (g_perip_pool[i].active) {
            per_ip_cms_cleanup(&g_perip_pool[i].cms);
        }
    }

    if (g_perip_hash) {
        rte_hash_free(g_perip_hash);
        g_perip_hash = NULL;
    }

    if (g_perip_pool) {
        rte_free(g_perip_pool);
        g_perip_pool = NULL;
    }

    if (g_free_slots) {
        rte_free(g_free_slots);
        g_free_slots = NULL;
    }

    g_max_ips = 0;
    g_registered_count = 0;
    g_free_count = 0;
    g_initialized = false;

    RTE_LOG(INFO, PERIP, "Per-IP features cleanup complete\n");
}

bool per_ip_features_is_initialized(void) {
    return g_initialized;
}

void per_ip_features_set_concentration_export(bool enabled) {
    __atomic_store_n(&g_concentration_export_enabled, enabled, __ATOMIC_RELAXED);
    RTE_LOG(INFO, PERIP, "CMS concentration export %s\n", enabled ? "ENABLED" : "disabled");
}

bool per_ip_features_concentration_export_enabled(void) {
    return __atomic_load_n(&g_concentration_export_enabled, __ATOMIC_RELAXED);
}

// ==================== Registration ====================

int per_ip_features_register(uint32_t dst_ip) {
    if (!g_initialized) {
        return -1;
    }

    // Check if already registered
    int ret = rte_hash_lookup(g_perip_hash, &dst_ip);
    if (ret >= 0) {
        RTE_LOG(DEBUG, PERIP, "IP already registered: %u.%u.%u.%u\n",
                (rte_be_to_cpu_32(dst_ip) >> 24) & 0xFF,
                (rte_be_to_cpu_32(dst_ip) >> 16) & 0xFF,
                (rte_be_to_cpu_32(dst_ip) >> 8) & 0xFF,
                rte_be_to_cpu_32(dst_ip) & 0xFF);
        return 0;  // Already registered is OK
    }

    // Get free slot
    if (g_free_count == 0) {
        RTE_LOG(ERR, PERIP, "Per-IP feature table full (max=%u)\n", g_max_ips);
        return -1;
    }

    uint32_t slot = g_free_slots[--g_free_count];
    struct per_ip_features *pif = &g_perip_pool[slot];

    // Initialize the slot
    memset(pif, 0, sizeof(*pif));
    pif->dst_ip = dst_ip;
    pif->active = 1;

    // Initialize HLL using global hyperloglog module
    hll_init(&pif->hll.src_ip);
    hll_init(&pif->hll.src_port);
    hll_init(&pif->hll.dst_port);   // For carpet bomb / port scan detection
    hll_init(&pif->hll.flows);

    // Initialize CMS
    if (per_ip_cms_init(&pif->cms) < 0) {
        RTE_LOG(ERR, PERIP, "Failed to initialize CMS for IP\n");
        g_free_slots[g_free_count++] = slot;
        return -1;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    pif->created_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    // Add to hash table (store slot index as data)
    ret = rte_hash_add_key_data(g_perip_hash, &dst_ip, (void *)(uintptr_t)slot);
    if (ret < 0) {
        // Return slot to free list
        per_ip_cms_cleanup(&pif->cms);
        pif->active = 0;
        g_free_slots[g_free_count++] = slot;
        RTE_LOG(ERR, PERIP, "Failed to add IP to hash table\n");
        return -1;
    }

    g_registered_count++;

    RTE_LOG(INFO, PERIP, "Registered protected IP: %u.%u.%u.%u (slot=%u, total=%u)\n",
            (rte_be_to_cpu_32(dst_ip) >> 24) & 0xFF,
            (rte_be_to_cpu_32(dst_ip) >> 16) & 0xFF,
            (rte_be_to_cpu_32(dst_ip) >> 8) & 0xFF,
            rte_be_to_cpu_32(dst_ip) & 0xFF,
            slot, g_registered_count);

    return 0;
}

int per_ip_features_unregister(uint32_t dst_ip) {
    if (!g_initialized) {
        return -1;
    }

    void *data;
    int ret = rte_hash_lookup_data(g_perip_hash, &dst_ip, &data);
    if (ret < 0) {
        return -1;  // Not found
    }

    uint32_t slot = (uint32_t)(uintptr_t)data;
    struct per_ip_features *pif = &g_perip_pool[slot];

    // Cleanup CMS
    per_ip_cms_cleanup(&pif->cms);

    // Remove from hash
    rte_hash_del_key(g_perip_hash, &dst_ip);

    // Mark slot as inactive
    pif->active = 0;

    // Return slot to free list
    g_free_slots[g_free_count++] = slot;
    g_registered_count--;

    RTE_LOG(INFO, PERIP, "Unregistered protected IP: %u.%u.%u.%u (total=%u)\n",
            (rte_be_to_cpu_32(dst_ip) >> 24) & 0xFF,
            (rte_be_to_cpu_32(dst_ip) >> 16) & 0xFF,
            (rte_be_to_cpu_32(dst_ip) >> 8) & 0xFF,
            rte_be_to_cpu_32(dst_ip) & 0xFF,
            g_registered_count);

    return 0;
}

struct per_ip_features* per_ip_features_lookup(uint32_t dst_ip) {
    if (!g_initialized || !g_perip_hash) {
        return NULL;
    }

    void *data;
    int ret = rte_hash_lookup_data(g_perip_hash, &dst_ip, &data);
    if (ret < 0) {
        return NULL;
    }

    uint32_t slot = (uint32_t)(uintptr_t)data;

    // Validate slot is within bounds (defensive check)
    if (slot >= MAX_PROTECTED_IPS) {
        RTE_LOG(ERR, PERIP, "Invalid slot %u from hash lookup for IP %08x\n", slot, dst_ip);
        return NULL;
    }

    // Read barrier to ensure we see consistent data after hash lookup
    rte_smp_rmb();

    return &g_perip_pool[slot];
}

// ==================== HLL and CMS Operations ====================

void per_ip_hll_cms_update(struct per_ip_features *pif,
                           uint32_t src_ip,
                           uint16_t src_port,
                           uint16_t dst_port,
                           uint32_t flow_hash) {
    if (!pif) return;

    // Update HLL for unique source IPs using global hyperloglog module
    hll_add_ip(&pif->hll.src_ip, src_ip);

    // Update HLL for unique source ports
    // Hash the port to get a 64-bit value
    uint64_t sport_hash = ((uint64_t)src_port << 32) | rte_hash_crc_4byte(src_port, 0xABCDEF);
    hll_add(&pif->hll.src_port, sport_hash);

    // Update HLL for unique destination ports (for carpet bomb / port scan detection)
    uint64_t dport_hash = ((uint64_t)dst_port << 32) | rte_hash_crc_4byte(dst_port, 0xFEDCBA);
    hll_add(&pif->hll.dst_port, dport_hash);

    // Update HLL for unique flows
    uint64_t flow_hash64 = ((uint64_t)flow_hash << 32) | rte_hash_crc_4byte(flow_hash, 0x123456);
    hll_add(&pif->hll.flows, flow_hash64);

    // Update CMS for concentration metrics
    cms_add_and_query(&pif->cms, flow_hash, 1);
}

// ==================== Fast Path Update ====================

void per_ip_features_update(struct per_ip_features *pif,
                            uint8_t protocol,
                            uint8_t tcp_flags,
                            uint16_t pkt_len,
                            uint32_t src_ip,
                            uint16_t src_port,
                            uint16_t dst_port,
                            uint32_t flow_hash,
                            bool is_new_flow) {
    if (!pif) return;

    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= RTE_MAX_LCORE) {
        lcore_id = 0;
    }

    // Update counters (inline for performance)
    per_ip_features_update_counters(pif, lcore_id, protocol, tcp_flags, pkt_len, is_new_flow);

    // Update HLL and CMS (can be sampled for performance if needed)
    per_ip_hll_cms_update(pif, src_ip, src_port, dst_port, flow_hash);

    // Update last packet timestamp
    __atomic_store_n(&pif->last_packet_ns, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
    __atomic_add_fetch(&pif->total_packets, 1, __ATOMIC_RELAXED);
}

void per_ip_flow_complete(struct per_ip_features *pif,
                          uint32_t flow_packets,
                          uint32_t flow_duration_ms) {
    if (!pif) return;

    __atomic_add_fetch(&pif->total_flow_packets, flow_packets, __ATOMIC_RELAXED);
    __atomic_add_fetch(&pif->total_flow_duration_ms, flow_duration_ms, __ATOMIC_RELAXED);
    __atomic_add_fetch(&pif->completed_flows, 1, __ATOMIC_RELAXED);
}

// ==================== CMS API ====================

bool per_ip_is_heavy_hitter(struct per_ip_features *pif, uint32_t flow_hash) {
    if (!pif) return false;

    uint32_t count = cms_query(&pif->cms, flow_hash);
    uint64_t total = __atomic_load_n(&pif->cms.window_count, __ATOMIC_RELAXED);

    if (total == 0) return false;

    // Heavy hitter if count > threshold% of total
    return (count * 100 / total) >= PER_IP_HEAVY_HITTER_PCT;
}

uint32_t per_ip_get_flow_count(struct per_ip_features *pif, uint32_t flow_hash) {
    if (!pif) return 0;
    return cms_query(&pif->cms, flow_hash);
}

// ==================== Control Path ====================

void per_ip_features_aggregate(struct per_ip_features *pif) {
    if (!pif) return;

    // Sum counters from all lcores
    memset(&pif->aggregated, 0, sizeof(pif->aggregated));

    for (unsigned int i = 0; i < RTE_MAX_LCORE; i++) {
        struct per_ip_lcore_counters *c = &pif->lcore_counters[i];
        pif->aggregated.rx_packets += c->rx_packets;
        pif->aggregated.rx_bytes += c->rx_bytes;
        pif->aggregated.new_flows += c->new_flows;
        pif->aggregated.tcp_packets += c->tcp_packets;
        pif->aggregated.udp_packets += c->udp_packets;
        pif->aggregated.icmp_packets += c->icmp_packets;
        pif->aggregated.other_packets += c->other_packets;
        pif->aggregated.syn_packets += c->syn_packets;
        pif->aggregated.syn_ack_packets += c->syn_ack_packets;
        pif->aggregated.ack_packets += c->ack_packets;
        pif->aggregated.rst_packets += c->rst_packets;
        pif->aggregated.fin_packets += c->fin_packets;
    }
}

static uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int per_ip_features_snapshot(uint32_t dst_ip, struct per_ip_feature_snapshot *out) {
    if (!out) return -1;

    struct per_ip_features *pif = per_ip_features_lookup(dst_ip);
    if (!pif) return -1;

    // Aggregate per-lcore counters
    per_ip_features_aggregate(pif);

    uint64_t now_ns = get_timestamp_ns();
    uint64_t delta_ns = (pif->previous.timestamp_ns > 0) ?
                        (now_ns - pif->previous.timestamp_ns) : 1000000000ULL;
    if (delta_ns == 0) delta_ns = 1;
    double delta_sec = delta_ns / 1000000000.0;

    // Fill snapshot
    memset(out, 0, sizeof(*out));
    out->dst_ip = dst_ip;
    out->timestamp_ns = now_ns;
    out->window_duration_ns = delta_ns;

    // Calculate deltas
    uint64_t pkt_diff = pif->aggregated.rx_packets - pif->previous.rx_packets;
    uint64_t bytes_diff = pif->aggregated.rx_bytes - pif->previous.rx_bytes;
    uint64_t flows_diff = pif->aggregated.new_flows - pif->previous.new_flows;

    // Volume rates
    out->packets_per_sec = (uint64_t)(pkt_diff / delta_sec);
    out->bytes_per_sec = (uint64_t)(bytes_diff / delta_sec);
    out->flows_per_sec = (uint32_t)(flows_diff / delta_sec);

    // Burst factor (Phase 2): this window's rate over the per-IP EWMA of past windows,
    // divided by the post-update mean exactly like the aggregate path (burst_ewma.h).
    // Preview only: this snapshot runs at least twice per window (the global aggregate
    // in l2_features_export_update() and the per-IP export), so the EWMA itself is
    // committed once, in per_ip_features_reset_window(), from the rate parked here.
    {
        double x = (double)out->packets_per_sec;
        out->burst_factor = burst_factor_from(burst_ewma_step(pif->burst_ewma_pps, x), x);
        pif->burst_window_pps = out->packets_per_sec;
        pif->burst_window_valid = 1;
    }

    // TCP flag rates
    uint64_t syn_diff = pif->aggregated.syn_packets - pif->previous.syn_packets;
    uint64_t synack_diff = pif->aggregated.syn_ack_packets - pif->previous.syn_ack_packets;
    uint64_t ack_diff = pif->aggregated.ack_packets - pif->previous.ack_packets;
    uint64_t rst_diff = pif->aggregated.rst_packets - pif->previous.rst_packets;
    uint64_t fin_diff = pif->aggregated.fin_packets - pif->previous.fin_packets;

    out->syn_per_sec = (uint32_t)(syn_diff / delta_sec);
    out->syn_ack_per_sec = (uint32_t)(synack_diff / delta_sec);
    out->ack_per_sec = (uint32_t)(ack_diff / delta_sec);
    out->rst_per_sec = (uint32_t)(rst_diff / delta_sec);
    out->fin_per_sec = (uint32_t)(fin_diff / delta_sec);

    // Protocol counts (this window)
    out->tcp_packets = (uint32_t)(pif->aggregated.tcp_packets - pif->previous.tcp_packets);
    out->udp_packets = (uint32_t)(pif->aggregated.udp_packets - pif->previous.udp_packets);
    out->icmp_packets = (uint32_t)(pif->aggregated.icmp_packets - pif->previous.icmp_packets);
    out->other_packets = (uint32_t)(pif->aggregated.other_packets - pif->previous.other_packets);

    // Protocol ratios
    uint64_t total_proto = out->tcp_packets + out->udp_packets + out->icmp_packets + out->other_packets;
    if (total_proto > 0) {
        out->tcp_ratio = (uint8_t)((out->tcp_packets * 100) / total_proto);
        out->udp_ratio = (uint8_t)((out->udp_packets * 100) / total_proto);
        out->icmp_ratio = (uint8_t)((out->icmp_packets * 100) / total_proto);
    }

    // Attack indicator ratios
    out->syn_ack_ratio = (ack_diff > 0) ? (uint16_t)((syn_diff * 100) / ack_diff) : 0;
    out->rst_syn_ratio = (syn_diff > 0) ? (uint16_t)((rst_diff * 100) / syn_diff) : 0;
    out->bytes_per_packet = (pkt_diff > 0) ? (uint16_t)(bytes_diff / pkt_diff) : 0;

    // HLL cardinality (using global hyperloglog module)
    out->unique_src_ips = (uint32_t)hll_count(&pif->hll.src_ip);
    out->unique_src_ports = (uint32_t)hll_count(&pif->hll.src_port);
    out->unique_dst_ports = (uint32_t)hll_count(&pif->hll.dst_port);
    out->unique_flows = (uint32_t)hll_count(&pif->hll.flows);

    // Churn (change in unique IPs and dst ports)
    out->src_ip_churn = (int32_t)out->unique_src_ips - (int32_t)pif->prev_unique_src_ips;
    out->dst_port_churn = (int32_t)out->unique_dst_ports - (int32_t)pif->prev_unique_dst_ports;
    out->expired_srcip_rate = 0;  // Placeholder

    // Concentration metrics from CMS top-K table (section 4.8). Shares are computed
    // against the within-window packet count; CMS over-estimation means a sum
    // can slightly exceed the total, so each share is clamped to 100%.
    uint64_t window_count = __atomic_load_n(&pif->cms.window_count, __ATOMIC_RELAXED);
    if (window_count > 0 &&
        __atomic_load_n(&g_concentration_export_enabled, __ATOMIC_RELAXED)) {
        rte_spinlock_lock(&pif->cms.topk_lock);
        uint32_t max_c = pif->cms.max_flow_count;
        uint64_t topk_sum = 0;
        uint32_t heavy_hitters = 0;
        // A flow is a heavy hitter if its estimate exceeds PER_IP_HEAVY_HITTER_PCT
        // of the window's packets (counted among the K tracked flows).
        uint32_t hh_thresh = (uint32_t)((window_count * PER_IP_HEAVY_HITTER_PCT) / 100);
        for (uint32_t i = 0; i < pif->cms.topk_n; i++) {
            topk_sum += pif->cms.topk_counts[i];
            if (pif->cms.topk_counts[i] > hh_thresh) {
                heavy_hitters++;
            }
        }
        rte_spinlock_unlock(&pif->cms.topk_lock);

        uint32_t max_frac = (uint32_t)((100ULL * max_c) / window_count);
        uint32_t topk_share = (uint32_t)((100ULL * topk_sum) / window_count);
        out->max_flow_fraction = (uint8_t)(max_frac > 100 ? 100 : max_frac);
        out->topk_flow_share = (uint8_t)(topk_share > 100 ? 100 : topk_share);
        out->heavy_hitter_count = (uint16_t)heavy_hitters;
    } else {
        out->max_flow_fraction = 0;
        out->topk_flow_share = 0;
        out->heavy_hitter_count = 0;
    }

    // Flow behavior metrics
    uint32_t completed = __atomic_load_n(&pif->completed_flows, __ATOMIC_RELAXED);
    if (completed > 0) {
        uint64_t total_flow_pkts = __atomic_load_n(&pif->total_flow_packets, __ATOMIC_RELAXED);
        uint64_t total_flow_dur = __atomic_load_n(&pif->total_flow_duration_ms, __ATOMIC_RELAXED);
        out->avg_packets_per_flow = (uint16_t)(total_flow_pkts / completed);
        out->flow_duration_avg_ms = (uint32_t)(total_flow_dur / completed);
    }

    // Metadata
    out->total_packets = __atomic_load_n(&pif->total_packets, __ATOMIC_RELAXED);
    out->sample_count = (uint32_t)pkt_diff;

    return 0;
}

/* Upper bound on the top-K selection scratch array (covers all real max_count). */
#define PERIP_SELECT_MAX 256

/* This-window packet volume for an entry -- the priority metric for export
 * selection. Cheap: aggregate (sum lcore counters) then delta vs the previous
 * window. A brand-new slot's previous is 0, so it ranks by all its traffic. */
static uint64_t per_ip_window_volume(struct per_ip_features *pif) {
    per_ip_features_aggregate(pif);
    uint64_t cur = pif->aggregated.rx_packets;
    uint64_t prev = pif->previous.rx_packets;
    return (cur > prev) ? (cur - prev) : 0;
}

uint32_t per_ip_features_snapshot_all(struct per_ip_feature_snapshot *out, uint32_t max_count) {
    if (!g_initialized || !out || max_count == 0) {
        return 0;
    }

    uint32_t total = rte_hash_count(g_perip_hash);
    uint32_t count = 0;
    uint32_t iter = 0;
    const void *key;
    void *data;

    // Fast path: everything fits -- export all, no selection cost.
    if (total <= max_count) {
        while (rte_hash_iterate(g_perip_hash, &key, &data, &iter) >= 0) {
            if (count >= max_count) break;
            uint32_t dst_ip = *(const uint32_t *)key;
            if (per_ip_features_snapshot(dst_ip, &out[count]) == 0) {
                count++;
            }
        }
        return count;
    }

    // Selection path: more registered than fit the export window. Export the
    // top max_count by THIS-WINDOW volume (busiest destinations) instead of an
    // arbitrary, nondeterministic hash-iteration-order subset. Bounded top-K via
    // an ascending insertion array (top[0] = current smallest); O(N*K), N<=pool.
    uint32_t k = max_count;
    if (k > PERIP_SELECT_MAX) k = PERIP_SELECT_MAX;  // clamp scratch (max_count is 64/100 in practice)

    struct { uint32_t dst_ip; uint64_t vol; } top[PERIP_SELECT_MAX];
    uint32_t ntop = 0;

    while (rte_hash_iterate(g_perip_hash, &key, &data, &iter) >= 0) {
        uint32_t dst_ip = *(const uint32_t *)key;
        struct per_ip_features *pif = per_ip_features_lookup(dst_ip);
        if (!pif) continue;
        uint64_t vol = per_ip_window_volume(pif);

        if (ntop < k) {
            uint32_t p = ntop;
            while (p > 0 && top[p - 1].vol > vol) { top[p] = top[p - 1]; p--; }
            top[p].dst_ip = dst_ip;
            top[p].vol = vol;
            ntop++;
        } else if (vol > top[0].vol) {
            uint32_t p = 0;
            while (p + 1 < k && top[p + 1].vol < vol) { top[p] = top[p + 1]; p++; }
            top[p].dst_ip = dst_ip;
            top[p].vol = vol;
        }
    }

    for (uint32_t i = 0; i < ntop && count < max_count; i++) {
        if (per_ip_features_snapshot(top[i].dst_ip, &out[count]) == 0) {
            count++;
        }
    }

    // Loud, rate-limited notice that priority selection is in effect: the
    // non-selected registrations get no L2 detection this cycle.
    static uint32_t warn_throttle = 0;
    if ((warn_throttle++ % 60) == 0) {  // ~once/min at the 1 Hz export cadence
        RTE_LOG(WARNING, PERIP,
                "Per-IP export oversubscribed: %u registered, exporting the top %u by "
                "volume to Layer 2; the rest get no L2 detection this cycle. Reduce "
                "registrations or coalesce IPs into subnets.\n", total, count);
    }

    return count;
}

void per_ip_features_reset_window(struct per_ip_features *pif) {
    if (!pif) return;

    // Save current HLL cardinalities
    pif->prev_unique_src_ips = (uint32_t)hll_count(&pif->hll.src_ip);
    pif->prev_unique_src_ports = (uint32_t)hll_count(&pif->hll.src_port);
    pif->prev_unique_dst_ports = (uint32_t)hll_count(&pif->hll.dst_port);
    pif->prev_unique_flows = (uint32_t)hll_count(&pif->hll.flows);

    uint64_t now_ns = get_timestamp_ns();

    // Commit this window's packet rate into the per-IP burst EWMA (Phase 2). This is
    // the one routine that runs exactly once per window roll: the only periodic caller
    // of per_ip_features_reset_all_windows() is the tail of
    // l2_per_ip_features_export_update() (1 Hz, stats thread), whereas
    // per_ip_features_snapshot() runs at least twice per window. Normally the rate is
    // the one the snapshot just exported, so the exported ratio's post-update mean is
    // exactly the mean committed here. When no snapshot ran this window (a slot
    // outside the export selection, or the factory reset) derive the rate from the
    // counters with the snapshot's own delta rule.
    {
        double x;
        if (pif->burst_window_valid) {
            x = (double)pif->burst_window_pps;
            pif->burst_window_valid = 0;
        } else {
            uint64_t pkt_diff = (pif->aggregated.rx_packets > pif->previous.rx_packets) ?
                                (pif->aggregated.rx_packets - pif->previous.rx_packets) : 0;
            uint64_t delta_ns = (pif->previous.timestamp_ns > 0) ?
                                (now_ns - pif->previous.timestamp_ns) : 1000000000ULL;
            if (delta_ns == 0) delta_ns = 1;
            x = (double)(uint64_t)(pkt_diff / (delta_ns / 1000000000.0));
        }
        pif->burst_ewma_pps = burst_ewma_step(pif->burst_ewma_pps, x);
    }

    // Save current aggregated as previous
    pif->previous.rx_packets = pif->aggregated.rx_packets;
    pif->previous.rx_bytes = pif->aggregated.rx_bytes;
    pif->previous.new_flows = pif->aggregated.new_flows;
    pif->previous.tcp_packets = pif->aggregated.tcp_packets;
    pif->previous.udp_packets = pif->aggregated.udp_packets;
    pif->previous.icmp_packets = pif->aggregated.icmp_packets;
    pif->previous.other_packets = pif->aggregated.other_packets;
    pif->previous.syn_packets = pif->aggregated.syn_packets;
    pif->previous.syn_ack_packets = pif->aggregated.syn_ack_packets;
    pif->previous.ack_packets = pif->aggregated.ack_packets;
    pif->previous.rst_packets = pif->aggregated.rst_packets;
    pif->previous.fin_packets = pif->aggregated.fin_packets;
    pif->previous.timestamp_ns = now_ns;

    // Reset CMS window counters (decay)
    cms_reset_window(&pif->cms);

    // Windowed HLL: reset the registers each window so unique_* reflects THIS
    // window's cardinality, not all-time. Cumulative HLLs saturated toward max --
    // harmless-ish for a single /32 but acute for a subnet-aggregate slot (it sees
    // the union of sources across the whole CIDR), where the absolute feature went
    // flat-high and lost discriminative power, and monotonic growth also defeats
    // the L2 z-score. prev_unique_* was just captured above, so window-over-window
    // churn (src_ip_churn etc.) still computes across the reset.
    // NOTE: behavior change for ALL per-IP slots -- L2 EWMA baselines re-learn the
    // per-window scale within a few windows.
    hll_reset(&pif->hll.src_ip);
    hll_reset(&pif->hll.src_port);
    hll_reset(&pif->hll.dst_port);
    hll_reset(&pif->hll.flows);
}

void per_ip_features_reset_all_windows(void) {
    if (!g_initialized) return;

    uint32_t iter = 0;
    const void *key;
    void *data;

    while (rte_hash_iterate(g_perip_hash, &key, &data, &iter) >= 0) {
        uint32_t slot = (uint32_t)(uintptr_t)data;
        per_ip_features_reset_window(&g_perip_pool[slot]);
    }
}

// ==================== Statistics ====================

uint32_t per_ip_features_count(void) {
    return g_registered_count;
}

void per_ip_features_print_stats(void) {
    if (!g_initialized) {
        printf("  Per-IP features: Not initialized\n");
        return;
    }

    printf("  Per-IP Features (with Layer 2 integration):\n");
    printf("    Registered IPs: %u / %u\n", g_registered_count, g_max_ips);
    printf("    Free slots: %u\n", g_free_count);
    printf("    Memory usage: %.2f MB\n", per_ip_features_memory_usage() / (1024.0 * 1024.0));
    printf("    Using global hyperloglog module\n");
    printf("    CMS per IP: %ux%u\n", PER_IP_CMS_WIDTH, PER_IP_CMS_DEPTH);

    // Print top 5 IPs by packet count
    if (g_registered_count > 0) {
        printf("    Top protected IPs by traffic:\n");

        uint32_t iter = 0;
        const void *key;
        void *data;
        int count = 0;

        while (rte_hash_iterate(g_perip_hash, &key, &data, &iter) >= 0 && count < 5) {
            uint32_t dst_ip = *(const uint32_t *)key;
            uint32_t slot = (uint32_t)(uintptr_t)data;
            struct per_ip_features *pif = &g_perip_pool[slot];

            per_ip_features_aggregate(pif);

            uint32_t unique_ips = (uint32_t)hll_count(&pif->hll.src_ip);

            printf("      %u.%u.%u.%u: %lu pkts, %lu bytes, %u unique src IPs\n",
                   (rte_be_to_cpu_32(dst_ip) >> 24) & 0xFF,
                   (rte_be_to_cpu_32(dst_ip) >> 16) & 0xFF,
                   (rte_be_to_cpu_32(dst_ip) >> 8) & 0xFF,
                   rte_be_to_cpu_32(dst_ip) & 0xFF,
                   pif->aggregated.rx_packets,
                   pif->aggregated.rx_bytes,
                   unique_ips);
            count++;
        }
    }
}

size_t per_ip_features_memory_usage(void) {
    if (!g_initialized) return 0;

    size_t pool_size = g_max_ips * sizeof(struct per_ip_features);
    size_t hash_size = rte_hash_count(g_perip_hash) * 32;  // Approximate
    size_t freelist_size = g_max_ips * sizeof(uint32_t);

    // CMS memory per registered IP
    size_t cms_per_ip = PER_IP_CMS_WIDTH * PER_IP_CMS_DEPTH * sizeof(uint32_t);
    size_t cms_total = g_registered_count * cms_per_ip;

    return pool_size + hash_size + freelist_size + cms_total;
}

// Stub: extended per-IP counters (small packets, fragments, TTL)
void per_ip_features_update_extended(struct per_ip_features *pif,
                                     unsigned int lcore_id,
                                     uint8_t ttl,
                                     uint16_t pkt_size,
                                     uint16_t ip_flags) {
    // Stub: extended tracking not yet implemented
    (void)pif;
    (void)lcore_id;
    (void)ttl;
    (void)pkt_size;
    (void)ip_flags;
}
