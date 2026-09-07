/**
 * @file per_ip_features_v6.c
 * @brief IPv6 Per-Protected-IP Feature Tracking Implementation
 *
 * Uses rte_hash with 16-byte keys for IPv6 address lookup.
 * Maintains separate hash table from IPv4 for better cache behavior.
 */

#include "per_ip_features_v6.h"
#include "hyperloglog.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_hash_crc.h>
#include <rte_memcpy.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>

#define RTE_LOGTYPE_PERIP6 RTE_LOGTYPE_USER8

/* ==================== Global State ==================== */

static struct rte_hash *g_perip6_hash = NULL;
static struct per_ip_features_v6 *g_perip6_pool = NULL;
static uint32_t g_max_ips_v6 = 0;
static uint32_t g_registered_count_v6 = 0;
static bool g_initialized_v6 = false;

/* Free list for per-IP feature slots */
static uint32_t *g_free_slots_v6 = NULL;
static uint32_t g_free_count_v6 = 0;

/* ==================== CMS Helper Functions ==================== */

/**
 * Hash function for CMS using CRC32 with different seeds
 */
static inline uint32_t cms_hash_v6(uint32_t key, uint32_t seed) {
    return rte_hash_crc_4byte(key, seed);
}

/**
 * Initialize CMS for a per-IPv6 structure
 */
static int per_ip_cms_v6_init(struct per_ip_cms_v6 *cms) {
    if (!cms) return -1;

    cms->width = PER_IP_CMS_WIDTH;
    cms->depth = PER_IP_CMS_DEPTH;

    size_t counter_size = cms->width * cms->depth * sizeof(uint32_t);
    cms->counters = rte_zmalloc("perip6_cms", counter_size, 64);
    if (!cms->counters) {
        return -1;
    }

    for (uint32_t i = 0; i < cms->depth; i++) {
        cms->seeds[i] = 0x12345678 + i * 0x87654321;
    }

    cms->total_count = 0;
    cms->window_count = 0;

    return 0;
}

/**
 * Cleanup CMS
 */
static void per_ip_cms_v6_cleanup(struct per_ip_cms_v6 *cms) {
    if (cms && cms->counters) {
        rte_free(cms->counters);
        cms->counters = NULL;
    }
}

/**
 * Add to CMS and return estimated count
 */
static uint32_t cms_v6_add_and_query(struct per_ip_cms_v6 *cms, uint32_t key, uint32_t count) {
    if (!cms || !cms->counters) return 0;

    uint32_t min_count = UINT32_MAX;

    for (uint32_t d = 0; d < cms->depth; d++) {
        uint32_t idx = cms_hash_v6(key, cms->seeds[d]) % cms->width;
        uint32_t offset = d * cms->width + idx;

        uint32_t new_val = __atomic_add_fetch(&cms->counters[offset], count, __ATOMIC_RELAXED);
        if (new_val < min_count) {
            min_count = new_val;
        }
    }

    __atomic_add_fetch(&cms->total_count, count, __ATOMIC_RELAXED);
    __atomic_add_fetch(&cms->window_count, count, __ATOMIC_RELAXED);

    return min_count;
}

/**
 * Query CMS for estimated count
 */
static uint32_t cms_v6_query(const struct per_ip_cms_v6 *cms, uint32_t key) {
    if (!cms || !cms->counters) return 0;

    uint32_t min_count = UINT32_MAX;

    for (uint32_t d = 0; d < cms->depth; d++) {
        uint32_t idx = cms_hash_v6(key, cms->seeds[d]) % cms->width;
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
static void cms_v6_reset_window(struct per_ip_cms_v6 *cms) {
    if (!cms || !cms->counters) return;

    for (uint32_t i = 0; i < cms->width * cms->depth; i++) {
        uint32_t val = __atomic_load_n(&cms->counters[i], __ATOMIC_RELAXED);
        __atomic_store_n(&cms->counters[i], val / 2, __ATOMIC_RELAXED);
    }

    cms->window_count = 0;
}

/* ==================== IPv6 Hash Function ==================== */

/**
 * Hash function for 16-byte IPv6 keys
 * Uses jhash on 4 32-bit words
 */
static inline uint32_t ipv6_hash_func(const void *key,
                                       __attribute__((unused)) uint32_t key_len,
                                       uint32_t init_val) {
    const uint32_t *k = (const uint32_t *)key;
    return rte_jhash_32b(k, 4, init_val);
}

/* ==================== Initialization ==================== */

int per_ip_features_v6_init(uint32_t max_ips) {
    if (g_initialized_v6) {
        RTE_LOG(WARNING, PERIP6, "IPv6 per-IP features already initialized\n");
        return 0;
    }

    if (max_ips == 0 || max_ips > MAX_PROTECTED_IPS_V6) {
        max_ips = MAX_PROTECTED_IPS_V6;
    }

    g_max_ips_v6 = max_ips;

    /* Create hash table for IPv6 -> slot lookup with 16-byte keys */
    char hash_name[64];
    snprintf(hash_name, sizeof(hash_name), "perip6_hash_%u", (unsigned)rte_lcore_id());

    struct rte_hash_parameters hash_params = {
        .name = hash_name,
        .entries = max_ips * 2,  /* 50% load factor */
        .key_len = 16,           /* 128-bit IPv6 address */
        .hash_func = ipv6_hash_func,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
    };

    g_perip6_hash = rte_hash_create(&hash_params);
    if (!g_perip6_hash) {
        RTE_LOG(ERR, PERIP6, "Failed to create IPv6 per-IP hash table\n");
        return -1;
    }

    /* Allocate pool of per-IPv6 feature structures */
    size_t pool_size = max_ips * sizeof(struct per_ip_features_v6);
    g_perip6_pool = rte_zmalloc_socket("perip6_pool", pool_size, 64, rte_socket_id());
    if (!g_perip6_pool) {
        RTE_LOG(ERR, PERIP6, "Failed to allocate IPv6 per-IP pool (%zu bytes)\n", pool_size);
        rte_hash_free(g_perip6_hash);
        g_perip6_hash = NULL;
        return -1;
    }

    /* Initialize free list */
    g_free_slots_v6 = rte_malloc("perip6_freelist", max_ips * sizeof(uint32_t), 0);
    if (!g_free_slots_v6) {
        RTE_LOG(ERR, PERIP6, "Failed to allocate IPv6 free list\n");
        rte_free(g_perip6_pool);
        rte_hash_free(g_perip6_hash);
        g_perip6_pool = NULL;
        g_perip6_hash = NULL;
        return -1;
    }

    /* Fill free list */
    for (uint32_t i = 0; i < max_ips; i++) {
        g_free_slots_v6[i] = i;
    }
    g_free_count_v6 = max_ips;

    g_initialized_v6 = true;

    RTE_LOG(INFO, PERIP6, "IPv6 per-IP features initialized: max_ips=%u, memory=%.2f MB\n",
            max_ips, pool_size / (1024.0 * 1024.0));

    return 0;
}

void per_ip_features_v6_cleanup(void) {
    if (!g_initialized_v6) {
        return;
    }

    /* Cleanup CMS for each registered IPv6 */
    for (uint32_t i = 0; i < g_max_ips_v6; i++) {
        if (g_perip6_pool[i].active) {
            per_ip_cms_v6_cleanup(&g_perip6_pool[i].cms);
        }
    }

    if (g_perip6_hash) {
        rte_hash_free(g_perip6_hash);
        g_perip6_hash = NULL;
    }

    if (g_perip6_pool) {
        rte_free(g_perip6_pool);
        g_perip6_pool = NULL;
    }

    if (g_free_slots_v6) {
        rte_free(g_free_slots_v6);
        g_free_slots_v6 = NULL;
    }

    g_max_ips_v6 = 0;
    g_registered_count_v6 = 0;
    g_free_count_v6 = 0;
    g_initialized_v6 = false;

    RTE_LOG(INFO, PERIP6, "IPv6 per-IP features cleanup complete\n");
}

bool per_ip_features_v6_is_initialized(void) {
    return g_initialized_v6;
}

/* ==================== Registration ==================== */

/**
 * Format IPv6 address for logging
 */
static void format_ipv6(const uint8_t ip6[16], char *buf, size_t size) {
    inet_ntop(AF_INET6, ip6, buf, size);
}

int per_ip_features_v6_register(const uint8_t dst_ip6[16]) {
    if (!g_initialized_v6) {
        return -1;
    }

    /* Check if already registered */
    int ret = rte_hash_lookup(g_perip6_hash, dst_ip6);
    if (ret >= 0) {
        char ipstr[INET6_ADDRSTRLEN];
        format_ipv6(dst_ip6, ipstr, sizeof(ipstr));
        RTE_LOG(DEBUG, PERIP6, "IPv6 already registered: %s\n", ipstr);
        return 0;
    }

    /* Get free slot */
    if (g_free_count_v6 == 0) {
        RTE_LOG(ERR, PERIP6, "IPv6 per-IP feature table full (max=%u)\n", g_max_ips_v6);
        return -1;
    }

    uint32_t slot = g_free_slots_v6[--g_free_count_v6];
    struct per_ip_features_v6 *pif = &g_perip6_pool[slot];

    /* Initialize the slot */
    memset(pif, 0, sizeof(*pif));
    rte_memcpy(pif->dst_ip6, dst_ip6, 16);
    pif->active = 1;

    /* Initialize HLL */
    hll_init(&pif->hll.src_ip);
    hll_init(&pif->hll.src_port);
    hll_init(&pif->hll.dst_port);
    hll_init(&pif->hll.flows);

    /* Initialize CMS */
    if (per_ip_cms_v6_init(&pif->cms) < 0) {
        RTE_LOG(ERR, PERIP6, "Failed to initialize CMS for IPv6\n");
        g_free_slots_v6[g_free_count_v6++] = slot;
        return -1;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    pif->created_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    /* Add to hash table */
    ret = rte_hash_add_key_data(g_perip6_hash, dst_ip6, (void *)(uintptr_t)slot);
    if (ret < 0) {
        per_ip_cms_v6_cleanup(&pif->cms);
        pif->active = 0;
        g_free_slots_v6[g_free_count_v6++] = slot;
        RTE_LOG(ERR, PERIP6, "Failed to add IPv6 to hash table\n");
        return -1;
    }

    g_registered_count_v6++;

    char ipstr[INET6_ADDRSTRLEN];
    format_ipv6(dst_ip6, ipstr, sizeof(ipstr));
    RTE_LOG(INFO, PERIP6, "Registered protected IPv6: %s (slot=%u, total=%u)\n",
            ipstr, slot, g_registered_count_v6);

    return 0;
}

int per_ip_features_v6_unregister(const uint8_t dst_ip6[16]) {
    if (!g_initialized_v6) {
        return -1;
    }

    void *data;
    int ret = rte_hash_lookup_data(g_perip6_hash, dst_ip6, &data);
    if (ret < 0) {
        return -1;
    }

    uint32_t slot = (uint32_t)(uintptr_t)data;
    struct per_ip_features_v6 *pif = &g_perip6_pool[slot];

    /* Cleanup CMS */
    per_ip_cms_v6_cleanup(&pif->cms);

    /* Remove from hash */
    rte_hash_del_key(g_perip6_hash, dst_ip6);

    /* Mark slot as inactive */
    pif->active = 0;

    /* Return slot to free list */
    g_free_slots_v6[g_free_count_v6++] = slot;
    g_registered_count_v6--;

    char ipstr[INET6_ADDRSTRLEN];
    format_ipv6(dst_ip6, ipstr, sizeof(ipstr));
    RTE_LOG(INFO, PERIP6, "Unregistered protected IPv6: %s (total=%u)\n",
            ipstr, g_registered_count_v6);

    return 0;
}

struct per_ip_features_v6* per_ip_features_v6_lookup(const uint8_t dst_ip6[16]) {
    if (!g_initialized_v6 || !g_perip6_hash) {
        return NULL;
    }

    void *data;
    int ret = rte_hash_lookup_data(g_perip6_hash, dst_ip6, &data);
    if (ret < 0) {
        return NULL;
    }

    uint32_t slot = (uint32_t)(uintptr_t)data;

    if (slot >= MAX_PROTECTED_IPS_V6) {
        return NULL;
    }

    rte_smp_rmb();

    return &g_perip6_pool[slot];
}

/* ==================== HLL and CMS Operations ==================== */

/**
 * Hash 128-bit IPv6 address for HLL
 */
static inline uint64_t hash_ipv6_for_hll(const uint8_t ip6[16]) {
    const uint64_t *words = (const uint64_t *)ip6;
    /* Combine both 64-bit halves with XOR and mix */
    uint64_t h = words[0] ^ (words[1] * 0x9e3779b97f4a7c15ULL);
    /* Apply a mixing step */
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return h;
}

void per_ip_hll_cms_v6_update(struct per_ip_features_v6 *pif,
                              const uint8_t src_ip6[16],
                              uint16_t src_port,
                              uint16_t dst_port,
                              uint32_t flow_hash) {
    if (!pif) return;

    /* Update HLL for unique source IPv6s */
    uint64_t src_hash = hash_ipv6_for_hll(src_ip6);
    hll_add(&pif->hll.src_ip, src_hash);

    /* Update HLL for unique source ports */
    uint64_t sport_hash = ((uint64_t)src_port << 32) | rte_hash_crc_4byte(src_port, 0xABCDEF);
    hll_add(&pif->hll.src_port, sport_hash);

    /* Update HLL for unique destination ports */
    uint64_t dport_hash = ((uint64_t)dst_port << 32) | rte_hash_crc_4byte(dst_port, 0xFEDCBA);
    hll_add(&pif->hll.dst_port, dport_hash);

    /* Update HLL for unique flows */
    uint64_t flow_hash64 = ((uint64_t)flow_hash << 32) | rte_hash_crc_4byte(flow_hash, 0x123456);
    hll_add(&pif->hll.flows, flow_hash64);

    /* Update CMS for concentration metrics */
    cms_v6_add_and_query(&pif->cms, flow_hash, 1);
}

/* ==================== Fast Path Update ==================== */

void per_ip_features_v6_update(struct per_ip_features_v6 *pif,
                               uint8_t protocol,
                               uint8_t tcp_flags,
                               uint16_t pkt_len,
                               const uint8_t src_ip6[16],
                               uint16_t src_port,
                               uint16_t dst_port,
                               uint32_t flow_hash,
                               bool is_new_flow) {
    if (!pif) return;

    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= RTE_MAX_LCORE) {
        lcore_id = 0;
    }

    /* Update counters */
    per_ip_features_v6_update_counters(pif, lcore_id, protocol, tcp_flags, pkt_len, is_new_flow);

    /* Update HLL and CMS */
    per_ip_hll_cms_v6_update(pif, src_ip6, src_port, dst_port, flow_hash);

    /* Update last packet timestamp */
    __atomic_store_n(&pif->last_packet_ns, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
    __atomic_add_fetch(&pif->total_packets, 1, __ATOMIC_RELAXED);
}

void per_ip_v6_flow_complete(struct per_ip_features_v6 *pif,
                             uint32_t flow_packets,
                             uint32_t flow_duration_ms) {
    if (!pif) return;

    __atomic_add_fetch(&pif->total_flow_packets, flow_packets, __ATOMIC_RELAXED);
    __atomic_add_fetch(&pif->total_flow_duration_ms, flow_duration_ms, __ATOMIC_RELAXED);
    __atomic_add_fetch(&pif->completed_flows, 1, __ATOMIC_RELAXED);
}

/* ==================== CMS API ==================== */

bool per_ip_v6_is_heavy_hitter(struct per_ip_features_v6 *pif, uint32_t flow_hash) {
    if (!pif) return false;

    uint32_t count = cms_v6_query(&pif->cms, flow_hash);
    uint64_t total = __atomic_load_n(&pif->cms.window_count, __ATOMIC_RELAXED);

    if (total == 0) return false;

    return (count * 100 / total) >= PER_IP_HEAVY_HITTER_PCT;
}

uint32_t per_ip_v6_get_flow_count(struct per_ip_features_v6 *pif, uint32_t flow_hash) {
    if (!pif) return 0;
    return cms_v6_query(&pif->cms, flow_hash);
}

/* ==================== Control Path ==================== */

void per_ip_features_v6_aggregate(struct per_ip_features_v6 *pif) {
    if (!pif) return;

    memset(&pif->aggregated, 0, sizeof(pif->aggregated));

    for (unsigned int i = 0; i < RTE_MAX_LCORE; i++) {
        struct per_ip_lcore_counters_v6 *c = &pif->lcore_counters[i];
        pif->aggregated.rx_packets += c->rx_packets;
        pif->aggregated.rx_bytes += c->rx_bytes;
        pif->aggregated.new_flows += c->new_flows;
        pif->aggregated.tcp_packets += c->tcp_packets;
        pif->aggregated.udp_packets += c->udp_packets;
        pif->aggregated.icmpv6_packets += c->icmpv6_packets;
        pif->aggregated.other_packets += c->other_packets;
        pif->aggregated.syn_packets += c->syn_packets;
        pif->aggregated.syn_ack_packets += c->syn_ack_packets;
        pif->aggregated.ack_packets += c->ack_packets;
        pif->aggregated.rst_packets += c->rst_packets;
        pif->aggregated.fin_packets += c->fin_packets;
    }
}

static uint64_t get_timestamp_ns_v6(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int per_ip_features_v6_snapshot(const uint8_t dst_ip6[16],
                                struct per_ip_feature_snapshot_v6 *out) {
    if (!out) return -1;

    struct per_ip_features_v6 *pif = per_ip_features_v6_lookup(dst_ip6);
    if (!pif) return -1;

    per_ip_features_v6_aggregate(pif);

    uint64_t now_ns = get_timestamp_ns_v6();
    uint64_t delta_ns = (pif->previous.timestamp_ns > 0) ?
                        (now_ns - pif->previous.timestamp_ns) : 1000000000ULL;
    if (delta_ns == 0) delta_ns = 1;
    double delta_sec = delta_ns / 1000000000.0;

    memset(out, 0, sizeof(*out));
    rte_memcpy(out->dst_ip6, dst_ip6, 16);
    out->timestamp_ns = now_ns;
    out->window_duration_ns = delta_ns;

    /* Calculate deltas */
    uint64_t pkt_diff = pif->aggregated.rx_packets - pif->previous.rx_packets;
    uint64_t bytes_diff = pif->aggregated.rx_bytes - pif->previous.rx_bytes;
    uint64_t flows_diff = pif->aggregated.new_flows - pif->previous.new_flows;

    /* Volume rates */
    out->packets_per_sec = (uint64_t)(pkt_diff / delta_sec);
    out->bytes_per_sec = (uint64_t)(bytes_diff / delta_sec);
    out->flows_per_sec = (uint32_t)(flows_diff / delta_sec);

    /* TCP flag rates */
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

    /* Protocol counts */
    out->tcp_packets = (uint32_t)(pif->aggregated.tcp_packets - pif->previous.tcp_packets);
    out->udp_packets = (uint32_t)(pif->aggregated.udp_packets - pif->previous.udp_packets);
    out->icmpv6_packets = (uint32_t)(pif->aggregated.icmpv6_packets - pif->previous.icmpv6_packets);
    out->other_packets = (uint32_t)(pif->aggregated.other_packets - pif->previous.other_packets);

    /* Protocol ratios */
    uint64_t total_proto = out->tcp_packets + out->udp_packets + out->icmpv6_packets + out->other_packets;
    if (total_proto > 0) {
        out->tcp_ratio = (uint8_t)((out->tcp_packets * 100) / total_proto);
        out->udp_ratio = (uint8_t)((out->udp_packets * 100) / total_proto);
        out->icmpv6_ratio = (uint8_t)((out->icmpv6_packets * 100) / total_proto);
    }

    /* Attack indicator ratios */
    out->syn_ack_ratio = (ack_diff > 0) ? (uint16_t)((syn_diff * 100) / ack_diff) : 0;
    out->rst_syn_ratio = (syn_diff > 0) ? (uint16_t)((rst_diff * 100) / syn_diff) : 0;
    out->bytes_per_packet = (pkt_diff > 0) ? (uint16_t)(bytes_diff / pkt_diff) : 0;

    /* HLL cardinality */
    out->unique_src_ips = (uint32_t)hll_count(&pif->hll.src_ip);
    out->unique_src_ports = (uint32_t)hll_count(&pif->hll.src_port);
    out->unique_dst_ports = (uint32_t)hll_count(&pif->hll.dst_port);
    out->unique_flows = (uint32_t)hll_count(&pif->hll.flows);

    /* Churn */
    out->src_ip_churn = (int32_t)out->unique_src_ips - (int32_t)pif->prev_unique_src_ips;
    out->dst_port_churn = (int32_t)out->unique_dst_ports - (int32_t)pif->prev_unique_dst_ports;
    out->expired_srcip_rate = 0;

    /* Flow behavior metrics */
    uint32_t completed = __atomic_load_n(&pif->completed_flows, __ATOMIC_RELAXED);
    if (completed > 0) {
        uint64_t total_flow_pkts = __atomic_load_n(&pif->total_flow_packets, __ATOMIC_RELAXED);
        uint64_t total_flow_dur = __atomic_load_n(&pif->total_flow_duration_ms, __ATOMIC_RELAXED);
        out->avg_packets_per_flow = (uint16_t)(total_flow_pkts / completed);
        out->flow_duration_avg_ms = (uint32_t)(total_flow_dur / completed);
    }

    /* Metadata */
    out->total_packets = __atomic_load_n(&pif->total_packets, __ATOMIC_RELAXED);
    out->sample_count = (uint32_t)pkt_diff;

    return 0;
}

uint32_t per_ip_features_v6_snapshot_all(struct per_ip_feature_snapshot_v6 *out,
                                         uint32_t max_count) {
    if (!g_initialized_v6 || !out || max_count == 0) {
        return 0;
    }

    uint32_t count = 0;
    uint32_t iter = 0;
    const void *key;
    void *data;

    while (rte_hash_iterate(g_perip6_hash, &key, &data, &iter) >= 0) {
        if (count >= max_count) break;

        const uint8_t *dst_ip6 = (const uint8_t *)key;
        if (per_ip_features_v6_snapshot(dst_ip6, &out[count]) == 0) {
            count++;
        }
    }

    return count;
}

void per_ip_features_v6_reset_window(struct per_ip_features_v6 *pif) {
    if (!pif) return;

    /* Save current HLL cardinalities */
    pif->prev_unique_src_ips = (uint32_t)hll_count(&pif->hll.src_ip);
    pif->prev_unique_src_ports = (uint32_t)hll_count(&pif->hll.src_port);
    pif->prev_unique_dst_ports = (uint32_t)hll_count(&pif->hll.dst_port);
    pif->prev_unique_flows = (uint32_t)hll_count(&pif->hll.flows);

    /* Save current aggregated as previous */
    pif->previous.rx_packets = pif->aggregated.rx_packets;
    pif->previous.rx_bytes = pif->aggregated.rx_bytes;
    pif->previous.new_flows = pif->aggregated.new_flows;
    pif->previous.tcp_packets = pif->aggregated.tcp_packets;
    pif->previous.udp_packets = pif->aggregated.udp_packets;
    pif->previous.icmpv6_packets = pif->aggregated.icmpv6_packets;
    pif->previous.other_packets = pif->aggregated.other_packets;
    pif->previous.syn_packets = pif->aggregated.syn_packets;
    pif->previous.syn_ack_packets = pif->aggregated.syn_ack_packets;
    pif->previous.ack_packets = pif->aggregated.ack_packets;
    pif->previous.rst_packets = pif->aggregated.rst_packets;
    pif->previous.fin_packets = pif->aggregated.fin_packets;
    pif->previous.timestamp_ns = get_timestamp_ns_v6();

    /* Reset CMS window counters */
    cms_v6_reset_window(&pif->cms);
}

void per_ip_features_v6_reset_all_windows(void) {
    if (!g_initialized_v6) return;

    uint32_t iter = 0;
    const void *key;
    void *data;

    while (rte_hash_iterate(g_perip6_hash, &key, &data, &iter) >= 0) {
        uint32_t slot = (uint32_t)(uintptr_t)data;
        per_ip_features_v6_reset_window(&g_perip6_pool[slot]);
    }
}

/* ==================== Statistics ==================== */

uint32_t per_ip_features_v6_count(void) {
    return g_registered_count_v6;
}

void per_ip_features_v6_print_stats(void) {
    if (!g_initialized_v6) {
        printf("  IPv6 Per-IP features: Not initialized\n");
        return;
    }

    printf("  IPv6 Per-IP Features:\n");
    printf("    Registered IPv6s: %u / %u\n", g_registered_count_v6, g_max_ips_v6);
    printf("    Free slots: %u\n", g_free_count_v6);
    printf("    Memory usage: %.2f MB\n", per_ip_features_v6_memory_usage() / (1024.0 * 1024.0));

    if (g_registered_count_v6 > 0) {
        printf("    Top protected IPv6s by traffic:\n");

        uint32_t iter = 0;
        const void *key;
        void *data;
        int count = 0;

        while (rte_hash_iterate(g_perip6_hash, &key, &data, &iter) >= 0 && count < 5) {
            const uint8_t *dst_ip6 = (const uint8_t *)key;
            uint32_t slot = (uint32_t)(uintptr_t)data;
            struct per_ip_features_v6 *pif = &g_perip6_pool[slot];

            per_ip_features_v6_aggregate(pif);

            char ipstr[INET6_ADDRSTRLEN];
            format_ipv6(dst_ip6, ipstr, sizeof(ipstr));

            uint32_t unique_ips = (uint32_t)hll_count(&pif->hll.src_ip);

            printf("      %s: %lu pkts, %lu bytes, %u unique src IPs\n",
                   ipstr,
                   pif->aggregated.rx_packets,
                   pif->aggregated.rx_bytes,
                   unique_ips);
            count++;
        }
    }
}

size_t per_ip_features_v6_memory_usage(void) {
    if (!g_initialized_v6) return 0;

    size_t pool_size = g_max_ips_v6 * sizeof(struct per_ip_features_v6);
    size_t hash_size = rte_hash_count(g_perip6_hash) * 48;  /* Approximate with 16-byte keys */
    size_t freelist_size = g_max_ips_v6 * sizeof(uint32_t);

    size_t cms_per_ip = PER_IP_CMS_WIDTH * PER_IP_CMS_DEPTH * sizeof(uint32_t);
    size_t cms_total = g_registered_count_v6 * cms_per_ip;

    return pool_size + hash_size + freelist_size + cms_total;
}

/* ==================== Dual-Stack Unified API ==================== */

void* per_ip_features_lookup_unified(const void *ip, bool is_ipv6) {
    if (is_ipv6) {
        return per_ip_features_v6_lookup((const uint8_t *)ip);
    } else {
        return per_ip_features_lookup(*(const uint32_t *)ip);
    }
}

int per_ip_features_register_unified(const void *ip, bool is_ipv6) {
    if (is_ipv6) {
        return per_ip_features_v6_register((const uint8_t *)ip);
    } else {
        return per_ip_features_register(*(const uint32_t *)ip);
    }
}

int per_ip_features_unregister_unified(const void *ip, bool is_ipv6) {
    if (is_ipv6) {
        return per_ip_features_v6_unregister((const uint8_t *)ip);
    } else {
        return per_ip_features_unregister(*(const uint32_t *)ip);
    }
}

void per_ip_features_print_stats_all(void) {
    printf("\n===== Per-IP Feature Statistics (Dual-Stack) =====\n");
    per_ip_features_print_stats();
    per_ip_features_v6_print_stats();
    printf("===================================================\n");
}
