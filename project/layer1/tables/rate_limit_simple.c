/**
 * @file rate_limit_simple.c
 * @brief Simplified rate limiting for single-organization deployment
 *
 * Two-level hierarchy: Global limits -> Per-source-IP limits
 * No tenant lookups, no per-tenant quotas.
 */

#include "rate_limit_simple.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef USE_DPDK
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#else
/* Fallback for non-DPDK builds */
static inline uint64_t get_tsc_hz(void) { return 1000000000ULL; }
static inline uint64_t get_tsc(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
#endif

/* ============================================================================
 * Global State
 * ============================================================================ */

static struct rate_limit_config g_rate_config;
static struct global_rate_state g_rate_state;
static struct src_rate_entry *g_src_table = NULL;
static uint64_t g_tsc_hz = 0;
static uint32_t g_current_time_ms = 0;

/* Statistics */
static _Atomic uint64_t g_packets_checked = 0;
static _Atomic uint64_t g_packets_allowed = 0;
static _Atomic uint64_t g_packets_dropped = 0;
static _Atomic uint32_t g_active_sources = 0;

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static inline uint32_t hash_src_ip(uint32_t ip)
{
    /* Simple but effective hash for IP addresses */
    uint32_t h = ip;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h & (RATE_LIMIT_HASH_SIZE - 1);
}

static inline uint32_t get_current_time_ms(void)
{
#ifdef USE_DPDK
    return (uint32_t)((rte_rdtsc() * 1000) / g_tsc_hz);
#else
    return (uint32_t)((get_tsc() / 1000000));
#endif
}

static inline uint64_t get_effective_limit(uint64_t base_limit, bool is_emergency)
{
    if (base_limit == 0) return 0; /* Unlimited */

    float factor = g_rate_config.progressive_factor;
    if (is_emergency && g_rate_config.emergency_mode) {
        factor *= g_rate_config.emergency_factor;
    }

    uint64_t effective = (uint64_t)((double)base_limit * factor);
    return effective > 0 ? effective : 1;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

int rate_limit_init(const struct rate_limit_config *cfg)
{
    /* Set TSC frequency */
#ifdef USE_DPDK
    g_tsc_hz = rte_get_tsc_hz();
#else
    g_tsc_hz = get_tsc_hz();
#endif

    /* Copy configuration */
    if (cfg) {
        memcpy(&g_rate_config, cfg, sizeof(g_rate_config));
    } else {
        rate_limit_default_config(&g_rate_config);
    }

    /* Initialize global state */
    memset(&g_rate_state, 0, sizeof(g_rate_state));
    atomic_store(&g_rate_state.pps_tokens, g_rate_config.global_pps);
    atomic_store(&g_rate_state.bps_tokens, g_rate_config.global_bps);

    for (int i = 0; i < RATE_LIMIT_PROTO_CLASSES; i++) {
        atomic_store(&g_rate_state.proto_tokens[i], g_rate_config.proto_pps[i]);
    }

#ifdef USE_DPDK
    g_rate_state.last_refill_tsc = rte_rdtsc();
#else
    g_rate_state.last_refill_tsc = get_tsc();
#endif

    /* Allocate per-source table */
#ifdef USE_DPDK
    g_src_table = rte_zmalloc("rate_limit_src",
                              RATE_LIMIT_HASH_SIZE * sizeof(struct src_rate_entry),
                              RTE_CACHE_LINE_SIZE);
#else
    g_src_table = calloc(RATE_LIMIT_HASH_SIZE, sizeof(struct src_rate_entry));
#endif

    if (!g_src_table) {
        return -1;
    }

    /* Reset statistics */
    atomic_store(&g_packets_checked, 0);
    atomic_store(&g_packets_allowed, 0);
    atomic_store(&g_packets_dropped, 0);
    atomic_store(&g_active_sources, 0);

    return 0;
}

void rate_limit_cleanup(void)
{
    if (g_src_table) {
#ifdef USE_DPDK
        rte_free(g_src_table);
#else
        free(g_src_table);
#endif
        g_src_table = NULL;
    }
}

/* ============================================================================
 * Rate Check Implementation
 * ============================================================================ */

bool rate_limit_check(uint32_t src_ip, proto_class_t proto_class,
                      uint16_t pkt_len, rate_drop_reason_t *out_reason)
{
    atomic_fetch_add(&g_packets_checked, 1);

    if (out_reason) *out_reason = RATE_DROP_NONE;

    bool emergency = g_rate_config.emergency_mode;

    /* -------------------------------------------------------------------------
     * Check 1: Global PPS limit
     * ------------------------------------------------------------------------- */
    if (g_rate_config.global_pps > 0) {
        uint64_t effective_pps = get_effective_limit(g_rate_config.global_pps, emergency);
        uint64_t tokens = atomic_load(&g_rate_state.pps_tokens);

        if (tokens == 0) {
            atomic_fetch_add(&g_rate_state.drops_global_pps, 1);
            atomic_fetch_add(&g_packets_dropped, 1);
            if (out_reason) *out_reason = RATE_DROP_GLOBAL_PPS;
            return false;
        }

        /* Consume token (atomic decrement) */
        atomic_fetch_sub(&g_rate_state.pps_tokens, 1);
    }

    /* -------------------------------------------------------------------------
     * Check 2: Global BPS limit
     * ------------------------------------------------------------------------- */
    if (g_rate_config.global_bps > 0) {
        uint64_t effective_bps = get_effective_limit(g_rate_config.global_bps, emergency);
        uint64_t tokens = atomic_load(&g_rate_state.bps_tokens);
        uint64_t pkt_bits = (uint64_t)pkt_len * 8;

        if (tokens < pkt_bits) {
            atomic_fetch_add(&g_rate_state.drops_global_bps, 1);
            atomic_fetch_add(&g_packets_dropped, 1);
            if (out_reason) *out_reason = RATE_DROP_GLOBAL_BPS;
            return false;
        }

        atomic_fetch_sub(&g_rate_state.bps_tokens, pkt_bits);
    }

    /* -------------------------------------------------------------------------
     * Check 3: Per-protocol PPS limit
     * ------------------------------------------------------------------------- */
    if (proto_class < RATE_LIMIT_PROTO_CLASSES) {
        uint32_t proto_limit = g_rate_config.proto_pps[proto_class];
        if (proto_limit > 0) {
            uint32_t effective = (uint32_t)get_effective_limit(proto_limit, emergency);
            uint32_t tokens = atomic_load(&g_rate_state.proto_tokens[proto_class]);

            if (tokens == 0) {
                atomic_fetch_add(&g_rate_state.drops_proto[proto_class], 1);
                atomic_fetch_add(&g_packets_dropped, 1);
                if (out_reason) *out_reason = RATE_DROP_PROTO_PPS;
                return false;
            }

            atomic_fetch_sub(&g_rate_state.proto_tokens[proto_class], 1);
        }
    }

    /* -------------------------------------------------------------------------
     * Check 4: Per-source-IP limits
     * ------------------------------------------------------------------------- */
    if (g_rate_config.per_src_pps > 0 || g_rate_config.per_src_bps > 0) {
        uint32_t idx = hash_src_ip(src_ip);
        struct src_rate_entry *entry = &g_src_table[idx];
        uint32_t now_ms = get_current_time_ms();

        /* Handle hash collision or new entry */
        if (!(entry->flags & SRC_RATE_FLAG_VALID) || entry->src_ip != src_ip) {
            /* New source - initialize entry */
            if (entry->flags & SRC_RATE_FLAG_VALID) {
                /* Collision - evict old entry */
                atomic_fetch_sub(&g_active_sources, 1);
            }

            entry->src_ip = src_ip;
            entry->pps_tokens = g_rate_config.per_src_pps;
            entry->bps_tokens = g_rate_config.per_src_bps;
            entry->last_update_ms = now_ms;
            entry->packet_count = 0;
            entry->byte_count = 0;
            entry->flags = SRC_RATE_FLAG_VALID;
            atomic_fetch_add(&g_active_sources, 1);
        }

        /* Refill tokens based on elapsed time */
        uint32_t elapsed_ms = now_ms - entry->last_update_ms;
        if (elapsed_ms > 0) {
            /* Refill PPS tokens */
            uint32_t pps_refill = (g_rate_config.per_src_pps * elapsed_ms) / 1000;
            uint32_t new_pps = entry->pps_tokens + pps_refill;
            if (new_pps > g_rate_config.per_src_pps) {
                new_pps = g_rate_config.per_src_pps;
            }
            entry->pps_tokens = new_pps;

            /* Refill BPS tokens */
            uint32_t bps_refill = (g_rate_config.per_src_bps * elapsed_ms) / 1000;
            uint32_t new_bps = entry->bps_tokens + bps_refill;
            if (new_bps > g_rate_config.per_src_bps) {
                new_bps = g_rate_config.per_src_bps;
            }
            entry->bps_tokens = new_bps;

            entry->last_update_ms = now_ms;
        }

        /* Apply emergency factor to per-source limits */
        uint32_t effective_pps = g_rate_config.per_src_pps;
        uint32_t effective_bps = g_rate_config.per_src_bps;
        if (emergency) {
            effective_pps = (uint32_t)(effective_pps * g_rate_config.emergency_factor);
            effective_bps = (uint32_t)(effective_bps * g_rate_config.emergency_factor);
        }

        /* Check per-source PPS */
        if (g_rate_config.per_src_pps > 0 && entry->pps_tokens == 0) {
            atomic_fetch_add(&g_rate_state.drops_src_pps, 1);
            atomic_fetch_add(&g_packets_dropped, 1);
            if (out_reason) *out_reason = RATE_DROP_SRC_PPS;
            return false;
        }

        /* Check per-source BPS */
        uint32_t pkt_bits = (uint32_t)pkt_len * 8;
        if (g_rate_config.per_src_bps > 0 && entry->bps_tokens < pkt_bits) {
            atomic_fetch_add(&g_rate_state.drops_src_bps, 1);
            atomic_fetch_add(&g_packets_dropped, 1);
            if (out_reason) *out_reason = RATE_DROP_SRC_BPS;
            return false;
        }

        /* Consume tokens */
        if (g_rate_config.per_src_pps > 0) {
            entry->pps_tokens--;
        }
        if (g_rate_config.per_src_bps > 0) {
            entry->bps_tokens -= pkt_bits;
        }

        entry->packet_count++;
        entry->byte_count += pkt_len;
    }

    /* Packet allowed */
    atomic_fetch_add(&g_packets_allowed, 1);
    return true;
}

/* ============================================================================
 * Protocol Classification
 * ============================================================================ */

proto_class_t rate_limit_get_proto_class(uint8_t protocol, uint8_t tcp_flags)
{
    switch (protocol) {
    case 6: /* TCP */
        if (tcp_flags & 0x02) {        /* SYN */
            if (tcp_flags & 0x10) {    /* SYN+ACK */
                return PROTO_CLASS_TCP_ACK;
            }
            return PROTO_CLASS_TCP_SYN;
        }
        if (tcp_flags & 0x01) return PROTO_CLASS_TCP_FIN;
        if (tcp_flags & 0x04) return PROTO_CLASS_TCP_RST;
        if (tcp_flags & 0x10) return PROTO_CLASS_TCP_ACK;
        return PROTO_CLASS_TCP_OTHER;

    case 17: /* UDP */
        return PROTO_CLASS_UDP;

    case 1:  /* ICMP */
    case 58: /* ICMPv6 */
        return PROTO_CLASS_ICMP;

    default:
        return PROTO_CLASS_OTHER;
    }
}

/* ============================================================================
 * Configuration Management
 * ============================================================================ */

void rate_limit_update_config(const struct rate_limit_config *cfg)
{
    memcpy(&g_rate_config, cfg, sizeof(g_rate_config));
}

void rate_limit_set_emergency(bool enabled)
{
    g_rate_config.emergency_mode = enabled;
}

void rate_limit_set_progressive_factor(float factor)
{
    if (factor < 0.1f) factor = 0.1f;
    if (factor > 1.0f) factor = 1.0f;
    g_rate_config.progressive_factor = factor;
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

void rate_limit_get_current(uint64_t *out_pps, uint64_t *out_bps)
{
    if (out_pps) *out_pps = atomic_load(&g_rate_state.current_pps);
    if (out_bps) *out_bps = atomic_load(&g_rate_state.current_bps);
}

void rate_limit_get_stats(struct rate_limit_stats *stats)
{
    if (!stats) return;

    stats->packets_checked = atomic_load(&g_packets_checked);
    stats->packets_allowed = atomic_load(&g_packets_allowed);
    stats->packets_dropped = atomic_load(&g_packets_dropped);

    stats->drops_by_reason[RATE_DROP_GLOBAL_PPS] = atomic_load(&g_rate_state.drops_global_pps);
    stats->drops_by_reason[RATE_DROP_GLOBAL_BPS] = atomic_load(&g_rate_state.drops_global_bps);
    stats->drops_by_reason[RATE_DROP_PROTO_PPS] = 0;
    for (int i = 0; i < RATE_LIMIT_PROTO_CLASSES; i++) {
        stats->drops_by_reason[RATE_DROP_PROTO_PPS] += atomic_load(&g_rate_state.drops_proto[i]);
    }
    stats->drops_by_reason[RATE_DROP_SRC_PPS] = atomic_load(&g_rate_state.drops_src_pps);
    stats->drops_by_reason[RATE_DROP_SRC_BPS] = atomic_load(&g_rate_state.drops_src_bps);

    stats->current_pps = atomic_load(&g_rate_state.current_pps);
    stats->current_bps = atomic_load(&g_rate_state.current_bps);
    stats->active_sources = atomic_load(&g_active_sources);
    stats->emergency_mode = g_rate_config.emergency_mode;
    stats->progressive_factor = g_rate_config.progressive_factor;
}

/* ============================================================================
 * Maintenance
 * ============================================================================ */

uint32_t rate_limit_clear_old_entries(uint32_t max_age_ms)
{
    if (!g_src_table) return 0;

    uint32_t cleared = 0;
    uint32_t now_ms = get_current_time_ms();

    for (uint32_t i = 0; i < RATE_LIMIT_HASH_SIZE; i++) {
        struct src_rate_entry *entry = &g_src_table[i];

        if (!(entry->flags & SRC_RATE_FLAG_VALID)) continue;

        uint32_t age = now_ms - entry->last_update_ms;
        if (age > max_age_ms) {
            entry->flags = 0;
            atomic_fetch_sub(&g_active_sources, 1);
            cleared++;
        }
    }

    return cleared;
}

void rate_limit_refill_tokens(void)
{
    uint64_t now_tsc;
#ifdef USE_DPDK
    now_tsc = rte_rdtsc();
#else
    now_tsc = get_tsc();
#endif

    uint64_t elapsed_tsc = now_tsc - g_rate_state.last_refill_tsc;
    uint64_t elapsed_ms = (elapsed_tsc * 1000) / g_tsc_hz;

    if (elapsed_ms == 0) return;

    /* Refill global PPS tokens */
    if (g_rate_config.global_pps > 0) {
        uint64_t refill = (g_rate_config.global_pps * elapsed_ms) / 1000;
        uint64_t current = atomic_load(&g_rate_state.pps_tokens);
        uint64_t new_val = current + refill;
        if (new_val > g_rate_config.global_pps) {
            new_val = g_rate_config.global_pps;
        }
        atomic_store(&g_rate_state.pps_tokens, new_val);
    }

    /* Refill global BPS tokens */
    if (g_rate_config.global_bps > 0) {
        uint64_t refill = (g_rate_config.global_bps * elapsed_ms) / 1000;
        uint64_t current = atomic_load(&g_rate_state.bps_tokens);
        uint64_t new_val = current + refill;
        if (new_val > g_rate_config.global_bps) {
            new_val = g_rate_config.global_bps;
        }
        atomic_store(&g_rate_state.bps_tokens, new_val);
    }

    /* Refill per-protocol tokens */
    for (int i = 0; i < RATE_LIMIT_PROTO_CLASSES; i++) {
        uint32_t limit = g_rate_config.proto_pps[i];
        if (limit > 0) {
            uint32_t refill = (limit * (uint32_t)elapsed_ms) / 1000;
            uint32_t current = atomic_load(&g_rate_state.proto_tokens[i]);
            uint32_t new_val = current + refill;
            if (new_val > limit) {
                new_val = limit;
            }
            atomic_store(&g_rate_state.proto_tokens[i], new_val);
        }
    }

    g_rate_state.last_refill_tsc = now_tsc;
}
