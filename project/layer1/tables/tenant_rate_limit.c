/**
 * @file tenant_rate_limit.c
 * @brief Hierarchical Per-Tenant Rate Limiting Implementation
 *
 * Implements the 4-level rate limiting hierarchy:
 * Level 1: Global Emergency (system-wide DDoS protection)
 * Level 2: Per-Tenant Aggregate (total PPS/BPS per tenant)
 * Level 3: Per-Protocol (TCP SYN, UDP, ICMP limits within tenant)
 * Level 4: Per-Source-IP (limits per source within tenant)
 *
 * Performance: <50 cycles per rate check using lock-free atomics
 */

#include "tenant_rate_limit.h"
#include "../layer1.h"
#include "../../common/tenant.h"
#include "../../common/tenant_config.h"

#include <rte_common.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>
#include <rte_atomic.h>

#include <string.h>

// ==================== Internal State ====================

// Per-tenant rate state array (indexed by tenant_id)
static struct tenant_rate_state *g_tenant_rate_states[MAX_TENANTS];

// Global emergency rate state
static struct global_rate_state g_global_rate;

// Hash table for per-source-IP rate tracking
static struct rte_hash *g_src_rate_hash;
static struct tenant_src_rate_entry *g_src_rate_entries;

// TSC frequency for time calculations
static uint64_t g_tsc_hz;

// Lock for state modifications (not used in fast path)
static rte_spinlock_t g_rate_lock = RTE_SPINLOCK_INITIALIZER;

// Initialization flag
static bool g_initialized = false;

// ==================== Protocol Class Names ====================

static const char *proto_class_names[] = {
    "TCP_SYN",
    "TCP_OTHER",
    "UDP",
    "ICMP",
    "OTHER"
};

const char* proto_class_to_string(uint8_t proto_class) {
    if (proto_class >= PROTO_CLASS_COUNT) {
        return "UNKNOWN";
    }
    return proto_class_names[proto_class];
}

// ==================== Token Bucket Implementation ====================

bool token_bucket_consume(struct token_bucket *tb, uint64_t count,
                          uint64_t now_tsc, uint64_t tsc_hz) {
    // First refill based on elapsed time
    token_bucket_refill(tb, now_tsc, tsc_hz);

    // Try to consume tokens atomically
    uint64_t current = atomic_load(&tb->tokens);

    while (current >= count) {
        if (atomic_compare_exchange_weak(&tb->tokens, &current, current - count)) {
            return true;  // Successfully consumed
        }
        // CAS failed, current has been updated, retry
    }

    return false;  // Insufficient tokens
}

void token_bucket_refill(struct token_bucket *tb,
                         uint64_t now_tsc, uint64_t tsc_hz) {
    if (tb->last_update_tsc == 0) {
        tb->last_update_tsc = now_tsc;
        return;
    }

    // Calculate elapsed time in seconds (with high precision)
    uint64_t elapsed_tsc = now_tsc - tb->last_update_tsc;

    // Avoid division by computing: tokens_to_add = (elapsed * rate) / tsc_hz
    // Use 64-bit arithmetic carefully to avoid overflow
    if (elapsed_tsc < tsc_hz / 1000) {
        // Less than 1ms elapsed, skip refill for performance
        return;
    }

    // tokens_to_add = (elapsed_tsc * refill_rate) / tsc_hz
    // Split to avoid overflow: (elapsed_tsc / 1000) * (refill_rate / (tsc_hz / 1000))
    uint64_t tokens_to_add = (elapsed_tsc / 1000) * (tb->refill_rate / (tsc_hz / 1000 + 1));

    if (tokens_to_add == 0) {
        return;
    }

    // Update last_update_tsc
    tb->last_update_tsc = now_tsc;

    // Add tokens atomically, capped at capacity
    uint64_t current = atomic_load(&tb->tokens);
    uint64_t new_val;

    do {
        new_val = current + tokens_to_add;
        if (new_val > tb->capacity) {
            new_val = tb->capacity;
        }
    } while (!atomic_compare_exchange_weak(&tb->tokens, &current, new_val));
}

// ==================== Initialization ====================

int tenant_rate_limit_init(void) {
    if (g_initialized) {
        return 0;
    }

    g_tsc_hz = rte_get_tsc_hz();

    // Initialize global rate state
    memset(&g_global_rate, 0, sizeof(g_global_rate));

    // Default global emergency thresholds (100 Mpps, 100 Gbps)
    g_global_rate.emergency_threshold_pps = 100000000ULL;
    g_global_rate.emergency_threshold_bps = 100000000000ULL;

    // Initialize emergency buckets (very high defaults when not in emergency)
    token_bucket_init(&g_global_rate.emergency_pps,
                      g_global_rate.emergency_threshold_pps,
                      TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&g_global_rate.emergency_bps,
                      g_global_rate.emergency_threshold_bps,
                      TENANT_RATE_BUCKET_BURST_MULT);

    // Create hash table for per-source rate tracking
    struct rte_hash_parameters hash_params = {
        .name = "tenant_src_rate",
        .entries = TENANT_RATE_SRC_HASH_ENTRIES,
        .key_len = sizeof(struct tenant_src_rate_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
    };

    g_src_rate_hash = rte_hash_create(&hash_params);
    if (!g_src_rate_hash) {
        RTE_LOG(ERR, USER1, "Failed to create per-source rate hash table\n");
        return -1;
    }

    // Allocate per-source rate entries
    g_src_rate_entries = rte_zmalloc("tenant_src_rate_entries",
                                      sizeof(struct tenant_src_rate_entry) * TENANT_RATE_MAX_SRC_IPS,
                                      RTE_CACHE_LINE_SIZE);
    if (!g_src_rate_entries) {
        RTE_LOG(ERR, USER1, "Failed to allocate per-source rate entries\n");
        rte_hash_free(g_src_rate_hash);
        g_src_rate_hash = NULL;
        return -1;
    }

    // Initialize per-tenant state pointers to NULL
    memset(g_tenant_rate_states, 0, sizeof(g_tenant_rate_states));

    g_initialized = true;
    RTE_LOG(INFO, USER1, "Tenant rate limiting initialized: %u source IP entries\n",
            TENANT_RATE_MAX_SRC_IPS);

    return 0;
}

void tenant_rate_limit_cleanup(void) {
    if (!g_initialized) {
        return;
    }

    rte_spinlock_lock(&g_rate_lock);

    // Free all tenant rate states
    for (uint32_t i = 0; i < MAX_TENANTS; i++) {
        if (g_tenant_rate_states[i]) {
            rte_free(g_tenant_rate_states[i]);
            g_tenant_rate_states[i] = NULL;
        }
    }

    // Free source rate hash and entries
    if (g_src_rate_hash) {
        rte_hash_free(g_src_rate_hash);
        g_src_rate_hash = NULL;
    }

    if (g_src_rate_entries) {
        rte_free(g_src_rate_entries);
        g_src_rate_entries = NULL;
    }

    g_initialized = false;
    rte_spinlock_unlock(&g_rate_lock);

    RTE_LOG(INFO, USER1, "Tenant rate limiting cleaned up\n");
}

int tenant_rate_state_init(tenant_id_t tenant_id,
                           const struct tenant_l1_config *config) {
    if (!g_initialized || tenant_id >= MAX_TENANTS || !config) {
        return -1;
    }

    rte_spinlock_lock(&g_rate_lock);

    // Cleanup existing state if any
    if (g_tenant_rate_states[tenant_id]) {
        rte_free(g_tenant_rate_states[tenant_id]);
    }

    // Allocate new state
    struct tenant_rate_state *state = rte_zmalloc("tenant_rate_state",
                                                   sizeof(struct tenant_rate_state),
                                                   RTE_CACHE_LINE_SIZE);
    if (!state) {
        rte_spinlock_unlock(&g_rate_lock);
        return -1;
    }

    state->tenant_id = tenant_id;
    state->config = config;
    state->config_version = 1;
    state->flags = TENANT_RATE_FLAG_ACTIVE;

    // Initialize aggregate buckets from config
    token_bucket_init(&state->total_pps, config->rate_limits.global_pps, TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&state->total_bps, config->rate_limits.global_bps, TENANT_RATE_BUCKET_BURST_MULT);

    // Initialize per-protocol buckets
    token_bucket_init(&state->proto[PROTO_CLASS_TCP_SYN], config->rate_limits.syn_pps, TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&state->proto[PROTO_CLASS_TCP_OTHER], config->rate_limits.global_pps / 2, TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&state->proto[PROTO_CLASS_UDP], config->rate_limits.udp_pps, TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&state->proto[PROTO_CLASS_ICMP], config->rate_limits.icmp_pps, TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&state->proto[PROTO_CLASS_OTHER], config->rate_limits.global_pps / 4, TENANT_RATE_BUCKET_BURST_MULT);

    // Initialize measurement window
    state->window_start_tsc = rte_rdtsc();

    g_tenant_rate_states[tenant_id] = state;

    rte_spinlock_unlock(&g_rate_lock);

    RTE_LOG(DEBUG, USER1, "Tenant %u rate state initialized: %lu PPS, %lu BPS\n",
            tenant_id, config->rate_limits.global_pps, config->rate_limits.global_bps);

    return 0;
}

void tenant_rate_state_cleanup(tenant_id_t tenant_id) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return;
    }

    rte_spinlock_lock(&g_rate_lock);

    if (g_tenant_rate_states[tenant_id]) {
        rte_free(g_tenant_rate_states[tenant_id]);
        g_tenant_rate_states[tenant_id] = NULL;
    }

    rte_spinlock_unlock(&g_rate_lock);
}

int tenant_rate_state_update_config(tenant_id_t tenant_id,
                                    const struct tenant_l1_config *config) {
    if (!g_initialized || tenant_id >= MAX_TENANTS || !config) {
        return -1;
    }

    struct tenant_rate_state *state = g_tenant_rate_states[tenant_id];
    if (!state) {
        // State doesn't exist, create it
        return tenant_rate_state_init(tenant_id, config);
    }

    rte_spinlock_lock(&g_rate_lock);

    // Update config pointer and version
    state->config = config;
    state->config_version++;

    // Reinitialize buckets with new limits (preserves current tokens if within new capacity)
    token_bucket_init(&state->total_pps, config->rate_limits.global_pps, TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&state->total_bps, config->rate_limits.global_bps, TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&state->proto[PROTO_CLASS_TCP_SYN], config->rate_limits.syn_pps, TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&state->proto[PROTO_CLASS_TCP_OTHER], config->rate_limits.global_pps / 2, TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&state->proto[PROTO_CLASS_UDP], config->rate_limits.udp_pps, TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&state->proto[PROTO_CLASS_ICMP], config->rate_limits.icmp_pps, TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&state->proto[PROTO_CLASS_OTHER], config->rate_limits.global_pps / 4, TENANT_RATE_BUCKET_BURST_MULT);

    rte_spinlock_unlock(&g_rate_lock);

    return 0;
}

// ==================== Fast Path: Rate Checking ====================

/**
 * Level 4: Per-source-IP rate check
 */
static inline bool check_src_rate(tenant_id_t tenant_id, uint32_t src_ip,
                                  uint8_t proto_class, uint16_t pkt_len,
                                  const struct tenant_l1_config *config,
                                  uint64_t *out_src_pps) {
    struct tenant_src_rate_key key = {
        .tenant_id = tenant_id,
        .src_ip = src_ip,
        .proto_class = proto_class,
    };

    int32_t idx = rte_hash_lookup(g_src_rate_hash, &key);

    if (idx < 0) {
        // New source IP, try to add
        idx = rte_hash_add_key(g_src_rate_hash, &key);
        if (idx < 0) {
            // Hash table full, allow packet (fail-open for per-source)
            *out_src_pps = 0;
            return true;
        }

        // Initialize new entry using atomic operations
        struct tenant_src_rate_entry *entry = &g_src_rate_entries[idx];
        atomic_store(&entry->tokens, config->rate_limits.per_src_pps);  // Start with full bucket
        atomic_store(&entry->last_update_ms, (uint32_t)(rte_rdtsc() / (g_tsc_hz / 1000)));
        atomic_store(&entry->packet_count, 1);
        atomic_store(&entry->byte_count, pkt_len);
        *out_src_pps = 1;
        return true;
    }

    struct tenant_src_rate_entry *entry = &g_src_rate_entries[idx];

    // Use atomic operations for all field access
    // Calculate elapsed time for token refill
    uint32_t now_ms = (uint32_t)(rte_rdtsc() / (g_tsc_hz / 1000));
    uint32_t last_ms = atomic_load(&entry->last_update_ms);
    uint32_t elapsed_ms = now_ms - last_ms;

    if (elapsed_ms > 0) {
        // Try to claim this refill window (only one lcore should update)
        if (atomic_compare_exchange_weak(&entry->last_update_ms, &last_ms, now_ms)) {
            // Refill tokens: tokens_per_ms = per_src_pps / 1000
            uint32_t refill = (elapsed_ms * config->rate_limits.per_src_pps) / 1000;
            uint32_t max_tokens = config->rate_limits.per_src_pps * TENANT_RATE_BUCKET_BURST_MULT;

            // Atomically add tokens with cap
            uint32_t current = atomic_load(&entry->tokens);
            uint32_t new_tokens;
            do {
                new_tokens = current + refill;
                if (new_tokens > max_tokens) {
                    new_tokens = max_tokens;
                }
            } while (!atomic_compare_exchange_weak(&entry->tokens, &current, new_tokens));

            // Reset window counters if elapsed > 1 second
            if (elapsed_ms > 1000) {
                atomic_store(&entry->packet_count, 0);
                atomic_store(&entry->byte_count, 0);
            }
        }
    }

    // Try to consume token atomically
    uint32_t tokens = atomic_load(&entry->tokens);
    while (tokens > 0) {
        if (atomic_compare_exchange_weak(&entry->tokens, &tokens, tokens - 1)) {
            atomic_fetch_add(&entry->packet_count, 1);
            atomic_fetch_add(&entry->byte_count, pkt_len);
            *out_src_pps = atomic_load(&entry->packet_count);
            return true;
        }
        // tokens was updated by CAS, retry with new value
    }

    // Rate exceeded
    *out_src_pps = atomic_load(&entry->packet_count);
    return false;
}

bool tenant_rate_check(tenant_id_t tenant_id,
                       uint32_t src_ip,
                       uint8_t protocol,
                       uint16_t pkt_len,
                       uint8_t tcp_flags,
                       struct rate_check_result *result) {
    uint64_t now_tsc = rte_rdtsc();
    uint8_t proto_class = get_proto_class(protocol, tcp_flags);

    // Initialize result
    result->allowed = false;
    result->drop_reason = 0;
    result->drop_level = 0;
    result->proto_class = proto_class;
    result->tenant_pps = 0;
    result->tenant_bps = 0;
    result->src_pps = 0;

    // Level 1: Global emergency check
    if (atomic_load(&g_global_rate.emergency_active)) {
        if (!token_bucket_consume(&g_global_rate.emergency_pps, 1, now_tsc, g_tsc_hz) ||
            !token_bucket_consume(&g_global_rate.emergency_bps, pkt_len, now_tsc, g_tsc_hz)) {
            result->drop_reason = DROP_REASON_TENANT_EMERGENCY;
            result->drop_level = 1;
            atomic_fetch_add(&g_global_rate.emergency_drops, 1);
            return false;
        }
    }

    // Get tenant rate state
    if (tenant_id >= MAX_TENANTS) {
        result->drop_reason = DROP_REASON_NOT_PROTECTED;
        result->drop_level = 2;
        return false;
    }

    struct tenant_rate_state *state = g_tenant_rate_states[tenant_id];
    if (!state || !(state->flags & TENANT_RATE_FLAG_ACTIVE)) {
        result->drop_reason = DROP_REASON_TENANT_SUSPENDED;
        result->drop_level = 2;
        return false;
    }

    // Check tenant emergency mode
    if (atomic_load(&state->emergency_mode)) {
        // In emergency, use much stricter limits (10% of normal)
        // For now, just mark as rate limited
        result->drop_reason = DROP_REASON_TENANT_EMERGENCY;
        result->drop_level = 2;
        atomic_fetch_add(&state->drops_total, 1);
        return false;
    }

    // Level 2: Per-tenant aggregate limits
    if (!token_bucket_consume(&state->total_pps, 1, now_tsc, g_tsc_hz)) {
        result->drop_reason = DROP_REASON_TENANT_RATE_LIMIT;
        result->drop_level = 2;
        atomic_fetch_add(&state->drops_total, 1);
        atomic_fetch_add(&state->drops_pps, 1);
        atomic_store(&state->rate_exceeded, true);
        return false;
    }

    if (!token_bucket_consume(&state->total_bps, pkt_len, now_tsc, g_tsc_hz)) {
        result->drop_reason = DROP_REASON_TENANT_RATE_LIMIT;
        result->drop_level = 2;
        atomic_fetch_add(&state->drops_total, 1);
        atomic_fetch_add(&state->drops_bps, 1);
        atomic_store(&state->rate_exceeded, true);
        return false;
    }

    // Level 3: Per-protocol limits
    if (!token_bucket_consume(&state->proto[proto_class], 1, now_tsc, g_tsc_hz)) {
        result->drop_reason = DROP_REASON_TENANT_RATE_LIMIT;
        result->drop_level = 3;
        atomic_fetch_add(&state->drops_total, 1);
        atomic_fetch_add(&state->drops_proto[proto_class], 1);
        return false;
    }

    // Level 4: Per-source-IP limits
    if (state->config && state->config->rate_limits.per_src_pps > 0) {
        if (!check_src_rate(tenant_id, src_ip, proto_class, pkt_len,
                           state->config, &result->src_pps)) {
            result->drop_reason = DROP_REASON_TENANT_RATE_LIMIT;
            result->drop_level = 4;
            atomic_fetch_add(&state->drops_total, 1);
            atomic_fetch_add(&state->drops_src, 1);
            return false;
        }
    }

    // Update counters for accepted packet
    atomic_fetch_add(&state->window_packets, 1);
    atomic_fetch_add(&state->window_bytes, pkt_len);

    // Update result
    result->allowed = true;
    result->tenant_pps = atomic_load(&state->current_pps);
    result->tenant_bps = atomic_load(&state->current_bps);

    return true;
}

bool tenant_rate_check_simple(tenant_id_t tenant_id,
                              uint32_t src_ip,
                              uint8_t protocol,
                              uint16_t pkt_len,
                              uint8_t tcp_flags,
                              uint8_t *out_reason) {
    struct rate_check_result result;
    bool allowed = tenant_rate_check(tenant_id, src_ip, protocol, pkt_len,
                                     tcp_flags, &result);
    if (out_reason) {
        *out_reason = result.drop_reason;
    }
    return allowed;
}

void tenant_rate_update_counters(tenant_id_t tenant_id,
                                 uint32_t src_ip __rte_unused,
                                 uint8_t protocol __rte_unused,
                                 uint16_t pkt_len) {
    if (tenant_id >= MAX_TENANTS) {
        return;
    }

    struct tenant_rate_state *state = g_tenant_rate_states[tenant_id];
    if (!state) {
        return;
    }

    atomic_fetch_add(&state->window_packets, 1);
    atomic_fetch_add(&state->window_bytes, pkt_len);
}

// ==================== Global Emergency API ====================

bool global_rate_check(uint32_t src_ip __rte_unused, uint16_t pkt_len) {
    if (!atomic_load(&g_global_rate.emergency_active)) {
        return true;
    }

    uint64_t now_tsc = rte_rdtsc();

    if (!token_bucket_consume(&g_global_rate.emergency_pps, 1, now_tsc, g_tsc_hz)) {
        atomic_fetch_add(&g_global_rate.emergency_drops, 1);
        return false;
    }

    if (!token_bucket_consume(&g_global_rate.emergency_bps, pkt_len, now_tsc, g_tsc_hz)) {
        atomic_fetch_add(&g_global_rate.emergency_drops, 1);
        return false;
    }

    return true;
}

void global_rate_set_emergency(uint64_t threshold_pps, uint64_t threshold_bps) {
    rte_spinlock_lock(&g_rate_lock);

    if (threshold_pps == 0) {
        threshold_pps = g_global_rate.emergency_threshold_pps / 10;  // Default to 10% of normal
    }
    if (threshold_bps == 0) {
        threshold_bps = g_global_rate.emergency_threshold_bps / 10;
    }

    token_bucket_init(&g_global_rate.emergency_pps, threshold_pps, 1);  // No burst in emergency
    token_bucket_init(&g_global_rate.emergency_bps, threshold_bps, 1);

    g_global_rate.emergency_start_tsc = rte_rdtsc();
    atomic_store(&g_global_rate.emergency_active, true);

    rte_spinlock_unlock(&g_rate_lock);

    RTE_LOG(ALERT, USER1, "GLOBAL EMERGENCY MODE ACTIVATED: %lu PPS, %lu BPS\n",
            threshold_pps, threshold_bps);
}

void global_rate_clear_emergency(void) {
    if (!atomic_load(&g_global_rate.emergency_active)) {
        return;
    }

    rte_spinlock_lock(&g_rate_lock);

    atomic_store(&g_global_rate.emergency_active, false);

    // Restore normal limits
    token_bucket_init(&g_global_rate.emergency_pps,
                      g_global_rate.emergency_threshold_pps,
                      TENANT_RATE_BUCKET_BURST_MULT);
    token_bucket_init(&g_global_rate.emergency_bps,
                      g_global_rate.emergency_threshold_bps,
                      TENANT_RATE_BUCKET_BURST_MULT);

    rte_spinlock_unlock(&g_rate_lock);

    RTE_LOG(NOTICE, USER1, "Global emergency mode deactivated\n");
}

bool global_rate_is_emergency(void) {
    return atomic_load(&g_global_rate.emergency_active);
}

void global_rate_update_stats(uint64_t pps, uint64_t bps) {
    atomic_store(&g_global_rate.global_pps, pps);
    atomic_store(&g_global_rate.global_bps, bps);

    // Check if we should auto-activate emergency mode
    if (!atomic_load(&g_global_rate.emergency_active)) {
        if (pps > g_global_rate.emergency_threshold_pps ||
            bps > g_global_rate.emergency_threshold_bps) {
            RTE_LOG(WARNING, USER1, "Traffic exceeds emergency thresholds: %lu PPS, %lu BPS\n",
                    pps, bps);
            // Note: Auto-activation should be policy decision, not automatic
        }
    }
}

// ==================== Tenant Control API ====================

int tenant_rate_set_limits(tenant_id_t tenant_id, uint64_t pps, uint64_t bps) {
    if (tenant_id >= MAX_TENANTS) {
        return -1;
    }

    struct tenant_rate_state *state = g_tenant_rate_states[tenant_id];
    if (!state) {
        return -1;
    }

    rte_spinlock_lock(&g_rate_lock);

    if (pps > 0) {
        token_bucket_init(&state->total_pps, pps, TENANT_RATE_BUCKET_BURST_MULT);
        state->flags |= TENANT_RATE_FLAG_CUSTOM_LIMIT;
    } else if (state->config) {
        // Clear override, restore tier default
        token_bucket_init(&state->total_pps, state->config->rate_limits.global_pps, TENANT_RATE_BUCKET_BURST_MULT);
        state->flags &= ~TENANT_RATE_FLAG_CUSTOM_LIMIT;
    }

    if (bps > 0) {
        token_bucket_init(&state->total_bps, bps, TENANT_RATE_BUCKET_BURST_MULT);
        state->flags |= TENANT_RATE_FLAG_CUSTOM_LIMIT;
    } else if (state->config) {
        token_bucket_init(&state->total_bps, state->config->rate_limits.global_bps, TENANT_RATE_BUCKET_BURST_MULT);
    }

    rte_spinlock_unlock(&g_rate_lock);

    RTE_LOG(INFO, USER1, "Tenant %u rate limits updated: %lu PPS, %lu BPS\n",
            tenant_id, pps, bps);

    return 0;
}

int tenant_rate_set_proto_limit(tenant_id_t tenant_id,
                                uint8_t proto_class, uint64_t pps) {
    if (tenant_id >= MAX_TENANTS || proto_class >= PROTO_CLASS_COUNT) {
        return -1;
    }

    struct tenant_rate_state *state = g_tenant_rate_states[tenant_id];
    if (!state) {
        return -1;
    }

    rte_spinlock_lock(&g_rate_lock);
    token_bucket_init(&state->proto[proto_class], pps, TENANT_RATE_BUCKET_BURST_MULT);
    rte_spinlock_unlock(&g_rate_lock);

    RTE_LOG(INFO, USER1, "Tenant %u %s rate limit: %lu PPS\n",
            tenant_id, proto_class_to_string(proto_class), pps);

    return 0;
}

void tenant_rate_set_emergency(tenant_id_t tenant_id, bool emergency) {
    if (tenant_id >= MAX_TENANTS) {
        return;
    }

    struct tenant_rate_state *state = g_tenant_rate_states[tenant_id];
    if (!state) {
        return;
    }

    atomic_store(&state->emergency_mode, emergency);

    if (emergency) {
        state->flags |= TENANT_RATE_FLAG_EMERGENCY;
        RTE_LOG(ALERT, USER1, "Tenant %u EMERGENCY MODE ACTIVATED\n", tenant_id);
    } else {
        state->flags &= ~TENANT_RATE_FLAG_EMERGENCY;
        RTE_LOG(NOTICE, USER1, "Tenant %u emergency mode deactivated\n", tenant_id);
    }
}

bool tenant_rate_is_emergency(tenant_id_t tenant_id) {
    if (tenant_id >= MAX_TENANTS) {
        return false;
    }

    struct tenant_rate_state *state = g_tenant_rate_states[tenant_id];
    if (!state) {
        return false;
    }

    return atomic_load(&state->emergency_mode);
}

// ==================== Statistics API ====================

int tenant_rate_get_current(tenant_id_t tenant_id,
                            uint64_t *out_pps, uint64_t *out_bps) {
    if (tenant_id >= MAX_TENANTS) {
        return -1;
    }

    struct tenant_rate_state *state = g_tenant_rate_states[tenant_id];
    if (!state) {
        return -1;
    }

    if (out_pps) {
        *out_pps = atomic_load(&state->current_pps);
    }
    if (out_bps) {
        *out_bps = atomic_load(&state->current_bps);
    }

    return 0;
}

int tenant_rate_get_peak(tenant_id_t tenant_id,
                         uint64_t *out_peak_pps, uint64_t *out_peak_bps) {
    if (tenant_id >= MAX_TENANTS) {
        return -1;
    }

    struct tenant_rate_state *state = g_tenant_rate_states[tenant_id];
    if (!state) {
        return -1;
    }

    if (out_peak_pps) {
        *out_peak_pps = atomic_load(&state->peak_pps);
    }
    if (out_peak_bps) {
        *out_peak_bps = atomic_load(&state->peak_bps);
    }

    return 0;
}

int tenant_rate_get_drops(tenant_id_t tenant_id,
                          uint64_t *out_total,
                          uint64_t *out_pps_drops,
                          uint64_t *out_bps_drops) {
    if (tenant_id >= MAX_TENANTS) {
        return -1;
    }

    struct tenant_rate_state *state = g_tenant_rate_states[tenant_id];
    if (!state) {
        return -1;
    }

    if (out_total) {
        *out_total = atomic_load(&state->drops_total);
    }
    if (out_pps_drops) {
        *out_pps_drops = atomic_load(&state->drops_pps);
    }
    if (out_bps_drops) {
        *out_bps_drops = atomic_load(&state->drops_bps);
    }

    return 0;
}

void tenant_rate_reset_stats(tenant_id_t tenant_id) {
    if (tenant_id >= MAX_TENANTS) {
        return;
    }

    struct tenant_rate_state *state = g_tenant_rate_states[tenant_id];
    if (!state) {
        return;
    }

    atomic_store(&state->drops_total, 0);
    atomic_store(&state->drops_pps, 0);
    atomic_store(&state->drops_bps, 0);
    for (int i = 0; i < PROTO_CLASS_COUNT; i++) {
        atomic_store(&state->drops_proto[i], 0);
    }
    atomic_store(&state->drops_src, 0);
    atomic_store(&state->peak_pps, 0);
    atomic_store(&state->peak_bps, 0);
}

void tenant_rate_reset_all_stats(void) {
    for (uint32_t i = 0; i < MAX_TENANTS; i++) {
        tenant_rate_reset_stats(i);
    }
    atomic_store(&g_global_rate.emergency_drops, 0);
}

// ==================== Maintenance API ====================

void tenant_rate_maintenance(void) {
    uint64_t now_tsc = rte_rdtsc();

    // Update rates for all active tenants
    for (uint32_t i = 0; i < MAX_TENANTS; i++) {
        struct tenant_rate_state *state = g_tenant_rate_states[i];
        if (!state || !(state->flags & TENANT_RATE_FLAG_ACTIVE)) {
            continue;
        }

        // Calculate elapsed time
        uint64_t elapsed_tsc = now_tsc - state->window_start_tsc;
        uint64_t elapsed_ms = (elapsed_tsc * 1000) / g_tsc_hz;

        if (elapsed_ms >= 100) {  // Update every 100ms
            // Calculate current rates
            uint64_t packets = atomic_exchange(&state->window_packets, 0);
            uint64_t bytes = atomic_exchange(&state->window_bytes, 0);

            // Convert to per-second rates
            uint64_t pps = (packets * 1000) / elapsed_ms;
            uint64_t bps = (bytes * 8 * 1000) / elapsed_ms;  // Convert to bits

            atomic_store(&state->current_pps, pps);
            atomic_store(&state->current_bps, bps);

            // Update peaks
            uint64_t peak_pps = atomic_load(&state->peak_pps);
            if (pps > peak_pps) {
                atomic_store(&state->peak_pps, pps);
            }

            uint64_t peak_bps = atomic_load(&state->peak_bps);
            if (bps > peak_bps) {
                atomic_store(&state->peak_bps, bps);
            }

            // Reset window
            state->window_start_tsc = now_tsc;

            // Clear rate_exceeded flag if we're back under limits
            if (atomic_load(&state->rate_exceeded)) {
                // Check if current rate is under 90% of limit
                if (state->config &&
                    pps < state->config->rate_limits.global_pps * 9 / 10 &&
                    bps < state->config->rate_limits.global_bps * 9 / 10) {
                    atomic_store(&state->rate_exceeded, false);
                }
            }

            // Refill token buckets
            token_bucket_refill(&state->total_pps, now_tsc, g_tsc_hz);
            token_bucket_refill(&state->total_bps, now_tsc, g_tsc_hz);
            for (int j = 0; j < PROTO_CLASS_COUNT; j++) {
                token_bucket_refill(&state->proto[j], now_tsc, g_tsc_hz);
            }
        }
    }

    // Update global rate stats
    uint64_t total_pps = 0, total_bps = 0;
    for (uint32_t i = 0; i < MAX_TENANTS; i++) {
        struct tenant_rate_state *state = g_tenant_rate_states[i];
        if (state && (state->flags & TENANT_RATE_FLAG_ACTIVE)) {
            total_pps += atomic_load(&state->current_pps);
            total_bps += atomic_load(&state->current_bps);
        }
    }
    global_rate_update_stats(total_pps, total_bps);
}

uint32_t tenant_rate_age_src_entries(void) {
    if (!g_src_rate_hash || !g_src_rate_entries) {
        return 0;
    }

    uint32_t aged_out = 0;
    uint32_t now_ms = (uint32_t)(rte_rdtsc() / (g_tsc_hz / 1000));
    uint32_t age_threshold_ms = 60000;  // 60 seconds

    // Iterate through hash table
    const void *key;
    void *data;
    uint32_t iter = 0;
    int32_t idx;

    while ((idx = rte_hash_iterate(g_src_rate_hash, &key, &data, &iter)) >= 0) {
        struct tenant_src_rate_entry *entry = &g_src_rate_entries[idx];
        uint32_t age = now_ms - entry->last_update_ms;

        if (age > age_threshold_ms) {
            // Remove stale entry
            rte_hash_del_key(g_src_rate_hash, key);
            aged_out++;
        }
    }

    if (aged_out > 0) {
        RTE_LOG(DEBUG, USER1, "Aged out %u per-source rate entries\n", aged_out);
    }

    return aged_out;
}
