/**
 * @file flow_table_v6.c
 * @brief IPv6 flow table implementation
 *
 * Full implementation using the same design principles as IPv4 flow table:
 * - CANONICAL keys: ip_lo <= ip_hi (lexicographic comparison)
 * - Lock-free operations: rte_ring for index allocation
 * - Per-lcore statistics to avoid cache contention
 * - Cache-aligned entries for multi-core access
 */

#include "flow_table_v6.h"
#include "flow_table.h"
#include "../datapath/packet_parser.h"
#include "../interlayer/shared_memory.h"
#include "../config/layer1_config.h"
#include <rte_hash.h>
#include <rte_ring.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_lcore.h>
#include <rte_memcpy.h>
#include <string.h>
#include <netinet/in.h>

#define RTE_LOGTYPE_FLOW_V6 RTE_LOGTYPE_USER4

// ==================== Constants ====================

#define AGING_BATCH_SIZE      512
#define FREE_RING_NAME_FMT    "flow6_free_%u_%lu"
#define HASH_NAME_FMT         "flow6_hash_%u_%lu"
#define MAX_LCORES            RTE_MAX_LCORE

// ==================== Global State ====================

static struct rte_hash *flow_hash_v6 = NULL;
static struct flow_entry_v6 *flow_entries_v6 = NULL;
static struct rte_ring *free_index_ring_v6 = NULL;
static struct flow_table_v6_config config_v6;
static uint64_t tsc_hz_v6 = 0;
static bool initialized_v6 = false;

// Per-lcore statistics - NO ATOMICS in fast path
static struct flow_table_v6_stats lcore_stats_v6[MAX_LCORES] __rte_cache_aligned;

// Per-lcore RST/FIN validation stats
struct rst_fin_lcore_stats_v6 {
    uint64_t valid_count;
    uint64_t invalid_seq;
    uint64_t invalid_no_flow;
    uint64_t invalid_state;
    uint64_t _pad[4];
} __rte_cache_aligned;
static struct rst_fin_lcore_stats_v6 rst_fin_stats_v6[MAX_LCORES] __rte_cache_aligned;

// Global stats for aging (single-threaded operation)
static uint64_t global_deletes_v6 = 0;

// ==================== Per-Lcore Free Cache ====================

#define LOCAL_FREE_CACHE_SIZE_V6  64
#define LOCAL_REFILL_BATCH_V6     32

struct lcore_free_cache_v6 {
    uint32_t indices[LOCAL_FREE_CACHE_SIZE_V6];
    uint32_t count;
    uint32_t _pad[14];
} __rte_cache_aligned;

static struct lcore_free_cache_v6 lcore_free_caches_v6[MAX_LCORES];

// ==================== Helper Functions ====================

static inline uint64_t seconds_to_tsc_v6(uint32_t seconds) {
    return (uint64_t)seconds * tsc_hz_v6;
}

// Hash function for IPv6 flow keys
static inline uint32_t flow_key_v6_hash(const void *key, uint32_t key_len __rte_unused,
                                         uint32_t init_val)
{
    const uint32_t *k = (const uint32_t *)key;
    // Hash 36 bytes = 9 uint32_t (2x16 bytes for IPs + 4 bytes protocol/padding)
    return rte_jhash_32b(k, 9, init_val);
}

// ==================== Index Allocation ====================

static inline int32_t flow_entry_v6_alloc(void) {
    unsigned int lcore_id = rte_lcore_id();
    if (unlikely(lcore_id >= MAX_LCORES)) {
        lcore_id = 0;
    }

    struct lcore_free_cache_v6 *cache = &lcore_free_caches_v6[lcore_id];

    // Fast path: get from local cache
    if (likely(cache->count > 0)) {
        return (int32_t)cache->indices[--cache->count];
    }

    // Calculate available space to prevent overflow
    uint32_t available_space = LOCAL_FREE_CACHE_SIZE_V6 - cache->count;
    uint32_t refill_count = (available_space > LOCAL_REFILL_BATCH_V6) ?
                            LOCAL_REFILL_BATCH_V6 : available_space;

    // Slow path: refill from global ring
    void *idx_ptrs[LOCAL_REFILL_BATCH_V6];
    unsigned int got = rte_ring_mc_dequeue_burst(free_index_ring_v6, idx_ptrs,
                                                  refill_count, NULL);
    if (unlikely(got == 0)) {
        return -1;  // Ring empty
    }

    // Store all but one in local cache
    for (unsigned int i = 1; i < got && cache->count < LOCAL_FREE_CACHE_SIZE_V6; i++) {
        cache->indices[cache->count++] = (uint32_t)(uintptr_t)idx_ptrs[i];
    }

    return (int32_t)(uintptr_t)idx_ptrs[0];
}

static inline void flow_entry_v6_free(uint32_t index) {
    rte_ring_mp_enqueue(free_index_ring_v6, (void *)(uintptr_t)index);
}

// ==================== Initialization ====================

int flow_table_v6_init(const struct flow_table_v6_config *cfg)
{
    struct rte_hash_parameters hash_params = {0};
    char name[RTE_RING_NAMESIZE];
    uint32_t i;
    int socket_id;

    if (initialized_v6) {
        RTE_LOG(WARNING, FLOW_V6, "IPv6 flow table already initialized\n");
        return 0;
    }

    if (cfg) {
        memcpy(&config_v6, cfg, sizeof(config_v6));
    } else {
        // Defaults
        memset(&config_v6, 0, sizeof(config_v6));
        config_v6.max_flows = 100000;
        config_v6.idle_timeout_sec = 120;
        config_v6.syn_timeout_sec = 30;
        config_v6.enable_syn_protection = true;
        config_v6.aging_scan_limit = 4096;
    }

    memset(lcore_stats_v6, 0, sizeof(lcore_stats_v6));
    memset(rst_fin_stats_v6, 0, sizeof(rst_fin_stats_v6));
    global_deletes_v6 = 0;
    tsc_hz_v6 = rte_get_tsc_hz();

    socket_id = SOCKET_ID_ANY;

    RTE_LOG(INFO, FLOW_V6, "Initializing IPv6 flow table:\n");
    RTE_LOG(INFO, FLOW_V6, "  Max flows: %u\n", config_v6.max_flows);
    RTE_LOG(INFO, FLOW_V6, "  Idle timeout: %u sec\n", config_v6.idle_timeout_sec);
    RTE_LOG(INFO, FLOW_V6, "  SYN timeout: %u sec\n", config_v6.syn_timeout_sec);
    RTE_LOG(INFO, FLOW_V6, "  Entry size: %zu bytes\n", sizeof(struct flow_entry_v6));

    // Allocate flow entries array
    flow_entries_v6 = rte_zmalloc_socket("flow_entries_v6",
                                          config_v6.max_flows * sizeof(struct flow_entry_v6),
                                          RTE_CACHE_LINE_SIZE,
                                          socket_id);
    if (!flow_entries_v6) {
        RTE_LOG(ERR, FLOW_V6, "Failed to allocate flow entries (%zu MB)\n",
                (config_v6.max_flows * sizeof(struct flow_entry_v6)) / (1024 * 1024));
        return -1;
    }

    // Create free index ring
    uint32_t ring_size = rte_align32pow2(config_v6.max_flows + 1);

    snprintf(name, sizeof(name), FREE_RING_NAME_FMT,
             rte_lcore_id(), (unsigned long)rte_get_tsc_cycles());

    free_index_ring_v6 = rte_ring_create(name, ring_size, socket_id, 0);
    if (!free_index_ring_v6) {
        RTE_LOG(ERR, FLOW_V6, "Failed to create free index ring (size %u)\n", ring_size);
        rte_free(flow_entries_v6);
        flow_entries_v6 = NULL;
        return -1;
    }

    // Pre-populate ring with all available indices
    for (i = 0; i < config_v6.max_flows; i++) {
        rte_ring_mp_enqueue(free_index_ring_v6, (void *)(uintptr_t)i);
    }

    // Initialize per-lcore free caches
    memset(lcore_free_caches_v6, 0, sizeof(lcore_free_caches_v6));

    RTE_LOG(INFO, FLOW_V6, "  Free ring size: %u (populated: %u)\n",
            ring_size, rte_ring_count(free_index_ring_v6));

    // Create hash table
    snprintf(name, sizeof(name), HASH_NAME_FMT,
             rte_lcore_id(), (unsigned long)rte_get_tsc_cycles());

    hash_params.name = name;
    hash_params.entries = config_v6.max_flows;
    hash_params.key_len = sizeof(struct flow_key_v6);
    hash_params.hash_func = flow_key_v6_hash;
    hash_params.hash_func_init_val = 0;
    hash_params.socket_id = socket_id;
    hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                             RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT;

    flow_hash_v6 = rte_hash_create(&hash_params);
    if (!flow_hash_v6) {
        RTE_LOG(ERR, FLOW_V6, "Failed to create hash table\n");
        rte_ring_free(free_index_ring_v6);
        free_index_ring_v6 = NULL;
        rte_free(flow_entries_v6);
        flow_entries_v6 = NULL;
        return -1;
    }

    initialized_v6 = true;
    RTE_LOG(INFO, FLOW_V6, "IPv6 flow table initialized (lock-free, thread-safe)\n");
    return 0;
}

void flow_table_v6_cleanup(void)
{
    if (!initialized_v6) {
        return;
    }

    if (flow_hash_v6) {
        rte_hash_free(flow_hash_v6);
        flow_hash_v6 = NULL;
    }
    if (free_index_ring_v6) {
        rte_ring_free(free_index_ring_v6);
        free_index_ring_v6 = NULL;
    }
    if (flow_entries_v6) {
        rte_free(flow_entries_v6);
        flow_entries_v6 = NULL;
    }

    initialized_v6 = false;
    RTE_LOG(INFO, FLOW_V6, "IPv6 flow table cleanup complete\n");
}

// ==================== Per-Lcore Stats Helper ====================

static inline struct flow_table_v6_stats* get_flow_v6_lcore_stats(void) {
    unsigned int lcore_id = rte_lcore_id();
    if (unlikely(lcore_id >= MAX_LCORES)) lcore_id = 0;
    return &lcore_stats_v6[lcore_id];
}

// ==================== Flow Lookup Operations ====================

struct flow_entry_v6* flow_table_v6_lookup(struct packet_features_v6 *features)
{
    struct flow_key_v6 key;
    struct flow_entry_v6 *flow = NULL;
    int ret;

    if (unlikely(!initialized_v6 || !features)) {
        return NULL;
    }

    extract_flow_key_v6(features, &key);

    struct flow_table_v6_stats *lstats = get_flow_v6_lcore_stats();
    lstats->lookups++;

    ret = rte_hash_lookup_data(flow_hash_v6, &key, (void **)&flow);
    if (ret >= 0 && flow != NULL) {
        lstats->lookup_hits++;
        rte_prefetch0(flow);
        return flow;
    }

    return NULL;
}

/**
 * Internal lookup or create implementation
 */
static inline struct flow_entry_v6* flow_table_v6_lookup_or_create_internal(
        struct packet_features_v6 *features,
        bool *created,
        uint64_t now_tsc)
{
    struct flow_key_v6 key;
    struct flow_entry_v6 *flow = NULL;
    int32_t entry_index;
    int ret;
    hash_sig_t hash;

    if (unlikely(!initialized_v6 || !features)) {
        return NULL;
    }

    *created = false;

    extract_flow_key_v6(features, &key);

    struct flow_table_v6_stats *lstats = get_flow_v6_lcore_stats();
    lstats->lookups++;

    // Compute hash once
    hash = rte_hash_hash(flow_hash_v6, &key);

    // Fast path: check if flow exists
    ret = rte_hash_lookup_with_hash_data(flow_hash_v6, &key, hash, (void **)&flow);
    if (ret >= 0 && flow != NULL) {
        lstats->lookup_hits++;
        rte_prefetch0(flow);
        return flow;
    }

    // Slow path: create new flow
    entry_index = flow_entry_v6_alloc();
    if (unlikely(entry_index < 0)) {
        lstats->create_failures++;
        static uint64_t log_count = 0;
        if (unlikely(__atomic_fetch_add(&log_count, 1, __ATOMIC_RELAXED) < 10)) {
            RTE_LOG(WARNING, FLOW_V6, "IPv6 flow table full (max %u)\n",
                    config_v6.max_flows);
        }
        return NULL;
    }

    flow = &flow_entries_v6[entry_index];

    if (now_tsc == 0) {
        now_tsc = rte_rdtsc();
    }

    // Zero entire struct to prevent info leakage
    memset(flow, 0, sizeof(*flow));

    // Two-phase initialization
    __atomic_store_n(&flow->state, FLOW_STATE_INITIALIZING, __ATOMIC_RELEASE);

    // Initialize fields
    flow->key = key;
    flow->entry_index = (uint32_t)entry_index;
    flow->first_seen_tsc = now_tsc;
    flow->last_seen_tsc = now_tsc;
    flow->window_start_tsc = now_tsc;
    flow->window_packets = 0;
    flow->window_bytes = 0;
    flow->pps_limit = config_v6.default_pps_limit;
    flow->bps_limit = config_v6.default_bps_limit;
    flow->tcp_flags_lo_to_hi = 0;
    flow->tcp_flags_hi_to_lo = 0;
    flow->flags = FLOW_FLAG_INITIATOR_KNOWN;
    flow->initiator_dir = features->flow_direction;
    flow->packets_lo_to_hi = 0;
    flow->bytes_lo_to_hi = 0;
    flow->packets_hi_to_lo = 0;
    flow->bytes_hi_to_lo = 0;
    rte_memcpy(flow->initiator_ip, features->src_ip.v6, 16);
    flow->initiator_port = features->src_port;
    flow->responder_port = features->dst_port;
    flow->ipv6_flow_label = features->ipv6_flow_label;
    flow->ext_hdr_len = features->ext_hdr_len;

    __atomic_thread_fence(__ATOMIC_SEQ_CST);

    // Add to hash table
    ret = rte_hash_add_key_with_hash_data(flow_hash_v6, &key, hash, flow);
    if (unlikely(ret < 0)) {
        __atomic_store_n(&flow->state, FLOW_STATE_NEW, __ATOMIC_RELEASE);
        memset(flow->key.ip_lo, 0, 16);
        memset(flow->key.ip_hi, 0, 16);
        flow_entry_v6_free((uint32_t)entry_index);

        // Check if another thread added it
        ret = rte_hash_lookup_with_hash_data(flow_hash_v6, &key, hash, (void **)&flow);
        if (ret >= 0 && flow != NULL) {
            uint8_t other_state;
            int spin_count = 0;
            do {
                other_state = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
                if (++spin_count > 1000) {
                    rte_pause();
                    spin_count = 0;
                }
            } while (other_state == FLOW_STATE_INITIALIZING);
            return flow;
        }

        lstats->create_failures++;
        return NULL;
    }

    // Transition to valid state
    __atomic_store_n(&flow->state, FLOW_STATE_NEW, __ATOMIC_RELEASE);

    lstats->creates++;
    *created = true;

    return flow;
}

struct flow_entry_v6* flow_table_v6_lookup_or_create(
    struct packet_features_v6 *features,
    bool *created)
{
    return flow_table_v6_lookup_or_create_internal(features, created, 0);
}

struct flow_entry_v6* flow_table_v6_lookup_or_create_tsc(
    struct packet_features_v6 *features,
    bool *created,
    uint64_t now_tsc)
{
    return flow_table_v6_lookup_or_create_internal(features, created, now_tsc);
}

// ==================== Flow Update ====================

void flow_table_v6_update(struct flow_entry_v6 *flow,
                          const struct packet_features_v6 *features)
{
    if (unlikely(!flow || !features)) {
        return;
    }

    struct flow_table_v6_stats *lstats = get_flow_v6_lcore_stats();
    lstats->updates++;

    uint64_t now_tsc = features->timestamp_tsc ? features->timestamp_tsc : rte_rdtsc();
    __atomic_store_n(&flow->last_seen_tsc, now_tsc, __ATOMIC_RELEASE);

    // Update direction-specific counters
    if (features->flow_direction == FLOW_DIR_LO_TO_HI) {
        __atomic_add_fetch(&flow->packets_lo_to_hi, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&flow->bytes_lo_to_hi, features->packet_size, __ATOMIC_RELAXED);
        if (features->protocol == IPPROTO_TCP) {
            __atomic_fetch_or(&flow->tcp_flags_lo_to_hi, features->tcp_flags, __ATOMIC_RELAXED);
        }
    } else {
        __atomic_add_fetch(&flow->packets_hi_to_lo, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&flow->bytes_hi_to_lo, features->packet_size, __ATOMIC_RELAXED);
        if (features->protocol == IPPROTO_TCP) {
            __atomic_fetch_or(&flow->tcp_flags_hi_to_lo, features->tcp_flags, __ATOMIC_RELAXED);
        }
    }

    // TCP state machine (same as IPv4)
    if (features->protocol == IPPROTO_TCP) {
        uint8_t flags = features->tcp_flags;
        bool is_initiator = (features->flow_direction == flow->initiator_dir);
        uint8_t current_state = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);

        // Track sequence numbers
        if (features->flow_direction == FLOW_DIR_LO_TO_HI) {
            uint32_t payload_len = features->payload_len;
            if (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) {
                payload_len += 1;
            }
            uint32_t next_seq = features->tcp_seq + payload_len;
            __atomic_store_n(&flow->seq_lo_to_hi, next_seq, __ATOMIC_RELAXED);
            __atomic_store_n(&flow->ack_lo_to_hi, features->tcp_ack, __ATOMIC_RELAXED);
            if (payload_len > 0 || (flags & (TCP_FLAG_SYN | TCP_FLAG_ACK))) {
                __atomic_fetch_or(&flow->flags, FLOW_FLAG_SEQ_TRACKING_ENABLED, __ATOMIC_RELAXED);
            }
        } else {
            uint32_t payload_len = features->payload_len;
            if (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) {
                payload_len += 1;
            }
            uint32_t next_seq = features->tcp_seq + payload_len;
            __atomic_store_n(&flow->seq_hi_to_lo, next_seq, __ATOMIC_RELAXED);
            __atomic_store_n(&flow->ack_hi_to_lo, features->tcp_ack, __ATOMIC_RELAXED);
            if (payload_len > 0 || (flags & (TCP_FLAG_SYN | TCP_FLAG_ACK))) {
                __atomic_fetch_or(&flow->flags, FLOW_FLAG_SEQ_TRACKING_ENABLED, __ATOMIC_RELAXED);
            }
        }

        // RST always transitions to RST state
        if (flags & TCP_FLAG_RST) {
            __atomic_store_n(&flow->state, FLOW_STATE_RST, __ATOMIC_RELEASE);
            return;
        }

        // State transitions (same as IPv4)
        switch (current_state) {
            case FLOW_STATE_NEW:
                if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK)) {
                    if (is_initiator) {
                        __atomic_store_n(&flow->state, FLOW_STATE_SYN_RECEIVED, __ATOMIC_RELEASE);
                    }
                }
                break;

            case FLOW_STATE_SYN_RECEIVED:
                if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_ACK)) {
                    if (!is_initiator) {
                        __atomic_store_n(&flow->state, FLOW_STATE_SYN_ACK_RECEIVED, __ATOMIC_RELEASE);
                    }
                }
                if ((flags & TCP_FLAG_ACK) && !(flags & TCP_FLAG_SYN)) {
                    if (is_initiator) {
                        __atomic_store_n(&flow->state, FLOW_STATE_ESTABLISHED, __ATOMIC_RELEASE);
                        __atomic_fetch_or(&flow->flags, FLOW_FLAG_ESTABLISHED, __ATOMIC_RELAXED);
                    }
                }
                break;

            case FLOW_STATE_SYN_ACK_RECEIVED:
                if ((flags & TCP_FLAG_ACK) && !(flags & TCP_FLAG_SYN)) {
                    if (is_initiator) {
                        __atomic_store_n(&flow->state, FLOW_STATE_ESTABLISHED, __ATOMIC_RELEASE);
                        __atomic_fetch_or(&flow->flags, FLOW_FLAG_ESTABLISHED, __ATOMIC_RELAXED);
                    }
                }
                break;

            case FLOW_STATE_ESTABLISHED:
                if (flags & TCP_FLAG_FIN) {
                    if (is_initiator) {
                        __atomic_store_n(&flow->state, FLOW_STATE_FIN_WAIT_1, __ATOMIC_RELEASE);
                    } else {
                        __atomic_store_n(&flow->state, FLOW_STATE_CLOSE_WAIT, __ATOMIC_RELEASE);
                    }
                }
                break;

            case FLOW_STATE_FIN_WAIT_1:
                if (flags & TCP_FLAG_FIN) {
                    if (!is_initiator) {
                        __atomic_store_n(&flow->state, FLOW_STATE_CLOSING, __ATOMIC_RELEASE);
                    }
                } else if (flags & TCP_FLAG_ACK) {
                    if (!is_initiator) {
                        __atomic_store_n(&flow->state, FLOW_STATE_FIN_WAIT_2, __ATOMIC_RELEASE);
                    }
                }
                break;

            case FLOW_STATE_FIN_WAIT_2:
                if (flags & TCP_FLAG_FIN) {
                    if (!is_initiator) {
                        __atomic_store_n(&flow->state, FLOW_STATE_TIME_WAIT, __ATOMIC_RELEASE);
                    }
                }
                break;

            case FLOW_STATE_CLOSE_WAIT:
                if (flags & TCP_FLAG_FIN) {
                    if (is_initiator) {
                        __atomic_store_n(&flow->state, FLOW_STATE_LAST_ACK, __ATOMIC_RELEASE);
                    }
                }
                break;

            case FLOW_STATE_CLOSING:
                if (flags & TCP_FLAG_ACK) {
                    __atomic_store_n(&flow->state, FLOW_STATE_TIME_WAIT, __ATOMIC_RELEASE);
                }
                break;

            case FLOW_STATE_LAST_ACK:
                if (flags & TCP_FLAG_ACK) {
                    __atomic_store_n(&flow->state, FLOW_STATE_CLOSED, __ATOMIC_RELEASE);
                }
                break;

            default:
                break;
        }
    }
}

// ==================== Rate Limiting ====================

enum rate_limit_action flow_table_v6_check_rate_limit(
    struct flow_entry_v6 *flow,
    const struct packet_features_v6 *features)
{
    if (unlikely(!flow || !features)) {
        return RL_ACCEPT;
    }

    // Only rate limit initiator direction
    if (features->flow_direction != flow->initiator_dir) {
        return RL_ACCEPT;
    }

    uint64_t now_tsc = features->timestamp_tsc ? features->timestamp_tsc : rte_rdtsc();
    uint64_t window_start = __atomic_load_n(&flow->window_start_tsc, __ATOMIC_ACQUIRE);
    uint64_t window_elapsed = now_tsc - window_start;

    // Reset window after 1 second
    if (window_elapsed >= tsc_hz_v6) {
        __atomic_store_n(&flow->window_start_tsc, now_tsc, __ATOMIC_RELEASE);
        __atomic_store_n(&flow->window_packets, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&flow->window_bytes, 0, __ATOMIC_RELAXED);
    }

    uint32_t pps_limit = __atomic_load_n(&flow->pps_limit, __ATOMIC_RELAXED);
    uint32_t bps_limit = __atomic_load_n(&flow->bps_limit, __ATOMIC_RELAXED);

    // Check PPS limit
    if (pps_limit > 0) {
        uint32_t current_packets = __atomic_load_n(&flow->window_packets, __ATOMIC_RELAXED);
        if (current_packets >= pps_limit) {
            __atomic_fetch_or(&flow->flags, FLOW_FLAG_RATE_LIMITED, __ATOMIC_RELAXED);
            get_flow_v6_lcore_stats()->rate_limit_drops++;
            return RL_DROP_PPS;
        }
    }

    // Check BPS limit
    if (bps_limit > 0) {
        uint32_t current_bytes = __atomic_load_n(&flow->window_bytes, __ATOMIC_RELAXED);
        if (current_bytes + features->packet_size > bps_limit) {
            __atomic_fetch_or(&flow->flags, FLOW_FLAG_RATE_LIMITED, __ATOMIC_RELAXED);
            get_flow_v6_lcore_stats()->rate_limit_drops++;
            return RL_DROP_BPS;
        }
    }

    // Update counters
    __atomic_add_fetch(&flow->window_packets, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&flow->window_bytes, features->packet_size, __ATOMIC_RELAXED);

    return RL_ACCEPT;
}

// ==================== Flow Aging ====================

static uint32_t aging_iterator_v6 = 0;

uint32_t flow_table_v6_age_flows(void)
{
    struct flow_key_v6 keys[AGING_BATCH_SIZE];
    uint32_t indices[AGING_BATCH_SIZE];
    uint32_t batch_count = 0;
    uint32_t total_aged = 0;
    uint64_t now_tsc = rte_rdtsc();
    uint64_t timeout_tsc = seconds_to_tsc_v6(config_v6.idle_timeout_sec);
    uint64_t syn_timeout_tsc = seconds_to_tsc_v6(config_v6.syn_timeout_sec);
    uint32_t iter = aging_iterator_v6;
    uint32_t scanned = 0;
    const struct flow_key_v6 *key_ptr;
    void *data;
    int32_t pos;

    if (unlikely(!initialized_v6)) {
        return 0;
    }

    // Adaptive timeout based on occupancy
    uint32_t active_count = config_v6.max_flows - rte_ring_count(free_index_ring_v6);
    float occupancy = (float)active_count / config_v6.max_flows;

    if (occupancy > 0.95f) {
        timeout_tsc /= 4;
        syn_timeout_tsc /= 4;
    } else if (occupancy > 0.90f) {
        timeout_tsc /= 2;
        syn_timeout_tsc /= 2;
    }

    uint32_t scan_limit = config_v6.aging_scan_limit > 0 ? config_v6.aging_scan_limit : 4096;
    if (occupancy > 0.90f) {
        scan_limit *= 2;
    }

    while ((pos = rte_hash_iterate(flow_hash_v6, (const void **)&key_ptr, &data, &iter)) >= 0) {
        scanned++;
        struct flow_entry_v6 *flow = (struct flow_entry_v6 *)data;

        if (unlikely(flow == NULL)) {
            continue;
        }
        if (unlikely(flow < flow_entries_v6 || flow >= &flow_entries_v6[config_v6.max_flows])) {
            continue;
        }

        uint64_t last_seen = __atomic_load_n(&flow->last_seen_tsc, __ATOMIC_ACQUIRE);
        uint64_t idle_time = now_tsc - last_seen;
        uint64_t flow_timeout = timeout_tsc;

        // State-based timeouts for TCP
        if (flow->key.protocol == IPPROTO_TCP) {
            uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_RELAXED);

            switch (state) {
                case FLOW_STATE_NEW:
                case FLOW_STATE_SYN_RECEIVED:
                case FLOW_STATE_SYN_ACK_RECEIVED:
                    if (config_v6.enable_syn_protection) {
                        flow_timeout = syn_timeout_tsc;
                    }
                    break;

                case FLOW_STATE_TIME_WAIT:
                    flow_timeout = syn_timeout_tsc * 6;
                    break;

                case FLOW_STATE_FIN_WAIT_1:
                case FLOW_STATE_FIN_WAIT_2:
                case FLOW_STATE_CLOSE_WAIT:
                case FLOW_STATE_CLOSING:
                case FLOW_STATE_LAST_ACK:
                    flow_timeout = syn_timeout_tsc * 4;
                    break;

                case FLOW_STATE_CLOSED:
                case FLOW_STATE_RST:
                    flow_timeout = 0;
                    break;

                default:
                    break;
            }
        }

        if (idle_time > flow_timeout) {
            rte_memcpy(&keys[batch_count], key_ptr, sizeof(struct flow_key_v6));
            indices[batch_count] = flow->entry_index;
            batch_count++;

            if (batch_count >= AGING_BATCH_SIZE) {
                break;
            }
        }

        if (scanned >= scan_limit) {
            break;
        }
    }

    // Save iterator
    if (pos < 0) {
        aging_iterator_v6 = 0;
    } else {
        aging_iterator_v6 = iter;
    }

    // Delete collected flows
    for (uint32_t i = 0; i < batch_count; i++) {
        int32_t del_pos = rte_hash_del_key(flow_hash_v6, &keys[i]);

        if (del_pos >= 0) {
            uint32_t entry_idx = indices[i];

            if (likely(entry_idx < config_v6.max_flows)) {
                memset(&flow_entries_v6[entry_idx], 0, sizeof(struct flow_entry_v6));
                flow_entry_v6_free(entry_idx);
            }
            total_aged++;
        }
    }

    if (total_aged > 0) {
        global_deletes_v6 += total_aged;

        if (total_aged >= AGING_BATCH_SIZE) {
            RTE_LOG(DEBUG, FLOW_V6, "Aged %u IPv6 flows (batch limit)\n", total_aged);
        } else {
            RTE_LOG(DEBUG, FLOW_V6, "Aged %u IPv6 flows\n", total_aged);
        }
    }

    return total_aged;
}

// ==================== Statistics ====================

void flow_table_v6_get_stats(struct flow_table_v6_stats *stats)
{
    if (!stats) {
        return;
    }

    memset(stats, 0, sizeof(*stats));

    unsigned int lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        struct flow_table_v6_stats *lstats = &lcore_stats_v6[lcore_id];
        stats->lookups += lstats->lookups;
        stats->lookup_hits += lstats->lookup_hits;
        stats->creates += lstats->creates;
        stats->create_failures += lstats->create_failures;
        stats->updates += lstats->updates;
        stats->rate_limit_drops += lstats->rate_limit_drops;
    }

    stats->deletes = global_deletes_v6;
}

uint32_t flow_table_v6_get_occupancy_percent(void)
{
    if (!initialized_v6 || config_v6.max_flows == 0) return 0;

    uint32_t active = rte_hash_count(flow_hash_v6);
    return (active * 100) / config_v6.max_flows;
}

void flow_table_v6_clear(void)
{
    struct flow_key_v6 keys[256];
    uint32_t indices[256];
    uint32_t batch_count;
    uint32_t iter;
    const struct flow_key_v6 *key_ptr;
    void *data;

    if (!initialized_v6) {
        return;
    }

    do {
        batch_count = 0;
        iter = 0;

        while (rte_hash_iterate(flow_hash_v6, (const void **)&key_ptr, &data, &iter) >= 0) {
            struct flow_entry_v6 *flow = (struct flow_entry_v6 *)data;

            rte_memcpy(&keys[batch_count], key_ptr, sizeof(struct flow_key_v6));
            indices[batch_count] = (flow != NULL) ? flow->entry_index : UINT32_MAX;
            batch_count++;

            if (batch_count >= 256) {
                break;
            }
        }

        for (uint32_t i = 0; i < batch_count; i++) {
            rte_hash_del_key(flow_hash_v6, &keys[i]);
            if (indices[i] < config_v6.max_flows) {
                memset(&flow_entries_v6[indices[i]], 0, sizeof(struct flow_entry_v6));
                flow_entry_v6_free(indices[i]);
            }
        }
    } while (batch_count > 0);

    memset(lcore_stats_v6, 0, sizeof(lcore_stats_v6));
    global_deletes_v6 = 0;

    RTE_LOG(INFO, FLOW_V6, "IPv6 flow table cleared\n");
}

// ==================== RST/FIN Validation ====================

#define RST_FIN_SEQ_WINDOW_V6  (1 << 20)

static inline bool seq_in_window_v6(uint32_t seq, uint32_t expected, uint32_t window) {
    int32_t diff = (int32_t)(seq - expected);
    return (diff >= -(int32_t)window && diff <= (int32_t)window);
}

enum rst_fin_validation_result flow_table_v6_validate_rst_fin(
    struct packet_features_v6 *features)
{
    if (unlikely(!initialized_v6 || !features)) {
        return RST_FIN_NO_FLOW;
    }

    if (features->protocol != IPPROTO_TCP) {
        return RST_FIN_VALID;
    }

    uint8_t flags = features->tcp_flags;
    if (!(flags & (TCP_FLAG_RST | TCP_FLAG_FIN))) {
        return RST_FIN_VALID;
    }

    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= MAX_LCORES) lcore_id = 0;
    struct rst_fin_lcore_stats_v6 *rstats = &rst_fin_stats_v6[lcore_id];

    struct flow_entry_v6 *flow = flow_table_v6_lookup(features);
    if (!flow) {
        rstats->invalid_no_flow++;
        return RST_FIN_NO_FLOW;
    }

    uint8_t flow_flags = __atomic_load_n(&flow->flags, __ATOMIC_RELAXED);

    if (!(flow_flags & FLOW_FLAG_SEQ_TRACKING_ENABLED)) {
        rstats->valid_count++;
        return RST_FIN_VALID;
    }

    uint32_t expected_seq;
    uint32_t last_ack;

    if (features->flow_direction == FLOW_DIR_LO_TO_HI) {
        expected_seq = __atomic_load_n(&flow->seq_lo_to_hi, __ATOMIC_RELAXED);
        last_ack = __atomic_load_n(&flow->ack_hi_to_lo, __ATOMIC_RELAXED);
    } else {
        expected_seq = __atomic_load_n(&flow->seq_hi_to_lo, __ATOMIC_RELAXED);
        last_ack = __atomic_load_n(&flow->ack_lo_to_hi, __ATOMIC_RELAXED);
    }

    if (flags & TCP_FLAG_RST) {
        bool seq_ok = seq_in_window_v6(features->tcp_seq, expected_seq, RST_FIN_SEQ_WINDOW_V6);
        bool ack_ok = seq_in_window_v6(features->tcp_seq, last_ack, RST_FIN_SEQ_WINDOW_V6);

        if (!seq_ok && !ack_ok) {
            rstats->invalid_seq++;
            return RST_FIN_SEQ_OUT_OF_WINDOW;
        }
    }

    if (flags & TCP_FLAG_FIN) {
        if (!seq_in_window_v6(features->tcp_seq, expected_seq, RST_FIN_SEQ_WINDOW_V6)) {
            rstats->invalid_seq++;
            return RST_FIN_SEQ_OUT_OF_WINDOW;
        }

        uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_RELAXED);
        switch (state) {
            case FLOW_STATE_ESTABLISHED:
            case FLOW_STATE_FIN_WAIT_1:
            case FLOW_STATE_FIN_WAIT_2:
            case FLOW_STATE_CLOSE_WAIT:
            case FLOW_STATE_CLOSING:
                break;

            case FLOW_STATE_NEW:
            case FLOW_STATE_SYN_RECEIVED:
            case FLOW_STATE_SYN_ACK_RECEIVED:
                rstats->invalid_state++;
                return RST_FIN_UNEXPECTED_STATE;

            default:
                break;
        }
    }

    rstats->valid_count++;
    return RST_FIN_VALID;
}
