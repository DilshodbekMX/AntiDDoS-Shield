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
#include <string.h>
#include <netinet/in.h>

#define RTE_LOGTYPE_FLOWTBL RTE_LOGTYPE_USER4

// ==================== Constants ====================

#define AGING_BATCH_SIZE      512      // Flows to age per iteration
#define FREE_RING_NAME_FMT    "flow_free_%u_%lu"
#define HASH_NAME_FMT         "flow_hash_%u_%lu"
#define MAX_LCORES            RTE_MAX_LCORE

// ==================== Global State ====================

static struct rte_hash *flow_hash = NULL;
static struct flow_entry *flow_entries = NULL;
static struct rte_ring *free_index_ring = NULL;
static struct flow_table_config config;
static uint64_t tsc_hz = 0;
static bool initialized = false;

// Per-lcore statistics - NO ATOMICS in fast path
static struct flow_table_lcore_stats lcore_stats[MAX_LCORES] __rte_cache_aligned;

// Per-lcore RST/FIN validation stats
struct rst_fin_lcore_stats {
    uint64_t valid_count;
    uint64_t invalid_seq;
    uint64_t invalid_no_flow;
    uint64_t invalid_state;
    uint64_t _pad[4];
} __rte_cache_aligned;
static struct rst_fin_lcore_stats rst_fin_stats[MAX_LCORES] __rte_cache_aligned;

// Global stats for aging (single-threaded operation)
static uint64_t global_deletes = 0;

// ==================== Helper Functions ====================

static inline uint64_t seconds_to_tsc(uint32_t seconds) {
    return (uint64_t)seconds * tsc_hz;
}

// ==================== Index Allocation (Per-Lcore + Global Ring) ====================

/**
 * OPTIMIZED: Per-lcore free lists to reduce contention.
 * Each lcore maintains a local cache of free indices.
 * When local cache is empty, refill from global ring (batch).
 * When local cache is full, return to global ring (batch).
 */
#define LOCAL_FREE_CACHE_SIZE  64   // Per-lcore cache size
#define LOCAL_REFILL_BATCH     32   // How many to grab at once

struct lcore_free_cache {
    uint32_t indices[LOCAL_FREE_CACHE_SIZE];
    uint32_t count;
    uint32_t _pad[14];  // Pad to cache line
} __rte_cache_aligned;

static struct lcore_free_cache lcore_free_caches[MAX_LCORES];

/**
 * Allocate a flow entry index from per-lcore cache (fast path)
 * or global ring (slow path).
 *
 * @return Index into flow_entries, or -1 if none available
 */
static inline int32_t flow_entry_alloc(void) {
    unsigned int lcore_id = rte_lcore_id();
    if (unlikely(lcore_id >= MAX_LCORES)) {
        lcore_id = 0;
    }

    struct lcore_free_cache *cache = &lcore_free_caches[lcore_id];

    // Fast path: get from local cache
    if (likely(cache->count > 0)) {
        return (int32_t)cache->indices[--cache->count];
    }

    // Calculate how many we can actually store in local cache
    // to prevent buffer overflow if cache->count is unexpectedly high
    uint32_t available_space = LOCAL_FREE_CACHE_SIZE - cache->count;
    uint32_t refill_count = (available_space > LOCAL_REFILL_BATCH) ? LOCAL_REFILL_BATCH : available_space;

    // Slow path: refill from global ring
    void *idx_ptrs[LOCAL_REFILL_BATCH];
    unsigned int got = rte_ring_mc_dequeue_burst(free_index_ring, idx_ptrs,
                                                  refill_count, NULL);
    if (unlikely(got == 0)) {
        return -1;  // Ring empty
    }

    // Store all but one in local cache with bounds checking
    // Ensure we never exceed LOCAL_FREE_CACHE_SIZE
    for (unsigned int i = 1; i < got && cache->count < LOCAL_FREE_CACHE_SIZE; i++) {
        cache->indices[cache->count++] = (uint32_t)(uintptr_t)idx_ptrs[i];
    }

    // Return the first one
    return (int32_t)(uintptr_t)idx_ptrs[0];
}

/**
 * Allocate multiple flow entry indices (batch operation).
 * More efficient when creating many flows.
 *
 * @param indices  Output array for indices
 * @param count    Number of indices requested
 * @return Actual number of indices allocated
 */
static inline uint32_t flow_entry_alloc_bulk(int32_t *indices, uint32_t count) {
    unsigned int lcore_id = rte_lcore_id();
    if (unlikely(lcore_id >= MAX_LCORES)) {
        lcore_id = 0;
    }

    struct lcore_free_cache *cache = &lcore_free_caches[lcore_id];
    uint32_t allocated = 0;

    // First, drain local cache
    while (cache->count > 0 && allocated < count) {
        indices[allocated++] = (int32_t)cache->indices[--cache->count];
    }

    // If we need more, get from global ring
    if (allocated < count) {
        void *idx_ptrs[256];
        uint32_t need = count - allocated;
        if (need > 256) need = 256;

        unsigned int got = rte_ring_mc_dequeue_burst(free_index_ring, idx_ptrs, need, NULL);
        for (unsigned int i = 0; i < got; i++) {
            indices[allocated++] = (int32_t)(uintptr_t)idx_ptrs[i];
        }
    }

    return allocated;
}

/**
 * Return a flow entry index to global ring.
 * Called primarily by aging thread.
 *
 * @param index  Index to return
 */
static inline void flow_entry_free(uint32_t index) {
    // Aging runs on single thread, use MP enqueue for safety from multiple aging calls
    rte_ring_mp_enqueue(free_index_ring, (void *)(uintptr_t)index);
}

/**
 * Return multiple flow entry indices (batch operation).
 * Called primarily by aging thread.
 *
 * @param indices  Array of indices to return
 * @param count    Number of indices
 */
static inline void flow_entry_free_bulk(uint32_t *indices, uint32_t count) {
    rte_ring_mp_enqueue_burst(free_index_ring, (void **)indices, count, NULL);
}

// ==================== Initialization ====================

int flow_table_init(const struct flow_table_config *cfg) {
    struct rte_hash_parameters hash_params = {0};
    char name[RTE_RING_NAMESIZE];
    uint32_t i;
    int socket_id;

    if (!cfg || cfg->max_flows == 0) {
        RTE_LOG(ERR, FLOWTBL, "Invalid config\n");
        return -1;
    }

    if (initialized) {
        RTE_LOG(WARNING, FLOWTBL, "Flow table already initialized\n");
        return 0;
    }

    memcpy(&config, cfg, sizeof(config));
    // Clear per-lcore stats
    memset(lcore_stats, 0, sizeof(lcore_stats));
    memset(rst_fin_stats, 0, sizeof(rst_fin_stats));  // RST/FIN validation stats
    global_deletes = 0;
    tsc_hz = rte_get_tsc_hz();

    // Use SOCKET_ID_ANY for shared data structures accessed by all lcores
    // rte_socket_id() returns the init thread's NUMA node which may not be where workers run
    // Using SOCKET_ID_ANY lets DPDK choose the best location (usually node 0)
    socket_id = SOCKET_ID_ANY;

    RTE_LOG(INFO, FLOWTBL, "Initializing flow table:\n");
    RTE_LOG(INFO, FLOWTBL, "  Max flows: %u\n", config.max_flows);
    RTE_LOG(INFO, FLOWTBL, "  Idle timeout: %u sec\n", config.idle_timeout_sec);
    RTE_LOG(INFO, FLOWTBL, "  SYN timeout: %u sec\n", config.syn_timeout_sec);
    RTE_LOG(INFO, FLOWTBL, "  Entry size: %zu bytes\n", sizeof(struct flow_entry));

    // ========== 1. Allocate flow entries array ==========
    flow_entries = rte_zmalloc_socket("flow_entries",
                                       config.max_flows * sizeof(struct flow_entry),
                                       RTE_CACHE_LINE_SIZE,
                                       socket_id);
    if (!flow_entries) {
        RTE_LOG(ERR, FLOWTBL, "Failed to allocate flow entries (%zu MB)\n",
                (config.max_flows * sizeof(struct flow_entry)) / (1024 * 1024));
        return -1;
    }

    // ========== 2. Create free index ring (lock-free allocation) ==========
    // Ring size must be power of 2, and we need max_flows entries
    uint32_t ring_size = rte_align32pow2(config.max_flows + 1);

    snprintf(name, sizeof(name), FREE_RING_NAME_FMT,
             rte_lcore_id(), (unsigned long)rte_get_tsc_cycles());

    // OPTIMIZED: Multi-consumer/multi-producer ring for per-lcore caching
    // Per-lcore caches batch dequeue/enqueue to reduce contention
    free_index_ring = rte_ring_create(name, ring_size, socket_id, 0);  // MP/MC mode
    if (!free_index_ring) {
        RTE_LOG(ERR, FLOWTBL, "Failed to create free index ring (size %u)\n", ring_size);
        rte_free(flow_entries);
        flow_entries = NULL;
        return -1;
    }

    // Pre-populate ring with all available indices
    for (i = 0; i < config.max_flows; i++) {
        rte_ring_mp_enqueue(free_index_ring, (void *)(uintptr_t)i);
    }

    // Initialize per-lcore free caches
    memset(lcore_free_caches, 0, sizeof(lcore_free_caches));

    RTE_LOG(INFO, FLOWTBL, "  Free ring size: %u (populated: %u)\n", 
            ring_size, rte_ring_count(free_index_ring));

    // ========== 3. Create hash table ==========
    snprintf(name, sizeof(name), HASH_NAME_FMT,
             rte_lcore_id(), (unsigned long)rte_get_tsc_cycles());
    
    hash_params.name = name;
    hash_params.entries = config.max_flows;
    hash_params.key_len = sizeof(struct flow_key);
    hash_params.hash_func = rte_jhash;
    hash_params.hash_func_init_val = 0;
    hash_params.socket_id = socket_id;
    // Thread-safe concurrent read/write access
    hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                             RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT;

    flow_hash = rte_hash_create(&hash_params);
    if (!flow_hash) {
        RTE_LOG(ERR, FLOWTBL, "Failed to create hash table\n");
        rte_ring_free(free_index_ring);
        free_index_ring = NULL;
        rte_free(flow_entries);
        flow_entries = NULL;
        return -1;
    }

    initialized = true;
    RTE_LOG(INFO, FLOWTBL, "Flow table initialized (lock-free, thread-safe)\n");
    return 0;
}

void flow_table_cleanup(void) {
    if (!initialized) {
        return;
    }

    if (flow_hash) {
        rte_hash_free(flow_hash);
        flow_hash = NULL;
    }
    if (free_index_ring) {
        rte_ring_free(free_index_ring);
        free_index_ring = NULL;
    }
    if (flow_entries) {
        rte_free(flow_entries);
        flow_entries = NULL;
    }

    initialized = false;
    RTE_LOG(INFO, FLOWTBL, "Flow table cleanup complete\n");
}

// ==================== Per-Lcore Stats Helper ====================

static inline struct flow_table_lcore_stats* get_flow_lcore_stats(void) {
    return &lcore_stats[rte_lcore_id()];
}

// ==================== Flow Lookup Operations ====================

struct flow_entry* flow_table_lookup(struct packet_features *features) {
    struct flow_key key;
    struct flow_entry *flow = NULL;
    int ret;

    if (unlikely(!initialized || !features)) {
        return NULL;
    }

    // Extract canonical key (sets features->flow_direction)
    extract_flow_key(features, &key);

    // Per-lcore stats - NO ATOMICS
    struct flow_table_lcore_stats *lstats = get_flow_lcore_stats();
    lstats->lookups++;

    ret = rte_hash_lookup_data(flow_hash, &key, (void **)&flow);
    if (ret >= 0 && flow != NULL) {
        lstats->lookup_hits++;
        // Prefetch flow entry for subsequent access
        rte_prefetch0(flow);
        return flow;
    }

    return NULL;
}

struct flow_entry* flow_table_lookup_with_hash(const struct flow_key *key,
                                                uint32_t hash) {
    struct flow_entry *flow = NULL;

    if (unlikely(!initialized || !key)) {
        return NULL;
    }

    // Per-lcore stats - NO ATOMICS
    struct flow_table_lcore_stats *lstats = get_flow_lcore_stats();
    lstats->lookups++;

    // Use precomputed hash to avoid rehashing
    int ret = rte_hash_lookup_with_hash_data(flow_hash, key, hash, (void **)&flow);
    if (ret >= 0 && flow != NULL) {
        lstats->lookup_hits++;
        // Prefetch flow entry for subsequent access
        rte_prefetch0(flow);
        return flow;
    }

    return NULL;
}

/**
 * OPTIMIZED: Internal implementation with precomputed hash and optional TSC
 */
static inline struct flow_entry* flow_table_lookup_or_create_internal(
        struct packet_features *features,
        bool *created,
        uint64_t now_tsc) {
    struct flow_key key;
    struct flow_entry *flow = NULL;
    int32_t entry_index;
    int ret;
    hash_sig_t hash;

    if (unlikely(!initialized || !features)) {
        return NULL;
    }

    *created = false;

    // Extract canonical key (sets features->flow_direction)
    extract_flow_key(features, &key);

    // Per-lcore stats - NO ATOMICS in fast path
    struct flow_table_lcore_stats *lstats = get_flow_lcore_stats();
    lstats->lookups++;

    // Compute hash ONCE - reuse for both lookup and add
    hash = rte_hash_hash(flow_hash, &key);

    // Fast path: check if flow exists using precomputed hash
    ret = rte_hash_lookup_with_hash_data(flow_hash, &key, hash, (void **)&flow);
    if (ret >= 0 && flow != NULL) {
        lstats->lookup_hits++;
        // Prefetch flow entry for subsequent access
        rte_prefetch0(flow);
        return flow;
    }

    // Slow path: need to create new flow

    // Allocate index from free ring (lock-free)
    entry_index = flow_entry_alloc();
    if (unlikely(entry_index < 0)) {
        // Try emergency eviction before giving up
        // This prevents dropping legitimate connections during attacks
        static uint64_t evict_attempts = 0;
        static uint64_t last_evict_tsc = 0;
        uint64_t evict_now = rte_rdtsc();

        // Rate-limit eviction attempts (max once per 100ms)
        uint64_t min_interval = rte_get_tsc_hz() / 10;  // 100ms
        if (evict_now - last_evict_tsc > min_interval) {
            last_evict_tsc = evict_now;
            evict_attempts++;

            // Try to evict some low-priority flows
            uint32_t evicted = flow_table_emergency_evict(256);

            if (evicted > 0) {
                // Retry allocation
                entry_index = flow_entry_alloc();
            }
        }

        if (unlikely(entry_index < 0)) {
            lstats->create_failures++;

            static uint64_t log_count = 0;
            if (unlikely(__atomic_fetch_add(&log_count, 1, __ATOMIC_RELAXED) < 10)) {
                RTE_LOG(WARNING, FLOWTBL, "Flow table full after eviction attempt "
                        "(max %u, evict_attempts=%lu)\n",
                        config.max_flows, (unsigned long)evict_attempts);
            }
            return NULL;
        }
    }

    // Initialize flow entry BEFORE adding to hash
    flow = &flow_entries[entry_index];

    // Use provided TSC or read now (only if not provided)
    if (now_tsc == 0) {
        now_tsc = rte_rdtsc();
    }

    // Zero entire struct before selective initialization to prevent
    // information leakage through uninitialized padding bytes (_pad1, _pad2, _reserved)
    // This is safe because we hold the entry exclusively during initialization
    memset(flow, 0, sizeof(*flow));

    // Two-phase initialization to prevent race condition
    // Phase 1: Mark entry as being initialized (prevents use-after-free of stale data)
    // Use atomic store to set a sentinel state before initialization
    __atomic_store_n(&flow->state, FLOW_STATE_INITIALIZING, __ATOMIC_RELEASE);

    // Phase 2: Initialize all fields while entry is marked as initializing
    // Any concurrent reader seeing FLOW_STATE_INITIALIZING will retry or skip
    flow->key = key;
    flow->entry_index = (uint32_t)entry_index;
    flow->first_seen_tsc = now_tsc;
    flow->last_seen_tsc = now_tsc;
    flow->window_start_tsc = now_tsc;
    flow->window_packets = 0;
    flow->window_bytes = 0;
    flow->pps_limit = config.default_pps_limit;
    flow->bps_limit = config.default_bps_limit;
    flow->tcp_flags_lo_to_hi = 0;
    flow->tcp_flags_hi_to_lo = 0;
    flow->flags = FLOW_FLAG_INITIATOR_KNOWN;
    flow->initiator_dir = features->flow_direction;
    flow->packets_lo_to_hi = 0;
    flow->bytes_lo_to_hi = 0;
    flow->packets_hi_to_lo = 0;
    flow->bytes_hi_to_lo = 0;
    flow->initiator_ip = features->src_ip;
    flow->initiator_port = features->src_port;
    flow->responder_port = features->dst_port;
    flow->reputation_score = 0;
    flow->mss_value = 0;
    flow->window_scale = 0;

    // Full memory barrier to ensure all initialization is visible
    // before we add to hash table and transition to valid state
    __atomic_thread_fence(__ATOMIC_SEQ_CST);

    // Add to hash table using precomputed hash (thread-safe with RW_CONCURRENCY)
    ret = rte_hash_add_key_with_hash_data(flow_hash, &key, hash, flow);
    if (unlikely(ret < 0)) {
        // Failed to add - likely race condition or hash table issue
        // Clear sensitive fields before freeing
        __atomic_store_n(&flow->state, FLOW_STATE_NEW, __ATOMIC_RELEASE);
        flow->key.ip_lo = 0;
        flow->key.ip_hi = 0;
        flow_entry_free((uint32_t)entry_index);

        // Check if another thread added it
        ret = rte_hash_lookup_with_hash_data(flow_hash, &key, hash, (void **)&flow);
        if (ret >= 0 && flow != NULL) {
            // Wait for the other thread's initialization to complete
            uint8_t other_state;
            int spin_count = 0;
            do {
                other_state = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
                if (++spin_count > 1000) {
                    // Timeout waiting for initialization
                    rte_pause();
                    spin_count = 0;
                }
            } while (other_state == FLOW_STATE_INITIALIZING);
            return flow;
        }

        lstats->create_failures++;
        return NULL;
    }

    // Phase 3: Transition to valid state AFTER hash insertion
    // This ensures any thread that finds the entry via hash lookup
    // will see either FLOW_STATE_INITIALIZING (and wait) or a valid state
    __atomic_store_n(&flow->state, FLOW_STATE_NEW, __ATOMIC_RELEASE);

    lstats->creates++;
    *created = true;

    return flow;
}

struct flow_entry* flow_table_lookup_or_create(struct packet_features *features,
                                                bool *created) {
    return flow_table_lookup_or_create_internal(features, created, 0);
}

struct flow_entry* flow_table_lookup_or_create_tsc(struct packet_features *features,
                                                    bool *created,
                                                    uint64_t now_tsc) {
    return flow_table_lookup_or_create_internal(features, created, now_tsc);
}

// ==================== Flow Update ====================

/**
 * Internal flow update implementation with optional TSC parameter
 */
static inline void flow_table_update_internal(struct flow_entry *flow,
                                               const struct packet_features *features,
                                               uint64_t now_tsc) {
    if (unlikely(!flow || !features)) {
        return;
    }

    // Per-lcore stats - NO ATOMICS in fast path
    struct flow_table_lcore_stats *lstats = get_flow_lcore_stats();
    lstats->updates++;

    // Use provided TSC or get from features or read now
    if (now_tsc == 0) {
        now_tsc = features->timestamp_tsc ? features->timestamp_tsc : rte_rdtsc();
    }
    
    // Use RELEASE ordering for last_seen_tsc to ensure all prior
    // packet processing is visible before the timestamp update
    // This pairs with ACQUIRE in flow_table_age_flows() for correct aging
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

    // TCP state machine (RFC 793 compliant)
    if (features->protocol == IPPROTO_TCP) {
        uint8_t flags = features->tcp_flags;
        bool is_initiator = (features->flow_direction == flow->initiator_dir);
        uint8_t current_state = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);

        // Track sequence numbers for RST/FIN validation
        // Update expected sequence based on direction
        if (features->flow_direction == FLOW_DIR_LO_TO_HI) {
            // Calculate next expected seq: current_seq + payload_len (+ 1 for SYN/FIN)
            uint32_t payload_len = features->payload_len;
            if (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) {
                payload_len += 1;  // SYN and FIN consume a sequence number
            }
            uint32_t next_seq = features->tcp_seq + payload_len;
            __atomic_store_n(&flow->seq_lo_to_hi, next_seq, __ATOMIC_RELAXED);
            __atomic_store_n(&flow->ack_lo_to_hi, features->tcp_ack, __ATOMIC_RELAXED);
            // Enable sequence tracking once we have data
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

        // RST always transitions to RST state (immediate close)
        if (flags & TCP_FLAG_RST) {
            __atomic_store_n(&flow->state, FLOW_STATE_RST, __ATOMIC_RELEASE);
            return;
        }

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
                // Simultaneous open: initiator sends ACK
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
                        // Initiator (client) is closing
                        __atomic_store_n(&flow->state, FLOW_STATE_FIN_WAIT_1, __ATOMIC_RELEASE);
                    } else {
                        // Responder (server) is closing
                        __atomic_store_n(&flow->state, FLOW_STATE_CLOSE_WAIT, __ATOMIC_RELEASE);
                    }
                }
                break;

            case FLOW_STATE_FIN_WAIT_1:
                // Initiator sent FIN, waiting for ACK or FIN from responder
                if (flags & TCP_FLAG_FIN) {
                    if (!is_initiator) {
                        // Simultaneous close: responder also sent FIN
                        __atomic_store_n(&flow->state, FLOW_STATE_CLOSING, __ATOMIC_RELEASE);
                    }
                } else if (flags & TCP_FLAG_ACK) {
                    if (!is_initiator) {
                        // Responder ACKed our FIN
                        __atomic_store_n(&flow->state, FLOW_STATE_FIN_WAIT_2, __ATOMIC_RELEASE);
                    }
                }
                break;

            case FLOW_STATE_FIN_WAIT_2:
                // Our FIN was ACKed, waiting for responder's FIN
                if (flags & TCP_FLAG_FIN) {
                    if (!is_initiator) {
                        // Responder sent FIN
                        __atomic_store_n(&flow->state, FLOW_STATE_TIME_WAIT, __ATOMIC_RELEASE);
                    }
                }
                break;

            case FLOW_STATE_CLOSE_WAIT:
                // Responder sent FIN first, waiting for initiator to close
                if (flags & TCP_FLAG_FIN) {
                    if (is_initiator) {
                        // Initiator also sending FIN
                        __atomic_store_n(&flow->state, FLOW_STATE_LAST_ACK, __ATOMIC_RELEASE);
                    }
                }
                break;

            case FLOW_STATE_CLOSING:
                // Both sides sent FIN, waiting for final ACKs
                if (flags & TCP_FLAG_ACK) {
                    __atomic_store_n(&flow->state, FLOW_STATE_TIME_WAIT, __ATOMIC_RELEASE);
                }
                break;

            case FLOW_STATE_LAST_ACK:
                // Waiting for ACK of our FIN
                if (flags & TCP_FLAG_ACK) {
                    __atomic_store_n(&flow->state, FLOW_STATE_CLOSED, __ATOMIC_RELEASE);
                }
                break;

            case FLOW_STATE_TIME_WAIT:
                // Already in TIME_WAIT, will be cleaned up by aging
                // Stay in TIME_WAIT until timeout (handled by flow aging)
                break;

            case FLOW_STATE_CLOSED:
            case FLOW_STATE_RST:
                // Terminal states - no transitions
                break;

            default:
                break;
        }
    }
}

void flow_table_update(struct flow_entry *flow, const struct packet_features *features) {
    flow_table_update_internal(flow, features, 0);
}

void flow_table_update_tsc(struct flow_entry *flow, const struct packet_features *features,
                           uint64_t now_tsc) {
    flow_table_update_internal(flow, features, now_tsc);
}

// ==================== Rate Limiting ====================

/**
 * Get effective rate limits based on anomaly state and configuration
 * Returns dynamically adjusted limits based on current threat level
 */
static inline void get_effective_rate_limits(uint32_t *pps_out, uint32_t *bps_out) {
    const struct layer1_config *cfg = layer1_config_get();
    uint32_t pps_limit = 0;
    uint32_t bps_limit = 0;

    if (cfg && cfg->rate_limits.dynamic_enabled) {
        // Dynamic rate limiting based on anomaly level
        if (anomaly_is_active()) {
            // Use attack mode limits
            pps_limit = cfg->rate_limits.attack_pps_per_ip;
            bps_limit = cfg->rate_limits.attack_bps_per_ip;

            // Further reduce based on rate limit percentage
            uint32_t pct = anomaly_get_rate_limit_pct();
            pps_limit = (pps_limit * pct) / 100;
            bps_limit = (bps_limit * pct) / 100;
        } else {
            // Normal mode limits
            pps_limit = cfg->rate_limits.normal_pps_per_ip;
            bps_limit = cfg->rate_limits.normal_bps_per_ip;
        }
    }

    *pps_out = pps_limit;
    *bps_out = bps_limit;
}

enum rate_limit_action flow_table_check_rate_limit(struct flow_entry *flow,
                                                   const struct packet_features *features,
                                                   const struct per_ip_anomaly_snapshot *ip_anom) {
    (void)ip_anom;  // Reserved for future per-IP rate adjustment
    if (unlikely(!flow || !features)) {
        return RL_ACCEPT;
    }

    // Only rate limit initiator direction (protects against inbound floods)
    if (features->flow_direction != flow->initiator_dir) {
        return RL_ACCEPT;
    }

    uint64_t now_tsc = features->timestamp_tsc ? features->timestamp_tsc : rte_rdtsc();
    uint64_t window_start = __atomic_load_n(&flow->window_start_tsc, __ATOMIC_ACQUIRE);
    uint64_t window_elapsed = now_tsc - window_start;

    // Reset window after 1 second
    if (window_elapsed >= tsc_hz) {
        __atomic_store_n(&flow->window_start_tsc, now_tsc, __ATOMIC_RELEASE);
        __atomic_store_n(&flow->window_packets, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&flow->window_bytes, 0, __ATOMIC_RELAXED);
    }

    // Get effective limits (flow-specific or dynamic global)
    uint32_t pps_limit = __atomic_load_n(&flow->pps_limit, __ATOMIC_RELAXED);
    uint32_t bps_limit = __atomic_load_n(&flow->bps_limit, __ATOMIC_RELAXED);

    // If no flow-specific limits, use dynamic limits from config
    if (pps_limit == 0 && bps_limit == 0) {
        get_effective_rate_limits(&pps_limit, &bps_limit);
    }

    // Check PPS limit
    if (pps_limit > 0) {
        uint32_t current_packets = __atomic_load_n(&flow->window_packets, __ATOMIC_RELAXED);
        if (current_packets >= pps_limit) {
            __atomic_fetch_or(&flow->flags, FLOW_FLAG_RATE_LIMITED, __ATOMIC_RELAXED);
            // Per-lcore stats - NO ATOMICS
            get_flow_lcore_stats()->rate_limit_drops++;
            return RL_DROP_PPS;
        }
    }

    // Check BPS limit
    if (bps_limit > 0) {
        uint32_t current_bytes = __atomic_load_n(&flow->window_bytes, __ATOMIC_RELAXED);
        if (current_bytes + features->packet_size > bps_limit) {
            __atomic_fetch_or(&flow->flags, FLOW_FLAG_RATE_LIMITED, __ATOMIC_RELAXED);
            // Per-lcore stats - NO ATOMICS
            get_flow_lcore_stats()->rate_limit_drops++;
            return RL_DROP_BPS;
        }
    }

    // Update counters
    __atomic_add_fetch(&flow->window_packets, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&flow->window_bytes, features->packet_size, __ATOMIC_RELAXED);

    return RL_ACCEPT;
}

int flow_table_set_limits(struct packet_features *features, 
                          uint32_t pps_limit, uint32_t bps_limit) {
    struct flow_entry *flow = flow_table_lookup(features);
    if (!flow) {
        return -1;
    }
    __atomic_store_n(&flow->pps_limit, pps_limit, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->bps_limit, bps_limit, __ATOMIC_RELAXED);
    return 0;
}

// ==================== Flow Aging ====================

/**
 * Information needed to delete a flow after iteration.
 */
struct flow_delete_batch {
    struct flow_key keys[AGING_BATCH_SIZE];
    uint32_t indices[AGING_BATCH_SIZE];
    uint32_t count;
};

// Incremental aging to avoid O(n) full table scan each call
// Save iterator state between calls and limit entries scanned per invocation
static uint32_t aging_iterator = 0;
// AGING_SCAN_LIMIT is now configurable via layer1_config.flow_table.aging_scan_limit
// Default: 4096, configurable at runtime

uint32_t flow_table_age_flows(void) {
    struct flow_delete_batch batch;
    uint32_t total_aged = 0;
    uint64_t now_tsc = rte_rdtsc();
    uint64_t timeout_tsc = seconds_to_tsc(config.idle_timeout_sec);
    uint64_t syn_timeout_tsc = seconds_to_tsc(config.syn_timeout_sec);
    uint32_t iter = aging_iterator;  // Resume from saved position
    uint32_t scanned = 0;            // Track entries scanned
    const struct flow_key *key_ptr;
    void *data;
    int32_t pos;

    if (unlikely(!initialized)) {
        return 0;
    }

    // Adaptive timeout based on table occupancy
    uint32_t active_count = rte_ring_free_count(free_index_ring);
    active_count = config.max_flows - rte_ring_count(free_index_ring);
    float occupancy = (float)active_count / config.max_flows;
    
    // Under pressure: reduce timeouts
    if (occupancy > 0.95f) {
        timeout_tsc /= 4;
        syn_timeout_tsc /= 4;
    } else if (occupancy > 0.90f) {
        timeout_tsc /= 2;
        syn_timeout_tsc /= 2;
    }

    batch.count = 0;

    // Track corruption count for monitoring
    static uint32_t corruption_count = 0;

    // Iterate with scan limit to avoid O(n) full table scan
    // Under pressure (occupancy > 90%), scan more aggressively
    // Scan limits are now configurable via layer1_config
    uint32_t scan_limit_normal = config.aging_scan_limit > 0 ? config.aging_scan_limit : 4096;
    uint32_t scan_limit_pressure = config.aging_scan_limit_pressure > 0 ? config.aging_scan_limit_pressure : scan_limit_normal * 2;
    uint32_t scan_limit = (occupancy > 0.90f) ? scan_limit_pressure : scan_limit_normal;

    while ((pos = rte_hash_iterate(flow_hash, (const void **)&key_ptr, &data, &iter)) >= 0) {
        scanned++;
        struct flow_entry *flow = (struct flow_entry *)data;

        // Enhanced defensive checks with corruption tracking
        // Invalid pointers indicate hash table corruption - log and skip but track occurrences
        if (unlikely(flow == NULL)) {
            if (__atomic_add_fetch(&corruption_count, 1, __ATOMIC_RELAXED) <= 10) {
                RTE_LOG(ERR, FLOWTBL, "NULL flow pointer in hash iteration (corruption?)\n");
            }
            continue;
        }
        if (unlikely(flow < flow_entries || flow >= &flow_entries[config.max_flows])) {
            if (__atomic_add_fetch(&corruption_count, 1, __ATOMIC_RELAXED) <= 10) {
                RTE_LOG(ERR, FLOWTBL, "Flow pointer %p out of bounds [%p, %p) - possible memory corruption\n",
                        (void *)flow, (void *)flow_entries, (void *)&flow_entries[config.max_flows]);
            }
            continue;
        }

        // Use ACQUIRE ordering for last_seen_tsc to ensure we see
        // all prior writes from the updating thread before making aging decision
        uint64_t last_seen = __atomic_load_n(&flow->last_seen_tsc, __ATOMIC_ACQUIRE);
        uint64_t idle_time = now_tsc - last_seen;
        uint64_t flow_timeout = timeout_tsc;

        // State-based timeouts for TCP flows
        if (flow->key.protocol == IPPROTO_TCP) {
            uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_RELAXED);

            switch (state) {
                case FLOW_STATE_NEW:
                case FLOW_STATE_SYN_RECEIVED:
                case FLOW_STATE_SYN_ACK_RECEIVED:
                    // Incomplete handshake - short timeout (SYN flood protection)
                    if (config.enable_syn_protection) {
                        flow_timeout = syn_timeout_tsc;
                    }
                    break;

                case FLOW_STATE_TIME_WAIT:
                    // TIME_WAIT: standard 2*MSL timeout, use short timeout here
                    // (full 2*MSL=240s is too long for high-performance systems)
                    flow_timeout = syn_timeout_tsc * 6;  // ~30 seconds
                    break;

                case FLOW_STATE_FIN_WAIT_1:
                case FLOW_STATE_FIN_WAIT_2:
                case FLOW_STATE_CLOSE_WAIT:
                case FLOW_STATE_CLOSING:
                case FLOW_STATE_LAST_ACK:
                    // Closing states - moderate timeout
                    flow_timeout = syn_timeout_tsc * 4;  // ~20 seconds
                    break;

                case FLOW_STATE_CLOSED:
                case FLOW_STATE_RST:
                    // Terminal states - immediate cleanup
                    flow_timeout = 0;
                    break;

                case FLOW_STATE_ESTABLISHED:
                default:
                    // Established or unknown - use normal idle timeout
                    break;
            }
        }

        if (idle_time > flow_timeout) {
            // Add to delete batch
            memcpy(&batch.keys[batch.count], key_ptr, sizeof(struct flow_key));
            batch.indices[batch.count] = flow->entry_index;
            batch.count++;

            // Process batch when full
            if (batch.count >= AGING_BATCH_SIZE) {
                break;
            }
        }

        // Stop after scan limit to spread work across calls
        if (scanned >= scan_limit) {
            break;
        }
    }

    // Save iterator for next call (wraps to 0 when iteration completes)
    // rte_hash_iterate returns -ENOENT when done, at which point iter should reset
    if (pos < 0) {
        // Completed full iteration, reset to start
        aging_iterator = 0;
    } else {
        // Stopped early (batch full or scan limit), save position
        aging_iterator = iter;
    }

    // Delete collected flows (safe: iteration complete or batch full)
    for (uint32_t i = 0; i < batch.count; i++) {
        int32_t del_pos = rte_hash_del_key(flow_hash, &batch.keys[i]);
        
        if (del_pos >= 0) {
            uint32_t entry_idx = batch.indices[i];
            
            if (likely(entry_idx < config.max_flows)) {
                // Clear entry
                memset(&flow_entries[entry_idx], 0, sizeof(struct flow_entry));
                
                // Return index to free ring
                flow_entry_free(entry_idx);
            }
            total_aged++;
        }
    }

    if (total_aged > 0) {
        // Aging is single-threaded, no need for atomic
        global_deletes += total_aged;

        if (total_aged >= AGING_BATCH_SIZE) {
            RTE_LOG(DEBUG, FLOWTBL, "Aged %u flows (batch limit, more pending)\n", total_aged);
        } else {
            RTE_LOG(DEBUG, FLOWTBL, "Aged %u flows\n", total_aged);
        }
    }

    return total_aged;
}

// ==================== Statistics ====================

void flow_table_get_stats(uint32_t *active_flows, uint32_t *total_flows, uint32_t *aged_flows) {
    if (active_flows) {
        *active_flows = initialized ? rte_hash_count(flow_hash) : 0;
    }
    if (total_flows) {
        // Aggregate creates from per-lcore stats
        uint64_t total = 0;
        unsigned int lcore_id;
        RTE_LCORE_FOREACH(lcore_id) {
            total += lcore_stats[lcore_id].creates;
        }
        *total_flows = (uint32_t)total;
    }
    if (aged_flows) {
        *aged_flows = (uint32_t)global_deletes;
    }
}

void flow_table_get_detailed_stats(struct flow_table_stats *out_stats) {
    if (!out_stats) {
        return;
    }

    // Aggregate from per-lcore statistics
    memset(out_stats, 0, sizeof(*out_stats));

    unsigned int lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        struct flow_table_lcore_stats *lstats = &lcore_stats[lcore_id];
        out_stats->lookups += lstats->lookups;
        out_stats->lookup_hits += lstats->lookup_hits;
        out_stats->creates += lstats->creates;
        out_stats->create_failures += lstats->create_failures;
        out_stats->updates += lstats->updates;
        out_stats->rate_limit_drops += lstats->rate_limit_drops;
    }

    // Add global deletes (from aging, single-threaded)
    out_stats->deletes = global_deletes;
}

void flow_table_clear(void) {
    struct flow_key keys[256];
    uint32_t indices[256];
    uint32_t batch_count;
    uint32_t iter;
    const struct flow_key *key_ptr;
    void *data;

    if (!initialized) {
        return;
    }

    // Delete all entries in batches
    do {
        batch_count = 0;
        iter = 0;

        while (rte_hash_iterate(flow_hash, (const void **)&key_ptr, &data, &iter) >= 0) {
            struct flow_entry *flow = (struct flow_entry *)data;
            
            memcpy(&keys[batch_count], key_ptr, sizeof(struct flow_key));
            indices[batch_count] = (flow != NULL) ? flow->entry_index : UINT32_MAX;
            batch_count++;

            if (batch_count >= 256) {
                break;
            }
        }

        for (uint32_t i = 0; i < batch_count; i++) {
            rte_hash_del_key(flow_hash, &keys[i]);
            if (indices[i] < config.max_flows) {
                memset(&flow_entries[indices[i]], 0, sizeof(struct flow_entry));
                flow_entry_free(indices[i]);
            }
        }
    } while (batch_count > 0);

    // Clear per-lcore stats and global counters
    memset(lcore_stats, 0, sizeof(lcore_stats));
    global_deletes = 0;

    RTE_LOG(INFO, FLOWTBL, "Flow table cleared\n");
}

void flow_table_print_stats(void) {
    uint32_t active = initialized ? rte_hash_count(flow_hash) : 0;
    uint32_t free_count = initialized ? rte_ring_count(free_index_ring) : 0;
    float occupancy = config.max_flows > 0 ?
                      (float)active / config.max_flows * 100.0f : 0.0f;

    // Aggregate per-lcore stats for display
    struct flow_table_stats agg;
    flow_table_get_detailed_stats(&agg);

    printf("  Flow Table:\n");
    printf("    Active:       %u / %u (%.1f%%)\n", active, config.max_flows, occupancy);
    printf("    Free indices: %u\n", free_count);
    printf("    Lookups:      %lu (hits: %lu)\n", agg.lookups, agg.lookup_hits);
    printf("    Creates:      %lu (failures: %lu)\n", agg.creates, agg.create_failures);
    printf("    Deletes:      %lu\n", agg.deletes);
    printf("    Updates:      %lu\n", agg.updates);
    printf("    Rate drops:   %lu\n", agg.rate_limit_drops);
}

void flow_table_dump(uint32_t max_entries) {
    uint32_t iter = 0;
    uint32_t count = 0;
    const struct flow_key *key_ptr;
    void *data;

    if (!initialized) {
        printf("Flow table not initialized\n");
        return;
    }

    printf("\n=== Flow Table Dump ===\n");
    
    while (rte_hash_iterate(flow_hash, (const void **)&key_ptr, &data, &iter) >= 0) {
        struct flow_entry *flow = (struct flow_entry *)data;
        
        if (!flow) continue;

        printf("Flow %u: %u.%u.%u.%u <-> %u.%u.%u.%u proto=%u\n",
               count,
               (key_ptr->ip_lo >> 24) & 0xFF, (key_ptr->ip_lo >> 16) & 0xFF,
               (key_ptr->ip_lo >> 8) & 0xFF, key_ptr->ip_lo & 0xFF,
               (key_ptr->ip_hi >> 24) & 0xFF, (key_ptr->ip_hi >> 16) & 0xFF,
               (key_ptr->ip_hi >> 8) & 0xFF, key_ptr->ip_hi & 0xFF,
               key_ptr->protocol);
        printf("  State: %s, Pkts: %lu/%lu, Bytes: %lu/%lu\n",
               flow_state_str(flow->state),
               flow->packets_lo_to_hi, flow->packets_hi_to_lo,
               flow->bytes_lo_to_hi, flow->bytes_hi_to_lo);

        count++;
        if (max_entries > 0 && count >= max_entries) {
            printf("  ... (truncated at %u entries)\n", max_entries);
            break;
        }
    }

    printf("Total: %u flows\n", count);
}

// ==================== RST/FIN Validation ====================

/**
 * TCP sequence number window size for RST/FIN validation.
 * A larger window allows for out-of-order packets but is less strict.
 * RFC 5961 recommends exact match for RST, but we use a window for practicality.
 */
#define RST_FIN_SEQ_WINDOW  (1 << 20)  // ~1MB window (typical receive window)

/**
 * Check if sequence number is within acceptable window.
 * Handles 32-bit wraparound correctly using signed comparison.
 */
static inline bool seq_in_window(uint32_t seq, uint32_t expected, uint32_t window) {
    // Use signed arithmetic to handle wraparound
    int32_t diff = (int32_t)(seq - expected);
    // Accept if seq is within window before or after expected
    return (diff >= -(int32_t)window && diff <= (int32_t)window);
}

enum rst_fin_validation_result flow_table_validate_rst_fin(
    struct packet_features *features) {

    if (unlikely(!initialized || !features)) {
        return RST_FIN_NO_FLOW;
    }

    // Only validate TCP RST/FIN packets
    if (features->protocol != IPPROTO_TCP) {
        return RST_FIN_VALID;
    }

    uint8_t flags = features->tcp_flags;
    if (!(flags & (TCP_FLAG_RST | TCP_FLAG_FIN))) {
        return RST_FIN_VALID;  // Not RST or FIN, no validation needed
    }

    // Get per-lcore stats
    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= MAX_LCORES) lcore_id = 0;
    struct rst_fin_lcore_stats *rstats = &rst_fin_stats[lcore_id];

    // Lookup the flow
    struct flow_entry *flow = flow_table_lookup(features);
    if (!flow) {
        // RST/FIN for non-existent flow - suspicious
        rstats->invalid_no_flow++;
        return RST_FIN_NO_FLOW;
    }

    uint8_t flow_flags = __atomic_load_n(&flow->flags, __ATOMIC_RELAXED);

    // If sequence tracking is not enabled, accept (flow just started)
    if (!(flow_flags & FLOW_FLAG_SEQ_TRACKING_ENABLED)) {
        rstats->valid_count++;
        return RST_FIN_VALID;
    }

    // Get the expected sequence number for this direction
    uint32_t expected_seq;
    uint32_t last_ack;

    if (features->flow_direction == FLOW_DIR_LO_TO_HI) {
        expected_seq = __atomic_load_n(&flow->seq_lo_to_hi, __ATOMIC_RELAXED);
        last_ack = __atomic_load_n(&flow->ack_hi_to_lo, __ATOMIC_RELAXED);  // ACK from other side
    } else {
        expected_seq = __atomic_load_n(&flow->seq_hi_to_lo, __ATOMIC_RELAXED);
        last_ack = __atomic_load_n(&flow->ack_lo_to_hi, __ATOMIC_RELAXED);
    }

    // RST validation: sequence must be in expected window
    // RFC 5961 is stricter, but we allow a window for practical deployments
    if (flags & TCP_FLAG_RST) {
        // RST sequence should be close to what we expect next, or close to last ACK
        bool seq_ok = seq_in_window(features->tcp_seq, expected_seq, RST_FIN_SEQ_WINDOW);
        bool ack_ok = seq_in_window(features->tcp_seq, last_ack, RST_FIN_SEQ_WINDOW);

        if (!seq_ok && !ack_ok) {
            rstats->invalid_seq++;
            RTE_LOG(DEBUG, FLOWTBL, "RST seq validation failed: seq=%u, expected=%u, last_ack=%u\n",
                    features->tcp_seq, expected_seq, last_ack);
            return RST_FIN_SEQ_OUT_OF_WINDOW;
        }
    }

    // FIN validation: sequence should be in expected window
    if (flags & TCP_FLAG_FIN) {
        // FIN should be sent at the end of data, so seq should be near expected
        if (!seq_in_window(features->tcp_seq, expected_seq, RST_FIN_SEQ_WINDOW)) {
            rstats->invalid_seq++;
            RTE_LOG(DEBUG, FLOWTBL, "FIN seq validation failed: seq=%u, expected=%u\n",
                    features->tcp_seq, expected_seq);
            return RST_FIN_SEQ_OUT_OF_WINDOW;
        }

        // Check flow state - FIN should come in appropriate states
        uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_RELAXED);
        switch (state) {
            case FLOW_STATE_ESTABLISHED:
            case FLOW_STATE_FIN_WAIT_1:
            case FLOW_STATE_FIN_WAIT_2:
            case FLOW_STATE_CLOSE_WAIT:
            case FLOW_STATE_CLOSING:
                // FIN is valid in these states
                break;

            case FLOW_STATE_NEW:
            case FLOW_STATE_SYN_RECEIVED:
            case FLOW_STATE_SYN_ACK_RECEIVED:
                // FIN before connection established - suspicious
                rstats->invalid_state++;
                RTE_LOG(DEBUG, FLOWTBL, "FIN in pre-established state %d\n", state);
                return RST_FIN_UNEXPECTED_STATE;

            case FLOW_STATE_TIME_WAIT:
            case FLOW_STATE_CLOSED:
            case FLOW_STATE_RST:
                // FIN after close - ignore but don't fail
                break;

            default:
                break;
        }
    }

    rstats->valid_count++;
    return RST_FIN_VALID;
}

void flow_table_get_rst_fin_stats(uint64_t *valid_count, uint64_t *invalid_count) {
    uint64_t valid = 0;
    uint64_t invalid = 0;

    unsigned int lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        struct rst_fin_lcore_stats *rstats = &rst_fin_stats[lcore_id];
        valid += rstats->valid_count;
        invalid += rstats->invalid_seq + rstats->invalid_no_flow + rstats->invalid_state;
    }

    if (valid_count) *valid_count = valid;
    if (invalid_count) *invalid_count = invalid;
}

// ==================== Reputation-Based Emergency Eviction ====================

/**
 * Calculate eviction priority score for a flow (lower = evict first)
 *
 * Made scoring much more aggressive for attack traffic
 * During DDoS, most flows are single-direction SYN or incomplete - evict these first
 *
 * Scoring factors (negative = evict sooner):
 * - Incomplete handshakes (SYN_RECEIVED): -2000 (prime eviction target)
 * - Single-direction flows (no response): -1500 (definitely attack)
 * - Very short-lived flows (<1 sec): -500
 * - Terminal states (CLOSED, RST): -300 (cleanup)
 * - Low reputation: -200 per bad event
 *
 * Protection factors (positive = keep longer):
 * - Established + bidirectional: +500 (definitely legitimate)
 * - Bidirectional traffic: +300 (likely legitimate)
 * - Good reputation: +100
 * - Age bonus: +1 per 10 seconds (capped at +100)
 */
static int32_t calculate_eviction_priority(const struct flow_entry *flow, uint64_t now_tsc) {
    int32_t score = 0;

    uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_RELAXED);

    // Get packet counts first - used in multiple decisions
    uint64_t pkts_lo = __atomic_load_n(&flow->packets_lo_to_hi, __ATOMIC_RELAXED);
    uint64_t pkts_hi = __atomic_load_n(&flow->packets_hi_to_lo, __ATOMIC_RELAXED);
    bool bidirectional = (pkts_lo > 0 && pkts_hi > 0);

    // Calculate flow age
    uint64_t first_seen = flow->first_seen_tsc;
    uint64_t age_sec = 0;
    if (first_seen > 0 && now_tsc > first_seen) {
        age_sec = (now_tsc - first_seen) / rte_get_tsc_hz();
    }

    // State-based scoring - AGGRESSIVE for incomplete flows
    switch (state) {
        case FLOW_STATE_NEW:
        case FLOW_STATE_SYN_RECEIVED:
            // Incomplete handshakes - PRIME eviction targets during DDoS
            // These are almost certainly attack traffic when table is full
            score -= 2000;
            // Extra penalty if flow is old but still not established
            if (age_sec > 5) {
                score -= 500;  // Stuck in SYN state for >5 sec = attack
            }
            break;

        case FLOW_STATE_SYN_ACK_RECEIVED:
            // Got SYN-ACK but no ACK - slightly less suspicious
            score -= 1500;
            break;

        case FLOW_STATE_ESTABLISHED:
            // Established - protect, especially if bidirectional
            if (bidirectional) {
                score += 500;  // Definitely legitimate
            } else {
                score += 100;  // Established but one-way - could be data transfer
            }
            break;

        case FLOW_STATE_CLOSED:
        case FLOW_STATE_RST:
        case FLOW_STATE_TIME_WAIT:
            // Terminal states - cleanup these
            score -= 300;
            break;

        case FLOW_STATE_FIN_WAIT_1:
        case FLOW_STATE_FIN_WAIT_2:
        case FLOW_STATE_CLOSE_WAIT:
        case FLOW_STATE_CLOSING:
        case FLOW_STATE_LAST_ACK:
            // Closing states - moderate priority for eviction
            score -= 100;
            break;

        default:
            break;
    }

    // Bidirectional traffic is THE key indicator of legitimate connection
    if (bidirectional) {
        score += 300;
    } else {
        // Single-direction = almost certainly attack during DDoS
        score -= 1500;
    }

    // Very short-lived non-established flows are likely attack
    if (age_sec < 1 && state != FLOW_STATE_ESTABLISHED) {
        score -= 500;
    }

    // Reputation score (0-65535, higher is better)
    uint16_t rep = flow->reputation_score;
    if (rep < 100) {
        score -= 200;  // Very bad reputation
    } else if (rep < 500) {
        score -= 100;  // Bad reputation
    } else if (rep > 2000) {
        score += 100;  // Good reputation
    }

    // Small bonus for longer-lived established connections
    // But don't over-protect - age is less important than bidirectionality
    if (state == FLOW_STATE_ESTABLISHED && age_sec > 10) {
        score += (int32_t)(age_sec / 10);  // +1 per 10 seconds
        if (score > 600) score = 600;  // Cap at +100 from age
    }

    return score;
}

// Eviction candidate structure
struct eviction_candidate {
    struct flow_key key;
    uint32_t entry_index;
    int32_t priority;
};

// Comparison function for sorting (lowest priority first)
static int compare_eviction_candidates(const void *a, const void *b) {
    const struct eviction_candidate *ca = (const struct eviction_candidate *)a;
    const struct eviction_candidate *cb = (const struct eviction_candidate *)b;
    return ca->priority - cb->priority;  // Lower priority = earlier in sorted array
}

uint32_t flow_table_emergency_evict(uint32_t count_needed) {
    if (!initialized || count_needed == 0) {
        return 0;
    }

    // Limit single eviction pass to prevent stalling
    const uint32_t max_scan = 10000;
    const uint32_t max_candidates = 1024;

    uint64_t now_tsc = rte_rdtsc();
    uint32_t iter = 0;
    const struct flow_key *key_ptr;
    void *data;
    uint32_t scanned = 0;

    // Collect eviction candidates
    struct eviction_candidate *candidates = rte_malloc("evict_candidates",
        max_candidates * sizeof(struct eviction_candidate), RTE_CACHE_LINE_SIZE);

    if (!candidates) {
        RTE_LOG(ERR, FLOWTBL, "Failed to allocate eviction candidate buffer\n");
        return 0;
    }

    uint32_t candidate_count = 0;

    // Phase 1: Collect candidates with priority scores
    while (rte_hash_iterate(flow_hash, (const void **)&key_ptr, &data, &iter) >= 0) {
        scanned++;
        if (scanned > max_scan) break;

        struct flow_entry *flow = (struct flow_entry *)data;
        if (!flow) continue;

        // Skip flows being initialized
        uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_RELAXED);
        if (state == FLOW_STATE_INITIALIZING) continue;

        // Calculate eviction priority
        int32_t priority = calculate_eviction_priority(flow, now_tsc);

        // Add to candidates if buffer not full, or if better than worst current candidate
        if (candidate_count < max_candidates) {
            candidates[candidate_count].key = *key_ptr;
            candidates[candidate_count].entry_index = flow->entry_index;
            candidates[candidate_count].priority = priority;
            candidate_count++;
        } else if (priority < candidates[max_candidates - 1].priority) {
            // Replace worst candidate (highest priority = last after sort)
            // Simple insertion: find and replace worst
            int worst_idx = 0;
            int32_t worst_priority = candidates[0].priority;
            for (uint32_t i = 1; i < max_candidates; i++) {
                if (candidates[i].priority > worst_priority) {
                    worst_priority = candidates[i].priority;
                    worst_idx = i;
                }
            }
            if (priority < worst_priority) {
                candidates[worst_idx].key = *key_ptr;
                candidates[worst_idx].entry_index = flow->entry_index;
                candidates[worst_idx].priority = priority;
            }
        }
    }

    if (candidate_count == 0) {
        rte_free(candidates);
        return 0;
    }

    // Phase 2: Sort candidates by priority (lowest first)
    qsort(candidates, candidate_count, sizeof(struct eviction_candidate),
          compare_eviction_candidates);

    // Phase 3: Evict lowest-priority flows
    uint32_t evicted = 0;
    uint32_t to_evict = (count_needed < candidate_count) ? count_needed : candidate_count;

    for (uint32_t i = 0; i < to_evict; i++) {
        int32_t del_pos = rte_hash_del_key(flow_hash, &candidates[i].key);

        if (del_pos >= 0) {
            uint32_t entry_idx = candidates[i].entry_index;

            if (likely(entry_idx < config.max_flows)) {
                // Clear entry
                memset(&flow_entries[entry_idx], 0, sizeof(struct flow_entry));
                // Return index to free ring
                flow_entry_free(entry_idx);
            }
            evicted++;
        }
    }

    rte_free(candidates);

    if (evicted > 0) {
        global_deletes += evicted;
        RTE_LOG(NOTICE, FLOWTBL, "Emergency eviction: evicted %u flows (needed %u, scanned %u)\n",
                evicted, count_needed, scanned);
    }

    return evicted;
}

bool flow_table_needs_emergency_evict(void) {
    if (!initialized) return false;

    uint32_t active = rte_hash_count(flow_hash);
    float occupancy = (float)active / config.max_flows;

    return (occupancy > 0.95f);
}

uint32_t flow_table_get_occupancy_percent(void) {
    if (!initialized || config.max_flows == 0) return 0;

    uint32_t active = rte_hash_count(flow_hash);
    return (active * 100) / config.max_flows;
}