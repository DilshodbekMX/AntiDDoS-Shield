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
#include "flow_table_internal.h"
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
#include <rte_pause.h>
#include <rte_spinlock.h>
#include <rte_rcu_qsbr.h>
#include <errno.h>
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

// Every writer of flow_hash_v6 (each add and each delete) holds this lock;
// readers do not. As in flow_table.c (flow_hash_wlock): RW_CONCURRENCY makes
// readers safe against one writer, while two concurrent adds could take the
// same key slot; MULTI_WRITER_ADD would fault on non-EAL threads.
static rte_spinlock_t flow_hash_v6_wlock = RTE_SPINLOCK_INITIALIZER;

// Longest wait for a flow another lcore has just added to leave
// FLOW_STATE_INITIALIZING (it is published right after the add)
#define FLOW_V6_PUBLISH_WAIT_US  50

// Non-EAL threads (LCORE_ID_ANY) own no per-lcore slot. They share the extra
// stats slot at NON_EAL_SLOT_V6 and update it atomically, so they race
// neither lcore 0's plain counters nor each other.
#define NON_EAL_SLOT_V6       MAX_LCORES

// Per-lcore statistics - NO ATOMICS in fast path
// The getter sums all MAX_LCORES + 1 slots: RTE_LCORE_FOREACH skips the
// lcore ids of threads registered with rte_thread_register() (role
// ROLE_NON_EAL).
static struct flow_table_v6_stats lcore_stats_v6[MAX_LCORES + 1] __rte_cache_aligned;

// Per-lcore RST/FIN validation stats
struct rst_fin_lcore_stats_v6 {
    uint64_t valid_count;
    uint64_t invalid_seq;
    uint64_t invalid_no_flow;
    uint64_t invalid_state;
    uint64_t _pad[4];
} __rte_cache_aligned;
static struct rst_fin_lcore_stats_v6 rst_fin_stats_v6[MAX_LCORES + 1] __rte_cache_aligned;

// Count one event: a plain increment in an lcore's own slot, an atomic one
// in the slot non-EAL threads share
#define SLOT_STAT_INC_V6(shared, counter) do {                  \
    if (unlikely(shared)) {                                     \
        __atomic_fetch_add(&(counter), 1, __ATOMIC_RELAXED);    \
    } else {                                                    \
        (counter)++;                                            \
    }                                                           \
} while (0)
#define FLOW_V6_STAT_INC(lstats, field) \
    SLOT_STAT_INC_V6((lstats) == &lcore_stats_v6[NON_EAL_SLOT_V6], (lstats)->field)
#define RST_FIN_V6_STAT_INC(rstats, field) \
    SLOT_STAT_INC_V6((rstats) == &rst_fin_stats_v6[NON_EAL_SLOT_V6], (rstats)->field)

// Flows deleted by aging (main lcore) and emergency eviction (any lcore):
// updated and read atomically
static uint64_t global_deletes_v6 = 0;

// Aging position saved between calls: the entry index (a position in
// flow_used_v6) the next call starts at (init and cleanup reset it: a
// position saved in one table means nothing in the next)
static uint32_t aging_iterator_v6 = 0;

// Occupancy bitmap, as flow_used in flow_table.c: bit i is set while entry i
// holds a flow in the hash (set by the add, cleared by the delete, both
// under flow_hash_v6_wlock). Aging walks it instead of the hash, at most
// AGING_WORD_LIMIT_V6 words per call.
static uint64_t *flow_used_v6 = NULL;
static uint32_t flow_used_words_v6 = 0;
#define AGING_WORD_LIMIT_V6    65536

// Seed of flow_hash_v6's hash function (see flow_table_hash_seed_seam())
static uint32_t hash_seed_v6 = 0;

// Deleted entries waiting for their grace period (see "Deferred
// Reclamation" in flow_table.h)
static struct flow_limbo limbo_v6;

// As in flow_table.c: most indices one create or aging pass takes back from
// the limbo, the eviction batch (no eviction while that many deleted entries
// wait), and the wait after which aging reports a reader that stopped
#define RECLAIM_CREATE_MAX_V6  64
#define RECLAIM_AGING_MAX_V6   65536
#define FLOW_EVICT_BATCH_V6    256
#define LIMBO_STALL_SEC_V6     2

// ==================== Per-Lcore Free Cache ====================

#define LOCAL_FREE_CACHE_SIZE_V6  64
#define LOCAL_REFILL_BATCH_V6     32
#define FREE_CACHE_SHARE_DIV_V6   64   // All caches together hold at most max_flows / 64

struct lcore_free_cache_v6 {
    uint32_t indices[LOCAL_FREE_CACHE_SIZE_V6];
    uint32_t count;
    uint32_t _pad[14];
} __rte_cache_aligned;

static struct lcore_free_cache_v6 lcore_free_caches_v6[MAX_LCORES];

// How many indices one refill takes from the ring (set by
// flow_table_v6_init()), as cache_refill_batch in flow_table.c: each cache
// has a single owner, so indices parked in one lcore's cache are out of
// every other lcore's reach. Init sizes the refill so that all caches
// together hold at most max_flows / FREE_CACHE_SHARE_DIV_V6; below
// FREE_CACHE_SHARE_DIV_V6 * MAX_LCORES flows (16384 with 256 lcores) a
// refill takes one index and caches none, so allocation fails only when
// the table is full.
static uint32_t cache_refill_batch_v6 = LOCAL_REFILL_BATCH_V6;

// ==================== Helper Functions ====================

static inline uint64_t seconds_to_tsc_v6(uint32_t seconds) {
    return (uint64_t)seconds * tsc_hz_v6;
}

static inline void flow_used_v6_set(uint32_t idx) {
    __atomic_fetch_or(&flow_used_v6[idx >> 6], 1ULL << (idx & 63), __ATOMIC_RELEASE);
}

static inline void flow_used_v6_clear(uint32_t idx) {
    __atomic_fetch_and(&flow_used_v6[idx >> 6], ~(1ULL << (idx & 63)), __ATOMIC_RELEASE);
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

// Return an index to the free ring at once. Only for an entry no reader can
// hold: one a create took and never added to the hash. An entry deleted from
// the hash goes through the limbo (flow_retire_v6()).
static inline void flow_entry_v6_free(uint32_t index) {
    rte_ring_mp_enqueue(free_index_ring_v6, (void *)(uintptr_t)index);
}

// Take back up to max deleted entries whose grace period is over and return
// their indices to the free ring (as flow_reclaim() in flow_table.c). An
// entry is cleared when a create takes it.
static uint32_t flow_reclaim_v6(uint32_t max) {
    uint32_t idx[256];
    void *objs[256];
    uint32_t total = 0;

    while (total < max) {
        uint32_t want = (max - total < RTE_DIM(idx)) ? max - total : (uint32_t)RTE_DIM(idx);
        uint32_t n = flow_limbo_take(&limbo_v6, idx, want);
        for (uint32_t i = 0; i < n; i++) {
            objs[i] = (void *)(uintptr_t)idx[i];
        }
        if (n > 0 && rte_ring_mp_enqueue_burst(free_index_ring_v6, objs, n, NULL) != n) {
            RTE_LOG(ERR, FLOW_V6, "Free index ring refused reclaimed indices\n");
        }
        total += n;
        if (n < want) {
            break;
        }
    }
    return total;
}

// Hand the n entries a delete pass removed from the hash to the limbo
static void flow_retire_v6(const uint32_t *idx, uint32_t n) {
    uint32_t refused = flow_limbo_push(&limbo_v6, idx, n);
    if (unlikely(refused > 0)) {
        // Not reachable while an index is in one place at a time: free them
        // at once rather than leak them
        RTE_LOG(ERR, FLOW_V6, "Limbo refused %u deleted IPv6 entries, freed at once\n", refused);
        for (uint32_t i = n - refused; i < n; i++) {
            flow_entry_v6_free(idx[i]);
        }
    }
}

// An empty ring first takes back deleted entries past their grace period
static inline int32_t flow_entry_v6_alloc(void) {
    unsigned int lcore_id = rte_lcore_id();

    // Non-EAL threads (LCORE_ID_ANY) own no cache. Sharing lcore 0's, whose
    // count is a plain field, let them and lcore 0 hand out the same index,
    // so they take one index straight from the multi-consumer ring.
    if (unlikely(lcore_id >= MAX_LCORES)) {
        void *idx_ptr = NULL;
        if (rte_ring_mc_dequeue(free_index_ring_v6, &idx_ptr) != 0 &&
            (flow_reclaim_v6(RECLAIM_CREATE_MAX_V6) == 0 ||
             rte_ring_mc_dequeue(free_index_ring_v6, &idx_ptr) != 0)) {
            return -1;  // Ring empty
        }
        return (int32_t)(uintptr_t)idx_ptr;
    }

    struct lcore_free_cache_v6 *cache = &lcore_free_caches_v6[lcore_id];

    // Fast path: get from local cache
    if (likely(cache->count > 0)) {
        return (int32_t)cache->indices[--cache->count];
    }

    // Calculate available space to prevent overflow
    uint32_t available_space = LOCAL_FREE_CACHE_SIZE_V6 - cache->count;
    uint32_t refill_count = (available_space > cache_refill_batch_v6) ?
                            cache_refill_batch_v6 : available_space;

    // Slow path: refill from global ring (an empty one first takes back
    // deleted entries past their grace period)
    void *idx_ptrs[LOCAL_REFILL_BATCH_V6];
    unsigned int got = rte_ring_mc_dequeue_burst(free_index_ring_v6, idx_ptrs,
                                                  refill_count, NULL);
    if (unlikely(got == 0)) {
        if (flow_reclaim_v6(RECLAIM_CREATE_MAX_V6) == 0) {
            return -1;  // Ring empty
        }
        got = rte_ring_mc_dequeue_burst(free_index_ring_v6, idx_ptrs, refill_count, NULL);
        if (got == 0) {
            return -1;  // Other lcores took them first
        }
    }

    // Store all but one in local cache
    for (unsigned int i = 1; i < got && cache->count < LOCAL_FREE_CACHE_SIZE_V6; i++) {
        cache->indices[cache->count++] = (uint32_t)(uintptr_t)idx_ptrs[i];
    }

    return (int32_t)(uintptr_t)idx_ptrs[0];
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

    // Deleted entries wait for the readers' grace periods (the variable is
    // shared with the IPv4 table and outlives both)
    if (flow_table_readers() == NULL) {
        return -1;
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
    __atomic_store_n(&global_deletes_v6, 0, __ATOMIC_RELAXED);
    aging_iterator_v6 = 0;
    tsc_hz_v6 = rte_get_tsc_hz();

    // Bound what the per-lcore free caches can hold (see cache_refill_batch_v6)
    uint32_t per_cache = config_v6.max_flows / (FREE_CACHE_SHARE_DIV_V6 * MAX_LCORES);
    cache_refill_batch_v6 = (per_cache + 1 < LOCAL_REFILL_BATCH_V6) ? per_cache + 1 : LOCAL_REFILL_BATCH_V6;

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

    // A random seed per table, as in flow_table_init()
    hash_seed_v6 = flow_table_new_hash_seed();

    hash_params.name = name;
    hash_params.entries = config_v6.max_flows;
    hash_params.key_len = sizeof(struct flow_key_v6);
    hash_params.hash_func = flow_key_v6_hash;
    hash_params.hash_func_init_val = hash_seed_v6;
    hash_params.socket_id = socket_id;
    // Readers concurrent with one writer; writers are serialized by
    // flow_hash_v6_wlock. Extendable buckets let every key fit while a key
    // slot is free, so the free entry indices alone set the capacity at
    // max_flows (see the IPv4 table, also for their cost: aging walks the
    // occupancy bitmap rather than rte_hash_iterate(), 15 us per call over a
    // sparse 1M-slot table where iterating took 1.27 ms).
    hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                             RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT |
                             RTE_HASH_EXTRA_FLAGS_EXT_TABLE;

    flow_hash_v6 = rte_hash_create(&hash_params);
    if (!flow_hash_v6) {
        RTE_LOG(ERR, FLOW_V6, "Failed to create hash table\n");
        rte_ring_free(free_index_ring_v6);
        free_index_ring_v6 = NULL;
        rte_free(flow_entries_v6);
        flow_entries_v6 = NULL;
        return -1;
    }

    // Occupancy bitmap and limbo of deleted entries
    flow_used_words_v6 = (config_v6.max_flows + 63) / 64;
    flow_used_v6 = rte_zmalloc_socket("flow_used_v6", (size_t)flow_used_words_v6 * sizeof(uint64_t),
                                      RTE_CACHE_LINE_SIZE, socket_id);
    if (!flow_used_v6 || flow_limbo_init(&limbo_v6, config_v6.max_flows, "flow_limbo_v6") != 0) {
        RTE_LOG(ERR, FLOW_V6, "Failed to allocate the occupancy bitmap or the limbo\n");
        rte_free(flow_used_v6);
        flow_used_v6 = NULL;
        flow_used_words_v6 = 0;
        rte_hash_free(flow_hash_v6);
        flow_hash_v6 = NULL;
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
    flow_limbo_free(&limbo_v6);
    rte_free(flow_used_v6);
    flow_used_v6 = NULL;
    flow_used_words_v6 = 0;

    aging_iterator_v6 = 0;
    initialized_v6 = false;
    RTE_LOG(INFO, FLOW_V6, "IPv6 flow table cleanup complete\n");
}

// ==================== Per-Lcore Stats Helper ====================

static inline struct flow_table_v6_stats* get_flow_v6_lcore_stats(void) {
    unsigned int lcore_id = rte_lcore_id();
    // Non-EAL threads get LCORE_ID_ANY: the shared slot (see NON_EAL_SLOT_V6)
    if (unlikely(lcore_id >= MAX_LCORES)) lcore_id = NON_EAL_SLOT_V6;
    return &lcore_stats_v6[lcore_id];
}

// ==================== Hash Writer Lock ====================

static inline void flow_hash_v6_write_lock(void) {
    rte_spinlock_lock(&flow_hash_v6_wlock);
}

static inline void flow_hash_v6_write_unlock(void) {
    rte_spinlock_unlock(&flow_hash_v6_wlock);
}

// Wait, bounded, for a flow another lcore has just added to be published
// (see flow_wait_published() in flow_table.c)
static inline void flow_v6_wait_published(const struct flow_entry_v6 *flow) {
    uint64_t deadline = 0;

    if (__atomic_load_n(&flow->state, __ATOMIC_ACQUIRE) == FLOW_STATE_INITIALIZING) {
        flow_table_race_seam(FLOW_SEAM_V6_PUBLISH_WAIT);
    }
    while (__atomic_load_n(&flow->state, __ATOMIC_ACQUIRE) == FLOW_STATE_INITIALIZING) {
        uint64_t now = rte_rdtsc();
        if (deadline == 0) {
            deadline = now + (tsc_hz_v6 / 1000000) * FLOW_V6_PUBLISH_WAIT_US;
        } else if (now > deadline) {
            break;
        }
        rte_pause();
    }
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
    FLOW_V6_STAT_INC(lstats, lookups);

    ret = rte_hash_lookup_data(flow_hash_v6, &key, (void **)&flow);
    if (ret >= 0 && flow != NULL) {
        FLOW_V6_STAT_INC(lstats, lookup_hits);
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
    FLOW_V6_STAT_INC(lstats, lookups);

    // Compute hash once
    hash = rte_hash_hash(flow_hash_v6, &key);

    // Fast path: check if flow exists
    ret = rte_hash_lookup_with_hash_data(flow_hash_v6, &key, hash, (void **)&flow);
    if (ret >= 0 && flow != NULL) {
        FLOW_V6_STAT_INC(lstats, lookup_hits);
        rte_prefetch0(flow);
        return flow;
    }

    // Slow path: create new flow
    flow_table_race_seam(FLOW_SEAM_V6_CREATE_MISSED);
    entry_index = flow_entry_v6_alloc();
    if (unlikely(entry_index < 0)) {
        // Emergency eviction before giving up, as in the IPv4 table
        // (flow_table_lookup_or_create()): at most once per 100 ms across
        // lcores, the lcore whose compare-and-swap moves last_evict_tsc_v6
        // runs it (a later clock already stored must not pass the limit),
        // and none while a batch of deleted entries still waits for its
        // grace period. Without it a full IPv6 table refused every new flow.
        static uint64_t evict_attempts_v6 = 0;
        static uint64_t last_evict_tsc_v6 = 0;
        uint64_t evict_now = rte_rdtsc();
        uint64_t min_interval = tsc_hz_v6 / 10;  // 100ms
        uint64_t last_evict = __atomic_load_n(&last_evict_tsc_v6, __ATOMIC_RELAXED);
        if (flow_limbo_waiting(&limbo_v6) < FLOW_EVICT_BATCH_V6 &&
            evict_now > last_evict && evict_now - last_evict > min_interval &&
            __atomic_compare_exchange_n(&last_evict_tsc_v6, &last_evict, evict_now, false,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            __atomic_fetch_add(&evict_attempts_v6, 1, __ATOMIC_RELAXED);
            if (flow_table_v6_emergency_evict(FLOW_EVICT_BATCH_V6) > 0) {
                // Retry; evicted entries pass through the limbo (see IPv4)
                entry_index = flow_entry_v6_alloc();
            }
        }

        if (unlikely(entry_index < 0)) {
            FLOW_V6_STAT_INC(lstats, create_failures);
            static uint64_t log_count = 0;
            if (unlikely(__atomic_fetch_add(&log_count, 1, __ATOMIC_RELAXED) < 10)) {
                RTE_LOG(WARNING, FLOW_V6, "IPv6 flow table full after eviction attempt "
                        "(max %u, evict_attempts=%lu)\n", config_v6.max_flows,
                        (unsigned long)__atomic_load_n(&evict_attempts_v6, __ATOMIC_RELAXED));
            }
            return NULL;
        }
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

    // Add under the writer lock, after looking the key up once more: another
    // lcore may have added it since the lookup above, and rte_hash_add of an
    // existing key replaces its data, orphaning the other lcore's entry
    struct flow_entry_v6 *existing = NULL;
    flow_hash_v6_write_lock();
    ret = rte_hash_lookup_with_hash_data(flow_hash_v6, &key, hash, (void **)&existing);
    if (likely(ret < 0)) {
        ret = rte_hash_add_key_with_hash_data(flow_hash_v6, &key, hash, flow);
        if (likely(ret >= 0)) {
            flow_used_v6_set((uint32_t)entry_index);
        }
    } else {
        ret = -EEXIST;
    }
    flow_hash_v6_write_unlock();

    if (unlikely(ret < 0)) {
        __atomic_store_n(&flow->state, FLOW_STATE_NEW, __ATOMIC_RELEASE);
        memset(flow->key.ip_lo, 0, 16);
        memset(flow->key.ip_hi, 0, 16);
        flow_entry_v6_free((uint32_t)entry_index);

        // Another lcore added this key first: use its flow
        if (ret == -EEXIST && existing != NULL) {
            flow_v6_wait_published(existing);
            return existing;
        }

        FLOW_V6_STAT_INC(lstats, create_failures);
        return NULL;
    }

    // Transition to valid state
    flow_table_race_seam(FLOW_SEAM_V6_CREATE_ADDED);
    __atomic_store_n(&flow->state, FLOW_STATE_NEW, __ATOMIC_RELEASE);

    FLOW_V6_STAT_INC(lstats, creates);
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

// The part of an update every packet gets: the update count, the last-seen
// time and the counters of its direction, plus (with_tcp_flags, a constant
// at each call) the TCP flags seen in that direction
static inline void flow_v6_count_packet_internal(struct flow_entry_v6 *flow,
                                                 const struct packet_features_v6 *features,
                                                 bool with_tcp_flags)
{
    struct flow_table_v6_stats *lstats = get_flow_v6_lcore_stats();
    FLOW_V6_STAT_INC(lstats, updates);

    uint64_t now_tsc = features->timestamp_tsc ? features->timestamp_tsc : rte_rdtsc();
    __atomic_store_n(&flow->last_seen_tsc, now_tsc, __ATOMIC_RELEASE);

    // Update direction-specific counters
    if (features->flow_direction == FLOW_DIR_LO_TO_HI) {
        __atomic_add_fetch(&flow->packets_lo_to_hi, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&flow->bytes_lo_to_hi, features->packet_size, __ATOMIC_RELAXED);
        if (with_tcp_flags && features->protocol == IPPROTO_TCP) {
            __atomic_fetch_or(&flow->tcp_flags_lo_to_hi, features->tcp_flags, __ATOMIC_RELAXED);
        }
    } else {
        __atomic_add_fetch(&flow->packets_hi_to_lo, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&flow->bytes_hi_to_lo, features->packet_size, __ATOMIC_RELAXED);
        if (with_tcp_flags && features->protocol == IPPROTO_TCP) {
            __atomic_fetch_or(&flow->tcp_flags_hi_to_lo, features->tcp_flags, __ATOMIC_RELAXED);
        }
    }
}

void flow_table_v6_count_packet(struct flow_entry_v6 *flow,
                                const struct packet_features_v6 *features)
{
    if (unlikely(!flow || !features)) {
        return;
    }
    // No TCP flags either (see flow_table_count_packet())
    flow_v6_count_packet_internal(flow, features, false);
}

void flow_table_v6_update(struct flow_entry_v6 *flow,
                          const struct packet_features_v6 *features)
{
    if (unlikely(!flow || !features)) {
        return;
    }

    flow_v6_count_packet_internal(flow, features, true);

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
                        // As in the IPv4 table: a real initiator acknowledges
                        // the responder's ISN + 1, its next sequence as
                        // tracked from its SYN-ACK; a blind ACK cannot know
                        // it. The IPv6 eviction protects only such flows.
                        // Set before the state, so that a reader seeing
                        // ESTABLISHED also sees the flag.
                        uint32_t responder_next = (features->flow_direction == FLOW_DIR_LO_TO_HI) ?
                            __atomic_load_n(&flow->seq_hi_to_lo, __ATOMIC_RELAXED) :
                            __atomic_load_n(&flow->seq_lo_to_hi, __ATOMIC_RELAXED);
                        if (features->tcp_ack == responder_next) {
                            __atomic_fetch_or(&flow->flags, FLOW_FLAG_HANDSHAKE_ACKED, __ATOMIC_RELAXED);
                        }
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

    // Reset window after 1 second. Every lcore that sees the flow's packets
    // shares the window, each stamping with its own clock reading: one that
    // read its clock just before another lcore opened the window would see
    // the unsigned difference wrap, and reset the window again.
    if (now_tsc > window_start && window_elapsed >= tsc_hz_v6) {
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
            struct flow_table_v6_stats *lstats = get_flow_v6_lcore_stats();
            FLOW_V6_STAT_INC(lstats, rate_limit_drops);
            return RL_DROP_PPS;
        }
    }

    // Check BPS limit
    if (bps_limit > 0) {
        uint32_t current_bytes = __atomic_load_n(&flow->window_bytes, __ATOMIC_RELAXED);
        if (current_bytes + features->packet_size > bps_limit) {
            __atomic_fetch_or(&flow->flags, FLOW_FLAG_RATE_LIMITED, __ATOMIC_RELAXED);
            struct flow_table_v6_stats *lstats = get_flow_v6_lcore_stats();
            FLOW_V6_STAT_INC(lstats, rate_limit_drops);
            return RL_DROP_BPS;
        }
    }

    // Update counters
    __atomic_add_fetch(&flow->window_packets, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&flow->window_bytes, features->packet_size, __ATOMIC_RELAXED);

    return RL_ACCEPT;
}

// ==================== Flow Aging ====================

// Whether a flow is expired at now_tsc, given the pass's (possibly
// pressure-reduced) timeouts. As flow_age_expired() in flow_table.c.
static bool flow_v6_age_expired(const struct flow_entry_v6 *flow, uint64_t now_tsc,
                                uint64_t timeout_tsc, uint64_t syn_timeout_tsc)
{
    uint64_t last_seen = __atomic_load_n(&flow->last_seen_tsc, __ATOMIC_ACQUIRE);

    // A packet another lcore stamped after this pass read now_tsc is newer
    // than now_tsc: that flow is not idle, and the unsigned difference
    // would wrap to a huge idle time
    if (last_seen >= now_tsc) {
        return false;
    }
    uint64_t idle_time = now_tsc - last_seen;
    uint64_t flow_timeout = timeout_tsc;

    // State-based timeouts for TCP
    if (flow->key.protocol == IPPROTO_TCP) {
        uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_RELAXED);

        switch (state) {
            case FLOW_STATE_NEW:
            case FLOW_STATE_SYN_RECEIVED:
            case FLOW_STATE_SYN_ACK_RECEIVED:
                // A TCP flow still NEW with traffic both ways was first seen
                // mid-stream: an exchange in progress, not a handshake, so
                // it keeps the idle timeout
                if (config_v6.enable_syn_protection &&
                    !(state == FLOW_STATE_NEW && flow_v6_is_bidirectional(flow))) {
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

    return idle_time > flow_timeout;
}

uint32_t flow_table_v6_age_flows(void)
{
    struct flow_key_v6 keys[AGING_BATCH_SIZE];
    uint32_t indices[AGING_BATCH_SIZE];    // Entry holding each key when scanned
    uint32_t freed[AGING_BATCH_SIZE];      // Entries this call deleted
    uint32_t nfreed = 0;
    uint32_t batch_count = 0;
    uint32_t total_aged = 0;
    uint64_t now_tsc = rte_rdtsc();
    uint64_t timeout_tsc = seconds_to_tsc_v6(config_v6.idle_timeout_sec);
    uint64_t syn_timeout_tsc = seconds_to_tsc_v6(config_v6.syn_timeout_sec);
    uint32_t pos = aging_iterator_v6;   // First entry index to look at (resume)
    uint32_t scanned = 0;
    uint32_t words = 0;
    bool pass_done = false;

    if (unlikely(!initialized_v6)) {
        return 0;
    }

    // Entries deleted earlier whose grace period is over go back to the free
    // indices (a create that finds none free takes them back too)
    flow_reclaim_v6(RECLAIM_AGING_MAX_V6);
    flow_limbo_check_stall(&limbo_v6, now_tsc, seconds_to_tsc_v6(LIMBO_STALL_SEC_V6),
                           "IPv6 flow table");

    // Adaptive timeout based on occupancy. Count the flows in the hash:
    // max_flows minus the free ring count would also count the free indices
    // parked in per-lcore caches (up to LOCAL_REFILL_BATCH_V6 - 1 each) as active.
    uint32_t active_count = rte_hash_count(flow_hash_v6);
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

    // Walk the occupancy bitmap from the saved position, as the IPv4 table
    // does: at most scan_limit flows and AGING_WORD_LIMIT_V6 words per call,
    // stopping at a full batch
    while (words < AGING_WORD_LIMIT_V6) {
        uint32_t word = pos >> 6;
        if (word >= flow_used_words_v6) {
            pass_done = true;
            break;
        }
        uint64_t bits = __atomic_load_n(&flow_used_v6[word], __ATOMIC_ACQUIRE);
        bits &= ~0ULL << (pos & 63);     // entries before pos were looked at
        words++;

        bool stop = false;
        while (bits != 0) {
            uint32_t idx = (word << 6) | (uint32_t)__builtin_ctzll(bits);
            bits &= bits - 1;
            if (unlikely(idx >= config_v6.max_flows)) {
                break;
            }
            struct flow_entry_v6 *flow = &flow_entries_v6[idx];
            scanned++;

            if (flow_v6_age_expired(flow, now_tsc, timeout_tsc, syn_timeout_tsc)) {
                // The key and the entry holding it (rechecked under the lock)
                memcpy(&keys[batch_count], &flow->key, sizeof(struct flow_key_v6));
                indices[batch_count] = idx;
                batch_count++;
            }

            if (batch_count >= AGING_BATCH_SIZE || scanned >= scan_limit) {
                pos = idx + 1;
                stop = true;
                break;
            }
        }
        if (stop) {
            break;
        }
        pos = (word + 1) << 6;
    }

    // Save the position for the next call (0 once the pass is complete)
    aging_iterator_v6 = pass_done ? 0 : pos;

    flow_table_race_seam(FLOW_SEAM_V6_AGE);

    // Delete collected flows under the writer lock, each only if its key
    // still maps to the entry the scan saw and that flow is still expired
    // (a packet may have refreshed it since): as in flow_table_age_flows(),
    // a key deleted and created again on another entry is not deleted, and
    // no index is freed twice
    for (uint32_t i = 0; i < batch_count; i++) {
        uint32_t entry_idx = indices[i];
        struct flow_entry_v6 *flow = &flow_entries_v6[entry_idx];
        hash_sig_t sig = rte_hash_hash(flow_hash_v6, &keys[i]);
        void *cur = NULL;
        bool deleted = false;

        flow_hash_v6_write_lock();
        if (rte_hash_lookup_with_hash_data(flow_hash_v6, &keys[i], sig, &cur) >= 0 &&
            cur == flow &&
            flow_v6_age_expired(flow, now_tsc, timeout_tsc, syn_timeout_tsc)) {
            flow_table_race_seam(FLOW_SEAM_V6_AGE_DELETE);
            deleted = rte_hash_del_key_with_hash(flow_hash_v6, &keys[i], sig) >= 0;
            if (deleted) {
                flow_used_v6_clear(entry_idx);
            }
        }
        flow_hash_v6_write_unlock();

        if (deleted) {
            // Out of the hash, but a reader may still hold it: it waits in
            // the limbo for the readers' grace period
            freed[nfreed++] = entry_idx;
            total_aged++;
        }
    }
    flow_retire_v6(freed, nfreed);

    if (total_aged > 0) {
        // Emergency eviction counts here too, from other lcores
        __atomic_fetch_add(&global_deletes_v6, total_aged, __ATOMIC_RELAXED);

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

    // Every per-lcore slot (see lcore_stats_v6), then the shared one
    for (unsigned int lcore_id = 0; lcore_id < MAX_LCORES; lcore_id++) {
        struct flow_table_v6_stats *lstats = &lcore_stats_v6[lcore_id];
        stats->lookups += lstats->lookups;
        stats->lookup_hits += lstats->lookup_hits;
        stats->creates += lstats->creates;
        stats->create_failures += lstats->create_failures;
        stats->updates += lstats->updates;
        stats->rate_limit_drops += lstats->rate_limit_drops;
    }

    const struct flow_table_v6_stats *shared = &lcore_stats_v6[NON_EAL_SLOT_V6];
    stats->lookups += __atomic_load_n(&shared->lookups, __ATOMIC_RELAXED);
    stats->lookup_hits += __atomic_load_n(&shared->lookup_hits, __ATOMIC_RELAXED);
    stats->creates += __atomic_load_n(&shared->creates, __ATOMIC_RELAXED);
    stats->create_failures += __atomic_load_n(&shared->create_failures, __ATOMIC_RELAXED);
    stats->updates += __atomic_load_n(&shared->updates, __ATOMIC_RELAXED);
    stats->rate_limit_drops += __atomic_load_n(&shared->rate_limit_drops, __ATOMIC_RELAXED);

    stats->deletes = __atomic_load_n(&global_deletes_v6, __ATOMIC_RELAXED);
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
            rte_memcpy(&keys[batch_count], key_ptr, sizeof(struct flow_key_v6));
            batch_count++;

            if (batch_count >= 256) {
                break;
            }
        }

        // Free the entry each deleted key mapped to at its delete (under the
        // writer lock), so an index is freed once, by the delete that
        // released it; the freed entries pass through the limbo (see the
        // IPv4 flow_table_clear())
        uint32_t freed[256];
        uint32_t nfreed = 0;
        for (uint32_t i = 0; i < batch_count; i++) {
            void *cur = NULL;
            bool deleted = false;

            flow_hash_v6_write_lock();
            if (rte_hash_lookup_data(flow_hash_v6, &keys[i], &cur) >= 0) {
                flow_table_race_seam(FLOW_SEAM_V6_CLEAR_DELETE);
                deleted = rte_hash_del_key(flow_hash_v6, &keys[i]) >= 0;
            }
            struct flow_entry_v6 *flow = (struct flow_entry_v6 *)cur;
            bool own = deleted && flow >= flow_entries_v6 && flow < &flow_entries_v6[config_v6.max_flows];
            if (own) {
                flow_used_v6_clear((uint32_t)(flow - flow_entries_v6));
            }
            flow_hash_v6_write_unlock();

            if (own) {
                freed[nfreed++] = (uint32_t)(flow - flow_entries_v6);
            }
        }
        flow_retire_v6(freed, nfreed);
    } while (batch_count > 0);

    // Take back at once what no reader can hold any more
    while (flow_reclaim_v6(RECLAIM_AGING_MAX_V6) > 0) {
    }

    memset(lcore_stats_v6, 0, sizeof(lcore_stats_v6));
    __atomic_store_n(&global_deletes_v6, 0, __ATOMIC_RELAXED);

    RTE_LOG(INFO, FLOW_V6, "IPv6 flow table cleared\n");
}

// ==================== Emergency Eviction ====================

// Eviction priority of an IPv6 flow (lower is evicted first): the IPv4
// table's score (flow_eviction_score()), from the same fields
static int32_t calculate_eviction_priority_v6(const struct flow_entry_v6 *flow, uint64_t now_tsc)
{
    uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_RELAXED);
    uint64_t pkts_lo = __atomic_load_n(&flow->packets_lo_to_hi, __ATOMIC_RELAXED);
    uint64_t pkts_hi = __atomic_load_n(&flow->packets_hi_to_lo, __ATOMIC_RELAXED);

    return flow_eviction_score(state, flow->key.protocol, pkts_lo, pkts_hi,
                               flow->first_seen_tsc, flow->reputation_score,
                               now_tsc, tsc_hz_v6);
}

// Flows the IPv6 eviction never chooses, as flow_evict_protected() in
// flow_table.c: ESTABLISHED TCP flows with traffic both ways whose handshake
// ACK acknowledged the responder's ISN + 1 (a blind ACK cannot)
static inline bool flow_v6_evict_protected(const struct flow_entry_v6 *flow, uint8_t state)
{
    return state == FLOW_STATE_ESTABLISHED &&
           (__atomic_load_n(&flow->flags, __ATOMIC_RELAXED) & FLOW_FLAG_HANDSHAKE_ACKED) &&
           flow_v6_is_bidirectional(flow);
}

// Limits of one pass, as in the IPv4 table: flows scanned, and candidates
// kept (and so deleted at most)
#define EVICT_MAX_SCAN_V6        10000
#define EVICT_MAX_CANDIDATES_V6  1024

struct eviction_candidate_v6 {
    struct flow_key_v6 key;
    uint32_t entry_index;
    int32_t priority;
};

// Lowest priority first
static int compare_eviction_candidates_v6(const void *a, const void *b)
{
    const struct eviction_candidate_v6 *ca = (const struct eviction_candidate_v6 *)a;
    const struct eviction_candidate_v6 *cb = (const struct eviction_candidate_v6 *)b;
    return ca->priority - cb->priority;
}

uint32_t flow_table_v6_emergency_evict(uint32_t count_needed)
{
    if (!initialized_v6 || count_needed == 0) {
        return 0;
    }

    uint64_t now_tsc = rte_rdtsc();
    uint32_t iter = 0;
    const struct flow_key_v6 *key_ptr;
    void *data;
    uint32_t scanned = 0;

    struct eviction_candidate_v6 *candidates = rte_malloc("evict_candidates_v6",
        EVICT_MAX_CANDIDATES_V6 * sizeof(struct eviction_candidate_v6), RTE_CACHE_LINE_SIZE);
    if (!candidates) {
        RTE_LOG(ERR, FLOW_V6, "Failed to allocate eviction candidate buffer\n");
        return 0;
    }

    uint32_t candidate_count = 0;
    // Index of the highest (worst) priority in the buffer, which is not
    // sorted before Phase 2
    uint32_t worst_idx = 0;

    // Phase 1: collect the EVICT_MAX_CANDIDATES_V6 lowest priorities among
    // unprotected flows
    while (rte_hash_iterate(flow_hash_v6, (const void **)&key_ptr, &data, &iter) >= 0) {
        scanned++;
        if (scanned > EVICT_MAX_SCAN_V6) {
            break;
        }

        struct flow_entry_v6 *flow = (struct flow_entry_v6 *)data;
        if (unlikely(flow < flow_entries_v6 || flow >= &flow_entries_v6[config_v6.max_flows])) {
            continue;
        }

        // Skip flows being initialized (or claimed by another eviction)
        uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
        if (state == FLOW_STATE_INITIALIZING) {
            continue;
        }

        // Never evict protected flows: count_needed is a batch size, not a
        // quota to fill from them; aging still expires them
        if (flow_v6_evict_protected(flow, state)) {
            continue;
        }

        int32_t priority = calculate_eviction_priority_v6(flow, now_tsc);
        // The entry from the pointer, not from a field of an entry another
        // lcore may be recycling
        uint32_t idx = (uint32_t)(flow - flow_entries_v6);

        if (candidate_count < EVICT_MAX_CANDIDATES_V6) {
            rte_memcpy(&candidates[candidate_count].key, key_ptr, sizeof(struct flow_key_v6));
            candidates[candidate_count].entry_index = idx;
            candidates[candidate_count].priority = priority;
            if (priority > candidates[worst_idx].priority) {
                worst_idx = candidate_count;
            }
            candidate_count++;
        } else if (priority < candidates[worst_idx].priority) {
            rte_memcpy(&candidates[worst_idx].key, key_ptr, sizeof(struct flow_key_v6));
            candidates[worst_idx].entry_index = idx;
            candidates[worst_idx].priority = priority;
            worst_idx = 0;
            for (uint32_t i = 1; i < EVICT_MAX_CANDIDATES_V6; i++) {
                if (candidates[i].priority > candidates[worst_idx].priority) {
                    worst_idx = i;
                }
            }
        }
    }

    if (candidate_count == 0) {
        rte_free(candidates);
        return 0;
    }

    // Phase 2: lowest priority first
    qsort(candidates, candidate_count, sizeof(struct eviction_candidate_v6),
          compare_eviction_candidates_v6);

    flow_table_race_seam(FLOW_SEAM_V6_EVICT);

    // Phase 3: delete, each flow checked again as in the IPv4 table. Under
    // the writer lock no other writer runs: delete only if the key still
    // maps to the scanned entry and that flow is still evictable, and claim
    // it (a compare-and-swap of the state just checked) so that a handshake
    // completing in between keeps it.
    uint32_t evicted = 0;
    uint32_t to_evict = (count_needed < candidate_count) ? count_needed : candidate_count;
    uint32_t freed[EVICT_MAX_CANDIDATES_V6];   // The entries this call deleted

    for (uint32_t i = 0; i < to_evict; i++) {
        uint32_t idx = candidates[i].entry_index;
        struct flow_entry_v6 *entry = &flow_entries_v6[idx];
        hash_sig_t sig = rte_hash_hash(flow_hash_v6, &candidates[i].key);
        void *cur = NULL;
        bool deleted = false;

        flow_hash_v6_write_lock();
        if (rte_hash_lookup_with_hash_data(flow_hash_v6, &candidates[i].key, sig, &cur) >= 0 &&
            cur == entry) {
            uint8_t state = __atomic_load_n(&entry->state, __ATOMIC_ACQUIRE);
            if (state != FLOW_STATE_INITIALIZING && !flow_v6_evict_protected(entry, state)) {
                flow_table_race_seam(FLOW_SEAM_V6_EVICT_CLAIM);
                if (__atomic_compare_exchange_n(&entry->state, &state, FLOW_STATE_INITIALIZING,
                                                false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                    deleted = rte_hash_del_key_with_hash(flow_hash_v6, &candidates[i].key, sig) >= 0;
                    if (likely(deleted)) {
                        flow_used_v6_clear(idx);
                    } else {
                        // Not reachable while every writer holds the lock:
                        // undo the claim rather than strand the flow
                        __atomic_store_n(&entry->state, state, __ATOMIC_RELEASE);
                    }
                }
            }
        }
        flow_hash_v6_write_unlock();

        if (deleted) {
            // Out of the hash, but a reader may still hold it: it waits in
            // the limbo for the readers' grace period
            freed[evicted++] = idx;
        }
    }
    flow_retire_v6(freed, evicted);

    rte_free(candidates);

    if (evicted > 0) {
        __atomic_fetch_add(&global_deletes_v6, evicted, __ATOMIC_RELAXED);
        RTE_LOG(NOTICE, FLOW_V6, "Emergency eviction: evicted %u IPv6 flows (needed %u, scanned %u)\n",
                evicted, count_needed, scanned);
    }

    return evicted;
}

// ==================== Diagnostics ====================

uint32_t flow_table_v6_get_hash_seed(void)
{
    return hash_seed_v6;
}

bool flow_table_v6_writer_lock_held(void)
{
    return rte_spinlock_is_locked(&flow_hash_v6_wlock) != 0;
}

uint32_t flow_table_v6_limbo_count(void)
{
    return initialized_v6 ? flow_limbo_waiting(&limbo_v6) : 0;
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

    // Only TCP RST/FIN segments are validated (and looked up)
    if (features->protocol != IPPROTO_TCP ||
        !(features->tcp_flags & (TCP_FLAG_RST | TCP_FLAG_FIN))) {
        return RST_FIN_VALID;
    }

    // Lookup the flow (sets features->flow_direction)
    return flow_table_v6_validate_rst_fin_flow(flow_table_v6_lookup(features), features);
}

enum rst_fin_validation_result flow_table_v6_validate_rst_fin_flow(
    struct flow_entry_v6 *flow, const struct packet_features_v6 *features)
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

    // Non-EAL threads: the shared slot (see NON_EAL_SLOT_V6)
    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= MAX_LCORES) lcore_id = NON_EAL_SLOT_V6;
    struct rst_fin_lcore_stats_v6 *rstats = &rst_fin_stats_v6[lcore_id];

    if (!flow) {
        RST_FIN_V6_STAT_INC(rstats, invalid_no_flow);
        return RST_FIN_NO_FLOW;
    }

    uint8_t flow_flags = __atomic_load_n(&flow->flags, __ATOMIC_RELAXED);

    if (!(flow_flags & FLOW_FLAG_SEQ_TRACKING_ENABLED)) {
        RST_FIN_V6_STAT_INC(rstats, valid_count);
        return RST_FIN_VALID;
    }

    uint32_t expected_seq;
    uint32_t last_ack;
    uint8_t peer_flags;  // TCP flags seen so far from the other side

    if (features->flow_direction == FLOW_DIR_LO_TO_HI) {
        expected_seq = __atomic_load_n(&flow->seq_lo_to_hi, __ATOMIC_RELAXED);
        last_ack = __atomic_load_n(&flow->ack_hi_to_lo, __ATOMIC_RELAXED);
        peer_flags = __atomic_load_n(&flow->tcp_flags_hi_to_lo, __ATOMIC_RELAXED);
    } else {
        expected_seq = __atomic_load_n(&flow->seq_hi_to_lo, __ATOMIC_RELAXED);
        last_ack = __atomic_load_n(&flow->ack_lo_to_hi, __ATOMIC_RELAXED);
        peer_flags = __atomic_load_n(&flow->tcp_flags_lo_to_hi, __ATOMIC_RELAXED);
    }

    if (flags & TCP_FLAG_RST) {
        bool seq_ok = seq_in_window_v6(features->tcp_seq, expected_seq, RST_FIN_SEQ_WINDOW_V6);
        // last_ack is an ACK only once the peer has sent a segment with ACK
        // set. Before that it is 0 (no reply yet) or the unused ack field of
        // a segment without ACK (a SYN), and a window around it would accept
        // any sequence near that value.
        bool ack_ok = (peer_flags & TCP_FLAG_ACK) &&
                      seq_in_window_v6(features->tcp_seq, last_ack, RST_FIN_SEQ_WINDOW_V6);

        if (!seq_ok && !ack_ok) {
            RST_FIN_V6_STAT_INC(rstats, invalid_seq);
            return RST_FIN_SEQ_OUT_OF_WINDOW;
        }
    }

    if (flags & TCP_FLAG_FIN) {
        if (!seq_in_window_v6(features->tcp_seq, expected_seq, RST_FIN_SEQ_WINDOW_V6)) {
            RST_FIN_V6_STAT_INC(rstats, invalid_seq);
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
                RST_FIN_V6_STAT_INC(rstats, invalid_state);
                return RST_FIN_UNEXPECTED_STATE;

            default:
                break;
        }
    }

    RST_FIN_V6_STAT_INC(rstats, valid_count);
    return RST_FIN_VALID;
}
