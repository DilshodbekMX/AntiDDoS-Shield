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
#include <rte_pause.h>
#include <rte_spinlock.h>
#include <rte_random.h>
#include <rte_rcu_qsbr.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/random.h>

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

// Every writer of flow_hash (each add and each delete, from any lcore or
// thread) holds this lock; readers (lookups, iteration) do not take it.
// RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY makes readers safe against one writer
// at a time, not writers against each other: an add takes its key slot from
// a single-consumer ring after dropping the hash's own lock, so two
// concurrent adds could get the same slot, and one key would then be lost or
// map to the other's flow. RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD is not used:
// its per-lcore slot cache is indexed by rte_lcore_id(), which faults on the
// non-EAL threads (LCORE_ID_ANY) this table serves. A spinlock rather than
// a ticket lock: a ticket lock hands the lock over in arrival order, so a
// waiter that is not running (a preempted non-EAL thread, an oversubscribed
// or virtualized CPU) stalls every writer queued behind it; a spinlock is
// held up only by a holder that is not running.
static rte_spinlock_t flow_hash_wlock = RTE_SPINLOCK_INITIALIZER;

// Longest wait for a flow another lcore has just added to leave
// FLOW_STATE_INITIALIZING (it is published right after the add)
#define FLOW_PUBLISH_WAIT_US  50

// Non-EAL threads (LCORE_ID_ANY) own no per-lcore slot. They share the extra
// stats slot at NON_EAL_SLOT and update it atomically, so they race neither
// lcore 0's plain counters nor each other.
#define NON_EAL_SLOT          MAX_LCORES

// Per-lcore statistics - NO ATOMICS in fast path
//
// STATS_EVERY_SLOT: the getters sum all MAX_LCORES + 1 slots. Threads
// registered with rte_thread_register() get lcore ids of role
// ROLE_NON_EAL, which RTE_LCORE_FOREACH skips, so their counts never reached
// the totals; init zeroes every slot, so unused ones add nothing, and a slot
// keeps its counts after its thread unregisters.
static struct flow_table_lcore_stats lcore_stats[MAX_LCORES + 1] __rte_cache_aligned;

// Per-lcore RST/FIN validation stats
struct rst_fin_lcore_stats {
    uint64_t valid_count;
    uint64_t invalid_seq;
    uint64_t invalid_no_flow;
    uint64_t invalid_state;
    uint64_t _pad[4];
} __rte_cache_aligned;
static struct rst_fin_lcore_stats rst_fin_stats[MAX_LCORES + 1] __rte_cache_aligned;

// Count one event: a plain increment in an lcore's own slot, an atomic one
// in the slot non-EAL threads share
#define SLOT_STAT_INC(shared, counter) do {                     \
    if (unlikely(shared)) {                                     \
        __atomic_fetch_add(&(counter), 1, __ATOMIC_RELAXED);    \
    } else {                                                    \
        (counter)++;                                            \
    }                                                           \
} while (0)
#define FLOW_STAT_INC(lstats, field) \
    SLOT_STAT_INC((lstats) == &lcore_stats[NON_EAL_SLOT], (lstats)->field)
#define RST_FIN_STAT_INC(rstats, field) \
    SLOT_STAT_INC((rstats) == &rst_fin_stats[NON_EAL_SLOT], (rstats)->field)

// Flows deleted by aging (main lcore) and emergency eviction (any lcore):
// updated and read atomically
static uint64_t global_deletes = 0;

// Incremental aging to avoid O(n) full table scan each call: the entry index
// (a position in flow_used) the next call starts at, and limits per call
// (init and cleanup reset it: a position saved in one table means nothing in the next)
static uint32_t aging_iterator = 0;

// Occupancy bitmap: bit i is set while entry i holds a flow in the hash. The
// create that adds a flow sets it and the delete that removes one clears it,
// both under flow_hash_wlock; aging reads it without the lock. Aging walks
// this bitmap instead of the hash: rte_hash_iterate() steps through every
// position of the main and extendable buckets, and skips the empty ones
// inside a single call, so one aging call over a sparse table walked them
// all and nothing bounded it. A bitmap word covers 64 entries, and one call
// reads at most AGING_WORD_LIMIT words.
static uint64_t *flow_used = NULL;
static uint32_t flow_used_words = 0;
#define AGING_WORD_LIMIT       65536    // 4M entries (512 KB of bitmap) per call

// Seed of flow_hash's hash function (see flow_table_hash_seed_seam())
static uint32_t hash_seed = 0;

// Deleted entries waiting for their grace period (see "Deferred
// Reclamation" in flow_table.h)
static struct flow_limbo limbo;

// Most indices one call takes back from the limbo: a create that found no
// free index (on the packet path) and an aging pass (main lcore)
#define RECLAIM_CREATE_MAX     64
#define RECLAIM_AGING_MAX      65536
// The emergency eviction's batch. While at least this many deleted entries
// wait for their grace period, a create that finds no free index does not
// evict (see lookup_or_create).
#define FLOW_EVICT_BATCH       256
// The oldest deleted entry has waited this long: a registered reader has
// stopped reporting quiescent states
#define LIMBO_STALL_SEC        2

// ==================== Helper Functions ====================

static inline uint64_t seconds_to_tsc(uint32_t seconds) {
    return (uint64_t)seconds * tsc_hz;
}

static inline void flow_used_set(uint32_t idx) {
    __atomic_fetch_or(&flow_used[idx >> 6], 1ULL << (idx & 63), __ATOMIC_RELEASE);
}

static inline void flow_used_clear(uint32_t idx) {
    __atomic_fetch_and(&flow_used[idx >> 6], ~(1ULL << (idx & 63)), __ATOMIC_RELEASE);
}

// ==================== Deferred Reclamation (both tables) ====================

// Quiescent-state variable of every flow table reader (see flow_table_readers())
static struct rte_rcu_qsbr *flow_readers_qsv = NULL;
static rte_spinlock_t flow_readers_qsv_lock = RTE_SPINLOCK_INITIALIZER;

struct rte_rcu_qsbr *flow_table_readers(void) {
    struct rte_rcu_qsbr *v = __atomic_load_n(&flow_readers_qsv, __ATOMIC_ACQUIRE);
    if (likely(v != NULL)) {
        return v;
    }

    rte_spinlock_lock(&flow_readers_qsv_lock);
    v = __atomic_load_n(&flow_readers_qsv, __ATOMIC_RELAXED);
    if (v == NULL) {
        size_t size = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
        v = rte_zmalloc("flow_readers", size, RTE_CACHE_LINE_SIZE);
        if (v != NULL && rte_rcu_qsbr_init(v, RTE_MAX_LCORE) != 0) {
            rte_free(v);
            v = NULL;
        }
        if (v != NULL) {
            __atomic_store_n(&flow_readers_qsv, v, __ATOMIC_RELEASE);
        } else {
            RTE_LOG(ERR, FLOWTBL, "Failed to create the flow readers' quiescent-state variable\n");
        }
    }
    rte_spinlock_unlock(&flow_readers_qsv_lock);
    return v;
}

int flow_table_reader_register(unsigned int reader_id) {
    if (reader_id >= RTE_MAX_LCORE) {
        return -1;
    }
    struct rte_rcu_qsbr *v = flow_table_readers();
    if (v == NULL || rte_rcu_qsbr_thread_register(v, reader_id) != 0) {
        return -1;
    }
    rte_rcu_qsbr_thread_online(v, reader_id);
    return 0;
}

void flow_table_reader_unregister(unsigned int reader_id) {
    struct rte_rcu_qsbr *v = __atomic_load_n(&flow_readers_qsv, __ATOMIC_ACQUIRE);
    if (v == NULL || reader_id >= RTE_MAX_LCORE) {
        return;
    }
    rte_rcu_qsbr_thread_offline(v, reader_id);
    rte_rcu_qsbr_thread_unregister(v, reader_id);
}

void flow_table_reader_quiescent(unsigned int reader_id) {
    struct rte_rcu_qsbr *v = __atomic_load_n(&flow_readers_qsv, __ATOMIC_ACQUIRE);
    if (likely(v != NULL && reader_id < RTE_MAX_LCORE)) {
        rte_rcu_qsbr_quiescent(v, reader_id);
    }
}

int flow_limbo_init(struct flow_limbo *l, uint32_t capacity, const char *name) {
    memset(l, 0, sizeof(*l));
    rte_spinlock_init(&l->lock);
    l->idx = rte_malloc(name, (size_t)capacity * sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
    if (l->idx == NULL) {
        return -1;
    }
    l->capacity = capacity;
    return 0;
}

void flow_limbo_free(struct flow_limbo *l) {
    rte_free(l->idx);
    memset(l, 0, sizeof(*l));
    rte_spinlock_init(&l->lock);
}

uint32_t flow_limbo_push(struct flow_limbo *l, const uint32_t *idx, uint32_t n) {
    struct rte_rcu_qsbr *v = flow_table_readers();
    uint64_t now = rte_rdtsc();

    if (n == 0 || v == NULL || l->idx == NULL) {
        return n;
    }

    rte_spinlock_lock(&l->lock);
    uint32_t room = l->capacity - l->count;
    uint32_t take = (n < room) ? n : room;
    if (take > 0) {
        // The token is taken after the caller's deletes: a reader that has
        // reported a quiescent state with it, or a later one, holds none of
        // these entries. Taken under the lock, tokens grow in batch order.
        uint64_t token = rte_rcu_qsbr_start(v);
        uint32_t tail = l->head + l->count;
        if (tail >= l->capacity) {
            tail -= l->capacity;
        }
        uint32_t first_part = l->capacity - tail;
        if (first_part > take) {
            first_part = take;
        }
        memcpy(&l->idx[tail], idx, first_part * sizeof(uint32_t));
        memcpy(&l->idx[0], idx + first_part, (take - first_part) * sizeof(uint32_t));
        __atomic_store_n(&l->count, l->count + take, __ATOMIC_RELAXED);

        struct flow_limbo_batch *b;
        if (l->nb < FLOW_LIMBO_BATCHES) {
            uint32_t slot = l->first + l->nb;
            if (slot >= FLOW_LIMBO_BATCHES) {
                slot -= FLOW_LIMBO_BATCHES;
            }
            b = &l->batch[slot];
            b->count = 0;
            b->since_tsc = now;
            l->nb++;
        } else {
            // Every batch is in use: join the newest, which then waits for
            // this later token
            uint32_t slot = l->first + l->nb - 1;
            if (slot >= FLOW_LIMBO_BATCHES) {
                slot -= FLOW_LIMBO_BATCHES;
            }
            b = &l->batch[slot];
        }
        b->count += take;
        b->token = token;
    }
    rte_spinlock_unlock(&l->lock);
    return n - take;
}

uint32_t flow_limbo_take(struct flow_limbo *l, uint32_t *out, uint32_t max) {
    if (max == 0 || __atomic_load_n(&l->count, __ATOMIC_RELAXED) == 0) {
        return 0;
    }
    struct rte_rcu_qsbr *v = flow_table_readers();
    if (v == NULL) {
        return 0;
    }

    uint32_t n = 0;
    rte_spinlock_lock(&l->lock);
    while (n < max && l->nb > 0) {
        struct flow_limbo_batch *b = &l->batch[l->first];
        // Non-blocking: a batch some reader may still hold stays, and so do
        // the later ones
        if (rte_rcu_qsbr_check(v, b->token, false) != 1) {
            break;
        }
        uint32_t k = (b->count < max - n) ? b->count : max - n;
        uint32_t first_part = l->capacity - l->head;
        if (first_part > k) {
            first_part = k;
        }
        memcpy(&out[n], &l->idx[l->head], first_part * sizeof(uint32_t));
        memcpy(&out[n + first_part], &l->idx[0], (k - first_part) * sizeof(uint32_t));
        l->head += k;
        if (l->head >= l->capacity) {
            l->head -= l->capacity;
        }
        __atomic_store_n(&l->count, l->count - k, __ATOMIC_RELAXED);
        b->count -= k;
        n += k;
        if (b->count == 0) {
            l->first = (l->first + 1 == FLOW_LIMBO_BATCHES) ? 0 : l->first + 1;
            l->nb--;
        }
    }
    rte_spinlock_unlock(&l->lock);
    return n;
}

uint32_t flow_limbo_waiting(const struct flow_limbo *l) {
    return __atomic_load_n(&l->count, __ATOMIC_RELAXED);
}

void flow_limbo_check_stall(struct flow_limbo *l, uint64_t now_tsc, uint64_t stall_tsc,
                            const char *table) {
    if (flow_limbo_waiting(l) == 0) {
        return;
    }
    struct rte_rcu_qsbr *v = flow_table_readers();
    if (v == NULL) {
        return;
    }

    uint64_t log_interval = 60 * rte_get_tsc_hz();
    uint64_t waited = 0;
    uint32_t waiting = 0;
    bool stalled = false;

    rte_spinlock_lock(&l->lock);
    if (l->nb > 0) {
        const struct flow_limbo_batch *b = &l->batch[l->first];
        if (now_tsc > b->since_tsc && now_tsc - b->since_tsc > stall_tsc &&
            rte_rcu_qsbr_check(v, b->token, false) != 1 &&
            (l->last_stall_log_tsc == 0 || now_tsc - l->last_stall_log_tsc > log_interval)) {
            stalled = true;
            waited = now_tsc - b->since_tsc;
            waiting = l->count;
            l->last_stall_log_tsc = now_tsc;
        }
    }
    rte_spinlock_unlock(&l->lock);

    if (stalled) {
        RTE_LOG(WARNING, FLOWTBL,
                "%s: %u deleted flow entries wait for a quiescent report (oldest %lu ms): "
                "a registered reader has stopped reporting, and they are not reused\n",
                table, waiting, (unsigned long)(waited * 1000 / rte_get_tsc_hz()));
    }
}

// Test seam (see flow_table.h): this weak default sets no seed
__attribute__((weak)) bool flow_table_hash_seed_seam(uint32_t *seed) {
    (void)seed;
    return false;
}

// Test seam (see flow_table.h): this weak default does nothing
__attribute__((weak)) void flow_table_race_seam(enum flow_table_seam_point point) {
    (void)point;
}

uint32_t flow_table_new_hash_seed(void) {
    uint32_t seed;
    if (flow_table_hash_seed_seam(&seed)) {
        return seed;
    }
    if (getrandom(&seed, sizeof(seed), GRND_NONBLOCK) == (ssize_t)sizeof(seed)) {
        return seed;
    }
    return (uint32_t)rte_rand();
}

uint32_t flow_table_get_hash_seed(void) {
    return hash_seed;
}

bool flow_table_writer_lock_held(void) {
    return rte_spinlock_is_locked(&flow_hash_wlock) != 0;
}

uint32_t flow_table_limbo_count(void) {
    return initialized ? flow_limbo_waiting(&limbo) : 0;
}

// Return an index nobody can reach any more to the free ring. The ring holds
// more slots than the table has entries, so it always takes it.
static inline void flow_entry_free(uint32_t index);

/**
 * Take back up to max deleted entries whose grace period is over, oldest
 * first, and return their indices to the free ring. An entry is cleared when
 * a create takes it (no reader can reach it from now on).
 *
 * @return number of indices returned
 */
static uint32_t flow_reclaim(uint32_t max) {
    uint32_t idx[256];
    void *objs[256];
    uint32_t total = 0;

    while (total < max) {
        uint32_t want = (max - total < RTE_DIM(idx)) ? max - total : (uint32_t)RTE_DIM(idx);
        uint32_t n = flow_limbo_take(&limbo, idx, want);
        for (uint32_t i = 0; i < n; i++) {
            objs[i] = (void *)(uintptr_t)idx[i];
        }
        if (n > 0 && rte_ring_mp_enqueue_burst(free_index_ring, objs, n, NULL) != n) {
            RTE_LOG(ERR, FLOWTBL, "Free index ring refused reclaimed indices\n");
        }
        total += n;
        if (n < want) {
            break;
        }
    }
    return total;
}

/**
 * Hand the n entries a delete pass removed from the hash to the limbo.
 */
static void flow_retire(const uint32_t *idx, uint32_t n) {
    uint32_t refused = flow_limbo_push(&limbo, idx, n);
    if (unlikely(refused > 0)) {
        // Not reachable while an index is in one place at a time: free them
        // at once rather than leak them
        RTE_LOG(ERR, FLOWTBL, "Limbo refused %u deleted entries, freed at once\n", refused);
        for (uint32_t i = n - refused; i < n; i++) {
            flow_entry_free(idx[i]);
        }
    }
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
#define FREE_CACHE_SHARE_DIV   64   // All caches together hold at most max_flows / 64

struct lcore_free_cache {
    uint32_t indices[LOCAL_FREE_CACHE_SIZE];
    uint32_t count;
    uint32_t _pad[14];  // Pad to cache line
} __rte_cache_aligned;

static struct lcore_free_cache lcore_free_caches[MAX_LCORES];

// How many indices one refill takes from the ring (set by flow_table_init()).
// Each cache has a single owner, so an allocation that finds its own cache
// and the ring empty fails while other lcores' caches may still hold free
// indices. Up to MAX_LCORES caches can each keep refill - 1 of them; init
// sizes the refill so that together they hold at most
// max_flows / FREE_CACHE_SHARE_DIV. Below FREE_CACHE_SHARE_DIV * MAX_LCORES
// flows (16384 with 256 lcores) a refill takes one index and caches none, so
// allocation fails only when the table is full.
static uint32_t cache_refill_batch = LOCAL_REFILL_BATCH;

/**
 * Allocate a flow entry index from per-lcore cache (fast path)
 * or global ring (slow path). An empty ring first takes back deleted
 * entries whose grace period is over (flow_reclaim()), without waiting.
 *
 * @return Index into flow_entries, or -1 if none available
 */
static inline int32_t flow_entry_alloc(void) {
    unsigned int lcore_id = rte_lcore_id();

    // Non-EAL threads (LCORE_ID_ANY) own no cache. Sharing lcore 0's, whose
    // count is a plain field, let them and lcore 0 hand out the same index,
    // so they take one index straight from the multi-consumer ring.
    if (unlikely(lcore_id >= MAX_LCORES)) {
        void *idx_ptr = NULL;
        if (rte_ring_mc_dequeue(free_index_ring, &idx_ptr) != 0 &&
            (flow_reclaim(RECLAIM_CREATE_MAX) == 0 ||
             rte_ring_mc_dequeue(free_index_ring, &idx_ptr) != 0)) {
            return -1;  // Ring empty
        }
        return (int32_t)(uintptr_t)idx_ptr;
    }

    struct lcore_free_cache *cache = &lcore_free_caches[lcore_id];

    // Fast path: get from local cache
    if (likely(cache->count > 0)) {
        return (int32_t)cache->indices[--cache->count];
    }

    // Calculate how many we can actually store in local cache
    // to prevent buffer overflow if cache->count is unexpectedly high
    uint32_t available_space = LOCAL_FREE_CACHE_SIZE - cache->count;
    uint32_t refill_count = (available_space > cache_refill_batch) ? cache_refill_batch : available_space;

    // Slow path: refill from global ring (an empty one first takes back
    // deleted entries past their grace period)
    void *idx_ptrs[LOCAL_REFILL_BATCH];
    unsigned int got = rte_ring_mc_dequeue_burst(free_index_ring, idx_ptrs,
                                                  refill_count, NULL);
    if (unlikely(got == 0)) {
        if (flow_reclaim(RECLAIM_CREATE_MAX) == 0) {
            return -1;  // Ring empty
        }
        got = rte_ring_mc_dequeue_burst(free_index_ring, idx_ptrs, refill_count, NULL);
        if (got == 0) {
            return -1;  // Other lcores took them first
        }
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
    uint32_t allocated = 0;

    // First, drain local cache (non-EAL threads own none: ring only, as in
    // flow_entry_alloc())
    if (likely(lcore_id < MAX_LCORES)) {
        struct lcore_free_cache *cache = &lcore_free_caches[lcore_id];
        while (cache->count > 0 && allocated < count) {
            indices[allocated++] = (int32_t)cache->indices[--cache->count];
        }
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
 * Return a flow entry index to global ring at once. Only for an entry no
 * reader can hold: one a create took and never added to the hash. An entry
 * deleted from the hash goes through the limbo (flow_retire()).
 *
 * @param index  Index to return
 */
static inline void flow_entry_free(uint32_t index) {
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

    // Deleted entries wait for the readers' grace periods (the variable is
    // shared with the IPv6 table and outlives both)
    if (flow_table_readers() == NULL) {
        return -1;
    }

    memcpy(&config, cfg, sizeof(config));
    // Clear per-lcore stats
    memset(lcore_stats, 0, sizeof(lcore_stats));
    memset(rst_fin_stats, 0, sizeof(rst_fin_stats));  // RST/FIN validation stats
    global_deletes = 0;
    aging_iterator = 0;
    tsc_hz = rte_get_tsc_hz();

    // Bound what the per-lcore free caches can hold (see cache_refill_batch)
    uint32_t per_cache = config.max_flows / (FREE_CACHE_SHARE_DIV * MAX_LCORES);
    cache_refill_batch = (per_cache + 1 < LOCAL_REFILL_BATCH) ? per_cache + 1 : LOCAL_REFILL_BATCH;

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

    // A random seed per table: with a fixed one (it was 0) a sender could
    // choose keys that share buckets, and the extendable buckets below chain
    // such keys instead of refusing them
    hash_seed = flow_table_new_hash_seed();

    hash_params.name = name;
    hash_params.entries = config.max_flows;
    hash_params.key_len = sizeof(struct flow_key);
    hash_params.hash_func = rte_jhash;
    hash_params.hash_func_init_val = hash_seed;
    hash_params.socket_id = socket_id;
    // Readers concurrent with one writer; writers are serialized by
    // flow_hash_wlock. Without extendable buckets the cuckoo table refuses
    // a key once its two candidate buckets are full, short of max_flows
    // (a 4096-slot table took 4083 of 4096 sequential keys); with them every
    // key fits while a key slot is free, and each flow holds one entry
    // index, so the free entry indices alone set the capacity at max_flows.
    // A create then fails only when its lcore finds the free ring and its
    // own cache empty (see cache_refill_batch), and that runs the emergency
    // eviction.
    // Cost of the extendable buckets: about 8 MB per 1M flows, and every
    // rte_hash_iterate() pass also walks their positions, twice
    // rte_align32pow2(max_flows) positions in all, empty or not, skipping the
    // empty ones inside one call. Measured with 1000 flows (-O3, 4 KB
    // pages): one aging call that iterated the hash took 1.27 ms over a
    // sparse 1M-slot table (0.75 ms without the extendable buckets) and
    // 2.54 ms over 2M slots (1.49 ms), on the main lcore between its RX
    // polls. Aging therefore walks the occupancy bitmap (flow_used), at most
    // AGING_WORD_LIMIT words per call: 15 us over 1M slots, 30 us over 2M.
    // The emergency eviction's scan (on a full table, where positions are
    // dense), clear and dump still iterate the hash.
    hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                             RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT |
                             RTE_HASH_EXTRA_FLAGS_EXT_TABLE;

    flow_hash = rte_hash_create(&hash_params);
    if (!flow_hash) {
        RTE_LOG(ERR, FLOWTBL, "Failed to create hash table\n");
        rte_ring_free(free_index_ring);
        free_index_ring = NULL;
        rte_free(flow_entries);
        flow_entries = NULL;
        return -1;
    }

    // ========== 4. Occupancy bitmap and limbo of deleted entries ==========
    flow_used_words = (config.max_flows + 63) / 64;
    flow_used = rte_zmalloc_socket("flow_used", (size_t)flow_used_words * sizeof(uint64_t),
                                   RTE_CACHE_LINE_SIZE, socket_id);
    if (!flow_used || flow_limbo_init(&limbo, config.max_flows, "flow_limbo") != 0) {
        RTE_LOG(ERR, FLOWTBL, "Failed to allocate the occupancy bitmap or the limbo\n");
        rte_free(flow_used);
        flow_used = NULL;
        flow_used_words = 0;
        rte_hash_free(flow_hash);
        flow_hash = NULL;
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
    flow_limbo_free(&limbo);
    rte_free(flow_used);
    flow_used = NULL;
    flow_used_words = 0;

    aging_iterator = 0;
    initialized = false;
    RTE_LOG(INFO, FLOWTBL, "Flow table cleanup complete\n");
}

// ==================== Per-Lcore Stats Helper ====================

static inline struct flow_table_lcore_stats* get_flow_lcore_stats(void) {
    unsigned int lcore_id = rte_lcore_id();
    // Non-EAL threads get LCORE_ID_ANY: the shared slot (see NON_EAL_SLOT)
    if (unlikely(lcore_id >= MAX_LCORES)) {
        lcore_id = NON_EAL_SLOT;
    }
    return &lcore_stats[lcore_id];
}

// ==================== Hash Writer Lock ====================

static inline void flow_hash_write_lock(void) {
    rte_spinlock_lock(&flow_hash_wlock);
}

static inline void flow_hash_write_unlock(void) {
    rte_spinlock_unlock(&flow_hash_wlock);
}

/**
 * Wait for a flow found in the hash to leave FLOW_STATE_INITIALIZING: its
 * creator added it moments ago and publishes it (FLOW_STATE_NEW) right after.
 * The wait is bounded so that a creator that is not running (a preempted
 * non-EAL thread) cannot stall the caller's RX path; the flow is then used
 * as it is, and the state machine makes no transition from INITIALIZING.
 */
static inline void flow_wait_published(const struct flow_entry *flow) {
    uint64_t deadline = 0;

    if (__atomic_load_n(&flow->state, __ATOMIC_ACQUIRE) == FLOW_STATE_INITIALIZING) {
        flow_table_race_seam(FLOW_SEAM_PUBLISH_WAIT);
    }
    while (__atomic_load_n(&flow->state, __ATOMIC_ACQUIRE) == FLOW_STATE_INITIALIZING) {
        uint64_t now = rte_rdtsc();
        if (deadline == 0) {
            deadline = now + (tsc_hz / 1000000) * FLOW_PUBLISH_WAIT_US;
        } else if (now > deadline) {
            break;
        }
        rte_pause();
    }
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
    FLOW_STAT_INC(lstats, lookups);

    ret = rte_hash_lookup_data(flow_hash, &key, (void **)&flow);
    if (ret >= 0 && flow != NULL) {
        FLOW_STAT_INC(lstats, lookup_hits);
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
    FLOW_STAT_INC(lstats, lookups);

    // Use precomputed hash to avoid rehashing
    int ret = rte_hash_lookup_with_hash_data(flow_hash, key, hash, (void **)&flow);
    if (ret >= 0 && flow != NULL) {
        FLOW_STAT_INC(lstats, lookup_hits);
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
    FLOW_STAT_INC(lstats, lookups);

    // Compute hash ONCE - reuse for both lookup and add
    hash = rte_hash_hash(flow_hash, &key);

    // Fast path: check if flow exists using precomputed hash
    ret = rte_hash_lookup_with_hash_data(flow_hash, &key, hash, (void **)&flow);
    if (ret >= 0 && flow != NULL) {
        FLOW_STAT_INC(lstats, lookup_hits);
        // Prefetch flow entry for subsequent access
        rte_prefetch0(flow);
        return flow;
    }

    // Slow path: need to create new flow
    flow_table_race_seam(FLOW_SEAM_CREATE_MISSED);

    // Allocate index from free ring (lock-free; takes back deleted entries
    // past their grace period when the ring is empty)
    entry_index = flow_entry_alloc();
    if (unlikely(entry_index < 0)) {
        // Try emergency eviction before giving up
        // This prevents dropping legitimate connections during attacks
        static uint64_t evict_attempts = 0;
        static uint64_t last_evict_tsc = 0;
        uint64_t evict_now = rte_rdtsc();

        // Rate-limit eviction attempts (max once per 100ms). Any lcore can
        // get here: the one whose compare-and-swap moves last_evict_tsc
        // runs the eviction, so lcores that find the table full together
        // do not each run one. Another lcore may have stored a clock read
        // after this one's: the unsigned difference would then wrap to a
        // huge interval and pass the limit.
        // No eviction while a batch of deleted entries still waits for its
        // grace period: those come back as soon as every reader has
        // reported, and evicting more live flows now would not make room any
        // sooner (or, with a reader that stopped reporting, at all).
        uint64_t min_interval = rte_get_tsc_hz() / 10;  // 100ms
        uint64_t last_evict = __atomic_load_n(&last_evict_tsc, __ATOMIC_RELAXED);
        if (flow_limbo_waiting(&limbo) < FLOW_EVICT_BATCH &&
            evict_now > last_evict && evict_now - last_evict > min_interval &&
            __atomic_compare_exchange_n(&last_evict_tsc, &last_evict, evict_now, false,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            __atomic_fetch_add(&evict_attempts, 1, __ATOMIC_RELAXED);

            // Try to evict some low-priority flows
            uint32_t evicted = flow_table_emergency_evict(FLOW_EVICT_BATCH);

            if (evicted > 0) {
                // Retry allocation. Evicted entries pass through the limbo:
                // with no reader registered this takes one back at once;
                // with readers (the packet loops, this lcore among them) they
                // come back once each has reported a quiescent state, so the
                // retry fails here and the next creates take them.
                entry_index = flow_entry_alloc();
            }
        }

        if (unlikely(entry_index < 0)) {
            FLOW_STAT_INC(lstats, create_failures);

            static uint64_t log_count = 0;
            if (unlikely(__atomic_fetch_add(&log_count, 1, __ATOMIC_RELAXED) < 10)) {
                RTE_LOG(WARNING, FLOWTBL, "Flow table full after eviction attempt "
                        "(max %u, evict_attempts=%lu)\n",
                        config.max_flows,
                        (unsigned long)__atomic_load_n(&evict_attempts, __ATOMIC_RELAXED));
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

    // Add under the writer lock (see flow_hash_wlock). Look the key up once
    // more first: another lcore may have added it since the lookup above,
    // and rte_hash_add of an existing key replaces its data, which would
    // orphan the other lcore's entry (never aged, never freed) while that
    // lcore goes on updating it.
    struct flow_entry *existing = NULL;
    flow_hash_write_lock();
    ret = rte_hash_lookup_with_hash_data(flow_hash, &key, hash, (void **)&existing);
    if (likely(ret < 0)) {
        ret = rte_hash_add_key_with_hash_data(flow_hash, &key, hash, flow);
        if (likely(ret >= 0)) {
            flow_used_set((uint32_t)entry_index);
        }
    } else {
        ret = -EEXIST;
    }
    flow_hash_write_unlock();

    if (unlikely(ret < 0)) {
        // Not added: clear sensitive fields and give the entry back
        __atomic_store_n(&flow->state, FLOW_STATE_NEW, __ATOMIC_RELEASE);
        flow->key.ip_lo = 0;
        flow->key.ip_hi = 0;
        flow_entry_free((uint32_t)entry_index);

        // Another lcore added this key first: use its flow
        if (ret == -EEXIST && existing != NULL) {
            flow_wait_published(existing);
            return existing;
        }

        FLOW_STAT_INC(lstats, create_failures);
        return NULL;
    }

    // Phase 3: Transition to valid state AFTER hash insertion
    // This ensures any thread that finds the entry via hash lookup
    // will see either FLOW_STATE_INITIALIZING (and wait) or a valid state
    flow_table_race_seam(FLOW_SEAM_CREATE_ADDED);
    __atomic_store_n(&flow->state, FLOW_STATE_NEW, __ATOMIC_RELEASE);

    FLOW_STAT_INC(lstats, creates);
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
 * The part of an update every packet gets: the update count, the last-seen
 * time and the counters of its direction, plus (with_tcp_flags, a constant
 * at each call) the TCP flags seen in that direction
 */
static inline void flow_count_packet_internal(struct flow_entry *flow,
                                              const struct packet_features *features,
                                              uint64_t now_tsc, bool with_tcp_flags) {
    // Per-lcore stats - NO ATOMICS in fast path
    struct flow_table_lcore_stats *lstats = get_flow_lcore_stats();
    FLOW_STAT_INC(lstats, updates);

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

void flow_table_count_packet(struct flow_entry *flow, const struct packet_features *features) {
    if (unlikely(!flow || !features)) {
        return;
    }
    // No TCP flags either: an ACK flag recorded here would let the RST
    // validator use the window around a peer ACK this segment never sent
    flow_count_packet_internal(flow, features, 0, false);
}

void flow_table_mark_handshake_verified(struct flow_entry *flow) {
    if (unlikely(!flow)) {
        return;
    }

    // The flag before the state, so that a reader that sees ESTABLISHED also
    // sees FLOW_FLAG_HANDSHAKE_ACKED (as the state machine's handshake ACK)
    __atomic_fetch_or(&flow->flags, FLOW_FLAG_HANDSHAKE_ACKED | FLOW_FLAG_ESTABLISHED,
                      __ATOMIC_RELEASE);

    // Only a handshake still in progress moves. Another lcore may move the
    // state meanwhile (a packet, or the eviction's claim), so each step is a
    // compare-and-swap: a claimed (INITIALIZING) or closing flow is left alone.
    uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
    while (state == FLOW_STATE_NEW || state == FLOW_STATE_SYN_RECEIVED ||
           state == FLOW_STATE_SYN_ACK_RECEIVED) {
        if (__atomic_compare_exchange_n(&flow->state, &state, FLOW_STATE_ESTABLISHED, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            break;
        }
    }
}

/**
 * Internal flow update implementation with optional TSC parameter
 */
static inline void flow_table_update_internal(struct flow_entry *flow,
                                               const struct packet_features *features,
                                               uint64_t now_tsc) {
    if (unlikely(!flow || !features)) {
        return;
    }

    flow_count_packet_internal(flow, features, now_tsc, true);

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
                        // A real initiator acknowledges the responder's ISN + 1,
                        // the responder's next sequence as tracked from its
                        // SYN-ACK. A blind ACK after a spoofed SYN cannot know
                        // it. Set before the state so that a reader seeing
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

    // Reset window after 1 second. Every lcore that sees the flow's packets
    // shares the window, each stamping with its own clock reading: one that
    // read its clock just before another lcore opened the window would see
    // the unsigned difference wrap, and reset the window again.
    if (now_tsc > window_start && window_elapsed >= tsc_hz) {
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
            struct flow_table_lcore_stats *lstats = get_flow_lcore_stats();
            FLOW_STAT_INC(lstats, rate_limit_drops);
            return RL_DROP_PPS;
        }
    }

    // Check BPS limit
    if (bps_limit > 0) {
        uint32_t current_bytes = __atomic_load_n(&flow->window_bytes, __ATOMIC_RELAXED);
        if (current_bytes + features->packet_size > bps_limit) {
            __atomic_fetch_or(&flow->flags, FLOW_FLAG_RATE_LIMITED, __ATOMIC_RELAXED);
            // Per-lcore stats - NO ATOMICS
            struct flow_table_lcore_stats *lstats = get_flow_lcore_stats();
            FLOW_STAT_INC(lstats, rate_limit_drops);
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
    uint32_t indices[AGING_BATCH_SIZE];    // Entry each key mapped to when scanned
    uint32_t count;
};

// Incremental aging: aging_iterator (Global State) saves the position between calls
// AGING_SCAN_LIMIT is now configurable via layer1_config.flow_table.aging_scan_limit
// Default: 4096, configurable at runtime

/**
 * Whether a flow is expired at now_tsc, given the pass's (possibly
 * pressure-reduced) timeouts.
 */
static bool flow_age_expired(const struct flow_entry *flow, uint64_t now_tsc,
                             uint64_t timeout_tsc, uint64_t syn_timeout_tsc) {
    // Use ACQUIRE ordering for last_seen_tsc to ensure we see
    // all prior writes from the updating thread before making aging decision
    uint64_t last_seen = __atomic_load_n(&flow->last_seen_tsc, __ATOMIC_ACQUIRE);

    // Another lcore stamps a packet with its own clock, read after this pass
    // read now_tsc: such a flow is not idle at all. The unsigned difference
    // would wrap to a huge idle time and age a flow seen a moment ago.
    if (last_seen >= now_tsc) {
        return false;
    }
    uint64_t idle_time = now_tsc - last_seen;
    uint64_t flow_timeout = timeout_tsc;

    // State-based timeouts for TCP flows
    if (flow->key.protocol == IPPROTO_TCP) {
        uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_RELAXED);

        switch (state) {
            case FLOW_STATE_NEW:
            case FLOW_STATE_SYN_RECEIVED:
            case FLOW_STATE_SYN_ACK_RECEIVED:
                // Incomplete handshake: short timeout (SYN flood protection).
                // A TCP flow still NEW with traffic both ways was first seen
                // mid-stream (it never saw the initiator's SYN): an exchange
                // in progress, not a handshake, so it keeps the idle timeout,
                // as its eviction score treats it as established.
                if (config.enable_syn_protection &&
                    !(state == FLOW_STATE_NEW && flow_is_bidirectional(flow))) {
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
                // Closing states: moderate timeout
                flow_timeout = syn_timeout_tsc * 4;  // ~20 seconds
                break;

            case FLOW_STATE_CLOSED:
            case FLOW_STATE_RST:
                // Terminal states: immediate cleanup
                flow_timeout = 0;
                break;

            case FLOW_STATE_ESTABLISHED:
            default:
                // Established or unknown: normal idle timeout
                break;
        }
    }

    return idle_time > flow_timeout;
}

// Test seam (see flow_table.h): this weak default does nothing
__attribute__((weak)) void flow_table_age_seam(void) {
}

uint32_t flow_table_age_flows(void) {
    struct flow_delete_batch batch;
    uint32_t freed[AGING_BATCH_SIZE];   // Entries this call deleted
    uint32_t nfreed = 0;
    uint32_t total_aged = 0;
    uint64_t now_tsc = rte_rdtsc();
    uint64_t timeout_tsc = seconds_to_tsc(config.idle_timeout_sec);
    uint64_t syn_timeout_tsc = seconds_to_tsc(config.syn_timeout_sec);
    uint32_t pos = aging_iterator;   // First entry index to look at (resume)
    uint32_t scanned = 0;            // Flows looked at
    uint32_t words = 0;              // Bitmap words read
    bool pass_done = false;

    if (unlikely(!initialized)) {
        return 0;
    }

    // Entries deleted earlier whose grace period is over go back to the free
    // indices (a create that finds none free takes them back too)
    flow_reclaim(RECLAIM_AGING_MAX);
    flow_limbo_check_stall(&limbo, now_tsc, seconds_to_tsc(LIMBO_STALL_SEC), "IPv4 flow table");

    // Adaptive timeout based on table occupancy. Count the flows in the hash:
    // max_flows minus the free ring count would also count the free indices
    // parked in per-lcore caches (up to LOCAL_REFILL_BATCH - 1 each) as active.
    uint32_t active_count = rte_hash_count(flow_hash);
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

    // Iterate with scan limit to avoid O(n) full table scan
    // Under pressure (occupancy > 90%), scan more aggressively
    // Scan limits are now configurable via layer1_config
    uint32_t scan_limit_normal = config.aging_scan_limit > 0 ? config.aging_scan_limit : 4096;
    uint32_t scan_limit_pressure = config.aging_scan_limit_pressure > 0 ? config.aging_scan_limit_pressure : scan_limit_normal * 2;
    uint32_t scan_limit = (occupancy > 0.90f) ? scan_limit_pressure : scan_limit_normal;

    // Walk the occupancy bitmap from the saved position: at most scan_limit
    // flows and AGING_WORD_LIMIT words per call, and stop at a full batch.
    // The next call resumes after the last flow looked at; after the last
    // word the pass is complete and the next call starts over.
    while (words < AGING_WORD_LIMIT) {
        uint32_t word = pos >> 6;
        if (word >= flow_used_words) {
            pass_done = true;
            break;
        }
        uint64_t bits = __atomic_load_n(&flow_used[word], __ATOMIC_ACQUIRE);
        bits &= ~0ULL << (pos & 63);     // entries before pos were looked at
        words++;

        bool stop = false;
        while (bits != 0) {
            uint32_t idx = (word << 6) | (uint32_t)__builtin_ctzll(bits);
            bits &= bits - 1;
            if (unlikely(idx >= config.max_flows)) {
                break;
            }
            struct flow_entry *flow = &flow_entries[idx];
            scanned++;

            if (flow_age_expired(flow, now_tsc, timeout_tsc, syn_timeout_tsc)) {
                // Add to delete batch: the key and the entry holding it (the
                // delete checks both again under the writer lock)
                memcpy(&batch.keys[batch.count], &flow->key, sizeof(struct flow_key));
                batch.indices[batch.count] = idx;
                batch.count++;
            }

            // Process batch when full; stop after scan limit to spread work
            // across calls
            if (batch.count >= AGING_BATCH_SIZE || scanned >= scan_limit) {
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
    aging_iterator = pass_done ? 0 : pos;

    flow_table_age_seam();

    // Delete collected flows. Since the scan, an emergency eviction on another
    // lcore may have deleted a key and a packet may have created it again on
    // another entry: deleting the key would then drop that new entry without
    // freeing it, and free the old index a second time (it would be handed
    // out twice). Under the writer lock no other writer runs, so a key still
    // mapping to the entry the scan saw stays so until it is deleted.
    // The flow must also still be expired: a packet may have refreshed it.
    for (uint32_t i = 0; i < batch.count; i++) {
        uint32_t entry_idx = batch.indices[i];
        struct flow_entry *flow = &flow_entries[entry_idx];
        hash_sig_t sig = rte_hash_hash(flow_hash, &batch.keys[i]);
        void *cur = NULL;
        bool deleted = false;

        flow_hash_write_lock();
        if (rte_hash_lookup_with_hash_data(flow_hash, &batch.keys[i], sig, &cur) >= 0 &&
            cur == flow &&
            flow_age_expired(flow, now_tsc, timeout_tsc, syn_timeout_tsc)) {
            flow_table_race_seam(FLOW_SEAM_AGE_DELETE);
            deleted = rte_hash_del_key_with_hash(flow_hash, &batch.keys[i], sig) >= 0;
            if (deleted) {
                flow_used_clear(entry_idx);
            }
        }
        flow_hash_write_unlock();

        if (deleted) {
            // Out of the hash, but a reader may still hold it: it waits in
            // the limbo for the readers' grace period
            freed[nfreed++] = entry_idx;
            total_aged++;
        }
    }
    flow_retire(freed, nfreed);

    if (total_aged > 0) {
        // Emergency eviction counts here too, from other lcores
        __atomic_fetch_add(&global_deletes, total_aged, __ATOMIC_RELAXED);

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
        // Aggregate creates from every per-lcore slot (see STATS_EVERY_SLOT)
        uint64_t total = 0;
        for (unsigned int lcore_id = 0; lcore_id < MAX_LCORES; lcore_id++) {
            total += lcore_stats[lcore_id].creates;
        }
        total += __atomic_load_n(&lcore_stats[NON_EAL_SLOT].creates, __ATOMIC_RELAXED);
        *total_flows = (uint32_t)total;
    }
    if (aged_flows) {
        *aged_flows = (uint32_t)__atomic_load_n(&global_deletes, __ATOMIC_RELAXED);
    }
}

void flow_table_get_detailed_stats(struct flow_table_stats *out_stats) {
    if (!out_stats) {
        return;
    }

    // Aggregate from every per-lcore slot (see STATS_EVERY_SLOT)
    memset(out_stats, 0, sizeof(*out_stats));

    for (unsigned int lcore_id = 0; lcore_id < MAX_LCORES; lcore_id++) {
        struct flow_table_lcore_stats *lstats = &lcore_stats[lcore_id];
        out_stats->lookups += lstats->lookups;
        out_stats->lookup_hits += lstats->lookup_hits;
        out_stats->creates += lstats->creates;
        out_stats->create_failures += lstats->create_failures;
        out_stats->updates += lstats->updates;
        out_stats->rate_limit_drops += lstats->rate_limit_drops;
    }

    // The slot non-EAL threads share (updated atomically)
    const struct flow_table_lcore_stats *shared = &lcore_stats[NON_EAL_SLOT];
    out_stats->lookups += __atomic_load_n(&shared->lookups, __ATOMIC_RELAXED);
    out_stats->lookup_hits += __atomic_load_n(&shared->lookup_hits, __ATOMIC_RELAXED);
    out_stats->creates += __atomic_load_n(&shared->creates, __ATOMIC_RELAXED);
    out_stats->create_failures += __atomic_load_n(&shared->create_failures, __ATOMIC_RELAXED);
    out_stats->updates += __atomic_load_n(&shared->updates, __ATOMIC_RELAXED);
    out_stats->rate_limit_drops += __atomic_load_n(&shared->rate_limit_drops, __ATOMIC_RELAXED);

    // Add global deletes (aging and emergency eviction)
    out_stats->deletes = __atomic_load_n(&global_deletes, __ATOMIC_RELAXED);
}

void flow_table_clear(void) {
    struct flow_key keys[256];
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
            memcpy(&keys[batch_count], key_ptr, sizeof(struct flow_key));
            batch_count++;

            if (batch_count >= 256) {
                break;
            }
        }

        // Free the entry each deleted key mapped to at its delete (under the
        // writer lock), so an index is freed once, by the delete that
        // released it. The freed entries pass through the limbo: the
        // contract says no packet is in flight, and a reader that still held
        // one is safe all the same.
        uint32_t freed[256];
        uint32_t nfreed = 0;
        for (uint32_t i = 0; i < batch_count; i++) {
            void *cur = NULL;
            bool deleted = false;

            flow_hash_write_lock();
            if (rte_hash_lookup_data(flow_hash, &keys[i], &cur) >= 0) {
                flow_table_race_seam(FLOW_SEAM_CLEAR_DELETE);
                deleted = rte_hash_del_key(flow_hash, &keys[i]) >= 0;
            }
            struct flow_entry *flow = (struct flow_entry *)cur;
            bool own = deleted && flow >= flow_entries && flow < &flow_entries[config.max_flows];
            if (own) {
                flow_used_clear((uint32_t)(flow - flow_entries));
            }
            flow_hash_write_unlock();

            if (own) {
                freed[nfreed++] = (uint32_t)(flow - flow_entries);
            }
        }
        flow_retire(freed, nfreed);
    } while (batch_count > 0);

    // Take back at once what no reader can hold any more; the rest comes
    // back after the readers' next quiescent reports
    while (flow_reclaim(RECLAIM_AGING_MAX) > 0) {
    }

    // Clear per-lcore stats and global counters
    memset(lcore_stats, 0, sizeof(lcore_stats));
    __atomic_store_n(&global_deletes, 0, __ATOMIC_RELAXED);

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

    // Only TCP RST/FIN segments are validated (and looked up)
    if (features->protocol != IPPROTO_TCP ||
        !(features->tcp_flags & (TCP_FLAG_RST | TCP_FLAG_FIN))) {
        return RST_FIN_VALID;
    }

    // Lookup the flow (sets features->flow_direction)
    return flow_table_validate_rst_fin_flow(flow_table_lookup(features), features);
}

enum rst_fin_validation_result flow_table_validate_rst_fin_flow(
    struct flow_entry *flow, const struct packet_features *features) {

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

    // Get per-lcore stats (non-EAL threads: the shared slot, see NON_EAL_SLOT)
    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= MAX_LCORES) lcore_id = NON_EAL_SLOT;
    struct rst_fin_lcore_stats *rstats = &rst_fin_stats[lcore_id];

    if (!flow) {
        // RST/FIN for non-existent flow - suspicious
        RST_FIN_STAT_INC(rstats, invalid_no_flow);
        return RST_FIN_NO_FLOW;
    }

    uint8_t flow_flags = __atomic_load_n(&flow->flags, __ATOMIC_RELAXED);

    // If sequence tracking is not enabled, accept (flow just started)
    if (!(flow_flags & FLOW_FLAG_SEQ_TRACKING_ENABLED)) {
        RST_FIN_STAT_INC(rstats, valid_count);
        return RST_FIN_VALID;
    }

    // Get the expected sequence number for this direction
    uint32_t expected_seq;
    uint32_t last_ack;
    uint8_t peer_flags;  // TCP flags seen so far from the other side

    if (features->flow_direction == FLOW_DIR_LO_TO_HI) {
        expected_seq = __atomic_load_n(&flow->seq_lo_to_hi, __ATOMIC_RELAXED);
        last_ack = __atomic_load_n(&flow->ack_hi_to_lo, __ATOMIC_RELAXED);  // ACK from other side
        peer_flags = __atomic_load_n(&flow->tcp_flags_hi_to_lo, __ATOMIC_RELAXED);
    } else {
        expected_seq = __atomic_load_n(&flow->seq_hi_to_lo, __ATOMIC_RELAXED);
        last_ack = __atomic_load_n(&flow->ack_lo_to_hi, __ATOMIC_RELAXED);
        peer_flags = __atomic_load_n(&flow->tcp_flags_lo_to_hi, __ATOMIC_RELAXED);
    }

    // RST validation: sequence must be in expected window
    // RFC 5961 is stricter, but we allow a window for practical deployments
    if (flags & TCP_FLAG_RST) {
        // RST sequence should be close to what we expect next, or close to last ACK
        bool seq_ok = seq_in_window(features->tcp_seq, expected_seq, RST_FIN_SEQ_WINDOW);
        // last_ack is an ACK only once the peer has sent a segment with ACK
        // set. Before that it is 0 (no reply yet) or the unused ack field of
        // a segment without ACK (a SYN), and a window around it would accept
        // any sequence near that value.
        bool ack_ok = (peer_flags & TCP_FLAG_ACK) &&
                      seq_in_window(features->tcp_seq, last_ack, RST_FIN_SEQ_WINDOW);

        if (!seq_ok && !ack_ok) {
            RST_FIN_STAT_INC(rstats, invalid_seq);
            RTE_LOG(DEBUG, FLOWTBL, "RST seq validation failed: seq=%u, expected=%u, last_ack=%u\n",
                    features->tcp_seq, expected_seq, last_ack);
            return RST_FIN_SEQ_OUT_OF_WINDOW;
        }
    }

    // FIN validation: sequence should be in expected window
    if (flags & TCP_FLAG_FIN) {
        // FIN should be sent at the end of data, so seq should be near expected
        if (!seq_in_window(features->tcp_seq, expected_seq, RST_FIN_SEQ_WINDOW)) {
            RST_FIN_STAT_INC(rstats, invalid_seq);
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
                RST_FIN_STAT_INC(rstats, invalid_state);
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

    RST_FIN_STAT_INC(rstats, valid_count);
    return RST_FIN_VALID;
}

void flow_table_get_rst_fin_stats(uint64_t *valid_count, uint64_t *invalid_count) {
    uint64_t valid = 0;
    uint64_t invalid = 0;

    // Every per-lcore slot (see STATS_EVERY_SLOT)
    for (unsigned int lcore_id = 0; lcore_id < MAX_LCORES; lcore_id++) {
        struct rst_fin_lcore_stats *rstats = &rst_fin_stats[lcore_id];
        valid += rstats->valid_count;
        invalid += rstats->invalid_seq + rstats->invalid_no_flow + rstats->invalid_state;
    }

    // The slot non-EAL threads share (updated atomically)
    const struct rst_fin_lcore_stats *shared = &rst_fin_stats[NON_EAL_SLOT];
    valid += __atomic_load_n(&shared->valid_count, __ATOMIC_RELAXED);
    invalid += __atomic_load_n(&shared->invalid_seq, __ATOMIC_RELAXED) +
               __atomic_load_n(&shared->invalid_no_flow, __ATOMIC_RELAXED) +
               __atomic_load_n(&shared->invalid_state, __ATOMIC_RELAXED);

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
 *
 * Non-TCP flows have no handshake and stay FLOW_STATE_NEW, and so does a TCP
 * flow first seen mid-stream (the state machine leaves NEW only on the
 * initiator's SYN): both score as established while they show traffic in
 * both directions.
 *
 * The score itself is flow_eviction_score() (flow_table_internal.h), which
 * the IPv6 table shares.
 */
static int32_t calculate_eviction_priority(const struct flow_entry *flow, uint64_t now_tsc) {
    uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_RELAXED);
    uint64_t pkts_lo = __atomic_load_n(&flow->packets_lo_to_hi, __ATOMIC_RELAXED);
    uint64_t pkts_hi = __atomic_load_n(&flow->packets_hi_to_lo, __ATOMIC_RELAXED);

    return flow_eviction_score(state, flow->key.protocol, pkts_lo, pkts_hi,
                               flow->first_seen_tsc, flow->reputation_score,
                               now_tsc, rte_get_tsc_hz());
}

/**
 * Flows emergency eviction never chooses: TCP flows that are ESTABLISHED, have
 * traffic in both directions, and whose handshake ACK acknowledged the
 * responder's ISN + 1. Traffic both ways alone proves nothing: a spoofed SYN
 * draws the server's SYN-ACK, and a blind ACK then completes the handshake as
 * the table sees it. Non-TCP flows have no handshake to check, and a spoofed
 * request that a UDP service answers makes a flow bidirectional, so they stay
 * evictable (their score treats traffic both ways as established).
 */
static inline bool flow_evict_protected(const struct flow_entry *flow, uint8_t state) {
    return state == FLOW_STATE_ESTABLISHED &&
           (__atomic_load_n(&flow->flags, __ATOMIC_RELAXED) & FLOW_FLAG_HANDSHAKE_ACKED) &&
           flow_is_bidirectional(flow);
}

// Test seams (see flow_table.h): these weak defaults do nothing
__attribute__((weak)) void flow_table_evict_seam(void) {
}

__attribute__((weak)) void flow_table_evict_claim_seam(void) {
}

// Most candidates one eviction keeps, and so deletes
#define EVICT_MAX_CANDIDATES 1024

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
    const uint32_t max_candidates = EVICT_MAX_CANDIDATES;

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
    // Index of the highest (worst) priority in the buffer. The buffer is not
    // sorted until Phase 2, so its last slot says nothing about the worst.
    uint32_t worst_idx = 0;

    // Phase 1: Collect candidates with priority scores
    while (rte_hash_iterate(flow_hash, (const void **)&key_ptr, &data, &iter) >= 0) {
        scanned++;
        if (scanned > max_scan) break;

        struct flow_entry *flow = (struct flow_entry *)data;
        if (!flow) continue;

        // Skip flows being initialized
        uint8_t state = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
        if (state == FLOW_STATE_INITIALIZING) continue;

        // Never evict protected flows (see flow_evict_protected()): the
        // scoring rates them "definitely legitimate", and count_needed is a
        // batch size, not a quota to fill from them. If only such flows
        // remain, nothing is evicted and the create fails; aging still
        // expires them.
        if (flow_evict_protected(flow, state)) continue;

        // Calculate eviction priority
        int32_t priority = calculate_eviction_priority(flow, now_tsc);
        // The entry from the pointer, not from a field of an entry another
        // lcore may be recycling (the recheck below catches a stale one)
        uint32_t idx = (uint32_t)(flow - flow_entries);

        // Keep the max_candidates lowest priorities seen: fill the buffer,
        // then let a lower priority replace the current worst
        if (candidate_count < max_candidates) {
            candidates[candidate_count].key = *key_ptr;
            candidates[candidate_count].entry_index = idx;
            candidates[candidate_count].priority = priority;
            if (priority > candidates[worst_idx].priority) {
                worst_idx = candidate_count;
            }
            candidate_count++;
        } else if (priority < candidates[worst_idx].priority) {
            candidates[worst_idx].key = *key_ptr;
            candidates[worst_idx].entry_index = idx;
            candidates[worst_idx].priority = priority;
            // Find the new worst
            worst_idx = 0;
            for (uint32_t i = 1; i < max_candidates; i++) {
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

    // Phase 2: Sort candidates by priority (lowest first)
    qsort(candidates, candidate_count, sizeof(struct eviction_candidate),
          compare_eviction_candidates);

    flow_table_evict_seam();

    // Phase 3: Evict lowest-priority flows
    uint32_t evicted = 0;
    uint32_t to_evict = (count_needed < candidate_count) ? count_needed : candidate_count;
    uint32_t freed[EVICT_MAX_CANDIDATES];   // The entries this call deleted

    for (uint32_t i = 0; i < to_evict; i++) {
        // Phase 1 read this flow a while ago. Since then another lcore may
        // have completed its handshake, or aging may have deleted the key and
        // a packet created it again on another entry; deleting the key would
        // then drop that new entry without freeing it, and free the old index
        // a second time. Under the writer lock no other writer runs: delete
        // only if the key still maps to the scanned entry and that flow is
        // still evictable. The claim (a compare-and-swap of the
        // state just checked to FLOW_STATE_INITIALIZING) makes that check and
        // the delete one step: a handshake that completes in between changes
        // the state, the claim fails and the flow is kept.
        void *cur = NULL;
        uint32_t idx = candidates[i].entry_index;
        if (idx >= config.max_flows) {
            continue;
        }
        struct flow_entry *entry = &flow_entries[idx];
        hash_sig_t sig = rte_hash_hash(flow_hash, &candidates[i].key);
        bool deleted = false;

        flow_hash_write_lock();
        if (rte_hash_lookup_with_hash_data(flow_hash, &candidates[i].key, sig, &cur) >= 0 &&
            cur == entry) {
            uint8_t state = __atomic_load_n(&entry->state, __ATOMIC_ACQUIRE);
            if (state != FLOW_STATE_INITIALIZING && !flow_evict_protected(entry, state)) {
                flow_table_evict_claim_seam();
                if (__atomic_compare_exchange_n(&entry->state, &state, FLOW_STATE_INITIALIZING,
                                                false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                    deleted = rte_hash_del_key_with_hash(flow_hash, &candidates[i].key, sig) >= 0;
                    if (likely(deleted)) {
                        flow_used_clear(idx);
                    } else {
                        // Not reachable while every writer holds the lock:
                        // undo the claim rather than strand the flow
                        __atomic_store_n(&entry->state, state, __ATOMIC_RELEASE);
                    }
                }
            }
        }
        flow_hash_write_unlock();

        if (deleted) {
            // Out of the hash, but a reader may still hold it: it waits in
            // the limbo for the readers' grace period
            freed[evicted++] = idx;
        }
    }
    flow_retire(freed, evicted);

    rte_free(candidates);

    if (evicted > 0) {
        __atomic_fetch_add(&global_deletes, evicted, __ATOMIC_RELAXED);
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