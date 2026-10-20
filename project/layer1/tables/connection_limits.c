#include "connection_limits.h"
#include "flow_table_internal.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>
#include <string.h>

#define RTE_LOGTYPE_CONNLIMIT RTE_LOGTYPE_USER4

// ==================== Global State ====================

static struct rte_hash *conn_hash = NULL;
static struct connection_tracker *trackers = NULL;
static uint32_t conn_max_key_id = 0;    // Positions are below this (trackers has this many)
static struct connection_limits_config config;
static bool initialized = false;

// Statistics (atomic for thread safety)
static uint64_t limits_exceeded = 0;
static uint64_t total_checks = 0;

// Every writer of conn_hash (each add, each delete and each release of a
// deleted IP's position, from any lcore or thread) holds this lock; lookups
// do not take it. RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY makes readers safe
// against one writer at a time, not writers against each other: an add
// takes its key slot from a single-consumer ring after dropping the hash's
// own lock, so two lcores adding at once could take the same slot (an IP
// lost, or two IPs on one tracker). MULTI_WRITER_ADD is not used: its
// per-lcore slot cache is indexed by rte_lcore_id(), which faults on
// non-EAL threads, and its positions run past the configured entries.
static rte_spinlock_t conn_wlock = RTE_SPINLOCK_INITIALIZER;

// Deleted IPs' positions waiting for the readers' grace period. The table
// keeps a deleted key's position allocated (RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL)
// because a packet lcore may still use its tracker after a lookup made
// before the delete; it is cleared and released once every registered flow
// table reader has reported a quiescent state since the delete. Each
// position is in one place at a time (the hash's free slots, a live key, or
// this limbo), so the limbo never refuses one.
static struct flow_limbo conn_limbo;

// Most positions an add that finds the table full takes back (packet path)
#define CONNLIM_RECLAIM_ADD_MAX 64

// ==================== Deferred Reclamation ====================

// Test seam (see connection_limits.h): this weak default does nothing
__attribute__((weak)) void connection_limits_seam(enum connection_limits_seam_point point) {
    (void)point;
}

bool connection_limits_writer_lock_held(void) {
    return rte_spinlock_is_locked(&conn_wlock) != 0;
}

/**
 * Clear and release up to max (at most 256) positions whose grace period is
 * over, oldest first. Caller holds conn_wlock: releasing a position is a
 * hash write.
 *
 * @return number of positions released
 */
static uint32_t connlim_reclaim_locked(uint32_t max) {
    uint32_t pos[256];
    uint32_t n = flow_limbo_take(&conn_limbo, pos, RTE_MIN(max, (uint32_t)RTE_DIM(pos)));
    for (uint32_t i = 0; i < n; i++) {
        // No packet lcore uses it any more: the next IP at this position
        // starts from a clear tracker
        struct connection_tracker *tracker = &trackers[pos[i]];
        __atomic_store_n(&tracker->ip, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&tracker->total_connections, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&tracker->active_connections, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&tracker->connections_last_window, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&tracker->last_update_tsc, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&tracker->window_start_tsc, 0, __ATOMIC_RELAXED);
        rte_hash_free_key_with_position(conn_hash, (int32_t)pos[i]);
    }
    return n;
}

/**
 * Release every position whose grace period is over, taking the writer
 * lock for 256 at a time. Caller does not hold conn_wlock.
 */
static uint32_t connlim_reclaim_all(void) {
    uint32_t total = 0;
    uint32_t n;

    do {
        rte_spinlock_lock(&conn_wlock);
        n = connlim_reclaim_locked(256);
        rte_spinlock_unlock(&conn_wlock);
        total += n;
    } while (n == 256);
    return total;
}

/**
 * Hand the n positions the cleanup deleted to the limbo, which starts their
 * grace period. Caller does not hold conn_wlock.
 */
static void connlim_retire(const uint32_t *pos, uint32_t n) {
    uint32_t refused = flow_limbo_push(&conn_limbo, pos, n);
    if (unlikely(refused > 0)) {
        // Only without the readers' quiescent-state variable (then no
        // reader can register to be waited for): release them at once
        // rather than lose them
        RTE_LOG(ERR, CONNLIMIT, "Deferred reclamation unavailable: %u deleted positions released at once\n",
                refused);
        uint32_t done = 0;
        while (done < refused) {
            rte_spinlock_lock(&conn_wlock);
            rte_hash_free_key_with_position(conn_hash, (int32_t)pos[n - refused + done]);
            rte_spinlock_unlock(&conn_wlock);
            done++;
        }
    }
}

/**
 * True if the tracker has no active connection and no update for longer
 * than expire_tsc as of now_tsc. A connection on another lcore may stamp it
 * after the caller read its clock: it is not idle (now_tsc - last_update
 * would wrap).
 */
static inline bool connlim_expired(const struct connection_tracker *tracker, uint64_t now_tsc,
                                   uint64_t expire_tsc) {
    uint64_t last_update = __atomic_load_n(&tracker->last_update_tsc, __ATOMIC_ACQUIRE);
    uint32_t active = __atomic_load_n(&tracker->active_connections, __ATOMIC_ACQUIRE);
    return active == 0 && last_update <= now_tsc && now_tsc - last_update > expire_tsc;
}

// ==================== Initialization ====================

int connection_limits_init(const struct connection_limits_config *cfg) {
    if (!cfg) {
        RTE_LOG(ERR, CONNLIMIT, "Invalid config\n");
        return -1;
    }

    if (initialized) {
        RTE_LOG(WARNING, CONNLIMIT, "Connection limits already initialized\n");
        return 0;
    }

    memcpy(&config, cfg, sizeof(config));

    RTE_LOG(INFO, CONNLIMIT, "Initializing connection limits (thread-safe):\n");
    RTE_LOG(INFO, CONNLIMIT, "  Max IPs: %u\n", config.max_ips);
    RTE_LOG(INFO, CONNLIMIT, "  Max connections/IP: %u\n", config.max_connections_per_ip);
    RTE_LOG(INFO, CONNLIMIT, "  Time window: %u sec\n", config.time_window_sec);

    // Create hash table with thread safety
    // Uses rte_hash_add_key which returns index directly - no separate index allocation needed
    struct rte_hash_parameters hash_params = {
        .name = "conn_limit_hash",
        .entries = config.max_ips,
        .key_len = sizeof(uint32_t),  // IP address
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        // CRITICAL: Enable thread-safe concurrent access (writers are
        // serialized by conn_wlock). A deleted key keeps its position until
        // its grace period is over (see conn_limbo).
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                      RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT |
                      RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL,
    };

    conn_hash = rte_hash_create(&hash_params);
    if (!conn_hash) {
        RTE_LOG(ERR, CONNLIMIT, "Failed to create hash table\n");
        return -1;
    }

    // Allocate tracker array - index comes from hash table, one tracker per
    // position it can hand out
    int32_t max_key_id = rte_hash_max_key_id(conn_hash);
    conn_max_key_id = max_key_id > 0 ? (uint32_t)max_key_id : 0;
    trackers = conn_max_key_id ? rte_zmalloc("conn_trackers",
                                             conn_max_key_id * sizeof(struct connection_tracker),
                                             RTE_CACHE_LINE_SIZE) : NULL;
    if (!trackers ||
        flow_limbo_init(&conn_limbo, conn_max_key_id, "conn_limit_limbo") != 0 ||
        flow_table_readers() == NULL) {
        RTE_LOG(ERR, CONNLIMIT, "Failed to allocate tracker array\n");
        flow_limbo_free(&conn_limbo);
        rte_free(trackers);
        trackers = NULL;
        rte_hash_free(conn_hash);
        conn_hash = NULL;
        conn_max_key_id = 0;
        return -1;
    }
    rte_spinlock_init(&conn_wlock);

    initialized = true;
    RTE_LOG(INFO, CONNLIMIT, "Connection limits initialized successfully (thread-safe)\n");
    return 0;
}

void connection_limits_cleanup(void) {
    if (conn_hash) {
        rte_hash_free(conn_hash);
        conn_hash = NULL;
    }

    if (trackers) {
        rte_free(trackers);
        trackers = NULL;
    }

    // The table is gone: positions still waiting go with it
    flow_limbo_free(&conn_limbo);
    conn_max_key_id = 0;

    initialized = false;
    RTE_LOG(INFO, CONNLIMIT, "Connection limits cleanup complete\n");
}

// ==================== Connection Tracking ====================

/**
 * Add an IP the lockless lookup missed and set up its tracker for its first
 * connection, under the writer lock. Another lcore may have added the IP
 * since that lookup: its position is then returned with *added false (the
 * caller counts this connection on it; setting it up again would reset the
 * other lcore's count).
 *
 * @return the IP's position, or a negative value if the table is full
 */
static int32_t connlim_add(uint32_t ip, uint64_t now_tsc, bool *added) {
    *added = false;
    rte_spinlock_lock(&conn_wlock);
    int32_t index = rte_hash_lookup(conn_hash, &ip);
    if (index < 0) {
        connection_limits_seam(CONNLIM_SEAM_ADD);
        index = rte_hash_add_key(conn_hash, &ip);
        if (index < 0 && connlim_reclaim_locked(CONNLIM_RECLAIM_ADD_MAX) > 0) {
            // Positions deleted earlier whose grace period is over
            index = rte_hash_add_key(conn_hash, &ip);
        }
        if (index >= 0) {
            // A position comes from the free slots: its tracker is clear
            // and no earlier reader uses it. Lookups of this IP on other
            // lcores find it from the add on and count their connections on
            // the clear tracker (a new window), so this connection is
            // counted with adds as theirs are: neither loses the other's.
            struct connection_tracker *tracker = &trackers[index];
            connection_limits_seam(CONNLIM_SEAM_PUBLISH);
            uint64_t clear = 0;
            __atomic_compare_exchange_n(&tracker->window_start_tsc, &clear, now_tsc,
                                        false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
            __atomic_store_n(&tracker->ip, ip, __ATOMIC_RELAXED);
            __atomic_add_fetch(&tracker->total_connections, 1, __ATOMIC_RELAXED);
            __atomic_add_fetch(&tracker->active_connections, 1, __ATOMIC_RELAXED);
            __atomic_add_fetch(&tracker->connections_last_window, 1, __ATOMIC_RELAXED);
            __atomic_store_n(&tracker->last_update_tsc, now_tsc, __ATOMIC_RELAXED);
            *added = true;
        }
    }
    rte_spinlock_unlock(&conn_wlock);
    return index;
}

bool connection_limits_check(uint32_t ip, uint16_t port) {
    (void)port;  // Reserved for per-port tracking

    if (!initialized) {
        return true;  // Fail-open
    }

    __atomic_add_fetch(&total_checks, 1, __ATOMIC_RELAXED);

    uint64_t now_tsc = rte_get_tsc_cycles();
    uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t window_tsc = config.time_window_sec * tsc_hz;

    // Try to find existing tracker
    int32_t index = rte_hash_lookup(conn_hash, &ip);

    if (index < 0) {
        // New IP - add to hash table under the writer lock
        connection_limits_seam(CONNLIM_SEAM_MISSED);
        bool added;
        index = connlim_add(ip, now_tsc, &added);

        if (index < 0) {
            // Table full - fail-open
            static uint64_t log_count = 0;
            if (__atomic_fetch_add(&log_count, 1, __ATOMIC_RELAXED) < 10) {
                RTE_LOG(WARNING, CONNLIMIT, "Connection tracker table full\n");
            }
            return true;
        }

        if (added) {
            return true;  // First connection from this IP - allow
        }
        // Another lcore added this IP first: count this connection on the
        // tracker it set up
    }

    // Existing IP - check limits
    struct connection_tracker *tracker = &trackers[index];
    connection_limits_seam(CONNLIM_SEAM_HIT);

    // Check if we need to reset the sliding window. Another lcore may have
    // started a window after this check read its clock: that window is
    // current (now_tsc - window_start would wrap and reset it again, losing
    // its connections)
    uint64_t window_start = __atomic_load_n(&tracker->window_start_tsc, __ATOMIC_ACQUIRE);
    uint64_t time_since_window_start = now_tsc - window_start;
    
    if (now_tsc > window_start && time_since_window_start > window_tsc) {
        // Window expired - reset (use CAS for thread safety)
        if (__atomic_compare_exchange_n(&tracker->window_start_tsc, 
                                        &window_start, now_tsc,
                                        false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            __atomic_store_n(&tracker->connections_last_window, 0, __ATOMIC_RELAXED);
        }
    }

    // Check limit
    uint32_t conns = __atomic_load_n(&tracker->connections_last_window, __ATOMIC_ACQUIRE);
    if (conns >= config.max_connections_per_ip) {
        __atomic_add_fetch(&limits_exceeded, 1, __ATOMIC_RELAXED);

        // Log first few occurrences
        static uint64_t log_count = 0;
        if (__atomic_fetch_add(&log_count, 1, __ATOMIC_RELAXED) < 10) {
            RTE_LOG(WARNING, CONNLIMIT,
                    "Connection limit exceeded: IP=%u.%u.%u.%u (%u conns in %u sec)\n",
                    (rte_be_to_cpu_32(ip) >> 24) & 0xFF,
                    (rte_be_to_cpu_32(ip) >> 16) & 0xFF,
                    (rte_be_to_cpu_32(ip) >> 8) & 0xFF,
                    rte_be_to_cpu_32(ip) & 0xFF,
                    conns,
                    config.time_window_sec);
        }

        return false;  // Limit exceeded
    }

    // Update counters atomically
    __atomic_add_fetch(&tracker->total_connections, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&tracker->active_connections, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&tracker->connections_last_window, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&tracker->last_update_tsc, now_tsc, __ATOMIC_RELAXED);

    return true;  // Allowed
}

void connection_limits_update(uint32_t ip, enum connection_state state) {
    if (!initialized) {
        return;
    }

    int32_t index = rte_hash_lookup(conn_hash, &ip);
    if (index < 0) {
        return;  // IP not tracked
    }

    struct connection_tracker *tracker = &trackers[index];

    switch (state) {
        case CONN_STATE_SYN_SENT:
            // Already counted in connection_limits_check()
            break;

        case CONN_STATE_ESTABLISHED:
            // Connection established
            break;

        case CONN_STATE_CLOSED:
            // Connection closed - decrement active count
            {
                uint32_t active = __atomic_load_n(&tracker->active_connections, __ATOMIC_ACQUIRE);
                if (active > 0) {
                    __atomic_sub_fetch(&tracker->active_connections, 1, __ATOMIC_RELAXED);
                }
            }
            break;
    }

    __atomic_store_n(&tracker->last_update_tsc, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
}

uint32_t connection_limits_cleanup_expired(void) {
    if (!initialized) {
        return 0;
    }

    // Positions deleted by earlier passes whose grace period is over are
    // cleared and released (an add that finds the table full takes them too)
    (void)connlim_reclaim_all();

    uint64_t now_tsc = rte_get_tsc_cycles();
    uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t expire_tsc = config.cleanup_interval_sec * tsc_hz;
    uint32_t cleaned = 0;
    connection_limits_seam(CONNLIM_SEAM_CLEANUP_SCAN);

    // Collect keys to delete (NEVER delete during iteration!), with the
    // position the scan saw each at
    uint32_t keys_to_delete[256];
    uint32_t positions[256];
    uint32_t retired[256];
    uint32_t delete_count = 0;
    uint32_t nretired = 0;

    const void *next_key;
    void *next_data;
    uint32_t iter = 0;
    int32_t index;

    while ((index = rte_hash_iterate(conn_hash, &next_key, &next_data, &iter)) >= 0) {
        if (delete_count >= 256) {
            break;  // Process in batches
        }

        if ((uint32_t)index >= conn_max_key_id) {
            continue;
        }

        struct connection_tracker *tracker = &trackers[index];

        // Check if entry is old and has no active connections
        if (connlim_expired(tracker, now_tsc, expire_tsc)) {
            keys_to_delete[delete_count] = *(const uint32_t *)next_key;
            positions[delete_count] = (uint32_t)index;
            delete_count++;
        }
    }

    // Now delete collected keys. Each is checked again under the writer
    // lock: since the scan a connection may have refreshed it, and the key
    // may have been deleted and added again at another position.
    for (uint32_t i = 0; i < delete_count; i++) {
        struct connection_tracker *tracker = &trackers[positions[i]];
        rte_spinlock_lock(&conn_wlock);
        if (rte_hash_lookup(conn_hash, &keys_to_delete[i]) == (int32_t)positions[i] &&
            connlim_expired(tracker, now_tsc, expire_tsc)) {
            connection_limits_seam(CONNLIM_SEAM_CLEANUP_DELETE);
            if (rte_hash_del_key(conn_hash, &keys_to_delete[i]) >= 0) {
                retired[nretired++] = positions[i];
                cleaned++;
            }
        }
        rte_spinlock_unlock(&conn_wlock);
    }

    // Out of the table, but a packet lcore may still use the tracker: the
    // positions wait for the readers' grace period
    connlim_retire(retired, nretired);
    // With no reader registered, what this pass deleted is free at once
    (void)connlim_reclaim_all();

    if (cleaned > 0) {
        RTE_LOG(DEBUG, CONNLIMIT, "Cleaned up %u expired connection trackers\n", cleaned);
    }

    return cleaned;
}

// ==================== Statistics ====================

bool connection_limits_get_count(uint32_t ip, uint32_t *active, uint32_t *total) {
    if (!initialized) {
        return false;
    }

    int32_t index = rte_hash_lookup(conn_hash, &ip);
    if (index < 0) {
        return false;
    }

    struct connection_tracker *tracker = &trackers[index];

    if (active) {
        *active = __atomic_load_n(&tracker->active_connections, __ATOMIC_RELAXED);
    }
    if (total) {
        *total = __atomic_load_n(&tracker->total_connections, __ATOMIC_RELAXED);
    }

    return true;
}

void connection_limits_get_stats(uint32_t *tracked_ips,
                                 uint32_t *total_connections,
                                 uint64_t *limits_exceeded_out) {
    if (tracked_ips) {
        // rte_hash_count() also counts the positions waiting for their
        // grace period
        uint32_t used = conn_hash ? (uint32_t)rte_hash_count(conn_hash) : 0;
        uint32_t waiting = initialized ? flow_limbo_waiting(&conn_limbo) : 0;
        *tracked_ips = used > waiting ? used - waiting : 0;
    }

    if (total_connections) {
        uint32_t total = 0;
        if (initialized) {
            const void *next_key;
            void *next_data;
            uint32_t iter = 0;

            while (rte_hash_iterate(conn_hash, &next_key, &next_data, &iter) >= 0) {
                int32_t index = rte_hash_lookup(conn_hash, next_key);
                if (index >= 0) {
                    total += __atomic_load_n(&trackers[index].active_connections, __ATOMIC_RELAXED);
                }
            }
        }
        *total_connections = total;
    }

    if (limits_exceeded_out) {
        *limits_exceeded_out = __atomic_load_n(&limits_exceeded, __ATOMIC_RELAXED);
    }
}

int32_t connection_limits_position(uint32_t ip) {
    if (!initialized) {
        return -1;
    }
    int32_t index = rte_hash_lookup(conn_hash, &ip);
    return index >= 0 ? index : -1;
}

uint32_t connection_limits_positions_waiting(void) {
    return initialized ? flow_limbo_waiting(&conn_limbo) : 0;
}
