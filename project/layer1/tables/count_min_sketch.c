#include "count_min_sketch.h"
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_hash_crc.h>
#include <rte_random.h>
#include <rte_log.h>
#include <string.h>

#define RTE_LOGTYPE_CMS RTE_LOGTYPE_USER5

// ==================== Hash Functions ====================

/**
 * Compute hash for a key with a specific seed.
 * Uses CRC32C for speed (hardware accelerated on modern CPUs).
 */
static inline uint32_t cms_hash(uint32_t key, uint32_t seed, uint32_t width) {
    // CRC32C is fast and provides good distribution
    uint32_t hash = rte_hash_crc_4byte(key, seed);
    // Fast modulo for power-of-2 width
    return hash & (width - 1);
}

// ==================== Initialization ====================

int cms_init(struct count_min_sketch *cms, uint32_t width, uint32_t depth,
             uint32_t window_sec) {
    if (!cms) {
        return -1;
    }

    // Validate parameters
    if (width == 0 || width > CMS_MAX_WIDTH) {
        RTE_LOG(ERR, CMS, "Invalid width %u (max %u)\n", width, CMS_MAX_WIDTH);
        return -1;
    }
    if (depth == 0 || depth > CMS_MAX_DEPTH) {
        RTE_LOG(ERR, CMS, "Invalid depth %u (max %u)\n", depth, CMS_MAX_DEPTH);
        return -1;
    }

    // Round width up to power of 2 for fast modulo
    uint32_t pow2_width = 1;
    while (pow2_width < width) {
        pow2_width <<= 1;
    }
    if (pow2_width != width) {
        RTE_LOG(INFO, CMS, "Rounding width %u up to %u (power of 2)\n",
                width, pow2_width);
        width = pow2_width;
    }

    memset(cms, 0, sizeof(*cms));
    cms->width = width;
    cms->depth = depth;

    // Allocate counter arrays for both buffers
    for (int buf = 0; buf < 2; buf++) {
        cms->counters[buf] = rte_zmalloc_socket("cms_rows",
                                                 depth * sizeof(uint32_t *),
                                                 RTE_CACHE_LINE_SIZE,
                                                 rte_socket_id());
        if (!cms->counters[buf]) {
            RTE_LOG(ERR, CMS, "Failed to allocate row pointers\n");
            cms_cleanup(cms);
            return -1;
        }

        for (uint32_t d = 0; d < depth; d++) {
            cms->counters[buf][d] = rte_zmalloc_socket("cms_counters",
                                                        width * sizeof(uint32_t),
                                                        RTE_CACHE_LINE_SIZE,
                                                        rte_socket_id());
            if (!cms->counters[buf][d]) {
                RTE_LOG(ERR, CMS, "Failed to allocate counter row %u\n", d);
                cms_cleanup(cms);
                return -1;
            }
        }
    }

    // Initialize hash seeds with random values
    for (uint32_t d = 0; d < depth; d++) {
        cms->seeds[d] = (uint32_t)rte_rand();
    }

    // Initialize timing
    cms->active_buffer = 0;
    cms->window_start_tsc = rte_get_tsc_cycles();
    cms->window_duration_tsc = window_sec > 0 ?
                               (uint64_t)window_sec * rte_get_tsc_hz() : 0;

    size_t mem_bytes = cms_memory_usage(cms);
    RTE_LOG(INFO, CMS, "Count-Min Sketch initialized: %ux%u, window=%us, memory=%zu KB\n",
            width, depth, window_sec, mem_bytes / 1024);

    return 0;
}

int cms_init_default(struct count_min_sketch *cms) {
    return cms_init(cms, CMS_DEFAULT_WIDTH, CMS_DEFAULT_DEPTH, 1);
}

void cms_cleanup(struct count_min_sketch *cms) {
    if (!cms) {
        return;
    }

    for (int buf = 0; buf < 2; buf++) {
        if (cms->counters[buf]) {
            for (uint32_t d = 0; d < cms->depth; d++) {
                if (cms->counters[buf][d]) {
                    rte_free(cms->counters[buf][d]);
                }
            }
            rte_free(cms->counters[buf]);
            cms->counters[buf] = NULL;
        }
    }

    RTE_LOG(INFO, CMS, "Count-Min Sketch cleanup complete\n");
}

// ==================== Core Operations ====================

void cms_add(struct count_min_sketch *cms, uint32_t key, uint32_t count) {
    if (!cms || !cms->counters[cms->active_buffer]) {
        return;
    }

    // Check for window rotation
    cms_rotate_if_needed(cms);

    uint8_t buf = cms->active_buffer;
    uint32_t width = cms->width;
    uint32_t depth = cms->depth;

    // Increment all counters for this key (one per hash function)
    for (uint32_t d = 0; d < depth; d++) {
        uint32_t idx = cms_hash(key, cms->seeds[d], width);
        __atomic_add_fetch(&cms->counters[buf][d][idx], count, __ATOMIC_RELAXED);
    }

    __atomic_add_fetch(&cms->total_updates, count, __ATOMIC_RELAXED);
    __atomic_add_fetch(&cms->window_updates, count, __ATOMIC_RELAXED);
}

uint32_t cms_add_and_query(struct count_min_sketch *cms, uint32_t key, uint32_t count) {
    if (!cms || !cms->counters[cms->active_buffer]) {
        return 0;
    }

    // Check for window rotation
    cms_rotate_if_needed(cms);

    uint8_t buf = cms->active_buffer;
    uint32_t width = cms->width;
    uint32_t depth = cms->depth;
    uint32_t min_count = UINT32_MAX;

    // Increment and track minimum
    for (uint32_t d = 0; d < depth; d++) {
        uint32_t idx = cms_hash(key, cms->seeds[d], width);
        uint32_t new_val = __atomic_add_fetch(&cms->counters[buf][d][idx],
                                               count, __ATOMIC_RELAXED);
        if (new_val < min_count) {
            min_count = new_val;
        }
    }

    __atomic_add_fetch(&cms->total_updates, count, __ATOMIC_RELAXED);
    __atomic_add_fetch(&cms->window_updates, count, __ATOMIC_RELAXED);

    return min_count;
}

uint32_t cms_query(const struct count_min_sketch *cms, uint32_t key) {
    if (!cms || !cms->counters[cms->active_buffer]) {
        return 0;
    }

    uint8_t buf = cms->active_buffer;
    uint32_t width = cms->width;
    uint32_t depth = cms->depth;
    uint32_t min_count = UINT32_MAX;

    // Return minimum count across all hash functions
    for (uint32_t d = 0; d < depth; d++) {
        uint32_t idx = cms_hash(key, cms->seeds[d], width);
        uint32_t val = __atomic_load_n(&cms->counters[buf][d][idx], __ATOMIC_RELAXED);
        if (val < min_count) {
            min_count = val;
        }
    }

    return (min_count == UINT32_MAX) ? 0 : min_count;
}

bool cms_exceeds_threshold(const struct count_min_sketch *cms, uint32_t key,
                           uint32_t threshold) {
    if (!cms || !cms->counters[cms->active_buffer]) {
        return false;
    }

    uint8_t buf = cms->active_buffer;
    uint32_t width = cms->width;
    uint32_t depth = cms->depth;
    uint32_t min_count = UINT32_MAX;

    // Short-circuit: if ALL counters are > threshold, key definitely exceeds
    // But we need the minimum to be accurate
    for (uint32_t d = 0; d < depth; d++) {
        uint32_t idx = cms_hash(key, cms->seeds[d], width);
        uint32_t val = __atomic_load_n(&cms->counters[buf][d][idx], __ATOMIC_RELAXED);

        if (val < min_count) {
            min_count = val;
        }

        // Early exit: if any counter is <= threshold, minimum is too
        if (val <= threshold) {
            return false;
        }
    }

    return min_count > threshold;
}

// ==================== Window Management ====================

bool cms_rotate_if_needed(struct count_min_sketch *cms) {
    if (!cms || cms->window_duration_tsc == 0) {
        return false;  // No windowing configured
    }

    uint64_t now = rte_get_tsc_cycles();
    uint64_t window_start = __atomic_load_n(&cms->window_start_tsc, __ATOMIC_RELAXED);
    uint64_t elapsed = now - window_start;

    if (elapsed < cms->window_duration_tsc) {
        return false;  // Window not expired
    }

    // Try to claim rotation (only one thread should rotate)
    if (!__atomic_compare_exchange_n(&cms->window_start_tsc,
                                      &window_start, now,
                                      false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
        return false;  // Another thread already rotating
    }

    // Swap buffers
    uint8_t old_buf = cms->active_buffer;
    uint8_t new_buf = 1 - old_buf;

    // Clear the new buffer before swapping
    for (uint32_t d = 0; d < cms->depth; d++) {
        memset(cms->counters[new_buf][d], 0, cms->width * sizeof(uint32_t));
    }

    // Memory barrier before making new buffer visible
    __atomic_thread_fence(__ATOMIC_RELEASE);

    // Atomic swap
    __atomic_store_n(&cms->active_buffer, new_buf, __ATOMIC_RELEASE);

    // Reset window counter
    __atomic_store_n(&cms->window_updates, 0, __ATOMIC_RELAXED);
    __atomic_add_fetch(&cms->rotations, 1, __ATOMIC_RELAXED);

    return true;
}

void cms_force_rotate(struct count_min_sketch *cms) {
    if (!cms) {
        return;
    }

    uint8_t old_buf = cms->active_buffer;
    uint8_t new_buf = 1 - old_buf;

    // Clear the new buffer
    for (uint32_t d = 0; d < cms->depth; d++) {
        memset(cms->counters[new_buf][d], 0, cms->width * sizeof(uint32_t));
    }

    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_store_n(&cms->active_buffer, new_buf, __ATOMIC_RELEASE);
    __atomic_store_n(&cms->window_start_tsc, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
    __atomic_store_n(&cms->window_updates, 0, __ATOMIC_RELAXED);
    __atomic_add_fetch(&cms->rotations, 1, __ATOMIC_RELAXED);
}

void cms_clear(struct count_min_sketch *cms) {
    if (!cms) {
        return;
    }

    for (int buf = 0; buf < 2; buf++) {
        if (cms->counters[buf]) {
            for (uint32_t d = 0; d < cms->depth; d++) {
                if (cms->counters[buf][d]) {
                    memset(cms->counters[buf][d], 0, cms->width * sizeof(uint32_t));
                }
            }
        }
    }

    cms->total_updates = 0;
    cms->window_updates = 0;
    cms->window_start_tsc = rte_get_tsc_cycles();
}

// ==================== Statistics ====================

void cms_get_stats(const struct count_min_sketch *cms, uint64_t *total_updates,
                   uint64_t *window_updates, uint64_t *rotations) {
    if (!cms) {
        if (total_updates) *total_updates = 0;
        if (window_updates) *window_updates = 0;
        if (rotations) *rotations = 0;
        return;
    }

    if (total_updates) {
        *total_updates = __atomic_load_n(&cms->total_updates, __ATOMIC_RELAXED);
    }
    if (window_updates) {
        *window_updates = __atomic_load_n(&cms->window_updates, __ATOMIC_RELAXED);
    }
    if (rotations) {
        *rotations = __atomic_load_n(&cms->rotations, __ATOMIC_RELAXED);
    }
}

size_t cms_memory_usage(const struct count_min_sketch *cms) {
    if (!cms) {
        return 0;
    }

    // Two buffers, depth rows, width counters each
    size_t counter_mem = 2 * cms->depth * cms->width * sizeof(uint32_t);
    // Row pointer arrays
    size_t pointer_mem = 2 * cms->depth * sizeof(uint32_t *);
    // Structure overhead
    size_t struct_mem = sizeof(struct count_min_sketch);

    return counter_mem + pointer_mem + struct_mem;
}

// ==================== Advanced Features ====================

int cms_merge(struct count_min_sketch *dst, const struct count_min_sketch *src) {
    if (!dst || !src) {
        return -1;
    }

    if (dst->width != src->width || dst->depth != src->depth) {
        RTE_LOG(ERR, CMS, "Cannot merge sketches with different dimensions\n");
        return -1;
    }

    uint8_t dst_buf = dst->active_buffer;
    uint8_t src_buf = src->active_buffer;

    // Add src counters to dst
    for (uint32_t d = 0; d < dst->depth; d++) {
        for (uint32_t w = 0; w < dst->width; w++) {
            uint32_t src_val = __atomic_load_n(&src->counters[src_buf][d][w],
                                                __ATOMIC_RELAXED);
            __atomic_add_fetch(&dst->counters[dst_buf][d][w], src_val,
                               __ATOMIC_RELAXED);
        }
    }

    dst->total_updates += src->total_updates;
    dst->window_updates += src->window_updates;

    return 0;
}

uint32_t cms_query_heavy_hitter(const struct count_min_sketch *cms, uint32_t key,
                                uint8_t threshold_pct, bool *is_heavy_hitter) {
    uint32_t count = cms_query(cms, key);

    if (is_heavy_hitter) {
        uint64_t total = __atomic_load_n(&cms->window_updates, __ATOMIC_RELAXED);
        uint64_t threshold = (total * threshold_pct) / 100;
        *is_heavy_hitter = (count > threshold);
    }

    return count;
}
