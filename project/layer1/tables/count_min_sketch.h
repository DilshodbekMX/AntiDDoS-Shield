#ifndef LAYER1_COUNT_MIN_SKETCH_H
#define LAYER1_COUNT_MIN_SKETCH_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_cycles.h>

/**
 * @file count_min_sketch.h
 * @brief Lock-free Count-Min Sketch for high-speed rate estimation
 *
 * Count-Min Sketch is a probabilistic data structure that provides
 * approximate frequency counts with bounded overestimation.
 *
 * Properties:
 * - Space efficient: O(w * d) where w=width, d=depth (num hashes)
 * - Query time: O(d) - constant for fixed depth
 * - Never underestimates: Always returns count >= true count
 * - Bounded overestimation: With high probability, error < epsilon * total_count
 *
 * Used for UDP admission control:
 * - Track packet rates per source IP without full flow state
 * - Detect flood sources before creating expensive flow entries
 * - Acts as a "doorkeeper" to protect the flow table
 */

// ==================== Configuration ====================

/**
 * CMS dimensions determine accuracy vs memory tradeoff:
 * - Width (w): More width = less hash collisions = less overestimation
 * - Depth (d): More depth = higher confidence in estimates
 *
 * Memory = w * d * sizeof(uint32_t) bytes
 * Error bound: epsilon = e / w (with probability 1 - 1/e^d)
 *
 * Default: 65536 * 4 * 4 = 1MB per sketch
 */
#define CMS_DEFAULT_WIDTH       65536   // 2^16 - good for ~100K unique IPs
#define CMS_DEFAULT_DEPTH       4       // 4 hash functions - 98.2% confidence
#define CMS_MAX_WIDTH           (1 << 20)  // 1M buckets max
#define CMS_MAX_DEPTH           8       // 8 hash functions max

// ==================== Data Structures ====================

/**
 * Time-windowed Count-Min Sketch
 * Uses double-buffering for atomic window rotation
 */
struct count_min_sketch {
    // Sketch dimensions (immutable after init)
    uint32_t width;
    uint32_t depth;

    // Counter arrays - two for double buffering
    // counters[active_buffer][depth][width]
    uint32_t **counters[2];

    // Active buffer index (0 or 1)
    uint8_t active_buffer;
    uint8_t _pad[3];

    // Time window management
    uint64_t window_start_tsc;
    uint64_t window_duration_tsc;

    // Statistics
    uint64_t total_updates;
    uint64_t window_updates;
    uint64_t rotations;

    // Hash seeds (one per depth level)
    uint32_t seeds[CMS_MAX_DEPTH];
};

// ==================== Public API ====================

/**
 * Initialize Count-Min Sketch with specified dimensions.
 *
 * @param cms              Sketch structure to initialize
 * @param width            Number of counters per hash function (power of 2 recommended)
 * @param depth            Number of hash functions
 * @param window_sec       Time window duration in seconds (0 = no windowing)
 * @return 0 on success, -1 on error
 */
int cms_init(struct count_min_sketch *cms, uint32_t width, uint32_t depth,
             uint32_t window_sec);

/**
 * Initialize with default parameters optimized for DDoS protection.
 * Uses CMS_DEFAULT_WIDTH, CMS_DEFAULT_DEPTH, and 1-second windows.
 *
 * @param cms  Sketch structure to initialize
 * @return 0 on success, -1 on error
 */
int cms_init_default(struct count_min_sketch *cms);

/**
 * Cleanup and free sketch memory.
 *
 * @param cms  Sketch to cleanup
 */
void cms_cleanup(struct count_min_sketch *cms);

/**
 * Increment counter for a key (typically IP address).
 * Thread-safe via atomic operations.
 *
 * @param cms    Sketch
 * @param key    Key to increment (e.g., source IP)
 * @param count  Amount to add (typically 1)
 */
void cms_add(struct count_min_sketch *cms, uint32_t key, uint32_t count);

/**
 * Increment counter for a key and return estimated count.
 * More efficient than separate add + query.
 *
 * @param cms    Sketch
 * @param key    Key to increment
 * @param count  Amount to add
 * @return Estimated count after increment
 */
uint32_t cms_add_and_query(struct count_min_sketch *cms, uint32_t key, uint32_t count);

/**
 * Query estimated count for a key.
 * Thread-safe - can be called concurrently with add.
 *
 * @param cms  Sketch
 * @param key  Key to query
 * @return Estimated count (minimum across all hash functions)
 */
uint32_t cms_query(const struct count_min_sketch *cms, uint32_t key);

/**
 * Check if key exceeds threshold.
 * Optimized to short-circuit when threshold is exceeded.
 *
 * @param cms        Sketch
 * @param key        Key to check
 * @param threshold  Maximum allowed count
 * @return true if count > threshold
 */
bool cms_exceeds_threshold(const struct count_min_sketch *cms, uint32_t key,
                           uint32_t threshold);

/**
 * Rotate time window (called periodically or on first packet after window expires).
 * Swaps active buffer and clears the new active buffer.
 *
 * @param cms  Sketch
 * @return true if rotation occurred
 */
bool cms_rotate_if_needed(struct count_min_sketch *cms);

/**
 * Force window rotation (for maintenance thread).
 *
 * @param cms  Sketch
 */
void cms_force_rotate(struct count_min_sketch *cms);

/**
 * Clear all counters (both buffers).
 *
 * @param cms  Sketch
 */
void cms_clear(struct count_min_sketch *cms);

/**
 * Get sketch statistics.
 *
 * @param cms             Sketch
 * @param total_updates   Output: total updates since init
 * @param window_updates  Output: updates in current window
 * @param rotations       Output: number of window rotations
 */
void cms_get_stats(const struct count_min_sketch *cms, uint64_t *total_updates,
                   uint64_t *window_updates, uint64_t *rotations);

/**
 * Get memory usage in bytes.
 *
 * @param cms  Sketch
 * @return Memory usage in bytes
 */
size_t cms_memory_usage(const struct count_min_sketch *cms);

// ==================== Advanced Features ====================

/**
 * Merge two sketches (useful for per-core sketches).
 * Result is stored in dst.
 *
 * @param dst  Destination sketch (will contain merged result)
 * @param src  Source sketch to merge from
 * @return 0 on success, -1 if dimensions don't match
 */
int cms_merge(struct count_min_sketch *dst, const struct count_min_sketch *src);

/**
 * Query with heavy hitter detection.
 * Returns count and sets is_heavy_hitter if count exceeds threshold.
 *
 * @param cms              Sketch
 * @param key              Key to query
 * @param threshold_pct    Percentage of total updates (0-100)
 * @param is_heavy_hitter  Output: true if key is a heavy hitter
 * @return Estimated count
 */
uint32_t cms_query_heavy_hitter(const struct count_min_sketch *cms, uint32_t key,
                                uint8_t threshold_pct, bool *is_heavy_hitter);

#endif // LAYER1_COUNT_MIN_SKETCH_H
