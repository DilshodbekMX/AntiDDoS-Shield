#ifndef SPIKE_DETECTOR_H
#define SPIKE_DETECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_hash.h>
#include <rte_lcore.h>

/**
 * @file spike_detector.h
 * @brief Fast-path Spike Detection
 *
 * Ultra-lightweight spike detection for the fast path.
 * Uses per-lcore counters and sub-second sliding windows to detect
 * sudden rate increases without waiting for full Layer 2 analysis.
 *
 * Design goals:
 * - Zero contention in fast path (per-lcore counters)
 * - Sub-millisecond overhead per packet
 * - ~100ms detection latency (vs 1-2s for L2)
 *
 * Detection mechanism:
 * - Maintains 10 x 100ms windows = 1 second history
 * - Compares current window rate vs moving average
 * - Triggers if current > (avg * multiplier)
 *
 * Memory: ~40 bytes per protected IP per lcore
 */

// ==================== Configuration ====================

#define SPIKE_WINDOW_COUNT      10      // Number of windows in sliding buffer
#define SPIKE_WINDOW_MS         100     // Window duration in milliseconds
#define SPIKE_DETECT_MULTIPLIER 3.0     // Spike = current > avg * multiplier
#define SPIKE_MIN_RATE_PPS      1000    // Minimum rate to consider (avoid noise)

// ==================== Spike State Per IP ====================

/**
 * Per-lcore spike tracking for a single protected IP
 * Extremely compact - fits in a cache line
 */
struct spike_window {
    uint64_t packet_count[SPIKE_WINDOW_COUNT];  // Ring buffer of counts
    uint64_t current_count;                     // Current window accumulator
    uint64_t window_start_tsc;                  // TSC when current window started
    uint8_t  current_idx;                       // Current window index
    uint8_t  filled_windows;                    // Number of valid historical windows
    uint8_t  spike_detected;                    // 1 if spike detected this cycle
    uint8_t  _pad[5];
} __attribute__((aligned(64)));

/**
 * Per-IP spike detector state
 * Contains per-lcore windows for lock-free tracking
 */
struct spike_detector {
    uint32_t dst_ip;                            // Protected IP (network byte order)
    uint32_t active;                            // 1 if active

    // Per-lcore spike windows (indexed by lcore_id)
    // Only allocate for active lcores to save memory
    struct spike_window *lcore_windows;         // Array[RTE_MAX_LCORE]

    // Aggregated spike detection state (updated by control thread)
    uint64_t last_aggregate_tsc;
    uint64_t aggregate_rate_pps;                // Aggregated rate from all lcores
    uint64_t baseline_rate_pps;                 // Moving average baseline
    double   spike_ratio;                       // current / baseline ratio
    bool     spike_active;                      // True if spike in progress
    uint32_t spike_count;                       // Number of spikes detected
};

// ==================== Global State ====================

/**
 * Initialize spike detector subsystem
 *
 * @param max_ips  Maximum protected IPs to track
 * @return 0 on success, -1 on error
 */
int spike_detector_init(uint32_t max_ips);

/**
 * Cleanup spike detector
 */
void spike_detector_cleanup(void);

/**
 * Register a protected IP for spike detection
 *
 * @param dst_ip  Protected IP (network byte order)
 * @return 0 on success, -1 on error
 */
int spike_detector_register(uint32_t dst_ip);

/**
 * Unregister a protected IP
 *
 * @param dst_ip  Protected IP (network byte order)
 * @return 0 on success, -1 on error
 */
int spike_detector_unregister(uint32_t dst_ip);

// ==================== Fast Path API ====================

/**
 * Record a packet for spike detection (call from fast path)
 * Extremely lightweight - just increments counter
 *
 * @param dst_ip    Protected destination IP (network byte order)
 * @param lcore_id  Current lcore ID
 * @return true if spike detected for this IP, false otherwise
 */
static inline bool spike_detector_record(uint32_t dst_ip, unsigned int lcore_id);

/**
 * Get spike detector for an IP (internal use)
 * Returns NULL if IP not registered
 */
struct spike_detector *spike_detector_lookup(uint32_t dst_ip);

/**
 * Check if spike is active for an IP (fast path query)
 *
 * @param dst_ip  Protected IP
 * @return true if spike currently active
 */
bool spike_detector_is_spiking(uint32_t dst_ip);

// ==================== Control Path API ====================

/**
 * Aggregate spike detection from all lcores
 * Call periodically from control thread (~100ms)
 *
 * @return Number of IPs currently in spike state
 */
uint32_t spike_detector_aggregate(void);

/**
 * Get spike info for an IP
 *
 * @param dst_ip       Protected IP
 * @param rate_pps     Output: Current aggregated rate
 * @param baseline_pps Output: Baseline rate
 * @param ratio        Output: Current spike ratio
 * @return true if spike active, false otherwise
 */
bool spike_detector_get_info(uint32_t dst_ip,
                             uint64_t *rate_pps,
                             uint64_t *baseline_pps,
                             double *ratio);

/**
 * Get statistics
 */
uint32_t spike_detector_active_count(void);
uint32_t spike_detector_spike_count(void);

// ==================== Inline Implementation ====================

// Forward declaration for internal use
extern struct rte_hash *g_spike_hash;
extern struct spike_detector *g_spike_pool;

/**
 * Fast path: Record packet and check for spike
 * This is the hot path - must be extremely fast
 */
static inline bool spike_detector_record(uint32_t dst_ip, unsigned int lcore_id) {
    extern struct rte_hash *g_spike_hash;
    extern struct spike_detector *g_spike_pool;

    if (!g_spike_hash || !g_spike_pool) {
        return false;
    }

    // Lookup protected IP
    int32_t idx = rte_hash_lookup(g_spike_hash, &dst_ip);
    if (idx < 0) {
        return false;  // Not a protected IP
    }

    struct spike_detector *sd = &g_spike_pool[idx];
    if (!sd->active || !sd->lcore_windows) {
        return false;
    }

    // Get this lcore's window
    struct spike_window *sw = &sd->lcore_windows[lcore_id];

    // Increment current window count (no atomics needed - per-lcore)
    sw->current_count++;

    // Return cached spike state (updated by control thread)
    // This avoids expensive TSC reads in fast path
    return sd->spike_active;
}

#endif // SPIKE_DETECTOR_H
