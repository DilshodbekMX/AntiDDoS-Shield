#ifndef LAYER1_HYPERLOGLOG_H
#define LAYER1_HYPERLOGLOG_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @file hyperloglog.h
 * @brief HyperLogLog for cardinality estimation (unique IP counting)
 *
 * Stage 11B: Probabilistic counting for DDoS detection
 *
 * HyperLogLog estimates the number of unique items (cardinality) in a stream
 * with very low memory overhead. Perfect for detecting DDoS attacks where
 * we need to track unique source IPs without storing each one.
 *
 * Memory usage:
 * - 14 bits precision (HLL_P=14): 16384 registers = ~16KB
 * - Typical error: 0.81% (1.04/sqrt(m) where m=2^p)
 *
 * Features:
 * - Lock-free updates using atomic operations
 * - Per-time-window tracking for anomaly detection
 * - Mergeable sketches for distributed counting
 * - DPDK-optimized with cache-aligned structures
 */

// ==================== Configuration ====================

// Precision (number of bits for register index)
// p=14 gives 16384 registers, ~0.81% error, ~16KB memory
#define HLL_P           14
#define HLL_REGISTERS   (1 << HLL_P)      // 16384
#define HLL_P_MASK      (HLL_REGISTERS - 1)

// Maximum register value (6 bits = 0-63)
#define HLL_REGISTER_MAX 63

// Alpha constant for bias correction (depends on m)
// For m >= 128: alpha_m ~= 0.7213 / (1 + 1.079/m)
#define HLL_ALPHA_INF   0.7213

// ==================== Data Structures ====================

/**
 * HyperLogLog sketch - cache-aligned for DPDK
 */
struct hyperloglog {
    uint8_t registers[HLL_REGISTERS];    // Register array (16384 bytes)
    uint64_t updates;                     // Total update count
    uint64_t last_reset_tsc;              // TSC when last reset
    uint8_t  _pad[48];                    // Pad to 16KB + 64 bytes
} __attribute__((aligned(64)));

/**
 * Time-windowed HyperLogLog for anomaly detection
 * Tracks unique IPs over multiple time windows
 */
struct hll_windowed {
    struct hyperloglog current;           // Current window
    struct hyperloglog previous;          // Previous window (for comparison)

    uint32_t window_sec;                  // Window duration in seconds
    uint64_t window_start_tsc;            // When current window started
    uint64_t hz;                          // TSC frequency for time conversion

    // Cardinality history (circular buffer)
    uint64_t history[16];                 // Last 16 window cardinalities
    uint32_t history_idx;                 // Current history index
    uint32_t history_count;               // Number of valid history entries

    // Statistics
    uint64_t total_updates;               // Total updates across all windows
    uint64_t window_switches;             // Number of window switches
    double   baseline_cardinality;        // Baseline cardinality for anomaly detection
    double   max_cardinality;             // Maximum cardinality seen

    uint8_t  _pad[16];
} __attribute__((aligned(64)));

// ==================== Core HLL API ====================

/**
 * Initialize HyperLogLog sketch
 *
 * @param hll  HyperLogLog structure to initialize
 */
void hll_init(struct hyperloglog *hll);

/**
 * Add an item to the HyperLogLog sketch
 * Thread-safe using atomic operations
 *
 * @param hll   HyperLogLog structure
 * @param hash  Hash of the item (use pre-computed hash for performance)
 */
void hll_add(struct hyperloglog *hll, uint64_t hash);

/**
 * Add an IP address to the HyperLogLog sketch
 * Convenience function that hashes the IP first
 *
 * @param hll  HyperLogLog structure
 * @param ip   IP address (network byte order)
 */
void hll_add_ip(struct hyperloglog *hll, uint32_t ip);

/**
 * Estimate cardinality (unique count)
 *
 * @param hll  HyperLogLog structure
 * @return Estimated cardinality
 */
uint64_t hll_count(const struct hyperloglog *hll);

/**
 * Reset HyperLogLog sketch
 *
 * @param hll  HyperLogLog structure
 */
void hll_reset(struct hyperloglog *hll);

/**
 * Merge two HyperLogLog sketches (union)
 * Result is stored in dst: dst = union(dst, src)
 *
 * @param dst  Destination sketch (modified)
 * @param src  Source sketch (unchanged)
 */
void hll_merge(struct hyperloglog *dst, const struct hyperloglog *src);

/**
 * Get the standard error for this HLL configuration
 *
 * @return Standard error as a fraction (e.g., 0.0081 for 0.81%)
 */
double hll_standard_error(void);

// ==================== Windowed HLL API ====================

/**
 * Initialize windowed HyperLogLog
 *
 * @param whll        Windowed HLL structure
 * @param window_sec  Window duration in seconds
 */
void hll_windowed_init(struct hll_windowed *whll, uint32_t window_sec);

/**
 * Add an IP to windowed HLL (handles window rotation)
 *
 * @param whll  Windowed HLL structure
 * @param ip    IP address (network byte order)
 */
void hll_windowed_add_ip(struct hll_windowed *whll, uint32_t ip);

/**
 * Get current window cardinality estimate
 *
 * @param whll  Windowed HLL structure
 * @return Estimated unique IPs in current window
 */
uint64_t hll_windowed_count(struct hll_windowed *whll);

/**
 * Get previous window cardinality
 *
 * @param whll  Windowed HLL structure
 * @return Cardinality from previous window
 */
uint64_t hll_windowed_count_previous(const struct hll_windowed *whll);

/**
 * Check for anomaly (significant cardinality increase)
 *
 * @param whll       Windowed HLL structure
 * @param threshold  Multiplier threshold (e.g., 2.0 = 2x increase is anomaly)
 * @return true if anomaly detected
 */
bool hll_windowed_is_anomaly(struct hll_windowed *whll, double threshold);

/**
 * Update baseline cardinality from history
 *
 * @param whll  Windowed HLL structure
 */
void hll_windowed_update_baseline(struct hll_windowed *whll);

/**
 * Get statistics
 *
 * @param whll  Windowed HLL structure
 * @param baseline_out        Output: baseline cardinality
 * @param max_out             Output: maximum cardinality seen
 * @param window_switches_out Output: number of window switches
 */
void hll_windowed_get_stats(const struct hll_windowed *whll,
                            double *baseline_out,
                            double *max_out,
                            uint64_t *window_switches_out);

// ==================== Global HLL Instances ====================

/**
 * Initialize global HLL instances for Layer 1
 * Creates windowed HLL for source IP tracking
 *
 * @param window_sec  Window duration in seconds (default: 60)
 * @return 0 on success, -1 on error
 */
int hll_global_init(uint32_t window_sec);

/**
 * Cleanup global HLL instances
 */
void hll_global_cleanup(void);

/**
 * Add source IP to global tracker
 * Call this from fast path for every packet
 *
 * @param src_ip  Source IP (network byte order)
 */
void hll_global_add_src_ip(uint32_t src_ip);

/**
 * Get current unique source IP estimate
 *
 * @return Estimated unique source IPs in current window
 */
uint64_t hll_global_src_ip_count(void);

/**
 * Check for unique IP anomaly
 *
 * @param threshold  Anomaly threshold multiplier
 * @return true if anomaly detected
 */
bool hll_global_check_anomaly(double threshold);

/**
 * Print HLL statistics
 */
void hll_print_stats(void);

#endif // LAYER1_HYPERLOGLOG_H
