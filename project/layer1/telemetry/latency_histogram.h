#ifndef LATENCY_HISTOGRAM_H
#define LATENCY_HISTOGRAM_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_lcore.h>

/**
 * @file latency_histogram.h
 * @brief Latency Histogram Tracking
 *
 * Tracks latency distributions for key operations:
 * - SYN->SYN-ACK latency (backend responsiveness)
 * - Request->Response latency per flow
 * - Processing latency within Layer 1
 *
 * Uses logarithmic bucketing to efficiently capture the full range
 * of latencies from microseconds to seconds.
 *
 * Bucket ranges (logarithmic):
 *   0: 0-10us
 *   1: 10-50us
 *   2: 50-100us
 *   3: 100-500us
 *   4: 500us-1ms
 *   5: 1-5ms
 *   6: 5-10ms
 *   7: 10-50ms
 *   8: 50-100ms
 *   9: 100-500ms
 *  10: 500ms-1s
 *  11: 1-5s
 *  12: >5s
 */

// ==================== Configuration ====================

#define LATENCY_HIST_BUCKETS     13     // Number of buckets
#define LATENCY_HIST_OVERFLOW    12     // Index of overflow bucket

// Bucket boundaries in microseconds
static const uint64_t latency_bucket_boundaries_us[] = {
    10,       // Bucket 0: 0-10us
    50,       // Bucket 1: 10-50us
    100,      // Bucket 2: 50-100us
    500,      // Bucket 3: 100-500us
    1000,     // Bucket 4: 500us-1ms
    5000,     // Bucket 5: 1-5ms
    10000,    // Bucket 6: 5-10ms
    50000,    // Bucket 7: 10-50ms
    100000,   // Bucket 8: 50-100ms
    500000,   // Bucket 9: 100-500ms
    1000000,  // Bucket 10: 500ms-1s
    5000000,  // Bucket 11: 1-5s
    UINT64_MAX // Bucket 12: >5s (overflow)
};

// ==================== Histogram Types ====================

enum latency_type {
    LAT_TYPE_SYN_SYNACK = 0,    // SYN to SYN-ACK (backend latency)
    LAT_TYPE_PROCESSING,        // Internal processing latency
    LAT_TYPE_MAX
};

// ==================== Per-Lcore Histogram ====================

/**
 * Per-lcore histogram to avoid contention
 */
struct latency_histogram {
    uint64_t buckets[LATENCY_HIST_BUCKETS];
    uint64_t count;
    uint64_t sum_us;        // Sum for mean calculation
    uint64_t min_us;
    uint64_t max_us;
} __attribute__((aligned(64)));

// ==================== Public API ====================

/**
 * Initialize latency histogram subsystem
 *
 * @return 0 on success, -1 on error
 */
int latency_histogram_init(void);

/**
 * Cleanup latency histogram subsystem
 */
void latency_histogram_cleanup(void);

/**
 * Record a latency measurement
 *
 * @param type       Type of latency being recorded
 * @param latency_us Latency in microseconds
 */
void latency_histogram_record(enum latency_type type, uint64_t latency_us);

/**
 * Record a latency measurement using TSC delta
 * Converts TSC cycles to microseconds automatically
 *
 * @param type       Type of latency being recorded
 * @param tsc_delta  Latency in TSC cycles
 */
void latency_histogram_record_tsc(enum latency_type type, uint64_t tsc_delta);

/**
 * Get aggregated histogram for a latency type
 *
 * @param type    Type of latency to get
 * @param hist    Output histogram (aggregated from all lcores)
 */
void latency_histogram_get(enum latency_type type, struct latency_histogram *hist);

/**
 * Get percentile value from histogram
 *
 * @param hist        Histogram to analyze
 * @param percentile  Percentile to get (0-100, e.g., 50 for median, 99 for P99)
 * @return Approximate latency in microseconds at the given percentile
 */
uint64_t latency_histogram_percentile(const struct latency_histogram *hist, int percentile);

/**
 * Get mean latency from histogram
 *
 * @param hist  Histogram to analyze
 * @return Mean latency in microseconds
 */
static inline uint64_t latency_histogram_mean(const struct latency_histogram *hist) {
    if (hist->count == 0) return 0;
    return hist->sum_us / hist->count;
}

/**
 * Reset all histograms (for new measurement window)
 */
void latency_histogram_reset(void);

/**
 * Print histogram to stdout (debugging)
 *
 * @param type  Type of latency to print
 */
void latency_histogram_print(enum latency_type type);

/**
 * Get bucket index for a latency value
 */
static inline int latency_get_bucket(uint64_t latency_us) {
    for (int i = 0; i < LATENCY_HIST_OVERFLOW; i++) {
        if (latency_us < latency_bucket_boundaries_us[i]) {
            return i;
        }
    }
    return LATENCY_HIST_OVERFLOW;
}

/**
 * Get bucket label string
 */
const char* latency_bucket_label(int bucket);

/**
 * Get latency type name
 */
const char* latency_type_str(enum latency_type type);

#endif // LATENCY_HISTOGRAM_H
