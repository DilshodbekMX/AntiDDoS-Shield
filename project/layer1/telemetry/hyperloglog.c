#include "hyperloglog.h"
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_hash_crc.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#define RTE_LOGTYPE_HLL RTE_LOGTYPE_USER7

// ==================== Global State ====================

static struct hll_windowed *global_src_ip_hll = NULL;

// ==================== Hash Functions ====================

/**
 * Fast hash for HLL using CRC32 intrinsics
 * Returns a well-distributed 64-bit hash
 */
static inline uint64_t hll_hash64(uint32_t value) {
    // Use CRC32 twice with different seeds for 64-bit distribution
    uint32_t lo = rte_hash_crc_4byte(value, 0x12345678);
    uint32_t hi = rte_hash_crc_4byte(value, 0x87654321);
    return ((uint64_t)hi << 32) | lo;
}

/**
 * Count leading zeros in 64-bit value
 * Returns 1-64 (we add 1 because HLL needs position of first 1)
 */
static inline uint8_t count_leading_zeros_plus_one(uint64_t value) {
    if (value == 0) return 64;
    return (uint8_t)(__builtin_clzll(value) + 1);
}

// ==================== Core HLL Implementation ====================

void hll_init(struct hyperloglog *hll) {
    if (!hll) return;

    memset(hll->registers, 0, HLL_REGISTERS);
    __atomic_store_n(&hll->updates, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&hll->last_reset_tsc, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
}

void hll_add(struct hyperloglog *hll, uint64_t hash) {
    if (!hll) return;

    // Split hash: low bits for register index, high bits for counting
    uint32_t index = hash & HLL_P_MASK;
    uint64_t remaining = hash >> HLL_P;

    // Count leading zeros + 1 (position of first 1 bit)
    uint8_t rho = count_leading_zeros_plus_one(remaining);
    if (rho > HLL_REGISTER_MAX) {
        rho = HLL_REGISTER_MAX;
    }

    // Atomic max update
    // We use a simple compare-and-swap loop
    uint8_t current;
    do {
        current = __atomic_load_n(&hll->registers[index], __ATOMIC_RELAXED);
        if (rho <= current) {
            break;  // Current value is already >= rho
        }
    } while (!__atomic_compare_exchange_n(&hll->registers[index],
                                          &current, rho,
                                          true,  // weak
                                          __ATOMIC_RELAXED,
                                          __ATOMIC_RELAXED));

    __atomic_add_fetch(&hll->updates, 1, __ATOMIC_RELAXED);
}

void hll_add_ip(struct hyperloglog *hll, uint32_t ip) {
    if (!hll) return;

    uint64_t hash = hll_hash64(ip);
    hll_add(hll, hash);
}

/**
 * Compute the raw HLL estimate using harmonic mean
 */
static double hll_raw_estimate(const struct hyperloglog *hll) {
    double sum = 0.0;
    uint32_t zero_count = 0;

    for (uint32_t i = 0; i < HLL_REGISTERS; i++) {
        uint8_t reg = __atomic_load_n(&hll->registers[i], __ATOMIC_RELAXED);
        sum += 1.0 / (1ULL << reg);
        if (reg == 0) {
            zero_count++;
        }
    }

    // Alpha constant for bias correction
    double alpha;
    if (HLL_REGISTERS == 16) {
        alpha = 0.673;
    } else if (HLL_REGISTERS == 32) {
        alpha = 0.697;
    } else if (HLL_REGISTERS == 64) {
        alpha = 0.709;
    } else {
        alpha = HLL_ALPHA_INF / (1.0 + 1.079 / HLL_REGISTERS);
    }

    double estimate = alpha * HLL_REGISTERS * HLL_REGISTERS / sum;

    // Small range correction using linear counting
    if (estimate <= 2.5 * HLL_REGISTERS && zero_count > 0) {
        estimate = HLL_REGISTERS * log((double)HLL_REGISTERS / zero_count);
    }

    // Large range correction (not typically needed for IP counting)
    // Skip for now as we won't hit 2^32 unique IPs

    return estimate;
}

uint64_t hll_count(const struct hyperloglog *hll) {
    if (!hll) return 0;

    double estimate = hll_raw_estimate(hll);
    return (uint64_t)(estimate + 0.5);  // Round to nearest integer
}

void hll_reset(struct hyperloglog *hll) {
    if (!hll) return;

    memset(hll->registers, 0, HLL_REGISTERS);
    __atomic_store_n(&hll->updates, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&hll->last_reset_tsc, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
}

void hll_merge(struct hyperloglog *dst, const struct hyperloglog *src) {
    if (!dst || !src) return;

    // Take maximum of each register
    for (uint32_t i = 0; i < HLL_REGISTERS; i++) {
        uint8_t src_val = __atomic_load_n(&src->registers[i], __ATOMIC_RELAXED);
        uint8_t dst_val;

        do {
            dst_val = __atomic_load_n(&dst->registers[i], __ATOMIC_RELAXED);
            if (src_val <= dst_val) {
                break;
            }
        } while (!__atomic_compare_exchange_n(&dst->registers[i],
                                              &dst_val, src_val,
                                              true, __ATOMIC_RELAXED, __ATOMIC_RELAXED));
    }

    // Add update counts
    uint64_t src_updates = __atomic_load_n(&src->updates, __ATOMIC_RELAXED);
    __atomic_add_fetch(&dst->updates, src_updates, __ATOMIC_RELAXED);
}

double hll_standard_error(void) {
    // Standard error = 1.04 / sqrt(m) where m = number of registers
    return 1.04 / sqrt((double)HLL_REGISTERS);
}

// ==================== Windowed HLL Implementation ====================

void hll_windowed_init(struct hll_windowed *whll, uint32_t window_sec) {
    if (!whll) return;

    hll_init(&whll->current);
    hll_init(&whll->previous);

    whll->window_sec = window_sec > 0 ? window_sec : 60;
    whll->hz = rte_get_tsc_hz();
    whll->window_start_tsc = rte_get_tsc_cycles();

    memset(whll->history, 0, sizeof(whll->history));
    whll->history_idx = 0;
    whll->history_count = 0;

    whll->total_updates = 0;
    whll->window_switches = 0;
    whll->baseline_cardinality = 0.0;
    whll->max_cardinality = 0.0;

    RTE_LOG(INFO, HLL, "Windowed HLL initialized: window=%us, registers=%u, error=%.2f%%\n",
            whll->window_sec, HLL_REGISTERS, hll_standard_error() * 100.0);
}

/**
 * Check if window has expired and rotate if needed
 */
static void hll_windowed_check_rotate(struct hll_windowed *whll) {
    uint64_t now = rte_get_tsc_cycles();
    uint64_t window_tsc = (uint64_t)whll->window_sec * whll->hz;

    if ((now - whll->window_start_tsc) >= window_tsc) {
        // Get cardinality before rotating
        uint64_t current_count = hll_count(&whll->current);

        // Store in history
        whll->history[whll->history_idx] = current_count;
        whll->history_idx = (whll->history_idx + 1) % 16;
        if (whll->history_count < 16) {
            whll->history_count++;
        }

        // Update max
        if ((double)current_count > whll->max_cardinality) {
            whll->max_cardinality = (double)current_count;
        }

        // Rotate: current -> previous, reset current
        memcpy(whll->previous.registers, whll->current.registers, HLL_REGISTERS);
        whll->previous.updates = whll->current.updates;
        whll->previous.last_reset_tsc = whll->current.last_reset_tsc;

        hll_reset(&whll->current);
        whll->window_start_tsc = now;
        whll->window_switches++;

        RTE_LOG(DEBUG, HLL, "Window rotated: previous_count=%lu, switches=%lu\n",
                current_count, whll->window_switches);
    }
}

void hll_windowed_add_ip(struct hll_windowed *whll, uint32_t ip) {
    if (!whll) return;

    // Check for window rotation (periodically, not every packet)
    // We check every 1024 updates for performance
    uint64_t updates = __atomic_add_fetch(&whll->total_updates, 1, __ATOMIC_RELAXED);
    if ((updates & 0x3FF) == 0) {
        hll_windowed_check_rotate(whll);
    }

    hll_add_ip(&whll->current, ip);
}

uint64_t hll_windowed_count(struct hll_windowed *whll) {
    if (!whll) return 0;

    // Check for rotation before counting
    hll_windowed_check_rotate(whll);
    return hll_count(&whll->current);
}

uint64_t hll_windowed_count_previous(const struct hll_windowed *whll) {
    if (!whll) return 0;
    return hll_count(&whll->previous);
}

bool hll_windowed_is_anomaly(struct hll_windowed *whll, double threshold) {
    if (!whll || threshold <= 1.0) return false;

    // Check rotation first
    hll_windowed_check_rotate(whll);

    uint64_t current = hll_count(&whll->current);

    // Compare against baseline if available
    if (whll->baseline_cardinality > 0.0) {
        double ratio = (double)current / whll->baseline_cardinality;
        if (ratio >= threshold) {
            RTE_LOG(WARNING, HLL, "Cardinality anomaly: current=%lu baseline=%.0f ratio=%.2f\n",
                    current, whll->baseline_cardinality, ratio);
            return true;
        }
    }

    // Also compare against previous window
    uint64_t previous = hll_count(&whll->previous);
    if (previous > 100) {  // Need minimum data for comparison
        double ratio = (double)current / (double)previous;
        if (ratio >= threshold) {
            RTE_LOG(WARNING, HLL, "Cardinality spike: current=%lu previous=%lu ratio=%.2f\n",
                    current, previous, ratio);
            return true;
        }
    }

    return false;
}

void hll_windowed_update_baseline(struct hll_windowed *whll) {
    if (!whll || whll->history_count == 0) return;

    // Calculate median of history
    uint64_t sorted[16];
    memcpy(sorted, whll->history, sizeof(sorted));

    // Simple bubble sort (only 16 elements)
    for (uint32_t i = 0; i < whll->history_count - 1; i++) {
        for (uint32_t j = 0; j < whll->history_count - i - 1; j++) {
            if (sorted[j] > sorted[j + 1]) {
                uint64_t temp = sorted[j];
                sorted[j] = sorted[j + 1];
                sorted[j + 1] = temp;
            }
        }
    }

    // Use median as baseline (more robust than mean)
    uint32_t mid = whll->history_count / 2;
    if (whll->history_count % 2 == 0) {
        whll->baseline_cardinality = (double)(sorted[mid - 1] + sorted[mid]) / 2.0;
    } else {
        whll->baseline_cardinality = (double)sorted[mid];
    }

    RTE_LOG(INFO, HLL, "Updated baseline cardinality: %.0f (from %u windows)\n",
            whll->baseline_cardinality, whll->history_count);
}

void hll_windowed_get_stats(const struct hll_windowed *whll,
                            double *baseline_out,
                            double *max_out,
                            uint64_t *window_switches_out) {
    if (!whll) return;

    if (baseline_out) *baseline_out = whll->baseline_cardinality;
    if (max_out) *max_out = whll->max_cardinality;
    if (window_switches_out) *window_switches_out = whll->window_switches;
}

// ==================== Global HLL Instances ====================

int hll_global_init(uint32_t window_sec) {
    if (global_src_ip_hll != NULL) {
        RTE_LOG(WARNING, HLL, "Global HLL already initialized\n");
        return 0;
    }

    global_src_ip_hll = rte_zmalloc_socket("hll_src_ip",
                                           sizeof(struct hll_windowed),
                                           64,
                                           rte_socket_id());
    if (!global_src_ip_hll) {
        RTE_LOG(ERR, HLL, "Failed to allocate global HLL\n");
        return -1;
    }

    hll_windowed_init(global_src_ip_hll, window_sec);

    RTE_LOG(INFO, HLL, "Global HLL initialized:\n");
    RTE_LOG(INFO, HLL, "  Window: %u seconds\n", window_sec);
    RTE_LOG(INFO, HLL, "  Registers: %u\n", HLL_REGISTERS);
    RTE_LOG(INFO, HLL, "  Memory: ~%lu KB per sketch\n", sizeof(struct hyperloglog) / 1024);
    RTE_LOG(INFO, HLL, "  Expected error: %.2f%%\n", hll_standard_error() * 100.0);

    return 0;
}

void hll_global_cleanup(void) {
    if (global_src_ip_hll) {
        rte_free(global_src_ip_hll);
        global_src_ip_hll = NULL;
        RTE_LOG(INFO, HLL, "Global HLL cleanup complete\n");
    }
}

void hll_global_add_src_ip(uint32_t src_ip) {
    if (global_src_ip_hll) {
        hll_windowed_add_ip(global_src_ip_hll, src_ip);
    }
}

uint64_t hll_global_src_ip_count(void) {
    if (!global_src_ip_hll) return 0;
    return hll_windowed_count(global_src_ip_hll);
}

bool hll_global_check_anomaly(double threshold) {
    if (!global_src_ip_hll) return false;
    return hll_windowed_is_anomaly(global_src_ip_hll, threshold);
}

void hll_print_stats(void) {
    if (!global_src_ip_hll) {
        printf("HyperLogLog: Not initialized\n");
        return;
    }

    printf("\n=== HyperLogLog Statistics ===\n");
    printf("  Window duration:      %u sec\n", global_src_ip_hll->window_sec);
    printf("  Current unique IPs:   %lu\n", hll_windowed_count(global_src_ip_hll));
    printf("  Previous unique IPs:  %lu\n", hll_windowed_count_previous(global_src_ip_hll));
    printf("  Baseline cardinality: %.0f\n", global_src_ip_hll->baseline_cardinality);
    printf("  Max cardinality:      %.0f\n", global_src_ip_hll->max_cardinality);
    printf("  Total updates:        %lu\n", global_src_ip_hll->total_updates);
    printf("  Window switches:      %lu\n", global_src_ip_hll->window_switches);
    printf("  History entries:      %u/16\n", global_src_ip_hll->history_count);
    printf("  Expected error:       %.2f%%\n", hll_standard_error() * 100.0);
    printf("==============================\n\n");
}
