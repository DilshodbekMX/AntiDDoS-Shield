#ifndef SYSTEM_MONITOR_H
#define SYSTEM_MONITOR_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_lcore.h>

// ==================== DPDK Resource Stats ====================

#define MAX_MONITORED_LCORES 64
#define MAX_MONITORED_MEMPOOLS 8

/**
 * Per-lcore CPU utilization stats
 * Tracks busy vs idle cycles to compute utilization percentage
 */
struct lcore_cpu_stats {
    uint32_t lcore_id;
    uint64_t busy_cycles;      // Cycles doing useful work (processing packets)
    uint64_t idle_cycles;      // Cycles with no work (rx_burst returned 0)
    uint64_t total_cycles;     // Total cycles since last reset
    double utilization_pct;    // Computed utilization (0-100%)
    bool is_active;            // True if lcore is processing packets
};

/**
 * Mempool usage stats
 */
struct mempool_stats {
    char name[32];
    uint32_t size;             // Total objects in pool
    uint32_t avail_count;      // Currently available
    uint32_t in_use_count;     // Currently in use
    double usage_pct;          // Computed usage percentage
};

/**
 * Aggregated DPDK resource stats
 */
struct dpdk_resource_stats {
    // Lcore stats
    uint32_t nb_lcores;
    struct lcore_cpu_stats lcore_stats[MAX_MONITORED_LCORES];
    double avg_lcore_utilization;

    // Mempool stats
    uint32_t nb_mempools;
    struct mempool_stats mempool_stats[MAX_MONITORED_MEMPOOLS];

    // Memory info
    uint64_t hugepage_total_bytes;
    uint64_t hugepage_used_bytes;
    double hugepage_usage_pct;
};

// ==================== System Resource Stats ====================

/**
 * Per-CPU stats from /proc/stat
 */
struct sys_cpu_stats {
    uint32_t cpu_id;
    double usage_pct;          // Overall CPU usage (0-100%)
    double user_pct;           // User space usage
    double system_pct;         // Kernel space usage
    double idle_pct;           // Idle percentage
    double iowait_pct;         // I/O wait percentage
};

/**
 * System memory stats from /proc/meminfo
 */
struct sys_memory_stats {
    uint64_t total_bytes;
    uint64_t free_bytes;
    uint64_t available_bytes;
    uint64_t buffers_bytes;
    uint64_t cached_bytes;
    uint64_t used_bytes;
    double usage_pct;

    // Hugepages
    uint64_t hugepages_total;
    uint64_t hugepages_free;
    uint64_t hugepage_size_kb;
};

/**
 * Complete system stats snapshot
 */
struct system_stats {
    uint64_t timestamp_ms;

    // DPDK resources
    struct dpdk_resource_stats dpdk;

    // System-wide
    uint32_t nb_cpus;
    struct sys_cpu_stats cpu_stats[MAX_MONITORED_LCORES];
    double avg_cpu_usage;
    struct sys_memory_stats memory;

    // System load average
    double load_1min;
    double load_5min;
    double load_15min;
};

// ==================== Per-Lcore Cycle Tracking ====================
// These are updated from the main loop (fast path)

struct lcore_cycle_tracker {
    uint64_t busy_cycles;
    uint64_t idle_cycles;
    uint64_t last_update_tsc;
    uint64_t poll_count;       // Number of rx_burst calls
    uint64_t empty_poll_count; // Number of rx_burst calls returning 0
} __attribute__((aligned(64)));  // Cache line aligned

extern struct lcore_cycle_tracker lcore_cycles[RTE_MAX_LCORE];

// ==================== API ====================

/**
 * Initialize system monitor
 * Should be called after DPDK EAL init
 */
int system_monitor_init(void);

/**
 * Cleanup system monitor
 */
void system_monitor_cleanup(void);

/**
 * Get current system stats snapshot
 * Thread-safe, can be called from any thread
 */
void system_monitor_get_stats(struct system_stats *stats);

/**
 * Update DPDK lcore busy cycles (call from main loop when work is done)
 */
static inline void lcore_cycles_add_busy(uint64_t cycles) {
    unsigned lcore_id = rte_lcore_id();
    if (lcore_id < RTE_MAX_LCORE) {
        lcore_cycles[lcore_id].busy_cycles += cycles;
        lcore_cycles[lcore_id].poll_count++;
    }
}

/**
 * Update DPDK lcore idle cycles (call from main loop when no packets)
 */
static inline void lcore_cycles_add_idle(uint64_t cycles) {
    unsigned lcore_id = rte_lcore_id();
    if (lcore_id < RTE_MAX_LCORE) {
        lcore_cycles[lcore_id].idle_cycles += cycles;
        lcore_cycles[lcore_id].poll_count++;
        lcore_cycles[lcore_id].empty_poll_count++;
    }
}

#endif // SYSTEM_MONITOR_H
