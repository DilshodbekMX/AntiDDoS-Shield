#include "system_monitor.h"
#include "dpdk_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_memory.h>
#include <rte_cycles.h>

// Per-lcore cycle trackers (cache-line aligned to avoid false sharing)
struct lcore_cycle_tracker lcore_cycles[RTE_MAX_LCORE];

// Previous CPU stats for delta calculation
static uint64_t prev_cpu_total[MAX_MONITORED_LCORES];
static uint64_t prev_cpu_idle[MAX_MONITORED_LCORES];
static uint64_t prev_cpu_user[MAX_MONITORED_LCORES];
static uint64_t prev_cpu_system[MAX_MONITORED_LCORES];
static uint64_t prev_cpu_iowait[MAX_MONITORED_LCORES];
static bool stats_initialized = false;

// Previous lcore cycle stats for delta calculation
static uint64_t prev_lcore_busy[RTE_MAX_LCORE];
static uint64_t prev_lcore_idle[RTE_MAX_LCORE];

static uint64_t get_timestamp_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// ==================== System CPU Stats ====================

static int read_cpu_stats(struct sys_cpu_stats *cpu_stats, uint32_t *nb_cpus) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return -1;

    char line[256];
    uint32_t cpu_count = 0;

    while (fgets(line, sizeof(line), f) && cpu_count < MAX_MONITORED_LCORES) {
        if (strncmp(line, "cpu", 3) != 0) continue;

        // Skip aggregate "cpu" line, only process individual cores "cpu0", "cpu1", etc.
        if (line[3] == ' ') continue;

        uint32_t cpu_id;
        uint64_t user, nice, system, idle, iowait, irq, softirq, steal;

        if (sscanf(line, "cpu%u %lu %lu %lu %lu %lu %lu %lu %lu",
                   &cpu_id, &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) < 8) {
            continue;
        }

        if (cpu_id >= MAX_MONITORED_LCORES) continue;

        uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal;
        uint64_t idle_total = idle + iowait;
        uint64_t user_total = user + nice;

        // Calculate delta from previous sample
        uint64_t total_delta = total - prev_cpu_total[cpu_id];
        uint64_t idle_delta = idle_total - prev_cpu_idle[cpu_id];
        uint64_t user_delta = user_total - prev_cpu_user[cpu_id];
        uint64_t system_delta = system - prev_cpu_system[cpu_id];
        uint64_t iowait_delta = iowait - prev_cpu_iowait[cpu_id];

        cpu_stats[cpu_count].cpu_id = cpu_id;

        if (total_delta > 0 && stats_initialized) {
            double busy_delta = (double)(total_delta - idle_delta);
            cpu_stats[cpu_count].usage_pct = (busy_delta / (double)total_delta) * 100.0;
            cpu_stats[cpu_count].idle_pct = ((double)idle_delta / (double)total_delta) * 100.0;
            cpu_stats[cpu_count].user_pct = ((double)user_delta / (double)total_delta) * 100.0;
            cpu_stats[cpu_count].system_pct = ((double)system_delta / (double)total_delta) * 100.0;
            cpu_stats[cpu_count].iowait_pct = ((double)iowait_delta / (double)total_delta) * 100.0;

            // Clamp values
            if (cpu_stats[cpu_count].usage_pct < 0) cpu_stats[cpu_count].usage_pct = 0;
            if (cpu_stats[cpu_count].usage_pct > 100) cpu_stats[cpu_count].usage_pct = 100;
            if (cpu_stats[cpu_count].user_pct < 0) cpu_stats[cpu_count].user_pct = 0;
            if (cpu_stats[cpu_count].system_pct < 0) cpu_stats[cpu_count].system_pct = 0;
            if (cpu_stats[cpu_count].iowait_pct < 0) cpu_stats[cpu_count].iowait_pct = 0;
        } else {
            cpu_stats[cpu_count].usage_pct = 0;
            cpu_stats[cpu_count].idle_pct = 100;
            cpu_stats[cpu_count].user_pct = 0;
            cpu_stats[cpu_count].system_pct = 0;
            cpu_stats[cpu_count].iowait_pct = 0;
        }

        // Store current values for next delta calculation
        prev_cpu_total[cpu_id] = total;
        prev_cpu_idle[cpu_id] = idle_total;
        prev_cpu_user[cpu_id] = user_total;
        prev_cpu_system[cpu_id] = system;
        prev_cpu_iowait[cpu_id] = iowait;
        cpu_count++;
    }

    fclose(f);
    *nb_cpus = cpu_count;
    stats_initialized = true;
    return 0;
}

// ==================== System Memory Stats ====================

static int read_memory_stats(struct sys_memory_stats *mem) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;

    char line[256];
    memset(mem, 0, sizeof(*mem));

    while (fgets(line, sizeof(line), f)) {
        uint64_t value;
        char unit[16];

        if (sscanf(line, "MemTotal: %lu %s", &value, unit) == 2) {
            mem->total_bytes = value * 1024;
        } else if (sscanf(line, "MemFree: %lu %s", &value, unit) == 2) {
            mem->free_bytes = value * 1024;
        } else if (sscanf(line, "MemAvailable: %lu %s", &value, unit) == 2) {
            mem->available_bytes = value * 1024;
        } else if (sscanf(line, "Buffers: %lu %s", &value, unit) == 2) {
            mem->buffers_bytes = value * 1024;
        } else if (sscanf(line, "Cached: %lu %s", &value, unit) == 2) {
            mem->cached_bytes = value * 1024;
        } else if (sscanf(line, "HugePages_Total: %lu", &value) == 1) {
            mem->hugepages_total = value;
        } else if (sscanf(line, "HugePages_Free: %lu", &value) == 1) {
            mem->hugepages_free = value;
        } else if (sscanf(line, "Hugepagesize: %lu %s", &value, unit) == 2) {
            mem->hugepage_size_kb = value;
        }
    }

    fclose(f);

    // Calculate used memory
    mem->used_bytes = mem->total_bytes - mem->available_bytes;
    if (mem->total_bytes > 0) {
        mem->usage_pct = ((double)mem->used_bytes / mem->total_bytes) * 100.0;
    }

    return 0;
}

// ==================== Load Average ====================

static int read_load_average(double *load_1, double *load_5, double *load_15) {
    FILE *f = fopen("/proc/loadavg", "r");
    if (!f) return -1;

    if (fscanf(f, "%lf %lf %lf", load_1, load_5, load_15) != 3) {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

// ==================== DPDK Resource Stats ====================

static void collect_dpdk_lcore_stats(struct dpdk_resource_stats *dpdk) {
    unsigned lcore_id;
    uint32_t idx = 0;
    double total_util = 0;
    uint32_t active_count = 0;

    dpdk->nb_lcores = 0;

    RTE_LCORE_FOREACH(lcore_id) {
        if (idx >= MAX_MONITORED_LCORES) break;

        struct lcore_cycle_tracker *tracker = &lcore_cycles[lcore_id];
        struct lcore_cpu_stats *stats = &dpdk->lcore_stats[idx];

        // Get current values
        uint64_t cur_busy = tracker->busy_cycles;
        uint64_t cur_idle = tracker->idle_cycles;

        // Calculate delta from previous sample
        uint64_t busy_delta = cur_busy - prev_lcore_busy[lcore_id];
        uint64_t idle_delta = cur_idle - prev_lcore_idle[lcore_id];
        uint64_t total_delta = busy_delta + idle_delta;

        stats->lcore_id = lcore_id;
        stats->busy_cycles = cur_busy;
        stats->idle_cycles = cur_idle;
        stats->total_cycles = cur_busy + cur_idle;

        // Check if lcore is active (has received cycles in this period)
        stats->is_active = (total_delta > 0);

        if (total_delta > 0) {
            stats->utilization_pct = ((double)busy_delta / (double)total_delta) * 100.0;
            total_util += stats->utilization_pct;
            active_count++;
        } else {
            stats->utilization_pct = 0;
        }

        // Store current values for next delta calculation
        prev_lcore_busy[lcore_id] = cur_busy;
        prev_lcore_idle[lcore_id] = cur_idle;

        idx++;
    }

    dpdk->nb_lcores = idx;
    // Average only across active lcores
    dpdk->avg_lcore_utilization = (active_count > 0) ? (total_util / active_count) : 0;
}

// Callback for mempool walk
struct mempool_walk_ctx {
    struct dpdk_resource_stats *dpdk;
};

static void mempool_walk_cb(struct rte_mempool *mp, void *arg) {
    struct mempool_walk_ctx *ctx = (struct mempool_walk_ctx *)arg;
    struct dpdk_resource_stats *dpdk = ctx->dpdk;

    if (dpdk->nb_mempools >= MAX_MONITORED_MEMPOOLS) return;

    struct mempool_stats *stats = &dpdk->mempool_stats[dpdk->nb_mempools];

    strncpy(stats->name, mp->name, sizeof(stats->name) - 1);
    stats->name[sizeof(stats->name) - 1] = '\0';
    stats->size = mp->size;
    stats->avail_count = rte_mempool_avail_count(mp);
    stats->in_use_count = rte_mempool_in_use_count(mp);

    if (stats->size > 0) {
        stats->usage_pct = ((double)stats->in_use_count / stats->size) * 100.0;
    } else {
        stats->usage_pct = 0;
    }

    dpdk->nb_mempools++;
}

static void collect_dpdk_mempool_stats(struct dpdk_resource_stats *dpdk) {
    dpdk->nb_mempools = 0;

    struct mempool_walk_ctx ctx = { .dpdk = dpdk };
    rte_mempool_walk(mempool_walk_cb, &ctx);
}

static void collect_dpdk_hugepage_stats(struct dpdk_resource_stats *dpdk) {
    // Read hugepage info from meminfo
    struct sys_memory_stats mem;
    if (read_memory_stats(&mem) == 0) {
        uint64_t hugepage_size_bytes = mem.hugepage_size_kb * 1024;
        dpdk->hugepage_total_bytes = mem.hugepages_total * hugepage_size_bytes;
        dpdk->hugepage_used_bytes = (mem.hugepages_total - mem.hugepages_free) * hugepage_size_bytes;

        if (dpdk->hugepage_total_bytes > 0) {
            dpdk->hugepage_usage_pct = ((double)dpdk->hugepage_used_bytes / dpdk->hugepage_total_bytes) * 100.0;
        }
    }
}

// ==================== Public API ====================

int system_monitor_init(void) {
    // Initialize cycle trackers
    memset(lcore_cycles, 0, sizeof(lcore_cycles));
    memset(prev_cpu_total, 0, sizeof(prev_cpu_total));
    memset(prev_cpu_idle, 0, sizeof(prev_cpu_idle));
    memset(prev_cpu_user, 0, sizeof(prev_cpu_user));
    memset(prev_cpu_system, 0, sizeof(prev_cpu_system));
    memset(prev_cpu_iowait, 0, sizeof(prev_cpu_iowait));
    memset(prev_lcore_busy, 0, sizeof(prev_lcore_busy));
    memset(prev_lcore_idle, 0, sizeof(prev_lcore_idle));
    stats_initialized = false;

    printf("[SystemMonitor] Initialized\n");
    return 0;
}

void system_monitor_cleanup(void) {
    printf("[SystemMonitor] Cleaned up\n");
}

void system_monitor_get_stats(struct system_stats *stats) {
    if (!stats) return;

    memset(stats, 0, sizeof(*stats));
    stats->timestamp_ms = get_timestamp_ms();

    // Collect DPDK stats
    collect_dpdk_lcore_stats(&stats->dpdk);
    collect_dpdk_mempool_stats(&stats->dpdk);
    collect_dpdk_hugepage_stats(&stats->dpdk);

    // Collect system stats
    read_cpu_stats(stats->cpu_stats, &stats->nb_cpus);
    read_memory_stats(&stats->memory);
    read_load_average(&stats->load_1min, &stats->load_5min, &stats->load_15min);

    // Calculate average CPU usage
    double total_usage = 0;
    for (uint32_t i = 0; i < stats->nb_cpus; i++) {
        total_usage += stats->cpu_stats[i].usage_pct;
    }
    stats->avg_cpu_usage = (stats->nb_cpus > 0) ? (total_usage / stats->nb_cpus) : 0;
}
