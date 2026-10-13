#include "spike_detector.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <string.h>

#define RTE_LOGTYPE_SPIKE RTE_LOGTYPE_USER8

// ==================== Global State ====================

struct rte_hash *g_spike_hash = NULL;
struct spike_detector *g_spike_pool = NULL;
static uint32_t g_max_ips = 0;
static uint32_t g_registered_count = 0;
static uint32_t g_spike_count_total = 0;
static bool g_initialized = false;
static uint64_t g_tsc_hz = 0;
static uint64_t g_window_tsc = 0;  // TSC cycles per window

// ==================== Initialization ====================

int spike_detector_init(uint32_t max_ips) {
    if (g_initialized) {
        return 0;  // Already initialized
    }

    if (max_ips == 0 || max_ips > 10000) {
        RTE_LOG(ERR, SPIKE, "Invalid max_ips: %u (must be 1-10000)\n", max_ips);
        return -1;
    }

    // Get TSC frequency
    g_tsc_hz = rte_get_tsc_hz();
    g_window_tsc = (g_tsc_hz * SPIKE_WINDOW_MS) / 1000;

    // Create hash table for IP lookup
    struct rte_hash_parameters hash_params = {
        .name = "spike_detector_hash",
        .entries = max_ips,
        .key_len = sizeof(uint32_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };

    g_spike_hash = rte_hash_create(&hash_params);
    if (!g_spike_hash) {
        RTE_LOG(ERR, SPIKE, "Failed to create hash table\n");
        return -1;
    }

    // Allocate spike detector pool
    size_t pool_size = max_ips * sizeof(struct spike_detector);
    g_spike_pool = rte_zmalloc("spike_pool", pool_size, RTE_CACHE_LINE_SIZE);
    if (!g_spike_pool) {
        RTE_LOG(ERR, SPIKE, "Failed to allocate spike pool (%zu bytes)\n", pool_size);
        rte_hash_free(g_spike_hash);
        g_spike_hash = NULL;
        return -1;
    }

    g_max_ips = max_ips;
    g_initialized = true;

    RTE_LOG(INFO, SPIKE, "Spike detector initialized: max_ips=%u, window=%ums\n",
            max_ips, SPIKE_WINDOW_MS);
    return 0;
}

void spike_detector_cleanup(void) {
    if (!g_initialized) return;

    // Free per-IP lcore windows
    for (uint32_t i = 0; i < g_max_ips; i++) {
        if (g_spike_pool[i].lcore_windows) {
            rte_free(g_spike_pool[i].lcore_windows);
        }
    }

    if (g_spike_pool) {
        rte_free(g_spike_pool);
        g_spike_pool = NULL;
    }

    if (g_spike_hash) {
        rte_hash_free(g_spike_hash);
        g_spike_hash = NULL;
    }

    g_initialized = false;
    g_registered_count = 0;
}

// ==================== Registration ====================

int spike_detector_register(uint32_t dst_ip) {
    if (!g_initialized) return -1;

    // Check if already registered
    int32_t idx = rte_hash_lookup(g_spike_hash, &dst_ip);
    if (idx >= 0) {
        return 0;  // Already registered
    }

    if (g_registered_count >= g_max_ips) {
        RTE_LOG(ERR, SPIKE, "Spike detector full: %u IPs\n", g_max_ips);
        return -1;
    }

    // Find free slot
    uint32_t slot = UINT32_MAX;
    for (uint32_t i = 0; i < g_max_ips; i++) {
        if (!g_spike_pool[i].active) {
            slot = i;
            break;
        }
    }

    if (slot == UINT32_MAX) {
        RTE_LOG(ERR, SPIKE, "No free slots in spike pool\n");
        return -1;
    }

    // Allocate per-lcore windows
    size_t windows_size = RTE_MAX_LCORE * sizeof(struct spike_window);
    g_spike_pool[slot].lcore_windows = rte_zmalloc("spike_windows", windows_size, RTE_CACHE_LINE_SIZE);
    if (!g_spike_pool[slot].lcore_windows) {
        RTE_LOG(ERR, SPIKE, "Failed to allocate lcore windows\n");
        return -1;
    }

    // Initialize spike detector
    struct spike_detector *sd = &g_spike_pool[slot];
    sd->dst_ip = dst_ip;
    sd->active = 1;
    sd->last_aggregate_tsc = rte_rdtsc();
    sd->aggregate_rate_pps = 0;
    sd->baseline_rate_pps = 0;
    sd->spike_ratio = 1.0;
    sd->spike_active = false;
    sd->spike_count = 0;

    // Initialize per-lcore windows
    uint64_t now = rte_rdtsc();
    for (unsigned int i = 0; i < RTE_MAX_LCORE; i++) {
        struct spike_window *sw = &sd->lcore_windows[i];
        memset(sw->packet_count, 0, sizeof(sw->packet_count));
        sw->current_count = 0;
        sw->window_start_tsc = now;
        sw->current_idx = 0;
        sw->filled_windows = 0;
        sw->spike_detected = 0;
    }

    // Add to hash
    int ret = rte_hash_add_key_data(g_spike_hash, &dst_ip, (void *)(uintptr_t)slot);
    if (ret < 0) {
        rte_free(sd->lcore_windows);
        sd->lcore_windows = NULL;
        sd->active = 0;
        RTE_LOG(ERR, SPIKE, "Failed to add IP to hash\n");
        return -1;
    }

    g_registered_count++;
    return 0;
}

int spike_detector_unregister(uint32_t dst_ip) {
    if (!g_initialized) return -1;

    int32_t idx = rte_hash_lookup(g_spike_hash, &dst_ip);
    if (idx < 0) {
        return -1;  // Not found
    }

    struct spike_detector *sd = &g_spike_pool[idx];
    if (sd->lcore_windows) {
        rte_free(sd->lcore_windows);
        sd->lcore_windows = NULL;
    }

    sd->active = 0;
    rte_hash_del_key(g_spike_hash, &dst_ip);
    g_registered_count--;

    return 0;
}

struct spike_detector *spike_detector_lookup(uint32_t dst_ip) {
    if (!g_initialized || !g_spike_hash) return NULL;

    int32_t idx = rte_hash_lookup(g_spike_hash, &dst_ip);
    if (idx < 0) return NULL;

    return &g_spike_pool[idx];
}

bool spike_detector_is_spiking(uint32_t dst_ip) {
    struct spike_detector *sd = spike_detector_lookup(dst_ip);
    if (!sd) return false;
    return sd->spike_active;
}

// ==================== Aggregation (Control Path) ====================

/**
 * Process windows for a single lcore
 * Advances window if enough time has passed, returns rate
 */
static uint64_t process_lcore_window(struct spike_window *sw, uint64_t now_tsc) {
    // Check if we need to advance window
    uint64_t elapsed = now_tsc - sw->window_start_tsc;

    if (elapsed >= g_window_tsc) {
        // Window expired - save current count and advance
        sw->packet_count[sw->current_idx] = sw->current_count;

        // Advance window index
        sw->current_idx = (sw->current_idx + 1) % SPIKE_WINDOW_COUNT;
        if (sw->filled_windows < SPIKE_WINDOW_COUNT) {
            sw->filled_windows++;
        }

        // Reset for new window
        sw->current_count = 0;
        sw->window_start_tsc = now_tsc;
    }

    // Calculate rate from historical windows
    if (sw->filled_windows == 0) {
        return 0;
    }

    uint64_t total = 0;
    for (uint8_t i = 0; i < sw->filled_windows; i++) {
        total += sw->packet_count[i];
    }

    // Convert to PPS (filled_windows * SPIKE_WINDOW_MS = total time in ms)
    uint64_t total_ms = sw->filled_windows * SPIKE_WINDOW_MS;
    return (total * 1000) / total_ms;
}

uint32_t spike_detector_aggregate(void) {
    if (!g_initialized) return 0;

    uint32_t spikes = 0;
    uint64_t now_tsc = rte_rdtsc();

    // Get list of active lcores
    unsigned int lcore_id;

    // Iterate over all registered IPs
    uint32_t iter = 0;
    const void *key;
    void *data;
    int32_t idx;

    while ((idx = rte_hash_iterate(g_spike_hash, &key, &data, &iter)) >= 0) {
        struct spike_detector *sd = &g_spike_pool[(uintptr_t)data];
        if (!sd->active || !sd->lcore_windows) continue;

        // Aggregate rate from all lcores
        uint64_t total_rate = 0;
        uint64_t current_window_total = 0;

        RTE_LCORE_FOREACH(lcore_id) {
            struct spike_window *sw = &sd->lcore_windows[lcore_id];

            // Process window and get rate
            uint64_t lcore_rate = process_lcore_window(sw, now_tsc);
            total_rate += lcore_rate;

            // Also sum current window for real-time spike detection
            current_window_total += sw->current_count;
        }

        sd->aggregate_rate_pps = total_rate;

        // Update baseline with exponential smoothing (alpha = 0.1)
        if (sd->baseline_rate_pps == 0) {
            sd->baseline_rate_pps = total_rate;
        } else {
            sd->baseline_rate_pps = (uint64_t)(0.9 * sd->baseline_rate_pps + 0.1 * total_rate);
        }

        // Calculate spike ratio
        if (sd->baseline_rate_pps > SPIKE_MIN_RATE_PPS) {
            sd->spike_ratio = (double)total_rate / (double)sd->baseline_rate_pps;

            // Check for spike
            bool was_spiking = sd->spike_active;
            sd->spike_active = (sd->spike_ratio >= SPIKE_DETECT_MULTIPLIER);

            if (sd->spike_active && !was_spiking) {
                sd->spike_count++;
                g_spike_count_total++;
                RTE_LOG(WARNING, SPIKE,
                        "SPIKE DETECTED: IP=%u.%u.%u.%u rate=%lu pps baseline=%lu pps ratio=%.2f\n",
                        (sd->dst_ip) & 0xFF,
                        (sd->dst_ip >> 8) & 0xFF,
                        (sd->dst_ip >> 16) & 0xFF,
                        (sd->dst_ip >> 24) & 0xFF,
                        total_rate, sd->baseline_rate_pps, sd->spike_ratio);
            }
        } else {
            sd->spike_ratio = 1.0;
            sd->spike_active = false;
        }

        if (sd->spike_active) {
            spikes++;
        }

        sd->last_aggregate_tsc = now_tsc;
    }

    return spikes;
}

bool spike_detector_get_info(uint32_t dst_ip,
                             uint64_t *rate_pps,
                             uint64_t *baseline_pps,
                             double *ratio) {
    struct spike_detector *sd = spike_detector_lookup(dst_ip);
    if (!sd) return false;

    if (rate_pps) *rate_pps = sd->aggregate_rate_pps;
    if (baseline_pps) *baseline_pps = sd->baseline_rate_pps;
    if (ratio) *ratio = sd->spike_ratio;

    return sd->spike_active;
}

uint32_t spike_detector_active_count(void) {
    return g_registered_count;
}

uint32_t spike_detector_spike_count(void) {
    return g_spike_count_total;
}
