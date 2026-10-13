/**
 * @file performance_optimization.c
 * @brief Performance optimization implementation
 *
 * Optimized paths for:
 * - Per-lcore tenant config caching
 * - Fast IP-to-tenant LPM lookup
 * - Batch packet processing
 * - Statistics aggregation
 */

#include "performance_optimization.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

// ==================== Global State ====================

static struct {
    lcore_cache_t *lcore_caches[PERF_MAX_LCORES];
    optimized_lpm_t *global_lpm;
    pthread_mutex_t init_lock;
    atomic_uint_fast32_t global_version;
    bool initialized;
} g_perf = {
    .init_lock = PTHREAD_MUTEX_INITIALIZER,
    .global_version = 0,
    .initialized = false,
};

// Thread-local lcore ID (set by DPDK or manually)
static __thread uint32_t tls_lcore_id = UINT32_MAX;

// Profiling hash table
#define PROFILE_HASH_SIZE 64
static struct {
    perf_profile_entry_t entries[PROFILE_HASH_SIZE];
    pthread_mutex_t lock;
    uint32_t count;
} g_profile = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .count = 0,
};

// ==================== Per-lcore Cache Implementation ====================

int perf_cache_init(void) {
    pthread_mutex_lock(&g_perf.init_lock);

    if (g_perf.initialized) {
        pthread_mutex_unlock(&g_perf.init_lock);
        return 0;
    }

    // Initialize lcore caches
    for (int i = 0; i < PERF_MAX_LCORES; i++) {
        g_perf.lcore_caches[i] = perf_alloc_aligned(sizeof(lcore_cache_t),
                                                     PERF_CACHE_LINE_SIZE);
        if (!g_perf.lcore_caches[i]) {
            // Cleanup on failure
            for (int j = 0; j < i; j++) {
                perf_free_aligned(g_perf.lcore_caches[j]);
                g_perf.lcore_caches[j] = NULL;
            }
            pthread_mutex_unlock(&g_perf.init_lock);
            return -1;
        }

        memset(g_perf.lcore_caches[i], 0, sizeof(lcore_cache_t));
        g_perf.lcore_caches[i]->lcore_id = i;
    }

    // Initialize global LPM
    g_perf.global_lpm = perf_lpm_init();
    if (!g_perf.global_lpm) {
        for (int i = 0; i < PERF_MAX_LCORES; i++) {
            perf_free_aligned(g_perf.lcore_caches[i]);
            g_perf.lcore_caches[i] = NULL;
        }
        pthread_mutex_unlock(&g_perf.init_lock);
        return -1;
    }

    g_perf.initialized = true;
    pthread_mutex_unlock(&g_perf.init_lock);

    return 0;
}

void perf_cache_cleanup(void) {
    pthread_mutex_lock(&g_perf.init_lock);

    if (!g_perf.initialized) {
        pthread_mutex_unlock(&g_perf.init_lock);
        return;
    }

    // Free lcore caches
    for (int i = 0; i < PERF_MAX_LCORES; i++) {
        if (g_perf.lcore_caches[i]) {
            perf_free_aligned(g_perf.lcore_caches[i]);
            g_perf.lcore_caches[i] = NULL;
        }
    }

    // Free LPM
    if (g_perf.global_lpm) {
        perf_lpm_cleanup(g_perf.global_lpm);
        g_perf.global_lpm = NULL;
    }

    g_perf.initialized = false;
    pthread_mutex_unlock(&g_perf.init_lock);
}

lcore_cache_t *perf_get_lcore_cache(void) {
    if (!g_perf.initialized) {
        return NULL;
    }

    // Get lcore ID (would use rte_lcore_id() with DPDK)
    uint32_t lcore_id = tls_lcore_id;
    if (lcore_id == UINT32_MAX) {
        // Fallback: use thread ID modulo
        lcore_id = (uint32_t)((uintptr_t)pthread_self() % PERF_MAX_LCORES);
    }

    if (lcore_id >= PERF_MAX_LCORES) {
        return NULL;
    }

    return g_perf.lcore_caches[lcore_id];
}

int perf_update_tenant_cache(uint32_t tenant_id, const void *config) {
    if (!g_perf.initialized || tenant_id >= PERF_MAX_TENANTS || !config) {
        return -1;
    }

    // Update cache on all lcores
    for (int i = 0; i < PERF_MAX_LCORES; i++) {
        lcore_cache_t *cache = g_perf.lcore_caches[i];
        if (!cache) continue;

        lcore_tenant_cache_t *tenant = &cache->tenants[tenant_id];

        // Copy relevant fields from config
        // In production, this would copy from tenant_l1_config
        tenant->tenant_id = tenant_id;
        tenant->version = atomic_fetch_add(&g_perf.global_version, 1);
    }

    return 0;
}

void perf_invalidate_cache(uint32_t tenant_id, int strategy) {
    if (!g_perf.initialized) {
        return;
    }

    atomic_fetch_add(&g_perf.global_version, 1);

    if (strategy == CACHE_INVALIDATE_IMMEDIATE) {
        // Immediate invalidation on all lcores
        for (int i = 0; i < PERF_MAX_LCORES; i++) {
            lcore_cache_t *cache = g_perf.lcore_caches[i];
            if (!cache) continue;

            if (tenant_id == 0) {
                // Invalidate all tenants
                for (uint32_t t = 0; t < PERF_MAX_TENANTS; t++) {
                    cache->tenants[t].version = 0;
                }
                cache->cache_invalidations += PERF_MAX_TENANTS;
            } else {
                cache->tenants[tenant_id].version = 0;
                cache->cache_invalidations++;
            }
        }
    }
    // LAZY and EPOCH strategies would be handled in lookup path
}

// ==================== Optimized LPM Implementation ====================

optimized_lpm_t *perf_lpm_init(void) {
    // Allocate LPM table (large - ~32MB)
    optimized_lpm_t *lpm = perf_alloc_aligned(sizeof(optimized_lpm_t),
                                               PERF_CACHE_LINE_SIZE);
    if (!lpm) {
        return NULL;
    }

    memset(lpm, 0, sizeof(optimized_lpm_t));
    return lpm;
}

void perf_lpm_cleanup(optimized_lpm_t *lpm) {
    if (lpm) {
        perf_free_aligned(lpm);
    }
}

int perf_lpm_add(optimized_lpm_t *lpm, uint32_t ip, uint8_t prefix_len,
                 uint16_t tenant_id) {
    if (!lpm || tenant_id == 0) {
        return -1;
    }

    if (prefix_len <= 24) {
        // Add to direct table
        // For /24: fill 1 entry
        // For /16: fill 256 entries
        // For /8: fill 65536 entries
        uint32_t base_idx = ip >> 8;
        uint32_t count = 1 << (24 - prefix_len);

        for (uint32_t i = 0; i < count; i++) {
            uint32_t idx = base_idx + i;
            if (idx < 16777216) {
                // Only set if not already set (longer prefix wins)
                if (lpm->direct_table_24[idx] == 0) {
                    lpm->direct_table_24[idx] = tenant_id;
                }
            }
        }
    } else {
        // Add to prefix table for /25-/32
        if (lpm->prefix_count >= 65536) {
            return -1;
        }

        uint32_t idx = lpm->prefix_count++;
        lpm->prefix_table[idx].ip = ip;
        lpm->prefix_table[idx].prefix_len = prefix_len;
        lpm->prefix_table[idx].tenant_id = tenant_id;
    }

    return 0;
}

int perf_lpm_remove(optimized_lpm_t *lpm, uint32_t ip, uint8_t prefix_len) {
    if (!lpm) {
        return -1;
    }

    if (prefix_len <= 24) {
        // Remove from direct table
        uint32_t base_idx = ip >> 8;
        uint32_t count = 1 << (24 - prefix_len);

        for (uint32_t i = 0; i < count; i++) {
            uint32_t idx = base_idx + i;
            if (idx < 16777216) {
                lpm->direct_table_24[idx] = 0;
            }
        }
    } else {
        // Remove from prefix table
        for (uint32_t i = 0; i < lpm->prefix_count; i++) {
            if (lpm->prefix_table[i].ip == ip &&
                lpm->prefix_table[i].prefix_len == prefix_len) {
                // Shift remaining entries
                if (i < lpm->prefix_count - 1) {
                    memmove(&lpm->prefix_table[i], &lpm->prefix_table[i + 1],
                           (lpm->prefix_count - i - 1) * sizeof(lpm->prefix_table[0]));
                }
                lpm->prefix_count--;
                break;
            }
        }
    }

    return 0;
}

void perf_lpm_lookup_batch(const optimized_lpm_t *lpm, const uint32_t *ips,
                           uint16_t *tenant_ids, uint32_t count) {
    if (!lpm || !ips || !tenant_ids) {
        return;
    }

    // Prefetch ahead
    for (uint32_t i = 0; i < count; i++) {
        if (i + PERF_PREFETCH_OFFSET < count) {
            uint32_t prefetch_ip = __builtin_bswap32(ips[i + PERF_PREFETCH_OFFSET]);
            __builtin_prefetch(&lpm->direct_table_24[prefetch_ip >> 8], 0, 0);
        }

        tenant_ids[i] = perf_lpm_lookup(lpm, ips[i]);
    }
}

// ==================== Batch Processing Implementation ====================

void perf_batch_init(batch_context_t *batch) {
    if (batch) {
        memset(batch, 0, sizeof(batch_context_t));
    }
}

int perf_batch_add(batch_context_t *batch, uint32_t tenant_id,
                   uint32_t src_ip, uint32_t dst_ip,
                   uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    if (!batch || batch->count >= 64) {
        return -1;
    }

    uint32_t idx = batch->count++;
    batch->tenant_ids[idx] = tenant_id;
    batch->src_ips[idx] = src_ip;
    batch->dst_ips[idx] = dst_ip;
    batch->src_ports[idx] = src_port;
    batch->dst_ports[idx] = dst_port;
    batch->protocols[idx] = protocol;
    batch->decisions[idx] = 0;  // Default: drop

    return idx;
}

uint32_t perf_batch_process(batch_context_t *batch) {
    if (!batch || batch->count == 0) {
        return 0;
    }

    lcore_cache_t *cache = perf_get_lcore_cache();
    if (!cache) {
        return 0;
    }

    uint32_t passed = 0;

    // Prefetch tenant caches
    for (uint32_t i = 0; i < batch->count && i < PERF_PREFETCH_OFFSET; i++) {
        perf_prefetch_tenant(batch->tenant_ids[i]);
    }

    // Process batch
    for (uint32_t i = 0; i < batch->count; i++) {
        // Prefetch next
        if (i + PERF_PREFETCH_OFFSET < batch->count) {
            perf_prefetch_tenant(batch->tenant_ids[i + PERF_PREFETCH_OFFSET]);
        }

        uint32_t tenant_id = batch->tenant_ids[i];
        if (tenant_id >= PERF_MAX_TENANTS) {
            continue;  // Drop - invalid tenant
        }

        lcore_tenant_cache_t *tenant = &cache->tenants[tenant_id];

        // Check status
        if (tenant->status != 1) {  // Not active
            continue;  // Drop
        }

        // Rate limit check (simplified)
        if (!perf_rate_limit_check(tenant, 1, 1000)) {
            continue;  // Drop - rate limited
        }

        // Passed all checks
        batch->decisions[i] = 1;
        passed++;

        // Update stats
        perf_stats_update(cache, tenant_id, 1, 1000);
    }

    return passed;
}

// ==================== Statistics Implementation ====================

void perf_stats_flush(lcore_cache_t *cache) {
    if (!cache || cache->stats_batch_count == 0) {
        return;
    }

    // In production, would atomically add to global counters
    // For now, just reset batch counters
    memset(cache->stats_batch_pps, 0, sizeof(cache->stats_batch_pps));
    memset(cache->stats_batch_bps, 0, sizeof(cache->stats_batch_bps));
    cache->stats_batch_count = 0;
}

// ==================== Profiling Implementation ====================

static uint32_t hash_string(const char *str) {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash % PROFILE_HASH_SIZE;
}

void perf_profile_end(const char *name, uint64_t start) {
    uint64_t end = __builtin_ia32_rdtsc();
    uint64_t cycles = end - start;

    uint32_t idx = hash_string(name);

    pthread_mutex_lock(&g_profile.lock);

    perf_profile_entry_t *entry = &g_profile.entries[idx];

    if (entry->name == NULL) {
        entry->name = name;
        entry->min_cycles = cycles;
        entry->max_cycles = cycles;
        g_profile.count++;
    } else if (entry->name != name) {
        // Hash collision - skip
        pthread_mutex_unlock(&g_profile.lock);
        return;
    }

    entry->total_cycles += cycles;
    entry->call_count++;
    if (cycles < entry->min_cycles) entry->min_cycles = cycles;
    if (cycles > entry->max_cycles) entry->max_cycles = cycles;

    pthread_mutex_unlock(&g_profile.lock);
}

int perf_profile_get_results(perf_profile_entry_t *entries, int max_entries) {
    pthread_mutex_lock(&g_profile.lock);

    int count = 0;
    for (int i = 0; i < PROFILE_HASH_SIZE && count < max_entries; i++) {
        if (g_profile.entries[i].name != NULL) {
            entries[count++] = g_profile.entries[i];
        }
    }

    pthread_mutex_unlock(&g_profile.lock);
    return count;
}

void perf_profile_reset(void) {
    pthread_mutex_lock(&g_profile.lock);
    memset(g_profile.entries, 0, sizeof(g_profile.entries));
    g_profile.count = 0;
    pthread_mutex_unlock(&g_profile.lock);
}

void perf_profile_report(void) {
    perf_profile_entry_t entries[PROFILE_HASH_SIZE];
    int count = perf_profile_get_results(entries, PROFILE_HASH_SIZE);

    printf("\n=== Performance Profile Report ===\n\n");
    printf("%-30s %12s %12s %12s %12s\n",
           "Path", "Calls", "Avg Cycles", "Min", "Max");
    printf("%-30s %12s %12s %12s %12s\n",
           "----", "-----", "----------", "---", "---");

    for (int i = 0; i < count; i++) {
        perf_profile_entry_t *e = &entries[i];
        uint64_t avg = e->call_count > 0 ? e->total_cycles / e->call_count : 0;

        printf("%-30s %12lu %12lu %12lu %12lu\n",
               e->name, e->call_count, avg, e->min_cycles, e->max_cycles);
    }

    printf("\n");
}

// ==================== Memory Allocation ====================

void *perf_alloc_aligned(size_t size, size_t alignment) {
    void *ptr = NULL;

    if (alignment < sizeof(void*)) {
        alignment = sizeof(void*);
    }

    if (posix_memalign(&ptr, alignment, size) != 0) {
        return NULL;
    }

    return ptr;
}

void perf_free_aligned(void *ptr) {
    free(ptr);
}
