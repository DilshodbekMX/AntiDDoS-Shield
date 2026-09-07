/**
 * @file performance_optimization.h
 * @brief Performance optimization for multi-tenant Anti-DDoS system
 *
 * Performance targets:
 * - Packet processing: 10+ Mpps per core
 * - Tenant lookup: < 20 cycles
 * - L4 reputation check: < 50 cycles
 * - L4 decision: < 100 cycles total
 * - Stats aggregation: < 100ms for 1000 tenants
 * - API response: < 50ms p99
 */

#ifndef PERFORMANCE_OPTIMIZATION_H
#define PERFORMANCE_OPTIMIZATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ==================== Constants ====================

#define PERF_MAX_LCORES             64
#define PERF_MAX_TENANTS            1024
#define PERF_CACHE_LINE_SIZE        64
#define PERF_PREFETCH_OFFSET        4

// Hot path optimization flags
#define PERF_OPT_PREFETCH           (1 << 0)
#define PERF_OPT_BRANCHLESS         (1 << 1)
#define PERF_OPT_SIMD               (1 << 2)
#define PERF_OPT_BATCH              (1 << 3)
#define PERF_OPT_INLINE_CACHE       (1 << 4)

// Cache invalidation strategies
#define CACHE_INVALIDATE_IMMEDIATE  0
#define CACHE_INVALIDATE_LAZY       1
#define CACHE_INVALIDATE_EPOCH      2

// ==================== Cache Line Aligned Structures ====================

/**
 * @brief Per-lcore tenant config cache (hot data only)
 * Fits in 2 cache lines for fast access
 */
typedef struct __attribute__((aligned(PERF_CACHE_LINE_SIZE))) {
    // First cache line - most frequently accessed
    uint32_t tenant_id;
    uint32_t status;                    // Active/suspended
    uint64_t rate_limit_pps;            // PPS limit
    uint64_t rate_limit_bps;            // BPS limit
    uint32_t syn_proxy_enabled : 1;
    uint32_t syn_proxy_always_on : 1;
    uint32_t geo_blocking_enabled : 1;
    uint32_t l4_enabled : 1;
    uint32_t reserved_flags : 28;
    uint32_t geo_blocked_bitmap[8];     // 256 countries bitmap

    // Second cache line - less frequently accessed
    uint64_t current_pps;               // Current rate (for rate limiting)
    uint64_t current_bps;
    uint64_t tokens_pps;                // Token bucket tokens
    uint64_t tokens_bps;
    uint64_t last_update_tsc;           // Last update timestamp
    uint32_t version;                   // Config version for invalidation
    uint32_t padding[3];
} lcore_tenant_cache_t;

/**
 * @brief Per-lcore cache structure
 */
typedef struct __attribute__((aligned(PERF_CACHE_LINE_SIZE))) {
    // Tenant caches indexed by tenant_id
    lcore_tenant_cache_t tenants[PERF_MAX_TENANTS];

    // Cache metadata
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t cache_invalidations;
    uint32_t cache_version;             // Global version for epoch-based invalidation
    uint32_t lcore_id;

    // Statistics batch buffer
    uint64_t stats_batch_pps[PERF_MAX_TENANTS];
    uint64_t stats_batch_bps[PERF_MAX_TENANTS];
    uint32_t stats_batch_count;
    uint32_t padding;
} lcore_cache_t;

/**
 * @brief Optimized IP-to-tenant lookup table (LPM)
 * Uses direct indexing for /24 networks for O(1) lookup
 */
typedef struct __attribute__((aligned(PERF_CACHE_LINE_SIZE))) {
    // Direct table for /24 lookups (16M entries, 16MB)
    // tenant_id = table[ip >> 8]
    uint16_t direct_table_24[16777216];

    // Fallback for longer prefixes
    struct {
        uint32_t ip;
        uint8_t prefix_len;
        uint8_t reserved[3];
        uint16_t tenant_id;
        uint16_t next;              // For hash collision chaining
    } prefix_table[65536];

    uint32_t prefix_count;
    uint32_t reserved;
} optimized_lpm_t;

/**
 * @brief Batch processing context
 */
typedef struct {
    uint32_t tenant_ids[64];        // Batch of tenant IDs
    uint32_t src_ips[64];           // Source IPs
    uint32_t dst_ips[64];           // Destination IPs
    uint16_t src_ports[64];         // Source ports
    uint16_t dst_ports[64];         // Destination ports
    uint8_t protocols[64];          // IP protocols
    uint8_t decisions[64];          // Batch decisions (pass/drop)
    uint32_t count;                 // Number of packets in batch
} batch_context_t;

// ==================== Per-lcore Cache API ====================

/**
 * @brief Initialize per-lcore caches
 * @return 0 on success
 */
int perf_cache_init(void);

/**
 * @brief Cleanup per-lcore caches
 */
void perf_cache_cleanup(void);

/**
 * @brief Get per-lcore cache for current core
 * @return Pointer to lcore cache, NULL if not initialized
 */
lcore_cache_t *perf_get_lcore_cache(void);

/**
 * @brief Get cached tenant config for current lcore
 * @param tenant_id Tenant identifier
 * @return Pointer to cached config, NULL if not found
 */
static inline lcore_tenant_cache_t *perf_get_tenant_cache(uint32_t tenant_id) {
    lcore_cache_t *cache = perf_get_lcore_cache();
    if (!cache || tenant_id >= PERF_MAX_TENANTS) {
        return NULL;
    }
    return &cache->tenants[tenant_id];
}

/**
 * @brief Update tenant cache from master config
 * @param tenant_id Tenant identifier
 * @param config Source configuration
 * @return 0 on success
 */
int perf_update_tenant_cache(uint32_t tenant_id, const void *config);

/**
 * @brief Invalidate tenant cache across all lcores
 * @param tenant_id Tenant identifier (0 for all)
 * @param strategy Invalidation strategy
 */
void perf_invalidate_cache(uint32_t tenant_id, int strategy);

/**
 * @brief Prefetch tenant cache
 * @param tenant_id Tenant identifier
 */
static inline void perf_prefetch_tenant(uint32_t tenant_id) {
    lcore_cache_t *cache = perf_get_lcore_cache();
    if (cache && tenant_id < PERF_MAX_TENANTS) {
        __builtin_prefetch(&cache->tenants[tenant_id], 0, 3);
    }
}

// ==================== Optimized LPM API ====================

/**
 * @brief Initialize optimized LPM table
 * @return Pointer to LPM table, NULL on failure
 */
optimized_lpm_t *perf_lpm_init(void);

/**
 * @brief Cleanup LPM table
 * @param lpm LPM table
 */
void perf_lpm_cleanup(optimized_lpm_t *lpm);

/**
 * @brief Add network to LPM table
 * @param lpm LPM table
 * @param ip Network IP (host byte order)
 * @param prefix_len Prefix length
 * @param tenant_id Tenant identifier
 * @return 0 on success
 */
int perf_lpm_add(optimized_lpm_t *lpm, uint32_t ip, uint8_t prefix_len,
                 uint16_t tenant_id);

/**
 * @brief Remove network from LPM table
 * @param lpm LPM table
 * @param ip Network IP
 * @param prefix_len Prefix length
 * @return 0 on success
 */
int perf_lpm_remove(optimized_lpm_t *lpm, uint32_t ip, uint8_t prefix_len);

/**
 * @brief Fast IP-to-tenant lookup (< 20 cycles for /24)
 * @param lpm LPM table
 * @param ip IP address (network byte order)
 * @return Tenant ID, 0 if not found
 */
static inline uint16_t perf_lpm_lookup(const optimized_lpm_t *lpm, uint32_t ip) {
    // Convert from network to host byte order
    uint32_t host_ip = __builtin_bswap32(ip);

    // Direct /24 lookup - O(1)
    uint16_t tenant_id = lpm->direct_table_24[host_ip >> 8];
    if (tenant_id != 0) {
        return tenant_id;
    }

    // Fallback for longer prefixes (rare path)
    // Would use hash lookup in production
    return 0;
}

/**
 * @brief Batch IP-to-tenant lookup
 * @param lpm LPM table
 * @param ips Array of IP addresses
 * @param tenant_ids Output array of tenant IDs
 * @param count Number of lookups
 */
void perf_lpm_lookup_batch(const optimized_lpm_t *lpm, const uint32_t *ips,
                           uint16_t *tenant_ids, uint32_t count);

// ==================== Batch Processing API ====================

/**
 * @brief Initialize batch context
 * @param batch Batch context
 */
void perf_batch_init(batch_context_t *batch);

/**
 * @brief Add packet to batch
 * @param batch Batch context
 * @param tenant_id Tenant ID
 * @param src_ip Source IP
 * @param dst_ip Destination IP
 * @param src_port Source port
 * @param dst_port Destination port
 * @param protocol IP protocol
 * @return Index in batch, or -1 if full
 */
int perf_batch_add(batch_context_t *batch, uint32_t tenant_id,
                   uint32_t src_ip, uint32_t dst_ip,
                   uint16_t src_port, uint16_t dst_port, uint8_t protocol);

/**
 * @brief Process batch of packets
 * @param batch Batch context
 * @return Number of packets passed
 */
uint32_t perf_batch_process(batch_context_t *batch);

// ==================== Rate Limiting (Optimized) ====================

/**
 * @brief Fast rate limit check using cached tokens
 * @param cache Tenant cache
 * @param pps Packets per second to check
 * @param bps Bits per second to check
 * @return true if within limits
 */
static inline bool perf_rate_limit_check(lcore_tenant_cache_t *cache,
                                         uint64_t pps, uint64_t bps) {
    // Token bucket algorithm with cached state
    uint64_t now = __builtin_ia32_rdtsc();
    uint64_t elapsed = now - cache->last_update_tsc;

    // Refill tokens (simplified - assumes 1 token per cycle at limit)
    uint64_t refill_pps = (elapsed * cache->rate_limit_pps) / 1000000000ULL;
    uint64_t refill_bps = (elapsed * cache->rate_limit_bps) / 1000000000ULL;

    cache->tokens_pps = (cache->tokens_pps + refill_pps > cache->rate_limit_pps) ?
                        cache->rate_limit_pps : cache->tokens_pps + refill_pps;
    cache->tokens_bps = (cache->tokens_bps + refill_bps > cache->rate_limit_bps) ?
                        cache->rate_limit_bps : cache->tokens_bps + refill_bps;

    cache->last_update_tsc = now;

    // Check if tokens available
    if (cache->tokens_pps >= pps && cache->tokens_bps >= bps) {
        cache->tokens_pps -= pps;
        cache->tokens_bps -= bps;
        return true;
    }

    return false;
}

// ==================== Geo-blocking (Optimized) ====================

/**
 * @brief Fast geo-blocking check using bitmap
 * @param cache Tenant cache
 * @param country_code Country code (1-255)
 * @return true if country is blocked
 */
static inline bool perf_geo_check(const lcore_tenant_cache_t *cache,
                                  uint8_t country_code) {
    if (!cache->geo_blocking_enabled || country_code == 0) {
        return false;
    }

    uint32_t word_idx = country_code / 32;
    uint32_t bit_idx = country_code % 32;

    return (cache->geo_blocked_bitmap[word_idx] >> bit_idx) & 1;
}

// ==================== Statistics (Optimized) ====================

/**
 * @brief Batch update statistics
 * @param cache Lcore cache
 * @param tenant_id Tenant ID
 * @param pps Packets
 * @param bps Bytes
 */
static inline void perf_stats_update(lcore_cache_t *cache, uint32_t tenant_id,
                                     uint64_t pps, uint64_t bps) {
    if (tenant_id < PERF_MAX_TENANTS) {
        cache->stats_batch_pps[tenant_id] += pps;
        cache->stats_batch_bps[tenant_id] += bps;
        cache->stats_batch_count++;
    }
}

/**
 * @brief Flush statistics batch to global counters
 * @param cache Lcore cache
 */
void perf_stats_flush(lcore_cache_t *cache);

// ==================== Profiling API ====================

/**
 * @brief Hot path profiler entry
 */
typedef struct {
    const char *name;
    uint64_t total_cycles;
    uint64_t call_count;
    uint64_t min_cycles;
    uint64_t max_cycles;
} perf_profile_entry_t;

/**
 * @brief Start profiling a hot path
 * @param name Path name
 * @return Start timestamp
 */
static inline uint64_t perf_profile_start(const char *name) {
    (void)name;
    return __builtin_ia32_rdtsc();
}

/**
 * @brief End profiling a hot path
 * @param name Path name
 * @param start Start timestamp
 */
void perf_profile_end(const char *name, uint64_t start);

/**
 * @brief Get profiling results
 * @param entries Output array
 * @param max_entries Maximum entries
 * @return Number of entries
 */
int perf_profile_get_results(perf_profile_entry_t *entries, int max_entries);

/**
 * @brief Reset profiling counters
 */
void perf_profile_reset(void);

/**
 * @brief Print profiling report
 */
void perf_profile_report(void);

// ==================== Memory Optimization ====================

/**
 * @brief Allocate cache-aligned memory
 * @param size Allocation size
 * @param alignment Alignment (must be power of 2)
 * @return Aligned pointer, NULL on failure
 */
void *perf_alloc_aligned(size_t size, size_t alignment);

/**
 * @brief Free cache-aligned memory
 * @param ptr Pointer to free
 */
void perf_free_aligned(void *ptr);

/**
 * @brief Prefetch data for read
 * @param addr Address to prefetch
 */
static inline void perf_prefetch_read(const void *addr) {
    __builtin_prefetch(addr, 0, 3);
}

/**
 * @brief Prefetch data for write
 * @param addr Address to prefetch
 */
static inline void perf_prefetch_write(void *addr) {
    __builtin_prefetch(addr, 1, 3);
}

#endif /* PERFORMANCE_OPTIMIZATION_H */
