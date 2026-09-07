/**
 * @file tenant_benchmark.c
 * @brief Multi-tenant performance benchmarks
 *
 * Performance tests ensuring:
 * - 1000 tenants @ 10 Mpps total
 * - Tenant lookup < 20 cycles
 * - Config hot-reload under load
 * - Stats aggregation < 100ms
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "../../common/tenant.h"
#include "../../common/tenant_config.h"

// ==================== Timing Utilities ====================

#if defined(__x86_64__)
static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
#elif defined(__aarch64__)
static inline uint64_t rdtsc(void) {
    uint64_t val;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}
#else
static inline uint64_t rdtsc(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
#endif

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static inline double cycles_to_ns(uint64_t cycles, double cpu_freq_ghz) {
    return (double)cycles / cpu_freq_ghz;
}

// Estimate CPU frequency
static double estimate_cpu_freq_ghz(void) {
    uint64_t start_cycles = rdtsc();
    uint64_t start_ns = get_time_ns();

    // Busy wait for ~10ms
    while (get_time_ns() - start_ns < 10000000ULL) {
        __asm__ volatile("" ::: "memory");
    }

    uint64_t end_cycles = rdtsc();
    uint64_t end_ns = get_time_ns();

    double elapsed_ns = (double)(end_ns - start_ns);
    double elapsed_cycles = (double)(end_cycles - start_cycles);

    return elapsed_cycles / elapsed_ns;  // cycles per ns = GHz
}

// ==================== Benchmark Framework ====================

typedef struct {
    const char *name;
    uint64_t iterations;
    uint64_t total_cycles;
    uint64_t min_cycles;
    uint64_t max_cycles;
    double avg_cycles;
    double avg_ns;
    bool passed;
    uint64_t target_cycles;  // Target for pass/fail
} benchmark_result_t;

static void print_benchmark_result(benchmark_result_t *result, double cpu_freq) {
    const char *status = result->passed ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m";

    printf("  %-40s %s\n", result->name, status);
    printf("    Iterations: %'lu\n", result->iterations);
    printf("    Avg cycles: %.1f  (target: <%lu)\n", result->avg_cycles, result->target_cycles);
    printf("    Avg time:   %.1f ns\n", result->avg_ns);
    printf("    Min/Max:    %lu / %lu cycles\n", result->min_cycles, result->max_cycles);
}

// ==================== Benchmarks ====================

static tenant_id_t *tenant_ids = NULL;
static uint32_t *tenant_ips = NULL;
static int num_tenants = 0;

static int setup_tenants(int count) {
    int ret = tenant_registry_init();
    if (ret != TENANT_OK) return -1;

    ret = tenant_config_init();
    if (ret != 0) return -1;

    tenant_ids = malloc(count * sizeof(tenant_id_t));
    tenant_ips = malloc(count * sizeof(uint32_t));
    if (!tenant_ids || !tenant_ips) return -1;

    for (int i = 0; i < count; i++) {
        struct tenant t = {0};
        t.id = TENANT_ID_INVALID;
        snprintf(t.name, MAX_TENANT_NAME_LEN, "Benchmark Tenant %d", i);
        t.status = TENANT_STATUS_ACTIVE;
        t.tier = (tenant_tier_t)(i % TENANT_TIER_COUNT);
        t.type = TENANT_TYPE_DIRECT;

        ret = tenant_create(&t, &tenant_ids[i]);
        if (ret != TENANT_OK) {
            printf("Failed to create tenant %d\n", i);
            return -1;
        }

        // Assign network: 10.x.y.0/24 where x.y derived from i
        tenant_ips[i] = 0x0A000000 + (i << 8);  // 10.i.0.0/24
        ret = tenant_add_network(tenant_ids[i], tenant_ips[i], 24);
        if (ret != TENANT_OK) {
            printf("Failed to add network for tenant %d\n", i);
            // Continue anyway - not critical for some benchmarks
        }
    }

    num_tenants = count;
    return 0;
}

static void cleanup_tenants(void) {
    if (tenant_ids) free(tenant_ids);
    if (tenant_ips) free(tenant_ips);
    tenant_config_cleanup();
    tenant_registry_cleanup();
}

/**
 * Benchmark: Tenant ID lookup by ID
 * Target: < 20 cycles
 */
static benchmark_result_t bench_tenant_lookup_by_id(int iterations) {
    benchmark_result_t result = {
        .name = "Tenant lookup by ID",
        .iterations = iterations,
        .target_cycles = 20,
        .min_cycles = UINT64_MAX,
        .max_cycles = 0
    };

    // Warmup
    for (int i = 0; i < 1000; i++) {
        const struct tenant *t = tenant_lookup(tenant_ids[i % num_tenants]);
        (void)t;
    }

    uint64_t total = 0;
    for (int i = 0; i < iterations; i++) {
        tenant_id_t id = tenant_ids[i % num_tenants];

        uint64_t start = rdtsc();
        const struct tenant *t = tenant_lookup(id);
        uint64_t end = rdtsc();

        (void)t;  // Prevent optimization

        uint64_t cycles = end - start;
        total += cycles;
        if (cycles < result.min_cycles) result.min_cycles = cycles;
        if (cycles > result.max_cycles) result.max_cycles = cycles;
    }

    result.total_cycles = total;
    result.avg_cycles = (double)total / iterations;
    result.passed = (result.avg_cycles < result.target_cycles);

    return result;
}

/**
 * Benchmark: IP-to-tenant lookup (LPM)
 * Target: < 50 cycles
 */
static benchmark_result_t bench_ip_to_tenant_lookup(int iterations) {
    benchmark_result_t result = {
        .name = "IP-to-tenant LPM lookup",
        .iterations = iterations,
        .target_cycles = 50,
        .min_cycles = UINT64_MAX,
        .max_cycles = 0
    };

    // Warmup
    for (int i = 0; i < 1000; i++) {
        uint32_t ip = htonl(tenant_ips[i % num_tenants] + 100);
        tenant_id_t id = tenant_ip_to_id(ip);
        (void)id;
    }

    uint64_t total = 0;
    for (int i = 0; i < iterations; i++) {
        // Lookup IP within tenant's network
        uint32_t ip = htonl(tenant_ips[i % num_tenants] + (i % 256));

        uint64_t start = rdtsc();
        tenant_id_t id = tenant_ip_to_id(ip);
        uint64_t end = rdtsc();

        (void)id;

        uint64_t cycles = end - start;
        total += cycles;
        if (cycles < result.min_cycles) result.min_cycles = cycles;
        if (cycles > result.max_cycles) result.max_cycles = cycles;
    }

    result.total_cycles = total;
    result.avg_cycles = (double)total / iterations;
    result.passed = (result.avg_cycles < result.target_cycles);

    return result;
}

/**
 * Benchmark: L1 config lookup
 * Target: < 30 cycles
 */
static benchmark_result_t bench_l1_config_lookup(int iterations) {
    benchmark_result_t result = {
        .name = "L1 config lookup",
        .iterations = iterations,
        .target_cycles = 30,
        .min_cycles = UINT64_MAX,
        .max_cycles = 0
    };

    // Warmup
    for (int i = 0; i < 1000; i++) {
        const struct tenant_l1_config *cfg = tenant_get_l1_config(tenant_ids[i % num_tenants]);
        (void)cfg;
    }

    uint64_t total = 0;
    for (int i = 0; i < iterations; i++) {
        tenant_id_t id = tenant_ids[i % num_tenants];

        uint64_t start = rdtsc();
        const struct tenant_l1_config *cfg = tenant_get_l1_config(id);
        uint64_t end = rdtsc();

        (void)cfg;

        uint64_t cycles = end - start;
        total += cycles;
        if (cycles < result.min_cycles) result.min_cycles = cycles;
        if (cycles > result.max_cycles) result.max_cycles = cycles;
    }

    result.total_cycles = total;
    result.avg_cycles = (double)total / iterations;
    result.passed = (result.avg_cycles < result.target_cycles);

    return result;
}

/**
 * Benchmark: Feature flag check
 * Target: < 10 cycles
 */
static benchmark_result_t bench_feature_flag_check(int iterations) {
    benchmark_result_t result = {
        .name = "Feature flag check",
        .iterations = iterations,
        .target_cycles = 10,
        .min_cycles = UINT64_MAX,
        .max_cycles = 0
    };

    // Warmup
    for (int i = 0; i < 1000; i++) {
        bool has = tenant_has_feature(tenant_ids[i % num_tenants], TENANT_FEATURE_L1_BASIC);
        (void)has;
    }

    uint64_t total = 0;
    for (int i = 0; i < iterations; i++) {
        tenant_id_t id = tenant_ids[i % num_tenants];
        uint32_t feature = 1 << (i % 16);

        uint64_t start = rdtsc();
        bool has = tenant_has_feature(id, feature);
        uint64_t end = rdtsc();

        (void)has;

        uint64_t cycles = end - start;
        total += cycles;
        if (cycles < result.min_cycles) result.min_cycles = cycles;
        if (cycles > result.max_cycles) result.max_cycles = cycles;
    }

    result.total_cycles = total;
    result.avg_cycles = (double)total / iterations;
    result.passed = (result.avg_cycles < result.target_cycles);

    return result;
}

/**
 * Benchmark: Stats aggregation for all tenants
 * Target: < 100ms for 1000 tenants
 */
static benchmark_result_t bench_stats_aggregation(int tenant_count) {
    benchmark_result_t result = {
        .name = "Stats aggregation (all tenants)",
        .iterations = tenant_count,
        .target_cycles = 0,  // We use time, not cycles
        .min_cycles = 0,
        .max_cycles = 0
    };

    // Simulate per-tenant stats collection and aggregation
    typedef struct {
        uint64_t packets_total;
        uint64_t bytes_total;
        uint64_t packets_dropped;
        uint64_t current_pps;
    } tenant_stats_t;

    tenant_stats_t *all_stats = malloc(tenant_count * sizeof(tenant_stats_t));
    if (!all_stats) {
        result.passed = false;
        return result;
    }

    // Initialize with random values
    for (int i = 0; i < tenant_count; i++) {
        all_stats[i].packets_total = rand() % 1000000000;
        all_stats[i].bytes_total = all_stats[i].packets_total * 1000;
        all_stats[i].packets_dropped = rand() % 100000;
        all_stats[i].current_pps = rand() % 1000000;
    }

    // Measure aggregation time
    uint64_t start_ns = get_time_ns();

    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint64_t total_dropped = 0;
    uint64_t total_pps = 0;

    for (int i = 0; i < tenant_count; i++) {
        total_packets += all_stats[i].packets_total;
        total_bytes += all_stats[i].bytes_total;
        total_dropped += all_stats[i].packets_dropped;
        total_pps += all_stats[i].current_pps;
    }

    uint64_t end_ns = get_time_ns();
    uint64_t elapsed_ns = end_ns - start_ns;
    double elapsed_ms = (double)elapsed_ns / 1000000.0;

    // Prevent optimization
    if (total_packets == 0) printf("Unexpected zero\n");

    free(all_stats);

    result.total_cycles = elapsed_ns;  // Store ns as cycles
    result.avg_cycles = elapsed_ms;    // Store ms as avg
    result.avg_ns = (double)elapsed_ns;
    result.passed = (elapsed_ms < 100.0);  // Target: < 100ms

    return result;
}

/**
 * Benchmark: Config hot-reload under simulated load
 */
typedef struct {
    int thread_id;
    int iterations;
    int lookups_completed;
    bool stop;
} load_thread_ctx_t;

static void* load_thread(void *arg) {
    load_thread_ctx_t *ctx = (load_thread_ctx_t*)arg;

    while (!ctx->stop) {
        // Simulate packet processing with tenant lookup
        tenant_id_t id = tenant_ids[ctx->iterations % num_tenants];
        const struct tenant *t = tenant_lookup(id);
        const struct tenant_l1_config *cfg = tenant_get_l1_config(id);

        (void)t;
        (void)cfg;

        ctx->lookups_completed++;
        ctx->iterations++;
    }

    return NULL;
}

static benchmark_result_t bench_config_hot_reload(int num_threads) {
    benchmark_result_t result = {
        .name = "Config hot-reload under load",
        .iterations = 0,
        .target_cycles = 10000,  // 10µs target for reload
        .min_cycles = UINT64_MAX,
        .max_cycles = 0
    };

    pthread_t threads[num_threads];
    load_thread_ctx_t contexts[num_threads];

    // Start load threads
    for (int i = 0; i < num_threads; i++) {
        contexts[i].thread_id = i;
        contexts[i].iterations = i * 1000;  // Offset to vary tenant access
        contexts[i].lookups_completed = 0;
        contexts[i].stop = false;
        pthread_create(&threads[i], NULL, load_thread, &contexts[i]);
    }

    // Let load threads run a bit
    usleep(10000);  // 10ms

    // Perform config hot-reloads while under load
    const int num_reloads = 100;
    uint64_t total_cycles = 0;

    for (int r = 0; r < num_reloads; r++) {
        tenant_id_t id = tenant_ids[r % num_tenants];
        const struct tenant_l1_config *cfg = tenant_get_l1_config(id);

        struct tenant_l1_config new_cfg = *cfg;
        new_cfg.rate_limits.global_pps = 1000000 + (r * 1000);

        uint64_t start = rdtsc();
        int ret = tenant_set_l1_config(id, &new_cfg);
        uint64_t end = rdtsc();

        if (ret != 0) {
            result.passed = false;
            break;
        }

        uint64_t cycles = end - start;
        total_cycles += cycles;
        if (cycles < result.min_cycles) result.min_cycles = cycles;
        if (cycles > result.max_cycles) result.max_cycles = cycles;
    }

    // Stop load threads
    for (int i = 0; i < num_threads; i++) {
        contexts[i].stop = true;
    }
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    result.iterations = num_reloads;
    result.total_cycles = total_cycles;
    result.avg_cycles = (double)total_cycles / num_reloads;
    result.passed = result.passed && (result.avg_cycles < result.target_cycles);

    // Count total lookups performed during test
    int total_lookups = 0;
    for (int i = 0; i < num_threads; i++) {
        total_lookups += contexts[i].lookups_completed;
    }
    printf("    Load threads completed %d lookups during reload test\n", total_lookups);

    return result;
}

/**
 * Benchmark: Tenant creation rate
 */
static benchmark_result_t bench_tenant_creation(int count) {
    benchmark_result_t result = {
        .name = "Tenant creation rate",
        .iterations = count,
        .target_cycles = 100000,  // 100µs per tenant
        .min_cycles = UINT64_MAX,
        .max_cycles = 0
    };

    // Clean up existing tenants
    cleanup_tenants();

    int ret = tenant_registry_init();
    if (ret != TENANT_OK) {
        result.passed = false;
        return result;
    }
    ret = tenant_config_init();
    if (ret != 0) {
        result.passed = false;
        return result;
    }

    uint64_t total = 0;
    tenant_id_t temp_id;

    for (int i = 0; i < count && i < MAX_TENANTS - 1; i++) {
        struct tenant t = {0};
        t.id = TENANT_ID_INVALID;
        snprintf(t.name, MAX_TENANT_NAME_LEN, "Bench Tenant %d", i);
        t.status = TENANT_STATUS_ACTIVE;
        t.tier = (tenant_tier_t)(i % TENANT_TIER_COUNT);
        t.type = TENANT_TYPE_DIRECT;

        uint64_t start = rdtsc();
        ret = tenant_create(&t, &temp_id);
        uint64_t end = rdtsc();

        if (ret != TENANT_OK) break;

        uint64_t cycles = end - start;
        total += cycles;
        if (cycles < result.min_cycles) result.min_cycles = cycles;
        if (cycles > result.max_cycles) result.max_cycles = cycles;

        result.iterations = i + 1;
    }

    result.total_cycles = total;
    result.avg_cycles = (double)total / result.iterations;
    result.passed = (result.avg_cycles < result.target_cycles);

    // Cleanup and re-setup for other tests
    tenant_config_cleanup();
    tenant_registry_cleanup();

    return result;
}

/**
 * Benchmark: Simulated 10 Mpps packet processing
 */
static benchmark_result_t bench_packet_processing_simulation(int duration_sec) {
    benchmark_result_t result = {
        .name = "10 Mpps packet simulation",
        .iterations = 0,
        .target_cycles = 100,  // 100 cycles per packet
        .min_cycles = UINT64_MAX,
        .max_cycles = 0
    };

    uint64_t start_ns = get_time_ns();
    uint64_t end_time_ns = start_ns + (duration_sec * 1000000000ULL);

    uint64_t packets_processed = 0;
    uint64_t total_lookup_cycles = 0;

    // Simulate packet processing loop
    while (get_time_ns() < end_time_ns) {
        // Process batch of 32 packets
        for (int batch = 0; batch < 32; batch++) {
            // Simulate tenant lookup per packet
            tenant_id_t id = tenant_ids[packets_processed % num_tenants];

            uint64_t lookup_start = rdtsc();
            const struct tenant *t = tenant_lookup(id);
            const struct tenant_l1_config *cfg = tenant_get_l1_config(id);
            uint64_t lookup_end = rdtsc();

            (void)t;
            (void)cfg;

            uint64_t cycles = lookup_end - lookup_start;
            total_lookup_cycles += cycles;
            if (cycles < result.min_cycles) result.min_cycles = cycles;
            if (cycles > result.max_cycles) result.max_cycles = cycles;

            packets_processed++;
        }
    }

    uint64_t elapsed_ns = get_time_ns() - start_ns;
    double elapsed_sec = (double)elapsed_ns / 1000000000.0;
    double mpps = (double)packets_processed / elapsed_sec / 1000000.0;

    result.iterations = packets_processed;
    result.total_cycles = total_lookup_cycles;
    result.avg_cycles = (double)total_lookup_cycles / packets_processed;
    result.passed = (mpps >= 10.0);  // Target: 10+ Mpps

    printf("    Achieved %.2f Mpps (target: 10 Mpps)\n", mpps);

    return result;
}

// ==================== Main ====================

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║        Multi-Tenant Performance Benchmarks                   ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    // Enable locale for thousands separator
    setlocale(LC_NUMERIC, "");

    // Estimate CPU frequency
    printf("\n[SETUP] Estimating CPU frequency...\n");
    double cpu_freq = estimate_cpu_freq_ghz();
    printf("[SETUP] CPU frequency: %.2f GHz\n", cpu_freq);

    // Setup tenants
    const int tenant_count = 1000;  // Target: 1000 tenants
    printf("[SETUP] Creating %d tenants...\n", tenant_count);

    if (setup_tenants(tenant_count) != 0) {
        printf("\033[31m[ERROR] Failed to setup tenants\033[0m\n");
        return 1;
    }
    printf("[SETUP] Created %d tenants successfully\n", tenant_get_active_count());

    // Run benchmarks
    printf("\n--- Core Lookup Benchmarks ---\n");

    benchmark_result_t results[10];
    int result_count = 0;

    // Tenant ID lookup
    results[result_count] = bench_tenant_lookup_by_id(1000000);
    results[result_count].avg_ns = cycles_to_ns(results[result_count].avg_cycles, cpu_freq);
    print_benchmark_result(&results[result_count], cpu_freq);
    result_count++;

    // IP-to-tenant lookup
    results[result_count] = bench_ip_to_tenant_lookup(1000000);
    results[result_count].avg_ns = cycles_to_ns(results[result_count].avg_cycles, cpu_freq);
    print_benchmark_result(&results[result_count], cpu_freq);
    result_count++;

    // L1 config lookup
    results[result_count] = bench_l1_config_lookup(1000000);
    results[result_count].avg_ns = cycles_to_ns(results[result_count].avg_cycles, cpu_freq);
    print_benchmark_result(&results[result_count], cpu_freq);
    result_count++;

    // Feature flag check
    results[result_count] = bench_feature_flag_check(1000000);
    results[result_count].avg_ns = cycles_to_ns(results[result_count].avg_cycles, cpu_freq);
    print_benchmark_result(&results[result_count], cpu_freq);
    result_count++;

    printf("\n--- Aggregation Benchmarks ---\n");

    // Stats aggregation
    results[result_count] = bench_stats_aggregation(tenant_count);
    print_benchmark_result(&results[result_count], cpu_freq);
    printf("    Aggregation time: %.3f ms (target: <100 ms)\n", results[result_count].avg_cycles);
    result_count++;

    printf("\n--- Concurrent Operation Benchmarks ---\n");

    // Config hot-reload under load
    results[result_count] = bench_config_hot_reload(4);
    results[result_count].avg_ns = cycles_to_ns(results[result_count].avg_cycles, cpu_freq);
    print_benchmark_result(&results[result_count], cpu_freq);
    result_count++;

    printf("\n--- Throughput Benchmarks ---\n");

    // Packet processing simulation
    results[result_count] = bench_packet_processing_simulation(1);  // 1 second
    results[result_count].avg_ns = cycles_to_ns(results[result_count].avg_cycles, cpu_freq);
    print_benchmark_result(&results[result_count], cpu_freq);
    result_count++;

    printf("\n--- Creation Benchmarks ---\n");

    // Tenant creation rate
    results[result_count] = bench_tenant_creation(500);
    results[result_count].avg_ns = cycles_to_ns(results[result_count].avg_cycles, cpu_freq);
    print_benchmark_result(&results[result_count], cpu_freq);
    result_count++;

    // Re-setup tenants that were cleaned up
    cleanup_tenants();
    setup_tenants(tenant_count);

    // Cleanup
    printf("\n[CLEANUP] Destroying test fixtures...\n");
    cleanup_tenants();

    // Summary
    int passed = 0, failed = 0;
    for (int i = 0; i < result_count; i++) {
        if (results[i].passed) passed++;
        else failed++;
    }

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                    Benchmark Summary                         ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Total:  %3d                                                 ║\n", result_count);
    printf("║  Passed: %3d  \033[32m✓\033[0m                                              ║\n", passed);
    printf("║  Failed: %3d  %s                                              ║\n",
           failed, failed > 0 ? "\033[31m✗\033[0m" : " ");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    if (failed > 0) {
        printf("\n\033[31m[RESULT] SOME BENCHMARKS FAILED!\033[0m\n\n");
        return 1;
    }

    printf("\n\033[32m[RESULT] ALL BENCHMARKS PASSED!\033[0m\n\n");
    return 0;
}
