/**
 * @file shared_table_test.h
 * @brief Harness shared by the unit tests of the Layer 1 tables written from
 *        several lcores (test_tcp_flag_rate.c, test_connection_limits.c,
 *        test_per_ip_unregister.c, test_src_ip_stats.c, test_spike_detector.c).
 *
 * A failed check prints its line, counts the subtest as failed and jumps to
 * the subtest's "out:" label, where the subtest releases what it set up (its
 * module, a registered flow table reader), so that one failure does not
 * cascade into the next subtest.
 *
 * EAL runs on up to four lcores, one per CPU the process may use (lcore 0
 * is the main lcore), with --no-huge --no-shconf --no-telemetry, so that
 * meson can run the tests in parallel. A stress subtest that finds no worker
 * lcore prints a NOTE and runs its jobs on lcore 0 alone.
 */

#ifndef SHARED_TABLE_TEST_H
#define SHARED_TABLE_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sched.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_pause.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define CHECK(expr, msg) do { \
    if (!(expr)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        tests_failed++; \
        goto out; \
    } \
} while (0)

#define CHECK_EQ(expected, actual, msg) do { \
    long long check_e_ = (long long)(expected); \
    long long check_a_ = (long long)(actual); \
    if (check_e_ != check_a_) { \
        printf("  FAIL: %s (expected=%lld, actual=%lld, line %d)\n", msg, \
               check_e_, check_a_, __LINE__); \
        tests_failed++; \
        goto out; \
    } \
} while (0)

#define RUN_TEST(test_func) do { \
    printf("Running %s...\n", #test_func); \
    fflush(stdout); \
    tests_run++; \
    int before_ = tests_failed; \
    test_func(); \
    if (tests_failed == before_) { tests_passed++; printf("  PASS\n"); } \
    fflush(stdout); \
} while (0)

// "--lcores" map of up to four lcores, lcore n on the n-th CPU this
// process may run on
static inline void table_test_lcore_map(char *buf, size_t len) {
    cpu_set_t set;
    unsigned int n = 0;
    size_t off = 0;

    if (sched_getaffinity(0, sizeof(set), &set) == 0) {
        for (int cpu = 0; cpu < CPU_SETSIZE && n < 4; cpu++) {
            if (!CPU_ISSET(cpu, &set)) {
                continue;
            }
            int w = snprintf(buf + off, len - off, "%s%u@%d", n ? "," : "", n, cpu);
            if (w < 0 || (size_t)w >= len - off) {
                break;
            }
            off += (size_t)w;
            n++;
        }
    }
    if (n == 0) {
        snprintf(buf, len, "0@0");
    }
}

// @return 0, or 77 (meson's skip code) if EAL cannot initialise
static inline int table_test_eal_init(char *argv0) {
    static char lcore_map[64];
    table_test_lcore_map(lcore_map, sizeof(lcore_map));
    char *eal_args[] = {
        argv0,
        "--lcores", lcore_map,
        "-n", "1",
        "--no-huge",
        "--no-pci",
        "-m", "512",
        "--no-shconf",
        "--no-telemetry",
        NULL
    };
    int eal_argc = (int)RTE_DIM(eal_args) - 1;
    if (rte_eal_init(eal_argc, eal_args) < 0) {
        fprintf(stderr, "EAL init failed (missing DPDK permissions / runtime directory): skipping test\n");
        return 77;
    }
    return 0;
}

// Workers of a stress subtest start together
static uint32_t table_test_go = 0;

static inline void table_test_start_wait(void) {
    while (!__atomic_load_n(&table_test_go, __ATOMIC_ACQUIRE)) {
        rte_pause();
    }
}

#define TABLE_TEST_MAX_WORKERS 3

struct table_test_job {
    lcore_function_t *fn;
    void *arg;
};
static struct table_test_job table_test_jobs[TABLE_TEST_MAX_WORKERS];
static uint32_t table_test_done = 0;

static inline int table_test_job_main(void *arg) {
    struct table_test_job *job = arg;
    int rc = job->fn(job->arg);
    __atomic_fetch_add(&table_test_done, 1, __ATOMIC_ACQ_REL);
    return rc;
}

/**
 * Run fn(args[k]) on up to TABLE_TEST_MAX_WORKERS worker lcores at once and,
 * until they finish, main_step() (if given) on the calling lcore. Each job
 * should call table_test_start_wait() first. With no worker lcore one job
 * runs on the calling lcore, with a NOTE.
 *
 * @return the number of jobs that ran
 */
static inline unsigned int table_test_run(lcore_function_t *fn, void *args[TABLE_TEST_MAX_WORKERS],
                                          void (*main_step)(void)) {
    unsigned int lcores[TABLE_TEST_MAX_WORKERS];
    unsigned int n = 0;
    unsigned int lcore_id;

    __atomic_store_n(&table_test_go, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&table_test_done, 0, __ATOMIC_RELEASE);
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (n == TABLE_TEST_MAX_WORKERS) {
            break;
        }
        table_test_jobs[n].fn = fn;
        table_test_jobs[n].arg = args[n];
        if (rte_eal_remote_launch(table_test_job_main, &table_test_jobs[n], lcore_id) != 0) {
            break;
        }
        lcores[n++] = lcore_id;
    }
    __atomic_store_n(&table_test_go, 1, __ATOMIC_RELEASE);

    if (n == 0) {
        printf("  NOTE: no worker lcore, one job runs alone (no concurrency)\n");
        fflush(stdout);
        fn(args[0]);
        return 1;
    }
    while (__atomic_load_n(&table_test_done, __ATOMIC_ACQUIRE) < n) {
        if (main_step) {
            main_step();
        } else {
            rte_pause();
        }
    }
    for (unsigned int k = 0; k < n; k++) {
        rte_eal_wait_lcore(lcores[k]);
    }
    return n;
}

static inline int table_test_report(const char *title) {
    printf("\n========================================\n");
    printf("  %s: %d/%d passed, %d failed\n", title, tests_passed, tests_run, tests_failed);
    printf("========================================\n\n");
    return tests_failed ? 1 : 0;
}

#endif // SHARED_TABLE_TEST_H
