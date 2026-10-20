/**
 * @file test_ip_lists.c
 * @brief Unit tests of ip_lists.c: writers of the whitelist from several
 *        threads at once, and the legitimate-source table (sources that
 *        returned a valid SYN cookie): bounded, expiring, never the
 *        whitelist, and written from every packet lcore without a lock.
 *
 * Requires DPDK EAL (rte_hash, rte_lpm, rte_malloc) and runs with --no-huge
 * --no-shconf --no-telemetry like the other per-module tests; exits 77 (skip)
 * if EAL cannot initialise. The concurrency subtests run on up to four lcores,
 * each on a CPU of its own, as the packet lcores and the control thread
 * would; what they assert holds on a correct tree whatever the interleaving.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sched.h>

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_pause.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>
#include <rte_common.h>

#include "../../layer1/tables/ip_lists.h"

// ==================== Test Framework ====================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(expr, msg) do { \
    if (!(expr)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while (0)

#define TEST_ASSERT_EQ(expected, actual, msg) do { \
    long e_ = (long)(expected), a_ = (long)(actual); \
    if (e_ != a_) { \
        printf("  FAIL: %s (expected=%ld, actual=%ld, line %d)\n", msg, e_, a_, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while (0)

// legitimate_ip_clock() of this binary: the TSC, or a time a subtest holds
static uint64_t legit_clock_held = 0;

uint64_t legitimate_ip_clock(void) {
    return legit_clock_held ? legit_clock_held : rte_get_tsc_cycles();
}

// ip_lists_write_seam() of this binary: counts the writes, and those made
// without the module's writer lock
static int write_seam_calls = 0, write_seam_unlocked = 0;

void ip_lists_write_seam(void) {
    write_seam_calls++;
    if (!ip_lists_writer_lock_held()) {
        write_seam_unlocked++;
    }
}

// legitimate_ip_add_seam() of this binary: once armed with a source, the
// add it runs in meets another lcore's add of that source between its look
// at the set and its swap (the nested add sees the seam disarmed)
static uint32_t add_seam_source = 0;

void legitimate_ip_add_seam(void) {
    if (add_seam_source != 0) {
        const uint32_t ip = add_seam_source;
        add_seam_source = 0;
        legitimate_ip_add(ip);
    }
}

// A failed assertion returns before the subtest's cleanup: release the
// tables here so that every subtest starts clean, and release the clock
#define RUN_TEST(test_func) do { \
    printf("Running %s...\n", #test_func); \
    tests_run++; \
    int failed_before = tests_failed; \
    test_func(); \
    legit_clock_held = 0; \
    add_seam_source = 0; \
    legitimate_ip_free(); \
    if (tests_failed > failed_before) { \
        ip_lists_cleanup(); \
    } else { \
        tests_passed++; \
        printf("  PASS\n"); \
    } \
} while (0)

static int lists_init(uint32_t whitelist_entries) {
    struct ip_lists_config cfg = {
        .max_whitelist_entries = whitelist_entries,
        .max_blacklist_entries = 1024,
        .max_protected_entries = 64,
        .max_whitelist_cidrs = 64,
        .enforce_protected_ips = false,
    };
    return ip_lists_init(&cfg);
}

// Source n of a test, network byte order: 10.x.y.z, never 0
static uint32_t source(uint32_t base, uint32_t n) {
    return rte_cpu_to_be_32(base + n);
}

// ==================== Lcores ====================

// main() maps up to four lcores to CPUs of their own (the first CPUs this
// process may use), so the jobs below run at once; a plain thread would
// inherit lcore 0's CPU and only interleave with it. With one CPU the
// subtests still check their invariants but show no concurrency.
enum job_op {
    JOB_NONE = 0,
    JOB_WHITELIST_ADD,
    JOB_WHITELIST_REMOVE,
    JOB_LEGIT_ADD,
    JOB_LEGIT_READ,         // lookups and cleanup passes until the writers are done
};

struct lcore_job {
    enum job_op op;
    uint32_t base;          // First source of this lcore (host order)
    uint32_t count;
};

static struct lcore_job jobs[RTE_MAX_LCORE];
static uint32_t jobs_arrived = 0, jobs_done = 0, jobs_total = 0, writers_left = 0;
static uint64_t reader_rounds = 0;

static int run_job(void *arg) {
    (void)arg;
    const struct lcore_job *job = &jobs[rte_lcore_index(rte_lcore_id())];
    const uint32_t total = __atomic_load_n(&jobs_total, __ATOMIC_RELAXED);
    // Start together
    __atomic_add_fetch(&jobs_arrived, 1, __ATOMIC_ACQ_REL);
    while (__atomic_load_n(&jobs_arrived, __ATOMIC_ACQUIRE) < total) {
        rte_pause();
    }
    switch (job->op) {
    case JOB_WHITELIST_ADD:
        for (uint32_t i = 0; i < job->count; i++) {
            ip_whitelist_add(source(job->base, i), WL_MODE_BYPASS);
        }
        break;
    case JOB_WHITELIST_REMOVE:
        for (uint32_t i = 0; i < job->count; i++) {
            ip_whitelist_remove(source(job->base, i));
        }
        break;
    case JOB_LEGIT_ADD:
        for (uint32_t i = 0; i < job->count; i++) {
            legitimate_ip_add(source(job->base, i));
        }
        break;
    case JOB_LEGIT_READ:
        do {
            for (uint32_t i = 0; i < job->count; i += 7) {
                (void)legitimate_ip_lookup(source(job->base, i));
            }
            (void)legitimate_ip_cleanup();
            __atomic_add_fetch(&reader_rounds, 1, __ATOMIC_RELAXED);
        } while (__atomic_load_n(&writers_left, __ATOMIC_ACQUIRE) > 0);
        break;
    case JOB_NONE:
        break;
    }
    if (job->op != JOB_NONE && job->op != JOB_LEGIT_READ) {
        __atomic_sub_fetch(&writers_left, 1, __ATOMIC_ACQ_REL);
    }
    // The last access of the lcore: run_jobs() waits for it, which orders
    // everything the lcore did before whatever main does next. The EAL's
    // own wait orders it too, but in code TSan does not see.
    __atomic_add_fetch(&jobs_done, 1, __ATOMIC_RELEASE);
    return 0;
}

// Runs jobs[0 .. lcores - 1] on every lcore at once and waits for them
static void run_jobs(void) {
    const uint32_t total = rte_lcore_count();
    uint32_t writers = 0;
    for (unsigned int i = 0; i < total; i++) {
        if (jobs[i].op != JOB_NONE && jobs[i].op != JOB_LEGIT_READ) {
            writers++;
        }
    }
    __atomic_store_n(&jobs_total, total, __ATOMIC_RELAXED);
    __atomic_store_n(&jobs_arrived, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&jobs_done, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&writers_left, writers, __ATOMIC_RELAXED);
    rte_eal_mp_remote_launch(run_job, NULL, CALL_MAIN);
    rte_eal_mp_wait_lcore();
    while (__atomic_load_n(&jobs_done, __ATOMIC_ACQUIRE) < total) {
        rte_pause();
    }
}

// ==================== Whitelist Tests ====================

// Four threads add disjoint sources to the whitelist at once, then remove
// half of them at once. Its hash has RW_CONCURRENCY without MULTI_WRITER_ADD,
// so it takes one writer at a time: without the module's writer lock two adds
// could take the same key slot, and a key was lost (the round-4 probe lost
// 218 to 307 of 20,000). The packet path used to be such a writer
// (legitimate_ip_add() on every lcore).
void test_whitelist_concurrent_writers(void) {
    const uint32_t lcores = rte_lcore_count(), per_lcore = 5000, base = 0x0A400000;
    TEST_ASSERT_EQ(0, lists_init(32768), "IP lists should initialize");
    if (lcores < 2) {
        printf("  NOTE: one lcore, no concurrent writers\n");
    }

    memset(jobs, 0, sizeof(jobs));
    for (uint32_t i = 0; i < lcores; i++) {
        jobs[i] = (struct lcore_job){ JOB_WHITELIST_ADD, base + i * per_lcore, per_lcore };
    }
    run_jobs();

    uint32_t missing = 0;
    for (uint32_t i = 0; i < lcores * per_lcore; i++) {
        uint8_t mode = 0xFF;
        if (!ip_whitelist_lookup(source(base, i), &mode) || mode != WL_MODE_BYPASS) {
            missing++;
        }
    }
    printf("  %u lcores: %u of %u concurrent adds missing, count %u\n", lcores, missing,
           lcores * per_lcore, ip_whitelist_count());
    TEST_ASSERT_EQ(0, missing, "No concurrent add should be lost");
    TEST_ASSERT_EQ(lcores * per_lcore, ip_whitelist_count(), "The whitelist should count every add");

    // Each lcore removes the first half of its sources
    for (uint32_t i = 0; i < lcores; i++) {
        jobs[i] = (struct lcore_job){ JOB_WHITELIST_REMOVE, base + i * per_lcore, per_lcore / 2 };
    }
    run_jobs();
    uint32_t wrong = 0;
    for (uint32_t l = 0; l < lcores; l++) {
        for (uint32_t i = 0; i < per_lcore; i++) {
            bool want = i >= per_lcore / 2;
            if (ip_whitelist_lookup(source(base + l * per_lcore, i), NULL) != want) {
                wrong++;
            }
        }
    }
    TEST_ASSERT_EQ(0, wrong, "Exactly the removed sources should be gone");
    TEST_ASSERT_EQ(lcores * (per_lcore - per_lcore / 2), ip_whitelist_count(),
                   "The whitelist should count what is left");

    ip_whitelist_clear();
    TEST_ASSERT_EQ(0, ip_whitelist_count(), "A clear should empty the whitelist");
    ip_lists_cleanup();
}

// Every writer of the lists holds the module's writer lock for its table
// change, so there is one writer at a time whichever thread calls it. Once
// none did, and legitimate_ip_add() wrote the whitelist from every packet
// lcore.
void test_list_writers_hold_lock(void) {
    TEST_ASSERT_EQ(0, lists_init(64), "IP lists should initialize");
    const uint32_t ip = source(0x0A470000, 1);
    write_seam_calls = 0;
    write_seam_unlocked = 0;

    TEST_ASSERT_EQ(0, ip_whitelist_add(ip, WL_MODE_TRACK), "Whitelist add");
    TEST_ASSERT_EQ(0, ip_whitelist_remove(ip), "Whitelist remove");
    ip_whitelist_clear();
    TEST_ASSERT_EQ(0, ip_whitelist_cidr_add(0x0A470000, 24), "CIDR whitelist add");
    TEST_ASSERT_EQ(0, ip_whitelist_cidr_remove(0x0A470000, 24), "CIDR whitelist remove");
    ip_whitelist_cidr_clear();
    TEST_ASSERT_EQ(0, ip_blacklist_add(ip), "Blacklist add");
    TEST_ASSERT_EQ(0, ip_blacklist_remove(ip), "Blacklist remove");
    ip_blacklist_clear();
    TEST_ASSERT_EQ(0, ip_protected_add(ip), "Protected add");
    TEST_ASSERT_EQ(0, ip_protected_remove(ip), "Protected remove");
    ip_protected_clear();
    TEST_ASSERT_EQ(0, ip_protected_subnet_add(0x0A480000, 24), "Protected subnet add");
    TEST_ASSERT_EQ(0, ip_protected_subnet_remove(0x0A480000, 24), "Protected subnet remove");
    ip_protected_subnet_clear();

    TEST_ASSERT_EQ(15, write_seam_calls, "Each of the 15 writes should run under the writer lock");
    TEST_ASSERT_EQ(0, write_seam_unlocked, "No write should run without the writer lock");
    TEST_ASSERT(!ip_lists_writer_lock_held(), "The lock should be free between writes");
    ip_lists_cleanup();
}

// ==================== Legitimate Source Tests ====================

// A source that returned a valid cookie is marked in its own table, never on
// the whitelist, which Stage 5 reads to skip every later stage (and which the
// control socket saves to disk)
void test_legitimate_add_leaves_whitelist(void) {
    TEST_ASSERT_EQ(0, lists_init(64), "IP lists should initialize");
    TEST_ASSERT_EQ(0, legitimate_ip_init(64, 300), "The legitimate-source table should be created");

    for (uint32_t i = 0; i < 3; i++) {
        legitimate_ip_add(source(0x0A410000, i));
    }
    TEST_ASSERT_EQ(0, ip_whitelist_count(), "Marking sources legitimate must not whitelist them");
    TEST_ASSERT(!ip_whitelist_lookup(source(0x0A410000, 0), NULL), "A legitimate source is not whitelisted");
    TEST_ASSERT(legitimate_ip_lookup(source(0x0A410000, 0)), "The source should be legitimate");
    TEST_ASSERT_EQ(3, legitimate_ip_count(), "The table should hold the three sources");
    ip_lists_cleanup();
}

// Size, expiry, renewal, the cleanup, clear and free
void test_legitimate_table_expires(void) {
    const uint64_t hz = rte_get_tsc_hz();
    const uint32_t a = source(0x0A420000, 1), b = source(0x0A420000, 2);

    TEST_ASSERT_EQ(0, legitimate_ip_capacity(), "No table before init");
    legitimate_ip_add(a);
    TEST_ASSERT(!legitimate_ip_lookup(a), "Without the table no source is legitimate");

    TEST_ASSERT_EQ(0, legitimate_ip_init(1000, 300), "The table should be created");
    TEST_ASSERT_EQ(1024, legitimate_ip_capacity(), "The size should round up to a power of two");
    legitimate_ip_add(0);
    TEST_ASSERT(!legitimate_ip_lookup(0), "Source 0 is never legitimate");
    TEST_ASSERT_EQ(0, legitimate_ip_count(), "Source 0 takes no entry");

    // One entry per source, renewed in place
    const uint64_t t0 = rte_get_tsc_cycles();
    legit_clock_held = t0;
    legitimate_ip_add(a);
    legitimate_ip_add(a);
    TEST_ASSERT(legitimate_ip_lookup(a), "An added source should be legitimate");
    TEST_ASSERT(!legitimate_ip_lookup(b), "Another source should not be");
    TEST_ASSERT_EQ(1, legitimate_ip_count(), "Adding a source again should renew its entry, not add one");

    // Its entry lasts the TTL from the last add, and nothing else renews it
    legit_clock_held = t0 + 299 * hz;
    TEST_ASSERT(legitimate_ip_lookup(a), "Within the TTL the source should be legitimate");
    legit_clock_held = t0 + 301 * hz;
    TEST_ASSERT(!legitimate_ip_lookup(a), "Past the TTL the source should not be legitimate");
    TEST_ASSERT_EQ(0, legitimate_ip_count(), "An expired entry should count as absent");
    legit_clock_held = t0 + 200 * hz;
    legitimate_ip_add(a);
    legit_clock_held = t0 + 450 * hz;
    TEST_ASSERT(legitimate_ip_lookup(a), "A renewal should last the TTL from the renewal");

    // A reader whose clock lags the writer's (a cleanup pass that read its
    // clock before the add) still sees the new entry as valid
    legitimate_ip_add(b);                       // valid until t0 + 750 s
    legit_clock_held = t0 + 449 * hz;
    TEST_ASSERT(legitimate_ip_lookup(b), "A clock that lags the add should still see the entry");
    TEST_ASSERT_EQ(0, legitimate_ip_cleanup(), "A cleanup whose clock lags the add should keep the entry");
    legit_clock_held = t0 + 450 * hz;

    // The cleanup removes expired entries only
    legit_clock_held = t0 + 600 * hz;           // a expired, b not
    TEST_ASSERT_EQ(1, legitimate_ip_cleanup(), "The cleanup should remove the expired entry");
    TEST_ASSERT(legitimate_ip_lookup(b), "The cleanup should keep the valid entry");
    TEST_ASSERT_EQ(0, legitimate_ip_cleanup(), "A second pass should find nothing to remove");

    legitimate_ip_clear();
    TEST_ASSERT(!legitimate_ip_lookup(b), "A clear should remove every entry");
    TEST_ASSERT_EQ(0, legitimate_ip_count(), "A clear should leave the table empty");

    // The cleanup examines a bounded number of entries per call and resumes:
    // 20000 expired entries in a 32768-entry table go in two or three calls
    TEST_ASSERT_EQ(0, legitimate_ip_init(32768, 1), "A larger table should be created");
    legit_clock_held = t0;
    for (uint32_t i = 0; i < 20000; i++) {
        legitimate_ip_add(source(0x0A430000, i));
    }
    uint32_t held = legitimate_ip_count();
    legit_clock_held = t0 + 2 * hz;
    uint32_t first = legitimate_ip_cleanup();
    uint32_t second = legitimate_ip_cleanup();
    uint32_t total = first + second;
    for (int pass = 0; pass < 4; pass++) {
        total += legitimate_ip_cleanup();
    }
    printf("  %u entries, cleanup passes %u + %u, %u in all\n", held, first, second, total);
    TEST_ASSERT(first > 0 && first < held, "One pass should examine a bounded part of the table");
    TEST_ASSERT_EQ(held, total, "The passes should remove every expired entry once");

    legitimate_ip_free();
    TEST_ASSERT_EQ(0, legitimate_ip_capacity(), "Free should drop the table");
    TEST_ASSERT(!legitimate_ip_lookup(source(0x0A430000, 1)), "Without the table no source is legitimate");
}

// The table never grows: past its size the entry that expires first gives
// way. With one set (8 entries), the oldest proof goes; with 4096 sources in
// a 1024-entry table, the table holds 1024 and the latest are present.
void test_legitimate_table_bounded(void) {
    const uint64_t hz = rte_get_tsc_hz();
    const uint64_t t0 = rte_get_tsc_cycles();

    TEST_ASSERT_EQ(0, legitimate_ip_init(8, 300), "A one-set table should be created");
    TEST_ASSERT_EQ(8, legitimate_ip_capacity(), "It should hold 8 entries");
    for (uint32_t i = 0; i < 8; i++) {
        legit_clock_held = t0 + (uint64_t)i * hz;
        legitimate_ip_add(source(0x0A440000, i));
    }
    TEST_ASSERT_EQ(8, legitimate_ip_count(), "Eight sources should fill the set");
    legit_clock_held = t0 + 8 * hz;
    legitimate_ip_add(source(0x0A440000, 8));
    TEST_ASSERT_EQ(8, legitimate_ip_count(), "A full table should not grow");
    TEST_ASSERT(!legitimate_ip_lookup(source(0x0A440000, 0)), "The entry that expires first should give way");
    for (uint32_t i = 1; i <= 8; i++) {
        TEST_ASSERT(legitimate_ip_lookup(source(0x0A440000, i)), "The other entries should stay");
    }
    // An expired entry is taken before a valid one: at t0 + 301.5 s source 1
    // (added at t0 + 1 s) has expired, source 2 (t0 + 2 s) has not
    legit_clock_held = t0 + 301 * hz + hz / 2;
    legitimate_ip_add(source(0x0A440000, 9));
    TEST_ASSERT(legitimate_ip_lookup(source(0x0A440000, 9)), "The new source should take an expired entry");
    for (uint32_t i = 2; i <= 8; i++) {
        TEST_ASSERT(legitimate_ip_lookup(source(0x0A440000, i)), "The valid entries should stay");
    }

    TEST_ASSERT_EQ(0, legitimate_ip_init(1024, 300), "A 1024-entry table should be created");
    for (uint32_t i = 0; i < 4096; i++) {
        legit_clock_held = t0 + (uint64_t)i * (hz / 64);
        legitimate_ip_add(source(0x0A450000, i));
    }
    uint32_t count = legitimate_ip_count();
    uint32_t latest = 0;
    for (uint32_t i = 4096 - 64; i < 4096; i++) {
        latest += legitimate_ip_lookup(source(0x0A450000, i));
    }
    printf("  4096 sources in a table of %u: %u held, %u of the latest 64\n",
           legitimate_ip_capacity(), count, latest);
    TEST_ASSERT(count <= legitimate_ip_capacity(), "The table should never hold more than its size");
    TEST_ASSERT(count >= legitimate_ip_capacity() / 2, "The table should be mostly full");
    TEST_ASSERT_EQ(64, latest, "The latest sources should be present");
}

// Another lcore's add changes the word an add chose, between the add's look
// and its compare-and-swap (the seam): the swap fails and the add looks
// again, so neither source is lost. Two adds that chose the same free word
// both get one; a renewal that meets the eviction of its own word keeps it,
// and the word that expires next gives way instead. A plain store would keep
// only the later write of the two.
void test_legitimate_add_race(void) {
    const uint64_t hz = rte_get_tsc_hz();
    const uint64_t t0 = rte_get_tsc_cycles();
    const uint32_t base = 0x0A480000;

    TEST_ASSERT_EQ(0, legitimate_ip_init(8, 300), "A one-set table should be created");
    legit_clock_held = t0;
    add_seam_source = source(base, 2);
    legitimate_ip_add(source(base, 1));
    TEST_ASSERT_EQ(0, add_seam_source, "The other lcore's add should have run");
    TEST_ASSERT(legitimate_ip_lookup(source(base, 2)), "The add that took the word first should keep it");
    TEST_ASSERT(legitimate_ip_lookup(source(base, 1)), "The add that lost the word should take another");
    TEST_ASSERT_EQ(2, legitimate_ip_count(), "Both sources should hold an entry");

    // A full set: source 10 expires first, then 11. Adding 18 evicts 10,
    // whose renewal comes in between
    TEST_ASSERT_EQ(0, legitimate_ip_init(8, 300), "The table should be created again");
    for (uint32_t i = 0; i < 8; i++) {
        legit_clock_held = t0 + (uint64_t)i * hz;
        legitimate_ip_add(source(base, 10 + i));
    }
    legit_clock_held = t0 + 8 * hz;
    add_seam_source = source(base, 10);
    legitimate_ip_add(source(base, 18));
    TEST_ASSERT_EQ(0, add_seam_source, "The renewal should have run");
    TEST_ASSERT(legitimate_ip_lookup(source(base, 10)), "The renewed source should keep its entry");
    TEST_ASSERT(legitimate_ip_lookup(source(base, 18)), "The new source should take the next word to expire");
    TEST_ASSERT(!legitimate_ip_lookup(source(base, 11)), "The next source to expire should give way");
    TEST_ASSERT_EQ(8, legitimate_ip_count(), "The set should stay full");
}

// Every lcore but the last adds disjoint sources at once while the last looks
// them up and runs the cleanup, as the packet lcores and the main lcore do.
// Every add is a compare-and-swap of a whole word: with room in the table
// none is lost, and no lookup or cleanup sees half an entry (TSan checks the
// accesses).
void test_legitimate_table_concurrent(void) {
    const uint32_t lcores = rte_lcore_count(), per_lcore = 20000, base = 0x0A460000;
    const uint32_t writers = lcores > 1 ? lcores - 1 : 1;
    TEST_ASSERT_EQ(0, legitimate_ip_init(1u << 20, 300), "The table should be created");
    if (lcores < 2) {
        printf("  NOTE: one lcore, no concurrent writers\n");
    }

    memset(jobs, 0, sizeof(jobs));
    __atomic_store_n(&reader_rounds, 0, __ATOMIC_RELAXED);
    for (uint32_t i = 0; i < writers; i++) {
        jobs[i] = (struct lcore_job){ JOB_LEGIT_ADD, base + i * per_lcore, per_lcore };
    }
    if (lcores > 1) {
        jobs[lcores - 1] = (struct lcore_job){ JOB_LEGIT_READ, base, writers * per_lcore };
    }
    run_jobs();

    uint32_t missing = 0;
    for (uint32_t i = 0; i < writers * per_lcore; i++) {
        missing += !legitimate_ip_lookup(source(base, i));
    }
    printf("  %u writer lcores: %u of %u concurrent adds missing, %u counted, %lu reader rounds\n",
           writers, missing, writers * per_lcore, legitimate_ip_count(),
           (unsigned long)__atomic_load_n(&reader_rounds, __ATOMIC_RELAXED));
    TEST_ASSERT_EQ(0, missing, "No concurrent add should be lost");
    TEST_ASSERT_EQ(writers * per_lcore, legitimate_ip_count(), "Each source should hold one entry");

    // The same sources again, at once: renewals, no second entry
    run_jobs();
    TEST_ASSERT_EQ(writers * per_lcore, legitimate_ip_count(), "Renewals should add no entry");
}

// ==================== Main ====================

// Lcores 0 to 3 on the first CPUs this process may use, one CPU each
static void build_lcore_map(char *buf, size_t len) {
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

int main(int argc, char **argv) {
    (void)argc;
    char lcore_map[64];
    build_lcore_map(lcore_map, sizeof(lcore_map));
    char *eal_args[] = {
        argv[0], "--lcores", lcore_map, "-n", "1", "--no-huge", "--no-pci", "-m", "256",
        "--no-shconf", "--no-telemetry", NULL
    };
    if (rte_eal_init((int)RTE_DIM(eal_args) - 1, eal_args) < 0) {
        fprintf(stderr, "EAL init failed (missing DPDK permissions / runtime directory), skipping test\n");
        return 77;
    }

    printf("\n========================================\n");
    printf("  IP Lists Unit Tests\n");
    printf("========================================\n\n");

    RUN_TEST(test_list_writers_hold_lock);
    RUN_TEST(test_whitelist_concurrent_writers);
    RUN_TEST(test_legitimate_add_leaves_whitelist);
    RUN_TEST(test_legitimate_table_expires);
    RUN_TEST(test_legitimate_table_bounded);
    RUN_TEST(test_legitimate_add_race);
    RUN_TEST(test_legitimate_table_concurrent);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed, %d total\n", tests_passed, tests_failed, tests_run);
    printf("========================================\n\n");

    rte_eal_cleanup();
    return tests_failed > 0 ? 1 : 0;
}
