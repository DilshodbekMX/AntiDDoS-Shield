/**
 * @file test_src_ip_stats.c
 * @brief Unit tests for the per-source-IP statistics table
 *        (layer1/interlayer/src_ip_stats.c). The shipped engine does not
 *        initialise this module; these tests cover what wiring it needs.
 *
 * Covers:
 * - the entry array covers every position the hash can hand out;
 * - the module's nanosecond clock follows the TSC;
 * - updates and expiry work from a non-EAL thread (in a child process, so
 *   that a crash fails only that subtest; in this process under
 *   ThreadSanitizer, which cannot start a thread after such a fork);
 * - a deleted source's entry is neither reused nor cleared while a
 *   registered flow table reader may still update it;
 * - writers hold the writer lock and the control path the control lock
 *   (pinned through seams);
 * - concurrent first packets of shared sources on several lcores are all
 *   counted (stress).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>

#include <rte_cycles.h>
#include <rte_lcore.h>

#include "../../layer1/interlayer/src_ip_stats.h"
#include "../../layer1/tables/flow_table.h"
#include "shared_table_test.h"

// ==================== Seam ====================

static uint32_t seam_recording = 0;
static uint32_t seam_calls[SRCIP_SEAM_MAX];
static uint32_t seam_wlocked[SRCIP_SEAM_MAX];
static uint32_t seam_ctl_locked[SRCIP_SEAM_MAX];

void src_ip_stats_seam(enum src_ip_stats_seam_point point) {
    if (!__atomic_load_n(&seam_recording, __ATOMIC_ACQUIRE) ||
        (unsigned int)point >= SRCIP_SEAM_MAX) {
        return;
    }
    __atomic_fetch_add(&seam_calls[point], 1, __ATOMIC_RELAXED);
    if (src_ip_stats_writer_lock_held()) {
        __atomic_fetch_add(&seam_wlocked[point], 1, __ATOMIC_RELAXED);
    }
    if (src_ip_stats_ctl_lock_held()) {
        __atomic_fetch_add(&seam_ctl_locked[point], 1, __ATOMIC_RELAXED);
    }
}

static void seam_start(void) {
    for (int p = 0; p < SRCIP_SEAM_MAX; p++) {
        seam_calls[p] = 0;
        seam_wlocked[p] = 0;
        seam_ctl_locked[p] = 0;
    }
    __atomic_store_n(&seam_recording, 1, __ATOMIC_RELEASE);
}

static void seam_stop(void) {
    __atomic_store_n(&seam_recording, 0, __ATOMIC_RELEASE);
}

// ==================== Helpers ====================

static struct src_pkt_features pkt(uint32_t src_ip, uint16_t size) {
    struct src_pkt_features f;
    memset(&f, 0, sizeof(f));
    f.src_ip = src_ip;
    f.dst_ip = 0xC0A80101u;
    f.src_port = 40000;
    f.dst_port = 80;
    f.pkt_size = size;
    f.protocol = 6;
    f.ttl = 64;
    f.tcp_flags = 0x02;
    f.tcp_wscale = 0xFF;
    return f;
}

static inline uint32_t sip(uint32_t group, uint32_t i) {
    return 0x0E000000u | (group << 16) | i;
}

// ==================== Positions and Threads ====================

static void test_srcip_entries_cover_every_position(void) {
    CHECK_EQ(0, src_ip_stats_init(), "init");
    uint32_t capacity = src_ip_stats_capacity();
    uint32_t positions = src_ip_stats_max_position();
    printf("  %u entries for %u positions (%u configured sources)\n", capacity, positions,
           MAX_SRC_IP_ENTRIES);
    // With per-lcore slot caches (MULTI_WRITER_ADD) the hash hands out up to
    // (RTE_MAX_LCORE - 1) * 63 positions past its configured entries
    CHECK(capacity >= MAX_SRC_IP_ENTRIES, "an entry for every configured source");
    CHECK(capacity >= positions, "an entry for every position the hash can hand out");

    struct src_pkt_features f = pkt(sip(1, 1), 100);
    struct src_ip_entry *e = src_ip_stats_update(&f);
    CHECK(e != NULL, "a new source is tracked");
    CHECK(src_ip_stats_lookup(sip(1, 1)) == e, "and found again");
out:
    src_ip_stats_cleanup();
}

// The module's clock is the TSC in nanoseconds: it must follow the TSC, not
// wrap every few seconds (the expiry of 300 s idle could never fire)
static void test_srcip_clock_follows_tsc(void) {
    CHECK_EQ(0, src_ip_stats_init(), "init");
    struct src_pkt_features f = pkt(sip(1, 2), 100);
    struct src_ip_entry *e = src_ip_stats_update(&f);
    CHECK(e != NULL, "tracked");
    double tsc_sec = (double)rte_get_tsc_cycles() / (double)rte_get_tsc_hz();
    double seen_sec = (double)e->first_seen_ns / 1e9;
    printf("  TSC at %.3f s, entry first seen at %.3f s\n", tsc_sec, seen_sec);
    CHECK(seen_sec <= tsc_sec && tsc_sec - seen_sec < 1.0, "the entry's time is the TSC's");
out:
    src_ip_stats_cleanup();
}

struct thread_result {
    bool updated;
    uint32_t expired;
};

static void *non_eal_ops(void *arg) {
    struct thread_result *r = arg;
    struct src_pkt_features f = pkt(sip(2, 1), 100);
    struct src_ip_entry *e = src_ip_stats_update(&f);
    r->updated = (e != NULL && src_ip_stats_lookup(sip(2, 1)) == e);
    if (e) {
        e->last_seen_ns = 0;    // expired
    }
    r->expired = src_ip_stats_expire_old();
    return NULL;
}

// ThreadSanitizer cannot start a thread in a child forked from a
// multi-threaded process (the child dies, and with die_after_fork=0 its
// thread bookkeeping fails): under it the non-EAL thread runs in this
// process, with the same checks
#if defined(__SANITIZE_THREAD__)
#define SRCIP_TEST_NO_FORK 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define SRCIP_TEST_NO_FORK 1
#endif
#endif

static void test_srcip_non_eal_thread(void) {
    CHECK_EQ(0, src_ip_stats_init(), "init");

#ifdef SRCIP_TEST_NO_FORK
    {
        struct thread_result r = { false, 0 };
        pthread_t t;
        CHECK(pthread_create(&t, NULL, non_eal_ops, &r) == 0, "the non-EAL thread started");
        pthread_join(t, NULL);
        CHECK(r.updated && r.expired == 1, "a non-EAL thread's source is tracked, found and expired");
    }
#else
    // In a child process, so that a crash fails only this subtest
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        struct thread_result r = { false, 0 };
        pthread_t t;
        if (pthread_create(&t, NULL, non_eal_ops, &r) != 0) {
            _exit(3);
        }
        pthread_join(t, NULL);
        _exit(r.updated && r.expired == 1 ? 0 : 1);
    }
    int status = 0;
    bool reaped = pid > 0 && waitpid(pid, &status, 0) == pid;
    CHECK(reaped, "the child ran");
    CHECK_EQ(0, WIFSIGNALED(status) ? WTERMSIG(status) : 0,
             "an update and an expiry on a non-EAL thread do not crash");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "a non-EAL thread's source is tracked, found and expired");
#endif
out:
    src_ip_stats_cleanup();
}

// ==================== Deferred Reuse ====================

static void test_srcip_reader_holds_entry_across_expire(void) {
    unsigned int lcore = rte_lcore_id();
    bool reader = false;

    CHECK_EQ(0, src_ip_stats_init(), "init");
    CHECK_EQ(0, flow_table_reader_register(lcore), "reader registration");
    reader = true;

    struct src_pkt_features fa = pkt(sip(3, 1), 100);
    struct src_ip_entry *ea = src_ip_stats_update(&fa);
    CHECK(ea != NULL, "source A tracked");
    ea->last_seen_ns = 0;   // expired
    CHECK_EQ(1, src_ip_stats_expire_old(), "the expiry deletes A");
    CHECK(src_ip_stats_lookup(sip(3, 1)) == NULL, "A is no longer found");
    CHECK_EQ(1, src_ip_stats_positions_waiting(), "its position waits for this reader");
    CHECK_EQ(sip(3, 1), ea->src_ip, "a deleted entry is not cleared while a reader may update it");

    struct src_pkt_features fb = pkt(sip(3, 2), 100);
    struct src_ip_entry *eb = src_ip_stats_update(&fb);
    CHECK(eb != NULL, "source B tracked");
    CHECK(eb != ea, "B does not get the entry a reader may still update");

    flow_table_reader_quiescent(lcore);
    CHECK_EQ(0, src_ip_stats_expire_old(), "nothing else expired");
    CHECK_EQ(0, src_ip_stats_positions_waiting(), "after the report A's position is released");
    CHECK_EQ(0, ea->src_ip, "and its entry cleared");
out:
    if (reader) {
        flow_table_reader_unregister(lcore);
    }
    src_ip_stats_cleanup();
}

// ==================== Guards Pinned Through Seams ====================

static void test_srcip_writers_and_control_hold_locks(void) {
    struct src_ip_entry out_one;
    struct src_ip_entry out_many[4];

    CHECK_EQ(0, src_ip_stats_init(), "init");
    seam_start();
    struct src_pkt_features f = pkt(sip(4, 1), 100);
    struct src_ip_entry *e = src_ip_stats_update(&f);
    CHECK(e != NULL, "tracked");
    CHECK(src_ip_stats_snapshot(sip(4, 1), &out_one), "snapshot");
    (void)src_ip_stats_snapshot_active(out_many, 4);
    (void)src_ip_stats_get_attackers(out_many, 4);
    src_ip_stats_set_action(sip(4, 1), 1, 50);
    src_ip_stats_mark_attacker(sip(4, 1));
    src_ip_stats_mark_trusted(sip(4, 1));
    src_ip_stats_clear_flags(sip(4, 1), SRC_IP_FLAG_TRUSTED);
    src_ip_stats_reset_window();
    e->last_seen_ns = 0;
    CHECK_EQ(1, src_ip_stats_expire_old(), "expired");
    seam_stop();

    CHECK_EQ(1, seam_calls[SRCIP_SEAM_ADD], "one add");
    CHECK_EQ(1, seam_wlocked[SRCIP_SEAM_ADD], "the add holds the writer lock");
    CHECK_EQ(1, seam_calls[SRCIP_SEAM_EXPIRE_DELETE], "one expiry delete");
    CHECK_EQ(1, seam_wlocked[SRCIP_SEAM_EXPIRE_DELETE], "the delete holds the writer lock");
    CHECK_EQ(1, seam_ctl_locked[SRCIP_SEAM_EXPIRE_DELETE], "within the control lock");
    CHECK_EQ(8, seam_calls[SRCIP_SEAM_CONTROL], "eight control-path reads of the entry");
    CHECK_EQ(8, seam_ctl_locked[SRCIP_SEAM_CONTROL], "each holds the control lock");
    CHECK(!src_ip_stats_writer_lock_held() && !src_ip_stats_ctl_lock_held(), "locks free afterwards");
out:
    seam_stop();
    src_ip_stats_cleanup();
}

// ==================== Concurrency (stress) ====================

#define MW_OWN      2000
#define MW_SHARED   500
#define MW_REPEAT   4

struct mw_job {
    uint32_t worker;
    uint32_t untracked;
};
static struct mw_job mw_jobs[TABLE_TEST_MAX_WORKERS];

static int mw_job_fn(void *arg) {
    struct mw_job *job = arg;
    table_test_start_wait();
    // The shared sources first, in the same order on every worker, so that
    // the workers race on each first packet
    for (uint32_t r = 0; r < MW_REPEAT; r++) {
        for (uint32_t i = 0; i < MW_SHARED; i++) {
            struct src_pkt_features f = pkt(sip(0x20, i), 100);
            if (!src_ip_stats_update(&f)) {
                job->untracked++;
            }
        }
    }
    for (uint32_t i = 0; i < MW_OWN; i++) {
        struct src_pkt_features f = pkt(sip(0x30 + job->worker, i), 100);
        if (!src_ip_stats_update(&f)) {
            job->untracked++;
        }
    }
    return 0;
}

static void test_srcip_concurrent_first_packets_counted(void) {
    CHECK_EQ(0, src_ip_stats_init(), "init");

    void *args[TABLE_TEST_MAX_WORKERS];
    for (uint32_t w = 0; w < TABLE_TEST_MAX_WORKERS; w++) {
        memset(&mw_jobs[w], 0, sizeof(mw_jobs[w]));
        mw_jobs[w].worker = w;
        args[w] = &mw_jobs[w];
    }
    unsigned int jobs = table_test_run(mw_job_fn, args, NULL);

    uint32_t missing = 0, miscounted = 0, untracked = 0;
    for (uint32_t w = 0; w < jobs; w++) {
        untracked += mw_jobs[w].untracked;
        for (uint32_t i = 0; i < MW_OWN; i++) {
            struct src_ip_entry *e = src_ip_stats_lookup(sip(0x30 + w, i));
            if (!e) {
                missing++;
            } else if (e->packets_total != 1) {
                miscounted++;
            }
        }
    }
    for (uint32_t i = 0; i < MW_SHARED; i++) {
        struct src_ip_entry *e = src_ip_stats_lookup(sip(0x20, i));
        if (!e) {
            missing++;
        } else if (e->packets_total != (uint64_t)jobs * MW_REPEAT) {
            miscounted++;
        }
    }
    struct src_ip_stats_table st;
    src_ip_stats_get_stats(&st);
    printf("  %u workers, %u sources: %u not found, %u miscounted, %u updates untracked, %u entries\n",
           jobs, jobs * MW_OWN + MW_SHARED, missing, miscounted, untracked, st.entry_count);
    CHECK_EQ(0, untracked, "every update is tracked");
    CHECK_EQ(0, missing, "every source is found");
    CHECK_EQ(0, miscounted, "every packet is counted once, on its source's entry");
    CHECK_EQ(jobs * MW_OWN + MW_SHARED, st.entry_count, "each source has one entry");
out:
    src_ip_stats_cleanup();
}

// ==================== Main ====================

int main(int argc __rte_unused, char **argv) {
    int rc = table_test_eal_init(argv[0]);
    if (rc != 0) {
        return rc;
    }

    printf("\n========================================\n");
    printf("  Source IP Stats Table Tests (%u lcores)\n", rte_lcore_count());
    printf("========================================\n\n");

    RUN_TEST(test_srcip_entries_cover_every_position);
    RUN_TEST(test_srcip_clock_follows_tsc);
    RUN_TEST(test_srcip_non_eal_thread);
    RUN_TEST(test_srcip_reader_holds_entry_across_expire);
    RUN_TEST(test_srcip_writers_and_control_hold_locks);
    RUN_TEST(test_srcip_concurrent_first_packets_counted);

    return table_test_report("Source IP stats table");
}
