/**
 * @file test_spike_detector.c
 * @brief Unit tests for the fast-path spike detector
 *        (layer1/telemetry/spike_detector.c). The shipped engine does not
 *        initialise this module; these tests cover what wiring it needs.
 *
 * Covers:
 * - lookups, recording and unregistration use the slot registration stored
 *   with the key, not the key's hash position;
 * - recording with an lcore id that has no window (a non-EAL thread) is
 *   refused, not written out of bounds (in a child process);
 * - an unregistered IP's windows stay allocated, and its slot unused, while
 *   a registered flow table reader may still count into them;
 * - the aggregation releases unregistered slots once their grace period is
 *   over, and a registration that finds no free slot waits a bounded time
 *   for one;
 * - registration, unregistration and aggregation hold the control lock
 *   (pinned through seams);
 * - concurrent recording, registration churn and aggregation (stress).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/wait.h>

#include <rte_cycles.h>
#include <rte_lcore.h>

#include "../../layer1/telemetry/spike_detector.h"
#include "../../layer1/tables/flow_table.h"
#include "shared_table_test.h"

// ==================== Seam ====================

static uint32_t seam_recording = 0;
static uint32_t seam_calls[SPIKE_SEAM_MAX];
static uint32_t seam_locked[SPIKE_SEAM_MAX];

void spike_detector_seam(enum spike_detector_seam_point point) {
    if (!__atomic_load_n(&seam_recording, __ATOMIC_ACQUIRE) ||
        (unsigned int)point >= SPIKE_SEAM_MAX) {
        return;
    }
    __atomic_fetch_add(&seam_calls[point], 1, __ATOMIC_RELAXED);
    if (spike_detector_ctl_lock_held()) {
        __atomic_fetch_add(&seam_locked[point], 1, __ATOMIC_RELAXED);
    }
}

static void seam_start(void) {
    for (int p = 0; p < SPIKE_SEAM_MAX; p++) {
        seam_calls[p] = 0;
        seam_locked[p] = 0;
    }
    __atomic_store_n(&seam_recording, 1, __ATOMIC_RELEASE);
}

static void seam_stop(void) {
    __atomic_store_n(&seam_recording, 0, __ATOMIC_RELEASE);
}

static inline uint32_t dip(uint32_t i) {
    return 0x0F000001u + i;
}

// ==================== Slots ====================

/*
 * Register A and B, unregister A, register C: C takes A's slot but its key
 * another hash position. Every lookup must reach the IP's own slot.
 */
static void test_spike_lookup_follows_registered_slot(void) {
    CHECK_EQ(0, spike_detector_init(16), "init");
    CHECK_EQ(0, spike_detector_register(dip(1)), "register A");
    CHECK_EQ(0, spike_detector_register(dip(2)), "register B");
    CHECK_EQ(0, spike_detector_unregister(dip(1)), "unregister A");
    CHECK_EQ(0, spike_detector_register(dip(3)), "register C");

    struct spike_detector *b = spike_detector_lookup(dip(2));
    struct spike_detector *c = spike_detector_lookup(dip(3));
    CHECK(b != NULL && c != NULL, "B and C found");
    CHECK_EQ(dip(2), b->dst_ip, "B's lookup reaches B's slot");
    CHECK_EQ(dip(3), c->dst_ip, "C's lookup reaches C's slot");
    CHECK(c->active == 1 && c->lcore_windows != NULL, "C's slot is set up");
    CHECK(spike_detector_lookup(dip(1)) == NULL, "A is gone");

    // Recording counts into the IP's own windows
    unsigned int lcore = rte_lcore_id();
    (void)spike_detector_record(dip(3), lcore);
    (void)spike_detector_record(dip(3), lcore);
    CHECK_EQ(2, c->lcore_windows[lcore].current_count, "C's packets land in C's windows");
    CHECK_EQ(0, b->lcore_windows[lcore].current_count, "and not in B's");

    // Unregistering C releases C's slot and leaves B's alone
    CHECK_EQ(0, spike_detector_unregister(dip(3)), "unregister C");
    CHECK(b->active == 1 && b->lcore_windows != NULL, "B's slot is untouched");
    CHECK_EQ(1, spike_detector_active_count(), "one IP left");
    CHECK(c->active == 0 && c->lcore_windows == NULL, "C's slot is free again");
out:
    (void)spike_detector_unregister(dip(2));
    spike_detector_cleanup();
}

static void test_spike_record_refuses_foreign_lcore(void) {
    CHECK_EQ(0, spike_detector_init(16), "init");
    CHECK_EQ(0, spike_detector_register(dip(4)), "register");

    // In a child process, so that a crash fails only this subtest
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        bool counted = spike_detector_record(dip(4), LCORE_ID_ANY);
        counted |= spike_detector_record(dip(4), RTE_MAX_LCORE);
        _exit(counted ? 1 : 0);
    }
    int status = 0;
    bool reaped = pid > 0 && waitpid(pid, &status, 0) == pid;
    CHECK(reaped, "the child ran");
    CHECK_EQ(0, WIFSIGNALED(status) ? WTERMSIG(status) : 0,
             "recording with an lcore id that has no window does not crash");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "and records nothing");
out:
    (void)spike_detector_unregister(dip(4));
    spike_detector_cleanup();
}

// ==================== Deferred Release ====================

static void test_spike_reader_holds_windows_across_unregister(void) {
    unsigned int lcore = rte_lcore_id();
    bool reader = false;

    CHECK_EQ(0, spike_detector_init(16), "init");
    CHECK_EQ(0, flow_table_reader_register(lcore), "reader registration");
    reader = true;

    CHECK_EQ(0, spike_detector_register(dip(5)), "register A");
    struct spike_detector *sd = spike_detector_lookup(dip(5));
    CHECK(sd != NULL, "A found");
    struct spike_window *windows = sd->lcore_windows;
    CHECK(windows != NULL, "A has windows");

    CHECK_EQ(0, spike_detector_unregister(dip(5)), "unregister A");
    CHECK(spike_detector_lookup(dip(5)) == NULL, "A is no longer found");
    CHECK(sd->lcore_windows == windows, "the windows a reader may still count into are not freed");
    CHECK_EQ(1, spike_detector_slots_waiting(), "A's slot waits for the reader");
    windows[lcore].current_count++;  // the held reader still counts

    CHECK_EQ(0, spike_detector_register(dip(6)), "register B");
    CHECK(spike_detector_lookup(dip(6)) != sd, "B does not get the slot a reader may still use");

    flow_table_reader_quiescent(lcore);
    CHECK_EQ(0, spike_detector_register(dip(7)), "register C");
    CHECK_EQ(0, spike_detector_slots_waiting(), "after the report A's slot is released");
    CHECK(spike_detector_lookup(dip(7)) == sd, "and handed out again");
    CHECK_EQ(0, sd->lcore_windows[lcore].current_count, "with fresh windows");
out:
    (void)spike_detector_unregister(dip(6));
    (void)spike_detector_unregister(dip(7));
    if (reader) {
        flow_table_reader_unregister(lcore);
    }
    spike_detector_cleanup();
}

// The aggregation releases an unregistered slot once its grace period is
// over, without waiting for the next registration call
static void test_spike_aggregate_releases_slots(void) {
    unsigned int lcore = rte_lcore_id();
    bool reader = false;

    CHECK_EQ(0, spike_detector_init(16), "init");
    CHECK_EQ(0, flow_table_reader_register(lcore), "reader registration");
    reader = true;
    CHECK_EQ(0, spike_detector_register(dip(20)), "register");
    CHECK_EQ(0, spike_detector_unregister(dip(20)), "unregister");
    CHECK_EQ(1, spike_detector_slots_waiting(), "its slot waits for this reader");

    (void)spike_detector_aggregate();
    CHECK_EQ(1, spike_detector_slots_waiting(), "an aggregation before the report keeps it");
    flow_table_reader_quiescent(lcore);
    (void)spike_detector_aggregate();
    CHECK_EQ(0, spike_detector_slots_waiting(), "the next aggregation releases it");
out:
    if (reader) {
        flow_table_reader_unregister(lcore);
    }
    spike_detector_cleanup();
}

// A worker lcore stands for a packet lcore that still holds what it looked
// up, and reports a quiescent state a few milliseconds later
static uint32_t wait_reader_state;      // 1 registered, 2 registration failed
static uint32_t wait_reader_go;

static int wait_reader_fn(void *arg __rte_unused) {
    unsigned int lcore = rte_lcore_id();
    int rc = flow_table_reader_register(lcore);
    __atomic_store_n(&wait_reader_state, rc == 0 ? 1 : 2, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&wait_reader_go, __ATOMIC_ACQUIRE)) {
        rte_pause();
    }
    rte_delay_us_block(5000);
    if (rc == 0) {
        flow_table_reader_quiescent(lcore);
        rte_delay_us_block(1000);
        flow_table_reader_unregister(lcore);
    }
    return 0;
}

/*
 * Every slot of a detector of 8 is in use but one, unregistered and held by
 * another lcore that reports 5 ms later: a registration waits for that
 * report and gets the slot.
 */
static void test_spike_full_pool_waits_for_reader(void) {
    unsigned int worker = rte_get_next_lcore(-1, 1, 0);
    bool launched = false;

    if (worker >= RTE_MAX_LCORE) {
        printf("  NOTE: no worker lcore, nothing to wait for\n");
        return;
    }
    CHECK_EQ(0, spike_detector_init(8), "init");
    for (uint32_t i = 0; i < 8; i++) {
        CHECK_EQ(0, spike_detector_register(dip(40 + i)), "fill the detector");
    }

    __atomic_store_n(&wait_reader_state, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&wait_reader_go, 0, __ATOMIC_RELEASE);
    CHECK_EQ(0, rte_eal_remote_launch(wait_reader_fn, NULL, worker), "launch the reader");
    launched = true;
    while (__atomic_load_n(&wait_reader_state, __ATOMIC_ACQUIRE) == 0) {
        rte_pause();
    }
    CHECK_EQ(1, __atomic_load_n(&wait_reader_state, __ATOMIC_ACQUIRE), "reader registration");

    CHECK_EQ(0, spike_detector_unregister(dip(40)), "unregister one");
    __atomic_store_n(&wait_reader_go, 1, __ATOMIC_RELEASE);
    uint64_t t0 = rte_get_tsc_cycles();
    int ret = spike_detector_register(dip(50));
    uint64_t waited_us = (rte_get_tsc_cycles() - t0) * 1000000 / rte_get_tsc_hz();
    printf("  registration returned %d after %lu us\n", ret, (unsigned long)waited_us);
    CHECK_EQ(0, ret, "the registration waits for the reader's report and gets the slot");
    CHECK(waited_us >= 3000, "the slot was not handed out before the report");
out:
    if (launched) {
        __atomic_store_n(&wait_reader_go, 1, __ATOMIC_RELEASE);
        rte_eal_wait_lcore(worker);
    }
    for (uint32_t i = 0; i < 8; i++) {
        (void)spike_detector_unregister(dip(40 + i));
    }
    (void)spike_detector_unregister(dip(50));
    spike_detector_cleanup();
}

// ==================== Guards Pinned Through Seams ====================

static void test_spike_control_path_holds_lock(void) {
    uint64_t rate = 0, baseline = 0;
    double ratio = 0;

    CHECK_EQ(0, spike_detector_init(16), "init");
    seam_start();
    CHECK_EQ(0, spike_detector_register(dip(8)), "register");
    CHECK_EQ(0, spike_detector_register(dip(9)), "register");
    (void)spike_detector_aggregate();
    (void)spike_detector_get_info(dip(8), &rate, &baseline, &ratio);
    CHECK_EQ(0, spike_detector_unregister(dip(9)), "unregister");
    seam_stop();

    CHECK_EQ(2, seam_calls[SPIKE_SEAM_REGISTER], "two registrations");
    CHECK_EQ(2, seam_locked[SPIKE_SEAM_REGISTER], "each holds the control lock");
    CHECK_EQ(2, seam_calls[SPIKE_SEAM_AGGREGATE], "two slots aggregated");
    CHECK_EQ(2, seam_locked[SPIKE_SEAM_AGGREGATE], "the aggregation holds the control lock");
    CHECK_EQ(1, seam_calls[SPIKE_SEAM_UNREGISTER], "one unregistration");
    CHECK_EQ(1, seam_locked[SPIKE_SEAM_UNREGISTER], "it holds the control lock");
    CHECK(!spike_detector_ctl_lock_held(), "the lock is free afterwards");
out:
    seam_stop();
    (void)spike_detector_unregister(dip(8));
    spike_detector_cleanup();
}

// ==================== Concurrency (stress) ====================

#define SPIKE_IPS       12
#define SPIKE_KEEP      6
#define SPIKE_CYCLES    3000

static uint32_t spike_stop = 0;

struct spike_job {
    uint32_t role;              // 0: packet lcore (reader), 1: control-path aggregation
    uint64_t iterations;
    int reader_rc;
};
static struct spike_job spike_jobs[TABLE_TEST_MAX_WORKERS];

static int spike_job_fn(void *arg) {
    struct spike_job *job = arg;
    unsigned int lcore = rte_lcore_id();

    if (job->role == 0) {
        job->reader_rc = flow_table_reader_register(lcore);
    }
    table_test_start_wait();
    while (!__atomic_load_n(&spike_stop, __ATOMIC_ACQUIRE)) {
        if (job->role == 0) {
            for (uint32_t i = 0; i < SPIKE_IPS; i++) {
                (void)spike_detector_record(dip(100 + i), lcore);
            }
            if (job->reader_rc == 0) {
                flow_table_reader_quiescent(lcore);
            }
        } else {
            // The control path's aggregation, every 50 us (back to back it
            // would keep the control lock to itself)
            (void)spike_detector_aggregate();
            rte_delay_us_block(50);
        }
        job->iterations++;
    }
    if (job->role == 0 && job->reader_rc == 0) {
        flow_table_reader_unregister(lcore);
    }
    return 0;
}

static uint32_t spike_failures;
static uint32_t spike_cycle;

// The control path: registrations and unregistrations of a rotating set
static void spike_control_step(void) {
    if (spike_cycle < SPIKE_CYCLES) {
        uint32_t c = spike_cycle++;
        if (spike_detector_register(dip(100 + c % SPIKE_IPS)) != 0) {
            spike_failures++;
        }
        if (c >= SPIKE_KEEP && spike_detector_unregister(dip(100 + (c - SPIKE_KEEP) % SPIKE_IPS)) != 0) {
            spike_failures++;
        }
    } else {
        __atomic_store_n(&spike_stop, 1, __ATOMIC_RELEASE);
        rte_pause();
    }
}

static void test_spike_concurrent_churn(void) {
    // Room for the registered IPs plus the slots waiting for a report
    CHECK_EQ(0, spike_detector_init(64), "init");

    __atomic_store_n(&spike_stop, 0, __ATOMIC_RELEASE);
    spike_failures = 0;
    spike_cycle = 0;
    void *args[TABLE_TEST_MAX_WORKERS];
    for (uint32_t w = 0; w < TABLE_TEST_MAX_WORKERS; w++) {
        memset(&spike_jobs[w], 0, sizeof(spike_jobs[w]));
        spike_jobs[w].role = (w == 1) ? 1 : 0;
        args[w] = &spike_jobs[w];
    }
    unsigned int jobs;
    if (rte_lcore_count() < 2) {
        while (spike_cycle < SPIKE_CYCLES) {
            spike_control_step();
        }
        spike_control_step();
        jobs = table_test_run(spike_job_fn, args, NULL);
    } else {
        jobs = table_test_run(spike_job_fn, args, spike_control_step);
    }

    for (uint32_t w = 0; w < jobs; w++) {
        if (spike_jobs[w].role == 0) {
            CHECK_EQ(0, spike_jobs[w].reader_rc, "reader registration");
        }
    }
    for (uint32_t i = 0; i < SPIKE_IPS; i++) {
        (void)spike_detector_unregister(dip(100 + i));
    }
    CHECK_EQ(0, spike_detector_register(dip(300)), "a registration after the run");
    CHECK_EQ(0, spike_detector_unregister(dip(300)), "and its unregistration");
    // Every unregistration released its own IP's slot: none is left in use
    uint32_t slots_in_use = 0;
    for (uint32_t s = 0; s < 64; s++) {
        if (g_spike_pool[s].active != 0 || g_spike_pool[s].lcore_windows != NULL) {
            slots_in_use++;
        }
    }
    printf("  %u jobs, %u control cycles: %u failed calls, %u registered, %u waiting and "
           "%u slots in use at the end\n", jobs, spike_cycle, spike_failures,
           spike_detector_active_count(), spike_detector_slots_waiting(), slots_in_use);
    CHECK_EQ(0, spike_failures, "every registration and unregistration succeeds");
    CHECK_EQ(0, spike_detector_active_count(), "nothing registered at the end");
    CHECK_EQ(0, spike_detector_slots_waiting(), "nothing waits at the end");
    CHECK_EQ(0, slots_in_use, "every slot is free at the end");
out:
    spike_detector_cleanup();
}

// ==================== Main ====================

int main(int argc __rte_unused, char **argv) {
    int rc = table_test_eal_init(argv[0]);
    if (rc != 0) {
        return rc;
    }

    printf("\n========================================\n");
    printf("  Spike Detector Tests (%u lcores)\n", rte_lcore_count());
    printf("========================================\n\n");

    RUN_TEST(test_spike_lookup_follows_registered_slot);
    RUN_TEST(test_spike_record_refuses_foreign_lcore);
    RUN_TEST(test_spike_reader_holds_windows_across_unregister);
    RUN_TEST(test_spike_aggregate_releases_slots);
    RUN_TEST(test_spike_full_pool_waits_for_reader);
    RUN_TEST(test_spike_control_path_holds_lock);
    RUN_TEST(test_spike_concurrent_churn);

    return table_test_report("Spike detector");
}
