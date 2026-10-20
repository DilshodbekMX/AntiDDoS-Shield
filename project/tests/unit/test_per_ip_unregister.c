/**
 * @file test_per_ip_unregister.c
 * @brief Unit tests for the release of unregistered protected IPs in the
 *        per-IP feature table (layer1/telemetry/per_ip_features.c).
 *
 * Covers:
 * - register and unregister cycles beyond the hash's size keep working
 *   (each unregistered key's hash position is released);
 * - while a registered flow table reader may still use an unregistered
 *   slot, its count-min counters stay allocated and the slot is not handed
 *   out again; after the reader's quiescent report it is;
 * - a registration that finds no free slot waits for the grace period (and
 *   gets the slot once the reader reports), and only for a bounded time;
 * - the window roll releases unregistered slots once their grace period is
 *   over;
 * - the control-path walks and unregistration hold the control lock
 *   (pinned through seams);
 * - concurrent registration churn, control-path walks and packet updates on
 *   several lcores (stress).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>

#include "../../layer1/telemetry/per_ip_features.h"
#include "../../layer1/tables/flow_table.h"
#include "shared_table_test.h"

// ==================== Seam ====================

static uint32_t seam_recording = 0;
static uint32_t seam_calls[PERIP_SEAM_MAX];
static uint32_t seam_locked[PERIP_SEAM_MAX];

void per_ip_features_seam(enum per_ip_features_seam_point point) {
    if (!__atomic_load_n(&seam_recording, __ATOMIC_ACQUIRE) ||
        (unsigned int)point >= PERIP_SEAM_MAX) {
        return;
    }
    __atomic_fetch_add(&seam_calls[point], 1, __ATOMIC_RELAXED);
    if (per_ip_features_ctl_lock_held()) {
        __atomic_fetch_add(&seam_locked[point], 1, __ATOMIC_RELAXED);
    }
}

static void seam_start(void) {
    for (int p = 0; p < PERIP_SEAM_MAX; p++) {
        seam_calls[p] = 0;
        seam_locked[p] = 0;
    }
    __atomic_store_n(&seam_recording, 1, __ATOMIC_RELEASE);
}

static void seam_stop(void) {
    __atomic_store_n(&seam_recording, 0, __ATOMIC_RELEASE);
}

// ==================== Helpers ====================

static inline uint32_t ip(uint32_t i) {
    return 0x0A000001u + i;  // any value: the table keys on the 32 bits
}

static void unregister_quietly(uint32_t dst_ip) {
    (void)per_ip_features_unregister(dst_ip);
}

// ==================== Release of Unregistered Slots ====================

/*
 * max_ips 8 gives a hash of 16 positions. Registering and unregistering one
 * IP after another must work forever: before the fix each unregistered key
 * kept its position, and the 17th registration failed with the table empty.
 */
static void test_perip_register_unregister_cycles(void) {
    CHECK_EQ(0, per_ip_features_init(8), "init");

    for (uint32_t c = 0; c < 64; c++) {
        if (per_ip_features_register(ip(c)) != 0) {
            printf("  registration of a new IP failed at cycle %u, table empty\n", c);
        }
        CHECK_EQ(0, per_ip_features_lookup(ip(c)) != NULL ? 0 : -1, "each cycle's IP is registered");
        CHECK_EQ(0, per_ip_features_unregister(ip(c)), "and unregistered");
    }
    // Fill the pool, empty it, again and again
    for (uint32_t round = 0; round < 8; round++) {
        for (uint32_t i = 0; i < 8; i++) {
            CHECK_EQ(0, per_ip_features_register(ip(100 + round * 8 + i)), "fill the pool");
        }
        CHECK_EQ(8, per_ip_features_count(), "pool full");
        for (uint32_t i = 0; i < 8; i++) {
            CHECK_EQ(0, per_ip_features_unregister(ip(100 + round * 8 + i)), "empty the pool");
        }
        CHECK_EQ(0, per_ip_features_count(), "pool empty");
    }
    CHECK_EQ(0, per_ip_features_slots_waiting(), "no reader registered: nothing waits");
out:
    per_ip_features_cleanup();
}

static void test_perip_reader_holds_slot_across_unregister(void) {
    unsigned int lcore = rte_lcore_id();
    bool reader = false;

    CHECK_EQ(0, per_ip_features_init(8), "init");
    CHECK_EQ(0, flow_table_reader_register(lcore), "reader registration");
    reader = true;

    CHECK_EQ(0, per_ip_features_register(ip(1)), "register A");
    struct per_ip_features *pif = per_ip_features_lookup(ip(1));
    CHECK(pif != NULL, "A found");
    uint32_t *counters = pif->cms.counters;
    CHECK(counters != NULL, "A has count-min counters");

    // This lcore still holds pif (no quiescent report since its lookup)
    CHECK_EQ(0, per_ip_features_unregister(ip(1)), "unregister A");
    CHECK(per_ip_features_lookup(ip(1)) == NULL, "A is no longer found");
    CHECK(pif->cms.counters == counters, "the counters a reader may still use are not freed");
    CHECK_EQ(1, per_ip_features_slots_waiting(), "A's slot waits for the reader");

    // The held slot is still usable by this reader
    per_ip_hll_cms_update(pif, 0x0B000001u, 1234, 80, 0xABCD0001u);
    CHECK(per_ip_get_flow_count(pif, 0xABCD0001u) >= 1, "its counters still count");

    CHECK_EQ(0, per_ip_features_register(ip(2)), "register B");
    struct per_ip_features *pif_b = per_ip_features_lookup(ip(2));
    CHECK(pif_b != NULL, "B found");
    CHECK(pif_b != pif, "B does not get the slot a reader may still use");

    flow_table_reader_quiescent(lcore);
    CHECK_EQ(0, per_ip_features_register(ip(3)), "register C");
    CHECK_EQ(0, per_ip_features_slots_waiting(), "after the report A's slot is released");
    CHECK(per_ip_features_lookup(ip(3)) == pif, "and handed out again (last freed, first reused)");
    CHECK(pif->cms.counters != NULL, "C got fresh counters");
    CHECK_EQ(0, per_ip_get_flow_count(pif, 0xABCD0001u), "C starts with no counts of A");
out:
    unregister_quietly(ip(2));
    unregister_quietly(ip(3));
    if (reader) {
        flow_table_reader_unregister(lcore);
    }
    per_ip_features_cleanup();
}

/*
 * The pool is full but one slot is unregistered and still held by this
 * reader: a registration must neither reuse it nor wait forever. After the
 * reader reports, the registration succeeds.
 */
static void test_perip_full_pool_waits_bounded(void) {
    unsigned int lcore = rte_lcore_id();
    bool reader = false;

    CHECK_EQ(0, per_ip_features_init(8), "init");
    CHECK_EQ(0, flow_table_reader_register(lcore), "reader registration");
    reader = true;

    for (uint32_t i = 0; i < 8; i++) {
        CHECK_EQ(0, per_ip_features_register(ip(10 + i)), "fill the pool");
    }
    struct per_ip_features *held = per_ip_features_lookup(ip(10));
    CHECK(held != NULL, "first IP found");
    CHECK_EQ(0, per_ip_features_unregister(ip(10)), "unregister one");

    uint64_t t0 = rte_get_tsc_cycles();
    int ret = per_ip_features_register(ip(20));
    uint64_t waited_us = (rte_get_tsc_cycles() - t0) * 1000000 / rte_get_tsc_hz();
    printf("  registration with only a held slot left returned %d after %lu us\n",
           ret, (unsigned long)waited_us);
    CHECK_EQ(-1, ret, "the only slot left is still held: no registration");
    CHECK(waited_us < 1000000, "and the wait for it is bounded");
    CHECK(per_ip_features_lookup(ip(20)) == NULL, "the new IP is not registered");

    flow_table_reader_quiescent(lcore);
    CHECK_EQ(0, per_ip_features_register(ip(20)), "after the report the slot is free");
    CHECK(per_ip_features_lookup(ip(20)) == held, "it is the released slot");
out:
    for (uint32_t i = 0; i < 8; i++) {
        unregister_quietly(ip(10 + i));
    }
    unregister_quietly(ip(20));
    if (reader) {
        flow_table_reader_unregister(lcore);
    }
    per_ip_features_cleanup();
}

// The window roll (1 Hz, stats thread) releases an unregistered slot once
// its grace period is over, without waiting for the next registration call
static void test_perip_window_roll_releases_slots(void) {
    unsigned int lcore = rte_lcore_id();
    bool reader = false;

    CHECK_EQ(0, per_ip_features_init(8), "init");
    CHECK_EQ(0, flow_table_reader_register(lcore), "reader registration");
    reader = true;
    CHECK_EQ(0, per_ip_features_register(ip(60)), "register");
    CHECK_EQ(0, per_ip_features_unregister(ip(60)), "unregister");
    CHECK_EQ(1, per_ip_features_slots_waiting(), "its slot waits for this reader");

    per_ip_features_reset_all_windows();
    CHECK_EQ(1, per_ip_features_slots_waiting(), "a window roll before the report keeps it");
    flow_table_reader_quiescent(lcore);
    per_ip_features_reset_all_windows();
    CHECK_EQ(0, per_ip_features_slots_waiting(), "the next window roll releases it");
out:
    if (reader) {
        flow_table_reader_unregister(lcore);
    }
    per_ip_features_cleanup();
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
 * The pool is full but one slot is unregistered and held by another lcore,
 * which reports 5 ms later: a registration waits for that report and gets
 * the slot.
 */
static void test_perip_full_pool_waits_for_reader(void) {
    unsigned int worker = rte_get_next_lcore(-1, 1, 0);
    bool launched = false;

    if (worker >= RTE_MAX_LCORE) {
        printf("  NOTE: no worker lcore, nothing to wait for\n");
        return;
    }
    CHECK_EQ(0, per_ip_features_init(8), "init");
    for (uint32_t i = 0; i < 8; i++) {
        CHECK_EQ(0, per_ip_features_register(ip(40 + i)), "fill the pool");
    }

    __atomic_store_n(&wait_reader_state, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&wait_reader_go, 0, __ATOMIC_RELEASE);
    CHECK_EQ(0, rte_eal_remote_launch(wait_reader_fn, NULL, worker), "launch the reader");
    launched = true;
    while (__atomic_load_n(&wait_reader_state, __ATOMIC_ACQUIRE) == 0) {
        rte_pause();
    }
    CHECK_EQ(1, __atomic_load_n(&wait_reader_state, __ATOMIC_ACQUIRE), "reader registration");

    CHECK_EQ(0, per_ip_features_unregister(ip(40)), "unregister one");
    __atomic_store_n(&wait_reader_go, 1, __ATOMIC_RELEASE);
    uint64_t t0 = rte_get_tsc_cycles();
    int ret = per_ip_features_register(ip(50));
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
        unregister_quietly(ip(40 + i));
    }
    unregister_quietly(ip(50));
    per_ip_features_cleanup();
}

static void test_perip_control_path_holds_lock(void) {
    struct per_ip_feature_snapshot snaps[8];
    struct per_ip_feature_snapshot one;

    CHECK_EQ(0, per_ip_features_init(8), "init");
    CHECK_EQ(0, per_ip_features_register(ip(30)), "register");
    CHECK_EQ(0, per_ip_features_register(ip(31)), "register");

    seam_start();
    CHECK_EQ(2, per_ip_features_snapshot_all(snaps, 8), "snapshot all");
    CHECK_EQ(0, per_ip_features_snapshot(ip(30), &one), "snapshot one");
    per_ip_features_reset_all_windows();
    CHECK_EQ(0, per_ip_features_unregister(ip(31)), "unregister");
    seam_stop();

    CHECK_EQ(3, seam_calls[PERIP_SEAM_SNAPSHOT], "three slots read by snapshots");
    CHECK_EQ(3, seam_locked[PERIP_SEAM_SNAPSHOT], "every snapshot holds the control lock");
    CHECK_EQ(2, seam_calls[PERIP_SEAM_RESET], "two slots reset");
    CHECK_EQ(2, seam_locked[PERIP_SEAM_RESET], "the window reset holds the control lock");
    CHECK_EQ(1, seam_calls[PERIP_SEAM_UNREGISTER], "one unregistration");
    CHECK_EQ(1, seam_locked[PERIP_SEAM_UNREGISTER], "it holds the control lock");
    CHECK(!per_ip_features_ctl_lock_held(), "the lock is free afterwards");
out:
    seam_stop();
    unregister_quietly(ip(30));
    unregister_quietly(ip(31));
    per_ip_features_cleanup();
}

// ==================== Concurrency (stress) ====================

#define CHURN_IPS       12
#define CHURN_KEEP      6       // registered at a time
#define CHURN_CYCLES    3000

static uint32_t churn_stop = 0;

struct churn_job {
    uint32_t role;              // 0: packet lcore (reader), 1: stats thread
    uint64_t iterations;
    int reader_rc;
};
static struct churn_job churn_jobs[TABLE_TEST_MAX_WORKERS];

static int churn_job_fn(void *arg) {
    struct churn_job *job = arg;
    unsigned int lcore = rte_lcore_id();
    struct per_ip_feature_snapshot snaps[CHURN_IPS];

    if (job->role == 0) {
        job->reader_rc = flow_table_reader_register(lcore);
    }
    table_test_start_wait();
    while (!__atomic_load_n(&churn_stop, __ATOMIC_ACQUIRE)) {
        if (job->role == 0) {
            // A packet lcore: Stage 3c's lookup and update, quiescent
            // between bursts
            for (uint32_t i = 0; i < CHURN_IPS; i++) {
                struct per_ip_features *pif = per_ip_features_lookup(ip(200 + i));
                if (pif) {
                    per_ip_features_update(pif, 6, 0x02, 60, 0x0C000000u | i, 1000 + i, 80,
                                           0xF0000000u | (uint32_t)job->iterations, false);
                }
            }
            if (job->reader_rc == 0) {
                flow_table_reader_quiescent(lcore);
            }
        } else {
            // The stats thread: the 1 Hz export and window roll, here every
            // 50 us (back to back it would keep the control lock to itself)
            (void)per_ip_features_snapshot_all(snaps, CHURN_IPS);
            per_ip_features_reset_all_windows();
            rte_delay_us_block(50);
        }
        job->iterations++;
    }
    if (job->role == 0 && job->reader_rc == 0) {
        flow_table_reader_unregister(lcore);
    }
    return 0;
}

static uint32_t churn_failures;
static uint32_t churn_cycle;

// The control thread: registrations and unregistrations of a rotating set
static void churn_control_step(void) {
    if (churn_cycle < CHURN_CYCLES) {
        uint32_t c = churn_cycle++;
        if (per_ip_features_register(ip(200 + c % CHURN_IPS)) != 0) {
            churn_failures++;
        }
        if (c >= CHURN_KEEP && per_ip_features_unregister(ip(200 + (c - CHURN_KEEP) % CHURN_IPS)) != 0) {
            churn_failures++;
        }
    } else {
        __atomic_store_n(&churn_stop, 1, __ATOMIC_RELEASE);
        rte_pause();
    }
}

static void test_perip_concurrent_churn(void) {
    // One INFO line per registration would slow the run down
    int log_level = rte_log_get_level(RTE_LOGTYPE_USER7);
    rte_log_set_level(RTE_LOGTYPE_USER7, RTE_LOG_WARNING);
    // Room for the registered IPs plus the slots waiting for a report (a
    // registration that finds none free waits only a bounded time)
    CHECK_EQ(0, per_ip_features_init(32), "init");

    __atomic_store_n(&churn_stop, 0, __ATOMIC_RELEASE);
    churn_failures = 0;
    churn_cycle = 0;
    void *args[TABLE_TEST_MAX_WORKERS];
    for (uint32_t w = 0; w < TABLE_TEST_MAX_WORKERS; w++) {
        memset(&churn_jobs[w], 0, sizeof(churn_jobs[w]));
        churn_jobs[w].role = (w == 1) ? 1 : 0;
        args[w] = &churn_jobs[w];
    }
    unsigned int jobs;
    if (rte_lcore_count() < 2) {
        // No worker lcore: the control steps first, then one round of each role
        while (churn_cycle < CHURN_CYCLES) {
            churn_control_step();
        }
        churn_control_step();
        jobs = table_test_run(churn_job_fn, args, NULL);
    } else {
        jobs = table_test_run(churn_job_fn, args, churn_control_step);
    }

    for (uint32_t w = 0; w < jobs; w++) {
        if (churn_jobs[w].role == 0) {
            CHECK_EQ(0, churn_jobs[w].reader_rc, "reader registration");
        }
    }
    // Unregister what is left; the next registration call releases every
    // slot (no reader registered any more)
    for (uint32_t i = 0; i < CHURN_IPS; i++) {
        unregister_quietly(ip(200 + i));
    }
    CHECK_EQ(0, per_ip_features_register(ip(300)), "a registration after the run");
    CHECK_EQ(0, per_ip_features_unregister(ip(300)), "and its unregistration");
    printf("  %u jobs, %u control cycles: %u failed calls, %lu and %lu iterations, "
           "%u registered and %u waiting at the end\n",
           jobs, churn_cycle, churn_failures, (unsigned long)churn_jobs[0].iterations,
           (unsigned long)churn_jobs[1].iterations, per_ip_features_count(),
           per_ip_features_slots_waiting());
    CHECK_EQ(0, churn_failures, "every registration and unregistration succeeds");
    CHECK_EQ(0, per_ip_features_count(), "nothing registered at the end");
    CHECK_EQ(0, per_ip_features_slots_waiting(), "nothing waits at the end");
out:
    per_ip_features_cleanup();
    rte_log_set_level(RTE_LOGTYPE_USER7, (uint32_t)log_level);
}

// ==================== Main ====================

int main(int argc __rte_unused, char **argv) {
    int rc = table_test_eal_init(argv[0]);
    if (rc != 0) {
        return rc;
    }

    printf("\n========================================\n");
    printf("  Per-IP Feature Unregistration Tests (%u lcores)\n", rte_lcore_count());
    printf("========================================\n\n");

    RUN_TEST(test_perip_register_unregister_cycles);
    RUN_TEST(test_perip_reader_holds_slot_across_unregister);
    RUN_TEST(test_perip_full_pool_waits_bounded);
    RUN_TEST(test_perip_full_pool_waits_for_reader);
    RUN_TEST(test_perip_window_roll_releases_slots);
    RUN_TEST(test_perip_control_path_holds_lock);
    RUN_TEST(test_perip_concurrent_churn);

    return table_test_report("Per-IP feature unregistration");
}
