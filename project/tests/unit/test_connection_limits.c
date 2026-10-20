/**
 * @file test_connection_limits.c
 * @brief Unit tests for the per-IP connection limits table (Stage 10,
 *        layer1/tables/connection_limits.c), which every packet lcore
 *        writes when the SYN proxy is disabled.
 *
 * Covers:
 * - concurrent first connections of many IPs on several lcores: every IP is
 *   tracked on its own tracker, and racing first connections of one IP are
 *   each counted (stress);
 * - an IP another lcore adds between the lookup and the add is counted on
 *   that lcore's tracker, not set up again, and a connection that finds an
 *   IP before its tracker is set up is counted too (seams);
 * - adds and deletes hold the writer lock (seams);
 * - a deleted IP's tracker is reused only after every registered flow table
 *   reader has reported a quiescent state;
 * - the cleanup leaves alone a tracker refreshed after its pass read its
 *   clock, and a window another lcore starts after a check read its clock
 *   is not started again by that check.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_cycles.h>
#include <rte_lcore.h>

#include "../../layer1/tables/connection_limits.h"
#include "../../layer1/tables/flow_table.h"
#include "shared_table_test.h"

// ==================== Seam ====================

static uint32_t seam_recording = 0;
static void (*seam_action[CONNLIM_SEAM_MAX])(void);
static uint32_t seam_calls[CONNLIM_SEAM_MAX];
static uint32_t seam_locked[CONNLIM_SEAM_MAX];

void connection_limits_seam(enum connection_limits_seam_point point) {
    if (!__atomic_load_n(&seam_recording, __ATOMIC_ACQUIRE) ||
        (unsigned int)point >= CONNLIM_SEAM_MAX) {
        return;
    }
    __atomic_fetch_add(&seam_calls[point], 1, __ATOMIC_RELAXED);
    if (connection_limits_writer_lock_held()) {
        __atomic_fetch_add(&seam_locked[point], 1, __ATOMIC_RELAXED);
    }
    void (*action)(void) = __atomic_exchange_n(&seam_action[point], NULL, __ATOMIC_ACQ_REL);
    if (action) {
        action();
    }
}

static void seam_start(void) {
    for (int p = 0; p < CONNLIM_SEAM_MAX; p++) {
        seam_action[p] = NULL;
        seam_calls[p] = 0;
        seam_locked[p] = 0;
    }
    __atomic_store_n(&seam_recording, 1, __ATOMIC_RELEASE);
}

static void seam_stop(void) {
    __atomic_store_n(&seam_recording, 0, __ATOMIC_RELEASE);
    for (int p = 0; p < CONNLIM_SEAM_MAX; p++) {
        __atomic_store_n(&seam_action[p], NULL, __ATOMIC_RELAXED);
    }
}

// ==================== Helpers ====================

static int init_table_limits(uint32_t max_ips, uint32_t cleanup_sec, uint32_t window_sec,
                             uint32_t max_per_ip) {
    struct connection_limits_config cfg = {
        .max_ips = max_ips,
        .max_connections_per_ip = max_per_ip,
        .time_window_sec = window_sec,
        .cleanup_interval_sec = cleanup_sec,
    };
    return connection_limits_init(&cfg);
}

static int init_table(uint32_t max_ips, uint32_t cleanup_sec) {
    return init_table_limits(max_ips, cleanup_sec, 60, 1000000);
}

static inline uint32_t addr(uint32_t group, uint32_t i) {
    return 0x0D000000u | (group << 16) | i;
}

static uint32_t total_of(uint32_t ip) {
    uint32_t active = 0, total = 0;
    if (!connection_limits_get_count(ip, &active, &total)) {
        return 0;
    }
    return total;
}

// With a cleanup interval of 0 an idle tracker is expired once the TSC has
// moved past its last update
static uint32_t cleanup_after_tick(void) {
    rte_delay_us_block(5);
    return connection_limits_cleanup_expired();
}

// ==================== Guards Pinned Through Seams ====================

// The MISSED seam's action: another lcore's first connection of the same IP
// wins the race to add it
static uint32_t race_ip;
static bool race_nested_allowed;

static void seam_other_lcore_adds_first(void) {
    race_nested_allowed = connection_limits_check(race_ip, 80);
}

static void test_connlim_racing_add_counts_connection(void) {
    CHECK_EQ(0, init_table(1024, 60), "init");

    race_ip = addr(1, 1);
    race_nested_allowed = false;
    seam_start();
    seam_action[CONNLIM_SEAM_MISSED] = seam_other_lcore_adds_first;
    CHECK(connection_limits_check(race_ip, 80), "the connection that lost the race is allowed");
    seam_stop();
    CHECK(race_nested_allowed, "the winner's connection is allowed");

    CHECK_EQ(2, total_of(race_ip), "both first connections are counted on one tracker");
    uint32_t tracked = 0, conns = 0;
    uint64_t exceeded = 0;
    connection_limits_get_stats(&tracked, &conns, &exceeded);
    CHECK_EQ(1, tracked, "the IP is tracked once");
    connection_limits_cleanup();

    // One connection per window: the connection that lost the race is the
    // window's second, over the limit
    CHECK_EQ(0, init_table_limits(1024, 60, 60, 1), "init with a limit of 1");
    race_ip = addr(1, 2);
    race_nested_allowed = false;
    seam_start();
    seam_action[CONNLIM_SEAM_MISSED] = seam_other_lcore_adds_first;
    bool allowed = connection_limits_check(race_ip, 80);
    seam_stop();
    CHECK(race_nested_allowed, "the winner's connection is allowed");
    CHECK(!allowed, "the connection that lost the race is checked against the limit");
    CHECK_EQ(1, total_of(race_ip), "only the allowed connection is counted");
out:
    seam_stop();
    connection_limits_cleanup();
}

// The PUBLISH seam's action: another lcore's connection finds the IP the
// moment it is added, before its tracker is set up
static bool publish_nested_allowed;

static void seam_other_lcore_finds_new_ip(void) {
    publish_nested_allowed = connection_limits_check(addr(7, 1), 80);
}

static void test_connlim_lookup_during_setup_counted(void) {
    CHECK_EQ(0, init_table(1024, 60), "init");

    publish_nested_allowed = false;
    seam_start();
    seam_action[CONNLIM_SEAM_PUBLISH] = seam_other_lcore_finds_new_ip;
    CHECK(connection_limits_check(addr(7, 1), 80), "the first connection is allowed");
    seam_stop();

    CHECK(publish_nested_allowed, "the other lcore's connection is allowed");
    CHECK_EQ(2, total_of(addr(7, 1)), "both connections are counted");
out:
    seam_stop();
    connection_limits_cleanup();
}

static void test_connlim_writers_hold_lock(void) {
    CHECK_EQ(0, init_table(1024, 0), "init");

    seam_start();
    CHECK(connection_limits_check(addr(2, 1), 80), "first connection");
    CHECK(connection_limits_check(addr(2, 1), 80), "second connection");
    connection_limits_update(addr(2, 1), CONN_STATE_CLOSED);
    connection_limits_update(addr(2, 1), CONN_STATE_CLOSED);
    CHECK_EQ(1, cleanup_after_tick(), "the idle IP is deleted");
    seam_stop();

    CHECK_EQ(1, seam_calls[CONNLIM_SEAM_ADD], "one add");
    CHECK_EQ(1, seam_locked[CONNLIM_SEAM_ADD], "the add holds the writer lock");
    CHECK_EQ(0, seam_locked[CONNLIM_SEAM_MISSED], "a missed lookup takes no lock");
    CHECK_EQ(1, seam_calls[CONNLIM_SEAM_HIT], "one lookup hit");
    CHECK_EQ(0, seam_locked[CONNLIM_SEAM_HIT], "a lookup hit takes no lock");
    CHECK_EQ(1, seam_calls[CONNLIM_SEAM_CLEANUP_DELETE], "one delete");
    CHECK_EQ(1, seam_locked[CONNLIM_SEAM_CLEANUP_DELETE], "the delete holds the writer lock");
    CHECK(!connection_limits_writer_lock_held(), "the lock is free afterwards");
out:
    seam_stop();
    connection_limits_cleanup();
}

// ==================== Deferred Reuse ====================

/*
 * A table of 8 is full; one IP closes its connection and the cleanup deletes
 * it while this lcore, a registered flow table reader, has not reported a
 * quiescent state. The only position that frees up must not be handed out
 * until the reader reports: a new IP meanwhile is allowed untracked.
 */
static void test_connlim_deleted_tracker_waits_for_readers(void) {
    unsigned int lcore = rte_lcore_id();
    bool reader = false;
    int32_t pos_a = -1;

    CHECK_EQ(0, init_table(8, 0), "init");
    CHECK_EQ(0, flow_table_reader_register(lcore), "reader registration");
    reader = true;

    uint32_t tracked = 0;
    for (uint32_t i = 0; i < 8; i++) {
        CHECK(connection_limits_check(addr(3, i), 80), "first connection allowed");
        if (connection_limits_position(addr(3, i)) >= 0) {
            tracked++;
        }
    }
    CHECK_EQ(8, tracked, "the table is full");
    pos_a = connection_limits_position(addr(3, 0));

    connection_limits_update(addr(3, 0), CONN_STATE_CLOSED);
    CHECK_EQ(1, cleanup_after_tick(), "the cleanup deletes the closed IP");
    CHECK_EQ(1, connection_limits_positions_waiting(), "its position waits for this reader");

    CHECK(connection_limits_check(addr(4, 1), 80), "a new IP is allowed");
    CHECK_EQ(-1, connection_limits_position(addr(4, 1)),
             "it is not tracked on the tracker a reader may still use");

    flow_table_reader_quiescent(lcore);
    CHECK(connection_limits_check(addr(4, 1), 80), "after the report");
    CHECK_EQ(pos_a, connection_limits_position(addr(4, 1)), "the new IP gets the released position");
    CHECK_EQ(1, total_of(addr(4, 1)), "on a tracker cleared for it");
    CHECK_EQ(0, connection_limits_positions_waiting(), "nothing waits");
out:
    if (reader) {
        flow_table_reader_unregister(lcore);
    }
    connection_limits_cleanup();
}

// The CLEANUP_SCAN seam's action: the IP's connection closes on another
// lcore after the pass read its clock
static void seam_close_during_pass(void) {
    connection_limits_update(addr(5, 1), CONN_STATE_CLOSED);
}

static void test_connlim_cleanup_spares_tracker_refreshed_during_pass(void) {
    // Expiry after 1 s idle: nothing is expired, unless the clock
    // comparison wraps
    CHECK_EQ(0, init_table(1024, 1), "init");
    CHECK(connection_limits_check(addr(5, 1), 80), "first connection");
    connection_limits_update(addr(5, 1), CONN_STATE_CLOSED);

    seam_start();
    seam_action[CONNLIM_SEAM_CLEANUP_SCAN] = seam_close_during_pass;
    uint32_t cleaned = connection_limits_cleanup_expired();
    seam_stop();

    CHECK_EQ(0, cleaned, "a tracker updated after the pass read its clock is not idle");
    CHECK(connection_limits_position(addr(5, 1)) >= 0, "it stays tracked");
out:
    seam_stop();
    connection_limits_cleanup();
}

// The HIT seam's action: another lcore's connection of the same IP, whose
// clock is later, starts a new window between this check's clock read and
// its window test
static bool window_nested_result;

static void seam_other_lcore_starts_window(void) {
    window_nested_result = connection_limits_check(addr(6, 1), 80);
}

static void test_connlim_window_reset_by_other_lcore_keeps_count(void) {
    // Two connections per 1 s window
    CHECK_EQ(0, init_table_limits(1024, 60, 1, 2), "init");
    CHECK(connection_limits_check(addr(6, 1), 80), "first connection");
    rte_delay_us_sleep(1100 * 1000);  // its window is over

    window_nested_result = false;
    seam_start();
    seam_action[CONNLIM_SEAM_HIT] = seam_other_lcore_starts_window;
    bool allowed = connection_limits_check(addr(6, 1), 80);
    seam_stop();

    CHECK(window_nested_result, "the other lcore's connection starts a new window");
    CHECK(allowed, "this connection is the window's second");
    CHECK(!connection_limits_check(addr(6, 1), 80),
          "a third within the window is over the limit: the window was not started again");
out:
    seam_stop();
    connection_limits_cleanup();
}

// ==================== Concurrency (stress) ====================

#define MW_OWN      5000
#define MW_SHARED   1000

struct mw_job {
    uint32_t worker;
    uint32_t denied;
};
static struct mw_job mw_jobs[TABLE_TEST_MAX_WORKERS];

static int mw_job_fn(void *arg) {
    struct mw_job *job = arg;
    table_test_start_wait();
    // The shared IPs first, in the same order on every worker, so that the
    // workers race on each first connection
    for (uint32_t i = 0; i < MW_SHARED; i++) {
        if (!connection_limits_check(addr(0x20, i), 80)) {
            job->denied++;
        }
    }
    for (uint32_t i = 0; i < MW_OWN; i++) {
        if (!connection_limits_check(addr(0x30 + job->worker, i), 80)) {
            job->denied++;
        }
    }
    return 0;
}

static void test_connlim_concurrent_first_connections_tracked(void) {
    CHECK_EQ(0, init_table(100000, 60), "init");

    void *args[TABLE_TEST_MAX_WORKERS];
    for (uint32_t w = 0; w < TABLE_TEST_MAX_WORKERS; w++) {
        memset(&mw_jobs[w], 0, sizeof(mw_jobs[w]));
        mw_jobs[w].worker = w;
        args[w] = &mw_jobs[w];
    }
    unsigned int jobs = table_test_run(mw_job_fn, args, NULL);

    uint32_t missing = 0, wrong_own = 0, wrong_shared = 0, denied = 0;
    for (uint32_t w = 0; w < jobs; w++) {
        denied += mw_jobs[w].denied;
        for (uint32_t i = 0; i < MW_OWN; i++) {
            uint32_t ip = addr(0x30 + w, i);
            if (connection_limits_position(ip) < 0) {
                missing++;
            } else if (total_of(ip) != 1) {
                wrong_own++;
            }
        }
    }
    for (uint32_t i = 0; i < MW_SHARED; i++) {
        uint32_t ip = addr(0x20, i);
        if (connection_limits_position(ip) < 0) {
            missing++;
        } else if (total_of(ip) != jobs) {
            wrong_shared++;
        }
    }
    uint32_t tracked = 0, conns = 0;
    uint64_t exceeded = 0;
    connection_limits_get_stats(&tracked, &conns, &exceeded);
    uint32_t expected = jobs * MW_OWN + MW_SHARED;
    printf("  %u workers, %u IPs: %u not tracked, %u own and %u shared IPs miscounted, "
           "%u tracked, %u denied\n", jobs, expected, missing, wrong_own, wrong_shared, tracked, denied);
    CHECK_EQ(0, missing, "every IP is tracked");
    CHECK_EQ(0, wrong_own, "every IP's one connection is counted on its own tracker");
    CHECK_EQ(0, wrong_shared, "racing first connections of an IP are all counted");
    CHECK_EQ(expected, tracked, "the table holds each IP once");
    CHECK_EQ(0, denied, "no connection was denied");
out:
    connection_limits_cleanup();
}

// ==================== Main ====================

int main(int argc __rte_unused, char **argv) {
    int rc = table_test_eal_init(argv[0]);
    if (rc != 0) {
        return rc;
    }

    printf("\n========================================\n");
    printf("  Connection Limits Table Tests (%u lcores)\n", rte_lcore_count());
    printf("========================================\n\n");

    RUN_TEST(test_connlim_racing_add_counts_connection);
    RUN_TEST(test_connlim_lookup_during_setup_counted);
    RUN_TEST(test_connlim_writers_hold_lock);
    RUN_TEST(test_connlim_deleted_tracker_waits_for_readers);
    RUN_TEST(test_connlim_cleanup_spares_tracker_refreshed_during_pass);
    RUN_TEST(test_connlim_window_reset_by_other_lcore_keeps_count);
    RUN_TEST(test_connlim_concurrent_first_connections_tracked);

    return table_test_report("Connection limits table");
}
