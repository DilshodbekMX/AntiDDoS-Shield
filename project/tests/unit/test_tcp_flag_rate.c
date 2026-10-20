/**
 * @file test_tcp_flag_rate.c
 * @brief Unit tests for the TCP flag rate limiting table (Stage 9b,
 *        layer1/tables/tcp_flag_rate_limit.c), which every packet lcore
 *        writes.
 *
 * Covers:
 * - deleted sources' positions return to the table: under source churn,
 *   new sources are tracked and accepted however many have come and gone;
 * - a deleted position is reused only after every registered flow table
 *   reader has reported a quiescent state;
 * - a new source that finds the table full of live sources is accepted
 *   untracked (fail open), and tracked sources stay rate limited;
 * - writers hold the table's writer lock, a bucket is used only once it is
 *   set up, and an add that loses the race to another lcore keeps that
 *   lcore's bucket (pinned through seams);
 * - the cleanup leaves alone a source refreshed after its pass read its
 *   clock, and a refill stamped by another lcore after a check read its
 *   clock does not refill the bucket again;
 * - concurrent adds on several lcores lose no source, and concurrent churn
 *   with the cleanup leaks no position (stress subtests).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_cycles.h>
#include <rte_lcore.h>

#include "../../layer1/tables/tcp_flag_rate_limit.h"
#include "../../layer1/tables/flow_table.h"
#include "shared_table_test.h"

#define SYN 0x02
#define ACK 0x10

// ==================== Seam ====================

// tcp_flag_rate_seam(): while seam_recording is set, counts the calls at each
// point and how many found the writer lock held, and runs, once, the action
// a subtest set for that point (standing in for another lcore).
static uint32_t seam_recording = 0;
static void (*seam_action[TCPF_SEAM_MAX])(void);
static uint32_t seam_calls[TCPF_SEAM_MAX];
static uint32_t seam_locked[TCPF_SEAM_MAX];

void tcp_flag_rate_seam(enum tcp_flag_rate_seam_point point) {
    if (!__atomic_load_n(&seam_recording, __ATOMIC_ACQUIRE) ||
        (unsigned int)point >= TCPF_SEAM_MAX) {
        return;
    }
    __atomic_fetch_add(&seam_calls[point], 1, __ATOMIC_RELAXED);
    if (tcp_flag_rate_writer_lock_held()) {
        __atomic_fetch_add(&seam_locked[point], 1, __ATOMIC_RELAXED);
    }
    void (*action)(void) = __atomic_exchange_n(&seam_action[point], NULL, __ATOMIC_ACQ_REL);
    if (action) {
        action();
    }
}

static void seam_start(void) {
    for (int p = 0; p < TCPF_SEAM_MAX; p++) {
        seam_action[p] = NULL;
        seam_calls[p] = 0;
        seam_locked[p] = 0;
    }
    __atomic_store_n(&seam_recording, 1, __ATOMIC_RELEASE);
}

static void seam_stop(void) {
    __atomic_store_n(&seam_recording, 0, __ATOMIC_RELEASE);
    for (int p = 0; p < TCPF_SEAM_MAX; p++) {
        __atomic_store_n(&seam_action[p], NULL, __ATOMIC_RELAXED);
    }
}

// ==================== Helpers ====================

// Every class limited to pps packets/s with a bucket of 2 * pps
static int init_table(uint32_t max_entries, uint32_t cleanup_sec, uint32_t pps) {
    struct tcp_flag_rate_config c;
    memset(&c, 0, sizeof(c));
    c.enabled = true;
    c.max_entries = max_entries;
    c.cleanup_interval_sec = cleanup_sec;
    c.report_violations = false;
    for (int i = 0; i < TCPF_MAX; i++) {
        c.pps_limits[i] = pps;
        c.bucket_capacity[i] = 2 * pps;
    }
    return tcp_flag_rate_init(&c);
}

static struct tcp_flag_rate_stats get_stats(void) {
    struct tcp_flag_rate_stats s;
    tcp_flag_rate_get_stats(&s);
    return s;
}

// With a cleanup interval of 0 a source is expired once the TSC has moved
// past its last packet
static uint32_t cleanup_after_tick(void) {
    rte_delay_us_block(5);
    return tcp_flag_rate_cleanup_expired();
}

static inline uint32_t src(uint32_t group, uint32_t i) {
    return 0x0A000000u | (group << 16) | i;
}

// ==================== Churn and Reuse ====================

/*
 * A table of 1024 sees 256 new sources per round, and each round the cleanup
 * expires all of them. The table is empty after every cleanup, so every
 * round's sources must be tracked: before the fix each deleted source kept
 * its position, and from the fifth round on every new source was dropped.
 */
static void test_tcpf_churn_admits_new_sources(void) {
    CHECK_EQ(0, init_table(1024, 0, 1000), "init");

    for (uint32_t r = 0; r < 8; r++) {
        uint32_t accepted = 0, tracked = 0;
        for (uint32_t i = 0; i < 256; i++) {
            if (tcp_flag_rate_check(src(r, i), SYN, 60) == TCPF_RATE_ACCEPT) {
                accepted++;
            }
            if (tcp_flag_rate_position(src(r, i)) >= 0) {
                tracked++;
            }
        }
        if (accepted != 256 || tracked != 256) {
            printf("  round %u: %u of 256 new sources accepted, %u tracked\n", r, accepted, tracked);
        }
        CHECK_EQ(256, accepted, "every new source of an emptied table is accepted");
        CHECK_EQ(256, tracked, "every new source of an emptied table is tracked");
        CHECK_EQ(256, cleanup_after_tick(), "the cleanup expires the round's sources");
        struct tcp_flag_rate_stats s = get_stats();
        CHECK_EQ(0, s.current_entries, "no reader registered: their positions are free at once");
        CHECK_EQ(0, s.positions_waiting, "nothing waits for a grace period");
    }
    CHECK_EQ(0, get_stats().table_full, "the table was never full");
out:
    tcp_flag_rate_cleanup();
}

/*
 * With this lcore registered as a flow table reader that has not reported a
 * quiescent state, the positions of deleted sources stay out of use; each
 * report lets the next cleanup return what was deleted before it.
 */
static void test_tcpf_deleted_positions_wait_for_readers(void) {
    unsigned int lcore = rte_lcore_id();
    bool reader = false;
    int32_t pos_a[10];

    CHECK_EQ(0, init_table(64, 0, 1000), "init");
    CHECK_EQ(0, flow_table_reader_register(lcore), "reader registration");
    reader = true;

    for (uint32_t i = 0; i < 10; i++) {
        CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(1, i), SYN, 60), "source A accepted");
        pos_a[i] = tcp_flag_rate_position(src(1, i));
        CHECK(pos_a[i] >= 0, "source A tracked");
    }
    CHECK_EQ(10, cleanup_after_tick(), "the cleanup deletes the A sources");
    struct tcp_flag_rate_stats s = get_stats();
    CHECK_EQ(10, s.positions_waiting, "their positions wait for this reader");
    CHECK_EQ(10, s.current_entries, "and stay out of the free positions");

    for (uint32_t i = 0; i < 10; i++) {
        CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(2, i), SYN, 60), "source B accepted");
        int32_t pos_b = tcp_flag_rate_position(src(2, i));
        CHECK(pos_b >= 0, "source B tracked");
        for (uint32_t k = 0; k < 10; k++) {
            CHECK(pos_b != pos_a[k], "a position a reader may hold is not handed out");
        }
    }

    flow_table_reader_quiescent(lcore);
    CHECK_EQ(10, cleanup_after_tick(), "the cleanup deletes the B sources");
    s = get_stats();
    CHECK_EQ(10, s.positions_waiting, "A's positions are back, B's wait (deleted after the report)");
    CHECK_EQ(10, s.current_entries, "only B's positions are out of use");

    flow_table_reader_quiescent(lcore);
    CHECK_EQ(0, cleanup_after_tick(), "nothing left to expire");
    s = get_stats();
    CHECK_EQ(0, s.positions_waiting, "B's positions are back after the next report");
    CHECK_EQ(0, s.current_entries, "the table is empty");
out:
    if (reader) {
        flow_table_reader_unregister(lcore);
    }
    tcp_flag_rate_cleanup();
}

// The HIT seam's action: while the outer check holds source A's bucket, the
// cleanup deletes A and another lcore adds source B
static uint32_t hit_cleaned;
static int32_t hit_b_pos;

static void seam_delete_held_and_add_other(void) {
    hit_cleaned = cleanup_after_tick();
    (void)tcp_flag_rate_check(src(4, 2), SYN, 60);
    hit_b_pos = tcp_flag_rate_position(src(4, 2));
}

static void test_tcpf_held_bucket_not_reused(void) {
    unsigned int lcore = rte_lcore_id();
    bool reader = false;

    CHECK_EQ(0, init_table(64, 0, 1000), "init");
    CHECK_EQ(0, flow_table_reader_register(lcore), "reader registration");
    reader = true;

    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(4, 1), SYN, 60), "source A accepted");
    int32_t pos_a = tcp_flag_rate_position(src(4, 1));
    CHECK(pos_a >= 0, "source A tracked");

    hit_cleaned = 0;
    hit_b_pos = -1;
    seam_start();
    seam_action[TCPF_SEAM_HIT] = seam_delete_held_and_add_other;
    enum tcp_flag_rate_result r = tcp_flag_rate_check(src(4, 1), SYN, 60);
    seam_stop();

    CHECK_EQ(1, hit_cleaned, "the cleanup deleted A while its bucket was held");
    CHECK_EQ(TCPF_RATE_ACCEPT, r, "the held check of A still accepts");
    CHECK(hit_b_pos >= 0, "B is tracked");
    CHECK(hit_b_pos != pos_a, "B does not get the bucket the check of A still holds");
    CHECK_EQ(-1, tcp_flag_rate_position(src(4, 1)), "A is no longer tracked");

    flow_table_reader_quiescent(lcore);
    (void)cleanup_after_tick();
    flow_table_reader_quiescent(lcore);
    (void)cleanup_after_tick();
    CHECK_EQ(0, get_stats().current_entries, "every position is back after the reports");
out:
    seam_stop();
    if (reader) {
        flow_table_reader_unregister(lcore);
    }
    tcp_flag_rate_cleanup();
}

// ==================== Full Table ====================

/*
 * A table of live sources (nothing expires within the test) is filled until
 * the hash refuses a new source. That source is accepted untracked and
 * counted, and the tracked sources stay rate limited.
 */
static void test_tcpf_full_table_accepts_untracked(void) {
    // SYN limit 1/s, bucket of 2
    CHECK_EQ(0, init_table(64, 60, 1), "init");

    uint32_t tracked = 0;
    uint32_t full_at = UINT32_MAX;
    enum tcp_flag_rate_result full_result = TCPF_RATE_ERROR;
    for (uint32_t i = 0; i < 256; i++) {
        enum tcp_flag_rate_result r = tcp_flag_rate_check(src(5, i), SYN, 60);
        if (tcp_flag_rate_position(src(5, i)) >= 0) {
            tracked++;
            CHECK_EQ(TCPF_RATE_ACCEPT, r, "a tracked new source is accepted");
        } else {
            full_at = i;
            full_result = r;
            break;
        }
    }
    printf("  %u sources tracked before the table refused one\n", tracked);
    CHECK(full_at != UINT32_MAX, "the table filled up");
    CHECK_EQ(TCPF_RATE_ACCEPT, full_result, "a new source that finds the table full is accepted");
    CHECK_EQ(1, get_stats().table_full, "and counted as table_full");
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(5, full_at), SYN, 60),
             "its next packet too (still untracked)");
    CHECK_EQ(-1, tcp_flag_rate_position(src(5, full_at)), "it is not tracked");
    CHECK_EQ(2, get_stats().table_full, "counted again");

    // Source 0 spent one of its two tokens when it was added
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(5, 0), SYN, 60), "second SYN of a tracked source");
    CHECK_EQ(TCPF_RATE_DROP_SYN, tcp_flag_rate_check(src(5, 0), SYN, 60),
             "third SYN within the second is over its limit");
out:
    tcp_flag_rate_cleanup();
}

/*
 * Every position of a table of 8 waits for this reader's report. A new
 * source meanwhile finds the table full; once the reader has reported, the
 * next new source's add takes the positions back itself, without waiting
 * for a cleanup pass.
 */
static void test_tcpf_full_table_takes_back_released_positions(void) {
    unsigned int lcore = rte_lcore_id();
    bool reader = false;

    CHECK_EQ(0, init_table(8, 0, 1000), "init");
    CHECK_EQ(0, flow_table_reader_register(lcore), "reader registration");
    reader = true;

    for (uint32_t i = 0; i < 8; i++) {
        CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(11, i), SYN, 60), "fill the table");
        CHECK(tcp_flag_rate_position(src(11, i)) >= 0, "tracked");
    }
    CHECK_EQ(8, cleanup_after_tick(), "the cleanup deletes all of them");
    CHECK_EQ(8, get_stats().positions_waiting, "their positions wait for this reader");

    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(11, 100), SYN, 60), "a new source is accepted");
    CHECK_EQ(-1, tcp_flag_rate_position(src(11, 100)), "untracked: nothing is free yet");
    CHECK_EQ(1, get_stats().table_full, "counted as table_full");

    flow_table_reader_quiescent(lcore);
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(11, 101), SYN, 60), "the next new source");
    CHECK(tcp_flag_rate_position(src(11, 101)) >= 0, "is tracked: its add took the positions back");
    CHECK_EQ(1, get_stats().table_full, "no further table_full");
out:
    if (reader) {
        flow_table_reader_unregister(lcore);
    }
    tcp_flag_rate_cleanup();
}

// ==================== Guards Pinned Through Seams ====================

static void test_tcpf_writers_hold_lock(void) {
    CHECK_EQ(0, init_table(64, 0, 1000), "init");

    seam_start();
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(6, 1), SYN, 60), "new source");
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(6, 1), ACK, 60), "known source");
    CHECK_EQ(1, cleanup_after_tick(), "cleanup deletes it");
    seam_stop();

    CHECK_EQ(1, seam_calls[TCPF_SEAM_ADD], "one add");
    CHECK_EQ(1, seam_locked[TCPF_SEAM_ADD], "the add holds the writer lock");
    CHECK_EQ(1, seam_calls[TCPF_SEAM_PUBLISH], "one bucket published");
    CHECK_EQ(1, seam_locked[TCPF_SEAM_PUBLISH], "its setup holds the writer lock");
    CHECK_EQ(1, seam_calls[TCPF_SEAM_CLEANUP_DELETE], "one delete");
    CHECK_EQ(1, seam_locked[TCPF_SEAM_CLEANUP_DELETE], "the delete holds the writer lock");
    CHECK_EQ(1, seam_calls[TCPF_SEAM_HIT], "one lookup hit");
    CHECK_EQ(0, seam_locked[TCPF_SEAM_HIT], "a lookup hit takes no lock");
    CHECK_EQ(1, seam_calls[TCPF_SEAM_CLEANUP_SCAN], "one cleanup scan");
    CHECK_EQ(0, seam_locked[TCPF_SEAM_CLEANUP_SCAN], "the scan takes no lock");
    CHECK(!tcp_flag_rate_writer_lock_held(), "the lock is free afterwards");
out:
    seam_stop();
    tcp_flag_rate_cleanup();
}

// The PUBLISH seam's action: another lcore sees the key of a source whose
// bucket is not set up yet
static enum tcp_flag_rate_result publish_nested_result;

static void seam_check_unpublished(void) {
    publish_nested_result = tcp_flag_rate_check(src(7, 1), SYN, 60);
}

static void test_tcpf_unpublished_bucket_left_alone(void) {
    // SYN limit 1/s, bucket of 2: the first SYN leaves one token
    CHECK_EQ(0, init_table(64, 60, 1), "init");

    publish_nested_result = TCPF_RATE_ERROR;
    seam_start();
    seam_action[TCPF_SEAM_PUBLISH] = seam_check_unpublished;
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(7, 1), SYN, 60), "the adding check accepts");
    seam_stop();

    CHECK_EQ(TCPF_RATE_ACCEPT, publish_nested_result, "a check that meets the unpublished bucket accepts");
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(7, 1), SYN, 60),
             "one token left: the unpublished check spent none");
    CHECK_EQ(TCPF_RATE_DROP_SYN, tcp_flag_rate_check(src(7, 1), SYN, 60), "then the limit applies");
out:
    seam_stop();
    tcp_flag_rate_cleanup();
}

// The PUBLISH seam's action for a reused position: another lcore sees the
// new source's key while its bucket, last used by a deleted source, is set
// up again
static void seam_check_reused_unpublished(void) {
    publish_nested_result = tcp_flag_rate_check(src(7, 100), SYN, 60);
}

/*
 * A position comes back after its source is deleted: the next source there
 * is not published until it is set up, so a lookup that meets it first
 * leaves it alone (the deleted source must not leave it marked live).
 */
static void test_tcpf_reused_position_unpublished(void) {
    // A table of 8, SYN limit 1/s, bucket of 2
    CHECK_EQ(0, init_table(8, 0, 1), "init");

    // A takes the first position; once deleted, its position is released
    // to the back of the free positions
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(7, 50), SYN, 60), "source A");
    int32_t pos_a = tcp_flag_rate_position(src(7, 50));
    CHECK(pos_a >= 0, "A tracked");
    CHECK_EQ(1, cleanup_after_tick(), "A deleted");
    CHECK_EQ(0, get_stats().current_entries, "and its position released");

    // Seven sources take the other positions, the eighth gets A's
    for (uint32_t i = 0; i < 7; i++) {
        CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(7, 60 + i), SYN, 60), "filler source");
    }
    publish_nested_result = TCPF_RATE_ERROR;
    seam_start();
    seam_action[TCPF_SEAM_PUBLISH] = seam_check_reused_unpublished;
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(7, 100), SYN, 60), "the adding check accepts");
    seam_stop();
    CHECK_EQ(pos_a, tcp_flag_rate_position(src(7, 100)), "the new source got A's position");
    CHECK_EQ(TCPF_RATE_ACCEPT, publish_nested_result, "a check that meets it unpublished accepts");
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(7, 100), SYN, 60),
             "one token left: the unpublished check spent none");
    CHECK_EQ(TCPF_RATE_DROP_SYN, tcp_flag_rate_check(src(7, 100), SYN, 60), "then the limit applies");
out:
    seam_stop();
    tcp_flag_rate_cleanup();
}

// The MISSED seam's action: another lcore adds the same new source first
static enum tcp_flag_rate_result missed_nested_result;

static void seam_other_lcore_adds_source(void) {
    missed_nested_result = tcp_flag_rate_check(src(10, 1), SYN, 60);
}

static void test_tcpf_racing_add_keeps_bucket(void) {
    // SYN limit 1/s, bucket of 2
    CHECK_EQ(0, init_table(64, 60, 1), "init");

    missed_nested_result = TCPF_RATE_ERROR;
    seam_start();
    seam_action[TCPF_SEAM_MISSED] = seam_other_lcore_adds_source;
    enum tcp_flag_rate_result r = tcp_flag_rate_check(src(10, 1), SYN, 60);
    seam_stop();

    CHECK_EQ(TCPF_RATE_ACCEPT, missed_nested_result, "the other lcore's first SYN");
    CHECK_EQ(TCPF_RATE_ACCEPT, r, "this lcore's racing first SYN");
    CHECK_EQ(TCPF_RATE_DROP_SYN, tcp_flag_rate_check(src(10, 1), SYN, 60),
             "the bucket of 2 is spent: the add that lost the race did not refill it");
out:
    seam_stop();
    tcp_flag_rate_cleanup();
}

// The CLEANUP_SCAN seam's action: a packet of the source arrives on another
// lcore after the pass has read its clock
static void seam_refresh_source(void) {
    (void)tcp_flag_rate_check(src(8, 1), ACK, 60);
}

static void test_tcpf_cleanup_spares_source_refreshed_during_pass(void) {
    // Timeout 2 s: nothing is expired, unless the clock comparison wraps
    CHECK_EQ(0, init_table(64, 1, 1000), "init");
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(8, 1), SYN, 60), "source accepted");

    seam_start();
    seam_action[TCPF_SEAM_CLEANUP_SCAN] = seam_refresh_source;
    uint32_t cleaned = tcp_flag_rate_cleanup_expired();
    seam_stop();

    CHECK_EQ(0, cleaned, "a source seen after the pass read its clock is not expired");
    CHECK(tcp_flag_rate_position(src(8, 1)) >= 0, "it stays tracked");
out:
    seam_stop();
    tcp_flag_rate_cleanup();
}

// The HIT seam's action: another lcore's packet of the same source, whose
// clock is later, refills the bucket between this check's clock read and
// its refill
static enum tcp_flag_rate_result refill_nested_result;

static void seam_other_lcore_refills(void) {
    refill_nested_result = tcp_flag_rate_check(src(9, 1), SYN, 60);
}

static void test_tcpf_refill_by_other_lcore_keeps_limit(void) {
    // SYN limit 1/s, bucket of 2
    CHECK_EQ(0, init_table(64, 60, 1), "init");
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(9, 1), SYN, 60), "first SYN");
    CHECK_EQ(TCPF_RATE_ACCEPT, tcp_flag_rate_check(src(9, 1), SYN, 60), "second SYN");
    // 2 ms on: the next refill adds no token (1/s) but moves the refill time
    rte_delay_us_block(2000);

    refill_nested_result = TCPF_RATE_ERROR;
    seam_start();
    seam_action[TCPF_SEAM_HIT] = seam_other_lcore_refills;
    enum tcp_flag_rate_result r = tcp_flag_rate_check(src(9, 1), SYN, 60);
    seam_stop();

    CHECK_EQ(TCPF_RATE_DROP_SYN, refill_nested_result, "the other lcore's third SYN is over the limit");
    CHECK_EQ(TCPF_RATE_DROP_SYN, r,
             "so is this one: a refill stamped after this check's clock adds nothing");
out:
    seam_stop();
    tcp_flag_rate_cleanup();
}

// ==================== Concurrency (stress) ====================

#define MW_OWN      4000
#define MW_SHARED   1000

struct mw_job {
    uint32_t worker;
    uint32_t not_accepted;
};
static struct mw_job mw_jobs[TABLE_TEST_MAX_WORKERS];

static int mw_job_fn(void *arg) {
    struct mw_job *job = arg;
    table_test_start_wait();
    // The shared sources first, in the same order on every worker, so that
    // the workers race to add each of them
    for (uint32_t i = 0; i < MW_SHARED; i++) {
        if (tcp_flag_rate_check(src(0x20, i), SYN, 60) != TCPF_RATE_ACCEPT) {
            job->not_accepted++;
        }
    }
    for (uint32_t i = 0; i < MW_OWN; i++) {
        if (tcp_flag_rate_check(src(0x30 + job->worker, i), SYN, 60) != TCPF_RATE_ACCEPT) {
            job->not_accepted++;
        }
    }
    return 0;
}

static int compare_i32(const void *a, const void *b) {
    int32_t x = *(const int32_t *)a;
    int32_t y = *(const int32_t *)b;
    return (x > y) - (x < y);
}

static void test_tcpf_concurrent_adds_lose_nothing(void) {
    int32_t *positions = NULL;
    // Under half full: every add should succeed
    CHECK_EQ(0, init_table(40000, 60, 100000), "init");

    void *args[TABLE_TEST_MAX_WORKERS];
    for (uint32_t w = 0; w < TABLE_TEST_MAX_WORKERS; w++) {
        memset(&mw_jobs[w], 0, sizeof(mw_jobs[w]));
        mw_jobs[w].worker = w;
        args[w] = &mw_jobs[w];
    }
    unsigned int jobs = table_test_run(mw_job_fn, args, NULL);

    uint32_t expected = jobs * MW_OWN + MW_SHARED;
    positions = malloc(expected * sizeof(*positions));
    CHECK(positions != NULL, "malloc");
    uint32_t n = 0, missing = 0, not_accepted = 0;
    for (uint32_t w = 0; w < jobs; w++) {
        not_accepted += mw_jobs[w].not_accepted;
        for (uint32_t i = 0; i < MW_OWN; i++) {
            int32_t p = tcp_flag_rate_position(src(0x30 + w, i));
            if (p < 0) {
                missing++;
            } else {
                positions[n++] = p;
            }
        }
    }
    for (uint32_t i = 0; i < MW_SHARED; i++) {
        int32_t p = tcp_flag_rate_position(src(0x20, i));
        if (p < 0) {
            missing++;
        } else {
            positions[n++] = p;
        }
    }
    qsort(positions, n, sizeof(*positions), compare_i32);
    uint32_t shared_positions = 0;
    for (uint32_t i = 1; i < n; i++) {
        if (positions[i] == positions[i - 1]) {
            shared_positions++;
        }
    }
    struct tcp_flag_rate_stats s = get_stats();
    printf("  %u workers, %u sources: %u not tracked, %u positions shared, %lu entries, "
           "%u checks not accepted, %lu table_full\n",
           jobs, expected, missing, shared_positions, (unsigned long)s.current_entries,
           not_accepted, (unsigned long)s.table_full);
    CHECK_EQ(0, missing, "every source added on any lcore is tracked");
    CHECK_EQ(0, shared_positions, "no two sources share a bucket");
    CHECK_EQ(expected, s.current_entries, "the table holds each source once");
    CHECK_EQ(0, not_accepted, "every check accepted");
    CHECK_EQ(0, s.table_full, "the table never ran out of positions");
out:
    free(positions);
    tcp_flag_rate_cleanup();
}

#define CHURN_TABLE     4096
#define CHURN_SOURCES   20000   // per worker, each new
#define CHURN_REPORT    32      // checks between a worker's quiescent reports

struct churn_job {
    uint32_t worker;
    uint32_t dropped;
    int reader_rc;
};
static struct churn_job churn_jobs[TABLE_TEST_MAX_WORKERS];
static uint32_t churn_cleaned;

static int churn_job_fn(void *arg) {
    struct churn_job *job = arg;
    unsigned int lcore = rte_lcore_id();
    job->reader_rc = flow_table_reader_register(lcore);
    table_test_start_wait();
    for (uint32_t i = 0; i < CHURN_SOURCES; i++) {
        if (tcp_flag_rate_check(src(0x40 + job->worker, i), SYN, 60) != TCPF_RATE_ACCEPT) {
            job->dropped++;
        }
        if (i % CHURN_REPORT == CHURN_REPORT - 1) {
            flow_table_reader_quiescent(lcore);
        }
    }
    if (job->reader_rc == 0) {
        flow_table_reader_unregister(lcore);
    }
    return 0;
}

static void churn_main_step(void) {
    flow_table_reader_quiescent(rte_lcore_id());
    churn_cleaned += cleanup_after_tick();
}

static void test_tcpf_concurrent_churn_leaks_nothing(void) {
    unsigned int lcore = rte_lcore_id();
    bool reader = false;

    CHECK_EQ(0, init_table(CHURN_TABLE, 0, 100000), "init");
    CHECK_EQ(0, flow_table_reader_register(lcore), "reader registration");
    reader = true;

    churn_cleaned = 0;
    void *args[TABLE_TEST_MAX_WORKERS];
    for (uint32_t w = 0; w < TABLE_TEST_MAX_WORKERS; w++) {
        memset(&churn_jobs[w], 0, sizeof(churn_jobs[w]));
        churn_jobs[w].worker = w;
        args[w] = &churn_jobs[w];
    }
    unsigned int jobs = table_test_run(churn_job_fn, args, churn_main_step);

    // Everything still tracked expires, and every deleted position comes
    // back once this reader has reported
    for (int k = 0; k < 3; k++) {
        churn_main_step();
    }
    flow_table_reader_unregister(lcore);
    reader = false;
    (void)cleanup_after_tick();

    uint32_t dropped = 0;
    for (uint32_t w = 0; w < jobs; w++) {
        CHECK_EQ(0, churn_jobs[w].reader_rc, "worker reader registration");
        dropped += churn_jobs[w].dropped;
    }
    struct tcp_flag_rate_stats s = get_stats();
    printf("  %u workers, %u new sources against a table of %u: %u cleaned, %u dropped, "
           "%lu table_full, %lu entries and %lu waiting at the end\n",
           jobs, jobs * CHURN_SOURCES, CHURN_TABLE, churn_cleaned, dropped,
           (unsigned long)s.table_full, (unsigned long)s.current_entries,
           (unsigned long)s.positions_waiting);
    CHECK_EQ(0, dropped, "no new source is dropped");
    CHECK_EQ(0, s.positions_waiting, "nothing waits once the readers have reported");
    CHECK_EQ(0, s.current_entries, "every position came back: none leaked");
out:
    if (reader) {
        flow_table_reader_unregister(lcore);
    }
    tcp_flag_rate_cleanup();
}

// ==================== Main ====================

int main(int argc __rte_unused, char **argv) {
    int rc = table_test_eal_init(argv[0]);
    if (rc != 0) {
        return rc;
    }

    printf("\n========================================\n");
    printf("  TCP Flag Rate Table Tests (%u lcores)\n", rte_lcore_count());
    printf("========================================\n\n");

    RUN_TEST(test_tcpf_churn_admits_new_sources);
    RUN_TEST(test_tcpf_deleted_positions_wait_for_readers);
    RUN_TEST(test_tcpf_held_bucket_not_reused);
    RUN_TEST(test_tcpf_full_table_accepts_untracked);
    RUN_TEST(test_tcpf_full_table_takes_back_released_positions);
    RUN_TEST(test_tcpf_writers_hold_lock);
    RUN_TEST(test_tcpf_unpublished_bucket_left_alone);
    RUN_TEST(test_tcpf_reused_position_unpublished);
    RUN_TEST(test_tcpf_racing_add_keeps_bucket);
    RUN_TEST(test_tcpf_cleanup_spares_source_refreshed_during_pass);
    RUN_TEST(test_tcpf_refill_by_other_lcore_keeps_limit);
    RUN_TEST(test_tcpf_concurrent_adds_lose_nothing);
    RUN_TEST(test_tcpf_concurrent_churn_leaks_nothing);

    return table_test_report("TCP flag rate table");
}
