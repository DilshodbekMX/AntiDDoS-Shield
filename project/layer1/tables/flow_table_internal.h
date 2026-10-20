#ifndef LAYER1_FLOW_TABLE_INTERNAL_H
#define LAYER1_FLOW_TABLE_INTERNAL_H

/**
 * @file flow_table_internal.h
 * @brief Internals shared by flow_table.c and flow_table_v6.c: deferred
 *        reuse of deleted entries (see "Deferred Reclamation" in
 *        flow_table.h), the hash seed and the eviction score.
 *
 * Not part of either table's public API.
 */

#include <stdint.h>
#include <stdbool.h>
#include <rte_spinlock.h>
#include <netinet/in.h>
#include "flow_table.h"

struct rte_rcu_qsbr;

// ==================== Deferred Reclamation ====================

/**
 * The quiescent-state variable of every flow table reader (both tables).
 * The first table init or reader registration creates it, and it is kept
 * for the life of the process, so readers registered before a table is
 * created again stay registered. NULL only if it could not be allocated.
 */
struct rte_rcu_qsbr *flow_table_readers(void);

// Grace periods waited on at once. A delete pass (one aging call, one
// eviction, one clear batch) is one batch with one token; when every batch
// is in use a new one joins the newest and takes its later token, so a pass
// is never refused (its indices only wait a little longer).
#define FLOW_LIMBO_BATCHES  64

struct flow_limbo_batch {
    uint64_t token;      // rte_rcu_qsbr_start() taken after the batch's deletes
    uint64_t since_tsc;  // when the batch was handed over
    uint32_t count;      // indices of the batch still waiting
};

/**
 * Deleted entries of one table waiting for their grace period: a FIFO of
 * entry indices in batches. Its capacity is the table's max_flows: an index
 * is in one place at a time (the hash, the free indices, this limbo, or a
 * create in progress), so a delete pass always fits.
 */
struct flow_limbo {
    uint32_t *idx;              // circular buffer of capacity indices
    uint32_t capacity;
    uint32_t head;              // position of the oldest index
    uint32_t count;             // indices waiting (written under the lock)
    uint32_t first;             // oldest batch in batch[]
    uint32_t nb;                // batches in use
    uint64_t last_stall_log_tsc;
    rte_spinlock_t lock;
    struct flow_limbo_batch batch[FLOW_LIMBO_BATCHES];
};

/**
 * Prepare an empty limbo for a table of capacity entries.
 * @return 0, or -1 if its buffer cannot be allocated
 */
int flow_limbo_init(struct flow_limbo *l, uint32_t capacity, const char *name);

/**
 * Release a limbo's buffer. The table is gone: what still waits is dropped.
 */
void flow_limbo_free(struct flow_limbo *l);

/**
 * Hand over n indices the caller has just deleted from its table's hash
 * (each exactly once, none in use anywhere else) and start their grace
 * period. Never blocks on a reader.
 *
 * @return the number of indices it could not hold: 0 unless the
 *         one-place rule above was broken (the caller then logs and frees
 *         them at once, which is what the table did before)
 */
uint32_t flow_limbo_push(struct flow_limbo *l, const uint32_t *idx, uint32_t n);

/**
 * Take up to max indices whose grace period is over, oldest first. The
 * caller returns them to its free indices. Non-blocking: indices that a
 * registered reader may still hold stay in the limbo.
 *
 * @return the number of indices written to out[]
 */
uint32_t flow_limbo_take(struct flow_limbo *l, uint32_t *out, uint32_t max);

/**
 * Number of indices waiting (read without the lock: a hint).
 */
uint32_t flow_limbo_waiting(const struct flow_limbo *l);

/**
 * Log, at most once a minute, when the oldest batch has waited longer than
 * stall_tsc: a registered reader has stopped reporting quiescent states, and
 * its table's deleted entries are not reused meanwhile.
 */
void flow_limbo_check_stall(struct flow_limbo *l, uint64_t now_tsc, uint64_t stall_tsc,
                            const char *table);

// ==================== Hash Seed ====================

/**
 * Seed for a table's hash function: the test seam's when it sets one (see
 * flow_table_hash_seed_seam()), else random (getrandom(), or rte_rand() when
 * the kernel cannot provide random bytes yet).
 */
uint32_t flow_table_new_hash_seed(void);

// ==================== Eviction Score ====================

/**
 * Eviction priority of a flow (lower is evicted first), from its fields as
 * the caller read them. Shared by both tables so that they score alike; see
 * calculate_eviction_priority() in flow_table.c for the factors.
 */
static inline int32_t flow_eviction_score(uint8_t state, uint8_t protocol,
                                          uint64_t pkts_lo, uint64_t pkts_hi,
                                          uint64_t first_seen, uint16_t rep,
                                          uint64_t now_tsc, uint64_t tsc_hz) {
    int32_t score = 0;
    bool bidirectional = (pkts_lo > 0 && pkts_hi > 0);

    // The state machine runs for TCP only, so a non-TCP flow is NEW for life
    // and would score as an incomplete handshake. A TCP flow first seen
    // mid-stream (after a restart, or recreated after its entry was aged or
    // evicted) never sees the initiator's SYN and is NEW for life too. Score
    // either by what it shows: traffic both ways is the established
    // analogue, one-way stays NEW. Only the score changes: neither had a
    // verified handshake, so neither is protected (the protected check reads
    // the real state and needs FLOW_FLAG_HANDSHAKE_ACKED).
    if (bidirectional && (protocol != IPPROTO_TCP || state == FLOW_STATE_NEW)) {
        state = FLOW_STATE_ESTABLISHED;
    }

    // Calculate flow age
    uint64_t age_sec = 0;
    if (first_seen > 0 && now_tsc > first_seen) {
        age_sec = (now_tsc - first_seen) / tsc_hz;
    }

    // State-based scoring - AGGRESSIVE for incomplete flows
    switch (state) {
        case FLOW_STATE_NEW:
        case FLOW_STATE_SYN_RECEIVED:
            // Incomplete handshakes - PRIME eviction targets during DDoS
            // These are almost certainly attack traffic when table is full
            score -= 2000;
            // Extra penalty if flow is old but still not established
            if (age_sec > 5) {
                score -= 500;  // Stuck in SYN state for >5 sec = attack
            }
            break;

        case FLOW_STATE_SYN_ACK_RECEIVED:
            // Got SYN-ACK but no ACK - slightly less suspicious
            score -= 1500;
            break;

        case FLOW_STATE_ESTABLISHED:
            // Established - protect, especially if bidirectional
            if (bidirectional) {
                score += 500;  // Definitely legitimate
            } else {
                score += 100;  // Established but one-way - could be data transfer
            }
            break;

        case FLOW_STATE_CLOSED:
        case FLOW_STATE_RST:
        case FLOW_STATE_TIME_WAIT:
            // Terminal states - cleanup these
            score -= 300;
            break;

        case FLOW_STATE_FIN_WAIT_1:
        case FLOW_STATE_FIN_WAIT_2:
        case FLOW_STATE_CLOSE_WAIT:
        case FLOW_STATE_CLOSING:
        case FLOW_STATE_LAST_ACK:
            // Closing states - moderate priority for eviction
            score -= 100;
            break;

        default:
            break;
    }

    // Bidirectional traffic is THE key indicator of legitimate connection
    if (bidirectional) {
        score += 300;
    } else {
        // Single-direction = almost certainly attack during DDoS
        score -= 1500;
    }

    // Very short-lived non-established flows are likely attack
    if (age_sec < 1 && state != FLOW_STATE_ESTABLISHED) {
        score -= 500;
    }

    // Reputation score (0-65535, higher is better)
    if (rep < 100) {
        score -= 200;  // Very bad reputation
    } else if (rep < 500) {
        score -= 100;  // Bad reputation
    } else if (rep > 2000) {
        score += 100;  // Good reputation
    }

    // Small bonus for longer-lived established connections
    // But don't over-protect - age is less important than bidirectionality
    if (state == FLOW_STATE_ESTABLISHED && age_sec > 10) {
        score += (int32_t)(age_sec / 10);  // +1 per 10 seconds
        if (score > 600) score = 600;  // Cap at +100 from age
    }

    return score;
}

#endif // LAYER1_FLOW_TABLE_INTERNAL_H
