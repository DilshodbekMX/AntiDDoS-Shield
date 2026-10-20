#ifndef LAYER1_FLOW_TABLE_H
#define LAYER1_FLOW_TABLE_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ring.h>
#include "../../common/types.h"

// Forward declaration to avoid circular include with shared_memory.h
struct per_ip_anomaly_snapshot;

/**
 * @file flow_table.h
 * @brief High-performance bidirectional flow tracking using CANONICAL keys
 *
 * Design principles:
 * - CANONICAL keys: ip_lo <= ip_hi always, so both directions map to same flow
 * - Lock-free operations: rte_ring for index allocation, RW-concurrent hash
 * - Cache-aligned entries: One flow per cache line to avoid false sharing
 * - DPDK idiomatic: Uses rte_hash, rte_ring, rte_malloc throughout
 *
 * Thread safety:
 * - flow_table_lookup_or_create(): Safe from multiple lcores and threads:
 *   lookups run concurrently (RW_CONCURRENCY), and every add and delete of
 *   the hash, from creates, aging, eviction and clear, holds one writer lock
 * - flow_table_update(): Safe with atomic counters
 * - flow_table_age_flows(): Should run from single maintenance thread
 * - A deleted entry is reused only after every registered reader has
 *   reported a quiescent state since the delete (see "Deferred
 *   Reclamation" below)
 */

// ==================== Flow State ====================

/**
 * TCP connection states following RFC 793 terminology.
 * States track the flow from the perspective of seeing packets on the wire.
 */
enum flow_state {
    FLOW_STATE_NEW = 0,          // Initial state, no packets seen yet
    FLOW_STATE_SYN_RECEIVED,     // SYN from initiator seen
    FLOW_STATE_SYN_ACK_RECEIVED, // SYN-ACK from responder seen
    FLOW_STATE_ESTABLISHED,      // ACK completing handshake seen
    FLOW_STATE_FIN_WAIT_1,       // FIN from initiator seen (initiator closing)
    FLOW_STATE_FIN_WAIT_2,       // ACK of initiator's FIN seen
    FLOW_STATE_CLOSE_WAIT,       // FIN from responder seen (responder closing)
    FLOW_STATE_CLOSING,          // FIN from both sides, waiting for final ACKs
    FLOW_STATE_LAST_ACK,         // Waiting for final ACK
    FLOW_STATE_TIME_WAIT,        // Both sides closed, waiting for timeout
    FLOW_STATE_CLOSED,           // Connection fully closed
    FLOW_STATE_RST,              // Connection reset
    FLOW_STATE_INITIALIZING,     // Entry being initialized, or claimed for eviction (transient state)
    FLOW_STATE_MAX
};

// ==================== Flow Entry ====================

/**
 * Flow entry - cache-line aligned for optimal multi-core access.
 * Total size should be exactly 128 bytes (2 cache lines) or 64 bytes (1 cache line).
 */
struct flow_entry {
    // === Cache Line 1: Hot data (accessed every packet) ===
    
    // Canonical flow key (12 bytes)
    struct flow_key key;
    
    // Entry management (4 bytes)
    uint32_t entry_index;          // Position in flow_entries array

    // Timestamps (16 bytes) - hot, updated every packet
    uint64_t first_seen_tsc;
    uint64_t last_seen_tsc;

    // Rate limiting window (16 bytes) - hot during rate limiting
    uint64_t window_start_tsc;
    uint32_t window_packets;
    uint32_t window_bytes;

    // Limits (8 bytes)
    uint32_t pps_limit;
    uint32_t bps_limit;

    // State and flags (8 bytes) - frequently read
    uint8_t  state;
    uint8_t  tcp_flags_lo_to_hi;
    uint8_t  tcp_flags_hi_to_lo;
    uint8_t  flags;
    uint8_t  initiator_dir;
    uint8_t  vouched;              // FLOW_VOUCHED_BY_LO / _HI (see below)
    uint8_t  _pad1[2];

    // === Cache Line 2: Cold data (accessed less frequently) ===
    
    // Bidirectional counters (32 bytes)
    uint64_t packets_lo_to_hi;
    uint64_t bytes_lo_to_hi;
    uint64_t packets_hi_to_lo;
    uint64_t bytes_hi_to_lo;

    // Initiator tracking (8 bytes)
    uint32_t initiator_ip;
    uint16_t initiator_port;
    uint16_t responder_port;

    // Metadata (8 bytes)
    uint16_t reputation_score;
    uint16_t mss_value;
    uint8_t  window_scale;
    uint8_t  _pad2[3];

    // TCP Sequence tracking for RST/FIN validation (16 bytes)
    // Tracks expected sequence numbers to detect spoofed RST/FIN attacks
    uint32_t seq_lo_to_hi;         // Next expected seq from lo->hi direction
    uint32_t seq_hi_to_lo;         // Next expected seq from hi->lo direction
    uint32_t ack_lo_to_hi;         // Last ACK seen from lo->hi direction
    uint32_t ack_hi_to_lo;         // Last ACK seen from hi->lo direction

} __rte_cache_aligned;

// Compile-time size check - 128 bytes = 2 cache lines
_Static_assert(sizeof(struct flow_entry) == 128,
               "flow_entry must be 128 bytes (2 cache lines)");

// Flow flags
#define FLOW_FLAG_SYN_COOKIE_VALIDATED  0x01
#define FLOW_FLAG_RATE_LIMITED          0x02
#define FLOW_FLAG_INITIATOR_KNOWN       0x04
#define FLOW_FLAG_ESTABLISHED           0x08
#define FLOW_FLAG_MARKED_FOR_DELETE     0x10
#define FLOW_FLAG_SEQ_TRACKING_ENABLED  0x20  // Sequence tracking active
#define FLOW_FLAG_HANDSHAKE_ACKED       0x40  // Handshake ACK acknowledged the responder's ISN + 1

// Sides of a TCP flow (flow_entry.vouched) that have sent a segment of their
// own, set by flow_table_update() and read by flow_table_vouches_for(): a SYN
// without ACK (they opened the connection), or an ACK without SYN or RST,
// which a stack sends on a connection it holds. A SYN-ACK and an RST do not
// count: a spoofed SYN draws the first, a blind segment the second. Nor is
// the ACK proof: a Linux server ACKs a blind segment without ACK outside the
// window of the half-open connection a spoofed SYN opens (an open item).
#define FLOW_VOUCHED_BY_LO              0x01  // ip_lo sent one (FLOW_DIR_LO_TO_HI)
#define FLOW_VOUCHED_BY_HI              0x02  // ip_hi sent one (FLOW_DIR_HI_TO_LO)

// RST/FIN validation result
enum rst_fin_validation_result {
    RST_FIN_VALID = 0,           // RST/FIN is valid for this flow
    RST_FIN_NO_FLOW,             // No flow exists (suspicious)
    RST_FIN_SEQ_OUT_OF_WINDOW,   // Sequence number out of expected window
    RST_FIN_WRONG_DIRECTION,     // RST/FIN from unexpected direction in flow state
    RST_FIN_UNEXPECTED_STATE,    // RST/FIN in flow state that doesn't expect it
};

// ==================== Configuration ====================

struct flow_table_config {
    uint32_t max_flows;            // Maximum concurrent flows (a hard capacity: the hash refuses no key below it)
    uint32_t idle_timeout_sec;     // Timeout for established flows
    uint32_t syn_timeout_sec;      // Timeout for half-open connections
    uint32_t default_pps_limit;    // Default packets/sec limit (0 = unlimited)
    uint32_t default_bps_limit;    // Default bytes/sec limit (0 = unlimited)
    bool     enable_syn_protection;// Enable aggressive SYN timeout
    uint32_t aging_scan_limit;     // Max entries to scan per aging cycle (default: 4096)
    uint32_t aging_scan_limit_pressure; // Scan limit when under pressure (default: 8192)
};

// ==================== Statistics ====================

struct flow_table_stats {
    uint64_t lookups;              // Total lookup operations
    uint64_t lookup_hits;          // Successful lookups (existing flow)
    uint64_t creates;              // New flows created
    uint64_t create_failures;      // Failed creates (table full)
    uint64_t deletes;              // Flows deleted (aged or explicit)
    uint64_t updates;              // Flow update operations
    uint64_t rate_limit_drops;     // Packets dropped by rate limiting
};

// ==================== Per-Lcore Statistics ====================

/**
 * Per-lcore flow table statistics to avoid atomics in fast path.
 * Aggregated on demand by flow_table_get_detailed_stats().
 */
struct flow_table_lcore_stats {
    uint64_t lookups;              // Total lookup operations
    uint64_t lookup_hits;          // Successful lookups (existing flow)
    uint64_t creates;              // New flows created
    uint64_t create_failures;      // Failed creates (table full)
    uint64_t updates;              // Flow update operations
    uint64_t rate_limit_drops;     // Packets dropped by rate limiting
    uint64_t _pad[2];              // Pad to cache line
} __rte_cache_aligned;

// ==================== Public API ====================

/**
 * Initialize flow table.
 * Allocates hash table, flow entry array, and free index ring.
 *
 * @param config  Configuration parameters
 * @return 0 on success, -1 on error
 */
int flow_table_init(const struct flow_table_config *config);

/**
 * Cleanup flow table and free all resources.
 */
void flow_table_cleanup(void);

/**
 * Lookup existing flow or create new one.
 * Thread-safe for concurrent access from multiple lcores.
 *
 * @param features  Packet features (flow_direction set on return)
 * @param created   Output: true if new flow was created
 * @return Flow entry pointer, or NULL if table full
 */
struct flow_entry* flow_table_lookup_or_create(struct packet_features *features,
                                                bool *created);

/**
 * Lookup existing flow or create new one with pre-read timestamp.
 * OPTIMIZED version - avoids redundant rte_rdtsc() calls.
 *
 * @param features  Packet features (flow_direction set on return)
 * @param created   Output: true if new flow was created
 * @param now_tsc   Current timestamp (from batch TSC read)
 * @return Flow entry pointer, or NULL if table full
 */
struct flow_entry* flow_table_lookup_or_create_tsc(struct packet_features *features,
                                                    bool *created,
                                                    uint64_t now_tsc);

/**
 * Lookup existing flow without creating.
 * Thread-safe for concurrent access.
 *
 * @param features  Packet features (flow_direction set on return)
 * @return Flow entry pointer, or NULL if not found
 */
struct flow_entry* flow_table_lookup(struct packet_features *features);

/**
 * Lookup existing flow with precomputed hash (avoids double hashing): the
 * table's own hash, rte_jhash(key, sizeof(*key), flow_table_get_hash_seed()).
 *
 * @param key       Flow key (canonical)
 * @param hash      Precomputed hash value (the table's seed is random)
 * @return Flow entry pointer, or NULL if not found
 */
struct flow_entry* flow_table_lookup_with_hash(const struct flow_key *key,
                                                uint32_t hash);

/**
 * Update flow counters and state.
 * Thread-safe using atomic operations.
 *
 * Every packet moves the last-seen time, and so the flow's lifetime, except
 * a SYN-ACK on a flow whose handshake is not verified
 * (FLOW_FLAG_HANDSHAKE_ACKED): a server retransmits its SYN-ACK for a spoofed
 * SYN for half a minute, and the flow of that SYN would live as long. It
 * still updates the state and the sequence tracking, which the handshake ACK
 * is checked against.
 *
 * @param flow      Flow entry to update
 * @param features  Packet features
 */
void flow_table_update(struct flow_entry *flow, const struct packet_features *features);

/**
 * Update flow counters and state with pre-read timestamp.
 * OPTIMIZED version - avoids redundant rte_rdtsc() calls.
 *
 * @param flow      Flow entry to update
 * @param features  Packet features
 * @param now_tsc   Current timestamp (from batch TSC read)
 */
void flow_table_update_tsc(struct flow_entry *flow, const struct packet_features *features,
                           uint64_t now_tsc);

/**
 * Count a packet on its flow without letting it change the flow's TCP view:
 * the packet and byte counters of its direction and the last-seen time move,
 * as in flow_table_update(), while the TCP flags seen, the sequence and ACK
 * tracking and the state stay as they were. For a segment the flow cannot
 * vouch for, such as an RST or FIN outside the connection's sequence window
 * (flow_table_validate_rst_fin()): it is forwarded, but it neither tears the
 * flow down nor moves the window the next RST is checked against.
 *
 * @param flow      Flow entry to update
 * @param features  Packet features (flow_direction set by the lookup)
 */
void flow_table_count_packet(struct flow_entry *flow, const struct packet_features *features);

/**
 * Record on a TCP flow that its initiator completed a handshake verified
 * outside the flow table, which a blind sender cannot do: the SYN proxy
 * validated the cookie the initiator's ACK returned, or saw the initiator
 * acknowledge the server's ISN + 1 on a connection it let through (the table
 * misses that handshake when the proxy answers the SYN, or when the flow was
 * created after it). Sets FLOW_FLAG_HANDSHAKE_ACKED (and
 * FLOW_FLAG_ESTABLISHED) and moves a flow still in NEW, SYN_RECEIVED or
 * SYN_ACK_RECEIVED to ESTABLISHED, as the handshake the table sees itself
 * does; a closing or terminal state is kept. Like such a flow it is then
 * protected from emergency eviction while it shows traffic both ways.
 *
 * @param flow  Flow entry (from a lookup or create)
 */
void flow_table_mark_handshake_verified(struct flow_entry *flow);

/**
 * Whether a TCP flow vouches for a segment between its two hosts, which
 * Stage 8b requires in spoofed mode (layer1_spoofed_tcp_admit()). A flow
 * exists for any segment the pipeline let through, and a spoofed SYN plants
 * one that the server's SYN-ACKs make two-way, so its existence proves
 * nothing. It vouches when one of these holds:
 * - its handshake is verified (FLOW_FLAG_HANDSHAKE_ACKED);
 * - the segment's destination has sent a segment of its own
 *   (FLOW_VOUCHED_BY_LO / _HI): its own SYN, or an ACK without SYN or RST.
 *   The server's side of a planted flow sends SYN-ACKs and RSTs, but a blind
 *   segment can draw such an ACK from a Linux server (FLOW_VOUCHED_BY_LO);
 * - the segment completes the handshake as the flow tracked it: the
 *   initiator's ACK of the responder's ISN + 1 on a flow past the SYN-ACK,
 *   the check the state machine verifies a handshake with.
 * The flow key has no ports: a flow that vouches does so for every
 * connection between its hosts.
 *
 * @param flow      Flow entry (from a lookup)
 * @param features  The segment's features (flow_direction set by that lookup)
 * @return true if the flow vouches for the segment
 */
bool flow_table_vouches_for(const struct flow_entry *flow, const struct packet_features *features);

/**
 * Check and apply rate limits.
 * Only applies to initiator direction (inbound attacks).
 *
 * @param flow      Flow entry
 * @param features  Packet features
 * @param ip_anom   Per-IP anomaly snapshot (may be NULL)
 * @return Rate limit action (RL_ACCEPT, RL_DROP_PPS, RL_DROP_BPS)
 */
enum rate_limit_action flow_table_check_rate_limit(struct flow_entry *flow,
                                                   const struct packet_features *features,
                                                   const struct per_ip_anomaly_snapshot *ip_anom);

/**
 * Set rate limits for a flow.
 *
 * @param features   Packet features identifying the flow
 * @param pps_limit  Packets per second limit (0 = unlimited)
 * @param bps_limit  Bytes per second limit (0 = unlimited)
 * @return 0 on success, -1 if flow not found
 */
int flow_table_set_limits(struct packet_features *features, 
                          uint32_t pps_limit, uint32_t bps_limit);

/**
 * Age out expired flows.
 * Should be called periodically from maintenance thread.
 * NOT thread-safe with other aging calls (single caller only).
 * Each call also checks the registered readers for a stall, and deletes
 * nothing while one is stalled (see "Deferred Reclamation").
 *
 * @return Number of flows aged out
 */
uint32_t flow_table_age_flows(void);

/**
 * Emergency eviction based on reputation when table is full.
 * Evicts low-reputation flows to make room for new legitimate connections.
 *
 * Priority order for eviction (lowest priority evicted first):
 * 1. Incomplete handshakes (SYN_RECEIVED, SYN_ACK_RECEIVED) with bad reputation
 * 2. Single-direction flows (no response received) - likely attack
 * 3. Low reputation score flows
 * 4. Oldest inactive flows
 *
 * Never chosen for eviction (aging expires them when idle): established TCP
 * flows with traffic in both directions whose handshake ACK acknowledged the
 * responder's ISN + 1. A blind ACK cannot know that ISN, so its flow stays
 * evictable. Non-TCP flows have no handshake and stay evictable too; they
 * score as established while they show traffic in both directions, and so
 * does a TCP flow first seen mid-stream (still FLOW_STATE_NEW, no handshake
 * seen), which stays evictable for the same reason.
 * Each chosen flow is checked again, under the table's writer lock, just
 * before it is deleted, and claimed by a compare-and-swap of the state it was
 * checked in: a flow whose handshake completed before the claim is kept.
 * Fewer than count_needed flows, possibly none, may be evicted. An evicted
 * entry is reused only after every registered reader has reported a
 * quiescent state (see "Deferred Reclamation").
 *
 * @param count_needed  Number of flow slots needed
 * @return Number of flows evicted
 */
uint32_t flow_table_emergency_evict(uint32_t count_needed);

/**
 * Test seam: flow_table_emergency_evict() calls this after choosing its
 * candidates and before deleting them. The library's weak definition does
 * nothing; a unit test may link its own to change flows at that point.
 */
void flow_table_evict_seam(void);

/**
 * Test seam: flow_table_emergency_evict() calls this for each chosen flow
 * that passed its recheck, just before claiming and deleting it, with the
 * table's writer lock held (an override may update flows but must not
 * create, age, evict or clear). The library's weak definition does nothing.
 */
void flow_table_evict_claim_seam(void);

/**
 * Test seam: flow_table_age_flows() calls this after choosing the expired
 * flows of a pass and before deleting them, without the writer lock. The
 * library's weak definition does nothing.
 */
void flow_table_age_seam(void);

/**
 * Points at which both tables call flow_table_race_seam(): moments at which
 * another lcore could act on the same flows. "Under the lock" means with the
 * table's writer lock held.
 */
enum flow_table_seam_point {
    FLOW_SEAM_CREATE_MISSED = 0, // create: the lockless lookup missed, before the index allocation
    FLOW_SEAM_CREATE_ADDED,      // create: added to the hash (lock released), before the flow is published
    FLOW_SEAM_PUBLISH_WAIT,      // create: found another creator's unpublished flow (lock released), before the bounded wait
    FLOW_SEAM_AGE_DELETE,        // aging: a flow passed its recheck, under the lock, before its delete
    FLOW_SEAM_CLEAR_DELETE,      // clear: a key was found, under the lock, before its delete
    FLOW_SEAM_V6_CREATE_MISSED,  // IPv6 create: as FLOW_SEAM_CREATE_MISSED
    FLOW_SEAM_V6_CREATE_ADDED,   // IPv6 create: as FLOW_SEAM_CREATE_ADDED
    FLOW_SEAM_V6_PUBLISH_WAIT,   // IPv6 create: as FLOW_SEAM_PUBLISH_WAIT
    FLOW_SEAM_V6_AGE,            // IPv6 aging: after choosing the expired flows, before the deletes (no lock)
    FLOW_SEAM_V6_AGE_DELETE,     // IPv6 aging: as FLOW_SEAM_AGE_DELETE
    FLOW_SEAM_V6_EVICT,          // IPv6 eviction: after choosing the candidates, before the deletes (no lock)
    FLOW_SEAM_V6_EVICT_CLAIM,    // IPv6 eviction: a candidate passed its recheck, under the lock, before its claim
    FLOW_SEAM_V6_CLEAR_DELETE,   // IPv6 clear: as FLOW_SEAM_CLEAR_DELETE
    FLOW_SEAM_MAX
};

/**
 * Test seam: called at each point of enum flow_table_seam_point. The
 * library's weak definition does nothing; a unit test may link its own to
 * act there as another lcore would. At a point under the lock an override
 * may update flows but must not create, age, evict or clear.
 */
void flow_table_race_seam(enum flow_table_seam_point point);

/**
 * Test seam: flow_table_init() and flow_table_v6_init() call this for the
 * seed of their hash function. The library's weak definition returns false,
 * and the table then takes a random seed: with a fixed one, a sender could
 * choose keys that share buckets, which the extendable buckets chain instead
 * of refusing. A unit test may link its own definition that sets *seed and
 * returns true, for a reproducible layout.
 *
 * @param seed  Output: the seed to use
 * @return true if *seed was set
 */
bool flow_table_hash_seed_seam(uint32_t *seed);

/**
 * Seed of the IPv4 table's hash function (diagnostics and tests).
 */
uint32_t flow_table_get_hash_seed(void);

/**
 * Whether the IPv4 table's writer lock is held, by anyone (diagnostics and
 * tests: a seam at a point under the lock checks that it is).
 */
bool flow_table_writer_lock_held(void);

/**
 * Check if emergency eviction is needed.
 * @return true if table occupancy > 95%
 */
bool flow_table_needs_emergency_evict(void);

/**
 * Get current table occupancy percentage.
 * @return Occupancy as 0-100%
 */
uint32_t flow_table_get_occupancy_percent(void);

/**
 * Get flow table statistics.
 *
 * @param active_flows  Output: current active flow count
 * @param total_flows   Output: total flows created since init
 * @param aged_flows    Output: total flows aged out since init
 */
void flow_table_get_stats(uint32_t *active_flows, uint32_t *total_flows, uint32_t *aged_flows);

/**
 * Get detailed statistics.
 *
 * @param stats  Output: detailed statistics structure
 */
void flow_table_get_detailed_stats(struct flow_table_stats *stats);

/**
 * Clear all flows from the table.
 * NOT thread-safe - call only when no packets being processed.
 */
void flow_table_clear(void);

/**
 * Print flow table statistics to stdout.
 */
void flow_table_print_stats(void);

/**
 * Dump flow table state for debugging.
 *
 * @param max_entries  Maximum entries to dump (0 = all)
 */
void flow_table_dump(uint32_t max_entries);

// ==================== Deferred Reclamation ====================

/**
 * Aging, emergency eviction and clear delete flows while other lcores may
 * still hold pointers to them from earlier lookups, and write through them
 * (flow_table_update() and the rest). A deleted entry is therefore not
 * reused at once: it waits in its table's limbo, and returns to the free
 * indices only after every registered reader has reported a quiescent state
 * since the delete (rte_rcu_qsbr). A late write then lands on the dead
 * entry, never on the next flow that takes it. Both tables share the
 * readers.
 *
 * - Bounded: an index is in one place at a time (the hash, the free indices,
 *   the limbo, or a create in progress), so a limbo never holds more than
 *   max_flows indices, never refuses a delete and never leaks an index.
 * - Never blocks: a create that finds no free index takes back, without
 *   waiting, what has passed its grace period (a bounded number per call),
 *   and aging does the same once per pass. With no reader registered, a
 *   deleted entry can be taken back at once.
 * - While 256 or more deleted entries (an eviction's batch) wait, the
 *   emergency eviction is skipped: evicting more live flows would not make
 *   room any sooner.
 * - A registered reader that has not reported a quiescent state for more
 *   than 2 s is stalled (it hangs, or its lcore gets no CPU). Aging, which
 *   the maintenance lcore runs once a second, finds it 3 to 4 s after its
 *   last report (it checks against a probe token issued at most a second
 *   after that report, once the probe is over 2 s old), logs a WARNING with
 *   its reader id (the lcore id) and counts it
 *   (flow_table_reader_stall_count()). An entry deleted since its last
 *   report is never reused before it reports again: it may still hold the
 *   entry, and a write through that pointer would land on another flow.
 *   While it is stalled nothing deleted can be reused, so both tables stop
 *   deleting: aging deletes no expired flow (a flow that comes back still
 *   finds its entry) and a create that finds no free index runs no emergency
 *   eviction (it would only move live flows into a limbo that cannot drain).
 *   Creates take the free indices left, then fail: new flows go untracked
 *   until the reader reports. When it does, the next aging call logs it, the
 *   entries that waited come back and both tables delete again.
 *
 * A reader is a thread that holds flow pointers across calls into the table.
 * Each packet loop registers its lcore id once (flow_table_reader_register())
 * and reports a quiescent state at least once per RX burst
 * (flow_table_reader_quiescent()), at a point where it holds no flow
 * pointer; it unregisters before it exits. A thread that never registers is
 * not waited for, and must not use a flow pointer once the call that
 * returned it has ended.
 */

/**
 * Register the calling thread as a reader under reader_id (its lcore id,
 * below RTE_MAX_LCORE) and put it online: deleted entries now wait for its
 * quiescent reports.
 *
 * @return 0 on success, -1 on error (reader_id out of range, no memory)
 */
int flow_table_reader_register(unsigned int reader_id);

/**
 * Take a reader offline and unregister it: deleted entries stop waiting for
 * it. It must hold no flow pointer.
 */
void flow_table_reader_unregister(unsigned int reader_id);

/**
 * Report a quiescent state for a registered reader: it holds no flow pointer
 * obtained before this call. Cheap: a load of the shared token and, when it
 * changed, one store to the reader's own cache line.
 */
void flow_table_reader_quiescent(unsigned int reader_id);

/**
 * Number of deleted IPv4 flow entries waiting for their grace period.
 */
uint32_t flow_table_limbo_count(void);

/**
 * Number of registered readers found stalled that have not reported a
 * quiescent state since (see "Deferred Reclamation"). While it is above 0,
 * aging deletes no flow and a create runs no emergency eviction, in both
 * tables.
 */
uint32_t flow_table_readers_stalled(void);

/**
 * Whether the reader registered under reader_id is stalled now.
 */
bool flow_table_reader_stalled(unsigned int reader_id);

/**
 * Stalls found since the process started, over all readers: each is counted
 * once, when aging finds it.
 */
uint64_t flow_table_reader_stall_count(void);

/**
 * Test seam: the clock (TSC) the stalled-reader check reads. The library's
 * weak definition returns rte_rdtsc(); a unit test may link its own to move
 * the check's time forward.
 */
uint64_t flow_table_stall_clock(void);

// ==================== RST/FIN Validation ====================

/**
 * Validate RST or FIN packet against flow state.
 * Checks that the sequence number is within the expected window.
 * This prevents spoofed RST/FIN attacks that try to tear down connections.
 * Layer 1 validates every RST or FIN segment at Stage 11 (with
 * flow_table_validate_rst_fin_flow(), below) and counts a segment outside
 * the window on its flow without letting it change the flow
 * (flow_table_count_packet()); see Stage 11 in layer1.c.
 *
 * @param features  Packet features (must be RST or FIN packet)
 * @return RST_FIN_VALID if packet is valid, error code otherwise
 */
enum rst_fin_validation_result flow_table_validate_rst_fin(
    struct packet_features *features);

/**
 * The same validation and counting against a flow the caller has looked up
 * already, without a lookup of its own: Stage 11 validates against the flow
 * its own lookup returned, so an RST or FIN segment costs one lookup, as any
 * other segment does (a flood of blind RSTs would otherwise pay two). flow
 * is NULL when the segment has no flow, and so is a flow the caller's lookup
 * has just created for it: both count and return RST_FIN_NO_FLOW, as
 * flow_table_validate_rst_fin() does when its lookup misses. features must
 * have been through that lookup (it sets features->flow_direction).
 */
enum rst_fin_validation_result flow_table_validate_rst_fin_flow(
    struct flow_entry *flow, const struct packet_features *features);

/**
 * Get RST/FIN validation statistics
 *
 * @param valid_count     Output: Valid RST/FIN packets
 * @param invalid_count   Output: Invalid/spoofed RST/FIN packets
 */
void flow_table_get_rst_fin_stats(uint64_t *valid_count, uint64_t *invalid_count);

// ==================== Utility Functions ====================

static inline uint64_t flow_total_packets(const struct flow_entry *flow) {
    return __atomic_load_n(&flow->packets_lo_to_hi, __ATOMIC_RELAXED) +
           __atomic_load_n(&flow->packets_hi_to_lo, __ATOMIC_RELAXED);
}

static inline uint64_t flow_total_bytes(const struct flow_entry *flow) {
    return __atomic_load_n(&flow->bytes_lo_to_hi, __ATOMIC_RELAXED) +
           __atomic_load_n(&flow->bytes_hi_to_lo, __ATOMIC_RELAXED);
}

static inline bool flow_is_bidirectional(const struct flow_entry *flow) {
    return (__atomic_load_n(&flow->packets_lo_to_hi, __ATOMIC_RELAXED) > 0 &&
            __atomic_load_n(&flow->packets_hi_to_lo, __ATOMIC_RELAXED) > 0);
}

static inline bool flow_is_established(const struct flow_entry *flow) {
    return (__atomic_load_n(&flow->state, __ATOMIC_RELAXED) == FLOW_STATE_ESTABLISHED);
}

static inline const char* flow_state_str(enum flow_state state) {
    static const char *names[] = {
        "NEW", "SYN_RECV", "SYN_ACK_RECV", "ESTABLISHED",
        "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING",
        "LAST_ACK", "TIME_WAIT", "CLOSED", "RST", "INITIALIZING"
    };
    // One name per state: a state added without a name fails to compile
    _Static_assert(RTE_DIM(names) == FLOW_STATE_MAX,
                   "flow_state_str() needs one name per enum flow_state value");
    return ((unsigned int)state < RTE_DIM(names)) ? names[state] : "UNKNOWN";
}

#endif // LAYER1_FLOW_TABLE_H