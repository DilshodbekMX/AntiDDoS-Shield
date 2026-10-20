#ifndef LAYER1_FLOW_TABLE_V6_H
#define LAYER1_FLOW_TABLE_V6_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ring.h>
#include "../../common/types.h"
#include "flow_table.h"  // Reuse flow_state, flow_flags, etc.

/**
 * @file flow_table_v6.h
 * @brief IPv6 flow table with 128-bit address support
 *
 * This provides IPv6-specific flow tracking using the same design
 * principles as the IPv4 flow table:
 * - CANONICAL keys: ip_lo <= ip_hi (lexicographic comparison)
 * - Lock-free operations: rte_ring for index allocation
 * - Cache-aligned entries for multi-core access
 *
 * Key differences from IPv4 flow table:
 * - Flow key is 36 bytes (vs 12 bytes for IPv4)
 * - Uses separate hash table with larger key size
 * - Entry size is 192 bytes (3 cache lines)
 */

// ==================== IPv6 Flow Entry ====================

/**
 * IPv6 flow entry - cache-line aligned for optimal multi-core access.
 * Total size: 192 bytes (3 cache lines)
 */
struct flow_entry_v6 {
    // === Cache Line 1: Hot data (64 bytes) ===

    // Canonical flow key (36 bytes)
    struct flow_key_v6 key;

    // Entry management (4 bytes)
    uint32_t entry_index;          // Position in flow_entries array

    // Timestamps (16 bytes) - hot, updated every packet
    uint64_t first_seen_tsc;
    uint64_t last_seen_tsc;

    // Padding to cache line (8 bytes)
    uint64_t _pad0;

    // === Cache Line 2: Rate limiting and state (64 bytes) ===

    // Rate limiting window (16 bytes)
    uint64_t window_start_tsc;
    uint32_t window_packets;
    uint32_t window_bytes;

    // Limits (8 bytes)
    uint32_t pps_limit;
    uint32_t bps_limit;

    // State and flags (8 bytes)
    uint8_t  state;                // enum flow_state
    uint8_t  tcp_flags_lo_to_hi;
    uint8_t  tcp_flags_hi_to_lo;
    uint8_t  flags;
    uint8_t  initiator_dir;
    uint8_t  vouched;              // FLOW_VOUCHED_BY_LO / _HI (flow_table.h)
    uint8_t  _pad1[2];

    // Bidirectional counters (32 bytes)
    uint64_t packets_lo_to_hi;
    uint64_t bytes_lo_to_hi;
    uint64_t packets_hi_to_lo;
    uint64_t bytes_hi_to_lo;

    // === Cache Line 3: Metadata and sequence tracking (64 bytes) ===

    // Initiator tracking (16 bytes for IPv6)
    uint8_t  initiator_ip[16];

    // Port tracking (4 bytes)
    uint16_t initiator_port;
    uint16_t responder_port;

    // Metadata (8 bytes)
    uint16_t reputation_score;
    uint16_t mss_value;
    uint8_t  window_scale;
    uint8_t  _pad2[3];

    // TCP Sequence tracking (16 bytes)
    uint32_t seq_lo_to_hi;
    uint32_t seq_hi_to_lo;
    uint32_t ack_lo_to_hi;
    uint32_t ack_hi_to_lo;

    // IPv6 specific (8 bytes)
    uint32_t ipv6_flow_label;      // Flow label from IPv6 header
    uint32_t ext_hdr_len;          // Total extension header length

    // Padding to 192 bytes (12 bytes)
    uint8_t  _pad3[12];

} __rte_cache_aligned;

// Compile-time size check - 192 bytes = 3 cache lines
_Static_assert(sizeof(struct flow_entry_v6) == 192,
               "flow_entry_v6 must be 192 bytes (3 cache lines)");

// ==================== Configuration ====================

struct flow_table_v6_config {
    uint32_t max_flows;            // Maximum concurrent IPv6 flows
    uint32_t idle_timeout_sec;     // Timeout for established flows
    uint32_t syn_timeout_sec;      // Timeout for half-open connections
    uint32_t default_pps_limit;    // Default packets/sec limit (0 = unlimited)
    uint32_t default_bps_limit;    // Default bytes/sec limit (0 = unlimited)
    bool     enable_syn_protection;// Enable aggressive SYN timeout
    uint32_t aging_scan_limit;     // Max entries to scan per aging cycle
};

// ==================== Statistics ====================

struct flow_table_v6_stats {
    uint64_t lookups;              // Total lookup operations
    uint64_t lookup_hits;          // Successful lookups (existing flow)
    uint64_t creates;              // New flows created
    uint64_t create_failures;      // Failed creates (table full)
    uint64_t deletes;              // Flows deleted (aged or explicit)
    uint64_t updates;              // Flow update operations
    uint64_t rate_limit_drops;     // Packets dropped by rate limiting
};

// ==================== Public API ====================

/**
 * Initialize IPv6 flow table.
 * Allocates hash table, flow entry array, and free index ring.
 *
 * @param config  Configuration parameters
 * @return 0 on success, -1 on error
 */
int flow_table_v6_init(const struct flow_table_v6_config *config);

/**
 * Cleanup IPv6 flow table and free all resources.
 */
void flow_table_v6_cleanup(void);

/**
 * Lookup existing IPv6 flow or create new one.
 * Thread-safe for concurrent access from multiple lcores.
 *
 * @param features  Packet features (flow_direction set on return)
 * @param created   Output: true if new flow was created
 * @return Flow entry pointer, or NULL if table full
 */
struct flow_entry_v6* flow_table_v6_lookup_or_create(
    struct packet_features_v6 *features,
    bool *created);

/**
 * Lookup existing IPv6 flow or create new one with pre-read timestamp.
 * OPTIMIZED version - avoids redundant rte_rdtsc() calls.
 *
 * @param features  Packet features (flow_direction set on return)
 * @param created   Output: true if new flow was created
 * @param now_tsc   Current timestamp (from batch TSC read)
 * @return Flow entry pointer, or NULL if table full
 */
struct flow_entry_v6* flow_table_v6_lookup_or_create_tsc(
    struct packet_features_v6 *features,
    bool *created,
    uint64_t now_tsc);

/**
 * Lookup existing IPv6 flow without creating.
 * Thread-safe for concurrent access.
 *
 * @param features  Packet features (flow_direction set on return)
 * @return Flow entry pointer, or NULL if not found
 */
struct flow_entry_v6* flow_table_v6_lookup(struct packet_features_v6 *features);

/**
 * Update IPv6 flow counters and state.
 * Thread-safe using atomic operations. As flow_table_update(), a SYN-ACK
 * does not move the last-seen time of a flow whose handshake is not
 * verified.
 *
 * @param flow      Flow entry to update
 * @param features  Packet features
 */
void flow_table_v6_update(struct flow_entry_v6 *flow,
                          const struct packet_features_v6 *features);

/**
 * Whether an IPv6 TCP flow vouches for a segment between its two hosts
 * (IPv6 Stage 8b in spoofed mode), by the rules of flow_table_vouches_for().
 *
 * @param flow      Flow entry (from a lookup)
 * @param features  The segment's features (flow_direction set by that lookup)
 * @return true if the flow vouches for the segment
 */
bool flow_table_v6_vouches_for(const struct flow_entry_v6 *flow,
                               const struct packet_features_v6 *features);

/**
 * Count a packet on its IPv6 flow without letting it change the flow's TCP
 * view, as flow_table_count_packet() for IPv4: the packet and byte counters
 * and the last-seen time move; the TCP flags seen, the sequence and ACK
 * tracking and the state stay as they were.
 *
 * @param flow      Flow entry to update
 * @param features  Packet features (flow_direction set by the lookup)
 */
void flow_table_v6_count_packet(struct flow_entry_v6 *flow,
                                const struct packet_features_v6 *features);

/**
 * Check and apply rate limits for IPv6 flow.
 *
 * @param flow      Flow entry
 * @param features  Packet features
 * @return Rate limit action (RL_ACCEPT, RL_DROP_PPS, RL_DROP_BPS)
 */
enum rate_limit_action flow_table_v6_check_rate_limit(
    struct flow_entry_v6 *flow,
    const struct packet_features_v6 *features);

/**
 * Age out expired IPv6 flows.
 * Should be called periodically from maintenance thread.
 * As flow_table_age_flows(), each call checks the registered readers for a
 * stall and deletes nothing while one is stalled.
 *
 * @return Number of flows aged out
 */
uint32_t flow_table_v6_age_flows(void);

/**
 * Emergency eviction for the IPv6 table, as flow_table_emergency_evict() for
 * IPv4: the same score (flow_eviction_score()), the same protected class
 * (TCP flows that are ESTABLISHED, with traffic both ways, whose handshake
 * ACK acknowledged the responder's ISN + 1, which a blind ACK cannot know),
 * and the same recheck under the writer lock with a claim of the checked
 * state just before each delete. A create that finds the table full runs it,
 * at most once per 100 ms across lcores. Fewer than count_needed flows,
 * possibly none, may be evicted. Evicted entries wait for the readers'
 * grace period (see "Deferred Reclamation" in flow_table.h).
 *
 * @param count_needed  Number of flow slots needed
 * @return Number of flows evicted
 */
uint32_t flow_table_v6_emergency_evict(uint32_t count_needed);

/**
 * Seed of the IPv6 table's hash function (diagnostics and tests; see
 * flow_table_hash_seed_seam()).
 */
uint32_t flow_table_v6_get_hash_seed(void);

/**
 * The IPv6 table's hash of a key, as its lookups compute it, with its seed
 * (diagnostics and tests). The key may be at any address: the hash reads a
 * copy of it.
 *
 * @return the hash, or 0 if the table is not initialized
 */
uint32_t flow_table_v6_key_hash(const struct flow_key_v6 *key);

/**
 * Whether the IPv6 table's writer lock is held, by anyone (diagnostics and
 * tests, as flow_table_writer_lock_held()).
 */
bool flow_table_v6_writer_lock_held(void);

/**
 * Number of deleted IPv6 flow entries waiting for their grace period (see
 * "Deferred Reclamation" in flow_table.h).
 */
uint32_t flow_table_v6_limbo_count(void);

/**
 * Get IPv6 flow table statistics.
 *
 * @param stats  Output: statistics structure
 */
void flow_table_v6_get_stats(struct flow_table_v6_stats *stats);

/**
 * Get current IPv6 table occupancy percentage.
 * @return Occupancy as 0-100%
 */
uint32_t flow_table_v6_get_occupancy_percent(void);

/**
 * Clear all IPv6 flows from the table.
 * NOT thread-safe - call only when no packets being processed.
 */
void flow_table_v6_clear(void);

/**
 * Validate RST or FIN packet against IPv6 flow state. Layer 1 validates
 * every RST or FIN segment at IPv6 Stage 11 (with
 * flow_table_v6_validate_rst_fin_flow(), below), as at IPv4 Stage 11 (see
 * flow_table_validate_rst_fin()).
 *
 * @param features  Packet features (must be RST or FIN packet)
 * @return RST_FIN_VALID if packet is valid, error code otherwise
 */
enum rst_fin_validation_result flow_table_v6_validate_rst_fin(
    struct packet_features_v6 *features);

/**
 * The same against a flow the caller has looked up already (NULL, or just
 * created: no flow), as flow_table_validate_rst_fin_flow() for IPv4.
 */
enum rst_fin_validation_result flow_table_v6_validate_rst_fin_flow(
    struct flow_entry_v6 *flow, const struct packet_features_v6 *features);

// ==================== Utility Functions ====================

static inline uint64_t flow_v6_total_packets(const struct flow_entry_v6 *flow) {
    return __atomic_load_n(&flow->packets_lo_to_hi, __ATOMIC_RELAXED) +
           __atomic_load_n(&flow->packets_hi_to_lo, __ATOMIC_RELAXED);
}

static inline uint64_t flow_v6_total_bytes(const struct flow_entry_v6 *flow) {
    return __atomic_load_n(&flow->bytes_lo_to_hi, __ATOMIC_RELAXED) +
           __atomic_load_n(&flow->bytes_hi_to_lo, __ATOMIC_RELAXED);
}

static inline bool flow_v6_is_bidirectional(const struct flow_entry_v6 *flow) {
    return (__atomic_load_n(&flow->packets_lo_to_hi, __ATOMIC_RELAXED) > 0 &&
            __atomic_load_n(&flow->packets_hi_to_lo, __ATOMIC_RELAXED) > 0);
}

static inline bool flow_v6_is_established(const struct flow_entry_v6 *flow) {
    return (__atomic_load_n(&flow->state, __ATOMIC_RELAXED) == FLOW_STATE_ESTABLISHED);
}

#endif // LAYER1_FLOW_TABLE_V6_H
