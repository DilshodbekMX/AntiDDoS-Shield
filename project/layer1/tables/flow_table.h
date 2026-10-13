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
 * - flow_table_lookup_or_create(): Safe from multiple lcores (RW_CONCURRENCY)
 * - flow_table_update(): Safe with atomic counters
 * - flow_table_age_flows(): Should run from single maintenance thread
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
    FLOW_STATE_INITIALIZING,     // Entry being initialized (transient state)
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
    uint8_t  _pad1[3];

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
    uint32_t max_flows;            // Maximum concurrent flows
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
 * Lookup existing flow with precomputed hash (avoids double hashing).
 * Use when you already computed the flow hash.
 *
 * @param key       Flow key (canonical)
 * @param hash      Precomputed hash value
 * @return Flow entry pointer, or NULL if not found
 */
struct flow_entry* flow_table_lookup_with_hash(const struct flow_key *key,
                                                uint32_t hash);

/**
 * Update flow counters and state.
 * Thread-safe using atomic operations.
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
 * @param count_needed  Number of flow slots needed
 * @return Number of flows evicted
 */
uint32_t flow_table_emergency_evict(uint32_t count_needed);

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

// ==================== RST/FIN Validation ====================

/**
 * Validate RST or FIN packet against flow state.
 * Checks that the sequence number is within the expected window.
 * This prevents spoofed RST/FIN attacks that try to tear down connections.
 *
 * @param features  Packet features (must be RST or FIN packet)
 * @return RST_FIN_VALID if packet is valid, error code otherwise
 */
enum rst_fin_validation_result flow_table_validate_rst_fin(
    struct packet_features *features);

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
        "LAST_ACK", "TIME_WAIT", "CLOSED", "RST"
    };
    return (state < FLOW_STATE_MAX) ? names[state] : "UNKNOWN";
}

#endif // LAYER1_FLOW_TABLE_H