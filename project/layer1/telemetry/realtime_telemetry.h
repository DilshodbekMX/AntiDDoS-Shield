#ifndef LAYER1_REALTIME_TELEMETRY_H
#define LAYER1_REALTIME_TELEMETRY_H

/**
 * @file realtime_telemetry.h
 * @brief Zero-copy shared memory telemetry for Layer 2 integration
 *
 * This provides LINE-RATE telemetry export via shared memory (mmap).
 * Layer 2 (Python) can read stats directly without any IPC overhead.
 *
 * Features:
 * - Zero-copy: Layer 2 reads directly from shared memory
 * - Lock-free: Uses atomic counters and sequence numbers
 * - Real-time: Sub-microsecond latency
 * - Cache-aligned: Optimized for multi-core access
 *
 * Usage from Python:
 *   import mmap, struct, ctypes
 *   fd = os.open('/dev/shm/antiddos_realtime', os.O_RDONLY)
 *   mm = mmap.mmap(fd, TELEMETRY_SHM_SIZE, access=mmap.ACCESS_READ)
 *   # Read header, then stats structures
 */

#include <stdint.h>
#include <stdbool.h>
#include <rte_atomic.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==================== Shared Memory Layout ====================

#define REALTIME_SHM_PATH      "/dev/shm/antiddos_realtime"
#define REALTIME_SHM_MAGIC     0x414E544944444F53ULL  // "ANTIDDOS"
#define REALTIME_SHM_VERSION   1

// Ring buffer sizes (must be power of 2)
#define EVENT_RING_SIZE        4096
#define FLOW_RING_SIZE         8192

// Maximum lcores supported
#define RT_MAX_LCORES          64

/**
 * Global statistics - updated atomically by lcores
 * Cache-line aligned to prevent false sharing
 */
struct rt_global_stats {
    // Packet counters
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t packets_accepted;
    uint64_t packets_dropped;

    // Direction breakdown
    uint64_t inbound_packets;
    uint64_t inbound_bytes;
    uint64_t outbound_packets;
    uint64_t outbound_bytes;

    // Drop reasons
    uint64_t drop_validation;
    uint64_t drop_blacklist;
    uint64_t drop_rate_limit;
    uint64_t drop_syn_flood;
    uint64_t drop_reputation;
    uint64_t drop_policy;

    // Protocol breakdown
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_packets;

    // TCP flags
    uint64_t syn_packets;
    uint64_t syn_ack_packets;
    uint64_t ack_packets;
    uint64_t rst_packets;
    uint64_t fin_packets;

    // Flow stats
    uint64_t active_flows;
    uint64_t total_flows_created;
    uint64_t flows_aged;

    // SYN proxy stats
    uint64_t syn_proxy_challenges;
    uint64_t syn_proxy_established;
    uint64_t syn_proxy_active;
    uint64_t cookies_sent;
    uint64_t cookies_valid;
    uint64_t cookies_invalid;

    // Rate limiting
    uint64_t rate_limit_triggers;

    // Cardinality (HLL estimates)
    uint64_t unique_src_ips;
    uint64_t unique_dst_ports;
    uint64_t unique_flows;

    // Timestamps
    uint64_t last_update_tsc;
    uint64_t tsc_hz;

    uint64_t _pad[4];  // Pad to cache line
} __attribute__((aligned(64)));

/**
 * Per-lcore statistics - each lcore writes to its own slot
 * Readers sum all slots for totals
 */
struct rt_lcore_stats {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t dropped;

    uint64_t l1_accepted;
    uint64_t l1_dropped;

    // Per-protocol
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t syn_packets;

    uint64_t _pad[7];  // Pad to cache line
} __attribute__((aligned(64)));

/**
 * Compact event record for the ring buffer
 * Fixed 64 bytes for easy indexing
 */
struct rt_event {
    uint64_t timestamp_ns;      // Nanoseconds since epoch
    uint32_t src_ip;            // Network byte order
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  event_type;        // RT_EVENT_*
    uint8_t  severity;          // 0-255
    uint8_t  drop_reason;
    uint32_t value1;            // Event-specific (e.g., packet count)
    uint32_t value2;            // Event-specific (e.g., byte count)
    uint64_t _pad[3];           // Pad to 64 bytes
} __attribute__((aligned(64)));

// Event types
#define RT_EVENT_DROP           1   // Packet dropped
#define RT_EVENT_RATE_LIMIT     2   // Rate limit triggered
#define RT_EVENT_SYN_FLOOD      3   // SYN flood detected
#define RT_EVENT_BLACKLIST      4   // Blacklist hit
#define RT_EVENT_CONN_LIMIT     5   // Connection limit hit
#define RT_EVENT_INVALID_COOKIE 6   // Invalid SYN cookie
#define RT_EVENT_MODE_SWITCH    7   // SYN proxy mode switch

/**
 * Compact flow summary for the ring buffer
 * Fixed 128 bytes
 */
struct rt_flow_summary {
    uint64_t timestamp_ns;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  direction;
    uint8_t  tcp_state;
    uint8_t  dropped;

    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
    uint64_t packet_count;
    uint64_t byte_count;

    uint32_t avg_pkt_size;
    uint32_t max_pkt_size;
    uint32_t avg_iat_us;        // Inter-arrival time microseconds
    uint16_t tcp_flags_seen;
    uint8_t  drop_reason;
    uint8_t  _pad1;

    uint64_t _pad2[6];          // Pad to 128 bytes
} __attribute__((aligned(128)));

/**
 * Lock-free ring buffer header
 * Uses sequence numbers for wait-free reads
 */
struct rt_ring_header {
    uint64_t write_idx;         // Next write position (atomic)
    uint64_t _pad1[7];          // Separate cache line
    uint64_t size;              // Ring size (power of 2)
    uint64_t mask;              // size - 1 for fast modulo
    uint64_t element_size;      // Size of each element
    uint64_t _pad2[5];
} __attribute__((aligned(64)));

/**
 * Main shared memory header
 */
struct rt_shm_header {
    uint64_t magic;             // REALTIME_SHM_MAGIC
    uint32_t version;           // REALTIME_SHM_VERSION
    uint32_t num_lcores;        // Number of active lcores
    uint64_t creation_time;     // Unix timestamp
    uint64_t total_size;        // Total shared memory size

    // Offsets to sections (from start of shm)
    uint64_t global_stats_offset;
    uint64_t lcore_stats_offset;
    uint64_t event_ring_offset;
    uint64_t flow_ring_offset;

    // Sequence number for consistent reads
    uint64_t update_sequence;   // Incremented on each batch update

    uint64_t _pad[4];
} __attribute__((aligned(64)));

// ==================== API ====================

/**
 * Initialize real-time telemetry shared memory
 * Creates /dev/shm/antiddos_realtime
 *
 * @return 0 on success, -1 on error
 */
int realtime_telemetry_init(void);

/**
 * Cleanup shared memory
 */
void realtime_telemetry_cleanup(void);

/**
 * Update global stats from Layer 1 aggregated stats
 * Called periodically (e.g., every 100ms) from main thread
 */
void realtime_telemetry_update_global(const struct rt_global_stats *stats);

/**
 * Update per-lcore stats
 * Called from each lcore's processing loop (very low overhead)
 */
void realtime_telemetry_update_lcore(unsigned int lcore_id,
                                      const struct rt_lcore_stats *stats);

/**
 * Record an event to the ring buffer
 * Lock-free, safe to call from any lcore
 */
void realtime_telemetry_record_event(const struct rt_event *event);

/**
 * Record a flow summary to the ring buffer
 * Typically called on flow aging/completion
 */
void realtime_telemetry_record_flow(const struct rt_flow_summary *flow);

/**
 * Get pointer to shared memory for direct access
 * Returns NULL if not initialized
 */
void *realtime_telemetry_get_shm(void);

/**
 * Get total shared memory size
 */
size_t realtime_telemetry_get_shm_size(void);

#ifdef __cplusplus
}
#endif

#endif // LAYER1_REALTIME_TELEMETRY_H
