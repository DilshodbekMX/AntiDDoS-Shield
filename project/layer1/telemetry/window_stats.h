#ifndef LAYER1_WINDOW_STATS_H
#define LAYER1_WINDOW_STATS_H

/**
 * @file window_stats.h
 * @brief Multi-window sliding statistics for Layer 2 anomaly detection
 *
 * Provides 1-second, 10-second, and 60-second rolling window statistics.
 * All windows are updated atomically and accessible via shared memory.
 *
 * Design:
 * - Ring buffer of 1-second samples (60 entries for 60s history)
 * - Each sample contains complete stats snapshot
 * - 10s and 60s stats computed by summing appropriate samples
 * - Lock-free updates using per-lcore counters + periodic aggregation
 *
 * Memory layout in shared memory:
 *   [Header][Current 1s counters][60x 1s samples][Aggregated windows]
 */

#include <stdint.h>
#include <stdbool.h>
#include <rte_atomic.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==================== Constants ====================

#define WINDOW_SHM_PATH        "/dev/shm/antiddos_windows"
#define WINDOW_SHM_MAGIC       0x57494E444F575331ULL  // "WINDOWS1"
#define WINDOW_SHM_VERSION     1

#define WINDOW_1S              1
#define WINDOW_10S             10
#define WINDOW_60S             60

#define SAMPLE_RING_SIZE       60    // 60 seconds of history
#define WS_MAX_LCORES          64

// ==================== Statistics Structures ====================

/**
 * Core packet counters for a time window
 * These are the metrics Layer 2 needs for anomaly detection
 */
struct window_counters {
    // Volume metrics
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t packets_accepted;
    uint64_t packets_dropped;

    // Direction
    uint64_t inbound_packets;
    uint64_t inbound_bytes;
    uint64_t outbound_packets;
    uint64_t outbound_bytes;

    // Protocol breakdown
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_proto_packets;

    // TCP flags (critical for SYN flood detection)
    uint64_t syn_packets;
    uint64_t syn_ack_packets;
    uint64_t ack_packets;
    uint64_t rst_packets;
    uint64_t fin_packets;
    uint64_t psh_packets;

    // Drop reasons
    uint64_t drop_validation;
    uint64_t drop_blacklist;
    uint64_t drop_rate_limit;
    uint64_t drop_syn_flood;
    uint64_t drop_reputation;
    uint64_t drop_policy;

    // SYN proxy
    uint64_t syn_proxy_challenges;
    uint64_t syn_proxy_established;
    uint64_t cookies_sent;
    uint64_t cookies_valid;
    uint64_t cookies_invalid;

    // Flow metrics
    uint64_t new_flows;
    uint64_t aged_flows;
    uint64_t active_flows;      // Snapshot, not cumulative

    // Cardinality estimates (from HyperLogLog)
    uint64_t unique_src_ips;    // Snapshot
    uint64_t unique_dst_ports;  // Snapshot

    // Packet size distribution buckets
    uint64_t pkt_size_0_64;     // Tiny packets (often attacks)
    uint64_t pkt_size_65_128;
    uint64_t pkt_size_129_256;
    uint64_t pkt_size_257_512;
    uint64_t pkt_size_513_1024;
    uint64_t pkt_size_1025_1518;
    uint64_t pkt_size_jumbo;    // >1518

    uint64_t _pad[5];           // Pad to 512 bytes
} __attribute__((aligned(64)));

/**
 * A single 1-second sample with timestamp
 */
struct window_sample {
    uint64_t timestamp_sec;     // Unix timestamp when sample was taken
    uint64_t timestamp_tsc;     // TSC when sample was taken
    struct window_counters counters;
} __attribute__((aligned(64)));

/**
 * Computed rates for a window (derived metrics)
 */
struct window_rates {
    // Packets per second
    double pps_total;
    double pps_inbound;
    double pps_outbound;
    double pps_tcp;
    double pps_udp;
    double pps_syn;
    double pps_dropped;

    // Bytes per second
    double bps_total;
    double bps_inbound;
    double bps_outbound;

    // Ratios (useful for anomaly detection)
    double syn_to_synack_ratio;     // High = potential SYN flood
    double syn_to_ack_ratio;        // Handshake completion rate
    double rst_ratio;               // RST packets / total
    double small_pkt_ratio;         // <64 bytes / total
    double drop_ratio;              // Dropped / total
    double new_flow_rate;           // New flows per second

    // Multi-window characterization (paper section 4.1.3): pulsing vs ramping signals.
    // Computed over the per-second pps series in the window's ring-buffer samples.
    double pps_variance;            // 10s pulsing signal: variance of per-second pps in window
    double pps_trend_slope;         // 60s ramping signal: least-squares slope (pps/sec)
} __attribute__((aligned(64)));

/**
 * Complete window statistics (counters + rates)
 */
struct window_stats {
    uint32_t window_seconds;    // 1, 10, or 60
    uint32_t samples_used;      // How many 1s samples contributed
    uint64_t start_timestamp;   // Start of window (Unix time)
    uint64_t end_timestamp;     // End of window (Unix time)

    struct window_counters counters;    // Summed counters
    struct window_rates rates;          // Computed rates

    uint64_t _pad[4];
} __attribute__((aligned(64)));

/**
 * Per-lcore accumulator (no locks, each lcore writes to its own)
 */
struct lcore_window_accum {
    struct window_counters counters;
} __attribute__((aligned(64)));

/**
 * Shared memory header
 */
struct window_shm_header {
    uint64_t magic;
    uint32_t version;
    uint32_t num_lcores;
    uint64_t tsc_hz;
    uint64_t creation_time;

    // Current sample index in ring buffer
    uint32_t current_sample_idx;
    uint32_t samples_valid;         // How many samples have been written

    // Sequence number for consistent reads
    uint64_t update_sequence;

    // Offsets
    uint64_t lcore_accum_offset;    // Per-lcore accumulators
    uint64_t sample_ring_offset;    // Ring of 60 1-second samples
    uint64_t window_1s_offset;      // Computed 1s stats
    uint64_t window_10s_offset;     // Computed 10s stats
    uint64_t window_60s_offset;     // Computed 60s stats

    uint64_t _pad[4];
} __attribute__((aligned(64)));

// ==================== API ====================

/**
 * Initialize window statistics shared memory
 * Creates /dev/shm/antiddos_windows
 */
int window_stats_init(void);

/**
 * Cleanup
 */
void window_stats_cleanup(void);

/**
 * Update counters from fast path (called per packet)
 * Extremely low overhead - just increments per-lcore counters
 *
 * @param pkt_size      Packet size in bytes
 * @param protocol      IP protocol (IPPROTO_TCP, etc.)
 * @param tcp_flags     TCP flags if TCP, 0 otherwise
 * @param direction     0=inbound, 1=outbound
 * @param accepted      true if packet was accepted
 * @param drop_reason   Drop reason if not accepted
 */
void window_stats_update_packet(uint16_t pkt_size,
                                 uint8_t protocol,
                                 uint8_t tcp_flags,
                                 uint8_t direction,
                                 bool accepted,
                                 uint8_t drop_reason);

/**
 * Update SYN proxy counters
 */
void window_stats_update_syn_proxy(bool challenge_sent,
                                    bool established,
                                    bool cookie_valid,
                                    bool cookie_invalid);

/**
 * Update flow counters
 */
void window_stats_update_flow(bool new_flow, bool aged_flow);

/**
 * Set current cardinality estimates (called periodically)
 */
void window_stats_set_cardinality(uint64_t unique_src_ips,
                                   uint64_t unique_dst_ports,
                                   uint64_t active_flows);

/**
 * Tick function - called once per second from timer
 * Aggregates per-lcore counters, stores sample, computes windows
 */
void window_stats_tick(void);

/**
 * Get computed window statistics
 * @param window_sec    1, 10, or 60
 * @param stats         Output structure
 * @return 0 on success
 */
int window_stats_get(uint32_t window_sec, struct window_stats *stats);

/**
 * Get pointer to shared memory for direct access
 */
void *window_stats_get_shm(void);

/**
 * Get shared memory size
 */
size_t window_stats_get_shm_size(void);

#ifdef __cplusplus
}
#endif

#endif // LAYER1_WINDOW_STATS_H
