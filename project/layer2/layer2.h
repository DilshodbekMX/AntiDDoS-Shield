#ifndef LAYER2_H
#define LAYER2_H

#include "baselines.h"
#include "detection.h"
#include "config/layer2_config.h"

#include <stdint.h>
#include <stdbool.h>

/**
 * @file layer2.h
 * @brief Layer 2: Behavioral Monitor & Detection Engine
 *
 * Public API for the Layer 2 anomaly detection engine.
 *
 * Layer 2 is the analytical control plane that:
 * 1. LEARNS normal traffic patterns using 3-tier EWMA baselines
 * 2. DETECTS anomalies using multi-tier Z-score analysis
 * 3. TRIGGERS mitigation by setting anomaly_active flag
 * 4. PROTECTS baselines by freezing during attacks
 * 5. ADAPTS to legitimate traffic changes over time
 *
 * Architecture:
 * - Runs at 1 Hz (once per second) on a dedicated thread
 * - Reads features from Layer 1 via shared memory or direct call
 * - Writes anomaly state to shared memory for Layer 1 to read
 * - Persists learned baselines to survive restarts
 *
 * Threading Model:
 * - Main detection loop runs on its own thread (or DPDK lcore)
 * - All public functions are thread-safe
 * - Internal state protected by pthread_mutex
 */

// ==================== Initialization ====================

/**
 * Initialize Layer 2 detection engine
 *
 * @param config_file Path to configuration JSON (NULL for defaults)
 * @return 0 on success, -1 on error
 */
int layer2_init(const char *config_file);

/**
 * Cleanup Layer 2 and free resources
 */
void layer2_cleanup(void);

/**
 * Check if Layer 2 is initialized
 */
bool layer2_is_initialized(void);

// ==================== Thread Control ====================

/**
 * Start Layer 2 detection thread
 *
 * Creates a new thread running at 1 Hz that:
 * 1. Reads current features from Layer 1
 * 2. Runs detection cycle
 * 3. Updates baselines
 * 4. Writes anomaly state to shared memory
 *
 * @return 0 on success, -1 on error
 */
int layer2_start(void);

/**
 * Stop Layer 2 detection thread
 * Blocks until thread exits cleanly
 */
void layer2_stop(void);

/**
 * Check if Layer 2 is running
 */
bool layer2_is_running(void);

/**
 * Layer 2 main loop for DPDK lcore
 *
 * Use this function when running on a dedicated DPDK lcore
 * instead of layer2_start() for pthread-based execution.
 *
 * @param arg Unused (for DPDK compatibility)
 * @return 0 on normal exit
 */
int layer2_lcore_main(void *arg);

// ==================== Feature Input ====================

/**
 * Feature snapshot structure for Layer 2 input (39 features)
 * This matches the l2_features_export structure from Layer 1
 *
 * Categories:
 * - Volume (3): packets/sec, bytes/sec, flows/sec
 * - TCP Flags (5): SYN, SYN-ACK, ACK, RST, FIN rates
 * - Protocol Mix (4): TCP/UDP/ICMP/OTHER ratios
 * - Ratios (3): SYN/ACK, RST/SYN, bytes/packet
 * - Cardinality (3): Unique src IPs, dst ports, flows
 * - Churn (1): Source IP churn rate
 * - Concentration (3): Top flow %, heavy hitters, top-K flow share
 * - Flow Behavior (2): packets/flow, flow duration avg
 * - TCP Flag Ratios (5): SYN/TCP, SYNACK/TCP, ACK/TCP, RST/TCP, FIN/TCP %
 * - Volume Extended (1): burst_factor
 * - Flow Behavior Extended (1): udp_flow_ratio
 * - Protocol Mix Extended (1): icmp_echo_ratio
 * - Cardinality Extended (1): dst_port_density
 * - Entropy (2): src_ip_entropy, src_port_entropy
 * - Packet Characteristics (3): small_pkt_ratio, fragment_ratio, ttl_mean
 * - Ratio Extended (1): tcp_completion_rate
 */
struct layer2_features {
    uint64_t timestamp_ns;

    // ===== VOLUME FEATURES (3) =====
    uint64_t packets_per_sec;
    uint64_t bytes_per_sec;
    uint32_t flows_per_sec;

    // ===== TCP FLAG FEATURES (5) =====
    uint32_t syn_per_sec;
    uint32_t syn_ack_per_sec;
    uint32_t ack_per_sec;
    uint32_t rst_per_sec;
    uint32_t fin_per_sec;

    // ===== PROTOCOL MIX FEATURES (4) =====
    uint8_t  tcp_ratio;             // TCP % (0-100)
    uint8_t  udp_ratio;             // UDP % (0-100)
    uint8_t  icmp_ratio;            // ICMP % (0-100)
    uint8_t  other_ratio;           // Other % (computed: 100 - tcp - udp - icmp)

    // ===== RATIO FEATURES (3) =====
    uint16_t syn_ack_ratio;
    uint16_t rst_syn_ratio;
    uint16_t bytes_per_packet;

    // ===== CARDINALITY FEATURES (3) =====
    uint32_t unique_src_ips;
    uint32_t unique_dst_ports;
    // unique_flows is the HyperLogLog distinct count, within the window, of the same
    // canonical port-less (ip_lo, ip_hi, protocol) flow key on which flows_per_sec
    // (above) counts NEW flow-table entries per second; neither is a 5-tuple count.
    uint32_t unique_flows;

    // ===== CHURN FEATURES (1) =====
    int32_t  new_srcip_rate;

    // ===== CONCENTRATION FEATURES (3) =====
    uint8_t  max_flow_fraction;
    uint8_t  topk_flow_share;
    uint16_t heavy_hitter_count;

    // ===== FLOW BEHAVIOR FEATURES (2) =====
    uint16_t avg_packets_per_flow;
    uint32_t flow_duration_avg_ms;

    // ===== TCP FLAG RATIO FEATURES (5) =====
    uint8_t  syn_tcp_ratio;         // SYN as % of TCP packets (0-100)
    uint8_t  synack_tcp_ratio;      // SYN-ACK as % of TCP packets (0-100)
    uint8_t  ack_tcp_ratio;         // ACK as % of TCP packets (0-100)
    uint8_t  rst_tcp_ratio;         // RST as % of TCP packets (0-100)
    uint8_t  fin_tcp_ratio;         // FIN as % of TCP packets (0-100)

    // ===== VOLUME EXTENDED (1) =====
    // 100 * window_pps / post-update EWMA (alpha = BURST_EWMA_ALPHA = 0.033, burst_ewma.h):
    // because the divisor already contains alpha * window_pps the ratio saturates at
    // 100/alpha = 3030. Global EWMA on the aggregate path, one EWMA per protected IP on
    // the per-IP path (Phase 2).
    uint16_t burst_factor;          // Current PPS / EWMA PPS * 100 (100=normal)

    // ===== FLOW BEHAVIOR EXTENDED (1) =====
    uint16_t udp_flow_ratio;        // UDP flows / UDP PPS * 100

    // ===== PROTOCOL MIX EXTENDED (1) =====
    uint8_t  icmp_echo_ratio;       // ICMP echo / ICMP total * 100

    // ===== CARDINALITY EXTENDED (1) =====
    uint16_t dst_port_density;      // Unique dst ports / PPS * 1000

    // ===== ENTROPY FEATURES (2) =====
    uint8_t  src_ip_entropy;        // Source IP entropy (0-255 scaled from 0-8 bits)
    uint8_t  src_port_entropy;      // Source port entropy (0-255 scaled from 0-8 bits)

    // ===== PACKET CHARACTERISTICS (3) =====
    uint8_t  small_pkt_ratio;       // Packets <= 64B as % of total
    uint8_t  fragment_ratio;        // Fragment packets as % of total
    uint8_t  ttl_mean;              // Mean IP TTL value

    // ===== RATIO EXTENDED (1) =====
    uint8_t  tcp_completion_rate;   // SYN-ACK / SYN * 100

    // ===== METADATA =====
    uint32_t active_flows;
};

/**
 * Set feature input callback
 *
 * By default, Layer 2 reads from shared memory.
 * Use this to provide features via callback instead.
 *
 * @param callback Function that fills layer2_features struct
 */
typedef void (*layer2_feature_callback_t)(struct layer2_features *features);
void layer2_set_feature_callback(layer2_feature_callback_t callback);

// ==================== Status Queries ====================

/**
 * Get current anomaly state
 */
void layer2_get_anomaly_state(struct l2_anomaly_state *state);

/**
 * Check if anomaly is currently active
 */
bool layer2_is_anomaly_active(void);

/**
 * Get current anomaly level
 */
enum l2_anomaly_level layer2_get_anomaly_level(void);

/**
 * Get baseline summary
 */
void layer2_get_baseline_summary(struct baseline_summary *summary);

/**
 * Get detection statistics
 */
struct layer2_stats {
    uint64_t cycles;                // Total detection cycles
    uint64_t detections;            // Total anomalies detected
    uint64_t false_positive_corrections; // Cool-down prevented triggers
    uint64_t baseline_updates;      // Total baseline updates
    double uptime_sec;              // Time since start
};
void layer2_get_stats(struct layer2_stats *stats);

// ==================== Configuration ====================

/**
 * Get current configuration
 */
const struct layer2_config *layer2_get_config(void);

/**
 * Reload configuration from file
 * @return 0 on success, -1 on error
 */
int layer2_reload_config(void);

/**
 * MF6 FIX: Reload feature weights from current config
 * Call after layer2_reload_config() to apply weight changes
 * @return 0 on success, -1 on error
 */
int layer2_reload_weights(void);

/**
 * Update configuration value at runtime
 * @param key Configuration key (e.g., "z_score_threshold")
 * @param value New value as string
 * @return 0 on success, -1 on invalid key/value
 */
int layer2_set_config(const char *key, const char *value);

// ==================== Baseline Management ====================

/**
 * Save baselines to file
 * @return 0 on success, -1 on error
 */
int layer2_save_baselines(void);

/**
 * Load baselines from file
 * @return 0 on success, -1 if file doesn't exist or parse error
 */
int layer2_load_baselines(void);

/**
 * Reset all baselines to initial state
 * Warning: This clears all learned patterns!
 */
void layer2_reset_baselines(void);

// ==================== Manual Control ====================

/**
 * Force anomaly level (for testing or manual override)
 * @param level Level to force (use L2_ANOMALY_NONE to clear)
 */
void layer2_force_anomaly(enum l2_anomaly_level level);

/**
 * Clear current anomaly (manual reset)
 */
void layer2_clear_anomaly(void);

/**
 * Freeze baselines (prevent updates)
 */
void layer2_freeze_baselines(void);

/**
 * Unfreeze baselines (allow updates)
 */
void layer2_unfreeze_baselines(void);

/**
 * Reload per-IP feature weights from data/per_ip_l2_config.json.
 * Called on CMD_L2_RELOAD_PER_IP_CONFIG.
 */
void layer2_load_per_ip_feature_weights(void);

// ==================== Logging ====================

/**
 * Print current status to stdout
 */
void layer2_print_status(void);

/**
 * Set log level
 * @param level 0=errors only, 1=warnings, 2=info, 3=debug
 */
void layer2_set_log_level(int level);

// ==================== Per-IP Detection API ====================

/**
 * Per-IP feature snapshot structure
 * Same as layer2_features but includes dst_ip identifier
 */
struct layer2_per_ip_features {
    uint32_t dst_ip;                    // Protected IP (network byte order)
    bool active;                        // True if slot has valid data
    struct layer2_features features;    // Feature data for this IP
};

/**
 * Register a protected IP for per-IP detection
 * Creates baseline tracking for this IP
 *
 * @param dst_ip Protected IP (network byte order)
 * @return 0 on success, -1 on error
 */
int layer2_register_protected_ip(uint32_t dst_ip);

/**
 * Unregister a protected IP
 *
 * @param dst_ip Protected IP (network byte order)
 * @return 0 on success, -1 if not found
 */
int layer2_unregister_protected_ip(uint32_t dst_ip);

/**
 * Get anomaly state for a specific protected IP
 *
 * @param dst_ip Protected IP (network byte order)
 * @param state Output: anomaly state
 * @return 0 on success, -1 if IP not found
 */
int layer2_get_per_ip_anomaly_state(uint32_t dst_ip, struct l2_anomaly_state *state);

/**
 * Check if anomaly is active for a specific protected IP
 *
 * @param dst_ip Protected IP (network byte order)
 * @return true if anomaly is active for this IP
 */
bool layer2_is_per_ip_anomaly_active(uint32_t dst_ip);

/**
 * Get anomaly level for a specific protected IP
 *
 * @param dst_ip Protected IP (network byte order)
 * @return L2_ANOMALY_* level
 */
enum l2_anomaly_level layer2_get_per_ip_anomaly_level(uint32_t dst_ip);

/**
 * Get count of registered protected IPs
 */
uint32_t layer2_get_protected_ip_count(void);

/**
 * Get list of all protected IPs with their anomaly states
 *
 * @param out Output array of per-IP anomaly results
 * @param max_count Maximum number of results to return
 * @return Number of results returned
 */
uint32_t layer2_get_all_per_ip_anomaly_states(struct per_ip_anomaly_result *out,
                                              uint32_t max_count);

/**
 * Force anomaly level for a specific protected IP (for testing)
 *
 * @param dst_ip Protected IP (network byte order)
 * @param level L2_ANOMALY_* level
 */
void layer2_force_per_ip_anomaly(uint32_t dst_ip, enum l2_anomaly_level level);

/**
 * Clear anomaly for a specific protected IP
 *
 * @param dst_ip Protected IP (network byte order)
 */
void layer2_clear_per_ip_anomaly(uint32_t dst_ip);

/**
 * Freeze baselines for a specific protected IP
 *
 * @param dst_ip Protected IP (network byte order)
 */
void layer2_freeze_per_ip_baselines(uint32_t dst_ip);

/**
 * Unfreeze baselines for a specific protected IP
 *
 * @param dst_ip Protected IP (network byte order)
 */
void layer2_unfreeze_per_ip_baselines(uint32_t dst_ip);

/**
 * Save per-IP baselines to file
 *
 * @return 0 on success, -1 on error
 */
int layer2_save_per_ip_baselines(void);

/**
 * Load per-IP baselines from file
 *
 * @return 0 on success, -1 on error
 */
int layer2_load_per_ip_baselines(void);

/**
 * Reset per-IP baselines for all protected IPs
 */
void layer2_reset_per_ip_baselines(void);

#endif // LAYER2_H
