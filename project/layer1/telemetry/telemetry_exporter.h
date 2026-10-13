#ifndef LAYER1_TELEMETRY_EXPORTER_H
#define LAYER1_TELEMETRY_EXPORTER_H

#include "types.h"
#include <stdint.h>
#include <stdbool.h>

/**
 * @file telemetry_exporter.h
 * @brief Stage 11: SQLite Telemetry Exporter
 *
 * Exports flow records, statistics, and attack events to SQLite database
 * for analysis by Layer 3/4/5 and monitoring dashboards.
 *
 * Features:
 * - Attack events: Always recorded (drops, SYN floods, etc.)
 * - Flow records: Configurable sampling rate (1:1 to 1:N)
 * - Runs in separate thread to avoid blocking fast path
 */

// ==================== Configuration ====================

struct telemetry_config {
    const char *db_path;            // Path to SQLite database file
    uint32_t export_interval_sec;   // How often to export (e.g., 5 seconds)
    uint32_t max_flow_records;      // Max flow records in ring buffer
    bool export_packet_samples;     // Export individual packet samples
    
    // Sampling configuration
    uint32_t flow_sample_rate;      // 1 = all flows, 100 = 1 in 100, 0 = disabled
    bool     events_enabled;        // Enable attack event recording
};

// ==================== Flow Record ====================

/**
 * Flow record for export to database
 */
struct flow_record {
    // Flow identification
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  direction;             // DIRECTION_INBOUND or DIRECTION_OUTBOUND
    uint8_t  _pad1[2];

    // Flow statistics
    uint64_t first_seen_ns;         // Timestamp of first packet
    uint64_t last_seen_ns;          // Timestamp of last packet
    uint64_t packet_count;          // Total packets
    uint64_t byte_count;            // Total bytes

    // TCP-specific
    uint8_t  tcp_flags_seen;        // OR of all TCP flags seen
    uint8_t  tcp_state;             // Final TCP state
    uint16_t _pad2;

    // Flow characteristics
    uint16_t avg_packet_size;       // Average packet size
    uint16_t max_packet_size;       // Maximum packet size
    uint32_t avg_inter_arrival_us;  // Average inter-arrival time

    // Derived features
    uint8_t  avg_payload_entropy;   // Average payload entropy
    uint8_t  avg_header_entropy;    // Average header entropy
    uint8_t  retransmit_count;      // Number of retransmissions
    uint8_t  out_of_order_count;    // Number of out-of-order packets

    // Drop reasons
    uint8_t  dropped;               // 1 if flow was dropped
    uint8_t  drop_reason;           // Reason code
    uint16_t _pad3;
} __attribute__((aligned(64)));

// ==================== Attack Event ====================

/**
 * Attack event for export
 */
struct attack_event {
    uint64_t timestamp_ns;          // Event timestamp
    uint8_t  event_type;            // Event type (SYN_FLOOD, RATE_LIMIT, etc.)
    uint8_t  severity;              // Severity (0-100)
    uint8_t  direction;             // DIRECTION_INBOUND or DIRECTION_OUTBOUND
    uint8_t  _pad1;

    uint32_t src_ip;                // Source IP involved
    uint32_t dst_ip;                // Destination IP
    uint16_t src_port;              // Source port
    uint16_t dst_port;              // Destination port
    uint8_t  protocol;              // Protocol
    uint8_t  drop_reason;           // Drop reason code
    uint16_t _pad2;

    uint64_t packet_count;          // Packets involved in attack
    uint64_t byte_count;            // Bytes involved

    char description[128];          // Human-readable description
};

// Event types
#define EVENT_SYN_FLOOD            1
#define EVENT_RATE_LIMIT_EXCEEDED  2
#define EVENT_CONNECTION_LIMIT     3
#define EVENT_INVALID_PACKET       4
#define EVENT_REPUTATION_DROP      5
#define EVENT_POLICY_DROP          6
#define EVENT_BLACKLIST_DROP       7
#define EVENT_VALIDATION_DROP      8
#define EVENT_PROXY_ERROR          9
#define EVENT_COOKIE_INVALID       10
#define EVENT_GEO_BLOCKED          11
#define EVENT_SIGNATURE_MATCH      12
#define EVENT_OTHER_PROTO_DROP     13
#define EVENT_TCP_ABUSE            14
#define EVENT_PROTO_BLOCKED        15
#define EVENT_PROTO_RATE_LIMITED   16

// Severity levels
#define SEVERITY_LOW      25
#define SEVERITY_MEDIUM   50
#define SEVERITY_HIGH     75
#define SEVERITY_CRITICAL 100

// ==================== Public API ====================

/**
 * Initialize telemetry exporter
 *
 * @param config  Configuration parameters
 * @return 0 on success, -1 on error
 */
int telemetry_init(const struct telemetry_config *config);

/**
 * Cleanup telemetry exporter
 */
void telemetry_cleanup(void);

/**
 * Check if telemetry is initialized
 */
bool telemetry_is_initialized(void);

/**
 * Record a flow for export (subject to sampling)
 *
 * Applies configured sampling rate.
 * If sample_rate=100, only 1 in 100 calls actually records.
 *
 * @param record  Flow record to export
 */
void telemetry_record_flow(const struct flow_record *record);

/**
 * Record a flow unconditionally (bypasses sampling)
 *
 * Use for important flows you always want to capture.
 *
 * @param record  Flow record to export
 */
void telemetry_record_flow_force(const struct flow_record *record);

/**
 * Record an attack event (always recorded, no sampling)
 *
 * @param event  Attack event to export
 */
void telemetry_record_attack(const struct attack_event *event);

/**
 * Export aggregated statistics
 */
void telemetry_export_stats(void);

// ==================== Runtime Configuration ====================

/**
 * Set flow sampling rate at runtime
 *
 * @param rate  1 = all flows, 100 = 1 in 100, 0 = disable flow recording
 */
void telemetry_set_flow_sample_rate(uint32_t rate);

/**
 * Get current flow sampling rate
 *
 * @return Current sampling rate
 */
uint32_t telemetry_get_flow_sample_rate(void);

/**
 * Enable/disable attack event recording
 *
 * @param enable  true to enable, false to disable
 */
void telemetry_set_events_enabled(bool enable);

/**
 * Check if events are enabled
 */
bool telemetry_get_events_enabled(void);

// ==================== Statistics ====================

/**
 * Get telemetry statistics
 *
 * @param flows_exported      Output: total flows exported
 * @param flows_sampled       Output: total flows sampled (before export)
 * @param flows_skipped       Output: total flows skipped due to sampling
 * @param events_exported     Output: total events exported
 * @param export_errors       Output: export errors
 * @param alloc_failures      Output: memory allocation failures
 */
void telemetry_get_stats(uint64_t *flows_exported,
                         uint64_t *flows_sampled,
                         uint64_t *flows_skipped,
                         uint64_t *events_exported,
                         uint64_t *export_errors,
                         uint64_t *alloc_failures);

/**
 * Print telemetry statistics
 */
void telemetry_print_stats(void);

#endif // LAYER1_TELEMETRY_EXPORTER_H