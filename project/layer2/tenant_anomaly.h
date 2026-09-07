/**
 * @file tenant_anomaly.h
 * @brief Per-Tenant Anomaly Detection and Aggregation (Phase 3)
 *
 * Provides tenant-level anomaly aggregation on top of per-IP detection:
 *
 * Architecture:
 *   Per-IP Anomaly Detection (existing Layer 2)
 *       │
 *       ▼
 *   Per-Tenant Aggregation (NEW)
 *       │
 *       ▼
 *   Global System State (existing)
 *
 * Key features:
 * - Aggregates per-IP anomalies into tenant-wide state
 * - Tracks attack timelines per tenant
 * - Provides tenant sensitivity multipliers
 * - Implements callbacks for L3/L4 integration
 * - Supports per-attack-type statistics
 */

#ifndef TENANT_ANOMALY_H
#define TENANT_ANOMALY_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

#include "../common/tenant.h"
#include "../common/tenant_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// ==================== Attack Type Definitions ====================

/**
 * Attack types detected by Layer 2
 */
typedef enum {
    ATTACK_TYPE_NONE = 0,
    ATTACK_TYPE_SYN_FLOOD,          // High SYN rate, low completion
    ATTACK_TYPE_UDP_FLOOD,          // High UDP volume
    ATTACK_TYPE_ICMP_FLOOD,         // High ICMP rate
    ATTACK_TYPE_HTTP_FLOOD,         // High HTTP request rate (L7)
    ATTACK_TYPE_SLOWLORIS,          // Slow HTTP attacks
    ATTACK_TYPE_DNS_AMPLIFICATION,  // DNS amplification
    ATTACK_TYPE_NTP_AMPLIFICATION,  // NTP amplification
    ATTACK_TYPE_MEMCACHED_AMP,      // Memcached amplification
    ATTACK_TYPE_SSDP_AMPLIFICATION, // SSDP amplification
    ATTACK_TYPE_ACK_FLOOD,          // ACK flood
    ATTACK_TYPE_RST_FLOOD,          // RST flood
    ATTACK_TYPE_FRAGMENT_FLOOD,     // IP fragmentation attack
    ATTACK_TYPE_MIXED,              // Multiple attack types
    ATTACK_TYPE_UNKNOWN,            // Anomaly but unknown type
    ATTACK_TYPE_COUNT
} attack_type_t;

/**
 * Attack severity levels (0-5 scale)
 */
typedef enum {
    SEVERITY_NONE = 0,              // No attack
    SEVERITY_LOW = 1,               // Minor anomaly, monitoring
    SEVERITY_MEDIUM = 2,            // Moderate attack, mitigation starting
    SEVERITY_HIGH = 3,              // Significant attack, active mitigation
    SEVERITY_SEVERE = 4,            // Major attack, emergency response
    SEVERITY_CRITICAL = 5,          // Critical attack, all-hands response
} attack_severity_t;

// ==================== Tenant Anomaly State ====================

/**
 * Per-tenant anomaly aggregation state
 * One instance per tenant, updated periodically by Layer 2
 *
 * FIX BUG L2-3: All fields accessed from multiple threads are now atomic
 * This includes the detection thread (writing) and API threads (reading)
 */
struct tenant_anomaly_state {
    tenant_id_t tenant_id;

    // ===== Aggregate State =====
    _Atomic bool     any_ip_anomalous;       // Any protected IP under attack
    _Atomic uint32_t anomalous_ip_count;     // Count of anomalous IPs
    _Atomic uint8_t  max_severity;           // Highest severity across IPs
    _Atomic uint8_t  dominant_attack_type;   // Most common attack type

    // ===== Tenant-Wide Metrics =====
    _Atomic uint64_t total_pps;              // Aggregate PPS across all IPs
    _Atomic uint64_t total_bps;              // Aggregate BPS across all IPs
    // FIX BUG L2-3: Use uint64_t with fixed-point for thread-safe access
    // Stored as value * 1000 (3 decimal places of precision)
    _Atomic uint64_t avg_z_score_fp;         // Average z-score (fixed-point)
    _Atomic uint64_t max_z_score_fp;         // Maximum z-score (fixed-point)

    // ===== Attack Tracking =====
    _Atomic bool     under_attack;           // Tenant currently under attack
    _Atomic uint64_t attack_start_ns;        // When current attack started
    _Atomic uint64_t attack_duration_ns;     // Duration of current/last attack
    _Atomic uint32_t attack_count_24h;       // Attacks in last 24 hours
    _Atomic uint8_t  current_severity;       // Current severity (0-5)

    // ===== Per-Attack-Type Counts (24h rolling window) =====
    _Atomic uint32_t syn_flood_count;
    _Atomic uint32_t udp_flood_count;
    _Atomic uint32_t http_flood_count;
    _Atomic uint32_t amp_attack_count;       // All amplification attacks
    _Atomic uint32_t other_attack_count;

    // ===== Attack Timeline =====
    _Atomic uint64_t last_attack_end_ns;     // When last attack ended
    _Atomic uint64_t time_since_attack_ns;   // Time since last attack

    // ===== Sensitivity Multiplier =====
    // FIX BUG L2-3: Use fixed-point for thread-safe access
    _Atomic uint64_t sensitivity_multiplier_fp; // Fixed-point (value * 1000)
    _Atomic uint64_t effective_z_threshold_fp;  // Fixed-point (value * 1000)

    // ===== Statistics =====
    _Atomic uint64_t total_packets_analyzed;
    _Atomic uint64_t total_anomalies_detected;
    _Atomic uint64_t false_positives;        // User-reported false positives

    // ===== State Tracking =====
    _Atomic uint64_t last_update_ns;
    _Atomic uint64_t state_change_ns;        // When attack state last changed
    _Atomic bool     initialized;
};

// FIX BUG L2-3: Macros for fixed-point conversion (3 decimal places)
#define FP_SCALE 1000
#define DOUBLE_TO_FP(d) ((uint64_t)((d) * FP_SCALE))
#define FP_TO_DOUBLE(fp) ((double)(fp) / FP_SCALE)

// ==================== Attack Event Structure ====================

/**
 * Attack event for callbacks and logging
 */
struct tenant_attack_event {
    tenant_id_t      tenant_id;
    attack_type_t    attack_type;
    attack_severity_t severity;

    // Attack details
    uint32_t         anomalous_ip_count;
    uint64_t         attack_pps;             // Attack traffic PPS
    uint64_t         attack_bps;             // Attack traffic BPS
    double           max_z_score;
    uint32_t         primary_target_ip;      // Most targeted IP (network order)

    // Timing
    uint64_t         start_time_ns;
    uint64_t         duration_ns;
    bool             is_ongoing;             // true if attack still active

    // Classification confidence
    double           confidence;             // 0.0 - 1.0
};

// ==================== Callback Types ====================

/**
 * Callback for attack state changes
 * Called when tenant transitions into or out of attack state
 *
 * @param tenant_id Affected tenant
 * @param severity Current severity (0 = attack ended)
 * @param attack_type Detected attack type
 * @param ctx User-provided context
 */
typedef void (*tenant_attack_callback_t)(tenant_id_t tenant_id,
                                         attack_severity_t severity,
                                         attack_type_t attack_type,
                                         void *ctx);

/**
 * Callback for severity escalation
 * Called when attack severity increases
 */
typedef void (*tenant_escalation_callback_t)(tenant_id_t tenant_id,
                                             attack_severity_t old_severity,
                                             attack_severity_t new_severity,
                                             const struct tenant_attack_event *event,
                                             void *ctx);

// ==================== Initialization ====================

/**
 * Initialize tenant anomaly detection subsystem
 *
 * @return 0 on success, -1 on failure
 */
int tenant_anomaly_init(void);

/**
 * Cleanup tenant anomaly detection subsystem
 */
void tenant_anomaly_cleanup(void);

/**
 * Initialize anomaly state for a specific tenant
 *
 * @param tenant_id Tenant ID
 * @param config Tenant L2 config for sensitivity settings
 * @return 0 on success, -1 on failure
 */
int tenant_anomaly_state_init(tenant_id_t tenant_id,
                              const struct tenant_l2_config *config);

/**
 * Cleanup anomaly state for a tenant
 */
void tenant_anomaly_state_cleanup(tenant_id_t tenant_id);

// ==================== Update API ====================

/**
 * Update tenant anomaly state based on per-IP results
 * Called periodically by Layer 2 detection loop
 *
 * @param tenant_id Tenant ID
 */
void tenant_anomaly_update(tenant_id_t tenant_id);

/**
 * Report per-IP anomaly to tenant aggregation
 * Called when per-IP anomaly is detected
 *
 * @param tenant_id Tenant ID
 * @param dst_ip Protected IP
 * @param z_score Maximum z-score
 * @param anomaly_level Anomaly level
 * @param attack_type Detected attack type
 */
void tenant_anomaly_report_ip(tenant_id_t tenant_id,
                              uint32_t dst_ip,
                              double z_score,
                              uint32_t anomaly_level,
                              attack_type_t attack_type);

/**
 * Clear per-IP anomaly (attack ended for this IP)
 *
 * @param tenant_id Tenant ID
 * @param dst_ip Protected IP
 */
void tenant_anomaly_clear_ip(tenant_id_t tenant_id, uint32_t dst_ip);

// ==================== Query API ====================

/**
 * Get current anomaly state for a tenant
 *
 * @param tenant_id Tenant ID
 * @return Pointer to state (read-only) or NULL if not found
 */
const struct tenant_anomaly_state* tenant_anomaly_get(tenant_id_t tenant_id);

/**
 * Check if tenant is currently under attack
 *
 * @param tenant_id Tenant ID
 * @return true if under attack
 */
bool tenant_anomaly_is_active(tenant_id_t tenant_id);

/**
 * Get current attack severity for tenant
 *
 * @param tenant_id Tenant ID
 * @return Severity level (0 if not under attack)
 */
attack_severity_t tenant_anomaly_get_severity(tenant_id_t tenant_id);

/**
 * Get dominant attack type for tenant
 *
 * @param tenant_id Tenant ID
 * @return Attack type (ATTACK_TYPE_NONE if not under attack)
 */
attack_type_t tenant_anomaly_get_attack_type(tenant_id_t tenant_id);

/**
 * Get current attack event details
 * Only valid if tenant_anomaly_is_active() returns true
 *
 * @param tenant_id Tenant ID
 * @param event Output: attack event details
 * @return 0 on success, -1 if not under attack
 */
int tenant_anomaly_get_event(tenant_id_t tenant_id,
                             struct tenant_attack_event *event);

// ==================== Callback Registration ====================

/**
 * Set callback for attack state changes
 * Called when tenant enters or exits attack state
 *
 * @param cb Callback function
 * @param ctx User context passed to callback
 */
void tenant_anomaly_set_attack_callback(tenant_attack_callback_t cb, void *ctx);

/**
 * Set callback for severity escalation
 * Called when attack severity increases
 *
 * @param cb Callback function
 * @param ctx User context
 */
void tenant_anomaly_set_escalation_callback(tenant_escalation_callback_t cb, void *ctx);

// ==================== Sensitivity Configuration ====================

/**
 * Set sensitivity multiplier for a tenant
 * Lower values = more sensitive (more detections)
 * Higher values = less sensitive (fewer false positives)
 *
 * @param tenant_id Tenant ID
 * @param multiplier Sensitivity multiplier (0.5 - 2.0 typical)
 * @return 0 on success
 */
int tenant_anomaly_set_sensitivity(tenant_id_t tenant_id, double multiplier);

/**
 * Get sensitivity multiplier for a tenant
 *
 * @param tenant_id Tenant ID
 * @return Sensitivity multiplier (1.0 = default)
 */
double tenant_anomaly_get_sensitivity(tenant_id_t tenant_id);

/**
 * Update tenant config (sensitivity, thresholds, etc.)
 *
 * @param tenant_id Tenant ID
 * @param config New L2 config
 * @return 0 on success
 */
int tenant_anomaly_update_config(tenant_id_t tenant_id,
                                 const struct tenant_l2_config *config);

// ==================== Statistics ====================

/**
 * Get attack statistics for tenant
 */
struct tenant_attack_stats {
    tenant_id_t tenant_id;

    // Attack counts (24h window)
    uint32_t total_attacks_24h;
    uint32_t syn_flood_count;
    uint32_t udp_flood_count;
    uint32_t http_flood_count;
    uint32_t amp_attack_count;
    uint32_t other_count;

    // Severity distribution (24h)
    uint32_t low_severity_count;
    uint32_t medium_severity_count;
    uint32_t high_severity_count;
    uint32_t severe_count;
    uint32_t critical_count;

    // Duration stats
    uint64_t total_attack_duration_ns;
    uint64_t avg_attack_duration_ns;
    uint64_t max_attack_duration_ns;

    // Impact
    uint64_t packets_during_attacks;
    uint64_t bytes_during_attacks;

    // Detection quality
    uint32_t false_positives_reported;
    double   estimated_accuracy;
};

int tenant_anomaly_get_stats(tenant_id_t tenant_id,
                             struct tenant_attack_stats *stats);

/**
 * Reset attack statistics for tenant
 */
void tenant_anomaly_reset_stats(tenant_id_t tenant_id);

/**
 * Report false positive (for improving detection)
 *
 * @param tenant_id Tenant ID
 * @param attack_start_ns Start time of false positive
 */
void tenant_anomaly_report_false_positive(tenant_id_t tenant_id,
                                          uint64_t attack_start_ns);

// ==================== Global Operations ====================

/**
 * Get aggregated anomaly state across all tenants
 */
struct global_anomaly_state {
    uint32_t tenants_under_attack;
    uint32_t total_anomalous_ips;
    uint8_t  max_severity_global;
    attack_type_t dominant_attack_type;
    uint64_t global_attack_pps;
    uint64_t global_attack_bps;
};

void tenant_anomaly_get_global_state(struct global_anomaly_state *state);

/**
 * Check if system is in global emergency (many tenants under attack)
 */
bool tenant_anomaly_is_global_emergency(void);

// ==================== Maintenance ====================

/**
 * Periodic maintenance (call every ~100ms)
 * - Updates attack durations
 * - Rolls over 24h window statistics
 * - Cleans up stale state
 */
void tenant_anomaly_maintenance(void);

// ==================== Utility Functions ====================

/**
 * Get attack type name as string
 */
const char* attack_type_to_string(attack_type_t type);

/**
 * Get severity name as string
 */
const char* attack_severity_to_string(attack_severity_t severity);

/**
 * Classify attack type from feature anomalies
 *
 * @param anomalous_features Array of anomalous feature indices
 * @param feature_count Number of anomalous features
 * @param z_scores Z-scores for features
 * @return Detected attack type
 */
attack_type_t classify_attack_type(const int *anomalous_features,
                                   int feature_count,
                                   const double *z_scores);

/**
 * Calculate severity from z-score and impact metrics
 *
 * @param max_z_score Maximum z-score
 * @param anomalous_ip_count Number of IPs affected
 * @param attack_pps Attack traffic PPS
 * @return Severity level
 */
attack_severity_t calculate_severity(double max_z_score,
                                     uint32_t anomalous_ip_count,
                                     uint64_t attack_pps);

#ifdef __cplusplus
}
#endif

#endif // TENANT_ANOMALY_H
