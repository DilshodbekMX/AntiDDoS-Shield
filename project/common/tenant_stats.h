/**
 * @file tenant_stats.h
 * @brief Per-Tenant Statistics Collection (Phase 7.1)
 *
 * Comprehensive, isolated statistics for each tenant:
 * - Traffic metrics (pps, bps, packets in/out)
 * - Security metrics (drops, attacks, mitigations)
 * - Layer-specific metrics (L1-L5)
 * - SLA metrics (availability, effectiveness)
 *
 * Design:
 * - Per-lcore counters for lock-free updates
 * - Periodic aggregation to global stats
 * - Historical storage with configurable retention
 * - Prometheus-compatible export format
 */

#ifndef TENANT_STATS_H
#define TENANT_STATS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include "tenant.h"

#ifdef __cplusplus
extern "C" {
#endif

// ==================== Constants ====================

#define MAX_DROP_REASONS        32
#define MAX_ATTACK_TYPES        16
#define STATS_HISTORY_SLOTS     1440    // 24 hours at 1-minute resolution
#define STATS_AGGREGATION_INTERVAL_MS 1000  // 1 second

// Drop reason codes
typedef enum {
    DROP_REASON_NONE = 0,
    DROP_REASON_RATE_LIMIT,
    DROP_REASON_BLACKLIST,
    DROP_REASON_SYN_PROXY_FAIL,
    DROP_REASON_INVALID_PACKET,
    DROP_REASON_GEO_BLOCK,
    DROP_REASON_POLICY,
    DROP_REASON_SIGNATURE,
    DROP_REASON_ML_BLOCK,
    DROP_REASON_REPUTATION,
    DROP_REASON_BOT_DETECTION,
    DROP_REASON_CHALLENGE_FAIL,
    DROP_REASON_QUOTA_EXCEEDED,
    DROP_REASON_MALFORMED,
    DROP_REASON_TTL_EXPIRED,
    DROP_REASON_FRAGMENT,
    DROP_REASON_OTHER,
    DROP_REASON_MAX
} drop_reason_t;

// Attack type codes
typedef enum {
    ATTACK_TYPE_NONE = 0,
    ATTACK_TYPE_SYN_FLOOD,
    ATTACK_TYPE_UDP_FLOOD,
    ATTACK_TYPE_ICMP_FLOOD,
    ATTACK_TYPE_DNS_AMPLIFICATION,
    ATTACK_TYPE_NTP_AMPLIFICATION,
    ATTACK_TYPE_SSDP_AMPLIFICATION,
    ATTACK_TYPE_HTTP_FLOOD,
    ATTACK_TYPE_SLOWLORIS,
    ATTACK_TYPE_SLOW_POST,
    ATTACK_TYPE_ACK_FLOOD,
    ATTACK_TYPE_RST_FLOOD,
    ATTACK_TYPE_FRAGMENTATION,
    ATTACK_TYPE_MEMCACHED,
    ATTACK_TYPE_MIXED,
    ATTACK_TYPE_UNKNOWN,
    ATTACK_TYPE_MAX
} attack_type_t;

// ==================== Per-Lcore Stats (Lock-Free) ====================

/**
 * Per-lcore statistics for a single tenant
 * Updated by data plane without locks
 */
struct tenant_lcore_stats {
    // Traffic counters
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;

    // Drop counters by reason
    uint64_t drops_by_reason[DROP_REASON_MAX];

    // Layer 1 specific
    uint64_t l1_rate_limit_hits;
    uint64_t l1_blacklist_hits;
    uint64_t l1_whitelist_hits;
    uint64_t l1_syn_proxy_challenges;
    uint64_t l1_syn_proxy_passed;
    uint64_t l1_flow_creates;
    uint64_t l1_flow_expires;
    uint64_t l1_signature_hits;

    // Layer 4 specific
    uint64_t l4_challenges_issued;
    uint64_t l4_challenges_passed;
    uint64_t l4_challenges_failed;
    uint64_t l4_bots_detected;
    uint64_t l4_bots_blocked;

    // Padding to cache line
    uint8_t _pad[64];
} __attribute__((aligned(64)));

// ==================== Aggregated Stats ====================

/**
 * Traffic statistics block
 */
struct tenant_traffic_stats {
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t current_pps;       // Calculated rate
    uint64_t current_bps;       // Calculated rate
    uint64_t peak_pps_1m;       // Peak in last 1 minute
    uint64_t peak_bps_1m;
    uint64_t peak_pps_1h;       // Peak in last 1 hour
    uint64_t peak_bps_1h;
    uint64_t peak_pps_24h;      // Peak in last 24 hours
    uint64_t peak_bps_24h;
};

/**
 * Security statistics block
 */
struct tenant_security_stats {
    uint64_t total_drops;
    uint64_t drops_by_reason[DROP_REASON_MAX];
    uint64_t attacks_detected;
    uint64_t attacks_mitigated;
    uint64_t attacks_by_type[ATTACK_TYPE_MAX];
    uint64_t false_positives;
    uint64_t false_negatives;
    double   avg_detection_time_ms;
    double   avg_mitigation_time_ms;
};

/**
 * Layer 1 statistics block
 */
struct tenant_l1_stats {
    uint64_t rate_limit_hits;
    uint64_t blacklist_hits;
    uint64_t whitelist_hits;
    uint64_t syn_proxy_challenges;
    uint64_t syn_proxy_passed;
    uint64_t syn_proxy_pass_rate;   // Percentage * 100
    uint64_t flow_table_usage;
    uint64_t flow_table_capacity;
    uint64_t signature_hits;
    uint64_t policies_active;
};

/**
 * Layer 2 statistics block
 */
struct tenant_l2_stats {
    double   current_z_score;
    double   baseline_pps;
    double   baseline_bps;
    bool     anomaly_active;
    uint8_t  anomaly_severity;      // 0-3: none, low, high, critical
    uint8_t  anomaly_protocol;      // TCP/UDP/ICMP/ALL
    uint64_t anomaly_duration_ms;
    uint64_t total_anomalies;
    double   avg_anomaly_duration_ms;
};

/**
 * Layer 3 statistics block
 */
struct tenant_l3_stats {
    uint64_t ml_inferences;
    uint64_t policies_generated;
    uint64_t signatures_generated;
    uint64_t clusters_found;
    uint64_t attack_clusters;
    double   model_precision;
    double   model_recall;
    double   model_f1;
    uint64_t reputation_updates;
};

/**
 * Layer 4 statistics block
 */
struct tenant_l4_stats {
    double   avg_reputation_score;
    double   min_reputation_score;
    uint64_t trusted_ips;
    uint64_t suspicious_ips;
    uint64_t attacker_ips;
    uint64_t challenges_issued;
    uint64_t challenges_passed;
    uint64_t challenges_failed;
    double   challenge_pass_rate;
    uint64_t bots_detected;
    uint64_t bots_blocked;
    uint64_t browser_verified;
};

/**
 * Layer 5 statistics block
 */
struct tenant_l5_stats {
    uint64_t threat_intel_hits;
    uint64_t global_reputation_lookups;
    uint64_t early_warnings_sent;
    uint64_t baseline_recommendations;
    uint64_t baselines_optimized;
    uint64_t patterns_shared;       // Cross-tenant
    uint64_t patterns_received;     // Cross-tenant
    uint64_t reports_generated;
};

/**
 * SLA statistics block
 */
struct tenant_sla_stats {
    double   availability_percent;      // 0.0 - 100.0
    uint64_t total_uptime_sec;
    uint64_t total_downtime_sec;
    uint64_t incidents_count;
    double   mttr_sec;                  // Mean time to recovery
    double   mttd_sec;                  // Mean time to detect
    double   mitigation_effectiveness;  // 0.0 - 1.0
    double   false_positive_rate;       // 0.0 - 1.0
    bool     sla_breach;
    uint64_t sla_breaches_count;
};

/**
 * Comprehensive tenant statistics
 */
struct tenant_comprehensive_stats {
    tenant_id_t tenant_id;
    uint64_t    timestamp;          // Unix timestamp
    uint64_t    collection_period_ms;

    // Component stats
    struct tenant_traffic_stats  traffic;
    struct tenant_security_stats security;
    struct tenant_l1_stats       layer1;
    struct tenant_l2_stats       layer2;
    struct tenant_l3_stats       layer3;
    struct tenant_l4_stats       layer4;
    struct tenant_l5_stats       layer5;
    struct tenant_sla_stats      sla;
};

// ==================== Historical Stats ====================

/**
 * Single point in time history
 */
struct tenant_stats_point {
    uint64_t timestamp;
    uint64_t pps_in;
    uint64_t bps_in;
    uint64_t drops;
    uint64_t attacks;
    uint8_t  anomaly_severity;
    uint8_t  _pad[7];
};

/**
 * Historical stats ring buffer
 */
struct tenant_stats_history {
    uint32_t head;
    uint32_t count;
    struct tenant_stats_point points[STATS_HISTORY_SLOTS];
};

// ==================== Stats Manager ====================

/**
 * Global stats manager
 */
struct tenant_stats_manager {
    // Per-lcore stats arrays (indexed by [lcore_id][tenant_id])
    struct tenant_lcore_stats **lcore_stats;
    uint32_t num_lcores;
    uint32_t max_tenants;

    // Aggregated stats per tenant
    struct tenant_comprehensive_stats *tenant_stats;

    // Historical data per tenant
    struct tenant_stats_history *history;

    // Timing
    uint64_t last_aggregation_tsc;
    uint64_t aggregation_interval_tsc;

    // Lock for aggregated stats access
    pthread_rwlock_t lock;

    // Stats export
    bool prometheus_enabled;
    uint16_t prometheus_port;

    // Configuration
    uint32_t history_retention_hours;
    bool track_per_ip_stats;
};

// ==================== API Functions ====================

/**
 * Initialize stats manager
 *
 * @param num_lcores Number of lcores
 * @param max_tenants Maximum tenant count
 * @return 0 on success, -1 on failure
 */
int tenant_stats_init(uint32_t num_lcores, uint32_t max_tenants);

/**
 * Cleanup stats manager
 */
void tenant_stats_cleanup(void);

/**
 * Get per-lcore stats pointer for fast updates
 *
 * @param lcore_id Lcore ID
 * @param tenant_id Tenant ID
 * @return Pointer to lcore stats, NULL if invalid
 */
struct tenant_lcore_stats* tenant_stats_get_lcore(uint32_t lcore_id,
                                                   tenant_id_t tenant_id);

// ==================== Fast Update Functions (Lock-Free) ====================

/**
 * Record incoming packet
 */
static inline void tenant_stats_packet_in(struct tenant_lcore_stats *stats,
                                          uint32_t bytes) {
    if (stats) {
        stats->packets_in++;
        stats->bytes_in += bytes;
    }
}

/**
 * Record outgoing packet
 */
static inline void tenant_stats_packet_out(struct tenant_lcore_stats *stats,
                                           uint32_t bytes) {
    if (stats) {
        stats->packets_out++;
        stats->bytes_out += bytes;
    }
}

/**
 * Record packet drop
 */
static inline void tenant_stats_drop(struct tenant_lcore_stats *stats,
                                     drop_reason_t reason) {
    if (stats && reason < DROP_REASON_MAX) {
        stats->drops_by_reason[reason]++;
    }
}

/**
 * Record Layer 1 events
 */
static inline void tenant_stats_l1_rate_limit(struct tenant_lcore_stats *s) {
    if (s) s->l1_rate_limit_hits++;
}

static inline void tenant_stats_l1_blacklist(struct tenant_lcore_stats *s) {
    if (s) s->l1_blacklist_hits++;
}

static inline void tenant_stats_l1_whitelist(struct tenant_lcore_stats *s) {
    if (s) s->l1_whitelist_hits++;
}

static inline void tenant_stats_l1_syn_challenge(struct tenant_lcore_stats *s,
                                                  bool passed) {
    if (s) {
        s->l1_syn_proxy_challenges++;
        if (passed) s->l1_syn_proxy_passed++;
    }
}

static inline void tenant_stats_l1_signature(struct tenant_lcore_stats *s) {
    if (s) s->l1_signature_hits++;
}

/**
 * Record Layer 4 events
 */
static inline void tenant_stats_l4_challenge(struct tenant_lcore_stats *s,
                                              bool passed) {
    if (s) {
        s->l4_challenges_issued++;
        if (passed) s->l4_challenges_passed++;
        else s->l4_challenges_failed++;
    }
}

static inline void tenant_stats_l4_bot(struct tenant_lcore_stats *s,
                                        bool blocked) {
    if (s) {
        s->l4_bots_detected++;
        if (blocked) s->l4_bots_blocked++;
    }
}

// ==================== Aggregation Functions ====================

/**
 * Aggregate all lcore stats for a tenant
 *
 * @param tenant_id Tenant ID
 * @return 0 on success
 */
int tenant_stats_aggregate(tenant_id_t tenant_id);

/**
 * Aggregate all lcore stats for all tenants
 *
 * @return Number of tenants aggregated
 */
int tenant_stats_aggregate_all(void);

/**
 * Periodic maintenance (call from timer)
 */
void tenant_stats_maintenance(void);

// ==================== Query Functions ====================

/**
 * Get comprehensive stats for a tenant
 *
 * @param tenant_id Tenant ID
 * @param stats Output stats structure
 * @return 0 on success
 */
int tenant_stats_get(tenant_id_t tenant_id,
                     struct tenant_comprehensive_stats *stats);

/**
 * Get traffic stats only
 */
int tenant_stats_get_traffic(tenant_id_t tenant_id,
                              struct tenant_traffic_stats *stats);

/**
 * Get security stats only
 */
int tenant_stats_get_security(tenant_id_t tenant_id,
                               struct tenant_security_stats *stats);

/**
 * Get layer-specific stats
 */
int tenant_stats_get_l1(tenant_id_t tenant_id, struct tenant_l1_stats *stats);
int tenant_stats_get_l2(tenant_id_t tenant_id, struct tenant_l2_stats *stats);
int tenant_stats_get_l3(tenant_id_t tenant_id, struct tenant_l3_stats *stats);
int tenant_stats_get_l4(tenant_id_t tenant_id, struct tenant_l4_stats *stats);
int tenant_stats_get_l5(tenant_id_t tenant_id, struct tenant_l5_stats *stats);

/**
 * Get SLA stats
 */
int tenant_stats_get_sla(tenant_id_t tenant_id, struct tenant_sla_stats *stats);

// ==================== Historical Data ====================

/**
 * Get historical data points
 *
 * @param tenant_id Tenant ID
 * @param start_time Start timestamp (0 for all)
 * @param end_time End timestamp (0 for now)
 * @param points Output array
 * @param max_points Array size
 * @return Number of points returned
 */
int tenant_stats_get_history(tenant_id_t tenant_id,
                              uint64_t start_time, uint64_t end_time,
                              struct tenant_stats_point *points,
                              int max_points);

/**
 * Get peak traffic in time range
 */
int tenant_stats_get_peak(tenant_id_t tenant_id,
                          uint64_t start_time, uint64_t end_time,
                          uint64_t *peak_pps, uint64_t *peak_bps);

// ==================== Update Functions (Higher Level) ====================

/**
 * Update Layer 2 stats
 */
void tenant_stats_update_l2(tenant_id_t tenant_id,
                            double z_score, bool anomaly_active,
                            uint8_t severity, uint8_t protocol);

/**
 * Update Layer 3 stats
 */
void tenant_stats_update_l3(tenant_id_t tenant_id,
                            uint64_t inferences, uint64_t policies,
                            double precision, double recall);

/**
 * Update Layer 4 stats
 */
void tenant_stats_update_l4(tenant_id_t tenant_id,
                            double avg_reputation,
                            uint64_t trusted, uint64_t suspicious,
                            uint64_t attackers);

/**
 * Update Layer 5 stats
 */
void tenant_stats_update_l5(tenant_id_t tenant_id,
                            uint64_t threat_hits, uint64_t warnings,
                            uint64_t reports);

/**
 * Record attack detection
 */
void tenant_stats_attack_detected(tenant_id_t tenant_id,
                                   attack_type_t type,
                                   double detection_time_ms);

/**
 * Record attack mitigation
 */
void tenant_stats_attack_mitigated(tenant_id_t tenant_id,
                                    double mitigation_time_ms,
                                    bool effective);

/**
 * Record false positive/negative
 */
void tenant_stats_false_positive(tenant_id_t tenant_id);
void tenant_stats_false_negative(tenant_id_t tenant_id);

// ==================== SLA Functions ====================

/**
 * Update SLA metrics
 */
void tenant_stats_sla_update(tenant_id_t tenant_id,
                              bool available, uint64_t duration_sec);

/**
 * Check SLA compliance
 *
 * @param tenant_id Tenant ID
 * @param min_availability Minimum required availability (0-100)
 * @param max_fp_rate Maximum false positive rate (0-1)
 * @return true if compliant
 */
bool tenant_stats_sla_check(tenant_id_t tenant_id,
                            double min_availability, double max_fp_rate);

// ==================== Export Functions ====================

/**
 * Export stats to JSON string
 *
 * @param tenant_id Tenant ID
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return Bytes written
 */
int tenant_stats_export_json(tenant_id_t tenant_id,
                              char *buf, size_t buf_size);

/**
 * Export all tenants stats to JSON
 */
int tenant_stats_export_all_json(char *buf, size_t buf_size);

/**
 * Get stats in Prometheus format
 *
 * @param tenant_id Tenant ID (0 for all)
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return Bytes written
 */
int tenant_stats_export_prometheus(tenant_id_t tenant_id,
                                    char *buf, size_t buf_size);

// ==================== Reset Functions ====================

/**
 * Reset stats for a tenant
 */
void tenant_stats_reset(tenant_id_t tenant_id);

/**
 * Reset all tenant stats
 */
void tenant_stats_reset_all(void);

/**
 * Clear historical data
 */
void tenant_stats_clear_history(tenant_id_t tenant_id);

// ==================== Utility ====================

/**
 * Get drop reason name
 */
const char* tenant_stats_drop_reason_name(drop_reason_t reason);

/**
 * Get attack type name
 */
const char* tenant_stats_attack_type_name(attack_type_t type);

/**
 * Get manager status
 */
void tenant_stats_get_status(uint32_t *num_tenants, uint64_t *total_packets);

#ifdef __cplusplus
}
#endif

#endif // TENANT_STATS_H
