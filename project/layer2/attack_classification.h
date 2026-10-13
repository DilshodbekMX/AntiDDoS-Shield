#ifndef LAYER2_ATTACK_CLASSIFICATION_H
#define LAYER2_ATTACK_CLASSIFICATION_H

#include "baselines.h"
#include "detection.h"
#include <stdint.h>
#include <stdbool.h>

/**
 * @file attack_classification.h
 * @brief Attack Type Classification for DDoS Detection
 *
 * MF1 FIX: Implements attack classification to distinguish between:
 * - SYN Flood: High SYN rate, low SYN-ACK ratio, many unique src IPs
 * - UDP Amplification: High UDP ratio, large packets, concentrated sources
 * - ICMP Flood: High ICMP ratio
 * - Slowloris: Low volume but high connection count, long flow durations
 * - HTTP Flood: High TCP ratio, normal packet sizes, many flows
 * - DNS Amplification: UDP port 53, large response packets
 * - NTP Amplification: UDP port 123, large response packets
 * - Volumetric Flood: Pure volume-based attack
 * - Multi-Vector: Multiple attack types detected simultaneously
 */

// ==================== Attack Types ====================

/**
 * Attack type enumeration
 * Can be ORed together for multi-vector attacks
 */
enum l2_attack_type {
    L2_ATTACK_NONE           = 0,
    L2_ATTACK_SYN_FLOOD      = (1 << 0),   // SYN flood
    L2_ATTACK_UDP_FLOOD      = (1 << 1),   // Generic UDP flood
    L2_ATTACK_UDP_AMP        = (1 << 2),   // UDP amplification (DNS/NTP/etc)
    L2_ATTACK_ICMP_FLOOD     = (1 << 3),   // ICMP flood
    L2_ATTACK_SLOWLORIS      = (1 << 4),   // Slow connection exhaustion
    L2_ATTACK_HTTP_FLOOD     = (1 << 5),   // HTTP request flood
    L2_ATTACK_ACK_FLOOD      = (1 << 6),   // ACK flood
    L2_ATTACK_RST_FLOOD      = (1 << 7),   // RST flood
    L2_ATTACK_VOLUMETRIC     = (1 << 8),   // Pure volume attack
    L2_ATTACK_FRAGMENTATION  = (1 << 9),   // Fragmentation attack
    L2_ATTACK_UNKNOWN        = (1 << 15),  // Detected but unclassified
};

/**
 * Attack classification confidence
 */
enum l2_classification_confidence {
    L2_CONF_NONE = 0,      // No classification
    L2_CONF_LOW = 1,       // Weak signals, might be false positive
    L2_CONF_MEDIUM = 2,    // Moderate signals, likely attack
    L2_CONF_HIGH = 3,      // Strong signals, definitely attack
};

// ==================== Classification Result ====================

/**
 * Attack signature - feature pattern that indicates attack type
 */
struct attack_signature {
    // Feature thresholds (Z-score based)
    double syn_z_min;           // Minimum SYN Z-score for SYN flood
    double udp_ratio_min;       // Minimum UDP ratio for UDP attack
    double icmp_ratio_min;      // Minimum ICMP ratio for ICMP flood
    double bytes_per_pkt_min;   // Large packets (amplification)
    double bytes_per_pkt_max;   // Small packets (SYN flood)
    double flow_duration_max;   // Short flows (flood)
    double flow_duration_min;   // Long flows (slowloris)
    double src_ip_diversity;    // High = distributed, low = single source
};

/**
 * Per-attack-type classification details
 */
struct attack_type_info {
    enum l2_attack_type type;
    const char *name;
    const char *description;
    double score;                       // Classification score (0.0 - 1.0)
    enum l2_classification_confidence confidence;
};

/**
 * Full classification result
 */
struct attack_classification {
    // Primary attack type (highest score)
    enum l2_attack_type primary_type;
    const char *primary_name;
    double primary_score;
    enum l2_classification_confidence primary_confidence;

    // All detected attack types (bitmask)
    uint32_t detected_types;
    int num_types_detected;

    // Per-type scores (top 3)
    struct attack_type_info top_attacks[3];

    // Multi-vector detection
    bool is_multi_vector;

    // Feature analysis
    double syn_score;           // SYN flood likelihood
    double udp_score;           // UDP flood likelihood
    double amp_score;           // Amplification likelihood
    double icmp_score;          // ICMP flood likelihood
    double slowloris_score;     // Slowloris likelihood
    double volumetric_score;    // Pure volume likelihood

    // Derived indicators
    bool is_amplification;      // Large response packets
    bool is_spoofed;            // Many unique source IPs
    bool is_targeted;           // Concentrated on few destinations
    bool is_distributed;        // Many sources, low per-source rate

    // Timestamp
    uint64_t timestamp_ns;
};

// ==================== Classification API ====================

/**
 * Initialize classification result
 */
void l2_attack_classification_init(struct attack_classification *result);

/**
 * Classify attack based on feature snapshot and detection result
 *
 * @param snapshot Current feature values
 * @param z_scores Z-scores for all features
 * @param detection Detection result (for tier agreement, severity)
 * @param result Output: classification result
 */
void l2_classify_attack(const struct l2_feature_snapshot *snapshot,
                        const double z_scores[L2_MAX_FEATURES],
                        const struct detection_result *detection,
                        struct attack_classification *result);

/**
 * Get attack type name
 */
const char *l2_attack_type_name(enum l2_attack_type type);

/**
 * Get attack type description (longer form for logs)
 */
const char *l2_attack_type_description(enum l2_attack_type type);

/**
 * Get all attack types as string (for multi-vector)
 * @param types Bitmask of attack types
 * @param buffer Output buffer
 * @param size Buffer size
 * @return Number of characters written
 */
int l2_attack_types_to_string(uint32_t types, char *buffer, size_t size);

/**
 * Get confidence name
 */
const char *l2_classification_confidence_name(enum l2_classification_confidence conf);

// ==================== Scoring Functions ====================

/**
 * Compute SYN flood score
 * High score = likely SYN flood
 */
double l2_score_syn_flood(const struct l2_feature_snapshot *snapshot,
                          const double z_scores[L2_MAX_FEATURES]);

/**
 * Compute UDP amplification score
 * High score = likely UDP amplification attack
 */
double l2_score_udp_amplification(const struct l2_feature_snapshot *snapshot,
                                   const double z_scores[L2_MAX_FEATURES]);

/**
 * Compute ICMP flood score
 */
double l2_score_icmp_flood(const struct l2_feature_snapshot *snapshot,
                           const double z_scores[L2_MAX_FEATURES]);

/**
 * Compute slowloris score
 * High score = likely slowloris or slow attack
 */
double l2_score_slowloris(const struct l2_feature_snapshot *snapshot,
                          const double z_scores[L2_MAX_FEATURES]);

/**
 * Compute pure volumetric score
 */
double l2_score_volumetric(const struct l2_feature_snapshot *snapshot,
                           const double z_scores[L2_MAX_FEATURES]);

// ==================== Logging ====================

/**
 * Log attack classification result
 */
void l2_log_classification(const struct attack_classification *result);

// ==================== Protocol Info Extraction ====================

/**
 * Get protocol category and attack type from classification result
 *
 * This function extracts the information needed to set per-IP anomaly state
 * with protocol-specific info for Layer 3 signature extraction.
 *
 * For hybrid/multi-protocol attacks:
 * - If multiple protocols are under attack, proto_cat is set to PROTO_CAT_ALL
 * - secondary_proto_cat contains the second-strongest attack's protocol
 * - Layer 3 should analyze all protocols when proto_cat is ALL
 *
 * @param classification  Result from l2_classify_attack()
 * @param snapshot        Current feature values (for fallback heuristics)
 * @param proto_cat_out   Output: PROTO_CAT_TCP/UDP/ICMP/OTHER/ALL
 * @param attack_type_out Output: ATTACK_TYPE_* constant for shared memory
 * @param dst_port_out    Output: Specific port under attack (0 = all ports)
 * @param secondary_proto_cat_out Output: Secondary protocol for hybrid attacks
 */
void l2_get_protocol_info(const struct attack_classification *classification,
                          const struct l2_feature_snapshot *snapshot,
                          uint8_t *proto_cat_out,
                          uint8_t *attack_type_out,
                          uint16_t *dst_port_out,
                          uint8_t *secondary_proto_cat_out);

#endif // LAYER2_ATTACK_CLASSIFICATION_H
