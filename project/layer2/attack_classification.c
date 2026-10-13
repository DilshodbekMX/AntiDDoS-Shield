#include "attack_classification.h"
#include "../layer1/interlayer/shared_memory.h"
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>

// ==================== Attack Type Names ====================

static const char *attack_type_names[] = {
    [0] = "none",
    [1] = "syn_flood",
    [2] = "udp_flood",
    [3] = "udp_amplification",
    [4] = "icmp_flood",
    [5] = "slowloris",
    [6] = "http_flood",
    [7] = "ack_flood",
    [8] = "rst_flood",
    [9] = "volumetric",
    [10] = "fragmentation",
};

static const char *attack_type_descriptions[] = {
    [0] = "No attack detected",
    [1] = "SYN Flood - TCP SYN packet flood",
    [2] = "UDP Flood - Generic UDP packet flood",
    [3] = "UDP Amplification - DNS/NTP/SSDP reflection attack",
    [4] = "ICMP Flood - Ping/ICMP packet flood",
    [5] = "Slowloris - Slow connection exhaustion",
    [6] = "HTTP Flood - Application layer request flood",
    [7] = "ACK Flood - TCP ACK packet flood",
    [8] = "RST Flood - TCP RST packet flood",
    [9] = "Volumetric - High bandwidth flood",
    [10] = "Fragmentation - IP fragmentation attack",
};

static const char *confidence_names[] = {
    [L2_CONF_NONE] = "none",
    [L2_CONF_LOW] = "low",
    [L2_CONF_MEDIUM] = "medium",
    [L2_CONF_HIGH] = "high",
};

// ==================== Helper: Get bit position ====================

static int get_attack_type_index(enum l2_attack_type type) {
    if (type == L2_ATTACK_NONE) return 0;
    for (int i = 0; i < 16; i++) {
        if (type == (enum l2_attack_type)(1 << i)) return i + 1;
    }
    return 0;
}

// ==================== Public API ====================

const char *l2_attack_type_name(enum l2_attack_type type) {
    int idx = get_attack_type_index(type);
    if (idx >= 0 && idx < 11) {
        return attack_type_names[idx];
    }
    return "unknown";
}

const char *l2_attack_type_description(enum l2_attack_type type) {
    int idx = get_attack_type_index(type);
    if (idx >= 0 && idx < 11) {
        return attack_type_descriptions[idx];
    }
    return "Unknown attack type";
}

const char *l2_classification_confidence_name(enum l2_classification_confidence conf) {
    if (conf <= L2_CONF_HIGH) {
        return confidence_names[conf];
    }
    return "unknown";
}

int l2_attack_types_to_string(uint32_t types, char *buffer, size_t size) {
    if (!buffer || size == 0) return 0;

    buffer[0] = '\0';
    int written = 0;
    bool first = true;

    for (int i = 0; i < 16; i++) {
        if (types & (1 << i)) {
            const char *name = l2_attack_type_name(1 << i);
            int n;
            if (first) {
                n = snprintf(buffer + written, size - written, "%s", name);
                first = false;
            } else {
                n = snprintf(buffer + written, size - written, "+%s", name);
            }
            if (n > 0) written += n;
            if ((size_t)written >= size - 1) break;
        }
    }

    return written;
}

void l2_attack_classification_init(struct attack_classification *result) {
    if (!result) return;

    memset(result, 0, sizeof(*result));
    result->primary_type = L2_ATTACK_NONE;
    result->primary_name = "none";
    result->primary_confidence = L2_CONF_NONE;
}

// ==================== Scoring Functions ====================

double l2_score_syn_flood(const struct l2_feature_snapshot *snapshot,
                          const double z_scores[L2_MAX_FEATURES]) {
    if (!snapshot || !z_scores) return 0.0;

    double score = 0.0;

    // High SYN rate is primary indicator
    double syn_z = z_scores[L2_FEAT_SYN_PER_SEC];
    if (syn_z > 3.0) {
        score += 0.3 * fmin(syn_z / 10.0, 1.0);
    }

    // Low SYN-ACK ratio indicates unanswered SYNs (spoofed sources)
    double syn_ack_ratio = snapshot->values[L2_FEAT_SYN_ACK_RATIO];
    if (syn_ack_ratio < 50.0 && snapshot->values[L2_FEAT_SYN_PER_SEC] > 1000) {
        score += 0.25 * (1.0 - syn_ack_ratio / 100.0);
    }

    // High unique source IPs (spoofed)
    double src_ip_z = z_scores[L2_FEAT_UNIQUE_SRC_IPS];
    if (src_ip_z > 2.0) {
        score += 0.2 * fmin(src_ip_z / 8.0, 1.0);
    }

    // Small packets (SYN packets are small)
    double bytes_per_pkt = snapshot->values[L2_FEAT_BYTES_PER_PACKET];
    if (bytes_per_pkt < 100 && bytes_per_pkt > 0) {
        score += 0.15;
    }

    // High TCP ratio
    double tcp_ratio = snapshot->values[L2_FEAT_TCP_RATIO];
    if (tcp_ratio > 80.0) {
        score += 0.1;
    }

    return fmin(score, 1.0);
}

/**
 * FIX #9: Separate UDP flood vs UDP amplification scoring
 * UDP Flood: Many small packets from many sources
 * UDP Amplification: Large packets from few sources (reflectors)
 */
double l2_score_udp_flood(const struct l2_feature_snapshot *snapshot,
                          const double z_scores[L2_MAX_FEATURES]) {
    if (!snapshot || !z_scores) return 0.0;

    double score = 0.0;

    // High UDP ratio is primary indicator
    double udp_ratio = snapshot->values[L2_FEAT_UDP_RATIO];
    if (udp_ratio > 60.0) {
        score += 0.2 * (udp_ratio / 100.0);
    }

    // High packet rate (flood = volume via packets)
    double pps_z = z_scores[L2_FEAT_PACKETS_PER_SEC];
    if (pps_z > 4.0) {
        score += 0.25 * fmin(pps_z / 10.0, 1.0);
    }

    // SMALL packets (flood uses minimal size for max pps)
    double bytes_per_pkt = snapshot->values[L2_FEAT_BYTES_PER_PACKET];
    if (bytes_per_pkt > 0 && bytes_per_pkt < 200) {  // Small UDP packets
        score += 0.2 * (1.0 - bytes_per_pkt / 200.0);
    }

    // HIGH source diversity (spoofed flood has many src IPs)
    double src_ip_z = z_scores[L2_FEAT_UNIQUE_SRC_IPS];
    if (src_ip_z > 3.0) {
        score += 0.2 * fmin(src_ip_z / 8.0, 1.0);
    }

    // Low concentration (distributed attack)
    double max_flow_frac = snapshot->values[L2_FEAT_MAX_FLOW_FRACTION];
    if (max_flow_frac < 10.0) {
        score += 0.15 * (1.0 - max_flow_frac / 10.0);
    }

    return fmin(score, 1.0);
}

double l2_score_udp_amplification(const struct l2_feature_snapshot *snapshot,
                                   const double z_scores[L2_MAX_FEATURES]) {
    if (!snapshot || !z_scores) return 0.0;

    double score = 0.0;

    // High UDP ratio is primary indicator
    double udp_ratio = snapshot->values[L2_FEAT_UDP_RATIO];
    if (udp_ratio > 60.0) {
        score += 0.2 * (udp_ratio / 100.0);
    }

    // LARGE packets indicate amplification (DNS/NTP/Memcached responses are big)
    double bytes_per_pkt = snapshot->values[L2_FEAT_BYTES_PER_PACKET];
    if (bytes_per_pkt > 500) {
        score += 0.3 * fmin((bytes_per_pkt - 500) / 1000.0, 1.0);
    }

    // High bytes/sec relative to packet rate (large packets = high bytes/pps ratio)
    double bytes_z = z_scores[L2_FEAT_BYTES_PER_SEC];
    double pps_z = z_scores[L2_FEAT_PACKETS_PER_SEC];
    if (bytes_z > pps_z * 1.5 && bytes_z > 3.0) {
        score += 0.2;
    }

    // LOW source diversity (reflectors are limited pools)
    double src_ips = snapshot->values[L2_FEAT_UNIQUE_SRC_IPS];
    double total_pkts = snapshot->values[L2_FEAT_PACKETS_PER_SEC];
    if (total_pkts > 0 && src_ips > 0) {
        double pkts_per_src = total_pkts / src_ips;
        if (pkts_per_src > 100) {  // High packets per source = few sources
            score += 0.15 * fmin(pkts_per_src / 1000.0, 1.0);
        }
    }

    // High concentration (few reflectors dominate)
    double max_flow_frac = snapshot->values[L2_FEAT_MAX_FLOW_FRACTION];
    if (max_flow_frac > 20.0) {
        score += 0.15 * (max_flow_frac / 100.0);
    }

    return fmin(score, 1.0);
}

double l2_score_icmp_flood(const struct l2_feature_snapshot *snapshot,
                           const double z_scores[L2_MAX_FEATURES]) {
    if (!snapshot || !z_scores) return 0.0;

    double score = 0.0;

    // High ICMP ratio is primary indicator
    double icmp_ratio = snapshot->values[L2_FEAT_ICMP_RATIO];
    if (icmp_ratio > 30.0) {
        score += 0.5 * (icmp_ratio / 100.0);
    }

    // Protocol mix Z-score
    double icmp_z = z_scores[L2_FEAT_ICMP_RATIO];
    if (icmp_z > 3.0) {
        score += 0.3 * fmin(icmp_z / 10.0, 1.0);
    }

    // High packet rate
    double pps_z = z_scores[L2_FEAT_PACKETS_PER_SEC];
    if (pps_z > 3.0) {
        score += 0.2 * fmin(pps_z / 10.0, 1.0);
    }

    return fmin(score, 1.0);
}

double l2_score_slowloris(const struct l2_feature_snapshot *snapshot,
                          const double z_scores[L2_MAX_FEATURES]) {
    if (!snapshot || !z_scores) return 0.0;

    double score = 0.0;

    // Long flow durations
    double flow_duration = snapshot->values[L2_FEAT_FLOW_DURATION_AVG];
    if (flow_duration > 30000) {  // > 30 seconds average
        score += 0.3 * fmin(flow_duration / 300000.0, 1.0);
    }

    // High flow count but low packet rate per flow
    double flows_z = z_scores[L2_FEAT_FLOWS_PER_SEC];
    double pps_z = z_scores[L2_FEAT_PACKETS_PER_SEC];
    if (flows_z > pps_z && flows_z > 3.0) {
        score += 0.25;
    }

    // Low packets per flow
    double pkts_per_flow = snapshot->values[L2_FEAT_AVG_PACKETS_PER_FLOW];
    if (pkts_per_flow < 10 && pkts_per_flow > 0) {
        score += 0.25 * (1.0 - pkts_per_flow / 10.0);
    }

    // TCP-based (slowloris is HTTP)
    double tcp_ratio = snapshot->values[L2_FEAT_TCP_RATIO];
    if (tcp_ratio > 80.0) {
        score += 0.1;
    }

    // Low volume but many connections
    double bytes_z = z_scores[L2_FEAT_BYTES_PER_SEC];
    if (flows_z > bytes_z * 2 && flows_z > 3.0) {
        score += 0.1;
    }

    return fmin(score, 1.0);
}

double l2_score_volumetric(const struct l2_feature_snapshot *snapshot,
                           const double z_scores[L2_MAX_FEATURES]) {
    if (!snapshot || !z_scores) return 0.0;

    double score = 0.0;

    // High bytes/sec is primary indicator
    double bytes_z = z_scores[L2_FEAT_BYTES_PER_SEC];
    if (bytes_z > 4.0) {
        score += 0.4 * fmin(bytes_z / 12.0, 1.0);
    }

    // High packet rate
    double pps_z = z_scores[L2_FEAT_PACKETS_PER_SEC];
    if (pps_z > 4.0) {
        score += 0.3 * fmin(pps_z / 12.0, 1.0);
    }

    // Proportional increase (not just one metric)
    if (bytes_z > 3.0 && pps_z > 3.0) {
        double ratio = fmin(bytes_z, pps_z) / fmax(bytes_z, pps_z);
        if (ratio > 0.5) {
            score += 0.2 * ratio;
        }
    }

    // Check for no specific attack pattern (generic flood)
    double tcp_ratio = snapshot->values[L2_FEAT_TCP_RATIO];
    double udp_ratio = snapshot->values[L2_FEAT_UDP_RATIO];
    if (tcp_ratio < 70.0 && udp_ratio < 70.0) {
        score += 0.1;  // Mixed traffic = generic volumetric
    }

    return fmin(score, 1.0);
}

// ==================== Main Classification ====================

void l2_classify_attack(const struct l2_feature_snapshot *snapshot,
                        const double z_scores[L2_MAX_FEATURES],
                        const struct detection_result *detection,
                        struct attack_classification *result) {
    if (!result) return;

    l2_attack_classification_init(result);

    if (!snapshot || !z_scores || !detection || !detection->detected) {
        return;  // No attack detected, nothing to classify
    }

    // Get current timestamp
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    result->timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    // Compute scores for each attack type
    result->syn_score = l2_score_syn_flood(snapshot, z_scores);
    // FIX #9: Separate UDP flood (small packets, many sources) from amplification (large packets, few sources)
    result->udp_score = l2_score_udp_flood(snapshot, z_scores);
    result->amp_score = l2_score_udp_amplification(snapshot, z_scores);
    result->icmp_score = l2_score_icmp_flood(snapshot, z_scores);
    result->slowloris_score = l2_score_slowloris(snapshot, z_scores);
    result->volumetric_score = l2_score_volumetric(snapshot, z_scores);

    // Additional scores for other attack types
    double ack_score = 0.0;
    double rst_score = 0.0;

    // ACK flood scoring
    double ack_z = z_scores[L2_FEAT_ACK_PER_SEC];
    if (ack_z > 4.0 && snapshot->values[L2_FEAT_TCP_RATIO] > 80.0) {
        ack_score = 0.5 * fmin(ack_z / 10.0, 1.0);
        // Low SYN rate differentiates from SYN flood
        if (z_scores[L2_FEAT_SYN_PER_SEC] < 2.0) {
            ack_score += 0.3;
        }
    }

    // RST flood scoring
    double rst_z = z_scores[L2_FEAT_RST_PER_SEC];
    double rst_syn_ratio = snapshot->values[L2_FEAT_RST_SYN_RATIO];
    if (rst_z > 4.0 && rst_syn_ratio > 200.0) {  // More RST than SYN
        rst_score = 0.5 * fmin(rst_z / 10.0, 1.0);
        if (rst_syn_ratio > 500.0) {
            rst_score += 0.3;
        }
    }

    // Collect all scores for ranking
    struct {
        enum l2_attack_type type;
        double score;
    } scores[] = {
        { L2_ATTACK_SYN_FLOOD,  result->syn_score },
        { L2_ATTACK_UDP_AMP,    result->udp_score },
        { L2_ATTACK_UDP_FLOOD,  result->udp_score * 0.9 },  // Slightly lower priority
        { L2_ATTACK_ICMP_FLOOD, result->icmp_score },
        { L2_ATTACK_SLOWLORIS,  result->slowloris_score },
        { L2_ATTACK_VOLUMETRIC, result->volumetric_score },
        { L2_ATTACK_ACK_FLOOD,  ack_score },
        { L2_ATTACK_RST_FLOOD,  rst_score },
    };
    int num_types = sizeof(scores) / sizeof(scores[0]);

    // Sort by score (simple bubble sort, small array)
    for (int i = 0; i < num_types - 1; i++) {
        for (int j = i + 1; j < num_types; j++) {
            if (scores[j].score > scores[i].score) {
                enum l2_attack_type t = scores[i].type;
                double s = scores[i].score;
                scores[i].type = scores[j].type;
                scores[i].score = scores[j].score;
                scores[j].type = t;
                scores[j].score = s;
            }
        }
    }

    // Threshold for detection
    const double DETECTION_THRESHOLD = 0.3;
    const double HIGH_CONF_THRESHOLD = 0.6;
    const double MEDIUM_CONF_THRESHOLD = 0.4;

    // Primary attack type
    if (scores[0].score >= DETECTION_THRESHOLD) {
        result->primary_type = scores[0].type;
        result->primary_name = l2_attack_type_name(scores[0].type);
        result->primary_score = scores[0].score;

        if (scores[0].score >= HIGH_CONF_THRESHOLD) {
            result->primary_confidence = L2_CONF_HIGH;
        } else if (scores[0].score >= MEDIUM_CONF_THRESHOLD) {
            result->primary_confidence = L2_CONF_MEDIUM;
        } else {
            result->primary_confidence = L2_CONF_LOW;
        }

        result->detected_types |= scores[0].type;
        result->num_types_detected = 1;
    } else {
        // Attack detected but unclassifiable
        result->primary_type = L2_ATTACK_UNKNOWN;
        result->primary_name = "unknown";
        result->primary_confidence = L2_CONF_LOW;
        result->detected_types = L2_ATTACK_UNKNOWN;
        result->num_types_detected = 1;
    }

    // Fill top 3
    for (int i = 0; i < 3 && i < num_types; i++) {
        result->top_attacks[i].type = scores[i].type;
        result->top_attacks[i].name = l2_attack_type_name(scores[i].type);
        result->top_attacks[i].description = l2_attack_type_description(scores[i].type);
        result->top_attacks[i].score = scores[i].score;

        if (scores[i].score >= HIGH_CONF_THRESHOLD) {
            result->top_attacks[i].confidence = L2_CONF_HIGH;
        } else if (scores[i].score >= MEDIUM_CONF_THRESHOLD) {
            result->top_attacks[i].confidence = L2_CONF_MEDIUM;
        } else if (scores[i].score >= DETECTION_THRESHOLD) {
            result->top_attacks[i].confidence = L2_CONF_LOW;
        } else {
            result->top_attacks[i].confidence = L2_CONF_NONE;
        }
    }

    // Check for multi-vector attack (multiple types above threshold)
    for (int i = 1; i < num_types; i++) {
        if (scores[i].score >= DETECTION_THRESHOLD) {
            // Only count if meaningfully different from primary
            if (scores[i].score >= scores[0].score * 0.6) {
                result->detected_types |= scores[i].type;
                result->num_types_detected++;
            }
        }
    }

    result->is_multi_vector = (result->num_types_detected >= 2);

    // Derived indicators
    double bytes_per_pkt = snapshot->values[L2_FEAT_BYTES_PER_PACKET];
    result->is_amplification = (bytes_per_pkt > 500 &&
                                snapshot->values[L2_FEAT_UDP_RATIO] > 50.0);

    double src_ips = snapshot->values[L2_FEAT_UNIQUE_SRC_IPS];
    double total_pkts = snapshot->values[L2_FEAT_PACKETS_PER_SEC];
    result->is_distributed = (src_ips > 1000 && total_pkts / src_ips < 100);
    result->is_spoofed = (z_scores[L2_FEAT_UNIQUE_SRC_IPS] > 4.0 &&
                          snapshot->values[L2_FEAT_SYN_ACK_RATIO] < 30.0);

    result->is_targeted = (snapshot->values[L2_FEAT_MAX_FLOW_FRACTION] > 30.0);
}

// ==================== Logging ====================

void l2_log_classification(const struct attack_classification *result) {
    if (!result || result->primary_type == L2_ATTACK_NONE) {
        return;
    }

    char types_str[256];
    l2_attack_types_to_string(result->detected_types, types_str, sizeof(types_str));

    printf("[Layer2] Attack Classification: %s (%.0f%% confidence: %s)\n",
           result->primary_name,
           result->primary_score * 100.0,
           l2_classification_confidence_name(result->primary_confidence));

    if (result->is_multi_vector) {
        printf("[Layer2]   Multi-vector attack: %s\n", types_str);
    }

    // Print derived indicators
    if (result->is_amplification) {
        printf("[Layer2]   Indicator: Amplification attack (large packets)\n");
    }
    if (result->is_spoofed) {
        printf("[Layer2]   Indicator: Spoofed sources (low SYN-ACK ratio)\n");
    }
    if (result->is_distributed) {
        printf("[Layer2]   Indicator: Distributed attack (many sources)\n");
    }
    if (result->is_targeted) {
        printf("[Layer2]   Indicator: Targeted attack (concentrated flow)\n");
    }

    // Print top 3 if multiple types detected
    if (result->num_types_detected > 1) {
        printf("[Layer2]   Attack scores:\n");
        for (int i = 0; i < 3 && result->top_attacks[i].score > 0.1; i++) {
            printf("[Layer2]     %d. %s: %.0f%%\n",
                   i + 1,
                   result->top_attacks[i].name,
                   result->top_attacks[i].score * 100.0);
        }
    }
}

// ==================== Protocol Category Detection ====================

/**
 * Map L2 attack type to protocol category
 */
static uint8_t attack_type_to_proto_cat(enum l2_attack_type type) {
    switch (type) {
        case L2_ATTACK_SYN_FLOOD:
        case L2_ATTACK_ACK_FLOOD:
        case L2_ATTACK_RST_FLOOD:
        case L2_ATTACK_SLOWLORIS:
        case L2_ATTACK_HTTP_FLOOD:
            return PROTO_CAT_TCP;

        case L2_ATTACK_UDP_FLOOD:
        case L2_ATTACK_UDP_AMP:
            return PROTO_CAT_UDP;

        case L2_ATTACK_ICMP_FLOOD:
            return PROTO_CAT_ICMP;

        case L2_ATTACK_VOLUMETRIC:
        case L2_ATTACK_FRAGMENTATION:
        case L2_ATTACK_UNKNOWN:
        case L2_ATTACK_NONE:
        default:
            return PROTO_CAT_ALL;  // Volumetric may use any protocol
    }
}

/**
 * Map L2 attack type bitmask to shared memory ATTACK_TYPE_* constant
 */
static uint8_t l2_attack_to_shmem_attack_type(enum l2_attack_type type) {
    switch (type) {
        case L2_ATTACK_SYN_FLOOD:     return ATTACK_TYPE_SYN_FLOOD;
        case L2_ATTACK_UDP_FLOOD:     return ATTACK_TYPE_UDP_FLOOD;
        case L2_ATTACK_UDP_AMP:       return ATTACK_TYPE_DNS_AMP;  // Generic amplification
        case L2_ATTACK_ICMP_FLOOD:    return ATTACK_TYPE_ICMP_FLOOD;
        case L2_ATTACK_SLOWLORIS:     return ATTACK_TYPE_SLOWLORIS;
        case L2_ATTACK_HTTP_FLOOD:    return ATTACK_TYPE_HTTP_FLOOD;
        case L2_ATTACK_ACK_FLOOD:     return ATTACK_TYPE_ACK_FLOOD;
        case L2_ATTACK_RST_FLOOD:     return ATTACK_TYPE_RST_FLOOD;
        case L2_ATTACK_FRAGMENTATION: return ATTACK_TYPE_FRAG_FLOOD;
        case L2_ATTACK_VOLUMETRIC:    return ATTACK_TYPE_UNKNOWN;  // Generic volumetric
        default:                      return ATTACK_TYPE_UNKNOWN;
    }
}

void l2_get_protocol_info(const struct attack_classification *classification,
                          const struct l2_feature_snapshot *snapshot,
                          uint8_t *proto_cat_out,
                          uint8_t *attack_type_out,
                          uint16_t *dst_port_out,
                          uint8_t *secondary_proto_cat_out) {
    if (!classification || !snapshot) {
        if (proto_cat_out) *proto_cat_out = PROTO_CAT_ALL;
        if (attack_type_out) *attack_type_out = ATTACK_TYPE_UNKNOWN;
        if (dst_port_out) *dst_port_out = 0;
        if (secondary_proto_cat_out) *secondary_proto_cat_out = PROTO_CAT_ALL;
        return;
    }

    // Primary protocol from attack classification
    uint8_t primary_proto = attack_type_to_proto_cat(classification->primary_type);
    uint8_t attack_type = l2_attack_to_shmem_attack_type(classification->primary_type);

    // For hybrid attacks, check if multiple protocols are involved
    uint8_t secondary_proto = PROTO_CAT_ALL;
    if (classification->is_multi_vector) {
        // Check for TCP-based attacks
        bool has_tcp = (classification->detected_types &
                       (L2_ATTACK_SYN_FLOOD | L2_ATTACK_ACK_FLOOD |
                        L2_ATTACK_RST_FLOOD | L2_ATTACK_SLOWLORIS |
                        L2_ATTACK_HTTP_FLOOD)) != 0;
        // Check for UDP-based attacks
        bool has_udp = (classification->detected_types &
                       (L2_ATTACK_UDP_FLOOD | L2_ATTACK_UDP_AMP)) != 0;
        // Check for ICMP-based attacks
        bool has_icmp = (classification->detected_types & L2_ATTACK_ICMP_FLOOD) != 0;

        // Determine if truly multi-protocol
        int proto_count = (has_tcp ? 1 : 0) + (has_udp ? 1 : 0) + (has_icmp ? 1 : 0);
        if (proto_count > 1) {
            // True multi-protocol attack - set primary to ALL
            primary_proto = PROTO_CAT_ALL;
            attack_type = ATTACK_TYPE_UNKNOWN;  // Can't classify single type

            // But also provide secondary proto for the strongest attack
            // (Layer 3 can use this for targeted signature extraction)
            if (classification->top_attacks[1].score >= 0.3) {
                secondary_proto = attack_type_to_proto_cat(classification->top_attacks[1].type);
            }
        }
    }

    // If attack type is unknown but we have high protocol ratios, use heuristics
    if (primary_proto == PROTO_CAT_ALL && classification->primary_type == L2_ATTACK_VOLUMETRIC) {
        double tcp_ratio = snapshot->values[L2_FEAT_TCP_RATIO];
        double udp_ratio = snapshot->values[L2_FEAT_UDP_RATIO];
        double icmp_ratio = snapshot->values[L2_FEAT_ICMP_RATIO];

        if (tcp_ratio > 70.0) {
            primary_proto = PROTO_CAT_TCP;
        } else if (udp_ratio > 70.0) {
            primary_proto = PROTO_CAT_UDP;
        } else if (icmp_ratio > 30.0) {
            primary_proto = PROTO_CAT_ICMP;
        }
        // Otherwise keep as ALL
    }

    // Destination port detection (for amplification attacks or specific floods)
    uint16_t dst_port = 0;
    if (attack_type == ATTACK_TYPE_DNS_AMP) {
        dst_port = 53;  // DNS
    } else if (attack_type == ATTACK_TYPE_NTP_AMP) {
        dst_port = 123;  // NTP
    }
    // Note: Heavy hitter port detection would require additional analysis
    // that's done in Layer 1's per_ip_features tracking

    // Output results
    if (proto_cat_out) *proto_cat_out = primary_proto;
    if (attack_type_out) *attack_type_out = attack_type;
    if (dst_port_out) *dst_port_out = dst_port;
    if (secondary_proto_cat_out) *secondary_proto_cat_out = secondary_proto;
}
