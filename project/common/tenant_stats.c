/**
 * @file tenant_stats.c
 * @brief Per-Tenant Statistics Implementation (Phase 7.1)
 */

#include "tenant_stats.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

#ifdef DPDK_ENABLED
#include <rte_cycles.h>
#include <rte_malloc.h>
#define MALLOC(size) rte_zmalloc("tenant_stats", size, 64)
#define FREE(ptr) rte_free(ptr)
#define GET_TSC() rte_rdtsc()
#define TSC_HZ rte_get_tsc_hz()
#else
#define MALLOC(size) calloc(1, size)
#define FREE(ptr) free(ptr)
#define GET_TSC() 0
#define TSC_HZ 1000000000ULL
#endif

// Global stats manager instance
static struct tenant_stats_manager *g_stats_mgr = NULL;

// Drop reason names
static const char *drop_reason_names[] = {
    [DROP_REASON_NONE] = "none",
    [DROP_REASON_RATE_LIMIT] = "rate_limit",
    [DROP_REASON_BLACKLIST] = "blacklist",
    [DROP_REASON_SYN_PROXY_FAIL] = "syn_proxy_fail",
    [DROP_REASON_INVALID_PACKET] = "invalid_packet",
    [DROP_REASON_GEO_BLOCK] = "geo_block",
    [DROP_REASON_POLICY] = "policy",
    [DROP_REASON_SIGNATURE] = "signature",
    [DROP_REASON_ML_BLOCK] = "ml_block",
    [DROP_REASON_REPUTATION] = "reputation",
    [DROP_REASON_BOT_DETECTION] = "bot_detection",
    [DROP_REASON_CHALLENGE_FAIL] = "challenge_fail",
    [DROP_REASON_QUOTA_EXCEEDED] = "quota_exceeded",
    [DROP_REASON_MALFORMED] = "malformed",
    [DROP_REASON_TTL_EXPIRED] = "ttl_expired",
    [DROP_REASON_FRAGMENT] = "fragment",
    [DROP_REASON_OTHER] = "other",
};

// Attack type names
static const char *attack_type_names[] = {
    [ATTACK_TYPE_NONE] = "none",
    [ATTACK_TYPE_SYN_FLOOD] = "syn_flood",
    [ATTACK_TYPE_UDP_FLOOD] = "udp_flood",
    [ATTACK_TYPE_ICMP_FLOOD] = "icmp_flood",
    [ATTACK_TYPE_DNS_AMPLIFICATION] = "dns_amplification",
    [ATTACK_TYPE_NTP_AMPLIFICATION] = "ntp_amplification",
    [ATTACK_TYPE_SSDP_AMPLIFICATION] = "ssdp_amplification",
    [ATTACK_TYPE_HTTP_FLOOD] = "http_flood",
    [ATTACK_TYPE_SLOWLORIS] = "slowloris",
    [ATTACK_TYPE_SLOW_POST] = "slow_post",
    [ATTACK_TYPE_ACK_FLOOD] = "ack_flood",
    [ATTACK_TYPE_RST_FLOOD] = "rst_flood",
    [ATTACK_TYPE_FRAGMENTATION] = "fragmentation",
    [ATTACK_TYPE_MEMCACHED] = "memcached",
    [ATTACK_TYPE_MIXED] = "mixed",
    [ATTACK_TYPE_UNKNOWN] = "unknown",
};

// ==================== Initialization ====================

int tenant_stats_init(uint32_t num_lcores, uint32_t max_tenants) {
    if (g_stats_mgr != NULL) {
        return 0;  // Already initialized
    }

    g_stats_mgr = MALLOC(sizeof(struct tenant_stats_manager));
    if (!g_stats_mgr) {
        return -1;
    }

    g_stats_mgr->num_lcores = num_lcores;
    g_stats_mgr->max_tenants = max_tenants;

    // Allocate per-lcore stats arrays
    g_stats_mgr->lcore_stats = MALLOC(sizeof(struct tenant_lcore_stats*) * num_lcores);
    if (!g_stats_mgr->lcore_stats) {
        FREE(g_stats_mgr);
        g_stats_mgr = NULL;
        return -1;
    }

    for (uint32_t i = 0; i < num_lcores; i++) {
        g_stats_mgr->lcore_stats[i] = MALLOC(
            sizeof(struct tenant_lcore_stats) * max_tenants);
        if (!g_stats_mgr->lcore_stats[i]) {
            // Cleanup on failure
            for (uint32_t j = 0; j < i; j++) {
                FREE(g_stats_mgr->lcore_stats[j]);
            }
            FREE(g_stats_mgr->lcore_stats);
            FREE(g_stats_mgr);
            g_stats_mgr = NULL;
            return -1;
        }
        memset(g_stats_mgr->lcore_stats[i], 0,
               sizeof(struct tenant_lcore_stats) * max_tenants);
    }

    // Allocate aggregated stats
    g_stats_mgr->tenant_stats = MALLOC(
        sizeof(struct tenant_comprehensive_stats) * max_tenants);
    if (!g_stats_mgr->tenant_stats) {
        goto cleanup;
    }

    // Allocate history
    g_stats_mgr->history = MALLOC(
        sizeof(struct tenant_stats_history) * max_tenants);
    if (!g_stats_mgr->history) {
        goto cleanup;
    }

    // Initialize lock
    pthread_rwlock_init(&g_stats_mgr->lock, NULL);

    // Set defaults
    g_stats_mgr->aggregation_interval_tsc = TSC_HZ;  // 1 second
    g_stats_mgr->history_retention_hours = 24;
    g_stats_mgr->prometheus_enabled = false;
    g_stats_mgr->prometheus_port = 9100;

    return 0;

cleanup:
    for (uint32_t i = 0; i < num_lcores; i++) {
        if (g_stats_mgr->lcore_stats[i]) {
            FREE(g_stats_mgr->lcore_stats[i]);
        }
    }
    FREE(g_stats_mgr->lcore_stats);
    FREE(g_stats_mgr->tenant_stats);
    FREE(g_stats_mgr->history);
    FREE(g_stats_mgr);
    g_stats_mgr = NULL;
    return -1;
}

void tenant_stats_cleanup(void) {
    if (!g_stats_mgr) return;

    pthread_rwlock_destroy(&g_stats_mgr->lock);

    for (uint32_t i = 0; i < g_stats_mgr->num_lcores; i++) {
        FREE(g_stats_mgr->lcore_stats[i]);
    }
    FREE(g_stats_mgr->lcore_stats);
    FREE(g_stats_mgr->tenant_stats);
    FREE(g_stats_mgr->history);
    FREE(g_stats_mgr);
    g_stats_mgr = NULL;
}

struct tenant_lcore_stats* tenant_stats_get_lcore(uint32_t lcore_id,
                                                   tenant_id_t tenant_id) {
    if (!g_stats_mgr) return NULL;
    if (lcore_id >= g_stats_mgr->num_lcores) return NULL;
    if (tenant_id >= g_stats_mgr->max_tenants) return NULL;

    return &g_stats_mgr->lcore_stats[lcore_id][tenant_id];
}

// ==================== Aggregation ====================

int tenant_stats_aggregate(tenant_id_t tenant_id) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) {
        return -1;
    }

    pthread_rwlock_wrlock(&g_stats_mgr->lock);

    struct tenant_comprehensive_stats *stats = &g_stats_mgr->tenant_stats[tenant_id];
    uint64_t prev_packets_in = stats->traffic.packets_in;
    uint64_t prev_bytes_in = stats->traffic.bytes_in;

    // Reset traffic and security counters
    memset(&stats->traffic, 0, sizeof(stats->traffic));
    memset(&stats->security, 0, sizeof(stats->security));
    memset(&stats->layer1, 0, sizeof(stats->layer1));

    // Aggregate from all lcores
    for (uint32_t lcore = 0; lcore < g_stats_mgr->num_lcores; lcore++) {
        struct tenant_lcore_stats *lc = &g_stats_mgr->lcore_stats[lcore][tenant_id];

        // Traffic
        stats->traffic.packets_in += lc->packets_in;
        stats->traffic.packets_out += lc->packets_out;
        stats->traffic.bytes_in += lc->bytes_in;
        stats->traffic.bytes_out += lc->bytes_out;

        // Security drops
        for (int r = 0; r < DROP_REASON_MAX; r++) {
            stats->security.drops_by_reason[r] += lc->drops_by_reason[r];
            stats->security.total_drops += lc->drops_by_reason[r];
        }

        // Layer 1
        stats->layer1.rate_limit_hits += lc->l1_rate_limit_hits;
        stats->layer1.blacklist_hits += lc->l1_blacklist_hits;
        stats->layer1.whitelist_hits += lc->l1_whitelist_hits;
        stats->layer1.syn_proxy_challenges += lc->l1_syn_proxy_challenges;
        stats->layer1.syn_proxy_passed += lc->l1_syn_proxy_passed;
        stats->layer1.signature_hits += lc->l1_signature_hits;

        // Layer 4
        stats->layer4.challenges_issued += lc->l4_challenges_issued;
        stats->layer4.challenges_passed += lc->l4_challenges_passed;
        stats->layer4.bots_detected += lc->l4_bots_detected;
        stats->layer4.bots_blocked += lc->l4_bots_blocked;
    }

    // Calculate rates
    stats->traffic.current_pps = stats->traffic.packets_in - prev_packets_in;
    stats->traffic.current_bps = (stats->traffic.bytes_in - prev_bytes_in) * 8;

    // Update peaks
    if (stats->traffic.current_pps > stats->traffic.peak_pps_1m) {
        stats->traffic.peak_pps_1m = stats->traffic.current_pps;
    }
    if (stats->traffic.current_bps > stats->traffic.peak_bps_1m) {
        stats->traffic.peak_bps_1m = stats->traffic.current_bps;
    }
    if (stats->traffic.current_pps > stats->traffic.peak_pps_24h) {
        stats->traffic.peak_pps_24h = stats->traffic.current_pps;
    }
    if (stats->traffic.current_bps > stats->traffic.peak_bps_24h) {
        stats->traffic.peak_bps_24h = stats->traffic.current_bps;
    }

    // Calculate pass rates
    if (stats->layer1.syn_proxy_challenges > 0) {
        stats->layer1.syn_proxy_pass_rate =
            (stats->layer1.syn_proxy_passed * 100) / stats->layer1.syn_proxy_challenges;
    }
    if (stats->layer4.challenges_issued > 0) {
        stats->layer4.challenge_pass_rate =
            (double)stats->layer4.challenges_passed / stats->layer4.challenges_issued;
    }

    // Update timestamp
    stats->tenant_id = tenant_id;
    stats->timestamp = (uint64_t)time(NULL);

    pthread_rwlock_unlock(&g_stats_mgr->lock);
    return 0;
}

int tenant_stats_aggregate_all(void) {
    if (!g_stats_mgr) return 0;

    int count = 0;
    for (tenant_id_t t = 0; t < g_stats_mgr->max_tenants; t++) {
        if (tenant_stats_aggregate(t) == 0) {
            count++;
        }
    }
    return count;
}

void tenant_stats_maintenance(void) {
    if (!g_stats_mgr) return;

    uint64_t now = GET_TSC();

    // Check if aggregation is needed
    if (now - g_stats_mgr->last_aggregation_tsc >= g_stats_mgr->aggregation_interval_tsc) {
        tenant_stats_aggregate_all();
        g_stats_mgr->last_aggregation_tsc = now;

        // Record history points
        uint64_t ts = (uint64_t)time(NULL);
        pthread_rwlock_rdlock(&g_stats_mgr->lock);

        for (tenant_id_t t = 0; t < g_stats_mgr->max_tenants; t++) {
            struct tenant_comprehensive_stats *stats = &g_stats_mgr->tenant_stats[t];
            struct tenant_stats_history *hist = &g_stats_mgr->history[t];

            if (stats->traffic.packets_in > 0) {
                struct tenant_stats_point *point = &hist->points[hist->head];
                point->timestamp = ts;
                point->pps_in = stats->traffic.current_pps;
                point->bps_in = stats->traffic.current_bps;
                point->drops = stats->security.total_drops;
                point->attacks = stats->security.attacks_detected;
                point->anomaly_severity = stats->layer2.anomaly_severity;

                hist->head = (hist->head + 1) % STATS_HISTORY_SLOTS;
                if (hist->count < STATS_HISTORY_SLOTS) {
                    hist->count++;
                }
            }
        }

        pthread_rwlock_unlock(&g_stats_mgr->lock);
    }
}

// ==================== Query Functions ====================

int tenant_stats_get(tenant_id_t tenant_id,
                     struct tenant_comprehensive_stats *stats) {
    if (!g_stats_mgr || !stats || tenant_id >= g_stats_mgr->max_tenants) {
        return -1;
    }

    pthread_rwlock_rdlock(&g_stats_mgr->lock);
    memcpy(stats, &g_stats_mgr->tenant_stats[tenant_id], sizeof(*stats));
    pthread_rwlock_unlock(&g_stats_mgr->lock);

    return 0;
}

int tenant_stats_get_traffic(tenant_id_t tenant_id,
                              struct tenant_traffic_stats *stats) {
    if (!g_stats_mgr || !stats || tenant_id >= g_stats_mgr->max_tenants) {
        return -1;
    }

    pthread_rwlock_rdlock(&g_stats_mgr->lock);
    memcpy(stats, &g_stats_mgr->tenant_stats[tenant_id].traffic, sizeof(*stats));
    pthread_rwlock_unlock(&g_stats_mgr->lock);

    return 0;
}

int tenant_stats_get_security(tenant_id_t tenant_id,
                               struct tenant_security_stats *stats) {
    if (!g_stats_mgr || !stats || tenant_id >= g_stats_mgr->max_tenants) {
        return -1;
    }

    pthread_rwlock_rdlock(&g_stats_mgr->lock);
    memcpy(stats, &g_stats_mgr->tenant_stats[tenant_id].security, sizeof(*stats));
    pthread_rwlock_unlock(&g_stats_mgr->lock);

    return 0;
}

int tenant_stats_get_l1(tenant_id_t tenant_id, struct tenant_l1_stats *stats) {
    if (!g_stats_mgr || !stats || tenant_id >= g_stats_mgr->max_tenants) {
        return -1;
    }

    pthread_rwlock_rdlock(&g_stats_mgr->lock);
    memcpy(stats, &g_stats_mgr->tenant_stats[tenant_id].layer1, sizeof(*stats));
    pthread_rwlock_unlock(&g_stats_mgr->lock);

    return 0;
}

int tenant_stats_get_l2(tenant_id_t tenant_id, struct tenant_l2_stats *stats) {
    if (!g_stats_mgr || !stats || tenant_id >= g_stats_mgr->max_tenants) {
        return -1;
    }

    pthread_rwlock_rdlock(&g_stats_mgr->lock);
    memcpy(stats, &g_stats_mgr->tenant_stats[tenant_id].layer2, sizeof(*stats));
    pthread_rwlock_unlock(&g_stats_mgr->lock);

    return 0;
}

int tenant_stats_get_l3(tenant_id_t tenant_id, struct tenant_l3_stats *stats) {
    if (!g_stats_mgr || !stats || tenant_id >= g_stats_mgr->max_tenants) {
        return -1;
    }

    pthread_rwlock_rdlock(&g_stats_mgr->lock);
    memcpy(stats, &g_stats_mgr->tenant_stats[tenant_id].layer3, sizeof(*stats));
    pthread_rwlock_unlock(&g_stats_mgr->lock);

    return 0;
}

int tenant_stats_get_l4(tenant_id_t tenant_id, struct tenant_l4_stats *stats) {
    if (!g_stats_mgr || !stats || tenant_id >= g_stats_mgr->max_tenants) {
        return -1;
    }

    pthread_rwlock_rdlock(&g_stats_mgr->lock);
    memcpy(stats, &g_stats_mgr->tenant_stats[tenant_id].layer4, sizeof(*stats));
    pthread_rwlock_unlock(&g_stats_mgr->lock);

    return 0;
}

int tenant_stats_get_l5(tenant_id_t tenant_id, struct tenant_l5_stats *stats) {
    if (!g_stats_mgr || !stats || tenant_id >= g_stats_mgr->max_tenants) {
        return -1;
    }

    pthread_rwlock_rdlock(&g_stats_mgr->lock);
    memcpy(stats, &g_stats_mgr->tenant_stats[tenant_id].layer5, sizeof(*stats));
    pthread_rwlock_unlock(&g_stats_mgr->lock);

    return 0;
}

int tenant_stats_get_sla(tenant_id_t tenant_id, struct tenant_sla_stats *stats) {
    if (!g_stats_mgr || !stats || tenant_id >= g_stats_mgr->max_tenants) {
        return -1;
    }

    pthread_rwlock_rdlock(&g_stats_mgr->lock);
    memcpy(stats, &g_stats_mgr->tenant_stats[tenant_id].sla, sizeof(*stats));
    pthread_rwlock_unlock(&g_stats_mgr->lock);

    return 0;
}

// ==================== Historical Data ====================

int tenant_stats_get_history(tenant_id_t tenant_id,
                              uint64_t start_time, uint64_t end_time,
                              struct tenant_stats_point *points,
                              int max_points) {
    if (!g_stats_mgr || !points || tenant_id >= g_stats_mgr->max_tenants) {
        return 0;
    }

    if (end_time == 0) {
        end_time = (uint64_t)time(NULL);
    }

    pthread_rwlock_rdlock(&g_stats_mgr->lock);

    struct tenant_stats_history *hist = &g_stats_mgr->history[tenant_id];
    int count = 0;

    // Iterate through history ring buffer
    for (uint32_t i = 0; i < hist->count && count < max_points; i++) {
        uint32_t idx = (hist->head + STATS_HISTORY_SLOTS - hist->count + i) % STATS_HISTORY_SLOTS;
        struct tenant_stats_point *p = &hist->points[idx];

        if (p->timestamp >= start_time && p->timestamp <= end_time) {
            memcpy(&points[count], p, sizeof(*p));
            count++;
        }
    }

    pthread_rwlock_unlock(&g_stats_mgr->lock);
    return count;
}

int tenant_stats_get_peak(tenant_id_t tenant_id,
                          uint64_t start_time, uint64_t end_time,
                          uint64_t *peak_pps, uint64_t *peak_bps) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) {
        return -1;
    }

    if (end_time == 0) {
        end_time = (uint64_t)time(NULL);
    }

    uint64_t max_pps = 0, max_bps = 0;

    pthread_rwlock_rdlock(&g_stats_mgr->lock);

    struct tenant_stats_history *hist = &g_stats_mgr->history[tenant_id];

    for (uint32_t i = 0; i < hist->count; i++) {
        uint32_t idx = (hist->head + STATS_HISTORY_SLOTS - hist->count + i) % STATS_HISTORY_SLOTS;
        struct tenant_stats_point *p = &hist->points[idx];

        if (p->timestamp >= start_time && p->timestamp <= end_time) {
            if (p->pps_in > max_pps) max_pps = p->pps_in;
            if (p->bps_in > max_bps) max_bps = p->bps_in;
        }
    }

    pthread_rwlock_unlock(&g_stats_mgr->lock);

    if (peak_pps) *peak_pps = max_pps;
    if (peak_bps) *peak_bps = max_bps;

    return 0;
}

// ==================== Update Functions ====================

void tenant_stats_update_l2(tenant_id_t tenant_id,
                            double z_score, bool anomaly_active,
                            uint8_t severity, uint8_t protocol) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_stats_mgr->lock);

    struct tenant_l2_stats *l2 = &g_stats_mgr->tenant_stats[tenant_id].layer2;

    // Track anomaly transitions
    if (anomaly_active && !l2->anomaly_active) {
        l2->total_anomalies++;
    }

    l2->current_z_score = z_score;
    l2->anomaly_active = anomaly_active;
    l2->anomaly_severity = severity;
    l2->anomaly_protocol = protocol;

    pthread_rwlock_unlock(&g_stats_mgr->lock);
}

void tenant_stats_update_l3(tenant_id_t tenant_id,
                            uint64_t inferences, uint64_t policies,
                            double precision, double recall) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_stats_mgr->lock);

    struct tenant_l3_stats *l3 = &g_stats_mgr->tenant_stats[tenant_id].layer3;
    l3->ml_inferences += inferences;
    l3->policies_generated += policies;
    l3->model_precision = precision;
    l3->model_recall = recall;
    if (precision + recall > 0) {
        l3->model_f1 = 2 * precision * recall / (precision + recall);
    }

    pthread_rwlock_unlock(&g_stats_mgr->lock);
}

void tenant_stats_update_l4(tenant_id_t tenant_id,
                            double avg_reputation,
                            uint64_t trusted, uint64_t suspicious,
                            uint64_t attackers) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_stats_mgr->lock);

    struct tenant_l4_stats *l4 = &g_stats_mgr->tenant_stats[tenant_id].layer4;
    l4->avg_reputation_score = avg_reputation;
    l4->trusted_ips = trusted;
    l4->suspicious_ips = suspicious;
    l4->attacker_ips = attackers;

    pthread_rwlock_unlock(&g_stats_mgr->lock);
}

void tenant_stats_update_l5(tenant_id_t tenant_id,
                            uint64_t threat_hits, uint64_t warnings,
                            uint64_t reports) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_stats_mgr->lock);

    struct tenant_l5_stats *l5 = &g_stats_mgr->tenant_stats[tenant_id].layer5;
    l5->threat_intel_hits += threat_hits;
    l5->early_warnings_sent += warnings;
    l5->reports_generated += reports;

    pthread_rwlock_unlock(&g_stats_mgr->lock);
}

void tenant_stats_attack_detected(tenant_id_t tenant_id,
                                   attack_type_t type,
                                   double detection_time_ms) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_stats_mgr->lock);

    struct tenant_security_stats *sec = &g_stats_mgr->tenant_stats[tenant_id].security;
    sec->attacks_detected++;

    if (type < ATTACK_TYPE_MAX) {
        sec->attacks_by_type[type]++;
    }

    // Update average detection time
    double total = sec->avg_detection_time_ms * (sec->attacks_detected - 1);
    sec->avg_detection_time_ms = (total + detection_time_ms) / sec->attacks_detected;

    // Update SLA metrics
    struct tenant_sla_stats *sla = &g_stats_mgr->tenant_stats[tenant_id].sla;
    double total_mttd = sla->mttd_sec * sla->incidents_count;
    sla->incidents_count++;
    sla->mttd_sec = (total_mttd + detection_time_ms / 1000.0) / sla->incidents_count;

    pthread_rwlock_unlock(&g_stats_mgr->lock);
}

void tenant_stats_attack_mitigated(tenant_id_t tenant_id,
                                    double mitigation_time_ms,
                                    bool effective) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_stats_mgr->lock);

    struct tenant_security_stats *sec = &g_stats_mgr->tenant_stats[tenant_id].security;
    sec->attacks_mitigated++;

    // Update average mitigation time
    double total = sec->avg_mitigation_time_ms * (sec->attacks_mitigated - 1);
    sec->avg_mitigation_time_ms = (total + mitigation_time_ms) / sec->attacks_mitigated;

    // Update SLA metrics
    struct tenant_sla_stats *sla = &g_stats_mgr->tenant_stats[tenant_id].sla;
    double total_mttr = sla->mttr_sec * (sec->attacks_mitigated - 1);
    sla->mttr_sec = (total_mttr + mitigation_time_ms / 1000.0) / sec->attacks_mitigated;

    // Update effectiveness
    double total_eff = sla->mitigation_effectiveness * (sec->attacks_mitigated - 1);
    sla->mitigation_effectiveness = (total_eff + (effective ? 1.0 : 0.0)) / sec->attacks_mitigated;

    pthread_rwlock_unlock(&g_stats_mgr->lock);
}

void tenant_stats_false_positive(tenant_id_t tenant_id) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_stats_mgr->lock);

    g_stats_mgr->tenant_stats[tenant_id].security.false_positives++;

    // Update FP rate
    struct tenant_sla_stats *sla = &g_stats_mgr->tenant_stats[tenant_id].sla;
    uint64_t total_detections = g_stats_mgr->tenant_stats[tenant_id].security.attacks_detected +
                                 g_stats_mgr->tenant_stats[tenant_id].security.false_positives;
    if (total_detections > 0) {
        sla->false_positive_rate = (double)g_stats_mgr->tenant_stats[tenant_id].security.false_positives /
                                    total_detections;
    }

    pthread_rwlock_unlock(&g_stats_mgr->lock);
}

void tenant_stats_false_negative(tenant_id_t tenant_id) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_stats_mgr->lock);
    g_stats_mgr->tenant_stats[tenant_id].security.false_negatives++;
    pthread_rwlock_unlock(&g_stats_mgr->lock);
}

// ==================== SLA Functions ====================

void tenant_stats_sla_update(tenant_id_t tenant_id,
                              bool available, uint64_t duration_sec) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_stats_mgr->lock);

    struct tenant_sla_stats *sla = &g_stats_mgr->tenant_stats[tenant_id].sla;

    if (available) {
        sla->total_uptime_sec += duration_sec;
    } else {
        sla->total_downtime_sec += duration_sec;
    }

    uint64_t total = sla->total_uptime_sec + sla->total_downtime_sec;
    if (total > 0) {
        sla->availability_percent = (double)sla->total_uptime_sec * 100.0 / total;
    }

    pthread_rwlock_unlock(&g_stats_mgr->lock);
}

bool tenant_stats_sla_check(tenant_id_t tenant_id,
                            double min_availability, double max_fp_rate) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) return false;

    pthread_rwlock_rdlock(&g_stats_mgr->lock);

    struct tenant_sla_stats *sla = &g_stats_mgr->tenant_stats[tenant_id].sla;
    bool compliant = (sla->availability_percent >= min_availability &&
                      sla->false_positive_rate <= max_fp_rate);

    if (!compliant && !sla->sla_breach) {
        // Mark breach (need write lock)
        pthread_rwlock_unlock(&g_stats_mgr->lock);
        pthread_rwlock_wrlock(&g_stats_mgr->lock);
        sla->sla_breach = true;
        sla->sla_breaches_count++;
        pthread_rwlock_unlock(&g_stats_mgr->lock);
        return false;
    }

    pthread_rwlock_unlock(&g_stats_mgr->lock);
    return compliant;
}

// ==================== Export Functions ====================

int tenant_stats_export_json(tenant_id_t tenant_id,
                              char *buf, size_t buf_size) {
    if (!g_stats_mgr || !buf || tenant_id >= g_stats_mgr->max_tenants) {
        return 0;
    }

    pthread_rwlock_rdlock(&g_stats_mgr->lock);

    struct tenant_comprehensive_stats *s = &g_stats_mgr->tenant_stats[tenant_id];

    int n = snprintf(buf, buf_size,
        "{"
        "\"tenant_id\":%u,"
        "\"timestamp\":%lu,"
        "\"traffic\":{"
            "\"packets_in\":%lu,\"packets_out\":%lu,"
            "\"bytes_in\":%lu,\"bytes_out\":%lu,"
            "\"current_pps\":%lu,\"current_bps\":%lu,"
            "\"peak_pps_24h\":%lu,\"peak_bps_24h\":%lu"
        "},"
        "\"security\":{"
            "\"total_drops\":%lu,"
            "\"attacks_detected\":%lu,"
            "\"attacks_mitigated\":%lu,"
            "\"false_positives\":%lu"
        "},"
        "\"layer1\":{"
            "\"rate_limit_hits\":%lu,"
            "\"blacklist_hits\":%lu,"
            "\"syn_proxy_challenges\":%lu,"
            "\"syn_proxy_pass_rate\":%lu"
        "},"
        "\"layer2\":{"
            "\"z_score\":%.2f,"
            "\"anomaly_active\":%s,"
            "\"anomaly_severity\":%u"
        "},"
        "\"layer3\":{"
            "\"ml_inferences\":%lu,"
            "\"policies_generated\":%lu,"
            "\"model_f1\":%.3f"
        "},"
        "\"layer4\":{"
            "\"avg_reputation\":%.3f,"
            "\"challenges_issued\":%lu,"
            "\"bots_blocked\":%lu"
        "},"
        "\"sla\":{"
            "\"availability_percent\":%.4f,"
            "\"mitigation_effectiveness\":%.3f,"
            "\"sla_breach\":%s"
        "}"
        "}",
        tenant_id,
        s->timestamp,
        s->traffic.packets_in, s->traffic.packets_out,
        s->traffic.bytes_in, s->traffic.bytes_out,
        s->traffic.current_pps, s->traffic.current_bps,
        s->traffic.peak_pps_24h, s->traffic.peak_bps_24h,
        s->security.total_drops,
        s->security.attacks_detected,
        s->security.attacks_mitigated,
        s->security.false_positives,
        s->layer1.rate_limit_hits,
        s->layer1.blacklist_hits,
        s->layer1.syn_proxy_challenges,
        s->layer1.syn_proxy_pass_rate,
        s->layer2.current_z_score,
        s->layer2.anomaly_active ? "true" : "false",
        s->layer2.anomaly_severity,
        s->layer3.ml_inferences,
        s->layer3.policies_generated,
        s->layer3.model_f1,
        s->layer4.avg_reputation_score,
        s->layer4.challenges_issued,
        s->layer4.bots_blocked,
        s->sla.availability_percent,
        s->sla.mitigation_effectiveness,
        s->sla.sla_breach ? "true" : "false"
    );

    pthread_rwlock_unlock(&g_stats_mgr->lock);
    return n;
}

int tenant_stats_export_prometheus(tenant_id_t tenant_id,
                                    char *buf, size_t buf_size) {
    if (!g_stats_mgr || !buf) return 0;

    int written = 0;
    char *p = buf;
    size_t remaining = buf_size;

    pthread_rwlock_rdlock(&g_stats_mgr->lock);

    // Determine range
    tenant_id_t start = (tenant_id == 0) ? 1 : tenant_id;
    tenant_id_t end = (tenant_id == 0) ? (tenant_id_t)g_stats_mgr->max_tenants : (tenant_id_t)(tenant_id + 1);

    for (tenant_id_t t = start; t < end; t++) {
        struct tenant_comprehensive_stats *s = &g_stats_mgr->tenant_stats[t];

        // Skip inactive tenants
        if (s->traffic.packets_in == 0 && s->traffic.packets_out == 0) {
            continue;
        }

        int n = snprintf(p, remaining,
            "# Tenant %u metrics\n"
            "antiddos_tenant_traffic_pps{tenant_id=\"%u\",direction=\"in\"} %lu\n"
            "antiddos_tenant_traffic_bps{tenant_id=\"%u\",direction=\"in\"} %lu\n"
            "antiddos_tenant_traffic_pps{tenant_id=\"%u\",direction=\"out\"} %lu\n"
            "antiddos_tenant_drops_total{tenant_id=\"%u\"} %lu\n"
            "antiddos_tenant_attacks_total{tenant_id=\"%u\"} %lu\n"
            "antiddos_tenant_attacks_mitigated{tenant_id=\"%u\"} %lu\n"
            "antiddos_tenant_anomaly_active{tenant_id=\"%u\"} %d\n"
            "antiddos_tenant_anomaly_severity{tenant_id=\"%u\"} %u\n"
            "antiddos_tenant_ml_inferences{tenant_id=\"%u\"} %lu\n"
            "antiddos_tenant_policies_generated{tenant_id=\"%u\"} %lu\n"
            "antiddos_tenant_reputation_avg{tenant_id=\"%u\"} %.3f\n"
            "antiddos_tenant_challenges_total{tenant_id=\"%u\",result=\"passed\"} %lu\n"
            "antiddos_tenant_challenges_total{tenant_id=\"%u\",result=\"failed\"} %lu\n"
            "antiddos_tenant_bots_blocked{tenant_id=\"%u\"} %lu\n"
            "antiddos_tenant_availability_ratio{tenant_id=\"%u\"} %.6f\n"
            "antiddos_tenant_mitigation_effectiveness{tenant_id=\"%u\"} %.3f\n"
            "antiddos_tenant_sla_breach{tenant_id=\"%u\"} %d\n"
            "\n",
            t,
            t, s->traffic.current_pps,
            t, s->traffic.current_bps,
            t, s->traffic.packets_out - (s->traffic.packets_out > 0 ? s->traffic.packets_out : 0),
            t, s->security.total_drops,
            t, s->security.attacks_detected,
            t, s->security.attacks_mitigated,
            t, s->layer2.anomaly_active ? 1 : 0,
            t, s->layer2.anomaly_severity,
            t, s->layer3.ml_inferences,
            t, s->layer3.policies_generated,
            t, s->layer4.avg_reputation_score,
            t, s->layer4.challenges_passed,
            t, s->layer4.challenges_issued - s->layer4.challenges_passed,
            t, s->layer4.bots_blocked,
            t, s->sla.availability_percent / 100.0,
            t, s->sla.mitigation_effectiveness,
            t, s->sla.sla_breach ? 1 : 0
        );

        if (n > 0 && (size_t)n < remaining) {
            p += n;
            remaining -= n;
            written += n;
        } else {
            break;
        }
    }

    pthread_rwlock_unlock(&g_stats_mgr->lock);
    return written;
}

// ==================== Reset Functions ====================

void tenant_stats_reset(tenant_id_t tenant_id) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_stats_mgr->lock);

    // Reset lcore stats
    for (uint32_t lcore = 0; lcore < g_stats_mgr->num_lcores; lcore++) {
        memset(&g_stats_mgr->lcore_stats[lcore][tenant_id], 0,
               sizeof(struct tenant_lcore_stats));
    }

    // Reset aggregated stats
    memset(&g_stats_mgr->tenant_stats[tenant_id], 0,
           sizeof(struct tenant_comprehensive_stats));

    pthread_rwlock_unlock(&g_stats_mgr->lock);
}

void tenant_stats_reset_all(void) {
    if (!g_stats_mgr) return;

    for (tenant_id_t t = 0; t < g_stats_mgr->max_tenants; t++) {
        tenant_stats_reset(t);
    }
}

void tenant_stats_clear_history(tenant_id_t tenant_id) {
    if (!g_stats_mgr || tenant_id >= g_stats_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_stats_mgr->lock);
    memset(&g_stats_mgr->history[tenant_id], 0,
           sizeof(struct tenant_stats_history));
    pthread_rwlock_unlock(&g_stats_mgr->lock);
}

// ==================== Utility ====================

const char* tenant_stats_drop_reason_name(drop_reason_t reason) {
    if (reason >= DROP_REASON_MAX) return "unknown";
    return drop_reason_names[reason];
}

const char* tenant_stats_attack_type_name(attack_type_t type) {
    if (type >= ATTACK_TYPE_MAX) return "unknown";
    return attack_type_names[type];
}

void tenant_stats_get_status(uint32_t *num_tenants, uint64_t *total_packets) {
    if (!g_stats_mgr) {
        if (num_tenants) *num_tenants = 0;
        if (total_packets) *total_packets = 0;
        return;
    }

    uint32_t active = 0;
    uint64_t packets = 0;

    pthread_rwlock_rdlock(&g_stats_mgr->lock);

    for (tenant_id_t t = 0; t < g_stats_mgr->max_tenants; t++) {
        if (g_stats_mgr->tenant_stats[t].traffic.packets_in > 0) {
            active++;
            packets += g_stats_mgr->tenant_stats[t].traffic.packets_in;
        }
    }

    pthread_rwlock_unlock(&g_stats_mgr->lock);

    if (num_tenants) *num_tenants = active;
    if (total_packets) *total_packets = packets;
}
