/**
 * @file tenant_anomaly.c
 * @brief Per-Tenant Anomaly Detection and Aggregation Implementation
 *
 * Aggregates per-IP anomaly detection into tenant-wide state with:
 * - Attack type classification
 * - Severity calculation
 * - Timeline tracking
 * - Callback notifications for L3/L4
 */

#include "tenant_anomaly.h"
#include "baselines.h"
#include "../common/tenant.h"
#include "../common/tenant_config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <pthread.h>

// ==================== Internal State ====================

// Per-tenant anomaly states
static struct tenant_anomaly_state *g_tenant_states[MAX_TENANTS];

// Global state aggregation
static struct global_anomaly_state g_global_state;

// Callbacks
static tenant_attack_callback_t g_attack_callback = NULL;
static void *g_attack_callback_ctx = NULL;
static tenant_escalation_callback_t g_escalation_callback = NULL;
static void *g_escalation_callback_ctx = NULL;

// Initialization flag
static bool g_initialized = false;

// FIX BUG L2-2: Mutex for thread-safe state init/cleanup
// Protects g_tenant_states array modifications
static pthread_mutex_t g_tenant_state_lock = PTHREAD_MUTEX_INITIALIZER;

// Default thresholds
#define DEFAULT_Z_THRESHOLD         3.0
#define DEFAULT_SENSITIVITY         1.0
#define SEVERITY_Z_LOW             3.0
#define SEVERITY_Z_MEDIUM          4.0
#define SEVERITY_Z_HIGH            5.0
#define SEVERITY_Z_SEVERE          7.0
#define SEVERITY_Z_CRITICAL        10.0

// Attack timeout (ns) - attack considered ended after this quiet period
#define ATTACK_TIMEOUT_NS          (30ULL * 1000000000ULL)  // 30 seconds

// 24-hour window in nanoseconds
#define WINDOW_24H_NS              (24ULL * 60 * 60 * 1000000000ULL)

// ==================== String Tables ====================

static const char *attack_type_names[] = {
    "NONE",
    "SYN_FLOOD",
    "UDP_FLOOD",
    "ICMP_FLOOD",
    "HTTP_FLOOD",
    "SLOWLORIS",
    "DNS_AMPLIFICATION",
    "NTP_AMPLIFICATION",
    "MEMCACHED_AMPLIFICATION",
    "SSDP_AMPLIFICATION",
    "ACK_FLOOD",
    "RST_FLOOD",
    "FRAGMENT_FLOOD",
    "MIXED",
    "UNKNOWN"
};

static const char *severity_names[] = {
    "NONE",
    "LOW",
    "MEDIUM",
    "HIGH",
    "SEVERE",
    "CRITICAL"
};

const char* attack_type_to_string(attack_type_t type) {
    if (type >= ATTACK_TYPE_COUNT) {
        return "INVALID";
    }
    return attack_type_names[type];
}

const char* attack_severity_to_string(attack_severity_t severity) {
    if (severity > SEVERITY_CRITICAL) {
        return "INVALID";
    }
    return severity_names[severity];
}

// ==================== Time Utilities ====================

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// ==================== Initialization ====================

int tenant_anomaly_init(void) {
    if (g_initialized) {
        return 0;
    }

    memset(g_tenant_states, 0, sizeof(g_tenant_states));
    memset(&g_global_state, 0, sizeof(g_global_state));

    g_initialized = true;
    return 0;
}

void tenant_anomaly_cleanup(void) {
    if (!g_initialized) {
        return;
    }

    for (uint32_t i = 0; i < MAX_TENANTS; i++) {
        if (g_tenant_states[i]) {
            free(g_tenant_states[i]);
            g_tenant_states[i] = NULL;
        }
    }

    g_attack_callback = NULL;
    g_escalation_callback = NULL;
    g_initialized = false;
}

int tenant_anomaly_state_init(tenant_id_t tenant_id,
                              const struct tenant_l2_config *config) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return -1;
    }

    struct tenant_anomaly_state *state = calloc(1, sizeof(struct tenant_anomaly_state));
    if (!state) {
        return -1;
    }

    state->tenant_id = tenant_id;
    atomic_store(&state->initialized, true);
    atomic_store(&state->last_update_ns, get_time_ns());

    // Apply config (FIX BUG L2-3: use atomic fixed-point fields)
    double sens_mult, z_thresh;
    if (config) {
        sens_mult = config->thresholds.sensitivity_multiplier > 0
            ? config->thresholds.sensitivity_multiplier : DEFAULT_SENSITIVITY;
        z_thresh = config->thresholds.z_score_threshold > 0
            ? config->thresholds.z_score_threshold * sens_mult
            : DEFAULT_Z_THRESHOLD * sens_mult;
    } else {
        sens_mult = DEFAULT_SENSITIVITY;
        z_thresh = DEFAULT_Z_THRESHOLD;
    }
    atomic_store(&state->sensitivity_multiplier_fp, DOUBLE_TO_FP(sens_mult));
    atomic_store(&state->effective_z_threshold_fp, DOUBLE_TO_FP(z_thresh));

    // FIX BUG L2-2: Thread-safe state swap
    // Use mutex to protect the pointer swap and delay free to allow readers to complete
    pthread_mutex_lock(&g_tenant_state_lock);

    struct tenant_anomaly_state *old_state = g_tenant_states[tenant_id];

    // Memory barrier before making new state visible
    __atomic_thread_fence(__ATOMIC_RELEASE);

    g_tenant_states[tenant_id] = state;

    pthread_mutex_unlock(&g_tenant_state_lock);

    // Delay free to allow any in-flight readers to complete
    // This is a simple grace period; in production, use RCU or epoch-based reclamation
    if (old_state) {
        // Mark as not initialized to signal readers
        old_state->initialized = false;
        __atomic_thread_fence(__ATOMIC_RELEASE);

        // Brief delay for readers to notice
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };  // 1ms
        nanosleep(&ts, NULL);

        free(old_state);
    }

    return 0;
}

void tenant_anomaly_state_cleanup(tenant_id_t tenant_id) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return;
    }

    // FIX BUG L2-2: Thread-safe cleanup with grace period
    pthread_mutex_lock(&g_tenant_state_lock);

    struct tenant_anomaly_state *old_state = g_tenant_states[tenant_id];
    g_tenant_states[tenant_id] = NULL;

    pthread_mutex_unlock(&g_tenant_state_lock);

    if (old_state) {
        // Mark as not initialized to signal readers
        old_state->initialized = false;
        __atomic_thread_fence(__ATOMIC_RELEASE);

        // Brief delay for readers to complete
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };  // 1ms
        nanosleep(&ts, NULL);

        free(old_state);
    }
}

// ==================== Attack Classification ====================

attack_type_t classify_attack_type(const int *anomalous_features,
                                   int feature_count,
                                   const double *z_scores) {
    if (!anomalous_features || feature_count == 0 || !z_scores) {
        return ATTACK_TYPE_UNKNOWN;
    }

    // Count indicators for each attack type
    int syn_indicators = 0;
    int udp_indicators = 0;
    int icmp_indicators = 0;
    int amp_indicators = 0;
    int ack_indicators = 0;
    int rst_indicators = 0;

    for (int i = 0; i < feature_count; i++) {
        int feat = anomalous_features[i];

        switch (feat) {
            case L2_FEAT_SYN_PER_SEC:
                syn_indicators += 3;  // Strong indicator
                break;
            case L2_FEAT_SYN_ACK_RATIO:
                syn_indicators += 2;
                break;
            case L2_FEAT_UDP_RATIO:
            case L2_FEAT_BYTES_PER_PACKET:  // Large packets often indicate amp
                udp_indicators += 2;
                if (z_scores[L2_FEAT_BYTES_PER_PACKET] > 5.0) {
                    amp_indicators += 2;  // Large packets = amplification
                }
                break;
            case L2_FEAT_ICMP_RATIO:
                icmp_indicators += 3;
                break;
            case L2_FEAT_ACK_PER_SEC:
                ack_indicators += 2;
                break;
            case L2_FEAT_RST_PER_SEC:
            case L2_FEAT_RST_SYN_RATIO:
                rst_indicators += 2;
                break;
            case L2_FEAT_UNIQUE_SRC_IPS:
                // High unique IPs with high volume suggests distributed attack
                if (z_scores[feat] > 5.0) {
                    syn_indicators += 1;
                    udp_indicators += 1;
                }
                break;
            case L2_FEAT_NEW_SRCIP_RATE:
                // High churn suggests spoofed sources
                syn_indicators += 1;
                amp_indicators += 1;
                break;
            default:
                break;
        }
    }

    // Determine dominant attack type
    int max_score = 0;
    attack_type_t type = ATTACK_TYPE_UNKNOWN;

    if (syn_indicators > max_score) {
        max_score = syn_indicators;
        type = ATTACK_TYPE_SYN_FLOOD;
    }
    if (udp_indicators > max_score) {
        max_score = udp_indicators;
        type = amp_indicators > udp_indicators / 2 ?
               ATTACK_TYPE_DNS_AMPLIFICATION : ATTACK_TYPE_UDP_FLOOD;
    }
    if (icmp_indicators > max_score) {
        max_score = icmp_indicators;
        type = ATTACK_TYPE_ICMP_FLOOD;
    }
    if (ack_indicators > max_score) {
        max_score = ack_indicators;
        type = ATTACK_TYPE_ACK_FLOOD;
    }
    if (rst_indicators > max_score) {
        max_score = rst_indicators;
        type = ATTACK_TYPE_RST_FLOOD;
    }

    // Check for mixed attack
    int types_above_threshold = 0;
    if (syn_indicators >= 3) types_above_threshold++;
    if (udp_indicators >= 3) types_above_threshold++;
    if (icmp_indicators >= 3) types_above_threshold++;
    if (ack_indicators >= 3) types_above_threshold++;
    if (rst_indicators >= 3) types_above_threshold++;

    if (types_above_threshold >= 2) {
        type = ATTACK_TYPE_MIXED;
    }

    return type;
}

attack_severity_t calculate_severity(double max_z_score,
                                     uint32_t anomalous_ip_count,
                                     uint64_t attack_pps) {
    // Base severity from z-score
    attack_severity_t severity = SEVERITY_NONE;

    if (max_z_score >= SEVERITY_Z_CRITICAL) {
        severity = SEVERITY_CRITICAL;
    } else if (max_z_score >= SEVERITY_Z_SEVERE) {
        severity = SEVERITY_SEVERE;
    } else if (max_z_score >= SEVERITY_Z_HIGH) {
        severity = SEVERITY_HIGH;
    } else if (max_z_score >= SEVERITY_Z_MEDIUM) {
        severity = SEVERITY_MEDIUM;
    } else if (max_z_score >= SEVERITY_Z_LOW) {
        severity = SEVERITY_LOW;
    }

    // Escalate based on number of affected IPs
    if (anomalous_ip_count >= 10 && severity < SEVERITY_HIGH) {
        severity = SEVERITY_HIGH;
    } else if (anomalous_ip_count >= 50 && severity < SEVERITY_SEVERE) {
        severity = SEVERITY_SEVERE;
    } else if (anomalous_ip_count >= 100) {
        severity = SEVERITY_CRITICAL;
    }

    // Escalate based on attack volume
    if (attack_pps >= 10000000 && severity < SEVERITY_CRITICAL) {  // 10 Mpps
        severity = SEVERITY_CRITICAL;
    } else if (attack_pps >= 1000000 && severity < SEVERITY_SEVERE) {  // 1 Mpps
        severity = SEVERITY_SEVERE;
    } else if (attack_pps >= 100000 && severity < SEVERITY_HIGH) {  // 100 Kpps
        severity = SEVERITY_HIGH;
    }

    return severity;
}

// ==================== Update API ====================

void tenant_anomaly_report_ip(tenant_id_t tenant_id,
                              uint32_t dst_ip __attribute__((unused)),
                              double z_score,
                              uint32_t anomaly_level __attribute__((unused)),
                              attack_type_t attack_type) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state) {
        return;
    }

    uint64_t now = get_time_ns();
    bool was_under_attack = atomic_load(&state->under_attack);
    attack_severity_t old_severity = atomic_load(&state->current_severity);

    // Update anomalous IP count
    atomic_fetch_add(&state->anomalous_ip_count, 1);
    atomic_store(&state->any_ip_anomalous, true);

    // FIX BUG L2-3 & L2-5: Update max z-score atomically using CAS
    // Only update if new value is higher (proper max tracking)
    uint64_t new_z_fp = DOUBLE_TO_FP(z_score);
    uint64_t current_max_fp = atomic_load(&state->max_z_score_fp);
    while (new_z_fp > current_max_fp) {
        if (atomic_compare_exchange_weak(&state->max_z_score_fp, &current_max_fp, new_z_fp)) {
            break;
        }
    }

    // Update attack type counts
    switch (attack_type) {
        case ATTACK_TYPE_SYN_FLOOD:
            atomic_fetch_add(&state->syn_flood_count, 1);
            break;
        case ATTACK_TYPE_UDP_FLOOD:
        case ATTACK_TYPE_DNS_AMPLIFICATION:
        case ATTACK_TYPE_NTP_AMPLIFICATION:
        case ATTACK_TYPE_MEMCACHED_AMP:
        case ATTACK_TYPE_SSDP_AMPLIFICATION:
            if (attack_type == ATTACK_TYPE_UDP_FLOOD) {
                atomic_fetch_add(&state->udp_flood_count, 1);
            }
            atomic_fetch_add(&state->amp_attack_count, 1);
            break;
        case ATTACK_TYPE_HTTP_FLOOD:
        case ATTACK_TYPE_SLOWLORIS:
            atomic_fetch_add(&state->http_flood_count, 1);
            break;
        default:
            atomic_fetch_add(&state->other_attack_count, 1);
            break;
    }

    // Calculate new severity (FIX BUG L2-3: use atomic read)
    attack_severity_t new_severity = calculate_severity(
        FP_TO_DOUBLE(atomic_load(&state->max_z_score_fp)),
        atomic_load(&state->anomalous_ip_count),
        atomic_load(&state->total_pps)
    );

    // Update state
    // FIX BUG L2-6: Use CAS to atomically transition from not-under-attack to under-attack
    // This prevents two concurrent threads from both starting the attack
    if (!was_under_attack && new_severity > SEVERITY_NONE) {
        // Try to atomically set under_attack from false to true
        bool expected = false;
        if (atomic_compare_exchange_strong(&state->under_attack, &expected, true)) {
            // We won the race - we're the one starting the attack
            atomic_store(&state->attack_start_ns, now);
            atomic_store(&state->state_change_ns, now);
            atomic_fetch_add(&state->attack_count_24h, 1);

            // Trigger callback (only once, by the winner)
            if (g_attack_callback) {
                g_attack_callback(tenant_id, new_severity, attack_type, g_attack_callback_ctx);
            }
        }
        // If CAS failed, another thread already started the attack - that's fine
    }

    // Update severity
    atomic_store(&state->current_severity, new_severity);

    // FIX BUG L2-5: Update max_severity using CAS (only if higher)
    uint8_t current_max = atomic_load(&state->max_severity);
    while (new_severity > current_max) {
        if (atomic_compare_exchange_weak(&state->max_severity, &current_max, new_severity)) {
            break;
        }
    }

    // Check for escalation
    if (new_severity > old_severity && g_escalation_callback) {
        // FIX BUG L2-3: Use atomic reads for all shared fields
        uint64_t start_ns = atomic_load(&state->attack_start_ns);
        struct tenant_attack_event event = {
            .tenant_id = tenant_id,
            .attack_type = attack_type,
            .severity = new_severity,
            .anomalous_ip_count = atomic_load(&state->anomalous_ip_count),
            .attack_pps = atomic_load(&state->total_pps),
            .attack_bps = atomic_load(&state->total_bps),
            .max_z_score = FP_TO_DOUBLE(atomic_load(&state->max_z_score_fp)),
            .start_time_ns = start_ns,
            .duration_ns = now - start_ns,
            .is_ongoing = true,
        };
        g_escalation_callback(tenant_id, old_severity, new_severity, &event, g_escalation_callback_ctx);
    }

    // Update dominant attack type (most common)
    uint32_t max_count = 0;
    attack_type_t dominant = ATTACK_TYPE_NONE;
    if (atomic_load(&state->syn_flood_count) > max_count) {
        max_count = atomic_load(&state->syn_flood_count);
        dominant = ATTACK_TYPE_SYN_FLOOD;
    }
    if (atomic_load(&state->udp_flood_count) > max_count) {
        max_count = atomic_load(&state->udp_flood_count);
        dominant = ATTACK_TYPE_UDP_FLOOD;
    }
    if (atomic_load(&state->http_flood_count) > max_count) {
        max_count = atomic_load(&state->http_flood_count);
        dominant = ATTACK_TYPE_HTTP_FLOOD;
    }
    if (atomic_load(&state->amp_attack_count) > max_count) {
        dominant = ATTACK_TYPE_DNS_AMPLIFICATION;  // Generic amp
    }
    atomic_store(&state->dominant_attack_type, dominant);

    // FIX BUG L2-3: Use atomic store
    atomic_store(&state->last_update_ns, now);
    atomic_fetch_add(&state->total_anomalies_detected, 1);
}

void tenant_anomaly_clear_ip(tenant_id_t tenant_id, uint32_t dst_ip __attribute__((unused))) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state || !atomic_load(&state->initialized)) {
        return;
    }

    // FIX BUG L2-7: Use CAS to prevent underflow
    // Only decrement if count > 0, atomically
    uint32_t count = atomic_load(&state->anomalous_ip_count);
    while (count > 0) {
        if (atomic_compare_exchange_weak(&state->anomalous_ip_count, &count, count - 1)) {
            break;
        }
        // CAS failed, count was reloaded, loop will check if still > 0
    }
}

void tenant_anomaly_update(tenant_id_t tenant_id) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state || !atomic_load(&state->initialized)) {
        return;
    }

    uint64_t now = get_time_ns();

    // Check if attack has ended (no anomalies for timeout period)
    if (atomic_load(&state->under_attack)) {
        // FIX BUG L2-3: Use atomic reads for all shared fields
        uint64_t last_update = atomic_load(&state->last_update_ns);
        uint64_t elapsed = now - last_update;
        if (elapsed > ATTACK_TIMEOUT_NS && atomic_load(&state->anomalous_ip_count) == 0) {
            // Attack ended
            atomic_store(&state->under_attack, false);
            uint64_t start_ns = atomic_load(&state->attack_start_ns);
            atomic_store(&state->attack_duration_ns, now - start_ns);
            atomic_store(&state->last_attack_end_ns, now);
            atomic_store(&state->state_change_ns, now);

            // Clear severity and reset max for next attack
            atomic_store(&state->current_severity, SEVERITY_NONE);
            atomic_store(&state->max_severity, SEVERITY_NONE);
            atomic_store(&state->max_z_score_fp, 0);
            atomic_store(&state->any_ip_anomalous, false);

            // Trigger callback
            if (g_attack_callback) {
                g_attack_callback(tenant_id, SEVERITY_NONE, ATTACK_TYPE_NONE, g_attack_callback_ctx);
            }
        } else {
            // Update duration
            uint64_t start_ns = atomic_load(&state->attack_start_ns);
            atomic_store(&state->attack_duration_ns, now - start_ns);
        }
    }

    // Update time since last attack
    uint64_t last_end = atomic_load(&state->last_attack_end_ns);
    if (last_end > 0) {
        atomic_store(&state->time_since_attack_ns, now - last_end);
    }
}

// ==================== Query API ====================

const struct tenant_anomaly_state* tenant_anomaly_get(tenant_id_t tenant_id) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return NULL;
    }
    return g_tenant_states[tenant_id];
}

bool tenant_anomaly_is_active(tenant_id_t tenant_id) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return false;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state) {
        return false;
    }

    return atomic_load(&state->under_attack);
}

attack_severity_t tenant_anomaly_get_severity(tenant_id_t tenant_id) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return SEVERITY_NONE;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state) {
        return SEVERITY_NONE;
    }

    return atomic_load(&state->current_severity);
}

attack_type_t tenant_anomaly_get_attack_type(tenant_id_t tenant_id) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return ATTACK_TYPE_NONE;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state) {
        return ATTACK_TYPE_NONE;
    }

    return atomic_load(&state->dominant_attack_type);
}

int tenant_anomaly_get_event(tenant_id_t tenant_id,
                             struct tenant_attack_event *event) {
    if (!g_initialized || tenant_id >= MAX_TENANTS || !event) {
        return -1;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state || !atomic_load(&state->initialized) || !atomic_load(&state->under_attack)) {
        return -1;
    }

    // FIX BUG L2-3: Use atomic reads for all shared fields
    event->tenant_id = tenant_id;
    event->attack_type = atomic_load(&state->dominant_attack_type);
    event->severity = atomic_load(&state->current_severity);
    event->anomalous_ip_count = atomic_load(&state->anomalous_ip_count);
    event->attack_pps = atomic_load(&state->total_pps);
    event->attack_bps = atomic_load(&state->total_bps);
    event->max_z_score = FP_TO_DOUBLE(atomic_load(&state->max_z_score_fp));
    event->start_time_ns = atomic_load(&state->attack_start_ns);
    event->duration_ns = atomic_load(&state->attack_duration_ns);
    event->is_ongoing = true;
    event->confidence = 0.8;  // Default confidence

    return 0;
}

// ==================== Callback Registration ====================

void tenant_anomaly_set_attack_callback(tenant_attack_callback_t cb, void *ctx) {
    g_attack_callback = cb;
    g_attack_callback_ctx = ctx;
}

void tenant_anomaly_set_escalation_callback(tenant_escalation_callback_t cb, void *ctx) {
    g_escalation_callback = cb;
    g_escalation_callback_ctx = ctx;
}

// ==================== Sensitivity Configuration ====================

int tenant_anomaly_set_sensitivity(tenant_id_t tenant_id, double multiplier) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return -1;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state || !atomic_load(&state->initialized)) {
        return -1;
    }

    if (multiplier < 0.1 || multiplier > 10.0) {
        return -1;  // Invalid range
    }

    // FIX BUG L2-3: Use atomic stores for thread-safe access
    atomic_store(&state->sensitivity_multiplier_fp, DOUBLE_TO_FP(multiplier));
    atomic_store(&state->effective_z_threshold_fp, DOUBLE_TO_FP(DEFAULT_Z_THRESHOLD * multiplier));

    return 0;
}

double tenant_anomaly_get_sensitivity(tenant_id_t tenant_id) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return DEFAULT_SENSITIVITY;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state || !atomic_load(&state->initialized)) {
        return DEFAULT_SENSITIVITY;
    }

    // FIX BUG L2-3: Use atomic read
    return FP_TO_DOUBLE(atomic_load(&state->sensitivity_multiplier_fp));
}

int tenant_anomaly_update_config(tenant_id_t tenant_id,
                                 const struct tenant_l2_config *config) {
    if (!g_initialized || tenant_id >= MAX_TENANTS || !config) {
        return -1;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state || !atomic_load(&state->initialized)) {
        return -1;
    }

    // FIX BUG L2-3: Use atomic stores for thread-safe config update
    double sens_mult = config->thresholds.sensitivity_multiplier > 0
        ? config->thresholds.sensitivity_multiplier : DEFAULT_SENSITIVITY;
    double z_thresh = config->thresholds.z_score_threshold > 0
        ? config->thresholds.z_score_threshold * sens_mult
        : DEFAULT_Z_THRESHOLD * sens_mult;

    atomic_store(&state->sensitivity_multiplier_fp, DOUBLE_TO_FP(sens_mult));
    atomic_store(&state->effective_z_threshold_fp, DOUBLE_TO_FP(z_thresh));

    return 0;
}

// ==================== Statistics ====================

int tenant_anomaly_get_stats(tenant_id_t tenant_id,
                             struct tenant_attack_stats *stats) {
    if (!g_initialized || tenant_id >= MAX_TENANTS || !stats) {
        return -1;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state) {
        memset(stats, 0, sizeof(*stats));
        stats->tenant_id = tenant_id;
        return 0;
    }

    stats->tenant_id = tenant_id;
    stats->total_attacks_24h = atomic_load(&state->attack_count_24h);
    stats->syn_flood_count = atomic_load(&state->syn_flood_count);
    stats->udp_flood_count = atomic_load(&state->udp_flood_count);
    stats->http_flood_count = atomic_load(&state->http_flood_count);
    stats->amp_attack_count = atomic_load(&state->amp_attack_count);
    stats->other_count = atomic_load(&state->other_attack_count);

    stats->false_positives_reported = atomic_load(&state->false_positives);

    // Calculate estimated accuracy
    uint64_t total = atomic_load(&state->total_anomalies_detected);
    if (total > 0) {
        stats->estimated_accuracy = 1.0 - ((double)stats->false_positives_reported / total);
        if (stats->estimated_accuracy < 0) {
            stats->estimated_accuracy = 0;
        }
    } else {
        stats->estimated_accuracy = 1.0;
    }

    return 0;
}

void tenant_anomaly_reset_stats(tenant_id_t tenant_id) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state) {
        return;
    }

    atomic_store(&state->attack_count_24h, 0);
    atomic_store(&state->syn_flood_count, 0);
    atomic_store(&state->udp_flood_count, 0);
    atomic_store(&state->http_flood_count, 0);
    atomic_store(&state->amp_attack_count, 0);
    atomic_store(&state->other_attack_count, 0);
    atomic_store(&state->total_anomalies_detected, 0);
    atomic_store(&state->false_positives, 0);
}

void tenant_anomaly_report_false_positive(tenant_id_t tenant_id,
                                          uint64_t attack_start_ns __attribute__((unused))) {
    if (!g_initialized || tenant_id >= MAX_TENANTS) {
        return;
    }

    struct tenant_anomaly_state *state = g_tenant_states[tenant_id];
    if (!state) {
        return;
    }

    atomic_fetch_add(&state->false_positives, 1);
}

// ==================== Global Operations ====================

void tenant_anomaly_get_global_state(struct global_anomaly_state *state) {
    if (!g_initialized || !state) {
        memset(state, 0, sizeof(*state));
        return;
    }

    memset(state, 0, sizeof(*state));

    for (uint32_t i = 0; i < MAX_TENANTS; i++) {
        struct tenant_anomaly_state *ts = g_tenant_states[i];
        if (!ts) continue;

        if (atomic_load(&ts->under_attack)) {
            state->tenants_under_attack++;
            state->total_anomalous_ips += atomic_load(&ts->anomalous_ip_count);
            state->global_attack_pps += atomic_load(&ts->total_pps);
            state->global_attack_bps += atomic_load(&ts->total_bps);

            uint8_t sev = atomic_load(&ts->current_severity);
            if (sev > state->max_severity_global) {
                state->max_severity_global = sev;
            }
        }
    }

    // Determine dominant global attack type (simplified)
    if (state->tenants_under_attack > 0) {
        state->dominant_attack_type = ATTACK_TYPE_MIXED;
    }
}

bool tenant_anomaly_is_global_emergency(void) {
    struct global_anomaly_state state;
    tenant_anomaly_get_global_state(&state);

    // Emergency if >10 tenants under attack OR severity is critical
    return state.tenants_under_attack > 10 ||
           state.max_severity_global >= SEVERITY_CRITICAL;
}

// ==================== Maintenance ====================

void tenant_anomaly_maintenance(void) {
    if (!g_initialized) {
        return;
    }

    uint64_t now = get_time_ns();

    for (uint32_t i = 0; i < MAX_TENANTS; i++) {
        struct tenant_anomaly_state *state = g_tenant_states[i];
        if (!state || !atomic_load(&state->initialized)) continue;

        // Update each tenant
        tenant_anomaly_update(i);

        // Roll over 24h counters if needed
        // FIX BUG L2-3: Use atomic read for last_update_ns
        uint64_t last_update = atomic_load(&state->last_update_ns);
        if (last_update > 0 && (now - last_update) > WINDOW_24H_NS) {
            // Reset 24h counters
            atomic_store(&state->attack_count_24h, 0);
        }
    }

    // Update global state
    tenant_anomaly_get_global_state(&g_global_state);
}
