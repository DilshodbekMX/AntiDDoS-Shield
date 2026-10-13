/**
 * @file tenant_logging.c
 * @brief Per-Tenant Logging Implementation (Phase 7.3)
 */

#include "tenant_logging.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

// ==================== Internal Structures ====================

#define MAX_SUBSCRIPTIONS 32

struct log_subscription {
    bool                    active;
    tenant_id_t             tenant_id;
    log_level_t             min_level;
    tenant_log_callback_t   callback;
    void                    *user_data;
};

struct tenant_log_manager {
    uint32_t                max_tenants;
    uint32_t                buffer_size;

    // Per-tenant log buffers
    struct tenant_log_buffer *buffers;

    // Global lock
    pthread_rwlock_t        lock;

    // Subscriptions for real-time streaming
    struct log_subscription subscriptions[MAX_SUBSCRIPTIONS];
    pthread_mutex_t         sub_lock;

    // Log shipping
    struct log_ship_config  ship_config;
    bool                    shipping_enabled;
    pthread_t               ship_thread;
    bool                    ship_running;

    // Statistics
    uint64_t                total_logs;
    uint64_t                total_drops;
};

// ==================== Global Instance ====================

static struct tenant_log_manager *g_log_mgr = NULL;

// ==================== Name Tables ====================

static const char *level_names[] = {
    [LOG_LEVEL_DEBUG] = "DEBUG",
    [LOG_LEVEL_INFO] = "INFO",
    [LOG_LEVEL_WARN] = "WARN",
    [LOG_LEVEL_ERROR] = "ERROR",
    [LOG_LEVEL_SECURITY] = "SECURITY",
    [LOG_LEVEL_AUDIT] = "AUDIT",
};

static const char *category_names[] = {
    [LOG_CAT_SECURITY] = "security",
    [LOG_CAT_OPERATIONAL] = "operational",
    [LOG_CAT_AUDIT] = "audit",
    [LOG_CAT_TRAFFIC] = "traffic",
    [LOG_CAT_SYSTEM] = "system",
};

static const char *event_names[] = {
    [LOG_EVENT_ATTACK_DETECTED] = "attack_detected",
    [LOG_EVENT_ATTACK_MITIGATED] = "attack_mitigated",
    [LOG_EVENT_ATTACK_ENDED] = "attack_ended",
    [LOG_EVENT_IP_BLOCKED] = "ip_blocked",
    [LOG_EVENT_IP_UNBLOCKED] = "ip_unblocked",
    [LOG_EVENT_RATE_LIMITED] = "rate_limited",
    [LOG_EVENT_CHALLENGE_ISSUED] = "challenge_issued",
    [LOG_EVENT_CHALLENGE_PASSED] = "challenge_passed",
    [LOG_EVENT_CHALLENGE_FAILED] = "challenge_failed",
    [LOG_EVENT_BOT_DETECTED] = "bot_detected",
    [LOG_EVENT_SIGNATURE_MATCH] = "signature_match",
    [LOG_EVENT_ANOMALY_DETECTED] = "anomaly_detected",
    [LOG_EVENT_ANOMALY_CLEARED] = "anomaly_cleared",
    [LOG_EVENT_THREAT_INTEL_HIT] = "threat_intel_hit",
    [LOG_EVENT_FALSE_POSITIVE] = "false_positive",
    [LOG_EVENT_FALSE_NEGATIVE] = "false_negative",
    [LOG_EVENT_CONFIG_CHANGED] = "config_changed",
    [LOG_EVENT_POLICY_ADDED] = "policy_added",
    [LOG_EVENT_POLICY_REMOVED] = "policy_removed",
    [LOG_EVENT_BLACKLIST_ADD] = "blacklist_add",
    [LOG_EVENT_BLACKLIST_REMOVE] = "blacklist_remove",
    [LOG_EVENT_WHITELIST_ADD] = "whitelist_add",
    [LOG_EVENT_WHITELIST_REMOVE] = "whitelist_remove",
    [LOG_EVENT_THRESHOLD_CHANGED] = "threshold_changed",
    [LOG_EVENT_STATUS_CHANGED] = "status_changed",
    [LOG_EVENT_QUOTA_WARNING] = "quota_warning",
    [LOG_EVENT_QUOTA_EXCEEDED] = "quota_exceeded",
    [LOG_EVENT_ERROR] = "error",
    [LOG_EVENT_WARNING] = "warning",
    [LOG_EVENT_API_ACCESS] = "api_access",
    [LOG_EVENT_USER_LOGIN] = "user_login",
    [LOG_EVENT_USER_LOGOUT] = "user_logout",
    [LOG_EVENT_ADMIN_ACTION] = "admin_action",
    [LOG_EVENT_REPORT_GENERATED] = "report_generated",
    [LOG_EVENT_DATA_EXPORT] = "data_export",
    [LOG_EVENT_TENANT_CREATED] = "tenant_created",
    [LOG_EVENT_TENANT_DELETED] = "tenant_deleted",
    [LOG_EVENT_TENANT_SUSPENDED] = "tenant_suspended",
    [LOG_EVENT_TENANT_ACTIVATED] = "tenant_activated",
    [LOG_EVENT_MAINTENANCE] = "maintenance",
    [LOG_EVENT_SYNC] = "sync",
};

// ==================== Helper Functions ====================

static uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void format_ip(uint32_t ip, char *buf, size_t len) {
    snprintf(buf, len, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);
}

// ==================== Initialization ====================

int tenant_log_init(uint32_t max_tenants, uint32_t buffer_size) {
    if (g_log_mgr) return 0;

    g_log_mgr = calloc(1, sizeof(struct tenant_log_manager));
    if (!g_log_mgr) return -1;

    g_log_mgr->max_tenants = max_tenants;
    g_log_mgr->buffer_size = buffer_size ? buffer_size : LOG_BUFFER_SIZE;

    // Allocate per-tenant buffers
    g_log_mgr->buffers = calloc(max_tenants, sizeof(struct tenant_log_buffer));
    if (!g_log_mgr->buffers) {
        free(g_log_mgr);
        g_log_mgr = NULL;
        return -1;
    }

    // Initialize each buffer
    for (uint32_t t = 0; t < max_tenants; t++) {
        struct tenant_log_buffer *buf = &g_log_mgr->buffers[t];
        buf->tenant_id = t;
        buf->capacity = g_log_mgr->buffer_size;
        buf->entries = calloc(buf->capacity, sizeof(struct tenant_log_entry));
        if (!buf->entries) {
            // Cleanup on failure
            for (uint32_t j = 0; j < t; j++) {
                free(g_log_mgr->buffers[j].entries);
            }
            free(g_log_mgr->buffers);
            free(g_log_mgr);
            g_log_mgr = NULL;
            return -1;
        }
    }

    pthread_rwlock_init(&g_log_mgr->lock, NULL);
    pthread_mutex_init(&g_log_mgr->sub_lock, NULL);

    return 0;
}

void tenant_log_cleanup(void) {
    if (!g_log_mgr) return;

    tenant_log_ship_stop();

    pthread_rwlock_destroy(&g_log_mgr->lock);
    pthread_mutex_destroy(&g_log_mgr->sub_lock);

    for (uint32_t t = 0; t < g_log_mgr->max_tenants; t++) {
        free(g_log_mgr->buffers[t].entries);
    }
    free(g_log_mgr->buffers);
    free(g_log_mgr);
    g_log_mgr = NULL;
}

// ==================== Internal Logging ====================

static void notify_subscribers(const struct tenant_log_entry *entry) {
    if (!g_log_mgr) return;

    pthread_mutex_lock(&g_log_mgr->sub_lock);

    for (int i = 0; i < MAX_SUBSCRIPTIONS; i++) {
        struct log_subscription *sub = &g_log_mgr->subscriptions[i];
        if (!sub->active) continue;

        // Check tenant filter
        if (sub->tenant_id != 0 && sub->tenant_id != entry->tenant_id) {
            continue;
        }

        // Check level filter
        if (entry->level < sub->min_level) {
            continue;
        }

        // Call subscriber
        sub->callback(entry, sub->user_data);
    }

    pthread_mutex_unlock(&g_log_mgr->sub_lock);
}

static void write_log_entry(tenant_id_t tenant_id,
                            const struct tenant_log_entry *entry) {
    if (!g_log_mgr || tenant_id >= g_log_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_log_mgr->lock);

    struct tenant_log_buffer *buf = &g_log_mgr->buffers[tenant_id];

    // Check if buffer is full (ring buffer overwrites oldest)
    if (buf->count >= buf->capacity) {
        buf->drops++;
        g_log_mgr->total_drops++;
    }

    // Write entry
    memcpy(&buf->entries[buf->head], entry, sizeof(*entry));
    buf->entries[buf->head].sequence = buf->sequence++;

    buf->head = (buf->head + 1) % buf->capacity;
    if (buf->count < buf->capacity) {
        buf->count++;
    }

    g_log_mgr->total_logs++;

    pthread_rwlock_unlock(&g_log_mgr->lock);

    // Notify real-time subscribers (outside lock)
    notify_subscribers(entry);
}

// ==================== Public Logging Functions ====================

void tenant_log(tenant_id_t tenant_id, log_level_t level,
                log_category_t category, log_event_type_t event_type,
                const char *message, const char *details) {
    tenant_log_packet(tenant_id, level, category, event_type,
                      0, 0, 0, 0, 0, 0, message, details);
}

void tenant_log_ip(tenant_id_t tenant_id, log_level_t level,
                   log_category_t category, log_event_type_t event_type,
                   uint32_t src_ip, uint32_t dst_ip,
                   const char *message, const char *details) {
    tenant_log_packet(tenant_id, level, category, event_type,
                      src_ip, dst_ip, 0, 0, 0, 0, message, details);
}

void tenant_log_packet(tenant_id_t tenant_id, log_level_t level,
                       log_category_t category, log_event_type_t event_type,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t src_port, uint16_t dst_port,
                       uint8_t protocol, uint8_t severity,
                       const char *message, const char *details) {
    if (!g_log_mgr) return;

    struct tenant_log_entry entry = {
        .timestamp_ns = get_timestamp_ns(),
        .tenant_id = tenant_id,
        .level = level,
        .category = category,
        .event_type = event_type,
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol,
        .severity = severity,
    };

    if (message) {
        strncpy(entry.message, message, LOG_MESSAGE_MAX_LEN - 1);
    }
    if (details) {
        strncpy(entry.details, details, LOG_DETAILS_MAX_LEN - 1);
    }

    write_log_entry(tenant_id, &entry);
}

// ==================== Security Event Helpers ====================

void tenant_log_attack_detected(tenant_id_t tenant_id,
                                 uint8_t attack_type, uint8_t severity,
                                 uint32_t dst_ip, uint64_t pps) {
    char msg[256];
    char details[512];
    char ip_str[32];

    format_ip(dst_ip, ip_str, sizeof(ip_str));

    snprintf(msg, sizeof(msg), "Attack detected: type=%u severity=%u target=%s",
             attack_type, severity, ip_str);

    snprintf(details, sizeof(details),
             "{\"attack_type\":%u,\"severity\":%u,\"dst_ip\":\"%s\",\"pps\":%lu}",
             attack_type, severity, ip_str, pps);

    tenant_log_packet(tenant_id, LOG_LEVEL_SECURITY, LOG_CAT_SECURITY,
                      LOG_EVENT_ATTACK_DETECTED, 0, dst_ip, 0, 0, 0, severity,
                      msg, details);
}

void tenant_log_attack_mitigated(tenant_id_t tenant_id,
                                  uint8_t attack_type,
                                  double mitigation_time_ms,
                                  bool effective) {
    char msg[256];
    char details[512];

    snprintf(msg, sizeof(msg), "Attack mitigated: type=%u time=%.1fms effective=%s",
             attack_type, mitigation_time_ms, effective ? "yes" : "no");

    snprintf(details, sizeof(details),
             "{\"attack_type\":%u,\"mitigation_time_ms\":%.2f,\"effective\":%s}",
             attack_type, mitigation_time_ms, effective ? "true" : "false");

    tenant_log(tenant_id, LOG_LEVEL_SECURITY, LOG_CAT_SECURITY,
               LOG_EVENT_ATTACK_MITIGATED, msg, details);
}

void tenant_log_ip_blocked(tenant_id_t tenant_id,
                           uint32_t src_ip, const char *reason,
                           uint32_t duration_sec) {
    char msg[256];
    char details[512];
    char ip_str[32];

    format_ip(src_ip, ip_str, sizeof(ip_str));

    snprintf(msg, sizeof(msg), "IP blocked: %s reason=%s duration=%us",
             ip_str, reason ? reason : "unknown", duration_sec);

    snprintf(details, sizeof(details),
             "{\"src_ip\":\"%s\",\"reason\":\"%s\",\"duration_sec\":%u}",
             ip_str, reason ? reason : "unknown", duration_sec);

    tenant_log_ip(tenant_id, LOG_LEVEL_SECURITY, LOG_CAT_SECURITY,
                  LOG_EVENT_IP_BLOCKED, src_ip, 0, msg, details);
}

void tenant_log_challenge(tenant_id_t tenant_id,
                          uint32_t src_ip, bool passed,
                          const char *challenge_type) {
    char msg[256];
    char details[512];
    char ip_str[32];

    format_ip(src_ip, ip_str, sizeof(ip_str));

    snprintf(msg, sizeof(msg), "Challenge %s: %s type=%s",
             passed ? "passed" : "failed", ip_str,
             challenge_type ? challenge_type : "unknown");

    snprintf(details, sizeof(details),
             "{\"src_ip\":\"%s\",\"passed\":%s,\"type\":\"%s\"}",
             ip_str, passed ? "true" : "false",
             challenge_type ? challenge_type : "unknown");

    tenant_log_ip(tenant_id, LOG_LEVEL_INFO, LOG_CAT_SECURITY,
                  passed ? LOG_EVENT_CHALLENGE_PASSED : LOG_EVENT_CHALLENGE_FAILED,
                  src_ip, 0, msg, details);
}

void tenant_log_bot(tenant_id_t tenant_id,
                    uint32_t src_ip, const char *bot_type,
                    bool blocked) {
    char msg[256];
    char details[512];
    char ip_str[32];

    format_ip(src_ip, ip_str, sizeof(ip_str));

    snprintf(msg, sizeof(msg), "Bot detected: %s type=%s blocked=%s",
             ip_str, bot_type ? bot_type : "unknown",
             blocked ? "yes" : "no");

    snprintf(details, sizeof(details),
             "{\"src_ip\":\"%s\",\"bot_type\":\"%s\",\"blocked\":%s}",
             ip_str, bot_type ? bot_type : "unknown",
             blocked ? "true" : "false");

    tenant_log_ip(tenant_id, LOG_LEVEL_SECURITY, LOG_CAT_SECURITY,
                  LOG_EVENT_BOT_DETECTED, src_ip, 0, msg, details);
}

// ==================== Operational Event Helpers ====================

void tenant_log_config_change(tenant_id_t tenant_id,
                               const char *field, const char *old_value,
                               const char *new_value) {
    char msg[256];
    char details[512];

    snprintf(msg, sizeof(msg), "Config changed: %s",
             field ? field : "unknown");

    snprintf(details, sizeof(details),
             "{\"field\":\"%s\",\"old_value\":\"%s\",\"new_value\":\"%s\"}",
             field ? field : "", old_value ? old_value : "",
             new_value ? new_value : "");

    tenant_log(tenant_id, LOG_LEVEL_INFO, LOG_CAT_OPERATIONAL,
               LOG_EVENT_CONFIG_CHANGED, msg, details);
}

void tenant_log_policy_change(tenant_id_t tenant_id,
                               bool added, uint32_t src_ip,
                               const char *action, uint32_t duration_sec) {
    char msg[256];
    char details[512];
    char ip_str[32];

    format_ip(src_ip, ip_str, sizeof(ip_str));

    snprintf(msg, sizeof(msg), "Policy %s: %s action=%s duration=%us",
             added ? "added" : "removed", ip_str,
             action ? action : "unknown", duration_sec);

    snprintf(details, sizeof(details),
             "{\"src_ip\":\"%s\",\"action\":\"%s\",\"duration_sec\":%u}",
             ip_str, action ? action : "unknown", duration_sec);

    tenant_log_ip(tenant_id, LOG_LEVEL_INFO, LOG_CAT_OPERATIONAL,
                  added ? LOG_EVENT_POLICY_ADDED : LOG_EVENT_POLICY_REMOVED,
                  src_ip, 0, msg, details);
}

void tenant_log_quota(tenant_id_t tenant_id,
                      const char *quota_type, uint64_t current,
                      uint64_t limit, bool exceeded) {
    char msg[256];
    char details[512];

    snprintf(msg, sizeof(msg), "Quota %s: %s current=%lu limit=%lu",
             exceeded ? "exceeded" : "warning",
             quota_type ? quota_type : "unknown", current, limit);

    snprintf(details, sizeof(details),
             "{\"quota_type\":\"%s\",\"current\":%lu,\"limit\":%lu,\"exceeded\":%s}",
             quota_type ? quota_type : "unknown", current, limit,
             exceeded ? "true" : "false");

    tenant_log(tenant_id, exceeded ? LOG_LEVEL_ERROR : LOG_LEVEL_WARN,
               LOG_CAT_OPERATIONAL,
               exceeded ? LOG_EVENT_QUOTA_EXCEEDED : LOG_EVENT_QUOTA_WARNING,
               msg, details);
}

// ==================== Audit Event Helpers ====================

void tenant_log_api_access(tenant_id_t tenant_id,
                           const char *method, const char *path,
                           const char *user, int status_code) {
    char msg[256];
    char details[512];

    snprintf(msg, sizeof(msg), "API: %s %s -> %d",
             method ? method : "?", path ? path : "?", status_code);

    snprintf(details, sizeof(details),
             "{\"method\":\"%s\",\"path\":\"%s\",\"user\":\"%s\",\"status\":%d}",
             method ? method : "", path ? path : "",
             user ? user : "anonymous", status_code);

    tenant_log(tenant_id, LOG_LEVEL_AUDIT, LOG_CAT_AUDIT,
               LOG_EVENT_API_ACCESS, msg, details);
}

void tenant_log_admin_action(tenant_id_t tenant_id,
                              const char *admin_user,
                              const char *action,
                              const char *target) {
    char msg[256];
    char details[512];

    snprintf(msg, sizeof(msg), "Admin action: %s by %s on %s",
             action ? action : "unknown",
             admin_user ? admin_user : "unknown",
             target ? target : "unknown");

    snprintf(details, sizeof(details),
             "{\"admin\":\"%s\",\"action\":\"%s\",\"target\":\"%s\"}",
             admin_user ? admin_user : "",
             action ? action : "",
             target ? target : "");

    tenant_log(tenant_id, LOG_LEVEL_AUDIT, LOG_CAT_AUDIT,
               LOG_EVENT_ADMIN_ACTION, msg, details);
}

// ==================== Query Functions ====================

int tenant_log_query(const struct tenant_log_filter *filter,
                     struct tenant_log_entry *entries,
                     int max_entries) {
    if (!g_log_mgr || !filter || !entries || max_entries <= 0) {
        return 0;
    }

    int count = 0;

    pthread_rwlock_rdlock(&g_log_mgr->lock);

    // Determine tenant range
    tenant_id_t start = (filter->tenant_id == 0) ? 1 : filter->tenant_id;
    tenant_id_t end = (filter->tenant_id == 0) ? (tenant_id_t)g_log_mgr->max_tenants : (tenant_id_t)(filter->tenant_id + 1);

    for (tenant_id_t t = start; t < end && count < max_entries; t++) {
        struct tenant_log_buffer *buf = &g_log_mgr->buffers[t];

        for (uint32_t i = 0; i < buf->count && count < max_entries; i++) {
            uint32_t idx = (buf->head + buf->capacity - buf->count + i) % buf->capacity;
            struct tenant_log_entry *e = &buf->entries[idx];

            // Apply filters
            if (filter->start_time && e->timestamp_ns < filter->start_time * 1000000000ULL) {
                continue;
            }
            if (filter->end_time && e->timestamp_ns > filter->end_time * 1000000000ULL) {
                continue;
            }
            if (e->level < filter->min_level) {
                continue;
            }
            if (filter->categories && !(filter->categories & (1 << e->category))) {
                continue;
            }
            if (filter->src_ip && e->src_ip != filter->src_ip) {
                continue;
            }
            if (filter->dst_ip && e->dst_ip != filter->dst_ip) {
                continue;
            }

            memcpy(&entries[count], e, sizeof(*e));
            count++;
        }
    }

    pthread_rwlock_unlock(&g_log_mgr->lock);
    return count;
}

int tenant_log_get_recent(tenant_id_t tenant_id,
                          struct tenant_log_entry *entries,
                          int max_entries) {
    struct tenant_log_filter filter = {
        .tenant_id = tenant_id,
        .min_level = LOG_LEVEL_DEBUG,
        .max_entries = max_entries,
    };
    return tenant_log_query(&filter, entries, max_entries);
}

int tenant_log_get_by_level(tenant_id_t tenant_id, log_level_t min_level,
                            struct tenant_log_entry *entries,
                            int max_entries) {
    struct tenant_log_filter filter = {
        .tenant_id = tenant_id,
        .min_level = min_level,
        .max_entries = max_entries,
    };
    return tenant_log_query(&filter, entries, max_entries);
}

int tenant_log_get_security(tenant_id_t tenant_id,
                            struct tenant_log_entry *entries,
                            int max_entries) {
    struct tenant_log_filter filter = {
        .tenant_id = tenant_id,
        .min_level = LOG_LEVEL_DEBUG,
        .categories = (1 << LOG_CAT_SECURITY),
        .max_entries = max_entries,
    };
    return tenant_log_query(&filter, entries, max_entries);
}

int tenant_log_count(const struct tenant_log_filter *filter) {
    if (!g_log_mgr || !filter) return 0;

    int count = 0;

    pthread_rwlock_rdlock(&g_log_mgr->lock);

    if (filter->tenant_id == 0) {
        for (uint32_t t = 0; t < g_log_mgr->max_tenants; t++) {
            count += g_log_mgr->buffers[t].count;
        }
    } else if (filter->tenant_id < g_log_mgr->max_tenants) {
        count = g_log_mgr->buffers[filter->tenant_id].count;
    }

    pthread_rwlock_unlock(&g_log_mgr->lock);
    return count;
}

// ==================== Subscription Functions ====================

int tenant_log_subscribe(tenant_id_t tenant_id, log_level_t min_level,
                         tenant_log_callback_t callback, void *user_data) {
    if (!g_log_mgr || !callback) return -1;

    pthread_mutex_lock(&g_log_mgr->sub_lock);

    int slot = -1;
    for (int i = 0; i < MAX_SUBSCRIPTIONS; i++) {
        if (!g_log_mgr->subscriptions[i].active) {
            slot = i;
            break;
        }
    }

    if (slot >= 0) {
        g_log_mgr->subscriptions[slot] = (struct log_subscription){
            .active = true,
            .tenant_id = tenant_id,
            .min_level = min_level,
            .callback = callback,
            .user_data = user_data,
        };
    }

    pthread_mutex_unlock(&g_log_mgr->sub_lock);
    return slot;
}

void tenant_log_unsubscribe(int subscription_id) {
    if (!g_log_mgr || subscription_id < 0 || subscription_id >= MAX_SUBSCRIPTIONS) {
        return;
    }

    pthread_mutex_lock(&g_log_mgr->sub_lock);
    g_log_mgr->subscriptions[subscription_id].active = false;
    pthread_mutex_unlock(&g_log_mgr->sub_lock);
}

// ==================== Log Shipping ====================

int tenant_log_ship_configure(const struct log_ship_config *config) {
    if (!g_log_mgr || !config) return -1;

    memcpy(&g_log_mgr->ship_config, config, sizeof(*config));
    return 0;
}

int tenant_log_ship_start(void) {
    if (!g_log_mgr) return -1;
    g_log_mgr->shipping_enabled = true;
    // Thread implementation would go here for actual shipping
    return 0;
}

void tenant_log_ship_stop(void) {
    if (!g_log_mgr) return;
    g_log_mgr->shipping_enabled = false;
    g_log_mgr->ship_running = false;
}

int tenant_log_ship_flush(void) {
    // Placeholder for flushing pending logs
    return 0;
}

// ==================== Export Functions ====================

int tenant_log_export_json(const struct tenant_log_filter *filter,
                           char *buf, size_t buf_size) {
    if (!buf || buf_size < 100) return 0;

    struct tenant_log_entry *entries = malloc(1000 * sizeof(*entries));
    if (!entries) return 0;

    int count = tenant_log_query(filter, entries, 1000);

    int written = snprintf(buf, buf_size, "{\"logs\":[");
    char *p = buf + written;
    size_t remaining = buf_size - written;

    for (int i = 0; i < count && remaining > 100; i++) {
        int n = tenant_log_format_json(&entries[i], p, remaining);
        if (n > 0 && (size_t)n < remaining) {
            p += n;
            remaining -= n;
            written += n;

            if (i < count - 1) {
                *p++ = ',';
                remaining--;
                written++;
            }
        }
    }

    int n = snprintf(p, remaining, "],\"count\":%d}", count);
    if (n > 0) written += n;

    free(entries);
    return written;
}

// ==================== Maintenance ====================

void tenant_log_clear(tenant_id_t tenant_id) {
    if (!g_log_mgr || tenant_id >= g_log_mgr->max_tenants) return;

    pthread_rwlock_wrlock(&g_log_mgr->lock);

    struct tenant_log_buffer *buf = &g_log_mgr->buffers[tenant_id];
    buf->head = 0;
    buf->tail = 0;
    buf->count = 0;

    pthread_rwlock_unlock(&g_log_mgr->lock);
}

void tenant_log_clear_all(void) {
    if (!g_log_mgr) return;

    for (uint32_t t = 0; t < g_log_mgr->max_tenants; t++) {
        tenant_log_clear(t);
    }
}

int tenant_log_expire(uint32_t retention_hours) {
    if (!g_log_mgr) return 0;

    uint64_t cutoff_ns = get_timestamp_ns() -
                         (uint64_t)retention_hours * 3600 * 1000000000ULL;
    int expired = 0;

    pthread_rwlock_wrlock(&g_log_mgr->lock);

    for (uint32_t t = 0; t < g_log_mgr->max_tenants; t++) {
        struct tenant_log_buffer *buf = &g_log_mgr->buffers[t];

        // Remove old entries from tail
        while (buf->count > 0) {
            uint32_t idx = (buf->head + buf->capacity - buf->count) % buf->capacity;
            if (buf->entries[idx].timestamp_ns < cutoff_ns) {
                buf->count--;
                expired++;
            } else {
                break;
            }
        }
    }

    pthread_rwlock_unlock(&g_log_mgr->lock);
    return expired;
}

void tenant_log_get_stats(tenant_id_t tenant_id,
                          uint32_t *count, uint32_t *capacity,
                          uint64_t *drops) {
    if (!g_log_mgr || tenant_id >= g_log_mgr->max_tenants) {
        if (count) *count = 0;
        if (capacity) *capacity = 0;
        if (drops) *drops = 0;
        return;
    }

    pthread_rwlock_rdlock(&g_log_mgr->lock);

    struct tenant_log_buffer *buf = &g_log_mgr->buffers[tenant_id];
    if (count) *count = buf->count;
    if (capacity) *capacity = buf->capacity;
    if (drops) *drops = buf->drops;

    pthread_rwlock_unlock(&g_log_mgr->lock);
}

// ==================== Utility ====================

const char* tenant_log_level_name(log_level_t level) {
    if (level >= LOG_LEVEL_MAX) return "UNKNOWN";
    return level_names[level];
}

const char* tenant_log_category_name(log_category_t category) {
    if (category >= LOG_CAT_MAX) return "unknown";
    return category_names[category];
}

const char* tenant_log_event_name(log_event_type_t event) {
    if (event >= LOG_EVENT_MAX || !event_names[event]) return "unknown";
    return event_names[event];
}

int tenant_log_format(const struct tenant_log_entry *entry,
                      char *buf, size_t buf_size) {
    if (!entry || !buf) return 0;

    char timestamp[32];
    time_t ts = entry->timestamp_ns / 1000000000ULL;
    struct tm *tm = localtime(&ts);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

    return snprintf(buf, buf_size,
                    "[%s] [%s] [tenant=%u] [%s] %s",
                    timestamp,
                    tenant_log_level_name(entry->level),
                    entry->tenant_id,
                    tenant_log_event_name(entry->event_type),
                    entry->message);
}

int tenant_log_format_json(const struct tenant_log_entry *entry,
                           char *buf, size_t buf_size) {
    if (!entry || !buf) return 0;

    char src_ip[32] = "", dst_ip[32] = "";
    if (entry->src_ip) format_ip(entry->src_ip, src_ip, sizeof(src_ip));
    if (entry->dst_ip) format_ip(entry->dst_ip, dst_ip, sizeof(dst_ip));

    return snprintf(buf, buf_size,
        "{"
        "\"timestamp\":%lu,"
        "\"tenant_id\":%u,"
        "\"level\":\"%s\","
        "\"category\":\"%s\","
        "\"event\":\"%s\","
        "\"src_ip\":\"%s\","
        "\"dst_ip\":\"%s\","
        "\"message\":\"%s\""
        "%s%s"
        "}",
        entry->timestamp_ns / 1000000,  // Convert to milliseconds
        entry->tenant_id,
        tenant_log_level_name(entry->level),
        tenant_log_category_name(entry->category),
        tenant_log_event_name(entry->event_type),
        src_ip,
        dst_ip,
        entry->message,
        entry->details[0] ? ",\"details\":" : "",
        entry->details[0] ? entry->details : ""
    );
}
