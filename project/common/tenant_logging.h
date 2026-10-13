/**
 * @file tenant_logging.h
 * @brief Per-Tenant Logging Infrastructure (Phase 7.3)
 *
 * Provides isolated, structured logging for each tenant:
 * - Security logs (attacks, mitigations, policy changes)
 * - Operational logs (config changes, status, errors)
 * - Audit logs (API access, user actions)
 *
 * Features:
 * - Per-tenant log buffers with configurable retention
 * - Structured JSON format for analysis
 * - Real-time log streaming support
 * - Log shipping to external systems (syslog, Elasticsearch)
 */

#ifndef TENANT_LOGGING_H
#define TENANT_LOGGING_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "tenant.h"

#ifdef __cplusplus
extern "C" {
#endif

// ==================== Constants ====================

#define LOG_MESSAGE_MAX_LEN     256
#define LOG_DETAILS_MAX_LEN     512
#define LOG_BUFFER_SIZE         10000   // Per-tenant log entries
#define LOG_RETENTION_HOURS     24

// ==================== Log Levels ====================

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_SECURITY,     // Security-relevant events
    LOG_LEVEL_AUDIT,        // Audit trail
    LOG_LEVEL_MAX
} log_level_t;

// ==================== Log Categories ====================

typedef enum {
    LOG_CAT_SECURITY = 0,   // Security events
    LOG_CAT_OPERATIONAL,    // Operational events
    LOG_CAT_AUDIT,          // Audit events
    LOG_CAT_TRAFFIC,        // Traffic events
    LOG_CAT_SYSTEM,         // System events
    LOG_CAT_MAX
} log_category_t;

// ==================== Event Types ====================

typedef enum {
    // Security events (0-99)
    LOG_EVENT_ATTACK_DETECTED       = 1,
    LOG_EVENT_ATTACK_MITIGATED      = 2,
    LOG_EVENT_ATTACK_ENDED          = 3,
    LOG_EVENT_IP_BLOCKED            = 10,
    LOG_EVENT_IP_UNBLOCKED          = 11,
    LOG_EVENT_RATE_LIMITED          = 12,
    LOG_EVENT_CHALLENGE_ISSUED      = 13,
    LOG_EVENT_CHALLENGE_PASSED      = 14,
    LOG_EVENT_CHALLENGE_FAILED      = 15,
    LOG_EVENT_BOT_DETECTED          = 20,
    LOG_EVENT_SIGNATURE_MATCH       = 21,
    LOG_EVENT_ANOMALY_DETECTED      = 22,
    LOG_EVENT_ANOMALY_CLEARED       = 23,
    LOG_EVENT_THREAT_INTEL_HIT      = 24,
    LOG_EVENT_FALSE_POSITIVE        = 30,
    LOG_EVENT_FALSE_NEGATIVE        = 31,

    // Operational events (100-199)
    LOG_EVENT_CONFIG_CHANGED        = 100,
    LOG_EVENT_POLICY_ADDED          = 101,
    LOG_EVENT_POLICY_REMOVED        = 102,
    LOG_EVENT_BLACKLIST_ADD         = 103,
    LOG_EVENT_BLACKLIST_REMOVE      = 104,
    LOG_EVENT_WHITELIST_ADD         = 105,
    LOG_EVENT_WHITELIST_REMOVE      = 106,
    LOG_EVENT_THRESHOLD_CHANGED     = 107,
    LOG_EVENT_STATUS_CHANGED        = 110,
    LOG_EVENT_QUOTA_WARNING         = 111,
    LOG_EVENT_QUOTA_EXCEEDED        = 112,
    LOG_EVENT_ERROR                 = 120,
    LOG_EVENT_WARNING               = 121,

    // Audit events (200-299)
    LOG_EVENT_API_ACCESS            = 200,
    LOG_EVENT_USER_LOGIN            = 201,
    LOG_EVENT_USER_LOGOUT           = 202,
    LOG_EVENT_ADMIN_ACTION          = 203,
    LOG_EVENT_REPORT_GENERATED      = 204,
    LOG_EVENT_DATA_EXPORT           = 205,

    // System events (300-399)
    LOG_EVENT_TENANT_CREATED        = 300,
    LOG_EVENT_TENANT_DELETED        = 301,
    LOG_EVENT_TENANT_SUSPENDED      = 302,
    LOG_EVENT_TENANT_ACTIVATED      = 303,
    LOG_EVENT_MAINTENANCE           = 310,
    LOG_EVENT_SYNC                  = 311,

    LOG_EVENT_MAX
} log_event_type_t;

// ==================== Log Entry Structure ====================

/**
 * Single log entry with tenant context
 */
struct tenant_log_entry {
    uint64_t        timestamp_ns;       // Nanosecond timestamp
    tenant_id_t     tenant_id;
    uint8_t         level;              // log_level_t
    uint8_t         category;           // log_category_t
    uint16_t        event_type;         // log_event_type_t
    uint32_t        src_ip;             // Source IP (if applicable)
    uint32_t        dst_ip;             // Destination IP (if applicable)
    uint16_t        src_port;           // Source port (if applicable)
    uint16_t        dst_port;           // Destination port (if applicable)
    uint8_t         protocol;           // IP protocol (if applicable)
    uint8_t         severity;           // Attack severity (0-3)
    uint16_t        _pad;
    uint32_t        sequence;           // Per-tenant sequence number
    char            message[LOG_MESSAGE_MAX_LEN];
    char            details[LOG_DETAILS_MAX_LEN];   // JSON structured data
};

// ==================== Log Buffer ====================

/**
 * Per-tenant log buffer (ring buffer)
 */
struct tenant_log_buffer {
    tenant_id_t     tenant_id;
    uint32_t        head;               // Write position
    uint32_t        tail;               // Read position (for streaming)
    uint32_t        count;              // Total entries
    uint32_t        sequence;           // Next sequence number
    uint32_t        capacity;           // Buffer capacity
    uint64_t        drops;              // Dropped due to full buffer
    struct tenant_log_entry *entries;
};

// ==================== Log Filter ====================

/**
 * Log query filter
 */
struct tenant_log_filter {
    tenant_id_t     tenant_id;          // 0 for all tenants
    uint64_t        start_time;         // 0 for no start filter
    uint64_t        end_time;           // 0 for no end filter
    uint8_t         min_level;          // Minimum log level
    uint8_t         categories;         // Bitmask of categories
    uint16_t        event_types[16];    // Specific event types (0 = any)
    uint32_t        src_ip;             // Filter by source IP (0 = any)
    uint32_t        dst_ip;             // Filter by dest IP (0 = any)
    uint32_t        max_entries;        // Maximum entries to return
    bool            include_details;    // Include details field
};

// ==================== Log Shipping ====================

typedef enum {
    LOG_SHIP_NONE = 0,
    LOG_SHIP_SYSLOG,
    LOG_SHIP_ELASTICSEARCH,
    LOG_SHIP_KAFKA,
    LOG_SHIP_FILE,
    LOG_SHIP_HTTP,
    LOG_SHIP_MAX
} log_ship_type_t;

/**
 * Log shipping configuration
 */
struct log_ship_config {
    log_ship_type_t type;
    char            host[256];
    uint16_t        port;
    char            index[64];          // ES index or topic
    uint8_t         min_level;          // Minimum level to ship
    bool            batch_enabled;      // Batch shipping
    uint32_t        batch_size;         // Entries per batch
    uint32_t        batch_timeout_ms;   // Max wait before flush
};

// ==================== Callback Types ====================

/**
 * Real-time log callback
 */
typedef void (*tenant_log_callback_t)(const struct tenant_log_entry *entry,
                                       void *user_data);

// ==================== Initialization ====================

/**
 * Initialize tenant logging subsystem
 *
 * @param max_tenants Maximum number of tenants
 * @param buffer_size Log buffer size per tenant
 * @return 0 on success
 */
int tenant_log_init(uint32_t max_tenants, uint32_t buffer_size);

/**
 * Cleanup tenant logging
 */
void tenant_log_cleanup(void);

// ==================== Logging Functions ====================

/**
 * Log a message for a tenant
 *
 * @param tenant_id Tenant ID
 * @param level Log level
 * @param category Log category
 * @param event_type Event type
 * @param message Human-readable message
 * @param details JSON details (optional, NULL for none)
 */
void tenant_log(tenant_id_t tenant_id, log_level_t level,
                log_category_t category, log_event_type_t event_type,
                const char *message, const char *details);

/**
 * Log with IP context
 */
void tenant_log_ip(tenant_id_t tenant_id, log_level_t level,
                   log_category_t category, log_event_type_t event_type,
                   uint32_t src_ip, uint32_t dst_ip,
                   const char *message, const char *details);

/**
 * Log with full packet context
 */
void tenant_log_packet(tenant_id_t tenant_id, log_level_t level,
                       log_category_t category, log_event_type_t event_type,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t src_port, uint16_t dst_port,
                       uint8_t protocol, uint8_t severity,
                       const char *message, const char *details);

// ==================== Convenience Macros ====================

#define TENANT_LOG_DEBUG(tid, cat, evt, msg) \
    tenant_log(tid, LOG_LEVEL_DEBUG, cat, evt, msg, NULL)

#define TENANT_LOG_INFO(tid, cat, evt, msg) \
    tenant_log(tid, LOG_LEVEL_INFO, cat, evt, msg, NULL)

#define TENANT_LOG_WARN(tid, cat, evt, msg) \
    tenant_log(tid, LOG_LEVEL_WARN, cat, evt, msg, NULL)

#define TENANT_LOG_ERROR(tid, cat, evt, msg) \
    tenant_log(tid, LOG_LEVEL_ERROR, cat, evt, msg, NULL)

#define TENANT_LOG_SECURITY(tid, evt, msg, details) \
    tenant_log(tid, LOG_LEVEL_SECURITY, LOG_CAT_SECURITY, evt, msg, details)

#define TENANT_LOG_AUDIT(tid, evt, msg, details) \
    tenant_log(tid, LOG_LEVEL_AUDIT, LOG_CAT_AUDIT, evt, msg, details)

// ==================== Security Event Helpers ====================

/**
 * Log attack detected
 */
void tenant_log_attack_detected(tenant_id_t tenant_id,
                                 uint8_t attack_type, uint8_t severity,
                                 uint32_t dst_ip, uint64_t pps);

/**
 * Log attack mitigated
 */
void tenant_log_attack_mitigated(tenant_id_t tenant_id,
                                  uint8_t attack_type,
                                  double mitigation_time_ms,
                                  bool effective);

/**
 * Log IP blocked
 */
void tenant_log_ip_blocked(tenant_id_t tenant_id,
                           uint32_t src_ip, const char *reason,
                           uint32_t duration_sec);

/**
 * Log challenge result
 */
void tenant_log_challenge(tenant_id_t tenant_id,
                          uint32_t src_ip, bool passed,
                          const char *challenge_type);

/**
 * Log bot detection
 */
void tenant_log_bot(tenant_id_t tenant_id,
                    uint32_t src_ip, const char *bot_type,
                    bool blocked);

// ==================== Operational Event Helpers ====================

/**
 * Log configuration change
 */
void tenant_log_config_change(tenant_id_t tenant_id,
                               const char *field, const char *old_value,
                               const char *new_value);

/**
 * Log policy change
 */
void tenant_log_policy_change(tenant_id_t tenant_id,
                               bool added, uint32_t src_ip,
                               const char *action, uint32_t duration_sec);

/**
 * Log quota warning/exceeded
 */
void tenant_log_quota(tenant_id_t tenant_id,
                      const char *quota_type, uint64_t current,
                      uint64_t limit, bool exceeded);

// ==================== Audit Event Helpers ====================

/**
 * Log API access
 */
void tenant_log_api_access(tenant_id_t tenant_id,
                           const char *method, const char *path,
                           const char *user, int status_code);

/**
 * Log admin action
 */
void tenant_log_admin_action(tenant_id_t tenant_id,
                              const char *admin_user,
                              const char *action,
                              const char *target);

// ==================== Query Functions ====================

/**
 * Query logs for a tenant
 *
 * @param filter Query filter
 * @param entries Output array
 * @param max_entries Array size
 * @return Number of entries returned
 */
int tenant_log_query(const struct tenant_log_filter *filter,
                     struct tenant_log_entry *entries,
                     int max_entries);

/**
 * Get recent logs for a tenant
 *
 * @param tenant_id Tenant ID
 * @param entries Output array
 * @param max_entries Array size
 * @return Number of entries returned
 */
int tenant_log_get_recent(tenant_id_t tenant_id,
                          struct tenant_log_entry *entries,
                          int max_entries);

/**
 * Get logs by level
 */
int tenant_log_get_by_level(tenant_id_t tenant_id, log_level_t min_level,
                            struct tenant_log_entry *entries,
                            int max_entries);

/**
 * Get security logs only
 */
int tenant_log_get_security(tenant_id_t tenant_id,
                            struct tenant_log_entry *entries,
                            int max_entries);

/**
 * Count logs matching filter
 */
int tenant_log_count(const struct tenant_log_filter *filter);

// ==================== Real-time Streaming ====================

/**
 * Register callback for real-time log streaming
 *
 * @param tenant_id Tenant ID (0 for all)
 * @param min_level Minimum level to receive
 * @param callback Callback function
 * @param user_data User data passed to callback
 * @return Subscription ID, -1 on failure
 */
int tenant_log_subscribe(tenant_id_t tenant_id, log_level_t min_level,
                         tenant_log_callback_t callback, void *user_data);

/**
 * Unsubscribe from log streaming
 *
 * @param subscription_id Subscription ID from subscribe()
 */
void tenant_log_unsubscribe(int subscription_id);

// ==================== Log Shipping ====================

/**
 * Configure log shipping
 *
 * @param config Shipping configuration
 * @return 0 on success
 */
int tenant_log_ship_configure(const struct log_ship_config *config);

/**
 * Start log shipping
 */
int tenant_log_ship_start(void);

/**
 * Stop log shipping
 */
void tenant_log_ship_stop(void);

/**
 * Flush pending logs to shipping destination
 */
int tenant_log_ship_flush(void);

// ==================== Export Functions ====================

/**
 * Export logs to JSON string
 *
 * @param filter Query filter
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return Bytes written
 */
int tenant_log_export_json(const struct tenant_log_filter *filter,
                           char *buf, size_t buf_size);

/**
 * Export logs to file
 *
 * @param filter Query filter
 * @param filename Output filename
 * @return Number of entries exported
 */
int tenant_log_export_file(const struct tenant_log_filter *filter,
                           const char *filename);

// ==================== Maintenance ====================

/**
 * Clear logs for a tenant
 */
void tenant_log_clear(tenant_id_t tenant_id);

/**
 * Clear all logs
 */
void tenant_log_clear_all(void);

/**
 * Expire old logs
 *
 * @param retention_hours Keep logs newer than this
 * @return Number of logs expired
 */
int tenant_log_expire(uint32_t retention_hours);

/**
 * Get log buffer statistics
 */
void tenant_log_get_stats(tenant_id_t tenant_id,
                          uint32_t *count, uint32_t *capacity,
                          uint64_t *drops);

// ==================== Utility ====================

/**
 * Get log level name
 */
const char* tenant_log_level_name(log_level_t level);

/**
 * Get log category name
 */
const char* tenant_log_category_name(log_category_t category);

/**
 * Get event type name
 */
const char* tenant_log_event_name(log_event_type_t event);

/**
 * Format log entry as string
 */
int tenant_log_format(const struct tenant_log_entry *entry,
                      char *buf, size_t buf_size);

/**
 * Format log entry as JSON
 */
int tenant_log_format_json(const struct tenant_log_entry *entry,
                           char *buf, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif // TENANT_LOGGING_H
