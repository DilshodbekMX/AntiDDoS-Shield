/**
 * @file tenant.h
 * @brief Enterprise Multi-Tenant Core Data Model
 *
 * Provides the foundational tenant abstraction used throughout all 5 layers
 * of the Anti-DDoS system. Supports hierarchical tenants, resource quotas,
 * feature flags, and fast IP-to-tenant lookups.
 *
 * Key Features:
 * - Support for 1,024 tenants with hierarchical structure
 * - Up to 256 protected networks per tenant
 * - Thread-safe registry with read-write locks
 * - LPM-based IP-to-tenant lookup (<20 cycles)
 * - Per-tenant resource quotas and feature flags
 * - Billing integration hooks
 *
 * Performance Targets:
 * - Lookup by ID: O(1), ~5 cycles
 * - Lookup by IP (LPM): O(1), ~15-20 cycles
 * - CRUD operations: O(1) average with locking
 */

#ifndef TENANT_H
#define TENANT_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==================== Tenant Limits ====================

#define MAX_TENANTS                     1024
#define MAX_PROTECTED_IPS_PER_TENANT    256
#define MAX_TENANT_NAME_LEN             64
#define MAX_TENANT_EXTERNAL_ID_LEN      64
#define MAX_TENANT_HIERARCHY_DEPTH      3      // Reseller -> Customer -> Sub-account
#define MAX_TENANT_ALERT_EMAIL_LEN      128
#define MAX_TENANT_ALERT_WEBHOOK_LEN    256

// Reserved tenant IDs
#define TENANT_ID_INVALID               0xFFFF // Invalid/unassigned
#define TENANT_ID_GLOBAL                0      // Reserved for global policies
#define TENANT_ID_SYSTEM                0xFFFE // Reserved for system operations
#define TENANT_ID_MIN_USER              1      // First user-assignable ID
#define TENANT_ID_MAX_USER              (MAX_TENANTS - 2) // Last user-assignable ID

// ==================== Tenant Types ====================

typedef uint16_t tenant_id_t;

/**
 * Tenant operational status
 */
typedef enum {
    TENANT_STATUS_DISABLED = 0,      // Completely disabled (no traffic processed)
    TENANT_STATUS_PROVISIONING,      // Being set up (limited operation)
    TENANT_STATUS_ACTIVE,            // Normal operation
    TENANT_STATUS_SUSPENDED,         // Payment/policy issue (traffic dropped)
    TENANT_STATUS_ATTACK_MODE,       // Under active attack (elevated priority)
    TENANT_STATUS_MAINTENANCE,       // Scheduled maintenance (reduced logging)
    TENANT_STATUS_MIGRATING,         // Being moved between nodes
    TENANT_STATUS_COUNT              // Number of statuses
} tenant_status_t;

/**
 * Tenant service tier (determines SLA and resource levels)
 */
typedef enum {
    TENANT_TIER_FREE = 0,            // Limited features, best-effort
    TENANT_TIER_BASIC,               // Basic protection, no SLA
    TENANT_TIER_STANDARD,            // Standard SLA (99.9%)
    TENANT_TIER_PREMIUM,             // Enhanced SLA (99.95%)
    TENANT_TIER_ENTERPRISE,          // Full SLA (99.99%), dedicated resources
    TENANT_TIER_CUSTOM,              // Custom negotiated terms
    TENANT_TIER_COUNT                // Number of tiers
} tenant_tier_t;

/**
 * Tenant business classification
 */
typedef enum {
    TENANT_TYPE_DIRECT = 0,          // Direct customer
    TENANT_TYPE_RESELLER,            // Reseller with sub-accounts
    TENANT_TYPE_MANAGED,             // Managed service customer
    TENANT_TYPE_TRIAL,               // Trial account (time-limited)
    TENANT_TYPE_INTERNAL,            // Internal/test account
    TENANT_TYPE_COUNT                // Number of types
} tenant_type_t;

// ==================== Feature Flags ====================

/**
 * Feature flags for tenant_quotas.features_enabled
 * Each bit enables a specific capability
 */
#define TENANT_FEATURE_L1_BASIC         (1ULL << 0)   // Basic L1 filtering
#define TENANT_FEATURE_L1_ADVANCED      (1ULL << 1)   // Advanced L1 (TCP abuse, etc.)
#define TENANT_FEATURE_L2_ANOMALY       (1ULL << 2)   // L2 anomaly detection
#define TENANT_FEATURE_L3_ML            (1ULL << 3)   // L3 ML attribution
#define TENANT_FEATURE_L4_REPUTATION    (1ULL << 4)   // L4 reputation engine
#define TENANT_FEATURE_L4_CHALLENGES    (1ULL << 5)   // L4 JS/CAPTCHA challenges
#define TENANT_FEATURE_L4_BOT_MGMT      (1ULL << 6)   // L4 bot management
#define TENANT_FEATURE_L5_INTEL         (1ULL << 7)   // L5 threat intelligence
#define TENANT_FEATURE_GEO_BLOCKING     (1ULL << 8)   // Geo-IP blocking
#define TENANT_FEATURE_CUSTOM_RULES     (1ULL << 9)   // Custom firewall rules
#define TENANT_FEATURE_API_ACCESS       (1ULL << 10)  // API access
#define TENANT_FEATURE_REAL_TIME_LOGS   (1ULL << 11)  // Real-time log streaming
#define TENANT_FEATURE_ANALYTICS        (1ULL << 12)  // Advanced analytics
#define TENANT_FEATURE_ALERTING         (1ULL << 13)  // Custom alerting
#define TENANT_FEATURE_SSL_TERMINATION  (1ULL << 14)  // SSL/TLS termination
#define TENANT_FEATURE_WAF              (1ULL << 15)  // Web Application Firewall
#define TENANT_FEATURE_IPV6             (1ULL << 16)  // IPv6 support
#define TENANT_FEATURE_DNS_PROTECTION   (1ULL << 17)  // DNS amplification protection
#define TENANT_FEATURE_CUSTOM_SIGS      (1ULL << 18)  // Custom attack signatures
#define TENANT_FEATURE_CARPET_BOMB_DETECT (1ULL << 19) // Carpet Bomb Attack Detection (Subnet /24 Aggregation)

// Convenience feature sets for each tier
#define TENANT_FEATURES_FREE     (TENANT_FEATURE_L1_BASIC)

#define TENANT_FEATURES_BASIC    (TENANT_FEATURE_L1_BASIC | TENANT_FEATURE_L1_ADVANCED | \
                                  TENANT_FEATURE_L2_ANOMALY | TENANT_FEATURE_API_ACCESS)

#define TENANT_FEATURES_STANDARD (TENANT_FEATURES_BASIC | TENANT_FEATURE_L3_ML | \
                                  TENANT_FEATURE_L4_REPUTATION | TENANT_FEATURE_GEO_BLOCKING | \
                                  TENANT_FEATURE_ANALYTICS | TENANT_FEATURE_IPV6)

#define TENANT_FEATURES_PREMIUM  (TENANT_FEATURES_STANDARD | TENANT_FEATURE_L4_CHALLENGES | \
                                  TENANT_FEATURE_L4_BOT_MGMT | TENANT_FEATURE_CUSTOM_RULES | \
                                  TENANT_FEATURE_REAL_TIME_LOGS | TENANT_FEATURE_ALERTING | \
                                  TENANT_FEATURE_DNS_PROTECTION)

#define TENANT_FEATURES_ENTERPRISE (TENANT_FEATURES_PREMIUM | TENANT_FEATURE_L5_INTEL | \
                                    TENANT_FEATURE_SSL_TERMINATION | TENANT_FEATURE_WAF | \
                                    TENANT_FEATURE_CUSTOM_SIGS | TENANT_FEATURE_CARPET_BOMB_DETECT)

// ==================== Resource Quotas ====================

/**
 * Per-tenant resource quotas and limits
 * Values of 0 typically mean "unlimited" or "use tier default"
 */
struct tenant_quotas {
    // Traffic limits
    uint64_t    max_clean_bps;           // Max clean traffic (post-scrubbing)
    uint64_t    max_attack_bps;          // Max attack traffic to absorb
    uint32_t    max_clean_pps;           // Max clean PPS
    uint32_t    max_attack_pps;          // Max attack PPS to handle

    // Table allocations
    uint32_t    max_flows;               // Flow table entries (0 = default)
    uint32_t    max_connections;         // SYN proxy connections
    uint32_t    max_policies;            // Active policies (firewall rules)
    uint32_t    max_blacklist;           // Blacklist entries
    uint32_t    max_whitelist;           // Whitelist entries
    uint32_t    max_custom_signatures;   // Custom attack signatures

    // API limits
    uint32_t    api_requests_per_minute;
    uint32_t    api_requests_per_hour;
    uint32_t    max_api_tokens;

    // Feature flags (bitmask of TENANT_FEATURE_*)
    uint64_t    features_enabled;

    // Burst capacity (temporary overages allowed)
    uint32_t    burst_pps_multiplier;    // e.g., 2 = 2x burst for 10 sec
    uint32_t    burst_duration_sec;      // How long burst is allowed
};

// ==================== Protected Network ====================

/**
 * A single protected network/IP range belonging to a tenant
 */
struct tenant_protected_network {
    uint32_t    ip;                  // Network address (host byte order)
    uint8_t     prefix;              // CIDR prefix length (8-32 for IPv4)
    uint16_t    priority;            // Routing priority (lower = higher priority)
    bool        active;              // Currently active in protection
    uint8_t     _pad[2];
};

// ==================== Current Usage ====================

/**
 * Real-time usage tracking for a tenant
 * Updated periodically by the data plane
 */
struct tenant_usage {
    uint64_t    current_bps;         // Current bandwidth usage
    uint32_t    current_pps;         // Current packet rate
    uint32_t    active_flows;        // Active flow count
    uint32_t    active_connections;  // SYN proxy connection count
    uint32_t    blacklist_entries;   // Current blacklist size
    uint32_t    whitelist_entries;   // Current whitelist size
    uint32_t    policy_count;        // Active policy count
    uint64_t    total_bytes_24h;     // Total bytes in last 24 hours
    uint64_t    total_packets_24h;   // Total packets in last 24 hours
    uint64_t    drops_24h;           // Dropped packets in last 24 hours
};

// ==================== Attack State ====================

/**
 * Current attack state for a tenant
 */
struct tenant_attack_state {
    bool        under_attack;        // Currently under attack
    uint8_t     attack_severity;     // Severity 0-5 (0 = no attack)
    uint8_t     attack_type;         // Primary attack type (enum from types.h)
    uint8_t     _pad;
    uint64_t    attack_start_ns;     // When attack started (ns since epoch)
    uint64_t    attack_peak_pps;     // Peak attack PPS this incident
    uint64_t    attack_peak_bps;     // Peak attack BPS this incident
    uint32_t    attacks_24h;         // Attack count in last 24 hours
    uint32_t    attacks_total;       // Total attack count (lifetime)
    uint64_t    mitigated_pps;       // Currently mitigated PPS
    uint64_t    mitigated_bps;       // Currently mitigated BPS
};

// ==================== Core Tenant Structure ====================

/**
 * Complete tenant definition
 * This structure is stored in the tenant registry and contains
 * all information needed for tenant management and lookup.
 */
struct tenant {
    // Identity (16 bytes)
    tenant_id_t     id;                                      // Unique tenant ID
    tenant_id_t     parent_id;                               // Parent tenant ID (0 = root)
    char            name[MAX_TENANT_NAME_LEN];               // Human-readable name
    char            external_id[MAX_TENANT_EXTERNAL_ID_LEN]; // External system reference

    // Classification (4 bytes)
    tenant_status_t status;
    tenant_tier_t   tier;
    tenant_type_t   type;
    uint8_t         hierarchy_depth;      // 0 = root, 1 = child, etc.

    // Protected networks
    struct tenant_protected_network protected_networks[MAX_PROTECTED_IPS_PER_TENANT];
    uint32_t        protected_count;      // Number of active protected networks

    // Resource quotas
    struct tenant_quotas quotas;

    // Current usage (updated by data plane)
    struct tenant_usage usage;

    // Attack state (updated by detection layers)
    struct tenant_attack_state attack_state;

    // Timestamps (Unix timestamps in seconds)
    uint64_t        created_at;           // Creation time
    uint64_t        updated_at;           // Last config update
    uint64_t        last_active_at;       // Last traffic seen
    uint64_t        last_attack_at;       // Last attack detected
    uint64_t        trial_expires_at;     // For trial accounts

    // Contact for alerts
    char            alert_email[MAX_TENANT_ALERT_EMAIL_LEN];
    char            alert_webhook[MAX_TENANT_ALERT_WEBHOOK_LEN];
    uint64_t        alert_throttle_sec;   // Min seconds between alerts
    uint64_t        last_alert_at;        // Last alert sent (for throttling)

    // Internal flags
    uint32_t        internal_flags;       // System-internal flags
    uint32_t        _reserved[7];         // Reserved for future use
};

// Internal flags
#define TENANT_INTERNAL_FLAG_DIRTY      (1U << 0)  // Config changed, needs sync
#define TENANT_INTERNAL_FLAG_DELETED    (1U << 1)  // Marked for deletion
#define TENANT_INTERNAL_FLAG_LOCKED     (1U << 2)  // Admin-locked

// ==================== Tenant Registry ====================

/**
 * Registry error codes
 */
#define TENANT_OK                   0
#define TENANT_ERR_NOT_FOUND       -1
#define TENANT_ERR_EXISTS          -2
#define TENANT_ERR_INVALID         -3
#define TENANT_ERR_QUOTA           -4
#define TENANT_ERR_FULL            -5
#define TENANT_ERR_LOCKED          -6
#define TENANT_ERR_MEMORY          -7
#define TENANT_ERR_IO              -8
#define TENANT_ERR_CONFIG          -9

/**
 * Tenant registry statistics
 */
struct tenant_registry_stats {
    uint32_t        active_count;        // Active tenant count
    uint32_t        total_protected_ips; // Total protected IPs across all tenants
    uint64_t        lookups_by_id;       // Lookup by ID count
    uint64_t        lookups_by_ip;       // Lookup by IP count
    uint64_t        lookups_by_name;     // Lookup by name count
    uint64_t        cache_hits;          // Per-lcore cache hits
    uint64_t        cache_misses;        // Per-lcore cache misses
    uint64_t        lock_contentions;    // Lock contention count
    uint64_t        config_reloads;      // Config reload count
};

/**
 * Tenant registry (singleton, managed by tenant.c)
 * Internal implementation - use API functions instead
 */
struct tenant_registry {
    struct tenant   tenants[MAX_TENANTS];
    uint32_t        active_count;
    uint64_t        version;             // Config version (for cache invalidation)

    // Single-tenant optimization cache
    // Updated atomically when active_count transitions to/from 1
    tenant_id_t     default_tenant_id;   // Cached ID when active_count == 1
    uint16_t        _default_pad;        // Padding for alignment

    // Indexes for fast lookup (opaque pointers)
    void           *ip_to_tenant_lpm;    // rte_lpm for IP -> tenant_id
    void           *name_to_tenant_hash; // Hash table for name -> tenant_id
    void           *extid_to_tenant_hash;// Hash table for external_id -> tenant_id

    // Statistics
    struct tenant_registry_stats stats;

    // Concurrency control
    pthread_rwlock_t lock;
};

// ==================== Initialization API ====================

/**
 * Initialize the tenant registry
 * Must be called once before any other tenant functions
 *
 * @return TENANT_OK on success, negative error code on failure
 */
int tenant_registry_init(void);

/**
 * Cleanup the tenant registry
 * Frees all resources. No tenant functions may be called after this.
 */
void tenant_registry_cleanup(void);

/**
 * Load tenants from configuration file
 *
 * @param config_path  Path to JSON config file
 * @return TENANT_OK on success, negative error code on failure
 */
int tenant_registry_load(const char *config_path);

/**
 * Reload tenant configuration (hot reload)
 * Updates existing tenants, adds new ones, marks removed ones as deleted
 *
 * @return TENANT_OK on success, negative error code on failure
 */
int tenant_registry_reload(void);

/**
 * Get current registry version
 * Used by per-lcore caches to detect config changes
 *
 * @return Current version number
 */
uint64_t tenant_registry_get_version(void);

// ==================== Lookup API (Fast Path) ====================

/**
 * Lookup tenant by ID
 * Thread-safe, lock-free read
 *
 * @param id  Tenant ID
 * @return Pointer to tenant (READ-ONLY), or NULL if not found
 */
const struct tenant* tenant_lookup(tenant_id_t id);

/**
 * Lookup tenant by destination IP (LPM)
 * Thread-safe, lock-free read. ~15-20 cycles.
 *
 * @param dst_ip  Destination IP (network byte order)
 * @return Pointer to tenant (READ-ONLY), or NULL if IP not protected
 */
const struct tenant* tenant_lookup_by_ip(uint32_t dst_ip);

/**
 * Lookup tenant by name
 * Thread-safe, requires read lock
 *
 * @param name  Tenant name
 * @return Pointer to tenant (READ-ONLY), or NULL if not found
 */
const struct tenant* tenant_lookup_by_name(const char *name);

/**
 * Lookup tenant by external ID
 * Thread-safe, requires read lock
 *
 * @param external_id  External system ID
 * @return Pointer to tenant (READ-ONLY), or NULL if not found
 */
const struct tenant* tenant_lookup_by_external_id(const char *external_id);

/**
 * Get tenant ID from destination IP (fastest lookup)
 * Returns TENANT_ID_INVALID if IP is not protected
 *
 * @param dst_ip  Destination IP (network byte order)
 * @return Tenant ID, or TENANT_ID_INVALID
 */
tenant_id_t tenant_ip_to_id(uint32_t dst_ip);

/**
 * Check if tenant has a specific feature enabled
 *
 * @param id       Tenant ID
 * @param feature  Feature flag (TENANT_FEATURE_*)
 * @return true if feature is enabled
 */
bool tenant_has_feature(tenant_id_t id, uint64_t feature);

/**
 * Check if tenant is active and can receive traffic
 *
 * @param id  Tenant ID
 * @return true if tenant is active
 */
bool tenant_is_active(tenant_id_t id);

// ==================== CRUD API (Control Path) ====================

/**
 * Create a new tenant
 * Requires write lock. Validates all fields.
 *
 * @param t       Tenant data (id may be 0 for auto-assign)
 * @param out_id  Output: assigned tenant ID
 * @return TENANT_OK on success, negative error code on failure
 */
int tenant_create(const struct tenant *t, tenant_id_t *out_id);

/**
 * Update an existing tenant
 * Requires write lock. Does not modify ID or protected networks.
 *
 * @param id  Tenant ID to update
 * @param t   Updated tenant data
 * @return TENANT_OK on success, negative error code on failure
 */
int tenant_update(tenant_id_t id, const struct tenant *t);

/**
 * Delete a tenant
 * Requires write lock. Marks as deleted, actual cleanup on next maintenance.
 *
 * @param id  Tenant ID to delete
 * @return TENANT_OK on success, negative error code on failure
 */
int tenant_delete(tenant_id_t id);

/**
 * Set tenant status
 * Requires write lock.
 *
 * @param id      Tenant ID
 * @param status  New status
 * @return TENANT_OK on success, negative error code on failure
 */
int tenant_set_status(tenant_id_t id, tenant_status_t status);

// ==================== Protected Network Management ====================

/**
 * Add a protected network to a tenant
 * Requires write lock. Updates LPM table.
 *
 * @param id      Tenant ID
 * @param ip      Network IP (host byte order)
 * @param prefix  CIDR prefix (8-32)
 * @return TENANT_OK on success, negative error code on failure
 */
int tenant_add_network(tenant_id_t id, uint32_t ip, uint8_t prefix);

/**
 * Remove a protected network from a tenant
 * Requires write lock. Updates LPM table.
 *
 * @param id      Tenant ID
 * @param ip      Network IP (host byte order)
 * @param prefix  CIDR prefix
 * @return TENANT_OK on success, negative error code on failure
 */
int tenant_remove_network(tenant_id_t id, uint32_t ip, uint8_t prefix);

/**
 * Activate or deactivate a protected network
 *
 * @param id      Tenant ID
 * @param ip      Network IP (host byte order)
 * @param prefix  CIDR prefix
 * @param active  true to activate, false to deactivate
 * @return TENANT_OK on success, negative error code on failure
 */
int tenant_set_network_active(tenant_id_t id, uint32_t ip, uint8_t prefix, bool active);

// ==================== Usage & Attack State ====================

/**
 * Update tenant usage statistics
 * Called periodically by the data plane. Lock-free atomic updates.
 *
 * @param id       Tenant ID
 * @param bytes    Bytes processed since last update
 * @param packets  Packets processed since last update
 */
void tenant_update_usage(tenant_id_t id, uint64_t bytes, uint32_t packets);

/**
 * Check if tenant is within quota
 *
 * @param id       Tenant ID
 * @param bytes    Proposed bytes to process
 * @param packets  Proposed packets to process
 * @return true if within quota
 */
bool tenant_check_quota(tenant_id_t id, uint64_t bytes, uint32_t packets);

/**
 * Set tenant attack state
 * Called by detection layers (L2, L3, L4).
 *
 * @param id            Tenant ID
 * @param under_attack  true if attack is ongoing
 * @param severity      Attack severity (0-5)
 * @param attack_type   Attack type code
 */
void tenant_set_attack_state(tenant_id_t id, bool under_attack,
                             uint8_t severity, uint8_t attack_type);

/**
 * Update attack mitigation stats
 *
 * @param id       Tenant ID
 * @param pps      Mitigated packets per second
 * @param bps      Mitigated bits per second
 */
void tenant_update_mitigation_stats(tenant_id_t id, uint64_t pps, uint64_t bps);

// ==================== Iteration & Bulk Operations ====================

/**
 * Callback for tenant iteration
 */
typedef void (*tenant_iterator_fn)(const struct tenant *t, void *ctx);

/**
 * Iterate over all active tenants
 * Requires read lock during iteration.
 *
 * @param fn   Callback function
 * @param ctx  User context passed to callback
 */
void tenant_foreach(tenant_iterator_fn fn, void *ctx);

/**
 * Get count of active tenants
 */
uint32_t tenant_get_active_count(void);

// ==================== Single-Tenant Optimization API ====================

/**
 * Check if single-tenant optimization is active
 * Returns true when exactly 1 tenant is registered.
 * Use this for fast-path decisions to skip LPM lookups.
 *
 * @return true if exactly one tenant is active
 */
bool tenant_is_single_mode(void);

/**
 * Get default tenant ID for single-tenant mode
 * Returns the only active tenant_id when count == 1,
 * or TENANT_ID_INVALID if not in single-tenant mode.
 *
 * @return Tenant ID, or TENANT_ID_INVALID if multi-tenant mode
 */
tenant_id_t tenant_get_default_id(void);

/**
 * Get default tenant pointer for single-tenant optimization
 * Returns cached pointer when tenant_count == 1, NULL otherwise.
 * Use this to skip LPM lookup when only one tenant exists.
 *
 * @return Pointer to tenant (READ-ONLY), or NULL if multi-tenant mode
 */
const struct tenant* tenant_get_default(void);

/**
 * Get registry statistics
 *
 * @param stats  Output structure
 */
void tenant_get_stats(struct tenant_registry_stats *stats);

/**
 * Reset registry statistics
 */
void tenant_reset_stats(void);

// ==================== Serialization ====================

/**
 * Serialize tenant to JSON
 *
 * @param t         Tenant to serialize
 * @param buf       Output buffer
 * @param buf_size  Buffer size
 * @return Number of bytes written, or negative error code
 */
int tenant_to_json(const struct tenant *t, char *buf, size_t buf_size);

/**
 * Deserialize tenant from JSON
 *
 * @param json  JSON string
 * @param t     Output tenant structure
 * @return TENANT_OK on success, negative error code on failure
 */
int tenant_from_json(const char *json, struct tenant *t);

// ==================== Utility Functions ====================

/**
 * Get string name for tenant status
 */
const char* tenant_status_to_string(tenant_status_t status);

/**
 * Get string name for tenant tier
 */
const char* tenant_tier_to_string(tenant_tier_t tier);

/**
 * Get string name for tenant type
 */
const char* tenant_type_to_string(tenant_type_t type);

/**
 * Get default quotas for a tier
 */
void tenant_get_tier_default_quotas(tenant_tier_t tier, struct tenant_quotas *quotas);

/**
 * Validate tenant structure
 *
 * @param t            Tenant to validate
 * @param errors       Output buffer for error messages
 * @param errors_size  Buffer size
 * @return TENANT_OK if valid, TENANT_ERR_INVALID if not
 */
int tenant_validate(const struct tenant *t, char *errors, size_t errors_size);

/**
 * Print tenant info to stdout (for debugging)
 */
void tenant_print(const struct tenant *t);

/**
 * Print registry summary to stdout (for debugging)
 */
void tenant_print_registry_summary(void);

// ==================== IPv6 Support ====================

/**
 * IPv6 protected network entry
 */
struct tenant_protected_network_v6 {
    uint8_t     ip[16];               // IPv6 address (network byte order)
    uint8_t     prefix;               // CIDR prefix length (8-128)
    uint16_t    priority;             // Routing priority
    bool        active;               // Currently active
    uint8_t     _pad[4];
};

/**
 * Add an IPv6 protected network to a tenant
 *
 * @param id      Tenant ID
 * @param ip      IPv6 address (16 bytes, network byte order)
 * @param prefix  CIDR prefix (8-128)
 * @return TENANT_OK on success
 */
int tenant_add_network_v6(tenant_id_t id, const uint8_t ip[16], uint8_t prefix);

/**
 * Remove an IPv6 protected network from a tenant
 */
int tenant_remove_network_v6(tenant_id_t id, const uint8_t ip[16], uint8_t prefix);

/**
 * Lookup tenant by IPv6 destination
 *
 * @param dst_ip  Destination IPv6 (16 bytes, network byte order)
 * @return Tenant ID, or TENANT_ID_INVALID
 */
tenant_id_t tenant_ipv6_to_id(const uint8_t dst_ip[16]);

// ==================== Billing Integration ====================

/**
 * Billing record for usage-based pricing
 */
struct tenant_billing_record {
    tenant_id_t tenant_id;
    uint64_t    period_start;         // Unix timestamp
    uint64_t    period_end;           // Unix timestamp
    uint64_t    clean_bytes;          // Clean traffic bytes
    uint64_t    clean_packets;        // Clean traffic packets
    uint64_t    attack_bytes;         // Attack traffic mitigated
    uint64_t    attack_packets;       // Attack packets mitigated
    uint32_t    attacks_mitigated;    // Number of attacks
    uint64_t    peak_clean_bps;       // Peak clean bandwidth
    uint64_t    peak_attack_bps;      // Peak attack bandwidth
    double      uptime_percentage;    // Service uptime
};

/**
 * Callback for billing data export
 */
typedef void (*tenant_billing_callback_t)(const struct tenant_billing_record *record, void *ctx);

/**
 * Export billing data for a tenant
 *
 * @param id          Tenant ID (TENANT_ID_GLOBAL for all)
 * @param start_time  Period start (Unix timestamp)
 * @param end_time    Period end (Unix timestamp)
 * @param cb          Callback for each billing record
 * @param ctx         User context
 */
void tenant_export_billing(tenant_id_t id, uint64_t start_time,
                          uint64_t end_time, tenant_billing_callback_t cb, void *ctx);

/**
 * Get current billing period summary for a tenant
 */
int tenant_get_billing_summary(tenant_id_t id, struct tenant_billing_record *record);

/**
 * Reset billing counters for new billing period
 */
void tenant_reset_billing_period(tenant_id_t id);

// ==================== Emergency Operations ====================

/**
 * Set global emergency mode (affects all tenants)
 * Used during massive DDoS attacks
 *
 * @param emergency  true to enable emergency mode
 */
void tenant_set_global_emergency(bool emergency);

/**
 * Check if system is in global emergency mode
 */
bool tenant_is_global_emergency(void);

/**
 * Get tenants currently under attack
 *
 * @param ids       Output array of tenant IDs
 * @param max_count Maximum IDs to return
 * @return Number of tenants under attack
 */
uint32_t tenant_get_under_attack_list(tenant_id_t *ids, uint32_t max_count);

#ifdef __cplusplus
}
#endif

#endif // TENANT_H
