/**
 * @file tenant_rate_limit.h
 * @brief Hierarchical Per-Tenant Rate Limiting
 *
 * Implements a multi-level rate limiting hierarchy:
 *
 * Level 1: Global Emergency Limits (system-wide DDoS protection)
 *          - Always checked first, overrides all tenant limits
 *          - Used during massive attacks to protect system
 *
 * Level 2: Per-Tenant Aggregate Limits
 *          - Total PPS/BPS allowed for the tenant
 *          - Based on tier + any custom overrides
 *
 * Level 3: Per-Protocol Limits (within tenant)
 *          - TCP, UDP, ICMP, SYN separate buckets
 *          - Prevents protocol-specific floods from exhausting tenant quota
 *
 * Level 4: Per-Source-IP Limits (within tenant)
 *          - Limits per source IP within tenant scope
 *          - Prevents single source from exhausting tenant quota
 *
 * Algorithm: Token Bucket with configurable capacity and refill rate
 *
 * Performance Target: <50 cycles per rate check
 */

#ifndef TENANT_RATE_LIMIT_H
#define TENANT_RATE_LIMIT_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

#include "../../common/tenant.h"

#ifdef __cplusplus
extern "C" {
#endif

// ==================== Configuration ====================

// Maximum per-tenant source IP tracking entries
#define TENANT_RATE_MAX_SRC_IPS         (1024 * 1024)  // 1M total entries
#define TENANT_RATE_SRC_HASH_ENTRIES    (TENANT_RATE_MAX_SRC_IPS * 2)

// Token bucket defaults
#define TENANT_RATE_BUCKET_BURST_MULT   2     // Burst = 2x refill rate
#define TENANT_RATE_BUCKET_UPDATE_MS    10    // Refill every 10ms

// Protocol classes for per-protocol rate limiting
#define PROTO_CLASS_TCP_SYN     0
#define PROTO_CLASS_TCP_OTHER   1
#define PROTO_CLASS_UDP         2
#define PROTO_CLASS_ICMP        3
#define PROTO_CLASS_OTHER       4
#define PROTO_CLASS_COUNT       5

// ==================== Token Bucket Structure ====================

/**
 * Token bucket for rate limiting
 * Uses atomic operations for lock-free updates
 */
struct token_bucket {
    _Atomic uint64_t tokens;         // Current token count
    uint64_t         capacity;       // Maximum tokens (burst size)
    uint64_t         refill_rate;    // Tokens per second
    uint64_t         last_update_tsc;// TSC of last refill
};

/**
 * Initialize a token bucket
 */
static inline void token_bucket_init(struct token_bucket *tb,
                                     uint64_t rate_per_sec,
                                     uint64_t burst_mult) {
    tb->refill_rate = rate_per_sec;
    tb->capacity = rate_per_sec * burst_mult;
    atomic_store(&tb->tokens, tb->capacity);
    tb->last_update_tsc = 0;
}

/**
 * Try to consume tokens from bucket
 * Returns true if tokens were consumed, false if insufficient
 */
bool token_bucket_consume(struct token_bucket *tb, uint64_t count,
                          uint64_t now_tsc, uint64_t tsc_hz);

/**
 * Refill tokens based on elapsed time
 */
void token_bucket_refill(struct token_bucket *tb,
                         uint64_t now_tsc, uint64_t tsc_hz);

/**
 * Get current token count
 */
static inline uint64_t token_bucket_get_tokens(const struct token_bucket *tb) {
    return atomic_load(&tb->tokens);
}

// ==================== Per-Tenant Rate State ====================

/**
 * Per-tenant aggregate rate limiting state
 * One instance per active tenant
 */
struct tenant_rate_state {
    tenant_id_t tenant_id;
    uint8_t     _pad[2];
    uint32_t    flags;               // TENANT_RATE_FLAG_*

    // Aggregate token buckets
    struct token_bucket total_pps;   // Total packets/sec
    struct token_bucket total_bps;   // Total bytes/sec (tokens = bytes)

    // Per-protocol token buckets (packets/sec)
    struct token_bucket proto[PROTO_CLASS_COUNT];

    // Current measured rates (updated atomically)
    _Atomic uint64_t current_pps;
    _Atomic uint64_t current_bps;
    _Atomic uint64_t peak_pps;       // Peak in current period
    _Atomic uint64_t peak_bps;

    // Measurement window
    uint64_t window_start_tsc;
    _Atomic uint64_t window_packets;
    _Atomic uint64_t window_bytes;

    // Rate exceeded state
    _Atomic bool     rate_exceeded;
    uint64_t         exceeded_since_tsc;
    uint8_t          exceeded_reason;  // DROP_REASON_* that triggered

    // Emergency mode
    _Atomic bool     emergency_mode;

    // Config reference (from tenant_config)
    uint64_t         config_version;
    const struct tenant_l1_config *config;

    // Statistics
    _Atomic uint64_t drops_total;
    _Atomic uint64_t drops_pps;
    _Atomic uint64_t drops_bps;
    _Atomic uint64_t drops_proto[PROTO_CLASS_COUNT];
    _Atomic uint64_t drops_src;      // Per-source drops
};

// Tenant rate state flags
#define TENANT_RATE_FLAG_ACTIVE       0x01
#define TENANT_RATE_FLAG_CUSTOM_LIMIT 0x02  // Has custom limits (not tier default)
#define TENANT_RATE_FLAG_EMERGENCY    0x04
#define TENANT_RATE_FLAG_UNDER_ATTACK 0x08

// ==================== Per-Source Rate Tracking ====================

/**
 * Key for per-source rate lookup within tenant scope
 */
struct tenant_src_rate_key {
    tenant_id_t tenant_id;
    uint32_t    src_ip;
    uint8_t     proto_class;         // PROTO_CLASS_*
    uint8_t     _pad[3];
} __attribute__((packed));

/**
 * Per-source-IP rate entry
 * Smaller structure for memory efficiency (millions of entries)
 * Use atomic types for lock-free multi-lcore access
 */
struct tenant_src_rate_entry {
    _Atomic uint32_t tokens;         // Token count (packets)
    _Atomic uint32_t last_update_ms; // Milliseconds since epoch (lower 32 bits)
    _Atomic uint32_t packet_count;   // Packets in current window
    _Atomic uint32_t byte_count;     // Bytes in current window
};

// ==================== Global Rate State ====================

/**
 * Global emergency rate limiting state
 * Applied before any tenant-specific checks
 */
struct global_rate_state {
    _Atomic bool     emergency_active;
    uint64_t         emergency_start_tsc;

    // Emergency limits
    struct token_bucket emergency_pps;
    struct token_bucket emergency_bps;

    // Current global rates
    _Atomic uint64_t global_pps;
    _Atomic uint64_t global_bps;

    // Emergency thresholds
    uint64_t         emergency_threshold_pps;
    uint64_t         emergency_threshold_bps;

    // Statistics
    _Atomic uint64_t emergency_drops;
};

// ==================== Rate Check Result ====================

/**
 * Result of rate limit check
 */
struct rate_check_result {
    bool     allowed;                // true if packet allowed
    uint8_t  drop_reason;            // DROP_REASON_* if dropped
    uint8_t  drop_level;             // Which level dropped (1-4)
    uint8_t  proto_class;            // Protocol class that was limited

    // Current usage for monitoring
    uint64_t tenant_pps;             // Current tenant PPS
    uint64_t tenant_bps;             // Current tenant BPS
    uint64_t src_pps;                // Current source PPS (if tracked)
};

// ==================== Initialization API ====================

/**
 * Initialize tenant rate limiting subsystem
 *
 * @return 0 on success, -1 on failure
 */
int tenant_rate_limit_init(void);

/**
 * Cleanup tenant rate limiting subsystem
 */
void tenant_rate_limit_cleanup(void);

/**
 * Initialize rate state for a tenant
 * Called when tenant is created or activated
 *
 * @param tenant_id  Tenant ID
 * @param config     Tenant L1 configuration
 * @return 0 on success, -1 on failure
 */
int tenant_rate_state_init(tenant_id_t tenant_id,
                           const struct tenant_l1_config *config);

/**
 * Cleanup rate state for a tenant
 * Called when tenant is deleted or deactivated
 */
void tenant_rate_state_cleanup(tenant_id_t tenant_id);

/**
 * Update rate state configuration
 * Called when tenant config changes
 */
int tenant_rate_state_update_config(tenant_id_t tenant_id,
                                    const struct tenant_l1_config *config);

// ==================== Fast Path API ====================

/**
 * Check rate limits for a packet (FAST PATH)
 * This is the main entry point for rate checking in packet processing
 *
 * @param tenant_id   Resolved tenant ID
 * @param src_ip      Source IP (network byte order)
 * @param protocol    IP protocol number (6=TCP, 17=UDP, 1=ICMP)
 * @param pkt_len     Packet length in bytes
 * @param tcp_flags   TCP flags (0 for non-TCP)
 * @param result      Output: check result with details
 * @return true if packet allowed, false if rate limited
 */
bool tenant_rate_check(tenant_id_t tenant_id,
                       uint32_t src_ip,
                       uint8_t protocol,
                       uint16_t pkt_len,
                       uint8_t tcp_flags,
                       struct rate_check_result *result);

/**
 * Simple rate check (returns only allow/deny)
 * Slightly faster than full check, use when details not needed
 *
 * @param tenant_id   Tenant ID
 * @param src_ip      Source IP
 * @param protocol    IP protocol
 * @param pkt_len     Packet length
 * @param tcp_flags   TCP flags
 * @param out_reason  Output: drop reason if dropped
 * @return true if allowed
 */
bool tenant_rate_check_simple(tenant_id_t tenant_id,
                              uint32_t src_ip,
                              uint8_t protocol,
                              uint16_t pkt_len,
                              uint8_t tcp_flags,
                              uint8_t *out_reason);

/**
 * Update packet counters (call after packet accepted)
 * Updates per-tenant and per-source statistics
 *
 * @param tenant_id  Tenant ID
 * @param src_ip     Source IP
 * @param protocol   Protocol
 * @param pkt_len    Packet length
 */
void tenant_rate_update_counters(tenant_id_t tenant_id,
                                 uint32_t src_ip,
                                 uint8_t protocol,
                                 uint16_t pkt_len);

// ==================== Global Emergency API ====================

/**
 * Check global emergency rate limits
 * Called before tenant-specific checks
 *
 * @param src_ip     Source IP
 * @param pkt_len    Packet length
 * @return true if allowed, false if blocked by emergency limits
 */
bool global_rate_check(uint32_t src_ip, uint16_t pkt_len);

/**
 * Activate global emergency mode
 * Dramatically reduces rate limits system-wide
 *
 * @param threshold_pps  Emergency PPS threshold (0 for auto)
 * @param threshold_bps  Emergency BPS threshold (0 for auto)
 */
void global_rate_set_emergency(uint64_t threshold_pps, uint64_t threshold_bps);

/**
 * Deactivate global emergency mode
 */
void global_rate_clear_emergency(void);

/**
 * Check if global emergency is active
 */
bool global_rate_is_emergency(void);

/**
 * Update global traffic statistics
 * Called periodically from stats collection
 */
void global_rate_update_stats(uint64_t pps, uint64_t bps);

// ==================== Tenant Control API ====================

/**
 * Set custom rate limits for tenant (overrides tier defaults)
 *
 * @param tenant_id  Tenant ID
 * @param pps        Packets per second (0 to clear override)
 * @param bps        Bytes per second (0 to clear override)
 * @return 0 on success
 */
int tenant_rate_set_limits(tenant_id_t tenant_id, uint64_t pps, uint64_t bps);

/**
 * Set per-protocol limits for tenant
 *
 * @param tenant_id    Tenant ID
 * @param proto_class  PROTO_CLASS_*
 * @param pps          Packets per second
 * @return 0 on success
 */
int tenant_rate_set_proto_limit(tenant_id_t tenant_id,
                                uint8_t proto_class, uint64_t pps);

/**
 * Set tenant emergency mode
 * More restrictive than normal rate limiting
 */
void tenant_rate_set_emergency(tenant_id_t tenant_id, bool emergency);

/**
 * Check if tenant is in emergency mode
 */
bool tenant_rate_is_emergency(tenant_id_t tenant_id);

// ==================== Statistics API ====================

/**
 * Get current rate usage for tenant
 *
 * @param tenant_id  Tenant ID
 * @param out_pps    Output: current PPS
 * @param out_bps    Output: current BPS
 * @return 0 on success, -1 if tenant not found
 */
int tenant_rate_get_current(tenant_id_t tenant_id,
                            uint64_t *out_pps, uint64_t *out_bps);

/**
 * Get peak rates for tenant in current period
 */
int tenant_rate_get_peak(tenant_id_t tenant_id,
                         uint64_t *out_peak_pps, uint64_t *out_peak_bps);

/**
 * Get rate drop statistics for tenant
 */
int tenant_rate_get_drops(tenant_id_t tenant_id,
                          uint64_t *out_total,
                          uint64_t *out_pps_drops,
                          uint64_t *out_bps_drops);

/**
 * Reset tenant rate statistics
 */
void tenant_rate_reset_stats(tenant_id_t tenant_id);

/**
 * Reset all rate statistics
 */
void tenant_rate_reset_all_stats(void);

// ==================== Maintenance API ====================

/**
 * Periodic maintenance (call every ~100ms)
 * - Refills token buckets
 * - Updates rate measurements
 * - Ages out per-source entries
 */
void tenant_rate_maintenance(void);

/**
 * Age out stale per-source entries
 * Called less frequently (every ~1s)
 *
 * @return Number of entries aged out
 */
uint32_t tenant_rate_age_src_entries(void);

// ==================== Utility Functions ====================

/**
 * Get protocol class from IP protocol and TCP flags
 */
static inline uint8_t get_proto_class(uint8_t protocol, uint8_t tcp_flags) {
    if (protocol == 6) {  // TCP
        // SYN without ACK
        if ((tcp_flags & 0x12) == 0x02) {
            return PROTO_CLASS_TCP_SYN;
        }
        return PROTO_CLASS_TCP_OTHER;
    } else if (protocol == 17) {  // UDP
        return PROTO_CLASS_UDP;
    } else if (protocol == 1) {   // ICMP
        return PROTO_CLASS_ICMP;
    }
    return PROTO_CLASS_OTHER;
}

/**
 * Get protocol class name
 */
const char* proto_class_to_string(uint8_t proto_class);

#ifdef __cplusplus
}
#endif

#endif // TENANT_RATE_LIMIT_H
