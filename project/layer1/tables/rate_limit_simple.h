/**
 * @file rate_limit_simple.h
 * @brief Simplified rate limiting for single-organization deployment
 *
 * This replaces the hierarchical tenant-based rate limiting with a simpler
 * two-level structure: Global limits -> Per-source-IP limits.
 *
 * No tenant lookups, no per-tenant quotas - just straightforward rate limiting.
 */

#ifndef RATE_LIMIT_SIMPLE_H
#define RATE_LIMIT_SIMPLE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

#define RATE_LIMIT_HASH_SIZE        (1 << 20)   /* 1M entries for per-src tracking */
#define RATE_LIMIT_PROTO_CLASSES    8           /* Protocol classes */

/* Protocol classes for rate limiting */
typedef enum {
    PROTO_CLASS_TCP_SYN = 0,
    PROTO_CLASS_TCP_ACK,
    PROTO_CLASS_TCP_RST,
    PROTO_CLASS_TCP_FIN,
    PROTO_CLASS_TCP_OTHER,
    PROTO_CLASS_UDP,
    PROTO_CLASS_ICMP,
    PROTO_CLASS_OTHER,
} proto_class_t;

/* Drop reasons */
typedef enum {
    RATE_DROP_NONE = 0,
    RATE_DROP_GLOBAL_PPS,
    RATE_DROP_GLOBAL_BPS,
    RATE_DROP_PROTO_PPS,
    RATE_DROP_SRC_PPS,
    RATE_DROP_SRC_BPS,
    RATE_DROP_EMERGENCY,
} rate_drop_reason_t;

/* ============================================================================
 * Configuration
 * ============================================================================ */

struct rate_limit_config {
    /* Global limits (applied first) */
    uint64_t    global_pps;             /* 0 = unlimited */
    uint64_t    global_bps;             /* 0 = unlimited */

    /* Per-protocol limits (PPS) */
    uint32_t    proto_pps[RATE_LIMIT_PROTO_CLASSES];

    /* Per-source-IP limits */
    uint32_t    per_src_pps;            /* Max PPS from single source */
    uint32_t    per_src_bps;            /* Max BPS from single source */

    /* Progressive rate limiting (during attack) */
    bool        progressive_enabled;
    float       progressive_factor;     /* Current multiplier (0.1 - 1.0) */

    /* Emergency mode */
    bool        emergency_mode;         /* Stricter limits during attack */
    float       emergency_factor;       /* Multiplier in emergency (default: 0.25) */
};

/* ============================================================================
 * Global Rate State (Token Bucket)
 * ============================================================================ */

struct global_rate_state {
    /* Token buckets for global limits */
    _Atomic uint64_t    pps_tokens;
    _Atomic uint64_t    bps_tokens;
    uint64_t            last_refill_tsc;

    /* Current measured rates */
    _Atomic uint64_t    current_pps;
    _Atomic uint64_t    current_bps;

    /* Per-protocol token buckets */
    _Atomic uint32_t    proto_tokens[RATE_LIMIT_PROTO_CLASSES];

    /* Statistics */
    _Atomic uint64_t    drops_global_pps;
    _Atomic uint64_t    drops_global_bps;
    _Atomic uint64_t    drops_proto[RATE_LIMIT_PROTO_CLASSES];
    _Atomic uint64_t    drops_src_pps;
    _Atomic uint64_t    drops_src_bps;
};

/* ============================================================================
 * Per-Source Rate Entry
 * ============================================================================ */

struct src_rate_entry {
    uint32_t    src_ip;
    uint32_t    pps_tokens;             /* Token bucket */
    uint32_t    bps_tokens;
    uint32_t    last_update_ms;         /* Timestamp for token refill */
    uint32_t    packet_count;           /* Packets in current window */
    uint32_t    byte_count;             /* Bytes in current window */
    uint8_t     flags;                  /* Entry flags */
    uint8_t     _pad[3];
};

/* Entry flags */
#define SRC_RATE_FLAG_VALID     (1 << 0)
#define SRC_RATE_FLAG_WARNED    (1 << 1)
#define SRC_RATE_FLAG_BLOCKED   (1 << 2)

/* ============================================================================
 * API Functions
 * ============================================================================ */

/**
 * Initialize rate limiting subsystem
 * @param cfg Initial configuration
 * @return 0 on success, -1 on error
 */
int rate_limit_init(const struct rate_limit_config *cfg);

/**
 * Cleanup rate limiting subsystem
 */
void rate_limit_cleanup(void);

/**
 * Check and consume rate limit tokens
 * @param src_ip Source IP address (host byte order)
 * @param proto_class Protocol class
 * @param pkt_len Packet length in bytes
 * @param out_reason Output: drop reason if rejected
 * @return true if packet allowed, false if rate limited
 */
bool rate_limit_check(uint32_t src_ip, proto_class_t proto_class,
                      uint16_t pkt_len, rate_drop_reason_t *out_reason);

/**
 * Get protocol class from packet info
 * @param protocol IP protocol number
 * @param tcp_flags TCP flags (if TCP)
 * @return Protocol class
 */
proto_class_t rate_limit_get_proto_class(uint8_t protocol, uint8_t tcp_flags);

/**
 * Update configuration
 * @param cfg New configuration
 */
void rate_limit_update_config(const struct rate_limit_config *cfg);

/**
 * Set emergency mode
 * @param enabled Enable emergency mode
 */
void rate_limit_set_emergency(bool enabled);

/**
 * Set progressive factor (during attack escalation)
 * @param factor Multiplier (0.1 = 10% of normal, 1.0 = full)
 */
void rate_limit_set_progressive_factor(float factor);

/**
 * Get current rates
 * @param out_pps Output: current packets per second
 * @param out_bps Output: current bits per second
 */
void rate_limit_get_current(uint64_t *out_pps, uint64_t *out_bps);

/**
 * Get statistics
 */
struct rate_limit_stats {
    uint64_t    packets_checked;
    uint64_t    packets_allowed;
    uint64_t    packets_dropped;
    uint64_t    drops_by_reason[8];
    uint64_t    current_pps;
    uint64_t    current_bps;
    uint32_t    active_sources;
    bool        emergency_mode;
    float       progressive_factor;
};
void rate_limit_get_stats(struct rate_limit_stats *stats);

/**
 * Clear per-source rate entries (for periodic cleanup)
 * @param max_age_ms Remove entries older than this (milliseconds)
 * @return Number of entries cleared
 */
uint32_t rate_limit_clear_old_entries(uint32_t max_age_ms);

/**
 * Refill token buckets (called periodically, e.g., every 10ms)
 */
void rate_limit_refill_tokens(void);

/* ============================================================================
 * Default Configuration Values
 * ============================================================================ */

#define RATE_DEFAULT_GLOBAL_PPS     10000000    /* 10 Mpps */
#define RATE_DEFAULT_GLOBAL_BPS     10000000000 /* 10 Gbps */
#define RATE_DEFAULT_PER_SRC_PPS    10000       /* 10K pps per source */
#define RATE_DEFAULT_PER_SRC_BPS    10000000    /* 10 Mbps per source */

/* Per-protocol defaults */
#define RATE_DEFAULT_SYN_PPS        5000
#define RATE_DEFAULT_ACK_PPS        50000
#define RATE_DEFAULT_RST_PPS        500
#define RATE_DEFAULT_FIN_PPS        500
#define RATE_DEFAULT_TCP_OTHER_PPS  100000
#define RATE_DEFAULT_UDP_PPS        50000
#define RATE_DEFAULT_ICMP_PPS       1000
#define RATE_DEFAULT_OTHER_PPS      10000

#define RATE_EMERGENCY_FACTOR       0.25f       /* 25% of normal in emergency */

/* ============================================================================
 * Inline Helper: Get default config
 * ============================================================================ */

static inline void rate_limit_default_config(struct rate_limit_config *cfg)
{
    cfg->global_pps = RATE_DEFAULT_GLOBAL_PPS;
    cfg->global_bps = RATE_DEFAULT_GLOBAL_BPS;
    cfg->per_src_pps = RATE_DEFAULT_PER_SRC_PPS;
    cfg->per_src_bps = RATE_DEFAULT_PER_SRC_BPS;

    cfg->proto_pps[PROTO_CLASS_TCP_SYN] = RATE_DEFAULT_SYN_PPS;
    cfg->proto_pps[PROTO_CLASS_TCP_ACK] = RATE_DEFAULT_ACK_PPS;
    cfg->proto_pps[PROTO_CLASS_TCP_RST] = RATE_DEFAULT_RST_PPS;
    cfg->proto_pps[PROTO_CLASS_TCP_FIN] = RATE_DEFAULT_FIN_PPS;
    cfg->proto_pps[PROTO_CLASS_TCP_OTHER] = RATE_DEFAULT_TCP_OTHER_PPS;
    cfg->proto_pps[PROTO_CLASS_UDP] = RATE_DEFAULT_UDP_PPS;
    cfg->proto_pps[PROTO_CLASS_ICMP] = RATE_DEFAULT_ICMP_PPS;
    cfg->proto_pps[PROTO_CLASS_OTHER] = RATE_DEFAULT_OTHER_PPS;

    cfg->progressive_enabled = true;
    cfg->progressive_factor = 1.0f;
    cfg->emergency_mode = false;
    cfg->emergency_factor = RATE_EMERGENCY_FACTOR;
}

#endif /* RATE_LIMIT_SIMPLE_H */
