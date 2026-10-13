#include "syn_proxy.h"
#include "flow_table.h"
#include "ip_lists.h"
#include "../layer1.h"
#include "../config/layer1_config.h"
#include "../interlayer/reputation_interface.h"
#include "../interlayer/policy_interface.h"
#include "../interlayer/shared_memory.h"
#include "../../core/dpdk_core.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ether.h>
#include <rte_random.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdatomic.h>

#define RTE_LOGTYPE_SYNPROXY RTE_LOGTYPE_USER3

// ==================== Constants ====================

#define MAX_SYN_RETRIES         3
#define COOKIE_TIMESTAMP_BITS   4
#define COOKIE_MSS_BITS         4
#define COOKIE_HASH_BITS        24
#define SYN_RATE_WINDOW_SEC     1       // 1-second window for rate estimation
#define DEFAULT_CHALLENGE_THRESHOLD 1000 // Default SYN PPS threshold for challenge
#define MAX_SYNACK_RATE         250000  // Maximum SYN-ACK responses per second (rate limit)

// MSS table for cookie encoding (4 bits = 16 values)
static const uint16_t MSS_TABLE[16] = {
    536, 1200, 1300, 1400, 1440, 1460, 1480, 1500,
    512, 768, 1024, 1280, 1360, 2048, 4096, 9000
};

// ==================== Global State ====================

static struct syn_proxy_config g_config;
static struct rte_hash *g_conn_hash = NULL;
static struct syn_proxy_conn *g_conn_pool = NULL;
static struct syn_proxy_stats g_stats;
static bool g_initialized = false;

// Cookie secrets (current and previous for rotation)
static uint32_t g_current_secret = 0;
static uint32_t g_previous_secret = 0;
static uint64_t g_last_rotation_tsc = 0;

// SipHash key for cryptographic cookie hashing (replaces CRC32C)
#include "../../common/siphash.h"
static uint64_t g_siphash_key[2];

// SYN rate tracking for intelligent challenging
static uint64_t g_syn_count_current = 0;
static uint64_t g_syn_count_previous = 0;
static uint64_t g_syn_window_start_tsc = 0;
static uint64_t g_tsc_hz = 0;
static uint32_t g_challenge_threshold = DEFAULT_CHALLENGE_THRESHOLD;

// SYN-ACK response rate limiting (prevent overwhelming network)
static uint64_t g_synack_count_current = 0;
static uint64_t g_synack_window_start_tsc = 0;

// ==================== Adaptive Mode State ====================
// Current operating mode (stateful vs stateless)
static enum syn_proxy_mode g_current_mode = SYN_PROXY_MODE_STATEFUL;
static int g_forced_mode = -1;  // -1 = adaptive, 0 = force stateful, 1 = force stateless

// Mode switch timing (hysteresis to prevent flapping)
static uint64_t g_last_mode_switch_tsc = 0;
static uint64_t g_mode_switch_delay_tsc = 0;

// Per-second SYN rate tracking for adaptive mode
static uint64_t g_adaptive_syn_count = 0;
static uint64_t g_adaptive_window_start_tsc = 0;
static uint32_t g_current_syn_rate_pps = 0;

// Consecutive window counters for hysteresis
// Require multiple consecutive windows above/below threshold before switching
static uint32_t g_consecutive_above_threshold = 0;  // Windows above stateless threshold
static uint32_t g_consecutive_below_threshold = 0;  // Windows below stateful threshold

// Default thresholds (can be overridden by config)
// Improved hysteresis to prevent mode oscillation attacks
// - Increased gap between thresholds (50K up, 5K down instead of 10K)
// - Increased time hysteresis from 1s to 3s
// - Added consecutive window requirement (3 windows)
#define DEFAULT_STATELESS_THRESHOLD_PPS  50000   // Switch to stateless above 50K SYN/sec
#define DEFAULT_STATEFUL_THRESHOLD_PPS   5000    // Switch back to stateful below 5K SYN/sec
#define DEFAULT_MODE_SWITCH_DELAY_MS     3000    // 3 second minimum between switches
#define DEFAULT_CONSECUTIVE_WINDOWS      3       // Require N consecutive windows above/below threshold

// ==================== Per-Source-IP Half-Open Connection Limit ====================
// Prevents a single source IP from monopolizing the connection pool
// Uses a small hash table with atomic counters (fast-path safe, no locks)
#define HALF_OPEN_TABLE_SIZE     65536   // 64K entries (power of 2 for fast modulo)
#define HALF_OPEN_TABLE_MASK     (HALF_OPEN_TABLE_SIZE - 1)
#define MAX_HALF_OPEN_PER_IP     64      // Max half-open connections per source IP

struct half_open_entry {
    uint32_t src_ip;               // Source IP (0 = empty)
    uint32_t count;                // Half-open connection count (atomic)
} __rte_cache_aligned;

static struct half_open_entry g_half_open_table[HALF_OPEN_TABLE_SIZE];

static inline uint32_t half_open_hash(uint32_t src_ip) {
    // Simple but effective hash for IPv4 -- mix bytes
    uint32_t h = src_ip;
    h ^= h >> 16;
    h *= 0x45d9f3b;
    h ^= h >> 16;
    return h & HALF_OPEN_TABLE_MASK;
}

static inline bool half_open_try_increment(uint32_t src_ip) {
    uint32_t idx = half_open_hash(src_ip);
    struct half_open_entry *e = &g_half_open_table[idx];
    // Simple open-addressing: if slot is empty or matches our IP, use it
    uint32_t existing = __atomic_load_n(&e->src_ip, __ATOMIC_RELAXED);
    if (existing != src_ip && existing != 0) {
        // Collision -- allow through (conservative: don't block on hash collision)
        return true;
    }
    // CAS to claim slot atomically (prevents TOCTOU between check and store)
    if (existing == 0) {
        if (!__atomic_compare_exchange_n(&e->src_ip, &existing, src_ip,
                                          false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            // Another lcore claimed it; if not our IP, allow through
            if (existing != src_ip) return true;
        }
    }
    // Atomic CAS loop for count increment with limit check
    uint32_t cur = __atomic_load_n(&e->count, __ATOMIC_RELAXED);
    while (cur < MAX_HALF_OPEN_PER_IP) {
        if (__atomic_compare_exchange_n(&e->count, &cur, cur + 1,
                                         true, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            return true;
        }
        // cur updated by CAS failure, retry
    }
    return false;  // Limit exceeded
}

static inline void half_open_decrement(uint32_t src_ip) {
    uint32_t idx = half_open_hash(src_ip);
    struct half_open_entry *e = &g_half_open_table[idx];
    if (__atomic_load_n(&e->src_ip, __ATOMIC_RELAXED) == src_ip) {
        uint32_t old = __atomic_fetch_sub(&e->count, 1, __ATOMIC_RELAXED);
        if (old <= 1) {
            // Last connection -- clear the slot
            __atomic_store_n(&e->count, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&e->src_ip, 0, __ATOMIC_RELAXED);
        }
    }
}

// ==================== Cached Offload Flags (Optimization) ====================
// Cached per-port offload capabilities - set once at init, avoid per-packet function calls
static bool g_port_ip_offload[RTE_MAX_ETHPORTS] = {false};
static bool g_port_tcp_offload[RTE_MAX_ETHPORTS] = {false};
static bool g_offload_cached = false;

// Per-lcore packet ID counter (replaces expensive rte_rand() calls)
static __thread uint16_t tls_pkt_id_counter = 0;

// Cached TSC divisors (avoid repeated rte_get_tsc_hz() calls in hot path)
static uint64_t g_tsc_ms_divisor = 0;    // g_tsc_hz / 1000 - for millisecond timestamps
static uint64_t g_tsc_32sec_divisor = 0; // g_tsc_hz * 32 - for cookie timestamp (32-sec granularity)

// Fast packet ID generation using TSC + counter (much faster than rte_rand)
static inline uint16_t fast_packet_id(void) {
    // Mix TSC low bits with counter for uniqueness without expensive RNG
    return (uint16_t)((rte_rdtsc() & 0xFF00) | (++tls_pkt_id_counter & 0xFF));
}

// Fast timestamp for TCP options (milliseconds) - uses cached divisor
static inline uint32_t fast_timestamp_ms(void) {
    uint64_t div = g_tsc_ms_divisor ? g_tsc_ms_divisor : (rte_get_tsc_hz() / 1000);
    return (uint32_t)(rte_rdtsc() / div);
}

/**
 * Ultra-fast MSS extraction for stateless mode
 * Only extracts MSS - skips all other options parsing
 * Returns default 1460 if MSS option not found at expected location
 *
 * Added max_len parameter to prevent buffer overflow.
 *
 * @param tcp      Pointer to TCP header
 * @param max_len  Maximum safe length to read from tcp pointer
 */
static inline uint16_t fast_extract_mss_safe(const struct rte_tcp_hdr *tcp, uint16_t max_len) {
    // Ensure we have at least minimum TCP header
    if (unlikely(max_len < 20)) {
        return 1460;  // Default MSS
    }

    // Use uint16_t to avoid truncation when comparing against max_len
    // TCP header length field is 4 bits, so max value is 15*4=60, but we need
    // safe comparison against max_len which can be up to 65535
    uint16_t tcp_hdr_len = (uint16_t)((tcp->data_off >> 4) * 4);

    // Cap header length to actual packet bounds
    // Now safe - both are uint16_t, no truncation possible
    if (tcp_hdr_len > max_len) {
        tcp_hdr_len = max_len;
    }

    if (tcp_hdr_len <= 20) {
        return 1460;  // No options, use default
    }

    const uint8_t *opt = (const uint8_t *)tcp + 20;
    const uint8_t *end = (const uint8_t *)tcp + tcp_hdr_len;

    // Fast path: MSS is typically first option after header
    // Format: NOP(1) or MSS directly at offset 20
    // MSS option: kind=2, len=4, value=2bytes
    // Validate bounds before each access
    // Use memcpy for potentially unaligned 16-bit reads
    if (opt + 4 <= end && *opt == 2 && opt[1] == 4) {
        // MSS at start (opt+2 is aligned)
        uint16_t mss_val;
        memcpy(&mss_val, opt + 2, sizeof(mss_val));
        return rte_be_to_cpu_16(mss_val);
    }
    if (opt + 5 <= end && *opt == 1 && opt[1] == 2 && opt[2] == 4) {
        // NOP + MSS (opt+3 is odd -- unaligned)
        uint16_t mss_val;
        memcpy(&mss_val, opt + 3, sizeof(mss_val));
        return rte_be_to_cpu_16(mss_val);
    }

    // Slow path: scan for MSS (rare - most SYNs have MSS first)
    while (opt < end) {
        if (*opt == 0) break;
        if (*opt == 1) { opt++; continue; }
        if (opt + 1 >= end) break;
        uint8_t len = opt[1];
        if (len < 2 || opt + len > end) break;
        if (*opt == 2 && len == 4 && opt + 4 <= end) {
            uint16_t mss_val;
            memcpy(&mss_val, opt + 2, sizeof(mss_val));
            return rte_be_to_cpu_16(mss_val);
        }
        opt += len;
    }
    return 1460;  // Default MSS
}

/**
 * Legacy wrapper - uses conservative 60-byte max for TCP header
 */
static inline uint16_t fast_extract_mss(const struct rte_tcp_hdr *tcp) {
    return fast_extract_mss_safe(tcp, 60);
}

/**
 * Ultra-fast cookie generation - inlined for stateless path
 * Combines timestamp, MSS index, and hash in single operation
 *
 * IMPORTANT: Must use identical hash algorithm as cookie_hash() for validation!
 */
static inline uint32_t fast_generate_cookie(uint32_t src_ip, uint32_t dst_ip,
                                            uint16_t src_port, uint16_t dst_port,
                                            uint16_t mss) {
    uint64_t div32 = g_tsc_32sec_divisor ? g_tsc_32sec_divisor : (rte_get_tsc_hz() * 32);
    uint8_t timestamp = (rte_rdtsc() / div32) & 0xF;

    // Fast MSS index (most common cases)
    uint8_t mss_idx = (mss >= 1450) ? 5 : ((mss <= 600) ? 0 : 4);

    // Load secret atomically (pairs with release store in rotate_secret)
    uint32_t secret = __atomic_load_n(&g_current_secret, __ATOMIC_ACQUIRE);

    // Hash calculation - MUST match cookie_hash() exactly for validation to work!
    // Uses SipHash-2-4 (cryptographic PRF) instead of CRC32C for collision resistance.
    uint32_t data[5];
    data[0] = src_ip;
    data[1] = dst_ip;
    data[2] = ((uint32_t)src_port << 16) | dst_port;
    data[3] = timestamp | (secret << 8);
    data[4] = 0xDEADBEEF ^ secret;

    uint32_t hash = (uint32_t)siphash_2_4(data, sizeof(data), g_siphash_key) & 0x00FFFFFF;

    return ((uint32_t)timestamp << 28) | ((uint32_t)mss_idx << 24) | hash;
}

// Forward declarations
static inline bool synack_rate_limit_check(void);
bool syn_proxy_should_challenge(const struct packet_features *features,
                                const struct per_ip_anomaly_snapshot *ip_anom);

// ==================== Connection Key ====================

/**
 * Connection lookup key (client's 4-tuple)
 */
struct conn_key {
    uint32_t client_ip;
    uint32_t server_ip;
    uint16_t client_port;
    uint16_t server_port;
} __attribute__((packed));

// ==================== Helper Functions ====================

/**
 * Get current timestamp for cookies (4-bit, 32-second granularity)
 * OPTIMIZED: Uses cached divisor instead of rte_get_tsc_hz() per call
 */
static inline uint8_t get_cookie_timestamp(void) {
    // g_tsc_32sec_divisor = g_tsc_hz * 32, so dividing gives us 32-second intervals
    uint64_t div = g_tsc_32sec_divisor ? g_tsc_32sec_divisor : (rte_get_tsc_hz() * 32);
    return (rte_rdtsc() / div) & 0xF;
}

/**
 * Find MSS index closest to given value
 * OPTIMIZED: Fast path for common MSS values (1460, 1380, 536)
 */
static inline uint8_t mss_to_index(uint16_t mss) {
    // Fast path for most common MSS values (avoid loop in 99%+ cases)
    // Index 5 = 1460 (standard Ethernet)
    if (mss >= 1450 && mss <= 1470) return 5;
    // Index 4 = 1440 (common with IP options)
    if (mss >= 1430 && mss <= 1449) return 4;
    // Index 0 = 536 (minimum MSS)
    if (mss <= 600) return 0;
    // Index 7 = 1500
    if (mss >= 1490) return 7;

    // Slow path for unusual MSS values
    uint8_t best = 0;
    int32_t best_diff = INT32_MAX;
    for (uint8_t i = 0; i < 16; i++) {
        int32_t diff = abs((int32_t)MSS_TABLE[i] - (int32_t)mss);
        if (diff < best_diff) {
            best_diff = diff;
            best = i;
        }
    }
    return best;
}

/**
 * Generate cookie hash (24-bit)
 */
static inline uint32_t cookie_hash(uint32_t src_ip, uint32_t dst_ip,
                                   uint16_t src_port, uint16_t dst_port,
                                   uint8_t timestamp, uint32_t secret) {
    uint32_t data[5];
    data[0] = src_ip;
    data[1] = dst_ip;
    data[2] = ((uint32_t)src_port << 16) | dst_port;
    data[3] = timestamp | (secret << 8);
    data[4] = 0xDEADBEEF ^ secret;
    
    return (uint32_t)siphash_2_4(data, sizeof(data), g_siphash_key) & 0x00FFFFFF;
}

/**
 * Generate SYN cookie value
 */
static uint32_t generate_cookie(uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint16_t mss) {
    uint8_t timestamp = get_cookie_timestamp();
    uint8_t mss_idx = mss_to_index(mss);
    // Atomic load of secret
    uint32_t secret = __atomic_load_n(&g_current_secret, __ATOMIC_ACQUIRE);
    uint32_t hash = cookie_hash(src_ip, dst_ip, src_port, dst_port,
                                timestamp, secret);
    
    // Cookie format: [timestamp:4][mss_idx:4][hash:24]
    return ((uint32_t)timestamp << 28) |
           ((uint32_t)mss_idx << 24) |
           hash;
}

/**
 * Validate SYN cookie and extract MSS
 */
static bool validate_cookie(uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint32_t ack_seq, uint16_t *mss_out) {
    // Constant-time validation: ALL paths must execute the hash computation
    // to prevent timing side-channel (~50us delta measurable via SYN-ACK RTT).
    // Early-exit conditions are tracked as flags, applied AFTER hash check.

    // ACK sequence = cookie + 1; ack_seq==0 means cookie 0xFFFFFFFF (invalid)
    uint32_t cookie = ack_seq - 1;
    bool ack_zero = (ack_seq == 0);

    uint8_t cookie_ts = (cookie >> 28) & 0xF;
    uint8_t cookie_mss_idx = (cookie >> 24) & 0xF;
    uint32_t cookie_hash_val = cookie & 0x00FFFFFF;

    // Check timestamp (allow 2 intervals = 64 seconds)
    uint8_t current_ts = get_cookie_timestamp();
    uint8_t ts_diff = (current_ts - cookie_ts) & 0xF;
    bool ts_expired = (ts_diff > 2);

    // Atomic load of secrets (pairs with release store in rotate_secret)
    uint32_t cur_secret = __atomic_load_n(&g_current_secret, __ATOMIC_ACQUIRE);
    uint32_t prev_secret = __atomic_load_n(&g_previous_secret, __ATOMIC_ACQUIRE);

    // Always compute BOTH hashes regardless of ack_zero/ts_expired
    uint32_t expected_cur = cookie_hash(src_ip, dst_ip, src_port, dst_port,
                                        cookie_ts, cur_secret);
    uint32_t expected_prev = cookie_hash(src_ip, dst_ip, src_port, dst_port,
                                         cookie_ts, prev_secret);

    // Constant-time comparison: XOR produces 0 on match
    uint32_t match_cur = cookie_hash_val ^ expected_cur;
    uint32_t match_prev = cookie_hash_val ^ expected_prev;
    // valid if either secret matched AND no pre-conditions failed
    bool hash_valid = (match_cur == 0) | (match_prev == 0);
    bool valid = hash_valid & (!ack_zero) & (!ts_expired);

    if (valid) {
        if (mss_out) *mss_out = MSS_TABLE[cookie_mss_idx];
        return true;
    }

    // Update stats for the specific failure reason (after constant-time path)
    if (ack_zero) {
        __atomic_add_fetch(&g_stats.cookies_invalid, 1, __ATOMIC_RELAXED);
    } else if (ts_expired) {
        __atomic_add_fetch(&g_stats.cookies_expired, 1, __ATOMIC_RELAXED);
    }

    // Debug: Log first few failed validations
    // Track logged count separately for monitoring visibility
    static uint64_t invalid_log_count = 0;
    uint64_t log_num = __atomic_add_fetch(&invalid_log_count, 1, __ATOMIC_RELAXED);
    if (log_num <= 10) {
        __atomic_add_fetch(&g_stats.cookies_invalid_logged, 1, __ATOMIC_RELAXED);
        uint32_t expected_cur = cookie_hash(src_ip, dst_ip, src_port, dst_port,
                                            cookie_ts, cur_secret);
        RTE_LOG(WARNING, SYNPROXY, "Cookie INVALID: "
                "src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u "
                "ack=0x%x cookie=0x%x ts=%u hash=0x%x expected=0x%x\n",
                (rte_be_to_cpu_32(src_ip) >> 24) & 0xFF,
                (rte_be_to_cpu_32(src_ip) >> 16) & 0xFF,
                (rte_be_to_cpu_32(src_ip) >> 8) & 0xFF,
                rte_be_to_cpu_32(src_ip) & 0xFF,
                src_port,
                (rte_be_to_cpu_32(dst_ip) >> 24) & 0xFF,
                (rte_be_to_cpu_32(dst_ip) >> 16) & 0xFF,
                (rte_be_to_cpu_32(dst_ip) >> 8) & 0xFF,
                rte_be_to_cpu_32(dst_ip) & 0xFF,
                dst_port,
                ack_seq, cookie, cookie_ts, cookie_hash_val, expected_cur);
    } else if (log_num == 11) {
        // Log once that subsequent errors are suppressed
        RTE_LOG(WARNING, SYNPROXY, "Cookie validation errors suppressed (>10). "
                "Monitor stats.cookies_invalid vs stats.cookies_invalid_logged for count.\n");
    }

    __atomic_add_fetch(&g_stats.cookies_invalid, 1, __ATOMIC_RELAXED);
    return false;
}

// ==================== Quick Cookie Check (for Stage 8b) ====================

/**
 * Quick cookie validation for Stage 8b (spoofed TCP flood detection).
 *
 * During spoofed attacks, Stage 8b drops orphan ACKs (no flow entry).
 * But SYN cookie completion ACKs also have no flow yet -- flows are
 * created at Stage 9 after full cookie validation. This function lets
 * Stage 8b distinguish valid cookie ACKs from spoofed orphan ACKs,
 * so legitimate handshake completions pass through to Stage 9.
 *
 * Returns true if the ACK carries a valid SYN cookie.
 */
bool syn_proxy_quick_cookie_check(uint32_t src_ip, uint32_t dst_ip,
                                   uint16_t src_port, uint16_t dst_port,
                                   uint32_t tcp_ack) {
    if (!g_config.enabled)
        return false;
    return validate_cookie(src_ip, dst_ip, src_port, dst_port, tcp_ack, NULL);
}

// ==================== Adaptive Mode Logic ====================

/**
 * Update SYN rate tracking and check for mode switch
 * Called for each SYN packet processed
 * Returns current mode (stateful or stateless)
 */
static inline enum syn_proxy_mode adaptive_mode_update(void) {
    // Use atomic increment for multi-lcore safety
    uint64_t count = __atomic_add_fetch(&g_adaptive_syn_count, 1, __ATOMIC_RELAXED);

    // If mode is forced, return immediately (no TSC needed)
    int forced = __atomic_load_n(&g_forced_mode, __ATOMIC_RELAXED);
    if (unlikely(forced >= 0)) {
        return (enum syn_proxy_mode)forced;
    }

    // Load current mode atomically
    enum syn_proxy_mode current_mode = __atomic_load_n(&g_current_mode, __ATOMIC_ACQUIRE);

    // Fast path: in stateless mode, use counter-based check instead of TSC
    // Check every 4096 packets (cheap modulo with power of 2)
    if (likely(current_mode == SYN_PROXY_MODE_STATELESS)) {
        if (likely((count & 0xFFF) != 0)) {
            return SYN_PROXY_MODE_STATELESS;  // Fast return, no TSC read
        }
    }

    uint64_t now_tsc = rte_rdtsc();

    // Atomically load window start for comparison
    uint64_t window_start = __atomic_load_n(&g_adaptive_window_start_tsc, __ATOMIC_ACQUIRE);
    uint64_t elapsed_tsc = now_tsc - window_start;
    uint64_t hz = g_tsc_hz ? g_tsc_hz : rte_get_tsc_hz();

    // Window expired (1 second)? Use CAS to ensure only one lcore rotates
    if (elapsed_tsc >= hz) {
        // CAS-based window rotation - only one lcore wins
        if (__atomic_compare_exchange_n(&g_adaptive_window_start_tsc,
                                         &window_start, now_tsc,
                                         false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            // This lcore won the CAS - perform window rotation and mode decision
            uint64_t syn_count = __atomic_exchange_n(&g_adaptive_syn_count, 0, __ATOMIC_RELAXED);

            // Calculate PPS for the window
            __atomic_store_n(&g_current_syn_rate_pps, (uint32_t)syn_count, __ATOMIC_RELAXED);

            // Check if we should switch modes (with dual hysteresis: time + consecutive windows)
            uint64_t since_last_switch = now_tsc - __atomic_load_n(&g_last_mode_switch_tsc, __ATOMIC_RELAXED);

            // Get thresholds from config or use defaults
            uint32_t stateless_thresh = g_config.stateless_threshold_pps ?
                                        g_config.stateless_threshold_pps :
                                        DEFAULT_STATELESS_THRESHOLD_PPS;
            uint32_t stateful_thresh = g_config.stateful_threshold_pps ?
                                       g_config.stateful_threshold_pps :
                                       DEFAULT_STATEFUL_THRESHOLD_PPS;

            // Track consecutive windows above/below thresholds
            // These are only modified by the CAS winner, so plain access is safe
            if ((uint32_t)syn_count > stateless_thresh) {
                g_consecutive_above_threshold++;
                g_consecutive_below_threshold = 0;
            } else if ((uint32_t)syn_count < stateful_thresh) {
                g_consecutive_below_threshold++;
                g_consecutive_above_threshold = 0;
            } else {
                if (g_consecutive_above_threshold > 0) g_consecutive_above_threshold--;
                if (g_consecutive_below_threshold > 0) g_consecutive_below_threshold--;
            }

            // Only switch if both time AND consecutive window requirements are met
            if (since_last_switch >= g_mode_switch_delay_tsc) {
                enum syn_proxy_mode new_mode = current_mode;

                if (current_mode == SYN_PROXY_MODE_STATEFUL &&
                    g_consecutive_above_threshold >= DEFAULT_CONSECUTIVE_WINDOWS) {
                    new_mode = SYN_PROXY_MODE_STATELESS;
                } else if (current_mode == SYN_PROXY_MODE_STATELESS &&
                           g_consecutive_below_threshold >= DEFAULT_CONSECUTIVE_WINDOWS) {
                    new_mode = SYN_PROXY_MODE_STATEFUL;
                }

                if (new_mode != current_mode) {
                    // Atomic store for mode change visible to all lcores
                    __atomic_store_n(&g_current_mode, new_mode, __ATOMIC_RELEASE);
                    __atomic_store_n(&g_last_mode_switch_tsc, now_tsc, __ATOMIC_RELAXED);
                    g_consecutive_above_threshold = 0;
                    g_consecutive_below_threshold = 0;
                    __atomic_add_fetch(&g_stats.mode_switches, 1, __ATOMIC_RELAXED);

                    RTE_LOG(NOTICE, SYNPROXY, "Mode switch: %s -> %s (SYN rate: %u PPS, required %u consecutive windows)\n",
                            (new_mode == SYN_PROXY_MODE_STATELESS) ? "STATEFUL" : "STATELESS",
                            (new_mode == SYN_PROXY_MODE_STATELESS) ? "STATELESS" : "STATEFUL",
                            (uint32_t)syn_count, DEFAULT_CONSECUTIVE_WINDOWS);
                    current_mode = new_mode;
                }
            }
        }
        // If CAS failed, another lcore already rotated - just return current mode
    }

    return current_mode;
}

/**
 * Get current operating mode
 */
enum syn_proxy_mode syn_proxy_get_mode(void) {
    // Use ACQUIRE to see latest mode from adaptive_mode_update RELEASE stores
    return __atomic_load_n(&g_current_mode, __ATOMIC_ACQUIRE);
}

/**
 * Force a specific mode or return to adaptive
 * mode: 0 = stateful, 1 = stateless, -1 = adaptive (auto)
 */
void syn_proxy_set_mode(int mode) {
    if (mode < 0) {
        __atomic_store_n(&g_forced_mode, -1, __ATOMIC_RELEASE);
        RTE_LOG(NOTICE, SYNPROXY, "Returning to adaptive mode\n");
    } else {
        __atomic_store_n(&g_forced_mode, mode, __ATOMIC_RELEASE);
        __atomic_store_n(&g_current_mode, (enum syn_proxy_mode)mode, __ATOMIC_RELEASE);
        RTE_LOG(NOTICE, SYNPROXY, "Forced mode: %s\n",
                (mode == SYN_PROXY_MODE_STATELESS) ? "STATELESS" : "STATEFUL");
    }
}

/**
 * Parse TCP options from SYN packet
 *
 * Added max_len parameter to prevent buffer overflow.
 * Validates that tcp_hdr_len from data_off doesn't exceed actual packet size.
 *
 * @param tcp      Pointer to TCP header
 * @param opts     Output structure for parsed options
 * @param max_len  Maximum safe length to read from tcp pointer (packet bounds)
 */
static void parse_tcp_options_safe(const struct rte_tcp_hdr *tcp,
                                    struct tcp_syn_options *opts,
                                    uint16_t max_len) {
    memset(opts, 0, sizeof(*opts));
    opts->mss = 536;  // Default MSS
    opts->wscale = 255;  // Not present

    // Minimum packet must contain at least 20-byte TCP header
    if (unlikely(max_len < 20)) {
        return;
    }

    uint8_t tcp_hdr_len = (tcp->data_off >> 4) * 4;

    // Validate header length against actual packet bounds
    // data_off can indicate up to 60 bytes (15*4), but packet might be smaller
    if (tcp_hdr_len > max_len) {
        tcp_hdr_len = max_len;  // Cap to actual packet size
    }

    if (tcp_hdr_len <= 20) {
        return;  // No options
    }

    const uint8_t *opt = (const uint8_t *)tcp + 20;
    const uint8_t *end = (const uint8_t *)tcp + tcp_hdr_len;

    while (opt < end) {
        uint8_t kind = *opt;

        if (kind == 0) break;  // End of options
        if (kind == 1) {       // NOP
            opt++;
            continue;
        }

        if (opt + 1 >= end) break;
        uint8_t len = opt[1];
        if (len < 2 || opt + len > end) break;

        switch (kind) {
            case 2:  // MSS
                if (len == 4 && opt + 4 <= end) {
                    // Safe unaligned read
                    uint16_t mss_val;
                    memcpy(&mss_val, opt + 2, sizeof(mss_val));
                    opts->mss = rte_be_to_cpu_16(mss_val);
                }
                break;
            case 3:  // Window Scale (RFC 7323: valid range 0-14)
                if (len == 3 && opt + 3 <= end) {
                    opts->wscale = (opt[2] <= 14) ? opt[2] : 14;
                }
                break;
            case 4:  // SACK Permitted
                opts->sack_permitted = true;
                break;
            case 8:  // Timestamp
                if (len == 10 && opt + 10 <= end) {
                    opts->timestamp_present = true;
                    // Safe unaligned reads
                    uint32_t ts_val, ts_ecr;
                    memcpy(&ts_val, opt + 2, sizeof(ts_val));
                    memcpy(&ts_ecr, opt + 6, sizeof(ts_ecr));
                    opts->tsval = rte_be_to_cpu_32(ts_val);
                    opts->tsecr = rte_be_to_cpu_32(ts_ecr);
                }
                break;
        }
        opt += len;
    }
}

/**
 * Legacy wrapper - uses IP total length to determine safe bounds
 * Note: Caller should use parse_tcp_options_safe when packet length is known
 */
static void parse_tcp_options(const struct rte_tcp_hdr *tcp,
                              struct tcp_syn_options *opts) {
    // Conservative default: assume minimum SYN packet with options (60 bytes max TCP)
    // This is safe for most cases but callers should prefer parse_tcp_options_safe
    parse_tcp_options_safe(tcp, opts, 60);
}

/**
 * Calculate TCP checksum (software fallback) - OPTIMIZED
 * Uses single-iteration fold instead of loop
 */
static inline uint16_t calc_tcp_checksum(const struct rte_ipv4_hdr *ip,
                                         const struct rte_tcp_hdr *tcp,
                                         uint16_t tcp_len) {
    uint32_t sum = 0;

    // Pseudo header - unrolled for better pipelining
    sum += (ip->src_addr >> 16) & 0xFFFF;
    sum += ip->src_addr & 0xFFFF;
    sum += (ip->dst_addr >> 16) & 0xFFFF;
    sum += ip->dst_addr & 0xFFFF;
    sum += rte_cpu_to_be_16(IPPROTO_TCP);
    sum += rte_cpu_to_be_16(tcp_len);

    // TCP header + data - use DPDK's optimized raw checksum if available
    sum += rte_raw_cksum(tcp, tcp_len);

    // Single-iteration fold (handles up to 64KB packets)
    // Two iterations guaranteed to reduce any 32-bit sum to 16-bit
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

/**
 * Cache offload capabilities for all ports (call once at init)
 */
static void cache_offload_capabilities(void) {
    if (g_offload_cached) return;

    for (uint16_t port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        g_port_ip_offload[port_id] = is_tx_ip_cksum_offload_enabled(port_id);
        g_port_tcp_offload[port_id] = is_tx_tcp_cksum_offload_enabled(port_id);
    }
    g_offload_cached = true;
}

/**
 * Prepare mbuf for TX checksum offload (if supported) - OPTIMIZED
 * Uses cached offload flags instead of per-packet function calls
 * Sets up l2_len, l3_len, ol_flags for hardware checksum calculation
 *
 * Always compute software checksum as fallback, then configure offload.
 * This ensures valid checksums even if hardware offload is expected but fails.
 * The NIC will overwrite our software checksum if offload succeeds.
 *
 * @param m         Packet mbuf
 * @param ip        IPv4 header pointer
 * @param tcp       TCP header pointer (NULL for non-TCP)
 * @param tcp_len   TCP header + data length (required for software checksum)
 * @param port_id   Output port (to check offload capability)
 * @return true if TCP offload was configured (caller may skip software checksum),
 *         false if software TCP checksum is required
 */
static inline bool prepare_tx_checksum_offload_safe(struct rte_mbuf *m,
                                                     struct rte_ipv4_hdr *ip,
                                                     struct rte_tcp_hdr *tcp,
                                                     uint16_t tcp_len,
                                                     uint16_t port_id) {
    // Bounds check port_id before array access
    if (unlikely(port_id >= RTE_MAX_ETHPORTS))
        return false;

    // Use cached values - avoid function call overhead per packet
    const bool ip_offload = g_port_ip_offload[port_id];
    const bool tcp_offload = g_port_tcp_offload[port_id];

    // Always compute software checksums first as defensive fallback
    // If hardware offload works, it will overwrite these values
    // If hardware offload fails silently, packets will still have valid checksums
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    if (tcp != NULL && tcp_len > 0) {
        tcp->cksum = 0;
        tcp->cksum = calc_tcp_checksum(ip, tcp, tcp_len);
    }

    // Now configure hardware offload if available
    // NIC will overwrite checksums on successful offload
    if (ip_offload || tcp_offload) {
        // Set header lengths for offload engine
        m->l2_len = sizeof(struct rte_ether_hdr);
        m->l3_len = sizeof(struct rte_ipv4_hdr);

        if (ip_offload) {
            m->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
            ip->hdr_checksum = 0;  // NIC will compute (overwriting our software checksum)
        }

        if (tcp_offload && tcp != NULL) {
            m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
            // Set pseudo-header checksum for TCP offload
            // NIC adds this to payload checksum to get final value
            tcp->cksum = rte_ipv4_phdr_cksum(ip, m->ol_flags);
        }
    }

    return tcp_offload;  // Return whether TCP was offloaded
}

/**
 * Legacy wrapper for backwards compatibility - delegates to safe version
 */
static inline bool prepare_tx_checksum_offload(struct rte_mbuf *m,
                                               struct rte_ipv4_hdr *ip,
                                               struct rte_tcp_hdr *tcp,
                                               uint16_t port_id) {
    // Calculate TCP length from IP total length
    uint16_t tcp_len = 0;
    if (tcp != NULL) {
        uint16_t ip_total_len = rte_be_to_cpu_16(ip->total_length);
        uint16_t ip_hdr_len = (ip->version_ihl & 0x0F) * 4;
        tcp_len = ip_total_len - ip_hdr_len;
    }
    return prepare_tx_checksum_offload_safe(m, ip, tcp, tcp_len, port_id);
}

/**
 * Create connection key
 */
static inline void make_conn_key(struct conn_key *key,
                                 uint32_t client_ip, uint32_t server_ip,
                                 uint16_t client_port, uint16_t server_port) {
    key->client_ip = client_ip;
    key->server_ip = server_ip;
    key->client_port = client_port;
    key->server_port = server_port;
}

/**
 * Compute hash for connection key (can be reused for lookup and add)
 */
static inline hash_sig_t compute_conn_hash(const struct conn_key *key) {
    return rte_jhash(key, sizeof(struct conn_key), 0);
}

/**
 * Find connection entry with precomputed hash - OPTIMIZED
 * Includes prefetch for the connection pool entry
 */
static inline struct syn_proxy_conn *find_connection_with_hash(
    const struct conn_key *key, hash_sig_t hash) {
    int32_t idx = rte_hash_lookup_with_hash(g_conn_hash, key, hash);
    if (idx >= 0) {
        struct syn_proxy_conn *conn = &g_conn_pool[idx];
        rte_prefetch0(conn);  // Prefetch connection data
        return conn;
    }
    return NULL;
}

/**
 * Find connection entry (backward compatible wrapper)
 */
static struct syn_proxy_conn *find_connection(const struct conn_key *key) {
    hash_sig_t hash = compute_conn_hash(key);
    return find_connection_with_hash(key, hash);
}

/**
 * Allocate new connection entry with precomputed hash - OPTIMIZED
 */
static inline struct syn_proxy_conn *alloc_connection_with_hash(
    const struct conn_key *key, hash_sig_t hash) {
    int32_t idx = rte_hash_add_key_with_hash(g_conn_hash, key, hash);
    if (idx < 0) {
        __atomic_add_fetch(&g_stats.table_full_drops, 1, __ATOMIC_RELAXED);
        return NULL;
    }

    struct syn_proxy_conn *conn = &g_conn_pool[idx];

    // Initialize connection - faster than memset for known structure
    conn->client_ip = key->client_ip;
    conn->server_ip = key->server_ip;
    conn->client_port = key->client_port;
    conn->server_port = key->server_port;
    conn->state = SYN_PROXY_NONE;

    uint64_t now = rte_get_tsc_cycles();
    conn->created_tsc = now;
    conn->state_change_tsc = now;
    conn->last_client_tsc = now;
    conn->last_server_tsc = 0;
    conn->client_isn = 0;
    conn->server_isn = 0;
    conn->proxy_isn = 0;
    conn->seq_delta_c2s = 0;
    conn->seq_delta_s2c = 0;
    conn->packets_c2s = 0;
    conn->packets_s2c = 0;
    conn->bytes_c2s = 0;
    conn->bytes_s2c = 0;

    __atomic_add_fetch(&g_stats.connections_created, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_stats.connections_active, 1, __ATOMIC_RELAXED);

    return conn;
}

/**
 * Allocate new connection entry (backward compatible wrapper)
 */
static struct syn_proxy_conn *alloc_connection(const struct conn_key *key) {
    hash_sig_t hash = compute_conn_hash(key);
    return alloc_connection_with_hash(key, hash);
}

/**
 * Free connection entry
 */
static void free_connection(struct syn_proxy_conn *conn) {
    struct conn_key key;
    make_conn_key(&key, conn->client_ip, conn->server_ip,
                  conn->client_port, conn->server_port);

    // Release half-open slot if connection was still in CONNECTING state
    if (conn->state == SYN_PROXY_CONNECTING) {
        half_open_decrement(conn->client_ip);
    }

    rte_hash_del_key(g_conn_hash, &key);
    conn->state = SYN_PROXY_NONE;

    __atomic_add_fetch(&g_stats.connections_closed, 1, __ATOMIC_RELAXED);
    __atomic_sub_fetch(&g_stats.connections_active, 1, __ATOMIC_RELAXED);
}

// ==================== Packet Generation ====================

/**
 * Build TCP options for SYN-ACK
 */
__attribute__((unused))
static uint16_t build_synack_options(uint8_t *opts, uint16_t mss,
                                     bool sack_permitted,
                                     const struct tcp_syn_options *client_opts) {
    uint8_t *p = opts;
    
    // MSS option (required)
    *p++ = 2;   // Kind
    *p++ = 4;   // Length
    *(uint16_t *)p = rte_cpu_to_be_16(mss);
    p += 2;
    
    // SACK Permitted (if client requested)
    if (sack_permitted) {
        *p++ = 4;   // Kind
        *p++ = 2;   // Length
    }
    
    // Timestamp (if client sent)
    if (client_opts && client_opts->timestamp_present) {
        *p++ = 8;   // Kind
        *p++ = 10;  // Length
        *(uint32_t *)p = rte_cpu_to_be_32(fast_timestamp_ms());
        p += 4;
        *(uint32_t *)p = rte_cpu_to_be_32(client_opts->tsval);
        p += 4;
    }
    
    // Window Scale (if client sent)
    if (client_opts && client_opts->wscale != 255) {
        *p++ = 1;   // NOP for alignment
        *p++ = 3;   // Kind
        *p++ = 3;   // Length
        *p++ = 7;   // Scale factor (128x)
    }
    
    // Pad to 4-byte boundary
    while ((p - opts) % 4 != 0) {
        *p++ = 0;  // End of options
    }
    
    return p - opts;
}

/**
 * Transform SYN packet into SYN-ACK IN-PLACE (zero-copy)
 * This eliminates mbuf allocation overhead - the key bottleneck!
 *
 * Returns true on success (mbuf is now a SYN-ACK ready to send)
 * Returns false if packet too small (caller should use create_synack_to_client)
 */
static inline bool transform_syn_to_synack_inplace(
    struct rte_mbuf *m,
    uint32_t cookie,
    uint16_t port_id) {

    // Get pointers to headers in existing packet
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + ((ip->version_ihl & 0x0F) * 4));

    // Swap Ethernet addresses
    struct rte_ether_addr tmp_mac;
    rte_ether_addr_copy(&eth->src_addr, &tmp_mac);
    rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
    rte_ether_addr_copy(&tmp_mac, &eth->dst_addr);

    // Swap IP addresses
    uint32_t tmp_ip = ip->src_addr;
    ip->src_addr = ip->dst_addr;
    ip->dst_addr = tmp_ip;
    ip->packet_id = rte_cpu_to_be_16(fast_packet_id());
    ip->time_to_live = 64;
    ip->hdr_checksum = 0;

    // Swap TCP ports
    uint16_t tmp_port = tcp->src_port;
    tcp->src_port = tcp->dst_port;
    tcp->dst_port = tmp_port;

    // Set SYN-ACK specific fields
    uint32_t client_seq = rte_be_to_cpu_32(tcp->sent_seq);
    tcp->recv_ack = rte_cpu_to_be_32(client_seq + 1);
    tcp->sent_seq = rte_cpu_to_be_32(cookie);
    tcp->tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    tcp->rx_win = rte_cpu_to_be_16(65535);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    // Simple SYN-ACK with just MSS option (20 bytes TCP header + 4 bytes MSS = 24 bytes)
    // This is faster than echoing all client options
    uint16_t tcp_hdr_len = 24;  // Fixed: 20 + 4 (MSS only)
    tcp->data_off = (tcp_hdr_len / 4) << 4;

    // Build minimal TCP options (MSS only for speed)
    uint8_t *opt_ptr = (uint8_t *)tcp + 20;
    *opt_ptr++ = 2;   // MSS Kind
    *opt_ptr++ = 4;   // MSS Length
    *(uint16_t *)opt_ptr = rte_cpu_to_be_16(1460);  // MSS Value
    opt_ptr += 2;

    // Update IP total length
    uint16_t ip_hdr_len = (ip->version_ihl & 0x0F) * 4;
    uint16_t ip_total_len = ip_hdr_len + tcp_hdr_len;
    ip->total_length = rte_cpu_to_be_16(ip_total_len);

    // Update mbuf length
    uint16_t frame_len = sizeof(struct rte_ether_hdr) + ip_total_len;
    m->data_len = frame_len;
    m->pkt_len = frame_len;

    // Clear offload flags from RX and set TX flags
    m->ol_flags = 0;

    // Compute checksums
    // prepare_tx_checksum_offload_safe already computes software checksums.
    // No fallback needed -- it either computed software or configured hardware offload.
    prepare_tx_checksum_offload(m, ip, tcp, port_id);

    return true;
}

/**
 * Create SYN-ACK packet to send to client - ALLOCATES NEW MBUF
 * Used as fallback when in-place transformation isn't possible
 */
static struct rte_mbuf *create_synack_to_client(
    struct rte_mempool *mempool,
    const struct packet_features *orig_features,
    const struct rte_ether_hdr *orig_eth,
    uint32_t cookie,
    const struct tcp_syn_options *client_opts,
    uint16_t port_id) {

    struct rte_mbuf *m = rte_pktmbuf_alloc(mempool);
    if (unlikely(!m)) {
        return NULL;
    }

    // Calculate TCP options length - build directly into packet later
    uint16_t opts_len = 4;  // MSS always present (4 bytes)
    if (client_opts->sack_permitted) opts_len += 2;
    if (client_opts->timestamp_present) opts_len += 10;
    if (client_opts->wscale != 255) opts_len += 4;  // NOP + wscale (1+3)
    // Pad to 4-byte boundary
    opts_len = (opts_len + 3) & ~3;

    uint16_t tcp_hdr_len = 20 + opts_len;
    uint16_t ip_total_len = 20 + tcp_hdr_len;
    uint16_t frame_len = 14 + ip_total_len;

    // Direct data_len manipulation instead of rte_pktmbuf_append
    // (faster: avoid function call + NULL check inside append)
    char *pkt = rte_pktmbuf_mtod(m, char *);
    m->data_len = frame_len;
    m->pkt_len = frame_len;

    // Ethernet header (swap src/dst from original)
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt;
    rte_ether_addr_copy(&orig_eth->src_addr, &eth->dst_addr);
    rte_ether_addr_copy(&orig_eth->dst_addr, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // IP header - NO memset, set all fields explicitly
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(ip_total_len);
    ip->packet_id = rte_cpu_to_be_16(fast_packet_id());  // Fast ID generation
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->hdr_checksum = 0;  // Will be computed later
    ip->src_addr = orig_features->dst_ip;  // Swap
    ip->dst_addr = orig_features->src_ip;

    // TCP header - NO memset, set all fields explicitly
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(orig_features->dst_port);  // Swap
    tcp->dst_port = rte_cpu_to_be_16(orig_features->src_port);
    tcp->sent_seq = rte_cpu_to_be_32(cookie);
    tcp->recv_ack = rte_cpu_to_be_32(orig_features->tcp_seq + 1);
    tcp->data_off = (tcp_hdr_len / 4) << 4;
    tcp->tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    tcp->rx_win = rte_cpu_to_be_16(65535);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    // Build TCP options directly in packet (avoid temp buffer + memcpy)
    uint8_t *opt_ptr = (uint8_t *)tcp + 20;
    // MSS option
    *opt_ptr++ = 2;  // Kind
    *opt_ptr++ = 4;  // Length
    *(uint16_t *)opt_ptr = rte_cpu_to_be_16(1460);
    opt_ptr += 2;
    // SACK Permitted
    if (client_opts->sack_permitted) {
        *opt_ptr++ = 4;  // Kind
        *opt_ptr++ = 2;  // Length
    }
    // Timestamp
    if (client_opts->timestamp_present) {
        *opt_ptr++ = 8;  // Kind
        *opt_ptr++ = 10; // Length
        *(uint32_t *)opt_ptr = rte_cpu_to_be_32(fast_timestamp_ms());
        opt_ptr += 4;
        *(uint32_t *)opt_ptr = rte_cpu_to_be_32(client_opts->tsval);
        opt_ptr += 4;
    }
    // Window Scale
    if (client_opts->wscale != 255) {
        *opt_ptr++ = 1;  // NOP
        *opt_ptr++ = 3;  // Kind
        *opt_ptr++ = 3;  // Length
        *opt_ptr++ = 7;  // Scale factor
    }
    // Pad remaining with EOL
    while (opt_ptr < (uint8_t *)tcp + tcp_hdr_len) {
        *opt_ptr++ = 0;
    }

    // Try TX checksum offload, fall back to software if not available
    // prepare_tx_checksum_offload_safe already computes software checksums.
    // No fallback needed -- it either computed software or configured hardware offload.
    prepare_tx_checksum_offload(m, ip, tcp, port_id);

    return m;
}

/**
 * Create SYN packet to send to server - OPTIMIZED
 * Removed memset, replaced rte_rand, direct data_len, inline options
 */
static struct rte_mbuf *create_syn_to_server(
    struct rte_mempool *mempool,
    struct syn_proxy_conn *conn,
    const struct rte_ether_hdr *orig_eth,
    uint16_t port_id) {

    struct rte_mbuf *m = rte_pktmbuf_alloc(mempool);
    if (unlikely(!m)) {
        return NULL;
    }

    // Calculate options length inline
    uint16_t opts_len = 4;  // MSS always present
    if (conn->client_opts.sack_permitted) opts_len += 2;
    if (conn->client_opts.timestamp_present) opts_len += 10;
    if (conn->client_opts.wscale != 255) opts_len += 4;
    opts_len = (opts_len + 3) & ~3;  // Pad to 4-byte boundary

    uint16_t tcp_hdr_len = 20 + opts_len;
    uint16_t ip_total_len = 20 + tcp_hdr_len;
    uint16_t frame_len = 14 + ip_total_len;

    // Direct data_len manipulation
    char *pkt = rte_pktmbuf_mtod(m, char *);
    m->data_len = frame_len;
    m->pkt_len = frame_len;

    // Ethernet header - preserve original client MACs for transparent bridging
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt;
    rte_ether_addr_copy(&orig_eth->src_addr, &eth->src_addr);
    rte_ether_addr_copy(&orig_eth->dst_addr, &eth->dst_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // IP header - NO memset
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(ip_total_len);
    ip->packet_id = rte_cpu_to_be_16(fast_packet_id());
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->hdr_checksum = 0;
    ip->src_addr = conn->client_ip;
    ip->dst_addr = conn->server_ip;

    // TCP header - NO memset
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(conn->client_port);
    tcp->dst_port = rte_cpu_to_be_16(conn->server_port);
    tcp->sent_seq = rte_cpu_to_be_32(conn->proxy_isn);
    tcp->recv_ack = 0;
    tcp->data_off = (tcp_hdr_len / 4) << 4;
    tcp->tcp_flags = TCP_FLAG_SYN;
    tcp->rx_win = rte_cpu_to_be_16(65535);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    // Build options directly in packet
    uint8_t *opt_ptr = (uint8_t *)tcp + 20;
    // MSS
    *opt_ptr++ = 2;
    *opt_ptr++ = 4;
    *(uint16_t *)opt_ptr = rte_cpu_to_be_16(conn->client_opts.mss);
    opt_ptr += 2;
    // SACK
    if (conn->client_opts.sack_permitted) {
        *opt_ptr++ = 4;
        *opt_ptr++ = 2;
    }
    // Timestamp
    if (conn->client_opts.timestamp_present) {
        *opt_ptr++ = 8;
        *opt_ptr++ = 10;
        *(uint32_t *)opt_ptr = rte_cpu_to_be_32(fast_timestamp_ms());
        opt_ptr += 4;
        *(uint32_t *)opt_ptr = rte_cpu_to_be_32(conn->client_opts.tsval);
        opt_ptr += 4;
    }
    // Window Scale
    if (conn->client_opts.wscale != 255) {
        *opt_ptr++ = 1;  // NOP
        *opt_ptr++ = 3;
        *opt_ptr++ = 3;
        *opt_ptr++ = conn->client_opts.wscale;
    }
    // Pad
    while (opt_ptr < (uint8_t *)tcp + tcp_hdr_len) {
        *opt_ptr++ = 0;
    }

    // Checksum
    // prepare_tx_checksum_offload_safe already computes software checksums.
    // No fallback needed -- it either computed software or configured hardware offload.
    prepare_tx_checksum_offload(m, ip, tcp, port_id);

    return m;
}

/**
 * Create ACK packet to send to server (completes handshake) - OPTIMIZED
 * No memset, fast packet ID, direct data_len
 */
static struct rte_mbuf *create_ack_to_server(
    struct rte_mempool *mempool,
    struct syn_proxy_conn *conn,
    const struct rte_ether_hdr *orig_eth,
    uint16_t port_id) {

    struct rte_mbuf *m = rte_pktmbuf_alloc(mempool);
    if (unlikely(!m)) {
        return NULL;
    }

    // ACK packet has no options - fixed size
    const uint16_t tcp_hdr_len = 20;
    const uint16_t ip_total_len = 40;  // 20 IP + 20 TCP
    const uint16_t frame_len = 54;      // 14 ETH + 40 IP+TCP

    // Direct data_len manipulation
    char *pkt = rte_pktmbuf_mtod(m, char *);
    m->data_len = frame_len;
    m->pkt_len = frame_len;

    // Ethernet header - SWAP src/dst from incoming server SYN-ACK
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt;
    rte_ether_addr_copy(&orig_eth->dst_addr, &eth->src_addr);  // client MAC
    rte_ether_addr_copy(&orig_eth->src_addr, &eth->dst_addr);  // server MAC
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // IP header - NO memset
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(ip_total_len);
    ip->packet_id = rte_cpu_to_be_16(fast_packet_id());
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->hdr_checksum = 0;
    ip->src_addr = conn->client_ip;
    ip->dst_addr = conn->server_ip;

    // TCP header - NO memset
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(conn->client_port);
    tcp->dst_port = rte_cpu_to_be_16(conn->server_port);
    tcp->sent_seq = rte_cpu_to_be_32(conn->proxy_isn + 1);
    tcp->recv_ack = rte_cpu_to_be_32(conn->server_isn + 1);
    tcp->data_off = (tcp_hdr_len / 4) << 4;
    tcp->tcp_flags = TCP_FLAG_ACK;
    tcp->rx_win = rte_cpu_to_be_16(65535);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    // Checksum
    // prepare_tx_checksum_offload_safe already computes software checksums.
    // No fallback needed -- it either computed software or configured hardware offload.
    prepare_tx_checksum_offload(m, ip, tcp, port_id);

    return m;
}

// ==================== Sequence Number Translation ====================

/**
 * Translate packet from client to server direction
 *
 * Modifies seq/ack numbers and recalculates checksum
 */
/**
 * Translate packet from client to server direction
 */
static void translate_c2s(struct rte_mbuf *m,
                          struct rte_ipv4_hdr *ip,
                          struct rte_tcp_hdr *tcp,
                          struct syn_proxy_conn *conn) {
    // Client's seq becomes server-expected seq
    // client sends seq X, server expects X + (proxy_isn - client_isn)
    uint32_t client_seq = rte_be_to_cpu_32(tcp->sent_seq);
    uint32_t server_seq = client_seq + conn->seq_delta_c2s;
    tcp->sent_seq = rte_cpu_to_be_32(server_seq);
    
    // Client's ack (based on cookie_isn) becomes server ack (based on server_isn)
    // client acks Y (relative to cookie_isn), server expects Y - (cookie_isn - server_isn)
    if (tcp->tcp_flags & TCP_FLAG_ACK) {
        uint32_t client_ack = rte_be_to_cpu_32(tcp->recv_ack);
        uint32_t server_ack = client_ack - conn->seq_delta_s2c;  // FIXED: minus not plus
        tcp->recv_ack = rte_cpu_to_be_32(server_ack);
    }
    
    // Recalculate TCP checksum
    uint16_t tcp_len = rte_be_to_cpu_16(ip->total_length) - 
                       ((ip->version_ihl & 0x0F) * 4);
    tcp->cksum = 0;
    tcp->cksum = calc_tcp_checksum(ip, tcp, tcp_len);
    
    conn->packets_c2s++;
    conn->bytes_c2s += rte_pktmbuf_pkt_len(m);
    conn->last_client_tsc = rte_get_tsc_cycles();
}

/**
 * Translate packet from server to client direction
 */
static void translate_s2c(struct rte_mbuf *m,
                          struct rte_ipv4_hdr *ip,
                          struct rte_tcp_hdr *tcp,
                          struct syn_proxy_conn *conn) {
    // Server's seq becomes client-expected seq
    // server sends seq X (relative to server_isn), client expects X + (cookie_isn - server_isn)
    uint32_t server_seq = rte_be_to_cpu_32(tcp->sent_seq);
    uint32_t client_seq = server_seq + conn->seq_delta_s2c;  // FIXED: plus not minus
    tcp->sent_seq = rte_cpu_to_be_32(client_seq);
    
    // Server's ack (based on proxy_isn) becomes client ack (based on client_isn)
    // server acks Y (relative to proxy_isn), client expects Y - (proxy_isn - client_isn)
    if (tcp->tcp_flags & TCP_FLAG_ACK) {
        uint32_t server_ack = rte_be_to_cpu_32(tcp->recv_ack);
        uint32_t client_ack = server_ack - conn->seq_delta_c2s;  // This was correct
        tcp->recv_ack = rte_cpu_to_be_32(client_ack);
    }
    
    // Recalculate TCP checksum
    uint16_t tcp_len = rte_be_to_cpu_16(ip->total_length) - 
                       ((ip->version_ihl & 0x0F) * 4);
    tcp->cksum = 0;
    tcp->cksum = calc_tcp_checksum(ip, tcp, tcp_len);
    
    conn->packets_s2c++;
    conn->bytes_s2c += rte_pktmbuf_pkt_len(m);
    conn->last_server_tsc = rte_get_tsc_cycles();
}

// ==================== Initialization ====================

int syn_proxy_init(const struct syn_proxy_config *config) {
    if (!config) {
        RTE_LOG(ERR, SYNPROXY, "Invalid config\n");
        return -1;
    }
    
    if (g_initialized) {
        RTE_LOG(WARNING, SYNPROXY, "Already initialized\n");
        return 0;
    }
    
    memcpy(&g_config, config, sizeof(g_config));
    
    RTE_LOG(INFO, SYNPROXY, "Initializing SYN proxy:\n");
    RTE_LOG(INFO, SYNPROXY, "  Max connections: %u\n", config->max_connections);
    RTE_LOG(INFO, SYNPROXY, "  Connect timeout: %u ms\n", config->connect_timeout_ms);
    RTE_LOG(INFO, SYNPROXY, "  Idle timeout: %u sec\n", config->idle_timeout_sec);
    
    // Create connection hash table - OPTIMIZED with TRANS_MEM support
    struct rte_hash_parameters hash_params = {
        .name = "syn_proxy_hash",
        .entries = config->max_connections,
        .key_len = sizeof(struct conn_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                      RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,  // Added for better concurrency
    };

    g_conn_hash = rte_hash_create(&hash_params);
    if (!g_conn_hash) {
        RTE_LOG(ERR, SYNPROXY, "Failed to create hash table\n");
        return -1;
    }
    
    // Allocate connection pool
    g_conn_pool = rte_zmalloc("syn_proxy_conns",
                              config->max_connections * sizeof(struct syn_proxy_conn),
                              RTE_CACHE_LINE_SIZE);
    if (!g_conn_pool) {
        RTE_LOG(ERR, SYNPROXY, "Failed to allocate connection pool\n");
        rte_hash_free(g_conn_hash);
        g_conn_hash = NULL;
        return -1;
    }
    
    // Initialize secrets
    g_current_secret = config->secret;
    g_previous_secret = config->secret;
    g_last_rotation_tsc = rte_get_tsc_cycles();

    // Initialize SipHash key from DPDK random source
    g_siphash_key[0] = rte_rand();
    g_siphash_key[1] = rte_rand();

    memset(&g_stats, 0, sizeof(g_stats));
    g_initialized = true;

    // Cache TX checksum offload capabilities (avoid per-packet function calls)
    cache_offload_capabilities();

    // Initialize adaptive mode state
    g_tsc_hz = rte_get_tsc_hz();
    // Cache divisors for fast timestamp calculations (avoid rte_get_tsc_hz() in hot path)
    g_tsc_ms_divisor = g_tsc_hz / 1000;         // For millisecond timestamps
    g_tsc_32sec_divisor = g_tsc_hz * 32;        // For cookie timestamps (32-sec granularity)
    g_current_mode = SYN_PROXY_MODE_STATEFUL;  // Start in stateful mode
    g_forced_mode = -1;  // Adaptive by default
    __atomic_store_n(&g_last_mode_switch_tsc, rte_rdtsc(), __ATOMIC_RELAXED);
    g_adaptive_window_start_tsc = rte_rdtsc();
    g_adaptive_syn_count = 0;
    g_current_syn_rate_pps = 0;

    // Calculate mode switch delay in TSC cycles
    uint32_t delay_ms = config->mode_switch_delay_ms ?
                        config->mode_switch_delay_ms :
                        DEFAULT_MODE_SWITCH_DELAY_MS;
    g_mode_switch_delay_tsc = (g_tsc_hz * delay_ms) / 1000;

    // Set challenge threshold from config (syn_cookie.challenge_threshold)
    if (config->challenge_threshold > 0) {
        g_challenge_threshold = config->challenge_threshold;
    }

    RTE_LOG(INFO, SYNPROXY, "SYN proxy initialized successfully\n");
    RTE_LOG(INFO, SYNPROXY, "  Adaptive mode: ENABLED\n");
    RTE_LOG(INFO, SYNPROXY, "  Stateless threshold: %u PPS\n",
            config->stateless_threshold_pps ? config->stateless_threshold_pps :
            DEFAULT_STATELESS_THRESHOLD_PPS);
    RTE_LOG(INFO, SYNPROXY, "  Stateful threshold:  %u PPS\n",
            config->stateful_threshold_pps ? config->stateful_threshold_pps :
            DEFAULT_STATEFUL_THRESHOLD_PPS);
    RTE_LOG(INFO, SYNPROXY, "  Mode switch delay:   %u ms\n", delay_ms);
    RTE_LOG(INFO, SYNPROXY, "  Challenge threshold: %u PPS\n", g_challenge_threshold);

    return 0;
}

void syn_proxy_cleanup(void) {
    if (g_conn_hash) {
        rte_hash_free(g_conn_hash);
        g_conn_hash = NULL;
    }
    
    if (g_conn_pool) {
        rte_free(g_conn_pool);
        g_conn_pool = NULL;
    }
    
    g_initialized = false;
    RTE_LOG(INFO, SYNPROXY, "SYN proxy cleanup complete\n");
}

// ==================== Main Packet Processing ====================

int syn_proxy_process_packet(struct rte_mbuf *m,
                             struct packet_features *features,
                             uint8_t direction,
                             struct rte_mempool *mempool,
                             struct syn_proxy_result *result,
                             uint16_t port_id,
                             const struct per_ip_anomaly_snapshot *ip_anom) {

    // Initialize result with safe defaults
    memset(result, 0, sizeof(*result));
    result->action = SYN_PROXY_BYPASS;
    
    if (!g_initialized || !g_config.enabled) {
        return 0;
    }
    
    // Only handle TCP
    if (features->protocol != IPPROTO_TCP) {
        return 0;
    }
    
    // Get packet headers
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    uint8_t ip_hdr_len = (ip->version_ihl & 0x0F) * 4;
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + ip_hdr_len);
    
    // Build connection key (always from client's perspective)
    struct conn_key key;
    if (direction == DIRECTION_INBOUND) {
        make_conn_key(&key, features->src_ip, features->dst_ip,
                      features->src_port, features->dst_port);
    } else {
        make_conn_key(&key, features->dst_ip, features->src_ip,
                      features->dst_port, features->src_port);
    }
    
    struct syn_proxy_conn *conn = find_connection(&key);
    
    // ========== INBOUND (Client -> Server) ==========
    if (direction == DIRECTION_INBOUND) {
        uint8_t tcp_flags = features->tcp_flags;

        // Handle bypassed connections first - forward all packets without modification
        // These are connections that were allowed through without SYN cookie challenge
        if (conn && conn->state == SYN_PROXY_BYPASSED) {
            conn->last_client_tsc = rte_get_tsc_cycles();
            result->action = SYN_PROXY_FORWARD;
            result->packet_modified = false;
            result->conn_state = conn->state;
            return 0;
        }

        // ----- Pure SYN Packet -----
        if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
            // If connection exists in CONNECTING or later, this is a retransmit
            if (conn && conn->state >= SYN_PROXY_CONNECTING) {
                // Client retransmitting SYN - ignore, we've already validated
                result->action = SYN_PROXY_DROP;
                return 0;
            }

            // Check if we should challenge this SYN with a cookie
            // This uses intelligent logic based on:
            // - Reputation (good IPs bypass during normal load)
            // - Policy rules
            // - Current SYN rate vs threshold
            // - Anomaly state
            if (!syn_proxy_should_challenge(features, ip_anom)) {
                // Trusted traffic during normal conditions - bypass to server
                // Create a connection entry in BYPASSED state so subsequent packets
                // are forwarded without cookie validation
                struct syn_proxy_conn *bypass_conn = alloc_connection(&key);
                if (bypass_conn) {
                    bypass_conn->client_ip = features->src_ip;
                    bypass_conn->server_ip = features->dst_ip;
                    bypass_conn->client_port = features->src_port;
                    bypass_conn->server_port = features->dst_port;
                    bypass_conn->state = SYN_PROXY_BYPASSED;
                    bypass_conn->created_tsc = rte_get_tsc_cycles();
                    bypass_conn->state_change_tsc = bypass_conn->created_tsc;
                    bypass_conn->last_client_tsc = bypass_conn->created_tsc;
                }
                __atomic_add_fetch(&g_stats.packets_bypassed, 1, __ATOMIC_RELAXED);
                result->action = SYN_PROXY_BYPASS;
                return 0;
            }

            // ========== ADAPTIVE MODE: Choose stateful or stateless handling ==========
            enum syn_proxy_mode mode = adaptive_mode_update();

            if (likely(mode == SYN_PROXY_MODE_STATELESS)) {
                // ===== ULTRA-FAST STATELESS MODE (Attack) - ZERO-COPY =====
                // Maximum speed path: no options parsing, no hash ops, no atomics
                // Just extract MSS, generate cookie, transform packet in-place

                // Check SYN-ACK rate limit before sending
                if (!synack_rate_limit_check()) {
                    result->action = SYN_PROXY_DROP;
                    return 0;
                }

                // Fast MSS extraction (skips full options parsing)
                uint16_t mss = fast_extract_mss(tcp);

                // Fast cookie generation (inlined, optimized)
                uint32_t cookie = fast_generate_cookie(features->src_ip, features->dst_ip,
                                                       features->src_port, features->dst_port,
                                                       mss);

                // Transform SYN -> SYN-ACK in place (no allocation!)
                transform_syn_to_synack_inplace(m, cookie, port_id);

                // Stats - use relaxed atomics (single instruction, very fast)
                __atomic_add_fetch(&g_stats.cookies_sent, 1, __ATOMIC_RELAXED);
                __atomic_add_fetch(&g_stats.stateless_syns, 1, __ATOMIC_RELAXED);

                // Tell caller: send this mbuf as reply, don't free it
                result->action = SYN_PROXY_REPLY_INPLACE;
                result->conn_state = SYN_PROXY_SYN_SENT;
                return 0;

            } else {
                // ===== STATEFUL MODE (Normal) =====
                // Check SYN-ACK rate limit before sending
                if (!synack_rate_limit_check()) {
                    result->action = SYN_PROXY_DROP;
                    return 0;
                }

                // Full options parsing for better TCP option handling
                struct tcp_syn_options client_opts;
                parse_tcp_options(tcp, &client_opts);

                uint32_t cookie = generate_cookie(features->src_ip, features->dst_ip,
                                                  features->src_port, features->dst_port,
                                                  client_opts.mss);

                // Create SYN-ACK to client (allocates new mbuf)
                result->reply_pkt = create_synack_to_client(mempool, features, eth,
                                                            cookie, &client_opts, port_id);
                if (!result->reply_pkt) {
                    result->action = SYN_PROXY_ERROR;
                    return -1;
                }

                __atomic_add_fetch(&g_stats.cookies_sent, 1, __ATOMIC_RELAXED);
                __atomic_add_fetch(&g_stats.stateful_syns, 1, __ATOMIC_RELAXED);

                result->action = SYN_PROXY_REPLY;
                result->conn_state = SYN_PROXY_SYN_SENT;
                return 0;
            }
        }
        
        // ----- ACK Packet (with or without data) -----
        if (tcp_flags & TCP_FLAG_ACK) {
            // Established connection - translate and forward
            if (conn && conn->state == SYN_PROXY_ESTABLISHED) {
                translate_c2s(m, ip, tcp, conn);
                result->action = SYN_PROXY_FORWARD;
                result->packet_modified = true;
                result->conn_state = conn->state;
                __atomic_add_fetch(&g_stats.packets_proxied_c2s, 1, __ATOMIC_RELAXED);
                return 0;
            }

            // Connection waiting for server - drop client packets (they'll retransmit)
            if (conn && conn->state == SYN_PROXY_CONNECTING) {
                result->action = SYN_PROXY_DROP;
                result->conn_state = conn->state;
                return 0;
            }

            // Closing states - translate and forward
            if (conn && (conn->state == SYN_PROXY_CLIENT_FIN ||
                        conn->state == SYN_PROXY_SERVER_FIN ||
                        conn->state == SYN_PROXY_CLOSING)) {
                translate_c2s(m, ip, tcp, conn);
                result->action = SYN_PROXY_FORWARD;
                result->packet_modified = true;
                result->conn_state = conn->state;
                return 0;
            }
            
            // No connection - try to validate cookie (only for pure ACK, no data)
            uint16_t payload_len = rte_be_to_cpu_16(ip->total_length) - ip_hdr_len -
                                   ((tcp->data_off >> 4) * 4);

            // Only validate cookie for pure ACK (handshake completion)
            if (payload_len == 0 && !(tcp_flags & TCP_FLAG_FIN) && !(tcp_flags & TCP_FLAG_RST)) {
                uint16_t recovered_mss;
                if (!validate_cookie(features->src_ip, features->dst_ip,
                                     features->src_port, features->dst_port,
                                     features->tcp_ack, &recovered_mss)) {
                    // Invalid cookie - bypass (might be normal traffic)
                    result->action = SYN_PROXY_BYPASS;
                    __atomic_add_fetch(&g_stats.packets_bypassed, 1, __ATOMIC_RELAXED);
                    return 0;
                }
                
                // Valid cookie! Create connection state
                __atomic_add_fetch(&g_stats.cookies_valid, 1, __ATOMIC_RELAXED);

                // Per-source-IP half-open connection limit
                if (!half_open_try_increment(features->src_ip)) {
                    result->action = SYN_PROXY_DROP;
                    __atomic_add_fetch(&g_stats.table_full_drops, 1, __ATOMIC_RELAXED);
                    return 0;
                }

                // Add to legitimate IP table (spoofed mode fast-path)
                legitimate_ip_add(features->src_ip);

                conn = alloc_connection(&key);
                if (!conn) {
                    half_open_decrement(features->src_ip);
                    result->action = SYN_PROXY_DROP;
                    return 0;
                }
                
                // Store sequence numbers
                conn->client_isn = features->tcp_seq - 1;
                conn->cookie_isn = features->tcp_ack - 1;
                // Generate ISN from connection tuple + secret (not predictable rte_rand)
                {
                    uint32_t isn_data[4];
                    isn_data[0] = features->src_ip;
                    isn_data[1] = features->dst_ip;
                    isn_data[2] = ((uint32_t)features->src_port << 16) | features->dst_port;
                    isn_data[3] = (uint32_t)rte_get_tsc_cycles();
                    (void)__atomic_load_n(&g_current_secret, __ATOMIC_ACQUIRE);
                    conn->proxy_isn = (uint32_t)siphash_2_4(isn_data, sizeof(isn_data), g_siphash_key);
                }
                
                conn->client_opts.mss = recovered_mss;
                conn->state = SYN_PROXY_CONNECTING;
                conn->state_change_tsc = rte_get_tsc_cycles();
                
                // Send SYN to server
                result->reply_pkt = create_syn_to_server(mempool, conn, eth, port_id);
                if (!result->reply_pkt) {
                    free_connection(conn);
                    result->action = SYN_PROXY_ERROR;
                    return -1;
                }
                
                result->action = SYN_PROXY_REPLY;
                result->conn_state = SYN_PROXY_CONNECTING;
                return 0;
            }
            
            // ACK with data but no connection - bypass
            result->action = SYN_PROXY_BYPASS;
            __atomic_add_fetch(&g_stats.packets_bypassed, 1, __ATOMIC_RELAXED);
            return 0;
        }
        
        // ----- FIN Packet -----
        if (tcp_flags & TCP_FLAG_FIN) {
            if (conn && conn->state >= SYN_PROXY_ESTABLISHED) {
                translate_c2s(m, ip, tcp, conn);
                conn->state = SYN_PROXY_CLIENT_FIN;
                result->action = SYN_PROXY_FORWARD;
                result->packet_modified = true;
                return 0;
            }
            // No connection - bypass
            result->action = SYN_PROXY_BYPASS;
            return 0;
        }
        
        // ----- RST Packet -----
        if (tcp_flags & TCP_FLAG_RST) {
            if (conn) {
                if (conn->state >= SYN_PROXY_ESTABLISHED) {
                    translate_c2s(m, ip, tcp, conn);
                    result->action = SYN_PROXY_FORWARD;
                    result->packet_modified = true;
                }
                free_connection(conn);
            }
            // Bypass RST for non-proxied or forward translated RST
            if (result->action != SYN_PROXY_FORWARD) {
                result->action = SYN_PROXY_BYPASS;
            }
            return 0;
        }
        
        // Default: bypass
        result->action = SYN_PROXY_BYPASS;
        __atomic_add_fetch(&g_stats.packets_bypassed, 1, __ATOMIC_RELAXED);
        return 0;
    }
    
    // ========== OUTBOUND (Server -> Client) ==========
    else {
        if (!conn) {
            result->action = SYN_PROXY_BYPASS;
            __atomic_add_fetch(&g_stats.packets_bypassed, 1, __ATOMIC_RELAXED);
            return 0;
        }

        // Bypassed connection - forward without translation
        // Server responses to bypassed connections should pass through unchanged
        if (conn->state == SYN_PROXY_BYPASSED) {
            conn->last_server_tsc = rte_get_tsc_cycles();
            result->action = SYN_PROXY_FORWARD;
            result->packet_modified = false;
            result->conn_state = conn->state;
            return 0;
        }

        uint8_t tcp_flags = features->tcp_flags;
        
        // ----- SYN-ACK from Server -----
        if ((tcp_flags & TCP_FLAG_SYN) && (tcp_flags & TCP_FLAG_ACK)) {
            
            if (conn->state != SYN_PROXY_CONNECTING) {
                result->action = SYN_PROXY_DROP;
                return 0;
            }
            
            // Record server's ISN
            conn->server_isn = features->tcp_seq;
            
            // Calculate sequence deltas
            conn->seq_delta_c2s = (int32_t)(conn->proxy_isn - conn->client_isn);
            conn->seq_delta_s2c = (int32_t)(conn->cookie_isn - conn->server_isn);

            // Release half-open slot on successful establishment
            half_open_decrement(conn->client_ip);
            conn->state = SYN_PROXY_ESTABLISHED;
            conn->state_change_tsc = rte_get_tsc_cycles();
            conn->last_server_tsc = rte_get_tsc_cycles();
            
            __atomic_add_fetch(&g_stats.connections_established, 1, __ATOMIC_RELAXED);
            
            // Send ACK to server
            result->reply_pkt = create_ack_to_server(mempool, conn, eth, port_id);
            if (!result->reply_pkt) {
                free_connection(conn);
                result->action = SYN_PROXY_ERROR;
                return -1;
            }
            
            // Don't forward server's SYN-ACK (client already got ours)
            result->action = SYN_PROXY_REPLY;
            result->conn_state = SYN_PROXY_ESTABLISHED;
            return 0;
        }
        
        // ----- RST from Server -----
        if (tcp_flags & TCP_FLAG_RST) {
            if (conn->state == SYN_PROXY_ESTABLISHED ||
                conn->state == SYN_PROXY_CLIENT_FIN ||
                conn->state == SYN_PROXY_SERVER_FIN) {
                translate_s2c(m, ip, tcp, conn);
                result->action = SYN_PROXY_FORWARD;
                result->packet_modified = true;
            }
            free_connection(conn);
            if (result->action != SYN_PROXY_FORWARD) {
                result->action = SYN_PROXY_DROP;
            }
            return 0;
        }
        
        // ----- FIN from Server -----
        if (tcp_flags & TCP_FLAG_FIN) {
            if (conn->state >= SYN_PROXY_ESTABLISHED) {
                translate_s2c(m, ip, tcp, conn);
                if (conn->state == SYN_PROXY_CLIENT_FIN) {
                    conn->state = SYN_PROXY_CLOSING;
                } else {
                    conn->state = SYN_PROXY_SERVER_FIN;
                }
                result->action = SYN_PROXY_FORWARD;
                result->packet_modified = true;
                return 0;
            }
            result->action = SYN_PROXY_DROP;
            return 0;
        }
        
        // ----- Data/ACK from Server -----
        if (conn->state >= SYN_PROXY_ESTABLISHED) {
            translate_s2c(m, ip, tcp, conn);
            result->action = SYN_PROXY_FORWARD;
            result->packet_modified = true;
            result->conn_state = conn->state;
            __atomic_add_fetch(&g_stats.packets_proxied_s2c, 1, __ATOMIC_RELAXED);
            return 0;
        }
        
        // Server sending data before established - drop
        result->action = SYN_PROXY_DROP;
        return 0;
    }
}

// ==================== Utility Functions ====================
bool syn_proxy_is_enabled(void) {
    return g_initialized && g_config.enabled;
}

void syn_proxy_set_enabled(bool enabled) {
    if (!g_initialized) return;
    g_config.enabled = enabled;
}

void syn_proxy_set_challenge_threshold(uint32_t threshold) {
    if (!g_initialized) return;
    g_config.challenge_threshold = threshold;
}

bool syn_proxy_is_proxied(const struct packet_features *features, uint8_t direction) {
    if (!g_initialized) return false;
    
    struct conn_key key;
    if (direction == 0) {
        make_conn_key(&key, features->src_ip, features->dst_ip,
                      features->src_port, features->dst_port);
    } else {
        make_conn_key(&key, features->dst_ip, features->src_ip,
                      features->dst_port, features->src_port);
    }
    
    return find_connection(&key) != NULL;
}



// ==================== SYN Rate Tracking ====================

/**
 * Update SYN rate tracking window.
 * Called internally to maintain sliding window statistics.
 */
static inline void update_syn_rate_window(void) {
    if (g_tsc_hz == 0) {
        g_tsc_hz = rte_get_tsc_hz();
        __atomic_store_n(&g_syn_window_start_tsc, rte_get_tsc_cycles(), __ATOMIC_RELEASE);
        return;
    }

    uint64_t now = rte_get_tsc_cycles();
    uint64_t window_duration = SYN_RATE_WINDOW_SEC * g_tsc_hz;
    uint64_t window_start = __atomic_load_n(&g_syn_window_start_tsc, __ATOMIC_ACQUIRE);

    // CAS-based window rotation to prevent multi-lcore TOCTOU
    if (now - window_start >= window_duration) {
        if (__atomic_compare_exchange_n(&g_syn_window_start_tsc,
                                         &window_start, now,
                                         false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            // This lcore won - rotate windows
            uint64_t current = __atomic_exchange_n(&g_syn_count_current, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&g_syn_count_previous, current, __ATOMIC_RELAXED);
        }
    }
}

/**
 * Get current estimated SYN rate (packets per second).
 * Uses weighted average of current and previous window for smoother estimate.
 */
static inline uint64_t get_current_syn_rate(void) {
    update_syn_rate_window();

    if (g_tsc_hz == 0) return 0;

    uint64_t now = rte_get_tsc_cycles();
    uint64_t window_duration = SYN_RATE_WINDOW_SEC * g_tsc_hz;
    uint64_t elapsed = now - __atomic_load_n(&g_syn_window_start_tsc, __ATOMIC_ACQUIRE);

    if (elapsed == 0) elapsed = 1;  // Prevent division by zero

    // Weighted average: extrapolate current window + decay previous
    uint64_t current_count = __atomic_load_n(&g_syn_count_current, __ATOMIC_RELAXED);
    uint64_t previous_count = __atomic_load_n(&g_syn_count_previous, __ATOMIC_RELAXED);
    uint64_t current_rate = (current_count * g_tsc_hz) / elapsed;
    uint64_t previous_rate = previous_count / SYN_RATE_WINDOW_SEC;

    // Blend: weight current more as window progresses
    double fraction = (double)elapsed / window_duration;
    if (fraction > 1.0) fraction = 1.0;

    return (uint64_t)(current_rate * fraction + previous_rate * (1.0 - fraction));
}

/**
 * Record a SYN packet for rate tracking.
 */
static inline void record_syn_packet(void) {
    update_syn_rate_window();
    __atomic_add_fetch(&g_syn_count_current, 1, __ATOMIC_RELAXED);
}

/**
 * Check if we can send a SYN-ACK response (rate limiting).
 * Uses probabilistic acceptance above 50% threshold to give legitimate
 * clients a fair chance during floods.
 * Returns true if allowed, false if rate limit exceeded.
 */
static inline bool synack_rate_limit_check(void) {
    if (unlikely(g_tsc_hz == 0)) {
        g_tsc_hz = rte_get_tsc_hz();
        __atomic_store_n(&g_synack_window_start_tsc, rte_rdtsc(), __ATOMIC_RELEASE);
        return true;
    }

    uint64_t now = rte_rdtsc();
    uint64_t window_duration = g_tsc_hz;  // 1 second window

    // CAS-based window reset to prevent multi-lcore TOCTOU
    uint64_t window_start = __atomic_load_n(&g_synack_window_start_tsc, __ATOMIC_ACQUIRE);
    if (now - window_start >= window_duration) {
        if (__atomic_compare_exchange_n(&g_synack_window_start_tsc,
                                         &window_start, now,
                                         false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            __atomic_store_n(&g_synack_count_current, 0, __ATOMIC_RELAXED);
        }
    }

    uint64_t current_count = __atomic_load_n(&g_synack_count_current, __ATOMIC_RELAXED);

    // Hard limit exceeded - always drop
    if (current_count >= MAX_SYNACK_RATE) {
        __atomic_add_fetch(&g_stats.synack_rate_limited, 1, __ATOMIC_RELAXED);
        return false;
    }

    // Allow and increment counter
    __atomic_add_fetch(&g_synack_count_current, 1, __ATOMIC_RELAXED);
    return true;
}

/**
 * Intelligent SYN challenge decision.
 *
 * Determines whether to challenge a SYN packet based on:
 * 1. Policy rules (explicit CHALLENGE action)
 * 2. Source IP reputation
 * 3. Global anomaly state (set by Layer 3/4)
 * 4. Current SYN rate vs threshold
 *
 * @param features  Packet features from SYN packet
 * @return true if should challenge with SYN cookie, false for normal processing
 */
bool syn_proxy_should_challenge(const struct packet_features *features,
                                const struct per_ip_anomaly_snapshot *ip_anom) {
    if (!g_initialized || !g_config.enabled) {
        return false;
    }

    // Record this SYN for rate tracking
    record_syn_packet();

    // ========== Check 0: Spoofed attack mode (per-IP or global) ==========
    // Per-IP: only challenge if THIS destination is in spoofed mode for TCP
    // Global fallback: challenge all if system-wide spoofed mode active
    {
        bool spoofed = false;
        if (ip_anom && ip_anom->valid && ip_anom->spoofed_mode) {
            spoofed = protocol_matches_anomaly(IPPROTO_TCP, ip_anom->anomaly_protocol);
        } else if (!ip_anom || !ip_anom->valid) {
            spoofed = anomaly_is_spoofed_mode();  // Global fallback
        } else if (layer1_config_get()->global_circuit_breaker && anomaly_is_spoofed_mode()) {
            spoofed = true;  // Global circuit breaker (gated by config)
        }
        if (spoofed) {
            __atomic_add_fetch(&g_stats.challenged_spoofed_mode, 1, __ATOMIC_RELAXED);
            return true;
        }
    }

    // ========== Check 1: Policy-based challenge ==========
    struct policy_result policy_result;
    policy_lookup(features, &policy_result);

    if (policy_result.matched) {
        if (policy_result.action == POLICY_CHALLENGE) {
            // Policy explicitly requires challenge
            return true;
        }
        if (policy_result.action == POLICY_ALLOW) {
            // Policy explicitly allows - bypass challenge (trusted traffic)
            return false;
        }
        // POLICY_DROP should have been handled earlier in pipeline
        // POLICY_RATE_LIMIT - continue to other checks
    }

    // ========== Check 2: Reputation-based challenge ==========
    struct reputation_result rep_result;
    reputation_lookup(features->src_ip, &rep_result);

    if (rep_result.found) {
        // Known attacker - should have been dropped earlier, but challenge if here
        if (rep_result.level == REP_ATTACKER) {
            return true;
        }

        // Suspicious reputation - always challenge
        if (rep_result.level == REP_SUSPICIOUS) {
            return true;
        }

        // Good or excellent reputation - trust during normal/moderate load
        if (rep_result.level >= REP_GOOD) {
            uint64_t syn_rate = get_current_syn_rate();
            // Only challenge good IPs if rate is 10x threshold (severe attack)
            if (syn_rate > (uint64_t)g_challenge_threshold * 10) {
                return true;
            }
            return false;
        }
    }

    // ========== Check 3: Anomaly state (per-IP or global) ==========
    // Per-IP: challenge if THIS destination has anomaly level >= MEDIUM for TCP
    // Global fallback: challenge if system-wide anomaly level >= MEDIUM
    {
        bool should_challenge_anomaly = false;
        if (ip_anom && ip_anom->valid && ip_anom->anomaly_active) {
            if (protocol_matches_anomaly(IPPROTO_TCP, ip_anom->anomaly_protocol) &&
                ip_anom->anomaly_level >= ANOMALY_LEVEL_MEDIUM) {
                should_challenge_anomaly = true;
            }
        } else if (!ip_anom || !ip_anom->valid) {
            // Global fallback
            if (anomaly_is_active() && anomaly_get_level() >= ANOMALY_LEVEL_MEDIUM) {
                should_challenge_anomaly = true;
            }
        } else if (layer1_config_get()->global_circuit_breaker) {
            // Circuit breaker: per-IP valid but not active/not TCP, global overrides
            if (anomaly_is_active() && anomaly_get_level() >= ANOMALY_LEVEL_MEDIUM) {
                should_challenge_anomaly = true;
            }
        }
        if (should_challenge_anomaly) {
            return true;
        }
    }

    // ========== Check 4: Rate-based challenge ==========
    uint64_t syn_rate = get_current_syn_rate();
    if (syn_rate > g_challenge_threshold) {
        return true;
    }

    // Normal conditions - no challenge needed
    return false;
}

uint32_t syn_proxy_cleanup_connections(void) {
    if (!g_initialized) return 0;
    
    uint64_t now = rte_get_tsc_cycles();
    uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t connect_timeout_tsc = (g_config.connect_timeout_ms * tsc_hz) / 1000;
    uint64_t idle_timeout_tsc = g_config.idle_timeout_sec * tsc_hz;
    
    uint32_t cleaned = 0;
    const void *key;
    void *data;
    uint32_t iter = 0;
    
    // Collect keys to delete (can't delete during iteration)
    struct conn_key keys_to_delete[256];
    uint32_t delete_count = 0;
    
    int32_t pos;
    while ((pos = rte_hash_iterate(g_conn_hash, &key, &data, &iter)) >= 0) {
        // Use position returned by rte_hash_iterate directly,
        // avoiding redundant rte_hash_lookup that could race with data-path.
        if (pos >= (int32_t)g_config.max_connections) continue;

        struct syn_proxy_conn *conn = &g_conn_pool[pos];
        bool should_delete = false;
        
        switch (conn->state) {
            case SYN_PROXY_CONNECTING:
                // Check connect timeout
                if (now - conn->state_change_tsc > connect_timeout_tsc) {
                    __atomic_add_fetch(&g_stats.server_timeout, 1, __ATOMIC_RELAXED);
                    should_delete = true;
                }
                break;
                
            case SYN_PROXY_ESTABLISHED:
            case SYN_PROXY_CLIENT_FIN:
            case SYN_PROXY_SERVER_FIN:
                // Check idle timeout
                {
                    uint64_t last_activity = conn->last_client_tsc > conn->last_server_tsc ?
                                             conn->last_client_tsc : conn->last_server_tsc;
                    if (now - last_activity > idle_timeout_tsc) {
                        __atomic_add_fetch(&g_stats.connections_timeout, 1, __ATOMIC_RELAXED);
                        should_delete = true;
                    }
                }
                break;
                
            case SYN_PROXY_CLOSING:
            case SYN_PROXY_CLOSED:
                should_delete = true;
                break;
                
            default:
                break;
        }
        
        if (should_delete && delete_count < 256) {
            memcpy(&keys_to_delete[delete_count], key, sizeof(struct conn_key));
            delete_count++;
        }
    }
    
    // Now delete collected keys
    for (uint32_t i = 0; i < delete_count; i++) {
        int32_t idx = rte_hash_lookup(g_conn_hash, &keys_to_delete[i]);
        if (idx >= 0) {
            struct syn_proxy_conn *conn = &g_conn_pool[idx];

            // Release half-open slot if connection was still CONNECTING
            if (conn->state == SYN_PROXY_CONNECTING) {
                half_open_decrement(conn->client_ip);
            }

            conn->state = SYN_PROXY_NONE;
            rte_hash_del_key(g_conn_hash, &keys_to_delete[i]);
            cleaned++;
            __atomic_sub_fetch(&g_stats.connections_active, 1, __ATOMIC_RELAXED);
        }
    }
    
    if (cleaned > 0) {
        RTE_LOG(DEBUG, SYNPROXY, "Cleaned up %u connections\n", cleaned);
    }
    
    return cleaned;
}

void syn_proxy_rotate_secret(uint32_t new_secret) {
    // Use atomic stores with release semantics so hot path readers
    // (fast_generate_cookie, validate_cookie) see consistent secret pair.
    // Store previous BEFORE current, so readers never see both changed.
    __atomic_store_n(&g_previous_secret, g_current_secret, __ATOMIC_RELEASE);
    __atomic_store_n(&g_current_secret, new_secret, __ATOMIC_RELEASE);
    g_last_rotation_tsc = rte_get_tsc_cycles();

    RTE_LOG(INFO, SYNPROXY, "Secret rotated\n");
}

// ==================== Statistics ====================

void syn_proxy_get_stats(struct syn_proxy_stats *stats) {
    if (stats) {
        memcpy(stats, &g_stats, sizeof(*stats));
        // Add current adaptive mode info
        stats->current_mode = g_current_mode;
        stats->current_syn_rate = g_current_syn_rate_pps;
    }
}

void syn_proxy_clear_all(void) {
    if (!g_initialized || !g_conn_hash || !g_conn_pool) return;
    rte_hash_reset(g_conn_hash);
    memset(g_conn_pool, 0, g_config.max_connections * sizeof(struct syn_proxy_conn));
    memset(&g_stats, 0, sizeof(g_stats));
    g_current_mode = 0;
    g_current_syn_rate_pps = 0;
    RTE_LOG(INFO, SYNPROXY, "SYN proxy cleared (factory reset)\n");
}

void syn_proxy_reset_stats(void) {
    uint32_t active = g_stats.connections_active;
    memset(&g_stats, 0, sizeof(g_stats));
    g_stats.connections_active = active;
}

void syn_proxy_print_stats(void) {
    printf("  SYN Proxy Statistics:\n");
    printf("    Connections: %u active, %lu created, %lu established\n",
           g_stats.connections_active,
           g_stats.connections_created,
           g_stats.connections_established);
    printf("    Cookies: %lu sent, %lu valid, %lu invalid, %lu expired\n",
           g_stats.cookies_sent,
           g_stats.cookies_valid,
           g_stats.cookies_invalid,
           g_stats.cookies_expired);
    printf("    Packets: %lu c2s, %lu s2c, %lu bypassed\n",
           g_stats.packets_proxied_c2s,
           g_stats.packets_proxied_s2c,
           g_stats.packets_bypassed);
    printf("    Rate Limited: %lu SYN-ACK responses dropped\n",
           g_stats.synack_rate_limited);
    printf("    Errors: %lu server failures, %lu timeouts, %lu table full\n",
           g_stats.server_connect_failed,
           g_stats.server_timeout,
           g_stats.table_full_drops);
    printf("    Adaptive Mode: %s (SYN rate: %u PPS)\n",
           (g_current_mode == SYN_PROXY_MODE_STATELESS) ? "STATELESS" : "STATEFUL",
           g_current_syn_rate_pps);
    printf("    Mode switches: %lu (stateless: %lu, stateful: %lu)\n",
           g_stats.mode_switches,
           g_stats.stateless_syns,
           g_stats.stateful_syns);
    printf("    Spoofed mode challenges: %lu\n",
           g_stats.challenged_spoofed_mode);
}

// ==================== Spoofed Rate Limiter ====================

int spoofed_rate_init(uint32_t legitimate_table_size) {
    // Stub: no per-dst aggregate rate limiting yet
    (void)legitimate_table_size;
    return 0;
}

enum rate_limit_action spoofed_rate_check(const struct packet_features *features,
                                          bool has_prior_flow) {
    // Under spoofed attack: apply aggregate per-destination rate limiting
    // Per-source limits are useless when each fake IP sends ~1 packet.
    // This is a stub implementation; full implementation uses per-dst counters.
    (void)features;
    (void)has_prior_flow;
    return RL_ACCEPT;
}

void spoofed_rate_cleanup(void) {
    /* Stub: nothing to free in stub implementation */
}

/* Weak fallbacks for checksum offload query (defined in libcore).
 * Used when liblayer1 is linked without libcore (e.g., unit tests). */
__attribute__((weak)) bool is_tx_ip_cksum_offload_enabled(uint16_t port_id) {
    (void)port_id;
    return false;
}

__attribute__((weak)) bool is_tx_tcp_cksum_offload_enabled(uint16_t port_id) {
    (void)port_id;
    return false;
}

