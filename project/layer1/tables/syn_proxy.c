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
#define DEFAULT_CHALLENGE_THRESHOLD L1_DEFAULT_CHALLENGE_THRESHOLD  // Default SYN PPS threshold for challenge
#define MAX_SYNACK_RATE         250000  // Maximum SYN-ACK responses per second (rate limit)

// MSS a SYN without an MSS option announces: the default send MSS of
// RFC 9293 (3.7.1) for IPv4. Both the stateful option parser and the
// stateless fast extraction use it, so the cookie keeps the same MSS in both.
#define TCP_DEFAULT_MSS         536

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

// Entries in g_conn_pool: one per key position the connection hash can
// return, rte_hash_max_key_id(). Every lcore adds keys, so the hash takes
// RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD, whose per-lcore caches of free key
// slots make positions run past max_connections.
static uint32_t g_pool_entries = 0;
// Entries claimed and not yet retired (see "Entry control word"). The hash
// alone could hold more than max_connections keys; this counter keeps
// max_connections the capacity. Unlike connections_active it is never reset
// with the statistics.
static uint32_t g_entries_used = 0;
// Where syn_proxy_cleanup_connections() resumes its scan
static uint32_t g_cleanup_iter = 0;

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

// One word per slot: the source IP in the high 32 bits and its count in the
// low 32 bits, changed only by compare-and-swap, so the count and the source
// it counts for always change together. With two separate fields a release
// could clear a count that an increment of the same source had just taken;
// that connection's own release then no longer matched the slot, which was
// left holding a count that no connection held.
struct half_open_entry {
    uint64_t word;                 // HALF_OPEN_WORD(src_ip, count); count 0 = empty
} __rte_cache_aligned;

#define HALF_OPEN_WORD(ip, count)  (((uint64_t)(ip) << 32) | (uint32_t)(count))
#define HALF_OPEN_IP(w)            ((uint32_t)((w) >> 32))
#define HALF_OPEN_COUNT(w)         ((uint32_t)(w))

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
    struct half_open_entry *e = &g_half_open_table[half_open_hash(src_ip)];
    uint64_t w = __atomic_load_n(&e->word, __ATOMIC_RELAXED);
    for (;;) {
        uint64_t desired;
        if (HALF_OPEN_COUNT(w) == 0) {
            desired = HALF_OPEN_WORD(src_ip, 1);  // Empty: claim it for this source
        } else if (HALF_OPEN_IP(w) != src_ip) {
            // Collision: allow through (conservative: don't block on hash collision)
            return true;
        } else if (HALF_OPEN_COUNT(w) >= MAX_HALF_OPEN_PER_IP) {
            return false;  // Limit exceeded
        } else {
            desired = w + 1;
        }
        if (__atomic_compare_exchange_n(&e->word, &w, desired,
                                         true, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            return true;
        }
        // w updated by CAS failure, retry
    }
}

static inline void half_open_decrement(uint32_t src_ip) {
    struct half_open_entry *e = &g_half_open_table[half_open_hash(src_ip)];
    uint64_t w = __atomic_load_n(&e->word, __ATOMIC_RELAXED);
    for (;;) {
        // Nothing held for this source: a collision let it through uncounted
        if (HALF_OPEN_IP(w) != src_ip || HALF_OPEN_COUNT(w) == 0) {
            return;
        }
        // Last connection: the slot becomes empty
        uint64_t desired = (HALF_OPEN_COUNT(w) == 1) ? 0 : w - 1;
        if (__atomic_compare_exchange_n(&e->word, &w, desired,
                                         true, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            return;
        }
    }
}

// The counts describe CONNECTING entries of the connection table, so they
// are cleared whenever that table is created (init) or wiped (clear_all)
static void half_open_reset(void) {
    memset(g_half_open_table, 0, sizeof(g_half_open_table));
}

// ==================== Cached Offload Flags (Optimization) ====================
// Cached per-port offload capabilities - set once at init, avoid per-packet function calls
static bool g_port_ip_offload[RTE_MAX_ETHPORTS] = {false};
static bool g_port_tcp_offload[RTE_MAX_ETHPORTS] = {false};
static bool g_offload_cached = false;

// Per-lcore packet ID counter (replaces expensive rte_rand() calls)
static __thread uint16_t tls_pkt_id_counter = 0;

// Cached TSC divisor (avoid repeated rte_get_tsc_hz() calls in hot path)
static uint64_t g_tsc_32sec_divisor = 0; // g_tsc_hz * 32 - for cookie timestamp (32-sec granularity)

// Fast packet ID generation using TSC + counter (much faster than rte_rand)
static inline uint16_t fast_packet_id(void) {
    // Mix TSC low bits with counter for uniqueness without expensive RNG
    return (uint16_t)((rte_rdtsc() & 0xFF00) | (++tls_pkt_id_counter & 0xFF));
}

/**
 * Ultra-fast MSS extraction for stateless mode
 * Only extracts MSS - skips all other options parsing
 * Returns TCP_DEFAULT_MSS (536) if the SYN carries no MSS option, as
 * parse_tcp_options_safe() does for the stateful mode
 *
 * Added max_len parameter to prevent buffer overflow.
 *
 * @param tcp      Pointer to TCP header
 * @param max_len  Maximum safe length to read from tcp pointer
 */
static inline uint16_t fast_extract_mss_safe(const struct rte_tcp_hdr *tcp, uint16_t max_len) {
    // Ensure we have at least minimum TCP header
    if (unlikely(max_len < 20)) {
        return TCP_DEFAULT_MSS;
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
        return TCP_DEFAULT_MSS;  // No options
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
    return TCP_DEFAULT_MSS;  // No MSS option
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

    // Update stats for the specific failure reason (after constant-time path).
    // Every failure counts once in cookies_invalid (below); an expired
    // timestamp is also counted in cookies_expired.
    if (!ack_zero && ts_expired) {
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
 * But SYN cookie completion ACKs also have no flow: the proxy keeps the
 * connections it handles in its own table, and no flow is created for
 * them. This function lets Stage 8b distinguish valid cookie ACKs from
 * spoofed orphan ACKs, so legitimate handshake completions pass through
 * to Stage 9; later packets of the connection pass on its proxy entry
 * (syn_proxy_admits_segment()).
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
    opts->mss = TCP_DEFAULT_MSS;
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

// ==================== Entry Control Word ====================
//
// Every lcore runs the pipeline. The inbound and the outbound lcore of a
// connection can hold its entry at the same time, and the cleanup on the main
// lcore can end it meanwhile; a pool slot is reused as soon as its key slot is
// free. Each entry therefore carries one 32-bit control word, conn->ctl:
//
//   bits 0-3   state: enum syn_proxy_state, CTL_ST_INIT or CTL_ST_DEAD
//   bits 4-8   flags (CTL_F_*)
//   bits 9-31  generation, advanced each time the slot is freed
//
// An lcore reads the word once (acquire) when it looks the entry up, checks
// that the entry's 4-tuple is the key it looked up (the slot may have been
// reused between the lookup and that read), decides from what it read, and
// makes each change with a compare-and-swap against that word. The swap fails
// if anything changed in between, and in particular if the entry was freed
// and its slot reused, since the generation differs. So:
// - exactly one lcore ends CONNECTING (server SYN-ACK, connect timeout, RST
//   or an error path), and only that one releases the half-open slot;
// - exactly one lcore retires an entry (deletes its key, counts it, frees its
//   slot), and only for the key it looked up, never for a new occupant;
// - the FIN and handshake flags of a BYPASSED entry, and the FIN states and
//   acknowledgements of a proxied one, change atomically, also when its
//   inbound and outbound lcores see segments at the same time.
//
// Life of a slot: NONE (free) -> CTL_ST_INIT (claimed by the lcore that added
// the key, which fills in the fields) -> published state (release store) ->
// ... -> CTL_ST_DEAD (claimed by the retiring lcore; the key is still in the
// hash) -> NONE of the next generation -> rte_hash_free_key_with_position().
// The hash has RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL: deleting a key does not
// free its slot, so the slot cannot be reused before it is marked NONE.
//
// CTL_F_BUSY marks an entry whose owner writes fields that other lcores read:
// server_isn and the sequence deltas. Nobody retires a BUSY entry or reads
// those fields, and a proxied ESTABLISHED entry that is BUSY is handled like
// CONNECTING. The flag is held for a few instructions.
//
// Fields that other lcores read outside that ordering (the timestamps the
// cleanup reads, server_isn, the deltas) use relaxed atomic loads and stores,
// which are plain loads and stores on x86.
//
// server_isn is also read where only the word's generation is checked after
// the read (syn_proxy_admits_segment(), the handshake check in
// bypass_segment()), seqlock style. Every store of server_isn is therefore a
// release store, made after the swap that claimed the slot or marked the
// entry BUSY, and those reads are acquire loads: a read that returns a later
// occupant's value synchronizes with that occupant's store, so the word read
// after it carries the later generation and the value is discarded. A relaxed
// read followed by an acquire reload of the word would not do: in the C11
// model the acquire keeps later accesses after the reload, not the earlier
// read before it. (A relaxed read, then an acquire fence, then the reload
// would do as well.) On x86 all these forms are plain moves.
//
// What remains open is benign. An lcore holding an entry that has been freed
// can still write a per-connection packet or byte counter (never read) or a
// last-activity timestamp of the new occupant, and it can forward one packet
// translated with the new occupant's deltas, which the server's TCP rejects.
// It can also overwrite the end of a FIN the new occupant has recorded
// (client_next_seq or server_next_seq, proxied_close_segment()); that FIN is
// then never seen acknowledged, and the cleanup's timeouts release the entry
// instead of its last ACK. Likewise it can overwrite a latest acknowledgement
// or the server's next sequence (client_next_ack, server_next_ack,
// server_snd_nxt) until the side's next segment: an RST of the new occupant
// in between is judged against the old value, so it is forwarded without
// ending the entry (or, from the client side, dropped), and the entry ages
// out instead.

#define CTL_STATE_MASK      0x0000000Fu
#define CTL_ST_INIT         0x0Eu         // Claimed by the adding lcore, fields not yet valid
#define CTL_ST_DEAD         0x0Fu         // Claimed by the retiring lcore, key still in the hash
#define CTL_F_BUSY          0x00000010u   // Owner is writing server_isn or the deltas
#define CTL_F_FIN_CLIENT    0x00000020u   // BYPASSED: the client sent FIN
#define CTL_F_FIN_SERVER    0x00000040u   // BYPASSED: the server sent FIN
#define CTL_F_ISN_SEEN      0x00000080u   // BYPASSED: server_isn holds the ISN of its SYN-ACK
#define CTL_F_HS_ACKED      0x00000100u   // BYPASSED: the client acknowledged server_isn + 1
#define CTL_FLAGS_MASK      0x000001F0u
#define CTL_FIN_BOTH        (CTL_F_FIN_CLIENT | CTL_F_FIN_SERVER)
// A proxied entry never carries the BYPASSED flags. Its state records which
// sides have sent FIN (CLIENT_FIN, SERVER_FIN, CLOSING); the two FIN bits
// record which of those FINs the other side has acknowledged
// (proxied_close_segment())
#define CTL_F_CLIENT_FIN_ACKED  CTL_F_FIN_CLIENT   // Proxied: the server acknowledged the client's FIN
#define CTL_F_SERVER_FIN_ACKED  CTL_F_FIN_SERVER   // Proxied: the client acknowledged the server's FIN
#define CTL_FIN_ACKED_BOTH      (CTL_F_CLIENT_FIN_ACKED | CTL_F_SERVER_FIN_ACKED)
#define CTL_GEN_SHIFT       9
#define CTL_GEN_MASK        (~(CTL_STATE_MASK | CTL_FLAGS_MASK))
#define CTL_GEN_ONE         (1u << CTL_GEN_SHIFT)

_Static_assert(SYN_PROXY_CLOSED < CTL_ST_INIT, "syn_proxy_state values must stay below CTL_ST_INIT");
_Static_assert((CTL_FLAGS_MASK >> CTL_GEN_SHIFT) == 0, "flags must stay below the generation");

static inline uint32_t ctl_load(const struct syn_proxy_conn *conn) {
    return __atomic_load_n(&conn->ctl, __ATOMIC_ACQUIRE);
}

static inline enum syn_proxy_state ctl_state(uint32_t ctl) {
    return (enum syn_proxy_state)(ctl & CTL_STATE_MASK);
}

static inline uint32_t ctl_with_state(uint32_t ctl, enum syn_proxy_state state) {
    return (ctl & ~CTL_STATE_MASK) | (uint32_t)state;
}

// A published entry: not free, not being filled in, not being retired
static inline bool ctl_live(uint32_t ctl) {
    uint32_t st = ctl & CTL_STATE_MASK;
    return st != SYN_PROXY_NONE && st < CTL_ST_INIT;
}

// Same occupant of the slot (same generation)
static inline bool ctl_same_entry(uint32_t a, uint32_t b) {
    return ((a ^ b) & CTL_GEN_MASK) == 0;
}

/**
 * Change the control word from *expected, the word this lcore read, to
 * desired. On failure *expected receives the current word.
 */
static inline bool ctl_cas(struct syn_proxy_conn *conn, uint32_t *expected, uint32_t desired) {
    return __atomic_compare_exchange_n(&conn->ctl, expected, desired, false,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

// Test seam (see syn_proxy.h): this weak default does nothing
__attribute__((weak)) void syn_proxy_race_seam(enum syn_proxy_seam_point point) {
    (void)point;
}

// A hash with RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD keeps a cache of free key
// slots per lcore, indexed by rte_lcore_id(). A thread without an lcore id
// (LCORE_ID_ANY) would index past it, so it neither adds keys nor frees slots.
static inline bool lcore_may_write_table(void) {
    return rte_lcore_id() < RTE_MAX_LCORE;
}

// The entry's 4-tuple, written while CTL_ST_INIT and the same for the life of
// the entry (relaxed atomics: a reader may race with the next occupant's)
static inline bool conn_is_key(const struct syn_proxy_conn *conn, const struct conn_key *key) {
    return __atomic_load_n(&conn->client_ip, __ATOMIC_RELAXED) == key->client_ip &&
           __atomic_load_n(&conn->server_ip, __ATOMIC_RELAXED) == key->server_ip &&
           __atomic_load_n(&conn->client_port, __ATOMIC_RELAXED) == key->client_port &&
           __atomic_load_n(&conn->server_port, __ATOMIC_RELAXED) == key->server_port;
}

/**
 * Find a live connection entry with precomputed hash - OPTIMIZED
 * *ctl gets the entry's control word. An entry that is free, being filled in
 * or being retired counts as absent. Between the lookup and the read of the
 * word, the entry the lookup found can be retired and its slot reused: the
 * word read then belongs to another connection. The 4-tuple, read after the
 * word, tells which connection it is.
 */
static inline struct syn_proxy_conn *find_connection_with_hash(
    const struct conn_key *key, hash_sig_t hash, uint32_t *ctl) {
    int32_t idx = rte_hash_lookup_with_hash(g_conn_hash, key, hash);
    if (idx >= 0 && likely((uint32_t)idx < g_pool_entries)) {
        struct syn_proxy_conn *conn = &g_conn_pool[idx];
        uint32_t c = ctl_load(conn);
        if (ctl_live(c) && conn_is_key(conn, key)) {
            *ctl = c;
            return conn;
        }
    }
    return NULL;
}

/**
 * Find connection entry (backward compatible wrapper)
 */
static struct syn_proxy_conn *find_connection(const struct conn_key *key, uint32_t *ctl) {
    hash_sig_t hash = compute_conn_hash(key);
    return find_connection_with_hash(key, hash, ctl);
}

// Take one of the max_connections entries (g_entries_used)
static inline bool reserve_entry(void) {
    uint32_t used = __atomic_load_n(&g_entries_used, __ATOMIC_RELAXED);
    do {
        if (used >= g_config.max_connections) {
            return false;
        }
    } while (!__atomic_compare_exchange_n(&g_entries_used, &used, used + 1, true,
                                          __ATOMIC_RELAXED, __ATOMIC_RELAXED));
    return true;
}

static inline void unreserve_entry(void) {
    __atomic_sub_fetch(&g_entries_used, 1, __ATOMIC_RELAXED);
}

/**
 * Allocate new connection entry with precomputed hash - OPTIMIZED
 *
 * Returns the entry in state CTL_ST_INIT, owned by this lcore: the caller fills
 * in its fields and then publishes its state with conn_publish(). *ctl gets
 * the INIT word. Returns NULL if the table is full, if the key is in the table
 * already (another lcore added it after this lcore's lookup, and the entry is
 * that lcore's), or on a thread without an lcore id.
 *
 * The slot is claimed only while the key maps to it. When the add finds the
 * key of another lcore's entry, that lcore can retire the entry (delete the
 * key, mark the slot NONE of the next generation and free it) before this
 * lcore reads the word. Claiming the NONE slot then would publish an entry
 * that the hash does not map, on a slot that the hash hands out again. So a
 * NONE slot is claimed only if the lookup still maps the key to it. The
 * mapping cannot change between that lookup and the swap: only the lcore that
 * retires a live entry deletes a key, its own, and a slot holding NONE has no
 * live entry; another lcore claiming the slot first makes the swap fail. If
 * the key has gone, the add is made once more (the key is new now); if it
 * maps to another slot, the entry there is another lcore's.
 */
static inline struct syn_proxy_conn *alloc_connection_with_hash(
    const struct conn_key *key, hash_sig_t hash, uint32_t *ctl) {
    if (unlikely(!lcore_may_write_table())) {
        static uint64_t non_eal_log = 0;
        if (__atomic_fetch_add(&non_eal_log, 1, __ATOMIC_RELAXED) < 10) {
            RTE_LOG(WARNING, SYNPROXY, "No connection entry from a thread without an lcore id\n");
        }
        return NULL;
    }
    // Table full. A caller that drops the packet counts table_full_drops;
    // a bypassed SYN is still forwarded, only without an entry.
    if (!reserve_entry()) {
        return NULL;
    }
    syn_proxy_race_seam(SYN_PROXY_SEAM_ALLOC);

    struct syn_proxy_conn *conn = NULL;
    uint32_t init = 0;
    for (int attempt = 0; attempt < 2 && !conn; attempt++) {
        int32_t idx = rte_hash_add_key_with_hash(g_conn_hash, key, hash);
        if (idx < 0) {
            break;
        }
        if (unlikely((uint32_t)idx >= g_pool_entries)) {
            // Cannot happen: the pool has rte_hash_max_key_id() entries
            RTE_LOG(ERR, SYNPROXY, "Key position %d outside the connection pool (%u)\n",
                    idx, g_pool_entries);
            break;
        }
        syn_proxy_race_seam(SYN_PROXY_SEAM_CLAIM);

        // Claim the slot. A free slot holds NONE; anything else means the key
        // was in the table already, and its entry belongs to another lcore.
        uint32_t c = ctl_load(&g_conn_pool[idx]);
        if (ctl_state(c) != SYN_PROXY_NONE) {
            break;
        }
        int32_t mapped = rte_hash_lookup_with_hash(g_conn_hash, key, hash);
        if (mapped == idx) {
            init = (c & CTL_GEN_MASK) | CTL_ST_INIT;
            syn_proxy_race_seam(SYN_PROXY_SEAM_CLAIM_SWAP);
            if (!ctl_cas(&g_conn_pool[idx], &c, init)) {
                break;  // Another lcore claimed it for the same key
            }
            conn = &g_conn_pool[idx];
        } else if (mapped >= 0) {
            break;      // Added again, on another slot, by another lcore
        }
        // Else the entry the add found was retired and its key deleted: add again
    }
    if (!conn) {
        unreserve_entry();
        return NULL;
    }

    // Initialize connection - faster than memset for known structure
    __atomic_store_n(&conn->client_ip, key->client_ip, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->server_ip, key->server_ip, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->client_port, key->client_port, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->server_port, key->server_port, __ATOMIC_RELAXED);

    uint64_t now = rte_get_tsc_cycles();
    conn->created_tsc = now;
    __atomic_store_n(&conn->state_change_tsc, now, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->last_client_tsc, now, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->last_server_tsc, 0, __ATOMIC_RELAXED);
    conn->client_isn = 0;
    // Release: see "Entry control word" (server_isn read seqlock style)
    __atomic_store_n(&conn->server_isn, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&conn->client_next_seq, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->server_next_seq, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->client_next_ack, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->server_next_ack, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->server_snd_nxt, 0, __ATOMIC_RELAXED);
    conn->proxy_isn = 0;
    __atomic_store_n(&conn->seq_delta_c2s, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->seq_delta_s2c, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->packets_c2s, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->packets_s2c, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->bytes_c2s, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&conn->bytes_s2c, 0, __ATOMIC_RELAXED);

    // No client options known yet: the defaults parse_tcp_options_safe() gives
    // a SYN without options, instead of the last occupant's. A valid cookie
    // then sets the MSS, the only option the server SYN carries.
    memset(&conn->client_opts, 0, sizeof(conn->client_opts));
    conn->client_opts.mss = TCP_DEFAULT_MSS;
    conn->client_opts.wscale = 255;  // Not present

    __atomic_add_fetch(&g_stats.connections_created, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_stats.connections_active, 1, __ATOMIC_RELAXED);

    *ctl = init;
    return conn;
}

/**
 * Publish the state of a new entry. The release store makes the fields filled
 * in during CTL_ST_INIT visible with it. Returns the published word.
 */
static inline uint32_t conn_publish(struct syn_proxy_conn *conn, uint32_t init_ctl,
                                    enum syn_proxy_state state) {
    uint32_t c = ctl_with_state(init_ctl, state);
    __atomic_store_n(&conn->ctl, c, __ATOMIC_RELEASE);
    return c;
}

// The counter a retired entry is counted in
enum retire_reason {
    RETIRE_CLOSED = 0,          // Ended by the packet path: connections_closed, unless
                                // CLOSED (counted when its close completed)
    RETIRE_SERVER_TIMEOUT,      // CONNECTING past connect_timeout_ms: server_timeout
    RETIRE_IDLE_TIMEOUT,        // Idle past idle_timeout_sec: connections_timeout
    RETIRE_CLEANUP_CLOSED,      // CLOSING or CLOSED, deleted by the cleanup: none
};

/**
 * Retire an entry: end it with one compare-and-swap from *expected, the word
 * this lcore read, then delete its key and free its slot. Only the lcore whose
 * swap succeeds releases the half-open slot (if the entry was CONNECTING) and
 * counts the entry, and it deletes the key it looked up.
 *
 * @return true if this call retired the entry. false if the word changed
 *         since *expected was read (*expected then holds the current word), or
 *         if the entry is not live, is BUSY or this thread has no lcore id
 *         (*expected unchanged).
 */
static bool retire_entry(struct syn_proxy_conn *conn, const struct conn_key *key,
                         uint32_t *expected, enum retire_reason why) {
    const uint32_t old = *expected;
    if (!ctl_live(old) || (old & CTL_F_BUSY) || unlikely(!lcore_may_write_table())) {
        return false;
    }
    if (!ctl_cas(conn, expected, (old & CTL_GEN_MASK) | CTL_ST_DEAD)) {
        return false;
    }

    // The slot cannot be reused before it is freed below
    int32_t pos = rte_hash_del_key(g_conn_hash, key);
    if (unlikely(pos != (int32_t)(conn - g_conn_pool))) {
        // Cannot happen: only the lcore that marked the entry DEAD deletes its
        // key. The entry stays DEAD and its slot unused, rather than free a
        // slot the hash may still hold.
        RTE_LOG(ERR, SYNPROXY, "Retired entry's key not found (position %d)\n", pos);
        return false;
    }

    if (ctl_state(old) == SYN_PROXY_CONNECTING) {
        half_open_decrement(key->client_ip);
    }
    switch (why) {
        case RETIRE_CLOSED:
            // A CLOSED entry was counted by the swap that completed its close
            if (ctl_state(old) != SYN_PROXY_CLOSED) {
                __atomic_add_fetch(&g_stats.connections_closed, 1, __ATOMIC_RELAXED);
            }
            break;
        case RETIRE_SERVER_TIMEOUT:
            __atomic_add_fetch(&g_stats.server_timeout, 1, __ATOMIC_RELAXED);
            break;
        case RETIRE_IDLE_TIMEOUT:
            __atomic_add_fetch(&g_stats.connections_timeout, 1, __ATOMIC_RELAXED);
            break;
        case RETIRE_CLEANUP_CLOSED:
            break;
    }
    __atomic_sub_fetch(&g_stats.connections_active, 1, __ATOMIC_RELAXED);

    // Free, of the next generation: no swap of an lcore that read the old
    // word can succeed any more
    __atomic_store_n(&conn->ctl, ((old & CTL_GEN_MASK) + CTL_GEN_ONE) | SYN_PROXY_NONE,
                     __ATOMIC_RELEASE);
    (void)rte_hash_free_key_with_position(g_conn_hash, pos);
    unreserve_entry();
    return true;
}

/**
 * Free connection entry: the packet path ends the entry it looked up (RST, the
 * end of a BYPASSED connection, an error path). It tries again while the same
 * entry only changed state or flags, and gives up once another lcore retired
 * it. A BUSY entry is left to the cleanup's timeouts.
 */
static void free_connection(struct syn_proxy_conn *conn, const struct conn_key *key,
                            uint32_t ctl) {
    syn_proxy_race_seam(SYN_PROXY_SEAM_FREE);
    uint32_t expected = ctl;
    for (;;) {
        uint32_t seen = expected;
        if (retire_entry(conn, key, &expected, RETIRE_CLOSED)) {
            return;
        }
        if (expected == seen || !ctl_same_entry(expected, ctl) || !ctl_live(expected)) {
            return;
        }
    }
}

/**
 * The close of a proxied connection, for one segment of an entry in
 * ESTABLISHED or a closing state that the caller has translated and forwards.
 * It decides from the word read at the lookup and changes it by swap, so the
 * client's and the server's segments may meet it on two lcores at once:
 * - a FIN records that its side has sent FIN: CLIENT_FIN or SERVER_FIN, and
 *   CLOSING once both sides have. fin_end (the sequence number after the FIN,
 *   as the receiver numbers it) is stored before the swap that records it;
 * - an ACK of the other side's recorded FIN marks that FIN acknowledged
 *   (CTL_F_CLIENT_FIN_ACKED, CTL_F_SERVER_FIN_ACKED). It carries exactly the
 *   FIN's end: the FIN's sender sends nothing after it, so no acceptable ACK
 *   goes beyond, and one short of it leaves the FIN (or data before it)
 *   unacknowledged;
 * - the segment after which both FINs are acknowledged completes the close:
 *   the entry becomes CLOSED and is counted as closed, once, by the lcore
 *   whose swap makes it CLOSED. Until then data and FINs sent before that
 *   last ACK may still be retransmitted and need translating. CLOSED is a
 *   TIME_WAIT for the proxy: if the last ACK is lost beyond the proxy, the
 *   peer retransmits its FIN, and that FIN and the answer to it are still
 *   translated. The cleanup frees a CLOSED entry once no segment came for
 *   SYN_PROXY_TIME_WAIT_SEC; a new SYN on the 4-tuple frees it at once.
 *   (bypass_segment() frees a BYPASSED entry on the ACK after both FINs:
 *   bypassed packets need no translation.) A connection that ends unseen
 *   ages out in the cleanup: CLOSING after SYN_PROXY_CLOSING_TIMEOUT_SEC
 *   without a segment, the half-closed states after the idle timeout.
 * Nothing changes if the entry was retired since ctl was read, or is BUSY.
 * @return true if this call completed the close
 */
static bool proxied_close_segment(struct syn_proxy_conn *conn, uint32_t ctl,
                                  bool from_server, uint8_t tcp_flags,
                                  uint32_t fin_end, uint32_t ack) {
    const bool fin = (tcp_flags & TCP_FLAG_FIN) != 0;
    const bool acks = (tcp_flags & (TCP_FLAG_ACK | TCP_FLAG_SYN)) == TCP_FLAG_ACK;
    if (fin) {
        __atomic_store_n(from_server ? &conn->server_next_seq : &conn->client_next_seq,
                         fin_end, __ATOMIC_RELAXED);
    }

    uint32_t c = ctl;
    for (;;) {
        const enum syn_proxy_state st = ctl_state(c);
        if (!ctl_same_entry(c, ctl) || (c & CTL_F_BUSY) ||
            (st != SYN_PROXY_ESTABLISHED && st != SYN_PROXY_CLIENT_FIN &&
             st != SYN_PROXY_SERVER_FIN && st != SYN_PROXY_CLOSING)) {
            return false;
        }
        bool client_fin = (st == SYN_PROXY_CLIENT_FIN || st == SYN_PROXY_CLOSING);
        bool server_fin = (st == SYN_PROXY_SERVER_FIN || st == SYN_PROXY_CLOSING);
        uint32_t acked = c & CTL_FIN_ACKED_BOTH;

        // The other side's FIN, recorded and not yet acknowledged. Its end was
        // stored before the swap that recorded it, which this word shows.
        if (acks && from_server && client_fin && !(acked & CTL_F_CLIENT_FIN_ACKED) &&
            ack == __atomic_load_n(&conn->client_next_seq, __ATOMIC_RELAXED)) {
            acked |= CTL_F_CLIENT_FIN_ACKED;
        } else if (acks && !from_server && server_fin && !(acked & CTL_F_SERVER_FIN_ACKED) &&
                   ack == __atomic_load_n(&conn->server_next_seq, __ATOMIC_RELAXED)) {
            acked |= CTL_F_SERVER_FIN_ACKED;
        }
        if (fin) {
            client_fin = client_fin || !from_server;
            server_fin = server_fin || from_server;
        }
        const enum syn_proxy_state next =
            client_fin ? (server_fin ? SYN_PROXY_CLOSING : SYN_PROXY_CLIENT_FIN)
                       : (server_fin ? SYN_PROXY_SERVER_FIN : SYN_PROXY_ESTABLISHED);

        syn_proxy_race_seam(SYN_PROXY_SEAM_CLOSE);
        // Both FINs acknowledged: the close is complete, CLOSED (TIME_WAIT)
        const enum syn_proxy_state to =
            (next == SYN_PROXY_CLOSING && acked == CTL_FIN_ACKED_BOTH) ? SYN_PROXY_CLOSED : next;
        const uint32_t want = (c & ~(CTL_STATE_MASK | CTL_FIN_ACKED_BOTH)) | (uint32_t)to | acked;
        if (want == c) {
            return false;
        }
        if (ctl_cas(conn, &c, want)) {
            if (to == SYN_PROXY_CLOSED) {
                __atomic_add_fetch(&g_stats.connections_closed, 1, __ATOMIC_RELAXED);
                return true;
            }
            return false;
        }
        // c holds the current word: decide again
    }
}

/**
 * One segment of a BYPASSED connection, not an RST (bypassed_rst()): the
 * client's (inbound) or the server's. The packet itself is still forwarded
 * unmodified.
 * - The entry is released when its connection ends: on an RST at the
 *   receiver's next sequence (bypassed_rst()), or on the ACK that follows FINs
 *   from both sides. A connection that ends unseen ages out in
 *   syn_proxy_cleanup_connections() by the idle timeout.
 * - A SYN-flagged segment (the client's SYN, the server's SYN-ACK) starts a
 *   new connection on the same 4-tuple, so it clears the FINs seen for the
 *   previous one.
 * - Handshake check for Stage 8b (syn_proxy_admits_segment()): the server's
 *   SYN-ACK records its ISN while the handshake is not yet acknowledged, and
 *   the client's ACK of that ISN + 1 sets CTL_F_HS_ACKED, as the flow table
 *   sets FLOW_FLAG_HANDSHAKE_ACKED. A blind sender does not know the ISN. The
 *   flag stays for the life of the entry.
 */
static void bypass_segment(struct syn_proxy_conn *conn, const struct conn_key *key,
                           uint32_t ctl, const struct packet_features *features,
                           bool inbound) {
    const uint8_t tcp_flags = features->tcp_flags;

    const bool server_synack = !inbound && (tcp_flags & TCP_FLAG_SYN) && (tcp_flags & TCP_FLAG_ACK);
    const bool client_ack = inbound && (tcp_flags & TCP_FLAG_ACK) && !(tcp_flags & TCP_FLAG_SYN);
    uint32_t c = ctl;

    for (;;) {
        // Retired since the lookup (the slot may hold a new occupant)
        if (!ctl_same_entry(c, ctl) || ctl_state(c) != SYN_PROXY_BYPASSED) {
            return;
        }

        uint32_t want = c;
        if (tcp_flags & TCP_FLAG_SYN) {
            want &= ~CTL_FIN_BOTH;
        } else if (tcp_flags & TCP_FLAG_FIN) {
            want |= inbound ? CTL_F_FIN_CLIENT : CTL_F_FIN_SERVER;
        } else if ((tcp_flags & TCP_FLAG_ACK) && (c & CTL_FIN_BOTH) == CTL_FIN_BOTH) {
            // The ACK after both FINs. A BUSY entry is left to the idle timeout.
            uint32_t seen = c;
            if (retire_entry(conn, key, &c, RETIRE_CLOSED) || c == seen) {
                return;
            }
            continue;  // The word changed: decide again
        }

        // Acquire: server_isn is checked against the word by the swap below
        // (see "Entry control word")
        if (client_ack && (c & (CTL_F_ISN_SEEN | CTL_F_HS_ACKED | CTL_F_BUSY)) == CTL_F_ISN_SEEN &&
            features->tcp_ack == __atomic_load_n(&conn->server_isn, __ATOMIC_ACQUIRE) + 1) {
            want |= CTL_F_HS_ACKED;
        }

        // Recording the ISN: claim server_isn (BUSY) before writing it
        const bool record = server_synack && !(c & (CTL_F_HS_ACKED | CTL_F_BUSY));
        if (record) {
            want |= CTL_F_BUSY;
        }

        if (want == c) {
            return;
        }
        if (ctl_cas(conn, &c, want)) {
            if (record) {
                __atomic_store_n(&conn->server_isn, features->tcp_seq, __ATOMIC_RELEASE);
                // Nobody retires a BUSY entry; other lcores may change its FIN
                // flags meanwhile. The release publishes server_isn.
                uint32_t cur = want;
                while (!ctl_cas(conn, &cur, (cur & ~CTL_F_BUSY) | CTL_F_ISN_SEEN)) {
                }
            }
            return;
        }
        // c holds the current word: decide again
    }
}

/**
 * Whether bypass_segment() can change the entry for this segment: its first
 * pass decides from the same word and flags. Most segments of a BYPASSED
 * connection (data and ACKs once its handshake is acknowledged) cannot, and
 * testing that here spares them the call, which is measurably slower when
 * the entry is not in cache.
 */
static inline bool bypass_segment_matters(uint32_t ctl, uint8_t tcp_flags, bool inbound) {
    if (tcp_flags & (TCP_FLAG_RST | TCP_FLAG_SYN | TCP_FLAG_FIN)) {
        return true;
    }
    if (!(tcp_flags & TCP_FLAG_ACK)) {
        return false;
    }
    return (ctl & CTL_FIN_BOTH) == CTL_FIN_BOTH ||
           (inbound && (ctl & (CTL_F_ISN_SEEN | CTL_F_HS_ACKED)) == CTL_F_ISN_SEEN);
}

// ==================== RST Validation ====================
//
// An RST ends the entry of its 4-tuple only when it is at the receiver's next
// expected sequence number, the rule a TCP receiver applies (RFC 5961, 3.2).
// Before, any RST ended it, so a sender that knew the 4-tuple but none of the
// connection's numbers made the proxy forget the connection, and the rest of
// a proxied connection went out untranslated. For an RST:
// - at the receiver's next sequence (exact): the entry ends, and the RST is
//   forwarded, translated if the connection is proxied;
// - in the receiver's window but not exact: the entry stays, and the RST is
//   forwarded all the same, so that the receiving stack can answer it with
//   its own challenge ACK (RFC 5961). A sender that did reset answers that
//   ACK with an RST at the acknowledged number, which then ends the entry.
//   The proxy sends no challenge ACK of its own;
// - outside every window the receiver can have: dropped, the entry stays.
// The receiver's next sequence is the last acknowledgement it sent
// (client_next_ack, server_next_ack). For an RST from the client side, which
// a blind sender imitates, that is the server's acknowledgement, which comes
// from the protected side. An RST from the server side is always forwarded
// (its window is judged against the client's acknowledgements, which a blind
// sender can forge) and ends the entry only when exact.
//
// Windows: a proxied connection never scales its windows (the proxy's SYN-ACK
// and its SYN to the server offer MSS only), so none exceeds 65535 bytes; a
// bypassed one may scale them, up to 2^30 bytes (RFC 7323). While the proxy
// waits on the server (CONNECTING) it is the client's peer itself, with next
// sequence client_isn + 1 and the 65535-byte window of its SYN-ACK, and it
// ignores (drops) an RST that is not exact. Toward the server it is then in
// SYN-SENT, where an RST counts only if it acknowledges the proxy's SYN
// (RFC 9293, 3.10.7.3).
//
// What remains: a sender that resets with data still unacknowledged sends its
// RST at its own next sequence, past the receiver's last ACK. That RST is
// forwarded, and the entry stays until the receiver's next segment draws an
// exact RST, or until the idle timeout, as for a connection that ends unseen.

#define PROXIED_MAX_WINDOW   65535u          // No window scaling on a proxied connection
#define BYPASSED_MAX_WINDOW  (1u << 30)      // The largest scaled window (RFC 7323)

enum rst_verdict {
    RST_EXACT = 0,      // At the receiver's next sequence: the connection ends
    RST_IN_WINDOW,      // In the receiver's window, or not judged: forwarded, the entry stays
    RST_OUT_OF_WINDOW,  // Outside every window the receiver can have: dropped, the entry stays
};

// An RST's sequence number against the receiver's next expected one. A
// sender that has filled the receiver's window before the receiver
// acknowledged any of it is a full window past the last ACK, and its RST
// there is exact for a receiver that got every byte: in the window, up to
// and including max_window past it.
static inline enum rst_verdict rst_check_seq(uint32_t seq, uint32_t rcv_nxt, uint32_t max_window) {
    const uint32_t d = seq - rcv_nxt;
    if (d == 0) {
        return RST_EXACT;
    }
    return d <= max_window ? RST_IN_WINDOW : RST_OUT_OF_WINDOW;
}

// The latest acknowledgement of a side (client_next_ack, server_next_ack):
// written for every segment with ACK but not RST, whose numbers are checked,
// never trusted
static inline void track_ack(uint32_t *next_ack, uint8_t tcp_flags, uint32_t ack) {
    if ((tcp_flags & (TCP_FLAG_ACK | TCP_FLAG_RST)) == TCP_FLAG_ACK) {
        __atomic_store_n(next_ack, ack, __ATOMIC_RELAXED);
    }
}

// The server's next sequence (server_snd_nxt): the end of the latest segment
// it sent that occupies sequence space (data, SYN or FIN), in its own
// numbering. Only the protected side's segments move it. A segment that
// occupies none (a pure ACK, a keepalive probe without data, one sequence
// number below the next) and an RST move nothing. It is only stored here,
// never read: a read would wait for the entry's second cache line on every
// server segment of a cold entry, which the bypassed path otherwise only
// writes. So a retransmission moves it back until the server's next new
// segment, and an abort sent right after a retransmission is not exact: it
// is forwarded, and the entry stays until an exact RST or the idle timeout.
static inline void track_server_snd_nxt(struct syn_proxy_conn *conn, uint8_t tcp_flags,
                                        uint32_t seq, uint32_t payload_len) {
    const uint32_t len = payload_len + ((tcp_flags & TCP_FLAG_SYN) ? 1u : 0u) +
                         ((tcp_flags & TCP_FLAG_FIN) ? 1u : 0u);
    if (len == 0 || (tcp_flags & TCP_FLAG_RST)) {
        return;
    }
    __atomic_store_n(&conn->server_snd_nxt, seq + len, __ATOMIC_RELAXED);
}

/**
 * An RST of a proxied entry (ESTABLISHED, a closing state or CLOSED). seq is
 * in its sender's numbering. From the server it is never out of window (see
 * above), and it is also exact at the server's own next sequence: a stack
 * that aborts sends its RST there, and only the protected side moves that
 * number. A side that has acknowledged nothing (0) cannot be judged.
 */
static inline enum rst_verdict proxied_rst(const struct syn_proxy_conn *conn, bool from_server,
                                           uint32_t seq) {
    if (from_server) {
        const uint32_t snd = __atomic_load_n(&conn->server_snd_nxt, __ATOMIC_RELAXED);
        const uint32_t rcv = __atomic_load_n(&conn->client_next_ack, __ATOMIC_RELAXED);
        const uint32_t seq_c = seq + (uint32_t)__atomic_load_n(&conn->seq_delta_s2c, __ATOMIC_RELAXED);
        return ((snd != 0 && seq == snd) || (rcv != 0 && seq_c == rcv)) ? RST_EXACT : RST_IN_WINDOW;
    }
    const uint32_t rcv = __atomic_load_n(&conn->server_next_ack, __ATOMIC_RELAXED);
    const uint32_t seq_s = seq + (uint32_t)__atomic_load_n(&conn->seq_delta_c2s, __ATOMIC_RELAXED);
    return rcv != 0 ? rst_check_seq(seq_s, rcv, PROXIED_MAX_WINDOW) : RST_IN_WINDOW;
}

/**
 * An RST of a BYPASSED entry, numbered end to end. Before the receiver has
 * acknowledged anything its next sequence follows from the SYN that created
 * the entry: the server's is client_isn + 1, and the client (in SYN-SENT)
 * takes only an RST that acknowledges its SYN.
 */
static inline enum rst_verdict bypassed_rst_verdict(const struct syn_proxy_conn *conn,
                                                    const struct packet_features *features,
                                                    bool inbound) {
    const uint32_t isn = __atomic_load_n(&conn->client_isn, __ATOMIC_RELAXED);
    if (!inbound) {
        const uint32_t snd = __atomic_load_n(&conn->server_snd_nxt, __ATOMIC_RELAXED);
        const uint32_t rcv = __atomic_load_n(&conn->client_next_ack, __ATOMIC_RELAXED);
        if ((snd != 0 && features->tcp_seq == snd) || (rcv != 0 && features->tcp_seq == rcv)) {
            return RST_EXACT;
        }
        return (rcv == 0 && (features->tcp_flags & TCP_FLAG_ACK) && features->tcp_ack == isn + 1) ?
               RST_EXACT : RST_IN_WINDOW;
    }
    const uint32_t rcv = __atomic_load_n(&conn->server_next_ack, __ATOMIC_RELAXED);
    if (rcv != 0) {
        return rst_check_seq(features->tcp_seq, rcv, BYPASSED_MAX_WINDOW);
    }
    return features->tcp_seq == isn + 1 ? RST_EXACT : RST_IN_WINDOW;
}

// An RST the proxy drops: from the client side and outside its receiver's
// window, or not exact while the proxy waits on the server. Stage 9 counts
// it as spoofed TCP. The entry stays.
static inline void drop_rst(struct syn_proxy_result *result) {
    result->action = SYN_PROXY_DROP;
    result->packet_modified = false;
    result->drop_reason = DROP_REASON_SPOOFED_TCP;
    __atomic_add_fetch(&g_stats.rst_dropped, 1, __ATOMIC_RELAXED);
}

/**
 * An RST of a BYPASSED entry, forwarded unmodified unless the caller drops it
 * (RST_OUT_OF_WINDOW from the client side). An exact one ends the entry; for
 * RST_IN_WINDOW the caller marks the result (forward_rst_unconfirmed()).
 */
static enum rst_verdict bypassed_rst(struct syn_proxy_conn *conn, const struct conn_key *key,
                                     uint32_t ctl, const struct packet_features *features,
                                     bool inbound) {
    const enum rst_verdict v = bypassed_rst_verdict(conn, features, inbound);
    if (v == RST_EXACT) {
        free_connection(conn, key, ctl);
    }
    return v;
}

// An RST forwarded without ending its entry
static inline void forward_rst_unconfirmed(struct syn_proxy_result *result) {
    result->rst_unconfirmed = true;
    __atomic_add_fetch(&g_stats.rst_unconfirmed, 1, __ATOMIC_RELAXED);
}

// ==================== Packet Generation ====================

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
    // No other option can be honoured on the server leg (see create_synack_to_client)
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
 *
 * The SYN-ACK offers MSS only, like the in-place one. The proxy opens the
 * server leg later from the cookie, which holds only an MSS index, so its SYN
 * to the server offers MSS only too, and both legs agree on every option. On
 * a proxied connection the proxy rewrites only seq and ack, so it could not
 * honour on the server leg what the other options would grant the client:
 * - window scaling: window fields pass unscaled, so a shift granted to the
 *   client would multiply every window the server sends;
 * - timestamps: TSval and TSecr pass untranslated, while the SYN-ACK's TSval
 *   came from the proxy's clock;
 * - SACK: SACK blocks carry sequence numbers, which are not translated.
 * This is the classic SYN-cookie limitation. Only challenged connections pay
 * it: under normal load a SYN bypasses the proxy, and the endpoints negotiate
 * their options end to end.
 */
static struct rte_mbuf *create_synack_to_client(
    struct rte_mempool *mempool,
    const struct packet_features *orig_features,
    const struct rte_ether_hdr *orig_eth,
    uint32_t cookie,
    uint16_t port_id) {

    struct rte_mbuf *m = rte_pktmbuf_alloc(mempool);
    if (unlikely(!m)) {
        return NULL;
    }

    // TCP options: MSS only (see above), a 4-byte multiple
    const uint16_t opts_len = 4;

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
 * Built from the caller's values, not from the entry: once the entry is
 * published another lcore may retire it and its slot be reused.
 */
static struct rte_mbuf *create_syn_to_server(
    struct rte_mempool *mempool,
    const struct conn_key *key,
    uint32_t proxy_isn,
    uint16_t mss,
    const struct rte_ether_hdr *orig_eth,
    uint16_t port_id) {

    struct rte_mbuf *m = rte_pktmbuf_alloc(mempool);
    if (unlikely(!m)) {
        return NULL;
    }

    // The cookie keeps only the client's MSS, so this SYN offers MSS only:
    // exactly what the SYN-ACK to the client offered (see
    // create_synack_to_client). A 4-byte multiple, no padding.
    const uint16_t opts_len = 4;

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
    ip->src_addr = key->client_ip;
    ip->dst_addr = key->server_ip;

    // TCP header - NO memset
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(key->client_port);
    tcp->dst_port = rte_cpu_to_be_16(key->server_port);
    tcp->sent_seq = rte_cpu_to_be_32(proxy_isn);
    tcp->recv_ack = 0;
    tcp->data_off = (tcp_hdr_len / 4) << 4;
    tcp->tcp_flags = TCP_FLAG_SYN;
    tcp->rx_win = rte_cpu_to_be_16(65535);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    // Build options directly in packet: MSS
    uint8_t *opt_ptr = (uint8_t *)tcp + 20;
    *opt_ptr++ = 2;
    *opt_ptr++ = 4;
    *(uint16_t *)opt_ptr = rte_cpu_to_be_16(mss);

    // Checksum
    // prepare_tx_checksum_offload_safe already computes software checksums.
    // No fallback needed -- it either computed software or configured hardware offload.
    prepare_tx_checksum_offload(m, ip, tcp, port_id);

    return m;
}

/**
 * Create ACK packet to send to server (completes handshake) - OPTIMIZED
 * No memset, fast packet ID, direct data_len
 * Built from the caller's values, like create_syn_to_server()
 */
static struct rte_mbuf *create_ack_to_server(
    struct rte_mempool *mempool,
    const struct conn_key *key,
    uint32_t proxy_isn,
    uint32_t server_isn,
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
    ip->src_addr = key->client_ip;
    ip->dst_addr = key->server_ip;

    // TCP header - NO memset
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(key->client_port);
    tcp->dst_port = rte_cpu_to_be_16(key->server_port);
    tcp->sent_seq = rte_cpu_to_be_32(proxy_isn + 1);
    tcp->recv_ack = rte_cpu_to_be_32(server_isn + 1);
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

// A per-connection counter. Only the lcore that handles the direction adds to
// it, so a relaxed load and store suffice (no locked add); they are atomic
// because an lcore holding a retired entry may still add to the slot's next
// occupant (see "Entry control word").
static inline void conn_counter_add(uint64_t *counter, uint64_t n) {
    __atomic_store_n(counter, __atomic_load_n(counter, __ATOMIC_RELAXED) + n, __ATOMIC_RELAXED);
}

// Payload bytes of a TCP segment by its IP total length; 0 if the headers
// claim more than that
static inline uint32_t tcp_payload_len(const struct rte_ipv4_hdr *ip, const struct rte_tcp_hdr *tcp) {
    const uint32_t total = rte_be_to_cpu_16(ip->total_length);
    const uint32_t headers = (uint32_t)(ip->version_ihl & 0x0F) * 4 + (uint32_t)(tcp->data_off >> 4) * 4;
    return total > headers ? total - headers : 0;
}

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
    uint32_t server_seq = client_seq + __atomic_load_n(&conn->seq_delta_c2s, __ATOMIC_RELAXED);
    tcp->sent_seq = rte_cpu_to_be_32(server_seq);
    
    // Client's ack (based on cookie_isn) becomes server ack (based on server_isn)
    // client acks Y (relative to cookie_isn), server expects Y - (cookie_isn - server_isn)
    if (tcp->tcp_flags & TCP_FLAG_ACK) {
        uint32_t client_ack = rte_be_to_cpu_32(tcp->recv_ack);
        track_ack(&conn->client_next_ack, tcp->tcp_flags, client_ack);
        uint32_t server_ack = client_ack - __atomic_load_n(&conn->seq_delta_s2c, __ATOMIC_RELAXED);  // FIXED: minus not plus
        tcp->recv_ack = rte_cpu_to_be_32(server_ack);
    }
    
    // Recalculate TCP checksum
    uint16_t tcp_len = rte_be_to_cpu_16(ip->total_length) - 
                       ((ip->version_ihl & 0x0F) * 4);
    tcp->cksum = 0;
    tcp->cksum = calc_tcp_checksum(ip, tcp, tcp_len);
    
    conn_counter_add(&conn->packets_c2s, 1);
    conn_counter_add(&conn->bytes_c2s, rte_pktmbuf_pkt_len(m));
    __atomic_store_n(&conn->last_client_tsc, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
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
    track_server_snd_nxt(conn, tcp->tcp_flags, server_seq, tcp_payload_len(ip, tcp));
    uint32_t client_seq = server_seq + __atomic_load_n(&conn->seq_delta_s2c, __ATOMIC_RELAXED);  // FIXED: plus not minus
    tcp->sent_seq = rte_cpu_to_be_32(client_seq);
    
    // Server's ack (based on proxy_isn) becomes client ack (based on client_isn)
    // server acks Y (relative to proxy_isn), client expects Y - (proxy_isn - client_isn)
    if (tcp->tcp_flags & TCP_FLAG_ACK) {
        uint32_t server_ack = rte_be_to_cpu_32(tcp->recv_ack);
        track_ack(&conn->server_next_ack, tcp->tcp_flags, server_ack);
        uint32_t client_ack = server_ack - __atomic_load_n(&conn->seq_delta_c2s, __ATOMIC_RELAXED);  // This was correct
        tcp->recv_ack = rte_cpu_to_be_32(client_ack);
    }
    
    // Recalculate TCP checksum
    uint16_t tcp_len = rte_be_to_cpu_16(ip->total_length) - 
                       ((ip->version_ihl & 0x0F) * 4);
    tcp->cksum = 0;
    tcp->cksum = calc_tcp_checksum(ip, tcp, tcp_len);
    
    conn_counter_add(&conn->packets_s2c, 1);
    conn_counter_add(&conn->bytes_s2c, rte_pktmbuf_pkt_len(m));
    __atomic_store_n(&conn->last_server_tsc, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
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
    
    // Create connection hash table - OPTIMIZED with TRANS_MEM support.
    // Every lcore adds keys (rte_eal_mp_remote_launch with CALL_MAIN), and
    // without MULTI_WRITER_ADD rte_hash takes a key slot after releasing its
    // writer lock with a single-consumer dequeue: two lcores could get the
    // same slot. NO_FREE_ON_DEL: retire_entry() frees a deleted key's slot
    // once the entry is marked free (see "Entry control word").
    struct rte_hash_parameters hash_params = {
        .name = "syn_proxy_hash",
        .entries = config->max_connections,
        .key_len = sizeof(struct conn_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                      RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT |  // Added for better concurrency
                      RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD |
                      RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL,
    };

    g_conn_hash = rte_hash_create(&hash_params);
    if (!g_conn_hash) {
        RTE_LOG(ERR, SYNPROXY, "Failed to create hash table\n");
        return -1;
    }
    
    // Allocate connection pool: one entry per key position the hash can
    // return. With MULTI_WRITER_ADD these run past max_connections, by the
    // free slots the per-lcore caches can hold.
    int32_t max_key_id = rte_hash_max_key_id(g_conn_hash);
    g_pool_entries = max_key_id > 0 ? (uint32_t)max_key_id : 0;
    g_conn_pool = g_pool_entries ?
                  rte_zmalloc("syn_proxy_conns",
                              (size_t)g_pool_entries * sizeof(struct syn_proxy_conn),
                              RTE_CACHE_LINE_SIZE) : NULL;
    if (!g_conn_pool) {
        RTE_LOG(ERR, SYNPROXY, "Failed to allocate connection pool\n");
        rte_hash_free(g_conn_hash);
        g_conn_hash = NULL;
        g_pool_entries = 0;
        return -1;
    }
    g_entries_used = 0;
    g_cleanup_iter = 0;
    
    // Initialize secrets
    g_current_secret = config->secret;
    g_previous_secret = config->secret;
    g_last_rotation_tsc = rte_get_tsc_cycles();

    // Initialize SipHash key from DPDK random source
    g_siphash_key[0] = rte_rand();
    g_siphash_key[1] = rte_rand();

    memset(&g_stats, 0, sizeof(g_stats));
    // Half-open counts from a previous init would outlive their connections
    half_open_reset();
    g_initialized = true;

    // Cache TX checksum offload capabilities (avoid per-packet function calls)
    cache_offload_capabilities();

    // Initialize adaptive mode state
    g_tsc_hz = rte_get_tsc_hz();
    // Cache divisor for cookie timestamps (avoid rte_get_tsc_hz() in hot path)
    g_tsc_32sec_divisor = g_tsc_hz * 32;        // For cookie timestamps (32-sec granularity)
    g_current_mode = SYN_PROXY_MODE_STATEFUL;  // Start in stateful mode
    g_forced_mode = -1;  // Adaptive by default
    __atomic_store_n(&g_last_mode_switch_tsc, rte_rdtsc(), __ATOMIC_RELAXED);
    g_adaptive_window_start_tsc = rte_rdtsc();
    g_adaptive_syn_count = 0;
    g_current_syn_rate_pps = 0;
    g_consecutive_above_threshold = 0;
    g_consecutive_below_threshold = 0;

    // Rate windows start afresh: counts from a previous init describe its
    // traffic, and would otherwise challenge or rate-limit this one's
    g_syn_count_current = 0;
    g_syn_count_previous = 0;
    g_syn_window_start_tsc = rte_get_tsc_cycles();
    g_synack_count_current = 0;
    g_synack_window_start_tsc = syn_proxy_synack_clock();

    // Calculate mode switch delay in TSC cycles
    uint32_t delay_ms = config->mode_switch_delay_ms ?
                        config->mode_switch_delay_ms :
                        DEFAULT_MODE_SWITCH_DELAY_MS;
    g_mode_switch_delay_tsc = (g_tsc_hz * delay_ms) / 1000;

    // Set challenge threshold from config (syn_cookie.challenge_threshold);
    // 0 selects the default, never the previous init's threshold
    g_challenge_threshold = config->challenge_threshold ?
                            config->challenge_threshold :
                            DEFAULT_CHALLENGE_THRESHOLD;

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
    g_pool_entries = 0;
    g_entries_used = 0;
    g_cleanup_iter = 0;
    
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
    hash_sig_t key_hash = compute_conn_hash(&key);
    
    // The entry and its control word, read once: each change below is a
    // compare-and-swap against this word (see "Entry control word")
    uint32_t ctl = 0;
    struct syn_proxy_conn *conn = find_connection_with_hash(&key, key_hash, &ctl);
    // The state acted on. A proxied entry whose owner is still writing its
    // sequence deltas (BUSY) is handled as CONNECTING.
    enum syn_proxy_state state = conn ? ctl_state(ctl) : SYN_PROXY_NONE;
    if (state == SYN_PROXY_ESTABLISHED && (ctl & CTL_F_BUSY)) {
        state = SYN_PROXY_CONNECTING;
    }
    
    // ========== INBOUND (Client -> Server) ==========
    if (direction == DIRECTION_INBOUND) {
        uint8_t tcp_flags = features->tcp_flags;

        // Handle bypassed connections first - forward all packets without modification
        // These are connections that were allowed through without SYN cookie challenge
        if (state == SYN_PROXY_BYPASSED) {
            __atomic_store_n(&conn->last_client_tsc, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
            result->action = SYN_PROXY_FORWARD;
            result->packet_modified = false;
            result->conn_state = SYN_PROXY_BYPASSED;
            if (unlikely(tcp_flags & TCP_FLAG_RST)) {
                // Ends the entry only at the server's next sequence (see "RST validation")
                const enum rst_verdict v = bypassed_rst(conn, &key, ctl, features, true);
                if (v == RST_OUT_OF_WINDOW) {
                    drop_rst(result);
                } else if (v == RST_IN_WINDOW) {
                    forward_rst_unconfirmed(result);
                }
                return 0;
            }
            // A SYN on the 4-tuple (a new connection, or a blind sender's)
            // changes none of the numbers an RST is checked against: those
            // follow what the receiver acknowledges, so a sender cannot pick
            // the ISN its RST then matches
            track_ack(&conn->client_next_ack, tcp_flags, features->tcp_ack);
            if (bypass_segment_matters(ctl, tcp_flags, true)) {
                bypass_segment(conn, &key, ctl, features, true);
            }
            return 0;
        }

        // ----- Pure SYN Packet -----
        if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
            // If connection exists in CONNECTING or later, this is a retransmit
            if (conn && state != SYN_PROXY_CLOSED) {
                // Client retransmitting SYN - ignore, we've already validated
                result->action = SYN_PROXY_DROP;
                return 0;
            }
            if (conn) {
                // A new connection on the 4-tuple of one whose close is
                // complete (CLOSED, the proxy's TIME_WAIT): the old entry
                // gives way, and the SYN is handled as the first of a new
                // connection. (A CLOSING entry keeps its 4-tuple: its last
                // segments may still need translating.)
                free_connection(conn, &key, ctl);
                conn = NULL;
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
                uint32_t init_ctl;
                struct syn_proxy_conn *bypass_conn =
                    alloc_connection_with_hash(&key, key_hash, &init_ctl);
                if (bypass_conn) {
                    // The SYN's ISN: the client's next sequence until the
                    // server acknowledges (see "RST validation")
                    __atomic_store_n(&bypass_conn->client_isn, features->tcp_seq, __ATOMIC_RELAXED);
                    conn_publish(bypass_conn, init_ctl, SYN_PROXY_BYPASSED);
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

                // Full options parsing: the cookie keeps the client's MSS
                struct tcp_syn_options client_opts;
                parse_tcp_options(tcp, &client_opts);

                uint32_t cookie = generate_cookie(features->src_ip, features->dst_ip,
                                                  features->src_port, features->dst_port,
                                                  client_opts.mss);

                // Create SYN-ACK to client (allocates new mbuf)
                result->reply_pkt = create_synack_to_client(mempool, features, eth,
                                                            cookie, port_id);
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
        
        // RST and FIN of a proxied connection come before the ACK branch, as
        // in the outbound path: after the handshake the client's FIN carries
        // ACK, and so does a typical RST, and the ACK branch would forward
        // them without ending the entry. A segment with ACK on an ESTABLISHED
        // entry still counts in packets_proxied_c2s, as in the ACK branch.

        // ----- RST of a proxied connection, whatever other flags -----
        // It ends the entry only at the receiver's next sequence (see "RST
        // validation")
        if (conn && (tcp_flags & TCP_FLAG_RST)) {
            if (state >= SYN_PROXY_ESTABLISHED) {
                const enum rst_verdict v = proxied_rst(conn, false, features->tcp_seq);
                if (v == RST_OUT_OF_WINDOW) {
                    drop_rst(result);
                    return 0;
                }
                translate_c2s(m, ip, tcp, conn);
                result->action = SYN_PROXY_FORWARD;
                result->packet_modified = true;
                result->conn_state = state;
                if ((tcp_flags & TCP_FLAG_ACK) && state == SYN_PROXY_ESTABLISHED) {
                    __atomic_add_fetch(&g_stats.packets_proxied_c2s, 1, __ATOMIC_RELAXED);
                }
                if (v == RST_EXACT) {
                    free_connection(conn, &key, ctl);
                } else {
                    forward_rst_unconfirmed(result);
                }
            } else if (rst_check_seq(features->tcp_seq, conn->client_isn + 1,
                                     PROXIED_MAX_WINDOW) == RST_EXACT) {
                // Waiting on the server: the proxy is the client's peer
                result->action = SYN_PROXY_BYPASS;  // Not translated
                free_connection(conn, &key, ctl);
            } else {
                drop_rst(result);
            }
            return 0;
        }

        // ----- FIN of an established proxied connection, whatever other flags -----
        if (state >= SYN_PROXY_ESTABLISHED && (tcp_flags & TCP_FLAG_FIN)) {
            translate_c2s(m, ip, tcp, conn);
            result->action = SYN_PROXY_FORWARD;
            result->packet_modified = true;
            result->conn_state = state;
            if ((tcp_flags & TCP_FLAG_ACK) && state == SYN_PROXY_ESTABLISHED) {
                __atomic_add_fetch(&g_stats.packets_proxied_c2s, 1, __ATOMIC_RELAXED);
            }
            proxied_close_segment(conn, ctl, false, tcp_flags,
                                  rte_be_to_cpu_32(tcp->sent_seq) + tcp_payload_len(ip, tcp) + 1,
                                  features->tcp_ack);
            return 0;
        }

        // ----- ACK Packet (with or without data) -----
        if (tcp_flags & TCP_FLAG_ACK) {
            // Established connection - translate and forward
            if (state == SYN_PROXY_ESTABLISHED) {
                translate_c2s(m, ip, tcp, conn);
                result->action = SYN_PROXY_FORWARD;
                result->packet_modified = true;
                result->conn_state = state;
                __atomic_add_fetch(&g_stats.packets_proxied_c2s, 1, __ATOMIC_RELAXED);
                return 0;
            }

            // Connection waiting for server - drop client packets (they'll retransmit)
            if (state == SYN_PROXY_CONNECTING) {
                result->action = SYN_PROXY_DROP;
                result->conn_state = state;
                return 0;
            }

            // Closing states - translate and forward. The client's ACK of the
            // server's FIN may complete the close (CLOSED). In CLOSED the
            // answer to a retransmitted FIN is translated too.
            if (state == SYN_PROXY_CLIENT_FIN ||
                state == SYN_PROXY_SERVER_FIN ||
                state == SYN_PROXY_CLOSING ||
                state == SYN_PROXY_CLOSED) {
                translate_c2s(m, ip, tcp, conn);
                result->action = SYN_PROXY_FORWARD;
                result->packet_modified = true;
                result->conn_state = state;
                proxied_close_segment(conn, ctl, false, tcp_flags, 0, features->tcp_ack);
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

                // The source has shown it completes handshakes: it is marked
                // in the legitimate-source table (bounded, expiring). Nothing
                // decides on the mark: its next SYNs are challenged like any
                // other source's (see syn_proxy_should_challenge()). Not the
                // whitelist either: its packets still run every stage, and
                // this connection's still reach Stage 9 for translation.
                legitimate_ip_add(features->src_ip);

                uint32_t init_ctl;
                conn = alloc_connection_with_hash(&key, key_hash, &init_ctl);
                if (!conn) {
                    half_open_decrement(features->src_ip);
                    result->action = SYN_PROXY_DROP;
                    __atomic_add_fetch(&g_stats.table_full_drops, 1, __ATOMIC_RELAXED);
                    return 0;
                }
                
                // Store sequence numbers
                conn->client_isn = features->tcp_seq - 1;
                conn->cookie_isn = features->tcp_ack - 1;
                // The client's handshake ACK: its next expected sequence
                __atomic_store_n(&conn->client_next_ack, features->tcp_ack, __ATOMIC_RELAXED);
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
                const uint32_t proxy_isn = conn->proxy_isn;
                
                conn->client_opts.mss = recovered_mss;
                __atomic_store_n(&conn->state_change_tsc, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
                uint32_t connecting = conn_publish(conn, init_ctl, SYN_PROXY_CONNECTING);
                
                // Send SYN to server
                result->reply_pkt = create_syn_to_server(mempool, &key, proxy_isn,
                                                         recovered_mss, eth, port_id);
                if (!result->reply_pkt) {
                    free_connection(conn, &key, connecting);
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
        
        // ----- FIN Packet (no ACK): no connection, or one waiting on the server -----
        // (An established proxied connection's FIN was handled above.)
        if (tcp_flags & TCP_FLAG_FIN) {
            result->action = SYN_PROXY_BYPASS;
            return 0;
        }
        
        // ----- RST Packet (no ACK) of no connection -----
        // (A proxied connection's RST was handled above.)
        if (tcp_flags & TCP_FLAG_RST) {
            result->action = SYN_PROXY_BYPASS;
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
        if (state == SYN_PROXY_BYPASSED) {
            __atomic_store_n(&conn->last_server_tsc, rte_get_tsc_cycles(), __ATOMIC_RELAXED);
            result->action = SYN_PROXY_FORWARD;
            result->packet_modified = false;
            result->conn_state = SYN_PROXY_BYPASSED;
            if (unlikely(features->tcp_flags & TCP_FLAG_RST)) {
                // Always forwarded; ends the entry only at the client's next
                // sequence (see "RST validation")
                if (bypassed_rst(conn, &key, ctl, features, false) != RST_EXACT) {
                    forward_rst_unconfirmed(result);
                }
                return 0;
            }
            // The parser's payload length: the packet itself is not read here
            track_ack(&conn->server_next_ack, features->tcp_flags, features->tcp_ack);
            track_server_snd_nxt(conn, features->tcp_flags, features->tcp_seq,
                                 features->payload_len);
            if (bypass_segment_matters(ctl, features->tcp_flags, false)) {
                bypass_segment(conn, &key, ctl, features, false);
            }
            return 0;
        }

        uint8_t tcp_flags = features->tcp_flags;
        
        // ----- SYN-ACK from Server -----
        if ((tcp_flags & TCP_FLAG_SYN) && (tcp_flags & TCP_FLAG_ACK)) {
            
            // (A BUSY entry is ESTABLISHED already: another copy of this SYN-ACK)
            if (ctl_state(ctl) != SYN_PROXY_CONNECTING) {
                result->action = SYN_PROXY_DROP;
                return 0;
            }
            
            // End CONNECTING. The cleanup's connect timeout, an RST and an
            // error path end it with the same kind of swap, and so does a copy
            // of this SYN-ACK on another lcore: only the one that succeeds
            // releases the half-open slot. BUSY until the deltas are written.
            syn_proxy_race_seam(SYN_PROXY_SEAM_SYNACK);
            uint32_t busy = ctl_with_state(ctl, SYN_PROXY_ESTABLISHED) | CTL_F_BUSY;
            if (!ctl_cas(conn, &ctl, busy)) {
                result->action = SYN_PROXY_DROP;
                return 0;
            }
            half_open_decrement(key.client_ip);

            // Record server's ISN (release: see "Entry control word")
            const uint32_t server_isn = features->tcp_seq;
            const uint32_t proxy_isn = conn->proxy_isn;
            __atomic_store_n(&conn->server_isn, server_isn, __ATOMIC_RELEASE);
            
            // Calculate sequence deltas
            __atomic_store_n(&conn->seq_delta_c2s, (int32_t)(proxy_isn - conn->client_isn),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&conn->seq_delta_s2c, (int32_t)(conn->cookie_isn - server_isn),
                             __ATOMIC_RELAXED);
            // The SYN-ACK's ACK and the end of its SYN: the server's next
            // expected sequence and its own next sequence
            __atomic_store_n(&conn->server_next_ack, features->tcp_ack, __ATOMIC_RELAXED);
            __atomic_store_n(&conn->server_snd_nxt, server_isn + 1, __ATOMIC_RELAXED);

            uint64_t now = rte_get_tsc_cycles();
            __atomic_store_n(&conn->state_change_tsc, now, __ATOMIC_RELAXED);
            __atomic_store_n(&conn->last_server_tsc, now, __ATOMIC_RELAXED);

            // Publish ESTABLISHED with the deltas. Nobody else changes a BUSY
            // proxied entry, so a release store suffices.
            uint32_t established = busy & ~CTL_F_BUSY;
            __atomic_store_n(&conn->ctl, established, __ATOMIC_RELEASE);
            
            __atomic_add_fetch(&g_stats.connections_established, 1, __ATOMIC_RELAXED);
            
            // Send ACK to server
            result->reply_pkt = create_ack_to_server(mempool, &key, proxy_isn, server_isn,
                                                     eth, port_id);
            if (!result->reply_pkt) {
                free_connection(conn, &key, established);
                result->action = SYN_PROXY_ERROR;
                return -1;
            }
            
            // Don't forward server's SYN-ACK (client already got ours)
            result->action = SYN_PROXY_REPLY;
            result->conn_state = SYN_PROXY_ESTABLISHED;
            return 0;
        }
        
        // ----- RST from Server -----
        // It ends the entry only at the client's next sequence (see "RST
        // validation"), and is always forwarded once the connection is
        // established
        if (tcp_flags & TCP_FLAG_RST) {
            if (state >= SYN_PROXY_ESTABLISHED) {   // ESTABLISHED, closing states, CLOSED
                const enum rst_verdict v = proxied_rst(conn, true, features->tcp_seq);
                translate_s2c(m, ip, tcp, conn);
                result->action = SYN_PROXY_FORWARD;
                result->packet_modified = true;
                if (v == RST_EXACT) {
                    free_connection(conn, &key, ctl);
                } else {
                    forward_rst_unconfirmed(result);
                }
                return 0;
            }
            // Waiting on the server: the proxy's SYN is in SYN-SENT, and an
            // RST counts only if it acknowledges that SYN. Not forwarded
            // either way (the client's leg is the proxy's).
            result->action = SYN_PROXY_DROP;
            if ((tcp_flags & TCP_FLAG_ACK) && features->tcp_ack == conn->proxy_isn + 1) {
                free_connection(conn, &key, ctl);
            } else {
                __atomic_add_fetch(&g_stats.rst_dropped, 1, __ATOMIC_RELAXED);
            }
            return 0;
        }
        
        // ----- FIN from Server -----
        if (tcp_flags & TCP_FLAG_FIN) {
            if (state >= SYN_PROXY_ESTABLISHED) {
                translate_s2c(m, ip, tcp, conn);
                proxied_close_segment(conn, ctl, true, tcp_flags,
                                      rte_be_to_cpu_32(tcp->sent_seq) + tcp_payload_len(ip, tcp) + 1,
                                      features->tcp_ack);
                result->action = SYN_PROXY_FORWARD;
                result->packet_modified = true;
                return 0;
            }
            result->action = SYN_PROXY_DROP;
            return 0;
        }
        
        // ----- Data/ACK from Server -----
        if (state >= SYN_PROXY_ESTABLISHED) {
            translate_s2c(m, ip, tcp, conn);
            result->action = SYN_PROXY_FORWARD;
            result->packet_modified = true;
            result->conn_state = state;
            __atomic_add_fetch(&g_stats.packets_proxied_s2c, 1, __ATOMIC_RELAXED);
            if (state != SYN_PROXY_ESTABLISHED) {
                // The server's ACK of the client's FIN may complete the close
                proxied_close_segment(conn, ctl, true, tcp_flags, 0, features->tcp_ack);
            }
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
    
    uint32_t ctl;
    return find_connection(&key, &ctl) != NULL;
}

bool syn_proxy_admits_segment(const struct packet_features *features) {
    if (!g_initialized) return false;

    struct conn_key key;
    make_conn_key(&key, features->src_ip, features->dst_ip,
                  features->src_port, features->dst_port);
    uint32_t ctl;
    struct syn_proxy_conn *conn = find_connection(&key, &ctl);
    if (!conn) {
        return false;
    }

    // A proxied (challenged) connection: its client returned a valid cookie
    if (ctl_state(ctl) != SYN_PROXY_BYPASSED) {
        return true;
    }

    // A BYPASSED one whose client acknowledged the server's ISN + 1
    if (ctl & CTL_F_HS_ACKED) {
        return true;
    }

    // ... or the segment that acknowledges it. server_isn belongs to the entry
    // read above only while its generation is unchanged: read it, then the
    // word again. The acquire load keeps the read of server_isn before that
    // of the word, and a value stored by a later occupant (a release store
    // after its claim) brings that occupant's generation into the word read
    // after it (see "Entry control word").
    if ((ctl & (CTL_F_ISN_SEEN | CTL_F_BUSY)) == CTL_F_ISN_SEEN &&
        (features->tcp_flags & TCP_FLAG_ACK) && !(features->tcp_flags & TCP_FLAG_SYN)) {
        uint32_t isn = __atomic_load_n(&conn->server_isn, __ATOMIC_ACQUIRE);
        return features->tcp_ack == isn + 1 && ctl_same_entry(ctl_load(conn), ctl);
    }
    return false;
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

// Test seam (see syn_proxy.h): this weak default reads the TSC
__attribute__((weak)) uint64_t syn_proxy_synack_clock(void) {
    return rte_rdtsc();
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
        __atomic_store_n(&g_synack_window_start_tsc, syn_proxy_synack_clock(), __ATOMIC_RELEASE);
        return true;
    }

    uint64_t now = syn_proxy_synack_clock();
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
 * Global circuit breaker setting of the active Layer 1 config.
 * layer1_config_get() returns NULL until a config is active; with no config
 * the breaker is off and a valid per-IP snapshot decides alone.
 */
static inline bool circuit_breaker_enabled(void) {
    const struct layer1_config *l1cfg = layer1_config_get();
    return l1cfg && l1cfg->global_circuit_breaker;
}

/**
 * Intelligent SYN challenge decision.
 *
 * Determines whether to challenge a SYN packet based on:
 * 0. Spoofed attack mode (per-IP or global)
 * 1. Policy rules (explicit CHALLENGE action)
 * 2. Source IP reputation
 * 3. Global anomaly state (set by Layer 3/4)
 * 4. Current SYN rate vs threshold
 * A source that returned a valid cookie (legitimate_ip_lookup()) is
 * challenged like any other. Exempting it for the legitimate TTL let one
 * source that completed one handshake fill the table under attack: every
 * exempt SYN made a BYPASSED entry, which an unanswered SYN keeps for the
 * idle timeout, before any per-source SYN limit (Stage 9b) and with none in
 * spoofed mode, where its address is also the easiest to forge. Other
 * clients' valid cookies then found no room (table_full_drops). The
 * challenge costs a returning client only the options the cookie path does
 * not offer (MSS only). An exemption needs a bound per source first.
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
        } else if (circuit_breaker_enabled() && anomaly_is_spoofed_mode()) {
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
        } else if (circuit_breaker_enabled()) {
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

// Due entries collected per batch by syn_proxy_cleanup_connections()
#define CLEANUP_BATCH_SIZE      256

// Due entries one pass of syn_proxy_cleanup_connections() may delete. It runs
// once a second inline on the main lcore, which in software RSS also receives
// for every port, so the budgets bound how long a pass holds that lcore.
// Nothing bounds the rate at which entries become due:
// - BYPASSED entries come from SYNs the proxy does not challenge: up to
//   challenge_threshold a second (1000 by default, 10 times that for sources
//   of good reputation), and at any rate from sources that a POLICY_ALLOW
//   rule lets through (syn_proxy_should_challenge()). Most are released when
//   their connection ends, as proxied entries are;
// - a CONNECTING entry times out only if its client returned a valid cookie
//   and the server never answered, and a source has at most
//   MAX_HALF_OPEN_PER_IP of them waiting (at the default 5 s connect timeout,
//   about 13 a second per source).
// Entries due beyond the budget wait for the next pass, which resumes the scan
// where this one stopped. If more than the budget become due every second
// (policy-allowed connections that end unseen, say), the cleanup falls
// behind: the table fills up to max_connections, bypassed SYNs are then
// forwarded without an entry, and valid-cookie ACKs are dropped and counted
// in table_full_drops.
#define CLEANUP_DELETE_BUDGET   65536

// Entries one pass examines, due or not. Without this bound a pass that finds
// few entries due still reads the control word of every entry in the table,
// about 49 ms on the main lcore for 900k entries. The next pass resumes the
// scan where this one stopped, so the scan covers a table of n entries once
// in n / CLEANUP_SCAN_BUDGET passes (about 8 for 1M entries), and an entry
// may wait that many seconds past its timeout. It is twice the delete budget,
// so a pass in which half the entries it examines are due still uses all of
// the delete budget. Between two entries rte_hash_iterate() also walks the
// empty slots, one walk of the bucket array per sweep of the table.
#define CLEANUP_SCAN_BUDGET     (2 * CLEANUP_DELETE_BUDGET)

// Test seam (see syn_proxy.h): this weak default reads the TSC
__attribute__((weak)) uint64_t syn_proxy_cleanup_clock(void) {
    return rte_get_tsc_cycles();
}

// A due entry as the scan saw it
struct cleanup_candidate {
    struct conn_key key;
    uint32_t pos;
    uint32_t ctl;
};

// The cleanup's timeouts, in TSC cycles
struct cleanup_timeouts {
    uint64_t connect;    // CONNECTING: connect_timeout_ms
    uint64_t idle;       // ESTABLISHED, BYPASSED, CLIENT_FIN, SERVER_FIN: idle_timeout_sec
    uint64_t closing;    // CLOSING: SYN_PROXY_CLOSING_TIMEOUT_SEC, at most the idle timeout
    uint64_t time_wait;  // CLOSED: SYN_PROXY_TIME_WAIT_SEC, at most the idle timeout
};

/**
 * Whether the cleanup deletes an entry, given its control word, and for which
 * counter. An activity time at or after now (a packet since the pass began,
 * possibly on an lcore whose TSC runs a little ahead) is not idle: the
 * unsigned difference would wrap and make an active entry look long idle.
 */
static inline bool cleanup_due(const struct syn_proxy_conn *conn, uint32_t ctl,
                               uint64_t now, const struct cleanup_timeouts *to,
                               enum retire_reason *why) {
    // Free, being filled in, being retired, or BUSY for a moment
    if (!ctl_live(ctl) || (ctl & CTL_F_BUSY)) {
        return false;
    }

    switch (ctl_state(ctl)) {
        case SYN_PROXY_CONNECTING: {
            // Check connect timeout
            uint64_t since = __atomic_load_n(&conn->state_change_tsc, __ATOMIC_RELAXED);
            if (since < now && now - since > to->connect) {
                *why = RETIRE_SERVER_TIMEOUT;
                return true;
            }
            return false;
        }

        case SYN_PROXY_ESTABLISHED:
        case SYN_PROXY_BYPASSED:
        case SYN_PROXY_CLIENT_FIN:
        case SYN_PROXY_SERVER_FIN: {
            // Check idle timeout (an entry is normally released when its
            // connection ends; this catches the ones that end unseen, and
            // half-closed ones that go quiet)
            uint64_t last_client = __atomic_load_n(&conn->last_client_tsc, __ATOMIC_RELAXED);
            uint64_t last_server = __atomic_load_n(&conn->last_server_tsc, __ATOMIC_RELAXED);
            uint64_t last_activity = last_client > last_server ? last_client : last_server;
            if (last_activity < now && now - last_activity > to->idle) {
                *why = RETIRE_IDLE_TIMEOUT;
                return true;
            }
            return false;
        }

        case SYN_PROXY_CLOSING:
        case SYN_PROXY_CLOSED: {
            // CLOSING: both sides sent FIN, and a FIN is not acknowledged yet.
            // Its retransmissions (and the data before it) and the last ACK
            // need translating, so the entry stays until no segment came for
            // the close timeout (SYN_PROXY_CLOSING_TIMEOUT_SEC). It used to be
            // connect_timeout_ms (5 s): a last data+FIN segment retransmitted
            // later than that went out untranslated, and the client never got
            // its last bytes. CLOSED: the close is complete; the entry stays
            // for the TIME_WAIT (SYN_PROXY_TIME_WAIT_SEC), so that a FIN
            // retransmitted for a lost last ACK, and the answer to it, are
            // still translated. Neither is counted here: a CLOSED entry was
            // counted when its close completed.
            uint64_t last_client = __atomic_load_n(&conn->last_client_tsc, __ATOMIC_RELAXED);
            uint64_t last_server = __atomic_load_n(&conn->last_server_tsc, __ATOMIC_RELAXED);
            uint64_t last_activity = last_client > last_server ? last_client : last_server;
            uint64_t timeout = ctl_state(ctl) == SYN_PROXY_CLOSED ? to->time_wait : to->closing;
            if (last_activity < now && now - last_activity > timeout) {
                *why = RETIRE_CLEANUP_CLOSED;
                return true;
            }
            return false;
        }

        default:
            return false;
    }
}

/**
 * Delete the entries of one cleanup batch. Each is checked again just before
 * it is retired: still the same entry, still due. A worker lcore may have
 * established it, used it or ended it since the scan; retire_entry() then
 * fails, and an entry ended by a worker has been counted by that worker. An
 * entry counts (cleaned, connections_active, its timeout counter) only if
 * this call retired it.
 */
static uint32_t cleanup_delete_batch(const struct cleanup_candidate *batch, uint32_t count,
                                     uint64_t now, const struct cleanup_timeouts *to) {
    uint32_t deleted = 0;

    for (uint32_t i = 0; i < count; i++) {
        struct syn_proxy_conn *conn = &g_conn_pool[batch[i].pos];
        uint32_t ctl = ctl_load(conn);
        enum retire_reason why;

        // Retired since the scan (its slot may hold a new entry), or no
        // longer due
        if (!ctl_same_entry(ctl, batch[i].ctl) ||
            !cleanup_due(conn, ctl, now, to, &why)) {
            continue;
        }

        syn_proxy_race_seam(SYN_PROXY_SEAM_CLEANUP);
        if (retire_entry(conn, &batch[i].key, &ctl, why)) {
            deleted++;
        }
    }
    return deleted;
}

uint32_t syn_proxy_cleanup_connections(void) {
    if (!g_initialized) return 0;
    // Freeing key slots needs an lcore id (lcore_may_write_table())
    if (unlikely(!lcore_may_write_table())) return 0;
    
    uint64_t now = syn_proxy_cleanup_clock();
    uint64_t tsc_hz = rte_get_tsc_hz();
    struct cleanup_timeouts to;
    to.connect = ((uint64_t)g_config.connect_timeout_ms * tsc_hz) / 1000;
    to.idle = (uint64_t)g_config.idle_timeout_sec * tsc_hz;
    to.closing = RTE_MIN((uint64_t)SYN_PROXY_CLOSING_TIMEOUT_SEC * tsc_hz, to.idle);
    to.time_wait = RTE_MIN((uint64_t)SYN_PROXY_TIME_WAIT_SEC * tsc_hz, to.idle);
    
    uint32_t cleaned = 0;
    uint32_t collected = 0;
    uint32_t scanned = 0;
    const void *key;
    void *data;
    uint32_t iter = g_cleanup_iter;  // Resume where the last pass stopped
    
    // Collect due entries (can't delete during iteration), and delete each
    // full batch before the scan goes on. Resuming the scan after a batch is
    // safe for this table: it has no extendable buckets, so a delete only
    // empties that key's slot and moves no other key, and the iterator is a
    // slot position. A pass ends at the end of the table, once it has
    // examined CLEANUP_SCAN_BUDGET entries, or once it has collected
    // CLEANUP_DELETE_BUDGET due entries; the next pass then resumes there, as
    // flow ageing does. A pass is bounded by CLEANUP_SCAN_BUDGET entries
    // examined (plus the empty slots between them) and CLEANUP_DELETE_BUDGET
    // deletes, with CLEANUP_BATCH_SIZE candidates on the stack.
    struct cleanup_candidate batch[CLEANUP_BATCH_SIZE];
    uint32_t batch_count = 0;
    
    int32_t pos = 0;
    while (collected < CLEANUP_DELETE_BUDGET && scanned < CLEANUP_SCAN_BUDGET &&
           (pos = rte_hash_iterate(g_conn_hash, &key, &data, &iter)) >= 0) {
        scanned++;
        // Use position returned by rte_hash_iterate directly,
        // avoiding redundant rte_hash_lookup that could race with data-path.
        // (The pool has one entry per position the hash can return.)
        if ((uint32_t)pos >= g_pool_entries) continue;

        struct syn_proxy_conn *conn = &g_conn_pool[pos];
        uint32_t ctl = ctl_load(conn);
        enum retire_reason why;
        if (!cleanup_due(conn, ctl, now, &to, &why)) {
            continue;
        }
        
        // The key is copied after the acquire load of the word it goes with
        memcpy(&batch[batch_count].key, key, sizeof(struct conn_key));
        batch[batch_count].pos = (uint32_t)pos;
        batch[batch_count].ctl = ctl;
        collected++;
        if (++batch_count == CLEANUP_BATCH_SIZE) {
            cleaned += cleanup_delete_batch(batch, batch_count, now, &to);
            batch_count = 0;
        }
    }
    
    // Now delete the last, partial batch
    cleaned += cleanup_delete_batch(batch, batch_count, now, &to);

    // Save the iterator for the next pass; start over once the scan is complete
    g_cleanup_iter = (pos < 0) ? 0 : iter;

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

/**
 * Factory reset of the connection table. Like rte_hash_reset(), not safe while
 * other lcores process packets: it also restarts every slot's generation.
 */
void syn_proxy_clear_all(void) {
    if (!g_initialized || !g_conn_hash || !g_conn_pool) return;
    rte_hash_reset(g_conn_hash);
    memset(g_conn_pool, 0, (size_t)g_pool_entries * sizeof(struct syn_proxy_conn));
    half_open_reset();
    legitimate_ip_clear();
    memset(&g_stats, 0, sizeof(g_stats));
    g_entries_used = 0;
    g_cleanup_iter = 0;
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
    // No per-destination aggregate rate limiting yet (spoofed_rate_check()
    // accepts). The legitimate-source table lives in ip_lists.c. Its TTL is
    // the shipped legitimate_ttl_sec (300 s): the config parser reads neither
    // legitimate_ttl_sec nor legitimate_table_size, which therefore arrives
    // here as 0, the shipped 100000.
    return legitimate_ip_init(legitimate_table_size, LEGITIMATE_DEFAULT_TTL_SEC);
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
    legitimate_ip_free();
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

