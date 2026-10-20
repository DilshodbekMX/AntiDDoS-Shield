#include "signatures.h"
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <rte_telemetry.h>
#include <string.h>
#include <stdio.h>

#define RTE_LOGTYPE_SIG RTE_LOGTYPE_USER6

/**
 * L3/L4 Attack Signature Detection
 *
 * Uses pattern matching for known attack signatures:
 * - Amplification attacks: detected by source port + packet size
 * - Scans: detected by packet pattern analysis
 * - Protocol anomalies: invalid header combinations
 * - Attack tools: known payload patterns
 */

// ==================== Signature Definitions ====================

// Signature ID ranges
#define SIG_ID_AMPLIFICATION_BASE  1000
#define SIG_ID_SCAN_BASE           2000
#define SIG_ID_ANOMALY_BASE        3000
#define SIG_ID_TOOL_BASE           4000

_Static_assert(SIG_ID_SYN_SCAN == SIG_ID_SCAN_BASE + 1, "SIG_ID_SYN_SCAN is scan signature 1");

// Known amplification ports and their characteristics
static struct amplification_sig amplification_sigs[] = {
    // Port, Name, Amplification Factor, Enabled
    {19,    "Chargen",      358, true},   // Character Generator
    {53,    "DNS",          28,  true},   // Domain Name System
    {111,   "RPC",          6,   true},   // Sun RPC
    {123,   "NTP",          556, true},   // Network Time Protocol
    {137,   "NetBIOS",      3,   true},   // NetBIOS Name Service
    {161,   "SNMP",         6,   true},   // Simple Network Management
    {389,   "CLDAP",        56,  true},   // Connectionless LDAP
    {520,   "RIP",          13,  true},   // Routing Information Protocol
    {751,   "Kerberos",     14,  true},   // Kerberos
    {1434,  "MSSQL",        25,  true},   // Microsoft SQL
    {1900,  "SSDP",         30,  true},   // Simple Service Discovery
    {3283,  "Apple Remote", 35,  true},   // Apple Remote Desktop
    {3389,  "RDP",          85,  true},   // Remote Desktop Protocol
    {3702,  "WS-Discovery", 10,  true},   // Web Services Discovery
    {5093,  "Sentinel",     50,  true},   // Sentinel LM
    {5353,  "mDNS",         2,   true},   // Multicast DNS
    {5683,  "CoAP",         34,  true},   // Constrained Application Protocol
    {6881,  "BitTorrent",   3,   true},   // BitTorrent
    {11211, "Memcached",    51000, true}, // Memcached (huge amplification!)
    {17185, "VxWorks",      17,  true},   // VxWorks Debug
    {27015, "Steam",        5,   true},   // Steam Protocol
    {33848, "Jenkins",      100, true},   // Jenkins UDP
    {0,     NULL,           0,   false}   // Sentinel
};
#define NUM_AMPLIFICATION_SIGS (sizeof(amplification_sigs)/sizeof(amplification_sigs[0]) - 1)

// ==================== Global State ====================

static bool sig_initialized = false;
static struct signatures_config sig_cfg;
static rte_spinlock_t sig_lock = RTE_SPINLOCK_INITIALIZER;

// Fast lookup for amplification ports (bitmap)
static uint8_t amplification_bitmap[8192];  // 65536 ports / 8

// Per-lcore statistics
struct sig_lcore_stats {
    uint64_t packets_checked;
    uint64_t signatures_matched;
    uint64_t amplification_detected;
    uint64_t scans_detected;
    uint64_t anomalies_detected;
    uint64_t attack_tools_detected;
    uint64_t packets_dropped;
    uint64_t packets_rate_limited;
    uint64_t syn_scan_indicators;
    uint64_t syn_scan_dropped;
    uint64_t syn_scan_untracked;
} __rte_cache_aligned;

static struct sig_lcore_stats lcore_sig_stats[RTE_MAX_LCORE];

// ==================== SYN Scan Tracker ====================
//
// Per-source evidence for SIG_ID_SYN_SCAN (see signatures.h). Each slot is
// one 64-bit word, updated only by compare-and-swap, so every reader sees a
// whole state of one source and no update can mix two sources:
//   bits 44..63  the source's hash bits 12..31 (the slot index is bits 0..11)
//   bits 28..43  window number, modulo 65536
//   bit  27      HOT: this window met a threshold
//   bit  26      CARRIED: the previous window met one
//   bits 16..25  SYNs in this window (at most SIG_SYN_SCAN_SYNS)
//   bits  0..15  destination ports seen in this window, one bit per hash
// The hash is a bijection of the 32-bit address, so slot and tag together
// name exactly one source. 0 is an empty slot (a state counts at least 1 SYN).
// Only SIG_ID_SYN_SCAN frames touch the table.

#define SCAN_SLOT_BITS     12
#define SCAN_TAG_SHIFT     44
#define SCAN_EPOCH_SHIFT   28
#define SCAN_HOT           (1ULL << 27)
#define SCAN_CARRIED       (1ULL << 26)
#define SCAN_COUNT_SHIFT   16
#define SCAN_COUNT_MASK    0x3FFULL
#define SCAN_PORTS_MASK    0xFFFFULL
#define SCAN_CAS_ATTEMPTS  4   // then the SYN is not tracked: bounded work per packet

_Static_assert(SIG_SYN_SCAN_SLOTS == (1u << SCAN_SLOT_BITS), "slot index is hash bits 0..11");
_Static_assert(SCAN_TAG_SHIFT + (32 - SCAN_SLOT_BITS) == 64, "the tag fills bits 44..63");
_Static_assert(SIG_SYN_SCAN_SYNS >= 2 && SIG_SYN_SCAN_SYNS <= SCAN_COUNT_MASK,
               "the count field holds SIG_SYN_SCAN_SYNS, and one SYN is never a scan");
_Static_assert(SIG_SYN_SCAN_PORTS >= 2 && SIG_SYN_SCAN_PORTS <= 16,
               "the port bitmap has 16 bits, and one port is never a scan");

enum scan_verdict {
    SCAN_PASS = 0,     // tracked, no scan pattern
    SCAN_DROP,         // tracked, the source shows a scan pattern
    SCAN_UNTRACKED     // not tracked (slot held by another scanning source, or contention)
};

static uint64_t scan_slots[SIG_SYN_SCAN_SLOTS] __rte_cache_aligned;
static uint64_t scan_window_tsc = 1;           // TSC cycles per window, set by signatures_init()
static uint64_t scan_window_inv = UINT64_MAX;  // 2^64 / scan_window_tsc, rounded down

// Test seam (see signatures.h): this weak default reads the TSC
__attribute__((weak)) uint64_t signatures_scan_clock(void) {
    return rte_get_tsc_cycles();
}

// Window number of a TSC time. The reciprocal saves a 64-bit division per
// SYN; it can place a SYN just after a window boundary in the window before
// (by under now / 2^64 windows, about 50 us after three days at 4 GHz)
static inline uint16_t scan_epoch_at(uint64_t tsc) {
#ifdef __SIZEOF_INT128__
    return (uint16_t)(((unsigned __int128)tsc * scan_window_inv) >> 64);
#else
    return (uint16_t)(tsc / scan_window_tsc);
#endif
}

// MurmurHash3's 32-bit finalizer: every step is invertible, so distinct
// addresses never share a hash. No seed: a collision can only leave a source
// untracked (its SYNs pass), never give it another source's state.
static inline uint32_t scan_hash(uint32_t x) {
    x ^= x >> 16;
    x *= 0x85ebca6bu;
    x ^= x >> 13;
    x *= 0xc2b2ae35u;
    x ^= x >> 16;
    return x;
}

uint32_t signatures_syn_scan_slot(uint32_t src_ip) {
    return scan_hash(src_ip) & (SIG_SYN_SCAN_SLOTS - 1);
}

// The top 4 bits of a multiplicative hash: neighbouring ports spread out
static inline uint32_t scan_port_index(uint16_t dst_port) {
    return ((uint32_t)dst_port * 0x9E3779B1u) >> 28;
}

uint32_t signatures_syn_scan_port_bit(uint16_t dst_port) {
    return scan_port_index(dst_port);
}

static inline uint16_t scan_epoch_of(uint64_t w) {
    return (uint16_t)(w >> SCAN_EPOCH_SHIFT);
}

static inline uint64_t scan_word(uint32_t tag, uint16_t epoch, uint64_t flags,
                                 uint64_t count, uint64_t ports) {
    return ((uint64_t)tag << SCAN_TAG_SHIFT) | ((uint64_t)epoch << SCAN_EPOCH_SHIFT) |
           flags | (count << SCAN_COUNT_SHIFT) | ports;
}

// A slot whose source is dropped now, or will be in the next window: another
// source does not take it
static inline bool scan_slot_live(uint64_t w, uint16_t epoch) {
    uint16_t e = scan_epoch_of(w);
    if (e == epoch || e == (uint16_t)(epoch + 1)) {
        return (w & (SCAN_HOT | SCAN_CARRIED)) != 0;
    }
    if (e == (uint16_t)(epoch - 1)) {
        return (w & SCAN_HOT) != 0;
    }
    return false;
}

// Record one SIG_ID_SYN_SCAN frame of src_ip to dst_port and judge its source
static enum scan_verdict syn_scan_track(uint32_t src_ip, uint16_t dst_port) {
    uint32_t h = scan_hash(src_ip);
    uint64_t *slot = &scan_slots[h & (SIG_SYN_SCAN_SLOTS - 1)];
    uint32_t tag = h >> SCAN_SLOT_BITS;
    uint16_t epoch = scan_epoch_at(signatures_scan_clock());
    uint64_t port_bit = 1ULL << scan_port_index(dst_port);

    uint64_t old = __atomic_load_n(slot, __ATOMIC_RELAXED);
    for (unsigned attempt = 0; attempt < SCAN_CAS_ATTEMPTS; attempt++) {
        uint64_t next;
        uint16_t e = scan_epoch_of(old);
        bool same_source = old != 0 && (uint32_t)(old >> SCAN_TAG_SHIFT) == tag;

        if (same_source && (e == epoch || e == (uint16_t)(epoch + 1))) {
            // This window (epoch + 1: an lcore whose TSC runs ahead began the next)
            if (old & SCAN_HOT) {
                return SCAN_DROP;   // already judged for this window: no write
            }
            uint64_t count = ((old >> SCAN_COUNT_SHIFT) & SCAN_COUNT_MASK) + 1;
            uint64_t ports = (old & SCAN_PORTS_MASK) | port_bit;
            uint64_t flags = old & SCAN_CARRIED;
            if (count >= SIG_SYN_SCAN_SYNS ||
                __builtin_popcountll(ports) >= SIG_SYN_SCAN_PORTS) {
                flags |= SCAN_HOT;
            }
            next = scan_word(tag, e, flags, count, ports);
        } else if (same_source && e == (uint16_t)(epoch - 1)) {
            // The next window: the last one's verdict carries over
            next = scan_word(tag, epoch, (old & SCAN_HOT) ? SCAN_CARRIED : 0, 1, port_bit);
        } else if (old != 0 && !same_source && scan_slot_live(old, epoch)) {
            // Another source's scan holds the slot: it keeps it, and this
            // source goes untracked (its SYN passes) rather than share state
            return SCAN_UNTRACKED;
        } else {
            // Empty, stale, or another source's quiet window: take the slot
            next = scan_word(tag, epoch, 0, 1, port_bit);
        }

        if (__atomic_compare_exchange_n(slot, &old, next, false,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            return (next & (SCAN_HOT | SCAN_CARRIED)) ? SCAN_DROP : SCAN_PASS;
        }
        // old now holds the slot's current word: judge again
    }
    return SCAN_UNTRACKED;
}

// ==================== Bitmap Operations ====================

static inline void amp_bitmap_set(uint16_t port) {
    amplification_bitmap[port / 8] |= (1 << (port % 8));
}

static inline void amp_bitmap_clear(uint16_t port) {
    amplification_bitmap[port / 8] &= ~(1 << (port % 8));
}

static inline bool amp_bitmap_test(uint16_t port) {
    return (amplification_bitmap[port / 8] & (1 << (port % 8))) != 0;
}

// ==================== Signature Matching ====================

/**
 * Check for amplification attack.
 * Amplification attacks use spoofed source IP and a UDP reflector port.
 * The reflector sends a large response to the victim.
 */
uint32_t signatures_check_amplification(uint16_t src_port, uint16_t pkt_len) {
    // Quick bitmap check
    if (!amp_bitmap_test(src_port)) {
        return 0;
    }

    // Amplification responses are typically large
    // Most reflection attacks have packets > 100 bytes
    if (pkt_len < 100) {
        return 0;  // Likely a legitimate small response
    }

    // Find the specific signature
    for (uint32_t i = 0; i < NUM_AMPLIFICATION_SIGS; i++) {
        if (amplification_sigs[i].port == src_port && amplification_sigs[i].enabled) {
            return SIG_ID_AMPLIFICATION_BASE + i;
        }
    }

    return 0;
}

/**
 * Check for scan patterns.
 * Scans are characterized by:
 * - TCP SYN packets to many different ports
 * - Small UDP packets to many ports
 * - ICMP echo requests to many IPs
 */
static uint32_t check_scan_pattern(uint8_t protocol, uint8_t tcp_flags,
                                   uint16_t pkt_len) {
    if (protocol == 6) {  // TCP
        // SYN scan: SYN flag only, small packet (no options, or MSS only).
        // On its own an indicator: signatures_check() drops it only when the
        // tracker sees a scan pattern from the same source
        if (tcp_flags == 0x02 && pkt_len <= 60) {
            return SIG_ID_SYN_SCAN;  // Potential SYN scan
        }

        // FIN scan: FIN only
        if (tcp_flags == 0x01) {
            return SIG_ID_SCAN_BASE + 2;  // FIN scan
        }

        // ACK scan: ACK only to closed port (can't detect here, need state)
    }

    if (protocol == 17) {  // UDP
        // UDP scan: very small packets
        if (pkt_len <= 28) {  // Just UDP header
            return SIG_ID_SCAN_BASE + 3;  // Potential UDP scan
        }
    }

    return 0;
}

/**
 * Check for protocol anomalies.
 */
static uint32_t check_protocol_anomaly(uint8_t protocol, uint8_t tcp_flags,
                                       uint16_t pkt_len, uint8_t ttl) {
    if (protocol == 6) {  // TCP
        // NULL scan: no flags
        if (tcp_flags == 0x00) {
            return SIG_ID_ANOMALY_BASE + 1;  // NULL scan
        }

        // XMAS scan: FIN+PSH+URG
        if ((tcp_flags & 0x29) == 0x29) {
            return SIG_ID_ANOMALY_BASE + 2;  // XMAS scan
        }

        // Invalid: SYN+FIN
        if ((tcp_flags & 0x03) == 0x03) {
            return SIG_ID_ANOMALY_BASE + 3;  // SYN+FIN (invalid)
        }

        // Invalid: SYN+RST
        if ((tcp_flags & 0x06) == 0x06) {
            return SIG_ID_ANOMALY_BASE + 4;  // SYN+RST (invalid)
        }
    }

    // Suspicious TTL values
    if (ttl == 1) {
        // TTL=1 from internet is suspicious (traceroute or attack)
        return SIG_ID_ANOMALY_BASE + 10;  // TTL=1 anomaly
    }

    // Very low TTL values are suspicious for DDoS
    if (ttl < 10 && protocol != 1) {  // Allow for ICMP TTL exceeded
        return SIG_ID_ANOMALY_BASE + 11;  // Low TTL anomaly
    }

    (void)pkt_len;
    return 0;
}

/**
 * Check for known attack tool signatures.
 * This is based on packet characteristics common to DDoS tools.
 */
static uint32_t check_attack_tool(uint8_t protocol, uint16_t src_port,
                                  uint16_t dst_port, uint16_t pkt_len,
                                  uint8_t tcp_flags) {
    // LOIC (Low Orbit Ion Cannon) patterns
    if (protocol == 6) {
        // LOIC HTTP flood: port 80, rapid SYNs with specific size
        if (dst_port == 80 && tcp_flags == 0x02 && pkt_len == 60) {
            // Could be LOIC - need more context
        }
    }

    // UDP flood tools often use fixed port ranges
    if (protocol == 17) {
        // Common UDP flood: high ports, fixed size
        if (src_port > 49152 && pkt_len == 1024) {
            return SIG_ID_TOOL_BASE + 1;  // Generic UDP flood tool
        }

        // Mirai botnet DNS amplification requests
        if (dst_port == 53 && pkt_len == 60) {
            // Standard ANY query size
            return SIG_ID_TOOL_BASE + 10;  // Potential Mirai DNS
        }
    }

    // GRE flood (encapsulation attack)
    if (protocol == 47) {
        return SIG_ID_TOOL_BASE + 20;  // GRE flood
    }

    return 0;
}

// ==================== Telemetry ====================

static int handle_signatures_telemetry(const char *cmd __rte_unused,
                                       const char *params __rte_unused,
                                       struct rte_tel_data *d) {
    struct signatures_stats s;
    signatures_get_stats(&s);

    rte_tel_data_start_dict(d);
    rte_tel_data_add_dict_int(d, "enabled", signatures_is_enabled() ? 1 : 0);
    rte_tel_data_add_dict_int(d, "strict_syn_scan", sig_cfg.strict_syn_scan ? 1 : 0);
    rte_tel_data_add_dict_uint(d, "packets_checked", s.packets_checked);
    rte_tel_data_add_dict_uint(d, "signatures_matched", s.signatures_matched);
    rte_tel_data_add_dict_uint(d, "amplification_detected", s.amplification_detected);
    rte_tel_data_add_dict_uint(d, "scans_detected", s.scans_detected);
    rte_tel_data_add_dict_uint(d, "anomalies_detected", s.anomalies_detected);
    rte_tel_data_add_dict_uint(d, "attack_tools_detected", s.attack_tools_detected);
    rte_tel_data_add_dict_uint(d, "packets_dropped", s.packets_dropped);
    rte_tel_data_add_dict_uint(d, "syn_scan_indicators", s.syn_scan_indicators);
    rte_tel_data_add_dict_uint(d, "syn_scan_dropped", s.syn_scan_dropped);
    rte_tel_data_add_dict_uint(d, "syn_scan_untracked", s.syn_scan_untracked);
    return 0;
}

// ==================== Public API ====================

int signatures_init(const struct signatures_config *config) {
    static bool telemetry_registered = false;

    if (sig_initialized) {
        RTE_LOG(WARNING, SIG, "Signatures already initialized\n");
        return 0;
    }

    rte_spinlock_lock(&sig_lock);

    memcpy(&sig_cfg, config, sizeof(sig_cfg));

    // Initialize amplification port bitmap
    memset(amplification_bitmap, 0, sizeof(amplification_bitmap));
    for (uint32_t i = 0; i < NUM_AMPLIFICATION_SIGS; i++) {
        if (amplification_sigs[i].enabled) {
            amp_bitmap_set(amplification_sigs[i].port);
        }
    }

    // Initialize per-lcore stats
    memset(lcore_sig_stats, 0, sizeof(lcore_sig_stats));

    // SYN scan tracker: empty slots, windows of SIG_SYN_SCAN_WINDOW_MS. Without
    // a TSC rate (no EAL) every cycle is its own window: nothing is dropped
    memset(scan_slots, 0, sizeof(scan_slots));
    scan_window_tsc = rte_get_tsc_hz() * SIG_SYN_SCAN_WINDOW_MS / 1000;
    if (scan_window_tsc == 0) {
        scan_window_tsc = 1;
    }
    scan_window_inv = UINT64_MAX / scan_window_tsc;

    sig_initialized = true;

    RTE_LOG(INFO, SIG, "Signatures initialized (%zu amplification signatures, "
            "minimal SYNs dropped %s)\n", NUM_AMPLIFICATION_SIGS,
            sig_cfg.strict_syn_scan ? "always (strict_syn_scan)" : "on a scan pattern");

    rte_spinlock_unlock(&sig_lock);

    // Statistics endpoint, once per process (the callback outlives cleanup)
    if (!telemetry_registered) {
        if (rte_telemetry_register_cmd("/antiddos/signatures", handle_signatures_telemetry,
                                       "Returns attack signature statistics") == 0) {
            telemetry_registered = true;
        } else {
            RTE_LOG(WARNING, SIG, "Failed to register /antiddos/signatures\n");
        }
    }
    return 0;
}

void signatures_cleanup(void) {
    if (!sig_initialized) return;

    rte_spinlock_lock(&sig_lock);
    sig_initialized = false;
    RTE_LOG(INFO, SIG, "Signatures cleanup complete\n");
    rte_spinlock_unlock(&sig_lock);
}

bool signatures_check(uint8_t protocol,
                      uint32_t src_ip, uint32_t dst_ip,
                      uint16_t src_port, uint16_t dst_port,
                      uint8_t tcp_flags, uint16_t pkt_len,
                      uint8_t ttl,
                      struct sig_match *match) {
    (void)dst_ip;

    if (!sig_initialized || !sig_cfg.enabled) {
        return false;
    }

    unsigned lcore_id = rte_lcore_id();
    if (lcore_id < RTE_MAX_LCORE) {
        lcore_sig_stats[lcore_id].packets_checked++;
    }

    uint32_t sig_id = 0;
    uint32_t indicator_id = 0;   // matched, not acted on: reported with SIG_ACTION_LOG
    enum sig_category category = 0;
    enum sig_action action = SIG_ACTION_LOG;
    const char *description = NULL;
    uint8_t severity = 0;
    bool should_drop = false;

    // Check amplification (UDP only)
    if (protocol == 17 && sig_cfg.block_amplification) {
        sig_id = signatures_check_amplification(src_port, pkt_len);
        if (sig_id) {
            category = SIG_CAT_AMPLIFICATION;
            action = SIG_ACTION_DROP;
            description = "Amplification attack";
            severity = 8;
            should_drop = true;

            if (lcore_id < RTE_MAX_LCORE) {
                lcore_sig_stats[lcore_id].amplification_detected++;
            }
        }
    }

    // Check scan patterns
    if (!sig_id && sig_cfg.block_scans) {
        sig_id = check_scan_pattern(protocol, tcp_flags, pkt_len);
        if (sig_id == SIG_ID_SYN_SCAN) {
            // The frame alone is an indicator; its source decides (signatures.h)
            enum scan_verdict verdict = sig_cfg.strict_syn_scan ?
                                        SCAN_DROP : syn_scan_track(src_ip, dst_port);
            if (lcore_id < RTE_MAX_LCORE) {
                lcore_sig_stats[lcore_id].syn_scan_indicators++;
                if (verdict == SCAN_DROP) {
                    lcore_sig_stats[lcore_id].syn_scan_dropped++;
                } else if (verdict == SCAN_UNTRACKED) {
                    lcore_sig_stats[lcore_id].syn_scan_untracked++;
                }
            }
            if (verdict != SCAN_DROP) {
                // Not a scan: the later checks still apply to the frame
                indicator_id = sig_id;
                sig_id = 0;
            }
        }
        if (sig_id) {
            category = SIG_CAT_SCAN;
            action = SIG_ACTION_DROP;
            description = "Scan pattern detected";
            severity = 5;
            should_drop = true;

            if (lcore_id < RTE_MAX_LCORE) {
                lcore_sig_stats[lcore_id].scans_detected++;
            }
        }
    }

    // Check protocol anomalies
    if (!sig_id && sig_cfg.block_anomalies) {
        sig_id = check_protocol_anomaly(protocol, tcp_flags, pkt_len, ttl);
        if (sig_id) {
            category = SIG_CAT_PROTOCOL_ANOMALY;
            action = SIG_ACTION_DROP;
            description = "Protocol anomaly";
            severity = 6;
            should_drop = true;

            if (lcore_id < RTE_MAX_LCORE) {
                lcore_sig_stats[lcore_id].anomalies_detected++;
            }
        }
    }

    // Check attack tool patterns
    if (!sig_id && sig_cfg.block_attack_tools) {
        sig_id = check_attack_tool(protocol, src_port, dst_port, pkt_len, tcp_flags);
        if (sig_id) {
            category = SIG_CAT_ATTACK_TOOL;
            action = SIG_ACTION_DROP;
            description = "Attack tool signature";
            severity = 9;
            should_drop = true;

            if (lcore_id < RTE_MAX_LCORE) {
                lcore_sig_stats[lcore_id].attack_tools_detected++;
            }
        }
    }

    // Fill match result if signature matched
    if (sig_id && match) {
        match->signature_id = sig_id;
        match->category = category;
        match->action = action;
        match->description = description;
        match->severity = severity;

        if (lcore_id < RTE_MAX_LCORE) {
            lcore_sig_stats[lcore_id].signatures_matched++;
            if (should_drop) {
                lcore_sig_stats[lcore_id].packets_dropped++;
            }
        }

        // Log if enabled
        if (sig_cfg.log_matches) {
            static uint64_t log_count = 0;
            if (__atomic_add_fetch(&log_count, 1, __ATOMIC_RELAXED) <= 100) {
                RTE_LOG(WARNING, SIG, "Signature match: id=%u cat=%d desc=%s\n",
                        sig_id, category, description ? description : "unknown");
            }
        }
    } else if (!sig_id && indicator_id && match) {
        // Reported and counted, not logged: the log's 100 lines stay for drops
        match->signature_id = indicator_id;
        match->category = SIG_CAT_SCAN;
        match->action = SIG_ACTION_LOG;
        match->description = "Minimal SYN (scan indicator)";
        match->severity = 2;

        if (lcore_id < RTE_MAX_LCORE) {
            lcore_sig_stats[lcore_id].signatures_matched++;
        }
    }

    return should_drop;
}

void signatures_set_amplification_enabled(uint16_t port, bool enable) {
    if (!sig_initialized) return;

    rte_spinlock_lock(&sig_lock);

    for (uint32_t i = 0; i < NUM_AMPLIFICATION_SIGS; i++) {
        if (amplification_sigs[i].port == port) {
            amplification_sigs[i].enabled = enable;
            if (enable) {
                amp_bitmap_set(port);
            } else {
                amp_bitmap_clear(port);
            }
            RTE_LOG(INFO, SIG, "Amplification signature for port %u %s\n",
                    port, enable ? "enabled" : "disabled");
            break;
        }
    }

    rte_spinlock_unlock(&sig_lock);
}

void signatures_set_block_amplification(bool enable) {
    rte_spinlock_lock(&sig_lock);
    sig_cfg.block_amplification = enable;
    rte_spinlock_unlock(&sig_lock);
}

void signatures_set_block_scans(bool enable) {
    rte_spinlock_lock(&sig_lock);
    sig_cfg.block_scans = enable;
    rte_spinlock_unlock(&sig_lock);
}

void signatures_set_block_anomalies(bool enable) {
    rte_spinlock_lock(&sig_lock);
    sig_cfg.block_anomalies = enable;
    rte_spinlock_unlock(&sig_lock);
}

void signatures_set_block_attack_tools(bool enable) {
    rte_spinlock_lock(&sig_lock);
    sig_cfg.block_attack_tools = enable;
    rte_spinlock_unlock(&sig_lock);
}

void signatures_set_enabled(bool enabled) {
    rte_spinlock_lock(&sig_lock);
    sig_cfg.enabled = enabled;
    RTE_LOG(INFO, SIG, "Signatures %s\n", enabled ? "enabled" : "disabled");
    rte_spinlock_unlock(&sig_lock);
}

bool signatures_is_enabled(void) {
    return sig_initialized && sig_cfg.enabled;
}

void signatures_get_stats(struct signatures_stats *stats) {
    if (!stats) return;

    memset(stats, 0, sizeof(*stats));

    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        stats->packets_checked += lcore_sig_stats[lcore_id].packets_checked;
        stats->signatures_matched += lcore_sig_stats[lcore_id].signatures_matched;
        stats->amplification_detected += lcore_sig_stats[lcore_id].amplification_detected;
        stats->scans_detected += lcore_sig_stats[lcore_id].scans_detected;
        stats->anomalies_detected += lcore_sig_stats[lcore_id].anomalies_detected;
        stats->attack_tools_detected += lcore_sig_stats[lcore_id].attack_tools_detected;
        stats->packets_dropped += lcore_sig_stats[lcore_id].packets_dropped;
        stats->packets_rate_limited += lcore_sig_stats[lcore_id].packets_rate_limited;
        stats->syn_scan_indicators += lcore_sig_stats[lcore_id].syn_scan_indicators;
        stats->syn_scan_dropped += lcore_sig_stats[lcore_id].syn_scan_dropped;
        stats->syn_scan_untracked += lcore_sig_stats[lcore_id].syn_scan_untracked;
    }
}

void signatures_reset_stats(void) {
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        memset(&lcore_sig_stats[lcore_id], 0, sizeof(lcore_sig_stats[0]));
    }
}

void signatures_print_stats(void) {
    struct signatures_stats stats;
    signatures_get_stats(&stats);

    printf("\n");
    printf("Attack Signatures Statistics:\n");
    printf("  Enabled: %s\n", sig_cfg.enabled ? "yes" : "no");
    printf("  Packets checked: %lu\n", stats.packets_checked);
    printf("  Signatures matched: %lu\n", stats.signatures_matched);
    printf("  Detection breakdown:\n");
    printf("    Amplification: %lu\n", stats.amplification_detected);
    printf("    Scans: %lu\n", stats.scans_detected);
    printf("    Anomalies: %lu\n", stats.anomalies_detected);
    printf("    Attack tools: %lu\n", stats.attack_tools_detected);
    printf("  Packets dropped: %lu\n", stats.packets_dropped);
    printf("  Packets rate limited: %lu\n", stats.packets_rate_limited);
}

uint32_t signatures_get_amplification_list(struct amplification_sig *sigs, uint32_t max) {
    if (!sigs) return 0;

    uint32_t count = 0;
    for (uint32_t i = 0; i < NUM_AMPLIFICATION_SIGS && count < max; i++) {
        memcpy(&sigs[count], &amplification_sigs[i], sizeof(struct amplification_sig));
        count++;
    }

    return count;
}

const char* signatures_get_description(uint32_t sig_id) {
    if (sig_id >= SIG_ID_AMPLIFICATION_BASE && sig_id < SIG_ID_SCAN_BASE) {
        uint32_t idx = sig_id - SIG_ID_AMPLIFICATION_BASE;
        if (idx < NUM_AMPLIFICATION_SIGS) {
            return amplification_sigs[idx].name;
        }
    } else if (sig_id >= SIG_ID_SCAN_BASE && sig_id < SIG_ID_ANOMALY_BASE) {
        switch (sig_id - SIG_ID_SCAN_BASE) {
            case 1: return "TCP SYN scan";
            case 2: return "TCP FIN scan";
            case 3: return "UDP scan";
        }
    } else if (sig_id >= SIG_ID_ANOMALY_BASE && sig_id < SIG_ID_TOOL_BASE) {
        switch (sig_id - SIG_ID_ANOMALY_BASE) {
            case 1: return "TCP NULL scan";
            case 2: return "TCP XMAS scan";
            case 3: return "Invalid SYN+FIN";
            case 4: return "Invalid SYN+RST";
            case 10: return "TTL=1 anomaly";
            case 11: return "Low TTL anomaly";
        }
    } else if (sig_id >= SIG_ID_TOOL_BASE) {
        switch (sig_id - SIG_ID_TOOL_BASE) {
            case 1: return "Generic UDP flood tool";
            case 10: return "Potential Mirai DNS";
            case 20: return "GRE flood";
        }
    }

    return "Unknown signature";
}
