#include "signatures.h"
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_spinlock.h>
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
} __rte_cache_aligned;

static struct sig_lcore_stats lcore_sig_stats[RTE_MAX_LCORE];

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
        // SYN scan: SYN flag only, small packet
        if (tcp_flags == 0x02 && pkt_len <= 60) {
            // This is a heuristic - actual scan detection needs
            // tracking multiple packets from same source
            return SIG_ID_SCAN_BASE + 1;  // Potential SYN scan
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

// ==================== Public API ====================

int signatures_init(const struct signatures_config *config) {
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

    sig_initialized = true;

    RTE_LOG(INFO, SIG, "Signatures initialized (%zu amplification signatures)\n",
            NUM_AMPLIFICATION_SIGS);

    rte_spinlock_unlock(&sig_lock);
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
    (void)src_ip;
    (void)dst_ip;

    if (!sig_initialized || !sig_cfg.enabled) {
        return false;
    }

    unsigned lcore_id = rte_lcore_id();
    if (lcore_id < RTE_MAX_LCORE) {
        lcore_sig_stats[lcore_id].packets_checked++;
    }

    uint32_t sig_id = 0;
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
