#include "tcp_fingerprint.h"
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_jhash.h>
#include <string.h>
#include <netinet/in.h>

#define RTE_LOGTYPE_TCPFP RTE_LOGTYPE_USER5

// ==================== State ====================

static bool initialized = false;

// Per-lcore fingerprint statistics (avoid atomics in fast path)
struct fp_lcore_stats {
    uint64_t category_counts[FP_CAT_MAX];
    uint64_t total_count;
    uint64_t attack_tool_count;
    uint64_t anomalous_count;
    uint64_t _pad[4];
} __rte_cache_aligned;

static struct fp_lcore_stats *lcore_stats = NULL;

// ==================== Known Signatures ====================

/**
 * Known attack tool signatures
 * Format: {initial_ttl, wscale, mss, window_size, options_sig, quirks}
 */
static const struct {
    struct tcp_fingerprint fp;
    const char *name;
} known_attack_tools[] = {
    // hping3 default
    {{64, 255, 0, 512, 0, FP_QUIRK_DF}, "hping3"},
    // masscan default (TTL=64, no options)
    {{64, 255, 1460, 1024, FP_OPT_MSS, FP_QUIRK_DF}, "masscan"},
    // nmap SYN scan default
    {{64, 10, 1460, 1024, FP_OPT_MSS | FP_OPT_WSCALE | FP_OPT_SACK_PERM | FP_OPT_TIMESTAMP, 0}, "nmap"},
    // Mirai botnet (simplified)
    {{64, 255, 1460, 65535, FP_OPT_MSS, 0}, "mirai-like"},
    // SYN flood tool (no options, small window)
    {{64, 255, 0, 64, 0, 0}, "synflood-tool"},
    // Random TTL with options mismatch (likely spoofed)
    {{128, 255, 0, 0, 0, 0}, "spoofed-null"},
};

#define NUM_ATTACK_TOOLS (sizeof(known_attack_tools) / sizeof(known_attack_tools[0]))

// ==================== TTL Heuristics ====================

/**
 * Estimate initial TTL from received TTL
 * Common initial TTL values: 32, 64, 128, 255
 */
static inline uint8_t estimate_initial_ttl(uint8_t received_ttl) {
    if (received_ttl <= 32) return 32;
    if (received_ttl <= 64) return 64;
    if (received_ttl <= 128) return 128;
    return 255;
}

// ==================== Initialization ====================

int tcp_fingerprint_init(uint32_t max_fingerprints) {
    (void)max_fingerprints;  // Reserved for future fingerprint tracking hash

    if (initialized) {
        return 0;
    }

    // Allocate per-lcore stats
    lcore_stats = rte_zmalloc_socket("fp_lcore_stats",
                                      sizeof(struct fp_lcore_stats) * RTE_MAX_LCORE,
                                      RTE_CACHE_LINE_SIZE,
                                      SOCKET_ID_ANY);
    if (!lcore_stats) {
        RTE_LOG(ERR, TCPFP, "Failed to allocate per-lcore stats\n");
        return -1;
    }

    initialized = true;
    RTE_LOG(INFO, TCPFP, "TCP fingerprinting initialized\n");
    return 0;
}

void tcp_fingerprint_cleanup(void) {
    if (!initialized) return;

    if (lcore_stats) {
        rte_free(lcore_stats);
        lcore_stats = NULL;
    }

    initialized = false;
    RTE_LOG(INFO, TCPFP, "TCP fingerprinting cleanup complete\n");
}

// ==================== Fingerprint Extraction ====================

int tcp_fingerprint_extract(const struct packet_features *features,
                            struct tcp_fingerprint *fp) {
    if (!features || !fp) {
        return -1;
    }

    // Must be TCP SYN packet
    if (features->protocol != IPPROTO_TCP ||
        !(features->tcp_flags & TCP_FLAG_SYN) ||
        (features->tcp_flags & TCP_FLAG_ACK)) {
        return -1;
    }

    memset(fp, 0, sizeof(*fp));

    // Estimate initial TTL
    fp->initial_ttl = estimate_initial_ttl(features->ttl);

    // Window size
    fp->window_size = features->tcp_window;

    // MSS (from parsed options)
    fp->mss = features->tcp_mss;
    if (fp->mss > 0) {
        fp->options_sig |= FP_OPT_MSS;
    }

    // Window scale
    if (features->tcp_wscale > 0) {
        fp->window_scale = features->tcp_wscale;
        fp->options_sig |= FP_OPT_WSCALE;
    } else {
        fp->window_scale = 255;  // Not present marker
    }

    // SACK permitted
    if (features->tcp_sack_perm) {
        fp->options_sig |= FP_OPT_SACK_PERM;
    }

    // Quirks detection
    if (features->ip_id == 0) {
        fp->quirks |= FP_QUIRK_ZERO_ID;
    }
    if (features->ip_flags & 0x4000) {  // DF flag
        fp->quirks |= FP_QUIRK_DF;
        if (features->ip_id != 0) {
            fp->quirks |= FP_QUIRK_NZ_ID_DF;  // Non-zero ID with DF is unusual
        }
    }
    if (features->tcp_ack != 0) {
        fp->quirks |= FP_QUIRK_NZ_ACK;  // Non-zero ACK in SYN
    }
    if ((features->tcp_flags & TCP_FLAG_URG) && features->tcp_seq == 0) {
        fp->quirks |= FP_QUIRK_NZ_URG;
    }
    if (features->tcp_flags & TCP_FLAG_ECE) {
        fp->quirks |= FP_QUIRK_ECNCE;
    }

    return 0;
}

// ==================== Classification ====================

enum fp_category tcp_fingerprint_classify(const struct tcp_fingerprint *fp) {
    if (!fp) return FP_CAT_UNKNOWN;

    // Check for attack tools first (most important)
    if (tcp_fingerprint_is_attack_tool(fp)) {
        return FP_CAT_ATTACK_TOOL;
    }

    // Check for anomalous fingerprints
    if (tcp_fingerprint_is_anomalous(fp)) {
        return FP_CAT_ANOMALOUS;
    }

    // Heuristic OS classification based on common patterns

    // Windows: TTL 128, specific window sizes, typically has MSS
    if (fp->initial_ttl == 128) {
        if (fp->window_size == 8192 || fp->window_size == 16384 ||
            fp->window_size == 65535 || fp->window_size == 64240) {
            return FP_CAT_WINDOWS;
        }
    }

    // Linux: TTL 64, window scale, SACK, timestamps common
    if (fp->initial_ttl == 64) {
        if ((fp->options_sig & (FP_OPT_WSCALE | FP_OPT_SACK_PERM | FP_OPT_TIMESTAMP)) ==
            (FP_OPT_WSCALE | FP_OPT_SACK_PERM | FP_OPT_TIMESTAMP)) {
            // Could be Linux or Android
            if (fp->mss == 1460 || fp->mss == 1448) {
                return FP_CAT_LINUX;
            }
        }
    }

    // macOS/iOS: TTL 64, large window, specific patterns
    if (fp->initial_ttl == 64 && fp->window_scale != 255) {
        if (fp->window_size == 65535 && fp->window_scale >= 5) {
            return FP_CAT_MACOS;
        }
    }

    // FreeBSD: TTL 64, different default window
    if (fp->initial_ttl == 64 && fp->window_size == 65535) {
        if (fp->window_scale == 6 && (fp->options_sig & FP_OPT_SACK_PERM)) {
            return FP_CAT_FREEBSD;
        }
    }

    return FP_CAT_UNKNOWN;
}

bool tcp_fingerprint_is_attack_tool(const struct tcp_fingerprint *fp) {
    if (!fp) return false;

    for (size_t i = 0; i < NUM_ATTACK_TOOLS; i++) {
        const struct tcp_fingerprint *known = &known_attack_tools[i].fp;

        // Check key fields (allow some flexibility)
        if (fp->initial_ttl == known->initial_ttl &&
            fp->mss == known->mss &&
            fp->window_size == known->window_size &&
            (known->options_sig == 0 || fp->options_sig == known->options_sig)) {
            return true;
        }
    }

    // Additional heuristics for attack tools

    // No TCP options at all (most real stacks have at least MSS)
    if (fp->options_sig == 0 && fp->mss == 0) {
        return true;
    }

    // Very small window with no options (typical of SYN flood tools)
    if (fp->window_size < 128 && fp->options_sig == 0) {
        return true;
    }

    return false;
}

bool tcp_fingerprint_is_anomalous(const struct tcp_fingerprint *fp) {
    if (!fp) return false;

    // Non-zero ACK in pure SYN is suspicious
    if (fp->quirks & FP_QUIRK_NZ_ACK) {
        return true;
    }

    // Window size 0 is anomalous for SYN
    if (fp->window_size == 0) {
        return true;
    }

    // MSS of 0 or 1 is invalid
    if (fp->mss == 1) {
        return true;
    }

    // MSS too large (> 9000 for jumbo frames)
    if (fp->mss > 9000) {
        return true;
    }

    // Window scale > 14 is invalid (RFC 7323)
    if (fp->window_scale != 255 && fp->window_scale > 14) {
        return true;
    }

    // TTL 255 with no DF flag and no options (rare legitimate)
    if (fp->initial_ttl == 255 && !(fp->quirks & FP_QUIRK_DF) &&
        fp->options_sig == 0) {
        return true;
    }

    return false;
}

// ==================== Recording & Statistics ====================

void tcp_fingerprint_record(const struct tcp_fingerprint *fp) {
    if (!initialized || !fp) return;

    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= RTE_MAX_LCORE) lcore_id = 0;

    struct fp_lcore_stats *stats = &lcore_stats[lcore_id];

    // Classify and record
    enum fp_category cat = tcp_fingerprint_classify(fp);
    stats->category_counts[cat]++;
    stats->total_count++;

    if (tcp_fingerprint_is_attack_tool(fp)) {
        stats->attack_tool_count++;
    }
    if (tcp_fingerprint_is_anomalous(fp)) {
        stats->anomalous_count++;
    }
}

void tcp_fingerprint_get_stats(uint64_t *category_counts, uint64_t *total_count) {
    uint64_t total = 0;
    uint64_t cats[FP_CAT_MAX] = {0};

    if (!initialized) {
        if (total_count) *total_count = 0;
        return;
    }

    // Aggregate from all lcores
    unsigned int lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        struct fp_lcore_stats *stats = &lcore_stats[lcore_id];
        total += stats->total_count;
        for (int i = 0; i < FP_CAT_MAX; i++) {
            cats[i] += stats->category_counts[i];
        }
    }

    if (category_counts) {
        memcpy(category_counts, cats, sizeof(cats));
    }
    if (total_count) {
        *total_count = total;
    }
}

bool tcp_fingerprint_distribution_anomalous(void) {
    if (!initialized) return false;

    uint64_t total = 0;
    uint64_t attack_tools = 0;
    uint64_t anomalous = 0;

    unsigned int lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        struct fp_lcore_stats *stats = &lcore_stats[lcore_id];
        total += stats->total_count;
        attack_tools += stats->attack_tool_count;
        anomalous += stats->anomalous_count;
    }

    if (total < 100) {
        return false;  // Not enough data
    }

    // Anomalous if > 10% attack tools or > 5% anomalous
    double attack_pct = (double)attack_tools / total * 100.0;
    double anomalous_pct = (double)anomalous / total * 100.0;

    return (attack_pct > 10.0 || anomalous_pct > 5.0);
}

const char* tcp_fingerprint_category_str(enum fp_category cat) {
    static const char *names[] = {
        "unknown",
        "windows",
        "linux",
        "macos",
        "android",
        "freebsd",
        "attack_tool",
        "bot",
        "scanner",
        "anomalous"
    };

    if (cat < FP_CAT_MAX) {
        return names[cat];
    }
    return "invalid";
}
