#include "other_protocols.h"
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
#include <string.h>
#include <stdio.h>

#define RTE_LOGTYPE_PROTO RTE_LOGTYPE_USER5

/**
 * Other Protocols Filter Implementation
 *
 * Filters IP protocols other than TCP, UDP, and ICMP.
 * Uses a bitmap for O(1) allowed protocol lookup.
 * Rate limiting uses a token bucket per protocol.
 */

// ==================== Global State ====================

static bool proto_initialized = false;
static struct other_proto_config proto_cfg;
static rte_spinlock_t proto_lock = RTE_SPINLOCK_INITIALIZER;

// Allowed protocols bitmap (256 bits = 32 bytes)
static uint8_t allowed_bitmap[32];

// Rate limiting token bucket
static struct {
    uint64_t last_update_tsc;
    uint64_t tokens;
    uint64_t rate_pps;
    uint64_t tsc_hz;
} rate_limiter;

// Per-lcore statistics
struct proto_lcore_stats {
    uint64_t total_packets;
    uint64_t allowed_packets;
    uint64_t dropped_packets;
    uint64_t rate_limited_packets;
    uint64_t per_protocol[256];
} __rte_cache_aligned;

static struct proto_lcore_stats lcore_proto_stats[RTE_MAX_LCORE];

// ==================== Protocol Names ====================

static const char* protocol_names[] = {
    [0] = "HOPOPT",
    [1] = "ICMP",
    [2] = "IGMP",
    [3] = "GGP",
    [4] = "IP-in-IP",
    [5] = "ST",
    [6] = "TCP",
    [7] = "CBT",
    [8] = "EGP",
    [9] = "IGP",
    [17] = "UDP",
    [27] = "RDP",
    [41] = "IPv6",
    [43] = "IPv6-Route",
    [44] = "IPv6-Frag",
    [46] = "RSVP",
    [47] = "GRE",
    [50] = "ESP",
    [51] = "AH",
    [58] = "ICMPv6",
    [59] = "IPv6-NoNxt",
    [60] = "IPv6-Opts",
    [88] = "EIGRP",
    [89] = "OSPF",
    [94] = "IPIP",
    [97] = "ETHERIP",
    [103] = "PIM",
    [112] = "VRRP",
    [115] = "L2TP",
    [132] = "SCTP",
    [136] = "UDPLite",
    [137] = "MPLS-in-IP",
};

const char* other_proto_name(uint8_t protocol) {
    if (protocol < sizeof(protocol_names)/sizeof(protocol_names[0]) &&
        protocol_names[protocol] != NULL) {
        return protocol_names[protocol];
    }
    return "Unknown";
}

// ==================== Bitmap Operations ====================

static inline void bitmap_set(uint8_t protocol) {
    allowed_bitmap[protocol / 8] |= (1 << (protocol % 8));
}

static inline void bitmap_clear(uint8_t protocol) {
    allowed_bitmap[protocol / 8] &= ~(1 << (protocol % 8));
}

static inline bool bitmap_test(uint8_t protocol) {
    return (allowed_bitmap[protocol / 8] & (1 << (protocol % 8))) != 0;
}

// ==================== Rate Limiting ====================

static bool check_rate_limit(void) {
    if (proto_cfg.rate_limit_pps == 0) {
        return true;  // No rate limit
    }

    uint64_t now = rte_get_tsc_cycles();
    uint64_t elapsed = now - rate_limiter.last_update_tsc;

    // Add tokens based on elapsed time
    uint64_t new_tokens = (elapsed * rate_limiter.rate_pps) / rate_limiter.tsc_hz;

    if (new_tokens > 0) {
        rate_limiter.tokens += new_tokens;
        if (rate_limiter.tokens > rate_limiter.rate_pps) {
            rate_limiter.tokens = rate_limiter.rate_pps;  // Cap at burst size
        }
        rate_limiter.last_update_tsc = now;
    }

    if (rate_limiter.tokens > 0) {
        rate_limiter.tokens--;
        return true;  // Allowed
    }

    return false;  // Rate limited
}

// ==================== Public API ====================

int other_proto_init(const struct other_proto_config *config) {
    if (proto_initialized) {
        RTE_LOG(WARNING, PROTO, "Other protocols filter already initialized\n");
        return 0;
    }

    rte_spinlock_lock(&proto_lock);

    // Copy configuration
    memcpy(&proto_cfg, config, sizeof(proto_cfg));

    // Initialize allowed bitmap
    memset(allowed_bitmap, 0, sizeof(allowed_bitmap));

    // TCP, UDP, ICMP are always handled by main pipeline, mark them
    // but they won't reach this filter
    bitmap_set(1);   // ICMP
    bitmap_set(6);   // TCP
    bitmap_set(17);  // UDP

    // Add configured allowed protocols
    for (uint32_t i = 0; i < config->allowed_count && i < OTHER_PROTO_MAX_ALLOWED; i++) {
        bitmap_set(config->allowed_protocols[i]);
    }

    // Initialize rate limiter
    rate_limiter.tsc_hz = rte_get_tsc_hz();
    rate_limiter.last_update_tsc = rte_get_tsc_cycles();
    rate_limiter.tokens = config->rate_limit_pps;
    rate_limiter.rate_pps = config->rate_limit_pps;

    // Initialize per-lcore stats
    memset(lcore_proto_stats, 0, sizeof(lcore_proto_stats));

    proto_initialized = true;

    RTE_LOG(INFO, PROTO, "Other protocols filter initialized (action=%s, allowed=%u, rate=%u pps)\n",
            config->default_action == OTHER_PROTO_DROP ? "drop" :
            (config->default_action == OTHER_PROTO_ACCEPT ? "accept" : "rate_limit"),
            config->allowed_count,
            config->rate_limit_pps);

    rte_spinlock_unlock(&proto_lock);
    return 0;
}

void other_proto_cleanup(void) {
    if (!proto_initialized) return;

    rte_spinlock_lock(&proto_lock);
    proto_initialized = false;
    RTE_LOG(INFO, PROTO, "Other protocols filter cleanup complete\n");
    rte_spinlock_unlock(&proto_lock);
}

bool other_proto_should_drop(uint8_t protocol, uint32_t src_ip) {
    (void)src_ip;  // Reserved for per-IP rate limiting in future

    if (!proto_initialized || !proto_cfg.enabled) {
        return false;  // Disabled = allow all
    }

    // Skip if it's TCP, UDP, or ICMP (handled by main pipeline)
    if (protocol == 6 || protocol == 17 || protocol == 1) {
        return false;
    }

    unsigned lcore_id = rte_lcore_id();
    if (lcore_id < RTE_MAX_LCORE) {
        lcore_proto_stats[lcore_id].total_packets++;
        lcore_proto_stats[lcore_id].per_protocol[protocol]++;
    }

    // Check if protocol is in allowed list
    bool is_allowed = bitmap_test(protocol);

    if (is_allowed) {
        // Protocol is explicitly allowed
        if (lcore_id < RTE_MAX_LCORE) {
            lcore_proto_stats[lcore_id].allowed_packets++;
        }
        return false;
    }

    // Protocol not in allowed list, apply default action
    switch (proto_cfg.default_action) {
        case OTHER_PROTO_ACCEPT:
            if (lcore_id < RTE_MAX_LCORE) {
                lcore_proto_stats[lcore_id].allowed_packets++;
            }
            return false;

        case OTHER_PROTO_DROP:
            if (lcore_id < RTE_MAX_LCORE) {
                lcore_proto_stats[lcore_id].dropped_packets++;
            }
            if (proto_cfg.log_unknown) {
                static uint64_t log_count = 0;
                if (__atomic_add_fetch(&log_count, 1, __ATOMIC_RELAXED) <= 10) {
                    RTE_LOG(INFO, PROTO, "Dropping protocol %u (%s)\n",
                            protocol, other_proto_name(protocol));
                }
            }
            return true;

        case OTHER_PROTO_RATE_LIMIT:
            if (check_rate_limit()) {
                if (lcore_id < RTE_MAX_LCORE) {
                    lcore_proto_stats[lcore_id].allowed_packets++;
                }
                return false;
            } else {
                if (lcore_id < RTE_MAX_LCORE) {
                    lcore_proto_stats[lcore_id].rate_limited_packets++;
                }
                return true;
            }
    }

    return false;
}

int other_proto_add_allowed(uint8_t protocol) {
    if (!proto_initialized) return -1;

    rte_spinlock_lock(&proto_lock);

    if (!bitmap_test(protocol)) {
        if (proto_cfg.allowed_count < OTHER_PROTO_MAX_ALLOWED) {
            proto_cfg.allowed_protocols[proto_cfg.allowed_count++] = protocol;
            bitmap_set(protocol);
            RTE_LOG(INFO, PROTO, "Added protocol %u (%s) to allowed list\n",
                    protocol, other_proto_name(protocol));
        }
    }

    rte_spinlock_unlock(&proto_lock);
    return 0;
}

int other_proto_remove_allowed(uint8_t protocol) {
    if (!proto_initialized) return -1;

    // Don't allow removing TCP/UDP/ICMP
    if (protocol == 1 || protocol == 6 || protocol == 17) {
        return -1;
    }

    rte_spinlock_lock(&proto_lock);

    bitmap_clear(protocol);

    // Remove from config array
    for (uint32_t i = 0; i < proto_cfg.allowed_count; i++) {
        if (proto_cfg.allowed_protocols[i] == protocol) {
            for (uint32_t j = i; j < proto_cfg.allowed_count - 1; j++) {
                proto_cfg.allowed_protocols[j] = proto_cfg.allowed_protocols[j + 1];
            }
            proto_cfg.allowed_count--;
            RTE_LOG(INFO, PROTO, "Removed protocol %u from allowed list\n", protocol);
            rte_spinlock_unlock(&proto_lock);
            return 0;
        }
    }

    rte_spinlock_unlock(&proto_lock);
    return -1;
}

void other_proto_clear_allowed(void) {
    if (!proto_initialized) return;

    rte_spinlock_lock(&proto_lock);

    memset(allowed_bitmap, 0, sizeof(allowed_bitmap));
    // Keep TCP/UDP/ICMP marked (they're handled elsewhere anyway)
    bitmap_set(1);
    bitmap_set(6);
    bitmap_set(17);
    proto_cfg.allowed_count = 0;

    RTE_LOG(INFO, PROTO, "Cleared all allowed protocols\n");

    rte_spinlock_unlock(&proto_lock);
}

void other_proto_set_action(enum other_proto_action action) {
    if (!proto_initialized) return;

    rte_spinlock_lock(&proto_lock);
    proto_cfg.default_action = action;
    RTE_LOG(INFO, PROTO, "Default action set to %s\n",
            action == OTHER_PROTO_DROP ? "drop" :
            (action == OTHER_PROTO_ACCEPT ? "accept" : "rate_limit"));
    rte_spinlock_unlock(&proto_lock);
}

void other_proto_set_rate_limit(uint32_t pps) {
    if (!proto_initialized) return;

    rte_spinlock_lock(&proto_lock);
    proto_cfg.rate_limit_pps = pps;
    rate_limiter.rate_pps = pps;
    RTE_LOG(INFO, PROTO, "Rate limit set to %u pps\n", pps);
    rte_spinlock_unlock(&proto_lock);
}

void other_proto_set_enabled(bool enabled) {
    if (!proto_initialized) return;

    rte_spinlock_lock(&proto_lock);
    proto_cfg.enabled = enabled;
    RTE_LOG(INFO, PROTO, "Other protocols filter %s\n", enabled ? "enabled" : "disabled");
    rte_spinlock_unlock(&proto_lock);
}

bool other_proto_is_enabled(void) {
    return proto_initialized && proto_cfg.enabled;
}

void other_proto_get_stats(struct other_proto_stats *stats) {
    if (!stats) return;

    memset(stats, 0, sizeof(*stats));

    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        stats->total_packets += lcore_proto_stats[lcore_id].total_packets;
        stats->allowed_packets += lcore_proto_stats[lcore_id].allowed_packets;
        stats->dropped_packets += lcore_proto_stats[lcore_id].dropped_packets;
        stats->rate_limited_packets += lcore_proto_stats[lcore_id].rate_limited_packets;

        for (int i = 0; i < 256; i++) {
            stats->per_protocol[i] += lcore_proto_stats[lcore_id].per_protocol[i];
        }
    }
}

void other_proto_reset_stats(void) {
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        memset(&lcore_proto_stats[lcore_id], 0, sizeof(lcore_proto_stats[0]));
    }
}

void other_proto_print_stats(void) {
    struct other_proto_stats stats;
    other_proto_get_stats(&stats);

    printf("\n");
    printf("Other Protocols Statistics:\n");
    printf("  Enabled: %s\n", proto_cfg.enabled ? "yes" : "no");
    printf("  Default action: %s\n",
           proto_cfg.default_action == OTHER_PROTO_DROP ? "drop" :
           (proto_cfg.default_action == OTHER_PROTO_ACCEPT ? "accept" : "rate_limit"));
    printf("  Rate limit: %u pps\n", proto_cfg.rate_limit_pps);
    printf("  Total packets: %lu\n", stats.total_packets);
    printf("  Allowed: %lu\n", stats.allowed_packets);
    printf("  Dropped: %lu\n", stats.dropped_packets);
    printf("  Rate limited: %lu\n", stats.rate_limited_packets);

    // Print per-protocol breakdown for protocols seen
    printf("  Per-protocol breakdown:\n");
    for (int i = 0; i < 256; i++) {
        if (stats.per_protocol[i] > 0) {
            printf("    Protocol %3d (%s): %lu\n",
                   i, other_proto_name(i), stats.per_protocol[i]);
        }
    }
}
