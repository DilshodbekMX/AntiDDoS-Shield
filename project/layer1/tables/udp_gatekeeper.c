#include "udp_gatekeeper.h"
#include "count_min_sketch.h"
#include "ip_lists.h"
#include "../interlayer/reputation_interface.h"
#include "../interlayer/shared_memory.h"
#include <rte_log.h>
#include <rte_cycles.h>
#include <string.h>

#define RTE_LOGTYPE_UDPGK RTE_LOGTYPE_USER6

// ==================== Global State ====================

static bool initialized = false;
static struct udp_gatekeeper_config config;
static struct udp_gatekeeper_stats stats;

// Separate Count-Min Sketches for PPS and BPS tracking
static struct count_min_sketch cms_pps;
static struct count_min_sketch cms_bps;

// ==================== Initialization ====================

int udp_gatekeeper_init(const struct udp_gatekeeper_config *cfg) {
    if (initialized) {
        RTE_LOG(WARNING, UDPGK, "UDP gatekeeper already initialized\n");
        return 0;
    }

    // Use provided config or defaults
    if (cfg) {
        memcpy(&config, cfg, sizeof(config));
    } else {
        // Set defaults
        config.pps_threshold = UDP_GK_DEFAULT_PPS_THRESHOLD;
        config.bps_threshold = UDP_GK_DEFAULT_BPS_THRESHOLD;
        config.cms_width = UDP_GK_DEFAULT_CMS_WIDTH;
        config.cms_depth = UDP_GK_DEFAULT_CMS_DEPTH;
        config.window_sec = UDP_GK_DEFAULT_WINDOW_SEC;
        config.check_reputation = true;
        config.reputation_threshold = UDP_GK_DEFAULT_REP_THRESHOLD;
        config.check_blacklist = true;
        config.attack_pps_divisor = UDP_GK_DEFAULT_ATTACK_DIVISOR;
        config.attack_bps_divisor = UDP_GK_DEFAULT_ATTACK_DIVISOR;
    }

    // Validate thresholds
    if (config.pps_threshold == 0) {
        config.pps_threshold = UDP_GK_DEFAULT_PPS_THRESHOLD;
    }
    if (config.bps_threshold == 0) {
        config.bps_threshold = UDP_GK_DEFAULT_BPS_THRESHOLD;
    }

    // Initialize PPS tracker
    if (cms_init(&cms_pps, config.cms_width, config.cms_depth, config.window_sec) < 0) {
        RTE_LOG(ERR, UDPGK, "Failed to initialize PPS Count-Min Sketch\n");
        return -1;
    }

    // Initialize BPS tracker
    if (cms_init(&cms_bps, config.cms_width, config.cms_depth, config.window_sec) < 0) {
        RTE_LOG(ERR, UDPGK, "Failed to initialize BPS Count-Min Sketch\n");
        cms_cleanup(&cms_pps);
        return -1;
    }

    memset(&stats, 0, sizeof(stats));
    initialized = true;

    RTE_LOG(INFO, UDPGK, "UDP Gatekeeper initialized:\n");
    RTE_LOG(INFO, UDPGK, "  PPS threshold: %u (attack: %u)\n",
            config.pps_threshold, config.pps_threshold / config.attack_pps_divisor);
    RTE_LOG(INFO, UDPGK, "  BPS threshold: %u (attack: %u)\n",
            config.bps_threshold, config.bps_threshold / config.attack_bps_divisor);
    RTE_LOG(INFO, UDPGK, "  CMS: %ux%u, window=%us\n",
            config.cms_width, config.cms_depth, config.window_sec);
    RTE_LOG(INFO, UDPGK, "  Memory: %zu KB (x2 for PPS+BPS)\n",
            cms_memory_usage(&cms_pps) / 1024);
    RTE_LOG(INFO, UDPGK, "  Reputation check: %s (threshold=%u)\n",
            config.check_reputation ? "enabled" : "disabled",
            config.reputation_threshold);
    RTE_LOG(INFO, UDPGK, "  Blacklist check: %s\n",
            config.check_blacklist ? "enabled" : "disabled");

    return 0;
}

void udp_gatekeeper_cleanup(void) {
    if (!initialized) {
        return;
    }

    cms_cleanup(&cms_pps);
    cms_cleanup(&cms_bps);
    initialized = false;

    RTE_LOG(INFO, UDPGK, "UDP Gatekeeper cleanup complete\n");
}

// ==================== Hot Path ====================

/**
 * Get effective thresholds based on attack mode
 */
static inline void get_thresholds(uint32_t *pps, uint32_t *bps) {
    if (anomaly_is_active()) {
        // Stricter limits during attack
        *pps = config.pps_threshold / config.attack_pps_divisor;
        *bps = config.bps_threshold / config.attack_bps_divisor;
    } else {
        *pps = config.pps_threshold;
        *bps = config.bps_threshold;
    }
}

enum udp_gk_action udp_gatekeeper_check(uint32_t src_ip, uint16_t packet_size,
                                        const struct per_ip_anomaly_snapshot *ip_anom) {
    (void)ip_anom;  // Reserved for future per-IP threshold adjustment
    if (unlikely(!initialized)) {
        return UDP_GK_ACCEPT;  // Fail open if not initialized
    }

    __atomic_add_fetch(&stats.packets_checked, 1, __ATOMIC_RELAXED);

    // Fast path: Check blacklist first (O(1) hash lookup)
    if (config.check_blacklist) {
        if (ip_blacklist_lookup(src_ip)) {
            __atomic_add_fetch(&stats.drops_blacklist, 1, __ATOMIC_RELAXED);
            return UDP_GK_DROP_BLACKLIST;
        }
    }

    // Check reputation (O(1) hash lookup)
    if (config.check_reputation) {
        struct reputation_result rep;
        reputation_lookup(src_ip, &rep);
        if (rep.found && rep.score < config.reputation_threshold) {
            __atomic_add_fetch(&stats.drops_reputation, 1, __ATOMIC_RELAXED);
            return UDP_GK_DROP_REPUTATION;
        }
    }

    // Get effective thresholds
    uint32_t pps_threshold, bps_threshold;
    get_thresholds(&pps_threshold, &bps_threshold);

    // PPS check: increment and check in one operation
    uint32_t current_pps = cms_add_and_query(&cms_pps, src_ip, 1);
    if (current_pps > pps_threshold) {
        __atomic_add_fetch(&stats.drops_pps, 1, __ATOMIC_RELAXED);
        return UDP_GK_DROP_RATE;
    }

    // BPS check: increment and check in one operation
    uint32_t current_bps = cms_add_and_query(&cms_bps, src_ip, packet_size);
    if (current_bps > bps_threshold) {
        __atomic_add_fetch(&stats.drops_bps, 1, __ATOMIC_RELAXED);
        return UDP_GK_DROP_BPS;
    }

    // All checks passed
    __atomic_add_fetch(&stats.packets_accepted, 1, __ATOMIC_RELAXED);
    return UDP_GK_ACCEPT;
}

enum udp_gk_action udp_gatekeeper_check_detailed(uint32_t src_ip, uint16_t packet_size,
                                                  uint32_t *pps_out, uint32_t *bps_out) {
    if (unlikely(!initialized)) {
        if (pps_out) *pps_out = 0;
        if (bps_out) *bps_out = 0;
        return UDP_GK_ACCEPT;
    }

    __atomic_add_fetch(&stats.packets_checked, 1, __ATOMIC_RELAXED);

    // Blacklist check
    if (config.check_blacklist) {
        if (ip_blacklist_lookup(src_ip)) {
            __atomic_add_fetch(&stats.drops_blacklist, 1, __ATOMIC_RELAXED);
            if (pps_out) *pps_out = 0;
            if (bps_out) *bps_out = 0;
            return UDP_GK_DROP_BLACKLIST;
        }
    }

    // Reputation check
    if (config.check_reputation) {
        struct reputation_result rep;
        reputation_lookup(src_ip, &rep);
        if (rep.found && rep.score < config.reputation_threshold) {
            __atomic_add_fetch(&stats.drops_reputation, 1, __ATOMIC_RELAXED);
            if (pps_out) *pps_out = 0;
            if (bps_out) *bps_out = 0;
            return UDP_GK_DROP_REPUTATION;
        }
    }

    // Get thresholds
    uint32_t pps_threshold, bps_threshold;
    get_thresholds(&pps_threshold, &bps_threshold);

    // PPS check
    uint32_t current_pps = cms_add_and_query(&cms_pps, src_ip, 1);
    if (pps_out) *pps_out = current_pps;

    if (current_pps > pps_threshold) {
        __atomic_add_fetch(&stats.drops_pps, 1, __ATOMIC_RELAXED);
        if (bps_out) *bps_out = cms_query(&cms_bps, src_ip);
        return UDP_GK_DROP_RATE;
    }

    // BPS check
    uint32_t current_bps = cms_add_and_query(&cms_bps, src_ip, packet_size);
    if (bps_out) *bps_out = current_bps;

    if (current_bps > bps_threshold) {
        __atomic_add_fetch(&stats.drops_bps, 1, __ATOMIC_RELAXED);
        return UDP_GK_DROP_BPS;
    }

    __atomic_add_fetch(&stats.packets_accepted, 1, __ATOMIC_RELAXED);
    return UDP_GK_ACCEPT;
}

void udp_gatekeeper_get_rate(uint32_t src_ip, uint32_t *pps_out, uint32_t *bps_out) {
    if (!initialized) {
        if (pps_out) *pps_out = 0;
        if (bps_out) *bps_out = 0;
        return;
    }

    if (pps_out) *pps_out = cms_query(&cms_pps, src_ip);
    if (bps_out) *bps_out = cms_query(&cms_bps, src_ip);
}

// ==================== Statistics ====================

void udp_gatekeeper_get_stats(struct udp_gatekeeper_stats *out) {
    if (!out) {
        return;
    }

    out->packets_checked = __atomic_load_n(&stats.packets_checked, __ATOMIC_RELAXED);
    out->packets_accepted = __atomic_load_n(&stats.packets_accepted, __ATOMIC_RELAXED);
    out->drops_pps = __atomic_load_n(&stats.drops_pps, __ATOMIC_RELAXED);
    out->drops_bps = __atomic_load_n(&stats.drops_bps, __ATOMIC_RELAXED);
    out->drops_reputation = __atomic_load_n(&stats.drops_reputation, __ATOMIC_RELAXED);
    out->drops_blacklist = __atomic_load_n(&stats.drops_blacklist, __ATOMIC_RELAXED);

    // Get CMS stats
    uint64_t pps_updates = 0, rotations = 0;
    cms_get_stats(&cms_pps, &pps_updates, NULL, &rotations);
    out->unique_ips_approx = pps_updates;  // Rough approximation
    out->cms_rotations = rotations;
}

void udp_gatekeeper_print_stats(void) {
    struct udp_gatekeeper_stats s;
    udp_gatekeeper_get_stats(&s);

    uint64_t total_drops = s.drops_pps + s.drops_bps + s.drops_reputation + s.drops_blacklist;
    double drop_rate = s.packets_checked > 0 ?
                       (double)total_drops / s.packets_checked * 100.0 : 0.0;

    printf("  UDP Gatekeeper:\n");
    printf("    Checked:   %lu\n", s.packets_checked);
    printf("    Accepted:  %lu\n", s.packets_accepted);
    printf("    Drops:     %lu (%.2f%%)\n", total_drops, drop_rate);
    printf("      - PPS:        %lu\n", s.drops_pps);
    printf("      - BPS:        %lu\n", s.drops_bps);
    printf("      - Reputation: %lu\n", s.drops_reputation);
    printf("      - Blacklist:  %lu\n", s.drops_blacklist);
    printf("    CMS rotations: %lu\n", s.cms_rotations);
}

// ==================== Maintenance ====================

void udp_gatekeeper_rotate(void) {
    if (!initialized) {
        return;
    }

    cms_force_rotate(&cms_pps);
    cms_force_rotate(&cms_bps);
}

void udp_gatekeeper_clear(void) {
    if (!initialized) {
        return;
    }

    cms_clear(&cms_pps);
    cms_clear(&cms_bps);
    memset(&stats, 0, sizeof(stats));

    RTE_LOG(INFO, UDPGK, "UDP Gatekeeper cleared\n");
}

void udp_gatekeeper_set_thresholds(uint32_t pps_threshold, uint32_t bps_threshold) {
    if (pps_threshold > 0) {
        config.pps_threshold = pps_threshold;
        RTE_LOG(INFO, UDPGK, "PPS threshold updated to %u\n", pps_threshold);
    }
    if (bps_threshold > 0) {
        config.bps_threshold = bps_threshold;
        RTE_LOG(INFO, UDPGK, "BPS threshold updated to %u\n", bps_threshold);
    }
}

void udp_gatekeeper_get_effective_thresholds(uint32_t *pps_out, uint32_t *bps_out) {
    uint32_t pps, bps;
    get_thresholds(&pps, &bps);
    if (pps_out) *pps_out = pps;
    if (bps_out) *bps_out = bps;
}
