#include "tcp_abuse_detection.h"
#include "../config/layer1_config.h"
#include "../interlayer/shared_memory.h"
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <string.h>
#include <stdio.h>

#define RTE_LOGTYPE_TCPABUSE RTE_LOGTYPE_USER6

/**
 * @file tcp_abuse_detection.c
 * @brief TCP Protocol Abuse Detection Implementation
 *
 * Detects 8 types of TCP abuse patterns by tracking per-flow state.
 * Designed to be integrated into flow table for zero-copy access.
 */

// ==================== Global State ====================

static struct tcp_abuse_config g_config;
static uint64_t g_tsc_hz = 0;
static bool g_initialized = false;

// Per-lcore statistics (no atomics in fast path)
struct tcp_abuse_lcore_stats {
    uint64_t packets_checked;
    uint64_t packets_clean;
    uint64_t abuse_detected[8];
    uint64_t drops[8];
    uint64_t rate_limits[8];
    uint64_t _pad[3];
} __attribute__((aligned(64)));

static struct tcp_abuse_lcore_stats g_lcore_stats[RTE_MAX_LCORE];

// ==================== Initialization ====================

int tcp_abuse_init(const struct tcp_abuse_config *config) {
    if (g_initialized) {
        RTE_LOG(WARNING, TCPABUSE, "Already initialized\n");
        return 0;
    }

    g_tsc_hz = rte_get_tsc_hz();

    // Use provided config or get from layer1_config
    if (config) {
        memcpy(&g_config, config, sizeof(g_config));
    } else {
        // Get from layer1_config
        const struct layer1_config *l1cfg = layer1_config_get();
        if (l1cfg) {
            g_config.enabled = l1cfg->tcp_abuse.enabled;
            g_config.report_to_layer4 = l1cfg->tcp_abuse.report_to_layer4;
            g_config.dup_seq_threshold = l1cfg->tcp_abuse.dup_seq_threshold;
            g_config.random_seq_threshold = l1cfg->tcp_abuse.random_seq_threshold;
            g_config.random_ack_threshold = l1cfg->tcp_abuse.random_ack_threshold;
            g_config.zero_window_threshold = l1cfg->tcp_abuse.zero_window_threshold;
            g_config.tiny_window_bytes = l1cfg->tcp_abuse.tiny_window_bytes;
            g_config.small_window_bytes = l1cfg->tcp_abuse.small_window_bytes;
            g_config.same_window_threshold = l1cfg->tcp_abuse.same_window_threshold;
            g_config.same_ack_threshold = l1cfg->tcp_abuse.same_ack_threshold;
            g_config.action_dup_seq = l1cfg->tcp_abuse.action_dup_seq;
            g_config.action_random_seq = l1cfg->tcp_abuse.action_random_seq;
            g_config.action_random_ack = l1cfg->tcp_abuse.action_random_ack;
            g_config.action_zero_window = l1cfg->tcp_abuse.action_zero_window;
            g_config.action_tiny_window = l1cfg->tcp_abuse.action_tiny_window;
            g_config.action_small_window = l1cfg->tcp_abuse.action_small_window;
            g_config.action_same_window = l1cfg->tcp_abuse.action_same_window;
            g_config.action_same_ack = l1cfg->tcp_abuse.action_same_ack;
        } else {
            // Set defaults
            g_config.enabled = true;
            g_config.report_to_layer4 = true;
            g_config.dup_seq_threshold = 150;
            g_config.random_seq_threshold = 45;
            g_config.random_ack_threshold = 45;
            g_config.zero_window_threshold = 5;
            g_config.tiny_window_bytes = 100;
            g_config.small_window_bytes = 2000;
            g_config.same_window_threshold = 150;
            g_config.same_ack_threshold = 150;
            g_config.action_dup_seq = TCP_ABUSE_ACTION_DROP;
            g_config.action_random_seq = TCP_ABUSE_ACTION_DROP;
            g_config.action_random_ack = TCP_ABUSE_ACTION_DROP;
            g_config.action_zero_window = TCP_ABUSE_ACTION_RATE_LIMIT;
            g_config.action_tiny_window = TCP_ABUSE_ACTION_RATE_LIMIT;
            g_config.action_small_window = TCP_ABUSE_ACTION_LOG;
            g_config.action_same_window = TCP_ABUSE_ACTION_DROP;
            g_config.action_same_ack = TCP_ABUSE_ACTION_DROP;
        }
    }

    if (!g_config.enabled) {
        RTE_LOG(INFO, TCPABUSE, "TCP abuse detection disabled\n");
        g_initialized = true;
        return 0;
    }

    memset(g_lcore_stats, 0, sizeof(g_lcore_stats));

    g_initialized = true;

    RTE_LOG(INFO, TCPABUSE, "TCP abuse detection initialized: "
            "dup_seq=%u, random_seq=%u, zero_win=%u, tiny_win=%u\n",
            g_config.dup_seq_threshold, g_config.random_seq_threshold,
            g_config.zero_window_threshold, g_config.tiny_window_bytes);

    return 0;
}

void tcp_abuse_cleanup(void) {
    if (!g_initialized) return;
    g_initialized = false;
    RTE_LOG(INFO, TCPABUSE, "TCP abuse detection cleaned up\n");
}

// ==================== Per-Flow State Management ====================

void tcp_abuse_state_init(struct tcp_abuse_state *state) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
    state->last_reset_tsc = rte_rdtsc();
}

void tcp_abuse_state_reset_counters(struct tcp_abuse_state *state) {
    if (!state) return;

    // Reset per-second counters
    state->dup_seq_count = 0;
    state->dup_ack_count = 0;
    state->same_window_count = 0;

    // Reset per-10-second counters periodically
    // Guard against division by zero if called before tcp_abuse_init()
    uint64_t now_tsc = rte_rdtsc();
    if (unlikely(g_tsc_hz == 0)) return;
    uint64_t elapsed_sec = (now_tsc - state->last_reset_tsc) / g_tsc_hz;

    if (elapsed_sec >= 10) {
        state->seq_jump_count = 0;
        state->ack_jump_count = 0;
        state->zero_window_count = 0;
        state->tiny_window_count = 0;
        state->detected_abuse = 0;
        state->last_reset_tsc = now_tsc;
    }
}

// ==================== Abuse Detection (Hot Path) ====================

enum tcp_abuse_result tcp_abuse_check(struct tcp_abuse_state *state,
                                       uint32_t src_ip,
                                       uint32_t seq_num,
                                       uint32_t ack_num,
                                       uint16_t window,
                                       uint8_t tcp_flags,
                                       uint16_t pkt_len) {
    // Fast path: disabled check
    if (!g_initialized || !g_config.enabled) {
        return TCP_ABUSE_RESULT_ACCEPT;
    }

    if (!state) {
        return TCP_ABUSE_RESULT_ACCEPT;
    }

    unsigned int lcore_id = rte_lcore_id();
    if (lcore_id >= RTE_MAX_LCORE) {
        lcore_id = 0;
    }
    struct tcp_abuse_lcore_stats *lstats = &g_lcore_stats[lcore_id];
    lstats->packets_checked++;

    uint8_t detected = 0;
    enum tcp_abuse_result result = TCP_ABUSE_RESULT_ACCEPT;

    // Convert network byte order to host byte order for comparison
    uint32_t seq_host = rte_be_to_cpu_32(seq_num);
    uint32_t ack_host = rte_be_to_cpu_32(ack_num);

    // Only check if we have previous state (not first packet)
    bool has_prev_state = (state->last_seq != 0 || state->last_ack != 0);

    if (has_prev_state) {
        // ===== Check 1: Duplicate SEQ =====
        if (seq_host == state->last_seq) {
            state->dup_seq_count++;
            if (state->dup_seq_count > g_config.dup_seq_threshold) {
                detected |= TCP_ABUSE_DUP_SEQ;
                lstats->abuse_detected[0]++;
            }
        }

        // ===== Check 2: Random SEQ Jump =====
        if (tcp_abuse_is_seq_jump(state->last_seq, seq_host, pkt_len)) {
            state->seq_jump_count++;
            if (state->seq_jump_count > g_config.random_seq_threshold) {
                detected |= TCP_ABUSE_RANDOM_SEQ;
                lstats->abuse_detected[1]++;
            }
        }

        // ===== Check 3: Duplicate ACK =====
        // Only check ACK if ACK flag is set
        if (tcp_flags & 0x10) {  // ACK flag
            if (ack_host == state->last_ack) {
                state->dup_ack_count++;
                if (state->dup_ack_count > g_config.same_ack_threshold) {
                    detected |= TCP_ABUSE_SAME_ACK;
                    lstats->abuse_detected[7]++;
                }
            }

            // ===== Check 4: Random ACK Jump =====
            if (tcp_abuse_is_ack_jump(state->last_ack, ack_host)) {
                state->ack_jump_count++;
                if (state->ack_jump_count > g_config.random_ack_threshold) {
                    detected |= TCP_ABUSE_RANDOM_ACK;
                    lstats->abuse_detected[2]++;
                }
            }
        }

        // ===== Check 5: Same Window Flood =====
        if (window == state->last_window) {
            state->same_window_count++;
            if (state->same_window_count > g_config.same_window_threshold) {
                detected |= TCP_ABUSE_SAME_WINDOW;
                lstats->abuse_detected[6]++;
            }
        }
    }

    // ===== Check 6: Zero Window =====
    if (window == 0) {
        // Saturate uint8 counter to prevent wraparound
        if (state->zero_window_count < 255) state->zero_window_count++;
        if (state->zero_window_count > g_config.zero_window_threshold) {
            detected |= TCP_ABUSE_ZERO_WINDOW;
            lstats->abuse_detected[3]++;
        }
    }

    // ===== Check 7: Tiny Window =====
    if (window > 0 && window < g_config.tiny_window_bytes) {
        // Saturate uint8 counter to prevent wraparound
        if (state->tiny_window_count < 255) state->tiny_window_count++;
        // Tiny window is concerning even with single occurrence
        if (state->tiny_window_count > 2) {
            detected |= TCP_ABUSE_TINY_WINDOW;
            lstats->abuse_detected[4]++;
        }
    }

    // ===== Check 8: Small Window (log only) =====
    if (window >= g_config.tiny_window_bytes && window < g_config.small_window_bytes) {
        // Don't track count, just flag if consistently small
        // This is a weak signal, just log
        if (state->last_window < g_config.small_window_bytes && window < g_config.small_window_bytes) {
            detected |= TCP_ABUSE_SMALL_WINDOW;
            lstats->abuse_detected[5]++;
        }
    }

    // Update state for next packet
    state->last_seq = seq_host;
    if (tcp_flags & 0x10) {
        state->last_ack = ack_host;
    }
    state->last_window = window;
    state->detected_abuse |= detected;

    // Determine result based on highest priority abuse detected
    if (detected) {
        // Check actions in priority order (most severe first)
        if ((detected & TCP_ABUSE_DUP_SEQ) && g_config.action_dup_seq == TCP_ABUSE_ACTION_DROP) {
            result = TCP_ABUSE_RESULT_DROP;
            lstats->drops[0]++;
        } else if ((detected & TCP_ABUSE_RANDOM_SEQ) && g_config.action_random_seq == TCP_ABUSE_ACTION_DROP) {
            result = TCP_ABUSE_RESULT_DROP;
            lstats->drops[1]++;
        } else if ((detected & TCP_ABUSE_RANDOM_ACK) && g_config.action_random_ack == TCP_ABUSE_ACTION_DROP) {
            result = TCP_ABUSE_RESULT_DROP;
            lstats->drops[2]++;
        } else if ((detected & TCP_ABUSE_SAME_WINDOW) && g_config.action_same_window == TCP_ABUSE_ACTION_DROP) {
            result = TCP_ABUSE_RESULT_DROP;
            lstats->drops[6]++;
        } else if ((detected & TCP_ABUSE_SAME_ACK) && g_config.action_same_ack == TCP_ABUSE_ACTION_DROP) {
            result = TCP_ABUSE_RESULT_DROP;
            lstats->drops[7]++;
        } else if ((detected & TCP_ABUSE_ZERO_WINDOW) && g_config.action_zero_window == TCP_ABUSE_ACTION_DROP) {
            result = TCP_ABUSE_RESULT_DROP;
            lstats->drops[3]++;
        } else if ((detected & TCP_ABUSE_TINY_WINDOW) && g_config.action_tiny_window == TCP_ABUSE_ACTION_DROP) {
            result = TCP_ABUSE_RESULT_DROP;
            lstats->drops[4]++;
        }
        // Check for rate limiting
        else if ((detected & TCP_ABUSE_ZERO_WINDOW) && g_config.action_zero_window == TCP_ABUSE_ACTION_RATE_LIMIT) {
            result = TCP_ABUSE_RESULT_RATE_LIMIT;
            lstats->rate_limits[3]++;
        } else if ((detected & TCP_ABUSE_TINY_WINDOW) && g_config.action_tiny_window == TCP_ABUSE_ACTION_RATE_LIMIT) {
            result = TCP_ABUSE_RESULT_RATE_LIMIT;
            lstats->rate_limits[4]++;
        } else if ((detected & TCP_ABUSE_SMALL_WINDOW) && g_config.action_small_window == TCP_ABUSE_ACTION_RATE_LIMIT) {
            result = TCP_ABUSE_RESULT_RATE_LIMIT;
            lstats->rate_limits[5]++;
        }
        // Otherwise log only
        else {
            result = TCP_ABUSE_RESULT_LOG;
        }

        // Report to Layer 4 if configured
        if (g_config.report_to_layer4 && result != TCP_ABUSE_RESULT_ACCEPT) {
            // Log first few detections
            static uint64_t abuse_log_count = 0;
            if (__atomic_fetch_add(&abuse_log_count, 1, __ATOMIC_RELAXED) < 10) {
                char abuse_str[128];
                tcp_abuse_types_to_string(detected, abuse_str, sizeof(abuse_str));
                RTE_LOG(DEBUG, TCPABUSE, "Abuse detected: IP=0x%08x types=%s\n", src_ip, abuse_str);
            }
        }
    } else {
        lstats->packets_clean++;
    }

    return result;
}

// ==================== Statistics ====================

void tcp_abuse_get_stats(struct tcp_abuse_stats *stats) {
    if (!stats) return;

    memset(stats, 0, sizeof(*stats));

    // Aggregate per-lcore stats
    for (unsigned int i = 0; i < RTE_MAX_LCORE; i++) {
        stats->packets_checked += g_lcore_stats[i].packets_checked;
        stats->packets_clean += g_lcore_stats[i].packets_clean;
        for (int j = 0; j < 8; j++) {
            stats->abuse_detected[j] += g_lcore_stats[i].abuse_detected[j];
            stats->drops[j] += g_lcore_stats[i].drops[j];
            stats->rate_limits[j] += g_lcore_stats[i].rate_limits[j];
        }
    }
}

void tcp_abuse_print_stats(void) {
    struct tcp_abuse_stats stats;
    tcp_abuse_get_stats(&stats);

    printf("=== TCP Abuse Detection Statistics ===\n");
    printf("Enabled: %s\n", g_config.enabled ? "yes" : "no");
    printf("Packets checked: %lu\n", stats.packets_checked);
    printf("Packets clean:   %lu\n", stats.packets_clean);
    printf("\nAbuse detected per type:\n");

    static const char *type_names[] = {
        "DUP_SEQ", "RANDOM_SEQ", "RANDOM_ACK", "ZERO_WIN",
        "TINY_WIN", "SMALL_WIN", "SAME_WIN", "SAME_ACK"
    };

    for (int i = 0; i < 8; i++) {
        printf("  %-12s: detected=%8lu drops=%8lu rate_limit=%8lu\n",
               type_names[i], stats.abuse_detected[i], stats.drops[i], stats.rate_limits[i]);
    }
}

void tcp_abuse_reset_stats(void) {
    memset(g_lcore_stats, 0, sizeof(g_lcore_stats));
}

bool tcp_abuse_is_enabled(void) {
    return g_initialized && g_config.enabled;
}

void tcp_abuse_update_config(const struct tcp_abuse_config *config) {
    if (!config || !g_initialized) return;
    // Temporarily disable to prevent hot path from seeing mixed old/new thresholds.
    // Brief disable window (~1 us for memcpy) lets a few packets bypass -- acceptable.
    g_config.enabled = false;
    rte_smp_wmb();  // Ensure disable is visible before copy

    g_config.report_to_layer4 = config->report_to_layer4;
    g_config.dup_seq_threshold = config->dup_seq_threshold;
    g_config.random_seq_threshold = config->random_seq_threshold;
    g_config.random_ack_threshold = config->random_ack_threshold;
    g_config.zero_window_threshold = config->zero_window_threshold;
    g_config.tiny_window_bytes = config->tiny_window_bytes;
    g_config.small_window_bytes = config->small_window_bytes;
    g_config.same_window_threshold = config->same_window_threshold;
    g_config.same_ack_threshold = config->same_ack_threshold;
    g_config.action_dup_seq = config->action_dup_seq;
    g_config.action_random_seq = config->action_random_seq;
    g_config.action_random_ack = config->action_random_ack;
    g_config.action_zero_window = config->action_zero_window;
    g_config.action_tiny_window = config->action_tiny_window;
    g_config.action_small_window = config->action_small_window;
    g_config.action_same_window = config->action_same_window;
    g_config.action_same_ack = config->action_same_ack;

    rte_smp_wmb();  // Ensure all fields written before re-enabling
    g_config.enabled = config->enabled;
}

// ==================== Name Helpers ====================

const char* tcp_abuse_type_name(enum tcp_abuse_type type) {
    switch (type) {
        case TCP_ABUSE_DUP_SEQ:      return "DUP_SEQ";
        case TCP_ABUSE_RANDOM_SEQ:   return "RANDOM_SEQ";
        case TCP_ABUSE_RANDOM_ACK:   return "RANDOM_ACK";
        case TCP_ABUSE_ZERO_WINDOW:  return "ZERO_WINDOW";
        case TCP_ABUSE_TINY_WINDOW:  return "TINY_WINDOW";
        case TCP_ABUSE_SMALL_WINDOW: return "SMALL_WINDOW";
        case TCP_ABUSE_SAME_WINDOW:  return "SAME_WINDOW";
        case TCP_ABUSE_SAME_ACK:     return "SAME_ACK";
        default:                     return "UNKNOWN";
    }
}

int tcp_abuse_types_to_string(uint8_t types, char *buffer, size_t size) {
    if (!buffer || size == 0) return 0;

    buffer[0] = '\0';
    int written = 0;

    static const char *names[] = {
        "DUP_SEQ", "RANDOM_SEQ", "RANDOM_ACK", "ZERO_WIN",
        "TINY_WIN", "SMALL_WIN", "SAME_WIN", "SAME_ACK"
    };

    bool first = true;
    for (int i = 0; i < 8; i++) {
        if (types & (1 << i)) {
            int n = snprintf(buffer + written, size - written,
                           "%s%s", first ? "" : "|", names[i]);
            if (n > 0 && (size_t)(written + n) < size) {
                written += n;
                first = false;
            }
        }
    }

    return written;
}
