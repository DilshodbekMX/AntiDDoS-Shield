#ifndef LAYER1_SYN_PROXY_H
#define LAYER1_SYN_PROXY_H

#include "../../common/types.h"
#include "../interlayer/shared_memory.h"
#include <stdint.h>
#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

/**
 * @file syn_proxy.h
 * @brief TCP SYN Proxy for DDoS Protection
 */

// ==================== Configuration ====================

/**
 * Adaptive mode states for SYN proxy
 * STATEFUL: Normal mode - creates hash entry for each SYN (better TCP options)
 * STATELESS: Attack mode - no hash entry for SYN, only on valid ACK (faster)
 */
enum syn_proxy_mode {
    SYN_PROXY_MODE_STATEFUL = 0,   // Normal: hash lookup + insert for each SYN
    SYN_PROXY_MODE_STATELESS = 1,  // Attack: no hash ops for SYN, only cookie
};

struct syn_proxy_config {
    uint32_t max_connections;
    uint32_t connect_timeout_ms;
    uint32_t idle_timeout_sec;
    uint32_t secret;
    uint32_t secret_rotation_sec;
    bool     enabled;

    // Adaptive mode thresholds
    uint32_t stateless_threshold_pps;  // Switch to stateless above this SYN rate
    uint32_t stateful_threshold_pps;   // Switch back to stateful below this rate
    uint32_t mode_switch_delay_ms;     // Hysteresis delay before switching modes

    // Challenge threshold: SYN rate above which all new connections are challenged
    uint32_t challenge_threshold;      // PPS threshold for forced cookie challenge
};

// ==================== NOTE: enum syn_proxy_state is in types.h ====================
// ==================== NOTE: enum syn_proxy_action is in types.h ====================

// ==================== TCP Options ====================

struct tcp_syn_options {
    uint16_t mss;
    uint8_t  wscale;
    bool     sack_permitted;
    bool     timestamp_present;
    uint32_t tsval;
    uint32_t tsecr;
};

// ==================== Connection State ====================

struct syn_proxy_conn {
    uint32_t client_ip;
    uint32_t server_ip;
    uint16_t client_port;
    uint16_t server_port;
    
    enum syn_proxy_state state;
    uint64_t state_change_tsc;
    
    uint32_t client_isn;
    uint32_t cookie_isn;
    uint32_t client_next_seq;
    uint32_t client_next_ack;
    
    uint32_t proxy_isn;
    uint32_t server_isn;
    uint32_t server_next_seq;
    uint32_t server_next_ack;
    
    int32_t seq_delta_c2s;
    int32_t seq_delta_s2c;
    
    struct tcp_syn_options client_opts;
    
    uint64_t created_tsc;
    uint64_t last_client_tsc;
    uint64_t last_server_tsc;
    
    uint64_t packets_c2s;
    uint64_t packets_s2c;
    uint64_t bytes_c2s;
    uint64_t bytes_s2c;
    
    uint8_t  syn_retries;
    uint8_t  _pad[3];
    
} __attribute__((aligned(64)));

// ==================== Result Structure ====================

struct syn_proxy_result {
    enum syn_proxy_action action;
    bool packet_modified;
    struct rte_mbuf *reply_pkt;
    enum syn_proxy_state conn_state;
    uint32_t conn_id;
};

// ==================== Statistics ====================

struct syn_proxy_stats {
    uint64_t connections_created;
    uint64_t connections_established;
    uint64_t connections_closed;
    uint64_t connections_timeout;
    uint32_t connections_active;

    uint64_t cookies_sent;
    uint64_t cookies_valid;
    uint64_t cookies_invalid;
    uint64_t cookies_invalid_logged;
    uint64_t cookies_expired;

    uint64_t packets_proxied_c2s;
    uint64_t packets_proxied_s2c;
    uint64_t packets_bypassed;

    uint64_t server_connect_failed;
    uint64_t server_timeout;
    uint64_t seq_translation_errors;
    uint64_t table_full_drops;
    uint64_t synack_rate_limited;  // SYN-ACKs dropped due to rate limit

    // Adaptive mode statistics
    enum syn_proxy_mode current_mode;
    uint64_t mode_switches;           // Total mode switches
    uint64_t stateless_syns;          // SYNs handled in stateless mode
    uint64_t stateful_syns;           // SYNs handled in stateful mode
    uint32_t current_syn_rate;        // Current SYN rate (PPS)

    // Spoofed-mode challenge counters
    uint64_t challenged_spoofed_mode; // SYNs challenged because spoofed attack mode active
};

// ==================== Public API ====================

/**
 * Check if SYN proxy is enabled
 */
bool syn_proxy_is_enabled(void);
void syn_proxy_set_enabled(bool enabled);

int syn_proxy_init(const struct syn_proxy_config *config);
void syn_proxy_cleanup(void);

int syn_proxy_process_packet(struct rte_mbuf *m,
                             struct packet_features *features,
                             uint8_t direction,
                             struct rte_mempool *mempool,
                             struct syn_proxy_result *result,
                             uint16_t port_id,
                             const struct per_ip_anomaly_snapshot *ip_anom);

bool syn_proxy_is_proxied(const struct packet_features *features, uint8_t direction);

int syn_proxy_close_connection(uint32_t client_ip, uint32_t server_ip,
                               uint16_t client_port, uint16_t server_port);

uint32_t syn_proxy_cleanup_connections(void);
void syn_proxy_rotate_secret(uint32_t new_secret);
bool syn_proxy_should_challenge(const struct packet_features *features,
                                const struct per_ip_anomaly_snapshot *ip_anom);

void syn_proxy_get_stats(struct syn_proxy_stats *stats);
void syn_proxy_reset_stats(void);
void syn_proxy_print_stats(void);
void syn_proxy_clear_all(void);

/**
 * Get current adaptive mode
 */
enum syn_proxy_mode syn_proxy_get_mode(void);

/**
 * Force a specific mode (for testing/override)
 * Pass SYN_PROXY_MODE_STATEFUL or SYN_PROXY_MODE_STATELESS
 * Pass -1 to return to adaptive (automatic) mode
 */
void syn_proxy_set_mode(int mode);

/**
 * Initialize spoofed-source rate limiting module.
 *
 * @param legitimate_table_size  Max entries in the legitimate IP table (0 = default)
 * @return 0 on success, -1 on error
 */
int spoofed_rate_init(uint32_t legitimate_table_size);

/**
 * Check if a packet should be rate-limited under spoofed-source attack conditions.
 * Used when per-flow rate limiting is not viable due to spoofed source IPs.
 *
 * @param features      Packet features
 * @param has_prior_flow True if packet matches a pre-existing (not just-created) flow
 * @return RL_ACCEPT, RL_DROP_PPS, or RL_DROP_BPS
 */
enum rate_limit_action spoofed_rate_check(const struct packet_features *features,
                                          bool has_prior_flow);

/**
 * Cleanup spoofed-source rate limiting module and free resources.
 */
void spoofed_rate_cleanup(void);

#endif // LAYER1_SYN_PROXY_H