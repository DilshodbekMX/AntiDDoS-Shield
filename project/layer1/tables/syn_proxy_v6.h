/**
 * @file syn_proxy_v6.h
 * @brief IPv6 TCP SYN Proxy for DDoS Protection
 *
 * Extension of syn_proxy.h for IPv6 support.
 * Implements SYN cookies with 128-bit IPv6 addresses.
 */

#ifndef LAYER1_SYN_PROXY_V6_H
#define LAYER1_SYN_PROXY_V6_H

#include "../../common/types.h"
#include "syn_proxy.h"
#include <stdint.h>
#include <stdbool.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== IPv6 Connection State ==================== */

/**
 * IPv6 SYN proxy connection state
 * 192 bytes, cache-line aligned for performance
 */
struct syn_proxy_conn_v6 {
    uint8_t  client_ip[16];     /* Client IPv6 address */
    uint8_t  server_ip[16];     /* Server IPv6 address */
    uint16_t client_port;       /* Client TCP port */
    uint16_t server_port;       /* Server TCP port */

    enum syn_proxy_state state;
    uint64_t state_change_tsc;

    /* Sequence number tracking */
    uint32_t client_isn;        /* Client's initial sequence number */
    uint32_t cookie_isn;        /* Cookie ISN we sent to client */
    uint32_t client_next_seq;
    uint32_t client_next_ack;

    uint32_t proxy_isn;         /* Our ISN to server */
    uint32_t server_isn;        /* Server's ISN */
    uint32_t server_next_seq;
    uint32_t server_next_ack;

    int32_t  seq_delta_c2s;     /* Sequence delta client->server */
    int32_t  seq_delta_s2c;     /* Sequence delta server->client */

    struct tcp_syn_options client_opts;  /* Client's TCP options */

    uint64_t created_tsc;
    uint64_t last_client_tsc;
    uint64_t last_server_tsc;

    uint64_t packets_c2s;
    uint64_t packets_s2c;
    uint64_t bytes_c2s;
    uint64_t bytes_s2c;

    uint8_t  syn_retries;
    uint8_t  _pad[7];

} __rte_cache_aligned;  /* 192 bytes aligned */

/* ==================== IPv6 Result Structure ==================== */

struct syn_proxy_result_v6 {
    enum syn_proxy_action action;
    bool packet_modified;
    struct rte_mbuf *reply_pkt;
    enum syn_proxy_state conn_state;
    uint32_t conn_id;
};

/* ==================== IPv6 Statistics ==================== */

struct syn_proxy_stats_v6 {
    uint64_t connections_created;
    uint64_t connections_established;
    uint64_t connections_closed;
    uint64_t connections_timeout;
    uint32_t connections_active;

    uint64_t cookies_sent;
    uint64_t cookies_valid;
    uint64_t cookies_invalid;
    uint64_t cookies_expired;

    uint64_t packets_proxied_c2s;
    uint64_t packets_proxied_s2c;
    uint64_t packets_bypassed;

    uint64_t server_connect_failed;
    uint64_t server_timeout;
    uint64_t seq_translation_errors;
    uint64_t table_full_drops;

    enum syn_proxy_mode current_mode;
    uint64_t mode_switches;
    uint32_t current_syn_rate;
};

/* ==================== Public API ==================== */

/**
 * Initialize IPv6 SYN proxy
 *
 * @param config  Configuration (uses same struct as IPv4)
 * @return 0 on success, -1 on error
 */
int syn_proxy_v6_init(const struct syn_proxy_config *config);

/**
 * Cleanup IPv6 SYN proxy
 */
void syn_proxy_v6_cleanup(void);

/**
 * Check if IPv6 SYN proxy is enabled
 */
bool syn_proxy_v6_is_enabled(void);

/**
 * Process an IPv6 TCP packet through the SYN proxy
 *
 * @param m         Packet mbuf
 * @param features  IPv6 packet features
 * @param direction Direction (0=client->server, 1=server->client)
 * @param mempool   Mempool for reply packets
 * @param result    Output: processing result
 * @param port_id   DPDK port ID
 * @return 0 on success, -1 on error
 */
int syn_proxy_v6_process_packet(struct rte_mbuf *m,
                                struct packet_features_v6 *features,
                                uint8_t direction,
                                struct rte_mempool *mempool,
                                struct syn_proxy_result_v6 *result,
                                uint16_t port_id);

/**
 * Check if connection is proxied
 *
 * @param features  IPv6 packet features
 * @param direction Direction
 * @return true if connection is being proxied
 */
bool syn_proxy_v6_is_proxied(const struct packet_features_v6 *features,
                             uint8_t direction);

/**
 * Close an IPv6 proxied connection
 *
 * @param client_ip   Client IPv6 address
 * @param server_ip   Server IPv6 address
 * @param client_port Client port
 * @param server_port Server port
 * @return 0 on success, -1 if not found
 */
int syn_proxy_v6_close_connection(const uint8_t client_ip[16],
                                  const uint8_t server_ip[16],
                                  uint16_t client_port,
                                  uint16_t server_port);

/**
 * Cleanup timed-out IPv6 connections
 *
 * @return Number of connections cleaned up
 */
uint32_t syn_proxy_v6_cleanup_connections(void);

/**
 * Rotate IPv6 SYN cookie secret
 *
 * @param new_secret  New secret value
 */
void syn_proxy_v6_rotate_secret(uint32_t new_secret);

/**
 * Check if IPv6 SYN should be challenged
 *
 * @param features  IPv6 packet features
 * @return true if SYN should be challenged with cookie
 */
bool syn_proxy_v6_should_challenge(const struct packet_features_v6 *features);

/**
 * Get IPv6 SYN proxy statistics
 *
 * @param stats  Output: statistics structure
 */
void syn_proxy_v6_get_stats(struct syn_proxy_stats_v6 *stats);

/**
 * Reset IPv6 SYN proxy statistics
 */
void syn_proxy_v6_reset_stats(void);

/**
 * Print IPv6 SYN proxy statistics
 */
void syn_proxy_v6_print_stats(void);

/**
 * Get current adaptive mode
 */
enum syn_proxy_mode syn_proxy_v6_get_mode(void);

/**
 * Set mode (or -1 for adaptive)
 */
void syn_proxy_v6_set_mode(int mode);

/* ==================== Dual-Stack API ==================== */

/**
 * Unified SYN proxy packet processing for both IPv4 and IPv6
 *
 * @param m         Packet mbuf
 * @param is_ipv6   true for IPv6, false for IPv4
 * @param features  Pointer to packet_features or packet_features_v6
 * @param direction Direction
 * @param mempool   Mempool for reply packets
 * @param result    Output: generic result
 * @param port_id   DPDK port ID
 * @return 0 on success, -1 on error
 */
int syn_proxy_process_unified(struct rte_mbuf *m,
                              bool is_ipv6,
                              void *features,
                              uint8_t direction,
                              struct rte_mempool *mempool,
                              struct syn_proxy_result *result,
                              uint16_t port_id);

/**
 * Check if connection is proxied (dual-stack)
 */
bool syn_proxy_is_proxied_unified(const void *features, bool is_ipv6,
                                  uint8_t direction);

/* ==================== Inplace Packet Transform ==================== */

/**
 * Transform an IPv6 SYN packet into a SYN-ACK in place.
 *
 * Swaps Ethernet/IPv6 addresses, sets ACK flag, sets cookie as ISN.
 *
 * @param m       Packet mbuf (modified in place)
 * @param cookie  SYN cookie to use as ISN in the SYN-ACK
 * @return true on success, false if packet too short
 */
bool transform_syn_to_synack_v6_inplace(struct rte_mbuf *m, uint32_t cookie);

/* ==================== SYN Cookie Functions ==================== */

/**
 * Generate IPv6 SYN cookie
 *
 * Cookie = SipHash(secret, client_ip, server_ip, client_port, server_port, time)
 * Encodes MSS index (4 bits) and timestamp (low bits)
 *
 * @param client_ip    Client IPv6 address
 * @param server_ip    Server IPv6 address
 * @param client_port  Client port
 * @param server_port  Server port
 * @param isn          Client's ISN
 * @param mss          Client's MSS (encoded in cookie)
 * @return 32-bit cookie ISN
 */
uint32_t syn_cookie_v6_generate(const uint8_t client_ip[16],
                                 const uint8_t server_ip[16],
                                 uint16_t client_port,
                                 uint16_t server_port,
                                 uint32_t isn,
                                 uint16_t mss);

/**
 * Validate IPv6 SYN cookie
 *
 * @param client_ip    Client IPv6 address
 * @param server_ip    Server IPv6 address
 * @param client_port  Client port
 * @param server_port  Server port
 * @param isn          Client's original ISN
 * @param cookie_ack   ACK number from client (cookie + 1)
 * @param mss_out      Output: decoded MSS
 * @return true if cookie is valid, false otherwise
 */
bool syn_cookie_v6_validate(const uint8_t client_ip[16],
                             const uint8_t server_ip[16],
                             uint16_t client_port,
                             uint16_t server_port,
                             uint32_t isn,
                             uint32_t cookie_ack,
                             uint16_t *mss_out);

#ifdef __cplusplus
}
#endif

#endif /* LAYER1_SYN_PROXY_V6_H */
