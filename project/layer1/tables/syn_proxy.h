#ifndef LAYER1_SYN_PROXY_H
#define LAYER1_SYN_PROXY_H

#include "../../common/types.h"
#include "../interlayer/shared_memory.h"
#include <stddef.h>
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
 * Adaptive mode states for SYN proxy. In both modes a challenged SYN keeps
 * no state; the ACK that returns a valid cookie creates the hash entry, and
 * the SYN-ACK offers MSS only.
 * STATEFUL: Normal mode - full SYN option parsing for the cookie MSS, SYN-ACK in a new mbuf
 * STATELESS: Attack mode - fast MSS extraction, SYN turned into the SYN-ACK in place (faster)
 */
enum syn_proxy_mode {
    SYN_PROXY_MODE_STATEFUL = 0,   // Normal: full option parsing, new mbuf
    SYN_PROXY_MODE_STATELESS = 1,  // Attack: fast MSS extraction, in-place SYN-ACK
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
                                       // (0 = L1_DEFAULT_CHALLENGE_THRESHOLD, 1000)
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
    
    // Control word: the state (enum syn_proxy_state), the flags of a BYPASSED
    // entry and the generation of the slot. It is read and changed only with
    // atomics; see "Entry control word" in syn_proxy.c.
    uint32_t ctl;
    uint64_t state_change_tsc;
    
    uint32_t client_isn;        // ISN of the client's SYN (proxied and BYPASSED)
    uint32_t cookie_isn;
    uint32_t client_next_seq;   // Proxied: end of the client's FIN, as the server numbers it
    uint32_t server_next_seq;   // Proxied: end of the server's FIN, as the client numbers it
    
    uint32_t proxy_isn;
    uint32_t server_isn;    // ISN of the server's SYN-ACK (proxied and BYPASSED)
    uint64_t created_tsc;
    
    int32_t seq_delta_c2s;
    int32_t seq_delta_s2c;
    
    // What an RST is checked against (see "RST validation" in syn_proxy.c),
    // 0 = nothing seen yet: the latest acknowledgement each side sent (its
    // next expected sequence number, as it numbers the other side's bytes),
    // and the server's next sequence number (the end of the latest segment it
    // sent that occupies sequence space, in its own numbering). Written, never
    // read, by the segments that move them, next to the activity timestamps
    // that the same segments write; only an RST reads them.
    uint32_t client_next_ack;
    uint32_t server_next_ack;
    uint32_t server_snd_nxt;
    uint8_t  syn_retries;
    uint8_t  _pad[3];
    uint64_t last_client_tsc;
    uint64_t last_server_tsc;
    
    uint64_t packets_c2s;
    uint64_t packets_s2c;
    uint64_t bytes_c2s;
    uint64_t bytes_s2c;
    
    struct tcp_syn_options client_opts;
    
} __attribute__((aligned(64)));

// Process-private, never in shared memory: only its size and alignment are
// pinned, and which cache line some fields are on. The first line holds what
// every packet reads (the 4-tuple, the control word, the sequence deltas);
// the fields written per packet are on the second, so that the inbound and
// the outbound lcore of a connection do not take the first line from each
// other on every packet.
_Static_assert(sizeof(struct syn_proxy_conn) == 192, "syn_proxy_conn must stay 192 bytes");
_Static_assert(_Alignof(struct syn_proxy_conn) == 64, "syn_proxy_conn must stay cache-line aligned");
_Static_assert(offsetof(struct syn_proxy_conn, seq_delta_s2c) < 64 &&
               offsetof(struct syn_proxy_conn, client_next_ack) >= 64 &&
               offsetof(struct syn_proxy_conn, bytes_s2c) + sizeof(uint64_t) <= 128,
               "the fields written per packet must stay on the second cache line");

// ==================== Close Timeouts ====================

/**
 * How long the cleanup keeps a proxied entry in CLOSING (both sides have sent
 * FIN, and a FIN is not acknowledged yet) without a segment, at most the idle
 * timeout. The FIN's sender retransmits it (and the data before it) with
 * exponential backoff until it is acknowledged; every retransmission needs
 * translating, and one that comes after the entry is gone reaches the peer in
 * the wrong numbering, so the peer never gets the last bytes. 60 s is the
 * FIN_WAIT_2 timeout of Linux (tcp_fin_timeout) and covers about eight
 * consecutive losses at a 200 ms RTO. A close is normally released by its
 * last ACK long before; an attacker can already hold an ESTABLISHED entry for
 * the idle timeout.
 */
#define SYN_PROXY_CLOSING_TIMEOUT_SEC   60

/**
 * How long the cleanup keeps a proxied entry in CLOSED (its close is complete:
 * both FINs are acknowledged) without a segment, at most the idle timeout: a
 * TIME_WAIT for the proxy. If the last ACK is lost beyond the proxy, the
 * passive closer retransmits its FIN after its RTO, and the active closer
 * answers it again; both still need translating. Every translated segment
 * restarts the wait. A new SYN on the 4-tuple ends the wait at once. The
 * table cost is the close rate times this time.
 */
#define SYN_PROXY_TIME_WAIT_SEC         5

// ==================== Result Structure ====================

struct syn_proxy_result {
    enum syn_proxy_action action;
    bool packet_modified;
    // With SYN_PROXY_DROP: why, as a DROP_REASON_* code of layer1.h. 0 is a
    // drop of the cookie path (Stage 9 reports DROP_REASON_COOKIE_INVALID);
    // DROP_REASON_SPOOFED_TCP is an RST outside its connection's window.
    uint8_t drop_reason;
    // With SYN_PROXY_FORWARD: an RST forwarded without ending the entry (not
    // at the receiver's next sequence), which the flow must not trust either
    bool rst_unconfirmed;
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

    // RST validation (see "RST validation" in syn_proxy.c)
    uint64_t rst_unconfirmed;         // Forwarded but not at the receiver's next sequence: the entry stays
    uint64_t rst_dropped;             // Dropped: outside the receiver's window, or not exact while waiting on the server
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

/**
 * Check whether the proxy holds an entry (any state, proxied or bypassed) for
 * the packet's connection. While the proxy is enabled, syn_proxy_process_packet()
 * handles such a packet from that entry.
 */
bool syn_proxy_is_proxied(const struct packet_features *features, uint8_t direction);

/**
 * Stage 8b in spoofed mode: whether the proxy vouches for an inbound segment
 * (not a SYN) that has no flow entry. These connections have no flow: Stage 9
 * returns before Stage 11 for every packet the proxy replies to or forwards.
 * The proxy vouches for:
 * - a proxied (challenged) connection: its client returned a valid cookie;
 * - a BYPASSED connection whose client has acknowledged the server's ISN + 1
 *   from the SYN-ACK, or the segment that is that acknowledgement.
 * A SYN that is not challenged leaves a BYPASSED entry, so a spoofed SYN in
 * calm conditions can plant one. A blind sender does not see the server's
 * SYN-ACK, so the entry it planted never vouches for its segments.
 */
bool syn_proxy_admits_segment(const struct packet_features *features);

int syn_proxy_close_connection(uint32_t client_ip, uint32_t server_ip,
                               uint16_t client_port, uint16_t server_port);

uint32_t syn_proxy_cleanup_connections(void);
void syn_proxy_rotate_secret(uint32_t new_secret);
bool syn_proxy_should_challenge(const struct packet_features *features,
                                const struct per_ip_anomaly_snapshot *ip_anom);

/**
 * Check whether an ACK carries a valid SYN cookie, without creating connection state.
 * Used by Stage 8b to let handshake completions through in spoofed mode.
 */
bool syn_proxy_quick_cookie_check(uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t src_port, uint16_t dst_port,
                                  uint32_t tcp_ack);

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

// ==================== Test Seams ====================

/**
 * Points where syn_proxy.c calls syn_proxy_race_seam(). Each lies between an
 * lcore's read of an entry and the compare-and-swap that acts on what it read.
 */
enum syn_proxy_seam_point {
    SYN_PROXY_SEAM_FREE = 0,  // Packet path, before it ends an entry it holds (RST, close, error)
    SYN_PROXY_SEAM_CLEANUP,   // syn_proxy_cleanup_connections(), before it ends an entry found due
    SYN_PROXY_SEAM_SYNACK,    // Server SYN-ACK of a CONNECTING entry, before it ends CONNECTING
    SYN_PROXY_SEAM_ALLOC,     // New entry, after the lookup missed and before the key is added
    SYN_PROXY_SEAM_CLAIM,     // New entry, after the key is added and before its slot is claimed
    SYN_PROXY_SEAM_CLAIM_SWAP,  // New entry, after the key is found on the free slot, before the swap
    SYN_PROXY_SEAM_CLOSE,     // Close of a proxied entry, before it records a FIN or its ACK, or ends it
};

/**
 * Test seam: the library's weak definition does nothing. A unit test may link
 * its own to run the operations of another lcore at one of these points, which
 * makes an interleaving of two lcores deterministic.
 */
void syn_proxy_race_seam(enum syn_proxy_seam_point point);

/**
 * Test seam: the TSC clock of the SYN-ACK rate window (one window per second
 * of TSC). The library's weak definition returns rte_rdtsc(); a unit test may
 * link its own to hold the window still.
 */
uint64_t syn_proxy_synack_clock(void);

/**
 * Test seam: the TSC time with which syn_proxy_cleanup_connections() compares
 * the entries' timestamps (read once per pass). The library's weak definition
 * returns rte_get_tsc_cycles(); a unit test may link its own to make entries
 * look idle without waiting, also entries stamped after the pass began, as an
 * lcore whose TSC lags the main lcore's would stamp them.
 */
uint64_t syn_proxy_cleanup_clock(void);

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