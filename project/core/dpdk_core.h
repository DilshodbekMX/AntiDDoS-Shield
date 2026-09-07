#ifndef DPDK_CORE_H
#define DPDK_CORE_H

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ring.h>
#include <rte_spinlock.h>
#include <stdbool.h>

// ==================== Configuration Constants ====================

#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100
#define MEMPOOL_CACHE_SIZE 256
#define MAX_RX_QUEUE_PER_LCORE 16
#define PREFETCH_OFFSET 3
#define US_PER_S 1000000

// RSS Configuration
#define MAX_RX_QUEUES_PER_PORT 16      // Maximum RX queues per port
#define MAX_TX_QUEUES_PER_PORT 16      // Maximum TX queues per port
#define RSS_HASH_KEY_LENGTH 40         // Standard Toeplitz key length

// Software RSS Configuration (fallback when hardware RSS unavailable)
#define SW_RSS_RING_SIZE 4096          // Per-worker ring size (power of 2)
#define SW_RSS_MAX_WORKERS 15          // Max worker lcores (1 lcore reserved for distributor)

// ==================== Data Structures ====================

/**
 * Per-lcore queue configuration
 * Each lcore handles specific queues on specific ports
 */
struct lcore_queue_conf {
    unsigned n_rx_port;
    uint16_t rx_port_list[MAX_RX_QUEUE_PER_LCORE];
    uint16_t rx_queue_list[MAX_RX_QUEUE_PER_LCORE];  // Queue ID for each port
    uint16_t tx_queue_list[MAX_RX_QUEUE_PER_LCORE];  // TX queue for each port
} __rte_cache_aligned;

/**
 * Per-port statistics
 */
struct port_stats {
    uint64_t rx;
    uint64_t tx;
    uint64_t dropped;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
} __rte_cache_aligned;

/**
 * Per-port RSS configuration info
 */
struct port_rss_conf {
    uint16_t nb_rx_queues;
    uint16_t nb_tx_queues;
    bool rss_enabled;
    uint64_t rss_hf;  // RSS hash functions enabled
} __rte_cache_aligned;

/**
 * Software RSS - per-worker TX batch for a single port
 */
struct sw_rss_tx_batch {
    struct rte_mbuf *pkts[MAX_PKT_BURST];
    uint16_t count;
};

/**
 * Software RSS - per-worker state
 */
struct sw_rss_worker {
    struct rte_ring *rx_ring;       // SPSC ring: distributor -> worker
    unsigned lcore_id;
    uint16_t tx_queue_id;           // TX queue (0 for shared)
    // Per-port TX batches -- lock-free buffering, locked only on flush
    struct sw_rss_tx_batch tx_batch[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

/**
 * Software RSS global configuration
 * Active only when NIC doesn't support hardware RSS but multiple lcores available.
 * One distributor lcore hashes packets and fans out to per-worker SPSC rings.
 */
struct sw_rss_conf {
    bool enabled;
    unsigned nb_workers;
    struct sw_rss_worker workers[SW_RSS_MAX_WORKERS];
    uint16_t rx_ports[RTE_MAX_ETHPORTS];  // All ports to poll (queue 0 each)
    unsigned nb_rx_ports;                  // Number of ports to poll
    uint16_t nb_tx_queues_avail;           // Actual TX queues available per port
    unsigned distributor_lcore;            // Lcore running the distributor loop
    // TX spinlock -- protects rte_eth_tx_burst on shared TX queue 0
    // Required because rte_eth_tx_burst is NOT thread-safe per queue
    rte_spinlock_t tx_lock[RTE_MAX_ETHPORTS];
    // Stats (written only by distributor lcore, read by control path)
    uint64_t dist_packets;
    uint64_t dist_drops;                   // Drops due to full worker rings
} __rte_cache_aligned;

extern struct sw_rss_conf sw_rss;

// ==================== Global State (extern) ====================
// Per-queue statistics (legacy, kept for compatibility)
struct queue_stats {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
} __rte_cache_aligned;

extern struct queue_stats queue_statistics[RTE_MAX_ETHPORTS][MAX_RX_QUEUES_PER_PORT];

// ==================== Per-Lcore Statistics ====================
// Each lcore writes only to its own struct - NO ATOMICS needed in fast path
// Aggregation happens only when stats are requested (lazy aggregation)

struct lcore_stats {
    // Port/queue level stats
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t dropped;

    // Layer 1 processing stats
    uint64_t l1_total_packets;
    uint64_t l1_total_bytes;
    uint64_t l1_packets_accepted;
    uint64_t l1_packets_dropped;

    uint64_t l1_inbound_packets;
    uint64_t l1_inbound_bytes;
    uint64_t l1_outbound_packets;
    uint64_t l1_outbound_bytes;

    // Drop reason counters
    uint64_t l1_drop_validation;
    uint64_t l1_drop_blacklist;
    uint64_t l1_drop_rate_limit;
    uint64_t l1_drop_syn_flood;
    uint64_t l1_drop_reputation;
    uint64_t l1_drop_policy;
    uint64_t l1_drop_proxy_error;
    uint64_t l1_drop_geo;
    uint64_t l1_drop_signature;
    uint64_t l1_drop_other_proto;
    uint64_t l1_drop_flow_table_full;  // Emergency drops when flow table exhausted
    uint64_t l1_drop_ipv6;             // IPv6 drops (protection not implemented)

    // IPv6 counters
    uint64_t l1_ipv6_packets;          // Total IPv6 packets seen

    // Hit counters
    uint64_t l1_whitelist_hits;
    uint64_t l1_syn_proxy_challenges;
    uint64_t l1_syn_proxy_established;

    // ============ Layer 2 Feature Counters ============
    // Protocol counters
    uint64_t l1_tcp_packets;
    uint64_t l1_udp_packets;
    uint64_t l1_icmp_packets;
    uint64_t l1_other_packets;

    // TCP flag counters (for SYN flood, ACK flood detection)
    uint64_t l1_syn_packets;      // Pure SYN (no ACK)
    uint64_t l1_syn_ack_packets;  // SYN+ACK
    uint64_t l1_ack_packets;      // Any packet with ACK flag
    uint64_t l1_rst_packets;      // RST packets
    uint64_t l1_fin_packets;      // FIN packets

    // Flow counters
    uint64_t l1_new_flows;        // New flows created

    // Extended flow/packet counters
    uint64_t l1_ttl_sum;           // Sum of TTL values (for mean TTL calc)
    uint64_t l1_new_udp_flows;     // New UDP flows
    uint64_t l1_icmp_echo_packets; // ICMP echo (ping) packets
    uint64_t l1_small_packets;     // Packets <= 64 bytes
    uint64_t l1_fragment_packets;  // Fragmented packets

    // Granular drop reason counters (extend l1_drop_validation bucket)
    uint64_t l1_drop_not_protected;    // Drop: dest not in protected list
    uint64_t l1_drop_proto_blocked;    // Drop: protocol blocked by profile
    uint64_t l1_drop_port_filter;      // Drop: port not in profile allowlist
    uint64_t l1_drop_proto_rate_limit; // Drop: per-profile protocol rate limit
    uint64_t l1_drop_ttl;              // Drop: TTL/hop-limit zero
    uint64_t l1_drop_checksum;         // Drop: bad checksum
    uint64_t l1_drop_parse_error;      // Drop: packet parse failure
    uint64_t l1_drop_l7_validation;    // Drop: L7 validation failure
    uint64_t l1_drop_proto_validation; // Drop: protocol validation failure
    uint64_t l1_drop_spoofed_tcp;      // Drop: spoofed TCP source

    // Padding to ensure struct size is a multiple of cache line (64 bytes)
    // Without proper padding, adjacent lcore_stats in array can share cache lines,
    // causing severe false sharing between cores (up to 80% throughput loss).
    // Current data fields: 54 x 8 = 432 bytes
    // Rounded to 448 bytes (7 cache lines) = 56 x 8 bytes
    // Padding needed: 56 - 54 = 2 uint64_t
    uint64_t _pad[2];
} __rte_cache_aligned;

extern struct lcore_stats lcore_statistics[RTE_MAX_LCORE];

// Aggregated stats structure (for display/export)
struct aggregated_stats {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t dropped;

    uint64_t l1_total_packets;
    uint64_t l1_total_bytes;
    uint64_t l1_packets_accepted;
    uint64_t l1_packets_dropped;

    uint64_t l1_inbound_packets;
    uint64_t l1_inbound_bytes;
    uint64_t l1_outbound_packets;
    uint64_t l1_outbound_bytes;

    uint64_t l1_drop_validation;
    uint64_t l1_drop_blacklist;
    uint64_t l1_drop_rate_limit;
    uint64_t l1_drop_syn_flood;
    uint64_t l1_drop_reputation;
    uint64_t l1_drop_policy;
    uint64_t l1_drop_proxy_error;
    uint64_t l1_drop_geo;
    uint64_t l1_drop_signature;
    uint64_t l1_drop_other_proto;
    uint64_t l1_drop_flow_table_full;
    uint64_t l1_drop_ipv6;
    uint64_t l1_ipv6_packets;

    uint64_t l1_whitelist_hits;
    uint64_t l1_syn_proxy_challenges;
    uint64_t l1_syn_proxy_established;

    // Layer 2 feature counters
    uint64_t l1_tcp_packets;
    uint64_t l1_udp_packets;
    uint64_t l1_icmp_packets;
    uint64_t l1_other_packets;
    uint64_t l1_syn_packets;
    uint64_t l1_syn_ack_packets;
    uint64_t l1_ack_packets;
    uint64_t l1_rst_packets;
    uint64_t l1_fin_packets;
    uint64_t l1_new_flows;
    uint64_t l1_new_udp_flows;        // New UDP flows created
    uint64_t l1_icmp_echo_packets;    // ICMP echo (ping) packets
    uint64_t l1_small_packets;        // Packets <= 64 bytes
    uint64_t l1_fragment_packets;     // Fragmented packets

    uint64_t l1_ttl_sum;               // Sum of TTL values (for mean TTL calc)
    uint64_t l1_drop_not_protected;
    uint64_t l1_drop_proto_blocked;
    uint64_t l1_drop_port_filter;
    uint64_t l1_drop_proto_rate_limit;
    uint64_t l1_drop_ttl;
    uint64_t l1_drop_checksum;
    uint64_t l1_drop_parse_error;
    uint64_t l1_drop_l7_validation;
    uint64_t l1_drop_proto_validation;
    uint64_t l1_drop_spoofed_tcp;
};

// Aggregate stats from all lcores (call from control path only)
void aggregate_lcore_stats(struct aggregated_stats *out);

// Get per-lcore stats pointer (for fast path - returns current lcore's stats)
static inline struct lcore_stats *get_lcore_stats(void) {
    return &lcore_statistics[rte_lcore_id()];
}
extern volatile bool force_quit;
extern int mac_updating;
extern struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
extern struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
extern uint32_t dst_ports[RTE_MAX_ETHPORTS];
extern struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS][MAX_TX_QUEUES_PER_PORT];
extern struct port_stats port_statistics[RTE_MAX_ETHPORTS];
extern struct port_rss_conf port_rss_info[RTE_MAX_ETHPORTS];

// ==================== Public API ====================

int dpdk_init(int argc, char **argv);

// Accessors
int get_promiscuous_on(void);
uint32_t get_enabled_port_mask(void);
unsigned get_rx_queue_per_lcore(void);
struct rte_mempool *get_pktmbuf_pool(void);
struct rte_eth_dev_tx_buffer *get_tx_buffer(uint16_t port_id);
struct rte_eth_dev_tx_buffer *get_tx_buffer_queue(uint16_t port_id, uint16_t queue_id);
struct rte_ether_addr *get_ports_eth_addr(void);
uint16_t get_dst_port(uint16_t port_id);
struct port_stats *get_port_stats(void);
uint16_t get_nb_rx_queues(uint16_t port_id);
uint16_t get_nb_tx_queues(uint16_t port_id);

// TX checksum offload support
bool is_tx_ip_cksum_offload_enabled(uint16_t port_id);
bool is_tx_tcp_cksum_offload_enabled(uint16_t port_id);

// Software RSS
int sw_rss_init(uint32_t port_mask, unsigned nb_lcores);
void sw_rss_cleanup(void);

#endif // DPDK_CORE_H