#include "dpdk_core.h"
#include "stats_socket.h"
#include "traffic_monitor.h"
#include "control_socket.h"
#include "system_monitor.h"
#include "../layer1/layer1.h"
#include "../layer1/config/layer1_config.h"
#include "../layer1/tables/ip_lists.h"
#include "../layer1/telemetry/window_stats.h"
#include "../layer2/layer2.h"
#include "../layer2/config/layer2_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <rte_thash.h>

// Define our log type
#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

// ==================== Symmetric RSS Key ====================
/**
 * Symmetric Toeplitz RSS key
 * This key ensures hash(src,dst) == hash(dst,src)
 * Critical for bidirectional flow handling - both directions go to same core
 */
static uint8_t rss_symmetric_key[RSS_HASH_KEY_LENGTH] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

// ==================== Global State ====================
volatile bool force_quit = false;
/* sig_atomic_t guarantees atomic read/write from signal handler context (C11 section 7.14) */
static volatile sig_atomic_t reload_config = 0;  /* Set by SIGHUP for config hot-reload */
int mac_updating = 0;
static int promiscuous_on = 1;
static uint32_t enabled_port_mask = 0;
static unsigned rx_queue_per_lcore = 1;
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
static struct rte_mempool *pktmbuf_pool = NULL;
struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
uint32_t dst_ports[RTE_MAX_ETHPORTS];
struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS][MAX_TX_QUEUES_PER_PORT];
struct port_stats port_statistics[RTE_MAX_ETHPORTS];
struct port_rss_conf port_rss_info[RTE_MAX_ETHPORTS];

// Per-lcore statistics - each lcore writes ONLY to its own entry
struct lcore_stats lcore_statistics[RTE_MAX_LCORE];

// Number of worker lcores (excluding main if it doesn't process packets)
static unsigned nb_worker_lcores = 0;

// ==================== Port Configuration with RSS ====================

static struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,  // Will be set during init
            .rss_key_len = RSS_HASH_KEY_LENGTH,
            .rss_hf = RTE_ETH_RSS_IP | 
                      RTE_ETH_RSS_TCP | 
                      RTE_ETH_RSS_UDP |
                      RTE_ETH_RSS_SCTP,
        },
    },
};

// ==================== Accessor Functions ====================

int get_promiscuous_on(void) { return promiscuous_on; }
uint32_t get_enabled_port_mask(void) { return enabled_port_mask; }
unsigned get_rx_queue_per_lcore(void) { return rx_queue_per_lcore; }
struct rte_mempool *get_pktmbuf_pool(void) { return pktmbuf_pool; }
struct queue_stats queue_statistics[RTE_MAX_ETHPORTS][MAX_RX_QUEUES_PER_PORT];

struct rte_eth_dev_tx_buffer *get_tx_buffer(uint16_t port_id) {
    if (port_id >= RTE_MAX_ETHPORTS) return NULL;
    return tx_buffer[port_id][0];  // Default to queue 0 for backward compatibility
}

struct rte_eth_dev_tx_buffer *get_tx_buffer_queue(uint16_t port_id, uint16_t queue_id) {
    if (port_id >= RTE_MAX_ETHPORTS || queue_id >= MAX_TX_QUEUES_PER_PORT) return NULL;
    return tx_buffer[port_id][queue_id];
}

struct rte_ether_addr *get_ports_eth_addr(void) { return ports_eth_addr; }

uint16_t get_dst_port(uint16_t port_id) {
    if (port_id >= RTE_MAX_ETHPORTS) return 0;
    return dst_ports[port_id];
}

struct port_stats *get_port_stats(void) {
    return port_statistics;
}

uint16_t get_nb_rx_queues(uint16_t port_id) {
    if (port_id >= RTE_MAX_ETHPORTS) return 0;
    return port_rss_info[port_id].nb_rx_queues;
}

uint16_t get_nb_tx_queues(uint16_t port_id) {
    if (port_id >= RTE_MAX_ETHPORTS) return 0;
    return port_rss_info[port_id].nb_tx_queues;
}

// ==================== TX Checksum Offload Support ====================
// Track which ports have TX checksum offload enabled

static uint64_t port_tx_offload_flags[RTE_MAX_ETHPORTS] = {0};

bool is_tx_ip_cksum_offload_enabled(uint16_t port_id) {
    if (port_id >= RTE_MAX_ETHPORTS) return false;
    return (port_tx_offload_flags[port_id] & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) != 0;
}

bool is_tx_tcp_cksum_offload_enabled(uint16_t port_id) {
    if (port_id >= RTE_MAX_ETHPORTS) return false;
    return (port_tx_offload_flags[port_id] & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) != 0;
}

// ==================== Per-Lcore Stats Aggregation ====================
// Called from control path only (stats display, export, etc.)
// Iterates over all lcores and sums their local counters

void aggregate_lcore_stats(struct aggregated_stats *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));

    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        const struct lcore_stats *s = &lcore_statistics[lcore_id];

        out->rx_packets += s->rx_packets;
        out->rx_bytes += s->rx_bytes;
        out->tx_packets += s->tx_packets;
        out->tx_bytes += s->tx_bytes;
        out->dropped += s->dropped;

        out->l1_total_packets += s->l1_total_packets;
        out->l1_total_bytes += s->l1_total_bytes;
        out->l1_packets_accepted += s->l1_packets_accepted;
        out->l1_packets_dropped += s->l1_packets_dropped;

        out->l1_inbound_packets += s->l1_inbound_packets;
        out->l1_inbound_bytes += s->l1_inbound_bytes;
        out->l1_outbound_packets += s->l1_outbound_packets;
        out->l1_outbound_bytes += s->l1_outbound_bytes;

        out->l1_drop_validation += s->l1_drop_validation;
        out->l1_drop_blacklist += s->l1_drop_blacklist;
        out->l1_drop_rate_limit += s->l1_drop_rate_limit;
        out->l1_drop_syn_flood += s->l1_drop_syn_flood;
        out->l1_drop_reputation += s->l1_drop_reputation;
        out->l1_drop_policy += s->l1_drop_policy;
        out->l1_drop_proxy_error += s->l1_drop_proxy_error;
        out->l1_drop_geo += s->l1_drop_geo;
        out->l1_drop_signature += s->l1_drop_signature;
        out->l1_drop_other_proto += s->l1_drop_other_proto;

        out->l1_whitelist_hits += s->l1_whitelist_hits;
        out->l1_syn_proxy_challenges += s->l1_syn_proxy_challenges;
        out->l1_syn_proxy_established += s->l1_syn_proxy_established;

        // Layer 2 feature counters
        out->l1_tcp_packets += s->l1_tcp_packets;
        out->l1_udp_packets += s->l1_udp_packets;
        out->l1_icmp_packets += s->l1_icmp_packets;
        out->l1_other_packets += s->l1_other_packets;
        out->l1_syn_packets += s->l1_syn_packets;
        out->l1_syn_ack_packets += s->l1_syn_ack_packets;
        out->l1_ack_packets += s->l1_ack_packets;
        out->l1_rst_packets += s->l1_rst_packets;
        out->l1_fin_packets += s->l1_fin_packets;
        out->l1_new_flows += s->l1_new_flows;
        out->l1_ttl_sum += s->l1_ttl_sum;
        out->l1_drop_flow_table_full += s->l1_drop_flow_table_full;
        out->l1_drop_ipv6 += s->l1_drop_ipv6;
        out->l1_ipv6_packets += s->l1_ipv6_packets;
        out->l1_new_udp_flows += s->l1_new_udp_flows;
        out->l1_icmp_echo_packets += s->l1_icmp_echo_packets;
        out->l1_small_packets += s->l1_small_packets;
        out->l1_fragment_packets += s->l1_fragment_packets;
        out->l1_drop_not_protected += s->l1_drop_not_protected;
        out->l1_drop_proto_blocked += s->l1_drop_proto_blocked;
        out->l1_drop_port_filter += s->l1_drop_port_filter;
        out->l1_drop_proto_rate_limit += s->l1_drop_proto_rate_limit;
        out->l1_drop_ttl += s->l1_drop_ttl;
        out->l1_drop_checksum += s->l1_drop_checksum;
        out->l1_drop_parse_error += s->l1_drop_parse_error;
        out->l1_drop_l7_validation += s->l1_drop_l7_validation;
        out->l1_drop_proto_validation += s->l1_drop_proto_validation;
        out->l1_drop_spoofed_tcp += s->l1_drop_spoofed_tcp;
    }
}

// ==================== SW RSS TX helpers (per-worker batch + locked burst) ====================

/**
 * Flush a worker's TX batch for a port.
 * Takes the per-port spinlock, calls rte_eth_tx_burst, frees unsent.
 * Lock is held only for the duration of the burst -- not per-packet.
 */
static inline uint16_t sw_rss_batch_flush(struct sw_rss_tx_batch *batch,
                                           uint16_t port, uint16_t queue)
{
    uint16_t n = batch->count;
    if (n == 0) return 0;

    rte_spinlock_lock(&sw_rss.tx_lock[port]);
    uint16_t sent = rte_eth_tx_burst(port, queue, batch->pkts, n);
    rte_spinlock_unlock(&sw_rss.tx_lock[port]);

    /* Free any packets the NIC couldn't send */
    for (uint16_t k = sent; k < n; k++)
        rte_pktmbuf_free(batch->pkts[k]);

    batch->count = 0;
    return sent;
}

/**
 * Enqueue a packet to a worker's per-port TX batch.
 * Lock-free -- each worker has its own batch.
 * Auto-flushes when batch is full (MAX_PKT_BURST = 32 packets).
 */
static inline uint16_t sw_rss_batch_enqueue(struct sw_rss_tx_batch *batch,
                                             uint16_t port, uint16_t queue,
                                             struct rte_mbuf *pkt)
{
    batch->pkts[batch->count++] = pkt;
    if (unlikely(batch->count >= MAX_PKT_BURST))
        return sw_rss_batch_flush(batch, port, queue);
    return 0;
}

// ==================== Packet Processing Constants ====================

#define TRAFFIC_SAMPLE_RATE 100
static __rte_cache_aligned uint64_t lcore_sample_counter[RTE_MAX_LCORE];

// ==================== Software RSS ====================

struct sw_rss_conf sw_rss;

/**
 * Compute software RSS hash for a packet.
 * Uses rte_softrss_be() with the same symmetric Toeplitz key as hardware RSS.
 * Returns 0 for non-IP or unparseable packets (all go to worker 0).
 */
static inline uint32_t sw_rss_hash_pkt(struct rte_mbuf *m)
{
    const struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
    const uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    if (likely(ether_type == RTE_ETHER_TYPE_IPV4)) {
        const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(eth + 1);
        /*
         * Build a 3-tuple (src_ip, dst_ip, ports) in network byte order
         * for rte_softrss_be(). The input is treated as an array of uint32_t.
         *   [0] = src_ip  (4 bytes)
         *   [1] = dst_ip  (4 bytes)
         *   [2] = src_port << 16 | dst_port  (4 bytes)
         */
        union {
            struct { uint32_t sip, dip, ports; } f;
            uint32_t data[3];
        } tuple;
        tuple.f.sip = ip->src_addr;
        tuple.f.dip = ip->dst_addr;

        uint8_t proto = ip->next_proto_id;
        if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
            /* L4 header starts after IPv4 header (no options check for speed --
             * IHL is almost always 5; if not, hash is slightly less uniform
             * but still deterministic per flow) */
            const uint16_t *l4 = (const uint16_t *)((const uint8_t *)ip +
                                  (ip->version_ihl & 0x0F) * 4);
            /* src_port in high 16 bits, dst_port in low 16 bits (network order) */
            tuple.f.ports = ((uint32_t)l4[0] << 16) | (uint32_t)l4[1];
        } else {
            /* Non-TCP/UDP: use protocol number as port substitute */
            tuple.f.ports = (uint32_t)proto;
        }
        return rte_softrss_be(tuple.data, 3, rss_symmetric_key);

    } else if (ether_type == RTE_ETHER_TYPE_IPV6) {
        const struct rte_ipv6_hdr *ip6 = (const struct rte_ipv6_hdr *)(eth + 1);
        /*
         * IPv6: XOR-fold 128-bit addresses into 32 bits each, then hash.
         *   [0] = XOR-fold of src_addr
         *   [1] = XOR-fold of dst_addr
         *   [2] = ports (same as IPv4)
         */
        union {
            struct { uint32_t sip, dip, ports; } f;
            uint32_t data[3];
        } tuple;
        const uint32_t *s6 = (const uint32_t *)&ip6->src_addr;
        const uint32_t *d6 = (const uint32_t *)&ip6->dst_addr;
        tuple.f.sip = s6[0] ^ s6[1] ^ s6[2] ^ s6[3];
        tuple.f.dip = d6[0] ^ d6[1] ^ d6[2] ^ d6[3];

        uint8_t proto = ip6->proto;
        if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
            const uint16_t *l4 = (const uint16_t *)(ip6 + 1);
            tuple.f.ports = ((uint32_t)l4[0] << 16) | (uint32_t)l4[1];
        } else {
            tuple.f.ports = (uint32_t)proto;
        }
        return rte_softrss_be(tuple.data, 3, rss_symmetric_key);
    }

    /* Non-IP (ARP, etc.) -- all go to worker 0 */
    return 0;
}

/**
 * Initialize software RSS rings and worker assignments.
 * Called from dpdk_init() after ports are configured.
 * Activates SW RSS only when hardware RSS is unavailable (single RX queue)
 * but multiple lcores are available.
 */
int sw_rss_init(uint32_t port_mask, unsigned nb_lcores)
{
    memset(&sw_rss, 0, sizeof(sw_rss));

    if (nb_lcores < 2) {
        printf("SW RSS: Only %u lcore(s) available, SW RSS not needed\n", nb_lcores);
        return 0;
    }

    /* Collect all enabled ports that fell back to single RX queue */
    bool need_sw_rss = false;
    uint16_t portid;
    uint16_t min_tx_queues = UINT16_MAX;

    RTE_ETH_FOREACH_DEV(portid) {
        if ((port_mask & (1 << portid)) == 0) continue;
        if (port_rss_info[portid].nb_rx_queues == 1 && !port_rss_info[portid].rss_enabled) {
            need_sw_rss = true;
            sw_rss.rx_ports[sw_rss.nb_rx_ports++] = portid;
        }
        /* Track minimum TX queues across all ports */
        if (port_rss_info[portid].nb_tx_queues < min_tx_queues)
            min_tx_queues = port_rss_info[portid].nb_tx_queues;
    }

    if (!need_sw_rss) {
        printf("SW RSS: Hardware RSS active on all ports, SW RSS not needed\n");
        return 0;
    }

    sw_rss.nb_tx_queues_avail = min_tx_queues;

    /* Assign lcores: main lcore = distributor, workers = SW RSS workers */
    unsigned distributor_lcore = rte_get_main_lcore();
    unsigned worker_count = 0;
    unsigned lcore_id;

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (worker_count >= SW_RSS_MAX_WORKERS) break;

        char ring_name[RTE_RING_NAMESIZE];
        snprintf(ring_name, sizeof(ring_name), "sw_rss_w%u", worker_count);

        struct rte_ring *ring = rte_ring_create(ring_name, SW_RSS_RING_SIZE,
                                                 rte_socket_id(),
                                                 RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!ring) {
            printf("SW RSS: Failed to create ring for worker %u: %s\n",
                   worker_count, rte_strerror(rte_errno));
            for (unsigned w = 0; w < worker_count; w++)
                rte_ring_free(sw_rss.workers[w].rx_ring);
            return -1;
        }

        sw_rss.workers[worker_count].rx_ring = ring;
        sw_rss.workers[worker_count].lcore_id = lcore_id;

        /* TX queue 0 for all workers.
         * Many virtual NIC drivers (net_e1000_em, net_virtio) report
         * max_tx_queues > 1 but only queue 0 reliably transmits.
         * Using queue 0 for all workers is safe because each worker has
         * its own tx_buffer object -- only the final rte_eth_tx_burst()
         * call touches the NIC TX ring, and at low rates the contention
         * window is negligible. For high-rate production NICs (mlx5, i40e),
         * hardware RSS is active so this code path isn't used. */
        sw_rss.workers[worker_count].tx_queue_id = 0;

        worker_count++;
    }

    if (worker_count == 0) {
        printf("SW RSS: No worker lcores available\n");
        return 0;
    }

    sw_rss.enabled = true;
    sw_rss.nb_workers = worker_count;
    sw_rss.distributor_lcore = distributor_lcore;
    sw_rss.dist_packets = 0;
    sw_rss.dist_drops = 0;

    /* Initialize per-port TX spinlocks for shared queue 0 */
    for (unsigned p = 0; p < RTE_MAX_ETHPORTS; p++)
        rte_spinlock_init(&sw_rss.tx_lock[p]);

    printf("\n=== Software RSS Mode ===\n");
    printf("  Reason: Hardware RSS unavailable on %u port(s):", sw_rss.nb_rx_ports);
    for (unsigned p = 0; p < sw_rss.nb_rx_ports; p++)
        printf(" %u", sw_rss.rx_ports[p]);
    printf("\n");
    printf("  Distributor: lcore %u (polling %u ports, queue 0 each)\n",
           distributor_lcore, sw_rss.nb_rx_ports);
    printf("  Workers: %u (lcores", worker_count);
    for (unsigned w = 0; w < worker_count; w++)
        printf(" %u", sw_rss.workers[w].lcore_id);
    printf(")\n");
    printf("  TX queues per port: %u (all workers use TX queue 0)\n", min_tx_queues);
    printf("  Ring size: %u per worker\n", SW_RSS_RING_SIZE);
    printf("  Hash: Toeplitz (symmetric, same key as HW RSS)\n");
    printf("===========================\n\n");

    return 0;
}

void sw_rss_cleanup(void)
{
    if (!sw_rss.enabled) return;

    printf("SW RSS: Cleaning up (%lu packets distributed, %lu drops)\n",
           sw_rss.dist_packets, sw_rss.dist_drops);

    for (unsigned w = 0; w < sw_rss.nb_workers; w++) {
        if (sw_rss.workers[w].rx_ring) {
            /* Drain and free any remaining mbufs in the ring */
            void *obj;
            while (rte_ring_sc_dequeue(sw_rss.workers[w].rx_ring, &obj) == 0) {
                rte_pktmbuf_free((struct rte_mbuf *)obj);
            }
            rte_ring_free(sw_rss.workers[w].rx_ring);
            sw_rss.workers[w].rx_ring = NULL;
        }
    }
    sw_rss.enabled = false;
}

/**
 * SW RSS distributor loop.
 * Runs on the distributor lcore: reads packets from ALL ports (queue 0 each),
 * computes Toeplitz hash, and enqueues to per-worker SPSC rings.
 * Workers determine per-packet RX port via m->port (set by rte_eth_rx_burst).
 * Also handles maintenance tasks (same as main lcore in HW RSS path).
 */
static void main_loop_sw_distributor(void)
{
    struct rte_mbuf *pkts[MAX_PKT_BURST];
    const unsigned lcore_id = rte_lcore_id();
    struct lcore_stats * const lstats = &lcore_statistics[lcore_id];

    const unsigned nb_workers = sw_rss.nb_workers;
    const unsigned nb_rx_ports = sw_rss.nb_rx_ports;

    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    const uint64_t maint_interval_tsc = rte_get_tsc_hz();
    const uint64_t pps_interval_tsc = rte_get_tsc_hz();
    uint64_t prev_tsc = 0;
    uint64_t prev_maint_tsc = rte_rdtsc();
    uint64_t prev_pps_tsc = rte_rdtsc();
    uint64_t pps_rx_count = 0;

    RTE_LOG(INFO, L2FWD, "lcore %u: SW RSS distributor polling %u port(s) -> %u workers\n",
            lcore_id, nb_rx_ports, nb_workers);
    for (unsigned p = 0; p < nb_rx_ports; p++)
        RTE_LOG(INFO, L2FWD, "  port %u queue 0\n", sw_rss.rx_ports[p]);

    /* Diagnostic: log first N packets per port to confirm NIC is receiving */
    uint32_t diag_count[RTE_MAX_ETHPORTS];
    memset(diag_count, 0, sizeof(diag_count));
    #define SW_RSS_DIAG_PACKETS 5  /* Log first 5 packets per port */

    while (likely(!force_quit)) {
        const uint64_t cur_tsc = rte_rdtsc();

        /* Per-second stats */
        if (unlikely(cur_tsc - prev_pps_tsc > pps_interval_tsc)) {
            double elapsed = (double)(cur_tsc - prev_pps_tsc) / rte_get_tsc_hz();
            RTE_LOG(INFO, L2FWD, "lcore %u [SW-RSS dist]: %.0f pkt/s, %lu total, %lu drops, polling %u ports\n",
                    lcore_id, pps_rx_count / elapsed,
                    sw_rss.dist_packets, sw_rss.dist_drops, nb_rx_ports);
            /* Per-port RX stats */
            for (unsigned pp = 0; pp < nb_rx_ports; pp++) {
                struct rte_eth_stats eth_stats;
                rte_eth_stats_get(sw_rss.rx_ports[pp], &eth_stats);
                RTE_LOG(INFO, L2FWD, "  port %u NIC stats: RX=%lu TX=%lu rx_err=%lu tx_err=%lu rx_nombuf=%lu\n",
                        sw_rss.rx_ports[pp],
                        (unsigned long)eth_stats.ipackets, (unsigned long)eth_stats.opackets,
                        (unsigned long)eth_stats.ierrors, (unsigned long)eth_stats.oerrors,
                        (unsigned long)eth_stats.rx_nombuf);
            }
            /* Per-worker ring occupancy */
            for (unsigned w = 0; w < nb_workers; w++) {
                RTE_LOG(INFO, L2FWD, "  worker %u (lcore %u): ring usage %u/%u\n",
                        w, sw_rss.workers[w].lcore_id,
                        rte_ring_count(sw_rss.workers[w].rx_ring),
                        SW_RSS_RING_SIZE);
            }
            pps_rx_count = 0;
            prev_pps_tsc = cur_tsc;
        }

        /* TX buffer drain for distributor (uses standard tx_buffer, locked) */
        if (unlikely(cur_tsc - prev_tsc > drain_tsc)) {
            for (unsigned p = 0; p < nb_rx_ports; p++) {
                uint16_t pid = sw_rss.rx_ports[p];
                if (tx_buffer[pid][0]) {
                    rte_spinlock_lock(&sw_rss.tx_lock[pid]);
                    rte_eth_tx_buffer_flush(pid, 0, tx_buffer[pid][0]);
                    rte_spinlock_unlock(&sw_rss.tx_lock[pid]);
                }
                uint16_t dst = dst_ports[pid];
                if (dst != pid && tx_buffer[dst][0]) {
                    rte_spinlock_lock(&sw_rss.tx_lock[dst]);
                    rte_eth_tx_buffer_flush(dst, 0, tx_buffer[dst][0]);
                    rte_spinlock_unlock(&sw_rss.tx_lock[dst]);
                }
            }
            prev_tsc = cur_tsc;
        }

        /* Periodic maintenance (config reload, flow table cleanup, etc.) */
        if (lcore_id == rte_get_main_lcore() &&
            unlikely(cur_tsc - prev_maint_tsc > maint_interval_tsc)) {

            if (unlikely(reload_config)) {
                reload_config = 0;
                RTE_LOG(INFO, L2FWD, "Processing config hot-reload request...\n");
                if (layer1_config_reload(L1_DEFAULT_CONFIG_FILE) == 0) {
                    layer1_refresh_cached_config();
                    RTE_LOG(INFO, L2FWD, "Layer 1 config reloaded successfully\n");
                } else {
                    RTE_LOG(ERR, L2FWD, "Layer 1 config reload failed\n");
                }
                if (layer2_reload_config() == 0) {
                    RTE_LOG(INFO, L2FWD, "Layer 2 config reloaded successfully\n");
                } else {
                    RTE_LOG(ERR, L2FWD, "Layer 2 config reload failed\n");
                }
            }

            uint32_t cleaned = layer1_maintenance();
            if (cleaned > 0)
                RTE_LOG(DEBUG, L2FWD, "Maintenance cleaned %u entries\n", cleaned);
            window_stats_tick();
            prev_maint_tsc = cur_tsc;
        }

        /* Read packets from ALL ports (queue 0 each) and distribute */
        for (unsigned p = 0; p < nb_rx_ports; p++) {
            const uint16_t nb_rx = rte_eth_rx_burst(sw_rss.rx_ports[p], 0,
                                                     pkts, MAX_PKT_BURST);
            if (unlikely(nb_rx == 0))
                continue;

            pps_rx_count += nb_rx;
            lstats->rx_packets += nb_rx;

            /* Diagnostic: log first few packets per port */
            uint16_t cur_port = sw_rss.rx_ports[p];
            if (unlikely(diag_count[cur_port] < SW_RSS_DIAG_PACKETS)) {
                for (uint16_t d = 0; d < nb_rx && diag_count[cur_port] < SW_RSS_DIAG_PACKETS; d++) {
                    const struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkts[d], const struct rte_ether_hdr *);
                    uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
                    if (etype == RTE_ETHER_TYPE_IPV4) {
                        const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(eth + 1);
                        uint32_t sip = rte_be_to_cpu_32(ip->src_addr);
                        uint32_t dip = rte_be_to_cpu_32(ip->dst_addr);
                        RTE_LOG(INFO, L2FWD,
                            "[DIAG] port %u pkt#%u: IPv4 %u.%u.%u.%u -> %u.%u.%u.%u proto=%u len=%u\n",
                            cur_port, diag_count[cur_port],
                            (sip >> 24) & 0xFF, (sip >> 16) & 0xFF, (sip >> 8) & 0xFF, sip & 0xFF,
                            (dip >> 24) & 0xFF, (dip >> 16) & 0xFF, (dip >> 8) & 0xFF, dip & 0xFF,
                            ip->next_proto_id, rte_be_to_cpu_16(ip->total_length));
                    } else if (etype == RTE_ETHER_TYPE_ARP) {
                        RTE_LOG(INFO, L2FWD, "[DIAG] port %u pkt#%u: ARP len=%u\n",
                                cur_port, diag_count[cur_port], pkts[d]->pkt_len);
                    } else {
                        RTE_LOG(INFO, L2FWD, "[DIAG] port %u pkt#%u: ether_type=0x%04x len=%u\n",
                                cur_port, diag_count[cur_port], etype, pkts[d]->pkt_len);
                    }
                    diag_count[cur_port]++;
                }
            }

            /* Distribute packets to workers based on flow hash.
             * m->port is already set by rte_eth_rx_burst() -- workers use it
             * to determine per-packet RX port for L1 processing. */
            for (uint16_t j = 0; j < nb_rx; j++) {
                uint32_t hash = sw_rss_hash_pkt(pkts[j]);
                unsigned worker_id = hash % nb_workers;

                if (unlikely(rte_ring_sp_enqueue(
                        sw_rss.workers[worker_id].rx_ring, pkts[j]) < 0)) {
                    rte_pktmbuf_free(pkts[j]);
                    sw_rss.dist_drops++;
                    lstats->dropped++;
                } else {
                    sw_rss.dist_packets++;
                }
            }
        }
    }

    RTE_LOG(INFO, L2FWD, "SW RSS distributor exiting: %lu distributed, %lu dropped\n",
            sw_rss.dist_packets, sw_rss.dist_drops);
}

/**
 * SW RSS worker loop.
 * Dequeues packets from its SPSC ring and processes them using
 * the same Layer 1 pipeline as the hardware RSS path.
 *
 * Key difference from HW RSS: packets may come from ANY port.
 * The RX port is determined per-packet via m->port (set by rte_eth_rx_burst).
 */
static void main_loop_sw_worker(void)
{
    struct rte_mbuf *pkts[MAX_PKT_BURST];
    const unsigned lcore_id = rte_lcore_id();
    struct lcore_stats * const lstats = &lcore_statistics[lcore_id];
    uint64_t * const sample_counter = &lcore_sample_counter[lcore_id];

    /* Find our worker entry */
    struct rte_ring *my_ring = NULL;
    uint16_t my_tx_queue = 0;
    struct sw_rss_worker *my_worker = NULL;
    for (unsigned w = 0; w < sw_rss.nb_workers; w++) {
        if (sw_rss.workers[w].lcore_id == lcore_id) {
            my_worker = &sw_rss.workers[w];
            my_ring = my_worker->rx_ring;
            my_tx_queue = my_worker->tx_queue_id;
            break;
        }
    }

    if (!my_ring) {
        RTE_LOG(INFO, L2FWD, "lcore %u: SW RSS worker with no ring, idling\n", lcore_id);
        while (!force_quit)
            rte_pause();
        return;
    }

    struct rte_mempool *pool = get_pktmbuf_pool();
    const int do_mac_update = mac_updating;

    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    const uint64_t pps_interval_tsc = rte_get_tsc_hz();
    uint64_t prev_tsc = 0;
    uint64_t prev_pps_tsc = rte_rdtsc();
    uint64_t pps_rx_count = 0;

    RTE_LOG(INFO, L2FWD, "lcore %u: SW RSS worker, TX queue %u, ring %s\n",
            lcore_id, my_tx_queue, my_ring->name);

    /* Diagnostic: log first N packets with L1 results */
    uint32_t worker_diag_count = 0;
    #define SW_RSS_WORKER_DIAG 5

    while (likely(!force_quit)) {
        const uint64_t cur_tsc = rte_rdtsc();

        /* Per-second pps */
        if (unlikely(cur_tsc - prev_pps_tsc > pps_interval_tsc)) {
            double elapsed = (double)(cur_tsc - prev_pps_tsc) / rte_get_tsc_hz();
            RTE_LOG(INFO, L2FWD, "lcore %u [SW-RSS worker]: %.0f pkt/s\n",
                    lcore_id, pps_rx_count / elapsed);
            pps_rx_count = 0;
            prev_pps_tsc = cur_tsc;
        }

        /* TX batch drain -- flush all per-worker batches (lock only during burst) */
        if (unlikely(cur_tsc - prev_tsc > drain_tsc)) {
            for (unsigned p = 0; p < sw_rss.nb_rx_ports; p++) {
                uint16_t pid = sw_rss.rx_ports[p];
                lstats->tx_packets += sw_rss_batch_flush(
                    &my_worker->tx_batch[pid], pid, my_tx_queue);
                uint16_t dst = dst_ports[pid];
                if (dst != pid)
                    lstats->tx_packets += sw_rss_batch_flush(
                        &my_worker->tx_batch[dst], dst, my_tx_queue);
            }
            prev_tsc = cur_tsc;
        }

        /* Dequeue from our SPSC ring */
        const uint16_t nb_rx = rte_ring_sc_dequeue_burst(my_ring,
                                    (void **)pkts, MAX_PKT_BURST, NULL);
        if (unlikely(nb_rx == 0))
            continue;

        pps_rx_count += nb_rx;

        /* Prefetch first packets */
        for (uint16_t p = 0; p < RTE_MIN(nb_rx, (uint16_t)PREFETCH_OFFSET); p++)
            rte_prefetch0(rte_pktmbuf_mtod(pkts[p], void *));

        /* Process packets -- per-packet port from m->port */
        for (uint16_t j = 0; j < nb_rx; j++) {
            struct rte_mbuf *m = pkts[j];

            if (j + PREFETCH_OFFSET < nb_rx)
                rte_prefetch0(rte_pktmbuf_mtod(pkts[j + PREFETCH_OFFSET], void *));

            /* Per-packet RX port (set by rte_eth_rx_burst in distributor) */
            const uint16_t rx_port = m->port;
            const uint16_t tx_port = dst_ports[rx_port];

            /* Early enforcement check -- only on client-facing port */
            if (rx_port == PORT_FACING_CLIENTS && ip_protected_enforcement_enabled()) {
                struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
                if (likely(rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV4)) {
                    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
                    if (!ip_protected_lookup(ip->dst_addr)) {
                        if (unlikely(worker_diag_count < SW_RSS_WORKER_DIAG)) {
                            uint32_t dip = rte_be_to_cpu_32(ip->dst_addr);
                            RTE_LOG(INFO, L2FWD,
                                "[DIAG] lcore %u: DROPPED by enforcement: dst %u.%u.%u.%u not protected\n",
                                lcore_id,
                                (dip >> 24) & 0xFF, (dip >> 16) & 0xFF,
                                (dip >> 8) & 0xFF, dip & 0xFF);
                            worker_diag_count++;
                        }
                        rte_pktmbuf_free(m);
                        continue;
                    }
                }
            }

            lstats->rx_packets++;
            lstats->rx_bytes += m->pkt_len;

            /* Traffic sampling */
            if (unlikely((++(*sample_counter) % TRAFFIC_SAMPLE_RATE) == 0))
                traffic_capture_packet(m, rx_port, 0);

            /* Layer 1 processing */
            struct layer1_result l1_result;
            int ret = layer1_process_packet_ex(m, rx_port, my_tx_queue,
                                                pool, &l1_result);

            /* Diagnostic: log first few L1 results */
            if (unlikely(worker_diag_count < SW_RSS_WORKER_DIAG)) {
                const struct rte_ether_hdr *deth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
                if (rte_be_to_cpu_16(deth->ether_type) == RTE_ETHER_TYPE_IPV4) {
                    const struct rte_ipv4_hdr *dip_hdr = (const struct rte_ipv4_hdr *)(deth + 1);
                    uint32_t sip = rte_be_to_cpu_32(dip_hdr->src_addr);
                    uint32_t dip = rte_be_to_cpu_32(dip_hdr->dst_addr);
                    const char *action_str = (ret < 0) ? "L1_ERROR" :
                        (l1_result.action == L1_ACTION_ACCEPT) ? "ACCEPT" :
                        (l1_result.action == L1_ACTION_ACCEPT_MODIFIED) ? "ACCEPT_MOD" :
                        (l1_result.action == L1_ACTION_DROP) ? "DROP" :
                        (l1_result.action == L1_ACTION_REPLY) ? "REPLY" :
                        (l1_result.action == L1_ACTION_REPLY_INPLACE) ? "REPLY_INPLACE" : "UNKNOWN";
                    RTE_LOG(INFO, L2FWD,
                        "[DIAG] lcore %u: port %u %u.%u.%u.%u -> %u.%u.%u.%u => %s (tx_port=%u tx_q=%u)\n",
                        lcore_id, rx_port,
                        (sip >> 24) & 0xFF, (sip >> 16) & 0xFF, (sip >> 8) & 0xFF, sip & 0xFF,
                        (dip >> 24) & 0xFF, (dip >> 16) & 0xFF, (dip >> 8) & 0xFF, dip & 0xFF,
                        action_str, tx_port, my_tx_queue);
                }
                worker_diag_count++;
            }

            if (ret < 0) {
                rte_pktmbuf_free(m);
                lstats->dropped++;
                continue;
            }

            /* Handle reply packets (SYN-ACK etc.) -- back to RX port */
            if (unlikely(l1_result.reply_pkt != NULL)) {
                lstats->tx_bytes += l1_result.reply_pkt->pkt_len;
                sw_rss_batch_enqueue(&my_worker->tx_batch[rx_port],
                                      rx_port, my_tx_queue,
                                      l1_result.reply_pkt);
            }

            /* Handle forward packets */
            if (unlikely(l1_result.forward_pkt != NULL)) {
                uint16_t fwd_port = l1_result.forward_port;
                if (unlikely(fwd_port >= RTE_MAX_ETHPORTS)) {
                    rte_pktmbuf_free(l1_result.forward_pkt);
                    lstats->dropped++;
                } else {
                    lstats->tx_bytes += l1_result.forward_pkt->pkt_len;
                    sw_rss_batch_enqueue(&my_worker->tx_batch[fwd_port],
                                          fwd_port, my_tx_queue,
                                          l1_result.forward_pkt);
                }
            }

            /* Handle original packet based on L1 action */
            switch (l1_result.action) {
                case L1_ACTION_DROP:
                case L1_ACTION_REPLY:
                    rte_pktmbuf_free(m);
                    lstats->dropped++;
                    break;

                case L1_ACTION_REPLY_INPLACE:
                    lstats->tx_bytes += m->pkt_len;
                    sw_rss_batch_enqueue(&my_worker->tx_batch[rx_port],
                                          rx_port, my_tx_queue, m);
                    break;

                case L1_ACTION_ACCEPT:
                case L1_ACTION_ACCEPT_MODIFIED: {
                    if (unlikely(do_mac_update)) {
                        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
                        rte_ether_addr_copy(&ports_eth_addr[tx_port], &eth->src_addr);
                    }
                    lstats->tx_bytes += m->pkt_len;
                    sw_rss_batch_enqueue(&my_worker->tx_batch[tx_port],
                                          tx_port, my_tx_queue, m);
                    break;
                }

                default:
                    rte_pktmbuf_free(m);
                    lstats->dropped++;
                    break;
            }
        }
    }

    /* Flush remaining TX batches on exit */
    for (unsigned p = 0; p < sw_rss.nb_rx_ports; p++) {
        uint16_t pid = sw_rss.rx_ports[p];
        sw_rss_batch_flush(&my_worker->tx_batch[pid], pid, my_tx_queue);
        uint16_t dst = dst_ports[pid];
        if (dst != pid)
            sw_rss_batch_flush(&my_worker->tx_batch[dst], dst, my_tx_queue);
    }
}

// ==================== Packet Processing ====================

/**
 * Main packet processing loop - RSS aware
 * Each lcore processes its assigned queue(s) on assigned port(s)
 */
static void main_loop(void)
{
    struct rte_mbuf *pkts[MAX_PKT_BURST];
    const unsigned lcore_id = rte_lcore_id();
    struct lcore_queue_conf * const qconf = &lcore_queue_conf[lcore_id];
    uint64_t * const sample_counter = &lcore_sample_counter[lcore_id];

    // Per-lcore stats pointer - NO ATOMICS needed, we own this cache line
    struct lcore_stats * const lstats = &lcore_statistics[lcore_id];

    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    uint64_t prev_tsc = 0;

    const unsigned n_rx_port = qconf->n_rx_port;

    if (n_rx_port == 0) {
        RTE_LOG(INFO, L2FWD, "lcore %u idle (no ports assigned)\n", lcore_id);
        while (!force_quit)
            rte_pause();
        return;
    }

    // Pre-compute port/queue info for fast path
    struct {
        uint16_t rx_port;
        uint16_t rx_queue;
        uint16_t tx_port;
        uint16_t tx_queue;
        struct rte_eth_dev_tx_buffer *tx_buf;
        struct rte_eth_dev_tx_buffer *reply_buf;   // TX buffer for reply packets (same port as rx)
        struct rte_eth_dev_tx_buffer *forward_buf; // TX buffer for forward packets (opposite port)
        struct rte_ether_addr *src_mac;
        struct port_stats *rx_stats;
        struct port_stats *tx_stats;
    } port_cache[MAX_RX_QUEUE_PER_LCORE];

    for (unsigned i = 0; i < n_rx_port; i++) {
        port_cache[i].rx_port = qconf->rx_port_list[i];
        port_cache[i].rx_queue = qconf->rx_queue_list[i];
        port_cache[i].tx_port = dst_ports[port_cache[i].rx_port];
        port_cache[i].tx_queue = qconf->tx_queue_list[i];
        port_cache[i].tx_buf = tx_buffer[port_cache[i].tx_port][port_cache[i].tx_queue];
        // Reply buffer = TX buffer for RX port (reply goes back to sender)
        port_cache[i].reply_buf = tx_buffer[port_cache[i].rx_port][port_cache[i].rx_queue];
        // Forward buffer = TX buffer for TX port (forward goes to opposite port)
        port_cache[i].forward_buf = tx_buffer[port_cache[i].tx_port][port_cache[i].tx_queue];
        port_cache[i].src_mac = &ports_eth_addr[port_cache[i].tx_port];
        port_cache[i].rx_stats = &port_statistics[port_cache[i].rx_port];
        port_cache[i].tx_stats = &port_statistics[port_cache[i].tx_port];
    }

    const int do_mac_update = mac_updating;

    RTE_LOG(INFO, L2FWD, "lcore %u: processing %u port/queue pairs, MAC update=%d\n",
            lcore_id, n_rx_port, do_mac_update);
    
    for (unsigned i = 0; i < n_rx_port; i++) {
        RTE_LOG(INFO, L2FWD, "  lcore %u: RX port %u queue %u -> TX port %u queue %u\n",
                lcore_id, port_cache[i].rx_port, port_cache[i].rx_queue,
                port_cache[i].tx_port, port_cache[i].tx_queue);
    }

    const uint64_t maint_interval_tsc = rte_get_tsc_hz();
    uint64_t prev_maint_tsc = rte_rdtsc();

    // Per-core RX pps tracking
    const uint64_t pps_interval_tsc = rte_get_tsc_hz(); // 1 second
    uint64_t prev_pps_tsc = rte_rdtsc();
    uint64_t pps_rx_count = 0;

    // Diagnostic: log first packets to confirm NIC is receiving
    uint32_t hwrss_diag_count = 0;
    #define HWRSS_DIAG_PACKETS 5

    while (likely(!force_quit)) {
        const uint64_t cur_tsc = rte_rdtsc();

        // Per-core packets/sec print (every ~1 second)
        if (unlikely(cur_tsc - prev_pps_tsc > pps_interval_tsc)) {
            double elapsed = (double)(cur_tsc - prev_pps_tsc) / rte_get_tsc_hz();
            RTE_LOG(INFO, L2FWD, "lcore %u: %.0f pkt/s from %u RX queue(s)\n",
                    lcore_id, pps_rx_count / elapsed, n_rx_port);
            pps_rx_count = 0;
            prev_pps_tsc = cur_tsc;
        }

        // TX buffer drain - flush all buffers (forward, reply)
        if (unlikely(cur_tsc - prev_tsc > drain_tsc)) {
            for (unsigned i = 0; i < n_rx_port; i++) {
                // Flush forward/accept buffer
                uint16_t sent = rte_eth_tx_buffer_flush(
                    port_cache[i].tx_port,
                    port_cache[i].tx_queue,
                    port_cache[i].tx_buf);
                if (sent > 0) {
                    lstats->tx_packets += sent;
                }
                // Flush reply buffer (SYN-ACKs go back to same port)
                sent = rte_eth_tx_buffer_flush(
                    port_cache[i].rx_port,
                    port_cache[i].rx_queue,
                    port_cache[i].reply_buf);
                if (sent > 0) {
                    lstats->tx_packets += sent;
                }
            }
            prev_tsc = cur_tsc;
        }

        // Periodic maintenance (only on lcore 0 to avoid duplicate work)
        // Runs every 1 second (maint_interval_tsc = rte_get_tsc_hz())
        if (lcore_id == rte_get_main_lcore() &&
            unlikely(cur_tsc - prev_maint_tsc > maint_interval_tsc)) {

            // Check for SIGHUP config reload request
            if (unlikely(reload_config)) {
                reload_config = 0;
                RTE_LOG(INFO, L2FWD, "Processing config hot-reload request...\n");

                // Reload Layer 1 config (rate limits, timeouts, validation)
                if (layer1_config_reload(L1_DEFAULT_CONFIG_FILE) == 0) {
                    layer1_refresh_cached_config();
                    RTE_LOG(INFO, L2FWD, "Layer 1 config reloaded successfully\n");
                } else {
                    RTE_LOG(ERR, L2FWD, "Layer 1 config reload failed\n");
                }

                // Reload Layer 2 config (detection thresholds, weights)
                if (layer2_reload_config() == 0) {
                    RTE_LOG(INFO, L2FWD, "Layer 2 config reloaded successfully\n");
                } else {
                    RTE_LOG(ERR, L2FWD, "Layer 2 config reload failed\n");
                }
            }

            uint32_t cleaned = layer1_maintenance();
            if (cleaned > 0) {
                RTE_LOG(DEBUG, L2FWD, "Maintenance cleaned %u entries\n", cleaned);
            }

            // Update window statistics (1s, 10s, 60s sliding windows)
            // Aggregates per-lcore counters and computes derived metrics
            window_stats_tick();

            prev_maint_tsc = cur_tsc;
        }

        // Process packets from each assigned port/queue
        for (unsigned i = 0; i < n_rx_port; i++) {
            const uint64_t poll_start_tsc = rte_rdtsc();

            const uint16_t nb_rx = rte_eth_rx_burst(
                port_cache[i].rx_port,
                port_cache[i].rx_queue,  // Use assigned RX queue
                pkts, MAX_PKT_BURST);

            pps_rx_count += nb_rx;

            if (unlikely(nb_rx == 0)) {
                continue;
            }

            // Diagnostic: log first few packets
            if (unlikely(hwrss_diag_count < HWRSS_DIAG_PACKETS)) {
                for (uint16_t d = 0; d < nb_rx && hwrss_diag_count < HWRSS_DIAG_PACKETS; d++) {
                    const struct rte_ether_hdr *deth = rte_pktmbuf_mtod(pkts[d], const struct rte_ether_hdr *);
                    uint16_t etype = rte_be_to_cpu_16(deth->ether_type);
                    if (etype == RTE_ETHER_TYPE_IPV4) {
                        const struct rte_ipv4_hdr *dip = (const struct rte_ipv4_hdr *)(deth + 1);
                        uint32_t sip = rte_be_to_cpu_32(dip->src_addr);
                        uint32_t d_ip = rte_be_to_cpu_32(dip->dst_addr);
                        RTE_LOG(INFO, L2FWD,
                            "[DIAG] lcore %u port %u q %u: IPv4 %u.%u.%u.%u -> %u.%u.%u.%u proto=%u len=%u\n",
                            lcore_id, port_cache[i].rx_port, port_cache[i].rx_queue,
                            (sip >> 24) & 0xFF, (sip >> 16) & 0xFF, (sip >> 8) & 0xFF, sip & 0xFF,
                            (d_ip >> 24) & 0xFF, (d_ip >> 16) & 0xFF, (d_ip >> 8) & 0xFF, d_ip & 0xFF,
                            dip->next_proto_id, rte_be_to_cpu_16(dip->total_length));
                    } else {
                        RTE_LOG(INFO, L2FWD, "[DIAG] lcore %u port %u q %u: ether_type=0x%04x len=%u\n",
                                lcore_id, port_cache[i].rx_port, port_cache[i].rx_queue,
                                etype, pkts[d]->pkt_len);
                    }
                    hwrss_diag_count++;
                }
            }

            // NOTE: rx_packets stats moved inside per-packet loop (after enforcement check)

            // Prefetch first few packets
            for (uint16_t p = 0; p < RTE_MIN(nb_rx, (uint16_t)PREFETCH_OFFSET); p++) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts[p], void *));
            }

            struct rte_eth_dev_tx_buffer * const tx_buf = port_cache[i].tx_buf;
            const uint16_t tx_port = port_cache[i].tx_port;
            const uint16_t tx_queue = port_cache[i].tx_queue;
            struct rte_ether_addr * const src_mac = port_cache[i].src_mac;

            // Check enforcement once per batch (avoid function call per packet)
            // Only enforce on client-facing port (inbound traffic).
            // Server-facing port carries return traffic with client dst IPs
            // that are NOT in the protected list -- must not be dropped.
            const bool enforce_protected =
                (port_cache[i].rx_port == PORT_FACING_CLIENTS) &&
                ip_protected_enforcement_enabled();

            // In main_loop(), replace the packet processing section:
            for (uint16_t j = 0; j < nb_rx; j++) {
                struct rte_mbuf *m = pkts[j];

                // Prefetch next packet
                if (j + PREFETCH_OFFSET < nb_rx) {
                    rte_prefetch0(rte_pktmbuf_mtod(pkts[j + PREFETCH_OFFSET], void *));
                }

                // ========== EARLY ENFORCEMENT CHECK (BEFORE ANY STATS) ==========
                // Drop packets to non-protected IPs as early as possible
                // This saves CPU cycles and ensures dropped packets don't appear in stats
                if (enforce_protected) {
                    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
                    if (likely(rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV4)) {
                        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
                        if (!ip_protected_lookup(ip->dst_addr)) {
                            // Packet destined to non-protected IP - drop immediately
                            // Don't count in any stats - as if it never arrived
                            rte_pktmbuf_free(m);
                            continue;
                        }
                    }
                }

                // Only count packets that pass enforcement check
                lstats->rx_packets++;
                lstats->rx_bytes += m->pkt_len;

                // Traffic sampling (only for packets that pass enforcement check)
                if (unlikely((++(*sample_counter) % TRAFFIC_SAMPLE_RATE) == 0)) {
                    traffic_capture_packet(m, port_cache[i].rx_port, 0);
                }

                // Layer 1 processing with extended API (pass queue_id!)
                struct layer1_result l1_result;
                int ret = layer1_process_packet_ex(m, port_cache[i].rx_port, 
                                                    port_cache[i].rx_queue,
                                                    pktmbuf_pool, &l1_result);
                
                if (ret < 0) {
                    rte_pktmbuf_free(m);
                    lstats->dropped++;  // Per-lcore, no atomics
                    continue;
                }

                // Handle reply packets using BUFFERED TX (batched for better throughput)
                // Reply packets (e.g., SYN-ACK) go back to RX port
                if (unlikely(l1_result.reply_pkt != NULL)) {
                    lstats->tx_bytes += l1_result.reply_pkt->pkt_len;
                    rte_eth_tx_buffer(port_cache[i].rx_port,
                                      port_cache[i].rx_queue,
                                      port_cache[i].reply_buf,
                                      l1_result.reply_pkt);
                }

                // Handle forward packets using BUFFERED TX (batched for better throughput)
                // Forward packets (e.g., SYN to server, ACK to server)
                // IMPORTANT: Use l1_result.forward_port, NOT port_cache tx_port!
                // Layer 1 determines the correct destination port based on context:
                // - Inbound SYN proxy: forward_port = opposite port (to server)
                // - Outbound SYN proxy: forward_port = same port (ACK stays on server side)
                if (unlikely(l1_result.forward_pkt != NULL)) {
                    uint16_t fwd_port = l1_result.forward_port;
                    uint16_t fwd_queue = l1_result.forward_queue;
                    if (unlikely(fwd_port >= RTE_MAX_ETHPORTS ||
                                 fwd_queue >= MAX_TX_QUEUES_PER_PORT)) {
                        RTE_LOG(ERR, L2FWD,
                                "Invalid forward port/queue %u/%u, dropping\n",
                                fwd_port, fwd_queue);
                        rte_pktmbuf_free(l1_result.forward_pkt);
                        lstats->dropped++;
                    } else {
                        lstats->tx_bytes += l1_result.forward_pkt->pkt_len;
                        struct rte_eth_dev_tx_buffer *fwd_buf =
                            tx_buffer[fwd_port][fwd_queue];
                        rte_eth_tx_buffer(fwd_port, fwd_queue, fwd_buf,
                                          l1_result.forward_pkt);
                    }
                }

                // Handle original packet based on action
                switch (l1_result.action) {
                    case L1_ACTION_DROP:
                    case L1_ACTION_REPLY:
                        rte_pktmbuf_free(m);
                        lstats->dropped++;  // Per-lcore, no atomics
                        break;

                    case L1_ACTION_REPLY_INPLACE:
                        // ZERO-COPY: Original mbuf was transformed into reply
                        // Send it back on the SAME port (reply to client)
                        // NOTE: Don't increment tx_packets here - it's counted
                        // when the buffer is flushed to avoid double-counting
                        lstats->tx_bytes += m->pkt_len;
                        rte_eth_tx_buffer(port_cache[i].rx_port,
                                          port_cache[i].rx_queue,
                                          port_cache[i].reply_buf, m);
                        break;

                    case L1_ACTION_ACCEPT:
                    case L1_ACTION_ACCEPT_MODIFIED:
                        if (unlikely(do_mac_update)) {
                            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
                            rte_ether_addr_copy(src_mac, &eth->src_addr);
                        }
                        lstats->tx_bytes += m->pkt_len;
                        rte_eth_tx_buffer(tx_port, tx_queue, tx_buf, m);
                        break;

                    default:
                        rte_pktmbuf_free(m);
                        lstats->dropped++;  // Per-lcore, no atomics
                        break;
                }
            }

            // Track busy cycles after processing packets
            lcore_cycles_add_busy(rte_rdtsc() - poll_start_tsc);
        }
    }

    // Flush remaining packets on exit (both forward and reply buffers)
    for (unsigned i = 0; i < n_rx_port; i++) {
        rte_eth_tx_buffer_flush(port_cache[i].tx_port, port_cache[i].tx_queue,
                                port_cache[i].tx_buf);
        rte_eth_tx_buffer_flush(port_cache[i].rx_port, port_cache[i].rx_queue,
                                port_cache[i].reply_buf);
    }
}

static int packet_monitor_launch(__rte_unused void *arg) {
    if (sw_rss.enabled) {
        unsigned lcore_id = rte_lcore_id();
        if (lcore_id == sw_rss.distributor_lcore) {
            main_loop_sw_distributor();
        } else {
            main_loop_sw_worker();
        }
    } else {
        main_loop();  /* HW RSS path -- unchanged */
    }
    return 0;
}

static void signal_handler(int signum) {
    /* printf() is NOT async-signal-safe (holds internal locks that can deadlock).
     * Use write() which is async-signal-safe per POSIX.
     * Assign return value to a local variable to satisfy -Wunused-result. */
    ssize_t _wr;
    if (signum == SIGINT || signum == SIGTERM) {
        static const char msg[] = "\nSignal received, exiting...\n";
        _wr = write(STDERR_FILENO, msg, sizeof(msg) - 1);
        (void)_wr;
        force_quit = true;
    } else if (signum == SIGHUP) {
        static const char msg[] = "\nSIGHUP received, scheduling config reload...\n";
        _wr = write(STDERR_FILENO, msg, sizeof(msg) - 1);
        (void)_wr;
        reload_config = 1;
    }
}

static void usage(const char *prgname) {
    printf("%s [EAL options] -- -p PORTMASK [-P] [-q NQ] [--no-mac-updating]\n", prgname);
    printf("  -p PORTMASK: hexadecimal bitmask of ports to use\n");
    printf("  -P: enable promiscuous mode\n");
    printf("  -q NQ: number of queues per lcore (default: 1)\n");
    printf("  --no-mac-updating: disable MAC address update\n");
    printf("  --mac-updating: enable MAC address update\n");
}

static int parse_args(int argc, char **argv) {
    static struct option lgopts[] = {
        {"mac-updating", no_argument, 0, 257},
        {"no-mac-updating", no_argument, 0, 256},
        {NULL, 0, 0, 0}
    };
    
    int opt, option_index;
    char *end;

    while ((opt = getopt_long(argc, argv, "p:Pq:", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'p':
            enabled_port_mask = strtoul(optarg, &end, 16);
            if (*optarg == '\0' || *end != '\0' || enabled_port_mask == 0) {
                printf("Invalid portmask\n");
                usage(argv[0]);
                return -1;
            }
            break;
        case 'P':
            promiscuous_on = 1;
            break;
        case 'q': {
            unsigned long n = strtoul(optarg, &end, 10);
            if (*end != '\0' || n == 0 || n >= MAX_RX_QUEUE_PER_LCORE) {
                printf("Invalid queue number\n");
                return -1;
            }
            rx_queue_per_lcore = n;
            break;
        }
        case 256: mac_updating = 0; break;
        case 257: mac_updating = 1; break;
        default: usage(argv[0]); return -1;
        }
    }
    return optind - 1;
}

static int wait_for_port_link_up(uint16_t portid, uint32_t timeout_ms) {
    struct rte_eth_link link;
    uint32_t waited = 0;
    const uint32_t check_interval = 100;

    printf("  Waiting for link up on port %u", portid);
    fflush(stdout);

    while (waited < timeout_ms) {
        memset(&link, 0, sizeof(link));
        int ret = rte_eth_link_get_nowait(portid, &link);
        
        if (ret == 0 && link.link_status == RTE_ETH_LINK_UP) {
            printf(" Link UP - speed %u Mbps - %s\n", 
                   link.link_speed,
                   link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX ? "full-duplex" : "half-duplex");
            return 0;
        }
        
        printf(".");
        fflush(stdout);
        rte_delay_ms(check_interval);
        waited += check_interval;
    }
    
    printf(" TIMEOUT\n");
    return -1;
}

/**
 * Initialize a port with RSS and multiple queues
 */
/**
 * Initialize a port with RSS and multiple queues
 */
static int init_port(uint16_t portid, uint16_t nb_rx_queues, uint16_t nb_tx_queues) {
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf local_port_conf = port_conf_default;
    int ret;
    uint16_t q;

    ret = rte_eth_dev_info_get(portid, &dev_info);
    if (ret != 0) {
        printf("Error getting device info for port %u: %s\n", portid, rte_strerror(-ret));
        return ret;
    }

    printf("\n=== Initializing port %u ===\n", portid);
    printf("  Driver: %s\n", dev_info.driver_name);
    printf("  Max RX queues: %u\n", dev_info.max_rx_queues);
    printf("  Max TX queues: %u\n", dev_info.max_tx_queues);
    printf("  RSS key size: %u\n", dev_info.hash_key_size);
    printf("  RSS offloads: 0x%" PRIx64 "\n", dev_info.flow_type_rss_offloads);

    // Clamp queue counts to device limits
    nb_rx_queues = RTE_MIN(nb_rx_queues, dev_info.max_rx_queues);
    nb_tx_queues = RTE_MIN(nb_tx_queues, dev_info.max_tx_queues);

    // Ensure at least 1 queue
    nb_rx_queues = RTE_MAX(nb_rx_queues, 1);
    nb_tx_queues = RTE_MAX(nb_tx_queues, 1);

    // Check if RSS is actually supported
    // RSS requires: hash_key_size > 0 OR device handles key internally, 
    // AND device supports RSS offloads, AND multiple queues requested
    uint64_t rss_hf_cap = dev_info.flow_type_rss_offloads;
    bool rss_supported = (rss_hf_cap != 0) && (nb_rx_queues > 1);

    if (rss_supported) {
        // Configure RSS
        local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        
        // Only enable RSS hash functions that the device supports
        local_port_conf.rx_adv_conf.rss_conf.rss_hf = 
            (RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_SCTP) & rss_hf_cap;

        // Check if device accepts a custom RSS key
        if (dev_info.hash_key_size > 0) {
            // Device accepts custom key - use our symmetric key
            // Make sure our key length matches what device expects
            if (dev_info.hash_key_size == RSS_HASH_KEY_LENGTH) {
                local_port_conf.rx_adv_conf.rss_conf.rss_key = rss_symmetric_key;
                local_port_conf.rx_adv_conf.rss_conf.rss_key_len = RSS_HASH_KEY_LENGTH;
                printf("  RSS: Using custom symmetric key (%u bytes)\n", RSS_HASH_KEY_LENGTH);
            } else {
                // Key size mismatch - let device use its default
                local_port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
                local_port_conf.rx_adv_conf.rss_conf.rss_key_len = 0;
                printf("  RSS: Key size mismatch (device wants %u, we have %u), using device default\n",
                       dev_info.hash_key_size, RSS_HASH_KEY_LENGTH);
            }
        } else {
            // Device doesn't accept custom key (hash_key_size == 0)
            // Let driver use its internal default key
            local_port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
            local_port_conf.rx_adv_conf.rss_conf.rss_key_len = 0;
            printf("  RSS: Device manages key internally (no custom key)\n");
        }

        if (local_port_conf.rx_adv_conf.rss_conf.rss_hf == 0) {
            printf("  WARNING: No usable RSS hash functions, falling back to single queue\n");
            local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
            nb_rx_queues = 1;
            rss_supported = false;
        } else {
            printf("  RSS hash functions: 0x%" PRIx64 "\n", 
                   local_port_conf.rx_adv_conf.rss_conf.rss_hf);
        }
    } else {
        // No RSS - single RX queue mode, but keep multiple TX queues
        // for SW RSS workers to transmit independently
        local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
        local_port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
        local_port_conf.rx_adv_conf.rss_conf.rss_key_len = 0;
        local_port_conf.rx_adv_conf.rss_conf.rss_hf = 0;
        nb_rx_queues = 1;
        // nb_tx_queues preserved -- SW RSS workers each need a TX queue
        printf("  RSS: Not supported or single queue requested (keeping %u TX queues for SW RSS)\n",
               nb_tx_queues);
    }

    printf("  Configuring: %u RX queues, %u TX queues\n", nb_rx_queues, nb_tx_queues);

    // Enable offloads if supported
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    // Enable TX checksum offloads for SYN proxy performance
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
        local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
        printf("  TX offload: IPv4 checksum enabled\n");
    }
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
        local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
        printf("  TX offload: TCP checksum enabled\n");
    }
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
        local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
        printf("  TX offload: UDP checksum enabled\n");
    }

    // Configure the port
    ret = rte_eth_dev_configure(portid, nb_rx_queues, nb_tx_queues, &local_port_conf);
    if (ret < 0) {
        printf("Cannot configure port %u (err=%d): %s\n", portid, ret, rte_strerror(-ret));
        
        // If RSS config failed, retry without RSS
        if (local_port_conf.rxmode.mq_mode == RTE_ETH_MQ_RX_RSS) {
            printf("  Retrying without RSS...\n");
            local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
            local_port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
            local_port_conf.rx_adv_conf.rss_conf.rss_key_len = 0;
            local_port_conf.rx_adv_conf.rss_conf.rss_hf = 0;
            nb_rx_queues = 1;
            nb_tx_queues = 1;
            
            ret = rte_eth_dev_configure(portid, nb_rx_queues, nb_tx_queues, &local_port_conf);
            if (ret < 0) {
                printf("Cannot configure port %u even without RSS (err=%d)\n", portid, ret);
                return ret;
            }
            rss_supported = false;
        } else {
            return ret;
        }
    }

    // Adjust descriptor counts
    uint16_t rxd = RTE_MIN(nb_rxd, dev_info.rx_desc_lim.nb_max);
    uint16_t txd = RTE_MIN(nb_txd, dev_info.tx_desc_lim.nb_max);
    rxd = RTE_MAX(rxd, dev_info.rx_desc_lim.nb_min);
    txd = RTE_MAX(txd, dev_info.tx_desc_lim.nb_min);
    
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &rxd, &txd);
    if (ret < 0) {
        printf("Cannot adjust descriptors for port %u\n", portid);
        return ret;
    }
    printf("  Descriptors: %u RX, %u TX per queue\n", rxd, txd);

    // Get MAC address
    ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
    if (ret < 0) {
        printf("Cannot get MAC for port %u\n", portid);
        return ret;
    }

    // Setup RX queues
    struct rte_eth_rxconf rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = local_port_conf.rxmode.offloads;
    
    for (q = 0; q < nb_rx_queues; q++) {
        ret = rte_eth_rx_queue_setup(portid, q, rxd,
                                     rte_eth_dev_socket_id(portid),
                                     &rxq_conf, pktmbuf_pool);
        if (ret < 0) {
            printf("Failed to setup RX queue %u on port %u\n", q, portid);
            return ret;
        }
    }

    // Setup TX queues
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = local_port_conf.txmode.offloads;
    
    for (q = 0; q < nb_tx_queues; q++) {
        ret = rte_eth_tx_queue_setup(portid, q, txd,
                                     rte_eth_dev_socket_id(portid),
                                     &txq_conf);
        if (ret < 0) {
            printf("Failed to setup TX queue %u on port %u\n", q, portid);
            return ret;
        }

        // Allocate TX buffer for this queue
        tx_buffer[portid][q] = rte_zmalloc_socket("tx_buffer",
            RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST * 4),
            RTE_CACHE_LINE_SIZE,
            rte_eth_dev_socket_id(portid));
        
        if (!tx_buffer[portid][q]) {
            printf("Failed to allocate TX buffer for port %u queue %u\n", portid, q);
            return -ENOMEM;
        }
        
        rte_eth_tx_buffer_init(tx_buffer[portid][q], MAX_PKT_BURST * 4);
        rte_eth_tx_buffer_set_err_callback(tx_buffer[portid][q],
            rte_eth_tx_buffer_count_callback,
            &port_statistics[portid].dropped);
    }

    // Disable ptype parsing for performance
    rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);

    // Start the port
    ret = rte_eth_dev_start(portid);
    if (ret < 0) {
        printf("Failed to start port %u\n", portid);
        return ret;
    }

    // Enable promiscuous mode if requested
    if (promiscuous_on) {
        ret = rte_eth_promiscuous_enable(portid);
        if (ret != 0) {
            printf("Failed to enable promiscuous mode on port %u\n", portid);
        }
    }

    // Store RSS info
    port_rss_info[portid].nb_rx_queues = nb_rx_queues;
    port_rss_info[portid].nb_tx_queues = nb_tx_queues;
    port_rss_info[portid].rss_enabled = (local_port_conf.rxmode.mq_mode == RTE_ETH_MQ_RX_RSS);
    port_rss_info[portid].rss_hf = local_port_conf.rx_adv_conf.rss_conf.rss_hf;

    // Store TX offload flags for checksum offload support
    port_tx_offload_flags[portid] = local_port_conf.txmode.offloads;

    printf("  MAC: " RTE_ETHER_ADDR_PRT_FMT "\n", 
           RTE_ETHER_ADDR_BYTES(&ports_eth_addr[portid]));
    printf("  RSS: %s\n", port_rss_info[portid].rss_enabled ? "ENABLED" : "DISABLED (single queue)");
    
    wait_for_port_link_up(portid, 10000);
    
    return 0;
}

static void check_all_ports_link_status(uint32_t port_mask) {
    uint16_t portid;
    struct rte_eth_link link;

    printf("\n=== Port Link Status ===\n");
    RTE_ETH_FOREACH_DEV(portid) {
        if ((port_mask & (1 << portid)) == 0) continue;
        
        memset(&link, 0, sizeof(link));
        { int _r = rte_eth_link_get_nowait(portid, &link); (void)_r; }
        printf("Port %u: %s - %u Mbps - %u RX queues, %u TX queues\n", 
               portid, 
               link.link_status == RTE_ETH_LINK_UP ? "UP" : "DOWN",
               link.link_speed,
               port_rss_info[portid].nb_rx_queues,
               port_rss_info[portid].nb_tx_queues);
    }
    printf("========================\n");
}

/**
 * Assign queues to lcores
 * Strategy: Each lcore gets one queue from each port
 * This ensures symmetric handling of bidirectional flows
 */
static int assign_queues_to_lcores(uint32_t port_mask) {
    uint16_t portid;
    unsigned lcore_id;
    uint16_t queue_id = 0;
    unsigned nb_ports_in_mask = 0;

    // Count enabled ports
    RTE_ETH_FOREACH_DEV(portid) {
        if ((port_mask & (1 << portid)) != 0) {
            nb_ports_in_mask++;
        }
    }

    printf("\n=== Queue-to-Lcore Assignment ===\n");

    // Assign queues to each worker lcore
    queue_id = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        struct lcore_queue_conf *qconf = &lcore_queue_conf[lcore_id];
        qconf->n_rx_port = 0;

        // Check if we have queues left to assign
        bool has_queues = false;
        RTE_ETH_FOREACH_DEV(portid) {
            if ((port_mask & (1 << portid)) == 0) continue;
            if (queue_id < port_rss_info[portid].nb_rx_queues) {
                has_queues = true;
                break;
            }
        }

        if (!has_queues) {
            printf("  lcore %u: idle (no more queues)\n", lcore_id);
            continue;
        }

        // Assign one queue from each port to this lcore
        RTE_ETH_FOREACH_DEV(portid) {
            if ((port_mask & (1 << portid)) == 0) continue;
            
            if (queue_id < port_rss_info[portid].nb_rx_queues) {
                unsigned idx = qconf->n_rx_port;
                qconf->rx_port_list[idx] = portid;
                qconf->rx_queue_list[idx] = queue_id;
                qconf->tx_queue_list[idx] = queue_id;  // Use same queue ID for TX
                qconf->n_rx_port++;
                
                printf("  lcore %u: port %u RX queue %u -> TX queue %u\n",
                       lcore_id, portid, queue_id, queue_id);
            }
        }

        queue_id++;
        nb_worker_lcores++;
    }

    // Also assign to main lcore if it should process packets
    lcore_id = rte_get_main_lcore();
    struct lcore_queue_conf *qconf = &lcore_queue_conf[lcore_id];
    
    // Check if we have more queues to assign
    bool has_queues = false;
    RTE_ETH_FOREACH_DEV(portid) {
        if ((port_mask & (1 << portid)) == 0) continue;
        if (queue_id < port_rss_info[portid].nb_rx_queues) {
            has_queues = true;
            break;
        }
    }

    if (has_queues && qconf->n_rx_port == 0) {
        RTE_ETH_FOREACH_DEV(portid) {
            if ((port_mask & (1 << portid)) == 0) continue;
            
            if (queue_id < port_rss_info[portid].nb_rx_queues) {
                unsigned idx = qconf->n_rx_port;
                qconf->rx_port_list[idx] = portid;
                qconf->rx_queue_list[idx] = queue_id;
                qconf->tx_queue_list[idx] = queue_id;
                qconf->n_rx_port++;
                
                printf("  lcore %u (main): port %u RX queue %u -> TX queue %u\n",
                       lcore_id, portid, queue_id, queue_id);
            }
        }
        nb_worker_lcores++;
    }

    printf("=================================\n");
    printf("Total worker lcores: %u\n", nb_worker_lcores);

    return 0;
}

int dpdk_init(int argc, char **argv) {
    uint16_t nb_ports, portid;
    unsigned nb_ports_in_mask = 0, nb_ports_available = 0;
    uint16_t nb_queues_per_port;
    int ret;

    // Initialize EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);  /* Config hot-reload on SIGHUP */

    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid arguments\n");

    printf("MAC updating %s\n", mac_updating ? "enabled" : "disabled");

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

    if (enabled_port_mask & ~((1U << nb_ports) - 1))
        rte_exit(EXIT_FAILURE, "Invalid portmask (ports don't exist)\n");

    // Count available lcores for queue calculation
    unsigned nb_lcores = 0;
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        nb_lcores++;
    }
    printf("Available lcores: %u\n", nb_lcores);

    // Determine number of queues per port based on available lcores
    nb_queues_per_port = RTE_MIN(nb_lcores, (unsigned)MAX_RX_QUEUES_PER_PORT);
    printf("Queues per port: %u\n", nb_queues_per_port);

    // Initialize port mapping (port 0 <-> port 1)
    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
        dst_ports[portid] = 0;

    uint16_t last_port = 0;
    RTE_ETH_FOREACH_DEV(portid) {
        if ((enabled_port_mask & (1 << portid)) == 0) continue;
        if (nb_ports_in_mask % 2) {
            dst_ports[portid] = last_port;
            dst_ports[last_port] = portid;
        } else {
            last_port = portid;
        }
        nb_ports_in_mask++;
    }
    if (nb_ports_in_mask % 2) {
        dst_ports[last_port] = last_port;  // Loop back to self
    }

    // Calculate mbuf pool size
    unsigned nb_mbufs = RTE_MAX(
        nb_ports * nb_queues_per_port * (nb_rxd + nb_txd + MAX_PKT_BURST * 8) + 
        nb_lcores * MEMPOOL_CACHE_SIZE,
        131072U);
    
    printf("Creating mbuf pool with %u mbufs\n", nb_mbufs);
    
    pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
        MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pktmbuf_pool)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    // Initialize each port with RSS
    RTE_ETH_FOREACH_DEV(portid) {
        if ((enabled_port_mask & (1 << portid)) == 0) continue;
        
        if (init_port(portid, nb_queues_per_port, nb_queues_per_port) < 0)
            rte_exit(EXIT_FAILURE, "Failed to initialize port %u\n", portid);
        
        nb_ports_available++;
    }

    if (nb_ports_available == 0)
        rte_exit(EXIT_FAILURE, "No ports available after initialization\n");

    // Assign queues to lcores (for HW RSS path)
    if (assign_queues_to_lcores(enabled_port_mask) < 0)
        rte_exit(EXIT_FAILURE, "Failed to assign queues to lcores\n");

    // Initialize software RSS if hardware RSS unavailable
    if (sw_rss_init(enabled_port_mask, nb_lcores) < 0)
        rte_exit(EXIT_FAILURE, "Failed to initialize software RSS\n");

    check_all_ports_link_status(enabled_port_mask);
    rte_delay_ms(2000);

    printf("\n========================================\n");
    printf("  DPDK Anti-DDoS with RSS + SYN Proxy\n");
    printf("========================================\n");
    printf("  Ports: %u\n", nb_ports_available);
    printf("  Worker lcores: %u\n", nb_worker_lcores);
    printf("  RX queues/port: %u\n", nb_queues_per_port);
    printf("  RSS: %s\n", sw_rss.enabled ? "SOFTWARE (Toeplitz + SPSC rings)" : "HARDWARE (Symmetric Toeplitz)");
    if (sw_rss.enabled)
        printf("  SW RSS workers: %u\n", sw_rss.nb_workers);
    printf("========================================\n\n");

    // Initialize subsystems
    if (system_monitor_init() < 0)
        printf("Warning: system monitor init failed\n");
    if (stats_socket_init() < 0)
        printf("Warning: stats socket init failed\n");
    if (traffic_monitor_init() < 0)
        printf("Warning: traffic monitor init failed\n");

    // Initialize control socket for real-time config updates from backend
    // Use defined constants instead of hardcoded absolute paths
    control_socket_set_config_path(L1_DEFAULT_CONFIG_FILE);
    if (control_socket_init() < 0)
        printf("Warning: control socket init failed\n");
    else
        printf("Control socket listening at %s\n", CONTROL_SOCKET_PATH);

    printf("Initializing Layer 1...\n");
    // Use defined constant for config path
    if (layer1_init(2000000, L1_DEFAULT_CONFIG_FILE) < 0)
        rte_exit(EXIT_FAILURE, "Failed to initialize Layer 1\n");

    // Initialize Layer 2 (Behavioral Monitor & Detection Engine)
    printf("Initializing Layer 2...\n");
    // Use defined constant for config path
    if (layer2_init(L2_DEFAULT_CONFIG_FILE) < 0) {
        printf("Warning: Layer 2 init failed, using defaults\n");
        if (layer2_init(NULL) < 0)
            rte_exit(EXIT_FAILURE, "Failed to initialize Layer 2\n");
    }

    // Start Layer 2 detection thread (runs at 1 Hz)
    if (layer2_start() < 0) {
        printf("Warning: Layer 2 thread start failed\n");
    } else {
        printf("Layer 2 detection thread started (1 Hz)\n");
    }

    // Launch worker threads
    rte_eal_mp_remote_launch(packet_monitor_launch, NULL, CALL_MAIN);
    
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    // ==================== Graceful Shutdown Sequence ====================
    printf("\n=== Initiating Graceful Shutdown ===\n");

    // Step 1: Drain TX buffers before stopping ports
    printf("Draining TX buffers...\n");
    RTE_ETH_FOREACH_DEV(portid) {
        if ((enabled_port_mask & (1 << portid)) == 0) continue;
        for (uint16_t q = 0; q < port_rss_info[portid].nb_tx_queues; q++) {
            if (tx_buffer[portid][q]) {
                rte_eth_tx_buffer_flush(portid, q, tx_buffer[portid][q]);
            }
        }
    }

    // Step 1.5: Clean up SW RSS rings (drain remaining mbufs)
    sw_rss_cleanup();

    // Step 2: Stop Layer 2 first (it reads from Layer 1)
    printf("Stopping Layer 2...\n");
    layer2_stop();
    layer2_save_baselines();  // Persist learned baselines
    layer2_cleanup();

    // Step 3: Stop control plane components
    printf("Stopping control plane...\n");
    control_socket_cleanup();
    traffic_monitor_cleanup();
    stats_socket_cleanup();
    system_monitor_cleanup();

    // Step 4: Print and cleanup Layer 1
    printf("Stopping Layer 1...\n");
    layer1_print_stats();
    layer1_cleanup();

    printf("\n=== Final Statistics ===\n");

    // Aggregate per-lcore stats
    struct aggregated_stats agg;
    aggregate_lcore_stats(&agg);

    printf("Aggregated (all lcores):\n");
    printf("  RX: %lu packets, %lu bytes\n", agg.rx_packets, agg.rx_bytes);
    printf("  TX: %lu packets\n", agg.tx_packets);
    printf("  Dropped: %lu\n", agg.dropped);
    printf("  L1 Accepted: %lu, Dropped: %lu\n", agg.l1_packets_accepted, agg.l1_packets_dropped);

    // Per-port info (for reference)
    RTE_ETH_FOREACH_DEV(portid) {
        if ((enabled_port_mask & (1 << portid)) == 0) continue;

        printf("Port %u: %u RX queues, %u TX queues\n", portid,
               port_rss_info[portid].nb_rx_queues,
               port_rss_info[portid].nb_tx_queues);
    }

    // Step 5: Cleanup ports
    printf("Stopping and closing ports...\n");
    RTE_ETH_FOREACH_DEV(portid) {
        if ((enabled_port_mask & (1 << portid)) == 0) continue;

        printf("  Port %u: stopping...\n", portid);
        int stop_ret = rte_eth_dev_stop(portid);
        if (stop_ret != 0) {
            printf("  Port %u: stop returned %d\n", portid, stop_ret);
        }

        printf("  Port %u: closing...\n", portid);
        rte_eth_dev_close(portid);

        // Free TX buffers for all queues
        for (uint16_t q = 0; q < port_rss_info[portid].nb_tx_queues; q++) {
            if (tx_buffer[portid][q]) {
                rte_free(tx_buffer[portid][q]);
                tx_buffer[portid][q] = NULL;
            }
        }
    }

    // Step 6: Final EAL cleanup
    printf("Cleaning up EAL...\n");
    rte_eal_cleanup();

    printf("\n=== Graceful Shutdown Complete ===\n");
    return ret;
}
