/**
 * @file layer1_benchmark.c
 * @brief Benchmark harness for Layer 1 packet processing performance
 *
 * Measures:
 * - Packets Per Second (PPS) throughput
 * - Per-packet latency (cycles and nanoseconds)
 * - CPU cycles per packet
 *
 * Usage:
 *   ./layer1_benchmark -l 0-3 -n 4 -- --packets 1000000 --warmup 10000
 *
 * This benchmark uses synthetic packets to isolate Layer 1 performance
 * from NIC I/O overhead.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <time.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_random.h>

#include "../../layer1/layer1.h"
#include "../../layer1/config/layer1_config.h"
#include "../../common/types.h"

// ==================== Configuration ====================

#define BENCHMARK_MEMPOOL_SIZE  (1 << 16)  // 64K mbufs
#define BENCHMARK_CACHE_SIZE    256
#define DEFAULT_PACKET_COUNT    1000000
#define DEFAULT_WARMUP_COUNT    10000
#define BATCH_SIZE              32

// ==================== Benchmark State ====================

struct benchmark_config {
    uint64_t packet_count;
    uint64_t warmup_count;
    bool test_tcp_syn;
    bool test_tcp_data;
    bool test_udp;
    bool test_mixed;
    bool verbose;
};

struct benchmark_results {
    uint64_t total_packets;
    uint64_t total_cycles;
    uint64_t min_cycles;
    uint64_t max_cycles;
    uint64_t accepted;
    uint64_t dropped;
    double elapsed_sec;
};

static struct rte_mempool *benchmark_pool = NULL;
static struct benchmark_config bench_cfg;
static struct benchmark_results results;

// ==================== Synthetic Packet Generation ====================

/**
 * Create a synthetic TCP SYN packet
 */
static struct rte_mbuf *create_tcp_syn_packet(void) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(benchmark_pool);
    if (!m) return NULL;

    // Allocate space for Ethernet + IP + TCP
    size_t pkt_len = sizeof(struct rte_ether_hdr) +
                     sizeof(struct rte_ipv4_hdr) +
                     sizeof(struct rte_tcp_hdr);

    char *data = rte_pktmbuf_append(m, pkt_len);
    if (!data) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memset(data, 0, pkt_len);

    // Ethernet header
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // IP header
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;  // IPv4, 5 words
    ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->src_addr = rte_cpu_to_be_32((10 << 24) | (rte_rand() & 0x00FFFFFF));  // 10.x.x.x
    ip->dst_addr = rte_cpu_to_be_32((192 << 24) | (168 << 16) | (1 << 8) | 1);  // 192.168.1.1

    // Calculate IP checksum
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // TCP header
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16((rte_rand() % 60000) + 1024);
    tcp->dst_port = rte_cpu_to_be_16(80);
    tcp->sent_seq = rte_cpu_to_be_32(rte_rand());
    tcp->data_off = 0x50;  // 5 words, no options
    tcp->tcp_flags = RTE_TCP_SYN_FLAG;
    tcp->rx_win = rte_cpu_to_be_16(65535);

    return m;
}

/**
 * Create a synthetic TCP data packet
 */
static struct rte_mbuf *create_tcp_data_packet(void) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(benchmark_pool);
    if (!m) return NULL;

    size_t payload_size = 64;
    size_t pkt_len = sizeof(struct rte_ether_hdr) +
                     sizeof(struct rte_ipv4_hdr) +
                     sizeof(struct rte_tcp_hdr) +
                     payload_size;

    char *data = rte_pktmbuf_append(m, pkt_len);
    if (!data) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memset(data, 0, pkt_len);

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + payload_size);
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->src_addr = rte_cpu_to_be_32((10 << 24) | (rte_rand() & 0x00FFFFFF));
    ip->dst_addr = rte_cpu_to_be_32((192 << 24) | (168 << 16) | (1 << 8) | 1);
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16((rte_rand() % 60000) + 1024);
    tcp->dst_port = rte_cpu_to_be_16(80);
    tcp->sent_seq = rte_cpu_to_be_32(rte_rand());
    tcp->recv_ack = rte_cpu_to_be_32(rte_rand());
    tcp->data_off = 0x50;
    tcp->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
    tcp->rx_win = rte_cpu_to_be_16(65535);

    return m;
}

/**
 * Create a synthetic UDP packet
 */
static struct rte_mbuf *create_udp_packet(void) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(benchmark_pool);
    if (!m) return NULL;

    size_t payload_size = 64;
    size_t pkt_len = sizeof(struct rte_ether_hdr) +
                     sizeof(struct rte_ipv4_hdr) +
                     sizeof(struct rte_udp_hdr) +
                     payload_size;

    char *data = rte_pktmbuf_append(m, pkt_len);
    if (!data) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memset(data, 0, pkt_len);

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + payload_size);
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = rte_cpu_to_be_32((10 << 24) | (rte_rand() & 0x00FFFFFF));
    ip->dst_addr = rte_cpu_to_be_32((192 << 24) | (168 << 16) | (1 << 8) | 1);
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
    udp->src_port = rte_cpu_to_be_16((rte_rand() % 60000) + 1024);
    udp->dst_port = rte_cpu_to_be_16(53);
    udp->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + payload_size);
    udp->dgram_cksum = 0;  // Optional for IPv4

    return m;
}

// ==================== Benchmark Core ====================

static void run_benchmark_single_type(
    struct rte_mbuf *(*create_fn)(void),
    const char *test_name
) {
    printf("\n  Testing: %s\n", test_name);
    printf("  %-20s %-15s %-15s %-15s\n", "Metric", "Value", "Unit", "Notes");
    printf("  %-20s %-15s %-15s %-15s\n", "------", "-----", "----", "-----");

    // Reset results
    memset(&results, 0, sizeof(results));
    results.min_cycles = UINT64_MAX;

    uint64_t tsc_hz = rte_get_tsc_hz();

    // Warmup phase
    printf("  Warming up (%lu packets)...\n", bench_cfg.warmup_count);
    for (uint64_t i = 0; i < bench_cfg.warmup_count; i++) {
        struct rte_mbuf *m = create_fn();
        if (!m) continue;

        struct layer1_result result;
        layer1_process_packet_ex(m, 0, 0, benchmark_pool, &result);

        // Cleanup
        if (result.reply_pkt) rte_pktmbuf_free(result.reply_pkt);
        if (result.forward_pkt) rte_pktmbuf_free(result.forward_pkt);
        rte_pktmbuf_free(m);
    }

    // Benchmark phase
    printf("  Running benchmark (%lu packets)...\n", bench_cfg.packet_count);

    uint64_t start_tsc = rte_get_tsc_cycles();

    for (uint64_t i = 0; i < bench_cfg.packet_count; i++) {
        struct rte_mbuf *m = create_fn();
        if (!m) continue;

        uint64_t pkt_start = rte_get_tsc_cycles();

        struct layer1_result result;
        int ret = layer1_process_packet_ex(m, 0, 0, benchmark_pool, &result);

        uint64_t pkt_end = rte_get_tsc_cycles();
        uint64_t pkt_cycles = pkt_end - pkt_start;

        results.total_packets++;
        results.total_cycles += pkt_cycles;
        if (pkt_cycles < results.min_cycles) results.min_cycles = pkt_cycles;
        if (pkt_cycles > results.max_cycles) results.max_cycles = pkt_cycles;

        if (ret == 0 && result.action != L1_ACTION_DROP) {
            results.accepted++;
        } else {
            results.dropped++;
        }

        // Cleanup
        if (result.reply_pkt) rte_pktmbuf_free(result.reply_pkt);
        if (result.forward_pkt) rte_pktmbuf_free(result.forward_pkt);
        rte_pktmbuf_free(m);
    }

    uint64_t end_tsc = rte_get_tsc_cycles();
    results.elapsed_sec = (double)(end_tsc - start_tsc) / tsc_hz;

    // Calculate and print results
    double pps = results.total_packets / results.elapsed_sec;
    double mpps = pps / 1e6;
    double avg_cycles = (double)results.total_cycles / results.total_packets;
    double avg_ns = avg_cycles * 1e9 / tsc_hz;
    double min_ns = results.min_cycles * 1e9 / tsc_hz;
    double max_ns = results.max_cycles * 1e9 / tsc_hz;

    printf("  %-20s %-15.3f %-15s %-15s\n", "Throughput", mpps, "Mpps", "");
    printf("  %-20s %-15.0f %-15s %-15s\n", "Total PPS", pps, "pps", "");
    printf("  %-20s %-15.1f %-15s %-15s\n", "Avg Latency", avg_ns, "ns", "");
    printf("  %-20s %-15.1f %-15s %-15s\n", "Min Latency", min_ns, "ns", "");
    printf("  %-20s %-15.1f %-15s %-15s\n", "Max Latency", max_ns, "ns", "");
    printf("  %-20s %-15.1f %-15s %-15s\n", "Avg Cycles", avg_cycles, "cycles/pkt", "");
    printf("  %-20s %-15lu %-15s %-15s\n", "Accepted", results.accepted, "packets", "");
    printf("  %-20s %-15lu %-15s %-15s\n", "Dropped", results.dropped, "packets", "");
    printf("  %-20s %-15.3f %-15s %-15s\n", "Elapsed", results.elapsed_sec, "seconds", "");
}

static void run_all_benchmarks(void) {
    printf("\n====================================================================\n");
    printf("                     Layer 1 Performance Benchmark                   \n");
    printf("====================================================================\n");
    printf("Configuration:\n");
    printf("  Packet Count:  %lu\n", bench_cfg.packet_count);
    printf("  Warmup Count:  %lu\n", bench_cfg.warmup_count);
    printf("  CPU Frequency: %.2f GHz\n", (double)rte_get_tsc_hz() / 1e9);
    printf("====================================================================\n");

    if (bench_cfg.test_tcp_syn || bench_cfg.test_mixed) {
        run_benchmark_single_type(create_tcp_syn_packet, "TCP SYN Packets");
    }

    if (bench_cfg.test_tcp_data || bench_cfg.test_mixed) {
        run_benchmark_single_type(create_tcp_data_packet, "TCP Data Packets");
    }

    if (bench_cfg.test_udp || bench_cfg.test_mixed) {
        run_benchmark_single_type(create_udp_packet, "UDP Packets");
    }

    printf("\n====================================================================\n");
    printf("                           Benchmark Complete                        \n");
    printf("====================================================================\n\n");
}

// ==================== Main ====================

static void print_usage(const char *prog_name) {
    printf("Usage: %s [EAL options] -- [benchmark options]\n", prog_name);
    printf("\nBenchmark options:\n");
    printf("  --packets N     Number of packets to process (default: %d)\n", DEFAULT_PACKET_COUNT);
    printf("  --warmup N      Warmup packet count (default: %d)\n", DEFAULT_WARMUP_COUNT);
    printf("  --tcp-syn       Test TCP SYN packets only\n");
    printf("  --tcp-data      Test TCP data packets only\n");
    printf("  --udp           Test UDP packets only\n");
    printf("  --mixed         Test all packet types (default)\n");
    printf("  --verbose       Verbose output\n");
    printf("  --help          Show this help\n");
}

static int parse_benchmark_args(int argc, char **argv) {
    // Set defaults
    bench_cfg.packet_count = DEFAULT_PACKET_COUNT;
    bench_cfg.warmup_count = DEFAULT_WARMUP_COUNT;
    bench_cfg.test_mixed = true;

    static struct option long_options[] = {
        {"packets",  required_argument, 0, 'p'},
        {"warmup",   required_argument, 0, 'w'},
        {"tcp-syn",  no_argument,       0, 's'},
        {"tcp-data", no_argument,       0, 'd'},
        {"udp",      no_argument,       0, 'u'},
        {"mixed",    no_argument,       0, 'm'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    // Reset getopt
    optind = 0;

    while ((opt = getopt_long(argc, argv, "p:w:sdumvh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                bench_cfg.packet_count = strtoull(optarg, NULL, 10);
                break;
            case 'w':
                bench_cfg.warmup_count = strtoull(optarg, NULL, 10);
                break;
            case 's':
                bench_cfg.test_tcp_syn = true;
                bench_cfg.test_mixed = false;
                break;
            case 'd':
                bench_cfg.test_tcp_data = true;
                bench_cfg.test_mixed = false;
                break;
            case 'u':
                bench_cfg.test_udp = true;
                bench_cfg.test_mixed = false;
                break;
            case 'm':
                bench_cfg.test_mixed = true;
                break;
            case 'v':
                bench_cfg.verbose = true;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                break;
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    int ret;

    // Initialize EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "Error: EAL initialization failed\n");
        return -1;
    }

    argc -= ret;
    argv += ret;

    // Parse benchmark-specific arguments
    parse_benchmark_args(argc, argv);

    printf("Initializing benchmark...\n");

    // Create mempool for synthetic packets
    benchmark_pool = rte_pktmbuf_pool_create(
        "benchmark_pool",
        BENCHMARK_MEMPOOL_SIZE,
        BENCHMARK_CACHE_SIZE,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id()
    );

    if (!benchmark_pool) {
        fprintf(stderr, "Error: Failed to create mempool\n");
        rte_eal_cleanup();
        return -1;
    }

    // Initialize Layer 1 with default config
    printf("Initializing Layer 1...\n");
    ret = layer1_init(1000000, NULL);  // Use default config
    if (ret < 0) {
        fprintf(stderr, "Error: Layer 1 initialization failed\n");
        rte_mempool_free(benchmark_pool);
        rte_eal_cleanup();
        return -1;
    }

    // Run benchmarks
    run_all_benchmarks();

    // Cleanup
    layer1_cleanup();
    rte_mempool_free(benchmark_pool);
    rte_eal_cleanup();

    return 0;
}
