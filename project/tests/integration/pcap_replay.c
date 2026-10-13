/**
 * @file pcap_replay.c
 * @brief PCAP Replay Integration Test Implementation
 *
 * Replays pcap files through the packet processing pipeline for testing.
 * Uses DPDK EAL in minimal mode (--no-huge) for CI-friendly testing.
 */

#include "pcap_replay.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_errno.h>

#include "../../layer1/datapath/packet_parser.h"
#include "../../layer1/tables/ip_lists.h"
#include "../../layer1/tables/flow_table.h"
#include "../../common/types.h"

/* ==================== Static State ==================== */

static struct rte_mempool *test_mbuf_pool = NULL;
static bool eal_initialized = false;
static bool layer1_initialized = false;

#define TEST_MBUF_POOL_SIZE   8192
#define TEST_MBUF_CACHE_SIZE  256
#define TEST_MBUF_DATA_SIZE   2048

/* ==================== Initialization ==================== */

int pcap_test_init_eal(void) {
    if (eal_initialized) {
        return 0;
    }

    /* Minimal EAL args for testing (no hugepages, no hardware) */
    char *argv[] = {
        "pcap_test",
        "--no-huge",
        "--no-pci",
        "-l", "0",
        "--log-level=warning",
        "-m", "256",
        "--in-memory",
        NULL
    };
    int argc = 8;

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "[PCAP_TEST] EAL init failed (environment limitation): %s\n", rte_strerror(rte_errno));
        return -1;
    }

    /* Create mbuf pool for packet processing */
    test_mbuf_pool = rte_pktmbuf_pool_create(
        "pcap_test_pool",
        TEST_MBUF_POOL_SIZE,
        TEST_MBUF_CACHE_SIZE,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id()
    );

    if (test_mbuf_pool == NULL) {
        fprintf(stderr, "[PCAP_TEST] Failed to create mbuf pool: %s\n",
                rte_strerror(rte_errno));
        return -1;
    }

    eal_initialized = true;
    printf("[PCAP_TEST] EAL initialized (no-huge mode)\n");
    return 0;
}

int pcap_test_init_layer1(void) {
    if (layer1_initialized) {
        return 0;
    }

    if (!eal_initialized) {
        if (pcap_test_init_eal() < 0) {
            return -1;
        }
    }

    /* Initialize flow table (minimal size for testing) */
    struct flow_table_config flow_cfg = {
        .max_flows = 1024,
        .idle_timeout_sec = 60,
        .syn_timeout_sec = 10,
    };
    if (flow_table_init(&flow_cfg) < 0) {
        fprintf(stderr, "[PCAP_TEST] Flow table init failed\n");
        return -1;
    }

    /* Initialize IP lists */
    struct ip_lists_config ip_cfg = {
        .max_whitelist_entries = 1024,
        .max_blacklist_entries = 1024,
        .max_protected_entries = 256,
        .max_whitelist_cidrs = 256,
        .enforce_protected_ips = false,
    };
    if (ip_lists_init(&ip_cfg) < 0) {
        fprintf(stderr, "[PCAP_TEST] IP lists init failed\n");
        return -1;
    }

    layer1_initialized = true;
    printf("[PCAP_TEST] Layer 1 subsystems initialized\n");
    return 0;
}

void pcap_test_cleanup(void) {
    if (layer1_initialized) {
        flow_table_cleanup();
        ip_lists_cleanup();
        layer1_initialized = false;
    }

    if (test_mbuf_pool != NULL) {
        rte_mempool_free(test_mbuf_pool);
        test_mbuf_pool = NULL;
    }

    if (eal_initialized) {
        rte_eal_cleanup();
        eal_initialized = false;
    }

    printf("[PCAP_TEST] Cleanup complete\n");
}

/* ==================== Mbuf Utilities ==================== */

struct rte_mbuf *pcap_create_mbuf(const uint8_t *data, uint16_t len) {
    if (!eal_initialized || test_mbuf_pool == NULL) {
        fprintf(stderr, "[PCAP_TEST] Not initialized\n");
        return NULL;
    }

    struct rte_mbuf *m = rte_pktmbuf_alloc(test_mbuf_pool);
    if (m == NULL) {
        return NULL;
    }

    char *pkt_data = rte_pktmbuf_append(m, len);
    if (pkt_data == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }

    memcpy(pkt_data, data, len);
    return m;
}

void pcap_free_mbuf(struct rte_mbuf *m) {
    if (m != NULL) {
        rte_pktmbuf_free(m);
    }
}

/* ==================== PCAP Replay ==================== */

static void process_packet(const u_char *data, int len,
                          struct pcap_test_stats *stats,
                          struct pcap_pkt_result *result,
                          uint32_t pkt_num) {
    /* Initialize result */
    memset(result, 0, sizeof(*result));
    result->pkt_num = pkt_num;
    result->pkt_len = len;

    stats->total_packets++;
    stats->total_bytes += len;

    /* Check minimum Ethernet header size */
    if (len < 14) {
        stats->non_ip_packets++;
        strcpy(result->drop_reason, "too_short");
        return;
    }

    /* Check ethertype */
    const struct ether_header *eth = (const struct ether_header *)data;
    uint16_t ethertype = ntohs(eth->ether_type);

    /* Handle VLAN tags */
    const u_char *ip_data = data + 14;
    int ip_len = len - 14;

    if (ethertype == 0x8100) {  /* VLAN */
        if (len < 18) {
            stats->non_ip_packets++;
            return;
        }
        ethertype = ntohs(*(uint16_t *)(data + 16));
        ip_data = data + 18;
        ip_len = len - 18;
    }

    if (ethertype == 0x0800) {
        stats->ipv4_packets++;
        result->is_ipv6 = false;
    } else if (ethertype == 0x86DD) {
        stats->ipv6_packets++;
        result->is_ipv6 = true;
    } else {
        stats->non_ip_packets++;
        strcpy(result->drop_reason, "non_ip");
        return;
    }

    /* Create mbuf for processing */
    struct rte_mbuf *m = pcap_create_mbuf(data, len);
    if (m == NULL) {
        strcpy(result->drop_reason, "mbuf_alloc_fail");
        return;
    }

    uint64_t start_cycles = rte_rdtsc();

    /* Parse packet */
    struct packet_features features;
    memset(&features, 0, sizeof(features));

    int parse_ret = parse_packet(m, &features);
    result->parse_result = parse_ret;

    if (parse_ret == PARSE_OK || parse_ret == PARSE_IPV6) {
        stats->parse_ok++;
        result->protocol = features.protocol;
        result->tcp_flags = features.tcp_flags;

        /* Update protocol stats */
        switch (features.protocol) {
            case IPPROTO_TCP:
                stats->tcp_packets++;

                /* TCP flag breakdown */
                #define TCP_FLAG_SYN 0x02
                #define TCP_FLAG_ACK 0x10
                #define TCP_FLAG_RST 0x04
                #define TCP_FLAG_FIN 0x01

                if ((features.tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN) {
                    stats->syn_packets++;
                }
                if ((features.tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) ==
                    (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
                    stats->syn_ack_packets++;
                }
                if ((features.tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_ACK) {
                    stats->ack_only_packets++;
                }
                if (features.tcp_flags & TCP_FLAG_RST) {
                    stats->rst_packets++;
                }
                if (features.tcp_flags & TCP_FLAG_FIN) {
                    stats->fin_packets++;
                }
                break;

            case IPPROTO_UDP:
                stats->udp_packets++;
                break;

            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                stats->icmp_packets++;
                break;

            default:
                stats->other_proto_packets++;
                break;
        }

        /* Validate packet */
        int validate_ret = validate_packet(&features);
        result->validate_result = validate_ret;

        if (validate_ret == VALIDATE_OK) {
            stats->validate_ok++;
        } else {
            stats->validate_failed++;
            result->dropped = true;
            stats->dropped_total++;
            stats->dropped_validation++;

            if (validate_ret < 32) {
                stats->validation_errors[validate_ret]++;
            }

            const char *err_str = validation_error_str(validate_ret);
            snprintf(result->drop_reason, sizeof(result->drop_reason),
                     "validation:%s", err_str);
        }

    } else if (parse_ret == PARSE_MALFORMED) {
        stats->parse_malformed++;
        result->dropped = true;
        stats->dropped_total++;
        stats->dropped_validation++;
        strcpy(result->drop_reason, "malformed");
    } else if (parse_ret == PARSE_UNSUPPORTED) {
        stats->parse_unsupported++;
        strcpy(result->drop_reason, "unsupported");
    } else if (parse_ret == PARSE_NOT_IP) {
        stats->non_ip_packets++;
        strcpy(result->drop_reason, "not_ip");
    }

    uint64_t end_cycles = rte_rdtsc();
    stats->processing_cycles += (end_cycles - start_cycles);

    pcap_free_mbuf(m);
}

int64_t pcap_replay_file(const char *pcap_path,
                         struct pcap_test_stats *stats,
                         uint64_t max_packets) {
    if (!eal_initialized) {
        if (pcap_test_init_eal() < 0) {
            return -1;
        }
    }

    if (stats != NULL) {
        pcap_reset_stats(stats);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(pcap_path, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "[PCAP_TEST] Failed to open %s: %s\n", pcap_path, errbuf);
        return -1;
    }

    struct pcap_pkthdr *header;
    const u_char *data;
    int64_t pkt_count = 0;

    struct pcap_test_stats local_stats;
    if (stats == NULL) {
        pcap_reset_stats(&local_stats);
        stats = &local_stats;
    }

    struct pcap_pkt_result result;

    uint64_t start_time = rte_rdtsc();

    while (pcap_next_ex(pcap, &header, &data) == 1) {
        pkt_count++;

        process_packet(data, header->caplen, stats, &result, pkt_count);

        if (max_packets > 0 && pkt_count >= (int64_t)max_packets) {
            break;
        }
    }

    uint64_t end_time = rte_rdtsc();
    uint64_t hz = rte_get_tsc_hz();
    double elapsed_sec = (double)(end_time - start_time) / hz;

    if (elapsed_sec > 0) {
        stats->packets_per_sec = pkt_count / elapsed_sec;
    }

    pcap_close(pcap);

    printf("[PCAP_TEST] Processed %ld packets from %s\n", pkt_count, pcap_path);
    return pkt_count;
}

int64_t pcap_replay_with_callback(const char *pcap_path,
                                  pcap_pkt_callback callback,
                                  void *user_data,
                                  uint64_t max_packets) {
    if (!eal_initialized) {
        if (pcap_test_init_eal() < 0) {
            return -1;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(pcap_path, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "[PCAP_TEST] Failed to open %s: %s\n", pcap_path, errbuf);
        return -1;
    }

    struct pcap_pkthdr *header;
    const u_char *data;
    int64_t pkt_count = 0;

    struct pcap_test_stats stats;
    pcap_reset_stats(&stats);

    struct pcap_pkt_result result;

    while (pcap_next_ex(pcap, &header, &data) == 1) {
        pkt_count++;

        process_packet(data, header->caplen, &stats, &result, pkt_count);

        if (callback != NULL) {
            callback(&result, user_data);
        }

        if (max_packets > 0 && pkt_count >= (int64_t)max_packets) {
            break;
        }
    }

    pcap_close(pcap);
    return pkt_count;
}

/* ==================== Test Execution ==================== */

bool pcap_run_attack_test(const struct attack_test_spec *spec,
                          struct pcap_test_stats *stats) {
    if (spec == NULL || spec->pcap_file == NULL) {
        return false;
    }

    printf("\n[TEST] %s\n", spec->name);
    printf("[TEST] File: %s\n", spec->pcap_file);

    int64_t pkt_count = pcap_replay_file(spec->pcap_file, stats, spec->max_packets);
    if (pkt_count < 0) {
        printf("[TEST] FAILED: Could not read pcap file\n");
        return false;
    }

    bool passed = true;

    /* Check minimum packets */
    if (spec->min_packets > 0 && (uint64_t)pkt_count < spec->min_packets) {
        printf("[TEST] FAILED: Expected at least %lu packets, got %ld\n",
               spec->min_packets, pkt_count);
        passed = false;
    }

    /* Check protocol ratio */
    if (spec->expected_protocol > 0 && stats->total_packets > 0) {
        uint64_t proto_count = 0;
        switch (spec->expected_protocol) {
            case IPPROTO_TCP: proto_count = stats->tcp_packets; break;
            case IPPROTO_UDP: proto_count = stats->udp_packets; break;
            case IPPROTO_ICMP: proto_count = stats->icmp_packets; break;
        }
        double ratio = (double)proto_count / stats->total_packets;
        if (ratio < spec->min_proto_ratio) {
            printf("[TEST] FAILED: Protocol ratio %.2f < %.2f\n",
                   ratio, spec->min_proto_ratio);
            passed = false;
        }
    }

    /* Check drop ratio */
    if (stats->total_packets > 0) {
        double drop_ratio = (double)stats->dropped_total / stats->total_packets;

        if (spec->min_drop_ratio > 0 && drop_ratio < spec->min_drop_ratio) {
            printf("[TEST] FAILED: Drop ratio %.2f < %.2f\n",
                   drop_ratio, spec->min_drop_ratio);
            passed = false;
        }

        if (spec->max_drop_ratio > 0 && drop_ratio > spec->max_drop_ratio) {
            printf("[TEST] FAILED: Drop ratio %.2f > %.2f\n",
                   drop_ratio, spec->max_drop_ratio);
            passed = false;
        }
    }

    /* Check malformed ratio */
    if (spec->min_malformed_ratio > 0 && stats->total_packets > 0) {
        double malformed_ratio = (double)stats->parse_malformed / stats->total_packets;
        if (malformed_ratio < spec->min_malformed_ratio) {
            printf("[TEST] FAILED: Malformed ratio %.2f < %.2f\n",
                   malformed_ratio, spec->min_malformed_ratio);
            passed = false;
        }
    }

    if (passed) {
        printf("[TEST] PASSED: %s\n", spec->name);
    }

    return passed;
}

/* ==================== Statistics Functions ==================== */

void pcap_reset_stats(struct pcap_test_stats *stats) {
    if (stats != NULL) {
        memset(stats, 0, sizeof(*stats));
    }
}

void pcap_print_stats(const struct pcap_test_stats *stats) {
    if (stats == NULL) return;

    printf("\n=== PCAP Test Statistics ===\n");
    printf("Total packets:     %lu\n", stats->total_packets);
    printf("Total bytes:       %lu\n", stats->total_bytes);
    printf("IPv4 packets:      %lu\n", stats->ipv4_packets);
    printf("IPv6 packets:      %lu\n", stats->ipv6_packets);
    printf("Non-IP packets:    %lu\n", stats->non_ip_packets);

    printf("\n--- Parse Results ---\n");
    printf("Parse OK:          %lu\n", stats->parse_ok);
    printf("Parse malformed:   %lu\n", stats->parse_malformed);
    printf("Parse unsupported: %lu\n", stats->parse_unsupported);

    printf("\n--- Validation Results ---\n");
    printf("Validate OK:       %lu\n", stats->validate_ok);
    printf("Validate failed:   %lu\n", stats->validate_failed);

    printf("\n--- Protocol Breakdown ---\n");
    printf("TCP:               %lu\n", stats->tcp_packets);
    printf("UDP:               %lu\n", stats->udp_packets);
    printf("ICMP:              %lu\n", stats->icmp_packets);
    printf("Other:             %lu\n", stats->other_proto_packets);

    printf("\n--- TCP Flags ---\n");
    printf("SYN:               %lu\n", stats->syn_packets);
    printf("SYN+ACK:           %lu\n", stats->syn_ack_packets);
    printf("ACK only:          %lu\n", stats->ack_only_packets);
    printf("RST:               %lu\n", stats->rst_packets);
    printf("FIN:               %lu\n", stats->fin_packets);

    printf("\n--- Drop Statistics ---\n");
    printf("Total dropped:     %lu\n", stats->dropped_total);
    printf("Validation drops:  %lu\n", stats->dropped_validation);

    if (stats->packets_per_sec > 0) {
        printf("\n--- Performance ---\n");
        printf("Throughput:        %.2f Mpps\n", stats->packets_per_sec / 1e6);
        if (stats->total_packets > 0) {
            printf("Cycles/packet:     %lu\n",
                   stats->processing_cycles / stats->total_packets);
        }
    }
    printf("============================\n\n");
}

/* ==================== Synthetic Attack Generation ==================== */

int pcap_generate_attack(const char *type,
                         uint32_t count,
                         uint32_t dst_ip,
                         pcap_pkt_callback callback,
                         void *user_data) {
    if (type == NULL || callback == NULL) {
        return -1;
    }

    /* Construct packet buffer */
    uint8_t pkt[128];
    memset(pkt, 0, sizeof(pkt));

    /* Ethernet header */
    struct ether_header *eth = (struct ether_header *)pkt;
    memset(eth->ether_dhost, 0xff, 6);  /* Broadcast */
    memset(eth->ether_shost, 0x00, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    /* IP header */
    struct iphdr *ip = (struct iphdr *)(pkt + 14);
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->daddr = dst_ip;

    struct pcap_test_stats stats;
    pcap_reset_stats(&stats);

    struct pcap_pkt_result result;
    uint16_t pkt_len = 0;

    for (uint32_t i = 0; i < count; i++) {
        /* Randomize source IP */
        ip->saddr = htonl(rand());

        if (strcmp(type, "syn_flood") == 0) {
            /* TCP SYN packet */
            ip->protocol = IPPROTO_TCP;
            ip->tot_len = htons(40);  /* 20 IP + 20 TCP */

            struct tcphdr *tcp = (struct tcphdr *)(pkt + 34);
            tcp->source = htons(rand() % 65535);
            tcp->dest = htons(80);
            tcp->seq = htonl(rand());
            tcp->ack_seq = 0;
            tcp->doff = 5;
            tcp->syn = 1;
            tcp->window = htons(65535);

            pkt_len = 54;  /* 14 Eth + 20 IP + 20 TCP */

        } else if (strcmp(type, "udp_flood") == 0) {
            /* UDP packet */
            ip->protocol = IPPROTO_UDP;
            ip->tot_len = htons(28);  /* 20 IP + 8 UDP */

            struct udphdr *udp = (struct udphdr *)(pkt + 34);
            udp->source = htons(rand() % 65535);
            udp->dest = htons(53);  /* DNS */
            udp->len = htons(8);

            pkt_len = 42;  /* 14 Eth + 20 IP + 8 UDP */

        } else if (strcmp(type, "icmp_flood") == 0) {
            /* ICMP Echo Request */
            ip->protocol = IPPROTO_ICMP;
            ip->tot_len = htons(28);  /* 20 IP + 8 ICMP */

            uint8_t *icmp = pkt + 34;
            icmp[0] = 8;   /* Echo Request */
            icmp[1] = 0;   /* Code */
            icmp[2] = 0;   /* Checksum (simplified) */
            icmp[3] = 0;

            pkt_len = 42;

        } else {
            fprintf(stderr, "[PCAP_TEST] Unknown attack type: %s\n", type);
            return -1;
        }

        /* Compute IP checksum */
        ip->check = 0;
        uint32_t sum = 0;
        uint16_t *ptr = (uint16_t *)ip;
        for (int j = 0; j < 10; j++) {
            sum += ntohs(ptr[j]);
        }
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ip->check = htons(~sum);

        /* Process through parser */
        process_packet(pkt, pkt_len, &stats, &result, i + 1);
        callback(&result, user_data);
    }

    return count;
}

/* ==================== Predefined Attack Scenarios ==================== */

const struct attack_test_spec attack_syn_flood_spec = {
    .name = "SYN Flood Attack",
    .pcap_file = "data/attacks/syn_flood.pcap",
    .min_packets = 1000,
    .max_packets = 0,
    .expected_protocol = IPPROTO_TCP,
    .min_proto_ratio = 0.9,
    .expect_syn_flood = true,
    .min_drop_ratio = 0.0,
    .max_drop_ratio = 1.0,
};

const struct attack_test_spec attack_udp_flood_spec = {
    .name = "UDP Flood Attack",
    .pcap_file = "data/attacks/udp_flood.pcap",
    .min_packets = 1000,
    .max_packets = 0,
    .expected_protocol = IPPROTO_UDP,
    .min_proto_ratio = 0.9,
    .expect_udp_flood = true,
    .min_drop_ratio = 0.0,
    .max_drop_ratio = 1.0,
};

const struct attack_test_spec attack_dns_amplification_spec = {
    .name = "DNS Amplification Attack",
    .pcap_file = "data/attacks/dns_amplification.pcap",
    .min_packets = 100,
    .max_packets = 0,
    .expected_protocol = IPPROTO_UDP,
    .min_proto_ratio = 0.9,
    .expect_amplification = true,
    .min_drop_ratio = 0.0,
    .max_drop_ratio = 1.0,
};

const struct attack_test_spec attack_ntp_amplification_spec = {
    .name = "NTP Amplification Attack",
    .pcap_file = "data/attacks/ntp_amplification.pcap",
    .min_packets = 100,
    .max_packets = 0,
    .expected_protocol = IPPROTO_UDP,
    .min_proto_ratio = 0.9,
    .expect_amplification = true,
};

const struct attack_test_spec attack_tcp_xmas_spec = {
    .name = "TCP XMAS Scan",
    .pcap_file = "data/attacks/tcp_xmas.pcap",
    .min_packets = 10,
    .expected_protocol = IPPROTO_TCP,
    .min_proto_ratio = 0.9,
    .min_drop_ratio = 0.9,  /* XMAS packets should be dropped */
    .expected_validation_errors = (1 << VALIDATE_ERR_TCP_XMAS),
};

const struct attack_test_spec attack_tcp_null_spec = {
    .name = "TCP NULL Scan",
    .pcap_file = "data/attacks/tcp_null.pcap",
    .min_packets = 10,
    .expected_protocol = IPPROTO_TCP,
    .min_proto_ratio = 0.9,
    .min_drop_ratio = 0.9,  /* NULL packets should be dropped */
    .expected_validation_errors = (1 << VALIDATE_ERR_TCP_NULL),
};

const struct attack_test_spec attack_land_spec = {
    .name = "LAND Attack",
    .pcap_file = "data/attacks/land.pcap",
    .min_packets = 10,
    .min_drop_ratio = 1.0,  /* All LAND packets must be dropped */
    .expected_validation_errors = (1 << VALIDATE_ERR_LAND_ATTACK),
};

const struct attack_test_spec attack_smurf_spec = {
    .name = "Smurf Attack",
    .pcap_file = "data/attacks/smurf.pcap",
    .min_packets = 10,
    .expected_protocol = IPPROTO_ICMP,
    .min_proto_ratio = 0.9,
};

const struct attack_test_spec attack_fraggle_spec = {
    .name = "Fraggle Attack",
    .pcap_file = "data/attacks/fraggle.pcap",
    .min_packets = 10,
    .expected_protocol = IPPROTO_UDP,
    .min_proto_ratio = 0.9,
};

const struct attack_test_spec attack_slowloris_spec = {
    .name = "Slowloris Attack",
    .pcap_file = "data/attacks/slowloris.pcap",
    .min_packets = 100,
    .expected_protocol = IPPROTO_TCP,
    .min_proto_ratio = 0.9,
};
