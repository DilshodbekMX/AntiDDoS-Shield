/**
 * test_carpet_bomb_subnet.c -- integration test for protected-subnet aggregation.
 *
 * Synthesizes a carpet-bomb: TCP SYNs to many DISTINCT destination IPs inside one
 * registered /24, each address individually low-rate (one packet here). Drives
 * them through the REAL packet parser and the REAL Stage-3c keying policy
 * (l1_resolve_track_key), then asserts they all fold into the ONE per-IP slot
 * keyed by the subnet network -- i.e. the whole /24 is visible to Layer 2 as a
 * single destination, which is the entire point of protected subnets. Per-IP
 * tracking of any single address would have seen only 1 packet and missed it.
 *
 * Needs EAL + libpcap mbuf pool (reuses the pcap_replay harness helpers).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#include <rte_byteorder.h>
#include <rte_lcore.h>

#include "pcap_replay.h"
#include "../../layer1/datapath/packet_parser.h"
#include "../../layer1/tables/ip_lists.h"
#include "../../layer1/telemetry/per_ip_features.h"
#include "../../common/types.h"

#define HOST_IP(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))
#define BE_IP(a, b, c, d) rte_cpu_to_be_32(HOST_IP(a, b, c, d))

/* Build a minimal Ethernet/IPv4/TCP-SYN frame; returns total length. */
static uint16_t build_syn(uint8_t *buf, uint32_t src_be, uint32_t dst_be,
                          uint16_t sport, uint16_t dport) {
    struct ether_header *eth = (struct ether_header *)buf;
    memset(eth->ether_dhost, 0x11, 6);
    memset(eth->ether_shost, 0x22, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    struct iphdr *ip = (struct iphdr *)(buf + sizeof(struct ether_header));
    memset(ip, 0, sizeof(*ip));
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = src_be;
    ip->daddr = dst_be;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
    memset(tcp, 0, sizeof(*tcp));
    tcp->source = htons(sport);
    tcp->dest = htons(dport);
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(64240);

    return (uint16_t)(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
}

/* Same flow as Layer 1 Stage 3c, via the production policy function. */
static struct per_ip_features *resolve_track_slot(uint32_t dst_be) {
    struct per_ip_features *exact = per_ip_features_lookup(dst_be);
    uint32_t net_be = 0;
    bool in_subnet = (!exact && ip_protected_subnet_count() > 0 &&
                      ip_protected_subnet_lookup(dst_be, &net_be));
    uint32_t key = l1_resolve_track_key(dst_be, exact != NULL, in_subnet, net_be);
    return exact ? exact : (in_subnet ? per_ip_features_lookup(key) : NULL);
}

int main(void) {
    if (pcap_test_init_layer1() < 0) {        /* EAL + flow_table + ip_lists */
        fprintf(stderr, "layer1 init failed (environment limitation) -- skipping test\n");
        return 77;
    }
    if (per_ip_features_init(256) < 0) {
        fprintf(stderr, "per_ip_features init failed -- skipping test\n");
        return 77;
    }
    packet_parser_init_hash_seed();

    /* Protect the whole /24 as one aggregate. */
    assert(ip_protected_subnet_add(HOST_IP(10, 0, 9, 0), 24) == 0);
    const uint32_t net_be = BE_IP(10, 0, 9, 0);
    const unsigned lcore = rte_lcore_id();
    const int N = 40;  /* distinct destinations in the /24 */

    int parsed = 0, tracked = 0;
    for (int i = 0; i < N; i++) {
        uint8_t buf[64];
        uint16_t len = build_syn(buf, BE_IP(192, 168, 1, (i % 250) + 1),
                                 rte_cpu_to_be_32(HOST_IP(10, 0, 9, 10 + i)),
                                 (uint16_t)(40000 + i), 80);
        struct rte_mbuf *m = pcap_create_mbuf(buf, len);
        assert(m != NULL);

        struct packet_features f;
        memset(&f, 0, sizeof(f));
        if (parse_packet(m, &f) == 0) {
            parsed++;
            struct per_ip_features *pif = resolve_track_slot(f.dst_ip);
            if (pif) {
                tracked++;
                per_ip_features_update_counters(pif, lcore, f.protocol, f.tcp_flags,
                                                f.packet_size, true);
            }
        }
        pcap_free_mbuf(m);
    }
    assert(parsed == N && "all synthetic SYNs should parse");
    assert(tracked == N && "every /24 address should resolve to the subnet slot");

    /* All N packets aggregated into the single subnet slot. */
    struct per_ip_features *agg = per_ip_features_lookup(net_be);
    assert(agg != NULL);
    uint64_t rx = 0, syn = 0;
    for (unsigned l = 0; l < RTE_MAX_LCORE; l++) {
        rx += agg->lcore_counters[l].rx_packets;
        syn += agg->lcore_counters[l].syn_packets;
    }
    printf("subnet aggregate 10.0.9.0/24: rx=%llu syn=%llu across %d distinct dst IPs\n",
           (unsigned long long)rx, (unsigned long long)syn, N);
    assert(rx == (uint64_t)N && "subnet slot must sum all destinations' packets");
    assert(syn == (uint64_t)N);

    /* No individual /24 address got its own slot -- they aggregated. */
    assert(per_ip_features_lookup(BE_IP(10, 0, 9, 10)) == NULL);
    /* An address outside the /24 is untracked. */
    assert(resolve_track_slot(BE_IP(10, 0, 99, 5)) == NULL);

    printf("\nPASS: carpet-bomb across %d IPs in a /24 folds into one tracked entry "
           "(per-IP would have seen 1 pkt each and missed it).\n", N);
    return 0;
}
