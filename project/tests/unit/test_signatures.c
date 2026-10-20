/**
 * @file test_signatures.c
 * @brief Unit tests for the Stage 6c attack signatures (signatures.c)
 *
 * The SYN scan rule (signature 2001) matches a SYN-only frame of 60 bytes or
 * less: no TCP options (54 bytes) or MSS only (58 bytes), padded to the
 * Ethernet minimum. Raw-socket scanners send such SYNs, and so do small
 * stacks such as lwIP, so the frame alone must not drop a connection. These
 * subtests check that such SYNs from normal clients pass, that a source that
 * scans (many ports, or many SYNs, in one window) is still dropped, that the
 * operator's strict_syn_scan mode keeps the old rule, and that the other
 * signatures behave as before.
 *
 * Frames are built as a NIC delivers them and go through parse_packet(), so
 * signatures_check() sees what Stage 6c passes it. The tracker's clock is
 * this binary's signatures_scan_clock(), held at a window a subtest chooses.
 *
 * Requires DPDK EAL (--no-huge --no-shconf --no-telemetry, up to four lcores);
 * exits 77 (skip) if EAL cannot initialise. SIG_SHIPPED_CONFIG names the
 * shipped layer1/config/layer1_config.json (set by meson).
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sched.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_pause.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_byteorder.h>

#include "../../layer1/tables/signatures.h"
#include "../../layer1/config/layer1_config.h"
#include "../../layer1/config/config_protobuf.h"
#include "../../layer1/datapath/packet_parser.h"
#include "../../common/types.h"

#ifndef SIG_SHIPPED_CONFIG
#define SIG_SHIPPED_CONFIG "layer1/config/layer1_config.json"
#endif

// ==================== Test Framework ====================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(expr, msg) do { \
    if (!(expr)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while (0)

#define TEST_ASSERT_EQ(expected, actual, msg) do { \
    if ((expected) != (actual)) { \
        printf("  FAIL: %s (expected=%ld, actual=%ld, line %d)\n", msg, \
               (long)(expected), (long)(actual), __LINE__); \
        tests_failed++; \
        return; \
    } \
} while (0)

// The tracker's clock: 0 is the TSC, otherwise the time this returns
static uint64_t clock_held = 0;
static uint64_t window_tsc = 1;   // TSC cycles per tracker window

uint64_t signatures_scan_clock(void) {
    uint64_t t = __atomic_load_n(&clock_held, __ATOMIC_RELAXED);
    return t ? t : rte_get_tsc_cycles();
}

// Hold the clock in the middle of window n
static void hold_window(uint64_t n) {
    __atomic_store_n(&clock_held, window_tsc * n + window_tsc / 2, __ATOMIC_RELAXED);
}

// Every subtest starts with the module released and the clock free, also
// after a failed assertion returned early
#define RUN_TEST(test_func) do { \
    printf("Running %s...\n", #test_func); \
    tests_run++; \
    int failed_before = tests_failed; \
    test_func(); \
    signatures_cleanup(); \
    __atomic_store_n(&clock_held, 0, __ATOMIC_RELAXED); \
    if (tests_failed == failed_before) { \
        tests_passed++; \
        printf("  PASS\n"); \
    } \
} while (0)

// ==================== Fixtures ====================

#define HOST_IP(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))
#define BE_IP(a, b, c, d) rte_cpu_to_be_32(HOST_IP(a, b, c, d))

#define SERVER BE_IP(10, 0, 0, 1)

static struct rte_mempool *g_pool;

// The signatures_config that layer1_init() builds from a layer1 config
// (layer1.c, "Initialize Attack Signatures Detection (Stage 6c)")
static struct signatures_config sig_config_from(const struct signatures_cfg *c) {
    struct signatures_config s = {
        .enabled = c->enabled,
        .log_matches = c->log_matches,
        .block_amplification = c->block_amplification,
        .block_scans = c->block_scans,
        .block_anomalies = c->block_anomalies,
        .block_attack_tools = c->block_attack_tools,
        .strict_syn_scan = c->strict_syn_scan,
    };
    return s;
}

// The module as layer1_config_defaults() configures it, with strict_syn_scan
// and block_anomalies as given
static int init_defaults(bool strict, bool anomalies) {
    struct layer1_config cfg;
    layer1_config_defaults(&cfg);
    cfg.signatures.strict_syn_scan = strict;
    cfg.signatures.block_anomalies = anomalies;
    struct signatures_config s = sig_config_from(&cfg.signatures);
    return signatures_init(&s);
}

// Ethernet / IPv4 / TCP frame as a NIC delivers it: a frame under the 60-byte
// Ethernet minimum (no FCS) arrives padded to 60. opt_len option bytes: 0 (no
// options, as raw-socket scanners and some small stacks send), 4 (MSS only, as
// lwIP sends), 20 (MSS, SACK, timestamps and window scale, as Linux sends).
// Parsed into *f as Stage 6c gets it. Returns 0 on success.
static int tcp_frame(struct packet_features *f, uint32_t src, uint16_t dport,
                     uint8_t flags, uint16_t opt_len, uint8_t ttl) {
    uint16_t l3_len = (uint16_t)(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + opt_len);
    uint16_t len = (uint16_t)(sizeof(struct rte_ether_hdr) + l3_len);
    uint16_t frame = len < 60 ? 60 : len;
    struct rte_mbuf *m = rte_pktmbuf_alloc(g_pool);
    if (!m) return -1;
    uint8_t *p = (uint8_t *)rte_pktmbuf_append(m, frame);
    if (!p) {
        rte_pktmbuf_free(m);
        return -1;
    }
    memset(p, 0, frame);

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    memset(&eth->dst_addr, 0x11, RTE_ETHER_ADDR_LEN);
    memset(&eth->src_addr, 0x22, RTE_ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->time_to_live = ttl;
    ip->next_proto_id = IPPROTO_TCP;
    ip->total_length = rte_cpu_to_be_16(l3_len);
    ip->src_addr = src;
    ip->dst_addr = SERVER;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(40000);
    tcp->dst_port = rte_cpu_to_be_16(dport);
    tcp->sent_seq = rte_cpu_to_be_32(1000);
    tcp->data_off = (uint8_t)(((sizeof(struct rte_tcp_hdr) + opt_len) / 4) << 4);
    tcp->tcp_flags = flags;
    tcp->rx_win = rte_cpu_to_be_16(5840);
    uint8_t *opt = (uint8_t *)(tcp + 1);
    if (opt_len >= 4) {
        opt[0] = 2;     // MSS 1460
        opt[1] = 4;
        opt[2] = 0x05;
        opt[3] = 0xB4;
        memset(opt + 4, 1, opt_len - 4u);   // NOP padding
    }

    memset(f, 0, sizeof(*f));
    int ret = parse_packet(m, f);
    rte_pktmbuf_free(m);
    return ret == PARSE_OK ? 0 : -1;
}

static bool sig_check(const struct packet_features *f, struct sig_match *m) {
    memset(m, 0, sizeof(*m));
    return signatures_check(f->protocol, f->src_ip, f->dst_ip, f->src_port, f->dst_port,
                            f->tcp_flags, f->packet_size, f->ttl, m);
}

// One SYN with opt_len option bytes from src to dport: 1 if Stage 6c would
// drop it, 0 if it passes, -1 if the frame could not be built
static int syn_dropped(uint32_t src, uint16_t dport, uint16_t opt_len, struct sig_match *m) {
    struct packet_features f;
    if (tcp_frame(&f, src, dport, RTE_TCP_SYN_FLAG, opt_len, 64) != 0) return -1;
    return sig_check(&f, m) ? 1 : 0;
}

// A port scan from src in the current window: SYNs with opt_len option bytes
// to ports base, base + 1, ... until one is dropped (at most max). Returns
// the 1-based number of the first dropped SYN, 0 if none was, -1 on error.
static int scan_until_dropped(uint32_t src, uint16_t base, int max, uint16_t opt_len) {
    struct sig_match m;
    for (int i = 0; i < max; i++) {
        int d = syn_dropped(src, (uint16_t)(base + i), opt_len, &m);
        if (d < 0) return -1;
        if (d) return i + 1;
    }
    return 0;
}

// ==================== Minimal SYNs of normal clients ====================

// No options (54 bytes, padded to 60): the frame alone is an indicator
static void test_sig_optionless_syn_passes(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    hold_window(1000);

    struct packet_features f;
    TEST_ASSERT_EQ(0, tcp_frame(&f, BE_IP(198, 51, 100, 7), 443, RTE_TCP_SYN_FLAG, 0, 64),
                   "frame builds and parses");
    TEST_ASSERT_EQ(60, f.packet_size, "an option-less SYN arrives as a 60-byte frame");
    TEST_ASSERT_EQ(20, f.tcp_header_len, "with no TCP options");

    struct sig_match m;
    TEST_ASSERT(!sig_check(&f, &m), "an option-less SYN from a normal client passes");
    TEST_ASSERT_EQ(SIG_ID_SYN_SCAN, m.signature_id, "it is reported as the SYN scan indicator");
    TEST_ASSERT_EQ(SIG_ACTION_LOG, m.action, "with action LOG, not DROP");
    TEST_ASSERT_EQ(SIG_CAT_SCAN, m.category, "in the scan category");

    struct signatures_stats s;
    signatures_get_stats(&s);
    TEST_ASSERT_EQ(1, s.syn_scan_indicators, "the indicator is counted");
    TEST_ASSERT_EQ(0, s.syn_scan_dropped, "and not dropped");
    TEST_ASSERT_EQ(0, s.scans_detected, "no scan is detected");
    TEST_ASSERT_EQ(0, s.packets_dropped, "nothing is dropped");
    TEST_ASSERT_EQ(1, s.signatures_matched, "the match is counted");
}

// MSS only (58 bytes, padded to 60), as lwIP and other embedded stacks send
static void test_sig_mss_only_syn_passes(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    hold_window(1000);

    struct packet_features f;
    TEST_ASSERT_EQ(0, tcp_frame(&f, BE_IP(198, 51, 100, 8), 1883, RTE_TCP_SYN_FLAG, 4, 64),
                   "frame builds and parses");
    TEST_ASSERT_EQ(60, f.packet_size, "an MSS-only SYN arrives as a 60-byte frame");
    TEST_ASSERT_EQ(24, f.tcp_header_len, "with only the 4-byte MSS option");

    struct sig_match m;
    TEST_ASSERT(!sig_check(&f, &m), "an MSS-only SYN from a normal client passes");
    TEST_ASSERT_EQ(SIG_ACTION_LOG, m.action, "reported with action LOG");

    struct signatures_stats s;
    signatures_get_stats(&s);
    TEST_ASSERT_EQ(1, s.syn_scan_indicators, "the indicator is counted");
    TEST_ASSERT_EQ(0, s.packets_dropped, "nothing is dropped");
}

// The shipped layer1_config.json, as layer1_init() reads it
static void test_sig_shipped_config_minimal_syns_pass(void) {
    struct layer1_config cfg;
    TEST_ASSERT_EQ(0, layer1_config_load(SIG_SHIPPED_CONFIG, &cfg), "the shipped config loads");
    TEST_ASSERT(cfg.signatures.enabled, "it enables signatures");
    TEST_ASSERT(cfg.signatures.block_scans, "and the scan category");
    TEST_ASSERT(!cfg.signatures.strict_syn_scan, "and leaves strict_syn_scan off");

    struct signatures_config s = sig_config_from(&cfg.signatures);
    TEST_ASSERT_EQ(0, signatures_init(&s), "init with the shipped settings");
    hold_window(1000);

    struct sig_match m;
    TEST_ASSERT_EQ(0, syn_dropped(BE_IP(198, 51, 100, 9), 443, 0, &m),
                   "an option-less SYN passes with the shipped config");
    TEST_ASSERT_EQ(0, syn_dropped(BE_IP(198, 51, 100, 10), 443, 4, &m),
                   "an MSS-only SYN passes with the shipped config");
}

// A client that retransmits its SYN and opens a few connections
static void test_sig_client_retries_and_few_ports_pass(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    hold_window(1000);

    uint32_t client = BE_IP(198, 51, 100, 11);
    static const uint16_t ports[] = { 443, 443, 443, 80, 8080, 8883, 443 };
    struct sig_match m;
    for (unsigned i = 0; i < RTE_DIM(ports); i++) {
        TEST_ASSERT_EQ(0, syn_dropped(client, ports[i], 4, &m),
                       "SYN retransmissions and a few ports in one window pass");
    }
    // The next window, and one long after
    hold_window(1001);
    TEST_ASSERT_EQ(0, syn_dropped(client, 443, 4, &m), "the next window's SYN passes");
    hold_window(1100);
    TEST_ASSERT_EQ(0, syn_dropped(client, 443, 0, &m), "a later window's SYN passes");

    struct signatures_stats s;
    signatures_get_stats(&s);
    TEST_ASSERT_EQ(RTE_DIM(ports) + 2, s.syn_scan_indicators, "every SYN is an indicator");
    TEST_ASSERT_EQ(0, s.packets_dropped, "none is dropped");
}

// ==================== Scans are still dropped ====================

// One source, minimal SYNs to many destination ports in one window
static void test_sig_port_scan_dropped(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    hold_window(2000);

    uint32_t scanner = BE_IP(203, 0, 113, 66);
    int first = scan_until_dropped(scanner, 1, 64, 4);
    TEST_ASSERT(first >= SIG_SYN_SCAN_PORTS,
                "SYNs to fewer than SIG_SYN_SCAN_PORTS distinct ports pass");
    TEST_ASSERT(first > 0 && first <= 64, "a scan of 64 ports is dropped");
    printf("  first SYN dropped: number %d (threshold %d distinct ports)\n",
           first, SIG_SYN_SCAN_PORTS);

    // From then on every minimal SYN of the source is dropped, also to a port
    // it already tried, and with no options
    struct sig_match m;
    for (int i = 0; i < 32; i++) {
        TEST_ASSERT_EQ(1, syn_dropped(scanner, (uint16_t)(100 + i), (i & 1) ? 4 : 0, &m),
                       "the scan's later SYNs are dropped");
    }
    TEST_ASSERT_EQ(1, syn_dropped(scanner, 1, 4, &m), "also to a port it already tried");
    TEST_ASSERT_EQ(SIG_ID_SYN_SCAN, m.signature_id, "as signature 2001");
    TEST_ASSERT_EQ(SIG_ACTION_DROP, m.action, "with action DROP");
    TEST_ASSERT_EQ(SIG_CAT_SCAN, m.category, "in the scan category");
    TEST_ASSERT_EQ(5, m.severity, "with the scan severity");

    struct signatures_stats s;
    signatures_get_stats(&s);
    uint64_t drops = 32 + 1 + 1;
    TEST_ASSERT_EQ((uint64_t)first + 33, s.syn_scan_indicators, "every SYN is an indicator");
    TEST_ASSERT_EQ(drops, s.syn_scan_dropped, "the dropped ones are counted");
    TEST_ASSERT_EQ(drops, s.scans_detected, "as detected scans");
    TEST_ASSERT_EQ(drops, s.packets_dropped, "and as drops");
}

// The port rule exactly: SYNs to any number of ports on SIG_SYN_SCAN_PORTS - 1
// of the 16 port bits pass; the SYN that sets the next bit is dropped
static void test_sig_port_rule_threshold_exact(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    hold_window(2100);

    // Three ports for each of the 16 bits
    uint16_t ports[16][3];
    unsigned per_bit[16] = { 0 }, complete = 0;
    for (uint32_t p = 1; p < 65536 && complete < 16; p++) {
        uint32_t b = signatures_syn_scan_port_bit((uint16_t)p);
        TEST_ASSERT(b < 16, "a port bit is below 16");
        if (per_bit[b] < 3) {
            ports[b][per_bit[b]++] = (uint16_t)p;
            if (per_bit[b] == 3) complete++;
        }
    }
    TEST_ASSERT_EQ(16, complete, "every bit has three ports");

    uint32_t src = BE_IP(203, 0, 113, 90);
    struct sig_match m;
    for (unsigned k = 0; k < 3; k++) {
        for (unsigned b = 0; b < SIG_SYN_SCAN_PORTS - 1; b++) {
            TEST_ASSERT_EQ(0, syn_dropped(src, ports[b][k], 0, &m),
                           "SYNs to 21 ports on SIG_SYN_SCAN_PORTS - 1 bits pass");
        }
    }
    TEST_ASSERT_EQ(1, syn_dropped(src, ports[SIG_SYN_SCAN_PORTS - 1][0], 0, &m),
                   "the SYN that sets the SIG_SYN_SCAN_PORTS-th bit is dropped");
}

// A scan that goes on is dropped from the first SYN of the next window; a
// source that stops is admitted again
static void test_sig_scan_stays_dropped_next_window(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    uint32_t scanner = BE_IP(203, 0, 113, 67);
    struct sig_match m;

    hold_window(3000);
    TEST_ASSERT(scan_until_dropped(scanner, 1, 64, 0) > 0, "the scan is dropped in window 3000");

    hold_window(3001);
    TEST_ASSERT_EQ(1, syn_dropped(scanner, 5000, 0, &m),
                   "the next window drops the source's first SYN");
    for (int i = 1; i < 64; i++) {
        TEST_ASSERT_EQ(1, syn_dropped(scanner, (uint16_t)(5000 + i), 0, &m),
                       "and the rest of the scan in that window");
    }

    hold_window(3002);
    TEST_ASSERT_EQ(1, syn_dropped(scanner, 6000, 0, &m),
                   "window 3001 scanned too, so window 3002 drops its first SYN");
    TEST_ASSERT_EQ(1, syn_dropped(scanner, 443, 0, &m), "and a second one");

    // Window 3002 saw two SYNs to two ports: no scan pattern, so 3003 admits it
    hold_window(3003);
    TEST_ASSERT_EQ(0, syn_dropped(scanner, 443, 0, &m),
                   "a source that stopped scanning is admitted in the window after");

    // A scanner that goes quiet for a window is admitted after it
    uint32_t other = BE_IP(203, 0, 113, 68);
    hold_window(3010);
    TEST_ASSERT(scan_until_dropped(other, 1, 64, 4) > 0, "a second scan is dropped");
    hold_window(3012);
    TEST_ASSERT_EQ(0, syn_dropped(other, 443, 4, &m),
                   "after a quiet window its next SYN passes");
}

// Many minimal SYNs from one source to one port (a sweep or a flood)
static void test_sig_syn_rate_dropped(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    hold_window(4000);

    uint32_t flooder = BE_IP(203, 0, 113, 70);
    struct sig_match m;
    int passed = 0, dropped = 0, first_drop = 0;
    for (int i = 1; i <= 150; i++) {
        int d = syn_dropped(flooder, 80, 0, &m);
        TEST_ASSERT(d >= 0, "frame builds");
        if (d) {
            dropped++;
            if (!first_drop) first_drop = i;
        } else {
            TEST_ASSERT_EQ(0, dropped, "no SYN passes after the first drop");
            passed++;
        }
    }
    TEST_ASSERT_EQ(SIG_SYN_SCAN_SYNS - 1, passed, "the first SIG_SYN_SCAN_SYNS - 1 SYNs pass");
    TEST_ASSERT_EQ(SIG_SYN_SCAN_SYNS, first_drop, "the SIG_SYN_SCAN_SYNS-th is dropped");
    TEST_ASSERT_EQ(150 - SIG_SYN_SCAN_SYNS + 1, dropped, "and every one after it");

    hold_window(4001);
    TEST_ASSERT_EQ(1, syn_dropped(flooder, 80, 0, &m), "the next window drops it from the start");
}

// While a scanner is dropped, everybody else's SYNs pass, and so does the
// scanner's own traffic that is not a minimal SYN
static void test_sig_other_traffic_unaffected_by_scanner(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    hold_window(5000);

    uint32_t scanner = BE_IP(203, 0, 113, 71);
    TEST_ASSERT(scan_until_dropped(scanner, 1, 64, 0) > 0, "the scan is dropped");

    struct sig_match m;
    for (uint32_t i = 1; i <= 50; i++) {
        uint32_t client = BE_IP(198, 18, 0, i);
        if (signatures_syn_scan_slot(client) == signatures_syn_scan_slot(scanner)) {
            continue;
        }
        TEST_ASSERT_EQ(0, syn_dropped(client, 443, (i & 1) ? 4 : 0, &m),
                       "other clients' minimal SYNs pass");
    }

    TEST_ASSERT_EQ(0, syn_dropped(scanner, 443, 20, &m),
                   "the scanner's SYN with the options of a full stack passes");
    TEST_ASSERT_EQ(0, m.signature_id, "and matches no signature");
    struct packet_features f;
    TEST_ASSERT_EQ(0, tcp_frame(&f, scanner, 443, RTE_TCP_ACK_FLAG, 0, 64), "ACK frame builds");
    TEST_ASSERT(!sig_check(&f, &m), "the scanner's ACK passes");
    TEST_ASSERT_EQ(1, syn_dropped(scanner, 443, 0, &m), "its minimal SYNs are still dropped");
}

// Sources that share a slot never share state
static void test_sig_colliding_sources_never_share_state(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");

    uint32_t scanner = BE_IP(203, 0, 113, 72);
    uint32_t slot = signatures_syn_scan_slot(scanner);
    TEST_ASSERT(slot < SIG_SYN_SCAN_SLOTS, "the slot index is in range");
    uint32_t client = 0;
    for (uint32_t i = 1; i < 1000000 && !client; i++) {
        uint32_t c = rte_cpu_to_be_32(HOST_IP(100, 64, 0, 0) + i);
        if (c != scanner && signatures_syn_scan_slot(c) == slot) {
            client = c;
        }
    }
    TEST_ASSERT(client != 0, "a client in the scanner's slot exists");

    struct sig_match m;
    struct signatures_stats s;

    // The scanner's scan holds the slot: the client is not tracked and passes,
    // whatever it sends, and the scanner stays dropped
    hold_window(6000);
    TEST_ASSERT(scan_until_dropped(scanner, 1, 64, 0) > 0, "the scan is dropped");
    for (int i = 0; i < 20; i++) {
        TEST_ASSERT_EQ(0, syn_dropped(client, (uint16_t)(2000 + i), 4, &m),
                       "the client in the same slot passes, even to many ports");
    }
    signatures_get_stats(&s);
    TEST_ASSERT_EQ(20, s.syn_scan_untracked, "untracked while the scan holds the slot");
    TEST_ASSERT_EQ(1, syn_dropped(scanner, 443, 0, &m), "the scanner is still dropped");

    // The next window: the scan's state still holds the slot, so the client
    // stays untracked and the scanner is dropped from its first SYN there
    hold_window(6001);
    TEST_ASSERT_EQ(0, syn_dropped(client, 443, 4, &m), "the next window's client SYN passes");
    signatures_get_stats(&s);
    TEST_ASSERT_EQ(21, s.syn_scan_untracked, "untracked: the scan's state holds the slot");
    TEST_ASSERT_EQ(1, syn_dropped(scanner, 444, 0, &m), "the scanner's carried state is kept");

    // Once the scan state is stale, the client takes the slot
    hold_window(6002);
    TEST_ASSERT_EQ(0, syn_dropped(client, 443, 4, &m), "the client takes the stale slot");
    signatures_get_stats(&s);
    TEST_ASSERT_EQ(21, s.syn_scan_untracked, "and is tracked again");

    // Alternating SYNs: each takes the other's quiet state, so neither sees
    // the other's ports (together 14 ports, each alone 7)
    hold_window(6010);
    for (int i = 0; i < SIG_SYN_SCAN_PORTS - 1; i++) {
        TEST_ASSERT_EQ(0, syn_dropped(client, (uint16_t)(3000 + i), 4, &m),
                       "the client's SYNs pass");
        TEST_ASSERT_EQ(0, syn_dropped(scanner, (uint16_t)(4000 + i), 0, &m),
                       "the other source's SYNs pass: no shared count");
    }
}

// An lcore whose TSC lags may still be in the window another lcore left:
// its SYN counts in that newer window rather than starting the source over
static void test_sig_lagging_clock_counts_in_window(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    uint32_t scanner = BE_IP(203, 0, 113, 73);
    struct sig_match m;

    hold_window(7001);
    for (int i = 0; i < SIG_SYN_SCAN_SYNS - 1; i++) {
        TEST_ASSERT_EQ(0, syn_dropped(scanner, 80, 0, &m),
                       "fewer than SIG_SYN_SCAN_SYNS SYNs pass");
    }
    // The same source's next SYN, from an lcore one window behind: it is the
    // window's SIG_SYN_SCAN_SYNS-th (a fresh start would count it as the first)
    hold_window(7000);
    TEST_ASSERT_EQ(1, syn_dropped(scanner, 80, 0, &m),
                   "the lagging lcore's SYN counts in the newer window");
    hold_window(7001);
    TEST_ASSERT_EQ(1, syn_dropped(scanner, 80, 0, &m), "the newer window drops the source");
    hold_window(7002);
    TEST_ASSERT_EQ(1, syn_dropped(scanner, 80, 0, &m), "and so does the one after it");
}

// Every slot held by a scan: a new source is not tracked and passes, and the
// table does not grow
static void test_sig_full_tracker_fails_open(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    hold_window(8000);

    static uint8_t taken[SIG_SYN_SCAN_SLOTS];
    memset(taken, 0, sizeof(taken));
    uint32_t filled = 0, next_ip = HOST_IP(10, 0, 0, 0);
    uint32_t newcomer = 0;
    while (filled < SIG_SYN_SCAN_SLOTS && next_ip < HOST_IP(10, 255, 255, 255)) {
        uint32_t src = rte_cpu_to_be_32(next_ip++);
        uint32_t slot = signatures_syn_scan_slot(src);
        if (taken[slot]) {
            if (!newcomer) newcomer = src;   // shares a slot with a scanner
            continue;
        }
        taken[slot] = 1;
        filled++;
        TEST_ASSERT(scan_until_dropped(src, 1, 64, 0) > 0, "each slot's scanner is dropped");
    }
    TEST_ASSERT_EQ(SIG_SYN_SCAN_SLOTS, filled, "every slot holds a scan");
    TEST_ASSERT(newcomer != 0, "a source outside them exists");

    struct signatures_stats before, after;
    signatures_get_stats(&before);
    struct sig_match m;
    for (int i = 0; i < 100; i++) {
        TEST_ASSERT_EQ(0, syn_dropped(newcomer, (uint16_t)(1 + i), 0, &m),
                       "a new source is not tracked, and passes");
    }
    signatures_get_stats(&after);
    TEST_ASSERT_EQ(100, after.syn_scan_untracked - before.syn_scan_untracked,
                   "its SYNs are counted as untracked");
    TEST_ASSERT_EQ(before.syn_scan_dropped, after.syn_scan_dropped, "none of them is dropped");
}

// A re-initialisation starts with an empty tracker
static void test_sig_reinit_clears_tracker(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    hold_window(8500);
    uint32_t scanner = BE_IP(203, 0, 113, 91);
    struct sig_match m;
    TEST_ASSERT(scan_until_dropped(scanner, 1, 64, 0) > 0, "the scan is dropped");

    signatures_cleanup();
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init again");
    TEST_ASSERT_EQ(0, syn_dropped(scanner, 1, 0, &m),
                   "in the same window the source starts over: its SYN passes");
    struct signatures_stats s;
    signatures_get_stats(&s);
    TEST_ASSERT_EQ(1, s.syn_scan_indicators, "the counters start over too");
}

// ==================== Operator settings ====================

// strict_syn_scan keeps the earlier rule: every minimal SYN is dropped
static void test_sig_strict_mode_drops_every_minimal_syn(void) {
    TEST_ASSERT_EQ(0, init_defaults(true, false), "init with strict_syn_scan");
    hold_window(9000);

    struct sig_match m;
    TEST_ASSERT_EQ(1, syn_dropped(BE_IP(198, 51, 100, 20), 443, 0, &m),
                   "an option-less SYN is dropped at once");
    TEST_ASSERT_EQ(SIG_ACTION_DROP, m.action, "with action DROP");
    TEST_ASSERT_EQ(1, syn_dropped(BE_IP(198, 51, 100, 21), 443, 4, &m),
                   "an MSS-only SYN is dropped at once");
    TEST_ASSERT_EQ(0, syn_dropped(BE_IP(198, 51, 100, 22), 443, 20, &m),
                   "a SYN with a full stack's options passes");

    struct signatures_stats s;
    signatures_get_stats(&s);
    TEST_ASSERT_EQ(2, s.syn_scan_indicators, "two indicators");
    TEST_ASSERT_EQ(2, s.syn_scan_dropped, "both dropped");
    TEST_ASSERT_EQ(2, s.scans_detected, "as detected scans");
}

// block_scans off: the scan category is not checked at all, as before
static void test_sig_block_scans_off_unchanged(void) {
    struct layer1_config cfg;
    layer1_config_defaults(&cfg);
    cfg.signatures.block_scans = false;
    struct signatures_config sc = sig_config_from(&cfg.signatures);
    TEST_ASSERT_EQ(0, signatures_init(&sc), "init with block_scans off");
    hold_window(9100);

    struct sig_match m;
    for (int i = 0; i < 64; i++) {
        TEST_ASSERT_EQ(0, syn_dropped(BE_IP(203, 0, 113, 74), (uint16_t)(1 + i), 0, &m),
                       "no minimal SYN is dropped");
    }
    TEST_ASSERT_EQ(0, m.signature_id, "and none matches");
    struct signatures_stats s;
    signatures_get_stats(&s);
    TEST_ASSERT_EQ(0, s.syn_scan_indicators, "nor is counted");
}

// The other signatures are untouched
static void test_sig_other_rules_unchanged(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    hold_window(9200);
    struct sig_match m;
    struct packet_features f;

    TEST_ASSERT_EQ(0, tcp_frame(&f, BE_IP(203, 0, 113, 75), 22, RTE_TCP_FIN_FLAG, 0, 64),
                   "FIN frame builds");
    TEST_ASSERT(sig_check(&f, &m), "a FIN-only segment is still dropped");
    TEST_ASSERT_EQ(2002, m.signature_id, "as the FIN scan");

    TEST_ASSERT(signatures_check(IPPROTO_UDP, BE_IP(203, 0, 113, 76), SERVER, 123, 40000,
                                 0, 500, 64, &m), "an NTP reflection is still dropped");
    TEST_ASSERT_EQ(1003, m.signature_id, "as amplification");
    TEST_ASSERT(!signatures_check(IPPROTO_UDP, BE_IP(203, 0, 113, 76), SERVER, 123, 40000,
                                  0, 90, 64, &m), "a small NTP reply passes");
    TEST_ASSERT(signatures_check(IPPROTO_UDP, BE_IP(203, 0, 113, 77), SERVER, 40000, 53,
                                 0, 28, 64, &m), "a header-only UDP datagram is still dropped");
    TEST_ASSERT_EQ(2003, m.signature_id, "as the UDP scan");

    struct signatures_stats before, after;
    signatures_get_stats(&before);
    TEST_ASSERT_EQ(0, syn_dropped(BE_IP(198, 51, 100, 30), 443, 20, &m),
                   "a full stack's SYN passes");
    TEST_ASSERT_EQ(0, m.signature_id, "and matches nothing");
    signatures_get_stats(&after);
    TEST_ASSERT_EQ(before.syn_scan_indicators, after.syn_scan_indicators,
                   "a full stack's SYN is not an indicator");
}

// A minimal SYN that passes the scan check still meets the later checks
static void test_sig_indicator_does_not_hide_later_rules(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, true), "init with block_anomalies on");
    hold_window(9300);
    struct sig_match m;
    struct packet_features f;

    TEST_ASSERT_EQ(0, tcp_frame(&f, BE_IP(198, 51, 100, 40), 443, RTE_TCP_SYN_FLAG, 4, 5),
                   "low-TTL minimal SYN builds");
    TEST_ASSERT(sig_check(&f, &m), "a minimal SYN with TTL 5 is dropped by the TTL rule");
    TEST_ASSERT_EQ(3011, m.signature_id, "as the low-TTL anomaly");
    TEST_ASSERT_EQ(SIG_CAT_PROTOCOL_ANOMALY, m.category, "in the anomaly category");

    TEST_ASSERT_EQ(0, tcp_frame(&f, BE_IP(198, 51, 100, 41), 443, RTE_TCP_SYN_FLAG, 4, 64),
                   "minimal SYN builds");
    TEST_ASSERT(!sig_check(&f, &m), "with a normal TTL it passes");
    TEST_ASSERT_EQ(SIG_ID_SYN_SCAN, m.signature_id, "as the indicator");

    struct signatures_stats s;
    signatures_get_stats(&s);
    TEST_ASSERT_EQ(2, s.syn_scan_indicators, "both are indicators");
    TEST_ASSERT_EQ(1, s.anomalies_detected, "one anomaly");
    TEST_ASSERT_EQ(0, s.scans_detected, "no scan");
}

// The layer1 config key, in both parsers and the writer
static void test_sig_config_strict_syn_scan(void) {
    struct layer1_config cfg;
    layer1_config_defaults(&cfg);
    TEST_ASSERT(!cfg.signatures.strict_syn_scan, "strict_syn_scan is off by default");

    const char *tmp = getenv("TMPDIR");
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/test_signatures_XXXXXX", (tmp && tmp[0]) ? tmp : "/tmp");
    TEST_ASSERT(mkdtemp(dir) != NULL, "temporary directory");
    char in[300], out[300];
    snprintf(in, sizeof(in), "%s/in.json", dir);
    snprintf(out, sizeof(out), "%s/out.json", dir);

    FILE *fp = fopen(in, "w");
    bool written = fp && fprintf(fp, "{ \"signatures\": { \"strict_syn_scan\": true } }\n") > 0;
    if (fp) fclose(fp);

    bool loaded = written && layer1_config_load(in, &cfg) == 0;
    bool strict_cjson = loaded && cfg.signatures.strict_syn_scan;
    bool scans_kept = loaded && cfg.signatures.block_scans;
    bool saved = loaded && layer1_config_save(out, &cfg) == 0;

    struct layer1_config back, secure;
    bool reloaded = saved && layer1_config_load(out, &back) == 0;
    bool strict_back = reloaded && back.signatures.strict_syn_scan;
    bool secure_ok = written && config_load_json(in, &secure) == CONFIG_OK;
    bool strict_secure = secure_ok && secure.signatures.strict_syn_scan;

    unlink(in);
    unlink(out);
    rmdir(dir);

    TEST_ASSERT(written, "the test config is written");
    TEST_ASSERT(loaded, "layer1_config_load() reads it");
    TEST_ASSERT(strict_cjson, "and sets strict_syn_scan");
    TEST_ASSERT(scans_kept, "keeping the other signature defaults");
    TEST_ASSERT(saved, "layer1_config_save() writes it");
    TEST_ASSERT(reloaded && strict_back, "and the saved file keeps strict_syn_scan");
    TEST_ASSERT(secure_ok && strict_secure, "config_load_json() reads strict_syn_scan too");
}

// ==================== Several lcores ====================

#define MT_CLIENTS_PER_LCORE 512
#define MT_SCAN_PORTS        256
#define MT_MAX_LCORES        4

static uint32_t mt_scanner;
static uint32_t mt_go = 0;
static uint32_t mt_done = 0;
static uint64_t mt_client_drops[MT_MAX_LCORES];
static uint64_t mt_scan_drops[MT_MAX_LCORES];
static uint64_t mt_sent[MT_MAX_LCORES];

// Lcore number n of the run: its own clients (one to three SYNs each, to one
// port) and its own share of the scanner's ports, interleaved
static int mt_job(void *arg) {
    unsigned n = (unsigned)(uintptr_t)arg;
    while (!__atomic_load_n(&mt_go, __ATOMIC_ACQUIRE)) {
        rte_pause();
    }
    struct sig_match m;
    uint64_t client_drops = 0, scan_drops = 0, sent = 0;
    for (uint32_t i = 0; i < MT_CLIENTS_PER_LCORE; i++) {
        uint32_t client = rte_cpu_to_be_32(HOST_IP(172, 16, 0, 0) + n * 65536 + i + 1);
        if (signatures_syn_scan_slot(client) != signatures_syn_scan_slot(mt_scanner)) {
            for (uint32_t r = 0; r <= i % 3; r++) {
                client_drops += signatures_check(IPPROTO_TCP, client, SERVER, 40000, 443,
                                                 RTE_TCP_SYN_FLAG, 60, 64, &m);
                sent++;
            }
        }
        if (i < MT_SCAN_PORTS) {
            uint16_t port = (uint16_t)(1 + n * MT_SCAN_PORTS + i);
            scan_drops += signatures_check(IPPROTO_TCP, mt_scanner, SERVER, 40000, port,
                                           RTE_TCP_SYN_FLAG, 60, 64, &m);
            sent++;
        }
    }
    mt_client_drops[n] = client_drops;
    mt_scan_drops[n] = scan_drops;
    mt_sent[n] = sent;
    __atomic_fetch_add(&mt_done, 1, __ATOMIC_RELEASE);
    return 0;
}

static void test_sig_concurrent_lcores(void) {
    TEST_ASSERT_EQ(0, init_defaults(false, false), "init with the default settings");
    hold_window(10000);
    mt_scanner = BE_IP(203, 0, 113, 80);
    __atomic_store_n(&mt_go, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&mt_done, 0, __ATOMIC_RELAXED);

    unsigned lcores = 1, lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (lcores == MT_MAX_LCORES) break;
        if (rte_eal_remote_launch(mt_job, (void *)(uintptr_t)lcores, lcore_id) != 0) break;
        lcores++;
    }
    if (lcores == 1) {
        printf("  NOTE: no worker lcore: the jobs run on the main lcore only\n");
    }
    __atomic_store_n(&mt_go, 1, __ATOMIC_RELEASE);
    mt_job((void *)(uintptr_t)0);
    while (__atomic_load_n(&mt_done, __ATOMIC_ACQUIRE) < lcores) {
        rte_pause();
    }
    rte_eal_mp_wait_lcore();

    uint64_t client_drops = 0, scan_drops = 0, sent = 0;
    for (unsigned n = 0; n < lcores; n++) {
        client_drops += mt_client_drops[n];
        scan_drops += mt_scan_drops[n];
        sent += mt_sent[n];
    }
    printf("  %u lcores: %lu minimal SYNs, scanner dropped %lu of %u\n", lcores,
           (unsigned long)sent, (unsigned long)scan_drops, lcores * MT_SCAN_PORTS);

    TEST_ASSERT_EQ(0, client_drops, "no client SYN is dropped on any lcore");
    TEST_ASSERT(scan_drops > 0, "the scan is dropped");
    struct sig_match m;
    TEST_ASSERT(signatures_check(IPPROTO_TCP, mt_scanner, SERVER, 40000, 9999,
                                 RTE_TCP_SYN_FLAG, 60, 64, &m),
                "after the run the scanner is still dropped");

    struct signatures_stats s;
    signatures_get_stats(&s);
    TEST_ASSERT_EQ(sent + 1, s.syn_scan_indicators, "every SYN is counted once");
    TEST_ASSERT_EQ(scan_drops + 1, s.syn_scan_dropped, "every drop is counted once");
}

// ==================== Main ====================

// Up to four lcores, each on its own CPU from this process's affinity mask
static void build_lcore_map(char *buf, size_t len) {
    cpu_set_t set;
    unsigned int n = 0;
    size_t off = 0;

    if (sched_getaffinity(0, sizeof(set), &set) == 0) {
        for (int cpu = 0; cpu < CPU_SETSIZE && n < MT_MAX_LCORES; cpu++) {
            if (!CPU_ISSET(cpu, &set)) {
                continue;
            }
            int w = snprintf(buf + off, len - off, "%s%u@%d", n ? "," : "", n, cpu);
            if (w < 0 || (size_t)w >= len - off) {
                break;
            }
            off += (size_t)w;
            n++;
        }
    }
    if (n == 0) {
        snprintf(buf, len, "0@0");
    }
}

int main(int argc, char **argv) {
    (void)argc;
    char lcore_map[64];
    build_lcore_map(lcore_map, sizeof(lcore_map));
    char *eal_args[] = {
        argv[0],
        "--lcores", lcore_map,
        "-n", "1",
        "--no-huge",
        "--no-pci",
        "-m", "64",
        "--no-shconf",
        "--no-telemetry",
        NULL
    };
    if (rte_eal_init((int)RTE_DIM(eal_args) - 1, eal_args) < 0) {
        fprintf(stderr, "EAL init failed, skipping test\n");
        return 77;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

    g_pool = rte_pktmbuf_pool_create("sig_test_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                     (int)rte_socket_id());
    if (!g_pool) {
        printf("mbuf pool creation failed\n");
        return 1;
    }
    window_tsc = rte_get_tsc_hz() * SIG_SYN_SCAN_WINDOW_MS / 1000;
    if (window_tsc == 0) {
        printf("no TSC rate\n");
        return 1;
    }

    printf("\n========================================\n");
    printf("  Attack Signature Unit Tests\n");
    printf("========================================\n\n");

    // Minimal SYNs of normal clients
    RUN_TEST(test_sig_optionless_syn_passes);
    RUN_TEST(test_sig_mss_only_syn_passes);
    RUN_TEST(test_sig_shipped_config_minimal_syns_pass);
    RUN_TEST(test_sig_client_retries_and_few_ports_pass);

    // Scans are still dropped
    RUN_TEST(test_sig_port_scan_dropped);
    RUN_TEST(test_sig_port_rule_threshold_exact);
    RUN_TEST(test_sig_scan_stays_dropped_next_window);
    RUN_TEST(test_sig_syn_rate_dropped);
    RUN_TEST(test_sig_other_traffic_unaffected_by_scanner);
    RUN_TEST(test_sig_colliding_sources_never_share_state);
    RUN_TEST(test_sig_lagging_clock_counts_in_window);
    RUN_TEST(test_sig_full_tracker_fails_open);
    RUN_TEST(test_sig_reinit_clears_tracker);

    // Operator settings and the other signatures
    RUN_TEST(test_sig_strict_mode_drops_every_minimal_syn);
    RUN_TEST(test_sig_block_scans_off_unchanged);
    RUN_TEST(test_sig_other_rules_unchanged);
    RUN_TEST(test_sig_indicator_does_not_hide_later_rules);
    RUN_TEST(test_sig_config_strict_syn_scan);

    // Several lcores
    RUN_TEST(test_sig_concurrent_lcores);

    rte_mempool_free(g_pool);

    printf("\n========================================\n");
    printf("  Results: %d total, %d passed, %d failed\n", tests_run, tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed > 0 ? 1 : 0;
}
