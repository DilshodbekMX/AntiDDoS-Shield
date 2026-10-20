/**
 * @file test_flow_pipeline.c
 * @brief Pipeline tests of flow tracking through layer1_process_packet_ex():
 *        RST/FIN validation at IPv4 and IPv6 Stage 11, the IPv6 Stage 11
 *        counters, and the flows of SYN proxy connections (Stage 9 and the
 *        outbound path).
 *
 * layer1_init() creates three files in /dev/shm and a telemetry database, so
 * the test must never run it against the host's /dev/shm. As
 * subnet_new_flows_seam_tests does, it compiles layer1.c into this test with
 * the three calls that create those files renamed: shared memory comes from
 * the private DPDK heap (shared_memory_init()) and the two telemetry segments
 * report failure, which layer1_init() continues past. Every stage is
 * layer1.c's own code. Where Landlock is available the pipeline process also
 * confines its writes to its temporary directory. The test fails when a seam
 * was not called or a new /dev/shm/antiddos* entry is left at the end.
 *
 * A child process runs the pipeline in a fresh temporary directory (config,
 * database, EAL runtime directory), ending with layer1_cleanup(); the parent
 * removes the directory however the child exits. The test skips (77) if EAL
 * cannot initialise.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#if defined(__has_include)
#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#endif
#endif

// layer1.c itself, with the three layer1_init() calls that create /dev/shm
// files renamed to the seam functions below
#define shared_memory_init_posix seam_shared_memory_init_posix
#define realtime_telemetry_init seam_realtime_telemetry_init
#define window_stats_init seam_window_stats_init
#include "../../layer1/layer1.c"
#undef shared_memory_init_posix
#undef realtime_telemetry_init
#undef window_stats_init

static int g_seam_calls[3];

// Shared memory in the private DPDK heap instead of /dev/shm
int seam_shared_memory_init_posix(void) {
    g_seam_calls[0]++;
    return shared_memory_init();
}

// No /dev/shm/antiddos_realtime: layer1_init() logs a warning and continues
int seam_realtime_telemetry_init(void) {
    g_seam_calls[1]++;
    return -1;
}

// No /dev/shm/antiddos_windows, the same way
int seam_window_stats_init(void) {
    g_seam_calls[2]++;
    return -1;
}

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_byteorder.h>

#define TEST_SKIP 77

#define HOST_IP(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))
#define BE_IP(a, b, c, d) rte_cpu_to_be_32(HOST_IP(a, b, c, d))

#define PORT_CLIENTS 0   // client-facing: inbound (the default config's port 0)
#define PORT_SERVERS 1   // server-facing: outbound

static int tests_failed = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        tests_failed++; \
    } else { \
        printf("  ok: %s\n", msg); \
    } \
} while (0)

#define CHECK_EQ(expected, actual, msg) do { \
    unsigned long e_ = (unsigned long)(expected), a_ = (unsigned long)(actual); \
    if (e_ != a_) { \
        printf("  FAIL: %s (expected=%lu, actual=%lu, line %d)\n", msg, e_, a_, __LINE__); \
        tests_failed++; \
    } else { \
        printf("  ok: %s (%lu)\n", msg, a_); \
    } \
} while (0)

// ==================== Isolation ====================

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

#ifdef LANDLOCK_CREATE_RULESET_VERSION
static int landlock_allow(int ruleset, const char *path, uint64_t access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return -1;
    struct landlock_path_beneath_attr rule = { .allowed_access = access, .parent_fd = fd };
    int ret = (int)syscall(__NR_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH,
                           &rule, 0);
    close(fd);
    return ret;
}
#endif

// Confine this thread, and the threads it creates from now on, so that files
// can be written, created, truncated or removed only beneath dir (plus /proc
// and /dev/null). Returns 0 when the kernel enforces it.
static int confine_writes(const char *dir) {
#ifdef LANDLOCK_CREATE_RULESET_VERSION
    int abi = (int)syscall(__NR_landlock_create_ruleset, NULL, 0,
                           LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) return -1;
    uint64_t handled = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                       LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
                       LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                       LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
                       LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM;
    uint64_t file_write = LANDLOCK_ACCESS_FS_WRITE_FILE;
    if (abi >= 2) {
        handled |= LANDLOCK_ACCESS_FS_REFER;
    }
    if (abi >= 3) {
        handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
        file_write |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    struct landlock_ruleset_attr attr = { .handled_access_fs = handled };
    int ruleset = (int)syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (ruleset < 0) return -1;
    bool ok = landlock_allow(ruleset, dir, handled) == 0 &&
              landlock_allow(ruleset, "/proc", file_write) == 0 &&
              landlock_allow(ruleset, "/dev/null", file_write) == 0 &&
              prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
              syscall(__NR_landlock_restrict_self, ruleset, 0) == 0;
    close(ruleset);
    return ok ? 0 : -1;
#else
    (void)dir;
    return -1;
#endif
}

// Names of the /dev/shm entries that start with "antiddos"
#define SHM_MAX_NAMES 64
struct shm_names {
    unsigned n;
    char name[SHM_MAX_NAMES][256];
};

static void list_antiddos_shm(struct shm_names *out) {
    out->n = 0;
    DIR *d = opendir("/dev/shm");
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && out->n < SHM_MAX_NAMES) {
        if (strncmp(e->d_name, "antiddos", 8) == 0) {
            snprintf(out->name[out->n++], sizeof(out->name[0]), "%s", e->d_name);
        }
    }
    closedir(d);
}

// Reports the entries that appeared since `before` and returns their count;
// never removes one (an engine started meanwhile owns its segments)
static int report_new_antiddos_shm(const struct shm_names *before) {
    struct shm_names now;
    list_antiddos_shm(&now);
    int found = 0;
    for (unsigned i = 0; i < now.n; i++) {
        bool known = false;
        for (unsigned j = 0; j < before->n && !known; j++) {
            known = strcmp(now.name[i], before->name[j]) == 0;
        }
        if (!known) {
            printf("  FAIL: /dev/shm/%s appeared during the test (left in place)\n", now.name[i]);
            found++;
        }
    }
    return found;
}

static int remove_entry(const char *path, const struct stat *sb, int type, struct FTW *ftw) {
    (void)sb;
    (void)type;
    (void)ftw;
    return remove(path);
}

static int remove_tree(const char *dir) {
    return nftw(dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS | FTW_MOUNT);
}

// ==================== Packets ====================

static struct rte_mempool *g_pool;

struct tcp_seg {
    uint32_t src, dst;           // IPv4, network byte order
    uint16_t sport, dport;
    uint8_t  flags;              // TCP flags
    uint32_t seq, ack;
    uint16_t payload;            // payload bytes
};

// Ethernet / IPv4 / TCP segment with checksums. A SYN carries an MSS option
// and padding to 74 bytes, as a real stack's SYN does (Stage 6c drops
// SYN-only frames of 60 bytes or less as scans).
static struct rte_mbuf *tcp4_packet(const struct tcp_seg *s) {
    uint16_t opt_len = (s->flags & RTE_TCP_SYN_FLAG) ? 20 : 0;
    uint16_t tcp_len = (uint16_t)(sizeof(struct rte_tcp_hdr) + opt_len);
    uint16_t len = (uint16_t)(sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                              tcp_len + s->payload);
    struct rte_mbuf *m = rte_pktmbuf_alloc(g_pool);
    if (!m) return NULL;
    uint8_t *p = (uint8_t *)rte_pktmbuf_append(m, len);
    if (!p) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memset(p, 0, len);

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    memset(&eth->dst_addr, 0x11, RTE_ETHER_ADDR_LEN);
    memset(&eth->src_addr, 0x22, RTE_ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->total_length = rte_cpu_to_be_16((uint16_t)(len - sizeof(*eth)));
    ip->src_addr = s->src;
    ip->dst_addr = s->dst;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(s->sport);
    tcp->dst_port = rte_cpu_to_be_16(s->dport);
    tcp->sent_seq = rte_cpu_to_be_32(s->seq);
    tcp->recv_ack = rte_cpu_to_be_32(s->ack);
    tcp->data_off = (uint8_t)((tcp_len / 4) << 4);
    tcp->tcp_flags = s->flags;
    tcp->rx_win = rte_cpu_to_be_16(65535);
    uint8_t *opt = (uint8_t *)(tcp + 1);
    if (opt_len) {
        opt[0] = 2;     // MSS 1460
        opt[1] = 4;
        opt[2] = 0x05;
        opt[3] = 0xB4;
        memset(opt + 4, 1, opt_len - 4);   // NOP padding
    }
    memset(opt + opt_len, 0x41, s->payload);
    tcp->cksum = 0;
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
    return m;
}

struct tcp6_seg {
    uint32_t src_host, dst_host;   // last 32 bits of 2001:db8::/96
    uint16_t sport, dport;
    uint8_t  flags;
    uint32_t seq, ack;
    uint16_t payload;
};

static void test_ip6(uint8_t a[16], uint32_t host) {
    memset(a, 0, 16);
    a[0] = 0x20;
    a[1] = 0x01;
    a[2] = 0x0d;
    a[3] = 0xb8;
    a[12] = (uint8_t)(host >> 24);
    a[13] = (uint8_t)(host >> 16);
    a[14] = (uint8_t)(host >> 8);
    a[15] = (uint8_t)host;
}

// Ethernet / IPv6 / TCP segment with checksum
static struct rte_mbuf *tcp6_packet(const struct tcp6_seg *s) {
    uint16_t tcp_len = (uint16_t)sizeof(struct rte_tcp_hdr);
    uint16_t len = (uint16_t)(sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) +
                              tcp_len + s->payload);
    struct rte_mbuf *m = rte_pktmbuf_alloc(g_pool);
    if (!m) return NULL;
    uint8_t *p = (uint8_t *)rte_pktmbuf_append(m, len);
    if (!p) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memset(p, 0, len);

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    memset(&eth->dst_addr, 0x11, RTE_ETHER_ADDR_LEN);
    memset(&eth->src_addr, 0x22, RTE_ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(eth + 1);
    ip6->vtc_flow = rte_cpu_to_be_32(6u << 28);
    ip6->payload_len = rte_cpu_to_be_16((uint16_t)(tcp_len + s->payload));
    ip6->proto = IPPROTO_TCP;
    ip6->hop_limits = 64;
    test_ip6(ip6->src_addr.a, s->src_host);
    test_ip6(ip6->dst_addr.a, s->dst_host);

    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip6 + 1);
    tcp->src_port = rte_cpu_to_be_16(s->sport);
    tcp->dst_port = rte_cpu_to_be_16(s->dport);
    tcp->sent_seq = rte_cpu_to_be_32(s->seq);
    tcp->recv_ack = rte_cpu_to_be_32(s->ack);
    tcp->data_off = (uint8_t)((tcp_len / 4) << 4);
    tcp->tcp_flags = s->flags;
    tcp->rx_win = rte_cpu_to_be_16(65535);
    memset(tcp + 1, 0x42, s->payload);
    tcp->cksum = 0;
    tcp->cksum = rte_ipv6_udptcp_cksum(ip6, tcp);
    return m;
}

// What a packet came to: its action and, for a SYN challenge, the cookie
struct sent {
    int action;
    uint8_t drop_reason;
    uint32_t synack_seq;   // sequence of a SYN-ACK the proxy answered with
};

// Runs one mbuf through layer1_process_packet_ex() on rx_port, then frees
// it and whatever the pipeline produced
static struct sent run_packet(struct rte_mbuf *m, uint16_t rx_port) {
    struct sent out = { -1, 0, 0 };
    if (!m) {
        printf("  mbuf allocation failed\n");
        tests_failed++;
        return out;
    }
    struct layer1_result res;
    memset(&res, 0, sizeof(res));
    layer1_process_packet_ex(m, rx_port, 0, g_pool, &res);
    out.action = res.action;
    out.drop_reason = res.drop_reason;

    // A SYN-ACK challenge: in a new mbuf (stateful) or in place (stateless)
    struct rte_mbuf *synack = NULL;
    if (res.action == L1_ACTION_REPLY && res.reply_pkt) {
        synack = res.reply_pkt;
    } else if (res.action == L1_ACTION_REPLY_INPLACE) {
        synack = m;
    }
    if (synack) {
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(synack, struct rte_ether_hdr *);
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        struct rte_tcp_hdr *tcp =
            (struct rte_tcp_hdr *)((uint8_t *)ip + (ip->version_ihl & 0x0F) * 4);
        if ((tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG)) ==
            (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG)) {
            out.synack_seq = rte_be_to_cpu_32(tcp->sent_seq);
        }
    }
    if (res.reply_pkt) {
        rte_pktmbuf_free(res.reply_pkt);
    }
    if (res.forward_pkt) {
        rte_pktmbuf_free(res.forward_pkt);
    }
    rte_pktmbuf_free(m);
    return out;
}

static struct sent send4(uint16_t rx_port, uint32_t src, uint32_t dst, uint16_t sport,
                         uint16_t dport, uint8_t flags, uint32_t seq, uint32_t ack,
                         uint16_t payload) {
    struct tcp_seg s = { src, dst, sport, dport, flags, seq, ack, payload };
    return run_packet(tcp4_packet(&s), rx_port);
}

static struct sent send6(uint16_t rx_port, uint32_t src, uint32_t dst, uint16_t sport,
                         uint16_t dport, uint8_t flags, uint32_t seq, uint32_t ack,
                         uint16_t payload) {
    struct tcp6_seg s = { src, dst, sport, dport, flags, seq, ack, payload };
    return run_packet(tcp6_packet(&s), rx_port);
}

static bool forwarded(struct sent s) {
    return s.action == L1_ACTION_ACCEPT || s.action == L1_ACTION_ACCEPT_MODIFIED;
}

static struct flow_entry *find4(uint32_t a, uint32_t b) {
    struct packet_features f;
    memset(&f, 0, sizeof(f));
    f.src_ip = a;
    f.dst_ip = b;
    f.protocol = IPPROTO_TCP;
    return flow_table_lookup(&f);
}

static struct flow_entry_v6 *find6(uint32_t a, uint32_t b) {
    struct packet_features_v6 f;
    memset(&f, 0, sizeof(f));
    f.ip_version = IP_VERSION_6;
    f.protocol = IPPROTO_TCP;
    test_ip6(f.src_ip.v6, a);
    test_ip6(f.dst_ip.v6, b);
    return flow_table_v6_lookup(&f);
}

static uint64_t rst_fin_invalid(void) {
    uint64_t valid, invalid;
    flow_table_get_rst_fin_stats(&valid, &invalid);
    return invalid;
}

// ==================== Scenarios ====================

// RST/FIN validation at IPv4 Stage 11 (the SYN proxy off, so that every
// segment reaches Stage 11)
static void scenario_rst_single_connection(void) {
    const uint32_t c = BE_IP(11, 2, 0, 1), s = BE_IP(10, 0, 9, 1);
    printf("IPv4 Stage 11, one connection: a blind RST outside the window\n");

    send4(PORT_CLIENTS, c, s, 40000, 5001, RTE_TCP_SYN_FLAG, 1000, 0, 0);
    send4(PORT_SERVERS, s, c, 5001, 40000, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 5000, 1001, 0);
    send4(PORT_CLIENTS, c, s, 40000, 5001, RTE_TCP_ACK_FLAG, 1001, 5001, 0);
    send4(PORT_CLIENTS, c, s, 40000, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 1001, 5001, 100);
    send4(PORT_SERVERS, s, c, 5001, 40000, RTE_TCP_ACK_FLAG, 5001, 1101, 0);
    struct flow_entry *flow = find4(c, s);
    CHECK(flow != NULL, "the connection has a flow");
    if (!flow) return;
    CHECK_EQ(FLOW_STATE_ESTABLISHED, flow->state, "the handshake established the flow");
    CHECK(flow->flags & FLOW_FLAG_HANDSHAKE_ACKED, "the handshake is verified");

    uint64_t invalid_before = rst_fin_invalid();
    uint64_t packets_before = flow_total_packets(flow);
    struct flow_table_stats st_before, st_after;
    flow_table_get_detailed_stats(&st_before);
    struct sent r = send4(PORT_CLIENTS, c, s, 40000, 5001, RTE_TCP_RST_FLAG, 1101 + 0x40000000u, 0, 0);
    flow_table_get_detailed_stats(&st_after);
    CHECK(forwarded(r), "the blind RST is forwarded (the server's stack checks it against its connection)");
    CHECK_EQ(FLOW_STATE_ESTABLISHED, flow->state, "the blind RST does not tear the flow down");
    CHECK_EQ(invalid_before + 1, rst_fin_invalid(), "the blind RST is counted as invalid");
    CHECK_EQ(packets_before + 1, flow_total_packets(flow), "the blind RST is counted on the flow");
    CHECK_EQ(1, st_after.lookups - st_before.lookups,
             "the RST costs one flow lookup (validated against Stage 11's own)");
    CHECK(find4(c, s) == flow, "the flow survives");

    // An RST in the window still closes it
    r = send4(PORT_CLIENTS, c, s, 40000, 5001, RTE_TCP_RST_FLAG, 1101, 0, 0);
    CHECK(forwarded(r), "the connection's own RST is forwarded");
    CHECK_EQ(FLOW_STATE_RST, flow->state, "the connection's own RST closes the flow");

    // An RST from a host without a flow: Stage 11's lookup creates one for
    // it, and the validator counts the RST as having none
    invalid_before = rst_fin_invalid();
    r = send4(PORT_CLIENTS, BE_IP(11, 2, 0, 9), s, 40009, 5001, RTE_TCP_RST_FLAG, 4242, 0, 0);
    CHECK(forwarded(r), "an RST without a flow is forwarded");
    CHECK_EQ(invalid_before + 1, rst_fin_invalid(), "an RST without a flow is counted as invalid");
}

static void scenario_fin_parallel_connections(void) {
    const uint32_t c = BE_IP(11, 2, 0, 2), s = BE_IP(10, 0, 9, 2);
    printf("IPv4 Stage 11, two connections between the same hosts: the first one's FIN\n");

    // Connection X, then connection Y, between the same two hosts: the flow
    // key has no ports, so both share one flow, which tracks Y's sequence
    send4(PORT_CLIENTS, c, s, 40001, 5001, RTE_TCP_SYN_FLAG, 100000, 0, 0);
    send4(PORT_SERVERS, s, c, 5001, 40001, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 200000, 100001, 0);
    send4(PORT_CLIENTS, c, s, 40001, 5001, RTE_TCP_ACK_FLAG, 100001, 200001, 0);
    send4(PORT_CLIENTS, c, s, 40001, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 100001, 200001, 200);
    send4(PORT_CLIENTS, c, s, 40002, 5001, RTE_TCP_SYN_FLAG, 900000000u, 0, 0);
    send4(PORT_SERVERS, s, c, 5001, 40002, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 1500000000u, 900000001u, 0);
    send4(PORT_CLIENTS, c, s, 40002, 5001, RTE_TCP_ACK_FLAG, 900000001u, 1500000001u, 0);
    send4(PORT_CLIENTS, c, s, 40002, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 900000001u, 1500000001u, 300);
    struct flow_entry *flow = find4(c, s);
    CHECK(flow != NULL, "the two connections share a flow");
    if (!flow) return;
    CHECK_EQ(FLOW_STATE_ESTABLISHED, flow->state, "the shared flow is established");

    // X closes: its FIN is legitimate but outside the window the flow
    // tracks (Y's). Dropping it would leave X unclosed, and its
    // retransmissions would meet the same window.
    uint64_t invalid_before = rst_fin_invalid();
    struct sent f = send4(PORT_CLIENTS, c, s, 40001, 5001, RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 100201, 200001, 0);
    CHECK(forwarded(f), "the other connection's FIN is forwarded");
    f = send4(PORT_CLIENTS, c, s, 40001, 5001, RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 100201, 200001, 0);
    CHECK(forwarded(f), "its retransmitted FIN is forwarded too");
    CHECK_EQ(invalid_before + 2, rst_fin_invalid(), "both are counted as outside the window");
    CHECK_EQ(FLOW_STATE_ESTABLISHED, flow->state,
             "a FIN outside the tracked window does not close the shared flow");

    // Y's own FIN is in the window and moves the flow
    f = send4(PORT_CLIENTS, c, s, 40002, 5001, RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 900000301u, 1500000001u, 0);
    CHECK(forwarded(f), "the tracked connection's FIN is forwarded");
    CHECK_EQ(FLOW_STATE_FIN_WAIT_1, flow->state, "the tracked connection's FIN starts the close");
}

// IPv6 Stage 11 (validation policy 3: the protected IPv6 pipeline)
static void scenario_ipv6_stage11(void) {
    const uint32_t c = 0x0B000001, s = 0x0A000001;
    printf("IPv6 Stage 11: counters, and a blind RST outside the window\n");

    // A flow first seen mid-stream (the IPv6 proxy answers SYNs itself):
    // 5 client segments of 100 bytes, then the server's ACK
    for (int i = 0; i < 5; i++) {
        struct sent d = send6(PORT_CLIENTS, c, s, 40000, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG,
                              3000 + 100u * (uint32_t)i, 7000, 100);
        CHECK(forwarded(d), "the client segment is forwarded");
    }
    send6(PORT_CLIENTS, s, c, 5001, 40000, RTE_TCP_ACK_FLAG, 7000, 3500, 0);
    struct flow_entry_v6 *flow = find6(c, s);
    CHECK(flow != NULL, "the connection has an IPv6 flow");
    if (!flow) return;
    uint64_t pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) +
                       sizeof(struct rte_tcp_hdr) + 100;
    uint64_t c_packets = (c < s) ? flow->packets_lo_to_hi : flow->packets_hi_to_lo;
    uint64_t c_bytes = (c < s) ? flow->bytes_lo_to_hi : flow->bytes_hi_to_lo;
    CHECK_EQ(5, c_packets, "each IPv6 client segment is counted once");
    CHECK_EQ(5 * pkt_len, c_bytes, "its bytes are counted once");
    CHECK_EQ(6, flow_v6_total_packets(flow), "the flow holds the 6 packets");

    struct flow_table_v6_stats st_before, st_after;
    flow_table_v6_get_stats(&st_before);
    struct sent r = send6(PORT_CLIENTS, c, s, 40000, 5001, RTE_TCP_RST_FLAG, 3500 + 0x40000000u, 0, 0);
    flow_table_v6_get_stats(&st_after);
    CHECK(forwarded(r), "the blind IPv6 RST is forwarded");
    CHECK(flow->state != FLOW_STATE_RST, "the blind IPv6 RST does not tear the flow down");
    CHECK_EQ(7, flow_v6_total_packets(flow), "the blind IPv6 RST is counted once on the flow");
    CHECK_EQ(1, st_after.lookups - st_before.lookups,
             "the IPv6 RST costs one flow lookup (validated against Stage 11's own)");

    r = send6(PORT_CLIENTS, c, s, 40000, 5001, RTE_TCP_RST_FLAG, 3500, 0, 0);
    CHECK(forwarded(r), "the connection's own IPv6 RST is forwarded");
    CHECK_EQ(FLOW_STATE_RST, flow->state, "the connection's own IPv6 RST closes the flow");
}

// A connection the SYN proxy lets through (calm conditions: not challenged)
static void scenario_proxy_bypassed(void) {
    const uint32_t c = BE_IP(11, 2, 0, 4), s = BE_IP(10, 0, 9, 4);
    printf("SYN proxy on, bypassed connection: the flow follows the handshake and the data\n");

    struct sent r = send4(PORT_CLIENTS, c, s, 40010, 5001, RTE_TCP_SYN_FLAG, 1000, 0, 0);
    CHECK(forwarded(r), "the SYN is let through (not challenged)");
    r = send4(PORT_SERVERS, s, c, 5001, 40010, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 5000, 1001, 0);
    CHECK(forwarded(r), "the server's SYN-ACK is forwarded");
    r = send4(PORT_CLIENTS, c, s, 40010, 5001, RTE_TCP_ACK_FLAG, 1001, 5001, 0);
    CHECK(forwarded(r), "the handshake ACK is forwarded");
    r = send4(PORT_CLIENTS, c, s, 40010, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 1001, 5001, 100);
    CHECK(forwarded(r), "client data is forwarded");
    r = send4(PORT_SERVERS, s, c, 5001, 40010, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 5001, 1101, 200);
    CHECK(forwarded(r), "server data is forwarded");

    struct flow_entry *flow = find4(c, s);
    CHECK(flow != NULL, "the connection has a flow");
    if (!flow) return;
    CHECK_EQ(FLOW_STATE_ESTABLISHED, flow->state, "the flow saw the handshake through the proxy");
    CHECK(flow->flags & FLOW_FLAG_HANDSHAKE_ACKED, "the handshake is verified");
    CHECK(flow_is_bidirectional(flow), "the flow saw traffic both ways");
    CHECK_EQ(5, flow_total_packets(flow), "every packet is counted on the flow");
}

// An entry planted by a spoofed SYN in calm conditions: the sender never
// sees the server's SYN-ACK, and its blind ACK must not move the flow
static void scenario_proxy_planted(void) {
    const uint32_t c = BE_IP(11, 2, 0, 5), s = BE_IP(10, 0, 9, 5);
    printf("SYN proxy on, entry planted by a spoofed SYN: a blind ACK leaves the flow alone\n");

    send4(PORT_CLIENTS, c, s, 40011, 5001, RTE_TCP_SYN_FLAG, 1000, 0, 0);
    send4(PORT_SERVERS, s, c, 5001, 40011, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 5000, 1001, 0);
    struct flow_entry *flow = find4(c, s);
    CHECK(flow != NULL, "the SYN has a flow");
    if (!flow) return;
    uint64_t c_packets = (c < s) ? flow->packets_lo_to_hi : flow->packets_hi_to_lo;

    struct sent r = send4(PORT_CLIENTS, c, s, 40011, 5001, RTE_TCP_ACK_FLAG, 1001, 0x12345678, 0);
    (void)r;
    uint64_t c_packets_after = (c < s) ? flow->packets_lo_to_hi : flow->packets_hi_to_lo;
    CHECK(flow->state != FLOW_STATE_ESTABLISHED, "a blind ACK does not establish the flow");
    CHECK(!(flow->flags & FLOW_FLAG_HANDSHAKE_ACKED), "a blind ACK does not verify the handshake");
    CHECK_EQ(c_packets, c_packets_after, "a blind ACK is not counted on the flow");
}

// A challenged connection: the proxy answers the SYN with a cookie and opens
// the server connection itself once the client returns the cookie
static void scenario_proxy_challenged(void) {
    const uint32_t c = BE_IP(11, 2, 0, 6), s = BE_IP(10, 0, 9, 6);
    printf("SYN proxy on, challenged connection: a valid cookie gives it a verified flow\n");

    anomaly_set_level(ANOMALY_LEVEL_MEDIUM);  // every SYN is challenged
    struct lcore_stats *ls = get_lcore_stats();
    uint64_t new_flows_before = ls->l1_new_flows;

    struct sent r = send4(PORT_CLIENTS, c, s, 40012, 5001, RTE_TCP_SYN_FLAG, 1000, 0, 0);
    CHECK(r.action == L1_ACTION_REPLY || r.action == L1_ACTION_REPLY_INPLACE,
          "the SYN is answered with a cookie");
    CHECK(r.synack_seq != 0, "the SYN-ACK carries the cookie");
    CHECK(find4(c, s) == NULL, "a challenged SYN keeps no flow");

    r = send4(PORT_CLIENTS, c, s, 40012, 5001, RTE_TCP_ACK_FLAG, 1001, r.synack_seq + 1, 0);
    CHECK_EQ(L1_ACTION_REPLY, r.action, "the cookie ACK opens the server connection");

    // The cookie path marks the client legitimate (legitimate_ip_add()), a
    // stub that whitelists it in bypass mode: its later segments then skip
    // Stage 9 untranslated, which breaks a proxied connection as shipped.
    // Take the entry out so that its segments reach Stage 9 as intended.
    uint8_t wl_mode;
    if (ip_whitelist_lookup(c, &wl_mode)) {
        printf("  NOTE: the valid cookie whitelisted the client (legitimate_ip_add); entry removed\n");
        ip_whitelist_remove(c);
    }

    r = send4(PORT_SERVERS, s, c, 5001, 40012, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 70000, 1, 0);
    CHECK_EQ(L1_ACTION_REPLY, r.action, "the proxy answers the server's SYN-ACK");
    r = send4(PORT_CLIENTS, c, s, 40012, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 1001, 0, 100);
    CHECK(forwarded(r), "client data is translated and forwarded");
    r = send4(PORT_SERVERS, s, c, 5001, 40012, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 70001, 0, 200);
    CHECK(forwarded(r), "server data is translated and forwarded");
    anomaly_clear();

    struct flow_entry *flow = find4(c, s);
    CHECK(flow != NULL, "the challenged connection has a flow");
    if (!flow) return;
    CHECK_EQ(FLOW_STATE_ESTABLISHED, flow->state, "the flow is established");
    CHECK(flow->flags & FLOW_FLAG_HANDSHAKE_ACKED, "the cookie verified the handshake");
    CHECK(flow_is_bidirectional(flow), "the flow saw traffic both ways");
    CHECK_EQ(4, flow_total_packets(flow), "the cookie ACK, the server's SYN-ACK and the data are counted");
    CHECK_EQ(new_flows_before, ls->l1_new_flows,
             "a flow made for a proxied connection is not counted as a new flow");
}

// ==================== Pipeline ====================

static int run_pipeline(char *prog, const char *dir) {
    int rc = 1;
    bool layer1_up = false;

    if (chdir(dir) != 0) {
        printf("entering %s failed: %s\n", dir, strerror(errno));
        return 1;
    }
    char cfg_path[320], db_path[320];
    snprintf(cfg_path, sizeof(cfg_path), "%s/layer1_config.json", dir);
    snprintf(db_path, sizeof(db_path), "%s/l1_telemetry.db", dir);
    FILE *cf = fopen(cfg_path, "w");
    if (!cf) {
        printf("writing the config failed: %s\n", strerror(errno));
        return 1;
    }
    // Small tables; a 1 s export interval keeps layer1_cleanup() short
    fprintf(cf, "{ \"telemetry\": { \"db_path\": \"%s\", \"export_interval_sec\": 1 },\n"
                "  \"ip_lists\": { \"max_whitelist_entries\": 1024, \"max_blacklist_entries\": 1024,\n"
                "                \"max_protected_entries\": 64, \"max_whitelist_cidrs\": 64,\n"
                "                \"enforce_protected_ips\": false },\n"
                "  \"flow_table\": { \"max_flows\": 4096 },\n"
                "  \"syn_proxy\": { \"max_connections\": 4096 },\n"
                "  \"connection_limits\": { \"max_ips\": 4096 } }\n", db_path);
    fclose(cf);
    setenv("XDG_RUNTIME_DIR", dir, 1);
    setenv("ANTIDDOS_CONFIG_DIR", dir, 1);

    char *eal_args[] = { prog, "-l", "0", "-n", "1", "--no-huge", "--no-pci",
                         "-m", "256", "--no-shconf", "--no-telemetry", NULL };
    if (rte_eal_init((int)RTE_DIM(eal_args) - 1, eal_args) < 0) {
        printf("EAL init failed, skipping test\n");
        return TEST_SKIP;
    }
    if (confine_writes(dir) == 0) {
        printf("Landlock: writes confined to %s\n", dir);
    } else {
        printf("Landlock unavailable: relying on the seams alone\n");
    }

    if (layer1_init(4096, cfg_path) < 0) {
        printf("layer1_init failed\n");
        goto out;
    }
    layer1_up = true;
    printf("layer1_init() without /dev/shm (seams):\n");
    CHECK_EQ(1, g_seam_calls[0], "shared memory came from the private heap");
    CHECK_EQ(1, g_seam_calls[1], "the realtime segment was skipped");
    CHECK_EQ(1, g_seam_calls[2], "the window segment was skipped");

    g_pool = rte_pktmbuf_pool_create("flow_pipeline_pool", 511, 0, 0,
                                     RTE_MBUF_DEFAULT_BUF_SIZE, 0);
    if (!g_pool) {
        printf("mbuf pool creation failed\n");
        goto out;
    }

    // RST/FIN validation with every segment at Stage 11
    syn_proxy_set_enabled(false);
    scenario_rst_single_connection();
    scenario_fin_parallel_connections();

    // The protected IPv6 pipeline (the policy is not read from the file)
    {
        struct layer1_config c6 = *layer1_config_get();
        c6.validation.ipv6_policy = 3;
        layer1_config_set_active(&c6);
        scenario_ipv6_stage11();
    }

    // The SYN proxy's connections
    syn_proxy_set_enabled(true);
    syn_proxy_set_mode(SYN_PROXY_MODE_STATEFUL);
    scenario_proxy_bypassed();
    scenario_proxy_planted();
    scenario_proxy_challenged();

    rc = tests_failed ? 1 : 0;
    if (tests_failed) {
        printf("\nFAIL: %d check(s) above failed\n", tests_failed);
    } else {
        printf("\nPASS: flow tracking through the pipeline\n");
    }

out:
    if (layer1_up) {
        layer1_cleanup();
    }
    if (g_pool) {
        rte_mempool_free(g_pool);
    }
    return rc;
}

// ==================== Main ====================

int main(int argc, char **argv) {
    (void)argc;
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("layer1.c compiled in with the /dev/shm init calls renamed\n");
    struct shm_names shm_before;
    list_antiddos_shm(&shm_before);

    const char *tmp = getenv("TMPDIR");
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/l1_flow_pipeline_XXXXXX", (tmp && tmp[0]) ? tmp : "/tmp");
    if (!mkdtemp(dir)) {
        printf("temporary directory failed: %s\n", strerror(errno));
        return 1;
    }

    fflush(stdout);
    pid_t child = fork();
    if (child < 0) {
        printf("fork failed: %s\n", strerror(errno));
        remove_tree(dir);
        return 1;
    }
    if (child == 0) {
        int child_rc = run_pipeline(argv[0], dir);
        fflush(stdout);
        exit(child_rc);
    }

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    int rc = 1;
    if (waited < 0) {
        printf("FAIL: waitpid failed: %s\n", strerror(errno));
    } else if (WIFEXITED(status)) {
        rc = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        printf("FAIL: the pipeline process died from signal %d\n", WTERMSIG(status));
    }

    if (remove_tree(dir) != 0) {
        printf("FAIL: could not remove %s: %s\n", dir, strerror(errno));
        rc = 1;
    }
    if (report_new_antiddos_shm(&shm_before) > 0) {
        rc = 1;
    }
    return rc;
}
