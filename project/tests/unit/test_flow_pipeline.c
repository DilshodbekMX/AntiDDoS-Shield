/**
 * @file test_flow_pipeline.c
 * @brief Pipeline tests of flow tracking through layer1_process_packet_ex():
 *        RST/FIN validation at IPv4 and IPv6 Stage 11, the IPv6 Stage 11
 *        counters, the flows of SYN proxy connections (Stage 9 and the
 *        outbound path), Stage 8b admission by flow in spoofed mode (IPv4
 *        and IPv6) with the flows spoofed SYNs plant, and the IPv6 per-IP
 *        slot lookup; the close of a challenged connection, a blind RST,
 *        and the client a valid cookie marks legitimate, end to end. Also
 *        Stage 6c's rule for SYN-only frames of 60 bytes or less, which
 *        normal clients of small stacks send.
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

// The SYN proxy's cleanup clock and the legitimate-source clock: the TSC, or a
// time a scenario holds (later than now: entries look idle, proofs expire)
static uint64_t g_cleanup_clock_held, g_legit_clock_held;

uint64_t syn_proxy_cleanup_clock(void) {
    return g_cleanup_clock_held ? g_cleanup_clock_held : rte_get_tsc_cycles();
}

uint64_t legitimate_ip_clock(void) {
    return g_legit_clock_held ? g_legit_clock_held : rte_get_tsc_cycles();
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
// and padding to 74 bytes, as a full stack's SYN does (tcp4_min_syn() builds
// the 60-byte SYNs of small stacks and scanners).
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

// A SYN as small stacks (lwIP: MSS only, opt_len 4) and raw-socket scanners
// (no options, opt_len 0) send it: 58 or 54 bytes, which the sender's NIC
// pads to the 60-byte Ethernet minimum
static struct rte_mbuf *tcp4_min_syn(uint32_t src, uint32_t dst, uint16_t sport,
                                     uint16_t dport, uint16_t opt_len) {
    uint16_t tcp_len = (uint16_t)(sizeof(struct rte_tcp_hdr) + opt_len);
    uint16_t ip_len = (uint16_t)(sizeof(struct rte_ipv4_hdr) + tcp_len);
    uint16_t len = (uint16_t)(sizeof(struct rte_ether_hdr) + ip_len);
    uint16_t frame = len < 60 ? 60 : len;
    struct rte_mbuf *m = rte_pktmbuf_alloc(g_pool);
    if (!m) return NULL;
    uint8_t *p = (uint8_t *)rte_pktmbuf_append(m, frame);
    if (!p) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memset(p, 0, frame);

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    memset(&eth->dst_addr, 0x11, RTE_ETHER_ADDR_LEN);
    memset(&eth->src_addr, 0x22, RTE_ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->total_length = rte_cpu_to_be_16(ip_len);
    ip->src_addr = src;
    ip->dst_addr = dst;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(sport);
    tcp->dst_port = rte_cpu_to_be_16(dport);
    tcp->sent_seq = rte_cpu_to_be_32(7000);
    tcp->data_off = (uint8_t)((tcp_len / 4) << 4);
    tcp->tcp_flags = RTE_TCP_SYN_FLAG;
    tcp->rx_win = rte_cpu_to_be_16(5840);
    if (opt_len >= 4) {
        uint8_t *opt = (uint8_t *)(tcp + 1);
        opt[0] = 2;     // MSS 1460
        opt[1] = 4;
        opt[2] = 0x05;
        opt[3] = 0xB4;
    }
    tcp->cksum = 0;
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
    return m;
}

// signatures_scan_clock() of this binary: the TSC, or a time a scenario holds
// so that its SYNs fall into one window of the Stage 6c scan tracker
static uint64_t sig_clock_held = 0;

uint64_t signatures_scan_clock(void) {
    return sig_clock_held ? sig_clock_held : rte_get_tsc_cycles();
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
    bool fwd;              // a segment left for the other side: this one or one the proxy built
    uint32_t fwd_seq, fwd_ack;
};

static void tcp4_numbers(struct rte_mbuf *m, uint32_t *seq, uint32_t *ack) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + (ip->version_ihl & 0x0F) * 4);
    *seq = rte_be_to_cpu_32(tcp->sent_seq);
    *ack = rte_be_to_cpu_32(tcp->recv_ack);
}

// Runs one mbuf through layer1_process_packet_ex() on rx_port, then frees
// it and whatever the pipeline produced
static struct sent run_packet(struct rte_mbuf *m, uint16_t rx_port) {
    struct sent out = { -1, 0, 0, false, 0, 0 };
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
    // The segment the other side gets, in the numbering it gets it
    if (res.forward_pkt) {
        out.fwd = true;
        tcp4_numbers(res.forward_pkt, &out.fwd_seq, &out.fwd_ack);
    } else if (res.action == L1_ACTION_ACCEPT || res.action == L1_ACTION_ACCEPT_MODIFIED) {
        out.fwd = true;
        tcp4_numbers(m, &out.fwd_seq, &out.fwd_ack);
    }

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

// Stage 6c: a SYN-only frame of 60 bytes or less (no options, or MSS only) is
// only an indicator. Such SYNs of normal clients go on through the pipeline;
// a source that sends them to many ports is dropped as a scan.
static void scenario_minimal_syn(void) {
    const uint32_t s = BE_IP(10, 0, 9, 6), scanner = BE_IP(11, 6, 1, 1);
    printf("Stage 6c: SYNs without options or with MSS only\n");
    sig_clock_held = rte_get_tsc_hz() * 5000 + rte_get_tsc_hz() / 2;   // one tracker window

    struct sent r = run_packet(tcp4_min_syn(BE_IP(11, 6, 0, 1), s, 40000, 443, 0), PORT_CLIENTS);
    CHECK(forwarded(r), "a SYN without options (54 bytes, padded to 60) is forwarded");
    r = run_packet(tcp4_min_syn(BE_IP(11, 6, 0, 2), s, 40000, 1883, 4), PORT_CLIENTS);
    CHECK(forwarded(r), "a SYN with MSS only (58 bytes, padded to 60), as lwIP sends, is forwarded");

    // One source scanning 64 ports with such SYNs
    struct layer1_stats before, after;
    layer1_get_stats(&before);
    int first = 0, passed_after = 0;
    for (int i = 0; i < 64; i++) {
        r = run_packet(tcp4_min_syn(scanner, s, 41000, (uint16_t)(1 + i), 4), PORT_CLIENTS);
        bool sig_drop = r.action == L1_ACTION_DROP && r.drop_reason == DROP_REASON_SIGNATURE;
        if (sig_drop && !first) {
            first = i + 1;
        } else if (!sig_drop && first) {
            passed_after++;
        }
    }
    layer1_get_stats(&after);
    CHECK(first >= SIG_SYN_SCAN_PORTS, "the scanner's SYNs to its first few ports pass Stage 6c");
    CHECK(first > 0, "its scan of 64 ports is dropped at Stage 6c");
    CHECK_EQ(0, passed_after, "every later SYN of the scan is dropped there");
    CHECK_EQ(first ? 64 - first + 1 : 0, after.drop_signature - before.drop_signature,
             "as signature drops");

    r = run_packet(tcp4_min_syn(BE_IP(11, 6, 0, 3), s, 40000, 443, 4), PORT_CLIENTS);
    CHECK(forwarded(r), "meanwhile another client's MSS-only SYN is forwarded");
    sig_clock_held = 0;

    // layer1_init() hands every signature setting to Stage 6c, the operator's
    // strict_syn_scan (which restores the drop of every such SYN) too
    struct layer1_config c = *layer1_config_get();
    CHECK(!layer1_signatures_config(&c).strict_syn_scan,
          "strict_syn_scan is off in this run's config, as by default");
    c.signatures.strict_syn_scan = true;
    c.signatures.block_anomalies = true;
    struct signatures_config sc = layer1_signatures_config(&c);
    CHECK(sc.strict_syn_scan, "a configured strict_syn_scan reaches Stage 6c");
    CHECK(sc.enabled && sc.block_scans && sc.block_anomalies && sc.block_amplification &&
          sc.block_attack_tools, "with the other signature settings");
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

    const uint32_t k = r.synack_seq;   // the cookie: the server's ISN as the client numbers it
    r = send4(PORT_CLIENTS, c, s, 40012, 5001, RTE_TCP_ACK_FLAG, 1001, k + 1, 0);
    CHECK_EQ(L1_ACTION_REPLY, r.action, "the cookie ACK opens the server connection");
    CHECK(r.fwd, "the proxy sends its SYN to the server");
    const uint32_t p = r.fwd_seq;      // the proxy's ISN toward the server

    // The valid cookie marks the client legitimate in a table of its own, not
    // on the whitelist (it used to: Stage 5 then sent the connection's later
    // segments out untranslated, which broke every challenged connection)
    uint8_t wl_mode;
    CHECK(!ip_whitelist_lookup(c, &wl_mode), "the valid cookie does not whitelist the client");
    CHECK(legitimate_ip_lookup(c), "the valid cookie marks the client legitimate");

    r = send4(PORT_SERVERS, s, c, 5001, 40012, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 70000, p + 1, 0);
    CHECK_EQ(L1_ACTION_REPLY, r.action, "the proxy answers the server's SYN-ACK");
    r = send4(PORT_CLIENTS, c, s, 40012, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 1001, k + 1, 100);
    CHECK(forwarded(r), "client data is translated and forwarded");
    CHECK_EQ(L1_ACTION_ACCEPT_MODIFIED, r.action, "the client data is modified (translated)");
    CHECK_EQ(p + 1, r.fwd_seq, "the client's data carries the server's numbering");
    CHECK_EQ(70001, r.fwd_ack, "the client's ACK is translated into the server's numbering");
    r = send4(PORT_SERVERS, s, c, 5001, 40012, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 70001, p + 101, 200);
    CHECK(forwarded(r), "server data is translated and forwarded");
    CHECK_EQ(k + 1, r.fwd_seq, "the server's data carries the client's numbering");
    CHECK_EQ(1101, r.fwd_ack, "the server's ACK is translated into the client's numbering");
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

// Whether the SYN proxy holds an entry for the client's 4-tuple
static bool proxy_holds(uint32_t c, uint32_t s, uint16_t cp, uint16_t sp) {
    struct packet_features f;
    memset(&f, 0, sizeof(f));
    f.src_ip = c;
    f.dst_ip = s;
    f.src_port = cp;
    f.dst_port = sp;
    f.protocol = IPPROTO_TCP;
    return syn_proxy_is_proxied(&f, DIRECTION_INBOUND);
}

static bool closing_flow_state(uint8_t st) {
    return st == FLOW_STATE_FIN_WAIT_1 || st == FLOW_STATE_FIN_WAIT_2 ||
           st == FLOW_STATE_CLOSE_WAIT || st == FLOW_STATE_CLOSING ||
           st == FLOW_STATE_LAST_ACK || st == FLOW_STATE_TIME_WAIT ||
           st == FLOW_STATE_CLOSED || st == FLOW_STATE_RST;
}

// A challenged connection through the pipeline: the SYN under attack, the
// cookie, the proxy's SYN to the server, the server's SYN-ACK, and 100 bytes
// from the client and 200 from the server. Every number is the one the proxy
// forwarded, so each side sees its own numbering.
struct proxied_numbers {
    uint32_t k;        // The cookie: the server's ISN as the client numbers it
    uint32_t cs;       // The client's next sequence as the server numbers it
};

static bool open_challenged(uint32_t c, uint32_t s, uint16_t cp, uint16_t sp,
                            struct proxied_numbers *pn) {
    const uint32_t c_isn = 1000, S = 70000;
    struct sent r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_SYN_FLAG, c_isn, 0, 0);
    CHECK(r.synack_seq != 0, "the SYN is answered with a cookie");
    pn->k = r.synack_seq;
    r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_ACK_FLAG, c_isn + 1, pn->k + 1, 0);
    CHECK_EQ(L1_ACTION_REPLY, r.action, "the cookie ACK opens the server connection");
    const uint32_t p = r.fwd_seq;
    r = send4(PORT_SERVERS, s, c, sp, cp, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, S, p + 1, 0);
    CHECK_EQ(L1_ACTION_REPLY, r.action, "the proxy answers the server's SYN-ACK");
    r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, c_isn + 1, pn->k + 1, 100);
    CHECK(forwarded(r), "client data is forwarded");
    CHECK_EQ(S + 1, r.fwd_ack, "the client's ACK is translated into the server's numbering");
    pn->cs = r.fwd_seq + 100;
    r = send4(PORT_SERVERS, s, c, sp, cp, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, S + 1, pn->cs, 200);
    CHECK(forwarded(r), "server data is forwarded");
    CHECK_EQ(pn->k + 1, r.fwd_seq, "the server's seq is translated into the client's numbering");
    CHECK_EQ(c_isn + 101, r.fwd_ack, "the server's ACK reaches the client in its numbering");
    return r.fwd_ack == c_isn + 101;
}

enum close_kind { CLIENT_FIRST, SERVER_FIRST, CLIENT_RST };

// The close of a challenged connection through layer1_process_packet_ex(), as
// shipped (the valid cookie whitelists nothing, so every segment reaches
// Stage 9): the client closes first, the server closes first, or the client
// aborts with RST+ACK. The last ACK completes a close: it is counted once,
// and the entry stays for the TIME_WAIT, in which a FIN retransmitted for a
// lost last ACK, and the answer to it, are still translated; the cleanup then
// releases it. An exact RST releases it at once. The connection's flow
// follows the close.
static void scenario_proxy_close(enum close_kind kind, uint8_t host) {
    const uint32_t c = BE_IP(11, 3, 0, host), s = BE_IP(10, 0, 10, host);
    const uint16_t cp = (uint16_t)(41000 + host), sp = 5001;
    printf("SYN proxy on, challenged connection closed through the pipeline: %s\n",
           kind == CLIENT_FIRST ? "the client closes first" :
           kind == SERVER_FIRST ? "the server closes first" : "the client aborts with RST+ACK");

    struct syn_proxy_stats st0, st1;
    syn_proxy_get_stats(&st0);
    uint64_t invalid0 = rst_fin_invalid();

    anomaly_set_level(ANOMALY_LEVEL_MEDIUM);   // every SYN is challenged
    struct proxied_numbers pn;
    if (!open_challenged(c, s, cp, sp, &pn)) {
        anomaly_clear();
        return;
    }

    const uint32_t c_next = 1101, s_next = 70201;   // each side's next sequence, its own numbering
    const uint32_t c_view_s = pn.k + 201;           // the client's ACK of all server data
    const uint32_t s_view_c = pn.cs;                // the server's ACK of all client data
    struct sent r;
    if (kind == CLIENT_FIRST) {
        r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, c_next, c_view_s, 0);
        CHECK(forwarded(r), "the client's FIN+ACK is forwarded");
        CHECK_EQ(s_view_c, r.fwd_seq, "the client's FIN carries the server's numbering");
        r = send4(PORT_SERVERS, s, c, sp, cp, RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, s_next, s_view_c + 1, 0);
        CHECK(forwarded(r), "the server's FIN+ACK is forwarded");
        CHECK(proxy_holds(c, s, cp, sp), "the entry is held until the last ACK");
        r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_ACK_FLAG, c_next + 1, c_view_s + 1, 0);
        CHECK(forwarded(r), "the client's last ACK is forwarded");
        CHECK_EQ(s_next + 1, r.fwd_ack, "the last ACK acknowledges the server's FIN in its numbering");
    } else if (kind == SERVER_FIRST) {
        r = send4(PORT_SERVERS, s, c, sp, cp, RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, s_next, s_view_c, 0);
        CHECK(forwarded(r), "the server's FIN+ACK is forwarded");
        CHECK_EQ(c_view_s, r.fwd_seq, "the server's FIN carries the client's numbering");
        r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, c_next, c_view_s + 1, 0);
        CHECK(forwarded(r), "the client's FIN+ACK is forwarded");
        CHECK(proxy_holds(c, s, cp, sp), "the entry is held until the last ACK");
        r = send4(PORT_SERVERS, s, c, sp, cp, RTE_TCP_ACK_FLAG, s_next + 1, s_view_c + 1, 0);
        CHECK(forwarded(r), "the server's last ACK (outbound) is forwarded");
        CHECK_EQ(c_next + 1, r.fwd_ack, "the last ACK acknowledges the client's FIN in its numbering");
    } else {
        r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG, c_next, c_view_s, 0);
        CHECK(forwarded(r), "the client's RST+ACK is forwarded");
        CHECK_EQ(s_view_c, r.fwd_seq, "the client's RST carries the server's numbering");
    }
    anomaly_clear();

    syn_proxy_get_stats(&st1);
    CHECK_EQ(st0.connections_closed + 1, st1.connections_closed, "the close is counted once");
    if (kind != CLIENT_RST) {
        // The last ACK is lost beyond the proxy: the FIN comes again, and is
        // answered again, both still translated
        CHECK(proxy_holds(c, s, cp, sp), "the entry stays for the TIME_WAIT");
        if (kind == CLIENT_FIRST) {
            r = send4(PORT_SERVERS, s, c, sp, cp, RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, s_next, s_view_c + 1, 0);
            CHECK_EQ(L1_ACTION_ACCEPT_MODIFIED, r.action, "the server's FIN again is translated and forwarded");
            CHECK_EQ(c_view_s, r.fwd_seq, "the server's FIN again carries the client's numbering");
            r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_ACK_FLAG, c_next + 1, c_view_s + 1, 0);
            CHECK_EQ(s_next + 1, r.fwd_ack, "the client's answer acknowledges it in the server's numbering");
        } else {
            r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, c_next, c_view_s + 1, 0);
            CHECK_EQ(L1_ACTION_ACCEPT_MODIFIED, r.action, "the client's FIN again is translated and forwarded");
            CHECK_EQ(s_view_c, r.fwd_seq, "the client's FIN again carries the server's numbering");
            CHECK_EQ(s_next + 1, r.fwd_ack, "the client's FIN again acknowledges in the server's numbering");
            r = send4(PORT_SERVERS, s, c, sp, cp, RTE_TCP_ACK_FLAG, s_next + 1, s_view_c + 1, 0);
            CHECK_EQ(c_next + 1, r.fwd_ack, "the server's answer acknowledges it in the client's numbering");
        }
        syn_proxy_get_stats(&st1);
        CHECK_EQ(st0.connections_closed + 1, st1.connections_closed, "the TIME_WAIT counts nothing again");
        // Past the TIME_WAIT the cleanup releases the entry
        g_cleanup_clock_held = rte_get_tsc_cycles() + (uint64_t)(SYN_PROXY_TIME_WAIT_SEC + 1) * rte_get_tsc_hz();
        uint32_t cleaned = syn_proxy_cleanup_connections();
        g_cleanup_clock_held = 0;
        CHECK_EQ(1, cleaned, "past the TIME_WAIT the cleanup releases the entry");
    }
    syn_proxy_get_stats(&st1);
    CHECK(!proxy_holds(c, s, cp, sp), "the proxy entry is released");
    CHECK_EQ(st0.connections_closed + 1, st1.connections_closed, "the close is still counted once");
    CHECK_EQ(st0.connections_active, st1.connections_active, "connections_active is back");
    struct flow_entry *flow = find4(c, s);
    CHECK(flow != NULL, "the connection has a flow");
    if (flow) {
        uint8_t fst = __atomic_load_n(&flow->state, __ATOMIC_RELAXED);
        CHECK(flow->flags & FLOW_FLAG_HANDSHAKE_ACKED, "the flow is verified (valid cookie)");
        CHECK(closing_flow_state(fst), "the flow followed the close");
    }
    CHECK_EQ(invalid0, rst_fin_invalid(), "no RST or FIN of the connection is counted as invalid");
}

// A blind RST on a challenged connection: outside the server's window it is
// dropped (as spoofed TCP), in the window but not exact it is forwarded and
// the entry stays; either way the connection's later segments are still
// translated. Once any RST on the 4-tuple ended the entry.
static void scenario_proxy_blind_rst(void) {
    const uint32_t c = BE_IP(11, 3, 0, 9), s = BE_IP(10, 0, 10, 9);
    const uint16_t cp = 41009, sp = 5001;
    printf("SYN proxy on, challenged connection: blind RSTs\n");

    anomaly_set_level(ANOMALY_LEVEL_MEDIUM);
    struct proxied_numbers pn;
    if (!open_challenged(c, s, cp, sp, &pn)) {
        anomaly_clear();
        return;
    }
    anomaly_clear();

    struct flow_entry *flow = find4(c, s);
    CHECK(flow != NULL, "the connection has a flow");
    uint8_t flow_state = flow ? __atomic_load_n(&flow->state, __ATOMIC_RELAXED) : 0;
    struct lcore_stats *ls = get_lcore_stats();
    uint64_t spoofed_before = ls->l1_drop_spoofed_tcp;
    struct sent r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_RST_FLAG, 1101 + 0x40000000u, 0, 0);
    CHECK_EQ(L1_ACTION_DROP, r.action, "a blind RST outside the window is dropped");
    CHECK_EQ(DROP_REASON_SPOOFED_TCP, r.drop_reason, "it is dropped as spoofed TCP");
    CHECK_EQ(spoofed_before + 1, ls->l1_drop_spoofed_tcp, "it is counted as spoofed TCP");
    r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_RST_FLAG, 1101 + 3000, 0, 0);
    CHECK(forwarded(r), "an RST in the window is forwarded for the server to judge");
    CHECK_EQ(pn.cs + 3000, r.fwd_seq, "it carries the server's numbering");
    CHECK(proxy_holds(c, s, cp, sp), "neither ends the entry");
    if (flow) {
        CHECK_EQ(flow_state, __atomic_load_n(&flow->state, __ATOMIC_RELAXED),
                 "neither tears the connection's flow down");
    }
    r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 1101, pn.k + 201, 10);
    CHECK_EQ(L1_ACTION_ACCEPT_MODIFIED, r.action, "the connection's data is still translated");
    CHECK_EQ(pn.cs, r.fwd_seq, "its data carries the server's numbering");
    // The client's own RST, at the server's next sequence once the server
    // has acknowledged the 10 bytes, ends it
    r = send4(PORT_SERVERS, s, c, sp, cp, RTE_TCP_ACK_FLAG, 70201, pn.cs + 10, 0);
    CHECK_EQ(1111, r.fwd_ack, "the server's ACK reaches the client in its numbering");
    r = send4(PORT_CLIENTS, c, s, cp, sp, RTE_TCP_RST_FLAG, 1111, 0, 0);
    CHECK(forwarded(r), "the client's RST is forwarded");
    CHECK(!proxy_holds(c, s, cp, sp), "the client's RST at the server's next sequence ends the entry");
}

// A client whose cookie validated is marked legitimate, never whitelisted:
// under attack its next connection is challenged like any other (and works
// end to end, translated), a blacklist entry still drops it (Stage 6), in
// spoofed mode and with a suspicious reputation it is challenged too, and the
// mark ends with the legitimate TTL. The mark changes no decision: once a
// valid cookie let the source's SYNs skip the challenge for the TTL, and one
// source could fill the SYN proxy table with their entries.
static void scenario_legitimate_source(void) {
    const uint32_t c = BE_IP(11, 4, 0, 1), s = BE_IP(10, 0, 11, 1);
    const uint16_t sp = 5001;
    printf("SYN proxy on, a client that returned a valid cookie\n");

    anomaly_set_level(ANOMALY_LEVEL_MEDIUM);   // every SYN is challenged
    const uint64_t proof = rte_get_tsc_cycles();
    g_legit_clock_held = proof;
    struct sent r = send4(PORT_CLIENTS, c, s, 42001, sp, RTE_TCP_SYN_FLAG, 1000, 0, 0);
    CHECK(r.synack_seq != 0, "the client's first SYN is challenged");
    r = send4(PORT_CLIENTS, c, s, 42001, sp, RTE_TCP_ACK_FLAG, 1001, r.synack_seq + 1, 0);
    CHECK_EQ(L1_ACTION_REPLY, r.action, "its cookie opens the server connection");
    uint8_t wl_mode;
    CHECK(legitimate_ip_lookup(c), "the valid cookie marks the client legitimate");
    CHECK(!ip_whitelist_lookup(c, &wl_mode), "the valid cookie does not whitelist the client");

    // Its next connection: challenged again, and translated end to end once
    // it returns that cookie too
    r = send4(PORT_CLIENTS, c, s, 42002, sp, RTE_TCP_SYN_FLAG, 5000, 0, 0);
    CHECK(r.synack_seq != 0 && !r.fwd, "under attack the legitimate client's next SYN is challenged");
    CHECK(!proxy_holds(c, s, 42002, sp), "the challenged SYN makes no entry");
    struct proxied_numbers pn;
    CHECK(open_challenged(c, s, 42003, sp, &pn), "its next connection works through the challenge");
    CHECK(proxy_holds(c, s, 42003, sp), "that connection is proxied");

    // Not a whitelist: Stage 6 still drops it once it is blacklisted
    CHECK_EQ(0, ip_blacklist_add(c), "the client is blacklisted");
    r = send4(PORT_CLIENTS, c, s, 42004, sp, RTE_TCP_SYN_FLAG, 6000, 0, 0);
    CHECK_EQ(L1_ACTION_DROP, r.action, "a blacklisted legitimate client is dropped");
    CHECK_EQ(DROP_REASON_BLACKLIST, r.drop_reason, "it is dropped by the blacklist");
    CHECK_EQ(0, ip_blacklist_remove(c), "the client leaves the blacklist");

    // In spoofed mode it is challenged, as with a suspicious reputation
    anomaly_set_spoofed_mode(1, 90);
    r = send4(PORT_CLIENTS, c, s, 42005, sp, RTE_TCP_SYN_FLAG, 7000, 0, 0);
    CHECK(r.synack_seq != 0 && !r.fwd, "in spoofed mode the legitimate client is challenged");
    CHECK_EQ(0, reputation_update(c, 400, 100, 0, 1), "the client's reputation becomes suspicious");
    r = send4(PORT_CLIENTS, c, s, 42006, sp, RTE_TCP_SYN_FLAG, 8000, 0, 0);
    CHECK(r.synack_seq != 0, "a suspicious reputation challenges the legitimate client");
    reputation_remove(c);
    anomaly_set_spoofed_mode(0, 0);

    // Past the legitimate TTL (from the cookie) the mark is gone, and its
    // SYN is challenged as before
    g_legit_clock_held = proof + (uint64_t)(LEGITIMATE_DEFAULT_TTL_SEC + 1) * rte_get_tsc_hz();
    CHECK(!legitimate_ip_lookup(c), "past the TTL the client is no longer legitimate");
    r = send4(PORT_CLIENTS, c, s, 42007, sp, RTE_TCP_SYN_FLAG, 9000, 0, 0);
    CHECK(r.synack_seq != 0, "past the TTL the client's SYN is challenged");
    g_legit_clock_held = 0;   // On the TSC the cookie is recent again
    anomaly_clear();

    // A source of good reputation is challenged only above 10 times the
    // challenge threshold, and a legitimate one there too. 20000 SYN
    // decisions put the rate there (the last ones of this scenario).
    const uint32_t g = BE_IP(11, 4, 0, 2);
    CHECK(legitimate_ip_lookup(c), "the client is still marked legitimate");
    CHECK_EQ(0, reputation_update(c, 800, 100, 0, 0), "the client's reputation becomes good");
    CHECK_EQ(0, reputation_update(g, 800, 100, 0, 0), "another client's reputation becomes good");
    struct packet_features syn = { .protocol = IPPROTO_TCP, .tcp_flags = RTE_TCP_SYN_FLAG,
                                   .dst_ip = s, .dst_port = sp, .src_port = 42008 };
    syn.src_ip = c;
    CHECK(!syn_proxy_should_challenge(&syn, NULL),
          "below 10 times the threshold the client of good reputation is not challenged");
    for (uint32_t i = 0; i < 20000; i++) {
        syn.src_ip = BE_IP(12, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
        (void)syn_proxy_should_challenge(&syn, NULL);
    }
    syn.src_ip = c;
    CHECK(syn_proxy_should_challenge(&syn, NULL),
          "above 10 times the threshold the legitimate client of good reputation is challenged");
    syn.src_ip = g;
    CHECK(syn_proxy_should_challenge(&syn, NULL), "another client of good reputation is challenged there");
    reputation_remove(c);
    reputation_remove(g);
}

// ==================== Stage 11: a Stalled Flow Table Reader ====================

// flow_table_stall_clock() of this binary: the TSC, or a time a scenario holds
// so that the stalled-reader check finds a silent reader without waiting
static uint64_t g_stall_clock_held = 0;

uint64_t flow_table_stall_clock(void) {
    return g_stall_clock_held ? g_stall_clock_held : rte_rdtsc();
}

// A real handshake as the flow table sees it, made in the table directly:
// ESTABLISHED, both ways, the ACK of the server's ISN + 1. Emergency eviction
// never takes such a flow, so a table full of them stays full.
static bool table_handshake4(uint32_t c, uint32_t s) {
    struct packet_features f;
    bool created;
    memset(&f, 0, sizeof(f));
    f.protocol = IPPROTO_TCP;
    f.packet_size = 74;
    f.timestamp_tsc = rte_rdtsc();
    f.src_ip = c;
    f.dst_ip = s;
    f.src_port = 40100;
    f.dst_port = 5001;
    f.tcp_flags = RTE_TCP_SYN_FLAG;
    f.tcp_seq = 1000;
    struct flow_entry *flow = flow_table_lookup_or_create(&f, &created);
    if (!flow) return false;
    flow_table_update(flow, &f);
    // Each segment is looked up first: the lookup sets its direction
    struct packet_features r = f;
    r.src_ip = s;
    r.dst_ip = c;
    r.src_port = 5001;
    r.dst_port = 40100;
    r.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    r.tcp_seq = 5000;
    r.tcp_ack = 1001;
    if (flow_table_lookup(&r) != flow) return false;
    flow_table_update(flow, &r);
    f.tcp_flags = RTE_TCP_ACK_FLAG;
    f.tcp_seq = 1001;
    f.tcp_ack = 5001;
    if (flow_table_lookup(&f) != flow) return false;
    flow_table_update(flow, &f);
    return __atomic_load_n(&flow->state, __ATOMIC_RELAXED) == FLOW_STATE_ESTABLISHED &&
           (flow->flags & FLOW_FLAG_HANDSHAKE_ACKED) && flow_is_bidirectional(flow);
}

#define STALL_SOURCES 32

// A full flow table makes Stage 11 drop the share of new sources its hash
// picks (emergency_drop_unknown_pct for unknown sources) and pass the rest
// untracked. While a flow table reader is stalled the table reuses no deleted
// entry and pauses aging and eviction, so creates fail whatever the traffic:
// then no new source is dropped for it. Once a stalled reader kept 90% of new
// unknown sources out until it reported again.
static void scenario_stalled_reader_new_sources(void) {
    const uint32_t s = BE_IP(10, 0, 12, 1);
    const unsigned int silent = 200;     // a reader id no lcore of this test uses
    struct lcore_stats *ls = get_lcore_stats();
    printf("Stage 11, flow table full: the emergency drop, and none while a reader is stalled\n");

    syn_proxy_set_enabled(false);
    flow_table_clear();
    uint32_t filled = 0;
    bool all_held = true;
    for (uint32_t i = 0; i < 2 * 4096; i++) {
        uint32_t c = BE_IP(12, 100 + (i >> 16), (i >> 8) & 0xFF, i & 0xFF);
        if (!table_handshake4(c, s)) {
            if (find4(c, s) != NULL) {
                all_held = false;     // created, but not as a verified handshake
            }
            break;
        }
        filled++;
    }
    CHECK_EQ(4096, filled, "the table is full of verified flows");
    CHECK(all_held, "every flow in it is one emergency eviction never takes");

    // No stall: a mid-stream segment from a new source finds no free entry,
    // and the sources the hash picks are dropped
    bool picked[STALL_SOURCES];
    uint32_t dropped = 0, other_reason = 0;
    uint64_t full_before = ls->l1_drop_flow_table_full;
    for (uint32_t i = 0; i < STALL_SOURCES; i++) {
        uint32_t c = BE_IP(11, 9, 0, i + 1);
        struct sent r = send4(PORT_CLIENTS, c, s, 43000, 5001, RTE_TCP_ACK_FLAG, 2000, 3000, 0);
        picked[i] = r.action == L1_ACTION_DROP;
        if (picked[i]) {
            dropped++;
            if (r.drop_reason != DROP_REASON_FLOW_TABLE_FULL) other_reason++;
        } else if (!forwarded(r)) {
            other_reason++;
        }
    }
    CHECK_EQ(full_before + STALL_SOURCES, ls->l1_drop_flow_table_full,
             "without a stall each new source finds the table full");
    CHECK(dropped > 0, "without a stall the emergency drop picks some new sources");
    CHECK_EQ(0, other_reason, "the others are forwarded untracked, and the drops are for the full table");

    // A reader stops reporting: the check finds it 3 s after its probe
    CHECK_EQ(0, flow_table_reader_register(silent), "a reader registers and then stays silent");
    const uint64_t t0 = rte_rdtsc();
    g_stall_clock_held = t0;
    flow_table_age_flows();                       // issues the probe
    g_stall_clock_held = t0 + 3 * rte_get_tsc_hz();
    flow_table_age_flows();                       // past the stall time: found
    CHECK_EQ(1, flow_table_readers_stalled(), "the silent reader is found stalled");
    CHECK(flow_table_reader_stalled(silent), "by its id");

    // The same new sources: none is dropped, each goes on untracked
    uint32_t dropped_stalled = 0, picked_forwarded = 0;
    full_before = ls->l1_drop_flow_table_full;
    for (uint32_t i = 0; i < STALL_SOURCES; i++) {
        uint32_t c = BE_IP(11, 9, 0, i + 1);
        struct sent r = send4(PORT_CLIENTS, c, s, 43000, 5001, RTE_TCP_ACK_FLAG, 2000, 3000, 0);
        if (r.action == L1_ACTION_DROP) {
            dropped_stalled++;
        } else if (picked[i] && forwarded(r)) {
            picked_forwarded++;
        }
    }
    CHECK_EQ(full_before + STALL_SOURCES, ls->l1_drop_flow_table_full,
             "while the reader is stalled each new source still finds the table full");
    CHECK_EQ(0, dropped_stalled, "while a reader is stalled no new source is dropped for the full table");
    CHECK_EQ(dropped, picked_forwarded, "the sources the emergency drop picked are forwarded untracked");
    CHECK(find4(BE_IP(11, 9, 0, 1), s) == NULL, "no flow is made for them");

    // The reader goes away: the stall ends
    flow_table_reader_unregister(silent);
    g_stall_clock_held = 0;
    CHECK_EQ(0, flow_table_readers_stalled(), "unregistering the reader ends the stall");
    flow_table_clear();
    struct sent r = send4(PORT_CLIENTS, BE_IP(11, 9, 1, 1), s, 43000, 5001, RTE_TCP_ACK_FLAG, 2000, 3000, 0);
    CHECK(forwarded(r) && find4(BE_IP(11, 9, 1, 1), s) != NULL, "with the table cleared a new source gets a flow");
    syn_proxy_set_enabled(true);
}

// ==================== Spoofed Mode (Stage 8b) ====================

static bool dropped_as_spoofed(struct sent s) {
    return s.action == L1_ACTION_DROP && s.drop_reason == DROP_REASON_SPOOFED_TCP;
}

// A spoofed SYN the proxy lets through (calm conditions) plants a flow, and
// the server retransmits its SYN-ACK to the spoofed source. The flow must not
// live on those retransmissions, and in spoofed mode it must admit no blind
// segment from that source (the flow key has no ports).
static void scenario_spoofed_planted(void) {
    const uint32_t x = BE_IP(11, 2, 0, 20), s = BE_IP(10, 0, 9, 20);
    const uint64_t hz = rte_get_tsc_hz();
    printf("Spoofed SYN let through: its flow neither lives on the server's SYN-ACKs nor admits blind segments\n");

    struct sent r = send4(PORT_CLIENTS, x, s, 40020, 5001, RTE_TCP_SYN_FLAG, 1000, 0, 0);
    CHECK(forwarded(r), "the spoofed SYN is let through (not challenged)");
    r = send4(PORT_SERVERS, s, x, 5001, 40020, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 5000, 1001, 0);
    CHECK(forwarded(r), "the server's SYN-ACK is forwarded");
    struct flow_entry *flow = find4(x, s);
    CHECK(flow != NULL, "the SYN has a flow");
    if (!flow) return;
    CHECK(!(flow->flags & FLOW_FLAG_HANDSHAKE_ACKED), "its handshake is not verified");

    // The SYN 4 s ago: the server's retransmission leaves the flow's time
    uint64_t syn_tsc = rte_rdtsc() - 4 * hz;
    flow->last_seen_tsc = syn_tsc;
    r = send4(PORT_SERVERS, s, x, 5001, 40020, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 5000, 1001, 0);
    CHECK(forwarded(r), "the retransmitted SYN-ACK is forwarded");
    CHECK(flow->last_seen_tsc == syn_tsc, "the retransmitted SYN-ACK does not keep the flow alive");

    // Spoofed mode: blind segments from the spoofed source are dropped, on
    // another port and on the SYN's own 4-tuple
    anomaly_set_spoofed_mode(1, 90);
    r = send4(PORT_CLIENTS, x, s, 40099, 5001, RTE_TCP_ACK_FLAG, 77777, 12345, 0);
    CHECK(dropped_as_spoofed(r), "a blind ACK on another port is dropped as spoofed");
    r = send4(PORT_CLIENTS, x, s, 40099, 5001, RTE_TCP_RST_FLAG, 77777, 0, 0);
    CHECK(dropped_as_spoofed(r), "a blind RST on another port is dropped as spoofed");
    r = send4(PORT_CLIENTS, x, s, 40020, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 1001, 12345, 40);
    CHECK(dropped_as_spoofed(r), "a blind segment on the SYN's 4-tuple is dropped as spoofed");
    anomaly_set_spoofed_mode(0, 0);
    CHECK(flow->last_seen_tsc == syn_tsc, "the dropped segments do not move the flow");

    // Past the SYN timeout (5 s) counted from the SYN the flow ages, and the
    // server's next retransmission does not bring it back
    flow->last_seen_tsc = rte_rdtsc() - 6 * hz;
    flow_table_age_flows();
    CHECK(find4(x, s) == NULL, "the flow ages at the SYN timeout counted from the SYN");
    r = send4(PORT_SERVERS, s, x, 5001, 40020, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 5000, 1001, 0);
    CHECK(forwarded(r), "the next retransmission is forwarded");
    CHECK(find4(x, s) == NULL, "the next retransmission does not create the flow again");
}

// A real client's connection, let through in calm conditions: in spoofed
// mode its verified flow admits its segments, and those of its other
// connections to the server
static void scenario_spoofed_legit(void) {
    const uint32_t c = BE_IP(11, 2, 0, 21), s = BE_IP(10, 0, 9, 21);
    printf("Spoofed mode: a real client's connections are admitted by its verified flow\n");

    send4(PORT_CLIENTS, c, s, 40021, 5001, RTE_TCP_SYN_FLAG, 1000, 0, 0);
    send4(PORT_SERVERS, s, c, 5001, 40021, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 5000, 1001, 0);
    send4(PORT_CLIENTS, c, s, 40021, 5001, RTE_TCP_ACK_FLAG, 1001, 5001, 0);
    send4(PORT_CLIENTS, c, s, 40021, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 1001, 5001, 100);
    send4(PORT_SERVERS, s, c, 5001, 40021, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 5001, 1101, 200);
    struct flow_entry *flow = find4(c, s);
    CHECK(flow != NULL && (flow->flags & FLOW_FLAG_HANDSHAKE_ACKED), "the connection's flow is verified");

    anomaly_set_spoofed_mode(1, 90);
    struct sent r = send4(PORT_CLIENTS, c, s, 40021, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG,
                          1101, 5201, 100);
    CHECK(forwarded(r), "its data is admitted in spoofed mode");
    r = send4(PORT_CLIENTS, c, s, 40022, 5001, RTE_TCP_ACK_FLAG, 3000, 4000, 0);
    CHECK(forwarded(r), "a segment of the client's other connection is admitted by the verified flow");
    r = send4(PORT_CLIENTS, c, s, 40021, 5001, RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 1201, 5201, 0);
    CHECK(forwarded(r), "its FIN is admitted");
    anomaly_set_spoofed_mode(0, 0);
}

// The SYN proxy off: Stage 8b admits by flow alone, so the handshake ACK
// must pass on its own evidence (the ACK of the server's ISN + 1), while a
// blind ACK from the same address does not
static void scenario_spoofed_unproxied(void) {
    const uint32_t c = BE_IP(11, 2, 0, 22), s = BE_IP(10, 0, 9, 22);
    printf("Spoofed mode, SYN proxy off: a handshake completes through its flow, a blind ACK does not\n");

    syn_proxy_set_enabled(false);
    anomaly_set_spoofed_mode(1, 90);
    struct sent r = send4(PORT_CLIENTS, c, s, 40023, 5001, RTE_TCP_SYN_FLAG, 1000, 0, 0);
    CHECK(forwarded(r), "the SYN reaches the server");
    r = send4(PORT_SERVERS, s, c, 5001, 40023, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 5000, 1001, 0);
    CHECK(forwarded(r), "the server's SYN-ACK is forwarded");
    r = send4(PORT_CLIENTS, c, s, 40024, 5001, RTE_TCP_ACK_FLAG, 2000, 777, 0);
    CHECK(dropped_as_spoofed(r), "a blind ACK from the client's address is dropped as spoofed");
    r = send4(PORT_CLIENTS, c, s, 40023, 5001, RTE_TCP_ACK_FLAG, 1001, 5001, 0);
    CHECK(forwarded(r), "the handshake ACK is admitted: it acknowledges the server's ISN + 1");
    r = send4(PORT_CLIENTS, c, s, 40023, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 1001, 5001, 100);
    CHECK(forwarded(r), "the connection's data is admitted");
    struct flow_entry *flow = find4(c, s);
    CHECK(flow != NULL && (flow->flags & FLOW_FLAG_HANDSHAKE_ACKED), "the handshake ACK verified the flow");
    anomaly_set_spoofed_mode(0, 0);
    syn_proxy_set_enabled(true);
}

// A connection the protected server opens: its own SYN vouches for the
// remote host's reply
static void scenario_spoofed_server_opens(void) {
    const uint32_t remote = BE_IP(11, 2, 0, 23), s = BE_IP(10, 0, 9, 23);
    printf("Spoofed mode: the reply to a connection the server opened is admitted\n");

    anomaly_set_spoofed_mode(1, 90);
    struct sent r = send4(PORT_SERVERS, s, remote, 40030, 443, RTE_TCP_SYN_FLAG, 4000, 0, 0);
    CHECK(forwarded(r), "the server's SYN goes out");
    r = send4(PORT_CLIENTS, remote, s, 443, 40030, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 8000, 4001, 0);
    CHECK(forwarded(r), "the remote host's SYN-ACK is admitted");
    send4(PORT_SERVERS, s, remote, 40030, 443, RTE_TCP_ACK_FLAG, 4001, 8001, 0);
    r = send4(PORT_CLIENTS, remote, s, 443, 40030, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 8001, 4001, 300);
    CHECK(forwarded(r), "the remote host's data is admitted");
    anomaly_set_spoofed_mode(0, 0);
}

// A connection the table first sees mid-stream, from the server (after a
// restart, or once its flow aged): the server's data vouches for the
// client's segments
static void scenario_spoofed_server_first(void) {
    const uint32_t c = BE_IP(11, 2, 0, 24), s = BE_IP(10, 0, 9, 24);
    printf("Spoofed mode: a connection first seen mid-stream from the server is admitted\n");

    anomaly_set_spoofed_mode(1, 90);
    struct sent r = send4(PORT_SERVERS, s, c, 5001, 40040, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 9000, 7000, 200);
    CHECK(forwarded(r), "the server's data goes out");
    r = send4(PORT_CLIENTS, c, s, 40040, 5001, RTE_TCP_ACK_FLAG, 7000, 9200, 0);
    CHECK(forwarded(r), "the client's ACK is admitted");
    anomaly_set_spoofed_mode(0, 0);
}

// An IPv6 handshake as the flow table sees it: the client's SYN and the
// server's SYN-ACK. (Through the pipeline the IPv6 proxy answers every SYN
// itself, so these flows are made in the table directly.)
static struct flow_entry_v6 *handshake6(uint32_t client, uint32_t server, uint16_t sport) {
    struct packet_features_v6 f;
    bool created;
    memset(&f, 0, sizeof(f));
    f.ip_version = IP_VERSION_6;
    f.protocol = IPPROTO_TCP;
    f.packet_size = 74;
    test_ip6(f.src_ip.v6, client);
    test_ip6(f.dst_ip.v6, server);
    f.src_port = sport;
    f.dst_port = 5001;
    f.tcp_flags = RTE_TCP_SYN_FLAG;
    f.tcp_seq = 1000;
    struct flow_entry_v6 *flow = flow_table_v6_lookup_or_create(&f, &created);
    if (!flow) return NULL;
    flow_table_v6_update(flow, &f);

    memset(&f, 0, sizeof(f));
    f.ip_version = IP_VERSION_6;
    f.protocol = IPPROTO_TCP;
    f.packet_size = 74;
    test_ip6(f.src_ip.v6, server);
    test_ip6(f.dst_ip.v6, client);
    f.src_port = 5001;
    f.dst_port = sport;
    f.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    f.tcp_seq = 5000;
    f.tcp_ack = 1001;
    if (flow_table_v6_lookup(&f) != flow) return NULL;
    flow_table_v6_update(flow, &f);
    return flow;
}

// IPv6 Stage 8b in spoofed mode (validation policy 3)
static void scenario_ipv6_spoofed(void) {
    const uint32_t x = 0x0B000020, c = 0x0B000021, s = 0x0A000020;
    printf("IPv6 Stage 8b in spoofed mode: a planted flow admits no blind segment, a handshake ACK passes\n");

    struct flow_entry_v6 *planted = handshake6(x, s, 40050);
    struct flow_entry_v6 *real = handshake6(c, s, 40051);
    CHECK(planted != NULL && real != NULL, "both IPv6 handshakes have flows");
    if (!planted || !real) return;

    anomaly_set_spoofed_mode(1, 90);
    struct sent r = send6(PORT_CLIENTS, x, s, 40050, 5001, RTE_TCP_ACK_FLAG, 1001, 0x12345678, 0);
    CHECK(dropped_as_spoofed(r), "a blind IPv6 ACK from the spoofed source is dropped as spoofed");
    r = send6(PORT_CLIENTS, s, x, 5001, 40050, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 5000, 1001, 0);
    CHECK(forwarded(r), "the server's IPv6 SYN-ACK to the host that opened is admitted");
    r = send6(PORT_CLIENTS, c, s, 40051, 5001, RTE_TCP_ACK_FLAG, 1001, 5001, 0);
    CHECK(forwarded(r), "the IPv6 handshake ACK is admitted: it acknowledges the server's ISN + 1");
    r = send6(PORT_CLIENTS, c, s, 40051, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, 1001, 5001, 100);
    CHECK(forwarded(r), "the IPv6 connection's data is admitted");
    anomaly_set_spoofed_mode(0, 0);
    CHECK(real->flags & FLOW_FLAG_HANDSHAKE_ACKED, "the IPv6 handshake ACK verified the flow");
}

// IPv6 per-IP features: Stage 3c looks the destination up by its address
// (from an aligned copy of the mbuf's), so a registered destination's slot
// counts its packets
static void scenario_ipv6_per_ip_slot(void) {
    const uint32_t c = 0x0B000030, s = 0x0A000030;
    printf("IPv6 per-IP features: the slot of a registered IPv6 destination counts its packets\n");

    union ip_addr s6;
    test_ip6(s6.v6, s);
    CHECK_EQ(0, per_ip_features_v6_register(s6.v6), "the IPv6 destination's slot is registered");
    struct per_ip_features_v6 *pif = per_ip_features_v6_lookup(s6.v6);
    CHECK(pif != NULL, "its slot is found");
    if (!pif) return;
    unsigned int lc = rte_lcore_id();
    uint64_t before = pif->lcore_counters[lc].rx_packets;
    for (uint32_t i = 0; i < 3; i++) {
        struct sent d = send6(PORT_CLIENTS, c, s, 40060, 5001, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG,
                              3000 + 100 * i, 7000, 100);
        CHECK(forwarded(d), "the segment to it is forwarded");
    }
    CHECK_EQ(before + 3, pif->lcore_counters[lc].rx_packets, "each packet to it is counted on its slot");
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

    // layer1_init() takes about 254 MiB of the DPDK heap, and the
    // legitimate-source table 1 MiB of that; 256 MiB left too little for the
    // packet pool. Untouched heap pages cost no memory.
    char *eal_args[] = { prog, "-l", "0", "-n", "1", "--no-huge", "--no-pci",
                         "-m", "512", "--no-shconf", "--no-telemetry", NULL };
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

    // Stage 6c, with the SYN proxy still off
    scenario_minimal_syn();

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

    // Stage 8b in spoofed mode, and the flows of spoofed SYNs
    scenario_spoofed_planted();
    scenario_spoofed_legit();
    scenario_spoofed_unproxied();
    scenario_spoofed_server_opens();
    scenario_spoofed_server_first();

    // IPv6 (the policy set above): Stage 8b, and the per-IP slot lookup
    scenario_ipv6_spoofed();
    scenario_ipv6_per_ip_slot();

    // The close of a challenged connection, blind RSTs, and a legitimate
    // source. The last raises the SYN rate above 10 times the challenge
    // threshold, so it runs after every scenario whose SYN must not be
    // challenged.
    scenario_proxy_close(CLIENT_FIRST, 1);
    scenario_proxy_close(SERVER_FIRST, 2);
    scenario_proxy_close(CLIENT_RST, 3);
    scenario_proxy_blind_rst();
    scenario_legitimate_source();

    // Stage 11 with a full flow table, and a stalled reader (clears the
    // table, so it runs last)
    scenario_stalled_reader_new_sources();

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
