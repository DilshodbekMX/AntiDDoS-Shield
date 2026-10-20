/**
 * @file test_hll_accuracy.c
 * @brief Accuracy of every HyperLogLog the engine feeds, through the engine's own
 *        key and hash path, for 1 to 10^6 distinct keys, random and sequential.
 *
 * HLL users covered:
 *   - per-IP IPv4 slot: per_ip_hll_cms_update() with the parser's flow hash
 *     (extract_flow_key + compute_flow_hash, see parser_flow_hash()), read
 *     back by per_ip_features_snapshot() as unique_src_ips, unique_src_ports,
 *     unique_dst_ports and unique_flows;
 *   - per-IP IPv6 slot: per_ip_hll_cms_v6_update() with the key Stage 3c passes
 *     (rte_hash_crc of the source, layer1.c), read by per_ip_features_v6_snapshot();
 *     random and sequential sources, and source sets shaped like address plans
 *     (many /64s, the subnets of a /48, EUI-64 interface IDs, random prefixes, 6to4),
 *     read from the 2-byte aligned offset where Stage 3c finds the source;
 *   - protected-subnet slot: the slot keyed by the subnet network, fed with packets
 *     to many addresses inside the subnet;
 *   - global source-IP HLL: hll_global_add_src_ip() / hll_global_src_ip_count(), the
 *     aggregate unique_src_ips.
 *
 * Window roll: per_ip_features_reset_window() and per_ip_features_v6_reset_window()
 * start a new window, so after a roll unique_* counts the new window's keys only.
 *
 * Bound per checkpoint (log-spaced, 10 per decade): |estimate - n| at most
 * 4 x 1.04/sqrt(m) x n (about 3.25%), and inside the linear-counting range
 * (n <= 2.5 m) also at most 4 linear-counting standard deviations
 * sqrt(m (e^(n/m) - n/m - 1)); 2 more counts absorb the discreteness of tiny n.
 *
 * Requires DPDK EAL (rte_hash / rte_malloc / rte_lpm) and runs with --no-huge
 * --no-shconf like the other per-module tests; exits 77 (skip) if EAL cannot init.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <netinet/in.h>

#include <rte_eal.h>
#include <rte_byteorder.h>
#include <rte_hash_crc.h>

#include "../../common/types.h"
#include "../../layer1/datapath/packet_parser.h"
#include "../../layer1/tables/ip_lists.h"
#include "../../layer1/telemetry/hyperloglog.h"
#include "../../layer1/telemetry/per_ip_features.h"
#include "../../layer1/telemetry/per_ip_features_v6.h"

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
} while(0)

#define TEST_ASSERT_EQ(expected, actual, msg) do { \
    if ((expected) != (actual)) { \
        printf("  FAIL: %s (expected=%ld, actual=%ld, line %d)\n", msg, \
               (long)(expected), (long)(actual), __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define RUN_TEST(test_func) do { \
    printf("Running %s...\n", #test_func); \
    tests_run++; \
    int before = tests_failed; \
    test_func(); \
    if (tests_failed == before) { tests_passed++; printf("  PASS\n"); } \
} while(0)

// ==================== Keys ====================

#define HOST_IP(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))
#define BE_IP(a, b, c, d) rte_cpu_to_be_32(HOST_IP(a, b, c, d))

#define MAX_KEYS   1000000u
#define PORT_SPACE 65536u

enum key_mode { KEYS_RANDOM, KEYS_SEQUENTIAL };

static const char *mode_name(enum key_mode mode) {
    return mode == KEYS_RANDOM ? "random" : "sequential";
}

// Bijections (distinct inputs give distinct outputs), so "random" keys are still
// guaranteed distinct. Neither is the finalizer hll_add() uses.
static uint32_t perm32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

static uint64_t perm64(uint64_t x) {
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

// Random order of all 65536 ports, so a port key repeats only after every port
static uint16_t g_port_perm[PORT_SPACE];

static void init_port_perm(uint64_t seed) {
    for (uint32_t i = 0; i < PORT_SPACE; i++) {
        g_port_perm[i] = (uint16_t)i;
    }
    uint64_t s = seed;
    for (uint32_t i = PORT_SPACE - 1; i > 0; i--) {
        s += 0x9e3779b97f4a7c15ULL;
        uint32_t j = (uint32_t)(perm64(s) % (i + 1));
        uint16_t t = g_port_perm[i];
        g_port_perm[i] = g_port_perm[j];
        g_port_perm[j] = t;
    }
}

// Source IPv4 for key k (network byte order): random 32-bit values, or
// consecutive addresses from 10.0.0.1
static uint32_t src_ip_key(enum key_mode mode, uint32_t k) {
    if (mode == KEYS_RANDOM) {
        return perm32(k ^ 0x5bd1e995U);
    }
    return rte_cpu_to_be_32(HOST_IP(10, 0, 0, 1) + k);
}

static uint16_t port_key(enum key_mode mode, uint32_t k) {
    if (mode == KEYS_RANDOM) {
        return g_port_perm[k % PORT_SPACE];
    }
    return (uint16_t)(k % PORT_SPACE);
}

static void put_be64(uint8_t out[8], uint64_t v) {
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(v >> (56 - 8 * i));
    }
}

// Source IPv6 for key k: random 128-bit values, or 2001:db8::/64 + k
static void src_ip6_key(enum key_mode mode, uint32_t k, uint8_t out[16]) {
    uint64_t hi, lo;
    if (mode == KEYS_RANDOM) {
        hi = perm64((uint64_t)k + 0x2545f4914f6cdd1dULL);
        lo = perm64((uint64_t)k);
    } else {
        hi = 0x20010db800000000ULL;
        lo = (uint64_t)k;
    }
    put_be64(out, hi);
    put_be64(out + 8, lo);
}

static void src_ip6_random(uint32_t k, uint8_t out[16]) {
    src_ip6_key(KEYS_RANDOM, k, out);
}

static void src_ip6_sequential(uint32_t k, uint8_t out[16]) {
    src_ip6_key(KEYS_SEQUENTIAL, k, out);
}

// Source sets shaped like IPv6 address plans, 2^20 distinct sources each (k below
// 2^20 gives distinct addresses by construction). Prefix and interface ID vary
// together, which is where a key that cancels prefix bits against IID bits loses
// sources.

// 256 /64s 2001:db8:0:N::/64 (the last prefix byte) x hosts ::0 to ::fff
static void src_ip6_prefix_x_hosts(uint32_t k, uint8_t out[16]) {
    put_be64(out, 0x20010db800000000ULL | (k & 0xff));
    put_be64(out + 8, k >> 8);
}

// The 4096 /64 subnets of 2001:db8:1::/48 (subnet ID 0 to 0xfff) x hosts ::0 to ::ff
static void src_ip6_subnets48_x_hosts(uint32_t k, uint8_t out[16]) {
    put_be64(out, 0x20010db800010000ULL | (k & 0xfff));
    put_be64(out + 8, k >> 12);
}

// 16 /64s x modified EUI-64 interface IDs of 65536 MACs 00:1b:21:00:xx:xx
static void src_ip6_eui64(uint32_t k, uint8_t out[16]) {
    put_be64(out, 0x20010db800000000ULL | (k & 0xf));
    put_be64(out + 8, 0x021b21fffe000000ULL | (k >> 4));
}

// 256 /64s (the last prefix byte) x random interface IDs
static void src_ip6_prefix_x_random_iid(uint32_t k, uint8_t out[16]) {
    put_be64(out, 0x20010db800000000ULL | (k & 0xff));
    put_be64(out + 8, perm64((uint64_t)k ^ 0x3c6ef372fe94f82bULL));
}

// 262144 random /64 prefixes x hosts ::1 to ::4
static void src_ip6_random_prefix_x_hosts(uint32_t k, uint8_t out[16]) {
    put_be64(out, perm64((uint64_t)(k >> 2) + 0x6a09e667f3bcc909ULL));
    put_be64(out + 8, 1 + (k & 3));
}

// 6to4: 2002:V4ADDR::1 for consecutive IPv4 addresses from 11.0.0.0
static void src_ip6_6to4(uint32_t k, uint8_t out[16]) {
    put_be64(out, 0x2002000000000000ULL | ((uint64_t)(HOST_IP(11, 0, 0, 0) + k) << 16));
    put_be64(out + 8, 1);
}

// Stage 3c hands per_ip_hll_cms_v6_update() the source address inside the frame:
// Ethernet (14 bytes) plus 8 bytes of the IPv6 header, so it is only 2-byte aligned
#define V6_SRC_FRAME_OFFSET 22
static uint8_t g_v6_frame[64] __attribute__((aligned(64)));

// The flow hash parse_packet() computes: compute_flow_hash() of the canonical
// 12-byte key (ip_lo, ip_hi, protocol, 3 zero bytes), the CRC32-C (seed 0) of
// that key. test_packet_parser pins that value, also with the key on the stack
// and the hash inlined, which link-time inlining can also do here.
static uint32_t parser_flow_hash(uint32_t src_be, uint32_t dst_be, uint8_t proto) {
    struct packet_features f;
    struct flow_key key;
    memset(&f, 0, sizeof(f));
    f.src_ip = src_be;
    f.dst_ip = dst_be;
    f.protocol = proto;
    extract_flow_key(&f, &key);
    return compute_flow_hash(&key);
}

// ==================== Exact distinct count of 32-bit flow hashes ====================

// Distinct keys give distinct addresses but can share a 32-bit flow hash, and the
// HLL can only count distinct hashes, so the truth for unique_flows is counted.
#define SET_SLOTS (1u << 21)

static uint64_t *g_set;
static uint32_t g_set_count;

static int set_reset(void) {
    if (!g_set) {
        g_set = calloc(SET_SLOTS, sizeof(*g_set));
        if (!g_set) return -1;
    } else {
        memset(g_set, 0, SET_SLOTS * sizeof(*g_set));
    }
    g_set_count = 0;
    return 0;
}

static void set_insert(uint32_t v) {
    uint64_t tagged = (1ULL << 32) | v;  // 0 marks an empty slot
    uint32_t i = perm32(v) & (SET_SLOTS - 1);
    while (g_set[i] != 0) {
        if (g_set[i] == tagged) return;
        i = (i + 1) & (SET_SLOTS - 1);
    }
    g_set[i] = tagged;
    g_set_count++;
}

// ==================== Checkpoints and bound ====================

#define MAX_CHECKPOINTS 64

static uint32_t g_checkpoints[MAX_CHECKPOINTS];
static uint32_t g_num_checkpoints;

// round(10^(i/10)) for i = 0..60, without repeats: 1, 2, 3, 4, 5, 6, 8, 10, 13, ...
static void init_checkpoints(void) {
    g_num_checkpoints = 0;
    for (int i = 0; i <= 60 && g_num_checkpoints < MAX_CHECKPOINTS; i++) {
        uint32_t n = (uint32_t)llround(pow(10.0, i / 10.0));
        if (n > MAX_KEYS) break;
        if (g_num_checkpoints == 0 || n != g_checkpoints[g_num_checkpoints - 1]) {
            g_checkpoints[g_num_checkpoints++] = n;
        }
    }
}

static double allowed_error(double n) {
    const double m = (double)HLL_REGISTERS;
    double tol = 4.0 * hll_standard_error() * n;
    if (n <= 2.5 * m) {
        double t = n / m;
        double lc = 4.0 * sqrt(m * (expm1(t) - t));
        if (lc < tol) tol = lc;
    }
    return tol + 2.0;
}

// Worst error seen for one HLL in one run, for the summary line
struct err_track {
    const char *name;
    double worst_rel;       // above the linear-counting range
    uint32_t worst_rel_n;
    double worst_abs;       // inside the linear-counting range
    uint32_t worst_abs_n;
};

// 0 when within the bound; otherwise prints the failing checkpoint and returns -1
static int check_estimate(struct err_track *t, const char *mode,
                          uint64_t truth, uint64_t estimate) {
    double err = fabs((double)estimate - (double)truth);
    double allowed = allowed_error((double)truth);
    if ((double)truth <= 2.5 * HLL_REGISTERS) {
        if (err > t->worst_abs) { t->worst_abs = err; t->worst_abs_n = (uint32_t)truth; }
    } else {
        double rel = err / (double)truth;
        if (rel > t->worst_rel) { t->worst_rel = rel; t->worst_rel_n = (uint32_t)truth; }
    }
    if (err > allowed) {
        printf("  %s (%s keys): n=%lu estimate=%lu |error|=%.0f (%.2f%%) allowed=%.1f\n",
               t->name, mode, (unsigned long)truth, (unsigned long)estimate, err,
               100.0 * err / (double)truth, allowed);
        return -1;
    }
    return 0;
}

static void print_track(const struct err_track *t, const char *mode) {
    printf("    %-16s %-10s worst |error| %5.0f in n<=2.5m (n=%u), worst %5.2f%% above (n=%u)\n",
           t->name, mode, t->worst_abs, t->worst_abs_n, 100.0 * t->worst_rel, t->worst_rel_n);
}

// ==================== Tests ====================

// Registers must hold rho of the 50 bits left after the index (1 to 51): with
// random keys about half of the touched registers are 1.
static void test_hll_register_values(void) {
    static struct hyperloglog hll;
    hll_init(&hll);
    for (uint32_t k = 0; k < 1000; k++) {
        hll_add_ip(&hll, src_ip_key(KEYS_RANDOM, k));
    }

    uint32_t touched = 0, ones = 0, low = 0;
    uint8_t max_reg = 0;
    for (uint32_t i = 0; i < HLL_REGISTERS; i++) {
        uint8_t r = hll.registers[i];
        if (r == 0) continue;
        touched++;
        if (r == 1) ones++;
        if (r <= HLL_P) low++;
        if (r > max_reg) max_reg = r;
    }
    printf("    1000 keys: touched=%u, value 1: %u, values 1..%d: %u, max=%u\n",
           touched, ones, HLL_P, low, max_reg);
    TEST_ASSERT(touched > 900, "1000 random keys touch most of their registers");
    TEST_ASSERT(max_reg <= 64 - HLL_P + 1, "a register never exceeds 64 - p + 1");
    TEST_ASSERT(ones > touched / 4, "about half of the touched registers hold rho 1");
    TEST_ASSERT(low > touched / 2, "most touched registers hold a rho of at most p");
}

static void run_per_ip_v4(enum key_mode mode, uint32_t dst_be) {
    const char *mname = mode_name(mode);
    TEST_ASSERT_EQ(0, per_ip_features_register(dst_be), "register v4 slot");
    struct per_ip_features *pif = per_ip_features_lookup(dst_be);
    TEST_ASSERT(pif != NULL, "lookup v4 slot");
    TEST_ASSERT_EQ(0, set_reset(), "allocate flow-hash set");

    struct err_track t_src = { "unique_src_ips", 0, 0, 0, 0 };
    struct err_track t_sport = { "unique_src_ports", 0, 0, 0, 0 };
    struct err_track t_dport = { "unique_dst_ports", 0, 0, 0, 0 };
    struct err_track t_flows = { "unique_flows", 0, 0, 0, 0 };
    int bad = 0;
    uint32_t k = 0;

    for (uint32_t c = 0; c < g_num_checkpoints && !bad; c++) {
        uint32_t n = g_checkpoints[c];
        for (; k < n; k++) {
            uint32_t src = src_ip_key(mode, k);
            uint32_t fh = parser_flow_hash(src, dst_be, IPPROTO_TCP);
            per_ip_hll_cms_update(pif, src, port_key(mode, k), port_key(mode, k + 7), fh);
            set_insert(fh);
        }
        struct per_ip_feature_snapshot snap;
        TEST_ASSERT_EQ(0, per_ip_features_snapshot(dst_be, &snap), "v4 snapshot");
        uint64_t ports = n < PORT_SPACE ? n : PORT_SPACE;
        bad |= check_estimate(&t_src, mname, n, snap.unique_src_ips);
        bad |= check_estimate(&t_sport, mname, ports, snap.unique_src_ports);
        bad |= check_estimate(&t_dport, mname, ports, snap.unique_dst_ports);
        bad |= check_estimate(&t_flows, mname, g_set_count, snap.unique_flows);
    }
    print_track(&t_src, mname);
    print_track(&t_sport, mname);
    print_track(&t_dport, mname);
    print_track(&t_flows, mname);
    TEST_ASSERT(!bad, "per-IP v4 HLL estimates within the bound");
}

static void test_hll_per_ip_v4_random(void) {
    run_per_ip_v4(KEYS_RANDOM, BE_IP(192, 168, 10, 1));
}

static void test_hll_per_ip_v4_sequential(void) {
    run_per_ip_v4(KEYS_SEQUENTIAL, BE_IP(192, 168, 10, 2));
}

// Sources from source(k); ports in port_mode. mname labels the failing checkpoint.
static void run_per_ip_v6(const char *mname, void (*source)(uint32_t k, uint8_t out[16]),
                          enum key_mode port_mode, uint8_t last_byte) {
    uint8_t dst6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0xaa,
                         0, 0, 0, 0, 0, 0, 0, last_byte };
    TEST_ASSERT_EQ(0, per_ip_features_v6_register(dst6), "register v6 slot");
    struct per_ip_features_v6 *pif = per_ip_features_v6_lookup(dst6);
    TEST_ASSERT(pif != NULL, "lookup v6 slot");
    TEST_ASSERT_EQ(0, set_reset(), "allocate flow-hash set");

    struct err_track t_src = { "unique_src_ips", 0, 0, 0, 0 };
    struct err_track t_sport = { "unique_src_ports", 0, 0, 0, 0 };
    struct err_track t_dport = { "unique_dst_ports", 0, 0, 0, 0 };
    struct err_track t_flows = { "unique_flows", 0, 0, 0, 0 };
    uint8_t *src6_in_frame = g_v6_frame + V6_SRC_FRAME_OFFSET;
    int bad = 0;
    uint32_t k = 0;

    for (uint32_t c = 0; c < g_num_checkpoints && !bad; c++) {
        uint32_t n = g_checkpoints[c];
        for (; k < n; k++) {
            uint8_t src6[16] __attribute__((aligned(8)));
            source(k, src6);
            // Stage 3c passes this source hash as the flow key (layer1.c). Hashed
            // from the aligned copy: rte_hash_crc() itself loads 8 bytes at a time.
            uint32_t src_v6_hash = rte_hash_crc(src6, 16, 0x5a6b7c8d);
            memcpy(src6_in_frame, src6, 16);
            per_ip_hll_cms_v6_update(pif, src6_in_frame, port_key(port_mode, k),
                                     port_key(port_mode, k + 7), src_v6_hash);
            set_insert(src_v6_hash);
        }
        struct per_ip_feature_snapshot_v6 snap;
        TEST_ASSERT_EQ(0, per_ip_features_v6_snapshot(dst6, &snap), "v6 snapshot");
        uint64_t ports = n < PORT_SPACE ? n : PORT_SPACE;
        bad |= check_estimate(&t_src, mname, n, snap.unique_src_ips);
        bad |= check_estimate(&t_sport, mname, ports, snap.unique_src_ports);
        bad |= check_estimate(&t_dport, mname, ports, snap.unique_dst_ports);
        bad |= check_estimate(&t_flows, mname, g_set_count, snap.unique_flows);
    }
    print_track(&t_src, mname);
    print_track(&t_sport, mname);
    print_track(&t_dport, mname);
    print_track(&t_flows, mname);
    TEST_ASSERT(!bad, "per-IP v6 HLL estimates within the bound");
}

static void test_hll_per_ip_v6_random(void) {
    run_per_ip_v6(mode_name(KEYS_RANDOM), src_ip6_random, KEYS_RANDOM, 0x01);
}

static void test_hll_per_ip_v6_sequential(void) {
    run_per_ip_v6(mode_name(KEYS_SEQUENTIAL), src_ip6_sequential, KEYS_SEQUENTIAL, 0x02);
}

// Address-plan shapes: distinct sources whose prefix and interface ID both vary
// must stay distinct keys, so unique_src_ips follows the truth
static void test_hll_per_ip_v6_prefixes_x_hosts(void) {
    run_per_ip_v6("256 /64s x hosts", src_ip6_prefix_x_hosts, KEYS_RANDOM, 0x03);
}

static void test_hll_per_ip_v6_subnets48_x_hosts(void) {
    run_per_ip_v6("/48 subnets x hosts", src_ip6_subnets48_x_hosts, KEYS_RANDOM, 0x04);
}

static void test_hll_per_ip_v6_eui64(void) {
    run_per_ip_v6("EUI-64 IIDs", src_ip6_eui64, KEYS_RANDOM, 0x05);
}

static void test_hll_per_ip_v6_prefixes_x_random_iid(void) {
    run_per_ip_v6("256 /64s x random IIDs", src_ip6_prefix_x_random_iid, KEYS_RANDOM, 0x06);
}

static void test_hll_per_ip_v6_random_prefixes_x_hosts(void) {
    run_per_ip_v6("random /64s x hosts", src_ip6_random_prefix_x_hosts, KEYS_RANDOM, 0x07);
}

static void test_hll_per_ip_v6_6to4(void) {
    run_per_ip_v6("6to4", src_ip6_6to4, KEYS_RANDOM, 0x08);
}

// A protected /24 aggregates every address in it into one slot keyed by the
// network; its HLLs see the union of sources and flows across the subnet.
static void run_subnet_slot(enum key_mode mode, uint8_t third_octet) {
    const char *mname = mode_name(mode);
    TEST_ASSERT_EQ(0, ip_protected_subnet_add(HOST_IP(10, 9, third_octet, 0), 24),
                   "add protected subnet");
    const uint32_t net_be = BE_IP(10, 9, third_octet, 0);
    struct per_ip_features *pif = per_ip_features_lookup(net_be);
    TEST_ASSERT(pif != NULL, "the subnet registered its slot");
    uint32_t net_check = 0;
    TEST_ASSERT(ip_protected_subnet_lookup(BE_IP(10, 9, third_octet, 77), &net_check),
                "an address inside the subnet hits it");
    TEST_ASSERT_EQ(net_be, net_check, "the hit returns the slot key");
    TEST_ASSERT_EQ(0, set_reset(), "allocate flow-hash set");

    struct err_track t_src = { "unique_src_ips", 0, 0, 0, 0 };
    struct err_track t_dport = { "unique_dst_ports", 0, 0, 0, 0 };
    struct err_track t_flows = { "unique_flows", 0, 0, 0, 0 };
    int bad = 0;
    uint32_t k = 0;

    for (uint32_t c = 0; c < g_num_checkpoints && !bad; c++) {
        uint32_t n = g_checkpoints[c];
        for (; k < n; k++) {
            uint32_t src = src_ip_key(mode, k);
            uint32_t dst = BE_IP(10, 9, third_octet, 1 + k % 254);
            uint32_t fh = parser_flow_hash(src, dst, IPPROTO_UDP);
            per_ip_hll_cms_update(pif, src, 53, port_key(mode, k), fh);
            set_insert(fh);
        }
        struct per_ip_feature_snapshot snap;
        TEST_ASSERT_EQ(0, per_ip_features_snapshot(net_be, &snap), "subnet snapshot");
        uint64_t ports = n < PORT_SPACE ? n : PORT_SPACE;
        bad |= check_estimate(&t_src, mname, n, snap.unique_src_ips);
        bad |= check_estimate(&t_dport, mname, ports, snap.unique_dst_ports);
        bad |= check_estimate(&t_flows, mname, g_set_count, snap.unique_flows);
    }
    print_track(&t_src, mname);
    print_track(&t_dport, mname);
    print_track(&t_flows, mname);
    TEST_ASSERT(!bad, "subnet slot HLL estimates within the bound");
}

static void test_hll_subnet_slot_random(void) {
    run_subnet_slot(KEYS_RANDOM, 1);
}

static void test_hll_subnet_slot_sequential(void) {
    run_subnet_slot(KEYS_SEQUENTIAL, 2);
}

static void run_global(enum key_mode mode) {
    const char *mname = mode_name(mode);
    // One hour window: no rotation while the test runs
    TEST_ASSERT_EQ(0, hll_global_init(3600), "global HLL init");

    struct err_track t_src = { "global src IPs", 0, 0, 0, 0 };
    int bad = 0;
    uint32_t k = 0;

    for (uint32_t c = 0; c < g_num_checkpoints && !bad; c++) {
        uint32_t n = g_checkpoints[c];
        for (; k < n; k++) {
            hll_global_add_src_ip(src_ip_key(mode, k));
        }
        bad |= check_estimate(&t_src, mname, n, hll_global_src_ip_count());
    }
    hll_global_cleanup();
    print_track(&t_src, mname);
    TEST_ASSERT(!bad, "global source-IP HLL estimate within the bound");
}

static void test_hll_global_random(void) {
    run_global(KEYS_RANDOM);
}

static void test_hll_global_sequential(void) {
    run_global(KEYS_SEQUENTIAL);
}

// ==================== Window roll ====================

// Window 1 feeds keys 0 to 19999, window 2 keys 20000 to 24999. Ports come from
// distinct positions of the permutation, so each window's ports are distinct too.
#define WIN1_KEYS 20000u
#define WIN2_KEYS 5000u

// After a roll unique_* must count the new window's keys only
static int check_window(const char *family, int w, uint32_t keys, uint32_t flow_hashes,
                        uint32_t src, uint32_t sport, uint32_t dport, uint32_t flows) {
    char mode[32];
    snprintf(mode, sizeof(mode), "%s window %d", family, w + 1);
    printf("    %s: %u keys -> unique_src_ips %u, unique_src_ports %u, "
           "unique_dst_ports %u, unique_flows %u (%u flow hashes)\n",
           mode, keys, src, sport, dport, flows, flow_hashes);
    struct err_track t = { "unique_src_ips", 0, 0, 0, 0 };
    int bad = check_estimate(&t, mode, keys, src);
    t.name = "unique_src_ports";
    bad |= check_estimate(&t, mode, keys, sport);
    t.name = "unique_dst_ports";
    bad |= check_estimate(&t, mode, keys, dport);
    t.name = "unique_flows";
    bad |= check_estimate(&t, mode, flow_hashes, flows);
    return bad;
}

// Control: the IPv4 roll, per_ip_features_reset_window()
static void test_hll_per_ip_v4_window_reset(void) {
    const uint32_t dst_be = BE_IP(192, 168, 10, 3);
    TEST_ASSERT_EQ(0, per_ip_features_register(dst_be), "register v4 slot");
    struct per_ip_features *pif = per_ip_features_lookup(dst_be);
    TEST_ASSERT(pif != NULL, "lookup v4 slot");

    struct per_ip_feature_snapshot snap[2];
    int bad = 0;
    uint32_t k = 0;
    for (int w = 0; w < 2; w++) {
        uint32_t keys = (w == 0) ? WIN1_KEYS : WIN2_KEYS;
        TEST_ASSERT_EQ(0, set_reset(), "allocate flow-hash set");
        for (uint32_t end = k + keys; k < end; k++) {
            uint32_t src = src_ip_key(KEYS_RANDOM, k);
            uint32_t fh = parser_flow_hash(src, dst_be, IPPROTO_TCP);
            per_ip_hll_cms_update(pif, src, port_key(KEYS_RANDOM, k),
                                  port_key(KEYS_RANDOM, k + 7), fh);
            set_insert(fh);
        }
        TEST_ASSERT_EQ(0, per_ip_features_snapshot(dst_be, &snap[w]), "v4 snapshot");
        bad |= check_window("v4", w, keys, g_set_count, snap[w].unique_src_ips,
                            snap[w].unique_src_ports, snap[w].unique_dst_ports,
                            snap[w].unique_flows);
        if (w == 0) {
            per_ip_features_reset_window(pif);
        }
    }
    TEST_ASSERT(!bad, "after the v4 window roll unique_* counts the new window only");
    TEST_ASSERT_EQ((int32_t)snap[1].unique_src_ips - (int32_t)snap[0].unique_src_ips,
                   snap[1].src_ip_churn, "src_ip_churn compares the two windows");
    TEST_ASSERT_EQ((int32_t)snap[1].unique_dst_ports - (int32_t)snap[0].unique_dst_ports,
                   snap[1].dst_port_churn, "dst_port_churn compares the two windows");
}

// The IPv6 roll, per_ip_features_v6_reset_window(), must do the same
static void test_hll_per_ip_v6_window_reset(void) {
    uint8_t dst6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0xaa,
                         0, 0, 0, 0, 0, 0, 0, 0x09 };
    TEST_ASSERT_EQ(0, per_ip_features_v6_register(dst6), "register v6 slot");
    struct per_ip_features_v6 *pif = per_ip_features_v6_lookup(dst6);
    TEST_ASSERT(pif != NULL, "lookup v6 slot");

    struct per_ip_feature_snapshot_v6 snap[2];
    uint8_t *src6_in_frame = g_v6_frame + V6_SRC_FRAME_OFFSET;
    int bad = 0;
    uint32_t k = 0;
    for (int w = 0; w < 2; w++) {
        uint32_t keys = (w == 0) ? WIN1_KEYS : WIN2_KEYS;
        TEST_ASSERT_EQ(0, set_reset(), "allocate flow-hash set");
        for (uint32_t end = k + keys; k < end; k++) {
            uint8_t src6[16] __attribute__((aligned(8)));
            src_ip6_key(KEYS_RANDOM, k, src6);
            uint32_t src_v6_hash = rte_hash_crc(src6, 16, 0x5a6b7c8d);
            memcpy(src6_in_frame, src6, 16);
            per_ip_hll_cms_v6_update(pif, src6_in_frame, port_key(KEYS_RANDOM, k),
                                     port_key(KEYS_RANDOM, k + 7), src_v6_hash);
            set_insert(src_v6_hash);
        }
        TEST_ASSERT_EQ(0, per_ip_features_v6_snapshot(dst6, &snap[w]), "v6 snapshot");
        bad |= check_window("v6", w, keys, g_set_count, snap[w].unique_src_ips,
                            snap[w].unique_src_ports, snap[w].unique_dst_ports,
                            snap[w].unique_flows);
        if (w == 0) {
            per_ip_features_v6_reset_window(pif);
        }
    }
    TEST_ASSERT(!bad, "after the v6 window roll unique_* counts the new window only");
    TEST_ASSERT_EQ((int32_t)snap[1].unique_src_ips - (int32_t)snap[0].unique_src_ips,
                   snap[1].src_ip_churn, "src_ip_churn compares the two windows");
    TEST_ASSERT_EQ((int32_t)snap[1].unique_dst_ports - (int32_t)snap[0].unique_dst_ports,
                   snap[1].dst_port_churn, "dst_port_churn compares the two windows");
}

// ==================== Main ====================

int main(int argc, char **argv) {
    (void)argc;
    setvbuf(stdout, NULL, _IOLBF, 0);  // keep line order with the EAL / RTE_LOG output
    char *eal_args[] = { argv[0], "-l", "0", "-n", "1", "--no-huge", "--no-pci",
                         "-m", "256", "--no-shconf", "--no-telemetry", NULL };
    if (rte_eal_init((int)RTE_DIM(eal_args) - 1, eal_args) < 0) {
        fprintf(stderr, "EAL init failed (missing DPDK permissions or runtime directory), skipping test\n");
        return 77;
    }

    struct ip_lists_config cfg = {
        .max_whitelist_entries = 64,
        .max_blacklist_entries = 64,
        .max_protected_entries = 64,
        .max_whitelist_cidrs = 16,
        .enforce_protected_ips = false,
    };
    if (per_ip_features_init(16) < 0 || per_ip_features_v6_init(16) < 0 ||
        ip_lists_init(&cfg) < 0) {
        fprintf(stderr, "per-IP features / IP lists init failed\n");
        return 1;
    }

    init_port_perm(0x0123456789abcdefULL);
    init_checkpoints();
    printf("HLL accuracy: %u checkpoints from 1 to %u keys, m=%d, bound 4 x %.4f\n\n",
           g_num_checkpoints, g_checkpoints[g_num_checkpoints - 1], HLL_REGISTERS,
           hll_standard_error());

    RUN_TEST(test_hll_register_values);
    RUN_TEST(test_hll_per_ip_v4_random);
    RUN_TEST(test_hll_per_ip_v4_sequential);
    RUN_TEST(test_hll_per_ip_v6_random);
    RUN_TEST(test_hll_per_ip_v6_sequential);
    RUN_TEST(test_hll_per_ip_v6_prefixes_x_hosts);
    RUN_TEST(test_hll_per_ip_v6_subnets48_x_hosts);
    RUN_TEST(test_hll_per_ip_v6_eui64);
    RUN_TEST(test_hll_per_ip_v6_prefixes_x_random_iid);
    RUN_TEST(test_hll_per_ip_v6_random_prefixes_x_hosts);
    RUN_TEST(test_hll_per_ip_v6_6to4);
    RUN_TEST(test_hll_subnet_slot_random);
    RUN_TEST(test_hll_subnet_slot_sequential);
    RUN_TEST(test_hll_global_random);
    RUN_TEST(test_hll_global_sequential);
    RUN_TEST(test_hll_per_ip_v4_window_reset);
    RUN_TEST(test_hll_per_ip_v6_window_reset);

    free(g_set);
    ip_lists_cleanup();
    per_ip_features_v6_cleanup();
    per_ip_features_cleanup();

    printf("\n========================================\n");
    printf("Tests run: %d, passed: %d, failed: %d\n", tests_run, tests_passed, tests_failed);
    printf("========================================\n");
    return tests_failed > 0 ? 1 : 0;
}
