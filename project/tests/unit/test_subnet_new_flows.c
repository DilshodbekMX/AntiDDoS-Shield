/**
 * @file test_subnet_new_flows.c
 * @brief Pipeline test: new flows to addresses covered only by a protected subnet are
 *        counted on the subnet's per-IP slot (flows_per_sec), through the real
 *        layer1_init() + layer1_process_packet_ex() path (Stage 3c and Stage 11).
 *
 * layer1_init() creates three files in /dev/shm (the POSIX shared memory segment, and
 * antiddos_realtime and antiddos_windows, both truncated on open) and a telemetry
 * database, so the test must never run it against the host's /dev/shm. This file
 * builds two tests:
 *
 * subnet_new_flows_tests (default build) moves into a private user + mount namespace
 * with its own tmpfs on /dev/shm and runs layer1_init() as built in liblayer1. It
 * exits 77 (skip) where unprivileged user namespaces or the mount are unavailable.
 *
 * subnet_new_flows_seam_tests (built with -DSUBNET_FLOWS_SEAM) needs no namespace, so
 * Stage 11's call site stays covered on such hosts. It compiles layer1.c into this
 * test with the three calls that create those files renamed: shared memory comes from
 * the private DPDK heap (shared_memory_init()) and the two telemetry segments report
 * failure, which layer1_init() continues past. Stage 3c, Stage 11 and every other
 * stage are layer1.c's own code. Where Landlock is available the pipeline process
 * also confines its writes to the temporary directory, so a future layer1_init()
 * that writes another host file is refused (EACCES) instead of writing it; if
 * layer1_init() continues past that failure, as it does for the two telemetry
 * segments, the test still passes. The test fails when a seam was not called or a
 * new /dev/shm/antiddos* entry is left at the end, which catches such a writer only
 * without Landlock and only if layer1_cleanup() does not remove its file.
 *
 * Both work in a fresh temporary directory (config, database, IP-list path, EAL
 * runtime directory). A child process runs the pipeline, ending with layer1_cleanup();
 * the parent removes the directory however the child exits. Both skip (77) if EAL
 * cannot initialise.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  // unshare(), CLONE_NEW*; the build also defines it
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <sched.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>

#ifdef SUBNET_FLOWS_SEAM
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#if defined(__has_include)
#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#endif
#endif

// layer1.c itself, with the three layer1_init() calls that create /dev/shm files
// renamed to the seam functions below
#define shared_memory_init_posix seam_shared_memory_init_posix
#define realtime_telemetry_init seam_realtime_telemetry_init
#define window_stats_init seam_window_stats_init
#include "../../layer1/layer1.c"
#undef shared_memory_init_posix
#undef realtime_telemetry_init
#undef window_stats_init

static int g_seam_calls[3];

// Shared memory in the private DPDK heap instead of /dev/shm/antiddos_layer1_shmem;
// same structure and size (POSIX_SHMEM_SIZE is its sizeof)
int seam_shared_memory_init_posix(void) {
    g_seam_calls[0]++;
    return shared_memory_init();
}

// No /dev/shm/antiddos_realtime: layer1_init() logs a warning and continues, and every
// realtime_telemetry_* call is a no-op while it is not initialised
int seam_realtime_telemetry_init(void) {
    g_seam_calls[1]++;
    return -1;
}

// No /dev/shm/antiddos_windows, the same way
int seam_window_stats_init(void) {
    g_seam_calls[2]++;
    return -1;
}
#endif  // SUBNET_FLOWS_SEAM

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

#include "../../layer1/layer1.h"
#include "../../layer1/tables/ip_lists.h"
#include "../../layer1/telemetry/per_ip_features.h"

#define TEST_SKIP 77

#define HOST_IP(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))
#define BE_IP(a, b, c, d) rte_cpu_to_be_32(HOST_IP(a, b, c, d))

static int tests_failed = 0;

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

#ifndef SUBNET_FLOWS_SEAM
static int write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t len = (ssize_t)strlen(text);
    ssize_t n = write(fd, text, (size_t)len);
    close(fd);
    return n == len ? 0 : -1;
}

// Private user + mount namespace with a tmpfs on /dev/shm. Must run before EAL
// starts threads. Returns 0, or -1 with the reason printed.
static int isolate_dev_shm(void) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    char map[64];

    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
        printf("unshare(CLONE_NEWUSER | CLONE_NEWNS) failed: %s\n", strerror(errno));
        return -1;
    }
    if (write_file("/proc/self/setgroups", "deny") != 0) {
        printf("writing /proc/self/setgroups failed: %s\n", strerror(errno));
        return -1;
    }
    snprintf(map, sizeof(map), "0 %u 1", (unsigned)uid);
    if (write_file("/proc/self/uid_map", map) != 0) {
        printf("writing uid_map failed: %s\n", strerror(errno));
        return -1;
    }
    snprintf(map, sizeof(map), "0 %u 1", (unsigned)gid);
    if (write_file("/proc/self/gid_map", map) != 0) {
        printf("writing gid_map failed: %s\n", strerror(errno));
        return -1;
    }
    // Keep every mount change inside this namespace
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        printf("making mounts private failed: %s\n", strerror(errno));
        return -1;
    }
    if (mount("none", "/dev/shm", "tmpfs", 0, NULL) != 0) {
        printf("mounting a private tmpfs on /dev/shm failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}
#else
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

// Confine this thread, and the threads it creates from now on, so that files can be
// written, created, truncated or removed only beneath dir (plus /proc for thread names
// and /dev/null). Reads are not restricted. Returns 0 when the kernel enforces it.
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

// Reports the entries that appeared since `before` and returns their count. It
// never removes one: an engine started on this host meanwhile owns its segments.
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
            printf("  FAIL: /dev/shm/%s appeared during the test; if layer1_init() created "
                   "it, it needs a seam (left in place)\n", now.name[i]);
            found++;
        }
    }
    return found;
}
#endif  // SUBNET_FLOWS_SEAM

// ==================== Temporary directory ====================

static int remove_entry(const char *path, const struct stat *sb, int type, struct FTW *ftw) {
    (void)sb;
    (void)type;
    (void)ftw;
    return remove(path);
}

// Everything under dir, then dir; never follows a symlink or leaves the filesystem
static int remove_tree(const char *dir) {
    return nftw(dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS | FTW_MOUNT);
}

// ==================== Packets ====================

// Ethernet / IPv4 / UDP datagram with a 32-byte payload to a port no L7 check covers
static struct rte_mbuf *udp_packet(struct rte_mempool *mp, uint32_t src_be, uint32_t dst_be,
                                   uint16_t sport, uint16_t dport) {
    const uint16_t payload = 32;
    const uint16_t len = (uint16_t)(sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                                    sizeof(struct rte_udp_hdr) + payload);
    struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
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
    ip->next_proto_id = IPPROTO_UDP;
    ip->total_length = rte_cpu_to_be_16((uint16_t)(len - sizeof(*eth)));
    ip->src_addr = src_be;
    ip->dst_addr = dst_be;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
    udp->src_port = rte_cpu_to_be_16(sport);
    udp->dst_port = rte_cpu_to_be_16(dport);
    udp->dgram_len = rte_cpu_to_be_16((uint16_t)(sizeof(*udp) + payload));
    udp->dgram_cksum = 0;  // no checksum (IPv4)
    memset(udp + 1, 0x41, payload);
    return m;
}

// ==================== Pipeline ====================

// Runs in the child process, inside dir. Every path after layer1_init() ends with
// layer1_cleanup(). Returns 0 (pass), 1 (fail) or TEST_SKIP.
static int run_pipeline(char *prog, const char *dir) {
    int rc = 1;
    bool layer1_up = false;
    struct rte_mempool *mp = NULL;

    if (chdir(dir) != 0) {
        printf("entering %s failed: %s\n", dir, strerror(errno));
        return 1;
    }
    // The config, the telemetry database and the relative IP-list path that
    // layer1_init() reads all live in dir
    char cfg_path[320], db_path[320];
    snprintf(cfg_path, sizeof(cfg_path), "%s/layer1_config.json", dir);
    snprintf(db_path, sizeof(db_path), "%s/l1_telemetry.db", dir);
    FILE *cf = fopen(cfg_path, "w");
    if (!cf) {
        printf("writing the config failed: %s\n", strerror(errno));
        return 1;
    }
    // Small tables (the shipped defaults need GBs); a 1 s export interval keeps
    // layer1_cleanup(), which joins the export thread, short
    fprintf(cf, "{ \"telemetry\": { \"db_path\": \"%s\", \"export_interval_sec\": 1 },\n"
                "  \"ip_lists\": { \"max_whitelist_entries\": 1024, \"max_blacklist_entries\": 1024,\n"
                "                \"max_protected_entries\": 64, \"max_whitelist_cidrs\": 64 },\n"
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

#ifdef SUBNET_FLOWS_SEAM
    // After EAL (whose threads stay unconfined), before anything of layer1 runs
    if (confine_writes(dir) == 0) {
        printf("Landlock: writes confined to %s\n", dir);
    } else {
        printf("Landlock unavailable: relying on the seams alone\n");
    }
#endif

    if (layer1_init(4096, cfg_path) < 0) {
        printf("layer1_init failed\n");
        goto out;
    }
    layer1_up = true;
#ifdef SUBNET_FLOWS_SEAM
    printf("layer1_init() without /dev/shm (seams):\n");
    CHECK_EQ(1, g_seam_calls[0], "shared memory came from the private heap");
    CHECK_EQ(1, g_seam_calls[1], "the realtime segment was skipped");
    CHECK_EQ(1, g_seam_calls[2], "the window segment was skipped");
#endif

    mp = rte_pktmbuf_pool_create("subnet_flows_pool", 255, 0, 0,
                                 RTE_MBUF_DEFAULT_BUF_SIZE, 0);
    if (!mp) {
        printf("mbuf pool creation failed\n");
        goto out;
    }

    // A protected /24 (one aggregate slot keyed by 10.0.7.0) with an exact /32 inside it
    if (ip_protected_subnet_add(HOST_IP(10, 0, 7, 0), 24) != 0 ||
        ip_protected_add(BE_IP(10, 0, 7, 50)) != 0) {
        printf("registering the protected subnet / exact IP failed\n");
        goto out;
    }
    const uint32_t net_be = BE_IP(10, 0, 7, 0);
    const uint32_t exact_be = BE_IP(10, 0, 7, 50);
    struct per_ip_features *s_net = per_ip_features_lookup(net_be);
    struct per_ip_features *s_exact = per_ip_features_lookup(exact_be);
    if (!s_net || !s_exact || s_net == s_exact) {
        printf("per-IP slots for the subnet / exact IP missing\n");
        goto out;
    }

    // Client-facing port 0 (default config): one new UDP flow to each of 40 addresses
    // covered only by the subnet, then one to the exact /32
    const uint32_t n_subnet = 40;
    uint32_t accepted = 0;
    for (uint32_t i = 0; i <= n_subnet; i++) {
        uint32_t dst = (i < n_subnet) ? BE_IP(10, 0, 7, 100 + i) : exact_be;
        struct rte_mbuf *m = udp_packet(mp, BE_IP(11, 1, 0, 1 + i), dst,
                                        (uint16_t)(40000 + i), 9999);
        if (!m) {
            printf("mbuf allocation failed\n");
            goto out;
        }
        struct layer1_result res;
        memset(&res, 0, sizeof(res));
        layer1_process_packet_ex(m, 0, 0, mp, &res);
        if (res.action == L1_ACTION_DROP) {
            printf("  packet %u dropped: %s\n", i, drop_reason_to_string(res.drop_reason));
        } else {
            accepted++;
        }
        rte_pktmbuf_free(m);
    }

    uint64_t rx = 0, new_flows = 0;
    for (unsigned l = 0; l < RTE_MAX_LCORE; l++) {
        rx += s_net->lcore_counters[l].rx_packets;
        new_flows += s_net->lcore_counters[l].new_flows;
    }
    // Fresh slots have no previous window, so the snapshot uses 1 s and
    // flows_per_sec equals the new flows counted
    struct per_ip_feature_snapshot snap_net, snap_exact;
    int rc_net = per_ip_features_snapshot(net_be, &snap_net);
    int rc_exact = per_ip_features_snapshot(exact_be, &snap_exact);

    printf("Subnet 10.0.7.0/24 slot after %u new flows through layer1_process_packet_ex():\n",
           n_subnet);
    CHECK_EQ(n_subnet + 1, accepted, "every packet accepted");
    CHECK_EQ(0, rc_net, "subnet snapshot");
    CHECK_EQ(0, rc_exact, "exact /32 snapshot");
    CHECK_EQ(n_subnet, rx, "Stage 3c counts the packets on the subnet slot");
    CHECK_EQ(n_subnet, new_flows, "Stage 11 counts their new flows on the same slot");
    CHECK_EQ(n_subnet, snap_net.flows_per_sec, "subnet flows_per_sec");
    CHECK_EQ(1, snap_exact.flows_per_sec, "the exact /32 keeps its own new flow");
    rc = tests_failed ? 1 : 0;
    if (tests_failed) {
        printf("\nFAIL: %d check(s) above failed\n", tests_failed);
    } else {
        printf("\nPASS: new flows to subnet-covered addresses are counted on the subnet slot\n");
    }

out:
    if (layer1_up) {
        layer1_cleanup();
    }
    if (mp) {
        rte_mempool_free(mp);
    }
    return rc;
}

// ==================== Main ====================

int main(int argc, char **argv) {
    (void)argc;
    setvbuf(stdout, NULL, _IOLBF, 0);

#ifndef SUBNET_FLOWS_SEAM
    if (isolate_dev_shm() != 0) {
        printf("No private /dev/shm, skipping test (layer1_init would write the host's)\n");
        return TEST_SKIP;
    }
#else
    printf("No namespace: layer1.c compiled in with the /dev/shm init calls renamed\n");
    struct shm_names shm_before;
    list_antiddos_shm(&shm_before);
#endif

    const char *tmp = getenv("TMPDIR");
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/l1_subnet_flows_XXXXXX", (tmp && tmp[0]) ? tmp : "/tmp");
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
#ifdef SUBNET_FLOWS_SEAM
    if (report_new_antiddos_shm(&shm_before) > 0) {
        rc = 1;
    }
#endif
    return rc;
}
