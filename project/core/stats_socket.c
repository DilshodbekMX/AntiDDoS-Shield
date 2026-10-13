#include "stats_socket.h"
#include "dpdk_core.h"
#include "shared_memory.h"
#include "system_monitor.h"
#include "../layer2/layer2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>

static pthread_t stats_thread;
static volatile bool stats_running = false;
static int server_fd = -1;
static int client_fd = -1;

static struct aggregated_stats prev_stats;
static uint64_t prev_timestamp = 0;

// System monitor send interval counter (send every 2 loops = 1 second)
#define SYSMON_SEND_INTERVAL 2
// Anomaly stats send interval (every 2 loops = 1 second)
#define ANOMALY_SEND_INTERVAL 2

static uint64_t get_timestamp_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int send_stats(void) {
    struct stats_packet pkt;
    struct aggregated_stats current_stats;
    uint64_t now = get_timestamp_ms();
    uint64_t time_delta = (prev_timestamp > 0) ? (now - prev_timestamp) : STATS_INTERVAL_MS;

    if (time_delta == 0) time_delta = 1;

    // Aggregate stats from all lcores
    aggregate_lcore_stats(&current_stats);

    // Initialize packet
    memset(&pkt, 0, sizeof(pkt));
    pkt.magic = STATS_MAGIC;
    pkt.timestamp_ms = now;
    pkt.port_count = 1;  // Report as single aggregated "port"

    // Fill aggregated stats into port 0
    pkt.ports[0].port_id = 0;
    pkt.ports[0].rx_packets = current_stats.rx_packets;
    pkt.ports[0].tx_packets = current_stats.tx_packets;
    pkt.ports[0].rx_bytes = current_stats.rx_bytes;
    pkt.ports[0].tx_bytes = current_stats.tx_bytes;
    pkt.ports[0].dropped = current_stats.dropped;

    // Calculate rates from aggregated stats
    uint64_t rx_diff = current_stats.rx_packets - prev_stats.rx_packets;
    uint64_t tx_diff = current_stats.tx_packets - prev_stats.tx_packets;
    uint64_t rx_bytes_diff = current_stats.rx_bytes - prev_stats.rx_bytes;
    uint64_t tx_bytes_diff = current_stats.tx_bytes - prev_stats.tx_bytes;

    pkt.ports[0].rx_pps = (rx_diff * 1000) / time_delta;
    pkt.ports[0].tx_pps = (tx_diff * 1000) / time_delta;
    pkt.ports[0].rx_bps = (rx_bytes_diff * 8 * 1000) / time_delta;
    pkt.ports[0].tx_bps = (tx_bytes_diff * 8 * 1000) / time_delta;

    // Save current stats for next rate calculation
    prev_stats = current_stats;

    pkt.length = sizeof(pkt);
    prev_timestamp = now;
    
    // Send to client
    if (client_fd >= 0) {
        ssize_t sent = send(client_fd, &pkt, sizeof(pkt), MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EPIPE || errno == ECONNRESET) {
                printf("[Stats] Client disconnected\n");
                close(client_fd);
                client_fd = -1;
            }
            return -1;
        }
    }
    
    return 0;
}

static int send_sysmon_stats(void) {
    struct sysmon_packet pkt;
    struct system_stats sys_stats;

    // Get current system stats
    system_monitor_get_stats(&sys_stats);

    // Initialize packet
    memset(&pkt, 0, sizeof(pkt));
    pkt.magic = SYSMON_MAGIC;
    pkt.length = sizeof(pkt);
    pkt.timestamp_ms = sys_stats.timestamp_ms;

    // DPDK lcore stats
    pkt.nb_lcores = sys_stats.dpdk.nb_lcores;
    pkt.avg_lcore_utilization = sys_stats.dpdk.avg_lcore_utilization;
    for (uint32_t i = 0; i < sys_stats.dpdk.nb_lcores && i < MAX_LCORE_STATS; i++) {
        pkt.lcore_stats[i].lcore_id = sys_stats.dpdk.lcore_stats[i].lcore_id;
        pkt.lcore_stats[i].is_active = sys_stats.dpdk.lcore_stats[i].is_active ? 1 : 0;
        pkt.lcore_stats[i].busy_cycles = sys_stats.dpdk.lcore_stats[i].busy_cycles;
        pkt.lcore_stats[i].idle_cycles = sys_stats.dpdk.lcore_stats[i].idle_cycles;
        pkt.lcore_stats[i].utilization_pct = sys_stats.dpdk.lcore_stats[i].utilization_pct;
    }

    // DPDK mempool stats
    pkt.nb_mempools = sys_stats.dpdk.nb_mempools;
    for (uint32_t i = 0; i < sys_stats.dpdk.nb_mempools && i < MAX_MEMPOOL_STATS; i++) {
        strncpy(pkt.mempool_stats[i].name, sys_stats.dpdk.mempool_stats[i].name, 31);
        pkt.mempool_stats[i].size = sys_stats.dpdk.mempool_stats[i].size;
        pkt.mempool_stats[i].avail_count = sys_stats.dpdk.mempool_stats[i].avail_count;
        pkt.mempool_stats[i].in_use_count = sys_stats.dpdk.mempool_stats[i].in_use_count;
        pkt.mempool_stats[i].usage_pct = sys_stats.dpdk.mempool_stats[i].usage_pct;
    }

    // DPDK hugepage stats
    pkt.hugepage_total_bytes = sys_stats.dpdk.hugepage_total_bytes;
    pkt.hugepage_used_bytes = sys_stats.dpdk.hugepage_used_bytes;
    pkt.hugepage_usage_pct = sys_stats.dpdk.hugepage_usage_pct;

    // System CPU stats
    pkt.nb_cpus = sys_stats.nb_cpus;
    pkt.avg_cpu_usage = sys_stats.avg_cpu_usage;
    for (uint32_t i = 0; i < sys_stats.nb_cpus && i < MAX_LCORE_STATS; i++) {
        pkt.cpu_stats[i].cpu_id = sys_stats.cpu_stats[i].cpu_id;
        pkt.cpu_stats[i].usage_pct = sys_stats.cpu_stats[i].usage_pct;
        pkt.cpu_stats[i].user_pct = sys_stats.cpu_stats[i].user_pct;
        pkt.cpu_stats[i].system_pct = sys_stats.cpu_stats[i].system_pct;
        pkt.cpu_stats[i].idle_pct = sys_stats.cpu_stats[i].idle_pct;
        pkt.cpu_stats[i].iowait_pct = sys_stats.cpu_stats[i].iowait_pct;
    }

    // System memory stats
    pkt.mem_total_bytes = sys_stats.memory.total_bytes;
    pkt.mem_free_bytes = sys_stats.memory.free_bytes;
    pkt.mem_available_bytes = sys_stats.memory.available_bytes;
    pkt.mem_used_bytes = sys_stats.memory.used_bytes;
    pkt.mem_usage_pct = sys_stats.memory.usage_pct;

    // Load average
    pkt.load_1min = sys_stats.load_1min;
    pkt.load_5min = sys_stats.load_5min;
    pkt.load_15min = sys_stats.load_15min;

    // Send to client
    if (client_fd >= 0) {
        ssize_t sent = send(client_fd, &pkt, sizeof(pkt), MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EPIPE || errno == ECONNRESET) {
                return -1;
            }
        }
    }

    return 0;
}

static int send_per_ip_features(void) {
    struct per_ip_features_packet pkt;

    // Initialize packet
    memset(&pkt, 0, sizeof(pkt));
    pkt.magic = PER_IP_FEATURES_MAGIC;
    pkt.length = sizeof(pkt);
    pkt.timestamp_ms = get_timestamp_ms();

    // Get per-IP features from shared memory
    struct l2_per_ip_export *per_ip = l2_per_ip_export_get();
    if (!per_ip) {
        return 0;  // No per-IP data available
    }

    // Seqlock read pattern
    uint64_t version_before = __atomic_load_n(&per_ip->version, __ATOMIC_ACQUIRE);
    if (version_before & 1) {
        return 0;  // Write in progress, skip this cycle
    }

    pkt.active_count = per_ip->active_count;

    // Copy active entries
    for (uint32_t i = 0; i < per_ip->active_count && i < MAX_PER_IP_EXPORT; i++) {
        const struct l2_per_ip_features_export *src = &per_ip->features[i];
        struct per_ip_features_entry *dst = &pkt.entries[i];

        if (!src->active) continue;

        dst->dst_ip = src->dst_ip;
        dst->active = src->active;
        dst->timestamp_ns = src->timestamp_ns;
        dst->packets_per_sec = src->packets_per_sec;
        dst->bytes_per_sec = src->bytes_per_sec;
        dst->flows_per_sec = src->flows_per_sec;
        dst->syn_per_sec = src->syn_per_sec;
        dst->syn_ack_per_sec = src->syn_ack_per_sec;
        dst->ack_per_sec = src->ack_per_sec;
        dst->rst_per_sec = src->rst_per_sec;
        dst->fin_per_sec = src->fin_per_sec;
        dst->tcp_ratio = src->tcp_ratio;
        dst->udp_ratio = src->udp_ratio;
        dst->icmp_ratio = src->icmp_ratio;
        dst->unique_src_ips = src->unique_src_ips;
        dst->unique_flows = src->unique_flows;
        dst->max_flow_fraction = src->max_flow_fraction;
        dst->topk_flow_share = src->topk_flow_share;
        dst->heavy_hitter_count = src->heavy_hitter_count;
        dst->avg_packets_per_flow = src->avg_packets_per_flow;
        dst->flow_duration_avg_ms = src->flow_duration_avg_ms;
        dst->total_packets = src->total_packets;
        dst->active_flows = src->active_flows;
    }

    // Check version consistency
    uint64_t version_after = __atomic_load_n(&per_ip->version, __ATOMIC_ACQUIRE);
    if (version_before != version_after) {
        return 0;  // Data changed during read, skip
    }

    // Send to client
    if (client_fd >= 0) {
        ssize_t sent = send(client_fd, &pkt, sizeof(pkt), MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EPIPE || errno == ECONNRESET) {
                return -1;
            }
        }
    }

    return 0;
}

static int send_anomaly_stats(void) {
    struct anomaly_packet pkt;

    // Initialize packet
    memset(&pkt, 0, sizeof(pkt));
    pkt.magic = ANOMALY_MAGIC;
    pkt.length = sizeof(pkt);
    pkt.timestamp_ms = get_timestamp_ms();

    // Get Layer 2 anomaly state
    if (layer2_is_initialized()) {
        struct l2_anomaly_state anomaly_state;
        layer2_get_anomaly_state(&anomaly_state);

        pkt.active = anomaly_state.active ? 1 : 0;
        pkt.level = (uint8_t)anomaly_state.level;
        pkt.tier_agreement = (uint8_t)anomaly_state.tier_agreement;
        pkt.max_z_score = anomaly_state.max_z_score;
        pkt.confidence = anomaly_state.confidence;
        pkt.primary_feature = anomaly_state.primary_feature_idx;
        pkt.start_time_ns = anomaly_state.start_time_ns;
        pkt.duration_sec = anomaly_state.duration_sec;
        pkt.cool_down_remaining = anomaly_state.cool_down_remaining_sec;
        pkt.detection_cycles = anomaly_state.cycle_count;
        pkt.detection_count = anomaly_state.detection_count;

        // Get baseline summary
        struct baseline_summary baseline_summary;
        layer2_get_baseline_summary(&baseline_summary);

        pkt.baselines_frozen = baseline_summary.any_frozen ? 1 : 0;
        pkt.tier1_ready = baseline_summary.tier1_ready ? 1 : 0;
        pkt.tier2_ready_count = (uint8_t)baseline_summary.tier2_ready_count;
        pkt.tier3_ready_count = (uint8_t)baseline_summary.tier3_ready_count;
        pkt.baseline_updates = baseline_summary.total_updates;

        // Get current stats
        struct layer2_stats l2_stats;
        layer2_get_stats(&l2_stats);
        pkt.detection_cycles = l2_stats.cycles;
        pkt.detection_count = l2_stats.detections;
    }

    // Get current features from shared memory
    struct l2_features_export *features = l2_features_export_get();
    if (features) {
        pkt.packets_per_sec = features->packets_per_sec;
        pkt.bytes_per_sec = features->bytes_per_sec;
        pkt.syn_per_sec = features->syn_per_sec;
        pkt.unique_src_ips = features->unique_src_ips;
        pkt.unique_flows = features->unique_flows;
        pkt.heavy_hitters = features->heavy_hitter_count;
    }

    // Get rate limit percentage
    pkt.rate_limit_pct = anomaly_get_rate_limit_pct();

    // Send to client
    if (client_fd >= 0) {
        ssize_t sent = send(client_fd, &pkt, sizeof(pkt), MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EPIPE || errno == ECONNRESET) {
                return -1;
            }
        }
    }

    return 0;
}

static void *stats_thread_func(void *arg) {
    (void)arg;
    struct sockaddr_in addr;
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[Stats] socket");
        return NULL;
    }
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(STATS_PORT);
    
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[Stats] bind");
        close(server_fd);
        return NULL;
    }
    
    if (listen(server_fd, 1) < 0) {
        perror("[Stats] listen");
        close(server_fd);
        return NULL;
    }
    
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Print sizes for debugging
    printf("[Stats] Listening on 127.0.0.1:%d\n", STATS_PORT);
    printf("[Stats] sizeof(port_stat_entry) = %zu\n", sizeof(struct port_stat_entry));
    printf("[Stats] sizeof(stats_packet) = %zu\n", sizeof(struct stats_packet));
    
    prev_timestamp = 0;
    memset(&prev_stats, 0, sizeof(prev_stats));

    // Counter for Layer 2 feature export (every 2 loops = 1 second at 500ms interval)
    uint32_t l2_export_counter = 0;
    // Counter for system monitor stats (every 2 loops = 1 second)
    uint32_t sysmon_counter = 0;
    // Counter for anomaly stats (every 2 loops = 1 second)
    uint32_t anomaly_counter = 0;
    // Counter for per-IP features (every 2 loops = 1 second)
    uint32_t per_ip_counter = 0;

    while (stats_running) {
        if (client_fd < 0) {
            client_fd = accept(server_fd, NULL, NULL);
            if (client_fd >= 0) {
                int flag = 1;
                setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
                printf("[Stats] Flask connected\n");
            }
        }

        send_stats();

        // Send system monitor stats every 1 second
        sysmon_counter++;
        if (sysmon_counter >= SYSMON_SEND_INTERVAL) {
            send_sysmon_stats();
            sysmon_counter = 0;
        }

        // Send anomaly stats every 1 second
        anomaly_counter++;
        if (anomaly_counter >= ANOMALY_SEND_INTERVAL) {
            send_anomaly_stats();
            anomaly_counter = 0;
        }

        // Send per-IP features every 1 second
        per_ip_counter++;
        if (per_ip_counter >= ANOMALY_SEND_INTERVAL) {
            send_per_ip_features();
            per_ip_counter = 0;
        }

        // Update Layer 2 features in shared memory every 1 second
        l2_export_counter++;
        if (l2_export_counter >= (1000 / STATS_INTERVAL_MS)) {
            l2_features_export_update();
            // Also export per-IP features for per-IP anomaly detection
            // Without this call, Layer 2 cannot detect attacks on specific protected IPs
            l2_per_ip_features_export_update();
            l2_export_counter = 0;
        }

        usleep(STATS_INTERVAL_MS * 1000);
    }
    
    return NULL;
}

int stats_socket_init(void) {
    stats_running = true;
    
    if (pthread_create(&stats_thread, NULL, stats_thread_func, NULL) != 0) {
        perror("[Stats] pthread_create");
        return -1;
    }
    
    pthread_setname_np(stats_thread, "dpdk-stats");
    printf("[Stats] Thread started (interval: %dms)\n", STATS_INTERVAL_MS);
    return 0;
}

void stats_socket_cleanup(void) {
    stats_running = false;
    
    if (stats_thread) {
        pthread_join(stats_thread, NULL);
    }
    
    if (client_fd >= 0) close(client_fd);
    if (server_fd >= 0) close(server_fd);
    
    printf("[Stats] Cleaned up\n");
}