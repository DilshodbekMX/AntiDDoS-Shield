#include "prometheus_exporter.h"
#include "dpdk_core.h"
#include "../layer2/layer2.h"
#include "../layer1/interlayer/shared_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

// ==================== State ====================

static pthread_t prom_thread;
static volatile bool prom_running = false;
static int server_fd = -1;
static uint16_t prom_port = PROMETHEUS_DEFAULT_PORT;

// Metrics buffer (pre-allocated for performance)
#define METRICS_BUFFER_SIZE 65536
static char metrics_buffer[METRICS_BUFFER_SIZE];

// ==================== Metrics Generation ====================

/**
 * Generate Prometheus metrics in exposition format
 * Returns length of generated metrics
 */
static int generate_metrics(char *buf, size_t buf_size) {
    int len = 0;
    int ret;

    // Get current stats
    struct aggregated_stats stats;
    aggregate_lcore_stats(&stats);

    // Get anomaly state
    struct l2_anomaly_state anomaly_state;
    layer2_get_anomaly_state(&anomaly_state);

    // Get baseline summary
    struct baseline_summary baseline;
    layer2_get_baseline_summary(&baseline);

    // Helper macro for safe snprintf
    #define METRIC_ADD(fmt, ...) do { \
        ret = snprintf(buf + len, buf_size - len, fmt, ##__VA_ARGS__); \
        if (ret > 0 && len + ret < (int)buf_size) len += ret; \
    } while(0)

    // ===== Volume Metrics =====
    METRIC_ADD("# HELP antiddos_packets_total Total packets processed\n");
    METRIC_ADD("# TYPE antiddos_packets_total counter\n");
    METRIC_ADD("antiddos_packets_total{direction=\"rx\"} %lu\n", stats.rx_packets);
    METRIC_ADD("antiddos_packets_total{direction=\"tx\"} %lu\n", stats.tx_packets);

    METRIC_ADD("# HELP antiddos_bytes_total Total bytes processed\n");
    METRIC_ADD("# TYPE antiddos_bytes_total counter\n");
    METRIC_ADD("antiddos_bytes_total{direction=\"rx\"} %lu\n", stats.rx_bytes);
    METRIC_ADD("antiddos_bytes_total{direction=\"tx\"} %lu\n", stats.tx_bytes);

    METRIC_ADD("# HELP antiddos_dropped_total Total packets dropped by reason\n");
    METRIC_ADD("# TYPE antiddos_dropped_total counter\n");
    METRIC_ADD("antiddos_dropped_total{reason=\"validation\"} %lu\n", stats.l1_drop_validation);
    METRIC_ADD("antiddos_dropped_total{reason=\"blacklist\"} %lu\n", stats.l1_drop_blacklist);
    METRIC_ADD("antiddos_dropped_total{reason=\"rate_limit\"} %lu\n", stats.l1_drop_rate_limit);
    METRIC_ADD("antiddos_dropped_total{reason=\"syn_flood\"} %lu\n", stats.l1_drop_syn_flood);
    METRIC_ADD("antiddos_dropped_total{reason=\"reputation\"} %lu\n", stats.l1_drop_reputation);
    METRIC_ADD("antiddos_dropped_total{reason=\"policy\"} %lu\n", stats.l1_drop_policy);
    METRIC_ADD("antiddos_dropped_total{reason=\"geo\"} %lu\n", stats.l1_drop_geo);
    METRIC_ADD("antiddos_dropped_total{reason=\"signature\"} %lu\n", stats.l1_drop_signature);

    // ===== Layer 1 Metrics =====
    METRIC_ADD("# HELP antiddos_l1_processed_total Total packets processed by Layer 1\n");
    METRIC_ADD("# TYPE antiddos_l1_processed_total counter\n");
    METRIC_ADD("antiddos_l1_processed_total %lu\n", stats.l1_total_packets);

    METRIC_ADD("# HELP antiddos_l1_accepted_total Total packets accepted by Layer 1\n");
    METRIC_ADD("# TYPE antiddos_l1_accepted_total counter\n");
    METRIC_ADD("antiddos_l1_accepted_total %lu\n", stats.l1_packets_accepted);

    METRIC_ADD("# HELP antiddos_l1_dropped_total Total packets dropped by Layer 1\n");
    METRIC_ADD("# TYPE antiddos_l1_dropped_total counter\n");
    METRIC_ADD("antiddos_l1_dropped_total %lu\n", stats.l1_packets_dropped);

    // ===== Protocol Metrics =====
    METRIC_ADD("# HELP antiddos_protocol_packets_total Packets by protocol\n");
    METRIC_ADD("# TYPE antiddos_protocol_packets_total counter\n");
    METRIC_ADD("antiddos_protocol_packets_total{protocol=\"tcp\"} %lu\n", stats.l1_tcp_packets);
    METRIC_ADD("antiddos_protocol_packets_total{protocol=\"udp\"} %lu\n", stats.l1_udp_packets);
    METRIC_ADD("antiddos_protocol_packets_total{protocol=\"icmp\"} %lu\n", stats.l1_icmp_packets);
    METRIC_ADD("antiddos_protocol_packets_total{protocol=\"other\"} %lu\n", stats.l1_other_packets);

    // ===== TCP Flag Metrics =====
    METRIC_ADD("# HELP antiddos_tcp_flags_total TCP packets by flag type\n");
    METRIC_ADD("# TYPE antiddos_tcp_flags_total counter\n");
    METRIC_ADD("antiddos_tcp_flags_total{flag=\"syn\"} %lu\n", stats.l1_syn_packets);
    METRIC_ADD("antiddos_tcp_flags_total{flag=\"syn_ack\"} %lu\n", stats.l1_syn_ack_packets);
    METRIC_ADD("antiddos_tcp_flags_total{flag=\"ack\"} %lu\n", stats.l1_ack_packets);
    METRIC_ADD("antiddos_tcp_flags_total{flag=\"rst\"} %lu\n", stats.l1_rst_packets);
    METRIC_ADD("antiddos_tcp_flags_total{flag=\"fin\"} %lu\n", stats.l1_fin_packets);

    // ===== SYN Proxy Metrics =====
    METRIC_ADD("# HELP antiddos_syn_proxy_challenges_total SYN proxy challenges sent\n");
    METRIC_ADD("# TYPE antiddos_syn_proxy_challenges_total counter\n");
    METRIC_ADD("antiddos_syn_proxy_challenges_total %lu\n", stats.l1_syn_proxy_challenges);

    METRIC_ADD("# HELP antiddos_syn_proxy_established_total SYN proxy connections established\n");
    METRIC_ADD("# TYPE antiddos_syn_proxy_established_total counter\n");
    METRIC_ADD("antiddos_syn_proxy_established_total %lu\n", stats.l1_syn_proxy_established);

    METRIC_ADD("# HELP antiddos_whitelist_hits_total Whitelist hits\n");
    METRIC_ADD("# TYPE antiddos_whitelist_hits_total counter\n");
    METRIC_ADD("antiddos_whitelist_hits_total %lu\n", stats.l1_whitelist_hits);

    // ===== Flow Metrics =====
    METRIC_ADD("# HELP antiddos_new_flows_total New flows created\n");
    METRIC_ADD("# TYPE antiddos_new_flows_total counter\n");
    METRIC_ADD("antiddos_new_flows_total %lu\n", stats.l1_new_flows);

    // ===== Anomaly Detection Metrics =====
    METRIC_ADD("# HELP antiddos_anomaly_active Whether anomaly detection is triggered\n");
    METRIC_ADD("# TYPE antiddos_anomaly_active gauge\n");
    METRIC_ADD("antiddos_anomaly_active %d\n", anomaly_state.active ? 1 : 0);

    METRIC_ADD("# HELP antiddos_anomaly_level Current anomaly level (0=none, 1=low, 2=medium, 3=high, 4=critical)\n");
    METRIC_ADD("# TYPE antiddos_anomaly_level gauge\n");
    METRIC_ADD("antiddos_anomaly_level %d\n", (int)anomaly_state.level);

    METRIC_ADD("# HELP antiddos_z_score Current max Z-score\n");
    METRIC_ADD("# TYPE antiddos_z_score gauge\n");
    METRIC_ADD("antiddos_z_score %.2f\n", anomaly_state.max_z_score);

    METRIC_ADD("# HELP antiddos_tier_agreement Number of baseline tiers agreeing on anomaly\n");
    METRIC_ADD("# TYPE antiddos_tier_agreement gauge\n");
    METRIC_ADD("antiddos_tier_agreement %d\n", anomaly_state.tier_agreement);

    // ===== Baseline Metrics =====
    METRIC_ADD("# HELP antiddos_baseline_ready Whether baseline tier is ready\n");
    METRIC_ADD("# TYPE antiddos_baseline_ready gauge\n");
    METRIC_ADD("antiddos_baseline_ready{tier=\"1\"} %d\n", baseline.tier1_ready ? 1 : 0);
    METRIC_ADD("antiddos_baseline_ready{tier=\"2\"} %u\n", baseline.tier2_ready_count);
    METRIC_ADD("antiddos_baseline_ready{tier=\"3\"} %u\n", baseline.tier3_ready_count);

    METRIC_ADD("# HELP antiddos_baseline_samples Sample count for tier 1\n");
    METRIC_ADD("# TYPE antiddos_baseline_samples gauge\n");
    METRIC_ADD("antiddos_baseline_samples{tier=\"1\"} %u\n", baseline.tier1_samples);

    METRIC_ADD("# HELP antiddos_baseline_pps_mean Mean packets per second baseline\n");
    METRIC_ADD("# TYPE antiddos_baseline_pps_mean gauge\n");
    METRIC_ADD("antiddos_baseline_pps_mean{tier=\"1\"} %.2f\n", baseline.tier1_pps_mean);

    #undef METRIC_ADD

    return len;
}

// ==================== HTTP Handler ====================

static void handle_client(int client_fd) {
    char request[1024];
    ssize_t n = recv(client_fd, request, sizeof(request) - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    request[n] = '\0';

    // Check for GET /metrics
    if (strncmp(request, "GET /metrics", 12) == 0 ||
        strncmp(request, "GET / ", 6) == 0) {

        // Generate metrics
        int metrics_len = generate_metrics(metrics_buffer, sizeof(metrics_buffer));

        // Send HTTP response
        char header[256];
        int header_len = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n",
            metrics_len);

        send(client_fd, header, header_len, 0);
        send(client_fd, metrics_buffer, metrics_len, 0);
    } else {
        // 404 for other paths
        const char *not_found =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 9\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Not Found";
        send(client_fd, not_found, strlen(not_found), 0);
    }

    close(client_fd);
}

// ==================== Server Thread ====================

static void *prometheus_thread_func(void *arg) {
    (void)arg;

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    while (prom_running) {
        // Accept connection with timeout
        fd_set fds;
        struct timeval tv;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(server_fd + 1, &fds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        int client = accept(server_fd, (struct sockaddr *)&addr, &addr_len);
        if (client < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Handle client request
        handle_client(client);
    }

    return NULL;
}

// ==================== Public API ====================

int prometheus_exporter_init(uint16_t port) {
    if (prom_running) {
        return 0;  // Already running
    }

    prom_port = (port > 0) ? port : PROMETHEUS_DEFAULT_PORT;

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[Prometheus] socket failed");
        return -1;
    }

    // Allow reuse
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(prom_port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[Prometheus] bind failed");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    // Listen
    if (listen(server_fd, 5) < 0) {
        perror("[Prometheus] listen failed");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    // Start thread
    prom_running = true;
    if (pthread_create(&prom_thread, NULL, prometheus_thread_func, NULL) != 0) {
        perror("[Prometheus] pthread_create failed");
        prom_running = false;
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    printf("[Prometheus] Metrics exporter started on port %u\n", prom_port);
    return 0;
}

void prometheus_exporter_stop(void) {
    if (!prom_running) return;

    prom_running = false;

    if (server_fd >= 0) {
        shutdown(server_fd, SHUT_RDWR);
        close(server_fd);
        server_fd = -1;
    }

    pthread_join(prom_thread, NULL);
    printf("[Prometheus] Metrics exporter stopped\n");
}

bool prometheus_exporter_is_running(void) {
    return prom_running;
}

uint16_t prometheus_exporter_get_port(void) {
    return prom_port;
}
