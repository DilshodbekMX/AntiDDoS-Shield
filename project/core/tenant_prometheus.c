/**
 * @file tenant_prometheus.c
 * @brief Prometheus Metrics Exporter for Per-Tenant Statistics
 *
 * HTTP endpoint serving metrics in Prometheus format:
 * - /metrics - All tenant metrics
 * - /metrics?tenant_id=N - Specific tenant metrics
 * - /health - Health check endpoint
 *
 * Designed to integrate with:
 * - Prometheus server (scraping)
 * - Grafana dashboards
 * - AlertManager for alerting
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#include "../common/tenant_stats.h"
#include "../common/tenant.h"

// ==================== Configuration ====================

#define PROMETHEUS_DEFAULT_PORT     9100
#define MAX_REQUEST_SIZE            4096
#define MAX_RESPONSE_SIZE           (1024 * 1024)  // 1MB
#define MAX_CONNECTIONS             16
#define LISTEN_BACKLOG              32
#define HTTP_READ_TIMEOUT_MS        5000

// ==================== Types ====================

struct prometheus_config {
    uint16_t port;
    bool     enabled;
    char     bind_address[64];
    char     metrics_path[64];
    bool     include_histograms;
    uint32_t scrape_timeout_ms;
};

struct prometheus_server {
    int                       listen_fd;
    pthread_t                 thread;
    bool                      running;
    struct prometheus_config  config;

    // Statistics
    uint64_t                  requests_total;
    uint64_t                  requests_success;
    uint64_t                  requests_error;
    uint64_t                  bytes_sent;
    uint64_t                  last_scrape_time;
    double                    avg_response_time_ms;
};

// ==================== Global Instance ====================

static struct prometheus_server *g_prom_server = NULL;

// ==================== HTTP Response Helpers ====================

static const char *HTTP_200_HEADER =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
    "Connection: close\r\n"
    "Content-Length: %zu\r\n"
    "\r\n";

static const char *HTTP_404_RESPONSE =
    "HTTP/1.1 404 Not Found\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 9\r\n"
    "\r\n"
    "Not Found";

static const char *HTTP_500_RESPONSE =
    "HTTP/1.1 500 Internal Server Error\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 21\r\n"
    "\r\n"
    "Internal Server Error";

static const char *HTTP_HEALTH_RESPONSE =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: %zu\r\n"
    "\r\n";

// ==================== Metrics Generation ====================

/**
 * Generate standard process metrics
 */
static int generate_process_metrics(char *buf, size_t buf_size) {
    int n = 0;

    // Process uptime
    static time_t start_time = 0;
    if (start_time == 0) start_time = time(NULL);
    time_t uptime = time(NULL) - start_time;

    // Memory usage (from /proc/self/status)
    FILE *status = fopen("/proc/self/status", "r");
    long vm_rss = 0;
    if (status) {
        char line[256];
        while (fgets(line, sizeof(line), status)) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                sscanf(line + 6, "%ld", &vm_rss);
                vm_rss *= 1024;  // Convert KB to bytes
                break;
            }
        }
        fclose(status);
    }

    n = snprintf(buf, buf_size,
        "# HELP antiddos_process_uptime_seconds Time since process started\n"
        "# TYPE antiddos_process_uptime_seconds counter\n"
        "antiddos_process_uptime_seconds %ld\n"
        "\n"
        "# HELP antiddos_process_memory_bytes Process memory usage\n"
        "# TYPE antiddos_process_memory_bytes gauge\n"
        "antiddos_process_memory_bytes %ld\n"
        "\n",
        uptime, vm_rss
    );

    return n;
}

/**
 * Generate global system metrics
 */
static int generate_global_metrics(char *buf, size_t buf_size) {
    uint32_t num_tenants = 0;
    uint64_t total_packets = 0;

    tenant_stats_get_status(&num_tenants, &total_packets);

    int n = snprintf(buf, buf_size,
        "# HELP antiddos_tenants_active Number of active tenants\n"
        "# TYPE antiddos_tenants_active gauge\n"
        "antiddos_tenants_active %u\n"
        "\n"
        "# HELP antiddos_packets_total Total packets processed\n"
        "# TYPE antiddos_packets_total counter\n"
        "antiddos_packets_total %lu\n"
        "\n"
        "# HELP antiddos_scrape_requests_total Total scrape requests\n"
        "# TYPE antiddos_scrape_requests_total counter\n"
        "antiddos_scrape_requests_total %lu\n"
        "\n"
        "# HELP antiddos_scrape_duration_seconds Last scrape duration\n"
        "# TYPE antiddos_scrape_duration_seconds gauge\n"
        "antiddos_scrape_duration_seconds %.6f\n"
        "\n",
        num_tenants,
        total_packets,
        g_prom_server ? g_prom_server->requests_total : 0,
        g_prom_server ? g_prom_server->avg_response_time_ms / 1000.0 : 0
    );

    return n;
}

/**
 * Generate tenant traffic metrics with proper Prometheus formatting
 */
static int generate_traffic_metrics(char *buf, size_t buf_size,
                                     tenant_id_t tenant_id,
                                     struct tenant_traffic_stats *traffic) {
    return snprintf(buf, buf_size,
        "antiddos_tenant_traffic_packets{tenant_id=\"%u\",direction=\"in\"} %lu\n"
        "antiddos_tenant_traffic_packets{tenant_id=\"%u\",direction=\"out\"} %lu\n"
        "antiddos_tenant_traffic_bytes{tenant_id=\"%u\",direction=\"in\"} %lu\n"
        "antiddos_tenant_traffic_bytes{tenant_id=\"%u\",direction=\"out\"} %lu\n"
        "antiddos_tenant_traffic_rate_pps{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_traffic_rate_bps{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_traffic_peak_pps{tenant_id=\"%u\",window=\"1m\"} %lu\n"
        "antiddos_tenant_traffic_peak_pps{tenant_id=\"%u\",window=\"1h\"} %lu\n"
        "antiddos_tenant_traffic_peak_pps{tenant_id=\"%u\",window=\"24h\"} %lu\n",
        tenant_id, traffic->packets_in,
        tenant_id, traffic->packets_out,
        tenant_id, traffic->bytes_in,
        tenant_id, traffic->bytes_out,
        tenant_id, traffic->current_pps,
        tenant_id, traffic->current_bps,
        tenant_id, traffic->peak_pps_1m,
        tenant_id, traffic->peak_pps_1h,
        tenant_id, traffic->peak_pps_24h
    );
}

/**
 * Generate security metrics
 */
static int generate_security_metrics(char *buf, size_t buf_size,
                                      tenant_id_t tenant_id,
                                      struct tenant_security_stats *sec) {
    int written = 0;
    char *p = buf;
    size_t remaining = buf_size;

    // Total drops
    int n = snprintf(p, remaining,
        "antiddos_tenant_drops_total{tenant_id=\"%u\"} %lu\n",
        tenant_id, sec->total_drops
    );
    if (n > 0) { p += n; remaining -= n; written += n; }

    // Drops by reason
    for (int r = 0; r < DROP_REASON_MAX && remaining > 0; r++) {
        if (sec->drops_by_reason[r] > 0) {
            n = snprintf(p, remaining,
                "antiddos_tenant_drops{tenant_id=\"%u\",reason=\"%s\"} %lu\n",
                tenant_id, tenant_stats_drop_reason_name(r),
                sec->drops_by_reason[r]
            );
            if (n > 0) { p += n; remaining -= n; written += n; }
        }
    }

    // Attack metrics
    n = snprintf(p, remaining,
        "antiddos_tenant_attacks_detected{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_attacks_mitigated{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_false_positives{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_false_negatives{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_detection_time_avg_ms{tenant_id=\"%u\"} %.3f\n"
        "antiddos_tenant_mitigation_time_avg_ms{tenant_id=\"%u\"} %.3f\n",
        tenant_id, sec->attacks_detected,
        tenant_id, sec->attacks_mitigated,
        tenant_id, sec->false_positives,
        tenant_id, sec->false_negatives,
        tenant_id, sec->avg_detection_time_ms,
        tenant_id, sec->avg_mitigation_time_ms
    );
    if (n > 0) { written += n; }

    return written;
}

/**
 * Generate layer-specific metrics
 */
static int generate_layer_metrics(char *buf, size_t buf_size,
                                   tenant_id_t tenant_id,
                                   struct tenant_comprehensive_stats *stats) {
    return snprintf(buf, buf_size,
        "# Layer 1 metrics\n"
        "antiddos_tenant_l1_rate_limit_hits{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l1_blacklist_hits{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l1_syn_proxy_challenges{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l1_syn_proxy_pass_rate{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l1_signature_hits{tenant_id=\"%u\"} %lu\n"
        "\n"
        "# Layer 2 metrics\n"
        "antiddos_tenant_l2_z_score{tenant_id=\"%u\"} %.3f\n"
        "antiddos_tenant_l2_anomaly_active{tenant_id=\"%u\"} %d\n"
        "antiddos_tenant_l2_anomaly_severity{tenant_id=\"%u\"} %u\n"
        "antiddos_tenant_l2_total_anomalies{tenant_id=\"%u\"} %lu\n"
        "\n"
        "# Layer 3 metrics\n"
        "antiddos_tenant_l3_ml_inferences{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l3_policies_generated{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l3_model_precision{tenant_id=\"%u\"} %.4f\n"
        "antiddos_tenant_l3_model_recall{tenant_id=\"%u\"} %.4f\n"
        "antiddos_tenant_l3_model_f1{tenant_id=\"%u\"} %.4f\n"
        "\n"
        "# Layer 4 metrics\n"
        "antiddos_tenant_l4_reputation_avg{tenant_id=\"%u\"} %.4f\n"
        "antiddos_tenant_l4_trusted_ips{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l4_suspicious_ips{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l4_attacker_ips{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l4_challenges_issued{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l4_challenges_passed{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l4_bots_detected{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l4_bots_blocked{tenant_id=\"%u\"} %lu\n"
        "\n"
        "# Layer 5 metrics\n"
        "antiddos_tenant_l5_threat_intel_hits{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l5_early_warnings{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_l5_reports_generated{tenant_id=\"%u\"} %lu\n",
        // L1
        tenant_id, stats->layer1.rate_limit_hits,
        tenant_id, stats->layer1.blacklist_hits,
        tenant_id, stats->layer1.syn_proxy_challenges,
        tenant_id, stats->layer1.syn_proxy_pass_rate,
        tenant_id, stats->layer1.signature_hits,
        // L2
        tenant_id, stats->layer2.current_z_score,
        tenant_id, stats->layer2.anomaly_active ? 1 : 0,
        tenant_id, stats->layer2.anomaly_severity,
        tenant_id, stats->layer2.total_anomalies,
        // L3
        tenant_id, stats->layer3.ml_inferences,
        tenant_id, stats->layer3.policies_generated,
        tenant_id, stats->layer3.model_precision,
        tenant_id, stats->layer3.model_recall,
        tenant_id, stats->layer3.model_f1,
        // L4
        tenant_id, stats->layer4.avg_reputation_score,
        tenant_id, stats->layer4.trusted_ips,
        tenant_id, stats->layer4.suspicious_ips,
        tenant_id, stats->layer4.attacker_ips,
        tenant_id, stats->layer4.challenges_issued,
        tenant_id, stats->layer4.challenges_passed,
        tenant_id, stats->layer4.bots_detected,
        tenant_id, stats->layer4.bots_blocked,
        // L5
        tenant_id, stats->layer5.threat_intel_hits,
        tenant_id, stats->layer5.early_warnings_sent,
        tenant_id, stats->layer5.reports_generated
    );
}

/**
 * Generate SLA metrics
 */
static int generate_sla_metrics(char *buf, size_t buf_size,
                                 tenant_id_t tenant_id,
                                 struct tenant_sla_stats *sla) {
    return snprintf(buf, buf_size,
        "antiddos_tenant_sla_availability{tenant_id=\"%u\"} %.6f\n"
        "antiddos_tenant_sla_uptime_seconds{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_sla_downtime_seconds{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_sla_incidents_total{tenant_id=\"%u\"} %lu\n"
        "antiddos_tenant_sla_mttd_seconds{tenant_id=\"%u\"} %.3f\n"
        "antiddos_tenant_sla_mttr_seconds{tenant_id=\"%u\"} %.3f\n"
        "antiddos_tenant_sla_effectiveness{tenant_id=\"%u\"} %.4f\n"
        "antiddos_tenant_sla_fp_rate{tenant_id=\"%u\"} %.6f\n"
        "antiddos_tenant_sla_breach{tenant_id=\"%u\"} %d\n"
        "antiddos_tenant_sla_breaches_total{tenant_id=\"%u\"} %lu\n",
        tenant_id, sla->availability_percent / 100.0,
        tenant_id, sla->total_uptime_sec,
        tenant_id, sla->total_downtime_sec,
        tenant_id, sla->incidents_count,
        tenant_id, sla->mttd_sec,
        tenant_id, sla->mttr_sec,
        tenant_id, sla->mitigation_effectiveness,
        tenant_id, sla->false_positive_rate,
        tenant_id, sla->sla_breach ? 1 : 0,
        tenant_id, sla->sla_breaches_count
    );
}

/**
 * Generate all metrics for a tenant
 */
static int generate_tenant_metrics(char *buf, size_t buf_size,
                                    tenant_id_t tenant_id) {
    struct tenant_comprehensive_stats stats;
    if (tenant_stats_get(tenant_id, &stats) != 0) {
        return 0;
    }

    // Skip inactive tenants
    if (stats.traffic.packets_in == 0 && stats.traffic.packets_out == 0) {
        return 0;
    }

    int written = 0;
    char *p = buf;
    size_t remaining = buf_size;

    // Traffic metrics
    int n = generate_traffic_metrics(p, remaining, tenant_id, &stats.traffic);
    if (n > 0 && (size_t)n < remaining) {
        p += n; remaining -= n; written += n;
    }

    // Security metrics
    n = generate_security_metrics(p, remaining, tenant_id, &stats.security);
    if (n > 0 && (size_t)n < remaining) {
        p += n; remaining -= n; written += n;
    }

    // Layer metrics
    n = generate_layer_metrics(p, remaining, tenant_id, &stats);
    if (n > 0 && (size_t)n < remaining) {
        p += n; remaining -= n; written += n;
    }

    // SLA metrics
    n = generate_sla_metrics(p, remaining, tenant_id, &stats.sla);
    if (n > 0 && (size_t)n < remaining) {
        written += n;
    }

    return written;
}

/**
 * Generate complete metrics response
 */
static int generate_all_metrics(char *buf, size_t buf_size,
                                 tenant_id_t filter_tenant) {
    int written = 0;
    char *p = buf;
    size_t remaining = buf_size;

    // Metric type declarations
    int n = snprintf(p, remaining,
        "# HELP antiddos_tenant_traffic_packets Total packets\n"
        "# TYPE antiddos_tenant_traffic_packets counter\n"
        "# HELP antiddos_tenant_traffic_bytes Total bytes\n"
        "# TYPE antiddos_tenant_traffic_bytes counter\n"
        "# HELP antiddos_tenant_traffic_rate_pps Current packets per second\n"
        "# TYPE antiddos_tenant_traffic_rate_pps gauge\n"
        "# HELP antiddos_tenant_traffic_rate_bps Current bits per second\n"
        "# TYPE antiddos_tenant_traffic_rate_bps gauge\n"
        "# HELP antiddos_tenant_drops_total Total dropped packets\n"
        "# TYPE antiddos_tenant_drops_total counter\n"
        "# HELP antiddos_tenant_drops Dropped packets by reason\n"
        "# TYPE antiddos_tenant_drops counter\n"
        "# HELP antiddos_tenant_attacks_detected Total attacks detected\n"
        "# TYPE antiddos_tenant_attacks_detected counter\n"
        "# HELP antiddos_tenant_attacks_mitigated Total attacks mitigated\n"
        "# TYPE antiddos_tenant_attacks_mitigated counter\n"
        "# HELP antiddos_tenant_sla_availability SLA availability ratio\n"
        "# TYPE antiddos_tenant_sla_availability gauge\n"
        "# HELP antiddos_tenant_sla_breach SLA breach indicator\n"
        "# TYPE antiddos_tenant_sla_breach gauge\n"
        "\n"
    );
    if (n > 0 && (size_t)n < remaining) {
        p += n; remaining -= n; written += n;
    }

    // Process metrics
    n = generate_process_metrics(p, remaining);
    if (n > 0 && (size_t)n < remaining) {
        p += n; remaining -= n; written += n;
    }

    // Global metrics
    n = generate_global_metrics(p, remaining);
    if (n > 0 && (size_t)n < remaining) {
        p += n; remaining -= n; written += n;
    }

    // Tenant metrics
    if (filter_tenant > 0) {
        // Single tenant
        n = generate_tenant_metrics(p, remaining, filter_tenant);
        if (n > 0) written += n;
    } else {
        // All tenants
        for (tenant_id_t t = 1; t < MAX_TENANTS && remaining > 1024; t++) {
            n = generate_tenant_metrics(p, remaining, t);
            if (n > 0 && (size_t)n < remaining) {
                p += n; remaining -= n; written += n;
            }
        }
    }

    return written;
}

// ==================== HTTP Request Handling ====================

/**
 * Parse tenant_id from query string
 */
static tenant_id_t parse_tenant_id_param(const char *request) {
    const char *query = strstr(request, "?tenant_id=");
    if (query) {
        return (tenant_id_t)atoi(query + 11);
    }
    return 0;
}

/**
 * Handle /metrics endpoint
 */
static int handle_metrics_request(int client_fd, const char *request) {
    char *body = malloc(MAX_RESPONSE_SIZE);
    char *response = malloc(MAX_RESPONSE_SIZE + 1024);

    if (!body || !response) {
        free(body);
        free(response);
        send(client_fd, HTTP_500_RESPONSE, strlen(HTTP_500_RESPONSE), 0);
        return -1;
    }

    // Parse tenant filter
    tenant_id_t filter = parse_tenant_id_param(request);

    // Generate metrics
    int body_len = generate_all_metrics(body, MAX_RESPONSE_SIZE - 1, filter);
    body[body_len] = '\0';

    // Build response
    int header_len = snprintf(response, 1024, HTTP_200_HEADER, (size_t)body_len);
    memcpy(response + header_len, body, body_len);

    // Send
    int total = header_len + body_len;
    send(client_fd, response, total, 0);

    if (g_prom_server) {
        g_prom_server->bytes_sent += total;
    }

    free(body);
    free(response);
    return 0;
}

/**
 * Handle /health endpoint
 */
static int handle_health_request(int client_fd) {
    char body[512];
    char response[1024];

    uint32_t num_tenants = 0;
    uint64_t total_packets = 0;
    tenant_stats_get_status(&num_tenants, &total_packets);

    int body_len = snprintf(body, sizeof(body),
        "{\"status\":\"healthy\","
        "\"active_tenants\":%u,"
        "\"total_packets\":%lu,"
        "\"uptime_seconds\":%lu}",
        num_tenants, total_packets,
        g_prom_server ? g_prom_server->requests_total : 0
    );

    int header_len = snprintf(response, sizeof(response),
                               HTTP_HEALTH_RESPONSE, (size_t)body_len);
    strcat(response, body);

    send(client_fd, response, header_len + body_len, 0);
    return 0;
}

/**
 * Handle incoming HTTP request
 */
static void handle_request(int client_fd) {
    char request[MAX_REQUEST_SIZE];

    // Read request
    ssize_t n = recv(client_fd, request, sizeof(request) - 1, 0);
    if (n <= 0) {
        return;
    }
    request[n] = '\0';

    if (g_prom_server) {
        g_prom_server->requests_total++;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Parse HTTP method and path
    if (strncmp(request, "GET ", 4) != 0) {
        send(client_fd, HTTP_404_RESPONSE, strlen(HTTP_404_RESPONSE), 0);
        return;
    }

    char *path = request + 4;
    char *space = strchr(path, ' ');
    if (space) *space = '\0';

    // Route request
    if (strncmp(path, "/metrics", 8) == 0) {
        handle_metrics_request(client_fd, path);
        if (g_prom_server) g_prom_server->requests_success++;
    } else if (strcmp(path, "/health") == 0) {
        handle_health_request(client_fd);
        if (g_prom_server) g_prom_server->requests_success++;
    } else {
        send(client_fd, HTTP_404_RESPONSE, strlen(HTTP_404_RESPONSE), 0);
        if (g_prom_server) g_prom_server->requests_error++;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 +
                        (end.tv_nsec - start.tv_nsec) / 1000000.0;

    if (g_prom_server) {
        g_prom_server->avg_response_time_ms =
            (g_prom_server->avg_response_time_ms * 0.9) + (elapsed_ms * 0.1);
        g_prom_server->last_scrape_time = (uint64_t)time(NULL);
    }
}

// ==================== Server Thread ====================

static void* prometheus_server_thread(void *arg) {
    (void)arg;

    struct prometheus_server *srv = g_prom_server;
    if (!srv) return NULL;

    while (srv->running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(srv->listen_fd,
                                (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Set socket timeout
        struct timeval tv;
        tv.tv_sec = srv->config.scrape_timeout_ms / 1000;
        tv.tv_usec = (srv->config.scrape_timeout_ms % 1000) * 1000;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        handle_request(client_fd);

        close(client_fd);
    }

    return NULL;
}

// ==================== Public API ====================

int prometheus_server_init(uint16_t port, const char *bind_addr) {
    if (g_prom_server) {
        return 0;  // Already initialized
    }

    g_prom_server = calloc(1, sizeof(struct prometheus_server));
    if (!g_prom_server) {
        return -1;
    }

    // Configure
    g_prom_server->config.port = port ? port : PROMETHEUS_DEFAULT_PORT;
    g_prom_server->config.enabled = true;
    g_prom_server->config.scrape_timeout_ms = HTTP_READ_TIMEOUT_MS;
    strncpy(g_prom_server->config.bind_address,
            bind_addr ? bind_addr : "0.0.0.0",
            sizeof(g_prom_server->config.bind_address) - 1);
    strcpy(g_prom_server->config.metrics_path, "/metrics");

    // Create socket
    g_prom_server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_prom_server->listen_fd < 0) {
        free(g_prom_server);
        g_prom_server = NULL;
        return -1;
    }

    // Set socket options
    int opt = 1;
    setsockopt(g_prom_server->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(g_prom_server->config.port),
    };
    inet_pton(AF_INET, g_prom_server->config.bind_address, &addr.sin_addr);

    if (bind(g_prom_server->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(g_prom_server->listen_fd);
        free(g_prom_server);
        g_prom_server = NULL;
        return -1;
    }

    // Listen
    if (listen(g_prom_server->listen_fd, LISTEN_BACKLOG) < 0) {
        close(g_prom_server->listen_fd);
        free(g_prom_server);
        g_prom_server = NULL;
        return -1;
    }

    return 0;
}

int prometheus_server_start(void) {
    if (!g_prom_server || g_prom_server->running) {
        return -1;
    }

    g_prom_server->running = true;

    if (pthread_create(&g_prom_server->thread, NULL,
                       prometheus_server_thread, NULL) != 0) {
        g_prom_server->running = false;
        return -1;
    }

    return 0;
}

void prometheus_server_stop(void) {
    if (!g_prom_server) return;

    g_prom_server->running = false;

    // Close listen socket to unblock accept()
    if (g_prom_server->listen_fd >= 0) {
        shutdown(g_prom_server->listen_fd, SHUT_RDWR);
        close(g_prom_server->listen_fd);
        g_prom_server->listen_fd = -1;
    }

    pthread_join(g_prom_server->thread, NULL);
}

void prometheus_server_cleanup(void) {
    prometheus_server_stop();

    if (g_prom_server) {
        free(g_prom_server);
        g_prom_server = NULL;
    }
}

void prometheus_server_get_stats(uint64_t *requests, uint64_t *bytes,
                                  double *avg_response_ms) {
    if (!g_prom_server) {
        if (requests) *requests = 0;
        if (bytes) *bytes = 0;
        if (avg_response_ms) *avg_response_ms = 0;
        return;
    }

    if (requests) *requests = g_prom_server->requests_total;
    if (bytes) *bytes = g_prom_server->bytes_sent;
    if (avg_response_ms) *avg_response_ms = g_prom_server->avg_response_time_ms;
}
