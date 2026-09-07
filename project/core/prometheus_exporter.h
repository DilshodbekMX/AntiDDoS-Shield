#ifndef PROMETHEUS_EXPORTER_H
#define PROMETHEUS_EXPORTER_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @file prometheus_exporter.h
 * @brief Prometheus Metrics Exporter
 *
 * Provides a lightweight HTTP server on port 9100 (configurable) that
 * exposes metrics in Prometheus exposition format.
 *
 * Metrics exposed:
 * - antiddos_packets_total{direction="rx|tx"}
 * - antiddos_bytes_total{direction="rx|tx"}
 * - antiddos_dropped_total{reason="..."}
 * - antiddos_pps{direction="rx|tx"}
 * - antiddos_bps{direction="rx|tx"}
 * - antiddos_anomaly_active
 * - antiddos_anomaly_level
 * - antiddos_z_score
 * - antiddos_flows_active
 * - antiddos_syn_proxy_challenges
 * - antiddos_syn_proxy_established
 * - antiddos_baseline_tier1_ready
 * - antiddos_baseline_tier2_ready
 * - antiddos_baseline_tier3_ready
 */

#define PROMETHEUS_DEFAULT_PORT 9100
#define PROMETHEUS_METRICS_PATH "/metrics"

/**
 * Initialize Prometheus metrics exporter
 *
 * @param port  HTTP port to listen on (0 = use default 9100)
 * @return 0 on success, -1 on error
 */
int prometheus_exporter_init(uint16_t port);

/**
 * Stop Prometheus exporter
 */
void prometheus_exporter_stop(void);

/**
 * Check if exporter is running
 */
bool prometheus_exporter_is_running(void);

/**
 * Get current port
 */
uint16_t prometheus_exporter_get_port(void);

#endif // PROMETHEUS_EXPORTER_H
