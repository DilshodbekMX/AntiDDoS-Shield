/**
 * @file tenant_prometheus.h
 * @brief Prometheus Metrics Exporter API
 */

#ifndef TENANT_PROMETHEUS_H
#define TENANT_PROMETHEUS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize Prometheus metrics server
 *
 * @param port Port to listen on (0 for default 9100)
 * @param bind_addr Address to bind to (NULL for 0.0.0.0)
 * @return 0 on success, -1 on failure
 */
int prometheus_server_init(uint16_t port, const char *bind_addr);

/**
 * Start the Prometheus server thread
 *
 * @return 0 on success
 */
int prometheus_server_start(void);

/**
 * Stop the Prometheus server
 */
void prometheus_server_stop(void);

/**
 * Cleanup server resources
 */
void prometheus_server_cleanup(void);

/**
 * Get server statistics
 *
 * @param requests Total requests served
 * @param bytes Total bytes sent
 * @param avg_response_ms Average response time
 */
void prometheus_server_get_stats(uint64_t *requests, uint64_t *bytes,
                                  double *avg_response_ms);

#ifdef __cplusplus
}
#endif

#endif // TENANT_PROMETHEUS_H
