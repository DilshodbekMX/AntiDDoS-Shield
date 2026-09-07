#ifndef LAYER1_DPDK_TELEMETRY_H
#define LAYER1_DPDK_TELEMETRY_H

/**
 * @file dpdk_telemetry.h
 * @brief DPDK Telemetry API Integration for Layer 1
 *
 * Registers Layer 1 statistics with DPDK's built-in telemetry system.
 * This provides zero-overhead stats export via Unix socket.
 *
 * Access via: dpdk-telemetry.py or connect to /var/run/dpdk/rte/dpdk_telemetry.v2
 *
 * Registered endpoints:
 *   /antiddos/info          - System information
 *   /antiddos/stats         - Aggregated packet statistics
 *   /antiddos/flow_table    - Flow table statistics
 *   /antiddos/syn_proxy     - SYN proxy statistics
 *   /antiddos/ip_lists      - IP list statistics (whitelist/blacklist counts)
 *   /antiddos/rate_limits   - Rate limiting statistics
 *   /antiddos/drop_reasons  - Drop reason breakdown
 *   /antiddos/per_lcore     - Per-lcore statistics (detailed)
 */

#include <stdint.h>

/**
 * Initialize DPDK telemetry endpoints for Layer 1.
 * Call after EAL init but before main loop starts.
 *
 * @return 0 on success, -1 on error
 */
int dpdk_telemetry_init(void);

/**
 * Cleanup DPDK telemetry (optional, cleaned up with EAL)
 */
void dpdk_telemetry_cleanup(void);

#endif // LAYER1_DPDK_TELEMETRY_H
