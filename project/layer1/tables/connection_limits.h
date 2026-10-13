#ifndef LAYER1_CONNECTION_LIMITS_H
#define LAYER1_CONNECTION_LIMITS_H

#include "types.h"
#include <stdint.h>
#include <stdbool.h>

/**
 * @file connection_limits.h
 * @brief Stage 10: Per-IP Connection Limit Tracking
 *
 * Tracks connection counts per IP address to detect:
 * - Port scans (many connections to different ports)
 * - Connection floods (many connections in short time)
 * - Slowloris attacks (many slow connections)
 *
 * Uses sliding window algorithm for time-based limits.
 * All operations are thread-safe for multi-core RSS.
 */

// ==================== Configuration ====================

struct connection_limits_config {
    uint32_t max_ips;                    // Maximum IPs to track (e.g., 100000)
    uint32_t max_connections_per_ip;     // Max connections per IP (e.g., 1000)
    uint32_t time_window_sec;            // Time window for limits (e.g., 10 sec)
    uint32_t cleanup_interval_sec;       // How often to cleanup expired entries (e.g., 60 sec)
};

// ==================== Connection Tracking ====================

/**
 * Connection state for tracking
 */
enum connection_state {
    CONN_STATE_SYN_SENT = 0,       // SYN seen
    CONN_STATE_ESTABLISHED,         // SYN+ACK seen
    CONN_STATE_CLOSED               // FIN or RST seen
};

/**
 * Per-IP connection tracking entry
 * All fields accessed atomically for thread safety
 */
struct connection_tracker {
    uint32_t ip;                           // IP address (network byte order)
    uint32_t total_connections;            // Total connections ever
    uint32_t active_connections;           // Currently active connections
    uint32_t connections_last_window;      // Connections in last time window
    uint64_t last_update_tsc;              // Last update timestamp
    uint64_t window_start_tsc;             // Start of current time window
} __attribute__((aligned(64)));  // Cache-line aligned for atomics

// ==================== Public API ====================

/**
 * Initialize connection limits system (thread-safe)
 *
 * @param config  Configuration parameters
 * @return 0 on success, -1 on error
 */
int connection_limits_init(const struct connection_limits_config *config);

/**
 * Cleanup connection limits
 */
void connection_limits_cleanup(void);

/**
 * Check if connection should be allowed for this IP (thread-safe)
 *
 * Called when a new connection is detected (SYN packet).
 *
 * @param ip     IP address (network byte order)
 * @param port   Destination port
 * @return true if allowed, false if limit exceeded
 */
bool connection_limits_check(uint32_t ip, uint16_t port);

/**
 * Update connection state for an IP (thread-safe)
 *
 * Called when connection state changes (SYN, SYN+ACK, FIN, RST).
 *
 * @param ip     IP address
 * @param state  New connection state
 */
void connection_limits_update(uint32_t ip, enum connection_state state);

/**
 * Cleanup expired entries (should be called periodically from single thread)
 *
 * @return Number of entries cleaned up
 */
uint32_t connection_limits_cleanup_expired(void);

/**
 * Get connection count for an IP (thread-safe)
 *
 * @param ip     IP address
 * @param active Output: active connections
 * @param total  Output: total connections
 * @return true if IP found, false otherwise
 */
bool connection_limits_get_count(uint32_t ip, uint32_t *active, uint32_t *total);

/**
 * Get statistics (thread-safe)
 *
 * @param tracked_ips       Output: number of IPs being tracked
 * @param total_connections Output: total active connections
 * @param limits_exceeded   Output: number of times limit exceeded
 */
void connection_limits_get_stats(uint32_t *tracked_ips,
                                 uint32_t *total_connections,
                                 uint64_t *limits_exceeded);

#endif // LAYER1_CONNECTION_LIMITS_H