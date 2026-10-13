#ifndef OTHER_PROTOCOLS_H
#define OTHER_PROTOCOLS_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @file other_protocols.h
 * @brief Filter for non-TCP/UDP/ICMP protocols
 *
 * Handles IP protocols other than TCP (6), UDP (17), and ICMP (1).
 * Common protocols:
 *   - GRE (47): Generic Routing Encapsulation
 *   - ESP (50): Encapsulating Security Payload (IPSec)
 *   - AH (51): Authentication Header (IPSec)
 *   - OSPF (89): Open Shortest Path First
 *   - SCTP (132): Stream Control Transmission Protocol
 *   - IPIP (4): IP in IP tunneling
 *
 * Three modes:
 *   - DROP: Drop all unrecognized protocols
 *   - ACCEPT: Accept all protocols
 *   - RATE_LIMIT: Apply rate limiting to other protocols
 */

// Action for other protocols
enum other_proto_action {
    OTHER_PROTO_DROP = 0,
    OTHER_PROTO_ACCEPT = 1,
    OTHER_PROTO_RATE_LIMIT = 2
};

// Maximum allowed protocols in whitelist
#define OTHER_PROTO_MAX_ALLOWED 32

// Configuration
struct other_proto_config {
    bool enabled;
    enum other_proto_action default_action;
    uint8_t allowed_protocols[OTHER_PROTO_MAX_ALLOWED];
    uint32_t allowed_count;
    uint32_t rate_limit_pps;
    bool log_unknown;
};

// Statistics
struct other_proto_stats {
    uint64_t total_packets;
    uint64_t allowed_packets;
    uint64_t dropped_packets;
    uint64_t rate_limited_packets;
    uint64_t per_protocol[256];  // Count per IP protocol number
};

/**
 * Initialize other protocols filter
 *
 * @param config  Configuration settings
 * @return 0 on success, -1 on error
 */
int other_proto_init(const struct other_proto_config *config);

/**
 * Cleanup other protocols filter
 */
void other_proto_cleanup(void);

/**
 * Check if a protocol should be allowed
 *
 * @param protocol  IP protocol number
 * @param src_ip    Source IP (network byte order) for rate limiting
 * @return true if packet should be dropped, false if allowed
 */
bool other_proto_should_drop(uint8_t protocol, uint32_t src_ip);

/**
 * Add a protocol to the allowed list
 *
 * @param protocol  IP protocol number
 * @return 0 on success, -1 on error
 */
int other_proto_add_allowed(uint8_t protocol);

/**
 * Remove a protocol from the allowed list
 *
 * @param protocol  IP protocol number
 * @return 0 on success, -1 if not found
 */
int other_proto_remove_allowed(uint8_t protocol);

/**
 * Clear all allowed protocols
 */
void other_proto_clear_allowed(void);

/**
 * Set default action
 *
 * @param action  Default action for unrecognized protocols
 */
void other_proto_set_action(enum other_proto_action action);

/**
 * Set rate limit
 *
 * @param pps  Packets per second limit
 */
void other_proto_set_rate_limit(uint32_t pps);

/**
 * Enable or disable
 */
void other_proto_set_enabled(bool enabled);

/**
 * Check if enabled
 */
bool other_proto_is_enabled(void);

/**
 * Get statistics
 */
void other_proto_get_stats(struct other_proto_stats *stats);

/**
 * Reset statistics
 */
void other_proto_reset_stats(void);

/**
 * Print statistics
 */
void other_proto_print_stats(void);

/**
 * Get protocol name
 *
 * @param protocol  IP protocol number
 * @return Protocol name string or "Unknown"
 */
const char* other_proto_name(uint8_t protocol);

#endif // OTHER_PROTOCOLS_H
