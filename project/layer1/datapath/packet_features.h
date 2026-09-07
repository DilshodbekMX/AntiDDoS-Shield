#ifndef LAYER1_PACKET_FEATURES_H
#define LAYER1_PACKET_FEATURES_H

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>

// Forward declaration to avoid circular dependency
struct packet_features;

/**
 * @file features.h
 * @brief Stage 3: Extended Feature Extraction
 *
 * Extracts 20+ features from packets for use by:
 * - Layer 1: Fast path decision making
 * - Layer 3: ML-based attribution
 * - Layer 4: Reputation analysis
 * - Layer 5: Deep packet inspection
 *
 * Features include:
 * - Basic headers (IP, TCP/UDP)
 * - Derived metrics (entropy, inter-arrival time)
 * - Payload samples
 * - Behavioral flags (retransmit, out-of-order)
 */

/**
 * Extract all features from a packet
 *
 * This builds upon basic parsing to add:
 * - Payload entropy calculation
 * - Payload sampling (first 16 bytes)
 * - TCP MSS extraction
 * - Inter-arrival time (requires flow lookup)
 *
 * @param m         Packet mbuf
 * @param features  Output: extracted features (already has basic parse data)
 * @return 0 on success, -1 on error
 */
int extract_features(struct rte_mbuf *m, struct packet_features *features);

// NOTE: calculate_entropy() REMOVED from hot path
// Payload/header entropy was ~20,000 cycles per packet due to log2()
// Destination port entropy is now tracked via HyperLogLog in per_ip_features
// Source IP entropy is tracked via global HyperLogLog

/**
 * Extract TCP MSS (Maximum Segment Size) from TCP options
 *
 * @param tcp_hdr  TCP header pointer
 * @return MSS value, or 0 if not found
 */
uint16_t extract_tcp_mss(const struct rte_tcp_hdr *tcp_hdr);

#endif // LAYER1_PACKET_FEATURES_H
