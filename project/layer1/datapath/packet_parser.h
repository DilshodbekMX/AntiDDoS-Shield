#ifndef LAYER1_PACKET_PARSER_H
#define LAYER1_PACKET_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include "../../common/types.h"

// ==================== Parsing Return Codes ====================

#define PARSE_OK            0
#define PARSE_NOT_IP       -1
#define PARSE_MALFORMED    -2
#define PARSE_UNSUPPORTED  -3
#define PARSE_IPV6          1   // Parsed successfully as IPv6

// ==================== IPv6 Protocol Constants ====================
// Use system definitions if available, otherwise define them
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6      58  // ICMPv6
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE        59  // No Next Header
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS     60  // Destination Options
#endif
#ifndef IPPROTO_MOBILITY
#define IPPROTO_MOBILITY    135 // Mobility Header
#endif

// IPv6 Extension Header Types
#define IPV6_EXT_HOP_BY_HOP     0   // Hop-by-Hop Options
#define IPV6_EXT_ROUTING        43  // Routing Header
#define IPV6_EXT_FRAGMENT       44  // Fragment Header
#define IPV6_EXT_ESP            50  // Encapsulating Security Payload
#define IPV6_EXT_AH             51  // Authentication Header
#define IPV6_EXT_DEST_OPTIONS   60  // Destination Options

// ==================== Validation Errors ====================

#define VALIDATE_OK                     0
#define VALIDATE_ERR_TOO_SHORT          1
#define VALIDATE_ERR_BAD_IPLEN          2
#define VALIDATE_ERR_BAD_CHECKSUM       3
#define VALIDATE_ERR_ZERO_TTL           4
#define VALIDATE_ERR_INVALID_SRC        5
#define VALIDATE_ERR_INVALID_DST        6
#define VALIDATE_ERR_FRAG_ATTACK        7
#define VALIDATE_ERR_LAND_ATTACK        8
#define VALIDATE_ERR_TCP_NULL           9
#define VALIDATE_ERR_TCP_XMAS           10
#define VALIDATE_ERR_TCP_INVALID        11
#define VALIDATE_ERR_TCP_SHORT          12
#define VALIDATE_ERR_UDP_SHORT          13
#define VALIDATE_ERR_UDP_CHECKSUM       14
#define VALIDATE_ERR_NOT_PROTECTED      15
// IPv6-specific validation errors
#define VALIDATE_ERR_IPV6_EXT_LOOP      16  // Extension header loop
#define VALIDATE_ERR_IPV6_BAD_EXT       17  // Malformed extension header
#define VALIDATE_ERR_IPV6_ROUTING_0     18  // Deprecated Type 0 Routing Header
#define VALIDATE_ERR_IPV6_MULTICAST_SRC 19  // Multicast source address
#define VALIDATE_ERR_IPV6_LOOPBACK      20  // Loopback address from external
#define VALIDATE_ERR_ICMP_CHECKSUM      21  // Bad ICMP checksum

// ==================== Public API ====================

int parse_packet(struct rte_mbuf *m, struct packet_features *features);
int validate_packet(const struct packet_features *features);

/**
 * Initialize the hash seed used by the packet parser for flow key hashing.
 * Must be called once at startup before any packet parsing.
 */
void packet_parser_init_hash_seed(void);

/**
 * Validate IP header checksum.
 *
 * @param m  Packet mbuf (must be IPv4)
 * @return VALIDATE_OK on success, VALIDATE_ERR_BAD_CHECKSUM on failure
 */
int validate_ip_checksum(struct rte_mbuf *m);

/**
 * Validate UDP checksum.
 *
 * @param m  Packet mbuf (must be UDP/IPv4)
 * @return VALIDATE_OK on success, VALIDATE_ERR_UDP_CHECKSUM on failure
 */
int validate_udp_checksum(struct rte_mbuf *m);

/**
 * Validate ICMP checksum.
 *
 * @param m  Packet mbuf (must be ICMP/IPv4)
 * @return VALIDATE_OK on success, VALIDATE_ERR_ICMP_CHECKSUM on failure
 */
int validate_icmp_checksum(struct rte_mbuf *m);

/**
 * Extract CANONICAL flow key from packet features.
 * 
 * Creates a normalized key where ip_lo <= ip_hi, ensuring the same
 * connection always produces the same key regardless of direction.
 *
 * Also sets features->flow_direction to indicate which direction
 * this packet is traveling within the canonical flow.
 *
 * @param features  Packet features (flow_direction will be set)
 * @param key       Output canonical flow key
 */
static inline void extract_flow_key(struct packet_features *features,
                                    struct flow_key *key) {
    // Compare IPs to determine canonical ordering
    // Network byte order comparison is fine - we just need consistency
    if (features->src_ip <= features->dst_ip) {
        key->ip_lo = features->src_ip;
        key->ip_hi = features->dst_ip;
        features->flow_direction = FLOW_DIR_LO_TO_HI;
    } else {
        key->ip_lo = features->dst_ip;
        key->ip_hi = features->src_ip;
        features->flow_direction = FLOW_DIR_HI_TO_LO;
    }
    key->protocol = features->protocol;
    key->_pad[0] = 0;
    key->_pad[1] = 0;
    key->_pad[2] = 0;
}

/**
 * Create canonical flow key from raw IP addresses.
 * Utility function for use outside of packet processing.
 *
 * @param src_ip       Source IP (network byte order)
 * @param dst_ip       Destination IP (network byte order)
 * @param protocol     IP protocol number
 * @param key          Output canonical flow key
 * @param flow_dir_out Output flow direction (can be NULL)
 */
static inline void make_canonical_key(uint32_t src_ip, uint32_t dst_ip,
                                      uint8_t protocol,
                                      struct flow_key *key,
                                      uint8_t *flow_dir_out) {
    if (src_ip <= dst_ip) {
        key->ip_lo = src_ip;
        key->ip_hi = dst_ip;
        if (flow_dir_out) *flow_dir_out = FLOW_DIR_LO_TO_HI;
    } else {
        key->ip_lo = dst_ip;
        key->ip_hi = src_ip;
        if (flow_dir_out) *flow_dir_out = FLOW_DIR_HI_TO_LO;
    }
    key->protocol = protocol;
    key->_pad[0] = 0;
    key->_pad[1] = 0;
    key->_pad[2] = 0;
}

uint32_t compute_flow_hash(const struct flow_key *key);
const char* validation_error_str(int error_code);

// ==================== IPv6 Parsing API ====================

/**
 * Parse packet into dual-stack features structure
 * Handles both IPv4 and IPv6 packets.
 *
 * @param m         Packet mbuf
 * @param features  Output features structure (192 bytes)
 * @return PARSE_OK for IPv4, PARSE_IPV6 for IPv6, negative on error
 */
int parse_packet_v6(struct rte_mbuf *m, struct packet_features_v6 *features);

/**
 * Validate IPv6 packet
 *
 * @param features  Parsed IPv6 packet features
 * @return VALIDATE_OK on success, error code on failure
 */
int validate_packet_v6(const struct packet_features_v6 *features);

/**
 * Extract CANONICAL flow key from dual-stack packet features.
 *
 * @param features  Packet features (flow_direction will be set)
 * @param key       Output canonical flow key (IPv6)
 */
static inline void extract_flow_key_v6(struct packet_features_v6 *features,
                                       struct flow_key_v6 *key) {
    int cmp = memcmp(features->src_ip.v6, features->dst_ip.v6, 16);

    if (cmp <= 0) {
        memcpy(key->ip_lo, features->src_ip.v6, 16);
        memcpy(key->ip_hi, features->dst_ip.v6, 16);
        features->flow_direction = FLOW_DIR_LO_TO_HI;
    } else {
        memcpy(key->ip_lo, features->dst_ip.v6, 16);
        memcpy(key->ip_hi, features->src_ip.v6, 16);
        features->flow_direction = FLOW_DIR_HI_TO_LO;
    }
    key->protocol = features->protocol;
    key->_pad[0] = 0;
    key->_pad[1] = 0;
    key->_pad[2] = 0;
}

/**
 * Compute flow hash for IPv6 flow key
 *
 * @param key  IPv6 flow key (36 bytes)
 * @return 32-bit hash value
 */
uint32_t compute_flow_hash_v6(const struct flow_key_v6 *key);

/**
 * Check if IPv6 address is link-local (fe80::/10)
 */
static inline bool ipv6_is_link_local(const uint8_t addr[16]) {
    return (addr[0] == 0xfe) && ((addr[1] & 0xc0) == 0x80);
}

/**
 * Check if IPv6 address is multicast (ff00::/8)
 */
static inline bool ipv6_is_multicast(const uint8_t addr[16]) {
    return addr[0] == 0xff;
}

/**
 * Check if IPv6 address is loopback (::1)
 */
static inline bool ipv6_is_loopback(const uint8_t addr[16]) {
    static const uint8_t loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    return memcmp(addr, loopback, 16) == 0;
}

/**
 * Check if IPv6 address is unspecified (::)
 */
static inline bool ipv6_is_unspecified(const uint8_t addr[16]) {
    return ipv6_is_zero(addr);
}

// ==================== TTL Handling ====================

/**
 * Check if packet TTL allows forwarding.
 * Returns false if TTL <= 1 (would become 0 after decrement).
 *
 * @param m  Packet mbuf
 * @return true if TTL > 1, false if packet should be dropped
 */
bool check_ttl_for_forwarding(struct rte_mbuf *m);

/**
 * Decrement TTL and update IP checksum.
 * Call this before forwarding a packet.
 *
 * @param m  Packet mbuf
 * @return 0 on success, -1 if TTL would become 0
 */
int decrement_ttl(struct rte_mbuf *m);

#endif // LAYER1_PACKET_PARSER_H