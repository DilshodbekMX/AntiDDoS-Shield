#ifndef LAYER1_IP_LISTS_H
#define LAYER1_IP_LISTS_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_hash.h>

/**
 * @file ip_lists.h
 * @brief Fast IP whitelist and blacklist using DPDK hash tables and LPM
 *
 * Features:
 * - Lock-free lookups for multi-core safety
 * - Hash-based O(1) lookup for exact IP matches
 * - LPM (Longest Prefix Match) for CIDR range whitelist
 * - Support for both whitelist and blacklist
 * - Whitelist takes priority over blacklist
 *
 * Whitelist lookup order:
 * 1. Exact IP match (hash table) - O(1)
 * 2. CIDR prefix match (LPM) - O(1) DIR-24-8 algorithm
 */

// ==================== Configuration ====================

struct ip_lists_config {
    uint32_t max_whitelist_entries;   // Maximum whitelist entries (default: 10000)
    uint32_t max_blacklist_entries;   // Maximum blacklist entries (default: 100000)
    uint32_t max_protected_entries;   // Maximum protected server entries (default: 1000)
    uint32_t max_whitelist_cidrs;     // Maximum CIDR whitelist entries (default: 1000)
    bool     enforce_protected_ips;   // If true, only allow traffic to protected IPs
};

// ==================== Whitelist Modes ====================

/**
 * Whitelist mode controls packet handling for whitelisted IPs.
 * WL_MODE_BYPASS: Accept immediately, skip all further checks.
 * WL_MODE_TRACK:  Continue through pipeline but never drop (tracking only).
 */
enum wl_mode {
    WL_MODE_BYPASS = 0,  // Accept immediately (default)
    WL_MODE_TRACK  = 1,  // Pass through pipeline, never drop
};

// ==================== Public API ====================

/**
 * Initialize IP lists
 *
 * @param config  Configuration parameters
 * @return 0 on success, -1 on error
 */
int ip_lists_init(const struct ip_lists_config *config);

/**
 * Cleanup IP lists and free resources
 */
void ip_lists_cleanup(void);

// ==================== Whitelist Operations ====================

/**
 * Add IP to whitelist with mode
 *
 * @param ip    IP address in network byte order
 * @param mode  WL_MODE_BYPASS or WL_MODE_TRACK
 * @return 0 on success, -1 on error
 */
int ip_whitelist_add(uint32_t ip, uint8_t mode);

/**
 * Remove IP from whitelist
 *
 * @param ip  IP address in network byte order
 * @return 0 on success, -1 if not found
 */
int ip_whitelist_remove(uint32_t ip);

/**
 * Check if IP is whitelisted and return its mode
 *
 * @param ip    IP address in network byte order
 * @param mode  Output: whitelist mode (may be NULL)
 * @return true if whitelisted, false otherwise
 */
bool ip_whitelist_lookup(uint32_t ip, uint8_t *mode);

/**
 * Clear all whitelist entries
 */
void ip_whitelist_clear(void);

/**
 * Get number of whitelist entries
 *
 * @return Number of entries
 */
uint32_t ip_whitelist_count(void);

// ==================== CIDR Whitelist Operations (LPM) ====================

/**
 * Add CIDR prefix to whitelist
 *
 * Uses DPDK LPM for fast prefix matching. All IPs within the prefix
 * will be treated as whitelisted.
 *
 * Example: ip_whitelist_cidr_add(0xC629C000, 17) for 198.41.192.0/17 (Cloudflare)
 *
 * @param ip_prefix  IP prefix in host byte order (e.g., 0xC629C000 for 198.41.192.0)
 * @param depth      Prefix length (1-32)
 * @return 0 on success, -1 on error
 */
int ip_whitelist_cidr_add(uint32_t ip_prefix, uint8_t depth);

/**
 * Remove CIDR prefix from whitelist
 *
 * @param ip_prefix  IP prefix in host byte order
 * @param depth      Prefix length (1-32)
 * @return 0 on success, -1 if not found
 */
int ip_whitelist_cidr_remove(uint32_t ip_prefix, uint8_t depth);

/**
 * Check if IP matches any whitelisted CIDR prefix
 *
 * @param ip  IP address in host byte order
 * @return true if IP is within a whitelisted prefix, false otherwise
 */
bool ip_whitelist_cidr_lookup(uint32_t ip);

/**
 * Clear all CIDR whitelist entries
 */
void ip_whitelist_cidr_clear(void);

/**
 * Get number of CIDR whitelist entries
 *
 * @return Number of CIDR prefixes
 */
uint32_t ip_whitelist_cidr_count(void);

// ==================== Blacklist Operations ====================

/**
 * Add IP to blacklist
 *
 * Blacklisted IPs are dropped immediately.
 * Use for known attackers, malicious sources, etc.
 *
 * @param ip  IP address in network byte order
 * @return 0 on success, -1 on error
 */
int ip_blacklist_add(uint32_t ip);

/**
 * Remove IP from blacklist
 *
 * @param ip  IP address in network byte order
 * @return 0 on success, -1 if not found
 */
int ip_blacklist_remove(uint32_t ip);

/**
 * Check if IP is blacklisted
 *
 * @param ip  IP address in network byte order
 * @return true if blacklisted, false otherwise
 */
bool ip_blacklist_lookup(uint32_t ip);

/**
 * Clear all blacklist entries
 */
void ip_blacklist_clear(void);

/**
 * Get number of blacklist entries
 *
 * @return Number of entries
 */
uint32_t ip_blacklist_count(void);

// ==================== Protected Server IPs ====================

/**
 * Add IP to protected servers list
 *
 * Protected server IPs are the backend servers we're protecting.
 * When enforce_protected_ips is enabled, only packets destined to
 * these IPs are processed.
 *
 * @param ip  IP address in network byte order
 * @return 0 on success, -1 on error
 */
int ip_protected_add(uint32_t ip);

/**
 * Remove IP from protected servers list
 *
 * @param ip  IP address in network byte order
 * @return 0 on success, -1 if not found
 */
int ip_protected_remove(uint32_t ip);

/**
 * Check if IP is a protected server
 *
 * @param ip  IP address in network byte order
 * @return true if protected, false otherwise
 */
bool ip_protected_lookup(uint32_t ip);

/**
 * Clear all protected server entries
 */
void ip_protected_clear(void);

/**
 * Get number of protected server entries
 *
 * @return Number of entries
 */
uint32_t ip_protected_count(void);

// ==================== Protected Subnets (CIDR aggregate tracking) ====================

/**
 * Add a protected SUBNET (CIDR).
 *
 * Unlike a protected /32, a protected subnet causes ALL traffic to any address
 * inside it to be aggregated into a SINGLE per-IP feature slot keyed by the
 * subnet's network address. This lets Layer 2 detect carpet-bombs spread across
 * many (incl. unregistered) destinations in the subnet that no single IP would
 * trip. An exact protected /32 always wins over a covering subnet (longest prefix).
 *
 * @param ip_prefix  Network prefix in HOST byte order (e.g. 0x0A000500 for 10.0.5.0)
 * @param depth      Prefix length, 1-31 (use ip_protected_add() for /32)
 * @return 0 on success, -1 on error
 */
int ip_protected_subnet_add(uint32_t ip_prefix, uint8_t depth);

/**
 * Remove a protected subnet.
 * @param ip_prefix  Network prefix in HOST byte order
 * @param depth      Prefix length, 1-31
 * @return 0 on success, -1 if not found
 */
int ip_protected_subnet_remove(uint32_t ip_prefix, uint8_t depth);

/**
 * Longest-prefix lookup: does dst_ip fall inside a protected subnet?
 *
 * @param dst_ip       Destination IP in NETWORK byte order (as seen in packets)
 * @param net_be_out   On hit, set to the matched subnet's network address in
 *                     NETWORK byte order (the per-IP tracking key for the subnet)
 * @return true if dst_ip is inside a protected subnet, false otherwise
 */
bool ip_protected_subnet_lookup(uint32_t dst_ip, uint32_t *net_be_out);

/** Remove all protected subnets. */
void ip_protected_subnet_clear(void);

/** @return number of registered protected subnets. */
uint32_t ip_protected_subnet_count(void);

/**
 * Pure policy: pick the per-IP feature tracking key for a destination.
 *
 * This is the single source of truth for the Stage-3c keying decision, factored
 * out so it can be unit-tested without DPDK EAL (it does no lookups itself -- the
 * caller supplies the lookup results):
 *   - an exact protected /32 keeps its own slot (longest-prefix wins);
 *   - otherwise an address in a protected subnet aggregates into the subnet's
 *     single slot (keyed by the subnet network);
 *   - otherwise the destination itself (the per-IP lookup then misses -> untracked).
 *
 * @param dst_ip_be            destination IP, network byte order
 * @param exact_registered     true if dst_ip is an exact protected /32
 * @param in_protected_subnet  true if dst_ip falls in a protected subnet
 * @param subnet_network_be    matched subnet network (network byte order),
 *                             meaningful only when in_protected_subnet is true
 * @return the per-IP tracking key (network byte order)
 */
static inline uint32_t l1_resolve_track_key(uint32_t dst_ip_be,
                                            bool exact_registered,
                                            bool in_protected_subnet,
                                            uint32_t subnet_network_be) {
    if (exact_registered)     return dst_ip_be;
    if (in_protected_subnet)  return subnet_network_be;
    return dst_ip_be;
}

/**
 * Check if protected IP enforcement is enabled
 *
 * @return true if enforcement is enabled
 */
bool ip_protected_enforcement_enabled(void);

/**
 * Set protected IP enforcement mode (called during config reload)
 *
 * @param enabled  true to enable enforcement, false to disable
 */
void ip_protected_set_enforcement(bool enabled);

// ==================== Statistics ====================

/**
 * Get IP lists statistics
 *
 * @param whitelist_count  Output: current whitelist entries
 * @param blacklist_count  Output: current blacklist entries
 * @param whitelist_hits   Output: total whitelist hits
 * @param blacklist_hits   Output: total blacklist hits
 */
void ip_lists_get_stats(uint32_t *whitelist_count, uint32_t *blacklist_count,
                        uint64_t *whitelist_hits, uint64_t *blacklist_hits);

/**
 * Print IP lists statistics
 */
void ip_lists_print_stats(void);

// ==================== Persistence (Save/Load) ====================

/**
 * Default path for IP lists persistence file
 */
// Use relative path from project root (configurable at runtime)
#define IP_LISTS_DEFAULT_PATH "layer1/config/ip_lists.json"

/**
 * Save all IP lists to JSON file
 * Saves: whitelist, blacklist, protected IPs
 *
 * @param path  Path to JSON file (NULL = default path)
 * @return 0 on success, -1 on error
 */
int ip_lists_save(const char *path);

/**
 * Load IP lists from JSON file
 * Loads: whitelist, blacklist, protected IPs
 * Note: Must be called AFTER ip_lists_init()
 *
 * @param path  Path to JSON file (NULL = default path)
 * @return 0 on success, -1 on error
 */
int ip_lists_load(const char *path);

/**
 * Get all protected IPs (for iteration)
 *
 * @param ips     Output array of IPs (network byte order)
 * @param max_ips Maximum number of IPs to return
 * @return Number of IPs returned
 */
uint32_t ip_protected_get_all(uint32_t *ips, uint32_t max_ips);

/**
 * Get all whitelist IPs (for iteration)
 *
 * @param ips     Output array of IPs (network byte order)
 * @param max_ips Maximum number of IPs to return
 * @return Number of IPs returned
 */
uint32_t ip_whitelist_get_all(uint32_t *ips, uint32_t max_ips);

/**
 * Get all blacklist IPs (for iteration)
 *
 * @param ips     Output array of IPs (network byte order)
 * @param max_ips Maximum number of IPs to return
 * @return Number of IPs returned
 */
uint32_t ip_blacklist_get_all(uint32_t *ips, uint32_t max_ips);

// ==================== rte_flow Hardware Offload ====================

/**
 * Enable hardware offload for IP blacklist using rte_flow
 *
 * When enabled, blacklisted IPs will be dropped in NIC hardware,
 * bypassing the CPU entirely. This is most effective for permanent
 * blacklist entries (known bad actors, botnets, etc.).
 *
 * @param port_id  DPDK port ID
 * @return 0 on success, -1 if hardware doesn't support rte_flow
 */
int ip_blacklist_hw_offload_init(uint16_t port_id);

/**
 * Disable hardware offload and remove all hardware rules
 *
 * @param port_id  DPDK port ID
 */
void ip_blacklist_hw_offload_cleanup(uint16_t port_id);

/**
 * Check if hardware offload is enabled for a port
 *
 * @param port_id  DPDK port ID
 * @return true if hardware offload is active
 */
bool ip_blacklist_hw_offload_enabled(uint16_t port_id);

/**
 * Add IP to blacklist with hardware offload (if enabled)
 *
 * If hardware offload is enabled, creates an rte_flow DROP rule.
 * Always adds to software blacklist as fallback.
 *
 * @param port_id  DPDK port ID (use RTE_MAX_ETHPORTS for software-only)
 * @param ip       IP address in network byte order
 * @return 0 on success, -1 on error
 */
int ip_blacklist_add_hw(uint16_t port_id, uint32_t ip);

/**
 * Remove IP from blacklist with hardware offload cleanup
 *
 * @param port_id  DPDK port ID
 * @param ip       IP address in network byte order
 * @return 0 on success, -1 if not found
 */
int ip_blacklist_remove_hw(uint16_t port_id, uint32_t ip);

/**
 * Get hardware offload statistics
 *
 * @param port_id       DPDK port ID
 * @param hw_rules      Output: number of active hardware rules
 * @param hw_add_ok     Output: successful hardware rule creations
 * @param hw_add_fail   Output: failed hardware rule creations
 */
void ip_blacklist_hw_get_stats(uint16_t port_id, uint32_t *hw_rules,
                               uint64_t *hw_add_ok, uint64_t *hw_add_fail);

// ==================== Protection Profiles ====================
// Per-destination-IP traffic filtering profiles

// Protocol action values for protection profiles
#define PROFILE_PROTO_DROP        0   // Drop all packets of this protocol
#define PROFILE_PROTO_RATE_LIMIT  1   // Rate-limit packets of this protocol
#define PROFILE_PROTO_ALLOW       2   // Allow packets of this protocol (default)

// SYN proxy mode for protection profiles
#define PROFILE_SYN_PROXY_DEFAULT   0  // Use global SYN proxy setting
#define PROFILE_SYN_PROXY_DISABLED  1  // Disable SYN proxy for this destination

#define MAX_PROFILE_TCP_PORTS   32
#define MAX_PROFILE_UDP_PORTS   32
#define MAX_PROFILE_OTHER_PROTOS 8

struct protection_profile {
    uint32_t pps_limit;             // PPS limit for this IP (0=unlimited)
    uint32_t bps_limit;             // BPS limit for this IP (0=unlimited)
    uint32_t attack_pps_limit;      // PPS limit during attack mode
    uint32_t attack_bps_limit;      // BPS limit during attack mode

    // Per-protocol action (indexed by IP proto number, 0..2 = drop/rate-limit/allow)
    uint8_t  proto_default_action;  // Default action for protocols not in lists
    uint8_t  _pad[3];

    // TCP port allowlist (if tcp_port_count>0, only listed ports pass)
    uint16_t tcp_ports[MAX_PROFILE_TCP_PORTS];
    uint8_t  tcp_port_count;

    // UDP port allowlist
    uint16_t udp_ports[MAX_PROFILE_UDP_PORTS];
    uint8_t  udp_port_count;

    // Other IP protocol allowlist
    uint8_t  other_allowed_protos[MAX_PROFILE_OTHER_PROTOS];
    uint8_t  other_proto_count;

    // Shared-memory anomaly slot (-1 = no slot assigned)
    int32_t  anomaly_slot_idx;

    // SYN proxy mode override (PROFILE_SYN_PROXY_DEFAULT or PROFILE_SYN_PROXY_DISABLED)
    uint8_t  syn_proxy_mode;
    uint8_t  _pad2[3];
};

/**
 * Look up protected IP and return its profile (no position).
 * Returns true if IP is protected.
 */
bool ip_protected_lookup_profile(uint32_t ip,
                                 const struct protection_profile **profile);

/**
 * Look up protected IP and return its profile and hash position.
 * pos is used for per-protocol rate counter indexing.
 * Returns true if IP is protected.
 */
bool ip_protected_lookup_profile_pos(uint32_t ip,
                                     const struct protection_profile **profile,
                                     int32_t *pos);

/**
 * Check whether this protocol is within its per-profile rate limit.
 * Returns true if the packet should be allowed.
 */
bool ip_protected_proto_rate_check(int32_t pos, uint8_t protocol,
                                   uint32_t limit_pps);

/**
 * Mark source IP as legitimate after passing SYN proxy challenge.
 */
void legitimate_ip_add(uint32_t src_ip);

/**
 * Remove expired entries from the legitimate IP table.
 * Called periodically to prevent unbounded growth.
 *
 * @return Number of entries removed
 */
uint32_t legitimate_ip_cleanup(void);

/**
 * Reset per-protocol rate counters for all protected IPs.
 * Called at the start of each rate-limit window.
 */
void ip_protected_proto_counters_reset(void);

/**
 * Get the protocol action for a protection profile.
 * Returns PROFILE_PROTO_DROP, PROFILE_PROTO_RATE_LIMIT, or PROFILE_PROTO_ALLOW.
 */
uint8_t profile_proto_action(const struct protection_profile *p, uint8_t proto);

/**
 * Check if a TCP or UDP port is allowed by a protection profile.
 * Returns true if allowed (or profile has no port filter for that proto).
 */
bool profile_port_allowed(const struct protection_profile *p,
                           uint8_t proto, uint16_t port);

/**
 * Check if an "other" IP protocol is in the allowed list.
 * Returns true if allowed (or profile has no other-proto filter).
 */
bool profile_other_proto_allowed(const struct protection_profile *p,
                                  uint8_t proto);

/**
 * Get rate-limit PPS for a given protocol in a protection profile.
 * Returns 0 if no rate limit configured.
 */
uint32_t profile_proto_rate_limit(const struct protection_profile *p,
                                   uint8_t proto);

#endif // LAYER1_IP_LISTS_H
