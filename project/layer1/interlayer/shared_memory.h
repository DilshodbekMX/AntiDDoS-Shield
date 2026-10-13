#ifndef LAYER1_SHARED_MEMORY_H
#define LAYER1_SHARED_MEMORY_H

#include <stdint.h>
#include <stdbool.h>
#include "../../common/types.h"

/**
 * @file shared_memory.h
 * @brief Shared memory structures for inter-layer communication
 *
 * ============================================================================
 *                          THREAD SAFETY STRATEGY
 * ============================================================================
 *
 * This shared memory region is accessed by multiple components:
 * - Layer 1 data plane (multiple lcores, lock-free reads)
 * - Layer 3 Attribution Engine (single Python process, writes)
 * - Layer 4 Reputation System (single Python process, writes)
 *
 * LOCKING MODEL:
 *
 * 1. POLICY TABLE (policy_interface.c):
 *    - READERS (Layer 1 lcores): Lock-free using atomic count reads
 *      * Read global_version and count atomically
 *      * Iterate through entries (safe: writers only append or compact)
 *      * Memory barriers ensure data visibility
 *    - WRITERS (Layer 3): Protected by rte_spinlock_t
 *      * Single writer at a time holds policy_lock
 *      * Increment global_version after modifications
 *      * Use rte_smp_wmb() before updating count
 *    - SAFE OPERATIONS:
 *      * policy_lookup(): Lock-free, thread-safe
 *      * policy_add/remove/clear_all(): Spinlock protected
 *
 * 2. REPUTATION TABLE (reputation_interface.c):
 *    - Uses rte_hash with RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY
 *    - READERS: Lock-free O(1) hash lookup
 *    - WRITERS: DPDK internal locking within rte_hash operations
 *    - Entry updates use atomic operations (__atomic_store_n)
 *    - SAFE OPERATIONS:
 *      * reputation_lookup(): Lock-free, thread-safe
 *      * reputation_update/remove(): DPDK hash provides internal locking
 *      * reputation_adjust(): Per-entry atomic updates
 *
 * 3. FEEDBACK QUEUE:
 *    - Single-producer (Layer 1) / single-consumer (Layer 3/4) model
 *    - head/tail pointers updated atomically
 *    - No explicit locking required for SPSC pattern
 *
 * 4. GLOBAL STATE:
 *    - All fields are atomically accessed
 *    - anomaly_* functions use atomic loads/stores
 *    - No locking required
 *
 * MEMORY BARRIERS:
 * - rte_smp_wmb(): Write memory barrier before publishing new data
 * - rte_smp_rmb(): Read memory barrier after reading version (if needed)
 * - __atomic_*_n with RELEASE/ACQUIRE semantics for inter-core visibility
 *
 * VERSIONING:
 * - global_version fields allow readers to detect concurrent modifications
 * - Readers can optionally re-read if version changed during operation
 * - Currently not implemented as a retry loop (single-pass reads are safe)
 *
 * IMPORTANT INVARIANTS:
 * - Policy table entries are never modified in-place after creation
 *   (updates create new entries, removes compact the table)
 * - Reputation entries can be modified in-place using atomic operations
 * - Expired flags prevent reading stale data before hash deletion
 *
 * ============================================================================
 */

// ==================== NOTE: enum policy_action is in types.h ====================

// ==================== Layer 3 Structures ====================
// Include headers for Layer 3 communication structures
#include "dynamic_signatures.h"
#include "packet_ring.h"
#include "src_ip_stats.h"

// ==================== Policy Table ====================

struct policy_entry {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  _pad1;

    enum policy_action action;

    uint32_t rate_limit_pps;
    uint32_t rate_limit_bps;

    uint32_t priority;
    uint64_t expiry_timestamp;
    uint64_t version;

    uint8_t  _pad2[8];
} __attribute__((aligned(64)));

#define MAX_POLICIES 10000

struct policy_table {
    struct policy_entry entries[MAX_POLICIES];
    uint32_t count;
    uint64_t global_version;
    uint8_t  _pad[52];
} __attribute__((aligned(64)));

// ==================== Reputation Table ====================

struct reputation_entry {
    uint32_t ip;
    uint16_t score;
    uint16_t confidence;

    uint64_t last_updated_ns;
    uint32_t packet_count;
    uint32_t attack_count;

    uint8_t  flags;
    uint8_t  _pad[7];
} __attribute__((aligned(32)));

#define REP_FLAG_IS_ATTACKER  0x01
#define REP_FLAG_IS_TRUSTED   0x02
#define REP_FLAG_IS_EXPIRED   0x04
#define REP_FLAG_IS_BUILDING  0x08  // Entry is being initialized - readers should skip

#define MAX_REPUTATION_ENTRIES 100000

struct reputation_table {
    struct reputation_entry entries[MAX_REPUTATION_ENTRIES];
    uint32_t count;
    uint64_t global_version;
    uint8_t  _pad[52];
} __attribute__((aligned(64)));

// ==================== Feedback Queue ====================

enum feedback_event_type {
    FEEDBACK_SYN_FLOOD = 1,
    FEEDBACK_RATE_LIMIT_EXCEEDED,
    FEEDBACK_INVALID_PACKET,
    FEEDBACK_CONNECTION_LIMIT,
    FEEDBACK_ATTACK_MITIGATED
};

struct feedback_event {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  event_type;

    uint64_t timestamp_ns;
    uint32_t packet_count;
    uint32_t severity;

    uint8_t  _pad[8];
} __attribute__((aligned(32)));

#define MAX_FEEDBACK_EVENTS 10000

struct feedback_queue {
    struct feedback_event events[MAX_FEEDBACK_EVENTS];
    uint32_t head;
    uint32_t tail;
    uint8_t  _pad[56];
} __attribute__((aligned(64)));

// ==================== Global State Flags ====================

struct global_state {
    uint32_t anomaly_active;         // Non-zero if attack/anomaly detected
    uint32_t anomaly_level;          // Severity level (0=none, 1=low, 2=medium, 3=high, 4=critical)
    uint64_t anomaly_start_ns;       // When anomaly was first detected
    uint64_t last_anomaly_update_ns; // Last time anomaly state was updated

    // Traffic stats for anomaly detection
    uint64_t total_pps;              // Current packets per second
    uint64_t total_bps;              // Current bytes per second
    uint64_t baseline_pps;           // Normal baseline PPS
    uint64_t baseline_bps;           // Normal baseline BPS

    // Dynamic rate limit multipliers (100 = 100% = normal)
    uint32_t rate_limit_pct;         // Current rate limit as % of normal (e.g., 50 = 50%)

    // Spoofed attack mode
    uint32_t spoofed_attack_mode;    // Non-zero if IP spoofing detected
    uint32_t randomness_pct;         // Estimated % of random/spoofed source IPs
    uint32_t mitigation_active;      // Non-zero if active mitigation is running

    uint8_t  _pad[16];
} __attribute__((aligned(64)));

// Anomaly levels
#define ANOMALY_LEVEL_NONE     0
#define ANOMALY_LEVEL_LOW      1
#define ANOMALY_LEVEL_MEDIUM   2
#define ANOMALY_LEVEL_HIGH     3
#define ANOMALY_LEVEL_CRITICAL 4

// ==================== Per-IP Features Export (for per-IP detection) ====================

/**
 * Maximum number of protected IPs to export to Layer 2
 * Keep reasonable to limit shared memory size
 */
#define MAX_PROTECTED_IPS_EXPORT 64

/**
 * Per-protected-IP features snapshot
 * Same features as l2_features_export but tracked per destination IP
 */
struct l2_per_ip_features_export {
    // Destination IP being protected (network byte order)
    uint32_t dst_ip;
    uint32_t active;                // 1 if slot is active, 0 if free

    // Timestamp
    uint64_t timestamp_ns;
    uint64_t window_duration_ns;

    // ===== VOLUME FEATURES =====
    uint64_t packets_per_sec;
    uint64_t bytes_per_sec;
    uint32_t flows_per_sec;

    // ===== TCP FLAG FEATURES =====
    uint32_t syn_per_sec;
    uint32_t syn_ack_per_sec;
    uint32_t ack_per_sec;
    uint32_t rst_per_sec;
    uint32_t fin_per_sec;

    // ===== PROTOCOL MIX FEATURES =====
    uint32_t tcp_packets;
    uint32_t udp_packets;
    uint32_t icmp_packets;
    uint32_t other_packets;
    uint8_t  tcp_ratio;
    uint8_t  udp_ratio;
    uint8_t  icmp_ratio;
    uint8_t  _pad1;

    // ===== RATIO FEATURES =====
    uint16_t syn_ack_ratio;
    uint16_t rst_syn_ratio;
    uint16_t bytes_per_packet;
    uint16_t _pad2;

    // ===== CARDINALITY FEATURES (HyperLogLog) =====
    uint32_t unique_src_ips;
    uint32_t unique_src_ports;
    uint32_t unique_dst_ports;
    uint32_t unique_flows;

    // ===== CHURN FEATURES =====
    int32_t  src_ip_churn;
    int32_t  dst_port_churn;
    int32_t  expired_srcip_rate;

    // ===== CONCENTRATION FEATURES (Count-Min Sketch) =====
    uint8_t  max_flow_fraction;
    uint8_t  topk_flow_share;
    uint16_t heavy_hitter_count;

    // ===== FLOW BEHAVIOR FEATURES =====
    uint16_t avg_packets_per_flow;
    uint32_t flow_duration_avg_ms;

    // ===== METADATA =====
    uint32_t active_flows;
    uint32_t sample_count;
    uint64_t total_packets;

    uint8_t  _pad3[4];

    // ===== TCP FLAG RATIO FEATURES =====
    uint8_t  syn_tcp_ratio;        // SYN as % of TCP packets
    uint8_t  synack_tcp_ratio;     // SYN-ACK as % of TCP packets
    uint8_t  ack_tcp_ratio;        // ACK as % of TCP packets
    uint8_t  rst_tcp_ratio;        // RST as % of TCP packets
    uint8_t  fin_tcp_ratio;        // FIN as % of TCP packets

    // ===== BURST AND DERIVED FEATURES =====
    uint16_t burst_factor;         // Current PPS / EWMA PPS * 100
    uint16_t udp_flow_ratio;       // UDP flows / UDP PPS * 100
    uint16_t dst_port_density;     // Unique dst ports / PPS * 1000
    uint8_t  icmp_echo_ratio;      // ICMP echo / ICMP total * 100
    uint8_t  small_pkt_ratio;      // Packets<=64B as % of total
    uint8_t  tcp_completion_rate;  // SYN-ACK / SYN * 100
    uint8_t  fragment_ratio;       // Fragment packets as % of total
    uint8_t  src_port_entropy;     // Source port entropy
    uint8_t  ttl_mean;             // Mean IP TTL value
    uint8_t  _pad4[2];             // Alignment
} __attribute__((aligned(64)));

// Protocol category constants for anomaly detection
#define PROTO_CAT_TCP    0   // TCP traffic anomaly
#define PROTO_CAT_UDP    1   // UDP traffic anomaly
#define PROTO_CAT_ICMP   2   // ICMP traffic anomaly
#define PROTO_CAT_OTHER  3   // Other protocol anomaly
#define PROTO_CAT_ALL    255 // All protocols (global anomaly)

// Attack type classification
#define ATTACK_TYPE_UNKNOWN        0
#define ATTACK_TYPE_SYN_FLOOD      1
#define ATTACK_TYPE_UDP_FLOOD      2
#define ATTACK_TYPE_ICMP_FLOOD     3
#define ATTACK_TYPE_DNS_AMP        4
#define ATTACK_TYPE_NTP_AMP        5
#define ATTACK_TYPE_MEMCACHED_AMP  6
#define ATTACK_TYPE_HTTP_FLOOD     7
#define ATTACK_TYPE_SLOWLORIS      8
#define ATTACK_TYPE_ACK_FLOOD      9
#define ATTACK_TYPE_RST_FLOOD     10
#define ATTACK_TYPE_FRAG_FLOOD    11

/**
 * Per-IP anomaly state - written by Layer 2, read by Layer 1 and Layer 3
 * One entry per protected IP
 *
 * Layer 2 sets anomaly_protocol to indicate which protocol category
 * triggered the anomaly. Layer 3 uses this to filter packet sampling
 * and feature collection to only the relevant protocol.
 */
struct per_ip_anomaly_state {
    uint32_t dst_ip;                 // Protected IP (network byte order)
    uint32_t active;                 // 1 if slot is active
    uint32_t anomaly_active;         // Non-zero if anomaly detected for this IP
    uint32_t anomaly_level;          // ANOMALY_LEVEL_*
    uint64_t anomaly_start_ns;       // When anomaly started
    uint64_t last_update_ns;         // Last time state was updated

    // Detection metadata
    double   max_z_score;            // Highest z-score detected
    uint32_t tier_agreement;         // Number of tiers agreeing on anomaly
    uint32_t anomalous_feature_count; // Number of features flagged

    // Protocol-specific anomaly info
    uint8_t  anomaly_protocol;       // PROTO_CAT_* - which protocol category is anomalous
    uint8_t  attack_type;            // ATTACK_TYPE_* - classified attack type
    uint16_t anomaly_dst_port;       // Specific port under attack (0 = all ports)

    // Traffic behavior scores (0-100)
    uint8_t  flash_crowd_score;      // Flash-crowd probability (0=attack, 100=legit)
    uint8_t  syn_completion_pct;     // SYN->ESTABLISHED completion rate
    uint8_t  response_ratio_pct;     // Response/request ratio for UDP/ICMP

    // Per-IP mitigation state
    uint8_t  spoofed_mode;           // Per-IP spoofed mode flag
    uint8_t  randomness_pct;         // % of random/spoofed sources for this IP
    uint8_t  rate_limit_pct;         // Per-IP rate limit % (100 = no limit)

    // Detection method details
    uint8_t  detection_method;       // Which detection algorithm triggered
    uint8_t  sensitivity_preset;     // Sensitivity level in effect
    uint8_t  learning_phase;         // Still in learning phase flag
    uint8_t  tier1_progress;         // Tier-1 learning progress (0-100)
    uint8_t  peak_z_feature;         // Feature index with highest z-score
    uint8_t  cusum_triggered;        // CUSUM detector fired
    uint8_t  jsd_triggered;          // JSD detector fired
    uint8_t  fast_triggered;         // Fast detector fired
    uint8_t  confidence;             // Detection confidence (0-100)
    uint8_t  severity;               // Attack severity score (0-100)
    uint16_t cool_down_remaining;    // Seconds remaining in cool-down

    uint8_t  _pad[0];                // No padding needed -- struct fits in 128B slot
} __attribute__((aligned(64)));

/**
 * Per-IP features and anomaly state container
 */
struct l2_per_ip_export {
    uint64_t version;                                      // Seqlock version
    uint32_t active_count;                                 // Number of active protected IPs
    uint32_t _pad;
    struct l2_per_ip_features_export features[MAX_PROTECTED_IPS_EXPORT];
    struct per_ip_anomaly_state anomaly[MAX_PROTECTED_IPS_EXPORT];
} __attribute__((aligned(64)));

// ==================== Layer 2 Features Export (Global/Aggregated) ====================

/**
 * Layer 2 features snapshot - exported every second for anomaly detection
 * This structure is written by Layer 1 and read by Layer 2 (Python)
 *
 * Thread safety:
 * - WRITER (Layer 1 control thread): Calls l2_features_export_update() every second
 * - READER (Layer 2 Python): Reads via mmap, uses version field to detect changes
 * - Single writer, multiple readers pattern (safe with version check)
 */
struct l2_features_export {
    // Version for change detection (odd = write in progress, even = stable)
    uint64_t version;

    // Timestamp
    uint64_t timestamp_ns;          // Nanoseconds since epoch
    uint64_t window_duration_ns;    // Actual window duration

    // ===== VOLUME FEATURES =====
    uint64_t packets_per_sec;       // Total packets/sec
    uint64_t bytes_per_sec;         // Total bytes/sec
    uint32_t flows_per_sec;         // New flows/sec

    // ===== TCP FLAG FEATURES =====
    uint32_t syn_per_sec;           // SYN packets/sec (pure SYN, no ACK)
    uint32_t syn_ack_per_sec;       // SYN-ACK packets/sec
    uint32_t ack_per_sec;           // ACK packets/sec
    uint32_t rst_per_sec;           // RST packets/sec
    uint32_t fin_per_sec;           // FIN packets/sec

    // ===== PROTOCOL MIX FEATURES =====
    uint32_t tcp_packets;           // TCP packet count this window
    uint32_t udp_packets;           // UDP packet count this window
    uint32_t icmp_packets;          // ICMP packet count this window
    uint32_t other_packets;         // Other protocol count
    uint8_t  tcp_ratio;             // TCP % (0-100)
    uint8_t  udp_ratio;             // UDP % (0-100)
    uint8_t  icmp_ratio;            // ICMP % (0-100)
    uint8_t  _pad1;

    // ===== RATIO FEATURES =====
    uint16_t syn_ack_ratio;         // SYN / ACK * 100 (0 = no SYN flood)
    uint16_t rst_syn_ratio;         // RST / SYN * 100
    uint16_t bytes_per_packet;      // Average bytes per packet
    uint16_t _pad2;

    // ===== CARDINALITY FEATURES (HyperLogLog) =====
    uint32_t unique_src_ips;        // Unique source IPs (HLL estimate)
    uint32_t unique_dst_ports;      // Unique destination ports (HLL estimate)
    uint32_t unique_flows;          // Unique flows (HLL estimate)

    // ===== CHURN FEATURES =====
    int32_t  new_srcip_rate;        // New src IPs vs previous window
    int32_t  dst_port_churn;        // Change in unique dst ports vs previous
    int32_t  expired_srcip_rate;    // Expired src IPs (placeholder)

    // ===== CONCENTRATION FEATURES (Count-Min Sketch) =====
    uint8_t  max_flow_fraction;     // Top flow as % of total (0-100)
    uint8_t  topk_flow_share;       // Top-10 flows as % of total (0-100)
    uint16_t heavy_hitter_count;    // Number of heavy hitters detected

    // ===== FLOW BEHAVIOR FEATURES =====
    uint16_t avg_packets_per_flow;  // Average packets per flow
    uint32_t flow_duration_avg_ms;  // Average flow duration in ms

    // ===== ENTROPY FEATURES =====
    uint8_t  src_ip_entropy;        // Source IP distribution entropy (0-255, scaled from 0-8 bits)

    // ===== TCP FLAG RATIO FEATURES =====
    uint8_t  syn_tcp_ratio;         // SYN as % of TCP packets (0-100)
    uint8_t  synack_tcp_ratio;      // SYN-ACK as % of TCP packets (0-100)
    uint8_t  ack_tcp_ratio;         // ACK as % of TCP packets (0-100)
    uint8_t  rst_tcp_ratio;         // RST as % of TCP packets (0-100)
    uint8_t  fin_tcp_ratio;         // FIN as % of TCP packets (0-100)

    // ===== BURST FEATURE =====
    uint16_t burst_factor;          // Current PPS / EWMA PPS * 100 (100=normal, >200=burst)

    // ===== METADATA =====
    uint32_t active_flows;          // Current active flows
    uint32_t sample_count;          // Number of samples in this window

    uint8_t  _pad3[0];

    // ===== EXTENDED FEATURES =====
    uint16_t udp_flow_ratio;       // UDP flows / UDP PPS * 100
    uint16_t dst_port_density;     // Unique dst ports / PPS * 1000
    uint8_t  icmp_echo_ratio;      // ICMP echo / ICMP total * 100
    uint8_t  small_pkt_ratio;      // Packets<=64B as % of total
    uint8_t  tcp_completion_rate;  // SYN-ACK / SYN * 100
    uint8_t  fragment_ratio;       // Fragment packets as % of total
    uint8_t  src_port_entropy;     // Source port entropy (0-255)
    uint8_t  ttl_mean;             // Mean IP TTL value
    uint8_t  _pad4[6];             // Alignment padding
} __attribute__((aligned(64)));

// Attack type alias used by shared_memory.c
#define SHM_ATTACK_UNKNOWN ATTACK_TYPE_UNKNOWN

// ==================== POSIX Shared Memory Header ====================

/**
 * Header placed at the start of shared memory for ABI validation by Python.
 * Defined here (before layer1_shared_memory) so it can be used as a member.
 */
struct shmem_header {
    uint32_t magic;           // SHMEM_MAGIC
    uint32_t version;         // ABI version (increment on struct changes)
    uint64_t size;            // Total size of shared memory
    uint64_t created_tsc;     // TSC when created
    uint64_t tsc_hz;          // TSC frequency for time conversion
} __attribute__((aligned(64)));

// ==================== Per-IP Anomaly Snapshot (Layer 1 fast path) ====================

/**
 * Lightweight snapshot of per-IP anomaly state populated once per packet.
 * Passed to functions that need anomaly context without re-reading shared memory.
 */
struct per_ip_anomaly_snapshot {
    bool     valid;              // true if per-IP data was available
    bool     anomaly_active;     // Per-IP anomaly active
    uint32_t anomaly_level;      // ANOMALY_LEVEL_*
    uint8_t  anomaly_protocol;   // PROTO_CAT_*
    uint8_t  attack_type;        // ATTACK_TYPE_*
    uint8_t  spoofed_mode;       // Per-IP spoofed mode (reserved, currently 0)
    uint8_t  rate_limit_pct;     // Per-IP rate limit % (reserved, currently 100)
};

/**
 * Returns true if the packet protocol matches the anomaly protocol category.
 */
#include <netinet/in.h>
static inline bool protocol_matches_anomaly(uint8_t pkt_proto, uint8_t anomaly_proto) {
    if (anomaly_proto == PROTO_CAT_ALL) return true;
    switch (pkt_proto) {
        case IPPROTO_TCP:  return anomaly_proto == PROTO_CAT_TCP;
        case IPPROTO_UDP:  return anomaly_proto == PROTO_CAT_UDP;
        case IPPROTO_ICMP: return anomaly_proto == PROTO_CAT_ICMP;
        default:           return anomaly_proto == PROTO_CAT_OTHER;
    }
}

// ==================== Shared Memory Region ====================

struct layer1_shared_memory {
    struct shmem_header       header;        // ABI validation header (must be first)
    struct policy_table       policies;
    struct reputation_table   reputation;
    struct feedback_queue     feedback;
    struct global_state       state;
    struct l2_features_export l2_features;       // Layer 2 anomaly detection features (global)
    struct l2_per_ip_export   l2_per_ip;         // Layer 2 per-IP features and anomaly state

    // Layer 3 structures (added for ML attribution)
    struct dynamic_signature_table dynamic_sigs; // Dynamic signatures from Layer 3
    struct packet_ring        packet_ring;       // Packet samples for signature extraction
    // Note: src_ip_stats uses separate rte_hash, not embedded in shared memory
} __attribute__((aligned(4096)));

// ==================== POSIX Shared Memory Constants ====================
// For Python IPC access via shm_open/mmap

#define POSIX_SHMEM_NAME "/antiddos_layer1_shmem"
#define POSIX_SHMEM_SIZE sizeof(struct layer1_shared_memory)

// Magic number for validation
#define SHMEM_MAGIC 0x4C315348  // "L1SH" in hex

#define SHMEM_ABI_VERSION 4  // v4: Added shmem_header, spoofed-mode fields, per_ip_anomaly_snapshot

// ==================== Public API ====================

/**
 * Initialize shared memory (default: DPDK hugepages)
 */
int shared_memory_init(void);

/**
 * Initialize POSIX shared memory for Python IPC access
 * Creates /dev/shm/antiddos_layer1_shmem
 */
int shared_memory_init_posix(void);

/**
 * Check if using POSIX shared memory
 */
bool shared_memory_is_posix(void);

/**
 * Get the POSIX shared memory file path (for Python)
 */
const char *shared_memory_get_path(void);

void shared_memory_cleanup(void);
struct layer1_shared_memory *shared_memory_get(void);

// ==================== Anomaly State API ====================

/**
 * Check if anomaly mode is active
 * @return true if anomaly is active
 */
bool anomaly_is_active(void);

/**
 * Get current anomaly level
 * @return ANOMALY_LEVEL_*
 */
uint32_t anomaly_get_level(void);

/**
 * Set anomaly state (called by Layer 3/4 or detection logic)
 * @param level  ANOMALY_LEVEL_*
 */
void anomaly_set_level(uint32_t level);

/**
 * Clear anomaly state
 */
void anomaly_clear(void);

/**
 * Get current rate limit percentage (100 = normal, 50 = half rate)
 * @return Rate limit percentage based on anomaly level
 */
uint32_t anomaly_get_rate_limit_pct(void);

/**
 * Update traffic statistics for anomaly detection
 * @param pps  Current packets per second
 * @param bps  Current bytes per second
 */
void anomaly_update_traffic_stats(uint64_t pps, uint64_t bps);

// ==================== Layer 2 Features Export API ====================

/**
 * Update Layer 2 features in shared memory
 * Call this every second from control path to export features to Python Layer 2
 *
 * Uses seqlock pattern: increments version to odd before write, even after
 * Python readers should check version before and after read to detect torn reads
 */
void l2_features_export_update(void);

/**
 * Get pointer to L2 features export structure
 * For direct access by control path
 */
struct l2_features_export *l2_features_export_get(void);

// ==================== Per-IP Features Export API ====================

/**
 * Update per-IP features in shared memory
 * Call this every second from control path to export per-IP features to Layer 2
 *
 * Uses seqlock pattern for thread safety
 */
void l2_per_ip_features_export_update(void);

/**
 * Get pointer to per-IP export structure
 */
struct l2_per_ip_export *l2_per_ip_export_get(void);

/**
 * Set per-IP anomaly state (called by Layer 2)
 * @param dst_ip   Protected IP (network byte order)
 * @param level    ANOMALY_LEVEL_*
 * @param z_score  Max z-score that triggered the anomaly
 * @param tier_agreement Number of tiers agreeing
 * @param feature_count  Number of anomalous features
 */
void per_ip_anomaly_set(uint32_t dst_ip, uint32_t level, double z_score,
                        uint32_t tier_agreement, uint32_t feature_count);

/**
 * Set per-IP anomaly state with protocol-specific info (called by Layer 2)
 *
 * Extended version that includes which protocol triggered the anomaly,
 * the attack type classification, and optionally a specific port.
 * This allows Layer 3 to focus signature extraction on the right traffic.
 *
 * For hybrid/multi-protocol attacks, call this function multiple times
 * with different protocol categories, or use PROTO_CAT_ALL.
 *
 * @param dst_ip         Protected IP (network byte order)
 * @param level          ANOMALY_LEVEL_*
 * @param z_score        Max z-score that triggered the anomaly
 * @param tier_agreement Number of tiers agreeing
 * @param feature_count  Number of anomalous features
 * @param proto_cat      PROTO_CAT_TCP/UDP/ICMP/OTHER/ALL - which protocol is anomalous
 * @param attack_type    ATTACK_TYPE_* - classified attack type
 * @param dst_port       Specific port under attack (0 = all ports)
 */
void per_ip_anomaly_set_ex(uint32_t dst_ip, uint32_t level, double z_score,
                           uint32_t tier_agreement, uint32_t feature_count,
                           uint8_t proto_cat, uint8_t attack_type, uint16_t dst_port);

/**
 * Clear per-IP anomaly state
 * @param dst_ip  Protected IP (network byte order)
 */
void per_ip_anomaly_clear(uint32_t dst_ip);

/**
 * Check if anomaly is active for a specific protected IP
 * @param dst_ip  Protected IP (network byte order)
 * @return true if anomaly is active for this IP
 */
bool per_ip_anomaly_is_active(uint32_t dst_ip);

/**
 * Get anomaly level for a specific protected IP
 * @param dst_ip  Protected IP (network byte order)
 * @return ANOMALY_LEVEL_*
 */
uint32_t per_ip_anomaly_get_level(uint32_t dst_ip);

/**
 * Fast lookup of per-IP anomaly state by pre-computed slot index.
 * O(1) - no hash lookup.
 * Returns NULL if idx is invalid.
 */
const struct per_ip_anomaly_state *per_ip_anomaly_get_fast(int32_t idx);

// ==================== Heavy Hitter Export API ====================

/**
 * Per-IP statistics for heavy hitter export
 */
struct per_ip_stats {
    uint32_t ip;               // IP address (network byte order)
    uint64_t total_packets;    // Total packets from/to this IP
    uint64_t total_bytes;      // Total bytes from/to this IP
    uint64_t current_pps;      // Current packets per second
    uint64_t current_bps;      // Current bytes per second
    uint64_t first_seen;       // First seen timestamp (unix seconds)
    uint64_t last_seen;        // Last seen timestamp (unix seconds)
    uint16_t reputation;       // Current reputation score
    uint8_t  blocked;          // 1 if currently blocked
    uint8_t  attack_type;      // Detected attack type (if any)
};

/**
 * Get top N talkers (heavy hitters) from per-IP feature tracking
 *
 * @param stats      Output array for stats entries
 * @param max_count  Maximum entries to return
 * @return Number of entries returned
 */
uint32_t get_per_ip_top_talkers(struct per_ip_stats *stats, uint32_t max_count);

// ==================== Layer 3 Integration API ====================

/**
 * Initialize Layer 3 components (dynamic signatures, packet ring, src IP stats)
 * @return 0 on success, -1 on failure
 */
int layer3_components_init(void);

/**
 * Cleanup Layer 3 components
 */
void layer3_components_cleanup(void);

/**
 * Get pointer to dynamic signature table
 */
struct dynamic_signature_table *layer3_get_dynamic_signatures(void);

/**
 * Get pointer to packet ring buffer
 */
struct packet_ring *layer3_get_packet_ring(void);

/**
 * Enable/disable Layer 3 packet sampling
 * @param enable  true to enable, false to disable
 * @param dst_ip  Target protected IP (0 for all)
 */
void layer3_enable_sampling(bool enable, uint32_t dst_ip);

/**
 * Adjust sampling rate based on anomaly level
 * Called automatically when anomaly level changes
 */
void layer3_adjust_sampling_rate(uint32_t anomaly_level);

#endif // LAYER1_SHARED_MEMORY_H