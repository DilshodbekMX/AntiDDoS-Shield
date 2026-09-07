/**
 * @file shared_memory_simple.h
 * @brief Simplified shared memory for single-organization deployment
 *
 * This version removes all tenant_id fields from structures and simplifies
 * the inter-layer communication for on-premises single-organization use.
 *
 * Key simplifications:
 * - No tenant_id in policy entries
 * - No tenant-specific filtering in any table
 * - Simpler API without tenant parameters
 */

#ifndef SHARED_MEMORY_SIMPLE_H
#define SHARED_MEMORY_SIMPLE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

/* ============================================================================
 * Policy Actions
 * ============================================================================ */

enum policy_action {
    POLICY_ALLOW = 0,           /* Allow packet through */
    POLICY_DROP,                /* Drop packet silently */
    POLICY_RATE_LIMIT,          /* Apply rate limiting */
    POLICY_CHALLENGE,           /* Send challenge (SYN cookie, etc.) */
    POLICY_TARPIT,              /* Slow down connection */
    POLICY_LOG,                 /* Allow but log */
    POLICY_REDIRECT,            /* Redirect to scrubbing */
};

/* ============================================================================
 * Policy Table (IPv4)
 * ============================================================================ */

struct policy_entry {
    uint32_t src_ip;            /* Source IP (0 = any) */
    uint32_t dst_ip;            /* Destination IP (0 = any) */
    uint16_t dst_port;          /* Destination port (0 = any) */
    uint8_t  protocol;          /* IP protocol (0 = any) */
    uint8_t  _pad1;

    enum policy_action action;

    uint32_t rate_limit_pps;    /* Max PPS if action = RATE_LIMIT */
    uint32_t rate_limit_bps;    /* Max BPS if action = RATE_LIMIT */

    uint32_t priority;          /* Higher = checked first */
    uint64_t expiry_timestamp;  /* 0 = never expires */
    uint64_t version;           /* For concurrent access detection */

    char     description[32];   /* Human-readable description */
    uint8_t  _pad2[8];
} __attribute__((aligned(64)));

#define MAX_POLICIES 10000

struct policy_table {
    struct policy_entry entries[MAX_POLICIES];
    _Atomic uint32_t count;
    _Atomic uint64_t global_version;
    uint8_t  _pad[52];
} __attribute__((aligned(64)));

/* ============================================================================
 * Policy Table (IPv6)
 * ============================================================================ */

struct policy_entry_v6 {
    uint8_t  src_ip6[16];       /* Source IPv6 (all zeros = any) */
    uint8_t  dst_ip6[16];       /* Destination IPv6 (all zeros = any) */
    uint8_t  src_prefix_len;    /* Source prefix length (0-128) */
    uint8_t  dst_prefix_len;    /* Destination prefix length (0-128) */
    uint16_t dst_port;          /* Destination port (0 = any) */
    uint8_t  protocol;          /* IP protocol (0 = any) */
    uint8_t  _pad1;

    enum policy_action action;

    uint32_t rate_limit_pps;
    uint32_t rate_limit_bps;

    uint32_t priority;
    uint64_t expiry_timestamp;
    uint64_t version;

    uint8_t  _pad2[18];
} __attribute__((aligned(64)));

#define MAX_POLICIES_V6 5000

struct policy_table_v6 {
    struct policy_entry_v6 entries[MAX_POLICIES_V6];
    _Atomic uint32_t count;
    _Atomic uint64_t global_version;
    uint8_t  _pad[52];
} __attribute__((aligned(64)));

/* ============================================================================
 * Reputation Table
 * ============================================================================ */

struct reputation_entry {
    uint32_t ip;                /* Source IP address */
    uint16_t score;             /* Reputation score (0-1000, higher = trusted) */
    uint16_t confidence;        /* Confidence level (0-1000) */

    uint64_t last_updated_ns;   /* Last update timestamp */
    uint32_t packet_count;      /* Total packets from this IP */
    uint32_t attack_count;      /* Number of detected attacks */

    uint8_t  flags;             /* REP_FLAG_* */
    uint8_t  _pad[7];
} __attribute__((aligned(32)));

/* Reputation flags */
#define REP_FLAG_IS_ATTACKER  0x01
#define REP_FLAG_IS_TRUSTED   0x02
#define REP_FLAG_IS_EXPIRED   0x04
#define REP_FLAG_IS_BUILDING  0x08

#define MAX_REPUTATION_ENTRIES 100000

struct reputation_table {
    struct reputation_entry entries[MAX_REPUTATION_ENTRIES];
    _Atomic uint32_t count;
    _Atomic uint64_t global_version;
    uint8_t  _pad[52];
} __attribute__((aligned(64)));

/* ============================================================================
 * Feedback Queue (Layer 1 -> Layer 3)
 * ============================================================================ */

enum feedback_event_type {
    FEEDBACK_SYN_FLOOD = 1,
    FEEDBACK_RATE_LIMIT_EXCEEDED,
    FEEDBACK_INVALID_PACKET,
    FEEDBACK_CONNECTION_LIMIT,
    FEEDBACK_ATTACK_MITIGATED,
    FEEDBACK_SUSPICIOUS_PATTERN,
    FEEDBACK_CHALLENGE_FAILED,
};

struct feedback_event {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  event_type;        /* feedback_event_type */

    uint64_t timestamp_ns;
    uint32_t packet_count;      /* Packets involved */
    uint32_t severity;          /* 0-100 */

    uint8_t  _pad[8];
} __attribute__((aligned(32)));

#define MAX_FEEDBACK_EVENTS 10000

struct feedback_queue {
    struct feedback_event events[MAX_FEEDBACK_EVENTS];
    _Atomic uint32_t head;      /* Next write position */
    _Atomic uint32_t tail;      /* Next read position */
    uint8_t  _pad[56];
} __attribute__((aligned(64)));

/* ============================================================================
 * Global State
 * ============================================================================ */

struct global_state {
    /* Anomaly detection state */
    _Atomic uint32_t anomaly_active;      /* Non-zero if attack detected */
    _Atomic uint32_t anomaly_level;       /* ANOMALY_LEVEL_* */
    _Atomic uint64_t anomaly_start_ns;    /* When anomaly started */
    _Atomic uint64_t last_anomaly_update_ns;

    /* Current traffic stats */
    _Atomic uint64_t total_pps;           /* Current packets per second */
    _Atomic uint64_t total_bps;           /* Current bytes per second */
    _Atomic uint64_t baseline_pps;        /* Normal baseline PPS */
    _Atomic uint64_t baseline_bps;        /* Normal baseline BPS */

    /* Dynamic rate limiting */
    _Atomic uint32_t rate_limit_pct;      /* Current rate % (100 = normal) */

    /* Spoofed attack detection */
    _Atomic uint32_t spoofed_attack_mode; /* High source IP randomness */
    _Atomic uint32_t randomness_pct;      /* Source IP randomness 0-100 */

    uint8_t  _pad[20];
} __attribute__((aligned(64)));

/* Anomaly levels */
#define ANOMALY_LEVEL_NONE     0
#define ANOMALY_LEVEL_LOW      1
#define ANOMALY_LEVEL_MEDIUM   2
#define ANOMALY_LEVEL_HIGH     3
#define ANOMALY_LEVEL_CRITICAL 4

/* ============================================================================
 * Layer 2 Features Export
 * ============================================================================ */

struct l2_features_export {
    _Atomic uint64_t version;   /* Seqlock: odd = writing, even = stable */

    uint64_t timestamp_ns;
    uint64_t window_duration_ns;

    /* Volume */
    uint64_t packets_per_sec;
    uint64_t bytes_per_sec;
    uint32_t flows_per_sec;

    /* TCP flags */
    uint32_t syn_per_sec;
    uint32_t syn_ack_per_sec;
    uint32_t ack_per_sec;
    uint32_t rst_per_sec;
    uint32_t fin_per_sec;

    /* Protocol mix */
    uint32_t tcp_packets;
    uint32_t udp_packets;
    uint32_t icmp_packets;
    uint32_t other_packets;
    uint8_t  tcp_ratio;         /* 0-100 */
    uint8_t  udp_ratio;
    uint8_t  icmp_ratio;
    uint8_t  _pad1;

    /* Ratios */
    uint16_t syn_ack_ratio;     /* SYN / ACK * 100 */
    uint16_t rst_syn_ratio;
    uint16_t bytes_per_packet;
    uint16_t _pad2;

    /* Cardinality (HyperLogLog) */
    uint32_t unique_src_ips;
    uint32_t unique_dst_ports;
    uint32_t unique_flows;

    /* Churn */
    int32_t  new_srcip_rate;
    int32_t  dst_port_churn;
    int32_t  expired_srcip_rate;

    /* Concentration */
    uint8_t  max_flow_fraction;
    uint8_t  topk_flow_share;
    uint16_t heavy_hitter_count;

    /* Flow behavior */
    uint16_t avg_packets_per_flow;
    uint32_t flow_duration_avg_ms;

    /* Entropy */
    uint8_t  src_ip_entropy;    /* 0-255, scaled from 0-8 bits */

    /* Metadata */
    uint32_t active_flows;
    uint32_t sample_count;

    uint8_t  _pad3[8];
} __attribute__((aligned(64)));

/* ============================================================================
 * Per-Protected-IP Features (for per-IP detection)
 * ============================================================================ */

#define MAX_PROTECTED_IPS_EXPORT 256   /* Reduced from 4096 for single-org */

struct per_ip_features_export {
    uint32_t dst_ip;            /* Protected IP */
    uint32_t active;            /* 1 if slot is active */

    uint64_t timestamp_ns;
    uint64_t window_duration_ns;

    /* Volume */
    uint64_t packets_per_sec;
    uint64_t bytes_per_sec;
    uint32_t flows_per_sec;

    /* TCP flags */
    uint32_t syn_per_sec;
    uint32_t syn_ack_per_sec;
    uint32_t ack_per_sec;
    uint32_t rst_per_sec;
    uint32_t fin_per_sec;

    /* Protocol mix */
    uint32_t tcp_packets;
    uint32_t udp_packets;
    uint32_t icmp_packets;
    uint32_t other_packets;

    /* Cardinality */
    uint32_t unique_src_ips;
    uint32_t unique_src_ports;
    uint32_t unique_dst_ports;

    /* Metadata */
    uint32_t active_flows;
    uint32_t sample_count;
    uint64_t total_packets;

    uint8_t  _pad[8];
} __attribute__((aligned(64)));

/* Attack type classification */
#define ATTACK_UNKNOWN        0
#define ATTACK_SYN_FLOOD      1
#define ATTACK_UDP_FLOOD      2
#define ATTACK_ICMP_FLOOD     3
#define ATTACK_DNS_AMP        4
#define ATTACK_NTP_AMP        5
#define ATTACK_MEMCACHED_AMP  6
#define ATTACK_HTTP_FLOOD     7
#define ATTACK_SLOWLORIS      8
#define ATTACK_ACK_FLOOD      9
#define ATTACK_RST_FLOOD     10

/* Protocol categories */
#define PROTO_CAT_TCP    0
#define PROTO_CAT_UDP    1
#define PROTO_CAT_ICMP   2
#define PROTO_CAT_OTHER  3
#define PROTO_CAT_ALL    255

struct per_ip_anomaly_state {
    uint32_t dst_ip;            /* Protected IP */
    uint32_t active;            /* 1 if slot active */
    uint32_t anomaly_active;    /* Non-zero if anomaly */
    uint32_t anomaly_level;     /* ANOMALY_LEVEL_* */
    uint64_t anomaly_start_ns;
    uint64_t last_update_ns;

    double   max_z_score;
    uint32_t tier_agreement;
    uint32_t anomalous_feature_count;

    uint8_t  anomaly_protocol;  /* PROTO_CAT_* */
    uint8_t  attack_type;       /* ATTACK_* */
    uint16_t anomaly_dst_port;  /* Specific port (0 = all) */

    uint8_t  _pad[20];
} __attribute__((aligned(64)));

struct per_ip_export {
    _Atomic uint64_t version;
    _Atomic uint32_t active_count;
    uint32_t _pad;
    struct per_ip_features_export features[MAX_PROTECTED_IPS_EXPORT];
    struct per_ip_anomaly_state anomaly[MAX_PROTECTED_IPS_EXPORT];
} __attribute__((aligned(64)));

/* ============================================================================
 * Per-Source-IP Export (for Layer 3 ML)
 * ============================================================================ */

#define MAX_SRC_IP_EXPORT 1024

struct src_ip_entry_export {
    uint32_t src_ip;
    uint32_t flags;

    uint64_t first_seen_ns;
    uint64_t last_seen_ns;

    uint32_t packets_window;
    uint32_t bytes_window;
    uint32_t flows_window;

    uint64_t packets_total;
    uint64_t bytes_total;

    /* Protocol distribution */
    uint16_t tcp_pkt_count;
    uint16_t udp_pkt_count;
    uint16_t icmp_pkt_count;
    uint16_t other_pkt_count;

    /* TCP behavior */
    uint16_t syn_count;
    uint16_t syn_ack_count;
    uint16_t ack_count;
    uint16_t rst_count;
    uint16_t fin_count;
    uint16_t incomplete_handshakes;

    /* Diversity */
    uint8_t  unique_dst_ports;
    uint8_t  unique_dst_ips;

    /* Packet characteristics */
    uint16_t min_pkt_size;
    uint16_t max_pkt_size;
    uint16_t avg_pkt_size;
    uint8_t  min_ttl;
    uint8_t  max_ttl;

    /* Rate */
    uint32_t pps_current;
    uint32_t bps_current;

    /* Mitigation */
    uint8_t  action;
    uint8_t  score;             /* Attack score 0-100 */
    uint8_t  rate_limited;
    uint8_t  challenged;

    _Atomic uint64_t version;

    uint8_t  _pad[4];
} __attribute__((packed, aligned(64)));

struct src_ip_export_table {
    _Atomic uint64_t version;
    _Atomic uint32_t entry_count;
    uint32_t total_tracked;
    uint64_t last_update_ns;
    uint64_t window_start_ns;

    struct src_ip_entry_export entries[MAX_SRC_IP_EXPORT];
} __attribute__((aligned(64)));

/* ============================================================================
 * Dynamic Signatures (from Layer 3)
 * ============================================================================ */

#define MAX_DYNAMIC_SIGNATURES 256
#define MAX_SIGNATURE_PATTERN_LEN 64

struct dynamic_signature {
    uint32_t signature_id;
    uint8_t  pattern[MAX_SIGNATURE_PATTERN_LEN];
    uint8_t  pattern_len;
    uint8_t  protocol;          /* 6=TCP, 17=UDP, 0=any */
    uint16_t dst_port;          /* 0 = any */

    uint32_t match_count;
    uint64_t added_timestamp;
    uint64_t expiry_timestamp;

    uint8_t  action;            /* policy_action */
    uint8_t  confidence;        /* 0-100 */
    uint8_t  active;
    uint8_t  _pad[5];
} __attribute__((aligned(64)));

struct dynamic_signature_table {
    struct dynamic_signature signatures[MAX_DYNAMIC_SIGNATURES];
    _Atomic uint32_t count;
    _Atomic uint64_t version;
    uint8_t  _pad[52];
} __attribute__((aligned(64)));

/* ============================================================================
 * Packet Ring Buffer (for Layer 3 sampling)
 * ============================================================================ */

#define PACKET_RING_SIZE 4096
#define MAX_SAMPLED_PKT_LEN 256

struct sampled_packet {
    uint8_t  data[MAX_SAMPLED_PKT_LEN];
    uint16_t actual_len;
    uint16_t captured_len;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  tcp_flags;
    uint8_t  _pad[2];
    uint64_t timestamp_ns;
} __attribute__((aligned(64)));

struct packet_ring {
    struct sampled_packet packets[PACKET_RING_SIZE];
    _Atomic uint32_t head;
    _Atomic uint32_t tail;
    _Atomic uint32_t dropped;
    _Atomic uint32_t sampling_enabled;
    uint32_t sampling_rate;     /* 1 in N packets */
    uint32_t target_dst_ip;     /* 0 = all protected IPs */
    uint8_t  _pad[40];
} __attribute__((aligned(64)));

/* ============================================================================
 * Master Shared Memory Structure
 * ============================================================================ */

struct shared_memory {
    struct policy_table       policies;
    struct policy_table_v6    policies_v6;
    struct reputation_table   reputation;
    struct feedback_queue     feedback;
    struct global_state       state;
    struct l2_features_export l2_features;
    struct per_ip_export      per_ip;
    struct src_ip_export_table src_ip_export;
    struct dynamic_signature_table dynamic_sigs;
    struct packet_ring        packet_ring;
} __attribute__((aligned(4096)));

/* ============================================================================
 * POSIX Shared Memory Constants
 * ============================================================================ */

#define SHMEM_NAME "/antiddos_shmem"
#define SHMEM_MAGIC 0x414E5449          /* "ANTI" in hex */
#define SHMEM_ABI_VERSION 5             /* v5: Single-organization version */

struct shmem_header {
    uint32_t magic;
    uint32_t abi_version;
    uint64_t size;
    uint64_t created_timestamp;
    uint64_t tsc_hz;            /* For time conversion */
} __attribute__((aligned(64)));

/* ============================================================================
 * API Functions
 * ============================================================================ */

/**
 * Initialize shared memory
 * @return 0 on success, -1 on error
 */
int shmem_init(void);

/**
 * Initialize using POSIX shared memory (for Python IPC)
 * Creates /dev/shm/antiddos_shmem
 * @return 0 on success, -1 on error
 */
int shmem_init_posix(void);

/**
 * Cleanup shared memory
 */
void shmem_cleanup(void);

/**
 * Get pointer to shared memory
 */
struct shared_memory *shmem_get(void);

/**
 * Check if using POSIX shared memory
 */
bool shmem_is_posix(void);

/**
 * Get POSIX shmem path
 */
const char *shmem_get_path(void);

/* ============================================================================
 * Policy API
 * ============================================================================ */

/**
 * Add a policy entry
 * @return policy index on success, -1 on error
 */
int policy_add(const struct policy_entry *entry);

/**
 * Remove a policy by index
 */
int policy_remove(uint32_t index);

/**
 * Lookup matching policy for packet
 * @return pointer to matching entry or NULL
 */
const struct policy_entry *policy_lookup(uint32_t src_ip, uint32_t dst_ip,
                                         uint16_t dst_port, uint8_t protocol);

/**
 * Clear all policies
 */
void policy_clear_all(void);

/**
 * Remove expired policies
 */
uint32_t policy_expire_old(void);

/* ============================================================================
 * Reputation API
 * ============================================================================ */

/**
 * Lookup reputation for IP
 * @return pointer to entry or NULL if not found
 */
const struct reputation_entry *reputation_lookup(uint32_t ip);

/**
 * Update reputation score
 */
int reputation_update(uint32_t ip, int16_t score_delta, uint8_t flags);

/**
 * Set reputation directly
 */
int reputation_set(uint32_t ip, uint16_t score, uint16_t confidence, uint8_t flags);

/**
 * Remove reputation entry
 */
int reputation_remove(uint32_t ip);

/* ============================================================================
 * Feedback Queue API
 * ============================================================================ */

/**
 * Push feedback event (from Layer 1)
 */
int feedback_push(const struct feedback_event *event);

/**
 * Pop feedback event (for Layer 3)
 */
int feedback_pop(struct feedback_event *event);

/**
 * Get number of pending feedback events
 */
uint32_t feedback_count(void);

/* ============================================================================
 * Anomaly State API
 * ============================================================================ */

bool anomaly_is_active(void);
uint32_t anomaly_get_level(void);
void anomaly_set_level(uint32_t level);
void anomaly_clear(void);
void anomaly_set_spoofed_mode(uint32_t spoofed, uint32_t randomness_pct);
bool anomaly_is_spoofed_mode(void);
uint32_t anomaly_get_randomness_pct(void);
uint32_t anomaly_get_rate_limit_pct(void);
void anomaly_update_traffic_stats(uint64_t pps, uint64_t bps);

/* ============================================================================
 * Per-IP Anomaly API
 * ============================================================================ */

void per_ip_anomaly_set(uint32_t dst_ip, uint32_t level, double z_score,
                        uint32_t tier_agreement, uint32_t feature_count);

void per_ip_anomaly_set_ex(uint32_t dst_ip, uint32_t level, double z_score,
                           uint32_t tier_agreement, uint32_t feature_count,
                           uint8_t proto_cat, uint8_t attack_type, uint16_t dst_port);

void per_ip_anomaly_clear(uint32_t dst_ip);
bool per_ip_anomaly_is_active(uint32_t dst_ip);
uint32_t per_ip_anomaly_get_level(uint32_t dst_ip);

/* ============================================================================
 * Dynamic Signature API
 * ============================================================================ */

int signature_add(const struct dynamic_signature *sig);
int signature_remove(uint32_t signature_id);
const struct dynamic_signature *signature_lookup(const uint8_t *pkt_data,
                                                  uint16_t pkt_len,
                                                  uint8_t protocol,
                                                  uint16_t dst_port);
void signature_expire_old(void);

/* ============================================================================
 * Packet Ring API
 * ============================================================================ */

void packet_ring_enable(bool enable, uint32_t target_dst_ip, uint32_t rate);
int packet_ring_push(const uint8_t *pkt, uint16_t len, uint32_t src_ip,
                     uint32_t dst_ip, uint16_t src_port, uint16_t dst_port,
                     uint8_t protocol, uint8_t tcp_flags);
int packet_ring_pop(struct sampled_packet *pkt);
uint32_t packet_ring_count(void);

/* ============================================================================
 * Export Update API (called periodically)
 * ============================================================================ */

void l2_features_export_update(void);
void per_ip_features_export_update(void);
void src_ip_export_update(void);

#endif /* SHARED_MEMORY_SIMPLE_H */
