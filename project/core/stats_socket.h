#ifndef STATS_SOCKET_H
#define STATS_SOCKET_H

#include <stdint.h>
#include <stdbool.h>

#define STATS_PORT 9999
#define STATS_INTERVAL_MS 500
#define STATS_MAX_PORTS 8
#define STATS_MAGIC 0x44504B53  // "DPKS"
#define SYSMON_MAGIC 0x53595354  // "SYST"
#define ANOMALY_MAGIC 0x414E4F4D // "ANOM"

#define MAX_LCORE_STATS 64
#define MAX_MEMPOOL_STATS 8

// Use packed structs to avoid padding issues with Python
#pragma pack(push, 1)

struct port_stat_entry {
    uint16_t port_id;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t dropped;
    uint64_t rx_pps;
    uint64_t tx_pps;
    uint64_t rx_bps;
    uint64_t tx_bps;
};  // 74 bytes (2 + 9*8)

struct stats_packet {
    uint32_t magic;
    uint32_t length;
    uint64_t timestamp_ms;
    uint16_t port_count;
    struct port_stat_entry ports[STATS_MAX_PORTS];
};  // 18 + 8*74 = 610 bytes

// ==================== System Monitor Packet ====================

struct lcore_stat_entry {
    uint32_t lcore_id;
    uint8_t is_active;
    uint8_t _pad[3];
    uint64_t busy_cycles;
    uint64_t idle_cycles;
    double utilization_pct;     // 0-100%
};  // 28 bytes

struct mempool_stat_entry {
    char name[32];
    uint32_t size;
    uint32_t avail_count;
    uint32_t in_use_count;
    double usage_pct;           // 0-100%
};  // 52 bytes

struct sys_cpu_stat_entry {
    uint32_t cpu_id;
    double usage_pct;
    double user_pct;
    double system_pct;
    double idle_pct;
    double iowait_pct;
};  // 44 bytes

struct sysmon_packet {
    uint32_t magic;             // SYSMON_MAGIC
    uint32_t length;
    uint64_t timestamp_ms;

    // DPDK lcore stats
    uint16_t nb_lcores;
    uint16_t _pad1;
    double avg_lcore_utilization;
    struct lcore_stat_entry lcore_stats[MAX_LCORE_STATS];

    // DPDK mempool stats
    uint16_t nb_mempools;
    uint16_t _pad2;
    struct mempool_stat_entry mempool_stats[MAX_MEMPOOL_STATS];

    // DPDK hugepage stats
    uint64_t hugepage_total_bytes;
    uint64_t hugepage_used_bytes;
    double hugepage_usage_pct;

    // System CPU stats
    uint16_t nb_cpus;
    uint16_t _pad3;
    double avg_cpu_usage;
    struct sys_cpu_stat_entry cpu_stats[MAX_LCORE_STATS];

    // System memory stats
    uint64_t mem_total_bytes;
    uint64_t mem_free_bytes;
    uint64_t mem_available_bytes;
    uint64_t mem_used_bytes;
    double mem_usage_pct;

    // Load average
    double load_1min;
    double load_5min;
    double load_15min;
};

// ==================== Per-IP Features Packet ====================
// Magic: "PIPF" = 0x50495046
#define PER_IP_FEATURES_MAGIC 0x50495046
#define MAX_PER_IP_EXPORT 64

struct per_ip_features_entry {
    uint32_t dst_ip;            // Protected IP (network byte order)
    uint32_t active;            // 1 if slot is active
    uint64_t timestamp_ns;      // Feature timestamp

    // Volume stats
    uint64_t packets_per_sec;
    uint64_t bytes_per_sec;
    uint32_t flows_per_sec;

    // TCP flag stats
    uint32_t syn_per_sec;
    uint32_t syn_ack_per_sec;
    uint32_t ack_per_sec;
    uint32_t rst_per_sec;
    uint32_t fin_per_sec;

    // Protocol mix
    uint8_t tcp_ratio;
    uint8_t udp_ratio;
    uint8_t icmp_ratio;
    uint8_t _pad1;

    // Cardinality
    uint32_t unique_src_ips;
    uint32_t unique_flows;

    // Concentration
    uint8_t max_flow_fraction;
    uint8_t topk_flow_share;
    uint16_t heavy_hitter_count;

    // Flow behavior
    uint16_t avg_packets_per_flow;
    uint32_t flow_duration_avg_ms;

    // Totals
    uint64_t total_packets;
    uint32_t active_flows;
    uint32_t _pad2;
};  // 104 bytes

struct per_ip_features_packet {
    uint32_t magic;             // PER_IP_FEATURES_MAGIC
    uint32_t length;
    uint64_t timestamp_ms;
    uint32_t active_count;
    uint32_t _pad;
    struct per_ip_features_entry entries[MAX_PER_IP_EXPORT];
};

// ==================== Layer 2 Anomaly Packet ====================

struct anomaly_packet {
    uint32_t magic;             // ANOMALY_MAGIC
    uint32_t length;
    uint64_t timestamp_ms;

    // Anomaly state
    uint8_t active;             // 1 if anomaly is active
    uint8_t level;              // 0=none, 1=low, 2=medium, 3=high, 4=critical
    uint8_t tier_agreement;     // How many tiers agree (0-3)
    uint8_t _pad1;
    double max_z_score;         // Maximum Z-score
    double confidence;          // Detection confidence (0.0-1.0)
    int32_t primary_feature;    // Index of primary triggered feature
    uint32_t _pad2;
    uint64_t start_time_ns;     // When anomaly started
    double duration_sec;        // How long anomaly has been active
    double cool_down_remaining; // Seconds remaining in cool-down

    // Baseline status
    uint8_t baselines_frozen;   // 1 if baselines are frozen
    uint8_t tier1_ready;        // Tier 1 baseline ready
    uint8_t tier2_ready_count;  // Number of hourly baselines ready (0-24)
    uint8_t tier3_ready_count;  // Number of weekly baselines ready (0-168)
    uint32_t baseline_updates;  // Total baseline updates

    // Detection stats
    uint64_t detection_cycles;  // Total detection cycles
    uint64_t detection_count;   // Total anomalies detected

    // Current features (for display)
    uint64_t packets_per_sec;
    uint64_t bytes_per_sec;
    uint32_t syn_per_sec;
    uint32_t unique_src_ips;
    uint32_t unique_flows;
    uint32_t heavy_hitters;

    // Rate limiting
    uint32_t rate_limit_pct;    // Current rate limit percentage (100 = normal)
};

#pragma pack(pop)

int stats_socket_init(void);
void stats_socket_cleanup(void);

#endif