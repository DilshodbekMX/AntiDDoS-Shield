"""
Binary packet format constants for DPDK communication.

These constants define the structure of packets exchanged between
the Python backend and the DPDK C application via Unix sockets.
"""

import struct

# ============================================================================
# Stats Packet Format
# ============================================================================

STATS_MAGIC = 0x44504B53  # "DPKS"
MAX_PORTS = 8

# Header: magic(I), version(I), timestamp(Q), num_ports(H)
HEADER_FORMAT = '<IIQH'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Port entry: port_id(H), rx_pkts(Q), tx_pkts(Q), rx_bytes(Q), tx_bytes(Q),
#             rx_dropped(Q), tx_dropped(Q), rx_errors(Q), tx_errors(Q), link_status(Q)
PORT_ENTRY_FORMAT = '<H9Q'
PORT_ENTRY_SIZE = struct.calcsize(PORT_ENTRY_FORMAT)

STATS_PACKET_SIZE = HEADER_SIZE + (MAX_PORTS * PORT_ENTRY_SIZE)

# ============================================================================
# System Monitor Packet Format
# ============================================================================

SYSMON_MAGIC = 0x53595354  # "SYST"
MAX_LCORE_STATS = 64
MAX_MEMPOOL_STATS = 8

# lcore_stat_entry: lcore_id(I), is_active(B), pad(3B), busy_cycles(Q),
#                   idle_cycles(Q), utilization_pct(d)
LCORE_STAT_FORMAT = '<IBxxxQQd'
LCORE_STAT_SIZE = struct.calcsize(LCORE_STAT_FORMAT)

# mempool_stat_entry: name(32s), size(I), avail_count(I), in_use_count(I), usage_pct(d)
MEMPOOL_STAT_FORMAT = '<32sIIId'
MEMPOOL_STAT_SIZE = struct.calcsize(MEMPOOL_STAT_FORMAT)

# sys_cpu_stat_entry: cpu_id(I), usage_pct(d), user_pct(d), system_pct(d),
#                     idle_pct(d), iowait_pct(d)
SYS_CPU_STAT_FORMAT = '<Iddddd'
SYS_CPU_STAT_SIZE = struct.calcsize(SYS_CPU_STAT_FORMAT)

# ============================================================================
# Traffic Packet Format
# ============================================================================

TRAFFIC_MAGIC = 0x5452464B  # "TRFK"
MAX_TRAFFIC_SAMPLES = 100

# Traffic header: magic(I), version(I), timestamp(Q), num_entries(H), pad(H)
TRAFFIC_HEADER_FORMAT = '<IIQHH'
TRAFFIC_HEADER_SIZE = struct.calcsize(TRAFFIC_HEADER_FORMAT)

# Traffic entry: timestamp(Q), src_ip(I), dst_ip(I), src_port(H), dst_port(H),
#                protocol(B), flags(B), pkt_len(H), port_id(H), direction(B), pad(B)
TRAFFIC_ENTRY_FORMAT = '<QIIHHBBHHBB'
TRAFFIC_ENTRY_SIZE = struct.calcsize(TRAFFIC_ENTRY_FORMAT)

TRAFFIC_PACKET_SIZE = TRAFFIC_HEADER_SIZE + (MAX_TRAFFIC_SAMPLES * TRAFFIC_ENTRY_SIZE)

# ============================================================================
# Anomaly Packet Format
# ============================================================================

ANOMALY_MAGIC = 0x414E4F4D  # "ANOM"

# anomaly_packet: magic(I) + length(I) + timestamp(Q) + active(B) + level(B) +
#                 tier_agreement(B) + pad(B) + max_z_score(d) + confidence(d) +
#                 primary_feature(i) + pad(I) + start_time(Q) + duration(d) +
#                 cool_down(d) + baselines_frozen(B) + tier1_ready(B) +
#                 tier2_ready(B) + tier3_ready(B) + baseline_updates(I) +
#                 detection_cycles(Q) + detection_count(Q) + packets_per_sec(Q) +
#                 bytes_per_sec(Q) + syn_per_sec(I) + unique_src_ips(I) +
#                 unique_flows(I) + heavy_hitters(I) + rate_limit_pct(I)
ANOMALY_PACKET_FORMAT = '<IIQBBBBddiIQddBBBBIQQQQIIIII'
ANOMALY_PACKET_SIZE = struct.calcsize(ANOMALY_PACKET_FORMAT)

ANOMALY_LEVEL_NAMES = {
    0: 'NONE',
    1: 'LOW',
    2: 'MEDIUM',
    3: 'HIGH',
    4: 'CRITICAL'
}

# ============================================================================
# Per-IP Anomaly Packet Format
# ============================================================================

PER_IP_ANOMALY_MAGIC = 0x50455250  # "PERP"
MAX_PER_IP_EXPORT = 64

# per_ip_anomaly_entry: dst_ip(I), active(I), anomaly_active(I), anomaly_level(I),
#                       anomaly_start_ns(Q), last_update_ns(Q), max_z_score(d),
#                       tier_agreement(I), anomalous_feature_count(I),
#                       anomaly_protocol(B), attack_type(B), anomaly_dst_port(H), pad(20s)
PER_IP_ANOMALY_ENTRY_FORMAT = '<IIIIQQdIIBBH20s'
PER_IP_ANOMALY_ENTRY_SIZE = struct.calcsize(PER_IP_ANOMALY_ENTRY_FORMAT)

# Protocol category names (matches PROTO_CAT_* in shared_memory.h)
PROTO_CAT_NAMES = {
    0: 'TCP',
    1: 'UDP',
    2: 'ICMP',
    3: 'OTHER',
    255: 'ALL',
}

# Attack type names (matches ATTACK_TYPE_* in shared_memory.h)
ATTACK_TYPE_NAMES = {
    0: 'UNKNOWN',
    1: 'SYN_FLOOD',
    2: 'UDP_FLOOD',
    3: 'ICMP_FLOOD',
    4: 'DNS_AMP',
    5: 'NTP_AMP',
    6: 'MEMCACHED_AMP',
    7: 'HTTP_FLOOD',
    8: 'SLOWLORIS',
    9: 'ACK_FLOOD',
    10: 'RST_FLOOD',
    11: 'FRAG_FLOOD',
}

# Per-IP anomaly header: magic(I), length(I), version(Q), active_count(I), pad(I)
PER_IP_ANOMALY_HEADER_FORMAT = '<IIQII'
PER_IP_ANOMALY_HEADER_SIZE = struct.calcsize(PER_IP_ANOMALY_HEADER_FORMAT)

PER_IP_ANOMALY_PACKET_SIZE = (
    PER_IP_ANOMALY_HEADER_SIZE +
    (MAX_PER_IP_EXPORT * PER_IP_ANOMALY_ENTRY_SIZE)
)

# ============================================================================
# Per-IP Features Packet Format
# ============================================================================

PER_IP_FEATURES_MAGIC = 0x50495046  # "PIPF"

# per_ip_features_entry: dst_ip(I), active(I), timestamp_ns(Q), window_duration_ns(Q),
#   packets_per_sec(Q), bytes_per_sec(Q), flows_per_sec(I), syn_per_sec(I),
#   syn_ack_per_sec(I), ack_per_sec(I), rst_per_sec(I), fin_per_sec(I),
#   tcp_packets(I), udp_packets(I), icmp_packets(I), other_packets(I),
#   tcp_ratio(B), udp_ratio(B), icmp_ratio(B), pad1(B),
#   syn_ack_ratio(H), rst_syn_ratio(H), bytes_per_packet(H), pad2(H),
#   unique_src_ips(I), unique_dst_ports(I), unique_flows(I),
#   src_ip_churn(i), expired_srcip_rate(i),
#   max_flow_fraction(B), topk_flow_share(B), heavy_hitter_count(H),
#   avg_packets_per_flow(H), flow_duration_avg_ms(I),
#   active_flows(I), sample_count(I), total_packets(Q), pad3(4s)
PER_IP_FEATURES_ENTRY_FORMAT = '<IIQQQQIIIIIIIIIIBBBBHHHHIIIiiB BHHIIIQ4s'
# Note: The format string has a space for readability but should be joined
PER_IP_FEATURES_ENTRY_FORMAT = '<IIQQQQIIIIIIIIIIBBBBHHHHIIIiiBBHHIIIQ4s'
PER_IP_FEATURES_ENTRY_SIZE = struct.calcsize(PER_IP_FEATURES_ENTRY_FORMAT)

# Per-IP features header: magic(I), length(I), version(Q), active_count(I), pad(I)
PER_IP_FEATURES_HEADER_FORMAT = '<IIQII'
PER_IP_FEATURES_HEADER_SIZE = struct.calcsize(PER_IP_FEATURES_HEADER_FORMAT)

PER_IP_FEATURES_PACKET_SIZE = (
    PER_IP_FEATURES_HEADER_SIZE +
    (MAX_PER_IP_EXPORT * PER_IP_FEATURES_ENTRY_SIZE)
)

# ============================================================================
# Protocol Names
# ============================================================================

PROTO_NAMES = {
    0: 'Unknown',
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    89: 'OSPF',
    132: 'SCTP',
}
