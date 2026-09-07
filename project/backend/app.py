#!/usr/bin/env python3
"""
DPDK Traffic Monitor - Simple REST API Version (no WebSocket)
"""

import struct
import socket
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS

from rules import (get_rules_engine, init_rules_engine, get_config_manager, init_config_manager,
                   get_layer2_config_manager, init_layer2_config_manager)

app = Flask(__name__)
CORS(app)

# Initialize rules engine and config managers with default paths
rules_engine = init_rules_engine()
config_manager = init_config_manager()
layer2_config_manager = init_layer2_config_manager()

STATS_HOST = "127.0.0.1"
STATS_PORT = 9999
TRAFFIC_HOST = "127.0.0.1"
TRAFFIC_PORT = 9998
MAX_PORTS = 8
MAX_TRAFFIC_SAMPLES = 100
MAX_LCORE_STATS = 64
MAX_MEMPOOL_STATS = 8

# Stats packet format
HEADER_FORMAT = '<IIQH'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
PORT_ENTRY_FORMAT = '<H9Q'
PORT_ENTRY_SIZE = struct.calcsize(PORT_ENTRY_FORMAT)
PACKET_SIZE = HEADER_SIZE + (MAX_PORTS * PORT_ENTRY_SIZE)
MAGIC = 0x44504B53

# System monitor packet format
SYSMON_MAGIC = 0x53595354  # "SYST"
# lcore_stat_entry: lcore_id(I), is_active(B), pad(3B), busy_cycles(Q), idle_cycles(Q), utilization_pct(d)
LCORE_STAT_FORMAT = '<IBxxxQQd'
LCORE_STAT_SIZE = struct.calcsize(LCORE_STAT_FORMAT)
# mempool_stat_entry: name(32s), size(I), avail_count(I), in_use_count(I), usage_pct(d)
MEMPOOL_STAT_FORMAT = '<32sIIId'
MEMPOOL_STAT_SIZE = struct.calcsize(MEMPOOL_STAT_FORMAT)
# sys_cpu_stat_entry: cpu_id(I), usage_pct(d), user_pct(d), system_pct(d), idle_pct(d), iowait_pct(d)
SYS_CPU_STAT_FORMAT = '<Iddddd'
SYS_CPU_STAT_SIZE = struct.calcsize(SYS_CPU_STAT_FORMAT)

# Traffic packet format
TRAFFIC_HEADER_FORMAT = '<IIQHH'
TRAFFIC_HEADER_SIZE = struct.calcsize(TRAFFIC_HEADER_FORMAT)
# C struct: timestamp(Q), src_ip(I), dst_ip(I), src_port(H), dst_port(H),
#           protocol(B), flags(B), pkt_len(H), port_id(H), direction(B), pad(B)
TRAFFIC_ENTRY_FORMAT = '<QIIHHBBHHBB'
TRAFFIC_ENTRY_SIZE = struct.calcsize(TRAFFIC_ENTRY_FORMAT)
TRAFFIC_PACKET_SIZE = TRAFFIC_HEADER_SIZE + (MAX_TRAFFIC_SAMPLES * TRAFFIC_ENTRY_SIZE)
TRAFFIC_MAGIC = 0x5452464B

PROTO_NAMES = {0: 'Unknown', 1: 'ICMP', 6: 'TCP', 17: 'UDP'}

# Anomaly packet format
ANOMALY_MAGIC = 0x414E4F4D  # "ANOM"
# anomaly_packet: magic(I) + length(I) + timestamp(Q) + active(B) + level(B) + tier_agreement(B) + pad(B) +
#                 max_z_score(d) + confidence(d) + primary_feature(i) + pad(I) + start_time(Q) +
#                 duration(d) + cool_down(d) + baselines_frozen(B) + tier1_ready(B) + tier2_ready(B) +
#                 tier3_ready(B) + baseline_updates(I) + detection_cycles(Q) + detection_count(Q) +
#                 packets_per_sec(Q) + bytes_per_sec(Q) + syn_per_sec(I) + unique_src_ips(I) +
#                 unique_flows(I) + heavy_hitters(I) + rate_limit_pct(I)
ANOMALY_PACKET_FORMAT = '<IIQBBBBddiIQddBBBBIQQQQIIIII'
ANOMALY_PACKET_SIZE = struct.calcsize(ANOMALY_PACKET_FORMAT)

ANOMALY_LEVEL_NAMES = {0: 'NONE', 1: 'LOW', 2: 'MEDIUM', 3: 'HIGH', 4: 'CRITICAL'}

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

# Per-IP anomaly packet format
# Magic: "PERP" = 0x50455250
PER_IP_ANOMALY_MAGIC = 0x50455250
MAX_PER_IP_EXPORT = 64

# per_ip_anomaly_state: dst_ip(I), active(I), anomaly_active(I), anomaly_level(I),
#                       anomaly_start_ns(Q), last_update_ns(Q), max_z_score(d),
#                       tier_agreement(I), anomalous_feature_count(I),
#                       anomaly_protocol(B), attack_type(B), anomaly_dst_port(H), pad(20s)
PER_IP_ANOMALY_ENTRY_FORMAT = '<IIIIQQdIIBBH20s'
PER_IP_ANOMALY_ENTRY_SIZE = struct.calcsize(PER_IP_ANOMALY_ENTRY_FORMAT)

# Per-IP anomaly header: magic(I), length(I), version(Q), active_count(I), pad(I)
PER_IP_ANOMALY_HEADER_FORMAT = '<IIQII'
PER_IP_ANOMALY_HEADER_SIZE = struct.calcsize(PER_IP_ANOMALY_HEADER_FORMAT)
PER_IP_ANOMALY_PACKET_SIZE = PER_IP_ANOMALY_HEADER_SIZE + (MAX_PER_IP_EXPORT * PER_IP_ANOMALY_ENTRY_SIZE)

# Per-IP features packet format (from stats_socket.h)
# Magic: "PIPF" = 0x50495046
PER_IP_FEATURES_MAGIC = 0x50495046

# per_ip_features_entry (94 bytes total, packed):
#   dst_ip(I=4), active(I=4), timestamp_ns(Q=8),                              -> offset 16
#   packets_per_sec(Q=8), bytes_per_sec(Q=8), flows_per_sec(I=4),             -> offset 36
#   syn_per_sec(I=4), syn_ack_per_sec(I=4), ack_per_sec(I=4),
#   rst_per_sec(I=4), fin_per_sec(I=4),                                       -> offset 56
#   tcp_ratio(B=1), udp_ratio(B=1), icmp_ratio(B=1), _pad1(B=1),              -> offset 60
#   unique_src_ips(I=4), unique_flows(I=4),                                   -> offset 68
#   max_flow_fraction(B=1), topk_flow_share(B=1), heavy_hitter_count(H=2),    -> offset 72
#   avg_packets_per_flow(H=2), flow_duration_avg_ms(I=4),                     -> offset 78
#   total_packets(Q=8), active_flows(I=4), _pad2(I=4)                         -> offset 94
# Note: No padding needed - struct is packed with #pragma pack(push, 1)
PER_IP_FEATURES_ENTRY_FORMAT = '<IIQQQIIIIIIBBBBIIBBHHIQII'
PER_IP_FEATURES_ENTRY_SIZE = struct.calcsize(PER_IP_FEATURES_ENTRY_FORMAT)

# Per-IP features header: magic(I), length(I), timestamp_ms(Q), active_count(I), pad(I)
PER_IP_FEATURES_HEADER_FORMAT = '<IIQII'
PER_IP_FEATURES_HEADER_SIZE = struct.calcsize(PER_IP_FEATURES_HEADER_FORMAT)
PER_IP_FEATURES_PACKET_SIZE = PER_IP_FEATURES_HEADER_SIZE + (MAX_PER_IP_EXPORT * PER_IP_FEATURES_ENTRY_SIZE)

# Feature names matching L2_MAX_FEATURES (24 features) from baselines.h
FEATURE_NAMES = [
    # Volume (3)
    'packets_per_sec',      # 0
    'bytes_per_sec',        # 1
    'flows_per_sec',        # 2
    # TCP Flags (5)
    'syn_per_sec',          # 3
    'syn_ack_per_sec',      # 4
    'ack_per_sec',          # 5
    'rst_per_sec',          # 6
    'fin_per_sec',          # 7
    # Protocol Mix (4)
    'tcp_ratio',            # 8
    'udp_ratio',            # 9
    'icmp_ratio',           # 10
    'other_ratio',          # 11
    # Ratios (3)
    'syn_ack_ratio',        # 12
    'rst_syn_ratio',        # 13
    'bytes_per_packet',     # 14
    # Cardinality (3)
    'unique_src_ips',       # 15
    'unique_dst_ports',     # 16
    'unique_flows',         # 17
    # Churn (1)
    'new_srcip_rate',       # 18
    # Concentration (3)
    'max_flow_fraction',    # 19
    'topk_flow_share',      # 20
    'heavy_hitter_count',   # 21
    # Flow Behavior (2)
    'avg_packets_per_flow', # 22
    'flow_duration_avg',    # 23
]

stats_lock = threading.Lock()
current_stats = {'timestamp': 0, 'ports': {}, 'connected': False}
stats_history = []

traffic_lock = threading.Lock()
traffic_data = []
traffic_connected = False

# Anomaly monitor stats
anomaly_lock = threading.Lock()
current_anomaly = {
    'timestamp': 0,
    'active': False,
    'level': 0,
    'level_name': 'NONE',
    'tier_agreement': 0,
    'max_z_score': 0.0,
    'confidence': 0.0,
    'primary_feature': -1,
    'primary_feature_name': 'unknown',
    'duration_sec': 0.0,
    'cool_down_remaining': 0.0,
    'baselines_frozen': False,
    'tier1_ready': False,
    'tier2_ready_count': 0,
    'tier3_ready_count': 0,
    'baseline_updates': 0,
    'detection_cycles': 0,
    'detection_count': 0,
    'packets_per_sec': 0,
    'bytes_per_sec': 0,
    'syn_per_sec': 0,
    'unique_src_ips': 0,
    'unique_flows': 0,
    'heavy_hitters': 0,
    'rate_limit_pct': 100
}

# System monitor stats
sysmon_lock = threading.Lock()
current_sysmon = {
    'timestamp': 0,
    'dpdk': {
        'lcores': [],
        'avg_lcore_utilization': 0,
        'mempools': [],
        'hugepage_total_mb': 0,
        'hugepage_used_mb': 0,
        'hugepage_usage_pct': 0
    },
    'system': {
        'cpus': [],
        'avg_cpu_usage': 0,
        'mem_total_gb': 0,
        'mem_used_gb': 0,
        'mem_available_gb': 0,
        'mem_usage_pct': 0,
        'load_1min': 0,
        'load_5min': 0,
        'load_15min': 0
    }
}


def parse_stats_packet(data):
    if len(data) < HEADER_SIZE:
        return None
    
    magic, length, timestamp_ms, port_count = struct.unpack_from(HEADER_FORMAT, data, 0)
    if magic != MAGIC:
        return None
    
    stats = {
        'timestamp': timestamp_ms,
        'timestamp_str': datetime.fromtimestamp(timestamp_ms / 1000).strftime('%H:%M:%S'),
        'ports': {}
    }
    
    offset = HEADER_SIZE
    for i in range(min(port_count, MAX_PORTS)):
        if offset + PORT_ENTRY_SIZE > len(data):
            break
        values = struct.unpack_from(PORT_ENTRY_FORMAT, data, offset)
        port_id = values[0]
        stats['ports'][port_id] = {
            'port_id': port_id,
            'rx_packets': values[1], 'tx_packets': values[2],
            'rx_bytes': values[3], 'tx_bytes': values[4],
            'dropped': values[5],
            'rx_pps': values[6], 'tx_pps': values[7],
            'rx_bps': values[8], 'tx_bps': values[9],
            'rx_mbps': round(values[8] / 1e6, 2),
            'tx_mbps': round(values[9] / 1e6, 2),
            'rx_kpps': round(values[6] / 1000, 2),
            'tx_kpps': round(values[7] / 1000, 2),
        }
        offset += PORT_ENTRY_SIZE
    return stats


def parse_traffic_packet(data):
    if len(data) < TRAFFIC_HEADER_SIZE:
        return None

    magic, length, timestamp_ms, entry_count, _pad = struct.unpack_from(TRAFFIC_HEADER_FORMAT, data, 0)
    if magic != TRAFFIC_MAGIC:
        return None

    entries = []
    offset = TRAFFIC_HEADER_SIZE
    for i in range(min(entry_count, MAX_TRAFFIC_SAMPLES)):
        if offset + TRAFFIC_ENTRY_SIZE > len(data):
            break
        values = struct.unpack_from(TRAFFIC_ENTRY_FORMAT, data, offset)

        timestamp_ms_entry = values[0]
        src_ip = values[1]
        dst_ip = values[2]
        src_port = values[3]
        dst_port = values[4]
        protocol = values[5]
        flags = values[6]
        pkt_len = values[7]
        port_id = values[8]
        direction = values[9]

        # Convert IP to string
        src_ip_str = f"{(src_ip >> 24) & 0xFF}.{(src_ip >> 16) & 0xFF}.{(src_ip >> 8) & 0xFF}.{src_ip & 0xFF}"
        dst_ip_str = f"{(dst_ip >> 24) & 0xFF}.{(dst_ip >> 16) & 0xFF}.{(dst_ip >> 8) & 0xFF}.{dst_ip & 0xFF}"

        entry = {
            'timestamp': timestamp_ms_entry,
            'timestamp_str': datetime.fromtimestamp(timestamp_ms_entry / 1000).strftime('%H:%M:%S.%f')[:-3],
            'src_ip': src_ip_str,
            'dst_ip': dst_ip_str,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': PROTO_NAMES.get(protocol, f'Proto-{protocol}'),
            'protocol_num': protocol,
            'flags': flags,
            'length': pkt_len,
            'port_id': port_id,
            'direction': 'RX' if direction == 0 else 'TX'
        }
        entries.append(entry)
        offset += TRAFFIC_ENTRY_SIZE

    return entries


def parse_sysmon_packet(data):
    """Parse system monitor packet from DPDK."""
    # Calculate minimum header size
    # magic(I) + length(I) + timestamp(Q) + nb_lcores(H) + pad(H) + avg_lcore_util(d)
    SYSMON_HEADER_SIZE = struct.calcsize('<IIQHHd')

    if len(data) < SYSMON_HEADER_SIZE:
        return None

    offset = 0
    magic, length, timestamp_ms, nb_lcores, _pad1, avg_lcore_util = struct.unpack_from('<IIQHHd', data, offset)
    offset += SYSMON_HEADER_SIZE

    if magic != SYSMON_MAGIC:
        return None

    sysmon = {
        'timestamp': timestamp_ms,
        'timestamp_str': datetime.fromtimestamp(timestamp_ms / 1000).strftime('%H:%M:%S'),
        'dpdk': {
            'lcores': [],
            'avg_lcore_utilization': round(avg_lcore_util, 1),
            'mempools': [],
            'hugepage_total_mb': 0,
            'hugepage_used_mb': 0,
            'hugepage_usage_pct': 0
        },
        'system': {
            'cpus': [],
            'avg_cpu_usage': 0,
            'mem_total_gb': 0,
            'mem_used_gb': 0,
            'mem_available_gb': 0,
            'mem_usage_pct': 0,
            'load_1min': 0,
            'load_5min': 0,
            'load_15min': 0
        }
    }

    # Parse lcore stats
    for i in range(min(nb_lcores, MAX_LCORE_STATS)):
        if offset + LCORE_STAT_SIZE > len(data):
            break
        lcore_id, is_active, busy_cycles, idle_cycles, util_pct = struct.unpack_from(LCORE_STAT_FORMAT, data, offset)
        offset += LCORE_STAT_SIZE

        sysmon['dpdk']['lcores'].append({
            'lcore_id': lcore_id,
            'is_active': is_active != 0,
            'busy_cycles': busy_cycles,
            'idle_cycles': idle_cycles,
            'utilization_pct': round(util_pct, 1)
        })

    # Skip remaining lcore slots
    offset = SYSMON_HEADER_SIZE + (MAX_LCORE_STATS * LCORE_STAT_SIZE)

    # Parse mempool stats: nb_mempools(H) + pad(H)
    if offset + 4 > len(data):
        return sysmon
    nb_mempools, _pad2 = struct.unpack_from('<HH', data, offset)
    offset += 4

    for i in range(min(nb_mempools, MAX_MEMPOOL_STATS)):
        if offset + MEMPOOL_STAT_SIZE > len(data):
            break
        name_bytes, size, avail, in_use, usage_pct = struct.unpack_from(MEMPOOL_STAT_FORMAT, data, offset)
        offset += MEMPOOL_STAT_SIZE

        name = name_bytes.decode('utf-8', errors='ignore').rstrip('\x00')
        sysmon['dpdk']['mempools'].append({
            'name': name,
            'size': size,
            'avail_count': avail,
            'in_use_count': in_use,
            'usage_pct': round(usage_pct, 1)
        })

    # Skip remaining mempool slots
    offset = SYSMON_HEADER_SIZE + (MAX_LCORE_STATS * LCORE_STAT_SIZE) + 4 + (MAX_MEMPOOL_STATS * MEMPOOL_STAT_SIZE)

    # Parse hugepage stats: total(Q), used(Q), usage_pct(d)
    if offset + 24 > len(data):
        return sysmon
    hp_total, hp_used, hp_usage_pct = struct.unpack_from('<QQd', data, offset)
    offset += 24

    sysmon['dpdk']['hugepage_total_mb'] = round(hp_total / (1024 * 1024), 1)
    sysmon['dpdk']['hugepage_used_mb'] = round(hp_used / (1024 * 1024), 1)
    sysmon['dpdk']['hugepage_usage_pct'] = round(hp_usage_pct, 1)

    # Parse system CPU stats: nb_cpus(H), pad(H), avg_cpu_usage(d)
    if offset + 12 > len(data):
        return sysmon
    nb_cpus, _pad3, avg_cpu_usage = struct.unpack_from('<HHd', data, offset)
    offset += 12

    sysmon['system']['avg_cpu_usage'] = round(avg_cpu_usage, 1)

    for i in range(min(nb_cpus, MAX_LCORE_STATS)):
        if offset + SYS_CPU_STAT_SIZE > len(data):
            break
        cpu_id, usage_pct, user_pct, system_pct, idle_pct, iowait_pct = struct.unpack_from(SYS_CPU_STAT_FORMAT, data, offset)
        offset += SYS_CPU_STAT_SIZE

        sysmon['system']['cpus'].append({
            'cpu_id': cpu_id,
            'usage_pct': round(usage_pct, 1),
            'user_pct': round(user_pct, 1),
            'system_pct': round(system_pct, 1),
            'idle_pct': round(idle_pct, 1),
            'iowait_pct': round(iowait_pct, 1)
        })

    # Skip remaining CPU slots
    offset = (SYSMON_HEADER_SIZE + (MAX_LCORE_STATS * LCORE_STAT_SIZE) + 4 +
              (MAX_MEMPOOL_STATS * MEMPOOL_STAT_SIZE) + 24 + 12 +
              (MAX_LCORE_STATS * SYS_CPU_STAT_SIZE))

    # Parse system memory stats: total(Q), free(Q), available(Q), used(Q), usage_pct(d)
    if offset + 40 > len(data):
        return sysmon
    mem_total, mem_free, mem_avail, mem_used, mem_usage_pct = struct.unpack_from('<QQQQd', data, offset)
    offset += 40

    sysmon['system']['mem_total_gb'] = round(mem_total / (1024 * 1024 * 1024), 2)
    sysmon['system']['mem_free_gb'] = round(mem_free / (1024 * 1024 * 1024), 2)
    sysmon['system']['mem_available_gb'] = round(mem_avail / (1024 * 1024 * 1024), 2)
    sysmon['system']['mem_used_gb'] = round(mem_used / (1024 * 1024 * 1024), 2)
    sysmon['system']['mem_usage_pct'] = round(mem_usage_pct, 1)

    # Parse load average: load_1min(d), load_5min(d), load_15min(d)
    if offset + 24 > len(data):
        return sysmon
    load_1, load_5, load_15 = struct.unpack_from('<ddd', data, offset)

    sysmon['system']['load_1min'] = round(load_1, 2)
    sysmon['system']['load_5min'] = round(load_5, 2)
    sysmon['system']['load_15min'] = round(load_15, 2)

    return sysmon


def parse_per_ip_anomaly_packet(data):
    """Parse per-IP anomaly packet from DPDK Layer 2."""
    if len(data) < PER_IP_ANOMALY_PACKET_SIZE:
        return None

    try:
        # Parse header
        header = struct.unpack_from(PER_IP_ANOMALY_HEADER_FORMAT, data, 0)
    except struct.error:
        return None

    magic = header[0]
    if magic != PER_IP_ANOMALY_MAGIC:
        return None

    # length = header[1]
    # version = header[2]
    active_count = header[3]

    entries = {}
    offset = PER_IP_ANOMALY_HEADER_SIZE

    for i in range(min(active_count, MAX_PER_IP_EXPORT)):
        if offset + PER_IP_ANOMALY_ENTRY_SIZE > len(data):
            break

        try:
            entry = struct.unpack_from(PER_IP_ANOMALY_ENTRY_FORMAT, data, offset)
        except struct.error:
            break

        dst_ip = entry[0]
        active = entry[1]
        anomaly_active = entry[2]
        anomaly_level = entry[3]
        anomaly_start_ns = entry[4]
        last_update_ns = entry[5]
        max_z_score = entry[6]
        tier_agreement = entry[7]
        anomalous_feature_count = entry[8]
        anomaly_protocol = entry[9]
        attack_type = entry[10]
        anomaly_dst_port = entry[11]

        if active:
            # Convert IP from network byte order to host byte order, then to string
            # per_ip_anomaly stores IPs in network order (from htonl in C code)
            dst_ip_host = ntohl(dst_ip)
            ip_str = ip_int_to_str(dst_ip_host)
            entries[ip_str] = {
                'active': True,
                'dst_ip_int': dst_ip_host,  # Store in host order for consistency
                'anomaly_active': anomaly_active != 0,
                'level': anomaly_level,
                'start_time_ns': anomaly_start_ns,
                'last_update_ns': last_update_ns,
                'max_z_score': max_z_score,
                'tier_agreement': tier_agreement,
                'anomalous_feature_count': anomalous_feature_count,
                # Protocol-specific fields
                'anomaly_protocol': anomaly_protocol,
                'anomaly_protocol_name': PROTO_CAT_NAMES.get(anomaly_protocol, 'UNKNOWN'),
                'attack_type': attack_type,
                'attack_type_name': ATTACK_TYPE_NAMES.get(attack_type, 'UNKNOWN'),
                'anomaly_dst_port': anomaly_dst_port,
            }

        offset += PER_IP_ANOMALY_ENTRY_SIZE

    return entries


def parse_per_ip_features_packet(data):
    """Parse per-IP features packet from DPDK stats thread."""
    if len(data) < PER_IP_FEATURES_PACKET_SIZE:
        return None

    try:
        # Parse header
        header = struct.unpack_from(PER_IP_FEATURES_HEADER_FORMAT, data, 0)
    except struct.error:
        return None

    magic = header[0]
    if magic != PER_IP_FEATURES_MAGIC:
        return None

    # length = header[1]
    # timestamp_ms = header[2]
    active_count = header[3]

    entries = {}
    offset = PER_IP_FEATURES_HEADER_SIZE

    for i in range(min(active_count, MAX_PER_IP_EXPORT)):
        if offset + PER_IP_FEATURES_ENTRY_SIZE > len(data):
            break

        try:
            entry = struct.unpack_from(PER_IP_FEATURES_ENTRY_FORMAT, data, offset)
        except struct.error:
            break

        dst_ip_int = entry[0]
        active = entry[1]
        # timestamp_ns = entry[2]
        packets_per_sec = entry[3]
        bytes_per_sec = entry[4]
        flows_per_sec = entry[5]
        syn_per_sec = entry[6]
        syn_ack_per_sec = entry[7]
        ack_per_sec = entry[8]
        rst_per_sec = entry[9]
        fin_per_sec = entry[10]
        tcp_ratio = entry[11]
        udp_ratio = entry[12]
        icmp_ratio = entry[13]
        # pad1 = entry[14]
        unique_src_ips = entry[15]
        unique_flows = entry[16]
        max_flow_fraction = entry[17]
        topk_flow_share = entry[18]
        heavy_hitter_count = entry[19]
        avg_packets_per_flow = entry[20]
        flow_duration_avg_ms = entry[21]
        total_packets = entry[22]
        active_flows = entry[23]

        if active:
            # Convert IP from network byte order to host byte order, then to string
            # per_ip_features stores IPs in network order (from htonl in C code)
            dst_ip_host = ntohl(dst_ip_int)
            ip_str = ip_int_to_str(dst_ip_host)

            # Sanity check: filter out obviously garbage data
            # Ratios should be 0-100, packets_per_sec should be reasonable
            ratio_sum = tcp_ratio + udp_ratio + icmp_ratio
            if ratio_sum > 100 or packets_per_sec > 1e12:
                # Skip this entry - likely corrupted data
                offset += PER_IP_FEATURES_ENTRY_SIZE
                continue

            entries[ip_str] = {
                'active': True,
                'dst_ip_int': dst_ip_host,  # Store in host order for consistency
                'packets_per_sec': packets_per_sec,
                'bytes_per_sec': bytes_per_sec,
                'flows_per_sec': flows_per_sec,
                'syn_per_sec': syn_per_sec,
                'syn_ack_per_sec': syn_ack_per_sec,
                'ack_per_sec': ack_per_sec,
                'rst_per_sec': rst_per_sec,
                'fin_per_sec': fin_per_sec,
                'tcp_ratio': tcp_ratio,
                'udp_ratio': udp_ratio,
                'icmp_ratio': icmp_ratio,
                'other_ratio': max(0, 100 - tcp_ratio - udp_ratio - icmp_ratio),
                'unique_src_ips': unique_src_ips,
                'unique_flows': unique_flows,
                'max_flow_fraction': max_flow_fraction,
                'topk_flow_share': topk_flow_share,
                'heavy_hitter_count': heavy_hitter_count,
                'avg_packets_per_flow': avg_packets_per_flow,
                'flow_duration_avg_ms': flow_duration_avg_ms,
                'total_packets': total_packets,
                'active_flows': active_flows
            }

        offset += PER_IP_FEATURES_ENTRY_SIZE

    return entries


def parse_anomaly_packet(data):
    """Parse anomaly packet from DPDK Layer 2."""
    if len(data) < ANOMALY_PACKET_SIZE:
        return None

    try:
        values = struct.unpack(ANOMALY_PACKET_FORMAT, data[:ANOMALY_PACKET_SIZE])
    except struct.error:
        return None

    magic = values[0]
    if magic != ANOMALY_MAGIC:
        return None

    # length = values[1]
    timestamp_ms = values[2]
    active = values[3]
    level = values[4]
    tier_agreement = values[5]
    # pad = values[6]
    max_z_score = values[7]
    confidence = values[8]
    primary_feature = values[9]
    # pad = values[10]
    # start_time_ns = values[11]
    duration_sec = values[12]
    cool_down_remaining = values[13]
    baselines_frozen = values[14]
    tier1_ready = values[15]
    tier2_ready_count = values[16]
    tier3_ready_count = values[17]
    baseline_updates = values[18]
    detection_cycles = values[19]
    detection_count = values[20]
    packets_per_sec = values[21]
    bytes_per_sec = values[22]
    syn_per_sec = values[23]
    unique_src_ips = values[24]
    unique_flows = values[25]
    heavy_hitters = values[26]
    rate_limit_pct = values[27]

    # Determine primary feature name
    primary_feature_name = 'unknown'
    if 0 <= primary_feature < len(FEATURE_NAMES):
        primary_feature_name = FEATURE_NAMES[primary_feature]

    return {
        'timestamp': timestamp_ms,
        'timestamp_str': datetime.fromtimestamp(timestamp_ms / 1000).strftime('%H:%M:%S'),
        'active': active != 0,
        'level': level,
        'level_name': ANOMALY_LEVEL_NAMES.get(level, 'UNKNOWN'),
        'tier_agreement': tier_agreement,
        'max_z_score': round(max_z_score, 2),
        'confidence': round(confidence * 100, 1),
        'primary_feature': primary_feature,
        'primary_feature_name': primary_feature_name,
        'duration_sec': round(duration_sec, 1),
        'cool_down_remaining': round(cool_down_remaining, 1),
        'baselines_frozen': baselines_frozen != 0,
        'tier1_ready': tier1_ready != 0,
        'tier2_ready_count': tier2_ready_count,
        'tier3_ready_count': tier3_ready_count,
        'baseline_updates': baseline_updates,
        'detection_cycles': detection_cycles,
        'detection_count': detection_count,
        'packets_per_sec': packets_per_sec,
        'bytes_per_sec': bytes_per_sec,
        'syn_per_sec': syn_per_sec,
        'unique_src_ips': unique_src_ips,
        'unique_flows': unique_flows,
        'heavy_hitters': heavy_hitters,
        'rate_limit_pct': rate_limit_pct
    }


def traffic_receiver_thread():
    global traffic_data, traffic_connected
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((TRAFFIC_HOST, TRAFFIC_PORT))
            print("[Flask] Connected to DPDK Traffic Monitor")

            with traffic_lock:
                traffic_connected = True

            buffer = b''
            while True:
                try:
                    data = sock.recv(8192)
                    if not data:
                        break
                    buffer += data

                    while len(buffer) >= TRAFFIC_PACKET_SIZE:
                        entries = parse_traffic_packet(buffer[:TRAFFIC_PACKET_SIZE])
                        buffer = buffer[TRAFFIC_PACKET_SIZE:]

                        if entries:
                            with traffic_lock:
                                traffic_data.extend(entries)
                                # Keep only last 200 entries
                                if len(traffic_data) > 200:
                                    traffic_data = traffic_data[-200:]

                except socket.timeout:
                    continue
        except Exception as e:
            print(f"[Flask] Traffic disconnected: {e}")
            with traffic_lock:
                traffic_connected = False
            time.sleep(2)
        finally:
            try:
                sock.close()
            except:
                pass


def receiver_thread():
    global current_stats, stats_history, current_sysmon, current_anomaly

    # Calculate sysmon packet size
    # Header: magic(I) + length(I) + timestamp(Q) + nb_lcores(H) + pad(H) + avg_lcore_util(d) = 24 bytes
    # Lcores: 64 * 28 = 1792 bytes
    # Mempools header: nb_mempools(H) + pad(H) = 4 bytes
    # Mempools: 8 * 52 = 416 bytes
    # Hugepage: total(Q) + used(Q) + usage_pct(d) = 24 bytes
    # CPU header: nb_cpus(H) + pad(H) + avg_cpu_usage(d) = 12 bytes
    # CPUs: 64 * 44 = 2816 bytes
    # Memory: total(Q) + free(Q) + available(Q) + used(Q) + usage_pct(d) = 40 bytes
    # Load: load_1(d) + load_5(d) + load_15(d) = 24 bytes
    SYSMON_PACKET_SIZE = 24 + (MAX_LCORE_STATS * LCORE_STAT_SIZE) + 4 + (MAX_MEMPOOL_STATS * MEMPOOL_STAT_SIZE) + 24 + 12 + (MAX_LCORE_STATS * SYS_CPU_STAT_SIZE) + 40 + 24

    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((STATS_HOST, STATS_PORT))
            print("[Flask] Connected to DPDK")

            with stats_lock:
                current_stats['connected'] = True

            buffer = b''
            while True:
                try:
                    data = sock.recv(16384)  # Larger buffer for sysmon packets
                    if not data:
                        break
                    buffer += data

                    # Process all complete packets in buffer
                    while len(buffer) >= 4:
                        # Peek at magic number to determine packet type
                        magic = struct.unpack_from('<I', buffer, 0)[0]

                        if magic == MAGIC:
                            # Stats packet
                            if len(buffer) < PACKET_SIZE:
                                break
                            stats = parse_stats_packet(buffer[:PACKET_SIZE])
                            buffer = buffer[PACKET_SIZE:]

                            if stats:
                                with stats_lock:
                                    current_stats = stats
                                    current_stats['connected'] = True
                                    stats_history.append(stats)
                                    if len(stats_history) > 120:
                                        stats_history = stats_history[-120:]

                        elif magic == SYSMON_MAGIC:
                            # System monitor packet
                            if len(buffer) < SYSMON_PACKET_SIZE:
                                break
                            sysmon = parse_sysmon_packet(buffer[:SYSMON_PACKET_SIZE])
                            buffer = buffer[SYSMON_PACKET_SIZE:]

                            if sysmon:
                                with sysmon_lock:
                                    current_sysmon = sysmon

                        elif magic == ANOMALY_MAGIC:
                            # Layer 2 anomaly packet
                            if len(buffer) < ANOMALY_PACKET_SIZE:
                                break
                            anomaly = parse_anomaly_packet(buffer[:ANOMALY_PACKET_SIZE])
                            buffer = buffer[ANOMALY_PACKET_SIZE:]

                            if anomaly:
                                with anomaly_lock:
                                    current_anomaly = anomaly

                        elif magic == PER_IP_ANOMALY_MAGIC:
                            # Per-IP anomaly packet
                            if len(buffer) < PER_IP_ANOMALY_PACKET_SIZE:
                                break
                            per_ip = parse_per_ip_anomaly_packet(buffer[:PER_IP_ANOMALY_PACKET_SIZE])
                            buffer = buffer[PER_IP_ANOMALY_PACKET_SIZE:]

                            if per_ip:
                                with per_ip_anomaly_lock:
                                    per_ip_anomaly_data.update(per_ip)

                        elif magic == PER_IP_FEATURES_MAGIC:
                            # Per-IP features packet
                            if len(buffer) < PER_IP_FEATURES_PACKET_SIZE:
                                break
                            per_ip_feat = parse_per_ip_features_packet(buffer[:PER_IP_FEATURES_PACKET_SIZE])
                            buffer = buffer[PER_IP_FEATURES_PACKET_SIZE:]

                            if per_ip_feat:
                                with per_ip_features_lock:
                                    per_ip_features_data.update(per_ip_feat)

                        else:
                            # Unknown packet, skip 1 byte and try again
                            buffer = buffer[1:]

                except socket.timeout:
                    continue
        except Exception as e:
            print(f"[Flask] Disconnected: {e}")
            with stats_lock:
                current_stats['connected'] = False
            time.sleep(2)
        finally:
            try:
                sock.close()
            except:
                pass


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/rules')
def rules():
    return render_template('rules.html')

@app.route('/api/stats')
def api_stats():
    with stats_lock:
        return jsonify(current_stats)

@app.route('/api/history')
def api_history():
    with stats_lock:
        return jsonify(stats_history[-60:])

@app.route('/api/traffic')
def api_traffic():
    with traffic_lock:
        return jsonify({
            'connected': traffic_connected,
            'entries': traffic_data[-100:]  # Last 100 entries
        })

@app.route('/api/traffic/clear')
def api_traffic_clear():
    with traffic_lock:
        traffic_data.clear()
    return jsonify({'status': 'cleared'})


@app.route('/api/sysmon')
def api_sysmon():
    """Get system monitor stats (DPDK resources + system CPU/memory)."""
    with sysmon_lock:
        return jsonify(current_sysmon)


@app.route('/api/anomaly')
def api_anomaly():
    """Get Layer 2 anomaly detection status."""
    with anomaly_lock:
        return jsonify(current_anomaly)


# Per-IP anomaly data structure
per_ip_anomaly_lock = threading.Lock()
per_ip_anomaly_data = {}  # dst_ip -> anomaly state

# Per-IP features data structure
per_ip_features_lock = threading.Lock()
per_ip_features_data = {}  # dst_ip -> features stats

def ip_int_to_str(ip_int):
    """Convert IP integer to string.
    IPs from traffic_monitor are in host byte order (already converted via rte_be_to_cpu_32).
    So we read bytes MSB-first from the host-order value.
    """
    # Ensure ip_int is a valid 32-bit unsigned integer
    if not isinstance(ip_int, int) or ip_int < 0 or ip_int > 0xFFFFFFFF:
        return "0.0.0.0"
    # Read bytes MSB-first (IP is in host order, e.g., 0xC0A80205 for 192.168.2.5)
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"


def ntohl(ip_int):
    """Convert network byte order to host byte order (byte swap on little-endian)."""
    if not isinstance(ip_int, int) or ip_int < 0 or ip_int > 0xFFFFFFFF:
        return 0
    # Swap bytes: ABCD -> DCBA
    return ((ip_int & 0xFF) << 24) | ((ip_int & 0xFF00) << 8) | \
           ((ip_int & 0xFF0000) >> 8) | ((ip_int >> 24) & 0xFF)

def ip_str_to_int(ip_str):
    """Convert IP string to integer matching DPDK storage format.
    Returns None on invalid input to prevent integer overflow.
    """
    if not isinstance(ip_str, str):
        return None
    parts = ip_str.split('.')
    if len(parts) != 4:
        return None
    try:
        octets = []
        for part in parts:
            val = int(part)
            if val < 0 or val > 255:
                return None
            octets.append(val)
        # Store in network byte order (MSB first) to match DPDK
        return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    except (ValueError, TypeError):
        return None

@app.route('/api/anomaly/per-ip')
def api_per_ip_anomaly():
    """Get per-protected-IP anomaly detection status."""
    with per_ip_anomaly_lock:
        result = []
        # Keys in per_ip_anomaly_data are now IP strings (e.g., "192.168.2.7")
        for ip_str, state in per_ip_anomaly_data.items():
            if state.get('active', False):
                result.append({
                    'dst_ip': state.get('dst_ip_int', 0),  # Keep raw int for backward compat
                    'dst_ip_str': ip_str,
                    'anomaly_active': state.get('anomaly_active', False),
                    'level': state.get('level', 0),
                    'level_name': ANOMALY_LEVEL_NAMES.get(state.get('level', 0), 'UNKNOWN'),
                    'max_z_score': round(state.get('max_z_score', 0.0), 2),
                    'tier_agreement': state.get('tier_agreement', 0),
                    'anomalous_feature_count': state.get('anomalous_feature_count', 0),
                    'start_time_ns': state.get('start_time_ns', 0),
                    'last_update_ns': state.get('last_update_ns', 0),
                    # Protocol-specific anomaly info
                    'anomaly_protocol': state.get('anomaly_protocol', 255),
                    'anomaly_protocol_name': state.get('anomaly_protocol_name', 'ALL'),
                    'attack_type': state.get('attack_type', 0),
                    'attack_type_name': state.get('attack_type_name', 'UNKNOWN'),
                    'anomaly_dst_port': state.get('anomaly_dst_port', 0),
                })
        return jsonify({
            'per_ip_anomalies': result,
            'count': len(result),
            'any_active': any(s.get('anomaly_active', False) for s in per_ip_anomaly_data.values())
        })


@app.route('/api/anomaly/per-ip/<ip>')
def api_per_ip_anomaly_single(ip):
    """Get anomaly status for a specific protected IP."""
    with per_ip_anomaly_lock:
        # Keys are now IP strings (e.g., "192.168.2.7")
        state = per_ip_anomaly_data.get(ip)

        if state is None:
            return jsonify({'error': f'Protected IP {ip} not found'}), 404

        return jsonify({
            'dst_ip': ip,
            'anomaly_active': state.get('anomaly_active', False),
            'level': state.get('level', 0),
            'level_name': ANOMALY_LEVEL_NAMES.get(state.get('level', 0), 'UNKNOWN'),
            'max_z_score': round(state.get('max_z_score', 0.0), 2),
            'tier_agreement': state.get('tier_agreement', 0),
            'anomalous_feature_count': state.get('anomalous_feature_count', 0),
            # Protocol-specific anomaly info
            'anomaly_protocol': state.get('anomaly_protocol', 255),
            'anomaly_protocol_name': state.get('anomaly_protocol_name', 'ALL'),
            'attack_type': state.get('attack_type', 0),
            'attack_type_name': state.get('attack_type_name', 'UNKNOWN'),
            'anomaly_dst_port': state.get('anomaly_dst_port', 0),
        })


@app.route('/api/anomaly/per-ip/summary')
def api_per_ip_anomaly_summary():
    """Get summary of per-IP anomaly detection."""
    with per_ip_anomaly_lock:
        total_ips = len([s for s in per_ip_anomaly_data.values() if s.get('active', False)])
        anomalous_ips = len([s for s in per_ip_anomaly_data.values()
                            if s.get('active', False) and s.get('anomaly_active', False)])

        # Get highest severity
        max_level = 0
        max_z = 0.0
        for state in per_ip_anomaly_data.values():
            if state.get('anomaly_active', False):
                if state.get('level', 0) > max_level:
                    max_level = state.get('level', 0)
                if state.get('max_z_score', 0.0) > max_z:
                    max_z = state.get('max_z_score', 0.0)

        return jsonify({
            'total_protected_ips': total_ips,
            'anomalous_ips': anomalous_ips,
            'healthy_ips': total_ips - anomalous_ips,
            'max_severity_level': max_level,
            'max_severity_name': ANOMALY_LEVEL_NAMES.get(max_level, 'UNKNOWN'),
            'max_z_score': round(max_z, 2)
        })


# ==================== Per-IP Statistics API ====================

@app.route('/api/debug/per-ip-keys')
def api_debug_per_ip_keys():
    """Debug endpoint: show keys in per_ip_features_data and protected IPs."""
    with per_ip_features_lock:
        dpdk_keys = list(per_ip_features_data.keys())
    protected = [p.get('ip', '') for p in rules_engine.get_protected()]
    return jsonify({
        'dpdk_keys': dpdk_keys,
        'protected_ips': protected,
        'match_check': {ip: ip in dpdk_keys for ip in protected}
    })

@app.route('/api/stats/per-ip')
def api_per_ip_stats():
    """Get per-protected-IP traffic statistics with anomaly status combined.

    Shows ONLY protected IPs from rules engine, with traffic data from DPDK if available.
    Non-protected IPs from DPDK data are filtered out.
    If DPDK is not running, protected IPs are still shown with zero traffic stats.
    """
    result = []

    # Get list of protected IPs from rules engine - this is the authoritative source
    protected_ips = rules_engine.get_protected()

    for protected in protected_ips:
        ip_str = protected.get('ip', '')
        if not ip_str:
            continue

        # Look up DPDK traffic data for this protected IP
        features = None
        has_traffic_data = False

        with per_ip_features_lock:
            features = per_ip_features_data.get(ip_str)
            if features is not None and features.get('active', False):
                has_traffic_data = True

        if has_traffic_data:
            # We have DPDK traffic data for this protected IP
            entry = {
                'dst_ip': features.get('dst_ip_int', 0),  # Keep raw int for backward compat
                'dst_ip_str': ip_str,
                'has_traffic_data': True,
                'description': protected.get('description', ''),
                # Traffic stats
                'packets_per_sec': features.get('packets_per_sec', 0),
                'bytes_per_sec': features.get('bytes_per_sec', 0),
                'flows_per_sec': features.get('flows_per_sec', 0),
                'total_packets': features.get('total_packets', 0),
                'active_flows': features.get('active_flows', 0),
                # TCP flags
                'syn_per_sec': features.get('syn_per_sec', 0),
                'syn_ack_per_sec': features.get('syn_ack_per_sec', 0),
                'ack_per_sec': features.get('ack_per_sec', 0),
                'rst_per_sec': features.get('rst_per_sec', 0),
                'fin_per_sec': features.get('fin_per_sec', 0),
                # Protocol mix
                'tcp_ratio': features.get('tcp_ratio', 0),
                'udp_ratio': features.get('udp_ratio', 0),
                'icmp_ratio': features.get('icmp_ratio', 0),
                'other_ratio': features.get('other_ratio', 0),
                # Cardinality
                'unique_src_ips': features.get('unique_src_ips', 0),
                'unique_flows': features.get('unique_flows', 0),
                # Concentration
                'max_flow_fraction': features.get('max_flow_fraction', 0),
                'topk_flow_share': features.get('topk_flow_share', 0),
                'heavy_hitter_count': features.get('heavy_hitter_count', 0),
                # Flow behavior
                'avg_packets_per_flow': features.get('avg_packets_per_flow', 0),
                'flow_duration_avg_ms': features.get('flow_duration_avg_ms', 0),
            }

            # Add anomaly status if available
            with per_ip_anomaly_lock:
                anomaly = per_ip_anomaly_data.get(ip_str, {})
                entry['anomaly_active'] = anomaly.get('anomaly_active', False)
                entry['anomaly_level'] = anomaly.get('level', 0)
                entry['anomaly_level_name'] = ANOMALY_LEVEL_NAMES.get(anomaly.get('level', 0), 'NONE')
                entry['max_z_score'] = round(anomaly.get('max_z_score', 0.0), 2)
                entry['tier_agreement'] = anomaly.get('tier_agreement', 0)
                # Protocol-specific anomaly info
                entry['anomaly_protocol'] = anomaly.get('anomaly_protocol', 255)
                entry['anomaly_protocol_name'] = PROTO_CAT_NAMES.get(anomaly.get('anomaly_protocol', 255), 'ALL')
                entry['attack_type'] = anomaly.get('attack_type', 0)
                entry['attack_type_name'] = ATTACK_TYPE_NAMES.get(anomaly.get('attack_type', 0), 'UNKNOWN')
                entry['anomaly_dst_port'] = anomaly.get('anomaly_dst_port', 0)
        else:
            # No DPDK data for this protected IP - show with zero stats
            ip_int = ip_str_to_int(ip_str)
            dst_ip = ip_int if ip_int is not None else 0

            entry = {
                'dst_ip': dst_ip,
                'dst_ip_str': ip_str,
                'has_traffic_data': False,
                'description': protected.get('description', ''),
                # Zero traffic stats (no DPDK data)
                'packets_per_sec': 0,
                'bytes_per_sec': 0,
                'flows_per_sec': 0,
                'total_packets': 0,
                'active_flows': 0,
                'syn_per_sec': 0,
                'syn_ack_per_sec': 0,
                'ack_per_sec': 0,
                'rst_per_sec': 0,
                'fin_per_sec': 0,
                'tcp_ratio': 0,
                'udp_ratio': 0,
                'icmp_ratio': 0,
                'other_ratio': 0,
                'unique_src_ips': 0,
                'unique_flows': 0,
                'max_flow_fraction': 0,
                'topk_flow_share': 0,
                'heavy_hitter_count': 0,
                'avg_packets_per_flow': 0,
                'flow_duration_avg_ms': 0,
                # No anomaly data (DPDK not running)
                'anomaly_active': False,
                'anomaly_level': 0,
                'anomaly_level_name': 'NONE',
                'max_z_score': 0.0,
                'tier_agreement': 0,
                'anomaly_protocol': 255,
                'anomaly_protocol_name': 'ALL',
                'attack_type': 0,
                'attack_type_name': 'UNKNOWN',
                'anomaly_dst_port': 0,
            }

        result.append(entry)

    # Sort by packets_per_sec descending (most active first), then by IP
    result.sort(key=lambda x: (-x['packets_per_sec'], x['dst_ip_str']))

    # Calculate totals
    total_pps = sum(e['packets_per_sec'] for e in result)
    total_bps = sum(e['bytes_per_sec'] for e in result)
    total_packets = sum(e['total_packets'] for e in result)

    return jsonify({
        'protected_ips': result,
        'count': len(result),
        'totals': {
            'packets_per_sec': total_pps,
            'bytes_per_sec': total_bps,
            'total_packets': total_packets
        }
    })


@app.route('/api/stats/per-ip/<ip>')
def api_per_ip_stats_single(ip):
    """Get detailed statistics for a specific protected IP.

    Returns data from DPDK if available, otherwise returns basic info from rules engine.
    """
    features = None
    has_traffic_data = False

    with per_ip_features_lock:
        # Keys are now IP strings (e.g., "192.168.2.7")
        features = per_ip_features_data.get(ip)

        if features is not None and features.get('active', False):
            has_traffic_data = True

    # If no DPDK data, check if IP exists in rules engine
    if not has_traffic_data:
        protected_ips = rules_engine.get_protected()
        protected_entry = None
        for p in protected_ips:
            if p.get('ip') == ip:
                protected_entry = p
                break

        if protected_entry is None:
            return jsonify({'error': f'Protected IP {ip} not found'}), 404

        # Return basic info from rules engine (no traffic data)
        return jsonify({
            'dst_ip': ip,
            'dst_ip_str': ip,
            'has_traffic_data': False,
            'description': protected_entry.get('description', ''),
            # Zero traffic stats
            'packets_per_sec': 0,
            'bytes_per_sec': 0,
            'flows_per_sec': 0,
            'total_packets': 0,
            'active_flows': 0,
            'syn_per_sec': 0,
            'syn_ack_per_sec': 0,
            'ack_per_sec': 0,
            'rst_per_sec': 0,
            'fin_per_sec': 0,
            'tcp_ratio': 0,
            'udp_ratio': 0,
            'icmp_ratio': 0,
            'other_ratio': 0,
            'unique_src_ips': 0,
            'unique_flows': 0,
            'max_flow_fraction': 0,
            'topk_flow_share': 0,
            'heavy_hitter_count': 0,
            'avg_packets_per_flow': 0,
            'flow_duration_avg_ms': 0,
            # No anomaly data
            'anomaly_active': False,
            'anomaly_level': 0,
            'anomaly_level_name': 'NONE',
            'max_z_score': 0.0,
            'tier_agreement': 0,
            'anomalous_feature_count': 0,
            'anomaly_protocol': 255,
            'anomaly_protocol_name': 'ALL',
            'attack_type': 0,
            'attack_type_name': 'UNKNOWN',
            'anomaly_dst_port': 0,
        })

    # Return full traffic data from DPDK
    dst_ip = ip
    if ip_int := ip_str_to_int(ip):
        dst_ip = str(ip_int)

    ip_str = ip_int_to_str(int(dst_ip)) if str(dst_ip).isdigit() else dst_ip

    result = {
        'dst_ip': dst_ip,
        'dst_ip_str': ip_str,
        'has_traffic_data': True,
        # Traffic stats
        'packets_per_sec': features.get('packets_per_sec', 0),
        'bytes_per_sec': features.get('bytes_per_sec', 0),
        'flows_per_sec': features.get('flows_per_sec', 0),
        'total_packets': features.get('total_packets', 0),
        'active_flows': features.get('active_flows', 0),
        # TCP flags
        'syn_per_sec': features.get('syn_per_sec', 0),
        'syn_ack_per_sec': features.get('syn_ack_per_sec', 0),
        'ack_per_sec': features.get('ack_per_sec', 0),
        'rst_per_sec': features.get('rst_per_sec', 0),
        'fin_per_sec': features.get('fin_per_sec', 0),
        # Protocol mix
        'tcp_ratio': features.get('tcp_ratio', 0),
        'udp_ratio': features.get('udp_ratio', 0),
        'icmp_ratio': features.get('icmp_ratio', 0),
        'other_ratio': features.get('other_ratio', 0),
        # Cardinality
        'unique_src_ips': features.get('unique_src_ips', 0),
        'unique_flows': features.get('unique_flows', 0),
        # Concentration
        'max_flow_fraction': features.get('max_flow_fraction', 0),
        'topk_flow_share': features.get('topk_flow_share', 0),
        'heavy_hitter_count': features.get('heavy_hitter_count', 0),
        # Flow behavior
        'avg_packets_per_flow': features.get('avg_packets_per_flow', 0),
        'flow_duration_avg_ms': features.get('flow_duration_avg_ms', 0),
    }

    # Add anomaly status
    with per_ip_anomaly_lock:
        anomaly = per_ip_anomaly_data.get(dst_ip, {})
        result['anomaly_active'] = anomaly.get('anomaly_active', False)
        result['anomaly_level'] = anomaly.get('level', 0)
        result['anomaly_level_name'] = ANOMALY_LEVEL_NAMES.get(anomaly.get('level', 0), 'NONE')
        result['max_z_score'] = round(anomaly.get('max_z_score', 0.0), 2)
        result['tier_agreement'] = anomaly.get('tier_agreement', 0)
        result['anomalous_feature_count'] = anomaly.get('anomalous_feature_count', 0)
        # Protocol-specific anomaly info
        result['anomaly_protocol'] = anomaly.get('anomaly_protocol', 255)
        result['anomaly_protocol_name'] = PROTO_CAT_NAMES.get(anomaly.get('anomaly_protocol', 255), 'ALL')
        result['attack_type'] = anomaly.get('attack_type', 0)
        result['attack_type_name'] = ATTACK_TYPE_NAMES.get(anomaly.get('attack_type', 0), 'UNKNOWN')
        result['anomaly_dst_port'] = anomaly.get('anomaly_dst_port', 0)

    return jsonify(result)


# ==================== Rules API ====================

@app.route('/api/rules/stats')
def api_rules_stats():
    """Get rules engine statistics."""
    return jsonify(rules_engine.get_stats())


@app.route('/api/rules/whitelist', methods=['GET'])
def api_get_whitelist():
    """Get all whitelist entries."""
    return jsonify({
        'entries': rules_engine.get_whitelist(),
        'count': len(rules_engine.whitelist)
    })


def sanitize_description(desc):
    """Sanitize description field to prevent log/command injection.
    - Limit length to 256 characters
    - Remove control characters and newlines (prevent log injection)
    - Escape HTML entities (prevent XSS if displayed in web UI)
    """
    if not isinstance(desc, str):
        return ''
    # Limit length
    desc = desc[:256]
    # Remove control characters including newlines (prevent log injection)
    # Allow only printable ASCII and common Unicode letters
    import re
    desc = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', desc)
    # Escape HTML entities for XSS prevention
    desc = desc.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    desc = desc.replace('"', '&quot;').replace("'", '&#x27;')
    return desc


@app.route('/api/rules/whitelist', methods=['POST'])
def api_add_whitelist():
    """Add IP to whitelist."""
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'error': 'Missing IP address'}), 400

    ip = data['ip']
    # Sanitize description to prevent log/command injection
    description = sanitize_description(data.get('description', ''))
    expires_hours = data.get('expires_hours')

    expires = None
    if expires_hours:
        expires = datetime.now() + timedelta(hours=int(expires_hours))

    if rules_engine.add_whitelist(ip, description, expires):
        return jsonify({'status': 'added', 'ip': ip})
    else:
        return jsonify({'error': 'Failed to add IP'}), 400


@app.route('/api/rules/whitelist/<ip>', methods=['DELETE'])
def api_delete_whitelist(ip):
    """Remove IP from whitelist."""
    if rules_engine.remove_whitelist(ip):
        return jsonify({'status': 'removed', 'ip': ip})
    else:
        return jsonify({'error': 'IP not found'}), 404


@app.route('/api/rules/whitelist/clear', methods=['POST'])
def api_clear_whitelist():
    """Clear all whitelist entries."""
    count = rules_engine.clear_whitelist()
    return jsonify({'status': 'cleared', 'count': count})


@app.route('/api/rules/blacklist', methods=['GET'])
def api_get_blacklist():
    """Get all blacklist entries."""
    return jsonify({
        'entries': rules_engine.get_blacklist(),
        'count': len(rules_engine.blacklist)
    })


@app.route('/api/rules/blacklist', methods=['POST'])
def api_add_blacklist():
    """Add IP to blacklist."""
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'error': 'Missing IP address'}), 400

    ip = data['ip']
    # Sanitize description to prevent log/command injection
    description = sanitize_description(data.get('description', ''))
    expires_hours = data.get('expires_hours')

    expires = None
    if expires_hours:
        expires = datetime.now() + timedelta(hours=int(expires_hours))

    if rules_engine.add_blacklist(ip, description, expires):
        return jsonify({'status': 'added', 'ip': ip})
    else:
        return jsonify({'error': 'Failed to add IP'}), 400


@app.route('/api/rules/blacklist/<ip>', methods=['DELETE'])
def api_delete_blacklist(ip):
    """Remove IP from blacklist."""
    if rules_engine.remove_blacklist(ip):
        return jsonify({'status': 'removed', 'ip': ip})
    else:
        return jsonify({'error': 'IP not found'}), 404


@app.route('/api/rules/blacklist/clear', methods=['POST'])
def api_clear_blacklist():
    """Clear all blacklist entries."""
    count = rules_engine.clear_blacklist()
    return jsonify({'status': 'cleared', 'count': count})


@app.route('/api/rules/protected', methods=['GET'])
def api_get_protected():
    """Get all protected server entries."""
    return jsonify({
        'entries': rules_engine.get_protected(),
        'count': len(rules_engine.protected)
    })


@app.route('/api/rules/protected', methods=['POST'])
def api_add_protected():
    """Add IP to protected servers."""
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'error': 'Missing IP address'}), 400

    ip = data['ip']
    # Sanitize description to prevent log/command injection
    description = sanitize_description(data.get('description', ''))

    if rules_engine.add_protected(ip, description):
        return jsonify({'status': 'added', 'ip': ip})
    else:
        return jsonify({'error': 'Failed to add IP'}), 400


@app.route('/api/rules/protected/<ip>', methods=['DELETE'])
def api_delete_protected(ip):
    """Remove IP from protected servers."""
    if rules_engine.remove_protected(ip):
        return jsonify({'status': 'removed', 'ip': ip})
    else:
        return jsonify({'error': 'IP not found'}), 404


@app.route('/api/rules/protected/clear', methods=['POST'])
def api_clear_protected():
    """Clear all protected server IPs.

    This removes ALL protected IPs from both the backend storage and the DPDK datapath.
    Use with caution - if enforce_protected_ips is enabled, ALL traffic will be dropped.
    """
    count = rules_engine.clear_protected()
    return jsonify({
        'status': 'cleared',
        'count': count,
        'warning': 'If enforce_protected_ips is enabled, all traffic will now be dropped'
    })


@app.route('/api/rules/check/<ip>')
def api_check_ip(ip):
    """Check if IP is in any list."""
    return jsonify(rules_engine.check_ip(ip))


@app.route('/api/rules/cleanup', methods=['POST'])
def api_cleanup_expired():
    """Remove expired rules."""
    count = rules_engine.cleanup_expired()
    return jsonify({'status': 'cleaned', 'count': count})


@app.route('/api/rules/sync', methods=['POST'])
def api_sync_rules():
    """Sync all rules to DPDK datapath.

    Call this after DPDK starts to ensure all rules are registered.
    """
    synced = rules_engine.sync_to_datapath()
    total = (len(rules_engine.whitelist) + len(rules_engine.blacklist) +
             len(rules_engine.protected) + len(rules_engine.cidr_whitelist))
    return jsonify({
        'status': 'synced',
        'synced': synced,
        'total': total
    })


# ==================== Configuration API ====================

@app.route('/api/config')
def api_get_config():
    """Get full Layer1 configuration."""
    return jsonify(config_manager.get_config())


@app.route('/api/config/info')
def api_config_info():
    """Get configuration metadata."""
    return jsonify(config_manager.get_config_info())


@app.route('/api/config/schema')
def api_config_schema():
    """Get configuration schema with field descriptions."""
    return jsonify(config_manager.get_config_schema())


@app.route('/api/config/section/<section>')
def api_get_config_section(section):
    """Get a specific configuration section."""
    data = config_manager.get_section(section)
    if data is None:
        return jsonify({'error': f'Section {section} not found'}), 404
    return jsonify(data)


@app.route('/api/config/section/<section>', methods=['PUT'])
def api_update_config_section(section):
    """Update a configuration section."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing data'}), 400

    if config_manager.update_section(section, data):
        return jsonify({'status': 'updated', 'section': section})
    else:
        return jsonify({'error': f'Failed to update section {section}'}), 400


@app.route('/api/config/section/<section>/reset', methods=['POST'])
def api_reset_config_section(section):
    """Reset a configuration section to defaults."""
    if config_manager.reset_section(section):
        return jsonify({'status': 'reset', 'section': section})
    else:
        return jsonify({'error': f'Section {section} not found'}), 404


@app.route('/api/config/value/<section>/<key>', methods=['PUT'])
def api_update_config_value(section, key):
    """Update a single configuration value."""
    data = request.get_json()
    if data is None or 'value' not in data:
        return jsonify({'error': 'Missing value'}), 400

    if config_manager.update_value(section, key, data['value']):
        return jsonify({'status': 'updated', 'section': section, 'key': key})
    else:
        return jsonify({'error': f'Failed to update {section}.{key}'}), 400


@app.route('/api/config/top-level', methods=['PUT'])
def api_update_top_level_config():
    """Update a top-level configuration value (log_level, stats_enabled, monitor_only)."""
    data = request.get_json()
    if data is None or 'key' not in data or 'value' not in data:
        return jsonify({'error': 'Missing key or value'}), 400

    key = data['key']
    value = data['value']

    # Only allow specific top-level keys
    allowed_keys = ['log_level', 'stats_enabled', 'monitor_only']
    if key not in allowed_keys:
        return jsonify({'error': f'Invalid top-level key: {key}'}), 400

    if config_manager.update_top_level(key, value):
        return jsonify({'status': 'updated', 'key': key})
    else:
        return jsonify({'error': f'Failed to update {key}'}), 400


@app.route('/api/config/reset', methods=['POST'])
def api_reset_config():
    """Reset entire configuration to defaults."""
    if config_manager.reset_to_defaults():
        return jsonify({'status': 'reset'})
    else:
        return jsonify({'error': 'Failed to reset configuration'}), 500


@app.route('/api/config/reload', methods=['POST'])
def api_reload_config():
    """Reload configuration from file."""
    if config_manager.load_config():
        return jsonify({'status': 'reloaded'})
    else:
        return jsonify({'error': 'Failed to reload configuration'}), 500


# ==================== Stages API ====================

@app.route('/api/stages')
def api_get_stages():
    """Get all stages with current status."""
    return jsonify({
        'stages': config_manager.get_stages()
    })


@app.route('/api/stages/categories')
def api_get_stages_by_category():
    """Get stages grouped by category."""
    return jsonify(config_manager.get_stages_by_category())


@app.route('/api/stages/<stage_id>')
def api_get_stage(stage_id):
    """Get status of a specific stage."""
    status = config_manager.get_stage_status(stage_id)
    if status is None:
        return jsonify({'error': f'Stage {stage_id} not found'}), 404
    return jsonify(status)


@app.route('/api/stages/<stage_id>/enable', methods=['POST'])
def api_enable_stage(stage_id):
    """Enable a stage."""
    if config_manager.set_stage_enabled(stage_id, True):
        return jsonify({'status': 'enabled', 'stage': stage_id})
    else:
        return jsonify({'error': f'Failed to enable stage {stage_id}'}), 400


@app.route('/api/stages/<stage_id>/disable', methods=['POST'])
def api_disable_stage(stage_id):
    """Disable a stage."""
    if config_manager.set_stage_enabled(stage_id, False):
        return jsonify({'status': 'disabled', 'stage': stage_id})
    else:
        return jsonify({'error': f'Failed to disable stage {stage_id}'}), 400


@app.route('/api/stages/<stage_id>/toggle', methods=['POST'])
def api_toggle_stage(stage_id):
    """Toggle a stage's enabled state."""
    status = config_manager.get_stage_status(stage_id)
    if status is None:
        return jsonify({'error': f'Stage {stage_id} not found'}), 404

    new_state = not status['enabled']
    if config_manager.set_stage_enabled(stage_id, new_state):
        return jsonify({
            'status': 'toggled',
            'stage': stage_id,
            'enabled': new_state
        })
    else:
        return jsonify({'error': f'Failed to toggle stage {stage_id}'}), 400


# ==================== Geo-Blocking API ====================

@app.route('/api/geo')
def api_get_geo_blocking():
    """Get geo-blocking configuration with all available countries."""
    return jsonify(config_manager.get_geo_blocking())


@app.route('/api/geo/enabled', methods=['POST'])
def api_set_geo_enabled():
    """Enable or disable geo-blocking."""
    data = request.get_json()
    if data is None or 'enabled' not in data:
        return jsonify({'error': 'Missing enabled field'}), 400

    if config_manager.set_geo_blocking_enabled(data['enabled']):
        return jsonify({'status': 'updated', 'enabled': data['enabled']})
    else:
        return jsonify({'error': 'Failed to update geo-blocking state'}), 400


@app.route('/api/geo/mode', methods=['POST'])
def api_set_geo_mode():
    """Set geo-blocking mode (blacklist or whitelist)."""
    data = request.get_json()
    if data is None or 'mode' not in data:
        return jsonify({'error': 'Missing mode field'}), 400

    mode = data['mode']
    if mode not in ('blacklist', 'whitelist'):
        return jsonify({'error': 'Mode must be "blacklist" or "whitelist"'}), 400

    if config_manager.set_geo_blocking_mode(mode):
        return jsonify({'status': 'updated', 'mode': mode})
    else:
        return jsonify({'error': 'Failed to update geo-blocking mode'}), 400


@app.route('/api/geo/countries', methods=['GET'])
def api_get_geo_countries():
    """Get currently configured countries."""
    geo = config_manager.get_geo_blocking()
    mode = geo.get('mode', 'blacklist')
    if mode == 'blacklist':
        countries = geo.get('blocked_countries', [])
    else:
        countries = geo.get('allowed_countries', [])
    return jsonify({
        'mode': mode,
        'countries': countries,
        'all_countries': geo.get('all_countries', [])
    })


@app.route('/api/geo/countries', methods=['POST'])
def api_set_geo_countries():
    """Set the list of countries for current mode."""
    data = request.get_json()
    if data is None or 'countries' not in data:
        return jsonify({'error': 'Missing countries field'}), 400

    countries = data['countries']
    if not isinstance(countries, list):
        return jsonify({'error': 'Countries must be a list'}), 400

    if config_manager.set_geo_countries(countries):
        return jsonify({'status': 'updated', 'countries': countries})
    else:
        return jsonify({'error': 'Failed to update countries'}), 400


@app.route('/api/geo/countries/add', methods=['POST'])
def api_add_geo_country():
    """Add a country to the geo filter."""
    data = request.get_json()
    if data is None or 'country' not in data:
        return jsonify({'error': 'Missing country field'}), 400

    country = data['country']
    if len(country) != 2:
        return jsonify({'error': 'Country code must be 2 characters (ISO 3166-1 alpha-2)'}), 400

    if config_manager.add_geo_country(country):
        return jsonify({'status': 'added', 'country': country.upper()})
    else:
        return jsonify({'error': 'Failed to add country'}), 400


@app.route('/api/geo/countries/remove', methods=['POST'])
def api_remove_geo_country():
    """Remove a country from the geo filter."""
    data = request.get_json()
    if data is None or 'country' not in data:
        return jsonify({'error': 'Missing country field'}), 400

    country = data['country']
    if config_manager.remove_geo_country(country):
        return jsonify({'status': 'removed', 'country': country.upper()})
    else:
        return jsonify({'error': 'Failed to remove country'}), 400


@app.route('/api/geo/countries/clear', methods=['POST'])
def api_clear_geo_countries():
    """Clear all countries from the geo filter."""
    if config_manager.clear_geo_countries():
        return jsonify({'status': 'cleared'})
    else:
        return jsonify({'error': 'Failed to clear countries'}), 400


# ==================== Signatures API ====================

@app.route('/api/signatures')
def api_get_signatures():
    """Get all signatures with their current state."""
    return jsonify(config_manager.get_signatures())


@app.route('/api/signatures/enabled', methods=['POST'])
def api_set_signatures_enabled():
    """Enable or disable signatures globally."""
    data = request.get_json()
    if data is None or 'enabled' not in data:
        return jsonify({'error': 'Missing enabled field'}), 400

    if config_manager.update_value("signatures", "enabled", data['enabled']):
        return jsonify({'status': 'updated', 'enabled': data['enabled']})
    else:
        return jsonify({'error': 'Failed to update signatures state'}), 400


@app.route('/api/signatures/category/<category>/enabled', methods=['POST'])
def api_set_signature_category_enabled(category):
    """Enable or disable an entire signature category."""
    data = request.get_json()
    if data is None or 'enabled' not in data:
        return jsonify({'error': 'Missing enabled field'}), 400

    if config_manager.set_signature_category_enabled(category, data['enabled']):
        return jsonify({'status': 'updated', 'category': category, 'enabled': data['enabled']})
    else:
        return jsonify({'error': f'Failed to update category {category}'}), 400


@app.route('/api/signatures/<int:sig_id>/enabled', methods=['POST'])
def api_set_signature_enabled(sig_id):
    """Enable or disable a specific signature by ID."""
    data = request.get_json()
    if data is None or 'enabled' not in data:
        return jsonify({'error': 'Missing enabled field'}), 400

    if config_manager.set_signature_enabled(sig_id, data['enabled']):
        return jsonify({'status': 'updated', 'signature_id': sig_id, 'enabled': data['enabled']})
    else:
        return jsonify({'error': f'Signature {sig_id} not found'}), 404


@app.route('/api/signatures/amplification/<int:port>/enabled', methods=['POST'])
def api_set_amplification_enabled(port):
    """Enable or disable an amplification signature by port."""
    data = request.get_json()
    if data is None or 'enabled' not in data:
        return jsonify({'error': 'Missing enabled field'}), 400

    if config_manager.set_amplification_signature_enabled(port, data['enabled']):
        return jsonify({'status': 'updated', 'port': port, 'enabled': data['enabled']})
    else:
        return jsonify({'error': f'Failed to update port {port}'}), 400


@app.route('/api/signatures/custom', methods=['GET'])
def api_get_custom_signatures():
    """Get custom amplification signatures."""
    return jsonify({
        'signatures': config_manager.get_custom_amplification_signatures()
    })


@app.route('/api/signatures/custom', methods=['POST'])
def api_add_custom_signature():
    """Add a custom amplification signature."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing data'}), 400

    port = data.get('port')
    name = data.get('name')

    if port is None or not name:
        return jsonify({'error': 'Missing port or name'}), 400

    amplification = data.get('amplification', 1)
    # Sanitize description to prevent log/command injection
    description = sanitize_description(data.get('description', ''))

    if config_manager.add_custom_amplification_signature(int(port), name, int(amplification), description):
        return jsonify({'status': 'added', 'port': port, 'name': name})
    else:
        return jsonify({'error': f'Port {port} already exists'}), 400


@app.route('/api/signatures/custom/<int:port>', methods=['DELETE'])
def api_delete_custom_signature(port):
    """Remove a custom amplification signature."""
    if config_manager.remove_custom_amplification_signature(port):
        return jsonify({'status': 'removed', 'port': port})
    else:
        return jsonify({'error': f'Port {port} not found'}), 404


# ==================== Protocol Management API ====================

# IP protocol number to name mapping
PROTOCOL_NAMES = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IP-IN-IP",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-II",
    12: "PUP",
    13: "ARGUS",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    20: "HMP",
    21: "PRM",
    22: "XNS-IDP",
    23: "TRUNK-1",
    24: "TRUNK-2",
    25: "LEAF-1",
    26: "LEAF-2",
    27: "RDP",
    28: "IRTP",
    29: "ISO-TP4",
    30: "NETBLT",
    31: "MFE-NSP",
    32: "MERIT-INP",
    33: "DCCP",
    34: "3PC",
    35: "IDPR",
    36: "XTP",
    37: "DDP",
    38: "IDPR-CMTP",
    39: "TP++",
    40: "IL",
    41: "IPV6",
    42: "SDRP",
    43: "IPV6-ROUTE",
    44: "IPV6-FRAG",
    45: "IDRP",
    46: "RSVP",
    47: "GRE",
    48: "DSR",
    49: "BNA",
    50: "ESP",
    51: "AH",
    52: "I-NLSP",
    53: "SWIPE",
    54: "NARP",
    55: "MOBILE",
    56: "TLSP",
    57: "SKIP",
    58: "IPV6-ICMP",
    59: "IPV6-NONXT",
    60: "IPV6-OPTS",
    61: "ANY-HOST",
    62: "CFTP",
    63: "ANY-LOCAL",
    64: "SAT-EXPAK",
    65: "KRYPTOLAN",
    66: "RVD",
    67: "IPPC",
    68: "ANY-DFS",
    69: "SAT-MON",
    70: "VISA",
    71: "IPCU",
    72: "CPNX",
    73: "CPHB",
    74: "WSN",
    75: "PVP",
    76: "BR-SAT-MON",
    77: "SUN-ND",
    78: "WB-MON",
    79: "WB-EXPAK",
    80: "ISO-IP",
    81: "VMTP",
    82: "SECURE-VMTP",
    83: "VINES",
    84: "TTP/IPTM",
    85: "NSFNET-IGP",
    86: "DGP",
    87: "TCF",
    88: "EIGRP",
    89: "OSPF",
    90: "SPRITE-RPC",
    91: "LARP",
    92: "MTP",
    93: "AX.25",
    94: "OS",
    95: "MICP",
    96: "SCC-SP",
    97: "ETHERIP",
    98: "ENCAP",
    99: "ANY-ENCRYPT",
    100: "GMTP",
    101: "IFMP",
    102: "PNNI",
    103: "PIM",
    104: "ARIS",
    105: "SCPS",
    106: "QNX",
    107: "A/N",
    108: "IPCOMP",
    109: "SNP",
    110: "COMPAQ-PEER",
    111: "IPX-IN-IP",
    112: "VRRP",
    113: "PGM",
    114: "ANY-0-HOP",
    115: "L2TP",
    116: "DDX",
    117: "IATP",
    118: "STP",
    119: "SRP",
    120: "UTI",
    121: "SMP",
    122: "SM",
    123: "PTP",
    124: "ISIS",
    125: "FIRE",
    126: "CRTP",
    127: "CRUDP",
    128: "SSCOPMCE",
    129: "IPLT",
    130: "SPS",
    131: "PIPE",
    132: "SCTP",
    133: "FC",
    134: "RSVP-E2E-IGNORE",
    135: "MOBILITY-HDR",
    136: "UDPLITE",
    137: "MPLS-IN-IP",
    138: "MANET",
    139: "HIP",
    140: "SHIM6",
    141: "WESP",
    142: "ROHC",
    143: "ETHERNET",
    144: "AGGFRAG",
    253: "EXPERIMENTAL-253",
    254: "EXPERIMENTAL-254",
    255: "RESERVED",
}


def get_protocol_name(proto_num: int) -> str:
    """Get protocol name from number (uppercase)."""
    return PROTOCOL_NAMES.get(proto_num, f"PROTO-{proto_num}")


@app.route('/api/protocols')
def api_get_protocols():
    """Get protocol filtering configuration."""
    config = config_manager.get_section('other_protocols')
    if config is None:
        config = {
            'enabled': True,
            'default_action': 'drop',
            'allowed_protocols': [],
            'rate_limit_pps': 1000,
            'log_unknown': True
        }

    # Add protocol names to allowed protocols
    allowed_with_names = []
    for proto_num in config.get('allowed_protocols', []):
        allowed_with_names.append({
            'number': proto_num,
            'name': get_protocol_name(proto_num)
        })

    return jsonify({
        'enabled': config.get('enabled', True),
        'default_action': config.get('default_action', 'drop'),
        'allowed_protocols': allowed_with_names,
        'rate_limit_pps': config.get('rate_limit_pps', 1000),
        'log_unknown': config.get('log_unknown', True),
        'all_protocols': [
            {'number': num, 'name': name}
            for num, name in sorted(PROTOCOL_NAMES.items())
            if num not in (1, 6, 17)  # Exclude TCP, UDP, ICMP (handled by main pipeline)
        ]
    })


@app.route('/api/protocols/enabled', methods=['POST'])
def api_set_protocols_enabled():
    """Enable or disable protocol filtering."""
    data = request.get_json()
    if data is None or 'enabled' not in data:
        return jsonify({'error': 'Missing enabled field'}), 400

    if config_manager.update_value('other_protocols', 'enabled', data['enabled']):
        return jsonify({'status': 'updated', 'enabled': data['enabled']})
    else:
        return jsonify({'error': 'Failed to update protocol filtering state'}), 400


@app.route('/api/protocols/action', methods=['POST'])
def api_set_protocols_action():
    """Set default action for unknown protocols."""
    data = request.get_json()
    if data is None or 'action' not in data:
        return jsonify({'error': 'Missing action field'}), 400

    action = data['action'].lower()
    if action not in ('drop', 'accept', 'rate_limit'):
        return jsonify({'error': 'Action must be "drop", "accept", or "rate_limit"'}), 400

    if config_manager.update_value('other_protocols', 'default_action', action):
        return jsonify({'status': 'updated', 'action': action})
    else:
        return jsonify({'error': 'Failed to update default action'}), 400


@app.route('/api/protocols/add', methods=['POST'])
def api_add_protocol():
    """Add a protocol to the allowed list."""
    data = request.get_json()
    if data is None:
        return jsonify({'error': 'Missing data'}), 400

    # Accept protocol number, name, or generic 'protocol' field
    proto_input = data.get('protocol')
    proto_num = data.get('number')
    proto_name = data.get('name', '').upper()

    # Handle generic 'protocol' field (can be number or name)
    if proto_input is not None and proto_num is None and not proto_name:
        if isinstance(proto_input, int) or (isinstance(proto_input, str) and proto_input.isdigit()):
            proto_num = int(proto_input)
        else:
            proto_name = str(proto_input).upper()

    if proto_num is None and proto_name:
        # Look up by name
        for num, name in PROTOCOL_NAMES.items():
            if name == proto_name:
                proto_num = num
                break
        if proto_num is None:
            return jsonify({'error': f'Unknown protocol name: {proto_name}'}), 400

    if proto_num is None:
        return jsonify({'error': 'Missing protocol number or name'}), 400

    proto_num = int(proto_num)
    if proto_num < 0 or proto_num > 255:
        return jsonify({'error': 'Protocol number must be 0-255'}), 400

    # Skip TCP, UDP, ICMP
    if proto_num in (1, 6, 17):
        return jsonify({'error': f'{get_protocol_name(proto_num)} is handled by main pipeline'}), 400

    config = config_manager.get_section('other_protocols') or {}
    allowed = config.get('allowed_protocols', [])

    if proto_num in allowed:
        return jsonify({'error': f'Protocol {proto_num} already in allowed list'}), 400

    allowed.append(proto_num)
    allowed.sort()

    if config_manager.update_value('other_protocols', 'allowed_protocols', allowed):
        return jsonify({
            'status': 'added',
            'protocol': {
                'number': proto_num,
                'name': get_protocol_name(proto_num)
            }
        })
    else:
        return jsonify({'error': 'Failed to add protocol'}), 400


@app.route('/api/protocols/remove', methods=['POST'])
def api_remove_protocol():
    """Remove a protocol from the allowed list."""
    data = request.get_json()
    if data is None:
        return jsonify({'error': 'Missing data'}), 400

    # Accept protocol number, name, or generic 'protocol' field
    proto_input = data.get('protocol')
    proto_num = data.get('number')
    proto_name = data.get('name', '').upper()

    # Handle generic 'protocol' field (can be number or name)
    if proto_input is not None and proto_num is None and not proto_name:
        if isinstance(proto_input, int) or (isinstance(proto_input, str) and str(proto_input).isdigit()):
            proto_num = int(proto_input)
        else:
            proto_name = str(proto_input).upper()

    if proto_num is None and proto_name:
        # Look up by name
        for num, name in PROTOCOL_NAMES.items():
            if name == proto_name:
                proto_num = num
                break

    if proto_num is None:
        return jsonify({'error': 'Missing protocol number or name'}), 400

    proto_num = int(proto_num)

    config = config_manager.get_section('other_protocols') or {}
    allowed = config.get('allowed_protocols', [])

    if proto_num not in allowed:
        return jsonify({'error': f'Protocol {proto_num} not in allowed list'}), 404

    allowed.remove(proto_num)

    if config_manager.update_value('other_protocols', 'allowed_protocols', allowed):
        return jsonify({
            'status': 'removed',
            'protocol': {
                'number': proto_num,
                'name': get_protocol_name(proto_num)
            }
        })
    else:
        return jsonify({'error': 'Failed to remove protocol'}), 400


@app.route('/api/protocols/clear', methods=['POST'])
def api_clear_protocols():
    """Clear all allowed protocols."""
    if config_manager.update_value('other_protocols', 'allowed_protocols', []):
        return jsonify({'status': 'cleared'})
    else:
        return jsonify({'error': 'Failed to clear protocols'}), 400


@app.route('/api/protocols/rate-limit', methods=['POST'])
def api_set_protocol_rate_limit():
    """Set rate limit for other protocols."""
    data = request.get_json()
    if data is None or 'pps' not in data:
        return jsonify({'error': 'Missing pps field'}), 400

    pps = int(data['pps'])
    if pps < 0 or pps > 10000000:
        return jsonify({'error': 'Rate limit must be 0-10000000 PPS'}), 400

    if config_manager.update_value('other_protocols', 'rate_limit_pps', pps):
        return jsonify({'status': 'updated', 'rate_limit_pps': pps})
    else:
        return jsonify({'error': 'Failed to update rate limit'}), 400


@app.route('/api/protocols/log', methods=['POST'])
def api_set_protocol_logging():
    """Enable or disable logging for unknown protocols."""
    data = request.get_json()
    if data is None or 'enabled' not in data:
        return jsonify({'error': 'Missing enabled field'}), 400

    if config_manager.update_value('other_protocols', 'log_unknown', data['enabled']):
        return jsonify({'status': 'updated', 'log_unknown': data['enabled']})
    else:
        return jsonify({'error': 'Failed to update logging state'}), 400


# ==================== Layer2 Configuration API ====================

@app.route('/api/layer2/config')
def api_get_layer2_config():
    """Get full Layer2 configuration."""
    return jsonify(layer2_config_manager.get_config())


@app.route('/api/layer2/config/info')
def api_layer2_config_info():
    """Get Layer2 configuration metadata."""
    return jsonify(layer2_config_manager.get_config_info())


@app.route('/api/layer2/config/schema')
def api_layer2_config_schema():
    """Get Layer2 configuration schema with field descriptions."""
    return jsonify(layer2_config_manager.get_config_schema())


@app.route('/api/layer2/config', methods=['PUT'])
def api_update_layer2_config():
    """Update Layer2 configuration values."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing data'}), 400

    if layer2_config_manager.update_config(data):
        return jsonify({'status': 'updated'})
    else:
        return jsonify({'error': 'Failed to update Layer2 configuration'}), 400


@app.route('/api/layer2/config/value/<key>', methods=['PUT'])
def api_update_layer2_value(key):
    """Update a single Layer2 configuration value."""
    data = request.get_json()
    if data is None or 'value' not in data:
        return jsonify({'error': 'Missing value'}), 400

    if layer2_config_manager.update_value(key, data['value']):
        return jsonify({'status': 'updated', 'key': key})
    else:
        return jsonify({'error': f'Failed to update {key}'}), 400


@app.route('/api/layer2/config/reset', methods=['POST'])
def api_reset_layer2_config():
    """Reset Layer2 configuration to defaults."""
    if layer2_config_manager.reset_to_defaults():
        return jsonify({'status': 'reset'})
    else:
        return jsonify({'error': 'Failed to reset Layer2 configuration'}), 500


@app.route('/api/layer2/config/reload', methods=['POST'])
def api_reload_layer2_config():
    """Reload Layer2 configuration from file."""
    if layer2_config_manager.load_config():
        return jsonify({'status': 'reloaded'})
    else:
        return jsonify({'error': 'Failed to reload Layer2 configuration'}), 500


# ==================== Adaptive Threshold API ====================

@app.route('/api/layer2/adaptive')
def api_get_adaptive_config():
    """Get adaptive threshold configuration."""
    config = layer2_config_manager.get_config()
    return jsonify({
        'enabled': config.get('adaptive_enabled', True),
        'min_threshold': config.get('adaptive_min_threshold', 4.0),
        'max_threshold': config.get('adaptive_max_threshold', 10.0),
        'step': config.get('adaptive_step', 0.25),
        'fp_threshold': config.get('adaptive_fp_threshold', 0.30),
        'tp_min': config.get('adaptive_tp_min', 0.50),
        'eval_interval_sec': config.get('adaptive_eval_interval_sec', 300),
        'min_samples': config.get('adaptive_min_samples', 10),
        'fp_duration_threshold_sec': config.get('fp_duration_threshold_sec', 10.0),
        'tp_duration_threshold_sec': config.get('tp_duration_threshold_sec', 30.0)
    })


@app.route('/api/layer2/adaptive', methods=['PUT'])
def api_update_adaptive_config():
    """Update adaptive threshold configuration."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing data'}), 400

    # Map API field names to config field names
    field_map = {
        'enabled': 'adaptive_enabled',
        'min_threshold': 'adaptive_min_threshold',
        'max_threshold': 'adaptive_max_threshold',
        'step': 'adaptive_step',
        'fp_threshold': 'adaptive_fp_threshold',
        'tp_min': 'adaptive_tp_min',
        'eval_interval_sec': 'adaptive_eval_interval_sec',
        'min_samples': 'adaptive_min_samples',
        'fp_duration_threshold_sec': 'fp_duration_threshold_sec',
        'tp_duration_threshold_sec': 'tp_duration_threshold_sec'
    }

    updates = {}
    for api_key, config_key in field_map.items():
        if api_key in data:
            updates[config_key] = data[api_key]

    if updates:
        if layer2_config_manager.update_config(updates):
            return jsonify({'status': 'updated', 'fields': list(updates.keys())})
        else:
            return jsonify({'error': 'Failed to update adaptive configuration'}), 400

    return jsonify({'error': 'No valid fields provided'}), 400


@app.route('/api/layer2/adaptive/enabled', methods=['POST'])
def api_set_adaptive_enabled():
    """Enable or disable adaptive threshold tuning."""
    data = request.get_json()
    if data is None or 'enabled' not in data:
        return jsonify({'error': 'Missing enabled field'}), 400

    if layer2_config_manager.update_value('adaptive_enabled', data['enabled']):
        return jsonify({'status': 'updated', 'enabled': data['enabled']})
    else:
        return jsonify({'error': 'Failed to update adaptive enabled state'}), 400


@app.route('/api/layer2/adaptive/thresholds', methods=['POST'])
def api_set_adaptive_thresholds():
    """Set min/max threshold bounds for adaptive tuning."""
    data = request.get_json()
    if data is None:
        return jsonify({'error': 'Missing data'}), 400

    updates = {}
    if 'min_threshold' in data:
        min_val = float(data['min_threshold'])
        if min_val < 3.0 or min_val > 8.0:
            return jsonify({'error': 'min_threshold must be between 3.0 and 8.0'}), 400
        updates['adaptive_min_threshold'] = min_val

    if 'max_threshold' in data:
        max_val = float(data['max_threshold'])
        if max_val < 6.0 or max_val > 15.0:
            return jsonify({'error': 'max_threshold must be between 6.0 and 15.0'}), 400
        updates['adaptive_max_threshold'] = max_val

    # Validate min < max
    config = layer2_config_manager.get_config()
    min_t = updates.get('adaptive_min_threshold', config.get('adaptive_min_threshold', 4.0))
    max_t = updates.get('adaptive_max_threshold', config.get('adaptive_max_threshold', 10.0))
    if min_t >= max_t:
        return jsonify({'error': 'min_threshold must be less than max_threshold'}), 400

    if updates:
        if layer2_config_manager.update_config(updates):
            return jsonify({'status': 'updated', 'min_threshold': min_t, 'max_threshold': max_t})
        else:
            return jsonify({'error': 'Failed to update thresholds'}), 400

    return jsonify({'error': 'No valid fields provided'}), 400


@app.route('/api/layer2/adaptive/classification', methods=['POST'])
def api_set_adaptive_classification():
    """Set FP/TP classification duration thresholds."""
    data = request.get_json()
    if data is None:
        return jsonify({'error': 'Missing data'}), 400

    updates = {}
    if 'fp_duration_sec' in data:
        fp_val = float(data['fp_duration_sec'])
        if fp_val < 1.0 or fp_val > 60.0:
            return jsonify({'error': 'fp_duration_sec must be between 1.0 and 60.0'}), 400
        updates['fp_duration_threshold_sec'] = fp_val

    if 'tp_duration_sec' in data:
        tp_val = float(data['tp_duration_sec'])
        if tp_val < 10.0 or tp_val > 300.0:
            return jsonify({'error': 'tp_duration_sec must be between 10.0 and 300.0'}), 400
        updates['tp_duration_threshold_sec'] = tp_val

    # Validate fp < tp
    config = layer2_config_manager.get_config()
    fp_t = updates.get('fp_duration_threshold_sec', config.get('fp_duration_threshold_sec', 10.0))
    tp_t = updates.get('tp_duration_threshold_sec', config.get('tp_duration_threshold_sec', 30.0))
    if fp_t >= tp_t:
        return jsonify({'error': 'fp_duration_sec must be less than tp_duration_sec'}), 400

    if updates:
        if layer2_config_manager.update_config(updates):
            return jsonify({'status': 'updated', 'fp_duration_sec': fp_t, 'tp_duration_sec': tp_t})
        else:
            return jsonify({'error': 'Failed to update classification thresholds'}), 400

    return jsonify({'error': 'No valid fields provided'}), 400


@app.route('/api/layer2/adaptive/tuning', methods=['POST'])
def api_set_adaptive_tuning():
    """Set adaptive tuning parameters (step, fp_threshold, tp_min, interval, samples)."""
    data = request.get_json()
    if data is None:
        return jsonify({'error': 'Missing data'}), 400

    updates = {}

    if 'step' in data:
        step = float(data['step'])
        if step < 0.1 or step > 1.0:
            return jsonify({'error': 'step must be between 0.1 and 1.0'}), 400
        updates['adaptive_step'] = step

    if 'fp_threshold' in data:
        fp_t = float(data['fp_threshold'])
        if fp_t < 0.1 or fp_t > 0.8:
            return jsonify({'error': 'fp_threshold must be between 0.1 and 0.8'}), 400
        updates['adaptive_fp_threshold'] = fp_t

    if 'tp_min' in data:
        tp_m = float(data['tp_min'])
        if tp_m < 0.2 or tp_m > 0.9:
            return jsonify({'error': 'tp_min must be between 0.2 and 0.9'}), 400
        updates['adaptive_tp_min'] = tp_m

    if 'eval_interval_sec' in data:
        interval = int(data['eval_interval_sec'])
        if interval < 60 or interval > 3600:
            return jsonify({'error': 'eval_interval_sec must be between 60 and 3600'}), 400
        updates['adaptive_eval_interval_sec'] = interval

    if 'min_samples' in data:
        samples = int(data['min_samples'])
        if samples < 5 or samples > 100:
            return jsonify({'error': 'min_samples must be between 5 and 100'}), 400
        updates['adaptive_min_samples'] = samples

    if updates:
        if layer2_config_manager.update_config(updates):
            return jsonify({'status': 'updated', 'fields': list(data.keys())})
        else:
            return jsonify({'error': 'Failed to update tuning parameters'}), 400

    return jsonify({'error': 'No valid fields provided'}), 400


if __name__ == '__main__':
    threading.Thread(target=receiver_thread, daemon=True).start()
    threading.Thread(target=traffic_receiver_thread, daemon=True).start()
    print("[Flask] http://localhost:5005")
    app.run(host='0.0.0.0', port=5005, debug=False, threaded=True)