"""
Anomaly detection packet parsers.
"""

import struct
from datetime import datetime
from .constants import (
    ANOMALY_MAGIC, ANOMALY_PACKET_FORMAT, ANOMALY_PACKET_SIZE,
    ANOMALY_LEVEL_NAMES, PROTO_CAT_NAMES, ATTACK_TYPE_NAMES,
    PER_IP_ANOMALY_MAGIC, PER_IP_ANOMALY_HEADER_FORMAT, PER_IP_ANOMALY_HEADER_SIZE,
    PER_IP_ANOMALY_ENTRY_FORMAT, PER_IP_ANOMALY_ENTRY_SIZE, MAX_PER_IP_EXPORT,
    PER_IP_FEATURES_MAGIC, PER_IP_FEATURES_HEADER_FORMAT, PER_IP_FEATURES_HEADER_SIZE,
    PER_IP_FEATURES_ENTRY_FORMAT, PER_IP_FEATURES_ENTRY_SIZE,
)


def ntohl(ip_int):
    """Convert network byte order to host byte order (byte swap on little-endian)."""
    if not isinstance(ip_int, int) or ip_int < 0 or ip_int > 0xFFFFFFFF:
        return 0
    return ((ip_int & 0xFF) << 24) | ((ip_int & 0xFF00) << 8) | \
           ((ip_int & 0xFF0000) >> 8) | ((ip_int >> 24) & 0xFF)


def ip_int_to_str(ip_int):
    """Convert IP integer from DPDK (network byte order) to string.

    DPDK stores IPs in network byte order. After unpacking with little-endian,
    we need to swap bytes to get the correct host-order value, then format.
    """
    if ip_int == 0:
        return "0.0.0.0"
    # Convert from network order to host order
    host_order = ntohl(ip_int)
    return f"{(host_order >> 24) & 0xFF}.{(host_order >> 16) & 0xFF}.{(host_order >> 8) & 0xFF}.{host_order & 0xFF}"


def parse_anomaly_packet(data):
    """
    Parse global anomaly detection status packet.

    Args:
        data: Raw bytes from stats socket

    Returns:
        dict with parsed anomaly status or None on error
    """
    if len(data) < ANOMALY_PACKET_SIZE:
        return None

    fields = struct.unpack_from(ANOMALY_PACKET_FORMAT, data, 0)

    magic = fields[0]
    if magic != ANOMALY_MAGIC:
        return None

    length = fields[1]
    timestamp = fields[2]
    active = bool(fields[3])
    level = fields[4]
    tier_agreement = fields[5]
    max_z_score = fields[7]
    confidence = fields[8]
    primary_feature = fields[9]
    start_time = fields[11]
    duration = fields[12]
    cool_down = fields[13]
    baselines_frozen = bool(fields[14])
    tier1_ready = bool(fields[15])
    tier2_ready = bool(fields[16])
    tier3_ready = bool(fields[17])
    baseline_updates = fields[18]
    detection_cycles = fields[19]
    detection_count = fields[20]
    packets_per_sec = fields[21]
    bytes_per_sec = fields[22]
    syn_per_sec = fields[23]
    unique_src_ips = fields[24]
    unique_flows = fields[25]
    heavy_hitters = fields[26]
    rate_limit_pct = fields[27]

    feature_names = [
        'packets_per_sec', 'bytes_per_sec', 'syn_per_sec', 'ack_per_sec',
        'rst_per_sec', 'fin_per_sec', 'udp_per_sec', 'icmp_per_sec',
        'unique_src_ips', 'unique_flows', 'syn_ratio', 'udp_ratio',
        'bytes_per_packet', 'flows_per_sec', 'heavy_hitter_share',
    ]
    primary_feature_name = (
        feature_names[primary_feature]
        if 0 <= primary_feature < len(feature_names)
        else f'unknown_{primary_feature}'
    )

    return {
        'timestamp': timestamp,
        'timestamp_readable': datetime.fromtimestamp(timestamp / 1e9).isoformat() if timestamp else None,
        'active': active,
        'level': level,
        'level_name': ANOMALY_LEVEL_NAMES.get(level, 'UNKNOWN'),
        'tier_agreement': tier_agreement,
        'max_z_score': max_z_score,
        'confidence': confidence,
        'primary_feature': primary_feature_name,
        'start_time': start_time,
        'duration_sec': duration,
        'cool_down_remaining': cool_down,
        'baselines_frozen': baselines_frozen,
        'tier_status': {
            'immediate': tier1_ready,
            'hourly': tier2_ready,
            'weekly': tier3_ready,
        },
        'baseline_updates': baseline_updates,
        'detection_cycles': detection_cycles,
        'detection_count': detection_count,
        'traffic': {
            'packets_per_sec': packets_per_sec,
            'bytes_per_sec': bytes_per_sec,
            'syn_per_sec': syn_per_sec,
            'unique_src_ips': unique_src_ips,
            'unique_flows': unique_flows,
            'heavy_hitters': heavy_hitters,
        },
        'rate_limit_pct': rate_limit_pct,
    }


def parse_per_ip_anomaly_packet(data):
    """
    Parse per-protected-IP anomaly status packet.

    Args:
        data: Raw bytes from stats socket

    Returns:
        dict with per-IP anomaly status or None on error
    """
    if len(data) < PER_IP_ANOMALY_HEADER_SIZE:
        return None

    header = struct.unpack_from(PER_IP_ANOMALY_HEADER_FORMAT, data, 0)
    magic, length, version, active_count, _ = header

    if magic != PER_IP_ANOMALY_MAGIC:
        return None

    entries = []
    offset = PER_IP_ANOMALY_HEADER_SIZE
    count = min(active_count, MAX_PER_IP_EXPORT)

    for _ in range(count):
        if offset + PER_IP_ANOMALY_ENTRY_SIZE > len(data):
            break

        entry = struct.unpack_from(PER_IP_ANOMALY_ENTRY_FORMAT, data, offset)
        (
            dst_ip, active, anomaly_active, anomaly_level,
            anomaly_start_ns, last_update_ns, max_z_score,
            tier_agreement, anomalous_feature_count,
            anomaly_protocol, attack_type, anomaly_dst_port, _
        ) = entry

        if active:
            entries.append({
                'ip': ip_int_to_str(dst_ip),
                'ip_int': dst_ip,
                'anomaly_active': bool(anomaly_active),
                'level': anomaly_level,
                'level_name': ANOMALY_LEVEL_NAMES.get(anomaly_level, 'UNKNOWN'),
                'start_time_ns': anomaly_start_ns,
                'last_update_ns': last_update_ns,
                'max_z_score': max_z_score,
                'tier_agreement': tier_agreement,
                'anomalous_features': anomalous_feature_count,
                # Protocol-specific anomaly info
                'anomaly_protocol': anomaly_protocol,
                'anomaly_protocol_name': PROTO_CAT_NAMES.get(anomaly_protocol, 'UNKNOWN'),
                'attack_type': attack_type,
                'attack_type_name': ATTACK_TYPE_NAMES.get(attack_type, 'UNKNOWN'),
                'anomaly_dst_port': anomaly_dst_port,
            })

        offset += PER_IP_ANOMALY_ENTRY_SIZE

    return {
        'version': version,
        'active_count': len(entries),
        'entries': entries,
    }


def parse_per_ip_features_packet(data):
    """
    Parse per-protected-IP feature statistics packet.

    Args:
        data: Raw bytes from stats socket

    Returns:
        dict with per-IP features or None on error
    """
    if len(data) < PER_IP_FEATURES_HEADER_SIZE:
        return None

    header = struct.unpack_from(PER_IP_FEATURES_HEADER_FORMAT, data, 0)
    magic, length, version, active_count, _ = header

    if magic != PER_IP_FEATURES_MAGIC:
        return None

    entries = []
    offset = PER_IP_FEATURES_HEADER_SIZE
    count = min(active_count, MAX_PER_IP_EXPORT)

    for _ in range(count):
        if offset + PER_IP_FEATURES_ENTRY_SIZE > len(data):
            break

        entry = struct.unpack_from(PER_IP_FEATURES_ENTRY_FORMAT, data, offset)
        (
            dst_ip, active, timestamp_ns, window_duration_ns,
            packets_per_sec, bytes_per_sec, flows_per_sec,
            syn_per_sec, syn_ack_per_sec, ack_per_sec, rst_per_sec, fin_per_sec,
            tcp_packets, udp_packets, icmp_packets, other_packets,
            tcp_ratio, udp_ratio, icmp_ratio, _pad1,
            syn_ack_ratio, rst_syn_ratio, bytes_per_packet, _pad2,
            unique_src_ips, unique_dst_ports, unique_flows,
            src_ip_churn, expired_srcip_rate,
            max_flow_fraction, topk_flow_share, heavy_hitter_count,
            avg_packets_per_flow, flow_duration_avg_ms,
            active_flows, sample_count, total_packets, _pad3
        ) = entry

        if active:
            entries.append({
                'ip': ip_int_to_str(dst_ip),
                'ip_int': dst_ip,
                'timestamp_ns': timestamp_ns,
                'window_duration_ns': window_duration_ns,
                'volume': {
                    'packets_per_sec': packets_per_sec,
                    'bytes_per_sec': bytes_per_sec,
                    'flows_per_sec': flows_per_sec,
                },
                'tcp_flags': {
                    'syn_per_sec': syn_per_sec,
                    'syn_ack_per_sec': syn_ack_per_sec,
                    'ack_per_sec': ack_per_sec,
                    'rst_per_sec': rst_per_sec,
                    'fin_per_sec': fin_per_sec,
                },
                'protocol_mix': {
                    'tcp_packets': tcp_packets,
                    'udp_packets': udp_packets,
                    'icmp_packets': icmp_packets,
                    'other_packets': other_packets,
                    'tcp_ratio': tcp_ratio,
                    'udp_ratio': udp_ratio,
                    'icmp_ratio': icmp_ratio,
                    'other_ratio': max(0, 100 - tcp_ratio - udp_ratio - icmp_ratio),
                },
                'ratios': {
                    'syn_ack_ratio': syn_ack_ratio,
                    'rst_syn_ratio': rst_syn_ratio,
                    'bytes_per_packet': bytes_per_packet,
                },
                'cardinality': {
                    'unique_src_ips': unique_src_ips,
                    'unique_dst_ports': unique_dst_ports,
                    'unique_flows': unique_flows,
                },
                'churn': {
                    'src_ip_churn': src_ip_churn,
                    'expired_srcip_rate': expired_srcip_rate,
                },
                'concentration': {
                    'max_flow_fraction': max_flow_fraction,
                    'topk_flow_share': topk_flow_share,
                    'heavy_hitter_count': heavy_hitter_count,
                },
                'flow_behavior': {
                    'avg_packets_per_flow': avg_packets_per_flow,
                    'flow_duration_avg_ms': flow_duration_avg_ms,
                    'active_flows': active_flows,
                },
                'metadata': {
                    'sample_count': sample_count,
                    'total_packets': total_packets,
                },
            })

        offset += PER_IP_FEATURES_ENTRY_SIZE

    return {
        'version': version,
        'active_count': len(entries),
        'entries': entries,
    }
