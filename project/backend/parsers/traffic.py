"""
Traffic packet parser.
"""

import struct
from datetime import datetime
from .constants import (
    TRAFFIC_MAGIC, TRAFFIC_HEADER_FORMAT, TRAFFIC_HEADER_SIZE,
    TRAFFIC_ENTRY_FORMAT, TRAFFIC_ENTRY_SIZE, MAX_TRAFFIC_SAMPLES,
    PROTO_NAMES,
)


def ip_int_to_str(ip_int):
    """Convert network byte order integer to IP string."""
    if ip_int == 0:
        return "0.0.0.0"
    # Network byte order (big endian)
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"


def parse_traffic_packet(data):
    """
    Parse traffic sample packet.

    Args:
        data: Raw bytes from traffic socket

    Returns:
        dict with parsed traffic samples or None on error
    """
    if len(data) < TRAFFIC_HEADER_SIZE:
        return None

    magic, version, ts, num_entries, _ = struct.unpack_from(
        TRAFFIC_HEADER_FORMAT, data, 0
    )
    if magic != TRAFFIC_MAGIC:
        return None

    num_entries = min(num_entries, MAX_TRAFFIC_SAMPLES)
    entries = []
    offset = TRAFFIC_HEADER_SIZE

    for _ in range(num_entries):
        if offset + TRAFFIC_ENTRY_SIZE > len(data):
            break

        entry = struct.unpack_from(TRAFFIC_ENTRY_FORMAT, data, offset)
        (
            pkt_ts, src_ip, dst_ip, src_port, dst_port,
            protocol, flags, pkt_len, port_id, direction, _
        ) = entry

        entries.append({
            'timestamp': pkt_ts,
            'src_ip': ip_int_to_str(src_ip),
            'dst_ip': ip_int_to_str(dst_ip),
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': PROTO_NAMES.get(protocol, f'Unknown({protocol})'),
            'protocol_num': protocol,
            'flags': flags,
            'flags_str': _format_tcp_flags(flags) if protocol == 6 else '',
            'packet_len': pkt_len,
            'port_id': port_id,
            'direction': 'IN' if direction == 0 else 'OUT',
        })
        offset += TRAFFIC_ENTRY_SIZE

    return {
        'version': version,
        'timestamp': ts,
        'timestamp_readable': datetime.fromtimestamp(ts / 1e9).isoformat() if ts else None,
        'entries': entries,
        'count': len(entries),
    }


def _format_tcp_flags(flags):
    """Format TCP flags byte as human-readable string."""
    flag_names = []
    if flags & 0x01:
        flag_names.append('FIN')
    if flags & 0x02:
        flag_names.append('SYN')
    if flags & 0x04:
        flag_names.append('RST')
    if flags & 0x08:
        flag_names.append('PSH')
    if flags & 0x10:
        flag_names.append('ACK')
    if flags & 0x20:
        flag_names.append('URG')
    if flags & 0x40:
        flag_names.append('ECE')
    if flags & 0x80:
        flag_names.append('CWR')
    return ','.join(flag_names) if flag_names else 'none'
