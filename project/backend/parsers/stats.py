"""
Stats and system monitor packet parsers.
"""

import struct
from datetime import datetime
from .constants import (
    STATS_MAGIC, HEADER_FORMAT, HEADER_SIZE, PORT_ENTRY_FORMAT, PORT_ENTRY_SIZE,
    SYSMON_MAGIC, LCORE_STAT_FORMAT, LCORE_STAT_SIZE,
    MEMPOOL_STAT_FORMAT, MEMPOOL_STAT_SIZE,
    SYS_CPU_STAT_FORMAT, SYS_CPU_STAT_SIZE,
    MAX_PORTS, MAX_LCORE_STATS, MAX_MEMPOOL_STATS,
)


def parse_stats_packet(data):
    """
    Parse DPDK port statistics packet.

    Args:
        data: Raw bytes from stats socket

    Returns:
        dict with parsed stats or None on error
    """
    if len(data) < HEADER_SIZE:
        return None

    magic, version, ts, num_ports = struct.unpack_from(HEADER_FORMAT, data, 0)
    if magic != STATS_MAGIC:
        return None

    num_ports = min(num_ports, MAX_PORTS)
    ports = []
    offset = HEADER_SIZE

    for _ in range(num_ports):
        if offset + PORT_ENTRY_SIZE > len(data):
            break
        entry = struct.unpack_from(PORT_ENTRY_FORMAT, data, offset)
        ports.append({
            'port_id': entry[0],
            'rx_packets': entry[1],
            'tx_packets': entry[2],
            'rx_bytes': entry[3],
            'tx_bytes': entry[4],
            'rx_dropped': entry[5],
            'tx_dropped': entry[6],
            'rx_errors': entry[7],
            'tx_errors': entry[8],
            'link_status': entry[9],
        })
        offset += PORT_ENTRY_SIZE

    return {
        'version': version,
        'timestamp': ts,
        'timestamp_readable': datetime.fromtimestamp(ts / 1e9).isoformat() if ts else None,
        'ports': ports,
    }


def parse_sysmon_packet(data):
    """
    Parse system monitor packet containing lcore and mempool stats.

    Args:
        data: Raw bytes from stats socket

    Returns:
        dict with parsed system stats or None on error
    """
    if len(data) < 16:
        return None

    # Header: magic(I), version(I), timestamp(Q), num_lcores(H),
    #         num_mempools(H), num_sys_cpus(H), pad(H)
    header_format = '<IIQHHHHQQQQQddddddd'
    header_size = struct.calcsize(header_format)

    if len(data) < header_size:
        return None

    header = struct.unpack_from(header_format, data, 0)
    magic = header[0]
    if magic != SYSMON_MAGIC:
        return None

    version = header[1]
    timestamp = header[2]
    num_lcores = min(header[3], MAX_LCORE_STATS)
    num_mempools = min(header[4], MAX_MEMPOOL_STATS)
    num_sys_cpus = min(header[5], 256)

    # System-wide metrics
    sys_total_mem = header[7]
    sys_free_mem = header[8]
    sys_total_hugepages = header[9]
    sys_free_hugepages = header[10]
    uptime_sec = header[11]
    avg_lcore_util = header[12]
    total_rx_pps = header[13]
    total_tx_pps = header[14]
    total_rx_bps = header[15]
    total_tx_bps = header[16]
    total_drop_pps = header[17]
    cache_hit_rate = header[18]

    offset = header_size

    # Parse lcore stats
    lcores = []
    for _ in range(num_lcores):
        if offset + LCORE_STAT_SIZE > len(data):
            break
        entry = struct.unpack_from(LCORE_STAT_FORMAT, data, offset)
        lcores.append({
            'lcore_id': entry[0],
            'is_active': bool(entry[1]),
            'busy_cycles': entry[2],
            'idle_cycles': entry[3],
            'utilization_pct': entry[4],
        })
        offset += LCORE_STAT_SIZE

    # Parse mempool stats
    mempools = []
    for _ in range(num_mempools):
        if offset + MEMPOOL_STAT_SIZE > len(data):
            break
        entry = struct.unpack_from(MEMPOOL_STAT_FORMAT, data, offset)
        name = entry[0].decode('utf-8', errors='ignore').rstrip('\x00')
        mempools.append({
            'name': name,
            'size': entry[1],
            'avail_count': entry[2],
            'in_use_count': entry[3],
            'usage_pct': entry[4],
        })
        offset += MEMPOOL_STAT_SIZE

    # Parse system CPU stats
    sys_cpus = []
    for _ in range(num_sys_cpus):
        if offset + SYS_CPU_STAT_SIZE > len(data):
            break
        entry = struct.unpack_from(SYS_CPU_STAT_FORMAT, data, offset)
        sys_cpus.append({
            'cpu_id': entry[0],
            'usage_pct': entry[1],
            'user_pct': entry[2],
            'system_pct': entry[3],
            'idle_pct': entry[4],
            'iowait_pct': entry[5],
        })
        offset += SYS_CPU_STAT_SIZE

    return {
        'version': version,
        'timestamp': timestamp,
        'timestamp_readable': datetime.fromtimestamp(timestamp / 1e9).isoformat() if timestamp else None,
        'lcores': lcores,
        'mempools': mempools,
        'sys_cpus': sys_cpus,
        'system': {
            'total_memory_mb': sys_total_mem / (1024 * 1024) if sys_total_mem else 0,
            'free_memory_mb': sys_free_mem / (1024 * 1024) if sys_free_mem else 0,
            'total_hugepages': sys_total_hugepages,
            'free_hugepages': sys_free_hugepages,
            'uptime_sec': uptime_sec,
            'avg_lcore_util': avg_lcore_util,
            'total_rx_pps': total_rx_pps,
            'total_tx_pps': total_tx_pps,
            'total_rx_bps': total_rx_bps,
            'total_tx_bps': total_tx_bps,
            'total_drop_pps': total_drop_pps,
            'cache_hit_rate': cache_hit_rate,
        },
    }
