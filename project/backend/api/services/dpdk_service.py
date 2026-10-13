"""
DPDK Socket Service

Handles real-time communication with DPDK datapath via TCP sockets.
Provides parsed data for stats, traffic, anomaly detection, and system monitoring.

This service replaces the Flask background threads and makes the data
available via async-compatible methods for FastAPI.
"""

import asyncio
import math
import struct
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from threading import Thread, Lock
from contextlib import contextmanager
import socket
import time

logger = logging.getLogger(__name__)

# Socket configuration
STATS_HOST = "127.0.0.1"
STATS_PORT = 9999
TRAFFIC_HOST = "127.0.0.1"
TRAFFIC_PORT = 9998
MAX_PORTS = 8
MAX_TRAFFIC_SAMPLES = 100
MAX_LCORE_STATS = 64
MAX_MEMPOOL_STATS = 8
MAX_PER_IP_EXPORT = 64

# Stats packet format
HEADER_FORMAT = '<IIQH'  # magic, length, timestamp, port_count (packed, no pad)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
PORT_ENTRY_FORMAT = '<H9Q'
PORT_ENTRY_SIZE = struct.calcsize(PORT_ENTRY_FORMAT)
MAGIC = 0x44504B53

# Drop reason indices (must match stats_socket.h DROP_REASON_COUNT)
DROP_REASON_COUNT = 13
DROP_REASON_NAMES = [
    'Validation Error',      # 0  DROP_REASON_VALIDATION
    'Blacklist',             # 1  DROP_REASON_BLACKLIST
    'Rate Limit',            # 2  DROP_REASON_RATE_LIMIT
    'SYN Flood',             # 3  DROP_REASON_SYN_FLOOD
    'Reputation',            # 4  DROP_REASON_REPUTATION
    'Policy',                # 5  DROP_REASON_POLICY
    'Proxy Error',           # 6  DROP_REASON_PROXY_ERROR
    'Geo Blocked',           # 7  DROP_REASON_GEO
    'Signature Match',       # 8  DROP_REASON_SIGNATURE
    'Other Protocol',        # 9  DROP_REASON_OTHER_PROTO
    'Spoofed TCP',           # 10 DROP_REASON_SPOOFED_TCP
    'Proto Blocked',         # 11 DROP_REASON_PROTO_BLOCKED
    'Proto Rate Limit',      # 12 DROP_REASON_PROTO_RATELIMIT
]
DROP_REASONS_FORMAT = f'<{DROP_REASON_COUNT}Q'  # 13 uint64 values
DROP_REASONS_SIZE = struct.calcsize(DROP_REASONS_FORMAT)
PACKET_SIZE = HEADER_SIZE + (MAX_PORTS * PORT_ENTRY_SIZE)  # 18 + 8*74 = 610 (matches C struct)

# System monitor packet format
SYSMON_MAGIC = 0x53595354  # "SYST"
LCORE_STAT_FORMAT = '<IBxxxQQd'
LCORE_STAT_SIZE = struct.calcsize(LCORE_STAT_FORMAT)
MEMPOOL_STAT_FORMAT = '<32sIIId'
MEMPOOL_STAT_SIZE = struct.calcsize(MEMPOOL_STAT_FORMAT)
SYS_CPU_STAT_FORMAT = '<Iddddd'
SYS_CPU_STAT_SIZE = struct.calcsize(SYS_CPU_STAT_FORMAT)

# Traffic packet format
TRAFFIC_HEADER_FORMAT = '<IIQHH'
TRAFFIC_HEADER_SIZE = struct.calcsize(TRAFFIC_HEADER_FORMAT)
TRAFFIC_ENTRY_FORMAT = '<QIIHHBBHHBB'
TRAFFIC_ENTRY_SIZE = struct.calcsize(TRAFFIC_ENTRY_FORMAT)
TRAFFIC_PACKET_SIZE = TRAFFIC_HEADER_SIZE + (MAX_TRAFFIC_SAMPLES * TRAFFIC_ENTRY_SIZE)
TRAFFIC_MAGIC = 0x5452464B

# Anomaly packet format
ANOMALY_MAGIC = 0x414E4F4D  # "ANOM"
ANOMALY_PACKET_FORMAT = '<IIQBBBBddiIQddBBBBIQQQQIIIII'
ANOMALY_PACKET_SIZE = struct.calcsize(ANOMALY_PACKET_FORMAT)

# Per-IP anomaly packet format
PER_IP_ANOMALY_MAGIC = 0x50455250  # "PERP"
PER_IP_ANOMALY_ENTRY_FORMAT = '<IIIIQQdIIBBHBBBBBBBBBBHBBBBBB2s'
PER_IP_ANOMALY_ENTRY_SIZE = struct.calcsize(PER_IP_ANOMALY_ENTRY_FORMAT)
PER_IP_ANOMALY_HEADER_FORMAT = '<IIQII'
PER_IP_ANOMALY_HEADER_SIZE = struct.calcsize(PER_IP_ANOMALY_HEADER_FORMAT)
PER_IP_ANOMALY_PACKET_SIZE = PER_IP_ANOMALY_HEADER_SIZE + (MAX_PER_IP_EXPORT * PER_IP_ANOMALY_ENTRY_SIZE)

# Per-IP features packet format
PER_IP_FEATURES_MAGIC = 0x50495046  # "PIPF"
# v2 format (116 bytes): includes src_ip_entropy + pad
PER_IP_FEATURES_ENTRY_FORMAT_V2 = '<IIQQQIIIIIIBBBBIIBBHHIQIHHIiHHBBBBBBBBH'
PER_IP_FEATURES_ENTRY_SIZE_V2 = struct.calcsize(PER_IP_FEATURES_ENTRY_FORMAT_V2)  # 116
# v1 format (114 bytes): original without src_ip_entropy
PER_IP_FEATURES_ENTRY_FORMAT_V1 = '<IIQQQIIIIIIBBBBIIBBHHIQIHHIiHHBBBBBBH'
PER_IP_FEATURES_ENTRY_SIZE_V1 = struct.calcsize(PER_IP_FEATURES_ENTRY_FORMAT_V1)  # 114
# Default to v2 (after rebuild); auto-detected at parse time
PER_IP_FEATURES_ENTRY_FORMAT = PER_IP_FEATURES_ENTRY_FORMAT_V2
PER_IP_FEATURES_ENTRY_SIZE = PER_IP_FEATURES_ENTRY_SIZE_V2
PER_IP_FEATURES_HEADER_FORMAT = '<IIQII'
PER_IP_FEATURES_HEADER_SIZE = struct.calcsize(PER_IP_FEATURES_HEADER_FORMAT)
PER_IP_FEATURES_PACKET_SIZE = PER_IP_FEATURES_HEADER_SIZE + (MAX_PER_IP_EXPORT * PER_IP_FEATURES_ENTRY_SIZE)

# Per-IP baseline packet format (all 5 EWMA tiers from C Layer 2)
PER_IP_BASELINE_MAGIC = 0x5049424C  # "PIBL"
L2_BASELINE_FEATURES = 39
L2_BASELINE_TIERS = 5  # 1s, 10s, 60s, hourly/ToD, weekly/DoW
_BL_DOUBLES = L2_BASELINE_TIERS * L2_BASELINE_FEATURES  # 125 doubles
_BL_ALL_DOUBLES = _BL_DOUBLES * 2  # means + variances = 250 doubles
PER_IP_BASELINE_ENTRY_FORMAT = f'<II{_BL_ALL_DOUBLES}d{L2_BASELINE_TIERS}B{L2_BASELINE_TIERS}I3x'  # dst_ip, active, means, variances, tier_ready, tier_samples, pad
PER_IP_BASELINE_ENTRY_SIZE = struct.calcsize(PER_IP_BASELINE_ENTRY_FORMAT)
PER_IP_BASELINE_HEADER_FORMAT = '<IIQII'
PER_IP_BASELINE_HEADER_SIZE = struct.calcsize(PER_IP_BASELINE_HEADER_FORMAT)
PER_IP_BASELINE_PACKET_SIZE = PER_IP_BASELINE_HEADER_SIZE + (MAX_PER_IP_EXPORT * PER_IP_BASELINE_ENTRY_SIZE)

PROTO_NAMES = {0: 'Unknown', 1: 'ICMP', 6: 'TCP', 17: 'UDP'}
ANOMALY_LEVEL_NAMES = {0: 'NONE', 1: 'LOW', 2: 'MEDIUM', 3: 'HIGH', 4: 'CRITICAL'}
LEARNING_PHASE_NAMES = {0: 'COLD', 1: 'WARMING', 2: 'MODERATE', 3: 'MATURE'}

PROTO_CAT_NAMES = {
    0: 'TCP', 1: 'UDP', 2: 'ICMP', 3: 'OTHER', 255: 'ALL',
}

ATTACK_TYPE_NAMES = {
    0: 'UNKNOWN', 1: 'SYN_FLOOD', 2: 'UDP_FLOOD', 3: 'ICMP_FLOOD',
    4: 'DNS_AMP', 5: 'NTP_AMP', 6: 'MEMCACHED_AMP', 7: 'HTTP_FLOOD',
    8: 'SLOWLORIS', 9: 'ACK_FLOOD', 10: 'RST_FLOOD', 11: 'FRAG_FLOOD',
    12: 'FIN_FLOOD',
}

# Feature names for Layer 2 anomaly detection (matches l2_feature_index enum in baselines.h)
FEATURE_NAMES = [
    'packets_per_sec', 'bytes_per_sec', 'flows_per_sec',
    'syn_per_sec', 'syn_ack_per_sec', 'ack_per_sec', 'rst_per_sec', 'fin_per_sec',
    'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'other_ratio',
    'syn_ack_ratio', 'rst_syn_ratio', 'bytes_per_packet',
    'unique_src_ips', 'unique_dst_ports', 'unique_flows',
    'new_srcip_rate',
    'max_flow_fraction', 'topk_flow_share', 'heavy_hitter_count',
    'avg_packets_per_flow', 'flow_duration_avg',
    'syn_tcp_ratio', 'synack_tcp_ratio', 'ack_tcp_ratio', 'rst_tcp_ratio', 'fin_tcp_ratio',
    'burst_factor',
    'udp_flow_ratio',
    'icmp_echo_ratio',
    'dst_port_density',
    'src_ip_entropy',
    'src_port_entropy',
    'small_pkt_ratio', 'fragment_ratio', 'ttl_mean',
    'tcp_completion_rate',
]

# Tier names for baseline export (index matches C L2_EXPORT_TIERS order)
BASELINE_TIER_NAMES = ['1s', '10s', '60s', 'hourly', 'weekly']

# L2 feature index -> dashboard feature key suffix (for baseline_{tier}_{key} naming)
BASELINE_FEATURE_KEYS = {
    0: 'packets_per_sec',
    1: 'bytes_per_sec',
    2: 'flows_per_sec',
    3: 'syn_per_sec',
    4: 'syn_ack_per_sec',
    5: 'ack_per_sec',
    6: 'rst_per_sec',
    7: 'fin_per_sec',
    8: 'tcp_ratio',
    9: 'udp_ratio',
    10: 'icmp_ratio',
    15: 'unique_src_ips',
    17: 'unique_flows',
    19: 'max_flow_fraction',
    20: 'topk_flow_share',
    21: 'heavy_hitter_count',
    22: 'avg_packets_per_flow',
    23: 'flow_duration_avg_ms',
}


def ip_int_to_str(ip_int: int) -> str:
    """Convert IP integer to string (host byte order)."""
    if not isinstance(ip_int, int) or ip_int < 0 or ip_int > 0xFFFFFFFF:
        return "0.0.0.0"
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"


def ntohl(ip_int: int) -> int:
    """Convert network byte order to host byte order."""
    if not isinstance(ip_int, int) or ip_int < 0 or ip_int > 0xFFFFFFFF:
        return 0
    return ((ip_int & 0xFF) << 24) | ((ip_int & 0xFF00) << 8) | \
           ((ip_int & 0xFF0000) >> 8) | ((ip_int >> 24) & 0xFF)


def ip_str_to_int(ip_str: str) -> Optional[int]:
    """Convert IP string to integer."""
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
        return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    except (ValueError, TypeError):
        return None


class DPDKService:
    """Service for communicating with DPDK datapath."""

    _instance: Optional['DPDKService'] = None
    _lock = Lock()

    def __new__(cls) -> 'DPDKService':
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        # Stats data
        self._stats_lock = Lock()
        self._current_stats: Dict[str, Any] = {'timestamp': 0, 'ports': {}, 'connected': False}
        self._stats_history: List[Dict] = []

        # Traffic data
        self._traffic_lock = Lock()
        self._traffic_data: List[Dict] = []
        self._traffic_connected = False

        # Anomaly data
        self._anomaly_lock = Lock()
        self._current_anomaly: Dict[str, Any] = self._default_anomaly()

        # System monitor data
        self._sysmon_lock = Lock()
        self._current_sysmon: Dict[str, Any] = self._default_sysmon()

        # Per-IP data
        self._per_ip_anomaly_lock = Lock()
        self._per_ip_anomaly_data: Dict[str, Dict] = {}

        self._per_ip_features_lock = Lock()
        self._per_ip_features_data: Dict[str, Dict] = {}

        # Per-IP baseline means (from C Layer 2 EWMA)
        self._per_ip_baseline_lock = Lock()
        self._per_ip_baseline_data: Dict[str, Dict] = {}

        # Background threads
        self._stats_thread: Optional[Thread] = None
        self._traffic_thread: Optional[Thread] = None
        self._running = False

    def _default_anomaly(self) -> Dict[str, Any]:
        return {
            'timestamp': 0, 'active': False, 'level': 0, 'level_name': 'NONE',
            'tier_agreement': 0, 'max_z_score': 0.0, 'confidence': 0.0,
            'primary_feature': -1, 'primary_feature_name': 'unknown',
            'duration_sec': 0.0, 'cool_down_remaining': 0.0, 'baselines_frozen': False,
            'tier1_ready': False, 'tier2_ready_count': 0, 'tier3_ready_count': 0,
            'baseline_updates': 0, 'detection_cycles': 0, 'detection_count': 0,
            'packets_per_sec': 0, 'bytes_per_sec': 0, 'syn_per_sec': 0,
            'unique_src_ips': 0, 'unique_flows': 0, 'heavy_hitters': 0,
            'rate_limit_pct': 100, 'current_threshold': 0.0,
            # Learning state defaults (overwritten by first stats packet)
            'learning_phase': 0, 'learning_phase_name': 'COLD',
            'tier1_progress': 0, 'tier2_progress': 0, 'tier3_progress': 0,
            'tier1_eta_sec': 0, 'tier2_eta_sec': 0, 'tier3_eta_sec': 0,
            'baseline_age_sec': 0, 'mitigation_active': False,
            'learning_action': 1, 'suppressed_count': 0, 'trust_multiplier': 2.0,
        }

    def _default_sysmon(self) -> Dict[str, Any]:
        return {
            'timestamp': 0,
            'dpdk': {
                'lcores': [], 'avg_lcore_utilization': 0, 'mempools': [],
                'hugepage_total_mb': 0, 'hugepage_used_mb': 0, 'hugepage_usage_pct': 0
            },
            'system': {
                'cpus': [], 'avg_cpu_usage': 0, 'mem_total_gb': 0,
                'mem_used_gb': 0, 'mem_available_gb': 0, 'mem_usage_pct': 0,
                'load_1min': 0, 'load_5min': 0, 'load_15min': 0
            }
        }

    def start(self):
        """Start background receiver threads."""
        if self._running:
            return
        self._running = True

        self._stats_thread = Thread(target=self._stats_receiver_thread, daemon=True)
        self._stats_thread.start()

        self._traffic_thread = Thread(target=self._traffic_receiver_thread, daemon=True)
        self._traffic_thread.start()

        logger.info("DPDK service started")

    def stop(self):
        """Stop background receiver threads."""
        self._running = False
        logger.info("DPDK service stopped")

    def _parse_stats_packet(self, data: bytes) -> Optional[Dict]:
        if len(data) < HEADER_SIZE:
            return None

        magic, length, timestamp_ms, port_count = struct.unpack_from(HEADER_FORMAT, data, 0)
        if magic != MAGIC:
            return None
        # Validate length field against actual data and cap port_count
        if length > 0 and length > len(data):
            logger.warning(f"Stats packet length field ({length}) exceeds data ({len(data)})")
            return None
        if port_count > MAX_PORTS:
            logger.warning(f"Stats packet port_count ({port_count}) exceeds MAX_PORTS ({MAX_PORTS})")
            port_count = MAX_PORTS

        stats = {
            'timestamp': timestamp_ms,
            'timestamp_str': datetime.fromtimestamp(timestamp_ms / 1000).strftime('%H:%M:%S'),
            'ports': {},
            'drops_by_reason': {},
        }

        offset = HEADER_SIZE
        for i in range(min(port_count, MAX_PORTS)):
            if offset + PORT_ENTRY_SIZE > len(data):
                break
            values = struct.unpack_from(PORT_ENTRY_FORMAT, data, offset)
            port_id = values[0]

            # Sanity check: port_id should be small (0-255 typically)
            # If it's huge, there's likely a protocol version mismatch
            if port_id > 255:
                logger.warning(f"Invalid port_id {port_id} detected - possible protocol mismatch. Rebuild C code with 'make rebuild'")
                # Use sequential index as fallback
                port_id = i

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

        # Parse drop reasons (after all ports, fixed position for MAX_PORTS)
        drop_reasons_offset = HEADER_SIZE + (MAX_PORTS * PORT_ENTRY_SIZE)
        if len(data) >= drop_reasons_offset + DROP_REASONS_SIZE:
            drop_values = struct.unpack_from(DROP_REASONS_FORMAT, data, drop_reasons_offset)
            for i, count in enumerate(drop_values):
                if count > 0 and i < len(DROP_REASON_NAMES):
                    stats['drops_by_reason'][DROP_REASON_NAMES[i]] = count

        return stats

    def _parse_traffic_packet(self, data: bytes) -> Optional[List[Dict]]:
        if len(data) < TRAFFIC_HEADER_SIZE:
            return None

        magic, length, timestamp_ms, entry_count, _pad = struct.unpack_from(
            TRAFFIC_HEADER_FORMAT, data, 0)
        if magic != TRAFFIC_MAGIC:
            return None

        entries = []
        offset = TRAFFIC_HEADER_SIZE
        for i in range(min(entry_count, MAX_TRAFFIC_SAMPLES)):
            if offset + TRAFFIC_ENTRY_SIZE > len(data):
                break
            values = struct.unpack_from(TRAFFIC_ENTRY_FORMAT, data, offset)

            src_ip = ntohl(values[1])
            dst_ip = ntohl(values[2])
            src_ip_str = ip_int_to_str(src_ip)
            dst_ip_str = ip_int_to_str(dst_ip)

            entry = {
                'timestamp': values[0],
                'timestamp_str': datetime.fromtimestamp(values[0] / 1000).strftime('%H:%M:%S.%f')[:-3],
                'src_ip': src_ip_str, 'dst_ip': dst_ip_str,
                'src_port': values[3], 'dst_port': values[4],
                'protocol': PROTO_NAMES.get(values[5], f'Proto-{values[5]}'),
                'protocol_num': values[5],
                'flags': values[6], 'length': values[7],
                'port_id': values[8],
                'direction': 'RX' if values[9] == 0 else 'TX'
            }
            entries.append(entry)
            offset += TRAFFIC_ENTRY_SIZE
        return entries

    def _parse_sysmon_packet(self, data: bytes) -> Optional[Dict]:
        SYSMON_HEADER_SIZE = struct.calcsize('<IIQHHd')
        if len(data) < SYSMON_HEADER_SIZE:
            return None

        offset = 0
        magic, length, timestamp_ms, nb_lcores, _pad1, avg_lcore_util = struct.unpack_from(
            '<IIQHHd', data, offset)
        offset += SYSMON_HEADER_SIZE

        if magic != SYSMON_MAGIC:
            return None

        sysmon = {
            'timestamp': timestamp_ms,
            'timestamp_str': datetime.fromtimestamp(timestamp_ms / 1000).strftime('%H:%M:%S'),
            'dpdk': {
                'lcores': [], 'avg_lcore_utilization': round(avg_lcore_util, 1),
                'mempools': [], 'hugepage_total_mb': 0,
                'hugepage_used_mb': 0, 'hugepage_usage_pct': 0
            },
            'system': {
                'cpus': [], 'avg_cpu_usage': 0, 'mem_total_gb': 0,
                'mem_used_gb': 0, 'mem_available_gb': 0, 'mem_usage_pct': 0,
                'load_1min': 0, 'load_5min': 0, 'load_15min': 0
            }
        }

        # Parse lcore stats
        for i in range(min(nb_lcores, MAX_LCORE_STATS)):
            if offset + LCORE_STAT_SIZE > len(data):
                break
            lcore_id, is_active, busy_cycles, idle_cycles, util_pct = struct.unpack_from(
                LCORE_STAT_FORMAT, data, offset)
            offset += LCORE_STAT_SIZE
            sysmon['dpdk']['lcores'].append({
                'lcore_id': lcore_id, 'is_active': is_active != 0,
                'busy_cycles': busy_cycles, 'idle_cycles': idle_cycles,
                'utilization_pct': round(util_pct, 1)
            })

        offset = SYSMON_HEADER_SIZE + (MAX_LCORE_STATS * LCORE_STAT_SIZE)

        # Parse mempool stats
        if offset + 4 > len(data):
            return sysmon
        nb_mempools, _pad2 = struct.unpack_from('<HH', data, offset)
        offset += 4

        for i in range(min(nb_mempools, MAX_MEMPOOL_STATS)):
            if offset + MEMPOOL_STAT_SIZE > len(data):
                break
            name_bytes, size, avail, in_use, usage_pct = struct.unpack_from(
                MEMPOOL_STAT_FORMAT, data, offset)
            offset += MEMPOOL_STAT_SIZE
            name = name_bytes.decode('utf-8', errors='ignore').rstrip('\x00')
            sysmon['dpdk']['mempools'].append({
                'name': name, 'size': size, 'avail_count': avail,
                'in_use_count': in_use, 'usage_pct': round(usage_pct, 1)
            })

        offset = SYSMON_HEADER_SIZE + (MAX_LCORE_STATS * LCORE_STAT_SIZE) + 4 + \
                 (MAX_MEMPOOL_STATS * MEMPOOL_STAT_SIZE)

        # Parse hugepage stats
        if offset + 24 > len(data):
            return sysmon
        hp_total, hp_used, hp_usage_pct = struct.unpack_from('<QQd', data, offset)
        offset += 24
        sysmon['dpdk']['hugepage_total_mb'] = round(hp_total / (1024 * 1024), 1)
        sysmon['dpdk']['hugepage_used_mb'] = round(hp_used / (1024 * 1024), 1)
        sysmon['dpdk']['hugepage_usage_pct'] = round(hp_usage_pct, 1)

        # Parse system CPU stats
        if offset + 12 > len(data):
            return sysmon
        nb_cpus, _pad3, avg_cpu_usage = struct.unpack_from('<HHd', data, offset)
        offset += 12
        sysmon['system']['avg_cpu_usage'] = round(avg_cpu_usage, 1)

        for i in range(min(nb_cpus, MAX_LCORE_STATS)):
            if offset + SYS_CPU_STAT_SIZE > len(data):
                break
            cpu_id, usage_pct, user_pct, system_pct, idle_pct, iowait_pct = struct.unpack_from(
                SYS_CPU_STAT_FORMAT, data, offset)
            offset += SYS_CPU_STAT_SIZE
            sysmon['system']['cpus'].append({
                'cpu_id': cpu_id, 'usage_pct': round(usage_pct, 1),
                'user_pct': round(user_pct, 1), 'system_pct': round(system_pct, 1),
                'idle_pct': round(idle_pct, 1), 'iowait_pct': round(iowait_pct, 1)
            })

        offset = (SYSMON_HEADER_SIZE + (MAX_LCORE_STATS * LCORE_STAT_SIZE) + 4 +
                  (MAX_MEMPOOL_STATS * MEMPOOL_STAT_SIZE) + 24 + 12 +
                  (MAX_LCORE_STATS * SYS_CPU_STAT_SIZE))

        # Parse system memory stats
        if offset + 40 > len(data):
            return sysmon
        mem_total, mem_free, mem_avail, mem_used, mem_usage_pct = struct.unpack_from(
            '<QQQQd', data, offset)
        offset += 40
        sysmon['system']['mem_total_gb'] = round(mem_total / (1024 * 1024 * 1024), 2)
        sysmon['system']['mem_free_gb'] = round(mem_free / (1024 * 1024 * 1024), 2)
        sysmon['system']['mem_available_gb'] = round(mem_avail / (1024 * 1024 * 1024), 2)
        sysmon['system']['mem_used_gb'] = round(mem_used / (1024 * 1024 * 1024), 2)
        sysmon['system']['mem_usage_pct'] = round(mem_usage_pct, 1)

        # Parse load average
        if offset + 24 > len(data):
            return sysmon
        load_1, load_5, load_15 = struct.unpack_from('<ddd', data, offset)
        sysmon['system']['load_1min'] = round(load_1, 2)
        sysmon['system']['load_5min'] = round(load_5, 2)
        sysmon['system']['load_15min'] = round(load_15, 2)

        return sysmon

    def _parse_anomaly_packet(self, data: bytes) -> Optional[Dict]:
        if len(data) < ANOMALY_PACKET_SIZE:
            return None

        try:
            values = struct.unpack(ANOMALY_PACKET_FORMAT, data[:ANOMALY_PACKET_SIZE])
        except struct.error:
            return None

        if values[0] != ANOMALY_MAGIC:
            return None

        primary_feature = values[9]
        primary_feature_name = 'unknown'
        if 0 <= primary_feature < len(FEATURE_NAMES):
            primary_feature_name = FEATURE_NAMES[primary_feature]

        return {
            'timestamp': values[2],
            'timestamp_str': datetime.fromtimestamp(values[2] / 1000).strftime('%H:%M:%S'),
            'active': values[3] != 0, 'level': values[4],
            'level_name': ANOMALY_LEVEL_NAMES.get(values[4], 'UNKNOWN'),
            'tier_agreement': values[5], 'max_z_score': round(values[7], 2),
            'confidence': round(values[8] * 100, 1),
            'primary_feature': primary_feature, 'primary_feature_name': primary_feature_name,
            'duration_sec': round(values[12], 1), 'cool_down_remaining': round(values[13], 1),
            'baselines_frozen': values[14] != 0, 'tier1_ready': values[15] != 0,
            'tier2_ready_count': values[16], 'tier3_ready_count': values[17],
            'baseline_updates': values[18], 'detection_cycles': values[19],
            'detection_count': values[20], 'packets_per_sec': values[21],
            'bytes_per_sec': values[22], 'syn_per_sec': values[23],
            'unique_src_ips': values[24], 'unique_flows': values[25],
            'heavy_hitters': values[26], 'rate_limit_pct': values[27],
            # Compute learning progress from available baseline summary fields
            'current_threshold': 0.0,
            'learning_phase': 2 if (values[15] != 0 and values[16] >= 24 and values[17] >= 168) else (1 if values[18] > 0 else 0),
            'learning_phase_name': 'MATURE' if (values[15] != 0 and values[16] >= 24 and values[17] >= 168) else ('LEARNING' if values[18] > 0 else 'COLD'),
            'tier1_progress': 100 if values[15] != 0 else min(99, int(values[18] / max(1, 10) * 100)),
            'tier2_progress': int(values[16] / 24 * 100),
            'tier3_progress': int(values[17] / 168 * 100),
            'tier1_eta_sec': 0, 'tier2_eta_sec': 0, 'tier3_eta_sec': 0,
            'baseline_age_sec': 0,
            'mitigation_active': True,
            'learning_action': 0,
            'suppressed_count': 0,
            'trust_multiplier': 1.0,
            'sensitivity_preset': 0,
            'cusum_active': False, 'jsd_active': False, 'fast_active': False,
            'fp_rate': 0.0, 'tp_rate': 0.0, 'adaptive_adjustments': 0,
        }

    def _parse_per_ip_anomaly_packet(self, data: bytes) -> Optional[Dict[str, Dict]]:
        if len(data) < PER_IP_ANOMALY_PACKET_SIZE:
            return None

        try:
            header = struct.unpack_from(PER_IP_ANOMALY_HEADER_FORMAT, data, 0)
        except struct.error:
            return None

        if header[0] != PER_IP_ANOMALY_MAGIC:
            return None

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

            if active:
                dst_ip_host = ntohl(dst_ip)
                ip_str = ip_int_to_str(dst_ip_host)
                entries[ip_str] = {
                    'active': True, 'dst_ip_int': dst_ip_host,
                    'anomaly_active': entry[2] != 0, 'level': entry[3],
                    'start_time_ns': entry[4], 'last_update_ns': entry[5],
                    'max_z_score': entry[6], 'tier_agreement': entry[7],
                    'anomalous_feature_count': entry[8],
                    'anomaly_protocol': entry[9],
                    'anomaly_protocol_name': PROTO_CAT_NAMES.get(entry[9], 'UNKNOWN'),
                    'attack_type': entry[10],
                    'attack_type_name': ATTACK_TYPE_NAMES.get(entry[10], 'UNKNOWN'),
                    'anomaly_dst_port': entry[11],
                    'flash_crowd_score': entry[12],
                    'syn_completion_pct': entry[13],
                    'response_ratio_pct': entry[14],
                    'spoofed_mode': bool(entry[15]),
                    'randomness_pct': entry[16],
                    'rate_limit_pct': entry[17],
                    'detection_method': entry[18],
                    'sensitivity_preset': entry[19],
                    'learning_phase': entry[20],
                    'tier1_progress': entry[21],
                    'cool_down_remaining_sec': entry[22],
                    'peak_z_feature': entry[23],
                    'cusum_triggered': bool(entry[24]),
                    'jsd_triggered': bool(entry[25]),
                    'fast_triggered': bool(entry[26]),
                    'confidence': entry[27],
                    'severity': entry[28],
                }
            offset += PER_IP_ANOMALY_ENTRY_SIZE

        return entries

    def _parse_per_ip_features_packet(self, data: bytes) -> Optional[Dict[str, Dict]]:
        if len(data) < PER_IP_FEATURES_PACKET_SIZE:
            return None

        try:
            header = struct.unpack_from(PER_IP_FEATURES_HEADER_FORMAT, data, 0)
        except struct.error:
            return None

        if header[0] != PER_IP_FEATURES_MAGIC:
            return None

        active_count = header[3]
        entries = {}
        offset = PER_IP_FEATURES_HEADER_SIZE

        # Auto-detect entry size from packet: v2=116 bytes (with src_ip_entropy), v1=114 bytes
        payload_size = len(data) - PER_IP_FEATURES_HEADER_SIZE
        if active_count > 0:
            detected_entry_size = payload_size // active_count
        else:
            detected_entry_size = PER_IP_FEATURES_ENTRY_SIZE_V2

        if detected_entry_size >= PER_IP_FEATURES_ENTRY_SIZE_V2:
            entry_fmt = PER_IP_FEATURES_ENTRY_FORMAT_V2
            entry_size = PER_IP_FEATURES_ENTRY_SIZE_V2
            has_src_ip_entropy = True
        else:
            entry_fmt = PER_IP_FEATURES_ENTRY_FORMAT_V1
            entry_size = PER_IP_FEATURES_ENTRY_SIZE_V1
            has_src_ip_entropy = False

        for i in range(min(active_count, MAX_PER_IP_EXPORT)):
            if offset + entry_size > len(data):
                break
            try:
                entry = struct.unpack_from(entry_fmt, data, offset)
            except struct.error:
                break

            dst_ip_int = entry[0]
            active = entry[1]

            if active:
                dst_ip_host = ntohl(dst_ip_int)
                ip_str = ip_int_to_str(dst_ip_host)

                # Sanity check
                ratio_sum = entry[11] + entry[12] + entry[13]
                if ratio_sum > 100 or entry[3] > 1e12:
                    offset += entry_size
                    continue

                unique_src_ips = entry[15]
                result = {
                    'active': True, 'dst_ip_int': dst_ip_host,
                    'packets_per_sec': entry[3], 'bytes_per_sec': entry[4],
                    'flows_per_sec': entry[5], 'syn_per_sec': entry[6],
                    'syn_ack_per_sec': entry[7], 'ack_per_sec': entry[8],
                    'rst_per_sec': entry[9], 'fin_per_sec': entry[10],
                    'tcp_ratio': entry[11], 'udp_ratio': entry[12],
                    'icmp_ratio': entry[13],
                    'other_ratio': max(0, 100 - entry[11] - entry[12] - entry[13]),
                    'unique_src_ips': unique_src_ips, 'unique_flows': entry[16],
                    'max_flow_fraction': entry[17], 'topk_flow_share': entry[18],
                    'heavy_hitter_count': entry[19], 'avg_packets_per_flow': entry[20],
                    'flow_duration_avg_ms': entry[21], 'total_packets': entry[22],
                    'active_flows': entry[23],
                    'rst_syn_ratio': entry[24] / 100.0,
                    'unique_dst_ports': entry[26],
                    'new_srcip_rate': entry[27],
                    'burst_factor': entry[28],
                    'udp_flow_ratio': entry[29],
                    'icmp_echo_ratio': entry[30],
                    'small_pkt_ratio': entry[31],
                    'fragment_ratio': entry[32],
                    'ttl_mean': entry[33],
                    'tcp_completion_rate': entry[34],
                    'src_port_entropy': entry[35] / 255.0 * 16.0,
                }
                if has_src_ip_entropy:
                    result['src_ip_entropy'] = entry[36] / 255.0 * 8.0
                    # entry[37] is _pad3
                    result['dst_port_density'] = entry[38]
                else:
                    result['src_ip_entropy'] = math.log2(max(1, unique_src_ips))
                    result['dst_port_density'] = entry[36]

                entries[ip_str] = result
            offset += entry_size

        return entries

    def _parse_per_ip_baseline_packet(self, data: bytes) -> Optional[Dict[str, Dict]]:
        if len(data) < PER_IP_BASELINE_PACKET_SIZE:
            return None

        try:
            header = struct.unpack_from(PER_IP_BASELINE_HEADER_FORMAT, data, 0)
        except struct.error:
            return None

        if header[0] != PER_IP_BASELINE_MAGIC:
            return None

        # Validate packet length field matches expected multi-tier size.
        # Rejects old single-tier binaries that send smaller packets.
        pkt_length = header[1]
        if pkt_length != PER_IP_BASELINE_PACKET_SIZE:
            logger.warning(
                "Baseline packet length mismatch: got %d, expected %d. "
                "Restart DPDK binary to pick up multi-tier baseline export.",
                pkt_length, PER_IP_BASELINE_PACKET_SIZE)
            return None

        active_count = header[3]
        entries = {}
        offset = PER_IP_BASELINE_HEADER_SIZE

        for i in range(min(active_count, MAX_PER_IP_EXPORT)):
            if offset + PER_IP_BASELINE_ENTRY_SIZE > len(data):
                break
            try:
                entry = struct.unpack_from(PER_IP_BASELINE_ENTRY_FORMAT, data, offset)
            except struct.error:
                break

            dst_ip_int = entry[0]
            active = entry[1]

            if active:
                dst_ip_host = ntohl(dst_ip_int)
                ip_str = ip_int_to_str(dst_ip_host)

                # Extract baseline means+variances for all 5 tiers x dashboard-relevant features
                # Memory layout: entry[2..196] = means, entry[197..391] = variances
                # Each tier has L2_BASELINE_FEATURES (39) contiguous doubles
                var_base_offset = 2 + _BL_DOUBLES  # where variances start
                meta_offset = var_base_offset + _BL_DOUBLES  # where tier_ready starts
                ready_end = meta_offset + L2_BASELINE_TIERS  # where tier_samples starts

                bl: Dict[str, float] = {}
                for tier_idx, tier_name in enumerate(BASELINE_TIER_NAMES):
                    mean_base = 2 + tier_idx * L2_BASELINE_FEATURES
                    var_base = var_base_offset + tier_idx * L2_BASELINE_FEATURES
                    for feat_idx, feat_key in BASELINE_FEATURE_KEYS.items():
                        bl[f'bl_{tier_name}_{feat_key}'] = entry[mean_base + feat_idx]
                        variance = entry[var_base + feat_idx]
                        bl[f'bl_{tier_name}_{feat_key}_stddev'] = variance ** 0.5 if variance > 0 else 0.0
                    bl[f'bl_{tier_name}_ready'] = bool(entry[meta_offset + tier_idx])
                    bl[f'bl_{tier_name}_samples'] = entry[ready_end + tier_idx]

                entries[ip_str] = bl

            offset += PER_IP_BASELINE_ENTRY_SIZE

        return entries

    def _stats_receiver_thread(self):
        """Background thread for receiving stats/sysmon/anomaly data."""
        SYSMON_PACKET_SIZE = (28 + (MAX_LCORE_STATS * LCORE_STAT_SIZE) + 4 +
                              (MAX_MEMPOOL_STATS * MEMPOOL_STAT_SIZE) + 24 + 12 +
                              (MAX_LCORE_STATS * SYS_CPU_STAT_SIZE) + 40 + 24)

        while self._running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((STATS_HOST, STATS_PORT))
                logger.info("Connected to DPDK stats socket")

                with self._stats_lock:
                    self._current_stats['connected'] = True

                buffer = b''
                while self._running:
                    try:
                        data = sock.recv(32768)
                        if not data:
                            break
                        buffer += data

                        while len(buffer) >= 4:
                            magic = struct.unpack_from('<I', buffer, 0)[0]

                            if magic == MAGIC:
                                if len(buffer) < PACKET_SIZE:
                                    break
                                stats = self._parse_stats_packet(buffer[:PACKET_SIZE])
                                buffer = buffer[PACKET_SIZE:]
                                if stats:
                                    with self._stats_lock:
                                        self._current_stats = stats
                                        self._current_stats['connected'] = True
                                        self._stats_history.append(stats)
                                        # Keep up to 1 hour of history at 1Hz (3600 samples)
                                        if len(self._stats_history) > 3600:
                                            self._stats_history = self._stats_history[-3600:]

                            elif magic == SYSMON_MAGIC:
                                if len(buffer) < SYSMON_PACKET_SIZE:
                                    break
                                sysmon = self._parse_sysmon_packet(buffer[:SYSMON_PACKET_SIZE])
                                buffer = buffer[SYSMON_PACKET_SIZE:]
                                if sysmon:
                                    with self._sysmon_lock:
                                        self._current_sysmon = sysmon

                            elif magic == ANOMALY_MAGIC:
                                if len(buffer) < ANOMALY_PACKET_SIZE:
                                    break
                                anomaly = self._parse_anomaly_packet(buffer[:ANOMALY_PACKET_SIZE])
                                buffer = buffer[ANOMALY_PACKET_SIZE:]
                                if anomaly:
                                    with self._anomaly_lock:
                                        self._current_anomaly = anomaly

                            elif magic == PER_IP_ANOMALY_MAGIC:
                                if len(buffer) < PER_IP_ANOMALY_PACKET_SIZE:
                                    break
                                per_ip = self._parse_per_ip_anomaly_packet(
                                    buffer[:PER_IP_ANOMALY_PACKET_SIZE])
                                buffer = buffer[PER_IP_ANOMALY_PACKET_SIZE:]
                                if per_ip:
                                    with self._per_ip_anomaly_lock:
                                        self._per_ip_anomaly_data.update(per_ip)

                            elif magic == PER_IP_FEATURES_MAGIC:
                                if len(buffer) < PER_IP_FEATURES_PACKET_SIZE:
                                    break
                                per_ip_feat = self._parse_per_ip_features_packet(
                                    buffer[:PER_IP_FEATURES_PACKET_SIZE])
                                buffer = buffer[PER_IP_FEATURES_PACKET_SIZE:]
                                if per_ip_feat:
                                    with self._per_ip_features_lock:
                                        self._per_ip_features_data.update(per_ip_feat)

                            elif magic == PER_IP_BASELINE_MAGIC:
                                # Read packet length from header to handle version mismatches
                                if len(buffer) < 8:  # Need at least magic + length
                                    break
                                pkt_len = struct.unpack_from('<I', buffer, 4)[0]
                                if pkt_len < 24 or pkt_len > 200000:
                                    buffer = buffer[1:]  # Bad length, skip byte
                                    continue
                                if len(buffer) < pkt_len:
                                    break  # Wait for full packet
                                per_ip_bl = self._parse_per_ip_baseline_packet(
                                    buffer[:pkt_len])
                                buffer = buffer[pkt_len:]
                                if per_ip_bl:
                                    with self._per_ip_baseline_lock:
                                        self._per_ip_baseline_data.update(per_ip_bl)

                            else:
                                buffer = buffer[1:]

                    except socket.timeout:
                        continue

            except Exception as e:
                logger.warning(f"Stats socket disconnected: {e}")
                with self._stats_lock:
                    self._current_stats['connected'] = False
                time.sleep(2)
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

    def _traffic_receiver_thread(self):
        """Background thread for receiving traffic samples."""
        while self._running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((TRAFFIC_HOST, TRAFFIC_PORT))
                logger.info("Connected to DPDK traffic socket")

                with self._traffic_lock:
                    self._traffic_connected = True

                buffer = b''
                while self._running:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            break
                        buffer += data

                        while len(buffer) >= TRAFFIC_PACKET_SIZE:
                            entries = self._parse_traffic_packet(buffer[:TRAFFIC_PACKET_SIZE])
                            buffer = buffer[TRAFFIC_PACKET_SIZE:]

                            if entries:
                                with self._traffic_lock:
                                    self._traffic_data.extend(entries)
                                    if len(self._traffic_data) > 200:
                                        self._traffic_data = self._traffic_data[-200:]

                    except socket.timeout:
                        continue

            except Exception as e:
                logger.warning(f"Traffic socket disconnected: {e}")
                with self._traffic_lock:
                    self._traffic_connected = False
                time.sleep(2)
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

    # Public API methods
    def get_stats(self) -> Dict[str, Any]:
        with self._stats_lock:
            return dict(self._current_stats)

    def get_stats_history(self, limit: int = 60) -> List[Dict]:
        with self._stats_lock:
            return list(self._stats_history[-limit:])

    def get_traffic(self, limit: int = 100) -> Dict[str, Any]:
        with self._traffic_lock:
            return {
                'connected': self._traffic_connected,
                'entries': list(self._traffic_data[-limit:])
            }

    def clear_traffic(self):
        with self._traffic_lock:
            self._traffic_data.clear()

    def clear_per_ip_data(self, ip_address: Optional[str] = None):
        """Clear per-IP anomaly, features, and baseline data.

        Args:
            ip_address: If provided, clear only this IP. Otherwise clear all.
        """
        with self._per_ip_anomaly_lock:
            if ip_address:
                self._per_ip_anomaly_data.pop(ip_address, None)
            else:
                self._per_ip_anomaly_data.clear()

        with self._per_ip_features_lock:
            if ip_address:
                self._per_ip_features_data.pop(ip_address, None)
            else:
                self._per_ip_features_data.clear()

        with self._per_ip_baseline_lock:
            if ip_address:
                self._per_ip_baseline_data.pop(ip_address, None)
            else:
                self._per_ip_baseline_data.clear()

    def clear_all_data(self):
        """Clear all in-memory data (stats, traffic, anomaly, per-IP)."""
        with self._stats_lock:
            self._stats_history.clear()
            self._current_stats = {'timestamp': 0, 'ports': {}, 'connected': False}

        with self._traffic_lock:
            self._traffic_data.clear()

        with self._anomaly_lock:
            self._current_anomaly = self._default_anomaly()

        with self._sysmon_lock:
            self._current_sysmon = self._default_sysmon()

        with self._per_ip_anomaly_lock:
            self._per_ip_anomaly_data.clear()

        with self._per_ip_features_lock:
            self._per_ip_features_data.clear()

        with self._per_ip_baseline_lock:
            self._per_ip_baseline_data.clear()

        logger.info("All DPDK service in-memory data cleared")

    def get_sysmon(self) -> Dict[str, Any]:
        with self._sysmon_lock:
            return dict(self._current_sysmon)

    def get_anomaly(self) -> Dict[str, Any]:
        with self._anomaly_lock:
            return dict(self._current_anomaly)

    def get_per_ip_anomaly(self) -> Dict[str, Dict]:
        with self._per_ip_anomaly_lock:
            return dict(self._per_ip_anomaly_data)

    def get_per_ip_features(self) -> Dict[str, Dict]:
        with self._per_ip_features_lock:
            return dict(self._per_ip_features_data)

    def get_per_ip_baselines(self) -> Dict[str, Dict]:
        with self._per_ip_baseline_lock:
            return dict(self._per_ip_baseline_data)

    def is_connected(self) -> bool:
        with self._stats_lock:
            return self._current_stats.get('connected', False)


# Singleton instance
_dpdk_service: Optional[DPDKService] = None


def get_dpdk_service() -> DPDKService:
    """Get or create the singleton DPDK service instance."""
    global _dpdk_service
    if _dpdk_service is None:
        _dpdk_service = DPDKService()
    return _dpdk_service
