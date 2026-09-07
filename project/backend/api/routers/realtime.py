"""
Realtime Data Router

FastAPI router providing real-time data from DPDK datapath:
- Port statistics (packets, bytes, PPS, BPS)
- Traffic samples
- Anomaly detection status
- System monitoring (CPU, memory, hugepages)
- Per-IP statistics and anomaly status
"""

from collections import deque
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Depends
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import time
import threading

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ..auth import UserContext, check_rate_limit, get_current_user
from ..services.dpdk_service import get_dpdk_service, ANOMALY_LEVEL_NAMES, PROTO_CAT_NAMES, ATTACK_TYPE_NAMES, FEATURE_NAMES
from rules import get_rules_engine

router = APIRouter(prefix="/realtime", tags=["Realtime Data"])

# Lock for global mutable state accessed from concurrent requests
_history_lock = threading.Lock()

# Global traffic history -- deque with maxlen caps memory automatically.
# Each sample: { timestamp, timestamp_str, pps, bps, drops, anomaly_count, rx_bps, tx_bps, ... }
_GLOBAL_HISTORY_MAX_SAMPLES = 300  # 5 minutes at 1Hz sampling
_global_traffic_history: deque = deque(maxlen=_GLOBAL_HISTORY_MAX_SAMPLES)
_last_global_sample_time: float = 0

# Port-level traffic history -- deque with maxlen caps memory automatically.
# Samples: { timestamp, timestamp_str, ports: {port_id: {rx_bps, tx_bps, rx_pps, tx_pps}} }
_PORT_HISTORY_MAX_SAMPLES = 300  # 5 minutes at 1Hz sampling
_port_traffic_history: deque = deque(maxlen=_PORT_HISTORY_MAX_SAMPLES)
_last_port_sample_time: float = 0

# Drop reason rate tracking (cumulative -> per-second)
_prev_drop_reasons: Dict[str, int] = {}
_prev_drop_time: float = 0.0
_cached_drop_rates: Dict[str, int] = {}

# Learning phase transition tracking -- detect phase changes and push WS events
_last_learning_phase: int = -1  # -1 = uninitialized
_last_learning_phase_check: float = 0.0
_LEARNING_PHASE_CHECK_INTERVAL: float = 5.0


def _normalize_ip(ip_str: str) -> str:
    """Normalize IP address to standard dotted-decimal format."""
    import ipaddress
    try:
        return str(ipaddress.ip_address(ip_str))
    except (ValueError, TypeError):
        return ip_str


_PROTOCOL_FLOOD_NAMES = {
    'TCP': 'TCP_FLOOD', 'UDP': 'UDP_FLOOD', 'ICMP': 'ICMP_FLOOD',
}


def _infer_attack_type(state: Dict, features: Dict) -> str:
    """Infer attack type name when L2 classifies as VOLUMETRIC (-> UNKNOWN).

    Uses anomaly protocol if specific, otherwise dominant protocol from traffic features.
    Only infers attack types when an anomaly is actually active -- otherwise returns 'Normal'.
    """
    # FIX: If no anomaly is active, return 'Normal' immediately.
    # Without this, any IP with >40% TCP traffic gets labeled 'TCP_FLOOD'
    # in the API response even when anomaly_active=False, causing the
    # dashboard to show non-anomalous IPs as under attack.
    if not state.get('anomaly_active', False):
        return 'Normal'

    attack_type = state.get('attack_type_name', 'UNKNOWN')
    if attack_type != 'UNKNOWN':
        return attack_type

    protocol = state.get('anomaly_protocol_name', 'ALL')
    # If L2 reported a specific protocol, use it
    if protocol in _PROTOCOL_FLOOD_NAMES:
        return _PROTOCOL_FLOOD_NAMES[protocol]

    # Protocol is ALL -- infer from traffic feature ratios
    if features:
        tcp_r = features.get('tcp_ratio', 0)
        udp_r = features.get('udp_ratio', 0)
        icmp_r = features.get('icmp_ratio', 0)
        dominant = max(tcp_r, udp_r, icmp_r)
        if dominant > 40:  # At least 40% of traffic
            if dominant == icmp_r:
                return 'ICMP_FLOOD'
            elif dominant == udp_r:
                return 'UDP_FLOOD'
            elif dominant == tcp_r:
                return 'TCP_FLOOD'

    return 'VOLUMETRIC'


def _compute_drop_rates(current_reasons: Dict[str, int]) -> Dict[str, int]:
    """Convert cumulative drop counters to per-second rates.

    Only updates baseline every 1.5+ seconds to avoid noise.
    Returns cached rates between updates.
    """
    global _prev_drop_reasons, _prev_drop_time, _cached_drop_rates
    now = time.time()
    dt = now - _prev_drop_time

    if dt < 1.5:
        # Too soon -- return cached rates
        return _cached_drop_rates

    if not _prev_drop_reasons:
        # First call -- store baseline, no rates yet
        _prev_drop_reasons = dict(current_reasons)
        _prev_drop_time = now
        return _cached_drop_rates

    # Compute per-second rates from delta
    rates = {}
    for reason, count in current_reasons.items():
        prev = _prev_drop_reasons.get(reason, None)
        if prev is None:
            continue  # New key -- skip until next cycle
        delta = max(0, count - prev)
        rate = int(delta / dt)
        if rate > 0:
            rates[reason] = rate

    _prev_drop_reasons = dict(current_reasons)
    _prev_drop_time = now
    _cached_drop_rates = rates
    return rates


def _sample_global_traffic() -> None:
    """Sample current global traffic and add to history.

    Called periodically (1Hz) when stats are fetched.
    Aggregates per-IP feature data for all protected IPs.
    Thread-safe: uses _history_lock to protect shared mutable state.
    """
    global _global_traffic_history, _last_global_sample_time

    now = time.time()

    # Check rate limit without lock (benign race: worst case double-sample)
    if now - _last_global_sample_time < 1.0:
        return

    from datetime import datetime
    timestamp_str = datetime.now().strftime('%H:%M:%S')
    timestamp = int(now * 1000)

    # Get current per-IP data
    service = get_dpdk_service()
    features_data = service.get_per_ip_features()
    anomaly_data = service.get_per_ip_anomaly()

    # Get global port stats for drops and TX rates
    stats = service.get_stats()
    port_values = list(stats.get('ports', {}).values())
    total_drops = sum(p.get('dropped', 0) for p in port_values)
    # TX = outbound traffic (servers -> internet), port-level only
    # NOTE: C stats_socket computes rx_bps/tx_bps as BITS/s (bytes_diff * 8)
    # Per-IP bytes_per_sec is BYTES/s. Convert port bits -> bytes with /8
    # so all history fields are in bytes/s (matching per-IP and formatBytes())
    global_tx_bps = sum(p.get('tx_bps', 0) for p in port_values) // 8
    global_tx_pps = sum(p.get('tx_pps', 0) for p in port_values)
    global_rx_bps_port = sum(p.get('rx_bps', 0) for p in port_values) // 8
    global_rx_pps_port = sum(p.get('rx_pps', 0) for p in port_values)
    # Compute drop pps from cumulative drop reason counters
    drop_rates = _compute_drop_rates(stats.get('drops_by_reason', {}))
    global_drop_pps = sum(drop_rates.values())

    # Compute forwarded traffic (clean traffic sent TO protected network)
    # fwd = received - dropped (what survived filtering)
    global_fwd_pps = max(0, global_rx_pps_port - global_drop_pps)
    # Estimate fwd_bps proportionally (avg pkt size assumed similar)
    if global_rx_pps_port > 0:
        global_fwd_bps = int(global_rx_bps_port * global_fwd_pps / global_rx_pps_port)
    else:
        global_fwd_bps = 0
    global_drop_bps = max(0, global_rx_bps_port - global_fwd_bps)

    # Aggregate per-IP traffic across all protected IPs
    global_pps = 0
    global_bps = 0
    global_anomaly_count = 0

    for ip_str, features in features_data.items():
        if features.get('active', False):
            global_pps += features.get('packets_per_sec', 0)
            global_bps += features.get('bytes_per_sec', 0)

    for ip_str, anomaly in anomaly_data.items():
        if anomaly.get('anomaly_active', False):
            global_anomaly_count += 1

    # For RX: use per-IP aggregate if available, fallback to port-level
    effective_rx_bps = global_bps if global_bps > 0 else global_rx_bps_port
    effective_rx_pps = global_pps if global_pps > 0 else global_rx_pps_port
    # Recompute fwd/drop based on effective RX (per-IP aggregate preferred)
    eff_fwd_pps = max(0, effective_rx_pps - global_drop_pps)
    if effective_rx_pps > 0:
        eff_fwd_bps = int(effective_rx_bps * eff_fwd_pps / effective_rx_pps)
    else:
        eff_fwd_bps = 0
    eff_drop_bps = max(0, effective_rx_bps - eff_fwd_bps)

    # NOTE: Despite field names ending in '_bps', all BPS values here are in BYTES/sec
    # (port-level bits/s from C are converted to bytes/s at lines 157-159 above).
    # This matches per-IP bytes_per_sec and dashboard formatBytes() expectations.
    sample = {
        'timestamp': timestamp,
        'timestamp_str': timestamp_str,
        'pps': global_pps,
        'bps': global_bps,
        'drops': total_drops,
        'attacks': global_anomaly_count,
        'rx_bps': effective_rx_bps,     # bytes/sec
        'tx_bps': global_tx_bps,        # bytes/sec
        'rx_pps': effective_rx_pps,
        'tx_pps': global_tx_pps,
        'drop_pps': global_drop_pps,
        'fwd_bps': eff_fwd_bps,         # bytes/sec
        'fwd_pps': eff_fwd_pps,
        'drop_bps': eff_drop_bps,       # bytes/sec
    }

    with _history_lock:
        _last_global_sample_time = now
        _global_traffic_history.append(sample)  # deque maxlen handles trimming


async def _check_learning_phase_transition() -> None:
    """Detect learning phase transitions and push WebSocket events.

    Polls anomaly data every 5s and broadcasts a 'learning_state_change' event
    to 'alerts' subscribers when the learning phase changes.
    """
    global _last_learning_phase, _last_learning_phase_check

    now = time.time()
    if now - _last_learning_phase_check < _LEARNING_PHASE_CHECK_INTERVAL:
        return
    _last_learning_phase_check = now

    try:
        service = get_dpdk_service()
        anomaly = service.get_anomaly()

        phase = int(anomaly.get('learning_phase', 0))
        if phase == _last_learning_phase:
            return

        # Phase changed -- broadcast event
        _last_learning_phase = phase
        _PHASE_NAMES = {0: 'cold_start', 1: 'warmup', 2: 'moderate', 3: 'mature'}
        tier1_progress = int(anomaly.get('tier1_progress', 0))
        tier2_progress = int(anomaly.get('tier2_progress', 0))
        tier3_progress = int(anomaly.get('tier3_progress', 0))
        progress_pct = int(tier1_progress * 0.20 + tier2_progress * 0.30 + tier3_progress * 0.50)
        tier1_eta = int(anomaly.get('tier1_eta_sec', 0))
        tier2_eta = int(anomaly.get('tier2_eta_sec', 0))
        tier3_eta = int(anomaly.get('tier3_eta_sec', 0))
        eta = max(tier1_eta, tier2_eta, tier3_eta) if phase < 3 else 0

        from ..websocket.handlers import handle_learning_state_change
        await handle_learning_state_change(
            state=_PHASE_NAMES.get(phase, 'cold_start'),
            phase=phase,
            progress_pct=progress_pct,
            tier1_ready=bool(anomaly.get('tier1_ready', False)),
            tier2_ready=tier2_progress >= 100,
            tier3_ready=tier3_progress >= 100,
            eta_mature_seconds=eta,
        )
    except Exception:
        pass  # Non-critical -- don't crash the request if WS broadcast fails


def _sample_port_traffic() -> None:
    """Sample current port-level traffic and add to history.

    Called periodically (1Hz) when stats are fetched.
    Used by Traffic page timeline chart.
    """
    global _port_traffic_history, _last_port_sample_time

    now = time.time()

    # Check rate limit without lock (benign race: worst case double-sample)
    if now - _last_port_sample_time < 1.0:
        return

    from datetime import datetime
    timestamp_str = datetime.now().strftime('%H:%M:%S')
    timestamp = int(now * 1000)

    # Get current port stats
    service = get_dpdk_service()
    stats = service.get_stats()

    # Build port snapshot
    ports_snapshot = {}
    for port_id, port_stats in stats.get('ports', {}).items():
        ports_snapshot[str(port_id)] = {
            'rx_bps': port_stats.get('rx_bps', 0),
            'tx_bps': port_stats.get('tx_bps', 0),
            'rx_pps': port_stats.get('rx_pps', 0),
            'tx_pps': port_stats.get('tx_pps', 0),
            'dropped': port_stats.get('dropped', 0),
        }

    # Create sample
    sample = {
        'timestamp': timestamp,
        'timestamp_str': timestamp_str,
        'ports': ports_snapshot,
    }

    # Add to history (thread-safe) -- deque maxlen handles trimming
    with _history_lock:
        _last_port_sample_time = now
        _port_traffic_history.append(sample)


# Response models
class PortStats(BaseModel):
    port_id: int
    rx_packets: int
    tx_packets: int
    rx_bytes: int
    tx_bytes: int
    dropped: int
    rx_pps: int
    tx_pps: int
    rx_bps: int
    tx_bps: int
    rx_mbps: float
    tx_mbps: float
    rx_kpps: float
    tx_kpps: float


class StatsResponse(BaseModel):
    timestamp: int
    timestamp_str: str
    connected: bool
    ports: Dict[str, Any]  # Port ID as string key, port stats as value


class TrafficEntry(BaseModel):
    timestamp: int
    timestamp_str: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    protocol_num: int
    flags: int
    length: int
    port_id: int
    direction: str


class ProtocolStat(BaseModel):
    packets: int
    bytes: int
    pps: int


class ProtocolStats(BaseModel):
    tcp: ProtocolStat
    udp: ProtocolStat
    icmp: ProtocolStat
    other: ProtocolStat


class TrafficResponse(BaseModel):
    connected: bool
    entries: List[TrafficEntry]
    protocol_stats: Optional[ProtocolStats] = None
    drop_reasons: Optional[Dict[str, int]] = None
    drop_reasons_total: Optional[Dict[str, int]] = None
    total_dropped: Optional[int] = None


class AnomalyResponse(BaseModel):
    timestamp: int
    timestamp_str: Optional[str] = None
    active: bool
    level: int
    level_name: str
    tier_agreement: int
    max_z_score: float
    confidence: float  # 0-100 percentage (C sends 0.0-1.0, backend converts to %)
    primary_feature: int
    primary_feature_name: str
    duration_sec: float
    cool_down_remaining: float
    baselines_frozen: bool
    tier1_ready: bool
    tier2_ready_count: int
    tier3_ready_count: int
    baseline_updates: int
    detection_cycles: int
    detection_count: int
    packets_per_sec: int
    bytes_per_sec: int
    syn_per_sec: int
    unique_src_ips: int
    unique_flows: int
    heavy_hitters: int
    rate_limit_pct: int
    current_threshold: float = 0.0  # Current adaptive Z-score threshold
    # Learning state
    learning_phase: int = 0
    learning_phase_name: str = 'COLD'
    tier1_progress: int = 0
    tier2_progress: int = 0
    tier3_progress: int = 0
    tier1_eta_sec: int = 0
    tier2_eta_sec: int = 0
    tier3_eta_sec: int = 0
    baseline_age_sec: int = 0
    # Alert-Only Mode
    mitigation_active: bool = False
    learning_action: int = 0
    suppressed_count: int = 0
    # Progressive trust
    trust_multiplier: float = 1.0
    # Detection method state
    sensitivity_preset: int = 0
    cusum_active: bool = False
    jsd_active: bool = False
    fast_active: bool = False
    fp_rate: float = 0.0
    tp_rate: float = 0.0
    adaptive_adjustments: int = 0


class LcoreStats(BaseModel):
    lcore_id: int
    is_active: bool
    busy_cycles: int
    idle_cycles: int
    utilization_pct: float


class MempoolStats(BaseModel):
    name: str
    size: int
    avail_count: int
    in_use_count: int
    usage_pct: float


class CpuStats(BaseModel):
    cpu_id: int
    usage_pct: float
    user_pct: float
    system_pct: float
    idle_pct: float
    iowait_pct: float


class DPDKResources(BaseModel):
    lcores: List[LcoreStats]
    avg_lcore_utilization: float
    mempools: List[MempoolStats]
    hugepage_total_mb: float
    hugepage_used_mb: float
    hugepage_usage_pct: float


class SystemResources(BaseModel):
    cpus: List[CpuStats]
    avg_cpu_usage: float
    mem_total_gb: float
    mem_used_gb: float
    mem_available_gb: float
    mem_usage_pct: float
    load_1min: float
    load_5min: float
    load_15min: float


class SysmonResponse(BaseModel):
    timestamp: int
    timestamp_str: Optional[str] = None
    dpdk: DPDKResources
    system: SystemResources


class PerIPAnomalyEntry(BaseModel):
    dst_ip: int
    dst_ip_str: str
    anomaly_active: bool
    level: int
    level_name: str
    max_z_score: float
    tier_agreement: int
    anomalous_feature_count: int
    start_time_ns: int
    last_update_ns: int
    anomaly_protocol: int
    anomaly_protocol_name: str
    attack_type: int
    attack_type_name: str
    anomaly_dst_port: int
    flash_crowd_score: int = 0
    syn_completion_pct: int = 0
    response_ratio_pct: int = 0
    spoofed_mode: bool = False
    randomness_pct: int = 0
    rate_limit_pct: int = 100
    packets_per_sec: int = 0
    bytes_per_sec: int = 0
    unique_src_ips: int = 0
    duration_sec: float = 0.0
    started_at: str = ""
    # Detection details
    detection_method: int = 0
    sensitivity_preset: int = 0
    learning_phase: int = 0
    tier1_progress: int = 0
    cool_down_remaining_sec: int = 0
    peak_z_feature: int = 0
    peak_z_feature_name: str = ""
    cusum_triggered: bool = False
    jsd_triggered: bool = False
    fast_triggered: bool = False
    confidence: int = 0
    severity: int = 0


class PerIPAnomalyResponse(BaseModel):
    per_ip_anomalies: List[PerIPAnomalyEntry]
    count: int
    any_active: bool


class PerIPAnomalySummary(BaseModel):
    total_protected_ips: int
    anomalous_ips: int
    healthy_ips: int
    max_severity_level: int
    max_severity_name: str
    max_z_score: float


# Endpoints
@router.get("/stats", response_model=StatsResponse)
async def get_stats(user: UserContext = Depends(get_current_user)):
    """Get current port statistics from DPDK."""
    import time
    service = get_dpdk_service()
    stats = service.get_stats()

    # Ensure timestamp fields exist even when disconnected
    if not stats.get('timestamp'):
        stats['timestamp'] = int(time.time() * 1000)
    if not stats.get('timestamp_str'):
        from datetime import datetime
        stats['timestamp_str'] = datetime.now().strftime('%H:%M:%S')
    if 'ports' not in stats:
        stats['ports'] = {}

    # Convert port keys to strings for JSON compatibility
    if stats.get('ports'):
        stats['ports'] = {str(k): v for k, v in stats['ports'].items()}

    return stats


@router.get("/stats/history")
async def get_stats_history(
        user: UserContext = Depends(get_current_user),
    limit: int = Query(60, ge=1, le=3600),
):
    """Get historical traffic statistics.

    Returns global aggregated per-IP traffic history.
    """
    # Trigger sampling on each request (1Hz max)
    _sample_global_traffic()
    _sample_port_traffic()

    with _history_lock:
        history = list(_global_traffic_history)
        return history[-limit:] if limit < len(history) else history


@router.get("/stats/port-history")
async def get_port_stats_history(
        user: UserContext = Depends(get_current_user),
    limit: int = Query(60, ge=1, le=3600),
):
    """Get historical port-level traffic statistics.

    Returns raw port-level RX/TX bps/pps history for Traffic page timeline.
    Each sample includes all ports with their individual stats.
    """
    # Trigger sampling on each request (1Hz max)
    _sample_port_traffic()

    with _history_lock:
        history = list(_port_traffic_history)
        return history[-limit:] if limit < len(history) else history


@router.get("/traffic", response_model=TrafficResponse)
async def get_traffic(limit: int = Query(100, ge=1, le=200),
                      user: UserContext = Depends(get_current_user)):
    """Get recent traffic samples from DPDK with protocol statistics."""
    service = get_dpdk_service()
    traffic_data = service.get_traffic(limit)

    # Try to get protocol stats from per-IP features (more accurate)
    features_data = service.get_per_ip_features()
    total_pps = 0
    tcp_ratio_sum, udp_ratio_sum, icmp_ratio_sum, other_ratio_sum = 0.0, 0.0, 0.0, 0.0
    active_count = 0

    for ip_str, features in features_data.items():
        if features.get('active', False):
            pps = features.get('packets_per_sec', 0)
            total_pps += pps
            tcp_ratio_sum += features.get('tcp_ratio', 0) * pps
            udp_ratio_sum += features.get('udp_ratio', 0) * pps
            icmp_ratio_sum += features.get('icmp_ratio', 0) * pps
            other_ratio_sum += features.get('other_ratio', 0) * pps
            active_count += 1

    # Calculate weighted average ratios
    if total_pps > 0:
        tcp_pps = int(tcp_ratio_sum / 100.0)
        udp_pps = int(udp_ratio_sum / 100.0)
        icmp_pps = int(icmp_ratio_sum / 100.0)
        other_pps = int(other_ratio_sum / 100.0)
    else:
        # Fall back to computing from traffic entries
        entries = traffic_data.get('entries', [])
        tcp_packets, udp_packets, icmp_packets, other_packets = 0, 0, 0, 0

        for entry in entries:
            proto = entry.get('protocol_num', 0)
            if proto == 6:  # TCP
                tcp_packets += 1
            elif proto == 17:  # UDP
                udp_packets += 1
            elif proto == 1:  # ICMP
                icmp_packets += 1
            else:
                other_packets += 1

        # Estimate PPS based on time range of entries
        tcp_pps, udp_pps, icmp_pps, other_pps = 0, 0, 0, 0
        if len(entries) >= 2:
            time_range_ms = entries[0].get('timestamp', 0) - entries[-1].get('timestamp', 0)
            if time_range_ms > 0:
                time_range_sec = time_range_ms / 1000.0
                tcp_pps = int(tcp_packets / time_range_sec) if time_range_sec > 0 else tcp_packets
                udp_pps = int(udp_packets / time_range_sec) if time_range_sec > 0 else udp_packets
                icmp_pps = int(icmp_packets / time_range_sec) if time_range_sec > 0 else icmp_packets
                other_pps = int(other_packets / time_range_sec) if time_range_sec > 0 else other_packets
            else:
                tcp_pps, udp_pps, icmp_pps, other_pps = tcp_packets, udp_packets, icmp_packets, other_packets
        else:
            tcp_pps, udp_pps, icmp_pps, other_pps = tcp_packets, udp_packets, icmp_packets, other_packets

    # Estimate packets/bytes (rough approximation using 60 byte avg packet size)
    avg_pkt_size = 60
    traffic_data['protocol_stats'] = {
        'tcp': {'packets': tcp_pps, 'bytes': tcp_pps * avg_pkt_size, 'pps': tcp_pps},
        'udp': {'packets': udp_pps, 'bytes': udp_pps * avg_pkt_size, 'pps': udp_pps},
        'icmp': {'packets': icmp_pps, 'bytes': icmp_pps * avg_pkt_size, 'pps': icmp_pps},
        'other': {'packets': other_pps, 'bytes': other_pps * avg_pkt_size, 'pps': other_pps},
    }

    # Add drop stats from DPDK - now includes actual drop reasons
    # (Blacklist, Rate Limit, Geo Blocked, SYN Flood, etc.)
    stats = service.get_stats()
    total_dropped = sum(p.get('dropped', 0) for p in stats.get('ports', {}).values())

    # Use real drop reasons if available, otherwise fall back to per-port totals
    drop_reasons = stats.get('drops_by_reason', {})
    if not drop_reasons:
        # Fallback: show per-port totals if real reasons not available
        for port_id, port_stats in stats.get('ports', {}).items():
            dropped = port_stats.get('dropped', 0)
            if dropped > 0:
                label = 'Ingress Blocked' if str(port_id) == '0' else f'Port {port_id} Blocked'
                drop_reasons[label] = dropped

    # Convert cumulative drop counters to per-second rates
    # so the chart shows current activity, not historical accumulation
    traffic_data['drop_reasons'] = _compute_drop_rates(drop_reasons) if drop_reasons else {}
    traffic_data['drop_reasons_total'] = drop_reasons if drop_reasons else {}
    traffic_data['total_dropped'] = total_dropped

    return traffic_data


@router.post("/traffic/clear")
async def clear_traffic(user: UserContext = Depends(check_rate_limit)):
    """Clear traffic sample buffer."""
    service = get_dpdk_service()
    service.clear_traffic()
    return {"status": "cleared"}


@router.get("/sysmon", response_model=SysmonResponse)
async def get_sysmon(user: UserContext = Depends(get_current_user)):
    """Get system monitor stats (DPDK resources + system CPU/memory)."""
    service = get_dpdk_service()
    return service.get_sysmon()


@router.get("/anomaly", response_model=AnomalyResponse)
async def get_anomaly(
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
):
    """Get Layer 2 anomaly detection status (global)."""
    service = get_dpdk_service()
    result = service.get_anomaly()
    # Piggyback phase-change detection as a background task (non-blocking)
    background_tasks.add_task(_check_learning_phase_transition)
    return result


@router.get("/anomaly/per-ip", response_model=PerIPAnomalyResponse)
async def get_per_ip_anomaly(user: UserContext = Depends(get_current_user)):
    """Get per-protected-IP anomaly detection status."""
    service = get_dpdk_service()
    per_ip_data = service.get_per_ip_anomaly()
    features_data = service.get_per_ip_features()

    # Only show anomalies for IPs that are actually in the protected list
    protected_ips: set = set()
    try:
        rules = get_rules_engine()
        for rule in rules.get_protected():
            pip = _normalize_ip(rule.get('ip', ''))
            if pip:
                protected_ips.add(pip)
    except Exception:
        pass

    # If no IPs are protected, there can be no anomalies to report
    if not protected_ips:
        return {
            'per_ip_anomalies': [],
            'count': 0,
            'any_active': False
        }

    # Build normalized lookup for features data (by IP string and by IP int)
    features_by_ip_int: Dict[int, Dict] = {}
    features_by_normalized_ip: Dict[str, Dict] = {}
    for fip, fdata in features_data.items():
        features_by_normalized_ip[_normalize_ip(fip)] = fdata
        if 'dst_ip_int' in fdata:
            features_by_ip_int[fdata['dst_ip_int']] = fdata

    # Compute monotonic-to-wall-clock offset once for timestamp conversion
    now_mono = time.monotonic_ns()
    now_wall = time.time()

    result = []
    for ip_str, state in per_ip_data.items():
        # Only include IPs that are protected AND have active anomalies
        if _normalize_ip(ip_str) not in protected_ips:
            continue
        if state.get('active', False) and state.get('anomaly_active', False):
            # Get traffic stats for this IP - try multiple lookup methods
            features = features_data.get(ip_str, {})
            if not features:
                # Try normalized IP lookup
                features = features_by_normalized_ip.get(_normalize_ip(ip_str), {})
            if not features and 'dst_ip_int' in state:
                # Try IP integer lookup
                features = features_by_ip_int.get(state['dst_ip_int'], {})

            # Convert monotonic start_time_ns to wall-clock time
            start_ns = state.get('start_time_ns', 0)
            if start_ns > 0:
                duration_sec = max(0, (now_mono - start_ns) / 1e9)
                started_wall = now_wall - duration_sec
                from datetime import datetime
                started_at = datetime.fromtimestamp(started_wall).strftime('%Y-%m-%dT%H:%M:%S')
            else:
                duration_sec = 0.0
                started_at = ""

            result.append({
                'dst_ip': state.get('dst_ip_int', 0),
                'dst_ip_str': ip_str,
                'anomaly_active': state.get('anomaly_active', False),
                'level': state.get('level', 0),
                'level_name': ANOMALY_LEVEL_NAMES.get(state.get('level', 0), 'UNKNOWN'),
                'max_z_score': round(state.get('max_z_score', 0.0), 2),
                'tier_agreement': state.get('tier_agreement', 0),
                'anomalous_feature_count': state.get('anomalous_feature_count', 0),
                'start_time_ns': start_ns,
                'last_update_ns': state.get('last_update_ns', 0),
                'anomaly_protocol': state.get('anomaly_protocol', 255),
                'anomaly_protocol_name': state.get('anomaly_protocol_name', 'ALL'),
                'attack_type': state.get('attack_type', 0),
                'attack_type_name': _infer_attack_type(state, features),
                'anomaly_dst_port': state.get('anomaly_dst_port', 0),
                # Flash crowd indicators (0-100 scaled)
                'flash_crowd_score': state.get('flash_crowd_score', 0),
                'syn_completion_pct': state.get('syn_completion_pct', 0),
                'response_ratio_pct': state.get('response_ratio_pct', 0),
                # Per-IP mitigation state
                'spoofed_mode': state.get('spoofed_mode', False),
                'randomness_pct': state.get('randomness_pct', 0),
                'rate_limit_pct': state.get('rate_limit_pct', 100),
                # Traffic info from per-IP features
                'packets_per_sec': features.get('packets_per_sec', 0),
                'bytes_per_sec': features.get('bytes_per_sec', 0),
                'unique_src_ips': features.get('unique_src_ips', 0),
                # Computed wall-clock times
                'duration_sec': round(duration_sec, 1),
                'started_at': started_at,
                # Detection details
                'detection_method': state.get('detection_method', 0),
                'sensitivity_preset': state.get('sensitivity_preset', 0),
                'learning_phase': state.get('learning_phase', 0),
                'tier1_progress': state.get('tier1_progress', 0),
                'cool_down_remaining_sec': state.get('cool_down_remaining_sec', 0),
                'peak_z_feature': state.get('peak_z_feature', 0),
                'peak_z_feature_name': FEATURE_NAMES[state.get('peak_z_feature', 0)]
                    if 0 <= state.get('peak_z_feature', 0) < len(FEATURE_NAMES) else '',
                'cusum_triggered': state.get('cusum_triggered', False),
                'jsd_triggered': state.get('jsd_triggered', False),
                'fast_triggered': state.get('fast_triggered', False),
                'confidence': state.get('confidence', 0),
                'severity': state.get('severity', 0),
            })

    return {
        'per_ip_anomalies': result,
        'count': len(result),
        'any_active': len(result) > 0  # result only contains anomalous IPs now
    }


@router.get("/anomaly/per-ip/summary", response_model=PerIPAnomalySummary)
async def get_per_ip_anomaly_summary(user: UserContext = Depends(get_current_user)):
    """Get summary of per-IP anomaly detection."""
    service = get_dpdk_service()
    per_ip_data = service.get_per_ip_anomaly()

    # Get configured protected IPs -- only count IPs that are actually protected
    protected_ips: set = set()
    try:
        rules = get_rules_engine()
        for rule in rules.get_protected():
            pip = _normalize_ip(rule.get('ip', ''))
            if pip:
                protected_ips.add(pip)
    except Exception:
        pass  # If rules unavailable, fall back to active anomaly states

    # Filter anomaly states to only configured protected IPs
    if protected_ips:
        active_states = []
        for ip_str, s in per_ip_data.items():
            if s.get('active', False) and _normalize_ip(ip_str) in protected_ips:
                active_states.append(s)
    else:
        active_states = []

    anomalous_states = [s for s in active_states if s.get('anomaly_active', False)]

    max_level = 0
    max_z = 0.0
    for state in anomalous_states:
        if state.get('level', 0) > max_level:
            max_level = state.get('level', 0)
        if state.get('max_z_score', 0.0) > max_z:
            max_z = state.get('max_z_score', 0.0)

    # Total count = configured protected IPs (authoritative source)
    total_count = len(protected_ips)

    return {
        'total_protected_ips': total_count,
        'anomalous_ips': len(anomalous_states),
        'healthy_ips': total_count - len(anomalous_states),
        'max_severity_level': max_level,
        'max_severity_name': ANOMALY_LEVEL_NAMES.get(max_level, 'UNKNOWN'),
        'max_z_score': round(max_z, 2)
    }


@router.get("/anomaly/per-ip/{ip}")
async def get_per_ip_anomaly_single(ip: str,
                                    user: UserContext = Depends(get_current_user)):
    """Get anomaly status for a specific protected IP."""
    service = get_dpdk_service()
    per_ip_data = service.get_per_ip_anomaly()

    # Try multiple lookup methods
    state = per_ip_data.get(ip)
    if state is None:
        # Try normalized IP lookup
        normalized_ip = _normalize_ip(ip)
        for key, val in per_ip_data.items():
            if _normalize_ip(key) == normalized_ip:
                state = val
                break

    if state is None:
        raise HTTPException(status_code=404, detail=f"Protected IP {ip} not found")

    # Get features for attack type inference
    features_data = service.get_per_ip_features()
    features = features_data.get(ip, {})
    if not features:
        normalized_ip = _normalize_ip(ip)
        for key, val in features_data.items():
            if _normalize_ip(key) == normalized_ip:
                features = val
                break

    return {
        'dst_ip': ip,
        'anomaly_active': state.get('anomaly_active', False),
        'level': state.get('level', 0),
        'level_name': ANOMALY_LEVEL_NAMES.get(state.get('level', 0), 'UNKNOWN'),
        'max_z_score': round(state.get('max_z_score', 0.0), 2),
        'tier_agreement': state.get('tier_agreement', 0),
        'anomalous_feature_count': state.get('anomalous_feature_count', 0),
        'anomaly_protocol': state.get('anomaly_protocol', 255),
        'anomaly_protocol_name': state.get('anomaly_protocol_name', 'ALL'),
        'attack_type': state.get('attack_type', 0),
        'attack_type_name': _infer_attack_type(state, features),
        'anomaly_dst_port': state.get('anomaly_dst_port', 0),
        'flash_crowd_score': state.get('flash_crowd_score', 0),
        'syn_completion_pct': state.get('syn_completion_pct', 0),
        'response_ratio_pct': state.get('response_ratio_pct', 0),
        'spoofed_mode': state.get('spoofed_mode', False),
        'randomness_pct': state.get('randomness_pct', 0),
        'rate_limit_pct': state.get('rate_limit_pct', 100),
        # Detection details
        'detection_method': state.get('detection_method', 0),
        'sensitivity_preset': state.get('sensitivity_preset', 0),
        'learning_phase': state.get('learning_phase', 0),
        'tier1_progress': state.get('tier1_progress', 0),
        'cool_down_remaining_sec': state.get('cool_down_remaining_sec', 0),
        'peak_z_feature': state.get('peak_z_feature', 0),
        'cusum_triggered': state.get('cusum_triggered', False),
        'jsd_triggered': state.get('jsd_triggered', False),
        'fast_triggered': state.get('fast_triggered', False),
        'confidence': state.get('confidence', 0),
        'severity': state.get('severity', 0),
    }


@router.get("/stats/per-ip")
async def get_per_ip_stats(user: UserContext = Depends(get_current_user)):
    """Get per-protected-IP traffic statistics with anomaly status combined."""
    service = get_dpdk_service()
    features_data = service.get_per_ip_features()
    anomaly_data = service.get_per_ip_anomaly()

    # Build set of currently protected IPs for filtering
    protected_ips: set = set()
    rules_available = False
    try:
        rules = get_rules_engine()
        for rule in rules.get_protected():
            pip = _normalize_ip(rule.get('ip', ''))
            if pip:
                protected_ips.add(pip)
        rules_available = True
    except Exception:
        pass  # If rules engine unavailable, show all IPs as fallback

    # If rules engine is available but no IPs are protected, return empty
    if rules_available and not protected_ips:
        return {
            'protected_ips': [],
            'count': 0,
            'totals': {
                'total_pps': 0,
                'total_bps': 0,
                'total_packets': 0,
            }
        }

    # Build normalized lookup for anomaly data (by IP string and by IP int)
    anomaly_by_ip_int: Dict[int, Dict] = {}
    anomaly_by_normalized_ip: Dict[str, Dict] = {}
    for aip, adata in anomaly_data.items():
        anomaly_by_normalized_ip[_normalize_ip(aip)] = adata
        if 'dst_ip_int' in adata:
            anomaly_by_ip_int[adata['dst_ip_int']] = adata

    result = []
    for ip_str, features in features_data.items():
        if not features.get('active', False):
            continue
        # Only show IPs that are in the protected list
        if _normalize_ip(ip_str) not in protected_ips:
            continue

        entry = {
            'dst_ip': features.get('dst_ip_int', 0),
            'dst_ip_str': ip_str,
            'has_traffic_data': True,
            'packets_per_sec': features.get('packets_per_sec', 0),
            'bytes_per_sec': features.get('bytes_per_sec', 0),
            'flows_per_sec': features.get('flows_per_sec', 0),
            'total_packets': features.get('total_packets', 0),
            'active_flows': features.get('active_flows', 0),
            'syn_per_sec': features.get('syn_per_sec', 0),
            'syn_ack_per_sec': features.get('syn_ack_per_sec', 0),
            'ack_per_sec': features.get('ack_per_sec', 0),
            'rst_per_sec': features.get('rst_per_sec', 0),
            'fin_per_sec': features.get('fin_per_sec', 0),
            'tcp_ratio': features.get('tcp_ratio', 0),
            'udp_ratio': features.get('udp_ratio', 0),
            'icmp_ratio': features.get('icmp_ratio', 0),
            'other_ratio': features.get('other_ratio', 0),
            'unique_src_ips': features.get('unique_src_ips', 0),
            'unique_flows': features.get('unique_flows', 0),
            'max_flow_fraction': features.get('max_flow_fraction', 0),
            'topk_flow_share': features.get('topk_flow_share', 0),
            'heavy_hitter_count': features.get('heavy_hitter_count', 0),
            'avg_packets_per_flow': features.get('avg_packets_per_flow', 0),
            'flow_duration_avg_ms': features.get('flow_duration_avg_ms', 0),
        }

        # Add anomaly status - try multiple lookup methods
        anomaly = anomaly_data.get(ip_str, {})
        if not anomaly:
            # Try normalized IP lookup
            anomaly = anomaly_by_normalized_ip.get(_normalize_ip(ip_str), {})
        if not anomaly and 'dst_ip_int' in features:
            # Try IP integer lookup
            anomaly = anomaly_by_ip_int.get(features['dst_ip_int'], {})
        is_anomalous = anomaly.get('anomaly_active', False)
        entry['anomaly_active'] = is_anomalous
        entry['anomaly_level'] = anomaly.get('level', 0) if is_anomalous else 0
        entry['anomaly_level_name'] = ANOMALY_LEVEL_NAMES.get(anomaly.get('level', 0), 'NONE') if is_anomalous else 'NONE'
        entry['max_z_score'] = round(anomaly.get('max_z_score', 0.0), 2) if is_anomalous else 0.0
        entry['tier_agreement'] = anomaly.get('tier_agreement', 0) if is_anomalous else 0
        entry['anomaly_protocol'] = anomaly.get('anomaly_protocol', 255) if is_anomalous else 255
        entry['anomaly_protocol_name'] = PROTO_CAT_NAMES.get(anomaly.get('anomaly_protocol', 255), 'ALL') if is_anomalous else 'ALL'
        entry['attack_type'] = anomaly.get('attack_type', 0) if is_anomalous else 0
        entry['attack_type_name'] = _infer_attack_type(anomaly, features)
        entry['anomaly_dst_port'] = anomaly.get('anomaly_dst_port', 0) if is_anomalous else 0
        entry['flash_crowd_score'] = anomaly.get('flash_crowd_score', 0) if is_anomalous else 0
        entry['syn_completion_pct'] = anomaly.get('syn_completion_pct', 0) if is_anomalous else 0
        entry['response_ratio_pct'] = anomaly.get('response_ratio_pct', 0) if is_anomalous else 0
        entry['spoofed_mode'] = anomaly.get('spoofed_mode', False) if is_anomalous else False
        entry['randomness_pct'] = anomaly.get('randomness_pct', 0) if is_anomalous else 0
        entry['rate_limit_pct'] = anomaly.get('rate_limit_pct', 100)
        # Detection details
        entry['detection_method'] = anomaly.get('detection_method', 0) if is_anomalous else 0
        entry['sensitivity_preset'] = anomaly.get('sensitivity_preset', 0) if is_anomalous else 0
        entry['learning_phase'] = anomaly.get('learning_phase', 0)
        entry['tier1_progress'] = anomaly.get('tier1_progress', 0)
        entry['cool_down_remaining_sec'] = anomaly.get('cool_down_remaining_sec', 0)
        entry['peak_z_feature'] = anomaly.get('peak_z_feature', 0) if is_anomalous else 0
        entry['cusum_triggered'] = anomaly.get('cusum_triggered', False) if is_anomalous else False
        entry['jsd_triggered'] = anomaly.get('jsd_triggered', False) if is_anomalous else False
        entry['fast_triggered'] = anomaly.get('fast_triggered', False) if is_anomalous else False
        entry['confidence'] = anomaly.get('confidence', 0) if is_anomalous else 0
        entry['severity'] = anomaly.get('severity', 0) if is_anomalous else 0

        result.append(entry)

    # Add configured protected IPs that don't have live traffic data
    seen_ips = {_normalize_ip(e['dst_ip_str']) for e in result}
    try:
        for rule_ip in protected_ips:
            if rule_ip not in seen_ips:
                entry = {
                    'dst_ip': 0,
                    'dst_ip_str': rule_ip,
                    'has_traffic_data': False,
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
                    'anomaly_active': False,
                    'anomaly_level': 0,
                    'anomaly_level_name': 'NONE',
                    'max_z_score': 0.0,
                    'tier_agreement': 0,
                    'anomaly_protocol': 255,
                    'anomaly_protocol_name': 'ALL',
                    'attack_type': 0,
                    'attack_type_name': 'Normal',
                    'anomaly_dst_port': 0,
                    'flash_crowd_score': 0,
                    'syn_completion_pct': 0,
                    'response_ratio_pct': 0,
                    'spoofed_mode': False,
                    'randomness_pct': 0,
                    'rate_limit_pct': 100,
                    # Detection details
                    'detection_method': 0,
                    'sensitivity_preset': 0,
                    'learning_phase': 0,
                    'tier1_progress': 0,
                    'cool_down_remaining_sec': 0,
                    'peak_z_feature': 0,
                    'cusum_triggered': False,
                    'jsd_triggered': False,
                    'fast_triggered': False,
                    'confidence': 0,
                    'severity': 0,
                }
                result.append(entry)
                seen_ips.add(rule_ip)
    except Exception:
        pass  # Rules engine may not be initialized yet

    # Sort: IPs with traffic first (by pps desc), then IPs without traffic (by IP)
    result.sort(key=lambda x: (-x['packets_per_sec'], x['dst_ip_str']))

    total_pps = sum(e['packets_per_sec'] for e in result)
    total_bps = sum(e['bytes_per_sec'] for e in result)
    total_packets = sum(e['total_packets'] for e in result)

    return {
        'protected_ips': result,
        'count': len(result),
        'totals': {
            'packets_per_sec': total_pps,
            'bytes_per_sec': total_bps,
            'total_packets': total_packets
        }
    }


@router.get("/stats/per-ip/{ip}")
async def get_per_ip_stats_single(ip: str,
                                  user: UserContext = Depends(get_current_user)):
    """Get detailed statistics for a specific protected IP."""
    service = get_dpdk_service()
    features_data = service.get_per_ip_features()

    # Try multiple lookup methods for features
    features = features_data.get(ip)
    if features is None:
        normalized_ip = _normalize_ip(ip)
        for key, val in features_data.items():
            if _normalize_ip(key) == normalized_ip:
                features = val
                break

    has_traffic = features is not None and features.get('active', False)

    if not has_traffic:
        # Check if IP is a configured protected IP (show with zeroed data)
        is_protected = False
        try:
            rules = get_rules_engine()
            normalized_ip = _normalize_ip(ip)
            for rule in rules.get_protected():
                if _normalize_ip(rule.get('ip', '')) == normalized_ip:
                    is_protected = True
                    break
        except Exception:
            pass
        if not is_protected:
            raise HTTPException(status_code=404, detail=f"Protected IP {ip} not found")
        features = {}

    anomaly_data = service.get_per_ip_anomaly()

    # Try multiple lookup methods for anomaly
    anomaly = anomaly_data.get(ip, {})
    if not anomaly:
        normalized_ip = _normalize_ip(ip)
        for key, val in anomaly_data.items():
            if _normalize_ip(key) == normalized_ip:
                anomaly = val
                break

    # Get per-IP baseline means from C Layer 2 EWMA (Tier 1, 10s sub-tier)
    baseline_data = service.get_per_ip_baselines()
    baselines = baseline_data.get(ip, {})
    if not baselines:
        normalized_ip = _normalize_ip(ip)
        for key, val in baseline_data.items():
            if _normalize_ip(key) == normalized_ip:
                baselines = val
                break

    # Compute TCP flag ratios (available in shared memory but not on wire)
    _pps = features.get('packets_per_sec', 0)
    _tcp_frac = features.get('tcp_ratio', 0) / 100.0 if features.get('tcp_ratio', 0) > 0 else 0
    _tcp_pps = _pps * _tcp_frac
    _syn_tcp = (features.get('syn_per_sec', 0) / _tcp_pps * 100) if _tcp_pps > 0 else 0
    _synack_tcp = (features.get('syn_ack_per_sec', 0) / _tcp_pps * 100) if _tcp_pps > 0 else 0
    _ack_tcp = (features.get('ack_per_sec', 0) / _tcp_pps * 100) if _tcp_pps > 0 else 0
    _rst_tcp = (features.get('rst_per_sec', 0) / _tcp_pps * 100) if _tcp_pps > 0 else 0
    _fin_tcp = (features.get('fin_per_sec', 0) / _tcp_pps * 100) if _tcp_pps > 0 else 0

    result = {
        'dst_ip': ip,
        'dst_ip_str': ip,
        'has_traffic_data': has_traffic,
        'packets_per_sec': features.get('packets_per_sec', 0),
        'bytes_per_sec': features.get('bytes_per_sec', 0),
        'flows_per_sec': features.get('flows_per_sec', 0),
        'total_packets': features.get('total_packets', 0),
        'active_flows': features.get('active_flows', 0),
        'syn_per_sec': features.get('syn_per_sec', 0),
        'syn_ack_per_sec': features.get('syn_ack_per_sec', 0),
        'ack_per_sec': features.get('ack_per_sec', 0),
        'rst_per_sec': features.get('rst_per_sec', 0),
        'fin_per_sec': features.get('fin_per_sec', 0),
        'tcp_ratio': features.get('tcp_ratio', 0),
        'udp_ratio': features.get('udp_ratio', 0),
        'icmp_ratio': features.get('icmp_ratio', 0),
        'other_ratio': features.get('other_ratio', 0),
        'unique_src_ips': features.get('unique_src_ips', 0),
        'unique_flows': features.get('unique_flows', 0),
        'max_flow_fraction': features.get('max_flow_fraction', 0),
        'topk_flow_share': features.get('topk_flow_share', 0),
        'heavy_hitter_count': features.get('heavy_hitter_count', 0),
        'avg_packets_per_flow': features.get('avg_packets_per_flow', 0),
        'flow_duration_avg_ms': features.get('flow_duration_avg_ms', 0),
        # Additional per-IP features
        'rst_syn_ratio': features.get('rst_syn_ratio', 0),
        'unique_dst_ports': features.get('unique_dst_ports', 0),
        'new_srcip_rate': features.get('new_srcip_rate', 0),
        'src_ip_entropy': features.get('src_ip_entropy', 0),
        'burst_factor': features.get('burst_factor', 100),
        'udp_flow_ratio': features.get('udp_flow_ratio', 0),
        'icmp_echo_ratio': features.get('icmp_echo_ratio', 0),
        'small_pkt_ratio': features.get('small_pkt_ratio', 0),
        'fragment_ratio': features.get('fragment_ratio', 0),
        'ttl_mean': features.get('ttl_mean', 0),
        'tcp_completion_rate': features.get('tcp_completion_rate', 0),
        'src_port_entropy': features.get('src_port_entropy', 0),
        'dst_port_density': features.get('dst_port_density', 0),
        # TCP flag ratios (computed from per-sec values)
        'syn_tcp_ratio': round(_syn_tcp, 1),
        'synack_tcp_ratio': round(_synack_tcp, 1),
        'ack_tcp_ratio': round(_ack_tcp, 1),
        'rst_tcp_ratio': round(_rst_tcp, 1),
        'fin_tcp_ratio': round(_fin_tcp, 1),
        'anomaly_active': anomaly.get('anomaly_active', False),
        'anomaly_level': anomaly.get('level', 0) if anomaly.get('anomaly_active') else 0,
        'anomaly_level_name': ANOMALY_LEVEL_NAMES.get(anomaly.get('level', 0), 'NONE') if anomaly.get('anomaly_active') else 'NONE',
        'max_z_score': round(anomaly.get('max_z_score', 0.0), 2) if anomaly.get('anomaly_active') else 0.0,
        'tier_agreement': anomaly.get('tier_agreement', 0) if anomaly.get('anomaly_active') else 0,
        'anomalous_feature_count': anomaly.get('anomalous_feature_count', 0) if anomaly.get('anomaly_active') else 0,
        'anomaly_protocol': anomaly.get('anomaly_protocol', 255) if anomaly.get('anomaly_active') else 255,
        'anomaly_protocol_name': PROTO_CAT_NAMES.get(anomaly.get('anomaly_protocol', 255), 'ALL') if anomaly.get('anomaly_active') else 'ALL',
        'attack_type': anomaly.get('attack_type', 0) if anomaly.get('anomaly_active') else 0,
        'attack_type_name': _infer_attack_type(anomaly, features) if anomaly.get('anomaly_active') else 'Normal',
        'anomaly_dst_port': anomaly.get('anomaly_dst_port', 0) if anomaly.get('anomaly_active') else 0,
        'flash_crowd_score': anomaly.get('flash_crowd_score', 0) if anomaly.get('anomaly_active') else 0,
        'syn_completion_pct': anomaly.get('syn_completion_pct', 0) if anomaly.get('anomaly_active') else 0,
        'response_ratio_pct': anomaly.get('response_ratio_pct', 0) if anomaly.get('anomaly_active') else 0,
        'spoofed_mode': anomaly.get('spoofed_mode', False) if anomaly.get('anomaly_active') else False,
        'randomness_pct': anomaly.get('randomness_pct', 0) if anomaly.get('anomaly_active') else 0,
        'rate_limit_pct': anomaly.get('rate_limit_pct', 100),
        # Detection details
        'detection_method': anomaly.get('detection_method', 0) if anomaly.get('anomaly_active') else 0,
        'sensitivity_preset': anomaly.get('sensitivity_preset', 0) if anomaly.get('anomaly_active') else 0,
        'learning_phase': anomaly.get('learning_phase', 0),
        'tier1_progress': anomaly.get('tier1_progress', 0),
        'cool_down_remaining_sec': anomaly.get('cool_down_remaining_sec', 0),
        'peak_z_feature': anomaly.get('peak_z_feature', 0) if anomaly.get('anomaly_active') else 0,
        'cusum_triggered': anomaly.get('cusum_triggered', False) if anomaly.get('anomaly_active') else False,
        'jsd_triggered': anomaly.get('jsd_triggered', False) if anomaly.get('anomaly_active') else False,
        'fast_triggered': anomaly.get('fast_triggered', False) if anomaly.get('anomaly_active') else False,
        'confidence': anomaly.get('confidence', 0) if anomaly.get('anomaly_active') else 0,
        'severity': anomaly.get('severity', 0) if anomaly.get('anomaly_active') else 0,
    }

    # Merge C Layer 2 EWMA baseline means into response
    # Keys like 'baseline_packets_per_sec', 'baseline_bytes_per_sec', etc.
    result.update(baselines)

    return result


@router.get("/connected")
async def get_connection_status(user: UserContext = Depends(get_current_user)):
    """Check if connected to DPDK datapath."""
    service = get_dpdk_service()
    return {"connected": service.is_connected()}
