"""
Background task workers.

Implements the actual work performed by scheduled tasks:
- Stats broadcasting to WebSocket clients
- Threat intel feed synchronization
- Reputation score decay
- Expired entry cleanup
- Scheduled report processing
- System health monitoring
- Webhook retry logic
"""

import logging
from datetime import datetime
from typing import Optional

from ..services.dpdk_service import get_dpdk_service
from ..websocket.handlers import (
    handle_stats_message,
    handle_traffic_message,
    handle_attack_message,
    handle_alert_message,
)

logger = logging.getLogger(__name__)


async def broadcast_stats():
    """
    Broadcast real-time statistics to WebSocket clients.

    Called every 1 second by the scheduler.
    Reads data from DPDK service and broadcasts to all connected clients.
    """
    dpdk = get_dpdk_service()

    # Get all current data from DPDK
    stats = dpdk.get_stats()
    anomaly = dpdk.get_anomaly()
    sysmon = dpdk.get_sysmon()
    traffic = dpdk.get_traffic()
    per_ip_anomaly = dpdk.get_per_ip_anomaly()
    per_ip_features = dpdk.get_per_ip_features()

    # Calculate aggregated stats
    total_rx_pps = 0
    total_tx_pps = 0
    total_rx_bps = 0
    total_tx_bps = 0
    total_dropped = 0

    for port_data in stats.get('ports', {}).values():
        total_rx_pps += port_data.get('rx_pps', 0)
        total_tx_pps += port_data.get('tx_pps', 0)
        total_rx_bps += port_data.get('rx_bps', 0)
        total_tx_bps += port_data.get('tx_bps', 0)
        total_dropped += port_data.get('dropped', 0)

    # Build comprehensive stats message
    stats_payload = {
        "type": "realtime_stats",
        "timestamp": datetime.utcnow().isoformat(),
        "connected": stats.get('connected', False),
        "ports": stats.get('ports', {}),
        "summary": {
            "total_rx_pps": total_rx_pps,
            "total_tx_pps": total_tx_pps,
            "total_rx_bps": total_rx_bps,
            "total_tx_bps": total_tx_bps,
            "total_rx_mbps": round(total_rx_bps / 1e6, 2),
            "total_tx_mbps": round(total_tx_bps / 1e6, 2),
            "total_dropped": total_dropped,
        },
        "anomaly": {
            "active": anomaly.get('active', False),
            "level": anomaly.get('level', 0),
            "level_name": anomaly.get('level_name', 'NONE'),
            "max_z_score": anomaly.get('max_z_score', 0.0),
            "confidence": anomaly.get('confidence', 0),
            "primary_feature": anomaly.get('primary_feature_name', 'unknown'),
            "duration_sec": anomaly.get('duration_sec', 0),
            "packets_per_sec": anomaly.get('packets_per_sec', 0),
            "bytes_per_sec": anomaly.get('bytes_per_sec', 0),
            "syn_per_sec": anomaly.get('syn_per_sec', 0),
            "unique_src_ips": anomaly.get('unique_src_ips', 0),
            "unique_flows": anomaly.get('unique_flows', 0),
            "heavy_hitters": anomaly.get('heavy_hitters', 0),
            "detection_count": anomaly.get('detection_count', 0),
            "baseline_updates": anomaly.get('baseline_updates', 0),
        },
        "system": {
            "dpdk": sysmon.get('dpdk', {}),
            "system": sysmon.get('system', {}),
        },
        "per_ip_count": len(per_ip_features),
        "anomalous_ips": len([ip for ip, data in per_ip_anomaly.items()
                             if data.get('anomaly_active', False)]),
    }

    # Broadcast stats
    await handle_stats_message(stats_payload)

    # If there's an active attack, also send attack notification
    if anomaly.get('active', False):
        attack_payload = {
            "id": f"anomaly_{anomaly.get('timestamp', 0)}",
            "type": anomaly.get('primary_feature_name', 'unknown'),
            "severity": _level_to_severity(anomaly.get('level', 0)),
            "target_ip": "0.0.0.0",  # Global anomaly
            "is_active": True,
            "pps": anomaly.get('packets_per_sec', 0),
            "bps": anomaly.get('bytes_per_sec', 0),
            "source_count": anomaly.get('unique_src_ips', 0),
            "z_score": anomaly.get('max_z_score', 0.0),
            "confidence": anomaly.get('confidence', 0),
            "duration_sec": anomaly.get('duration_sec', 0),
        }
        await handle_attack_message(attack_payload)

    # Broadcast traffic samples if available
    if traffic.get('entries'):
        traffic_payload = {
            "type": "traffic_samples",
            "timestamp": datetime.utcnow().isoformat(),
            "connected": traffic.get('connected', False),
            "samples": traffic.get('entries', [])[-20:],  # Last 20 samples
            "sample_count": len(traffic.get('entries', [])),
        }
        await handle_traffic_message(traffic_payload)


def _level_to_severity(level: int) -> str:
    """Convert anomaly level to severity string."""
    if level >= 4:
        return "critical"
    elif level >= 3:
        return "high"
    elif level >= 2:
        return "medium"
    elif level >= 1:
        return "low"
    return "none"


async def sync_threat_intel():
    """
    Synchronize threat intelligence feeds.

    Called every 1 hour by the scheduler.
    """
    logger.info("Syncing threat intel feeds...")
    # This would integrate with Layer 5 threat intel module
    # For now, just log
    logger.info("Threat intel sync completed")


async def decay_reputation():
    """
    Apply reputation score decay.

    Called every 5 minutes by the scheduler.
    Gradually increases reputation scores toward neutral for IPs
    that haven't been seen recently.
    """
    logger.info("Applying reputation decay...")
    # This would integrate with Layer 4 reputation module
    logger.info("Reputation decay completed")


async def cleanup_expired():
    """
    Clean up expired entries.

    Called every 1 hour by the scheduler.
    Removes expired policies, blacklist entries, etc.
    """
    logger.info("Cleaning up expired entries...")
    # This would clean up database entries
    logger.info("Cleanup completed")


async def process_scheduled_reports():
    """
    Process scheduled reports.

    Called every 1 minute by the scheduler.
    Checks for reports due to be generated and processes them.
    """
    # This would check scheduled reports and generate them
    pass


async def check_system_health():
    """
    Check system health and send alerts if needed.

    Called every 30 seconds by the scheduler.
    """
    dpdk = get_dpdk_service()

    # Check DPDK connection
    stats = dpdk.get_stats()
    sysmon = dpdk.get_sysmon()

    if not stats.get('connected', False):
        await handle_alert_message(
            alert_type="system",
            alert_message="DPDK datapath disconnected",
            severity="warning",
            details={"component": "dpdk", "status": "disconnected"},
        )

    # Check memory usage
    mem_usage = sysmon.get('system', {}).get('mem_usage_pct', 0)
    if mem_usage > 90:
        await handle_alert_message(
            alert_type="system",
            alert_message=f"High memory usage: {mem_usage:.1f}%",
            severity="warning",
            details={"metric": "memory", "value": mem_usage, "threshold": 90},
        )

    # Check hugepage usage
    hp_usage = sysmon.get('dpdk', {}).get('hugepage_usage_pct', 0)
    if hp_usage > 90:
        await handle_alert_message(
            alert_type="system",
            alert_message=f"High hugepage usage: {hp_usage:.1f}%",
            severity="warning",
            details={"metric": "hugepages", "value": hp_usage, "threshold": 90},
        )

    # Check lcore utilization
    avg_lcore = sysmon.get('dpdk', {}).get('avg_lcore_utilization', 0)
    if avg_lcore > 95:
        await handle_alert_message(
            alert_type="system",
            alert_message=f"High lcore utilization: {avg_lcore:.1f}%",
            severity="warning",
            details={"metric": "lcore", "value": avg_lcore, "threshold": 95},
        )


async def retry_failed_webhooks():
    """
    Retry failed webhook deliveries.

    Called every 1 minute by the scheduler.
    """
    # This would check for failed webhooks and retry them
    pass
