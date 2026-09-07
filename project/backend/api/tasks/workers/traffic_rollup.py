"""
Traffic rollup worker.

Captures 1-minute traffic snapshots to SQLite for historical queries.
Also prunes old records (>90 days) on each run.
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Previous cumulative counters for delta computation
_prev_dropped = 0
_prev_drops_by_reason: dict = {}


async def collect_traffic_rollup():
    """
    Collect and persist a 1-minute traffic rollup.

    Runs every 60 seconds via scheduler.
    Reads current DPDK stats and writes a TrafficRollup row.
    """
    global _prev_dropped, _prev_drops_by_reason

    try:
        from ...services.dpdk_service import get_dpdk_service
        from ...database.connection import get_db
        from ...database.repositories.traffic_repo import TrafficRepository

        dpdk = get_dpdk_service()

        # Get current port stats (aggregated across all ports)
        stats = dpdk.get_stats()
        if not stats:
            return

        # Aggregate rx/tx across all ports
        rx_pps = 0
        tx_pps = 0
        rx_bps = 0
        tx_bps = 0
        dropped_cumulative = 0

        ports = stats.get('ports', {})
        for port_data in ports.values():
            rx_pps += port_data.get('rx_pps', 0)
            tx_pps += port_data.get('tx_pps', 0)
            # rx_bps/tx_bps from stats_socket are in BITS/sec, convert to bytes
            rx_bps += port_data.get('rx_bps', 0) // 8
            tx_bps += port_data.get('tx_bps', 0) // 8
            dropped_cumulative += port_data.get('dropped', 0)

        # Compute dropped delta (cumulative counter -> per-minute rate)
        if _prev_dropped > 0 and dropped_cumulative >= _prev_dropped:
            dropped_pps = dropped_cumulative - _prev_dropped
        else:
            # First run or counter reset -- use 0 (no delta available)
            dropped_pps = 0
        _prev_dropped = dropped_cumulative

        # Get drop reasons (also cumulative counters) and compute deltas
        raw_drops = stats.get('drops_by_reason', {})
        drops_by_reason = {}
        for reason, cumulative in raw_drops.items():
            prev = _prev_drops_by_reason.get(reason, 0)
            if prev > 0 and cumulative >= prev:
                drops_by_reason[reason] = cumulative - prev
            else:
                drops_by_reason[reason] = 0
        _prev_drops_by_reason = dict(raw_drops)

        # Get anomaly state
        anomaly = dpdk.get_anomaly()
        anomaly_active = anomaly.get('active', False) if anomaly else False
        anomaly_level = anomaly.get('level', 0) if anomaly else 0

        # Count active per-IP attacks
        per_ip_anomaly = dpdk.get_per_ip_anomaly()
        active_attacks = sum(
            1 for a in per_ip_anomaly.values()
            if a.get('anomaly_active', False)
        ) if per_ip_anomaly else 0

        # Count protected IPs
        protected_ip_count = len(per_ip_anomaly) if per_ip_anomaly else 0

        # Write to database
        db = next(get_db())
        try:
            repo = TrafficRepository(db)
            repo.insert_rollup(
                rx_pps=rx_pps,
                tx_pps=tx_pps,
                rx_bps=rx_bps,
                tx_bps=tx_bps,
                dropped_pps=dropped_pps,
                drops_by_reason=drops_by_reason,
                anomaly_active=anomaly_active,
                anomaly_level=anomaly_level,
                active_attacks=active_attacks,
                protected_ip_count=protected_ip_count,
            )

            # Prune old records every run (cheap query, keeps DB bounded)
            pruned = repo.prune_old(days=90)
            if pruned > 0:
                logger.info(f"Pruned {pruned} old traffic rollup records")

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Traffic rollup failed: {e}")
