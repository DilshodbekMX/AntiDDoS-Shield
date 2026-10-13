"""
Stats collector worker.

Collects real-time statistics from DPDK and broadcasts to WebSocket clients.
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)


async def broadcast_stats():
    """
    Collect and broadcast real-time statistics.

    This runs every 1 second to push live stats to WebSocket clients.
    """
    try:
        from ...services.dpdk_service import get_dpdk_service
        from ...websocket import get_connection_manager
        from ...websocket.handlers import handle_stats_message

        dpdk_service = get_dpdk_service()
        manager = get_connection_manager()

        # Skip if no WebSocket clients connected
        if manager.connection_count == 0:
            return

        # Get stats from DPDK service
        stats = dpdk_service.get_stats()

        if stats:
            # Broadcast to WebSocket clients
            await handle_stats_message({
                "type": "port_stats",
                "timestamp": datetime.utcnow().isoformat(),
                "ports": stats,
            })

        # Get system stats from the stats dict
        sysmon = stats.get("system") if stats else None
        if sysmon:
            await handle_stats_message({
                "type": "system_stats",
                "timestamp": datetime.utcnow().isoformat(),
                "stats": sysmon,
            })

    except Exception as e:
        # Don't log every second if there's an issue
        pass
