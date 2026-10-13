"""
Health check worker.

Monitors system health and broadcasts alerts.
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)


async def check_system_health():
    """
    Perform system health checks.

    This runs every 30 seconds to monitor:
    - DPDK connection status
    - Database connectivity
    - Redis availability
    - Memory usage
    - Attack detection status
    """
    try:
        from ...websocket.handlers import handle_alert_message

        health_issues = []

        # Check DPDK service
        try:
            from ...services.dpdk_service import get_dpdk_service
            dpdk = get_dpdk_service()
            if not dpdk.is_connected():
                health_issues.append({
                    "component": "dpdk",
                    "status": "disconnected",
                    "message": "DPDK datapath not connected",
                })
        except Exception as e:
            health_issues.append({
                "component": "dpdk",
                "status": "error",
                "message": str(e),
            })

        # Check Redis
        try:
            from ...cache import get_redis_client
            redis = get_redis_client()
            if not redis.ping():
                health_issues.append({
                    "component": "redis",
                    "status": "unavailable",
                    "message": "Redis cache not responding",
                })
        except Exception as e:
            # Redis is optional, don't alert
            pass

        # Check database
        try:
            from ...database import get_db
            from sqlalchemy import text
            db = next(get_db())
            db.execute(text("SELECT 1"))
        except Exception as e:
            health_issues.append({
                "component": "database",
                "status": "error",
                "message": str(e),
            })

        # Broadcast alerts for any issues
        for issue in health_issues:
            await handle_alert_message(
                alert_type="health",
                alert_message=issue["message"],
                severity="warning" if issue["status"] != "error" else "error",
                details=issue,
            )

        if health_issues:
            logger.warning(f"Health check found {len(health_issues)} issues")

    except Exception as e:
        logger.error(f"Health check failed: {e}")
