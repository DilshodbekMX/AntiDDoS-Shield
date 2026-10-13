"""
Background tasks module.

Provides scheduled task execution for:
- Real-time stats broadcasting
- Attack lifecycle monitoring
- Traffic rollup collection
- Expired entry cleanup
- Scheduled report generation
- Webhook dispatch and retry
- Health monitoring
"""

from .scheduler import (
    TaskScheduler,
    get_scheduler,
    start_scheduler,
    stop_scheduler,
)

from .workers import (
    broadcast_stats,
    cleanup_expired,
    process_scheduled_reports,
    check_system_health,
    retry_failed_webhooks,
    monitor_attack_lifecycle,
    collect_traffic_rollup,
)

__all__ = [
    "TaskScheduler",
    "get_scheduler",
    "start_scheduler",
    "stop_scheduler",
    "broadcast_stats",
    "cleanup_expired",
    "process_scheduled_reports",
    "check_system_health",
    "retry_failed_webhooks",
    "monitor_attack_lifecycle",
    "collect_traffic_rollup",
]
