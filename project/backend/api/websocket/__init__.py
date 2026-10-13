"""
WebSocket module for real-time data streaming.

Provides WebSocket support for:
- Real-time port statistics (1 Hz)
- Attack notifications
- Traffic samples
- System alerts
"""

from .manager import ConnectionManager, get_connection_manager
from .handlers import (
    handle_stats_message,
    handle_attack_message,
    handle_traffic_message,
    handle_alert_message,
)

__all__ = [
    "ConnectionManager",
    "get_connection_manager",
    "handle_stats_message",
    "handle_attack_message",
    "handle_traffic_message",
    "handle_alert_message",
]
