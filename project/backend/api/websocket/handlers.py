"""
WebSocket message handlers.

Handles incoming WebSocket messages and routes them to appropriate
processing logic based on message type.
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime

from .manager import (
    ConnectionManager,
    Connection,
    WSMessage,
    MessageType,
    SubscriptionTopic,
    get_connection_manager,
)

logger = logging.getLogger(__name__)


async def handle_ping(
    client_id: str,
    connection: Connection,
    message: WSMessage,
):
    """Handle ping message - respond with pong."""
    manager = get_connection_manager()
    await manager.send_to_client(
        client_id,
        WSMessage(
            type=MessageType.PONG,
            timestamp=datetime.utcnow().timestamp(),
            payload={"client_time": message.payload.get("client_time")},
        ),
    )


async def handle_subscribe(
    client_id: str,
    connection: Connection,
    message: WSMessage,
):
    """Handle subscription request."""
    manager = get_connection_manager()
    topics = message.payload.get("topics", [])

    if isinstance(topics, str):
        topics = [topics]

    subscribed = []
    for topic in topics:
        # Validate topic
        if topic == SubscriptionTopic.ALL.value:
            # Subscribe to all standard topics
            for sub_topic in [SubscriptionTopic.STATS, SubscriptionTopic.ATTACKS,
                             SubscriptionTopic.TRAFFIC, SubscriptionTopic.ALERTS]:
                room = sub_topic.value
                await manager.subscribe(client_id, room)
                subscribed.append(room)
        elif topic in {t.value for t in SubscriptionTopic}:
            await manager.subscribe(client_id, topic)
            subscribed.append(topic)
        else:
            logger.warning(f"Client {client_id} tried to subscribe to invalid topic: {topic}")

    await manager.send_to_client(
        client_id,
        WSMessage(
            type=MessageType.ACK,
            timestamp=datetime.utcnow().timestamp(),
            payload={
                "action": "subscribe",
                "topics": subscribed,
                "success": True,
            },
        ),
    )

    logger.info(f"Client {client_id} subscribed to: {subscribed}")


async def handle_unsubscribe(
    client_id: str,
    connection: Connection,
    message: WSMessage,
):
    """Handle unsubscription request."""
    manager = get_connection_manager()
    topics = message.payload.get("topics", [])

    if isinstance(topics, str):
        topics = [topics]

    unsubscribed = []
    for topic in topics:
        await manager.unsubscribe(client_id, topic)
        unsubscribed.append(topic)

    await manager.send_to_client(
        client_id,
        WSMessage(
            type=MessageType.ACK,
            timestamp=datetime.utcnow().timestamp(),
            payload={
                "action": "unsubscribe",
                "topics": unsubscribed,
                "success": True,
            },
        ),
    )

    logger.info(f"Client {client_id} unsubscribed from: {unsubscribed}")


async def handle_stats_message(stats: Dict[str, Any]):
    """
    Handle incoming stats data and broadcast to subscribers.

    This is called by the DPDK service when new stats are available.

    Args:
        stats: Statistics data from DPDK
    """
    manager = get_connection_manager()

    message = WSMessage(
        type=MessageType.STATS,
        timestamp=datetime.utcnow().timestamp(),
        payload=stats,
    )

    # Broadcast to global stats room
    await manager.broadcast_to_room("stats", message)


async def handle_attack_message(attack_data: Dict[str, Any]):
    """
    Handle attack notification and broadcast to subscribers.

    This is called when an attack is detected.

    Args:
        attack_data: Attack details including type, severity, targets
    """
    manager = get_connection_manager()

    # Enrich attack data
    enriched_data = {
        "id": attack_data.get("id"),
        "type": attack_data.get("type", "unknown"),
        "severity": attack_data.get("severity", "medium"),
        "target_ip": attack_data.get("target_ip"),
        "target_port": attack_data.get("target_port"),
        "detected_at": attack_data.get("detected_at", datetime.utcnow().isoformat()),
        "is_active": attack_data.get("is_active", True),
        "metrics": {
            "pps": attack_data.get("pps", 0),
            "bps": attack_data.get("bps", 0),
            "source_count": attack_data.get("source_count", 0),
        },
        "mitigation": attack_data.get("mitigation", {}),
    }

    message = WSMessage(
        type=MessageType.ATTACK,
        timestamp=datetime.utcnow().timestamp(),
        payload=enriched_data,
    )

    # Broadcast to global attacks room
    await manager.broadcast_to_room("attacks", message)

    logger.info(
        f"Attack broadcast: type={enriched_data['type']}, "
        f"severity={enriched_data['severity']}"
    )


async def handle_traffic_message(traffic_data: Dict[str, Any]):
    """
    Handle traffic sample and broadcast to subscribers.

    This is called periodically with traffic samples.

    Args:
        traffic_data: Traffic sample data
    """
    manager = get_connection_manager()

    message = WSMessage(
        type=MessageType.TRAFFIC,
        timestamp=datetime.utcnow().timestamp(),
        payload=traffic_data,
    )

    await manager.broadcast_to_room("traffic", message)


async def handle_alert_message(
    alert_type: str,
    alert_message: str,
    severity: str = "info",
    details: Optional[Dict[str, Any]] = None,
):
    """
    Handle system alert and broadcast to subscribers.

    Args:
        alert_type: Type of alert (system, security, threshold, etc.)
        alert_message: Human-readable alert message
        severity: Alert severity (info, warning, error, critical)
        details: Optional additional details
    """
    manager = get_connection_manager()

    alert_data = {
        "alert_type": alert_type,
        "message": alert_message,
        "severity": severity,
        "details": details or {},
        "timestamp": datetime.utcnow().isoformat(),
    }

    message = WSMessage(
        type=MessageType.ALERT,
        timestamp=datetime.utcnow().timestamp(),
        payload=alert_data,
    )

    # Broadcast to global alerts room
    await manager.broadcast_to_room("alerts", message)

    logger.info(f"Alert broadcast: type={alert_type}, severity={severity}")


async def handle_learning_state_change(
    state: str,
    phase: int,
    progress_pct: int,
    tier1_ready: bool,
    tier2_ready: bool,
    tier3_ready: bool,
    eta_mature_seconds: int,
):
    """Broadcast a learning phase transition event to all 'alerts' subscribers.

    Called by the background polling loop in realtime.py when a phase change
    is detected. The dashboard listens for this to refresh the LearningStatus widget.
    """
    manager = get_connection_manager()

    payload = {
        "type": "learning_state_change",
        "state": state,
        "phase": phase,
        "progress_pct": progress_pct,
        "tier1_ready": tier1_ready,
        "tier2_ready": tier2_ready,
        "tier3_ready": tier3_ready,
        "eta_mature_seconds": eta_mature_seconds,
        "timestamp": datetime.utcnow().isoformat(),
    }

    message = WSMessage(
        type=MessageType.ALERT,
        timestamp=datetime.utcnow().timestamp(),
        payload=payload,
    )

    await manager.broadcast_to_room("alerts", message)
    logger.info(f"Learning state change broadcast: state={state}, phase={phase}")


def register_default_handlers(manager: ConnectionManager):
    """Register default message handlers with the connection manager."""
    manager.register_handler(MessageType.PING, handle_ping)
    manager.register_handler(MessageType.SUBSCRIBE, handle_subscribe)
    manager.register_handler(MessageType.UNSUBSCRIBE, handle_unsubscribe)


# Message processing loop for a single client
async def process_client_messages(client_id: str):
    """
    Process messages from a connected client.

    This runs as a task for each connected client, receiving and
    handling messages until the client disconnects.

    Args:
        client_id: Client identifier
    """
    manager = get_connection_manager()

    while True:
        message = await manager.receive_message(client_id)
        if message is None:
            break

        # Handle the message
        await manager.handle_message(client_id, message)


# Utility functions for sending broadcasts from other parts of the application

async def broadcast_port_stats(port_stats: Dict[str, Any]):
    """
    Broadcast port statistics from DPDK.

    Called by the stats collection service.

    Args:
        port_stats: Port statistics dictionary
    """
    await handle_stats_message({
        "type": "port_stats",
        "ports": port_stats,
    })


async def broadcast_layer_stats(
    layer: int,
    stats: Dict[str, Any],
):
    """
    Broadcast layer-specific statistics.

    Args:
        layer: Layer number (1-5)
        stats: Layer statistics
    """
    await handle_stats_message({
        "type": f"layer{layer}_stats",
        "stats": stats,
    })


async def broadcast_system_stats(stats: Dict[str, Any]):
    """
    Broadcast system-level statistics (CPU, memory, etc.).

    Args:
        stats: System statistics
    """
    await handle_stats_message({
        "type": "system_stats",
        "stats": stats,
    })


async def broadcast_attack_started(
    attack_id: str,
    attack_type: str,
    severity: str,
    target_ip: str,
    **kwargs,
):
    """
    Broadcast attack start notification.

    Args:
        attack_id: Unique attack identifier
        attack_type: Type of attack (syn_flood, udp_flood, etc.)
        severity: Attack severity (low, medium, high, critical)
        target_ip: Target IP address
        **kwargs: Additional attack details
    """
    await handle_attack_message({
        "id": attack_id,
        "type": attack_type,
        "severity": severity,
        "target_ip": target_ip,
        "is_active": True,
        "event": "started",
        **kwargs,
    })


async def broadcast_attack_mitigated(
    attack_id: str,
    mitigation_time_ms: float,
):
    """
    Broadcast attack mitigation notification.

    Args:
        attack_id: Attack identifier
        mitigation_time_ms: Time to mitigate in milliseconds
    """
    await handle_attack_message({
        "id": attack_id,
        "is_mitigated": True,
        "mitigation_time_ms": mitigation_time_ms,
        "event": "mitigated",
    })


async def broadcast_attack_ended(
    attack_id: str,
    duration_seconds: float,
    packets_dropped: int,
):
    """
    Broadcast attack end notification.

    Args:
        attack_id: Attack identifier
        duration_seconds: Total attack duration
        packets_dropped: Total packets dropped during attack
    """
    await handle_attack_message({
        "id": attack_id,
        "is_active": False,
        "duration_seconds": duration_seconds,
        "packets_dropped": packets_dropped,
        "event": "ended",
    })


async def broadcast_threshold_alert(
    metric_name: str,
    current_value: float,
    threshold_value: float,
):
    """
    Broadcast threshold exceeded alert.

    Args:
        metric_name: Name of the metric
        current_value: Current metric value
        threshold_value: Threshold that was exceeded
    """
    severity = "warning"
    if current_value > threshold_value * 1.5:
        severity = "error"
    if current_value > threshold_value * 2:
        severity = "critical"

    await handle_alert_message(
        alert_type="threshold",
        alert_message=f"{metric_name} exceeded threshold: {current_value:.2f} > {threshold_value:.2f}",
        severity=severity,
        details={
            "metric": metric_name,
            "current": current_value,
            "threshold": threshold_value,
            "percent_over": ((current_value - threshold_value) / threshold_value) * 100,
        },
    )


async def broadcast_security_alert(
    alert_type: str,
    message: str,
    source_ip: Optional[str] = None,
    **details,
):
    """
    Broadcast security-related alert.

    Args:
        alert_type: Type of security alert
        message: Alert message
        source_ip: Source IP if applicable
        **details: Additional details
    """
    await handle_alert_message(
        alert_type=f"security:{alert_type}",
        alert_message=message,
        severity="warning",
        details={
            "source_ip": source_ip,
            **details,
        },
    )
