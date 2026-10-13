"""
WebSocket connection manager for real-time data streaming.

Handles:
- Connection lifecycle (connect, disconnect, reconnect)
- Room-based subscriptions (by topic)
- Message broadcasting (unicast, multicast, broadcast)
- Authentication and authorization
- Rate limiting and message queuing
"""

import asyncio
import json
import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional, Dict, Set, List, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

logger = logging.getLogger(__name__)


class MessageType(str, Enum):
    """WebSocket message types."""
    STATS = "stats"
    ATTACK = "attack"
    TRAFFIC = "traffic"
    ALERT = "alert"
    ERROR = "error"
    PING = "ping"
    PONG = "pong"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    ACK = "ack"


class SubscriptionTopic(str, Enum):
    """Available subscription topics."""
    STATS = "stats"
    ATTACKS = "attacks"
    TRAFFIC = "traffic"
    ALERTS = "alerts"
    ALL = "all"


@dataclass
class WSMessage:
    """WebSocket message structure."""
    type: MessageType
    timestamp: float
    payload: Any
    message_id: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "type": self.type.value if isinstance(self.type, Enum) else self.type,
            "timestamp": self.timestamp,
            "message_id": self.message_id,
            "payload": self.payload,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "WSMessage":
        """Create from dictionary."""
        return cls(
            type=MessageType(data.get("type", "error")),
            timestamp=data.get("timestamp", datetime.utcnow().timestamp()),
            payload=data.get("payload", {}),
            message_id=data.get("message_id"),
        )


@dataclass
class Connection:
    """Represents a WebSocket connection."""
    websocket: WebSocket
    client_id: str
    user_id: Optional[str] = None
    subscriptions: Set[str] = field(default_factory=set)
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    is_authenticated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.utcnow()


class ConnectionManager:
    """
    Manages WebSocket connections with room-based subscriptions.

    Features:
    - Connection lifecycle management
    - Room/topic-based subscriptions
    - Message queuing for offline clients
    - Heartbeat monitoring
    - Connection limit to prevent resource exhaustion
    """

    MAX_CONNECTIONS = 500
    # Per-IP rate limit: max 10 connect attempts per 60 seconds
    CONNECT_RATE_LIMIT = 10
    CONNECT_RATE_WINDOW = 60

    def __init__(
        self,
        heartbeat_interval: float = 30.0,
        message_queue_size: int = 1000,
    ):
        # Connection storage
        self._connections: Dict[str, Connection] = {}
        # Per-IP connect timestamps for rate limiting (connect-close DoS prevention)
        self._connect_attempts: Dict[str, List[float]] = defaultdict(list)

        # Room-based subscriptions: room_name -> set of client_ids
        self._rooms: Dict[str, Set[str]] = {}

        # Configuration
        self._heartbeat_interval = heartbeat_interval
        self._message_queue_size = message_queue_size

        # Background tasks
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._running = False

        # Statistics
        self._stats = {
            "total_connections": 0,
            "total_messages_sent": 0,
            "total_messages_received": 0,
            "total_errors": 0,
        }

        # Message handlers
        self._message_handlers: Dict[MessageType, List[Callable]] = {}

    async def start(self):
        """Start background tasks."""
        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("WebSocket connection manager started")

    async def stop(self):
        """Stop background tasks and close all connections."""
        self._running = False

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # Close all connections
        for client_id in list(self._connections.keys()):
            await self.disconnect(client_id)

        logger.info("WebSocket connection manager stopped")

    async def connect(
        self,
        websocket: WebSocket,
        client_id: str,
        user_id: Optional[str] = None,
    ) -> Connection:
        """
        Accept a new WebSocket connection.

        Args:
            websocket: FastAPI WebSocket instance
            client_id: Unique client identifier
            user_id: Optional user ID

        Returns:
            Connection object
        """
        if len(self._connections) >= self.MAX_CONNECTIONS:
            await websocket.close(code=1013, reason="Max connections reached")
            logger.warning(
                f"WebSocket connection rejected: limit {self.MAX_CONNECTIONS} reached"
            )
            raise WebSocketDisconnect(code=1013)

        # Per-IP connect rate limiting (prevents connect-close DoS)
        client_ip = ""
        if hasattr(websocket, "client") and websocket.client:
            client_ip = websocket.client.host or ""
        if client_ip:
            now = time.monotonic()
            attempts = self._connect_attempts[client_ip]
            # Prune old entries
            cutoff = now - self.CONNECT_RATE_WINDOW
            self._connect_attempts[client_ip] = [t for t in attempts if t > cutoff]
            if len(self._connect_attempts[client_ip]) >= self.CONNECT_RATE_LIMIT:
                await websocket.close(code=1008, reason="Connection rate limit exceeded")
                logger.warning(
                    f"WebSocket connection rate-limited: ip={client_ip}"
                )
                raise WebSocketDisconnect(code=1008)
            self._connect_attempts[client_ip].append(now)

        await websocket.accept()

        connection = Connection(
            websocket=websocket,
            client_id=client_id,
            user_id=user_id,
            is_authenticated=True,
        )

        self._connections[client_id] = connection

        # Update stats
        self._stats["total_connections"] += 1

        logger.info(
            f"WebSocket connected: client={client_id}, "
            f"total={len(self._connections)}"
        )

        # Send welcome message
        await self.send_to_client(
            client_id,
            WSMessage(
                type=MessageType.ACK,
                timestamp=datetime.utcnow().timestamp(),
                payload={
                    "message": "Connected successfully",
                    "client_id": client_id,
                    "server_time": datetime.utcnow().isoformat(),
                },
            ),
        )

        return connection

    async def disconnect(self, client_id: str):
        """
        Disconnect a client and clean up resources.

        Args:
            client_id: Client identifier to disconnect
        """
        connection = self._connections.get(client_id)
        if not connection:
            return

        # Remove from rooms
        for room in list(connection.subscriptions):
            await self.unsubscribe(client_id, room)

        # Close websocket if still open
        try:
            if connection.websocket.client_state == WebSocketState.CONNECTED:
                await connection.websocket.close()
        except Exception as e:
            logger.debug(f"Error closing websocket: {e}")

        # Remove connection
        del self._connections[client_id]

        logger.info(f"WebSocket disconnected: client={client_id}, total={len(self._connections)}")

    async def subscribe(self, client_id: str, room: str) -> bool:
        """
        Subscribe a client to a room.

        Args:
            client_id: Client identifier
            room: Room name to subscribe to

        Returns:
            True if subscription successful
        """
        connection = self._connections.get(client_id)
        if not connection:
            return False

        if room not in self._rooms:
            self._rooms[room] = set()

        self._rooms[room].add(client_id)
        connection.subscriptions.add(room)

        logger.debug(f"Client {client_id} subscribed to room {room}")
        return True

    async def unsubscribe(self, client_id: str, room: str) -> bool:
        """
        Unsubscribe a client from a room.

        Args:
            client_id: Client identifier
            room: Room name to unsubscribe from

        Returns:
            True if unsubscription successful
        """
        connection = self._connections.get(client_id)
        if not connection:
            return False

        if room in self._rooms:
            self._rooms[room].discard(client_id)
            if not self._rooms[room]:
                del self._rooms[room]

        connection.subscriptions.discard(room)

        logger.debug(f"Client {client_id} unsubscribed from room {room}")
        return True

    async def send_to_client(self, client_id: str, message: WSMessage) -> bool:
        """
        Send a message to a specific client.

        Args:
            client_id: Target client identifier
            message: Message to send

        Returns:
            True if message sent successfully
        """
        connection = self._connections.get(client_id)
        if not connection:
            return False

        try:
            if connection.websocket.client_state == WebSocketState.CONNECTED:
                await connection.websocket.send_text(message.to_json())
                connection.update_activity()
                self._stats["total_messages_sent"] += 1
                return True
        except Exception as e:
            logger.error(f"Error sending to client {client_id}: {e}")
            self._stats["total_errors"] += 1
            await self.disconnect(client_id)

        return False

    async def broadcast_to_room(self, room: str, message: WSMessage):
        """
        Broadcast a message to all clients in a room.

        Args:
            room: Room name
            message: Message to broadcast
        """
        client_ids = self._rooms.get(room, set()).copy()

        for client_id in client_ids:
            await self.send_to_client(client_id, message)

    async def broadcast_all(self, message: WSMessage):
        """
        Broadcast a message to all connected clients.

        Args:
            message: Message to broadcast
        """
        for client_id in list(self._connections.keys()):
            await self.send_to_client(client_id, message)

    async def broadcast_stats(self, stats: dict):
        """
        Broadcast statistics update.

        Args:
            stats: Statistics data
        """
        message = WSMessage(
            type=MessageType.STATS,
            timestamp=datetime.utcnow().timestamp(),
            payload=stats,
        )

        await self.broadcast_to_room("stats", message)

    async def broadcast_attack(self, attack_data: dict):
        """
        Broadcast attack notification.

        Args:
            attack_data: Attack details
        """
        message = WSMessage(
            type=MessageType.ATTACK,
            timestamp=datetime.utcnow().timestamp(),
            payload=attack_data,
        )

        # Broadcast to attacks room
        await self.broadcast_to_room("attacks", message)

    async def broadcast_alert(
        self,
        alert_data: dict,
        severity: str = "info",
    ):
        """
        Broadcast system alert.

        Args:
            alert_data: Alert details
            severity: Alert severity (info, warning, error, critical)
        """
        message = WSMessage(
            type=MessageType.ALERT,
            timestamp=datetime.utcnow().timestamp(),
            payload={
                "severity": severity,
                **alert_data,
            },
        )

        await self.broadcast_to_room("alerts", message)

    async def receive_message(self, client_id: str) -> Optional[WSMessage]:
        """
        Receive a message from a client.

        Args:
            client_id: Client identifier

        Returns:
            Received message or None
        """
        connection = self._connections.get(client_id)
        if not connection:
            return None

        try:
            data = await connection.websocket.receive_text()
            connection.update_activity()
            self._stats["total_messages_received"] += 1

            message_data = json.loads(data)
            return WSMessage.from_dict(message_data)
        except WebSocketDisconnect:
            await self.disconnect(client_id)
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON from client {client_id}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error receiving from client {client_id}: {e}")
            await self.disconnect(client_id)
            return None

    def register_handler(self, message_type: MessageType, handler: Callable):
        """
        Register a message handler for a specific message type.

        Args:
            message_type: Type of message to handle
            handler: Async callable to handle the message
        """
        if message_type not in self._message_handlers:
            self._message_handlers[message_type] = []
        self._message_handlers[message_type].append(handler)

    async def handle_message(self, client_id: str, message: WSMessage):
        """
        Process a received message through registered handlers.

        Args:
            client_id: Client that sent the message
            message: Message to process
        """
        connection = self._connections.get(client_id)
        if not connection:
            return

        handlers = self._message_handlers.get(message.type, [])
        for handler in handlers:
            try:
                await handler(client_id, connection, message)
            except Exception as e:
                logger.error(f"Handler error for {message.type}: {e}")

    async def _heartbeat_loop(self):
        """Send periodic heartbeats to all connections."""
        while self._running:
            try:
                await asyncio.sleep(self._heartbeat_interval)

                ping_message = WSMessage(
                    type=MessageType.PING,
                    timestamp=datetime.utcnow().timestamp(),
                    payload={"server_time": datetime.utcnow().isoformat()},
                )

                for client_id in list(self._connections.keys()):
                    connection = self._connections.get(client_id)
                    if connection:
                        # Check for stale connections
                        idle_time = (datetime.utcnow() - connection.last_activity).total_seconds()
                        if idle_time > self._heartbeat_interval * 3:
                            logger.info(f"Disconnecting stale client {client_id}")
                            await self.disconnect(client_id)
                        else:
                            await self.send_to_client(client_id, ping_message)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

    def get_connection(self, client_id: str) -> Optional[Connection]:
        """Get a connection by client ID."""
        return self._connections.get(client_id)

    def get_room_clients(self, room: str) -> Set[str]:
        """Get all client IDs in a room."""
        return self._rooms.get(room, set()).copy()

    def get_stats(self) -> dict:
        """Get connection manager statistics."""
        return {
            **self._stats,
            "active_connections": len(self._connections),
            "active_rooms": len(self._rooms),
        }

    @property
    def connection_count(self) -> int:
        """Get total number of active connections."""
        return len(self._connections)

    @property
    def room_count(self) -> int:
        """Get total number of active rooms."""
        return len(self._rooms)


# Global connection manager instance
_connection_manager: Optional[ConnectionManager] = None


def get_connection_manager() -> ConnectionManager:
    """Get or create the global connection manager instance."""
    global _connection_manager
    if _connection_manager is None:
        _connection_manager = ConnectionManager()
    return _connection_manager


async def init_connection_manager():
    """Initialize and start the connection manager."""
    manager = get_connection_manager()
    await manager.start()
    return manager


async def shutdown_connection_manager():
    """Stop the connection manager."""
    global _connection_manager
    if _connection_manager:
        await _connection_manager.stop()
        _connection_manager = None
