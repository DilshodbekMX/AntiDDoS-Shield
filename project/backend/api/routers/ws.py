"""
WebSocket router for real-time data streaming.

Provides WebSocket endpoints for:
- Real-time port statistics
- Attack notifications
- Traffic samples
- System alerts

All WebSocket endpoints require authentication.
"""

import logging
import os
import uuid
from typing import Optional, Tuple

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends, HTTPException, status
from fastapi.security import HTTPBearer

from ..websocket import (
    get_connection_manager,
    ConnectionManager,
)
from ..websocket.handlers import (
    register_default_handlers,
    process_client_messages,
)
from ..websocket.manager import (
    WSMessage,
    MessageType,
    init_connection_manager,
    shutdown_connection_manager,
)
from ..auth import verify_token_optional, verify_api_key_optional, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ws", tags=["WebSocket"])

security = HTTPBearer(auto_error=False)

# WebSocket close codes
WS_CLOSE_AUTH_REQUIRED = 4001
WS_CLOSE_AUTH_FAILED = 4002
WS_CLOSE_ACCESS_DENIED = 4003
WS_CLOSE_RATE_LIMITED = 4029


async def authenticate_websocket(
    websocket: WebSocket,
    token: Optional[str] = None,
    api_key: Optional[str] = None,
    require_auth: bool = True,
) -> Tuple[Optional[str], bool]:
    """
    Authenticate WebSocket connection.

    Supports authentication via:
    - Query parameter token
    - Query parameter api_key
    - Sec-WebSocket-Protocol header (for browsers)

    Args:
        websocket: WebSocket connection
        token: JWT token from query parameter
        api_key: API key from query parameter
        require_auth: If True, authentication is mandatory

    Returns:
        Tuple of (user_id, authenticated)
        If require_auth=True and auth fails, returns (None, False)
    """
    user_id = None
    authenticated = False

    # Try token authentication
    if token:
        try:
            payload = verify_token_optional(token)
            if payload:
                user_id = payload.get("user_id")
                authenticated = True
        except Exception as e:
            logger.debug(f"WebSocket token auth failed: {e}")

    # Try API key authentication
    if not authenticated and api_key:
        try:
            result = verify_api_key_optional(api_key)
            if result:
                user_id = None
                authenticated = True
        except Exception as e:
            logger.debug(f"WebSocket API key auth failed: {e}")

    # Try Sec-WebSocket-Protocol header (useful for browser clients)
    if not authenticated:
        protocol = websocket.headers.get("sec-websocket-protocol", "")
        if protocol.startswith("auth_"):
            auth_token = protocol.replace("auth_", "")
            try:
                payload = verify_token_optional(auth_token)
                if payload:
                    user_id = payload.get("user_id")
                    authenticated = True
            except Exception as e:
                logger.debug(f"WebSocket protocol auth failed: {e}")

    return user_id, authenticated


async def require_websocket_auth(
    websocket: WebSocket,
    token: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Optional[str]:
    """
    Require authentication for WebSocket connection.

    Closes connection with appropriate error if auth fails.

    Returns:
        user_id

    Raises:
        Closes WebSocket connection if auth fails
    """
    user_id, authenticated = await authenticate_websocket(
        websocket, token, api_key, require_auth=True
    )

    if not authenticated:
        client_host = websocket.client.host if websocket.client else "unknown"
        if os.environ.get('APP_ENV', '').lower() == 'production':
            logger.warning(
                "WebSocket auth rejected in production from %s (path=%s)",
                client_host, websocket.url.path,
            )
        else:
            logger.debug("WebSocket auth rejected from %s", client_host)
        await websocket.accept()
        await websocket.close(code=WS_CLOSE_AUTH_REQUIRED, reason="Authentication required")
        raise WebSocketDisconnect(code=WS_CLOSE_AUTH_REQUIRED)

    return user_id


@router.websocket("/stats")
async def websocket_stats(
    websocket: WebSocket,
    token: Optional[str] = Query(None, description="JWT token"),
    api_key: Optional[str] = Query(None, alias="api_key", description="API key"),
):
    """
    WebSocket endpoint for real-time statistics.

    Broadcasts port statistics at 1 Hz rate.

    Authentication:
    - Pass `token` query parameter with JWT
    - Pass `api_key` query parameter with API key
    - Or use Sec-WebSocket-Protocol header with `auth_<token>`

    Messages sent:
    - `stats`: Port statistics updates
    - `ping`: Periodic heartbeat

    Messages accepted:
    - `subscribe`: Subscribe to topics
    - `unsubscribe`: Unsubscribe from topics
    - `pong`: Heartbeat response
    """
    manager = get_connection_manager()
    client_id = str(uuid.uuid4())

    # Require authentication
    try:
        user_id = await require_websocket_auth(websocket, token, api_key)
    except WebSocketDisconnect:
        return

    try:
        # Connect
        connection = await manager.connect(
            websocket=websocket,
            client_id=client_id,
            user_id=user_id,
        )

        # Auto-subscribe to stats
        await manager.subscribe(client_id, "stats")

        logger.info(f"WebSocket stats connected: {client_id}")

        # Process messages until disconnect
        await process_client_messages(client_id)

    except WebSocketDisconnect:
        logger.info(f"WebSocket stats disconnected: {client_id}")
    except Exception as e:
        logger.error(f"WebSocket stats error for {client_id}: {e}")
    finally:
        await manager.disconnect(client_id)


@router.websocket("/attacks")
async def websocket_attacks(
    websocket: WebSocket,
    token: Optional[str] = Query(None, description="JWT token"),
    api_key: Optional[str] = Query(None, alias="api_key", description="API key"),
):
    """
    WebSocket endpoint for attack notifications.

    Receives real-time notifications when attacks are detected,
    mitigated, or ended.

    Messages sent:
    - `attack`: Attack notification with details
    - `ping`: Periodic heartbeat
    """
    manager = get_connection_manager()
    client_id = str(uuid.uuid4())

    # Require authentication
    try:
        user_id = await require_websocket_auth(websocket, token, api_key)
    except WebSocketDisconnect:
        return

    try:
        # Connect
        connection = await manager.connect(
            websocket=websocket,
            client_id=client_id,
            user_id=user_id,
        )

        # Auto-subscribe to attacks
        await manager.subscribe(client_id, "attacks")

        logger.info(f"WebSocket attacks connected: {client_id}")

        # Process messages until disconnect
        await process_client_messages(client_id)

    except WebSocketDisconnect:
        logger.info(f"WebSocket attacks disconnected: {client_id}")
    except Exception as e:
        logger.error(f"WebSocket attacks error for {client_id}: {e}")
    finally:
        await manager.disconnect(client_id)


@router.websocket("/traffic")
async def websocket_traffic(
    websocket: WebSocket,
    token: Optional[str] = Query(None, description="JWT token"),
    api_key: Optional[str] = Query(None, alias="api_key", description="API key"),
):
    """
    WebSocket endpoint for traffic samples.

    Receives periodic traffic samples including:
    - Protocol distribution
    - Top source/destination IPs
    - Port distribution
    - Geographic distribution

    Messages sent:
    - `traffic`: Traffic sample data
    - `ping`: Periodic heartbeat
    """
    manager = get_connection_manager()
    client_id = str(uuid.uuid4())

    # Require authentication
    try:
        user_id = await require_websocket_auth(websocket, token, api_key)
    except WebSocketDisconnect:
        return

    try:
        # Connect
        connection = await manager.connect(
            websocket=websocket,
            client_id=client_id,
            user_id=user_id,
        )

        # Auto-subscribe to traffic
        await manager.subscribe(client_id, "traffic")

        logger.info(f"WebSocket traffic connected: {client_id}")

        # Process messages until disconnect
        await process_client_messages(client_id)

    except WebSocketDisconnect:
        logger.info(f"WebSocket traffic disconnected: {client_id}")
    except Exception as e:
        logger.error(f"WebSocket traffic error for {client_id}: {e}")
    finally:
        await manager.disconnect(client_id)


@router.websocket("/alerts")
async def websocket_alerts(
    websocket: WebSocket,
    token: Optional[str] = Query(None, description="JWT token"),
    api_key: Optional[str] = Query(None, alias="api_key", description="API key"),
):
    """
    WebSocket endpoint for system alerts.

    Receives real-time alerts including:
    - Threshold exceeded alerts
    - Security alerts
    - System status changes
    - Configuration changes

    Messages sent:
    - `alert`: Alert notification with severity and details
    - `ping`: Periodic heartbeat
    """
    manager = get_connection_manager()
    client_id = str(uuid.uuid4())

    # Require authentication
    try:
        user_id = await require_websocket_auth(websocket, token, api_key)
    except WebSocketDisconnect:
        return

    try:
        # Connect
        connection = await manager.connect(
            websocket=websocket,
            client_id=client_id,
            user_id=user_id,
        )

        # Auto-subscribe to alerts
        await manager.subscribe(client_id, "alerts")

        logger.info(f"WebSocket alerts connected: {client_id}")

        # Process messages until disconnect
        await process_client_messages(client_id)

    except WebSocketDisconnect:
        logger.info(f"WebSocket alerts disconnected: {client_id}")
    except Exception as e:
        logger.error(f"WebSocket alerts error for {client_id}: {e}")
    finally:
        await manager.disconnect(client_id)


@router.websocket("/all")
async def websocket_all(
    websocket: WebSocket,
    token: Optional[str] = Query(None, description="JWT token"),
    api_key: Optional[str] = Query(None, alias="api_key", description="API key"),
):
    """
    WebSocket endpoint for all data streams.

    Subscribes to all available topics:
    - stats
    - attacks
    - traffic
    - alerts

    Use this for dashboard connections that need all data.
    """
    manager = get_connection_manager()
    client_id = str(uuid.uuid4())

    # Require authentication
    try:
        user_id = await require_websocket_auth(websocket, token, api_key)
    except WebSocketDisconnect:
        return

    try:
        # Connect
        connection = await manager.connect(
            websocket=websocket,
            client_id=client_id,
            user_id=user_id,
        )

        # Auto-subscribe to all topics
        topics = ["stats", "attacks", "traffic", "alerts"]
        for topic in topics:
            await manager.subscribe(client_id, topic)

        logger.info(f"WebSocket all connected: {client_id}")

        # Process messages until disconnect
        await process_client_messages(client_id)

    except WebSocketDisconnect:
        logger.info(f"WebSocket all disconnected: {client_id}")
    except Exception as e:
        logger.error(f"WebSocket all error for {client_id}: {e}")
    finally:
        await manager.disconnect(client_id)


# REST endpoints for WebSocket management (admin only)

@router.get("/connections")
async def get_connections(current_user: dict = Depends(get_current_user)):
    """
    Get WebSocket connection statistics.

    Returns connection counts and room information.
    Requires admin authentication.
    """
    manager = get_connection_manager()
    return {
        "success": True,
        "stats": manager.get_stats(),
    }


# Startup and shutdown hooks

async def startup_websocket():
    """Initialize WebSocket manager on startup."""
    manager = await init_connection_manager()
    register_default_handlers(manager)
    logger.info("WebSocket manager initialized")


async def shutdown_websocket():
    """Shutdown WebSocket manager."""
    await shutdown_connection_manager()
    logger.info("WebSocket manager shutdown")
