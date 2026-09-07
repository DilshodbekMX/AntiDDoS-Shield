"""
Anti-DDoS Management API

FastAPI application providing comprehensive REST API for
configuration, statistics, and security operations.
"""

import logging
import os
import secrets
import time
from collections import defaultdict
from datetime import datetime
from contextlib import asynccontextmanager
from threading import Lock
from typing import Optional

from fastapi import FastAPI, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi

from . import __version__
from .routers import (
    config_router,
    stats_router,
    security_router,
    policies_router,
    reports_router,
    auth_router,
    realtime_router,
    rules_router,
    layer1_config_router,
    layer2_config_router,
    system_router,
    per_ip_l2_config_router,
    telemetry_router,
)
from .routers.layer3 import router as layer3_router
from .routers.org_settings import router as org_settings_router
from .routers.ws import router as ws_router, startup_websocket, shutdown_websocket
from .routers.metrics import router as metrics_router, metrics_middleware
from .services.dpdk_service import get_dpdk_service
from .services.telemetry_recorder import get_telemetry_recorder
from .services.telemetry_forwarder import init_forwarder, stop_forwarder
from sqlalchemy import text

from .database import init_db, close_db, get_db
from .cache import get_redis, CacheService
from .tasks import start_scheduler, stop_scheduler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting Anti-DDoS Management API v%s", __version__)

    # Initialize database (SQLite with SQLAlchemy)
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize database: %s", e)
        raise

    # Initialize Redis cache (optional - graceful degradation if unavailable)
    redis_client = get_redis()
    try:
        if redis_client and redis_client.ping():
            logger.info("Redis cache connected successfully")
            app.state.redis_available = True
        else:
            logger.warning("Redis cache unavailable - running without caching")
            app.state.redis_available = False
    except Exception:
        logger.warning("Redis cache unavailable - running without caching")
        app.state.redis_available = False
        redis_client = None

    # Initialize cache service
    app.state.cache_service = CacheService()

    # Initialize WebSocket manager
    await startup_websocket()
    logger.info("WebSocket manager started")

    # Initialize and start DPDK service (connects to DPDK datapath)
    dpdk_service = get_dpdk_service()
    dpdk_service.start()
    logger.info("DPDK service started - connecting to datapath")

    # Start telemetry recorder (per-IP feature + attack event persistence)
    telemetry = get_telemetry_recorder()
    telemetry.start()
    logger.info("Telemetry recorder started")

    # Start telemetry forwarder (remote stats export)
    forwarder = init_forwarder()
    logger.info("Telemetry forwarder started")

    # Start background task scheduler
    await start_scheduler()
    logger.info("Background task scheduler started")

    yield

    # Shutdown
    # Stop task scheduler
    await stop_scheduler()
    logger.info("Background task scheduler stopped")

    stop_forwarder()
    logger.info("Telemetry forwarder stopped")

    dpdk_service.stop()
    logger.info("DPDK service stopped")

    telemetry.stop()
    logger.info("Telemetry recorder stopped")

    # Shutdown WebSocket manager
    await shutdown_websocket()
    logger.info("WebSocket manager stopped")

    # Close Redis connection
    if redis_client:
        try:
            redis_client.close()
            logger.info("Redis connection closed")
        except Exception:
            pass

    # Close database connections
    close_db()
    logger.info("Database connections closed")

    logger.info("Anti-DDoS Management API shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="Anti-DDoS Management API",
    description="""
## Overview

Enterprise-grade REST API for managing Anti-DDoS protection.

## Features

- **Configuration**: Per-layer configuration for Layer 1 and Layer 2 protection
- **Statistics**: Real-time and historical traffic and security metrics
- **Security Operations**: Blacklist/whitelist management, attack handling
- **Policy Management**: Custom policies with flexible conditions
- **Reports**: Generate and schedule various report types

## Authentication

All endpoints require authentication via:
- **JWT Bearer Token**: `Authorization: Bearer <token>`
- **API Key**: `X-API-Key: <key>`

Use the `/auth/login` endpoint to obtain a JWT token or create API keys
via `/auth/keys`.

## Rate Limiting

API requests are rate-limited per user:
- Default: 60 requests/minute, 1000 requests/hour
- Rate limit headers are included in all responses

## Error Handling

All errors return a consistent JSON structure:
```json
{
  "success": false,
  "error": "Error message",
  "detail": "Additional details if available"
}
```
    """,
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
# SECURITY: Configure allowed origins from environment for production deployments.
# The default localhost origins are suitable for development only.
# In production, set CORS_ORIGINS environment variable to your dashboard domain(s).
# Example: CORS_ORIGINS=https://dashboard.example.com,https://admin.example.com
_cors_origins_env = os.environ.get('CORS_ORIGINS', '')
_cors_origins = [
    origin.strip() for origin in _cors_origins_env.split(',')
    if origin.strip()
] if _cors_origins_env else [
    # Development-only defaults
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:5005",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:5005",
    "http://127.0.0.1:5173",
]

_app_env = os.environ.get('APP_ENV', 'development').lower()
if not _cors_origins_env:
    if _app_env == 'production':
        logger.error(
            "FATAL: CORS_ORIGINS not set in production mode. "
            "Set CORS_ORIGINS environment variable to your dashboard domain(s). "
            "Example: CORS_ORIGINS=https://dashboard.example.com"
        )
        import sys
        sys.exit(1)
    else:
        logger.warning(
            "CORS_ORIGINS not set - using localhost defaults (APP_ENV=%s). "
            "Set CORS_ORIGINS environment variable for production.",
            _app_env,
        )

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"],
)


# ==================== Admin credential safety (production) ====================
# Fail closed if the shipped weak default admin password would be live in production,
# mirroring the CORS guard above. The 'REMOVED_DEV_DEFAULT' default is for local development only.
if _app_env == 'production':
    _admin_pass = os.environ.get('ANTIDDOS_ADMIN_PASS')
    _admin_hash = os.environ.get('ANTIDDOS_ADMIN_PASS_HASH')
    if not _admin_hash and (not _admin_pass or _admin_pass == 'REMOVED_DEV_DEFAULT'):
        logger.error(
            "FATAL: default or blank admin password in production mode. "
            "Set ANTIDDOS_ADMIN_PASS (or ANTIDDOS_ADMIN_PASS_HASH) to a strong secret; "
            "the development default 'REMOVED_DEV_DEFAULT' is refused when APP_ENV=production."
        )
        import sys
        sys.exit(1)


# ==================== CSRF Protection ====================
# Double-submit cookie pattern: for requests authenticated via httpOnly cookie,
# require a matching X-CSRF-Token header. The CSRF token is set as a readable
# (non-httpOnly) cookie on login, and the frontend must echo it back in the header.
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Paths exempt from CSRF (login issues the CSRF token, so it can't require one)
CSRF_EXEMPT_PATHS = {"/api/v2/auth/login", "/api/v2/auth/logout"}


@app.middleware("http")
async def csrf_protection(request: Request, call_next):
    """Enforce CSRF token for cookie-authenticated state-changing requests."""
    if request.method not in CSRF_SAFE_METHODS and request.url.path not in CSRF_EXEMPT_PATHS:
        # Only enforce CSRF if the request carries an auth cookie (not Bearer/API key)
        auth_cookie = request.cookies.get("access_token")
        auth_header = request.headers.get("authorization", "")
        api_key = request.headers.get("x-api-key", "")

        if auth_cookie and not auth_header and not api_key:
            csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME, "")
            csrf_header = request.headers.get(CSRF_HEADER_NAME, "")

            if not csrf_cookie or not csrf_header or not secrets.compare_digest(csrf_cookie, csrf_header):
                return JSONResponse(
                    status_code=403,
                    content={"success": False, "error": "CSRF token missing or invalid"}
                )

    return await call_next(request)


# Request size limits
MAX_REQUEST_SIZE = int(os.environ.get('MAX_REQUEST_SIZE', 10 * 1024 * 1024))  # 10MB default


# Request size limit middleware
@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """Enforce request size limits to prevent DoS attacks."""
    content_length = request.headers.get("content-length")

    if content_length:
        try:
            size = int(content_length)
            if size > MAX_REQUEST_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={
                        "success": False,
                        "error": "Request entity too large",
                        "detail": f"Maximum allowed size is {MAX_REQUEST_SIZE // (1024*1024)}MB"
                    }
                )
        except ValueError:
            pass

    return await call_next(request)


# ==================== Global IP-Based Rate Limiting ====================
# Catches ALL requests including unauthenticated ones.
# Per-user rate limiting (in auth.py) handles authenticated granularity.
# This middleware prevents IP-level flooding of public/unauthenticated endpoints.

GLOBAL_RATE_LIMIT_PER_SECOND = int(os.environ.get('GLOBAL_RATE_LIMIT_PER_SEC', 50))
GLOBAL_RATE_LIMIT_BURST = int(os.environ.get('GLOBAL_RATE_LIMIT_BURST', 100))
_RATE_EXEMPT_PATHS = {"/health", "/metrics", "/"}
# Localhost IPs are exempt -- the global limiter targets external flooding,
# not the co-located dashboard polling its own backend.
_RATE_EXEMPT_IPS = {"127.0.0.1", "::1"}


class _GlobalRateLimiter:
    """Token-bucket rate limiter keyed by client IP."""

    def __init__(self, rate: float, burst: int):
        self._rate = rate          # tokens per second
        self._burst = burst        # max tokens
        self._buckets: dict = {}   # ip -> (tokens, last_time)
        self._lock = Lock()
        self._last_cleanup = time.monotonic()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            # Periodic cleanup (every 60s)
            if now - self._last_cleanup > 60:
                cutoff = now - 120
                self._buckets = {
                    k: v for k, v in self._buckets.items() if v[1] > cutoff
                }
                self._last_cleanup = now

            tokens, last = self._buckets.get(ip, (self._burst, now))
            elapsed = now - last
            tokens = min(self._burst, tokens + elapsed * self._rate)
            if tokens >= 1.0:
                self._buckets[ip] = (tokens - 1.0, now)
                return True
            else:
                self._buckets[ip] = (tokens, now)
                return False


_global_limiter = _GlobalRateLimiter(
    rate=GLOBAL_RATE_LIMIT_PER_SECOND,
    burst=GLOBAL_RATE_LIMIT_BURST,
)


@app.middleware("http")
async def global_rate_limit(request: Request, call_next):
    """Global IP-based rate limiting for all endpoints."""
    path = request.url.path
    if path in _RATE_EXEMPT_PATHS:
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"

    if client_ip in _RATE_EXEMPT_IPS:
        return await call_next(request)

    if not _global_limiter.allow(client_ip):
        return JSONResponse(
            status_code=429,
            content={
                "success": False,
                "error": "Too many requests",
                "detail": "Global rate limit exceeded. Try again shortly.",
            },
            headers={"Retry-After": "1"},
        )

    return await call_next(request)


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)

    # Core security headers
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Prevent browser caching of authenticated API responses
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"

    # HSTS - enforce HTTPS (only in production)
    if not _DEBUG_MODE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Content Security Policy - restrictive default
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'"
    )

    # Permissions Policy - disable unnecessary features
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=()"
    )

    # Add rate limit headers if available
    if hasattr(request.state, "rate_limit_info"):
        info = request.state.rate_limit_info
        response.headers["X-RateLimit-Limit"] = str(info.get("limit", 60))
        response.headers["X-RateLimit-Remaining"] = str(info.get("remaining", 0))

    return response


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests."""
    start_time = datetime.utcnow()

    response = await call_next(request)

    duration = (datetime.utcnow() - start_time).total_seconds() * 1000
    logger.info(
        f"{request.method} {request.url.path} - {response.status_code} - {duration:.2f}ms"
    )

    return response


# Check if running in development mode
_DEBUG_MODE = os.environ.get('DEBUG', '').lower() in ('true', '1', 'yes')

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle uncaught exceptions."""
    # Generate a unique error ID for tracking
    error_id = secrets.token_hex(8)
    logger.exception(f"Unhandled exception [error_id={error_id}]: {exc}")

    # Include CORS headers in error responses (use centralized config)
    origin = request.headers.get("origin", "")
    headers = {}

    if origin in _cors_origins:
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"

    # SECURITY: Only expose exception details in debug mode
    # In production, expose only error_id for log correlation
    response_content = {
        "success": False,
        "error": "Internal server error",
        "error_id": error_id,  # Always include for log correlation
    }

    if _DEBUG_MODE:
        # Only include exception details in development
        response_content["detail"] = str(exc)
        response_content["type"] = type(exc).__name__

    return JSONResponse(
        status_code=500,
        content=response_content,
        headers=headers
    )


# Include routers
app.include_router(auth_router, prefix="/api/v2")
app.include_router(config_router, prefix="/api/v2")
app.include_router(stats_router, prefix="/api/v2")
app.include_router(security_router, prefix="/api/v2")
app.include_router(policies_router, prefix="/api/v2")
app.include_router(reports_router, prefix="/api/v2")

# Real-time data routers (from Flask app migration)
app.include_router(realtime_router, prefix="/api/v2")
app.include_router(rules_router, prefix="/api/v2")
app.include_router(layer1_config_router, prefix="/api/v2")

# WebSocket router for real-time streaming
app.include_router(ws_router, prefix="/api/v2")
app.include_router(layer2_config_router, prefix="/api/v2")
app.include_router(per_ip_l2_config_router, prefix="/api/v2")
app.include_router(telemetry_router, prefix="/api/v2")

# System router (hot reload, health, kill switch)
app.include_router(system_router, prefix="/api/v2")

# Layer 3 ML attribution router
app.include_router(layer3_router, prefix="/api/v2")

# Organization settings router
app.include_router(org_settings_router, prefix="/api/v2")

# Metrics router (no prefix - available at /metrics)
app.include_router(metrics_router)

# Add metrics middleware
app.middleware("http")(metrics_middleware)


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """API root endpoint."""
    return {
        "name": "Anti-DDoS Management API",
        "version": __version__,
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health",
    }


# Health check
@app.get("/health", tags=["Health"])
async def health_check(request: Request):
    """Health check endpoint with component status."""
    # Check Redis status
    redis_status = "unknown"
    try:
        redis_client = get_redis()
        redis_status = "healthy" if redis_client and redis_client.ping() else "unavailable"
    except Exception:
        redis_status = "error"

    # Check database status
    db_status = "unknown"
    try:
        db = next(get_db())
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception:
        db_status = "error"

    # Check DPDK service status
    dpdk_status = "unknown"
    try:
        dpdk_service = get_dpdk_service()
        dpdk_status = "healthy" if dpdk_service.is_connected() else "disconnected"
    except Exception:
        dpdk_status = "error"

    # Overall status
    overall_status = "healthy"
    if db_status != "healthy":
        overall_status = "degraded"
    if dpdk_status not in ("healthy", "disconnected"):
        overall_status = "degraded"

    return {
        "status": overall_status,
        "version": __version__,
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "database": db_status,
            "redis": redis_status,
            "dpdk": dpdk_status,
        },
    }


# API info
@app.get("/api/v2", tags=["Root"])
async def api_info():
    """API information endpoint."""
    return {
        "version": "2.0.0",
        "endpoints": {
            "auth": "/api/v2/auth",
            "config": "/api/v2/config",
            "stats": "/api/v2/stats",
            "security": "/api/v2/security",
            "policies": "/api/v2/policies",
            "reports": "/api/v2/reports",
            # Real-time DPDK data
            "realtime_stats": "/api/v2/realtime/stats",
            "realtime_traffic": "/api/v2/realtime/traffic",
            "realtime_anomaly": "/api/v2/realtime/anomaly",
            "realtime_sysmon": "/api/v2/realtime/sysmon",
            # Rules engine
            "rules_whitelist": "/api/v2/rules/whitelist",
            "rules_blacklist": "/api/v2/rules/blacklist",
            "rules_protected": "/api/v2/rules/protected",
            # Layer configuration
            "layer1_config": "/api/v2/layer1/config",
            "layer1_stages": "/api/v2/layer1/stages",
            "layer1_geo": "/api/v2/layer1/geo",
            "layer1_signatures": "/api/v2/layer1/signatures",
            "layer1_protocols": "/api/v2/layer1/protocols",
            "layer2_config": "/api/v2/layer2/config",
            "layer2_adaptive": "/api/v2/layer2/adaptive",
            # Layer 3 ML attribution
            "layer3_summary": "/api/v2/layer3/summary",
            "layer3_signatures": "/api/v2/layer3/signatures",
            "layer3_attackers": "/api/v2/layer3/attackers",
            # WebSocket endpoints
            "ws_stats": "ws://host/api/v2/ws/stats",
            "ws_attacks": "ws://host/api/v2/ws/attacks",
            "ws_traffic": "ws://host/api/v2/ws/traffic",
            "ws_alerts": "ws://host/api/v2/ws/alerts",
            "ws_all": "ws://host/api/v2/ws/all",
        },
    }


# Custom OpenAPI schema
def custom_openapi():
    """Generate custom OpenAPI schema."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Anti-DDoS Management API",
        version=__version__,
        description=app.description,
        routes=app.routes,
    )

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        },
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
        },
    }

    # Apply security globally
    openapi_schema["security"] = [
        {"BearerAuth": []},
        {"ApiKeyAuth": []},
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Run with uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
