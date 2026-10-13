"""
Authentication and Authorization Module

Provides:
- JWT-based authentication
- API key authentication
- Role-based access control
- Rate limiting
"""

import os
import uuid
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple
from threading import Lock

import jwt
from fastapi import HTTPException, Security, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from pydantic import BaseModel

logger = logging.getLogger(__name__)


# ==================== Configuration ====================

# Path for persisting JWT secret key
_JWT_SECRET_FILE = os.environ.get('JWT_SECRET_FILE', '/var/lib/antiddos/.jwt_secret')

def _get_or_create_jwt_secret() -> str:
    """
    Get JWT secret from environment, file, or generate and persist a new one.

    SECURITY: The JWT secret must be persistent across restarts to prevent
    invalidating all existing tokens. Order of precedence:
    1. JWT_SECRET_KEY environment variable (for container/orchestration deployments)
    2. Persisted secret file (for standalone deployments)
    3. Generate new secret and persist to file (first run only)
    """
    # First, check environment variable (highest priority)
    env_secret = os.environ.get('JWT_SECRET_KEY')
    if env_secret:
        if len(env_secret) < 32:
            logger.warning("JWT_SECRET_KEY is less than 32 characters - consider using a longer key")
        return env_secret

    # Second, try to read from persisted file
    try:
        if os.path.exists(_JWT_SECRET_FILE):
            with open(_JWT_SECRET_FILE, 'r') as f:
                secret = f.read().strip()
                if secret and len(secret) >= 32:
                    return secret
                logger.warning("Persisted JWT secret is invalid, generating new one")
    except (IOError, OSError) as e:
        logger.warning(f"Could not read JWT secret file: {e}")

    # Third, generate new secret and try to persist it
    new_secret = secrets.token_urlsafe(64)  # 64 bytes = 512 bits

    try:
        # Ensure directory exists
        secret_dir = os.path.dirname(_JWT_SECRET_FILE)
        if secret_dir and not os.path.exists(secret_dir):
            os.makedirs(secret_dir, mode=0o700, exist_ok=True)

        # Write secret with restricted permissions
        with open(_JWT_SECRET_FILE, 'w') as f:
            f.write(new_secret)
        os.chmod(_JWT_SECRET_FILE, 0o600)  # Owner read/write only
        logger.info(f"Generated and persisted new JWT secret to {_JWT_SECRET_FILE}")
    except (IOError, OSError) as e:
        # SECURITY WARNING: If we can't persist, tokens will be invalidated on restart
        logger.warning(
            f"Could not persist JWT secret to {_JWT_SECRET_FILE}: {e}. "
            "Tokens will be invalidated on restart. Set JWT_SECRET_KEY env var for production."
        )

    return new_secret


class AuthConfig:
    """Authentication configuration."""
    # JWT settings - use persistent secret
    JWT_SECRET_KEY = _get_or_create_jwt_secret()
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRY_HOURS = 24
    JWT_REFRESH_EXPIRY_DAYS = 7

    # API key settings
    API_KEY_LENGTH = 64
    API_KEY_PREFIX = "adx_"  # Anti-DDoS X prefix

    # API key hashing - use unique salt per key
    API_KEY_HASH_ITERATIONS = 100000

    # Rate limiting -- dashboard polls ~10 endpoints every 2s + per-IP stats + page loads
    DEFAULT_RATE_LIMIT_PER_MINUTE = 600
    DEFAULT_RATE_LIMIT_PER_HOUR = 15000
    RATE_LIMIT_BURST = 300

    # Password requirements
    MIN_PASSWORD_LENGTH = 12
    PASSWORD_HASH_ITERATIONS = 100000


# ==================== Security Schemes ====================

bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ==================== JWT Token Management ====================

class JWTManager:
    """JWT token creation and validation."""

    def __init__(self, secret_key: str = None, algorithm: str = None):
        self.secret_key = secret_key or AuthConfig.JWT_SECRET_KEY
        self.algorithm = algorithm or AuthConfig.JWT_ALGORITHM

    def create_access_token(
        self,
        user_id: str,
        permissions: List[str] = None,
        expires_delta: timedelta = None
    ) -> str:
        """Create a JWT access token."""
        if expires_delta is None:
            expires_delta = timedelta(hours=AuthConfig.JWT_EXPIRY_HOURS)

        expire = datetime.utcnow() + expires_delta

        payload = {
            "sub": user_id,
            "jti": str(uuid.uuid4()),
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access",
            "permissions": permissions or ["read"],
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(self, user_id: str) -> str:
        """Create a JWT refresh token."""
        expire = datetime.utcnow() + timedelta(days=AuthConfig.JWT_REFRESH_EXPIRY_DAYS)

        payload = {
            "sub": user_id,
            "jti": str(uuid.uuid4()),
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh",
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode_token(self, token: str) -> Dict:
        """Decode and validate a JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")

    def verify_access_token(self, token: str) -> Dict:
        """Verify an access token and return payload."""
        payload = self.decode_token(token)

        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")

        # Check token blacklist
        try:
            from .routers.auth import get_token_blacklist
            token_jti = payload.get("jti") or payload.get("sub", "") + str(payload.get("iat", ""))
            if get_token_blacklist().is_blacklisted(token_jti):
                raise HTTPException(status_code=401, detail="Token has been revoked")
        except ImportError:
            pass  # Blacklist module not available

        return payload


# Global JWT manager instance
_jwt_manager = None

def get_jwt_manager() -> JWTManager:
    """Get or create the global JWT manager."""
    global _jwt_manager
    if _jwt_manager is None:
        _jwt_manager = JWTManager()
    return _jwt_manager


# ==================== API Key Management ====================

class APIKeyStore:
    """
    API key storage and validation with database persistence.

    Keys are stored in the database using SQLAlchemy ORM.
    The admin API key from ANTIDDOS_ADMIN_API_KEY environment variable
    is initialized on startup if not already present.
    """

    def __init__(self):
        self._lock = Lock()
        self._db_initialized = False
        # Memory cache for env-based admin key (doesn't need DB)
        self._env_admin_key: Optional[Dict] = None

        # Load admin key from environment
        self._init_env_admin_key()

    def _init_env_admin_key(self):
        """Initialize admin API key from environment variable."""
        admin_key = os.environ.get('ANTIDDOS_ADMIN_API_KEY')
        if admin_key:
            # Store in memory for fast lookup (env keys don't go to DB)
            key_hash = hashlib.sha256(admin_key.encode()).hexdigest()
            self._env_admin_key = {
                "hash": key_hash,
                "name": "admin",
                "permissions": ["*"],
                "created": datetime.utcnow(),
                "expires": None,
                "last_used": None,
            }

    def _get_db(self):
        """Get database session."""
        try:
            if not self._db_initialized:
                from .database import init_db
                init_db()
                self._db_initialized = True
            from .database import get_db
            return next(get_db())
        except Exception as e:
            logger.warning(f"Database not available for API keys: {e}")
            return None

    def _get_repo(self):
        """Get token repository."""
        db = self._get_db()
        if db:
            from .database.repositories.token_repo import APITokenRepository
            return APITokenRepository(db)
        return None

    def generate_key(self) -> str:
        """Generate a new API key."""
        return AuthConfig.API_KEY_PREFIX + secrets.token_urlsafe(AuthConfig.API_KEY_LENGTH)

    def create_key(
        self,
        name: str,
        key: str = None,
        permissions: List[str] = None,
        expires_in_hours: int = None
    ) -> str:
        """Create a new API key."""
        expires = None
        if expires_in_hours:
            expires = datetime.utcnow() + timedelta(hours=expires_in_hours)

        repo = self._get_repo()
        if repo:
            # Use database storage
            api_token, plain_key = repo.create_token(
                name=name,
                permissions=permissions or ["read"],
                expires_at=expires,
                created_by="system"
            )
            return plain_key
        else:
            # Fallback: return generated key (not persisted)
            if key is None:
                key = self.generate_key()
            logger.warning("API key created but not persisted (database unavailable)")
            return key

    def validate_key(self, key: str) -> Tuple[bool, Optional[Dict]]:
        """Validate an API key."""
        if not key.startswith(AuthConfig.API_KEY_PREFIX):
            return False, None

        # First check env-based admin key (constant-time comparison)
        if self._env_admin_key:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            if secrets.compare_digest(key_hash, self._env_admin_key["hash"]):
                self._env_admin_key["last_used"] = datetime.utcnow()
                return True, self._env_admin_key

        # Then check database
        repo = self._get_repo()
        if repo:
            api_token = repo.verify_token(key)
            if api_token:
                # Record usage (non-critical - failure shouldn't block auth)
                try:
                    repo.record_usage(api_token.id)
                except (ConnectionError, OSError) as e:
                    logger.debug(f"Failed to record API key usage: {e}")
                except Exception as e:
                    logger.debug(f"Failed to record API key usage: {type(e).__name__}: {e}")

                return True, {
                    "id": api_token.id,
                    "name": api_token.name,
                    "permissions": api_token.permissions or ["read"],
                    "created": api_token.created_at,
                    "expires": api_token.expires_at,
                    "last_used": api_token.last_used_at,
                }

        return False, None

    def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key by its ID."""
        repo = self._get_repo()
        if repo:
            result = repo.revoke_token(key_id)
            return result is not None
        return False

    def list_keys(self) -> List[Dict]:
        """List all API keys (without exposing sensitive data)."""
        keys = []

        # Include env admin key
        if self._env_admin_key:
            keys.append({
                "id": "env_admin",
                "name": self._env_admin_key["name"],
                "permissions": self._env_admin_key["permissions"],
                "created": self._env_admin_key["created"],
                "expires": self._env_admin_key["expires"],
                "last_used": self._env_admin_key["last_used"],
                "source": "environment",
            })

        # Get database keys
        repo = self._get_repo()
        if repo:
            api_tokens = repo.list_tokens()
            for token in api_tokens:
                keys.append({
                    "id": token.id,
                    "name": token.name,
                    "permissions": token.permissions or ["read"],
                    "created": token.created_at,
                    "expires": token.expires_at,
                    "last_used": token.last_used_at,
                    "prefix": token.token_prefix,
                    "source": "database",
                })

        return keys

    def has_permission(self, key_info: Dict, permission: str) -> bool:
        """Check if key has required permission."""
        permissions = key_info.get("permissions", [])
        return "*" in permissions or permission in permissions


# Global API key store
_api_key_store = None

def get_api_key_store() -> APIKeyStore:
    """Get or create the global API key store."""
    global _api_key_store
    if _api_key_store is None:
        _api_key_store = APIKeyStore()
    return _api_key_store


# ==================== Optional Token/Key Verification ====================

def verify_token_optional(token: str) -> Optional[Dict]:
    """
    Verify a JWT token without raising exceptions.

    Returns the payload dict if valid, None otherwise.
    Used for WebSocket authentication where we don't want exceptions.
    """
    if not token:
        return None
    try:
        jwt_manager = get_jwt_manager()
        payload = jwt_manager.decode_token(token)
        if payload.get("type") != "access":
            return None
        return payload
    except jwt.ExpiredSignatureError:
        logger.debug("Token verification failed: token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.debug(f"Token verification failed: invalid token - {e}")
        return None
    except HTTPException:
        # Raised by decode_token for auth errors
        return None


def verify_api_key_optional(api_key: str) -> Optional[Dict]:
    """
    Verify an API key without raising exceptions.

    Returns key info dict if valid, None otherwise.
    Used for WebSocket authentication where we don't want exceptions.
    """
    if not api_key:
        return None
    try:
        api_key_store = get_api_key_store()
        valid, key_info = api_key_store.validate_key(api_key)
        if valid and key_info:
            return {
                "permissions": key_info.get("permissions", []),
                "name": key_info.get("name"),
            }
        return None
    except ValueError as e:
        logger.debug(f"API key verification failed: {e}")
        return None
    except (ConnectionError, OSError) as e:
        # Database connection issues
        logger.warning(f"API key verification failed due to database error: {e}")
        return None


# ==================== Rate Limiter ====================

class RateLimiter:
    """Rate limiter for API requests."""

    def __init__(self):
        self._buckets: Dict[str, Dict] = {}
        self._lock = Lock()
        self._cleanup_interval = 300
        self._last_cleanup = datetime.utcnow()

    def check(
        self,
        key: str,
        limit_per_minute: int = None,
        limit_per_hour: int = None
    ) -> Tuple[bool, Dict]:
        """
        Check if request is within rate limits.

        Returns:
            (allowed, rate_info)
        """
        if limit_per_minute is None:
            limit_per_minute = AuthConfig.DEFAULT_RATE_LIMIT_PER_MINUTE
        if limit_per_hour is None:
            limit_per_hour = AuthConfig.DEFAULT_RATE_LIMIT_PER_HOUR

        now = datetime.utcnow()

        with self._lock:
            # Cleanup old buckets periodically
            if (now - self._last_cleanup).total_seconds() > self._cleanup_interval:
                self._cleanup()

            # Get or create bucket
            if key not in self._buckets:
                self._buckets[key] = {
                    "tokens": AuthConfig.RATE_LIMIT_BURST,
                    "last_update": now,
                    "minute_start": now,
                    "minute_count": 0,
                    "hour_start": now,
                    "hour_count": 0,
                }

            bucket = self._buckets[key]

            # Refill tokens
            elapsed = (now - bucket["last_update"]).total_seconds()
            refill_rate = limit_per_minute / 60.0
            bucket["tokens"] = min(
                AuthConfig.RATE_LIMIT_BURST,
                bucket["tokens"] + elapsed * refill_rate
            )
            bucket["last_update"] = now

            # Reset minute counter
            if (now - bucket["minute_start"]).total_seconds() > 60:
                bucket["minute_start"] = now
                bucket["minute_count"] = 0

            # Reset hour counter
            if (now - bucket["hour_start"]).total_seconds() > 3600:
                bucket["hour_start"] = now
                bucket["hour_count"] = 0

            # Check limits
            rate_info = {
                "limit": limit_per_minute,
                "remaining": int(bucket["tokens"]),
                "reset": int((bucket["minute_start"] + timedelta(seconds=60) - now).total_seconds()),
            }

            if bucket["tokens"] < 1:
                rate_info["retry_after"] = int(1 / refill_rate)
                return False, rate_info

            if bucket["minute_count"] >= limit_per_minute:
                rate_info["retry_after"] = int((bucket["minute_start"] + timedelta(seconds=60) - now).total_seconds())
                rate_info["remaining"] = 0
                return False, rate_info

            if bucket["hour_count"] >= limit_per_hour:
                rate_info["retry_after"] = int((bucket["hour_start"] + timedelta(hours=1) - now).total_seconds())
                rate_info["remaining"] = 0
                return False, rate_info

            # Consume token
            bucket["tokens"] -= 1
            bucket["minute_count"] += 1
            bucket["hour_count"] += 1
            rate_info["remaining"] = int(bucket["tokens"])

            return True, rate_info

    def _cleanup(self):
        """Remove stale buckets (safe for concurrent access)."""
        now = datetime.utcnow()
        stale = [
            k for k, v in list(self._buckets.items())
            if (now - v["last_update"]).total_seconds() > 3600
        ]
        for k in stale:
            self._buckets.pop(k, None)
        self._last_cleanup = now


# Global rate limiter
_rate_limiter = None

def get_rate_limiter() -> RateLimiter:
    """Get or create the global rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


# ==================== User Context ====================

class UserContext(BaseModel):
    """Authenticated user context."""
    user_id: str
    permissions: List[str] = []
    is_admin: bool = False
    auth_type: str = "jwt"  # jwt or api_key


# ==================== Cookie Configuration ====================

# Cookie name must match the one in routers/auth.py
AUTH_COOKIE_NAME = "access_token"


# ==================== Authentication Dependencies ====================

async def get_current_user(
    request: Request,
    bearer_token: HTTPAuthorizationCredentials = Security(bearer_scheme),
    api_key: str = Security(api_key_header),
) -> UserContext:
    """
    Extract and validate user from request.

    Supports JWT Bearer tokens, API keys, and httpOnly cookies.
    Authentication is checked in order: API key, Bearer token, Cookie.
    """
    # Try API key first (highest priority for programmatic access)
    if api_key:
        valid, key_info = get_api_key_store().validate_key(api_key)
        if valid:
            return UserContext(
                user_id=f"apikey:{key_info['name']}",
                permissions=key_info.get("permissions", []),
                is_admin="*" in key_info.get("permissions", []),
                auth_type="api_key",
            )

    # Try JWT Bearer token from Authorization header
    if bearer_token:
        try:
            payload = get_jwt_manager().verify_access_token(bearer_token.credentials)
            return UserContext(
                user_id=payload["sub"],
                permissions=payload.get("permissions", []),
                is_admin="*" in payload.get("permissions", []),
                auth_type="jwt",
            )
        except HTTPException:
            pass

    # Try JWT from httpOnly cookie (browser-based sessions)
    cookie_token = request.cookies.get(AUTH_COOKIE_NAME)
    if cookie_token:
        try:
            payload = get_jwt_manager().verify_access_token(cookie_token)
            return UserContext(
                user_id=payload["sub"],
                permissions=payload.get("permissions", []),
                is_admin="*" in payload.get("permissions", []),
                auth_type="cookie",
            )
        except HTTPException:
            pass

    # No valid authentication
    raise HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_optional_user(
    request: Request,
    bearer_token: HTTPAuthorizationCredentials = Security(bearer_scheme),
    api_key: str = Security(api_key_header),
) -> Optional[UserContext]:
    """Get current user if authenticated, None otherwise."""
    try:
        return await get_current_user(request, bearer_token, api_key)
    except HTTPException:
        return None


def require_permission(permission: str):
    """Dependency that requires a specific permission."""
    async def check_permission(user: UserContext = Depends(get_current_user)):
        if user.is_admin:
            return user

        if permission not in user.permissions and "*" not in user.permissions:
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: requires '{permission}'"
            )
        return user

    return check_permission


def require_admin():
    """Dependency that requires admin access."""
    async def check_admin(user: UserContext = Depends(get_current_user)):
        if not user.is_admin:
            raise HTTPException(
                status_code=403,
                detail="Admin access required"
            )
        return user

    return check_admin


# ==================== Rate Limiting Middleware ====================

async def check_rate_limit(
    request: Request,
    user: UserContext = Depends(get_current_user),
) -> UserContext:
    """Check rate limits for authenticated requests."""
    key = f"user:{user.user_id}"

    limit_per_minute = AuthConfig.DEFAULT_RATE_LIMIT_PER_MINUTE
    limit_per_hour = AuthConfig.DEFAULT_RATE_LIMIT_PER_HOUR

    allowed, rate_info = get_rate_limiter().check(key, limit_per_minute, limit_per_hour)

    # Add rate limit headers to response
    request.state.rate_limit_info = rate_info

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={
                "Retry-After": str(rate_info.get("retry_after", 60)),
                "X-RateLimit-Limit": str(rate_info["limit"]),
                "X-RateLimit-Remaining": "0",
            }
        )

    return user


# ==================== Audit Logging ====================

class AuditLogger:
    """Audit logger for security events."""

    def __init__(self):
        self.logger = logging.getLogger("audit")

    def log_auth_success(self, user: UserContext, request: Request):
        """Log successful authentication."""
        self.logger.info(
            f"AUTH_SUCCESS | user={user.user_id} | "
            f"ip={request.client.host} | method={request.method} | path={request.url.path}"
        )

    def log_auth_failure(self, reason: str, request: Request):
        """Log failed authentication."""
        self.logger.warning(
            f"AUTH_FAILURE | reason={reason} | ip={request.client.host} | "
            f"method={request.method} | path={request.url.path}"
        )

    def log_permission_denied(self, user: UserContext, permission: str, request: Request):
        """Log permission denied."""
        self.logger.warning(
            f"PERMISSION_DENIED | user={user.user_id} | "
            f"required={permission} | ip={request.client.host} | path={request.url.path}"
        )

    def log_config_change(self, user: UserContext, section: str, request: Request):
        """Log configuration change."""
        self.logger.info(
            f"CONFIG_CHANGE | user={user.user_id} | "
            f"section={section} | ip={request.client.host}"
        )

    def log_api_action(self, user: UserContext, action: str, target: str, request: Request):
        """Log API action."""
        self.logger.info(
            f"API_ACTION | user={user.user_id} | "
            f"action={action} | target={target} | ip={request.client.host}"
        )


# Global audit logger
_audit_logger = None

def get_audit_logger() -> AuditLogger:
    """Get or create the global audit logger."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
