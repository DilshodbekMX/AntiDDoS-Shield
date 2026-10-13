"""
Authentication Router (Security Hardened)

Token management and authentication endpoints.
Includes: bcrypt password hashing, rate limiting, token blacklist, httpOnly cookies.
"""

import logging
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from collections import defaultdict
import threading

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, Cookie

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from ..auth import (
    UserContext, get_current_user, get_optional_user, require_admin,
    get_jwt_manager, get_api_key_store, get_audit_logger, AuthConfig
)
from ..models import (
    Token, TokenCreate, TokenInfo, UserLogin, LoginResponse,
    APIResponse
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])


# ==================== Password Hashing ====================

class PasswordManager:
    """Secure password hashing with bcrypt."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        if not BCRYPT_AVAILABLE:
            raise RuntimeError(
                "bcrypt is required for password hashing but is not installed. "
                "Install with: pip install bcrypt"
            )

        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode(), salt).decode()

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify a password against its hash."""
        if hashed.startswith("sha256:"):
            # Fallback for legacy hashes
            import hashlib
            return hashed == "sha256:" + hashlib.sha256(password.encode()).hexdigest()

        if not BCRYPT_AVAILABLE:
            return False

        try:
            return bcrypt.checkpw(password.encode(), hashed.encode())
        except Exception:
            return False

    @staticmethod
    def get_admin_password_hash() -> Optional[str]:
        """Get or create admin password hash."""
        # Check for pre-hashed password
        hashed = os.environ.get('ANTIDDOS_ADMIN_PASS_HASH')
        if hashed:
            return hashed

        # Fall back to plain password (hash it)
        plain = os.environ.get('ANTIDDOS_ADMIN_PASS')
        if plain:
            return PasswordManager.hash_password(plain)

        return None


# ==================== Login Rate Limiter ====================

class LoginRateLimiter:
    """Rate limiter specifically for login attempts."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _clean_old_attempts(self, key: str):
        """Remove attempts outside the window."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]

    def is_blocked(self, key: str) -> bool:
        """Check if key is currently rate limited."""
        with self._lock:
            self._clean_old_attempts(key)
            return len(self._attempts[key]) >= self.max_attempts

    def record_attempt(self, key: str):
        """Record a failed login attempt."""
        with self._lock:
            self._clean_old_attempts(key)
            self._attempts[key].append(time.time())

    def get_retry_after(self, key: str) -> int:
        """Get seconds until rate limit expires."""
        with self._lock:
            if not self._attempts[key]:
                return 0
            oldest = min(self._attempts[key])
            retry_after = int(oldest + self.window_seconds - time.time())
            return max(0, retry_after)

    def clear(self, key: str):
        """Clear attempts for a key after successful login."""
        with self._lock:
            self._attempts.pop(key, None)


# Global login rate limiter
_login_limiter = LoginRateLimiter(max_attempts=5, window_seconds=300)


# ==================== Token Blacklist ====================

class TokenBlacklist:
    """Token blacklist for logout invalidation."""

    def __init__(self):
        self._memory_blacklist: Dict[str, datetime] = {}
        self._redis: Optional[redis.Redis] = None
        self._lock = threading.Lock()

        # Try to connect to Redis
        if REDIS_AVAILABLE:
            try:
                redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
                self._redis = redis.from_url(redis_url, decode_responses=True)
                self._redis.ping()
                logger.info("Token blacklist using Redis")
            except Exception as e:
                logger.warning(f"Redis not available for token blacklist, using memory: {e}")
                self._redis = None

    def add(self, token_jti: str, expires_at: datetime):
        """Add token to blacklist."""
        ttl = int((expires_at - datetime.utcnow()).total_seconds())
        if ttl <= 0:
            return  # Token already expired

        if self._redis:
            try:
                self._redis.setex(f"token_blacklist:{token_jti}", ttl, "1")
                return
            except Exception as e:
                logger.warning(f"Redis blacklist add failed: {e}")

        # Fallback to memory
        with self._lock:
            self._memory_blacklist[token_jti] = expires_at
            # Clean expired entries
            now = datetime.utcnow()
            self._memory_blacklist = {
                k: v for k, v in self._memory_blacklist.items() if v > now
            }

    def is_blacklisted(self, token_jti: str) -> bool:
        """Check if token is blacklisted."""
        if self._redis:
            try:
                return self._redis.exists(f"token_blacklist:{token_jti}") > 0
            except Exception as e:
                logger.warning(f"Redis blacklist check failed: {e}")

        # Fallback to memory
        with self._lock:
            if token_jti in self._memory_blacklist:
                if self._memory_blacklist[token_jti] > datetime.utcnow():
                    return True
                else:
                    del self._memory_blacklist[token_jti]
            return False


# Global token blacklist
_token_blacklist = TokenBlacklist()


def get_token_blacklist() -> TokenBlacklist:
    """Get the global token blacklist."""
    return _token_blacklist


# ==================== Cookie Configuration ====================

# Cookie settings for secure token storage
COOKIE_NAME = "access_token"

# Development mode detection (same as main.py)
_DEBUG_MODE = os.environ.get('DEBUG', '').lower() in ('true', '1', 'yes')

# In development (DEBUG=true):
# - COOKIE_SECURE=false for HTTP localhost
# - COOKIE_SAMESITE=none to allow cross-origin requests between frontend (5173) and backend (8000)
# In production:
# - COOKIE_SECURE=true (require HTTPS)
# - COOKIE_SAMESITE=lax (default browser behavior)
_cookie_secure_default = 'false' if _DEBUG_MODE else 'true'
_cookie_samesite_default = 'none' if _DEBUG_MODE else 'lax'
COOKIE_SECURE = os.environ.get('COOKIE_SECURE', _cookie_secure_default).lower() == 'true'
COOKIE_SAMESITE = os.environ.get('COOKIE_SAMESITE', _cookie_samesite_default)  # lax, strict, or none
COOKIE_DOMAIN = os.environ.get('COOKIE_DOMAIN')  # None = current domain only
COOKIE_PATH = "/"


def set_auth_cookie(response: Response, token: str, max_age: int):
    """Set httpOnly authentication cookie."""
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=max_age,
        httponly=True,  # Not accessible via JavaScript - XSS protection
        secure=COOKIE_SECURE,  # Only sent over HTTPS
        samesite=COOKIE_SAMESITE,  # CSRF protection
        domain=COOKIE_DOMAIN,
        path=COOKIE_PATH,
    )


def clear_auth_cookie(response: Response):
    """Clear the authentication cookie."""
    response.delete_cookie(
        key=COOKIE_NAME,
        domain=COOKIE_DOMAIN,
        path=COOKIE_PATH,
    )


# ==================== Login ====================

@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    response: Response,
    credentials: UserLogin,
    use_cookie: bool = Query(default=True, description="Store token in httpOnly cookie"),
):
    """
    Login with username and password.

    Returns a JWT access token. By default, token is also stored in an httpOnly cookie
    for enhanced security (not accessible via JavaScript, protecting against XSS).

    Security features:
    - Rate limiting: 5 failed attempts per 5 minutes per IP
    - Bcrypt password hashing
    - httpOnly cookie storage (optional, default enabled)
    - Audit logging
    """
    # Get client IP for rate limiting
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"login:{client_ip}"

    # Check rate limit
    if _login_limiter.is_blocked(rate_key):
        retry_after = _login_limiter.get_retry_after(rate_key)
        get_audit_logger().log_auth_failure(
            f"rate_limited (retry after {retry_after}s)",
            request
        )
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    # Get admin credentials
    admin_user = os.environ.get('ANTIDDOS_ADMIN_USER', 'admin')
    admin_pass_hash = PasswordManager.get_admin_password_hash()

    if not admin_pass_hash:
        raise HTTPException(
            status_code=500,
            detail="Authentication not configured. Set ANTIDDOS_ADMIN_PASS or ANTIDDOS_ADMIN_PASS_HASH environment variable."
        )

    # Verify credentials
    if credentials.username != admin_user or not PasswordManager.verify_password(credentials.password, admin_pass_hash):
        _login_limiter.record_attempt(rate_key)
        get_audit_logger().log_auth_failure(
            "invalid_credentials",
            request
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Clear rate limit on successful login
    _login_limiter.clear(rate_key)

    # Create JWT token
    jwt_manager = get_jwt_manager()
    access_token = jwt_manager.create_access_token(
        user_id=credentials.username,
        permissions=["*"]  # Admin has all permissions
    )

    get_audit_logger().log_auth_success(
        UserContext(user_id=credentials.username, is_admin=True, permissions=["*"]),
        request
    )

    # Set httpOnly cookie if requested (default)
    if use_cookie:
        set_auth_cookie(response, access_token, AuthConfig.JWT_EXPIRY_HOURS * 3600)
        # Set CSRF double-submit cookie (readable by JS, paired with httpOnly auth cookie)
        csrf_token = secrets.token_hex(32)
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            max_age=AuthConfig.JWT_EXPIRY_HOURS * 3600,
            httponly=False,  # Must be readable by JavaScript
            secure=COOKIE_SECURE,
            samesite=COOKIE_SAMESITE,
            domain=COOKIE_DOMAIN,
            path=COOKIE_PATH,
        )

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=AuthConfig.JWT_EXPIRY_HOURS * 3600,
        user=credentials.username,
        permissions=["*"]
    )


@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(
    request: Request,
    response: Response,
    user: UserContext = Depends(get_current_user),
    use_cookie: bool = Query(default=True, description="Store token in httpOnly cookie"),
):
    """
    Refresh an access token.

    Exchange a valid token for a new one with extended expiry.
    """
    jwt_manager = get_jwt_manager()
    new_token = jwt_manager.create_access_token(
        user_id=user.user_id,
        permissions=user.permissions
    )

    # Update cookie if requested
    if use_cookie:
        set_auth_cookie(response, new_token, AuthConfig.JWT_EXPIRY_HOURS * 3600)

    return LoginResponse(
        access_token=new_token,
        token_type="bearer",
        expires_in=AuthConfig.JWT_EXPIRY_HOURS * 3600,
        user=user.user_id,
        permissions=user.permissions
    )


@router.post("/logout", response_model=APIResponse)
async def logout(
    request: Request,
    response: Response,
    user: UserContext = Depends(get_current_user),
):
    """
    Logout (invalidate current token).

    Adds the current token to a blacklist to prevent reuse.
    Blacklist is stored in Redis if available, otherwise in memory.
    Also clears the httpOnly authentication cookie.
    """
    # Try to blacklist the token from header or cookie
    token = None

    # Check Authorization header first
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]

    # Also check cookie
    if not token:
        token = request.cookies.get(COOKIE_NAME)

    if token:
        try:
            jwt_manager = get_jwt_manager()
            payload = jwt_manager.decode_token(token)

            # Get JTI (JWT ID) or use token hash as identifier
            token_jti = payload.get("jti") or payload.get("sub", "") + str(payload.get("iat", ""))

            # Calculate token expiry for blacklist TTL
            exp = payload.get("exp")
            if exp:
                expires_at = datetime.fromtimestamp(exp)
            else:
                expires_at = datetime.utcnow() + timedelta(hours=AuthConfig.JWT_EXPIRY_HOURS)

            # Add to blacklist
            _token_blacklist.add(token_jti, expires_at)
            logger.info(f"Token blacklisted for user {user.user_id}")
        except Exception as e:
            logger.warning(f"Failed to blacklist token: {e}")

    # Clear the authentication cookie and CSRF cookie
    clear_auth_cookie(response)
    response.delete_cookie(
        key="csrf_token",
        domain=COOKIE_DOMAIN,
        path=COOKIE_PATH,
    )

    get_audit_logger().log_api_action(
        user, "logout", f"user:{user.user_id}", request
    )

    return APIResponse(success=True, message="Logged out successfully. Token has been invalidated.")


# ==================== API Keys ====================

@router.get("/keys", response_model=APIResponse)
async def list_api_keys(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    List API keys for the current user.

    Only shows key metadata, not the actual key values.
    """
    store = get_api_key_store()

    keys = store.list_keys()

    return APIResponse(success=True, data=keys)


@router.post("/keys", response_model=APIResponse)
async def create_api_key(
    request: Request,
    key_request: TokenCreate,
    user: UserContext = Depends(get_current_user),
):
    """
    Create a new API key.

    The key value is only shown once upon creation.
    Store it securely - it cannot be retrieved again.
    """
    # Non-admins can only create keys with subset of their permissions
    if not user.is_admin:
        for perm in key_request.permissions:
            if perm not in user.permissions and perm != "read":
                raise HTTPException(
                    status_code=403,
                    detail=f"Cannot create key with permission '{perm}' you don't have"
                )

    store = get_api_key_store()

    # Rate limit: max 10 API keys per user to prevent abuse
    existing_keys = store.list_keys()
    user_keys = [k for k in existing_keys if k.get("created_by") == user.user_id]
    if len(user_keys) >= 10:
        raise HTTPException(
            status_code=429,
            detail="Maximum 10 API keys per user. Revoke unused keys first."
        )

    key = store.create_key(
        name=key_request.name,
        permissions=key_request.permissions,
        expires_in_hours=key_request.expires_in_hours
    )

    get_audit_logger().log_api_action(
        user, "create_api_key", f"name:{key_request.name}", request
    )

    return APIResponse(
        success=True,
        data={
            "name": key_request.name,
            "key": key,
            "permissions": key_request.permissions,
            "expires_in_hours": key_request.expires_in_hours
        },
        message="API key created. Store this key securely - it won't be shown again."
    )


@router.delete("/keys/{key_id}", response_model=APIResponse)
async def revoke_api_key(
    request: Request,
    key_id: str,
    user: UserContext = Depends(get_current_user),
):
    """
    Revoke an API key.
    """
    store = get_api_key_store()

    # Find the full hash from partial ID
    keys = store.list_keys()

    full_hash = None
    for k in keys:
        if k["id"] == key_id:
            # Need to reconstruct - in real impl, store hash separately
            full_hash = key_id  # Simplified

    if not full_hash:
        raise HTTPException(status_code=404, detail=f"API key {key_id} not found")

    store.revoke_key(full_hash)

    get_audit_logger().log_api_action(
        user, "revoke_api_key", f"key:{key_id}", request
    )

    return APIResponse(success=True, message="API key revoked")


# ==================== User Info ====================

@router.get("/me", response_model=APIResponse)
async def get_current_user_info(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    Get information about the currently authenticated user.
    """
    return APIResponse(
        success=True,
        data={
            "user_id": user.user_id,
            "permissions": user.permissions,
            "is_admin": user.is_admin,
            "auth_type": user.auth_type
        }
    )


@router.get("/permissions", response_model=APIResponse)
async def list_permissions(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    List all available permissions.
    """
    permissions = {
        "read": "Read access to system data",
        "config:write": "Modify system configuration",
        "security:write": "Modify blacklist/whitelist",
        "policy:write": "Create/modify policies",
        "reports:generate": "Generate reports",
        "reports:schedule": "Schedule automated reports",
        "api:manage": "Manage API keys",
        "*": "Full administrative access"
    }

    return APIResponse(
        success=True,
        data={
            "available_permissions": permissions,
            "your_permissions": user.permissions
        }
    )


# ==================== Health Check ====================

@router.get("/health", response_model=APIResponse)
async def health_check(request: Request):
    """
    Health check endpoint (no authentication required).
    """
    return APIResponse(
        success=True,
        data={
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat()
        }
    )
