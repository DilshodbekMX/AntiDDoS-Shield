"""
API Security Module for Anti-DDoS Backend

Provides:
- Token-based authentication
- Rate limiting
- Audit logging
- Input validation
- CSRF protection
"""

import os
import re
import time
import hashlib
import secrets
import logging
import ipaddress
import functools
from datetime import datetime, timedelta
from threading import Lock
from collections import defaultdict
from typing import Optional, Tuple, Dict, Any, Callable

# ==================== Configuration ====================

class SecurityConfig:
    """Security configuration with secure defaults."""

    # Token settings
    TOKEN_LENGTH = 64
    TOKEN_EXPIRY_HOURS = 24
    MAX_TOKENS_PER_USER = 5

    # Rate limiting
    RATE_LIMIT_REQUESTS_PER_MINUTE = 60
    RATE_LIMIT_REQUESTS_PER_HOUR = 1000
    RATE_LIMIT_BURST = 20

    # Stricter limits for sensitive endpoints
    SENSITIVE_RATE_LIMIT_PER_MINUTE = 10

    # Audit logging
    AUDIT_LOG_PATH = "/var/log/antiddos/audit.log"
    AUDIT_LOG_MAX_SIZE = 100 * 1024 * 1024  # 100MB

    # Input validation
    MAX_IP_LIST_SIZE = 10000
    MAX_DESCRIPTION_LENGTH = 256
    MAX_REQUEST_SIZE = 1024 * 1024  # 1MB

    # Allowed origins for CORS
    ALLOWED_ORIGINS = ["http://localhost:5005", "http://127.0.0.1:5005"]


# ==================== Audit Logger ====================

class AuditLogger:
    """Thread-safe audit logger for security events."""

    def __init__(self, log_path: str = None):
        self.log_path = log_path or SecurityConfig.AUDIT_LOG_PATH
        self._lock = Lock()
        self._logger = None
        self._setup_logger()

    def _setup_logger(self):
        """Configure the audit logger."""
        try:
            # Ensure directory exists
            log_dir = os.path.dirname(self.log_path)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, mode=0o750, exist_ok=True)

            self._logger = logging.getLogger(f'audit_{id(self)}')
            self._logger.setLevel(logging.INFO)
            self._logger.propagate = False

            # Remove existing handlers
            self._logger.handlers = []

            # File handler with rotation
            from logging.handlers import RotatingFileHandler
            handler = RotatingFileHandler(
                self.log_path,
                maxBytes=SecurityConfig.AUDIT_LOG_MAX_SIZE,
                backupCount=5
            )
            handler.setFormatter(logging.Formatter(
                '%(asctime)s | %(levelname)s | %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%S%z'
            ))
            self._logger.addHandler(handler)
        except Exception as e:
            # Fallback to stderr if file logging fails
            print(f"Warning: Could not setup audit log: {e}")
            self._logger = logging.getLogger(f'audit_fallback_{id(self)}')
            self._logger.addHandler(logging.StreamHandler())

    def log(self, event_type: str, user: str, action: str,
            details: Dict[str, Any] = None, success: bool = True,
            remote_ip: str = None):
        """Log an audit event."""
        with self._lock:
            status = "SUCCESS" if success else "FAILURE"
            detail_str = ""
            if details:
                # Sanitize details for logging
                safe_details = {k: self._sanitize_value(v) for k, v in details.items()}
                detail_str = f" | {safe_details}"

            ip_str = f" | IP={self._sanitize_value(remote_ip)}" if remote_ip else ""

            safe_user = self._sanitize_value(user)
            safe_action = self._sanitize_value(action)
            self._logger.info(f"{event_type} | {status} | user={safe_user} | action={safe_action}{ip_str}{detail_str}")
            for h in self._logger.handlers:
                try:
                    h.flush()
                except Exception:
                    pass

    def _sanitize_value(self, value) -> str:
        """Sanitize a value for safe logging."""
        s = str(value)[:200]  # Truncate long values
        # Remove control characters
        s = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', s)
        return s

    def log_auth_attempt(self, user: str, success: bool, remote_ip: str, reason: str = None):
        """Log authentication attempt."""
        details = {"reason": reason} if reason else None
        self.log("AUTH", user, "login_attempt", details, success, remote_ip)

    def log_config_change(self, user: str, section: str, changes: Dict, remote_ip: str):
        """Log configuration change."""
        self.log("CONFIG", user, f"modify_{section}", changes, True, remote_ip)

    def log_rule_change(self, user: str, action: str, rule_type: str,
                        target: str, remote_ip: str):
        """Log rule modification (whitelist/blacklist)."""
        self.log("RULE", user, action, {"type": rule_type, "target": target}, True, remote_ip)

    def log_security_event(self, event: str, details: Dict, remote_ip: str):
        """Log security-related events."""
        self.log("SECURITY", "system", event, details, True, remote_ip)


# Global audit logger instance
_audit_logger = None

def get_audit_logger() -> AuditLogger:
    """Get or create the global audit logger."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


# ==================== Token Authentication ====================

class TokenStore:
    """Secure token storage and validation."""

    def __init__(self):
        self._tokens: Dict[str, Dict] = {}  # hash -> {user, created, expires, permissions}
        self._user_tokens: Dict[str, set] = defaultdict(set)  # user -> set of token hashes
        self._lock = Lock()

        # Create default admin token from environment or generate
        self._init_default_token()

    def _init_default_token(self):
        """Initialize default admin token."""
        env_token = os.environ.get('ANTIDDOS_API_TOKEN')
        if env_token:
            self.create_token('admin', env_token, permissions=['*'])
        else:
            # Generate token file if it doesn't exist
            token_file = '/var/lib/antiddos/api_token'
            try:
                if os.path.exists(token_file):
                    with open(token_file, 'r') as f:
                        token = f.read().strip()
                else:
                    token = secrets.token_urlsafe(SecurityConfig.TOKEN_LENGTH)
                    os.makedirs(os.path.dirname(token_file), mode=0o750, exist_ok=True)
                    with open(token_file, 'w') as f:
                        f.write(token)
                    os.chmod(token_file, 0o600)
                    print(f"[Security] Generated API token saved to {token_file}")

                self.create_token('admin', token, permissions=['*'])
            except Exception as e:
                print(f"[Security] Warning: Could not setup token file: {e}")
                # Generate ephemeral token
                token = secrets.token_urlsafe(SecurityConfig.TOKEN_LENGTH)
                self.create_token('admin', token, permissions=['*'])
                print(f"[Security] Ephemeral admin token: {token}")

    def _hash_token(self, token: str) -> str:
        """Create secure hash of token."""
        return hashlib.sha256(token.encode()).hexdigest()

    def create_token(self, user: str, token: str = None,
                     permissions: list = None,
                     expiry_hours: int = None) -> str:
        """Create a new API token."""
        if token is None:
            token = secrets.token_urlsafe(SecurityConfig.TOKEN_LENGTH)

        token_hash = self._hash_token(token)
        expiry = expiry_hours or SecurityConfig.TOKEN_EXPIRY_HOURS

        with self._lock:
            # Enforce max tokens per user
            if len(self._user_tokens[user]) >= SecurityConfig.MAX_TOKENS_PER_USER:
                # Remove oldest token
                oldest_hash = next(iter(self._user_tokens[user]))
                self._tokens.pop(oldest_hash, None)
                self._user_tokens[user].discard(oldest_hash)

            self._tokens[token_hash] = {
                'user': user,
                'created': datetime.utcnow(),
                'expires': datetime.utcnow() + timedelta(hours=expiry),
                'permissions': permissions or ['read']
            }
            self._user_tokens[user].add(token_hash)

        return token

    def validate_token(self, token: str) -> Tuple[bool, Optional[Dict]]:
        """Validate a token and return user info if valid."""
        token_hash = self._hash_token(token)

        with self._lock:
            token_info = self._tokens.get(token_hash)

            if not token_info:
                return False, None

            if datetime.utcnow() > token_info['expires']:
                # Token expired, remove it
                self._tokens.pop(token_hash, None)
                self._user_tokens[token_info['user']].discard(token_hash)
                return False, None

            return True, token_info

    def revoke_token(self, token: str) -> bool:
        """Revoke a token."""
        token_hash = self._hash_token(token)

        with self._lock:
            token_info = self._tokens.pop(token_hash, None)
            if token_info:
                self._user_tokens[token_info['user']].discard(token_hash)
                return True
            return False

    def revoke_user_tokens(self, user: str) -> int:
        """Revoke all tokens for a user."""
        with self._lock:
            hashes = self._user_tokens.pop(user, set())
            for h in hashes:
                self._tokens.pop(h, None)
            return len(hashes)

    def has_permission(self, token_info: Dict, permission: str) -> bool:
        """Check if token has required permission."""
        permissions = token_info.get('permissions', [])
        return '*' in permissions or permission in permissions


# Global token store
_token_store = None

def get_token_store() -> TokenStore:
    """Get or create the global token store."""
    global _token_store
    if _token_store is None:
        _token_store = TokenStore()
    return _token_store


# ==================== Rate Limiter ====================

class RateLimiter:
    """Token bucket rate limiter with per-IP tracking."""

    def __init__(self):
        self._buckets: Dict[str, Dict] = {}  # ip -> {tokens, last_update, minute_count, hour_count}
        self._lock = Lock()
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = time.time()

    def _get_bucket(self, key: str) -> Dict:
        """Get or create a rate limit bucket."""
        now = time.time()

        if key not in self._buckets:
            self._buckets[key] = {
                'tokens': SecurityConfig.RATE_LIMIT_BURST,
                'last_update': now,
                'minute_start': now,
                'minute_count': 0,
                'hour_start': now,
                'hour_count': 0
            }

        bucket = self._buckets[key]

        # Refill tokens based on time elapsed
        elapsed = now - bucket['last_update']
        refill_rate = SecurityConfig.RATE_LIMIT_REQUESTS_PER_MINUTE / 60.0
        bucket['tokens'] = min(
            SecurityConfig.RATE_LIMIT_BURST,
            bucket['tokens'] + elapsed * refill_rate
        )
        bucket['last_update'] = now

        # Reset minute counter
        if now - bucket['minute_start'] > 60:
            bucket['minute_start'] = now
            bucket['minute_count'] = 0

        # Reset hour counter
        if now - bucket['hour_start'] > 3600:
            bucket['hour_start'] = now
            bucket['hour_count'] = 0

        return bucket

    def check_rate_limit(self, remote_ip: str, sensitive: bool = False) -> Tuple[bool, Dict]:
        """
        Check if request is within rate limits.

        Returns:
            (allowed, info) where info contains remaining limits
        """
        with self._lock:
            # Periodic cleanup
            if time.time() - self._last_cleanup > self._cleanup_interval:
                self._cleanup()

            bucket = self._get_bucket(remote_ip)

            # Check limits
            per_minute = SecurityConfig.SENSITIVE_RATE_LIMIT_PER_MINUTE if sensitive \
                        else SecurityConfig.RATE_LIMIT_REQUESTS_PER_MINUTE

            if bucket['tokens'] < 1:
                return False, {
                    'retry_after': int(1 / (per_minute / 60.0)),
                    'limit': per_minute,
                    'remaining': 0
                }

            if bucket['minute_count'] >= per_minute:
                return False, {
                    'retry_after': int(60 - (time.time() - bucket['minute_start'])),
                    'limit': per_minute,
                    'remaining': 0
                }

            if bucket['hour_count'] >= SecurityConfig.RATE_LIMIT_REQUESTS_PER_HOUR:
                return False, {
                    'retry_after': int(3600 - (time.time() - bucket['hour_start'])),
                    'limit': SecurityConfig.RATE_LIMIT_REQUESTS_PER_HOUR,
                    'remaining': 0
                }

            # Consume token
            bucket['tokens'] -= 1
            bucket['minute_count'] += 1
            bucket['hour_count'] += 1

            return True, {
                'limit': per_minute,
                'remaining': int(bucket['tokens']),
                'reset': int(bucket['minute_start'] + 60)
            }

    def _cleanup(self):
        """Remove stale buckets."""
        now = time.time()
        stale_keys = [
            k for k, v in self._buckets.items()
            if now - v['last_update'] > 3600
        ]
        for k in stale_keys:
            del self._buckets[k]
        self._last_cleanup = now


# Global rate limiter
_rate_limiter = None

def get_rate_limiter() -> RateLimiter:
    """Get or create the global rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


# ==================== Input Validation ====================

class InputValidator:
    """Validate and sanitize user input."""

    # IP address patterns
    IPV4_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    IPV4_CIDR_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')

    @staticmethod
    def validate_ip(ip_str: str) -> Tuple[bool, Optional[str]]:
        """
        Validate an IP address.

        Returns:
            (valid, error_message)
        """
        if not ip_str or not isinstance(ip_str, str):
            return False, "IP address is required"

        ip_str = ip_str.strip()

        try:
            ip = ipaddress.ip_address(ip_str)

            # Additional checks
            if ip.is_multicast:
                return False, "Multicast addresses not allowed"
            if ip.is_unspecified:
                return False, "Unspecified addresses not allowed"

            return True, None
        except ValueError:
            return False, f"Invalid IP address format: {ip_str}"

    @staticmethod
    def validate_ip_or_cidr(ip_str: str) -> Tuple[bool, Optional[str]]:
        """Validate an IP address or CIDR range."""
        if not ip_str or not isinstance(ip_str, str):
            return False, "IP address or CIDR is required"

        ip_str = ip_str.strip()

        try:
            if '/' in ip_str:
                network = ipaddress.ip_network(ip_str, strict=False)
                # Check for overly broad ranges
                if network.prefixlen < 8:
                    return False, "CIDR range too broad (minimum /8)"
            else:
                ipaddress.ip_address(ip_str)

            return True, None
        except ValueError:
            return False, f"Invalid IP/CIDR format: {ip_str}"

    @staticmethod
    def sanitize_description(desc: str) -> str:
        """Sanitize description field to prevent injection attacks."""
        if not desc or not isinstance(desc, str):
            return ''

        # Limit length
        desc = desc[:SecurityConfig.MAX_DESCRIPTION_LENGTH]

        # Remove control characters (prevent log injection)
        desc = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', desc)

        # Escape HTML entities (prevent XSS)
        desc = desc.replace('&', '&amp;')
        desc = desc.replace('<', '&lt;')
        desc = desc.replace('>', '&gt;')
        desc = desc.replace('"', '&quot;')
        desc = desc.replace("'", '&#x27;')

        return desc

    @staticmethod
    def validate_port(port: int) -> Tuple[bool, Optional[str]]:
        """Validate a port number."""
        try:
            port = int(port)
            if port < 0 or port > 65535:
                return False, "Port must be 0-65535"
            return True, None
        except (TypeError, ValueError):
            return False, "Port must be an integer"

    @staticmethod
    def validate_country_code(code: str) -> Tuple[bool, Optional[str]]:
        """Validate an ISO 3166-1 alpha-2 country code."""
        if not code or not isinstance(code, str):
            return False, "Country code is required"

        code = code.strip().upper()

        if len(code) != 2:
            return False, "Country code must be 2 characters"

        if not code.isalpha():
            return False, "Country code must be letters only"

        return True, None

    @staticmethod
    def validate_positive_int(value, name: str, max_value: int = None) -> Tuple[bool, Optional[str]]:
        """Validate a positive integer."""
        try:
            value = int(value)
            if value < 0:
                return False, f"{name} must be non-negative"
            if max_value is not None and value > max_value:
                return False, f"{name} must be at most {max_value}"
            return True, None
        except (TypeError, ValueError):
            return False, f"{name} must be an integer"


# ==================== Flask Integration ====================

def require_auth(permission: str = 'write'):
    """Decorator to require authentication for an endpoint."""
    def decorator(f: Callable):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, jsonify, g

            # Extract token from Authorization header
            auth_header = request.headers.get('Authorization', '')
            token = None

            if auth_header.startswith('Bearer '):
                token = auth_header[7:]

            if not token:
                get_audit_logger().log_auth_attempt(
                    'anonymous', False, request.remote_addr, 'no_token'
                )
                return jsonify({'error': 'Authentication required'}), 401

            # Validate token
            valid, token_info = get_token_store().validate_token(token)

            if not valid:
                get_audit_logger().log_auth_attempt(
                    'anonymous', False, request.remote_addr, 'invalid_token'
                )
                return jsonify({'error': 'Invalid or expired token'}), 401

            # Check permission
            if not get_token_store().has_permission(token_info, permission):
                get_audit_logger().log_auth_attempt(
                    token_info['user'], False, request.remote_addr, 'insufficient_permission'
                )
                return jsonify({'error': 'Insufficient permissions'}), 403

            # Store user info in Flask g object
            g.user = token_info['user']
            g.permissions = token_info['permissions']

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def rate_limit(sensitive: bool = False):
    """Decorator to apply rate limiting to an endpoint."""
    def decorator(f: Callable):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, jsonify

            remote_ip = request.remote_addr
            allowed, info = get_rate_limiter().check_rate_limit(remote_ip, sensitive)

            if not allowed:
                get_audit_logger().log_security_event(
                    'rate_limit_exceeded',
                    {'endpoint': request.path, 'method': request.method},
                    remote_ip
                )

                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': info['retry_after']
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(info['retry_after'])
                response.headers['X-RateLimit-Limit'] = str(info['limit'])
                response.headers['X-RateLimit-Remaining'] = str(info.get('remaining', 0))
                return response

            # Add rate limit headers to response
            response = f(*args, **kwargs)

            # Handle tuple responses (response, status_code)
            if isinstance(response, tuple):
                resp_obj = response[0]
            else:
                resp_obj = response

            if hasattr(resp_obj, 'headers'):
                resp_obj.headers['X-RateLimit-Limit'] = str(info['limit'])
                resp_obj.headers['X-RateLimit-Remaining'] = str(info['remaining'])

            return response

        return decorated_function
    return decorator


def validate_json_input(schema: Dict[str, type]):
    """Decorator to validate JSON input against a schema."""
    def decorator(f: Callable):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, jsonify

            data = request.get_json()

            if data is None:
                return jsonify({'error': 'JSON body required'}), 400

            # Validate required fields and types
            for field, expected_type in schema.items():
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400

                if not isinstance(data[field], expected_type):
                    return jsonify({
                        'error': f'Invalid type for {field}: expected {expected_type.__name__}'
                    }), 400

            return f(*args, **kwargs)

        return decorated_function
    return decorator


# ==================== Security Headers Middleware ====================

def add_security_headers(response):
    """Add security headers to response."""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'

    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Content Security Policy
    response.headers['Content-Security-Policy'] = "default-src 'self'"

    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    return response


def init_security(app):
    """Initialize security features for Flask app."""
    # Add security headers to all responses
    app.after_request(add_security_headers)

    # Initialize global instances
    get_token_store()
    get_rate_limiter()
    get_audit_logger()

    print("[Security] Security module initialized")
    print(f"[Security] Audit log: {SecurityConfig.AUDIT_LOG_PATH}")
