"""
Cache service for high-level caching operations.

Provides decorator-based caching, cache invalidation,
and convenience methods for common caching patterns.
"""

import json
import logging
import functools
import hashlib
from typing import Optional, Any, Callable, Union, List
from datetime import datetime, timedelta

from .redis_client import get_redis, RedisClient, RedisKeys

logger = logging.getLogger(__name__)

# Default TTLs
DEFAULT_TTL = 300  # 5 minutes
SHORT_TTL = 30  # 30 seconds
LONG_TTL = 3600  # 1 hour


class CacheService:
    """
    High-level caching service.

    Provides caching for configs, stats, and other
    frequently accessed data with automatic invalidation.
    """

    def __init__(self, redis_client: Optional[RedisClient] = None):
        """Initialize with optional Redis client."""
        self._redis = redis_client

    @property
    def redis(self) -> Optional[RedisClient]:
        """Get Redis client, initializing if needed."""
        if self._redis is None:
            self._redis = get_redis()
        return self._redis

    @property
    def available(self) -> bool:
        """Check if cache is available."""
        return self.redis is not None and self.redis.ping()

    # ==================== Config Cache ====================

    def get_config(self) -> Optional[dict]:
        """Get cached system configuration."""
        if not self.available:
            return None

        key = RedisKeys.system_config()
        return self.redis.get_json(key)

    def set_config(
        self,
        config: dict,
        ttl: int = DEFAULT_TTL,
    ) -> bool:
        """Cache system configuration."""
        if not self.available:
            return False

        key = RedisKeys.system_config()
        return self.redis.set_json(key, config, ex=ttl)

    def invalidate_config(self) -> bool:
        """Invalidate config cache."""
        if not self.available:
            return False

        key = RedisKeys.system_config()
        return self.redis.delete(key) > 0

    # ==================== Stats Cache ====================

    def get_stats(self) -> Optional[dict]:
        """Get cached system statistics."""
        if not self.available:
            return None

        key = RedisKeys.system_stats()
        return self.redis.get_json(key)

    def set_stats(
        self,
        stats: dict,
        ttl: int = SHORT_TTL,
    ) -> bool:
        """Cache system statistics."""
        if not self.available:
            return False

        key = RedisKeys.system_stats()
        return self.redis.set_json(key, stats, ex=ttl)

    # ==================== DPDK Stats Cache ====================

    def get_dpdk_stats(self) -> Optional[dict]:
        """Get cached DPDK statistics."""
        if not self.available:
            return None

        key = RedisKeys.dpdk_stats()
        return self.redis.get_json(key)

    def set_dpdk_stats(self, stats: dict, ttl: int = 2) -> bool:
        """Cache DPDK statistics (short TTL for real-time)."""
        if not self.available:
            return False

        key = RedisKeys.dpdk_stats()
        return self.redis.set_json(key, stats, ex=ttl)

    # ==================== Active Attacks Cache ====================

    def get_active_attacks(self) -> Optional[List[dict]]:
        """Get cached active attacks list."""
        if not self.available:
            return None

        key = RedisKeys.active_attacks()
        return self.redis.get_json(key)

    def set_active_attacks(
        self,
        attacks: List[dict],
        ttl: int = 10,
    ) -> bool:
        """Cache active attacks list."""
        if not self.available:
            return False

        key = RedisKeys.active_attacks()
        return self.redis.set_json(key, attacks, ex=ttl)

    # ==================== Reputation Cache ====================

    def get_reputation(self, ip_address: str) -> Optional[dict]:
        """Get cached IP reputation."""
        if not self.available:
            return None

        key = RedisKeys.reputation(ip_address)
        return self.redis.get_json(key)

    def set_reputation(
        self,
        ip_address: str,
        reputation: dict,
        ttl: int = LONG_TTL,
    ) -> bool:
        """Cache IP reputation."""
        if not self.available:
            return False

        key = RedisKeys.reputation(ip_address)
        return self.redis.set_json(key, reputation, ex=ttl)

    def invalidate_reputation(self, ip_address: str) -> bool:
        """Invalidate IP reputation cache."""
        if not self.available:
            return False

        key = RedisKeys.reputation(ip_address)
        return self.redis.delete(key) > 0

    # ==================== Generic Cache Operations ====================

    def get(self, key: str) -> Optional[Any]:
        """Get cached value by key."""
        if not self.available:
            return None
        return self.redis.get_json(key)

    def set(self, key: str, value: Any, ttl: int = DEFAULT_TTL) -> bool:
        """Set cached value with TTL."""
        if not self.available:
            return False
        return self.redis.set_json(key, value, ex=ttl)

    def delete(self, key: str) -> bool:
        """Delete cached value."""
        if not self.available:
            return False
        return self.redis.delete(key) > 0

    def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern."""
        if not self.available:
            return 0

        keys = self.redis.keys(pattern)
        if keys:
            return self.redis.delete(*keys)
        return 0

    # ==================== Pub/Sub ====================

    def publish_stats(
        self,
        stats: dict,
    ) -> int:
        """Publish stats update to channel."""
        if not self.available:
            return 0

        channel = RedisKeys.channel_stats()
        return self.redis.publish_json(channel, stats)

    def publish_attack(self, attack: dict) -> int:
        """Publish attack notification."""
        if not self.available:
            return 0

        channel = RedisKeys.channel_attacks()
        return self.redis.publish_json(channel, attack)

    def publish_alert(self, alert: dict) -> int:
        """Publish system alert."""
        if not self.available:
            return 0

        channel = RedisKeys.channel_alerts()
        return self.redis.publish_json(channel, alert)

    def publish_traffic(self, traffic: dict) -> int:
        """Publish traffic sample."""
        if not self.available:
            return 0

        channel = RedisKeys.channel_traffic()
        return self.redis.publish_json(channel, traffic)

    # ==================== Rate Limiting ====================

    def check_rate_limit(
        self,
        user_id: str,
        limit_per_minute: int = 60,
        limit_per_hour: int = 1000,
    ) -> tuple[bool, dict]:
        """
        Check and update rate limits.

        Returns:
            Tuple of (allowed, info_dict)
        """
        if not self.available:
            # Allow if Redis unavailable
            return True, {"redis_unavailable": True}

        now = datetime.utcnow()
        pipe = self.redis.pipeline()

        # Per-minute check
        minute_key = RedisKeys.rate_limit_minute(user_id)
        pipe.incr(minute_key)
        pipe.expire(minute_key, 60)

        # Per-hour check
        hour_key = RedisKeys.rate_limit_hour(user_id)
        pipe.incr(hour_key)
        pipe.expire(hour_key, 3600)

        results = pipe.execute()

        minute_count = results[0]
        hour_count = results[2]

        info = {
            "minute_count": minute_count,
            "minute_limit": limit_per_minute,
            "minute_remaining": max(0, limit_per_minute - minute_count),
            "hour_count": hour_count,
            "hour_limit": limit_per_hour,
            "hour_remaining": max(0, limit_per_hour - hour_count),
        }

        if minute_count > limit_per_minute:
            info["exceeded"] = "minute"
            info["retry_after"] = 60 - now.second
            return False, info

        if hour_count > limit_per_hour:
            info["exceeded"] = "hour"
            info["retry_after"] = 3600 - (now.minute * 60 + now.second)
            return False, info

        return True, info


# ==================== Global Cache Service ====================

_cache_service: Optional[CacheService] = None


def get_cache_service() -> CacheService:
    """Get global cache service instance."""
    global _cache_service

    if _cache_service is None:
        _cache_service = CacheService()

    return _cache_service


# ==================== Convenience Functions ====================


def get_cached(key: str) -> Optional[Any]:
    """Get value from cache."""
    return get_cache_service().get(key)


def set_cached(key: str, value: Any, ttl: int = DEFAULT_TTL) -> bool:
    """Set value in cache."""
    return get_cache_service().set(key, value, ttl)


def invalidate_cache(key: str) -> bool:
    """Delete value from cache."""
    return get_cache_service().delete(key)


# ==================== Cache Decorator ====================


def _make_cache_key(prefix: str, args: tuple, kwargs: dict) -> str:
    """Generate cache key from function arguments."""
    # Create a hashable representation
    key_parts = [prefix]

    for arg in args:
        if isinstance(arg, (str, int, float, bool)):
            key_parts.append(str(arg))
        else:
            key_parts.append(hashlib.md5(str(arg).encode()).hexdigest()[:8])

    for k, v in sorted(kwargs.items()):
        if isinstance(v, (str, int, float, bool)):
            key_parts.append(f"{k}={v}")
        else:
            key_parts.append(f"{k}={hashlib.md5(str(v).encode()).hexdigest()[:8]}")

    return ":".join(key_parts)


def cache(
    ttl: int = DEFAULT_TTL,
    prefix: Optional[str] = None,
    key_builder: Optional[Callable] = None,
):
    """
    Decorator for caching function results.

    Usage:
        @cache(ttl=300)
        def get_data(key: str) -> dict:
            ...

        @cache(ttl=60, prefix="stats")
        def get_stats() -> dict:
            ...

        @cache(ttl=300, key_builder=lambda key, **kw: f"custom:{key}")
        def get_custom(key: str, **kwargs) -> dict:
            ...
    """
    def decorator(func: Callable) -> Callable:
        cache_prefix = prefix or f"cache:{func.__module__}:{func.__name__}"

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            cache_svc = get_cache_service()

            # Skip cache if Redis unavailable
            if not cache_svc.available:
                return func(*args, **kwargs)

            # Generate cache key
            if key_builder:
                cache_key = key_builder(*args, **kwargs)
            else:
                cache_key = _make_cache_key(cache_prefix, args, kwargs)

            # Try to get from cache
            cached = cache_svc.get(cache_key)
            if cached is not None:
                return cached

            # Call function and cache result
            result = func(*args, **kwargs)

            if result is not None:
                cache_svc.set(cache_key, result, ttl)

            return result

        # Add cache control methods
        wrapper.cache_prefix = cache_prefix
        wrapper.invalidate = lambda *args, **kwargs: invalidate_cache(
            key_builder(*args, **kwargs) if key_builder
            else _make_cache_key(cache_prefix, args, kwargs)
        )

        return wrapper

    return decorator


def cache_async(
    ttl: int = DEFAULT_TTL,
    prefix: Optional[str] = None,
    key_builder: Optional[Callable] = None,
):
    """
    Async version of cache decorator.

    Usage:
        @cache_async(ttl=300)
        async def get_data(key: str) -> dict:
            ...
    """
    def decorator(func: Callable) -> Callable:
        cache_prefix = prefix or f"cache:{func.__module__}:{func.__name__}"

        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            cache_svc = get_cache_service()

            if not cache_svc.available:
                return await func(*args, **kwargs)

            if key_builder:
                cache_key = key_builder(*args, **kwargs)
            else:
                cache_key = _make_cache_key(cache_prefix, args, kwargs)

            cached = cache_svc.get(cache_key)
            if cached is not None:
                return cached

            result = await func(*args, **kwargs)

            if result is not None:
                cache_svc.set(cache_key, result, ttl)

            return result

        wrapper.cache_prefix = cache_prefix
        wrapper.invalidate = lambda *args, **kwargs: invalidate_cache(
            key_builder(*args, **kwargs) if key_builder
            else _make_cache_key(cache_prefix, args, kwargs)
        )

        return wrapper

    return decorator
