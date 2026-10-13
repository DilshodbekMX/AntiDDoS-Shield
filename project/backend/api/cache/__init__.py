"""
Redis cache module for Anti-DDoS Platform.

Provides caching, session management, rate limiting,
and pub/sub functionality for real-time features.
"""

from .redis_client import (
    get_redis,
    get_redis_pool,
    init_redis,
    close_redis,
    redis_health_check,
    RedisClient,
)
from .cache_service import (
    CacheService,
    cache,
    invalidate_cache,
    get_cached,
    set_cached,
)

__all__ = [
    # Client
    "get_redis",
    "get_redis_pool",
    "init_redis",
    "close_redis",
    "redis_health_check",
    "RedisClient",
    # Cache service
    "CacheService",
    "cache",
    "invalidate_cache",
    "get_cached",
    "set_cached",
]
