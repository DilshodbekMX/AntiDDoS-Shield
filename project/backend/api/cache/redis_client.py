"""
Redis client connection management.

Provides connection pooling, health checks, and utilities
for Redis operations in the Anti-DDoS platform.
"""

import os
import json
import logging
from typing import Optional, Any, Union, List
from datetime import timedelta

logger = logging.getLogger(__name__)

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_MAX_CONNECTIONS = int(os.getenv("REDIS_MAX_CONNECTIONS", "10"))
REDIS_DECODE_RESPONSES = True
REDIS_SOCKET_TIMEOUT = 5.0
REDIS_SOCKET_CONNECT_TIMEOUT = 5.0

# Global Redis pool and client
_redis_pool = None
_redis_client = None


class RedisClient:
    """
    Redis client wrapper with convenience methods.

    Provides type-safe operations, automatic JSON serialization,
    and helper methods for common patterns.
    """

    def __init__(self, redis_instance):
        """Initialize with a redis-py client instance."""
        self._redis = redis_instance

    @property
    def client(self):
        """Get underlying redis client."""
        return self._redis

    # ==================== Basic Operations ====================

    def get(self, key: str) -> Optional[str]:
        """Get string value."""
        return self._redis.get(key)

    def set(
        self,
        key: str,
        value: str,
        ex: Optional[int] = None,
        px: Optional[int] = None,
        nx: bool = False,
        xx: bool = False,
    ) -> bool:
        """Set string value with optional expiration."""
        return self._redis.set(key, value, ex=ex, px=px, nx=nx, xx=xx)

    def delete(self, *keys: str) -> int:
        """Delete one or more keys."""
        return self._redis.delete(*keys)

    def exists(self, *keys: str) -> int:
        """Check if keys exist."""
        return self._redis.exists(*keys)

    def expire(self, key: str, seconds: int) -> bool:
        """Set key expiration in seconds."""
        return self._redis.expire(key, seconds)

    def ttl(self, key: str) -> int:
        """Get remaining TTL in seconds."""
        return self._redis.ttl(key)

    def keys(self, pattern: str = "*") -> List[str]:
        """Get keys matching pattern."""
        return self._redis.keys(pattern)

    # ==================== JSON Operations ====================

    def get_json(self, key: str) -> Optional[Any]:
        """Get and deserialize JSON value."""
        value = self._redis.get(key)
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return None
        return None

    def set_json(
        self,
        key: str,
        value: Any,
        ex: Optional[int] = None,
    ) -> bool:
        """Serialize and set JSON value."""
        return self._redis.set(key, json.dumps(value), ex=ex)

    # ==================== Hash Operations ====================

    def hget(self, name: str, key: str) -> Optional[str]:
        """Get hash field value."""
        return self._redis.hget(name, key)

    def hset(self, name: str, key: str = None, value: str = None, mapping: dict = None) -> int:
        """Set hash field(s)."""
        if mapping:
            return self._redis.hset(name, mapping=mapping)
        return self._redis.hset(name, key, value)

    def hdel(self, name: str, *keys: str) -> int:
        """Delete hash fields."""
        return self._redis.hdel(name, *keys)

    def hgetall(self, name: str) -> dict:
        """Get all hash fields."""
        return self._redis.hgetall(name)

    def hget_json(self, name: str, key: str) -> Optional[Any]:
        """Get and deserialize hash field as JSON."""
        value = self._redis.hget(name, key)
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return None
        return None

    def hset_json(self, name: str, key: str, value: Any) -> int:
        """Serialize and set hash field as JSON."""
        return self._redis.hset(name, key, json.dumps(value))

    # ==================== List Operations ====================

    def lpush(self, name: str, *values: str) -> int:
        """Push values to list head."""
        return self._redis.lpush(name, *values)

    def rpush(self, name: str, *values: str) -> int:
        """Push values to list tail."""
        return self._redis.rpush(name, *values)

    def lpop(self, name: str) -> Optional[str]:
        """Pop from list head."""
        return self._redis.lpop(name)

    def rpop(self, name: str) -> Optional[str]:
        """Pop from list tail."""
        return self._redis.rpop(name)

    def lrange(self, name: str, start: int, end: int) -> List[str]:
        """Get list range."""
        return self._redis.lrange(name, start, end)

    def llen(self, name: str) -> int:
        """Get list length."""
        return self._redis.llen(name)

    def ltrim(self, name: str, start: int, end: int) -> bool:
        """Trim list to range."""
        return self._redis.ltrim(name, start, end)

    # ==================== Set Operations ====================

    def sadd(self, name: str, *values: str) -> int:
        """Add members to set."""
        return self._redis.sadd(name, *values)

    def srem(self, name: str, *values: str) -> int:
        """Remove members from set."""
        return self._redis.srem(name, *values)

    def smembers(self, name: str) -> set:
        """Get all set members."""
        return self._redis.smembers(name)

    def sismember(self, name: str, value: str) -> bool:
        """Check if value is in set."""
        return self._redis.sismember(name, value)

    def scard(self, name: str) -> int:
        """Get set cardinality."""
        return self._redis.scard(name)

    # ==================== Sorted Set Operations ====================

    def zadd(self, name: str, mapping: dict, nx: bool = False, xx: bool = False) -> int:
        """Add members to sorted set."""
        return self._redis.zadd(name, mapping, nx=nx, xx=xx)

    def zrem(self, name: str, *values: str) -> int:
        """Remove members from sorted set."""
        return self._redis.zrem(name, *values)

    def zrange(
        self,
        name: str,
        start: int,
        end: int,
        withscores: bool = False,
    ) -> Union[List[str], List[tuple]]:
        """Get sorted set range by rank."""
        return self._redis.zrange(name, start, end, withscores=withscores)

    def zrangebyscore(
        self,
        name: str,
        min_score: float,
        max_score: float,
        withscores: bool = False,
    ) -> Union[List[str], List[tuple]]:
        """Get sorted set range by score."""
        return self._redis.zrangebyscore(name, min_score, max_score, withscores=withscores)

    def zscore(self, name: str, value: str) -> Optional[float]:
        """Get score of member."""
        return self._redis.zscore(name, value)

    def zincrby(self, name: str, amount: float, value: str) -> float:
        """Increment score of member."""
        return self._redis.zincrby(name, amount, value)

    def zcard(self, name: str) -> int:
        """Get sorted set cardinality."""
        return self._redis.zcard(name)

    # ==================== Counter Operations ====================

    def incr(self, name: str, amount: int = 1) -> int:
        """Increment counter."""
        return self._redis.incr(name, amount)

    def decr(self, name: str, amount: int = 1) -> int:
        """Decrement counter."""
        return self._redis.decr(name, amount)

    def incrbyfloat(self, name: str, amount: float) -> float:
        """Increment counter by float."""
        return self._redis.incrbyfloat(name, amount)

    # ==================== Pub/Sub Operations ====================

    def publish(self, channel: str, message: str) -> int:
        """Publish message to channel."""
        return self._redis.publish(channel, message)

    def publish_json(self, channel: str, message: Any) -> int:
        """Publish JSON message to channel."""
        return self._redis.publish(channel, json.dumps(message))

    def pubsub(self):
        """Get pubsub object for subscribing."""
        return self._redis.pubsub()

    # ==================== Pipeline Operations ====================

    def pipeline(self, transaction: bool = True):
        """Get pipeline for batch operations."""
        return self._redis.pipeline(transaction=transaction)

    # ==================== Utility Methods ====================

    def ping(self) -> bool:
        """Check connection."""
        try:
            return self._redis.ping()
        except Exception:
            return False

    def info(self, section: Optional[str] = None) -> dict:
        """Get server info."""
        return self._redis.info(section)

    def dbsize(self) -> int:
        """Get number of keys."""
        return self._redis.dbsize()

    def flushdb(self) -> bool:
        """Flush current database."""
        return self._redis.flushdb()


def init_redis() -> RedisClient:
    """
    Initialize Redis connection pool and client.

    Returns:
        RedisClient instance
    """
    global _redis_pool, _redis_client

    try:
        import redis

        logger.info(f"Initializing Redis connection: {REDIS_URL.split('@')[-1]}")

        _redis_pool = redis.ConnectionPool.from_url(
            REDIS_URL,
            max_connections=REDIS_MAX_CONNECTIONS,
            decode_responses=REDIS_DECODE_RESPONSES,
            socket_timeout=REDIS_SOCKET_TIMEOUT,
            socket_connect_timeout=REDIS_SOCKET_CONNECT_TIMEOUT,
        )

        redis_instance = redis.Redis(connection_pool=_redis_pool)

        # Test connection
        redis_instance.ping()

        _redis_client = RedisClient(redis_instance)
        logger.info("Redis connection established")

        return _redis_client

    except ImportError:
        logger.warning("redis-py not installed. Redis features disabled.")
        return None
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}. Running without Redis.")
        return None


def get_redis() -> Optional[RedisClient]:
    """
    Get Redis client instance.

    Returns:
        RedisClient or None if not initialized
    """
    global _redis_client

    if _redis_client is None:
        _redis_client = init_redis()

    return _redis_client


def get_redis_pool():
    """Get Redis connection pool."""
    global _redis_pool
    return _redis_pool


def close_redis():
    """Close Redis connections."""
    global _redis_pool, _redis_client

    if _redis_pool:
        logger.info("Closing Redis connections")
        _redis_pool.disconnect()
        _redis_pool = None

    _redis_client = None


def redis_health_check() -> dict:
    """
    Check Redis health.

    Returns:
        Health status dict
    """
    redis_client = get_redis()

    if redis_client is None:
        return {
            "status": "unavailable",
            "error": "Redis not initialized",
        }

    try:
        if redis_client.ping():
            info = redis_client.info("server")
            return {
                "status": "healthy",
                "version": info.get("redis_version", "unknown"),
                "uptime_seconds": info.get("uptime_in_seconds", 0),
                "connected_clients": redis_client.info("clients").get("connected_clients", 0),
                "used_memory": redis_client.info("memory").get("used_memory_human", "unknown"),
                "keys": redis_client.dbsize(),
            }
        else:
            return {
                "status": "unhealthy",
                "error": "Ping failed",
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
        }


# ==================== Key Schema Constants ====================

class RedisKeys:
    """
    Redis key schema for consistent naming.

    All keys are prefixed with 'antiddos:' namespace.
    """

    PREFIX = "antiddos"

    # Rate limiting
    @staticmethod
    def rate_limit_minute(user_id: str) -> str:
        return f"{RedisKeys.PREFIX}:rate:{user_id}:min"

    @staticmethod
    def rate_limit_hour(user_id: str) -> str:
        return f"{RedisKeys.PREFIX}:rate:{user_id}:hour"

    # Sessions
    @staticmethod
    def session(session_id: str) -> str:
        return f"{RedisKeys.PREFIX}:session:{session_id}"

    # Cache
    @staticmethod
    def system_config() -> str:
        return f"{RedisKeys.PREFIX}:cache:system:config"

    @staticmethod
    def system_stats() -> str:
        return f"{RedisKeys.PREFIX}:cache:system:stats"

    @staticmethod
    def active_attacks() -> str:
        return f"{RedisKeys.PREFIX}:cache:attacks:active"

    @staticmethod
    def dpdk_stats() -> str:
        return f"{RedisKeys.PREFIX}:cache:dpdk:stats"

    # Reputation cache
    @staticmethod
    def reputation(ip_address: str) -> str:
        return f"{RedisKeys.PREFIX}:reputation:{ip_address}"

    # Pub/Sub channels
    @staticmethod
    def channel_stats() -> str:
        return f"{RedisKeys.PREFIX}:channel:stats"

    @staticmethod
    def channel_attacks() -> str:
        return f"{RedisKeys.PREFIX}:channel:attacks"

    @staticmethod
    def channel_alerts() -> str:
        return f"{RedisKeys.PREFIX}:channel:alerts"

    @staticmethod
    def channel_traffic() -> str:
        return f"{RedisKeys.PREFIX}:channel:traffic"

    # Locks
    @staticmethod
    def lock(name: str) -> str:
        return f"{RedisKeys.PREFIX}:lock:{name}"

    # Counters
    @staticmethod
    def counter(name: str) -> str:
        return f"{RedisKeys.PREFIX}:counter:{name}"
