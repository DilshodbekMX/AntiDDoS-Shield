"""
Policy Persistence Service

Provides durable storage for policies with crash recovery support.
Uses SQLite for local persistence with Redis for distributed caching.

Key Features:
- Automatic policy backup on creation/update
- Crash recovery on startup
- Periodic snapshots
- Redis cache for fast lookups
"""

import os
import json
import time
import sqlite3
import logging
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
from contextlib import contextmanager

# Try to import Redis
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logging.warning("Redis not available, using SQLite-only persistence")


class PolicyAction(Enum):
    DROP = "DROP"
    RATE_LIMIT = "RATE_LIMIT"
    CHALLENGE = "CHALLENGE"
    MONITOR = "MONITOR"
    ALLOW = "ALLOW"


@dataclass
class Policy:
    """Policy data model for persistence"""
    id: int
    src_ip: Optional[str]
    src_cidr: Optional[str]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    protocol: Optional[int]
    action: str
    rate_limit_pps: Optional[int]
    rate_limit_bps: Optional[int]
    priority: int
    ttl_sec: int
    created_at: float
    expires_at: float
    source: str  # L3_ML, L4_REPUTATION, L5_THREAT_INTEL, OPERATOR
    confidence: float
    reason: str
    active: bool = True

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'Policy':
        return cls(**data)

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class PolicyPersistenceService:
    """
    Durable policy storage with crash recovery

    Architecture:
    - SQLite: Primary persistent storage
    - Redis: Distributed cache for fast lookups (optional)
    - In-memory: Hot cache for ultra-fast access
    """

    def __init__(self,
                 db_path: str = "data/policies.db",
                 redis_url: Optional[str] = None,
                 snapshot_interval_sec: int = 300):
        self.db_path = db_path
        self.redis_url = redis_url
        self.snapshot_interval = snapshot_interval_sec
        self.logger = logging.getLogger(__name__)

        # In-memory cache: policy_id -> Policy
        self._cache: Dict[int, Policy] = {}
        self._cache_lock = threading.RLock()

        # Redis client
        self._redis: Optional[redis.Redis] = None
        if REDIS_AVAILABLE and redis_url:
            try:
                self._redis = redis.from_url(redis_url)
                self._redis.ping()
                self.logger.info("Redis connection established for policy caching")
            except Exception as e:
                self.logger.warning(f"Redis connection failed, using SQLite only: {e}")
                self._redis = None

        # Initialize database
        self._init_db()

        # Load existing policies into cache
        self._load_from_db()

        # Start background snapshot thread
        self._snapshot_thread: Optional[threading.Thread] = None
        self._shutdown_flag = threading.Event()
        self._start_snapshot_thread()

    def _init_db(self):
        """Initialize SQLite database schema"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        with self._get_db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    src_cidr TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol INTEGER,
                    action TEXT NOT NULL,
                    rate_limit_pps INTEGER,
                    rate_limit_bps INTEGER,
                    priority INTEGER DEFAULT 100,
                    ttl_sec INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL DEFAULT 1.0,
                    reason TEXT,
                    active INTEGER DEFAULT 1,
                    UNIQUE(src_ip, dst_ip, dst_port, protocol, action)
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_policies_expires
                ON policies(expires_at)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_policies_active
                ON policies(active)
            """)

            # Create snapshots table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    policy_count INTEGER NOT NULL,
                    data TEXT NOT NULL
                )
            """)

            conn.commit()
            self.logger.info(f"Policy database initialized at {self.db_path}")

    @contextmanager
    def _get_db(self):
        """Get database connection with context manager"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _load_from_db(self):
        """Load all active policies from database into cache"""
        with self._get_db() as conn:
            cursor = conn.execute("""
                SELECT * FROM policies WHERE active = 1 AND expires_at > ?
            """, (time.time(),))

            count = 0
            for row in cursor:
                policy = self._row_to_policy(row)
                self._cache_put(policy)
                count += 1

            self.logger.info(f"Loaded {count} active policies from database")

    def _row_to_policy(self, row: sqlite3.Row) -> Policy:
        """Convert database row to Policy object"""
        return Policy(
            id=row['id'],
            src_ip=row['src_ip'],
            src_cidr=row['src_cidr'],
            dst_ip=row['dst_ip'],
            dst_port=row['dst_port'],
            protocol=row['protocol'],
            action=row['action'],
            rate_limit_pps=row['rate_limit_pps'],
            rate_limit_bps=row['rate_limit_bps'],
            priority=row['priority'],
            ttl_sec=row['ttl_sec'],
            created_at=row['created_at'],
            expires_at=row['expires_at'],
            source=row['source'],
            confidence=row['confidence'],
            reason=row['reason'],
            active=bool(row['active']),
        )

    def _cache_put(self, policy: Policy):
        """Put policy in in-memory cache"""
        with self._cache_lock:
            self._cache[policy.id] = policy

        # Also put in Redis if available
        if self._redis:
            try:
                key = f"policy:{policy.id}"
                self._redis.setex(
                    key,
                    int(policy.expires_at - time.time()),
                    json.dumps(policy.to_dict())
                )
            except Exception as e:
                self.logger.warning(f"Redis cache put failed: {e}")

    def _cache_remove(self, policy_id: int):
        """Remove policy from cache"""
        with self._cache_lock:
            if policy_id in self._cache:
                del self._cache[policy_id]

        if self._redis:
            try:
                key = f"policy:{policy_id}"
                self._redis.delete(key)
            except Exception as e:
                self.logger.warning(f"Redis cache remove failed: {e}")

    # ==================== Public API ====================

    def add_policy(self, policy_data: Dict) -> Policy:
        """
        Add a new policy with persistence

        Args:
            policy_data: Policy data dict

        Returns:
            Created Policy object
        """
        now = time.time()
        expires_at = now + policy_data.get('ttl_sec', 3600)

        with self._get_db() as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO policies
                (src_ip, src_cidr, dst_ip, dst_port, protocol,
                 action, rate_limit_pps, rate_limit_bps, priority, ttl_sec,
                 created_at, expires_at, source, confidence, reason, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (
                policy_data.get('src_ip'),
                policy_data.get('src_cidr'),
                policy_data.get('dst_ip'),
                policy_data.get('dst_port'),
                policy_data.get('protocol'),
                policy_data['action'],
                policy_data.get('rate_limit_pps'),
                policy_data.get('rate_limit_bps'),
                policy_data.get('priority', 100),
                policy_data.get('ttl_sec', 3600),
                now,
                expires_at,
                policy_data.get('source', 'OPERATOR'),
                policy_data.get('confidence', 1.0),
                policy_data.get('reason', ''),
            ))
            conn.commit()

            policy = Policy(
                id=cursor.lastrowid,
                src_ip=policy_data.get('src_ip'),
                src_cidr=policy_data.get('src_cidr'),
                dst_ip=policy_data.get('dst_ip'),
                dst_port=policy_data.get('dst_port'),
                protocol=policy_data.get('protocol'),
                action=policy_data['action'],
                rate_limit_pps=policy_data.get('rate_limit_pps'),
                rate_limit_bps=policy_data.get('rate_limit_bps'),
                priority=policy_data.get('priority', 100),
                ttl_sec=policy_data.get('ttl_sec', 3600),
                created_at=now,
                expires_at=expires_at,
                source=policy_data.get('source', 'OPERATOR'),
                confidence=policy_data.get('confidence', 1.0),
                reason=policy_data.get('reason', ''),
                active=True,
            )

        self._cache_put(policy)
        self.logger.debug(f"Added policy {policy.id}")
        return policy

    def get_policy(self, policy_id: int) -> Optional[Policy]:
        """Get a specific policy by ID"""
        # Check in-memory cache first
        with self._cache_lock:
            if policy_id in self._cache:
                policy = self._cache[policy_id]
                if not policy.is_expired():
                    return policy

        # Check Redis
        if self._redis:
            try:
                key = f"policy:{policy_id}"
                data = self._redis.get(key)
                if data:
                    policy = Policy.from_dict(json.loads(data))
                    if not policy.is_expired():
                        self._cache_put(policy)
                        return policy
            except Exception as e:
                self.logger.warning(f"Redis get failed: {e}")

        # Fall back to database
        with self._get_db() as conn:
            cursor = conn.execute("""
                SELECT * FROM policies
                WHERE id = ? AND active = 1 AND expires_at > ?
            """, (policy_id, time.time()))
            row = cursor.fetchone()
            if row:
                policy = self._row_to_policy(row)
                self._cache_put(policy)
                return policy

        return None

    def get_policies(self,
                     active_only: bool = True,
                     action: Optional[str] = None) -> List[Policy]:
        """Get all policies"""
        policies = []

        # Try cache first for active policies
        with self._cache_lock:
            for policy in self._cache.values():
                if active_only and policy.is_expired():
                    continue
                if action and policy.action != action:
                    continue
                policies.append(policy)

        # If cache miss or need all, query database
        if not policies or not active_only:
            with self._get_db() as conn:
                query = "SELECT * FROM policies WHERE 1=1"
                params = []

                if active_only:
                    query += " AND active = 1 AND expires_at > ?"
                    params.append(time.time())

                if action:
                    query += " AND action = ?"
                    params.append(action)

                query += " ORDER BY priority ASC, created_at DESC"

                cursor = conn.execute(query, params)
                policies = [self._row_to_policy(row) for row in cursor]

                # Update cache
                for policy in policies:
                    if not policy.is_expired():
                        self._cache_put(policy)

        return policies

    def get_policies_for_ip(self, src_ip: str) -> List[Policy]:
        """Get all policies matching a specific source IP"""
        with self._get_db() as conn:
            cursor = conn.execute("""
                SELECT * FROM policies
                WHERE (src_ip = ? OR src_ip IS NULL)
                AND active = 1 AND expires_at > ?
                ORDER BY priority ASC
            """, (src_ip, time.time()))
            return [self._row_to_policy(row) for row in cursor]

    def update_policy(self, policy_id: int, updates: Dict) -> Optional[Policy]:
        """Update an existing policy"""
        with self._get_db() as conn:
            # Build update query dynamically
            set_clauses = []
            params = []

            allowed_fields = ['action', 'rate_limit_pps', 'rate_limit_bps',
                              'priority', 'ttl_sec', 'reason', 'active']

            for field in allowed_fields:
                if field in updates:
                    set_clauses.append(f"{field} = ?")
                    params.append(updates[field])

            if 'ttl_sec' in updates:
                set_clauses.append("expires_at = ?")
                params.append(time.time() + updates['ttl_sec'])

            if not set_clauses:
                return self.get_policy(policy_id)

            query = f"UPDATE policies SET {', '.join(set_clauses)} WHERE id = ?"
            params.append(policy_id)

            conn.execute(query, params)
            conn.commit()

        # Refresh from database
        policy = self.get_policy(policy_id)
        if policy:
            self._cache_put(policy)
        return policy

    def delete_policy(self, policy_id: int) -> bool:
        """Delete a policy (soft delete - sets active=0)"""
        with self._get_db() as conn:
            cursor = conn.execute("""
                UPDATE policies SET active = 0 WHERE id = ?
            """, (policy_id,))
            conn.commit()
            deleted = cursor.rowcount > 0

        if deleted:
            self._cache_remove(policy_id)
            self.logger.debug(f"Deleted policy {policy_id}")

        return deleted

    def expire_old_policies(self) -> int:
        """Mark expired policies as inactive"""
        now = time.time()
        expired_count = 0

        with self._get_db() as conn:
            cursor = conn.execute("""
                UPDATE policies SET active = 0
                WHERE active = 1 AND expires_at < ?
            """, (now,))
            conn.commit()
            expired_count = cursor.rowcount

        # Clean up cache
        with self._cache_lock:
            for policy_id in list(self._cache.keys()):
                if self._cache[policy_id].is_expired():
                    del self._cache[policy_id]

        if expired_count > 0:
            self.logger.info(f"Expired {expired_count} policies")

        return expired_count

    # ==================== Crash Recovery ====================

    def create_snapshot(self) -> int:
        """Create a snapshot of all active policies"""
        with self._cache_lock:
            all_policies = []
            for policy in self._cache.values():
                if not policy.is_expired():
                    all_policies.append(policy.to_dict())

        snapshot_data = json.dumps(all_policies)

        with self._get_db() as conn:
            conn.execute("""
                INSERT INTO snapshots (timestamp, policy_count, data)
                VALUES (?, ?, ?)
            """, (time.time(), len(all_policies), snapshot_data))
            conn.commit()

            # Keep only last 10 snapshots
            conn.execute("""
                DELETE FROM snapshots WHERE id NOT IN (
                    SELECT id FROM snapshots ORDER BY timestamp DESC LIMIT 10
                )
            """)
            conn.commit()

        self.logger.info(f"Created snapshot with {len(all_policies)} policies")
        return len(all_policies)

    def restore_from_snapshot(self, snapshot_id: Optional[int] = None) -> int:
        """Restore policies from a snapshot"""
        with self._get_db() as conn:
            if snapshot_id:
                cursor = conn.execute(
                    "SELECT * FROM snapshots WHERE id = ?", (snapshot_id,))
            else:
                cursor = conn.execute(
                    "SELECT * FROM snapshots ORDER BY timestamp DESC LIMIT 1")

            row = cursor.fetchone()
            if not row:
                self.logger.warning("No snapshot found to restore")
                return 0

            policies = json.loads(row['data'])

        # Clear current cache and reload
        with self._cache_lock:
            self._cache.clear()

        restored = 0
        for policy_data in policies:
            if policy_data.get('expires_at', 0) > time.time():
                policy = Policy.from_dict(policy_data)
                self._cache_put(policy)
                restored += 1

        self.logger.info(f"Restored {restored} policies from snapshot")
        return restored

    def _start_snapshot_thread(self):
        """Start background snapshot thread"""
        def snapshot_loop():
            while not self._shutdown_flag.is_set():
                self._shutdown_flag.wait(self.snapshot_interval)
                if not self._shutdown_flag.is_set():
                    try:
                        self.expire_old_policies()
                        self.create_snapshot()
                    except Exception as e:
                        self.logger.error(f"Snapshot failed: {e}")

        self._snapshot_thread = threading.Thread(target=snapshot_loop, daemon=True)
        self._snapshot_thread.start()

    def shutdown(self):
        """Shutdown the persistence service"""
        self._shutdown_flag.set()
        if self._snapshot_thread:
            self._snapshot_thread.join(timeout=5)

        # Final snapshot
        try:
            self.create_snapshot()
        except Exception as e:
            self.logger.error(f"Final snapshot failed: {e}")

        self.logger.info("Policy persistence service shutdown complete")

    # ==================== Statistics ====================

    def get_stats(self) -> Dict:
        """Get persistence service statistics"""
        with self._cache_lock:
            cached_count = len(self._cache)

        with self._get_db() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM policies WHERE active = 1")
            db_active = cursor.fetchone()[0]

            cursor = conn.execute("SELECT COUNT(*) FROM policies")
            db_total = cursor.fetchone()[0]

            cursor = conn.execute("SELECT COUNT(*) FROM snapshots")
            snapshot_count = cursor.fetchone()[0]

        return {
            "cache": {
                "policies": cached_count,
            },
            "database": {
                "active_policies": db_active,
                "total_policies": db_total,
                "snapshots": snapshot_count,
            },
            "redis_connected": self._redis is not None,
        }


# Global instance
_persistence_service: Optional[PolicyPersistenceService] = None


def get_persistence_service() -> PolicyPersistenceService:
    """Get the global persistence service instance"""
    global _persistence_service
    if _persistence_service is None:
        db_path = os.environ.get("POLICY_DB_PATH", "data/policies.db")
        redis_url = os.environ.get("REDIS_URL")
        _persistence_service = PolicyPersistenceService(
            db_path=db_path,
            redis_url=redis_url,
        )
    return _persistence_service


def shutdown_persistence_service():
    """Shutdown the global persistence service"""
    global _persistence_service
    if _persistence_service:
        _persistence_service.shutdown()
        _persistence_service = None
