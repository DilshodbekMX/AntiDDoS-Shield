"""
Security Service (Database Persistence)

Business logic for blacklist/whitelist, attacks, and IP investigation.
Uses SQLAlchemy repository for persistent storage.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, List, Tuple, Dict, Any
import ipaddress

from sqlalchemy.orm import Session

from ..models import (
    IPListEntry as IPListEntrySchema,
    IPListEntryCreate,
    IPListBulkAdd,
    IPListType,
    Attack,
    AttackSummary,
    AttackType,
    AttackSeverity
)
from ..database import get_db, init_db
from ..database.models import (
    IPListEntry as IPListEntryModel,
    IPListType as DBIPListType,
    Attack as AttackModel,
    AttackType as DBAttackType,
    AttackSeverity as DBAttackSeverity
)
from ..database.repositories.iplist_repo import IPListRepository
from ..database.repositories.attack_repo import AttackRepository
from .dataplane_service import get_dataplane_service

logger = logging.getLogger(__name__)


class SecurityService:
    """
    Service layer for security operations.

    Uses SQLAlchemy repositories for persistent storage with
    real-time sync to C data plane via socket.
    """

    def __init__(self, db: Optional[Session] = None):
        self._db = db
        self._db_initialized = False

    def _get_db(self) -> Session:
        """Get database session, initializing if needed.

        Creates a fresh SessionLocal() instead of next(get_db()) to avoid:
        1. Generator leak (session never closed when generator not exhausted)
        2. Async-unsafe session sharing between concurrent coroutines
        """
        if not self._db_initialized:
            try:
                init_db()
                self._db_initialized = True
            except Exception as e:
                logger.warning(f"Database init warning: {e}")
        if self._db:
            return self._db
        from ..database.connection import SessionLocal
        return SessionLocal()

    def _get_iplist_repo(self) -> IPListRepository:
        """Get IP list repository."""
        return IPListRepository(self._get_db())

    # ==================== Model Conversion ====================

    def _parse_ip_cidr(self, ip: str) -> Tuple[str, int]:
        """Parse IP/CIDR string into address and prefix length."""
        if '/' in ip:
            ip_addr, prefix_str = ip.rsplit('/', 1)
            return ip_addr, int(prefix_str)
        return ip, 32

    def _format_ip_cidr(self, ip_address: str, prefix_len: int) -> str:
        """Format IP address and prefix length to IP/CIDR string."""
        if prefix_len == 32:
            return ip_address
        return f"{ip_address}/{prefix_len}"

    def _schema_to_db_list_type(self, list_type: IPListType) -> DBIPListType:
        """Convert Pydantic IPListType to SQLAlchemy enum."""
        return DBIPListType(list_type.value)

    def _db_entry_to_schema(self, db_entry: IPListEntryModel, list_type: IPListType) -> IPListEntrySchema:
        """Convert SQLAlchemy IPListEntry to Pydantic schema."""
        now = datetime.utcnow()
        is_expired = db_entry.expires_at is not None and db_entry.expires_at <= now

        return IPListEntrySchema(
            id=db_entry.id,
            list_type=list_type,
            ip=self._format_ip_cidr(db_entry.ip_address, db_entry.prefix_len),
            description=db_entry.description,
            expires_at=db_entry.expires_at,
            created_at=db_entry.created_at,
            created_by=db_entry.created_by or "system",
            hit_count=db_entry.hit_count or 0,
            last_hit_at=db_entry.last_hit_at,
            is_expired=is_expired
        )

    # ==================== IP Lists ====================

    async def get_ip_list(
        self,
        list_type: IPListType,
        search: Optional[str] = None,
        include_expired: bool = False,
        page: int = 1,
        per_page: int = 50
    ) -> Tuple[List[IPListEntrySchema], int]:
        """Get IP list entries with filtering and pagination."""
        repo = self._get_iplist_repo()
        db_list_type = self._schema_to_db_list_type(list_type)

        # If searching, use search method
        if search:
            db_entries = repo.search(
                query=search,
                list_type=db_list_type,
                limit=per_page * page  # Get enough for pagination
            )
            # Filter expired if needed
            if not include_expired:
                now = datetime.utcnow()
                db_entries = [
                    e for e in db_entries
                    if e.expires_at is None or e.expires_at > now
                ]
            total = len(db_entries)
            # Paginate in memory for search
            start = (page - 1) * per_page
            end = start + per_page
            db_entries = db_entries[start:end]
        else:
            # Use optimized repository methods
            total = repo.count_by_type(
                list_type=db_list_type,
                include_expired=include_expired
            )
            skip = (page - 1) * per_page
            db_entries = repo.list_by_type(
                list_type=db_list_type,
                include_expired=include_expired,
                skip=skip,
                limit=per_page
            )

        # Convert to Pydantic schemas
        entries = [self._db_entry_to_schema(e, list_type) for e in db_entries]

        return entries, total

    async def get_ip_entry(
        self,
        list_type: IPListType,
        ip: str
    ) -> Optional[IPListEntrySchema]:
        """Get a specific IP entry."""
        repo = self._get_iplist_repo()
        db_list_type = self._schema_to_db_list_type(list_type)

        ip_addr, prefix_len = self._parse_ip_cidr(ip)
        db_entry = repo.get_entry(
            list_type=db_list_type,
            ip_address=ip_addr,
            prefix_len=prefix_len
        )

        if db_entry:
            return self._db_entry_to_schema(db_entry, list_type)
        return None

    async def add_to_list(
        self,
        list_type: IPListType,
        entry_data: IPListEntryCreate,
        added_by: str,
        check_quota: bool = True,
    ) -> IPListEntrySchema:
        """Add an IP to a list.

        Quota check is done atomically with insertion to prevent TOCTOU races.
        """
        repo = self._get_iplist_repo()
        db_list_type = self._schema_to_db_list_type(list_type)

        # Atomic quota check + insert (prevents TOCTOU race from router-level check)
        if check_quota and not await self.check_list_quota(list_type):
            raise ValueError(f"{list_type.value} quota exceeded")

        # Parse IP and prefix
        ip_addr, prefix_len = self._parse_ip_cidr(entry_data.ip)

        # Calculate expiry
        expires_at = None
        if entry_data.duration_seconds and entry_data.duration_seconds > 0:
            expires_at = datetime.utcnow() + timedelta(seconds=entry_data.duration_seconds)
        elif entry_data.expires_at:
            expires_at = entry_data.expires_at

        # Check if already exists (repo will raise DuplicateError)
        try:
            db_entry = repo.add_entry(
                list_type=db_list_type,
                ip_address=ip_addr,
                prefix_len=prefix_len,
                description=entry_data.description,
                expires_at=expires_at,
                created_by=added_by,
                source="api"
            )
        except Exception as e:
            # Check if it's a duplicate
            if "already in" in str(e).lower() or "duplicate" in str(e).lower():
                raise ValueError(f"IP {entry_data.ip} already exists in {list_type.value}")
            raise

        # Push to data plane -- rollback DB on failure to stay consistent
        if not self._push_ip_to_dataplane(entry_data.ip, list_type, add=True):
            try:
                repo.remove_entry(
                    list_type=db_list_type,
                    ip_address=ip_addr,
                    prefix_len=prefix_len
                )
            except Exception:
                logger.error(f"Rollback also failed for {entry_data.ip} in {list_type.value}")
            raise RuntimeError(f"Failed to push {entry_data.ip} to data plane, DB entry rolled back")

        logger.info(f"Added {entry_data.ip} to {list_type.value} by {added_by}")
        return self._db_entry_to_schema(db_entry, list_type)

    async def bulk_add_to_list(
        self,
        list_type: IPListType,
        bulk_data: IPListBulkAdd,
        added_by: str
    ) -> Dict[str, int]:
        """Bulk add IPs to a list."""
        repo = self._get_iplist_repo()
        db_list_type = self._schema_to_db_list_type(list_type)

        # Calculate expiry
        expires_at = None
        if bulk_data.duration_seconds and bulk_data.duration_seconds > 0:
            expires_at = datetime.utcnow() + timedelta(seconds=bulk_data.duration_seconds)

        # Separate IPs with prefixes
        ip_addresses = []
        for ip in bulk_data.ips:
            ip_addr, prefix_len = self._parse_ip_cidr(ip)
            # For bulk add, we only support /32 for simplicity
            # (the repository's bulk_add assumes /32)
            if prefix_len != 32:
                # Add individually for non-/32 prefixes
                try:
                    await self.add_to_list(
                        list_type=list_type,
                        entry_data=IPListEntryCreate(
                            ip=ip,
                            description=bulk_data.description,
                            duration_seconds=bulk_data.duration_seconds
                        ),
                        added_by=added_by
                    )
                except ValueError:
                    pass  # Skip duplicates
            else:
                ip_addresses.append(ip_addr)

        # Bulk add /32 IPs
        added = repo.bulk_add(
            list_type=db_list_type,
            ip_addresses=ip_addresses,
            reason=bulk_data.description,
            expires_at=expires_at,
            created_by=added_by
        )

        skipped = len(ip_addresses) - added

        # Push to data plane -- log failures but don't rollback bulk ops
        push_failures = 0
        for ip in bulk_data.ips:
            if not self._push_ip_to_dataplane(ip, list_type, add=True):
                push_failures += 1
        if push_failures > 0:
            logger.error(f"Bulk add: {push_failures}/{len(bulk_data.ips)} failed to push to data plane")

        return {
            "added": added + (len(bulk_data.ips) - len(ip_addresses)),
            "skipped": skipped,
            "dataplane_failures": push_failures,
        }

    async def remove_from_list(
        self,
        list_type: IPListType,
        ip: str
    ) -> bool:
        """Remove an IP from a list."""
        repo = self._get_iplist_repo()
        db_list_type = self._schema_to_db_list_type(list_type)

        ip_addr, prefix_len = self._parse_ip_cidr(ip)
        removed = repo.remove_entry(
            list_type=db_list_type,
            ip_address=ip_addr,
            prefix_len=prefix_len
        )

        if removed:
            # Push to data plane -- warn but don't re-add on failure
            # (stale dataplane entry is less dangerous than stale DB entry)
            if not self._push_ip_to_dataplane(ip, list_type, add=False):
                logger.warning(f"Removed {ip} from DB but dataplane push failed — entry may persist in dataplane until restart")
            else:
                logger.info(f"Removed {ip} from {list_type.value}")

        return removed

    async def check_list_quota(
        self,
        list_type: IPListType
    ) -> bool:
        """Check if there is quota for more entries."""
        repo = self._get_iplist_repo()
        db_list_type = self._schema_to_db_list_type(list_type)

        current_count = repo.count_by_type(
            list_type=db_list_type,
            include_expired=False
        )

        # Default quotas
        quotas = {
            IPListType.BLACKLIST: 10000,
            IPListType.WHITELIST: 1000,
            IPListType.GREYLIST: 5000,
        }

        return current_count < quotas.get(list_type, 1000)

    async def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted."""
        repo = self._get_iplist_repo()
        ip_addr, _ = self._parse_ip_cidr(ip)
        return repo.is_whitelisted(ip_addr)

    async def is_blacklisted(self, ip: str) -> bool:
        """Check if IP is blacklisted."""
        repo = self._get_iplist_repo()
        ip_addr, _ = self._parse_ip_cidr(ip)
        return repo.is_blacklisted(ip_addr)

    # ==================== Attacks ====================

    def _get_attack_repo(self) -> AttackRepository:
        """Get attack repository."""
        return AttackRepository(self._get_db())

    def _db_attack_to_summary(self, db_attack: AttackModel) -> AttackSummary:
        """Convert DB Attack to Pydantic AttackSummary."""
        return AttackSummary(
            id=str(db_attack.id),
            attack_type=AttackType(db_attack.attack_type.value),
            severity=AttackSeverity(db_attack.severity.value),
            target_ip=db_attack.target_ip,
            started_at=db_attack.started_at,
            ended_at=db_attack.ended_at,
            is_active=db_attack.is_active,
            mitigated=db_attack.is_mitigated,
            peak_pps=db_attack.peak_pps or 0,
            peak_bps=db_attack.peak_bps or 0,
        )

    def _db_attack_to_full(self, db_attack: AttackModel) -> Attack:
        """Convert DB Attack to full Pydantic Attack."""
        duration = None
        if db_attack.ended_at and db_attack.started_at:
            duration = int((db_attack.ended_at - db_attack.started_at).total_seconds())

        return Attack(
            id=str(db_attack.id),
            attack_type=AttackType(db_attack.attack_type.value),
            severity=AttackSeverity(db_attack.severity.value),
            target_ip=db_attack.target_ip,
            target_port=db_attack.target_port,
            source_ips_count=db_attack.source_ips_count or 0,
            peak_pps=db_attack.peak_pps or 0,
            peak_bps=db_attack.peak_bps or 0,
            started_at=db_attack.started_at,
            ended_at=db_attack.ended_at,
            duration_seconds=duration,
            is_active=db_attack.is_active,
            mitigated=db_attack.is_mitigated,
            mitigation_time_ms=db_attack.mitigation_time_ms,
            total_packets_dropped=db_attack.packets_dropped or 0,
            total_bytes_dropped=db_attack.bytes_dropped or 0,
            top_source_ips=db_attack.top_source_ips or [],
            signatures_matched=db_attack.signatures_matched or [],
            ml_confidence=db_attack.ml_confidence,
        )

    async def get_attacks(
        self,
        is_active: Optional[bool] = None,
        attack_type: Optional[AttackType] = None,
        severity: Optional[AttackSeverity] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        page: int = 1,
        per_page: int = 20
    ) -> Tuple[List[AttackSummary], int]:
        """Get attack history with filtering."""
        repo = self._get_attack_repo()

        # Map Pydantic enums to DB enums for filtering
        db_attack_type = DBAttackType(attack_type.value) if attack_type else None
        db_severity = DBAttackSeverity(severity.value) if severity else None

        db_attacks = repo.list_attacks(
            attack_type=db_attack_type,
            severity=db_severity,
            is_active=is_active,
            start_date=start_date,
            end_date=end_date,
            skip=(page - 1) * per_page,
            limit=per_page,
        )

        total = repo.count_attacks(
            is_active=is_active,
            since=start_date,
        )

        summaries = [self._db_attack_to_summary(a) for a in db_attacks]
        return summaries, total

    async def get_active_attacks(self) -> List[Attack]:
        """Get currently active attacks."""
        repo = self._get_attack_repo()
        db_attacks = repo.get_active_attacks()
        return [self._db_attack_to_full(a) for a in db_attacks]

    async def get_attack(
        self,
        attack_id: str
    ) -> Optional[Attack]:
        """Get detailed attack information."""
        repo = self._get_attack_repo()
        db_attack = repo.get(attack_id)
        if not db_attack:
            return None
        return self._db_attack_to_full(db_attack)

    async def get_attack_sources(
        self,
        attack_id: str,
        limit: int
    ) -> List[Dict[str, Any]]:
        """Get top source IPs for an attack from DB."""
        repo = self._get_attack_repo()
        db_attack = repo.get(attack_id)
        if not db_attack or not db_attack.top_source_ips:
            return []

        sources = []
        for ip in db_attack.top_source_ips[:limit]:
            sources.append({
                "ip": ip,
                "packets": 0,
                "bytes": 0,
                "country": "Unknown",
                "first_seen": db_attack.started_at,
                "last_seen": db_attack.ended_at or datetime.utcnow(),
            })
        return sources

    async def trigger_mitigation(
        self,
        attack_id: str,
        action: str,
        triggered_by: str
    ) -> Dict[str, Any]:
        """Trigger manual mitigation action."""
        attack = await self.get_attack(attack_id)
        if not attack:
            return {"success": False, "error": "Attack not found"}

        # Trigger mitigation in data plane
        dp = get_dataplane_service()
        if action == "block_sources" and attack.top_source_ips:
            for src_ip in attack.top_source_ips[:10]:  # Block top 10 sources
                dp.add_to_blacklist(src_ip, 32)
        elif action == "reload_config":
            dp.reload_config()

        logger.info(f"Mitigation triggered for attack {attack_id}: {action} by {triggered_by}")

        return {
            "success": True,
            "action": action,
            "attack_id": attack_id,
            "timestamp": datetime.utcnow().isoformat(),
        }

    # ==================== IP Investigation ====================

    async def investigate_ip(
        self,
        ip: str
    ) -> Dict[str, Any]:
        """Investigate an IP address."""
        ip_addr, _ = self._parse_ip_cidr(ip)

        # Check list membership via repository
        in_blacklist = await self.is_blacklisted(ip_addr)
        in_whitelist = await self.is_whitelisted(ip_addr)

        repo = self._get_iplist_repo()
        db_greylist_type = self._schema_to_db_list_type(IPListType.GREYLIST)
        greylist_entry = repo.get_entry(db_greylist_type, ip_addr, 32)
        in_greylist = greylist_entry is not None

        # Check attack history from DB
        attack_repo = self._get_attack_repo()
        attacks_as_target = attack_repo.get_by_target_ip(ip_addr)
        last_attack_time = attacks_as_target[0].started_at if attacks_as_target else None

        return {
            "ip": ip,
            "list_membership": {
                "blacklist": in_blacklist,
                "whitelist": in_whitelist,
                "greylist": in_greylist,
            },
            "reputation": {
                "score": 0.0,
                "category": "unknown",
                "confidence": 0.0,
            },
            "traffic_summary": {
                "packets_24h": 0,
                "bytes_24h": 0,
                "first_seen": None,
                "last_seen": None,
            },
            "attack_involvement": {
                "attacks_as_target": len(attacks_as_target),
                "last_attack": last_attack_time,
            },
            "geolocation": {
                "country": "Unknown",
                "city": "Unknown",
                "asn": "Unknown",
                "organization": "Unknown",
            },
        }

    # ==================== Data Plane Integration ====================

    def _push_ip_to_dataplane(self, ip: str, list_type: IPListType, add: bool) -> bool:
        """Push IP list change to the data plane.

        Returns:
            True if push succeeded, False on failure.
        """
        try:
            dp = get_dataplane_service()

            # Parse prefix length if CIDR
            ip_addr, prefix_len = self._parse_ip_cidr(ip)

            if list_type == IPListType.BLACKLIST:
                if add:
                    dp.add_to_blacklist(ip_addr, prefix_len)
                else:
                    dp.remove_from_blacklist(ip_addr, prefix_len)
            elif list_type == IPListType.WHITELIST:
                if add:
                    dp.add_to_whitelist(ip_addr, prefix_len)
                else:
                    dp.remove_from_whitelist(ip_addr, prefix_len)
            # Greylist is handled differently (reputation-based, not direct block)

            logger.debug(f"Pushed IP {ip} to data plane: {list_type} add={add}")
            return True
        except Exception as e:
            logger.error(f"Failed to push IP to data plane (ip={ip}, list={list_type}, add={add}): {e}")
            return False


# Singleton instance
_security_service = None

def get_security_service() -> SecurityService:
    """Get or create the security service singleton."""
    global _security_service
    if _security_service is None:
        _security_service = SecurityService()
    return _security_service
