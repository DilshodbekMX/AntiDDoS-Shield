"""
IP list repository for whitelist/blacklist/greylist management.
"""

from typing import Optional, List
from datetime import datetime

from sqlalchemy import func, and_, or_
from sqlalchemy.orm import Session

from ..models import IPListEntry, IPListType
from .base import BaseRepository, DuplicateError


class IPListRepository(BaseRepository[IPListEntry]):
    """Repository for IP list management."""

    def __init__(self, db: Session):
        super().__init__(IPListEntry, db)

    def get_entry(
        self,
        list_type: IPListType,
        ip_address: str,
        prefix_len: int = 32,
    ) -> Optional[IPListEntry]:
        """Get specific IP list entry."""
        return (
            self.db.query(IPListEntry)
            .filter(
                IPListEntry.list_type == list_type,
                IPListEntry.ip_address == ip_address,
                IPListEntry.prefix_len == prefix_len,
            )
            .first()
        )

    def list_by_type(
        self,
        list_type: IPListType,
        include_expired: bool = False,
        skip: int = 0,
        limit: int = 100,
    ) -> List[IPListEntry]:
        """List entries of a specific type."""
        query = self.db.query(IPListEntry).filter(
            IPListEntry.list_type == list_type,
        )

        if not include_expired:
            now = datetime.utcnow()
            query = query.filter(
                or_(
                    IPListEntry.expires_at == None,
                    IPListEntry.expires_at > now,
                )
            )

        return query.order_by(IPListEntry.created_at.desc()).offset(skip).limit(limit).all()

    def count_by_type(
        self,
        list_type: IPListType,
        include_expired: bool = False,
    ) -> int:
        """Count entries by type."""
        query = self.db.query(func.count(IPListEntry.id)).filter(
            IPListEntry.list_type == list_type,
        )

        if not include_expired:
            now = datetime.utcnow()
            query = query.filter(
                or_(
                    IPListEntry.expires_at == None,
                    IPListEntry.expires_at > now,
                )
            )

        return query.scalar() or 0

    def add_entry(
        self,
        list_type: IPListType,
        ip_address: str,
        prefix_len: int = 32,
        description: Optional[str] = None,
        reason: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        created_by: Optional[str] = None,
        source: Optional[str] = "manual",
    ) -> IPListEntry:
        """Add IP to list."""
        existing = self.get_entry(list_type, ip_address, prefix_len)
        if existing:
            raise DuplicateError(f"IP {ip_address}/{prefix_len} already in {list_type.value}")

        entry = IPListEntry(
            list_type=list_type,
            ip_address=ip_address,
            prefix_len=prefix_len,
            description=description,
            reason=reason,
            expires_at=expires_at,
            is_permanent=expires_at is None,
            created_by=created_by,
            source=source,
        )
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry

    def remove_entry(
        self,
        list_type: IPListType,
        ip_address: str,
        prefix_len: int = 32,
    ) -> bool:
        """Remove IP from list."""
        result = (
            self.db.query(IPListEntry)
            .filter(
                IPListEntry.list_type == list_type,
                IPListEntry.ip_address == ip_address,
                IPListEntry.prefix_len == prefix_len,
            )
            .delete()
        )
        self.db.commit()
        return result > 0

    def clear_list(self, list_type: IPListType) -> int:
        """Clear all entries of a type."""
        result = (
            self.db.query(IPListEntry)
            .filter(
                IPListEntry.list_type == list_type,
            )
            .delete()
        )
        self.db.commit()
        return result

    def check_ip(
        self,
        ip_address: str,
    ) -> Optional[IPListEntry]:
        """Check if IP is in any list (returns first match)."""
        now = datetime.utcnow()
        return (
            self.db.query(IPListEntry)
            .filter(
                IPListEntry.ip_address == ip_address,
                or_(
                    IPListEntry.expires_at == None,
                    IPListEntry.expires_at > now,
                ),
            )
            .first()
        )

    def is_whitelisted(self, ip_address: str) -> bool:
        """Check if IP is whitelisted."""
        entry = self.get_entry(IPListType.WHITELIST, ip_address)
        if entry and (entry.expires_at is None or entry.expires_at > datetime.utcnow()):
            return True
        return False

    def is_blacklisted(self, ip_address: str) -> bool:
        """Check if IP is blacklisted."""
        entry = self.get_entry(IPListType.BLACKLIST, ip_address)
        if entry and (entry.expires_at is None or entry.expires_at > datetime.utcnow()):
            return True
        return False

    def increment_hit_count(self, entry_id: int) -> None:
        """Increment hit counter for entry."""
        self.db.query(IPListEntry).filter(IPListEntry.id == entry_id).update(
            {
                "hit_count": IPListEntry.hit_count + 1,
                "last_hit_at": datetime.utcnow(),
            }
        )
        self.db.commit()

    def delete_expired(self) -> int:
        """Delete all expired entries."""
        now = datetime.utcnow()
        result = (
            self.db.query(IPListEntry)
            .filter(
                IPListEntry.expires_at != None,
                IPListEntry.expires_at < now,
                IPListEntry.is_permanent == False,
            )
            .delete()
        )
        self.db.commit()
        return result

    def search(
        self,
        query: str,
        list_type: Optional[IPListType] = None,
        limit: int = 50,
    ) -> List[IPListEntry]:
        """Search IP list entries."""
        search_term = f"%{query}%"
        db_query = self.db.query(IPListEntry).filter(
            or_(
                IPListEntry.ip_address.like(search_term),
                IPListEntry.description.ilike(search_term),
                IPListEntry.reason.ilike(search_term),
            ),
        )

        if list_type:
            db_query = db_query.filter(IPListEntry.list_type == list_type)

        return db_query.limit(limit).all()

    def bulk_add(
        self,
        list_type: IPListType,
        ip_addresses: List[str],
        reason: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        created_by: Optional[str] = None,
    ) -> int:
        """Bulk add IPs to list (skips duplicates)."""
        added = 0
        for ip in ip_addresses:
            try:
                self.add_entry(
                    list_type=list_type,
                    ip_address=ip,
                    reason=reason,
                    expires_at=expires_at,
                    created_by=created_by,
                )
                added += 1
            except DuplicateError:
                pass
        return added
