"""
Policy repository for DDoS mitigation policy management.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from sqlalchemy import func, and_, or_
from sqlalchemy.orm import Session

from ..models import Policy, PolicyAction, PolicySource
from .base import BaseRepository, DuplicateError


class PolicyRepository(BaseRepository[Policy]):
    """Repository for policy management."""

    def __init__(self, db: Session):
        super().__init__(Policy, db)

    def get_by_name(self, name: str) -> Optional[Policy]:
        """Get policy by name."""
        return (
            self.db.query(Policy)
            .filter(Policy.name == name)
            .first()
        )

    def list_policies(
        self,
        enabled_only: bool = False,
        action: Optional[PolicyAction] = None,
        source: Optional[PolicySource] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Policy]:
        """List policies with filters."""
        query = self.db.query(Policy)

        if enabled_only:
            query = query.filter(Policy.enabled == True)
        if action:
            query = query.filter(Policy.action == action)
        if source:
            query = query.filter(Policy.source == source)

        return query.order_by(Policy.priority).offset(skip).limit(limit).all()

    def list_active(self) -> List[Policy]:
        """Get active, non-expired policies ordered by priority."""
        now = datetime.utcnow()
        return (
            self.db.query(Policy)
            .filter(
                Policy.enabled == True,
                or_(Policy.expires_at == None, Policy.expires_at > now),
            )
            .order_by(Policy.priority)
            .all()
        )

    def count_policies(self, enabled_only: bool = False) -> int:
        """Count policies."""
        query = self.db.query(func.count(Policy.id))
        if enabled_only:
            query = query.filter(Policy.enabled == True)
        return query.scalar() or 0

    def create_policy(
        self,
        name: str,
        action: PolicyAction,
        conditions: Optional[dict] = None,
        priority: int = 100,
        description: Optional[str] = None,
        rate_limit_pps: Optional[int] = None,
        rate_limit_bps: Optional[int] = None,
        expires_at: Optional[datetime] = None,
        source: PolicySource = PolicySource.MANUAL,
        confidence: Optional[float] = None,
        created_by: Optional[str] = None,
    ) -> Policy:
        """Create a new policy."""
        if self.get_by_name(name):
            raise DuplicateError(f"Policy '{name}' already exists")

        policy = Policy(
            name=name,
            action=action,
            conditions=conditions or {},
            priority=priority,
            description=description,
            rate_limit_pps=rate_limit_pps,
            rate_limit_bps=rate_limit_bps,
            expires_at=expires_at,
            source=source,
            confidence=confidence,
            created_by=created_by,
        )
        self.db.add(policy)
        self.db.commit()
        self.db.refresh(policy)
        return policy

    def toggle_enabled(self, policy_id: int) -> Optional[Policy]:
        """Toggle policy enabled state."""
        policy = self.get(policy_id)
        if policy:
            policy.enabled = not policy.enabled
            policy.updated_at = datetime.utcnow()
            self.db.commit()
            self.db.refresh(policy)
        return policy

    def increment_hit_count(self, policy_id: int) -> None:
        """Increment policy hit counter."""
        self.db.query(Policy).filter(Policy.id == policy_id).update(
            {
                "hit_count": Policy.hit_count + 1,
                "last_hit_at": datetime.utcnow(),
            }
        )
        self.db.commit()

    def delete_expired(self) -> int:
        """Delete all expired policies."""
        now = datetime.utcnow()
        result = (
            self.db.query(Policy)
            .filter(Policy.expires_at != None, Policy.expires_at < now)
            .delete()
        )
        self.db.commit()
        return result

    def delete_all(self) -> int:
        """Delete all policies."""
        result = (
            self.db.query(Policy)
            .delete()
        )
        self.db.commit()
        return result

    def get_ml_policies(self) -> List[Policy]:
        """Get ML-generated policies."""
        return (
            self.db.query(Policy)
            .filter(
                Policy.source == PolicySource.ML,
            )
            .order_by(Policy.created_at.desc())
            .all()
        )
