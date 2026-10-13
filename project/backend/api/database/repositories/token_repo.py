"""
API token repository for token management.
"""

import hashlib
import secrets
from typing import Optional, List
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import APIToken
from .base import BaseRepository


class APITokenRepository(BaseRepository[APIToken]):
    """Repository for API token management."""

    def __init__(self, db: Session):
        super().__init__(APIToken, db)

    @staticmethod
    def generate_token() -> tuple[str, str, str]:
        """
        Generate a new API token.

        Returns:
            Tuple of (full_token, prefix, hash)
        """
        token = f"adx_{secrets.token_hex(32)}"
        prefix = token[:12]
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return token, prefix, token_hash

    @staticmethod
    def hash_token(token: str) -> str:
        """Hash a token for storage/lookup."""
        return hashlib.sha256(token.encode()).hexdigest()

    def get_by_hash(self, token_hash: str) -> Optional[APIToken]:
        """Get token by its hash."""
        return (
            self.db.query(APIToken)
            .filter(APIToken.token_hash == token_hash, APIToken.is_active == True)
            .first()
        )

    def verify_token(self, token: str) -> Optional[APIToken]:
        """Verify a token and return the token record if valid."""
        token_hash = self.hash_token(token)
        api_token = self.get_by_hash(token_hash)

        if not api_token:
            return None

        # Check expiration
        if api_token.expires_at and api_token.expires_at < datetime.utcnow():
            return None

        return api_token

    def list_tokens(
        self,
        include_revoked: bool = False,
        skip: int = 0,
        limit: int = 100,
    ) -> List[APIToken]:
        """List tokens."""
        query = self.db.query(APIToken)

        if not include_revoked:
            query = query.filter(APIToken.is_active == True)

        return query.order_by(APIToken.created_at.desc()).offset(skip).limit(limit).all()

    def count_tokens(self, active_only: bool = True) -> int:
        """Count tokens."""
        query = self.db.query(func.count(APIToken.id))
        if active_only:
            query = query.filter(APIToken.is_active == True)
        return query.scalar() or 0

    def create_token(
        self,
        name: str,
        permissions: Optional[List[str]] = None,
        expires_at: Optional[datetime] = None,
        created_by: Optional[str] = None,
    ) -> tuple[APIToken, str]:
        """
        Create a new API token.

        Returns:
            Tuple of (APIToken record, plain_text_token)
        """
        token, prefix, token_hash = self.generate_token()

        api_token = APIToken(
            name=name,
            token_prefix=prefix,
            token_hash=token_hash,
            permissions=permissions or ["read"],
            expires_at=expires_at,
            created_by=created_by,
        )
        self.db.add(api_token)
        self.db.commit()
        self.db.refresh(api_token)

        return api_token, token

    def revoke_token(
        self,
        token_id: str,
        revoked_by: Optional[str] = None,
    ) -> Optional[APIToken]:
        """Revoke a token."""
        api_token = self.get(token_id)
        if api_token:
            api_token.is_active = False
            api_token.revoked_at = datetime.utcnow()
            api_token.revoked_by = revoked_by
            self.db.commit()
            self.db.refresh(api_token)
        return api_token

    def record_usage(
        self,
        token_id: str,
        ip_address: Optional[str] = None,
    ) -> None:
        """Record token usage."""
        self.db.query(APIToken).filter(APIToken.id == token_id).update(
            {
                "last_used_at": datetime.utcnow(),
                "last_used_ip": ip_address,
                "use_count": APIToken.use_count + 1,
            }
        )
        self.db.commit()

    def delete_expired(self) -> int:
        """Delete all expired tokens."""
        now = datetime.utcnow()
        result = (
            self.db.query(APIToken)
            .filter(APIToken.expires_at != None, APIToken.expires_at < now)
            .delete()
        )
        self.db.commit()
        return result

    def get_admin_tokens(self) -> List[APIToken]:
        """Get tokens with admin permissions."""
        return (
            self.db.query(APIToken)
            .filter(
                APIToken.is_active == True,
            )
            .all()
        )
