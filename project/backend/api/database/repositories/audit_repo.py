"""
Audit log repository for security audit trail.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import AuditLog
from .base import BaseRepository


class AuditLogRepository(BaseRepository[AuditLog]):
    """Repository for audit log management."""

    def __init__(self, db: Session):
        super().__init__(AuditLog, db)

    def log(
        self,
        action: str,
        resource_type: str,
        user_id: Optional[str] = None,
        user_name: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_name: Optional[str] = None,
        details: Optional[dict] = None,
        old_value: Optional[dict] = None,
        new_value: Optional[dict] = None,
        success: bool = True,
        error_message: Optional[str] = None,
    ) -> AuditLog:
        """Create an audit log entry."""
        entry = AuditLog(
            user_id=user_id,
            user_name=user_name,
            ip_address=ip_address,
            user_agent=user_agent,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            details=details,
            old_value=old_value,
            new_value=new_value,
            success=success,
            error_message=error_message,
        )
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry

    def list_logs(
        self,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        user_id: Optional[str] = None,
        success: Optional[bool] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditLog]:
        """List audit logs with filters."""
        query = self.db.query(AuditLog)

        if action:
            query = query.filter(AuditLog.action == action)
        if resource_type:
            query = query.filter(AuditLog.resource_type == resource_type)
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if success is not None:
            query = query.filter(AuditLog.success == success)
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)

        return query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()

    def list_by_user(
        self,
        user_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditLog]:
        """List audit logs for a user."""
        query = self.db.query(AuditLog).filter(AuditLog.user_id == user_id)

        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)

        return query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()

    def count_logs(
        self,
        action: Optional[str] = None,
        success: Optional[bool] = None,
    ) -> int:
        """Count audit logs."""
        query = self.db.query(func.count(AuditLog.id))
        if action:
            query = query.filter(AuditLog.action == action)
        if success is not None:
            query = query.filter(AuditLog.success == success)
        return query.scalar() or 0

    def get_recent_failures(
        self,
        hours: int = 24,
        limit: int = 100,
    ) -> List[AuditLog]:
        """Get recent failed actions."""
        since = datetime.utcnow() - timedelta(hours=hours)
        query = self.db.query(AuditLog).filter(
            AuditLog.success == False,
            AuditLog.timestamp >= since,
        )

        return query.order_by(AuditLog.timestamp.desc()).limit(limit).all()

    def get_login_attempts(
        self,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        hours: int = 24,
    ) -> List[AuditLog]:
        """Get login attempts for security analysis."""
        since = datetime.utcnow() - timedelta(hours=hours)
        query = self.db.query(AuditLog).filter(
            AuditLog.action.in_(["login", "login_failed", "logout"]),
            AuditLog.timestamp >= since,
        )

        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if ip_address:
            query = query.filter(AuditLog.ip_address == ip_address)

        return query.order_by(AuditLog.timestamp.desc()).all()

    def get_stats(
        self,
        days: int = 7,
    ) -> Dict[str, Any]:
        """Get audit log statistics."""
        since = datetime.utcnow() - timedelta(days=days)

        query = self.db.query(AuditLog).filter(
            AuditLog.timestamp >= since,
        )

        logs = query.all()

        stats = {
            "total": len(logs),
            "success": sum(1 for l in logs if l.success),
            "failed": sum(1 for l in logs if not l.success),
            "by_action": {},
            "by_resource": {},
            "by_user": {},
        }

        for log in logs:
            # By action
            stats["by_action"][log.action] = stats["by_action"].get(log.action, 0) + 1
            # By resource
            stats["by_resource"][log.resource_type] = stats["by_resource"].get(log.resource_type, 0) + 1
            # By user
            if log.user_id:
                stats["by_user"][log.user_id] = stats["by_user"].get(log.user_id, 0) + 1

        return stats

    def delete_old_logs(self, days: int = 365) -> int:
        """Delete logs older than N days."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        result = (
            self.db.query(AuditLog)
            .filter(AuditLog.timestamp < cutoff)
            .delete()
        )
        self.db.commit()
        return result

    def search(
        self,
        query: str,
        limit: int = 100,
    ) -> List[AuditLog]:
        """Search audit logs."""
        from sqlalchemy import or_

        search_term = f"%{query}%"
        db_query = self.db.query(AuditLog).filter(
            or_(
                AuditLog.action.ilike(search_term),
                AuditLog.resource_type.ilike(search_term),
                AuditLog.resource_name.ilike(search_term),
                AuditLog.user_name.ilike(search_term),
            )
        )

        return db_query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
