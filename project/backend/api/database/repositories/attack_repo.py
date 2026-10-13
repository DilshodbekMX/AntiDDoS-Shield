"""
Attack repository for attack detection and history management.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from sqlalchemy import func, and_, or_
from sqlalchemy.orm import Session

from ..models import Attack, AttackType, AttackSeverity
from .base import BaseRepository


class AttackRepository(BaseRepository[Attack]):
    """Repository for attack management."""

    def __init__(self, db: Session):
        super().__init__(Attack, db)

    def get_active_attacks(self) -> List[Attack]:
        """Get currently active attacks."""
        query = self.db.query(Attack).filter(
            Attack.is_active == True,
        )
        return query.order_by(Attack.started_at.desc()).all()

    def get_recent_attacks(
        self,
        hours: int = 24,
        limit: int = 100,
    ) -> List[Attack]:
        """Get attacks from last N hours."""
        since = datetime.utcnow() - timedelta(hours=hours)
        query = self.db.query(Attack).filter(
            Attack.started_at >= since,
        )
        return query.order_by(Attack.started_at.desc()).limit(limit).all()

    def list_attacks(
        self,
        attack_type: Optional[AttackType] = None,
        severity: Optional[AttackSeverity] = None,
        is_active: Optional[bool] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Attack]:
        """List attacks with filters."""
        query = self.db.query(Attack)

        if attack_type:
            query = query.filter(Attack.attack_type == attack_type)
        if severity:
            query = query.filter(Attack.severity == severity)
        if is_active is not None:
            query = query.filter(Attack.is_active == is_active)
        if start_date:
            query = query.filter(Attack.started_at >= start_date)
        if end_date:
            query = query.filter(Attack.started_at <= end_date)

        return query.order_by(Attack.started_at.desc()).offset(skip).limit(limit).all()

    def count_attacks(
        self,
        is_active: Optional[bool] = None,
        since: Optional[datetime] = None,
    ) -> int:
        """Count attacks."""
        query = self.db.query(func.count(Attack.id))
        if is_active is not None:
            query = query.filter(Attack.is_active == is_active)
        if since:
            query = query.filter(Attack.started_at >= since)
        return query.scalar() or 0

    def start_attack(
        self,
        attack_type: AttackType,
        severity: AttackSeverity,
        target_ip: str,
        target_port: Optional[int] = None,
        detected_at: Optional[datetime] = None,
    ) -> Attack:
        """Record start of a new attack."""
        now = datetime.utcnow()
        attack = Attack(
            attack_type=attack_type,
            severity=severity,
            target_ip=target_ip,
            target_port=target_port,
            started_at=now,
            detected_at=detected_at or now,
            is_active=True,
        )
        self.db.add(attack)
        self.db.commit()
        self.db.refresh(attack)
        return attack

    def end_attack(
        self,
        attack_id: str,
        peak_pps: Optional[int] = None,
        peak_bps: Optional[int] = None,
        packets_dropped: Optional[int] = None,
        source_ips_count: Optional[int] = None,
    ) -> Optional[Attack]:
        """Record end of an attack."""
        attack = self.get(attack_id)
        if not attack:
            return None

        now = datetime.utcnow()
        attack.ended_at = now
        attack.is_active = False

        if peak_pps is not None:
            attack.peak_pps = peak_pps
        if peak_bps is not None:
            attack.peak_bps = peak_bps
        if packets_dropped is not None:
            attack.packets_dropped = packets_dropped
        if source_ips_count is not None:
            attack.source_ips_count = source_ips_count

        self.db.commit()
        self.db.refresh(attack)
        return attack

    def mark_mitigated(
        self,
        attack_id: str,
        mitigation_time_ms: Optional[float] = None,
    ) -> Optional[Attack]:
        """Mark attack as mitigated."""
        attack = self.get(attack_id)
        if not attack:
            return None

        attack.mitigated_at = datetime.utcnow()
        attack.is_mitigated = True
        if mitigation_time_ms:
            attack.mitigation_time_ms = mitigation_time_ms

        self.db.commit()
        self.db.refresh(attack)
        return attack

    def update_metrics(
        self,
        attack_id: str,
        peak_pps: Optional[int] = None,
        peak_bps: Optional[int] = None,
        total_packets: Optional[int] = None,
        packets_dropped: Optional[int] = None,
        source_ips_count: Optional[int] = None,
    ) -> Optional[Attack]:
        """Update attack metrics during ongoing attack."""
        attack = self.get(attack_id)
        if not attack:
            return None

        if peak_pps and peak_pps > attack.peak_pps:
            attack.peak_pps = peak_pps
        if peak_bps and peak_bps > attack.peak_bps:
            attack.peak_bps = peak_bps
        if total_packets:
            attack.total_packets = total_packets
        if packets_dropped:
            attack.packets_dropped = packets_dropped
        if source_ips_count:
            attack.source_ips_count = source_ips_count

        self.db.commit()
        self.db.refresh(attack)
        return attack

    def get_attack_stats(
        self,
        days: int = 30,
    ) -> Dict[str, Any]:
        """Get attack statistics for a time period."""
        since = datetime.utcnow() - timedelta(days=days)

        query = self.db.query(Attack).filter(
            Attack.started_at >= since,
        )

        attacks = query.all()

        stats = {
            "total": len(attacks),
            "active": sum(1 for a in attacks if a.is_active),
            "mitigated": sum(1 for a in attacks if a.is_mitigated),
            "by_type": {},
            "by_severity": {},
            "avg_mitigation_time_ms": 0,
            "total_packets_dropped": 0,
        }

        mitigation_times = []
        for attack in attacks:
            # By type
            attack_type = attack.attack_type.value
            stats["by_type"][attack_type] = stats["by_type"].get(attack_type, 0) + 1

            # By severity
            severity = attack.severity.value
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

            # Mitigation time
            if attack.mitigation_time_ms:
                mitigation_times.append(attack.mitigation_time_ms)

            # Packets dropped
            stats["total_packets_dropped"] += attack.packets_dropped or 0

        if mitigation_times:
            stats["avg_mitigation_time_ms"] = sum(mitigation_times) / len(mitigation_times)

        return stats

    def get_by_target_ip(
        self,
        target_ip: str,
        active_only: bool = False,
    ) -> List[Attack]:
        """Get attacks targeting a specific IP."""
        query = self.db.query(Attack).filter(Attack.target_ip == target_ip)
        if active_only:
            query = query.filter(Attack.is_active == True)
        return query.order_by(Attack.started_at.desc()).all()
