"""
Traffic rollup repository for historical traffic queries.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from sqlalchemy import func, and_, Integer
from sqlalchemy.orm import Session

from ..models import TrafficRollup
from .base import BaseRepository


class TrafficRepository(BaseRepository[TrafficRollup]):
    """Repository for traffic rollup data."""

    def __init__(self, db: Session):
        super().__init__(TrafficRollup, db)

    def insert_rollup(
        self,
        rx_pps: int = 0,
        tx_pps: int = 0,
        rx_bps: int = 0,
        tx_bps: int = 0,
        dropped_pps: int = 0,
        drops_by_reason: Optional[Dict[str, int]] = None,
        anomaly_active: bool = False,
        anomaly_level: int = 0,
        active_attacks: int = 0,
        protected_ip_count: int = 0,
    ) -> TrafficRollup:
        """Insert a new 1-minute rollup record."""
        drops = drops_by_reason or {}
        rollup = TrafficRollup(
            timestamp=datetime.utcnow(),
            rx_pps=rx_pps,
            tx_pps=tx_pps,
            rx_bps=rx_bps,
            tx_bps=tx_bps,
            dropped_pps=dropped_pps,
            drops_validation=drops.get('Validation Error', 0),
            drops_blacklist=drops.get('Blacklist', 0),
            drops_rate_limit=drops.get('Rate Limit', 0),
            drops_syn_flood=drops.get('SYN Flood', 0),
            drops_reputation=drops.get('Reputation', 0),
            drops_signature=drops.get('Signature Match', 0),
            drops_proto_blocked=drops.get('Proto Blocked', 0),
            drops_proto_rate_limit=drops.get('Proto Rate Limit', 0),
            anomaly_active=anomaly_active,
            anomaly_level=anomaly_level,
            active_attacks=active_attacks,
            protected_ip_count=protected_ip_count,
        )
        self.db.add(rollup)
        self.db.commit()
        self.db.refresh(rollup)
        return rollup

    def get_history(
        self,
        start: datetime,
        end: datetime,
        resolution_minutes: int = 1,
    ) -> List[TrafficRollup]:
        """
        Get traffic history for a time range.

        Args:
            start: Start of time range
            end: End of time range
            resolution_minutes: Downsampling interval (1=raw, 5, 60, 1440)
        """
        query = self.db.query(TrafficRollup).filter(
            and_(
                TrafficRollup.timestamp >= start,
                TrafficRollup.timestamp <= end,
            )
        ).order_by(TrafficRollup.timestamp)

        if resolution_minutes <= 1:
            return query.all()

        # For downsampling, fetch all and aggregate in Python
        # (SQLite doesn't have great time-bucket support)
        rows = query.all()
        if not rows:
            return []

        buckets = []
        bucket_start = rows[0].timestamp
        bucket_rows = []

        for row in rows:
            if (row.timestamp - bucket_start).total_seconds() >= resolution_minutes * 60:
                if bucket_rows:
                    buckets.append(self._aggregate_bucket(bucket_rows))
                bucket_start = row.timestamp
                bucket_rows = [row]
            else:
                bucket_rows.append(row)

        if bucket_rows:
            buckets.append(self._aggregate_bucket(bucket_rows))

        return buckets

    def get_summary(
        self,
        start: datetime,
        end: datetime,
    ) -> Dict[str, Any]:
        """Get aggregate traffic summary for a time range."""
        result = self.db.query(
            func.max(TrafficRollup.rx_pps).label('peak_rx_pps'),
            func.max(TrafficRollup.tx_pps).label('peak_tx_pps'),
            func.max(TrafficRollup.rx_bps).label('peak_rx_bps'),
            func.max(TrafficRollup.tx_bps).label('peak_tx_bps'),
            func.avg(TrafficRollup.rx_pps).label('avg_rx_pps'),
            func.avg(TrafficRollup.tx_pps).label('avg_tx_pps'),
            func.avg(TrafficRollup.rx_bps).label('avg_rx_bps'),
            func.avg(TrafficRollup.tx_bps).label('avg_tx_bps'),
            func.sum(TrafficRollup.rx_pps * 60).label('total_rx_packets'),
            func.sum(TrafficRollup.dropped_pps).label('total_dropped'),
            func.sum(TrafficRollup.drops_validation).label('total_drops_validation'),
            func.sum(TrafficRollup.drops_blacklist).label('total_drops_blacklist'),
            func.sum(TrafficRollup.drops_rate_limit).label('total_drops_rate_limit'),
            func.sum(TrafficRollup.drops_syn_flood).label('total_drops_syn_flood'),
            func.sum(TrafficRollup.drops_reputation).label('total_drops_reputation'),
            func.sum(TrafficRollup.drops_signature).label('total_drops_signature'),
            func.sum(TrafficRollup.drops_proto_blocked).label('total_drops_proto_blocked'),
            func.sum(TrafficRollup.drops_proto_rate_limit).label('total_drops_proto_rate_limit'),
            func.count(TrafficRollup.id).label('total_minutes'),
            func.sum(
                func.cast(TrafficRollup.anomaly_active, Integer)
            ).label('anomaly_minutes'),
        ).filter(
            and_(
                TrafficRollup.timestamp >= start,
                TrafficRollup.timestamp <= end,
            )
        ).first()

        if not result or not result.total_minutes:
            return {
                'peak_rx_pps': 0, 'peak_tx_pps': 0,
                'peak_rx_bps': 0, 'peak_tx_bps': 0,
                'avg_rx_pps': 0, 'avg_tx_pps': 0,
                'avg_rx_bps': 0, 'avg_tx_bps': 0,
                'total_rx_packets': 0, 'total_dropped': 0,
                'total_minutes': 0, 'anomaly_minutes': 0,
                'availability_pct': 100.0,
                'drops_by_reason': {},
            }

        total_min = result.total_minutes or 1
        anomaly_min = result.anomaly_minutes or 0
        availability = ((total_min - anomaly_min) / total_min) * 100

        return {
            'peak_rx_pps': int(result.peak_rx_pps or 0),
            'peak_tx_pps': int(result.peak_tx_pps or 0),
            'peak_rx_bps': int(result.peak_rx_bps or 0),
            'peak_tx_bps': int(result.peak_tx_bps or 0),
            'avg_rx_pps': int(result.avg_rx_pps or 0),
            'avg_tx_pps': int(result.avg_tx_pps or 0),
            'avg_rx_bps': int(result.avg_rx_bps or 0),
            'avg_tx_bps': int(result.avg_tx_bps or 0),
            'total_rx_packets': int(result.total_rx_packets or 0),
            'total_dropped': int(result.total_dropped or 0),
            'total_minutes': total_min,
            'anomaly_minutes': anomaly_min,
            'availability_pct': round(availability, 3),
            'drops_by_reason': {
                'Validation Error': int(result.total_drops_validation or 0),
                'Blacklist': int(result.total_drops_blacklist or 0),
                'Rate Limit': int(result.total_drops_rate_limit or 0),
                'SYN Flood': int(result.total_drops_syn_flood or 0),
                'Reputation': int(result.total_drops_reputation or 0),
                'Signature Match': int(result.total_drops_signature or 0),
                'Proto Blocked': int(result.total_drops_proto_blocked or 0),
                'Proto Rate Limit': int(result.total_drops_proto_rate_limit or 0),
            },
        }

    def prune_old(self, days: int = 90) -> int:
        """Delete rollup records older than N days."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        count = self.db.query(TrafficRollup).filter(
            TrafficRollup.timestamp < cutoff
        ).delete(synchronize_session=False)
        self.db.commit()
        return count

    @staticmethod
    def _aggregate_bucket(rows: List[TrafficRollup]) -> TrafficRollup:
        """Aggregate a list of rollup rows into a single summary row."""
        if not rows:
            return TrafficRollup()

        n = len(rows)
        agg = TrafficRollup(
            timestamp=rows[0].timestamp,
            rx_pps=sum(r.rx_pps for r in rows) // n,
            tx_pps=sum(r.tx_pps for r in rows) // n,
            rx_bps=sum(r.rx_bps for r in rows) // n,
            tx_bps=sum(r.tx_bps for r in rows) // n,
            dropped_pps=sum(r.dropped_pps for r in rows) // n,
            drops_validation=sum(r.drops_validation for r in rows),
            drops_blacklist=sum(r.drops_blacklist for r in rows),
            drops_rate_limit=sum(r.drops_rate_limit for r in rows),
            drops_syn_flood=sum(r.drops_syn_flood for r in rows),
            drops_reputation=sum(r.drops_reputation for r in rows),
            drops_signature=sum(r.drops_signature for r in rows),
            drops_proto_blocked=sum(r.drops_proto_blocked for r in rows),
            drops_proto_rate_limit=sum(r.drops_proto_rate_limit for r in rows),
            anomaly_active=any(r.anomaly_active for r in rows),
            anomaly_level=max(r.anomaly_level for r in rows),
            active_attacks=max(r.active_attacks for r in rows),
            protected_ip_count=rows[-1].protected_ip_count,
        )
        return agg
