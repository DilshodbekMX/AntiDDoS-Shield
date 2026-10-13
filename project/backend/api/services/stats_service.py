"""
Statistics Service (Real Data Integration)

Business logic for statistics and monitoring.
Integrates with DPDK service for real datapath statistics.

Filtering:
- Per-IP stats are filtered by protected IPs from L1 config
- Only data for protected IPs is returned
- Traffic stats are aggregated from protected IP data
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, Set

from ..models import (
    SystemStats, StatsPeriod,
    TrafficStats, SecurityStats, LayerStats, SLAStats,
    StatsHistoryPoint
)
from .dpdk_service import get_dpdk_service, DPDKService

logger = logging.getLogger(__name__)

# Period -> days mapping (shared across methods)
_PERIOD_DAYS = {
    StatsPeriod.REALTIME: 0,
    StatsPeriod.HOUR_1: 0,
    StatsPeriod.HOUR_24: 1,
    StatsPeriod.DAY_7: 7,
    StatsPeriod.DAY_30: 30,
}

# Path to L1 config IP lists
_IP_LISTS_PATH = Path(__file__).resolve().parents[3] / "layer1" / "config" / "ip_lists.json"


class StatsService:
    """
    Service layer for statistics.

    Integrates with:
    - DPDK socket for real-time stats from C data plane
    - Stats history for historical data
    - Per-IP features and anomaly data

    Filtering:
    - Filters all per-IP data by protected IPs from L1 config
    - Aggregates stats only from protected IPs
    """

    def __init__(self):
        # Cache for computed values
        self._cache: Dict[str, Any] = {}
        self._dpdk: DPDKService = get_dpdk_service()
        # Cache for protected IPs (TTL: 60 seconds)
        self._protected_ips_cache: Optional[tuple] = None  # (timestamp, set of IPs)
        self._cache_ttl_seconds = 60

    def _get_protected_ips(self) -> Set[str]:
        """
        Get set of protected IP addresses from L1 config.
        Uses caching to avoid repeated file reads.

        Returns:
            Set of IP address strings from ip_lists.json
        """
        now = datetime.utcnow().timestamp()

        # Check cache
        if self._protected_ips_cache is not None:
            cached_time, cached_ips = self._protected_ips_cache
            if now - cached_time < self._cache_ttl_seconds:
                return cached_ips

        # Read from L1 config
        try:
            with open(_IP_LISTS_PATH, "r") as f:
                data = json.load(f)
            ip_set = set(data.get("protected_ips", []))
            self._protected_ips_cache = (now, ip_set)
            return ip_set
        except Exception as e:
            logger.warning(f"Failed to read protected IPs from {_IP_LISTS_PATH}: {e}")
            return set()

    def _filter_per_ip_data(
        self,
        per_ip_data: Dict[str, Dict],
        protected_ips: Set[str]
    ) -> Dict[str, Dict]:
        """
        Filter per-IP data to only include protected IPs.

        Args:
            per_ip_data: Dict keyed by IP address
            protected_ips: Set of protected IP addresses

        Returns:
            Filtered dict containing only protected IPs
        """
        if not protected_ips:
            return {}
        return {ip: data for ip, data in per_ip_data.items() if ip in protected_ips}

    async def get_stats(
        self,
        period: StatsPeriod
    ) -> Optional[SystemStats]:
        """Get comprehensive statistics."""
        # In production, fetch from stats socket/shared memory
        return SystemStats(
            timestamp=datetime.utcnow(),
            period=period,
            traffic=await self.get_traffic_stats(period),
            security=await self.get_security_stats(period),
            layer1=await self._get_layer_stats_internal(1, period),
            layer2=await self._get_layer_stats_internal(2, period),
            sla=await self.get_sla_stats(period),
        )

    async def get_summary(self) -> Dict[str, Any]:
        """Get quick summary for dashboard cards using real DPDK data."""
        # Get protected IPs for filtering
        protected_ips = self._get_protected_ips()

        # Get real data from DPDK service
        stats = self._dpdk.get_stats()
        anomaly = self._dpdk.get_anomaly()
        per_ip_anomaly = self._dpdk.get_per_ip_anomaly()

        # Filter to protected IPs only
        filtered_anomaly = self._filter_per_ip_data(per_ip_anomaly, protected_ips)

        # Use real port stats for traffic (not per-IP estimates)
        ports = stats.get('ports', {})
        total_rx_pps = sum(p.get('rx_pps', 0) for p in ports.values())
        total_rx_bps = sum(p.get('rx_bps', 0) for p in ports.values())
        total_dropped = sum(p.get('dropped', 0) for p in ports.values())
        total_rx_packets = sum(p.get('rx_packets', 0) for p in ports.values())

        # Use real drops_by_reason for blacklist hits
        drops = stats.get('drops_by_reason', {})
        blacklist_hits = drops.get('Blacklist', 0)

        # Calculate drop rate
        drop_rate = round(total_dropped / max(total_rx_packets, 1) * 100, 2)

        # Count active attacks for protected IPs
        active_attacks = 0
        max_attack_level = 0
        for ip_data in filtered_anomaly.values():
            if ip_data.get('anomaly_active', False):
                active_attacks += 1
                level = ip_data.get('level', 0)
                if level > max_attack_level:
                    max_attack_level = level

        # Availability based on anomaly state (not drop rate)
        any_attack = any(d.get('anomaly_active', False) for d in filtered_anomaly.values())

        level_names = {0: 'NONE', 1: 'LOW', 2: 'MEDIUM', 3: 'HIGH', 4: 'CRITICAL'}

        return {
            "current_pps": total_rx_pps,
            "current_bps": total_rx_bps,
            "drop_rate_pct": drop_rate,
            "active_attacks": active_attacks,
            "attack_level": max_attack_level,
            "attack_level_name": level_names.get(max_attack_level, 'NONE'),
            "attacks_24h": anomaly.get('detection_count', 0),
            "blacklist_hits_24h": blacklist_hits,
            "syn_proxy_challenges": drops.get('SYN Flood', 0),
            "availability_pct": 99.0 if any_attack else 100.0,
            "connected": stats.get('connected', False),
            "protected_ips_count": len(protected_ips),
        }

    async def get_traffic_stats(
        self,
        period: StatsPeriod
    ) -> TrafficStats:
        """Get traffic statistics from real DPDK port stats + DB rollups."""
        days = _PERIOD_DAYS.get(period, 0)

        if days > 0:
            # HISTORICAL: use traffic rollups from database
            from ..database import get_db
            from ..database.repositories.traffic_repo import TrafficRepository

            end = datetime.utcnow()
            start = end - timedelta(days=days)
            db = next(get_db())
            try:
                summary = TrafficRepository(db).get_summary(start, end)
                total_min = max(summary.get('total_minutes', 1), 1)
                total_rx = summary.get('total_rx_packets', 0)
                total_dropped = summary.get('total_dropped', 0)
                drop_rate = round(total_dropped / max(total_rx, 1) * 100, 2)

                return TrafficStats(
                    packets_in=total_rx,
                    packets_out=int(summary.get('avg_tx_pps', 0) * total_min * 60),
                    bytes_in=int(summary.get('avg_rx_bps', 0) * total_min * 60),
                    bytes_out=int(summary.get('avg_tx_bps', 0) * total_min * 60),
                    packets_dropped=total_dropped,
                    bytes_dropped=total_dropped * 800,
                    drop_rate_pct=drop_rate,
                    current_pps=int(summary.get('avg_rx_pps', 0)),
                    current_bps=int(summary.get('avg_rx_bps', 0)),
                    peak_pps_24h=int(summary.get('peak_rx_pps', 0)),
                    peak_bps_24h=int(summary.get('peak_rx_bps', 0)),
                )
            finally:
                db.close()
        else:
            # REALTIME: use current port stats (has real TX data)
            stats = self._dpdk.get_stats()
            ports = stats.get('ports', {})

            rx_pps = sum(p.get('rx_pps', 0) for p in ports.values())
            tx_pps = sum(p.get('tx_pps', 0) for p in ports.values())
            rx_bps = sum(p.get('rx_bps', 0) for p in ports.values())
            tx_bps = sum(p.get('tx_bps', 0) for p in ports.values())
            rx_packets = sum(p.get('rx_packets', 0) for p in ports.values())
            tx_packets = sum(p.get('tx_packets', 0) for p in ports.values())
            rx_bytes = sum(p.get('rx_bytes', 0) for p in ports.values())
            tx_bytes = sum(p.get('tx_bytes', 0) for p in ports.values())
            dropped = sum(p.get('dropped', 0) for p in ports.values())
            drop_rate = round(dropped / max(rx_packets, 1) * 100, 2)

            return TrafficStats(
                packets_in=rx_packets,
                packets_out=tx_packets,
                bytes_in=rx_bytes,
                bytes_out=tx_bytes,
                packets_dropped=dropped,
                bytes_dropped=dropped * 800,
                drop_rate_pct=drop_rate,
                current_pps=rx_pps,
                current_bps=rx_bps,
                peak_pps_24h=rx_pps,
                peak_bps_24h=rx_bps,
            )

    async def get_traffic_history(
        self,
        start: datetime,
        end: datetime,
        resolution: str
    ) -> List[StatsHistoryPoint]:
        """Get traffic history from DPDK in-memory buffer or DB rollups.

        For ranges <= 1 hour: uses DPDK in-memory history (1s granularity).
        For ranges > 1 hour: uses traffic_rollups table (1m+ granularity).
        """
        range_seconds = (end - start).total_seconds()

        if range_seconds <= 3600:
            # Short range: use in-memory DPDK history (1s granularity)
            dpdk_history = self._dpdk.get_stats_history(limit=3600)
            history = []
            for entry in dpdk_history:
                ts_ms = entry.get('timestamp', 0)
                if ts_ms == 0:
                    continue
                entry_time = datetime.fromtimestamp(ts_ms / 1000)
                if entry_time < start or entry_time > end:
                    continue

                total_pps = sum(p.get('rx_pps', 0) for p in entry.get('ports', {}).values())
                total_bps = sum(p.get('rx_bps', 0) for p in entry.get('ports', {}).values())
                total_drops = sum(p.get('dropped', 0) for p in entry.get('ports', {}).values())

                history.append(StatsHistoryPoint(
                    timestamp=entry_time, pps=total_pps, bps=total_bps,
                    drops=total_drops, attacks=0,
                ))
            return history
        else:
            # Long range: use traffic rollups from database
            from ..database import get_db
            from ..database.repositories.traffic_repo import TrafficRepository

            res_map = {'1m': 1, '5m': 5, '1h': 60, '1d': 1440}
            res_min = res_map.get(resolution, 1)

            db = next(get_db())
            try:
                rollups = TrafficRepository(db).get_history(start, end, res_min)
                return [
                    StatsHistoryPoint(
                        timestamp=r.timestamp, pps=r.rx_pps, bps=r.rx_bps,
                        drops=r.dropped_pps,
                        attacks=1 if r.anomaly_active else 0,
                    ) for r in rollups
                ]
            finally:
                db.close()

    async def get_top_sources(
        self,
        limit: int,
        period: StatsPeriod
    ) -> List[Dict[str, Any]]:
        """Get top traffic sources from real per-IP features data."""
        # Get protected IPs for filtering
        protected_ips = self._get_protected_ips()

        # Get real per-IP features from DPDK
        per_ip_features = self._dpdk.get_per_ip_features()
        per_ip_anomaly = self._dpdk.get_per_ip_anomaly()

        # Filter to protected IPs only
        filtered_features = self._filter_per_ip_data(per_ip_features, protected_ips)
        filtered_anomaly = self._filter_per_ip_data(per_ip_anomaly, protected_ips)

        sources = []
        for ip_str, features in filtered_features.items():
            if not features.get('active', False):
                continue

            # Check anomaly status for this IP
            anomaly_data = filtered_anomaly.get(ip_str, {})
            is_anomalous = anomaly_data.get('anomaly_active', False)

            # Calculate reputation score (inverse of anomaly)
            reputation = 1.0
            if is_anomalous:
                z_score = anomaly_data.get('max_z_score', 0)
                # Higher z_score = lower reputation
                reputation = max(0.0, 1.0 - min(z_score / 10.0, 1.0))

            sources.append({
                "ip": ip_str,
                "packets": features.get('total_packets', 0),
                "bytes": features.get('bytes_per_sec', 0) * 60,  # Estimate for period
                "packets_per_sec": features.get('packets_per_sec', 0),
                "bytes_per_sec": features.get('bytes_per_sec', 0),
                "flows": features.get('active_flows', 0),
                "tcp_ratio": features.get('tcp_ratio', 0),
                "udp_ratio": features.get('udp_ratio', 0),
                "icmp_ratio": features.get('icmp_ratio', 0),
                "syn_per_sec": features.get('syn_per_sec', 0),
                "unique_flows": features.get('unique_flows', 0),
                "heavy_hitter_count": features.get('heavy_hitter_count', 0),
                "country": "??",  # Would need GeoIP lookup
                "reputation": round(reputation, 2),
                "is_anomalous": is_anomalous,
                "attack_type": anomaly_data.get('attack_type_name', 'NONE') if is_anomalous else 'NONE',
            })

        # Sort by packets descending and limit
        sources.sort(key=lambda x: x["packets"], reverse=True)
        return sources[:limit]

    async def get_protocol_breakdown(
        self,
        period: StatsPeriod
    ) -> Dict[str, Any]:
        """Get traffic breakdown by protocol from real per-IP features."""
        # Get protected IPs for filtering
        protected_ips = self._get_protected_ips()

        # Get per-IP features and filter to protected IPs
        per_ip_features = self._dpdk.get_per_ip_features()
        filtered_features = self._filter_per_ip_data(per_ip_features, protected_ips)

        total_tcp = 0
        total_udp = 0
        total_icmp = 0
        total_other = 0
        total_packets = 0

        for features in filtered_features.values():
            if not features.get('active', False):
                continue
            packets = features.get('total_packets', 0)
            if packets == 0:
                continue

            tcp_ratio = features.get('tcp_ratio', 0) / 100.0
            udp_ratio = features.get('udp_ratio', 0) / 100.0
            icmp_ratio = features.get('icmp_ratio', 0) / 100.0
            other_ratio = features.get('other_ratio', 0) / 100.0

            total_tcp += int(packets * tcp_ratio)
            total_udp += int(packets * udp_ratio)
            total_icmp += int(packets * icmp_ratio)
            total_other += int(packets * other_ratio)
            total_packets += packets

        # Calculate percentages
        if total_packets > 0:
            tcp_pct = round((total_tcp / total_packets) * 100, 1)
            udp_pct = round((total_udp / total_packets) * 100, 1)
            icmp_pct = round((total_icmp / total_packets) * 100, 1)
            other_pct = round((total_other / total_packets) * 100, 1)
        else:
            tcp_pct = udp_pct = icmp_pct = other_pct = 0

        # Estimate bytes (avg packet sizes: TCP=500, UDP=300, ICMP=64, other=200)
        return {
            "tcp": {"percent": tcp_pct, "packets": total_tcp, "bytes": total_tcp * 500},
            "udp": {"percent": udp_pct, "packets": total_udp, "bytes": total_udp * 300},
            "icmp": {"percent": icmp_pct, "packets": total_icmp, "bytes": total_icmp * 64},
            "other": {"percent": other_pct, "packets": total_other, "bytes": total_other * 200},
        }

    async def get_geo_distribution(
        self,
        period: StatsPeriod
    ) -> List[Dict[str, Any]]:
        """Get geographic distribution of traffic.

        Note: Returns empty list. Real implementation would
        require GeoIP database integration (MaxMind GeoIP2).
        """
        return []

    async def get_security_stats(
        self,
        period: StatsPeriod
    ) -> SecurityStats:
        """Get security statistics from real DPDK drops_by_reason + DB."""
        days = _PERIOD_DAYS.get(period, 0)

        if days > 0:
            # HISTORICAL: use DB for attack counts and traffic rollups for drops
            from ..database import get_db
            from ..database.repositories.traffic_repo import TrafficRepository
            from ..database.repositories.attack_repo import AttackRepository

            end = datetime.utcnow()
            start = end - timedelta(days=days)
            db = next(get_db())
            try:
                traffic_repo = TrafficRepository(db)
                attack_repo = AttackRepository(db)

                summary = traffic_repo.get_summary(start, end)
                attack_stats = attack_repo.get_attack_stats(days=days)
                drops = summary.get('drops_by_reason', {})

                # Count currently active attacks
                per_ip_anomaly = self._dpdk.get_per_ip_anomaly()
                protected_ips = self._get_protected_ips()
                filtered = self._filter_per_ip_data(per_ip_anomaly, protected_ips)
                active = sum(1 for d in filtered.values() if d.get('anomaly_active', False))

                return SecurityStats(
                    attacks_detected=attack_stats.get('total', 0),
                    attacks_mitigated=attack_stats.get('mitigated', 0),
                    attacks_active=active,
                    avg_mitigation_time_ms=attack_stats.get('avg_mitigation_time_ms', 0),
                    false_positives=0,
                    blacklist_hits=drops.get('Blacklist', 0),
                    whitelist_hits=0,
                    rate_limit_drops=drops.get('Rate Limit', 0),
                    syn_proxy_challenges=drops.get('SYN Flood', 0),
                    syn_proxy_passes=0,
                    geo_blocks=drops.get('Geo Blocked', 0),
                )
            finally:
                db.close()
        else:
            # REALTIME: use current DPDK drops_by_reason
            stats = self._dpdk.get_stats()
            drops = stats.get('drops_by_reason', {})
            anomaly = self._dpdk.get_anomaly()

            per_ip_anomaly = self._dpdk.get_per_ip_anomaly()
            protected_ips = self._get_protected_ips()
            filtered = self._filter_per_ip_data(per_ip_anomaly, protected_ips)

            active_attacks = 0
            detection_count = 0
            for ip_data in filtered.values():
                if ip_data.get('anomaly_active', False):
                    active_attacks += 1
                detection_count += ip_data.get('detection_count', 0)

            return SecurityStats(
                attacks_detected=detection_count,
                attacks_mitigated=detection_count,
                attacks_active=active_attacks,
                avg_mitigation_time_ms=anomaly.get('duration_sec', 0) * 1000 if active_attacks else 0,
                false_positives=0,
                blacklist_hits=drops.get('Blacklist', 0),
                whitelist_hits=0,
                rate_limit_drops=drops.get('Rate Limit', 0),
                syn_proxy_challenges=drops.get('SYN Flood', 0),
                syn_proxy_passes=0,
                geo_blocks=drops.get('Geo Blocked', 0),
            )

    async def get_drop_reasons(
        self,
        period: StatsPeriod
    ) -> Dict[str, int]:
        """Get breakdown of drops by reason from real DPDK stats or DB rollups."""
        days = _PERIOD_DAYS.get(period, 0)

        if days > 0:
            # HISTORICAL: use traffic rollups
            from ..database import get_db
            from ..database.repositories.traffic_repo import TrafficRepository

            end = datetime.utcnow()
            start = end - timedelta(days=days)
            db = next(get_db())
            try:
                summary = TrafficRepository(db).get_summary(start, end)
                drops = summary.get('drops_by_reason', {})
                return {r: c for r, c in drops.items() if c > 0}
            finally:
                db.close()
        else:
            # REALTIME: use current DPDK stats (per-second rates)
            stats = self._dpdk.get_stats()
            if not stats:
                return {}
            drops = stats.get('drops_by_reason', {})
            return {r: c for r, c in drops.items() if c > 0}

    async def get_layer_stats(
        self,
        layer: int,
        period: StatsPeriod
    ) -> Dict[str, Any]:
        """Get detailed statistics for a specific layer using real DPDK data."""
        base_stats = await self._get_layer_stats_internal(layer, period)

        # Get per-IP data for layer-specific details
        protected_ips = self._get_protected_ips()
        per_ip_features = self._dpdk.get_per_ip_features()
        per_ip_anomaly = self._dpdk.get_per_ip_anomaly()
        filtered_features = self._filter_per_ip_data(per_ip_features, protected_ips)
        filtered_anomaly = self._filter_per_ip_data(per_ip_anomaly, protected_ips)

        # Real drop reasons from DPDK
        stats = self._dpdk.get_stats()
        drops = stats.get('drops_by_reason', {})

        total_unique_flows = sum(
            f.get('unique_flows', 0) for f in filtered_features.values() if f.get('active', False)
        )
        active_attacks = sum(
            1 for d in filtered_anomaly.values() if d.get('anomaly_active', False)
        )
        max_z_score = max(
            (d.get('max_z_score', 0.0) for d in filtered_anomaly.values()), default=0.0
        )
        total_detection_count = sum(
            d.get('detection_count', 0) for d in filtered_anomaly.values()
        )

        if layer == 1:
            return {
                **base_stats.dict(),
                "rate_limit_triggered": drops.get('Rate Limit', 0),
                "syn_proxy_active_connections": total_unique_flows,
                "tcp_fingerprint_matches": drops.get('Signature Match', 0),
                "geo_blocks": drops.get('Geo Blocked', 0),
            }
        elif layer == 2:
            any_attack_active = active_attacks > 0
            return {
                **base_stats.dict(),
                "baseline_ready": True,
                "anomaly_active": any_attack_active,
                "current_z_score": round(max_z_score, 2),
                "features_anomalous": active_attacks,
                "confidence": 80 if any_attack_active else 0,
                "primary_feature": "pps" if any_attack_active else "none",
                "detection_cycles": total_detection_count,
            }

        return base_stats.dict()

    async def _get_layer_stats_internal(
        self,
        layer: int,
        period: StatsPeriod
    ) -> LayerStats:
        """Get base layer statistics from real DPDK drops_by_reason.

        Layer 1 drops: Validation, Blacklist, Rate Limit, SYN Flood,
            Geo Blocked, Signature, Policy, Spoofed TCP, Proto Blocked/RateLimit.
        Layer 2 drops: Reputation (scored by L2 anomaly detection).
        """
        # L1 drop reasons (everything in the C datapath)
        L1_REASONS = [
            'Validation Error', 'Blacklist', 'Rate Limit', 'SYN Flood',
            'Policy', 'Proxy Error', 'Geo Blocked', 'Signature Match',
            'Other Protocol', 'Spoofed TCP', 'Proto Blocked', 'Proto Rate Limit',
        ]
        L2_REASONS = ['Reputation']

        stats = self._dpdk.get_stats()
        ports = stats.get('ports', {})
        drops = stats.get('drops_by_reason', {})

        rx_packets = sum(p.get('rx_packets', 0) for p in ports.values())

        # Sum drops for this layer from real drop reasons
        reasons = L1_REASONS if layer == 1 else L2_REASONS
        layer_drops = sum(drops.get(r, 0) for r in reasons)

        # L2 processes packets that survived L1
        l1_total_drops = sum(drops.get(r, 0) for r in L1_REASONS)
        if layer == 2:
            packets_processed = max(rx_packets - l1_total_drops, 0)
        else:
            packets_processed = rx_packets

        return LayerStats(
            packets_processed=packets_processed,
            packets_dropped=layer_drops,
            decisions_made=packets_processed,
            avg_latency_ns=100 + (layer * 50),  # Approximate: no C-side latency export
            errors=0,
        )

    async def get_sla_stats(
        self,
        period: StatsPeriod
    ) -> SLAStats:
        """Get SLA compliance statistics from traffic rollups + real-time data."""
        from ..database import get_db
        from ..database.repositories.traffic_repo import TrafficRepository
        from ..database.repositories.attack_repo import AttackRepository

        days = _PERIOD_DAYS.get(period, 0)

        if days > 0:
            # Use traffic rollups for historical SLA
            end = datetime.utcnow()
            start = end - timedelta(days=days)

            db = next(get_db())
            try:
                traffic_repo = TrafficRepository(db)
                attack_repo = AttackRepository(db)

                summary = traffic_repo.get_summary(start, end)
                attack_stats = attack_repo.get_attack_stats(days=days)

                availability = summary.get('availability_pct', 100.0)
                avg_mttm = attack_stats.get('avg_mitigation_time_ms', 0)
                total_attacks = attack_stats.get('total', 0)
                mitigated = attack_stats.get('mitigated', 0)
                effectiveness = (mitigated / max(total_attacks, 1)) * 100

                return SLAStats(
                    availability_pct=round(availability, 3),
                    mttd_ms=0,
                    mttr_ms=round(avg_mttm, 2),
                    mitigation_effectiveness_pct=round(effectiveness, 2),
                    false_positive_rate_pct=0.0,
                    sla_breaches=1 if availability < 99.9 else 0,
                )
            finally:
                db.close()
        else:
            # Real-time: use current DPDK snapshot
            protected_ips = self._get_protected_ips()
            per_ip_anomaly = self._dpdk.get_per_ip_anomaly()
            filtered_anomaly = self._filter_per_ip_data(per_ip_anomaly, protected_ips)

            any_attack = any(d.get('anomaly_active', False) for d in filtered_anomaly.values())

            return SLAStats(
                availability_pct=99.0 if any_attack else 100.0,
                mttd_ms=0,
                mttr_ms=0,
                mitigation_effectiveness_pct=100.0,
                false_positive_rate_pct=0.0,
                sla_breaches=1 if any_attack else 0,
            )

    async def get_realtime_metrics(self) -> Dict[str, Any]:
        """Get real-time metrics for live updates from DPDK."""
        # Get protected IPs for filtering
        protected_ips = self._get_protected_ips()

        # Get per-IP data
        per_ip_features = self._dpdk.get_per_ip_features()
        per_ip_anomaly = self._dpdk.get_per_ip_anomaly()
        filtered_features = self._filter_per_ip_data(per_ip_features, protected_ips)
        filtered_anomaly = self._filter_per_ip_data(per_ip_anomaly, protected_ips)

        stats = self._dpdk.get_stats()

        # Aggregate from per-IP data
        total_pps = sum(
            f.get('packets_per_sec', 0) for f in filtered_features.values() if f.get('active', False)
        )
        total_bps = sum(
            f.get('bytes_per_sec', 0) * 8 for f in filtered_features.values() if f.get('active', False)
        )
        total_packets = sum(
            f.get('total_packets', 0) for f in filtered_features.values() if f.get('active', False)
        )

        # Estimate drop rate using global ratio
        global_rx = sum(p.get('rx_packets', 0) for p in stats.get('ports', {}).values())
        global_drop = sum(p.get('dropped', 0) for p in stats.get('ports', {}).values())
        drop_ratio = global_drop / global_rx if global_rx > 0 else 0
        total_drop_pps = int(total_pps * drop_ratio)

        # Aggregate anomaly metrics
        total_unique_flows = sum(
            f.get('unique_flows', 0) for f in filtered_features.values() if f.get('active', False)
        )
        total_syn_per_sec = sum(
            f.get('syn_per_sec', 0) for f in filtered_features.values() if f.get('active', False)
        )
        any_attack_active = any(d.get('anomaly_active', False) for d in filtered_anomaly.values())
        max_z_score = max(
            (d.get('max_z_score', 0.0) for d in filtered_anomaly.values()), default=0.0
        )
        attack_count = sum(1 for d in filtered_anomaly.values() if d.get('anomaly_active', False))

        # Calculate max attack level from anomalies
        max_level = 0
        level_name = 'NONE'
        for d in filtered_anomaly.values():
            if d.get('anomaly_active', False):
                level = d.get('level', 0)
                if level > max_level:
                    max_level = level
                    level_name = d.get('level_name', 'UNKNOWN')

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "pps": total_pps,
            "bps": total_bps,
            "drop_pps": total_drop_pps,
            "active_flows": total_unique_flows,
            "syn_proxy_active": total_syn_per_sec,
            "anomaly_score": max_level / 4.0 if max_level > 0 else 0.0,  # Normalized 0-1 from max anomaly level (0-4)
            "attack_active": any_attack_active,
            "attack_level": max_level,
            "attack_level_name": level_name,
            "max_z_score": max_z_score,
            "primary_feature": "pps" if any_attack_active else "none",
            "heavy_hitters": attack_count,
            "unique_src_ips": len(filtered_features),
            "connected": stats.get('connected', False),
            "protected_ips_count": len(protected_ips),
        }

    async def compare_periods(
        self,
        period1: StatsPeriod,
        period2: StatsPeriod
    ) -> Dict[str, Any]:
        """Compare statistics between two periods."""
        stats1 = await self.get_stats(period1)
        stats2 = await self.get_stats(period2)

        def calc_change(v1, v2):
            if v2 == 0:
                return 0
            return round((v1 - v2) / v2 * 100, 2)

        return {
            "period1": period1,
            "period2": period2,
            "traffic": {
                "packets_change_pct": calc_change(
                    stats1.traffic.packets_in, stats2.traffic.packets_in
                ),
                "bytes_change_pct": calc_change(
                    stats1.traffic.bytes_in, stats2.traffic.bytes_in
                ),
                "drops_change_pct": calc_change(
                    stats1.traffic.packets_dropped, stats2.traffic.packets_dropped
                ),
            },
            "security": {
                "attacks_change": stats1.security.attacks_detected - stats2.security.attacks_detected,
                "blacklist_hits_change_pct": calc_change(
                    stats1.security.blacklist_hits, stats2.security.blacklist_hits
                ),
            },
        }

    async def export_stats(
        self,
        start: datetime,
        end: datetime,
        format: str
    ) -> Dict[str, Any]:
        """Export statistics data."""
        history = await self.get_traffic_history(start, end, "1m")

        if format == "csv":
            # Return data in CSV-ready format
            return {
                "format": "csv",
                "headers": ["timestamp", "pps", "bps", "drops", "attacks"],
                "rows": [
                    [p.timestamp.isoformat(), p.pps, p.bps, p.drops, p.attacks]
                    for p in history
                ]
            }
        else:
            return {
                "format": "json",
                "data": [p.dict() for p in history]
            }



# Singleton instance
_stats_service = None

def get_stats_service() -> StatsService:
    """Get or create the stats service singleton."""
    global _stats_service
    if _stats_service is None:
        _stats_service = StatsService()
    return _stats_service
