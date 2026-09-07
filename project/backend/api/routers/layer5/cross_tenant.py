"""
Layer 5 Cross-Tenant Analytics API router.

Provides endpoints for analyzing patterns across multiple tenants,
sharing threat intelligence, and coordinated defense.
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
import uuid

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field

from ...database import get_db
from ...auth import require_admin, require_tenant_access

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/layer5/cross-tenant", tags=["Layer 5 - Cross-Tenant"])


# Pydantic models

class AttackPatternType(str, Enum):
    """Cross-tenant attack pattern types."""
    COORDINATED = "coordinated"
    SIMILAR_SIGNATURE = "similar_signature"
    COMMON_SOURCE = "common_source"
    TIME_CORRELATED = "time_correlated"
    ESCALATION = "escalation"


class SharedIndicatorType(str, Enum):
    """Types of shared indicators."""
    IP = "ip"
    SIGNATURE = "signature"
    USER_AGENT = "user_agent"
    PAYLOAD_HASH = "payload_hash"
    ATTACK_PATTERN = "attack_pattern"


class CrossTenantAttack(BaseModel):
    """Cross-tenant attack pattern."""
    pattern_id: str
    pattern_type: AttackPatternType
    confidence: float
    affected_tenants: List[int]
    common_sources: List[str]
    attack_type: str
    first_detected: datetime
    last_detected: datetime
    severity: str
    is_active: bool
    description: str


class SharedIndicator(BaseModel):
    """Shared threat indicator across tenants."""
    indicator_id: str
    indicator_type: SharedIndicatorType
    value: str
    shared_by_tenant: int
    affected_tenants: List[int]
    hit_count: int
    first_seen: datetime
    last_seen: datetime
    confidence: float
    is_active: bool


class CrossTenantStats(BaseModel):
    """Cross-tenant analytics statistics."""
    success: bool = True
    total_tenants: int
    active_tenants: int
    shared_indicators: int
    common_attack_patterns: int
    coordinated_attacks_detected: int
    time_range_hours: int


class CrossTenantConfig(BaseModel):
    """Cross-tenant analytics configuration."""
    success: bool = True
    enabled: bool
    auto_share_indicators: bool
    share_attack_signatures: bool
    correlation_window_minutes: int
    min_tenant_match: int
    anonymize_tenant_data: bool


# In-memory storage for demo
_shared_indicators: Dict[str, Dict[str, Any]] = {}
_attack_patterns: Dict[str, Dict[str, Any]] = {}
_config = {
    "enabled": True,
    "auto_share_indicators": True,
    "share_attack_signatures": True,
    "correlation_window_minutes": 15,
    "min_tenant_match": 2,
    "anonymize_tenant_data": False,
}


def _generate_demo_patterns() -> List[Dict[str, Any]]:
    """Generate demo attack patterns."""
    now = datetime.utcnow()
    return [
        {
            "pattern_id": "ptn-001",
            "pattern_type": AttackPatternType.COORDINATED,
            "confidence": 0.92,
            "affected_tenants": [1, 3, 5],
            "common_sources": ["185.220.100.252", "185.220.100.253"],
            "attack_type": "syn_flood",
            "first_detected": now - timedelta(hours=2),
            "last_detected": now - timedelta(minutes=30),
            "severity": "high",
            "is_active": False,
            "description": "Coordinated SYN flood from Tor exit nodes targeting multiple tenants",
        },
        {
            "pattern_id": "ptn-002",
            "pattern_type": AttackPatternType.SIMILAR_SIGNATURE,
            "confidence": 0.85,
            "affected_tenants": [2, 4],
            "common_sources": ["45.33.32.156", "45.33.32.157"],
            "attack_type": "http_flood",
            "first_detected": now - timedelta(hours=6),
            "last_detected": now - timedelta(hours=4),
            "severity": "medium",
            "is_active": False,
            "description": "HTTP flood with identical request patterns across tenants",
        },
        {
            "pattern_id": "ptn-003",
            "pattern_type": AttackPatternType.COMMON_SOURCE,
            "confidence": 0.78,
            "affected_tenants": [1, 2, 3, 4, 5],
            "common_sources": ["192.168.1.100"],
            "attack_type": "scanning",
            "first_detected": now - timedelta(days=1),
            "last_detected": now - timedelta(hours=1),
            "severity": "low",
            "is_active": True,
            "description": "Port scanning activity from single source across all tenants",
        },
    ]


def _generate_demo_indicators() -> List[Dict[str, Any]]:
    """Generate demo shared indicators."""
    now = datetime.utcnow()
    return [
        {
            "indicator_id": "ind-001",
            "indicator_type": SharedIndicatorType.IP,
            "value": "185.220.100.252",
            "shared_by_tenant": 1,
            "affected_tenants": [1, 3, 5],
            "hit_count": 15420,
            "first_seen": now - timedelta(days=7),
            "last_seen": now - timedelta(hours=1),
            "confidence": 0.95,
            "is_active": True,
        },
        {
            "indicator_id": "ind-002",
            "indicator_type": SharedIndicatorType.SIGNATURE,
            "value": "TCP flags: SYN, window=0, urgent=0",
            "shared_by_tenant": 3,
            "affected_tenants": [1, 2, 3, 5],
            "hit_count": 89230,
            "first_seen": now - timedelta(days=14),
            "last_seen": now - timedelta(minutes=30),
            "confidence": 0.88,
            "is_active": True,
        },
        {
            "indicator_id": "ind-003",
            "indicator_type": SharedIndicatorType.USER_AGENT,
            "value": "Mozilla/5.0 (compatible; DDoSBot/1.0)",
            "shared_by_tenant": 2,
            "affected_tenants": [2, 4],
            "hit_count": 4521,
            "first_seen": now - timedelta(days=3),
            "last_seen": now - timedelta(hours=6),
            "confidence": 0.92,
            "is_active": True,
        },
    ]


# Routes

@router.get("/attacks")
async def get_cross_tenant_attacks(
    pattern_type: Optional[AttackPatternType] = Query(None, description="Filter by pattern type"),
    active_only: bool = Query(False, description="Only active attacks"),
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(50, ge=1, le=500),
    _=Depends(require_admin),
):
    """
    Get cross-tenant attack patterns.

    Identifies attacks that target multiple tenants simultaneously
    or share common characteristics.

    **Requires admin access**
    """
    patterns = _generate_demo_patterns()

    result = []
    for p in patterns:
        if pattern_type and p["pattern_type"] != pattern_type:
            continue
        if active_only and not p["is_active"]:
            continue

        result.append(CrossTenantAttack(**p))

    return {
        "success": True,
        "time_range_hours": hours,
        "total": len(result),
        "patterns": result[:limit],
    }


@router.get("/threats")
async def get_shared_threats(
    indicator_type: Optional[SharedIndicatorType] = Query(None, description="Filter by type"),
    min_tenant_count: int = Query(2, ge=2, le=100, description="Minimum affected tenants"),
    active_only: bool = Query(True, description="Only active indicators"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    _=Depends(require_admin),
):
    """
    Get shared threat indicators across tenants.

    Returns indicators that have been observed targeting
    multiple tenants.

    **Requires admin access**
    """
    indicators = _generate_demo_indicators()

    result = []
    for ind in indicators:
        if indicator_type and ind["indicator_type"] != indicator_type:
            continue
        if active_only and not ind["is_active"]:
            continue
        if len(ind["affected_tenants"]) < min_tenant_count:
            continue

        result.append(SharedIndicator(**ind))

    total = len(result)
    result = result[skip:skip + limit]

    return {
        "success": True,
        "total": total,
        "skip": skip,
        "limit": limit,
        "indicators": result,
    }


@router.get("/signatures")
async def get_shared_signatures(
    hours: int = Query(24, ge=1, le=168, description="Time range"),
    min_matches: int = Query(100, ge=1, description="Minimum matches"),
    _=Depends(require_admin),
):
    """
    Get attack signatures shared across tenants.

    Returns signatures that have been effective against
    attacks targeting multiple tenants.

    **Requires admin access**
    """
    now = datetime.utcnow()

    signatures = [
        {
            "signature_id": "sig-001",
            "name": "SYN Flood Pattern A",
            "pattern": "TCP SYN, window_size=0, mss=0",
            "attack_type": "syn_flood",
            "tenants_using": [1, 2, 3, 4, 5],
            "total_matches": 1523890,
            "effectiveness": 0.98,
            "created_at": (now - timedelta(days=30)).isoformat(),
        },
        {
            "signature_id": "sig-002",
            "name": "UDP Amplification",
            "pattern": "UDP, src_port=53|123|1900, payload_ratio>10",
            "attack_type": "udp_amplification",
            "tenants_using": [1, 3, 5],
            "total_matches": 892340,
            "effectiveness": 0.95,
            "created_at": (now - timedelta(days=60)).isoformat(),
        },
        {
            "signature_id": "sig-003",
            "name": "HTTP Slowloris",
            "pattern": "HTTP, incomplete_headers, connection_held>10s",
            "attack_type": "slowloris",
            "tenants_using": [2, 4],
            "total_matches": 45210,
            "effectiveness": 0.92,
            "created_at": (now - timedelta(days=14)).isoformat(),
        },
    ]

    return {
        "success": True,
        "time_range_hours": hours,
        "signatures": [s for s in signatures if s["total_matches"] >= min_matches],
    }


@router.get("/stats", response_model=CrossTenantStats)
async def get_cross_tenant_stats(
    hours: int = Query(24, ge=1, le=168, description="Time range"),
    _=Depends(require_admin),
):
    """
    Get aggregated cross-tenant statistics.

    Returns overall statistics about cross-tenant attack
    patterns and shared intelligence.

    **Requires admin access**
    """
    patterns = _generate_demo_patterns()
    indicators = _generate_demo_indicators()

    return CrossTenantStats(
        total_tenants=5,
        active_tenants=5,
        shared_indicators=len(indicators),
        common_attack_patterns=len(patterns),
        coordinated_attacks_detected=sum(1 for p in patterns if p["pattern_type"] == AttackPatternType.COORDINATED),
        time_range_hours=hours,
    )


@router.post("/share/{tenant_id}")
async def share_indicator(
    tenant_id: int,
    indicator_type: SharedIndicatorType = Query(..., description="Indicator type"),
    value: str = Query(..., min_length=1, max_length=500, description="Indicator value"),
    confidence: float = Query(0.8, ge=0, le=1, description="Confidence score"),
    _=Depends(require_tenant_access),
):
    """
    Share a threat indicator from a tenant.

    Allows tenants to contribute to shared threat intelligence
    that benefits all tenants on the platform.
    """
    indicator_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow()

    indicator = {
        "indicator_id": indicator_id,
        "indicator_type": indicator_type,
        "value": value,
        "shared_by_tenant": tenant_id,
        "affected_tenants": [tenant_id],
        "hit_count": 0,
        "first_seen": now,
        "last_seen": now,
        "confidence": confidence,
        "is_active": True,
    }

    _shared_indicators[indicator_id] = indicator

    logger.info(f"Indicator shared: tenant={tenant_id}, type={indicator_type.value}, value={value}")

    return {
        "success": True,
        "indicator_id": indicator_id,
        "message": "Indicator shared successfully",
    }


@router.get("/config", response_model=CrossTenantConfig)
async def get_cross_tenant_config(
    _=Depends(require_admin),
):
    """
    Get cross-tenant analytics configuration.

    Returns settings controlling cross-tenant correlation
    and sharing behavior.

    **Requires admin access**
    """
    return CrossTenantConfig(
        enabled=_config["enabled"],
        auto_share_indicators=_config["auto_share_indicators"],
        share_attack_signatures=_config["share_attack_signatures"],
        correlation_window_minutes=_config["correlation_window_minutes"],
        min_tenant_match=_config["min_tenant_match"],
        anonymize_tenant_data=_config["anonymize_tenant_data"],
    )


@router.put("/config")
async def update_cross_tenant_config(
    enabled: Optional[bool] = Query(None),
    auto_share_indicators: Optional[bool] = Query(None),
    share_attack_signatures: Optional[bool] = Query(None),
    correlation_window_minutes: Optional[int] = Query(None, ge=5, le=60),
    min_tenant_match: Optional[int] = Query(None, ge=2, le=10),
    anonymize_tenant_data: Optional[bool] = Query(None),
    _=Depends(require_admin),
):
    """
    Update cross-tenant analytics configuration.

    **Requires admin access**
    """
    if enabled is not None:
        _config["enabled"] = enabled
    if auto_share_indicators is not None:
        _config["auto_share_indicators"] = auto_share_indicators
    if share_attack_signatures is not None:
        _config["share_attack_signatures"] = share_attack_signatures
    if correlation_window_minutes is not None:
        _config["correlation_window_minutes"] = correlation_window_minutes
    if min_tenant_match is not None:
        _config["min_tenant_match"] = min_tenant_match
    if anonymize_tenant_data is not None:
        _config["anonymize_tenant_data"] = anonymize_tenant_data

    logger.info("Cross-tenant config updated")

    return CrossTenantConfig(
        enabled=_config["enabled"],
        auto_share_indicators=_config["auto_share_indicators"],
        share_attack_signatures=_config["share_attack_signatures"],
        correlation_window_minutes=_config["correlation_window_minutes"],
        min_tenant_match=_config["min_tenant_match"],
        anonymize_tenant_data=_config["anonymize_tenant_data"],
    )


@router.get("/correlation")
async def get_attack_correlation(
    hours: int = Query(24, ge=1, le=168, description="Time range"),
    _=Depends(require_admin),
):
    """
    Get attack correlation matrix across tenants.

    Shows which tenants are experiencing similar attacks
    at similar times.

    **Requires admin access**
    """
    # Simulated correlation matrix
    tenants = [1, 2, 3, 4, 5]
    matrix = {}

    for t1 in tenants:
        matrix[t1] = {}
        for t2 in tenants:
            if t1 == t2:
                matrix[t1][t2] = 1.0
            else:
                # Simulated correlation
                matrix[t1][t2] = round(0.3 + (0.5 * ((t1 + t2) % 3) / 3), 2)

    return {
        "success": True,
        "time_range_hours": hours,
        "tenants": tenants,
        "correlation_matrix": matrix,
        "high_correlation_pairs": [
            {"tenants": [1, 3], "correlation": 0.87, "common_attacks": 5},
            {"tenants": [2, 4], "correlation": 0.82, "common_attacks": 3},
        ],
    }


@router.get("/timeline")
async def get_cross_tenant_timeline(
    hours: int = Query(24, ge=1, le=168, description="Time range"),
    resolution: str = Query("1h", pattern="^(5m|15m|1h|6h)$"),
    _=Depends(require_admin),
):
    """
    Get cross-tenant attack timeline.

    Shows when attacks occurred across all tenants
    for correlation analysis.

    **Requires admin access**
    """
    now = datetime.utcnow()
    resolution_minutes = {"5m": 5, "15m": 15, "1h": 60, "6h": 360}[resolution]
    points = (hours * 60) // resolution_minutes

    timeline = []
    for i in range(points):
        timestamp = now - timedelta(minutes=i * resolution_minutes)
        timeline.append({
            "timestamp": timestamp.isoformat(),
            "attacks": {
                1: 2 if i % 5 == 0 else 0,
                2: 1 if i % 7 == 0 else 0,
                3: 3 if i % 4 == 0 else 0,
                4: 0,
                5: 1 if i % 6 == 0 else 0,
            },
            "coordinated": i % 12 == 0,
        })

    timeline.reverse()

    return {
        "success": True,
        "time_range_hours": hours,
        "resolution": resolution,
        "data_points": len(timeline),
        "timeline": timeline,
    }
