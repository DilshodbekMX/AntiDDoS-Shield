"""
Layer 4 IP Reputation API router.

Provides endpoints for managing IP reputation scores and categories.
Reputation scoring helps prioritize traffic handling and identify threats.
"""

import logging
from typing import Optional, List
from datetime import datetime, timedelta
from enum import Enum

from fastapi import APIRouter, HTTPException, Query, Depends, Body
from pydantic import BaseModel, Field, IPvAnyAddress

from ...database import get_db
from ...database.models import ReputationEntry
from ...auth import require_tenant_access, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/layer4/reputation", tags=["Layer 4 - Reputation"])


# Pydantic models

class ReputationCategoryEnum(str, Enum):
    """Reputation category classifications."""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    BOT = "bot"
    PROXY = "proxy"
    TOR = "tor"
    VPN = "vpn"
    SCANNER = "scanner"
    ATTACKER = "attacker"
    UNKNOWN = "unknown"


class ReputationResponse(BaseModel):
    """IP reputation response."""
    ip_address: str
    score: float = Field(..., ge=0, le=100, description="Reputation score (0=worst, 100=best)")
    category: ReputationCategoryEnum
    threat_level: str = Field(..., description="Threat level: none, low, medium, high, critical")
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_requests: int = 0
    blocked_requests: int = 0
    flags: List[str] = []
    metadata: dict = {}

    class Config:
        from_attributes = True


class ReputationListResponse(BaseModel):
    """Paginated reputation list response."""
    success: bool = True
    total: int
    skip: int
    limit: int
    items: List[ReputationResponse]


class ReputationAdjustRequest(BaseModel):
    """Request to adjust IP reputation."""
    adjustment: float = Field(..., ge=-100, le=100, description="Score adjustment (-100 to +100)")
    reason: str = Field(..., min_length=1, max_length=500, description="Reason for adjustment")
    duration_hours: Optional[int] = Field(None, ge=1, le=8760, description="Duration in hours (auto-expire)")


class BulkAdjustRequest(BaseModel):
    """Request for bulk reputation adjustment."""
    ip_addresses: List[str] = Field(..., min_items=1, max_items=1000)
    adjustment: float = Field(..., ge=-100, le=100)
    reason: str = Field(..., min_length=1, max_length=500)
    category: Optional[ReputationCategoryEnum] = None


class ReputationStatsResponse(BaseModel):
    """Reputation statistics response."""
    success: bool = True
    total_entries: int
    by_category: dict
    by_threat_level: dict
    average_score: float
    score_distribution: dict


class TopThreatResponse(BaseModel):
    """Top threat IPs response."""
    success: bool = True
    entries: List[ReputationResponse]


class ReputationDecayRequest(BaseModel):
    """Request to trigger reputation decay."""
    decay_factor: float = Field(0.1, ge=0.01, le=0.5, description="Decay factor per hour")
    min_score: float = Field(50.0, ge=0, le=100, description="Minimum score after decay")


# Helper functions

def calculate_threat_level(score: float) -> str:
    """Calculate threat level from reputation score."""
    if score >= 80:
        return "none"
    elif score >= 60:
        return "low"
    elif score >= 40:
        return "medium"
    elif score >= 20:
        return "high"
    else:
        return "critical"


def get_reputation_entry(db, tenant_id: int, ip_address: str) -> Optional[ReputationEntry]:
    """Get or create reputation entry for an IP."""
    entry = (
        db.query(ReputationEntry)
        .filter(
            ReputationEntry.tenant_id == tenant_id,
            ReputationEntry.ip_address == ip_address,
        )
        .first()
    )
    return entry


# Routes

@router.get("/", response_model=ReputationListResponse)
async def list_reputation_entries(
    tenant_id: int = Query(..., description="Tenant ID"),
    category: Optional[ReputationCategoryEnum] = Query(None, description="Filter by category"),
    min_score: Optional[float] = Query(None, ge=0, le=100, description="Minimum score"),
    max_score: Optional[float] = Query(None, ge=0, le=100, description="Maximum score"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    List IP reputation entries for a tenant.

    Supports filtering by category and score range.
    Results are ordered by score (ascending, worst first).
    """
    query = db.query(ReputationEntry).filter(ReputationEntry.tenant_id == tenant_id)

    if category:
        query = query.filter(ReputationEntry.category == category.value)
    if min_score is not None:
        query = query.filter(ReputationEntry.score >= min_score)
    if max_score is not None:
        query = query.filter(ReputationEntry.score <= max_score)

    total = query.count()
    entries = query.order_by(ReputationEntry.score.asc()).offset(skip).limit(limit).all()

    return ReputationListResponse(
        total=total,
        skip=skip,
        limit=limit,
        items=[
            ReputationResponse(
                ip_address=e.ip_address,
                score=e.score,
                category=ReputationCategoryEnum(e.category) if e.category else ReputationCategoryEnum.UNKNOWN,
                threat_level=calculate_threat_level(e.score),
                first_seen=e.first_seen,
                last_seen=e.last_seen,
                total_requests=e.total_requests or 0,
                blocked_requests=e.blocked_requests or 0,
                flags=e.flags or [],
                metadata=e.metadata or {},
            )
            for e in entries
        ],
    )


@router.get("/{ip_address}", response_model=ReputationResponse)
async def get_ip_reputation(
    ip_address: str,
    tenant_id: int = Query(..., description="Tenant ID"),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    Get reputation details for a specific IP address.

    Returns detailed reputation information including score,
    category, threat level, and historical data.
    """
    entry = get_reputation_entry(db, tenant_id, ip_address)

    if not entry:
        # Return default reputation for unknown IPs
        return ReputationResponse(
            ip_address=ip_address,
            score=75.0,  # Default neutral-good score
            category=ReputationCategoryEnum.UNKNOWN,
            threat_level="low",
            total_requests=0,
            blocked_requests=0,
            flags=[],
            metadata={"source": "default"},
        )

    return ReputationResponse(
        ip_address=entry.ip_address,
        score=entry.score,
        category=ReputationCategoryEnum(entry.category) if entry.category else ReputationCategoryEnum.UNKNOWN,
        threat_level=calculate_threat_level(entry.score),
        first_seen=entry.first_seen,
        last_seen=entry.last_seen,
        total_requests=entry.total_requests or 0,
        blocked_requests=entry.blocked_requests or 0,
        flags=entry.flags or [],
        metadata=entry.metadata or {},
    )


@router.post("/{ip_address}/adjust")
async def adjust_ip_reputation(
    ip_address: str,
    request: ReputationAdjustRequest,
    tenant_id: int = Query(..., description="Tenant ID"),
    db=Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(require_tenant_access),
):
    """
    Adjust reputation score for an IP address.

    Positive adjustments improve reputation, negative adjustments
    decrease it. Changes are logged for audit purposes.
    """
    entry = get_reputation_entry(db, tenant_id, ip_address)

    if not entry:
        # Create new entry
        entry = ReputationEntry(
            tenant_id=tenant_id,
            ip_address=ip_address,
            score=75.0,  # Default score
            category="unknown",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            metadata={},
        )
        db.add(entry)

    # Calculate new score
    old_score = entry.score
    new_score = max(0, min(100, entry.score + request.adjustment))
    entry.score = new_score
    entry.last_seen = datetime.utcnow()

    # Update category based on new score
    if new_score < 20:
        entry.category = "malicious"
    elif new_score < 40:
        entry.category = "suspicious"
    elif new_score >= 80:
        entry.category = "clean"

    # Set expiration if duration specified
    if request.duration_hours:
        entry.expires_at = datetime.utcnow() + timedelta(hours=request.duration_hours)

    # Log adjustment in metadata
    adjustments = entry.metadata.get("adjustments", [])
    adjustments.append({
        "timestamp": datetime.utcnow().isoformat(),
        "old_score": old_score,
        "new_score": new_score,
        "adjustment": request.adjustment,
        "reason": request.reason,
        "user": user.get("user_id") if user else None,
    })
    entry.metadata["adjustments"] = adjustments[-10:]  # Keep last 10

    db.commit()

    logger.info(
        f"Reputation adjusted: ip={ip_address}, tenant={tenant_id}, "
        f"old={old_score:.1f}, new={new_score:.1f}, reason={request.reason}"
    )

    return {
        "success": True,
        "ip_address": ip_address,
        "old_score": old_score,
        "new_score": new_score,
        "adjustment": request.adjustment,
        "threat_level": calculate_threat_level(new_score),
    }


@router.post("/bulk-adjust")
async def bulk_adjust_reputation(
    request: BulkAdjustRequest,
    tenant_id: int = Query(..., description="Tenant ID"),
    db=Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(require_tenant_access),
):
    """
    Bulk adjust reputation for multiple IP addresses.

    Efficiently adjusts scores for up to 1000 IPs in a single request.
    """
    adjusted = 0
    created = 0
    now = datetime.utcnow()

    for ip in request.ip_addresses:
        entry = get_reputation_entry(db, tenant_id, ip)

        if not entry:
            entry = ReputationEntry(
                tenant_id=tenant_id,
                ip_address=ip,
                score=75.0,
                category=request.category.value if request.category else "unknown",
                first_seen=now,
                last_seen=now,
                metadata={},
            )
            db.add(entry)
            created += 1

        entry.score = max(0, min(100, entry.score + request.adjustment))
        entry.last_seen = now

        if request.category:
            entry.category = request.category.value

        adjusted += 1

    db.commit()

    logger.info(
        f"Bulk reputation adjustment: tenant={tenant_id}, "
        f"adjusted={adjusted}, created={created}, reason={request.reason}"
    )

    return {
        "success": True,
        "adjusted": adjusted,
        "created": created,
        "total_ips": len(request.ip_addresses),
    }


@router.get("/stats", response_model=ReputationStatsResponse)
async def get_reputation_stats(
    tenant_id: int = Query(..., description="Tenant ID"),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    Get reputation statistics for a tenant.

    Returns aggregated statistics including category distribution,
    threat level distribution, and score histogram.
    """
    from sqlalchemy import func

    entries = (
        db.query(ReputationEntry)
        .filter(ReputationEntry.tenant_id == tenant_id)
        .all()
    )

    total = len(entries)

    if total == 0:
        return ReputationStatsResponse(
            total_entries=0,
            by_category={},
            by_threat_level={},
            average_score=75.0,
            score_distribution={},
        )

    # Category distribution
    by_category = {}
    for entry in entries:
        cat = entry.category or "unknown"
        by_category[cat] = by_category.get(cat, 0) + 1

    # Threat level distribution
    by_threat_level = {"none": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    total_score = 0
    for entry in entries:
        level = calculate_threat_level(entry.score)
        by_threat_level[level] += 1
        total_score += entry.score

    # Score distribution (histogram)
    score_distribution = {
        "0-20": 0,
        "20-40": 0,
        "40-60": 0,
        "60-80": 0,
        "80-100": 0,
    }
    for entry in entries:
        if entry.score < 20:
            score_distribution["0-20"] += 1
        elif entry.score < 40:
            score_distribution["20-40"] += 1
        elif entry.score < 60:
            score_distribution["40-60"] += 1
        elif entry.score < 80:
            score_distribution["60-80"] += 1
        else:
            score_distribution["80-100"] += 1

    return ReputationStatsResponse(
        total_entries=total,
        by_category=by_category,
        by_threat_level=by_threat_level,
        average_score=total_score / total,
        score_distribution=score_distribution,
    )


@router.get("/top-threats", response_model=TopThreatResponse)
async def get_top_threats(
    tenant_id: int = Query(..., description="Tenant ID"),
    limit: int = Query(50, ge=1, le=500, description="Number of results"),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    Get top threat IPs by lowest reputation score.

    Returns the IPs with the worst reputation scores,
    useful for security monitoring and investigation.
    """
    entries = (
        db.query(ReputationEntry)
        .filter(
            ReputationEntry.tenant_id == tenant_id,
            ReputationEntry.score < 50,  # Only include suspicious/malicious
        )
        .order_by(ReputationEntry.score.asc())
        .limit(limit)
        .all()
    )

    return TopThreatResponse(
        entries=[
            ReputationResponse(
                ip_address=e.ip_address,
                score=e.score,
                category=ReputationCategoryEnum(e.category) if e.category else ReputationCategoryEnum.UNKNOWN,
                threat_level=calculate_threat_level(e.score),
                first_seen=e.first_seen,
                last_seen=e.last_seen,
                total_requests=e.total_requests or 0,
                blocked_requests=e.blocked_requests or 0,
                flags=e.flags or [],
                metadata=e.metadata or {},
            )
            for e in entries
        ]
    )


@router.get("/categories")
async def get_reputation_categories(
    tenant_id: int = Query(..., description="Tenant ID"),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    Get category breakdown with counts and examples.

    Provides detailed information about each reputation category
    and sample IPs in each category.
    """
    from sqlalchemy import func

    categories = {}

    for cat in ReputationCategoryEnum:
        entries = (
            db.query(ReputationEntry)
            .filter(
                ReputationEntry.tenant_id == tenant_id,
                ReputationEntry.category == cat.value,
            )
            .order_by(ReputationEntry.score.asc())
            .limit(5)
            .all()
        )

        count = (
            db.query(func.count(ReputationEntry.id))
            .filter(
                ReputationEntry.tenant_id == tenant_id,
                ReputationEntry.category == cat.value,
            )
            .scalar()
            or 0
        )

        categories[cat.value] = {
            "count": count,
            "description": _get_category_description(cat),
            "sample_ips": [e.ip_address for e in entries],
        }

    return {
        "success": True,
        "categories": categories,
    }


def _get_category_description(category: ReputationCategoryEnum) -> str:
    """Get human-readable description for category."""
    descriptions = {
        ReputationCategoryEnum.CLEAN: "Known clean IP with good history",
        ReputationCategoryEnum.SUSPICIOUS: "Shows suspicious patterns but not confirmed malicious",
        ReputationCategoryEnum.MALICIOUS: "Confirmed malicious activity detected",
        ReputationCategoryEnum.BOT: "Automated bot traffic detected",
        ReputationCategoryEnum.PROXY: "Open proxy or anonymizer",
        ReputationCategoryEnum.TOR: "Tor exit node",
        ReputationCategoryEnum.VPN: "VPN service IP",
        ReputationCategoryEnum.SCANNER: "Port scanner or vulnerability scanner",
        ReputationCategoryEnum.ATTACKER: "Active attack source",
        ReputationCategoryEnum.UNKNOWN: "Not yet categorized",
    }
    return descriptions.get(category, "Unknown category")


@router.post("/decay")
async def trigger_reputation_decay(
    request: ReputationDecayRequest,
    tenant_id: int = Query(..., description="Tenant ID"),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    Trigger reputation decay for all entries.

    Moves reputation scores toward the neutral value (50) over time.
    This helps ensure old reputation data doesn't persist indefinitely.
    """
    from sqlalchemy import case

    # Decay scores toward neutral (50)
    # Scores below 50 increase, scores above 50 decrease
    updated = (
        db.query(ReputationEntry)
        .filter(ReputationEntry.tenant_id == tenant_id)
        .update(
            {
                "score": case(
                    (ReputationEntry.score < 50, ReputationEntry.score + (50 - ReputationEntry.score) * request.decay_factor),
                    else_=ReputationEntry.score - (ReputationEntry.score - 50) * request.decay_factor,
                )
            },
            synchronize_session=False,
        )
    )

    # Ensure minimum score is respected
    db.query(ReputationEntry).filter(
        ReputationEntry.tenant_id == tenant_id,
        ReputationEntry.score < request.min_score,
    ).update({"score": request.min_score}, synchronize_session=False)

    db.commit()

    logger.info(
        f"Reputation decay applied: tenant={tenant_id}, entries={updated}, "
        f"factor={request.decay_factor}"
    )

    return {
        "success": True,
        "entries_updated": updated,
        "decay_factor": request.decay_factor,
    }


@router.delete("/{ip_address}")
async def delete_reputation_entry(
    ip_address: str,
    tenant_id: int = Query(..., description="Tenant ID"),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    Delete reputation entry for an IP address.

    Removes the reputation record, causing future lookups
    to return the default reputation score.
    """
    result = (
        db.query(ReputationEntry)
        .filter(
            ReputationEntry.tenant_id == tenant_id,
            ReputationEntry.ip_address == ip_address,
        )
        .delete()
    )
    db.commit()

    if result == 0:
        raise HTTPException(status_code=404, detail="Reputation entry not found")

    return {
        "success": True,
        "ip_address": ip_address,
        "deleted": True,
    }
