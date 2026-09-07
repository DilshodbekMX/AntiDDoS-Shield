"""
Layer 5 Threat Intelligence API router.

Provides endpoints for managing threat intelligence feeds,
indicators of compromise (IoCs), and threat lookups.
"""

import logging
from typing import Optional, List
from datetime import datetime, timedelta
from enum import Enum
import uuid

from fastapi import APIRouter, HTTPException, Query, Depends, Body, BackgroundTasks
from pydantic import BaseModel, Field, HttpUrl

from ...database import get_db
from ...database.models import ThreatIntelFeed, ThreatIntelEntry
from ...auth import require_tenant_access, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/layer5/intel", tags=["Layer 5 - Threat Intelligence"])


# Pydantic models

class FeedType(str, Enum):
    """Threat feed types."""
    IP_BLOCKLIST = "ip_blocklist"
    DOMAIN_BLOCKLIST = "domain_blocklist"
    URL_BLOCKLIST = "url_blocklist"
    HASH_BLOCKLIST = "hash_blocklist"
    MALWARE = "malware"
    BOTNET = "botnet"
    PHISHING = "phishing"
    SPAM = "spam"
    TOR = "tor"
    PROXY = "proxy"
    VPN = "vpn"
    CUSTOM = "custom"


class IndicatorType(str, Enum):
    """Indicator types."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    USER_AGENT = "user_agent"
    ASN = "asn"
    CIDR = "cidr"


class FeedFormat(str, Enum):
    """Feed data formats."""
    PLAIN_TEXT = "plain_text"
    CSV = "csv"
    JSON = "json"
    STIX = "stix"
    TAXII = "taxii"
    MISP = "misp"


class ThreatFeedResponse(BaseModel):
    """Threat feed response."""
    id: str
    name: str
    description: Optional[str] = None
    feed_type: FeedType
    feed_format: FeedFormat
    url: Optional[str] = None
    enabled: bool = True
    is_public: bool = False
    refresh_interval_hours: int = 24
    last_sync_at: Optional[datetime] = None
    next_sync_at: Optional[datetime] = None
    entry_count: int = 0
    error_count: int = 0
    last_error: Optional[str] = None
    created_at: datetime
    metadata: dict = {}

    class Config:
        from_attributes = True


class ThreatFeedCreate(BaseModel):
    """Create threat feed request."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    feed_type: FeedType
    feed_format: FeedFormat = FeedFormat.PLAIN_TEXT
    url: Optional[str] = Field(None, max_length=1000)
    enabled: bool = True
    is_public: bool = False
    refresh_interval_hours: int = Field(24, ge=1, le=168)
    auth_header: Optional[str] = None
    auth_value: Optional[str] = None


class ThreatFeedUpdate(BaseModel):
    """Update threat feed request."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    enabled: Optional[bool] = None
    refresh_interval_hours: Optional[int] = Field(None, ge=1, le=168)
    url: Optional[str] = Field(None, max_length=1000)


class IndicatorResponse(BaseModel):
    """Threat indicator response."""
    id: str
    feed_id: str
    indicator_type: IndicatorType
    value: str
    severity: str
    confidence: float
    tags: List[str] = []
    first_seen: datetime
    last_seen: datetime
    expires_at: Optional[datetime] = None
    metadata: dict = {}

    class Config:
        from_attributes = True


class IndicatorCheck(BaseModel):
    """Indicator check result."""
    found: bool
    indicator: str
    indicator_type: IndicatorType
    matches: List[dict] = []
    threat_level: str
    recommendations: List[str] = []


class ThreatIntelStats(BaseModel):
    """Threat intel statistics."""
    success: bool = True
    total_feeds: int
    active_feeds: int
    total_indicators: int
    by_feed_type: dict
    by_indicator_type: dict
    recent_matches: int
    last_sync: Optional[datetime] = None


# In-memory storage for demo (would be database in production)
_feeds = {}
_indicators = {}


def get_feeds(tenant_id: int) -> dict:
    """Get feeds for tenant."""
    if tenant_id not in _feeds:
        # Initialize with some default public feeds
        _feeds[tenant_id] = {
            "emerging-threats-compromised": {
                "id": "emerging-threats-compromised",
                "tenant_id": tenant_id,
                "name": "Emerging Threats Compromised IPs",
                "description": "IPs of compromised hosts from Emerging Threats",
                "feed_type": FeedType.IP_BLOCKLIST,
                "feed_format": FeedFormat.PLAIN_TEXT,
                "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
                "enabled": True,
                "is_public": True,
                "refresh_interval_hours": 24,
                "entry_count": 0,
                "error_count": 0,
                "created_at": datetime.utcnow(),
            },
            "feodotracker-botnet": {
                "id": "feodotracker-botnet",
                "tenant_id": tenant_id,
                "name": "Feodo Tracker Botnet C2",
                "description": "Botnet C2 IPs from abuse.ch Feodo Tracker",
                "feed_type": FeedType.BOTNET,
                "feed_format": FeedFormat.CSV,
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
                "enabled": True,
                "is_public": True,
                "refresh_interval_hours": 6,
                "entry_count": 0,
                "error_count": 0,
                "created_at": datetime.utcnow(),
            },
            "tor-exit-nodes": {
                "id": "tor-exit-nodes",
                "tenant_id": tenant_id,
                "name": "Tor Exit Nodes",
                "description": "List of Tor exit node IPs",
                "feed_type": FeedType.TOR,
                "feed_format": FeedFormat.PLAIN_TEXT,
                "url": "https://check.torproject.org/torbulkexitlist",
                "enabled": True,
                "is_public": True,
                "refresh_interval_hours": 1,
                "entry_count": 0,
                "error_count": 0,
                "created_at": datetime.utcnow(),
            },
        }
    return _feeds[tenant_id]


def get_indicators(tenant_id: int) -> dict:
    """Get indicators for tenant."""
    if tenant_id not in _indicators:
        _indicators[tenant_id] = {}
    return _indicators[tenant_id]


# Routes

@router.get("/feeds")
async def list_feeds(
    tenant_id: int = Query(..., description="Tenant ID"),
    feed_type: Optional[FeedType] = Query(None, description="Filter by type"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    _=Depends(require_tenant_access),
):
    """
    List threat intelligence feeds.

    Returns configured threat feeds with their sync status
    and indicator counts.
    """
    feeds = get_feeds(tenant_id)

    result = []
    for feed_id, feed in feeds.items():
        if feed_type and feed.get("feed_type") != feed_type:
            continue
        if enabled is not None and feed.get("enabled") != enabled:
            continue

        result.append(ThreatFeedResponse(
            id=feed["id"],
            name=feed["name"],
            description=feed.get("description"),
            feed_type=FeedType(feed["feed_type"]),
            feed_format=FeedFormat(feed.get("feed_format", FeedFormat.PLAIN_TEXT)),
            url=feed.get("url"),
            enabled=feed.get("enabled", True),
            is_public=feed.get("is_public", False),
            refresh_interval_hours=feed.get("refresh_interval_hours", 24),
            last_sync_at=feed.get("last_sync_at"),
            next_sync_at=feed.get("next_sync_at"),
            entry_count=feed.get("entry_count", 0),
            error_count=feed.get("error_count", 0),
            last_error=feed.get("last_error"),
            created_at=feed.get("created_at", datetime.utcnow()),
            metadata=feed.get("metadata", {}),
        ))

    total = len(result)
    result = result[skip:skip + limit]

    return {
        "success": True,
        "total": total,
        "skip": skip,
        "limit": limit,
        "feeds": result,
    }


@router.post("/feeds")
async def create_feed(
    request: ThreatFeedCreate,
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Add a new threat intelligence feed.

    Creates a new feed configuration that will be synced
    on the specified interval.
    """
    feeds = get_feeds(tenant_id)

    feed_id = str(uuid.uuid4())[:8]

    feeds[feed_id] = {
        "id": feed_id,
        "tenant_id": tenant_id,
        "name": request.name,
        "description": request.description,
        "feed_type": request.feed_type,
        "feed_format": request.feed_format,
        "url": request.url,
        "enabled": request.enabled,
        "is_public": request.is_public,
        "refresh_interval_hours": request.refresh_interval_hours,
        "auth_header": request.auth_header,
        "auth_value": request.auth_value,
        "entry_count": 0,
        "error_count": 0,
        "created_at": datetime.utcnow(),
    }

    logger.info(f"Threat feed created: tenant={tenant_id}, name={request.name}")

    return {
        "success": True,
        "feed_id": feed_id,
        "message": "Feed created successfully",
    }


@router.get("/feeds/{feed_id}", response_model=ThreatFeedResponse)
async def get_feed(
    feed_id: str,
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Get details for a specific feed.

    Returns full feed configuration and status information.
    """
    feeds = get_feeds(tenant_id)

    if feed_id not in feeds:
        raise HTTPException(status_code=404, detail="Feed not found")

    feed = feeds[feed_id]

    return ThreatFeedResponse(
        id=feed["id"],
        name=feed["name"],
        description=feed.get("description"),
        feed_type=FeedType(feed["feed_type"]),
        feed_format=FeedFormat(feed.get("feed_format", FeedFormat.PLAIN_TEXT)),
        url=feed.get("url"),
        enabled=feed.get("enabled", True),
        is_public=feed.get("is_public", False),
        refresh_interval_hours=feed.get("refresh_interval_hours", 24),
        last_sync_at=feed.get("last_sync_at"),
        next_sync_at=feed.get("next_sync_at"),
        entry_count=feed.get("entry_count", 0),
        error_count=feed.get("error_count", 0),
        last_error=feed.get("last_error"),
        created_at=feed.get("created_at", datetime.utcnow()),
        metadata=feed.get("metadata", {}),
    )


@router.put("/feeds/{feed_id}")
async def update_feed(
    feed_id: str,
    request: ThreatFeedUpdate,
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Update feed configuration.

    Allows modifying feed settings without losing sync history.
    """
    feeds = get_feeds(tenant_id)

    if feed_id not in feeds:
        raise HTTPException(status_code=404, detail="Feed not found")

    feed = feeds[feed_id]

    if request.name is not None:
        feed["name"] = request.name
    if request.description is not None:
        feed["description"] = request.description
    if request.enabled is not None:
        feed["enabled"] = request.enabled
    if request.refresh_interval_hours is not None:
        feed["refresh_interval_hours"] = request.refresh_interval_hours
    if request.url is not None:
        feed["url"] = request.url

    logger.info(f"Threat feed updated: tenant={tenant_id}, feed={feed_id}")

    return {
        "success": True,
        "feed_id": feed_id,
        "message": "Feed updated successfully",
    }


@router.delete("/feeds/{feed_id}")
async def delete_feed(
    feed_id: str,
    tenant_id: int = Query(..., description="Tenant ID"),
    delete_indicators: bool = Query(True, description="Also delete indicators"),
    _=Depends(require_tenant_access),
):
    """
    Delete a threat feed.

    Optionally removes all indicators associated with the feed.
    """
    feeds = get_feeds(tenant_id)

    if feed_id not in feeds:
        raise HTTPException(status_code=404, detail="Feed not found")

    del feeds[feed_id]

    # Delete associated indicators if requested
    deleted_indicators = 0
    if delete_indicators:
        indicators = get_indicators(tenant_id)
        to_delete = [k for k, v in indicators.items() if v.get("feed_id") == feed_id]
        for key in to_delete:
            del indicators[key]
            deleted_indicators += 1

    logger.info(f"Threat feed deleted: tenant={tenant_id}, feed={feed_id}")

    return {
        "success": True,
        "feed_id": feed_id,
        "deleted_indicators": deleted_indicators,
    }


@router.post("/feeds/{feed_id}/sync")
async def sync_feed(
    feed_id: str,
    background_tasks: BackgroundTasks,
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Force sync a threat feed.

    Triggers an immediate refresh of the feed data.
    """
    feeds = get_feeds(tenant_id)

    if feed_id not in feeds:
        raise HTTPException(status_code=404, detail="Feed not found")

    feed = feeds[feed_id]

    if not feed.get("enabled"):
        raise HTTPException(status_code=400, detail="Feed is disabled")

    # In production, this would trigger actual feed sync
    # Here we just update the sync timestamp
    feed["last_sync_at"] = datetime.utcnow()
    feed["next_sync_at"] = datetime.utcnow() + timedelta(hours=feed.get("refresh_interval_hours", 24))

    logger.info(f"Threat feed sync triggered: tenant={tenant_id}, feed={feed_id}")

    return {
        "success": True,
        "feed_id": feed_id,
        "message": "Feed sync initiated",
        "last_sync_at": feed["last_sync_at"].isoformat(),
    }


@router.get("/indicators")
async def search_indicators(
    tenant_id: int = Query(..., description="Tenant ID"),
    indicator_type: Optional[IndicatorType] = Query(None, description="Filter by type"),
    feed_id: Optional[str] = Query(None, description="Filter by feed"),
    query: Optional[str] = Query(None, description="Search query"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    _=Depends(require_tenant_access),
):
    """
    Search threat indicators.

    Returns indicators matching the specified filters.
    """
    indicators = get_indicators(tenant_id)

    result = []
    for ind_id, ind in indicators.items():
        if indicator_type and ind.get("indicator_type") != indicator_type.value:
            continue
        if feed_id and ind.get("feed_id") != feed_id:
            continue
        if query and query.lower() not in ind.get("value", "").lower():
            continue

        result.append(IndicatorResponse(
            id=ind["id"],
            feed_id=ind["feed_id"],
            indicator_type=IndicatorType(ind["indicator_type"]),
            value=ind["value"],
            severity=ind.get("severity", "medium"),
            confidence=ind.get("confidence", 0.8),
            tags=ind.get("tags", []),
            first_seen=ind.get("first_seen", datetime.utcnow()),
            last_seen=ind.get("last_seen", datetime.utcnow()),
            expires_at=ind.get("expires_at"),
            metadata=ind.get("metadata", {}),
        ))

    total = len(result)
    result = result[skip:skip + limit]

    return {
        "success": True,
        "total": total,
        "skip": skip,
        "limit": limit,
        "indicators": result,
    }


@router.get("/check/{indicator}")
async def check_indicator(
    indicator: str,
    tenant_id: int = Query(..., description="Tenant ID"),
    indicator_type: Optional[IndicatorType] = Query(None, description="Indicator type hint"),
    _=Depends(require_tenant_access),
):
    """
    Check if an indicator is in any threat feed.

    Searches all active feeds for the specified indicator
    and returns match details if found.
    """
    indicators = get_indicators(tenant_id)
    feeds = get_feeds(tenant_id)

    # Auto-detect indicator type if not specified
    if not indicator_type:
        indicator_type = _detect_indicator_type(indicator)

    matches = []

    for ind_id, ind in indicators.items():
        if ind.get("value", "").lower() == indicator.lower():
            feed = feeds.get(ind.get("feed_id", ""), {})
            matches.append({
                "indicator_id": ind_id,
                "feed_id": ind.get("feed_id"),
                "feed_name": feed.get("name", "Unknown"),
                "severity": ind.get("severity", "medium"),
                "confidence": ind.get("confidence", 0.8),
                "first_seen": ind.get("first_seen", datetime.utcnow()).isoformat(),
                "tags": ind.get("tags", []),
            })

    # Calculate threat level based on matches
    if not matches:
        threat_level = "none"
        recommendations = ["No threat indicators found for this value"]
    elif len(matches) >= 3:
        threat_level = "critical"
        recommendations = [
            "Indicator found in multiple threat feeds",
            "Consider immediate blocking",
            "Investigate associated activity",
        ]
    elif any(m.get("severity") == "critical" for m in matches):
        threat_level = "high"
        recommendations = [
            "High severity threat detected",
            "Review and consider blocking",
        ]
    else:
        threat_level = "medium"
        recommendations = [
            "Threat indicator detected",
            "Monitor for suspicious activity",
        ]

    return IndicatorCheck(
        found=len(matches) > 0,
        indicator=indicator,
        indicator_type=indicator_type,
        matches=matches,
        threat_level=threat_level,
        recommendations=recommendations,
    )


def _detect_indicator_type(indicator: str) -> IndicatorType:
    """Auto-detect indicator type from value."""
    import re

    # IP address pattern
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
        return IndicatorType.IP

    # CIDR notation
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", indicator):
        return IndicatorType.CIDR

    # Domain
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$", indicator):
        return IndicatorType.DOMAIN

    # URL
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return IndicatorType.URL

    # MD5 hash
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return IndicatorType.HASH_MD5

    # SHA1 hash
    if re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return IndicatorType.HASH_SHA1

    # SHA256 hash
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return IndicatorType.HASH_SHA256

    # Email
    if "@" in indicator and "." in indicator:
        return IndicatorType.EMAIL

    # ASN
    if re.match(r"^AS\d+$", indicator, re.IGNORECASE):
        return IndicatorType.ASN

    return IndicatorType.IP  # Default


@router.get("/stats", response_model=ThreatIntelStats)
async def get_intel_stats(
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Get threat intelligence statistics.

    Returns aggregated statistics about feeds and indicators.
    """
    feeds = get_feeds(tenant_id)
    indicators = get_indicators(tenant_id)

    total_feeds = len(feeds)
    active_feeds = sum(1 for f in feeds.values() if f.get("enabled"))
    total_indicators = len(indicators)

    # Count by feed type
    by_feed_type = {}
    for feed in feeds.values():
        ft = feed.get("feed_type", "unknown")
        if isinstance(ft, FeedType):
            ft = ft.value
        by_feed_type[ft] = by_feed_type.get(ft, 0) + 1

    # Count by indicator type
    by_indicator_type = {}
    for ind in indicators.values():
        it = ind.get("indicator_type", "unknown")
        by_indicator_type[it] = by_indicator_type.get(it, 0) + 1

    # Get last sync time
    sync_times = [f.get("last_sync_at") for f in feeds.values() if f.get("last_sync_at")]
    last_sync = max(sync_times) if sync_times else None

    return ThreatIntelStats(
        total_feeds=total_feeds,
        active_feeds=active_feeds,
        total_indicators=total_indicators,
        by_feed_type=by_feed_type,
        by_indicator_type=by_indicator_type,
        recent_matches=0,  # Would track actual matches in production
        last_sync=last_sync,
    )


@router.get("/recent")
async def get_recent_matches(
    tenant_id: int = Query(..., description="Tenant ID"),
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(50, ge=1, le=500),
    _=Depends(require_tenant_access),
):
    """
    Get recent threat indicator matches.

    Returns indicators that were recently matched against traffic.
    """
    # In production, this would query actual match logs
    return {
        "success": True,
        "time_range_hours": hours,
        "matches": [],
        "message": "No recent matches found",
    }


@router.post("/indicators")
async def add_indicator(
    indicator_type: IndicatorType = Query(..., description="Indicator type"),
    value: str = Query(..., min_length=1, max_length=500, description="Indicator value"),
    severity: str = Query("medium", pattern="^(low|medium|high|critical)$"),
    tenant_id: int = Query(..., description="Tenant ID"),
    tags: Optional[List[str]] = Query(None, description="Tags"),
    _=Depends(require_tenant_access),
):
    """
    Add a custom threat indicator.

    Manually add an indicator not from a feed.
    """
    indicators = get_indicators(tenant_id)

    ind_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow()

    indicators[ind_id] = {
        "id": ind_id,
        "feed_id": "custom",
        "indicator_type": indicator_type.value,
        "value": value,
        "severity": severity,
        "confidence": 1.0,  # Manual entries are high confidence
        "tags": tags or [],
        "first_seen": now,
        "last_seen": now,
        "metadata": {"source": "manual"},
    }

    logger.info(f"Custom indicator added: tenant={tenant_id}, type={indicator_type.value}, value={value}")

    return {
        "success": True,
        "indicator_id": ind_id,
        "message": "Indicator added successfully",
    }


@router.delete("/indicators/{indicator_id}")
async def delete_indicator(
    indicator_id: str,
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Delete a threat indicator.
    """
    indicators = get_indicators(tenant_id)

    if indicator_id not in indicators:
        raise HTTPException(status_code=404, detail="Indicator not found")

    del indicators[indicator_id]

    return {
        "success": True,
        "indicator_id": indicator_id,
        "deleted": True,
    }
