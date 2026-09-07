"""
Statistics Router

Statistics and monitoring endpoints.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..auth import UserContext, get_current_user
from ..models import (
    SystemStats, StatsPeriod, StatsHistoryPoint,
    TrafficStats, SecurityStats, LayerStats, SLAStats,
    APIResponse, PaginatedResponse
)
from ..services.stats_service import get_stats_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/stats", tags=["Statistics"])


# ==================== Overview Stats ====================

@router.get("", response_model=APIResponse)
async def get_stats(
    request: Request,
    period: StatsPeriod = Query(default=StatsPeriod.REALTIME, description="Time period"),
    user: UserContext = Depends(get_current_user),
):
    """
    Get comprehensive statistics.

    **Periods:**
    - `realtime`: Current metrics
    - `1h`: Last hour aggregated
    - `24h`: Last 24 hours aggregated
    - `7d`: Last 7 days aggregated
    - `30d`: Last 30 days aggregated
    """
    service = get_stats_service()
    stats = await service.get_stats(period)

    if stats is None:
        raise HTTPException(status_code=404, detail="Stats not found")

    return APIResponse(success=True, data=stats)


@router.get("/summary", response_model=APIResponse)
async def get_stats_summary(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    Get quick summary statistics for dashboard cards.
    """
    service = get_stats_service()
    summary = await service.get_summary()

    return APIResponse(success=True, data=summary)


# ==================== Traffic Stats ====================

@router.get("/traffic", response_model=APIResponse)
async def get_traffic_stats(
    request: Request,
    period: StatsPeriod = Query(default=StatsPeriod.REALTIME),
    user: UserContext = Depends(get_current_user),
):
    """
    Get detailed traffic statistics.
    """
    service = get_stats_service()
    traffic = await service.get_traffic_stats(period)

    return APIResponse(success=True, data=traffic)


@router.get("/traffic/history", response_model=APIResponse)
async def get_traffic_history(
    request: Request,
    start: Optional[datetime] = Query(default=None, description="Start time (default: 1 hour ago)"),
    end: Optional[datetime] = Query(default=None, description="End time (default: now)"),
    resolution: str = Query(default="1m", pattern="^(10s|1m|5m|1h)$", description="Data point resolution"),
    user: UserContext = Depends(get_current_user),
):
    """
    Get traffic history for graphing.

    Returns time-series data points with PPS, BPS, and drop counts.
    """
    # Default time range
    if end is None:
        end = datetime.utcnow()
    if start is None:
        start = end - timedelta(hours=1)

    # Validate range
    max_range = timedelta(days=7)
    if end - start > max_range:
        raise HTTPException(
            status_code=400,
            detail=f"Time range too large. Maximum: {max_range.days} days"
        )

    service = get_stats_service()
    history = await service.get_traffic_history(start, end, resolution)

    return APIResponse(success=True, data=history)


@router.get("/traffic/top-sources", response_model=APIResponse)
async def get_top_sources(
    request: Request,
    limit: int = Query(default=10, ge=1, le=100),
    period: StatsPeriod = Query(default=StatsPeriod.HOUR_1),
    user: UserContext = Depends(get_current_user),
):
    """
    Get top traffic sources by volume.
    """
    service = get_stats_service()
    sources = await service.get_top_sources(limit, period)

    return APIResponse(success=True, data=sources)


@router.get("/traffic/protocol-breakdown", response_model=APIResponse)
async def get_protocol_breakdown(
    request: Request,
    period: StatsPeriod = Query(default=StatsPeriod.REALTIME),
    user: UserContext = Depends(get_current_user),
):
    """
    Get traffic breakdown by protocol.
    """
    service = get_stats_service()
    breakdown = await service.get_protocol_breakdown(period)

    return APIResponse(success=True, data=breakdown)


@router.get("/traffic/geo", response_model=APIResponse)
async def get_geo_distribution(
    request: Request,
    period: StatsPeriod = Query(default=StatsPeriod.HOUR_1),
    user: UserContext = Depends(get_current_user),
):
    """
    Get geographic distribution of traffic.
    """
    service = get_stats_service()
    geo = await service.get_geo_distribution(period)

    return APIResponse(success=True, data=geo)


# ==================== Security Stats ====================

@router.get("/security", response_model=APIResponse)
async def get_security_stats(
    request: Request,
    period: StatsPeriod = Query(default=StatsPeriod.HOUR_24),
    user: UserContext = Depends(get_current_user),
):
    """
    Get security statistics (attacks, mitigations, blocks).
    """
    service = get_stats_service()
    security = await service.get_security_stats(period)

    return APIResponse(success=True, data=security)


@router.get("/security/drop-reasons", response_model=APIResponse)
async def get_drop_reasons(
    request: Request,
    period: StatsPeriod = Query(default=StatsPeriod.HOUR_1),
    user: UserContext = Depends(get_current_user),
):
    """
    Get breakdown of packet drops by reason.
    """
    service = get_stats_service()
    drops = await service.get_drop_reasons(period)

    return APIResponse(success=True, data=drops)


# ==================== Per-Layer Stats ====================

@router.get("/layer1", response_model=APIResponse)
async def get_layer1_stats(
    request: Request,
    period: StatsPeriod = Query(default=StatsPeriod.REALTIME),
    user: UserContext = Depends(get_current_user),
):
    """
    Get Layer 1 (packet processing) statistics.

    Includes rate limiting, SYN proxy, geo-blocking metrics.
    """
    service = get_stats_service()
    stats = await service.get_layer_stats(1, period)

    return APIResponse(success=True, data=stats)


@router.get("/layer2", response_model=APIResponse)
async def get_layer2_stats(
    request: Request,
    period: StatsPeriod = Query(default=StatsPeriod.REALTIME),
    user: UserContext = Depends(get_current_user),
):
    """
    Get Layer 2 (anomaly detection) statistics.

    Includes baseline status, anomaly detections, feature scores.
    """
    service = get_stats_service()
    stats = await service.get_layer_stats(2, period)

    return APIResponse(success=True, data=stats)


# ==================== SLA Stats ====================

@router.get("/sla", response_model=APIResponse)
async def get_sla_stats(
    request: Request,
    period: StatsPeriod = Query(default=StatsPeriod.DAY_30),
    user: UserContext = Depends(get_current_user),
):
    """
    Get SLA compliance statistics.

    Includes availability, MTTD, MTTR, effectiveness metrics.
    """
    service = get_stats_service()
    sla = await service.get_sla_stats(period)

    return APIResponse(success=True, data=sla)


# ==================== Real-time Metrics ====================

@router.get("/realtime", response_model=APIResponse)
async def get_realtime_metrics(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    Get real-time metrics for live dashboard updates.

    Returns current PPS, BPS, active attacks, and key indicators.
    """
    service = get_stats_service()
    realtime = await service.get_realtime_metrics()

    return APIResponse(success=True, data=realtime)


# ==================== Comparison Stats ====================

@router.get("/compare", response_model=APIResponse)
async def compare_periods(
    request: Request,
    period1: StatsPeriod = Query(description="First period to compare"),
    period2: StatsPeriod = Query(description="Second period to compare"),
    user: UserContext = Depends(get_current_user),
):
    """
    Compare statistics between two time periods.

    Useful for week-over-week or month-over-month analysis.
    """
    service = get_stats_service()
    comparison = await service.compare_periods(period1, period2)

    return APIResponse(success=True, data=comparison)


# ==================== Export ====================

@router.get("/export", response_model=APIResponse)
async def export_stats(
    request: Request,
    start: datetime = Query(description="Start time"),
    end: datetime = Query(description="End time"),
    format: str = Query(default="json", pattern="^(json|csv)$"),
    user: UserContext = Depends(get_current_user),
):
    """
    Export statistics data.
    """
    # Validate range
    max_range = timedelta(days=30)
    if end - start > max_range:
        raise HTTPException(
            status_code=400,
            detail=f"Time range too large. Maximum: {max_range.days} days"
        )

    service = get_stats_service()
    data = await service.export_stats(start, end, format)

    return APIResponse(success=True, data=data)
