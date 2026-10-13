"""
Layer 5 Baseline Optimization API router.

Provides endpoints for managing traffic baselines, anomaly thresholds,
and automatic baseline optimization.
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
import random

from fastapi import APIRouter, HTTPException, Query, Depends, BackgroundTasks
from pydantic import BaseModel, Field

from ...database import get_db
from ...auth import require_tenant_access, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/layer5/baselines", tags=["Layer 5 - Baselines"])


# Pydantic models

class MetricType(str, Enum):
    """Baseline metric types."""
    PPS = "pps"
    BPS = "bps"
    CONNECTIONS = "connections"
    NEW_CONNECTIONS_PER_SEC = "new_conns_per_sec"
    SYN_RATE = "syn_rate"
    UDP_RATE = "udp_rate"
    ICMP_RATE = "icmp_rate"
    HTTP_REQUESTS = "http_requests"
    DNS_QUERIES = "dns_queries"
    UNIQUE_SRC_IPS = "unique_src_ips"


class BaselineStatus(str, Enum):
    """Baseline learning status."""
    LEARNING = "learning"
    STABLE = "stable"
    UPDATING = "updating"
    ANOMALY = "anomaly"


class BaselineMetric(BaseModel):
    """Single baseline metric."""
    metric: MetricType
    current_value: float
    baseline_mean: float
    baseline_stddev: float
    lower_threshold: float
    upper_threshold: float
    confidence: float
    status: BaselineStatus
    last_updated: datetime
    samples: int


class TenantBaseline(BaseModel):
    """Tenant baseline summary."""
    tenant_id: int
    status: BaselineStatus
    learning_started: Optional[datetime] = None
    learning_completed: Optional[datetime] = None
    last_updated: datetime
    metrics: List[BaselineMetric]
    overall_health: str
    recommendations: List[str] = []


class BaselineHistory(BaseModel):
    """Baseline history entry."""
    timestamp: datetime
    metrics: Dict[str, float]
    anomalies_detected: int
    status: BaselineStatus


class BaselineRecommendation(BaseModel):
    """Baseline optimization recommendation."""
    metric: MetricType
    current_threshold: float
    recommended_threshold: float
    change_percent: float
    reason: str
    confidence: float
    impact: str


class BaselineHealthResponse(BaseModel):
    """Baseline health status response."""
    success: bool = True
    overall_health: str
    learning_progress: float
    metrics_status: Dict[str, str]
    anomaly_rate: float
    last_anomaly: Optional[datetime] = None
    recommendations: List[str] = []


# In-memory baseline storage
_baselines: Dict[int, Dict[str, Any]] = {}


def get_baseline(tenant_id: int) -> dict:
    """Get or initialize baseline for tenant."""
    if tenant_id not in _baselines:
        now = datetime.utcnow()
        _baselines[tenant_id] = {
            "tenant_id": tenant_id,
            "status": BaselineStatus.LEARNING,
            "learning_started": now,
            "learning_completed": None,
            "last_updated": now,
            "learning_progress": 0.0,
            "metrics": {
                MetricType.PPS.value: {
                    "mean": 10000,
                    "stddev": 2000,
                    "lower_threshold": 4000,
                    "upper_threshold": 16000,
                    "confidence": 0.0,
                    "samples": 0,
                    "status": BaselineStatus.LEARNING,
                },
                MetricType.BPS.value: {
                    "mean": 100000000,  # 100 Mbps
                    "stddev": 20000000,
                    "lower_threshold": 40000000,
                    "upper_threshold": 160000000,
                    "confidence": 0.0,
                    "samples": 0,
                    "status": BaselineStatus.LEARNING,
                },
                MetricType.CONNECTIONS.value: {
                    "mean": 5000,
                    "stddev": 1000,
                    "lower_threshold": 2000,
                    "upper_threshold": 8000,
                    "confidence": 0.0,
                    "samples": 0,
                    "status": BaselineStatus.LEARNING,
                },
                MetricType.NEW_CONNECTIONS_PER_SEC.value: {
                    "mean": 100,
                    "stddev": 30,
                    "lower_threshold": 10,
                    "upper_threshold": 190,
                    "confidence": 0.0,
                    "samples": 0,
                    "status": BaselineStatus.LEARNING,
                },
                MetricType.SYN_RATE.value: {
                    "mean": 200,
                    "stddev": 50,
                    "lower_threshold": 50,
                    "upper_threshold": 350,
                    "confidence": 0.0,
                    "samples": 0,
                    "status": BaselineStatus.LEARNING,
                },
                MetricType.UDP_RATE.value: {
                    "mean": 5000,
                    "stddev": 1500,
                    "lower_threshold": 500,
                    "upper_threshold": 9500,
                    "confidence": 0.0,
                    "samples": 0,
                    "status": BaselineStatus.LEARNING,
                },
            },
            "history": [],
            "anomaly_count": 0,
            "last_anomaly": None,
        }
    return _baselines[tenant_id]


def simulate_current_value(metric: str, baseline: dict) -> float:
    """Simulate current metric value for demo."""
    mean = baseline.get("mean", 1000)
    stddev = baseline.get("stddev", 200)
    # Usually within normal range, occasionally anomalous
    if random.random() < 0.05:  # 5% chance of anomaly
        return mean + (random.choice([-1, 1]) * stddev * random.uniform(3, 5))
    return mean + (random.uniform(-2, 2) * stddev)


# Routes

@router.get("/{tenant_id}", response_model=TenantBaseline)
async def get_tenant_baseline(
    tenant_id: int,
    _=Depends(require_tenant_access),
):
    """
    Get baseline information for a tenant.

    Returns current baseline metrics, thresholds, and status.
    """
    baseline = get_baseline(tenant_id)

    metrics = []
    for metric_name, metric_data in baseline["metrics"].items():
        current = simulate_current_value(metric_name, metric_data)
        metrics.append(BaselineMetric(
            metric=MetricType(metric_name),
            current_value=current,
            baseline_mean=metric_data["mean"],
            baseline_stddev=metric_data["stddev"],
            lower_threshold=metric_data["lower_threshold"],
            upper_threshold=metric_data["upper_threshold"],
            confidence=metric_data["confidence"],
            status=BaselineStatus(metric_data["status"]),
            last_updated=baseline["last_updated"],
            samples=metric_data["samples"],
        ))

    # Calculate overall health
    anomaly_count = sum(1 for m in metrics if m.current_value < m.lower_threshold or m.current_value > m.upper_threshold)
    if anomaly_count == 0:
        health = "healthy"
    elif anomaly_count <= 2:
        health = "degraded"
    else:
        health = "critical"

    # Generate recommendations
    recommendations = []
    if baseline["status"] == BaselineStatus.LEARNING:
        progress = baseline.get("learning_progress", 0)
        recommendations.append(f"Baseline learning in progress ({progress:.0%} complete)")
    for m in metrics:
        if m.confidence < 0.5:
            recommendations.append(f"Low confidence for {m.metric.value} baseline - need more samples")

    return TenantBaseline(
        tenant_id=tenant_id,
        status=BaselineStatus(baseline["status"]),
        learning_started=baseline.get("learning_started"),
        learning_completed=baseline.get("learning_completed"),
        last_updated=baseline["last_updated"],
        metrics=metrics,
        overall_health=health,
        recommendations=recommendations,
    )


@router.get("/{tenant_id}/history")
async def get_baseline_history(
    tenant_id: int,
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    resolution: str = Query("1h", pattern="^(5m|15m|1h|6h|1d)$", description="Data resolution"),
    _=Depends(require_tenant_access),
):
    """
    Get baseline history for a tenant.

    Returns historical baseline data for trend analysis.
    """
    baseline = get_baseline(tenant_id)

    # Generate simulated history for demo
    history = []
    now = datetime.utcnow()

    resolution_minutes = {"5m": 5, "15m": 15, "1h": 60, "6h": 360, "1d": 1440}[resolution]
    points = (hours * 60) // resolution_minutes

    for i in range(points):
        timestamp = now - timedelta(minutes=i * resolution_minutes)
        metrics = {}
        for metric_name, metric_data in baseline["metrics"].items():
            metrics[metric_name] = simulate_current_value(metric_name, metric_data)

        history.append(BaselineHistory(
            timestamp=timestamp,
            metrics=metrics,
            anomalies_detected=random.randint(0, 2) if random.random() < 0.1 else 0,
            status=BaselineStatus.STABLE if random.random() > 0.05 else BaselineStatus.ANOMALY,
        ))

    history.reverse()  # Oldest first

    return {
        "success": True,
        "tenant_id": tenant_id,
        "time_range_hours": hours,
        "resolution": resolution,
        "data_points": len(history),
        "history": history,
    }


@router.post("/{tenant_id}/reset")
async def reset_baseline(
    tenant_id: int,
    _=Depends(require_tenant_access),
):
    """
    Reset baseline learning for a tenant.

    Clears existing baseline data and restarts learning.
    """
    if tenant_id in _baselines:
        del _baselines[tenant_id]

    # Re-initialize
    baseline = get_baseline(tenant_id)

    logger.info(f"Baseline reset: tenant={tenant_id}")

    return {
        "success": True,
        "tenant_id": tenant_id,
        "message": "Baseline reset successfully, learning restarted",
        "status": baseline["status"],
    }


@router.get("/{tenant_id}/recommendations")
async def get_recommendations(
    tenant_id: int,
    _=Depends(require_tenant_access),
):
    """
    Get baseline optimization recommendations.

    Returns suggested threshold adjustments based on traffic patterns.
    """
    baseline = get_baseline(tenant_id)

    recommendations = []

    for metric_name, metric_data in baseline["metrics"].items():
        # Simulate recommendation based on samples and variance
        if metric_data["samples"] < 100:
            continue

        # Check if thresholds are too tight or too loose
        current_range = metric_data["upper_threshold"] - metric_data["lower_threshold"]
        expected_range = metric_data["stddev"] * 6  # 3 sigma on each side

        if current_range < expected_range * 0.8:
            # Thresholds too tight
            new_upper = metric_data["mean"] + (metric_data["stddev"] * 3)
            recommendations.append(BaselineRecommendation(
                metric=MetricType(metric_name),
                current_threshold=metric_data["upper_threshold"],
                recommended_threshold=new_upper,
                change_percent=((new_upper - metric_data["upper_threshold"]) / metric_data["upper_threshold"]) * 100,
                reason="Thresholds too tight, causing false positives",
                confidence=0.8,
                impact="Reduce false positive alerts",
            ))
        elif current_range > expected_range * 1.5:
            # Thresholds too loose
            new_upper = metric_data["mean"] + (metric_data["stddev"] * 3)
            recommendations.append(BaselineRecommendation(
                metric=MetricType(metric_name),
                current_threshold=metric_data["upper_threshold"],
                recommended_threshold=new_upper,
                change_percent=((new_upper - metric_data["upper_threshold"]) / metric_data["upper_threshold"]) * 100,
                reason="Thresholds too loose, may miss attacks",
                confidence=0.75,
                impact="Improve attack detection sensitivity",
            ))

    return {
        "success": True,
        "tenant_id": tenant_id,
        "recommendations": recommendations,
        "recommendation_count": len(recommendations),
    }


@router.post("/optimize")
async def trigger_optimization(
    background_tasks: BackgroundTasks,
    tenant_ids: Optional[List[int]] = Query(None, description="Specific tenant IDs"),
    _=Depends(require_tenant_access),
):
    """
    Trigger baseline optimization.

    Runs optimization algorithm to adjust thresholds based on
    recent traffic patterns. Can target specific tenants or all.
    """
    targets = tenant_ids if tenant_ids else list(_baselines.keys())

    optimized = 0
    for tid in targets:
        if tid in _baselines:
            baseline = _baselines[tid]
            baseline["last_updated"] = datetime.utcnow()

            # Simulate optimization - adjust thresholds based on mean/stddev
            for metric_name, metric_data in baseline["metrics"].items():
                if metric_data["samples"] >= 50:
                    metric_data["lower_threshold"] = max(0, metric_data["mean"] - (metric_data["stddev"] * 3))
                    metric_data["upper_threshold"] = metric_data["mean"] + (metric_data["stddev"] * 3)
                    metric_data["confidence"] = min(1.0, metric_data["samples"] / 1000)

            optimized += 1

    logger.info(f"Baseline optimization triggered: tenants={optimized}")

    return {
        "success": True,
        "tenants_optimized": optimized,
        "message": "Baseline optimization completed",
    }


@router.get("/health", response_model=BaselineHealthResponse)
async def get_baseline_health(
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Get baseline system health status.

    Returns overall health of baseline learning and anomaly detection.
    """
    baseline = get_baseline(tenant_id)

    # Calculate learning progress
    total_samples = sum(m["samples"] for m in baseline["metrics"].values())
    min_samples_per_metric = 100
    required_samples = len(baseline["metrics"]) * min_samples_per_metric
    learning_progress = min(1.0, total_samples / required_samples)

    # Get metrics status
    metrics_status = {}
    for metric_name, metric_data in baseline["metrics"].items():
        if metric_data["samples"] < min_samples_per_metric:
            metrics_status[metric_name] = "learning"
        elif metric_data["confidence"] < 0.7:
            metrics_status[metric_name] = "low_confidence"
        else:
            metrics_status[metric_name] = "stable"

    # Calculate anomaly rate
    anomaly_count = baseline.get("anomaly_count", 0)
    total_checks = total_samples or 1
    anomaly_rate = (anomaly_count / total_checks) * 100

    # Determine overall health
    if learning_progress < 0.5:
        overall_health = "learning"
    elif anomaly_rate > 10:
        overall_health = "degraded"
    elif all(s == "stable" for s in metrics_status.values()):
        overall_health = "healthy"
    else:
        overall_health = "fair"

    # Generate recommendations
    recommendations = []
    if learning_progress < 1.0:
        recommendations.append(f"Continue collecting data - {learning_progress:.0%} complete")
    if anomaly_rate > 5:
        recommendations.append("High anomaly rate detected - review thresholds")
    low_conf = [m for m, s in metrics_status.items() if s == "low_confidence"]
    if low_conf:
        recommendations.append(f"Low confidence for: {', '.join(low_conf)}")

    return BaselineHealthResponse(
        overall_health=overall_health,
        learning_progress=learning_progress,
        metrics_status=metrics_status,
        anomaly_rate=anomaly_rate,
        last_anomaly=baseline.get("last_anomaly"),
        recommendations=recommendations,
    )


@router.put("/{tenant_id}/thresholds")
async def update_thresholds(
    tenant_id: int,
    metric: MetricType = Query(..., description="Metric to update"),
    lower_threshold: Optional[float] = Query(None, ge=0, description="Lower threshold"),
    upper_threshold: Optional[float] = Query(None, ge=0, description="Upper threshold"),
    _=Depends(require_tenant_access),
):
    """
    Manually update baseline thresholds.

    Allows overriding auto-calculated thresholds with custom values.
    """
    baseline = get_baseline(tenant_id)

    if metric.value not in baseline["metrics"]:
        raise HTTPException(status_code=404, detail=f"Metric {metric.value} not found")

    metric_data = baseline["metrics"][metric.value]

    if lower_threshold is not None:
        metric_data["lower_threshold"] = lower_threshold
    if upper_threshold is not None:
        metric_data["upper_threshold"] = upper_threshold

    # Validate thresholds
    if metric_data["lower_threshold"] >= metric_data["upper_threshold"]:
        raise HTTPException(status_code=400, detail="Lower threshold must be less than upper threshold")

    baseline["last_updated"] = datetime.utcnow()

    logger.info(f"Baseline thresholds updated: tenant={tenant_id}, metric={metric.value}")

    return {
        "success": True,
        "tenant_id": tenant_id,
        "metric": metric.value,
        "lower_threshold": metric_data["lower_threshold"],
        "upper_threshold": metric_data["upper_threshold"],
    }


@router.post("/{tenant_id}/learn")
async def start_learning(
    tenant_id: int,
    duration_hours: int = Query(24, ge=1, le=168, description="Learning duration in hours"),
    _=Depends(require_tenant_access),
):
    """
    Start or restart baseline learning.

    Initiates learning mode for the specified duration.
    """
    baseline = get_baseline(tenant_id)

    baseline["status"] = BaselineStatus.LEARNING
    baseline["learning_started"] = datetime.utcnow()
    baseline["learning_completed"] = None
    baseline["learning_progress"] = 0.0

    # Reset samples for all metrics
    for metric_data in baseline["metrics"].values():
        metric_data["samples"] = 0
        metric_data["confidence"] = 0.0
        metric_data["status"] = BaselineStatus.LEARNING

    logger.info(f"Baseline learning started: tenant={tenant_id}, duration={duration_hours}h")

    return {
        "success": True,
        "tenant_id": tenant_id,
        "status": BaselineStatus.LEARNING.value,
        "learning_started": baseline["learning_started"].isoformat(),
        "expected_completion": (baseline["learning_started"] + timedelta(hours=duration_hours)).isoformat(),
    }
