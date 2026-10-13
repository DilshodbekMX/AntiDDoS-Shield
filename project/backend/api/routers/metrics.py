"""
Prometheus Metrics Router for FastAPI Backend

Provides /metrics endpoint for exposing Python backend metrics in Prometheus format.
This complements the C-based Prometheus exporter (port 9100) with API-level metrics.

Metrics exported:
- API request counts and latencies
- Database connection pool stats
- Cache hit/miss rates
- WebSocket connection counts
- Background task status
"""

import time
import logging
from typing import Dict, Any
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Request, Response
from fastapi.responses import PlainTextResponse

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/metrics", tags=["Metrics"])

# ============================================================================
# In-memory metrics storage (lightweight, no external dependencies)
# ============================================================================

class MetricsCollector:
    """Simple in-memory metrics collector."""

    def __init__(self):
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, list] = defaultdict(list)
        self.start_time = time.time()

        # Request tracking
        self.request_counts: Dict[str, int] = defaultdict(int)
        self.request_latencies: Dict[str, list] = defaultdict(list)
        self.status_counts: Dict[str, int] = defaultdict(int)

    def inc_counter(self, name: str, value: int = 1, labels: Dict[str, str] = None):
        """Increment a counter."""
        key = self._make_key(name, labels)
        self.counters[key] += value

    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge value."""
        key = self._make_key(name, labels)
        self.gauges[key] = value

    def observe_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Add an observation to a histogram."""
        key = self._make_key(name, labels)
        self.histograms[key].append(value)
        # Keep only last 1000 observations for memory efficiency
        if len(self.histograms[key]) > 1000:
            self.histograms[key] = self.histograms[key][-1000:]

    def record_request(self, method: str, path: str, status: int, latency_ms: float):
        """Record an API request."""
        # Normalize path (remove IDs)
        normalized_path = self._normalize_path(path)

        key = f"{method}:{normalized_path}"
        self.request_counts[key] += 1
        self.request_latencies[key].append(latency_ms)

        # Keep only last 100 latencies per endpoint
        if len(self.request_latencies[key]) > 100:
            self.request_latencies[key] = self.request_latencies[key][-100:]

        # Status code counts
        status_key = f"{status // 100}xx"
        self.status_counts[status_key] += 1

    def _normalize_path(self, path: str) -> str:
        """Normalize path by replacing numeric IDs with {id}."""
        parts = path.split("/")
        normalized = []
        for i, part in enumerate(parts):
            # Replace numeric values with {id}
            if part.isdigit():
                normalized.append("{id}")
            # Replace UUIDs
            elif len(part) == 36 and part.count("-") == 4:
                normalized.append("{uuid}")
            else:
                normalized.append(part)
        return "/".join(normalized)

    def _make_key(self, name: str, labels: Dict[str, str] = None) -> str:
        """Create a metric key with optional labels."""
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def export_prometheus(self) -> str:
        """Export metrics in Prometheus exposition format."""
        lines = []

        # Uptime
        uptime = time.time() - self.start_time
        lines.append("# HELP antiddos_api_uptime_seconds API uptime in seconds")
        lines.append("# TYPE antiddos_api_uptime_seconds gauge")
        lines.append(f"antiddos_api_uptime_seconds {uptime:.2f}")

        # Request counters
        lines.append("")
        lines.append("# HELP antiddos_api_requests_total Total API requests")
        lines.append("# TYPE antiddos_api_requests_total counter")
        for key, count in sorted(self.request_counts.items()):
            method, path = key.split(":", 1)
            lines.append(f'antiddos_api_requests_total{{method="{method}",path="{path}"}} {count}')

        # Status code distribution
        lines.append("")
        lines.append("# HELP antiddos_api_responses_total Responses by status code class")
        lines.append("# TYPE antiddos_api_responses_total counter")
        for status_class, count in sorted(self.status_counts.items()):
            lines.append(f'antiddos_api_responses_total{{status="{status_class}"}} {count}')

        # Request latencies (average)
        lines.append("")
        lines.append("# HELP antiddos_api_latency_ms Average request latency in ms")
        lines.append("# TYPE antiddos_api_latency_ms gauge")
        for key, latencies in sorted(self.request_latencies.items()):
            if latencies:
                avg = sum(latencies) / len(latencies)
                method, path = key.split(":", 1)
                lines.append(f'antiddos_api_latency_ms{{method="{method}",path="{path}"}} {avg:.2f}')

        # Custom counters
        if self.counters:
            lines.append("")
            lines.append("# HELP antiddos_api_counter Custom counter metrics")
            lines.append("# TYPE antiddos_api_counter counter")
            for key, value in sorted(self.counters.items()):
                lines.append(f"antiddos_api_counter_{key} {value}")

        # Custom gauges
        if self.gauges:
            lines.append("")
            lines.append("# HELP antiddos_api_gauge Custom gauge metrics")
            lines.append("# TYPE antiddos_api_gauge gauge")
            for key, value in sorted(self.gauges.items()):
                lines.append(f"antiddos_api_gauge_{key} {value:.4f}")

        # Timestamp
        lines.append("")
        lines.append(f"# Generated at {datetime.utcnow().isoformat()}Z")

        return "\n".join(lines)


# Global metrics collector instance
metrics = MetricsCollector()


# ============================================================================
# Middleware Integration
# ============================================================================

async def metrics_middleware(request: Request, call_next):
    """Middleware to record request metrics."""
    start_time = time.time()

    response = await call_next(request)

    # Calculate latency
    latency_ms = (time.time() - start_time) * 1000

    # Record metrics
    metrics.record_request(
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        latency_ms=latency_ms
    )

    return response


# ============================================================================
# Endpoints
# ============================================================================

@router.get("", response_class=PlainTextResponse)
async def get_metrics():
    """
    Prometheus metrics endpoint.

    Returns metrics in Prometheus exposition format (text/plain).

    **Note**: For datapath metrics, use the C-based exporter on port 9100.
    This endpoint provides API-level metrics only.
    """
    return PlainTextResponse(
        content=metrics.export_prometheus(),
        media_type="text/plain; version=0.0.4; charset=utf-8"
    )


@router.get("/json")
async def get_metrics_json():
    """
    Get metrics in JSON format (for debugging).
    """
    return {
        "uptime_seconds": time.time() - metrics.start_time,
        "request_counts": dict(metrics.request_counts),
        "status_counts": dict(metrics.status_counts),
        "counters": dict(metrics.counters),
        "gauges": dict(metrics.gauges),
        "exported_at": datetime.utcnow().isoformat(),
    }


@router.post("/custom/{name}")
async def record_custom_metric(name: str, value: float, metric_type: str = "counter"):
    """
    Record a custom metric (for integration with other services).

    - **name**: Metric name (alphanumeric and underscore only)
    - **value**: Metric value
    - **metric_type**: "counter" (adds to existing) or "gauge" (sets value)
    """
    # Sanitize name
    safe_name = "".join(c for c in name if c.isalnum() or c == "_")

    if metric_type == "counter":
        metrics.inc_counter(safe_name, int(value))
    else:
        metrics.set_gauge(safe_name, value)

    return {"status": "recorded", "name": safe_name, "value": value}


# ============================================================================
# Helper functions for use by other modules
# ============================================================================

def record_db_query(duration_ms: float, query_type: str = "select"):
    """Record a database query metric."""
    metrics.observe_histogram("db_query_duration", duration_ms, {"type": query_type})
    metrics.inc_counter(f"db_queries_{query_type}")


def record_cache_operation(hit: bool, operation: str = "get"):
    """Record a cache operation."""
    result = "hit" if hit else "miss"
    metrics.inc_counter(f"cache_{operation}_{result}")


def record_websocket_connection(connected: bool):
    """Record WebSocket connection change."""
    if connected:
        metrics.inc_counter("websocket_connections_total")
    metrics.set_gauge("websocket_connections_active",
                      metrics.counters.get("websocket_connections_active", 0) + (1 if connected else -1))


def record_background_task(task_name: str, success: bool, duration_ms: float):
    """Record background task execution."""
    result = "success" if success else "failure"
    metrics.inc_counter(f"bg_task_{task_name}_{result}")
    metrics.observe_histogram("bg_task_duration", duration_ms, {"task": task_name})


def set_active_attacks(count: int):
    """Set the active attack count gauge."""
    metrics.set_gauge("active_attacks", float(count))
