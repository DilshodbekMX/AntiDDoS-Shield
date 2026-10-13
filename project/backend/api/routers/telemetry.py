"""
Telemetry API Router

Endpoints for querying recorded per-IP feature samples and attack events.
Supports ML dataset export, attack forensics, and operator feedback.
"""

import time
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..services.telemetry_recorder import get_telemetry_recorder

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


class FeedbackRequest(BaseModel):
    event_id: int
    feedback: str  # 'tp', 'fp', 'flash_crowd'


@router.get("/stats")
async def get_telemetry_stats():
    """Get telemetry recorder statistics (sample counts, DB size, etc.)."""
    recorder = get_telemetry_recorder()
    return recorder.get_stats()


@router.get("/features")
async def get_feature_samples(
    dst_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    label: Optional[str] = Query(None, description="Filter by label (normal, attack, tp, fp)"),
    since_minutes: Optional[int] = Query(None, ge=1, le=10080, description="Samples from last N minutes"),
    limit: int = Query(1000, ge=1, le=50000, description="Max rows to return"),
):
    """Query recorded per-IP feature samples.

    Each row contains a 39-element feature vector, baseline means/stds,
    detection state, and a label (normal/attack/tp/fp).
    """
    recorder = get_telemetry_recorder()
    since = time.time() - (since_minutes * 60) if since_minutes else None
    rows = recorder.get_feature_samples(dst_ip=dst_ip, label=label, since=since, limit=limit)
    return {'count': len(rows), 'samples': rows}


@router.get("/events")
async def get_attack_events(
    dst_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    label: Optional[str] = Query(None, description="Filter by label (tp, fp, ambiguous)"),
    since_minutes: Optional[int] = Query(None, ge=1, le=43200, description="Events from last N minutes"),
    limit: int = Query(100, ge=1, le=5000, description="Max rows to return"),
):
    """Query recorded attack events.

    Each event captures the full lifecycle of a detection: start, end,
    peak metrics, classification label, and optional operator feedback.
    """
    recorder = get_telemetry_recorder()
    since = time.time() - (since_minutes * 60) if since_minutes else None
    rows = recorder.get_attack_events(dst_ip=dst_ip, label=label, since=since, limit=limit)
    return {'count': len(rows), 'events': rows}


@router.post("/events/feedback")
async def submit_event_feedback(req: FeedbackRequest):
    """Submit operator feedback on an attack event.

    Overrides the automatic duration-based TP/FP classification with
    operator ground truth. Also updates the label for ML training.

    Valid feedback values: 'tp', 'fp', 'flash_crowd'
    """
    recorder = get_telemetry_recorder()
    if recorder.update_event_feedback(req.event_id, req.feedback):
        return {'status': 'updated', 'event_id': req.event_id, 'feedback': req.feedback}
    raise HTTPException(status_code=400, detail="Failed to update feedback. Invalid event_id or feedback value.")


@router.get("/export/csv")
async def export_features_csv(
    dst_ip: Optional[str] = Query(None),
    label: Optional[str] = Query(None),
    since_minutes: Optional[int] = Query(None, ge=1, le=10080),
    limit: int = Query(50000, ge=1, le=500000),
):
    """Export feature samples as CSV for ML training.

    Returns a CSV with columns: timestamp, dst_ip, feat_0..feat_38,
    anomaly_active, anomaly_level, max_z_score, attack_type, label.
    """
    from fastapi.responses import StreamingResponse
    import io
    import json

    recorder = get_telemetry_recorder()
    since = time.time() - (since_minutes * 60) if since_minutes else None
    rows = recorder.get_feature_samples(dst_ip=dst_ip, label=label, since=since, limit=limit)

    from ..services.telemetry_recorder import L2_FEATURE_NAMES

    def generate():
        # Header
        feat_cols = ','.join(f'feat_{name}' for name in L2_FEATURE_NAMES)
        yield f"timestamp,dst_ip,{feat_cols},anomaly_active,anomaly_level,max_z_score,attack_type,label\n"

        for row in rows:
            feat_values = json.loads(row.get('feat_values', '[]'))
            feat_str = ','.join(f'{v:.6g}' for v in feat_values)
            yield (f"{row['timestamp']},{row['dst_ip']},{feat_str},"
                   f"{row['anomaly_active']},{row['anomaly_level']},"
                   f"{row['max_z_score']:.4f},{row['attack_type']},{row['label']}\n")

    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=telemetry_features.csv"}
    )
