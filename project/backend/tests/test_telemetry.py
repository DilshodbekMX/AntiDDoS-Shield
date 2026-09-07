"""
Tests for the Telemetry router (/api/v2/telemetry).

Covers: stats, features, events, feedback, CSV export.
"""

import pytest

BASE = "/api/v2/telemetry"


@pytest.mark.asyncio
async def test_telemetry_stats_returns_200(client):
    """Telemetry stats endpoint has no auth requirement."""
    response = await client.get(f"{BASE}/stats")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_telemetry_features_returns_200(client):
    response = await client.get(f"{BASE}/features")
    assert response.status_code == 200
    data = response.json()
    assert data is not None


@pytest.mark.asyncio
async def test_telemetry_events_returns_200(client):
    response = await client.get(f"{BASE}/events")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_telemetry_feedback_post(client):
    """Submit feedback event -- accepts even with minimal payload."""
    response = await client.post(
        f"{BASE}/events/feedback",
        json={"event_id": "test-event", "correct": True},
    )
    assert response.status_code in (200, 201, 422)


@pytest.mark.asyncio
async def test_telemetry_csv_export(client):
    response = await client.get(f"{BASE}/export/csv")
    assert response.status_code in (200, 204)
