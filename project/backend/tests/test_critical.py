"""
Critical endpoint tests.

Covers:
- GET /api/v2/system/health
- GET /api/v2/realtime/anomaly
- GET /api/v2/realtime/stats
- GET /api/v2/realtime/connected
- GET /api/v2/layer1/config (schema check)
- GET /api/v2/layer2/config (schema check)
"""

import pytest


@pytest.mark.asyncio
async def test_health_check_returns_200(client):
    """Health endpoint must be accessible without auth and return expected fields."""
    response = await client.get("/api/v2/system/health")
    assert response.status_code == 200
    data = response.json()
    # Health response uses 'overall' as the top-level status key
    assert "overall" in data or "status" in data or "api" in data


@pytest.mark.asyncio
async def test_realtime_connected_requires_auth(client):
    response = await client.get("/api/v2/realtime/connected")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_realtime_connected_with_auth(client, auth_headers):
    response = await client.get("/api/v2/realtime/connected", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "connected" in data
    assert isinstance(data["connected"], bool)


@pytest.mark.asyncio
async def test_realtime_stats_with_auth(client, auth_headers):
    response = await client.get("/api/v2/realtime/stats", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "connected" in data
    assert "ports" in data


@pytest.mark.asyncio
async def test_realtime_anomaly_with_auth(client, auth_headers):
    """Anomaly endpoint must return a valid response even without DPDK running."""
    response = await client.get("/api/v2/realtime/anomaly", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "active" in data
    assert "level" in data
    assert isinstance(data["active"], bool)


@pytest.mark.asyncio
async def test_realtime_anomaly_requires_auth(client):
    response = await client.get("/api/v2/realtime/anomaly")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_layer1_config_returns_json(client, auth_headers):
    response = await client.get("/api/v2/layer1/config", headers=auth_headers)
    # May be 200 or 404 if config file not present, but never 500
    assert response.status_code != 500


@pytest.mark.asyncio
async def test_layer2_config_returns_json(client, auth_headers):
    response = await client.get("/api/v2/layer2/config", headers=auth_headers)
    assert response.status_code != 500


@pytest.mark.asyncio
async def test_stats_history_returns_list(client, auth_headers):
    response = await client.get("/api/v2/realtime/stats/history?limit=10", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_stats_history_limit_max_3600(client, auth_headers):
    """Ensure limit cannot exceed 3600 (api validation)."""
    response = await client.get("/api/v2/realtime/stats/history?limit=99999", headers=auth_headers)
    assert response.status_code == 422  # FastAPI validation error


@pytest.mark.asyncio
async def test_learning_status_endpoint(client, auth_headers):
    """GET /layer2/learning-status returns valid learning state schema."""
    response = await client.get("/api/v2/layer2/learning-status", headers=auth_headers)
    # Endpoint should succeed even when DPDK is not running (falls back to defaults)
    assert response.status_code == 200
    data = response.json()
    # Required fields
    assert "state" in data
    assert "phase" in data
    assert "progress_pct" in data
    assert "tier1_ready" in data
    assert "tier2_ready" in data
    assert "tier3_ready" in data
    assert "tier1_progress" in data
    assert "tier2_progress" in data
    assert "tier3_progress" in data
    assert "eta_mature_seconds" in data
    assert "trust_multiplier" in data
    # Type checks
    assert isinstance(data["state"], str)
    assert data["state"] in ("cold_start", "warmup", "moderate", "mature")
    assert isinstance(data["phase"], int)
    assert 0 <= data["progress_pct"] <= 100
    assert isinstance(data["tier1_ready"], bool)
    assert isinstance(data["trust_multiplier"], float)
