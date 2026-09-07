"""
Tests for the Stats router (/api/v2/stats).

Covers: overview, summary, traffic, traffic history, top-sources,
        protocol-breakdown, geo, security, drop-reasons, layer1,
        layer2, sla, realtime, compare, export.
"""

import pytest

BASE = "/api/v2/stats"


@pytest.mark.asyncio
async def test_stats_root_requires_auth(client):
    response = await client.get(BASE)
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_stats_root_returns_data(client, auth_headers):
    response = await client.get(BASE, headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_summary_requires_auth(client):
    response = await client.get(f"{BASE}/summary")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_stats_summary_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/summary", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data is not None


@pytest.mark.asyncio
async def test_stats_traffic_requires_auth(client):
    response = await client.get(f"{BASE}/traffic")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_stats_traffic_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/traffic", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_traffic_history_requires_auth(client):
    response = await client.get(f"{BASE}/traffic/history")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_stats_traffic_history_returns_list(client, auth_headers):
    response = await client.get(f"{BASE}/traffic/history", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_top_sources_requires_auth(client):
    response = await client.get(f"{BASE}/traffic/top-sources")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_stats_top_sources_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/traffic/top-sources", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_protocol_breakdown_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/traffic/protocol-breakdown", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_geo_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/traffic/geo", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_security_requires_auth(client):
    response = await client.get(f"{BASE}/security")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_stats_security_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/security", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_drop_reasons_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/security/drop-reasons", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_layer1_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/layer1", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_layer2_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/layer2", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_sla_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/sla", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_realtime_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/realtime", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_compare_returns_data(client, auth_headers):
    response = await client.get(
        f"{BASE}/compare",
        params={"period1": "1h", "period2": "24h"},
        headers=auth_headers,
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_export_returns_data(client, auth_headers):
    response = await client.get(
        f"{BASE}/export",
        params={
            "start": "2026-03-26T00:00:00",
            "end": "2026-03-27T00:00:00",
            "format": "json",
        },
        headers=auth_headers,
    )
    assert response.status_code in (200, 202)
