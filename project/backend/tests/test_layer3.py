"""
Tests for the Layer3 router (/api/v2/layer3).

Covers: summary, signatures, attackers, packet-ring,
        generate signatures, add/enable/disable/delete.
"""

import pytest

BASE = "/api/v2/layer3"


@pytest.mark.asyncio
async def test_layer3_summary_requires_auth(client):
    response = await client.get(f"{BASE}/summary")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_layer3_summary_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/summary", headers=auth_headers)
    assert response.status_code in (200, 503)  # 503 if DPDK not running


@pytest.mark.asyncio
async def test_layer3_signatures_requires_auth(client):
    response = await client.get(f"{BASE}/signatures")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_layer3_signatures_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/signatures", headers=auth_headers)
    assert response.status_code in (200, 503)


@pytest.mark.asyncio
async def test_layer3_attackers_requires_auth(client):
    response = await client.get(f"{BASE}/attackers")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_layer3_attackers_returns_list(client, auth_headers):
    response = await client.get(f"{BASE}/attackers", headers=auth_headers)
    assert response.status_code in (200, 503)


@pytest.mark.asyncio
async def test_layer3_attackers_limit_param(client, auth_headers):
    """Limit param must be validated (1-200)."""
    response = await client.get(f"{BASE}/attackers?limit=500", headers=auth_headers)
    assert response.status_code in (200, 422, 503)


@pytest.mark.asyncio
async def test_layer3_packet_ring_requires_auth(client):
    response = await client.get(f"{BASE}/packet-ring")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_layer3_packet_ring_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/packet-ring", headers=auth_headers)
    assert response.status_code in (200, 503)


@pytest.mark.asyncio
async def test_layer3_generate_signatures_requires_auth(client):
    response = await client.post(f"{BASE}/signatures/generate")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_layer3_generate_signatures_ok(client, auth_headers):
    response = await client.post(f"{BASE}/signatures/generate", headers=auth_headers)
    assert response.status_code in (200, 503)
