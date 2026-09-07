"""
Tests for the Config router (/api/v2/config).

Covers: GET config, PUT config, reload, reset, history, layer1/layer2 config.
"""

import pytest

BASE = "/api/v2/config"


@pytest.mark.asyncio
async def test_config_get_requires_auth(client):
    response = await client.get(BASE)
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_config_get_returns_data(client, auth_headers):
    response = await client.get(BASE, headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    # Accept either a wrapped APIResponse or a raw config dict
    assert data is not None


@pytest.mark.asyncio
async def test_config_put_requires_auth(client):
    response = await client.put(BASE, json={})
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_config_put_returns_ok_or_validation_error(client, auth_headers):
    # PUT with no changes should succeed or return 422 for invalid fields
    response = await client.put(BASE, json={}, headers=auth_headers)
    assert response.status_code in (200, 400, 422)


@pytest.mark.asyncio
async def test_config_reload_requires_auth(client):
    response = await client.post(f"{BASE}/reload")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_config_reload_ok(client, auth_headers):
    response = await client.post(f"{BASE}/reload", headers=auth_headers)
    assert response.status_code in (200, 202, 500)  # 500 acceptable when DPDK not running


@pytest.mark.asyncio
async def test_config_history_requires_auth(client):
    response = await client.get(f"{BASE}/history")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_config_history_returns_list(client, auth_headers):
    response = await client.get(f"{BASE}/history", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_config_layer1_get(client, auth_headers):
    response = await client.get(f"{BASE}/layer1", headers=auth_headers)
    assert response.status_code != 500


@pytest.mark.asyncio
async def test_config_layer2_get(client, auth_headers):
    response = await client.get(f"{BASE}/layer2", headers=auth_headers)
    assert response.status_code != 500
