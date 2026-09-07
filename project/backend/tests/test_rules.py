"""
Tests for the Rules router (/api/v2/rules).

Covers: whitelist, blacklist, protected, check, stats, cleanup.
"""

import pytest

BASE = "/api/v2/rules"


# ── Whitelist ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_whitelist_get_requires_auth(client):
    response = await client.get(f"{BASE}/whitelist")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_whitelist_get_returns_list(client, auth_headers):
    response = await client.get(f"{BASE}/whitelist", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "ips" in data or isinstance(data, list) or "data" in data or "entries" in data


@pytest.mark.asyncio
async def test_whitelist_add_and_remove(client, auth_headers):
    # Add
    add = await client.post(
        f"{BASE}/whitelist",
        json={"ip": "192.0.2.1"},
        headers=auth_headers,
    )
    assert add.status_code in (200, 201)

    # Delete
    delete = await client.delete(f"{BASE}/whitelist/192.0.2.1", headers=auth_headers)
    assert delete.status_code in (200, 204)


@pytest.mark.asyncio
async def test_whitelist_add_invalid_ip(client, auth_headers):
    response = await client.post(
        f"{BASE}/whitelist",
        json={"ip": "not-an-ip"},
        headers=auth_headers,
    )
    assert response.status_code in (400, 422)


@pytest.mark.asyncio
async def test_whitelist_clear(client, auth_headers):
    response = await client.post(f"{BASE}/whitelist/clear", headers=auth_headers)
    assert response.status_code in (200, 204)


# ── Blacklist ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_blacklist_get_requires_auth(client):
    response = await client.get(f"{BASE}/blacklist")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_blacklist_get_returns_list(client, auth_headers):
    response = await client.get(f"{BASE}/blacklist", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_blacklist_add_and_remove(client, auth_headers):
    add = await client.post(
        f"{BASE}/blacklist",
        json={"ip": "198.51.100.1"},
        headers=auth_headers,
    )
    assert add.status_code in (200, 201)

    delete = await client.delete(f"{BASE}/blacklist/198.51.100.1", headers=auth_headers)
    assert delete.status_code in (200, 204)


@pytest.mark.asyncio
async def test_blacklist_clear(client, auth_headers):
    response = await client.post(f"{BASE}/blacklist/clear", headers=auth_headers)
    assert response.status_code in (200, 204)


# ── Protected list ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_protected_get_requires_auth(client):
    response = await client.get(f"{BASE}/protected")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_protected_get_returns_list(client, auth_headers):
    response = await client.get(f"{BASE}/protected", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_protected_add_and_remove(client, auth_headers):
    add = await client.post(
        f"{BASE}/protected",
        json={"ip": "203.0.113.5"},
        headers=auth_headers,
    )
    assert add.status_code in (200, 201)

    delete = await client.delete(f"{BASE}/protected/203.0.113.5", headers=auth_headers)
    assert delete.status_code in (200, 204)


# ── IP check ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_check_ip_requires_auth(client):
    response = await client.get(f"{BASE}/check/1.2.3.4")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_check_ip_returns_verdict(client, auth_headers):
    response = await client.get(f"{BASE}/check/1.2.3.4", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    # Expect some verdict/status field
    assert any(k in data for k in ("action", "verdict", "listed", "allowed", "status",
                                    "in_whitelist", "in_blacklist", "is_protected"))


# ── Rules stats ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rules_stats_requires_auth(client):
    response = await client.get(f"{BASE}/stats")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_rules_stats_returns_data(client, auth_headers):
    response = await client.get(f"{BASE}/stats", headers=auth_headers)
    assert response.status_code == 200


# ── Cleanup ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rules_cleanup_requires_auth(client):
    response = await client.post(f"{BASE}/cleanup")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_rules_cleanup_succeeds(client, auth_headers):
    response = await client.post(f"{BASE}/cleanup", headers=auth_headers)
    assert response.status_code in (200, 204)
