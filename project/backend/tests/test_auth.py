"""
Auth endpoint tests.

Covers:
- POST /api/v2/auth/login: valid credentials -> JWT
- POST /api/v2/auth/login: invalid credentials -> 401
- GET  /api/v2/auth/me: valid token -> user info
- GET  /api/v2/auth/me: no token -> 401
"""

import pytest
import pytest_asyncio


@pytest.mark.asyncio
async def test_login_valid_credentials(client):
    response = await client.post(
        "/api/v2/auth/login",
        json={"username": "admin", "password": "testpassword"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 10


@pytest.mark.asyncio
async def test_login_invalid_password(client):
    response = await client.post(
        "/api/v2/auth/login",
        json={"username": "admin", "password": "wrongpassword"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_invalid_username(client):
    response = await client.post(
        "/api/v2/auth/login",
        json={"username": "notauser", "password": "testpassword"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_auth_me_with_valid_token(client, auth_headers):
    response = await client.get("/api/v2/auth/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    # Response may be wrapped in APIResponse envelope {"success": true, "data": {...}}
    # or returned directly as user object
    if "data" in data and isinstance(data["data"], dict):
        user = data["data"]
    else:
        user = data
    assert "user_id" in user or "username" in user or "permissions" in user


@pytest.mark.asyncio
async def test_auth_me_without_token(client):
    response = await client.get("/api/v2/auth/me")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_auth_me_with_invalid_token(client):
    response = await client.get(
        "/api/v2/auth/me",
        headers={"Authorization": "Bearer invalid.token.here"},
    )
    assert response.status_code in (401, 403)
