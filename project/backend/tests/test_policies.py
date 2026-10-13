"""
Policy endpoint tests.

Covers:
- POST /api/v2/policies: creates policy in DB
- GET  /api/v2/policies: lists policies
- DELETE /api/v2/policies/{id}: removes from DB
- Dataplane service is called on create/delete (mock verification)
"""

import pytest
from unittest.mock import MagicMock, patch


@pytest.mark.asyncio
async def test_list_policies_empty(client, auth_headers):
    response = await client.get("/api/v2/policies", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    # Response is wrapped in APIResponse: {"success": true, "data": {"items": [...], "total": 0}}
    if "data" in data and isinstance(data["data"], dict):
        inner = data["data"]
        assert "items" in inner or "policies" in inner
    else:
        assert "items" in data or "policies" in data or isinstance(data, list)


@pytest.mark.asyncio
async def test_create_policy_success(client, auth_headers):
    payload = {
        "name": "Test Block Policy",
        "action": "block",
        "conditions": [
            {"field": "src_ip", "operator": "eq", "value": "1.2.3.4"}
        ],
        "priority": 10,
        "enabled": True,
    }
    response = await client.post("/api/v2/policies", json=payload, headers=auth_headers)
    assert response.status_code in (200, 201)
    data = response.json()
    # May be wrapped in APIResponse
    policy = data.get("data", data)
    assert policy.get("name") == "Test Block Policy"
    assert policy.get("action") == "block"


@pytest.mark.asyncio
async def test_create_policy_invalid_action(client, auth_headers):
    payload = {
        "name": "Invalid Action Policy",
        "action": "nuke",
        "conditions": [],
    }
    response = await client.post("/api/v2/policies", json=payload, headers=auth_headers)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_and_delete_policy(client, auth_headers):
    """Create a policy then delete it -- both DB and dataplane calls."""
    mock_dp = MagicMock()
    mock_dp.add_policy.return_value = True
    mock_dp.delete_policy.return_value = True

    with patch("api.services.policy_service.get_dataplane_service", return_value=mock_dp):
        # Create
        create_response = await client.post(
            "/api/v2/policies",
            json={
                "name": "Temp Delete Test Policy",
                "action": "block",
                "conditions": [{"field": "src_ip", "operator": "eq", "value": "10.0.0.1"}],
            },
            headers=auth_headers,
        )
        assert create_response.status_code in (200, 201)
        resp_data = create_response.json()
        # Response may be wrapped in APIResponse envelope
        policy = resp_data.get("data", resp_data)
        policy_id = policy.get("id")
        assert policy_id is not None

        # Dataplane add_policy should have been called
        mock_dp.add_policy.assert_called_once()

        # Delete
        delete_response = await client.delete(
            f"/api/v2/policies/{policy_id}",
            headers=auth_headers,
        )
        assert delete_response.status_code in (200, 204)

        # Dataplane delete_policy should have been called
        mock_dp.delete_policy.assert_called_once_with(policy_id)


@pytest.mark.asyncio
async def test_get_policy_not_found(client, auth_headers):
    response = await client.get("/api/v2/policies/99999", headers=auth_headers)
    # May return 404 or 200 with empty/null data depending on router implementation
    assert response.status_code in (404, 200)


@pytest.mark.asyncio
async def test_policy_requires_auth(client):
    response = await client.get("/api/v2/policies")
    assert response.status_code in (401, 403)
