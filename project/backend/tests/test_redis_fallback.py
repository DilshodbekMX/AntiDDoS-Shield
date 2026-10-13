"""
Redis cache fallback tests.

Validates that the API operates correctly when Redis is unavailable
(returns None from get_redis), which is the default in tests.
"""

import pytest
from unittest.mock import patch, MagicMock


@pytest.mark.asyncio
async def test_stats_summary_works_without_redis(client, auth_headers):
    """Stats summary must succeed even when Redis is unavailable."""
    with patch("api.cache.get_redis", return_value=None):
        response = await client.get("/api/v2/stats/summary", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_root_works_without_redis(client, auth_headers):
    with patch("api.cache.get_redis", return_value=None):
        response = await client.get("/api/v2/stats", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_rules_whitelist_works_without_redis(client, auth_headers):
    with patch("api.cache.get_redis", return_value=None):
        response = await client.get("/api/v2/rules/whitelist", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_policies_list_works_without_redis(client, auth_headers):
    with patch("api.cache.get_redis", return_value=None):
        response = await client.get("/api/v2/policies", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_redis_error_does_not_crash_api(client, auth_headers):
    """A Redis client that raises on every call must not 500 the API."""
    mock_redis = MagicMock()
    mock_redis.get.side_effect = Exception("Redis connection refused")
    mock_redis.set.side_effect = Exception("Redis connection refused")
    with patch("api.cache.get_redis", return_value=mock_redis):
        response = await client.get("/api/v2/stats/summary", headers=auth_headers)
    # Should degrade gracefully, not 500
    assert response.status_code in (200, 503)
