"""
Test configuration and fixtures for the Anti-DDoS backend API.

Uses an in-memory SQLite DB for isolation and mocks external dependencies
(DPDK service, Redis) so tests run without infrastructure.
"""

import os
import sys
import pytest
import pytest_asyncio
from unittest.mock import MagicMock, patch

# Ensure backend directory is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Set test environment BEFORE importing the app
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-32-chars-long")
os.environ.setdefault("ANTIDDOS_ADMIN_USER", "admin")
os.environ.setdefault("ANTIDDOS_ADMIN_PASS", "testpassword")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
# Disable telemetry forwarder in tests
os.environ.setdefault("TELEMETRY_ENABLED", "false")

from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.database.models import Base
from api.database.connection import SessionLocal


# ─────────────────────────────────────────────────────────────────
# In-memory database fixture
# ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def test_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture(scope="session")
def TestSessionLocal(test_engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


# ─────────────────────────────────────────────────────────────────
# App fixture -- patches external services for test isolation
# ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def mock_dpdk_service():
    """Mock DPDK service so tests don't need a running dataplane."""
    mock = MagicMock()
    mock.is_connected.return_value = False
    mock.get_stats.return_value = {
        "connected": False,
        "timestamp": 0,
        "timestamp_str": "00:00:00",
        "ports": {},
        "drops_by_reason": {},
    }
    mock.get_anomaly.return_value = {
        "timestamp": 0,
        "active": False,
        "level": 0,
        "level_name": "NONE",
        "tier_agreement": 0,
        "max_z_score": 0.0,
        "confidence": 0.0,
        "primary_feature": 0,
        "primary_feature_name": "",
        "duration_sec": 0.0,
        "cool_down_remaining": 0.0,
        "baselines_frozen": False,
        "tier1_ready": False,
        "tier2_ready_count": 0,
        "tier3_ready_count": 0,
        "baseline_updates": 0,
        "detection_cycles": 0,
        "detection_count": 0,
        "packets_per_sec": 0,
        "bytes_per_sec": 0,
        "syn_per_sec": 0,
        "unique_src_ips": 0,
        "unique_flows": 0,
        "heavy_hitters": 0,
        "rate_limit_pct": 100,
        "current_threshold": 3.0,
        "learning_phase": 0,
        "learning_phase_name": "COLD",
        "tier1_progress": 0,
        "tier2_progress": 0,
        "tier3_progress": 0,
        "tier1_eta_sec": 0,
        "tier2_eta_sec": 0,
        "tier3_eta_sec": 0,
        "baseline_age_sec": 0,
        "mitigation_active": False,
        "learning_action": 0,
        "suppressed_count": 0,
        "trust_multiplier": 1.0,
        "sensitivity_preset": 0,
        "cusum_active": False,
        "jsd_active": False,
        "fast_active": False,
        "fp_rate": 0.0,
        "tp_rate": 0.0,
        "adaptive_adjustments": 0,
    }
    mock.get_per_ip_features.return_value = {}
    mock.get_per_ip_anomaly.return_value = {}
    mock.get_per_ip_baselines.return_value = {}
    mock.get_traffic.return_value = {"connected": False, "entries": []}
    mock.get_sysmon.return_value = {
        "timestamp": 0,
        "dpdk": {
            "lcores": [],
            "avg_lcore_utilization": 0.0,
            "mempools": [],
            "hugepage_total_mb": 0.0,
            "hugepage_used_mb": 0.0,
            "hugepage_usage_pct": 0.0,
        },
        "system": {
            "cpus": [],
            "avg_cpu_usage": 0.0,
            "mem_total_gb": 0.0,
            "mem_used_gb": 0.0,
            "mem_available_gb": 0.0,
            "mem_usage_pct": 0.0,
            "load_1min": 0.0,
            "load_5min": 0.0,
            "load_15min": 0.0,
        },
    }
    return mock


@pytest_asyncio.fixture(scope="session")
async def app(test_engine, TestSessionLocal, mock_dpdk_service):
    """Create the FastAPI app with test overrides."""
    from api.database.connection import get_db
    from api.services.policy_service import PolicyService

    def override_get_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()

    test_session = TestSessionLocal()

    def make_test_policy_service():
        """Policy service backed by the in-memory test DB."""
        return PolicyService(db=test_session)

    def test_get_db_generator():
        """Generator that yields the shared test session."""
        try:
            yield test_session
        finally:
            pass

    with (
        patch("api.database.connection.init_db"),
        patch("api.database.init_db"),
        patch("api.database.get_db", side_effect=test_get_db_generator),
        patch("api.services.config_service.get_db", side_effect=test_get_db_generator),
        patch("api.services.dpdk_service.get_dpdk_service", return_value=mock_dpdk_service),
        patch("api.routers.realtime.get_dpdk_service", return_value=mock_dpdk_service),
        patch("api.services.telemetry_recorder.get_telemetry_recorder", return_value=MagicMock()),
        patch("api.services.telemetry_forwarder.init_forwarder", return_value=MagicMock()),
        patch("api.services.telemetry_forwarder.stop_forwarder"),
        patch("api.tasks.start_scheduler"),
        patch("api.tasks.stop_scheduler"),
        patch("api.routers.ws.startup_websocket"),
        patch("api.routers.ws.shutdown_websocket"),
        patch("api.cache.get_redis", return_value=None),
        patch("api.routers.policies.get_policy_service", side_effect=make_test_policy_service),
    ):
        from api.main import app as _app
        _app.dependency_overrides[get_db] = override_get_db
        yield _app
        test_session.close()
        _app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client(app):
    """HTTP test client for the FastAPI app."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def auth_token(client):
    """Get a valid JWT by logging in as admin."""
    response = await client.post(
        "/api/v2/auth/login",
        json={"username": "admin", "password": "testpassword"},
    )
    assert response.status_code == 200, f"Login failed: {response.text}"
    return response.json()["access_token"]


@pytest_asyncio.fixture
async def auth_headers(auth_token):
    """Authorization headers for authenticated requests."""
    return {"Authorization": f"Bearer {auth_token}"}
