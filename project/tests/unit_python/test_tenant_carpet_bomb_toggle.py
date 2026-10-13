"""Unit tests for Tenant Carpet Bomb Feature Flag and Subnet /24 Aggregation Toggle."""
import os, sys
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(HERE, "..", ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from backend.api.models import (
    TenantCreate, TenantUpdate, Tenant, TenantFeatures, TenantQuotas, TenantContact,
    TenantTier, TenantStatus, TenantType
)

def test_tenant_features_default():
    """Verify carpet_bomb_detection defaults to False in TenantFeatures."""
    features = TenantFeatures()
    assert features.carpet_bomb_detection is False
    assert features.l1_basic is True
    assert features.l2_anomaly is True

def test_tenant_create_with_carpet_bomb_toggle():
    """Verify TenantCreate schema parses and preserves carpet_bomb_detection flag."""
    contact = TenantContact(primary_email="admin@example.com")
    features = TenantFeatures(carpet_bomb_detection=True)
    
    tenant_req = TenantCreate(
        name="Enterprise Client A",
        tier=TenantTier.ENTERPRISE,
        protected_prefixes=["192.168.10.0/24"],
        contact=contact,
        features=features
    )
    assert tenant_req.features.carpet_bomb_detection is True
    assert tenant_req.protected_prefixes == ["192.168.10.0/24"]

def test_tenant_update_carpet_bomb_toggle():
    """Verify TenantUpdate allows enabling/disabling carpet_bomb_detection."""
    features_off = TenantFeatures(carpet_bomb_detection=False)
    update_req = TenantUpdate(features=features_off)
    assert update_req.features.carpet_bomb_detection is False

    features_on = TenantFeatures(carpet_bomb_detection=True)
    update_req2 = TenantUpdate(features=features_on)
    assert update_req2.features.carpet_bomb_detection is True

def test_tenant_full_model_serialization():
    """Verify Tenant model serializes carpet_bomb_detection in JSON export."""
    contact = TenantContact(primary_email="secops@client.com")
    tenant = Tenant(
        id=42,
        name="Client 42",
        contact=contact,
        features=TenantFeatures(carpet_bomb_detection=True)
    )
    data = tenant.dict()
    assert data["features"]["carpet_bomb_detection"] is True
