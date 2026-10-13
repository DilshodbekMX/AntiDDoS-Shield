"""
Per-IP Layer 2 Configuration Router

CRUD API for per-IP detection config overrides.
Each protected IP can have custom z_score_threshold, alpha values, etc.
NULL fields inherit from the global Layer 2 config.
"""

import json
import ipaddress
import logging
import socket
import struct
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, HTTPException, Depends, Body
from pydantic import BaseModel, Field
from ..auth import UserContext, get_current_user
from sqlalchemy.orm import Session

from ..database.connection import get_db
from ..database.repositories.per_ip_config_repo import (
    PerIPL2ConfigRepository,
    OVERRIDE_FIELDS,
)

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from rules import DEFAULT_LAYER2_CONFIG_PATH

# Feature name list -- canonical ordering must match C enum in baselines.h
from .layer2_config import L2_FEATURE_NAMES, L2_FEATURE_GROUPS

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/layer2/per-ip-config",
    tags=["Layer 2 Per-IP Config"],
    dependencies=[Depends(get_current_user)],
)

# Control socket
CONTROL_SOCKET_PATH = "/var/run/antiddos/control.sock"
CMD_L2_RELOAD_PER_IP_CONFIG = 0x37

# Output JSON for C consumption
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
PER_IP_CONFIG_JSON_PATH = PROJECT_ROOT / "data" / "per_ip_l2_config.json"


# ==================== Request/Response Models ====================

class PerIPL2ConfigUpdate(BaseModel):
    z_score_threshold: Optional[float] = Field(None, ge=3.0, le=12.0)
    min_tier_agreement: Optional[int] = Field(None, ge=1, le=3)
    min_features_per_tier: Optional[int] = Field(None, ge=1, le=24)
    cool_down_seconds: Optional[float] = Field(None, ge=0.0, le=300.0)
    baseline_freeze_enabled: Optional[bool] = None
    alpha_immediate_1s: Optional[float] = Field(None, gt=0.0, le=1.0)
    alpha_immediate_10s: Optional[float] = Field(None, gt=0.0, le=1.0)
    alpha_immediate_60s: Optional[float] = Field(None, gt=0.0, le=1.0)
    min_samples_immediate_1s: Optional[int] = Field(None, ge=1, le=1000)
    min_samples_immediate_10s: Optional[int] = Field(None, ge=1, le=1000)
    min_samples_immediate_60s: Optional[int] = Field(None, ge=1, le=1000)
    warmup_pps_threshold: Optional[int] = Field(None, ge=1000, le=10000000)
    warmup_syn_threshold: Optional[int] = Field(None, ge=100, le=1000000)


# ==================== Helpers ====================

def _get_global_config() -> Dict[str, Any]:
    """Read the current global Layer 2 config from disk."""
    try:
        with open(DEFAULT_LAYER2_CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        # Return sensible defaults
        return {
            "z_score_threshold": 4.0,
            "min_tier_agreement": 2,
            "min_features_per_tier": 2,
            "cool_down_seconds": 30.0,
            "baseline_freeze_enabled": True,
            "alpha_immediate_1s": 0.8,
            "alpha_immediate_10s": 0.18,
            "alpha_immediate_60s": 0.033,
            "min_samples_immediate_1s": 10,
            "min_samples_immediate_10s": 10,
            "min_samples_immediate_60s": 30,
            "warmup_pps_threshold": 50000,
            "warmup_syn_threshold": 5000,
        }


def _get_global_feature_weights() -> List[float]:
    """Return global feature_weights from layer2_config.json."""
    try:
        cfg = _get_global_config()
        w = cfg.get('feature_weights', [])
        if len(w) == len(L2_FEATURE_NAMES):
            return w
    except Exception:
        pass
    return [1.0] * len(L2_FEATURE_NAMES)


def _ip_to_network_int(ip_str: str) -> int:
    """Convert IP string to network byte order integer."""
    return int(ipaddress.IPv4Address(ip_str))


def _write_per_ip_config_json(db: Session) -> None:
    """Write all active per-IP configs to JSON for C consumption."""
    repo = PerIPL2ConfigRepository(db)
    configs = repo.get_all_active()

    entries = []
    for cfg in configs:
        entry: Dict[str, Any] = {
            "ip": cfg.ip_address,
            "ip_net": _ip_to_network_int(cfg.ip_address),
        }
        for field in OVERRIDE_FIELDS:
            value = getattr(cfg, field, None)
            if value is not None:
                entry[field] = value
        # Per-IP feature weights for C detection engine
        if cfg.feature_weights is not None:
            try:
                weights = json.loads(cfg.feature_weights)
                entry["feature_weights"] = weights
                entry["use_feature_weights"] = True
            except (ValueError, TypeError):
                pass
        entries.append(entry)

    output = {"configs": entries}

    PER_IP_CONFIG_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(PER_IP_CONFIG_JSON_PATH, "w") as f:
        json.dump(output, f, indent=2)

    logger.info("Wrote %d per-IP L2 configs to %s", len(entries), PER_IP_CONFIG_JSON_PATH)


def _notify_datapath() -> bool:
    """Send CMD_L2_RELOAD_PER_IP_CONFIG to C datapath."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(CONTROL_SOCKET_PATH)
        packet = struct.pack('<BIB', CMD_L2_RELOAD_PER_IP_CONFIG, 0, 0)
        sock.sendall(packet)
        response = sock.recv(4)
        sock.close()
        return len(response) >= 1 and response[0] == 0
    except Exception as e:
        logger.warning("Failed to notify datapath of per-IP config change: %s", e)
        return False


def _validate_protected_ip(ip: str, db: Session) -> None:
    """Ensure the IP is a valid protected IP."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IPv4 address: {ip}")

    # Check if IP exists in protected_ips table
    from ..database.models import ProtectedIP
    exists = db.query(ProtectedIP).filter(ProtectedIP.ip_address == ip).first()
    if not exists:
        raise HTTPException(
            status_code=404,
            detail=f"IP {ip} is not a protected IP. Add it first via /rules/protected."
        )


# ==================== Endpoints ====================

@router.get("")
def list_per_ip_configs(db: Session = Depends(get_db)):
    """List all per-IP Layer 2 config overrides."""
    repo = PerIPL2ConfigRepository(db)
    configs = repo.get_all_active()
    global_config = _get_global_config()

    result = []
    for cfg in configs:
        overrides = repo.get_overrides_dict(cfg)
        effective = dict(global_config)
        for field, value in overrides.items():
            effective[field] = value

        result.append({
            "ip_address": cfg.ip_address,
            "is_active": cfg.is_active,
            "version": cfg.version,
            "overrides": overrides,
            "effective": {k: effective.get(k) for k in OVERRIDE_FIELDS},
            "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
            "updated_by": cfg.updated_by,
        })

    return {"success": True, "data": result, "total": len(result)}


@router.get("/{ip}")
def get_per_ip_config(ip: str, db: Session = Depends(get_db)):
    """Get per-IP config for a specific IP (overrides + effective merged)."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IPv4 address: {ip}")

    repo = PerIPL2ConfigRepository(db)
    cfg = repo.get_by_ip(ip)
    global_config = _get_global_config()

    if cfg and cfg.is_active:
        overrides = repo.get_overrides_dict(cfg)
        effective = dict(global_config)
        for field, value in overrides.items():
            effective[field] = value

        return {
            "success": True,
            "data": {
                "ip_address": cfg.ip_address,
                "is_active": cfg.is_active,
                "version": cfg.version,
                "overrides": overrides,
                "effective": {k: effective.get(k) for k in OVERRIDE_FIELDS},
                "global_defaults": {k: global_config.get(k) for k in OVERRIDE_FIELDS},
                "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
                "updated_by": cfg.updated_by,
            },
        }
    else:
        # No per-IP override exists: return global defaults
        return {
            "success": True,
            "data": {
                "ip_address": ip,
                "is_active": False,
                "version": 0,
                "overrides": {},
                "effective": {k: global_config.get(k) for k in OVERRIDE_FIELDS},
                "global_defaults": {k: global_config.get(k) for k in OVERRIDE_FIELDS},
                "updated_at": None,
                "updated_by": None,
            },
        }


@router.put("/{ip}")
def upsert_per_ip_config(
    ip: str,
    body: PerIPL2ConfigUpdate,
    db: Session = Depends(get_db),
):
    """Create or update per-IP Layer 2 config override."""
    _validate_protected_ip(ip, db)

    repo = PerIPL2ConfigRepository(db)
    data = body.model_dump(exclude_unset=True)

    if not data:
        raise HTTPException(status_code=400, detail="No fields provided to update")

    cfg = repo.upsert(ip, data, updated_by="api")

    # Write JSON for C and notify datapath
    _write_per_ip_config_json(db)
    datapath_notified = _notify_datapath()

    overrides = repo.get_overrides_dict(cfg)
    global_config = _get_global_config()
    effective = dict(global_config)
    for field, value in overrides.items():
        effective[field] = value

    return {
        "success": True,
        "data": {
            "ip_address": cfg.ip_address,
            "is_active": cfg.is_active,
            "version": cfg.version,
            "overrides": overrides,
            "effective": {k: effective.get(k) for k in OVERRIDE_FIELDS},
            "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
            "updated_by": cfg.updated_by,
        },
        "datapath_notified": datapath_notified,
    }


@router.delete("/{ip}")
def delete_per_ip_config(ip: str, db: Session = Depends(get_db)):
    """Delete per-IP config override (revert to global defaults)."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IPv4 address: {ip}")

    repo = PerIPL2ConfigRepository(db)
    deleted = repo.delete_by_ip(ip)

    if not deleted:
        raise HTTPException(status_code=404, detail=f"No per-IP config found for {ip}")

    # Rewrite JSON and notify datapath
    _write_per_ip_config_json(db)
    datapath_notified = _notify_datapath()

    return {
        "success": True,
        "message": f"Per-IP config for {ip} deleted. Now using global defaults.",
        "datapath_notified": datapath_notified,
    }


# ==================== Per-IP Feature Selection ====================

@router.get("/{ip}/features")
def get_per_ip_features(ip: str, db: Session = Depends(get_db)):
    """Get per-IP feature enabled states.

    Returns which of the 39 L2 features are enabled for this IP.
    - If the IP has per-IP overrides, those are returned.
    - Otherwise the global feature_weights from layer2_config.json are used.
    """
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IPv4 address: {ip}")

    n = len(L2_FEATURE_NAMES)
    repo = PerIPL2ConfigRepository(db)
    per_ip_weights = repo.get_feature_weights(ip)
    global_weights = _get_global_feature_weights()

    if per_ip_weights is not None and len(per_ip_weights) == n:
        source = "per_ip"
        weights = per_ip_weights
    else:
        # Fall back to global if stored weights are absent or from a different feature count
        source = "global"
        weights = global_weights

    features = [
        {
            "index": i,
            "name": L2_FEATURE_NAMES[i],
            "group": L2_FEATURE_GROUPS[i],
            "enabled": weights[i] > 0.0,
            "weight": weights[i],
        }
        for i in range(n)
    ]

    return {
        "success": True,
        "ip_address": ip,
        "source": source,  # "per_ip" or "global"
        "features": features,
    }


@router.put("/{ip}/features")
def set_per_ip_features(
    ip: str,
    data: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
):
    """Set per-IP feature enabled states.

    Body: { "feature_enabled": [bool x 39] }

    Disabled features get weight 0.0; enabled features preserve their
    existing per-IP weight (or fall back to the global weight, minimum 1.0).
    The C engine reloads via CMD_L2_RELOAD_PER_IP_CONFIG.
    """
    _validate_protected_ip(ip, db)

    enabled = data.get('feature_enabled')
    if not isinstance(enabled, list) or len(enabled) != len(L2_FEATURE_NAMES):
        raise HTTPException(
            status_code=400,
            detail=f'feature_enabled must be an array of {len(L2_FEATURE_NAMES)} booleans',
        )
    if not all(isinstance(v, bool) for v in enabled):
        raise HTTPException(status_code=400, detail='All entries must be booleans')

    n = len(L2_FEATURE_NAMES)
    repo = PerIPL2ConfigRepository(db)
    # Resolve current per-IP weights (fall back to global if absent or wrong length)
    stored = repo.get_feature_weights(ip)
    current_weights = stored if (stored and len(stored) == n) else _get_global_feature_weights()

    effective_weights = [
        0.0 if not enabled[i] else (current_weights[i] if current_weights[i] > 0.0 else 1.0)
        for i in range(n)
    ]

    repo.set_feature_weights(ip, effective_weights, updated_by="api")

    _write_per_ip_config_json(db)
    datapath_notified = _notify_datapath()

    features = [
        {
            "index": i,
            "name": L2_FEATURE_NAMES[i],
            "enabled": effective_weights[i] > 0.0,
            "weight": effective_weights[i],
        }
        for i in range(len(L2_FEATURE_NAMES))
    ]

    return {
        "success": True,
        "ip_address": ip,
        "features": features,
        "datapath_notified": datapath_notified,
    }


@router.delete("/{ip}/features")
def reset_per_ip_features(ip: str, db: Session = Depends(get_db)):
    """Reset per-IP feature selection to global defaults."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IPv4 address: {ip}")

    repo = PerIPL2ConfigRepository(db)
    if not repo.clear_feature_weights(ip, updated_by="api"):
        raise HTTPException(status_code=404, detail=f"No per-IP feature overrides for {ip}")

    _write_per_ip_config_json(db)
    datapath_notified = _notify_datapath()

    return {
        "success": True,
        "message": f"Per-IP feature selection for {ip} reset to global defaults.",
        "datapath_notified": datapath_notified,
    }
