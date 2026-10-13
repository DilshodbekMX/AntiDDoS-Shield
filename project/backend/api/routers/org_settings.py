"""
Organization Settings Router

CRUD for single-org configuration: organization info, protected networks,
telemetry, alerting, and telemetry forwarding settings.
Reads/writes config/single_org_config.json directly.
"""

import json
import logging
import socket
import struct
import fcntl
import array
from typing import Any, Dict, List, Optional
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/org",
    tags=["Organization Settings"],
    dependencies=[Depends(get_current_user)],
)

CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "single_org_config.json"


def _read_config() -> dict:
    """Read the org config file."""
    try:
        return json.loads(CONFIG_PATH.read_text())
    except FileNotFoundError:
        raise HTTPException(404, "Organization config not found")
    except json.JSONDecodeError as e:
        raise HTTPException(500, f"Invalid config JSON: {e}")


def _write_config(data: dict) -> None:
    """Write the org config file with pretty formatting."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(data, indent=4) + "\n")


# ==================== Models ====================

class OrganizationInfo(BaseModel):
    name: str = Field(max_length=200)
    contact_email: str = Field(max_length=200)
    alert_webhook: str = Field(default="", max_length=500)


class ProtectedNetwork(BaseModel):
    network: str = Field(..., pattern=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')
    description: str = Field(default="", max_length=200)


class AlertingConfig(BaseModel):
    enabled: bool = True
    throttle_sec: int = Field(default=60, ge=1, le=3600)
    attack_start: bool = True
    attack_end: bool = True
    severity_threshold: int = Field(default=2, ge=0, le=4)


class LoggingConfig(BaseModel):
    level: str = Field(default="info", pattern=r'^(debug|info|warn|error)$')
    path: str = Field(default="logs/antiddos.log", max_length=500)
    max_size_mb: int = Field(default=100, ge=1, le=10000)
    max_files: int = Field(default=10, ge=1, le=100)


class PrometheusConfig(BaseModel):
    enabled: bool = True
    port: int = Field(default=9090, ge=1024, le=65535)
    path: str = Field(default="/metrics", max_length=200)


class ForwardingStreams(BaseModel):
    stats: bool = True
    traffic: bool = True
    anomaly: bool = True
    per_ip_features: bool = True
    sysmon: bool = False


class ForwardingConfig(BaseModel):
    enabled: bool = False
    bind_ip: str = Field(default="", max_length=45, pattern=r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?$')
    dest_ip: str = Field(default="", max_length=45, pattern=r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?$')
    dest_port: int = Field(default=9999, ge=1, le=65535)
    protocol: str = Field(default="tcp", pattern=r'^(tcp|udp)$')
    streams: ForwardingStreams = Field(default_factory=ForwardingStreams)
    interval_ms: int = Field(default=500, ge=100, le=10000)


# ==================== Endpoints ====================

@router.get("/settings")
async def get_settings():
    """Get full organization settings (organization, telemetry, alerting)."""
    config = _read_config()
    return {
        "organization": config.get("organization", {}),
        "telemetry": config.get("telemetry", {}),
        "alerting": config.get("alerting", {}),
    }


@router.put("/settings/organization")
async def update_organization(org: OrganizationInfo):
    """Update organization info (name, email, webhook)."""
    config = _read_config()
    config["organization"] = org.model_dump()
    _write_config(config)
    logger.info("Organization info updated: %s", org.name)
    return {"ok": True}


@router.get("/settings/networks")
async def get_networks():
    """Get protected networks list."""
    config = _read_config()
    return {"networks": config.get("protected_networks", [])}


@router.put("/settings/networks")
async def update_networks(networks: List[ProtectedNetwork]):
    """Update protected networks list."""
    if len(networks) > 100:
        raise HTTPException(400, "Maximum 100 protected networks")
    config = _read_config()
    config["protected_networks"] = [n.model_dump() for n in networks]
    _write_config(config)
    logger.info("Protected networks updated: %d entries", len(networks))
    return {"ok": True, "count": len(networks)}


@router.get("/settings/alerting")
async def get_alerting():
    """Get alerting configuration."""
    config = _read_config()
    return config.get("alerting", {})


@router.put("/settings/alerting")
async def update_alerting(alerting: AlertingConfig):
    """Update alerting configuration."""
    config = _read_config()
    config["alerting"] = alerting.model_dump()
    _write_config(config)
    logger.info("Alerting config updated")
    return {"ok": True}


@router.get("/settings/telemetry")
async def get_telemetry():
    """Get telemetry configuration (prometheus, logging)."""
    config = _read_config()
    return config.get("telemetry", {})


@router.put("/settings/telemetry/prometheus")
async def update_prometheus(prom: PrometheusConfig):
    """Update Prometheus configuration."""
    config = _read_config()
    if "telemetry" not in config:
        config["telemetry"] = {}
    config["telemetry"]["prometheus"] = prom.model_dump()
    _write_config(config)
    logger.info("Prometheus config updated")
    return {"ok": True}


@router.put("/settings/telemetry/logging")
async def update_logging(log_cfg: LoggingConfig):
    """Update logging configuration."""
    config = _read_config()
    if "telemetry" not in config:
        config["telemetry"] = {}
    config["telemetry"]["logging"] = log_cfg.model_dump()
    _write_config(config)
    logger.info("Logging config updated")
    return {"ok": True}


# ==================== Telemetry Forwarding ====================

@router.get("/settings/telemetry/forwarding")
async def get_forwarding():
    """Get telemetry forwarding configuration."""
    config = _read_config()
    return config.get("telemetry", {}).get("forwarding", {})


@router.put("/settings/telemetry/forwarding")
async def update_forwarding(fwd: ForwardingConfig):
    """Update telemetry forwarding configuration."""
    config = _read_config()
    if "telemetry" not in config:
        config["telemetry"] = {}
    config["telemetry"]["forwarding"] = fwd.model_dump()
    _write_config(config)

    # Notify forwarder service to reload config
    from ..services.telemetry_forwarder import get_forwarder
    forwarder = get_forwarder()
    if forwarder:
        forwarder.reload_config()

    logger.info("Telemetry forwarding config updated: enabled=%s dest=%s:%d/%s",
                fwd.enabled, fwd.dest_ip, fwd.dest_port, fwd.protocol)
    return {"ok": True}


@router.get("/settings/telemetry/forwarding/status")
async def get_forwarding_status():
    """Get live telemetry forwarding status (connection state, counters, errors)."""
    from ..services.telemetry_forwarder import get_forwarder
    forwarder = get_forwarder()
    if not forwarder:
        return {"running": False, "enabled": False}
    return forwarder.status


# ==================== Network Interfaces ====================

def _get_system_interfaces() -> List[Dict[str, str]]:
    """Get network interfaces using SIOCGIFCONF ioctl (Linux, no external deps)."""
    SIOCGIFCONF = 0x8912
    max_bytes = 8096
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        buf = array.array("B", b"\0" * max_bytes)
        ifconf = struct.pack("iL", max_bytes, buf.buffer_info()[0])
        result = fcntl.ioctl(s.fileno(), SIOCGIFCONF, ifconf)
        outbytes = struct.unpack("iL", result)[0]
        data = buf.tobytes()[:outbytes]
        iface_size = 40  # 64-bit Linux: 16 (name) + 24 (sockaddr)
        interfaces = []
        for i in range(0, len(data), iface_size):
            name = data[i : i + 16].split(b"\0", 1)[0].decode()
            ip = socket.inet_ntoa(data[i + 20 : i + 24])
            interfaces.append({"name": name, "ip": ip})
        return interfaces
    finally:
        s.close()


@router.get("/settings/interfaces")
async def get_network_interfaces():
    """List available network interfaces and their IPv4 addresses for bind IP selection."""
    try:
        interfaces = _get_system_interfaces()
    except OSError as e:
        logger.warning("Failed to enumerate interfaces: %s", e)
        interfaces = [{"name": "all", "ip": "0.0.0.0"}]
    # Always include 0.0.0.0 (all interfaces) as an option
    result = [{"name": "all", "ip": "0.0.0.0"}]
    result.extend(iface for iface in interfaces if iface["ip"] != "127.0.0.1")
    return {"interfaces": result}
