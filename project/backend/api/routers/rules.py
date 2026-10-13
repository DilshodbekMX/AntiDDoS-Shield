"""
Rules Engine Router

FastAPI router for IP whitelist/blacklist/protected management.
Communicates with DPDK datapath via the rules engine.
"""

import re
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Body, Request
from pydantic import BaseModel, Field, field_validator, model_validator

# Import rules engine from backend
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from rules import (
    get_rules_engine, init_rules_engine,
    get_config_manager, init_config_manager,
    get_layer2_config_manager, init_layer2_config_manager
)
from ..auth import UserContext, get_current_user

router = APIRouter(prefix="/rules", tags=["Rules Engine"])

# Initialize rules engine on import
rules_engine = init_rules_engine()


def sanitize_description(desc: str) -> str:
    """Sanitize description field to prevent log/command injection."""
    if not isinstance(desc, str):
        return ''
    desc = desc[:256]
    desc = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', desc)
    desc = desc.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    desc = desc.replace('"', '&quot;').replace("'", '&#x27;')
    return desc


# Request/Response models
class IPEntry(BaseModel):
    ip: str = Field(..., description="IP address (IPv4 or IPv6)")
    description: Optional[str] = Field(None, max_length=256)
    expires_hours: Optional[int] = Field(None, ge=1, le=8760, description="Hours until expiration")
    mode: Optional[str] = Field("bypass", description="Whitelist mode: bypass or track")

    @field_validator('description')
    @classmethod
    def sanitize_desc(cls, v):
        return sanitize_description(v) if v else ''


class IPListEntry(BaseModel):
    ip: str
    description: str = ""
    added: Optional[str] = None
    created: Optional[str] = None
    expires: Optional[str] = None
    rule_type: Optional[int] = None
    hit_count: Optional[int] = 0
    last_hit: Optional[str] = None
    profile_name: Optional[str] = None
    profile_overrides: Optional[Dict[str, Any]] = None
    mode: Optional[str] = None


class IPListResponse(BaseModel):
    entries: List[IPListEntry]
    count: int


class IPCheckResponse(BaseModel):
    ip: str
    in_whitelist: bool
    in_blacklist: bool
    is_protected: bool
    in_cidr_whitelist: bool


class RulesStatsResponse(BaseModel):
    whitelist_count: int
    blacklist_count: int
    protected_count: int
    cidr_whitelist_count: int
    total_rules: int = 0
    last_sync: Optional[str] = None
    sync_errors: int = 0
    datapath_connected: bool = False


class ProtectionProfileOverrides(BaseModel):
    pps_limit: Optional[int] = Field(None, ge=0, le=10000000)
    bps_limit: Optional[int] = Field(None, ge=0, le=10000000000)
    attack_pps_limit: Optional[int] = Field(None, ge=0, le=10000000)
    attack_bps_limit: Optional[int] = Field(None, ge=0, le=10000000000)
    max_conn_per_src: Optional[int] = Field(None, ge=0, le=1000000)
    max_conn_total: Optional[int] = Field(None, ge=0, le=10000000)
    syn_proxy_mode: Optional[str] = Field(None, pattern="^(global|disabled|always|threshold)$")
    syn_challenge_threshold: Optional[int] = Field(None, ge=0, le=1000000)
    tcp_ports: Optional[List[int]] = Field(None, max_length=16)
    udp_ports: Optional[List[int]] = Field(None, max_length=16)
    # Per-protocol actions
    tcp_action: Optional[str] = Field(None, pattern="^(allow|drop|rate_limit)$")
    udp_action: Optional[str] = Field(None, pattern="^(allow|drop|rate_limit)$")
    icmp_action: Optional[str] = Field(None, pattern="^(allow|drop|rate_limit)$")
    other_action: Optional[str] = Field(None, pattern="^(allow|drop|rate_limit)$")
    # Per-protocol aggregate PPS rate limits
    tcp_rate_limit_pps: Optional[int] = Field(None, ge=0, le=100000000)
    udp_rate_limit_pps: Optional[int] = Field(None, ge=0, le=100000000)
    icmp_rate_limit_pps: Optional[int] = Field(None, ge=0, le=100000000)
    other_rate_limit_pps: Optional[int] = Field(None, ge=0, le=100000000)

    # Allowed IP protocol numbers for "other" category (e.g. [47, 50] for GRE+ESP)
    other_allowed_protos: Optional[list[int]] = Field(None, max_length=16)

    @field_validator('tcp_ports', 'udp_ports')
    @classmethod
    def validate_ports(cls, v):
        if v is not None:
            for port in v:
                if port < 0 or port > 65535:
                    raise ValueError(f"Port {port} out of range (0-65535)")
        return v

    @field_validator('other_allowed_protos')
    @classmethod
    def validate_protos(cls, v):
        if v is not None:
            for p in v:
                if p < 0 or p > 255:
                    raise ValueError(f"Protocol number {p} out of range (0-255)")
        return v

    @model_validator(mode='after')
    def validate_rate_limit_requires_pps(self):
        """If protocol action is 'rate_limit', the corresponding PPS limit must be set and > 0."""
        for proto in ('tcp', 'udp', 'icmp', 'other'):
            action = getattr(self, f'{proto}_action')
            pps = getattr(self, f'{proto}_rate_limit_pps')
            if action == 'rate_limit' and (pps is None or pps == 0):
                raise ValueError(
                    f"{proto}_action is 'rate_limit' but {proto}_rate_limit_pps is not set. "
                    f"Set a PPS limit > 0, or use 'allow' / 'drop' instead."
                )
        return self


class ProtectedIPEntry(BaseModel):
    ip: str = Field(..., description="IP address, or CIDR subnet (e.g. 10.0.5.0/24) to "
                                    "aggregate the whole subnet into one protected entry")
    description: Optional[str] = Field(None, max_length=256)
    profile: str = Field("generic", description="Profile template name")
    overrides: Optional[ProtectionProfileOverrides] = None

    @field_validator('description')
    @classmethod
    def sanitize_desc(cls, v):
        return sanitize_description(v) if v else ''


# Whitelist endpoints
@router.get("/whitelist", response_model=IPListResponse)
async def get_whitelist(user: UserContext = Depends(get_current_user)):
    """Get all whitelist entries."""
    return {
        'entries': rules_engine.get_whitelist(),
        'count': len(rules_engine.whitelist)
    }


@router.post("/whitelist")
async def add_whitelist(entry: IPEntry, user: UserContext = Depends(get_current_user)):
    """Add IP to whitelist."""
    expires = None
    if entry.expires_hours:
        expires = datetime.now() + timedelta(hours=entry.expires_hours)

    mode = entry.mode if entry.mode in ("bypass", "track") else "bypass"
    if rules_engine.add_whitelist(entry.ip, entry.description or '', expires, mode=mode):
        return {'status': 'added', 'ip': entry.ip, 'mode': mode}
    else:
        raise HTTPException(status_code=400, detail='Failed to add IP')


@router.delete("/whitelist/{ip}")
async def delete_whitelist(ip: str, user: UserContext = Depends(get_current_user)):
    """Remove IP from whitelist."""
    if rules_engine.remove_whitelist(ip):
        return {'status': 'removed', 'ip': ip}
    else:
        raise HTTPException(status_code=404, detail='IP not found')


@router.post("/whitelist/clear")
async def clear_whitelist(user: UserContext = Depends(get_current_user)):
    """Clear all whitelist entries."""
    count = rules_engine.clear_whitelist()
    return {'status': 'cleared', 'count': count}


# Blacklist endpoints
@router.get("/blacklist", response_model=IPListResponse)
async def get_blacklist(user: UserContext = Depends(get_current_user)):
    """Get all blacklist entries."""
    return {
        'entries': rules_engine.get_blacklist(),
        'count': len(rules_engine.blacklist)
    }


@router.post("/blacklist")
async def add_blacklist(entry: IPEntry, user: UserContext = Depends(get_current_user)):
    """Add IP to blacklist."""
    expires = None
    if entry.expires_hours:
        expires = datetime.now() + timedelta(hours=entry.expires_hours)

    if rules_engine.add_blacklist(entry.ip, entry.description or '', expires):
        return {'status': 'added', 'ip': entry.ip}
    else:
        raise HTTPException(status_code=400, detail='Failed to add IP')


@router.delete("/blacklist/{ip}")
async def delete_blacklist(ip: str, user: UserContext = Depends(get_current_user)):
    """Remove IP from blacklist."""
    if rules_engine.remove_blacklist(ip):
        return {'status': 'removed', 'ip': ip}
    else:
        raise HTTPException(status_code=404, detail='IP not found')


@router.post("/blacklist/clear")
async def clear_blacklist(user: UserContext = Depends(get_current_user)):
    """Clear all blacklist entries."""
    count = rules_engine.clear_blacklist()
    return {'status': 'cleared', 'count': count}


# Protected IPs endpoints
@router.get("/protected", response_model=IPListResponse)
async def get_protected(user: UserContext = Depends(get_current_user)):
    """Get all protected server entries."""
    return {
        'entries': rules_engine.get_protected(),
        'count': len(rules_engine.protected)
    }


@router.post("/protected")
async def add_protected(entry: ProtectedIPEntry, user: UserContext = Depends(get_current_user)):
    """Add IP to protected servers with optional protection profile."""
    overrides_dict = entry.overrides.model_dump(exclude_none=True) if entry.overrides else None
    if rules_engine.add_protected(
        entry.ip,
        entry.description or '',
        profile_name=entry.profile,
        profile_overrides=overrides_dict
    ):
        return {'status': 'added', 'ip': entry.ip, 'profile': entry.profile}
    else:
        raise HTTPException(status_code=400, detail='Failed to add IP')


@router.delete("/protected/{ip:path}")
async def delete_protected(ip: str, user: UserContext = Depends(get_current_user)):
    """Remove an IP or CIDR subnet from protected servers.

    The {ip:path} converter allows CIDR values whose '/' would otherwise not match
    a normal path segment (e.g. DELETE /protected/10.0.5.0/24).
    """
    if rules_engine.remove_protected(ip):
        return {'status': 'removed', 'ip': ip}
    else:
        raise HTTPException(status_code=404, detail='IP not found')


@router.post("/protected/clear")
async def clear_protected(user: UserContext = Depends(get_current_user)):
    """Clear all protected server IPs.

    Warning: If enforce_protected_ips is enabled, ALL traffic will be dropped.
    """
    count = rules_engine.clear_protected()
    return {
        'status': 'cleared',
        'count': count,
        'warning': 'If enforce_protected_ips is enabled, all traffic will now be dropped'
    }


# Profile endpoints
@router.get("/profiles")
async def get_profile_templates(user: UserContext = Depends(get_current_user)):
    """Get available protection profile templates."""
    return {
        'templates': rules_engine.get_profile_templates(),
        'count': len(rules_engine.PROFILE_TEMPLATES)
    }


@router.get("/protected/{ip}/profile")
async def get_protected_profile(ip: str, user: UserContext = Depends(get_current_user)):
    """Get the protection profile for a protected IP."""
    profile = rules_engine.get_protected_profile(ip)
    if profile is None:
        raise HTTPException(status_code=404, detail='Protected IP not found')
    return profile


@router.put("/protected/{ip}/profile")
async def update_protected_profile(ip: str, profile: ProtectionProfileOverrides,
                                    profile_name: str = "generic",
                                    user: UserContext = Depends(get_current_user)):
    """Update the protection profile for a protected IP."""
    overrides_dict = profile.model_dump(exclude_none=True)
    if rules_engine.update_protected_profile(ip, profile_name, overrides_dict):
        return {'status': 'updated', 'ip': ip, 'profile': profile_name}
    else:
        raise HTTPException(status_code=404, detail='Protected IP not found')


# IP check endpoint
@router.get("/check/{ip}", response_model=IPCheckResponse)
async def check_ip(ip: str, user: UserContext = Depends(get_current_user)):
    """Check if IP is in any list."""
    result = rules_engine.check_ip(ip)
    # Transform field names to match response model
    return {
        'ip': result.get('ip', ip),
        'in_whitelist': result.get('whitelisted', False),
        'in_blacklist': result.get('blacklisted', False),
        'is_protected': result.get('protected', False),
        'in_cidr_whitelist': 'whitelist_cidr' in result,
    }


# Stats endpoint
@router.get("/stats", response_model=RulesStatsResponse)
async def get_rules_stats(user: UserContext = Depends(get_current_user)):
    """Get rules engine statistics."""
    stats = rules_engine.get_stats()
    # Add datapath_connected based on sync_errors (0 errors = connected)
    stats['datapath_connected'] = stats.get('sync_errors', 0) == 0
    return stats


# Maintenance endpoints
@router.post("/cleanup")
async def cleanup_expired(user: UserContext = Depends(get_current_user)):
    """Remove expired rules."""
    count = rules_engine.cleanup_expired()
    return {'status': 'cleaned', 'count': count}


@router.post("/sync")
async def sync_rules(user: UserContext = Depends(get_current_user)):
    """Sync all rules to DPDK datapath.

    Call this after DPDK starts to ensure all rules are registered.
    """
    synced = rules_engine.sync_to_datapath()
    total = (len(rules_engine.whitelist) + len(rules_engine.blacklist) +
             len(rules_engine.protected) + len(rules_engine.cidr_whitelist))
    return {
        'status': 'synced',
        'synced': synced,
        'total': total
    }
