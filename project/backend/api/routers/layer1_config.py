"""
Layer 1 Configuration Router

FastAPI router for Layer 1 (DPDK) configuration management:
- Full configuration CRUD
- Section-level updates
- Stage enable/disable controls
- Geo-blocking configuration
- Signature management
- Protocol filtering
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Body, Depends
from pydantic import BaseModel, Field
from ..auth import UserContext, get_current_user

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from rules import get_config_manager, init_config_manager

router = APIRouter(
    prefix="/layer1",
    tags=["Layer 1 Config"],
    dependencies=[Depends(get_current_user)],
)

# Initialize config manager
config_manager = init_config_manager()


# Request/Response models
class ConfigUpdateRequest(BaseModel):
    value: Any


class SectionUpdateRequest(BaseModel):
    data: Dict[str, Any]


class TopLevelUpdateRequest(BaseModel):
    key: str = Field(..., pattern='^(log_level|stats_enabled|monitor_only|tap_mode)$')
    value: Any


class StageToggleRequest(BaseModel):
    enabled: bool


class GeoModeRequest(BaseModel):
    mode: str = Field(..., pattern='^(blacklist|whitelist)$')


class GeoCountryRequest(BaseModel):
    country: str = Field(..., min_length=2, max_length=2)


class GeoCountriesRequest(BaseModel):
    countries: List[str]


# Configuration endpoints
@router.get("/config")
async def get_config():
    """Get full Layer1 configuration."""
    return config_manager.get_config()


@router.get("/config/info")
async def get_config_info():
    """Get configuration metadata."""
    return config_manager.get_config_info()


@router.get("/config/schema")
async def get_config_schema():
    """Get configuration schema with field descriptions."""
    return config_manager.get_config_schema()


@router.get("/config/section/{section}")
async def get_config_section(section: str):
    """Get a specific configuration section."""
    data = config_manager.get_section(section)
    if data is None:
        raise HTTPException(status_code=404, detail=f'Section {section} not found')
    return data


# Valid section names for update_config_section
VALID_SECTIONS = {
    'rate_limits', 'syn_proxy', 'syn_cookie', 'geo_blocking', 'tcp_fingerprint',
    'signatures', 'protocols', 'other_protocols', 'udp_gatekeeper',
    'connection_limits', 'entropy', 'tcp_abuse', 'tcp_flag_rate',
    'flow_table', 'telemetry', 'ports', 'maintenance', 'ip_lists',
    'layer2_response', 'emergency'
}


@router.put("/config/section/{section}")
async def update_config_section(section: str, data: Dict[str, Any] = Body(...)):
    """Update a configuration section."""
    # Validate section name
    if section not in VALID_SECTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid section '{section}'. Valid sections: {sorted(VALID_SECTIONS)}"
        )

    # Validate data is not empty and has reasonable structure
    if not data:
        raise HTTPException(status_code=400, detail='Configuration data cannot be empty')
    if len(data) > 50:
        raise HTTPException(status_code=400, detail='Too many configuration keys')

    if config_manager.update_section(section, data):
        return {'status': 'updated', 'section': section}
    else:
        raise HTTPException(status_code=400, detail=f'Failed to update section {section}')


@router.post("/config/section/{section}/reset")
async def reset_config_section(section: str):
    """Reset a configuration section to defaults."""
    if config_manager.reset_section(section):
        return {'status': 'reset', 'section': section}
    else:
        raise HTTPException(status_code=404, detail=f'Section {section} not found')


@router.put("/config/value/{section}/{key}")
async def update_config_value(section: str, key: str, req: ConfigUpdateRequest):
    """Update a single configuration value."""
    result = config_manager.update_value(section, key, req.value)
    if result:
        applied = result.get('applied', False) if isinstance(result, dict) else False
        return {'status': 'updated', 'section': section, 'key': key, 'applied': applied}
    else:
        raise HTTPException(status_code=400, detail=f'Failed to update {section}.{key}')


@router.put("/config/top-level")
async def update_top_level_config(req: TopLevelUpdateRequest):
    """Update a top-level configuration value (log_level, stats_enabled, monitor_only, tap_mode)."""
    result = config_manager.update_top_level(req.key, req.value)
    if result:
        applied = result.get('applied', False) if isinstance(result, dict) else False
        return {'status': 'updated', 'key': req.key, 'applied': applied}
    else:
        raise HTTPException(status_code=400, detail=f'Failed to update {req.key}')


@router.post("/config/reset")
async def reset_config():
    """Reset entire configuration to defaults."""
    if config_manager.reset_to_defaults():
        return {'status': 'reset'}
    else:
        raise HTTPException(status_code=500, detail='Failed to reset configuration')


@router.post("/config/reload")
async def reload_config():
    """Reload configuration from file."""
    if config_manager.load_config():
        return {'status': 'reloaded'}
    else:
        raise HTTPException(status_code=500, detail='Failed to reload configuration')


# Config history endpoints
@router.get("/config/history")
async def get_config_history(limit: int = 20):
    """Get config version history."""
    return {'history': config_manager.get_config_history(limit=min(limit, 50))}


@router.get("/config/history/{snapshot_id}")
async def get_snapshot_config(snapshot_id: int):
    """Get config data from a specific snapshot."""
    data = config_manager.get_snapshot_config(snapshot_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f'Snapshot {snapshot_id} not found')
    return data


@router.post("/config/history/{snapshot_id}/restore")
async def restore_snapshot(snapshot_id: int):
    """Restore config from a previous snapshot."""
    if config_manager.restore_snapshot(snapshot_id):
        return {'status': 'restored', 'snapshot_id': snapshot_id}
    else:
        raise HTTPException(status_code=404, detail=f'Snapshot {snapshot_id} not found or restore failed')


# Stages endpoints
@router.get("/stages")
async def get_stages():
    """Get all stages with current status."""
    return {'stages': config_manager.get_stages()}


@router.get("/stages/categories")
async def get_stages_by_category():
    """Get stages grouped by category."""
    return config_manager.get_stages_by_category()


@router.get("/stages/{stage_id}")
async def get_stage(stage_id: str):
    """Get status of a specific stage."""
    status = config_manager.get_stage_status(stage_id)
    if status is None:
        raise HTTPException(status_code=404, detail=f'Stage {stage_id} not found')
    return status


@router.post("/stages/{stage_id}/enable")
async def enable_stage(stage_id: str):
    """Enable a stage."""
    if config_manager.set_stage_enabled(stage_id, True):
        return {'status': 'enabled', 'stage': stage_id}
    else:
        raise HTTPException(status_code=400, detail=f'Failed to enable stage {stage_id}')


@router.post("/stages/{stage_id}/disable")
async def disable_stage(stage_id: str):
    """Disable a stage."""
    if config_manager.set_stage_enabled(stage_id, False):
        return {'status': 'disabled', 'stage': stage_id}
    else:
        raise HTTPException(status_code=400, detail=f'Failed to disable stage {stage_id}')


@router.post("/stages/{stage_id}/toggle")
async def toggle_stage(stage_id: str):
    """Toggle a stage's enabled state."""
    status = config_manager.get_stage_status(stage_id)
    if status is None:
        raise HTTPException(status_code=404, detail=f'Stage {stage_id} not found')

    new_state = not status['enabled']
    if config_manager.set_stage_enabled(stage_id, new_state):
        return {'status': 'toggled', 'stage': stage_id, 'enabled': new_state}
    else:
        raise HTTPException(status_code=400, detail=f'Failed to toggle stage {stage_id}')


# Geo-blocking endpoints
@router.get("/geo")
async def get_geo_blocking():
    """Get geo-blocking configuration with all available countries."""
    return config_manager.get_geo_blocking()


@router.post("/geo/enabled")
async def set_geo_enabled(req: StageToggleRequest):
    """Enable or disable geo-blocking."""
    if config_manager.set_geo_blocking_enabled(req.enabled):
        return {'status': 'updated', 'enabled': req.enabled}
    else:
        raise HTTPException(status_code=400, detail='Failed to update geo-blocking state')


@router.post("/geo/mode")
async def set_geo_mode(req: GeoModeRequest):
    """Set geo-blocking mode (blacklist or whitelist)."""
    if config_manager.set_geo_blocking_mode(req.mode):
        return {'status': 'updated', 'mode': req.mode}
    else:
        raise HTTPException(status_code=400, detail='Failed to update geo-blocking mode')


@router.post("/geo/block-unknown")
async def set_geo_block_unknown(req: StageToggleRequest):
    """Set whether to block IPs with unknown/unresolvable country."""
    if config_manager.set_geo_block_unknown(req.enabled):
        return {'status': 'updated', 'block_unknown': req.enabled}
    else:
        raise HTTPException(status_code=400, detail='Failed to update geo block unknown setting')


@router.get("/geo/countries")
async def get_geo_countries():
    """Get currently configured countries."""
    geo = config_manager.get_geo_blocking()
    mode = geo.get('mode', 'blacklist')
    if mode == 'blacklist':
        countries = geo.get('blocked_countries', [])
    else:
        countries = geo.get('allowed_countries', [])
    return {
        'mode': mode,
        'countries': countries,
        'all_countries': geo.get('all_countries', [])
    }


@router.post("/geo/countries")
async def set_geo_countries(req: GeoCountriesRequest):
    """Set the list of countries for current mode."""
    if config_manager.set_geo_countries(req.countries):
        return {'status': 'updated', 'countries': req.countries}
    else:
        raise HTTPException(status_code=400, detail='Failed to update countries')


@router.post("/geo/countries/add")
async def add_geo_country(req: GeoCountryRequest):
    """Add a country to the geo filter."""
    if config_manager.add_geo_country(req.country):
        return {'status': 'added', 'country': req.country.upper()}
    else:
        raise HTTPException(status_code=400, detail='Failed to add country')


@router.post("/geo/countries/remove")
async def remove_geo_country(req: GeoCountryRequest):
    """Remove a country from the geo filter."""
    if config_manager.remove_geo_country(req.country):
        return {'status': 'removed', 'country': req.country.upper()}
    else:
        raise HTTPException(status_code=400, detail='Failed to remove country')


@router.post("/geo/countries/clear")
async def clear_geo_countries():
    """Clear all countries from the geo filter."""
    if config_manager.clear_geo_countries():
        return {'status': 'cleared'}
    else:
        raise HTTPException(status_code=400, detail='Failed to clear countries')


# Signatures endpoints
@router.get("/signatures")
async def get_signatures():
    """Get all signatures with their current state."""
    return config_manager.get_signatures()


@router.post("/signatures/enabled")
async def set_signatures_enabled(req: StageToggleRequest):
    """Enable or disable signatures globally."""
    if config_manager.update_value("signatures", "enabled", req.enabled):
        return {'status': 'updated', 'enabled': req.enabled}
    else:
        raise HTTPException(status_code=400, detail='Failed to update signatures state')


@router.post("/signatures/category/{category}/enabled")
async def set_signature_category_enabled(category: str, req: StageToggleRequest):
    """Enable or disable an entire signature category."""
    if config_manager.set_signature_category_enabled(category, req.enabled):
        return {'status': 'updated', 'category': category, 'enabled': req.enabled}
    else:
        raise HTTPException(status_code=400, detail=f'Failed to update category {category}')


@router.post("/signatures/{sig_id}/enabled")
async def set_signature_enabled(sig_id: int, req: StageToggleRequest):
    """Enable or disable a specific signature by ID."""
    if config_manager.set_signature_enabled(sig_id, req.enabled):
        return {'status': 'updated', 'signature_id': sig_id, 'enabled': req.enabled}
    else:
        raise HTTPException(status_code=404, detail=f'Signature {sig_id} not found')


@router.post("/signatures/amplification/{port}/enabled")
async def set_amplification_enabled(port: int, req: StageToggleRequest):
    """Enable or disable an amplification signature by port."""
    if config_manager.set_amplification_signature_enabled(port, req.enabled):
        return {'status': 'updated', 'port': port, 'enabled': req.enabled}
    else:
        raise HTTPException(status_code=400, detail=f'Failed to update port {port}')


class CustomSignatureRequest(BaseModel):
    port: int = Field(..., ge=1, le=65535)
    name: str = Field(..., min_length=1, max_length=64)
    amplification: int = Field(1, ge=1, le=1000)
    description: str = Field('', max_length=256)


@router.get("/signatures/custom")
async def get_custom_signatures():
    """Get custom amplification signatures."""
    return {'signatures': config_manager.get_custom_amplification_signatures()}


@router.post("/signatures/custom")
async def add_custom_signature(req: CustomSignatureRequest):
    """Add a custom amplification signature."""
    # Sanitize description
    import re
    desc = req.description[:256]
    desc = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', desc)
    desc = desc.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    if config_manager.add_custom_amplification_signature(req.port, req.name, req.amplification, desc):
        return {'status': 'added', 'port': req.port, 'name': req.name}
    else:
        raise HTTPException(status_code=400, detail=f'Port {req.port} already exists')


@router.delete("/signatures/custom/{port}")
async def delete_custom_signature(port: int):
    """Remove a custom amplification signature."""
    if config_manager.remove_custom_amplification_signature(port):
        return {'status': 'removed', 'port': port}
    else:
        raise HTTPException(status_code=404, detail=f'Port {port} not found')


# Protocol names lookup
PROTOCOL_NAMES = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
    41: "IPV6", 43: "IPV6-ROUTE", 44: "IPV6-FRAG", 47: "GRE",
    50: "ESP", 51: "AH", 58: "IPV6-ICMP", 89: "OSPF",
    132: "SCTP", 136: "UDPLITE",
}


def get_protocol_name(proto_num: int) -> str:
    return PROTOCOL_NAMES.get(proto_num, f"PROTO-{proto_num}")


# Protocol filtering endpoints
@router.get("/protocols")
async def get_protocols():
    """Get protocol filtering configuration."""
    config = config_manager.get_section('other_protocols')
    if config is None:
        config = {
            'enabled': True, 'default_action': 'drop',
            'allowed_protocols': [], 'rate_limit_pps': 1000, 'log_unknown': True
        }

    allowed_with_names = [
        {'number': proto_num, 'name': get_protocol_name(proto_num)}
        for proto_num in config.get('allowed_protocols', [])
    ]

    return {
        'enabled': config.get('enabled', True),
        'default_action': config.get('default_action', 'drop'),
        'allowed_protocols': allowed_with_names,
        'rate_limit_pps': config.get('rate_limit_pps', 1000),
        'log_unknown': config.get('log_unknown', True),
        'all_protocols': [
            {'number': num, 'name': name}
            for num, name in sorted(PROTOCOL_NAMES.items())
            if num not in (1, 6, 17)
        ]
    }


@router.post("/protocols/enabled")
async def set_protocols_enabled(req: StageToggleRequest):
    """Enable or disable protocol filtering."""
    if config_manager.update_value('other_protocols', 'enabled', req.enabled):
        return {'status': 'updated', 'enabled': req.enabled}
    else:
        raise HTTPException(status_code=400, detail='Failed to update protocol filtering state')


class ProtocolActionRequest(BaseModel):
    action: str = Field(..., pattern='^(drop|accept|rate_limit)$')


@router.post("/protocols/action")
async def set_protocols_action(req: ProtocolActionRequest):
    """Set default action for unknown protocols."""
    if config_manager.update_value('other_protocols', 'default_action', req.action):
        return {'status': 'updated', 'action': req.action}
    else:
        raise HTTPException(status_code=400, detail='Failed to update default action')


class ProtocolAddRequest(BaseModel):
    protocol: Optional[Any] = None
    number: Optional[int] = Field(None, ge=0, le=255)
    name: Optional[str] = None


@router.post("/protocols/add")
async def add_protocol(req: ProtocolAddRequest):
    """Add a protocol to the allowed list."""
    proto_num = req.number
    proto_name = (req.name or '').upper()

    if req.protocol is not None and proto_num is None and not proto_name:
        if isinstance(req.protocol, int) or (isinstance(req.protocol, str) and req.protocol.isdigit()):
            proto_num = int(req.protocol)
        else:
            proto_name = str(req.protocol).upper()

    if proto_num is None and proto_name:
        for num, name in PROTOCOL_NAMES.items():
            if name == proto_name:
                proto_num = num
                break
        if proto_num is None:
            raise HTTPException(status_code=400, detail=f'Unknown protocol name: {proto_name}')

    if proto_num is None:
        raise HTTPException(status_code=400, detail='Missing protocol number or name')

    if proto_num in (1, 6, 17):
        raise HTTPException(status_code=400, detail=f'{get_protocol_name(proto_num)} is handled by main pipeline')

    config = config_manager.get_section('other_protocols') or {}
    allowed = config.get('allowed_protocols', [])

    if proto_num in allowed:
        raise HTTPException(status_code=400, detail=f'Protocol {proto_num} already in allowed list')

    allowed.append(proto_num)
    allowed.sort()

    if config_manager.update_value('other_protocols', 'allowed_protocols', allowed):
        return {'status': 'added', 'protocol': {'number': proto_num, 'name': get_protocol_name(proto_num)}}
    else:
        raise HTTPException(status_code=400, detail='Failed to add protocol')


@router.post("/protocols/remove")
async def remove_protocol(req: ProtocolAddRequest):
    """Remove a protocol from the allowed list."""
    proto_num = req.number
    proto_name = (req.name or '').upper()

    if req.protocol is not None and proto_num is None and not proto_name:
        if isinstance(req.protocol, int) or (isinstance(req.protocol, str) and str(req.protocol).isdigit()):
            proto_num = int(req.protocol)
        else:
            proto_name = str(req.protocol).upper()

    if proto_num is None and proto_name:
        for num, name in PROTOCOL_NAMES.items():
            if name == proto_name:
                proto_num = num
                break

    if proto_num is None:
        raise HTTPException(status_code=400, detail='Missing protocol number or name')

    config = config_manager.get_section('other_protocols') or {}
    allowed = config.get('allowed_protocols', [])

    if proto_num not in allowed:
        raise HTTPException(status_code=404, detail=f'Protocol {proto_num} not in allowed list')

    allowed.remove(proto_num)

    if config_manager.update_value('other_protocols', 'allowed_protocols', allowed):
        return {'status': 'removed', 'protocol': {'number': proto_num, 'name': get_protocol_name(proto_num)}}
    else:
        raise HTTPException(status_code=400, detail='Failed to remove protocol')


@router.post("/protocols/clear")
async def clear_protocols():
    """Clear all allowed protocols."""
    if config_manager.update_value('other_protocols', 'allowed_protocols', []):
        return {'status': 'cleared'}
    else:
        raise HTTPException(status_code=400, detail='Failed to clear protocols')


class RateLimitRequest(BaseModel):
    pps: int = Field(..., ge=0, le=10000000)


@router.post("/protocols/rate-limit")
async def set_protocol_rate_limit(req: RateLimitRequest):
    """Set rate limit for other protocols."""
    if config_manager.update_value('other_protocols', 'rate_limit_pps', req.pps):
        return {'status': 'updated', 'rate_limit_pps': req.pps}
    else:
        raise HTTPException(status_code=400, detail='Failed to update rate limit')


@router.post("/protocols/log")
async def set_protocol_logging(req: StageToggleRequest):
    """Enable or disable logging for unknown protocols."""
    if config_manager.update_value('other_protocols', 'log_unknown', req.enabled):
        return {'status': 'updated', 'log_unknown': req.enabled}
    else:
        raise HTTPException(status_code=400, detail='Failed to update logging state')
