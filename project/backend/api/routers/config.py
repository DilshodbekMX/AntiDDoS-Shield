"""
Configuration Management Router

Configuration management for all layers.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request

from ..auth import (
    UserContext, get_current_user, require_permission, get_audit_logger
)
from ..models import (
    SystemConfig, ConfigUpdate, APIResponse,
    Layer1Config, Layer2Config,
)
from ..services.config_service import get_config_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/config", tags=["Configuration"])


# ==================== Full Configuration ====================

@router.get("", response_model=APIResponse)
async def get_config(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    Get complete configuration for all layers.
    """
    service = get_config_service()
    config = await service.get_config()

    if config is None:
        raise HTTPException(status_code=404, detail="Configuration not found")

    return APIResponse(success=True, data=config)


@router.put("", response_model=APIResponse)
async def update_config(
    request: Request,
    config_update: ConfigUpdate,
    user: UserContext = Depends(get_current_user),
):
    """
    Update configuration.

    Only specified layers will be updated.
    """
    # Check write permission for non-admins
    if not user.is_admin and "config:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Configuration write permission required")

    service = get_config_service()

    # Validate configuration
    errors = await service.validate_config(config_update)
    if errors:
        raise HTTPException(
            status_code=400,
            detail={"message": "Configuration validation failed", "errors": errors}
        )

    # Apply configuration
    updated_config = await service.update_config(config_update, updated_by=user.user_id)

    get_audit_logger().log_config_change(user, "full_config", request)

    return APIResponse(
        success=True,
        data=updated_config,
        message="Configuration updated successfully"
    )


# ==================== Layer 1 Configuration ====================

@router.get("/layer1", response_model=APIResponse)
async def get_layer1_config(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    Get Layer 1 (DPDK packet processing) configuration.
    """
    service = get_config_service()
    config = await service.get_layer_config(1)

    return APIResponse(success=True, data=config)


@router.put("/layer1", response_model=APIResponse)
async def update_layer1_config(
    request: Request,
    config: Layer1Config,
    user: UserContext = Depends(get_current_user),
):
    """
    Update Layer 1 configuration.

    **Key settings:**
    - Rate limits (PPS, BPS)
    - SYN proxy mode
    - TCP fingerprinting
    - Geo-blocking
    """
    if not user.is_admin and "config:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Configuration write permission required")

    service = get_config_service()

    # Validate
    errors = await service.validate_layer_config(1, config)
    if errors:
        raise HTTPException(status_code=400, detail={"errors": errors})

    # Apply
    updated = await service.update_layer_config(1, config, updated_by=user.user_id)

    get_audit_logger().log_config_change(user, "layer1", request)

    return APIResponse(success=True, data=updated, message="Layer 1 configuration updated")


# ==================== Layer 2 Configuration ====================

@router.get("/layer2", response_model=APIResponse)
async def get_layer2_config(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    Get Layer 2 (anomaly detection) configuration.
    """
    service = get_config_service()
    config = await service.get_layer_config(2)

    return APIResponse(success=True, data=config)


@router.put("/layer2", response_model=APIResponse)
async def update_layer2_config(
    request: Request,
    config: Layer2Config,
    user: UserContext = Depends(get_current_user),
):
    """
    Update Layer 2 configuration.

    **Key settings:**
    - Detection sensitivity
    - Z-score threshold
    - Baseline learning period
    - Anomaly cooldown
    """
    if not user.is_admin and "config:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Configuration write permission required")

    service = get_config_service()

    errors = await service.validate_layer_config(2, config)
    if errors:
        raise HTTPException(status_code=400, detail={"errors": errors})

    updated = await service.update_layer_config(2, config, updated_by=user.user_id)

    get_audit_logger().log_config_change(user, "layer2", request)

    return APIResponse(success=True, data=updated, message="Layer 2 configuration updated")


# ==================== Configuration Actions ====================

@router.post("/reload", response_model=APIResponse)
async def reload_config(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    Force reload of configuration in the data plane.

    Useful after bulk changes or if configuration appears out of sync.
    """
    if not user.is_admin and "config:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Configuration write permission required")

    service = get_config_service()

    success = await service.reload_config()

    if not success:
        raise HTTPException(
            status_code=500,
            detail="Failed to reload configuration. Check system logs."
        )

    get_audit_logger().log_config_change(user, "reload", request)

    return APIResponse(success=True, message="Configuration reloaded successfully")


@router.post("/reset", response_model=APIResponse)
async def reset_config(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    Reset configuration to defaults.

    Warning: This will overwrite all custom settings.
    """
    if not user.is_admin and "config:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Configuration write permission required")

    service = get_config_service()
    config = await service.reset_config(reset_by=user.user_id)

    get_audit_logger().log_config_change(user, "reset_to_defaults", request)

    return APIResponse(
        success=True,
        data=config,
        message="Configuration reset to defaults"
    )


@router.get("/history", response_model=APIResponse)
async def get_config_history(
    request: Request,
    limit: int = 20,
    user: UserContext = Depends(get_current_user),
):
    """
    Get configuration change history.
    """
    service = get_config_service()
    history = await service.get_config_history(limit=limit)

    return APIResponse(success=True, data=history)
