"""
Tenant Management Router

CRUD operations for tenant management.
"""

import logging
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..auth import (
    UserContext, get_current_user, require_permission, require_admin,
    get_audit_logger
)
from ..models import (
    Tenant, TenantCreate, TenantUpdate, TenantStatus, TenantTier,
    TenantQuotas, TenantFeatures, TenantContact,
    TenantConfig, ConfigUpdate,
    APIResponse, PaginatedResponse, PaginationParams
)
from ..services.tenant_service import get_tenant_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/tenants", tags=["Tenants"])


# ==================== Tenant CRUD ====================

@router.get("", response_model=PaginatedResponse)
async def list_tenants(
    request: Request,
    status: Optional[TenantStatus] = Query(default=None, description="Filter by status"),
    tier: Optional[TenantTier] = Query(default=None, description="Filter by tier"),
    search: Optional[str] = Query(default=None, description="Search by name"),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    user: UserContext = Depends(get_current_user),
):
    """
    List all tenants with optional filtering.

    - **status**: Filter by tenant status (active, suspended, etc.)
    - **tier**: Filter by service tier
    - **search**: Search tenants by name
    """
    service = get_tenant_service()

    # Non-admin users can only see their own tenant
    if not user.is_admin:
        if user.tenant_id is None:
            raise HTTPException(status_code=403, detail="No tenant access")

        tenant = await service.get_tenant(user.tenant_id)
        if tenant is None:
            return PaginatedResponse(items=[], total=0, page=1, per_page=per_page, pages=0)

        return PaginatedResponse(
            items=[tenant],
            total=1,
            page=1,
            per_page=per_page,
            pages=1
        )

    # Admin: get all tenants with filtering
    tenants, total = await service.list_tenants(
        status=status,
        tier=tier,
        search=search,
        page=page,
        per_page=per_page
    )

    pages = (total + per_page - 1) // per_page if per_page > 0 else 0

    return PaginatedResponse(
        items=tenants,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages
    )


@router.post("", response_model=APIResponse)
async def create_tenant(
    request: Request,
    tenant_data: TenantCreate,
    user: UserContext = Depends(require_admin()),
):
    """
    Create a new tenant.

    Requires admin access.
    """
    service = get_tenant_service()

    # Check for duplicate name
    existing = await service.get_tenant_by_name(tenant_data.name)
    if existing:
        raise HTTPException(status_code=409, detail=f"Tenant with name '{tenant_data.name}' already exists")

    # Create tenant
    tenant = await service.create_tenant(tenant_data, created_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "create_tenant", f"tenant:{tenant.id}", request
    )

    return APIResponse(
        success=True,
        data=tenant,
        message=f"Tenant '{tenant.name}' created successfully with ID {tenant.id}"
    )


@router.get("/{tenant_id}", response_model=APIResponse)
async def get_tenant(
    request: Request,
    tenant_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Get tenant details by ID.
    """
    # Check access
    if not user.is_admin and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    service = get_tenant_service()
    tenant = await service.get_tenant(tenant_id)

    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

    return APIResponse(success=True, data=tenant)


@router.put("/{tenant_id}", response_model=APIResponse)
async def update_tenant(
    request: Request,
    tenant_id: int,
    update_data: TenantUpdate,
    user: UserContext = Depends(get_current_user),
):
    """
    Update tenant details.

    - Admins can update any tenant
    - Tenant users can update limited fields (contact info, description)
    """
    service = get_tenant_service()

    # Check tenant exists
    tenant = await service.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

    # Check access
    if not user.is_admin:
        if user.tenant_id != tenant_id:
            raise HTTPException(status_code=403, detail="Access denied")

        # Non-admins can only update certain fields
        allowed_fields = {"description", "contact"}
        update_dict = update_data.dict(exclude_unset=True)
        disallowed = set(update_dict.keys()) - allowed_fields

        if disallowed:
            raise HTTPException(
                status_code=403,
                detail=f"Cannot modify fields: {', '.join(disallowed)}"
            )

    # Perform update
    updated_tenant = await service.update_tenant(
        tenant_id, update_data, updated_by=user.user_id
    )

    get_audit_logger().log_api_action(
        user, "update_tenant", f"tenant:{tenant_id}", request
    )

    return APIResponse(
        success=True,
        data=updated_tenant,
        message="Tenant updated successfully"
    )


@router.delete("/{tenant_id}", response_model=APIResponse)
async def delete_tenant(
    request: Request,
    tenant_id: int,
    user: UserContext = Depends(require_admin()),
):
    """
    Delete a tenant.

    Requires admin access. Tenant will be soft-deleted (status=DISABLED).
    """
    service = get_tenant_service()

    # Check tenant exists
    tenant = await service.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

    # Soft delete
    await service.delete_tenant(tenant_id, deleted_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "delete_tenant", f"tenant:{tenant_id}", request
    )

    return APIResponse(
        success=True,
        message=f"Tenant {tenant_id} deleted successfully"
    )


# ==================== Tenant Status ====================

@router.post("/{tenant_id}/suspend", response_model=APIResponse)
async def suspend_tenant(
    request: Request,
    tenant_id: int,
    reason: str = Query(description="Suspension reason"),
    user: UserContext = Depends(require_admin()),
):
    """
    Suspend a tenant.

    Traffic will continue to be monitored but mitigation may be reduced.
    """
    service = get_tenant_service()

    tenant = await service.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

    await service.set_tenant_status(
        tenant_id,
        TenantStatus.SUSPENDED,
        reason=reason,
        updated_by=user.user_id
    )

    get_audit_logger().log_api_action(
        user, "suspend_tenant", f"tenant:{tenant_id}:{reason}", request
    )

    return APIResponse(success=True, message=f"Tenant {tenant_id} suspended: {reason}")


@router.post("/{tenant_id}/activate", response_model=APIResponse)
async def activate_tenant(
    request: Request,
    tenant_id: int,
    user: UserContext = Depends(require_admin()),
):
    """
    Activate a suspended tenant.
    """
    service = get_tenant_service()

    tenant = await service.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

    await service.set_tenant_status(
        tenant_id,
        TenantStatus.ACTIVE,
        updated_by=user.user_id
    )

    get_audit_logger().log_api_action(
        user, "activate_tenant", f"tenant:{tenant_id}", request
    )

    return APIResponse(success=True, message=f"Tenant {tenant_id} activated")


# ==================== Protected IPs ====================

@router.get("/{tenant_id}/protected-ips", response_model=APIResponse)
async def get_protected_ips(
    request: Request,
    tenant_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Get list of protected IPs for a tenant.
    """
    if not user.is_admin and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    service = get_tenant_service()
    tenant = await service.get_tenant(tenant_id)

    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

    return APIResponse(
        success=True,
        data={
            "ips": tenant.protected_ips,
            "prefixes": tenant.protected_prefixes
        }
    )


@router.post("/{tenant_id}/protected-ips", response_model=APIResponse)
async def add_protected_ip(
    request: Request,
    tenant_id: int,
    ip: str = Query(description="IP address or CIDR to protect"),
    user: UserContext = Depends(get_current_user),
):
    """
    Add an IP address or prefix to protection.
    """
    if not user.is_admin and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    service = get_tenant_service()

    tenant = await service.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

    # Check quota
    current_count = len(tenant.protected_ips) + len(tenant.protected_prefixes)
    max_ips = 256  # Default, could be from quotas

    if current_count >= max_ips:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum protected IPs ({max_ips}) reached"
        )

    await service.add_protected_ip(tenant_id, ip, added_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "add_protected_ip", f"tenant:{tenant_id}:ip:{ip}", request
    )

    return APIResponse(success=True, message=f"IP {ip} added to protection")


@router.delete("/{tenant_id}/protected-ips", response_model=APIResponse)
async def remove_protected_ip(
    request: Request,
    tenant_id: int,
    ip: str = Query(description="IP address or CIDR to remove"),
    user: UserContext = Depends(get_current_user),
):
    """
    Remove an IP address or prefix from protection.
    """
    if not user.is_admin and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    service = get_tenant_service()

    await service.remove_protected_ip(tenant_id, ip, removed_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "remove_protected_ip", f"tenant:{tenant_id}:ip:{ip}", request
    )

    return APIResponse(success=True, message=f"IP {ip} removed from protection")


# ==================== Quotas ====================

@router.get("/{tenant_id}/quotas", response_model=APIResponse)
async def get_tenant_quotas(
    request: Request,
    tenant_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Get tenant resource quotas and current usage.
    """
    if not user.is_admin and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    service = get_tenant_service()
    tenant = await service.get_tenant(tenant_id)

    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

    usage = await service.get_quota_usage(tenant_id)

    return APIResponse(
        success=True,
        data={
            "quotas": tenant.quotas,
            "usage": usage
        }
    )


@router.put("/{tenant_id}/quotas", response_model=APIResponse)
async def update_tenant_quotas(
    request: Request,
    tenant_id: int,
    quotas: TenantQuotas,
    user: UserContext = Depends(require_admin()),
):
    """
    Update tenant resource quotas.

    Requires admin access.
    """
    service = get_tenant_service()

    tenant = await service.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

    await service.update_quotas(tenant_id, quotas, updated_by=user.user_id)

    get_audit_logger().log_config_change(user, tenant_id, "quotas", request)

    return APIResponse(success=True, message="Quotas updated successfully")


# ==================== Features ====================

@router.get("/{tenant_id}/features", response_model=APIResponse)
async def get_tenant_features(
    request: Request,
    tenant_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Get tenant enabled features.
    """
    if not user.is_admin and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    service = get_tenant_service()
    tenant = await service.get_tenant(tenant_id)

    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

    return APIResponse(success=True, data=tenant.features)


@router.put("/{tenant_id}/features", response_model=APIResponse)
async def update_tenant_features(
    request: Request,
    tenant_id: int,
    features: TenantFeatures,
    user: UserContext = Depends(require_admin()),
):
    """
    Update tenant enabled features.

    Requires admin access.
    """
    service = get_tenant_service()

    tenant = await service.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

    await service.update_features(tenant_id, features, updated_by=user.user_id)

    get_audit_logger().log_config_change(user, tenant_id, "features", request)

    return APIResponse(success=True, message="Features updated successfully")


# NOTE: Stats and attacks endpoints are handled by stats_router and security_router
# See: /api/v2/tenants/{tenant_id}/stats/* and /api/v2/tenants/{tenant_id}/attacks


# ==================== Layer Configs ====================

@router.get("/{tenant_id}/config/l1", response_model=APIResponse)
async def get_l1_config(
    request: Request,
    tenant_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Get Layer 1 (DPDK packet processing) configuration.
    """
    if not user.is_admin and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    service = get_tenant_service()
    config = await service.get_l1_config(tenant_id)

    return APIResponse(success=True, data=config)


@router.put("/{tenant_id}/config/l1", response_model=APIResponse)
async def update_l1_config(
    request: Request,
    tenant_id: int,
    config: dict,  # L1ConfigUpdate schema
    user: UserContext = Depends(require_admin()),
):
    """
    Update Layer 1 configuration.
    """
    service = get_tenant_service()
    await service.update_l1_config(tenant_id, config, updated_by=user.user_id)

    get_audit_logger().log_config_change(user, tenant_id, "l1_config", request)

    return APIResponse(success=True, message="L1 config updated")


@router.get("/{tenant_id}/config/l2", response_model=APIResponse)
async def get_l2_config(
    request: Request,
    tenant_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Get Layer 2 (anomaly detection) configuration.
    """
    if not user.is_admin and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    service = get_tenant_service()
    config = await service.get_l2_config(tenant_id)

    return APIResponse(success=True, data=config)


@router.put("/{tenant_id}/config/l2", response_model=APIResponse)
async def update_l2_config(
    request: Request,
    tenant_id: int,
    config: dict,
    user: UserContext = Depends(require_admin()),
):
    """
    Update Layer 2 configuration.
    """
    service = get_tenant_service()
    await service.update_l2_config(tenant_id, config, updated_by=user.user_id)

    get_audit_logger().log_config_change(user, tenant_id, "l2_config", request)

    return APIResponse(success=True, message="L2 config updated")


@router.get("/{tenant_id}/config/l4", response_model=APIResponse)
async def get_l4_config(
    request: Request,
    tenant_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Get Layer 4 (reputation/challenge) configuration.
    """
    if not user.is_admin and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    service = get_tenant_service()
    config = await service.get_l4_config(tenant_id)

    return APIResponse(success=True, data=config)


@router.put("/{tenant_id}/config/l4", response_model=APIResponse)
async def update_l4_config(
    request: Request,
    tenant_id: int,
    config: dict,
    user: UserContext = Depends(require_admin()),
):
    """
    Update Layer 4 configuration.
    """
    service = get_tenant_service()
    await service.update_l4_config(tenant_id, config, updated_by=user.user_id)

    get_audit_logger().log_config_change(user, tenant_id, "l4_config", request)

    return APIResponse(success=True, message="L4 config updated")


# ==================== Billing ====================

@router.get("/{tenant_id}/billing", response_model=APIResponse)
async def get_tenant_billing(
    request: Request,
    tenant_id: int,
    period: str = Query("current", description="current, last_month, or YYYY-MM"),
    user: UserContext = Depends(get_current_user),
):
    """
    Get billing data for a tenant.
    """
    if not user.is_admin and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    service = get_tenant_service()
    billing = await service.get_billing_data(tenant_id, period)

    return APIResponse(success=True, data=billing)


# ==================== Health Check ====================

@router.get("/{tenant_id}/health", response_model=APIResponse)
async def get_tenant_health(
    request: Request,
    tenant_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Get tenant health status including SLA metrics.
    """
    if not user.is_admin and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    service = get_tenant_service()
    health = await service.get_tenant_health(tenant_id)

    return APIResponse(success=True, data=health)
