"""
Policy Management Router

Custom policy creation and management.
"""

import logging
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..auth import UserContext, get_current_user, get_audit_logger
from ..models import (
    Policy, PolicyCreate, PolicyAction, PolicyCondition,
    APIResponse, PaginatedResponse
)
from ..services.policy_service import get_policy_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/policies", tags=["Policies"])


# ==================== Policy CRUD ====================

@router.get("", response_model=APIResponse)
async def list_policies(
    request: Request,
    enabled: Optional[bool] = Query(default=None, description="Filter by enabled status"),
    action: Optional[PolicyAction] = Query(default=None, description="Filter by action type"),
    source: Optional[str] = Query(default=None, description="Filter by source (manual, ml, threat_intel)"),
    include_expired: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    user: UserContext = Depends(get_current_user),
):
    """
    List policies.

    Policies are returned sorted by priority (lowest number = highest priority).
    """
    service = get_policy_service()
    policies, total = await service.list_policies(
        enabled=enabled,
        action=action,
        source=source,
        include_expired=include_expired,
        page=page,
        per_page=per_page
    )

    pages = (total + per_page - 1) // per_page if per_page > 0 else 0

    return APIResponse(
        success=True,
        data=PaginatedResponse(
            items=policies,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
    )


@router.post("", response_model=APIResponse)
async def create_policy(
    request: Request,
    policy: PolicyCreate,
    user: UserContext = Depends(get_current_user),
):
    """
    Create a new policy.

    **Conditions** define when the policy matches:
    - `src_ip`: Source IP address (supports CIDR)
    - `dst_port`: Destination port
    - `protocol`: Protocol (tcp, udp, icmp)
    - `packet_size`: Packet size range
    - `rate`: Traffic rate threshold
    - `country`: Source country code
    - `tcp_flags`: TCP flags pattern

    **Operators:**
    - `eq`, `ne`: Equal, not equal
    - `gt`, `lt`, `ge`, `le`: Greater/less than
    - `in`, `not_in`: In list
    - `contains`: Contains substring
    - `matches`: Regex match
    """
    if not user.is_admin and "policy:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Policy write permission required")

    service = get_policy_service()

    # Check quota
    quota_ok = await service.check_policy_quota()
    if not quota_ok:
        raise HTTPException(status_code=400, detail="Policy quota exceeded")

    # Validate conditions
    errors = await service.validate_conditions(policy.conditions)
    if errors:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid policy conditions", "errors": errors}
        )

    created = await service.create_policy(policy, created_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "create_policy", f"policy:{created.id}", request
    )

    return APIResponse(
        success=True,
        data=created,
        message=f"Policy '{policy.name}' created with ID {created.id}"
    )


@router.get("/{policy_id}", response_model=APIResponse)
async def get_policy(
    request: Request,
    policy_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Get policy details.
    """
    service = get_policy_service()
    policy = await service.get_policy(policy_id)

    if policy is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found")

    return APIResponse(success=True, data=policy)


@router.put("/{policy_id}", response_model=APIResponse)
async def update_policy(
    request: Request,
    policy_id: int,
    policy_update: PolicyCreate,
    user: UserContext = Depends(get_current_user),
):
    """
    Update an existing policy.
    """
    if not user.is_admin and "policy:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Policy write permission required")

    service = get_policy_service()

    # Check exists
    existing = await service.get_policy(policy_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found")

    # Can't modify ML/threat-intel generated policies
    if existing.source != "manual" and not user.is_admin:
        raise HTTPException(
            status_code=403,
            detail=f"Cannot modify {existing.source}-generated policies"
        )

    # Validate conditions
    errors = await service.validate_conditions(policy_update.conditions)
    if errors:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid policy conditions", "errors": errors}
        )

    updated = await service.update_policy(
        policy_id, policy_update, updated_by=user.user_id
    )

    get_audit_logger().log_api_action(
        user, "update_policy", f"policy:{policy_id}", request
    )

    return APIResponse(success=True, data=updated, message="Policy updated")


@router.delete("/{policy_id}", response_model=APIResponse)
async def delete_policy(
    request: Request,
    policy_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Delete a policy.
    """
    if not user.is_admin and "policy:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Policy write permission required")

    service = get_policy_service()

    # Check exists
    existing = await service.get_policy(policy_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found")

    await service.delete_policy(policy_id, deleted_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "delete_policy", f"policy:{policy_id}", request
    )

    return APIResponse(success=True, message=f"Policy {policy_id} deleted")


# ==================== Policy Actions ====================

@router.post("/{policy_id}/enable", response_model=APIResponse)
async def enable_policy(
    request: Request,
    policy_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Enable a policy.
    """
    if not user.is_admin and "policy:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Policy write permission required")

    service = get_policy_service()
    await service.set_policy_enabled(policy_id, True, updated_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "enable_policy", f"policy:{policy_id}", request
    )

    return APIResponse(success=True, message=f"Policy {policy_id} enabled")


@router.post("/{policy_id}/disable", response_model=APIResponse)
async def disable_policy(
    request: Request,
    policy_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Disable a policy.
    """
    if not user.is_admin and "policy:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Policy write permission required")

    service = get_policy_service()
    await service.set_policy_enabled(policy_id, False, updated_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "disable_policy", f"policy:{policy_id}", request
    )

    return APIResponse(success=True, message=f"Policy {policy_id} disabled")


@router.get("/{policy_id}/stats", response_model=APIResponse)
async def get_policy_stats(
    request: Request,
    policy_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Get policy hit statistics.
    """
    service = get_policy_service()

    policy = await service.get_policy(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found")

    stats = await service.get_policy_stats(policy_id)

    return APIResponse(success=True, data=stats)


# ==================== Policy Testing ====================

@router.post("/test", response_model=APIResponse)
async def test_policy(
    request: Request,
    policy: PolicyCreate,
    test_packet: dict = None,
    user: UserContext = Depends(get_current_user),
):
    """
    Test a policy without creating it.

    Optionally provide a test packet to see if it would match.
    """
    service = get_policy_service()

    # Validate conditions
    errors = await service.validate_conditions(policy.conditions)
    if errors:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid policy conditions", "errors": errors}
        )

    result = {
        "valid": True,
        "conditions_parsed": len(policy.conditions),
    }

    # Test against packet if provided
    if test_packet:
        match_result = await service.test_policy_match(policy, test_packet)
        result["test_packet_match"] = match_result

    return APIResponse(success=True, data=result)


# ==================== Policy Templates ====================

@router.get("/templates", response_model=APIResponse)
async def get_policy_templates(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    Get available policy templates.
    """
    templates = [
        {
            "name": "Block Country",
            "description": "Block traffic from a specific country",
            "action": "block",
            "conditions": [
                {"field": "country", "operator": "eq", "value": "XX"}
            ]
        },
        {
            "name": "Rate Limit High Traffic Source",
            "description": "Rate limit sources exceeding threshold",
            "action": "rate_limit",
            "conditions": [
                {"field": "rate", "operator": "gt", "value": 10000}
            ]
        },
        {
            "name": "Block Small UDP Packets",
            "description": "Block small UDP packets (potential amplification)",
            "action": "block",
            "conditions": [
                {"field": "protocol", "operator": "eq", "value": "udp"},
                {"field": "packet_size", "operator": "lt", "value": 64}
            ]
        },
        {
            "name": "Challenge Suspicious TCP",
            "description": "Challenge connections with unusual TCP flags",
            "action": "challenge",
            "conditions": [
                {"field": "protocol", "operator": "eq", "value": "tcp"},
                {"field": "tcp_flags", "operator": "matches", "value": "^(SA|FA|PA)$"}
            ]
        },
        {
            "name": "Allow Monitoring Service",
            "description": "Allow traffic from monitoring IP ranges",
            "action": "allow",
            "priority": 10,
            "conditions": [
                {"field": "src_ip", "operator": "in", "value": ["10.0.0.0/8"]}
            ]
        }
    ]

    return APIResponse(success=True, data=templates)


# ==================== ML-Generated Policies ====================

@router.get("/ml-generated", response_model=APIResponse)
async def get_ml_policies(
    request: Request,
    pending_only: bool = Query(default=False, description="Show only pending approval"),
    user: UserContext = Depends(get_current_user),
):
    """
    Get ML-generated policies.

    These policies are automatically created by Layer 3 ML models.
    """
    service = get_policy_service()
    policies, total = await service.list_policies(
        source="ml",
        enabled=None if not pending_only else False,
        page=1,
        per_page=100
    )

    return APIResponse(success=True, data=policies)


@router.post("/ml-generated/{policy_id}/approve", response_model=APIResponse)
async def approve_ml_policy(
    request: Request,
    policy_id: int,
    user: UserContext = Depends(get_current_user),
):
    """
    Approve an ML-generated policy.

    Enables the policy for active use.
    """
    if not user.is_admin and "policy:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Policy write permission required")

    service = get_policy_service()

    policy = await service.get_policy(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found")

    if policy.source != "ml":
        raise HTTPException(status_code=400, detail="Policy is not ML-generated")

    await service.set_policy_enabled(policy_id, True, updated_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "approve_ml_policy", f"policy:{policy_id}", request
    )

    return APIResponse(success=True, message=f"ML policy {policy_id} approved and enabled")


@router.post("/ml-generated/{policy_id}/reject", response_model=APIResponse)
async def reject_ml_policy(
    request: Request,
    policy_id: int,
    feedback: str = Query(default=None, description="Rejection feedback for ML model"),
    user: UserContext = Depends(get_current_user),
):
    """
    Reject an ML-generated policy.

    Provides feedback to improve future ML suggestions.
    """
    if not user.is_admin and "policy:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Policy write permission required")

    service = get_policy_service()

    policy = await service.get_policy(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found")

    if policy.source != "ml":
        raise HTTPException(status_code=400, detail="Policy is not ML-generated")

    await service.reject_ml_policy(policy_id, feedback, rejected_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "reject_ml_policy", f"policy:{policy_id}", request
    )

    return APIResponse(success=True, message=f"ML policy {policy_id} rejected")
