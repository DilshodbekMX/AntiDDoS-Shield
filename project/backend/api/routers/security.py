"""
Security Operations Router

Blacklist/whitelist management, attacks, and IP investigation.
"""

import logging
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..auth import UserContext, get_current_user, require_permission, get_audit_logger
from ..models import (
    IPListEntry, IPListEntryCreate, IPListBulkAdd, IPListType,
    Attack, AttackSummary, AttackType, AttackSeverity,
    APIResponse, PaginatedResponse
)
from ..services.security_service import get_security_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/security", tags=["Security"])


# ==================== Blacklist Management ====================

@router.get("/blacklist", response_model=APIResponse)
async def get_blacklist(
    request: Request,
    search: Optional[str] = Query(default=None, description="Search by IP"),
    include_expired: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    user: UserContext = Depends(get_current_user),
):
    """
    Get blacklist entries.
    """
    service = get_security_service()
    entries, total = await service.get_ip_list(
        IPListType.BLACKLIST,
        search=search,
        include_expired=include_expired,
        page=page,
        per_page=per_page
    )

    pages = (total + per_page - 1) // per_page if per_page > 0 else 0

    return APIResponse(
        success=True,
        data=PaginatedResponse(
            items=entries,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
    )


@router.post("/blacklist", response_model=APIResponse)
async def add_to_blacklist(
    request: Request,
    entry: IPListEntryCreate,
    user: UserContext = Depends(get_current_user),
):
    """
    Add IP to blacklist.

    - Supports single IPs and CIDR ranges
    - Optional expiration time
    """
    if not user.is_admin and "security:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Security write permission required")

    service = get_security_service()

    # Check if already exists
    existing = await service.get_ip_entry(IPListType.BLACKLIST, entry.ip)
    if existing:
        raise HTTPException(status_code=409, detail=f"IP {entry.ip} already in blacklist")

    # Check quota
    quota_ok = await service.check_list_quota(IPListType.BLACKLIST)
    if not quota_ok:
        raise HTTPException(status_code=400, detail="Blacklist quota exceeded")

    created = await service.add_to_list(
        IPListType.BLACKLIST,
        entry,
        added_by=user.user_id
    )

    get_audit_logger().log_api_action(
        user, "blacklist_add", f"ip:{entry.ip}", request
    )

    return APIResponse(
        success=True,
        data=created,
        message=f"IP {entry.ip} added to blacklist"
    )


@router.post("/blacklist/bulk", response_model=APIResponse)
async def bulk_add_blacklist(
    request: Request,
    bulk_data: IPListBulkAdd,
    user: UserContext = Depends(get_current_user),
):
    """
    Bulk add IPs to blacklist.
    """
    if not user.is_admin and "security:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Security write permission required")

    service = get_security_service()

    result = await service.bulk_add_to_list(
        IPListType.BLACKLIST,
        bulk_data,
        added_by=user.user_id
    )

    get_audit_logger().log_api_action(
        user, "blacklist_bulk_add", f"count:{len(bulk_data.ips)}", request
    )

    return APIResponse(
        success=True,
        data=result,
        message=f"Added {result['added']} IPs, skipped {result['skipped']} duplicates"
    )


@router.delete("/blacklist", response_model=APIResponse)
async def remove_from_blacklist(
    request: Request,
    ip: str = Query(description="IP address or CIDR to remove"),
    user: UserContext = Depends(get_current_user),
):
    """
    Remove IP from blacklist.
    """
    if not user.is_admin and "security:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Security write permission required")

    service = get_security_service()

    removed = await service.remove_from_list(IPListType.BLACKLIST, ip)

    if not removed:
        raise HTTPException(status_code=404, detail=f"IP {ip} not found in blacklist")

    get_audit_logger().log_api_action(
        user, "blacklist_remove", f"ip:{ip}", request
    )

    return APIResponse(success=True, message=f"IP {ip} removed from blacklist")


# ==================== Whitelist Management ====================

@router.get("/whitelist", response_model=APIResponse)
async def get_whitelist(
    request: Request,
    search: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    user: UserContext = Depends(get_current_user),
):
    """
    Get whitelist entries.
    """
    service = get_security_service()
    entries, total = await service.get_ip_list(
        IPListType.WHITELIST,
        search=search,
        page=page,
        per_page=per_page
    )

    pages = (total + per_page - 1) // per_page if per_page > 0 else 0

    return APIResponse(
        success=True,
        data=PaginatedResponse(
            items=entries,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
    )


@router.post("/whitelist", response_model=APIResponse)
async def add_to_whitelist(
    request: Request,
    entry: IPListEntryCreate,
    user: UserContext = Depends(get_current_user),
):
    """
    Add IP to whitelist.

    Whitelisted IPs bypass rate limiting and challenge checks.
    """
    if not user.is_admin and "security:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Security write permission required")

    service = get_security_service()

    existing = await service.get_ip_entry(IPListType.WHITELIST, entry.ip)
    if existing:
        raise HTTPException(status_code=409, detail=f"IP {entry.ip} already in whitelist")

    quota_ok = await service.check_list_quota(IPListType.WHITELIST)
    if not quota_ok:
        raise HTTPException(status_code=400, detail="Whitelist quota exceeded")

    created = await service.add_to_list(
        IPListType.WHITELIST,
        entry,
        added_by=user.user_id
    )

    get_audit_logger().log_api_action(
        user, "whitelist_add", f"ip:{entry.ip}", request
    )

    return APIResponse(
        success=True,
        data=created,
        message=f"IP {entry.ip} added to whitelist"
    )


@router.delete("/whitelist", response_model=APIResponse)
async def remove_from_whitelist(
    request: Request,
    ip: str = Query(description="IP address or CIDR to remove"),
    user: UserContext = Depends(get_current_user),
):
    """
    Remove IP from whitelist.
    """
    if not user.is_admin and "security:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Security write permission required")

    service = get_security_service()

    removed = await service.remove_from_list(IPListType.WHITELIST, ip)

    if not removed:
        raise HTTPException(status_code=404, detail=f"IP {ip} not found in whitelist")

    get_audit_logger().log_api_action(
        user, "whitelist_remove", f"ip:{ip}", request
    )

    return APIResponse(success=True, message=f"IP {ip} removed from whitelist")


# ==================== Attacks ====================

@router.get("/attacks", response_model=APIResponse)
async def get_attacks(
    request: Request,
    is_active: Optional[bool] = Query(default=None, description="Filter by active status"),
    attack_type: Optional[AttackType] = Query(default=None),
    severity: Optional[AttackSeverity] = Query(default=None),
    start_date: Optional[datetime] = Query(default=None),
    end_date: Optional[datetime] = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    user: UserContext = Depends(get_current_user),
):
    """
    Get attack history.
    """
    service = get_security_service()
    attacks, total = await service.get_attacks(
        is_active=is_active,
        attack_type=attack_type,
        severity=severity,
        start_date=start_date,
        end_date=end_date,
        page=page,
        per_page=per_page
    )

    pages = (total + per_page - 1) // per_page if per_page > 0 else 0

    return APIResponse(
        success=True,
        data=PaginatedResponse(
            items=attacks,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
    )


@router.get("/attacks/active", response_model=APIResponse)
async def get_active_attacks(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    Get currently active attacks.
    """
    service = get_security_service()
    attacks = await service.get_active_attacks()

    return APIResponse(success=True, data=attacks)


@router.get("/attacks/{attack_id}", response_model=APIResponse)
async def get_attack(
    request: Request,
    attack_id: str,
    user: UserContext = Depends(get_current_user),
):
    """
    Get detailed attack information.
    """
    service = get_security_service()
    attack = await service.get_attack(attack_id)

    if attack is None:
        raise HTTPException(status_code=404, detail=f"Attack {attack_id} not found")

    return APIResponse(success=True, data=attack)


@router.get("/attacks/{attack_id}/sources", response_model=APIResponse)
async def get_attack_sources(
    request: Request,
    attack_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    user: UserContext = Depends(get_current_user),
):
    """
    Get top source IPs for an attack.
    """
    service = get_security_service()
    sources = await service.get_attack_sources(attack_id, limit)

    return APIResponse(success=True, data=sources)


@router.post("/attacks/{attack_id}/mitigate", response_model=APIResponse)
async def trigger_mitigation(
    request: Request,
    attack_id: str,
    action: str = Query(description="Mitigation action (block_sources, increase_rate_limit, enable_challenges)"),
    user: UserContext = Depends(get_current_user),
):
    """
    Manually trigger mitigation for an attack.
    """
    if not user.is_admin and "security:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Security write permission required")

    service = get_security_service()
    result = await service.trigger_mitigation(attack_id, action, triggered_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "trigger_mitigation", f"attack:{attack_id}:{action}", request
    )

    return APIResponse(success=True, data=result, message="Mitigation triggered")


# ==================== IP Investigation ====================

@router.get("/investigate/{ip}", response_model=APIResponse)
async def investigate_ip(
    request: Request,
    ip: str,
    user: UserContext = Depends(get_current_user),
):
    """
    Investigate an IP address.

    Returns:
    - List membership (blacklist/whitelist/greylist)
    - Recent traffic from this IP
    - Reputation score
    - Attack involvement
    - Geo location
    """
    service = get_security_service()
    investigation = await service.investigate_ip(ip)

    return APIResponse(success=True, data=investigation)


@router.post("/investigate/{ip}/block", response_model=APIResponse)
async def block_ip(
    request: Request,
    ip: str,
    duration_seconds: int = Query(default=3600, description="Block duration in seconds"),
    reason: str = Query(default="Manual block", description="Block reason"),
    user: UserContext = Depends(get_current_user),
):
    """
    Quick block an IP address.
    """
    if not user.is_admin and "security:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Security write permission required")

    service = get_security_service()

    entry = IPListEntryCreate(
        ip=ip,
        description=reason,
        duration_seconds=duration_seconds
    )

    await service.add_to_list(IPListType.BLACKLIST, entry, added_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "quick_block", f"ip:{ip}:{duration_seconds}s", request
    )

    return APIResponse(success=True, message=f"IP {ip} blocked for {duration_seconds} seconds")


@router.post("/investigate/{ip}/unblock", response_model=APIResponse)
async def unblock_ip(
    request: Request,
    ip: str,
    user: UserContext = Depends(get_current_user),
):
    """
    Quick unblock an IP address.
    """
    if not user.is_admin and "security:write" not in user.permissions:
        raise HTTPException(status_code=403, detail="Security write permission required")

    service = get_security_service()

    # Remove from blacklist
    await service.remove_from_list(IPListType.BLACKLIST, ip)

    # Remove from greylist
    await service.remove_from_list(IPListType.GREYLIST, ip)

    get_audit_logger().log_api_action(
        user, "quick_unblock", f"ip:{ip}", request
    )

    return APIResponse(success=True, message=f"IP {ip} unblocked")
