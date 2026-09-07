"""
Layer 4 Challenge Verification API router.

Provides endpoints for managing and verifying client challenges.
Challenges help distinguish legitimate users from bots and attackers.
"""

import logging
import secrets
import hashlib
from typing import Optional, List
from datetime import datetime, timedelta
from enum import Enum

from fastapi import APIRouter, HTTPException, Query, Depends, Body
from pydantic import BaseModel, Field

from ...database import get_db
from ...database.models import ChallengeSession, ChallengeType as DBChallengeType
from ...auth import require_tenant_access, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/layer4/challenges", tags=["Layer 4 - Challenges"])


# Pydantic models

class ChallengeTypeEnum(str, Enum):
    """Available challenge types."""
    JS_CHALLENGE = "js_challenge"
    CAPTCHA = "captcha"
    POW = "proof_of_work"
    COOKIE = "cookie_validation"
    FINGERPRINT = "fingerprint"
    RATE_CHECK = "rate_check"


class ChallengeStatus(str, Enum):
    """Challenge session status."""
    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    EXPIRED = "expired"


class ChallengeResponse(BaseModel):
    """Challenge session response."""
    session_id: str
    challenge_type: ChallengeTypeEnum
    ip_address: str
    status: ChallengeStatus
    created_at: datetime
    expires_at: datetime
    attempts: int
    max_attempts: int
    passed_at: Optional[datetime] = None
    metadata: dict = {}

    class Config:
        from_attributes = True


class ChallengeListResponse(BaseModel):
    """Paginated challenge list response."""
    success: bool = True
    total: int
    skip: int
    limit: int
    items: List[ChallengeResponse]


class ChallengeStatsResponse(BaseModel):
    """Challenge statistics response."""
    success: bool = True
    total_challenges: int
    by_type: dict
    by_status: dict
    success_rate: float
    avg_attempts_to_pass: float
    avg_time_to_pass_ms: float


class ChallengeConfigResponse(BaseModel):
    """Challenge configuration response."""
    success: bool = True
    enabled: bool
    default_challenge_type: ChallengeTypeEnum
    challenge_timeout_seconds: int
    max_attempts: int
    exempt_ips: List[str]
    exempt_user_agents: List[str]
    difficulty: str
    config: dict


class ChallengeConfigUpdate(BaseModel):
    """Challenge configuration update request."""
    enabled: Optional[bool] = None
    default_challenge_type: Optional[ChallengeTypeEnum] = None
    challenge_timeout_seconds: Optional[int] = Field(None, ge=10, le=3600)
    max_attempts: Optional[int] = Field(None, ge=1, le=10)
    exempt_ips: Optional[List[str]] = None
    exempt_user_agents: Optional[List[str]] = None
    difficulty: Optional[str] = Field(None, pattern="^(easy|medium|hard)$")


class VerifyChallengeRequest(BaseModel):
    """Challenge verification request."""
    solution: str = Field(..., min_length=1, max_length=1000)
    client_fingerprint: Optional[str] = None
    client_metadata: Optional[dict] = None


class CreateChallengeRequest(BaseModel):
    """Create challenge request."""
    ip_address: str
    challenge_type: ChallengeTypeEnum = ChallengeTypeEnum.JS_CHALLENGE
    metadata: Optional[dict] = None


# In-memory challenge config (would be stored in database in production)
_challenge_configs = {}


def get_challenge_config(tenant_id: int) -> dict:
    """Get challenge configuration for tenant."""
    if tenant_id not in _challenge_configs:
        _challenge_configs[tenant_id] = {
            "enabled": True,
            "default_challenge_type": ChallengeTypeEnum.JS_CHALLENGE,
            "challenge_timeout_seconds": 300,
            "max_attempts": 3,
            "exempt_ips": [],
            "exempt_user_agents": ["Googlebot", "Bingbot"],
            "difficulty": "medium",
            "pow_difficulty": 4,  # Number of leading zeros for PoW
            "js_challenge_script": "default",
        }
    return _challenge_configs[tenant_id]


def generate_challenge_token() -> str:
    """Generate a unique challenge token."""
    return secrets.token_urlsafe(32)


def generate_pow_challenge(difficulty: int = 4) -> tuple[str, str]:
    """
    Generate a proof-of-work challenge.

    Returns (challenge, expected_prefix) where the client must find
    a nonce such that hash(challenge + nonce) starts with expected_prefix.
    """
    challenge = secrets.token_hex(16)
    expected_prefix = "0" * difficulty
    return challenge, expected_prefix


def verify_pow_solution(challenge: str, nonce: str, difficulty: int = 4) -> bool:
    """Verify a proof-of-work solution."""
    data = f"{challenge}{nonce}".encode()
    hash_result = hashlib.sha256(data).hexdigest()
    expected_prefix = "0" * difficulty
    return hash_result.startswith(expected_prefix)


# Routes

@router.get("/", response_model=ChallengeListResponse)
async def list_challenges(
    tenant_id: int = Query(..., description="Tenant ID"),
    status: Optional[ChallengeStatus] = Query(None, description="Filter by status"),
    challenge_type: Optional[ChallengeTypeEnum] = Query(None, description="Filter by type"),
    ip_address: Optional[str] = Query(None, description="Filter by IP"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    List active challenge sessions.

    Returns currently active and recent challenge sessions
    with optional filtering by status, type, and IP.
    """
    query = db.query(ChallengeSession).filter(ChallengeSession.tenant_id == tenant_id)

    if status:
        query = query.filter(ChallengeSession.status == status.value)
    if challenge_type:
        query = query.filter(ChallengeSession.challenge_type == challenge_type.value)
    if ip_address:
        query = query.filter(ChallengeSession.ip_address == ip_address)

    total = query.count()
    sessions = query.order_by(ChallengeSession.created_at.desc()).offset(skip).limit(limit).all()

    return ChallengeListResponse(
        total=total,
        skip=skip,
        limit=limit,
        items=[
            ChallengeResponse(
                session_id=s.session_id,
                challenge_type=ChallengeTypeEnum(s.challenge_type),
                ip_address=s.ip_address,
                status=ChallengeStatus(s.status),
                created_at=s.created_at,
                expires_at=s.expires_at,
                attempts=s.attempts or 0,
                max_attempts=s.max_attempts or 3,
                passed_at=s.passed_at,
                metadata=s.metadata or {},
            )
            for s in sessions
        ],
    )


@router.get("/stats", response_model=ChallengeStatsResponse)
async def get_challenge_stats(
    tenant_id: int = Query(..., description="Tenant ID"),
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    Get challenge statistics for a tenant.

    Returns success rates, attempt counts, and timing statistics
    for the specified time range.
    """
    since = datetime.utcnow() - timedelta(hours=hours)

    sessions = (
        db.query(ChallengeSession)
        .filter(
            ChallengeSession.tenant_id == tenant_id,
            ChallengeSession.created_at >= since,
        )
        .all()
    )

    total = len(sessions)

    if total == 0:
        return ChallengeStatsResponse(
            total_challenges=0,
            by_type={},
            by_status={},
            success_rate=0.0,
            avg_attempts_to_pass=0.0,
            avg_time_to_pass_ms=0.0,
        )

    # Count by type
    by_type = {}
    for s in sessions:
        t = s.challenge_type or "unknown"
        by_type[t] = by_type.get(t, 0) + 1

    # Count by status
    by_status = {"pending": 0, "passed": 0, "failed": 0, "expired": 0}
    passed_sessions = []

    for s in sessions:
        status = s.status or "pending"
        by_status[status] = by_status.get(status, 0) + 1
        if status == "passed":
            passed_sessions.append(s)

    # Calculate success rate
    completed = by_status["passed"] + by_status["failed"]
    success_rate = (by_status["passed"] / completed * 100) if completed > 0 else 0.0

    # Calculate average attempts to pass
    total_attempts = sum(s.attempts or 1 for s in passed_sessions)
    avg_attempts = total_attempts / len(passed_sessions) if passed_sessions else 0.0

    # Calculate average time to pass
    total_time_ms = 0
    for s in passed_sessions:
        if s.passed_at and s.created_at:
            delta = (s.passed_at - s.created_at).total_seconds() * 1000
            total_time_ms += delta
    avg_time_ms = total_time_ms / len(passed_sessions) if passed_sessions else 0.0

    return ChallengeStatsResponse(
        total_challenges=total,
        by_type=by_type,
        by_status=by_status,
        success_rate=success_rate,
        avg_attempts_to_pass=avg_attempts,
        avg_time_to_pass_ms=avg_time_ms,
    )


@router.get("/config", response_model=ChallengeConfigResponse)
async def get_challenge_config_endpoint(
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Get challenge configuration for a tenant.

    Returns the current challenge settings including
    enabled status, default type, timeout, and exemptions.
    """
    config = get_challenge_config(tenant_id)

    return ChallengeConfigResponse(
        enabled=config["enabled"],
        default_challenge_type=ChallengeTypeEnum(config["default_challenge_type"]),
        challenge_timeout_seconds=config["challenge_timeout_seconds"],
        max_attempts=config["max_attempts"],
        exempt_ips=config["exempt_ips"],
        exempt_user_agents=config["exempt_user_agents"],
        difficulty=config["difficulty"],
        config=config,
    )


@router.put("/config", response_model=ChallengeConfigResponse)
async def update_challenge_config(
    update: ChallengeConfigUpdate,
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Update challenge configuration for a tenant.

    Allows modifying challenge settings including timeout,
    max attempts, difficulty, and exemptions.
    """
    config = get_challenge_config(tenant_id)

    if update.enabled is not None:
        config["enabled"] = update.enabled
    if update.default_challenge_type is not None:
        config["default_challenge_type"] = update.default_challenge_type
    if update.challenge_timeout_seconds is not None:
        config["challenge_timeout_seconds"] = update.challenge_timeout_seconds
    if update.max_attempts is not None:
        config["max_attempts"] = update.max_attempts
    if update.exempt_ips is not None:
        config["exempt_ips"] = update.exempt_ips
    if update.exempt_user_agents is not None:
        config["exempt_user_agents"] = update.exempt_user_agents
    if update.difficulty is not None:
        config["difficulty"] = update.difficulty
        # Adjust PoW difficulty
        difficulty_map = {"easy": 3, "medium": 4, "hard": 5}
        config["pow_difficulty"] = difficulty_map.get(update.difficulty, 4)

    _challenge_configs[tenant_id] = config

    logger.info(f"Challenge config updated: tenant={tenant_id}")

    return ChallengeConfigResponse(
        enabled=config["enabled"],
        default_challenge_type=ChallengeTypeEnum(config["default_challenge_type"]),
        challenge_timeout_seconds=config["challenge_timeout_seconds"],
        max_attempts=config["max_attempts"],
        exempt_ips=config["exempt_ips"],
        exempt_user_agents=config["exempt_user_agents"],
        difficulty=config["difficulty"],
        config=config,
    )


@router.post("/create")
async def create_challenge(
    request: CreateChallengeRequest,
    tenant_id: int = Query(..., description="Tenant ID"),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    Create a new challenge for an IP address.

    Generates a challenge that the client must solve to
    prove they are a legitimate user.
    """
    config = get_challenge_config(tenant_id)

    # Check if challenges are enabled
    if not config["enabled"]:
        return {
            "success": False,
            "error": "Challenges are disabled for this tenant",
        }

    # Check exemptions
    if request.ip_address in config["exempt_ips"]:
        return {
            "success": True,
            "exempt": True,
            "message": "IP is exempt from challenges",
        }

    # Generate challenge
    session_id = generate_challenge_token()
    now = datetime.utcnow()
    expires_at = now + timedelta(seconds=config["challenge_timeout_seconds"])

    # Generate challenge data based on type
    challenge_data = {}
    if request.challenge_type == ChallengeTypeEnum.POW:
        challenge, prefix = generate_pow_challenge(config["pow_difficulty"])
        challenge_data = {
            "challenge": challenge,
            "expected_prefix": prefix,
            "difficulty": config["pow_difficulty"],
        }
    elif request.challenge_type == ChallengeTypeEnum.JS_CHALLENGE:
        challenge_data = {
            "script_id": config["js_challenge_script"],
            "token": secrets.token_hex(16),
        }
    elif request.challenge_type == ChallengeTypeEnum.COOKIE:
        challenge_data = {
            "cookie_name": f"_challenge_{tenant_id}",
            "cookie_value": secrets.token_hex(16),
        }

    # Create session
    session = ChallengeSession(
        tenant_id=tenant_id,
        session_id=session_id,
        challenge_type=request.challenge_type.value,
        ip_address=request.ip_address,
        status="pending",
        created_at=now,
        expires_at=expires_at,
        attempts=0,
        max_attempts=config["max_attempts"],
        challenge_data=challenge_data,
        metadata=request.metadata or {},
    )
    db.add(session)
    db.commit()

    logger.info(
        f"Challenge created: session={session_id}, ip={request.ip_address}, "
        f"type={request.challenge_type.value}"
    )

    return {
        "success": True,
        "session_id": session_id,
        "challenge_type": request.challenge_type.value,
        "expires_at": expires_at.isoformat(),
        "challenge_data": challenge_data,
    }


@router.post("/verify/{session_id}")
async def verify_challenge(
    session_id: str,
    request: VerifyChallengeRequest,
    tenant_id: int = Query(..., description="Tenant ID"),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    Verify a challenge solution.

    Client submits their solution and receives pass/fail result.
    Failed attempts are tracked and may result in blocking.
    """
    session = (
        db.query(ChallengeSession)
        .filter(
            ChallengeSession.tenant_id == tenant_id,
            ChallengeSession.session_id == session_id,
        )
        .first()
    )

    if not session:
        raise HTTPException(status_code=404, detail="Challenge session not found")

    # Check if expired
    if session.expires_at < datetime.utcnow():
        session.status = "expired"
        db.commit()
        return {
            "success": False,
            "passed": False,
            "error": "Challenge expired",
        }

    # Check if already completed
    if session.status in ("passed", "failed"):
        return {
            "success": False,
            "passed": session.status == "passed",
            "error": f"Challenge already {session.status}",
        }

    # Check attempts
    session.attempts = (session.attempts or 0) + 1

    if session.attempts > session.max_attempts:
        session.status = "failed"
        db.commit()
        return {
            "success": False,
            "passed": False,
            "error": "Maximum attempts exceeded",
        }

    # Verify solution based on challenge type
    passed = False
    challenge_data = session.challenge_data or {}

    if session.challenge_type == ChallengeTypeEnum.POW.value:
        passed = verify_pow_solution(
            challenge_data.get("challenge", ""),
            request.solution,
            challenge_data.get("difficulty", 4),
        )
    elif session.challenge_type == ChallengeTypeEnum.JS_CHALLENGE.value:
        # JS challenge verification - check token
        expected_token = challenge_data.get("token", "")
        passed = request.solution == expected_token
    elif session.challenge_type == ChallengeTypeEnum.COOKIE.value:
        # Cookie challenge - check cookie value
        expected_value = challenge_data.get("cookie_value", "")
        passed = request.solution == expected_value
    elif session.challenge_type == ChallengeTypeEnum.FINGERPRINT.value:
        # Fingerprint challenge - just verify fingerprint is provided
        passed = bool(request.client_fingerprint)
    else:
        # Default: accept any non-empty solution
        passed = bool(request.solution)

    if passed:
        session.status = "passed"
        session.passed_at = datetime.utcnow()

        # Store client fingerprint if provided
        if request.client_fingerprint:
            session.metadata = session.metadata or {}
            session.metadata["client_fingerprint"] = request.client_fingerprint
    else:
        if session.attempts >= session.max_attempts:
            session.status = "failed"

    db.commit()

    logger.info(
        f"Challenge verification: session={session_id}, passed={passed}, "
        f"attempts={session.attempts}"
    )

    return {
        "success": True,
        "passed": passed,
        "attempts": session.attempts,
        "max_attempts": session.max_attempts,
        "status": session.status,
    }


@router.get("/types")
async def get_challenge_types():
    """
    Get available challenge types.

    Returns a list of all supported challenge types with
    descriptions and difficulty ratings.
    """
    return {
        "success": True,
        "types": [
            {
                "type": ChallengeTypeEnum.JS_CHALLENGE.value,
                "name": "JavaScript Challenge",
                "description": "Client must execute JavaScript to solve",
                "difficulty": "easy",
                "bot_effective": True,
                "user_friction": "low",
            },
            {
                "type": ChallengeTypeEnum.CAPTCHA.value,
                "name": "CAPTCHA",
                "description": "Visual challenge requiring human interaction",
                "difficulty": "medium",
                "bot_effective": True,
                "user_friction": "high",
            },
            {
                "type": ChallengeTypeEnum.POW.value,
                "name": "Proof of Work",
                "description": "Computational challenge requiring CPU time",
                "difficulty": "medium",
                "bot_effective": True,
                "user_friction": "medium",
            },
            {
                "type": ChallengeTypeEnum.COOKIE.value,
                "name": "Cookie Validation",
                "description": "Set and verify a challenge cookie",
                "difficulty": "easy",
                "bot_effective": False,
                "user_friction": "none",
            },
            {
                "type": ChallengeTypeEnum.FINGERPRINT.value,
                "name": "Browser Fingerprint",
                "description": "Collect and verify browser fingerprint",
                "difficulty": "medium",
                "bot_effective": True,
                "user_friction": "none",
            },
            {
                "type": ChallengeTypeEnum.RATE_CHECK.value,
                "name": "Rate Check",
                "description": "Verify request rate is within limits",
                "difficulty": "easy",
                "bot_effective": False,
                "user_friction": "none",
            },
        ],
    }


@router.delete("/{session_id}")
async def delete_challenge(
    session_id: str,
    tenant_id: int = Query(..., description="Tenant ID"),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    Delete a challenge session.

    Removes the challenge record from the database.
    """
    result = (
        db.query(ChallengeSession)
        .filter(
            ChallengeSession.tenant_id == tenant_id,
            ChallengeSession.session_id == session_id,
        )
        .delete()
    )
    db.commit()

    if result == 0:
        raise HTTPException(status_code=404, detail="Challenge session not found")

    return {
        "success": True,
        "session_id": session_id,
        "deleted": True,
    }


@router.delete("/expired")
async def cleanup_expired_challenges(
    tenant_id: int = Query(..., description="Tenant ID"),
    db=Depends(get_db),
    _=Depends(require_tenant_access),
):
    """
    Clean up expired challenge sessions.

    Removes all expired challenge records for the tenant.
    """
    now = datetime.utcnow()

    result = (
        db.query(ChallengeSession)
        .filter(
            ChallengeSession.tenant_id == tenant_id,
            ChallengeSession.expires_at < now,
        )
        .delete()
    )
    db.commit()

    logger.info(f"Expired challenges cleaned: tenant={tenant_id}, count={result}")

    return {
        "success": True,
        "deleted_count": result,
    }
