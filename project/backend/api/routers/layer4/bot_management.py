"""
Layer 4 Bot Management API router.

Provides endpoints for detecting, categorizing, and managing bot traffic.
Includes good bot allowlisting, bad bot detection, and traffic analysis.
"""

import logging
from typing import Optional, List
from datetime import datetime, timedelta
from enum import Enum

from fastapi import APIRouter, HTTPException, Query, Depends, Body
from pydantic import BaseModel, Field

from ...database import get_db
from ...auth import require_tenant_access, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/layer4/bots", tags=["Layer 4 - Bot Management"])


# Pydantic models

class BotCategory(str, Enum):
    """Bot category classifications."""
    GOOD = "good"
    BAD = "bad"
    UNKNOWN = "unknown"
    SEARCH_ENGINE = "search_engine"
    MONITORING = "monitoring"
    SOCIAL = "social"
    SCRAPER = "scraper"
    SPAM = "spam"
    CREDENTIAL_STUFFING = "credential_stuffing"
    DDOS = "ddos"


class BotAction(str, Enum):
    """Actions to take on bot traffic."""
    ALLOW = "allow"
    CHALLENGE = "challenge"
    THROTTLE = "throttle"
    BLOCK = "block"
    LOG = "log"


class BotEntry(BaseModel):
    """Bot entry model."""
    id: str
    user_agent_pattern: str
    category: BotCategory
    action: BotAction
    name: Optional[str] = None
    description: Optional[str] = None
    created_at: datetime
    last_seen: Optional[datetime] = None
    request_count: int = 0
    is_verified: bool = False
    metadata: dict = {}


class BotStatsResponse(BaseModel):
    """Bot traffic statistics response."""
    success: bool = True
    total_requests: int
    bot_requests: int
    human_requests: int
    bot_percentage: float
    by_category: dict
    by_action: dict
    top_user_agents: List[dict]


class BotConfigResponse(BaseModel):
    """Bot management configuration response."""
    success: bool = True
    enabled: bool
    default_action: BotAction
    challenge_unknown_bots: bool
    block_bad_bots: bool
    allow_good_bots: bool
    fingerprinting_enabled: bool
    js_challenge_enabled: bool
    rate_limit_bots: bool
    bot_rate_limit: int
    config: dict


class BotConfigUpdate(BaseModel):
    """Bot configuration update request."""
    enabled: Optional[bool] = None
    default_action: Optional[BotAction] = None
    challenge_unknown_bots: Optional[bool] = None
    block_bad_bots: Optional[bool] = None
    allow_good_bots: Optional[bool] = None
    fingerprinting_enabled: Optional[bool] = None
    js_challenge_enabled: Optional[bool] = None
    rate_limit_bots: Optional[bool] = None
    bot_rate_limit: Optional[int] = Field(None, ge=1, le=10000)


class AddBotRequest(BaseModel):
    """Add bot entry request."""
    user_agent_pattern: str = Field(..., min_length=1, max_length=500)
    category: BotCategory
    action: BotAction
    name: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    is_verified: bool = False


class BotDetectionResult(BaseModel):
    """Bot detection result."""
    is_bot: bool
    confidence: float = Field(..., ge=0, le=1)
    category: BotCategory
    recommended_action: BotAction
    signals: List[str]
    fingerprint: Optional[dict] = None


# In-memory storage (would be database in production)
_bot_configs = {}
_good_bots = {}
_bad_bots = {}
_bot_stats = {}


def get_bot_config(tenant_id: int) -> dict:
    """Get bot management configuration for tenant."""
    if tenant_id not in _bot_configs:
        _bot_configs[tenant_id] = {
            "enabled": True,
            "default_action": BotAction.CHALLENGE,
            "challenge_unknown_bots": True,
            "block_bad_bots": True,
            "allow_good_bots": True,
            "fingerprinting_enabled": True,
            "js_challenge_enabled": True,
            "rate_limit_bots": True,
            "bot_rate_limit": 100,  # requests per minute
        }
    return _bot_configs[tenant_id]


def get_good_bots(tenant_id: int) -> dict:
    """Get good bot list for tenant."""
    if tenant_id not in _good_bots:
        # Initialize with common good bots
        _good_bots[tenant_id] = {
            "googlebot": {
                "id": "googlebot",
                "user_agent_pattern": "Googlebot",
                "category": BotCategory.SEARCH_ENGINE,
                "action": BotAction.ALLOW,
                "name": "Google Bot",
                "description": "Google search crawler",
                "is_verified": True,
                "verify_method": "dns_reverse",
                "created_at": datetime.utcnow(),
            },
            "bingbot": {
                "id": "bingbot",
                "user_agent_pattern": "bingbot",
                "category": BotCategory.SEARCH_ENGINE,
                "action": BotAction.ALLOW,
                "name": "Bing Bot",
                "description": "Microsoft Bing crawler",
                "is_verified": True,
                "verify_method": "dns_reverse",
                "created_at": datetime.utcnow(),
            },
            "duckduckbot": {
                "id": "duckduckbot",
                "user_agent_pattern": "DuckDuckBot",
                "category": BotCategory.SEARCH_ENGINE,
                "action": BotAction.ALLOW,
                "name": "DuckDuckGo Bot",
                "description": "DuckDuckGo crawler",
                "is_verified": True,
                "created_at": datetime.utcnow(),
            },
            "slurp": {
                "id": "slurp",
                "user_agent_pattern": "Slurp",
                "category": BotCategory.SEARCH_ENGINE,
                "action": BotAction.ALLOW,
                "name": "Yahoo Slurp",
                "description": "Yahoo crawler",
                "is_verified": True,
                "created_at": datetime.utcnow(),
            },
            "facebookbot": {
                "id": "facebookbot",
                "user_agent_pattern": "facebookexternalhit",
                "category": BotCategory.SOCIAL,
                "action": BotAction.ALLOW,
                "name": "Facebook Bot",
                "description": "Facebook link preview crawler",
                "is_verified": True,
                "created_at": datetime.utcnow(),
            },
            "twitterbot": {
                "id": "twitterbot",
                "user_agent_pattern": "Twitterbot",
                "category": BotCategory.SOCIAL,
                "action": BotAction.ALLOW,
                "name": "Twitter Bot",
                "description": "Twitter card crawler",
                "is_verified": True,
                "created_at": datetime.utcnow(),
            },
            "uptimerobot": {
                "id": "uptimerobot",
                "user_agent_pattern": "UptimeRobot",
                "category": BotCategory.MONITORING,
                "action": BotAction.ALLOW,
                "name": "UptimeRobot",
                "description": "Uptime monitoring service",
                "is_verified": False,
                "created_at": datetime.utcnow(),
            },
        }
    return _good_bots[tenant_id]


def get_bad_bots(tenant_id: int) -> dict:
    """Get bad bot list for tenant."""
    if tenant_id not in _bad_bots:
        # Initialize with common bad bot patterns
        _bad_bots[tenant_id] = {
            "python-requests": {
                "id": "python-requests",
                "user_agent_pattern": "python-requests",
                "category": BotCategory.SCRAPER,
                "action": BotAction.CHALLENGE,
                "name": "Python Requests",
                "description": "Python HTTP library - often used for scraping",
                "created_at": datetime.utcnow(),
            },
            "curl": {
                "id": "curl",
                "user_agent_pattern": "curl/",
                "category": BotCategory.UNKNOWN,
                "action": BotAction.CHALLENGE,
                "name": "cURL",
                "description": "Command-line HTTP client",
                "created_at": datetime.utcnow(),
            },
            "masscan": {
                "id": "masscan",
                "user_agent_pattern": "masscan",
                "category": BotCategory.BAD,
                "action": BotAction.BLOCK,
                "name": "Masscan",
                "description": "Port scanner",
                "created_at": datetime.utcnow(),
            },
            "sqlmap": {
                "id": "sqlmap",
                "user_agent_pattern": "sqlmap",
                "category": BotCategory.BAD,
                "action": BotAction.BLOCK,
                "name": "SQLMap",
                "description": "SQL injection tool",
                "created_at": datetime.utcnow(),
            },
            "nikto": {
                "id": "nikto",
                "user_agent_pattern": "Nikto",
                "category": BotCategory.BAD,
                "action": BotAction.BLOCK,
                "name": "Nikto",
                "description": "Web vulnerability scanner",
                "created_at": datetime.utcnow(),
            },
            "nmap": {
                "id": "nmap",
                "user_agent_pattern": "Nmap",
                "category": BotCategory.BAD,
                "action": BotAction.BLOCK,
                "name": "Nmap",
                "description": "Network scanner",
                "created_at": datetime.utcnow(),
            },
            "empty-ua": {
                "id": "empty-ua",
                "user_agent_pattern": "^$",
                "category": BotCategory.UNKNOWN,
                "action": BotAction.CHALLENGE,
                "name": "Empty User-Agent",
                "description": "Requests with empty user-agent",
                "created_at": datetime.utcnow(),
            },
        }
    return _bad_bots[tenant_id]


def get_bot_stats(tenant_id: int) -> dict:
    """Get bot statistics for tenant."""
    if tenant_id not in _bot_stats:
        _bot_stats[tenant_id] = {
            "total_requests": 0,
            "bot_requests": 0,
            "human_requests": 0,
            "by_category": {},
            "by_action": {},
            "user_agent_counts": {},
        }
    return _bot_stats[tenant_id]


# Routes

@router.get("/")
async def list_detected_bots(
    tenant_id: int = Query(..., description="Tenant ID"),
    category: Optional[BotCategory] = Query(None, description="Filter by category"),
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    _=Depends(require_tenant_access),
):
    """
    List detected bots for a tenant.

    Returns recently detected bots with their categories,
    actions taken, and request counts.
    """
    # Combine good and bad bots for listing
    good = get_good_bots(tenant_id)
    bad = get_bad_bots(tenant_id)

    all_bots = []

    for bot_id, bot in {**good, **bad}.items():
        if category and bot.get("category") != category.value:
            continue

        all_bots.append({
            "id": bot_id,
            "user_agent_pattern": bot["user_agent_pattern"],
            "category": bot.get("category", BotCategory.UNKNOWN),
            "action": bot.get("action", BotAction.LOG),
            "name": bot.get("name"),
            "description": bot.get("description"),
            "created_at": bot.get("created_at", datetime.utcnow()).isoformat(),
            "last_seen": bot.get("last_seen"),
            "request_count": bot.get("request_count", 0),
            "is_verified": bot.get("is_verified", False),
        })

    # Sort by request count descending
    all_bots.sort(key=lambda x: x.get("request_count", 0), reverse=True)

    total = len(all_bots)
    items = all_bots[skip:skip + limit]

    return {
        "success": True,
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": items,
    }


@router.get("/stats", response_model=BotStatsResponse)
async def get_bot_traffic_stats(
    tenant_id: int = Query(..., description="Tenant ID"),
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    _=Depends(require_tenant_access),
):
    """
    Get bot traffic statistics.

    Returns breakdown of bot vs human traffic, category
    distribution, and top user agents.
    """
    stats = get_bot_stats(tenant_id)

    total = stats["total_requests"] or 1  # Avoid division by zero
    bot = stats["bot_requests"]
    human = stats["human_requests"]

    # Calculate top user agents
    ua_counts = stats.get("user_agent_counts", {})
    top_uas = sorted(
        [{"user_agent": ua, "count": count} for ua, count in ua_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    return BotStatsResponse(
        total_requests=total,
        bot_requests=bot,
        human_requests=human,
        bot_percentage=(bot / total) * 100 if total > 0 else 0,
        by_category=stats.get("by_category", {}),
        by_action=stats.get("by_action", {}),
        top_user_agents=top_uas,
    )


@router.get("/categories")
async def get_bot_categories(
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Get bot category breakdown.

    Returns counts and examples for each bot category.
    """
    good = get_good_bots(tenant_id)
    bad = get_bad_bots(tenant_id)

    categories = {}

    for cat in BotCategory:
        good_in_cat = [b for b in good.values() if b.get("category") == cat.value]
        bad_in_cat = [b for b in bad.values() if b.get("category") == cat.value]

        categories[cat.value] = {
            "count": len(good_in_cat) + len(bad_in_cat),
            "good_bots": len(good_in_cat),
            "bad_bots": len(bad_in_cat),
            "description": _get_category_description(cat),
            "default_action": _get_category_default_action(cat),
            "examples": [b.get("name") for b in (good_in_cat + bad_in_cat)[:5]],
        }

    return {
        "success": True,
        "categories": categories,
    }


def _get_category_description(category: BotCategory) -> str:
    """Get description for bot category."""
    descriptions = {
        BotCategory.GOOD: "Verified legitimate bots",
        BotCategory.BAD: "Known malicious bots",
        BotCategory.UNKNOWN: "Unclassified bot traffic",
        BotCategory.SEARCH_ENGINE: "Search engine crawlers",
        BotCategory.MONITORING: "Uptime and performance monitors",
        BotCategory.SOCIAL: "Social media crawlers",
        BotCategory.SCRAPER: "Content scrapers",
        BotCategory.SPAM: "Spam bots",
        BotCategory.CREDENTIAL_STUFFING: "Credential stuffing bots",
        BotCategory.DDOS: "DDoS attack bots",
    }
    return descriptions.get(category, "Unknown category")


def _get_category_default_action(category: BotCategory) -> str:
    """Get default action for bot category."""
    actions = {
        BotCategory.GOOD: BotAction.ALLOW.value,
        BotCategory.BAD: BotAction.BLOCK.value,
        BotCategory.UNKNOWN: BotAction.CHALLENGE.value,
        BotCategory.SEARCH_ENGINE: BotAction.ALLOW.value,
        BotCategory.MONITORING: BotAction.ALLOW.value,
        BotCategory.SOCIAL: BotAction.ALLOW.value,
        BotCategory.SCRAPER: BotAction.THROTTLE.value,
        BotCategory.SPAM: BotAction.BLOCK.value,
        BotCategory.CREDENTIAL_STUFFING: BotAction.BLOCK.value,
        BotCategory.DDOS: BotAction.BLOCK.value,
    }
    return actions.get(category, BotAction.CHALLENGE.value)


@router.get("/good")
async def list_good_bots(
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    List good (allowed) bots.

    Returns the list of bots that are allowed without challenges.
    """
    bots = get_good_bots(tenant_id)

    return {
        "success": True,
        "count": len(bots),
        "bots": [
            {
                "id": bot_id,
                **{k: v.isoformat() if isinstance(v, datetime) else v for k, v in bot.items()},
            }
            for bot_id, bot in bots.items()
        ],
    }


@router.post("/good")
async def add_good_bot(
    request: AddBotRequest,
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Add a bot to the good (allowed) list.

    Good bots are allowed to access without challenges.
    """
    bots = get_good_bots(tenant_id)

    # Generate ID from user agent pattern
    bot_id = request.user_agent_pattern.lower().replace(" ", "-").replace("/", "-")[:50]

    if bot_id in bots:
        raise HTTPException(status_code=409, detail="Bot pattern already exists")

    bots[bot_id] = {
        "id": bot_id,
        "user_agent_pattern": request.user_agent_pattern,
        "category": request.category.value,
        "action": request.action.value,
        "name": request.name,
        "description": request.description,
        "is_verified": request.is_verified,
        "created_at": datetime.utcnow(),
        "request_count": 0,
    }

    logger.info(f"Good bot added: tenant={tenant_id}, pattern={request.user_agent_pattern}")

    return {
        "success": True,
        "id": bot_id,
        "message": "Good bot added successfully",
    }


@router.delete("/good/{bot_id}")
async def remove_good_bot(
    bot_id: str,
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Remove a bot from the good list.
    """
    bots = get_good_bots(tenant_id)

    if bot_id not in bots:
        raise HTTPException(status_code=404, detail="Bot not found")

    del bots[bot_id]

    logger.info(f"Good bot removed: tenant={tenant_id}, id={bot_id}")

    return {
        "success": True,
        "id": bot_id,
        "deleted": True,
    }


@router.get("/bad")
async def list_bad_bots(
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    List bad (blocked) bots.

    Returns the list of bots that are blocked or challenged.
    """
    bots = get_bad_bots(tenant_id)

    return {
        "success": True,
        "count": len(bots),
        "bots": [
            {
                "id": bot_id,
                **{k: v.isoformat() if isinstance(v, datetime) else v for k, v in bot.items()},
            }
            for bot_id, bot in bots.items()
        ],
    }


@router.post("/bad")
async def add_bad_bot(
    request: AddBotRequest,
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Add a bot signature to the bad bot list.

    Bad bots are blocked or challenged based on the specified action.
    """
    bots = get_bad_bots(tenant_id)

    # Generate ID from user agent pattern
    bot_id = request.user_agent_pattern.lower().replace(" ", "-").replace("/", "-")[:50]

    if bot_id in bots:
        raise HTTPException(status_code=409, detail="Bot pattern already exists")

    bots[bot_id] = {
        "id": bot_id,
        "user_agent_pattern": request.user_agent_pattern,
        "category": request.category.value,
        "action": request.action.value,
        "name": request.name,
        "description": request.description,
        "is_verified": False,
        "created_at": datetime.utcnow(),
        "request_count": 0,
    }

    logger.info(f"Bad bot added: tenant={tenant_id}, pattern={request.user_agent_pattern}")

    return {
        "success": True,
        "id": bot_id,
        "message": "Bad bot signature added successfully",
    }


@router.delete("/bad/{bot_id}")
async def remove_bad_bot(
    bot_id: str,
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Remove a bot signature from the bad bot list.
    """
    bots = get_bad_bots(tenant_id)

    if bot_id not in bots:
        raise HTTPException(status_code=404, detail="Bot not found")

    del bots[bot_id]

    logger.info(f"Bad bot removed: tenant={tenant_id}, id={bot_id}")

    return {
        "success": True,
        "id": bot_id,
        "deleted": True,
    }


@router.get("/config", response_model=BotConfigResponse)
async def get_bot_config_endpoint(
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Get bot management configuration.

    Returns the current bot detection and handling settings.
    """
    config = get_bot_config(tenant_id)

    return BotConfigResponse(
        enabled=config["enabled"],
        default_action=BotAction(config["default_action"]),
        challenge_unknown_bots=config["challenge_unknown_bots"],
        block_bad_bots=config["block_bad_bots"],
        allow_good_bots=config["allow_good_bots"],
        fingerprinting_enabled=config["fingerprinting_enabled"],
        js_challenge_enabled=config["js_challenge_enabled"],
        rate_limit_bots=config["rate_limit_bots"],
        bot_rate_limit=config["bot_rate_limit"],
        config=config,
    )


@router.put("/config", response_model=BotConfigResponse)
async def update_bot_config(
    update: BotConfigUpdate,
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Update bot management configuration.

    Allows modifying bot detection and handling settings.
    """
    config = get_bot_config(tenant_id)

    if update.enabled is not None:
        config["enabled"] = update.enabled
    if update.default_action is not None:
        config["default_action"] = update.default_action
    if update.challenge_unknown_bots is not None:
        config["challenge_unknown_bots"] = update.challenge_unknown_bots
    if update.block_bad_bots is not None:
        config["block_bad_bots"] = update.block_bad_bots
    if update.allow_good_bots is not None:
        config["allow_good_bots"] = update.allow_good_bots
    if update.fingerprinting_enabled is not None:
        config["fingerprinting_enabled"] = update.fingerprinting_enabled
    if update.js_challenge_enabled is not None:
        config["js_challenge_enabled"] = update.js_challenge_enabled
    if update.rate_limit_bots is not None:
        config["rate_limit_bots"] = update.rate_limit_bots
    if update.bot_rate_limit is not None:
        config["bot_rate_limit"] = update.bot_rate_limit

    _bot_configs[tenant_id] = config

    logger.info(f"Bot config updated: tenant={tenant_id}")

    return BotConfigResponse(
        enabled=config["enabled"],
        default_action=BotAction(config["default_action"]),
        challenge_unknown_bots=config["challenge_unknown_bots"],
        block_bad_bots=config["block_bad_bots"],
        allow_good_bots=config["allow_good_bots"],
        fingerprinting_enabled=config["fingerprinting_enabled"],
        js_challenge_enabled=config["js_challenge_enabled"],
        rate_limit_bots=config["rate_limit_bots"],
        bot_rate_limit=config["bot_rate_limit"],
        config=config,
    )


@router.post("/detect")
async def detect_bot(
    user_agent: str = Query(..., description="User-Agent string to analyze"),
    ip_address: Optional[str] = Query(None, description="IP address"),
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
) -> BotDetectionResult:
    """
    Detect if a request is from a bot.

    Analyzes the user-agent string and other signals to
    determine if traffic is from a bot.
    """
    config = get_bot_config(tenant_id)
    good = get_good_bots(tenant_id)
    bad = get_bad_bots(tenant_id)

    signals = []
    confidence = 0.0
    category = BotCategory.UNKNOWN
    action = BotAction(config["default_action"])

    # Check good bots first
    for bot_id, bot in good.items():
        if bot["user_agent_pattern"].lower() in user_agent.lower():
            return BotDetectionResult(
                is_bot=True,
                confidence=1.0,
                category=BotCategory(bot["category"]),
                recommended_action=BotAction(bot["action"]),
                signals=[f"Matched good bot pattern: {bot['name']}"],
            )

    # Check bad bots
    for bot_id, bot in bad.items():
        pattern = bot["user_agent_pattern"]
        if pattern.startswith("^") and pattern.endswith("$"):
            # Regex pattern (simple check for empty UA)
            if pattern == "^$" and not user_agent:
                signals.append("Empty user-agent detected")
                confidence = 0.9
                category = BotCategory.BAD
                action = BotAction(bot["action"])
                break
        elif pattern.lower() in user_agent.lower():
            signals.append(f"Matched bad bot pattern: {bot.get('name', pattern)}")
            confidence = 0.95
            category = BotCategory(bot["category"])
            action = BotAction(bot["action"])
            break

    # Additional heuristics if no pattern matched
    if not signals:
        # Check for common bot indicators
        bot_indicators = [
            ("bot", 0.7),
            ("spider", 0.7),
            ("crawler", 0.7),
            ("scraper", 0.8),
            ("curl", 0.6),
            ("wget", 0.6),
            ("python", 0.5),
            ("java", 0.4),
            ("go-http", 0.5),
        ]

        for indicator, conf in bot_indicators:
            if indicator.lower() in user_agent.lower():
                signals.append(f"User-agent contains '{indicator}'")
                confidence = max(confidence, conf)

        # Check for missing common browser features
        if "Mozilla" not in user_agent:
            signals.append("Missing Mozilla token")
            confidence = max(confidence, 0.4)

        if not any(browser in user_agent for browser in ["Chrome", "Firefox", "Safari", "Edge"]):
            signals.append("No common browser identifier")
            confidence = max(confidence, 0.3)

    # Determine if it's a bot
    is_bot = confidence > 0.5

    if is_bot and category == BotCategory.UNKNOWN:
        if confidence > 0.8:
            category = BotCategory.BAD
            action = BotAction.BLOCK if config["block_bad_bots"] else BotAction.CHALLENGE
        else:
            action = BotAction.CHALLENGE if config["challenge_unknown_bots"] else BotAction.LOG

    return BotDetectionResult(
        is_bot=is_bot,
        confidence=confidence,
        category=category,
        recommended_action=action,
        signals=signals,
    )


@router.post("/verify-good-bot")
async def verify_good_bot(
    user_agent: str = Query(..., description="User-Agent string"),
    ip_address: str = Query(..., description="IP address to verify"),
    tenant_id: int = Query(..., description="Tenant ID"),
    _=Depends(require_tenant_access),
):
    """
    Verify if a claimed good bot is legitimate.

    Uses reverse DNS lookup to verify search engine bots.
    """
    import socket

    good = get_good_bots(tenant_id)
    matched_bot = None

    for bot_id, bot in good.items():
        if bot["user_agent_pattern"].lower() in user_agent.lower():
            matched_bot = bot
            break

    if not matched_bot:
        return {
            "success": True,
            "is_verified": False,
            "reason": "User-agent does not match any good bot pattern",
        }

    # Attempt reverse DNS verification
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)

        # Check for known bot hostnames
        verified_domains = {
            "googlebot": [".googlebot.com", ".google.com"],
            "bingbot": [".search.msn.com"],
            "duckduckbot": [".duckduckgo.com"],
            "slurp": [".crawl.yahoo.net"],
        }

        bot_id = matched_bot.get("id", "").lower()
        expected_domains = verified_domains.get(bot_id, [])

        is_verified = any(hostname.endswith(domain) for domain in expected_domains)

        return {
            "success": True,
            "is_verified": is_verified,
            "hostname": hostname,
            "expected_domains": expected_domains,
            "bot_name": matched_bot.get("name"),
        }
    except socket.herror:
        return {
            "success": True,
            "is_verified": False,
            "reason": "Reverse DNS lookup failed",
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }
