"""
Layer 4 API routers.

Provides endpoints for:
- IP Reputation management
- Challenge verification
- Bot management
"""

from .reputation import router as reputation_router
from .challenges import router as challenges_router
from .bot_management import router as bot_management_router

__all__ = [
    "reputation_router",
    "challenges_router",
    "bot_management_router",
]
