"""
API Routers Package
"""

from .config import router as config_router
from .stats import router as stats_router
from .security import router as security_router
from .policies import router as policies_router
from .reports import router as reports_router
from .auth import router as auth_router
from .realtime import router as realtime_router
from .rules import router as rules_router
from .layer1_config import router as layer1_config_router
from .layer2_config import router as layer2_config_router
from .system import router as system_router
from .per_ip_l2_config import router as per_ip_l2_config_router
from .telemetry import router as telemetry_router

__all__ = [
    "config_router",
    "stats_router",
    "security_router",
    "policies_router",
    "reports_router",
    "auth_router",
    "realtime_router",
    "rules_router",
    "layer1_config_router",
    "layer2_config_router",
    "system_router",
    "per_ip_l2_config_router",
    "telemetry_router",
]
