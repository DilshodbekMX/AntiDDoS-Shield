"""
Repository pattern implementations for data access.

Repositories provide a clean abstraction over database operations,
making it easy to swap implementations (e.g., for testing) and
ensuring consistent data access patterns across the application.
"""

from .base import BaseRepository
from .policy_repo import PolicyRepository
from .attack_repo import AttackRepository
from .iplist_repo import IPListRepository
from .report_repo import ReportRepository
from .token_repo import APITokenRepository
from .audit_repo import AuditLogRepository
from .config_repo import ConfigRepository
from .per_ip_config_repo import PerIPL2ConfigRepository
from .traffic_repo import TrafficRepository

__all__ = [
    "BaseRepository",
    "PolicyRepository",
    "AttackRepository",
    "IPListRepository",
    "ReportRepository",
    "APITokenRepository",
    "AuditLogRepository",
    "ConfigRepository",
    "PerIPL2ConfigRepository",
    "TrafficRepository",
]
