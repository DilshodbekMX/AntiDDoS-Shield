"""
Database module for Anti-DDoS Platform.

Provides SQLAlchemy ORM models, async session management,
and repository pattern for data access.
"""

from .connection import (
    get_db,
    get_async_db,
    init_db,
    close_db,
    DatabaseSession,
    AsyncDatabaseSession,
    engine,
    async_engine,
)
from .models import (
    Base,
    ProtectedIP,
    IPListEntry,
    Policy,
    Attack,
    Report,
    Webhook,
    APIToken,
    AuditLog,
    SystemConfigDB,
    ConfigSnapshot,
    PerIPL2Config,
)

__all__ = [
    # Connection
    "get_db",
    "get_async_db",
    "init_db",
    "close_db",
    "DatabaseSession",
    "AsyncDatabaseSession",
    "engine",
    "async_engine",
    # Models
    "Base",
    "ProtectedIP",
    "IPListEntry",
    "Policy",
    "Attack",
    "Report",
    "Webhook",
    "APIToken",
    "AuditLog",
    "SystemConfigDB",
    "ConfigSnapshot",
    "PerIPL2Config",
]
