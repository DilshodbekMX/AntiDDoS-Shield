"""
Database connection management for Anti-DDoS Platform.

Provides both sync and async SQLAlchemy session management,
connection pooling, and database initialization utilities.
"""

import os
import logging
from contextlib import contextmanager, asynccontextmanager
from typing import Generator, AsyncGenerator, Optional

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

# For async support (optional - can work without it)
try:
    from sqlalchemy.ext.asyncio import (
        create_async_engine,
        AsyncSession,
        async_sessionmaker,
    )
    ASYNC_SUPPORT = True
except ImportError:
    ASYNC_SUPPORT = False
    AsyncSession = None

logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./data/antiddos.db"
)

# For async SQLite, use aiosqlite
ASYNC_DATABASE_URL = DATABASE_URL.replace(
    "sqlite:///",
    "sqlite+aiosqlite:///"
) if DATABASE_URL.startswith("sqlite") else DATABASE_URL

# Ensure data directory exists
DATA_DIR = os.path.dirname(DATABASE_URL.replace("sqlite:///", ""))
if DATA_DIR and DATA_DIR != ".":
    os.makedirs(DATA_DIR, exist_ok=True)

# Connection pool settings
POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "10"))
POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))

# SQLite-specific settings
SQLITE_PRAGMAS = {
    "journal_mode": "WAL",      # Write-Ahead Logging for better concurrency
    "synchronous": "NORMAL",    # Balance between safety and performance
    "cache_size": -64000,       # 64MB cache
    "foreign_keys": "ON",       # Enforce foreign key constraints
    "busy_timeout": 5000,       # 5 second timeout on locks
}

# Allowlist of pragma names to prevent injection via misconfigured envs
_ALLOWED_PRAGMAS = frozenset(SQLITE_PRAGMAS.keys())


def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Set SQLite pragmas for optimal performance."""
    cursor = dbapi_connection.cursor()
    for pragma, value in SQLITE_PRAGMAS.items():
        if pragma not in _ALLOWED_PRAGMAS:
            raise ValueError(f"Disallowed SQLite PRAGMA: {pragma!r}")
        cursor.execute(f"PRAGMA {pragma} = {value}")
    cursor.close()


# Create sync engine
if DATABASE_URL.startswith("sqlite"):
    # SQLite uses StaticPool for thread safety
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=os.getenv("DB_ECHO", "false").lower() == "true",
    )
    # Apply SQLite optimizations
    event.listen(engine, "connect", _set_sqlite_pragmas)
else:
    # PostgreSQL/MySQL with connection pooling
    engine = create_engine(
        DATABASE_URL,
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
        pool_timeout=POOL_TIMEOUT,
        pool_pre_ping=True,  # Verify connections before use
        echo=os.getenv("DB_ECHO", "false").lower() == "true",
    )

# Create sync session factory
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

# Create async engine and session factory (if supported)
async_engine = None
AsyncSessionLocal = None

if ASYNC_SUPPORT:
    try:
        if ASYNC_DATABASE_URL.startswith("sqlite"):
            async_engine = create_async_engine(
                ASYNC_DATABASE_URL,
                connect_args={"check_same_thread": False},
                echo=os.getenv("DB_ECHO", "false").lower() == "true",
            )
        else:
            async_engine = create_async_engine(
                ASYNC_DATABASE_URL,
                pool_size=POOL_SIZE,
                max_overflow=MAX_OVERFLOW,
                pool_timeout=POOL_TIMEOUT,
                pool_pre_ping=True,
                echo=os.getenv("DB_ECHO", "false").lower() == "true",
            )

        AsyncSessionLocal = async_sessionmaker(
            bind=async_engine,
            class_=AsyncSession,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )
    except Exception as e:
        logger.warning(f"Async database support not available: {e}")
        async_engine = None
        AsyncSessionLocal = None


class DatabaseSession:
    """Context manager for synchronous database sessions."""

    def __init__(self):
        self.session: Optional[Session] = None

    def __enter__(self) -> Session:
        self.session = SessionLocal()
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            if exc_type:
                self.session.rollback()
            self.session.close()


class AsyncDatabaseSession:
    """Context manager for asynchronous database sessions."""

    def __init__(self):
        self.session: Optional[AsyncSession] = None

    async def __aenter__(self) -> AsyncSession:
        if not AsyncSessionLocal:
            raise RuntimeError("Async database support not available")
        self.session = AsyncSessionLocal()
        return self.session

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            if exc_type:
                await self.session.rollback()
            await self.session.close()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency for synchronous database sessions.

    Usage:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for asynchronous database sessions.

    Usage:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_async_db)):
            result = await db.execute(select(Item))
            return result.scalars().all()
    """
    if not AsyncSessionLocal:
        raise RuntimeError("Async database support not available")

    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


@contextmanager
def db_session() -> Generator[Session, None, None]:
    """
    Context manager for manual session management.

    Usage:
        with db_session() as db:
            db.add(item)
            db.commit()
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@asynccontextmanager
async def async_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager for manual session management.

    Usage:
        async with async_db_session() as db:
            db.add(item)
            await db.commit()
    """
    if not AsyncSessionLocal:
        raise RuntimeError("Async database support not available")

    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def init_db():
    """
    Initialize the database by running Alembic migrations.

    Uses `alembic upgrade head` so schema changes are applied safely
    without dropping existing data. Falls back to create_all() when
    Alembic is not configured (e.g. in tests).
    """
    logger.info(f"Initializing database: {DATABASE_URL}")

    try:
        from alembic.config import Config
        from alembic import command
        import pathlib

        alembic_ini = pathlib.Path(__file__).parent.parent.parent / "alembic.ini"
        if alembic_ini.exists():
            alembic_cfg = Config(str(alembic_ini))
            command.upgrade(alembic_cfg, "head")
            logger.info("Database migrations applied via Alembic")
        else:
            raise FileNotFoundError("alembic.ini not found")
    except Exception as e:
        logger.warning(f"Alembic migration failed ({e}), falling back to create_all()")
        from .models import Base
        Base.metadata.create_all(bind=engine)

    # Verify connection
    with engine.connect() as conn:
        result = conn.execute(text("SELECT 1"))
        result.fetchone()

    logger.info("Database initialized successfully")


async def init_async_db():
    """
    Initialize the database asynchronously (delegates to sync init_db for migration).
    """
    logger.info("Running async database init (via sync Alembic)")
    init_db()


def close_db():
    """
    Close all database connections.

    This should be called at application shutdown.
    """
    logger.info("Closing database connections")
    engine.dispose()


async def close_async_db():
    """
    Close all async database connections.
    """
    if async_engine:
        logger.info("Closing async database connections")
        await async_engine.dispose()


def get_db_info() -> dict:
    """
    Get information about the database connection.

    Returns:
        dict: Database connection information
    """
    info = {
        "url": DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL,
        "pool_size": POOL_SIZE,
        "max_overflow": MAX_OVERFLOW,
        "async_support": ASYNC_SUPPORT and async_engine is not None,
    }

    if DATABASE_URL.startswith("sqlite"):
        info["type"] = "sqlite"
        info["pragmas"] = SQLITE_PRAGMAS
    elif DATABASE_URL.startswith("postgresql"):
        info["type"] = "postgresql"
    elif DATABASE_URL.startswith("mysql"):
        info["type"] = "mysql"
    else:
        info["type"] = "unknown"

    return info


def check_db_health() -> dict:
    """
    Check database health and return status.

    Returns:
        dict: Health check result with status and details
    """
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.fetchone()

        return {
            "status": "healthy",
            "database": get_db_info(),
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "database": get_db_info(),
        }
