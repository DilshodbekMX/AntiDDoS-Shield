import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool
from alembic import context

# Add backend directory to sys.path so api package can be imported
sys.path.insert(0, str(Path(__file__).parent.parent))

# Alembic Config object
config = context.config

# Set up logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import models so autogenerate can detect schema changes
from api.database.models import Base  # noqa: E402
from api.database.connection import DATABASE_URL  # noqa: E402

target_metadata = Base.metadata

# Override sqlalchemy.url only when DATABASE_URL is explicitly set in the environment.
# If it's not set, leave whatever the caller (e.g. test) put in the config unchanged.
_db_url_from_env = os.environ.get("DATABASE_URL")
if _db_url_from_env:
    config.set_main_option("sqlalchemy.url", _db_url_from_env)


def run_migrations_offline() -> None:
    """Run migrations in offline (SQL script generation) mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # Required for SQLite ALTER TABLE support
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # Required for SQLite ALTER TABLE support
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
