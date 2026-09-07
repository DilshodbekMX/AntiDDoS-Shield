"""initial

Revision ID: 0124f5ead45e
Revises:
Create Date: 2026-03-26 15:47:10.363293

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision: str = '0124f5ead45e'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    This initial migration brings the database to the current model state.
    On a fresh database it creates all tables from scratch via the ORM
    metadata.  On an existing database it drops legacy tables
    (threat_intel_*, reputation_entries, challenge_sessions) that were
    removed from the models, and adds missing indexes/constraints.
    All operations are conditional so this is safe to run on both fresh
    and existing databases.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # Fresh database: create all current domain tables using the ORM models.
    domain_tables = [t for t in existing_tables if t != 'alembic_version']
    if not domain_tables:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from api.database.models import Base as _Base
        _Base.metadata.create_all(bind=bind)
        return

    # Existing database: drop legacy tables no longer in the models.
    for table in ['threat_intel_entries', 'threat_intel_feeds', 'reputation_entries', 'challenge_sessions']:
        if table in existing_tables:
            op.drop_table(table)

    # Apply index/constraint changes to remaining tables.
    if 'api_tokens' in existing_tables:
        if not any('token_hash' in (c.get('column_names') or []) for c in inspector.get_unique_constraints('api_tokens')):
            with op.batch_alter_table('api_tokens', schema=None) as batch_op:
                batch_op.create_unique_constraint(None, ['token_hash'])

    if 'attacks' in existing_tables:
        existing_indexes = {idx['name'] for idx in inspector.get_indexes('attacks')}
        if 'ix_attacks_active' not in existing_indexes:
            with op.batch_alter_table('attacks', schema=None) as batch_op:
                batch_op.create_index('ix_attacks_active', ['is_active'], unique=False)

    if 'ip_lists' in existing_tables:
        existing_indexes = {idx['name'] for idx in inspector.get_indexes('ip_lists')}
        if 'ix_ip_lists_expires_at' not in existing_indexes:
            with op.batch_alter_table('ip_lists', schema=None) as batch_op:
                batch_op.create_index('ix_ip_lists_expires_at', ['expires_at'], unique=False)

    if 'policies' in existing_tables:
        if not any('name' in (c.get('column_names') or []) for c in inspector.get_unique_constraints('policies')):
            with op.batch_alter_table('policies', schema=None) as batch_op:
                batch_op.create_unique_constraint(None, ['name'])

    if 'webhooks' in existing_tables:
        if not any('name' in (c.get('column_names') or []) for c in inspector.get_unique_constraints('webhooks')):
            with op.batch_alter_table('webhooks', schema=None) as batch_op:
                batch_op.create_unique_constraint(None, ['name'])


def downgrade() -> None:
    """Downgrade schema.

    Reverses upgrade().  Two paths:

    * Fresh-DB path: upgrade() called create_all(), so downgrade() drops
      all ORM-owned tables to restore an empty database.
    * Existing-DB path: upgrade() only altered existing tables, so
      downgrade() reverses those incremental changes.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # Detect which path upgrade() took.
    # If legacy tables are absent AND current ORM tables exist, it was the
    # fresh-DB create_all path -- drop everything ORM-owned.
    legacy = {'threat_intel_entries', 'threat_intel_feeds', 'reputation_entries', 'challenge_sessions'}
    current_orm = {'protected_ips', 'ip_lists', 'policies', 'attacks', 'reports',
                   'webhooks', 'api_tokens', 'system_config', 'config_snapshots',
                   'per_ip_l2_config', 'audit_logs', 'traffic_rollups'}
    came_from_create_all = (
        not legacy.intersection(existing_tables)
        and bool(current_orm.intersection(existing_tables))
    )

    if came_from_create_all:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from api.database.models import Base as _Base
        _Base.metadata.drop_all(bind=bind)
        return

    # Existing-DB path: reverse incremental changes.
    # NOTE: Unnamed constraint drops are skipped because SQLite batch mode
    # cannot drop constraints that were created without an explicit name.
    if 'ip_lists' in existing_tables:
        with op.batch_alter_table('ip_lists', schema=None) as batch_op:
            batch_op.drop_index(batch_op.f('ix_ip_lists_expires_at'))

    if 'attacks' in existing_tables:
        with op.batch_alter_table('attacks', schema=None) as batch_op:
            batch_op.drop_index('ix_attacks_active')

    op.create_table('challenge_sessions',
    sa.Column('id', sa.VARCHAR(length=36), nullable=False),
    sa.Column('client_ip', sa.VARCHAR(length=45), nullable=False),
    sa.Column('challenge_type', sa.VARCHAR(length=16), nullable=False),
    sa.Column('status', sa.VARCHAR(length=7), nullable=False),
    sa.Column('challenge_data', sqlite.JSON(), nullable=True),
    sa.Column('attempts', sa.INTEGER(), server_default=sa.text('0'), nullable=False),
    sa.Column('max_attempts', sa.INTEGER(), server_default=sa.text('3'), nullable=False),
    sa.Column('issued_at', sa.DATETIME(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('expires_at', sa.DATETIME(), nullable=False),
    sa.Column('completed_at', sa.DATETIME(), nullable=True),
    sa.Column('user_agent', sa.VARCHAR(length=512), nullable=True),
    sa.Column('browser_fingerprint', sa.VARCHAR(length=64), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('challenge_sessions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_challenge_sessions_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_challenge_sessions_expires_at'), ['expires_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_challenge_sessions_client_ip'), ['client_ip'], unique=False)
        batch_op.create_index(batch_op.f('ix_challenge_lookup'), ['client_ip', 'status'], unique=False)

    op.create_table('reputation_entries',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('ip_address', sa.VARCHAR(length=45), nullable=False),
    sa.Column('score', sa.FLOAT(), server_default=sa.text('(50.0)'), nullable=False),
    sa.Column('category', sa.VARCHAR(length=30), nullable=True),
    sa.Column('confidence', sa.FLOAT(), server_default=sa.text('(0.0)'), nullable=False),
    sa.Column('packet_count', sa.BIGINT(), server_default=sa.text('0'), nullable=False),
    sa.Column('byte_count', sa.BIGINT(), server_default=sa.text('0'), nullable=False),
    sa.Column('connection_count', sa.INTEGER(), server_default=sa.text('0'), nullable=False),
    sa.Column('failed_connections', sa.INTEGER(), server_default=sa.text('0'), nullable=False),
    sa.Column('challenge_passes', sa.INTEGER(), server_default=sa.text('0'), nullable=False),
    sa.Column('challenge_failures', sa.INTEGER(), server_default=sa.text('0'), nullable=False),
    sa.Column('attack_associations', sa.INTEGER(), server_default=sa.text('0'), nullable=False),
    sa.Column('source', sa.VARCHAR(length=32), nullable=True),
    sa.Column('first_seen', sa.DATETIME(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('last_seen', sa.DATETIME(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('last_updated', sa.DATETIME(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('reputation_entries', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_reputation_score'), ['score'], unique=False)
        batch_op.create_index(batch_op.f('ix_reputation_entries_ip_address'), ['ip_address'], unique=False)

    op.create_table('threat_intel_feeds',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('name', sa.VARCHAR(length=64), nullable=False),
    sa.Column('url', sa.VARCHAR(length=512), nullable=False),
    sa.Column('feed_type', sa.VARCHAR(length=30), nullable=False),
    sa.Column('description', sa.VARCHAR(length=256), nullable=True),
    sa.Column('enabled', sa.BOOLEAN(), nullable=False),
    sa.Column('update_interval_hours', sa.INTEGER(), nullable=False),
    sa.Column('is_premium', sa.BOOLEAN(), nullable=False),
    sa.Column('requires_auth', sa.BOOLEAN(), nullable=False),
    sa.Column('auth_config', sqlite.JSON(), nullable=True),
    sa.Column('entry_count', sa.INTEGER(), nullable=False),
    sa.Column('last_updated', sa.DATETIME(), nullable=True),
    sa.Column('last_success', sa.DATETIME(), nullable=True),
    sa.Column('last_error', sa.TEXT(), nullable=True),
    sa.Column('next_update', sa.DATETIME(), nullable=True),
    sa.Column('created_at', sa.DATETIME(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('created_by', sa.VARCHAR(length=64), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    with op.batch_alter_table('threat_intel_feeds', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_threat_intel_feeds_next_update'), ['next_update'], unique=False)

    op.create_table('threat_intel_entries',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('feed_id', sa.INTEGER(), nullable=False),
    sa.Column('indicator', sa.VARCHAR(length=256), nullable=False),
    sa.Column('indicator_type', sa.VARCHAR(length=9), nullable=False),
    sa.Column('threat_type', sa.VARCHAR(length=50), nullable=True),
    sa.Column('severity', sa.VARCHAR(length=20), nullable=True),
    sa.Column('confidence', sa.FLOAT(), nullable=False),
    sa.Column('tags', sqlite.JSON(), nullable=True),
    sa.Column('description', sa.VARCHAR(length=512), nullable=True),
    sa.Column('reference_url', sa.VARCHAR(length=512), nullable=True),
    sa.Column('hit_count', sa.INTEGER(), nullable=False),
    sa.Column('last_hit_at', sa.DATETIME(), nullable=True),
    sa.Column('first_seen', sa.DATETIME(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('last_seen', sa.DATETIME(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('expires_at', sa.DATETIME(), nullable=True),
    sa.ForeignKeyConstraint(['feed_id'], ['threat_intel_feeds.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('feed_id', 'indicator', 'indicator_type', name=op.f('uq_threat_indicator'))
    )
    with op.batch_alter_table('threat_intel_entries', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_threat_intel_lookup'), ['indicator_type', 'indicator'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_intel_expires'), ['expires_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_intel_entries_indicator_type'), ['indicator_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_intel_entries_indicator'), ['indicator'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_intel_entries_feed_id'), ['feed_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_threat_intel_entries_expires_at'), ['expires_at'], unique=False)
