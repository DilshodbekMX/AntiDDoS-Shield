"""Add feature_weights column to per_ip_l2_config

Revision ID: a3f7b2c9d1e4
Revises: 0124f5ead45e
Create Date: 2026-03-29 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'a3f7b2c9d1e4'
down_revision: Union[str, Sequence[str], None] = '0124f5ead45e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if 'per_ip_l2_config' not in existing_tables:
        return  # Fresh DB: create_all in initial migration already has the column

    existing_cols = {c['name'] for c in inspector.get_columns('per_ip_l2_config')}
    if 'feature_weights' not in existing_cols:
        with op.batch_alter_table('per_ip_l2_config', schema=None) as batch_op:
            batch_op.add_column(sa.Column('feature_weights', sa.Text(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if 'per_ip_l2_config' not in existing_tables:
        return

    existing_cols = {c['name'] for c in inspector.get_columns('per_ip_l2_config')}
    if 'feature_weights' in existing_cols:
        with op.batch_alter_table('per_ip_l2_config', schema=None) as batch_op:
            batch_op.drop_column('feature_weights')
