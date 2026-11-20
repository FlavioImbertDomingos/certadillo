"""Console sessions for single sign-on

Revision ID: 0004
Revises: 0003
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import oracle

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('console_sessions',
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('subject', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.PrimaryKeyConstraint('token_hash')
    )
    op.create_index(op.f('ix_console_sessions_expires_at'), 'console_sessions', ['expires_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_console_sessions_expires_at'), table_name='console_sessions')
    op.drop_table('console_sessions')
