"""Leases for leader election: one replica runs housekeeping and audit shipping

Revision ID: 0003
Revises: 0002
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import oracle

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('leases',
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('holder', sa.String(length=120), nullable=False),
    sa.Column('acquired_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.PrimaryKeyConstraint('name')
    )


def downgrade() -> None:
    op.drop_table('leases')
