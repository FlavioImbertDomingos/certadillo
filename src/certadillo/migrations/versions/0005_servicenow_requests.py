"""Requests from the ServiceNow catalog item, and the work notes owed back

Revision ID: 0005
Revises: 0004
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import oracle

import certadillo.db

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('servicenow_requests',
    sa.Column('ritm', sa.String(length=40), nullable=False),
    sa.Column('sys_id', sa.String(length=64), nullable=False),
    sa.Column('app_id', sa.Integer(), nullable=False),
    sa.Column('approval_id', sa.Integer(), nullable=True),
    sa.Column('requested_for', sa.String(length=255), nullable=False),
    sa.Column('snow_approved_by', sa.String(length=255), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('notes_pending', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.PrimaryKeyConstraint('ritm')
    )
    op.create_index(op.f('ix_servicenow_requests_app_id'), 'servicenow_requests', ['app_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_servicenow_requests_app_id'), table_name='servicenow_requests')
    op.drop_table('servicenow_requests')
