"""acme_eab.hmac_key_b64 may be NULL

The legacy plaintext EAB key column used to hold an empty string once the key
was encrypted. Oracle reads '' back as NULL and refuses it in a NOT NULL
column, so the column becomes nullable and empty strings become NULL on every
database.

Revision ID: 0002
Revises: 0001
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("acme_eab") as batch:
        batch.alter_column("hmac_key_b64", existing_type=sa.String(length=128), nullable=True)
    op.execute("UPDATE acme_eab SET hmac_key_b64 = NULL WHERE hmac_key_b64 = ''")


def downgrade() -> None:
    op.execute("UPDATE acme_eab SET hmac_key_b64 = '' WHERE hmac_key_b64 IS NULL")
    with op.batch_alter_table("acme_eab") as batch:
        batch.alter_column("hmac_key_b64", existing_type=sa.String(length=128), nullable=False)
