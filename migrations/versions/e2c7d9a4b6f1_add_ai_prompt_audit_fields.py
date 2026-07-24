"""Add AI prompt audit fields.

Revision ID: e2c7d9a4b6f1
Revises: d1f4a6b9c8e2
Create Date: 2026-07-24 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e2c7d9a4b6f1"
down_revision: str | None = "d1f4a6b9c8e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("ai_analyses", schema=None) as batch_op:
        batch_op.add_column(sa.Column("prompt_sha256", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("input_tokens", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("output_tokens", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("schema_valid", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("reference_valid", sa.Boolean(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ai_analyses", schema=None) as batch_op:
        batch_op.drop_column("reference_valid")
        batch_op.drop_column("schema_valid")
        batch_op.drop_column("output_tokens")
        batch_op.drop_column("input_tokens")
        batch_op.drop_column("prompt_sha256")
