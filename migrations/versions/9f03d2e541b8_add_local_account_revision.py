"""Add a revision counter to local accounts.

Revision ID: 9f03d2e541b8
Revises: 7b1ac80518a7
Create Date: 2026-07-24 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9f03d2e541b8"
down_revision: str | None = "7b1ac80518a7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("local_accounts", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "revision",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("1"),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("local_accounts", schema=None) as batch_op:
        batch_op.drop_column("revision")
