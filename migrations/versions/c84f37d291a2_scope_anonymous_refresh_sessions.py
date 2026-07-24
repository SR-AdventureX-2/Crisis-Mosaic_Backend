"""Scope anonymous refresh sessions to their issuing incident.

Revision ID: c84f37d291a2
Revises: 9f03d2e541b8
Create Date: 2026-07-24 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c84f37d291a2"
down_revision: str | None = "9f03d2e541b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("refresh_sessions", schema=None) as batch_op:
        batch_op.add_column(sa.Column("incident_id", sa.String(length=36), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_refresh_sessions_incident_id"),
            ["incident_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("refresh_sessions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_refresh_sessions_incident_id"))
        batch_op.drop_column("incident_id")
