"""Add directed answer attachments.

Revision ID: f3a8c1e6d2b4
Revises: e2c7d9a4b6f1
Create Date: 2026-07-24 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f3a8c1e6d2b4"
down_revision: str | None = "e2c7d9a4b6f1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("report_attachments", schema=None) as batch_op:
        batch_op.add_column(sa.Column("directed_answer_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key(
            "fk_report_attachments_directed_answer_id_directed_answers",
            "directed_answers",
            ["directed_answer_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            batch_op.f("ix_report_attachments_directed_answer_id"),
            ["directed_answer_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("report_attachments", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_report_attachments_directed_answer_id"))
        batch_op.drop_constraint(
            "fk_report_attachments_directed_answer_id_directed_answers",
            type_="foreignkey",
        )
        batch_op.drop_column("directed_answer_id")
