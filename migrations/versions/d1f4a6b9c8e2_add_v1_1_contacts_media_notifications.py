"""Add V1.1 contacts, media sessions, and notifications.

Revision ID: d1f4a6b9c8e2
Revises: c84f37d291a2
Create Date: 2026-07-24 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d1f4a6b9c8e2"
down_revision: str | None = "c84f37d291a2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "reporter_contacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("resident_device_id", sa.String(length=36), nullable=False),
        sa.Column("full_name_ciphertext", sa.Text(), nullable=False),
        sa.Column("full_name_masked", sa.String(length=100), nullable=False),
        sa.Column("mobile_ciphertext", sa.Text(), nullable=False),
        sa.Column("mobile_blind_index", sa.String(length=64), nullable=False),
        sa.Column("mobile_masked", sa.String(length=32), nullable=False),
        sa.Column("national_id_ciphertext", sa.Text(), nullable=True),
        sa.Column("national_id_blind_index", sa.String(length=64), nullable=True),
        sa.Column("national_id_masked", sa.String(length=32), nullable=True),
        sa.Column("emergency_name_ciphertext", sa.Text(), nullable=True),
        sa.Column("emergency_name_masked", sa.String(length=100), nullable=True),
        sa.Column("emergency_mobile_ciphertext", sa.Text(), nullable=True),
        sa.Column("emergency_mobile_masked", sa.String(length=32), nullable=True),
        sa.Column("emergency_relation_ciphertext", sa.Text(), nullable=True),
        sa.Column("emergency_relation_masked", sa.String(length=100), nullable=True),
        sa.Column("rescue_notes_ciphertext", sa.Text(), nullable=True),
        sa.Column("encryption_key_version", sa.String(length=40), nullable=False),
        sa.Column("consent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retention_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("legal_hold", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("anonymized_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["resident_device_id"], ["anonymous_devices.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_reporter_contacts_incident_id"),
        "reporter_contacts",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_reporter_contacts_resident_device_id"),
        "reporter_contacts",
        ["resident_device_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_reporter_contacts_mobile_blind_index"),
        "reporter_contacts",
        ["mobile_blind_index"],
        unique=False,
    )
    op.create_index(
        op.f("ix_reporter_contacts_national_id_blind_index"),
        "reporter_contacts",
        ["national_id_blind_index"],
        unique=False,
    )
    op.create_index(
        op.f("ix_reporter_contacts_retention_until"),
        "reporter_contacts",
        ["retention_until"],
        unique=False,
    )
    op.create_index(
        op.f("ix_reporter_contacts_legal_hold"),
        "reporter_contacts",
        ["legal_hold"],
        unique=False,
    )

    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.add_column(sa.Column("reporter_contact_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key(
            "fk_reports_reporter_contact_id_reporter_contacts",
            "reporter_contacts",
            ["reporter_contact_id"],
            ["id"],
        )
        batch_op.create_index(
            batch_op.f("ix_reports_reporter_contact_id"),
            ["reporter_contact_id"],
            unique=False,
        )

    with op.batch_alter_table("report_attachments", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("media_type", sa.String(length=20), nullable=False, server_default="image")
        )
        batch_op.add_column(sa.Column("client_source", sa.String(length=20), nullable=True))
        batch_op.add_column(
            sa.Column(
                "storage_provider",
                sa.String(length=40),
                nullable=False,
                server_default="local_proxy",
            )
        )
        batch_op.add_column(sa.Column("bucket", sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column("object_key", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("etag", sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column("duration_ms", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("cover_path", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("preview_path", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("transcript_status", sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column("transcript_text", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("transcode_status", sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column("keyframe_status", sa.String(length=20), nullable=True))
        batch_op.add_column(
            sa.Column("processing_progress", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(sa.Column("policy_snapshot", sa.JSON(), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_report_attachments_media_type"), ["media_type"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_report_attachments_storage_provider"),
            ["storage_provider"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_report_attachments_object_key"), ["object_key"], unique=False
        )

    op.create_table(
        "media_upload_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attachment_id", sa.String(length=36), nullable=False),
        sa.Column("resident_device_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("mode", sa.String(length=20), nullable=False),
        sa.Column("object_key", sa.String(length=500), nullable=False),
        sa.Column("upload_token_fingerprint", sa.String(length=16), nullable=False),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("chunk_size_bytes", sa.Integer(), nullable=False),
        sa.Column("max_parallel_uploads", sa.Integer(), nullable=False),
        sa.Column("expected_size_bytes", sa.Integer(), nullable=False),
        sa.Column("expected_sha256", sa.String(length=64), nullable=False),
        sa.Column("confirmed_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("client_checkpoint_id", sa.String(length=120), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("policy_snapshot", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("aborted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["attachment_id"], ["report_attachments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["resident_device_id"], ["anonymous_devices.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("attachment_id", "client_checkpoint_id"),
    )
    op.create_index(
        op.f("ix_media_upload_sessions_attachment_id"),
        "media_upload_sessions",
        ["attachment_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_media_upload_sessions_resident_device_id"),
        "media_upload_sessions",
        ["resident_device_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_media_upload_sessions_object_key"),
        "media_upload_sessions",
        ["object_key"],
        unique=False,
    )
    op.create_index(
        op.f("ix_media_upload_sessions_status"),
        "media_upload_sessions",
        ["status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_media_upload_sessions_expires_at"),
        "media_upload_sessions",
        ["expires_at"],
        unique=False,
    )

    op.create_table(
        "media_upload_parts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("upload_session_id", sa.String(length=36), nullable=False),
        sa.Column("part_number", sa.Integer(), nullable=False),
        sa.Column("offset", sa.Integer(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("etag", sa.String(length=120), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.ForeignKeyConstraint(
            ["upload_session_id"], ["media_upload_sessions.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("upload_session_id", "part_number"),
    )
    op.create_index(
        op.f("ix_media_upload_parts_upload_session_id"),
        "media_upload_parts",
        ["upload_session_id"],
        unique=False,
    )

    op.create_table(
        "push_devices",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("operator_id", sa.String(length=36), nullable=False),
        sa.Column("installation_id_hash", sa.String(length=64), nullable=False),
        sa.Column("platform", sa.String(length=20), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("provider_token_ciphertext", sa.Text(), nullable=False),
        sa.Column("provider_token_hash", sa.String(length=64), nullable=False),
        sa.Column("token_fingerprint", sa.String(length=16), nullable=False),
        sa.Column("app_id", sa.String(length=160), nullable=False),
        sa.Column("environment", sa.String(length=20), nullable=False),
        sa.Column("authorization_status", sa.String(length=30), nullable=False),
        sa.Column("route_priority", sa.Integer(), nullable=False),
        sa.Column("app_version", sa.String(length=40), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(length=120), nullable=True),
        sa.ForeignKeyConstraint(["operator_id"], ["local_accounts.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operator_id", "provider", "provider_token_hash"),
        sa.UniqueConstraint("operator_id", "installation_id_hash", "provider"),
    )
    for column in (
        "operator_id",
        "installation_id_hash",
        "platform",
        "provider",
        "provider_token_hash",
        "status",
        "revoked_at",
    ):
        op.create_index(op.f(f"ix_push_devices_{column}"), "push_devices", [column], unique=False)

    op.create_table(
        "notification_preferences",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("operator_id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("minimum_priority", sa.String(length=12), nullable=False),
        sa.Column("event_types", sa.JSON(), nullable=False),
        sa.Column("quiet_hours", sa.JSON(), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["operator_id"], ["local_accounts.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operator_id", "incident_id"),
    )
    op.create_index(
        op.f("ix_notification_preferences_operator_id"),
        "notification_preferences",
        ["operator_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_preferences_incident_id"),
        "notification_preferences",
        ["incident_id"],
        unique=False,
    )

    op.create_table(
        "notification_outbox",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("recipient_operator_id", sa.String(length=36), nullable=False),
        sa.Column("business_event_id", sa.String(length=36), nullable=False),
        sa.Column("dedupe_key", sa.String(length=160), nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("priority", sa.String(length=12), nullable=False),
        sa.Column("resource_type", sa.String(length=50), nullable=False),
        sa.Column("resource_id", sa.String(length=36), nullable=True),
        sa.Column("resource_revision", sa.Integer(), nullable=True),
        sa.Column("deep_link", sa.String(length=300), nullable=True),
        sa.Column("title", sa.String(length=120), nullable=False),
        sa.Column("body", sa.String(length=240), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("run_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=80), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["recipient_operator_id"], ["local_accounts.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedupe_key", "recipient_operator_id"),
    )
    for column in (
        "incident_id",
        "recipient_operator_id",
        "business_event_id",
        "dedupe_key",
        "event_type",
        "priority",
        "status",
        "expires_at",
    ):
        op.create_index(
            op.f(f"ix_notification_outbox_{column}"),
            "notification_outbox",
            [column],
            unique=False,
        )

    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notification_outbox_id", sa.String(length=36), nullable=False),
        sa.Column("push_device_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("provider_message_id", sa.String(length=160), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("provider_response", sa.JSON(), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("clicked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["notification_outbox_id"], ["notification_outbox.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["push_device_id"], ["push_devices.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("notification_outbox_id", "push_device_id"),
    )
    op.create_index(
        op.f("ix_notification_deliveries_notification_outbox_id"),
        "notification_deliveries",
        ["notification_outbox_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_deliveries_push_device_id"),
        "notification_deliveries",
        ["push_device_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_deliveries_status"),
        "notification_deliveries",
        ["status"],
        unique=False,
    )

    op.create_table(
        "notification_receipts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notification_outbox_id", sa.String(length=36), nullable=False),
        sa.Column("receipt_type", sa.String(length=20), nullable=False),
        sa.Column("installation_id_hash", sa.String(length=64), nullable=False),
        sa.Column("app_state", sa.String(length=20), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["notification_outbox_id"], ["notification_outbox.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("notification_outbox_id", "receipt_type", "installation_id_hash"),
    )
    op.create_index(
        op.f("ix_notification_receipts_notification_outbox_id"),
        "notification_receipts",
        ["notification_outbox_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_receipts_receipt_type"),
        "notification_receipts",
        ["receipt_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_receipts_installation_id_hash"),
        "notification_receipts",
        ["installation_id_hash"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_notification_receipts_installation_id_hash"), table_name="notification_receipts")
    op.drop_index(op.f("ix_notification_receipts_receipt_type"), table_name="notification_receipts")
    op.drop_index(
        op.f("ix_notification_receipts_notification_outbox_id"),
        table_name="notification_receipts",
    )
    op.drop_table("notification_receipts")

    op.drop_index(op.f("ix_notification_deliveries_status"), table_name="notification_deliveries")
    op.drop_index(op.f("ix_notification_deliveries_push_device_id"), table_name="notification_deliveries")
    op.drop_index(
        op.f("ix_notification_deliveries_notification_outbox_id"),
        table_name="notification_deliveries",
    )
    op.drop_table("notification_deliveries")

    for column in reversed(
        (
            "incident_id",
            "recipient_operator_id",
            "business_event_id",
            "dedupe_key",
            "event_type",
            "priority",
            "status",
            "expires_at",
        )
    ):
        op.drop_index(op.f(f"ix_notification_outbox_{column}"), table_name="notification_outbox")
    op.drop_table("notification_outbox")

    op.drop_index(
        op.f("ix_notification_preferences_incident_id"),
        table_name="notification_preferences",
    )
    op.drop_index(
        op.f("ix_notification_preferences_operator_id"),
        table_name="notification_preferences",
    )
    op.drop_table("notification_preferences")

    for column in reversed(
        (
            "operator_id",
            "installation_id_hash",
            "platform",
            "provider",
            "provider_token_hash",
            "status",
            "revoked_at",
        )
    ):
        op.drop_index(op.f(f"ix_push_devices_{column}"), table_name="push_devices")
    op.drop_table("push_devices")

    op.drop_index(op.f("ix_media_upload_parts_upload_session_id"), table_name="media_upload_parts")
    op.drop_table("media_upload_parts")

    op.drop_index(op.f("ix_media_upload_sessions_expires_at"), table_name="media_upload_sessions")
    op.drop_index(op.f("ix_media_upload_sessions_status"), table_name="media_upload_sessions")
    op.drop_index(op.f("ix_media_upload_sessions_object_key"), table_name="media_upload_sessions")
    op.drop_index(
        op.f("ix_media_upload_sessions_resident_device_id"),
        table_name="media_upload_sessions",
    )
    op.drop_index(
        op.f("ix_media_upload_sessions_attachment_id"),
        table_name="media_upload_sessions",
    )
    op.drop_table("media_upload_sessions")

    with op.batch_alter_table("report_attachments", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_report_attachments_object_key"))
        batch_op.drop_index(batch_op.f("ix_report_attachments_storage_provider"))
        batch_op.drop_index(batch_op.f("ix_report_attachments_media_type"))
        for column in (
            "policy_snapshot",
            "processing_progress",
            "keyframe_status",
            "transcode_status",
            "transcript_text",
            "transcript_status",
            "preview_path",
            "cover_path",
            "duration_ms",
            "etag",
            "object_key",
            "bucket",
            "storage_provider",
            "client_source",
            "media_type",
        ):
            batch_op.drop_column(column)

    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_reports_reporter_contact_id"))
        batch_op.drop_constraint(
            "fk_reports_reporter_contact_id_reporter_contacts",
            type_="foreignkey",
        )
        batch_op.drop_column("reporter_contact_id")

    op.drop_index(op.f("ix_reporter_contacts_legal_hold"), table_name="reporter_contacts")
    op.drop_index(op.f("ix_reporter_contacts_retention_until"), table_name="reporter_contacts")
    op.drop_index(
        op.f("ix_reporter_contacts_national_id_blind_index"),
        table_name="reporter_contacts",
    )
    op.drop_index(
        op.f("ix_reporter_contacts_mobile_blind_index"),
        table_name="reporter_contacts",
    )
    op.drop_index(
        op.f("ix_reporter_contacts_resident_device_id"),
        table_name="reporter_contacts",
    )
    op.drop_index(op.f("ix_reporter_contacts_incident_id"), table_name="reporter_contacts")
    op.drop_table("reporter_contacts")
