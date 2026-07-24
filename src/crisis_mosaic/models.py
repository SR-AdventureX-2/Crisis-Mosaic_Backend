from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .utils import new_id, utcnow


class Base(DeclarativeBase):
    pass


class IdMixin:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Incident(Base, IdMixin, TimestampMixin):
    __tablename__ = "incidents"

    alias: Mapped[str | None] = mapped_column(String(80), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    type: Mapped[str] = mapped_column(String(40), default="flood")
    status: Mapped[str] = mapped_column(String(20), default="preparing", index=True)
    center_latitude: Mapped[float | None] = mapped_column(Float)
    center_longitude: Mapped[float | None] = mapped_column(Float)
    map_coordinate_system: Mapped[str] = mapped_column(String(12), default="gcj02")
    map_default_zoom: Mapped[float] = mapped_column(Float, default=12)
    timezone: Mapped[str] = mapped_column(String(50), default="Asia/Shanghai")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    feature_flags: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    event_sequence: Mapped[int] = mapped_column(Integer, default=0)
    data_revision: Mapped[int] = mapped_column(Integer, default=0)
    map_revision: Mapped[int] = mapped_column(Integer, default=0)


Index(
    "uq_incidents_single_active",
    Incident.status,
    unique=True,
    sqlite_where=Incident.status == "active",
)


class LocalAccount(Base, IdMixin, TimestampMixin):
    __tablename__ = "local_accounts"

    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(200), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class IncidentMembership(Base, IdMixin):
    __tablename__ = "incident_memberships"
    __table_args__ = (UniqueConstraint("account_id", "incident_id"),)

    account_id: Mapped[str] = mapped_column(ForeignKey("local_accounts.id", ondelete="CASCADE"))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    role: Mapped[str] = mapped_column(String(20))


class AnonymousDevice(Base, IdMixin):
    __tablename__ = "anonymous_devices"

    installation_id_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    platform: Mapped[str] = mapped_column(String(20))
    locale: Mapped[str | None] = mapped_column(String(20))
    region_code: Mapped[str | None] = mapped_column(String(40))
    token_version: Mapped[int] = mapped_column(Integer, default=1)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReporterContact(Base, IdMixin, TimestampMixin):
    __tablename__ = "reporter_contacts"

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    resident_device_id: Mapped[str] = mapped_column(ForeignKey("anonymous_devices.id"), index=True)
    full_name_ciphertext: Mapped[str] = mapped_column(Text)
    full_name_masked: Mapped[str] = mapped_column(String(100))
    mobile_ciphertext: Mapped[str] = mapped_column(Text)
    mobile_blind_index: Mapped[str] = mapped_column(String(64), index=True)
    mobile_masked: Mapped[str] = mapped_column(String(32))
    national_id_ciphertext: Mapped[str | None] = mapped_column(Text)
    national_id_blind_index: Mapped[str | None] = mapped_column(String(64), index=True)
    national_id_masked: Mapped[str | None] = mapped_column(String(32))
    emergency_name_ciphertext: Mapped[str | None] = mapped_column(Text)
    emergency_name_masked: Mapped[str | None] = mapped_column(String(100))
    emergency_mobile_ciphertext: Mapped[str | None] = mapped_column(Text)
    emergency_mobile_masked: Mapped[str | None] = mapped_column(String(32))
    emergency_relation_ciphertext: Mapped[str | None] = mapped_column(Text)
    emergency_relation_masked: Mapped[str | None] = mapped_column(String(100))
    rescue_notes_ciphertext: Mapped[str | None] = mapped_column(Text)
    encryption_key_version: Mapped[str] = mapped_column(String(40))
    consent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    retention_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    anonymized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RefreshSession(Base, IdMixin):
    __tablename__ = "refresh_sessions"

    subject_type: Mapped[str] = mapped_column(String(20), index=True)
    subject_id: Mapped[str] = mapped_column(String(36), index=True)
    incident_id: Mapped[str | None] = mapped_column(String(36), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    family_id: Mapped[str] = mapped_column(String(36), index=True)
    issued_token_version: Mapped[int] = mapped_column(Integer, default=1)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replaced_by_id: Mapped[str | None] = mapped_column(String(36))


class Report(Base, IdMixin, TimestampMixin):
    __tablename__ = "reports"

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    reporter_device_id: Mapped[str] = mapped_column(ForeignKey("anonymous_devices.id"), index=True)
    reporter_contact_id: Mapped[str | None] = mapped_column(
        ForeignKey("reporter_contacts.id"), index=True
    )
    category: Mapped[str] = mapped_column(String(20), index=True)
    content_original: Mapped[str] = mapped_column(Text)
    content_display: Mapped[str] = mapped_column(Text)
    location_text: Mapped[str] = mapped_column(String(300))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    location_wgs84_latitude: Mapped[float | None] = mapped_column(Float)
    location_wgs84_longitude: Mapped[float | None] = mapped_column(Float)
    location_gcj02_latitude: Mapped[float | None] = mapped_column(Float)
    location_gcj02_longitude: Mapped[float | None] = mapped_column(Float)
    location_accuracy_m: Mapped[float | None] = mapped_column(Float)
    location_source: Mapped[str] = mapped_column(String(20), default="manual")
    coordinate_system: Mapped[str | None] = mapped_column(String(12))
    location_provider: Mapped[str | None] = mapped_column(String(30))
    location_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    coordinate_algorithm_version: Mapped[str | None] = mapped_column(String(40))
    is_urgent: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    priority: Mapped[str] = mapped_column(String(12), default="medium", index=True)
    priority_source: Mapped[str] = mapped_column(String(30), default="category_default")
    manual_priority: Mapped[str | None] = mapped_column(String(12))
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    is_directed_answer: Mapped[bool] = mapped_column(Boolean, default=False)
    directed_answer_id: Mapped[str | None] = mapped_column(String(36))
    ai_refinement_id: Mapped[str | None] = mapped_column(String(36))
    attachment_count: Mapped[int] = mapped_column(Integer, default=0)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


Index("ix_reports_incident_updated", Report.incident_id, Report.updated_at)
Index(
    "ix_reports_incident_priority_updated",
    Report.incident_id,
    Report.priority,
    Report.updated_at,
)


class ReportRevision(Base, IdMixin):
    __tablename__ = "report_revisions"
    __table_args__ = (UniqueConstraint("report_id", "revision"),)

    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id", ondelete="CASCADE"))
    revision: Mapped[int] = mapped_column(Integer)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    changed_by_type: Mapped[str] = mapped_column(String(20))
    changed_by_id: Mapped[str | None] = mapped_column(String(36))
    change_reason: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Attachment(Base, IdMixin):
    __tablename__ = "report_attachments"

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    report_id: Mapped[str | None] = mapped_column(ForeignKey("reports.id"), index=True)
    directed_answer_id: Mapped[str | None] = mapped_column(
        ForeignKey("directed_answers.id", ondelete="SET NULL"), index=True
    )
    uploader_device_id: Mapped[str] = mapped_column(ForeignKey("anonymous_devices.id"))
    file_name: Mapped[str] = mapped_column(String(255))
    declared_mime_type: Mapped[str] = mapped_column(String(80))
    media_type: Mapped[str] = mapped_column(String(20), default="image", index=True)
    client_source: Mapped[str | None] = mapped_column(String(20))
    storage_provider: Mapped[str] = mapped_column(String(40), default="local_proxy", index=True)
    bucket: Mapped[str | None] = mapped_column(String(120))
    object_key: Mapped[str | None] = mapped_column(String(500), index=True)
    etag: Mapped[str | None] = mapped_column(String(120))
    mime_type: Mapped[str | None] = mapped_column(String(80))
    size_bytes: Mapped[int] = mapped_column(Integer)
    expected_sha256: Mapped[str] = mapped_column(String(64))
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    perceptual_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    duplicate_of_attachment_id: Mapped[str | None] = mapped_column(String(36))
    source_cluster_id: Mapped[str | None] = mapped_column(String(36), index=True)
    original_path: Mapped[str | None] = mapped_column(String(500))
    sanitized_path: Mapped[str | None] = mapped_column(String(500))
    thumbnail_path: Mapped[str | None] = mapped_column(String(500))
    width: Mapped[int | None] = mapped_column(Integer)
    height: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    cover_path: Mapped[str | None] = mapped_column(String(500))
    preview_path: Mapped[str | None] = mapped_column(String(500))
    transcript_status: Mapped[str | None] = mapped_column(String(20))
    transcript_text: Mapped[str | None] = mapped_column(Text)
    transcode_status: Mapped[str | None] = mapped_column(String(20))
    keyframe_status: Mapped[str | None] = mapped_column(String(20))
    processing_progress: Mapped[int] = mapped_column(Integer, default=0)
    policy_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    captured_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exif_data: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    metadata_status: Mapped[str] = mapped_column(String(20), default="pending")
    malware_scan_status: Mapped[str] = mapped_column(String(20), default="pending")
    ocr_status: Mapped[str] = mapped_column(String(20), default="pending")
    vision_status: Mapped[str] = mapped_column(String(20), default="pending")
    ocr_text: Mapped[str | None] = mapped_column(Text)
    vision_summary: Mapped[str | None] = mapped_column(Text)
    rejection_reason: Mapped[str | None] = mapped_column(String(300))
    upload_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    uploaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MediaUploadSession(Base, IdMixin, TimestampMixin):
    __tablename__ = "media_upload_sessions"
    __table_args__ = (UniqueConstraint("attachment_id", "client_checkpoint_id"),)

    attachment_id: Mapped[str] = mapped_column(
        ForeignKey("report_attachments.id", ondelete="CASCADE"), index=True
    )
    resident_device_id: Mapped[str] = mapped_column(ForeignKey("anonymous_devices.id"), index=True)
    provider: Mapped[str] = mapped_column(String(40), default="qiniu_kodo_mock")
    mode: Mapped[str] = mapped_column(String(20), default="resumable")
    object_key: Mapped[str] = mapped_column(String(500), index=True)
    upload_token_fingerprint: Mapped[str] = mapped_column(String(16))
    token_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    chunk_size_bytes: Mapped[int] = mapped_column(Integer)
    max_parallel_uploads: Mapped[int] = mapped_column(Integer)
    expected_size_bytes: Mapped[int] = mapped_column(Integer)
    expected_sha256: Mapped[str] = mapped_column(String(64))
    confirmed_bytes: Mapped[int] = mapped_column(Integer, default=0)
    client_checkpoint_id: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    aborted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MediaUploadPart(Base, IdMixin, TimestampMixin):
    __tablename__ = "media_upload_parts"
    __table_args__ = (UniqueConstraint("upload_session_id", "part_number"),)

    upload_session_id: Mapped[str] = mapped_column(
        ForeignKey("media_upload_sessions.id", ondelete="CASCADE"), index=True
    )
    part_number: Mapped[int] = mapped_column(Integer)
    offset: Mapped[int] = mapped_column(Integer)
    size_bytes: Mapped[int] = mapped_column(Integer)
    etag: Mapped[str] = mapped_column(String(120))
    sha256: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="confirmed")


class BlindSpot(Base, IdMixin, TimestampMixin):
    __tablename__ = "blind_spots"

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    claim_key: Mapped[str] = mapped_column(String(100), index=True)
    title: Mapped[str] = mapped_column(String(200))
    location_text: Mapped[str] = mapped_column(String(300))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    coordinate_system: Mapped[str | None] = mapped_column(String(12))
    scope_type: Mapped[str] = mapped_column(String(20), default="incident")
    scope_data: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    severity: Mapped[str] = mapped_column(String(12), default="medium")
    route_impact_count: Mapped[int] = mapped_column(Integer, default=0)
    min_valid_answers: Mapped[int] = mapped_column(Integer, default=2)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    resolution_value: Mapped[str | None] = mapped_column(String(100))
    revision: Mapped[int] = mapped_column(Integer, default=1)


class DirectedQuestion(Base, IdMixin, TimestampMixin):
    __tablename__ = "directed_questions"

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    blind_spot_id: Mapped[str] = mapped_column(ForeignKey("blind_spots.id"), index=True)
    title: Mapped[str] = mapped_column(String(200))
    location_text: Mapped[str] = mapped_column(String(300))
    target_geometry: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    route_impact_count: Mapped[int] = mapped_column(Integer, default=0)
    answer_type: Mapped[str] = mapped_column(String(30), default="single_choice")
    options: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="draft", index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(36))
    revision: Mapped[int] = mapped_column(Integer, default=1)


class DirectedAnswer(Base, IdMixin, TimestampMixin):
    __tablename__ = "directed_answers"
    __table_args__ = (UniqueConstraint("question_id", "device_id"),)

    question_id: Mapped[str] = mapped_column(ForeignKey("directed_questions.id"))
    device_id: Mapped[str] = mapped_column(ForeignKey("anonymous_devices.id"))
    option_id: Mapped[str] = mapped_column(String(80))
    semantic_value: Mapped[str] = mapped_column(String(100))
    answer_text: Mapped[str] = mapped_column(String(300))
    observed_latitude: Mapped[float | None] = mapped_column(Float)
    observed_longitude: Mapped[float | None] = mapped_column(Float)
    observed_coordinate_system: Mapped[str | None] = mapped_column(String(12))
    revision: Mapped[int] = mapped_column(Integer, default=1)


class DirectedAnswerRevision(Base, IdMixin):
    __tablename__ = "directed_answer_revisions"
    __table_args__ = (UniqueConstraint("answer_id", "revision"),)

    answer_id: Mapped[str] = mapped_column(ForeignKey("directed_answers.id"))
    revision: Mapped[int] = mapped_column(Integer)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InformationFragment(Base, IdMixin, TimestampMixin):
    __tablename__ = "information_fragments"

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    source_type: Mapped[str] = mapped_column(String(30))
    source_ref_id: Mapped[str | None] = mapped_column(String(36), index=True)
    source_cluster_id: Mapped[str | None] = mapped_column(String(36))
    topic: Mapped[str] = mapped_column(String(60), index=True)
    claim_key: Mapped[str | None] = mapped_column(String(100), index=True)
    claim_value: Mapped[str | None] = mapped_column(String(100))
    label: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text)
    location_text: Mapped[str] = mapped_column(String(300))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    coordinate_system: Mapped[str | None] = mapped_column(String(12))
    shape: Mapped[str] = mapped_column(String(20), default="circle")
    status: Mapped[str] = mapped_column(String(20), default="normal", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class ConflictCase(Base, IdMixin, TimestampMixin):
    __tablename__ = "conflict_cases"

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    alias: Mapped[str | None] = mapped_column(String(100), unique=True)
    fact_key: Mapped[str] = mapped_column(String(120), index=True)
    title: Mapped[str] = mapped_column(String(200))
    topic: Mapped[str] = mapped_column(String(60))
    location_text: Mapped[str] = mapped_column(String(300))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    coordinate_system: Mapped[str | None] = mapped_column(String(12))
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    severity: Mapped[str] = mapped_column(String(12), default="medium")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolution: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    resolved_by: Mapped[str | None] = mapped_column(String(36))
    revision: Mapped[int] = mapped_column(Integer, default=1)


class ConflictEvidence(Base, IdMixin):
    __tablename__ = "conflict_evidence"
    __table_args__ = (UniqueConstraint("conflict_id", "kind", "source_id", "source_revision"),)

    conflict_id: Mapped[str] = mapped_column(ForeignKey("conflict_cases.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    source_id: Mapped[str] = mapped_column(String(36))
    source_revision: Mapped[int] = mapped_column(Integer)
    source_cluster_id: Mapped[str | None] = mapped_column(String(36))
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AiAnalysis(Base, IdMixin):
    __tablename__ = "ai_analyses"

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    analysis_type: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    input_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    context_package: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    context_sha256: Mapped[str | None] = mapped_column(String(64))
    output: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    confidence: Mapped[float | None] = mapped_column(Float)
    model_provider: Mapped[str | None] = mapped_column(String(80))
    model_name: Mapped[str | None] = mapped_column(String(120))
    prompt_version: Mapped[str] = mapped_column(String(40))
    prompt_sha256: Mapped[str | None] = mapped_column(String(64))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    schema_valid: Mapped[bool | None] = mapped_column(Boolean)
    reference_valid: Mapped[bool | None] = mapped_column(Boolean)
    error_code: Mapped[str | None] = mapped_column(String(80))
    error_message: Mapped[str | None] = mapped_column(String(300))
    created_by_type: Mapped[str] = mapped_column(String(20))
    created_by_id: Mapped[str | None] = mapped_column(String(36))
    input_version: Mapped[int] = mapped_column(Integer, default=0)
    data_as_of: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_stale: Mapped[bool] = mapped_column(Boolean, default=False)
    stale_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stale_reason: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AiJobStep(Base, IdMixin):
    __tablename__ = "ai_job_steps"

    analysis_id: Mapped[str] = mapped_column(ForeignKey("ai_analyses.id"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(20), default="queued")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(80))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class ConflictDecision(Base, IdMixin):
    __tablename__ = "conflict_decisions"

    conflict_id: Mapped[str] = mapped_column(ForeignKey("conflict_cases.id"), index=True)
    conflict_revision: Mapped[int] = mapped_column(Integer)
    analysis_id: Mapped[str | None] = mapped_column(ForeignKey("ai_analyses.id"))
    evidence_decisions: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    conclusion: Mapped[str] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FactRecord(Base, IdMixin, TimestampMixin):
    __tablename__ = "incident_fact_records"
    __table_args__ = (UniqueConstraint("incident_id", "fact_key"),)

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    fact_key: Mapped[str] = mapped_column(String(120))
    topic: Mapped[str] = mapped_column(String(60))
    location_text: Mapped[str] = mapped_column(String(300))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    coordinate_system: Mapped[str | None] = mapped_column(String(12))
    current_version_id: Mapped[str | None] = mapped_column(String(36))
    current_revision: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(30), default="current", index=True)
    is_public: Mapped[bool] = mapped_column(Boolean, default=True)


class FactVersion(Base, IdMixin):
    __tablename__ = "incident_fact_versions"
    __table_args__ = (UniqueConstraint("fact_record_id", "revision"),)

    fact_record_id: Mapped[str] = mapped_column(ForeignKey("incident_fact_records.id"))
    previous_version_id: Mapped[str | None] = mapped_column(String(36))
    revision: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(30))
    statement: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Float)
    source_conflict_id: Mapped[str | None] = mapped_column(String(36))
    source_analysis_id: Mapped[str | None] = mapped_column(String(36))
    context_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    accepted_evidence_ids: Mapped[list[str]] = mapped_column(JSON)
    decision_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base, IdMixin):
    __tablename__ = "audit_logs"

    incident_id: Mapped[str | None] = mapped_column(String(36), index=True)
    actor_type: Mapped[str] = mapped_column(String(20))
    actor_id: Mapped[str | None] = mapped_column(String(36))
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(String(36))
    request_id: Mapped[str | None] = mapped_column(String(80))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IdempotencyRecord(Base, IdMixin):
    __tablename__ = "idempotency_records"
    __table_args__ = (UniqueConstraint("actor_key", "route", "idempotency_key"),)

    actor_key: Mapped[str] = mapped_column(String(100))
    route: Mapped[str] = mapped_column(String(200))
    idempotency_key: Mapped[str] = mapped_column(String(200))
    request_hash: Mapped[str] = mapped_column(String(64))
    response_status: Mapped[int] = mapped_column(Integer)
    response_body: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class BackgroundJob(Base, IdMixin):
    __tablename__ = "background_jobs"

    job_type: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    run_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class OutboxEvent(Base, IdMixin):
    __tablename__ = "outbox_events"
    __table_args__ = (UniqueConstraint("incident_id", "sequence"),)

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    visibility: Mapped[str] = mapped_column(String(20), default="operators")
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(String(36))
    resource_revision: Mapped[int | None] = mapped_column(Integer)
    actor_type: Mapped[str | None] = mapped_column(String(20))
    owner_device_id: Mapped[str | None] = mapped_column(String(36))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    request_id: Mapped[str | None] = mapped_column(String(80))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    publish_attempts: Mapped[int] = mapped_column(Integer, default=0)


class PushDevice(Base, IdMixin, TimestampMixin):
    __tablename__ = "push_devices"
    __table_args__ = (
        UniqueConstraint("operator_id", "provider", "provider_token_hash"),
        UniqueConstraint("operator_id", "installation_id_hash", "provider"),
    )

    operator_id: Mapped[str] = mapped_column(ForeignKey("local_accounts.id"), index=True)
    installation_id_hash: Mapped[str] = mapped_column(String(64), index=True)
    platform: Mapped[str] = mapped_column(String(20), index=True)
    provider: Mapped[str] = mapped_column(String(40), index=True)
    provider_token_ciphertext: Mapped[str] = mapped_column(Text)
    provider_token_hash: Mapped[str] = mapped_column(String(64), index=True)
    token_fingerprint: Mapped[str] = mapped_column(String(16))
    app_id: Mapped[str] = mapped_column(String(160))
    environment: Mapped[str] = mapped_column(String(20), default="dev")
    authorization_status: Mapped[str] = mapped_column(String(30), default="authorized")
    route_priority: Mapped[int] = mapped_column(Integer, default=1)
    app_version: Mapped[str | None] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(120))


class NotificationPreference(Base, IdMixin, TimestampMixin):
    __tablename__ = "notification_preferences"
    __table_args__ = (UniqueConstraint("operator_id", "incident_id"),)

    operator_id: Mapped[str] = mapped_column(ForeignKey("local_accounts.id"), index=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    minimum_priority: Mapped[str] = mapped_column(String(12), default="high")
    event_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    quiet_hours: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class NotificationOutbox(Base, IdMixin, TimestampMixin):
    __tablename__ = "notification_outbox"
    __table_args__ = (UniqueConstraint("dedupe_key", "recipient_operator_id"),)

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    recipient_operator_id: Mapped[str] = mapped_column(ForeignKey("local_accounts.id"), index=True)
    business_event_id: Mapped[str] = mapped_column(String(36), index=True)
    dedupe_key: Mapped[str] = mapped_column(String(160), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    priority: Mapped[str] = mapped_column(String(12), default="high", index=True)
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(String(36))
    resource_revision: Mapped[int | None] = mapped_column(Integer)
    deep_link: Mapped[str | None] = mapped_column(String(300))
    title: Mapped[str] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(String(240))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    run_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(80))


class NotificationDelivery(Base, IdMixin, TimestampMixin):
    __tablename__ = "notification_deliveries"
    __table_args__ = (UniqueConstraint("notification_outbox_id", "push_device_id"),)

    notification_outbox_id: Mapped[str] = mapped_column(
        ForeignKey("notification_outbox.id", ondelete="CASCADE"), index=True
    )
    push_device_id: Mapped[str] = mapped_column(ForeignKey("push_devices.id"), index=True)
    provider: Mapped[str] = mapped_column(String(40))
    provider_message_id: Mapped[str | None] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(80))
    provider_response: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    clicked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class NotificationReceipt(Base, IdMixin, TimestampMixin):
    __tablename__ = "notification_receipts"
    __table_args__ = (
        UniqueConstraint("notification_outbox_id", "receipt_type", "installation_id_hash"),
    )

    notification_outbox_id: Mapped[str] = mapped_column(
        ForeignKey("notification_outbox.id", ondelete="CASCADE"), index=True
    )
    receipt_type: Mapped[str] = mapped_column(String(20), index=True)
    installation_id_hash: Mapped[str] = mapped_column(String(64), index=True)
    app_state: Mapped[str | None] = mapped_column(String(20))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MapFeature(Base, IdMixin, TimestampMixin):
    __tablename__ = "map_features"
    __table_args__ = (UniqueConstraint("incident_id", "kind", "source_ref"),)

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    source_ref: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(30))
    severity: Mapped[str] = mapped_column(String(12), default="medium")
    latitude_wgs84: Mapped[float | None] = mapped_column(Float, index=True)
    longitude_wgs84: Mapped[float | None] = mapped_column(Float, index=True)
    latitude_gcj02: Mapped[float | None] = mapped_column(Float)
    longitude_gcj02: Mapped[float | None] = mapped_column(Float)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    public_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    private_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
