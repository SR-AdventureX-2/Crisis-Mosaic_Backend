from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.sql.elements import ColumnElement

from ..config import Settings, get_settings
from ..db import session_factory, write_lock
from ..models import (
    AiAnalysis,
    Attachment,
    AuditLog,
    ConflictCase,
    ConflictEvidence,
    DirectedAnswer,
    DirectedAnswerRevision,
    DirectedQuestion,
    IdempotencyRecord,
    Incident,
    InformationFragment,
    MapFeature,
    OutboxEvent,
    RefreshSession,
    Report,
    ReporterContact,
    ReportRevision,
)
from ..utils import canonical_json, sha256_text, utcnow

logger = logging.getLogger(__name__)

RETENTION_MARKER = "[retention-expired]"
RETENTION_REASON = "RETENTION_EXPIRED"


@dataclass(slots=True)
class RetentionCleanupResult:
    idempotency_records_deleted: int = 0
    refresh_sessions_deleted: int = 0
    outbox_events_deleted: int = 0
    audit_logs_deleted: int = 0
    incidents_anonymized: int = 0
    reports_anonymized: int = 0
    reporter_contacts_anonymized: int = 0
    report_revisions_anonymized: int = 0
    attachments_anonymized: int = 0
    directed_answers_anonymized: int = 0
    answer_revisions_anonymized: int = 0
    fragments_anonymized: int = 0
    conflict_evidence_anonymized: int = 0
    ai_analyses_anonymized: int = 0
    map_features_removed: int = 0
    files_deleted: int = 0
    unsafe_storage_paths_skipped: int = 0

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


async def _delete_selected(
    session: AsyncSession,
    model: type[Any],
    predicate: ColumnElement[bool],
) -> int:
    ids = list((await session.scalars(select(model.id).where(predicate))).all())
    if ids:
        await session.execute(delete(model).where(model.id.in_(ids)))
    return len(ids)


def _safe_storage_file(path_value: str | Path, storage_root: Path) -> Path | None:
    root = storage_root.resolve()
    raw_path = Path(path_value)
    candidate = raw_path.resolve()
    if candidate == root or root not in candidate.parents:
        return None
    return candidate


async def _remove_attachment_files(
    attachments: list[Attachment],
    storage_root: Path,
    result: RetentionCleanupResult,
) -> None:
    candidates: set[Path] = set()
    for attachment in attachments:
        stored_paths = (
            attachment.original_path,
            attachment.sanitized_path,
            attachment.thumbnail_path,
            storage_root / "quarantine" / f"{attachment.id}.upload",
        )
        for path_value in stored_paths:
            if path_value is None:
                continue
            candidate = _safe_storage_file(path_value, storage_root)
            if candidate is None:
                result.unsafe_storage_paths_skipped += 1
                logger.warning(
                    "retention skipped attachment path outside storage root",
                    extra={"attachment_id": attachment.id},
                )
                continue
            candidates.add(candidate)

    for candidate in candidates:
        if not candidate.exists():
            continue
        if not candidate.is_file():
            result.unsafe_storage_paths_skipped += 1
            logger.warning("retention skipped non-file storage path")
            continue
        await asyncio.to_thread(candidate.unlink, missing_ok=True)
        result.files_deleted += 1


def _anonymize_report(report: Report, now: datetime) -> bool:
    already_anonymized = (
        report.deleted_at is not None
        and report.content_original == RETENTION_MARKER
        and report.content_display == RETENTION_MARKER
    )
    report.content_original = RETENTION_MARKER
    report.content_display = RETENTION_MARKER
    report.location_text = RETENTION_MARKER
    report.latitude = None
    report.longitude = None
    report.location_wgs84_latitude = None
    report.location_wgs84_longitude = None
    report.location_gcj02_latitude = None
    report.location_gcj02_longitude = None
    report.location_accuracy_m = None
    report.location_source = "retention"
    report.coordinate_system = None
    report.location_provider = None
    report.location_observed_at = None
    report.coordinate_algorithm_version = None
    report.ai_refinement_id = None
    report.deleted_at = report.deleted_at or now
    return not already_anonymized


def _anonymize_attachment(attachment: Attachment) -> bool:
    already_anonymized = (
        attachment.rejection_reason == RETENTION_REASON
        and attachment.original_path is None
        and attachment.sanitized_path is None
        and attachment.thumbnail_path is None
    )
    attachment.file_name = RETENTION_MARKER
    attachment.mime_type = None
    attachment.size_bytes = 0
    attachment.expected_sha256 = "0" * 64
    attachment.sha256 = None
    attachment.perceptual_hash = None
    attachment.duplicate_of_attachment_id = None
    attachment.source_cluster_id = None
    attachment.original_path = None
    attachment.sanitized_path = None
    attachment.thumbnail_path = None
    attachment.bucket = None
    attachment.object_key = None
    attachment.etag = None
    attachment.width = None
    attachment.height = None
    attachment.duration_ms = None
    attachment.cover_path = None
    attachment.preview_path = None
    attachment.captured_at = None
    attachment.exif_data = None
    attachment.metadata_status = "expired"
    attachment.malware_scan_status = "expired"
    attachment.ocr_status = "expired"
    attachment.vision_status = "expired"
    attachment.ocr_text = None
    attachment.vision_summary = None
    attachment.transcript_status = "expired"
    attachment.transcript_text = None
    attachment.transcode_status = "expired"
    attachment.keyframe_status = "expired"
    attachment.policy_snapshot = None
    attachment.rejection_reason = RETENTION_REASON
    attachment.uploaded_at = None
    return not already_anonymized


def _anonymize_reporter_contact(contact: ReporterContact, now: datetime) -> bool:
    if contact.anonymized_at is not None:
        return False
    contact.full_name_ciphertext = RETENTION_MARKER
    contact.full_name_masked = RETENTION_MARKER
    contact.mobile_ciphertext = RETENTION_MARKER
    contact.mobile_blind_index = sha256_text(f"retention:{contact.id}:mobile")
    contact.mobile_masked = RETENTION_MARKER
    contact.national_id_ciphertext = None
    contact.national_id_blind_index = None
    contact.national_id_masked = None
    contact.emergency_name_ciphertext = None
    contact.emergency_name_masked = None
    contact.emergency_mobile_ciphertext = None
    contact.emergency_mobile_masked = None
    contact.emergency_relation_ciphertext = None
    contact.emergency_relation_masked = None
    contact.rescue_notes_ciphertext = None
    contact.encryption_key_version = "retention"
    contact.anonymized_at = now
    return True


def _anonymize_answer(answer: DirectedAnswer) -> bool:
    already_anonymized = answer.answer_text == RETENTION_MARKER
    answer.option_id = RETENTION_MARKER
    answer.semantic_value = RETENTION_MARKER
    answer.answer_text = RETENTION_MARKER
    answer.observed_latitude = None
    answer.observed_longitude = None
    answer.observed_coordinate_system = None
    return not already_anonymized


def _anonymize_fragment(fragment: InformationFragment) -> bool:
    already_anonymized = fragment.status == "expired" and fragment.description == RETENTION_MARKER
    fragment.source_ref_id = None
    fragment.source_cluster_id = None
    fragment.claim_key = None
    fragment.claim_value = None
    fragment.label = RETENTION_MARKER
    fragment.description = RETENTION_MARKER
    fragment.location_text = RETENTION_MARKER
    fragment.latitude = None
    fragment.longitude = None
    fragment.coordinate_system = None
    fragment.status = "expired"
    fragment.confidence = 0.0
    fragment.observed_at = None
    return not already_anonymized


async def _anonymize_incident(
    session: AsyncSession,
    incident_id: str,
    storage_root: Path,
    now: datetime,
    result: RetentionCleanupResult,
) -> bool:
    changed = False
    reports = list(
        (await session.scalars(select(Report).where(Report.incident_id == incident_id))).all()
    )
    report_ids = [report.id for report in reports]
    for report in reports:
        if _anonymize_report(report, now):
            result.reports_anonymized += 1
            changed = True

    contacts = list(
        (
            await session.scalars(
                select(ReporterContact).where(ReporterContact.incident_id == incident_id)
            )
        ).all()
    )
    for contact in contacts:
        if contact.legal_hold:
            continue
        if _anonymize_reporter_contact(contact, now):
            result.reporter_contacts_anonymized += 1
            changed = True

    if report_ids:
        report_revisions = list(
            (
                await session.scalars(
                    select(ReportRevision).where(ReportRevision.report_id.in_(report_ids))
                )
            ).all()
        )
        for report_revision in report_revisions:
            if report_revision.snapshot.get("retention_expired") is not True:
                report_revision.snapshot = {
                    "retention_expired": True,
                    "report_id": report_revision.report_id,
                    "revision": report_revision.revision,
                }
                result.report_revisions_anonymized += 1
                changed = True

    attachments = list(
        (
            await session.scalars(select(Attachment).where(Attachment.incident_id == incident_id))
        ).all()
    )
    await _remove_attachment_files(attachments, storage_root, result)
    for attachment in attachments:
        if _anonymize_attachment(attachment):
            result.attachments_anonymized += 1
            changed = True

    answers = list(
        (
            await session.scalars(
                select(DirectedAnswer)
                .join(
                    DirectedQuestion,
                    DirectedQuestion.id == DirectedAnswer.question_id,
                )
                .where(DirectedQuestion.incident_id == incident_id)
            )
        ).all()
    )
    answer_ids = [answer.id for answer in answers]
    for answer in answers:
        if _anonymize_answer(answer):
            result.directed_answers_anonymized += 1
            changed = True
    if answer_ids:
        answer_revisions = list(
            (
                await session.scalars(
                    select(DirectedAnswerRevision).where(
                        DirectedAnswerRevision.answer_id.in_(answer_ids)
                    )
                )
            ).all()
        )
        for answer_revision in answer_revisions:
            if answer_revision.snapshot.get("retention_expired") is not True:
                answer_revision.snapshot = {
                    "retention_expired": True,
                    "answer_id": answer_revision.answer_id,
                    "revision": answer_revision.revision,
                }
                result.answer_revisions_anonymized += 1
                changed = True

    fragments = list(
        (
            await session.scalars(
                select(InformationFragment).where(InformationFragment.incident_id == incident_id)
            )
        ).all()
    )
    for fragment in fragments:
        if _anonymize_fragment(fragment):
            result.fragments_anonymized += 1
            changed = True

    conflict_evidence = list(
        (
            await session.scalars(
                select(ConflictEvidence)
                .join(ConflictCase, ConflictCase.id == ConflictEvidence.conflict_id)
                .where(ConflictCase.incident_id == incident_id)
            )
        ).all()
    )
    for evidence in conflict_evidence:
        if evidence.snapshot.get("retention_expired") is True:
            continue
        evidence.snapshot = {
            "retention_expired": True,
            "kind": evidence.kind,
            "source_id": evidence.source_id,
            "source_revision": evidence.source_revision,
        }
        evidence.snapshot_sha256 = sha256_text(canonical_json(evidence.snapshot))
        evidence.source_cluster_id = None
        result.conflict_evidence_anonymized += 1
        changed = True

    analyses = list(
        (
            await session.scalars(select(AiAnalysis).where(AiAnalysis.incident_id == incident_id))
        ).all()
    )
    for analysis in analyses:
        if analysis.input_snapshot.get("retention_expired") is True:
            continue
        analysis.input_snapshot = {
            "retention_expired": True,
            "analysis_type": analysis.analysis_type,
            "input_version": analysis.input_version,
        }
        if analysis.context_package is not None:
            analysis.context_package = {"retention_expired": True}
            analysis.context_sha256 = sha256_text(canonical_json(analysis.context_package))
        if analysis.output is not None:
            analysis.output = {"retention_expired": True}
        analysis.is_stale = True
        analysis.stale_at = analysis.stale_at or now
        analysis.stale_reason = "retention_expired"
        result.ai_analyses_anonymized += 1
        changed = True

    map_features = list(
        (
            await session.scalars(
                select(MapFeature).where(
                    MapFeature.incident_id == incident_id,
                    MapFeature.kind.in_(("report", "fragment")),
                )
            )
        ).all()
    )
    for feature in map_features:
        already_removed = (
            feature.is_deleted
            and feature.latitude_wgs84 is None
            and feature.longitude_wgs84 is None
            and feature.public_data == {}
            and feature.private_data == {}
        )
        feature.title = RETENTION_MARKER
        feature.status = "expired"
        feature.latitude_wgs84 = None
        feature.longitude_wgs84 = None
        feature.latitude_gcj02 = None
        feature.longitude_gcj02 = None
        feature.is_deleted = True
        feature.public_data = {}
        feature.private_data = {}
        if not already_removed:
            result.map_features_removed += 1
            changed = True
    return changed


async def cleanup_retention_once(
    settings: Settings | None = None,
    *,
    now: datetime | None = None,
    session_maker: async_sessionmaker[AsyncSession] | None = None,
) -> RetentionCleanupResult:
    """Apply one idempotent retention pass under the process-wide SQLite write lock."""

    settings = settings or get_settings()
    now = now or utcnow()
    maker = session_maker or session_factory()
    result = RetentionCleanupResult()
    replay_cutoff = now - timedelta(hours=settings.realtime_replay_hours)
    audit_cutoff = now - timedelta(days=settings.audit_retention_days)
    business_cutoff = now - timedelta(days=settings.business_retention_days)

    async with write_lock:
        async with maker() as session:
            result.idempotency_records_deleted = await _delete_selected(
                session,
                IdempotencyRecord,
                IdempotencyRecord.expires_at <= now,
            )
            result.refresh_sessions_deleted = await _delete_selected(
                session,
                RefreshSession,
                RefreshSession.expires_at <= now,
            )
            result.outbox_events_deleted = await _delete_selected(
                session,
                OutboxEvent,
                OutboxEvent.published_at.is_not(None) & (OutboxEvent.published_at <= replay_cutoff),
            )
            result.audit_logs_deleted = await _delete_selected(
                session,
                AuditLog,
                AuditLog.created_at <= audit_cutoff,
            )
            expired_contacts = list(
                (
                    await session.scalars(
                        select(ReporterContact).where(
                            ReporterContact.retention_until <= now,
                            ReporterContact.legal_hold.is_(False),
                            ReporterContact.anonymized_at.is_(None),
                        )
                    )
                ).all()
            )
            for contact in expired_contacts:
                if _anonymize_reporter_contact(contact, now):
                    result.reporter_contacts_anonymized += 1

            incident_ids = list(
                (
                    await session.scalars(
                        select(Incident.id).where(
                            Incident.status == "closed",
                            Incident.closed_at.is_not(None),
                            Incident.closed_at <= business_cutoff,
                        )
                    )
                ).all()
            )
            for incident_id in incident_ids:
                if await _anonymize_incident(
                    session,
                    incident_id,
                    settings.storage_root,
                    now,
                    result,
                ):
                    result.incidents_anonymized += 1
            await session.commit()
    return result
