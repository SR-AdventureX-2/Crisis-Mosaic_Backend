from __future__ import annotations

import asyncio
import hashlib
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from crisis_mosaic.config import Settings
from crisis_mosaic.models import (
    AiAnalysis,
    AnonymousDevice,
    Attachment,
    AuditLog,
    Base,
    BlindSpot,
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
    ReportRevision,
)
from crisis_mosaic.services.retention import (
    RETENTION_MARKER,
    RETENTION_REASON,
    cleanup_retention_once,
)
from crisis_mosaic.utils import utcnow
from crisis_mosaic.workers import WorkerRuntime


async def _database(
    path: Path,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


@pytest.mark.asyncio
async def test_retention_cleanup_purges_and_anonymizes_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, maker = await _database(tmp_path / "retention.db")
    monkeypatch.setattr("crisis_mosaic.services.retention.write_lock", asyncio.Lock())
    now = utcnow()
    settings = Settings(
        app_env="test",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'retention.db'}",
        data_dir=tmp_path,
        storage_root=tmp_path / "uploads",
        business_retention_days=10,
        audit_retention_days=20,
        realtime_replay_hours=24,
    )
    settings.ensure_directories()
    inside_original = settings.storage_root / "original" / "resident.jpg"
    inside_sanitized = settings.storage_root / "sanitized" / "resident.jpg"
    outside_thumbnail = tmp_path / "outside-thumbnail.jpg"
    for path in (inside_original, inside_sanitized, outside_thumbnail):
        path.write_bytes(b"sensitive")

    ids: dict[str, str] = {}
    async with maker() as session:
        old_incident = Incident(
            name="Old closed incident",
            status="closed",
            closed_at=now - timedelta(days=11),
        )
        recent_incident = Incident(
            name="Recent closed incident",
            status="closed",
            closed_at=now - timedelta(days=1),
        )
        device = AnonymousDevice(
            installation_id_hash=hashlib.sha256(b"retention-device").hexdigest(),
            platform="test",
        )
        session.add_all([old_incident, recent_incident, device])
        await session.flush()

        old_report = Report(
            incident_id=old_incident.id,
            reporter_device_id=device.id,
            category="road_damage",
            content_original="resident name and details",
            content_display="resident name and details",
            location_text="private home",
            latitude=30.1,
            longitude=120.1,
            location_wgs84_latitude=30.1,
            location_wgs84_longitude=120.1,
            location_gcj02_latitude=30.2,
            location_gcj02_longitude=120.2,
            location_accuracy_m=5,
            coordinate_system="wgs84",
        )
        recent_report = Report(
            incident_id=recent_incident.id,
            reporter_device_id=device.id,
            category="road_damage",
            content_original="still retained",
            content_display="still retained",
            location_text="recent location",
        )
        session.add_all([old_report, recent_report])
        await session.flush()
        session.add(
            ReportRevision(
                report_id=old_report.id,
                revision=1,
                snapshot={"content": "resident name and details", "latitude": 30.1},
                changed_by_type="device",
                changed_by_id=device.id,
            )
        )

        attachment = Attachment(
            incident_id=old_incident.id,
            report_id=old_report.id,
            uploader_device_id=device.id,
            file_name="resident.jpg",
            declared_mime_type="image/jpeg",
            mime_type="image/jpeg",
            size_bytes=9,
            expected_sha256="1" * 64,
            sha256="1" * 64,
            original_path=str(inside_original),
            sanitized_path=str(inside_sanitized),
            thumbnail_path=str(outside_thumbnail),
            metadata_status="ready",
            malware_scan_status="clean",
            ocr_status="ready",
            vision_status="ready",
            ocr_text="resident phone",
            vision_summary="private house",
            upload_expires_at=now,
            uploaded_at=now,
        )
        blind_spot = BlindSpot(
            incident_id=old_incident.id,
            claim_key="road.open",
            title="Old blind spot",
            location_text="private road",
        )
        session.add_all([attachment, blind_spot])
        await session.flush()
        question = DirectedQuestion(
            incident_id=old_incident.id,
            blind_spot_id=blind_spot.id,
            title="Can you pass?",
            location_text="private road",
            options=[],
        )
        session.add(question)
        await session.flush()
        answer = DirectedAnswer(
            question_id=question.id,
            device_id=device.id,
            option_id="yes",
            semantic_value="passable",
            answer_text="I live here and it is passable",
            observed_latitude=30.1,
            observed_longitude=120.1,
            observed_coordinate_system="wgs84",
        )
        fragment = InformationFragment(
            incident_id=old_incident.id,
            source_type="directed_answer",
            source_ref_id=answer.id,
            topic="transport",
            claim_key="road.open",
            claim_value="passable",
            label="Resident observation",
            description="I live here",
            location_text="private road",
            latitude=30.1,
            longitude=120.1,
            coordinate_system="wgs84",
        )
        session.add_all([answer, fragment])
        await session.flush()
        session.add(
            DirectedAnswerRevision(
                answer_id=answer.id,
                revision=1,
                snapshot={"answer_text": "I live here and it is passable"},
            )
        )
        session.add_all(
            [
                MapFeature(
                    incident_id=old_incident.id,
                    kind="report",
                    source_ref=old_report.id,
                    title="private home",
                    status="new",
                    latitude_wgs84=30.1,
                    longitude_wgs84=120.1,
                    public_data={"location_text": "private home"},
                    private_data={"resident": "name"},
                ),
                MapFeature(
                    incident_id=old_incident.id,
                    kind="fragment",
                    source_ref=fragment.id,
                    title="private road",
                    status="normal",
                    latitude_wgs84=30.1,
                    longitude_wgs84=120.1,
                    public_data={"location_text": "private road"},
                    private_data={"description": "I live here"},
                ),
            ]
        )
        conflict = ConflictCase(
            incident_id=old_incident.id,
            fact_key="road.open",
            title="Resident-derived conflict",
            topic="transport",
            location_text="private road",
        )
        analysis = AiAnalysis(
            incident_id=old_incident.id,
            analysis_type="conflict_analysis",
            status="succeeded",
            input_snapshot={"resident_report_id": old_report.id},
            context_package={"evidence": [{"resident": "name"}]},
            context_sha256="e" * 64,
            output={"summary": "resident name says the road is open"},
            prompt_version="test",
            created_by_type="account",
        )
        session.add_all([conflict, analysis])
        await session.flush()
        evidence = ConflictEvidence(
            conflict_id=conflict.id,
            kind="report",
            source_id=old_report.id,
            source_revision=1,
            source_cluster_id="private-cluster",
            snapshot={"content_original": "resident name and details"},
            snapshot_sha256="f" * 64,
        )
        session.add(evidence)

        expired_idempotency = IdempotencyRecord(
            actor_key="device:expired",
            route="POST:/reports",
            idempotency_key="expired",
            request_hash="a" * 64,
            response_status=201,
            response_body={},
            expires_at=now - timedelta(seconds=1),
        )
        fresh_idempotency = IdempotencyRecord(
            actor_key="device:fresh",
            route="POST:/reports",
            idempotency_key="fresh",
            request_hash="b" * 64,
            response_status=201,
            response_body={},
            expires_at=now + timedelta(hours=1),
        )
        expired_refresh = RefreshSession(
            subject_type="device",
            subject_id=device.id,
            token_hash="c" * 64,
            family_id="expired-family",
            expires_at=now - timedelta(seconds=1),
        )
        fresh_refresh = RefreshSession(
            subject_type="device",
            subject_id=device.id,
            token_hash="d" * 64,
            family_id="fresh-family",
            expires_at=now + timedelta(hours=1),
        )
        old_audit = AuditLog(
            incident_id=old_incident.id,
            actor_type="system",
            action="old",
            resource_type="report",
            resource_id=old_report.id,
            created_at=now - timedelta(days=21),
        )
        fresh_audit = AuditLog(
            incident_id=old_incident.id,
            actor_type="system",
            action="fresh",
            resource_type="report",
            resource_id=old_report.id,
            created_at=now - timedelta(days=1),
        )
        old_published = OutboxEvent(
            incident_id=old_incident.id,
            sequence=1,
            event_type="old.published",
            resource_type="report",
            payload={"private": True},
            occurred_at=now - timedelta(days=2),
            published_at=now - timedelta(days=2),
        )
        fresh_published = OutboxEvent(
            incident_id=old_incident.id,
            sequence=2,
            event_type="fresh.published",
            resource_type="report",
            payload={},
            occurred_at=now,
            published_at=now,
        )
        old_unpublished = OutboxEvent(
            incident_id=old_incident.id,
            sequence=3,
            event_type="old.unpublished",
            resource_type="report",
            payload={},
            occurred_at=now - timedelta(days=2),
        )
        session.add_all(
            [
                expired_idempotency,
                fresh_idempotency,
                expired_refresh,
                fresh_refresh,
                old_audit,
                fresh_audit,
                old_published,
                fresh_published,
                old_unpublished,
            ]
        )
        await session.flush()
        ids = {
            "old_report": old_report.id,
            "recent_report": recent_report.id,
            "attachment": attachment.id,
            "answer": answer.id,
            "fragment": fragment.id,
            "expired_idempotency": expired_idempotency.id,
            "fresh_idempotency": fresh_idempotency.id,
            "expired_refresh": expired_refresh.id,
            "fresh_refresh": fresh_refresh.id,
            "old_audit": old_audit.id,
            "fresh_audit": fresh_audit.id,
            "old_published": old_published.id,
            "fresh_published": fresh_published.id,
            "old_unpublished": old_unpublished.id,
            "evidence": evidence.id,
            "analysis": analysis.id,
        }
        await session.commit()

    result = await cleanup_retention_once(settings, now=now, session_maker=maker)
    assert result.idempotency_records_deleted == 1
    assert result.refresh_sessions_deleted == 1
    assert result.outbox_events_deleted == 1
    assert result.audit_logs_deleted == 1
    assert result.incidents_anonymized == 1
    assert result.reports_anonymized == 1
    assert result.report_revisions_anonymized == 1
    assert result.attachments_anonymized == 1
    assert result.directed_answers_anonymized == 1
    assert result.answer_revisions_anonymized == 1
    assert result.fragments_anonymized == 1
    assert result.conflict_evidence_anonymized == 1
    assert result.ai_analyses_anonymized == 1
    assert result.map_features_removed == 2
    assert result.files_deleted == 2
    assert result.unsafe_storage_paths_skipped == 1

    assert not inside_original.exists()
    assert not inside_sanitized.exists()
    assert outside_thumbnail.read_bytes() == b"sensitive"

    async with maker() as session:
        for key in (
            "expired_idempotency",
            "expired_refresh",
            "old_audit",
            "old_published",
        ):
            model = {
                "expired_idempotency": IdempotencyRecord,
                "expired_refresh": RefreshSession,
                "old_audit": AuditLog,
                "old_published": OutboxEvent,
            }[key]
            assert await session.get(model, ids[key]) is None
        for key, model in (
            ("fresh_idempotency", IdempotencyRecord),
            ("fresh_refresh", RefreshSession),
            ("fresh_audit", AuditLog),
            ("fresh_published", OutboxEvent),
            ("old_unpublished", OutboxEvent),
        ):
            assert await session.get(model, ids[key]) is not None

        old_report = await session.get(Report, ids["old_report"])
        recent_report = await session.get(Report, ids["recent_report"])
        attachment = await session.get(Attachment, ids["attachment"])
        answer = await session.get(DirectedAnswer, ids["answer"])
        fragment = await session.get(InformationFragment, ids["fragment"])
        evidence = await session.get(ConflictEvidence, ids["evidence"])
        analysis = await session.get(AiAnalysis, ids["analysis"])
        assert old_report is not None
        assert old_report.content_original == RETENTION_MARKER
        assert old_report.location_wgs84_latitude is None
        assert recent_report is not None
        assert recent_report.content_original == "still retained"
        assert attachment is not None
        assert attachment.rejection_reason == RETENTION_REASON
        assert attachment.original_path is None
        assert attachment.thumbnail_path is None
        assert answer is not None
        assert answer.answer_text == RETENTION_MARKER
        assert answer.observed_latitude is None
        assert fragment is not None
        assert fragment.description == RETENTION_MARKER
        assert fragment.source_ref_id is None
        assert evidence is not None
        assert evidence.snapshot["retention_expired"] is True
        assert evidence.source_cluster_id is None
        assert analysis is not None
        assert analysis.input_snapshot["retention_expired"] is True
        assert analysis.context_package == {"retention_expired": True}
        assert analysis.output == {"retention_expired": True}
        assert analysis.is_stale is True

        report_revision = await session.scalar(
            select(ReportRevision).where(ReportRevision.report_id == ids["old_report"])
        )
        answer_revision = await session.scalar(
            select(DirectedAnswerRevision).where(DirectedAnswerRevision.answer_id == ids["answer"])
        )
        features = list(
            (
                await session.scalars(
                    select(MapFeature).where(
                        MapFeature.source_ref.in_((ids["old_report"], ids["fragment"]))
                    )
                )
            ).all()
        )
        assert report_revision is not None
        assert report_revision.snapshot["retention_expired"] is True
        assert answer_revision is not None
        assert answer_revision.snapshot["retention_expired"] is True
        assert len(features) == 2
        assert all(feature.is_deleted and feature.public_data == {} for feature in features)

    repeated = await cleanup_retention_once(settings, now=now, session_maker=maker)
    assert not any(repeated.as_dict().values())
    await engine.dispose()


@pytest.mark.asyncio
async def test_worker_runtime_schedules_retention_task(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        app_env="test",
        data_dir=tmp_path,
        storage_root=tmp_path / "uploads",
    )
    runtime = WorkerRuntime(settings)

    async def idle() -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(runtime, "_job_loop", idle)
    monkeypatch.setattr(runtime, "_outbox_loop", idle)
    monkeypatch.setattr(runtime, "_notification_loop", idle)
    monkeypatch.setattr(runtime, "_retention_loop", idle)
    await runtime.start()
    try:
        assert {task.get_name() for task in runtime._tasks} == {
            "crisis-mosaic-jobs",
            "crisis-mosaic-outbox",
            "crisis-mosaic-push",
            "crisis-mosaic-retention",
        }
    finally:
        await runtime.stop()
