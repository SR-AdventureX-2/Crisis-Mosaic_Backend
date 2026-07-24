from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest
from PIL import Image
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from crisis_mosaic.config import Settings
from crisis_mosaic.errors import ApiError
from crisis_mosaic.models import (
    AiAnalysis,
    AiJobStep,
    Attachment,
    BackgroundJob,
    Base,
    ConflictCase,
    ConflictEvidence,
    Incident,
)
from crisis_mosaic.schemas.ai import (
    BriefRecommendation,
    CommandBriefOutput,
    ConflictAnalysisOutput,
    EvidenceAssessment,
    ReportRefinementRequest,
)
from crisis_mosaic.schemas.uploads import ImageIntentRequest
from crisis_mosaic.security import Actor
from crisis_mosaic.services.ai import (
    build_conflict_context,
    enqueue_conflict_analysis,
    ensure_ai_available,
    process_analysis,
    refine_report,
)
from crisis_mosaic.services.uploads import (
    attachment_state,
    process_attachment,
    stream_request_to_quarantine,
)
from crisis_mosaic.utils import canonical_json, sha256_text, utcnow
from crisis_mosaic.workers import WorkerRuntime


def image_bytes() -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (32, 24), color=(20, 80, 160)).save(output, format="JPEG")
    return output.getvalue()


async def chunks(value: bytes):
    yield value[:11]
    yield value[11:]


def test_upload_intent_rejects_path_traversal() -> None:
    with pytest.raises(ValidationError):
        ImageIntentRequest(
            incident_id="incident",
            file_name="../secret.jpg",
            mime_type="image/jpeg",
            size_bytes=4,
            sha256="0" * 64,
        )


@pytest.mark.asyncio
async def test_stream_upload_checks_hash_and_size(tmp_path: Path) -> None:
    content = image_bytes()
    settings = Settings(
        app_env="test",
        storage_root=tmp_path / "uploads",
        data_dir=tmp_path,
        malware_scanner="fake",
        max_image_bytes=len(content) + 100,
    )
    attachment = Attachment(
        id="01900000-0000-7000-8000-000000000001",
        incident_id="incident",
        uploader_device_id="device",
        file_name="scene.jpg",
        declared_mime_type="image/jpeg",
        size_bytes=len(content),
        expected_sha256=hashlib.sha256(content).hexdigest(),
        upload_expires_at=utcnow(),
    )
    # Give the intent a future expiration without relying on wall-clock sleep.
    from datetime import timedelta

    attachment.upload_expires_at = utcnow() + timedelta(minutes=1)
    target = await stream_request_to_quarantine(attachment, chunks(content), settings)
    assert target.read_bytes() == content
    assert attachment.sha256 == hashlib.sha256(content).hexdigest()

    bad = Attachment(
        id="01900000-0000-7000-8000-000000000002",
        incident_id="incident",
        uploader_device_id="device",
        file_name="scene.jpg",
        declared_mime_type="image/jpeg",
        size_bytes=len(content),
        expected_sha256="0" * 64,
        upload_expires_at=utcnow() + timedelta(minutes=1),
    )
    with pytest.raises(ApiError, match="哈希"):
        await stream_request_to_quarantine(bad, chunks(content), settings)


@pytest.mark.asyncio
async def test_image_processing_sanitizes_and_clusters_duplicates(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        app_env="test",
        storage_root=tmp_path / "uploads",
        data_dir=tmp_path,
        malware_scanner="fake",
        ai_provider="fake",
    )
    settings.ensure_directories()
    content = image_bytes()
    digest = hashlib.sha256(content).hexdigest()
    async with maker() as session:
        incident = Incident(id="incident", name="Test", status="preparing")
        session.add(incident)
        for index in (1, 2):
            attachment_id = f"01900000-0000-7000-8000-00000000000{index}"
            source = settings.storage_root / "quarantine" / f"{attachment_id}.upload"
            source.write_bytes(content)
            session.add(
                Attachment(
                    id=attachment_id,
                    incident_id=incident.id,
                    uploader_device_id="device",
                    file_name=f"{index}.jpg",
                    declared_mime_type="image/jpeg",
                    size_bytes=len(content),
                    expected_sha256=digest,
                    sha256=digest,
                    original_path=str(source),
                    uploaded_at=utcnow(),
                    upload_expires_at=utcnow(),
                )
            )
        await session.commit()
        first = await process_attachment(session, "01900000-0000-7000-8000-000000000001", settings)
        await session.commit()
        second = await process_attachment(session, "01900000-0000-7000-8000-000000000002", settings)
        await session.commit()
        assert attachment_state(first) == "ready"
        assert Path(first.sanitized_path or "").is_file()
        assert first.exif_data == {}
        assert second.duplicate_of_attachment_id == first.id
        assert second.source_cluster_id == first.source_cluster_id
        assert second.vision_status == "succeeded"
    await engine.dispose()


def test_missing_ai_key_is_explicit_503() -> None:
    settings = Settings(app_env="test", ai_provider="openai_compatible", ai_api_key="")
    with pytest.raises(ApiError) as exc_info:
        ensure_ai_available(settings)
    assert exc_info.value.status_code == 503
    assert exc_info.value.code == "AI_SERVICE_UNAVAILABLE"


def test_conflict_ai_output_rejects_unknown_evidence() -> None:
    output = ConflictAnalysisOutput(
        recommended_evidence_id="made-up",
        suggested_conclusion="结论",
        reasoning_summary="摘要",
        confidence=0.5,
        evidence_assessments=[
            EvidenceAssessment(
                evidence_id="known",
                authenticity_score=0.8,
                credibility_score=0.7,
                verdict="likely",
                reason="可核验",
                extracted_facts=[],
            )
        ],
        warnings=[],
    )
    with pytest.raises(ValueError, match="unknown evidence"):
        output.validate_evidence_refs({"known"})


def test_conflict_ai_output_must_assess_every_evidence_once() -> None:
    output = ConflictAnalysisOutput(
        recommended_evidence_id="evidence-1",
        suggested_conclusion="Use the first source pending review.",
        reasoning_summary="Only one source was assessed.",
        confidence=0.5,
        evidence_assessments=[
            EvidenceAssessment(
                evidence_id="evidence-1",
                authenticity_score=0.8,
                credibility_score=0.7,
                verdict="likely",
                reason="The source is internally consistent.",
                extracted_facts=[],
            )
        ],
        warnings=[],
    )

    with pytest.raises(ValueError, match="omitted evidence assessments"):
        output.validate_evidence_refs({"evidence-1", "evidence-2"})


def test_command_brief_rejects_source_refs_outside_snapshot_whitelist() -> None:
    output = CommandBriefOutput(
        headline="Current incident brief",
        summary="One recommendation requires operator review.",
        recommendations=[
            BriefRecommendation(
                text="Inspect the affected bridge.",
                severity="high",
                source_refs=["report:not-in-snapshot"],
            )
        ],
        confidence=0.7,
    )

    with pytest.raises(ValueError, match="unknown sources"):
        output.validate_source_refs({"incident:current", "report:known"})


@pytest.mark.asyncio
async def test_fake_report_refinement_is_persisted(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'ai.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        app_env="test",
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'ai.db'}",
    )
    actor = Actor(
        subject_type="device",
        subject_id="device",
        role="resident",
        token_version=1,
        incident_ids=frozenset({"incident"}),
    )
    async with maker() as session:
        session.add(Incident(id="incident", name="Test", status="preparing"))
        await session.commit()
        analysis, result = await refine_report(
            session,
            ReportRefinementRequest(
                incident_id="incident",
                category="rescue",
                content="桥边老人被困，水位上涨",
                location_text="大关桥",
            ),
            actor,
            settings,
        )
        await session.commit()
        saved = await session.get(AiAnalysis, analysis.id)
        assert saved is not None and saved.status == "succeeded"
        assert result.suggest_urgent is True
        assert "elderly" in result.detected_risk_tags
    await engine.dispose()


@pytest.mark.asyncio
async def test_async_analysis_missing_key_persists_failure_and_reopens_conflict(
    tmp_path: Path,
) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'missing-key.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        app_env="test",
        ai_provider="openai_compatible",
        ai_api_key="",
        storage_root=tmp_path / "uploads",
    )
    async with maker() as session:
        incident = Incident(id="incident", name="Test", status="active")
        conflict = ConflictCase(
            id="conflict",
            incident_id=incident.id,
            fact_key="road:open",
            title="Road state",
            topic="road",
            location_text="Bridge",
            status="analyzing",
            revision=2,
        )
        analysis = AiAnalysis(
            id="analysis",
            incident_id=incident.id,
            analysis_type="conflict_analysis",
            status="queued",
            input_snapshot={
                "conflict_id": conflict.id,
                "conflict_revision": conflict.revision,
                "allowed_evidence_ids": ["evidence"],
            },
            context_package={"evidence": []},
            prompt_version="p0-v1",
            created_by_type="account",
            created_by_id="operator",
            input_version=conflict.revision,
        )
        session.add_all([incident, conflict, analysis])
        await session.commit()

        with pytest.raises(ApiError) as exc_info:
            await process_analysis(session, analysis.id, settings)
        assert exc_info.value.code == "AI_SERVICE_UNAVAILABLE"

    async with maker() as session:
        saved_analysis = await session.get(AiAnalysis, "analysis")
        saved_conflict = await session.get(ConflictCase, "conflict")
        steps = list(
            (
                await session.scalars(select(AiJobStep).where(AiJobStep.analysis_id == "analysis"))
            ).all()
        )
        assert saved_analysis is not None
        assert saved_analysis.status == "failed"
        assert saved_analysis.error_code == "AI_SERVICE_UNAVAILABLE"
        assert saved_analysis.completed_at is not None
        assert saved_conflict is not None and saved_conflict.status == "open"
        assert steps and all(step.status == "failed" for step in steps)
    await engine.dispose()


@pytest.mark.asyncio
async def test_conflict_context_has_observation_timeline_steps_and_stable_cache(
    tmp_path: Path,
) -> None:
    from datetime import timedelta

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'context.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(app_env="test", ai_provider="fake")
    actor = Actor(
        subject_type="account",
        subject_id="operator",
        role="operator",
        token_version=1,
        incident_ids=frozenset({"incident"}),
    )
    now = utcnow()
    async with maker() as session:
        incident = Incident(id="incident", name="Test", status="active")
        conflict = ConflictCase(
            id="conflict",
            incident_id=incident.id,
            fact_key="road:open",
            title="Road state",
            topic="road",
            location_text="Bridge",
            status="open",
            revision=1,
        )
        later_observation = ConflictEvidence(
            id="evidence-later",
            conflict_id=conflict.id,
            kind="fragment",
            source_id="fragment-later",
            source_revision=1,
            snapshot={"observed_at": now.isoformat(), "claim_value": "open"},
            snapshot_sha256="a" * 64,
            added_at=now - timedelta(hours=2),
        )
        earlier_observation = ConflictEvidence(
            id="evidence-earlier",
            conflict_id=conflict.id,
            kind="fragment",
            source_id="fragment-earlier",
            source_revision=1,
            snapshot={
                "observed_at": (now - timedelta(days=1)).isoformat(),
                "claim_value": "closed",
            },
            snapshot_sha256="b" * 64,
            added_at=now - timedelta(hours=1),
        )
        session.add_all([incident, conflict, later_observation, earlier_observation])
        await session.commit()

        context, allowed = await build_conflict_context(session, conflict, None)
        assert allowed == {"evidence-later", "evidence-earlier"}
        assert [item["id"] for item in context["evidence"]] == [
            "evidence-earlier",
            "evidence-later",
        ]
        analysis = await enqueue_conflict_analysis(
            session,
            conflict=conflict,
            revision=1,
            evidence_ids=None,
            actor=actor,
            settings=settings,
        )
        analysis.status = "succeeded"
        await session.commit()

        steps = list(
            (
                await session.scalars(select(AiJobStep).where(AiJobStep.analysis_id == analysis.id))
            ).all()
        )
        assert {
            "evidence_collection",
            "image_safety_and_deduplication",
            "ocr_and_vision_context",
            "text_normalization",
            "timeline_alignment",
            "context_persistence",
        } <= {step.name for step in steps}
        assert analysis.context_package is not None
        assert analysis.context_sha256 == sha256_text(canonical_json(analysis.context_package))

        conflict.status = "open"
        cached = await enqueue_conflict_analysis(
            session,
            conflict=conflict,
            revision=1,
            evidence_ids=None,
            actor=actor,
            settings=settings,
        )
        assert cached.id == analysis.id
        assert conflict.status == "analysis_ready"
    await engine.dispose()


@pytest.mark.asyncio
async def test_worker_retries_and_then_fails_unknown_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'worker.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr("crisis_mosaic.workers.session_factory", lambda: maker)
    settings = Settings(
        app_env="test",
        job_max_attempts=1,
        job_poll_seconds=0.01,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'worker.db'}",
    )
    async with maker() as session:
        job = BackgroundJob(job_type="unknown", payload={}, max_attempts=1)
        session.add(job)
        await session.commit()
        job_id = job.id
    runtime = WorkerRuntime(settings, outbox_handler=lambda _: _noop())
    claimed = await runtime._claim_job()
    assert claimed == job_id
    await runtime._execute_job(job_id)
    async with maker() as session:
        failed = await session.get(BackgroundJob, job_id)
        assert failed is not None and failed.status == "failed"
        assert "unknown background job type" in (failed.last_error or "")
    await engine.dispose()


async def _noop() -> None:
    return None
