from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest
from PIL import Image
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from crisis_mosaic.config import Settings, get_settings
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
    Report,
)
from crisis_mosaic.schemas.ai import (
    BriefRecommendation,
    CommandBriefOutput,
    ConflictAnalysisOutput,
    EvidenceAssessment,
    MediaEvidenceExtractionOutput,
    MediaObservation,
    ReportRefinementOutput,
    ReportRefinementRequest,
)
from crisis_mosaic.schemas.uploads import ImageIntentRequest
from crisis_mosaic.security import Actor
from crisis_mosaic.services.ai import (
    _conflict_reference_fallback,
    _ensure_conflict_human_confirmation_warning,
    _media_evidence_to_attachment_output,
    _read_report_attachment_visual,
    _validate_command_brief_contract,
    _validate_media_evidence_contract,
    _validate_report_refinement_contract,
    build_conflict_context,
    build_report_refinement_context,
    enqueue_conflict_analysis,
    ensure_ai_available,
    process_analysis,
    refine_report,
)
from crisis_mosaic.services.ai_prompts import (
    CONFLICT_ANALYSIS_PROMPT_VERSION,
    REPORT_REFINEMENT_PROMPT_VERSION,
)
from crisis_mosaic.services.attachments import serialize_attachment
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


def test_report_refinement_allows_number_adjustments() -> None:
    # 数字事实一致性校验已移除：模型遗漏或新增数字不再拦截，只要保留位置行即可。
    request = ReportRefinementRequest(
        incident_id="incident",
        category="rescue",
        content="水位上涨，有2人被困",
        location_text="东桥",
    )
    output = ReportRefinementOutput(
        refined_content="【需要救援】水位上涨，有2人被困，另有5人等待转移。\n【位置】东桥",
        risk_hint="检测到明确风险，建议居民确认紧急标记并尽快提交。",
        suggest_urgent=True,
        detected_risk_tags=["trapped_people", "rising_water"],
        confidence=0.8,
    )

    _validate_report_refinement_contract(request, output)


def test_report_refinement_attachment_request_contract_is_bounded() -> None:
    with pytest.raises(ValidationError, match="duplicates"):
        ReportRefinementRequest(
            incident_id="incident",
            category="rescue",
            content="需要帮助",
            location_text="东桥",
            attachment_ids=["same", "same"],
        )
    with pytest.raises(ValidationError, match="provided together"):
        ReportRefinementRequest(
            incident_id="incident",
            category="rescue",
            content="需要帮助",
            location_text="东桥",
            report_id="report",
        )
    limit = get_settings().media_max_attachment_count
    with pytest.raises(ValidationError, match="configured media attachment count"):
        ReportRefinementRequest(
            incident_id="incident",
            category="rescue",
            content="需要帮助",
            location_text="东桥",
            attachment_ids=[f"attachment-{index}" for index in range(limit + 1)],
        )


def test_media_evidence_output_maps_to_attachment_fields() -> None:
    attachment = Attachment(
        id="01900000-0000-7000-8000-000000000101",
        incident_id="incident",
        uploader_device_id="device",
        file_name="scene.jpg",
        declared_mime_type="image/jpeg",
        size_bytes=100,
        expected_sha256="0" * 64,
        media_type="image",
        upload_expires_at=utcnow(),
    )
    output = MediaEvidenceExtractionOutput(
        evidence_id=attachment.id,
        read_status="partially_readable",
        modality="image",
        observations=[
            MediaObservation(
                frame_ref="image",
                time_offset_seconds=None,
                fact="画面可见道路积水",
                confidence=0.8,
            )
        ],
        location_clues=["东桥"],
        time_clues=["傍晚"],
        risk_signals=["道路积水"],
        manipulation_signals=["局部低清晰度"],
        summary="画面显示道路积水，部分区域清晰度较低。",
        limitations=["无法判断水流速度"],
        confidence=0.72,
    )

    _validate_media_evidence_contract(attachment, output)
    folded = _media_evidence_to_attachment_output(output)

    assert folded.vision_summary.startswith("[vision_policy:no_text_v1]")
    assert "画面观察" in folded.vision_summary
    assert "局部低清晰度" in folded.vision_summary


def test_media_evidence_schema_has_no_ocr_fields() -> None:
    schema = MediaEvidenceExtractionOutput.model_json_schema()

    assert "ocr_items" not in schema["properties"]
    assert "MediaOcrItem" not in schema.get("$defs", {})


def test_attachment_serialization_hides_legacy_text_bearing_summaries() -> None:
    attachment = Attachment(
        id="01900000-0000-7000-8000-000000000102",
        incident_id="incident",
        uploader_device_id="device",
        file_name="scene.jpg",
        declared_mime_type="image/jpeg",
        size_bytes=100,
        expected_sha256="0" * 64,
        media_type="image",
        upload_expires_at=utcnow(),
        vision_summary="旧摘要可能包含画面文字",
        ocr_status="ready",
        ocr_text="旧画面文字",
    )

    hidden = serialize_attachment(attachment)
    assert hidden["ocr_status"] == "not_applicable"
    assert hidden["ocr_text"] is None
    assert hidden["vision_summary"] is None

    attachment.vision_summary = "[vision_policy:no_text_v1]\n画面可见道路积水"
    safe = serialize_attachment(attachment)
    assert safe["vision_summary"] == "画面可见道路积水"


@pytest.mark.asyncio
async def test_stream_upload_checks_hash_and_size(tmp_path: Path) -> None:
    content = image_bytes()
    settings = Settings(
        app_env="test",
        storage_root=tmp_path / "uploads",
        data_dir=tmp_path,
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


def test_conflict_ai_output_allows_no_recommendation_with_human_warning() -> None:
    output = ConflictAnalysisOutput(
        recommended_evidence_id="",
        suggested_conclusion="现有证据不足，无法形成可靠结论，建议人工复核。",
        reasoning_summary="所有证据都缺少可核验上下文。",
        confidence=0.2,
        evidence_assessments=[
            EvidenceAssessment(
                evidence_id="evidence-1",
                authenticity_score=0.5,
                credibility_score=0.2,
                verdict="uncertain",
                reason="缺少观察时间，无法可靠判断当前状态。",
                extracted_facts=[],
            )
        ],
        warnings=["AI 只提供辅助判断，最终结论必须由指挥人员确认。"],
    )

    output.validate_evidence_refs({"evidence-1"})


def test_conflict_ai_output_gets_server_owned_human_warning() -> None:
    output = ConflictAnalysisOutput(
        recommended_evidence_id="evidence-1",
        suggested_conclusion="现有证据倾向支持道路无法通行，仍需人工复核。",
        reasoning_summary="两条现场信息存在冲突，当前结论仅供参考。",
        confidence=0.5,
        evidence_assessments=[
            EvidenceAssessment(
                evidence_id="evidence-1",
                authenticity_score=0.7,
                credibility_score=0.6,
                verdict="likely",
                reason="来源信息完整，但尚未人工核实。",
                extracted_facts=[],
            )
        ],
        warnings=["现场状态仍可能变化。"],
    )

    normalized = _ensure_conflict_human_confirmation_warning(output)

    normalized.validate_evidence_refs({"evidence-1"})
    assert normalized.warnings == [
        "现场状态仍可能变化。",
        "AI 只提供辅助判断，最终结论必须由指挥人员确认。",
    ]
    assert output.warnings == ["现场状态仍可能变化。"]


def test_conflict_ai_invalid_reference_falls_back_without_rebinding() -> None:
    real_ids = [
        "019f9539-95cf-7dc8-b6e8-2d6abff9ae9d",
        "019f9539-95d3-7b21-a405-920685af8932",
    ]
    output = ConflictAnalysisOutput(
        recommended_evidence_id="019f9539-95d3-7dc8-b6e8-2d6abff9ae9d",
        suggested_conclusion="道路无法通行。",
        reasoning_summary="模型错误地拼接了证据 ID。",
        confidence=0.9,
        evidence_assessments=[
            EvidenceAssessment(
                evidence_id=real_ids[0],
                authenticity_score=0.8,
                credibility_score=0.8,
                verdict="supported",
                reason="第一条证据。",
                extracted_facts=["小型车辆可缓慢通行"],
            ),
            EvidenceAssessment(
                evidence_id="019f9539-95d3-7dc8-b6e8-2d6abff9ae9d",
                authenticity_score=0.8,
                credibility_score=0.8,
                verdict="supported",
                reason="错误引用。",
                extracted_facts=["机动车无法通行"],
            ),
        ],
        warnings=[],
    )

    fallback = _conflict_reference_fallback(
        output,
        payload={"evidence": [{"id": evidence_id} for evidence_id in real_ids]},
        allowed_evidence_ids=set(real_ids),
    )

    fallback.validate_evidence_refs(set(real_ids))
    assert fallback.recommended_evidence_id == ""
    assert fallback.confidence == 0.2
    assert [item.evidence_id for item in fallback.evidence_assessments] == real_ids
    assert all(item.verdict == "uncertain" for item in fallback.evidence_assessments)
    assert all(not item.extracted_facts for item in fallback.evidence_assessments)
    assert "019f9539-95d3-7dc8-b6e8-2d6abff9ae9d" not in fallback.model_dump_json()


def test_report_refinement_rejects_unknown_or_duplicate_risk_tags() -> None:
    with pytest.raises(ValidationError):
        ReportRefinementOutput(
            refined_content="【需要救援】桥边有人被困。\n【位置】大关桥",
            risk_hint="检测到明确风险。",
            suggest_urgent=True,
            detected_risk_tags=["injury"],
            confidence=0.8,
        )
    with pytest.raises(ValidationError):
        ReportRefinementOutput(
            refined_content="【需要救援】桥边有人被困。\n【位置】大关桥",
            risk_hint="检测到明确风险。",
            suggest_urgent=True,
            detected_risk_tags=["trapped_people", "trapped_people"],
            confidence=0.8,
        )


@pytest.mark.asyncio
async def test_report_refinement_context_sends_owned_visuals_without_ocr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'refinement-media.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        app_env="test",
        ai_provider="fake",
        storage_root=tmp_path / "uploads",
        max_attachments_per_report=5,
        media_max_parallel_uploads=2,
    )
    settings.ensure_directories()
    thumbnail = settings.storage_root / "thumbnails" / "scene.jpg"
    thumbnail.parent.mkdir(parents=True, exist_ok=True)
    thumbnail.write_bytes(image_bytes())
    fetched_keys: list[str] = []

    async def fake_fetch(
        object_key: str,
        *,
        max_bytes: int,
        settings: Settings,
    ) -> bytes:
        del max_bytes, settings
        fetched_keys.append(object_key)
        return image_bytes()

    monkeypatch.setattr("crisis_mosaic.services.ai.fetch_object_bytes", fake_fetch)
    actor = Actor(
        subject_type="device",
        subject_id="device",
        role="resident",
        token_version=1,
        incident_ids=frozenset({"incident"}),
    )
    async with maker() as session:
        incident = Incident(id="incident", name="Test", status="active")
        report = Report(
            id="report",
            incident_id=incident.id,
            reporter_device_id=actor.subject_id,
            category="rescue",
            content_original="有人需要救援",
            content_display="有人需要救援",
            location_text="东桥",
            revision=2,
        )
        image = Attachment(
            id="image",
            incident_id=incident.id,
            uploader_device_id=actor.subject_id,
            report_id=report.id,
            file_name="scene.jpg",
            declared_mime_type="image/jpeg",
            media_type="image",
            storage_provider="local_proxy",
            size_bytes=100,
            expected_sha256="1" * 64,
            sha256="1" * 64,
            thumbnail_path=str(thumbnail),
            metadata_status="ready",
            malware_scan_status="clean",
            ocr_status="ready",
            ocr_text="不得进入上下文的历史 OCR 文本",
            vision_status="succeeded",
            vision_summary="旧视觉摘要可能包含画面文字，不得复用",
            upload_expires_at=utcnow(),
        )
        video = Attachment(
            id="video",
            incident_id=incident.id,
            uploader_device_id=actor.subject_id,
            report_id=report.id,
            file_name="scene.mp4",
            declared_mime_type="video/mp4",
            media_type="video",
            storage_provider="qiniu_kodo",
            object_key="safe/video.mp4",
            size_bytes=1000,
            expected_sha256="2" * 64,
            sha256=None,
            etag="server-etag",
            duration_ms=10_000,
            metadata_status="ready",
            malware_scan_status="clean",
            vision_status="unavailable",
            transcript_status="succeeded",
            transcript_text="音轨中有人呼救",
            keyframe_status="ready",
            upload_expires_at=utcnow(),
        )
        session.add_all([incident, report, image, video])
        await session.commit()

        request = ReportRefinementRequest(
            incident_id=incident.id,
            report_id=report.id,
            report_revision=report.revision,
            category="rescue",
            content="有人需要救援",
            location_text="东桥",
            attachment_ids=[image.id, video.id],
        )
        context, visuals = await build_report_refinement_context(
            session, request, actor, settings
        )

        serialized = canonical_json(context)
        assert "不得进入上下文的历史 OCR 文本" not in serialized
        assert "旧视觉摘要可能包含画面文字" not in serialized
        assert "ocr_text" not in serialized
        assert context["attachments"][1]["transcript_text"] == "音轨中有人呼救"
        assert context["attachments"][0]["model_image_indices"] == [1]
        assert context["attachments"][1]["model_image_indices"] == [2, 3, 4]
        assert len(visuals) == 4
        assert len(fetched_keys) == 3

        with pytest.raises(ApiError, match="报告上下文不存在或已过期"):
            await build_report_refinement_context(
                session,
                request.model_copy(update={"report_revision": 1}),
                actor,
                settings,
            )
    await engine.dispose()


@pytest.mark.asyncio
async def test_report_refinement_attempts_all_requested_images_with_independent_frame_cap(
    tmp_path: Path,
) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'all-media.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        app_env="test",
        ai_provider="fake",
        storage_root=tmp_path / "uploads",
        max_attachments_per_report=5,
        max_image_bytes=10 * 1024 * 1024,
    )
    settings.ensure_directories()
    actor = Actor(
        subject_type="device",
        subject_id="device",
        role="resident",
        token_version=1,
        incident_ids=frozenset({"incident"}),
    )
    image_contents = [b"small-image"] * 6
    image_contents[0] = b"x" * (750 * 1024)
    attachments: list[Attachment] = []
    for index, content in enumerate(image_contents):
        path = settings.storage_root / "thumbnails" / f"scene-{index}.jpg"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        attachments.append(
            Attachment(
                id=f"image-{index}",
                incident_id="incident",
                uploader_device_id=actor.subject_id,
                file_name=path.name,
                declared_mime_type="image/jpeg",
                media_type="image",
                storage_provider="local_proxy",
                size_bytes=len(content),
                expected_sha256=str(index) * 64,
                thumbnail_path=str(path),
                metadata_status="ready",
                malware_scan_status="clean",
                vision_status="unavailable",
                upload_expires_at=utcnow(),
            )
        )

    async with maker() as session:
        session.add(Incident(id="incident", name="Test", status="active"))
        session.add_all(attachments)
        await session.commit()
        request = ReportRefinementRequest(
            incident_id="incident",
            category="rescue",
            content="Need help",
            location_text="Bridge",
            attachment_ids=[item.id for item in attachments],
        )

        context, visuals = await build_report_refinement_context(
            session, request, actor, settings
        )

    assert len(visuals[0]) > 699 * 1024
    assert context["attachments"][0]["model_image_indices"] == [1]
    assert context["attachments"][5]["model_image_indices"] == [6]
    assert len(visuals) == 6
    await engine.dispose()


@pytest.mark.asyncio
async def test_report_refinement_allocates_video_frames_round_robin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'round-robin.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        app_env="test",
        ai_provider="fake",
        storage_root=tmp_path / "uploads",
        max_image_bytes=800,
    )
    settings.ensure_directories()
    actor = Actor(
        subject_type="device",
        subject_id="device",
        role="resident",
        token_version=1,
        incident_ids=frozenset({"incident"}),
    )

    async def fake_read_visual(
        attachment: Attachment,
        settings: Settings,
        *,
        max_bytes_per_frame: int,
    ) -> tuple[list[bytes], str | None]:
        del settings
        assert max_bytes_per_frame == 800
        return [attachment.id.encode() * 200] * 3, None

    monkeypatch.setattr(
        "crisis_mosaic.services.ai._read_report_attachment_visual", fake_read_visual
    )
    videos = [
        Attachment(
            id=f"v{index}",
            incident_id="incident",
            uploader_device_id=actor.subject_id,
            file_name=f"v{index}.mp4",
            declared_mime_type="video/mp4",
            media_type="video",
            storage_provider="qiniu_kodo",
            object_key=f"v{index}.mp4",
            size_bytes=100,
            expected_sha256=str(index) * 64,
            duration_ms=10_000,
            metadata_status="ready",
            malware_scan_status="clean",
            keyframe_status="ready",
            vision_status="unavailable",
            upload_expires_at=utcnow(),
        )
        for index in range(2)
    ]
    async with maker() as session:
        session.add(Incident(id="incident", name="Test", status="active"))
        session.add_all(videos)
        await session.commit()
        request = ReportRefinementRequest(
            incident_id="incident",
            category="rescue",
            content="Need help",
            location_text="Bridge",
            attachment_ids=[item.id for item in videos],
        )

        context, visuals = await build_report_refinement_context(
            session, request, actor, settings
        )

    assert len(visuals) == 2
    assert context["attachments"][0]["model_image_indices"] == [1]
    assert context["attachments"][1]["model_image_indices"] == [2]
    await engine.dispose()


@pytest.mark.asyncio
async def test_video_visual_read_keeps_successful_frames_when_one_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(app_env="test", ai_provider="fake")
    attachment = Attachment(
        id="video",
        incident_id="incident",
        uploader_device_id="device",
        file_name="video.mp4",
        declared_mime_type="video/mp4",
        media_type="video",
        storage_provider="qiniu_kodo",
        object_key="video.mp4",
        size_bytes=100,
        expected_sha256="1" * 64,
        duration_ms=10_000,
        metadata_status="ready",
        malware_scan_status="clean",
        keyframe_status="ready",
        vision_status="unavailable",
        upload_expires_at=utcnow(),
    )

    async def fake_fetch(
        object_key: str,
        *,
        max_bytes: int,
        settings: Settings,
    ) -> bytes:
        del max_bytes, settings
        if "offset/5" in object_key:
            raise ApiError(502, "FRAME_FETCH_FAILED", "frame failed")
        return object_key.encode()

    monkeypatch.setattr("crisis_mosaic.services.ai.fetch_object_bytes", fake_fetch)

    frames, limitation = await _read_report_attachment_visual(
        attachment,
        settings,
        max_bytes_per_frame=2 * 1024 * 1024,
    )

    assert len(frames) == 2
    assert limitation is not None
    assert "partial" in limitation
    assert "FRAME_FETCH_FAILED" in limitation


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


def test_command_brief_summary_allows_time_and_year_numbers() -> None:
    snapshot = {
        "metrics": {
            "active_report_count": 28,
            "urgent_report_count": 4,
            "open_conflict_count": 2,
            "open_blind_spot_count": 3,
        }
    }
    output = CommandBriefOutput(
        headline="人员救援与道路通行仍存在关键风险",
        summary="截至 2026-07-25 18:44，当前共有 29 条有效上报，其中 4 条标记紧急。",
        recommendations=[
            BriefRecommendation(
                text="优先人工复核大关桥上报。",
                severity="high",
                source_refs=["report:known"],
            )
        ],
        confidence=0.6,
    )
    # 统计数字一致性校验已移除，年份/日期/时刻等数字不再触发拦截。
    _validate_command_brief_contract(snapshot, output)


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
        assert saved.prompt_version == REPORT_REFINEMENT_PROMPT_VERSION
        assert saved.prompt_sha256 is not None and len(saved.prompt_sha256) == 64
        assert saved.schema_valid is True
        assert saved.reference_valid is True
        assert result.suggest_urgent is True
        assert result.refined_content.startswith("【需要救援】")
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
            prompt_version=CONFLICT_ANALYSIS_PROMPT_VERSION,
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
            "vision_context",
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

        analysis.prompt_version = "cm-conflict-analysis-v1.0.0"
        conflict.status = "open"
        await session.flush()
        refreshed = await enqueue_conflict_analysis(
            session,
            conflict=conflict,
            revision=1,
            evidence_ids=None,
            actor=actor,
            settings=settings,
        )
        assert refreshed.id != analysis.id
        assert refreshed.prompt_version == CONFLICT_ANALYSIS_PROMPT_VERSION
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
