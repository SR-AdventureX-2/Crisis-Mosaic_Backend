from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from crisis_mosaic.domain.priority import effective_priority
from crisis_mosaic.errors import ApiError
from crisis_mosaic.models import AiAnalysis, AnonymousDevice, Base, Incident
from crisis_mosaic.schemas.reports import ReportCreate
from crisis_mosaic.security import Actor
from crisis_mosaic.services.reports import (
    ai_priority_from_refinement,
    create_report,
    validate_report_refinement,
)
from crisis_mosaic.utils import canonical_json, sha256_text


def _analysis(
    *,
    suggest_urgent: bool,
    confidence: object = None,
    risk_tags: list[str] | None = None,
) -> AiAnalysis:
    output: dict[str, object] = {
        "suggest_urgent": suggest_urgent,
        "detected_risk_tags": risk_tags or [],
    }
    if confidence is not None:
        output["confidence"] = confidence
    return AiAnalysis(output=output)


@pytest.mark.parametrize("category", ["rescue", "medical", "water", "food", "shelter", "road"])
def test_category_alone_never_raises_priority(category: str) -> None:
    assert effective_priority(category, is_urgent=False) == ("low", "category_default")


@pytest.mark.parametrize(
    ("suggest_urgent", "confidence", "risk_tags", "expected"),
    [
        (False, 0.99, [], "low"),  # greeting or random content
        (True, 0.99, [], "low"),  # confidence and urgency cannot replace evidence
        (True, 0.99, ["elderly"], "low"),  # vulnerability alone is not danger
        (False, 0.75, ["road_blocked"], "medium"),
        (True, 0.99, ["road_blocked"], "medium"),
        (False, 0.99, ["trapped_people"], "medium"),
        (True, 0.85, ["trapped_people"], "high"),
        (True, 0.95, ["injured_people"], "high"),
        (True, 0.8499, ["injured_people"], "medium"),
        (True, 0.7499, ["injured_people"], "low"),
        (True, None, ["injured_people"], "low"),
        (True, "0.95", ["injured_people"], "low"),
        (True, True, ["injured_people"], "low"),
        (True, 0.99, ["unknown_risk"], "low"),
    ],
)
def test_ai_priority_requires_supported_risk_and_conservative_thresholds(
    suggest_urgent: bool,
    confidence: object,
    risk_tags: list[str],
    expected: str | None,
) -> None:
    assert (
        ai_priority_from_refinement(
            _analysis(
                suggest_urgent=suggest_urgent,
                confidence=confidence,
                risk_tags=risk_tags,
            ),
        )
        == expected
    )


def test_missing_analysis_or_output_has_no_ai_priority() -> None:
    assert ai_priority_from_refinement(None) is None
    assert ai_priority_from_refinement(AiAnalysis(output=None)) is None


def test_create_report_persists_evidence_based_ai_priority() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with factory() as session:
                async with session.begin():
                    incident = Incident(
                        alias="ai-priority-incident",
                        name="AI priority test",
                        status="active",
                    )
                    device = AnonymousDevice(
                        installation_id_hash="d" * 64,
                        platform="android",
                    )
                    session.add_all([incident, device])
                    await session.flush()
                    actor = Actor(
                        subject_type="device",
                        subject_id=device.id,
                        role="resident",
                        token_version=1,
                        incident_ids=frozenset({incident.id}),
                    )
                    context = {
                        "request_context": {
                            "incident_id": incident.id,
                            "language": "zh-CN",
                            "timezone": "Asia/Shanghai",
                        },
                        "report": {
                            "category": "road",
                            "content": "Road is blocked",
                            "location_text": "Daguan Bridge",
                        },
                    }
                    refined_content = "【道路情况】Road is blocked\n【位置】Daguan Bridge"
                    refinement = AiAnalysis(
                        incident_id=incident.id,
                        analysis_type="report_refinement",
                        status="succeeded",
                        input_snapshot=context,
                        context_package=context,
                        context_sha256=sha256_text(canonical_json(context)),
                        output={
                            "refined_content": refined_content,
                            "suggest_urgent": True,
                            "detected_risk_tags": ["road_blocked"],
                            "confidence": 0.82,
                        },
                        prompt_version="test-v1",
                        created_by_type="device",
                        created_by_id=device.id,
                    )
                    session.add(refinement)
                    await session.flush()

                    validated_original = await validate_report_refinement(
                        session,
                        analysis_id=refinement.id,
                        incident_id=incident.id,
                        actor=actor,
                        category="road",
                        content="Road is blocked",
                        location_text="Daguan Bridge",
                        attachment_ids=[],
                    )
                    assert validated_original is refinement
                    with pytest.raises(ApiError) as wrong_attachment:
                        await validate_report_refinement(
                            session,
                            analysis_id=refinement.id,
                            incident_id=incident.id,
                            actor=actor,
                            category="road",
                            content="Road is blocked",
                            location_text="Daguan Bridge",
                            attachment_ids=["missing"],
                        )
                    assert wrong_attachment.value.code == "ATTACHMENT_NOT_READY"

                    report = await create_report(
                        session,
                        incident=incident,
                        actor=actor,
                        payload=ReportCreate(
                            category="road",
                            reporter={
                                "full_name": "Zhang Ming",
                                "mobile": "13800138000",
                            },
                            content_original=refined_content,
                            location={"text": "Daguan Bridge"},
                            ai_refinement_id=refinement.id,
                        ),
                    )

                    assert report.priority == "medium"
                    assert report.priority_source == "ai"
                    assert report.ai_refinement_id == refinement.id
                    with pytest.raises(ApiError) as mismatch:
                        await validate_report_refinement(
                            session,
                            analysis_id=refinement.id,
                            incident_id=incident.id,
                            actor=actor,
                            category=report.category,
                            content=report.content_original,
                            location_text=report.location_text,
                            attachment_ids=[],
                            report_id=report.id,
                            report_revision=report.revision,
                            bound_report_id=report.id,
                        )
                    assert mismatch.value.code == "AI_REFINEMENT_CONTEXT_MISMATCH"

                    edit_context = {
                        **context,
                        "request_context": {
                            **context["request_context"],
                            "report_id": report.id,
                            "report_revision": report.revision,
                        },
                        "attachments": [],
                    }
                    edit_refinement = AiAnalysis(
                        incident_id=incident.id,
                        analysis_type="report_refinement",
                        status="succeeded",
                        input_snapshot=edit_context,
                        context_package=edit_context,
                        context_sha256=sha256_text(canonical_json(edit_context)),
                        output={
                            "refined_content": refined_content,
                            "suggest_urgent": True,
                            "detected_risk_tags": ["road_blocked"],
                            "confidence": 0.82,
                        },
                        prompt_version="test-v1",
                        created_by_type="device",
                        created_by_id=device.id,
                    )
                    session.add(edit_refinement)
                    await session.flush()
                    with pytest.raises(ApiError) as wrong_revision:
                        await validate_report_refinement(
                            session,
                            analysis_id=edit_refinement.id,
                            incident_id=incident.id,
                            actor=actor,
                            category=report.category,
                            content=report.content_original,
                            location_text=report.location_text,
                            attachment_ids=[],
                            report_id=report.id,
                            report_revision=report.revision + 1,
                            bound_report_id=report.id,
                        )
                    assert wrong_revision.value.code == "AI_REFINEMENT_CONTEXT_MISMATCH"

                    reused_after_revision_advance = await validate_report_refinement(
                        session,
                        analysis_id=edit_refinement.id,
                        incident_id=incident.id,
                        actor=actor,
                        category=report.category,
                        content=report.content_original,
                        location_text=report.location_text,
                        attachment_ids=[],
                        report_id=report.id,
                        report_revision=report.revision + 1,
                        bound_report_id=report.id,
                        use_stored_report_context=True,
                    )
                    assert reused_after_revision_advance is edit_refinement

                    legacy_refinement = AiAnalysis(
                        incident_id=incident.id,
                        analysis_type="report_refinement",
                        status="succeeded",
                        input_snapshot=context,
                        context_package=None,
                        context_sha256=None,
                        output={
                            "refined_content": refined_content,
                            "suggest_urgent": False,
                            "confidence": 0.8,
                        },
                        prompt_version="cm-report-refinement-v1.0.0",
                        created_by_type="device",
                        created_by_id=device.id,
                    )
                    session.add(legacy_refinement)
                    await session.flush()

                    validated_legacy = await validate_report_refinement(
                        session,
                        analysis_id=legacy_refinement.id,
                        incident_id=incident.id,
                        actor=actor,
                        category="road",
                        content="Road is blocked",
                        location_text="Daguan Bridge",
                        attachment_ids=[],
                    )
                    assert validated_legacy is legacy_refinement

                    for category, content, location_text in (
                        ("rescue", "Road is blocked", "Daguan Bridge"),
                        ("road", "Road is passable", "Daguan Bridge"),
                        ("road", "Road is blocked", "Another bridge"),
                    ):
                        with pytest.raises(ApiError) as legacy_context_mismatch:
                            await validate_report_refinement(
                                session,
                                analysis_id=legacy_refinement.id,
                                incident_id=incident.id,
                                actor=actor,
                                category=category,
                                content=content,
                                location_text=location_text,
                                attachment_ids=[],
                            )
                        assert (
                            legacy_context_mismatch.value.code == "AI_REFINEMENT_CONTEXT_MISMATCH"
                        )

                    other_actor = Actor(
                        subject_type="device",
                        subject_id="other-device",
                        role="resident",
                        token_version=1,
                        incident_ids=frozenset({incident.id}),
                    )
                    with pytest.raises(ApiError) as legacy_wrong_owner:
                        await validate_report_refinement(
                            session,
                            analysis_id=legacy_refinement.id,
                            incident_id=incident.id,
                            actor=other_actor,
                            category="road",
                            content="Road is blocked",
                            location_text="Daguan Bridge",
                            attachment_ids=[],
                        )
                    assert legacy_wrong_owner.value.code == "AI_REFINEMENT_ACCESS_DENIED"

                    legacy_refinement.input_snapshot = {**context, "attachments": []}
                    with pytest.raises(ApiError) as legacy_with_attachment_context:
                        await validate_report_refinement(
                            session,
                            analysis_id=legacy_refinement.id,
                            incident_id=incident.id,
                            actor=actor,
                            category="road",
                            content="Road is blocked",
                            location_text="Daguan Bridge",
                            attachment_ids=[],
                        )
                    assert legacy_with_attachment_context.value.code == "AI_REFINEMENT_INVALID"

                    legacy_refinement.input_snapshot = {
                        **context,
                        "request_context": {
                            **context["request_context"],
                            "report_id": report.id,
                            "report_revision": report.revision,
                        },
                    }
                    with pytest.raises(ApiError) as legacy_with_report_context:
                        await validate_report_refinement(
                            session,
                            analysis_id=legacy_refinement.id,
                            incident_id=incident.id,
                            actor=actor,
                            category="road",
                            content="Road is blocked",
                            location_text="Daguan Bridge",
                            attachment_ids=[],
                        )
                    assert legacy_with_report_context.value.code == "AI_REFINEMENT_INVALID"
        finally:
            await engine.dispose()

    asyncio.run(scenario())
