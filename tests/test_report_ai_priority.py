from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from crisis_mosaic.models import AiAnalysis, AnonymousDevice, Base, Incident
from crisis_mosaic.schemas.reports import ReportCreate
from crisis_mosaic.security import Actor
from crisis_mosaic.services.reports import ai_priority_from_refinement, create_report


def _analysis(*, suggest_urgent: bool, confidence: object = None) -> AiAnalysis:
    output: dict[str, object] = {"suggest_urgent": suggest_urgent}
    if confidence is not None:
        output["confidence"] = confidence
    return AiAnalysis(output=output)


@pytest.mark.parametrize("confidence", [0.0, 0.39, 0.70, 1.0, None])
def test_non_urgent_ai_suggestion_keeps_category_default(confidence: object) -> None:
    assert (
        ai_priority_from_refinement(
            _analysis(suggest_urgent=False, confidence=confidence),
        )
        is None
    )


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [
        (1.0, "high"),
        (0.70, "high"),
        (0.6999, None),
        (0.40, None),
        (0.0, None),
        (None, None),
        ("0.91", None),
        (True, None),
    ],
)
def test_urgent_ai_suggestion_requires_confidence_threshold(
    confidence: object,
    expected: str | None,
) -> None:
    assert (
        ai_priority_from_refinement(
            _analysis(suggest_urgent=True, confidence=confidence),
        )
        == expected
    )


def test_missing_analysis_or_output_has_no_ai_priority() -> None:
    assert ai_priority_from_refinement(None) is None
    assert ai_priority_from_refinement(AiAnalysis(output=None)) is None


def test_create_report_persists_high_priority_from_owned_ai_refinement() -> None:
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
                    refinement = AiAnalysis(
                        incident_id=incident.id,
                        analysis_type="report_refinement",
                        status="succeeded",
                        input_snapshot={},
                        output={"suggest_urgent": True, "confidence": 0.82},
                        prompt_version="test-v1",
                        created_by_type="device",
                        created_by_id=device.id,
                    )
                    session.add(refinement)
                    await session.flush()

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
                            content_original="Road is blocked",
                            location={"text": "Daguan Bridge"},
                            ai_refinement_id=refinement.id,
                        ),
                    )

                    assert report.priority == "high"
                    assert report.priority_source == "ai"
                    assert report.ai_refinement_id == refinement.id
        finally:
            await engine.dispose()

    asyncio.run(scenario())
