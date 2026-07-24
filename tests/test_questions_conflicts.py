from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from crisis_mosaic.dependencies import get_actor
from crisis_mosaic.errors import ApiError, install_error_handlers
from crisis_mosaic.models import (
    AnonymousDevice,
    Base,
    BlindSpot,
    ConflictCase,
    ConflictEvidence,
    DirectedAnswer,
    DirectedQuestion,
    FactRecord,
    FactVersion,
    Incident,
    InformationFragment,
    MapFeature,
    OutboxEvent,
    Report,
)
from crisis_mosaic.routers.questions import router as questions_router
from crisis_mosaic.schemas.conflicts import (
    ConflictDecisionRequest,
    EvidenceDisposition,
    EvidenceReference,
)
from crisis_mosaic.schemas.questions import DirectedQuestionCreate, QuestionOption
from crisis_mosaic.security import Actor
from crisis_mosaic.services.conflicts import (
    add_evidence,
    decide_conflict,
    valid_answer_consensus,
)


@pytest.fixture
async def session_maker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def test_question_options_must_be_unique() -> None:
    with pytest.raises(ValueError):
        DirectedQuestionCreate(
            blind_spot_id="blind",
            title="Is the bridge open?",
            location_text="Bridge",
            options=[
                QuestionOption(id="open", label="Open"),
                QuestionOption(id="open", label="Also open"),
            ],
        )


def test_evidence_reference_rejects_client_snapshot() -> None:
    with pytest.raises(ValidationError, match="snapshot"):
        EvidenceReference.model_validate(
            {
                "kind": "fragment",
                "source_id": "fragment-1",
                "snapshot": {"claim_value": "client-controlled"},
            }
        )


@pytest.mark.asyncio
async def test_cross_incident_conflict_evidence_is_rejected(
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    async with session_maker() as session:
        first_incident = Incident(id="incident-a", name="First", status="active")
        second_incident = Incident(id="incident-b", name="Second", status="preparing")
        case = ConflictCase(
            id="conflict-a",
            incident_id=first_incident.id,
            fact_key="bridge.passability",
            title="Bridge status",
            topic="passability",
            location_text="Daguan Bridge",
        )
        foreign_fragment = InformationFragment(
            id="fragment-b",
            incident_id=second_incident.id,
            source_type="operator",
            topic="passability",
            claim_key="bridge.passability",
            claim_value="blocked",
            label="Blocked",
            description="Foreign incident evidence",
            location_text="Daguan Bridge",
        )
        session.add_all([first_incident, second_incident, case, foreign_fragment])
        await session.flush()

        with pytest.raises(ApiError) as error:
            await add_evidence(
                session,
                case,
                [EvidenceReference(kind="fragment", source_id=foreign_fragment.id)],
            )

        assert error.value.code == "CROSS_INCIDENT_EVIDENCE"
        assert await session.scalar(select(func.count(ConflictEvidence.id))) == 0


@pytest.mark.asyncio
async def test_answer_upsert_creates_fragment_not_report_and_resolves_consensus(
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    async with session_maker() as session:
        incident = Incident(id="incident-1", name="Flood", status="active")
        first_device = AnonymousDevice(
            id="device-1",
            installation_id_hash="a" * 64,
            platform="test",
        )
        second_device = AnonymousDevice(
            id="device-2",
            installation_id_hash="b" * 64,
            platform="test",
        )
        blind = BlindSpot(
            id="blind-1",
            incident_id=incident.id,
            claim_key="bridge.passability",
            title="Bridge passability",
            location_text="Bridge",
            min_valid_answers=2,
        )
        question = DirectedQuestion(
            id="question-1",
            incident_id=incident.id,
            blind_spot_id=blind.id,
            title="Can vehicles cross?",
            location_text="Bridge",
            options=[
                {"id": "open", "label": "Open"},
                {"id": "blocked", "label": "Blocked"},
                {"id": "unknown", "label": "Unknown"},
            ],
            status="published",
        )
        session.add_all([incident, first_device, second_device, blind, question])
        await session.commit()

    actor_holder = {
        "actor": Actor(
            subject_type="device",
            subject_id="device-1",
            role="resident",
            token_version=1,
            incident_ids=frozenset({"incident-1"}),
        )
    }

    async def session_override() -> AsyncIterator[AsyncSession]:
        async with session_maker() as session:
            yield session

    async def actor_override() -> Actor:
        return actor_holder["actor"]

    app = FastAPI()
    install_error_handlers(app)
    app.include_router(questions_router, prefix="/api/v1")
    app.dependency_overrides[get_actor] = actor_override
    from crisis_mosaic.db import get_session

    app.dependency_overrides[get_session] = session_override
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.put(
            "/api/v1/directed-questions/question-1/my-answer",
            headers={"X-Incident-Id": "incident-1"},
            json={"option_id": "open", "revision": 0},
        )
        assert first.status_code == 200, first.text
        assert first.json()["data"]["blind_spot"]["status"] == "open"
        update = await client.put(
            "/api/v1/directed-questions/question-1/my-answer",
            headers={"X-Incident-Id": "incident-1"},
            json={"option_id": "open", "revision": 1},
        )
        assert update.status_code == 200, update.text
        assert update.json()["data"]["answer"]["revision"] == 2
        actor_holder["actor"] = Actor(
            subject_type="device",
            subject_id="device-2",
            role="resident",
            token_version=1,
            incident_ids=frozenset({"incident-1"}),
        )
        second = await client.put(
            "/api/v1/directed-questions/question-1/my-answer",
            headers={"X-Incident-Id": "incident-1"},
            json={"option_id": "open", "revision": 0},
        )
        assert second.status_code == 200, second.text
        assert second.json()["data"]["blind_spot"]["status"] == "resolved"

    async with session_maker() as session:
        assert (await session.scalar(select(func.count(DirectedAnswer.id)))) == 2
        assert (await session.scalar(select(func.count(InformationFragment.id)))) == 2
        assert await session.scalar(select(func.count(Report.id))) == 0
        assert (
            await session.scalar(
                select(DirectedAnswer.revision).where(
                    DirectedAnswer.id == first.json()["data"]["answer"]["id"]
                )
            )
            == 2
        )


@pytest.mark.asyncio
async def test_unknown_answers_do_not_count_for_consensus(
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    async with session_maker() as session:
        session.add_all(
            [
                DirectedAnswer(
                    question_id="question",
                    device_id="device-1",
                    option_id="unknown",
                    semantic_value="unknown",
                    answer_text="Unknown",
                ),
                DirectedAnswer(
                    question_id="question",
                    device_id="device-2",
                    option_id="blocked",
                    semantic_value="blocked",
                    answer_text="Blocked",
                ),
            ]
        )
        await session.flush()
        value, count, distinct = await valid_answer_consensus(session, "question")
        assert (value, count, distinct) == ("blocked", 1, {"blocked"})


@pytest.mark.asyncio
async def test_decision_requires_all_evidence_and_atomically_versions_fact(
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    async with session_maker() as session:
        incident = Incident(id="incident-2", name="Flood", status="preparing")
        case = ConflictCase(
            id="conflict-1",
            incident_id=incident.id,
            fact_key="road.passability",
            title="Road conflict",
            topic="passability",
            location_text="River Road",
            latitude=30.0,
            longitude=120.0,
            coordinate_system="gcj02",
        )
        first = InformationFragment(
            id="fragment-1",
            incident_id=incident.id,
            source_type="operator",
            topic="passability",
            claim_key="road.passability",
            claim_value="open",
            label="Open",
            description="Road is open",
            location_text="River Road",
        )
        second = InformationFragment(
            id="fragment-2",
            incident_id=incident.id,
            source_type="operator",
            topic="passability",
            claim_key="road.passability",
            claim_value="blocked",
            label="Blocked",
            description="Road is blocked",
            location_text="River Road",
        )
        session.add_all([incident, case, first, second])
        await session.flush()
        evidence = await add_evidence(
            session,
            case,
            [
                EvidenceReference(kind="fragment", source_id=first.id),
                EvidenceReference(kind="fragment", source_id=second.id),
            ],
        )
        await session.commit()

    actor = Actor(
        subject_type="account",
        subject_id="operator",
        role="operator",
        token_version=1,
        incident_ids=frozenset({"incident-2"}),
    )
    async with session_maker() as session:
        case = await session.get(ConflictCase, "conflict-1")
        assert case is not None
        incomplete = ConflictDecisionRequest(
            revision=1,
            decision="accept_evidence",
            evidence_decisions=[
                EvidenceDisposition(evidence_id=evidence[0].id, disposition="accepted")
            ],
            conclusion="Road is open",
        )
        with pytest.raises(ApiError) as error:
            await decide_conflict(
                session,
                case=case,
                payload=incomplete,
                actor=actor,
                request_id="request-1",
            )
        assert error.value.code == "INCOMPLETE_EVIDENCE_DISPOSITION"
        await session.rollback()

    async with session_maker() as session:
        case = await session.get(ConflictCase, "conflict-1")
        assert case is not None
        payload = ConflictDecisionRequest(
            revision=1,
            decision="accept_evidence",
            evidence_decisions=[
                EvidenceDisposition(evidence_id=evidence[0].id, disposition="rejected"),
                EvidenceDisposition(evidence_id=evidence[1].id, disposition="accepted"),
            ],
            conclusion="Road is blocked",
            expected_fact_revision=0,
            confidence=0.9,
        )
        _, fact, version, event_ids = await decide_conflict(
            session,
            case=case,
            payload=payload,
            actor=actor,
            request_id="request-2",
        )
        await session.commit()
        assert case.status == "resolved"
        assert fact.current_revision == 1
        assert version.statement == "Road is blocked"
        assert len(event_ids) == 2

    async with session_maker() as session:
        assert await session.scalar(select(func.count(FactRecord.id))) == 1
        assert await session.scalar(select(func.count(FactVersion.id))) == 1
        # Two evidence fragments, the conflict, and the resolved fact all have
        # independent map projections after the atomic decision.
        assert await session.scalar(select(func.count(MapFeature.id))) == 4
        assert await session.scalar(select(func.count(OutboxEvent.id))) == 3
        current_evidence_rows = (
            await session.scalars(
                select(ConflictEvidence).where(
                    ConflictEvidence.conflict_id == "conflict-1",
                    ConflictEvidence.is_current.is_(True),
                )
            )
        ).all()
        assert len(current_evidence_rows) == 2
