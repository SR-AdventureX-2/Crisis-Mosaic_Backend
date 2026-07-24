from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

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
    Attachment,
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
from crisis_mosaic.routers.questions import replace_answer_attachments, target_matches
from crisis_mosaic.routers.questions import router as questions_router
from crisis_mosaic.schemas.conflicts import (
    ConflictDecisionRequest,
    EvidenceDisposition,
    EvidenceReference,
)
from crisis_mosaic.schemas.questions import (
    DirectedAnswerPut,
    DirectedQuestionCreate,
    QuestionOption,
)
from crisis_mosaic.security import Actor
from crisis_mosaic.services.conflicts import (
    add_evidence,
    decide_conflict,
    valid_answer_consensus,
)
from crisis_mosaic.utils import utcnow


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


def test_geojson_point_question_matches_nearby_resident_location() -> None:
    question = DirectedQuestion(
        target_geometry={
            "type": "Point",
            "coordinates": [120.1558, 30.3132],
            "radius_m": 500,
            "coordinate_system": "gcj02",
        }
    )

    assert target_matches(
        question,
        latitude=30.3132,
        longitude=120.1558,
        coordinate_system="gcj02",
        region_code=None,
    )
    assert not target_matches(
        question,
        latitude=30.325,
        longitude=120.154,
        coordinate_system="gcj02",
        region_code=None,
    )


def test_directed_answer_attachment_ids_must_be_unique() -> None:
    with pytest.raises(ValidationError, match="attachment_ids must not contain duplicates"):
        DirectedAnswerPut(
            option_id="open",
            revision=0,
            attachment_ids=["attachment-1", "attachment-1"],
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
        first_attachment = Attachment(
            id="attachment-1",
            incident_id=incident.id,
            uploader_device_id=first_device.id,
            file_name="first.jpg",
            declared_mime_type="image/jpeg",
            mime_type="image/jpeg",
            size_bytes=100,
            expected_sha256="1" * 64,
            sha256="1" * 64,
            sanitized_path="C:/safe/first.jpg",
            metadata_status="ready",
            malware_scan_status="clean",
            upload_expires_at=utcnow() + timedelta(hours=1),
            uploaded_at=utcnow(),
        )
        second_attachment = Attachment(
            id="attachment-2",
            incident_id=incident.id,
            uploader_device_id=first_device.id,
            file_name="second.jpg",
            declared_mime_type="image/jpeg",
            mime_type="image/jpeg",
            size_bytes=200,
            expected_sha256="2" * 64,
            sha256="2" * 64,
            sanitized_path="C:/safe/second.jpg",
            metadata_status="ready",
            malware_scan_status="clean",
            upload_expires_at=utcnow() + timedelta(hours=1),
            uploaded_at=utcnow(),
        )
        session.add_all(
            [
                incident,
                first_device,
                second_device,
                blind,
                question,
                first_attachment,
                second_attachment,
            ]
        )
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
            json={
                "option_id": "open",
                "revision": 0,
                "attachment_ids": ["attachment-1"],
            },
        )
        assert first.status_code == 200, first.text
        assert first.json()["data"]["blind_spot"]["status"] == "open"
        assert first.json()["data"]["answer"]["attachment_ids"] == ["attachment-1"]
        assert first.json()["data"]["answer"]["attachments"][0]["status"] == "ready"
        assert first.json()["data"]["answer"]["attachments"][0]["content_url"].endswith(
            "/attachment-1/content"
        )
        active = await client.get(
            "/api/v1/incidents/incident-1/directed-questions/active",
            headers={"X-Incident-Id": "incident-1"},
        )
        assert active.status_code == 200, active.text
        assert active.json()["data"][0]["my_answer"]["attachment_ids"] == ["attachment-1"]
        preserved = await client.put(
            "/api/v1/directed-questions/question-1/my-answer",
            headers={"X-Incident-Id": "incident-1"},
            json={
                "option_id": "open",
                "revision": 1,
                "attachment_ids": ["attachment-1"],
            },
        )
        assert preserved.status_code == 200, preserved.text
        assert preserved.json()["data"]["answer"]["revision"] == 2
        assert preserved.json()["data"]["answer"]["attachment_ids"] == ["attachment-1"]
        update = await client.put(
            "/api/v1/directed-questions/question-1/my-answer",
            headers={"X-Incident-Id": "incident-1"},
            json={
                "option_id": "open",
                "revision": 2,
                "attachment_ids": ["attachment-2"],
            },
        )
        assert update.status_code == 200, update.text
        assert update.json()["data"]["answer"]["revision"] == 3
        assert update.json()["data"]["answer"]["attachment_ids"] == ["attachment-2"]
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
            == 3
        )
        assert (await session.get(Attachment, "attachment-1")).directed_answer_id is None
        assert (await session.get(Attachment, "attachment-2")).directed_answer_id == first.json()[
            "data"
        ]["answer"]["id"]


@pytest.mark.asyncio
async def test_directed_answer_rejects_unusable_attachments(
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    async with session_maker() as session:
        incident = Incident(id="incident-1", name="Flood", status="active")
        foreign_incident = Incident(id="incident-2", name="Storm", status="preparing")
        device = AnonymousDevice(
            id="device-1",
            installation_id_hash="c" * 64,
            platform="test",
        )
        foreign_device = AnonymousDevice(
            id="device-2",
            installation_id_hash="d" * 64,
            platform="test",
        )
        blind = BlindSpot(
            id="blind-1",
            incident_id=incident.id,
            claim_key="bridge.passability",
            title="Bridge passability",
            location_text="Bridge",
        )
        question = DirectedQuestion(
            id="question-1",
            incident_id=incident.id,
            blind_spot_id=blind.id,
            title="Can vehicles cross?",
            location_text="Bridge",
            options=[{"id": "open", "label": "Open"}, {"id": "blocked", "label": "Blocked"}],
            status="published",
        )
        other_question = DirectedQuestion(
            id="question-2",
            incident_id=incident.id,
            blind_spot_id=blind.id,
            title="Is water available?",
            location_text="Bridge",
            options=[{"id": "yes", "label": "Yes"}, {"id": "no", "label": "No"}],
            status="published",
        )
        answer = DirectedAnswer(
            id="answer-1",
            question_id=question.id,
            device_id=device.id,
            option_id="open",
            semantic_value="open",
            answer_text="Open",
        )
        other_answer = DirectedAnswer(
            id="answer-2",
            question_id=other_question.id,
            device_id=device.id,
            option_id="yes",
            semantic_value="yes",
            answer_text="Yes",
        )
        report = Report(
            id="report-1",
            incident_id=incident.id,
            reporter_device_id=device.id,
            category="road",
            content_original="Road update",
            content_display="Road update",
            location_text="Bridge",
        )

        def attachment(
            attachment_id: str,
            *,
            incident_id: str = incident.id,
            device_id: str = device.id,
            metadata_status: str = "ready",
            report_id: str | None = None,
            directed_answer_id: str | None = None,
        ) -> Attachment:
            return Attachment(
                id=attachment_id,
                incident_id=incident_id,
                uploader_device_id=device_id,
                report_id=report_id,
                directed_answer_id=directed_answer_id,
                file_name=f"{attachment_id}.jpg",
                declared_mime_type="image/jpeg",
                mime_type="image/jpeg",
                size_bytes=100,
                expected_sha256="e" * 64,
                sha256="e" * 64,
                sanitized_path=f"C:/safe/{attachment_id}.jpg",
                metadata_status=metadata_status,
                malware_scan_status="clean",
                upload_expires_at=utcnow() + timedelta(hours=1),
                uploaded_at=utcnow(),
            )

        invalid_attachments = [
            attachment("foreign-incident", incident_id=foreign_incident.id),
            attachment("foreign-device", device_id=foreign_device.id),
            attachment("pending", metadata_status="pending"),
            attachment("report-bound", report_id=report.id),
            attachment("answer-bound", directed_answer_id=other_answer.id),
        ]
        session.add_all(
            [
                incident,
                foreign_incident,
                device,
                foreign_device,
                blind,
                question,
                other_question,
                answer,
                other_answer,
                report,
                *invalid_attachments,
            ]
        )
        await session.flush()

        for attachment_item in invalid_attachments:
            with pytest.raises(ApiError) as error:
                await replace_answer_attachments(
                    session,
                    answer=answer,
                    incident_id=incident.id,
                    uploader_device_id=device.id,
                    attachment_ids=[attachment_item.id],
                )
            assert error.value.code == "ATTACHMENT_NOT_READY"

        with pytest.raises(ApiError) as error:
            await replace_answer_attachments(
                session,
                answer=answer,
                incident_id=incident.id,
                uploader_device_id=device.id,
                attachment_ids=["missing"],
            )
        assert error.value.code == "ATTACHMENT_NOT_READY"


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
