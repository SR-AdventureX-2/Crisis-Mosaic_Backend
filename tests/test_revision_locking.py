from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import Request
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from crisis_mosaic.errors import ApiError
from crisis_mosaic.models import (
    AnonymousDevice,
    Base,
    BlindSpot,
    ConflictCase,
    ConflictEvidence,
    DirectedAnswer,
    DirectedQuestion,
    Incident,
    InformationFragment,
    LocalAccount,
)
from crisis_mosaic.routers import admin as admin_module
from crisis_mosaic.routers import conflicts as conflicts_module
from crisis_mosaic.routers import questions as questions_module
from crisis_mosaic.routers.admin import patch_user
from crisis_mosaic.routers.conflicts import append_conflict_evidence
from crisis_mosaic.routers.questions import change_question_status, put_my_answer
from crisis_mosaic.schemas.admin import AdminUserPatch
from crisis_mosaic.schemas.conflicts import AddConflictEvidence, EvidenceReference
from crisis_mosaic.schemas.questions import DirectedAnswerPut, RevisionAction
from crisis_mosaic.security import Actor, hash_password


class CoordinatedWriteLock:
    """Make two callers reach the lock boundary before serving them in arrival order."""

    def __init__(self, parties: int = 2) -> None:
        self._parties = parties
        self._arrivals = 0
        self._turn_events = [asyncio.Event() for _ in range(parties)]
        self._tickets: dict[asyncio.Task[Any], int] = {}

    async def __aenter__(self) -> CoordinatedWriteLock:
        task = asyncio.current_task()
        assert task is not None
        ticket = self._arrivals
        self._arrivals += 1
        self._tickets[task] = ticket
        if self._arrivals == self._parties:
            self._turn_events[0].set()
        await self._turn_events[ticket].wait()
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        task = asyncio.current_task()
        assert task is not None
        ticket = self._tickets.pop(task)
        next_ticket = ticket + 1
        if next_ticket < self._parties:
            self._turn_events[next_ticket].set()


@pytest.fixture
async def session_maker(
    tmp_path: Path,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    database_path = tmp_path / "revision-locking.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path.as_posix()}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def request_for(path: str, request_id: str) -> Request:
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [],
            "client": ("test", 1),
            "server": ("test", 80),
        }
    )
    request.state.request_id = request_id
    return request


def actor(role: str, subject_id: str, incident_id: str) -> Actor:
    return Actor(
        subject_type="device" if role == "resident" else "account",
        subject_id=subject_id,
        role=role,
        token_version=1,
        incident_ids=frozenset({incident_id}),
    )


def assert_one_revision_conflict(results: list[object]) -> None:
    successes = [result for result in results if isinstance(result, dict)]
    failures = [result for result in results if isinstance(result, ApiError)]
    assert len(successes) == 1, results
    assert len(failures) == 1, results
    assert failures[0].status_code == 409
    assert failures[0].code == "REVISION_CONFLICT"


def test_admin_user_patch_requires_revision_in_api_schema() -> None:
    with pytest.raises(ValidationError):
        AdminUserPatch.model_validate({"email": "operator@example.test"})
    assert "revision" in AdminUserPatch.model_json_schema()["required"]


@pytest.mark.asyncio
async def test_concurrent_question_publish_allows_only_one_revision(
    session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incident_id = "incident-question-race"
    async with session_maker() as session:
        incident = Incident(id=incident_id, name="Question race", status="active")
        blind = BlindSpot(
            id="blind-question-race",
            incident_id=incident_id,
            claim_key="bridge.passability",
            title="Bridge",
            location_text="Bridge",
        )
        question = DirectedQuestion(
            id="question-race",
            incident_id=incident_id,
            blind_spot_id=blind.id,
            title="Is the bridge open?",
            location_text="Bridge",
            options=[
                {"id": "open", "label": "Open"},
                {"id": "closed", "label": "Closed"},
            ],
            status="draft",
            revision=1,
        )
        session.add_all([incident, blind, question])
        await session.commit()

    monkeypatch.setattr(questions_module, "write_lock", CoordinatedWriteLock())
    operator = actor("operator", "operator-race", incident_id)

    async def publish(request_id: str) -> dict[str, Any]:
        async with session_maker() as session:
            assert await session.get(DirectedQuestion, "question-race") is not None
            return await change_question_status(
                question_id="question-race",
                payload=RevisionAction(revision=1),
                target_status="published",
                request=request_for("/questions/question-race/publish", request_id),
                session=session,
                actor=operator,
                incident_header=incident_id,
            )

    results = await asyncio.wait_for(
        asyncio.gather(
            publish("question-race-1"),
            publish("question-race-2"),
            return_exceptions=True,
        ),
        timeout=5,
    )
    assert_one_revision_conflict(list(results))
    async with session_maker() as session:
        question = await session.get(DirectedQuestion, "question-race")
        assert question is not None
        assert (question.status, question.revision) == ("published", 2)


@pytest.mark.asyncio
async def test_question_close_wins_before_answer_status_check(
    session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incident_id = "incident-answer-race"
    async with session_maker() as session:
        incident = Incident(id=incident_id, name="Answer race", status="active")
        device = AnonymousDevice(
            id="device-answer-race",
            installation_id_hash="a" * 64,
            platform="test",
        )
        blind = BlindSpot(
            id="blind-answer-race",
            incident_id=incident_id,
            claim_key="road.passability",
            title="Road",
            location_text="Road",
        )
        question = DirectedQuestion(
            id="question-answer-race",
            incident_id=incident_id,
            blind_spot_id=blind.id,
            title="Is the road open?",
            location_text="Road",
            options=[
                {"id": "open", "label": "Open"},
                {"id": "closed", "label": "Closed"},
            ],
            status="published",
            revision=1,
        )
        session.add_all([incident, device, blind, question])
        await session.commit()

    monkeypatch.setattr(questions_module, "write_lock", CoordinatedWriteLock())

    async def close() -> dict[str, Any]:
        async with session_maker() as session:
            assert await session.get(DirectedQuestion, "question-answer-race") is not None
            return await change_question_status(
                question_id="question-answer-race",
                payload=RevisionAction(revision=1),
                target_status="closed",
                request=request_for("/questions/question-answer-race/close", "close-race"),
                session=session,
                actor=actor("operator", "operator-race", incident_id),
                incident_header=incident_id,
            )

    async def answer() -> dict[str, Any]:
        async with session_maker() as session:
            assert await session.get(DirectedQuestion, "question-answer-race") is not None
            return await put_my_answer(
                question_id="question-answer-race",
                payload=DirectedAnswerPut(option_id="open", revision=0),
                request=request_for("/questions/question-answer-race/my-answer", "answer-race"),
                session=session,
                actor=actor("resident", "device-answer-race", incident_id),
                incident_header=incident_id,
            )

    results = await asyncio.wait_for(
        asyncio.gather(close(), answer(), return_exceptions=True),
        timeout=5,
    )
    assert isinstance(results[0], dict), results
    assert isinstance(results[1], ApiError), results
    assert results[1].code == "QUESTION_NOT_ACTIVE"
    async with session_maker() as session:
        assert await session.scalar(select(func.count(DirectedAnswer.id))) == 0


@pytest.mark.asyncio
async def test_concurrent_conflict_evidence_append_allows_only_one_revision(
    session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incident_id = "incident-conflict-race"
    async with session_maker() as session:
        incident = Incident(id=incident_id, name="Conflict race", status="active")
        case = ConflictCase(
            id="conflict-race",
            incident_id=incident_id,
            fact_key="road.passability",
            title="Road conflict",
            topic="transport",
            location_text="Road",
            revision=1,
        )
        fragment = InformationFragment(
            id="fragment-race",
            incident_id=incident_id,
            source_type="operator",
            topic="transport",
            claim_key="road.passability",
            claim_value="closed",
            label="Road closed",
            description="Observed closure",
            location_text="Road",
            revision=1,
        )
        session.add_all([incident, case, fragment])
        await session.commit()

    monkeypatch.setattr(conflicts_module, "write_lock", CoordinatedWriteLock())
    operator = actor("operator", "operator-race", incident_id)
    payload = AddConflictEvidence(
        revision=1,
        evidence=[
            EvidenceReference(
                kind="fragment",
                source_id="fragment-race",
                source_revision=1,
            )
        ],
    )

    async def append(request_id: str) -> dict[str, Any]:
        async with session_maker() as session:
            assert await session.get(ConflictCase, "conflict-race") is not None
            return await append_conflict_evidence(
                conflict_id="conflict-race",
                payload=payload,
                request=request_for("/conflicts/conflict-race/evidence", request_id),
                session=session,
                actor=operator,
                incident_header=incident_id,
            )

    results = await asyncio.wait_for(
        asyncio.gather(
            append("conflict-race-1"),
            append("conflict-race-2"),
            return_exceptions=True,
        ),
        timeout=5,
    )
    assert_one_revision_conflict(list(results))
    async with session_maker() as session:
        case = await session.get(ConflictCase, "conflict-race")
        assert case is not None
        assert case.revision == 2
        assert await session.scalar(select(func.count(ConflictEvidence.id))) == 1


@pytest.mark.asyncio
async def test_concurrent_account_patch_uses_persisted_revision(
    session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with session_maker() as session:
        session.add(
            LocalAccount(
                id="account-race",
                username="account-race",
                password_hash=hash_password("Correct-Horse-Battery-Staple-2026!"),
                role="operator",
                revision=1,
            )
        )
        await session.commit()

    monkeypatch.setattr(admin_module, "write_lock", CoordinatedWriteLock())
    administrator = actor("admin", "administrator", "unused")

    async def update(email: str, request_id: str) -> dict[str, object]:
        async with session_maker() as session:
            assert await session.get(LocalAccount, "account-race") is not None
            return await patch_user(
                account_id="account-race",
                body=AdminUserPatch(revision=1, email=email),
                request=request_for("/admin/users/account-race", request_id),
                session=session,
                actor=administrator,
            )

    results = await asyncio.wait_for(
        asyncio.gather(
            update("first@example.test", "account-race-1"),
            update("second@example.test", "account-race-2"),
            return_exceptions=True,
        ),
        timeout=5,
    )
    assert_one_revision_conflict(list(results))
    success_result = next(result for result in results if isinstance(result, dict))
    assert success_result["data"]["revision"] == 2
    async with session_maker() as session:
        account = await session.get(LocalAccount, "account-race")
        assert account is not None
        assert account.revision == 2
