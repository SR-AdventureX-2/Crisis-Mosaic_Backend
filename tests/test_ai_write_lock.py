from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from crisis_mosaic.config import Settings
from crisis_mosaic.errors import ApiError
from crisis_mosaic.models import (
    AiAnalysis,
    AiJobStep,
    AuditLog,
    Base,
    ConflictCase,
    Incident,
    OutboxEvent,
)
from crisis_mosaic.schemas.ai import ReportRefinementRequest
from crisis_mosaic.security import Actor
from crisis_mosaic.services import ai as ai_service
from crisis_mosaic.services.ai_prompts import COMMAND_BRIEF_PROMPT_VERSION


class LockCheckingSession:
    """Proxy the write methods that AI service code must only call while locked."""

    def __init__(self, session: AsyncSession, lock: asyncio.Lock) -> None:
        self._session = session
        self._lock = lock
        self.operations: list[str] = []

    def _record(self, operation: str) -> None:
        assert self._lock.locked(), f"{operation} happened outside write_lock"
        self.operations.append(operation)

    def add(self, instance: object) -> None:
        self._record("add")
        self._session.add(instance)

    async def flush(self, objects: Any = None) -> None:
        self._record("flush")
        await self._session.flush(objects)

    async def commit(self) -> None:
        self._record("commit")
        await self._session.commit()

    async def rollback(self) -> None:
        self._record("rollback")
        await self._session.rollback()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)


def _resident_actor() -> Actor:
    return Actor(
        subject_type="device",
        subject_id="device",
        role="resident",
        token_version=1,
        incident_ids=frozenset({"incident"}),
    )


def _operator_actor() -> Actor:
    return Actor(
        subject_type="account",
        subject_id="operator",
        role="operator",
        token_version=1,
        incident_ids=frozenset({"incident"}),
    )


def _guard_model_call(
    monkeypatch: pytest.MonkeyPatch,
    lock: asyncio.Lock,
    *,
    fail: bool,
) -> None:
    original = ai_service._invoke_structured

    async def guarded_invoke(**kwargs: Any) -> BaseModel:
        assert not lock.locked(), "external AI call held write_lock"
        if fail:
            raise ApiError(503, "AI_TEST_FAILURE", "forced failure")
        return await original(**kwargs)

    monkeypatch.setattr(ai_service, "_invoke_structured", guarded_invoke)


async def _maker(tmp_path: Path, name: str) -> tuple[Any, async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / name}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
async def test_report_refinement_serializes_every_write_and_persists_terminal_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail: bool,
) -> None:
    engine, maker = await _maker(tmp_path, f"report-{fail}.db")
    lock = asyncio.Lock()
    monkeypatch.setattr(ai_service, "write_lock", lock)
    _guard_model_call(monkeypatch, lock, fail=fail)
    settings = Settings(app_env="test", ai_provider="fake")

    async with maker() as real_session:
        real_session.add(Incident(id="incident", name="Test", status="active"))
        await real_session.commit()
        session = LockCheckingSession(real_session, lock)
        request = ReportRefinementRequest(
            incident_id="incident",
            category="rescue",
            content="桥边老人被困，水位上涨",
            location_text="大关桥",
        )
        if fail:
            with pytest.raises(ApiError, match="forced failure"):
                await ai_service.refine_report(session, request, _resident_actor(), settings)  # type: ignore[arg-type]
        else:
            analysis, _ = await ai_service.refine_report(  # type: ignore[arg-type]
                session, request, _resident_actor(), settings
            )
            assert analysis.status == "succeeded"
        assert {"add", "flush", "commit"} <= set(session.operations)
        assert not real_session.in_transaction()

    async with maker() as verification:
        analysis = await verification.scalar(select(AiAnalysis))
        audits = list((await verification.scalars(select(AuditLog))).all())
        events = list((await verification.scalars(select(OutboxEvent))).all())
        assert analysis is not None
        assert analysis.status == ("failed" if fail else "succeeded")
        assert analysis.error_code == ("AI_TEST_FAILURE" if fail else None)
        assert len(audits) == 1
        assert len(events) == 1
    await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
async def test_legacy_conflict_serializes_writes_and_failure_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail: bool,
) -> None:
    engine, maker = await _maker(tmp_path, f"legacy-{fail}.db")
    lock = asyncio.Lock()
    monkeypatch.setattr(ai_service, "write_lock", lock)
    _guard_model_call(monkeypatch, lock, fail=fail)
    settings = Settings(
        app_env="test",
        ai_provider="fake",
        enable_legacy_demo_ai=True,
    )

    async with maker() as real_session:
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
        real_session.add_all([incident, conflict])
        await real_session.commit()
        session = LockCheckingSession(real_session, lock)
        context = {"evidence": [{"id": "evidence-1", "content": "Road is open"}]}
        if fail:
            with pytest.raises(ApiError, match="forced failure"):
                await ai_service.analyze_legacy_conflict(
                    session,  # type: ignore[arg-type]
                    conflict=conflict,
                    context=context,
                    actor=_operator_actor(),
                    settings=settings,
                )
        else:
            analysis, _ = await ai_service.analyze_legacy_conflict(
                session,  # type: ignore[arg-type]
                conflict=conflict,
                context=context,
                actor=_operator_actor(),
                settings=settings,
            )
            assert analysis.status == "succeeded"
        expected_operations = {"add", "flush", "commit"}
        if fail:
            expected_operations.add("rollback")
        assert expected_operations <= set(session.operations)
        assert not real_session.in_transaction()

    async with maker() as verification:
        analysis = await verification.scalar(select(AiAnalysis))
        steps = list((await verification.scalars(select(AiJobStep))).all())
        assert analysis is not None
        assert analysis.status == ("failed" if fail else "succeeded")
        assert steps
        if fail:
            model_step = next(step for step in steps if step.name == "model_call")
            assert model_step.status == "failed"
            assert all(step.status == "succeeded" for step in steps if step.name != "model_call")
    await engine.dispose()


@pytest.mark.asyncio
async def test_canonical_worker_completion_keeps_model_call_outside_write_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, maker = await _maker(tmp_path, "canonical.db")
    lock = asyncio.Lock()
    monkeypatch.setattr(ai_service, "write_lock", lock)
    _guard_model_call(monkeypatch, lock, fail=False)
    settings = Settings(app_env="test", ai_provider="fake")

    async with maker() as real_session:
        incident = Incident(id="incident", name="Test", status="active")
        analysis = AiAnalysis(
            id="analysis",
            incident_id=incident.id,
            analysis_type="command_brief",
            status="queued",
            input_snapshot={
                "metrics": {
                    "active_report_count": 0,
                    "urgent_report_count": 0,
                    "open_conflict_count": 0,
                    "open_blind_spot_count": 0,
                }
            },
            context_package={
                "metrics": {
                    "active_report_count": 0,
                    "urgent_report_count": 0,
                    "open_conflict_count": 0,
                    "open_blind_spot_count": 0,
                }
            },
            prompt_version=COMMAND_BRIEF_PROMPT_VERSION,
            created_by_type="account",
            created_by_id="operator",
            input_version=0,
            model_provider="fake",
            model_name="fake-brief",
        )
        real_session.add_all([incident, analysis])
        await real_session.commit()
        session = LockCheckingSession(real_session, lock)
        result = await ai_service.process_analysis(  # type: ignore[arg-type]
            session, analysis.id, settings
        )
        assert result.status == "succeeded"
        assert {"add", "commit"} <= set(session.operations)
        assert not real_session.in_transaction()

    async with maker() as verification:
        saved = await verification.get(AiAnalysis, "analysis")
        assert saved is not None and saved.status == "succeeded"
        assert await verification.scalar(select(AuditLog.id)) is not None
        assert await verification.scalar(select(OutboxEvent.id)) is not None
    await engine.dispose()
