from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from crisis_mosaic.db import get_session
from crisis_mosaic.dependencies import get_actor
from crisis_mosaic.errors import install_error_handlers
from crisis_mosaic.models import (
    AiAnalysis,
    AuditLog,
    Base,
    ConflictCase,
    ConflictDecision,
    ConflictEvidence,
    FactRecord,
    FactVersion,
    Incident,
)
from crisis_mosaic.routers.conflicts import router as conflicts_router
from crisis_mosaic.security import Actor


@pytest.fixture
async def fact_api() -> AsyncIterator[
    tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        dict[str, Actor],
    ]
]:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    actor_holder = {
        "actor": Actor(
            subject_type="account",
            subject_id="operator-1",
            role="operator",
            token_version=1,
            incident_ids=frozenset({"incident-1"}),
            username="operator",
        )
    }

    async def session_override() -> AsyncIterator[AsyncSession]:
        async with session_maker() as session:
            yield session

    async def actor_override() -> Actor:
        return actor_holder["actor"]

    app = FastAPI()
    install_error_handlers(app)
    app.include_router(conflicts_router, prefix="/api/v1")
    app.dependency_overrides[get_session] = session_override
    app.dependency_overrides[get_actor] = actor_override
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, session_maker, actor_holder
    await engine.dispose()


async def _seed_fact_chain(session_maker: async_sessionmaker[AsyncSession]) -> None:
    now = datetime(2026, 7, 24, 5, 0, tzinfo=UTC)
    incident = Incident(
        id="incident-1",
        name="Hangzhou flood",
        status="active",
    )
    conflict = ConflictCase(
        id="conflict-1",
        incident_id=incident.id,
        fact_key="road.passability",
        title="Road passability",
        topic="transport",
        location_text="Riverside Road",
        latitude=30.25,
        longitude=120.17,
        coordinate_system="gcj02",
        status="resolved",
        revision=3,
    )
    accepted = ConflictEvidence(
        id="evidence-accepted",
        conflict_id=conflict.id,
        kind="fragment",
        source_id="fragment-1",
        source_revision=2,
        snapshot={
            "claim_key": "road.passability",
            "claim_value": "blocked",
            "description": "Road is blocked by flood water",
            "observed_at": now.isoformat(),
        },
        snapshot_sha256="a" * 64,
    )
    rejected = ConflictEvidence(
        id="evidence-rejected",
        conflict_id=conflict.id,
        kind="report",
        source_id="report-1",
        source_revision=1,
        snapshot={
            "content": "Road was open earlier",
            "received_at": (now - timedelta(hours=2)).isoformat(),
        },
        snapshot_sha256="b" * 64,
    )
    analysis = AiAnalysis(
        id="analysis-1",
        incident_id=incident.id,
        analysis_type="conflict_analysis",
        status="succeeded",
        input_snapshot={"conflict_id": conflict.id},
        context_package={"evidence_ids": [accepted.id, rejected.id], "timeline": ["14:00"]},
        context_sha256="c" * 64,
        output={"recommendation": "accept_blocked"},
        confidence=0.91,
        prompt_version="conflict-v1",
        created_by_type="account",
        created_by_id="operator-1",
        input_version=2,
        completed_at=now,
    )
    first_version = FactVersion(
        id="version-1",
        fact_record_id="fact-new",
        revision=1,
        status="current",
        statement="Road access is uncertain",
        confidence=0.6,
        source_conflict_id=conflict.id,
        source_analysis_id=None,
        context_snapshot=None,
        accepted_evidence_ids=[rejected.id],
        decision_snapshot={"conclusion": "uncertain"},
        decided_by="operator-1",
        valid_from=now - timedelta(hours=3),
        valid_to=now - timedelta(hours=1),
        created_at=now - timedelta(hours=3),
    )
    second_version = FactVersion(
        id="version-2",
        fact_record_id="fact-new",
        previous_version_id=first_version.id,
        revision=2,
        status="current",
        statement="Riverside Road is impassable",
        confidence=0.95,
        source_conflict_id=conflict.id,
        source_analysis_id=analysis.id,
        context_snapshot=analysis.context_package,
        accepted_evidence_ids=[accepted.id],
        decision_snapshot={"conclusion": "blocked", "analysis_id": analysis.id},
        decided_by="operator-1",
        valid_from=now - timedelta(hours=1),
        created_at=now - timedelta(hours=1),
    )
    newest = FactRecord(
        id="fact-new",
        incident_id=incident.id,
        fact_key="road.passability",
        topic="transport",
        location_text="Riverside Road",
        latitude=30.25,
        longitude=120.17,
        coordinate_system="gcj02",
        current_version_id=second_version.id,
        current_revision=2,
        status="current",
        is_public=True,
        created_at=now - timedelta(hours=3),
        updated_at=now,
    )
    older_version = FactVersion(
        id="version-old",
        fact_record_id="fact-old",
        revision=1,
        status="current",
        statement="Shelter is operating",
        confidence=0.9,
        context_snapshot=None,
        accepted_evidence_ids=[],
        decision_snapshot={"conclusion": "open"},
        decided_by="operator-1",
        valid_from=now - timedelta(hours=4),
        created_at=now - timedelta(hours=4),
    )
    older = FactRecord(
        id="fact-old",
        incident_id=incident.id,
        fact_key="shelter.status",
        topic="shelter",
        location_text="West shelter",
        latitude=30.20,
        longitude=120.10,
        coordinate_system="wgs84",
        current_version_id=older_version.id,
        current_revision=1,
        status="current",
        is_public=True,
        created_at=now - timedelta(hours=4),
        updated_at=now - timedelta(hours=1),
    )
    far_version = FactVersion(
        id="version-far",
        fact_record_id="fact-far",
        revision=1,
        status="under_review",
        statement="Remote road condition",
        context_snapshot=None,
        accepted_evidence_ids=[],
        decision_snapshot={"conclusion": "review"},
        decided_by="operator-1",
    )
    far = FactRecord(
        id="fact-far",
        incident_id=incident.id,
        fact_key="remote.road",
        topic="transport",
        location_text="Remote",
        latitude=39.9,
        longitude=116.4,
        coordinate_system="wgs84",
        current_version_id=far_version.id,
        current_revision=1,
        status="under_review",
        is_public=False,
        updated_at=now - timedelta(minutes=30),
    )
    decision = ConflictDecision(
        id="decision-1",
        conflict_id=conflict.id,
        conflict_revision=2,
        analysis_id=analysis.id,
        evidence_decisions=[
            {"evidence_id": accepted.id, "disposition": "accepted"},
            {"evidence_id": rejected.id, "disposition": "rejected"},
        ],
        conclusion=second_version.statement,
        note="Confirmed by operator",
        decided_by="operator-1",
        created_at=now - timedelta(hours=1),
    )
    audit = AuditLog(
        id="audit-1",
        incident_id=incident.id,
        actor_type="account",
        actor_id="operator-1",
        action="conflict.decided",
        resource_type="conflict",
        resource_id=conflict.id,
        request_id="request-1",
        details={"after": {"fact_record_id": newest.id, "fact_revision": 2}},
        created_at=now - timedelta(hours=1),
    )
    unrelated_audit = AuditLog(
        id="audit-unrelated",
        incident_id=incident.id,
        actor_type="system",
        action="report.updated",
        resource_type="report",
        resource_id="report-unrelated",
        details={},
        created_at=now,
    )
    async with session_maker() as session:
        session.add_all(
            [
                incident,
                conflict,
                accepted,
                rejected,
                analysis,
                first_version,
                second_version,
                newest,
                older_version,
                older,
                far_version,
                far,
                decision,
                audit,
                unrelated_audit,
            ]
        )
        await session.commit()


@pytest.mark.asyncio
async def test_fact_list_supports_bbox_coordinate_conversion_and_stable_cursor(
    fact_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        dict[str, Actor],
    ],
) -> None:
    client, session_maker, _ = fact_api
    await _seed_fact_chain(session_maker)

    first = await client.get(
        "/api/v1/incidents/incident-1/fact-records",
        params={
            "bbox": "119,29,121,31",
            "coordinate_system": "wgs84",
            "limit": 1,
        },
        headers={"X-Incident-Id": "incident-1"},
    )
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert [item["id"] for item in first_body["data"]] == ["fact-new"]
    assert first_body["data"][0]["coordinate_system"] == "wgs84"
    assert first_body["data"][0]["position"]["coordinate_system"] == "wgs84"
    assert first_body["data"][0]["evidence_summary"] == {
        "count": 1,
        "resolved_count": 1,
        "by_kind": {"fragment": 1},
        "references": [
            {
                "evidence_id": "evidence-accepted",
                "kind": "fragment",
                "source_id": "fragment-1",
                "source_revision": 2,
                "claim_key": "road.passability",
                "claim_value": "blocked",
                "summary": "Road is blocked by flood water",
                "observed_at": "2026-07-24T05:00:00+00:00",
                "is_current": True,
            }
        ],
    }
    assert first_body["data"][0]["ai_analysis_reference"]["id"] == "analysis-1"
    assert first_body["meta"]["total"] == 2
    assert first_body["meta"]["has_more"] is True
    assert first_body["meta"]["coordinate_system"] == "wgs84"
    assert first_body["meta"]["as_of"].endswith("Z")
    cursor = first_body["meta"]["next_cursor"]
    assert cursor

    second = await client.get(
        "/api/v1/incidents/incident-1/fact-records",
        params={
            "bbox": "119,29,121,31",
            "coordinate_system": "wgs84",
            "limit": 1,
            "cursor": cursor,
        },
        headers={"X-Incident-Id": "incident-1"},
    )
    assert second.status_code == 200, second.text
    assert [item["id"] for item in second.json()["data"]] == ["fact-old"]
    assert second.json()["meta"]["has_more"] is False
    assert second.json()["meta"]["next_cursor"] is None

    malformed = await client.get(
        "/api/v1/incidents/incident-1/fact-records",
        params={"cursor": "not-a-cursor"},
        headers={"X-Incident-Id": "incident-1"},
    )
    assert malformed.status_code == 422
    assert malformed.json()["error"]["code"] == "INVALID_CURSOR"


@pytest.mark.asyncio
async def test_operator_fact_detail_returns_complete_decision_chain(
    fact_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        dict[str, Actor],
    ],
) -> None:
    client, session_maker, _ = fact_api
    await _seed_fact_chain(session_maker)

    response = await client.get(
        "/api/v1/fact-records/fact-new",
        headers={"X-Incident-Id": "incident-1"},
    )
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert [version["revision"] for version in data["versions"]] == [1, 2]
    assert data["versions"][1]["previous_version_id"] == "version-1"
    assert {row["id"] for row in data["evidence_references"]} == {
        "evidence-accepted",
        "evidence-rejected",
    }
    assert data["decisions"][0]["id"] == "decision-1"
    assert data["decisions"][0]["evidence_decisions"][1]["disposition"] == "rejected"
    assert data["ai_analyses"][0]["id"] == "analysis-1"
    assert data["ai_analyses"][0]["context_package"]["evidence_ids"] == [
        "evidence-accepted",
        "evidence-rejected",
    ]
    assert [row["id"] for row in data["audit"]] == ["audit-1"]


@pytest.mark.asyncio
async def test_resident_fact_detail_only_exposes_public_current_redacted_view(
    fact_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        dict[str, Actor],
    ],
) -> None:
    client, session_maker, actor_holder = fact_api
    await _seed_fact_chain(session_maker)
    actor_holder["actor"] = Actor(
        subject_type="device",
        subject_id="device-1",
        role="resident",
        token_version=1,
        incident_ids=frozenset({"incident-1"}),
    )

    response = await client.get(
        "/api/v1/fact-records/fact-new",
        headers={"X-Incident-Id": "incident-1"},
    )
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()["data"]
    for internal_key in (
        "source_conflict_id",
        "source_analysis_id",
        "ai_analysis_reference",
        "accepted_evidence_ids",
        "versions",
        "evidence_references",
        "decisions",
        "ai_analyses",
        "audit",
    ):
        assert internal_key not in data
    assert "references" not in data["evidence_summary"]
    assert data["statement"] == "Riverside Road is impassable"

    private_response = await client.get(
        "/api/v1/fact-records/fact-far",
        headers={"X-Incident-Id": "incident-1"},
    )
    assert private_response.status_code == 403
    assert private_response.json()["error"]["code"] == "FACT_NOT_PUBLIC"
