from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import timedelta

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from crisis_mosaic import workers as workers_module
from crisis_mosaic.config import Settings
from crisis_mosaic.db import get_session
from crisis_mosaic.dependencies import get_actor
from crisis_mosaic.errors import install_error_handlers
from crisis_mosaic.models import (
    AiAnalysis,
    AnonymousDevice,
    BackgroundJob,
    Base,
    BlindSpot,
    ConflictCase,
    ConflictEvidence,
    Incident,
    InformationFragment,
    MapFeature,
    OutboxEvent,
    Report,
)
from crisis_mosaic.routers.map import router as map_router
from crisis_mosaic.routers.questions import router as questions_router
from crisis_mosaic.routers.reports import router as reports_router
from crisis_mosaic.security import Actor
from crisis_mosaic.services.report_observations import (
    extract_structured_claim,
    run_report_blind_spot_detection,
)
from crisis_mosaic.utils import as_utc, utcnow
from crisis_mosaic.workers import WorkerRuntime


@pytest.fixture
async def report_api() -> AsyncIterator[
    tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
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
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        incident = Incident(
            id="incident-report-observations",
            name="Report observation test",
            status="active",
            feature_flags={"blind_spot_report_grace_minutes": 0},
        )
        device = AnonymousDevice(
            id="resident-report-observations",
            installation_id_hash="8" * 64,
            platform="android",
        )
        second_device = AnonymousDevice(
            id="resident-report-observations-2",
            installation_id_hash="9" * 64,
            platform="android",
        )
        third_device = AnonymousDevice(
            id="resident-report-observations-3",
            installation_id_hash="a" * 64,
            platform="android",
        )
        session.add_all([incident, device, second_device, third_device])
        await session.commit()
    first_actor = Actor(
        subject_type="device",
        subject_id=device.id,
        role="resident",
        token_version=1,
        incident_ids=frozenset({incident.id}),
    )
    second_actor = Actor(
        subject_type="device",
        subject_id=second_device.id,
        role="resident",
        token_version=1,
        incident_ids=frozenset({incident.id}),
    )
    actors = {
        "first": first_actor,
        "second": second_actor,
        "third": Actor(
            subject_type="device",
            subject_id=third_device.id,
            role="resident",
            token_version=1,
            incident_ids=frozenset({incident.id}),
        ),
        "current": first_actor,
    }

    async def session_override() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    async def actor_override() -> Actor:
        return actors["current"]

    app = FastAPI()
    install_error_handlers(app)
    app.include_router(reports_router, prefix="/api/v1")
    app.include_router(questions_router, prefix="/api/v1")
    app.include_router(map_router, prefix="/api/v1")
    app.dependency_overrides[get_session] = session_override
    app.dependency_overrides[get_actor] = actor_override
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, maker, incident, actors
    await engine.dispose()


def _report_payload(
    content: str,
    *,
    location_text: str = "Daguan Bridge",
    latitude: float | None = 30.3132,
    longitude: float | None = 120.1558,
) -> dict[str, object]:
    return {
        "category": "road",
        "reporter": {"full_name": "Test Resident", "mobile": "13800138000"},
        "content_original": content,
        "location": {
            "text": location_text,
            "latitude": latitude,
            "longitude": longitude,
            "coordinate_system": "gcj02",
            "source": "manual",
            "provider": "manual",
        },
    }


@pytest.mark.parametrize(
    ("content", "expected_topic", "expected_value"),
    [
        ("无积水", "road_flooding", "absent"),
        ("没有积水", "road_flooding", "absent"),
        ("未发现积水", "road_flooding", "absent"),
        ("积水严重", "road_flooding", "present"),
        ("路面有很多积水", "road_flooding", "present"),
        ("不确定是否积水", "road_flooding", "unknown"),
        ("没有积水，但道路无法通行", "road_passability", "blocked"),
        ("积水很多但仍可缓慢通行", "road_passability", "passable"),
    ],
)
def test_extracts_narrow_road_flooding_claims_without_inferring_passability(
    content: str,
    expected_topic: str,
    expected_value: str,
) -> None:
    report = Report(
        incident_id="incident",
        reporter_device_id="resident",
        category="road",
        content_original=content,
        content_display=content,
        location_text="沿江路",
    )

    claim = extract_structured_claim(report)

    assert claim is not None
    assert claim.topic == expected_topic
    assert claim.value == expected_value
    assert claim.key.startswith(
        "road.flooding:" if expected_topic == "road_flooding" else "road.passability:"
    )


async def _open_two_source_conflict(
    client: httpx.AsyncClient,
    incident: Incident,
    actors: dict[str, Actor],
    *,
    key_prefix: str,
    location_text: str = "Daguan Bridge",
    latitude: float = 30.3132,
    longitude: float = 120.1558,
) -> tuple[dict[str, object], dict[str, object]]:
    actors["current"] = actors["first"]
    first = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": f"{key_prefix}-passable",
        },
        json=_report_payload(
            "道路可通行。",
            location_text=location_text,
            latitude=latitude,
            longitude=longitude,
        ),
    )
    assert first.status_code == 201, first.text
    actors["current"] = actors["second"]
    second = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": f"{key_prefix}-blocked",
        },
        json=_report_payload(
            "道路积水严重，机动车无法通行。",
            location_text=location_text,
            latitude=latitude,
            longitude=longitude,
        ),
    )
    assert second.status_code == 201, second.text
    return first.json()["data"], second.json()["data"]


@pytest.mark.asyncio
async def test_resident_reports_upsert_fragments_and_open_one_conflict_idempotently(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
) -> None:
    client, maker, incident, actors = report_api
    headers = {"X-Incident-Id": incident.id}
    first = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={**headers, "Idempotency-Key": "passable-report"},
        json=_report_payload("道路可通行。"),
    )
    assert first.status_code == 201, first.text

    edited = await client.patch(
        f"/api/v1/reports/{first.json()['data']['id']}",
        headers=headers,
        json={"revision": 1, "content_original": "道路仍可缓慢通行。"},
    )
    assert edited.status_code == 200, edited.text

    same_source = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={**headers, "Idempotency-Key": "same-source-blocked-report"},
        json=_report_payload("道路积水严重，机动车无法通行。"),
    )
    assert same_source.status_code == 201, same_source.text
    async with maker() as session:
        assert await session.scalar(select(func.count(ConflictCase.id))) == 0

    actors["current"] = actors["second"]
    second = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={**headers, "Idempotency-Key": "blocked-report"},
        json=_report_payload("道路积水严重，机动车无法通行。"),
    )
    assert second.status_code == 201, second.text
    replay = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={**headers, "Idempotency-Key": "blocked-report"},
        json=_report_payload("道路积水严重，机动车无法通行。"),
    )
    assert replay.status_code == 201
    assert replay.json() == second.json()

    async with maker() as session:
        fragments = list(
            (
                await session.scalars(
                    select(InformationFragment).order_by(InformationFragment.created_at)
                )
            ).all()
        )
        assert len(fragments) == 3
        assert fragments[0].revision == 2
        assert {fragment.claim_value for fragment in fragments} == {"passable", "blocked"}
        assert [fragment.status for fragment in fragments].count("conflict") == 2
        assert [fragment.status for fragment in fragments].count("normal") == 1
        assert fragments[0].source_cluster_id == fragments[1].source_cluster_id
        assert fragments[2].source_cluster_id != fragments[0].source_cluster_id
        assert all(
            fragment.source_cluster_id
            not in {actors["first"].subject_id, actors["second"].subject_id}
            for fragment in fragments
        )
        assert await session.scalar(select(func.count(ConflictCase.id))) == 1
        assert await session.scalar(select(func.count(ConflictEvidence.id))) == 2


@pytest.mark.asyncio
async def test_opposing_road_flood_reports_open_one_conflict(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
) -> None:
    client, maker, incident, actors = report_api
    location_text = "浙江省杭州市余杭区礼贤路9号靠近湖畔创研中心"
    actors["current"] = actors["first"]
    first = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "road-flood-absent",
        },
        json=_report_payload(
            "没有积水",
            location_text=location_text,
            latitude=30.293205,
            longitude=120.007637,
        ),
    )
    assert first.status_code == 201, first.text

    actors["current"] = actors["second"]
    second = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "road-flood-present",
        },
        json=_report_payload(
            "路面有很多积水",
            location_text=f"{location_text}南门",
            latitude=30.293198,
            longitude=120.007544,
        ),
    )
    assert second.status_code == 201, second.text

    async with maker() as session:
        fragments = list(
            (
                await session.scalars(
                    select(InformationFragment).order_by(InformationFragment.created_at)
                )
            ).all()
        )
        assert {fragment.topic for fragment in fragments} == {"road_flooding"}
        assert {fragment.claim_value for fragment in fragments} == {"absent", "present"}
        assert {fragment.status for fragment in fragments} == {"conflict"}
        conflict_case = await session.scalar(select(ConflictCase))
        assert conflict_case is not None
        assert conflict_case.status == "open"
        assert conflict_case.topic == "road_flooding"
        assert await session.scalar(select(func.count(ConflictEvidence.id))) == 2
        assert await session.scalar(select(func.count(BackgroundJob.id))) == 0
        assert await session.scalar(select(func.count(BlindSpot.id))) == 0


@pytest.mark.asyncio
async def test_fuzzy_address_matches_opposing_reports_without_coordinates(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
) -> None:
    client, maker, incident, actors = report_api
    actors["current"] = actors["first"]
    first = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "fuzzy-address-passable",
        },
        json=_report_payload(
            "道路可以通行",
            location_text="浙江省杭州市余杭区礼贤路9号靠近湖畔创研中心",
            latitude=None,
            longitude=None,
        ),
    )
    assert first.status_code == 201, first.text

    actors["current"] = actors["second"]
    second = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "fuzzy-address-blocked",
        },
        json=_report_payload(
            "机动车无法通行",
            location_text="杭州市余杭区礼贤路9号湖畔创研中心南门",
            latitude=None,
            longitude=None,
        ),
    )
    assert second.status_code == 201, second.text

    async with maker() as session:
        assert await session.scalar(select(func.count(ConflictCase.id))) == 1
        assert await session.scalar(select(func.count(ConflictEvidence.id))) == 2


@pytest.mark.asyncio
async def test_fuzzy_address_matches_despite_coordinate_drift(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
) -> None:
    client, maker, incident, actors = report_api
    actors["current"] = actors["first"]
    first = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "drift-address-passable",
        },
        json=_report_payload(
            "道路可以通行",
            location_text="浙江省杭州市余杭区礼贤路9号靠近湖畔创研中心",
            latitude=30.293205,
            longitude=120.007637,
        ),
    )
    assert first.status_code == 201, first.text

    actors["current"] = actors["second"]
    second = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "drift-address-blocked",
        },
        json=_report_payload(
            "机动车无法通行",
            location_text="杭州市余杭区礼贤路9号湖畔创研中心南门",
            latitude=30.300205,
            longitude=120.007637,
        ),
    )
    assert second.status_code == 201, second.text

    async with maker() as session:
        assert await session.scalar(select(func.count(ConflictCase.id))) == 1
        assert await session.scalar(select(func.count(ConflictEvidence.id))) == 2


@pytest.mark.asyncio
async def test_fuzzy_address_rejects_different_house_numbers_without_coordinates(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
) -> None:
    client, maker, incident, actors = report_api
    actors["current"] = actors["first"]
    first = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "house-number-9-passable",
        },
        json=_report_payload(
            "道路可以通行",
            location_text="杭州市余杭区礼贤路9号湖畔创研中心",
            latitude=None,
            longitude=None,
        ),
    )
    assert first.status_code == 201, first.text

    actors["current"] = actors["second"]
    second = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "house-number-19-blocked",
        },
        json=_report_payload(
            "机动车无法通行",
            location_text="杭州市余杭区礼贤路19号湖畔创研中心",
            latitude=None,
            longitude=None,
        ),
    )
    assert second.status_code == 201, second.text

    async with maker() as session:
        assert await session.scalar(select(func.count(ConflictCase.id))) == 0


@pytest.mark.asyncio
async def test_ambiguous_resident_road_report_opens_and_later_resolves_one_blind_spot(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, maker, incident, _ = report_api
    headers = {
        "X-Incident-Id": incident.id,
        "Idempotency-Key": "ambiguous-road-report",
    }
    report = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers=headers,
        json=_report_payload("The road is flooded near the bridge."),
    )
    assert report.status_code == 201, report.text
    replay = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers=headers,
        json=_report_payload("The road is flooded near the bridge."),
    )
    assert replay.status_code == 201

    async with maker() as session:
        fragment = await session.scalar(select(InformationFragment))
        assert fragment is not None and fragment.claim_value == "unknown"
        assert await session.scalar(select(func.count(InformationFragment.id))) == 1
        assert await session.scalar(select(func.count(BackgroundJob.id))) == 1

    monkeypatch.setattr(workers_module, "session_factory", lambda: maker)
    monkeypatch.setattr(workers_module, "write_lock", asyncio.Lock())
    runtime = WorkerRuntime(Settings(blind_spot_report_grace_minutes=0))
    job_id = await runtime._claim_job()
    assert job_id is not None
    await runtime._execute_job(job_id)

    async with maker() as session:
        blind_spot = await session.scalar(select(BlindSpot))
        fragment = await session.scalar(select(InformationFragment))
        job = await session.get(BackgroundJob, job_id)
        assert blind_spot is not None and blind_spot.status == "open"
        assert job is not None and job.status == "succeeded"
        assert fragment is not None
        duplicate = await run_report_blind_spot_detection(
            session,
            incident_id=incident.id,
            fragment_id=fragment.id,
            fragment_revision=fragment.revision,
            settings=runtime.settings,
        )
        assert duplicate is None
        assert await session.scalar(select(func.count(BlindSpot.id))) == 1

    clear_report = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "clear-road-report",
        },
        json=_report_payload("Road is passable."),
    )
    assert clear_report.status_code == 201, clear_report.text
    async with maker() as session:
        blind_spot = await session.scalar(select(BlindSpot))
        assert blind_spot is not None
        assert blind_spot.status == "resolved"
        assert blind_spot.resolution_value == "passable"
        assert await session.scalar(select(func.count(BlindSpot.id))) == 1

    deleted = await client.request(
        "DELETE",
        f"/api/v1/reports/{clear_report.json()['data']['id']}",
        headers={"X-Incident-Id": incident.id},
        json={"revision": 1},
    )
    assert deleted.status_code == 200, deleted.text
    async with maker() as session:
        blind_spot = await session.scalar(select(BlindSpot))
        feature = await session.scalar(
            select(MapFeature).where(MapFeature.kind == "blind_spot")
        )
        assert blind_spot is not None
        assert blind_spot.status == "reopened"
        assert blind_spot.resolution_value is None
        assert "resolution_fragment_id" not in (blind_spot.scope_data or {})
        assert feature is not None and feature.is_deleted is False


@pytest.mark.asyncio
async def test_explicit_road_uncertainty_opens_blind_spot_without_grace_delay(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
) -> None:
    client, maker, incident, _ = report_api
    async with maker() as session:
        stored_incident = await session.get(Incident, incident.id)
        assert stored_incident is not None
        stored_incident.feature_flags = {}
        await session.commit()

    report = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "explicit-road-uncertainty",
        },
        json=_report_payload("不知道路面能不能通行"),
    )
    assert report.status_code == 201, report.text

    async with maker() as session:
        blind_spot = await session.scalar(select(BlindSpot))
        assert blind_spot is not None
        assert blind_spot.status == "open"
        assert await session.scalar(select(func.count(BackgroundJob.id))) == 0


@pytest.mark.asyncio
async def test_road_questions_stay_unknown_and_resident_fragment_views_remain_private(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
) -> None:
    client, maker, incident, actors = report_api
    questions = [
        "道路是否可以通行？",
        "不知道能不能通行",
        "通行情况不确定",
    ]
    for index, content in enumerate(questions):
        response = await client.post(
            f"/api/v1/incidents/{incident.id}/reports",
            headers={
                "X-Incident-Id": incident.id,
                "Idempotency-Key": f"road-question-{index}",
            },
            json=_report_payload(content),
        )
        assert response.status_code == 201, response.text

    resident_view = await client.get(
        f"/api/v1/incidents/{incident.id}/fragments",
        headers={"X-Incident-Id": incident.id},
    )
    assert resident_view.status_code == 200, resident_view.text
    assert resident_view.json()["data"] == []
    assert resident_view.json()["meta"]["total"] == 0

    actors["current"] = Actor(
        subject_type="account",
        subject_id="operator-observation-review",
        role="operator",
        token_version=1,
        incident_ids=frozenset({incident.id}),
        username="operator",
    )
    operator_view = await client.get(
        f"/api/v1/incidents/{incident.id}/fragments",
        headers={"X-Incident-Id": incident.id},
    )
    assert operator_view.status_code == 200, operator_view.text
    assert len(operator_view.json()["data"]) == 3
    assert all(item["source_cluster_id"] is None for item in operator_view.json()["data"])

    async with maker() as session:
        fragments = list((await session.scalars(select(InformationFragment))).all())
        assert {fragment.claim_value for fragment in fragments} == {"unknown"}
        assert await session.scalar(select(func.count(BackgroundJob.id))) == 0
        assert await session.scalar(select(func.count(BlindSpot.id))) == 1
        assert await session.scalar(select(func.count(ConflictCase.id))) == 0
        assert (
            await session.scalar(
                select(func.count(MapFeature.id)).where(MapFeature.kind == "fragment")
            )
            == 0
        )


@pytest.mark.asyncio
async def test_editing_blind_spot_origin_removes_its_previous_unknown_claim(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
) -> None:
    client, maker, incident, _ = report_api
    created = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "blind-spot-origin-edit",
        },
        json=_report_payload("The road is flooded near the bridge."),
    )
    assert created.status_code == 201, created.text

    async with maker() as session:
        fragment = await session.scalar(select(InformationFragment))
        assert fragment is not None
        blind_spot = await run_report_blind_spot_detection(
            session,
            incident_id=incident.id,
            fragment_id=fragment.id,
            fragment_revision=fragment.revision,
            settings=Settings(blind_spot_report_grace_minutes=0),
        )
        assert blind_spot is not None
        await session.commit()

    edited = await client.patch(
        f"/api/v1/reports/{created.json()['data']['id']}",
        headers={"X-Incident-Id": incident.id},
        json={
            "revision": 1,
            "content_original": "Hello.",
            "content_display": "Hello.",
        },
    )
    assert edited.status_code == 200, edited.text

    async with maker() as session:
        fragment = await session.scalar(select(InformationFragment))
        blind_spot = await session.scalar(select(BlindSpot))
        feature = await session.scalar(
            select(MapFeature).where(MapFeature.kind == "blind_spot")
        )
        assert fragment is not None
        assert fragment.claim_key is None
        assert fragment.claim_value is None
        assert blind_spot is not None
        assert blind_spot.status == "resolved"
        assert blind_spot.resolution_value == "source_report_updated"
        assert feature is not None and feature.is_deleted is True


@pytest.mark.asyncio
async def test_withdrawing_one_of_three_conflict_sources_advances_revision_and_stales_ai(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
) -> None:
    client, maker, incident, actors = report_api
    await _open_two_source_conflict(
        client,
        incident,
        actors,
        key_prefix="three-source",
    )
    actors["current"] = actors["third"]
    third = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "three-source-blocked-2",
        },
        json=_report_payload("Road is blocked."),
    )
    assert third.status_code == 201, third.text

    async with maker() as session:
        conflict_case = await session.scalar(select(ConflictCase))
        assert conflict_case is not None
        previous_revision = conflict_case.revision
        analysis = AiAnalysis(
            incident_id=incident.id,
            analysis_type="conflict_analysis",
            status="succeeded",
            input_snapshot={"conflict_id": conflict_case.id},
            prompt_version="test-v1",
            created_by_type="account",
            input_version=conflict_case.revision,
        )
        session.add(analysis)
        await session.commit()
        analysis_id = analysis.id

    deleted = await client.request(
        "DELETE",
        f"/api/v1/reports/{third.json()['data']['id']}",
        headers={"X-Incident-Id": incident.id},
        json={"revision": 1},
    )
    assert deleted.status_code == 200, deleted.text

    async with maker() as session:
        conflict_case = await session.scalar(select(ConflictCase))
        analysis = await session.get(AiAnalysis, analysis_id)
        assert conflict_case is not None
        assert conflict_case.status == "open"
        assert conflict_case.revision == previous_revision + 1
        assert analysis is not None and analysis.is_stale is True
        assert analysis.stale_reason == "evidence_withdrawn"
        current_evidence_count = await session.scalar(
            select(func.count(ConflictEvidence.id)).where(
                ConflictEvidence.conflict_id == conflict_case.id,
                ConflictEvidence.is_current.is_(True),
            )
        )
        assert current_evidence_count == 2
        feature = await session.scalar(
            select(MapFeature).where(
                MapFeature.kind == "conflict",
                MapFeature.source_ref == conflict_case.id,
            )
        )
        assert feature is not None
        assert feature.revision == conflict_case.revision
        updated_event = await session.scalar(
            select(OutboxEvent)
            .where(
                OutboxEvent.resource_id == conflict_case.id,
                OutboxEvent.event_type == "conflict.updated",
                OutboxEvent.resource_revision == conflict_case.revision,
            )
            .order_by(OutboxEvent.occurred_at.desc())
        )
        assert updated_event is not None
        assert updated_event.payload["data"]["reason"] == "evidence_withdrawn"


@pytest.mark.asyncio
async def test_blind_spot_job_keeps_fixed_due_time_when_grace_setting_changes(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, maker, incident, _ = report_api
    async with maker() as session:
        stored_incident = await session.get(Incident, incident.id)
        assert stored_incident is not None
        stored_incident.feature_flags = {"blind_spot_report_grace_minutes": 30}
        await session.commit()

    created = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "fixed-blind-spot-due",
        },
        json=_report_payload("The road is flooded near the bridge."),
    )
    assert created.status_code == 201, created.text

    async with maker() as session:
        job = await session.scalar(select(BackgroundJob))
        assert job is not None
        assert job.payload["grace_minutes"] == 30
        assert isinstance(job.payload["due_at"], str)
        fixed_due_at = as_utc(job.run_after)
        stored_incident = await session.get(Incident, incident.id)
        assert stored_incident is not None
        stored_incident.feature_flags = {"blind_spot_report_grace_minutes": 60}
        job.run_after = utcnow() - timedelta(seconds=1)
        await session.commit()

    monkeypatch.setattr(workers_module, "session_factory", lambda: maker)
    monkeypatch.setattr(workers_module, "write_lock", asyncio.Lock())
    runtime = WorkerRuntime(Settings(blind_spot_report_grace_minutes=60))
    job_id = await runtime._claim_job()
    assert job_id is not None
    await runtime._execute_job(job_id)

    async with maker() as session:
        job = await session.get(BackgroundJob, job_id)
        assert job is not None
        assert job.status == "queued"
        assert job.attempts == 0
        assert as_utc(job.run_after) == fixed_due_at
        assert await session.scalar(select(func.count(BlindSpot.id))) == 0


@pytest.mark.asyncio
async def test_blind_spot_job_is_noop_after_incident_closes(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, maker, incident, _ = report_api
    created = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "closed-incident-blind-spot",
        },
        json=_report_payload("The road is flooded near the bridge."),
    )
    assert created.status_code == 201, created.text

    async with maker() as session:
        stored_incident = await session.get(Incident, incident.id)
        assert stored_incident is not None
        stored_incident.status = "closed"
        await session.commit()

    monkeypatch.setattr(workers_module, "session_factory", lambda: maker)
    monkeypatch.setattr(workers_module, "write_lock", asyncio.Lock())
    runtime = WorkerRuntime(Settings(blind_spot_report_grace_minutes=0))
    job_id = await runtime._claim_job()
    assert job_id is not None
    await runtime._execute_job(job_id)

    async with maker() as session:
        job = await session.get(BackgroundJob, job_id)
        assert job is not None and job.status == "succeeded"
        assert await session.scalar(select(func.count(BlindSpot.id))) == 0


@pytest.mark.asyncio
async def test_resident_map_fuzzes_automatic_conflict_and_blind_spot_locations(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
) -> None:
    client, maker, incident, actors = report_api
    await _open_two_source_conflict(
        client,
        incident,
        actors,
        key_prefix="private-map-conflict",
        location_text="Exact Conflict Place",
        latitude=30.3132,
        longitude=120.1558,
    )
    actors["current"] = actors["first"]
    ambiguous = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "private-map-blind-spot",
        },
        json=_report_payload(
            "The road is flooded near the bridge.",
            location_text="Exact Blind Place",
            latitude=30.6543,
            longitude=120.9876,
        ),
    )
    assert ambiguous.status_code == 201, ambiguous.text
    async with maker() as session:
        fragment = await session.scalar(
            select(InformationFragment).where(
                InformationFragment.source_ref_id == ambiguous.json()["data"]["id"]
            )
        )
        assert fragment is not None
        blind_spot = await run_report_blind_spot_detection(
            session,
            incident_id=incident.id,
            fragment_id=fragment.id,
            fragment_revision=fragment.revision,
            settings=Settings(blind_spot_report_grace_minutes=0),
        )
        assert blind_spot is not None
        await session.commit()

    resident_view = await client.get(
        f"/api/v1/incidents/{incident.id}/map-view",
        headers={"X-Incident-Id": incident.id},
        params={"layers": "conflicts,blind_spots"},
    )
    assert resident_view.status_code == 200, resident_view.text
    resident_items = resident_view.json()["data"]["items"]
    assert {item["kind"] for item in resident_items} == {"conflict", "blind_spot"}
    assert all(item["position_precision"] == "fuzzy_100m" for item in resident_items)
    assert all("location_text" not in item for item in resident_items)
    assert {item["title"] for item in resident_items} == {
        "现场信息冲突",
        "现场信息盲区",
    }
    assert "Exact Conflict Place" not in resident_view.text
    assert "Exact Blind Place" not in resident_view.text

    actors["current"] = Actor(
        subject_type="account",
        subject_id="operator-map-review",
        role="operator",
        token_version=1,
        incident_ids=frozenset({incident.id}),
        username="operator",
    )
    operator_view = await client.get(
        f"/api/v1/incidents/{incident.id}/map-view",
        headers={"X-Incident-Id": incident.id},
        params={"layers": "conflicts,blind_spots"},
    )
    assert operator_view.status_code == 200, operator_view.text
    operator_items = operator_view.json()["data"]["items"]
    assert all(item["position_precision"] == "exact" for item in operator_items)
    assert {item["location_text"] for item in operator_items} == {
        "Exact Conflict Place",
        "Exact Blind Place",
    }


@pytest.mark.asyncio
async def test_delete_and_invalid_reports_fully_deactivate_observation_state(
    report_api: tuple[
        httpx.AsyncClient,
        async_sessionmaker[AsyncSession],
        Incident,
        dict[str, Actor],
    ],
) -> None:
    client, maker, incident, actors = report_api
    first_report, second_report = await _open_two_source_conflict(
        client,
        incident,
        actors,
        key_prefix="deactivate-conflict",
        location_text="Location A",
    )
    deleted = await client.request(
        "DELETE",
        f"/api/v1/reports/{second_report['id']}",
        headers={"X-Incident-Id": incident.id},
        json={"revision": 1},
    )
    assert deleted.status_code == 200, deleted.text

    actors["current"] = actors["first"]
    invalid_target = await client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        headers={
            "X-Incident-Id": incident.id,
            "Idempotency-Key": "invalid-observation",
        },
        json=_report_payload("Road is passable.", location_text="Location B"),
    )
    assert invalid_target.status_code == 201, invalid_target.text

    actors["current"] = Actor(
        subject_type="account",
        subject_id="operator-observation-invalid",
        role="operator",
        token_version=1,
        incident_ids=frozenset({incident.id}),
        username="operator",
    )
    invalidated = await client.patch(
        f"/api/v1/reports/{invalid_target.json()['data']['id']}/status",
        headers={"X-Incident-Id": incident.id},
        json={"revision": 1, "status": "invalid"},
    )
    assert invalidated.status_code == 200, invalidated.text

    default_fragments = await client.get(
        f"/api/v1/incidents/{incident.id}/fragments",
        headers={"X-Incident-Id": incident.id},
    )
    assert default_fragments.status_code == 200, default_fragments.text
    listed_source_ids = {
        item["source_ref_id"] for item in default_fragments.json()["data"]
    }
    assert first_report["id"] in listed_source_ids
    assert second_report["id"] not in listed_source_ids
    assert invalid_target.json()["data"]["id"] not in listed_source_ids

    async with maker() as session:
        fragments = list((await session.scalars(select(InformationFragment))).all())
        fragments_by_report = {item.source_ref_id: item for item in fragments}
        first_fragment = fragments_by_report[first_report["id"]]
        deleted_fragment = fragments_by_report[second_report["id"]]
        invalid_fragment = fragments_by_report[invalid_target.json()["data"]["id"]]
        assert deleted_fragment.status == "withdrawn"
        assert invalid_fragment.status == "withdrawn"
        assert first_fragment.claim_key != invalid_fragment.claim_key

        conflict_case = await session.scalar(select(ConflictCase))
        assert conflict_case is not None and conflict_case.status == "resolved"
        conflict_feature = await session.scalar(
            select(MapFeature).where(
                MapFeature.kind == "conflict",
                MapFeature.source_ref == conflict_case.id,
            )
        )
        assert conflict_feature is not None and conflict_feature.is_deleted is True
        assert (
            await session.scalar(
                select(func.count(ConflictEvidence.id)).where(
                    ConflictEvidence.conflict_id == conflict_case.id,
                    ConflictEvidence.is_current.is_(True),
                )
            )
            == 1
        )
