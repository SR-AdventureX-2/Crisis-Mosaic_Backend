from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastapi import Request
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from crisis_mosaic.errors import ApiError
from crisis_mosaic.models import (
    AnonymousDevice,
    Base,
    Incident,
    MapFeature,
    ReportRevision,
)
from crisis_mosaic.routers.map import map_view
from crisis_mosaic.schemas.reports import ReportCreate, ReportLocation, ReportPatch
from crisis_mosaic.security import Actor
from crisis_mosaic.services.idempotency import finish, replay_or_reserve
from crisis_mosaic.services.reports import (
    apply_location,
    assert_report_access,
    create_report,
)


async def _database() -> tuple[Any, async_sessionmaker[Any]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def _seed(session: Any) -> tuple[Incident, AnonymousDevice, Actor]:
    incident = Incident(
        alias="demo-incident",
        name="Hangzhou Flood",
        status="active",
        center_latitude=30.2741,
        center_longitude=120.1551,
        map_coordinate_system="gcj02",
    )
    device = AnonymousDevice(
        installation_id_hash="a" * 64,
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
    return incident, device, actor


def _reporter() -> dict[str, object]:
    return {
        "full_name": "张明",
        "mobile": "13800138000",
    }


@pytest.mark.parametrize(
    "category",
    ["rescue", "medical", "water", "food", "shelter", "road"],
)
def test_all_six_report_categories_are_accepted(category: str) -> None:
    payload = ReportCreate(
        category=category,
        reporter=_reporter(),
        content_original="Need assistance",
        location={"text": "Daguan Bridge"},
    )
    assert payload.category == category


def test_patch_uses_model_fields_set_to_distinguish_omitted_and_null() -> None:
    omitted = ReportPatch(revision=1)
    explicit_null = ReportPatch(revision=1, ai_refinement_id=None)

    assert "ai_refinement_id" not in omitted.model_fields_set
    assert "ai_refinement_id" in explicit_null.model_fields_set


def test_gps_location_requires_accuracy() -> None:
    with pytest.raises(ValidationError, match="accuracy_m is required"):
        ReportLocation(
            text="Daguan Bridge",
            latitude=30.31,
            longitude=120.15,
            coordinate_system="gcj02",
            source="gps",
        )

    location = ReportLocation(
        text="Daguan Bridge",
        latitude=30.31,
        longitude=120.15,
        coordinate_system="gcj02",
        source="gps",
        accuracy_m=12.5,
    )
    assert location.accuracy_m == 12.5


def test_create_report_writes_revision_priority_map_and_idempotency() -> None:
    async def scenario() -> None:
        engine, factory = await _database()
        try:
            async with factory() as session:
                async with session.begin():
                    incident, _, actor = await _seed(session)
                    payload = ReportCreate(
                        category="rescue",
                        reporter=_reporter(),
                        content_original="Two residents trapped",
                        location={
                            "text": "Daguan Bridge",
                            "latitude": 30.31,
                            "longitude": 120.15,
                            "coordinate_system": "gcj02",
                            "provider": "amap",
                            "source": "gps",
                            "accuracy_m": 15,
                        },
                        is_urgent=True,
                    )
                    reservation = await replay_or_reserve(
                        session,
                        actor=actor,
                        route=f"POST:/incidents/{incident.id}/reports",
                        key="test-report-key",
                        body=payload.model_dump(mode="json"),
                    )
                    assert not isinstance(reservation, dict)
                    report = await create_report(
                        session,
                        incident=incident,
                        actor=actor,
                        payload=payload,
                    )
                    response = {"data": {"id": report.id, "revision": report.revision}}
                    finish(reservation, status_code=201, body=response)
                    assert report.revision == 1
                    assert report.priority == "high"
                    assert report.priority_source == "urgent_flag"
                    assert report.location_wgs84_latitude is not None

            async with factory() as session:
                replay = await replay_or_reserve(
                    session,
                    actor=actor,
                    route=f"POST:/incidents/{incident.id}/reports",
                    key="test-report-key",
                    body=payload.model_dump(mode="json"),
                )
                assert replay == response
                assert (
                    await session.scalar(
                        select(func.count(ReportRevision.id)).where(
                            ReportRevision.report_id == report.id
                        )
                    )
                    == 1
                )
                feature = await session.scalar(
                    select(MapFeature).where(MapFeature.source_ref == report.id)
                )
                assert feature is not None
                assert feature.public_data["priority"] == "high"
                assert "device_id" not in feature.public_data
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_location_replacement_clears_previous_coordinates_atomically() -> None:
    async def scenario() -> None:
        engine, factory = await _database()
        try:
            async with factory() as session:
                async with session.begin():
                    incident, _, actor = await _seed(session)
                    report = await create_report(
                        session,
                        incident=incident,
                        actor=actor,
                        payload=ReportCreate(
                            category="road",
                            reporter=_reporter(),
                            content_original="Road is flooded",
                            location={
                                "text": "Old location",
                                "latitude": 30.31,
                                "longitude": 120.15,
                                "coordinate_system": "gcj02",
                            },
                        ),
                    )
                    assert report.location_gcj02_latitude is not None
                    apply_location(report, ReportLocation(text="Manual landmark"))
                    assert report.location_text == "Manual landmark"
                    assert report.latitude is None
                    assert report.longitude is None
                    assert report.location_wgs84_latitude is None
                    assert report.location_gcj02_latitude is None
                    assert report.coordinate_algorithm_version is None
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_resident_cannot_access_another_devices_report() -> None:
    async def scenario() -> None:
        engine, factory = await _database()
        try:
            async with factory() as session:
                async with session.begin():
                    incident, _, actor = await _seed(session)
                    report = await create_report(
                        session,
                        incident=incident,
                        actor=actor,
                        payload=ReportCreate(
                            category="water",
                            reporter=_reporter(),
                            content_original="No drinking water",
                            location={"text": "Shelter A"},
                        ),
                    )
                    other_actor = Actor(
                        subject_type="device",
                        subject_id="01900000-0000-7000-8000-000000000000",
                        role="resident",
                        token_version=1,
                        incident_ids=actor.incident_ids,
                    )
                    with pytest.raises(ApiError) as error:
                        assert_report_access(other_actor, report)
                    assert error.value.code == "REPORT_OWNERSHIP_REQUIRED"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_map_returns_exact_points_without_device_identifiers_and_caps_at_500() -> None:
    async def scenario() -> None:
        engine, factory = await _database()
        try:
            async with factory() as session:
                async with session.begin():
                    incident, _, actor = await _seed(session)
                    session.add_all(
                        [
                            MapFeature(
                                incident_id=incident.id,
                                kind="report",
                                source_ref=f"report-{index}",
                                title=f"Report {index}",
                                status="new",
                                severity="medium",
                                latitude_wgs84=30.0 + index / 100_000,
                                longitude_wgs84=120.0,
                                latitude_gcj02=30.1 + index / 100_000,
                                longitude_gcj02=120.1,
                                public_data={
                                    "category": "road",
                                    "device_id": "must-not-leak",
                                },
                            )
                            for index in range(500)
                        ]
                    )
            request = Request({"type": "http"})
            async with factory() as session:
                response = await map_view(
                    incident.id,
                    request,
                    session,
                    actor,
                    None,
                    coordinate_system="gcj02",
                )
                items = response["data"]["items"]
                assert len(items) == 500
                assert items[0]["position"]["latitude"] is not None
                assert all("device_id" not in item for item in items)

            async with factory() as session:
                async with session.begin():
                    session.add(
                        MapFeature(
                            incident_id=incident.id,
                            kind="report",
                            source_ref="report-over-limit",
                            title="Overflow",
                            status="new",
                            severity="medium",
                            latitude_wgs84=30.2,
                            longitude_wgs84=120.2,
                            latitude_gcj02=30.3,
                            longitude_gcj02=120.3,
                            public_data={},
                        )
                    )
            async with factory() as session:
                with pytest.raises(ApiError) as error:
                    await map_view(
                        incident.id,
                        request,
                        session,
                        actor,
                        None,
                        coordinate_system="gcj02",
                    )
                assert error.value.code == "MAP_VIEW_TOO_LARGE"
        finally:
            await engine.dispose()

    asyncio.run(scenario())
