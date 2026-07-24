from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import Request
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from crisis_mosaic.domain.coordinates import normalize
from crisis_mosaic.main import create_app
from crisis_mosaic.models import (
    AnonymousDevice,
    Base,
    Incident,
    InformationFragment,
    Report,
)
from crisis_mosaic.routers.questions import list_fragments
from crisis_mosaic.routers.reports import list_reports
from crisis_mosaic.security import Actor


@pytest.fixture
async def session_maker() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [],
        }
    )


def _actor(
    incident_id: str,
    *,
    role: str,
    subject_id: str,
) -> Actor:
    return Actor(
        subject_type="device" if role == "resident" else "account",
        subject_id=subject_id,
        role=role,
        token_version=1,
        incident_ids=frozenset({incident_id}),
    )


@pytest.mark.asyncio
async def test_fragment_bbox_and_response_use_requested_coordinate_system_without_mutation(
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    wgs_latitude = 30.2741
    wgs_longitude = 120.1551
    converted = normalize(wgs_latitude, wgs_longitude, "wgs84")

    async with session_maker() as session:
        incident = Incident(id="incident-spatial", name="Flood", status="active")
        wgs_fragment = InformationFragment(
            id="fragment-wgs",
            incident_id=incident.id,
            source_type="operator",
            topic="road",
            label="WGS source",
            description="Stored in WGS84",
            location_text="Center",
            latitude=wgs_latitude,
            longitude=wgs_longitude,
            coordinate_system="wgs84",
        )
        gcj_fragment = InformationFragment(
            id="fragment-gcj",
            incident_id=incident.id,
            source_type="operator",
            topic="road",
            label="GCJ source",
            description="Stored in GCJ-02",
            location_text="Center",
            latitude=converted.gcj02_latitude,
            longitude=converted.gcj02_longitude,
            coordinate_system="gcj02",
        )
        outside = InformationFragment(
            id="fragment-outside",
            incident_id=incident.id,
            source_type="operator",
            topic="road",
            label="Outside",
            description="Outside bbox",
            location_text="Elsewhere",
            latitude=31.0,
            longitude=121.0,
            coordinate_system="wgs84",
        )
        session.add_all([incident, wgs_fragment, gcj_fragment, outside])
        await session.commit()

        actor = _actor(incident.id, role="operator", subject_id="operator")
        wgs_response = await list_fragments(
            incident.id,
            _request(),
            session,
            actor,
            None,
            coordinate_system="wgs84",
            west=wgs_longitude - 0.0005,
            south=wgs_latitude - 0.0005,
            east=wgs_longitude + 0.0005,
            north=wgs_latitude + 0.0005,
            limit=100,
            offset=0,
        )
        assert wgs_response["meta"]["total"] == 2
        assert {item["id"] for item in wgs_response["data"]} == {
            wgs_fragment.id,
            gcj_fragment.id,
        }
        assert all(item["coordinate_system"] == "wgs84" for item in wgs_response["data"])
        assert all(
            item["latitude"] == pytest.approx(wgs_latitude, abs=0.0001)
            and item["longitude"] == pytest.approx(wgs_longitude, abs=0.0001)
            for item in wgs_response["data"]
        )

        gcj_response = await list_fragments(
            incident.id,
            _request(),
            session,
            actor,
            None,
            coordinate_system="gcj02",
            west=converted.gcj02_longitude - 0.0005,
            south=converted.gcj02_latitude - 0.0005,
            east=converted.gcj02_longitude + 0.0005,
            north=converted.gcj02_latitude + 0.0005,
            limit=100,
            offset=0,
        )
        assert gcj_response["meta"]["total"] == 2
        assert all(item["coordinate_system"] == "gcj02" for item in gcj_response["data"])
        assert all(
            item["latitude"] == pytest.approx(converted.gcj02_latitude, abs=0.0001)
            and item["longitude"] == pytest.approx(converted.gcj02_longitude, abs=0.0001)
            for item in gcj_response["data"]
        )

        await session.refresh(wgs_fragment)
        await session.refresh(gcj_fragment)
        assert (wgs_fragment.latitude, wgs_fragment.longitude, wgs_fragment.coordinate_system) == (
            wgs_latitude,
            wgs_longitude,
            "wgs84",
        )
        assert (
            gcj_fragment.latitude,
            gcj_fragment.longitude,
            gcj_fragment.coordinate_system,
        ) == (
            converted.gcj02_latitude,
            converted.gcj02_longitude,
            "gcj02",
        )


@pytest.mark.asyncio
async def test_operator_report_priority_order_cursor_and_resident_recency(
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    async with session_maker() as session:
        incident = Incident(id="incident-sort", name="Flood", status="active")
        device = AnonymousDevice(
            id="device-sort",
            installation_id_hash="d" * 64,
            platform="test",
        )
        session.add_all([incident, device])
        await session.flush()

        rows = [
            ("report-high-urgent", "high", True, datetime(2026, 1, 1, tzinfo=UTC)),
            ("report-high-normal", "high", False, datetime(2026, 1, 5, tzinfo=UTC)),
            ("report-medium-new", "medium", False, datetime(2026, 1, 4, tzinfo=UTC)),
            ("report-medium-old", "medium", False, datetime(2026, 1, 3, tzinfo=UTC)),
            ("report-low", "low", False, datetime(2026, 1, 6, tzinfo=UTC)),
        ]
        for report_id, priority, is_urgent, updated_at in rows:
            session.add(
                Report(
                    id=report_id,
                    incident_id=incident.id,
                    reporter_device_id=device.id,
                    category="road",
                    content_original=report_id,
                    content_display=report_id,
                    location_text="Road",
                    is_urgent=is_urgent,
                    priority=priority,
                    status="new",
                    updated_at=updated_at,
                )
            )
        await session.commit()

        operator = _actor(incident.id, role="operator", subject_id="operator")
        operator_ids: list[str] = []
        cursor: str | None = None
        while True:
            response = await list_reports(
                incident.id,
                _request(),
                session,
                operator,
                None,
                cursor=cursor,
                limit=2,
            )
            operator_ids.extend(item["id"] for item in response["data"])
            cursor = response["meta"]["next_cursor"]
            if cursor is None:
                break

        assert operator_ids == [
            "report-high-urgent",
            "report-high-normal",
            "report-medium-new",
            "report-medium-old",
            "report-low",
        ]
        assert len(operator_ids) == len(set(operator_ids))

        resident = _actor(incident.id, role="resident", subject_id=device.id)
        resident_response = await list_reports(
            incident.id,
            _request(),
            session,
            resident,
            None,
            limit=10,
        )
        assert [item["id"] for item in resident_response["data"]] == [
            "report-low",
            "report-high-normal",
            "report-medium-new",
            "report-medium-old",
            "report-high-urgent",
        ]


def test_openapi_registers_used_tags_fragment_coordinate_system_and_404() -> None:
    document: dict[str, Any] = create_app().openapi()
    tags = {tag["name"] for tag in document["tags"]}
    assert {"管理员", "Map", "运行状态"} <= tags

    assert document["paths"]["/api/v1/admin/users"]["get"]["tags"] == ["管理员"]
    assert document["paths"]["/api/v1/incidents/{incident_id}/map-view"]["get"]["tags"] == ["Map"]
    assert document["paths"]["/api/v1/health/live"]["get"]["tags"] == ["运行状态"]

    fragment_parameters = {
        parameter["name"]: parameter
        for parameter in document["paths"]["/api/v1/incidents/{incident_id}/fragments"]["get"][
            "parameters"
        ]
    }
    coordinate_parameter = fragment_parameters["coordinate_system"]
    assert coordinate_parameter["schema"]["enum"] == ["wgs84", "gcj02"]
    assert coordinate_parameter["schema"]["default"] == "gcj02"

    report_operation = document["paths"]["/api/v1/reports/{report_id}"]["get"]
    assert report_operation["responses"]["404"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorEnvelope"
    }
