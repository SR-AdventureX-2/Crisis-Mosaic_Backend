from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from crisis_mosaic.db import get_session
from crisis_mosaic.dependencies import get_actor
from crisis_mosaic.errors import ApiError, install_error_handlers
from crisis_mosaic.models import (
    AiAnalysis,
    AnonymousDevice,
    Attachment,
    AuditLog,
    Base,
    Incident,
    MapFeature,
    OutboxEvent,
    Report,
    ReportRevision,
)
from crisis_mosaic.routers.map import map_view
from crisis_mosaic.routers.reports import router as reports_router
from crisis_mosaic.schemas.reports import ReportCreate, ReportLocation, ReportPatch
from crisis_mosaic.security import Actor
from crisis_mosaic.services.attachments import attachments_by_report
from crisis_mosaic.services.idempotency import finish, replay_or_reserve
from crisis_mosaic.services.reports import (
    apply_location,
    assert_report_access,
    create_report,
)
from crisis_mosaic.utils import canonical_json, sha256_text, utcnow


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


def test_patch_reuses_bound_refinement_for_non_context_changes() -> None:
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
                            content_original="Road is blocked",
                            location={"text": "Daguan Bridge"},
                        ),
                    )
                    context = {
                        "request_context": {
                            "incident_id": incident.id,
                            "language": "zh-CN",
                            "timezone": "Asia/Shanghai",
                            "report_id": report.id,
                            "report_revision": report.revision,
                        },
                        "report": {
                            "category": report.category,
                            "content": report.content_original,
                            "location_text": report.location_text,
                        },
                        "attachments": [],
                    }
                    refinement = AiAnalysis(
                        incident_id=incident.id,
                        analysis_type="report_refinement",
                        status="succeeded",
                        input_snapshot=context,
                        context_package=context,
                        context_sha256=sha256_text(canonical_json(context)),
                        output={
                            "refined_content": (
                                "【道路情况】Road is blocked\n【位置】Daguan Bridge"
                            ),
                            "suggest_urgent": False,
                            "confidence": 0.8,
                        },
                        prompt_version="cm-report-refinement-v1.1.0",
                        created_by_type="device",
                        created_by_id=actor.subject_id,
                    )
                    session.add(refinement)
                    await session.flush()
                    report_id = report.id
                    incident_id = incident.id
                    refinement_id = refinement.id

            async def session_override() -> AsyncIterator[Any]:
                async with factory() as session:
                    yield session

            async def actor_override() -> Actor:
                return actor

            app = FastAPI()
            install_error_handlers(app)
            app.include_router(reports_router, prefix="/api/v1")
            app.dependency_overrides[get_actor] = actor_override
            app.dependency_overrides[get_session] = session_override
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                applied = await client.patch(
                    f"/api/v1/reports/{report_id}",
                    headers={"X-Incident-Id": incident_id},
                    json={"revision": 1, "ai_refinement_id": refinement_id},
                )
                assert applied.status_code == 200, applied.text

                urgent = await client.patch(
                    f"/api/v1/reports/{report_id}",
                    headers={"X-Incident-Id": incident_id},
                    json={"revision": 2, "is_urgent": True},
                )
                assert urgent.status_code == 200, urgent.text
                assert urgent.json()["data"]["ai_refinement_id"] == refinement_id

                display = await client.patch(
                    f"/api/v1/reports/{report_id}",
                    headers={"X-Incident-Id": incident_id},
                    json={"revision": 3, "content_display": "Road remains blocked"},
                )
                assert display.status_code == 200, display.text

                explicit_rebind = await client.patch(
                    f"/api/v1/reports/{report_id}",
                    headers={"X-Incident-Id": incident_id},
                    json={"revision": 4, "ai_refinement_id": refinement_id},
                )
                assert explicit_rebind.status_code == 422
                assert explicit_rebind.json()["error"]["code"] == "AI_REFINEMENT_CONTEXT_MISMATCH"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_report_responses_include_attachments_and_patch_replaces_explicitly() -> None:
    async def scenario() -> None:
        engine, factory = await _database()
        try:
            async with factory() as session:
                async with session.begin():
                    incident, device, actor = await _seed(session)
                    first_attachment = Attachment(
                        id="report-attachment-1",
                        incident_id=incident.id,
                        uploader_device_id=device.id,
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
                        id="report-attachment-2",
                        incident_id=incident.id,
                        uploader_device_id=device.id,
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
                    session.add_all([first_attachment, second_attachment])
                    report = await create_report(
                        session,
                        incident=incident,
                        actor=actor,
                        payload=ReportCreate(
                            category="road",
                            reporter=_reporter(),
                            content_original="Road is flooded",
                            location={"text": "Daguan Bridge"},
                            attachment_ids=[first_attachment.id],
                        ),
                    )
                    report_id = report.id
                    incident_id = incident.id

            async def session_override() -> AsyncIterator[Any]:
                async with factory() as session:
                    yield session

            async def actor_override() -> Actor:
                return actor

            from crisis_mosaic.db import get_session

            app = FastAPI()
            install_error_handlers(app)
            app.include_router(reports_router, prefix="/api/v1")
            app.dependency_overrides[get_actor] = actor_override
            app.dependency_overrides[get_session] = session_override
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get(
                    f"/api/v1/reports/{report_id}",
                    headers={"X-Incident-Id": incident_id},
                )
                assert response.status_code == 200, response.text
                data = response.json()["data"]
                assert data["attachment_ids"] == ["report-attachment-1"]
                assert data["attachments"][0]["report_id"] == report_id
                assert data["attachments"][0]["directed_answer_id"] is None
                assert data["attachments"][0]["content_url"].endswith(
                    "/report-attachment-1/content"
                )

                omitted = await client.patch(
                    f"/api/v1/reports/{report_id}",
                    headers={"X-Incident-Id": incident_id},
                    json={"revision": 1, "content_original": "Road remains flooded"},
                )
                assert omitted.status_code == 200, omitted.text
                assert omitted.json()["data"]["attachment_ids"] == ["report-attachment-1"]

                replaced = await client.patch(
                    f"/api/v1/reports/{report_id}",
                    headers={"X-Incident-Id": incident_id},
                    json={"revision": 2, "attachment_ids": ["report-attachment-2"]},
                )
                assert replaced.status_code == 200, replaced.text
                assert replaced.json()["data"]["attachment_ids"] == ["report-attachment-2"]

                cleared = await client.patch(
                    f"/api/v1/reports/{report_id}",
                    headers={"X-Incident-Id": incident_id},
                    json={"revision": 3, "attachment_ids": []},
                )
                assert cleared.status_code == 200, cleared.text
                assert cleared.json()["data"]["attachment_ids"] == []
                assert cleared.json()["data"]["attachment_count"] == 0

            async with factory() as session:
                attachment_map = await attachments_by_report(session, [report_id])
                assert attachment_map[report_id] == []
                assert (await session.get(Attachment, "report-attachment-1")).report_id is None
                assert (await session.get(Attachment, "report-attachment-2")).report_id is None
                stored_report = await session.get(Report, report_id)
                assert stored_report is not None
                assert stored_report.attachment_count == 0
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_http_report_reads_return_plain_contact_without_caching() -> None:
    async def scenario() -> None:
        engine, factory = await _database()
        try:
            async with factory() as session:
                async with session.begin():
                    incident, _, resident = await _seed(session)
                    report = await create_report(
                        session,
                        incident=incident,
                        actor=resident,
                        payload=ReportCreate(
                            category="road",
                            reporter={
                                "full_name": "Zhang Ming",
                                "mobile": "13800138000",
                                "additional_info": {
                                    "national_id": "11010519491231002X",
                                    "emergency_contact": {
                                        "name": "Li Ming",
                                        "mobile": "13900139000",
                                        "relation": "friend",
                                    },
                                    "rescue_notes": "Needs medication",
                                },
                            },
                            content_original="Road is blocked",
                            location={"text": "Daguan Bridge"},
                        ),
                    )
                    report_id = report.id
                    incident_id = incident.id

            operator = Actor(
                subject_type="account",
                subject_id="operator-report-reader",
                role="operator",
                token_version=1,
                incident_ids=frozenset({incident_id}),
                username="operator",
            )
            admin = Actor(
                subject_type="account",
                subject_id="admin-report-reader",
                role="admin",
                token_version=1,
                incident_ids=frozenset({incident_id}),
                username="admin",
            )
            actor_ref = {"value": operator}

            async def session_override() -> AsyncIterator[Any]:
                async with factory() as session:
                    yield session

            async def actor_override() -> Actor:
                return actor_ref["value"]

            app = FastAPI()
            install_error_handlers(app)
            app.include_router(reports_router, prefix="/api/v1")
            app.dependency_overrides[get_actor] = actor_override
            app.dependency_overrides[get_session] = session_override
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            headers = {"X-Incident-Id": incident_id}
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                list_response = await client.get(
                    f"/api/v1/incidents/{incident_id}/reports",
                    headers=headers,
                )
                assert list_response.status_code == 200, list_response.text
                listed = list_response.json()["data"][0]
                assert listed["source"] == {
                    "type": "anonymous_device",
                    "device_id": resident.subject_id,
                }
                assert listed["reporter"] == {
                    "full_name_masked": "Z***",
                    "mobile_masked": "138****8000",
                    "has_national_id": True,
                    "emergency_contact": {
                        "name_masked": "L***",
                        "mobile_masked": "139****9000",
                        "relation_masked": "friend",
                    },
                    "has_rescue_notes": True,
                }
                assert "Zhang Ming" not in list_response.text
                assert "13800138000" not in list_response.text

                detail_response = await client.get(
                    f"/api/v1/reports/{report_id}",
                    headers=headers,
                )
                assert detail_response.status_code == 200, detail_response.text
                assert detail_response.headers["cache-control"] == "no-store"
                plain_reporter = {
                    "full_name": "Zhang Ming",
                    "mobile": "+8613800138000",
                    "additional_info": {
                        "national_id": "11010519491231002X",
                        "emergency_contact": {
                            "name": "Li Ming",
                            "mobile": "+8613900139000",
                            "relation": "friend",
                        },
                        "rescue_notes": "Needs medication",
                    },
                }
                assert detail_response.json()["data"]["reporter"] == plain_reporter

                actor_ref["value"] = admin
                admin_response = await client.get(
                    f"/api/v1/reports/{report_id}",
                    headers=headers,
                )
                assert admin_response.status_code == 200, admin_response.text
                assert admin_response.headers["cache-control"] == "no-store"
                assert admin_response.json()["data"]["reporter"] == plain_reporter

                actor_ref["value"] = resident
                resident_response = await client.get(
                    f"/api/v1/reports/{report_id}",
                    headers=headers,
                )
                assert resident_response.status_code == 200, resident_response.text
                assert resident_response.headers["cache-control"] == "no-store"
                assert resident_response.json()["data"]["reporter"] == {
                    "full_name_masked": "Z***",
                    "mobile_masked": "138****8000",
                    "has_national_id": True,
                    "emergency_contact": {
                        "name_masked": "L***",
                        "mobile_masked": "139****9000",
                        "relation_masked": "friend",
                    },
                    "has_rescue_notes": True,
                }

            async with factory() as session:
                audits = list(
                    (
                        await session.scalars(
                            select(AuditLog)
                            .where(
                                AuditLog.resource_id == report_id,
                                AuditLog.action == "report.command_detail_read",
                            )
                            .order_by(AuditLog.created_at)
                        )
                    ).all()
                )
                assert [audit.actor_id for audit in audits] == [
                    operator.subject_id,
                    admin.subject_id,
                ]
                assert [audit.details["metadata"]["actor_role"] for audit in audits] == [
                    "operator",
                    "admin",
                ]
                assert all(
                    audit.details["metadata"]["access_scope"]
                    == "authenticated_command_report_detail"
                    for audit in audits
                )
                events = list(
                    (
                        await session.scalars(
                            select(OutboxEvent).where(OutboxEvent.resource_id == report_id)
                        )
                    ).all()
                )
                assert events == []
                persisted_security_records = json.dumps(
                    {
                        "audits": [audit.details for audit in audits],
                        "events": [event.payload for event in events],
                    },
                    ensure_ascii=False,
                )
                assert "Zhang Ming" not in persisted_security_records
                assert "13800138000" not in persisted_security_records
                assert "11010519491231002X" not in persisted_security_records
                assert "Needs medication" not in persisted_security_records
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_resident_owner_can_soft_delete_report_with_revision() -> None:
    async def scenario() -> None:
        engine, factory = await _database()
        try:
            async with factory() as session:
                async with session.begin():
                    incident, _, owner = await _seed(session)
                    report = await create_report(
                        session,
                        incident=incident,
                        actor=owner,
                        payload=ReportCreate(
                            category="road",
                            reporter={
                                "full_name": "Delete Owner",
                                "mobile": "13800138000",
                            },
                            content_original="Delete this report",
                            location={
                                "text": "Daguan Bridge",
                                "latitude": 30.31,
                                "longitude": 120.15,
                                "coordinate_system": "gcj02",
                            },
                        ),
                    )
                    report_id = report.id
                    incident_id = incident.id

            operator = Actor(
                subject_type="account",
                subject_id="operator-delete-denied",
                role="operator",
                token_version=1,
                incident_ids=frozenset({incident_id}),
                username="operator",
            )
            other_resident = Actor(
                subject_type="device",
                subject_id="other-resident-device",
                role="resident",
                token_version=1,
                incident_ids=frozenset({incident_id}),
            )
            actor_ref = {"value": operator}

            async def session_override() -> AsyncIterator[Any]:
                async with factory() as session:
                    yield session

            async def actor_override() -> Actor:
                return actor_ref["value"]

            app = FastAPI()
            install_error_handlers(app)
            app.include_router(reports_router, prefix="/api/v1")
            app.dependency_overrides[get_actor] = actor_override
            app.dependency_overrides[get_session] = session_override
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            headers = {"X-Incident-Id": incident_id}
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                denied_operator = await client.request(
                    "DELETE",
                    f"/api/v1/reports/{report_id}",
                    headers=headers,
                    json={"revision": 1},
                )
                assert denied_operator.status_code == 403, denied_operator.text
                assert denied_operator.json()["error"]["code"] == "RESIDENT_REQUIRED"

                actor_ref["value"] = other_resident
                denied_other = await client.request(
                    "DELETE",
                    f"/api/v1/reports/{report_id}",
                    headers=headers,
                    json={"revision": 1},
                )
                assert denied_other.status_code == 403, denied_other.text
                assert denied_other.json()["error"]["code"] == "REPORT_OWNERSHIP_REQUIRED"

                actor_ref["value"] = owner
                stale = await client.request(
                    "DELETE",
                    f"/api/v1/reports/{report_id}",
                    headers=headers,
                    json={"revision": 2},
                )
                assert stale.status_code == 409, stale.text
                assert stale.json()["error"]["code"] == "REVISION_CONFLICT"

                deleted = await client.request(
                    "DELETE",
                    f"/api/v1/reports/{report_id}",
                    headers=headers,
                    json={"revision": 1},
                )
                assert deleted.status_code == 200, deleted.text
                tombstone = deleted.json()["data"]
                assert tombstone["report_id"] == report_id
                assert tombstone["revision"] == 2
                assert tombstone["deleted_at"] is not None

                missing = await client.get(
                    f"/api/v1/reports/{report_id}",
                    headers=headers,
                )
                assert missing.status_code == 404, missing.text
                reports_after_delete = await client.get(
                    f"/api/v1/incidents/{incident_id}/reports",
                    headers=headers,
                )
                assert reports_after_delete.status_code == 200, reports_after_delete.text
                assert reports_after_delete.json()["data"] == []

            async with factory() as session:
                stored_report = await session.get(Report, report_id)
                assert stored_report is not None
                assert stored_report.deleted_at is not None
                assert stored_report.revision == 2
                revisions = list(
                    (
                        await session.scalars(
                            select(ReportRevision)
                            .where(ReportRevision.report_id == report_id)
                            .order_by(ReportRevision.revision)
                        )
                    ).all()
                )
                assert [revision.revision for revision in revisions] == [1, 2]
                assert revisions[-1].change_reason == "resident_deleted"
                assert revisions[-1].snapshot["deleted_at"] == tombstone["deleted_at"]

                feature = await session.scalar(
                    select(MapFeature).where(MapFeature.source_ref == report_id)
                )
                assert feature is not None
                assert feature.is_deleted is True
                audit = await session.scalar(
                    select(AuditLog).where(
                        AuditLog.resource_id == report_id,
                        AuditLog.action == "report.deleted",
                    )
                )
                assert audit is not None
                event = await session.scalar(
                    select(OutboxEvent).where(
                        OutboxEvent.resource_id == report_id,
                        OutboxEvent.event_type == "report.deleted",
                    )
                )
                assert event is not None
                assert event.visibility == "owner"
                assert event.owner_device_id == owner.subject_id
                assert event.payload["data"] == tombstone
                persisted_payloads = json.dumps(
                    {"audit": audit.details, "event": event.payload},
                    ensure_ascii=False,
                )
                assert "Delete Owner" not in persisted_payloads
                assert "13800138000" not in persisted_payloads
        finally:
            await engine.dispose()

    asyncio.run(scenario())


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
