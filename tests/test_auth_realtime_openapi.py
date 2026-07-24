from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session
from starlette.websockets import WebSocketDisconnect

from crisis_mosaic import main as main_module
from crisis_mosaic import realtime as realtime_module
from crisis_mosaic import security as security_module
from crisis_mosaic.config import Settings
from crisis_mosaic.db import get_session
from crisis_mosaic.models import (
    AnonymousDevice,
    Attachment,
    Base,
    BlindSpot,
    ConflictCase,
    DirectedQuestion,
    FactRecord,
    Incident,
    IncidentMembership,
    LocalAccount,
    OutboxEvent,
    Report,
)
from crisis_mosaic.routers import auth as auth_module
from crisis_mosaic.routers import incidents as incidents_module
from crisis_mosaic.security import Actor, hash_password

INCIDENT_LIVE = "incident-live"
INCIDENT_GAP = "incident-gap"
PASSWORD = "Correct-Horse-Battery-Staple-2026!"
PASSWORD_HASH = hash_password(PASSWORD)
ALLOWED_ORIGIN = "https://command.example.test"


def _event_payload(
    *,
    event_id: str,
    incident_id: str,
    sequence: int,
    event_type: str,
) -> dict[str, object]:
    return {
        "event_id": event_id,
        "type": event_type,
        "incident_id": incident_id,
        "sequence": sequence,
        "resource_type": "report",
        "resource_id": f"report-{sequence}",
        "resource_revision": 1,
        "occurred_at": datetime.now(UTC).isoformat(),
        "visibility": "public",
        "owner_device_id": None,
        "data": {"sequence": sequence},
        "payload": {"sequence": sequence},
    }


def _seed_database(database_path: Path) -> None:
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        live = Incident(
            id=INCIDENT_LIVE,
            alias="live",
            name="Live incident",
            status="active",
            event_sequence=2,
        )
        gap = Incident(
            id=INCIDENT_GAP,
            alias="gap",
            name="Replay gap incident",
            status="preparing",
            event_sequence=5,
        )
        admin = LocalAccount(
            id="account-admin",
            username="admin",
            password_hash=PASSWORD_HASH,
            role="admin",
        )
        operator = LocalAccount(
            id="account-operator",
            username="operator",
            password_hash=PASSWORD_HASH,
            role="operator",
        )
        resident = LocalAccount(
            id="account-resident",
            username="resident",
            password_hash=PASSWORD_HASH,
            role="resident",
        )
        device = AnonymousDevice(
            id="device-live",
            installation_id_hash="0" * 64,
            platform="test",
        )
        report = Report(
            id="report-live",
            incident_id=live.id,
            reporter_device_id=device.id,
            category="other",
            content_original="Resource header contract report",
            content_display="Resource header contract report",
            location_text="Test location",
        )
        attachment = Attachment(
            id="attachment-live",
            incident_id=live.id,
            report_id=report.id,
            uploader_device_id=device.id,
            file_name="evidence.jpg",
            declared_mime_type="image/jpeg",
            size_bytes=100,
            expected_sha256="1" * 64,
            upload_expires_at=now + timedelta(hours=1),
        )
        blind_spot = BlindSpot(
            id="blind-live",
            incident_id=live.id,
            claim_key="bridge.access",
            title="Bridge access",
            location_text="Test bridge",
        )
        question = DirectedQuestion(
            id="question-live",
            incident_id=live.id,
            blind_spot_id=blind_spot.id,
            title="Is the bridge open?",
            location_text="Test bridge",
            options=[
                {"id": "yes", "label": "Yes", "semantic_value": "open"},
                {"id": "no", "label": "No", "semantic_value": "closed"},
            ],
            status="published",
        )
        conflict_case = ConflictCase(
            id="conflict-live",
            incident_id=live.id,
            fact_key="bridge.access",
            title="Bridge access conflict",
            topic="transport",
            location_text="Test bridge",
        )
        fact_record = FactRecord(
            id="fact-live",
            incident_id=live.id,
            fact_key="bridge.access",
            topic="transport",
            location_text="Test bridge",
        )
        session.add_all(
            [
                live,
                gap,
                admin,
                operator,
                resident,
                device,
                report,
                attachment,
                blind_spot,
                question,
                conflict_case,
                fact_record,
            ]
        )
        session.add_all(
            [
                IncidentMembership(
                    account_id=admin.id,
                    incident_id=live.id,
                    role=admin.role,
                ),
                IncidentMembership(
                    account_id=admin.id,
                    incident_id=gap.id,
                    role=admin.role,
                ),
                IncidentMembership(
                    account_id=operator.id,
                    incident_id=live.id,
                    role=operator.role,
                ),
                IncidentMembership(
                    account_id=resident.id,
                    incident_id=live.id,
                    role=resident.role,
                ),
                OutboxEvent(
                    id="event-live-1",
                    incident_id=live.id,
                    sequence=1,
                    event_type="report.created",
                    visibility="public",
                    resource_type="report",
                    resource_id="report-1",
                    resource_revision=1,
                    payload=_event_payload(
                        event_id="event-live-1",
                        incident_id=live.id,
                        sequence=1,
                        event_type="report.created",
                    ),
                    occurred_at=now,
                ),
                OutboxEvent(
                    id="event-live-2",
                    incident_id=live.id,
                    sequence=2,
                    event_type="report.updated",
                    visibility="public",
                    resource_type="report",
                    resource_id="report-2",
                    resource_revision=1,
                    payload=_event_payload(
                        event_id="event-live-2",
                        incident_id=live.id,
                        sequence=2,
                        event_type="report.updated",
                    ),
                    occurred_at=now,
                ),
                OutboxEvent(
                    id="event-gap-5",
                    incident_id=gap.id,
                    sequence=5,
                    event_type="report.created",
                    visibility="public",
                    resource_type="report",
                    resource_id="report-5",
                    resource_revision=1,
                    payload=_event_payload(
                        event_id="event-gap-5",
                        incident_id=gap.id,
                        sequence=5,
                        event_type="report.created",
                    ),
                    occurred_at=now,
                ),
            ]
        )
        session.commit()
    engine.dispose()


@pytest.fixture
def client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TestClient]:
    database_path = tmp_path / "integration.db"
    _seed_database(database_path)
    database_url = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    settings = Settings(
        app_env="test",
        auto_create_schema=False,
        database_url=database_url,
        data_dir=tmp_path,
        storage_root=tmp_path / "uploads",
        cors_origins=[ALLOWED_ORIGIN],
        jwt_secret="integration-test-jwt-secret-with-sufficient-entropy",
        installation_id_pepper="integration-test-installation-pepper",
        upload_signing_secret="integration-test-upload-signing-secret",
        ai_provider="fake",
        realtime_replay_hours=24,
        realtime_heartbeat_seconds=30,
    )
    engine = create_async_engine(database_url)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)

    async def session_override() -> AsyncIterator[AsyncSession]:
        async with session_maker() as session:
            yield session

    @asynccontextmanager
    async def test_lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await engine.dispose()

    def get_test_settings() -> Settings:
        return settings

    monkeypatch.setattr(main_module, "get_settings", get_test_settings)
    monkeypatch.setattr(auth_module, "get_settings", get_test_settings)
    monkeypatch.setattr(incidents_module, "get_settings", get_test_settings)
    monkeypatch.setattr(security_module, "get_settings", get_test_settings)
    monkeypatch.setattr(realtime_module, "get_settings", get_test_settings)
    monkeypatch.setattr(realtime_module, "session_factory", lambda: session_maker)

    app = main_module.create_app()
    app.router.lifespan_context = test_lifespan
    app.dependency_overrides[get_session] = session_override
    with TestClient(app) as test_client:
        yield test_client


def _login(client: TestClient, username: str) -> dict[str, object]:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": PASSWORD},
    )
    assert response.status_code == 200, response.text
    return response.json()["data"]


def test_login_me_refresh_rotation_replay_and_logout(client: TestClient) -> None:
    login = _login(client, "admin")
    access_token = str(login["access_token"])
    original_refresh = str(login["refresh_token"])

    me = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me.status_code == 200, me.text
    assert me.json()["data"] == {
        "subject_type": "account",
        "subject_id": "account-admin",
        "username": "admin",
        "role": "admin",
        "incident_ids": [INCIDENT_GAP, INCIDENT_LIVE],
    }

    rotated = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original_refresh},
    )
    assert rotated.status_code == 200, rotated.text
    replacement_refresh = rotated.json()["data"]["refresh_token"]
    assert replacement_refresh != original_refresh

    replay = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original_refresh},
    )
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "REFRESH_TOKEN_REPLAYED"

    logout = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": replacement_refresh},
    )
    assert logout.status_code == 200
    assert logout.json()["data"] == {"revoked": True}

    revoked = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": replacement_refresh},
    )
    assert revoked.status_code == 401
    assert revoked.json()["error"]["code"] == "REFRESH_TOKEN_EXPIRED"


def test_role_incident_context_request_ids_and_cors(client: TestClient) -> None:
    resident = _login(client, "resident")
    resident_denied = client.get(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {resident['access_token']}"},
    )
    assert resident_denied.status_code == 403
    assert resident_denied.json()["error"]["code"] == "FORBIDDEN"

    operator = _login(client, "operator")
    operator_headers = {"Authorization": f"Bearer {operator['access_token']}"}
    context_mismatch = client.get(
        f"/api/v1/incidents/{INCIDENT_LIVE}/command-overview",
        headers={**operator_headers, "X-Incident-Id": INCIDENT_GAP},
    )
    assert context_mismatch.status_code == 403
    assert context_mismatch.json()["error"]["code"] == "INCIDENT_CONTEXT_MISMATCH"

    incident_denied = client.get(
        f"/api/v1/incidents/{INCIDENT_GAP}/command-overview",
        headers={**operator_headers, "X-Incident-Id": INCIDENT_GAP},
    )
    assert incident_denied.status_code == 403
    assert incident_denied.json()["error"]["code"] == "INCIDENT_ACCESS_DENIED"

    request_id = "integration-request-id"
    success = client.get(
        "/api/v1/incidents/current",
        headers={**operator_headers, "X-Request-Id": request_id},
    )
    assert success.status_code == 200
    assert success.headers["X-Request-Id"] == request_id
    assert success.json()["meta"]["request_id"] == request_id

    missing_auth = client.get(
        "/api/v1/auth/me",
        headers={"X-Request-Id": request_id},
    )
    assert missing_auth.status_code == 401
    assert missing_auth.headers["X-Request-Id"] == request_id
    assert missing_auth.json()["error"]["request_id"] == request_id

    preflight = client.options(
        "/api/v1/auth/me",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization,X-Request-Id",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["Access-Control-Allow-Origin"] == ALLOWED_ORIGIN
    assert preflight.headers["Access-Control-Allow-Credentials"] == "true"


def test_resource_id_routes_reject_mismatched_incident_header(client: TestClient) -> None:
    tokens = {
        role: str(_login(client, role)["access_token"])
        for role in ("admin", "operator", "resident")
    }
    cases: list[tuple[str, str, dict[str, object] | None, str]] = [
        ("GET", "/api/v1/reports/report-live", None, "operator"),
        ("GET", "/api/v1/uploads/attachment-live", None, "operator"),
        (
            "POST",
            "/api/v1/directed-questions/question-live/publish",
            {"revision": 1},
            "operator",
        ),
        (
            "POST",
            "/api/v1/directed-questions/question-live/close",
            {"revision": 1},
            "operator",
        ),
        (
            "PUT",
            "/api/v1/directed-questions/question-live/my-answer",
            {"revision": 0, "option_id": "yes"},
            "resident",
        ),
        ("GET", "/api/v1/conflicts/conflict-live", None, "operator"),
        (
            "POST",
            "/api/v1/conflicts/conflict-live/evidence",
            {
                "revision": 1,
                "evidence": [
                    {
                        "kind": "report",
                        "source_id": "report-live",
                        "source_revision": 1,
                    }
                ],
            },
            "operator",
        ),
        (
            "POST",
            "/api/v1/conflicts/conflict-live/reopen",
            {"revision": 1, "reason": "Retest header contract"},
            "operator",
        ),
        (
            "POST",
            "/api/v1/conflicts/conflict-live/decision",
            {
                "revision": 1,
                "decision": "manual_conclusion",
                "evidence_decisions": [
                    {
                        "evidence_id": "evidence-live",
                        "disposition": "accepted",
                    }
                ],
                "conclusion": "Header mismatch must fail first",
            },
            "operator",
        ),
        ("GET", "/api/v1/fact-records/fact-live", None, "operator"),
        (
            "PATCH",
            f"/api/v1/incidents/{INCIDENT_LIVE}",
            {"revision": 0, "name": "Should not be applied"},
            "admin",
        ),
    ]

    for method, path, body, role in cases:
        response = client.request(
            method,
            path,
            headers={
                "Authorization": f"Bearer {tokens[role]}",
                "X-Incident-Id": INCIDENT_GAP,
            },
            json=body,
        )
        assert response.status_code == 403, (method, path, response.text)
        assert response.json()["error"]["code"] == "INCIDENT_CONTEXT_MISMATCH"


def test_incident_creator_membership_allows_immediate_scoped_patch(
    client: TestClient,
) -> None:
    token = str(_login(client, "admin")["access_token"])
    authorization = {"Authorization": f"Bearer {token}"}
    created = client.post(
        "/api/v1/incidents",
        headers=authorization,
        json={
            "alias": "new-admin-incident",
            "name": "New admin incident",
            "status": "preparing",
        },
    )
    assert created.status_code == 201, created.text
    incident = created.json()["data"]

    mismatch = client.patch(
        f"/api/v1/incidents/{incident['id']}",
        headers={**authorization, "X-Incident-Id": INCIDENT_GAP},
        json={"revision": incident["data_revision"], "name": "Rejected name"},
    )
    assert mismatch.status_code == 403
    assert mismatch.json()["error"]["code"] == "INCIDENT_CONTEXT_MISMATCH"

    updated = client.patch(
        f"/api/v1/incidents/{incident['id']}",
        headers={**authorization, "X-Incident-Id": incident["id"]},
        json={"revision": incident["data_revision"], "name": "Managed immediately"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["data"]["name"] == "Managed immediately"


def test_admin_user_patch_requires_and_increments_revision(client: TestClient) -> None:
    token = str(_login(client, "admin")["access_token"])
    headers = {"Authorization": f"Bearer {token}"}

    users = client.get("/api/v1/admin/users", headers=headers)
    assert users.status_code == 200, users.text
    operator = next(item for item in users.json()["data"] if item["id"] == "account-operator")
    assert operator["revision"] == 1

    missing_revision = client.patch(
        "/api/v1/admin/users/account-operator",
        headers=headers,
        json={"is_active": False},
    )
    assert missing_revision.status_code == 422
    assert missing_revision.json()["error"]["code"] == "VALIDATION_ERROR"

    updated = client.patch(
        "/api/v1/admin/users/account-operator",
        headers=headers,
        json={"revision": 1, "is_active": False},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["data"]["revision"] == 2
    assert updated.json()["data"]["is_active"] is False

    stale = client.patch(
        "/api/v1/admin/users/account-operator",
        headers=headers,
        json={"revision": 1, "is_active": True},
    )
    assert stale.status_code == 409
    assert stale.json()["error"] == {
        "code": "REVISION_CONFLICT",
        "message": "account revision does not match",
        "request_id": stale.headers["X-Request-Id"],
        "details": {"expected_revision": 1, "current_revision": 2},
    }


def test_openapi_self_hosted_swagger_and_realtime_schema(client: TestClient) -> None:
    root = client.get("/", follow_redirects=False)
    assert root.status_code == 307
    assert root.headers["location"] == "/docs"

    openapi = client.get("/api/v1/openapi.json")
    assert openapi.status_code == 200
    document = openapi.json()
    assert document["openapi"].startswith("3.1.")
    assert any(tag["name"] == "AI" for tag in document["tags"])
    assert "/api/v1/ai/report-refinements" in document["paths"]
    assert "/api/v1/realtime" not in document["paths"]
    assert document["components"]["securitySchemes"]["HTTPBearer"] == {
        "type": "http",
        "scheme": "bearer",
    }
    upload_content = document["paths"]["/api/v1/uploads/{attachment_id}/content"]["put"]
    assert upload_content["requestBody"] == {
        "required": True,
        "description": "Raw file bytes. Content-Type must match the upload intent MIME type.",
        "content": {"*/*": {"schema": {"type": "string", "format": "binary"}}},
    }
    complete_schema = document["paths"]["/api/v1/uploads/{attachment_id}/complete"][
        "post"
    ]["requestBody"]["content"]["application/json"]["schema"]
    assert {"$ref": "#/components/schemas/UploadCompleteRequest"} in complete_schema[
        "anyOf"
    ]
    resource_markers = (
        "{incident_id}",
        "{report_id}",
        "{attachment_id}",
        "{question_id}",
        "{conflict_id}",
        "{fact_record_id}",
        "{analysis_id}",
    )
    for path, path_item in document["paths"].items():
        if not any(marker in path for marker in resource_markers):
            continue
        for method, operation in path_item.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            incident_parameters = [
                parameter
                for parameter in operation.get("parameters", [])
                if isinstance(parameter, dict) and parameter.get("name") == "X-Incident-Id"
            ]
            assert len(incident_parameters) == 1, (method, path)
            assert incident_parameters[0]["required"] is True, (method, path)

    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "/static/swagger/swagger-ui-bundle.js?v=5.32.11" in docs.text
    assert "/static/swagger/swagger-ui.css?v=5.32.11" in docs.text
    assert "cdn.jsdelivr.net" not in docs.text
    javascript = client.get("/static/swagger/swagger-ui-bundle.js?v=5.32.11")
    stylesheet = client.get("/static/swagger/swagger-ui.css?v=5.32.11")
    assert javascript.status_code == 200
    assert "SwaggerUIBundle" in javascript.text
    assert stylesheet.status_code == 200
    assert ".swagger-ui" in stylesheet.text

    realtime_schema = client.get("/schemas/realtime-event.json")
    assert realtime_schema.status_code == 200
    assert realtime_schema.headers["content-type"].startswith("application/schema+json")
    schema = realtime_schema.json()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert {
        "event_id",
        "type",
        "incident_id",
        "sequence",
        "resource_type",
        "occurred_at",
        "data",
    } <= set(schema["required"])
    assert "payload" not in schema["required"]
    assert "payload" in schema["properties"]

    push_schema = client.get("/schemas/push-payload.json")
    assert push_schema.status_code == 200
    assert push_schema.headers["content-type"].startswith("application/schema+json")
    push_document = push_schema.json()
    assert push_document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert push_document["properties"]["data"]["additionalProperties"] is False
    assert {
        "notification_id",
        "business_event_id",
        "incident_id",
        "event_type",
        "resource_type",
        "deep_link",
    } <= set(push_document["properties"]["data"]["required"])


def test_question_realtime_visibility_honors_region_and_hides_spatial_targets() -> None:
    resident = Actor(
        subject_type="device",
        subject_id="device-hangzhou",
        role="resident",
        token_version=1,
        incident_ids=frozenset({INCIDENT_LIVE}),
        region_code="330100",
    )
    regional_event = {
        "type": "question.published",
        "visibility": "public",
        "data": {"target_geometry": {"region_codes": ["330100"]}},
    }
    other_region_event = {
        "type": "question.published",
        "visibility": "public",
        "data": {"target_geometry": {"region_codes": ["310000"]}},
    }
    spatial_event = {
        "type": "question.published",
        "visibility": "public",
        "data": {
            "target_geometry": {
                "region_codes": ["330100"],
                "bbox": [120.0, 30.0, 120.2, 30.2],
            }
        },
    }

    assert realtime_module.event_visible(resident, regional_event) is True
    assert realtime_module.event_visible(resident, other_region_event) is False
    assert realtime_module.event_visible(resident, spatial_event) is False
    assert realtime_module.event_visible(
        resident,
        {"type": "report.created", "visibility": "public", "data": {}},
    )


def test_operator_cannot_use_resident_report_patch(client: TestClient) -> None:
    operator = _login(client, "operator")
    response = client.patch(
        "/api/v1/reports/does-not-exist",
        headers={
            "Authorization": f"Bearer {operator['access_token']}",
            "X-Incident-Id": INCIDENT_LIVE,
        },
        json={"revision": 1, "content_original": "operator edit"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "RESIDENT_REQUIRED"


def test_websocket_first_message_authentication_and_replay(
    client: TestClient,
) -> None:
    with client.websocket_connect("/api/v1/realtime") as websocket:
        websocket.send_json({"type": "subscribe"})
        assert websocket.receive_json() == {
            "type": "error",
            "code": "AUTHENTICATION_REQUIRED",
        }
        with pytest.raises(WebSocketDisconnect) as disconnect:
            websocket.receive_json()
        assert disconnect.value.code == 4401

    access_token = _login(client, "admin")["access_token"]
    with client.websocket_connect("/api/v1/realtime") as websocket:
        websocket.send_json(
            {
                "type": "authenticate",
                "access_token": access_token,
                "incident_id": INCIDENT_LIVE,
                "last_sequence": 0,
            }
        )
        ready = websocket.receive_json()
        assert ready["type"] == "ready"
        assert ready["latest_sequence"] == 2
        assert ready["oldest_available_sequence"] == 1
        assert [websocket.receive_json()["sequence"] for _ in range(2)] == [1, 2]


def test_websocket_replay_window_and_query_token_rejection(
    client: TestClient,
) -> None:
    access_token = _login(client, "admin")["access_token"]
    with client.websocket_connect(f"/api/v1/realtime?access_token={access_token}") as websocket:
        assert websocket.receive_json() == {
            "type": "error",
            "code": "QUERY_TOKEN_FORBIDDEN",
        }
        with pytest.raises(WebSocketDisconnect) as disconnect:
            websocket.receive_json()
        assert disconnect.value.code == 4401

    with client.websocket_connect("/api/v1/realtime") as websocket:
        websocket.send_json(
            {
                "type": "authenticate",
                "access_token": access_token,
                "incident_id": INCIDENT_GAP,
                "last_sequence": 0,
            }
        )
        assert websocket.receive_json() == {
            "type": "full_resync_required",
            "oldest_available_sequence": 5,
            "latest_sequence": 5,
        }
        with pytest.raises(WebSocketDisconnect) as disconnect:
            websocket.receive_json()
        assert disconnect.value.code == 4409
