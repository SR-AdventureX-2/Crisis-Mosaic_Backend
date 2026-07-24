from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

from crisis_mosaic import main as main_module
from crisis_mosaic import middleware as middleware_module
from crisis_mosaic import security as security_module
from crisis_mosaic.config import Settings
from crisis_mosaic.db import get_session
from crisis_mosaic.models import Base, IdempotencyRecord, Incident, LocalAccount
from crisis_mosaic.routers import auth as auth_module
from crisis_mosaic.routers import incidents as incidents_module
from crisis_mosaic.security import hash_password

PASSWORD = "Correct-Horse-Battery-Staple-2026!"


def _seed_database(database_path: Path) -> None:
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all(
            [
                LocalAccount(
                    id="idempotency-admin",
                    username="idempotency-admin",
                    password_hash=hash_password(PASSWORD),
                    role="admin",
                ),
                Incident(
                    id="existing-active-incident",
                    alias="existing-active",
                    name="Existing active incident",
                    status="active",
                ),
            ]
        )
        session.commit()
    engine.dispose()


@pytest.fixture
def idempotency_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[TestClient, Path]]:
    database_path = tmp_path / "idempotency.db"
    _seed_database(database_path)
    database_url = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    settings = Settings(
        app_env="test",
        auto_create_schema=False,
        database_url=database_url,
        data_dir=tmp_path,
        storage_root=tmp_path / "uploads",
        jwt_secret="idempotency-test-jwt-secret-with-sufficient-entropy",
        installation_id_pepper="idempotency-test-installation-pepper",
        upload_signing_secret="idempotency-test-upload-signing-secret",
        ai_provider="fake",
        rate_limit_anonymous_sessions_per_minute=1,
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
    monkeypatch.setattr(middleware_module, "get_settings", get_test_settings)
    monkeypatch.setattr(middleware_module, "session_factory", lambda: session_maker)
    monkeypatch.setattr(security_module, "get_settings", get_test_settings)

    app = main_module.create_app()
    app.router.lifespan_context = test_lifespan
    app.dependency_overrides[get_session] = session_override
    with TestClient(app) as client:
        yield client, database_path


def _authorization(client: TestClient) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "idempotency-admin", "password": PASSWORD},
    )
    assert response.status_code == 200, response.text
    return f"Bearer {response.json()['data']['access_token']}"


def _database_value(database_path: Path, statement: Any) -> Any:
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    try:
        with Session(engine) as session:
            return session.scalar(statement)
    finally:
        engine.dispose()


def test_success_replay_and_body_conflict_are_persistent(
    idempotency_client: tuple[TestClient, Path],
) -> None:
    client, database_path = idempotency_client
    authorization = _authorization(client)
    body = {
        "alias": "idempotent-incident",
        "name": "Idempotent incident",
        "status": "preparing",
    }
    first = client.post(
        "/api/v1/incidents",
        json=body,
        headers={
            "Authorization": authorization,
            "Idempotency-Key": "incident-create-1",
            "X-Request-Id": "first-request",
        },
    )
    assert first.status_code == 201, first.text

    replay = client.post(
        "/api/v1/incidents",
        json=body,
        headers={
            "Authorization": authorization,
            "Idempotency-Key": "incident-create-1",
            "X-Request-Id": "replay-request",
        },
    )
    assert replay.status_code == 201
    assert replay.json() == first.json()
    assert replay.headers["X-Request-Id"] == "replay-request"

    conflict = client.post(
        "/api/v1/incidents",
        json={**body, "name": "A different request body"},
        headers={
            "Authorization": authorization,
            "Idempotency-Key": "incident-create-1",
        },
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"

    assert (
        _database_value(
            database_path,
            select(func.count(Incident.id)).where(Incident.alias == body["alias"]),
        )
        == 1
    )
    record = _database_value(
        database_path,
        select(IdempotencyRecord).where(
            IdempotencyRecord.actor_key == "account:idempotency-admin",
            IdempotencyRecord.route == "POST:/api/v1/incidents",
            IdempotencyRecord.idempotency_key == "incident-create-1",
        ),
    )
    assert record is not None
    assert record.response_status == 201
    assert record.response_body == first.json()


def test_failed_response_releases_reservation(
    idempotency_client: tuple[TestClient, Path],
) -> None:
    client, database_path = idempotency_client
    authorization = _authorization(client)
    headers = {
        "Authorization": authorization,
        "Idempotency-Key": "retry-after-failure",
    }
    body = {
        "alias": "event-after-failure",
        "name": "Eventually created",
        "status": "active",
    }
    rejected = client.post("/api/v1/incidents", json=body, headers=headers)
    assert rejected.status_code == 409
    assert rejected.json()["error"]["code"] == "ACTIVE_INCIDENT_EXISTS"
    assert (
        _database_value(
            database_path,
            select(func.count(IdempotencyRecord.id)).where(
                IdempotencyRecord.idempotency_key == "retry-after-failure"
            ),
        )
        == 0
    )

    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    try:
        with Session(engine) as session:
            session.execute(
                update(Incident)
                .where(Incident.id == "existing-active-incident")
                .values(status="closed")
            )
            session.commit()
    finally:
        engine.dispose()

    accepted = client.post("/api/v1/incidents", json=body, headers=headers)
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["data"]["alias"] == "event-after-failure"


def test_openapi_marks_only_eligible_authenticated_post_and_put_operations(
    idempotency_client: tuple[TestClient, Path],
) -> None:
    client, _ = idempotency_client
    document = client.get("/api/v1/openapi.json").json()
    parameter = document["components"]["parameters"]["IdempotencyKey"]
    assert parameter["name"] == "Idempotency-Key"
    assert parameter["required"] is False

    reference = {"$ref": "#/components/parameters/IdempotencyKey"}
    assert reference in document["paths"]["/api/v1/incidents"]["post"]["parameters"]
    assert reference in document["paths"]["/api/v1/admin/users"]["post"]["parameters"]
    assert reference not in document["paths"]["/api/v1/uploads/{attachment_id}/content"]["put"].get(
        "parameters", []
    )

    report_parameters = document["paths"]["/api/v1/incidents/{incident_id}/reports"]["post"][
        "parameters"
    ]
    assert reference not in report_parameters
    report_header = next(
        item for item in report_parameters if item.get("name") == "Idempotency-Key"
    )
    assert report_header["required"] is True

    assert reference not in document["paths"]["/api/v1/auth/login"]["post"].get("parameters", [])
    assert reference not in document["paths"]["/api/v1/anonymous-sessions"]["post"].get(
        "parameters", []
    )


def test_anonymous_session_rate_limit_returns_standard_429(
    idempotency_client: tuple[TestClient, Path],
) -> None:
    client, _ = idempotency_client
    body = {
        "installation_id": "first-installation-id-with-128-bits-of-entropy",
        "platform": "android",
        "incident_id": "existing-active-incident",
    }
    first = client.post("/api/v1/anonymous-sessions", json=body)
    assert first.status_code == 201, first.text

    limited = client.post(
        "/api/v1/anonymous-sessions",
        json={**body, "installation_id": "second-installation-id-with-128-bits-of-entropy"},
    )
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMITED"
    assert int(limited.headers["Retry-After"]) >= 1
    assert limited.json()["error"]["details"]["retry_after_seconds"] >= 1
