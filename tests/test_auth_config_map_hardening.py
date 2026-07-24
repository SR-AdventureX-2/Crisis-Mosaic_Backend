from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

from crisis_mosaic import main as main_module
from crisis_mosaic import middleware as middleware_module
from crisis_mosaic import security as security_module
from crisis_mosaic.config import Settings
from crisis_mosaic.db import get_session
from crisis_mosaic.errors import ApiError
from crisis_mosaic.models import AnonymousDevice, Base, Incident, RefreshSession
from crisis_mosaic.routers import auth as auth_module
from crisis_mosaic.routers import incidents as incidents_module
from crisis_mosaic.routers import map as map_module
from crisis_mosaic.security import Actor, refresh_token_hash

ACTIVE_INCIDENT_ID = "incident-active"
PREPARING_INCIDENT_ID = "incident-preparing"
CLOSED_INCIDENT_ID = "incident-closed"


def _seed_auth_database(database_path: Path) -> None:
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all(
            [
                Incident(
                    id=ACTIVE_INCIDENT_ID,
                    alias="active",
                    name="Active incident",
                    status="active",
                ),
                Incident(
                    id=PREPARING_INCIDENT_ID,
                    alias="preparing",
                    name="Preparing incident",
                    status="preparing",
                ),
                Incident(
                    id=CLOSED_INCIDENT_ID,
                    alias="closed",
                    name="Closed incident",
                    status="closed",
                ),
            ]
        )
        session.commit()
    engine.dispose()


@pytest.fixture
def anonymous_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[TestClient, Path]]:
    database_path = tmp_path / "anonymous-scope.db"
    _seed_auth_database(database_path)
    database_url = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    settings = Settings(
        app_env="test",
        database_url=database_url,
        data_dir=tmp_path,
        storage_root=tmp_path / "uploads",
        jwt_secret="test-jwt-secret-with-enough-entropy-for-auth",
        installation_id_pepper="test-installation-pepper-with-enough-entropy",
        upload_signing_secret="test-upload-secret-with-enough-entropy",
        ai_provider="fake",
        rate_limit_enabled=False,
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
    monkeypatch.setattr(security_module, "get_settings", get_test_settings)

    app = main_module.create_app()
    app.router.lifespan_context = test_lifespan
    app.dependency_overrides[get_session] = session_override
    with TestClient(app) as client:
        yield client, database_path


def _anonymous_session_body(installation_id: str, incident_id: str | None = None) -> dict[str, str]:
    body = {
        "installation_id": installation_id,
        "platform": "test",
    }
    if incident_id is not None:
        body["incident_id"] = incident_id
    return body


def _switch_active_incident(database_path: Path, *, old_id: str, new_id: str) -> None:
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    with Session(engine) as session:
        session.execute(update(Incident).where(Incident.id == old_id).values(status="closed"))
        session.flush()
        session.execute(update(Incident).where(Incident.id == new_id).values(status="active"))
        session.commit()
    engine.dispose()


def test_anonymous_sessions_only_issue_for_active_incidents_and_refresh_keeps_scope(
    anonymous_client: tuple[TestClient, Path],
) -> None:
    client, database_path = anonymous_client

    for incident_id in (PREPARING_INCIDENT_ID, CLOSED_INCIDENT_ID):
        response = client.post(
            "/api/v1/anonymous-sessions",
            json=_anonymous_session_body(
                f"installation-for-{incident_id}-0001",
                incident_id,
            ),
        )
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "INCIDENT_NOT_ACTIVE"

    issued = client.post(
        "/api/v1/anonymous-sessions",
        json=_anonymous_session_body("installation-active-default-0001"),
    )
    assert issued.status_code == 201, issued.text
    issued_data = issued.json()["data"]
    assert issued_data["current_incident_id"] == ACTIVE_INCIDENT_ID
    original_refresh = str(issued_data["refresh_token"])

    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    with Session(engine) as session:
        refresh = session.scalar(
            select(RefreshSession).where(
                RefreshSession.token_hash == refresh_token_hash(original_refresh)
            )
        )
        assert refresh is not None
        assert refresh.incident_id == ACTIVE_INCIDENT_ID
    engine.dispose()

    _switch_active_incident(
        database_path,
        old_id=ACTIVE_INCIDENT_ID,
        new_id=PREPARING_INCIDENT_ID,
    )

    default_now_uses_new_active = client.post(
        "/api/v1/anonymous-sessions",
        json=_anonymous_session_body("installation-new-active-default-0002"),
    )
    assert default_now_uses_new_active.status_code == 201
    assert (
        default_now_uses_new_active.json()["data"]["current_incident_id"] == PREPARING_INCIDENT_ID
    )

    inactive_refresh = client.post(
        "/api/v1/anonymous-sessions/refresh",
        json={"refresh_token": original_refresh},
    )
    assert inactive_refresh.status_code == 409
    assert inactive_refresh.json()["error"]["code"] == "INCIDENT_NOT_ACTIVE"

    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    with Session(engine) as session:
        refresh = session.scalar(
            select(RefreshSession).where(
                RefreshSession.token_hash == refresh_token_hash(original_refresh)
            )
        )
        assert refresh is not None
        assert refresh.used_at is None
    engine.dispose()

    _switch_active_incident(
        database_path,
        old_id=PREPARING_INCIDENT_ID,
        new_id=ACTIVE_INCIDENT_ID,
    )
    resumed = client.post(
        "/api/v1/anonymous-sessions/refresh",
        json={"refresh_token": original_refresh},
    )
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["data"]["current_incident_id"] == ACTIVE_INCIDENT_ID


def _production_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "app_env": "production",
        "cors_origins": ["https://command.example.test"],
        "enable_legacy_demo_ai": False,
        "jwt_secret": "jwt-N8vQ2uF9yL4sR7wX1cK6mP3tZ5hB0dG",
        "installation_id_pepper": "pepper-U6mN2vC8xQ4wL9sK1fT7zR5pJ3hD0b",
        "upload_signing_secret": "upload-G4xV8mQ2tK7wN1cR6pL9sF3zH5jB0d",
        "pii_encryption_key": "pii-encrypt-A8vQ2uF9yL4sR7wX1cK6mP3tZ5hB0dG",
        "pii_blind_index_secret": "pii-blind-J3mQ8vN2xC7wL1sK4fT9zR5pH6dB0g",
        "push_token_secret": "push-token-P9sL2vC8xQ4wN1mK7fT6zR5pJ3hD0b",
        "bootstrap_admin_password": "Admin-N7qL2vX9cF4mP8!",
        "bootstrap_operator_password": "Operator-R6tK3wZ8hD1sM5!",
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.parametrize(
    ("field", "placeholder"),
    [
        ("jwt_secret", "replace-with-at-least-48-random-characters"),
        ("installation_id_pepper", "replace-with-independent-random-pepper"),
        ("upload_signing_secret", "replace-with-independent-random-secret"),
        ("pii_encryption_key", "replace-with-independent-pii-encryption-key"),
        ("pii_blind_index_secret", "replace-with-independent-pii-blind-index-secret"),
        ("push_token_secret", "replace-with-independent-push-token-secret"),
        ("bootstrap_admin_password", "replace-with-a-strong-local-password"),
        ("bootstrap_operator_password", "replace-with-another-strong-local-password"),
    ],
)
def test_production_rejects_example_placeholders(field: str, placeholder: str) -> None:
    with pytest.raises(ValidationError, match=field):
        _production_settings(**{field: placeholder})


@pytest.mark.parametrize(
    ("field", "weak_value"),
    [
        ("jwt_secret", "too-short"),
        ("installation_id_pepper", "a" * 64),
        ("upload_signing_secret", "password" * 8),
        ("pii_encryption_key", "changeme" * 8),
        ("pii_blind_index_secret", "b" * 64),
        ("push_token_secret", "secret" * 8),
        ("bootstrap_admin_password", "password-password"),
        ("bootstrap_operator_password", "operator123"),
    ],
)
def test_production_rejects_short_or_obviously_weak_credentials(
    field: str,
    weak_value: str,
) -> None:
    with pytest.raises(ValidationError, match=field):
        _production_settings(**{field: weak_value})


def test_non_production_keeps_local_defaults_available() -> None:
    assert Settings(app_env="dev").app_env == "dev"
    assert (
        Settings(
            app_env="test",
            jwt_secret="short",
            bootstrap_admin_password="password",
        ).app_env
        == "test"
    )


@pytest.mark.parametrize(
    "missing_field",
    ["qiniu_access_key", "qiniu_secret_key", "qiniu_bucket", "qiniu_upload_host"],
)
def test_real_qiniu_provider_requires_server_side_configuration(missing_field: str) -> None:
    values = {
        "app_env": "test",
        "media_storage_provider": "qiniu_kodo",
        "qiniu_access_key": "test-qiniu-access-key",
        "qiniu_secret_key": "test-qiniu-secret-key",
        "qiniu_bucket": "test-bucket",
        "qiniu_upload_host": "https://upload.qiniup.com",
    }
    values[missing_field] = ""
    with pytest.raises(ValidationError, match=missing_field):
        Settings(**values)


@pytest.mark.parametrize("upload_host", ["http://upload.qiniup.com", "upload.qiniup.com"])
def test_real_qiniu_provider_requires_https_upload_host(upload_host: str) -> None:
    with pytest.raises(ValidationError, match="absolute HTTPS URL"):
        Settings(
            app_env="test",
            media_storage_provider="qiniu_kodo",
            qiniu_access_key="test-qiniu-access-key",
            qiniu_secret_key="test-qiniu-secret-key",
            qiniu_bucket="test-bucket",
            qiniu_upload_host=upload_host,
        )


def test_real_qiniu_provider_accepts_complete_https_configuration() -> None:
    settings = Settings(
        app_env="test",
        media_storage_provider="qiniu_kodo",
        qiniu_access_key="test-qiniu-access-key",
        qiniu_secret_key="test-qiniu-secret-key",
        qiniu_bucket="test-bucket",
        qiniu_upload_host="https://upload.qiniup.com",
    )
    assert settings.media_storage_provider == "qiniu_kodo"


def test_qiniu_configuration_errors_do_not_expose_secret_key() -> None:
    secret_key = "server-only-test-qiniu-secret"
    with pytest.raises(ValidationError) as error:
        Settings(
            app_env="test",
            media_storage_provider="qiniu_kodo",
            qiniu_access_key="test-qiniu-access-key",
            qiniu_secret_key=secret_key,
            qiniu_bucket="test-bucket",
            qiniu_upload_host="http://upload.qiniup.com",
        )
    if secret_key in str(error.value):
        raise AssertionError("configuration validation exposed qiniu_secret_key")


def test_env_template_does_not_embed_ai_api_key() -> None:
    template = Path(__file__).resolve().parents[1] / ".env.example"
    value = next(
        line.partition("=")[2]
        for line in template.read_text(encoding="utf-8").splitlines()
        if line.startswith("AI_API_KEY=")
    )
    if value:
        raise AssertionError("AI_API_KEY must be empty in .env.example")


def test_production_accepts_independent_strong_credentials() -> None:
    assert _production_settings().app_env == "production"


def test_production_rejects_reused_signing_secret() -> None:
    with pytest.raises(ValidationError, match="signing secrets must be independent"):
        _production_settings(installation_id_pepper="jwt-N8vQ2uF9yL4sR7wX1cK6mP3tZ5hB0dG")


def test_production_rejects_reused_bootstrap_password() -> None:
    with pytest.raises(ValidationError, match="bootstrap passwords must be independent"):
        _production_settings(
            bootstrap_operator_password="Admin-N7qL2vX9cF4mP8!",
        )


async def test_map_view_rejects_bbox_over_configured_area(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(app_env="test", map_max_bbox_area_degrees=0.01)
    monkeypatch.setattr(map_module, "get_settings", lambda: settings)

    try:
        async with session_maker() as session:
            incident = Incident(
                id="map-area-incident",
                alias="map-area",
                name="Map area incident",
                status="active",
            )
            device = AnonymousDevice(
                id="map-area-device",
                installation_id_hash="f" * 64,
                platform="test",
            )
            session.add_all([incident, device])
            await session.commit()
            actor = Actor(
                subject_type="device",
                subject_id=device.id,
                role="resident",
                token_version=1,
                incident_ids=frozenset({incident.id}),
            )

        async with session_maker() as session:
            with pytest.raises(ApiError) as error:
                await map_module.map_view(
                    incident.id,
                    Request({"type": "http"}),
                    session,
                    actor,
                    None,
                    bbox="120,30,120.2,30.2",
                    coordinate_system="wgs84",
                )
            assert error.value.status_code == 422
            assert error.value.code == "MAP_VIEW_TOO_LARGE"
            assert error.value.details == {
                "bbox_area_degrees": pytest.approx(0.04),
                "max_bbox_area_degrees": 0.01,
            }
    finally:
        await engine.dispose()
