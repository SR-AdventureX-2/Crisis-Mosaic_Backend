from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
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

from crisis_mosaic import ai_websocket as ai_ws_module
from crisis_mosaic import main as main_module
from crisis_mosaic import middleware as middleware_module
from crisis_mosaic import realtime as realtime_module
from crisis_mosaic import security as security_module
from crisis_mosaic.config import Settings
from crisis_mosaic.db import get_session
from crisis_mosaic.models import (
    AiAnalysis,
    AiJobStep,
    Base,
    Incident,
    IncidentMembership,
    LocalAccount,
)
from crisis_mosaic.routers import auth as auth_module
from crisis_mosaic.security import hash_password
from crisis_mosaic.services import ai as ai_service_module

INCIDENT_ID = "incident-gw"
ANALYSIS_ID = "analysis-gw"
PASSWORD = "Correct-Horse-Battery-Staple-2026!"
PASSWORD_HASH = hash_password(PASSWORD)
WS_PATH = "/api/v1/ai/ws"


def _seed_database(database_path: Path) -> None:
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        incident = Incident(id=INCIDENT_ID, alias="gw", name="Gateway incident", status="active")
        operator = LocalAccount(
            id="account-operator",
            username="operator",
            password_hash=PASSWORD_HASH,
            role="operator",
        )
        analysis = AiAnalysis(
            id=ANALYSIS_ID,
            incident_id=INCIDENT_ID,
            analysis_type="command_brief",
            status="succeeded",
            input_snapshot={"metrics": {}},
            output={"headline": "当前信息不足", "summary": "", "recommendations": []},
            prompt_version="cm-command-brief-v1.0.0",
            created_by_type="account",
            created_by_id=operator.id,
            input_version=0,
            model_provider="fake",
            model_name="fake-brief",
        )
        step = AiJobStep(
            analysis_id=ANALYSIS_ID,
            name="model_call",
            status="succeeded",
        )
        session.add_all(
            [
                incident,
                operator,
                IncidentMembership(
                    account_id=operator.id,
                    incident_id=INCIDENT_ID,
                    role=operator.role,
                ),
                analysis,
                step,
            ]
        )
        session.commit()
    engine.dispose()


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    database_path = tmp_path / "ai-gw.db"
    _seed_database(database_path)
    database_url = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    settings = Settings(
        app_env="test",
        auto_create_schema=False,
        database_url=database_url,
        data_dir=tmp_path,
        storage_root=tmp_path / "uploads",
        jwt_secret="integration-test-jwt-secret-with-sufficient-entropy",
        installation_id_pepper="integration-test-installation-pepper",
        upload_signing_secret="integration-test-upload-signing-secret",
        ai_provider="fake",
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
    monkeypatch.setattr(security_module, "get_settings", get_test_settings)
    monkeypatch.setattr(realtime_module, "get_settings", get_test_settings)
    monkeypatch.setattr(middleware_module, "get_settings", get_test_settings)
    monkeypatch.setattr(ai_ws_module, "get_settings", get_test_settings)
    monkeypatch.setattr(ai_service_module, "get_settings", get_test_settings)
    monkeypatch.setattr(realtime_module, "session_factory", lambda: session_maker)
    monkeypatch.setattr(middleware_module, "session_factory", lambda: session_maker)
    monkeypatch.setattr(ai_ws_module, "session_factory", lambda: session_maker)

    app = main_module.create_app()
    app.router.lifespan_context = test_lifespan
    app.dependency_overrides[get_session] = session_override
    with TestClient(app) as test_client:
        yield test_client


def _access_token(client: TestClient) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": PASSWORD},
    )
    assert response.status_code == 200, response.text
    return str(response.json()["data"]["access_token"])


def _authenticate(websocket, token: str) -> dict[str, object]:
    websocket.send_json(
        {"type": "authenticate", "access_token": token, "incident_id": INCIDENT_ID}
    )
    ready = websocket.receive_json()
    assert ready["type"] == "ai.ready"
    return ready


def test_gateway_rejects_query_token(client: TestClient) -> None:
    token = _access_token(client)
    with client.websocket_connect(f"{WS_PATH}?access_token={token}") as websocket:
        error = websocket.receive_json()
        assert error["type"] == "ai.error"
        assert error["body"]["error"]["code"] == "QUERY_TOKEN_FORBIDDEN"
        with pytest.raises(WebSocketDisconnect) as disconnect:
            websocket.receive_json()
        assert disconnect.value.code == 4401


def test_gateway_requires_authentication_message(client: TestClient) -> None:
    with client.websocket_connect(WS_PATH) as websocket:
        websocket.send_json({"type": "subscribe"})
        error = websocket.receive_json()
        assert error["body"]["error"]["code"] == "AUTHENTICATION_REQUIRED"
        with pytest.raises(WebSocketDisconnect) as disconnect:
            websocket.receive_json()
        assert disconnect.value.code == 4401


def test_gateway_ready_frame_and_analysis_status(client: TestClient) -> None:
    token = _access_token(client)
    with client.websocket_connect(WS_PATH) as websocket:
        ready = _authenticate(websocket, token)
        assert ready["incident_id"] == INCIDENT_ID
        assert "analysis_status" in ready["operations"]
        websocket.send_json(
            {
                "type": "ai.request",
                "request_id": "status-1",
                "operation": "analysis_status",
                "payload": {"analysis_id": ANALYSIS_ID},
            }
        )
        response = websocket.receive_json()
        assert response["type"] == "ai.response"
        assert response["request_id"] == "status-1"
        assert response["status_code"] == 200
        data = response["body"]["data"]
        assert data["analysis_id"] == ANALYSIS_ID
        assert data["status"] == "succeeded"
        assert [step["name"] for step in data["steps"]] == ["model_call"]


def test_gateway_command_brief_enqueues_and_replays_idempotently(client: TestClient) -> None:
    token = _access_token(client)
    with client.websocket_connect(WS_PATH) as websocket:
        _authenticate(websocket, token)
        request_frame = {
            "type": "ai.request",
            "request_id": "brief-1",
            "operation": "command_brief",
            "payload": {},
        }
        websocket.send_json(request_frame)
        first = websocket.receive_json()
        assert first["type"] == "ai.response"
        assert first["status_code"] == 202
        analysis_id = first["body"]["data"]["analysis_id"]
        assert first["body"]["data"]["status"] == "queued"
        # 相同 request_id + payload 必须回放首次结果，而不是重复入队。
        websocket.send_json(request_frame)
        replay = websocket.receive_json()
        assert replay["status_code"] == 202
        assert replay["body"]["data"]["analysis_id"] == analysis_id


def test_gateway_rejects_unknown_operation_and_bad_request_id(client: TestClient) -> None:
    token = _access_token(client)
    with client.websocket_connect(WS_PATH) as websocket:
        _authenticate(websocket, token)
        websocket.send_json(
            {
                "type": "ai.request",
                "request_id": "bad-1",
                "operation": "unsupported_op",
                "payload": {},
            }
        )
        error = websocket.receive_json()
        assert error["type"] == "ai.error"
        assert error["status_code"] == 422
        assert error["body"]["error"]["details"]["allowed_operations"] == list(
            ai_ws_module.AI_OPERATIONS
        )
        websocket.send_json({"type": "ai.request", "operation": "command_brief", "payload": {}})
        missing_id = websocket.receive_json()
        assert missing_id["type"] == "ai.error"
        assert missing_id["status_code"] == 422
        websocket.send_json({"type": "ping"})
        assert websocket.receive_json() == {"type": "pong"}
