from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import (
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .ai_websocket import router as ai_websocket_router
from .db import configure_database, create_schema, dispose_database
from .errors import add_error_openapi_responses, install_error_handlers
from .middleware import add_idempotency_openapi_parameters, install_middleware
from .realtime import router as realtime_router
from .routers import (
    admin,
    ai,
    auth,
    conflicts,
    health,
    incidents,
    map,
    notifications,
    questions,
    reports,
    uploads,
)
from .runtime_guard import SingleProcessGuard
from .workers import start_workers, stop_workers


def _drop_non_ai_debug_events(
    _logger: Any, _method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    # AI 调试模式：仅保留 ai_debug.* 事件，静默 http_request 等其余 structlog 输出。
    if not str(event_dict.get("event", "")).startswith("ai_debug"):
        raise structlog.DropEvent
    return event_dict


def _configure_logging(settings: Any = None) -> None:
    ai_debug_enabled = bool(getattr(settings, "ai_debug_log", False))
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]
    if ai_debug_enabled:
        processors.insert(0, _drop_non_ai_debug_events)
        # ensure_ascii=False 让中文提示词/回复以原文输出，便于人工核对。
        processors.append(structlog.processors.JSONRenderer(ensure_ascii=False, indent=2))
        for logger_name in ("uvicorn.access", "uvicorn.error", "uvicorn"):
            logging.getLogger(logger_name).setLevel(logging.WARNING)
    else:
        processors.append(structlog.processors.JSONRenderer())
    structlog.configure(processors=processors)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if int(os.getenv("WEB_CONCURRENCY", "1")) != 1:
        raise RuntimeError("SQLite P0 must run with exactly one worker")
    settings.ensure_directories()
    process_guard = SingleProcessGuard(settings.data_dir / ".single-process.lock")
    process_guard.acquire()
    workers_started = False
    try:
        configure_database(settings)
        if settings.auto_create_schema:
            await create_schema()
        await start_workers(settings)
        workers_started = True
        yield
    finally:
        try:
            if workers_started:
                await stop_workers()
            await dispose_database()
        finally:
            process_guard.release()


def create_app() -> FastAPI:
    settings = get_settings()
    _configure_logging(settings)
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        summary="Crisis Mosaic 单机功能型 P0 后端",
        description=(
            "匿名上报、精确地图、定向问答、冲突事实、图片证据、AI、审计与实时事件。"
            "这是 SQLite 单进程实施，不声明生产容量或高可用指标。"
        ),
        docs_url=None,
        redoc_url=None,
        openapi_url=f"{settings.api_prefix}/openapi.json",
        lifespan=lifespan,
        openapi_tags=[
            {"name": "认证", "description": "本地账号与匿名设备会话、轮换和吊销。"},
            {"name": "管理员", "description": "本地账号、成员关系与管理操作。"},
            {"name": "事件", "description": "事件配置、概览与审计。"},
            {"name": "Reports", "description": "居民上报、版本、状态和优先级。"},
            {"name": "Map", "description": "事件地图视图、边界框与坐标系转换。"},
            {"name": "Uploads", "description": "隔离上传与安全图片内容。"},
            {"name": "Notifications", "description": "指挥端 Push 设备、偏好、Outbox 和回执。"},
            {"name": "Questions & blind spots", "description": "盲区和定向问答。"},
            {"name": "Conflicts & facts", "description": "证据冲突、人工决策和事实版本链。"},
            {
                "name": "AI",
                "description": "严格 Schema 校验的整理、冲突分析和态势简报调试入口。",
            },
            {"name": "实时事件", "description": "首包鉴权 WebSocket 与 SQLite 历史回放。"},
            {"name": "运行状态", "description": "存活、就绪和 Prometheus 指标。"},
        ],
    )
    install_middleware(app)
    install_error_handlers(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Accept",
            "Idempotency-Key",
            "X-Incident-Id",
            "X-Request-Id",
        ],
        expose_headers=["X-Request-Id"],
    )
    swagger_ui_path = Path(__file__).parent / "static" / "swagger"
    app.mount(
        "/static/swagger",
        StaticFiles(directory=swagger_ui_path),
        name="swagger-static",
    )

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse("/docs", status_code=307)

    @app.get("/docs", include_in_schema=False)
    async def swagger_docs() -> HTMLResponse:
        return get_swagger_ui_html(
            openapi_url=app.openapi_url or f"{settings.api_prefix}/openapi.json",
            title=f"{settings.app_name} - Swagger UI",
            oauth2_redirect_url="/docs/oauth2-redirect",
            swagger_js_url="/static/swagger/swagger-ui-bundle.js?v=5.32.11",
            swagger_css_url="/static/swagger/swagger-ui.css?v=5.32.11",
            swagger_favicon_url="/static/swagger/favicon-32x32.png?v=5.32.11",
            swagger_ui_parameters={
                "persistAuthorization": True,
                "displayRequestDuration": True,
                "filter": True,
                "tryItOutEnabled": True,
            },
        )

    @app.get("/docs/oauth2-redirect", include_in_schema=False)
    async def swagger_oauth_redirect() -> HTMLResponse:
        return get_swagger_ui_oauth2_redirect_html()

    @app.get("/schemas/realtime-event.json", include_in_schema=False)
    async def realtime_schema() -> FileResponse:
        schema_path = Path(__file__).parent / "schemas" / "realtime_event.json"
        return FileResponse(schema_path, media_type="application/schema+json")

    @app.get("/schemas/push-payload.json", include_in_schema=False)
    async def push_payload_schema() -> FileResponse:
        schema_path = Path(__file__).parent / "schemas" / "push_payload.json"
        return FileResponse(schema_path, media_type="application/schema+json")

    prefix = settings.api_prefix
    for route in (
        auth.router,
        admin.router,
        incidents.router,
        reports.router,
        map.router,
        uploads.router,
        uploads.callback_router,
        notifications.router,
        questions.router,
        conflicts.router,
        ai.router,
        ai_websocket_router,
        health.router,
        realtime_router,
    ):
        app.include_router(route, prefix=prefix)

    original_openapi = app.openapi

    def openapi_with_idempotency() -> dict[str, Any]:
        schema = original_openapi()
        add_idempotency_openapi_parameters(schema)
        add_error_openapi_responses(schema)
        return schema

    app.openapi = openapi_with_idempotency  # type: ignore[method-assign]
    return app


app = create_app()
