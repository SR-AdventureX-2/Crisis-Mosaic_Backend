from __future__ import annotations

import asyncio
import json
import re
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, cast

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.responses import StreamingResponse

from .config import get_settings
from .db import session_factory, write_lock
from .errors import ApiError, error_body
from .models import IdempotencyRecord
from .observability import (
    BUSINESS_ERRORS,
    IDEMPOTENCY_OUTCOMES,
    observe_http_request,
)
from .security import decode_access_token
from .utils import (
    as_utc,
    current_request_id,
    new_id,
    request_hash,
    sha256_bytes,
    utcnow,
)

log = structlog.get_logger()
_SENSITIVE = re.compile(r"(authorization|token|secret|password|api[_-]?key)", re.IGNORECASE)
_REPORT_CREATE_PATH = re.compile(r"^/api/v1/incidents/[^/]+/reports/?$")
_UPLOAD_CONTENT_PATH = re.compile(r"^/api/v1/uploads/[^/]+/content/?$")
_REPORT_RESOURCE_PATH = re.compile(r"^/api/v1/reports/[^/]+/?$")
_AI_BRIEF_PATH = re.compile(r"^/api/v1/incidents/[^/]+/ai-command-briefs/?$")
_IDEMPOTENCY_HEADER = "Idempotency-Key"


@dataclass(frozen=True, slots=True)
class _Reservation:
    record_id: str


@dataclass(frozen=True, slots=True)
class _Replay:
    status_code: int
    body: dict[str, Any]


def redact(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: "***" if _SENSITIVE.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def idempotency_eligible(method: str, path: str) -> bool:
    if method.upper() not in {"POST", "PUT"} or not path.startswith("/api/v1/"):
        return False
    if path == "/api/v1/auth" or path.startswith("/api/v1/auth/"):
        return False
    if path == "/api/v1/anonymous-sessions" or path.startswith("/api/v1/anonymous-sessions/"):
        return False
    if (
        path == "/api/v1/resident-device-sessions"
        or path.startswith("/api/v1/resident-device-sessions/")
    ):
        return False
    if method.upper() == "PUT" and _UPLOAD_CONTENT_PATH.fullmatch(path):
        return False
    return not (method.upper() == "POST" and _REPORT_CREATE_PATH.fullmatch(path))


def add_idempotency_openapi_parameters(schema: dict[str, Any]) -> None:
    components = schema.setdefault("components", {})
    parameters = components.setdefault("parameters", {})
    parameters["IdempotencyKey"] = {
        "name": _IDEMPOTENCY_HEADER,
        "in": "header",
        "required": False,
        "description": (
            "可选的 24 小时幂等键。同一身份、路径和请求体会回放首次成功响应；"
            "同一键对应不同请求体时返回 409。"
        ),
        "schema": {"type": "string", "minLength": 1, "maxLength": 200},
    }
    paths = schema.get("paths", {})
    if not isinstance(paths, dict):
        return
    parameter_reference = {"$ref": "#/components/parameters/IdempotencyKey"}
    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            continue
        for method in ("post", "put"):
            operation = path_item.get(method)
            if (
                not isinstance(operation, dict)
                or not operation.get("security")
                or not idempotency_eligible(method, path)
            ):
                continue
            operation_parameters = operation.setdefault("parameters", [])
            if parameter_reference not in operation_parameters:
                operation_parameters.append(parameter_reference)


def _actor_key(request: Request) -> str | None:
    authorization = request.headers.get("authorization")
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    try:
        payload = decode_access_token(token)
    except ApiError:
        return None
    subject_type = payload.get("subject_type")
    subject_id = payload.get("sub")
    if subject_type not in {"account", "device"} or not isinstance(subject_id, str):
        return None
    return f"{subject_type}:{subject_id}"


async def _request_fingerprint(request: Request) -> str:
    body = await request.body()
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type == "application/json" or content_type.endswith("+json"):
        try:
            return request_hash(json.loads(body))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return request_hash(
        {
            "content_type": content_type,
            "sha256": sha256_bytes(body),
        }
    )


async def _reserve_or_replay(
    *,
    actor_key: str,
    route: str,
    key: str,
    fingerprint: str,
) -> _Reservation | _Replay:
    if not key or len(key) > 200:
        raise ApiError(
            422,
            "INVALID_IDEMPOTENCY_KEY",
            "Idempotency-Key 长度必须为 1 到 200",
        )
    now = utcnow()
    async with write_lock:
        async with session_factory()() as session:
            async with session.begin():
                existing = await session.scalar(
                    select(IdempotencyRecord).where(
                        IdempotencyRecord.actor_key == actor_key,
                        IdempotencyRecord.route == route,
                        IdempotencyRecord.idempotency_key == key,
                    )
                )
                if existing is not None:
                    if as_utc(existing.expires_at) <= now:
                        IDEMPOTENCY_OUTCOMES.labels(outcome="expired_reused").inc()
                        existing.request_hash = fingerprint
                        existing.response_status = 0
                        existing.response_body = None
                        existing.created_at = now
                        existing.expires_at = now + timedelta(
                            hours=get_settings().idempotency_hours
                        )
                        await session.flush()
                        return _Reservation(existing.id)
                    if existing.request_hash != fingerprint:
                        IDEMPOTENCY_OUTCOMES.labels(outcome="conflict").inc()
                        raise ApiError(
                            409,
                            "IDEMPOTENCY_CONFLICT",
                            "该 Idempotency-Key 已用于不同请求",
                        )
                    if existing.response_body is None:
                        IDEMPOTENCY_OUTCOMES.labels(outcome="in_progress").inc()
                        raise ApiError(
                            409,
                            "IDEMPOTENCY_IN_PROGRESS",
                            "相同请求正在处理中",
                        )
                    IDEMPOTENCY_OUTCOMES.labels(outcome="replayed").inc()
                    return _Replay(existing.response_status, existing.response_body)
                record = IdempotencyRecord(
                    actor_key=actor_key,
                    route=route,
                    idempotency_key=key,
                    request_hash=fingerprint,
                    response_status=0,
                    response_body=None,
                    expires_at=now + timedelta(hours=get_settings().idempotency_hours),
                )
                session.add(record)
                await session.flush()
                IDEMPOTENCY_OUTCOMES.labels(outcome="reserved").inc()
                return _Reservation(record.id)


async def _release_reservation(record_id: str) -> None:
    async with write_lock:
        async with session_factory()() as session:
            async with session.begin():
                record = await session.get(IdempotencyRecord, record_id)
                if record is not None and record.response_body is None:
                    await session.delete(record)


async def _safe_release_reservation(record_id: str, request: Request) -> None:
    try:
        await _release_reservation(record_id)
    except Exception:
        log.exception(
            "idempotency_release_failed",
            method=request.method,
            path=request.url.path,
        )


async def _finish_reservation(
    record_id: str,
    *,
    status_code: int,
    body: dict[str, Any],
) -> None:
    async with write_lock:
        async with session_factory()() as session:
            async with session.begin():
                record = await session.get(IdempotencyRecord, record_id)
                if record is None:
                    return
                record.response_status = status_code
                record.response_body = body


async def _materialize_response(response: Response) -> tuple[Response, bytes]:
    streaming = cast(StreamingResponse, response)
    chunks: list[bytes] = []
    async for chunk in streaming.body_iterator:
        chunks.append(chunk.encode() if isinstance(chunk, str) else bytes(chunk))
    body = b"".join(chunks)
    rebuilt = Response(
        content=body,
        status_code=response.status_code,
        background=response.background,
    )
    rebuilt.raw_headers = response.raw_headers
    return rebuilt, body


def _replay_response(replay: _Replay) -> Response:
    if replay.status_code == 204:
        return Response(status_code=204)
    return JSONResponse(status_code=replay.status_code, content=replay.body)


def _error_response(request: Request, exc: ApiError) -> JSONResponse:
    BUSINESS_ERRORS.labels(code=exc.code).inc()
    return JSONResponse(
        status_code=exc.status_code,
        content=error_body(request, exc.code, exc.message, exc.details),
        headers=exc.headers,
    )


class _RateLimiter:
    def __init__(self) -> None:
        self._entries: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, key: str, limit: int) -> int | None:
        now = time.monotonic()
        cutoff = now - 60
        async with self._lock:
            entries = self._entries[key]
            while entries and entries[0] <= cutoff:
                entries.popleft()
            if len(entries) >= limit:
                return max(1, int(60 - (now - entries[0])))
            entries.append(now)
            return None


def _rate_limit_rule(request: Request) -> tuple[str, int] | None:
    settings = get_settings()
    if not settings.rate_limit_enabled:
        return None
    method = request.method.upper()
    path = request.url.path
    actor_key = _actor_key(request)
    client_host = request.client.host if request.client else "unknown"
    incident = request.headers.get("X-Incident-Id", "none")
    if method == "POST" and path in {
        "/api/v1/anonymous-sessions",
        "/api/v1/resident-device-sessions",
    }:
        return (
            f"anonymous_session:ip:{client_host}",
            settings.rate_limit_anonymous_sessions_per_minute,
        )
    if method == "POST" and _REPORT_CREATE_PATH.fullmatch(path) and actor_key:
        return (
            f"report_create:{actor_key}:{incident}",
            settings.rate_limit_report_creates_per_minute,
        )
    if method == "PATCH" and _REPORT_RESOURCE_PATH.fullmatch(path) and actor_key:
        return (
            f"report_update:{actor_key}:{incident}",
            settings.rate_limit_report_updates_per_minute,
        )
    if method == "POST" and path == "/api/v1/ai/report-refinements" and actor_key:
        return (
            f"ai_refinement:{actor_key}:{incident}",
            settings.rate_limit_ai_refinements_per_minute,
        )
    if method == "POST" and _AI_BRIEF_PATH.fullmatch(path) and actor_key:
        return (
            f"ai_brief:{actor_key}:{incident}",
            settings.rate_limit_ai_briefs_per_minute,
        )
    return None


async def _call_with_idempotency(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    key = request.headers.get(_IDEMPOTENCY_HEADER)
    if key is None or not idempotency_eligible(request.method, request.url.path):
        return await call_next(request)
    actor_key = _actor_key(request)
    if actor_key is None:
        return await call_next(request)
    try:
        fingerprint = await _request_fingerprint(request)
        outcome = await _reserve_or_replay(
            actor_key=actor_key,
            route=f"{request.method.upper()}:{request.url.path}",
            key=key,
            fingerprint=fingerprint,
        )
    except ApiError as exc:
        return _error_response(request, exc)
    except Exception:
        log.exception(
            "idempotency_reservation_failed",
            method=request.method,
            path=request.url.path,
        )
        return _error_response(
            request,
            ApiError(503, "IDEMPOTENCY_UNAVAILABLE", "幂等服务暂时不可用"),
        )
    if isinstance(outcome, _Replay):
        return _replay_response(outcome)
    try:
        response = await call_next(request)
    except BaseException:
        await _safe_release_reservation(outcome.record_id, request)
        raise
    if not 200 <= response.status_code < 300:
        await _safe_release_reservation(outcome.record_id, request)
        return response
    try:
        rebuilt, body = await _materialize_response(response)
    except BaseException:
        await _safe_release_reservation(outcome.record_id, request)
        raise
    if response.status_code == 204:
        response_body: dict[str, Any] = {}
    else:
        try:
            parsed = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            await _safe_release_reservation(outcome.record_id, request)
            return rebuilt
        if not isinstance(parsed, dict):
            await _safe_release_reservation(outcome.record_id, request)
            return rebuilt
        response_body = parsed
    try:
        await _finish_reservation(
            outcome.record_id,
            status_code=response.status_code,
            body=response_body,
        )
    except Exception:
        log.exception(
            "idempotency_completion_failed",
            method=request.method,
            path=request.url.path,
        )
        # Preserve the in-progress reservation. Releasing it after the business
        # transaction committed could allow a retry to create a duplicate.
    return rebuilt


def install_middleware(app: FastAPI) -> None:
    limiter = _RateLimiter()
    # 暴露给 AI WebSocket 网关（crisis_mosaic.ai_websocket）复用同一限流器。
    app.state.rate_limiter = limiter

    @app.middleware("http")
    async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("X-Request-Id") or new_id()
        request.state.request_id = request_id
        context_token = current_request_id.set(request_id)
        started = time.perf_counter()
        response_status = 500
        try:
            rule = _rate_limit_rule(request)
            retry_after = await limiter.check(*rule) if rule is not None else None
            response: Response
            if retry_after is not None:
                response = _error_response(
                    request,
                    ApiError(
                        429,
                        "RATE_LIMITED",
                        "请求过于频繁，请稍后重试",
                        details={"retry_after_seconds": retry_after},
                        headers={"Retry-After": str(retry_after)},
                    ),
                )
            else:
                response = await _call_with_idempotency(request, call_next)
            response_status = response.status_code
            response.headers["X-Request-Id"] = request_id
            log.info(
                "http_request",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                latency_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            return response
        finally:
            elapsed = time.perf_counter() - started
            route = request.scope.get("route")
            route_template = str(getattr(route, "path", "unmatched"))
            observe_http_request(
                request.method,
                route_template,
                response_status,
                elapsed,
            )
            current_request_id.reset(context_token)
