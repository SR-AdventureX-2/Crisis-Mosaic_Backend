from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, cast

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .config import get_settings
from .db import session_factory
from .errors import ApiError
from .middleware import (
    IdempotencyReplay,
    IdempotencyReservation,
    finish_reservation,
    release_reservation,
    reserve_or_replay,
)
from .realtime import actor_from_token
from .routers.ai import (
    analysis_retry,
    analysis_status,
    command_brief,
    conflict_analysis,
    report_refinement,
)
from .schemas.ai import CommandBriefRequest, ConflictAnalysisRequest, ReportRefinementRequest
from .security import Actor
from .utils import current_request_id, new_id, request_hash, utcnow

router = APIRouter(tags=["AI"])
logger = logging.getLogger(__name__)

AI_OPERATIONS = (
    "report_refinement",
    "conflict_analysis",
    "command_brief",
    "analysis_status",
    "analysis_retry",
)
MUTATING_AI_OPERATIONS = frozenset(
    {
        "report_refinement",
        "conflict_analysis",
        "command_brief",
        "analysis_retry",
    }
)


def _error_body(
    *,
    request_id: str | None,
    code: str,
    message: str,
    details: Any = None,
) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
            "details": jsonable_encoder(details),
        }
    }


async def _send_error(
    websocket: WebSocket,
    *,
    client_request_id: str | None,
    status_code: int,
    code: str,
    message: str,
    operation: str | None = None,
    server_request_id: str | None = None,
    details: Any = None,
) -> None:
    frame: dict[str, Any] = {
        "type": "ai.error",
        "request_id": client_request_id,
        "status_code": status_code,
        "body": _error_body(
            request_id=server_request_id,
            code=code,
            message=message,
            details=details,
        ),
    }
    if operation is not None:
        frame["operation"] = operation
    await websocket.send_json(frame)


def _required_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ApiError(422, "VALIDATION_ERROR", f"{key} must be a non-empty string")
    return value


async def _rate_limit_retry_after(
    websocket: WebSocket,
    *,
    actor: Actor,
    incident_id: str,
    operation: str,
) -> int | None:
    settings = get_settings()
    if not settings.rate_limit_enabled:
        return None
    rule = {
        "report_refinement": (
            "ai_refinement",
            settings.rate_limit_ai_refinements_per_minute,
        ),
        "command_brief": ("ai_brief", settings.rate_limit_ai_briefs_per_minute),
    }.get(operation)
    if rule is None:
        return None
    limiter = getattr(websocket.app.state, "rate_limiter", None)
    if limiter is None:
        return None
    actor_key = f"{actor.subject_type}:{actor.subject_id}"
    key_prefix, limit = rule
    return cast(
        int | None,
        await limiter.check(f"{key_prefix}:{actor_key}:{incident_id}", limit),
    )


async def _reserve_mutating_operation(
    *,
    actor: Actor,
    incident_id: str,
    operation: str,
    payload: dict[str, Any],
    client_request_id: str,
) -> IdempotencyReservation | IdempotencyReplay | None:
    if operation not in MUTATING_AI_OPERATIONS:
        return None
    return await reserve_or_replay(
        actor_key=f"{actor.subject_type}:{actor.subject_id}",
        route=f"WS:/api/v1/ai/ws:{operation}:{incident_id}",
        key=client_request_id,
        fingerprint=request_hash(
            {
                "incident_id": incident_id,
                "operation": operation,
                "payload": payload,
            }
        ),
    )


async def _dispatch_operation(
    *,
    operation: str,
    payload: dict[str, Any],
    websocket: WebSocket,
    actor: Actor,
    incident_id: str,
) -> tuple[int, dict[str, Any]]:
    async with session_factory()() as session:
        if operation == "report_refinement":
            report_request = ReportRefinementRequest.model_validate(payload)
            result = await report_refinement(
                report_request,
                websocket,  # type: ignore[arg-type]
                actor,
                session,
                incident_id,
            )
            return 200, result

        if operation == "conflict_analysis":
            request_payload = dict(payload)
            conflict_id = _required_string(request_payload, "conflict_id")
            request_payload.pop("conflict_id", None)
            conflict_request = ConflictAnalysisRequest.model_validate(request_payload)
            result = await conflict_analysis(
                conflict_id,
                conflict_request,
                websocket,  # type: ignore[arg-type]
                actor,
                session,
                incident_id,
            )
            if isinstance(result, JSONResponse):
                return result.status_code, json.loads(bytes(result.body))
            return 202, result

        if operation == "command_brief":
            request_payload = dict(payload)
            requested_incident_id = request_payload.pop("incident_id", incident_id)
            if requested_incident_id != incident_id:
                raise ApiError(
                    403,
                    "INCIDENT_CONTEXT_MISMATCH",
                    "WebSocket incident does not match the requested incident",
                )
            brief_request = CommandBriefRequest.model_validate(request_payload)
            result = await command_brief(
                incident_id,
                brief_request,
                websocket,  # type: ignore[arg-type]
                actor,
                session,
                incident_id,
            )
            return 202, result

        if operation == "analysis_status":
            analysis_id = _required_string(payload, "analysis_id")
            result = await analysis_status(
                analysis_id,
                websocket,  # type: ignore[arg-type]
                actor,
                session,
                incident_id,
            )
            return 200, result

        if operation == "analysis_retry":
            analysis_id = _required_string(payload, "analysis_id")
            result = await analysis_retry(
                analysis_id,
                websocket,  # type: ignore[arg-type]
                actor,
                session,
                incident_id,
            )
            return 202, result

    raise ApiError(400, "UNKNOWN_AI_OPERATION", "Unknown AI WebSocket operation")


async def _handle_request(
    websocket: WebSocket,
    message: Any,
    *,
    actor: Actor,
    incident_id: str,
) -> None:
    client_request_id = message.get("request_id") if isinstance(message, dict) else None
    if not isinstance(client_request_id, str) or not 1 <= len(client_request_id) <= 200:
        await _send_error(
            websocket,
            client_request_id=None,
            status_code=422,
            code="VALIDATION_ERROR",
            message="request_id must contain 1 to 200 characters",
        )
        return
    operation = message.get("operation")
    payload = message.get("payload")
    if operation not in AI_OPERATIONS or not isinstance(payload, dict):
        await _send_error(
            websocket,
            client_request_id=client_request_id,
            status_code=422,
            code="VALIDATION_ERROR",
            message="operation or payload is invalid",
            details={"allowed_operations": list(AI_OPERATIONS)},
        )
        return

    retry_after = await _rate_limit_retry_after(
        websocket,
        actor=actor,
        incident_id=incident_id,
        operation=operation,
    )
    if retry_after is not None:
        await _send_error(
            websocket,
            client_request_id=client_request_id,
            status_code=429,
            code="RATE_LIMITED",
            message="Too many AI requests; retry later",
            operation=operation,
            details={"retry_after_seconds": retry_after},
        )
        return

    server_request_id = new_id()
    websocket.state.request_id = server_request_id
    context_token = current_request_id.set(server_request_id)
    reservation: IdempotencyReservation | None = None
    try:
        outcome = await _reserve_mutating_operation(
            actor=actor,
            incident_id=incident_id,
            operation=operation,
            payload=payload,
            client_request_id=client_request_id,
        )
        if isinstance(outcome, IdempotencyReplay):
            status_code, body = outcome.status_code, outcome.body
        else:
            reservation = outcome
            status_code, body = await _dispatch_operation(
                operation=operation,
                payload=payload,
                websocket=websocket,
                actor=actor,
                incident_id=incident_id,
            )
            if reservation is not None:
                try:
                    await finish_reservation(
                        reservation.record_id,
                        status_code=status_code,
                        body=body,
                    )
                except Exception:
                    logger.exception(
                        "AI WebSocket idempotency completion failed",
                        extra={"request_id": server_request_id, "operation": operation},
                    )
                reservation = None
        await websocket.send_json(
            {
                "type": "ai.response",
                "request_id": client_request_id,
                "operation": operation,
                "status_code": status_code,
                "body": body,
            }
        )
    except ValidationError as exc:
        await _send_error(
            websocket,
            client_request_id=client_request_id,
            status_code=422,
            code="VALIDATION_ERROR",
            message="AI WebSocket payload validation failed",
            operation=operation,
            server_request_id=server_request_id,
            details=exc.errors(include_url=False),
        )
    except ApiError as exc:
        await _send_error(
            websocket,
            client_request_id=client_request_id,
            status_code=exc.status_code,
            code=exc.code,
            message=exc.message,
            operation=operation,
            server_request_id=server_request_id,
            details=exc.details,
        )
    except Exception:
        logger.exception(
            "AI WebSocket operation failed",
            extra={"request_id": server_request_id, "operation": operation},
        )
        await _send_error(
            websocket,
            client_request_id=client_request_id,
            status_code=500,
            code="INTERNAL_ERROR",
            message="The server failed to process the AI request",
            operation=operation,
            server_request_id=server_request_id,
        )
    finally:
        if reservation is not None:
            try:
                await release_reservation(reservation.record_id)
            except Exception:
                logger.exception(
                    "AI WebSocket idempotency release failed",
                    extra={"request_id": server_request_id, "operation": operation},
                )
        current_request_id.reset(context_token)


@router.websocket("/ai/ws")
async def ai_websocket(websocket: WebSocket) -> None:
    await websocket.accept()
    if "access_token" in websocket.query_params:
        await _send_error(
            websocket,
            client_request_id=None,
            status_code=401,
            code="QUERY_TOKEN_FORBIDDEN",
            message="Tokens are forbidden in the WebSocket URL",
        )
        await websocket.close(code=4401, reason="tokens are forbidden in URL")
        return

    try:
        message = await asyncio.wait_for(websocket.receive_json(), timeout=5)
    except (TimeoutError, WebSocketDisconnect):
        await websocket.close(code=4408, reason="authentication message timeout")
        return
    if not isinstance(message, dict) or message.get("type") != "authenticate":
        await _send_error(
            websocket,
            client_request_id=None,
            status_code=401,
            code="AUTHENTICATION_REQUIRED",
            message="The first WebSocket message must authenticate",
        )
        await websocket.close(code=4401, reason="first message must authenticate")
        return

    access_token = message.get("access_token")
    incident_id = message.get("incident_id")
    if not isinstance(access_token, str) or not isinstance(incident_id, str):
        await websocket.close(code=4401, reason="invalid authentication message")
        return
    try:
        actor, expires_at = await actor_from_token(access_token, incident_id)
    except PermissionError:
        await websocket.close(code=4403, reason="incident access denied")
        return
    except Exception:
        await websocket.close(code=4401, reason="invalid or expired access token")
        return

    await websocket.send_json(
        {
            "type": "ai.ready",
            "protocol_version": 1,
            "incident_id": incident_id,
            "operations": list(AI_OPERATIONS),
        }
    )
    try:
        while True:
            incoming = await websocket.receive_json()
            if utcnow().timestamp() >= expires_at:
                await _send_error(
                    websocket,
                    client_request_id=None,
                    status_code=401,
                    code="ACCESS_TOKEN_EXPIRED",
                    message="The access token expired",
                )
                await websocket.close(code=4401, reason="access token expired")
                return
            if isinstance(incoming, dict) and incoming.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
                continue
            if not isinstance(incoming, dict) or incoming.get("type") != "ai.request":
                await _send_error(
                    websocket,
                    client_request_id=None,
                    status_code=400,
                    code="UNSUPPORTED_MESSAGE",
                    message="Expected an ai.request message",
                )
                continue
            await _handle_request(
                websocket,
                incoming,
                actor=actor,
                incident_id=incident_id,
            )
    except WebSocketDisconnect:
        return
