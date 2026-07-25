from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select

from ..db import session_factory, write_lock
from ..dependencies import ActorDep, IncidentHeader, SessionDep, ensure_incident_access
from ..errors import ApiError
from ..models import AiAnalysis, AiJobStep, Incident
from ..realtime import _actor_from_token
from ..responses import SuccessEnvelope, success
from ..schemas.ai import (
    AnalysisAcceptedResponse,
    AnalysisStatusResponse,
    CommandBriefRequest,
    ConflictAnalysisRequest,
    LegacyConflictResponse,
    ReportRefinementRequest,
    ReportRefinementResponse,
)
from ..services.ai import (
    ai_debug,
    analyze_legacy_conflict,
    enqueue_command_brief,
    enqueue_conflict_analysis,
    refine_report,
    resolve_conflict,
    retry_analysis,
)
from ..services.events import emit_event, record_audit
from ..services.map_features import upsert_conflict_map_feature
from ..utils import isoformat, utcnow

router = APIRouter(tags=["AI"])

# WebSocket 状态流：服务端监测间隔与单连接最长推送时长。
_WS_POLL_SECONDS = 1.0
_WS_MAX_STREAM_SECONDS = 600.0


def _status_payload(analysis: AiAnalysis) -> dict[str, Any]:
    return {
        "analysis_id": analysis.id,
        "incident_id": analysis.incident_id,
        "analysis_type": analysis.analysis_type,
        "status": analysis.status,
        "output": analysis.output,
        "confidence": analysis.confidence,
        "model_provider": analysis.model_provider,
        "model_name": analysis.model_name,
        "prompt_version": analysis.prompt_version,
        "prompt_sha256": analysis.prompt_sha256,
        "latency_ms": analysis.latency_ms,
        "input_tokens": analysis.input_tokens,
        "output_tokens": analysis.output_tokens,
        "schema_valid": analysis.schema_valid,
        "reference_valid": analysis.reference_valid,
        "error_code": analysis.error_code,
        "error_message": analysis.error_message,
        "input_version": analysis.input_version,
        "data_as_of": isoformat(analysis.data_as_of),
        "is_stale": analysis.is_stale,
        "created_at": isoformat(analysis.created_at),
        "completed_at": isoformat(analysis.completed_at),
    }


async def _analysis_snapshot(session: Any, analysis: AiAnalysis) -> dict[str, Any]:
    steps = list(
        (
            await session.scalars(
                select(AiJobStep)
                .where(AiJobStep.analysis_id == analysis.id)
                .order_by(AiJobStep.started_at, AiJobStep.id)
            )
        ).all()
    )
    data = _status_payload(analysis)
    data["steps"] = [
        {
            "id": step.id,
            "name": step.name,
            "status": step.status,
            "started_at": isoformat(step.started_at),
            "finished_at": isoformat(step.finished_at),
            "error_code": step.error_code,
            "details": step.details,
        }
        for step in steps
    ]
    return data


@router.post(
    "/ai/report-refinements",
    response_model=SuccessEnvelope[ReportRefinementResponse],
    responses={
        503: {
            "description": "AI provider is not configured or unavailable",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "AI_SERVICE_UNAVAILABLE",
                            "message": "AI 服务未配置；核心上报与人工处理功能仍可使用",
                            "request_id": "019-example",
                            "details": {"hint": "请在 .env 中设置 AI_API_KEY"},
                        }
                    }
                }
            },
        }
    },
)
async def report_refinement(
    payload: ReportRefinementRequest,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    ensure_incident_access(actor, payload.incident_id, incident_header)
    if actor.role != "resident":
        raise ApiError(403, "RESIDENT_REQUIRED", "仅居民可请求上报整理建议")
    if not await session.get(Incident, payload.incident_id):
        raise ApiError(404, "INCIDENT_NOT_FOUND", "事件不存在")
    analysis, output = await refine_report(session, payload, actor)
    envelope = success(
        {
            "analysis_id": analysis.id,
            **output.model_dump(mode="json"),
            "model_version": analysis.model_name,
        },
        request,
    )
    ai_debug("ai_debug.client_response", operation="report_refinement", response=envelope)
    return envelope


@router.post(
    "/conflicts/{conflict_id}/ai-analysis",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=SuccessEnvelope[AnalysisAcceptedResponse],
    responses={
        200: {
            "model": SuccessEnvelope[LegacyConflictResponse],
            "description": "Development-only synchronous Flutter compatibility response",
        }
    },
)
async def conflict_analysis(
    conflict_id: str,
    payload: ConflictAnalysisRequest,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> Any:
    if actor.role not in {"operator", "admin"}:
        raise ApiError(403, "OPERATOR_REQUIRED", "仅指挥人员可请求冲突研判")
    conflict = await resolve_conflict(session, conflict_id)
    if not conflict:
        raise ApiError(404, "CONFLICT_NOT_FOUND", "冲突不存在")
    ensure_incident_access(actor, conflict.incident_id, incident_header)
    if payload.incident_id and payload.incident_id != conflict.incident_id:
        incident = await session.scalar(
            # Legacy demo payload may use the incident alias.
            select(Incident).where(
                (Incident.id == payload.incident_id) | (Incident.alias == payload.incident_id)
            )
        )
        if not incident or incident.id != conflict.incident_id:
            raise ApiError(403, "INCIDENT_CONTEXT_MISMATCH", "请求事件与冲突不一致")
    if payload.is_legacy:
        if conflict.revision != payload.conflict_revision:
            raise ApiError(
                409,
                "REVISION_CONFLICT",
                "冲突版本已变化",
                details={"expected": payload.conflict_revision, "current": conflict.revision},
            )
        analysis, output = await analyze_legacy_conflict(
            session,
            conflict=conflict,
            context=payload.context or {},
            actor=actor,
        )
        async with write_lock:
            incident = await session.get(Incident, conflict.incident_id)
            if incident is not None:
                await record_audit(
                    session,
                    actor=actor,
                    incident_id=incident.id,
                    action="ai.legacy_conflict_analysis.succeeded",
                    resource_type="ai_analysis",
                    resource_id=analysis.id,
                    request_id=getattr(request.state, "request_id", None),
                    after={
                        "analysis_id": analysis.id,
                        "conflict_id": conflict.id,
                        "status": analysis.status,
                    },
                )
            await session.commit()
        result = {
            "analysis_id": analysis.id,
            "status": "succeeded",
            **output.model_dump(mode="json"),
            "selected_evidence_id": output.recommended_evidence_id,
            "recommendation": output.suggested_conclusion,
            "engine_label": "multimodal-conflict-api",
            "model_version": analysis.model_name,
            "data_as_of": isoformat(analysis.data_as_of or utcnow()),
            "context_summary": {
                "image_count": sum(
                    1
                    for item in (payload.context or {}).get("evidence", [])
                    if isinstance(item, dict)
                    and str(item.get("type", item.get("kind", ""))).lower()
                    in {"image", "attachment", "photo"}
                ),
                "text_count": sum(
                    1
                    for item in (payload.context or {}).get("evidence", [])
                    if not isinstance(item, dict)
                    or str(item.get("type", item.get("kind", "text"))).lower()
                    not in {"image", "attachment", "photo"}
                ),
                "digest": "图片读取 → 非文字视觉提取 → 文字归一化 → 时间线对齐 → 多来源交叉验证",
                "context_sha256": analysis.context_sha256,
            },
        }
        # Override the decorator's default status for the synchronous Flutter contract.
        from fastapi.responses import JSONResponse

        legacy_envelope = success(result, request)
        ai_debug(
            "ai_debug.client_response",
            operation="conflict_analysis_legacy",
            status_code=200,
            response=legacy_envelope,
        )
        return JSONResponse(status_code=200, content=legacy_envelope)
    async with write_lock:
        await session.refresh(conflict)
        analysis = await enqueue_conflict_analysis(
            session,
            conflict=conflict,
            revision=payload.conflict_revision,
            evidence_ids=payload.evidence_ids,
            actor=actor,
        )
        incident = await session.get(Incident, conflict.incident_id)
        if incident is None:
            raise ApiError(404, "INCIDENT_NOT_FOUND", "事件不存在")
        await upsert_conflict_map_feature(session, conflict)
        event_type = (
            "conflict.analysis_ready"
            if analysis.status == "succeeded"
            else "conflict.analysis_requested"
        )
        await record_audit(
            session,
            actor=actor,
            incident_id=incident.id,
            action=event_type,
            resource_type="ai_analysis",
            resource_id=analysis.id,
            request_id=getattr(request.state, "request_id", None),
            after={
                "analysis_id": analysis.id,
                "conflict_id": conflict.id,
                "status": analysis.status,
            },
        )
        await emit_event(
            session,
            incident=incident,
            event_type=event_type,
            resource_type="conflict",
            resource_id=conflict.id,
            resource_revision=conflict.revision,
            payload={"analysis_id": analysis.id, "status": analysis.status},
        )
        await session.commit()
    envelope = success(
        {
            "analysis_id": analysis.id,
            "status": analysis.status,
            "status_url": f"/api/v1/ai/analyses/{analysis.id}",
        },
        request,
    )
    ai_debug("ai_debug.client_response", operation="conflict_analysis", response=envelope)
    return envelope


@router.post(
    "/incidents/{incident_id}/ai-command-briefs",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=SuccessEnvelope[AnalysisAcceptedResponse],
)
async def command_brief(
    incident_id: str,
    payload: CommandBriefRequest,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    if actor.role not in {"operator", "admin"}:
        raise ApiError(403, "OPERATOR_REQUIRED", "仅指挥人员可生成态势简报")
    ensure_incident_access(actor, incident_id, incident_header)
    incident = await session.get(Incident, incident_id)
    if not incident:
        raise ApiError(404, "INCIDENT_NOT_FOUND", "事件不存在")
    async with write_lock:
        await session.refresh(incident)
        analysis = await enqueue_command_brief(
            session, incident=incident, request=payload, actor=actor
        )
        await record_audit(
            session,
            actor=actor,
            incident_id=incident.id,
            action="ai.command_brief.requested",
            resource_type="ai_analysis",
            resource_id=analysis.id,
            request_id=getattr(request.state, "request_id", None),
            after={"status": analysis.status, "input_version": analysis.input_version},
        )
        await session.commit()
    envelope = success(
        {
            "analysis_id": analysis.id,
            "status": analysis.status,
            "status_url": f"/api/v1/ai/analyses/{analysis.id}",
        },
        request,
    )
    ai_debug("ai_debug.client_response", operation="command_brief", response=envelope)
    return envelope


@router.get(
    "/ai/analyses/{analysis_id}",
    response_model=SuccessEnvelope[AnalysisStatusResponse],
)
async def analysis_status(
    analysis_id: str,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    """查询 AI 分析状态（轮询接口）。

    推荐改用 WebSocket 推送通道 `WS /api/v1/ai/analyses/{analysis_id}/ws`
    （OpenAPI 不支持 WebSocket，故未出现在本文档中）：连接后首条消息发送
    `{"type": "authenticate", "access_token": "..."}` 完成认证，服务端在状态
    变化时推送 `analysis_status` 消息，终态（succeeded/failed）后以 1000 关闭。
    """
    analysis = await session.get(AiAnalysis, analysis_id)
    if not analysis:
        raise ApiError(404, "ANALYSIS_NOT_FOUND", "AI 分析不存在")
    ensure_incident_access(actor, analysis.incident_id, incident_header)
    if actor.role == "resident" and analysis.created_by_id != actor.subject_id:
        raise ApiError(403, "ANALYSIS_ACCESS_DENIED", "无权访问该 AI 分析")
    data = await _analysis_snapshot(session, analysis)
    envelope = success(data, request)
    ai_debug("ai_debug.client_response", operation="analysis_status", response=envelope)
    return envelope


async def _consume_ws_client_messages(websocket: WebSocket) -> None:
    try:
        while True:
            incoming = await websocket.receive_json()
            if incoming.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        return


@router.websocket("/ai/analyses/{analysis_id}/ws")
async def analysis_status_stream(websocket: WebSocket, analysis_id: str) -> None:
    """AI 分析状态推送通道，替代客户端对 GET /ai/analyses/{id} 的轮询。

    协议与 /realtime 一致：连接后首条消息必须是
    {"type": "authenticate", "access_token": "..."}，禁止在 URL 中携带令牌。
    服务端在状态/步骤变化时推送 analysis_status 消息，分析进入终态
    （succeeded/failed）后推送最终快照并以 1000 正常关闭。
    """
    await websocket.accept()
    if "access_token" in websocket.query_params:
        await websocket.send_json({"type": "error", "code": "QUERY_TOKEN_FORBIDDEN"})
        await websocket.close(code=4401, reason="tokens are forbidden in URL")
        return
    try:
        message = await asyncio.wait_for(websocket.receive_json(), timeout=5)
    except (TimeoutError, WebSocketDisconnect):
        await websocket.close(code=4408, reason="authentication message timeout")
        return
    if message.get("type") != "authenticate" or not isinstance(message.get("access_token"), str):
        await websocket.send_json({"type": "error", "code": "AUTHENTICATION_REQUIRED"})
        await websocket.close(code=4401, reason="first message must authenticate")
        return
    async with session_factory()() as session:
        analysis = await session.get(AiAnalysis, analysis_id)
        incident_id = analysis.incident_id if analysis else None
        created_by_id = analysis.created_by_id if analysis else None
    if incident_id is None:
        await websocket.close(code=4404, reason="analysis not found")
        return
    try:
        actor, expires_at = await _actor_from_token(message["access_token"], incident_id)
    except PermissionError:
        await websocket.close(code=4403, reason="incident access denied")
        return
    except Exception:
        await websocket.close(code=4401, reason="invalid or expired access token")
        return
    if actor.role == "resident" and created_by_id != actor.subject_id:
        await websocket.close(code=4403, reason="analysis access denied")
        return

    receiver = asyncio.create_task(_consume_ws_client_messages(websocket))
    deadline = utcnow().timestamp() + _WS_MAX_STREAM_SECONDS
    last_sent: dict[str, Any] | None = None
    try:
        while True:
            now = utcnow().timestamp()
            if now >= expires_at:
                await websocket.close(code=4401, reason="access token expired")
                return
            if now >= deadline:
                await websocket.close(code=4408, reason="analysis stream budget exceeded")
                return
            async with session_factory()() as session:
                current = await session.get(AiAnalysis, analysis_id)
                data = (
                    await _analysis_snapshot(session, current) if current is not None else None
                )
            if data is None:
                await websocket.close(code=4404, reason="analysis not found")
                return
            if data != last_sent:
                await websocket.send_json({"type": "analysis_status", "data": data})
                ai_debug(
                    "ai_debug.client_response",
                    operation="analysis_status_stream",
                    analysis_id=analysis_id,
                    message={"type": "analysis_status", "data": data},
                )
                last_sent = data
            if data["status"] in {"succeeded", "failed"}:
                await websocket.close(code=1000, reason="analysis finished")
                return
            if receiver.done():
                return
            await asyncio.sleep(_WS_POLL_SECONDS)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        receiver.cancel()


@router.post(
    "/ai/analyses/{analysis_id}/retry",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=SuccessEnvelope[AnalysisAcceptedResponse],
)
async def analysis_retry(
    analysis_id: str,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    analysis = await session.get(AiAnalysis, analysis_id)
    if not analysis:
        raise ApiError(404, "ANALYSIS_NOT_FOUND", "AI 分析不存在")
    ensure_incident_access(actor, analysis.incident_id, incident_header)
    if actor.role not in {"operator", "admin"} and analysis.created_by_id != actor.subject_id:
        raise ApiError(403, "ANALYSIS_ACCESS_DENIED", "无权重试该 AI 分析")
    async with write_lock:
        await session.refresh(analysis)
        await retry_analysis(session, analysis)
        await record_audit(
            session,
            actor=actor,
            incident_id=analysis.incident_id,
            action="ai.analysis.retried",
            resource_type="ai_analysis",
            resource_id=analysis.id,
            request_id=getattr(request.state, "request_id", None),
            after={"status": "queued"},
        )
        await session.commit()
    envelope = success(
        {
            "analysis_id": analysis.id,
            "status": "queued",
            "status_url": f"/api/v1/ai/analyses/{analysis.id}",
        },
        request,
    )
    ai_debug("ai_debug.client_response", operation="analysis_retry", response=envelope)
    return envelope
