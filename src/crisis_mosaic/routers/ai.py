from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request, status
from sqlalchemy import select

from ..db import write_lock
from ..dependencies import ActorDep, IncidentHeader, SessionDep, ensure_incident_access
from ..errors import ApiError
from ..models import AiAnalysis, AiJobStep, Incident
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
    return success(
        {
            "analysis_id": analysis.id,
            **output.model_dump(mode="json"),
            "model_version": analysis.model_name,
        },
        request,
    )


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
                "digest": "图片读取 → OCR/视觉提取 → 文字归一化 → 时间线对齐 → 多来源交叉验证",
                "context_sha256": analysis.context_sha256,
            },
        }
        # Override the decorator's default status for the synchronous Flutter contract.
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=200, content=success(result, request))
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
    return success(
        {
            "analysis_id": analysis.id,
            "status": analysis.status,
            "status_url": f"/api/v1/ai/analyses/{analysis.id}",
        },
        request,
    )


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
    return success(
        {
            "analysis_id": analysis.id,
            "status": analysis.status,
            "status_url": f"/api/v1/ai/analyses/{analysis.id}",
        },
        request,
    )


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
    analysis = await session.get(AiAnalysis, analysis_id)
    if not analysis:
        raise ApiError(404, "ANALYSIS_NOT_FOUND", "AI 分析不存在")
    ensure_incident_access(actor, analysis.incident_id, incident_header)
    if actor.role == "resident" and analysis.created_by_id != actor.subject_id:
        raise ApiError(403, "ANALYSIS_ACCESS_DENIED", "无权访问该 AI 分析")
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
    return success(data, request)


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
    return success(
        {
            "analysis_id": analysis.id,
            "status": "queued",
            "status_url": f"/api/v1/ai/analyses/{analysis.id}",
        },
        request,
    )
