from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import httpx
import structlog
from pydantic import BaseModel, ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..db import write_lock
from ..errors import ApiError
from ..models import (
    AiAnalysis,
    AiJobStep,
    Attachment,
    BackgroundJob,
    BlindSpot,
    ConflictCase,
    ConflictEvidence,
    FactRecord,
    Incident,
    Report,
)
from ..schemas.ai import (
    AttachmentEnrichmentOutput,
    CommandBriefOutput,
    CommandBriefRequest,
    ConflictAnalysisOutput,
    EvidenceAssessment,
    MediaEvidenceExtractionOutput,
    ReportRefinementOutput,
    ReportRefinementRequest,
)
from ..security import Actor
from ..services.ai_prompts import (
    COMMAND_BRIEF_PROMPT_VERSION,
    CONFLICT_ANALYSIS_PROMPT_VERSION,
    REPORT_REFINEMENT_PROMPT_VERSION,
    get_prompt_spec,
    prompt_sha256,
)
from ..services.events import emit_event, record_audit
from ..services.map_features import upsert_conflict_map_feature
from ..services.qiniu import fetch_object_bytes
from ..services.reports import load_bindable_attachments
from ..utils import canonical_json, sha256_text, utcnow


@dataclass(frozen=True)
class AiInvocationResult[OutputT: BaseModel]:
    output: OutputT
    prompt_version: str
    prompt_sha256: str
    input_tokens: int | None
    output_tokens: int | None
    schema_valid: bool
    reference_valid: bool


_HUMAN_CONFIRMATION_WARNING = "AI 只提供辅助判断，最终结论必须由指挥人员确认。"
_INVALID_REFERENCE_WARNING = (
    "AI 返回的证据引用与当前证据清单不一致，本次结果已按保守策略降级。"
)


def _ensure_conflict_human_confirmation_warning(
    output: ConflictAnalysisOutput,
) -> ConflictAnalysisOutput:
    if any(
        "AI 只提供辅助判断" in warning and "指挥人员确认" in warning for warning in output.warnings
    ):
        return output
    warnings = [*output.warnings]
    if len(warnings) >= 30:
        warnings[-1] = _HUMAN_CONFIRMATION_WARNING
    else:
        warnings.append(_HUMAN_CONFIRMATION_WARNING)
    return output.model_copy(update={"warnings": warnings})


def _conflict_reference_fallback(
    output: ConflictAnalysisOutput,
    *,
    payload: dict[str, Any],
    allowed_evidence_ids: set[str],
) -> ConflictAnalysisOutput:
    ordered_evidence_ids: list[str] = []
    for item in payload.get("evidence", []):
        if not isinstance(item, dict):
            continue
        evidence_id = item.get("id")
        if (
            isinstance(evidence_id, str)
            and evidence_id in allowed_evidence_ids
            and evidence_id not in ordered_evidence_ids
        ):
            ordered_evidence_ids.append(evidence_id)
    if set(ordered_evidence_ids) != allowed_evidence_ids:
        raise ApiError(
            500,
            "AI_CONTEXT_INVALID",
            "AI 冲突上下文与允许证据清单不一致",
        )
    assessments = [
        EvidenceAssessment(
            evidence_id=evidence_id,
            authenticity_score=0.5,
            credibility_score=0.0,
            verdict="uncertain",
            reason="AI 返回的证据引用无效，未采纳自动评估，需人工复核。",
            extracted_facts=[],
        )
        for evidence_id in ordered_evidence_ids
    ]
    return ConflictAnalysisOutput(
        recommended_evidence_id="",
        suggested_conclusion="现有证据不足，无法形成可靠结论，建议人工复核。",
        reasoning_summary=(
            "AI 返回的证据引用与当前冲突证据清单不一致，"
            "服务端已拒绝引用并按全部当前证据回退为待人工复核。"
        ),
        confidence=min(output.confidence, 0.2),
        evidence_assessments=assessments,
        warnings=[
            _INVALID_REFERENCE_WARNING,
            _HUMAN_CONFIRMATION_WARNING,
        ],
    )


_PII_PATTERNS = (
    re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
    re.compile(r"(?<![A-Za-z0-9])\d{17}[\dXx](?![A-Za-z0-9])"),
)
_COMPLETION_PHRASES = (
    "已通知",
    "已经通知",
    "已派遣",
    "已经派遣",
    "已核实",
    "已经核实",
    "已封路",
    "已经封路",
    "已救援",
    "已经救援",
    "已解决",
    "已经解决",
    "已完成处置",
)
_PROTECTED_TERMS = (
    "没有",
    "未发现",
    "不能",
    "尚未",
    "不是",
    "可能",
    "好像",
    "大约",
    "听说",
    "无法确认",
    "正在",
    "已经",
    "刚刚",
    "曾经",
)


@asynccontextmanager
async def _committing_write_phase(session: AsyncSession) -> AsyncIterator[None]:
    """Serialize and close one short SQLite write transaction."""

    async with write_lock:
        try:
            yield
            await session.commit()
        except BaseException:
            await session.rollback()
            raise


def ensure_ai_available(settings: Settings) -> None:
    if not settings.ai_configured:
        raise ApiError(
            503,
            "AI_SERVICE_UNAVAILABLE",
            "AI 服务未配置；核心上报与人工处理功能仍可使用",
            details={
                "provider": settings.ai_provider,
                "hint": "请在 .env 中设置 AI_API_KEY，或在测试环境使用 AI_PROVIDER=fake",
            },
        )


def _add_completed_step(
    session: AsyncSession,
    analysis_id: str,
    name: str,
    details: dict[str, Any],
) -> None:
    completed_at = utcnow()
    session.add(
        AiJobStep(
            analysis_id=analysis_id,
            name=name,
            status="succeeded",
            started_at=completed_at,
            finished_at=completed_at,
            details={"duration_ms": 0, **details},
        )
    )


def _evidence_timeline_value(item: dict[str, Any]) -> str:
    snapshot = item.get("snapshot")
    if not isinstance(snapshot, dict):
        snapshot = {}
    location = snapshot.get("location")
    if not isinstance(location, dict):
        location = {}
    values = (
        snapshot.get("observed_at"),
        location.get("observed_at"),
        snapshot.get("captured_at"),
        snapshot.get("updated_at"),
        snapshot.get("created_at"),
        snapshot.get("received_at"),
        item.get("added_at"),
    )
    return next((str(value) for value in values if value), "")


def _has_pii(text: str) -> bool:
    return any(pattern.search(text) for pattern in _PII_PATTERNS)


def _contains_completion_phrase(text: str) -> bool:
    return any(phrase in text for phrase in _COMPLETION_PHRASES)


def _extract_usage(body: dict[str, Any]) -> tuple[int | None, int | None]:
    usage = body.get("usage")
    if not isinstance(usage, dict):
        return None, None
    input_tokens = usage.get("prompt_tokens")
    output_tokens = usage.get("completion_tokens")
    return (
        int(input_tokens) if isinstance(input_tokens, int) else None,
        int(output_tokens) if isinstance(output_tokens, int) else None,
    )


def _sum_tokens(left: int | None, right: int | None) -> int | None:
    if left is None and right is None:
        return None
    return (left or 0) + (right or 0)


def _report_input_payload(
    request: ReportRefinementRequest,
    attachments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "request_context": {
            "incident_id": request.incident_id,
            "language": "zh-CN",
            "timezone": "Asia/Shanghai",
        },
        "report": {
            "category": request.category,
            "content": request.content,
            "location_text": request.location_text,
        },
    }
    if request.report_id is not None:
        payload["request_context"].update(
            {
                "report_id": request.report_id,
                "report_revision": request.report_revision,
            }
        )
    if attachments is not None:
        payload["attachments"] = attachments
    return payload


_READY_MEDIA_STATUSES = frozenset({"ready", "succeeded"})
_NO_TEXT_VISION_PREFIX = "[vision_policy:no_text_v1]\n"


def _available_media_text(status: str | None, value: str | None, max_length: int) -> str | None:
    if status not in _READY_MEDIA_STATUSES or not value:
        return None
    return _truncate_text(value, max_length)


def _report_attachment_context(attachment: Attachment) -> dict[str, Any]:
    limitations: list[str] = []
    vision_summary = None
    if attachment.vision_summary and attachment.vision_summary.startswith(
        _NO_TEXT_VISION_PREFIX
    ):
        vision_summary = _available_media_text(
            attachment.vision_status,
            attachment.vision_summary.removeprefix(_NO_TEXT_VISION_PREFIX),
            3000,
        )
    if vision_summary is None:
        limitations.append(f"vision_status:{attachment.vision_status or 'missing'}")
    context: dict[str, Any] = {
        "attachment_id": attachment.id,
        "media_type": attachment.media_type,
        "sha256": attachment.sha256,
        "storage_etag": attachment.etag,
        "size_bytes": attachment.size_bytes,
        "captured_at": attachment.captured_at.isoformat() if attachment.captured_at else None,
        "duration_ms": attachment.duration_ms,
        "vision_status": attachment.vision_status,
        "vision_summary": vision_summary,
        "raw_media_status": "pending",
        "limitations": limitations,
    }
    if attachment.media_type == "video":
        transcript = _available_media_text(
            attachment.transcript_status,
            attachment.transcript_text,
            5000,
        )
        context["transcript_status"] = attachment.transcript_status
        context["transcript_text"] = transcript
        context["keyframe_status"] = attachment.keyframe_status
        if transcript is None:
            limitations.append(
                f"transcript_status:{attachment.transcript_status or 'missing'}"
            )
    return context


def _read_bounded_local_media(
    path_value: str,
    *,
    settings: Settings,
    max_bytes: int,
) -> bytes:
    storage_root = settings.storage_root.resolve()
    try:
        path = Path(path_value).resolve(strict=True)
    except OSError as exc:
        raise ApiError(503, "AI_MEDIA_READ_FAILED", "AI 无法读取已处理的媒体文件") from exc
    if path == storage_root or storage_root not in path.parents:
        raise ApiError(503, "AI_MEDIA_PATH_INVALID", "AI 媒体文件不在受控存储目录内")
    try:
        if path.stat().st_size > max_bytes:
            raise ApiError(413, "AI_MEDIA_TOO_LARGE", "AI 媒体预览超过读取限制")
        content = path.read_bytes()
    except OSError as exc:
        raise ApiError(503, "AI_MEDIA_READ_FAILED", "AI 无法读取已处理的媒体文件") from exc
    if not content:
        raise ApiError(503, "AI_MEDIA_READ_FAILED", "AI 媒体预览为空")
    return content


async def _read_report_attachment_visual(
    attachment: Attachment,
    settings: Settings,
    *,
    max_bytes_per_frame: int,
) -> tuple[list[bytes], str | None]:
    if attachment.media_type == "video" and attachment.keyframe_status not in _READY_MEDIA_STATUSES:
        return [], f"keyframe_status:{attachment.keyframe_status or 'missing'}"
    if attachment.storage_provider == "local_proxy":
        path_value = (
            attachment.thumbnail_path or attachment.sanitized_path
            if attachment.media_type == "image"
            else attachment.cover_path
        )
        if not path_value:
            return [], "processed_media_path:missing"
        try:
            return ([
                await asyncio.to_thread(
                    _read_bounded_local_media,
                    path_value,
                    settings=settings,
                    max_bytes=max_bytes_per_frame,
                ),
            ], None)
        except ApiError as exc:
            return [], exc.code
    if attachment.storage_provider == "qiniu_kodo" and attachment.object_key:
        transforms = ["imageView2/2/w/1280/h/1280/format/jpg"]
        if attachment.media_type == "video":
            if not attachment.duration_ms:
                return [], "video_duration:missing"
            transforms = [
                f"vframe/jpg/offset/{offset:g}"
                for offset in _video_frame_offsets(attachment.duration_ms)
            ]

            async def fetch_frame(transform: str) -> tuple[bytes | None, str | None]:
                try:
                    return (
                        await fetch_object_bytes(
                            f"{attachment.object_key}?{transform}",
                            max_bytes=max_bytes_per_frame,
                            settings=settings,
                        ),
                        None,
                    )
                except ApiError as exc:
                    return None, exc.code

            frame_results = await asyncio.gather(
                *(fetch_frame(transform) for transform in transforms)
            )
            contents = [content for content, _ in frame_results if content is not None]
            failure_codes = [code for _, code in frame_results if code is not None]
            if failure_codes:
                outcome = "partial_failure" if contents else "unavailable"
                codes = ",".join(sorted(set(failure_codes)))
                limitation = (
                    f"video_keyframes:{outcome}:"
                    f"{len(failure_codes)}/{len(frame_results)}:{codes}"
                )
                return contents, limitation
            return contents, None
        try:
            content = await fetch_object_bytes(
                f"{attachment.object_key}?{transforms[0]}",
                max_bytes=max_bytes_per_frame,
                settings=settings,
            )
        except ApiError as exc:
            return [], exc.code
        return [content], None
    return [], "raw_media_provider:unavailable"


def _video_frame_offsets(duration_ms: int) -> list[float]:
    duration_seconds = max(duration_ms / 1000, 0.0)
    candidates = (0.0, duration_seconds / 2, max(0.0, duration_seconds - 0.1))
    return list(dict.fromkeys(round(value, 3) for value in candidates))


async def build_report_refinement_context(
    session: AsyncSession,
    request: ReportRefinementRequest,
    actor: Actor,
    settings: Settings,
) -> tuple[dict[str, Any], list[bytes]]:
    bound_report_id: str | None = None
    if request.report_id is not None:
        report = await session.get(Report, request.report_id)
        if (
            report is None
            or report.incident_id != request.incident_id
            or report.reporter_device_id != actor.subject_id
            or report.deleted_at is not None
            or report.revision != request.report_revision
        ):
            raise ApiError(
                422,
                "AI_REPORT_CONTEXT_INVALID",
                "AI 上报整理请求中的报告上下文不存在或已过期",
        )
        bound_report_id = report.id
    if not request.attachment_ids:
        return _report_input_payload(request, [] if request.report_id else None), []
    attachments = await load_bindable_attachments(
        session,
        incident_id=request.incident_id,
        uploader_device_id=actor.subject_id,
        attachment_ids=request.attachment_ids,
        bound_report_id=bound_report_id,
    )
    attachment_contexts = [_report_attachment_context(item) for item in attachments]
    image_payloads: list[bytes] = []
    total_byte_budget = settings.max_image_bytes
    max_bytes_per_frame = min(total_byte_budget, 2 * 1024 * 1024)
    semaphore = asyncio.Semaphore(max(1, settings.media_max_parallel_uploads))

    async def read_visual(index: int) -> tuple[int, list[bytes], str | None]:
        async with semaphore:
            try:
                frames, limitation = await asyncio.wait_for(
                    _read_report_attachment_visual(
                        attachments[index],
                        settings,
                        max_bytes_per_frame=max_bytes_per_frame,
                    ),
                    timeout=min(8.0, max(1.0, settings.ai_report_timeout_seconds / 3)),
                )
            except TimeoutError:
                return index, [], "raw_media_read:timeout"
            return index, frames, limitation

    tasks = {
        asyncio.create_task(read_visual(index)): index
        for index in range(len(attachments))
    }
    done, pending = await asyncio.wait(
        tasks,
        timeout=min(15.0, max(2.0, settings.ai_report_timeout_seconds / 3)),
    )
    for task in pending:
        task.cancel()
        index = tasks[task]
        attachment_contexts[index]["raw_media_status"] = "unavailable"
        attachment_contexts[index]["limitations"].append("raw_media_read:timeout")
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    visual_results = {
        index: (frames, limitation)
        for index, frames, limitation in (task.result() for task in done)
    }
    model_indices_by_attachment: dict[int, list[int]] = {
        index: [] for index in visual_results
    }
    used_bytes = 0
    max_frame_count = max(
        (len(frames) for frames, _ in visual_results.values()),
        default=0,
    )
    for frame_index in range(max_frame_count):
        for index in sorted(visual_results):
            frames, _ = visual_results[index]
            if frame_index >= len(frames):
                continue
            frame = frames[frame_index]
            context = attachment_contexts[index]
            if used_bytes + len(frame) > total_byte_budget:
                budget_limitation = "raw_media:omitted_total_byte_budget"
                if budget_limitation not in context["limitations"]:
                    context["limitations"].append(budget_limitation)
                continue
            used_bytes += len(frame)
            image_payloads.append(frame)
            model_indices_by_attachment[index].append(len(image_payloads))

    for index in sorted(visual_results):
        frames, limitation = visual_results[index]
        context = attachment_contexts[index]
        model_indices = model_indices_by_attachment[index]
        if model_indices:
            context["raw_media_status"] = (
                "loaded"
                if len(model_indices) == len(frames) and limitation is None
                else "partially_loaded"
            )
            context["model_image_indices"] = model_indices
            context["model_image_kind"] = (
                "image" if attachments[index].media_type == "image" else "video_keyframe"
            )
        else:
            context["raw_media_status"] = "unavailable"
        if limitation:
            context["limitations"].append(limitation)
    return _report_input_payload(request, attachment_contexts), image_payloads


def _prompt_hash_for(purpose: str, output_model: type[BaseModel]) -> str:
    spec = get_prompt_spec(purpose)  # type: ignore[arg-type]
    return prompt_sha256(spec, output_model.model_json_schema())


def _fake_output[OutputT: BaseModel](
    output_model: type[OutputT], payload: dict[str, Any], allowed_ids: set[str] | None
) -> OutputT:
    if output_model is ReportRefinementOutput:
        report_value = payload.get("report")
        report = report_value if isinstance(report_value, dict) else payload
        content = str(report["content"]).strip()
        location = str(report["location_text"]).strip()
        category = str(report.get("category", "rescue"))
        category_labels = {
            "rescue": "需要救援",
            "medical": "医疗情况",
            "water": "饮水需求",
            "food": "食物需求",
            "shelter": "避难安置",
            "road": "道路情况",
        }
        urgent_terms = (
            "被困",
            "受伤",
            "急救",
            "快速上涨",
            "失联",
            "救援",
            "昏迷",
            "呼吸困难",
            "严重失血",
        )
        tags = [
            tag
            for keyword, tag in (
                ("被困", "trapped_people"),
                ("老人", "elderly"),
                ("上涨", "rising_water"),
                ("快速上涨", "rising_water"),
                ("受伤", "injured_people"),
                ("失联", "missing_people"),
                ("昏迷", "unconscious_person"),
                ("呼吸困难", "breathing_difficulty"),
                ("严重失血", "severe_bleeding"),
                ("道路不能通行", "road_blocked"),
                ("完全中断", "road_blocked"),
            )
            if keyword in content
        ]
        tags = list(dict.fromkeys(tags))
        ordinary_need = any(term in content for term in ("普通饮用水", "现场安全"))
        urgent = any(term in content for term in urgent_terms) and not ordinary_need
        refinement_value: dict[str, Any] = {
            "refined_content": (
                f"【{category_labels.get(category, '现场情况')}】{content.rstrip('。')}。"
                f"\n【位置】{location}"
            ),
            "risk_hint": (
                "检测到明确风险，建议居民确认紧急标记并尽快提交。"
                if urgent
                else "仅整理了表达，请居民核对后提交。"
            ),
            "suggest_urgent": urgent,
            "detected_risk_tags": tags,
            "confidence": 0.91 if urgent else 0.78,
        }
        return output_model.model_validate(refinement_value, strict=True)
    if output_model is ConflictAnalysisOutput:
        evidence = list(payload.get("evidence", []))
        ids = sorted(allowed_ids or {str(item.get("id")) for item in evidence})
        if not ids:
            raise ApiError(422, "AI_CONTEXT_EMPTY", "冲突没有可分析的证据")
        assessments = [
            {
                "evidence_id": evidence_id,
                "authenticity_score": 0.92,
                "credibility_score": max(0.45, 0.9 - index * 0.08),
                "verdict": "supported" if index == 0 else "likely",
                "reason": "文件与来源信息未发现明显异常；应结合观察时间由人工复核。",
                "extracted_facts": ["来源已记录", "时间线已对齐"],
            }
            for index, evidence_id in enumerate(ids)
        ]
        conflict_value: dict[str, Any] = {
            "recommended_evidence_id": ids[0],
            "suggested_conclusion": "多条证据支持最新现场状态，建议以最新有效观察为准。",
            "reasoning_summary": "已按时间、来源、图片指纹与地点一致性完成交叉核验。",
            "confidence": 0.82,
            "evidence_assessments": assessments,
            "warnings": ["AI 只提供辅助判断，最终结论必须由指挥人员确认。"],
        }
        return output_model.model_validate(conflict_value, strict=True)
    if output_model is CommandBriefOutput:
        metrics = payload.get("metrics", payload.get("counts", {}))
        source_refs: list[str] = []
        for collection in (
            "urgent_reports",
            "recent_reports",
            "open_conflicts",
            "blind_spots",
            "current_facts",
            "recent_changes",
            "reports",
            "conflicts",
        ):
            for item in payload.get(collection, []):
                if isinstance(item, dict):
                    if item.get("source_ref"):
                        source_refs.append(str(item["source_ref"]))
                    elif item.get("id"):
                        source_refs.append(str(item["id"]))
        source_refs = list(dict.fromkeys(source_refs))
        recommendations = (
            [
                {
                    "text": "优先复核紧急上报、未解决冲突和高影响盲区。",
                    "severity": "high",
                    "source_refs": [source_refs[0]],
                }
            ]
            if source_refs
            else []
        )
        active_reports = int(metrics.get("active_report_count", metrics.get("reports", 0)) or 0)
        urgent_reports = int(
            metrics.get("urgent_report_count", metrics.get("urgent_reports", 0)) or 0
        )
        open_conflicts = int(
            metrics.get("open_conflict_count", metrics.get("open_conflicts", 0)) or 0
        )
        open_blind_spots = int(
            metrics.get("open_blind_spot_count", metrics.get("open_blind_spots", 0)) or 0
        )
        brief_value: dict[str, Any] = {
            "headline": "仍有需要人工关注的现场风险" if source_refs else "当前信息不足",
            "summary": (
                f"当前共有 {active_reports} 条有效上报，其中 {urgent_reports} 条标记紧急；"
                f"另有 {open_conflicts} 个未解决冲突和 {open_blind_spots} 个信息盲区。"
            ),
            "recommendations": recommendations,
            "confidence": 0.68 if source_refs else 0.2,
        }
        return output_model.model_validate(brief_value, strict=True)
    raise TypeError(f"no fake output for {output_model.__name__}")


def _json_schema_response_format(output_model: type[BaseModel]) -> dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": output_model.__name__,
            "strict": True,
            "schema": output_model.model_json_schema(),
        },
    }


_JSON_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL)

_debug_log = structlog.get_logger()


def ai_debug(event: str, /, **fields: Any) -> None:
    """AI 调试日志：仅在 AI_DEBUG_LOG=true 时输出，事件名以 ai_debug. 开头。"""
    if get_settings().ai_debug_log:
        _debug_log.info(event, **fields)


def _redact_request_body(request_body: dict[str, Any]) -> dict[str, Any]:
    # base64 图片会把日志撑爆，替换为占位符；其余内容原样保留。
    redacted = dict(request_body)
    messages = []
    for message in request_body.get("messages", []):
        content = message.get("content")
        if isinstance(content, list):
            parts = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "image_url":
                    url = str(part.get("image_url", {}).get("url", ""))
                    parts.append(
                        {"type": "image_url", "image_url": f"<base64 省略，{len(url)} 字符>"}
                    )
                else:
                    parts.append(part)
            message = {**message, "content": parts}
        messages.append(message)
    redacted["messages"] = messages
    return redacted


def _strip_json_fences(content: str) -> str:
    # Some OpenAI-compatible proxies ignore response_format and let the model
    # wrap its JSON output in Markdown code fences.
    match = _JSON_FENCE_RE.match(content)
    return match.group(1) if match else content


async def _repair_structured_output[OutputT: BaseModel](
    *,
    invalid_content: str,
    validation_error: ValidationError,
    allowed_resource_ids: set[str],
    output_model: type[OutputT],
    model: str,
    timeout_seconds: float,
    settings: Settings,
) -> tuple[OutputT, int | None, int | None]:
    repair_spec = get_prompt_spec("json_repair")
    user_prompt = (
        repair_spec.user_prompt_template.replace(
            "{{validation_errors_json}}",
            canonical_json(validation_error.errors()),
        )
        .replace("{{allowed_resource_ids_json}}", canonical_json(sorted(allowed_resource_ids)))
        .replace("{{invalid_output_json_or_text}}", invalid_content)
        .replace("{{target_schema_json}}", canonical_json(output_model.model_json_schema()))
    )
    request_body: dict[str, Any] = {
        "model": model,
        "temperature": repair_spec.temperature,
        "messages": [
            {"role": "system", "content": repair_spec.system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": (
            _json_schema_response_format(output_model)
            if settings.ai_supports_json_schema
            else {"type": "json_object"}
        ),
    }
    ai_debug(
        "ai_debug.model_request",
        purpose="json_repair",
        model=model,
        endpoint=settings.ai_endpoint,
        timeout_seconds=timeout_seconds,
        request_body=_redact_request_body(request_body),
    )
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.post(
                settings.ai_endpoint,
                headers={
                    "Authorization": f"Bearer {settings.ai_api_key}",
                    "Content-Type": "application/json",
                },
                json=request_body,
            )
            response.raise_for_status()
        body = response.json()
        content = body["choices"][0]["message"]["content"]
        if isinstance(content, list):
            content = "".join(
                str(item.get("text", "")) for item in content if isinstance(item, dict)
            )
        if not isinstance(content, str):
            raise TypeError("AI repair response content is not text")
        ai_debug(
            "ai_debug.model_response",
            purpose="json_repair",
            model=model,
            status_code=response.status_code,
            content=content,
            usage=body.get("usage"),
        )
        repaired = output_model.model_validate_json(_strip_json_fences(content), strict=True)
        input_tokens, output_tokens = _extract_usage(body)
        return repaired, input_tokens, output_tokens
    except (httpx.TimeoutException, TimeoutError) as exc:
        raise ApiError(504, "AI_MODEL_TIMEOUT", "AI 服务响应超时") from exc
    except ValidationError as exc:
        raise ApiError(
            502,
            "AI_OUTPUT_SCHEMA_INVALID",
            "AI 返回结果未通过结构校验",
            details=exc.errors(),
        ) from exc
    except (httpx.HTTPError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise ApiError(503, "AI_SERVICE_UNAVAILABLE", "AI 服务调用失败") from exc


async def _invoke_structured[OutputT: BaseModel](
    *,
    purpose: str,
    payload: dict[str, Any],
    output_model: type[OutputT],
    model: str,
    timeout_seconds: float,
    settings: Settings,
    allowed_evidence_ids: set[str] | None = None,
    allowed_source_refs: set[str] | None = None,
    image_payloads: list[bytes] | None = None,
) -> AiInvocationResult[OutputT]:
    ensure_ai_available(settings)
    prompt_spec = get_prompt_spec(purpose)  # type: ignore[arg-type]
    response_schema = output_model.model_json_schema()
    digest = prompt_sha256(prompt_spec, response_schema)
    input_tokens: int | None = None
    output_tokens: int | None = None
    if settings.ai_provider == "fake":
        await asyncio.sleep(0)
        result = _fake_output(output_model, payload, allowed_evidence_ids)
        ai_debug(
            "ai_debug.model_request",
            purpose=purpose,
            provider="fake",
            model=model,
            payload=payload,
        )
        ai_debug(
            "ai_debug.model_response",
            purpose=purpose,
            provider="fake",
            output=result.model_dump(mode="json"),
        )
    else:
        user_prompt = prompt_spec.render_user_prompt(canonical_json(payload))
        user_content: str | list[dict[str, Any]] = user_prompt
        if image_payloads:
            multimodal_content: list[dict[str, Any]] = [
                {"type": "text", "text": user_prompt}
            ]
            for image_bytes in image_payloads:
                encoded = base64.b64encode(image_bytes).decode("ascii")
                multimodal_content.append(
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/jpeg;base64,{encoded}",
                            "detail": "low",
                        },
                    }
                )
            user_content = multimodal_content
        request_body: dict[str, Any] = {
            "model": model,
            "temperature": prompt_spec.temperature,
            "messages": [
                {"role": "system", "content": prompt_spec.system_prompt},
                {"role": "user", "content": user_content},
            ],
        }
        if settings.ai_supports_json_schema:
            request_body["response_format"] = _json_schema_response_format(output_model)
        else:
            request_body["response_format"] = {"type": "json_object"}
        ai_debug(
            "ai_debug.model_request",
            purpose=purpose,
            model=model,
            endpoint=settings.ai_endpoint,
            timeout_seconds=timeout_seconds,
            request_body=_redact_request_body(request_body),
        )
        started_at = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.post(
                    settings.ai_endpoint,
                    headers={
                        "Authorization": f"Bearer {settings.ai_api_key}",
                        "Content-Type": "application/json",
                    },
                    json=request_body,
                )
                response.raise_for_status()
            body = response.json()
            input_tokens, output_tokens = _extract_usage(body)
            content = body["choices"][0]["message"]["content"]
            if isinstance(content, list):
                content = "".join(
                    str(item.get("text", "")) for item in content if isinstance(item, dict)
                )
            if not isinstance(content, str):
                raise TypeError("AI response content is not text")
            ai_debug(
                "ai_debug.model_response",
                purpose=purpose,
                model=model,
                status_code=response.status_code,
                elapsed_ms=round((time.perf_counter() - started_at) * 1000, 1),
                content=content,
                usage=body.get("usage"),
            )
            result = output_model.model_validate_json(_strip_json_fences(content), strict=True)
        except (httpx.TimeoutException, TimeoutError) as exc:
            ai_debug(
                "ai_debug.model_error",
                purpose=purpose,
                model=model,
                elapsed_ms=round((time.perf_counter() - started_at) * 1000, 1),
                error_code="AI_MODEL_TIMEOUT",
                error=repr(exc),
            )
            raise ApiError(504, "AI_MODEL_TIMEOUT", "AI 服务响应超时") from exc
        except (httpx.HTTPError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            ai_debug(
                "ai_debug.model_error",
                purpose=purpose,
                model=model,
                elapsed_ms=round((time.perf_counter() - started_at) * 1000, 1),
                error_code="AI_SERVICE_UNAVAILABLE",
                error=repr(exc),
            )
            raise ApiError(503, "AI_SERVICE_UNAVAILABLE", "AI 服务调用失败") from exc
        except ValidationError as exc:
            try:
                # json_object 模式下常见类型偏差（如数字被写成字符串），先本地宽松解析，
                # 避免为可自愈的偏差再发起一次远程修复调用。
                result = output_model.model_validate_json(_strip_json_fences(content))
                ai_debug(
                    "ai_debug.schema_lenient_reparse",
                    purpose=purpose,
                    model=model,
                    validation_errors=exc.errors(include_url=False),
                )
            except ValidationError:
                ai_debug(
                    "ai_debug.schema_repair_triggered",
                    purpose=purpose,
                    model=model,
                    invalid_content=content,
                    validation_errors=exc.errors(include_url=False),
                )
                allowed_ids = (allowed_evidence_ids or set()) | (allowed_source_refs or set())
                result, repair_input_tokens, repair_output_tokens = (
                    await _repair_structured_output(
                        invalid_content=content,
                        validation_error=exc,
                        allowed_resource_ids=allowed_ids,
                        output_model=output_model,
                        model=model,
                        timeout_seconds=min(30.0, timeout_seconds),
                        settings=settings,
                    )
                )
                input_tokens = _sum_tokens(input_tokens, repair_input_tokens)
                output_tokens = _sum_tokens(output_tokens, repair_output_tokens)
    reference_valid = True
    if isinstance(result, ConflictAnalysisOutput):
        conflict_result = _ensure_conflict_human_confirmation_warning(result)
        try:
            conflict_result.validate_evidence_refs(allowed_evidence_ids or set())
        except ValueError as exc:
            reference_valid = False
            ai_debug(
                "ai_debug.reference_fallback_triggered",
                purpose=purpose,
                validation_error=str(exc),
                allowed_evidence_ids=list(
                    item.get("id")
                    for item in payload.get("evidence", [])
                    if isinstance(item, dict)
                    and item.get("id") in (allowed_evidence_ids or set())
                ),
            )
            conflict_result = _conflict_reference_fallback(
                conflict_result,
                payload=payload,
                allowed_evidence_ids=allowed_evidence_ids or set(),
            )
            conflict_result.validate_evidence_refs(allowed_evidence_ids or set())
        result = cast(OutputT, conflict_result)
    if isinstance(result, CommandBriefOutput):
        try:
            result.validate_source_refs(allowed_source_refs or set())
        except ValueError as exc:
            reference_valid = False
            raise ApiError(502, "AI_OUTPUT_REFERENCE_INVALID", str(exc)) from exc
    return AiInvocationResult(
        output=result,
        prompt_version=prompt_spec.prompt_version,
        prompt_sha256=digest,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        schema_valid=True,
        reference_valid=reference_valid,
    )


def _validate_report_refinement_contract(
    request: ReportRefinementRequest, output: ReportRefinementOutput
) -> None:
    text = f"{output.refined_content}\n{output.risk_hint}"
    if _has_pii(text):
        raise ApiError(
            502,
            "AI_OUTPUT_FACT_INTEGRITY_FAILED",
            "AI 上报整理输出包含敏感明文",
        )
    if _contains_completion_phrase(text):
        raise ApiError(
            502,
            "AI_OUTPUT_FACT_INTEGRITY_FAILED",
            "AI 上报整理输出包含完成态处置表述",
        )
    expected_location_line = f"【位置】{request.location_text.strip()}"
    lines = [line.strip() for line in output.refined_content.splitlines() if line.strip()]
    if expected_location_line not in lines:
        raise ApiError(
            502,
            "AI_OUTPUT_FACT_INTEGRITY_FAILED",
            "AI 上报整理输出未保留确认位置",
        )
    # 数字事实一致性校验已移除：误伤场景过多（居民文本中混入无意义数字、
    # 模型合并/规整数字表达时都会被拦截），数字准确性交由居民提交前人工核对。
    for term in _PROTECTED_TERMS:
        if term in request.content and term not in output.refined_content:
            raise ApiError(
                502,
                "AI_OUTPUT_FACT_INTEGRITY_FAILED",
                "AI 上报整理输出遗漏受保护限定词",
            )


def _validate_attachment_enrichment_contract(output: AttachmentEnrichmentOutput) -> None:
    text = output.vision_summary
    if _has_pii(text) or _contains_completion_phrase(text):
        raise ApiError(
            502,
            "AI_OUTPUT_FACT_INTEGRITY_FAILED",
            "AI 媒体提取输出包含敏感明文或完成态表述",
        )


def _media_evidence_text(output: MediaEvidenceExtractionOutput) -> str:
    chunks: list[str] = [
        output.evidence_id,
        output.summary,
        *output.location_clues,
        *output.time_clues,
        *output.risk_signals,
        *output.manipulation_signals,
        *output.limitations,
    ]
    chunks.extend(item.fact for item in output.observations)
    return "\n".join(chunks)


def _validate_media_evidence_contract(
    attachment: Attachment, output: MediaEvidenceExtractionOutput
) -> None:
    if output.evidence_id != attachment.id:
        raise ApiError(
            502,
            "AI_OUTPUT_REFERENCE_INVALID",
            "AI 媒体提取输出引用了错误的证据 ID",
        )
    if output.modality != attachment.media_type:
        raise ApiError(
            502,
            "AI_OUTPUT_FACT_INTEGRITY_FAILED",
            "AI 媒体提取输出改变了媒体类型",
        )
    if output.read_status == "unreadable" and (
        output.observations
        or output.location_clues
        or output.time_clues
        or output.risk_signals
        or output.manipulation_signals
    ):
        raise ApiError(
            502,
            "AI_OUTPUT_FACT_INTEGRITY_FAILED",
            "AI 媒体提取输出在 unreadable 状态下仍给出观察结论",
        )
    text = _media_evidence_text(output)
    if _has_pii(text) or _contains_completion_phrase(text):
        raise ApiError(
            502,
            "AI_OUTPUT_FACT_INTEGRITY_FAILED",
            "AI 媒体提取输出包含敏感明文或完成态表述",
        )


def _truncate_text(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    marker = "\n【截断】媒体提取内容超过当前附件字段长度，已保留前部内容。"
    return value[: max(0, max_length - len(marker))] + marker


def _media_evidence_to_attachment_output(
    output: MediaEvidenceExtractionOutput,
) -> AttachmentEnrichmentOutput:
    observation_lines = [
        f"- {item.fact}（frame_ref={item.frame_ref}, confidence={item.confidence:.2f}）"
        for item in output.observations
    ]
    sections = [
        f"读取状态：{output.read_status}",
        f"媒体类型：{output.modality}",
        f"摘要：{output.summary or '无可审计摘要'}",
    ]
    if observation_lines:
        sections.append("画面观察：\n" + "\n".join(observation_lines))
    if output.location_clues:
        sections.append("位置线索：" + "；".join(output.location_clues))
    if output.time_clues:
        sections.append("时间线索：" + "；".join(output.time_clues))
    if output.risk_signals:
        sections.append("风险信号：" + "；".join(output.risk_signals))
    if output.manipulation_signals:
        sections.append("可见异常：" + "；".join(output.manipulation_signals))
    if output.limitations:
        sections.append("局限性：" + "；".join(output.limitations))
    sections.append(f"置信度：{output.confidence:.2f}")
    return AttachmentEnrichmentOutput(
        vision_summary=_NO_TEXT_VISION_PREFIX
        + _truncate_text("\n".join(sections), 3000 - len(_NO_TEXT_VISION_PREFIX)),
    )


def _validate_command_brief_contract(
    snapshot: dict[str, Any], output: CommandBriefOutput
) -> None:
    text = (
        f"{output.headline}\n{output.summary}\n"
        + "\n".join(recommendation.text for recommendation in output.recommendations)
    )
    if _has_pii(text) or _contains_completion_phrase(text):
        raise ApiError(
            502,
            "AI_OUTPUT_FACT_INTEGRITY_FAILED",
            "AI 态势简报输出包含敏感明文或完成态处置表述",
        )
    # 统计数字一致性校验已移除：年份、日期、时刻等时间数字极易被误判为统计数量，
    # 误伤场景过多，数字准确性交由指挥人员人工复核。
    if not output.recommendations and output.headline != "当前信息不足":
        raise ApiError(
            502,
            "AI_OUTPUT_FACT_INTEGRITY_FAILED",
            "AI 态势简报在无建议时未标注信息不足",
        )


async def refine_report(
    session: AsyncSession,
    request: ReportRefinementRequest,
    actor: Actor,
    settings: Settings | None = None,
) -> tuple[AiAnalysis, ReportRefinementOutput]:
    settings = settings or get_settings()
    ensure_ai_available(settings)
    started = time.perf_counter()
    prompt_digest = _prompt_hash_for("report_refinement", ReportRefinementOutput)
    report_payload, image_payloads = await build_report_refinement_context(
        session,
        request,
        actor,
        settings,
    )
    analysis = AiAnalysis(
        incident_id=request.incident_id,
        analysis_type="report_refinement",
        status="running",
        input_snapshot=report_payload,
        context_package=report_payload,
        context_sha256=sha256_text(canonical_json(report_payload)),
        prompt_version=REPORT_REFINEMENT_PROMPT_VERSION,
        prompt_sha256=prompt_digest,
        created_by_type=actor.subject_type,
        created_by_id=actor.subject_id,
        model_provider=settings.ai_provider,
        model_name=settings.ai_report_model,
        input_version=request.report_revision or 0,
        data_as_of=utcnow(),
    )
    incident: Incident
    model_step: AiJobStep
    async with _committing_write_phase(session):
        with session.no_autoflush:
            current_incident = await session.get(Incident, request.incident_id)
        if current_incident is None:
            raise ApiError(404, "INCIDENT_NOT_FOUND", "事件不存在")
        incident = current_incident
        session.add(analysis)
        await session.flush()
        model_step = AiJobStep(
            analysis_id=analysis.id,
            name="model_call",
            status="running",
            started_at=utcnow(),
            details={
                "model": settings.ai_report_model,
                "attachment_count": len(request.attachment_ids),
                "visual_input_count": len(image_payloads),
            },
        )
        session.add(model_step)

    async def persist_failure(error: ApiError) -> None:
        async with _committing_write_phase(session):
            await session.refresh(incident)
            failed_at = utcnow()
            model_step.status = "failed"
            model_step.finished_at = failed_at
            model_step.error_code = error.code
            analysis.status = "failed"
            analysis.error_code = error.code
            analysis.error_message = error.message
            analysis.schema_valid = (
                False
                if error.code in {"AI_OUTPUT_SCHEMA_INVALID", "AI_OUTPUT_FACT_INTEGRITY_FAILED"}
                else None
            )
            analysis.reference_valid = (
                False if error.code == "AI_OUTPUT_REFERENCE_INVALID" else None
            )
            analysis.latency_ms = int((time.perf_counter() - started) * 1000)
            analysis.completed_at = failed_at
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="ai.report_refinement.failed",
                resource_type="ai_analysis",
                resource_id=analysis.id,
                after={"status": "failed", "error_code": error.code},
            )
            await emit_event(
                session,
                incident=incident,
                event_type="ai.report_refinement.failed",
                resource_type="ai_analysis",
                resource_id=analysis.id,
                resource_revision=0,
                visibility="owner",
                owner_device_id=actor.subject_id,
                payload={"analysis_id": analysis.id, "error_code": error.code},
            )

    try:
        invocation = await asyncio.wait_for(
            _invoke_structured(
                purpose="report_refinement",
                payload=report_payload,
                output_model=ReportRefinementOutput,
                model=settings.ai_report_model,
                timeout_seconds=settings.ai_report_timeout_seconds,
                settings=settings,
                image_payloads=image_payloads,
            ),
            timeout=settings.ai_report_timeout_seconds,
        )
        output = invocation.output
        _validate_report_refinement_contract(request, output)
    except TimeoutError as exc:
        error = ApiError(504, "AI_MODEL_TIMEOUT", "AI 服务响应超时")
        await persist_failure(error)
        raise error from exc
    except ApiError as exc:
        await persist_failure(exc)
        raise
    except Exception as exc:
        error = ApiError(503, "AI_PROCESSING_FAILED", "AI 上报整理处理失败")
        await persist_failure(error)
        raise error from exc
    async with _committing_write_phase(session):
        await session.refresh(incident)
        model_step.status = "succeeded"
        model_step.finished_at = utcnow()
        session.add(
            AiJobStep(
                analysis_id=analysis.id,
                name="schema_validation",
                status="succeeded",
                started_at=model_step.finished_at,
                finished_at=model_step.finished_at,
                details={"schema": "ReportRefinementOutput"},
            )
        )
        analysis.status = "succeeded"
        analysis.output = output.model_dump(mode="json")
        analysis.confidence = output.confidence
        analysis.prompt_version = invocation.prompt_version
        analysis.prompt_sha256 = invocation.prompt_sha256
        analysis.input_tokens = invocation.input_tokens
        analysis.output_tokens = invocation.output_tokens
        analysis.schema_valid = invocation.schema_valid
        analysis.reference_valid = invocation.reference_valid
        analysis.latency_ms = int((time.perf_counter() - started) * 1000)
        analysis.completed_at = utcnow()
        await record_audit(
            session,
            actor=actor,
            incident_id=incident.id,
            action="ai.report_refinement.succeeded",
            resource_type="ai_analysis",
            resource_id=analysis.id,
            after={
                "status": "succeeded",
                "model": analysis.model_name,
                "latency_ms": analysis.latency_ms,
            },
        )
        await emit_event(
            session,
            incident=incident,
            event_type="ai.report_refinement.ready",
            resource_type="ai_analysis",
            resource_id=analysis.id,
            resource_revision=0,
            visibility="owner",
            owner_device_id=actor.subject_id,
            payload={"analysis_id": analysis.id, "status": "succeeded"},
        )
    return analysis, output


async def resolve_conflict(session: AsyncSession, conflict_id_or_alias: str) -> ConflictCase | None:
    conflict = await session.get(ConflictCase, conflict_id_or_alias)
    if conflict:
        return conflict
    result = await session.scalar(
        select(ConflictCase).where(ConflictCase.alias == conflict_id_or_alias)
    )
    return result if isinstance(result, ConflictCase) else None


async def build_conflict_context(
    session: AsyncSession,
    conflict: ConflictCase,
    requested_evidence_ids: list[str] | None,
) -> tuple[dict[str, Any], set[str]]:
    evidence_rows = list(
        (
            await session.scalars(
                select(ConflictEvidence)
                .where(
                    ConflictEvidence.conflict_id == conflict.id,
                    ConflictEvidence.is_current.is_(True),
                )
                .order_by(ConflictEvidence.added_at)
            )
        ).all()
    )
    allowed = {row.id for row in evidence_rows}
    source_ids = {row.source_id for row in evidence_rows}
    if requested_evidence_ids:
        unknown = sorted(set(requested_evidence_ids) - allowed - source_ids)
        if unknown:
            raise ApiError(
                422,
                "EVIDENCE_NOT_FOUND",
                "请求包含不属于当前冲突的证据",
                details={"unknown_evidence_ids": unknown},
            )
    evidence: list[dict[str, Any]] = []
    for row in evidence_rows:
        item = {
            "id": row.id,
            "kind": row.kind,
            "source_id": row.source_id,
            "source_revision": row.source_revision,
            "source_cluster_id": row.source_cluster_id,
            "snapshot": row.snapshot,
            "snapshot_sha256": row.snapshot_sha256,
            "added_at": row.added_at.isoformat(),
        }
        if row.kind in {"attachment", "image"}:
            attachment = await session.get(Attachment, row.source_id)
            safe_vision_summary = None
            if attachment and attachment.vision_summary and attachment.vision_summary.startswith(
                _NO_TEXT_VISION_PREFIX
            ):
                safe_vision_summary = attachment.vision_summary.removeprefix(
                    _NO_TEXT_VISION_PREFIX
                )
            item["image"] = {
                "status": "ready" if attachment and attachment.sanitized_path else "unreadable",
                "sha256": attachment.sha256 if attachment else None,
                "perceptual_hash": attachment.perceptual_hash if attachment else None,
                "vision_status": attachment.vision_status if attachment else "missing",
                "vision_summary": safe_vision_summary,
                "width": attachment.width if attachment else None,
                "height": attachment.height if attachment else None,
            }
        evidence.append(item)
    if not evidence:
        raise ApiError(422, "AI_CONTEXT_EMPTY", "冲突没有当前有效证据")
    for item in evidence:
        item["timeline_at"] = _evidence_timeline_value(item)
    evidence.sort(key=lambda item: (str(item["timeline_at"]), str(item["id"])))
    context = {
        "conflict": {
            "id": conflict.id,
            "revision": conflict.revision,
            "title": conflict.title,
            "fact_key": conflict.fact_key,
            "topic": conflict.topic,
            "location_text": conflict.location_text,
            "status": conflict.status,
        },
        "evidence": evidence,
        "data_as_of": max(
            (row.added_at for row in evidence_rows),
            default=conflict.updated_at,
        ).isoformat(),
        "rules": {
            "all_current_evidence_included": True,
            "duplicate_clusters_are_single_sources": True,
            "human_decision_required": True,
        },
    }
    return context, allowed


async def enqueue_conflict_analysis(
    session: AsyncSession,
    *,
    conflict: ConflictCase,
    revision: int,
    evidence_ids: list[str] | None,
    actor: Actor,
    settings: Settings | None = None,
) -> AiAnalysis:
    settings = settings or get_settings()
    ensure_ai_available(settings)
    if conflict.revision != revision:
        raise ApiError(
            409,
            "REVISION_CONFLICT",
            "冲突版本已变化",
            details={"expected": revision, "current": conflict.revision},
        )
    context, allowed = await build_conflict_context(session, conflict, evidence_ids)
    context_hash = sha256_text(canonical_json(context))
    existing = await session.scalar(
        select(AiAnalysis)
        .where(
            AiAnalysis.analysis_type == "conflict_analysis",
            AiAnalysis.status == "succeeded",
            AiAnalysis.is_stale.is_(False),
            AiAnalysis.context_sha256 == context_hash,
            AiAnalysis.model_name == settings.ai_vision_model,
            AiAnalysis.prompt_version == CONFLICT_ANALYSIS_PROMPT_VERSION,
        )
        .order_by(AiAnalysis.created_at.desc())
    )
    if existing:
        conflict.status = "analysis_ready"
        return existing
    conflict.status = "analyzing"
    analysis = AiAnalysis(
        incident_id=conflict.incident_id,
        analysis_type="conflict_analysis",
        status="queued",
        input_snapshot={
            "conflict_id": conflict.id,
            "conflict_revision": revision,
            "allowed_evidence_ids": sorted(allowed),
        },
        context_package=context,
        context_sha256=context_hash,
        prompt_version=CONFLICT_ANALYSIS_PROMPT_VERSION,
        prompt_sha256=_prompt_hash_for("conflict_analysis", ConflictAnalysisOutput),
        created_by_type=actor.subject_type,
        created_by_id=actor.subject_id,
        input_version=revision,
        data_as_of=utcnow(),
        model_provider=settings.ai_provider,
        model_name=settings.ai_vision_model,
    )
    session.add(analysis)
    await session.flush()
    image_evidence = [
        item
        for item in context["evidence"]
        if isinstance(item, dict) and item.get("kind") in {"attachment", "image"}
    ]
    source_clusters = {
        str(item["source_cluster_id"])
        for item in context["evidence"]
        if isinstance(item, dict) and item.get("source_cluster_id")
    }
    _add_completed_step(
        session,
        analysis.id,
        "evidence_collection",
        {
            "evidence_count": len(context["evidence"]),
            "allowed_evidence_ids": len(allowed),
        },
    )
    _add_completed_step(
        session,
        analysis.id,
        "image_safety_and_deduplication",
        {
            "image_evidence_count": len(image_evidence),
            "source_cluster_count": len(source_clusters),
            "policy": "ready_and_malware_clean_only",
        },
    )
    _add_completed_step(
        session,
        analysis.id,
        "vision_context",
        {
            "vision_ready_count": sum(
                1
                for item in image_evidence
                if isinstance(item.get("image"), dict)
                and item["image"].get("vision_status") == "succeeded"
            ),
            "source": "attachment_processing_pipeline",
        },
    )
    _add_completed_step(
        session,
        analysis.id,
        "text_normalization",
        {"normalized_evidence_count": len(context["evidence"])},
    )
    _add_completed_step(
        session,
        analysis.id,
        "timeline_alignment",
        {
            "ordered_evidence_ids": [str(item["id"]) for item in context["evidence"]],
            "ordering": "observed_or_captured_then_received",
        },
    )
    _add_completed_step(
        session,
        analysis.id,
        "context_persistence",
        {
            "context_sha256": context_hash,
            "prompt_version": CONFLICT_ANALYSIS_PROMPT_VERSION,
            "prompt_sha256": analysis.prompt_sha256,
        },
    )
    session.add(
        BackgroundJob(
            job_type="ai.analysis",
            payload={"analysis_id": analysis.id},
            max_attempts=settings.job_max_attempts,
        )
    )
    return analysis


async def build_brief_snapshot(
    session: AsyncSession, incident: Incident, request: CommandBriefRequest
) -> dict[str, Any]:
    report_filters = (
        Report.incident_id == incident.id,
        Report.deleted_at.is_(None),
    )
    report_count = int(
        await session.scalar(select(func.count()).select_from(Report).where(*report_filters)) or 0
    )
    urgent_report_count = int(
        await session.scalar(
            select(func.count())
            .select_from(Report)
            .where(*report_filters, Report.is_urgent.is_(True))
        )
        or 0
    )
    recent_reports = list(
        (
            await session.scalars(
                select(Report).where(*report_filters).order_by(Report.updated_at.desc()).limit(80)
            )
        ).all()
    )
    unresolved_urgent_reports = list(
        (
            await session.scalars(
                select(Report)
                .where(
                    *report_filters,
                    Report.is_urgent.is_(True),
                    Report.status.not_in(("resolved", "invalid")),
                )
                .order_by(Report.updated_at.desc())
                .limit(40)
            )
        ).all()
    )
    reports_by_id = {row.id: row for row in [*unresolved_urgent_reports, *recent_reports]}
    report_rows = list(reports_by_id.values())[:120]
    conflicts = list(
        (
            await session.scalars(
                select(ConflictCase).where(
                    ConflictCase.incident_id == incident.id,
                    *(
                        ()
                        if request.include_resolved
                        else (ConflictCase.status.not_in(("resolved", "closed")),)
                    ),
                )
            )
        ).all()
    )
    blind_spots = list(
        (
            await session.scalars(
                select(BlindSpot).where(
                    BlindSpot.incident_id == incident.id,
                    *(
                        ()
                        if request.include_resolved
                        else (BlindSpot.status.not_in(("resolved", "closed")),)
                    ),
                )
            )
        ).all()
    )
    fact_count = int(
        await session.scalar(
            select(func.count())
            .select_from(FactRecord)
            .where(
                FactRecord.incident_id == incident.id,
                FactRecord.status.in_(("current", "under_review")),
            )
        )
        or 0
    )
    fact_rows = list(
        (
            await session.scalars(
                select(FactRecord)
                .where(
                    FactRecord.incident_id == incident.id,
                    FactRecord.status.in_(("current", "under_review")),
                )
                .order_by(FactRecord.updated_at.desc())
                .limit(40)
            )
        ).all()
    )
    high_conflict_count = sum(1 for row in conflicts if row.severity == "high")
    critical_blind_spot_count = sum(1 for row in blind_spots if row.severity == "high")
    return {
        "request_context": {
            "incident_id": incident.id,
            "scope": request.scope,
            "include_resolved": request.include_resolved,
            "language": request.language,
            "data_as_of": utcnow().isoformat(),
            "input_version": incident.data_revision,
        },
        "incident": {
            "id": incident.id,
            "name": incident.name,
            "status": incident.status,
            "timezone": incident.timezone,
        },
        "metrics": {
            "active_report_count": report_count,
            "urgent_report_count": urgent_report_count,
            "open_conflict_count": len(conflicts),
            "high_severity_conflict_count": high_conflict_count,
            "open_blind_spot_count": len(blind_spots),
            "critical_blind_spot_count": critical_blind_spot_count,
            "current_fact_count": fact_count,
            "included_report_count": len(report_rows),
            "updated_report_count_since_last_brief": len(recent_reports),
        },
        "urgent_reports": [
            {
                "source_ref": f"report:{row.id}",
                "id": row.id,
                "category": row.category,
                "content_display": row.content_display,
                "priority": row.priority,
                "is_urgent": row.is_urgent,
                "location_text": row.location_text,
                "updated_at": row.updated_at.isoformat(),
            }
            for row in unresolved_urgent_reports
        ],
        "recent_reports": [
            {
                "source_ref": f"report:{row.id}",
                "id": row.id,
                "category": row.category,
                "content_display": row.content_display,
                "priority": row.priority,
                "is_urgent": row.is_urgent,
                "location_text": row.location_text,
                "updated_at": row.updated_at.isoformat(),
            }
            for row in report_rows
        ],
        "open_conflicts": [
            {
                "source_ref": f"conflict:{row.id}",
                "id": row.id,
                "title": row.title,
                "severity": row.severity,
                "status": row.status,
                "revision": row.revision,
                "location_text": row.location_text,
                "updated_at": row.updated_at.isoformat(),
            }
            for row in conflicts
        ],
        "blind_spots": [
            {
                "source_ref": f"blind_spot:{row.id}",
                "id": row.id,
                "title": row.title,
                "severity": row.severity,
                "location_text": row.location_text,
                "route_impact_count": row.route_impact_count,
                "updated_at": row.updated_at.isoformat(),
            }
            for row in blind_spots
        ],
        "current_facts": [
            {
                "source_ref": f"fact:{row.id}",
                "id": row.id,
                "topic": row.topic,
                "location_text": row.location_text,
                "status": row.status,
                "updated_at": row.updated_at.isoformat(),
            }
            for row in fact_rows
        ],
        "recent_changes": [
            {
                "source_ref": f"report:{row.id}",
                "change": row.content_display,
                "updated_at": row.updated_at.isoformat(),
            }
            for row in recent_reports[:20]
        ],
        "data_as_of": utcnow().isoformat(),
        "incident_data_revision": incident.data_revision,
        "report_context": {
            "included": len(report_rows),
            "total": report_count,
            "recent_limit": 80,
            "unresolved_urgent_limit": 40,
            "truncated": report_count > len(report_rows),
        },
    }


async def enqueue_command_brief(
    session: AsyncSession,
    *,
    incident: Incident,
    request: CommandBriefRequest,
    actor: Actor,
    settings: Settings | None = None,
) -> AiAnalysis:
    settings = settings or get_settings()
    ensure_ai_available(settings)
    snapshot = await build_brief_snapshot(session, incident, request)
    analysis = AiAnalysis(
        incident_id=incident.id,
        analysis_type="command_brief",
        status="queued",
        input_snapshot=snapshot,
        context_package=snapshot,
        context_sha256=sha256_text(canonical_json(snapshot)),
        prompt_version=COMMAND_BRIEF_PROMPT_VERSION,
        prompt_sha256=_prompt_hash_for("command_brief", CommandBriefOutput),
        created_by_type=actor.subject_type,
        created_by_id=actor.subject_id,
        input_version=incident.data_revision,
        data_as_of=utcnow(),
        model_provider=settings.ai_provider,
        model_name=settings.ai_brief_model,
    )
    session.add(analysis)
    await session.flush()
    _add_completed_step(
        session,
        analysis.id,
        "snapshot_collection",
        {
            "report_count": snapshot["metrics"]["active_report_count"],
            "open_conflict_count": snapshot["metrics"]["open_conflict_count"],
            "open_blind_spot_count": snapshot["metrics"]["open_blind_spot_count"],
            "input_version": incident.data_revision,
        },
    )
    _add_completed_step(
        session,
        analysis.id,
        "text_normalization",
        {
            "included_reports": snapshot["report_context"]["included"],
            "truncated": snapshot["report_context"]["truncated"],
        },
    )
    _add_completed_step(
        session,
        analysis.id,
        "context_persistence",
        {
            "context_sha256": analysis.context_sha256,
            "prompt_version": COMMAND_BRIEF_PROMPT_VERSION,
            "prompt_sha256": analysis.prompt_sha256,
        },
    )
    session.add(
        BackgroundJob(
            job_type="ai.analysis",
            payload={"analysis_id": analysis.id},
            max_attempts=settings.job_max_attempts,
        )
    )
    return analysis


async def _complete_async_analysis(
    session: AsyncSession,
    *,
    analysis: AiAnalysis,
    model_step: AiJobStep,
    invocation: AiInvocationResult[BaseModel],
    started: float,
) -> AiAnalysis:
    output = invocation.output
    async with _committing_write_phase(session):
        analysis.output = output.model_dump(mode="json")
        analysis.prompt_version = invocation.prompt_version
        analysis.prompt_sha256 = invocation.prompt_sha256
        analysis.input_tokens = invocation.input_tokens
        analysis.output_tokens = invocation.output_tokens
        analysis.schema_valid = invocation.schema_valid
        analysis.reference_valid = invocation.reference_valid
        model_step.status = "succeeded"
        model_step.finished_at = utcnow()
        session.add(
            AiJobStep(
                analysis_id=analysis.id,
                name="schema_and_evidence_validation",
                status="succeeded",
                started_at=model_step.finished_at,
                finished_at=model_step.finished_at,
                details={"output_schema": type(output).__name__},
            )
        )
        analysis.confidence = float(getattr(output, "confidence", 0))
        analysis.status = "succeeded"
        stale_reason: str | None = None
        current_conflict: ConflictCase | None = None
        current_incident: Incident | None = None
        with session.no_autoflush:
            if analysis.analysis_type == "conflict_analysis":
                conflict_id = str(analysis.input_snapshot.get("conflict_id", ""))
                current_conflict = await session.get(ConflictCase, conflict_id)
                if current_conflict is None or current_conflict.revision != analysis.input_version:
                    stale_reason = "conflict_revision_changed_during_analysis"
            else:
                current_incident = await session.get(Incident, analysis.incident_id)
                if (
                    current_incident is None
                    or current_incident.data_revision != analysis.input_version
                ):
                    stale_reason = "incident_data_revision_changed_during_analysis"
        if stale_reason is not None:
            analysis.is_stale = True
            analysis.stale_at = utcnow()
            analysis.stale_reason = stale_reason
        analysis.completed_at = utcnow()
        analysis.latency_ms = int((time.perf_counter() - started) * 1000)
        with session.no_autoflush:
            incident = current_incident or await session.get(Incident, analysis.incident_id)
        if incident is None:
            raise ApiError(404, "INCIDENT_NOT_FOUND", "事件不存在")
        if analysis.analysis_type == "conflict_analysis":
            if current_conflict is not None and not analysis.is_stale:
                current_conflict.status = "analysis_ready"
                await upsert_conflict_map_feature(session, current_conflict)
            elif current_conflict is not None and current_conflict.status == "analyzing":
                current_conflict.status = "open"
                await upsert_conflict_map_feature(session, current_conflict)
            await emit_event(
                session,
                incident=incident,
                event_type="conflict.analysis_ready",
                resource_type="conflict",
                resource_id=current_conflict.id if current_conflict else None,
                resource_revision=(
                    current_conflict.revision if current_conflict else analysis.input_version
                ),
                payload={
                    "analysis_id": analysis.id,
                    "is_stale": analysis.is_stale,
                    "confidence": analysis.confidence,
                },
            )
        else:
            await emit_event(
                session,
                incident=incident,
                event_type=("command_brief.stale" if analysis.is_stale else "command_brief.ready"),
                resource_type="ai_analysis",
                resource_id=analysis.id,
                resource_revision=analysis.input_version,
                payload={"analysis_id": analysis.id, "is_stale": analysis.is_stale},
            )
        await record_audit(
            session,
            actor=None,
            incident_id=incident.id,
            action=f"ai.{analysis.analysis_type}.succeeded",
            resource_type="ai_analysis",
            resource_id=analysis.id,
            after={
                "status": analysis.status,
                "is_stale": analysis.is_stale,
                "model": analysis.model_name,
                "latency_ms": analysis.latency_ms,
            },
            metadata={
                "created_by_type": analysis.created_by_type,
                "created_by_id": analysis.created_by_id,
            },
        )
    return analysis


async def _fail_async_analysis(
    session: AsyncSession,
    *,
    analysis: AiAnalysis,
    model_step: AiJobStep,
    error: ApiError,
    started: float,
) -> None:
    async with _committing_write_phase(session):
        analysis_id = analysis.id
        model_step_id = model_step.id
        await session.rollback()
        current_analysis = await session.get(AiAnalysis, analysis_id)
        current_model_step = await session.get(AiJobStep, model_step_id)
        if current_analysis is None:
            return
        failed_at = utcnow()
        if current_model_step is not None:
            current_model_step.status = "failed"
            current_model_step.finished_at = failed_at
            current_model_step.error_code = error.code
        running_steps = list(
            (
                await session.scalars(
                    select(AiJobStep).where(
                        AiJobStep.analysis_id == analysis_id,
                        AiJobStep.status.in_(("queued", "running")),
                    )
                )
            ).all()
        )
        for step in running_steps:
            step.status = "failed"
            step.finished_at = failed_at
            step.error_code = error.code
        current_analysis.status = "failed"
        current_analysis.error_code = error.code
        current_analysis.error_message = error.message
        current_analysis.schema_valid = (
            False
            if error.code in {"AI_OUTPUT_SCHEMA_INVALID", "AI_OUTPUT_FACT_INTEGRITY_FAILED"}
            else None
        )
        current_analysis.reference_valid = (
            False if error.code == "AI_OUTPUT_REFERENCE_INVALID" else None
        )
        current_analysis.completed_at = failed_at
        current_analysis.latency_ms = int((time.perf_counter() - started) * 1000)
        analysis = current_analysis
        incident = await session.get(Incident, analysis.incident_id)
        if incident is not None:
            if analysis.analysis_type == "conflict_analysis":
                conflict_id = str(analysis.input_snapshot.get("conflict_id", ""))
                current_conflict = await session.get(ConflictCase, conflict_id)
                if current_conflict is not None and current_conflict.status == "analyzing":
                    current_conflict.status = "open"
                    await upsert_conflict_map_feature(session, current_conflict)
                await emit_event(
                    session,
                    incident=incident,
                    event_type="conflict.analysis_failed",
                    resource_type="conflict",
                    resource_id=current_conflict.id if current_conflict else None,
                    resource_revision=(
                        current_conflict.revision if current_conflict else analysis.input_version
                    ),
                    payload={"analysis_id": analysis.id, "error_code": error.code},
                )
            elif analysis.analysis_type == "command_brief":
                await emit_event(
                    session,
                    incident=incident,
                    event_type="command_brief.failed",
                    resource_type="ai_analysis",
                    resource_id=analysis.id,
                    resource_revision=analysis.input_version,
                    payload={"analysis_id": analysis.id, "error_code": error.code},
                )
            await record_audit(
                session,
                actor=None,
                incident_id=incident.id,
                action=f"ai.{analysis.analysis_type}.failed",
                resource_type="ai_analysis",
                resource_id=analysis.id,
                after={"status": "failed", "error_code": error.code},
                metadata={
                    "created_by_type": analysis.created_by_type,
                    "created_by_id": analysis.created_by_id,
                },
            )


async def process_analysis(
    session: AsyncSession,
    analysis_id: str,
    settings: Settings | None = None,
) -> AiAnalysis:
    settings = settings or get_settings()
    analysis = await session.get(AiAnalysis, analysis_id)
    if not analysis:
        raise ApiError(404, "ANALYSIS_NOT_FOUND", "AI 分析不存在")
    started = time.perf_counter()
    model_step = AiJobStep(
        analysis_id=analysis.id,
        name="model_call",
        status="running",
        started_at=utcnow(),
        details={"model": analysis.model_name, "analysis_type": analysis.analysis_type},
    )
    async with _committing_write_phase(session):
        analysis.status = "running"
        analysis.error_code = None
        analysis.error_message = None
        session.add(model_step)
    try:
        ensure_ai_available(settings)
        invocation: AiInvocationResult[BaseModel]
        if analysis.analysis_type == "conflict_analysis":
            allowed = set(analysis.input_snapshot.get("allowed_evidence_ids", []))
            image_step = AiJobStep(
                analysis_id=analysis.id,
                name="safe_image_read",
                status="running",
                started_at=utcnow(),
                details={"policy": "sanitized_storage_only"},
            )
            async with _committing_write_phase(session):
                session.add(image_step)
            image_payloads: list[bytes] = []
            storage_root = await asyncio.to_thread(settings.storage_root.resolve)
            for item in (analysis.context_package or {}).get("evidence", []):
                if not isinstance(item, dict) or item.get("kind") not in {
                    "attachment",
                    "image",
                }:
                    continue
                attachment = await session.get(Attachment, str(item.get("source_id", "")))
                if (
                    attachment is None
                    or attachment.metadata_status != "ready"
                    or attachment.malware_scan_status not in {"clean", "fake_clean"}
                    or not attachment.sanitized_path
                ):
                    raise ApiError(
                        503,
                        "AI_IMAGE_EVIDENCE_UNAVAILABLE",
                        "AI 图片证据不再处于可安全读取状态",
                    )
                path = await asyncio.to_thread(Path(attachment.sanitized_path).resolve)
                if path == storage_root or storage_root not in path.parents:
                    raise ApiError(
                        503,
                        "AI_IMAGE_PATH_INVALID",
                        "AI 图片证据路径不在受控存储目录内",
                    )
                try:
                    image_payloads.append(await asyncio.to_thread(path.read_bytes))
                except OSError as exc:
                    raise ApiError(
                        503,
                        "AI_IMAGE_READ_FAILED",
                        "AI 无法读取已净化的图片证据",
                    ) from exc
            async with _committing_write_phase(session):
                image_step.status = "succeeded"
                image_step.finished_at = utcnow()
                image_step.details = {
                    "policy": "sanitized_storage_only",
                    "image_count": len(image_payloads),
                    "total_bytes": sum(len(value) for value in image_payloads),
                }
            invocation = await _invoke_structured(
                purpose="conflict_analysis",
                payload=analysis.context_package or {},
                output_model=ConflictAnalysisOutput,
                model=settings.ai_vision_model,
                timeout_seconds=settings.ai_conflict_timeout_seconds,
                settings=settings,
                allowed_evidence_ids=allowed,
                image_payloads=image_payloads,
            )
        elif analysis.analysis_type == "command_brief":
            brief_context = analysis.context_package or analysis.input_snapshot
            allowed_source_refs = {"incident:current"}
            for collection in (
                "urgent_reports",
                "recent_reports",
                "open_conflicts",
                "blind_spots",
                "current_facts",
                "recent_changes",
            ):
                for item in brief_context.get(collection, []):
                    if isinstance(item, dict) and item.get("source_ref"):
                        allowed_source_refs.add(str(item["source_ref"]))
            async with _committing_write_phase(session):
                _add_completed_step(
                    session,
                    analysis.id,
                    "source_reference_whitelist",
                    {
                        "allowed_source_ref_count": len(allowed_source_refs),
                        "input_version": analysis.input_version,
                    },
                )
            invocation = await _invoke_structured(
                purpose="command_brief",
                payload=brief_context,
                output_model=CommandBriefOutput,
                model=settings.ai_brief_model,
                timeout_seconds=settings.ai_brief_timeout_seconds,
                settings=settings,
                allowed_source_refs=allowed_source_refs,
            )
            _validate_command_brief_contract(
                brief_context,
                cast(CommandBriefOutput, invocation.output),
            )
        else:
            raise ApiError(422, "ANALYSIS_TYPE_UNSUPPORTED", "不支持的 AI 分析类型")
        return await _complete_async_analysis(
            session,
            analysis=analysis,
            model_step=model_step,
            invocation=invocation,
            started=started,
        )
    except ApiError as exc:
        await _fail_async_analysis(
            session,
            analysis=analysis,
            model_step=model_step,
            error=exc,
            started=started,
        )
        raise
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        error = ApiError(503, "AI_PROCESSING_FAILED", "AI 分析处理失败")
        await _fail_async_analysis(
            session,
            analysis=analysis,
            model_step=model_step,
            error=error,
            started=started,
        )
        raise error from exc


async def retry_analysis(
    session: AsyncSession, analysis: AiAnalysis, settings: Settings | None = None
) -> BackgroundJob:
    settings = settings or get_settings()
    ensure_ai_available(settings)
    if analysis.status != "failed":
        raise ApiError(409, "ANALYSIS_NOT_RETRYABLE", "仅失败的分析可以重试")
    if analysis.analysis_type not in {"conflict_analysis", "command_brief"}:
        raise ApiError(
            409,
            "ANALYSIS_NOT_RETRYABLE",
            "同步上报整理不能通过异步分析队列重试，请重新提交整理请求",
        )
    analysis.status = "queued"
    analysis.is_stale = False
    analysis.stale_at = None
    analysis.stale_reason = None
    analysis.error_code = None
    analysis.error_message = None
    analysis.completed_at = None
    analysis.output = None
    analysis.confidence = None
    analysis.latency_ms = None
    analysis.input_tokens = None
    analysis.output_tokens = None
    analysis.schema_valid = None
    analysis.reference_valid = None
    job = BackgroundJob(
        job_type="ai.analysis",
        payload={"analysis_id": analysis.id},
        max_attempts=settings.job_max_attempts,
    )
    session.add(job)
    return job


async def analyze_legacy_conflict(
    session: AsyncSession,
    *,
    conflict: ConflictCase,
    context: dict[str, Any],
    actor: Actor,
    settings: Settings | None = None,
) -> tuple[AiAnalysis, ConflictAnalysisOutput]:
    settings = settings or get_settings()
    ensure_ai_available(settings)
    if not settings.enable_legacy_demo_ai:
        raise ApiError(422, "LEGACY_AI_DISABLED", "开发兼容 AI 接口未启用")
    evidence_raw = context.get("evidence", [])
    evidence = evidence_raw if isinstance(evidence_raw, list) else []
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(evidence):
        value = item if isinstance(item, dict) else {"content": str(item)}
        evidence_id = str(
            value.get("id")
            or value.get("evidence_id")
            or value.get("source_id")
            or f"legacy-evidence-{index + 1}"
        )
        normalized.append({**value, "id": evidence_id})
    if not normalized:
        raise ApiError(422, "AI_CONTEXT_EMPTY", "legacy context.evidence 不能为空")
    package = {
        "conflict": {
            "id": conflict.id,
            "revision": conflict.revision,
            "title": conflict.title,
            "location_text": conflict.location_text,
        },
        "evidence": normalized,
        "legacy_context": {k: v for k, v in context.items() if k != "evidence"},
        "data_as_of": utcnow().isoformat(),
    }
    allowed = {str(item["id"]) for item in normalized}
    analysis = AiAnalysis(
        incident_id=conflict.incident_id,
        analysis_type="conflict_analysis",
        status="running",
        input_snapshot={
            "conflict_id": conflict.id,
            "conflict_revision": conflict.revision,
            "allowed_evidence_ids": sorted(allowed),
            "legacy": True,
        },
        context_package=package,
        context_sha256=sha256_text(canonical_json(package)),
        prompt_version=CONFLICT_ANALYSIS_PROMPT_VERSION,
        prompt_sha256=_prompt_hash_for("conflict_analysis", ConflictAnalysisOutput),
        created_by_type=actor.subject_type,
        created_by_id=actor.subject_id,
        input_version=conflict.revision,
        data_as_of=utcnow(),
        model_provider=settings.ai_provider,
        model_name=settings.ai_vision_model,
    )
    started = time.perf_counter()
    model_step: AiJobStep
    async with _committing_write_phase(session):
        session.add(analysis)
        await session.flush()
        _add_completed_step(
            session,
            analysis.id,
            "legacy_context_collection",
            {
                "evidence_count": len(normalized),
                "client_supplied_context": True,
            },
        )
        _add_completed_step(
            session,
            analysis.id,
            "text_normalization",
            {"normalized_evidence_count": len(normalized), "legacy": True},
        )
        _add_completed_step(
            session,
            analysis.id,
            "timeline_alignment",
            {
                "ordering": "client_order_with_server_timestamp",
                "legacy": True,
            },
        )
        _add_completed_step(
            session,
            analysis.id,
            "context_persistence",
            {
                "context_sha256": analysis.context_sha256,
                "prompt_version": CONFLICT_ANALYSIS_PROMPT_VERSION,
                "prompt_sha256": analysis.prompt_sha256,
                "legacy": True,
            },
        )
        model_step = AiJobStep(
            analysis_id=analysis.id,
            name="model_call",
            status="running",
            started_at=utcnow(),
            details={"model": settings.ai_vision_model, "legacy": True},
        )
        session.add(model_step)
    try:
        invocation = await asyncio.wait_for(
            _invoke_structured(
                purpose="conflict_analysis",
                payload=package,
                output_model=ConflictAnalysisOutput,
                model=settings.ai_vision_model,
                timeout_seconds=min(10.0, settings.ai_conflict_timeout_seconds),
                settings=settings,
                allowed_evidence_ids=allowed,
            ),
            timeout=min(10.0, settings.ai_conflict_timeout_seconds),
        )
        output = invocation.output
    except TimeoutError as exc:
        error = ApiError(504, "AI_MODEL_TIMEOUT", "AI 服务响应超时")
        await _fail_async_analysis(
            session,
            analysis=analysis,
            model_step=model_step,
            error=error,
            started=started,
        )
        raise error from exc
    except ApiError as exc:
        await _fail_async_analysis(
            session,
            analysis=analysis,
            model_step=model_step,
            error=exc,
            started=started,
        )
        raise
    except Exception as exc:
        error = ApiError(503, "AI_PROCESSING_FAILED", "AI 冲突研判处理失败")
        await _fail_async_analysis(
            session,
            analysis=analysis,
            model_step=model_step,
            error=error,
            started=started,
        )
        raise error from exc
    async with _committing_write_phase(session):
        model_step.status = "succeeded"
        model_step.finished_at = utcnow()
        session.add(
            AiJobStep(
                analysis_id=analysis.id,
                name="schema_and_evidence_validation",
                status="succeeded",
                started_at=model_step.finished_at,
                finished_at=model_step.finished_at,
                details={"output_schema": "ConflictAnalysisOutput", "legacy": True},
            )
        )
        analysis.status = "succeeded"
        analysis.output = output.model_dump(mode="json")
        analysis.confidence = output.confidence
        analysis.prompt_version = invocation.prompt_version
        analysis.prompt_sha256 = invocation.prompt_sha256
        analysis.input_tokens = invocation.input_tokens
        analysis.output_tokens = invocation.output_tokens
        analysis.schema_valid = invocation.schema_valid
        analysis.reference_valid = invocation.reference_valid
        analysis.latency_ms = int((time.perf_counter() - started) * 1000)
        analysis.completed_at = utcnow()
    return analysis, output


async def enrich_attachment(
    session: AsyncSession,
    attachment: Attachment,
    settings: Settings | None = None,
    *,
    image_bytes: bytes | None = None,
) -> None:
    settings = settings or get_settings()
    attachment.ocr_status = "not_applicable"
    attachment.ocr_text = None
    if not settings.ai_configured:
        attachment.vision_status = "unavailable"
        return
    if settings.ai_provider == "fake":
        attachment.vision_status = "succeeded"
        attachment.vision_summary = (
            _NO_TEXT_VISION_PREFIX + "测试图片已安全解码，未配置真实视觉内容。"
        )
        return
    if image_bytes is None and not attachment.sanitized_path:
        attachment.vision_status = "failed"
        return
    try:
        if image_bytes is None:
            assert attachment.sanitized_path is not None
            image_bytes = await asyncio.to_thread(Path(attachment.sanitized_path).read_bytes)
        invocation = await _invoke_structured(
            purpose="attachment_enrichment",
            payload={
                "request_context": {
                    "incident_id": attachment.incident_id,
                    "evidence_id": attachment.id,
                    "language": "zh-CN",
                },
                "media": {
                    "modality": attachment.media_type,
                    "file_name": attachment.file_name,
                    "declared_mime_type": attachment.declared_mime_type,
                    "sha256": attachment.sha256,
                },
            },
            output_model=MediaEvidenceExtractionOutput,
            model=settings.ai_vision_model,
            timeout_seconds=settings.ai_conflict_timeout_seconds,
            settings=settings,
            image_payloads=[image_bytes],
        )
        media_result = invocation.output
        _validate_media_evidence_contract(attachment, media_result)
        result = _media_evidence_to_attachment_output(media_result)
        _validate_attachment_enrichment_contract(result)
    except Exception:
        attachment.vision_status = "failed"
        raise
    attachment.vision_summary = result.vision_summary
    attachment.vision_status = "succeeded"
