from __future__ import annotations

import base64
import json
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Select, and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..domain.coordinates import normalize
from ..domain.priority import Priority, effective_priority
from ..errors import ApiError, not_found
from ..models import (
    AiAnalysis,
    Attachment,
    Incident,
    MapFeature,
    Report,
    ReporterContact,
    ReportRevision,
)
from ..schemas.reports import ReportCreate, ReportLocation
from ..security import Actor
from ..utils import as_utc, canonical_json, sha256_text, utcnow
from .attachments import serialize_attachment
from .contacts import create_reporter_contact, serialize_contact_masked

_IMMEDIATE_DANGER_RISK_TAGS = frozenset(
    {
        "trapped_people",
        "missing_people",
        "injured_people",
        "severe_bleeding",
        "unconscious_person",
        "breathing_difficulty",
        "rising_water",
        "rapid_current",
        "deep_flooding",
        "building_collapse",
        "landslide",
        "fire",
        "electric_hazard",
        "gas_leak",
        "bridge_damage",
    }
)
_OPERATIONAL_RISK_TAGS = frozenset(
    {
        "road_blocked",
        "medical_shortage",
        "drinking_water_shortage",
        "food_shortage",
        "unsafe_shelter",
        "communication_outage",
    }
)
_PRIORITY_RISK_TAGS = _IMMEDIATE_DANGER_RISK_TAGS | _OPERATIONAL_RISK_TAGS
_AI_MEDIUM_CONFIDENCE_MIN = 0.75
_AI_HIGH_CONFIDENCE_MIN = 0.85


async def get_incident(session: AsyncSession, incident_id: str) -> Incident:
    incident = await session.scalar(
        select(Incident).where(or_(Incident.id == incident_id, Incident.alias == incident_id))
    )
    if incident is None:
        raise not_found("incident")
    return incident


def assert_incident_access(
    actor: Actor,
    incident: Incident,
    header_id: str | None,
) -> None:
    if header_id is not None and header_id not in {incident.id, incident.alias}:
        raise ApiError(
            403,
            "INCIDENT_CONTEXT_MISMATCH",
            "X-Incident-Id does not match the requested incident",
        )
    if incident.id not in actor.incident_ids:
        raise ApiError(403, "INCIDENT_ACCESS_DENIED", "incident access denied")


def assert_report_access(actor: Actor, report: Report, *, write: bool = False) -> None:
    if report.incident_id not in actor.incident_ids:
        raise ApiError(403, "INCIDENT_ACCESS_DENIED", "incident access denied")
    if actor.is_resident and report.reporter_device_id != actor.subject_id:
        raise ApiError(
            403,
            "REPORT_OWNERSHIP_REQUIRED",
            "residents may only access reports created by this device",
        )
    if write and actor.subject_type == "account" and actor.role not in {"operator", "admin"}:
        raise ApiError(403, "FORBIDDEN", "this account cannot modify reports")


async def get_report(session: AsyncSession, report_id: str) -> Report:
    report = await session.get(Report, report_id)
    if report is None or report.deleted_at is not None:
        raise not_found("report")
    return report


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.isoformat() + "Z"
    return value.isoformat().replace("+00:00", "Z")


def report_snapshot(report: Report) -> dict[str, Any]:
    return {
        "id": report.id,
        "incident_id": report.incident_id,
        "reporter_device_id": report.reporter_device_id,
        "reporter_contact_id": report.reporter_contact_id,
        "category": report.category,
        "content_original": report.content_original,
        "content_display": report.content_display,
        "location_text": report.location_text,
        "location": {
            "latitude": report.latitude,
            "longitude": report.longitude,
            "accuracy_m": report.location_accuracy_m,
            "source": report.location_source,
            "provider": report.location_provider,
            "coordinate_system": report.coordinate_system,
            "observed_at": _iso(report.location_observed_at),
            "wgs84": {
                "latitude": report.location_wgs84_latitude,
                "longitude": report.location_wgs84_longitude,
            },
            "gcj02": {
                "latitude": report.location_gcj02_latitude,
                "longitude": report.location_gcj02_longitude,
            },
            "algorithm_version": report.coordinate_algorithm_version,
        },
        "is_urgent": report.is_urgent,
        "priority": report.priority,
        "priority_source": report.priority_source,
        "manual_priority": report.manual_priority,
        "status": report.status,
        "is_directed_answer": report.is_directed_answer,
        "ai_refinement_id": report.ai_refinement_id,
        "attachment_count": report.attachment_count,
        "revision": report.revision,
        "created_at": _iso(report.created_at),
        "updated_at": _iso(report.updated_at),
    }


def serialize_report(
    report: Report,
    actor: Actor | None = None,
    *,
    contact: ReporterContact | None = None,
    attachments: Sequence[Attachment] = (),
) -> dict[str, Any]:
    snapshot = report_snapshot(report)
    snapshot.pop("reporter_device_id", None)
    snapshot.pop("reporter_contact_id", None)
    snapshot.pop("manual_priority", None)
    snapshot["reporter"] = serialize_contact_masked(contact)
    snapshot["attachment_ids"] = [attachment.id for attachment in attachments]
    snapshot["attachments"] = [serialize_attachment(attachment) for attachment in attachments]
    if actor is not None and not actor.is_resident:
        snapshot["source"] = {
            "type": "anonymous_device",
            "device_id": report.reporter_device_id,
        }
        snapshot["manual_priority"] = report.manual_priority
    return snapshot


def apply_location(report: Report, location: ReportLocation) -> None:
    if location.observed_at is not None and as_utc(location.observed_at) > utcnow() + timedelta(
        minutes=get_settings().location_future_tolerance_minutes
    ):
        raise ApiError(
            422,
            "LOCATION_OBSERVED_AT_IN_FUTURE",
            "位置观察时间不能晚于服务器时间容差",
        )
    report.location_text = location.text
    report.location_accuracy_m = location.accuracy_m
    report.location_source = location.source
    report.location_provider = location.provider
    report.location_observed_at = location.observed_at
    if location.latitude is None or location.longitude is None:
        report.latitude = None
        report.longitude = None
        report.coordinate_system = None
        report.location_wgs84_latitude = None
        report.location_wgs84_longitude = None
        report.location_gcj02_latitude = None
        report.location_gcj02_longitude = None
        report.coordinate_algorithm_version = None
        return
    assert location.coordinate_system is not None
    coordinates = normalize(
        location.latitude,
        location.longitude,
        location.coordinate_system,
    )
    report.latitude = coordinates.raw_latitude
    report.longitude = coordinates.raw_longitude
    report.coordinate_system = coordinates.coordinate_system
    report.location_wgs84_latitude = coordinates.wgs84_latitude
    report.location_wgs84_longitude = coordinates.wgs84_longitude
    report.location_gcj02_latitude = coordinates.gcj02_latitude
    report.location_gcj02_longitude = coordinates.gcj02_longitude
    report.coordinate_algorithm_version = coordinates.algorithm_version


async def bind_attachments(
    session: AsyncSession,
    *,
    report: Report,
    attachment_ids: list[str],
) -> None:
    if not attachment_ids:
        report.attachment_count = 0
        return
    attachments = await load_bindable_attachments(
        session,
        incident_id=report.incident_id,
        uploader_device_id=report.reporter_device_id,
        attachment_ids=attachment_ids,
    )
    for attachment in attachments:
        attachment.report_id = report.id
    report.attachment_count = len(attachments)


async def load_bindable_attachments(
    session: AsyncSession,
    *,
    incident_id: str,
    uploader_device_id: str,
    attachment_ids: list[str],
    bound_report_id: str | None = None,
) -> list[Attachment]:
    if not attachment_ids:
        return []
    attachments = list(
        (await session.scalars(select(Attachment).where(Attachment.id.in_(attachment_ids)))).all()
    )
    attachments_by_id = {attachment.id: attachment for attachment in attachments}
    if len(attachments_by_id) != len(attachment_ids):
        raise ApiError(
            422,
            "ATTACHMENT_NOT_READY",
            "one or more attachments do not exist",
        )
    for attachment in attachments:
        if (
            attachment.incident_id != incident_id
            or attachment.uploader_device_id != uploader_device_id
            or attachment.report_id not in {None, bound_report_id}
            or attachment.directed_answer_id is not None
            or attachment.metadata_status != "ready"
            or attachment.malware_scan_status not in {"clean", "fake_clean"}
        ):
            raise ApiError(
                422,
                "ATTACHMENT_NOT_READY",
                "attachment is not ready or is owned by another device",
            )
    return [attachments_by_id[attachment_id] for attachment_id in attachment_ids]


async def replace_attachments(
    session: AsyncSession,
    *,
    report: Report,
    attachment_ids: list[str],
) -> None:
    current = list(
        (
            await session.scalars(
                select(Attachment).where(
                    Attachment.report_id == report.id,
                    Attachment.incident_id == report.incident_id,
                )
            )
        ).all()
    )
    for attachment in current:
        attachment.report_id = None
    await bind_attachments(session, report=report, attachment_ids=attachment_ids)


async def upsert_report_map_feature(
    session: AsyncSession,
    report: Report,
) -> MapFeature | None:
    feature = await session.scalar(
        select(MapFeature).where(
            MapFeature.incident_id == report.incident_id,
            MapFeature.kind == "report",
            MapFeature.source_ref == report.id,
        )
    )
    has_position = (
        report.location_wgs84_latitude is not None
        and report.location_wgs84_longitude is not None
        and report.location_gcj02_latitude is not None
        and report.location_gcj02_longitude is not None
    )
    if feature is None and not has_position:
        return None
    if feature is None:
        feature = MapFeature(
            incident_id=report.incident_id,
            kind="report",
            source_ref=report.id,
            title=report.location_text,
            status=report.status,
            severity=report.priority,
        )
        session.add(feature)
    feature.title = report.location_text
    feature.status = report.status
    feature.severity = report.priority
    feature.latitude_wgs84 = report.location_wgs84_latitude
    feature.longitude_wgs84 = report.location_wgs84_longitude
    feature.latitude_gcj02 = report.location_gcj02_latitude
    feature.longitude_gcj02 = report.location_gcj02_longitude
    feature.revision = report.revision
    feature.is_deleted = not has_position or report.deleted_at is not None
    feature.public_data = {
        "category": report.category,
        "is_urgent": report.is_urgent,
        "priority": report.priority,
        "location_text": report.location_text,
    }
    feature.private_data = {"owner_device_id": report.reporter_device_id}
    return feature


async def create_report(
    session: AsyncSession,
    *,
    incident: Incident,
    actor: Actor,
    payload: ReportCreate,
) -> Report:
    if not actor.is_resident:
        raise ApiError(
            403,
            "RESIDENT_REQUIRED",
            "only anonymous residents create reports",
        )
    refinement = await validate_report_refinement(
        session,
        analysis_id=payload.ai_refinement_id,
        incident_id=incident.id,
        actor=actor,
        category=payload.category,
        content=payload.content_original,
        location_text=payload.location.text,
        attachment_ids=payload.attachment_ids,
    )
    priority, source = effective_priority(
        payload.category,
        is_urgent=payload.is_urgent,
        ai_priority=ai_priority_from_refinement(refinement),
    )
    report = Report(
        incident_id=incident.id,
        reporter_device_id=actor.subject_id,
        category=payload.category,
        content_original=payload.content_original,
        content_display=payload.content_display or payload.content_original,
        location_text=payload.location.text,
        is_urgent=payload.is_urgent,
        priority=priority,
        priority_source=source,
        status="new",
        is_directed_answer=False,
        ai_refinement_id=payload.ai_refinement_id,
        revision=1,
    )
    contact = create_reporter_contact(
        incident=incident,
        device_id=actor.subject_id,
        reporter=payload.reporter,
    )
    session.add(contact)
    await session.flush()
    report.reporter_contact_id = contact.id
    apply_location(report, payload.location)
    session.add(report)
    await session.flush()
    await bind_attachments(
        session,
        report=report,
        attachment_ids=payload.attachment_ids,
    )
    session.add(
        ReportRevision(
            report_id=report.id,
            revision=1,
            snapshot=report_snapshot(report),
            changed_by_type=actor.subject_type,
            changed_by_id=actor.subject_id,
            change_reason="created",
        )
    )
    await upsert_report_map_feature(session, report)
    return report


async def validate_report_refinement(
    session: AsyncSession,
    *,
    analysis_id: str | None,
    incident_id: str,
    actor: Actor,
    category: str,
    content: str,
    location_text: str,
    attachment_ids: list[str],
    report_id: str | None = None,
    report_revision: int | None = None,
    bound_report_id: str | None = None,
    use_stored_report_context: bool = False,
) -> AiAnalysis | None:
    if analysis_id is None:
        return None
    analysis = await session.get(AiAnalysis, analysis_id)
    if (
        analysis is None
        or analysis.analysis_type != "report_refinement"
        or analysis.incident_id != incident_id
        or analysis.status != "succeeded"
        or analysis.is_stale
    ):
        raise ApiError(
            422,
            "AI_REFINEMENT_INVALID",
            "AI 上报整理结果不存在、未成功或已失效",
        )
    if actor.is_resident and analysis.created_by_id != actor.subject_id:
        raise ApiError(403, "AI_REFINEMENT_ACCESS_DENIED", "无权使用其他设备的 AI 建议")
    context = analysis.context_package or analysis.input_snapshot
    request_context_candidate = context.get("request_context")
    is_legacy_text_refinement = (
        analysis.prompt_version == "cm-report-refinement-v1.0.0"
        and analysis.context_sha256 is None
        and analysis.context_package is None
        and not attachment_ids
        and "attachments" not in context
        and isinstance(request_context_candidate, dict)
        and "report_id" not in request_context_candidate
        and "report_revision" not in request_context_candidate
    )
    if not is_legacy_text_refinement and (
        analysis.context_sha256 is None
        or analysis.context_sha256 != sha256_text(canonical_json(context))
    ):
        raise ApiError(422, "AI_REFINEMENT_INVALID", "AI 上报整理上下文完整性校验失败")
    attachments = await load_bindable_attachments(
        session,
        incident_id=incident_id,
        uploader_device_id=actor.subject_id,
        attachment_ids=attachment_ids,
        bound_report_id=bound_report_id if bound_report_id is not None else report_id,
    )
    expected_attachments = sorted(
        (
            {
                "attachment_id": attachment.id,
                "media_type": attachment.media_type,
                "sha256": attachment.sha256,
                "storage_etag": attachment.etag,
                "size_bytes": attachment.size_bytes,
            }
            for attachment in attachments
        ),
        key=lambda item: str(item["attachment_id"]),
    )
    context_attachments = context.get("attachments", [])
    if not isinstance(context_attachments, list):
        context_attachments = []
    actual_attachments = sorted(
        (
            {
                "attachment_id": item.get("attachment_id"),
                "media_type": item.get("media_type"),
                "sha256": item.get("sha256"),
                "storage_etag": item.get("storage_etag"),
                "size_bytes": item.get("size_bytes"),
            }
            for item in context_attachments
            if isinstance(item, dict)
        ),
        key=lambda item: str(item["attachment_id"]),
    )
    report_context = context.get("report")
    request_context = context.get("request_context")
    if not isinstance(report_context, dict) or not isinstance(request_context, dict):
        raise ApiError(422, "AI_REFINEMENT_INVALID", "AI 上报整理上下文结构无效")
    context_report_id = request_context.get("report_id")
    context_report_revision = request_context.get("report_revision")
    if use_stored_report_context:
        report_id = context_report_id if isinstance(context_report_id, str) else None
        report_revision = (
            context_report_revision if isinstance(context_report_revision, int) else None
        )
    refined_content = (
        analysis.output.get("refined_content") if isinstance(analysis.output, dict) else None
    )
    if (
        report_context.get("category") != category
        or content not in {report_context.get("content"), refined_content}
        or report_context.get("location_text") != location_text
        or actual_attachments != expected_attachments
        or context_report_id != report_id
        or context_report_revision != report_revision
    ):
        raise ApiError(
            422,
            "AI_REFINEMENT_CONTEXT_MISMATCH",
            "AI 上报整理结果与当前正文、位置或附件不一致，请重新分析",
        )
    return analysis


def ai_priority_from_refinement(analysis: AiAnalysis | None) -> Priority | None:
    if analysis is None or analysis.output is None:
        return None

    confidence = analysis.output.get("confidence")
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or confidence < _AI_MEDIUM_CONFIDENCE_MIN
    ):
        return "low"

    raw_risk_tags = analysis.output.get("detected_risk_tags")
    if not isinstance(raw_risk_tags, list) or not all(
        isinstance(tag, str) for tag in raw_risk_tags
    ):
        return "low"
    risk_tags = set(raw_risk_tags) & _PRIORITY_RISK_TAGS
    if not risk_tags:
        return "low"

    if (
        analysis.output.get("suggest_urgent") is True
        and confidence >= _AI_HIGH_CONFIDENCE_MIN
        and risk_tags & _IMMEDIATE_DANGER_RISK_TAGS
    ):
        return "high"
    return "medium"


def encode_cursor(report: Report) -> str:
    raw = json.dumps(
        {"updated_at": _iso(report.updated_at), "id": report.id},
        separators=(",", ":"),
    ).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded).decode())
        updated_at = datetime.fromisoformat(str(data["updated_at"]).replace("Z", "+00:00"))
        return updated_at, str(data["id"])
    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ApiError(422, "INVALID_CURSOR", "cursor is invalid") from exc


def apply_cursor(statement: Select[Any], cursor: str | None) -> Select[Any]:
    if not cursor:
        return statement
    updated_at, report_id = decode_cursor(cursor)
    updated_at = as_utc(updated_at).replace(tzinfo=None)
    return statement.where(
        or_(
            Report.updated_at < updated_at,
            and_(Report.updated_at == updated_at, Report.id < report_id),
        )
    )
