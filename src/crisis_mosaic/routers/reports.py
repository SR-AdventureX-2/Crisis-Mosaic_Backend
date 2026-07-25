from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Header, Query, Request, Response
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.sql import Select

from ..db import write_lock
from ..dependencies import ActorDep, IncidentHeader, SessionDep
from ..domain.priority import effective_priority
from ..errors import ApiError
from ..models import Attachment, Incident, Report, ReporterContact, ReportRevision
from ..responses import success
from ..schemas.reports import (
    ReportCategory,
    ReportCreate,
    ReportDelete,
    ReporterRevealRequest,
    ReportPatch,
    ReportPriority,
    ReportPriorityPatch,
    ReportStatus,
    ReportStatusPatch,
)
from ..security import Actor
from ..services.attachments import attachments_by_report
from ..services.contacts import (
    authorize_reveal,
    serialize_contact_plain,
    update_reporter_contact,
)
from ..services.events import emit_event, record_audit
from ..services.idempotency import finish, replay_or_reserve
from ..services.notifications import enqueue_operator_notifications
from ..services.report_observations import (
    deactivate_report_observation,
    process_report_observation,
)
from ..services.reports import (
    ai_priority_from_refinement,
    apply_cursor,
    apply_location,
    assert_incident_access,
    assert_report_access,
    create_report,
    decode_cursor,
    encode_cursor,
    get_incident,
    get_report,
    replace_attachments,
    report_snapshot,
    serialize_report,
    upsert_report_map_feature,
    validate_report_refinement,
)
from ..utils import as_utc, isoformat, utcnow

router = APIRouter(tags=["Reports"])

_ALLOWED_STATUS_TRANSITIONS: dict[str, set[str]] = {
    "new": {"acknowledged", "invalid"},
    "acknowledged": {"in_progress", "invalid"},
    "in_progress": {"resolved", "invalid"},
    "resolved": set(),
    "invalid": {"acknowledged"},
}


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


@asynccontextmanager
async def _write_transaction(session: SessionDep) -> AsyncIterator[None]:
    """Commit the dependency's autobegun transaction as one serialized write."""
    try:
        yield
        await session.commit()
    except Exception:
        await session.rollback()
        raise


def _raise_revision_conflict(report: Report, expected: int) -> None:
    raise ApiError(
        409,
        "REVISION_CONFLICT",
        "report was updated by another request",
        details={"expected_revision": expected, "current_revision": report.revision},
    )


async def _incident_for_report(session: SessionDep, report: Report) -> Incident:
    incident = await session.get(Incident, report.incident_id)
    if incident is None:
        raise ApiError(404, "NOT_FOUND", "incident not found")
    return incident


async def _contact_for_report(session: SessionDep, report: Report) -> ReporterContact | None:
    if not report.reporter_contact_id:
        return None
    return await session.get(ReporterContact, report.reporter_contact_id)


async def _contacts_for_reports(
    session: SessionDep,
    reports: list[Report],
) -> dict[str, ReporterContact]:
    ids = [report.reporter_contact_id for report in reports if report.reporter_contact_id]
    if not ids:
        return {}
    rows = list(
        (await session.scalars(select(ReporterContact).where(ReporterContact.id.in_(ids)))).all()
    )
    return {row.id: row for row in rows}


def _serialize_report_detail(
    report: Report,
    actor: Actor,
    *,
    contact: ReporterContact | None,
    attachments: Sequence[Attachment],
) -> dict[str, Any]:
    data = serialize_report(report, actor, contact=contact, attachments=attachments)
    if contact is not None and actor.role in {"operator", "admin"}:
        data["reporter"] = serialize_contact_plain(contact)
    return data


def _priority_rank() -> Any:
    return case(
        (Report.priority == "high", 3),
        (Report.priority == "medium", 2),
        (Report.priority == "low", 1),
        else_=0,
    )


def _urgent_rank() -> Any:
    return case((Report.is_urgent.is_(True), 1), else_=0)


async def _apply_operator_cursor(
    session: SessionDep,
    statement: Select[Any],
    cursor: str | None,
    *,
    incident_id: str,
) -> Select[Any]:
    if cursor is None:
        return statement

    cursor_updated_at, cursor_id = decode_cursor(cursor)
    cursor_report = await session.get(Report, cursor_id)
    if cursor_report is None or cursor_report.incident_id != incident_id:
        raise ApiError(422, "INVALID_CURSOR", "cursor is invalid")
    cursor_updated_at = as_utc(cursor_updated_at).replace(tzinfo=None)

    cursor_priority = {"high": 3, "medium": 2, "low": 1}.get(
        cursor_report.priority,
        0,
    )
    cursor_urgent = int(cursor_report.is_urgent)
    priority_rank = _priority_rank()
    urgent_rank = _urgent_rank()
    return statement.where(
        or_(
            priority_rank < cursor_priority,
            and_(
                priority_rank == cursor_priority,
                urgent_rank < cursor_urgent,
            ),
            and_(
                priority_rank == cursor_priority,
                urgent_rank == cursor_urgent,
                or_(
                    Report.updated_at < cursor_updated_at,
                    and_(
                        Report.updated_at == cursor_updated_at,
                        Report.id < cursor_id,
                    ),
                ),
            ),
        )
    )


@router.post("/incidents/{incident_id}/reports", status_code=201)
async def post_report(
    incident_id: str,
    payload: ReportCreate,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
) -> dict[str, Any]:
    async with write_lock:
        async with _write_transaction(session):
            incident = await get_incident(session, incident_id)
            assert_incident_access(actor, incident, incident_header)
            reservation = await replay_or_reserve(
                session,
                actor=actor,
                route=f"POST:/incidents/{incident.id}/reports",
                key=idempotency_key,
                body=payload.model_dump(mode="json"),
            )
            if isinstance(reservation, dict):
                return reservation
            report = await create_report(
                session,
                incident=incident,
                actor=actor,
                payload=payload,
            )
            contact = await _contact_for_report(session, report)
            attachments = (await attachments_by_report(session, [report.id])).get(report.id, [])
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="report.created",
                resource_type="report",
                resource_id=report.id,
                request_id=_request_id(request),
                after=report_snapshot(report),
            )
            event = await emit_event(
                session,
                incident=incident,
                event_type="report.created",
                resource_type="report",
                resource_id=report.id,
                resource_revision=report.revision,
                visibility="owner",
                owner_device_id=report.reporter_device_id,
                payload=serialize_report(report, contact=contact, attachments=attachments),
            )
            await process_report_observation(
                session,
                incident=incident,
                report=report,
                actor=actor,
                request_id=_request_id(request),
            )
            notification_event_type = (
                "urgent_report.created" if report.is_urgent else "report.created"
            )
            await enqueue_operator_notifications(
                session,
                incident=incident,
                business_event_id=str(event.payload["event_id"]),
                event_type=notification_event_type,
                priority=report.priority,
                resource_type="report",
                resource_id=report.id,
                resource_revision=report.revision,
                deep_link=f"crisismosaic://incidents/{incident.id}/reports/{report.id}",
                title="Crisis Mosaic 紧急提醒",
                body="收到一条新的高优先级现场上报，请打开应用查看。",
            )
            response = success(
                serialize_report(report, actor, contact=contact, attachments=attachments),
                request,
            )
            finish(reservation, status_code=201, body=response)
            return response


@router.get("/incidents/{incident_id}/reports")
async def list_reports(
    incident_id: str,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
    priority: ReportPriority | None = None,
    category: ReportCategory | None = None,
    status: ReportStatus | None = None,
    urgent: bool | None = None,
    updated_after: datetime | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 30,
) -> dict[str, Any]:
    incident = await get_incident(session, incident_id)
    assert_incident_access(actor, incident, incident_header)
    filters: list[Any] = [
        Report.incident_id == incident.id,
        Report.deleted_at.is_(None),
        Report.is_directed_answer.is_(False),
    ]
    if actor.is_resident:
        filters.append(Report.reporter_device_id == actor.subject_id)
    if priority is not None:
        filters.append(Report.priority == priority)
    if category is not None:
        filters.append(Report.category == category)
    if status is not None:
        filters.append(Report.status == status)
    if urgent is not None:
        filters.append(Report.is_urgent == urgent)
    if updated_after is not None:
        filters.append(Report.updated_at > as_utc(updated_after).replace(tzinfo=None))

    total = int(await session.scalar(select(func.count(Report.id)).where(*filters)) or 0)
    statement = select(Report).where(*filters)
    if actor.is_resident:
        statement = apply_cursor(statement, cursor)
        statement = statement.order_by(Report.updated_at.desc(), Report.id.desc())
    else:
        statement = await _apply_operator_cursor(
            session,
            statement,
            cursor,
            incident_id=incident.id,
        )
        statement = statement.order_by(
            _priority_rank().desc(),
            _urgent_rank().desc(),
            Report.updated_at.desc(),
            Report.id.desc(),
        )
    statement = statement.limit(limit + 1)
    reports = list((await session.scalars(statement)).all())
    has_more = len(reports) > limit
    page = reports[:limit]
    contacts = await _contacts_for_reports(session, page)
    attachment_map = await attachments_by_report(session, [item.id for item in page])
    next_cursor = encode_cursor(page[-1]) if has_more and page else None
    return success(
        [
            serialize_report(
                item,
                actor,
                contact=contacts.get(item.reporter_contact_id or ""),
                attachments=attachment_map.get(item.id, []),
            )
            for item in page
        ],
        request,
        meta={
            "total": total,
            "limit": limit,
            "next_cursor": next_cursor,
            "has_more": has_more,
            "as_of": utcnow().isoformat(),
        },
    )


@router.get("/reports/{report_id}")
async def read_report(
    report_id: str,
    request: Request,
    response: Response,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    report = await get_report(session, report_id)
    assert_report_access(actor, report)
    incident = await _incident_for_report(session, report)
    assert_incident_access(actor, incident, incident_header)
    contact = await _contact_for_report(session, report)
    attachments = (await attachments_by_report(session, [report.id])).get(report.id, [])
    data = _serialize_report_detail(
        report,
        actor,
        contact=contact,
        attachments=attachments,
    )
    if contact is not None and actor.role in {"operator", "admin"}:
        async with write_lock:
            try:
                await record_audit(
                    session,
                    actor=actor,
                    incident_id=incident.id,
                    action="report.command_detail_read",
                    resource_type="report",
                    resource_id=report.id,
                    request_id=_request_id(request),
                    metadata={
                        "access_scope": "authenticated_command_report_detail",
                        "actor_role": actor.role,
                        "plaintext_reporter_fields_returned": True,
                    },
                )
                await session.commit()
            except Exception:
                await session.rollback()
                raise
    response.headers["Cache-Control"] = "no-store"
    return success(data, request)


@router.get("/reports/{report_id}/history")
@router.get("/reports/{report_id}/revisions")
async def report_history(
    report_id: str,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    report = await get_report(session, report_id)
    assert_report_access(actor, report)
    incident = await _incident_for_report(session, report)
    assert_incident_access(actor, incident, incident_header)
    revisions = list(
        (
            await session.scalars(
                select(ReportRevision)
                .where(ReportRevision.report_id == report.id)
                .order_by(ReportRevision.revision.asc())
            )
        ).all()
    )
    data: list[dict[str, Any]] = []
    for revision in revisions:
        snapshot = dict(revision.snapshot)
        if actor.is_resident:
            snapshot.pop("reporter_device_id", None)
            snapshot.pop("manual_priority", None)
        data.append(
            {
                "revision": revision.revision,
                "snapshot": snapshot,
                "changed_by_type": revision.changed_by_type,
                "change_reason": revision.change_reason,
                "created_at": revision.created_at,
            }
        )
    return success(data, request, meta={"current_revision": report.revision})


@router.patch("/reports/{report_id}")
async def patch_report(
    report_id: str,
    payload: ReportPatch,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    if not actor.is_resident:
        raise ApiError(
            403,
            "RESIDENT_REQUIRED",
            "居民上报正文和原始位置只能由创建该上报的设备修改",
        )
    async with write_lock:
        async with _write_transaction(session):
            report = await get_report(session, report_id)
            assert_report_access(actor, report, write=True)
            incident = await _incident_for_report(session, report)
            assert_incident_access(actor, incident, incident_header)
            if report.revision != payload.revision:
                _raise_revision_conflict(report, payload.revision)
            fields = payload.model_fields_set - {"revision"}
            if not fields:
                raise ApiError(422, "NO_CHANGES", "at least one field must be supplied")
            non_nullable = {
                "category",
                "content_original",
                "content_display",
                "location",
                "is_urgent",
            }
            for name in fields & non_nullable:
                if getattr(payload, name) is None:
                    raise ApiError(
                        422,
                        "FIELD_NOT_NULLABLE",
                        f"{name} cannot be null",
                    )
            before = report_snapshot(report)
            if "category" in fields:
                assert payload.category is not None
                report.category = payload.category
            if "content_original" in fields:
                assert payload.content_original is not None
                report.content_original = payload.content_original
            if "content_display" in fields:
                assert payload.content_display is not None
                report.content_display = payload.content_display
            if "location" in fields:
                assert payload.location is not None
                apply_location(report, payload.location)
            if "is_urgent" in fields:
                assert payload.is_urgent is not None
                report.is_urgent = payload.is_urgent
            if "ai_refinement_id" in fields:
                report.ai_refinement_id = payload.ai_refinement_id
            elif fields & {"category", "content_original", "location", "attachment_ids"}:
                report.ai_refinement_id = None
            if "reporter" in fields:
                if payload.reporter is None:
                    raise ApiError(422, "REPORTER_CONTACT_REQUIRED", "上报人联系方式不得清空")
                previous_contact = await _contact_for_report(session, report)
                if previous_contact is None:
                    raise ApiError(409, "REPORTER_CONTACT_MISSING", "当前上报缺少联系人快照")
                next_contact = update_reporter_contact(
                    incident=incident,
                    previous=previous_contact,
                    patch=payload.reporter,
                )
                session.add(next_contact)
                await session.flush()
                report.reporter_contact_id = next_contact.id
            if "attachment_ids" in fields:
                if payload.attachment_ids is None:
                    raise ApiError(422, "FIELD_NOT_NULLABLE", "attachment_ids cannot be null")
                await replace_attachments(
                    session,
                    report=report,
                    attachment_ids=payload.attachment_ids,
                )
            final_attachment_ids = list(
                (
                    await session.scalars(
                        select(Attachment.id)
                        .where(Attachment.report_id == report.id)
                        .order_by(Attachment.id)
                    )
                ).all()
            )
            reuse_stored_refinement_context = (
                report.ai_refinement_id is not None
                and "ai_refinement_id" not in fields
                and not fields & {"category", "content_original", "location", "attachment_ids"}
            )
            refinement = await validate_report_refinement(
                session,
                analysis_id=report.ai_refinement_id,
                incident_id=incident.id,
                actor=actor,
                category=report.category,
                content=report.content_original,
                location_text=report.location_text,
                attachment_ids=final_attachment_ids,
                report_id=report.id,
                report_revision=payload.revision,
                bound_report_id=(report.id if reuse_stored_refinement_context else None),
                use_stored_report_context=reuse_stored_refinement_context,
            )
            priority, source = effective_priority(
                report.category,
                is_urgent=report.is_urgent,
                manual_priority=report.manual_priority,  # type: ignore[arg-type]
                ai_priority=ai_priority_from_refinement(refinement),
            )
            report.priority = priority
            report.priority_source = source
            report.revision += 1
            report.updated_at = utcnow()
            snapshot = report_snapshot(report)
            session.add(
                ReportRevision(
                    report_id=report.id,
                    revision=report.revision,
                    snapshot=snapshot,
                    changed_by_type=actor.subject_type,
                    changed_by_id=actor.subject_id,
                    change_reason=("resident_update" if actor.is_resident else "operator_update"),
                )
            )
            await upsert_report_map_feature(session, report)
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="report.updated",
                resource_type="report",
                resource_id=report.id,
                request_id=_request_id(request),
                before=before,
                after=snapshot,
            )
            attachments = (await attachments_by_report(session, [report.id])).get(report.id, [])
            await emit_event(
                session,
                incident=incident,
                event_type="report.updated",
                resource_type="report",
                resource_id=report.id,
                resource_revision=report.revision,
                visibility="owner",
                owner_device_id=report.reporter_device_id,
                payload=serialize_report(
                    report,
                    contact=await _contact_for_report(session, report),
                    attachments=attachments,
                ),
            )
            if fields & {"category", "content_original", "content_display", "location"}:
                await process_report_observation(
                    session,
                    incident=incident,
                    report=report,
                    actor=actor,
                    request_id=_request_id(request),
                )
            contact = await _contact_for_report(session, report)
            return success(
                serialize_report(report, actor, contact=contact, attachments=attachments),
                request,
            )


@router.delete("/reports/{report_id}")
async def delete_report(
    report_id: str,
    payload: ReportDelete,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    if not actor.is_resident:
        raise ApiError(403, "RESIDENT_REQUIRED", "only residents may delete their own reports")
    async with write_lock:
        async with _write_transaction(session):
            report = await get_report(session, report_id)
            assert_report_access(actor, report, write=True)
            if report.is_directed_answer:
                raise ApiError(404, "NOT_FOUND", "report not found")
            incident = await _incident_for_report(session, report)
            assert_incident_access(actor, incident, incident_header)
            if report.revision != payload.revision:
                _raise_revision_conflict(report, payload.revision)

            before = report_snapshot(report)
            deleted_at = utcnow()
            report.deleted_at = deleted_at
            report.revision += 1
            report.updated_at = deleted_at
            await deactivate_report_observation(
                session,
                incident=incident,
                report=report,
                actor=actor,
                request_id=_request_id(request),
                reason="source_report_deleted",
            )
            tombstone = {
                "report_id": report.id,
                "revision": report.revision,
                "deleted_at": isoformat(deleted_at),
            }
            snapshot = {
                **report_snapshot(report),
                "deleted_at": tombstone["deleted_at"],
            }
            session.add(
                ReportRevision(
                    report_id=report.id,
                    revision=report.revision,
                    snapshot=snapshot,
                    changed_by_type=actor.subject_type,
                    changed_by_id=actor.subject_id,
                    change_reason="resident_deleted",
                )
            )
            await upsert_report_map_feature(session, report)
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="report.deleted",
                resource_type="report",
                resource_id=report.id,
                request_id=_request_id(request),
                before=before,
                after=tombstone,
            )
            await emit_event(
                session,
                incident=incident,
                event_type="report.deleted",
                resource_type="report",
                resource_id=report.id,
                resource_revision=report.revision,
                visibility="owner",
                owner_device_id=report.reporter_device_id,
                payload=tombstone,
            )
            return success(tombstone, request)


@router.get("/me/reports/recent")
async def recent_report(
    request: Request,
    response: Response,
    session: SessionDep,
    actor: ActorDep,
    directed_answer: bool = False,
) -> dict[str, Any]:
    if not actor.is_resident:
        raise ApiError(403, "RESIDENT_REQUIRED", "only residents have a recent report")
    report = await session.scalar(
        select(Report)
        .where(
            Report.reporter_device_id == actor.subject_id,
            Report.incident_id.in_(actor.incident_ids),
            Report.is_directed_answer == directed_answer,
            Report.deleted_at.is_(None),
        )
        .order_by(Report.updated_at.desc(), Report.id.desc())
        .limit(1)
    )
    if report is None:
        return success(None, request)
    contact = await _contact_for_report(session, report)
    attachments = (await attachments_by_report(session, [report.id])).get(report.id, [])
    data = serialize_report(report, actor, contact=contact, attachments=attachments)
    if contact is not None:
        data["reporter"] = serialize_contact_plain(contact)
    response.headers["Cache-Control"] = "no-store"
    return success(data, request)


@router.post("/reports/{report_id}/reporter-contact/reveal")
async def reveal_reporter_contact(
    report_id: str,
    payload: ReporterRevealRequest,
    request: Request,
    response: Response,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    report = await get_report(session, report_id)
    assert_report_access(actor, report)
    incident = await _incident_for_report(session, report)
    assert_incident_access(actor, incident, incident_header)
    contact = await _contact_for_report(session, report)
    if contact is None:
        raise ApiError(404, "REPORTER_CONTACT_NOT_FOUND", "联系人快照不存在")
    allowed = False
    try:
        authorize_reveal(actor, payload.mfa_code)
        allowed = True
    finally:
        async with write_lock:
            try:
                await record_audit(
                    session,
                    actor=actor,
                    incident_id=incident.id,
                    action=(
                        "reporter_contact.reveal_succeeded"
                        if allowed
                        else "reporter_contact.reveal_denied"
                    ),
                    resource_type="reporter_contact",
                    resource_id=contact.id,
                    request_id=_request_id(request),
                    metadata={
                        "reason_code": payload.reason_code,
                        "ticket_ref": payload.ticket_ref,
                        "fields": payload.fields,
                    },
                )
                await session.commit()
            except Exception:
                await session.rollback()
                raise
    plain = serialize_contact_plain(contact)
    selected: dict[str, Any] = {}
    for field in payload.fields:
        if field == "full_name":
            selected["full_name"] = plain["full_name"]
        elif field == "mobile":
            selected["mobile"] = plain["mobile"]
        elif field == "national_id":
            selected["national_id"] = plain["additional_info"]["national_id"]
        elif field == "emergency_contact":
            selected["emergency_contact"] = plain["additional_info"]["emergency_contact"]
        elif field == "rescue_notes":
            selected["rescue_notes"] = plain["additional_info"]["rescue_notes"]
    response.headers["Cache-Control"] = "no-store"
    return success({"report_id": report.id, "reporter": selected}, request)


@router.patch("/reports/{report_id}/status")
async def patch_report_status(
    report_id: str,
    payload: ReportStatusPatch,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    if actor.role not in {"operator", "admin"}:
        raise ApiError(403, "FORBIDDEN", "operator or admin role required")
    async with write_lock:
        async with _write_transaction(session):
            report = await get_report(session, report_id)
            assert_report_access(actor, report, write=True)
            incident = await _incident_for_report(session, report)
            assert_incident_access(actor, incident, incident_header)
            if report.revision != payload.revision:
                _raise_revision_conflict(report, payload.revision)
            if payload.status == report.status:
                raise ApiError(422, "NO_CHANGES", "status is already set")
            if (
                report.status == "invalid"
                and payload.status == "acknowledged"
                and actor.role != "admin"
            ):
                raise ApiError(
                    403,
                    "ADMIN_REQUIRED",
                    "only an admin may restore an invalid report",
                )
            allowed_transitions = _ALLOWED_STATUS_TRANSITIONS.get(report.status, set())
            if payload.status not in allowed_transitions:
                raise ApiError(
                    409,
                    "INVALID_STATUS_TRANSITION",
                    f"cannot transition from {report.status} to {payload.status}",
                )
            before = report_snapshot(report)
            report.status = payload.status
            report.revision += 1
            report.updated_at = utcnow()
            if payload.status == "invalid":
                await deactivate_report_observation(
                    session,
                    incident=incident,
                    report=report,
                    actor=actor,
                    request_id=_request_id(request),
                    reason="source_report_invalid",
                )
            elif before["status"] == "invalid":
                await process_report_observation(
                    session,
                    incident=incident,
                    report=report,
                    actor=actor,
                    request_id=_request_id(request),
                )
            snapshot = report_snapshot(report)
            session.add(
                ReportRevision(
                    report_id=report.id,
                    revision=report.revision,
                    snapshot=snapshot,
                    changed_by_type=actor.subject_type,
                    changed_by_id=actor.subject_id,
                    change_reason=payload.note or "status_update",
                )
            )
            await upsert_report_map_feature(session, report)
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="report.status_updated",
                resource_type="report",
                resource_id=report.id,
                request_id=_request_id(request),
                before=before,
                after=snapshot,
                metadata={"note": payload.note},
            )
            attachments = (await attachments_by_report(session, [report.id])).get(report.id, [])
            event = await emit_event(
                session,
                incident=incident,
                event_type="report.status_changed",
                resource_type="report",
                resource_id=report.id,
                resource_revision=report.revision,
                visibility="owner",
                owner_device_id=report.reporter_device_id,
                payload=serialize_report(
                    report,
                    contact=await _contact_for_report(session, report),
                    attachments=attachments,
                ),
            )
            await enqueue_operator_notifications(
                session,
                incident=incident,
                business_event_id=str(event.payload["event_id"]),
                event_type="report.status_changed",
                priority=report.priority,
                resource_type="report",
                resource_id=report.id,
                resource_revision=report.revision,
                deep_link=f"crisismosaic://incidents/{incident.id}/reports/{report.id}",
                title="Crisis Mosaic 上报状态更新",
                body="一条现场上报状态已更新，请打开应用查看。",
            )
            contact = await _contact_for_report(session, report)
            return success(
                serialize_report(report, actor, contact=contact, attachments=attachments),
                request,
            )


@router.patch("/reports/{report_id}/priority")
async def patch_report_priority(
    report_id: str,
    payload: ReportPriorityPatch,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    if actor.role not in {"operator", "admin"}:
        raise ApiError(403, "FORBIDDEN", "operator or admin role required")
    async with write_lock:
        async with _write_transaction(session):
            report = await get_report(session, report_id)
            assert_report_access(actor, report, write=True)
            incident = await _incident_for_report(session, report)
            assert_incident_access(actor, incident, incident_header)
            if report.revision != payload.revision:
                _raise_revision_conflict(report, payload.revision)
            if report.is_urgent and payload.priority not in {None, "high"}:
                raise ApiError(
                    422,
                    "URGENT_PRIORITY_CANNOT_BE_DOWNGRADED",
                    "urgent reports must remain high priority",
                )
            before = report_snapshot(report)
            report.manual_priority = payload.priority
            final_attachment_ids = list(
                (
                    await session.scalars(
                        select(Attachment.id)
                        .where(Attachment.report_id == report.id)
                        .order_by(Attachment.id)
                    )
                ).all()
            )
            refinement = await validate_report_refinement(
                session,
                analysis_id=report.ai_refinement_id,
                incident_id=incident.id,
                actor=actor,
                category=report.category,
                content=report.content_original,
                location_text=report.location_text,
                attachment_ids=final_attachment_ids,
                bound_report_id=report.id,
                use_stored_report_context=True,
            )
            priority, source = effective_priority(
                report.category,
                is_urgent=report.is_urgent,
                manual_priority=payload.priority,
                ai_priority=ai_priority_from_refinement(refinement),
            )
            report.priority = priority
            report.priority_source = source
            report.revision += 1
            report.updated_at = utcnow()
            snapshot = report_snapshot(report)
            session.add(
                ReportRevision(
                    report_id=report.id,
                    revision=report.revision,
                    snapshot=snapshot,
                    changed_by_type=actor.subject_type,
                    changed_by_id=actor.subject_id,
                    change_reason=payload.note or "manual_priority",
                )
            )
            await upsert_report_map_feature(session, report)
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="report.priority_updated",
                resource_type="report",
                resource_id=report.id,
                request_id=_request_id(request),
                before=before,
                after=snapshot,
                metadata={"note": payload.note},
            )
            attachments = (await attachments_by_report(session, [report.id])).get(report.id, [])
            event = await emit_event(
                session,
                incident=incident,
                event_type="report.priority_updated",
                resource_type="report",
                resource_id=report.id,
                resource_revision=report.revision,
                visibility="owner",
                owner_device_id=report.reporter_device_id,
                payload=serialize_report(
                    report,
                    contact=await _contact_for_report(session, report),
                    attachments=attachments,
                ),
            )
            await enqueue_operator_notifications(
                session,
                incident=incident,
                business_event_id=str(event.payload["event_id"]),
                event_type="report.priority_updated",
                priority=report.priority,
                resource_type="report",
                resource_id=report.id,
                resource_revision=report.revision,
                deep_link=f"crisismosaic://incidents/{incident.id}/reports/{report.id}",
                title="Crisis Mosaic 优先级更新",
                body="一条现场上报优先级已更新，请打开应用查看。",
            )
            contact = await _contact_for_report(session, report)
            return success(
                serialize_report(report, actor, contact=contact, attachments=attachments),
                request,
            )
