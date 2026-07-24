from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, select

from ..config import get_settings
from ..db import write_lock
from ..dependencies import (
    ActorDep,
    IncidentHeader,
    SessionDep,
    ensure_incident_access,
    require_roles,
)
from ..domain.coordinates import normalize
from ..errors import ApiError, not_found
from ..models import (
    AiAnalysis,
    AuditLog,
    BlindSpot,
    ConflictCase,
    Incident,
    IncidentMembership,
    InformationFragment,
    Report,
)
from ..responses import page_meta, success
from ..schemas.admin import IncidentCreate, IncidentPatch
from ..security import Actor
from ..services.events import emit_event, record_audit
from ..utils import isoformat, utcnow

router = APIRouter(tags=["事件"])
OperatorActor = Annotated[Actor, Depends(require_roles("operator", "admin"))]
AdminActor = Annotated[Actor, Depends(require_roles("admin"))]


def incident_data(row: Incident) -> dict[str, object]:
    settings = get_settings()
    center_latitude = row.center_latitude or settings.map_default_latitude
    center_longitude = row.center_longitude or settings.map_default_longitude
    return {
        "id": row.id,
        "alias": row.alias,
        "name": row.name,
        "type": row.type,
        "status": row.status,
        "timezone": row.timezone,
        "started_at": isoformat(row.started_at),
        "closed_at": isoformat(row.closed_at),
        "feature_flags": row.feature_flags,
        "data_revision": row.data_revision,
        "map_revision": row.map_revision,
        "latest_sequence": row.event_sequence,
        "map": {
            "provider": "amap",
            "coordinate_system": row.map_coordinate_system,
            "default_center": {
                "latitude": center_latitude,
                "longitude": center_longitude,
            },
            "default_zoom": row.map_default_zoom,
            "enabled_layers": ["reports", "fragments", "conflicts", "blind_spots"],
        },
    }


@router.get("/incidents/current")
async def current_incident(
    request: Request,
    session: SessionDep,
    actor: ActorDep,
) -> dict[str, object]:
    rows = (
        await session.scalars(
            select(Incident).where(
                Incident.status == "active",
                Incident.id.in_(actor.incident_ids),
            )
        )
    ).all()
    if not rows:
        raise ApiError(404, "NO_ACTIVE_INCIDENT", "当前没有可访问的启用事件")
    return success(incident_data(rows[0]), request)


@router.get("/incidents")
async def list_incidents(
    request: Request,
    session: SessionDep,
    actor: OperatorActor,
) -> dict[str, object]:
    query = select(Incident).order_by(Incident.started_at.desc())
    if actor.role != "admin":
        query = query.where(Incident.id.in_(actor.incident_ids))
    rows = (await session.scalars(query)).all()
    return success([incident_data(row) for row in rows], request, meta={"total": len(rows)})


@router.post("/incidents", status_code=status.HTTP_201_CREATED)
async def create_incident(
    body: IncidentCreate,
    request: Request,
    session: SessionDep,
    actor: AdminActor,
) -> dict[str, object]:
    async with write_lock:
        if body.status == "active" and await session.scalar(
            select(Incident.id).where(Incident.status == "active")
        ):
            raise ApiError(409, "ACTIVE_INCIDENT_EXISTS", "已有启用事件")
        center_lat = body.center_latitude
        center_lon = body.center_longitude
        if center_lat is not None and center_lon is not None:
            coordinates = normalize(center_lat, center_lon, body.map_coordinate_system)
            if body.map_coordinate_system == "gcj02":
                center_lat, center_lon = (
                    coordinates.gcj02_latitude,
                    coordinates.gcj02_longitude,
                )
            else:
                center_lat, center_lon = (
                    coordinates.wgs84_latitude,
                    coordinates.wgs84_longitude,
                )
        row = Incident(
            alias=body.alias,
            name=body.name,
            type=body.type,
            status=body.status,
            center_latitude=center_lat,
            center_longitude=center_lon,
            map_coordinate_system=body.map_coordinate_system,
            map_default_zoom=body.map_default_zoom,
            timezone=body.timezone,
            started_at=body.started_at or utcnow(),
            feature_flags=body.feature_flags,
        )
        session.add(row)
        await session.flush()
        session.add(
            IncidentMembership(
                account_id=actor.subject_id,
                incident_id=row.id,
                role=actor.role,
            )
        )
        await record_audit(
            session,
            actor=actor,
            incident_id=row.id,
            action="incident.created",
            resource_type="incident",
            resource_id=row.id,
            request_id=request.state.request_id,
            after=incident_data(row),
        )
        await session.commit()
    return success(incident_data(row), request)


@router.patch("/incidents/{incident_id}")
async def patch_incident(
    incident_id: str,
    body: IncidentPatch,
    request: Request,
    session: SessionDep,
    actor: AdminActor,
    incident_header: IncidentHeader,
) -> dict[str, object]:
    async with write_lock:
        row = await session.get(Incident, incident_id)
        if row is None:
            raise not_found("事件")
        ensure_incident_access(actor, row.id, incident_header)
        if body.revision != row.data_revision:
            raise ApiError(
                409,
                "REVISION_CONFLICT",
                "事件版本已变化",
                details={"current_revision": row.data_revision},
            )
        if body.status == "active" and row.status != "active":
            existing = await session.scalar(
                select(Incident.id).where(Incident.status == "active", Incident.id != row.id)
            )
            if existing:
                raise ApiError(409, "ACTIVE_INCIDENT_EXISTS", "已有启用事件")
        before = incident_data(row)
        for field in ("name", "status", "feature_flags", "map_default_zoom"):
            value = getattr(body, field)
            if value is not None:
                setattr(row, field, value)
        if body.status == "closed":
            row.closed_at = utcnow()
        if (
            "center_latitude" in body.model_fields_set
            or "center_longitude" in body.model_fields_set
        ):
            if body.center_latitude is None or body.center_longitude is None:
                raise ApiError(422, "INVALID_LOCATION", "事件中心经纬度必须同时提交")
            coordinates = normalize(
                body.center_latitude,
                body.center_longitude,
                row.map_coordinate_system,
            )
            row.center_latitude = (
                coordinates.gcj02_latitude
                if row.map_coordinate_system == "gcj02"
                else coordinates.wgs84_latitude
            )
            row.center_longitude = (
                coordinates.gcj02_longitude
                if row.map_coordinate_system == "gcj02"
                else coordinates.wgs84_longitude
            )
        await emit_event(
            session,
            incident=row,
            event_type="incident.updated",
            resource_type="incident",
            resource_id=row.id,
            resource_revision=row.data_revision + 1,
            payload={"status": row.status},
            visibility="public",
        )
        await record_audit(
            session,
            actor=actor,
            incident_id=row.id,
            action="incident.updated",
            resource_type="incident",
            resource_id=row.id,
            request_id=request.state.request_id,
            before=before,
            after=incident_data(row),
        )
        await session.commit()
    return success(incident_data(row), request)


@router.get("/incidents/{incident_id}/command-overview")
async def command_overview(
    incident_id: str,
    request: Request,
    session: SessionDep,
    header_incident_id: IncidentHeader,
    actor: OperatorActor,
) -> dict[str, object]:
    ensure_incident_access(actor, incident_id, header_incident_id)
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise not_found("事件")
    priority_rows = (
        await session.execute(
            select(Report.priority, func.count(Report.id))
            .where(Report.incident_id == incident_id, Report.deleted_at.is_(None))
            .group_by(Report.priority)
        )
    ).all()
    counts = {key: value for key, value in priority_rows}
    fragments = (
        await session.scalars(
            select(InformationFragment)
            .where(InformationFragment.incident_id == incident_id)
            .order_by(InformationFragment.updated_at.desc())
            .limit(10)
        )
    ).all()
    urgent_reports = (
        await session.scalars(
            select(Report)
            .where(
                Report.incident_id == incident_id,
                Report.is_urgent.is_(True),
                Report.deleted_at.is_(None),
            )
            .order_by(Report.updated_at.desc())
            .limit(10)
        )
    ).all()
    open_conflicts = await session.scalar(
        select(func.count(ConflictCase.id)).where(
            ConflictCase.incident_id == incident_id,
            ConflictCase.status != "resolved",
        )
    )
    open_blind_spots = await session.scalar(
        select(func.count(BlindSpot.id)).where(
            BlindSpot.incident_id == incident_id,
            BlindSpot.status == "open",
        )
    )
    latest_brief = await session.scalar(
        select(AiAnalysis)
        .where(
            AiAnalysis.incident_id == incident_id,
            AiAnalysis.analysis_type == "command_brief",
            AiAnalysis.status == "succeeded",
            AiAnalysis.is_stale.is_(False),
            AiAnalysis.input_version == incident.data_revision,
        )
        .order_by(AiAnalysis.completed_at.desc())
        .limit(1)
    )
    data = {
        "incident": incident_data(incident),
        "fragment_count": await session.scalar(
            select(func.count(InformationFragment.id)).where(
                InformationFragment.incident_id == incident_id
            )
        ),
        "priority_counts": {
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
        },
        "open_conflict_count": open_conflicts or 0,
        "open_blind_spot_count": open_blind_spots or 0,
        "latest_fragments": [
            {
                "id": row.id,
                "topic": row.topic,
                "label": row.label,
                "description": row.description,
                "status": row.status,
                "revision": row.revision,
            }
            for row in fragments
        ],
        "urgent_reports": [
            {
                "id": row.id,
                "category": row.category,
                "content": row.content_display,
                "location_text": row.location_text,
                "revision": row.revision,
            }
            for row in urgent_reports
        ],
        "ai_command_brief": latest_brief.output if latest_brief else None,
        "as_of": isoformat(utcnow()),
        "realtime": {
            "url": "/api/v1/realtime",
            "latest_sequence": incident.event_sequence,
        },
    }
    return success(data, request)


@router.get("/incidents/{incident_id}/audit-logs")
async def audit_logs(
    incident_id: str,
    request: Request,
    session: SessionDep,
    header_incident_id: IncidentHeader,
    actor: OperatorActor,
    action: str | None = None,
    resource_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, object]:
    ensure_incident_access(actor, incident_id, header_incident_id)
    predicates = [AuditLog.incident_id == incident_id]
    if action:
        predicates.append(AuditLog.action == action)
    if resource_type:
        predicates.append(AuditLog.resource_type == resource_type)
    total = await session.scalar(select(func.count(AuditLog.id)).where(*predicates)) or 0
    rows = (
        await session.scalars(
            select(AuditLog)
            .where(*predicates)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    items = [
        {
            "id": row.id,
            "actor_type": row.actor_type,
            "actor_id": row.actor_id,
            "action": row.action,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "request_id": row.request_id,
            "details": row.details,
            "created_at": isoformat(row.created_at),
        }
        for row in rows
    ]
    return success(
        items,
        request,
        meta=page_meta(total=total, limit=limit, offset=offset),
    )
