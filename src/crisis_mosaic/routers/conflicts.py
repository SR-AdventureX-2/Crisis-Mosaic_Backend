from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import ValidationError
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import reset_transaction_for_write, write_lock
from ..dependencies import (
    ActorDep,
    IncidentHeader,
    SessionDep,
    ensure_incident_access,
    require_roles,
)
from ..domain.coordinates import normalize
from ..errors import ApiError, conflict, not_found
from ..models import (
    AiAnalysis,
    AuditLog,
    ConflictCase,
    ConflictDecision,
    ConflictEvidence,
    FactRecord,
    FactVersion,
    Incident,
)
from ..responses import page_meta, success
from ..schemas.conflicts import (
    AddConflictEvidence,
    ConflictCreate,
    ConflictDecisionRequest,
    ReopenConflict,
)
from ..schemas.incidents import BoundingBox
from ..security import Actor
from ..services.conflicts import (
    add_evidence,
    decide_conflict,
    mark_analyses_stale,
    mark_fact_under_review,
)
from ..services.events import emit_event, record_audit
from ..services.map_features import upsert_conflict_map_feature
from ..utils import as_utc, isoformat, utcnow

router = APIRouter()
OperatorDep = Annotated[Actor, Depends(require_roles("operator", "admin"))]


async def get_incident(session: AsyncSession, incident_id: str) -> Incident:
    incident = await session.get(Incident, incident_id)
    if incident is None:
        incident = await session.scalar(select(Incident).where(Incident.alias == incident_id))
    if incident is None:
        raise not_found("incident")
    return incident


async def get_case(session: AsyncSession, conflict_id: str) -> ConflictCase:
    item = await session.get(ConflictCase, conflict_id)
    if item is None:
        item = await session.scalar(select(ConflictCase).where(ConflictCase.alias == conflict_id))
    if item is None:
        raise not_found("conflict")
    return item


def evidence_data(item: ConflictEvidence) -> dict[str, Any]:
    return {
        "id": item.id,
        "kind": item.kind,
        "source_id": item.source_id,
        "source_revision": item.source_revision,
        "source_cluster_id": item.source_cluster_id,
        "snapshot": item.snapshot,
        "snapshot_sha256": item.snapshot_sha256,
        "is_current": item.is_current,
        "added_at": isoformat(item.added_at),
    }


def conflict_data(
    item: ConflictCase, evidence: list[ConflictEvidence] | None = None
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": item.id,
        "alias": item.alias,
        "incident_id": item.incident_id,
        "fact_key": item.fact_key,
        "title": item.title,
        "topic": item.topic,
        "location_text": item.location_text,
        "latitude": item.latitude,
        "longitude": item.longitude,
        "coordinate_system": item.coordinate_system,
        "status": item.status,
        "severity": item.severity,
        "detected_at": isoformat(item.detected_at),
        "resolved_at": isoformat(item.resolved_at),
        "resolution": item.resolution,
        "resolved_by": item.resolved_by,
        "revision": item.revision,
        "created_at": isoformat(item.created_at),
        "updated_at": isoformat(item.updated_at),
    }
    if evidence is not None:
        data["evidence"] = [evidence_data(value) for value in evidence]
    return data


async def current_evidence(session: AsyncSession, conflict_id: str) -> list[ConflictEvidence]:
    return list(
        (
            await session.scalars(
                select(ConflictEvidence)
                .where(
                    ConflictEvidence.conflict_id == conflict_id,
                    ConflictEvidence.is_current.is_(True),
                )
                .order_by(ConflictEvidence.added_at)
            )
        ).all()
    )


def fact_version_data(item: FactVersion) -> dict[str, Any]:
    return {
        "id": item.id,
        "fact_record_id": item.fact_record_id,
        "previous_version_id": item.previous_version_id,
        "revision": item.revision,
        "status": item.status,
        "statement": item.statement,
        "confidence": item.confidence,
        "source_conflict_id": item.source_conflict_id,
        "source_analysis_id": item.source_analysis_id,
        "context_snapshot": item.context_snapshot,
        "accepted_evidence_ids": item.accepted_evidence_ids,
        "decision_snapshot": item.decision_snapshot,
        "valid_from": isoformat(item.valid_from),
        "valid_to": isoformat(item.valid_to),
        "decided_by": item.decided_by,
        "created_at": isoformat(item.created_at),
    }


def _parse_fact_bbox(value: str | None) -> BoundingBox | None:
    if value is None:
        return None
    try:
        parts = [float(part.strip()) for part in value.split(",")]
        if len(parts) != 4:
            raise ValueError
        return BoundingBox(
            min_longitude=parts[0],
            min_latitude=parts[1],
            max_longitude=parts[2],
            max_latitude=parts[3],
        )
    except (ValueError, ValidationError) as exc:
        raise ApiError(
            422,
            "INVALID_BBOX",
            "bbox must be min_longitude,min_latitude,max_longitude,max_latitude",
        ) from exc


def _fact_position(
    item: FactRecord,
    coordinate_system: Literal["wgs84", "gcj02"],
) -> dict[str, float | str] | None:
    if (
        item.latitude is None
        or item.longitude is None
        or item.coordinate_system not in {"wgs84", "gcj02"}
    ):
        return None
    coordinates = normalize(item.latitude, item.longitude, item.coordinate_system)
    if coordinate_system == "wgs84":
        latitude = coordinates.wgs84_latitude
        longitude = coordinates.wgs84_longitude
    else:
        latitude = coordinates.gcj02_latitude
        longitude = coordinates.gcj02_longitude
    return {
        "latitude": latitude,
        "longitude": longitude,
        "coordinate_system": coordinate_system,
    }


def _encode_fact_cursor(item: FactRecord) -> str:
    raw = json.dumps(
        {"updated_at": isoformat(item.updated_at), "id": item.id},
        separators=(",", ":"),
    ).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_fact_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode())
        updated_at = datetime.fromisoformat(str(payload["updated_at"]).replace("Z", "+00:00"))
        fact_id = str(payload["id"])
        if not fact_id:
            raise ValueError
        return as_utc(updated_at), fact_id
    except (
        binascii.Error,
        UnicodeDecodeError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise ApiError(422, "INVALID_CURSOR", "cursor is invalid") from exc


def _after_fact_cursor(item: FactRecord, cursor_value: tuple[datetime, str]) -> bool:
    updated_at, fact_id = cursor_value
    item_key = (as_utc(item.updated_at), item.id)
    return item_key < (updated_at, fact_id)


def _in_fact_bbox(
    position: dict[str, float | str] | None,
    bbox: BoundingBox | None,
) -> bool:
    if bbox is None:
        return True
    if position is None:
        return False
    latitude = float(position["latitude"])
    longitude = float(position["longitude"])
    return (
        bbox.min_longitude <= longitude <= bbox.max_longitude
        and bbox.min_latitude <= latitude <= bbox.max_latitude
    )


def _evidence_brief(item: ConflictEvidence) -> dict[str, Any]:
    snapshot = item.snapshot or {}
    summary_value = next(
        (
            snapshot[key]
            for key in (
                "description",
                "answer_text",
                "content",
                "label",
                "claim_value",
            )
            if snapshot.get(key) not in {None, ""}
        ),
        None,
    )
    summary = str(summary_value)[:240] if summary_value is not None else None
    return {
        "evidence_id": item.id,
        "kind": item.kind,
        "source_id": item.source_id,
        "source_revision": item.source_revision,
        "claim_key": snapshot.get("claim_key"),
        "claim_value": snapshot.get("claim_value"),
        "summary": summary,
        "observed_at": snapshot.get("observed_at") or snapshot.get("received_at"),
        "is_current": item.is_current,
    }


async def _evidence_summary(
    session: AsyncSession,
    evidence_ids: list[str],
    *,
    include_references: bool,
) -> dict[str, Any]:
    if not evidence_ids:
        empty_data: dict[str, Any] = {"count": 0, "resolved_count": 0, "by_kind": {}}
        if include_references:
            empty_data["references"] = []
        return empty_data
    rows = list(
        (
            await session.scalars(
                select(ConflictEvidence).where(ConflictEvidence.id.in_(evidence_ids))
            )
        ).all()
    )
    by_id = {row.id: row for row in rows}
    ordered = [by_id[evidence_id] for evidence_id in evidence_ids if evidence_id in by_id]
    by_kind: dict[str, int] = {}
    for row in ordered:
        by_kind[row.kind] = by_kind.get(row.kind, 0) + 1
    data: dict[str, Any] = {
        "count": len(evidence_ids),
        "resolved_count": len(ordered),
        "by_kind": by_kind,
    }
    if include_references:
        data["references"] = [_evidence_brief(row) for row in ordered]
    return data


async def fact_data(
    session: AsyncSession,
    item: FactRecord,
    *,
    coordinate_system: Literal["wgs84", "gcj02"] = "gcj02",
    include_internal: bool = True,
    include_history: bool = False,
) -> dict[str, Any]:
    current = (
        await session.get(FactVersion, item.current_version_id) if item.current_version_id else None
    )
    position = _fact_position(item, coordinate_system)
    accepted_evidence_ids = list(current.accepted_evidence_ids or []) if current else []
    evidence_summary = await _evidence_summary(
        session,
        accepted_evidence_ids,
        include_references=include_internal,
    )
    source_analysis = (
        await session.get(AiAnalysis, current.source_analysis_id)
        if include_internal and current and current.source_analysis_id
        else None
    )
    data: dict[str, Any] = {
        "id": item.id,
        "incident_id": item.incident_id,
        "fact_key": item.fact_key,
        "topic": item.topic,
        "location_text": item.location_text,
        "latitude": position["latitude"] if position else None,
        "longitude": position["longitude"] if position else None,
        "coordinate_system": coordinate_system if position else None,
        "position": position,
        "status": item.status,
        "is_public": item.is_public,
        "revision": item.current_revision,
        "statement": current.statement if current else None,
        "confidence": current.confidence if current else None,
        "evidence_summary": evidence_summary,
        "valid_from": isoformat(current.valid_from) if current else None,
        "created_at": isoformat(item.created_at),
        "updated_at": isoformat(item.updated_at),
    }
    if include_internal:
        data.update(
            {
                "source_conflict_id": current.source_conflict_id if current else None,
                "source_analysis_id": current.source_analysis_id if current else None,
                "ai_analysis_reference": (
                    {
                        "id": source_analysis.id,
                        "status": source_analysis.status,
                        "is_stale": source_analysis.is_stale,
                        "input_version": source_analysis.input_version,
                        "completed_at": isoformat(source_analysis.completed_at),
                    }
                    if source_analysis
                    else None
                ),
                "accepted_evidence_ids": accepted_evidence_ids,
            }
        )
    if include_history:
        versions = (
            await session.scalars(
                select(FactVersion)
                .where(FactVersion.fact_record_id == item.id)
                .order_by(FactVersion.revision.desc())
            )
        ).all()
        data["versions"] = [fact_version_data(version) for version in versions]
    return data


def _decision_data(item: ConflictDecision) -> dict[str, Any]:
    return {
        "id": item.id,
        "conflict_id": item.conflict_id,
        "conflict_revision": item.conflict_revision,
        "analysis_id": item.analysis_id,
        "evidence_decisions": item.evidence_decisions,
        "conclusion": item.conclusion,
        "note": item.note,
        "decided_by": item.decided_by,
        "created_at": isoformat(item.created_at),
    }


def _related_analysis_data(item: AiAnalysis) -> dict[str, Any]:
    return {
        "id": item.id,
        "analysis_type": item.analysis_type,
        "status": item.status,
        "input_snapshot": item.input_snapshot,
        "context_package": item.context_package,
        "context_sha256": item.context_sha256,
        "output": item.output,
        "confidence": item.confidence,
        "model_provider": item.model_provider,
        "model_name": item.model_name,
        "prompt_version": item.prompt_version,
        "latency_ms": item.latency_ms,
        "input_version": item.input_version,
        "data_as_of": isoformat(item.data_as_of),
        "is_stale": item.is_stale,
        "stale_at": isoformat(item.stale_at),
        "stale_reason": item.stale_reason,
        "created_at": isoformat(item.created_at),
        "completed_at": isoformat(item.completed_at),
    }


def _audit_data(item: AuditLog) -> dict[str, Any]:
    return {
        "id": item.id,
        "actor_type": item.actor_type,
        "actor_id": item.actor_id,
        "action": item.action,
        "resource_type": item.resource_type,
        "resource_id": item.resource_id,
        "request_id": item.request_id,
        "details": item.details,
        "created_at": isoformat(item.created_at),
    }


async def _operator_fact_detail(
    session: AsyncSession,
    item: FactRecord,
    *,
    coordinate_system: Literal["wgs84", "gcj02"],
) -> dict[str, Any]:
    data = await fact_data(
        session,
        item,
        coordinate_system=coordinate_system,
        include_internal=True,
    )
    versions = list(
        (
            await session.scalars(
                select(FactVersion)
                .where(FactVersion.fact_record_id == item.id)
                .order_by(FactVersion.revision)
            )
        ).all()
    )
    conflict_ids = {
        version.source_conflict_id for version in versions if version.source_conflict_id
    }
    accepted_evidence_ids = {
        evidence_id for version in versions for evidence_id in (version.accepted_evidence_ids or [])
    }

    decisions: list[ConflictDecision] = []
    if conflict_ids:
        decisions = list(
            (
                await session.scalars(
                    select(ConflictDecision)
                    .where(ConflictDecision.conflict_id.in_(conflict_ids))
                    .order_by(ConflictDecision.created_at, ConflictDecision.id)
                )
            ).all()
        )

    analysis_ids = {
        version.source_analysis_id for version in versions if version.source_analysis_id
    }
    analysis_ids.update(
        decision.analysis_id for decision in decisions if decision.analysis_id is not None
    )
    candidate_analyses = list(
        (
            await session.scalars(
                select(AiAnalysis)
                .where(
                    AiAnalysis.incident_id == item.incident_id,
                    AiAnalysis.analysis_type == "conflict_analysis",
                )
                .order_by(AiAnalysis.created_at, AiAnalysis.id)
            )
        ).all()
    )
    analyses = [
        analysis
        for analysis in candidate_analyses
        if analysis.id in analysis_ids
        or str((analysis.input_snapshot or {}).get("conflict_id", "")) in conflict_ids
    ]
    analysis_ids.update(analysis.id for analysis in analyses)

    evidence: list[ConflictEvidence] = []
    if conflict_ids or accepted_evidence_ids:
        evidence_filters: list[Any] = []
        if conflict_ids:
            evidence_filters.append(ConflictEvidence.conflict_id.in_(conflict_ids))
        if accepted_evidence_ids:
            evidence_filters.append(ConflictEvidence.id.in_(accepted_evidence_ids))
        evidence = list(
            (
                await session.scalars(
                    select(ConflictEvidence)
                    .where(or_(*evidence_filters))
                    .order_by(ConflictEvidence.added_at, ConflictEvidence.id)
                )
            ).all()
        )

    related_resource_ids = {
        item.id,
        *conflict_ids,
        *(decision.id for decision in decisions),
        *analysis_ids,
    }
    audit_rows = list(
        (
            await session.scalars(
                select(AuditLog)
                .where(
                    AuditLog.incident_id == item.incident_id,
                    AuditLog.resource_id.in_(related_resource_ids),
                )
                .order_by(AuditLog.created_at, AuditLog.id)
                .limit(500)
            )
        ).all()
    )
    data.update(
        {
            "versions": [fact_version_data(version) for version in versions],
            "evidence_references": [evidence_data(row) for row in evidence],
            "decisions": [_decision_data(decision) for decision in decisions],
            "ai_analyses": [_related_analysis_data(analysis) for analysis in analyses],
            "audit": [_audit_data(row) for row in audit_rows],
        }
    )
    return data


@router.get(
    "/incidents/{incident_id}/conflicts",
    tags=["Conflicts & facts"],
)
async def list_conflicts(
    incident_id: str,
    request: Request,
    session: SessionDep,
    actor: OperatorDep,
    incident_header: IncidentHeader,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    ensure_incident_access(actor, incident_id, incident_header)
    filters = [ConflictCase.incident_id == incident_id]
    if status:
        filters.append(ConflictCase.status == status)
    total = await session.scalar(select(func.count(ConflictCase.id)).where(*filters))
    cases = (
        await session.scalars(
            select(ConflictCase)
            .where(*filters)
            .order_by(ConflictCase.updated_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    rows: list[dict[str, Any]] = []
    for item in cases:
        rows.append(conflict_data(item, await current_evidence(session, item.id)))
    return success(
        rows,
        request,
        meta=page_meta(
            total=int(total or 0),
            limit=limit,
            offset=offset,
            request=request,
        ),
    )


@router.get("/conflicts/{conflict_id}", tags=["Conflicts & facts"])
async def get_conflict(
    conflict_id: str,
    request: Request,
    session: SessionDep,
    actor: OperatorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    item = await get_case(session, conflict_id)
    ensure_incident_access(actor, item.incident_id, incident_header)
    evidence = await current_evidence(session, item.id)
    analyses = (
        await session.scalars(
            select(AiAnalysis)
            .where(
                AiAnalysis.incident_id == item.incident_id,
                AiAnalysis.analysis_type == "conflict_analysis",
                AiAnalysis.input_snapshot["conflict_id"].as_string() == item.id,
            )
            .order_by(AiAnalysis.created_at.desc())
        )
    ).all()
    data = conflict_data(item, evidence)
    data["analyses"] = [
        {
            "id": analysis.id,
            "status": analysis.status,
            "confidence": analysis.confidence,
            "output": analysis.output,
            "input_version": analysis.input_version,
            "is_stale": analysis.is_stale,
            "created_at": isoformat(analysis.created_at),
            "completed_at": isoformat(analysis.completed_at),
        }
        for analysis in analyses
    ]
    return success(data, request)


@router.post(
    "/incidents/{incident_id}/conflicts",
    status_code=201,
    tags=["Conflicts & facts"],
)
async def create_conflict(
    incident_id: str,
    payload: ConflictCreate,
    request: Request,
    session: SessionDep,
    actor: OperatorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    ensure_incident_access(actor, incident_id, incident_header)
    async with write_lock:
        await reset_transaction_for_write(session)
        try:
            incident = await get_incident(session, incident_id)
            item = ConflictCase(
                incident_id=incident.id,
                alias=payload.alias,
                fact_key=payload.fact_key,
                title=payload.title,
                topic=payload.topic,
                location_text=payload.location_text,
                latitude=payload.latitude,
                longitude=payload.longitude,
                coordinate_system=payload.coordinate_system,
                status="open",
                severity=payload.severity,
            )
            session.add(item)
            await session.flush()
            evidence = await add_evidence(session, item, payload.evidence)
            await upsert_conflict_map_feature(session, item)
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="conflict.created",
                resource_type="conflict",
                resource_id=item.id,
                request_id=getattr(request.state, "request_id", None),
                after=conflict_data(item, evidence),
            )
            await emit_event(
                session,
                incident=incident,
                event_type="conflict.opened",
                resource_type="conflict",
                resource_id=item.id,
                resource_revision=item.revision,
                payload={
                    "conflict_id": item.id,
                    "fact_key": item.fact_key,
                    "evidence_count": len(evidence),
                },
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(conflict_data(item, evidence), request)


@router.post(
    "/conflicts/{conflict_id}/evidence",
    tags=["Conflicts & facts"],
)
async def append_conflict_evidence(
    conflict_id: str,
    payload: AddConflictEvidence,
    request: Request,
    session: SessionDep,
    actor: OperatorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    async with write_lock:
        await reset_transaction_for_write(session)
        try:
            item = await get_case(session, conflict_id)
            ensure_incident_access(actor, item.incident_id, incident_header)
            if item.revision != payload.revision:
                raise conflict(
                    "REVISION_CONFLICT",
                    "conflict revision does not match",
                    {
                        "expected_revision": payload.revision,
                        "current_revision": item.revision,
                    },
                )
            incident = await get_incident(session, item.incident_id)
            added = await add_evidence(session, item, payload.evidence)
            item.revision += 1
            await mark_analyses_stale(session, item, "evidence_added")
            await upsert_conflict_map_feature(session, item)
            await record_audit(
                session,
                actor=actor,
                incident_id=item.incident_id,
                action="conflict.evidence_added",
                resource_type="conflict",
                resource_id=item.id,
                request_id=getattr(request.state, "request_id", None),
                after={
                    "revision": item.revision,
                    "evidence_ids": [evidence.id for evidence in added],
                },
            )
            await emit_event(
                session,
                incident=incident,
                event_type="conflict.updated",
                resource_type="conflict",
                resource_id=item.id,
                resource_revision=item.revision,
                payload={
                    "conflict_id": item.id,
                    "evidence_ids": [evidence.id for evidence in added],
                },
            )
            evidence = await current_evidence(session, item.id)
            await session.commit()
            response_data = conflict_data(item, evidence)
        except Exception:
            await session.rollback()
            raise
    return success(response_data, request)


@router.post(
    "/conflicts/{conflict_id}/reopen",
    tags=["Conflicts & facts"],
)
async def reopen_conflict(
    conflict_id: str,
    payload: ReopenConflict,
    request: Request,
    session: SessionDep,
    actor: OperatorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    async with write_lock:
        await reset_transaction_for_write(session)
        try:
            item = await get_case(session, conflict_id)
            ensure_incident_access(actor, item.incident_id, incident_header)
            if item.revision != payload.revision:
                raise conflict(
                    "REVISION_CONFLICT",
                    "conflict revision does not match",
                    {
                        "expected_revision": payload.revision,
                        "current_revision": item.revision,
                    },
                )
            if item.status != "resolved":
                raise conflict(
                    "CONFLICT_NOT_RESOLVED",
                    "only a resolved conflict can be reopened",
                )
            incident = await get_incident(session, item.incident_id)
            item.status = "reopened"
            item.resolved_at = None
            item.resolved_by = None
            item.resolution = None
            item.revision += 1
            fact = await mark_fact_under_review(session, item)
            await mark_analyses_stale(session, item, "conflict_reopened")
            await upsert_conflict_map_feature(session, item)
            await record_audit(
                session,
                actor=actor,
                incident_id=item.incident_id,
                action="conflict.reopened",
                resource_type="conflict",
                resource_id=item.id,
                request_id=getattr(request.state, "request_id", None),
                after={
                    "revision": item.revision,
                    "reason": payload.reason,
                    "fact_record_id": fact.id if fact else None,
                },
            )
            await emit_event(
                session,
                incident=incident,
                event_type="conflict.opened",
                resource_type="conflict",
                resource_id=item.id,
                resource_revision=item.revision,
                payload={
                    "conflict_id": item.id,
                    "reopened": True,
                    "reason": payload.reason,
                    "fact_record_id": fact.id if fact else None,
                },
            )
            if fact is not None:
                await emit_event(
                    session,
                    incident=incident,
                    event_type="fact_record.under_review",
                    resource_type="fact",
                    resource_id=fact.id,
                    resource_revision=fact.current_revision,
                    payload={"status": "under_review", "reason": payload.reason},
                )
            evidence = await current_evidence(session, item.id)
            await session.commit()
            response_data = conflict_data(item, evidence)
        except Exception:
            await session.rollback()
            raise
    return success(response_data, request)


@router.post(
    "/conflicts/{conflict_id}/decision",
    tags=["Conflicts & facts"],
)
async def submit_conflict_decision(
    conflict_id: str,
    payload: ConflictDecisionRequest,
    request: Request,
    session: SessionDep,
    actor: OperatorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    async with write_lock:
        await reset_transaction_for_write(session)
        try:
            item = await get_case(session, conflict_id)
            ensure_incident_access(actor, item.incident_id, incident_header)
            decision, fact, version, outbox_event_ids = await decide_conflict(
                session,
                case=item,
                payload=payload,
                actor=actor,
                request_id=getattr(request.state, "request_id", None),
            )
            evidence = await current_evidence(session, item.id)
            await session.commit()
            response_data = {
                "conflict": conflict_data(item, evidence),
                "decision_id": decision.id,
                "fact_record_id": fact.id,
                "fact_record_revision": version.revision,
                "outbox_event_ids": outbox_event_ids,
            }
        except Exception:
            await session.rollback()
            raise
    return success(response_data, request)


@router.get(
    "/incidents/{incident_id}/fact-records",
    tags=["Conflicts & facts"],
)
async def list_fact_records(
    incident_id: str,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
    status: str | None = None,
    topic: str | None = None,
    bbox: str | None = None,
    coordinate_system: Literal["wgs84", "gcj02"] = "gcj02",
    updated_after: datetime | None = None,
    cursor: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    ensure_incident_access(actor, incident_id, incident_header)
    parsed_bbox = _parse_fact_bbox(bbox)
    statuses = (
        [item.strip() for item in status.split(",") if item.strip()]
        if status
        else ["current", "under_review"]
    )
    supported_statuses = {"current", "under_review", "superseded", "revoked"}
    invalid_statuses = sorted(set(statuses) - supported_statuses)
    if not statuses or invalid_statuses:
        raise ApiError(
            422,
            "INVALID_FACT_STATUS",
            "status contains unsupported fact-record states",
            details={"invalid": invalid_statuses},
        )
    filters = [
        FactRecord.incident_id == incident_id,
        FactRecord.status.in_(statuses),
    ]
    if actor.is_resident:
        filters.append(FactRecord.is_public.is_(True))
        filters.append(FactRecord.status == "current")
    if topic:
        filters.append(FactRecord.topic == topic)
    if updated_after:
        filters.append(FactRecord.updated_at > as_utc(updated_after).replace(tzinfo=None))
    matching_items = list(
        (
            await session.scalars(
                select(FactRecord)
                .where(*filters)
                .order_by(FactRecord.updated_at.desc(), FactRecord.id.desc())
            )
        ).all()
    )
    positions = {item.id: _fact_position(item, coordinate_system) for item in matching_items}
    matching_items = [
        item for item in matching_items if _in_fact_bbox(positions[item.id], parsed_bbox)
    ]
    total = len(matching_items)
    if cursor:
        cursor_value = _decode_fact_cursor(cursor)
        matching_items = [item for item in matching_items if _after_fact_cursor(item, cursor_value)]
    page = matching_items[offset : offset + limit + 1]
    has_more = len(page) > limit
    items = page[:limit]
    next_cursor = _encode_fact_cursor(items[-1]) if has_more and items else None
    data = [
        await fact_data(
            session,
            item,
            coordinate_system=coordinate_system,
            include_internal=not actor.is_resident,
        )
        for item in items
    ]
    return success(
        data,
        request,
        meta={
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "next_cursor": next_cursor,
            "as_of": isoformat(utcnow()),
            "coordinate_system": coordinate_system,
        },
    )


@router.get("/fact-records/{fact_record_id}", tags=["Conflicts & facts"])
async def get_fact_record(
    fact_record_id: str,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
    coordinate_system: Literal["wgs84", "gcj02"] = "gcj02",
) -> dict[str, Any]:
    item = await session.get(FactRecord, fact_record_id)
    if item is None:
        raise not_found("fact record")
    ensure_incident_access(actor, item.incident_id, incident_header)
    if actor.is_resident and (not item.is_public or item.status != "current"):
        raise ApiError(403, "FACT_NOT_PUBLIC", "fact record is not public")
    if actor.is_resident:
        data = await fact_data(
            session,
            item,
            coordinate_system=coordinate_system,
            include_internal=False,
        )
    else:
        data = await _operator_fact_detail(
            session,
            item,
            coordinate_system=coordinate_system,
        )
    return success(
        data,
        request,
    )
