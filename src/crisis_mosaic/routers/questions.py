from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import reset_transaction_for_write, write_lock
from ..dependencies import (
    ActorDep,
    IncidentHeader,
    SessionDep,
    ensure_incident_access,
    require_roles,
)
from ..domain.coordinates import haversine_m, normalize
from ..errors import ApiError, conflict, not_found
from ..models import (
    AnonymousDevice,
    Attachment,
    BlindSpot,
    ConflictCase,
    ConflictEvidence,
    DirectedAnswer,
    DirectedAnswerRevision,
    DirectedQuestion,
    Incident,
    InformationFragment,
)
from ..responses import page_meta, success
from ..schemas.conflicts import EvidenceReference
from ..schemas.questions import (
    BlindSpotCreate,
    DirectedAnswerPut,
    DirectedQuestionCreate,
    FragmentCreate,
    QuestionMatchRequest,
    RevisionAction,
)
from ..security import Actor
from ..services.attachments import attachments_by_answer, serialize_attachment
from ..services.conflicts import (
    add_evidence,
    detect_structured_fragment_conflict,
    find_or_open_structured_conflict,
    mark_analyses_stale,
    valid_answer_consensus,
)
from ..services.events import emit_event, record_audit
from ..services.map_features import (
    upsert_blind_spot_map_feature,
    upsert_conflict_map_feature,
    upsert_fragment_map_feature,
)
from ..utils import as_utc, isoformat, utcnow

router = APIRouter()
OperatorDep = Annotated[Actor, Depends(require_roles("operator", "admin"))]


def blind_spot_data(item: BlindSpot) -> dict[str, Any]:
    return {
        "id": item.id,
        "incident_id": item.incident_id,
        "claim_key": item.claim_key,
        "title": item.title,
        "location_text": item.location_text,
        "latitude": item.latitude,
        "longitude": item.longitude,
        "coordinate_system": item.coordinate_system,
        "scope_type": item.scope_type,
        "scope_data": item.scope_data,
        "severity": item.severity,
        "route_impact_count": item.route_impact_count,
        "min_valid_answers": item.min_valid_answers,
        "status": item.status,
        "resolution_value": item.resolution_value,
        "revision": item.revision,
        "created_at": isoformat(item.created_at),
        "updated_at": isoformat(item.updated_at),
    }


def question_data(item: DirectedQuestion) -> dict[str, Any]:
    return {
        "id": item.id,
        "incident_id": item.incident_id,
        "blind_spot_id": item.blind_spot_id,
        "title": item.title,
        "location_text": item.location_text,
        "target_geometry": item.target_geometry,
        "route_impact_count": item.route_impact_count,
        "answer_type": item.answer_type,
        "options": item.options,
        "status": item.status,
        "expires_at": isoformat(item.expires_at),
        "revision": item.revision,
        "created_at": isoformat(item.created_at),
        "updated_at": isoformat(item.updated_at),
    }


def answer_data(
    item: DirectedAnswer,
    attachments: Sequence[Attachment] = (),
) -> dict[str, Any]:
    return {
        "id": item.id,
        "question_id": item.question_id,
        "option_id": item.option_id,
        "semantic_value": item.semantic_value,
        "answer_text": item.answer_text,
        "observed_latitude": item.observed_latitude,
        "observed_longitude": item.observed_longitude,
        "observed_coordinate_system": item.observed_coordinate_system,
        "attachment_ids": [attachment.id for attachment in attachments],
        "attachments": [serialize_attachment(attachment) for attachment in attachments],
        "revision": item.revision,
        "created_at": isoformat(item.created_at),
        "updated_at": isoformat(item.updated_at),
    }


async def replace_answer_attachments(
    session: AsyncSession,
    *,
    answer: DirectedAnswer,
    incident_id: str,
    uploader_device_id: str,
    attachment_ids: list[str],
) -> list[Attachment]:
    current = list(
        (
            await session.scalars(
                select(Attachment).where(Attachment.directed_answer_id == answer.id)
            )
        ).all()
    )
    requested: list[Attachment] = []
    if attachment_ids:
        rows = list(
            (
                await session.scalars(select(Attachment).where(Attachment.id.in_(attachment_ids)))
            ).all()
        )
        by_id = {attachment.id: attachment for attachment in rows}
        if len(by_id) != len(attachment_ids):
            raise ApiError(
                422,
                "ATTACHMENT_NOT_READY",
                "one or more attachments do not exist",
            )
        requested = [by_id[attachment_id] for attachment_id in attachment_ids]

    for attachment in requested:
        if (
            attachment.incident_id != incident_id
            or attachment.uploader_device_id != uploader_device_id
            or attachment.report_id is not None
            or attachment.directed_answer_id not in {None, answer.id}
            or attachment.metadata_status != "ready"
            or attachment.malware_scan_status not in {"clean", "fake_clean"}
        ):
            raise ApiError(
                422,
                "ATTACHMENT_NOT_READY",
                "attachment is not ready or is owned by another device",
            )

    requested_ids = set(attachment_ids)
    for attachment in current:
        if attachment.id not in requested_ids:
            attachment.directed_answer_id = None
    for attachment in requested:
        attachment.directed_answer_id = answer.id
    return requested


def _fragment_position(
    item: InformationFragment,
    coordinate_system: Literal["wgs84", "gcj02"] | None = None,
) -> tuple[float | None, float | None, str | None]:
    latitude = item.latitude
    longitude = item.longitude
    source_system = item.coordinate_system
    if coordinate_system is None or latitude is None or longitude is None or source_system is None:
        return latitude, longitude, source_system

    source_system = source_system.lower()
    if source_system == coordinate_system:
        return latitude, longitude, coordinate_system

    coordinates = normalize(latitude, longitude, source_system)
    if coordinate_system == "wgs84":
        return (
            coordinates.wgs84_latitude,
            coordinates.wgs84_longitude,
            coordinate_system,
        )
    return (
        coordinates.gcj02_latitude,
        coordinates.gcj02_longitude,
        coordinate_system,
    )


def fragment_data(
    item: InformationFragment,
    *,
    coordinate_system: Literal["wgs84", "gcj02"] | None = None,
) -> dict[str, Any]:
    latitude, longitude, response_coordinate_system = _fragment_position(
        item,
        coordinate_system,
    )
    return {
        "id": item.id,
        "incident_id": item.incident_id,
        "source_type": item.source_type,
        "source_ref_id": item.source_ref_id,
        "source_cluster_id": (
            None if item.source_type == "resident_report" else item.source_cluster_id
        ),
        "topic": item.topic,
        "claim_key": item.claim_key,
        "claim_value": item.claim_value,
        "label": item.label,
        "description": item.description,
        "location_text": item.location_text,
        "latitude": latitude,
        "longitude": longitude,
        "coordinate_system": response_coordinate_system,
        "shape": item.shape,
        "status": item.status,
        "confidence": item.confidence,
        "observed_at": isoformat(item.observed_at),
        "received_at": isoformat(item.received_at),
        "revision": item.revision,
        "created_at": isoformat(item.created_at),
        "updated_at": isoformat(item.updated_at),
    }


async def get_incident(session: AsyncSession, incident_id: str) -> Incident:
    incident = await session.get(Incident, incident_id)
    if incident is None:
        incident = await session.scalar(select(Incident).where(Incident.alias == incident_id))
    if incident is None:
        raise not_found("incident")
    return incident


def target_matches(
    question: DirectedQuestion,
    *,
    latitude: float | None,
    longitude: float | None,
    coordinate_system: str | None,
    region_code: str | None,
) -> bool:
    geometry = question.target_geometry or {}
    allowed_regions = geometry.get("region_codes")
    if allowed_regions and region_code not in allowed_regions:
        return False
    bbox = geometry.get("bbox")
    if bbox:
        if latitude is None or longitude is None or len(bbox) != 4:
            return False
        target_system = str(geometry.get("coordinate_system") or coordinate_system or "")
        if coordinate_system and target_system in {"wgs84", "gcj02"}:
            point = normalize(latitude, longitude, coordinate_system)
            if target_system == "wgs84":
                latitude, longitude = point.wgs84_latitude, point.wgs84_longitude
            else:
                latitude, longitude = point.gcj02_latitude, point.gcj02_longitude
        west, south, east, north = (float(value) for value in bbox)
        if not (west <= longitude <= east and south <= latitude <= north):
            return False
    center = geometry.get("center")
    if center is None and geometry.get("type") == "Point":
        coordinates = geometry.get("coordinates")
        if isinstance(coordinates, list) and len(coordinates) >= 2:
            center = {
                "longitude": coordinates[0],
                "latitude": coordinates[1],
                "coordinate_system": geometry.get("coordinate_system"),
            }
    radius_m = geometry.get("radius_m")
    if center is not None or radius_m is not None:
        if (
            latitude is None
            or longitude is None
            or coordinate_system is None
            or not isinstance(center, dict)
            or radius_m is None
        ):
            return False
        try:
            center_latitude = float(center["latitude"])
            center_longitude = float(center["longitude"])
            center_system = str(
                center.get("coordinate_system")
                or geometry.get("coordinate_system")
                or coordinate_system
            )
            point = normalize(latitude, longitude, coordinate_system)
            target = normalize(center_latitude, center_longitude, center_system)
            if haversine_m(
                point.wgs84_latitude,
                point.wgs84_longitude,
                target.wgs84_latitude,
                target.wgs84_longitude,
            ) > float(radius_m):
                return False
        except (KeyError, TypeError, ValueError):
            return False
    return True


@router.post(
    "/incidents/{incident_id}/blind-spots",
    status_code=201,
    tags=["Questions & blind spots"],
)
async def create_blind_spot(
    incident_id: str,
    payload: BlindSpotCreate,
    request: Request,
    session: SessionDep,
    actor: OperatorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    ensure_incident_access(actor, incident_id, incident_header)
    settings = get_settings()
    async with write_lock:
        await reset_transaction_for_write(session)
        try:
            incident = await get_incident(session, incident_id)
            item = BlindSpot(
                incident_id=incident.id,
                claim_key=payload.claim_key,
                title=payload.title,
                location_text=payload.location_text,
                latitude=payload.latitude,
                longitude=payload.longitude,
                coordinate_system=payload.coordinate_system,
                scope_type=payload.scope_type,
                scope_data=payload.scope_data,
                severity=payload.severity,
                route_impact_count=payload.route_impact_count,
                min_valid_answers=(
                    payload.min_valid_answers
                    if payload.min_valid_answers is not None
                    else settings.directed_min_valid_answers
                ),
            )
            session.add(item)
            await session.flush()
            await upsert_blind_spot_map_feature(session, item)
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="blind_spot.created",
                resource_type="blind_spot",
                resource_id=item.id,
                request_id=getattr(request.state, "request_id", None),
                after=blind_spot_data(item),
            )
            await emit_event(
                session,
                incident=incident,
                event_type="blind_spot.created",
                resource_type="blind_spot",
                resource_id=item.id,
                resource_revision=item.revision,
                payload=blind_spot_data(item),
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(blind_spot_data(item), request)


@router.get(
    "/incidents/{incident_id}/blind-spots",
    tags=["Questions & blind spots"],
)
async def list_blind_spots(
    incident_id: str,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
    status: str | None = None,
) -> dict[str, Any]:
    ensure_incident_access(actor, incident_id, incident_header)
    statement = select(BlindSpot).where(BlindSpot.incident_id == incident_id)
    if status:
        statement = statement.where(BlindSpot.status == status)
    items = (await session.scalars(statement.order_by(BlindSpot.created_at.desc()))).all()
    return success([blind_spot_data(item) for item in items], request)


@router.post(
    "/incidents/{incident_id}/directed-questions",
    status_code=201,
    tags=["Questions & blind spots"],
)
async def create_question(
    incident_id: str,
    payload: DirectedQuestionCreate,
    request: Request,
    session: SessionDep,
    actor: OperatorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    ensure_incident_access(actor, incident_id, incident_header)
    expires_at = payload.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=utcnow().tzinfo)
    if expires_at is not None and expires_at <= utcnow():
        raise ApiError(422, "INVALID_EXPIRY", "expires_at must be in the future")
    async with write_lock:
        await reset_transaction_for_write(session)
        try:
            incident = await get_incident(session, incident_id)
            blind = await session.get(BlindSpot, payload.blind_spot_id)
            if blind is None or blind.incident_id != incident.id:
                raise not_found("blind spot")
            item = DirectedQuestion(
                incident_id=incident.id,
                blind_spot_id=blind.id,
                title=payload.title,
                location_text=payload.location_text,
                target_geometry=payload.target_geometry,
                route_impact_count=payload.route_impact_count,
                answer_type=payload.answer_type,
                options=[option.model_dump(mode="json") for option in payload.options],
                status="draft",
                expires_at=expires_at,
                created_by=actor.subject_id,
            )
            session.add(item)
            await session.flush()
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="question.created",
                resource_type="question",
                resource_id=item.id,
                request_id=getattr(request.state, "request_id", None),
                after=question_data(item),
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(question_data(item), request)


@router.get(
    "/incidents/{incident_id}/directed-questions",
    tags=["Questions & blind spots"],
)
async def list_questions(
    incident_id: str,
    request: Request,
    session: SessionDep,
    actor: OperatorDep,
    incident_header: IncidentHeader,
    status: str | None = None,
) -> dict[str, Any]:
    ensure_incident_access(actor, incident_id, incident_header)
    statement = select(DirectedQuestion).where(DirectedQuestion.incident_id == incident_id)
    if status:
        statement = statement.where(DirectedQuestion.status == status)
    items = (await session.scalars(statement.order_by(DirectedQuestion.created_at.desc()))).all()
    return success([question_data(item) for item in items], request)


async def change_question_status(
    *,
    question_id: str,
    payload: RevisionAction,
    target_status: str,
    request: Request,
    session: AsyncSession,
    actor: Actor,
    incident_header: str | None,
) -> dict[str, Any]:
    async with write_lock:
        await reset_transaction_for_write(session)
        try:
            item = await session.get(DirectedQuestion, question_id)
            if item is None:
                raise not_found("question")
            ensure_incident_access(actor, item.incident_id, incident_header)
            if item.revision != payload.revision:
                raise conflict(
                    "REVISION_CONFLICT",
                    "question revision does not match",
                    {
                        "expected_revision": payload.revision,
                        "current_revision": item.revision,
                    },
                )
            if target_status == "published" and item.expires_at is not None:
                expires_at = item.expires_at
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=utcnow().tzinfo)
                if expires_at <= utcnow():
                    raise ApiError(
                        422,
                        "QUESTION_EXPIRED",
                        "expired question cannot be published",
                    )
            incident = await get_incident(session, item.incident_id)
            before = question_data(item)
            item.status = target_status
            item.revision += 1
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action=f"question.{target_status}",
                resource_type="question",
                resource_id=item.id,
                request_id=getattr(request.state, "request_id", None),
                before=before,
                after=question_data(item),
            )
            await emit_event(
                session,
                incident=incident,
                event_type=f"question.{target_status}",
                resource_type="question",
                resource_id=item.id,
                resource_revision=item.revision,
                payload=question_data(item),
                visibility="public",
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(question_data(item), request)


@router.post(
    "/directed-questions/{question_id}/publish",
    tags=["Questions & blind spots"],
)
async def publish_question(
    question_id: str,
    payload: RevisionAction,
    request: Request,
    session: SessionDep,
    actor: OperatorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    return await change_question_status(
        question_id=question_id,
        payload=payload,
        target_status="published",
        request=request,
        session=session,
        actor=actor,
        incident_header=incident_header,
    )


@router.post(
    "/directed-questions/{question_id}/close",
    tags=["Questions & blind spots"],
)
async def close_question(
    question_id: str,
    payload: RevisionAction,
    request: Request,
    session: SessionDep,
    actor: OperatorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    return await change_question_status(
        question_id=question_id,
        payload=payload,
        target_status="closed",
        request=request,
        session=session,
        actor=actor,
        incident_header=incident_header,
    )


async def matching_questions(
    session: AsyncSession,
    incident_id: str,
    *,
    latitude: float | None,
    longitude: float | None,
    coordinate_system: str | None,
    region_code: str | None,
) -> list[DirectedQuestion]:
    now = utcnow()
    candidates = (
        await session.scalars(
            select(DirectedQuestion)
            .where(
                DirectedQuestion.incident_id == incident_id,
                DirectedQuestion.status == "published",
            )
            .order_by(DirectedQuestion.created_at.desc())
        )
    ).all()
    result: list[DirectedQuestion] = []
    for item in candidates:
        expires_at = item.expires_at
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=now.tzinfo)
        if expires_at is not None and expires_at <= now:
            continue
        if target_matches(
            item,
            latitude=latitude,
            longitude=longitude,
            coordinate_system=coordinate_system,
            region_code=region_code,
        ):
            result.append(item)
    return result


@router.get(
    "/incidents/{incident_id}/directed-questions/active",
    tags=["Questions & blind spots"],
)
async def active_questions(
    incident_id: str,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
    latitude: float | None = Query(default=None, ge=-90, le=90),
    longitude: float | None = Query(default=None, ge=-180, le=180),
    coordinate_system: Literal["wgs84", "gcj02"] | None = None,
    region_code: str | None = Query(default=None, max_length=40),
) -> dict[str, Any]:
    ensure_incident_access(actor, incident_id, incident_header)
    items = await matching_questions(
        session,
        incident_id,
        latitude=latitude,
        longitude=longitude,
        coordinate_system=coordinate_system,
        region_code=region_code,
    )
    data = [question_data(item) for item in items]
    if actor.is_resident and items:
        answers = list(
            (
                await session.scalars(
                    select(DirectedAnswer).where(
                        DirectedAnswer.question_id.in_([item.id for item in items]),
                        DirectedAnswer.device_id == actor.subject_id,
                    )
                )
            ).all()
        )
        answers_by_question = {answer.question_id: answer for answer in answers}
        attachment_map = await attachments_by_answer(session, [answer.id for answer in answers])
        for question, item_data in zip(items, data, strict=True):
            answer = answers_by_question.get(question.id)
            item_data["my_answer"] = None
            if answer is not None:
                item_data["my_answer"] = answer_data(
                    answer,
                    attachment_map.get(answer.id, []),
                )
    return success(data, request)


@router.post(
    "/incidents/{incident_id}/directed-questions/match",
    tags=["Questions & blind spots"],
)
async def match_questions(
    incident_id: str,
    payload: QuestionMatchRequest,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    ensure_incident_access(actor, incident_id, incident_header)
    items = await matching_questions(
        session,
        incident_id,
        latitude=payload.latitude,
        longitude=payload.longitude,
        coordinate_system=payload.coordinate_system,
        region_code=payload.region_code,
    )
    return success([question_data(item) for item in items], request)


@router.put(
    "/directed-questions/{question_id}/my-answer",
    tags=["Questions & blind spots"],
)
async def put_my_answer(
    question_id: str,
    payload: DirectedAnswerPut,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    if not actor.is_resident:
        raise ApiError(403, "RESIDENT_REQUIRED", "only resident devices can answer")
    async with write_lock:
        await reset_transaction_for_write(session)
        try:
            question = await session.get(DirectedQuestion, question_id)
            if question is None:
                raise not_found("question")
            ensure_incident_access(actor, question.incident_id, incident_header)
            if question.status != "published":
                raise conflict("QUESTION_NOT_ACTIVE", "question is not active")
            if question.expires_at is not None:
                expires_at = question.expires_at
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=utcnow().tzinfo)
                if expires_at <= utcnow():
                    raise conflict("QUESTION_EXPIRED", "question has expired")
            device = await session.get(AnonymousDevice, actor.subject_id)
            if device is None:
                raise ApiError(401, "INVALID_ACCESS_TOKEN", "匿名设备不存在")
            if not target_matches(
                question,
                latitude=payload.latitude,
                longitude=payload.longitude,
                coordinate_system=payload.coordinate_system,
                region_code=device.region_code,
            ):
                raise ApiError(
                    403,
                    "QUESTION_TARGET_MISMATCH",
                    "设备位置不在问题目标范围内",
                )
            option = next(
                (item for item in question.options if str(item.get("id")) == payload.option_id),
                None,
            )
            if option is None:
                raise ApiError(422, "INVALID_QUESTION_OPTION", "option is not defined")
            semantic_value = str(option.get("semantic_value") or option["id"])
            answer_text = payload.answer_text or str(option.get("label") or semantic_value)
            incident = await get_incident(session, question.incident_id)
            blind = await session.get(BlindSpot, question.blind_spot_id)
            if blind is None:
                raise not_found("blind spot")
            answer = await session.scalar(
                select(DirectedAnswer).where(
                    DirectedAnswer.question_id == question.id,
                    DirectedAnswer.device_id == actor.subject_id,
                )
            )
            created = answer is None
            if answer is None:
                if payload.revision != 0:
                    raise conflict(
                        "REVISION_CONFLICT",
                        "answer does not exist",
                        {"current_revision": 0},
                    )
                answer = DirectedAnswer(
                    question_id=question.id,
                    device_id=actor.subject_id,
                    option_id=payload.option_id,
                    semantic_value=semantic_value,
                    answer_text=answer_text,
                    observed_latitude=payload.latitude,
                    observed_longitude=payload.longitude,
                    observed_coordinate_system=payload.coordinate_system,
                    revision=1,
                )
                session.add(answer)
                await session.flush()
            else:
                if answer.revision != payload.revision:
                    raise conflict(
                        "REVISION_CONFLICT",
                        "answer revision does not match",
                        {"current_revision": answer.revision},
                    )
                answer.revision += 1
                answer.option_id = payload.option_id
                answer.semantic_value = semantic_value
                answer.answer_text = answer_text
                answer.observed_latitude = payload.latitude
                answer.observed_longitude = payload.longitude
                answer.observed_coordinate_system = payload.coordinate_system
            answer_attachments = await replace_answer_attachments(
                session,
                answer=answer,
                incident_id=question.incident_id,
                uploader_device_id=actor.subject_id,
                attachment_ids=payload.attachment_ids,
            )
            session.add(
                DirectedAnswerRevision(
                    answer_id=answer.id,
                    revision=answer.revision,
                    snapshot=answer_data(answer, answer_attachments),
                )
            )
            fragment = await session.scalar(
                select(InformationFragment).where(
                    InformationFragment.source_type == "directed_answer",
                    InformationFragment.source_ref_id == answer.id,
                )
            )
            if fragment is None:
                fragment = InformationFragment(
                    incident_id=incident.id,
                    source_type="directed_answer",
                    source_ref_id=answer.id,
                    topic=blind.claim_key,
                    claim_key=blind.claim_key,
                    claim_value=semantic_value,
                    label=answer_text,
                    description=f"{question.title}: {answer_text}",
                    location_text=question.location_text,
                    latitude=payload.latitude if payload.latitude is not None else blind.latitude,
                    longitude=payload.longitude
                    if payload.longitude is not None
                    else blind.longitude,
                    coordinate_system=payload.coordinate_system or blind.coordinate_system,
                    status="normal",
                    confidence=0.6,
                    observed_at=utcnow(),
                )
                session.add(fragment)
                await session.flush()
            else:
                fragment.claim_value = semantic_value
                fragment.label = answer_text
                fragment.description = f"{question.title}: {answer_text}"
                fragment.latitude = (
                    payload.latitude if payload.latitude is not None else fragment.latitude
                )
                fragment.longitude = (
                    payload.longitude if payload.longitude is not None else fragment.longitude
                )
                fragment.coordinate_system = payload.coordinate_system or fragment.coordinate_system
                fragment.revision += 1
            consensus_value, consensus_count, distinct_values = await valid_answer_consensus(
                session, question.id
            )
            blind_changed = False
            conflict_case = None
            if len(distinct_values) <= 1 and not created:
                conflict_case = await session.scalar(
                    select(ConflictCase)
                    .join(
                        ConflictEvidence,
                        ConflictEvidence.conflict_id == ConflictCase.id,
                    )
                    .where(
                        ConflictCase.incident_id == incident.id,
                        ConflictEvidence.kind == "fragment",
                        ConflictEvidence.source_id == fragment.id,
                    )
                    .order_by(ConflictCase.created_at.desc())
                )
                if conflict_case is not None:
                    await add_evidence(
                        session,
                        conflict_case,
                        [
                            EvidenceReference(
                                kind="fragment",
                                source_id=fragment.id,
                                source_revision=fragment.revision,
                            )
                        ],
                    )
                    conflict_case.revision += 1
                    await mark_analyses_stale(
                        session,
                        conflict_case,
                        "directed_answer_updated",
                    )
                    await emit_event(
                        session,
                        incident=incident,
                        event_type="conflict.updated",
                        resource_type="conflict",
                        resource_id=conflict_case.id,
                        resource_revision=conflict_case.revision,
                        payload={
                            "conflict_id": conflict_case.id,
                            "fact_key": conflict_case.fact_key,
                        },
                    )
            if len(distinct_values) > 1:
                current_answers = (
                    await session.scalars(
                        select(DirectedAnswer).where(
                            DirectedAnswer.question_id == question.id,
                            DirectedAnswer.semantic_value != "unknown",
                        )
                    )
                ).all()
                answer_ids = [item.id for item in current_answers]
                fragments = (
                    await session.scalars(
                        select(InformationFragment).where(
                            InformationFragment.source_type == "directed_answer",
                            InformationFragment.source_ref_id.in_(answer_ids),
                        )
                    )
                ).all()
                conflict_case, opened = await find_or_open_structured_conflict(
                    session,
                    incident_id=incident.id,
                    fact_key=blind.claim_key,
                    title=f"{blind.title} information conflict",
                    topic=blind.claim_key,
                    location_text=blind.location_text,
                    latitude=blind.latitude,
                    longitude=blind.longitude,
                    coordinate_system=blind.coordinate_system,
                    fragments=list(fragments),
                )
                if blind.status == "resolved":
                    blind.status = "open"
                    blind.resolution_value = None
                    blind.revision += 1
                    blind_changed = True
                if opened:
                    await emit_event(
                        session,
                        incident=incident,
                        event_type="conflict.opened",
                        resource_type="conflict",
                        resource_id=conflict_case.id,
                        resource_revision=conflict_case.revision,
                        payload={
                            "conflict_id": conflict_case.id,
                            "fact_key": conflict_case.fact_key,
                        },
                    )
            elif consensus_value is not None and consensus_count >= blind.min_valid_answers:
                if blind.status != "resolved" or blind.resolution_value != consensus_value:
                    blind.status = "resolved"
                    blind.resolution_value = consensus_value
                    blind.revision += 1
                    blind_changed = True
                fragment.status = "resolved"
            elif blind.status == "resolved":
                blind.status = "open"
                blind.resolution_value = None
                blind.revision += 1
                question.status = "published"
                question.revision += 1
                blind_changed = True
            await upsert_fragment_map_feature(session, fragment)
            await upsert_blind_spot_map_feature(session, blind)
            if conflict_case is not None:
                await upsert_conflict_map_feature(session, conflict_case)
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="directed_answer.created" if created else "directed_answer.updated",
                resource_type="directed_answer",
                resource_id=answer.id,
                request_id=getattr(request.state, "request_id", None),
                after={
                    "answer": answer_data(answer, answer_attachments),
                    "fragment_id": fragment.id,
                    "blind_spot_status": blind.status,
                },
            )
            await emit_event(
                session,
                incident=incident,
                event_type=("directed_answer.created" if created else "directed_answer.updated"),
                resource_type="directed_answer",
                resource_id=answer.id,
                resource_revision=answer.revision,
                visibility="owner",
                owner_device_id=actor.subject_id,
                payload={
                    "question_id": question.id,
                    "answer_id": answer.id,
                    "fragment_id": fragment.id,
                },
            )
            await emit_event(
                session,
                incident=incident,
                event_type="fragment.created" if created else "fragment.updated",
                resource_type="fragment",
                resource_id=fragment.id,
                resource_revision=fragment.revision,
                payload=fragment_data(fragment),
            )
            if blind_changed:
                await emit_event(
                    session,
                    incident=incident,
                    event_type=(
                        "blind_spot.resolved"
                        if blind.status == "resolved"
                        else "blind_spot.reopened"
                    ),
                    resource_type="blind_spot",
                    resource_id=blind.id,
                    resource_revision=blind.revision,
                    payload=blind_spot_data(blind),
                    visibility="public",
                )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(
        {
            "answer": answer_data(answer, answer_attachments),
            "fragment": fragment_data(fragment),
            "blind_spot": blind_spot_data(blind),
            "conflict_id": conflict_case.id if conflict_case else None,
        },
        request,
    )


@router.post(
    "/incidents/{incident_id}/fragments",
    status_code=201,
    tags=["Questions & blind spots"],
)
async def create_fragment(
    incident_id: str,
    payload: FragmentCreate,
    request: Request,
    session: SessionDep,
    actor: OperatorDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    ensure_incident_access(actor, incident_id, incident_header)
    detected_conflict = None
    async with write_lock:
        await reset_transaction_for_write(session)
        try:
            incident = await get_incident(session, incident_id)
            item = InformationFragment(
                incident_id=incident.id,
                source_type="operator",
                source_ref_id=actor.subject_id,
                topic=payload.topic,
                claim_key=payload.claim_key,
                claim_value=payload.claim_value,
                label=payload.label,
                description=payload.description,
                location_text=payload.location_text,
                latitude=payload.latitude,
                longitude=payload.longitude,
                coordinate_system=payload.coordinate_system,
                status="normal",
                confidence=payload.confidence,
                observed_at=payload.observed_at,
            )
            session.add(item)
            await session.flush()
            conflict_result = await detect_structured_fragment_conflict(session, item)
            if conflict_result is not None:
                detected_conflict, opened = conflict_result
                await emit_event(
                    session,
                    incident=incident,
                    event_type="conflict.opened" if opened else "conflict.updated",
                    resource_type="conflict",
                    resource_id=detected_conflict.id,
                    resource_revision=detected_conflict.revision,
                    payload={
                        "conflict_id": detected_conflict.id,
                        "fact_key": detected_conflict.fact_key,
                    },
                )
                await upsert_conflict_map_feature(session, detected_conflict)
            await upsert_fragment_map_feature(session, item)
            await emit_event(
                session,
                incident=incident,
                event_type="fragment.created",
                resource_type="fragment",
                resource_id=item.id,
                resource_revision=item.revision,
                payload=fragment_data(item),
            )
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="fragment.created",
                resource_type="fragment",
                resource_id=item.id,
                request_id=getattr(request.state, "request_id", None),
                after=fragment_data(item),
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    data = fragment_data(item)
    data["conflict_id"] = detected_conflict.id if detected_conflict else None
    return success(data, request)


@router.get(
    "/incidents/{incident_id}/fragments",
    tags=["Questions & blind spots"],
)
async def list_fragments(
    incident_id: str,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
    status: str | None = None,
    updated_after: datetime | None = None,
    coordinate_system: Literal["wgs84", "gcj02"] = Query(default="gcj02"),
    west: float | None = Query(default=None, ge=-180, le=180),
    south: float | None = Query(default=None, ge=-90, le=90),
    east: float | None = Query(default=None, ge=-180, le=180),
    north: float | None = Query(default=None, ge=-90, le=90),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    ensure_incident_access(actor, incident_id, incident_header)
    filters = [InformationFragment.incident_id == incident_id]
    if actor.is_resident:
        filters.append(InformationFragment.source_type != "resident_report")
    if status:
        filters.append(InformationFragment.status == status)
    else:
        filters.append(InformationFragment.status != "withdrawn")
    if updated_after:
        filters.append(InformationFragment.updated_at > as_utc(updated_after).replace(tzinfo=None))
    supplied_bbox = [west, south, east, north]
    bbox: tuple[float, float, float, float] | None = None
    if any(value is not None for value in supplied_bbox):
        if not all(value is not None for value in supplied_bbox):
            raise ApiError(422, "INVALID_BBOX", "all bbox coordinates are required")
        assert west is not None
        assert south is not None
        assert east is not None
        assert north is not None
        if west > east or south > north:
            raise ApiError(422, "INVALID_BBOX", "bbox bounds are reversed")
        bbox = (west, south, east, north)

    statement = (
        select(InformationFragment)
        .where(*filters)
        .order_by(InformationFragment.updated_at.desc(), InformationFragment.id.desc())
    )
    if bbox is None:
        total = int(
            await session.scalar(select(func.count(InformationFragment.id)).where(*filters)) or 0
        )
        items = (await session.scalars(statement.limit(limit).offset(offset))).all()
    else:
        matching_items: list[InformationFragment] = []
        for item in (await session.scalars(statement)).all():
            latitude, longitude, _ = _fragment_position(item, coordinate_system)
            if latitude is None or longitude is None:
                continue
            if bbox[0] <= longitude <= bbox[2] and bbox[1] <= latitude <= bbox[3]:
                matching_items.append(item)
        total = len(matching_items)
        items = matching_items[offset : offset + limit]

    return success(
        [fragment_data(item, coordinate_system=coordinate_system) for item in items],
        request,
        meta=page_meta(
            total=int(total or 0),
            limit=limit,
            offset=offset,
            request=request,
        ),
    )
