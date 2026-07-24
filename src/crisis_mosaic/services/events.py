from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import AiAnalysis, AuditLog, Incident, OutboxEvent
from ..security import Actor
from ..utils import current_request_id, new_id, utcnow


async def record_audit(
    session: AsyncSession,
    *,
    actor: Actor | None,
    incident_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    request_id: str | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    row = AuditLog(
        actor_type=actor.subject_type if actor else "system",
        actor_id=actor.subject_id if actor else None,
        incident_id=incident_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        request_id=request_id or current_request_id.get(),
        details={
            "before": before,
            "after": after,
            "metadata": metadata or {},
        },
    )
    session.add(row)
    return row


async def emit_event(
    session: AsyncSession,
    *,
    incident: Incident,
    event_type: str,
    resource_type: str,
    resource_id: str | None,
    resource_revision: int | None,
    payload: dict[str, Any],
    visibility: str = "operators",
    owner_device_id: str | None = None,
    request_id: str | None = None,
) -> OutboxEvent:
    transaction = session.sync_session.get_transaction()
    transaction_key = (id(transaction), incident.id)
    incident.event_sequence += 1
    data_affecting = resource_type in {
        "incident",
        "report",
        "attachment",
        "blind_spot",
        "question",
        "directed_answer",
        "fragment",
        "conflict",
        "fact",
    }
    if data_affecting and session.info.get("data_revision_marker") != transaction_key:
        incident.data_revision += 1
        session.info["data_revision_marker"] = transaction_key
    map_bumped = False
    if (
        resource_type in {"report", "blind_spot", "fact", "conflict", "fragment"}
        and session.info.get("map_revision_marker") != transaction_key
    ):
        incident.map_revision += 1
        session.info["map_revision_marker"] = transaction_key
        map_bumped = True
    effective_request_id = request_id or current_request_id.get()
    envelope = {
        "event_id": new_id(),
        "type": event_type,
        "incident_id": incident.id,
        "sequence": incident.event_sequence,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "resource_revision": resource_revision,
        "occurred_at": utcnow().isoformat(),
        "visibility": visibility,
        "owner_device_id": owner_device_id,
        "request_id": effective_request_id,
        "data": payload,
        "payload": payload,
    }
    row = OutboxEvent(
        incident_id=incident.id,
        sequence=incident.event_sequence,
        event_type=event_type,
        visibility=visibility,
        resource_type=resource_type,
        owner_device_id=owner_device_id,
        resource_id=resource_id,
        resource_revision=resource_revision,
        actor_type=None,
        payload=envelope,
        request_id=effective_request_id,
    )
    session.add(row)
    if data_affecting:
        with session.no_autoflush:
            current_briefs = list(
                (
                    await session.scalars(
                        select(AiAnalysis).where(
                            AiAnalysis.incident_id == incident.id,
                            AiAnalysis.analysis_type == "command_brief",
                            AiAnalysis.status == "succeeded",
                            AiAnalysis.is_stale.is_(False),
                            AiAnalysis.input_version != incident.data_revision,
                        )
                    )
                ).all()
            )
        for analysis in current_briefs:
            analysis.is_stale = True
            analysis.stale_at = utcnow()
            analysis.stale_reason = f"incident_changed:{event_type}"
            incident.event_sequence += 1
            stale_envelope = {
                "event_id": new_id(),
                "type": "command_brief.stale",
                "incident_id": incident.id,
                "sequence": incident.event_sequence,
                "resource_type": "ai_analysis",
                "resource_id": analysis.id,
                "resource_revision": analysis.input_version,
                "occurred_at": utcnow().isoformat(),
                "visibility": "operators",
                "owner_device_id": None,
                "request_id": effective_request_id,
                "data": {
                    "analysis_id": analysis.id,
                    "reason": analysis.stale_reason,
                    "current_data_revision": incident.data_revision,
                },
                "payload": {
                    "analysis_id": analysis.id,
                    "reason": analysis.stale_reason,
                    "current_data_revision": incident.data_revision,
                },
            }
            session.add(
                OutboxEvent(
                    incident_id=incident.id,
                    sequence=incident.event_sequence,
                    event_type="command_brief.stale",
                    visibility="operators",
                    resource_type="ai_analysis",
                    owner_device_id=None,
                    resource_id=analysis.id,
                    resource_revision=analysis.input_version,
                    actor_type=None,
                    payload=stale_envelope,
                    request_id=effective_request_id,
                )
            )
    if map_bumped:
        incident.event_sequence += 1
        invalidated_envelope = {
            "event_id": new_id(),
            "type": "map_view.invalidated",
            "incident_id": incident.id,
            "sequence": incident.event_sequence,
            "resource_type": "map_view",
            "resource_id": incident.id,
            "resource_revision": incident.map_revision,
            "occurred_at": utcnow().isoformat(),
            "visibility": "public",
            "owner_device_id": None,
            "request_id": effective_request_id,
            "data": {"map_revision": incident.map_revision},
            "payload": {"map_revision": incident.map_revision},
        }
        session.add(
            OutboxEvent(
                incident_id=incident.id,
                sequence=incident.event_sequence,
                event_type="map_view.invalidated",
                visibility="public",
                resource_type="map_view",
                owner_device_id=None,
                resource_id=incident.id,
                resource_revision=incident.map_revision,
                actor_type=None,
                payload=invalidated_envelope,
                request_id=effective_request_id,
            )
        )
    return row
