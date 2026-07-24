from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request, status

from ..db import write_lock
from ..dependencies import ActorDep, IncidentHeader, SessionDep, ensure_incident_access
from ..errors import ApiError
from ..models import Incident, NotificationOutbox
from ..responses import success
from ..schemas.notifications import (
    NotificationPreferencePatch,
    NotificationReceiptCreate,
    PushDeviceRegistration,
)
from ..services.events import record_audit
from ..services.notifications import (
    get_preference,
    list_push_devices,
    patch_preference,
    record_notification_receipt,
    register_push_device,
    revoke_push_device,
    serialize_preference,
    serialize_push_device,
)

router = APIRouter(tags=["Notifications"])


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


async def _incident(session: SessionDep, incident_id: str) -> Incident:
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise ApiError(404, "INCIDENT_NOT_FOUND", "事件不存在")
    return incident


@router.post("/me/push-devices", status_code=status.HTTP_201_CREATED)
async def post_my_push_device(
    payload: PushDeviceRegistration,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
) -> dict[str, Any]:
    async with write_lock:
        try:
            device = await register_push_device(session, actor=actor, payload=payload)
            await record_audit(
                session,
                actor=actor,
                incident_id=None,
                action="push_device.registered",
                resource_type="push_device",
                resource_id=device.id,
                request_id=_request_id(request),
                after={
                    "provider": device.provider,
                    "platform": device.platform,
                    "token_fingerprint": device.token_fingerprint,
                    "status": device.status,
                },
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(serialize_push_device(device), request)


@router.get("/me/push-devices")
async def get_my_push_devices(
    request: Request,
    actor: ActorDep,
    session: SessionDep,
) -> dict[str, Any]:
    devices = await list_push_devices(session, actor=actor)
    return success([serialize_push_device(device) for device in devices], request)


@router.delete("/me/push-devices/{push_device_id}")
async def delete_my_push_device(
    push_device_id: str,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
) -> dict[str, Any]:
    async with write_lock:
        try:
            device = await revoke_push_device(
                session,
                actor=actor,
                push_device_id=push_device_id,
            )
            await record_audit(
                session,
                actor=actor,
                incident_id=None,
                action="push_device.revoked",
                resource_type="push_device",
                resource_id=device.id,
                request_id=_request_id(request),
                after={"status": device.status, "reason": device.revoked_reason},
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(serialize_push_device(device), request)


@router.get("/me/notification-preferences/{incident_id}")
async def get_my_notification_preference(
    incident_id: str,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    incident = await _incident(session, incident_id)
    ensure_incident_access(actor, incident.id, incident_header)
    preference = await get_preference(session, actor=actor, incident_id=incident.id)
    return success(serialize_preference(preference, incident.id), request)


@router.patch("/me/notification-preferences/{incident_id}")
async def patch_my_notification_preference(
    incident_id: str,
    payload: NotificationPreferencePatch,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    incident = await _incident(session, incident_id)
    ensure_incident_access(actor, incident.id, incident_header)
    async with write_lock:
        try:
            preference = await patch_preference(
                session,
                actor=actor,
                incident_id=incident.id,
                payload=payload,
            )
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="notification_preference.updated",
                resource_type="notification_preference",
                resource_id=preference.id,
                request_id=_request_id(request),
                after=serialize_preference(preference, incident.id),
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(serialize_preference(preference, incident.id), request)


@router.post("/notifications/{notification_id}/receipts")
async def post_notification_receipt(
    notification_id: str,
    payload: NotificationReceiptCreate,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    notification = await session.get(NotificationOutbox, notification_id)
    if notification is None:
        raise ApiError(404, "NOTIFICATION_NOT_FOUND", "通知不存在")
    ensure_incident_access(actor, notification.incident_id, incident_header)
    async with write_lock:
        try:
            receipt = await record_notification_receipt(
                session,
                actor=actor,
                notification_id=notification.id,
                receipt_type=payload.receipt_type,
                installation_id=payload.installation_id,
                app_state=payload.app_state,
                occurred_at=payload.occurred_at,
            )
            await record_audit(
                session,
                actor=actor,
                incident_id=notification.incident_id,
                action="notification.receipt_recorded",
                resource_type="notification",
                resource_id=notification.id,
                request_id=_request_id(request),
                after={
                    "receipt_type": receipt.receipt_type,
                    "app_state": receipt.app_state,
                },
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(
        {
            "notification_id": notification.id,
            "receipt_type": receipt.receipt_type,
            "accepted": True,
        },
        request,
    )
