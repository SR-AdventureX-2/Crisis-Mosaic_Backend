from __future__ import annotations

import base64
import json
import secrets
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..db import session_factory, write_lock
from ..errors import ApiError
from ..models import (
    Incident,
    IncidentMembership,
    LocalAccount,
    NotificationDelivery,
    NotificationOutbox,
    NotificationPreference,
    NotificationReceipt,
    PushDevice,
)
from ..schemas.notifications import NotificationPreferencePatch, PushDeviceRegistration
from ..security import Actor
from ..utils import as_utc, hmac_sha256, sha256_text, utcnow

_PRIORITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _aes(settings: Settings) -> AESGCM:
    return AESGCM(bytes.fromhex(sha256_text(settings.push_token_secret)))


def _encrypt_token(
    value: str,
    *,
    operator_id: str,
    provider: str,
    settings: Settings,
) -> str:
    nonce = secrets.token_bytes(12)
    aad = f"{operator_id}:{provider}:{settings.pii_encryption_key_version}".encode()
    token = _aes(settings).encrypt(nonce, value.encode("utf-8"), aad)
    payload = {
        "v": 1,
        "nonce": base64.urlsafe_b64encode(nonce).decode(),
        "ciphertext": base64.urlsafe_b64encode(token).decode(),
    }
    return base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()


def _require_operator_account(actor: Actor) -> None:
    if actor.subject_type != "account" or actor.role not in {"operator", "admin"}:
        raise ApiError(403, "OPERATOR_ACCOUNT_REQUIRED", "仅指挥账号可管理 Push")


def _validate_registration(payload: PushDeviceRegistration, settings: Settings) -> None:
    provider = payload.provider.lower()
    if provider not in settings.push_allowed_providers:
        raise ApiError(
            422,
            "INVALID_PUSH_REGISTRATION",
            "Push 提供方未启用",
            details={"provider": provider},
        )
    if payload.app_id not in settings.push_allowed_app_ids:
        raise ApiError(
            422,
            "INVALID_PUSH_REGISTRATION",
            "Push App ID 不匹配",
            details={"app_id": payload.app_id},
        )
    if payload.platform == "ios" and provider != "apns":
        raise ApiError(422, "INVALID_PUSH_REGISTRATION", "iOS 设备必须使用 APNs")
    if payload.platform == "android" and provider == "apns":
        raise ApiError(422, "INVALID_PUSH_REGISTRATION", "Android 设备不能使用 APNs")


def _installation_hash(installation_id: str, settings: Settings) -> str:
    return hmac_sha256(settings.push_token_secret, installation_id)


def _provider_token_hash(provider_token: str, settings: Settings) -> str:
    return hmac_sha256(settings.push_token_secret, provider_token)


def serialize_push_device(device: PushDevice) -> dict[str, Any]:
    return {
        "push_device_id": device.id,
        "platform": device.platform,
        "provider": device.provider,
        "token_fingerprint": device.token_fingerprint,
        "app_id": device.app_id,
        "environment": device.environment,
        "authorization_status": device.authorization_status,
        "route_priority": device.route_priority,
        "status": device.status,
        "updated_at": device.updated_at,
        "revoked_at": device.revoked_at,
    }


async def register_push_device(
    session: AsyncSession,
    *,
    actor: Actor,
    payload: PushDeviceRegistration,
    settings: Settings | None = None,
) -> PushDevice:
    settings = settings or get_settings()
    _require_operator_account(actor)
    _validate_registration(payload, settings)
    provider = payload.provider.lower()
    installation_digest = _installation_hash(payload.installation_id, settings)
    token_digest = _provider_token_hash(payload.provider_token, settings)
    existing = await session.scalar(
        select(PushDevice)
        .where(
            PushDevice.operator_id == actor.subject_id,
            PushDevice.provider == provider,
            or_(
                PushDevice.installation_id_hash == installation_digest,
                PushDevice.provider_token_hash == token_digest,
            ),
        )
        .order_by(PushDevice.updated_at.desc())
    )
    now = utcnow()
    encrypted = _encrypt_token(
        payload.provider_token,
        operator_id=actor.subject_id,
        provider=provider,
        settings=settings,
    )
    if existing is None:
        existing = PushDevice(
            operator_id=actor.subject_id,
            installation_id_hash=installation_digest,
            platform=payload.platform,
            provider=provider,
            provider_token_ciphertext=encrypted,
            provider_token_hash=token_digest,
            token_fingerprint=token_digest[-8:],
            app_id=payload.app_id,
            environment=payload.environment,
            authorization_status=payload.authorization_status,
            route_priority=payload.route_priority,
            app_version=payload.app_version,
            status="active",
            last_seen_at=now,
        )
        session.add(existing)
    else:
        existing.installation_id_hash = installation_digest
        existing.platform = payload.platform
        existing.provider_token_ciphertext = encrypted
        existing.provider_token_hash = token_digest
        existing.token_fingerprint = token_digest[-8:]
        existing.app_id = payload.app_id
        existing.environment = payload.environment
        existing.authorization_status = payload.authorization_status
        existing.route_priority = payload.route_priority
        existing.app_version = payload.app_version
        existing.status = "active"
        existing.revoked_at = None
        existing.revoked_reason = None
        existing.last_seen_at = now
    await session.flush()
    return existing


async def list_push_devices(
    session: AsyncSession,
    *,
    actor: Actor,
) -> list[PushDevice]:
    _require_operator_account(actor)
    return list(
        (
            await session.scalars(
                select(PushDevice)
                .where(PushDevice.operator_id == actor.subject_id)
                .order_by(PushDevice.route_priority, PushDevice.updated_at.desc())
            )
        ).all()
    )


async def revoke_push_device(
    session: AsyncSession,
    *,
    actor: Actor,
    push_device_id: str,
    reason: str = "client_revoked",
) -> PushDevice:
    _require_operator_account(actor)
    device = await session.get(PushDevice, push_device_id)
    if device is None or device.operator_id != actor.subject_id:
        raise ApiError(404, "PUSH_DEVICE_NOT_FOUND", "Push 设备不存在")
    if device.status != "revoked":
        device.status = "revoked"
        device.revoked_at = utcnow()
        device.revoked_reason = reason
    await session.flush()
    return device


def serialize_preference(
    preference: NotificationPreference | None,
    incident_id: str,
) -> dict[str, Any]:
    if preference is None:
        return {
            "incident_id": incident_id,
            "enabled": True,
            "minimum_priority": "high",
            "event_types": [],
            "quiet_hours": None,
            "revision": 0,
            "updated_at": None,
        }
    return {
        "incident_id": incident_id,
        "enabled": preference.enabled,
        "minimum_priority": preference.minimum_priority,
        "event_types": preference.event_types,
        "quiet_hours": preference.quiet_hours,
        "revision": preference.revision,
        "updated_at": preference.updated_at,
    }


async def get_preference(
    session: AsyncSession,
    *,
    actor: Actor,
    incident_id: str,
) -> NotificationPreference | None:
    _require_operator_account(actor)
    preference = await session.scalar(
        select(NotificationPreference).where(
            NotificationPreference.operator_id == actor.subject_id,
            NotificationPreference.incident_id == incident_id,
        )
    )
    return preference


async def patch_preference(
    session: AsyncSession,
    *,
    actor: Actor,
    incident_id: str,
    payload: NotificationPreferencePatch,
) -> NotificationPreference:
    _require_operator_account(actor)
    preference = await get_preference(session, actor=actor, incident_id=incident_id)
    current_revision = preference.revision if preference else 0
    if payload.revision != current_revision:
        raise ApiError(
            409,
            "REVISION_CONFLICT",
            "notification preference revision does not match",
            details={
                "expected_revision": payload.revision,
                "current_revision": current_revision,
            },
        )
    if preference is None:
        preference = NotificationPreference(
            operator_id=actor.subject_id,
            incident_id=incident_id,
            enabled=True,
            minimum_priority="high",
            event_types=[],
            quiet_hours=None,
            revision=0,
        )
        session.add(preference)
    fields = payload.model_fields_set - {"revision"}
    if "enabled" in fields and payload.enabled is not None:
        preference.enabled = payload.enabled
    if "minimum_priority" in fields and payload.minimum_priority is not None:
        preference.minimum_priority = payload.minimum_priority
    if "event_types" in fields and payload.event_types is not None:
        preference.event_types = payload.event_types
    if "quiet_hours" in fields:
        preference.quiet_hours = payload.quiet_hours
    preference.revision += 1
    await session.flush()
    return preference


def _preference_allows(
    preference: NotificationPreference | None,
    *,
    event_type: str,
    priority: str,
) -> bool:
    if preference is not None:
        if not preference.enabled:
            return False
        if preference.event_types and event_type not in preference.event_types:
            return False
        minimum = preference.minimum_priority
    else:
        minimum = "high"
    return _PRIORITY_RANK.get(priority, 0) >= _PRIORITY_RANK.get(minimum, 3)


def _safe_deep_link(deep_link: str | None, settings: Settings) -> str | None:
    if deep_link is None:
        return None
    parsed = urlparse(deep_link)
    if parsed.scheme in settings.push_deep_link_allowed_schemes:
        return deep_link[:300]
    return None


def push_payload(notification: NotificationOutbox) -> dict[str, dict[str, str]]:
    return {
        "notification": {
            "title": notification.title,
            "body": notification.body,
        },
        "data": {
            "schema_version": "1",
            "notification_id": notification.id,
            "business_event_id": notification.business_event_id,
            "incident_id": notification.incident_id,
            "event_type": notification.event_type,
            "resource_type": notification.resource_type,
            "resource_id": notification.resource_id or "",
            "resource_revision": str(notification.resource_revision or ""),
            "deep_link": notification.deep_link or "",
        },
    }


async def enqueue_operator_notifications(
    session: AsyncSession,
    *,
    incident: Incident,
    business_event_id: str,
    event_type: str,
    priority: str,
    resource_type: str,
    resource_id: str | None,
    resource_revision: int | None,
    deep_link: str | None,
    title: str,
    body: str,
    settings: Settings | None = None,
) -> list[NotificationOutbox]:
    settings = settings or get_settings()
    if not settings.push_notifications_enabled:
        return []
    safe_deep_link = _safe_deep_link(deep_link, settings)
    accounts = list(
        (
            await session.scalars(
                select(LocalAccount)
                .join(IncidentMembership, IncidentMembership.account_id == LocalAccount.id)
                .where(
                    IncidentMembership.incident_id == incident.id,
                    LocalAccount.is_active.is_(True),
                    LocalAccount.role.in_(("operator", "admin")),
                )
            )
        ).all()
    )
    rows: list[NotificationOutbox] = []
    expires_at = utcnow() + timedelta(seconds=settings.push_notification_ttl_seconds)
    dedupe_key = (
        f"{business_event_id}:{event_type}:"
        f"{resource_type}:{resource_id}:{resource_revision}"
    )
    for account in accounts:
        preference = await session.scalar(
            select(NotificationPreference).where(
                NotificationPreference.operator_id == account.id,
                NotificationPreference.incident_id == incident.id,
            )
        )
        if not _preference_allows(preference, event_type=event_type, priority=priority):
            continue
        existing = await session.scalar(
            select(NotificationOutbox).where(
                NotificationOutbox.dedupe_key == dedupe_key,
                NotificationOutbox.recipient_operator_id == account.id,
            )
        )
        if existing is not None:
            rows.append(existing)
            continue
        row = NotificationOutbox(
            incident_id=incident.id,
            recipient_operator_id=account.id,
            business_event_id=business_event_id,
            dedupe_key=dedupe_key,
            event_type=event_type,
            priority=priority,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_revision=resource_revision,
            deep_link=safe_deep_link,
            title=title[:120],
            body=body[:240],
            payload={
                "schema_version": "1",
                "business_event_id": business_event_id,
                "event_type": event_type,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "resource_revision": resource_revision,
            },
            expires_at=expires_at,
        )
        session.add(row)
        rows.append(row)
    return rows


async def record_notification_receipt(
    session: AsyncSession,
    *,
    actor: Actor,
    notification_id: str,
    receipt_type: str,
    installation_id: str,
    app_state: str | None,
    occurred_at: Any,
    settings: Settings | None = None,
) -> NotificationReceipt:
    settings = settings or get_settings()
    _require_operator_account(actor)
    notification = await session.get(NotificationOutbox, notification_id)
    if notification is None or notification.recipient_operator_id != actor.subject_id:
        raise ApiError(404, "NOTIFICATION_NOT_FOUND", "通知不存在")
    digest = _installation_hash(installation_id, settings)
    existing = await session.scalar(
        select(NotificationReceipt).where(
            NotificationReceipt.notification_outbox_id == notification.id,
            NotificationReceipt.receipt_type == receipt_type,
            NotificationReceipt.installation_id_hash == digest,
        )
    )
    if existing is not None:
        return existing
    row = NotificationReceipt(
        notification_outbox_id=notification.id,
        receipt_type=receipt_type,
        installation_id_hash=digest,
        app_state=app_state,
        occurred_at=as_utc(occurred_at),
    )
    session.add(row)
    await session.flush()
    delivery = await session.scalar(
        select(NotificationDelivery)
        .join(PushDevice, PushDevice.id == NotificationDelivery.push_device_id)
        .where(
            NotificationDelivery.notification_outbox_id == notification.id,
            PushDevice.installation_id_hash == digest,
        )
    )
    if delivery is not None:
        if receipt_type in {"delivered", "displayed"}:
            delivery.delivered_at = delivery.delivered_at or as_utc(occurred_at)
        if receipt_type == "clicked":
            delivery.clicked_at = delivery.clicked_at or as_utc(occurred_at)
    return row


async def deliver_notifications_batch(settings: Settings | None = None) -> int:
    settings = settings or get_settings()
    now = utcnow()
    async with write_lock:
        async with session_factory()() as session:
            rows = list(
                (
                    await session.scalars(
                        select(NotificationOutbox)
                        .where(
                            NotificationOutbox.status.in_(("queued", "retry")),
                            NotificationOutbox.run_after <= now,
                            NotificationOutbox.expires_at > now,
                        )
                        .order_by(NotificationOutbox.run_after, NotificationOutbox.created_at)
                        .limit(settings.push_outbox_batch_size)
                    )
                ).all()
            )
            for notification in rows:
                await _deliver_one(session, notification, settings)
            await session.commit()
    return len(rows)


async def _deliver_one(
    session: AsyncSession,
    notification: NotificationOutbox,
    settings: Settings,
) -> None:
    now = utcnow()
    notification.attempts += 1
    if not settings.push_notifications_enabled or settings.push_provider_mode == "disabled":
        notification.status = "cancelled"
        notification.cancelled_at = now
        notification.last_error_code = "PUSH_PROVIDER_DISABLED"
        return
    device = await session.scalar(
        select(PushDevice)
        .where(
            PushDevice.operator_id == notification.recipient_operator_id,
            PushDevice.status == "active",
            PushDevice.revoked_at.is_(None),
            PushDevice.authorization_status.in_(("authorized", "provisional", "ephemeral")),
        )
        .order_by(PushDevice.route_priority, PushDevice.last_seen_at.desc())
    )
    if device is None:
        notification.status = "no_device"
        notification.last_error_code = "PUSH_DEVICE_NOT_REGISTERED"
        return
    delivery = await session.scalar(
        select(NotificationDelivery).where(
            NotificationDelivery.notification_outbox_id == notification.id,
            NotificationDelivery.push_device_id == device.id,
        )
    )
    if delivery is None:
        delivery = NotificationDelivery(
            notification_outbox_id=notification.id,
            push_device_id=device.id,
            provider=device.provider,
            status="queued",
            attempts=0,
        )
        session.add(delivery)
    delivery.status = "accepted"
    delivery.attempts = (delivery.attempts or 0) + 1
    delivery.sent_at = now
    delivery.provider_message_id = f"mock-{sha256_text(notification.id + device.id)[:24]}"
    delivery.provider_response = {
        "mode": settings.push_provider_mode,
        "payload": push_payload(notification),
    }
    notification.status = "sent"
    notification.sent_at = now
    notification.last_error_code = None


async def safe_enqueue_operator_notifications(
    *args: Any,
    **kwargs: Any,
) -> list[NotificationOutbox]:
    try:
        return await enqueue_operator_notifications(*args, **kwargs)
    except IntegrityError:
        return []
