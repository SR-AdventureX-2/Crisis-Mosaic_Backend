from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from crisis_mosaic.config import Settings
from crisis_mosaic.errors import ApiError
from crisis_mosaic.models import (
    AnonymousDevice,
    Base,
    Incident,
    IncidentMembership,
    LocalAccount,
    NotificationDelivery,
    NotificationOutbox,
)
from crisis_mosaic.schemas.notifications import (
    NotificationPreferencePatch,
    NotificationReceiptCreate,
    PushDeviceRegistration,
)
from crisis_mosaic.schemas.reports import ReporterInput
from crisis_mosaic.schemas.uploads import UploadCompletePart
from crisis_mosaic.security import Actor, hash_password
from crisis_mosaic.services import notifications as notification_service
from crisis_mosaic.services.contacts import (
    authorize_reveal,
    create_reporter_contact,
    serialize_contact_masked,
    serialize_contact_plain,
)
from crisis_mosaic.services.notifications import (
    deliver_notifications_batch,
    enqueue_operator_notifications,
    patch_preference,
    push_payload,
    record_notification_receipt,
    register_push_device,
    serialize_preference,
    serialize_push_device,
)
from crisis_mosaic.services.uploads import (
    complete_remote_upload,
    create_media_intent,
    create_resumable_session,
    process_remote_media,
    record_resumable_part,
    resumable_session_payload,
)


@pytest.fixture
async def session_maker() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


def _settings() -> Settings:
    return Settings(
        app_env="test",
        pii_encryption_key="pii-test-encryption-key-with-enough-entropy-2026",
        pii_blind_index_secret="pii-test-blind-index-secret-with-enough-entropy",
        push_token_secret="push-test-token-secret-with-enough-entropy-2026",
        media_storage_provider="qiniu_kodo_mock",
        qiniu_bucket="test-bucket",
        push_provider_mode="mock",
        push_allowed_app_ids=["com.srstudio.advx2team.crisismosaic"],
        push_allowed_providers=["huawei", "fcm", "apns"],
    )


async def _seed_incident_device(session: AsyncSession) -> tuple[Incident, AnonymousDevice]:
    incident = Incident(id="incident-v11", name="V1.1 incident", status="active")
    device = AnonymousDevice(
        id="device-v11",
        installation_id_hash="d" * 64,
        platform="android",
    )
    session.add_all([incident, device])
    await session.flush()
    return incident, device


def _resident_actor(incident_id: str, device_id: str) -> Actor:
    return Actor(
        subject_type="device",
        subject_id=device_id,
        role="resident",
        token_version=1,
        incident_ids=frozenset({incident_id}),
    )


def _operator_actor(incident_id: str, account_id: str = "operator-v11") -> Actor:
    return Actor(
        subject_type="account",
        subject_id=account_id,
        role="operator",
        token_version=1,
        incident_ids=frozenset({incident_id}),
        username="operator",
    )


@pytest.mark.asyncio
async def test_reporter_contact_is_encrypted_masked_and_reveal_authorized(
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    settings = _settings()
    async with session_maker() as session:
        incident, device = await _seed_incident_device(session)
        contact = create_reporter_contact(
            incident=incident,
            device_id=device.id,
            reporter=ReporterInput(full_name="张明", mobile="13800138000"),
            settings=settings,
        )
        session.add(contact)
        await session.flush()

        assert "张明" not in contact.full_name_ciphertext
        assert contact.mobile_blind_index != "13800138000"
        assert serialize_contact_masked(contact) == {
            "full_name_masked": "张*",
            "mobile_masked": "138****8000",
            "has_national_id": False,
            "emergency_contact": None,
            "has_rescue_notes": False,
        }
        assert serialize_contact_plain(contact, settings)["mobile"] == "+8613800138000"

    operator = _operator_actor("incident-v11")
    with pytest.raises(ApiError) as forbidden:
        authorize_reveal(operator, "000000", settings)
    assert forbidden.value.code == "REPORTER_PII_READ_REQUIRED"
    admin = Actor(
        subject_type="account",
        subject_id="admin-v11",
        role="admin",
        token_version=1,
        incident_ids=frozenset({"incident-v11"}),
        username="admin",
    )
    with pytest.raises(ApiError) as mfa_error:
        authorize_reveal(admin, "bad-code", settings)
    assert mfa_error.value.code == "MFA_REQUIRED"
    authorize_reveal(admin, settings.reporter_reveal_mock_mfa_code, settings)


@pytest.mark.asyncio
async def test_media_intent_resumable_parts_and_mock_processing(
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    settings = _settings()
    sha256 = "a" * 64
    async with session_maker() as session:
        incident, device = await _seed_incident_device(session)
        attachment, intent, token_fingerprint = await create_media_intent(
            session,
            incident_id=incident.id,
            uploader_device_id=device.id,
            media_type="image",
            client_source="camera",
            file_name="现场照片.jpg",
            mime_type="image/jpeg",
            size_bytes=128,
            expected_sha256=sha256,
            duration_ms=None,
            resumable_upload=True,
            settings=settings,
        )
        assert intent["upload"]["method"] == "KODO_RESUMABLE_V2"
        assert "qiniu_secret_key" not in str(intent).lower()
        assert token_fingerprint

        upload_session, upload_token = await create_resumable_session(
            session,
            attachment=attachment,
            device_id=device.id,
            size_bytes=128,
            sha256=sha256,
            client_checkpoint_id="local-checkpoint-1",
            settings=settings,
        )
        first_part = await record_resumable_part(
            session,
            upload_session=upload_session,
            part_number=1,
            offset=0,
            size_bytes=128,
            etag="etag-1",
            sha256=sha256,
        )
        duplicate = await record_resumable_part(
            session,
            upload_session=upload_session,
            part_number=1,
            offset=0,
            size_bytes=128,
            etag="etag-1",
            sha256=sha256,
        )
        assert duplicate.id == first_part.id
        with pytest.raises(ApiError) as conflict:
            await record_resumable_part(
                session,
                upload_session=upload_session,
                part_number=1,
                offset=0,
                size_bytes=128,
                etag="different",
                sha256=sha256,
            )
        assert conflict.value.code == "UPLOAD_PART_CONFLICT"
        resume_payload = await resumable_session_payload(
            session,
            upload_session,
            upload_token=upload_token,
        )
        assert resume_payload["confirmed_bytes"] == 128
        assert resume_payload["missing_parts"] == []

        await complete_remote_upload(
            session,
            attachment=attachment,
            upload_session_id=upload_session.id,
            object_key=attachment.object_key,
            etag="kodo-etag",
            size_bytes=128,
            parts=[UploadCompletePart(part_number=1, etag="etag-1", size_bytes=128)],
        )
        await process_remote_media(session, attachment.id, settings)
        assert attachment.metadata_status == "ready"
        assert attachment.malware_scan_status == "clean"
        assert attachment.object_key is not None


@pytest.mark.parametrize(
    ("media_type", "resumable_upload", "expected_method"),
    [
        ("image", False, "KODO_FORM"),
        ("video", False, "KODO_FORM"),
        ("image", True, "KODO_RESUMABLE_V2"),
        ("video", True, "KODO_RESUMABLE_V2"),
    ],
)
@pytest.mark.asyncio
async def test_media_intent_honors_resumable_capability_for_images_and_videos(
    session_maker: async_sessionmaker[AsyncSession],
    media_type: str,
    resumable_upload: bool,
    expected_method: str,
) -> None:
    settings = Settings(
        app_env="test",
        enable_video_upload=True,
        media_storage_provider="qiniu_kodo_mock",
        qiniu_bucket="test-bucket",
    )
    mime_type = "video/mp4" if media_type == "video" else "image/jpeg"
    async with session_maker() as session:
        incident, device = await _seed_incident_device(session)
        _, intent, _ = await create_media_intent(
            session,
            incident_id=incident.id,
            uploader_device_id=device.id,
            media_type=media_type,
            client_source="camera",
            file_name=f"evidence.{'mp4' if media_type == 'video' else 'jpg'}",
            mime_type=mime_type,
            size_bytes=128,
            expected_sha256="b" * 64,
            duration_ms=1_000 if media_type == "video" else None,
            resumable_upload=resumable_upload,
            settings=settings,
        )

    upload = intent["upload"]
    assert upload["method"] == expected_method
    assert upload["mode"] == ("resumable" if resumable_upload else "form")
    if resumable_upload:
        assert "session_endpoint" in upload
        assert "form_field" not in upload
    else:
        assert upload["form_field"] == "file"
        assert "session_endpoint" not in upload


@pytest.mark.asyncio
async def test_real_qiniu_intent_uses_standard_signed_upload_policy(
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    access_key = "test-qiniu-access-key"
    secret_key = "test-qiniu-secret-key"
    settings = Settings(
        app_env="test",
        media_storage_provider="qiniu_kodo",
        qiniu_access_key=access_key,
        qiniu_secret_key=secret_key,
        qiniu_bucket="test-bucket",
        qiniu_upload_host="https://upload.qiniup.com",
        qiniu_callback_url="https://api.example.test/qiniu/callback",
    )
    before = int(datetime.now(UTC).timestamp())
    async with session_maker() as session:
        incident, device = await _seed_incident_device(session)
        attachment, intent, token_fingerprint = await create_media_intent(
            session,
            incident_id=incident.id,
            uploader_device_id=device.id,
            media_type="image",
            client_source="gallery",
            file_name="evidence.jpg",
            mime_type="image/jpeg",
            size_bytes=128,
            expected_sha256="c" * 64,
            duration_ms=None,
            resumable_upload=False,
            settings=settings,
        )

    token = str(intent["upload"]["fields"]["token"])
    token_access_key, signature, encoded_policy = token.split(":", 2)
    expected_signature = base64.urlsafe_b64encode(
        hmac.new(
            secret_key.encode("utf-8"),
            encoded_policy.encode("ascii"),
            hashlib.sha1,
        ).digest()
    ).decode("ascii")
    policy = json.loads(base64.urlsafe_b64decode(encoded_policy).decode("utf-8"))

    assert token_access_key == access_key
    assert hmac.compare_digest(signature, expected_signature)
    assert policy["scope"] == f"test-bucket:{attachment.object_key}"
    assert policy["insertOnly"] == 1
    assert before < policy["deadline"] <= before + settings.qiniu_upload_token_ttl_seconds + 1
    assert policy["callbackUrl"] == settings.qiniu_callback_url
    assert intent["upload"]["method"] == "KODO_FORM"
    assert secret_key not in str(intent)
    assert len(token_fingerprint) == 8


@pytest.mark.asyncio
async def test_push_registration_preferences_outbox_delivery_and_receipts(
    session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    async with session_maker() as session:
        incident = Incident(id="incident-push", name="Push incident", status="active")
        operator = LocalAccount(
            id="operator-v11",
            username="operator",
            password_hash=hash_password("Correct-Horse-Battery-Staple-2026!"),
            role="operator",
        )
        session.add_all(
            [
                incident,
                operator,
                IncidentMembership(
                    account_id=operator.id,
                    incident_id=incident.id,
                    role=operator.role,
                ),
            ]
        )
        await session.flush()
        actor = _operator_actor(incident.id, operator.id)
        device = await register_push_device(
            session,
            actor=actor,
            payload=PushDeviceRegistration(
                installation_id="app-installation-id-with-entropy-2026",
                platform="android",
                provider="huawei",
                provider_token="provider-token-secret-value",
                app_id="com.srstudio.advx2team.crisismosaic",
                environment="production",
            ),
            settings=settings,
        )
        serialized = serialize_push_device(device)
        assert serialized["token_fingerprint"] == device.provider_token_hash[-8:]
        assert "provider-token-secret-value" not in str(serialized)

        preference = await patch_preference(
            session,
            actor=actor,
            incident_id=incident.id,
            payload=NotificationPreferencePatch(
                revision=0,
                enabled=True,
                minimum_priority="medium",
                event_types=["urgent_report.created"],
            ),
        )
        assert serialize_preference(preference, incident.id)["revision"] == 1
        notifications = await enqueue_operator_notifications(
            session,
            incident=incident,
            business_event_id="event-push-1",
            event_type="urgent_report.created",
            priority="high",
            resource_type="report",
            resource_id="report-push",
            resource_revision=1,
            deep_link="crisismosaic://incidents/incident-push/reports/report-push",
            title="Crisis Mosaic 紧急提醒",
            body="收到一条新的高优先级现场上报，请打开应用查看。",
            settings=settings,
        )
        await session.commit()

    assert len(notifications) == 1
    monkeypatch.setattr(notification_service, "session_factory", lambda: session_maker)
    assert await deliver_notifications_batch(settings) == 1

    async with session_maker() as session:
        notification = await session.get(NotificationOutbox, notifications[0].id)
        assert notification is not None
        assert notification.status == "sent"
        assert "provider-token-secret-value" not in str(push_payload(notification))
        delivery = await session.scalar(
            select(NotificationDelivery).where(
                NotificationDelivery.notification_outbox_id == notification.id
            )
        )
        assert delivery is not None
        assert delivery.status == "accepted"

        receipt_payload = NotificationReceiptCreate(
            receipt_type="clicked",
            installation_id="app-installation-id-with-entropy-2026",
            occurred_at=datetime.now(UTC),
            app_state="background",
        )
        receipt = await record_notification_receipt(
            session,
            actor=_operator_actor(notification.incident_id),
            notification_id=notification.id,
            receipt_type=receipt_payload.receipt_type,
            installation_id=receipt_payload.installation_id,
            app_state=receipt_payload.app_state,
            occurred_at=receipt_payload.occurred_at,
            settings=settings,
        )
        await session.commit()
        assert receipt.receipt_type == "clicked"
