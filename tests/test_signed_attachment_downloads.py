from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import crisis_mosaic.services.attachments as attachment_service
from crisis_mosaic.config import Settings
from crisis_mosaic.db import get_session
from crisis_mosaic.errors import install_error_handlers
from crisis_mosaic.models import AnonymousDevice, Attachment, Base, Incident
from crisis_mosaic.routers.uploads import router as uploads_router
from crisis_mosaic.services.attachments import (
    serialize_attachment,
    sign_local_attachment_url,
    verify_local_attachment_url,
)
from crisis_mosaic.utils import utcnow


async def _signed_download_app(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    AsyncEngine,
    async_sessionmaker[AsyncSession],
    FastAPI,
    Attachment,
    Settings,
]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'signed-download.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        app_env="test",
        upload_signing_secret="signed-attachment-test-secret",
        signed_download_minutes=10,
    )
    monkeypatch.setattr(attachment_service, "get_settings", lambda: settings)

    content_path = tmp_path / "evidence.jpg"
    thumbnail_path = tmp_path / "evidence-thumbnail.jpg"
    content_path.write_bytes(b"full-size-image")
    thumbnail_path.write_bytes(b"thumbnail-image")
    async with factory() as session:
        incident = Incident(id="signed-download-incident", name="Signed download")
        device = AnonymousDevice(
            id="signed-download-device",
            installation_id_hash="d" * 64,
            platform="android",
        )
        attachment = Attachment(
            id="signed-download-attachment",
            incident_id=incident.id,
            uploader_device_id=device.id,
            file_name="evidence.jpg",
            declared_mime_type="image/jpeg",
            media_type="image",
            storage_provider="local_proxy",
            mime_type="image/jpeg",
            size_bytes=content_path.stat().st_size,
            expected_sha256="a" * 64,
            sha256="a" * 64,
            original_path=str(content_path),
            sanitized_path=str(content_path),
            thumbnail_path=str(thumbnail_path),
            metadata_status="ready",
            malware_scan_status="clean",
            upload_expires_at=utcnow() + timedelta(minutes=10),
            uploaded_at=utcnow(),
        )
        session.add_all([incident, device, attachment])
        await session.commit()

    async def session_override() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            yield session

    app = FastAPI()
    install_error_handlers(app)
    app.include_router(uploads_router, prefix="/api/v1")
    app.dependency_overrides[get_session] = session_override
    return engine, factory, app, attachment, settings


def test_local_attachment_signature_is_scoped_and_expires() -> None:
    settings = Settings(
        app_env="test",
        upload_signing_secret="signed-attachment-test-secret",
    )
    deadline = int((utcnow() + timedelta(minutes=1)).timestamp())
    url = sign_local_attachment_url(
        "attachment-1",
        "content",
        settings=settings,
        expires_at=deadline,
    )
    segments = url.split("/")
    signature = segments[-3]
    expires_at = segments[-4]

    assert verify_local_attachment_url(
        "attachment-1",
        "content",
        expires_at,
        signature,
        settings=settings,
    )
    assert not verify_local_attachment_url(
        "attachment-1",
        "thumbnail",
        expires_at,
        signature,
        settings=settings,
    )
    assert not verify_local_attachment_url(
        "attachment-2",
        "content",
        expires_at,
        signature,
        settings=settings,
    )
    assert not verify_local_attachment_url(
        "attachment-1",
        "content",
        expires_at,
        ("0" if signature[0] != "0" else "1") + signature[1:],
        settings=settings,
    )

    expired = int((utcnow() - timedelta(seconds=1)).timestamp())
    expired_url = sign_local_attachment_url(
        "attachment-1",
        "content",
        settings=settings,
        expires_at=expired,
    )
    expired_segments = expired_url.split("/")
    assert not verify_local_attachment_url(
        "attachment-1",
        "content",
        expired_segments[-4],
        expired_segments[-3],
        settings=settings,
    )


@pytest.mark.asyncio
async def test_signed_local_downloads_work_without_bearer_and_reject_bad_signatures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _, app, attachment, settings = await _signed_download_app(tmp_path, monkeypatch)
    try:
        serialized = serialize_attachment(attachment)
        content_url = serialized["content_url"]
        thumbnail_url = serialized["thumbnail_url"]
        assert isinstance(content_url, str)
        assert isinstance(thumbnail_url, str)
        assert "access_token" not in content_url
        assert "bearer" not in content_url.casefold()

        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            content = await client.get(content_url)
            assert content.status_code == 200, content.text
            assert content.content == b"full-size-image"
            assert content.headers["content-disposition"].startswith("inline;")

            thumbnail = await client.get(thumbnail_url)
            assert thumbnail.status_code == 200, thumbnail.text
            assert thumbnail.content == b"thumbnail-image"

            authenticated_route = await client.get(f"/api/v1/uploads/{attachment.id}/content")
            assert authenticated_route.status_code == 401

            segments = content_url.split("/")
            signature = segments[-3]
            segments[-3] = ("0" if signature[0] != "0" else "1") + signature[1:]
            tampered = await client.get("/".join(segments))
            assert tampered.status_code == 403
            assert tampered.json()["error"]["code"] == "SIGNED_ATTACHMENT_URL_INVALID"

            expired_url = sign_local_attachment_url(
                attachment.id,
                "content",
                settings=settings,
                expires_at=int((utcnow() - timedelta(seconds=1)).timestamp()),
            )
            expired = await client.get(expired_url)
            assert expired.status_code == 403
            assert expired.json()["error"]["code"] == "SIGNED_ATTACHMENT_URL_INVALID"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_signed_local_download_rechecks_state_provider_and_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, factory, app, attachment, settings = await _signed_download_app(tmp_path, monkeypatch)
    content_url = sign_local_attachment_url(attachment.id, "content", settings=settings)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            async with factory() as session:
                stored = await session.get(Attachment, attachment.id)
                assert stored is not None
                stored.metadata_status = "pending"
                await session.commit()
            not_ready = await client.get(content_url)
            assert not_ready.status_code == 409
            assert not_ready.json()["error"]["code"] == "ATTACHMENT_NOT_READY"

            async with factory() as session:
                stored = await session.get(Attachment, attachment.id)
                assert stored is not None
                stored.metadata_status = "ready"
                stored.storage_provider = "qiniu_kodo_mock"
                await session.commit()
            wrong_provider = await client.get(content_url)
            assert wrong_provider.status_code == 409
            assert wrong_provider.json()["error"]["code"] == "ATTACHMENT_NOT_LOCAL_PROXY"

            async with factory() as session:
                stored = await session.get(Attachment, attachment.id)
                assert stored is not None
                stored.storage_provider = "local_proxy"
                stored.original_path = str(tmp_path / "missing.jpg")
                await session.commit()
            missing = await client.get(content_url)
            assert missing.status_code == 404
            assert missing.json()["error"]["code"] == "ATTACHMENT_CONTENT_MISSING"
    finally:
        await engine.dispose()
