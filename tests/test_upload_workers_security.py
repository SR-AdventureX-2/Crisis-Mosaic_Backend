from __future__ import annotations

import asyncio
import hashlib
import io
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path

import pytest
from PIL import Image
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from crisis_mosaic.config import Settings
from crisis_mosaic.errors import ApiError
from crisis_mosaic.models import (
    AnonymousDevice,
    Attachment,
    BackgroundJob,
    Base,
    Incident,
    OutboxEvent,
)
from crisis_mosaic.schemas.uploads import ImageIntentRequest
from crisis_mosaic.services.uploads import (
    attachment_state,
    process_attachment,
    safe_storage_path,
    stream_request_to_quarantine,
)
from crisis_mosaic.utils import utcnow
from crisis_mosaic.workers import WorkerRuntime


async def _database(
    path: Path,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


def _image_bytes(image_format: str = "JPEG", size: tuple[int, int] = (32, 24)) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", size, color=(30, 90, 180)).save(output, format=image_format)
    return output.getvalue()


async def _chunks(*values: bytes) -> AsyncIterator[bytes]:
    for value in values:
        yield value


async def _seed_uploaded_attachment(
    session: AsyncSession,
    settings: Settings,
    content: bytes,
    *,
    declared_mime_type: str = "image/jpeg",
    digest: str | None = None,
) -> tuple[Incident, AnonymousDevice, Attachment]:
    incident = Incident(name="Upload Security Test", status="preparing")
    device = AnonymousDevice(
        installation_id_hash=hashlib.sha256(content + b"device").hexdigest(),
        platform="test",
    )
    session.add_all([incident, device])
    await session.flush()
    attachment = Attachment(
        incident_id=incident.id,
        uploader_device_id=device.id,
        file_name="evidence.jpg",
        declared_mime_type=declared_mime_type,
        size_bytes=len(content),
        expected_sha256=digest or hashlib.sha256(content).hexdigest(),
        sha256=digest or hashlib.sha256(content).hexdigest(),
        upload_expires_at=utcnow() + timedelta(minutes=1),
        uploaded_at=utcnow(),
    )
    session.add(attachment)
    await session.flush()
    settings.ensure_directories()
    source = safe_storage_path(settings.storage_root, "quarantine", attachment.id, ".upload")
    source.write_bytes(content)
    attachment.original_path = str(source)
    await session.commit()
    return incident, device, attachment


def test_upload_file_name_and_storage_path_reject_traversal(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="file_name"):
        ImageIntentRequest(
            incident_id="incident",
            file_name=r"..\outside.jpg",
            mime_type="image/jpeg",
            size_bytes=10,
            sha256="0" * 64,
        )

    with pytest.raises(ApiError) as error:
        safe_storage_path(tmp_path, "quarantine", "../outside", ".upload")
    assert error.value.code == "INVALID_ATTACHMENT_ID"
    assert not (tmp_path.parent / "outside.upload").exists()


@pytest.mark.asyncio
async def test_stream_upload_rejects_over_limit_and_removes_partial_file(
    tmp_path: Path,
) -> None:
    settings = Settings(
        app_env="test",
        data_dir=tmp_path,
        storage_root=tmp_path / "uploads",
        max_image_bytes=4,
    )
    attachment = Attachment(
        id="01900000-0000-7000-8000-000000000101",
        incident_id="incident",
        uploader_device_id="device",
        file_name="evidence.jpg",
        declared_mime_type="image/jpeg",
        size_bytes=8,
        expected_sha256=hashlib.sha256(b"12345678").hexdigest(),
        upload_expires_at=utcnow() + timedelta(minutes=1),
    )

    with pytest.raises(ApiError) as error:
        await stream_request_to_quarantine(attachment, _chunks(b"123", b"45678"), settings)

    assert error.value.status_code == 413
    assert error.value.code == "IMAGE_TOO_LARGE"
    target = safe_storage_path(settings.storage_root, "quarantine", attachment.id, ".upload")
    assert not target.exists()
    assert attachment.sha256 is None
    assert attachment.uploaded_at is None


@pytest.mark.asyncio
async def test_stream_upload_rejects_hash_mismatch_and_removes_file(
    tmp_path: Path,
) -> None:
    content = b"not-the-declared-content"
    settings = Settings(
        app_env="test",
        data_dir=tmp_path,
        storage_root=tmp_path / "uploads",
        max_image_bytes=1024,
    )
    attachment = Attachment(
        id="01900000-0000-7000-8000-000000000102",
        incident_id="incident",
        uploader_device_id="device",
        file_name="evidence.jpg",
        declared_mime_type="image/jpeg",
        size_bytes=len(content),
        expected_sha256="0" * 64,
        upload_expires_at=utcnow() + timedelta(minutes=1),
    )

    with pytest.raises(ApiError) as error:
        await stream_request_to_quarantine(attachment, _chunks(content), settings)

    assert error.value.status_code == 422
    assert error.value.code == "UPLOAD_HASH_MISMATCH"
    target = safe_storage_path(settings.storage_root, "quarantine", attachment.id, ".upload")
    assert not target.exists()
    assert attachment.original_path is None


@pytest.mark.asyncio
async def test_processing_rejects_declared_mime_spoof(tmp_path: Path) -> None:
    engine, maker = await _database(tmp_path / "mime.db")
    settings = Settings(
        app_env="test",
        data_dir=tmp_path,
        storage_root=tmp_path / "uploads",
        ai_provider="fake",
    )
    try:
        async with maker() as session:
            _, _, attachment = await _seed_uploaded_attachment(
                session,
                settings,
                _image_bytes("PNG"),
                declared_mime_type="image/jpeg",
            )
            attachment_id = attachment.id
            with pytest.raises(ApiError) as error:
                await process_attachment(session, attachment_id, settings)
            await session.commit()

        assert error.value.status_code == 415
        assert error.value.code == "DECLARED_MIME_MISMATCH"
        async with maker() as session:
            rejected = await session.get(Attachment, attachment_id)
            assert rejected is not None
            assert attachment_state(rejected) == "rejected"
            assert rejected.malware_scan_status == "clean"
            assert rejected.rejection_reason == "DECLARED_MIME_MISMATCH"
            assert rejected.sanitized_path is None
            assert rejected.thumbnail_path is None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_expired_job_lease_is_reclaimed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, maker = await _database(tmp_path / "lease.db")
    monkeypatch.setattr("crisis_mosaic.workers.session_factory", lambda: maker)
    monkeypatch.setattr("crisis_mosaic.workers.write_lock", asyncio.Lock())
    settings = Settings(
        app_env="test",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'lease.db'}",
        job_lease_seconds=60,
    )
    try:
        async with maker() as session:
            job = BackgroundJob(
                job_type="unknown",
                status="running",
                payload={},
                attempts=1,
                max_attempts=3,
                lease_expires_at=utcnow() - timedelta(seconds=1),
            )
            session.add(job)
            await session.commit()
            job_id = job.id

        runtime = WorkerRuntime(settings)
        assert await runtime._claim_job() == job_id

        async with maker() as session:
            reclaimed = await session.get(BackgroundJob, job_id)
            assert reclaimed is not None
            assert reclaimed.status == "running"
            assert reclaimed.attempts == 2
            assert reclaimed.lease_expires_at is not None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_background_job_retries_then_fails_at_attempt_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, maker = await _database(tmp_path / "retry.db")
    monkeypatch.setattr("crisis_mosaic.workers.session_factory", lambda: maker)
    monkeypatch.setattr("crisis_mosaic.workers.write_lock", asyncio.Lock())
    settings = Settings(
        app_env="test",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'retry.db'}",
        job_max_attempts=2,
    )
    try:
        async with maker() as session:
            job = BackgroundJob(job_type="unknown", payload={}, max_attempts=2)
            session.add(job)
            await session.commit()
            job_id = job.id

        runtime = WorkerRuntime(settings)
        assert await runtime._claim_job() == job_id
        await runtime._execute_job(job_id)

        async with maker() as session:
            retrying = await session.get(BackgroundJob, job_id)
            assert retrying is not None
            assert retrying.status == "retry"
            assert retrying.attempts == 1
            assert retrying.lease_expires_at is None
            assert "unknown background job type" in (retrying.last_error or "")
            retrying.run_after = utcnow() - timedelta(seconds=1)
            await session.commit()

        assert await runtime._claim_job() == job_id
        await runtime._execute_job(job_id)

        async with maker() as session:
            failed = await session.get(BackgroundJob, job_id)
            assert failed is not None
            assert failed.status == "failed"
            assert failed.attempts == 2
            assert failed.lease_expires_at is None
            assert "unknown background job type" in (failed.last_error or "")
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_outbox_retries_in_order_and_marks_successful_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, maker = await _database(tmp_path / "outbox.db")
    monkeypatch.setattr("crisis_mosaic.workers.session_factory", lambda: maker)
    monkeypatch.setattr("crisis_mosaic.workers.write_lock", asyncio.Lock())
    delivered: list[int] = []
    handler_calls = 0

    async def flaky_handler(envelope: dict[str, object]) -> None:
        nonlocal handler_calls
        handler_calls += 1
        if handler_calls == 1:
            raise RuntimeError("temporary realtime outage")
        delivered.append(int(envelope["sequence"]))

    try:
        async with maker() as session:
            incident = Incident(name="Outbox Test", status="preparing")
            session.add(incident)
            await session.flush()
            session.add_all(
                [
                    OutboxEvent(
                        incident_id=incident.id,
                        sequence=sequence,
                        event_type="test.event",
                        visibility="operators",
                        resource_type="test",
                        resource_id=f"resource-{sequence}",
                        payload={"sequence": sequence},
                    )
                    for sequence in (1, 2)
                ]
            )
            await session.commit()

        runtime = WorkerRuntime(
            Settings(
                app_env="test",
                database_url=f"sqlite+aiosqlite:///{tmp_path / 'outbox.db'}",
            ),
            outbox_handler=flaky_handler,
        )
        assert await runtime._publish_outbox_batch() == 0
        assert delivered == []

        async with maker() as session:
            rows = list(
                (await session.scalars(select(OutboxEvent).order_by(OutboxEvent.sequence))).all()
            )
            assert [row.publish_attempts for row in rows] == [1, 0]
            assert all(row.published_at is None for row in rows)

        assert await runtime._publish_outbox_batch() == 2
        assert delivered == [1, 2]

        async with maker() as session:
            rows = list(
                (await session.scalars(select(OutboxEvent).order_by(OutboxEvent.sequence))).all()
            )
            assert [row.publish_attempts for row in rows] == [2, 1]
            assert all(row.published_at is not None for row in rows)
    finally:
        await engine.dispose()
