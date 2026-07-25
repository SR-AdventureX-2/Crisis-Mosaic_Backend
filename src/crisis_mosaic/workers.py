from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import or_, select

from .config import Settings, get_settings
from .db import session_factory, write_lock
from .models import Attachment, BackgroundJob, Incident, OutboxEvent
from .observability import (
    BACKGROUND_JOB_ATTEMPTS,
    OUTBOX_DELIVERIES,
    observe_outbox_delivery,
)
from .services.events import emit_event, record_audit
from .utils import as_utc, utcnow

logger = logging.getLogger(__name__)
OutboxHandler = Callable[[dict[str, Any]], Awaitable[None]]


async def _default_outbox_handler(envelope: dict[str, Any]) -> None:
    # Delayed import avoids a dependency cycle and lets the worker run in CLI/tests.
    from .realtime import hub

    await hub.publish(envelope)


class WorkerRuntime:
    """Single-process durable job runner and SQLite outbox dispatcher."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        outbox_handler: OutboxHandler | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.outbox_handler = outbox_handler or _default_outbox_handler
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[None]] = []

    @property
    def running(self) -> bool:
        return any(not task.done() for task in self._tasks)

    async def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._tasks = [
            asyncio.create_task(self._job_loop(), name="crisis-mosaic-jobs"),
            asyncio.create_task(self._outbox_loop(), name="crisis-mosaic-outbox"),
            asyncio.create_task(self._notification_loop(), name="crisis-mosaic-push"),
            asyncio.create_task(self._retention_loop(), name="crisis-mosaic-retention"),
        ]

    async def stop(self) -> None:
        self._stop.set()
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    async def _job_loop(self) -> None:
        while not self._stop.is_set():
            try:
                job_id = await self._claim_job()
                if job_id:
                    await self._execute_job(job_id)
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("persistent job loop failed")
            await self._wait(self.settings.job_poll_seconds)

    async def _outbox_loop(self) -> None:
        while not self._stop.is_set():
            try:
                published = await self._publish_outbox_batch()
                if published:
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("outbox dispatch failed")
            await self._wait(self.settings.job_poll_seconds)

    async def _notification_loop(self) -> None:
        while not self._stop.is_set():
            try:
                from .services.notifications import deliver_notifications_batch

                delivered = await deliver_notifications_batch(self.settings)
                if delivered:
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("notification dispatch failed")
            await self._wait(self.settings.job_poll_seconds)

    async def _retention_loop(self) -> None:
        while not self._stop.is_set():
            try:
                from .services.retention import cleanup_retention_once

                result = await cleanup_retention_once(self.settings)
                if any(result.as_dict().values()):
                    logger.info("retention cleanup completed: %s", result.as_dict())
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("retention cleanup failed")
            await self._wait(self.settings.retention_cleanup_hours * 60 * 60)

    async def _wait(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=max(0.05, seconds))
        except TimeoutError:
            pass

    async def _claim_job(self) -> str | None:
        now = utcnow()
        async with write_lock:
            async with session_factory()() as session:
                job = await session.scalar(
                    select(BackgroundJob)
                    .where(
                        or_(
                            (
                                BackgroundJob.status.in_(("queued", "retry"))
                                & (BackgroundJob.run_after <= now)
                            ),
                            (
                                (BackgroundJob.status == "running")
                                & (BackgroundJob.lease_expires_at.is_not(None))
                                & (BackgroundJob.lease_expires_at <= now)
                            ),
                        )
                    )
                    .order_by(BackgroundJob.run_after, BackgroundJob.created_at)
                    .limit(1)
                )
                if not job:
                    return None
                job.status = "running"
                job.attempts += 1
                job.lease_expires_at = now + timedelta(seconds=self.settings.job_lease_seconds)
                job.updated_at = now
                await session.commit()
                return job.id

    async def _execute_job(self, job_id: str) -> None:
        async with session_factory()() as session:
            job = await session.get(BackgroundJob, job_id)
            if not job or job.status != "running":
                return
            try:
                if job.job_type == "attachment.process":
                    from .services.uploads import process_attachment

                    attachment = await process_attachment(
                        session, str(job.payload["attachment_id"]), self.settings
                    )
                    with session.no_autoflush:
                        incident = await session.get(Incident, attachment.incident_id)
                    async with write_lock:
                        if incident is not None:
                            await record_audit(
                                session,
                                actor=None,
                                incident_id=incident.id,
                                action="attachment.ready",
                                resource_type="attachment",
                                resource_id=attachment.id,
                                after={
                                    "status": "ready",
                                    "mime_type": attachment.mime_type,
                                    "sha256": attachment.sha256,
                                },
                            )
                            await emit_event(
                                session,
                                incident=incident,
                                event_type="attachment.ready",
                                resource_type="attachment",
                                resource_id=attachment.id,
                                resource_revision=1,
                                visibility="owner",
                                owner_device_id=attachment.uploader_device_id,
                                payload={"attachment_id": attachment.id, "status": "ready"},
                            )
                        await session.commit()
                elif job.job_type == "media.process":
                    from .services.uploads import process_remote_media

                    attachment = await process_remote_media(
                        session,
                        str(job.payload["attachment_id"]),
                        self.settings,
                    )
                    with session.no_autoflush:
                        incident = await session.get(Incident, attachment.incident_id)
                    async with write_lock:
                        if incident is not None:
                            await record_audit(
                                session,
                                actor=None,
                                incident_id=incident.id,
                                action="attachment.ready",
                                resource_type="attachment",
                                resource_id=attachment.id,
                                after={
                                    "status": "ready",
                                    "mime_type": attachment.mime_type,
                                    "sha256": attachment.sha256,
                                    "storage_provider": attachment.storage_provider,
                                },
                            )
                            await emit_event(
                                session,
                                incident=incident,
                                event_type="attachment.ready",
                                resource_type="attachment",
                                resource_id=attachment.id,
                                resource_revision=1,
                                visibility="owner",
                                owner_device_id=attachment.uploader_device_id,
                                payload={"attachment_id": attachment.id, "status": "ready"},
                            )
                        await session.commit()
                elif job.job_type == "ai.analysis":
                    from .services.ai import process_analysis

                    await process_analysis(session, str(job.payload["analysis_id"]), self.settings)
                elif job.job_type == "blind_spot.detect":
                    from .services.report_observations import run_report_blind_spot_detection

                    async with write_lock:
                        due_at_value = job.payload.get("due_at")
                        due_at = (
                            as_utc(datetime.fromisoformat(due_at_value.replace("Z", "+00:00")))
                            if isinstance(due_at_value, str)
                            else as_utc(job.run_after)
                        )
                        if utcnow() < due_at:
                            job.status = "queued"
                            job.attempts = max(0, job.attempts - 1)
                            job.run_after = due_at
                            job.lease_expires_at = None
                            job.last_error = "deferred until the fixed blind-spot due time"
                            job.updated_at = utcnow()
                            await session.commit()
                            return
                        grace_minutes_value = job.payload.get("grace_minutes")
                        await run_report_blind_spot_detection(
                            session,
                            incident_id=str(job.payload["incident_id"]),
                            fragment_id=str(job.payload["fragment_id"]),
                            fragment_revision=int(job.payload["fragment_revision"]),
                            due_at=due_at,
                            grace_minutes=(
                                int(grace_minutes_value)
                                if grace_minutes_value is not None
                                else None
                            ),
                            settings=self.settings,
                        )
                        await session.commit()
                else:
                    raise RuntimeError(f"unknown background job type: {job.job_type}")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Domain handlers may deliberately persist a rejected/failed resource.
                try:
                    async with write_lock:
                        if job.job_type in {"attachment.process", "media.process"}:
                            rejected_attachment = await session.get(
                                Attachment,
                                str(job.payload.get("attachment_id", "")),
                            )
                            if rejected_attachment is not None:
                                incident = await session.get(
                                    Incident, rejected_attachment.incident_id
                                )
                                if incident is not None:
                                    await record_audit(
                                        session,
                                        actor=None,
                                        incident_id=incident.id,
                                        action="attachment.rejected",
                                        resource_type="attachment",
                                        resource_id=rejected_attachment.id,
                                        after={
                                            "status": "rejected",
                                            "reason": rejected_attachment.rejection_reason
                                            or type(exc).__name__,
                                        },
                                    )
                                    await emit_event(
                                        session,
                                        incident=incident,
                                        event_type="attachment.rejected",
                                        resource_type="attachment",
                                        resource_id=rejected_attachment.id,
                                        resource_revision=1,
                                        visibility="owner",
                                        owner_device_id=rejected_attachment.uploader_device_id,
                                        payload={
                                            "attachment_id": rejected_attachment.id,
                                            "status": "rejected",
                                            "reason": rejected_attachment.rejection_reason
                                            or type(exc).__name__,
                                        },
                                    )
                        await session.commit()
                except Exception:
                    await session.rollback()
                await self._finish_job(job_id, error=exc)
            else:
                await self._finish_job(job_id)

    async def _finish_job(self, job_id: str, error: Exception | None = None) -> None:
        async with write_lock:
            async with session_factory()() as session:
                job = await session.get(BackgroundJob, job_id)
                if not job:
                    return
                if job.status != "running":
                    return
                job.lease_expires_at = None
                job.updated_at = utcnow()
                if error is None:
                    job.status = "succeeded"
                    job.last_error = None
                    outcome = "succeeded"
                else:
                    job.last_error = f"{type(error).__name__}: {error}"[:4000]
                    if job.attempts >= job.max_attempts:
                        job.status = "failed"
                        outcome = "failed"
                    else:
                        job.status = "retry"
                        outcome = "retry"
                        delays = (1, 5, 30)
                        job.run_after = utcnow() + timedelta(
                            seconds=delays[min(job.attempts - 1, len(delays) - 1)]
                        )
                BACKGROUND_JOB_ATTEMPTS.labels(
                    job_type=job.job_type,
                    outcome=outcome,
                ).inc()
                await session.commit()

    async def _publish_outbox_batch(self) -> int:
        async with session_factory()() as session:
            rows = list(
                (
                    await session.scalars(
                        select(OutboxEvent)
                        .where(OutboxEvent.published_at.is_(None))
                        .order_by(OutboxEvent.incident_id, OutboxEvent.sequence)
                        .limit(100)
                    )
                ).all()
            )
        published = 0
        for row in rows:
            try:
                await self.outbox_handler(row.payload)
            except asyncio.CancelledError:
                raise
            except Exception:
                OUTBOX_DELIVERIES.labels(outcome="failed").inc()
                async with write_lock:
                    async with session_factory()() as session:
                        current = await session.get(OutboxEvent, row.id)
                        if current:
                            current.publish_attempts += 1
                            await session.commit()
                logger.exception("failed to publish outbox event %s", row.id)
                break
            async with write_lock:
                async with session_factory()() as session:
                    current = await session.get(OutboxEvent, row.id)
                    if current and current.published_at is None:
                        current.publish_attempts += 1
                        current.published_at = utcnow()
                        await session.commit()
            published += 1
            observe_outbox_delivery(row.payload)
        return published


_runtime: WorkerRuntime | None = None


async def start_workers(
    settings: Settings | None = None,
    *,
    outbox_handler: OutboxHandler | None = None,
) -> WorkerRuntime:
    global _runtime
    if _runtime is None:
        _runtime = WorkerRuntime(settings, outbox_handler=outbox_handler)
    await _runtime.start()
    return _runtime


async def stop_workers() -> None:
    global _runtime
    if _runtime is not None:
        await _runtime.stop()
        _runtime = None


def get_worker_runtime() -> WorkerRuntime | None:
    return _runtime
