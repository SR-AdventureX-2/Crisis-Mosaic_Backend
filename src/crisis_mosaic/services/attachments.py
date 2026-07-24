from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..models import Attachment
from ..utils import isoformat
from .qiniu import sign_download_url


def attachment_state(attachment: Attachment) -> str:
    if attachment.rejection_reason:
        return "rejected"
    if (
        attachment.metadata_status == "ready"
        and attachment.malware_scan_status == "clean"
        and (attachment.sanitized_path or attachment.object_key)
    ):
        return "ready"
    if attachment.uploaded_at:
        return "processing"
    return "pending"


def serialize_attachment(attachment: Attachment) -> dict[str, Any]:
    settings = get_settings()
    state = attachment_state(attachment)
    if attachment.storage_provider == "local_proxy":
        content_url = f"/api/v1/uploads/{attachment.id}/content" if state == "ready" else None
        thumbnail_url = f"/api/v1/uploads/{attachment.id}/thumbnail" if state == "ready" else None
    elif attachment.storage_provider == "qiniu_kodo":
        content_url = None
        thumbnail_url = None
        if state == "ready" and attachment.object_key:
            base = settings.qiniu_public_base_url.rstrip("/")
            ttl_seconds = settings.signed_download_minutes * 60
            if attachment.media_type == "video":
                thumbnail_raw = f"{base}/{attachment.object_key}?vframe/jpg/offset/1"
            else:
                thumbnail_raw = f"{base}/{attachment.object_key}?imageView2/2/w/640/h/640"
            content_url = sign_download_url(
                f"{base}/{attachment.object_key}",
                ttl_seconds=ttl_seconds,
                settings=settings,
            )
            thumbnail_url = sign_download_url(
                thumbnail_raw,
                ttl_seconds=ttl_seconds,
                settings=settings,
            )
    else:
        base = settings.qiniu_public_base_url.rstrip("/")
        content_url = (
            f"{base}/{attachment.object_key}?signature=mock&ttl={settings.signed_download_minutes}"
            if state == "ready" and attachment.object_key
            else None
        )
        thumbnail_url = (
            f"{base}/{attachment.object_key}.cover.jpg?signature=mock"
            if state == "ready" and attachment.object_key
            else None
        )
    return {
        "attachment_id": attachment.id,
        "incident_id": attachment.incident_id,
        "report_id": attachment.report_id,
        "directed_answer_id": attachment.directed_answer_id,
        "status": state,
        "media_type": attachment.media_type,
        "storage_provider": attachment.storage_provider,
        "object_key": attachment.object_key,
        "mime_type": attachment.mime_type,
        "size_bytes": attachment.size_bytes,
        "sha256": attachment.sha256,
        "width": attachment.width,
        "height": attachment.height,
        "duration_ms": attachment.duration_ms,
        "processing_progress": attachment.processing_progress,
        "duplicate_of_attachment_id": attachment.duplicate_of_attachment_id,
        "source_cluster_id": attachment.source_cluster_id,
        "metadata_status": attachment.metadata_status,
        "malware_scan_status": attachment.malware_scan_status,
        "ocr_status": attachment.ocr_status,
        "vision_status": attachment.vision_status,
        "ocr_text": attachment.ocr_text,
        "vision_summary": attachment.vision_summary,
        "transcript_status": attachment.transcript_status,
        "transcode_status": attachment.transcode_status,
        "keyframe_status": attachment.keyframe_status,
        "rejection_reason": attachment.rejection_reason,
        "content_url": content_url,
        "thumbnail_url": thumbnail_url,
        "created_at": isoformat(attachment.created_at),
        "uploaded_at": isoformat(attachment.uploaded_at),
    }


async def attachments_by_report(
    session: AsyncSession,
    report_ids: Sequence[str],
) -> dict[str, list[Attachment]]:
    if not report_ids:
        return {}
    attachments = list(
        (
            await session.scalars(
                select(Attachment)
                .where(Attachment.report_id.in_(report_ids))
                .order_by(Attachment.created_at, Attachment.id)
            )
        ).all()
    )
    result: dict[str, list[Attachment]] = {report_id: [] for report_id in report_ids}
    for attachment in attachments:
        if attachment.report_id is not None:
            result.setdefault(attachment.report_id, []).append(attachment)
    return result


async def attachments_by_answer(
    session: AsyncSession,
    answer_ids: Sequence[str],
) -> dict[str, list[Attachment]]:
    if not answer_ids:
        return {}
    attachments = list(
        (
            await session.scalars(
                select(Attachment)
                .where(Attachment.directed_answer_id.in_(answer_ids))
                .order_by(Attachment.created_at, Attachment.id)
            )
        ).all()
    )
    result: dict[str, list[Attachment]] = {answer_id: [] for answer_id in answer_ids}
    for attachment in attachments:
        if attachment.directed_answer_id is not None:
            result.setdefault(attachment.directed_answer_id, []).append(attachment)
    return result
