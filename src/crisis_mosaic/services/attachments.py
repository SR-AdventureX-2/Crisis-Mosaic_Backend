from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..models import Attachment
from ..utils import isoformat, utcnow
from .qiniu import sign_download_url

_NO_TEXT_VISION_PREFIX = "[vision_policy:no_text_v1]\n"


def _local_attachment_signature(
    attachment_id: str,
    resource: str,
    expires_at: str,
    settings: Settings,
) -> str:
    payload = f"local-proxy:v1:{attachment_id}:{resource}:{expires_at}".encode()
    return hmac.new(
        settings.upload_signing_secret.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()


def sign_local_attachment_url(
    attachment_id: str,
    resource: str,
    *,
    settings: Settings | None = None,
    expires_at: int | None = None,
) -> str:
    if resource not in {"content", "thumbnail"}:
        raise ValueError("unsupported local attachment resource")
    settings = settings or get_settings()
    deadline = expires_at
    if deadline is None:
        deadline = int((utcnow() + timedelta(minutes=settings.signed_download_minutes)).timestamp())
    deadline_text = str(deadline)
    signature = _local_attachment_signature(
        attachment_id,
        resource,
        deadline_text,
        settings,
    )
    prefix = settings.api_prefix.rstrip("/")
    return f"{prefix}/uploads/signed/{deadline_text}/{signature}/{attachment_id}/{resource}"


def verify_local_attachment_url(
    attachment_id: str,
    resource: str,
    expires_at: str,
    signature: str,
    *,
    settings: Settings | None = None,
) -> bool:
    settings = settings or get_settings()
    valid_deadline = expires_at.isascii() and expires_at.isdecimal() and len(expires_at) <= 12
    signing_deadline = expires_at if valid_deadline else "0"
    expected = _local_attachment_signature(
        attachment_id,
        resource,
        signing_deadline,
        settings,
    )
    signature_matches = hmac.compare_digest(signature.encode(), expected.encode())
    if not valid_deadline:
        return False
    return signature_matches and int(expires_at) > int(utcnow().timestamp())


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
        content_url = (
            sign_local_attachment_url(attachment.id, "content", settings=settings)
            if state == "ready"
            else None
        )
        thumbnail_url = (
            sign_local_attachment_url(attachment.id, "thumbnail", settings=settings)
            if state == "ready"
            else None
        )
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
        "ocr_status": "not_applicable",
        "vision_status": attachment.vision_status,
        "ocr_text": None,
        "vision_summary": (
            attachment.vision_summary.removeprefix(_NO_TEXT_VISION_PREFIX)
            if attachment.vision_summary
            and attachment.vision_summary.startswith(_NO_TEXT_VISION_PREFIX)
            else None
        ),
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
