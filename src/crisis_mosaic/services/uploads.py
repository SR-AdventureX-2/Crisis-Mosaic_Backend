from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import json
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import BinaryIO

import filetype  # type: ignore[import-untyped]
import imagehash
from fastapi import UploadFile
from PIL import Image, ImageOps, UnidentifiedImageError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..errors import ApiError
from ..models import Attachment, BackgroundJob, MediaUploadPart, MediaUploadSession
from ..utils import sha256_text, utcnow
from .attachments import attachment_state as attachment_state
from .qiniu import fetch_object_bytes, stat_object

ALLOWED_MIME_FORMATS = {
    "image/jpeg": "JPEG",
    "image/png": "PNG",
    "image/webp": "WEBP",
}
ALLOWED_IMAGE_MIME_TYPES = set(ALLOWED_MIME_FORMATS)
ALLOWED_VIDEO_MIME_TYPES = {"video/mp4", "video/quicktime", "video/webm"}
SAFE_EXIF_TAGS = {271: "make", 272: "model", 306: "datetime", 36867: "captured_at"}


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _video_keyframe_offsets(duration_ms: int) -> list[float]:
    duration_seconds = max(duration_ms / 1000, 0.0)
    candidates = (0.0, duration_seconds / 2, max(0.0, duration_seconds - 0.1))
    return list(dict.fromkeys(round(value, 3) for value in candidates))


def _validated_visual_bytes(content: bytes, settings: Settings) -> bytes:
    Image.MAX_IMAGE_PIXELS = settings.max_image_pixels
    try:
        with Image.open(io.BytesIO(content)) as probe:
            if probe.width * probe.height > settings.max_image_pixels:
                raise ApiError(422, "IMAGE_PIXEL_LIMIT_EXCEEDED", "图片像素数量超过限制")
            probe.verify()
        with Image.open(io.BytesIO(content)) as image:
            image.load()
            normalized = ImageOps.exif_transpose(image).convert("RGB")
            normalized.thumbnail((1280, 1280))
            output = io.BytesIO()
            normalized.save(output, format="JPEG", quality=88, optimize=True)
            return output.getvalue()
    except Image.DecompressionBombError as exc:
        raise ApiError(422, "IMAGE_PIXEL_LIMIT_EXCEEDED", "图片像素数量超过限制") from exc
    except (UnidentifiedImageError, OSError) as exc:
        raise ApiError(422, "IMAGE_DECODE_FAILED", "媒体画面无法安全解码") from exc


def safe_storage_path(root: Path, bucket: str, attachment_id: str, suffix: str) -> Path:
    if not attachment_id.replace("-", "").isalnum():
        raise ApiError(400, "INVALID_ATTACHMENT_ID", "附件标识无效")
    base = (root / bucket).resolve()
    candidate = (base / f"{attachment_id}{suffix}").resolve()
    if base not in candidate.parents:
        raise ApiError(400, "INVALID_STORAGE_PATH", "存储路径无效")
    return candidate


async def create_image_intent(
    session: AsyncSession,
    *,
    incident_id: str,
    uploader_device_id: str,
    file_name: str,
    mime_type: str,
    size_bytes: int,
    expected_sha256: str,
    settings: Settings | None = None,
) -> Attachment:
    settings = settings or get_settings()
    if size_bytes > settings.max_image_bytes:
        raise ApiError(
            413,
            "IMAGE_TOO_LARGE",
            "图片超过大小限制",
            details={"max_bytes": settings.max_image_bytes},
        )
    if mime_type not in ALLOWED_MIME_FORMATS:
        raise ApiError(415, "UNSUPPORTED_IMAGE_TYPE", "仅支持 JPEG、PNG 和 WebP")
    attachment = Attachment(
        incident_id=incident_id,
        uploader_device_id=uploader_device_id,
        file_name=file_name,
        declared_mime_type=mime_type,
        size_bytes=size_bytes,
        expected_sha256=expected_sha256.lower(),
        upload_expires_at=utcnow() + timedelta(minutes=settings.upload_intent_minutes),
    )
    session.add(attachment)
    await session.flush()
    return attachment


def media_policy(settings: Settings | None = None) -> dict[str, int | str]:
    settings = settings or get_settings()
    return {
        "version": settings.media_policy_version,
        "max_file_size_bytes": settings.media_max_file_size_bytes,
        "max_report_total_bytes": settings.media_max_report_total_bytes,
        "max_attachment_count": settings.media_max_attachment_count,
        "max_video_duration_ms": settings.media_max_video_duration_ms,
        "max_parallel_uploads": settings.media_max_parallel_uploads,
        "quota_remaining_bytes": settings.media_max_report_total_bytes,
    }


def _object_suffix(file_name: str, mime_type: str) -> str:
    suffix = Path(file_name).suffix.lower()
    if suffix and len(suffix) <= 12 and all(ch.isalnum() or ch == "." for ch in suffix):
        return suffix
    return {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
        "video/mp4": ".mp4",
        "video/quicktime": ".mov",
        "video/webm": ".webm",
    }.get(mime_type, ".bin")


def _upload_token(*, attachment_id: str, object_key: str, settings: Settings) -> tuple[str, str]:
    if settings.media_storage_provider == "qiniu_kodo":
        policy: dict[str, int | str] = {
            "scope": f"{settings.qiniu_bucket}:{object_key}",
            "deadline": int(
                (utcnow() + timedelta(seconds=settings.qiniu_upload_token_ttl_seconds)).timestamp()
            ),
            "insertOnly": 1,
        }
        if settings.qiniu_callback_url:
            policy.update(
                {
                    "callbackUrl": settings.qiniu_callback_url,
                    "callbackBody": (
                        "key=$(key)&hash=$(etag)&bucket=$(bucket)&"
                        "fsize=$(fsize)&mimeType=$(mimeType)"
                    ),
                    "callbackBodyType": "application/x-www-form-urlencoded",
                }
            )
        encoded_policy = base64.urlsafe_b64encode(
            json.dumps(policy, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).decode("ascii")
        signature = base64.urlsafe_b64encode(
            hmac.new(
                settings.qiniu_secret_key.encode("utf-8"),
                encoded_policy.encode("ascii"),
                hashlib.sha1,
            ).digest()
        ).decode("ascii")
        token = f"{settings.qiniu_access_key}:{signature}:{encoded_policy}"
    else:
        token = secrets.token_urlsafe(48)
    fingerprint = sha256_text(f"{attachment_id}:{object_key}:{token}")[-8:]
    return token, fingerprint


async def create_media_intent(
    session: AsyncSession,
    *,
    incident_id: str,
    uploader_device_id: str,
    media_type: str,
    client_source: str,
    file_name: str,
    mime_type: str,
    size_bytes: int,
    expected_sha256: str,
    duration_ms: int | None,
    resumable_upload: bool,
    settings: Settings | None = None,
) -> tuple[Attachment, dict[str, object], str]:
    settings = settings or get_settings()
    if media_type == "image" and mime_type not in ALLOWED_IMAGE_MIME_TYPES:
        raise ApiError(415, "UNSUPPORTED_IMAGE_TYPE", "仅支持 JPEG、PNG 和 WebP")
    if media_type == "video":
        if not settings.enable_video_upload:
            raise ApiError(501, "VIDEO_UPLOAD_DISABLED", "视频上传尚未开放")
        if mime_type not in ALLOWED_VIDEO_MIME_TYPES:
            raise ApiError(415, "UNSUPPORTED_VIDEO_TYPE", "仅支持 MP4、MOV 和 WebM 视频")
        if duration_ms is not None and duration_ms > settings.media_max_video_duration_ms:
            raise ApiError(
                413,
                "VIDEO_DURATION_EXCEEDED",
                "视频时长超过当前技术策略",
                details={"max_video_duration_ms": settings.media_max_video_duration_ms},
            )
    if size_bytes > settings.media_max_file_size_bytes:
        raise ApiError(
            413,
            "MEDIA_TOO_LARGE",
            "文件超过当前技术策略",
            details={"max_file_size_bytes": settings.media_max_file_size_bytes},
        )
    active_sessions = int(
        await session.scalar(
            select(func.count(MediaUploadSession.id)).where(
                MediaUploadSession.resident_device_id == uploader_device_id,
                MediaUploadSession.status == "active",
                MediaUploadSession.expires_at > utcnow(),
            )
        )
        or 0
    )
    if active_sessions >= settings.media_single_device_active_sessions:
        raise ApiError(
            429,
            "MEDIA_ACTIVE_SESSION_LIMIT",
            "当前设备未完成上传会话过多",
            details={"max_active_sessions": settings.media_single_device_active_sessions},
        )
    policy = media_policy(settings)
    attachment = Attachment(
        incident_id=incident_id,
        uploader_device_id=uploader_device_id,
        file_name=file_name,
        declared_mime_type=mime_type,
        media_type=media_type,
        client_source=client_source,
        storage_provider=settings.media_storage_provider,
        bucket=settings.qiniu_bucket,
        mime_type=None,
        size_bytes=size_bytes,
        expected_sha256=expected_sha256.lower(),
        duration_ms=duration_ms,
        metadata_status="pending",
        malware_scan_status="pending",
        ocr_status="not_applicable",
        vision_status="pending",
        transcript_status="pending" if media_type == "video" else "not_applicable",
        transcode_status="pending" if media_type == "video" else "not_applicable",
        keyframe_status="pending" if media_type == "video" else "not_applicable",
        policy_snapshot=policy,
        upload_expires_at=utcnow() + timedelta(seconds=settings.qiniu_upload_token_ttl_seconds),
    )
    session.add(attachment)
    await session.flush()
    object_key = (
        f"quarantine/incidents/{incident_id}/attachments/"
        f"{attachment.id}{_object_suffix(file_name, mime_type)}"
    )
    attachment.object_key = object_key
    token, fingerprint = _upload_token(
        attachment_id=attachment.id,
        object_key=object_key,
        settings=settings,
    )
    mode = "resumable" if resumable_upload else "form"
    upload: dict[str, object] = {
        "mode": mode,
        "method": "KODO_RESUMABLE_V2" if mode == "resumable" else "KODO_FORM",
        "url": settings.qiniu_upload_host,
        "fields": {"token": token, "key": object_key},
        "recommended_chunk_size_bytes": settings.media_recommended_chunk_size_bytes,
    }
    if mode == "resumable":
        upload["session_endpoint"] = f"/api/v1/uploads/{attachment.id}/resumable-sessions"
    else:
        upload["form_field"] = "file"
    return attachment, {"policy": policy, "upload": upload}, fingerprint


def _session_parts_payload(parts: list[MediaUploadPart]) -> list[dict[str, object]]:
    return [
        {
            "part_number": part.part_number,
            "offset": part.offset,
            "size_bytes": part.size_bytes,
            "etag": part.etag,
            "sha256": part.sha256,
        }
        for part in sorted(parts, key=lambda item: item.part_number)
    ]


async def create_resumable_session(
    session: AsyncSession,
    *,
    attachment: Attachment,
    device_id: str,
    size_bytes: int,
    sha256: str,
    client_checkpoint_id: str | None,
    settings: Settings | None = None,
) -> tuple[MediaUploadSession, str]:
    settings = settings or get_settings()
    if attachment.uploader_device_id != device_id:
        raise ApiError(403, "ATTACHMENT_ACCESS_DENIED", "无权访问其他设备的附件")
    if attachment.uploaded_at is not None:
        raise ApiError(409, "UPLOAD_ALREADY_FINISHED", "该附件内容已经上传")
    if attachment.size_bytes != size_bytes or attachment.expected_sha256 != sha256.lower():
        raise ApiError(422, "UPLOAD_FINGERPRINT_MISMATCH", "上传会话文件指纹不匹配")
    token, fingerprint = _upload_token(
        attachment_id=attachment.id,
        object_key=attachment.object_key or "",
        settings=settings,
    )
    row = MediaUploadSession(
        attachment_id=attachment.id,
        resident_device_id=device_id,
        provider=attachment.storage_provider,
        mode="resumable",
        object_key=attachment.object_key or "",
        upload_token_fingerprint=fingerprint,
        token_expires_at=utcnow() + timedelta(seconds=settings.qiniu_upload_token_ttl_seconds),
        chunk_size_bytes=settings.media_recommended_chunk_size_bytes,
        max_parallel_uploads=settings.media_max_parallel_uploads,
        expected_size_bytes=size_bytes,
        expected_sha256=sha256.lower(),
        client_checkpoint_id=client_checkpoint_id,
        policy_snapshot=attachment.policy_snapshot or media_policy(settings),
        expires_at=utcnow() + timedelta(hours=settings.media_upload_session_hours),
    )
    session.add(row)
    await session.flush()
    return row, token


async def record_resumable_part(
    session: AsyncSession,
    *,
    upload_session: MediaUploadSession,
    part_number: int,
    offset: int,
    size_bytes: int,
    etag: str,
    sha256: str | None,
) -> MediaUploadPart:
    if upload_session.status != "active":
        raise ApiError(409, "UPLOAD_SESSION_NOT_ACTIVE", "上传会话不可写入分片")
    if offset + size_bytes > upload_session.expected_size_bytes:
        raise ApiError(422, "UPLOAD_PART_OUT_OF_RANGE", "分片范围超出文件大小")
    existing = await session.scalar(
        select(MediaUploadPart).where(
            MediaUploadPart.upload_session_id == upload_session.id,
            MediaUploadPart.part_number == part_number,
        )
    )
    if existing is not None:
        if (
            existing.offset != offset
            or existing.size_bytes != size_bytes
            or existing.etag != etag
            or existing.sha256 != sha256
        ):
            raise ApiError(409, "UPLOAD_PART_CONFLICT", "同一分片号已有不同检查点")
        return existing
    part = MediaUploadPart(
        upload_session_id=upload_session.id,
        part_number=part_number,
        offset=offset,
        size_bytes=size_bytes,
        etag=etag,
        sha256=sha256,
    )
    session.add(part)
    await session.flush()
    upload_session.confirmed_bytes = int(
        await session.scalar(
            select(func.coalesce(func.sum(MediaUploadPart.size_bytes), 0)).where(
                MediaUploadPart.upload_session_id == upload_session.id
            )
        )
        or 0
    )
    return part


async def resumable_session_payload(
    session: AsyncSession,
    upload_session: MediaUploadSession,
    *,
    upload_token: str | None = None,
) -> dict[str, object]:
    parts = list(
        (
            await session.scalars(
                select(MediaUploadPart).where(
                    MediaUploadPart.upload_session_id == upload_session.id
                )
            )
        ).all()
    )
    confirmed = _session_parts_payload(parts)
    missing: list[dict[str, int]] = []
    if upload_session.expected_size_bytes:
        covered = {(part.offset, part.offset + part.size_bytes) for part in parts}
        cursor = 0
        for start, end in sorted(covered):
            if cursor < start:
                missing.append({"offset": cursor, "size_bytes": start - cursor})
            cursor = max(cursor, end)
        if cursor < upload_session.expected_size_bytes:
            missing.append(
                {
                    "offset": cursor,
                    "size_bytes": upload_session.expected_size_bytes - cursor,
                }
            )
    payload: dict[str, object] = {
        "session_id": upload_session.id,
        "attachment_id": upload_session.attachment_id,
        "provider": upload_session.provider,
        "object_key": upload_session.object_key,
        "status": upload_session.status,
        "chunk_size_bytes": upload_session.chunk_size_bytes,
        "max_parallel_uploads": upload_session.max_parallel_uploads,
        "confirmed_bytes": upload_session.confirmed_bytes,
        "confirmed_parts": confirmed,
        "missing_parts": missing,
        "policy": upload_session.policy_snapshot,
        "token_expires_at": upload_session.token_expires_at,
        "expires_at": upload_session.expires_at,
    }
    if upload_token is not None:
        payload["upload"] = {
            "mode": "resumable",
            "method": "KODO_RESUMABLE_V2",
            "url": get_settings().qiniu_upload_host,
            "fields": {"token": upload_token, "key": upload_session.object_key},
        }
    return payload


async def renew_resumable_session(
    upload_session: MediaUploadSession,
    settings: Settings | None = None,
) -> str:
    settings = settings or get_settings()
    if upload_session.status != "active":
        raise ApiError(409, "UPLOAD_SESSION_NOT_ACTIVE", "上传会话不可续签")
    if upload_session.expires_at < utcnow():
        raise ApiError(410, "UPLOAD_SESSION_EXPIRED", "上传会话已过期")
    token, fingerprint = _upload_token(
        attachment_id=upload_session.attachment_id,
        object_key=upload_session.object_key,
        settings=settings,
    )
    upload_session.upload_token_fingerprint = fingerprint
    upload_session.token_expires_at = utcnow() + timedelta(
        seconds=settings.qiniu_upload_token_ttl_seconds
    )
    return token


async def complete_remote_upload(
    session: AsyncSession,
    *,
    attachment: Attachment,
    upload_session_id: str | None,
    object_key: str | None,
    etag: str | None,
    size_bytes: int | None,
    parts: list[object],
) -> BackgroundJob:
    if attachment.object_key and object_key and attachment.object_key != object_key:
        raise ApiError(422, "UPLOAD_OBJECT_KEY_MISMATCH", "对象 Key 与上传意图不一致")
    if size_bytes is not None and size_bytes != attachment.size_bytes:
        raise ApiError(422, "UPLOAD_SIZE_MISMATCH", "上传内容大小与声明不一致")
    if upload_session_id is not None:
        upload_session = await session.get(MediaUploadSession, upload_session_id)
        if (
            upload_session is None
            or upload_session.attachment_id != attachment.id
            or upload_session.status != "active"
        ):
            raise ApiError(404, "UPLOAD_SESSION_NOT_FOUND", "上传会话不存在或不可用")
        stored_parts = list(
            (
                await session.scalars(
                    select(MediaUploadPart).where(
                        MediaUploadPart.upload_session_id == upload_session.id
                    )
                )
            ).all()
        )
        stored_size = sum(part.size_bytes for part in stored_parts)
        declared_size = sum(getattr(part, "size_bytes", 0) for part in parts)
        if stored_size != attachment.size_bytes or declared_size not in {0, stored_size}:
            raise ApiError(422, "UPLOAD_PARTS_INCOMPLETE", "上传分片尚未完整确认")
        upload_session.status = "completed"
    attachment.etag = etag
    attachment.sha256 = attachment.expected_sha256
    attachment.uploaded_at = utcnow()
    attachment.original_path = attachment.object_key
    attachment.metadata_status = "pending"
    attachment.malware_scan_status = "pending"
    job = BackgroundJob(
        job_type="media.process",
        payload={"attachment_id": attachment.id},
        max_attempts=get_settings().job_max_attempts,
    )
    session.add(job)
    return job


async def process_remote_media(
    session: AsyncSession,
    attachment_id: str,
    settings: Settings | None = None,
) -> Attachment:
    settings = settings or get_settings()
    attachment = await session.get(Attachment, attachment_id)
    if attachment is None:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    if not attachment.uploaded_at or not attachment.object_key:
        raise ApiError(409, "UPLOAD_NOT_FINISHED", "上传尚未完成")
    is_real_kodo = attachment.storage_provider == "qiniu_kodo"
    if is_real_kodo:
        # Verify the object truly exists in Kodo and adopt its real metadata.
        stat = await stat_object(attachment.object_key, settings)
        remote_size = int(stat.get("fsize") or 0)
        if remote_size != attachment.size_bytes:
            attachment.metadata_status = "rejected"
            attachment.rejection_reason = "UPLOAD_SIZE_MISMATCH"
            raise ApiError(
                422,
                "UPLOAD_SIZE_MISMATCH",
                "七牛云对象大小与上传声明不一致",
                details={"declared": attachment.size_bytes, "actual": remote_size},
            )
        attachment.etag = str(stat.get("hash") or attachment.etag or "") or None
        actual_mime_type = str(stat.get("mimeType") or "").split(";", 1)[0].strip().lower()
        allowed_types = (
            ALLOWED_IMAGE_MIME_TYPES
            if attachment.media_type == "image"
            else ALLOWED_VIDEO_MIME_TYPES
        )
        if (
            actual_mime_type != attachment.declared_mime_type
            or actual_mime_type not in allowed_types
        ):
            attachment.metadata_status = "rejected"
            attachment.rejection_reason = "DECLARED_MIME_MISMATCH"
            raise ApiError(415, "DECLARED_MIME_MISMATCH", "七牛云对象 MIME 与上传声明不一致")
        attachment.mime_type = actual_mime_type
    else:
        attachment.mime_type = attachment.declared_mime_type
    attachment.malware_scan_status = "clean"
    attachment.rejection_reason = None
    public_base = settings.qiniu_public_base_url.rstrip("/")
    if attachment.media_type == "image":
        attachment.ocr_status = "not_applicable"
        attachment.ocr_text = None
        attachment.vision_status = "unavailable"
        if is_real_kodo:
            attachment.vision_summary = None
            fetch_key = attachment.object_key
            verify_original_sha256 = attachment.size_bytes <= settings.max_image_bytes
            if not verify_original_sha256:
                fetch_key = (
                    f"{attachment.object_key}?imageView2/2/w/1280/h/1280/format/jpg"
                )
                attachment.sha256 = None
            image_bytes = await fetch_object_bytes(
                fetch_key,
                max_bytes=settings.max_image_bytes,
                settings=settings,
            )
            if verify_original_sha256:
                actual_sha256 = hashlib.sha256(image_bytes).hexdigest()
                if actual_sha256 != attachment.expected_sha256:
                    attachment.metadata_status = "rejected"
                    attachment.rejection_reason = "UPLOAD_HASH_MISMATCH"
                    raise ApiError(
                        422,
                        "UPLOAD_HASH_MISMATCH",
                        "七牛云对象哈希与声明不一致",
                    )
                attachment.sha256 = actual_sha256
            try:
                image_bytes = await asyncio.to_thread(
                    _validated_visual_bytes,
                    image_bytes,
                    settings,
                )
            except ApiError as exc:
                attachment.metadata_status = "rejected"
                attachment.rejection_reason = exc.code
                raise
            try:
                from .ai import enrich_attachment

                await enrich_attachment(session, attachment, settings, image_bytes=image_bytes)
            except Exception as exc:
                # Visual interpretation is degradable after hash/MIME/safe-decode checks pass.
                attachment.ocr_status = "not_applicable"
                attachment.ocr_text = None
                attachment.vision_status = "failed"
                attachment.vision_summary = f"AI enrichment unavailable: {type(exc).__name__}"
        else:
            attachment.vision_summary = None
    else:
        attachment.ocr_status = "not_applicable"
        attachment.ocr_text = None
        attachment.vision_status = "unavailable"
        attachment.transcript_status = "unavailable"
        if is_real_kodo:
            try:
                avinfo_bytes = await fetch_object_bytes(
                    f"{attachment.object_key}?avinfo",
                    max_bytes=1024 * 1024,
                    settings=settings,
                )
            except ApiError as exc:
                attachment.metadata_status = "rejected"
                attachment.keyframe_status = "failed"
                attachment.rejection_reason = exc.code
                raise
            try:
                avinfo = json.loads(avinfo_bytes)
                duration_ms = int(float(avinfo["format"]["duration"]) * 1000)
                streams = avinfo.get("streams", [])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                attachment.metadata_status = "rejected"
                attachment.keyframe_status = "failed"
                attachment.rejection_reason = "VIDEO_METADATA_INVALID"
                raise ApiError(422, "VIDEO_METADATA_INVALID", "无法读取可信的视频元数据") from exc
            if duration_ms <= 0 or not any(
                isinstance(stream, dict) and stream.get("codec_type") == "video"
                for stream in streams
            ):
                attachment.metadata_status = "rejected"
                attachment.keyframe_status = "failed"
                attachment.rejection_reason = "VIDEO_METADATA_INVALID"
                raise ApiError(422, "VIDEO_METADATA_INVALID", "上传对象不包含可读取的视频流")
            if duration_ms > settings.media_max_video_duration_ms:
                attachment.metadata_status = "rejected"
                attachment.keyframe_status = "failed"
                attachment.rejection_reason = "VIDEO_DURATION_EXCEEDED"
                raise ApiError(
                    413,
                    "VIDEO_DURATION_EXCEEDED",
                    "视频时长超过当前技术策略",
                    details={"max_video_duration_ms": settings.media_max_video_duration_ms},
                )
            attachment.duration_ms = duration_ms
            keyframes: list[bytes] = []
            for offset in _video_keyframe_offsets(duration_ms):
                try:
                    frame = await fetch_object_bytes(
                        f"{attachment.object_key}?vframe/jpg/offset/{offset:g}",
                        max_bytes=settings.max_image_bytes,
                        settings=settings,
                    )
                except ApiError as exc:
                    attachment.metadata_status = "rejected"
                    attachment.keyframe_status = "failed"
                    attachment.rejection_reason = exc.code
                    raise
                try:
                    keyframes.append(
                        await asyncio.to_thread(_validated_visual_bytes, frame, settings)
                    )
                except ApiError as exc:
                    attachment.metadata_status = "rejected"
                    attachment.keyframe_status = "failed"
                    attachment.rejection_reason = exc.code
                    raise
            if not keyframes:
                attachment.metadata_status = "rejected"
                attachment.keyframe_status = "failed"
                attachment.rejection_reason = "VIDEO_KEYFRAME_UNAVAILABLE"
                raise ApiError(422, "VIDEO_KEYFRAME_UNAVAILABLE", "视频没有可安全读取的关键帧")
            attachment.transcode_status = "ready"
            attachment.keyframe_status = "ready"
            attachment.cover_path = f"{public_base}/{attachment.object_key}?vframe/jpg/offset/0"
            attachment.preview_path = f"{public_base}/{attachment.object_key}"
            attachment.vision_summary = None
        else:
            attachment.transcode_status = "unavailable"
            attachment.keyframe_status = "unavailable"
            attachment.cover_path = None
            attachment.preview_path = f"{public_base}/{attachment.object_key}"
            attachment.vision_summary = None
    attachment.metadata_status = "ready"
    attachment.processing_progress = 100
    return attachment


async def stream_upload_to_quarantine(
    attachment: Attachment,
    source: UploadFile | BinaryIO,
    settings: Settings | None = None,
) -> Path:
    settings = settings or get_settings()
    if _aware(attachment.upload_expires_at) < utcnow():
        raise ApiError(410, "UPLOAD_INTENT_EXPIRED", "上传意图已过期")
    settings.ensure_directories()
    target = safe_storage_path(settings.storage_root, "quarantine", attachment.id, ".upload")
    digest = hashlib.sha256()
    total = 0
    with target.open("wb") as output:
        while True:
            if isinstance(source, UploadFile):
                chunk = await source.read(64 * 1024)
            else:
                chunk = await asyncio.to_thread(source.read, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > settings.max_image_bytes or total > attachment.size_bytes:
                output.close()
                target.unlink(missing_ok=True)
                raise ApiError(413, "IMAGE_TOO_LARGE", "上传内容超过声明或服务端大小限制")
            digest.update(chunk)
            output.write(chunk)
    if total != attachment.size_bytes:
        target.unlink(missing_ok=True)
        raise ApiError(
            422,
            "UPLOAD_SIZE_MISMATCH",
            "上传内容大小与声明不一致",
            details={"declared": attachment.size_bytes, "actual": total},
        )
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != attachment.expected_sha256:
        target.unlink(missing_ok=True)
        raise ApiError(
            422,
            "UPLOAD_HASH_MISMATCH",
            "上传内容哈希与声明不一致",
            details={"expected": attachment.expected_sha256, "actual": actual_sha256},
        )
    attachment.sha256 = actual_sha256
    attachment.original_path = str(target)
    attachment.uploaded_at = utcnow()
    return target


async def stream_request_to_quarantine(
    attachment: Attachment,
    chunks: AsyncIterator[bytes],
    settings: Settings | None = None,
) -> Path:
    settings = settings or get_settings()
    if _aware(attachment.upload_expires_at) < utcnow():
        raise ApiError(410, "UPLOAD_INTENT_EXPIRED", "上传意图已过期")
    settings.ensure_directories()
    target = safe_storage_path(settings.storage_root, "quarantine", attachment.id, ".upload")
    digest = hashlib.sha256()
    total = 0
    with target.open("wb") as output:
        async for chunk in chunks:
            if not chunk:
                continue
            total += len(chunk)
            if total > settings.max_image_bytes or total > attachment.size_bytes:
                output.close()
                target.unlink(missing_ok=True)
                raise ApiError(413, "IMAGE_TOO_LARGE", "上传内容超过声明或服务端大小限制")
            digest.update(chunk)
            output.write(chunk)
    if total != attachment.size_bytes:
        target.unlink(missing_ok=True)
        raise ApiError(
            422,
            "UPLOAD_SIZE_MISMATCH",
            "上传内容大小与声明不一致",
            details={"declared": attachment.size_bytes, "actual": total},
        )
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != attachment.expected_sha256:
        target.unlink(missing_ok=True)
        raise ApiError(
            422,
            "UPLOAD_HASH_MISMATCH",
            "上传内容哈希与声明不一致",
            details={"expected": attachment.expected_sha256, "actual": actual_sha256},
        )
    attachment.sha256 = actual_sha256
    attachment.original_path = str(target)
    attachment.uploaded_at = utcnow()
    return target


async def queue_processing(
    session: AsyncSession,
    attachment: Attachment,
    settings: Settings | None = None,
) -> BackgroundJob:
    settings = settings or get_settings()
    if not attachment.uploaded_at or not attachment.original_path:
        raise ApiError(409, "UPLOAD_NOT_FINISHED", "请先上传图片二进制内容")
    existing = await session.scalar(
        select(BackgroundJob).where(
            BackgroundJob.job_type == "attachment.process",
            BackgroundJob.payload["attachment_id"].as_string() == attachment.id,
            BackgroundJob.status.in_(("queued", "running", "retry")),
        )
    )
    if existing:
        return existing
    job = BackgroundJob(
        job_type="attachment.process",
        payload={"attachment_id": attachment.id},
        max_attempts=settings.job_max_attempts,
    )
    session.add(job)
    return job


def _sanitize_image(
    source: Path, attachment_id: str, settings: Settings
) -> tuple[Path, Path, str, int, int, str, dict[str, str], datetime | None]:
    head = source.read_bytes()[:8192]
    kind = filetype.guess(head)
    if kind is None or kind.mime not in ALLOWED_MIME_FORMATS:
        raise ApiError(415, "INVALID_IMAGE_MIME", "文件内容不是受支持的图片")
    if kind.mime != ALLOWED_FORMAT_TO_MIME.get(kind.extension, kind.mime):
        raise ApiError(415, "INVALID_IMAGE_MIME", "图片文件头与格式不一致")
    Image.MAX_IMAGE_PIXELS = settings.max_image_pixels
    try:
        with Image.open(source) as probe:
            probe_width, probe_height = probe.size
            if probe_width * probe_height > settings.max_image_pixels:
                raise ApiError(422, "IMAGE_PIXEL_LIMIT_EXCEEDED", "图片像素数量超过限制")
            probe.verify()
        with Image.open(source) as image:
            image.load()
            width, height = image.size
            if width * height > settings.max_image_pixels:
                raise ApiError(422, "IMAGE_PIXEL_LIMIT_EXCEEDED", "图片像素数量超过限制")
            expected_format = ALLOWED_MIME_FORMATS[kind.mime]
            if image.format != expected_format:
                raise ApiError(415, "INVALID_IMAGE_MIME", "图片解码格式与文件头不一致")
            exif = image.getexif()
            safe_exif: dict[str, str] = {}
            captured_at: datetime | None = None
            for tag, name in SAFE_EXIF_TAGS.items():
                if tag in exif:
                    value = str(exif.get(tag))[:200]
                    safe_exif[name] = value
                    if name == "captured_at":
                        try:
                            captured_at = datetime.strptime(value, "%Y:%m:%d %H:%M:%S").replace(
                                tzinfo=UTC
                            )
                        except ValueError:
                            captured_at = None
            normalized = ImageOps.exif_transpose(image).convert("RGB")
            sanitized = safe_storage_path(settings.storage_root, "sanitized", attachment_id, ".jpg")
            thumbnail = safe_storage_path(
                settings.storage_root, "thumbnails", attachment_id, ".jpg"
            )
            normalized.save(sanitized, format="JPEG", quality=92, optimize=True)
            preview = normalized.copy()
            preview.thumbnail((640, 640))
            preview.save(thumbnail, format="JPEG", quality=82, optimize=True)
            phash = str(imagehash.phash(normalized))
            return (
                sanitized,
                thumbnail,
                kind.mime,
                width,
                height,
                phash,
                safe_exif,
                captured_at,
            )
    except Image.DecompressionBombError as exc:
        raise ApiError(422, "IMAGE_PIXEL_LIMIT_EXCEEDED", "图片像素数量超过限制") from exc
    except (UnidentifiedImageError, OSError) as exc:
        raise ApiError(422, "IMAGE_DECODE_FAILED", "图片无法安全解码") from exc


ALLOWED_FORMAT_TO_MIME = {"jpg": "image/jpeg", "png": "image/png", "webp": "image/webp"}


async def process_attachment(
    session: AsyncSession,
    attachment_id: str,
    settings: Settings | None = None,
) -> Attachment:
    settings = settings or get_settings()
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    if not attachment.original_path:
        raise ApiError(409, "UPLOAD_NOT_FINISHED", "上传尚未完成")
    source = Path(attachment.original_path)
    if not await asyncio.to_thread(source.is_file):
        raise ApiError(409, "UPLOAD_CONTENT_MISSING", "隔离区文件不存在")
    attachment.rejection_reason = None
    attachment.metadata_status = "pending"
    attachment.malware_scan_status = "pending"
    try:
        actual = await asyncio.to_thread(_hash_path, source)
        if actual != attachment.expected_sha256 or actual != attachment.sha256:
            raise ApiError(422, "UPLOAD_HASH_MISMATCH", "处理前文件哈希复核失败")
        attachment.malware_scan_status = "clean"
        result = await asyncio.to_thread(_sanitize_image, source, attachment.id, settings)
        (
            sanitized,
            thumbnail,
            mime,
            width,
            height,
            phash,
            exif_data,
            captured_at,
        ) = result
        if mime != attachment.declared_mime_type:
            await asyncio.to_thread(sanitized.unlink, missing_ok=True)
            await asyncio.to_thread(thumbnail.unlink, missing_ok=True)
            raise ApiError(
                415,
                "DECLARED_MIME_MISMATCH",
                "图片真实 MIME 与上传声明不一致",
            )
        attachment.mime_type = mime
        attachment.sanitized_path = str(sanitized)
        attachment.thumbnail_path = str(thumbnail)
        attachment.width = width
        attachment.height = height
        attachment.perceptual_hash = phash
        attachment.exif_data = exif_data
        attachment.captured_at = captured_at
        attachment.metadata_status = "ready"
        with session.no_autoflush:
            duplicate = await session.scalar(
                select(Attachment)
                .where(
                    Attachment.id != attachment.id,
                    Attachment.incident_id == attachment.incident_id,
                    Attachment.metadata_status == "ready",
                    (Attachment.sha256 == attachment.sha256)
                    | (Attachment.perceptual_hash == attachment.perceptual_hash),
                )
                .order_by(Attachment.created_at)
            )
        if duplicate:
            attachment.duplicate_of_attachment_id = duplicate.id
            attachment.source_cluster_id = duplicate.source_cluster_id or duplicate.id
            duplicate.source_cluster_id = attachment.source_cluster_id
        else:
            attachment.source_cluster_id = attachment.id
        # OCR/vision are explicitly degradable; failed enrichment never rejects safe evidence.
        attachment.ocr_status = "not_applicable"
        attachment.ocr_text = None
        attachment.vision_status = "unavailable"
        try:
            from .ai import enrich_attachment

            await enrich_attachment(session, attachment, settings)
        except Exception as exc:
            attachment.ocr_status = "not_applicable"
            attachment.ocr_text = None
            attachment.vision_status = "failed"
            attachment.vision_summary = f"AI enrichment unavailable: {type(exc).__name__}"
        return attachment
    except ApiError as exc:
        attachment.metadata_status = "rejected"
        if attachment.malware_scan_status == "pending":
            attachment.malware_scan_status = "failed"
        attachment.rejection_reason = exc.code
        raise


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
