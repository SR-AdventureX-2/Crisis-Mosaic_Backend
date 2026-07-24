from __future__ import annotations

import asyncio
import hashlib
import shutil
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import BinaryIO

import filetype  # type: ignore[import-untyped]
import imagehash
from fastapi import UploadFile
from PIL import Image, ImageOps, UnidentifiedImageError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..errors import ApiError
from ..models import Attachment, BackgroundJob
from ..utils import utcnow

ALLOWED_MIME_FORMATS = {
    "image/jpeg": "JPEG",
    "image/png": "PNG",
    "image/webp": "WEBP",
}
SAFE_EXIF_TAGS = {271: "make", 272: "model", 306: "datetime", 36867: "captured_at"}


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def attachment_state(attachment: Attachment) -> str:
    if attachment.rejection_reason:
        return "rejected"
    if (
        attachment.metadata_status == "ready"
        and attachment.malware_scan_status == "clean"
        and attachment.sanitized_path
    ):
        return "ready"
    if attachment.uploaded_at:
        return "processing"
    return "pending"


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


async def _scan_file(path: Path, settings: Settings) -> None:
    if settings.malware_scanner == "fake":
        content = await asyncio.to_thread(path.read_bytes)
        if content.startswith(b"EICAR") or b"EICAR-STANDARD-ANTIVIRUS" in content:
            raise ApiError(422, "MALWARE_DETECTED", "恶意文件扫描未通过")
        return
    if settings.malware_scanner == "disabled":
        raise ApiError(503, "MALWARE_SCANNER_UNAVAILABLE", "恶意文件扫描器未启用")
    command = settings.defender_command.strip()
    executable = (
        Path(command)
        if command
        else Path(shutil.which("MpCmdRun.exe") or r"C:\Program Files\Windows Defender\MpCmdRun.exe")
    )
    if not await asyncio.to_thread(executable.is_file):
        raise ApiError(503, "MALWARE_SCANNER_UNAVAILABLE", "Windows Defender 扫描器不可用")
    process = await asyncio.create_subprocess_exec(
        str(executable),
        "-Scan",
        "-ScanType",
        "3",
        "-File",
        str(path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=settings.malware_scan_timeout_seconds,
        )
    except TimeoutError as exc:
        process.kill()
        await process.communicate()
        raise ApiError(
            503,
            "MALWARE_SCANNER_TIMEOUT",
            "恶意文件扫描超时",
        ) from exc
    if process.returncode != 0:
        message = (stdout + stderr).decode(errors="replace")[-500:]
        raise ApiError(
            422 if process.returncode == 2 else 503,
            "MALWARE_DETECTED" if process.returncode == 2 else "MALWARE_SCANNER_FAILED",
            "恶意文件扫描未通过" if process.returncode == 2 else "恶意文件扫描失败",
            details={"scanner_output": message},
        )


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


async def scanner_available(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    if settings.malware_scanner == "fake":
        return True
    if settings.malware_scanner == "disabled":
        return False
    command = settings.defender_command.strip()
    executable = (
        Path(command)
        if command
        else Path(shutil.which("MpCmdRun.exe") or r"C:\Program Files\Windows Defender\MpCmdRun.exe")
    )
    return await asyncio.to_thread(executable.is_file)


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
        await _scan_file(source, settings)
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
        attachment.ocr_status = "unavailable"
        attachment.vision_status = "unavailable"
        try:
            from .ai import enrich_attachment

            await enrich_attachment(session, attachment, settings)
        except Exception as exc:
            attachment.ocr_status = "failed"
            attachment.vision_status = "failed"
            attachment.vision_summary = f"AI enrichment unavailable: {type(exc).__name__}"
        return attachment
    except ApiError as exc:
        attachment.metadata_status = "rejected"
        if attachment.malware_scan_status == "pending":
            attachment.malware_scan_status = (
                "infected" if exc.code == "MALWARE_DETECTED" else "failed"
            )
        attachment.rejection_reason = exc.code
        raise


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
