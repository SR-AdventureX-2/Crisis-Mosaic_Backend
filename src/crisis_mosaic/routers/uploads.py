from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import FileResponse

from ..config import get_settings
from ..db import write_lock
from ..dependencies import ActorDep, IncidentHeader, SessionDep, ensure_incident_access
from ..errors import ApiError
from ..models import Attachment, Incident
from ..responses import success
from ..schemas.uploads import ImageIntentRequest
from ..services.events import emit_event, record_audit
from ..services.uploads import (
    attachment_state,
    create_image_intent,
    queue_processing,
    scanner_available,
    stream_request_to_quarantine,
)
from ..utils import isoformat

router = APIRouter(prefix="/uploads", tags=["Uploads"])


def _authorize_attachment(actor: Any, attachment: Attachment, header: str | None) -> None:
    ensure_incident_access(actor, attachment.incident_id, header)
    if actor.role == "resident" and attachment.uploader_device_id != actor.subject_id:
        raise ApiError(403, "ATTACHMENT_ACCESS_DENIED", "无权访问其他设备的附件")


def _attachment_payload(attachment: Attachment) -> dict[str, Any]:
    state = attachment_state(attachment)
    return {
        "attachment_id": attachment.id,
        "incident_id": attachment.incident_id,
        "report_id": attachment.report_id,
        "status": state,
        "mime_type": attachment.mime_type,
        "size_bytes": attachment.size_bytes,
        "sha256": attachment.sha256,
        "width": attachment.width,
        "height": attachment.height,
        "duplicate_of_attachment_id": attachment.duplicate_of_attachment_id,
        "source_cluster_id": attachment.source_cluster_id,
        "metadata_status": attachment.metadata_status,
        "malware_scan_status": attachment.malware_scan_status,
        "ocr_status": attachment.ocr_status,
        "vision_status": attachment.vision_status,
        "ocr_text": attachment.ocr_text,
        "vision_summary": attachment.vision_summary,
        "rejection_reason": attachment.rejection_reason,
        "content_url": f"/api/v1/uploads/{attachment.id}/content" if state == "ready" else None,
        "thumbnail_url": (
            f"/api/v1/uploads/{attachment.id}/thumbnail" if state == "ready" else None
        ),
        "created_at": isoformat(attachment.created_at),
        "uploaded_at": isoformat(attachment.uploaded_at),
    }


@router.post("/image-intents", status_code=status.HTTP_201_CREATED)
async def create_intent(
    payload: ImageIntentRequest,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    if actor.role != "resident" or actor.subject_type != "device":
        raise ApiError(403, "RESIDENT_DEVICE_REQUIRED", "仅匿名居民设备可创建图片上传意图")
    ensure_incident_access(actor, payload.incident_id, incident_header)
    incident = await session.get(Incident, payload.incident_id)
    if incident is None:
        raise ApiError(404, "INCIDENT_NOT_FOUND", "事件不存在")
    async with write_lock:
        try:
            attachment = await create_image_intent(
                session,
                incident_id=payload.incident_id,
                uploader_device_id=actor.subject_id,
                file_name=payload.file_name,
                mime_type=payload.mime_type,
                size_bytes=payload.size_bytes,
                expected_sha256=payload.sha256,
            )
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="attachment.intent_created",
                resource_type="attachment",
                resource_id=attachment.id,
                request_id=getattr(request.state, "request_id", None),
                after={"file_name": payload.file_name, "size_bytes": payload.size_bytes},
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    data = {
        "attachment_id": attachment.id,
        "upload_url": f"/api/v1/uploads/{attachment.id}/content",
        "upload_headers": {"Content-Type": payload.mime_type},
        "expires_at": isoformat(attachment.upload_expires_at),
    }
    return success(data, request)


@router.put("/{attachment_id}/content", status_code=status.HTTP_204_NO_CONTENT)
async def upload_content(
    attachment_id: str,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> Response:
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    _authorize_attachment(actor, attachment, incident_header)
    if attachment.uploaded_at:
        raise ApiError(409, "UPLOAD_ALREADY_FINISHED", "该附件内容已经上传")
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != attachment.declared_mime_type:
        raise ApiError(
            415,
            "DECLARED_MIME_MISMATCH",
            "Content-Type 与上传意图不一致",
        )
    await stream_request_to_quarantine(attachment, request.stream())
    async with write_lock:
        try:
            await record_audit(
                session,
                actor=actor,
                incident_id=attachment.incident_id,
                action="attachment.content_uploaded",
                resource_type="attachment",
                resource_id=attachment.id,
                request_id=getattr(request.state, "request_id", None),
                after={"sha256": attachment.sha256, "size_bytes": attachment.size_bytes},
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{attachment_id}/complete", status_code=status.HTTP_202_ACCEPTED)
async def complete_upload(
    attachment_id: str,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    _authorize_attachment(actor, attachment, incident_header)
    settings = get_settings()
    if not await scanner_available(settings):
        raise ApiError(
            503,
            "MALWARE_SCANNER_UNAVAILABLE",
            "恶意文件扫描器不可用；上传内容不会进入处理队列",
        )
    incident = await session.get(Incident, attachment.incident_id)
    if incident is None:
        raise ApiError(404, "INCIDENT_NOT_FOUND", "事件不存在")
    async with write_lock:
        try:
            await queue_processing(session, attachment, settings)
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="attachment.processing",
                resource_type="attachment",
                resource_id=attachment.id,
                request_id=getattr(request.state, "request_id", None),
                after={"status": "processing"},
            )
            await emit_event(
                session,
                incident=incident,
                event_type="attachment.processing",
                resource_type="attachment",
                resource_id=attachment.id,
                resource_revision=1,
                visibility="owner",
                owner_device_id=attachment.uploader_device_id,
                payload={"attachment_id": attachment.id, "status": "processing"},
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(
        {
            "attachment_id": attachment.id,
            "status": "processing",
            "status_url": f"/api/v1/uploads/{attachment.id}",
        },
        request,
    )


@router.get("/{attachment_id}")
async def get_attachment(
    attachment_id: str,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    _authorize_attachment(actor, attachment, incident_header)
    return success(_attachment_payload(attachment), request)


@router.get("/{attachment_id}/content", response_class=FileResponse)
async def download_content(
    attachment_id: str,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> FileResponse:
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    _authorize_attachment(actor, attachment, incident_header)
    if attachment_state(attachment) != "ready" or not attachment.original_path:
        raise ApiError(409, "ATTACHMENT_NOT_READY", "附件尚未通过安全处理")
    path = Path(attachment.original_path)
    if not await asyncio.to_thread(path.is_file):
        raise ApiError(404, "ATTACHMENT_CONTENT_MISSING", "附件文件不存在")
    return FileResponse(
        path,
        media_type=attachment.mime_type or "application/octet-stream",
        filename=attachment.file_name,
    )


@router.get("/{attachment_id}/thumbnail", response_class=FileResponse)
async def download_thumbnail(
    attachment_id: str,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> FileResponse:
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    _authorize_attachment(actor, attachment, incident_header)
    if attachment_state(attachment) != "ready" or not attachment.thumbnail_path:
        raise ApiError(409, "ATTACHMENT_NOT_READY", "缩略图尚未就绪")
    path = Path(attachment.thumbnail_path)
    if not await asyncio.to_thread(path.is_file):
        raise ApiError(404, "ATTACHMENT_CONTENT_MISSING", "缩略图文件不存在")
    return FileResponse(path, media_type="image/jpeg")
