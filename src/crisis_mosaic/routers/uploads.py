from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import FileResponse, RedirectResponse

from ..config import get_settings
from ..db import write_lock
from ..dependencies import ActorDep, IncidentHeader, SessionDep, ensure_incident_access
from ..errors import ApiError
from ..models import Attachment, Incident, MediaUploadSession
from ..responses import success
from ..schemas.uploads import (
    ImageIntentRequest,
    MediaIntentRequest,
    ResumablePartRequest,
    ResumableSessionRequest,
    UploadCompleteRequest,
)
from ..services.events import emit_event, record_audit
from ..services.uploads import (
    attachment_state,
    complete_remote_upload,
    create_image_intent,
    create_media_intent,
    create_resumable_session,
    queue_processing,
    record_resumable_part,
    renew_resumable_session,
    resumable_session_payload,
    stream_request_to_quarantine,
)
from ..utils import isoformat, utcnow

router = APIRouter(prefix="/uploads", tags=["Uploads"])


def _authorize_attachment(actor: Any, attachment: Attachment, header: str | None) -> None:
    ensure_incident_access(actor, attachment.incident_id, header)
    if actor.role == "resident" and attachment.uploader_device_id != actor.subject_id:
        raise ApiError(403, "ATTACHMENT_ACCESS_DENIED", "无权访问其他设备的附件")


def _attachment_payload(attachment: Attachment) -> dict[str, Any]:
    settings = get_settings()
    state = attachment_state(attachment)
    if attachment.storage_provider == "local_proxy":
        content_url = f"/api/v1/uploads/{attachment.id}/content" if state == "ready" else None
        thumbnail_url = (
            f"/api/v1/uploads/{attachment.id}/thumbnail" if state == "ready" else None
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


@router.post("/media-intents", status_code=status.HTTP_201_CREATED)
async def create_media_upload_intent(
    payload: MediaIntentRequest,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    if actor.role != "resident" or actor.subject_type != "device":
        raise ApiError(403, "RESIDENT_DEVICE_REQUIRED", "仅匿名居民设备可创建媒体上传意图")
    ensure_incident_access(actor, payload.incident_id, incident_header)
    incident = await session.get(Incident, payload.incident_id)
    if incident is None:
        raise ApiError(404, "INCIDENT_NOT_FOUND", "事件不存在")
    async with write_lock:
        try:
            attachment, intent, token_fingerprint = await create_media_intent(
                session,
                incident_id=payload.incident_id,
                uploader_device_id=actor.subject_id,
                media_type=payload.media_type,
                client_source=payload.client_source,
                file_name=payload.file_name,
                mime_type=payload.mime_type,
                size_bytes=payload.size_bytes,
                expected_sha256=payload.sha256,
                duration_ms=payload.duration_ms,
                resumable_upload=payload.client_capabilities.resumable_upload,
            )
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="attachment.media_intent_created",
                resource_type="attachment",
                resource_id=attachment.id,
                request_id=getattr(request.state, "request_id", None),
                after={
                    "media_type": payload.media_type,
                    "client_source": payload.client_source,
                    "storage_provider": attachment.storage_provider,
                    "token_fingerprint": token_fingerprint,
                    "size_bytes": payload.size_bytes,
                },
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    data = {
        "attachment_id": attachment.id,
        "provider": attachment.storage_provider,
        "media_type": attachment.media_type,
        "object_key": attachment.object_key,
        "policy": intent["policy"],
        "upload": intent["upload"],
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
    payload: UploadCompleteRequest | None = None,
) -> dict[str, Any]:
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    _authorize_attachment(actor, attachment, incident_header)
    settings = get_settings()
    incident = await session.get(Incident, attachment.incident_id)
    if incident is None:
        raise ApiError(404, "INCIDENT_NOT_FOUND", "事件不存在")
    async with write_lock:
        try:
            if attachment.storage_provider == "local_proxy":
                await queue_processing(session, attachment, settings)
            else:
                complete_parts: list[object] = list(payload.parts) if payload else []
                await complete_remote_upload(
                    session,
                    attachment=attachment,
                    upload_session_id=payload.upload_session_id if payload else None,
                    object_key=payload.object_key if payload else None,
                    etag=payload.etag if payload else None,
                    size_bytes=payload.size_bytes if payload else None,
                    parts=complete_parts,
                )
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


def _assert_upload_session(
    upload_session: MediaUploadSession | None,
    *,
    attachment: Attachment,
) -> MediaUploadSession:
    if upload_session is None or upload_session.attachment_id != attachment.id:
        raise ApiError(404, "UPLOAD_SESSION_NOT_FOUND", "上传会话不存在")
    return upload_session


@router.post(
    "/{attachment_id}/resumable-sessions",
    status_code=status.HTTP_201_CREATED,
)
async def post_resumable_session(
    attachment_id: str,
    payload: ResumableSessionRequest,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    _authorize_attachment(actor, attachment, incident_header)
    if actor.role != "resident" or actor.subject_type != "device":
        raise ApiError(403, "RESIDENT_DEVICE_REQUIRED", "仅匿名居民设备可恢复上传")
    async with write_lock:
        try:
            upload_session, upload_token = await create_resumable_session(
                session,
                attachment=attachment,
                device_id=actor.subject_id,
                size_bytes=payload.size_bytes,
                sha256=payload.sha256,
                client_checkpoint_id=payload.client_checkpoint_id,
            )
            await record_audit(
                session,
                actor=actor,
                incident_id=attachment.incident_id,
                action="media_upload_session.created",
                resource_type="media_upload_session",
                resource_id=upload_session.id,
                request_id=getattr(request.state, "request_id", None),
                after={
                    "attachment_id": attachment.id,
                    "client_checkpoint_id": payload.client_checkpoint_id,
                },
            )
            data = await resumable_session_payload(
                session,
                upload_session,
                upload_token=upload_token,
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(data, request)


@router.post("/{attachment_id}/resumable-sessions/{session_id}/parts")
async def post_resumable_part(
    attachment_id: str,
    session_id: str,
    payload: ResumablePartRequest,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    _authorize_attachment(actor, attachment, incident_header)
    upload_session = _assert_upload_session(
        await session.get(MediaUploadSession, session_id),
        attachment=attachment,
    )
    async with write_lock:
        try:
            part = await record_resumable_part(
                session,
                upload_session=upload_session,
                part_number=payload.part_number,
                offset=payload.offset,
                size_bytes=payload.size_bytes,
                etag=payload.etag,
                sha256=payload.sha256,
            )
            await record_audit(
                session,
                actor=actor,
                incident_id=attachment.incident_id,
                action="media_upload_part.confirmed",
                resource_type="media_upload_session",
                resource_id=upload_session.id,
                request_id=getattr(request.state, "request_id", None),
                after={
                    "attachment_id": attachment.id,
                    "part_number": part.part_number,
                    "confirmed_bytes": upload_session.confirmed_bytes,
                },
            )
            data = await resumable_session_payload(session, upload_session)
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(data, request)


@router.get("/{attachment_id}/resumable-sessions/{session_id}")
async def get_resumable_session(
    attachment_id: str,
    session_id: str,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    _authorize_attachment(actor, attachment, incident_header)
    upload_session = _assert_upload_session(
        await session.get(MediaUploadSession, session_id),
        attachment=attachment,
    )
    return success(await resumable_session_payload(session, upload_session), request)


@router.post("/{attachment_id}/resumable-sessions/{session_id}/renew")
async def post_resumable_session_renew(
    attachment_id: str,
    session_id: str,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    _authorize_attachment(actor, attachment, incident_header)
    upload_session = _assert_upload_session(
        await session.get(MediaUploadSession, session_id),
        attachment=attachment,
    )
    async with write_lock:
        try:
            upload_token = await renew_resumable_session(upload_session)
            await record_audit(
                session,
                actor=actor,
                incident_id=attachment.incident_id,
                action="media_upload_session.renewed",
                resource_type="media_upload_session",
                resource_id=upload_session.id,
                request_id=getattr(request.state, "request_id", None),
            )
            data = await resumable_session_payload(
                session,
                upload_session,
                upload_token=upload_token,
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success(data, request)


@router.delete("/{attachment_id}/resumable-sessions/{session_id}")
async def delete_resumable_session(
    attachment_id: str,
    session_id: str,
    request: Request,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> dict[str, Any]:
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    _authorize_attachment(actor, attachment, incident_header)
    upload_session = _assert_upload_session(
        await session.get(MediaUploadSession, session_id),
        attachment=attachment,
    )
    async with write_lock:
        try:
            if upload_session.status != "aborted":
                upload_session.status = "aborted"
                upload_session.aborted_at = utcnow()
            await record_audit(
                session,
                actor=actor,
                incident_id=attachment.incident_id,
                action="media_upload_session.aborted",
                resource_type="media_upload_session",
                resource_id=upload_session.id,
                request_id=getattr(request.state, "request_id", None),
                after={"status": upload_session.status},
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return success({"session_id": upload_session.id, "status": upload_session.status}, request)


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


@router.get("/{attachment_id}/content", response_model=None)
async def download_content(
    attachment_id: str,
    actor: ActorDep,
    session: SessionDep,
    incident_header: IncidentHeader,
) -> FileResponse | RedirectResponse:
    attachment = await session.get(Attachment, attachment_id)
    if not attachment:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    _authorize_attachment(actor, attachment, incident_header)
    if attachment_state(attachment) != "ready":
        raise ApiError(409, "ATTACHMENT_NOT_READY", "附件尚未通过安全处理")
    if attachment.storage_provider != "local_proxy":
        if not attachment.object_key:
            raise ApiError(409, "ATTACHMENT_NOT_READY", "附件尚未通过安全处理")
        base = get_settings().qiniu_public_base_url.rstrip("/")
        return RedirectResponse(
            f"{base}/{attachment.object_key}?signature=mock&ttl="
            f"{get_settings().signed_download_minutes}",
            status_code=307,
        )
    if not attachment.original_path:
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
