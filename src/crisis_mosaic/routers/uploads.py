from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

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
from ..services.attachments import (
    attachment_state,
    serialize_attachment,
    verify_local_attachment_url,
)
from ..services.events import emit_event, record_audit
from ..services.qiniu import sign_download_url, verify_callback_authorization
from ..services.uploads import (
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
callback_router = APIRouter(tags=["Uploads"])


def _authorize_attachment(actor: Any, attachment: Attachment, header: str | None) -> None:
    ensure_incident_access(actor, attachment.incident_id, header)
    if actor.role == "resident" and attachment.uploader_device_id != actor.subject_id:
        raise ApiError(403, "ATTACHMENT_ACCESS_DENIED", "无权访问其他设备的附件")


def _attachment_payload(attachment: Attachment) -> dict[str, Any]:
    return serialize_attachment(attachment)


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


@router.put(
    "/{attachment_id}/content",
    status_code=status.HTTP_204_NO_CONTENT,
    openapi_extra={
        "requestBody": {
            "required": True,
            "description": "Raw file bytes. Content-Type must match the upload intent MIME type.",
            "content": {
                "*/*": {"schema": {"type": "string", "format": "binary"}},
            },
        },
    },
)
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
        settings = get_settings()
        base = settings.qiniu_public_base_url.rstrip("/")
        if attachment.storage_provider == "qiniu_kodo":
            target_url = sign_download_url(
                f"{base}/{attachment.object_key}",
                ttl_seconds=settings.signed_download_minutes * 60,
                settings=settings,
            )
        else:
            target_url = (
                f"{base}/{attachment.object_key}?signature=mock&ttl="
                f"{settings.signed_download_minutes}"
            )
        return RedirectResponse(target_url, status_code=307)
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


async def _get_signed_local_attachment(
    *,
    attachment_id: str,
    resource: str,
    expires_at: str,
    signature: str,
    session: AsyncSession,
) -> Attachment:
    if not verify_local_attachment_url(
        attachment_id,
        resource,
        expires_at,
        signature,
    ):
        raise ApiError(
            403,
            "SIGNED_ATTACHMENT_URL_INVALID",
            "Attachment URL is invalid or expired",
        )
    attachment = await session.get(Attachment, attachment_id)
    if attachment is None:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "Attachment does not exist")
    if attachment.storage_provider != "local_proxy":
        raise ApiError(
            409,
            "ATTACHMENT_NOT_LOCAL_PROXY",
            "Attachment is not stored by the local proxy",
        )
    if attachment_state(attachment) != "ready":
        raise ApiError(409, "ATTACHMENT_NOT_READY", "Attachment is not ready")
    return attachment


@router.get(
    "/signed/{expires_at}/{signature}/{attachment_id}/content",
    response_model=None,
    include_in_schema=False,
)
async def download_signed_content(
    attachment_id: str,
    expires_at: str,
    signature: str,
    session: SessionDep,
) -> FileResponse:
    attachment = await _get_signed_local_attachment(
        attachment_id=attachment_id,
        resource="content",
        expires_at=expires_at,
        signature=signature,
        session=session,
    )
    if not attachment.original_path:
        raise ApiError(409, "ATTACHMENT_NOT_READY", "Attachment is not ready")
    path = Path(attachment.original_path)
    if not await asyncio.to_thread(path.is_file):
        raise ApiError(404, "ATTACHMENT_CONTENT_MISSING", "Attachment file does not exist")
    return FileResponse(
        path,
        media_type=attachment.mime_type or "application/octet-stream",
        filename=attachment.file_name,
        content_disposition_type="inline",
    )


@router.get(
    "/signed/{expires_at}/{signature}/{attachment_id}/thumbnail",
    response_class=FileResponse,
    include_in_schema=False,
)
async def download_signed_thumbnail(
    attachment_id: str,
    expires_at: str,
    signature: str,
    session: SessionDep,
) -> FileResponse:
    attachment = await _get_signed_local_attachment(
        attachment_id=attachment_id,
        resource="thumbnail",
        expires_at=expires_at,
        signature=signature,
        session=session,
    )
    if not attachment.thumbnail_path:
        raise ApiError(409, "ATTACHMENT_NOT_READY", "Attachment thumbnail is not ready")
    path = Path(attachment.thumbnail_path)
    if not await asyncio.to_thread(path.is_file):
        raise ApiError(404, "ATTACHMENT_CONTENT_MISSING", "Attachment file does not exist")
    return FileResponse(path, media_type="image/jpeg")


@callback_router.post("/qiniu/callback", status_code=status.HTTP_200_OK)
async def qiniu_upload_callback(request: Request, session: SessionDep) -> dict[str, Any]:
    """七牛云上传回调：验签后标记附件上传完成并排队处理。"""
    settings = get_settings()
    if settings.media_storage_provider != "qiniu_kodo":
        raise ApiError(404, "QINIU_CALLBACK_DISABLED", "七牛云回调未启用")
    body = await request.body()
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    configured = urlsplit(settings.qiniu_callback_url)
    if not verify_callback_authorization(
        authorization=request.headers.get("authorization"),
        path=configured.path or request.url.path,
        query=configured.query or request.url.query,
        body=body,
        content_type=content_type,
        settings=settings,
    ):
        raise ApiError(401, "QINIU_CALLBACK_UNAUTHORIZED", "七牛云回调签名校验失败")
    form = parse_qs(body.decode("utf-8"))
    key_values = form.get("key") or []
    object_key = key_values[0] if key_values else ""
    if not object_key:
        raise ApiError(422, "QINIU_CALLBACK_INVALID", "回调缺少对象 key")
    etag_values = form.get("hash") or []
    etag = etag_values[0] if etag_values else None
    fsize_values = form.get("fsize") or []
    fsize = int(fsize_values[0]) if fsize_values and fsize_values[0].isdigit() else None
    attachment = await session.scalar(select(Attachment).where(Attachment.object_key == object_key))
    if attachment is None:
        raise ApiError(404, "ATTACHMENT_NOT_FOUND", "附件不存在")
    if attachment.uploaded_at is not None:
        return {
            "success": True,
            "attachment_id": attachment.id,
            "status": attachment_state(attachment),
        }
    incident = await session.get(Incident, attachment.incident_id)
    async with write_lock:
        try:
            await complete_remote_upload(
                session,
                attachment=attachment,
                upload_session_id=None,
                object_key=object_key,
                etag=etag,
                size_bytes=fsize,
                parts=[],
            )
            active_sessions = (
                await session.scalars(
                    select(MediaUploadSession).where(
                        MediaUploadSession.attachment_id == attachment.id,
                        MediaUploadSession.status == "active",
                    )
                )
            ).all()
            for upload_session in active_sessions:
                upload_session.status = "completed"
            await record_audit(
                session,
                actor=None,
                incident_id=attachment.incident_id,
                action="attachment.content_uploaded",
                resource_type="attachment",
                resource_id=attachment.id,
                request_id=getattr(request.state, "request_id", None),
                after={"object_key": object_key, "etag": etag, "source": "qiniu_callback"},
            )
            if incident is not None:
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
    return {"success": True, "attachment_id": attachment.id, "status": "processing"}
