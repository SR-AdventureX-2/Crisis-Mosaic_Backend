from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, update

from ..config import get_settings
from ..db import write_lock
from ..dependencies import ActorDep, SessionDep
from ..errors import ApiError
from ..models import (
    AnonymousDevice,
    Incident,
    IncidentMembership,
    LocalAccount,
    RefreshSession,
)
from ..responses import success
from ..schemas.auth import AnonymousSessionCreate, LoginRequest, RefreshRequest
from ..security import (
    Actor,
    create_access_token,
    installation_hash,
    new_refresh_token,
    refresh_token_hash,
    validate_installation_id,
    verify_password,
)
from ..services.events import record_audit
from ..utils import as_utc, new_id, utcnow

router = APIRouter(tags=["认证"])


async def _active_incident(session: SessionDep, requested: str | None = None) -> Incident:
    query = select(Incident)
    if requested:
        query = query.where((Incident.id == requested) | (Incident.alias == requested))
    else:
        query = query.where(Incident.status == "active")
    incident = await session.scalar(query)
    if incident is None:
        if requested:
            raise ApiError(404, "INCIDENT_NOT_FOUND", "指定事件不存在")
        raise ApiError(503, "NO_ACTIVE_INCIDENT", "当前没有可用事件")
    if incident.status != "active":
        raise ApiError(
            409,
            "INCIDENT_NOT_ACTIVE",
            "指定事件当前未启用",
            details={"incident_id": incident.id, "status": incident.status},
        )
    return incident


async def _issue_pair(
    session: SessionDep,
    actor: Actor,
    *,
    family_id: str | None = None,
) -> tuple[dict[str, object], RefreshSession, str]:
    settings = get_settings()
    access_token, expires_in = create_access_token(actor, settings)
    refresh_token = new_refresh_token()
    refresh = RefreshSession(
        subject_type=actor.subject_type,
        subject_id=actor.subject_id,
        incident_id=(
            next(iter(actor.incident_ids), None) if actor.subject_type == "device" else None
        ),
        token_hash=refresh_token_hash(refresh_token),
        family_id=family_id or new_id(),
        issued_token_version=actor.token_version,
        expires_at=utcnow() + timedelta(days=settings.refresh_token_days),
    )
    session.add(refresh)
    data: dict[str, object] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "current_incident_id": next(iter(actor.incident_ids), None),
    }
    return data, refresh, refresh_token


@router.post("/resident-device-sessions", status_code=status.HTTP_201_CREATED)
@router.post("/anonymous-sessions", status_code=status.HTTP_201_CREATED)
async def create_anonymous_session(
    body: AnonymousSessionCreate,
    request: Request,
    session: SessionDep,
) -> dict[str, object]:
    validate_installation_id(body.installation_id)
    settings = get_settings()
    digest = installation_hash(body.installation_id, settings)
    async with write_lock:
        incident = await _active_incident(session, body.incident_id)
        device = await session.scalar(
            select(AnonymousDevice).where(AnonymousDevice.installation_id_hash == digest)
        )
        if device is not None and device.revoked_at is not None:
            device.installation_id_hash = f"revoked:{device.id}:{digest}"
            await session.flush()
            device = None
        if device is None:
            device = AnonymousDevice(
                installation_id_hash=digest,
                platform=body.platform,
                locale=body.locale,
                region_code=body.region_code,
            )
            session.add(device)
            await session.flush()
        else:
            device.platform = body.platform
            device.locale = body.locale
            device.region_code = body.region_code
            device.last_seen_at = utcnow()
        actor = Actor(
            subject_type="device",
            subject_id=device.id,
            role="resident",
            token_version=device.token_version,
            incident_ids=frozenset({incident.id}),
        )
        data, _, _ = await _issue_pair(session, actor)
        data["device_id"] = device.id
        await record_audit(
            session,
            actor=actor,
            incident_id=incident.id,
            action="anonymous_session.created",
            resource_type="anonymous_device",
            resource_id=device.id,
            request_id=request.state.request_id,
        )
        await session.commit()
    return success(data, request)


async def _login(
    username: str,
    password: str,
    request: Request,
    session: SessionDep,
) -> dict[str, object]:
    async with write_lock:
        account = await session.scalar(
            select(LocalAccount).where(LocalAccount.username == username)
        )
        if (
            account is None
            or not account.is_active
            or not verify_password(password, account.password_hash)
        ):
            raise ApiError(
                401,
                "INVALID_CREDENTIALS",
                "用户名或密码错误",
                headers={"WWW-Authenticate": "Bearer"},
            )
        memberships = (
            await session.scalars(
                select(IncidentMembership.incident_id).where(
                    IncidentMembership.account_id == account.id
                )
            )
        ).all()
        actor = Actor(
            subject_type="account",
            subject_id=account.id,
            role=account.role,
            token_version=1,
            incident_ids=frozenset(memberships),
            username=account.username,
        )
        data, _, _ = await _issue_pair(session, actor)
        await record_audit(
            session,
            actor=actor,
            incident_id=next(iter(actor.incident_ids), None),
            action="auth.login",
            resource_type="local_account",
            resource_id=account.id,
            request_id=request.state.request_id,
        )
        await session.commit()
    return success(data, request)


@router.post("/auth/token")
async def token(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    request: Request,
    session: SessionDep,
) -> dict[str, object]:
    return await _login(form.username, form.password, request, session)


@router.post("/auth/login")
async def login_json(
    body: LoginRequest,
    request: Request,
    session: SessionDep,
) -> dict[str, object]:
    return await _login(body.username, body.password, request, session)


async def _rotate_refresh(
    token_value: str,
    request: Request,
    session: SessionDep,
    *,
    expected_type: str | None,
) -> dict[str, object]:
    digest = refresh_token_hash(token_value)
    async with write_lock:
        refresh = await session.scalar(
            select(RefreshSession).where(RefreshSession.token_hash == digest)
        )
        if refresh is None:
            raise ApiError(401, "INVALID_REFRESH_TOKEN", "Refresh Token 无效")
        if expected_type and refresh.subject_type != expected_type:
            raise ApiError(401, "INVALID_REFRESH_TOKEN", "Refresh Token 主体类型不匹配")
        if refresh.used_at is not None:
            await record_audit(
                session,
                actor=None,
                incident_id=None,
                action="security.refresh_replay",
                resource_type="refresh_session",
                resource_id=refresh.id,
                request_id=request.state.request_id,
            )
            await session.commit()
            raise ApiError(401, "REFRESH_TOKEN_REPLAYED", "该 Refresh Token 已使用")
        if refresh.revoked_at is not None or as_utc(refresh.expires_at) <= utcnow():
            raise ApiError(401, "REFRESH_TOKEN_EXPIRED", "Refresh Token 已过期或被吊销")
        if refresh.subject_type == "device":
            device = await session.get(AnonymousDevice, refresh.subject_id)
            if (
                device is None
                or device.revoked_at is not None
                or device.token_version != refresh.issued_token_version
            ):
                raise ApiError(401, "ACCESS_REVOKED", "匿名会话已被吊销")
            if refresh.incident_id is None:
                raise ApiError(
                    401,
                    "ACCESS_REVOKED",
                    "匿名会话缺少事件作用域，请重新创建会话",
                )
            incident = await _active_incident(session, refresh.incident_id)
            actor = Actor(
                subject_type="device",
                subject_id=device.id,
                role="resident",
                token_version=device.token_version,
                incident_ids=frozenset({incident.id}),
            )
        else:
            account = await session.get(LocalAccount, refresh.subject_id)
            if account is None or not account.is_active:
                raise ApiError(401, "ACCESS_REVOKED", "账号已停用")
            memberships = (
                await session.scalars(
                    select(IncidentMembership.incident_id).where(
                        IncidentMembership.account_id == account.id
                    )
                )
            ).all()
            actor = Actor(
                subject_type="account",
                subject_id=account.id,
                role=account.role,
                token_version=1,
                incident_ids=frozenset(memberships),
                username=account.username,
            )
        refresh.used_at = utcnow()
        data, replacement, _ = await _issue_pair(session, actor, family_id=refresh.family_id)
        await session.flush()
        refresh.replaced_by_id = replacement.id
        await session.commit()
    return success(data, request)


@router.post("/auth/refresh")
async def refresh_account(
    body: RefreshRequest,
    request: Request,
    session: SessionDep,
) -> dict[str, object]:
    return await _rotate_refresh(body.refresh_token, request, session, expected_type="account")


@router.post("/resident-device-sessions/refresh")
@router.post("/anonymous-sessions/refresh")
async def refresh_anonymous(
    body: RefreshRequest,
    request: Request,
    session: SessionDep,
) -> dict[str, object]:
    return await _rotate_refresh(body.refresh_token, request, session, expected_type="device")


@router.post("/auth/logout")
async def logout(
    body: RefreshRequest,
    request: Request,
    session: SessionDep,
) -> dict[str, object]:
    async with write_lock:
        refresh = await session.scalar(
            select(RefreshSession).where(
                RefreshSession.token_hash == refresh_token_hash(body.refresh_token)
            )
        )
        if refresh is not None and refresh.revoked_at is None:
            refresh.revoked_at = utcnow()
        await session.commit()
    return success({"revoked": True}, request)


@router.post("/resident-device-sessions/revoke")
@router.post("/anonymous-sessions/revoke")
async def revoke_anonymous(
    body: RefreshRequest,
    request: Request,
    session: SessionDep,
) -> dict[str, object]:
    digest = refresh_token_hash(body.refresh_token)
    async with write_lock:
        refresh = await session.scalar(
            select(RefreshSession).where(
                RefreshSession.token_hash == digest,
                RefreshSession.subject_type == "device",
            )
        )
        if refresh is None:
            raise ApiError(401, "INVALID_REFRESH_TOKEN", "Refresh Token 无效")
        device = await session.get(AnonymousDevice, refresh.subject_id)
        if device is None:
            raise ApiError(401, "INVALID_REFRESH_TOKEN", "匿名设备不存在")
        now = utcnow()
        device.token_version += 1
        device.revoked_at = now
        await session.execute(
            update(RefreshSession)
            .where(
                RefreshSession.subject_type == "device",
                RefreshSession.subject_id == device.id,
                RefreshSession.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        await record_audit(
            session,
            actor=None,
            incident_id=None,
            action="anonymous_session.revoked",
            resource_type="anonymous_device",
            resource_id=device.id,
            request_id=request.state.request_id,
        )
        await session.commit()
    return success({"revoked": True}, request)


@router.get("/auth/me")
async def me(actor: ActorDep, request: Request) -> dict[str, object]:
    return success(
        {
            "subject_type": actor.subject_type,
            "subject_id": actor.subject_id,
            "username": actor.username,
            "role": actor.role,
            "incident_ids": sorted(actor.incident_ids),
        },
        request,
    )
