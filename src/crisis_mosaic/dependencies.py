from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_session
from .errors import ApiError
from .models import AnonymousDevice, IncidentMembership, LocalAccount
from .security import Actor, decode_access_token

bearer = HTTPBearer(auto_error=False)
SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def get_actor(
    session: SessionDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Actor:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise ApiError(
            401,
            "AUTHENTICATION_REQUIRED",
            "需要 Bearer 访问令牌",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_access_token(credentials.credentials)
    subject_type = payload.get("subject_type")
    subject_id = str(payload["sub"])
    token_version = int(payload.get("token_version", 0))
    if subject_type == "device":
        device = await session.get(AnonymousDevice, subject_id)
        if device is None or device.revoked_at is not None or device.token_version != token_version:
            raise ApiError(401, "ACCESS_REVOKED", "匿名会话已被吊销")
        return Actor(
            subject_type="device",
            subject_id=device.id,
            role="resident",
            token_version=device.token_version,
            incident_ids=frozenset(str(item) for item in payload.get("incident_ids", [])),
        )
    if subject_type == "account":
        account = await session.get(LocalAccount, subject_id)
        if account is None or not account.is_active:
            raise ApiError(401, "ACCESS_REVOKED", "账号已停用")
        rows = await session.scalars(
            select(IncidentMembership.incident_id).where(
                IncidentMembership.account_id == account.id
            )
        )
        return Actor(
            subject_type="account",
            subject_id=account.id,
            role=account.role,
            token_version=1,
            incident_ids=frozenset(rows.all()),
            username=account.username,
        )
    raise ApiError(401, "INVALID_ACCESS_TOKEN", "令牌主体无效")


ActorDep = Annotated[Actor, Depends(get_actor)]


def require_roles(*roles: str) -> Callable[[ActorDep], Awaitable[Actor]]:
    async def dependency(actor: ActorDep) -> Actor:
        if actor.role not in roles:
            raise ApiError(403, "FORBIDDEN", "当前角色无权执行此操作")
        return actor

    return dependency


def ensure_incident_access(
    actor: Actor,
    incident_id: str,
    header_incident_id: str | None = None,
) -> None:
    if header_incident_id is not None and header_incident_id != incident_id:
        raise ApiError(
            403,
            "INCIDENT_CONTEXT_MISMATCH",
            "X-Incident-Id 与路径事件不一致",
        )
    if incident_id not in actor.incident_ids:
        raise ApiError(403, "INCIDENT_ACCESS_DENIED", "无权访问该事件")


IncidentHeader = Annotated[str | None, Header(alias="X-Incident-Id")]
