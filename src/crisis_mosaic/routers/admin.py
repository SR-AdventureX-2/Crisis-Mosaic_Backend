from __future__ import annotations

from collections.abc import Sequence

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import delete, select

from ..db import reset_transaction_for_write, write_lock
from ..dependencies import SessionDep, require_roles
from ..errors import ApiError, conflict, not_found
from ..models import Incident, IncidentMembership, LocalAccount
from ..responses import success
from ..schemas.admin import AdminUserCreate, AdminUserPatch
from ..security import Actor, hash_password
from ..services.events import record_audit

router = APIRouter(prefix="/admin", tags=["管理员"])
AdminActor = Depends(require_roles("admin"))


def _user_data(account: LocalAccount, incident_ids: Sequence[str]) -> dict[str, object]:
    return {
        "id": account.id,
        "username": account.username,
        "email": account.email,
        "role": account.role,
        "is_active": account.is_active,
        "revision": account.revision,
        "incident_ids": incident_ids,
        "created_at": account.created_at,
        "updated_at": account.updated_at,
    }


async def _validate_incidents(session: SessionDep, incident_ids: list[str]) -> None:
    if not incident_ids:
        return
    found = set(
        (await session.scalars(select(Incident.id).where(Incident.id.in_(set(incident_ids))))).all()
    )
    missing = set(incident_ids) - found
    if missing:
        raise ApiError(
            422,
            "INVALID_INCIDENT_IDS",
            "包含不存在的事件",
            details={"missing": sorted(missing)},
        )


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    body: AdminUserCreate,
    request: Request,
    session: SessionDep,
    actor: Actor = AdminActor,
) -> dict[str, object]:
    async with write_lock:
        await reset_transaction_for_write(session)
        if await session.scalar(
            select(LocalAccount.id).where(LocalAccount.username == body.username)
        ):
            raise ApiError(409, "USERNAME_EXISTS", "用户名已存在")
        await _validate_incidents(session, body.incident_ids)
        account = LocalAccount(
            username=body.username,
            email=body.email,
            password_hash=hash_password(body.password),
            role=body.role,
        )
        session.add(account)
        await session.flush()
        for incident_id in dict.fromkeys(body.incident_ids):
            session.add(
                IncidentMembership(
                    account_id=account.id,
                    incident_id=incident_id,
                    role=body.role,
                )
            )
        await record_audit(
            session,
            actor=actor,
            incident_id=None,
            action="admin.user_created",
            resource_type="local_account",
            resource_id=account.id,
            request_id=request.state.request_id,
            after={"username": account.username, "role": account.role},
        )
        await session.commit()
    return success(_user_data(account, body.incident_ids), request)


@router.get("/users")
async def list_users(
    request: Request,
    session: SessionDep,
    actor: Actor = AdminActor,
) -> dict[str, object]:
    accounts = (await session.scalars(select(LocalAccount).order_by(LocalAccount.username))).all()
    items: list[dict[str, object]] = []
    for account in accounts:
        memberships = (
            await session.scalars(
                select(IncidentMembership.incident_id).where(
                    IncidentMembership.account_id == account.id
                )
            )
        ).all()
        items.append(_user_data(account, memberships))
    return success(items, request, meta={"total": len(items)})


@router.patch("/users/{account_id}")
async def patch_user(
    account_id: str,
    body: AdminUserPatch,
    request: Request,
    session: SessionDep,
    actor: Actor = AdminActor,
) -> dict[str, object]:
    async with write_lock:
        await reset_transaction_for_write(session)
        account = await session.get(LocalAccount, account_id)
        if account is None:
            raise not_found("账号")
        if account.revision != body.revision:
            raise conflict(
                "REVISION_CONFLICT",
                "account revision does not match",
                {
                    "expected_revision": body.revision,
                    "current_revision": account.revision,
                },
            )
        if body.incident_ids is not None:
            await _validate_incidents(session, body.incident_ids)
        before = {
            "email": account.email,
            "role": account.role,
            "is_active": account.is_active,
            "revision": account.revision,
        }
        fields = body.model_fields_set
        if "email" in fields:
            account.email = body.email
        if body.role is not None:
            account.role = body.role
        if body.is_active is not None:
            account.is_active = body.is_active
        if body.password is not None:
            account.password_hash = hash_password(body.password)
        if body.incident_ids is not None:
            await session.execute(
                delete(IncidentMembership).where(IncidentMembership.account_id == account.id)
            )
            for incident_id in dict.fromkeys(body.incident_ids):
                session.add(
                    IncidentMembership(
                        account_id=account.id,
                        incident_id=incident_id,
                        role=account.role,
                    )
                )
        elif body.role is not None:
            rows = (
                await session.scalars(
                    select(IncidentMembership).where(IncidentMembership.account_id == account.id)
                )
            ).all()
            for row in rows:
                row.role = account.role
        account.revision += 1
        await record_audit(
            session,
            actor=actor,
            incident_id=None,
            action="admin.user_updated",
            resource_type="local_account",
            resource_id=account.id,
            request_id=request.state.request_id,
            before=before,
            after={
                "email": account.email,
                "role": account.role,
                "is_active": account.is_active,
                "revision": account.revision,
            },
        )
        await session.commit()
        incident_ids = (
            await session.scalars(
                select(IncidentMembership.incident_id).where(
                    IncidentMembership.account_id == account.id
                )
            )
        ).all()
    return success(_user_data(account, incident_ids), request)
