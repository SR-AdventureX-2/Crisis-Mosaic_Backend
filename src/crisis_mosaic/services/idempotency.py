from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..errors import ApiError
from ..models import IdempotencyRecord
from ..security import Actor
from ..utils import as_utc, request_hash, utcnow


async def replay_or_reserve(
    session: AsyncSession,
    *,
    actor: Actor,
    route: str,
    key: str,
    body: Any,
) -> IdempotencyRecord | dict[str, Any]:
    if not key or len(key) > 200:
        raise ApiError(422, "INVALID_IDEMPOTENCY_KEY", "Idempotency-Key 长度必须为 1 到 200")
    digest = request_hash(body)
    now = utcnow()
    existing = await session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.actor_key == f"{actor.subject_type}:{actor.subject_id}",
            IdempotencyRecord.route == route,
            IdempotencyRecord.idempotency_key == key,
        )
    )
    if existing is not None:
        if as_utc(existing.expires_at) <= now:
            existing.request_hash = digest
            existing.response_status = 0
            existing.response_body = None
            existing.created_at = now
            existing.expires_at = now + timedelta(hours=get_settings().idempotency_hours)
            await session.flush()
            return existing
        if existing.request_hash != digest:
            raise ApiError(
                409,
                "IDEMPOTENCY_CONFLICT",
                "该 Idempotency-Key 已用于不同请求",
            )
        if existing.response_body is None:
            raise ApiError(409, "IDEMPOTENCY_IN_PROGRESS", "相同请求正在处理中")
        return existing.response_body
    row = IdempotencyRecord(
        actor_key=f"{actor.subject_type}:{actor.subject_id}",
        route=route,
        idempotency_key=key,
        request_hash=digest,
        response_status=0,
        response_body=None,
        expires_at=now + timedelta(hours=get_settings().idempotency_hours),
    )
    session.add(row)
    await session.flush()
    return row


def finish(
    record: IdempotencyRecord,
    *,
    status_code: int,
    body: dict[str, Any],
) -> None:
    record.response_status = status_code
    record.response_body = body
