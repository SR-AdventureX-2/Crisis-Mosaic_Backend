from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import func, select

from .config import get_settings
from .db import session_factory
from .models import (
    AnonymousDevice,
    Incident,
    IncidentMembership,
    LocalAccount,
    OutboxEvent,
)
from .observability import (
    REALTIME_CONNECTIONS,
    REALTIME_RECONNECTS,
    REALTIME_REPLAY_EVENTS,
    REALTIME_SLOW_CONSUMERS,
)
from .security import Actor, decode_access_token
from .utils import as_utc, utcnow

router = APIRouter(tags=["实时事件"])


@dataclass(eq=False, slots=True)
class Connection:
    websocket: WebSocket
    actor: Actor
    incident_id: str
    expires_at: float
    queue: asyncio.Queue[dict[str, Any]]


def event_visible(actor: Actor, envelope: dict[str, Any]) -> bool:
    if actor.role in {"operator", "admin"}:
        return True
    visibility = envelope.get("visibility")
    event_type = str(envelope.get("type", ""))
    if event_type.startswith("question."):
        data = envelope.get("data") or envelope.get("payload") or {}
        geometry = data.get("target_geometry") if isinstance(data, dict) else None
        if isinstance(geometry, dict):
            allowed_regions = geometry.get("region_codes")
            if allowed_regions and actor.region_code not in allowed_regions:
                return False
            if geometry.get("bbox") or geometry.get("center") or geometry.get("radius_m"):
                # Realtime authentication never collects a resident's current
                # location. Spatial questions are discovered via active/match.
                return False
    return visibility == "public" or envelope.get("owner_device_id") == actor.subject_id


class RealtimeHub:
    def __init__(self) -> None:
        self._connections: set[Connection] = set()
        self._lock = asyncio.Lock()

    async def add(self, connection: Connection) -> None:
        async with self._lock:
            self._connections.add(connection)
            REALTIME_CONNECTIONS.inc()

    async def remove(self, connection: Connection) -> None:
        async with self._lock:
            existed = connection in self._connections
            self._connections.discard(connection)
            if existed:
                REALTIME_CONNECTIONS.dec()

    async def publish(self, envelope: dict[str, Any]) -> None:
        async with self._lock:
            targets = list(self._connections)
        for connection in targets:
            if connection.incident_id != envelope.get("incident_id"):
                continue
            if not event_visible(connection.actor, envelope):
                continue
            try:
                connection.queue.put_nowait(envelope)
            except asyncio.QueueFull:
                REALTIME_SLOW_CONSUMERS.inc()
                await connection.websocket.close(
                    code=1013, reason="slow consumer; reconnect with last_sequence"
                )
                await self.remove(connection)


hub = RealtimeHub()


async def _actor_from_token(token: str, incident_id: str) -> tuple[Actor, float]:
    payload = decode_access_token(token)
    subject_type = payload.get("subject_type")
    subject_id = str(payload["sub"])
    token_version = int(payload.get("token_version", 0))
    async with session_factory()() as session:
        if subject_type == "device":
            device = await session.get(AnonymousDevice, subject_id)
            if (
                device is None
                or device.revoked_at is not None
                or device.token_version != token_version
            ):
                raise ValueError("revoked device")
            actor = Actor(
                subject_type="device",
                subject_id=device.id,
                role="resident",
                token_version=device.token_version,
                incident_ids=frozenset(str(value) for value in payload.get("incident_ids", [])),
                region_code=device.region_code,
            )
        elif subject_type == "account":
            account = await session.get(LocalAccount, subject_id)
            if account is None or not account.is_active:
                raise ValueError("inactive account")
            incident_ids = (
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
                incident_ids=frozenset(incident_ids),
                username=account.username,
            )
        else:
            raise ValueError("invalid subject")
    if incident_id not in actor.incident_ids:
        raise PermissionError("incident denied")
    return actor, float(payload["exp"])


async def _send_queued(connection: Connection) -> None:
    while True:
        envelope = await connection.queue.get()
        await connection.websocket.send_json(envelope)


@router.websocket("/realtime")
async def realtime(websocket: WebSocket) -> None:
    settings = get_settings()
    await websocket.accept()
    if "access_token" in websocket.query_params:
        await websocket.send_json({"type": "error", "code": "QUERY_TOKEN_FORBIDDEN"})
        await websocket.close(code=4401, reason="tokens are forbidden in URL")
        return
    try:
        message = await asyncio.wait_for(websocket.receive_json(), timeout=5)
    except (TimeoutError, WebSocketDisconnect):
        await websocket.close(code=4408, reason="authentication message timeout")
        return
    if message.get("type") != "authenticate":
        await websocket.send_json({"type": "error", "code": "AUTHENTICATION_REQUIRED"})
        await websocket.close(code=4401, reason="first message must authenticate")
        return
    token = message.get("access_token")
    incident_id = message.get("incident_id")
    last_sequence = message.get("last_sequence")
    if not isinstance(token, str) or not isinstance(incident_id, str):
        await websocket.close(code=4401, reason="invalid authentication message")
        return
    if last_sequence is not None and (not isinstance(last_sequence, int) or last_sequence < 0):
        await websocket.close(code=4401, reason="invalid last_sequence")
        return
    try:
        actor, expires_at = await _actor_from_token(token, incident_id)
    except PermissionError:
        await websocket.close(code=4403, reason="incident access denied")
        return
    except Exception:
        await websocket.close(code=4401, reason="invalid or expired access token")
        return

    connection = Connection(
        websocket=websocket,
        actor=actor,
        incident_id=incident_id,
        expires_at=expires_at,
        queue=asyncio.Queue(maxsize=settings.realtime_queue_size),
    )
    await hub.add(connection)
    if last_sequence is not None:
        REALTIME_RECONNECTS.inc()
    sender: asyncio.Task[None] | None = None
    missed_heartbeats = 0
    try:
        cutoff = utcnow() - timedelta(hours=settings.realtime_replay_hours)
        async with session_factory()() as session:
            incident = await session.get(Incident, incident_id)
            if incident is None:
                await websocket.close(code=4403, reason="incident not found")
                return
            oldest_available = await session.scalar(
                select(func.min(OutboxEvent.sequence)).where(
                    OutboxEvent.incident_id == incident_id,
                    OutboxEvent.occurred_at >= cutoff,
                )
            )
            latest = incident.event_sequence
            cursor = last_sequence if last_sequence is not None else latest
            replay_required = last_sequence is not None and cursor < latest
            if replay_required and (oldest_available is None or cursor < oldest_available - 1):
                await websocket.send_json(
                    {
                        "type": "full_resync_required",
                        "oldest_available_sequence": oldest_available,
                        "latest_sequence": latest,
                    }
                )
                await websocket.close(code=4409, reason="replay window exceeded")
                return
            await websocket.send_json(
                {
                    "type": "ready",
                    "incident_id": incident_id,
                    "oldest_available_sequence": oldest_available,
                    "latest_sequence": latest,
                    "heartbeat_seconds": settings.realtime_heartbeat_seconds,
                }
            )
            if replay_required:
                events = (
                    await session.scalars(
                        select(OutboxEvent)
                        .where(
                            OutboxEvent.incident_id == incident_id,
                            OutboxEvent.sequence > cursor,
                            OutboxEvent.sequence <= latest,
                            OutboxEvent.occurred_at >= cutoff,
                        )
                        .order_by(OutboxEvent.sequence)
                    )
                ).all()
                for event in events:
                    if event_visible(actor, event.payload):
                        await websocket.send_json(event.payload)
                        REALTIME_REPLAY_EVENTS.inc()
        # The hub was registered before the replay snapshot. Drain events newer
        # than that snapshot, and discard duplicates already replayed.
        while True:
            try:
                queued = connection.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if int(queued.get("sequence", 0)) > latest:
                await websocket.send_json(queued)
        sender = asyncio.create_task(_send_queued(connection))
        while True:
            if utcnow().timestamp() >= connection.expires_at:
                await websocket.close(code=4401, reason="access token expired")
                break
            try:
                incoming = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=settings.realtime_heartbeat_seconds,
                )
                if incoming.get("type") == "pong":
                    missed_heartbeats = 0
                elif incoming.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except TimeoutError:
                missed_heartbeats += 1
                if missed_heartbeats > 2:
                    await websocket.close(code=4408, reason="heartbeat timeout")
                    break
                await websocket.send_json(
                    {
                        "type": "ping",
                        "sent_at": as_utc(utcnow()).isoformat(),
                    }
                )
    except WebSocketDisconnect:
        pass
    finally:
        if sender is not None:
            sender.cancel()
        await hub.remove(connection)
