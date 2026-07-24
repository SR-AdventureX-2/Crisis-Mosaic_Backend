from __future__ import annotations

import hashlib
import hmac
import json
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from uuid6 import uuid7

current_request_id: ContextVar[str | None] = ContextVar(
    "crisis_mosaic_request_id",
    default=None,
)


def new_id() -> str:
    return str(uuid7())


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return as_utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def hmac_sha256(secret: str, value: str) -> str:
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def request_hash(value: Any) -> str:
    return sha256_text(canonical_json(value))
