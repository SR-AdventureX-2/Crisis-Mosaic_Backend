from __future__ import annotations

from typing import Any

from fastapi import Request
from pydantic import BaseModel, Field


class SuccessEnvelope[DataT](BaseModel):
    data: DataT
    meta: dict[str, Any] = Field(default_factory=dict)


def success(
    data: Any,
    request: Request | None = None,
    *,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response_meta: dict[str, Any] = {}
    if request is not None:
        response_meta["request_id"] = getattr(request.state, "request_id", None)
    if meta:
        response_meta.update(meta)
    return {"data": data, "meta": response_meta}


def page_meta(
    *,
    total: int,
    limit: int,
    offset: int,
    request: Request | None = None,
) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < total,
    }
    if request is not None:
        meta["request_id"] = getattr(request.state, "request_id", None)
    return meta
