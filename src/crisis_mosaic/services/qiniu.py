from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import timedelta
from typing import Any, cast

import httpx

from ..config import Settings, get_settings
from ..errors import ApiError
from ..utils import utcnow


def _urlsafe_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _hmac_sha1(secret_key: str, data: bytes) -> str:
    return _urlsafe_b64(hmac.new(secret_key.encode("utf-8"), data, hashlib.sha1).digest())


def sign_download_url(
    url: str,
    *,
    ttl_seconds: int,
    settings: Settings | None = None,
) -> str:
    """Sign a Kodo download URL with the private-bucket e/token scheme.

    Works for public buckets too: Kodo ignores the extra query parameters there.
    """
    settings = settings or get_settings()
    deadline = int((utcnow() + timedelta(seconds=ttl_seconds)).timestamp())
    separator = "&" if "?" in url else "?"
    to_sign = f"{url}{separator}e={deadline}"
    signature = _hmac_sha1(settings.qiniu_secret_key, to_sign.encode("utf-8"))
    return f"{to_sign}&token={settings.qiniu_access_key}:{signature}"


def qbox_authorization(
    *,
    path: str,
    query: str = "",
    body: bytes = b"",
    content_type: str | None = None,
    settings: Settings | None = None,
) -> str:
    """Build a QBox management/callback Authorization header value."""
    settings = settings or get_settings()
    signing = path
    if query:
        signing += f"?{query}"
    data = signing.encode("utf-8") + b"\n"
    if body and content_type == "application/x-www-form-urlencoded":
        data += body
    signature = _hmac_sha1(settings.qiniu_secret_key, data)
    return f"QBox {settings.qiniu_access_key}:{signature}"


def verify_callback_authorization(
    *,
    authorization: str | None,
    path: str,
    query: str = "",
    body: bytes = b"",
    content_type: str | None = None,
    settings: Settings | None = None,
) -> bool:
    if not authorization:
        return False
    expected = qbox_authorization(
        path=path,
        query=query,
        body=body,
        content_type=content_type,
        settings=settings,
    )
    return hmac.compare_digest(authorization.strip(), expected)


async def stat_object(
    object_key: str,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Fetch real object metadata (fsize/hash/mimeType) from the Kodo rs API."""
    settings = settings or get_settings()
    entry = _urlsafe_b64(f"{settings.qiniu_bucket}:{object_key}".encode())
    path = f"/stat/{entry}"
    authorization = qbox_authorization(path=path, settings=settings)
    url = f"{settings.qiniu_rs_host.rstrip('/')}{path}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers={"Authorization": authorization})
    except httpx.HTTPError as exc:
        raise ApiError(
            502,
            "QINIU_STAT_FAILED",
            "查询七牛云对象元数据失败",
            details={"reason": type(exc).__name__},
        ) from exc
    if response.status_code == 200:
        return cast(dict[str, Any], response.json())
    if response.status_code == 612:
        raise ApiError(409, "UPLOAD_CONTENT_MISSING", "七牛云对象不存在，上传尚未完成")
    raise ApiError(
        502,
        "QINIU_STAT_FAILED",
        "查询七牛云对象元数据失败",
        details={"status": response.status_code},
    )


async def fetch_object_bytes(
    object_key: str,
    *,
    max_bytes: int,
    settings: Settings | None = None,
) -> bytes:
    """Download an object from Kodo via a signed URL, bounded by max_bytes."""
    settings = settings or get_settings()
    base = settings.qiniu_public_base_url.rstrip("/")
    url = sign_download_url(f"{base}/{object_key}", ttl_seconds=300, settings=settings)
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            async with client.stream("GET", url) as response:
                if response.status_code != 200:
                    raise ApiError(
                        502,
                        "QINIU_FETCH_FAILED",
                        "从七牛云获取对象内容失败",
                        details={"status": response.status_code},
                    )
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes(64 * 1024):
                    total += len(chunk)
                    if total > max_bytes:
                        raise ApiError(413, "IMAGE_TOO_LARGE", "对象内容超过服务端大小限制")
                    chunks.append(chunk)
    except httpx.HTTPError as exc:
        raise ApiError(
            502,
            "QINIU_FETCH_FAILED",
            "从七牛云获取对象内容失败",
            details={"reason": type(exc).__name__},
        ) from exc
    return b"".join(chunks)
