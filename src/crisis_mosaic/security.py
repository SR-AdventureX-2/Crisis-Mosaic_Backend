from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal

import jwt
from jwt import InvalidTokenError
from pwdlib import PasswordHash

from .config import Settings, get_settings
from .errors import ApiError
from .utils import hmac_sha256, new_id, sha256_text, utcnow

password_hash = PasswordHash.recommended()


@dataclass(frozen=True, slots=True)
class Actor:
    subject_type: Literal["account", "device"]
    subject_id: str
    role: str
    token_version: int
    incident_ids: frozenset[str]
    username: str | None = None
    region_code: str | None = None

    @property
    def is_resident(self) -> bool:
        return self.role == "resident"


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    try:
        return password_hash.verify(password, encoded)
    except Exception:
        return False


def create_access_token(actor: Actor, settings: Settings | None = None) -> tuple[str, int]:
    settings = settings or get_settings()
    issued_at = utcnow()
    expires_at = issued_at + timedelta(minutes=settings.access_token_minutes)
    payload: dict[str, Any] = {
        "sub": actor.subject_id,
        "typ": "access",
        "subject_type": actor.subject_type,
        "role": actor.role,
        "token_version": actor.token_version,
        "incident_ids": sorted(actor.incident_ids),
        "username": actor.username,
        "jti": new_id(),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": issued_at,
        "exp": expires_at,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, int((expires_at - issued_at).total_seconds())


def decode_access_token(token: str, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["sub", "exp", "iat", "typ"]},
        )
    except InvalidTokenError as exc:
        raise ApiError(
            401,
            "INVALID_ACCESS_TOKEN",
            "访问令牌无效或已过期",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    if payload.get("typ") != "access":
        raise ApiError(401, "INVALID_ACCESS_TOKEN", "令牌类型无效")
    return payload


def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def refresh_token_hash(token: str) -> str:
    return sha256_text(token)


def installation_hash(installation_id: str, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    return hmac_sha256(settings.installation_id_pepper, installation_id)


def validate_installation_id(value: str) -> None:
    if len(value) < 22:
        raise ApiError(
            422,
            "INSTALLATION_ID_TOO_WEAK",
            "installation_id 必须至少包含 128 位随机熵",
        )
