from __future__ import annotations

import base64
import json
import re
import secrets
from datetime import datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import Settings, get_settings
from ..errors import ApiError
from ..models import Incident, ReporterContact
from ..schemas.reports import ReporterAdditionalInfo, ReporterInput, ReporterPatchInput
from ..security import Actor
from ..utils import as_utc, hmac_sha256, sha256_text, utcnow

_MOBILE_RE = re.compile(r"^1[3-9]\d{9}$")
_NATIONAL_ID_RE = re.compile(r"^\d{17}[\dXx]$")
_NATIONAL_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_NATIONAL_ID_CHECKS = "10X98765432"


def _aes(settings: Settings) -> AESGCM:
    return AESGCM(bytes.fromhex(sha256_text(settings.pii_encryption_key)))


def _aad(incident_id: str, device_id: str, field: str, key_version: str) -> bytes:
    return f"{incident_id}:{device_id}:{field}:{key_version}".encode()


def _encrypt(
    value: str | None,
    *,
    incident_id: str,
    device_id: str,
    field: str,
    settings: Settings,
) -> str | None:
    if value is None:
        return None
    nonce = secrets.token_bytes(12)
    token = _aes(settings).encrypt(
        nonce,
        value.encode("utf-8"),
        _aad(incident_id, device_id, field, settings.pii_encryption_key_version),
    )
    payload = {
        "v": 1,
        "nonce": base64.urlsafe_b64encode(nonce).decode(),
        "ciphertext": base64.urlsafe_b64encode(token).decode(),
    }
    return base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()


def _decrypt(
    value: str | None,
    *,
    incident_id: str,
    device_id: str,
    field: str,
    key_version: str,
    settings: Settings,
) -> str | None:
    if value is None:
        return None
    payload = json.loads(base64.urlsafe_b64decode(value.encode()).decode())
    nonce = base64.urlsafe_b64decode(str(payload["nonce"]).encode())
    ciphertext = base64.urlsafe_b64decode(str(payload["ciphertext"]).encode())
    plaintext = _aes(settings).decrypt(
        nonce,
        ciphertext,
        _aad(incident_id, device_id, field, key_version),
    )
    return plaintext.decode("utf-8")


def normalize_mobile(value: str) -> str:
    text = value.strip().replace(" ", "").replace("-", "")
    if text.startswith("+86"):
        text = text[3:]
    elif text.startswith("86") and len(text) == 13:
        text = text[2:]
    if not _MOBILE_RE.match(text):
        raise ApiError(422, "INVALID_MAINLAND_MOBILE", "手机号必须是合法中国大陆 11 位手机号")
    return f"+86{text}"


def _mask_name(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return ""
    return stripped[0] + "*" * max(1, min(len(stripped) - 1, 3))


def _mask_mobile(e164: str) -> str:
    local = e164[3:] if e164.startswith("+86") else e164
    return f"{local[:3]}****{local[-4:]}"


def _mask_national_id(value: str | None) -> str | None:
    if value is None:
        return None
    return f"{value[:4]}**********{value[-4:]}"


def _normalize_optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def validate_national_id(value: str | None) -> str | None:
    text = _normalize_optional(value)
    if text is None:
        return None
    text = text.upper()
    if not _NATIONAL_ID_RE.match(text):
        raise ApiError(422, "INVALID_NATIONAL_ID", "身份证号格式无效")
    try:
        datetime.strptime(text[6:14], "%Y%m%d")
    except ValueError as exc:
        raise ApiError(422, "INVALID_NATIONAL_ID", "身份证号出生日期无效") from exc
    checksum = sum(int(text[index]) * _NATIONAL_ID_WEIGHTS[index] for index in range(17))
    if _NATIONAL_ID_CHECKS[checksum % 11] != text[-1]:
        raise ApiError(422, "INVALID_NATIONAL_ID", "身份证号校验位无效")
    return text


def _contact_values(
    data: ReporterInput,
) -> dict[str, str | None | datetime]:
    return _validate_values(
        full_name=data.full_name,
        mobile=data.mobile,
        consent_at=data.consent_at,
        additional_info=data.additional_info,
    )


def _validate_values(
    *,
    full_name: str,
    mobile: str,
    consent_at: datetime | None,
    additional_info: ReporterAdditionalInfo | None,
) -> dict[str, str | None | datetime]:
    normalized_name = full_name.strip()
    if not normalized_name:
        raise ApiError(422, "REPORTER_NAME_REQUIRED", "上报人姓名必填")
    normalized_mobile = normalize_mobile(mobile)
    national_id: str | None = None
    emergency_name: str | None = None
    emergency_mobile: str | None = None
    emergency_relation: str | None = None
    rescue_notes: str | None = None
    if additional_info is not None:
        national_id = validate_national_id(additional_info.national_id)
        rescue_notes = _normalize_optional(additional_info.rescue_notes)
        emergency = additional_info.emergency_contact
        if emergency is not None:
            emergency_name = _normalize_optional(emergency.name)
            emergency_mobile_raw = _normalize_optional(emergency.mobile)
            emergency_relation = _normalize_optional(emergency.relation)
            if (
                emergency_name is None
                and emergency_mobile_raw is None
                and emergency_relation is None
            ):
                emergency_name = emergency_mobile = emergency_relation = None
            elif emergency_name is None or emergency_mobile_raw is None:
                raise ApiError(
                    422,
                    "INCOMPLETE_EMERGENCY_CONTACT",
                    "紧急联系人姓名和手机号必须同时提供",
                )
            else:
                emergency_mobile = normalize_mobile(emergency_mobile_raw)
    return {
        "full_name": normalized_name,
        "mobile": normalized_mobile,
        "national_id": national_id,
        "emergency_name": emergency_name,
        "emergency_mobile": emergency_mobile,
        "emergency_relation": emergency_relation,
        "rescue_notes": rescue_notes,
        "consent_at": consent_at or utcnow(),
    }


def _retention_until(incident: Incident, settings: Settings) -> datetime:
    base = as_utc(incident.closed_at) if incident.closed_at else utcnow()
    return base + timedelta(days=settings.reporter_contact_retention_days_after_incident)


def _blind_index(value: str | None, settings: Settings) -> str | None:
    if value is None:
        return None
    return hmac_sha256(settings.pii_blind_index_secret, value)


def _build_contact(
    *,
    incident: Incident,
    device_id: str,
    values: dict[str, str | None | datetime],
    settings: Settings,
) -> ReporterContact:
    full_name = str(values["full_name"])
    mobile = str(values["mobile"])
    national_id = values["national_id"] if isinstance(values["national_id"], str) else None
    emergency_name = (
        values["emergency_name"] if isinstance(values["emergency_name"], str) else None
    )
    emergency_mobile = (
        values["emergency_mobile"] if isinstance(values["emergency_mobile"], str) else None
    )
    emergency_relation = (
        values["emergency_relation"] if isinstance(values["emergency_relation"], str) else None
    )
    rescue_notes = values["rescue_notes"] if isinstance(values["rescue_notes"], str) else None
    consent_at = values["consent_at"]
    assert isinstance(consent_at, datetime)
    return ReporterContact(
        incident_id=incident.id,
        resident_device_id=device_id,
        full_name_ciphertext=_encrypt(
            full_name,
            incident_id=incident.id,
            device_id=device_id,
            field="full_name",
            settings=settings,
        )
        or "",
        full_name_masked=_mask_name(full_name),
        mobile_ciphertext=_encrypt(
            mobile,
            incident_id=incident.id,
            device_id=device_id,
            field="mobile",
            settings=settings,
        )
        or "",
        mobile_blind_index=_blind_index(mobile, settings) or "",
        mobile_masked=_mask_mobile(mobile),
        national_id_ciphertext=_encrypt(
            national_id,
            incident_id=incident.id,
            device_id=device_id,
            field="national_id",
            settings=settings,
        ),
        national_id_blind_index=_blind_index(national_id, settings),
        national_id_masked=_mask_national_id(national_id),
        emergency_name_ciphertext=_encrypt(
            emergency_name,
            incident_id=incident.id,
            device_id=device_id,
            field="emergency_name",
            settings=settings,
        ),
        emergency_name_masked=_mask_name(emergency_name) if emergency_name else None,
        emergency_mobile_ciphertext=_encrypt(
            emergency_mobile,
            incident_id=incident.id,
            device_id=device_id,
            field="emergency_mobile",
            settings=settings,
        ),
        emergency_mobile_masked=_mask_mobile(emergency_mobile) if emergency_mobile else None,
        emergency_relation_ciphertext=_encrypt(
            emergency_relation,
            incident_id=incident.id,
            device_id=device_id,
            field="emergency_relation",
            settings=settings,
        ),
        emergency_relation_masked=emergency_relation,
        rescue_notes_ciphertext=_encrypt(
            rescue_notes,
            incident_id=incident.id,
            device_id=device_id,
            field="rescue_notes",
            settings=settings,
        ),
        encryption_key_version=settings.pii_encryption_key_version,
        consent_at=as_utc(consent_at),
        retention_until=_retention_until(incident, settings),
        legal_hold=False,
    )


def create_reporter_contact(
    *,
    incident: Incident,
    device_id: str,
    reporter: ReporterInput,
    settings: Settings | None = None,
) -> ReporterContact:
    settings = settings or get_settings()
    return _build_contact(
        incident=incident,
        device_id=device_id,
        values=_contact_values(reporter),
        settings=settings,
    )


def _plain_contact(contact: ReporterContact, settings: Settings) -> dict[str, str | None]:
    def decrypt(field: str, value: str | None) -> str | None:
        return _decrypt(
            value,
            incident_id=contact.incident_id,
            device_id=contact.resident_device_id,
            field=field,
            key_version=contact.encryption_key_version,
            settings=settings,
        )

    return {
        "full_name": decrypt("full_name", contact.full_name_ciphertext),
        "mobile": decrypt("mobile", contact.mobile_ciphertext),
        "national_id": decrypt("national_id", contact.national_id_ciphertext),
        "emergency_name": decrypt("emergency_name", contact.emergency_name_ciphertext),
        "emergency_mobile": decrypt("emergency_mobile", contact.emergency_mobile_ciphertext),
        "emergency_relation": decrypt(
            "emergency_relation",
            contact.emergency_relation_ciphertext,
        ),
        "rescue_notes": decrypt("rescue_notes", contact.rescue_notes_ciphertext),
    }


def update_reporter_contact(
    *,
    incident: Incident,
    previous: ReporterContact,
    patch: ReporterPatchInput,
    settings: Settings | None = None,
) -> ReporterContact:
    settings = settings or get_settings()
    plain = _plain_contact(previous, settings)
    full_name = (
        patch.full_name
        if "full_name" in patch.model_fields_set and patch.full_name is not None
        else plain["full_name"]
    )
    mobile = (
        patch.mobile
        if "mobile" in patch.model_fields_set and patch.mobile is not None
        else plain["mobile"]
    )
    if full_name is None or mobile is None:
        raise ApiError(422, "REPORTER_CONTACT_REQUIRED", "上报人姓名和手机号必填")
    additional = patch.additional_info if "additional_info" in patch.model_fields_set else None
    if "additional_info" not in patch.model_fields_set:
        additional = ReporterAdditionalInfo(
            national_id=plain["national_id"],
            emergency_contact=(
                None
                if plain["emergency_name"] is None
                and plain["emergency_mobile"] is None
                and plain["emergency_relation"] is None
                else {
                    "name": plain["emergency_name"],
                    "mobile": plain["emergency_mobile"],
                    "relation": plain["emergency_relation"],
                }
            ),
            rescue_notes=plain["rescue_notes"],
        )
    values = _validate_values(
        full_name=full_name,
        mobile=mobile,
        consent_at=patch.consent_at,
        additional_info=additional,
    )
    return _build_contact(
        incident=incident,
        device_id=previous.resident_device_id,
        values=values,
        settings=settings,
    )


def serialize_contact_masked(contact: ReporterContact | None) -> dict[str, Any] | None:
    if contact is None:
        return None
    return {
        "full_name_masked": contact.full_name_masked,
        "mobile_masked": contact.mobile_masked,
        "has_national_id": bool(contact.national_id_ciphertext),
        "emergency_contact": (
            None
            if not contact.emergency_name_ciphertext
            else {
                "name_masked": contact.emergency_name_masked,
                "mobile_masked": contact.emergency_mobile_masked,
                "relation_masked": contact.emergency_relation_masked,
            }
        ),
        "has_rescue_notes": bool(contact.rescue_notes_ciphertext),
    }


def serialize_contact_plain(
    contact: ReporterContact,
    settings: Settings | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    plain = _plain_contact(contact, settings)
    return {
        "full_name": plain["full_name"],
        "mobile": plain["mobile"],
        "additional_info": {
            "national_id": plain["national_id"],
            "emergency_contact": (
                None
                if plain["emergency_name"] is None and plain["emergency_mobile"] is None
                else {
                    "name": plain["emergency_name"],
                    "mobile": plain["emergency_mobile"],
                    "relation": plain["emergency_relation"],
                }
            ),
            "rescue_notes": plain["rescue_notes"],
        },
    }


def authorize_reveal(actor: Actor, mfa_code: str, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if actor.role != "admin":
        raise ApiError(403, "REPORTER_PII_READ_REQUIRED", "缺少 reporter.pii.read 权限")
    if mfa_code != settings.reporter_reveal_mock_mfa_code:
        raise ApiError(403, "MFA_REQUIRED", "明文读取需要通过二次认证")
