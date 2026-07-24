from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Priority = Literal["high", "medium", "low"]


class PushDeviceRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    installation_id: Annotated[str, Field(min_length=22, max_length=512)]
    platform: Literal["android", "ios", "web"]
    provider: Annotated[str, Field(min_length=2, max_length=40)]
    provider_token: Annotated[str, Field(min_length=8, max_length=4096)]
    app_id: Annotated[str, Field(min_length=3, max_length=160)]
    environment: Literal["dev", "staging", "production"] = "dev"
    authorization_status: Literal[
        "authorized",
        "provisional",
        "denied",
        "ephemeral",
    ] = "authorized"
    route_priority: Annotated[int, Field(ge=1, le=10)] = 1
    app_version: Annotated[str | None, Field(max_length=40)] = None


class PushDeviceResponse(BaseModel):
    push_device_id: str
    platform: str
    provider: str
    token_fingerprint: str
    app_id: str
    environment: str
    authorization_status: str
    route_priority: int
    status: str
    updated_at: datetime
    revoked_at: datetime | None


class NotificationPreferencePatch(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    revision: Annotated[int, Field(ge=0)]
    enabled: bool | None = None
    minimum_priority: Priority | None = None
    event_types: list[Annotated[str, Field(min_length=3, max_length=80)]] | None = None
    quiet_hours: dict[str, object] | None = None

    @field_validator("event_types")
    @classmethod
    def unique_event_types(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and len(value) != len(set(value)):
            raise ValueError("event_types must not contain duplicates")
        return value


class NotificationPreferenceResponse(BaseModel):
    incident_id: str
    enabled: bool
    minimum_priority: Priority
    event_types: list[str]
    quiet_hours: dict[str, object] | None
    revision: int
    updated_at: datetime | None


class NotificationReceiptCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    receipt_type: Literal["displayed", "clicked", "dismissed", "delivered"]
    installation_id: Annotated[str, Field(min_length=22, max_length=512)]
    occurred_at: datetime
    app_state: Literal["foreground", "background", "terminated"] | None = None


class NotificationReceiptResponse(BaseModel):
    notification_id: str
    receipt_type: str
    accepted: bool
