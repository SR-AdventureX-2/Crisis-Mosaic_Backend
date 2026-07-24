from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class AdminUserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,80}$")
    password: str = Field(min_length=12, max_length=512)
    email: str | None = Field(default=None, max_length=200)
    role: Literal["operator", "admin"]
    incident_ids: list[str] = Field(default_factory=list, max_length=100)


class AdminUserPatch(BaseModel):
    revision: int = Field(ge=1)
    email: str | None = Field(default=None, max_length=200)
    role: Literal["operator", "admin"] | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=512)
    incident_ids: list[str] | None = Field(default=None, max_length=100)


class IncidentCreate(BaseModel):
    alias: str | None = Field(default=None, max_length=80)
    name: str = Field(min_length=1, max_length=120)
    type: str = Field(default="flood", max_length=40)
    status: Literal["preparing", "active", "closed"] = "preparing"
    center_latitude: float | None = None
    center_longitude: float | None = None
    map_coordinate_system: Literal["wgs84", "gcj02"] = "gcj02"
    map_default_zoom: float = Field(default=12, ge=1, le=22)
    timezone: str = Field(default="Asia/Shanghai", max_length=50)
    started_at: datetime | None = None
    feature_flags: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def coordinates_together(self) -> IncidentCreate:
        if (self.center_latitude is None) != (self.center_longitude is None):
            raise ValueError("center latitude and longitude must be provided together")
        return self


class IncidentPatch(BaseModel):
    revision: int = Field(ge=0)
    name: str | None = Field(default=None, min_length=1, max_length=120)
    status: Literal["preparing", "active", "closed"] | None = None
    feature_flags: dict[str, Any] | None = None
    center_latitude: float | None = None
    center_longitude: float | None = None
    map_default_zoom: float | None = Field(default=None, ge=1, le=22)
