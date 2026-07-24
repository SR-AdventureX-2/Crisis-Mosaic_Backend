from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..config import get_settings

ReportCategory = Literal["rescue", "medical", "water", "food", "shelter", "road"]
ReportPriority = Literal["high", "medium", "low"]
ReportStatus = Literal["new", "acknowledged", "in_progress", "resolved", "invalid"]
CoordinateSystem = Literal["wgs84", "gcj02"]


class ReportLocation(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    text: Annotated[str, Field(min_length=1, max_length=300)]
    latitude: float | None = None
    longitude: float | None = None
    accuracy_m: Annotated[float | None, Field(gt=0)] = None
    source: Literal["gps", "manual", "imported", "exif"] = "manual"
    provider: Literal["amap", "device", "manual", "imported"] | None = None
    coordinate_system: CoordinateSystem | None = None
    observed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_coordinate_pair(self) -> ReportLocation:
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("latitude and longitude must be provided together")
        if self.latitude is not None and self.coordinate_system is None:
            raise ValueError("coordinate_system is required when coordinates are provided")
        if self.source == "gps" and self.accuracy_m is None:
            raise ValueError("accuracy_m is required for GPS locations")
        if self.accuracy_m is not None and self.accuracy_m > get_settings().max_location_accuracy_m:
            raise ValueError(
                f"accuracy_m must not exceed {get_settings().max_location_accuracy_m:g}"
            )
        return self


class ReportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    category: ReportCategory
    content_original: Annotated[str, Field(min_length=1, max_length=300)]
    content_display: Annotated[str | None, Field(min_length=1, max_length=300)] = None
    location: ReportLocation
    is_urgent: bool = False
    ai_refinement_id: str | None = None
    attachment_ids: Annotated[list[str], Field(max_length=5)] = Field(default_factory=list)

    @field_validator("attachment_ids")
    @classmethod
    def unique_attachment_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("attachment_ids must not contain duplicates")
        return value


class ReportPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    revision: Annotated[int, Field(ge=1)]
    category: ReportCategory | None = None
    content_original: Annotated[str | None, Field(min_length=1, max_length=300)] = None
    content_display: Annotated[str | None, Field(min_length=1, max_length=300)] = None
    location: ReportLocation | None = None
    is_urgent: bool | None = None
    ai_refinement_id: str | None = None


class ReportStatusPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: ReportStatus
    revision: Annotated[int, Field(ge=1)]
    note: Annotated[str | None, Field(max_length=300)] = None


class ReportPriorityPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    priority: ReportPriority | None
    revision: Annotated[int, Field(ge=1)]
    note: Annotated[str | None, Field(max_length=300)] = None
