from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..config import get_settings

ReportCategory = Literal["rescue", "medical", "water", "food", "shelter", "road"]
ReportPriority = Literal["high", "medium", "low"]
ReportStatus = Literal["new", "acknowledged", "in_progress", "resolved", "invalid"]
CoordinateSystem = Literal["wgs84", "gcj02"]
ReporterRevealField = Literal[
    "full_name",
    "mobile",
    "national_id",
    "emergency_contact",
    "rescue_notes",
]


def _default_reveal_fields() -> list[ReporterRevealField]:
    return ["full_name", "mobile"]


class EmergencyContactInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: Annotated[str | None, Field(min_length=1, max_length=80)] = None
    mobile: Annotated[str | None, Field(min_length=11, max_length=32)] = None
    relation: Annotated[str | None, Field(min_length=1, max_length=40)] = None


class ReporterAdditionalInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    national_id: Annotated[str | None, Field(min_length=18, max_length=18)] = None
    emergency_contact: EmergencyContactInput | None = None
    rescue_notes: Annotated[str | None, Field(min_length=1, max_length=500)] = None


class ReporterInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    full_name: Annotated[str, Field(min_length=1, max_length=80)]
    mobile: Annotated[str, Field(min_length=11, max_length=32)]
    consent_at: datetime | None = None
    additional_info: ReporterAdditionalInfo | None = None


class ReporterPatchInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    full_name: Annotated[str | None, Field(min_length=1, max_length=80)] = None
    mobile: Annotated[str | None, Field(min_length=11, max_length=32)] = None
    consent_at: datetime | None = None
    additional_info: ReporterAdditionalInfo | None = None


class ReporterRevealRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    reason_code: Annotated[str, Field(min_length=2, max_length=60)]
    reason: Annotated[str, Field(min_length=5, max_length=300)]
    ticket_ref: Annotated[str, Field(min_length=2, max_length=120)]
    mfa_code: Annotated[str, Field(min_length=4, max_length=12)]
    fields: list[ReporterRevealField] = Field(default_factory=_default_reveal_fields)

    @field_validator("fields")
    @classmethod
    def unique_fields(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("fields must not contain duplicates")
        return value


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
    reporter: ReporterInput
    content_original: Annotated[str, Field(min_length=1, max_length=300)]
    content_display: Annotated[str | None, Field(min_length=1, max_length=300)] = None
    location: ReportLocation
    is_urgent: bool = False
    ai_refinement_id: str | None = None
    attachment_ids: list[str] = Field(default_factory=list)

    @field_validator("attachment_ids")
    @classmethod
    def unique_attachment_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("attachment_ids must not contain duplicates")
        return value


class ReportPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    revision: Annotated[int, Field(ge=1)]
    reporter: ReporterPatchInput | None = None
    category: ReportCategory | None = None
    content_original: Annotated[str | None, Field(min_length=1, max_length=300)] = None
    content_display: Annotated[str | None, Field(min_length=1, max_length=300)] = None
    location: ReportLocation | None = None
    is_urgent: bool | None = None
    ai_refinement_id: str | None = None
    attachment_ids: list[str] | None = None

    @field_validator("attachment_ids")
    @classmethod
    def unique_patch_attachment_ids(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and len(value) != len(set(value)):
            raise ValueError("attachment_ids must not contain duplicates")
        return value


class ReportDelete(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: Annotated[int, Field(ge=1)]


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
