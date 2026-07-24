from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

CoordinateSystem = Literal["wgs84", "gcj02"]
Severity = Literal["low", "medium", "high"]


class LocationInput(BaseModel):
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    coordinate_system: CoordinateSystem | None = None

    @model_validator(mode="after")
    def validate_coordinate_pair(self) -> LocationInput:
        has_latitude = self.latitude is not None
        has_longitude = self.longitude is not None
        if has_latitude != has_longitude:
            raise ValueError("latitude and longitude must be supplied together")
        if has_latitude and self.coordinate_system is None:
            raise ValueError("coordinate_system is required when coordinates are supplied")
        return self


class BlindSpotCreate(LocationInput):
    claim_key: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=200)
    location_text: str = Field(min_length=1, max_length=300)
    scope_type: Literal["incident", "region", "radius"] = "incident"
    scope_data: dict[str, Any] | None = None
    severity: Severity = "medium"
    route_impact_count: int = Field(default=0, ge=0)
    min_valid_answers: int | None = Field(default=None, ge=1, le=100)


class QuestionOption(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    label: str = Field(min_length=1, max_length=120)
    semantic_value: str | None = Field(default=None, min_length=1, max_length=100)


class DirectedQuestionCreate(BaseModel):
    blind_spot_id: str
    title: str = Field(min_length=1, max_length=200)
    location_text: str = Field(min_length=1, max_length=300)
    target_geometry: dict[str, Any] | None = None
    route_impact_count: int = Field(default=0, ge=0)
    answer_type: Literal["single_choice"] = "single_choice"
    options: list[QuestionOption] = Field(min_length=2, max_length=20)
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_unique_options(self) -> DirectedQuestionCreate:
        option_ids = [option.id for option in self.options]
        if len(option_ids) != len(set(option_ids)):
            raise ValueError("option ids must be unique")
        return self


class RevisionAction(BaseModel):
    revision: int = Field(ge=1)


class QuestionMatchRequest(LocationInput):
    region_code: str | None = Field(default=None, max_length=40)


class DirectedAnswerPut(LocationInput):
    option_id: str = Field(min_length=1, max_length=80)
    revision: int = Field(ge=0)
    answer_text: str | None = Field(default=None, max_length=300)
    attachment_ids: list[str] = Field(default_factory=list)

    @field_validator("attachment_ids")
    @classmethod
    def unique_attachment_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("attachment_ids must not contain duplicates")
        return value


class FragmentCreate(LocationInput):
    topic: str = Field(min_length=1, max_length=60)
    claim_key: str | None = Field(default=None, max_length=100)
    claim_value: str | None = Field(default=None, max_length=100)
    label: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1)
    location_text: str = Field(min_length=1, max_length=300)
    confidence: float = Field(default=0.5, ge=0, le=1)
    observed_at: datetime | None = None
