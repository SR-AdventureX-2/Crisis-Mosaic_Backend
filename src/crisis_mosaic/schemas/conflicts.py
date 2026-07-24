from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["fragment", "report", "attachment", "answer"] = "fragment"
    source_id: str
    source_revision: int | None = Field(default=None, ge=1)


class ConflictCreate(BaseModel):
    alias: str | None = Field(default=None, max_length=100)
    fact_key: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=200)
    topic: str = Field(min_length=1, max_length=60)
    location_text: str = Field(min_length=1, max_length=300)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    coordinate_system: Literal["wgs84", "gcj02"] | None = None
    severity: Literal["low", "medium", "high"] = "medium"
    evidence: list[EvidenceReference] = Field(min_length=2)

    @model_validator(mode="after")
    def validate_location(self) -> ConflictCreate:
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("latitude and longitude must be supplied together")
        if self.latitude is not None and self.coordinate_system is None:
            raise ValueError("coordinate_system is required with coordinates")
        return self


class AddConflictEvidence(BaseModel):
    revision: int = Field(ge=1)
    evidence: list[EvidenceReference] = Field(min_length=1)


class ReopenConflict(BaseModel):
    revision: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=500)


class EvidenceDisposition(BaseModel):
    evidence_id: str
    disposition: Literal["accepted", "rejected", "uncertain"]
    note: str | None = Field(default=None, max_length=500)


class ConflictDecisionRequest(BaseModel):
    revision: int = Field(ge=1)
    decision: Literal["accept_evidence", "manual_conclusion"]
    evidence_decisions: list[EvidenceDisposition] = Field(min_length=1)
    conclusion: str = Field(min_length=1)
    note: str | None = None
    analysis_id: str | None = None
    expected_fact_revision: int = Field(default=0, ge=0)
    confidence: float | None = Field(default=None, ge=0, le=1)
    fact_status: Literal["current", "under_review"] = "current"
    is_public: bool = True

    @model_validator(mode="after")
    def validate_unique_dispositions(self) -> ConflictDecisionRequest:
        ids = [item.evidence_id for item in self.evidence_decisions]
        if len(ids) != len(set(ids)):
            raise ValueError("each evidence must have exactly one disposition")
        if not any(item.disposition == "accepted" for item in self.evidence_decisions):
            raise ValueError("at least one evidence item must be accepted")
        return self


class ConflictAiRequest(BaseModel):
    conflict_revision: int = Field(ge=1)
    evidence_ids: list[str] | None = None
    processing: dict[str, bool] | None = None
    context: dict[str, Any] | None = None
