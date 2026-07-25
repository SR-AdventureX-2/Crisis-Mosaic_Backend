from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..config import get_settings

RiskTag = Literal[
    "trapped_people",
    "missing_people",
    "injured_people",
    "severe_bleeding",
    "unconscious_person",
    "breathing_difficulty",
    "elderly",
    "child",
    "pregnant_person",
    "disabled_person",
    "rising_water",
    "rapid_current",
    "deep_flooding",
    "building_collapse",
    "landslide",
    "fire",
    "electric_hazard",
    "gas_leak",
    "road_blocked",
    "bridge_damage",
    "medical_shortage",
    "drinking_water_shortage",
    "food_shortage",
    "unsafe_shelter",
    "communication_outage",
]


class ReportRefinementRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "examples": [
                {
                    "incident_id": "019-example-incident",
                    "category": "rescue",
                    "content": "大关桥下有两名老人被困，水位仍在上涨",
                    "location_text": "杭州市大关桥南侧",
                }
            ]
        },
    )

    incident_id: str
    category: Literal["rescue", "medical", "water", "food", "shelter", "road"]
    content: str = Field(min_length=1, max_length=300)
    location_text: str = Field(min_length=1, max_length=300)
    attachment_ids: list[str] = Field(default_factory=list)
    report_id: str | None = None
    report_revision: int | None = Field(default=None, ge=1)

    @field_validator("attachment_ids")
    @classmethod
    def validate_unique_attachment_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("attachment_ids must not contain duplicates")
        if len(value) > get_settings().media_max_attachment_count:
            raise ValueError(
                "attachment_ids must not exceed the configured media attachment count"
            )
        return value

    @model_validator(mode="after")
    def validate_report_context_pair(self) -> ReportRefinementRequest:
        if (self.report_id is None) != (self.report_revision is None):
            raise ValueError("report_id and report_revision must be provided together")
        return self


class ReportRefinementOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    refined_content: str = Field(min_length=1, max_length=5000)
    risk_hint: str = Field(max_length=1000)
    suggest_urgent: bool = Field(
        description=(
            "True only when the supplied report or non-text visual evidence directly supports "
            "a concrete current danger represented by detected_risk_tags."
        )
    )
    detected_risk_tags: list[RiskTag] = Field(
        max_length=20,
        description=(
            "Risks directly supported by concrete report facts or non-text media observations; "
            "category, location, greetings, test text and random text are not evidence."
        ),
        json_schema_extra={"uniqueItems": True},
    )
    confidence: float = Field(
        ge=0,
        le=1,
        description=(
            "Confidence in faithful refinement and correct risk extraction, not risk severity "
            "and never sufficient by itself to raise report priority."
        ),
    )

    @field_validator("detected_risk_tags")
    @classmethod
    def validate_unique_risk_tags(cls, value: list[RiskTag]) -> list[RiskTag]:
        if len(value) != len(set(value)):
            raise ValueError("detected_risk_tags must be unique")
        return value


class ReportRefinementResponse(ReportRefinementOutput):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "examples": [
                {
                    "analysis_id": "019-example-analysis",
                    "refined_content": "【现场情况】大关桥下有两名老人被困，水位仍在上涨。\n"
                    "【位置】杭州市大关桥南侧",
                    "risk_hint": "检测到高风险描述，建议标记为紧急并尽快提交。",
                    "suggest_urgent": True,
                    "detected_risk_tags": ["trapped_people", "elderly", "rising_water"],
                    "confidence": 0.91,
                    "model_version": "configured-report-model",
                }
            ]
        },
    )

    analysis_id: str
    model_version: str


class AttachmentEnrichmentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    vision_summary: str = Field(min_length=1, max_length=3000)


class MediaObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    frame_ref: str
    time_offset_seconds: float | None = Field(default=None, ge=0)
    fact: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)


class MediaEvidenceExtractionOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    evidence_id: str = Field(min_length=1)
    read_status: Literal["readable", "partially_readable", "unreadable"]
    modality: Literal["image", "video"]
    observations: list[MediaObservation] = Field(max_length=50)
    location_clues: list[str] = Field(max_length=20)
    time_clues: list[str] = Field(max_length=20)
    risk_signals: list[str] = Field(max_length=20)
    manipulation_signals: list[str] = Field(max_length=20)
    summary: str = Field(max_length=2000)
    limitations: list[str] = Field(max_length=20)
    confidence: float = Field(ge=0, le=1)


class ConflictProcessingOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    read_original_text: bool = True
    read_images: bool = True
    extract_ocr: Literal[False] = False
    verify_file_hash: bool = True
    cross_validate_timeline: bool = True


class ConflictAnalysisRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        json_schema_extra={
            "examples": [
                {
                    "incident_id": "019-example-incident",
                    "conflict_revision": 3,
                    "evidence_ids": [
                        "019-example-evidence-a",
                        "019-example-evidence-b",
                    ],
                    "processing": {
                        "read_original_text": True,
                        "read_images": True,
                        "extract_ocr": False,
                        "verify_file_hash": True,
                        "cross_validate_timeline": True,
                    },
                },
                {
                    "incident_id": "hangzhou-flood-2026",
                    "conflict_revision": 1,
                    "context": {
                        "evidence": [
                            {
                                "id": "legacy-a",
                                "type": "text",
                                "content": "沿江路仍可通行",
                            },
                            {
                                "id": "legacy-b",
                                "type": "text",
                                "content": "沿江路已积水封闭",
                            },
                        ]
                    },
                },
            ]
        },
    )

    incident_id: str | None = None
    conflict_revision: int = Field(ge=1)
    evidence_ids: list[str] | None = None
    processing: ConflictProcessingOptions = Field(default_factory=ConflictProcessingOptions)
    context: dict[str, Any] | None = None

    @property
    def is_legacy(self) -> bool:
        return self.context is not None


class EvidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    evidence_id: str
    authenticity_score: float = Field(ge=0, le=1)
    credibility_score: float = Field(ge=0, le=1)
    verdict: Literal["supported", "likely", "uncertain", "contradicted"]
    reason: str = Field(min_length=1, max_length=2000)
    extracted_facts: list[str] = Field(max_length=30)


class ConflictAnalysisOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    recommended_evidence_id: str
    suggested_conclusion: str = Field(min_length=1, max_length=1000)
    reasoning_summary: str = Field(min_length=1, max_length=2000)
    confidence: float = Field(ge=0, le=1)
    evidence_assessments: list[EvidenceAssessment] = Field(min_length=1, max_length=500)
    warnings: list[str] = Field(default_factory=list, max_length=30)

    def validate_evidence_refs(self, allowed: set[str]) -> None:
        assessment_ids = [item.evidence_id for item in self.evidence_assessments]
        if len(assessment_ids) != len(set(assessment_ids)):
            raise ValueError("AI output contains duplicate evidence assessments")
        referenced = set(assessment_ids)
        recommended = {self.recommended_evidence_id} if self.recommended_evidence_id else set()
        unknown = sorted((referenced | recommended) - allowed)
        if unknown:
            raise ValueError(f"AI output referenced unknown evidence: {unknown}")
        missing = sorted(allowed - referenced)
        if missing:
            raise ValueError(f"AI output omitted evidence assessments: {missing}")
        if not any(
            "AI 只提供辅助判断" in warning and "指挥人员确认" in warning
            for warning in self.warnings
        ):
            raise ValueError("AI output omitted human confirmation warning")


class BriefRecommendation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    text: str = Field(min_length=1, max_length=500)
    severity: Literal["low", "medium", "high"]
    source_refs: list[str] = Field(
        min_length=1,
        max_length=20,
        json_schema_extra={"uniqueItems": True},
    )

    @field_validator("source_refs")
    @classmethod
    def validate_unique_source_refs(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("source_refs must be unique")
        return value


class CommandBriefOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    headline: str = Field(min_length=1, max_length=100)
    summary: str = Field(min_length=1, max_length=1000)
    recommendations: list[BriefRecommendation] = Field(max_length=10)
    confidence: float = Field(ge=0, le=1)

    def validate_source_refs(self, allowed: set[str]) -> None:
        referenced = {
            source_ref
            for recommendation in self.recommendations
            for source_ref in recommendation.source_refs
        }
        unknown = sorted(referenced - allowed)
        if unknown:
            raise ValueError(f"AI output referenced unknown sources: {unknown}")


class CommandBriefRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "scope": "current_incident",
                    "include_resolved": False,
                    "language": "zh-CN",
                }
            ]
        },
    )

    scope: Literal["current_incident"] = "current_incident"
    include_resolved: bool = False
    language: str = Field(default="zh-CN", min_length=2, max_length=20)


class AnalysisAcceptedResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "analysis_id": "019-example-analysis",
                    "status": "queued",
                    "status_url": "/api/v1/ai/analyses/019-example-analysis",
                }
            ]
        }
    )

    analysis_id: str
    status: Literal["queued", "running", "succeeded", "failed"]
    status_url: str


class AiJobStepResponse(BaseModel):
    id: str
    name: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    error_code: str | None
    details: dict[str, Any] | None


class AnalysisStatusResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "analysis_id": "019-example-analysis",
                    "incident_id": "019-example-incident",
                    "analysis_type": "conflict_analysis",
                    "status": "succeeded",
                    "output": {
                        "recommended_evidence_id": "019-example-evidence-a",
                        "confidence": 0.82,
                    },
                    "confidence": 0.82,
                    "model_provider": "openai-compatible",
                    "model_name": "configured-vision-model",
                    "prompt_version": "v1",
                    "latency_ms": 842,
                    "error_code": None,
                    "error_message": None,
                    "input_version": 3,
                    "data_as_of": "2026-07-24T08:00:00Z",
                    "is_stale": False,
                    "created_at": "2026-07-24T08:00:00Z",
                    "completed_at": "2026-07-24T08:00:01Z",
                    "steps": [
                        {
                            "id": "019-example-step",
                            "name": "schema_and_evidence_validation",
                            "status": "succeeded",
                            "started_at": "2026-07-24T08:00:01Z",
                            "finished_at": "2026-07-24T08:00:01Z",
                            "error_code": None,
                            "details": {"output_schema": "ConflictAnalysisOutput"},
                        }
                    ],
                }
            ]
        }
    )

    analysis_id: str
    incident_id: str
    analysis_type: str
    status: str
    output: dict[str, Any] | None
    confidence: float | None
    model_provider: str | None
    model_name: str | None
    prompt_version: str
    prompt_sha256: str | None = None
    latency_ms: int | None
    input_tokens: int | None = None
    output_tokens: int | None = None
    schema_valid: bool | None = None
    reference_valid: bool | None = None
    error_code: str | None
    error_message: str | None
    input_version: int
    data_as_of: datetime | None
    is_stale: bool
    created_at: datetime
    completed_at: datetime | None
    steps: list[AiJobStepResponse] = Field(default_factory=list)


class LegacyConflictResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    analysis_id: str
    status: str
    recommended_evidence_id: str
    suggested_conclusion: str
    reasoning_summary: str
    confidence: float
    evidence_assessments: list[EvidenceAssessment]
    warnings: list[str]
    engine_label: str
    model_version: str
    data_as_of: datetime

    @model_validator(mode="after")
    def ensure_success(self) -> LegacyConflictResponse:
        if self.status != "succeeded":
            raise ValueError("legacy response must be final")
        return self
