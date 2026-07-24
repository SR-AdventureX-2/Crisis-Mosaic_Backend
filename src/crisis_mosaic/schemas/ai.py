from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


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
    content: str = Field(min_length=1, max_length=4000)
    location_text: str = Field(min_length=1, max_length=300)


class ReportRefinementOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    refined_content: str = Field(min_length=1, max_length=5000)
    risk_hint: str = Field(max_length=1000)
    suggest_urgent: bool
    detected_risk_tags: list[str] = Field(max_length=20)
    confidence: float = Field(ge=0, le=1)


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

    ocr_text: str = Field(max_length=10000)
    vision_summary: str = Field(min_length=1, max_length=3000)


class ConflictProcessingOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    read_original_text: bool = True
    read_images: bool = True
    extract_ocr: bool = True
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
                        "extract_ocr": True,
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
    suggested_conclusion: str = Field(min_length=1, max_length=4000)
    reasoning_summary: str = Field(min_length=1, max_length=4000)
    confidence: float = Field(ge=0, le=1)
    evidence_assessments: list[EvidenceAssessment] = Field(min_length=1)
    warnings: list[str] = Field(default_factory=list, max_length=20)

    def validate_evidence_refs(self, allowed: set[str]) -> None:
        assessment_ids = [item.evidence_id for item in self.evidence_assessments]
        if len(assessment_ids) != len(set(assessment_ids)):
            raise ValueError("AI output contains duplicate evidence assessments")
        referenced = set(assessment_ids)
        unknown = sorted((referenced | {self.recommended_evidence_id}) - allowed)
        if unknown:
            raise ValueError(f"AI output referenced unknown evidence: {unknown}")
        missing = sorted(allowed - referenced)
        if missing:
            raise ValueError(f"AI output omitted evidence assessments: {missing}")


class BriefRecommendation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    text: str = Field(min_length=1, max_length=2000)
    severity: Literal["low", "medium", "high"]
    source_refs: list[str] = Field(min_length=1, max_length=30)


class CommandBriefOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    headline: str = Field(min_length=1, max_length=300)
    summary: str = Field(min_length=1, max_length=5000)
    recommendations: list[BriefRecommendation] = Field(max_length=50)
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
    latency_ms: int | None
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
