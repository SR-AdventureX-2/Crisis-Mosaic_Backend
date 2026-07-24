from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ImageIntentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    file_name: str = Field(min_length=1, max_length=255)
    mime_type: Literal["image/jpeg", "image/png", "image/webp"]
    size_bytes: int = Field(gt=0)
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")

    @field_validator("file_name")
    @classmethod
    def safe_file_name(cls, value: str) -> str:
        if value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
            raise ValueError("file_name must not contain a path")
        return value

    @field_validator("sha256")
    @classmethod
    def normalize_sha256(cls, value: str) -> str:
        return value.lower()


class UploadIntentResponse(BaseModel):
    attachment_id: str
    upload_url: str
    upload_headers: dict[str, str]
    expires_at: datetime


class UploadCompleteResponse(BaseModel):
    attachment_id: str
    status: Literal["processing"]
    status_url: str


class AttachmentStatusResponse(BaseModel):
    attachment_id: str
    incident_id: str
    report_id: str | None
    status: Literal["pending", "processing", "ready", "rejected"]
    mime_type: str | None
    size_bytes: int
    sha256: str | None
    width: int | None
    height: int | None
    duplicate_of_attachment_id: str | None
    source_cluster_id: str | None
    metadata_status: str
    malware_scan_status: str
    ocr_status: str
    vision_status: str
    ocr_text: str | None
    vision_summary: str | None
    rejection_reason: str | None
    content_url: str | None
    thumbnail_url: str | None
    created_at: datetime
    uploaded_at: datetime | None
