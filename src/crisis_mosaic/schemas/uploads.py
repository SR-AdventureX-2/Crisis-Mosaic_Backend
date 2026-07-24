from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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


class MediaClientCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resumable_upload: bool = False
    background_upload: bool = False


class MediaIntentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    media_type: Literal["image", "video"]
    client_source: Literal["camera", "gallery", "other"] = "other"
    file_name: str = Field(min_length=1, max_length=255)
    mime_type: str = Field(min_length=3, max_length=120)
    size_bytes: int = Field(gt=0)
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    duration_ms: int | None = Field(default=None, gt=0)
    client_capabilities: MediaClientCapabilities = Field(default_factory=MediaClientCapabilities)

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

    @model_validator(mode="after")
    def validate_video_duration(self) -> MediaIntentRequest:
        if self.media_type == "image" and self.duration_ms is not None:
            raise ValueError("duration_ms is only valid for video")
        return self


class UploadPolicySnapshot(BaseModel):
    version: str
    max_file_size_bytes: int
    max_report_total_bytes: int
    max_attachment_count: int
    max_video_duration_ms: int
    max_parallel_uploads: int
    quota_remaining_bytes: int


class MediaIntentResponse(BaseModel):
    attachment_id: str
    provider: str
    media_type: Literal["image", "video"]
    object_key: str
    policy: UploadPolicySnapshot
    upload: dict[str, object]
    expires_at: datetime


class ResumableSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    size_bytes: int = Field(gt=0)
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    client_checkpoint_id: str | None = Field(default=None, min_length=1, max_length=120)
    min_part_size_bytes: int | None = Field(default=None, gt=0)
    max_part_size_bytes: int | None = Field(default=None, gt=0)

    @field_validator("sha256")
    @classmethod
    def normalize_sha256(cls, value: str) -> str:
        return value.lower()


class ResumablePartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    part_number: int = Field(ge=1)
    offset: int = Field(ge=0)
    size_bytes: int = Field(gt=0)
    etag: str = Field(min_length=1, max_length=120)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")

    @field_validator("sha256")
    @classmethod
    def normalize_optional_sha256(cls, value: str | None) -> str | None:
        return value.lower() if value else value


class UploadCompletePart(BaseModel):
    model_config = ConfigDict(extra="forbid")

    part_number: int = Field(ge=1)
    etag: str = Field(min_length=1, max_length=120)
    size_bytes: int = Field(gt=0)


class UploadCompleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    upload_session_id: str | None = None
    object_key: str | None = None
    etag: str | None = Field(default=None, max_length=120)
    size_bytes: int | None = Field(default=None, gt=0)
    parts: list[UploadCompletePart] = Field(default_factory=list)


class UploadCompleteResponse(BaseModel):
    attachment_id: str
    status: Literal["processing"]
    status_url: str


class AttachmentStatusResponse(BaseModel):
    attachment_id: str
    incident_id: str
    report_id: str | None
    status: Literal["pending", "uploaded", "processing", "ready", "rejected"]
    media_type: Literal["image", "video"]
    storage_provider: str
    object_key: str | None
    mime_type: str | None
    size_bytes: int
    sha256: str | None
    width: int | None
    height: int | None
    duration_ms: int | None
    processing_progress: int
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
