from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PRODUCTION_PLACEHOLDERS = {
    "development-only-change-me",
    "development-installation-pepper",
    "development-upload-signing-secret",
    "development-pii-encryption-key",
    "development-pii-blind-index-secret",
    "development-push-token-secret",
    "ChangeMe-Admin-2026!",
    "ChangeMe-Operator-2026!",
    "replace-with-at-least-48-random-characters",
    "replace-with-independent-random-pepper",
    "replace-with-independent-random-secret",
    "replace-with-independent-pii-encryption-key",
    "replace-with-independent-pii-blind-index-secret",
    "replace-with-independent-push-token-secret",
    "replace-with-a-strong-local-password",
    "replace-with-another-strong-local-password",
}
_OBVIOUSLY_WEAK_CREDENTIALS = {
    "admin",
    "admin123",
    "default",
    "letmein",
    "operator",
    "operator123",
    "password",
    "password123",
    "qwerty",
    "secret",
}


def _credential_is_weak(
    value: str,
    *,
    minimum_length: int,
    minimum_unique_characters: int,
) -> bool:
    stripped = value.strip()
    lowered = stripped.casefold()
    normalized = "".join(character for character in lowered if character.isalnum())
    return (
        len(stripped) < minimum_length
        or len(set(stripped)) < minimum_unique_characters
        or stripped in _PRODUCTION_PLACEHOLDERS
        or lowered.startswith("replace-with")
        or "changeme" in normalized
        or normalized in _OBVIOUSLY_WEAK_CREDENTIALS
        or normalized.startswith("password")
    )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        hide_input_in_errors=True,
    )

    app_name: str = "Crisis Mosaic API"
    app_env: Literal["dev", "test", "staging", "production"] = "dev"
    app_host: str = "127.0.0.1"
    app_port: int = 8000
    app_log_level: str = "INFO"
    app_debug: bool = False
    api_prefix: str = "/api/v1"
    auto_create_schema: bool = False

    database_url: str = "sqlite+aiosqlite:///./data/crisis_mosaic.db"
    data_dir: Path = Path("data")
    storage_root: Path = Path("data/uploads")

    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://127.0.0.1:52123",
            "http://localhost:52123",
        ]
    )

    jwt_secret: str = "development-only-change-me"
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "crisis-mosaic"
    jwt_audience: str = "crisis-mosaic-clients"
    access_token_minutes: int = 60
    refresh_token_days: int = 30
    installation_id_pepper: str = "development-installation-pepper"
    upload_signing_secret: str = "development-upload-signing-secret"
    pii_encryption_key: str = "development-pii-encryption-key"
    pii_blind_index_secret: str = "development-pii-blind-index-secret"
    pii_encryption_key_version: str = "local-v1"
    push_token_secret: str = "development-push-token-secret"

    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "ChangeMe-Admin-2026!"
    bootstrap_operator_username: str = "operator"
    bootstrap_operator_password: str = "ChangeMe-Operator-2026!"

    ai_provider: Literal["openai_compatible", "fake", "disabled"] = "openai_compatible"
    ai_base_url: str = "https://api.openai.com/v1"
    ai_api_key: str = ""
    ai_chat_completions_path: str = "/chat/completions"
    ai_report_model: str = "gpt-4.1-mini"
    ai_vision_model: str = "gpt-4.1-mini"
    ai_brief_model: str = "gpt-4.1-mini"
    ai_supports_json_schema: bool = True
    ai_report_timeout_seconds: float = 5.0
    ai_conflict_timeout_seconds: float = 10.0
    ai_brief_timeout_seconds: float = 15.0
    # 开启后：打印 AI 调用全链路详细日志（模型请求体/模型回复/返回客户端内容），
    # 并静默其他所有日志（http_request、uvicorn 访问日志等）。仅限调试使用。
    ai_debug_log: bool = False
    enable_legacy_demo_ai: bool = False

    max_image_bytes: int = 10 * 1024 * 1024
    max_image_pixels: int = 40_000_000
    max_attachments_per_report: int = 5
    upload_intent_minutes: int = 10
    signed_download_minutes: int = 10
    enable_video_upload: bool = False
    media_storage_provider: Literal["local_proxy", "qiniu_kodo_mock", "qiniu_kodo"] = (
        "qiniu_kodo_mock"
    )
    media_policy_version: str = "media-policy-local-v1"
    media_max_file_size_bytes: int = 5 * 1024 * 1024 * 1024
    media_max_report_total_bytes: int = 10 * 1024 * 1024 * 1024
    media_max_attachment_count: int = 200
    media_max_video_duration_ms: int = 2 * 60 * 60 * 1000
    media_max_parallel_uploads: int = 3
    media_recommended_chunk_size_bytes: int = 4 * 1024 * 1024
    media_upload_session_hours: int = 24
    media_single_device_active_sessions: int = 8
    qiniu_access_key: str = ""
    qiniu_secret_key: str = ""
    qiniu_bucket: str = "crisis-mosaic-local"
    qiniu_region: str = "mock"
    qiniu_upload_host: str = "https://upload-mock.qiniu.local"
    qiniu_public_base_url: str = "https://cdn-mock.qiniu.local"
    qiniu_upload_token_ttl_seconds: int = 600
    qiniu_callback_url: str = ""
    qiniu_rs_host: str = "https://rs.qiniuapi.com"

    map_default_latitude: float = 30.2741
    map_default_longitude: float = 120.1551
    map_default_zoom: float = 12.0
    map_max_points: int = 500
    map_max_bbox_area_degrees: float = 4.0
    coordinate_algorithm_version: str = "gcj02-v1"

    idempotency_hours: int = 24
    rate_limit_enabled: bool = True
    rate_limit_anonymous_sessions_per_minute: int = 10
    rate_limit_report_creates_per_minute: int = 6
    rate_limit_report_updates_per_minute: int = 12
    rate_limit_ai_refinements_per_minute: int = 6
    rate_limit_ai_briefs_per_minute: int = 6
    realtime_replay_hours: int = 24
    realtime_heartbeat_seconds: int = 25
    realtime_queue_size: int = 1000
    job_lease_seconds: int = 60
    job_poll_seconds: float = 0.5
    job_max_attempts: int = 3
    directed_min_valid_answers: int = 2
    conflict_radius_m: float = 500.0
    conflict_window_hours: int = 6
    blind_spot_report_grace_minutes: int = Field(default=30, ge=0)
    location_future_tolerance_minutes: int = 5
    max_location_accuracy_m: float = 5000.0
    business_retention_days: int = Field(default=180, ge=1)
    audit_retention_days: int = Field(default=365, ge=1)
    retention_cleanup_hours: float = Field(default=24.0, gt=0)
    reporter_national_id_retention_days_after_incident: int = 30
    reporter_contact_retention_days_after_incident: int = 90
    reporter_max_retention_days: int = 180
    reporter_reveal_mock_mfa_code: str = "000000"
    push_notifications_enabled: bool = True
    push_provider_mode: Literal["mock", "disabled"] = "mock"
    push_allowed_app_ids: list[str] = Field(
        default_factory=lambda: ["com.srstudio.advx2team.crisismosaic"]
    )
    push_allowed_providers: list[str] = Field(
        default_factory=lambda: ["fcm", "apns", "huawei", "xiaomi", "oppo", "vivo", "honor"]
    )
    push_outbox_batch_size: int = 100
    push_retry_max_attempts: int = 3
    push_notification_ttl_seconds: int = 3600
    push_deep_link_allowed_schemes: list[str] = Field(default_factory=lambda: ["crisismosaic"])

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: object) -> object:
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("["):
                return json.loads(text)
            return [item.strip() for item in text.split(",") if item.strip()]
        return value

    @field_validator(
        "push_allowed_app_ids",
        "push_allowed_providers",
        "push_deep_link_allowed_schemes",
        mode="before",
    )
    @classmethod
    def parse_string_lists(cls, value: object) -> object:
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("["):
                return json.loads(text)
            return [item.strip() for item in text.split(",") if item.strip()]
        return value

    @field_validator("data_dir", "storage_root", mode="before")
    @classmethod
    def normalize_paths(cls, value: object) -> object:
        return Path(str(value))

    @model_validator(mode="after")
    def validate_security(self) -> Settings:
        if self.app_env in {"staging", "production"} and self.enable_legacy_demo_ai:
            raise ValueError("legacy caller-supplied AI context is dev/test only")
        if self.media_storage_provider == "qiniu_kodo":
            required = {
                "qiniu_access_key": self.qiniu_access_key,
                "qiniu_secret_key": self.qiniu_secret_key,
                "qiniu_bucket": self.qiniu_bucket,
                "qiniu_upload_host": self.qiniu_upload_host,
            }
            missing = [name for name, value in required.items() if not value.strip()]
            if missing:
                raise ValueError("qiniu_kodo requires: " + ", ".join(missing))
            upload_host = urlsplit(self.qiniu_upload_host)
            if upload_host.scheme.lower() != "https" or not upload_host.netloc:
                raise ValueError("qiniu_upload_host must be an absolute HTTPS URL")
        if self.app_env == "production":
            credentials = {
                "jwt_secret": (self.jwt_secret, 32, 8),
                "installation_id_pepper": (self.installation_id_pepper, 32, 8),
                "upload_signing_secret": (self.upload_signing_secret, 32, 8),
                "pii_encryption_key": (self.pii_encryption_key, 32, 8),
                "pii_blind_index_secret": (self.pii_blind_index_secret, 32, 8),
                "push_token_secret": (self.push_token_secret, 32, 8),
                "bootstrap_admin_password": (self.bootstrap_admin_password, 16, 6),
                "bootstrap_operator_password": (
                    self.bootstrap_operator_password,
                    16,
                    6,
                ),
            }
            invalid_credentials = [
                name
                for name, (value, minimum_length, minimum_unique_characters) in credentials.items()
                if _credential_is_weak(
                    value,
                    minimum_length=minimum_length,
                    minimum_unique_characters=minimum_unique_characters,
                )
            ]
            if invalid_credentials:
                raise ValueError(
                    "production credentials must not be placeholders or weak values: "
                    + ", ".join(invalid_credentials)
                )
            if (
                len(
                    {
                        self.jwt_secret,
                        self.installation_id_pepper,
                        self.upload_signing_secret,
                        self.pii_encryption_key,
                        self.pii_blind_index_secret,
                        self.push_token_secret,
                    }
                )
                != 6
            ):
                raise ValueError("production signing secrets must be independent")
            if self.bootstrap_admin_password == self.bootstrap_operator_password:
                raise ValueError("production bootstrap passwords must be independent")
            if "*" in self.cors_origins:
                raise ValueError("wildcard CORS is forbidden in production")
        return self

    @property
    def ai_endpoint(self) -> str:
        return f"{self.ai_base_url.rstrip('/')}/{self.ai_chat_completions_path.lstrip('/')}"

    @property
    def ai_configured(self) -> bool:
        return self.ai_provider == "fake" or (
            self.ai_provider == "openai_compatible" and bool(self.ai_api_key)
        )

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        for child in ("quarantine", "original", "sanitized", "thumbnails"):
            (self.storage_root / child).mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
