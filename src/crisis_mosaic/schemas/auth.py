from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AnonymousSessionCreate(BaseModel):
    installation_id: str = Field(min_length=22, max_length=512)
    platform: str = Field(min_length=2, max_length=20)
    locale: str | None = Field(default=None, max_length=20)
    region_code: str | None = Field(default=None, max_length=40)
    incident_id: str | None = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=512)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=32, max_length=512)


class TokenPair(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    current_incident_id: str | None = None
