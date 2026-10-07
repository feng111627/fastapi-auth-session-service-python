"""请求/响应数据模型。"""
from __future__ import annotations

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class MeResponse(BaseModel):
    username: str
    roles: list[str]
    permissions: list[str]


class UpdateRolesRequest(BaseModel):
    roles: list[str]


class CleanupResponse(BaseModel):
    sessions: int
    refresh_tokens: int
    revocation_records: int


class EnabledRequest(BaseModel):
    enabled: bool
