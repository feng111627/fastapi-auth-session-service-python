"""全局配置：密钥、令牌有效期、数据库路径。"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    secret_key: str = field(
        default_factory=lambda: os.environ.get("AUTH_SECRET_KEY", "dev-only-secret-change-me-0123456789abcdef")
    )
    algorithm: str = "HS256"
    access_token_ttl_seconds: int = 15 * 60
    refresh_token_ttl_seconds: int = 7 * 24 * 3600
    db_path: str = field(
        default_factory=lambda: os.environ.get("AUTH_DB_PATH", "auth.db")
    )


def get_settings() -> Settings:
    return Settings()
