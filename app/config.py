"""运行期配置：令牌寿命、数据库路径、签名密钥等。

所有配置都可通过环境变量覆盖，便于测试与本地运行；不提供密钥时会生成
进程级随机密钥（仅用于本机体验，重启后旧访问令牌失效，刷新会话不受影响）。
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    database_path: str
    secret_key: str
    access_token_ttl_seconds: int = 15 * 60          # 访问令牌 15 分钟
    refresh_token_ttl_seconds: int = 7 * 24 * 3600   # 刷新令牌 7 天
    pbkdf2_iterations: int = 200_000


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        database_path=os.environ.get("AUTH_DB_PATH", "data/auth.db"),
        secret_key=os.environ.get("AUTH_SECRET_KEY") or secrets.token_hex(32),
        access_token_ttl_seconds=int(os.environ.get("AUTH_ACCESS_TTL", str(15 * 60))),
        refresh_token_ttl_seconds=int(os.environ.get("AUTH_REFRESH_TTL", str(7 * 24 * 3600))),
        pbkdf2_iterations=int(os.environ.get("AUTH_PBKDF2_ITERATIONS", "200000")),
    )
