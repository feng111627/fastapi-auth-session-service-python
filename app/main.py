"""应用工厂：装配配置、存储、令牌服务与路由，并预置本地用户。"""
from __future__ import annotations

import uuid

from fastapi import FastAPI

from app.config import Settings, get_settings
from app.db import Store
from app.routers import auth, protected
from app.security import hash_password
from app.tokens import TokenService

# 本地预置用户（仅本地验证用途，口令见 README）
SEED_USERS = [
    ("admin", "admin123", ["admin", "user"]),
    ("alice", "alice123", ["user"]),
]


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    store = Store(settings.db_path)
    store.init_schema()
    store.cleanup_expired()  # 启动时清理过期会话与撤销记录

    for username, password, roles in SEED_USERS:
        if store.get_user_by_username(username) is None:
            store.create_user(uuid.uuid4().hex, username, hash_password(password), roles)

    app = FastAPI(title="auth-session-service")
    app.state.settings = settings
    app.state.store = store
    app.state.token_service = TokenService(settings, store)
    app.include_router(auth.router)
    app.include_router(protected.router)

    @app.get("/")
    def read_root():
        return {"service": "auth-session-service", "status": "ok"}

    return app
