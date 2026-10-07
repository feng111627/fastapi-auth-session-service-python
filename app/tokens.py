"""令牌服务：签发访问/刷新令牌、刷新轮换、撤销。"""
from __future__ import annotations

from app.config import Settings
from app.db import Store


class TokenError(Exception):
    """令牌相关错误的基类，reason 用于区分失败原因。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class TokenService:
    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store

    def issue_token_pair(self, user_id: str) -> dict:
        raise NotImplementedError

    def refresh(self, refresh_token: str) -> dict:
        raise NotImplementedError

    def decode_access_token(self, token: str) -> dict:
        raise NotImplementedError

    def revoke_refresh_token(self, refresh_token: str) -> None:
        raise NotImplementedError

    def revoke_all_for_user(self, user_id: str) -> None:
        raise NotImplementedError
