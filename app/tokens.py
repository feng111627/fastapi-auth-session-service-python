"""令牌服务：签发访问/刷新令牌、刷新轮换、重放检测、撤销。

令牌模型：
- 访问令牌：JWT，携带 sub/username/roles/tv(token_version)/jti/exp，短有效期。
- 刷新令牌：JWT，携带 sub/jti/exp，长有效期；服务端只存其 SHA-256 哈希。
- 轮换：每次刷新必须换发新刷新令牌，旧令牌立即作废；
  旧令牌再次提交 => reason=reused，并撤销该用户全部刷新会话（防重放扩散）。
- 权限收回：用户角色变更会递增 token_version，旧访问令牌因 tv 不匹配立即失效。
"""
from __future__ import annotations

import time
import uuid

import jwt

from app.config import Settings
from app.db import Store


class TokenError(Exception):
    """令牌错误，reason 用于区分失败原因（expired/invalid/reused/revoked/stale_version）。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class TokenService:
    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store

    # ---------- 签发 ----------

    def issue_token_pair(self, user: dict) -> dict:
        now = int(time.time())
        return {
            "access_token": self._issue_access_token(user, now),
            "refresh_token": self._issue_refresh_token(user["id"], now),
            "token_type": "bearer",
            "expires_in": self.settings.access_token_ttl_seconds,
        }

    def _issue_access_token(self, user: dict, now: int) -> str:
        return jwt.encode(
            {
                "sub": user["id"],
                "username": user["username"],
                "roles": user["roles"],
                "tv": user["token_version"],
                "jti": uuid.uuid4().hex,
                "iat": now,
                "exp": now + self.settings.access_token_ttl_seconds,
                "type": "access",
            },
            self.settings.secret_key,
            algorithm=self.settings.algorithm,
        )

    def _issue_refresh_token(self, user_id: str, now: int) -> str:
        jti = uuid.uuid4().hex
        exp = now + self.settings.refresh_token_ttl_seconds
        token = jwt.encode(
            {"sub": user_id, "jti": jti, "iat": now, "exp": exp, "type": "refresh"},
            self.settings.secret_key,
            algorithm=self.settings.algorithm,
        )
        self.store.create_refresh_session(jti, user_id, token, float(exp))
        return token

    # ---------- 刷新（轮换 + 重放检测） ----------

    def refresh(self, refresh_token: str) -> dict:
        claims = self._decode(refresh_token, expected_type="refresh")
        new_jti = uuid.uuid4().hex
        now = int(time.time())
        new_exp = now + self.settings.refresh_token_ttl_seconds
        new_token = jwt.encode(
            {"sub": claims["sub"], "jti": new_jti, "iat": now, "exp": new_exp, "type": "refresh"},
            self.settings.secret_key,
            algorithm=self.settings.algorithm,
        )
        status = self.store.rotate_refresh_session(
            refresh_token, new_jti, new_token, float(new_exp)
        )
        if status == "not_found":
            raise TokenError("invalid")
        if status == "reused":
            # 重放检测：旧令牌被再次提交，撤销该用户全部刷新会话
            self.store.revoke_all_refresh_for_user(claims["sub"])
            raise TokenError("reused")
        if status == "revoked":
            raise TokenError("revoked")
        user = self.store.get_user_by_id(claims["sub"])
        if user is None:
            raise TokenError("invalid")
        return {
            "access_token": self._issue_access_token(user, int(time.time())),
            "refresh_token": new_token,
            "token_type": "bearer",
            "expires_in": self.settings.access_token_ttl_seconds,
        }

    # ---------- 访问令牌校验 ----------

    def decode_access_token(self, token: str) -> dict:
        claims = self._decode(token, expected_type="access")
        if self.store.is_access_revoked(claims["jti"]):
            raise TokenError("revoked")
        user = self.store.get_user_by_id(claims["sub"])
        if user is None or user["token_version"] != claims["tv"]:
            # 角色/权限已变更：旧访问令牌一律失效
            raise TokenError("stale_version")
        claims["user"] = user
        return claims

    # ---------- 撤销 ----------

    def revoke_refresh_token(self, refresh_token: str) -> None:
        """登出：撤销刷新令牌。签名非法时静默处理（幂等，不泄露信息）。"""
        try:
            claims = self._decode(refresh_token, expected_type="refresh")
        except TokenError as exc:
            if exc.reason == "invalid":
                return
            claims = jwt.decode(
                refresh_token,
                self.settings.secret_key,
                algorithms=[self.settings.algorithm],
                options={"verify_exp": False},
            )
        self.store.revoke_refresh_token(refresh_token)

    def revoke_access_token(self, access_token: str) -> None:
        """撤销当前访问令牌（按 jti 记录到过期为止）。"""
        try:
            claims = jwt.decode(
                access_token,
                self.settings.secret_key,
                algorithms=[self.settings.algorithm],
                options={"verify_exp": False},
            )
        except jwt.InvalidTokenError:
            return
        if claims.get("type") == "access" and "jti" in claims:
            self.store.revoke_access_jti(claims["jti"], float(claims.get("exp", 0)))

    def revoke_all_for_user(self, user_id: str) -> None:
        """注销用户全部会话：撤销所有刷新令牌并递增 token_version。"""
        self.store.revoke_all_refresh_for_user(user_id)
        user = self.store.get_user_by_id(user_id)
        if user is not None:
            self.store.set_user_roles(user_id, user["roles"])  # 仅用于递增 tv

    # ---------- 内部 ----------

    def _decode(self, token: str, expected_type: str) -> dict:
        try:
            claims = jwt.decode(
                token, self.settings.secret_key, algorithms=[self.settings.algorithm]
            )
        except jwt.ExpiredSignatureError:
            raise TokenError("expired") from None
        except jwt.InvalidTokenError:
            raise TokenError("invalid") from None
        if claims.get("type") != expected_type:
            raise TokenError("invalid")
        return claims
