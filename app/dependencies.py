"""FastAPI 依赖：解析访问令牌、实时加载会话与权限、按角色/权限放行。

规则（确定且可说明）：
1. 缺失/畸形/签名错/过期的访问令牌 → 401，错误码各不相同，不暴露用户信息。
2. 令牌有效但会话已撤销（登出、重放连带吊销、管理员撤销）→ 401 session_revoked，
   即撤销立即生效，与令牌自身是否过期无关。
3. 会话有效但用户被停用 → 401 account_disabled。
4. 已认证但角色/权限不满足 → 403（与 401 明确区分）。
5. 角色与权限每次请求实时查库，改动在"下一次请求"即生效，旧访问令牌不会越权。
"""
from __future__ import annotations

import time

from fastapi import Depends, Request

from app import auth
from app.config import get_settings
from app.db import get_conn
from app.security import parse_access_token


class Principal:
    def __init__(self, username: str, session_id: str, roles: list[str], permissions: list[str]):
        self.username = username
        self.session_id = session_id
        self.roles = roles
        self.permissions = permissions


def _fail(code: str, message: str, status_code: int = 401) -> auth.AuthError:
    return auth.AuthError(code, message, status_code)


def get_current_principal(request: Request) -> Principal:
    now = time.time()
    header = request.headers.get("Authorization")
    if not header:
        raise _fail("missing_token", "缺少访问令牌")
    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise _fail("invalid_scheme", "认证方案必须为 Bearer <token>")
    token = parts[1].strip()
    try:
        _jti, session_id, username = parse_access_token(
            get_settings().secret_key, token, now
        )
    except ValueError as exc:
        code = "token_expired" if "expired" in str(exc) else "token_invalid"
        raise _fail(code, "访问令牌无效或已过期")

    conn = get_conn()
    try:
        session = auth.load_session(conn, session_id, now)
        if session is None:
            raise _fail("session_revoked", "会话不存在、已撤销或已过期")
        roles, permissions, enabled = auth.load_principal_data(conn, username)
        if not enabled:
            raise _fail("account_disabled", "账户已被停用")
    finally:
        conn.close()
    return Principal(username=username, session_id=session_id, roles=roles, permissions=permissions)


def get_optional_principal(request: Request) -> Principal | None:
    """与 get_current_principal 相同，但缺失/无效令牌时返回 None 而非抛 401。

    供登出等"登录态可有可无"的接口使用。
    """
    if not request.headers.get("Authorization"):
        return None
    try:
        return get_current_principal(request)
    except auth.AuthError:
        return None


def require_roles(*roles: str):
    """满足任一给定角色即放行。"""
    required = set(roles)

    def dependency(principal: Principal = Depends(get_current_principal)) -> Principal:
        if not required.intersection(principal.roles):
            raise _fail(
                "forbidden_roles",
                f"需要以下角色之一: {sorted(required)}",
                status_code=403,
            )
        return principal

    return dependency


def require_permissions(*permissions: str):
    """必须同时具备全部给定权限才放行。"""
    required = list(permissions)

    def dependency(principal: Principal = Depends(get_current_principal)) -> Principal:
        missing = [p for p in required if p not in principal.permissions]
        if missing:
            raise _fail(
                "forbidden_permission",
                f"缺少权限: {missing}",
                status_code=403,
            )
        return principal

    return dependency
