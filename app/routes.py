"""HTTP 路由：登录/刷新/登出/会话信息/受保护示例/用户管理/过期清理。"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends

from app import auth
from app.db import cleanup_expired, get_conn, transaction
from app.dependencies import (
    Principal,
    get_current_principal,
    get_optional_principal,
    require_permissions,
)
from app.models import (
    CleanupResponse,
    EnabledRequest,
    LoginRequest,
    LogoutRequest,
    MeResponse,
    RefreshRequest,
    TokenPair,
    UpdateRolesRequest,
)

router = APIRouter()

# 角色 -> 权限的唯一权威映射；改角色即据此重算权限，保证两者不会长期不一致
ROLE_PERMISSIONS: dict[str, list[str]] = {
    "admin": ["admin:access", "admin:users:write", "profile:read"],
    "editor": ["doc:read", "doc:write", "profile:read"],
    "viewer": ["doc:read", "profile:read"],
}


def _me(username: str, roles: list[str], permissions: list[str]) -> MeResponse:
    return MeResponse(username=username, roles=sorted(roles), permissions=sorted(permissions))


@router.post("/auth/login", response_model=TokenPair)
def login(payload: LoginRequest) -> TokenPair:
    return auth.authenticate(payload.username, payload.password)


@router.post("/auth/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest) -> TokenPair:
    return auth.rotate_refresh_token(payload.refresh_token)


@router.post("/auth/logout")
def logout(
    payload: LogoutRequest,
    principal: Principal | None = Depends(get_optional_principal),
) -> dict:
    """撤销会话：优先使用请求体里的刷新令牌撤销；否则撤销访问令牌所属会话。幂等。"""
    revoked = False
    if payload.refresh_token:
        revoked = auth.revoke_by_refresh_token(payload.refresh_token)
    elif principal is not None:
        with transaction() as conn:
            revoked = auth.revoke_session(conn, principal.session_id, time.time(), "logout")
    return {"revoked": revoked}


@router.get("/auth/me", response_model=MeResponse)
def me(principal: Principal = Depends(get_current_principal)) -> MeResponse:
    return _me(principal.username, principal.roles, principal.permissions)


# ---- 受保护的业务示例：按权限放行 ----


@router.get("/docs")
def read_docs(principal: Principal = Depends(require_permissions("doc:read"))) -> dict:
    return {"docs": ["welcome.md", "guide.md"], "reader": principal.username}


@router.post("/docs")
def write_doc(principal: Principal = Depends(require_permissions("doc:write"))) -> dict:
    return {"written_by": principal.username}


# ---- 管理端 ----


@router.get("/admin/stats")
def admin_stats(principal: Principal = Depends(require_permissions("admin:access"))) -> dict:
    conn = get_conn()
    try:
        users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        sessions = conn.execute(
            "SELECT COUNT(*) AS c FROM sessions WHERE revoked_at IS NULL"
        ).fetchone()["c"]
    finally:
        conn.close()
    return {"users": users, "active_sessions": sessions}

@router.put("/admin/users/{username}/roles", response_model=MeResponse)
def update_roles(
    username: str,
    payload: UpdateRolesRequest,
    principal: Principal = Depends(require_permissions("admin:users:write")),
) -> MeResponse:
    """重设用户角色并按角色映射重算权限；下一次请求即生效（旧访问令牌同样受限）。"""
    import json

    unknown = sorted(set(payload.roles) - set(ROLE_PERMISSIONS))
    if unknown:
        raise auth.AuthError("unknown_role", f"未知角色: {unknown}", status_code=400)
    permissions = sorted({p for role in payload.roles for p in ROLE_PERMISSIONS[role]})
    with transaction() as conn:
        cur = conn.execute(
            "UPDATE users SET roles = ?, permissions = ?, version = version + 1"
            " WHERE username = ?",
            (json.dumps(sorted(payload.roles)), json.dumps(permissions), username),
        )
        if cur.rowcount == 0:
            raise auth.AuthError("user_not_found", "用户不存在", status_code=404)
    return _me(username, payload.roles, permissions)



@router.post("/admin/users/{username}/enabled", response_model=MeResponse)
def set_enabled(
    username: str,
    payload: EnabledRequest,
    principal: Principal = Depends(require_permissions("admin:users:write")),
) -> MeResponse:
    """停用账户会同时撤销其全部有效会话（旧令牌立刻不可用）；重新启用后需重新登录。"""
    import json

    now = time.time()
    with transaction() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None:
            raise auth.AuthError("user_not_found", "用户不存在", status_code=404)
        conn.execute("UPDATE users SET enabled = ? WHERE username = ?", (int(payload.enabled), username))
        if not payload.enabled:
            rows = conn.execute(
                "SELECT id FROM sessions WHERE username = ? AND revoked_at IS NULL", (username,)
            ).fetchall()
            for row in rows:
                auth.revoke_session(conn, row["id"], now, "account_disabled")
        roles = json.loads(user["roles"])
        permissions = json.loads(user["permissions"])
    return _me(username, roles, permissions)


@router.post("/admin/cleanup", response_model=CleanupResponse)
def admin_cleanup(
    principal: Principal = Depends(require_permissions("admin:access")),
) -> CleanupResponse:
    with transaction() as conn:
        result = cleanup_expired(conn, time.time())
    return CleanupResponse(**result)
