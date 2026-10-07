"""受保护资源：验证角色放行规则、角色变更、会话撤销与过期清理。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.deps import get_current_claims, get_token_service, require_role
from app.tokens import TokenService

router = APIRouter(tags=["protected"])


class RoleUpdateRequest(BaseModel):
    roles: list[str]


@router.get("/me")
def me(claims: dict = Depends(get_current_claims)):
    """任意已认证用户可访问。"""
    return {
        "id": claims["sub"],
        "username": claims["username"],
        "roles": claims["roles"],
    }


@router.get("/admin/dashboard")
def admin_dashboard(claims: dict = Depends(require_role("admin"))):
    """仅 admin 角色可访问。"""
    return {"message": "welcome admin", "username": claims["username"]}


@router.put("/admin/users/{user_id}/roles")
def set_user_roles(
    user_id: str,
    body: RoleUpdateRequest,
    request: Request,
    claims: dict = Depends(require_role("admin")),
):
    """修改用户角色：递增 token_version，该用户旧访问令牌立即失效。"""
    store = request.app.state.store
    if store.get_user_by_id(user_id) is None:
        raise HTTPException(status_code=404, detail={"reason": "not_found"})
    store.set_user_roles(user_id, body.roles)
    return {"id": user_id, "roles": body.roles}


@router.post("/admin/users/{user_id}/revoke")
def revoke_user_sessions(
    user_id: str,
    request: Request,
    claims: dict = Depends(require_role("admin")),
    service: TokenService = Depends(get_token_service),
):
    """撤销指定用户的全部会话（刷新令牌 + 访问令牌）。"""
    store = request.app.state.store
    if store.get_user_by_id(user_id) is None:
        raise HTTPException(status_code=404, detail={"reason": "not_found"})
    service.revoke_all_for_user(user_id)
    return {"id": user_id, "revoked": True}


@router.post("/admin/cleanup")
def cleanup(request: Request, claims: dict = Depends(require_role("admin"))):
    """清理已过期的刷新会话与撤销记录。"""
    return request.app.state.store.cleanup_expired()
