"""认证路由：登录、刷新、登出。

- 登录失败统一 401 invalid_credentials，不区分用户不存在还是口令错误。
- 刷新失败 401 且 reason 可区分：expired / invalid / reused / revoked。
- 登出幂等：撤销刷新令牌 + 当前访问令牌，返回 204。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.deps import get_token_service
from app.schemas import LoginRequest, RefreshRequest, TokenPairResponse
from app.security import verify_password
from app.tokens import TokenError, TokenService

router = APIRouter(prefix="/auth", tags=["auth"])
_bearer = HTTPBearer(auto_error=False)


@router.post("/login", response_model=TokenPairResponse)
def login(body: LoginRequest, request: Request, service: TokenService = Depends(get_token_service)):
    store = request.app.state.store
    user = store.get_user_by_username(body.username)
    # 用户不存在与口令错误返回完全相同的结果，避免枚举用户
    if user is None or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(
            status_code=401,
            detail={"reason": "invalid_credentials", "message": "invalid username or password"},
        )
    return service.issue_token_pair(user)


@router.post("/refresh", response_model=TokenPairResponse)
def refresh(body: RefreshRequest, service: TokenService = Depends(get_token_service)):
    try:
        return service.refresh(body.refresh_token)
    except TokenError as exc:
        raise HTTPException(
            status_code=401,
            detail={"reason": exc.reason, "message": f"refresh token {exc.reason}"},
        ) from None


@router.post("/logout", status_code=204)
def logout(
    body: RefreshRequest,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    service: TokenService = Depends(get_token_service),
):
    """登出：撤销提交的刷新令牌；若带了访问令牌则一并撤销。幂等，始终 204。"""
    service.revoke_refresh_token(body.refresh_token)
    if credentials is not None:
        service.revoke_access_token(credentials.credentials)
    return Response(status_code=204)
