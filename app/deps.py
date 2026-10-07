"""FastAPI 依赖：当前用户解析与角色校验。

- 未认证 / 令牌无效 => 401（带 reason，不泄露用户是否存在）
- 已认证但角色不足 => 403
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.tokens import TokenError, TokenService

_bearer = HTTPBearer(auto_error=False)


def get_token_service(request: Request) -> TokenService:
    return request.app.state.token_service


def get_current_claims(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    service: TokenService = Depends(get_token_service),
) -> dict:
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail={"reason": "missing_token", "message": "missing bearer token"},
        )
    try:
        return service.decode_access_token(credentials.credentials)
    except TokenError as exc:
        raise HTTPException(
            status_code=401,
            detail={"reason": exc.reason, "message": "invalid access token"},
        ) from None


def require_role(role: str):
    """要求当前用户拥有指定角色，否则 403。"""

    def checker(claims: dict = Depends(get_current_claims)) -> dict:
        if role not in claims.get("roles", []):
            raise HTTPException(
                status_code=403,
                detail={"reason": "insufficient_role", "message": f"role '{role}' required"},
            )
        return claims

    return checker
