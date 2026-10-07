"""认证路由：登录、刷新、登出。"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])

# 骨架占位：/login /refresh /logout 后续填充
