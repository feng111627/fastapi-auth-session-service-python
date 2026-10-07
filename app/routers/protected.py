"""受保护资源路由：验证角色/权限放行规则。"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["protected"])

# 骨架占位：/me /admin/* 后续填充
