"""口令散列与校验（stdlib pbkdf2）。"""
from __future__ import annotations


def hash_password(password: str) -> str:
    raise NotImplementedError


def verify_password(password: str, stored: str) -> bool:
    raise NotImplementedError
