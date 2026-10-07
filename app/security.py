"""密码哈希与访问令牌的签名/校验（仅用标准库，HMAC-SHA256 自包含令牌）。

访问令牌格式：``base64url(payload).base64url(hmac_sha256(secret, payload))``
payload 为 JSON：{v, jti, sid, sub, exp}。
令牌本身不携带角色/权限——授权一律以请求时数据库中的用户状态为准，因此
角色或权限被收回后，无需等待访问令牌过期即立即生效（见 dependencies 模块）。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

_PBKDF2_ALGO = "pbkdf2_sha256"


@dataclass(frozen=True)
class AccessToken:
    token: str
    jti: str
    session_id: str
    username: str
    expires_at: float


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def hash_password(password: str, iterations: int) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_PBKDF2_ALGO}${iterations}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iter_s, salt_s, dk_s = stored.split("$", 3)
        if algo != _PBKDF2_ALGO:
            return False
        salt = _b64d(salt_s)
        expected = _b64d(dk_s)
    except (ValueError, TypeError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iter_s))
    return hmac.compare_digest(dk, expected)


def new_refresh_token() -> str:
    """256 位随机不透明刷新令牌，只以 SHA-256 摘要落库。"""
    return secrets.token_urlsafe(48)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sign(secret_key: str, payload_b64: str) -> str:
    mac = hmac.new(secret_key.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256)
    return _b64e(mac.digest())


def create_access_token(
    secret_key: str, *, jti: str, session_id: str, username: str, now: float, ttl: int
) -> AccessToken:
    expires_at = now + ttl
    payload = {"v": 1, "jti": jti, "sid": session_id, "sub": username, "exp": int(expires_at)}
    payload_b64 = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig_b64 = _sign(secret_key, payload_b64)
    return AccessToken(
        token=f"{payload_b64}.{sig_b64}",
        jti=jti,
        session_id=session_id,
        username=username,
        expires_at=expires_at,
    )


def parse_access_token(secret_key: str, token: str, now: float) -> tuple[str, str, str]:
    """校验签名与过期时间，返回 (jti, session_id, username)；失败抛 ValueError。"""
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except (ValueError, AttributeError):
        raise ValueError("malformed token")
    expected_sig = _sign(secret_key, payload_b64)
    if not hmac.compare_digest(expected_sig, sig_b64):
        raise ValueError("bad signature")
    try:
        payload = json.loads(_b64d(payload_b64))
    except Exception:
        raise ValueError("malformed payload")
    if payload.get("v") != 1 or not all(isinstance(payload.get(k), str) for k in ("jti", "sid", "sub")):
        raise ValueError("invalid payload")
    if not isinstance(payload.get("exp"), int) or payload["exp"] <= int(now):
        raise ValueError("token expired")
    return payload["jti"], payload["sid"], payload["sub"]
