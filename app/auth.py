"""核心认证流程：登录、刷新轮换（含并发互斥与重放检测）、登出/撤销。

并发安全：刷新轮换在单条 ``BEGIN IMMEDIATE`` 事务内完成（读取→判定→置 used
→写入新令牌→提交）。SQLite 的写锁会让并发请求串行化，因此同一个刷新令牌被
并发重复提交时，只有第一个事务能换到新令牌，后到者看到的已是 used=1，按重放
处理并吊销整条令牌族（f​​amily）。

权限时效：访问令牌不携带角色/权限；每个受保护请求都实时读取 users 表，因此
角色/权限改动在当次请求即生效，不需要等旧令牌过期。
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import time

from app.config import Settings, get_settings
from app.db import get_conn, transaction
from app.models import TokenPair
from app.security import (
    create_access_token,
    hash_password,
    new_refresh_token,
    sha256_text,
    verify_password,
)

# 为避免"用户不存在"响应更快而泄露账户是否存在，对不存在用户也做一次等耗时校验
_DUMMY_HASH = hash_password("invalid-credential-timing-equalizer", 200_000)


class AuthError(Exception):
    """认证/授权失败；code 为可区分的机器可读原因，status_code 区分 401/403。"""

    def __init__(self, code: str, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def _get_user(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def _record_revocation(
    conn: sqlite3.Connection,
    target_type: str,
    target_id: str,
    reason: str,
    now: float,
    username: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO revocations(target_type, target_id, reason, username, created_at)"
        " VALUES (?,?,?,?,?)",
        (target_type, target_id, reason, username, now),
    )


def revoke_session(conn: sqlite3.Connection, session_id: str, now: float, reason: str) -> bool:
    """立即撤销会话及其全部刷新令牌；已撤销则返回 False（幂等）。"""
    row = conn.execute(
        "SELECT username FROM sessions WHERE id = ? AND revoked_at IS NULL", (session_id,)
    ).fetchone()
    if row is None:
        return False
    conn.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?", (now, session_id))
    conn.execute(
        "UPDATE refresh_tokens SET revoked = 1, revoked_at = ?, revoke_reason = ?"
        " WHERE session_id = ? AND revoked = 0",
        (now, reason, session_id),
    )
    _record_revocation(conn, "session", session_id, reason, now, row["username"])
    return True


def _revoke_family(conn: sqlite3.Connection, family_id: str, now: float, reason: str) -> None:
    conn.execute(
        "UPDATE refresh_tokens SET revoked = 1, revoked_at = ?, revoke_reason = ?"
        " WHERE family_id = ? AND revoked = 0",
        (now, reason, family_id),
    )
    _record_revocation(conn, "refresh_family", family_id, reason, now)


def _issue_pair(
    conn: sqlite3.Connection,
    settings: Settings,
    *,
    username: str,
    session_id: str,
    family_id: str,
    now: float,
) -> TokenPair:
    """生成访问令牌 + 新刷新令牌，并把刷新令牌摘要落库。"""
    jti = _new_id("jti")
    access = create_access_token(
        settings.secret_key,
        jti=jti,
        session_id=session_id,
        username=username,
        now=now,
        ttl=settings.access_token_ttl_seconds,
    )
    raw_refresh = new_refresh_token()
    conn.execute(
        "INSERT INTO refresh_tokens(token_hash, family_id, session_id, username,"
        " issued_at, expires_at) VALUES (?,?,?,?,?,?)",
        (
            sha256_text(raw_refresh),
            family_id,
            session_id,
            username,
            now,
            now + settings.refresh_token_ttl_seconds,
        ),
    )
    return TokenPair(
        access_token=access.token,
        refresh_token=raw_refresh,
        expires_in=settings.access_token_ttl_seconds,
    )


def authenticate(username: str, password: str, now: float | None = None) -> TokenPair:
    """校验账密并签发令牌对。账密错误、账户停用统一返回同一错误，不暴露用户是否存在。"""
    now = time.time() if now is None else now
    settings = get_settings()
    with transaction() as conn:
        user = _get_user(conn, username)
        stored_hash = user["password_hash"] if user is not None else _DUMMY_HASH
        password_ok = verify_password(password, stored_hash)
        if user is None or not password_ok or not user["enabled"]:
            # 三种情况（不存在 / 密码错 / 已停用）对外完全一致
            raise AuthError("invalid_credentials", "用户名或密码错误")
        session_id = _new_id("sess")
        family_id = _new_id("fam")
        conn.execute(
            "INSERT INTO sessions(id, username, created_at, expires_at) VALUES (?,?,?,?)",
            (session_id, username, now, now + settings.refresh_token_ttl_seconds),
        )
        return _issue_pair(
            conn, settings, username=username, session_id=session_id, family_id=family_id, now=now
        )


def rotate_refresh_token(refresh_token: str, now: float | None = None) -> TokenPair:
    """原子轮换刷新令牌；任何重放都会吊销整条令牌族及其会话。"""
    now = time.time() if now is None else now
    settings = get_settings()
    token_hash = sha256_text(refresh_token)
    # 注意：重放/停用分支需要"先提交吊销动作、再向调用方抛错"，
    # 因此这里手动管理事务，不能让异常触发回滚把吊销抹掉。
    conn = get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM refresh_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if row is None:
            conn.rollback()
            raise AuthError("refresh_invalid", "刷新令牌无效")
        if row["revoked"]:
            # 已被登出/重放连带吊销；原因落在 revoke_reason 便于审计
            conn.rollback()
            raise AuthError("refresh_revoked", "刷新令牌已被撤销")
        if row["used"]:
            # 重放（含并发重复提交中落败的那一个）：吊销整条族 + 会话
            _revoke_family(conn, row["family_id"], now, "refresh_token_replay")
            revoke_session(conn, row["session_id"], now, "refresh_token_replay")
            conn.commit()
            raise AuthError("refresh_replay", "刷新令牌已被使用（疑似重放），会话已被吊销")
        if row["expires_at"] <= now:
            conn.rollback()
            raise AuthError("refresh_expired", "刷新令牌已过期，请重新登录")

        user = _get_user(conn, row["username"])
        if user is None or not user["enabled"]:
            _revoke_family(conn, row["family_id"], now, "account_disabled")
            revoke_session(conn, row["session_id"], now, "account_disabled")
            conn.commit()
            raise AuthError("account_disabled", "账户已被停用")

        # 原子地把当前令牌标记为已使用
        conn.execute(
            "UPDATE refresh_tokens SET used = 1, used_at = ? WHERE token_hash = ? AND used = 0",
            (now, token_hash),
        )
        # 会话滑动续期
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE id = ?",
            (now + settings.refresh_token_ttl_seconds, row["session_id"]),
        )
        pair = _issue_pair(
            conn,
            settings,
            username=row["username"],
            session_id=row["session_id"],
            family_id=row["family_id"],
            now=now,
        )
        conn.commit()
        return pair
    except AuthError:
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def revoke_by_refresh_token(refresh_token: str, now: float | None = None) -> bool:
    """登出：按刷新令牌定位并撤销会话。令牌无效返回 False（路由层做幂等处理）。"""
    now = time.time() if now is None else now
    token_hash = sha256_text(refresh_token)
    with transaction() as conn:
        row = conn.execute(
            "SELECT session_id FROM refresh_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if row is None:
            return False
        return revoke_session(conn, row["session_id"], now, "logout")


def load_session(conn: sqlite3.Connection, session_id: str, now: float) -> sqlite3.Row | None:
    """返回有效会话；已撤销或已过期返回 None。"""
    return conn.execute(
        "SELECT * FROM sessions WHERE id = ? AND revoked_at IS NULL AND expires_at > ?",
        (session_id, now),
    ).fetchone()


def load_principal_data(
    conn: sqlite3.Connection, username: str
) -> tuple[list[str], list[str], bool]:
    """实时读取角色/权限/启用状态——授权判定的唯一依据。"""
    user = _get_user(conn, username)
    if user is None:
        return [], [], False
    return json.loads(user["roles"]), json.loads(user["permissions"]), bool(user["enabled"])
