"""SQLite 持久化：用户、会话、刷新令牌族、撤销记录。

表设计要点：
- ``users``：用户名、PBKDF2 密码哈希、启用状态、角色(JSON)、权限(JSON)、版本号。
- ``sessions``：一次登录一条；访问令牌通过 sid 绑定会话，撤销会话即令牌立即失效。
- ``refresh_tokens``：只存刷新令牌的 SHA-256 摘要与族(family)关系；
  ``used`` 标记已轮换，``revoked`` 标记吊销，重放检测依赖两者。
- ``revocations``：审计型撤销记录（谁、何时、为何被撤销）。
所有写入在单连接上以事务完成，SQLite 的写串行化保证并发刷新只有一次成功。
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator

from app.config import get_settings
from app.security import hash_password

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username     TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,
    roles        TEXT NOT NULL DEFAULT '[]',
    permissions  TEXT NOT NULL DEFAULT '[]',
    version      INTEGER NOT NULL DEFAULT 1,
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    username    TEXT NOT NULL REFERENCES users(username),
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    revoked_at  REAL
);
CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash  TEXT PRIMARY KEY,
    family_id   TEXT NOT NULL,
    session_id  TEXT NOT NULL REFERENCES sessions(id),
    username    TEXT NOT NULL,
    issued_at   REAL NOT NULL,
    expires_at  REAL NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    used_at     REAL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    revoked_at  REAL,
    revoke_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_rt_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_rt_session ON refresh_tokens(session_id);

CREATE TABLE IF NOT EXISTS revocations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL,           -- 'session' | 'refresh_family' | 'user'
    target_id   TEXT NOT NULL,
    reason      TEXT NOT NULL,
    username    TEXT,
    created_at  REAL NOT NULL
);
"""

_SEED_USERS = (
    # 用户名, 密码, 角色, 权限
    ("admin", "admin123", ["admin"], ["admin:access", "admin:users:write", "profile:read"]),
    ("alice", "alice123", ["editor"], ["doc:read", "doc:write", "profile:read"]),
    ("bob", "bob123", ["viewer"], ["doc:read", "profile:read"]),
)


def get_conn() -> sqlite3.Connection:
    settings = get_settings()
    db_dir = os.path.dirname(settings.database_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(settings.database_path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    """开启 IMMEDIATE 事务，保证并发刷新令牌轮换时的原子互斥。"""
    conn = get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(seed: bool = True) -> None:
    settings = get_settings()
    db_dir = os.path.dirname(settings.database_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = get_conn()
    try:
        conn.executescript(_SCHEMA)
        if seed:
            now = time.time()
            for username, password, roles, perms in _SEED_USERS:
                conn.execute(
                    "INSERT OR IGNORE INTO users(username, password_hash, enabled, roles,"
                    " permissions, version, created_at) VALUES (?,?,?,?,?,?,?)",
                    (
                        username,
                        hash_password(password, settings.pbkdf2_iterations),
                        1,
                        json.dumps(roles),
                        json.dumps(perms),
                        1,
                        now,
                    ),
                )
    finally:
        conn.close()

def cleanup_expired(conn: sqlite3.Connection, now: float) -> dict[str, int]:
    """删除已过期的会话与刷新令牌，并压缩撤销记录，返回各类删除条数。"""
    # 先统计过期会话名下的刷新令牌数（它们会随会话一起被级联删除）
    expired_sessions = conn.execute(
        "SELECT id FROM sessions WHERE expires_at <= ?", (now,)
    ).fetchall()
    session_ids = [r["id"] for r in expired_sessions]
    cascade_rt = 0
    if session_ids:
        placeholders = ",".join("?" * len(session_ids))
        cascade_rt = conn.execute(
            f"SELECT COUNT(*) AS c FROM refresh_tokens WHERE session_id IN ({placeholders})",
            session_ids,
        ).fetchone()["c"]
        conn.execute(
            f"DELETE FROM refresh_tokens WHERE session_id IN ({placeholders})", session_ids
        )
        conn.execute(f"DELETE FROM sessions WHERE id IN ({placeholders})", session_ids)

    # 会话仍有效但刷新令牌本身已过期的孤儿行
    cur = conn.execute("DELETE FROM refresh_tokens WHERE expires_at <= ?", (now,))
    rt_deleted = cascade_rt + cur.rowcount

    # 撤销记录仅保留近 30 天，避免无限堆积
    cur = conn.execute("DELETE FROM revocations WHERE created_at <= ?", (now - 30 * 24 * 3600,))
    rev_deleted = cur.rowcount
    return {
        "sessions": len(session_ids),
        "refresh_tokens": rt_deleted,
        "revocation_records": rev_deleted,
    }
