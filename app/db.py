"""SQLite 持久化层：用户、刷新会话、访问令牌撤销记录。

所有数据落盘到本地 SQLite，进程重启后会话与撤销记录保持一致。
刷新令牌在库中只存 SHA-256 哈希，不存明文。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    roles TEXT NOT NULL DEFAULT '[]',
    token_version INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_sessions (
    jti TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    replaced_by TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS revoked_access (
    jti TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);
"""


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Store:
    """线程安全的 SQLite 存储。单连接 + 互斥锁，保证刷新轮换的原子性。"""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self.init_schema()

    def init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---------- 用户 ----------

    def create_user(
        self, user_id: str, username: str, password_hash: str, roles: list[str]
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO users (id, username, password_hash, roles, token_version, created_at)"
                " VALUES (?, ?, ?, ?, 1, ?)",
                (user_id, username, password_hash, json.dumps(roles), time.time()),
            )
            self._conn.commit()

    def get_user_by_username(self, username: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        return self._row_to_user(row)

    def get_user_by_id(self, user_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return self._row_to_user(row)

    def set_user_roles(self, user_id: str, roles: list[str]) -> None:
        """修改角色并递增 token_version：旧访问令牌立即失效。"""
        with self._lock:
            self._conn.execute(
                "UPDATE users SET roles = ?, token_version = token_version + 1 WHERE id = ?",
                (json.dumps(roles), user_id),
            )
            self._conn.commit()

    @staticmethod
    def _row_to_user(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        return {
            "id": row["id"],
            "username": row["username"],
            "password_hash": row["password_hash"],
            "roles": json.loads(row["roles"]),
            "token_version": row["token_version"],
        }

    # ---------- 刷新会话 ----------

    def create_refresh_session(
        self, jti: str, user_id: str, token: str, expires_at: float
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO refresh_sessions (jti, user_id, token_hash, expires_at, revoked, replaced_by, created_at)"
                " VALUES (?, ?, ?, ?, 0, NULL, ?)",
                (jti, user_id, hash_token(token), expires_at, time.time()),
            )
            self._conn.commit()

    def get_refresh_session_by_token(self, token: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM refresh_sessions WHERE token_hash = ?",
                (hash_token(token),),
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    def rotate_refresh_session(
        self, old_token: str, new_jti: str, new_token: str, new_expires_at: float
    ) -> str:
        """原子轮换：仅当旧会话未撤销时成功。

        返回 "ok" / "not_found" / "reused" / "revoked"。
        并发重复提交时只有一个请求能把 revoked 从 0 改成 1。
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT user_id, revoked, replaced_by FROM refresh_sessions WHERE token_hash = ?",
                (hash_token(old_token),),
            ).fetchone()
            if row is None:
                return "not_found"
            if row["revoked"]:
                return "reused" if row["replaced_by"] is not None else "revoked"
            # 条件更新保证并发下只有一个请求能把 revoked 从 0 改成 1
            cur = self._conn.execute(
                "UPDATE refresh_sessions SET revoked = 1, replaced_by = ?"
                " WHERE token_hash = ? AND revoked = 0",
                (new_jti, hash_token(old_token)),
            )
            if cur.rowcount == 0:
                self._conn.rollback()
                return "reused"
            self._conn.execute(
                "INSERT INTO refresh_sessions (jti, user_id, token_hash, expires_at, revoked, replaced_by, created_at)"
                " VALUES (?, ?, ?, ?, 0, NULL, ?)",
                (new_jti, row["user_id"], hash_token(new_token), new_expires_at, time.time()),
            )
            self._conn.commit()
            return "ok"

    def revoke_refresh_token(self, token: str) -> bool:
        """按令牌撤销，返回是否有记录被撤销。"""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE refresh_sessions SET revoked = 1 WHERE token_hash = ? AND revoked = 0",
                (hash_token(token),),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def revoke_all_refresh_for_user(self, user_id: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE refresh_sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0",
                (user_id,),
            )
            self._conn.commit()
            return cur.rowcount

    # ---------- 访问令牌撤销 ----------

    def revoke_access_jti(self, jti: str, expires_at: float) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO revoked_access (jti, expires_at) VALUES (?, ?)",
                (jti, expires_at),
            )
            self._conn.commit()

    def is_access_revoked(self, jti: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM revoked_access WHERE jti = ?", (jti,)
            ).fetchone()
        return row is not None

    # ---------- 清理 ----------

    def cleanup_expired(self, now: float | None = None) -> dict:
        """删除已过期的刷新会话与访问令牌撤销记录，避免无限堆积。"""
        now = now if now is not None else time.time()
        with self._lock:
            cur1 = self._conn.execute(
                "DELETE FROM refresh_sessions WHERE expires_at < ?", (now,)
            )
            cur2 = self._conn.execute(
                "DELETE FROM revoked_access WHERE expires_at < ?", (now,)
            )
            self._conn.commit()
        return {"refresh_sessions": cur1.rowcount, "revoked_access": cur2.rowcount}
