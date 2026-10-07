"""SQLite 持久化层：用户、刷新会话、撤销记录。"""
from __future__ import annotations

import sqlite3


class Store:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def init_schema(self) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
