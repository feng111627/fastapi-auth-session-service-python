"""测试夹具：每个用例使用独立临时数据库；提供可控时钟与业务化结果日志。"""
from __future__ import annotations

import logging
import os
import tempfile
import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

LOGGER_NAME = "auth_business"
log = logging.getLogger(LOGGER_NAME)

_REAL_TIME = time.time


class Clock:
    """全局可控时钟：offset 秒叠加到真实时间上，用于模拟令牌过期。"""

    def __init__(self) -> None:
        self.offset = 0.0

    def now(self) -> float:
        return _REAL_TIME() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds


@pytest.fixture()
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    clk = Clock()
    # 所有模块均以 time.time() 取时，统一打桩
    import app.auth as auth_mod
    import app.dependencies as dep_mod
    import app.routes as routes_mod

    monkeypatch.setattr(time, "time", clk.now)
    monkeypatch.setattr(auth_mod.time, "time", clk.now)
    monkeypatch.setattr(dep_mod.time, "time", clk.now)
    monkeypatch.setattr(routes_mod.time, "time", clk.now)
    return clk


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch, tmp_path) -> Iterator[TestClient]:
    db_file = tmp_path / "test_auth.db"
    monkeypatch.setenv("AUTH_DB_PATH", str(db_file))
    monkeypatch.setenv("AUTH_SECRET_KEY", "unit-test-secret")
    monkeypatch.setenv("AUTH_ACCESS_TTL", "900")
    monkeypatch.setenv("AUTH_REFRESH_TTL", "86400")

    from app import config as config_mod

    config_mod.get_settings.cache_clear()

    from app import db as db_mod

    db_mod.init_db(seed=True)
    from app.main import create_app

    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def tokens(client: TestClient):
    """返回 (登录助手, 取令牌对助手)。"""
    def login(username: str, password: str) -> dict:
        r = client.post("/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return r.json()

    return login


def auth_header(token_pair: dict) -> dict[str, str]:
    return {"Authorization": "Bearer " + token_pair["access_token"]}


@pytest.fixture(autouse=True)
def _business_case_log(request: pytest.FixtureRequest) -> Iterator[None]:
    log.info("▶ 开始: %s", request.node.nodeid.split("::")[-1])
    yield
    outcome = request.node.rep_call.outcome if hasattr(request.node, "rep_call") else "unknown"
    mark = "PASS" if outcome == "passed" else "FAIL"
    log.info("■ 结束[%s]: %s", mark, request.node.nodeid.split("::")[-1])


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item):
    outcome = yield
    rep = outcome.get_result()
    item.rep_call = rep if rep.when == "call" else getattr(item, "rep_call", rep)
