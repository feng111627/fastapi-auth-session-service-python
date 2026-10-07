"""业务组4：登出/撤销即时生效；访问与刷新令牌过期；过期数据可清理；重启后状态一致。"""
from __future__ import annotations

import logging

from tests.conftest import auth_header

log = logging.getLogger("auth_business")


def test_logout_with_refresh_token_revokes_session_immediately(client, tokens):
    pair = tokens("alice", "alice123")
    h = auth_header(pair)
    assert client.get("/auth/me", headers=h).status_code == 200

    r = client.post("/auth/logout", json={"refresh_token": pair["refresh_token"]})
    assert r.status_code == 200 and r.json() == {"revoked": True}

    assert client.get("/auth/me", headers=h).status_code == 401
    rr = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert rr.status_code == 401 and rr.json()["error"]["code"] == "refresh_revoked"
    log.info("  登出 → 旧访问令牌立刻 401，刷新令牌 refresh_revoked")


def test_logout_is_idempotent(client, tokens):
    pair = tokens("alice", "alice123")
    client.post("/auth/logout", json={"refresh_token": pair["refresh_token"]})
    r = client.post("/auth/logout", json={"refresh_token": pair["refresh_token"]})
    assert r.status_code == 200 and r.json() == {"revoked": False}
    log.info("  重复登出幂等 → 200 revoked:false")


def test_logout_revokes_access_session_without_refresh_token(client, tokens):
    pair = tokens("alice", "alice123")
    h = auth_header(pair)
    r = client.post("/auth/logout", json={}, headers=h)
    assert r.status_code == 200 and r.json() == {"revoked": True}
    assert client.get("/auth/me", headers=h).status_code == 401
    log.info("  仅带访问令牌登出 → 当前会话被撤销，访问令牌立即失效")


def test_expired_access_token_is_rejected_with_distinct_code(client, tokens, clock):
    pair = tokens("alice", "alice123")
    clock.advance(901)  # 超过访问令牌 15 分钟寿命
    r = client.get("/auth/me", headers=auth_header(pair))
    assert r.status_code == 401 and r.json()["error"]["code"] == "token_expired"
    log.info("  访问令牌超过 TTL → 401 token_expired（与签名非法的 token_invalid 可区分）")


def test_expired_refresh_token_cannot_renew(client, tokens, clock):
    pair = tokens("alice", "alice123")
    clock.advance(86401)  # 超过刷新令牌 24 小时测试寿命
    r = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert r.status_code == 401 and r.json()["error"]["code"] == "refresh_expired"
    log.info("  刷新令牌过期 → 401 refresh_expired，要求重新登录")


def test_cleanup_removes_expired_sessions_and_tokens(client, tokens, clock):
    tokens("alice", "alice123")
    tokens("bob", "bob123")

    clock.advance(86401)  # 既有会话/刷新令牌均过期
    # 时钟推进后旧访问令牌也已过期，清理操作需由重新登录的管理员执行
    admin = tokens("admin", "admin123")
    r = client.post("/admin/cleanup", headers=auth_header(admin))
    assert r.status_code == 200
    body = r.json()
    assert body["sessions"] >= 2
    assert body["refresh_tokens"] >= 2
    log.info("  清理过期数据 → 删除 %d 个会话、%d 条刷新令牌", body["sessions"], body["refresh_tokens"])

    stats = client.get("/admin/stats", headers=auth_header(admin)).json()
    assert stats["active_sessions"] == 1
    log.info("  清理后 → 过期记录被删除，只剩当前管理员会话，数据不再无限堆积")


def test_revocation_survives_process_restart(tmp_path, monkeypatch):
    """进程重启：用同一个数据库文件重新 create_app，撤销状态必须保持一致。"""
    db_file = tmp_path / "persist.db"
    monkeypatch.setenv("AUTH_DB_PATH", str(db_file))
    monkeypatch.setenv("AUTH_SECRET_KEY", "stable-secret")

    from app import config as config_mod
    from fastapi.testclient import TestClient

    config_mod.get_settings.cache_clear()
    from app import db as db_mod
    db_mod.init_db(seed=True)
    from app.main import create_app

    client = TestClient(create_app())
    pair = client.post(
        "/auth/login", json={"username": "alice", "password": "alice123"}
    ).json()
    assert client.get("/auth/me", headers=auth_header(pair)).status_code == 200
    client.post("/auth/logout", json={"refresh_token": pair["refresh_token"]})

    # 模拟进程重启：清缓存、重新建 app（同一 DB 文件、同一签名密钥）
    config_mod.get_settings.cache_clear()
    client2 = TestClient(create_app())
    r = client2.get("/auth/me", headers=auth_header(pair))
    assert r.status_code == 401 and r.json()["error"]["code"] == "session_revoked"
    rr = client2.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert rr.status_code == 401 and rr.json()["error"]["code"] == "refresh_revoked"

    # 用户库仍在，可重新登录
    relogin = client2.post(
        "/auth/login", json={"username": "alice", "password": "alice123"}
    )
    assert relogin.status_code == 200
    logging.getLogger("auth_business").info(
        "  重启后 → 撤销状态持久保持（旧令牌仍 401），用户可重新登录"
    )
