"""业务组3：按角色/权限放行或拒绝；401 与 403 区分；权限改动后旧令牌即时受限。"""
from __future__ import annotations

import logging

from tests.conftest import auth_header

log = logging.getLogger("auth_business")


def test_permission_allowed_and_denied_distinctly(client, tokens):
    alice = tokens("alice", "alice123")  # editor: doc:read, doc:write
    bob = tokens("bob", "bob123")        # viewer: doc:read
    assert client.get("/docs", headers=auth_header(alice)).status_code == 200
    assert client.post("/docs", headers=auth_header(alice)).status_code == 200
    assert client.get("/docs", headers=auth_header(bob)).status_code == 200
    r = client.post("/docs", headers=auth_header(bob))
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden_permission"
    log.info("  viewer 读文档放行(200)、写文档拒绝(403 forbidden_permission)")


def test_unauthenticated_is_401_not_403(client):
    r = client.get("/admin/stats")
    assert r.status_code == 401 and r.json()["error"]["code"] == "missing_token"
    log.info("  未认证访问管理端 → 401（未认证与无权限结果不同）")


def test_admin_only_endpoint_rejects_non_admin_with_403(client, tokens):
    alice = tokens("alice", "alice123")
    r = client.get("/admin/stats", headers=auth_header(alice))
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden_permission"

    admin = tokens("admin", "admin123")
    assert client.get("/admin/stats", headers=auth_header(admin)).status_code == 200
    log.info("  editor 访问管理端 403；admin 访问 200")


def test_permission_revocation_takes_effect_immediately_with_old_token(client, tokens):
    """核心规则：管理员收回权限后，用户手里尚未过期的旧访问令牌在下一次请求即失去权限。"""
    alice = tokens("alice", "alice123")
    h = auth_header(alice)
    assert client.post("/docs", headers=h).status_code == 200

    admin = tokens("admin", "admin123")
    # 把 alice 从 editor 降为 viewer（重算权限，doc:write 被收回）
    r = client.put(
        "/admin/users/alice/roles",
        json={"roles": ["viewer"]},
        headers=auth_header(admin),
    )
    assert r.status_code == 200
    assert r.json()["permissions"] == ["doc:read", "profile:read"]

    # 旧访问令牌（未过期、未重签）立刻只能读、不能写
    assert client.get("/docs", headers=h).status_code == 200
    denied = client.post("/docs", headers=h)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "forbidden_permission"
    log.info("  alice 被降级后旧访问令牌立即失去 doc:write → 200 变 403，不存在越权窗口")


def test_permission_grant_takes_effect_immediately(client, tokens):
    bob = tokens("bob", "bob123")
    h = auth_header(bob)
    assert client.post("/docs", headers=h).status_code == 403

    admin = tokens("admin", "admin123")
    client.put("/admin/users/bob/roles", json={"roles": ["editor"]}, headers=auth_header(admin))
    assert client.post("/docs", headers=h).status_code == 200
    log.info("  bob 被提升为 editor 后，同一个旧访问令牌立刻获得 doc:write")


def test_disabling_user_revokes_existing_sessions_immediately(client, tokens):
    alice = tokens("alice", "alice123")
    h = auth_header(alice)
    assert client.get("/auth/me", headers=h).status_code == 200

    admin = tokens("admin", "admin123")
    r = client.post(
        "/admin/users/alice/enabled", json={"enabled": False}, headers=auth_header(admin)
    )
    assert r.status_code == 200

    r = client.get("/auth/me", headers=h)
    assert r.status_code == 401 and r.json()["error"]["code"] == "session_revoked"
    # 其刷新令牌也无法再换新
    rr = client.post("/auth/refresh", json={"refresh_token": alice["refresh_token"]})
    assert rr.status_code == 401 and rr.json()["error"]["code"] == "refresh_revoked"
    # 停用期间登录被统一拒绝（不暴露账户存在）
    bad = client.post("/auth/login", json={"username": "alice", "password": "alice123"})
    assert bad.status_code == 401 and bad.json()["error"]["code"] == "invalid_credentials"
    log.info("  停用账户 → 旧访问/刷新令牌立即失效，且登录仍返回统一 invalid_credentials")
