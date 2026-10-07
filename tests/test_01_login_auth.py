"""业务组1：登录与认证边界——成功、错误账密、用户枚举、令牌形态、缺失/畸形令牌。"""
from __future__ import annotations

import logging

from tests.conftest import auth_header

log = logging.getLogger("auth_business")


def test_login_success_issues_token_pair(client, tokens):
    pair = tokens("alice", "alice123")
    assert pair["token_type"] == "bearer"
    assert pair["expires_in"] == 900
    assert pair["access_token"].count(".") == 1
    assert len(pair["refresh_token"]) >= 40
    log.info("  登录成功 → 访问令牌(HMAC两段式) + 不透明刷新令牌(64字符) 均已签发")


def test_login_wrong_password_rejected(client):
    r = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_credentials"
    log.info("  密码错误 → 401 invalid_credentials，不区分具体原因")


def test_login_nonexistent_user_same_as_bad_password(client):
    r1 = client.post("/auth/login", json={"username": "ghost", "password": "whatever"})
    r2 = client.post("/auth/login", json={"username": "alice", "password": "whatever"})
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json()
    log.info("  用户不存在与密码错误响应体完全一致 → 不泄露用户是否存在")


def test_protected_endpoint_without_token_is_401(client):
    r = client.get("/auth/me")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "missing_token"
    log.info("  未携带令牌 → 401 missing_token")


def test_malformed_and_bad_signature_tokens_are_401(client):
    for token, code in (("not-a-jwt", "token_invalid"), ("aaa.bbb", "token_invalid")):
        r = client.get("/auth/me", headers={"Authorization": "Bearer " + token})
        assert r.status_code == 401, r.text
        assert r.json()["error"]["code"] == code
    log.info("  畸形/签名错误令牌 → 401 token_invalid")


def test_wrong_scheme_is_401(client, tokens):
    pair = tokens("bob", "bob123")
    r = client.get("/auth/me", headers={"Authorization": "Basic " + pair["access_token"]})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_scheme"
    log.info("  非 Bearer 方案 → 401 invalid_scheme")


def test_me_returns_live_identity(client, tokens):
    pair = tokens("bob", "bob123")
    r = client.get("/auth/me", headers=auth_header(pair))
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "bob"
    assert body["roles"] == ["viewer"]
    assert body["permissions"] == ["doc:read", "profile:read"]
    log.info("  /auth/me 返回实时角色/权限 → viewer: doc:read, profile:read")
