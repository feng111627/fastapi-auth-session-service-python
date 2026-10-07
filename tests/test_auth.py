"""认证主流程：登录、令牌结构、认证失败不泄露用户是否存在。"""
import logging

from tests.conftest import auth_headers, login

logger = logging.getLogger("tests")


class TestLogin:
    def test_login_success_returns_token_pair(self, client):
        """登录成功：签发访问令牌 + 刷新令牌"""
        r = login(client, "alice", "alice123")
        assert r.status_code == 200
        body = r.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"] and body["refresh_token"]
        assert body["expires_in"] > 0
        logger.info("PASS 登录成功签发令牌对")

    def test_login_wrong_password(self, client):
        """口令错误：401 invalid_credentials"""
        r = login(client, "alice", "wrong-password")
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "invalid_credentials"
        logger.info("PASS 口令错误返回 invalid_credentials")

    def test_login_unknown_user_same_as_wrong_password(self, client):
        """用户不存在与口令错误返回完全一致，不暴露用户是否存在"""
        r_unknown = login(client, "no-such-user", "whatever")
        r_wrongpw = login(client, "alice", "wrong-password")
        assert r_unknown.status_code == r_wrongpw.status_code == 401
        assert r_unknown.json() == r_wrongpw.json()
        logger.info("PASS 用户枚举防护：两种失败响应一致")


class TestAuthenticatedAccess:
    def test_me_with_valid_token(self, client, alice_tokens):
        """有效访问令牌可访问 /me"""
        r = client.get("/me", headers=auth_headers(alice_tokens["access_token"]))
        assert r.status_code == 200
        assert r.json()["username"] == "alice"
        logger.info("PASS 有效令牌访问 /me")

    def test_me_without_token(self, client):
        """未认证：401 missing_token"""
        r = client.get("/me")
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "missing_token"
        logger.info("PASS 未认证返回 401 missing_token")

    def test_me_with_garbage_token(self, client):
        """伪造令牌：401 invalid"""
        r = client.get("/me", headers=auth_headers("not.a.token"))
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "invalid"
        logger.info("PASS 伪造令牌返回 401 invalid")

    def test_refresh_token_cannot_access_api(self, client, alice_tokens):
        """刷新令牌不能当访问令牌用"""
        r = client.get("/me", headers=auth_headers(alice_tokens["refresh_token"]))
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "invalid"
        logger.info("PASS 刷新令牌不可访问业务接口")
