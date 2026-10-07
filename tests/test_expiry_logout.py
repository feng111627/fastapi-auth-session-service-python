"""过期、登出撤销、跨重启持久化、过期记录清理。"""
import logging
import time

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import auth_headers, login

logger = logging.getLogger("tests")


class TestExpiry:
    def test_expired_access_token_rejected(self, tmp_path):
        """访问令牌过期：401 expired"""
        app = create_app(Settings(db_path=str(tmp_path / "db"), access_token_ttl_seconds=-1))
        client = TestClient(app)
        tokens = login(client, "alice", "alice123").json()
        r = client.get("/me", headers=auth_headers(tokens["access_token"]))
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "expired"
        logger.info("PASS 过期访问令牌 reason=expired")

    def test_expired_refresh_token_rejected(self, tmp_path):
        """刷新令牌过期：401 expired，与 reused/revoked 可区分"""
        app = create_app(Settings(db_path=str(tmp_path / "db"), refresh_token_ttl_seconds=-1))
        client = TestClient(app)
        tokens = login(client, "alice", "alice123").json()
        time.sleep(0.01)
        r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "expired"
        logger.info("PASS 过期刷新令牌 reason=expired")


class TestLogoutRevocation:
    def test_logout_revokes_refresh_token(self, client, alice_tokens):
        """登出后刷新令牌立即失效：reason=revoked"""
        r = client.post("/auth/logout", json={"refresh_token": alice_tokens["refresh_token"]})
        assert r.status_code == 204
        r = client.post("/auth/refresh", json={"refresh_token": alice_tokens["refresh_token"]})
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "revoked"
        logger.info("PASS 登出后刷新令牌立即失效")

    def test_logout_revokes_access_token(self, client, alice_tokens):
        """登出时携带的访问令牌一并撤销"""
        headers = auth_headers(alice_tokens["access_token"])
        assert client.get("/me", headers=headers).status_code == 200
        client.post(
            "/auth/logout",
            json={"refresh_token": alice_tokens["refresh_token"]},
            headers=headers,
        )
        r = client.get("/me", headers=headers)
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "revoked"
        logger.info("PASS 登出后访问令牌立即失效")

    def test_logout_is_idempotent(self, client, alice_tokens):
        """重复登出/伪造令牌登出都返回 204，不泄露信息"""
        body = {"refresh_token": alice_tokens["refresh_token"]}
        assert client.post("/auth/logout", json=body).status_code == 204
        assert client.post("/auth/logout", json=body).status_code == 204
        assert client.post("/auth/logout", json={"refresh_token": "garbage"}).status_code == 204
        logger.info("PASS 登出幂等")

    def test_admin_revoke_all_sessions(self, client, admin_tokens, alice_tokens):
        """管理员撤销用户全部会话：访问令牌与刷新令牌都失效"""
        alice_headers = auth_headers(alice_tokens["access_token"])
        alice_id = client.get("/me", headers=alice_headers).json()["id"]
        r = client.post(
            f"/admin/users/{alice_id}/revoke",
            headers=auth_headers(admin_tokens["access_token"]),
        )
        assert r.status_code == 200
        assert client.get("/me", headers=alice_headers).status_code == 401
        r = client.post("/auth/refresh", json={"refresh_token": alice_tokens["refresh_token"]})
        assert r.status_code == 401
        logger.info("PASS 管理员一键撤销全部会话")


class TestPersistenceAndCleanup:
    def test_revocation_survives_restart(self, tmp_path):
        """进程重启后撤销记录仍生效"""
        db = str(tmp_path / "persist.db")
        client = TestClient(create_app(Settings(db_path=db)))
        tokens = login(client, "alice", "alice123").json()
        client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})

        # 模拟重启：同一数据库文件重建应用
        client2 = TestClient(create_app(Settings(db_path=db)))
        r = client2.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "revoked"
        logger.info("PASS 重启后撤销记录仍生效")

    def test_session_survives_restart(self, tmp_path):
        """进程重启后未撤销的刷新会话仍可用"""
        db = str(tmp_path / "persist.db")
        client = TestClient(create_app(Settings(db_path=db)))
        tokens = login(client, "alice", "alice123").json()

        client2 = TestClient(create_app(Settings(db_path=db)))
        r = client2.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert r.status_code == 200
        logger.info("PASS 重启后会话仍可刷新")

    def test_cleanup_removes_expired_records(self, tmp_path):
        """过期会话与撤销记录可被清理，不无限堆积"""
        db = str(tmp_path / "cleanup.db")
        app = create_app(
            Settings(db_path=db, access_token_ttl_seconds=-1, refresh_token_ttl_seconds=-1)
        )
        client = TestClient(app)
        tokens = login(client, "alice", "alice123").json()
        client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]}, headers=auth_headers(tokens["access_token"]))
        time.sleep(0.01)

        removed = app.state.store.cleanup_expired()
        assert removed["refresh_sessions"] >= 1
        assert removed["revoked_access"] >= 1
        # 再清理一次应为 0：不会重复计数，也不会残留
        removed2 = app.state.store.cleanup_expired()
        assert removed2 == {"refresh_sessions": 0, "revoked_access": 0}
        logger.info("PASS 过期记录清理生效")
