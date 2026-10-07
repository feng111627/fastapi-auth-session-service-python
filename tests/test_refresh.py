"""刷新令牌：轮换、重放检测、并发重复提交、过期。"""
import logging
from concurrent.futures import ThreadPoolExecutor

from tests.conftest import auth_headers, login

logger = logging.getLogger("tests")


class TestRefreshRotation:
    def test_refresh_rotates_tokens(self, client, alice_tokens):
        """刷新成功：换发新令牌对，新访问令牌可用"""
        r = client.post("/auth/refresh", json={"refresh_token": alice_tokens["refresh_token"]})
        assert r.status_code == 200
        new = r.json()
        assert new["refresh_token"] != alice_tokens["refresh_token"]
        assert new["access_token"] != alice_tokens["access_token"]
        r = client.get("/me", headers=auth_headers(new["access_token"]))
        assert r.status_code == 200
        logger.info("PASS 刷新轮换签发新令牌对")

    def test_old_refresh_token_replay_rejected(self, client, alice_tokens):
        """旧刷新令牌再次提交：401 reused，可区分原因"""
        client.post("/auth/refresh", json={"refresh_token": alice_tokens["refresh_token"]})
        r = client.post("/auth/refresh", json={"refresh_token": alice_tokens["refresh_token"]})
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "reused"
        logger.info("PASS 旧刷新令牌重放被拒绝 reason=reused")

    def test_replay_invalidates_whole_chain(self, client, alice_tokens):
        """重放检测后整链撤销：连最新刷新令牌也失效"""
        r = client.post("/auth/refresh", json={"refresh_token": alice_tokens["refresh_token"]})
        newest = r.json()["refresh_token"]
        client.post("/auth/refresh", json={"refresh_token": alice_tokens["refresh_token"]})
        r = client.post("/auth/refresh", json={"refresh_token": newest})
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "revoked"
        logger.info("PASS 重放触发整链撤销")

    def test_concurrent_refresh_only_one_succeeds(self, client, alice_tokens):
        """同一刷新令牌并发提交 N 次：恰好成功一次"""
        token = alice_tokens["refresh_token"]

        def do_refresh(_):
            return client.post("/auth/refresh", json={"refresh_token": token})

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(do_refresh, range(16)))
        successes = [r for r in results if r.status_code == 200]
        failures = [r for r in results if r.status_code == 401]
        assert len(successes) == 1, f"expected exactly 1 success, got {len(successes)}"
        assert all(r.json()["detail"]["reason"] == "reused" for r in failures)
        logger.info("PASS 并发重复提交仅一次成功（1/16）")

    def test_invalid_refresh_token(self, client):
        """伪造刷新令牌：401 invalid"""
        r = client.post("/auth/refresh", json={"refresh_token": "garbage"})
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "invalid"
        logger.info("PASS 伪造刷新令牌 reason=invalid")

    def test_access_token_cannot_refresh(self, client, alice_tokens):
        """访问令牌不能当刷新令牌用"""
        r = client.post("/auth/refresh", json={"refresh_token": alice_tokens["access_token"]})
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "invalid"
        logger.info("PASS 访问令牌不可用于刷新")
