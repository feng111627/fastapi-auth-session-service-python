"""业务组2：刷新令牌轮换、旧令牌重放拒绝(可区分原因)、并发重复提交仅一次成功。"""
from __future__ import annotations

import logging
import threading
import queue

from tests.conftest import auth_header

log = logging.getLogger("auth_business")


def _refresh(client, token: str):
    return client.post("/auth/refresh", json={"refresh_token": token})


def test_refresh_rotates_tokens(client, tokens):
    pair = tokens("alice", "alice123")
    r = _refresh(client, pair["refresh_token"])
    assert r.status_code == 200
    new_pair = r.json()
    assert new_pair["refresh_token"] != pair["refresh_token"]
    assert new_pair["access_token"] != pair["access_token"]
    log.info("  刷新成功 → 访问令牌与刷新令牌均已轮换，旧值不再等于新值")


def test_old_refresh_token_replay_is_rejected_with_distinct_code(client, tokens):
    pair = tokens("alice", "alice123")
    assert _refresh(client, pair["refresh_token"]).status_code == 200
    r = _refresh(client, pair["refresh_token"])
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "refresh_replay"
    log.info("  旧刷新令牌二次提交 → 401 refresh_replay（与 invalid/expired/revoked 可区分）")


def test_replay_revokes_session_and_entire_family(client, tokens):
    pair = tokens("alice", "alice123")
    second = _refresh(client, pair["refresh_token"]).json()
    # 攻击者拿到已轮换掉的旧令牌发起重放
    r = _refresh(client, pair["refresh_token"])
    assert r.json()["error"]["code"] == "refresh_replay"

    # 旧访问令牌（重放前签发）立刻不可用
    r1 = client.get("/auth/me", headers=auth_header(pair))
    assert r1.status_code == 401 and r1.json()["error"]["code"] == "session_revoked"
    # 族内最新访问令牌同样不可用（整条族被吊销）
    r2 = client.get("/auth/me", headers=auth_header(second))
    assert r2.status_code == 401 and r2.json()["error"]["code"] == "session_revoked"
    # 族内最新刷新令牌返回 refresh_revoked，与重放原因可区分
    r3 = _refresh(client, second["refresh_token"])
    assert r3.status_code == 401 and r3.json()["error"]["code"] == "refresh_revoked"
    log.info("  重放 → 会话与整条令牌族立即吊销；新旧访问令牌 401，族内刷新令牌 refresh_revoked")


def test_unknown_refresh_token_is_invalid(client):
    r = _refresh(client, "definitely-not-in-db")
    assert r.status_code == 401 and r.json()["error"]["code"] == "refresh_invalid"
    log.info("  未知刷新令牌 → 401 refresh_invalid")


def test_concurrent_duplicate_refresh_only_one_wins(client, tokens):
    """同令牌并发提交 N 次：恰有 1 次拿到新令牌，其余按重放失败，且只有一对有效令牌。"""
    pair = tokens("bob", "bob123")
    results: queue.Queue = queue.Queue()

    def worker():
        # 每个线程使用独立 TestClient（底层各自连接），真实并发打同一个 SQLite
        from fastapi.testclient import TestClient
        from app.main import app
        local = TestClient(app)
        resp = local.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
        results.put((resp.status_code, resp.json()))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    outcomes = [results.get() for _ in threads]
    ok = [o for o in outcomes if o[0] == 200]
    failed = [o for o in outcomes if o[0] == 401]
    codes = {o[1]["error"]["code"] for o in failed}
    assert len(ok) == 1, f"应恰好一次成功，实际 {len(ok)} 次: {outcomes}"
    assert len(failed) == 7
    # 先到的落败者判为重放并吊销整族；其后排队者读到已吊销状态，原因仍可区分
    assert codes <= {"refresh_replay", "refresh_revoked"}, codes
    assert "refresh_replay" in codes, "至少第一个落败者必须判定为重放"

    winner = ok[0][1]
    # 安全规则：系统无法区分"并发重试"与"令牌被盗"，检测到复用即吊销整族。
    # 因此兑换动作本身恰好成功一次；尘埃落定后会话已因复用被吊销，需重新登录。
    r = client.get("/auth/me", headers=auth_header(winner))
    assert r.status_code == 401 and r.json()["error"]["code"] == "session_revoked"
    log.info(
        "  8 个并发请求同刷一个令牌 → 兑换恰好成功 1 次；复用检测吊销整族（%d 重放 / %d 已吊销）",
        sum("refresh_replay" == o[1]["error"]["code"] for o in failed),
        sum("refresh_revoked" == o[1]["error"]["code"] for o in failed),
    )


def test_normal_sequential_rotation_chain_keeps_working(client, tokens):
    """无重放时连续轮换多次，每次旧的作废、新的可用。"""
    pair = tokens("alice", "alice123")
    for i in range(3):
        new_pair = _refresh(client, pair["refresh_token"]).json()
        assert client.get("/auth/me", headers=auth_header(new_pair)).status_code == 200
        pair = new_pair
    log.info("  正常链路连续轮换 3 次 → 每次最新令牌均可用，会话保持有效")
