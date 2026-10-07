"""授权：角色放行/拒绝、权限收回后旧令牌失效。"""
import logging

from tests.conftest import auth_headers, login

logger = logging.getLogger("tests")


class TestRoleBasedAccess:
    def test_admin_can_access_admin_api(self, client, admin_tokens):
        """admin 角色可访问管理接口"""
        r = client.get("/admin/dashboard", headers=auth_headers(admin_tokens["access_token"]))
        assert r.status_code == 200
        logger.info("PASS admin 放行管理接口")

    def test_user_role_forbidden(self, client, alice_tokens):
        """普通用户访问管理接口：403 insufficient_role（与 401 区分）"""
        r = client.get("/admin/dashboard", headers=auth_headers(alice_tokens["access_token"]))
        assert r.status_code == 403
        assert r.json()["detail"]["reason"] == "insufficient_role"
        logger.info("PASS 无权限返回 403 insufficient_role")

    def test_anonymous_gets_401_not_403(self, client):
        """未认证访问管理接口：401 而非 403"""
        r = client.get("/admin/dashboard")
        assert r.status_code == 401
        logger.info("PASS 未认证返回 401 而非 403")


class TestPermissionRevocation:
    def test_old_token_loses_access_after_role_change(self, client, admin_tokens):
        """角色被收回后，旧访问令牌立即失效（stale_version）"""
        r = login(client, "alice", "alice123")
        alice_token = r.json()["access_token"]
        assert client.get("/me", headers=auth_headers(alice_token)).status_code == 200

        alice_id = client.get("/me", headers=auth_headers(alice_token)).json()["id"]
        r = client.put(
            f"/admin/users/{alice_id}/roles",
            json={"roles": []},
            headers=auth_headers(admin_tokens["access_token"]),
        )
        assert r.status_code == 200

        r = client.get("/me", headers=auth_headers(alice_token))
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "stale_version"
        logger.info("PASS 角色变更后旧令牌立即失效")

    def test_new_token_reflects_new_roles(self, client, admin_tokens):
        """重新登录后新令牌携带新角色"""
        r = login(client, "alice", "alice123")
        me = client.get("/me", headers=auth_headers(r.json()["access_token"])).json()
        client.put(
            f"/admin/users/{me['id']}/roles",
            json={"roles": ["user", "editor"]},
            headers=auth_headers(admin_tokens["access_token"]),
        )
        r = login(client, "alice", "alice123")
        me = client.get("/me", headers=auth_headers(r.json()["access_token"])).json()
        assert "editor" in me["roles"]
        logger.info("PASS 新令牌反映新角色")

    def test_non_admin_cannot_change_roles(self, client, alice_tokens):
        """普通用户无权修改角色"""
        r = client.put(
            "/admin/users/whoever/roles",
            json={"roles": ["admin"]},
            headers=auth_headers(alice_tokens["access_token"]),
        )
        assert r.status_code == 403
        logger.info("PASS 普通用户改角色被拒绝")
