# fastapi-auth-session-service

本地可运行的用户认证与授权服务（FastAPI + SQLite + JWT）。用户与凭据全部存放在本地 SQLite，不依赖任何外部登录服务。

## 快速开始

```bash
uv sync                 # 安装依赖
uv run python main.py   # 启动服务，监听 127.0.0.1:8000
uv run pytest           # 运行全部单测（-v + 业务日志，逐条显示覆盖点与结果）
```

预置本地用户（首次启动自动写入 `auth.db`）：

| 用户名  | 口令      | 角色          |
| ------- | --------- | ------------- |
| `admin` | `admin123`| `admin`,`user`|
| `alice` | `alice123`| `user`        |

密钥与有效期通过环境变量覆盖：`AUTH_SECRET_KEY`、`AUTH_DB_PATH`（默认 `auth.db`）。

## 令牌模型

登录（`POST /auth/login`）成功后签发一对令牌：

- **访问令牌**（JWT，默认 15 分钟）：携带 `sub / username / roles / tv / jti / exp`，`type=access`。用于访问业务接口（`Authorization: Bearer <token>`）。
- **刷新令牌**（JWT，默认 7 天）：携带 `sub / jti / exp`，`type=refresh`。服务端只保存其 **SHA-256 哈希**（`refresh_sessions` 表），不落明文。只能用于 `POST /auth/refresh`，不能访问业务接口，反之亦然。

两种令牌类型互斥使用，混用一律 `401 invalid`。

### 刷新轮换与重放检测

- 每次 `POST /auth/refresh` 都会**换发新刷新令牌**，旧令牌立即作废（轮换）。
- 旧刷新令牌再次提交：`401`，`reason=reused`；同时**撤销该用户全部刷新会话**（防止重放扩散），此时连最新令牌也变为 `revoked`。
- 并发重复提交同一刷新令牌：存储层用条件更新（`UPDATE ... WHERE revoked=0`）保证**恰好一个请求成功**，其余全部 `reused`。
- 刷新失败原因可区分：`expired`（过期）/ `invalid`（伪造或类型错误）/ `reused`（重放）/ `revoked`（已撤销）。

## 权限规则

- 未认证（无令牌或令牌无效）→ **401**，`reason` 为 `missing_token / invalid / expired / revoked / stale_version`。
- 已认证但角色不足 → **403**，`reason=insufficient_role`。两者严格区分。
- 登录失败统一 `401 invalid_credentials`：用户不存在与口令错误返回**完全相同**的响应，不暴露用户是否存在。
- 角色校验基于令牌中的 `roles` 声明，管理接口（`/admin/*`）要求 `admin` 角色。

### 角色变更后旧令牌能做什么（确定性规则）

每个用户维护 `token_version`，签发访问令牌时把当前版本写入 `tv` 声明。**任何角色/权限变更都会使 `token_version` 递增**，之后每次请求都会比对令牌 `tv` 与库中当前版本：

- 不一致 → `401 stale_version`，旧访问令牌**立即全部失效**，不存在"权限已收回但旧令牌照样越权"的窗口。
- 用户重新登录后获得携带新角色的新令牌。

## 登出与撤销

- `POST /auth/logout`：撤销请求体中的刷新令牌；若同时携带访问令牌则一并撤销（按 `jti` 记入 `revoked_access` 表）。幂等，始终返回 `204`，伪造令牌也不报错。
- `POST /admin/users/{id}/revoke`（admin）：撤销指定用户全部会话——所有刷新令牌置为 revoked，并递增 `token_version` 使访问令牌失效。
- 撤销**立即生效**：刷新令牌在轮换/撤销时落库，访问令牌每次请求都检查撤销表与版本号。

## 持久化与清理

- 所有会话与撤销记录存于本地 SQLite（WAL 模式），**进程重启后状态保持一致**：已撤销的令牌重启后依然失效，未撤销的会话重启后仍可刷新（有对应测试覆盖）。
- 过期清理：`POST /admin/cleanup`（admin）或服务启动时自动执行，删除已过期的刷新会话与撤销记录，不会无限堆积。

## 接口一览

| 方法 | 路径 | 说明 | 鉴权 |
| --- | --- | --- | --- |
| POST | `/auth/login` | 登录，签发令牌对 | 无 |
| POST | `/auth/refresh` | 刷新（轮换） | 刷新令牌 |
| POST | `/auth/logout` | 登出，撤销令牌 | 无（幂等） |
| GET | `/me` | 当前用户信息 | 任意有效访问令牌 |
| GET | `/admin/dashboard` | 管理示例接口 | `admin` |
| PUT | `/admin/users/{id}/roles` | 修改角色（旧令牌立即失效） | `admin` |
| POST | `/admin/users/{id}/revoke` | 撤销用户全部会话 | `admin` |
| POST | `/admin/cleanup` | 清理过期记录 | `admin` |

## 本地验证

```bash
# 登录
curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}'

# 访问受保护接口
curl -s localhost:8000/me -H "Authorization: Bearer <access_token>"

# 刷新（旧刷新令牌再次提交会返回 401 reused）
curl -s -X POST localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'

# 登出
curl -s -X POST localhost:8000/auth/logout \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
```

## 测试

`uv run pytest` 运行 28 个用例，日志逐条显示覆盖的业务点与结果：

- `tests/test_auth.py`：登录成功/失败、用户枚举防护、未认证/伪造令牌、令牌类型互斥
- `tests/test_refresh.py`：刷新轮换、重放拒绝、整链撤销、**并发重复提交仅一次成功**、类型混用
- `tests/test_authorization.py`：角色放行/拒绝（401 vs 403）、角色变更后旧令牌失效、新令牌反映新角色
- `tests/test_expiry_logout.py`：访问/刷新令牌过期、登出撤销、登出幂等、管理员撤销、**重启后撤销与会话保持一致**、过期清理
