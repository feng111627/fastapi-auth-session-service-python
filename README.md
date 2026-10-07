# 本地用户认证与授权服务（FastAPI）

纯本地运行的用户认证/授权服务：用户与凭据全部保存在本地 SQLite，不接入任何
外部登录服务。实现了登录、双令牌签发、刷新令牌轮换与重放检测、基于角色/权限
的访问控制、会话撤销与过期清理。

## 1. 快速开始

```bash
uv sync                       # 安装依赖
uv run pytest                 # 运行全部单测（业务化日志，见第 7 节）
uv run python main.py         # 启动服务，默认 http://127.0.0.1:8000
# 或：uv run uvicorn app.main:app --reload
```

首次启动会在 `data/auth.db`（SQLite/WAL）建表并写入 3 个种子用户：

| 用户名 | 密码 | 角色 | 权限 |
|---|---|---|---|
| `admin` | `admin123` | admin | `admin:access` `admin:users:write` `profile:read` |
| `alice` | `alice123` | editor | `doc:read` `doc:write` `profile:read` |
| `bob` | `bob123` | viewer | `doc:read` `profile:read` |

可用环境变量：`AUTH_DB_PATH`（数据库路径）、`AUTH_SECRET_KEY`（访问令牌签名
密钥，不设则进程启动时随机生成）、`AUTH_ACCESS_TTL`、`AUTH_REFRESH_TTL`、
`AUTH_PBKDF2_ITERATIONS`。

## 2. 令牌模型

- **访问令牌（access token）**：自包含的 HMAC-SHA256 签名令牌（非 JWT，仅用
  标准库实现），格式 `base64url(payload).base64url(signature)`，载荷为
  `{v, jti, sid, sub, exp}`，默认 **15 分钟**有效。
  载荷里**故意不放角色/权限**——授权一律以每次请求时数据库中的用户状态为准。
  刷新令牌只以 `SHA-256` 摘要落库，明文仅在签发响应中出现一次。
- **刷新令牌（refresh token）**：256 位随机不透明串（约 64 字符），默认
  **7 天**有效。属于一个会话（session）和一个令牌族（family）：一次登录产生
  一个会话与一个族；族内每次轮换产生新的刷新令牌，旧令牌立即作废。
- 刷新成功时会话做**滑动续期**（过期时间重置为 7 天）。

## 3. 刷新轮换与重放/并发规则（核心）

`POST /auth/refresh` 在单条 `BEGIN IMMEDIATE` 事务内完成
「读取 → 判定 → 置 used → 写入新令牌 → 提交」。SQLite 写锁把并发请求串行化，
因此同一个刷新令牌被并发重复提交时，**兑换动作恰好成功一次**。

对旧令牌的再次提交，按原因返回**可区分**的错误码：

| 场景 | HTTP | error.code | 连带动作 |
|---|---|---|---|
| 令牌库里不存在 | 401 | `refresh_invalid` | 无 |
| 已轮换后再次提交（含并发落败者） | 401 | `refresh_replay` | **吊销整条令牌族 + 会话** |
| 已被登出/连带吊销 | 401 | `refresh_revoked` | 无（已是吊销态） |
| 已过期 | 401 | `refresh_expired` | 无 |
| 用户在轮换期间被停用 | 401 | `account_disabled` | 吊销整族 + 会话 |

安全取舍：服务端无法区分「客户端网络重试导致的并发重复提交」与「窃取到刷新
令牌的攻击者重放」，因此任何复用都按 OAuth 刷新令牌轮换的惯例处理——判重放、
吊销整族，要求重新登录。**客户端必须串行化刷新请求**（同一时刻只允许一个
refresh 在途，失败后直接走重新登录，不要自行重试旧令牌）。

## 4. 权限规则与「旧令牌还能做什么」

- 未认证（无令牌/方案错/签名错/过期/会话失效）→ **401**；
  已认证但角色或权限不足 → **403**（`forbidden_roles` / `forbidden_permission`）。
- 授权判定**不相信令牌内容**，每个受保护请求都实时读取 `users` 表。因此：
  - 管理员通过 `PUT /admin/users/{username}/roles` 调整角色（权限由角色映射
    重算）后，**用户手里尚未过期的旧访问令牌在下一次请求即受新权限约束**——
    收回的权限不可能再用旧令牌越权，新授予的权限也无需重新登录即生效。
  - 停用账户（`POST /admin/users/{username}/enabled` `{"enabled": false}`）会
    立即撤销该用户全部有效会话，旧访问/刷新令牌立刻不可用。
- 登录失败（用户不存在 / 密码错 / 账户停用）返回**完全相同**的响应
  `401 invalid_credentials`，并对不存在用户也执行一次 PBKDF2 校验拉平耗时，
  不暴露用户是否存在。

## 5. 失效时机、持久化与清理

- 撤销会话是**即时**的：登出、重放连带吊销、账户停用都会把会话标记为
  `revoked_at` 并吊销其全部刷新令牌；该会话的访问令牌在下一次请求即返回
  `401 session_revoked`，无需等待其 15 分钟自然过期。
- 用户、会话、刷新令牌摘要、撤销记录全部在 SQLite 落盘，**进程重启后状态
  一致**（测试 `test_revocation_survives_process_restart` 覆盖）。注意：若未
  固定 `AUTH_SECRET_KEY`，重启后进程级随机密钥会变，旧访问令牌会因签名失效
  而不可用（刷新会话/撤销记录不受影响）；生产/演示请固定密钥。
- 过期数据不会无限堆积：`POST /admin/cleanup`（需 `admin:access`）删除过期
  会话（级联其刷新令牌）与孤儿过期刷新令牌，并只保留近 30 天撤销记录。

## 6. API 一览

| 方法 路径 | 说明 | 鉴权 |
|---|---|---|
| `POST /auth/login` | 登录，返回令牌对 | 无 |
| `POST /auth/refresh` | 刷新令牌轮换 | 刷新令牌（请求体） |
| `POST /auth/logout` | 撤销会话（请求体可带 refresh_token，否则撤销当前访问令牌会话） | 可选 |
| `GET  /auth/me` | 当前用户、角色、权限 | 已认证 |
| `GET  /docs` | 业务示例：读文档 | `doc:read` |
| `POST /docs` | 业务示例：写文档 | `doc:write` |
| `GET  /admin/stats` | 用户/活跃会话统计 | `admin:access` |
| `PUT  /admin/users/{u}/roles` | 修改角色并重算权限 | `admin:users:write` |
| `POST /admin/users/{u}/enabled` | 启用/停用账户（停用即吊销会话） | `admin:users:write` |
| `POST /admin/cleanup` | 清理过期数据 | `admin:access` |

错误响应统一为 `{"error": {"code": "...", "message": "..."}}`。

### 本地手工验证（curl）

```bash
# 登录
curl -s -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}'
# 用 access_token 访问
curl -s localhost:8000/auth/me -H "Authorization: Bearer <access_token>"
# 刷新（拿到新的一对令牌，旧 refresh_token 立即失效）
curl -s -X POST localhost:8000/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
# 再用一次旧 refresh_token → 401 refresh_replay，且整族/会话被吊销
# 登出
curl -s -X POST localhost:8000/auth/logout -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
# 越权：bob 写文档 → 403；不带令牌 → 401
curl -s -X POST localhost:8000/docs -H "Authorization: Bearer <bob_access>"
```

## 7. 测试

`uv run pytest`（`-v` + 实时业务日志已在 `pytest.ini` 中配置）。26 个用例按
业务分 4 组，日志会打印每个用例覆盖的业务点与 PASS/FAIL 结果：

1. `tests/test_01_login_auth.py`：登录成功、错误账密、用户枚举防护、
   缺失/畸形/错误方案令牌、身份读取。
2. `tests/test_02_refresh_rotation.py`：轮换、旧令牌重放（可区分原因）、
   重放吊销整族与会话、未知令牌、**8 线程并发同刷一个令牌恰好一次成功**、
   正常连续轮换链路。
3. `tests/test_03_authorization.py`：权限放行/拒绝、401 与 403 区分、
   降权后旧令牌立即受限（无越权窗口）、提权即时生效、停用账户即时失效。
4. `tests/test_04_revocation_expiry.py`：登出即时失效与幂等、访问/刷新令牌
   过期（可区分错误码）、过期清理计数、**进程重启后撤销状态持久一致**。

## 8. 代码结构

```
app/config.py        配置（环境变量、TTL、密钥）
app/db.py            SQLite 建表/连接/事务/种子用户/过期清理
app/security.py      PBKDF2 密码哈希、HMAC 访问令牌签发与校验、随机串
app/auth.py          登录、原子轮换+重放检测、登出/撤销、实时权限读取
app/dependencies.py  Bearer 解析、会话实时校验、require_roles/require_permissions
app/routes.py        HTTP 路由与角色→权限映射
app/main.py          应用工厂与统一错误处理
tests/               4 组 26 个用例
```
