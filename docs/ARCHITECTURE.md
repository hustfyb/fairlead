# frplike 架构设计（v1）

| 项目 | 内容 |
| --- | --- |
| 状态 | Accepted（v0.1 实现基线） |
| 日期 | 2026-10-29 |
| 对应 PRD | `docs/PRD.md` v0.1 |
| 发布方案 | `docs/RELEASE.md` |

本文只写**已经拍板**的东西。带「ADR-n」的条目在 `docs/DECISIONS.md` 里有取舍记录。

---

## 1. 一句话架构

**Nginx 收 HTTP/1.1、按 Host 转给回环上的 Host；Host 只做 Host 查表 + 原样转发，不解析响应；每条请求在 TLS+yamux 隧道上开一条逻辑流，Agent 连本地目标，双向搬字节。**

```
client ──HTTP/1.1──> nginx :8080/:443 ──127.0.0.1:9000──> host
                                                             │  Host 查 route table
                                                             │  yamux::open_stream
                                                             ▼
                                                    TLS1.3 + yamux :9443
                                                             │
                                        ┌────────────────────┴───────────────────┐
                                        ▼                                        ▼
                                     agent A (tunnel×N)                      agent B
                                        │ dial target                           │
                                        ▼                                        ▼
                                  127.0.0.1:7884                            127.0.0.1:7885
```

三个监听、三套中间件，**永不合并 router**：

| 监听 | 默认地址 | 谁能连 | 中间件 |
| --- | --- | --- | --- |
| Edge | `127.0.0.1:9000` | 只有 Nginx（回环） | Host 嗅探、路由、转发、限流 |
| Admin | `127.0.0.1:9001` | 管理员（SSH 隧道 / 受控入口） | 登录会话、CSRF、审计 |
| Tunnel | `0.0.0.0:9443` | Agent（TLS 客户端证书/凭据） | TLS、凭据校验、每 IP 握手限速 |

ADR-1：`frplike-host` 启动时若 `edge_listen` 绑定到非回环地址，直接拒绝启动，除非显式 `allow_public_edge = true`（开发模式）。

---

## 2. 控制面 vs 数据面

| | 数据面 | 控制面 |
| --- | --- | --- |
| 谁 | Edge 请求转发、yamux 流 | Agent 注册、路由声明、心跳、管理 API |
| 状态 | `ArcSwap<RouteTable>` 只读快照 | `RwLock<HashMap<AgentId, Session>>` + SQLite |
| 阻塞 | 不允许任何 DB / 锁等待 | 允许，但单写 actor |

**路由表永远不查 SQLite。** SQLite 只做持久化、审计、重启恢复。写路径唯一：`DbWriter` 单线程 actor + 有界 channel（满了 log + 计数，绝不反压数据面）。

ADR-2：用 `rusqlite`（bundled）+ 写 actor，而不是 `sqlx`。理由：单写者模型不需要连接池；bundled 让 musl 静态链接和 Windows 零依赖成立；省掉 SQLx 的 async trait 与编译期 DB 校验。

---

## 3. 路由模型（PRD 9.2 的修正）

PRD 只有 `routes.enabled`（管理员）和 Agent 声明，两者混在一张表里会导致**管理员删除的路由在 Agent 重连后复活**。v0.1 用显式 tombstone：

```sql
routes(
  id TEXT PRIMARY KEY,
  public_host TEXT UNIQUE NOT NULL,   -- 归一化后
  agent_id TEXT NOT NULL,
  target TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1, -- 管理员意图
  deleted_at INTEGER,                 -- 管理员删除的墓碑
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
)
```

有效路由 = **Agent 本次会话声明** ∩ **`enabled = 1 AND deleted_at IS NULL`**。

| 事件 | 结果 |
| --- | --- |
| Agent 声明新 host | upsert，`active` |
| Agent 不再声明 | 标 `offline`（不删，保留管理员意图） |
| 管理员 disable | `enabled = 0`，立即从快照移除 → 503 |
| 管理员 delete | `deleted_at = now`，Agent 再声明也不复活（`conflict/deleted` 返回给 Agent 并写入 rejected） |
| 管理员 restore | 清 `deleted_at`，下次 Agent 心跳/重连生效 |
| 两个 Agent 抢同一 host | 第二个注册的整条拒绝（`conflict`），不静默顶替 |

`routes` 的 4 个状态：`active` / `offline` / `disabled` / `conflict`，与 PRD 7.3 一致，但 `conflict` 只出现在拒绝回执里，不落库。

---

## 4. HTTP 转发（数据面最关键的 300 行）

### 4.1 Host 只嗅探请求头，响应原样流

1. 从 Edge 连接读到 `\r\n\r\n`，上限 16 KiB（`proto::sniff`，`httparse`）。
2. 解析 request-line + `Host`，归一化（去端口、小写、校验字符集与后缀）。
3. 查 `RouteTable` → 拿 `agent_id` + `target` + `route_id`。
4. 选该 Agent 的一条健康隧道（轮转），`open_stream()`。
5. 写数据流前导：`0x01 | u16 target_len | target`，随后**原样写请求头**。
6. 等 Agent 回 1 字节状态：`0x00` 成功 / `0x01` refuse / `0x02` timeout / `0x03` blocked。
7. 成功 → 双向 `copy`；失败 → Host 自己生成 502/504/503。

### 4.2 只改一个字节序列：`Connection: close`

不重写请求就无从知道响应体何时结束（`Content-Length` / `chunked` / `until-close` 三态），而不结束就关不掉客户端连接。v0.1 的选择是**让上游明确关连接**：

- 普通请求：把 `Connection` 头替换为 `close`，删除 `Keep-Alive`、`Proxy-Connection`。其余字节原样。
- 带 `Upgrade` 的请求（WebSocket）：**一个字节都不改**。响应 101 之后进入裸字节隧道，等任一侧关闭或 idle timeout（默认 300s）。
- 因此 v0.1 **没有上游 keepalive**：每请求一次回环建连（几十微秒）+ TIME_WAIT。2000 并发流完全够用；QPS 上千后再在 `edge::forward` 一个函数里加连接池。

ADR-3：一连接一请求。ADR-4：Upgrade 永不被改写。

### 4.3 错误码

| 场景 | 状态码 | 谁生成 |
| --- | --- | --- |
| 无 Host / 非法 request-line | 400 | Host |
| Host 超 16 KiB | 431 | Host |
| 后缀不匹配 / 无路由 | 404 | Host |
| Agent 离线 / 无健康隧道 / route disabled | 503 | Host |
| Agent dial 目标被 policy 拒绝 | 403（`0x03`） | Host |
| Agent dial 连接失败 | 502（`0x01`） | Host |
| Agent dial 超时 | 504（`0x02`） | Host |
| 状态字节等待超时 | 504 | Host |

错误响应固定 `Connection: close` + 小文本体 + `x-frplike-error` 头（不含内部细节）。

### 4.4 请求日志与指标

数据面只做三件事：分配 request_id（8 字节 base32）、计数器、把 `RequestLog` 丢进有界 channel。落库由 `DbWriter` 批量写。状态码从响应首行前缀嗅探（不改字节、不缓冲，最多看 32 字节）。

---

## 5. 隧道协议 v1

### 5.1 分层

```
TCP
 └ TLS 1.3 (rustls, ALPN "frplike/1")
    └ yamux (Mode::Client on agent, Mode::Server on host)
       ├ stream #1 (agent 开)：控制流，`u32 len | JSON`
       └ stream #2.. (host 开)：数据流，`0x01 | u16 | target | 请求头 | 请求体`
```

- **只有 Agent 能开第一条流**（控制流），Host 收到 Agent 开的第二条流直接 `reset`。数据流只能 Host 开。
- 控制帧上限 64 KiB，JSON（`serde_json`）。控制面 QPS 低，可读性优先于几个字节。
- 心跳：Agent 每 `heartbeat_secs`（默认 10s，由 Welcome 下发）发 `Heartbeat`；Host 30s 未收到即判定失联、关闭隧道、Route → offline。

### 5.2 消息

```rust
// Agent -> Host
Hello { protocol: 1, agent_version, agent_name, credential, routes: [RouteDecl], tunnels: u8 }
Heartbeat { ts_ms }
Routes { routes: [RouteDecl] }          // 热更新声明

// Host -> Agent
Welcome { agent_id, session_id, credential: Option<String>, accepted: [Accepted], rejected: [Rejected], heartbeat_secs, tunnel_count }
Reject { code, message }                // 随后关流，Agent 不再重试（除 5xx 瞬时错误）
Pong { ts_ms }
Revoked { reason }                      // 管理员吊销，Agent 立刻停
RouteUpdate { accepted, rejected }
```

`credential` 是 `enum Token | Credential`（两步注册，ADR-5）：第一次用 enrollment token，Host 在 `Welcome` 里下发一次性可见的长期 credential，Agent 写入状态文件后**丢掉 token**。之后重连只用 credential。支持新旧双凭据重叠 24h，吊销即时生效（内存 + DB）。

### 5.3 隧道池

每个 Agent 建立 `tunnels`（默认 2，上限 4）条物理 TLS 连接，逻辑上属于同一 `session_id`。Host 按 `round-robin` 在健康隧道上开流；某条隧道死掉只摘掉它，其余继续服务 → 单条 TCP 的队头阻塞不再影响整个 Agent。

ADR-6：隧道池进协议（`tunnels` 字段），不是后续优化。

### 5.4 重连

指数退避 1s → 30s，±30% 抖动，握手并发上限（每 IP 8 个在建 TLS）。Host 重启时 100 个 Agent 不会在同一毫秒敲门。

---

## 6. 本地目标安全（PRD 15.5）

Agent 解析 `target` 后按策略放行：

1. `127.0.0.0/8`、`::1`：允许。
2. RFC1918 / ULA / 链路本地：默认允许（自部署场景，Agent 与目标同机/同网）。
3. 其它（公网地址）：拒绝，返回 `0x03`，除非配置 `allow_public_targets = true`。
4. 目标必须是 `host:port`，端口 1–65535，禁止域名解析到公网（解析结果再过一遍 1–3）。

ADR-7：默认只允许私网 + 回环。

---

## 7. 管理面

- 服务端渲染 HTML（axum + 手写模板 + 转义），无前端构建、无 CDN、无 JS 框架。一行 `cargo build` 出全部资产。
- 登录：账号在 SQLite（`admins` 表，用户名 + argon2id），由 `frplike admin` 管理；兼容旧的 `[admin] password_hash`，首次启动自动迁移成账号 `admin`。会话也在 SQLite（`admin_sessions`，只存 cookie 的 SHA-256），`HttpOnly; SameSite=Strict; Secure`（https 时），默认 12h；改密码/停用账号即刻失效。
- CSRF：所有 POST 校验 `Origin`/`Referer` 同源 + 每会话 token 隐藏域。
- 页面：登录、总览（Agent / Route 表）、Route 详情（诊断）、请求日志、审计日志、设置（只读展示证书路径与到期）。
- 诊断（PRD 7.6）：`host → route → agent online → agent 回 ping(target)` 四步，其中最后一步会真的让 Agent dial 一次目标，结果 200ms 级返回。

---

## 8. 代码结构

```
crates/
  frplike-proto/   协议、Host 嗅探、帧、状态字节、错误、极限值（无 I/O 依赖以外的逻辑）
  frplike-host/    edge / tunnel / admin / db / registry / metrics
  frplike-agent/   连接池、注册、心跳、本地 dial、转发、状态文件
  frplike-testkit/ 进程内 e2e 夹具（起 host + agent + 假 origin）
  frplike/         CLI：host / agent / token / passwd / gen-nginx / doctor / demo
tests/             跨 crate 集成测试（垂直切片 + 验收 1–14）
```

单个发布物：`frplike` 一个二进制，子命令区分角色（ADR-8）。Windows/macOS/Linux 同源同版本。

---

## 9. 明确不做（v0.1）

- 上游 keepalive、HTTP/2 到上游、响应体解析。
- QUIC（保留 `Transport` trait，v0.2 换实现不动协议语义）。
- 自动升级、多管理员、RBAC、PostgreSQL、SNI 直通、路径路由。
- 公网直连 Edge（Nginx 是唯一入口；`--dev` 模式仅回环）。
