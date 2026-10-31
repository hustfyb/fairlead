# fairlead 架构设计（v1）

| 项目 | 内容 |
| --- | --- |
| 状态 | Accepted（v0.1 实现基线） |
| 日期 | 2026-10-29 |
| 对应 PRD | `docs/PRD.md` v0.1 |
| 发布方案 | `docs/RELEASE.md` |

本文只写**已经拍板**的东西。带「ADR-n」的条目在 `docs/DECISIONS.md` 里有取舍记录。

---

## 1. 一句话架构

**一个端口，三个面；请求自己说明自己属于哪个面。Host 只做 Host 查表 + 原样转发，不解析响应；每条请求在 yamux 隧道上开一条逻辑流，Agent 连本地目标，双向搬字节。**

```
                 ┌── Host: admin.x      ──────────────> admin plane (axum: 会话/CSRF/审计)
:9000 ───────────┼── Host: tunnel.x + Upgrade: fairlead/1 ──> tunnel plane (yamux 控制面)
                 └── 其它 Host ──────────────────────> edge plane ──> yamux::open_stream
                                                                          │
                                              ┌───────────────────────────┴──────────┐
                                              ▼                                      ▼
                                           agent A (tunnel×N)                     agent B
                                              │ dial target                          │
                                              ▼                                      ▼
                                        127.0.0.1:7884                         127.0.0.1:7885
```

三个面、三套中间件，**永不合并 router**——合并的只是 socket：

| 面 | 选中条件（合并端口） | split 模式地址 | 中间件 |
| --- | --- | --- | --- |
| Edge | 其它所有 `Host` | `127.0.0.1:9000` | Host 嗅探、路由、转发、限流 |
| Admin | `Host == server.admin_host`（或设了 `server.admin_listen` 时整个面搬去那个端口，合并端口上不再可达） | `127.0.0.1:9001` | 登录会话、CSRF、审计 |
| Tunnel | `Host == server.tunnel_host` 且 `Upgrade: fairlead/1` | `0.0.0.0:9443` | 凭据校验、握手预算、心跳 |

前端没有 TLS 时没有 SNI，所以面的选择**只能来自第一个 HTTP 头**：前门用与 Edge 完全相同的、有界的（≤16 KiB / 10 s）头解析器读一次，然后按面把整条连接交出去——Edge 拿到原始字节流，Tunnel 拿到 `101` 之后的 yamux 会话，Admin 拿到「把已读字节重放一遍」的流，因此 peer 地址、cookie、keep-alive 全部与独占端口时一致。

ADR-15：合并不是把 router 合成一个，而是让**入口**认得三个面。ADR-1（`edge_listen` 非回环即拒启，除非 `allow_public_edge = true`）在 split 模式下继续有效；合并模式下暴露的不是某个内部监听，而是三个面共用的公网入口，因此它由 `admin.allow_remote = true` 这一句显式授权——管理面是这里唯一真正敏感的东西。

管理面可以从合并端口上摘出去：`server.admin_listen` 一设，管理面就单独 `bind` 一个 socket，`listen` 只剩隧道面和 edge 面。公网只映射 `listen` 时，管理台连端口都不可达；这也是「唯一映射口」部署里推荐形态。此时 `admin_host` 不再参与分流，打 `listen` 的管理台域名会得到 404（不是站点内容，也不是登录页）。

### 1.1 第四种应答：安装页（`[landing] dir`，默认关）

前门还有一种回答：**没有路由可匹配的 Host**——直接用 IP 打，或者用一个不属于任何后缀的域名。默认它们是 `400 host is an ip literal` / `404 no route`；设了 `[landing] dir` 之后，这些请求拿到一页静态下载页（五个平台的包、`SHA256SUMS`、`install.sh`），而路由表、管理面、隧道面都不参与。

边界只有一条，但必须成立：**只有不可能成为路由的 Host 才会看到这页**。写错的 `a1.<后缀>`、被停用或删除的路由，仍然分别是 404 / 503 / 404。实现上就是 `!is_site_host(host, allowed_suffixes)`——后缀的 apex（`relay.example.com` 本身）算「不是站点」，因为它本来就不会有自己的路由；任何真子域名都算站点，宁可 404。

`[landing] host` 是这条边界的唯一例外：运维显式点名的那个名字（通常是 `app.<后缀>`）看起来是站点，但它永远返回安装页，且在路由表之前判定——同名路由盖不住它。理由很实际：一页只能在打错时看到的文档没有价值，它得有个能写进 wiki 的固定地址。

页面不含任何凭据：token 只能在中继机上用 `fairlead token` 签发。下载只在 `dir` 这一层目录里按文件名精确匹配，不解码、不允许 `..`、不列目录，所以这一面不是一个静态文件服务器——它只是「没有路由时的一段固定回答」。


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

错误响应固定 `Connection: close` + 小文本体 + `x-fairlead-error` 头（不含内部细节）。

### 4.4 请求日志与指标

数据面只做三件事：分配 request_id（8 字节 base32）、计数器、把 `RequestLog` 丢进有界 channel。落库由 `DbWriter` 批量写。状态码从响应首行前缀嗅探（不改字节、不缓冲，最多看 32 字节）。

---

## 5. 隧道协议 v1

### 5.1 分层

```
TCP
 └ [TLS 1.3 (rustls, ALPN "fairlead/1")]   ← 可选：前面有 TLS 终结者时省略
    └ HTTP/1.1 升级：GET /tunnel  Host: tunnel.x  Upgrade: fairlead/1  →  101
       └ yamux (Mode::Client on agent, Mode::Server on host)
          ├ stream #1 (agent 开)：控制流，`u32 len | JSON`
          └ stream #2.. (host 开)：数据流，`0x01 | u16 | target | 请求头 | 请求体`
```

升级请求只做**选择**，不做认证：凭据仍在控制流的 `Hello` 里，所以一条认证路径、一套拒绝词表，split 模式与合并端口行为一致。代价是 `101` 之后两端都必须把「响应头之后多读到的字节」重放给 yamux——服务端的开场 ping 常常和 `101` 挤在同一个 TCP 段里，丢掉它会让会话永久卡住（`fairlead_proto::Prefixed`）。

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

每个 Agent 建立 `tunnels`（默认 2，上限 4）条物理隧道连接，逻辑上属于同一 `session_id`。Host 按 `round-robin` 在健康隧道上开流；某条隧道死掉只摘掉它，其余继续服务 → 单条 TCP 的队头阻塞不再影响整个 Agent。

ADR-6：隧道池进协议（`tunnels` 字段），不是后续优化。

### 5.4 重连

指数退避 1s → 30s，±30% 抖动；合并端口上另有 128 个并发隧道握手的硬上限（满了直接 503，不排队）。Host 重启时 100 个 Agent 不会在同一毫秒敲门。

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
- 登录：只有一个管理身份，没有用户名——密码就是全部凭据。哈希存在 SQLite 的 `admin` 表（单行）；密码来自启动时的 `FAIRLEAD_ADMIN_PASSWORD`（与库里一致就不动，不一致才改密并清会话）或 `fairlead admin passwd`。`[admin] password_hash` 只在空库时播种一次；v2 库升级时保留「最近登录过的那个账号」的密码，旧会话全部作废。会话在 `admin_sessions`（只存 cookie 的 SHA-256），`HttpOnly; SameSite=Strict; Secure`（https 时），默认 12h；改密码即刻全部失效。
- CSRF：所有 POST 校验 `Origin`/`Referer` 同源 + 每会话 token 隐藏域。
- 页面：登录、总览（Agent / Route 表）、Route 详情（诊断）、请求日志、审计日志、设置（只读展示证书路径与到期）。
- 诊断（PRD 7.6）：`host → route → agent online → agent 回 ping(target)` 四步，其中最后一步会真的让 Agent dial 一次目标，结果 200ms 级返回。

---

## 8. 代码结构

```
crates/
  fairlead-proto/   协议、Host 嗅探、帧、状态字节、错误、极限值（无 I/O 依赖以外的逻辑）
  fairlead-host/    edge / tunnel / admin / db / registry / metrics
  fairlead-agent/   连接池、注册、心跳、本地 dial、转发、状态文件
  fairlead-testkit/ 进程内 e2e 夹具（起 host + agent + 假 origin）
  fairlead/         CLI：host / agent / token / passwd / gen-nginx / doctor / demo
tests/             跨 crate 集成测试（垂直切片 + 验收 1–14）
```

单个发布物：`fairlead` 一个二进制，子命令区分角色（ADR-8）。Windows/macOS/Linux 同源同版本。

---

## 9. 明确不做（v0.1）

- 上游 keepalive、HTTP/2 到上游、响应体解析。
- QUIC（保留 `Transport` trait，v0.2 换实现不动协议语义）。
- 自动升级、多管理员、RBAC、PostgreSQL、SNI 直通、路径路由。
- 公网直连 Edge（Nginx 是唯一入口；`--dev` 模式仅回环）。
