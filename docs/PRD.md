# fairlead 产品需求文档（PRD）

| 项目 | 内容 |
| --- | --- |
| 产品代号 | fairlead |
| 文档版本 | v0.1 |
| 状态 | Draft |
| 日期 | 2026-10-29 |
| 部署形态 | 单节点、自部署 |
| 首发技术栈 | Rust、Nginx、SQLite |
| MVP 范围 | 共享公网端口、Host 路由、Agent 注册、TCP 隧道 |

## 1. 背景

需要一套类似 Cloudflare Tunnel / FRP 的自部署服务：

- 公网侧只有一台入口服务器。
- 多台内网机器通过 Agent 主动连接入口服务器。
- Agent 把域名映射到本机端口，例如：
  - `a1.relay.example.com -> 127.0.0.1:7884`
  - `a2.relay.example.com -> 127.0.0.1:7885`
- 所有服务共用一个公网端口。
- 客户端通过域名访问，端口可以是标准端口，也可以是部署者自行选择的非标准端口。
- Cloudflare、DNS、TLS 证书签发和端口可达性属于外部基础设施，不是本产品的核心职责。

## 2. 产品定义

fairlead 是一个**带动态 Host 路由能力的单节点反向 TCP 隧道服务**。

```text
客户端
  -> Nginx 公共监听端口
  -> Rust Host（按 Host 查找路由）
  -> TLS + 多路复用隧道
  -> Agent
  -> 127.0.0.1:本地端口
```

公共入口必须能够区分 `a1.relay.example.com` 和 `a2.relay.example.com`。由于两者共用同一个端口，因此：

- HTTP 入口必须读取 `Host`。
- HTTPS 入口由 Nginx 终止 TLS，再读取 `Host`。
- Agent 隧道和本地转发仍然是原始 TCP。
- 路由切换由 Rust Host 动态完成，不通过改写 Nginx 配置实现。

## 3. 目标与非目标

### 3.1 产品目标

1. 内网机器不需要公网 IP 或入站端口。
2. 多个域名可以共享一个公网端口。
3. Agent 可以自行注册域名到本地端口的映射。
4. 新增或删除路由不要求重启 Agent、Rust Host 或 Nginx。
5. 单机部署简单，核心依赖少。
6. 转发路径可观测、可诊断，故障状态明确。

### 3.2 非目标

- 不做 Cloudflare 橙云代理、DNS 记录管理或 SSL 模式管理。
- 不做 ICP 备案、运营商封锁、跨境网络或公网端口可达性处理。
- 不做证书签发和 ACME 流程；MVP 只使用部署者提供的证书。
- 不做多 Edge 节点、跨地域调度或高可用集群。
- 不做多租户、计费、复杂 RBAC、WAF 或 Cloudflare Access。
- 不支持在同一个共享端口上承载无 Host/SNI 信息的任意 L4 协议。
- 不支持 UDP。
- 不保证根域名或 `a.b.relay.example.com` 等多级域名；MVP 以一级子域为主。

## 4. 术语

| 术语 | 定义 |
| --- | --- |
| Host Server | 部署在公网入口机器上的 Rust 服务，负责控制面、路由和隧道连接 |
| Agent | 部署在内网机器上的 Rust 客户端，主动连接 Host Server |
| Route | `域名 -> Agent -> 本地目标地址` 的映射 |
| Public Listener | Nginx 对外提供的共享监听端口 |
| 上游/本地目标 | Agent 所在机器上的 TCP 服务地址，例如 `127.0.0.1:7884` |
| 数据流 | 一次客户端请求对应的一条隧道逻辑 TCP 流 |

## 5. 用户与使用场景

### 5.1 用户角色

- **管理员**：部署 Host、配置 Nginx、管理 Agent 和路由。
- **内网机器使用者**：安装 Agent，并声明本机服务映射。
- **客户端**：通过域名访问已注册的服务。

### 5.2 核心用户故事

1. 作为管理员，我可以在一台公网服务器启动 Host 和 Nginx。
2. 作为内网机器使用者，我可以运行一条命令启动 Agent 并连接 Host。
3. 作为 Agent，我可以注册 `a1.relay.example.com -> 127.0.0.1:7884`。
4. 作为客户端，我访问 `http://a1.relay.example.com:8080` 或标准端口域名时，请求被转发到对应端口。
5. 作为管理员，我可以看到 Agent 是否在线、路由是否生效、最近一次错误是什么。
6. 作为管理员，我可以禁用某个路由或吊销某个 Agent 凭据。
7. 当 Agent 掉线时，客户端收到明确的 502/503，而不是无限等待。

## 6. 总体架构

```text
                         ┌─────────────────────────────────────┐
                         │             公网入口机器              │
                         │                                     │
客户端                   │  ┌──────────┐      ┌──────────────┐  │
  │   HTTP/HTTPS         │  │  Nginx   │      │  Rust Host   │  │
  └──────────────────────┼─>│ :8080    │─────>│ 127.0.0.1:9000│  │
                         │  │ TLS/HTTP │      │ Host 路由     │  │
                         │  └──────────┘      │ Agent 注册表  │  │
                         │                     │ 隧道复用器    │  │
                         │                     └──────┬───────┘  │
                         │                            │          │
                         │                       TLS/TCP 隧道    │
                         │                            │          │
                         └────────────────────────────┼──────────┘
                                                      │
                                       ┌──────────────┴─────────────┐
                                       │                            │
                                 ┌─────▼─────┐                ┌─────▼─────┐
                                 │  Agent A  │                │  Agent B  │
                                 │           │                │           │
                                 │ 127.0.0.1 │                │ 127.0.0.1 │
                                 │   :7884   │                │   :7885   │
                                 └───────────┘                └───────────┘
```

### 6.1 Nginx 的职责

Nginx 在前，Rust Host 在后。Nginx 处理所有公共 HTTP/HTTPS 入口：

- 监听一个可配置的公共端口，例如 `80`、`443`、`8080`、`8443`。
- HTTPS 模式下终止 TLS，并使用部署者提供的通配符证书。
- 处理 HTTP/1.1、HTTP/2、WebSocket Upgrade、SSE 和流式响应。
- 保留原始 Host，转发 `X-Forwarded-For`、`X-Forwarded-Proto`、`X-Real-IP`。
- 提供连接数、请求大小、超时和基础限流能力。
- 记录入口访问日志。
- 将全部域名请求转发到 Rust Host 的单一内部地址。

### 6.2 Nginx 不负责的事情

- 不维护动态 Agent 路由表。
- 不根据 Agent 上线/下线重写配置。
- 不直接连接 Agent。
- 不负责 Agent 鉴权或隧道复用。
- 不承担域名注册、证书签发或 Cloudflare API 调用。

### 6.3 Rust Host 的职责

- 接收 Agent 注册、校验凭据、维护 Agent 和 Route 状态。
- 解析 Nginx 转发的 HTTP `Host`，归一化后查找路由。
- 为每次请求在 Agent 隧道上打开独立逻辑 TCP 流。
- 管理连接超时、并发上限、错误响应、日志和指标。
- 提供管理员 API/UI、Agent 控制协议和健康检查。

### 6.4 技术栈方向

MVP 首选：

| 组件 | 技术选择 |
| --- | --- |
| Host Server | Rust |
| Agent | Rust |
| 异步运行时 | Tokio |
| HTTP 服务/代理 | Axum + Hyper |
| TLS | rustls |
| 隧道复用 | TLS over TCP + yamux（后续可评估 QUIC） |
| 数据库 | SQLite + SQLx |
| CLI | clap |
| 日志与指标 | tracing + Prometheus 指标端点 |
| 公共入口 | Nginx |
| 部署 | Docker Compose；Agent 支持 Docker 和 systemd |

最终 crate 和协议细节可在技术设计阶段确定，但应保持 Host 与 Agent 使用同一套 Rust 协议实现。

这里使用的是 TLS/TCP 传输，不是 HTTPS Agent。TLS 只负责加密和认证，Agent 协议本身是二进制帧，不包含 HTTP 方法、Header 或 URL 语义。

## 7. 功能需求

### 7.1 P0：Host 与 Nginx 入口

- 公共监听端口必须可配置。
- 支持 HTTP 和 HTTPS 两种入口模式。
- HTTPS 模式只加载部署者指定的证书和私钥，证书更新后支持平滑 reload。
- 所有域名共享 Nginx 默认入口，并转发给 Rust Host 的内部监听地址。
- Rust Host 的入口端口默认只绑定 `127.0.0.1`，避免绕过 Nginx 直接访问。
- 请求必须读取并归一化 Host：
  - 去除端口。
  - 转小写。
  - 拒绝空 Host、非法字符和不符合配置后缀的 Host。
- 路由不存在时返回 404。
- Agent 不在线时返回 503。
- 上游连接超时返回 504。
- 连接失败返回 502。
- 支持 WebSocket Upgrade。
- 支持请求和响应流式传输，不因大文件上传/下载而整包缓冲。
- 支持可配置的请求头大小、请求体限制、连接超时和空闲超时。

### 7.2 P0：Agent 注册与身份

- Agent 使用一次性注册 Token 或预分配凭据连接 Host。
- Agent 与 Host 之间使用 TLS 加密。
- Agent 必须主动连接 Host，不监听公网端口。
- Agent 注册信息包括：
  - Agent 名称或 ID。
  - 版本号。
  - 域名到本地目标的映射列表。
- Host 校验：
  - Token 有效且未吊销。
  - 域名属于允许的后缀，例如 `*.relay.example.com`。
  - 本地目标格式合法。
  - 同一域名未被另一个在线 Agent 占用。
- 注册成功后，Host 将 Route 置为可用并记录 Agent 在线状态。
- Agent 断线后，Route 保留但标记为 `offline`；重连后自动恢复。
- Agent 心跳超时后，Host 主动关闭其隧道并清理在途状态。
- 支持 Token 吊销和服务端主动断开 Agent。

### 7.3 P0：Route 管理

- Route 的唯一键为归一化后的公共 Host。
- 同一 Host 不允许同时由多个在线 Agent 提供。
- Route 状态至少包括：
  - `active`
  - `offline`
  - `disabled`
  - `conflict`
- 管理员可以启用、停用、删除 Route。
- Agent 重连时不得覆盖管理员已停用的 Route。
- Agent 删除映射后，Host 应根据注册更新删除或停用对应 Route。
- Route 变更必须在秒级生效，不要求重启 Nginx。

### 7.4 P0：隧道与数据转发

- Host 与 Agent 保持一条持久 TLS/TCP 连接。
- 使用多路复用协议承载多个并发逻辑流。
- 每次客户端请求由 Host 选择 Route，并在隧道上打开一条逻辑流。
- Agent 收到逻辑流后，连接本地目标并双向复制字节。
- Agent 不解析 HTTP 内容。
- 支持多路并发、流关闭传播、半关闭和异常断开清理。
- 支持 keepalive 和心跳，避免中间网络设备静默断开。
- 对 Agent 到本地目标的连接设置独立超时。
- 支持可配置的最大并发流数量和单 Agent 连接数上限。

### 7.5 P0：管理 API 与最小控制台

- 提供管理员登录。
- 展示 Agent 列表：
  - 名称、ID、版本、在线状态、最后心跳时间、连接数。
- 展示 Route 列表：
  - Host、Agent、目标地址、状态、最近错误、创建时间。
- 支持 Route 启用、停用、删除。
- 支持 Agent 凭据轮换和吊销。
- 支持查看最近请求日志和错误日志。
- MVP 允许单管理员、单组织。
- 管理 UI 默认只允许通过回环地址或受控入口访问。

### 7.6 P0：诊断与可观测性

- 记录每个请求的：
  - 请求 ID。
  - Host。
  - Route ID。
  - Agent ID。
  - HTTP 状态码。
  - 耗时。
  - 上行/下行字节数。
- 提供 `/healthz` 和 `/metrics`。
- Nginx 和 Rust Host 的日志应能通过请求 ID 关联。
- 管理控制台提供“链路诊断”：
  - Host 路由是否存在。
  - Agent 是否在线。
  - 本地目标是否可连接。
  - 最近一次转发错误。
- 支持对 Agent 心跳超时、注册冲突、连续 5xx 和证书到期进行告警或日志标记。

### 7.7 P1：增强能力

- Route 创建后的自动连通性测试。
- Agent 自动升级。
- 多管理员和基础 RBAC。
- TLS SNI 直通模式。
- 访问控制和 IP 白名单。
- Cloudflare API 可选插件，仅用于外部 DNS/证书自动化。
- PostgreSQL 支持。
- 多 Host 语法和路径级路由。
- QUIC 传输。

## 8. 关键流程

### 8.1 Agent 启动和注册

```text
Agent 启动
  -> 加载本地配置和凭据
  -> 建立到 Host 的 TLS 连接
  -> 发送 Hello 和版本信息
  -> 提交 Route 列表
  -> Host 校验 Token、域名、目标和冲突
  -> Host 返回注册结果
  -> Agent 保持心跳
  -> Route 状态变为 active
```

### 8.2 客户端请求

```text
客户端访问 a1.relay.example.com:8080
  -> DNS 解析到入口服务器
  -> Nginx 接收 HTTP/HTTPS
  -> Nginx 将 Host 转发给 Rust Host
  -> Rust Host 查 Route
  -> 在隧道上打开逻辑流
  -> Agent 连接 127.0.0.1:7884
  -> 双向转发
  -> 返回响应
```

### 8.3 Agent 断线

```text
网络中断或 Agent 退出
  -> Host 心跳超时
  -> Route 标记 offline
  -> 新请求返回 503
  -> 在途流被清理
  -> Agent 重连后重新注册
  -> Route 恢复 active
```

## 9. 数据模型

### 9.1 Agent

| 字段 | 说明 |
| --- | --- |
| id | Agent 唯一 ID |
| name | 用户可见名称 |
| status | online / offline / revoked |
| version | Agent 版本 |
| last_seen_at | 最后心跳时间 |
| credential_hash | 凭据哈希，不保存明文 |
| created_at | 创建时间 |

### 9.2 Route

| 字段 | 说明 |
| --- | --- |
| id | Route 唯一 ID |
| public_host | 归一化后的公共域名 |
| agent_id | 负责该路由的 Agent |
| target | `host:port`，由 Agent 解释 |
| status | active / offline / disabled / conflict |
| enabled | 管理员启停状态 |
| last_error | 最近一次错误 |
| created_at / updated_at | 时间字段 |

### 9.3 Enrollment Token

| 字段 | 说明 |
| --- | --- |
| id | Token ID |
| token_hash | 哈希 |
| allowed_suffix | 允许注册的域名后缀 |
| expires_at | 有效期 |
| used_at | 使用时间 |
| revoked_at | 吊销时间 |

### 9.4 Request Log / Audit Log

- Request Log 可短期保留，支持按 Host、Route、Agent、状态码查询。
- Audit Log 记录 Route 变更、Agent 吊销、登录和管理操作。

## 10. 配置与部署

### 10.1 推荐部署

```text
docker-compose
  ├── nginx（可选；只在需要 HTTPS 时出现）
  │   ├── 公共端口 8080/443
  │   └── 证书目录
  └── fairlead-host
      ├── 0.0.0.0:9000  唯一入口：管理面 / 隧道面 / edge 面按 Host 分流
      └── SQLite volume
```

### 10.2 端口

- 唯一入口：`server.listen`（默认 `0.0.0.0:9000`），三个面按请求的 `Host` 分流：
  `admin_host` → 管理面，`tunnel_host` + `Upgrade` → 隧道面，其余 → edge 面。
- 部署者只需要映射这一个端口；DNS（或本机 hosts）里把三个三级域名都指向它。
- 没有公网 IP / 只能映射一个端口时，这正是目标形态；split 模式（`edge_listen` /
  `tunnel_listen` / `admin_listen` 三个独立监听 + 隧道自带 TLS）保留给「管理面必须留在回环」的部署。
- TLS 不属于核心：由前面的 Nginx 终止，它只透传 `Host` 与 `Upgrade`。

### 10.3 证书

- 证书由外部工具或部署者提供，fairlead 不负责签发，也不在自己的端口上终结 TLS（split 模式的隧道监听除外）。
- Nginx 读取配置目录中的证书和私钥。
- 证书更新后支持 `nginx -s reload` 或等价平滑 reload。
- 管理台只展示证书路径、有效期和最近 reload 结果，不展示私钥。
- 如果部署要求全自动续期，可使用外部 `acme.sh`/Certbot + Cloudflare DNS API 完成续期，再由 Nginx reload；该自动化属于部署集成，不是 fairlead 核心依赖。

### 10.4 Agent 安装

Agent 支持：

- 独立二进制。
- systemd 服务。
- Docker。

示例配置：

```toml
server = "http://relay.example.com:9000"
token = "enrollment-token"

[[routes]]
host = "a1.relay.example.com"
target = "127.0.0.1:7884"

[[routes]]
host = "a2.relay.example.com"
target = "127.0.0.1:7885"
```

## 11. 安全要求

- Agent 隧道必须使用 TLS。
- Agent 注册 Token 只展示一次，服务端只保存哈希。
- Token 必须可以吊销和轮换。
- Host 只信任来自 Nginx 回环地址的管理请求和来自已认证 Agent 的隧道连接。
- Nginx 必须覆盖客户端伪造的转发头，不能信任公网传入的 `X-Forwarded-*`。
- Agent 默认只允许连接 `127.0.0.1` 或明确配置的私有网段。
- 禁止 Agent 将 Route 指向公网任意目标，除非管理员显式放开。
- Route 域名必须通过允许后缀校验，避免 Agent 抢注任意域名。
- 管理控制台必须有登录保护；密码使用强哈希，Session 设置过期时间。
- 访问日志不得记录敏感请求头、Token 或证书私钥。
- Nginx 和 Host 均设置请求头大小、连接数、并发流和超时上限。

## 12. 非功能需求

### 12.1 性能目标

MVP 以单机为目标，发布前至少验证：

- 100 个在线 Agent。
- 1,000 条 Route。
- 2,000 条并发隧道逻辑流。
- 单个响应体不做整包缓冲。
- 路由新增后 2 秒内生效。
- Agent 短暂断网后 5 秒内自动重连。

### 12.2 可靠性

- Host 和 Agent 支持优雅关闭。
- 连接异常时清理逻辑流和资源。
- SQLite 开启 WAL，支持事务写入。
- Host 重启后可以恢复 Agent 和 Route 的持久化状态。
- 单机部署是已知单点故障，不承诺多节点容灾。

### 12.3 可维护性

- Host、Agent 和协议代码共享 Rust workspace。
- 协议消息有版本号。
- 关键协议和路由逻辑必须有单元测试和集成测试。
- 日志采用结构化输出。

## 13. 验收标准

以下场景全部通过才算 MVP 完成：

1. 启动 Nginx 和 Host 后，Agent 能主动连接 Host。
2. Agent 能注册：
   - `a1.relay.example.com -> 127.0.0.1:7884`
   - `a2.relay.example.com -> 127.0.0.1:7885`
3. 客户端通过同一个公开端口访问两个域名，分别命中不同本地服务。
4. 标准端口为 80 时，客户端访问不需要显式带端口；非标准端口时，客户端 URL 带对应端口。
5. 新增、停用、删除 Route 不触发 Nginx reload，也不重启 Host。
6. 未注册 Host 返回 404。
7. Agent 离线时返回 503。
8. Agent 重连后 Route 自动恢复。
9. WebSocket 连接可正常建立和关闭。
10. 大响应和流式响应不会被整包缓冲。
11. 管理台可以查看 Agent、Route、请求日志和最近错误。
12. Token 吊销后 Agent 无法重新连接。
13. 伪造的 `X-Forwarded-For` 不会覆盖 Nginx 设置的真实客户端 IP。
14. 不安装 Nginx 时，Host 仍可在开发模式下通过回环入口运行，但生产部署默认使用 Nginx。

## 14. 里程碑

### M0：协议与骨架

- Rust workspace。
- Host/Agent TLS 连接。
- 注册消息、心跳、路由模型。
- SQLite schema。

### M1：核心隧道

- Agent 注册和 Route 状态。
- 隧道多路复用。
- Host 按 Host 查路由。
- Agent 到本地 TCP 的转发。
- 404/502/503/504 错误处理。

### M2：Nginx 与生产入口

- Nginx Compose 配置。
- HTTP 和 HTTPS 模式。
- 公共端口可配置。
- WebSocket、流式传输、请求限制。
- 证书 reload 流程。

### M3：管理与可观测性

- 管理员 API/UI。
- Agent/Route 管理。
- 请求日志、指标、健康检查。
- Token 轮换与吊销。

### M4：加固与发布

- 并发和长连接测试。
- 安全边界测试。
- Docker、systemd、升级和备份文档。
- 发布候选版本。

## 15. 风险与待确认项

1. **共享端口与纯 TCP 的边界**：按 Host 路由必须理解 HTTP；如果要共享端口承载任意非 HTTP 协议，需要 SNI 或其他显式多路复用标记。
2. **Nginx 缓冲配置**：必须验证 WebSocket、SSE、大文件和长连接不会被 Nginx 默认配置破坏。
3. **Route 抢注**：需要决定是 Token 绑定域名后缀、管理员审批，还是两者结合。
4. **多实例 Agent 冲突**：同一个 Host 从不同 Agent 注册时必须明确拒绝策略。
5. **本地目标安全**：需要确定默认允许的私有地址范围。
6. **管理入口**：管理 UI 是否允许公网访问，还是只允许 SSH 隧道/内网访问。
7. **证书自动化**：MVP 外部提供证书；是否在下一版本集成 Cloudflare API 或其他 ACME DNS Provider。
8. **数据保留**：请求日志保留时长和存储上限。

## 16. 首发不包含

- Cloudflare 橙云行为和 DNS 管理。
- Cloudflare Origin CA 证书管理。
- 自动申请证书。
- 根域名和三级以上子域。
- UDP、非 HTTP 共享端口协议。
- 多节点、集群、Kubernetes Operator。
- 计费和多租户。
- WAF、Bot 管理、访问控制。
- 完整的 TCP 代理协议兼容层。
