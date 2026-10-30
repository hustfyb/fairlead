# 决策记录（ADR）

只记「当时为什么这么选」，不记实现细节。实现细节在 `docs/ARCHITECTURE.md`。

---

## ADR-1：Edge 只绑定回环，除非显式放开

**决定**：`edge_listen` 非回环时拒绝启动，除非 `server.allow_public_edge = true`。

**理由**：绕过 Nginx 直连 Host 会同时绕过 TLS、限流、请求头上限和 XFF 覆写。默认安全，例外要显式。

---

## ADR-2：SQLite 单写者 actor，不用 SQLx

**决定**：`rusqlite`（bundled）+ 一个专属写线程 + 有界 channel；数据面只读 `ArcSwap` 快照。

**理由**：
- 单写者模型下连接池没有意义，`SQLITE_BUSY` 从架构上不可能出现。
- 请求日志可以批量提交（一次事务 256 条），否则每请求一次 fsync。
- bundled SQLite 让 musl 静态链接和 Windows 零依赖成立。
- 省掉 SQLx 的 async trait 与编译期 DB 校验。

---

## ADR-3：一连接一请求，不做上游 keepalive

**决定**：Host 把请求头里的 `Connection` 覆写为 `close`，响应结束即关客户端连接。

**理由**：不解析响应体就不知道响应何时结束（`Content-Length` / `chunked` / `until-close` 三态）。解析响应体 = 写一个 HTTP 代理，正是本项目要避免的复杂度。代价是每请求一次回环建连（几十微秒）+ TIME_WAIT。

**何时推翻**：QPS 过千、`TIME_WAIT` 成为问题时，在 `edge::forward` 一个函数里加连接池，协议不变。

---

## ADR-4：Upgrade 请求一个字节都不改

**决定**：带 `Upgrade` 且 `Connection: upgrade` 的请求原样转发；101 之后进入裸字节隧道；idle 超时 300s。

**理由**：WebSocket 需要 `Connection: Upgrade`，覆写会直接破坏握手。裸隧道也顺带支持 gRPC streaming 和任意协议升级。

---

## ADR-5：Token → Credential 两步注册

**决定**：
1. 管理员 `fairlead token` 生成一次性 enrollment token（只存 sha256，可限后缀、可设过期）。
2. Agent 首次用 token 连接，Host 在 `Welcome` 里下发 32 字节长期 credential，Agent 写入状态文件（0600）后不再使用 token。
3. 之后重连只用 credential；吊销按 credential 生效。

**理由**：PRD 原文「一次性 token」又当长期凭据用，自相矛盾。两步同时满足「token 只展示一次」和「重连不需要人工介入」。token 一次性也意味着状态文件丢失的代价是找管理员要新 token，而不是永久的秘密扩散。

---

## ADR-6：隧道池进协议（`tunnels` 字段）

**决定**：每个 Agent 默认 2 条物理隧道，Host 轮转开流；`Welcome.tunnel_count` 由 Host 下发上限（默认 4）。

**理由**：单条 TCP 上的 yamux 仍有队头阻塞——一个大文件下载会让同一 Agent 的所有请求排队。分池的收益在 v0.1 就成立，不是「以后的优化」。字段放进 Hello 是为了避免以后改协议。

---

## ADR-7：本地目标默认只允许私网 + 回环

**决定**：`127.0.0.0/8`、RFC1918、ULA、链路本地允许；公网地址拒绝（`0x03 BLOCKED`），除非 `allow_public_targets = true`。解析出任意一个公网地址就整体拒绝。

**理由**：否则一个被盗的 Agent 能把入口变成开放代理。

---

## ADR-8：一个二进制，子命令区分角色

**决定**：`fairlead host|agent|token|passwd|gen-nginx|doctor|demo`。

**理由**：发布矩阵从 2 个产物 × 5 平台降到 1 个；`token`/`doctor` 需要直接开数据库，做成同一程序最省事；三平台打包脚本只需处理一个文件。

---

## ADR-9：管理台服务端渲染，无前端构建

**决定**：axum + 手写 HTML + 转义函数，无 npm、无 CDN、无 JS 框架。

**理由**：单管理员、单组织、几个表格。引入前端工具链会让「cargo build」不再是完整的构建指令，也让离线部署多一个坑。

---

## ADR-10：路由 = Agent 声明 ∩ 管理员意图

**决定**：`routes` 表同时保存 `enabled`（管理员启停）和 `deleted_at`（墓碑）。Agent 每次注册只能新增或更新自己名下的行；删除过的 host 再声明会被拒绝（`deleted_by_admin`）。

**理由**：PRD 9.2 只有 `enabled`，无法表达「管理员删了」。没有墓碑时，管理员删除的路由会在 Agent 下次重连时复活——这是最容易被忽略、也最容易被用户投诉的一类 bug。

---

## ADR-11：错误码由 Host 生成，Agent 只回一个状态字节

**决定**：数据流建立后，Agent 先写 1 字节（`00` OK / `01` refuse / `02` timeout / `03` blocked / `04` bad request），然后才开始搬字节。

**理由**：yamux 的流关闭不携带原因，「连不上」和「超时」在 Host 侧无法区分。一个字节换来准确的 502/504/403，以及在上传大 body 之前就知道流是否可用。

---

## ADR-12：v0.1 不做域名审批流

**决定**：域名权限 = token 绑定的后缀（+ 全局 `allowed_suffixes`），管理员可随时 disable/delete 路由；不做「待审批」队列。

**理由**：自部署场景里管理员就是给 token 的人，审批流只是多一次点击。真要收紧，给不同 Agent 发不同后缀的 token 即可。

---

## ADR-13：发布按「最贵的未知量」排序

**决定**：第一周只做垂直切片（curl → nginx → host → agent → 本地服务，含 WS/SSE/100MB），管理台放在切片之后。

**理由**：传输选型（yamux vs QUIC）、Nginx 缓冲、半关闭语义这三件事任何一件不成立都要改协议。管理台晚做不会推倒任何东西。

---

## ADR-14：管理台账号在数据库，不在配置文件；默认不监听公网

**决定**：管理员是 SQLite `admins` 表里的行（用户名 + argon2id），用 `fairlead admin add|passwd|list|disable|rm` 管理；会话存在 `admin_sessions`，只存 cookie 的 SHA-256。`[admin] password_hash` 保留为一次性迁移入口。`admin_listen` 默认回环，绑非回环必须显式 `admin.allow_remote = true`。

**理由**：单个 `password_hash` 意味着「加一个同事 = 改 TOML + 重启」，也没有办法只停用某一个人；审计日志里更分不清是谁点的删除。账号进库后，改密码/停用/删除能立刻反杀该账号所有会话，而这些动作不需要重启。默认拒绝公网绑定不是洁癖：管理台一旦可写路由，就等于把隧道配置权交出去；真要远程访问，应该由 Nginx 终止 TLS，而不是让 9001 端口裸奔。

---

## ADR-15：一个端口三个面，按 Host 分流；TLS 交给前面

**决定**：`server.listen` 设了就进入合并端口模式：`admin_host` 选管理面，`tunnel_host` + `Upgrade: fairlead/1` 选隧道面，其它 Host 走路由表。隧道面不再自己终结 TLS；要 HTTPS 就在前面套一层 Nginx，它只负责透传 `Host` 和 `Upgrade`。留空 `listen` 则回到三端口 + 隧道自带 TLS 的 split 模式。

**理由**：
- 现实里常常只有一个可映射端口（没有公网 IP、路由器只给一条映射），而「只把隧道口露出去」的结果是站点内容进不来、管理台也进不来。
- 没有 TLS 就没有 SNI，面的选择只能来自第一个 HTTP 头；让隧道也走一次 HTTP 升级，就把「一个字节猜错就跨边界」的嗅探问题变成了标准的 `Upgrade` 协商，两种传输（明文 / TLS 后）共用同一套握手。
- 合并的是 socket，不是中间件：管理面仍是 axum，隧道面仍是 yamux，edge 面仍是搬字节。前门只做一次有界头解析，然后把整条连接交出去。
- TLS 交给前面是刻意的：证书续期、SNI、HSTS 这些事 Nginx 做得比我们好，而 host 一旦自己管证书，就必须回答「CLI 用什么验证」，那是 v0.2 的活。

**代价**：合并端口本身是明文。管理台的会话 cookie 和登录口令在它上面是裸的，所以非回环 `listen` 必须显式 `admin.allow_remote = true`，启动打警告；上线前应有 TLS 终结者。`Upgrade` 之后的两端都必须重放「头之后多读到的字节」，否则 yamux 的开场帧会被吞掉。
