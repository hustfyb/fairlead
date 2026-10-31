# Changelog

## v0.1.0 — unreleased

首个可运行版本：单节点、共享端口、按 Host 路由。

- **Agent 侧的命令行**（本机管理端口映射，不用手改 TOML）：`fairlead agent list`（发布中的端口 + 实时状态）、`add <host> <port>`（或 `add 8080`，自动命名 `a8080.<后缀>`）、`rm <host>`、`status`。`add`/`rm` 用 toml_edit 只动 `[[routes]]`，注释和其它键原样保留；运行中的服务两秒内重读配置并把新声明发给中继，不重启、不掉隧道
- **装成服务**：`fairlead agent service install|uninstall|start|stop|restart|status`——Linux systemd、macOS launchd、Windows 计划任务；`install.sh` 默认调用它，开机自启；服务以安装者身份运行（`--user` 可指定），`--no-service` 跳过，`--dry-run` 只打印 unit/plist
- 中继把「Agent 的声明」当作事实：不再声明的路由连数据库行一起删除（墓碑保留），所以 `fairlead agent rm` 之后是 404，不是留着一条 503 的幽灵记录
- Agent 状态文件 `agent.status.json`（credential 旁边，每秒重写）：pid、连接状态、每条路由 `serving` / `rejected` 及原因；`list` / `status` 只读它，不打扰中继
- `fairlead agent` 的空路由表不再是启动错误（`rm` 掉最后一条后服务照常活着，等 `add` 回来）
- **一个端口，三个面**（ADR-15）：`server.listen` 上由请求自己选面——`Host` 等于 `admin_host` 走管理面，等于 `tunnel_host` 且带 `Upgrade: fairlead/1` 走隧道面，其余走 edge 面。隧道面不再自己终结 TLS：`http://` 明文或 `tls://` 交给前面的 Nginx。原三端口布局保留为 split 模式（`listen` 留空）
- Agent 新增 `server` scheme（`http://` / `tcp://` / `tls://` / `https://`，无 scheme 仍按 TLS）与 `tunnel_host`；隧道握手改为一次 HTTP 升级（`101` 后接 yamux），凭据仍只在控制流的 `Hello` 里
- 前门用与 edge 相同的 ≤16 KiB / 10 s 头解析器分流，然后整条连接交给对应面：管理面仍是 axum（peer 地址、cookie、keep-alive 与独占端口一致），edge 仍是搬字节，隧道面拿到 yamux
- `fairlead_proto::Prefixed`：`101` 之后多读到的字节（yamux 开场帧）重放到 mux，否则会话会永久卡住
- 管理面可以搬出合并端口：`server.admin_listen` 一设，管理台单独 `bind`（典型：`listen` 映射公网跑 Agent + 站点，管理台留 LAN）；`listen` 上连管理台域名都只回 404
- **安装页**（`[landing] dir`）：用 IP 或任何不可能成为路由的 Host 打开端口时，返回下载页（五个平台、大小、`SHA256SUMS`）+ `/install.sh`（按 `uname` 选包、校验、装二进制、写 agent 配置）+ `/download/<file>`；真子域名没路由时仍是 404，页面不含任何凭据
- 安装页可以有固定门牌：`[landing] host = "app.<后缀>"`。设了之后这个名字永远返回安装页（在路由表之前判定，同名路由盖不住它），通配记录已经指向 relay，不用另加 DNS
- 安装页顶部把唯一的前置条件写在命令之前：`*.<后缀>` 通配解析到中继——一条记录覆盖之后所有路由（含隧道入口 `tunnel.<后缀>`），不必每加一条路由改一次 DNS
- 新增 8 条安装页验收测试（页面、apex 与子域名的分界、字节一致下载、目录穿越、HEAD/405、真实路由优先、关闭时不出现、4 MiB 流式下载）
- 新增 6 条合并端口验收测试（三面分流、管理面不可由站点 Host 触达、隧道面不接受浏览器、管理面单开端口、8 MiB 下载 / 2 MiB 上传）

- 项目名 **fairlead**（原 frplike）：仓库、五个 crate、二进制、`fairlead-host.toml` / `fairlead-agent.toml`、systemd/docker 路径一并改；线上标识同步为 ALPN `fairlead/1`、`x-fairlead-request-id` / `x-fairlead-error`、cookie `fairlead_session`
- `fairlead host|agent|token|passwd|gen-nginx|doctor|demo` 单二进制
- yamux 隧道（可选 TLS 1.3 在外层）；每 Agent 2 条物理隧道轮转
- 请求头嗅探（≤16KB），响应原样流式转发；Upgrade 请求逐字节透传
- 404 / 503 / 502 / 504 / 403 语义，数据流 1 字节状态回执
- 路由 = Agent 声明 ∩ 管理员意图（含删除墓碑，重连不复活）
- 一次性 enrollment token → 长期 credential（0600 状态文件）
- 管理台只有一个密码，**没有用户名**：`FAIRLEAD_ADMIN_PASSWORD` 启动时应用（与库里一致则不动，重启不掉线；不一致才改密并让所有会话退出），或 `fairlead admin passwd` 写库；登录页只剩一个密码框，未设密码时直接给设置指引；限流改为只按客户端 IP（10 次/5 分钟）
- 数据库 `user_version` 2→3：`admins`（多账号）并入单行 `admin`，升级保留最近登录过的那个账号的密码，旧会话作废；`admin_sessions` 不再带 `admin_id`
- `fairlead admin` 子命令收成 `passwd` 与 `status`；`[admin] password_hash` 只在空库时播种一次
- 管理台默认只绑回环；`admin.allow_remote` 才能监听公网地址，`admin.trust_forwarded_for` 支持放在自有代理之后
- 管理台：登录、账户自助改密、Agent/路由管理、请求日志、审计、链路诊断；删除过的路由是墓碑，默认不出现在总览和路由列表（`/routes?deleted=1` 才列出来，仍可「恢复」）
- 管理台「Token」页签发一次性 enrollment token：选后缀、有效期（30m/1h/24h/7d/不过期）、备注；签发后那一页显示明文一次（旁边一个「复制 token」按钮，点框即整串选中；命令与片段也各有一个），并给出填好 token 的 `install.sh` 命令和 `agent.toml` 片段；列表只留后缀/状态/被哪个 Agent 用了，可吊销。安装页与 `install.sh` 的指引改成「管理台签发」（`fairlead token` 仍可用）
- 管理台的复制按钮在没有 `navigator.clipboard` 的明文 HTTP（局域网地址不是安全上下文）下退回 textarea + `execCommand`，再不行就选中文本让 ⌘C 收尾\n- 管理台在窄屏（≤620px）下表格自己横向滚动、导航自动换行，日期与状态徽章不再折成两三行
- Prometheus `/metrics`、`/healthz`
- 端到端验收测试（16 条 split + 6 条合并端口 + 7 条管理台（单密码 + Token）+ 9 条安装页）+ 2000 并发流压测
- 五个平台产物：macOS(arm64/x86_64)、Linux(arm64/x86_64 静态 musl)、Windows(x86_64)
- 全平台由 `cargo zigbuild` 单机交叉编译，产物附 `SHA256SUMS`
- 目标安全：默认只允许回环与私网目标
