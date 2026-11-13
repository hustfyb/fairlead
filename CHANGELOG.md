# Changelog

## v0.1.3 — unreleased

- **一个端口也能当正向代理**：`[proxy] route` 让中继应答 `CONNECT host:port` 和绝对形式（`GET http://host/ …`）的请求——它们的目的地在请求行里，`Host` 也是目的地，所以按 Host 查路由永远查不到，过去会落到自己的 404/落地页。现在这类请求交给指定的那条路由，请求头**原字节**进隧道，`Proxy-Authorization: Basic`（`proxy.auth`）或来源地址（`proxy.allow_from`）先过一道。中继不实现代理协议：`CONNECT` 的 200、TLS、目标解析都由 Agent 那台机器上真正的正向代理完成
- 代理流默认**不设空闲上限**（`proxy.idle_timeout_secs = 0`）：静默的 CONNECT 隧道不该按站点流量的 120s 被掐
- 两个入口都空时 `validate()` 拒绝启动：一个开放的公网代理会在几小时内被发现并滥用。`doctor` 打一行 `proxy`，启动横幅同样
- 修正上一版的说法：`CONNECT` 从来不是「不支持」，隧道一直在原样搬运，缺的只是不靠 Host 选路（ARCHITECTURE §4.5、ADR-19）
- **`deploy/nginx/fairlead-tls.conf` 改成「公网口只收 HTTPS」**：两个 TLS 终结器都放进 `stream{}`，非 TLS 的字节回一句 `400 TLS only` 后断开，不再透传明文。上一版把浏览器 TLS 放在 `http{}` 里——而 nginx 的 http 层不实现 `CONNECT`，正向代理的隧道请求会被它直接 400 掉，fairlead 收不到。现在 TLS 在 stream 层终结、解密后的字节原样交给 host，`CONNECT`、`Upgrade`、绝对形式请求都归 fairlead 处理；代价是这一口没有 h2、也没有 `X-Forwarded-For`，对外协议名由 `public_scheme` 提供。想保留明文就把 `map` 里 `"|"` 那条改回 `127.0.0.1:9003`
- **`deploy/nginx/fairlead-tls.conf`**：把 HTTPS 套在公网口上的完整写法——`stream` + `ssl_preread` 在同一端口区分明文、浏览器 TLS 和 Agent 隧道（`ssl_alpn fairlead/1`），host 退到回环口，管理台单独 TLS。证书走 Let's Encrypt 通配符 + DNS-01，不需要 80 端口

## v0.1.2 — 2026-11-01

首个公开版本：仓库开源到 GitHub，README 中英双语（`README.md` / `README.en.md`）。

- **`fairlead agent add` 会先敲一下目标端口**：中继接受一条路由时不看目标活不活，第一个请求才是发现真相的地方——它会变成 `502 agent could not connect to the local target`，而这句里既没有端口也没有机器名。现在 `add` 写完之后立刻 TCP 连一次目标，没人应答就直说：「nothing answers on 127.0.0.1:3773 (connection refused); the route still publishes, but requests to it come back 502 until something listens there」。只是提示，不阻止发布——目标可能本来就还没起来

## v0.1.1 — 2026-11-01

- **装和配分开**：`install.sh` 只做安装——装二进制、写一份**没有路由**的配置、装服务。token 交给 `fairlead agent enroll <TOKEN>`（写进配置，跑着的服务两秒内自己读到并连上，不用重启；`--fresh` 用于吊销之后重新登记），路由交给 `fairlead agent add` / `rm`。旧版的 `--token` / `--route` 参数删掉了：脚本会被反复运行，而 token 是一次性的、路由是天天加的，混在一起既不能重跑也说不清它在做什么
- **`install.sh host`**：同一支脚本装中继自己——`fairlead-host` 服务 + 一份 `host.toml`（listen / admin_listen / tunnel_host / allowed_suffixes / database / public_port），密码随后 `fairlead admin passwd`。`install.sh agent` 仍是默认
- 服务模块按角色生成 unit：`fairlead-agent` 跑 `agent run`，`fairlead-host` 跑 `host`，后者把密码放进配置旁边的 `admin.env`（`EnvironmentFile=-…`），不写进 unit
- 没有 token 的 Agent 不再启动即退出：服务起来后先等（日志一行「no enrollment token yet」），`enroll` 写进配置就连上。旧行为是 `Restart=always` 下的崩溃循环
- 配置只在不存在时写一次：重跑 `install.sh` 不会抹掉 token 和 `[[routes]]`
- 管理台「Token 已签发」页的一键命令改成 install + enroll + add 四条（一次复制全带走）；安装页同样改成四步，并说明脚本只装、`enroll` 和 `add` 随时可再来一次
- `fairlead agent status` / `service install` 的提示打真实二进制路径与角色（`agent` / `host`）
- 版本 0.1.1：安装脚本「同版本不重下」的判据是包名里的版本等于本地 `--version`，二进制变了而版本不变的时候，旧逻辑会把新包当成「已装」跳过

## v0.1.0 — 2026-10-29

首个可运行版本：单节点、共享端口、按 Host 路由。

- **Agent 侧的命令行**（本机管理端口映射，不用手改 TOML）：`fairlead agent list`（发布中的端口 + 实时状态）、`add <host> <port>`（或 `add 8080`，自动命名 `a8080.<后缀>`）、`rm <host>`、`status`。`add`/`rm` 用 toml_edit 只动 `[[routes]]`，注释和其它键原样保留；运行中的服务两秒内重读配置并把新声明发给中继，不重启、不掉隧道
- **装成服务**：`fairlead agent service install|uninstall|start|stop|restart|status`——Linux systemd、macOS launchd、Windows 计划任务；`install.sh` 默认调用它，开机自启；服务以安装者身份运行（`--user` 可指定），`--no-service` 跳过，`--dry-run` 只打印 unit/plist
- **`install.sh` 装到你自己的账号下**：不加 `sudo` 时二进制进 `~/.local/bin/fairlead`、配置进 `~/.config/fairlead/agent.toml`、状态进 `~/.local/state/fairlead`，服务也以你身份运行，`fairlead agent add` 不用密码；`~/.local/bin` 不在 `PATH` 时脚本直接把该加的那行打出来。`sudo` 仍走系统级（`/usr/local/bin`、`/etc/fairlead`、`/var/lib/fairlead`）。装前先检查目录可写，写不了就停在那一步并给出该用的 `--prefix` / `--config`——旧版是下完 20 MB、解包后才在 `/usr/local/bin` 上失败，还建议「加 sudo 重跑」，那其实是另一种安装（系统级、配置进 `/etc`）
- `fairlead agent list|add|rm|status` 找配置时也认 `~/.config/fairlead/agent.toml`（家目录安装），顺序：`--config` → `./fairlead-agent.toml` → `/etc/fairlead/agent.toml` → 家目录
- **tar 包不再带 macOS 扩展属性**：`package.sh` 打包时去掉 xattrs（`--no-xattrs`，bsdtar 再加 `--disable-copyfile`），Linux 上解包不再刷 20 行 `Ignoring unknown extended header keyword 'LIBARCHIVE.xattr.com.apple.provenance'`；打完会自查一遍
- `install.sh` 的用法文本从反引号改成单引号：那段写在未加引号的 heredoc 里，`--help` 会把 `` `fairlead token` `` 当命令执行（打印 “not found” 并吞掉那段文字）
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
