# fairlead

**中文** · [English](README.en.md)

[![ci](https://github.com/hustfyb/fairlead/actions/workflows/ci.yml/badge.svg)](https://github.com/hustfyb/fairlead/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/hustfyb/fairlead?sort=semver)](https://github.com/hustfyb/fairlead/releases)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](Cargo.toml)

单节点、自部署的反向 TCP 隧道：内网机器主动连出来，公网入口按 `Host` 把请求路由到对应的本地端口。不用开入站端口，不用为每个域名改 Nginx 配置。

```
                              ┌── Host: admin.example.com   ──> 管理台
client/agent ──:9000（一个端口）┼── Host: tunnel.example.com + Upgrade ──> 隧道控制面
                              └── 其它 Host ─────────────────> 按路由表转发

fairlead host ──yamux（每 Agent 2 条）──> agent A / agent B ──> 127.0.0.1:7884 / :7885
```

一个端口同时是数据面、控制面和管理面：**请求自己说明自己属于哪个面**（`Host`，隧道再加一个 `Upgrade`）。TLS 不在这里做——要 HTTPS 就在前面放一层 Nginx，它只需把 `Host` 和 `Upgrade` 原样透传。

- **一个二进制**，一个命令区分角色：`host` / `agent` / `admin` / `token` / `gen-nginx` / `doctor` / `demo`。
- **Mac / Linux / Windows** 同一份源码、同一套协议；Linux 产物是静态 musl，不依赖 glibc，Windows 产物不需要 VC++ 运行库。
- 设计取舍见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)，为什么这么选见 [`docs/DECISIONS.md`](docs/DECISIONS.md)，发版规则见 [`docs/RELEASE.md`](docs/RELEASE.md)。

## 安装

每个版本发布五个平台的二进制，全部从同一份源码用 `cargo zigbuild` 交叉编译：

| 平台 | 产物 |
| --- | --- |
| macOS Apple Silicon | `fairlead-<ver>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `fairlead-<ver>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64（静态，glibc/musl 通吃） | `fairlead-<ver>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64（静态） | `fairlead-<ver>-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `fairlead-<ver>-x86_64-pc-windows-gnu.zip` |

```bash
# Linux / macOS
curl -LO https://github.com/hustfyb/fairlead/releases/download/v0.1.2/fairlead-0.1.2-x86_64-unknown-linux-musl.tar.gz
sha256sum -c <(grep x86_64-unknown-linux-musl SHA256SUMS)   # 先校验
tar -xzf fairlead-0.1.2-x86_64-unknown-linux-musl.tar.gz
sudo install -m755 fairlead-0.1.2-x86_64-unknown-linux-musl/fairlead /usr/local/bin/fairlead
```

```powershell
# Windows（PowerShell）
Expand-Archive fairlead-0.1.2-x86_64-pc-windows-gnu.zip .
.\fairlead-0.1.2-x86_64-pc-windows-gnu\fairlead.exe --version
```

macOS 首次运行会被 Gatekeeper 拦（未公证）：

```bash
xattr -d com.apple.quarantine ./fairlead
```

不想下载二进制也可以直接从源码编（需要 stable Rust）：

```bash
cargo install --path crates/fairlead --locked
```

自己打包发布产物：

```bash
./scripts/build-dist.sh      # 五个 target 全编（需要 zig）
./scripts/package.sh all     # 生成 dist/*.tar.gz、dist/*.zip 和 SHA256SUMS
```

## 30 秒看效果（不需要 Nginx）

```bash
cargo run -- demo
```

它会在回环上起 host + agent + 两个演示 origin，**所有东西共用一个随机端口**，并打印可直接粘贴的 curl：

```bash
curl -H 'Host: a1.relay.test' http://127.0.0.1:<port>/
curl -N -H 'Host: a1.relay.test' http://127.0.0.1:<port>/stream      # 逐块到达，不缓冲
curl -H 'Host: a2.relay.test' http://127.0.0.1:<port>/big?mb=64      # 64MB
curl -H 'Host: a1.relay.test' http://127.0.0.1:<port>/echo           # 看 origin 收到的头
curl -o /dev/null -w '%{http_code}\n' -H 'Host: nope.relay.test' http://127.0.0.1:<port>/  # 404
curl -H 'Host: admin.relay.test' http://127.0.0.1:<port>/login       # 管理台，同一个端口
```

管理台只有一个密码（demo 启动时打印），没有用户名；把 `admin.relay.test` 和 `tunnel.relay.test` 写进 `/etc/hosts` 就能用浏览器打开。

## 部署

### 1. Host（公网入口机）

装这台机器自己，也是同一支脚本：

```bash
curl -fsSLO https://app.relay.example.com/install.sh   # 从任何一台中继拿都行
sh install.sh host                                     # 二进制 + host.toml + fairlead-host 服务
fairlead admin passwd --config ~/.config/fairlead/host.toml
$EDITOR ~/.config/fairlead/host.toml                   # listen、tunnel_host、allowed_suffixes
fairlead doctor --config ~/.config/fairlead/host.toml
```

不想要服务就加 `--no-service`。下面是手工装法，效果一样：

```bash
cp deploy/host.toml /etc/fairlead/host.toml
$EDITOR /etc/fairlead/host.toml      # listen、admin_host、tunnel_host、allowed_suffixes

export FAIRLEAD_ADMIN_PASSWORD='至少十个字符'                # 管理台密码，启动时读取
fairlead doctor --config /etc/fairlead/host.toml            # 自检并打印一份可粘贴的 agent 配置
fairlead host   --config /etc/fairlead/host.toml
```

密码不在配置文件里：要么用环境变量（systemd 里写 `Environment=` / `EnvironmentFile=`），要么 `fairlead admin passwd --config /etc/fairlead/host.toml` 写进数据库，两者都不需要改 TOML。

Nginx 只需要一个 server（HTTP/HTTPS），`proxy_pass` 到 `server.listen`；`Host` 和 `Upgrade` 原样透传，三个面由 host 自己分流：

```bash
fairlead gen-nginx --config /etc/fairlead/host.toml > /etc/nginx/conf.d/fairlead.conf
nginx -t && nginx -s reload
```

或者直接用 `deploy/docker-compose.yml`。

**必须保留的几行**（`gen-nginx` 已经写好）：

```nginx
proxy_set_header Host $host;                     # 在合并端口上它就是「面的选择器」
proxy_set_header Upgrade $http_upgrade;          # Agent 靠它升级成隧道
proxy_set_header Connection $fairlead_connection_upgrade;
proxy_set_header X-Forwarded-For $remote_addr;   # 覆写，不要用 $proxy_add_x_forwarded_for
proxy_buffering off; proxy_request_buffering off; # SSE 和大文件
```

#### 套上 HTTPS（推荐，不用开 80 端口）

公网口通常只映射了一个高位端口，80 走不通，所以证书用 **Let's Encrypt 通配符 + DNS-01**：验证记录写进 DNS，不需要任何入站端口。Cloudflare 托管的话建一个 `Zone → DNS → Edit` 权限的 API Token：

```bash
export CF_Token=...                       # Zone / DNS / Edit，仅限本域
acme.sh --issue --dns dns_cf -d relay.example.com -d '*.relay.example.com'
acme.sh --install-cert -d relay.example.com --ecc \
  --fullchain-file /etc/nginx/ssl/relay.example.com.fullchain.pem \
  --key-file       /etc/nginx/ssl/relay.example.com.key.pem \
  --reloadcmd      "nginx -s reload"      # 每 60 天自动续期，续完自己 reload
```

然后把 host 挪到回环口——`listen = "127.0.0.1:9003"`、`admin_listen = "127.0.0.1:9004"`、`public_scheme = "https"`——nginx 占住公网口。完整示例见 **`deploy/nginx/fairlead-tls.conf`**（`http{}` 里只剩管理台，数据面的两个 TLS 终结器都在 `stream{}` 里）。

公网口默认**只收 HTTPS**：

- **HTTPS**：`stream` 层用 `$ssl_preread_protocol` 认出 TLS，交给 9101（`ssl_alpn http/1.1`）在 **stream 层**终结，解密后的字节原样转给 host；
- **明文一律拒**：非 TLS 走 9100，回一句 `400 TLS only` 就断开——`http://…:29001` 不再落进 relay；
- **Agent 走 `tls://relay.example.com:29001`**：Agent 在 TLS 上带 ALPN `fairlead/1`，交给 9102（`ssl_alpn fairlead/1`）终结后原样转给 host。这条不能放到 `http{}` 里——那里只会答应 h2/http1.1，握手会以 `NoApplicationProtocol` 失败。

两个终结器都放在 `stream{}` 而不是 `http{}`，是因为 nginx 的 http 层不实现 `CONNECT`：放 `http{}` 会把正向代理的隧道请求直接 400 掉，fairlead 根本收不到。代价是这个口不再提供 h2（客户端回落 HTTP/1.1）、也没有 `X-Forwarded-For`；HTTPS 的对外名字由 host 的 `public_scheme = "https"` 提供。

**`public_scheme` 不只是写落地页链接**：TLS 在 stream 层终结后，nginx 无法再注入 `X-Forwarded-Proto`，而后面的服务要用它算自己的 origin（OAuth `resource`、DPoP、配对 URL 等）。fairlead 在转发每个站点请求时，会用 `server.public_scheme` 覆盖客户端自带的 `X-Forwarded-Proto`，再发给 Agent 后面的目标：

```
client --HTTPS--> nginx stream --plain HTTP--> fairlead --X-Forwarded-Proto: https--> 目标服务
```

所以 TLS 口一定要配 `public_scheme = "https"`，否则目标会以为自己是 `http://`，客户端发 `resource=https://…/mcp` 时会被 OAuth 校验判 `invalid_target`。自测：`curl https://a1.relay.example.com:29001/.well-known/oauth-protected-resource`，`resource` 应是 `https://…/mcp`。Upgrade（WebSocket）请求也会带这个头；`[proxy]` 的 CONNECT / 绝对形式请求保持原字节转发，不注入。

想保留明文（老用法，比如 `curl -H 'Host: a1.…'` 和明文正向代理）：把 `stream` 里 `"|"` 那条从 `127.0.0.1:9100` 改回 `127.0.0.1:9003` 即可。

管理台同理（9002 整口 TLS，回源 9004）。浏览器访问 `https://<IP>:9002` 会报证书名不匹配——证书只签了 `*.relay.example.com`，用域名访问或在弹窗里继续即可。

### 2. Agent（内网机器）

先签一个一次性 token。最顺手的地方是管理台：登录后 **Token → 签发一个一次性 token**，选后缀和有效期（30 分钟 / 1 小时 / 24 小时 / 7 天 / 不过期），签出来的串**只显示这一遍**，同一页上带着已经填好 token 的 `install.sh` 命令和 `agent.toml` 片段，复制即可。

不想开浏览器也行，在同一台 host 上：

```bash
# 只能注册 *.relay.example.com，24 小时不用就作废
fairlead token --config /etc/fairlead/host.toml --suffix relay.example.com --ttl 24h
```

token 打在 stdout（那两行说明打在 stderr），库里只有它的 SHA-256——事后没有地方能再查出来，丢了就再签一个；`/tokens` 里能看到它用没用、被谁用了、还能吊销。两台机器时顺手带走，别手抄：

```bash
TOKEN=$(ssh relay 'fairlead token --config /etc/fairlead/host.toml --suffix relay.example.com --ttl 24h')
ssh agent "curl -fsSLO https://app.relay.example.com/install.sh && sh install.sh"
ssh agent "~/.local/bin/fairlead agent enroll $TOKEN && ~/.local/bin/fairlead agent add a1.relay.example.com 8080"
```

```bash
curl -fsSLO https://app.relay.example.com/install.sh
sh install.sh                             # 装二进制、写配置、装成服务
fairlead agent enroll <TOKEN>             # 把 token 交给它，服务两秒内连上
fairlead agent add a1.relay.example.com 8080
```

`install.sh` **只做安装**：挑包、校验、装二进制、写一份没有路由的配置、装成服务（Linux systemd、macOS launchd、Windows 计划任务）并启动。服务开机自启，关掉终端也还在。装完它先等着——没有 token 不退出、也不刷错误日志；`enroll` 把 token 写进配置，跑着的服务自己读到就连上，不用重启。`--no-service` 只写配置不装服务，`--start` 前台跑。装脚本再跑一次不会动你的 token 和路由（配置已存在就原样留着），所以可以反复用。

装 host 是同一支脚本：`sh install.sh host`——二进制、`host.toml` 和 `fairlead-host` 服务，密码随后用 `fairlead admin passwd` 设。

**不要加 `sudo`**（除非你就是要装成系统服务）：以你自己的账号跑，二进制进 `~/.local/bin/fairlead`，配置进 `~/.config/fairlead/agent.toml`，状态进 `~/.local/state/fairlead`，服务也以你的身份运行——之后 `fairlead agent add` 不用密码。`~/.local/bin` 不在 PATH 上时脚本会打一行把它加进去；服务按绝对路径启动，加不加 PATH 都开机自启。`sudo sh install.sh …` 仍可用，走系统级：`/usr/local/bin`、`/etc/fairlead`、`/var/lib/fairlead`（`SUDO_USER` 存在时配置和状态会 chown 回你）。装前脚本先查目录能不能写，写不了就停在那一步并给出该用的 `--prefix` / `--config`，不会先下完 20 MB 再说。

之后**不用手改 TOML**，都用命令：

```bash
fairlead agent list                     # 这台机器发布了什么，现在是 serving 还是被中继拒绝
fairlead agent add 8080                 # 发布 127.0.0.1:8080，名字是 a8080.<后缀>
fairlead agent add a3.relay.example.com 3000
fairlead agent rm a3.relay.example.com
fairlead agent status                   # 服务状态、隧道数、最后一次错误
sudo fairlead agent service restart     # 还有 start / stop / uninstall / status
```

`add` / `rm` 只改配置文件里的路由表；正在跑的服务两秒内自己重读、重新声明，不重启、不掉隧道，中继那边同步增删（Agent 声明什么就是什么）。所以「加一个端口映射」在终端里一句话就完，退出终端、机器重启都不影响。

首次连接用 token 换长期 credential，存在 `state_file`（0600，默认 `/var/lib/fairlead/agent-state.json`）。之后重连只用 credential，token 不会再用第二次。

### 3. 开机自启

Agent 不用管：`install.sh` 已经装成服务了，`fairlead agent service status|restart|uninstall` 就够。Host 同理（`install.sh host` 装的是 `fairlead-host`，`fairlead host service status|restart|uninstall`），仓库里的 unit 是手工装法：

```bash
install -m0644 deploy/systemd/fairlead-host.service /etc/systemd/system/
systemctl enable --now fairlead-host
```

## 配置

两个文件，`deny_unknown_fields`：键名写错会启动失败，而不是悄悄用默认值。

| Host | 说明 |
| --- | --- |
| `server.listen` | **合并端口**。设了它，一个 socket 服务三个面；留空则回到下面三个独立监听（split 模式，隧道自带 TLS） |
| `server.admin_host` | 合并端口上选管理面的三级域名，例如 `admin.relay.example.com` |
| `server.tunnel_host` | 合并端口上选隧道面的三级域名，例如 `tunnel.relay.example.com` |
| `server.edge_listen` | split 模式：Nginx 上游，默认 `127.0.0.1:9000`（非回环会拒绝启动） |
| `server.tunnel_listen` | split 模式：Agent 连接端口，默认 `0.0.0.0:9443` |
| `server.admin_listen` | 管理台自己的 socket。设了就从这个端口提供管理面（split 模式默认 `127.0.0.1:9001`；合并端口下管理面随之离开 `listen`）；留空则管理面留在 `server.listen` 上，由 `admin_host` 选中。非回环需 `admin.allow_remote = true` |
| `server.allowed_suffixes` | 允许注册的域名后缀，空列表直接拒绝启动 |
| `landing.dir` | 安装页的产物目录（`scripts/package.sh` 的输出）。留空=关，未知 Host 继续回 400/404 |
| `landing.host` | 给安装页一个固定名字，通常 `app.<后缀>`（通配记录已经指向这里）。设了之后这个 Host 永远返回安装页，哪怕它看起来是个站点，同名路由也被它盖住。需要 `landing.dir` |
| `proxy.route` | 让**同一个端口**也能当中转代理：应答 `CONNECT host:port` 和绝对形式（`GET http://host/ …`）的请求。写短名 `muse` 等于 `muse.<第一个 allowed_suffix>`。留空=关 |
| `proxy.auth` | `user:password`，客户端要用 `Proxy-Authorization: Basic` 带上它。和 `allow_from` 至少给一个，两个都空会拒绝启动 |
| `proxy.allow_from` | 只允许这些客户端地址用代理：`10.0.0.0/8`、`203.0.113.7`、`::1` |
| `proxy.idle_timeout_secs` | 代理流的空闲上限，`0`（默认）表示不因为安静而断开——静默的 CONNECT 隧道不该被掐 |
| `tls.cert` / `tls.key` | split 模式的隧道监听证书；开发可用 `tls.dev_self_signed = true`。合并端口不做 TLS，这两个键被忽略 |
| `limits.*` | 头上限、并发流、心跳、空闲超时 |
| `admin.password_hash` | 只为兼容旧配置：库里还没有密码时用它播种一次；新部署请用 `FAIRLEAD_ADMIN_PASSWORD` 或 `fairlead admin passwd` |
| `admin.session_ttl_secs` | 管理台会话有效期，默认 12h |
| `admin.allow_remote` | 允许管理台监听非回环地址（默认拒绝，防止手滑把后台暴露到公网） |
| `admin.trust_forwarded_for` | 从 `X-Real-IP` / `X-Forwarded-For` 取客户端 IP（只放在你自己的代理后面） |
| `admin.secure_cookie` | 管理台走 HTTPS 时置 true，cookie 加 `Secure` |

**只有一个端口能映射时**（宽带没有公网 IP、路由器只给一个映射、或就想少开一个洞）：

```toml
[server]
listen = "0.0.0.0:9000"                    # 唯一的 socket，映射到它
admin_host = "admin.relay.example.com"     # 浏览器用这个域名开管理台
tunnel_host = "tunnel.relay.example.com"   # Agent 用这个域名连隧道
allowed_suffixes = ["relay.example.com"]
public_port = 29001                        # 只是给 gen-nginx / doctor 看的
```

三个面各占一个三级域名，其它 Host 全部走路由表。DNS（或本机 `hosts`）里把三个名字都指向同一个 IP 即可。**这一层没有 TLS**：管理台的会话 cookie 和登录口令都是明文，先套 Nginx 再对公网开放，并把 `admin.secure_cookie` 打开。

**不想让管理台占那个公网口**：再加一行 `admin_listen`，管理面就搬到内网端口上，`listen` 只留隧道和站点流量：

```toml
[server]
listen = "0.0.0.0:9000"          # 映射到它：Agent（tunnel_host）+ 站点
admin_listen = "0.0.0.0:9001"    # 只在内网可达，不要做端口映射
tunnel_host = "tunnel.relay.example.com"
```

这时 `admin_host` 不再需要：公网上用任何 Host（包括原来的管理台域名）打 `listen` 都只会落到路由表，管理面拿不到站点流量，站点也拿不到管理台。

**把同一个端口当正向代理用**（不额外开端口）：`Host` 在这里是**目的地**，所以中继查不到路由——`CONNECT example.com:443` 和 `GET http://example.com/ …` 会被当成「没这条路由」。`[proxy] route` 指名一条路由来应答这类请求：

```toml
[proxy]
route = "muse"                    # = muse.relay.example.com，必须是一条真路由
auth = "user:password"            # 或者 allow_from = ["192.168.1.0/24"]
idle_timeout_secs = 0             # 静默的隧道不断
```

```bash
# Agent 那台机器上有一只真正的正向代理（xray / mihomo / squid / privoxy 都行）：
fairlead agent add muse 7890      # 就把那条路由指向它

# 客户端：HTTP 和 HTTPS 都走这一个端口
curl --proxy http://user:password@relay.example.com:9000 http://example.com/
curl --proxy http://user:password@relay.example.com:9000 https://example.com/
# 浏览器：代理填 relay.example.com:9000，认证框里填 user / password
```

前面套了「只收 HTTPS」的 nginx（上面那节）就换个写法——代理本身就是个 `https://` 地址，`CONNECT` 在 TLS 里面：

```bash
curl --proxy https://user:password@relay.example.com:29001 https://example.com/
# curl 会先对代理做 TLS 握手，再在加密流里发 CONNECT；明文 --proxy http:// 会被回 400
```

关键在**中继没有实现代理协议**：它把请求头原字节塞进隧道，剩下的 200、TLS、目标解析都是 Agent 那台机器上的那只代理在做。所以 `CONNECT` 不需要我们实现，HTTPS、`ssh -o ProxyCommand`、gRPC 也一并能用。代价是这条路由把公网端口变成了一个出口，因此 `proxy.auth` 或 `proxy.allow_from` 必须有——两个都空时中继拒绝启动。

| Agent | 说明 |
| --- | --- |
| `server` | `http://relay.example.com:9000`（明文，合并端口）/ `tls://relay.example.com:443`（Nginx 终止 TLS）/ `tls://…:9443`（split 模式，旧写法不带 scheme 也按 TLS 处理） |
| `tunnel_host` | 升级请求里的 `Host`，必须等于 host 的 `server.tunnel_host`；省略时用 `server` 的主机名 |
| `tls.mode` | `system`（系统根 + 内置 Mozilla 根）/ `pin`（证书指纹）/ `insecure`（仅开发）；只对 `tls://` 生效 |
| `tunnels` | 物理隧道数，默认 2（一条大下载不会拖慢同一 Agent 的其它请求） |
| `allow_public_targets` | 默认 `false`：只允许回环和私网目标 |
| `state_file` | 长期 credential 的位置，默认 `/var/lib/fairlead/agent-state.json`；状态文件 `agent.status.json` 放在它旁边 |
| `[[routes]]` | `host` + `target`（`127.0.0.1:7884`）。**用 `fairlead agent add` / `rm` 改，不要手写**，服务会自己重读 |

## 安装页（一条命令装 Agent）

直接用 IP 打开端口，或者用一个不可能成为路由的 Host，返回的不是 404 而是一页静态页面：五个平台的包、`SHA256SUMS`、以及一个 `install.sh`。

先决条件只有一条：`*.<后缀>` 的通配 A 记录指向中继。路由用的全是子域名，有这一条通配，以后每加一个服务都不用再动 DNS；隧道入口 `tunnel.<后缀>` 也落在这条记录里。只配 apex、或者一个子域配一条 A 记录，会变成「每加一次路由改一次 DNS」。

```toml
[landing]
dir = "/var/lib/fairlead/dist"       # scripts/package.sh 的输出目录；不写这一节就是关
host = "app.relay.example.com"       # 可选：给这页一个固定地址
```

设了 `host` 之后，这页不再只靠「打错才看得到」：`app.<后缀>` 就是它的门牌，可以直接印进文档发给新同事。这个名字优先于路由表——同名路由不会盖住它，反过来也成立，别拿它当业务域用。不设就还是老行为：只有 IP、后缀的 apex、以及不属于任何后缀的 Host 看得到。

```bash
./scripts/package.sh all
rsync -a dist/ /var/lib/fairlead/dist/
fairlead doctor --config host.toml
# ✓ landing page                 /var/lib/fairlead/dist (5 downloads + install.sh, on app.relay.example.com, plus unrouted hosts)
```

| 路径 | 内容 |
| --- | --- |
| `/` | 下载页：平台、文件名、大小、SHA-256、安装命令 |
| `/install.sh` | 安装脚本：按 `uname` 选包、校验 SHA-256、装二进制、写配置、装服务（自己跑进 `~/.local/bin`，`sudo` 跑进 `/usr/local/bin`）；`sh install.sh host` 装的是中继自己 |
| `/download/<file>` | `dir` 里的产物，按文件名精确匹配 |
| `/SHA256SUMS` | 校验清单 |

```bash
sh install.sh                  # agent：二进制 + 配置 + fairlead-agent 服务
sh install.sh host             # host：二进制 + host.toml + fairlead-host 服务
# 默认（非 root）：--prefix ~/.local/bin, --config ~/.config/fairlead/agent.toml, --state ~/.local/state/fairlead
# 可选：--server / --tunnel-host / --tunnels / --name / --prefix / --config
#       --no-config / --no-service / --start / --refresh
```

默认装成服务（`systemctl status fairlead-agent` / `launchctl print system/com.fairlead.agent`），服务以执行安装的用户身份运行，所以之后 `fairlead agent add` 不需要 sudo。

边界（也是它不会帮倒忙的原因）：只有**不可能成为路由**的 Host 才会看到这页——`nope.relay.example.com` 这种写错的子域名仍然是 404，停用/删除的路由仍然是 503/404，所以这页不会掩盖真正的问题。页面里没有任何凭据——token 在管理台的「Token」页签发（或主机上 `fairlead token`）；下载只在 `dir` 这一层按文件名精确匹配（不解码、不允许 `..`、不列目录），它不是一个静态文件服务器。

## 管理台密码

只有**一个**管理身份，而且**没有用户名**：密码就是全部凭据。登录页只有一个输入框。

```bash
export FAIRLEAD_ADMIN_PASSWORD='至少十个字符'      # 方式一：环境变量，每次启动生效
fairlead admin passwd --config /etc/fairlead/host.toml   # 方式二：写进数据库（提示输入，或从 stdin 读两行）
fairlead admin status --config /etc/fairlead/host.toml   # 有没有密码、什么时候改的、上次登录
```

- **优先级**：环境变量 > 数据库。启动时若设了 `FAIRLEAD_ADMIN_PASSWORD`，它会被写进库里；如果它与库里已有的密码一致，什么都不做——所以重启不会把人踢下线，只有在真的换了密码时才会让所有会话失效。用环境变量管密码时，就别在网页上改（下次启动会被覆盖，`/account` 页会提醒你）。
- 密码只存 argon2id 哈希（不可还原——忘了只能重设）；明文只在环境变量或你输入的那一刻存在。
- 登录失败按客户端 IP 限流（10 次 / 5 分钟）；失败提示不区分「没设密码」和「密码错」。
- **Token**：`/tokens` 签发一次性 enrollment token——选后缀、有效期（30 分钟 / 1 小时 / 24 小时 / 7 天 / 不过期）、备注；签发后那一页显示明文一次（旁边一个「复制 token」按钮，点一下 token 框也会整串选中，命令和片段也各有一个复制按钮），并给出已经填好 token 的 `install.sh` 命令和 `agent.toml` 片段。列表只留后缀、备注、状态（可用 / 已使用 / 已过期 / 已吊销）、被哪个 Agent 用了，随时可吊销。CLI 等价物仍是 `fairlead token`。
- 会话存在 SQLite（`admin_sessions`），浏览器里的 cookie 是随机会话密钥，库里只存 SHA-256；改密码会立刻让所有管理会话失效。host 重启不影响登录态。
- 合并端口上，管理面只由 `server.admin_host` 这个 Host 选中：站点路由拿不到管理台，随便猜一个 Host 也不会掉进登录页。设了 `server.admin_listen` 则管理面整个搬到那个端口，合并端口上连管理台域名都只回 404。要远程访问，推荐前面套 Nginx 并 `admin.secure_cookie = true`；直接监听非回环地址需要显式 `admin.allow_remote = true`，启动会打警告。
- 没设密码时管理台不假装能用：登录页直接说明怎么设置，任何登录尝试都被拒。
- 删除路由是墓碑（名字被占住，Agent 重连不会复活它），所以它默认不出现在总览和路由列表里；要找回误删的那条，打开 `/routes?deleted=1`，点「恢复」。

## 运维

| 端点 | 用途 |
| --- | --- |
| `GET /healthz`（管理面） | JSON：db、在线 Agent、隧道数、路由数、丢弃日志数 |
| `GET /metrics`（管理面） | Prometheus 文本 |
| 管理台 `/diagnostics?host=...` | 四步链路诊断，最后一步真的经 Edge 发一次 `GET /` |

- **错误语义**：无路由 404，Agent 离线/路由停用 503，Agent 连不上目标 502，超时 504，目标被策略拒绝 403。
- **日志**：每请求一条结构化记录（request id / host / route / agent / 状态码 / 耗时 / 上下行字节），有界队列，满了丢弃并计数，绝不反压数据面。
- **升级**：先 `VACUUM INTO` 备份再换二进制；回滚要成对回滚二进制和数据库（见 `docs/RELEASE.md`）。

## 开发

```bash
cargo test --workspace          # 140 条：单元测试 + 48 条端到端验收
cargo run -- demo               # 手动玩
RUST_LOG=info,fairlead_host::edge=debug cargo run -- demo
```

代码结构：

```
crates/fairlead-proto/   协议、Host 嗅探、帧、数据流前导、目标策略、yamux 驱动
crates/fairlead-host/    edge / tunnel / admin / db / registry / metrics
crates/fairlead-agent/   隧道池、注册、心跳、本地 dial、转发
crates/fairlead-testkit/ 进程内 e2e 夹具 + 验收测试
crates/fairlead/         CLI
```

## 发布流程

```bash
./scripts/build-dist.sh          # 五个 target 全交叉编译（zig）
./scripts/package.sh all         # dist/*.tar.gz、*.zip、SHA256SUMS
```

`git tag v0.1.2 && git push --tags` 之后 CI（`.github/workflows/release.yml`）跑同样的两步并挂到 Release 上。发版门禁与回滚步骤见 [`docs/RELEASE.md`](docs/RELEASE.md)。

压测（需要 `ulimit -n 65535`）：

```bash
cargo test -p fairlead-testkit --test load -- --ignored --nocapture --test-threads=1
```

## 明确不做

多节点/HA、Kubernetes Operator、Cloudflare 橙云、ACME 自动签发、UDP、非 HTTP 共享端口协议、多租户与计费。单机就是单点，不包装成高可用。

## License

MIT
