# frplike

单节点、自部署的反向 TCP 隧道：内网机器主动连出来，公网入口按 `Host` 把请求路由到对应的本地端口。不用开入站端口，不用为每个域名改 Nginx 配置。

```
client ──HTTP/1.1──> nginx :8080/:443 ──127.0.0.1:9000──> frplike host
                                                              │  查 Host 路由
                                                              │  TLS + yamux
                                                              ▼
                                                     agent A / agent B
                                                              │
                                                     127.0.0.1:7884 / :7885
```

- **一个二进制**，一个命令区分角色：`host` / `agent` / `token` / `passwd` / `gen-nginx` / `doctor` / `demo`。
- **Mac / Linux / Windows** 同一份源码、同一套协议；Linux 产物是静态 musl，不依赖 glibc，Windows 产物不需要 VC++ 运行库。
- 设计取舍见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)，为什么这么选见 [`docs/DECISIONS.md`](docs/DECISIONS.md)，发版规则见 [`docs/RELEASE.md`](docs/RELEASE.md)。

## 安装

每个版本发布五个平台的二进制，全部从同一份源码用 `cargo zigbuild` 交叉编译：

| 平台 | 产物 |
| --- | --- |
| macOS Apple Silicon | `frplike-<ver>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `frplike-<ver>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64（静态，glibc/musl 通吃） | `frplike-<ver>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64（静态） | `frplike-<ver>-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `frplike-<ver>-x86_64-pc-windows-gnu.zip` |

```bash
# Linux / macOS
curl -LO https://github.com/<org>/frplike/releases/download/v0.1.0/frplike-0.1.0-x86_64-unknown-linux-musl.tar.gz
sha256sum -c <(grep x86_64-unknown-linux-musl SHA256SUMS)   # 先校验
tar -xzf frplike-0.1.0-x86_64-unknown-linux-musl.tar.gz
sudo install -m755 frplike-0.1.0-x86_64-unknown-linux-musl/frplike /usr/local/bin/frplike
```

```powershell
# Windows（PowerShell）
Expand-Archive frplike-0.1.0-x86_64-pc-windows-gnu.zip .
.\frplike-0.1.0-x86_64-pc-windows-gnu\frplike.exe --version
```

macOS 首次运行会被 Gatekeeper 拦（未公证）：

```bash
xattr -d com.apple.quarantine ./frplike
```

不想下载二进制也可以直接从源码编（需要 stable Rust）：

```bash
cargo install --path crates/frplike --locked
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

它会在回环上起 host + agent + 两个演示 origin，并打印可直接粘贴的 curl：

```bash
curl -H 'Host: a1.relay.test' http://127.0.0.1:<edge>/
curl -N -H 'Host: a1.relay.test' http://127.0.0.1:<edge>/stream      # 逐块到达，不缓冲
curl -H 'Host: a2.relay.test' http://127.0.0.1:<edge>/big?mb=64      # 64MB
curl -H 'Host: a1.relay.test' http://127.0.0.1:<edge>/echo           # 看 origin 收到的头
curl -o /dev/null -w '%{http_code}\n' -H 'Host: nope.relay.test' http://127.0.0.1:<edge>/  # 404
```

管理台在打印出的 `admin` 地址上，账号是单个管理员，密码在启动时打印。

## 部署

### 1. Host（公网入口机）

```bash
frplike passwd > /tmp/hash          # 交互式输入，输出 argon2id 哈希
cp deploy/host.toml /etc/frplike/host.toml
$EDITOR /etc/frplike/host.toml      # allowed_suffixes、tls.cert/key、password_hash

frplike doctor --config /etc/frplike/host.toml   # 自检并打印隧道证书指纹
frplike host   --config /etc/frplike/host.toml
```

Nginx 只需要两个 server（HTTP/HTTPS），都 `proxy_pass` 到 `127.0.0.1:9000`：

```bash
frplike gen-nginx --config /etc/frplike/host.toml > /etc/nginx/conf.d/frplike.conf
nginx -t && nginx -s reload
```

或者直接用 `deploy/docker-compose.yml`。

**必须保留的两行**（`gen-nginx` 已经写好）：

```nginx
proxy_set_header X-Forwarded-For $remote_addr;   # 覆写，不要用 $proxy_add_x_forwarded_for
proxy_buffering off; proxy_request_buffering off; # SSE 和大文件
```

### 2. Agent（内网机器）

```bash
# 在 host 上签发一个只能注册 *.relay.example.com 的一次性 token
frplike token --config /etc/frplike/host.toml --suffix relay.example.com --ttl 24h

cp deploy/agent.toml /etc/frplike/agent.toml
$EDITOR /etc/frplike/agent.toml     # server、token、[[routes]]
frplike agent --config /etc/frplike/agent.toml
```

首次连接用 token 换长期 credential，存在 `state_file`（0600）。之后重连只用 credential，token 不会再用第二次。

### 3. systemd

```bash
install -m0644 deploy/systemd/frplike-host.service /etc/systemd/system/
systemctl enable --now frplike-host
```

## 配置

两个文件，`deny_unknown_fields`：键名写错会启动失败，而不是悄悄用默认值。

| Host | 说明 |
| --- | --- |
| `server.edge_listen` | Nginx 上游，默认 `127.0.0.1:9000`（非回环会拒绝启动） |
| `server.tunnel_listen` | Agent 连接端口，默认 `0.0.0.0:9443` |
| `server.admin_listen` | 管理台，默认 `127.0.0.1:9001` |
| `server.allowed_suffixes` | 允许注册的域名后缀，空列表直接拒绝启动 |
| `tls.cert` / `tls.key` | 隧道监听证书；开发可用 `tls.dev_self_signed = true` |
| `limits.*` | 头上限、并发流、心跳、空闲超时 |

| Agent | 说明 |
| --- | --- |
| `server` | `tls://relay.example.com:9443` |
| `tls.mode` | `system`（系统根 + 内置 Mozilla 根）/ `pin`（证书指纹）/ `insecure`（仅开发） |
| `tunnels` | 物理隧道数，默认 2（一条大下载不会拖慢同一 Agent 的其它请求） |
| `allow_public_targets` | 默认 `false`：只允许回环和私网目标 |
| `[[routes]]` | `host` + `target`（`127.0.0.1:7884`） |

## 运维

| 端点 | 用途 |
| --- | --- |
| `GET /healthz`（admin 端口） | JSON：db、在线 Agent、隧道数、路由数、丢弃日志数 |
| `GET /metrics`（admin 端口） | Prometheus 文本 |
| 管理台 `/diagnostics?host=...` | 四步链路诊断，最后一步真的经 Edge 发一次 `GET /` |

- **错误语义**：无路由 404，Agent 离线/路由停用 503，Agent 连不上目标 502，超时 504，目标被策略拒绝 403。
- **日志**：每请求一条结构化记录（request id / host / route / agent / 状态码 / 耗时 / 上下行字节），有界队列，满了丢弃并计数，绝不反压数据面。
- **升级**：先 `VACUUM INTO` 备份再换二进制；回滚要成对回滚二进制和数据库（见 `docs/RELEASE.md`）。

## 开发

```bash
cargo test --workspace          # 单元 + 15 条端到端验收
cargo run -- demo               # 手动玩
RUST_LOG=info,frplike_host::edge=debug cargo run -- demo
```

代码结构：

```
crates/frplike-proto/   协议、Host 嗅探、帧、数据流前导、目标策略、yamux 驱动
crates/frplike-host/    edge / tunnel / admin / db / registry / metrics
crates/frplike-agent/   隧道池、注册、心跳、本地 dial、转发
crates/frplike-testkit/ 进程内 e2e 夹具 + 验收测试
crates/frplike/         CLI
```

## 发布流程

```bash
./scripts/build-dist.sh          # 五个 target 全交叉编译（zig）
./scripts/package.sh all         # dist/*.tar.gz、*.zip、SHA256SUMS
```

`git tag v0.1.0 && git push --tags` 之后 CI（`.github/workflows/release.yml`）跑同样的两步并挂到 Release 上。发版门禁与回滚步骤见 [`docs/RELEASE.md`](docs/RELEASE.md)。

压测（需要 `ulimit -n 65535`）：

```bash
cargo test -p frplike-testkit --test load -- --ignored --nocapture --test-threads=1
```

## 明确不做

多节点/HA、Kubernetes Operator、Cloudflare 橙云、ACME 自动签发、UDP、非 HTTP 共享端口协议、多租户与计费。单机就是单点，不包装成高可用。

## License

MIT
