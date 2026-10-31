# fairlead 发布方案

| 项目 | 内容 |
| --- | --- |
| 状态 | Accepted |
| 日期 | 2026-10-29 |
| 版本线 | v0.1.0 起 |
| 产物 | 单二进制 `fairlead`（Mac / Linux / Windows） |

---

## 1. 版本语义（硬边界，不是愿望）

| 段 | 含义 | 允许的破坏 |
| --- | --- | --- |
| `0.x.y` | 修补 | 不改传输协议、不改配置键名、不删 CLI 参数 |
| `0.x` | 功能 | 可加协议字段（旧 Agent 必须能连），可加配置键（必须有默认值） |
| `0.(x+1).0` | 协议破坏 | Host 拒绝旧 Agent，报 `protocol_mismatch` 并在控制台标红 |

判定标准只有一条：**旧 Agent 连新 Host 是否还能工作**。不能用就 bump minor，同时把 `PROTOCOL_VERSION` 加一，Host 给出可读错误，而不是让旧 Agent 在半兼容状态里随机失败。

v0.1.x 明确不做自动升级。半升级状态（新二进制已落地、旧进程还在跑、磁盘上新旧配置并存）的处理成本远高于它省下的运维。

## 2. 产物矩阵

一个二进制，五个平台：

| 目标三元组 | 平台 | 构建方式 |
| --- | --- | --- |
| `aarch64-apple-darwin` | macOS Apple Silicon | zig |
| `x86_64-apple-darwin` | macOS Intel | zig |
| `x86_64-unknown-linux-musl` | Linux x86_64（静态） | zig |
| `aarch64-unknown-linux-musl` | Linux arm64（静态） | zig |
| `x86_64-pc-windows-gnu` | Windows x86_64 | zig（无 VC++ 运行库依赖）|

- **musl 静态链接**：Linux 产物不依赖 glibc，Alpine / Debian / CentOS 7 都能直接跑。SQLite 用 `bundled` 编进二进制，没有任何 `.so` 依赖。
- **macOS**：两个架构分别构建（不用 universal binary：体积翻倍，收益只有少一个下载项）。
- **Windows**：console 程序；服务化用 `sc.exe create` 或 NSSM，v0.1 不内置 `windows-service`。
- 归档：`fairlead-<version>-<target>.tar.gz`，外加 `SHA256SUMS`。Windows 也有 `tar.exe`（1803+），不为它单独出 zip。

每个归档包含：

```
fairlead              # 二进制
README.md
LICENSE
docs/ARCHITECTURE.md
docs/RELEASE.md
deploy/              # 示例配置、nginx、systemd、docker-compose
```

## 3. 发布列车

| 车次 | 内容 | EXIT 闸门 |
| --- | --- | --- |
| `v0.1.0-alpha.1` | 协议骨架 + 垂直切片 | 端到端能跑通一次 GET；WS/SSE/大文件手工验证 |
| `v0.1.0` | MVP（PRD 13 全部 14 条） | 14 条验收自动化全绿 + 2000 并发流压测 + 备份/恢复/回滚演练 |
| `v0.1.1..` | 修补 | 回归集全绿；协议号不变 |
| `v0.2.0` | QUIC 传输、SNI 直通、PostgreSQL | 0.1 的 Agent 能连 0.2 的 Host（否则就是 0.3） |
| `v1.0.0` | 多节点、HA、RBAC | 破坏性变更必须有迁移脚本和回滚脚本 |

## 4. 发布门禁（全部自动化，缺一不可）

1. `cargo test --workspace`：单元 + 15 条端到端验收。
2. **14 条 PRD 验收**逐条映射到测试用例（见第 6 节），缺一条不算发布。
3. **2000 并发流压测**：`testkit` 的压测用例（`--ignored` 手动跑），要求 p99 < 200ms、无错误、内存增长 < 500MB。
4. **备份→恢复→回滚**演练：见第 5 节。
5. **Nginx golden test**：`fairlead gen-nginx` 生成的片段过 `nginx -t`。
6. 三个平台的二进制都能 `fairlead --version` 并启动 `fairlead demo`（CI 里 smoke）。

## 5. 升级与回滚

SQLite 迁移**只前进**，没有 down migration。因此升级流程必须自带备份：

```
1. fairlead host --check          # 配置/数据库/TLS 自检
2. sqlite3 fairlead.db "VACUUM INTO 'backup-<version>-<ts>.db'"   # 原子备份
3. 停旧进程 → 换二进制 → 起新进程；若设了 `landing.dir`，同一步里把新产物同步过去（`rsync -a dist/ /var/lib/fairlead/dist/`），否则安装页继续发旧包
4. curl -H 'Host: admin.<你的域名>' 127.0.0.1:9000/healthz   # 期望 status=ok, db=true
   # split 模式则是 curl 127.0.0.1:9001/healthz
5. 验证一条真实路由：curl -H 'Host: a1.<你的域名>' 127.0.0.1:9000/
```

回滚 = **旧二进制 digest + 第 2 步的备份**。只回滚二进制、不回滚数据库，会在 schema 变更后炸掉；只回滚数据库、不回滚二进制，会在新字段上炸掉。两者必须成对。

`fairlead host --check` 在 v0.1 里由 `fairlead doctor` 承担。`scripts/upgrade.sh` 把上面五步固化，避免文档和现实分叉。

## 6. 验收映射（PRD 13 → 自动化用例）

| # | PRD 验收 | 用例 |
| --- | --- | --- |
| 1 | Agent 主动连接 Host | `shared_port_routes_by_host` |
| 2 | 注册两个域名 | 同上 |
| 3 | 同端口命中不同本地服务 | 同上（`x-origin` 断言） |
| 4 | 标准/非标准端口 | `gen-nginx` + 手工（端口只是部署参数） |
| 5 | 增删路由不 reload | `disabled_route_is_503_and_delete_is_a_tombstone` |
| 6 | 未注册 Host → 404 | `unknown_host_is_404_and_bad_suffix_too` |
| 7 | Agent 离线 → 503 | `agent_offline_is_503_and_reconnect_restores` |
| 8 | 重连自动恢复 | 同上 |
| 9 | WebSocket | `websocket_upgrade_and_echo` |
| 10 | 大响应/流式不缓冲 | `streaming_response_is_not_buffered`、`large_download_and_upload` |
| 11 | 管理台可见 | 手工 + `requests_are_logged_with_route_and_status` |
| 12 | Token 吊销后无法重连 | `revoked_agent_cannot_reconnect` |
| 13 | 伪造 XFF 不生效 | `deploy/nginx/fairlead.conf`（`$remote_addr` 覆写）+ `origin_sees_connection_close...` |
| 14 | 无 Nginx 也能开发运行 | `fairlead demo` |

## 7. 发布清单

- [ ] 版本号在 `Cargo.toml` 的 `[workspace.package]` 一处修改
- [ ] `docs/ARCHITECTURE.md` 的协议段落与代码一致
- [ ] `CHANGELOG.md` 写清楚破坏性变更
- [ ] tag `vX.Y.Z`，CI 产出 5 个归档 + `SHA256SUMS`
- [ ] 在空目录用二进制跑一次 `fairlead doctor` + `fairlead demo`
- [ ] 回滚脚本在测试机上真的跑过一遍

## 8. 已知风险与对策

| 风险 | 对策 |
| --- | --- |
| Nginx 配置抄错 | `fairlead gen-nginx` 生成 + `fairlead doctor` 检查；文档里标注两行关键配置 |
| macOS 公证 | v0.1 不签名，用户首次运行需 `xattr -d com.apple.quarantine`；v0.2 加 Developer ID + notarize |
| Windows Defender 误报 | v0.1 不签名，文档说明；后续用 EV 证书 |
| musl 下 DNS | `lookup_host` 用 libc `getaddrinfo`，Alpine 需要 `/etc/nsswitch.conf`；文档提示 |
| 单机是单点 | 明确写进 README，不做伪装的高可用 |
