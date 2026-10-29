# Changelog

## v0.1.0 — unreleased

首个可运行版本：单节点、共享端口、按 Host 路由。

- `frplike host|agent|token|passwd|gen-nginx|doctor|demo` 单二进制
- TLS 1.3 + yamux 隧道；每 Agent 2 条物理隧道轮转
- 请求头嗅探（≤16KB），响应原样流式转发；Upgrade 请求逐字节透传
- 404 / 503 / 502 / 504 / 403 语义，数据流 1 字节状态回执
- 路由 = Agent 声明 ∩ 管理员意图（含删除墓碑，重连不复活）
- 一次性 enrollment token → 长期 credential（0600 状态文件）
- 管理台：用户名 + 密码的多账号体系（SQLite，`frplike admin add|passwd|list|disable|rm`），会话存库、改密码即全端下线，按 IP 与用户名双限流
- 管理台默认只绑回环；`admin.allow_remote` 才能监听公网地址，`admin.trust_forwarded_for` 支持放在自有代理之后
- 管理台：登录、账户自助改密、Agent/路由管理、请求日志、审计、链路诊断
- Prometheus `/metrics`、`/healthz`
- 18 条端到端验收测试（含管理台账号/会话/限流）+ 2000 并发流压测
- 五个平台产物：macOS(arm64/x86_64)、Linux(arm64/x86_64 静态 musl)、Windows(x86_64)
- 全平台由 `cargo zigbuild` 单机交叉编译，产物附 `SHA256SUMS`
- 目标安全：默认只允许回环与私网目标
