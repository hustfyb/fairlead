# Changelog

## v0.1.0 — unreleased

首个可运行版本：单节点、共享端口、按 Host 路由。

- `frplike host|agent|token|passwd|gen-nginx|doctor|demo` 单二进制
- TLS 1.3 + yamux 隧道；每 Agent 2 条物理隧道轮转
- 请求头嗅探（≤16KB），响应原样流式转发；Upgrade 请求逐字节透传
- 404 / 503 / 502 / 504 / 403 语义，数据流 1 字节状态回执
- 路由 = Agent 声明 ∩ 管理员意图（含删除墓碑，重连不复活）
- 一次性 enrollment token → 长期 credential（0600 状态文件）
- 管理台：登录、Agent/路由管理、请求日志、审计、链路诊断
- Prometheus `/metrics`、`/healthz`
- 15 条端到端验收测试；Mac / Linux(musl) / Windows 产物
- 目标安全：默认只允许回环与私网目标
