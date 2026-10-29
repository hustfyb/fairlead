//! Admin UI and API: server-rendered HTML, no build step, no JS framework.
//!
//! Bound to loopback by default. Every mutating request needs a session-bound
//! CSRF token *and* a same-origin `Origin` header when one is present.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use frplike_proto::hostname;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::metrics::fmt_ts;
use crate::registry::RouteStatus;
use crate::HostState;

struct Session {
    csrf: String,
    expires: Instant,
}

pub struct AdminState {
    host: Arc<HostState>,
    sessions: Mutex<HashMap<String, Session>>,
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

pub fn router(host: Arc<HostState>) -> Router {
    let state = Arc::new(AdminState {
        host,
        sessions: Mutex::new(HashMap::new()),
        failures: Mutex::new(HashMap::new()),
    });
    Router::new()
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/", get(dashboard))
        .route("/routes", get(routes_page))
        .route("/routes/{id}", get(route_detail))
        .route("/routes/{id}/enable", post(route_enable))
        .route("/routes/{id}/disable", post(route_disable))
        .route("/routes/{id}/delete", post(route_delete))
        .route("/routes/{id}/restore", post(route_restore))
        .route("/agents", get(agents_page))
        .route("/agents/{id}/revoke", post(agent_revoke))
        .route("/logs", get(logs_page))
        .route("/audit", get(audit_page))
        .route("/diagnostics", get(diagnostics_page))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_page))
        .with_state(state)
}

// ---------------------------------------------------------------- auth

fn parse_cookies(headers: &HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for value in headers.get_all(header::COOKIE) {
        if let Ok(s) = value.to_str() {
            for pair in s.split(';') {
                if let Some((k, v)) = pair.trim().split_once('=') {
                    out.insert(k.to_string(), v.to_string());
                }
            }
        }
    }
    out
}

fn session_of(st: &AdminState, headers: &HeaderMap) -> Option<(String, String)> {
    let sid = parse_cookies(headers).get("frplike_session")?.clone();
    let mut sessions = st.sessions.lock().unwrap();
    sessions.retain(|_, s| s.expires > Instant::now());
    let s = sessions.get(&sid)?;
    Some((sid, s.csrf.clone()))
}

fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true; // curl / same-origin navigations without Origin
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    origin
        .split("//")
        .nth(1)
        .map(|o| o.eq_ignore_ascii_case(host))
        .unwrap_or(false)
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

#[derive(Deserialize)]
struct CsrfForm {
    _csrf: String,
}

fn csrf_ok(form: &CsrfForm, session_csrf: &str, headers: &HeaderMap) -> bool {
    form._csrf == session_csrf && same_origin(headers)
}

// ---------------------------------------------------------------- pages

async fn login_page(State(st): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    if session_of(&st, &headers).is_some() {
        return Redirect::to("/").into_response();
    }
    if st.host.cfg.admin.password_hash.is_empty() {
        return Html(page(
            "未配置管理员",
            "<div class=\"card\"><h1>管理员未启用</h1><p>先在主机上运行 <code>frplike passwd</code>，把输出的 argon2 哈希写入配置文件 <code>[admin] password_hash</code>，然后重启 host。</p></div>",
            None,
            false,
        ))
        .into_response();
    }
    Html(page(
        "登录",
        r#"<div class="card narrow">
        <h1>登录</h1>
        <form method="post" action="/login">
          <label>管理员密码<input type="password" name="password" autofocus autocomplete="current-password" required></label>
          <button type="submit">登录</button>
        </form></div>"#,
        None,
        false,
    ))
    .into_response()
}

async fn login_submit(
    State(st): State<Arc<AdminState>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ip = client_ip(&headers);
    {
        let mut failures = st.failures.lock().unwrap();
        failures.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(300));
        if let Some((count, _)) = failures.get(&ip) {
            if *count >= 10 {
                return Html(page("登录过于频繁", "<div class=\"card narrow\"><p>失败次数过多，请 5 分钟后再试。</p></div>", None, false))
                    .into_response();
            }
        }
    }
    if !same_origin(&headers) {
        return (StatusCode::FORBIDDEN, "cross-origin login").into_response();
    }

    let stored = &st.host.cfg.admin.password_hash;
    let ok = match PasswordHash::new(stored) {
        Ok(hash) => Argon2::default()
            .verify_password(form.password.as_bytes(), &hash)
            .is_ok(),
        Err(_) => false,
    };
    if !ok {
        let mut failures = st.failures.lock().unwrap();
        let e = failures.entry(ip).or_insert((0, Instant::now()));
        e.0 += 1;
        let st = st.clone();
        drop(failures);
        st.host.db.audit_write("admin", "login_failed", &format!("ip={ip}"));
        return Redirect::to("/login").into_response();
    }
    st.failures.lock().unwrap().remove(&ip);

    let sid = random_hex(32);
    let csrf = random_hex(16);
    let ttl = Duration::from_secs(st.host.cfg.admin.session_ttl_secs.max(60));
    st.sessions.lock().unwrap().insert(
        sid.clone(),
        Session { csrf, expires: Instant::now() + ttl },
    );
    st.host.db.audit_write("admin", "login_ok", &format!("ip={ip}"));

    let secure = if st.host.cfg.admin.secure_cookie { "; Secure" } else { "" };
    let cookie = format!(
        "frplike_session={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}",
        ttl.as_secs()
    );
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
}

async fn logout(State(st): State<Arc<AdminState>>, headers: HeaderMap, Form(form): Form<CsrfForm>) -> Response {
    let Some((sid, csrf)) = session_of(&st, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&form, &csrf, &headers) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    st.sessions.lock().unwrap().remove(&sid);
    (
        [(header::SET_COOKIE, "frplike_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")],
        Redirect::to("/login"),
    )
        .into_response()
}

async fn dashboard(State(st): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some((_sid, _csrf)) = session_of(&st, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let routes = st.host.registry.routes();
    let agents = st.host.registry.agents();
    let online = agents.online_count();
    let active = routes.active_count();
    let tunnels = agents.tunnel_count();

    let mut agent_rows = String::new();
    for a in agents.iter() {
        agent_rows.push_str(&format!(
            "<tr><td><a href=\"/agents\">{}</a></td><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&a.name),
            esc(&a.id[..a.id.len().min(8)]),
            esc(&a.version),
            if a.is_online() { "<span class=\"ok\">在线</span>" } else { "<span class=\"bad\">离线</span>" },
            a.tunnels.len()
        ));
    }
    if agent_rows.is_empty() {
        agent_rows.push_str("<tr><td colspan=\"5\" class=\"muted\">还没有 Agent 连接。</td></tr>");
    }

    let mut route_rows = String::new();
    for (host, r) in routes.iter().take(20) {
        route_rows.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
            esc(host),
            esc(&r.target),
            status_badge(r.status)
        ));
    }
    if route_rows.is_empty() {
        route_rows.push_str("<tr><td colspan=\"3\" class=\"muted\">还没有路由。</td></tr>");
    }

    let body = format!(
        r#"<div class="grid">
  <div class="card"><div class="muted">在线 Agent</div><div class="big">{online}</div></div>
  <div class="card"><div class="muted">生效路由</div><div class="big">{active}</div></div>
  <div class="card"><div class="muted">隧道</div><div class="big">{tunnels}</div></div>
  <div class="card"><div class="muted">累计请求</div><div class="big">{requests}</div></div>
</div>
<h2>Agent</h2><table><thead><tr><th>名称</th><th>ID</th><th>版本</th><th>状态</th><th>隧道</th></tr></thead><tbody>{agent_rows}</tbody></table>
<h2>路由 <a class="more" href="/routes">全部</a></h2><table><thead><tr><th>Host</th><th>目标</th><th>状态</th></tr></thead><tbody>{route_rows}</tbody></table>
<nav class="quick"><a href="/logs">请求日志</a><a href="/audit">审计日志</a><a href="/diagnostics">链路诊断</a></nav>"#,
        online = online,
        active = active,
        tunnels = tunnels,
        requests = st.host.metrics().requests.load(Ordering::Relaxed),
        agent_rows = agent_rows,
        route_rows = route_rows
    );
    Html(page("总览", &body, None, true)).into_response()
}

async fn routes_page(State(st): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some((_sid, csrf)) = session_of(&st, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let rows = st.host.db.routes().await.unwrap_or_default();
    let table = st.host.registry.routes();
    let mut body = String::from("<h1>路由</h1><table><thead><tr><th>Host</th><th>目标</th><th>Agent</th><th>状态</th><th>操作</th></tr></thead><tbody>");
    for row in rows {
        let status = table
            .get(&row.public_host)
            .map(|r| r.status)
            .unwrap_or(RouteStatus::Disabled);
        let mut actions = String::new();
        if row.deleted_at.is_some() {
            actions.push_str(&action_form(&row.id, "restore", "恢复", &csrf));
        } else if row.enabled {
            actions.push_str(&action_form(&row.id, "disable", "停用", &csrf));
        } else {
            actions.push_str(&action_form(&row.id, "enable", "启用", &csrf));
        }
        if row.deleted_at.is_none() {
            actions.push_str(&action_form(&row.id, "delete", "删除", &csrf));
        }
        body.push_str(&format!(
            "<tr><td class=\"mono\"><a href=\"/routes/{id}\">{host}</a></td><td class=\"mono\">{target}</td><td class=\"mono\">{agent}</td><td>{status}{deleted}</td><td class=\"actions\">{actions}</td></tr>",
            id = esc(&row.id),
            host = esc(&row.public_host),
            target = esc(&row.target),
            agent = esc(&row.agent_id[..row.agent_id.len().min(8)]),
            status = status_badge(status),
            deleted = if row.deleted_at.is_some() { "<div class=\"muted\">已删除（墓碑）</div>" } else { "" },
            actions = actions
        ));
    }
    if table.is_empty() {
        body.push_str("<tr><td colspan=\"5\" class=\"muted\">还没有路由。启动一个 Agent 并声明 [[routes]]。</td></tr>");
    }
    body.push_str("</tbody></table>");
    Html(page("路由", &body, None, true)).into_response()
}

async fn route_detail(
    State(st): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some((_sid, _csrf)) = session_of(&st, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let rows = st.host.db.routes().await.unwrap_or_default();
    let Some(row) = rows.into_iter().find(|r| r.id == id) else {
        return (StatusCode::NOT_FOUND, "route not found").into_response();
    };
    let logs = st.host.db.recent_logs(200).await.unwrap_or_default();
    let mut log_rows = String::new();
    for l in logs.iter().filter(|l| l.route_id.as_deref() == Some(&id)).take(30) {
        log_rows.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td></tr>",
            esc(&fmt_ts(l.ts)),
            l.status,
            esc(l.error.as_deref().unwrap_or("")),
            l.bytes_up,
            l.bytes_down
        ));
    }
    let body = format!(
        r#"<h1 class="mono">{host}</h1>
<table class="kv">
<tr><th>Route ID</th><td class="mono">{id}</td></tr>
<tr><th>目标</th><td class="mono">{target}</td></tr>
<tr><th>Agent</th><td class="mono">{agent}</td></tr>
<tr><th>管理员启用</th><td>{enabled}</td></tr>
<tr><th>删除时间</th><td>{deleted}</td></tr>
<tr><th>更新时间</th><td>{updated}</td></tr>
</table>
<p><a href="/diagnostics?host={host}">运行链路诊断 →</a></p>
<h2>最近请求</h2>
<table><thead><tr><th>时间</th><th>状态</th><th>错误</th><th>上行</th><th>下行</th></tr></thead><tbody>{log_rows}</tbody></table>
"#,
        host = esc(&row.public_host),
        id = esc(&row.id),
        target = esc(&row.target),
        agent = esc(&row.agent_id),
        enabled = if row.enabled { "是" } else { "否" },
        deleted = row.deleted_at.map(fmt_ts).unwrap_or_else(|| "—".into()),
        updated = fmt_ts(row.updated_at),
        log_rows = if log_rows.is_empty() { "<tr><td colspan=\"5\" class=\"muted\">暂无</td></tr>".into() } else { log_rows }
    );
    Html(page("路由详情", &body, None, true)).into_response()
}

fn action_form(id: &str, action: &str, label: &str, csrf: &str) -> String {
    format!(
        "<form method=\"post\" action=\"/routes/{id}/{action}\"><input type=\"hidden\" name=\"_csrf\" value=\"{csrf}\"><button type=\"submit\">{label}</button></form>",
        id = esc(id),
        action = action,
        label = label,
        csrf = esc(csrf)
    )
}

async fn route_enable(State(st): State<Arc<AdminState>>, headers: HeaderMap, Path(id): Path<String>, Form(form): Form<CsrfForm>) -> Response {
    route_action(st, headers, id, form, "enable", |db, id| Box::pin(async move { db.set_route_enabled(&id, true).await })).await
}

async fn route_disable(State(st): State<Arc<AdminState>>, headers: HeaderMap, Path(id): Path<String>, Form(form): Form<CsrfForm>) -> Response {
    route_action(st, headers, id, form, "disable", |db, id| Box::pin(async move { db.set_route_enabled(&id, false).await })).await
}

async fn route_delete(State(st): State<Arc<AdminState>>, headers: HeaderMap, Path(id): Path<String>, Form(form): Form<CsrfForm>) -> Response {
    route_action(st, headers, id, form, "delete", |db, id| Box::pin(async move { db.delete_route(&id).await })).await
}

async fn route_restore(State(st): State<Arc<AdminState>>, headers: HeaderMap, Path(id): Path<String>, Form(form): Form<CsrfForm>) -> Response {
    route_action(st, headers, id, form, "restore", |db, id| Box::pin(async move { db.restore_route(&id).await })).await
}

async fn route_action<F>(
    st: Arc<AdminState>,
    headers: HeaderMap,
    id: String,
    form: CsrfForm,
    action: &str,
    f: F,
) -> Response
where
    F: for<'a> FnOnce(
        &'a crate::db::Db,
        String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<bool>> + Send + 'a>,
    >,
{
    let Some((_sid, csrf)) = session_of(&st, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&form, &csrf, &headers) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    let result = f(&st.host.db, id.clone()).await;
    st.host.db.audit_write("admin", &format!("route_{action}"), &format!("route_id={id} ok={result:?}"));
    let _ = st.host.registry.publish().await;
    Redirect::to("/routes").into_response()
}

async fn agents_page(State(st): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some((_sid, csrf)) = session_of(&st, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let rows = st.host.db.agents().await.unwrap_or_default();
    let live = st.host.registry.agents();
    let mut body = String::from("<h1>Agent</h1><table><thead><tr><th>名称</th><th>ID</th><th>版本</th><th>状态</th><th>隧道</th><th>最后心跳</th><th>操作</th></tr></thead><tbody>");
    for a in rows {
        let view = live.get(&a.id);
        let status = if a.status == "revoked" {
            "<span class=\"bad\">已吊销</span>".to_string()
        } else if view.map(|v| v.is_online()).unwrap_or(false) {
            "<span class=\"ok\">在线</span>".to_string()
        } else {
            "<span class=\"muted\">离线</span>".to_string()
        };
        body.push_str(&format!(
            "<tr><td>{name}</td><td class=\"mono\">{id}</td><td>{ver}</td><td>{status}</td><td>{tunnels}</td><td class=\"mono\">{seen}</td><td>{action}</td></tr>",
            name = esc(&a.name),
            id = esc(&a.id),
            ver = esc(&a.version),
            tunnels = view.map(|v| v.tunnels.len()).unwrap_or(0),
            seen = a.last_seen_at.map(fmt_ts).unwrap_or_else(|| "—".into()),
            action = if a.status == "revoked" {
                String::new()
            } else {
                format!(
                    "<form method=\"post\" action=\"/agents/{id}/revoke\"><input type=\"hidden\" name=\"_csrf\" value=\"{csrf}\"><button class=\"danger\" type=\"submit\">吊销</button></form>",
                    id = esc(&a.id),
                    csrf = esc(&csrf)
                )
            }
        ));
    }
    body.push_str("</tbody></table><p class=\"muted\">吊销会立即断开该 Agent 的所有隧道，并使其凭据永久失效。</p>");
    Html(page("Agent", &body, None, true)).into_response()
}

async fn agent_revoke(
    State(st): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some((_sid, csrf)) = session_of(&st, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&form, &csrf, &headers) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    let _ = st.host.db.revoke_agent(&id).await;
    st.host.registry.disconnect_agent(&id).await;
    let _ = st.host.registry.publish().await;
    st.host.db.audit_write("admin", "agent_revoke", &format!("agent_id={id}"));
    Redirect::to("/agents").into_response()
}

async fn logs_page(State(st): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some((_sid, _csrf)) = session_of(&st, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let logs = st.host.db.recent_logs(100).await.unwrap_or_default();
    let mut rows = String::new();
    for l in &logs {
        let cls = if l.status >= 500 {
            "bad"
        } else if l.status >= 400 {
            "warn"
        } else {
            "ok"
        };
        rows.push_str(&format!(
            "<tr><td class=\"mono\">{ts}</td><td class=\"mono\">{rid}</td><td class=\"mono\">{host}</td><td class=\"{cls}\">{status}</td><td>{dur} ms</td><td class=\"mono\">{up}</td><td class=\"mono\">{down}</td><td>{err}</td></tr>",
            ts = esc(&fmt_ts(l.ts)),
            rid = esc(&l.request_id),
            host = esc(l.host.as_deref().unwrap_or("—")),
            status = l.status,
            dur = l.duration_ms,
            up = l.bytes_up,
            down = l.bytes_down,
            err = esc(l.error.as_deref().unwrap_or(""))
        ));
    }
    let body = format!(
        "<h1>请求日志</h1><p class=\"muted\">最近 100 条，按时间倒序。完整的 request id 可以拿去 grep Nginx 日志。</p><table><thead><tr><th>时间</th><th>请求 ID</th><th>Host</th><th>状态</th><th>耗时</th><th>上行</th><th>下行</th><th>错误</th></tr></thead><tbody>{rows}</tbody></table>"
    );
    Html(page("请求日志", &body, None, true)).into_response()
}

async fn audit_page(State(st): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some((_sid, _csrf)) = session_of(&st, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let rows = st.host.db.audit(100).await.unwrap_or_default();
    let mut body = String::from("<h1>审计日志</h1><table><thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>详情</th></tr></thead><tbody>");
    for r in rows {
        body.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td></tr>",
            esc(&fmt_ts(r.ts)),
            esc(&r.actor),
            esc(&r.action),
            esc(r.detail.as_deref().unwrap_or(""))
        ));
    }
    body.push_str("</tbody></table>");
    Html(page("审计日志", &body, None, true)).into_response()
}

#[derive(Deserialize)]
struct DiagQuery {
    host: Option<String>,
}

async fn diagnostics_page(
    State(st): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(q): Query<DiagQuery>,
) -> Response {
    let Some((_sid, _csrf)) = session_of(&st, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let Some(raw) = q.host.filter(|h| !h.trim().is_empty()) else {
        return Html(page(
            "链路诊断",
            r#"<h1>链路诊断</h1><form method="get" action="/diagnostics"><label>Host<input name="host" placeholder="a1.relay.example.com" required></label><button type="submit">检查</button></form>"#,
            None,
            true,
        ))
        .into_response();
    };
    let host = match hostname::normalize(&raw) {
        Ok(h) => h,
        Err(e) => {
            return Html(page("链路诊断", &format!("<p class=\"bad\">Host 非法：{}</p>", esc(&e.to_string())), None, true))
                .into_response()
        }
    };

    let table = st.host.registry.routes();
    let agents = st.host.registry.agents();
    let mut steps: Vec<(bool, String)> = Vec::new();
    let route = table.get(&host).cloned();
    steps.push((route.is_some(), format!("路由存在：{}", if route.is_some() { "是" } else { "否（404）" })));
    if let Some(r) = &route {
        steps.push((
            r.status == RouteStatus::Active,
            format!("路由状态：{}", r.status.as_str()),
        ));
        let agent = agents.get(&r.agent_id);
        steps.push((
            agent.map(|a| a.is_online()).unwrap_or(false),
            format!(
                "Agent 在线：{}（隧道 {} 条）",
                if agent.map(|a| a.is_online()).unwrap_or(false) { "是" } else { "否（503）" },
                agent.map(|a| a.tunnels.len()).unwrap_or(0)
            ),
        ));
    }

    // End-to-end probe through the real edge path.
    let probe = probe_edge(&st.host, &host).await;
    steps.push((probe.0, probe.1));

    let mut html = format!("<h1>链路诊断</h1><p class=\"mono\">{}</p><ul class=\"steps\">", esc(&host));
    for (ok, text) in &steps {
        html.push_str(&format!(
            "<li><span class=\"{}\">{}</span> {}</li>",
            if *ok { "ok" } else { "bad" },
            if *ok { "✓" } else { "✗" },
            esc(text)
        ));
    }
    html.push_str("</ul><p class=\"muted\">最后一步会通过 Edge 真实发送一次 <code>GET /</code>，可能触发目标服务的业务逻辑。</p>");
    Html(page("链路诊断", &html, None, true)).into_response()
}

async fn probe_edge(host: &Arc<HostState>, name: &str) -> (bool, String) {
    let addr: SocketAddr = host.edge_addr;
    let fut = async {
        let mut s = TcpStream::connect(addr).await?;
        let req = format!("GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\nUser-Agent: frplike-diagnose\r\n\r\n");
        s.write_all(req.as_bytes()).await?;
        let mut buf = vec![0u8; 32];
        let n = s.read(&mut buf).await?;
        let line = String::from_utf8_lossy(&buf[..n]).to_string();
        let code = line.split(' ').nth(1).and_then(|c| c.parse::<u16>().ok());
        Ok::<_, std::io::Error>((code, line.lines().next().unwrap_or("").to_string()))
    };
    match timeout(Duration::from_secs(5), fut).await {
        Ok(Ok((Some(code), line))) => {
            let ok = code < 500;
            (ok, format!("端到端：{}（{}）", code, line.trim()))
        }
        Ok(Ok((None, line))) => (false, format!("端到端：无法解析响应（{line}）")),
        Ok(Err(e)) => (false, format!("端到端：连接 Edge 失败：{e}")),
        Err(_) => (false, "端到端：5 秒超时".into()),
    }
}

async fn healthz(State(st): State<Arc<AdminState>>) -> Response {
    let db_ok = st.host.db.agents().await.is_ok();
    let routes = st.host.registry.routes();
    let agents = st.host.registry.agents();
    let body = format!(
        "{{\"status\":\"{}\",\"db\":{},\"agents_online\":{},\"tunnels\":{},\"routes_total\":{},\"routes_active\":{},\"dropped_logs\":{}}}",
        if db_ok { "ok" } else { "degraded" },
        db_ok,
        agents.online_count(),
        agents.tunnel_count(),
        routes.len(),
        routes.active_count(),
        st.host.db.dropped_logs()
    );
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

async fn metrics_page(State(st): State<Arc<AdminState>>) -> Response {
    let routes = st.host.registry.routes();
    let agents = st.host.registry.agents();
    let body = st
        .host
        .metrics()
        .render(agents.online_count(), routes.active_count());
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

// ---------------------------------------------------------------- html

fn status_badge(s: RouteStatus) -> String {
    match s {
        RouteStatus::Active => "<span class=\"ok\">active</span>".into(),
        RouteStatus::Offline => "<span class=\"warn\">offline</span>".into(),
        RouteStatus::Disabled => "<span class=\"muted\">disabled</span>".into(),
        RouteStatus::Deleted => "<span class=\"bad\">deleted</span>".into(),
    }
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn client_ip(headers: &HeaderMap) -> IpAddr {
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

fn page(title: &str, body: &str, flash: Option<&str>, nav: bool) -> String {
    let flash_html = flash
        .map(|f| format!("<div class=\"flash\">{}</div>", esc(f)))
        .unwrap_or_default();
    let nav_html = if nav {
        r#"<nav><a href="/">总览</a><a href="/routes">路由</a><a href="/agents">Agent</a><a href="/logs">日志</a><a href="/audit">审计</a><a href="/diagnostics">诊断</a></nav>"#
    } else {
        ""
    };
    format!(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>frplike · {title}</title>
<style>
:root{{--bg:#f6f7f9;--fg:#16181d;--muted:#6b7280;--card:#fff;--line:#e5e7eb;--ok:#067647;--bad:#b42318;--warn:#b54708;--accent:#1d4ed8}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0e1014;--fg:#e6e8ec;--muted:#8b93a1;--card:#161a21;--line:#242a34;--ok:#4ade80;--bad:#f87171;--warn:#fbbf24;--accent:#7aa2ff}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif}}
header{{display:flex;align-items:center;gap:20px;padding:12px 24px;border-bottom:1px solid var(--line);background:var(--card)}}
header .brand{{font-weight:700;letter-spacing:-.02em}}header nav{{display:flex;gap:14px;flex:1}}header nav a{{color:var(--muted);text-decoration:none}}header nav a:hover{{color:var(--fg)}}
main{{max-width:1040px;margin:0 auto;padding:24px}}h1{{font-size:20px;margin:0 0 16px}}h2{{font-size:15px;margin:28px 0 10px;color:var(--muted);font-weight:600}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}}.narrow{{max-width:380px;margin:60px auto}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}}.big{{font-size:26px;font-weight:700;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:middle}}th{{font-size:12px;color:var(--muted);font-weight:600;background:color-mix(in srgb,var(--card) 88%,var(--bg))}}
tr:last-child td{{border-bottom:none}}a{{color:var(--accent)}}.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}}
.ok{{color:var(--ok)}}.bad{{color:var(--bad)}}.warn{{color:var(--warn)}}.muted{{color:var(--muted)}}
form{{display:inline}}button{{font:inherit;padding:4px 10px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}}button:hover{{border-color:var(--accent)}}button.danger{{color:var(--bad)}}
.actions form{{margin-right:4px}}label{{display:block;margin:12px 0}}input{{display:block;width:100%;margin-top:6px;padding:8px 10px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--fg);font:inherit}}
button[type=submit]{{background:var(--accent);color:#fff;border-color:transparent;padding:8px 14px}}
.steps{{list-style:none;padding:0}}.steps li{{padding:8px 0;border-bottom:1px solid var(--line)}}.flash{{padding:10px 14px;border-radius:8px;background:var(--card);border:1px solid var(--line);margin-bottom:16px}}
.quick{{display:flex;gap:16px;margin-top:24px}}.kv th{{width:160px}}
</style></head><body>
<header><span class="brand">frplike</span>{nav_html}</header>
<main>{flash_html}{body}</main>
</body></html>"#,
        title = esc(title),
        nav_html = nav_html,
        flash_html = flash_html,
        body = body
    )
}
