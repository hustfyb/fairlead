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
use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::serve::IncomingStream;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use fairlead_proto::hostname;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::db;
use crate::metrics::{fmt_ts, now_unix};
use crate::registry::RouteStatus;
use crate::HostState;

const SESSION_COOKIE: &str = "fairlead_session";

/// The client address of a connection.
///
/// A newtype rather than a bare `SocketAddr` so both listeners can report one:
/// the split admin listener (a plain `TcpListener`) and the unified front door,
/// which hands `axum::serve` connections it accepted on the shared port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer(pub std::net::SocketAddr);

impl Connected<IncomingStream<'_, tokio::net::TcpListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, tokio::net::TcpListener>) -> Self {
        Peer(*stream.remote_addr())
    }
}

impl Connected<IncomingStream<'_, crate::front::VhostListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, crate::front::VhostListener>) -> Self {
        Peer(*stream.remote_addr())
    }
}

pub struct AdminState {
    host: Arc<HostState>,
    /// Last `last_seen_at` write per session, so a page view does not always
    /// cost a database round-trip.
    touched: Mutex<HashMap<String, Instant>>,
    /// Login throttling, keyed by `ip:<addr>` or `user:<name>`.
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

pub fn router(host: Arc<HostState>) -> Router {
    let state = Arc::new(AdminState {
        host,
        touched: Mutex::new(HashMap::new()),
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
        .route("/tokens", get(tokens_page).post(token_create))
        .route("/tokens/{id}/revoke", post(token_revoke))
        .route("/logs", get(logs_page))
        .route("/audit", get(audit_page))
        .route("/diagnostics", get(diagnostics_page))
        .route("/account", get(account_page))
        .route("/account/password", post(account_password))
        .route("/account/sessions", post(account_sessions))
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

/// `(session id, csrf)` for a valid session cookie. The cookie holds a random
/// secret; the database only ever sees its SHA-256.
async fn session_of(st: &AdminState, headers: &HeaderMap) -> Option<(String, String)> {
    let raw = parse_cookies(headers).get(SESSION_COOKIE)?.clone();
    let sid = db::hash_secret(&raw);
    let row = st.host.db.session_get(&sid).await.ok()??;
    let due = {
        let mut touched = st.touched.lock().unwrap();
        let due = match touched.get(&sid) {
            Some(t) => t.elapsed() > Duration::from_secs(60),
            None => true,
        };
        if due {
            touched.insert(sid.clone(), Instant::now());
        }
        due
    };
    if due {
        st.host.db.session_touch(&sid);
    }
    Some((sid, row.csrf))
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
struct PasswordForm {
    _csrf: String,
    current: String,
    new_password: String,
    confirm: String,
}

const LOGIN_WINDOW: Duration = Duration::from_secs(300);

/// Burned when the username does not exist, so a login attempt costs the same
/// argon2 work either way and cannot be used to enumerate accounts.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$ZnJwbGlrZS1kdW1teS1zYWx0$1s0n5fJ0mQ0k9r6m2y4xW3x8F1G0h9V3o8m0yQ2iK5A";

#[derive(Deserialize)]
struct CsrfForm {
    _csrf: String,
}

fn csrf_ok(form: &CsrfForm, session_csrf: &str, headers: &HeaderMap) -> bool {
    form._csrf == session_csrf && same_origin(headers)
}

// ---------------------------------------------------------------- pages

async fn login_page(State(st): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    if session_of(&st, &headers).await.is_some() {
        return Redirect::to("/").into_response();
    }
    if st.host.db.admin().await.ok().flatten().is_none() {
        return Html(page(
            "未设置密码",
            "<div class=\"card\"><h1>还没有设置管理密码</h1>\
             <p>管理台只有一个账号，而且没有用户名：密码就是全部凭据。两种设置方式——</p>\
             <pre>FAIRLEAD_ADMIN_PASSWORD='至少十个字符' fairlead host --config fairlead-host.toml</pre>\
             <p class=\"muted\">启动时读取；密码与库里一致就不动会话，不一致就改密并让所有会话退出。</p>\
             <p class=\"muted\">也可以直接在主机上写进数据库，不需要重启：</p>\
             <pre>fairlead admin passwd --config fairlead-host.toml</pre></div>",
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
          <label>密码<input type="password" name="password" autofocus autocomplete="current-password" required></label>
          <button type="submit">登录</button>
        </form>
        <p class="muted">没有用户名。改密码在「账户」页，或在主机上跑 <code>fairlead admin passwd</code>。</p></div>"#,
        None,
        false,
    ))
    .into_response()
}

fn session_cookie(value: &str, ttl: Duration, secure: bool) -> String {
    format!(
        "{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        ttl.as_secs(),
        if secure { "; Secure" } else { "" }
    )
}

fn throttled(st: &AdminState, keys: &[String], max: u32) -> bool {
    let mut failures = st.failures.lock().unwrap();
    failures.retain(|_, (_, at)| at.elapsed() < LOGIN_WINDOW);
    keys.iter().any(|k| failures.get(k).map(|(c, _)| *c >= max).unwrap_or(false))
}

fn record_failure(st: &AdminState, keys: &[String]) {
    let mut failures = st.failures.lock().unwrap();
    for key in keys {
        let e = failures.entry(key.clone()).or_insert((0, Instant::now()));
        e.0 += 1;
        e.1 = Instant::now();
    }
}

async fn verify_password(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || match PasswordHash::new(&hash) {
        Ok(h) => Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok(),
        Err(_) => false,
    })
    .await
    .unwrap_or(false)
}

async fn login_submit(
    State(st): State<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    if !same_origin(&headers) {
        return (StatusCode::FORBIDDEN, "cross-origin login").into_response();
    }
    let ip = client_ip(&headers, peer.0, st.host.cfg.admin.trust_forwarded_for);
    let key = format!("ip:{ip}");
    if throttled(&st, &[key.clone()], 10) {
        return Html(page(
            "登录过于频繁",
            "<div class=\"card narrow\"><p>失败次数过多，请 5 分钟后再试。</p></div>",
            None,
            false,
        ))
        .into_response();
    }
    let stored = st.host.db.admin().await.ok().flatten();
    // With no password configured the form is not reachable, but a direct POST
    // still costs one argon2 verification, exactly like a wrong password.
    let hash = stored
        .as_ref()
        .map(|a| a.password_hash.clone())
        .unwrap_or_else(|| DUMMY_HASH.to_string());
    let password_ok = verify_password(form.password.clone(), hash).await;
    if !password_ok || stored.is_none() {
        record_failure(&st, &[key]);
        st.host.db.audit_write("admin", "login_failed", &format!("ip={ip}"));
        return Redirect::to("/login").into_response();
    }
    st.failures.lock().unwrap().remove(&format!("ip:{ip}"));

    let ttl = Duration::from_secs(st.host.cfg.admin.session_ttl_secs.clamp(300, 30 * 86_400));
    let secret = random_hex(32);
    let sid = db::hash_secret(&secret);
    let csrf = random_hex(16);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect::<String>();
    let expires_at = now_unix() as i64 + ttl.as_secs() as i64;
    if let Err(e) = st
        .host
        .db
        .session_create(&sid, &csrf, &ip.to_string(), &user_agent, expires_at)
        .await
    {
        tracing::warn!(error = %e, "create admin session");
        return (StatusCode::INTERNAL_SERVER_ERROR, "session store unavailable").into_response();
    }
    let _ = st.host.db.admin_touch_login().await;
    st.host.db.audit_write("admin", "login_ok", &format!("ip={ip}"));

    let cookie = session_cookie(&secret, ttl, st.host.cfg.admin.secure_cookie);
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
}

async fn logout(State(st): State<Arc<AdminState>>, headers: HeaderMap, Form(form): Form<CsrfForm>) -> Response {
    let Some((sid, csrf)) = session_of(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&form, &csrf, &headers) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    let _ = st.host.db.session_delete(&sid).await;
    st.host.db.audit_write("admin", "logout", "");
    (
        [(header::SET_COOKIE, format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"))],
        Redirect::to("/login"),
    )
        .into_response()
}

async fn dashboard(State(st): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some((_sid, _csrf)) = session_of(&st, &headers).await else {
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
    // Deleted routes are tombstones: they keep the name reserved but are gone
    // from the operator's point of view, so they never reach this table.
    let mut listed = 0usize;
    for (host, r) in routes.iter() {
        if r.status == RouteStatus::Deleted {
            continue;
        }
        if listed == 20 {
            break;
        }
        listed += 1;
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

async fn routes_page(
    State(st): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(q): Query<RoutesQuery>,
) -> Response {
    let Some((_sid, csrf)) = session_of(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let rows = st.host.db.routes().await.unwrap_or_default();
    let table = st.host.registry.routes();
    // Tombstones are hidden by default; `?deleted=1` brings them back so a
    // mistaken delete can still be restored from the UI.
    let show_deleted = matches!(q.deleted.as_deref(), Some("1") | Some("true") | Some(""));
    let deleted_count = rows.iter().filter(|r| r.deleted_at.is_some()).count();
    let toggle = match (deleted_count, show_deleted) {
        (0, _) => String::new(),
        (n, false) => format!(
            "<p class=\"muted tomb\"><a href=\"/routes?deleted=1\">显示已删除的 {n} 条（墓碑）</a></p>"
        ),
        (n, true) => format!(
            "<p class=\"muted tomb\"><a href=\"/routes\">隐藏已删除的 {n} 条（墓碑）</a></p>"
        ),
    };
    let mut body = format!(
        "<h1>路由</h1>{toggle}<table><thead><tr><th>Host</th><th>目标</th><th>Agent</th><th>状态</th><th>操作</th></tr></thead><tbody>"
    );
    let mut rendered = 0usize;
    for row in rows {
        if row.deleted_at.is_some() && !show_deleted {
            continue;
        }
        rendered += 1;
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
    if rendered == 0 {
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
    let Some((_sid, _csrf)) = session_of(&st, &headers).await else {
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
    let Some((_sid, csrf)) = session_of(&st, &headers).await else {
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
    let Some((_sid, csrf)) = session_of(&st, &headers).await else {
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
    body.push_str("<p class=\"muted\">Agent 第一次连上来需要一个一次性 token：<a href=\"/tokens\">签发 Token →</a></p>");
    Html(page("Agent", &body, None, true)).into_response()
}

async fn agent_revoke(
    State(st): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some((_sid, csrf)) = session_of(&st, &headers).await else {
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

#[derive(Deserialize)]
struct TokensQuery {
    r: Option<String>,
}

#[derive(Deserialize)]
struct NewTokenForm {
    _csrf: String,
    suffix: String,
    ttl: String,
    #[serde(default)]
    note: String,
}

/// The four states a token can be in, in the order that matters to an operator:
/// revoked beats used, used beats expired.
fn token_status(t: &db::TokenRow, now: i64) -> &'static str {
    if t.revoked_at.is_some() {
        "revoked"
    } else if t.used_at.is_some() {
        "used"
    } else if t.expires_at.map(|e| e <= now).unwrap_or(false) {
        "expired"
    } else {
        "active"
    }
}

fn token_badge(state: &str) -> &'static str {
    match state {
        "active" => "<span class=\"ok\">可用</span>",
        "used" => "<span class=\"muted\">已使用</span>",
        "expired" => "<span class=\"warn\">已过期</span>",
        _ => "<span class=\"bad\">已吊销</span>",
    }
}

/// `(value, label)` for the TTL picker. The empty value means "never expires".
const TOKEN_TTLS: &[(&str, &str)] = &[
    ("1800", "30 分钟"),
    ("3600", "1 小时"),
    ("86400", "24 小时"),
    ("604800", "7 天"),
    ("", "不过期"),
];

/// What an agent dials: the tunnel vhost on the public port in unified mode,
/// the tunnel listener in the split layout.
fn dial_url(cfg: &crate::config::HostConfig) -> String {
    if cfg.server.unified() {
        let scheme = if cfg.server.public_scheme.eq_ignore_ascii_case("https") { "tls" } else { "http" };
        format!("{scheme}://{}:{}", cfg.server.tunnel_host, cfg.server.public_port)
    } else {
        let host = cfg
            .server
            .allowed_suffixes
            .first()
            .cloned()
            .unwrap_or_else(|| "relay.example.com".into());
        let port = cfg.server.tunnel_listen.rsplit_once(':').map(|(_, p)| p).unwrap_or("9443");
        format!("tls://{host}:{port}")
    }
}

async fn tokens_page(
    State(st): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(q): Query<TokensQuery>,
) -> Response {
    let Some((_sid, csrf)) = session_of(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let rows = st.host.db.tokens().await.unwrap_or_default();
    let now = now_unix() as i64;
    let flash = match q.r.as_deref() {
        Some("revoked") => Some("Token 已吊销。"),
        _ => None,
    };
    let cfg = &st.host.cfg;
    let suffix_options: String = cfg
        .server
        .allowed_suffixes
        .iter()
        .map(|s| format!("<option value=\"{0}\">{0}</option>", esc(s)))
        .collect();
    let ttl_options: String = TOKEN_TTLS
        .iter()
        .map(|(v, label)| {
            let sel = if *v == "86400" { " selected" } else { "" };
            format!("<option value=\"{v}\"{sel}>{label}</option>")
        })
        .collect();

    let form = format!(
        r#"<form method="post" action="/tokens" class="card">
<input type="hidden" name="_csrf" value="{csrf}">
<h2 style="margin-top:0">签发一个一次性 token</h2>
<p class="muted">给一台新 Agent 用一次。它只属于一个后缀，只能注册这个后缀下的主机。</p>
<label>后缀<select name="suffix">{suffix_options}</select></label>
<label>有效期<select name="ttl">{ttl_options}</select></label>
<label>备注<input name="note" placeholder="比如 agent-3 / 机房 A" maxlength="120"></label>
<button type="submit">签发</button>
</form>"#,
        csrf = esc(&csrf),
        suffix_options = suffix_options,
        ttl_options = ttl_options
    );

    let mut body = String::from("<h1>Token</h1>");
    body.push_str(&form);
    body.push_str("<h2>已签发的 token</h2><table><thead><tr><th>创建</th><th>后缀</th><th>备注</th><th>状态</th><th>Agent</th><th>过期</th><th>操作</th></tr></thead><tbody>");
    let mut rendered = 0usize;
    for t in &rows {
        rendered += 1;
        let state = token_status(t, now);
        let used = t
            .used_agent_id
            .as_ref()
            .map(|id| {
                format!(
                    "<a class=\"mono\" href=\"/agents\">{}</a>",
                    esc(t.used_agent_name.as_deref().unwrap_or(&id[..id.len().min(8)]))
                )
            })
            .unwrap_or_else(|| "—".into());
        let action = if state == "active" {
            format!(
                "<form method=\"post\" action=\"/tokens/{}/revoke\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><button class=\"danger\" type=\"submit\">吊销</button></form>",
                esc(&t.id),
                esc(&csrf)
            )
        } else {
            String::new()
        };
        body.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
            esc(&fmt_ts(t.created_at)),
            esc(&t.allowed_suffix),
            esc(t.note.as_deref().unwrap_or("—")),
            token_badge(state),
            used,
            t.expires_at.map(fmt_ts).unwrap_or_else(|| "不过期".into()),
            action
        ));
    }
    if rendered == 0 {
        body.push_str("<tr><td colspan=\"7\" class=\"muted\">还没有签发过 token。</td></tr>");
    }
    body.push_str("</tbody></table>");
    body.push_str("<p class=\"muted\">库里只有 token 的 SHA-256，列表里不会再出现明文；丢了就吊销再签一个。</p>");
    Html(page("Token", &body, flash, true)).into_response()
}

/// Clipboard glue for the token page. `navigator.clipboard` only exists on
/// HTTPS (or localhost) and the console is normally reached over plain HTTP on
/// a LAN address, so fall back to the textarea + `execCommand` trick; if the
/// browser refuses that too, select the text so a ⌘C/ctrl-C still gets it.
const COPY_JS: &str = r#"<script>
function fairleadCopy(el, b) {
  var t = el ? (el.innerText || el.textContent || "") : "";
  var label = b.dataset.label || "复制";
  var ok = function () { b.textContent = "已复制"; setTimeout(function () { b.textContent = label; }, 1400); };
  var fail = function () {
    if (!el) return;
    var r = document.createRange(); r.selectNodeContents(el);
    var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
    b.textContent = "已选中，按 ⌘C";
    setTimeout(function () { b.textContent = label; }, 2600);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(t).then(ok, fail);
    return;
  }
  var a = document.createElement("textarea");
  a.value = t; a.style.position = "fixed"; a.style.top = "-1000px"; a.style.opacity = "0";
  document.body.appendChild(a); a.select();
  var copied = false;
  try { copied = document.execCommand("copy"); } catch (e) { copied = false; }
  document.body.removeChild(a);
  copied ? ok() : fail();
}
document.querySelectorAll("button.copy").forEach(function (b) {
  b.dataset.label = b.textContent;
  b.addEventListener("click", function () { fairleadCopy(document.getElementById(b.dataset.copy), b); });
});
</script>"#;

async fn token_create(
    State(st): State<Arc<AdminState>>,
    headers: HeaderMap,
    Form(form): Form<NewTokenForm>,
) -> Response {
    let Some((_sid, csrf)) = session_of(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(
        &CsrfForm { _csrf: form._csrf.clone() },
        &csrf,
        &headers,
    ) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    let cfg = &st.host.cfg;
    let suffix = match hostname::normalize(&form.suffix) {
        Ok(s) => s,
        Err(e) => return token_error(&st, &csrf, &format!("后缀非法：{e}")).await,
    };
    if !cfg.server.allowed_suffixes.iter().any(|s| s == &suffix) {
        return token_error(&st, &csrf, &format!("{suffix} 不在 server.allowed_suffixes 里")).await;
    }
    let ttl_secs = match form.ttl.as_str() {
        "" => None,
        v => match TOKEN_TTLS.iter().find(|(value, _)| *value == v) {
            Some((value, _)) => Some(value.parse::<u64>().unwrap_or(86400)),
            None => return token_error(&st, &csrf, "有效期不认识").await,
        },
    };
    let note: String = form.note.trim().chars().take(120).collect();
    let (id, token) = match st.host.db.create_token_with_id(&suffix, ttl_secs, &note).await {
        Ok(v) => v,
        Err(e) => return token_error(&st, &csrf, &format!("写库失败：{e}")).await,
    };
    st.host
        .db
        .audit_write("admin", "token_create", &format!("token_id={id} suffix={suffix}"));

    let dial = dial_url(cfg);
    let tunnel_line = if cfg.server.unified() {
        format!("tunnel_host = \"{}\"\n", esc(&cfg.server.tunnel_host))
    } else {
        String::new()
    };
    let mut install = String::new();
    if cfg.landing.dir.is_some() {
        if let Some(lh) = cfg.landing.host.as_deref() {
            let scheme = cfg.server.public_scheme.trim().to_ascii_lowercase();
            install = format!(
                r#"<p>装到一台新机器上，一条命令（token 已经带上）：</p>
<pre id="install">curl -fsSLO {scheme}://{lh}/install.sh && sh install.sh --token {token} --route a1.{suffix}=127.0.0.1:8080</pre>
<button type="button" class="copy" data-copy="install">复制命令</button>"#,
                scheme = esc(&scheme),
                lh = esc(lh),
                token = token,
                suffix = esc(&suffix)
            );
        }
    }
    let snippet = format!(
        r#"server = "{dial}"
{tunnel_line}name = "agent-a"
token = "{token}"
tunnels = 2

[[routes]]
host = "a1.{suffix}"
target = "127.0.0.1:8080""#,
        dial = esc(&dial),
        tunnel_line = tunnel_line,
        token = token,
        suffix = esc(&suffix)
    );
    let mut body = format!(
        r#"<h1>Token 已签发</h1>
<div class="card">
<p>这串 token <b>只显示这一遍</b>。库里只存它的 SHA-256，关掉这个页面就再也拿不到——丢了就吊销再签一个。</p>
<p>只能注册 <code class="mono">*.{suffix}</code> 下的主机{ttl}。</p>
<div class="tokrow"><pre class="tok" id="token">{token}</pre><button type="button" class="copy" data-copy="token">复制 token</button></div>
<p class="muted">离开页面之前把它放进下面那条命令或 <code class="mono">agent.toml</code> 里。</p>
</div>
{install}
<h2>agent.toml（把 token 那一行换成你自己的也行）</h2>
<pre id="snippet">{snippet}</pre>
<button type="button" class="copy" data-copy="snippet">复制 agent.toml</button>
<p><a href="/tokens">← 回到 Token 列表</a></p>"#,
        suffix = esc(&suffix),
        ttl = match ttl_secs {
            Some(s) => format!("，{s} 秒后过期"),
            None => "，不过期".to_string(),
        },
        token = token,
        install = install,
        snippet = esc(&snippet)
    );
    body.push_str(COPY_JS);
    Html(page("Token 已签发", &body, None, true)).into_response()
}

/// Error page for the create form: no token, no redirect, the operator gets to
/// fix the field and try again.
async fn token_error(st: &Arc<AdminState>, csrf: &str, message: &str) -> Response {
    let cfg = &st.host.cfg;
    let suffix_options: String = cfg
        .server
        .allowed_suffixes
        .iter()
        .map(|s| format!("<option value=\"{0}\">{0}</option>", esc(s)))
        .collect();
    let ttl_options: String = TOKEN_TTLS
        .iter()
        .map(|(v, label)| {
            let sel = if *v == "86400" { " selected" } else { "" };
            format!("<option value=\"{v}\"{sel}>{label}</option>")
        })
        .collect();
    let body = format!(
        r#"<h1>Token</h1><p class="bad">{}</p>
<form method="post" action="/tokens" class="card">
<input type="hidden" name="_csrf" value="{}">
<h2 style="margin-top:0">签发一个一次性 token</h2>
<label>后缀<select name="suffix">{}</select></label>
<label>有效期<select name="ttl">{}</select></label>
<label>备注<input name="note" maxlength="120"></label>
<button type="submit">签发</button>
</form>"#,
        esc(message),
        esc(csrf),
        suffix_options,
        ttl_options
    );
    Html(page("Token", &body, None, true)).into_response()
}

async fn token_revoke(
    State(st): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some((_sid, csrf)) = session_of(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&form, &csrf, &headers) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    let ok = st.host.db.revoke_token(&id).await.unwrap_or(false);
    st.host.db.audit_write("admin", "token_revoke", &format!("token_id={id} ok={ok}"));
    Redirect::to("/tokens?r=revoked").into_response()
}

async fn logs_page(State(st): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some((_sid, _csrf)) = session_of(&st, &headers).await else {
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
    let Some((_sid, _csrf)) = session_of(&st, &headers).await else {
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
    let Some((_sid, _csrf)) = session_of(&st, &headers).await else {
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
        let req = format!("GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\nUser-Agent: fairlead-diagnose\r\n\r\n");
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

#[derive(Deserialize)]
struct AccountQuery {
    ok: Option<String>,
    e: Option<String>,
}

#[derive(Deserialize)]
struct RoutesQuery {
    deleted: Option<String>,
}

async fn open_session(st: &AdminState, ip: IpAddr, ua: &str) -> Option<String> {
    let ttl = Duration::from_secs(st.host.cfg.admin.session_ttl_secs.clamp(300, 30 * 86_400));
    let secret = random_hex(32);
    let sid = db::hash_secret(&secret);
    let csrf = random_hex(16);
    let expires_at = now_unix() as i64 + ttl.as_secs() as i64;
    match st.host.db.session_create(&sid, &csrf, &ip.to_string(), ua, expires_at).await {
        Ok(()) => Some(session_cookie(&secret, ttl, st.host.cfg.admin.secure_cookie)),
        Err(e) => {
            tracing::warn!(error = %e, "create admin session");
            None
        }
    }
}

async fn account_page(
    State(st): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(q): Query<AccountQuery>,
) -> Response {
    let Some((_sid, csrf)) = session_of(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let Some(account) = st.host.db.admin().await.ok().flatten() else {
        return Redirect::to("/login").into_response();
    };
    let flash = match (q.ok.as_deref(), q.e.as_deref()) {
        (Some("password"), _) => Some("密码已更新，其他会话已退出。".to_string()),
        (Some("sessions"), _) => Some("其他会话已全部退出。".to_string()),
        (_, Some("current")) => Some("当前密码不正确。".to_string()),
        (_, Some("match")) => Some("两次输入的新密码不一致。".to_string()),
        (_, Some("short")) => Some("新密码至少 10 个字符。".to_string()),
        (_, Some("weak")) => Some("新密码不能与当前密码相同。".to_string()),
        _ => None,
    };
    let last = account.last_login_at.map(fmt_ts).unwrap_or_else(|| "—".into());
    let env_note = if std::env::var_os(crate::ADMIN_PASSWORD_ENV).is_some() {
        format!(
            "<p class=\"muted\">提示：这个进程带着 <code>{}</code> 启动，每次启动都会用它覆盖这里改的密码；要长期保存，请改那个环境变量。</p>",
            crate::ADMIN_PASSWORD_ENV
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<h1>账户</h1>
<div class="card">
  <table class="kv">
    <tr><th>凭据</th><td>只有一个密码，没有用户名</td></tr>
    <tr><th>密码更新时间</th><td>{updated}</td></tr>
    <tr><th>上次登录</th><td>{last}</td></tr>
    <tr><th>会话有效期</th><td>{ttl}s</td></tr>
  </table>
</div>
<h2>修改密码</h2>
<form method="post" action="/account/password" class="card">
  <input type="hidden" name="_csrf" value="{csrf}">
  <label>当前密码<input type="password" name="current" autocomplete="current-password" required></label>
  <label>新密码<input type="password" name="new_password" autocomplete="new-password" minlength="10" required></label>
  <label>再输一次<input type="password" name="confirm" autocomplete="new-password" minlength="10" required></label>
  <button type="submit">更新密码</button>
  <p class="muted">更新后，所有浏览器上的管理会话都会失效，只保留当前这个。</p>
  {env_note}
</form>
<h2>会话</h2>
<div class="card">
  <form method="post" action="/account/sessions">
    <input type="hidden" name="_csrf" value="{csrf}">
    <button type="submit">退出其他所有会话</button>
  </form>
  <form method="post" action="/logout" style="margin-left:12px">
    <input type="hidden" name="_csrf" value="{csrf}">
    <button type="submit">退出登录</button>
  </form>
</div>"#,
        updated = fmt_ts(account.updated_at),
        ttl = st.host.cfg.admin.session_ttl_secs,
    );
    Html(page("账户", &body, flash.as_deref(), true)).into_response()
}

async fn account_password(
    State(st): State<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> Response {
    let Some((_sid, csrf)) = session_of(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&CsrfForm { _csrf: form._csrf.clone() }, &csrf, &headers) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    let Some(account) = st.host.db.admin().await.ok().flatten() else {
        return Redirect::to("/login").into_response();
    };
    if form.new_password.len() < 10 {
        return Redirect::to("/account?e=short").into_response();
    }
    if form.new_password != form.confirm {
        return Redirect::to("/account?e=match").into_response();
    }
    if form.new_password == form.current {
        return Redirect::to("/account?e=weak").into_response();
    }
    if !verify_password(form.current.clone(), account.password_hash.clone()).await {
        st.host.db.audit_write("admin", "password_failed", "wrong current password");
        return Redirect::to("/account?e=current").into_response();
    }
    let ip = client_ip(&headers, peer.0, st.host.cfg.admin.trust_forwarded_for);
    let new_password = form.new_password.clone();
    let hash = tokio::task::spawn_blocking(move || db::hash_password(&new_password))
        .await
        .ok()
        .and_then(|r| r.ok());
    let Some(hash) = hash else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "hash failed").into_response();
    };
    if let Err(e) = st.host.db.admin_set_hash(&hash).await {
        tracing::warn!(error = %e, "store new admin password");
        return (StatusCode::INTERNAL_SERVER_ERROR, "password store unavailable").into_response();
    }
    st.host.db.audit_write("admin", "password_changed", &format!("ip={ip}"));
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let Some(cookie) = open_session(&st, ip, ua).await else {
        return Redirect::to("/login").into_response();
    };
    ([(header::SET_COOKIE, cookie)], Redirect::to("/account?ok=password")).into_response()
}

async fn account_sessions(
    State(st): State<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some((_sid, csrf)) = session_of(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&form, &csrf, &headers) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    let _ = st.host.db.session_delete_all().await;
    st.host.db.audit_write("admin", "sessions_reset", "");
    let ip = client_ip(&headers, peer.0, st.host.cfg.admin.trust_forwarded_for);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let Some(cookie) = open_session(&st, ip, ua).await else {
        return Redirect::to("/login").into_response();
    };
    ([(header::SET_COOKIE, cookie)], Redirect::to("/account?ok=sessions")).into_response()
}

fn client_ip(headers: &HeaderMap, peer: SocketAddr, trust_forwarded_for: bool) -> IpAddr {
    if trust_forwarded_for {
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

fn page(title: &str, body: &str, flash: Option<&str>, nav: bool) -> String {
    let flash_html = flash
        .map(|f| format!("<div class=\"flash\">{}</div>", esc(f)))
        .unwrap_or_default();
    let nav_html = if nav {
        r#"<nav><a href="/">总览</a><a href="/routes">路由</a><a href="/agents">Agent</a><a href="/tokens">Token</a><a href="/logs">日志</a><a href="/audit">审计</a><a href="/diagnostics">诊断</a><a href="/account">账户</a></nav>"#
    } else {
        ""
    };
    format!(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>fairlead · {title}</title>
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
td .ok,td .bad,td .warn,td button{{white-space:nowrap}}
td button,td button[type=submit]{{background:transparent;color:var(--fg);border-color:var(--line);padding:4px 10px}}td button.danger{{color:var(--bad)}}td button:hover{{border-color:var(--accent)}}
form{{display:inline}}form.card{{display:block}}form.card button{{margin-right:8px}}button{{font:inherit;padding:4px 10px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}}button:hover{{border-color:var(--accent)}}button.danger{{color:var(--bad)}}
.actions form{{margin-right:4px}}label{{display:block;margin:12px 0}}input{{display:block;width:100%;margin-top:6px;padding:8px 10px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--fg);font:inherit}}
button[type=submit]{{background:var(--accent);color:#fff;border-color:transparent;padding:8px 14px}}
.steps{{list-style:none;padding:0}}.steps li{{padding:8px 0;border-bottom:1px solid var(--line)}}.flash{{padding:10px 14px;border-radius:8px;background:var(--card);border:1px solid var(--line);margin-bottom:16px}}
.quick{{display:flex;gap:16px;margin-top:24px}}.kv th{{width:160px}}.tomb a{{color:var(--muted);font-size:12px}}
pre{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:color-mix(in srgb,var(--card) 85%,var(--bg));border:1px solid var(--line);border-radius:8px;padding:12px;white-space:pre-wrap;overflow-wrap:anywhere;overflow-x:auto}}
pre.tok{{font-size:15px;font-weight:600;letter-spacing:.02em;color:var(--accent)}}.copy{{margin-top:8px}}.tokrow{{display:flex;gap:12px;align-items:center;flex-wrap:wrap}}.tokrow pre{{flex:1 1 auto;min-width:0;margin:0}}.tokrow .copy{{margin:0}}
select{{display:block;width:100%;margin-top:6px;padding:8px 10px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--fg);font:inherit}}
@media (max-width:620px){{header{{flex-wrap:wrap}}header nav{{flex-wrap:wrap;gap:10px 14px}}header nav a{{white-space:nowrap}}table{{display:block;overflow-x:auto}}td,th{{white-space:nowrap}}}}
</style></head><body>
<header><span class="brand">fairlead</span>{nav_html}</header>
<main>{flash_html}{body}</main>
</body></html>"#,
        title = esc(title),
        nav_html = nav_html,
        flash_html = flash_html,
        body = body
    )
}
