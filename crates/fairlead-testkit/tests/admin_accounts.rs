//! The single admin: password login (no username), server-side sessions,
//! password rotation, and per-IP login throttling — over real HTTP, no mocks.

use std::net::SocketAddr;

use fairlead_testkit::{
    create_token, read_response, start_agent, start_host, start_host_without_admin_password,
    start_origin, wait_routes_active, TempDir, ADMIN_PASSWORD,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

struct Reply {
    status: u16,
    location: Option<String>,
    cookie: Option<String>,
    body: String,
}

async fn req(addr: SocketAddr, method: &str, path: &str, cookie: Option<&str>, body: Option<&str>) -> Reply {
    let mut s = timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: fairlead-test\r\nAccept: */*\r\n"
    );
    if let Some(c) = cookie {
        head.push_str(&format!("Cookie: fairlead_session={c}\r\n"));
    }
    if let Some(b) = body {
        head.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        head.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    head.push_str("Connection: close\r\n\r\n");
    s.write_all(head.as_bytes()).await.unwrap();
    if let Some(b) = body {
        s.write_all(b.as_bytes()).await.unwrap();
    }
    s.flush().await.unwrap();
    let resp = read_response(&mut s).await.unwrap();
    let location = resp.header("location").map(|s| s.to_string());
    let cookie = resp.header("set-cookie").and_then(|raw| {
        let value = raw
            .split(';')
            .next()?
            .strip_prefix("fairlead_session=")?
            .to_string();
        (!value.is_empty()).then_some(value)
    });
    // Drain the body if read_response stopped at the headers.
    let mut body = resp.text();
    if body.is_empty() {
        let mut rest = Vec::new();
        let _ = timeout(Duration::from_secs(2), s.read_to_end(&mut rest)).await;
        body = String::from_utf8_lossy(&rest).to_string();
    }
    Reply {
        status: resp.status,
        location,
        cookie,
        body,
    }
}

fn form(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn csrf_of(html: &str) -> String {
    let needle = "name=\"_csrf\" value=\"";
    let start = html.find(needle).expect("csrf field") + needle.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("csrf value end");
    rest[..end].to_string()
}

#[tokio::test]
async fn the_password_is_the_whole_credential() {
    let dir = TempDir::new("admin-login");
    let host = start_host(dir.path(), &["relay.test"]).await.unwrap();
    let admin = host.admin_addr();

    let page = req(admin, "GET", "/login", None, None).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("name=\"password\""), "{}", page.body);
    assert!(!page.body.contains("name=\"username\""), "there is no username field");

    // Wrong password: refused, no session, back to the form.
    let r = req(admin, "POST", "/login", None, Some(&form(&[("password", "wrong-password")]))).await;
    assert_eq!(r.status, 303);
    assert_eq!(r.location.as_deref(), Some("/login"));
    assert!(r.cookie.is_none(), "no session on failure");

    // A stray `username` field is ignored rather than required.
    let r = req(
        admin,
        "POST",
        "/login",
        None,
        Some(&form(&[("username", "whatever"), ("password", ADMIN_PASSWORD)])),
    )
    .await;
    assert_eq!(r.location.as_deref(), Some("/"), "unknown fields do not matter");
    let cookie = r.cookie.expect("session cookie");

    let dash = req(admin, "GET", "/", Some(&cookie), None).await;
    assert_eq!(dash.status, 200);
    assert!(dash.body.contains("总览"), "{}", dash.body);

    let account = req(admin, "GET", "/account", Some(&cookie), None).await;
    assert_eq!(account.status, 200);
    assert!(account.body.contains("只有一个密码"), "{}", account.body);

    // No cookie: every page bounces to /login.
    let anon = req(admin, "GET", "/routes", None, None).await;
    assert_eq!(anon.status, 303);
    assert_eq!(anon.location.as_deref(), Some("/login"));
}

#[tokio::test]
async fn without_a_password_the_login_page_says_how_to_set_one() {
    let dir = TempDir::new("admin-empty");
    let host = start_host_without_admin_password(dir.path(), &["relay.test"]).await.unwrap();
    let admin = host.admin_addr();

    let page = req(admin, "GET", "/login", None, None).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("还没有设置管理密码"), "{}", page.body);
    assert!(page.body.contains("FAIRLEAD_ADMIN_PASSWORD"), "{}", page.body);

    // Even the empty password cannot get in while nothing is configured.
    let r = req(admin, "POST", "/login", None, Some(&form(&[("password", "")]))).await;
    assert_eq!(r.status, 303);
    assert_eq!(r.location.as_deref(), Some("/login"));
    assert!(r.cookie.is_none());
}

#[tokio::test]
async fn password_change_signs_out_old_sessions() {
    let dir = TempDir::new("admin-passwd");
    let host = start_host(dir.path(), &["relay.test"]).await.unwrap();
    let admin = host.admin_addr();
    let login = form(&[("password", ADMIN_PASSWORD)]);
    let session = req(admin, "POST", "/login", None, Some(&login))
        .await
        .cookie
        .expect("session cookie");

    let account = req(admin, "GET", "/account", Some(&session), None).await;
    let csrf = csrf_of(&account.body);

    // Wrong current password: nothing changes.
    let bad = form(&[("_csrf", &csrf), ("current", "nope"), ("new_password", "a-longer-secret-1"), ("confirm", "a-longer-secret-1")]);
    let r = req(admin, "POST", "/account/password", Some(&session), Some(&bad)).await;
    assert_eq!(r.status, 303);
    assert_eq!(r.location.as_deref(), Some("/account?e=current"));
    assert!(req(admin, "GET", "/", Some(&session), None).await.status == 200);

    // Mismatched confirmation is refused before any hashing.
    let mismatch = form(&[("_csrf", &csrf), ("current", ADMIN_PASSWORD), ("new_password", "a-longer-secret-1"), ("confirm", "a-longer-secret-2")]);
    let r = req(admin, "POST", "/account/password", Some(&session), Some(&mismatch)).await;
    assert_eq!(r.location.as_deref(), Some("/account?e=match"));

    // Real change: old cookie dies, the response carries a fresh one.
    let good = form(&[("_csrf", &csrf), ("current", ADMIN_PASSWORD), ("new_password", "a-longer-secret-1"), ("confirm", "a-longer-secret-1")]);
    let r = req(admin, "POST", "/account/password", Some(&session), Some(&good)).await;
    assert_eq!(r.status, 303);
    assert_eq!(r.location.as_deref(), Some("/account?ok=password"));
    let fresh = r.cookie.expect("rotated cookie");
    assert_ne!(fresh, session);

    let old = req(admin, "GET", "/account", Some(&session), None).await;
    assert_eq!(old.status, 303, "old session must be dead");
    assert!(req(admin, "GET", "/account", Some(&fresh), None).await.status == 200);

    // Old password no longer works, the new one does.
    let stale = req(admin, "POST", "/login", None, Some(&login)).await;
    assert_eq!(stale.location.as_deref(), Some("/login"));
    let new_login = form(&[("password", "a-longer-secret-1")]);
    let ok = req(admin, "POST", "/login", None, Some(&new_login)).await;
    assert_eq!(ok.location.as_deref(), Some("/"));

    // Signing out every other session keeps the caller in.
    let account = req(admin, "GET", "/account", Some(&fresh), None).await;
    let csrf = csrf_of(&account.body);
    let r = req(
        admin,
        "POST",
        "/account/sessions",
        Some(&fresh),
        Some(&form(&[("_csrf", &csrf)])),
    )
    .await;
    assert_eq!(r.location.as_deref(), Some("/account?ok=sessions"));
    let kept = r.cookie.expect("fresh cookie");
    assert!(req(admin, "GET", "/", Some(&kept), None).await.status == 200);

    // Logout invalidates the current session.
    let account = req(admin, "GET", "/account", Some(&kept), None).await;
    let csrf = csrf_of(&account.body);
    let out = req(
        admin,
        "POST",
        "/logout",
        Some(&kept),
        Some(&form(&[("_csrf", &csrf)])),
    )
    .await;
    assert_eq!(out.status, 303);
    assert_eq!(req(admin, "GET", "/", Some(&kept), None).await.status, 303);
}

#[tokio::test]
async fn repeated_failures_throttle_the_client_address() {
    let dir = TempDir::new("admin-throttle");
    let host = start_host(dir.path(), &["relay.test"]).await.unwrap();
    let admin = host.admin_addr();

    let mut throttled = false;
    for i in 0..14 {
        let r = req(
            admin,
            "POST",
            "/login",
            None,
            Some(&form(&[("password", "wrong-password")])),
        )
        .await;
        if r.status == 200 && r.body.contains("登录过于频繁") {
            throttled = true;
            assert!(i >= 10, "throttled after only {i} failures");
            break;
        }
        assert_eq!(r.status, 303);
    }
    assert!(throttled, "repeated failures must eventually be throttled");
}

#[tokio::test]
async fn a_deleted_route_leaves_the_list_but_can_be_summoned() {
    let dir = TempDir::new("admin-deleted");
    let host = start_host(dir.path(), &["relay.test"]).await.unwrap();
    let admin = host.admin_addr();
    let origin = start_origin("a1").await.unwrap();
    let token = create_token(&host, "relay.test").await.unwrap();
    let _agent = start_agent(
        &host,
        "agent-a",
        Some(&token),
        &[("a1.relay.test", origin.addr)],
        dir.path(),
        1,
        false,
    )
    .await
    .unwrap();
    wait_routes_active(&host, 1).await.unwrap();

    let r = req(admin, "POST", "/login", None, Some(&form(&[("password", ADMIN_PASSWORD)]))).await;
    let cookie = r.cookie.expect("session cookie");

    let page = req(admin, "GET", "/routes", Some(&cookie), None).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("a1.relay.test"), "route is listed before deleting");
    assert!(!page.body.contains("显示已删除"), "no tombstones yet");

    // Delete it through the UI, exactly like an operator clicking 删除.
    let csrf = csrf_of(&page.body);
    let id = host
        .state
        .db
        .routes()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.public_host == "a1.relay.test")
        .expect("route row")
        .id;
    let r = req(
        admin,
        "POST",
        &format!("/routes/{id}/delete"),
        Some(&cookie),
        Some(&form(&[("_csrf", &csrf)])),
    )
    .await;
    assert_eq!(r.status, 303);

    // The tombstone is hidden: no row, no "deleted" badge, but a way back.
    let page = req(admin, "GET", "/routes", Some(&cookie), None).await;
    assert!(!page.body.contains("a1.relay.test"), "deleted route is not listed");
    assert!(!page.body.contains(">deleted<"), "no deleted badge in the list");
    assert!(page.body.contains("显示已删除的 1 条"), "a toggle remains");

    // Asking for them brings the tombstone (and its 恢复 action) back.
    let page = req(admin, "GET", "/routes?deleted=1", Some(&cookie), None).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("a1.relay.test"));
    assert!(page.body.contains("恢复"), "a tombstone can still be restored");
    assert!(page.body.contains("隐藏已删除的 1 条"));

    // The dashboard never shows them, asked or not.
    let dash = req(admin, "GET", "/", Some(&cookie), None).await;
    assert!(!dash.body.contains("a1.relay.test"), "{}", dash.body);
}

/// The freshly minted token: the only run of hex in the "issued" page's
/// `pre.tok` box. This is what an operator copies.
fn minted_token(html: &str) -> String {
    let open = "<pre class=\"tok\">";
    let start = html.find(open).expect("token box") + open.len();
    let rest = &html[start..];
    let end = rest.find("</pre>").expect("token box end");
    rest[..end].trim().to_string()
}

#[tokio::test]
async fn a_token_can_be_issued_from_the_console() {
    let dir = TempDir::new("admin-tokens");
    let host = start_host(dir.path(), &["relay.test"]).await.unwrap();
    let admin = host.admin_addr();

    let r = req(admin, "POST", "/login", None, Some(&form(&[("password", ADMIN_PASSWORD)]))).await;
    let cookie = r.cookie.expect("session cookie");

    // The page is reachable from the nav and explains what a token is for.
    let page = req(admin, "GET", "/tokens", Some(&cookie), None).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("签发一个一次性 token"), "{}", page.body);
    assert!(page.body.contains("还没有签发过 token"));
    let csrf = csrf_of(&page.body);

    // Sign one for *.relay.test, 24h, with a note.
    let r = req(
        admin,
        "POST",
        "/tokens",
        Some(&cookie),
        Some(&form(&[
            ("_csrf", &csrf),
            ("suffix", "relay.test"),
            ("ttl", "86400"),
            ("note", "agent-3"),
        ])),
    )
    .await;
    assert_eq!(r.status, 200, "the token is rendered, not redirected: {}", r.body);
    assert!(r.body.contains("Token 已签发"));
    let token = minted_token(&r.body);
    assert_eq!(token.len(), 64, "a token is 64 hex characters: {token}");
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

    // It enrolls exactly the agent we hand it to.
    let origin = start_origin("t1").await.unwrap();
    let _agent = start_agent(
        &host,
        "agent-t",
        Some(&token),
        &[("t1.relay.test", origin.addr)],
        dir.path(),
        1,
        false,
    )
    .await
    .unwrap();
    wait_routes_active(&host, 1).await.unwrap();

    // The list says it was used, by that agent — and never shows the secret.
    let page = req(admin, "GET", "/tokens", Some(&cookie), None).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("已使用"), "{}", page.body);
    assert!(page.body.contains("agent-t"));
    assert!(page.body.contains("agent-3"), "the note is kept");
    assert!(!page.body.contains(&token[..16]), "the secret is gone for good");

    // A second one goes unused, and can be revoked from the same page.
    let r = req(
        admin,
        "POST",
        "/tokens",
        Some(&cookie),
        Some(&form(&[
            ("_csrf", &csrf),
            ("suffix", "relay.test"),
            ("ttl", "1800"),
            ("note", ""),
        ])),
    )
    .await;
    assert_eq!(r.status, 200);
    let spare = minted_token(&r.body);
    assert_ne!(spare, token);

    let id = host
        .state
        .db
        .tokens()
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.used_at.is_none() && t.revoked_at.is_none())
        .expect("unused token row")
        .id;
    let r = req(
        admin,
        "POST",
        &format!("/tokens/{id}/revoke"),
        Some(&cookie),
        Some(&form(&[("_csrf", &csrf)])),
    )
    .await;
    assert_eq!(r.status, 303);

    let page = req(admin, "GET", "/tokens?r=revoked", Some(&cookie), None).await;
    assert!(page.body.contains("Token 已吊销"), "flash confirms it");
    assert!(page.body.contains("已吊销"), "the row shows it");

    // And the host really refuses it now.
    let out = host.state.db.authenticate(&spare, true, "x", "0.1.0").await.unwrap();
    assert!(format!("{out:?}").contains("revoked"), "revoked token must not enroll: {out:?}");
}

#[tokio::test]
async fn a_token_form_rejects_a_foreign_suffix() {
    let dir = TempDir::new("admin-tokens-bad");
    let host = start_host(dir.path(), &["relay.test"]).await.unwrap();
    let admin = host.admin_addr();
    let r = req(admin, "POST", "/login", None, Some(&form(&[("password", ADMIN_PASSWORD)]))).await;
    let cookie = r.cookie.expect("session cookie");
    let page = req(admin, "GET", "/tokens", Some(&cookie), None).await;
    let csrf = csrf_of(&page.body);
    let r = req(
        admin,
        "POST",
        "/tokens",
        Some(&cookie),
        Some(&form(&[
            ("_csrf", &csrf),
            ("suffix", "someone-else.example"),
            ("ttl", "86400"),
            ("note", ""),
        ])),
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("不在 server.allowed_suffixes"), "{}", r.body);
    assert!(r.body.contains("签发一个一次性 token"), "the form comes back");
    assert!(host.state.db.tokens().await.unwrap().is_empty(), "nothing was written");
}
