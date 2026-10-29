//! Admin accounts: username + password in SQLite, server-side sessions,
//! password rotation, and login throttling — over real HTTP, no mocks.

use std::net::SocketAddr;

use fairlead_testkit::{read_response, start_host, TempDir, ADMIN_PASSWORD, ADMIN_USER};
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
async fn login_requires_the_right_username_and_password() {
    let dir = TempDir::new("admin-login");
    let host = start_host(dir.path(), &["relay.test"]).await.unwrap();
    let admin = host.admin_addr();

    let page = req(admin, "GET", "/login", None, None).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("用户名"), "{}", page.body);

    // Wrong password and unknown user look exactly the same from outside.
    for body in [
        form(&[("username", ADMIN_USER), ("password", "wrong-password")]),
        form(&[("username", "nobody"), ("password", ADMIN_PASSWORD)]),
    ] {
        let r = req(admin, "POST", "/login", None, Some(&body)).await;
        assert_eq!(r.status, 303);
        assert_eq!(r.location.as_deref(), Some("/login"));
        assert!(r.cookie.is_none(), "no session on failure");
    }

    let body = form(&[("username", ADMIN_USER), ("password", ADMIN_PASSWORD)]);
    let r = req(admin, "POST", "/login", None, Some(&body)).await;
    assert_eq!(r.status, 303);
    assert_eq!(r.location.as_deref(), Some("/"));
    let cookie = r.cookie.expect("session cookie");

    let dash = req(admin, "GET", "/", Some(&cookie), None).await;
    assert_eq!(dash.status, 200);
    assert!(dash.body.contains("总览"), "{}", dash.body);

    let account = req(admin, "GET", "/account", Some(&cookie), None).await;
    assert_eq!(account.status, 200);
    assert!(account.body.contains(ADMIN_USER), "{}", account.body);

    // No cookie: every page bounces to /login.
    let anon = req(admin, "GET", "/routes", None, None).await;
    assert_eq!(anon.status, 303);
    assert_eq!(anon.location.as_deref(), Some("/login"));
}

#[tokio::test]
async fn password_change_signs_out_old_sessions() {
    let dir = TempDir::new("admin-passwd");
    let host = start_host(dir.path(), &["relay.test"]).await.unwrap();
    let admin = host.admin_addr();
    let login = form(&[("username", ADMIN_USER), ("password", ADMIN_PASSWORD)]);
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
    let new_login = form(&[("username", ADMIN_USER), ("password", "a-longer-secret-1")]);
    let ok = req(admin, "POST", "/login", None, Some(&new_login)).await;
    assert_eq!(ok.location.as_deref(), Some("/"));

    // Logout invalidates the current session.
    let account = req(admin, "GET", "/account", Some(&fresh), None).await;
    let csrf = csrf_of(&account.body);
    let out = req(
        admin,
        "POST",
        "/logout",
        Some(&fresh),
        Some(&form(&[("_csrf", &csrf)])),
    )
    .await;
    assert_eq!(out.status, 303);
    assert_eq!(req(admin, "GET", "/", Some(&fresh), None).await.status, 303);
}

#[tokio::test]
async fn repeated_failures_throttle_per_username() {
    let dir = TempDir::new("admin-throttle");
    let host = start_host(dir.path(), &["relay.test"]).await.unwrap();
    let admin = host.admin_addr();

    let mut throttled = false;
    for i in 0..8 {
        let r = req(
            admin,
            "POST",
            "/login",
            None,
            Some(&form(&[("username", ADMIN_USER), ("password", "wrong-password")])),
        )
        .await;
        if r.status == 200 && r.body.contains("登录过于频繁") {
            throttled = true;
            assert!(i >= 5, "throttled after {i} failures");
            break;
        }
        assert_eq!(r.status, 303);
    }
    assert!(throttled, "repeated failures must eventually be throttled");
}
