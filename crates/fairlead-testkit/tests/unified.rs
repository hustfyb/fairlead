//! One port, three planes.
//!
//! Everything here talks to a single socket. The only thing that distinguishes
//! the planes is the request: `Host` selects admin or tunnel, and a tunnel
//! request must also carry `Upgrade: fairlead/1`. These tests exist because
//! that merge is exactly the kind of change that quietly makes the admin UI
//! reachable as a site route, or lets a stray `GET` become a tunnel.

use std::net::SocketAddr;
use std::time::Duration;

use fairlead_testkit::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const SUFFIX: &str = "relay.test";
const ADMIN_HOST: &str = "admin.relay.test";
const TUNNEL_HOST: &str = "tunnel.relay.test";

struct Env {
    host: fairlead_host::Host,
    port: SocketAddr,
    origin: Origin,
    dir: TempDir,
}

impl Env {
    fn addr(&self) -> SocketAddr {
        self.port
    }
}

async fn env() -> Env {
    let dir = TempDir::new("unified");
    let host = start_unified_host(dir.path(), &[SUFFIX], ADMIN_HOST, TUNNEL_HOST)
        .await
        .expect("host");
    let port = host.edge_addr();
    assert_eq!(port, host.tunnel_addr(), "unified mode must share one socket");
    assert_eq!(port, host.admin_addr(), "unified mode must share one socket");
    assert!(host.state.unified);
    let origin = start_origin("u1").await.expect("origin");
    Env { host, port, origin, dir }
}

async fn agent(env: &Env, token: &str) -> AgentFixture {
    start_agent_at(
        &format!("http://{}", env.addr()),
        Some(TUNNEL_HOST),
        "agent-u",
        Some(token),
        &[(format!("a1.{SUFFIX}").as_str(), env.origin.addr)],
        env.dir.path(),
        1,
        false,
    )
    .await
    .expect("agent")
}

/// Send raw bytes and read whatever comes back, without assuming a status.
async fn raw(addr: SocketAddr, request: &[u8]) -> String {
    let mut s = timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();
    s.write_all(request).await.unwrap();
    s.flush().await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match timeout(Duration::from_millis(800), s.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 64 * 1024 {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

async fn with_headers(
    addr: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: Option<&str>,
) -> Response {
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("Connection: keep-alive\r\n\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    let mut s = timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    s.flush().await.unwrap();
    read_response(&mut s).await.expect("response")
}

#[tokio::test]
async fn one_port_serves_the_edge_plane_and_404s_unknown_hosts() {
    let env = env().await;
    let token = create_token(&env.host, SUFFIX).await.expect("token");
    let _agent = agent(&env, &token).await;
    wait_routes_active(&env.host, 1).await.expect("routes");

    let ok = http(env.addr(), &format!("a1.{SUFFIX}"), "GET", "/", None)
        .await
        .unwrap();
    assert_eq!(ok.status, 200);
    assert_eq!(ok.header("x-origin"), Some("u1"));
    assert_eq!(ok.header("x-fairlead-error"), None);

    // Same socket, unknown host: still the edge plane's 404.
    let missing = http(env.addr(), &format!("nope.{SUFFIX}"), "GET", "/", None)
        .await
        .unwrap();
    assert_eq!(missing.status, 404);
    assert_eq!(missing.header("x-fairlead-error"), Some("404"));
}

#[tokio::test]
async fn admin_plane_is_selected_by_host_only() {
    let env = env().await;
    let token = create_token(&env.host, SUFFIX).await.expect("token");
    let _agent = agent(&env, &token).await;
    wait_routes_active(&env.host, 1).await.expect("routes");

    let login = http(env.addr(), ADMIN_HOST, "GET", "/login", None)
        .await
        .unwrap();
    assert_eq!(login.status, 200);
    assert!(login.text().contains("fairlead"), "{}", login.text());

    // The admin plane is not a route: a site host gets the origin, not the UI.
    let site = http(env.addr(), &format!("a1.{SUFFIX}"), "GET", "/login", None)
        .await
        .unwrap();
    assert_eq!(site.header("x-origin"), Some("u1"));
    assert!(!site.text().contains("密码"), "admin leaked into a route");

    // ... and an unregistered host does not fall back to the admin plane.
    let other = http(env.addr(), &format!("ghost.{SUFFIX}"), "GET", "/login", None)
        .await
        .unwrap();
    assert_eq!(other.status, 404);
}

#[tokio::test]
async fn the_admin_plane_does_not_upgrade_and_the_tunnel_plane_does_not_browse() {
    let env = env().await;

    // An upgrade aimed at the admin vhost is just a request the admin plane
    // does not serve: never a 101, and never a tunnel.
    let admin = raw(
        env.addr(),
        format!(
            "GET /tunnel HTTP/1.1\r\nHost: {ADMIN_HOST}\r\nUpgrade: fairlead/1\r\nConnection: Upgrade\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(!admin.contains("101"), "admin vhost upgraded: {admin}");
    assert!(!admin.to_ascii_lowercase().contains("upgrade: fairlead/1"), "{admin}");
    assert!(admin.starts_with("HTTP/1.1 4"), "{admin}");

    // A browser (or a scanner) on the tunnel vhost gets a 400, not a tunnel.
    let browse = raw(
        env.addr(),
        format!("GET / HTTP/1.1\r\nHost: {TUNNEL_HOST}\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(browse.starts_with("HTTP/1.1 400"), "{browse}");

    // A body before the upgrade is not an agent either: those bytes would be
    // parsed as yamux frames.
    let body = raw(
        env.addr(),
        format!(
            "POST /tunnel HTTP/1.1\r\nHost: {TUNNEL_HOST}\r\nUpgrade: fairlead/1\r\nConnection: Upgrade\r\nContent-Length: 2\r\n\r\nhi"
        )
        .as_bytes(),
    )
    .await;
    assert!(body.starts_with("HTTP/1.1 400"), "{body}");
}

#[tokio::test]
async fn admin_login_works_through_the_shared_port() {
    let env = env().await;

    let form = format!("password={ADMIN_PASSWORD}");
    let login = with_headers(
        env.addr(),
        ADMIN_HOST,
        "POST",
        "/login",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        Some(&form),
    )
    .await;
    assert_eq!(login.status, 303, "login should redirect: {}", login.text());
    let cookie = login
        .header("set-cookie")
        .expect("session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(cookie.starts_with("fairlead_session="), "{cookie}");

    let dash = with_headers(
        env.addr(),
        ADMIN_HOST,
        "GET",
        "/",
        &[("Cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(dash.status, 200);
    assert!(dash.text().contains("总览") || dash.text().contains("fairlead"), "{}", dash.text());

    // A wrong password is still refused on the shared port.
    let bad = with_headers(
        env.addr(),
        ADMIN_HOST,
        "POST",
        "/login",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        Some("password=nope"),
    )
    .await;
    assert_eq!(bad.status, 303);
    assert!(bad.header("set-cookie").is_none());
}

#[tokio::test]
async fn large_download_and_upload_survive_the_shared_port() {
    let env = env().await;
    let token = create_token(&env.host, SUFFIX).await.expect("token");
    let _agent = agent(&env, &token).await;
    wait_routes_active(&env.host, 1).await.expect("routes");

    let big = http(env.addr(), &format!("a1.{SUFFIX}"), "GET", "/big?n=8388608", None)
        .await
        .unwrap();
    assert_eq!(big.status, 200);
    assert_eq!(big.body.len(), 8 * 1024 * 1024, "truncated download");

    let body = vec![b'z'; 2 * 1024 * 1024];
    let up = http(env.addr(), &format!("a1.{SUFFIX}"), "POST", "/upload", Some(&body))
        .await
        .unwrap();
    assert_eq!(up.status, 200);
    assert!(up.text().contains(&body.len().to_string()), "{}", up.text());
}

/// `admin_listen` takes the admin plane off the shared port. The shared port
/// then carries only site traffic and agents, and a request naming the admin
/// vhost there must not turn into one of them.
#[tokio::test]
async fn the_admin_plane_can_move_to_its_own_port() {
    let dir = TempDir::new("unified-split-admin");
    let host = start_unified_host_with_admin_port(dir.path(), &[SUFFIX], TUNNEL_HOST)
        .await
        .expect("host");
    let edge = host.edge_addr();
    let admin = host.admin_addr();
    assert!(host.state.unified, "the front door is still one port");
    assert!(!host.state.admin_shared, "but the admin plane is not on it");
    assert_ne!(edge, admin);

    let origin = start_origin("u2").await.expect("origin");
    let token = create_token(&host, SUFFIX).await.expect("token");
    let _agent = start_agent_at(
        &format!("http://{edge}"),
        Some(TUNNEL_HOST),
        "agent-v",
        Some(&token),
        &[(format!("a1.{SUFFIX}").as_str(), origin.addr)],
        dir.path(),
        1,
        false,
    )
    .await
    .expect("agent");
    wait_routes_active(&host, 1).await.expect("routes");

    // The site still works on the shared port.
    let site = http(edge, &format!("a1.{SUFFIX}"), "GET", "/", None)
        .await
        .unwrap();
    assert_eq!(site.status, 200);
    assert_eq!(site.header("x-origin"), Some("u2"));

    // The admin vhost on that port is not a route and not the UI.
    let stray = http(edge, ADMIN_HOST, "GET", "/login", None).await.unwrap();
    assert_eq!(stray.status, 404, "{}", stray.text());
    assert_eq!(stray.header("x-fairlead-error"), Some("404"));
    assert!(!stray.text().contains("fairlead"), "admin leaked on the shared port");

    // The admin plane answers on its own port, with the ordinary login flow.
    let login_page = http(admin, ADMIN_HOST, "GET", "/login", None).await.unwrap();
    assert_eq!(login_page.status, 200);
    assert!(login_page.text().contains("fairlead"), "{}", login_page.text());

    let form = format!("password={ADMIN_PASSWORD}");
    let login = with_headers(
        admin,
        ADMIN_HOST,
        "POST",
        "/login",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        Some(&form),
    )
    .await;
    assert_eq!(login.status, 303, "{}", login.text());
    assert!(login
        .header("set-cookie")
        .expect("cookie")
        .starts_with("fairlead_session="));
}
