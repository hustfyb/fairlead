//! Proxy traffic on the one public port.
//!
//! These tests exist because a proxy request looks like a site request: it is
//! HTTP/1.1 with a `Host` header. The difference is that `Host` names the
//! *destination*, so the relay has nothing to look up, and the answer used to
//! be the landing page's 404. What is checked here is that `[proxy] route` gets
//! such a request to the egress route **byte for byte** — `CONNECT` included,
//! which needs no proxy implementation on our side as long as we do not touch
//! the bytes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fairlead_testkit::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

const SUFFIX: &str = "relay.test";
const ADMIN_HOST: &str = "admin.relay.test";
const TUNNEL_HOST: &str = "tunnel.relay.test";
const EGRESS: &str = "muse.relay.test";
/// `base64("user:pass")`, what curl sends for `-x user:pass@host:port`.
const AUTH: &str = "user:pass";
const AUTH_HEADER: &str = "Basic dXNlcjpwYXNz";

// ------------------------------------------------------------------ fixtures

/// A stand-in for the real forward proxy on the agent's machine: it records the
/// request heads it was given, answers `CONNECT` with 200 (then echoes), and
/// answers anything else with the request line it saw.
struct FakeProxy {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
}

impl FakeProxy {
    async fn heads(&self) -> Vec<String> {
        self.heads.lock().await.clone()
    }
}

async fn start_fake_proxy() -> FakeProxy {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake proxy bind");
    let addr = listener.local_addr().unwrap();
    let heads: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = heads.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let heads = recorder.clone();
            tokio::spawn(async move {
                let mut r = BufReader::new(stream);
                loop {
                    let Some(head) = read_head(&mut r).await else {
                        break;
                    };
                    heads.lock().await.push(head.clone());
                    if head.starts_with("CONNECT ") {
                        // A real proxy says "the tunnel is up" and stops caring
                        // about HTTP from here on.
                        if r.get_mut()
                            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                            .await
                            .is_err()
                        {
                            return;
                        }
                        let mut buf = [0u8; 1024];
                        loop {
                            match r.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    if r.get_mut().write_all(&buf[..n]).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    let line = head.lines().next().unwrap_or("").to_string();
                    let body = format!("proxy saw {line}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if r.get_mut().write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    FakeProxy { addr, heads }
}

async fn read_head(r: &mut BufReader<TcpStream>) -> Option<String> {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        match timeout(Duration::from_secs(10), r.read_line(&mut line)).await {
            Ok(Ok(0)) | Err(_) => return None,
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return None,
        }
        if line == "\r\n" || line == "\n" {
            // The blank line belongs to the head: the relay must forward it too.
            head.push_str(&line);
            return Some(head);
        }
        head.push_str(&line);
    }
}

struct Env {
    host: fairlead_host::Host,
    dir: TempDir,
    port: SocketAddr,
    proxy: FakeProxy,
}

/// A proxy on the port that only loopback may use: the simplest configuration
/// that a real single-machine setup would have.
const OPEN: &str = "route = \"muse\"\nallow_from = [\"127.0.0.1\"]\n";

async fn env(proxy_toml: &str) -> Env {
    let dir = TempDir::new("proxy");
    let host = start_unified_host_with_proxy(dir.path(), &[SUFFIX], ADMIN_HOST, TUNNEL_HOST, proxy_toml)
        .await
        .expect("host");
    let port = host.edge_addr();
    Env {
        host,
        dir,
        port,
        proxy: start_fake_proxy().await,
    }
}

impl Env {
    /// One agent that declares the egress route (and nothing else). Keep the
    /// returned fixture alive: dropping it stops the agent.
    async fn egress_agent(&self) -> AgentFixture {
        self.egress_agent_in("egress").await
    }

    /// Each agent needs its own state directory: two fixtures in one directory
    /// would overwrite each other's `agent.toml` and state file.
    async fn egress_agent_in(&self, sub: &str) -> AgentFixture {
        let dir = self.dir.path().join(sub);
        std::fs::create_dir_all(&dir).expect("agent dir");
        let token = create_token(&self.host, SUFFIX).await.expect("token");
        let fixture = start_agent_at(
            &format!("http://{}", self.port),
            Some(TUNNEL_HOST),
            "agent-egress",
            Some(&token),
            &[(EGRESS, self.proxy.addr)],
            &dir,
            1,
            false,
        )
        .await
        .expect("agent");
        wait_routes_active(&self.host, 1).await.expect("route active");
        fixture
    }

    async fn client(&self) -> BufReader<TcpStream> {
        let s = timeout(Duration::from_secs(5), TcpStream::connect(self.port))
            .await
            .unwrap()
            .unwrap();
        BufReader::new(s)
    }
}

async fn send(r: &mut BufReader<TcpStream>, request: &[u8]) {
    r.get_mut().write_all(request).await.unwrap();
    r.get_mut().flush().await.unwrap();
}

/// Status line of the next response, reading the head only.
async fn status_line(r: &mut BufReader<TcpStream>) -> String {
    read_head(r)
        .await
        .expect("response head")
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Head plus `Content-Length` bytes of body.
async fn response(r: &mut BufReader<TcpStream>) -> (String, String) {
    let head = read_head(r).await.expect("response head");
    let len: usize = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l[15..].trim().parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.expect("response body");
    (head, String::from_utf8_lossy(&body).to_string())
}

// --------------------------------------------------------------------- tests

/// The whole point: HTTPS through the relay is just a `CONNECT` that gets
/// forwarded untouched. Nothing here implements CONNECT.
#[tokio::test]
async fn a_connect_request_is_forwarded_untouched() {
    let env = env(&format!("route = \"muse\"\nauth = \"{AUTH}\"\n")).await;
    let _egress = env.egress_agent().await;
    let mut c = env.client().await;

    let connect = format!(
        "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: {AUTH_HEADER}\r\n\r\n"
    );
    send(&mut c, connect.as_bytes()).await;
    assert_eq!(status_line(&mut c).await, "HTTP/1.1 200 Connection established");

    // Everything after the 200 is opaque to the relay: a TLS handshake (here:
    // any bytes at all) has to travel both ways.
    let hello = b"\x16\x03\x01\x00\x05hello";
    c.get_mut().write_all(hello).await.unwrap();
    let mut echoed = vec![0u8; hello.len()];
    timeout(Duration::from_secs(5), c.read_exact(&mut echoed))
        .await
        .expect("echo timed out")
        .expect("echo failed");
    assert_eq!(&echoed, hello, "bytes must survive the round trip unchanged");

    let heads = env.proxy.heads().await;
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert_eq!(
        heads[0], connect,
        "the CONNECT head must reach the egress proxy byte for byte"
    );
}

/// Plain HTTP through the proxy is an absolute-form request, and one client
/// connection carries many of them: the relay must splice, not answer once.
#[tokio::test]
async fn absolute_form_requests_keep_their_connection() {
    let env = env(OPEN).await;
    let _egress = env.egress_agent().await;
    let mut c = env.client().await;

    let first = "GET http://example.test/a?b=1 HTTP/1.1\r\nHost: example.test\r\nProxy-Connection: keep-alive\r\n\r\n";
    send(&mut c, first.as_bytes()).await;
    let (_, body) = response(&mut c).await;
    assert_eq!(body, "proxy saw GET http://example.test/a?b=1 HTTP/1.1");

    let second = "GET http://example.test/second HTTP/1.1\r\nHost: example.test\r\n\r\n";
    send(&mut c, second.as_bytes()).await;
    let (_, body) = response(&mut c).await;
    assert_eq!(body, "proxy saw GET http://example.test/second HTTP/1.1");

    assert_eq!(env.proxy.heads().await, vec![first.to_string(), second.to_string()]);
}

/// Without `[proxy] route` nothing changes: a proxy request is a request for a
/// host we do not publish.
#[tokio::test]
async fn without_a_proxy_route_a_connect_is_still_a_404() {
    let dir = TempDir::new("proxy-off");
    let host = start_unified_host(dir.path(), &[SUFFIX], ADMIN_HOST, TUNNEL_HOST)
        .await
        .expect("host");
    let port = host.edge_addr();
    let proxy = start_fake_proxy().await;

    let mut c = BufReader::new(TcpStream::connect(port).await.unwrap());
    send(
        &mut c,
        b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
    )
    .await;
    let (head, body) = response(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 404 "), "{head}");
    assert!(body.contains("no route"), "{body}");
    assert!(proxy.heads().await.is_empty(), "the origin must never be dialled");
}

/// A published route keeps working while the port is also a proxy.
#[tokio::test]
async fn site_routes_are_unaffected_by_the_proxy_section() {
    let env = env(OPEN).await;
    let _egress = env.egress_agent().await;
    let origin = start_origin("proxy-coexist").await.expect("origin");
    let token = create_token(&env.host, SUFFIX).await.expect("token");
    let site_dir = env.dir.path().join("site");
    std::fs::create_dir_all(&site_dir).expect("site dir");
    let _site = start_agent_at(
        &format!("http://{}", env.port),
        Some(TUNNEL_HOST),
        "agent-site",
        Some(&token),
        &[(format!("a1.{SUFFIX}").as_str(), origin.addr)],
        &site_dir,
        1,
        false,
    )
    .await
    .expect("agent");
    wait_routes_active(&env.host, 2).await.expect("routes");

    let r = http(env.port, &format!("a1.{SUFFIX}"), "GET", "/", None)
        .await
        .expect("site request");
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.text().contains("proxy-coexist"), "{}", r.text());
    assert!(
        env.proxy.heads().await.is_empty(),
        "the proxy must not see site traffic"
    );
}

#[tokio::test]
async fn a_proxy_request_needs_the_configured_credential() {
    let env = env(&format!("route = \"muse\"\nauth = \"{AUTH}\"\n")).await;
    let _egress = env.egress_agent().await;

    // No credential: 407 with a challenge, so a browser or curl asks the user.
    let mut c = env.client().await;
    send(
        &mut c,
        b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
    )
    .await;
    let (head, _) = response(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 407 "), "{head}");
    assert!(
        head.to_ascii_lowercase().contains("proxy-authenticate: basic"),
        "{head}"
    );

    // Wrong secret: still a 407, never a tunnel.
    let mut c = env.client().await;
    send(
        &mut c,
        b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: Basic d3Jvbmc6d3Jvbmc=\r\n\r\n",
    )
    .await;
    assert!(status_line(&mut c).await.starts_with("HTTP/1.1 407 "));
    assert!(env.proxy.heads().await.is_empty());

    // The right one gets through.
    let mut c = env.client().await;
    let ok = format!(
        "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: {AUTH_HEADER}\r\n\r\n"
    );
    send(&mut c, ok.as_bytes()).await;
    assert_eq!(status_line(&mut c).await, "HTTP/1.1 200 Connection established");
    assert_eq!(env.proxy.heads().await.len(), 1);
}

#[tokio::test]
async fn an_address_filter_refuses_other_clients() {
    let env = env("route = \"muse\"\nallow_from = [\"10.9.9.9\"]\n").await;
    let _egress = env.egress_agent().await;

    let mut c = env.client().await;
    send(
        &mut c,
        b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n",
    )
    .await;
    let (head, body) = response(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
    assert!(body.contains("not allowed"), "{body}");
    assert!(env.proxy.heads().await.is_empty());
}

/// The egress route is a route: no agent, no proxy.
#[tokio::test]
async fn a_dead_egress_route_says_so_in_band() {
    let env = env(OPEN).await;
    // A route that exists in the database but no agent declares it.
    let mut c = env.client().await;
    send(
        &mut c,
        b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n",
    )
    .await;
    let (head, body) = response(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 503 "), "{head}");
    assert!(body.contains(EGRESS), "the message should name the route: {body}");
    assert!(env.proxy.heads().await.is_empty());
}
