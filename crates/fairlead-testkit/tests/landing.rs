//! The public landing page.
//!
//! Reaching the relay by IP — or on a name that cannot be a route — is what a
//! person does before they have an agent. With `[landing] dir` set that answers
//! with the download page and `install.sh` instead of a bare 404. The tests
//! below pin the boundary: a route always wins, a subdomain with no route is
//! still a 404, and nothing outside the configured directory is downloadable.

use std::net::SocketAddr;

use fairlead_testkit::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SUFFIX: &str = "relay.test";
const ADMIN_HOST: &str = "admin.relay.test";
const TUNNEL_HOST: &str = "tunnel.relay.test";
const ARTIFACT: &str = "fairlead-0.1.0-x86_64-unknown-linux-musl.tar.gz";
const PAYLOAD: &[u8] = b"not really a tarball, but byte-identical on the way out";

struct Env {
    host: fairlead_host::Host,
    port: SocketAddr,
    origin: Origin,
    dir: TempDir,
    /// Kept alive for the whole test: dropping it deletes the artifacts.
    _assets: TempDir,
}

impl Env {
    fn by_ip(&self) -> String {
        format!("127.0.0.1:{}", self.port.port())
    }
}

async fn env() -> Env {
    let dir = TempDir::new("landing");
    let assets = TempDir::new("landing-assets");
    std::fs::write(assets.path().join(ARTIFACT), PAYLOAD).unwrap();
    std::fs::write(
        assets.path().join("SHA256SUMS"),
        format!("{}  {ARTIFACT}\n", "ab".repeat(32)),
    )
    .unwrap();
    let host = start_unified_host_with_landing(
        dir.path(),
        &[SUFFIX],
        ADMIN_HOST,
        TUNNEL_HOST,
        assets.path(),
    )
    .await
    .expect("host");
    let port = host.edge_addr();
    let origin = start_origin("l1").await.expect("origin");
    Env { host, port, origin, dir, _assets: assets }
}

#[tokio::test]
async fn the_bare_ip_gets_the_download_page() {
    let e = env().await;
    let r = http(e.port, &e.by_ip(), "GET", "/", None).await.expect("get /");
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.header("content-type").unwrap().starts_with("text/html"));
    let body = r.text();
    assert!(body.contains(ARTIFACT), "the artifact must be linked");
    assert!(body.contains("Linux · x86_64"), "human-readable target");
    assert!(body.contains("/install.sh"));
    assert!(body.contains(&format!("http://{}/install.sh", e.by_ip())), "commands use the address the client used");
    assert!(!body.contains("@ROWS@") && !body.contains("@BASE@"), "every placeholder is replaced");
}

#[tokio::test]
async fn the_apex_of_a_suffix_is_the_page_and_a_bare_subdomain_is_not() {
    let e = env().await;
    let apex = http(e.port, SUFFIX, "GET", "/", None).await.expect("apex");
    assert_eq!(apex.status, 200);
    assert!(apex.text().contains(ARTIFACT));

    // A route-less subdomain is a typo or a deleted route, never a landing.
    let ghost = http(e.port, &format!("nope.{SUFFIX}"), "GET", "/", None).await.expect("ghost");
    assert_eq!(ghost.status, 404, "{}", ghost.text());
    assert!(ghost.text().contains("no route for this host"));
}

#[tokio::test]
async fn install_sh_carries_this_relay() {
    let e = env().await;
    let r = http(e.port, &e.by_ip(), "GET", "/install.sh", None).await.expect("get script");
    assert_eq!(r.status, 200);
    assert!(r.header("content-type").unwrap().contains("x-shellscript"));
    let script = r.text();
    assert!(script.starts_with("#!/bin/sh"));
    assert!(script.contains(&format!("BASE=\"http://{}\"", e.by_ip())));
    assert!(script.contains(&format!("SUFFIX=\"{SUFFIX}\"")));
    assert!(script.contains(&format!("TUNNEL_HOST=\"{TUNNEL_HOST}\"")));
    assert!(script.contains("SHA256SUMS"));
}

#[tokio::test]
async fn downloads_are_byte_exact_and_stay_inside_the_directory() {
    let e = env().await;
    let r = http(e.port, &e.by_ip(), "GET", &format!("/download/{ARTIFACT}"), None)
        .await
        .expect("download");
    assert_eq!(r.status, 200);
    assert_eq!(r.body, PAYLOAD);
    assert_eq!(r.header("content-length"), Some(PAYLOAD.len().to_string().as_str()));
    assert_eq!(r.header("content-type"), Some("application/gzip"));

    let sums = http(e.port, &e.by_ip(), "GET", "/SHA256SUMS", None).await.expect("sums");
    assert_eq!(sums.status, 200);
    assert!(sums.text().contains(ARTIFACT));

    for path in [
        "/download/",
        "/download/..",
        "/download/../fairlead.db",
        "/download/..%2ffairlead.db",
        "/download/.SHA256SUMS",
        "/etc/passwd",
    ] {
        let r = http(e.port, &e.by_ip(), "GET", path, None).await.expect(path);
        assert_eq!(r.status, 404, "{path} must not be served");
        assert!(!r.text().contains("PRAGMA"), "{path} leaked the database");
    }
}

#[tokio::test]
async fn head_and_wrong_methods() {
    let e = env().await;
    let head = http(e.port, &e.by_ip(), "HEAD", "/", None).await.expect("head");
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty(), "HEAD must not carry a body");
    let len: usize = head.header("content-length").unwrap().parse().unwrap();
    assert!(len > 500, "content-length still describes the page");

    let post = http(e.port, &e.by_ip(), "POST", "/", Some(b"x")).await.expect("post");
    assert_eq!(post.status, 405, "{}", post.text());
}

#[tokio::test]
async fn the_page_never_shadows_a_real_route() {
    let e = env().await;
    let token = create_token(&e.host, SUFFIX).await.expect("token");
    let origin_addr = e.origin.addr;
    let a1 = format!("a1.{SUFFIX}");
    let _agent = start_agent_at(
        &format!("http://{}", e.port),
        Some(TUNNEL_HOST),
        "agent-l",
        Some(&token),
        &[(a1.as_str(), origin_addr)],
        e.dir.path(),
        1,
        false,
    )
    .await
    .expect("agent");
    wait_routes_active(&e.host, 1).await.expect("routes");

    let r = http(e.port, &a1, "GET", "/", None).await.expect("route");
    assert_eq!(r.status, 200);
    assert!(r.text().contains("origin=l1"), "{}", r.text());

    // ... and the landing page did not swallow a 404 that used to be a 404.
    let gone = http(e.port, &format!("gone.{SUFFIX}"), "GET", "/", None).await.expect("gone");
    assert_eq!(gone.status, 404);
}

#[tokio::test]
async fn without_a_landing_directory_an_ip_still_gets_400() {
    let dir = TempDir::new("landing-off");
    let host = start_unified_host(dir.path(), &[SUFFIX], ADMIN_HOST, TUNNEL_HOST)
        .await
        .expect("host");
    let port = host.edge_addr();
    let r = http(port, &format!("127.0.0.1:{}", port.port()), "GET", "/", None)
        .await
        .expect("by ip");
    assert_eq!(r.status, 400);
    assert!(r.text().contains("ip literal"));
}

#[tokio::test]
async fn large_downloads_stream_through_unchanged() {
    let dir = TempDir::new("landing-big");
    let assets = TempDir::new("landing-big-assets");
    let name = "fairlead-0.1.0-aarch64-apple-darwin.tar.gz";
    let blob = vec![0x5au8; 4 * 1024 * 1024];
    std::fs::write(assets.path().join(name), &blob).unwrap();
    let host =
        start_unified_host_with_landing(dir.path(), &[SUFFIX], ADMIN_HOST, TUNNEL_HOST, assets.path())
            .await
            .expect("host");
    let port = host.edge_addr();

    let mut s = TcpStream::connect(port).await.expect("connect");
    let req = format!("GET /download/{name} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", port.port());
    s.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.expect("read");
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(String::from_utf8_lossy(&buf[..head_end]).starts_with("HTTP/1.1 200"));
    assert_eq!(buf.len() - head_end, blob.len());
    assert_eq!(&buf[head_end..head_end + 16], &blob[..16]);
}
