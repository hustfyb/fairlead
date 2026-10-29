//! End-to-end acceptance tests: real host, real agent, real TLS/yamux, real
//! origins. Each test runs on its own ephemeral ports and database.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use frplike_testkit::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

struct Env {
    host: frplike_host::Host,
    dir: TempDir,
    origin_a: Origin,
    origin_b: Origin,
}

async fn env() -> Env {
    let dir = TempDir::new("acc");
    let host = start_host(dir.path(), &["relay.test"]).await.expect("host");
    let origin_a = start_origin("a1").await.expect("origin a");
    let origin_b = start_origin("a2").await.expect("origin b");
    Env { host, dir, origin_a, origin_b }
}

impl Env {
    fn edge(&self) -> SocketAddr {
        self.host.edge_addr()
    }
}

async fn enroll(env: &Env) -> String {
    create_token(&env.host, "relay.test").await.expect("token")
}

async fn agent_two_routes(env: &Env, token: &str) -> AgentFixture {
    start_agent(
        &env.host,
        "agent-a",
        Some(token),
        &[
            ("a1.relay.test", env.origin_a.addr),
            ("a2.relay.test", env.origin_b.addr),
        ],
        env.dir.path(),
        2,
        false,
    )
    .await
    .expect("agent")
}

// ------------------------------------------------------------------ routing

#[tokio::test]
async fn shared_port_routes_by_host() {
    let env = env().await;
    let token = enroll(&env).await;
    let _agent = agent_two_routes(&env, &token).await;
    wait_routes_active(&env.host, 2).await.unwrap();

    let r1 = http(env.edge(), "a1.relay.test", "GET", "/", None).await.unwrap();
    assert_eq!(r1.status, 200);
    assert_eq!(r1.header("x-origin"), Some("a1"));

    let r2 = http(env.edge(), "a2.relay.test", "GET", "/", None).await.unwrap();
    assert_eq!(r2.status, 200);
    assert_eq!(r2.header("x-origin"), Some("a2"));
}

#[tokio::test]
async fn unknown_host_is_404_and_bad_suffix_too() {
    let env = env().await;
    let token = enroll(&env).await;
    let _agent = agent_two_routes(&env, &token).await;
    wait_routes_active(&env.host, 2).await.unwrap();

    let r = http(env.edge(), "nope.relay.test", "GET", "/", None).await.unwrap();
    assert_eq!(r.status, 404);

    let r = http(env.edge(), "a1.example.com", "GET", "/", None).await.unwrap();
    assert_eq!(r.status, 404);
}

#[tokio::test]
async fn malformed_and_oversized_requests_are_rejected() {
    let env = env().await;

    // Missing Host.
    let mut s = TcpStream::connect(env.edge()).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let r = read_response(&mut s).await.unwrap();
    assert_eq!(r.status, 400);

    // Oversized head: 20 KiB of header.
    let mut s = TcpStream::connect(env.edge()).await.unwrap();
    let mut req = b"GET / HTTP/1.1\r\nHost: a1.relay.test\r\nX: ".to_vec();
    req.extend(std::iter::repeat(b'a').take(20 * 1024));
    req.extend_from_slice(b"\r\n\r\n");
    s.write_all(&req).await.ok();
    let r = read_response(&mut s).await.unwrap();
    assert_eq!(r.status, 431);
}

#[tokio::test]
async fn origin_sees_connection_close_but_upgrades_stay_verbatim() {
    let env = env().await;
    let token = enroll(&env).await;
    let _agent = agent_two_routes(&env, &token).await;
    wait_routes_active(&env.host, 2).await.unwrap();

    let r = http(env.edge(), "a1.relay.test", "GET", "/echo", None).await.unwrap();
    let echoed = r.text().to_ascii_lowercase();
    assert!(echoed.contains("connection: close"), "origin did not see close:\n{echoed}");
    assert!(!echoed.contains("keep-alive"), "keep-alive leaked:\n{echoed}");
}

// ------------------------------------------------------------------ failures

#[tokio::test]
async fn agent_offline_is_503_and_reconnect_restores() {
    let env = env().await;
    let token = enroll(&env).await;
    let agent = agent_two_routes(&env, &token).await;
    wait_routes_active(&env.host, 2).await.unwrap();
    assert_eq!(http(env.edge(), "a1.relay.test", "GET", "/", None).await.unwrap().status, 200);

    agent.stop().await;
    wait_routes_inactive(&env.host).await.unwrap();
    let r = http(env.edge(), "a1.relay.test", "GET", "/", None).await.unwrap();
    assert_eq!(r.status, 503);

    // Reconnect using the cached credential, not the (already used) token.
    let _agent2 = start_agent(
        &env.host,
        "agent-a",
        None,
        &[
            ("a1.relay.test", env.origin_a.addr),
            ("a2.relay.test", env.origin_b.addr),
        ],
        env.dir.path(),
        2,
        false,
    )
    .await
    .unwrap();
    wait_routes_active(&env.host, 2).await.unwrap();
    assert_eq!(http(env.edge(), "a1.relay.test", "GET", "/", None).await.unwrap().status, 200);
}

#[tokio::test]
async fn dead_target_is_502() {
    let env = env().await;
    let token = enroll(&env).await;
    // Reserve a port and drop it so the target is refused.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = l.local_addr().unwrap();
    drop(l);
    let _agent = start_agent(
        &env.host,
        "agent-dead",
        Some(&token),
        &[("dead.relay.test", dead)],
        env.dir.path(),
        1,
        false,
    )
    .await
    .unwrap();
    wait_routes_active(&env.host, 1).await.unwrap();

    let r = http(env.edge(), "dead.relay.test", "GET", "/", None).await.unwrap();
    assert_eq!(r.status, 502);
    assert_eq!(r.header("x-frplike-error"), Some("502"));
}

// ------------------------------------------------------------------ protocol edges

#[tokio::test]
async fn websocket_upgrade_and_echo() {
    let env = env().await;
    let token = enroll(&env).await;
    let _agent = agent_two_routes(&env, &token).await;
    wait_routes_active(&env.host, 2).await.unwrap();

    let mut s = raw_upgrade(env.edge(), "a1.relay.test", "/ws").await.unwrap();
    let mut buf = Vec::new();
    let mut b = [0u8; 256];
    loop {
        let n = timeout(Duration::from_secs(5), s.read(&mut b)).await.unwrap().unwrap();
        buf.extend_from_slice(&b[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    assert!(head.starts_with("HTTP/1.1 101"), "no 101: {head}");

    s.write_all(b"ping-pong").await.unwrap();
    let mut echo = [0u8; 9];
    timeout(Duration::from_secs(3), s.read_exact(&mut echo))
        .await
        .expect("upgraded stream did not echo")
        .unwrap();
    assert_eq!(&echo, b"ping-pong");
}

#[tokio::test]
async fn streaming_response_is_not_buffered() {
    let env = env().await;
    let token = enroll(&env).await;
    let _agent = agent_two_routes(&env, &token).await;
    wait_routes_active(&env.host, 2).await.unwrap();

    let mut s = TcpStream::connect(env.edge()).await.unwrap();
    s.write_all(b"GET /stream HTTP/1.1\r\nHost: a1.relay.test\r\n\r\n").await.unwrap();
    let start = Instant::now();
    let mut buf = Vec::new();
    let mut b = [0u8; 1024];
    // Wait for the first chunk of the body.
    while !buf.windows(6).any(|w| w == b"part-0") {
        let n = timeout(Duration::from_secs(3), s.read(&mut b)).await.unwrap().unwrap();
        assert!(n > 0);
        buf.extend_from_slice(&b[..n]);
    }
    let first = start.elapsed();
    // Drain the rest; the origin takes ~600ms for all four chunks.
    let mut total = buf.len();
    loop {
        match timeout(Duration::from_secs(3), s.read(&mut b)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => total += n,
            Ok(Err(_)) => break,
        }
    }
    let full = start.elapsed();
    assert!(first < Duration::from_millis(450), "first bytes took {first:?} (buffered?)");
    assert!(full >= Duration::from_millis(500), "whole body arrived in {full:?}");
    assert!(total > 0);
}

#[tokio::test]
async fn large_download_and_upload() {
    let env = env().await;
    let token = enroll(&env).await;
    let _agent = agent_two_routes(&env, &token).await;
    wait_routes_active(&env.host, 2).await.unwrap();

    let r = http(env.edge(), "a2.relay.test", "GET", "/big?n=8388608", None).await.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), 8 * 1024 * 1024);

    let body = vec![b'u'; 4 * 1024 * 1024];
    let r = http(env.edge(), "a1.relay.test", "POST", "/upload", Some(&body)).await.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.text().trim(), format!("received={}", body.len()));
}

// ------------------------------------------------------------------ admin intent

#[tokio::test]
async fn disabled_route_is_503_and_delete_is_a_tombstone() {
    let env = env().await;
    let token = enroll(&env).await;
    let agent = agent_two_routes(&env, &token).await;
    wait_routes_active(&env.host, 2).await.unwrap();

    let rows = env.host.state.db.routes().await.unwrap();
    let a1 = rows.iter().find(|r| r.public_host == "a1.relay.test").unwrap().clone();

    env.host.state.db.set_route_enabled(&a1.id, false).await.unwrap();
    env.host.state.registry.publish().await.unwrap();
    assert_eq!(http(env.edge(), "a1.relay.test", "GET", "/", None).await.unwrap().status, 503);

    env.host.state.db.set_route_enabled(&a1.id, true).await.unwrap();
    env.host.state.registry.publish().await.unwrap();
    assert_eq!(http(env.edge(), "a1.relay.test", "GET", "/", None).await.unwrap().status, 200);

    env.host.state.db.delete_route(&a1.id).await.unwrap();
    env.host.state.registry.publish().await.unwrap();
    assert_eq!(http(env.edge(), "a1.relay.test", "GET", "/", None).await.unwrap().status, 404);

    // Re-declaring the deleted host on reconnect must not resurrect it.
    agent.stop().await;
    wait_routes_inactive(&env.host).await.unwrap();
    let _agent2 = start_agent(
        &env.host,
        "agent-a",
        None,
        &[
            ("a1.relay.test", env.origin_a.addr),
            ("a2.relay.test", env.origin_b.addr),
        ],
        env.dir.path(),
        2,
        false,
    )
    .await
    .unwrap();
    // a1 was deleted, so it never becomes active again; wait for a2 only.
    wait_routes_active(&env.host, 1).await.unwrap();
    assert_eq!(http(env.edge(), "a1.relay.test", "GET", "/", None).await.unwrap().status, 404);
    assert_eq!(http(env.edge(), "a2.relay.test", "GET", "/", None).await.unwrap().status, 200);
}

// ------------------------------------------------------------------ credentials

#[tokio::test]
async fn enrollment_token_is_single_use() {
    let env = env().await;
    let token = enroll(&env).await;
    let agent = agent_two_routes(&env, &token).await;
    wait_routes_active(&env.host, 2).await.unwrap();
    agent.stop().await;
    wait_routes_inactive(&env.host).await.unwrap();

    let other_dir = env.dir.path().join("other");
    let second = start_agent(
        &env.host,
        "agent-b",
        Some(&token),
        &[("b1.relay.test", env.origin_a.addr)],
        &other_dir,
        1,
        false,
    )
    .await;
    // Either the spawn fails validation or the process reports a fatal reject;
    // in both cases the token must not enroll a second agent.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let routes = env.host.state.db.routes().await.unwrap();
    assert!(routes.iter().all(|r| r.public_host != "b1.relay.test"));
    drop(second);
}

#[tokio::test]
async fn revoked_agent_cannot_reconnect() {
    let env = env().await;
    let token = enroll(&env).await;
    let agent = agent_two_routes(&env, &token).await;
    wait_routes_active(&env.host, 2).await.unwrap();

    let agents = env.host.state.db.agents().await.unwrap();
    let id = agents[0].id.clone();
    env.host.state.db.revoke_agent(&id).await.unwrap();
    env.host.state.registry.disconnect_agent(&id).await;
    wait_routes_inactive(&env.host).await.unwrap();
    agent.stop().await;

    let _agent2 = start_agent(
        &env.host,
        "agent-a",
        None,
        &[("a1.relay.test", env.origin_a.addr)],
        env.dir.path(),
        1,
        false,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(env.host.state.registry.agents().online_count(), 0);
    assert_eq!(http(env.edge(), "a1.relay.test", "GET", "/", None).await.unwrap().status, 503);
}

#[tokio::test]
async fn suffix_scope_of_the_token_is_enforced() {
    let env = env().await;
    let token = create_token(&env.host, "inner.relay.test").await.unwrap();
    let _agent = start_agent(
        &env.host,
        "agent-scope",
        Some(&token),
        &[("x.inner.relay.test", env.origin_a.addr), ("x.relay.test", env.origin_b.addr)],
        env.dir.path(),
        1,
        false,
    )
    .await
    .unwrap();
    wait_routes_active(&env.host, 1).await.unwrap();

    assert_eq!(http(env.edge(), "x.inner.relay.test", "GET", "/", None).await.unwrap().status, 200);
    assert_eq!(http(env.edge(), "x.relay.test", "GET", "/", None).await.unwrap().status, 404);
}

// ------------------------------------------------------------------ observability

#[tokio::test]
async fn requests_are_logged_with_route_and_status() {
    let env = env().await;
    let token = enroll(&env).await;
    let _agent = agent_two_routes(&env, &token).await;
    wait_routes_active(&env.host, 2).await.unwrap();
    assert_eq!(http(env.edge(), "a1.relay.test", "GET", "/", None).await.unwrap().status, 200);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let logs = env.host.state.db.recent_logs(20).await.unwrap();
    let row = logs
        .iter()
        .find(|l| l.host.as_deref() == Some("a1.relay.test"))
        .expect("request was not logged");
    assert_eq!(row.status, 200);
    assert!(row.route_id.is_some());
    assert!(row.bytes_down > 0);
    assert_eq!(row.error, None);
}

#[tokio::test]
async fn concurrent_requests_share_two_tunnels() {
    let env = env().await;
    let token = enroll(&env).await;
    let _agent = agent_two_routes(&env, &token).await;
    wait_routes_active(&env.host, 2).await.unwrap();
    wait_tunnels(&env.host, 2).await.unwrap();

    let mut tasks = Vec::new();
    for i in 0..60 {
        let edge = env.edge();
        tasks.push(tokio::spawn(async move {
            let host = if i % 2 == 0 { "a1.relay.test" } else { "a2.relay.test" };
            http(edge, host, "GET", "/", None).await.map(|r| r.status)
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap().unwrap(), 200);
    }
}
