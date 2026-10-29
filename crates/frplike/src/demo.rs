//! `frplike demo`: host + agent + two origins on loopback, no nginx required.
//!
//! This is the fastest way to see the whole data path: it prints copy-pasteable
//! curl commands that exercise routing, streaming, large bodies and error codes.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context};
use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use frplike_agent::AgentConfig;
use frplike_host::db::Db;
use frplike_host::HostConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;

pub async fn run(dir: Option<PathBuf>, public_port: u16) -> anyhow::Result<()> {
    let dir = dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("frplike-demo-{}", std::process::id()))
    });
    std::fs::create_dir_all(&dir)?;
    let dir = dir.canonicalize().unwrap_or(dir);
    let db_path = dir.join("frplike.db");

    // A password so the admin UI is usable in the demo.
    let salt = SaltString::generate(&mut OsRng);
    let demo_password = "frplike-demo";
    let admin_hash = argon2::Argon2::default()
        .hash_password(demo_password.as_bytes(), &salt)
        .map_err(|e| anyhow!("hash demo password: {e}"))?
        .to_string();

    let host_toml = format!(
        r#"
[server]
edge_listen = "127.0.0.1:0"
tunnel_listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"
database = {db:?}
allowed_suffixes = ["relay.test"]
public_port = {public_port}
public_scheme = "http"

[tls]
dev_self_signed = true

[admin]
password_hash = {hash:?}
session_ttl_secs = 43200
"#,
        db = db_path.to_string_lossy(),
        hash = admin_hash
    );
    let host_cfg = HostConfig::from_toml(&host_toml)?;
    host_cfg.validate()?;

    // Enrollment token must exist before the host starts serving.
    let db = Db::open(&db_path).await.context("open demo database")?;
    let token = db.create_token("relay.test", Some(7 * 86400), "demo").await?;
    drop(db);

    let origin_a = spawn_origin("a1").await?;
    let origin_b = spawn_origin("a2").await?;

    let host = frplike_host::start(host_cfg).await?;
    let edge_port = host.edge_addr().port();

    let agent_toml = format!(
        r#"
server = "tls://127.0.0.1:{tunnel}"
name = "demo-agent"
token = {token:?}
state_file = {state:?}
tunnels = 2
allow_public_targets = false

[tls]
mode = "insecure"

[[routes]]
host = "a1.relay.test"
target = "127.0.0.1:{a}"

[[routes]]
host = "a2.relay.test"
target = "127.0.0.1:{b}"
"#,
        tunnel = host.tunnel_addr().port(),
        token = token,
        state = dir.join("agent.json").to_string_lossy(),
        a = origin_a.port(),
        b = origin_b.port(),
    );
    let agent_cfg = AgentConfig::from_toml(&agent_toml)?;
    let (agent_stop, agent_rx) = watch::channel(false);
    let agent_task = tokio::spawn(async move { frplike_agent::run(agent_cfg, agent_rx).await });

    // Wait until the agent is actually registered.
    let mut ready = false;
    for _ in 0..50 {
        if host.state.registry.agents().online_count() > 0 {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!();
    println!("frplike demo — {}", if ready { "agent online" } else { "agent NOT yet online" });
    println!("  data dir      {}", dir.display());
    println!("  edge (nginx)  http://{}", host.edge_addr());
    println!("  tunnel        {}", host.tunnel_addr());
    println!("  admin         http://{}   (password: {})", host.admin_addr(), demo_password);
    println!();
    println!("  curl -H 'Host: a1.relay.test' http://127.0.0.1:{edge_port}/");
    println!("  curl -N -H 'Host: a1.relay.test' http://127.0.0.1:{edge_port}/stream");
    println!("  curl -H 'Host: a2.relay.test' http://127.0.0.1:{edge_port}/big?mb=64 -o /dev/null -w '%{{size_download}} bytes in %{{time_total}}s\\n'");
    println!("  curl -s -o /dev/null -w '%{{http_code}}\\n' -H 'Host: nope.relay.test' http://127.0.0.1:{edge_port}/");
    println!("  curl -s -H 'Host: a1.relay.test' http://127.0.0.1:{edge_port}/echo");
    println!();
    println!("  (public port {public_port} is only what the agent config advertises; this demo has no nginx)");
    println!("  Ctrl-C to stop");
    println!();

    let _ = tokio::signal::ctrl_c().await;
    let _ = agent_stop.send(true);
    host.shutdown().await;
    agent_task.abort();
    Ok(())
}

/// A tiny origin server that exercises different response shapes.
async fn spawn_origin(ident: &'static str) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                if let Err(e) = serve_origin(stream, ident).await {
                    tracing::debug!(error = %e, "origin connection ended");
                }
            });
        }
    });
    Ok(addr)
}

async fn serve_origin(mut s: TcpStream, ident: &'static str) -> anyhow::Result<()> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 32 * 1024 {
            return Ok(());
        }
        let n = match timeout(Duration::from_secs(10), s.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            _ => return Ok(()),
        };
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    tracing::debug!(ident, bytes = buf.len(), "origin got request head");
    let text = String::from_utf8_lossy(&buf);
    let mut parts = text.split(' ');
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let host = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("host:"))
        .map(|l| l[5..].trim().to_string())
        .unwrap_or_default();

    if let Some(rest) = path.strip_prefix("/big") {
        let mb: u64 = query_param(rest, "mb").and_then(|v| v.parse().ok()).unwrap_or(16);
        let total = mb * 1024 * 1024;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {total}\r\nConnection: close\r\nX-Origin: {ident}\r\n\r\n"
        );
        s.write_all(head.as_bytes()).await?;
        let block = vec![b'x'; 64 * 1024];
        let mut sent = 0u64;
        while sent < total {
            let n = (total - sent).min(block.len() as u64) as usize;
            s.write_all(&block[..n]).await?;
            sent += n as u64;
        }
        let _ = s.shutdown().await;
        return Ok(());
    }

    if path == "/stream" {
        s.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nX-Origin: ",
        )
        .await?;
        s.write_all(ident.as_bytes()).await?;
        s.write_all(b"\r\n\r\n").await?;
        for i in 0..8 {
            let line = format!("chunk {i} at {:?}\n", std::time::Instant::now());
            s.write_all(format!("{:x}\r\n", line.len()).as_bytes()).await?;
            s.write_all(line.as_bytes()).await?;
            s.write_all(b"\r\n").await?;
            s.flush().await?;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        s.write_all(b"0\r\n\r\n").await?;
        let _ = s.shutdown().await;
        return Ok(());
    }

    if path == "/slow" {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let body = if path == "/echo" {
        format!("method={method}\npath={path}\nhost={host}\n\n--- request head ---\n{text}")
    } else {
        format!(
            "hello from origin {ident}\nmethod={method}\npath={path}\nhost={host}\n\nTry /stream, /big?mb=64, /slow, /echo\n"
        )
    };
    tracing::debug!(ident, path = %path, "origin responding");
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nX-Origin: {ident}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body.as_bytes()).await?;
    let _ = s.shutdown().await;
    Ok(())
}

fn query_param<'a>(rest: &'a str, key: &str) -> Option<&'a str> {
    let q = rest.split_once('?')?.1;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            return Some(v);
        }
    }
    None
}
