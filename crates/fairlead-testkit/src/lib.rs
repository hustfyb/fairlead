//! In-process fixtures for end-to-end tests: a real host, real agent, real TLS,
//! real yamux, and a configurable origin — no mocks of the parts that break.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::anyhow;
use fairlead_agent::AgentConfig;
use fairlead_host::{db::Db, Host, HostConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::{timeout, Instant};

pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "fairlead-{prefix}-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// The admin password every test host is bootstrapped with. There is no
/// username: a single password is the whole credential.
pub const ADMIN_PASSWORD: &str = "test-admin-password";

pub async fn start_host(dir: &Path, suffixes: &[&str]) -> anyhow::Result<Host> {
    let admin_hash = fairlead_host::db::hash_password(ADMIN_PASSWORD)?;
    start_split_host(dir, suffixes, Some(&admin_hash)).await
}

/// A split host that has never had an admin password: the login page has to
/// explain how to set one, and every login is refused.
pub async fn start_host_without_admin_password(dir: &Path, suffixes: &[&str]) -> anyhow::Result<Host> {
    start_split_host(dir, suffixes, None).await
}

async fn start_split_host(
    dir: &Path,
    suffixes: &[&str],
    admin_hash: Option<&str>,
) -> anyhow::Result<Host> {
    let suffixes: Vec<String> = suffixes.iter().map(|s| format!("\"{s}\"")).collect();
    let admin = admin_hash
        .map(|h| format!("[admin]\npassword_hash = {h:?}\n"))
        .unwrap_or_default();
    let toml = format!(
        r#"
[server]
edge_listen = "127.0.0.1:0"
tunnel_listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"
database = {db:?}
allowed_suffixes = [{suffixes}]
public_port = 8080

{admin}
[tls]
dev_self_signed = true

[limits]
heartbeat_secs = 1
heartbeat_timeout_secs = 5
idle_timeout_secs = 30
"#,
        db = dir.join("fairlead.db").to_string_lossy(),
        suffixes = suffixes.join(", ")
    );
    let cfg = HostConfig::from_toml(&toml)?;
    cfg.validate()?;
    fairlead_host::start(cfg).await
}

pub async fn create_token(host: &Host, suffix: &str) -> anyhow::Result<String> {
    let db = Db::open(&host.state.cfg.server.database).await?;
    let token = db.create_token(suffix, Some(3600), "test").await?;
    Ok(token)
}

pub struct AgentFixture {
    stop: Option<watch::Sender<bool>>,
    task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
    pub state_file: PathBuf,
}

impl AgentFixture {
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(true);
        }
        if let Some(task) = self.task.take() {
            let _ = timeout(Duration::from_secs(2), task).await;
        }
    }
}

impl Drop for AgentFixture {
    fn drop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(true);
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// A host whose one port serves all three planes.
pub async fn start_unified_host(
    dir: &Path,
    suffixes: &[&str],
    admin_host: &str,
    tunnel_host: &str,
) -> anyhow::Result<Host> {
    start_vhost_host(dir, suffixes, Some(admin_host), tunnel_host, None, None).await
}

/// Same, plus the public landing page for requests that name no route.
pub async fn start_unified_host_with_landing(
    dir: &Path,
    suffixes: &[&str],
    admin_host: &str,
    tunnel_host: &str,
    landing_dir: &Path,
) -> anyhow::Result<Host> {
    start_vhost_host(dir, suffixes, Some(admin_host), tunnel_host, Some(landing_dir), None).await
}

/// Same, and the page also has a name of its own (`[landing] host`): that name
/// answers the page even though it is a site host under an allowed suffix.
pub async fn start_unified_host_with_landing_host(
    dir: &Path,
    suffixes: &[&str],
    admin_host: &str,
    tunnel_host: &str,
    landing_dir: &Path,
    landing_host: &str,
) -> anyhow::Result<Host> {
    start_vhost_host(
        dir,
        suffixes,
        Some(admin_host),
        tunnel_host,
        Some(landing_dir),
        Some(landing_host),
    )
    .await
}

async fn start_vhost_host(
    dir: &Path,
    suffixes: &[&str],
    admin_host: Option<&str>,
    tunnel_host: &str,
    landing_dir: Option<&Path>,
    landing_host: Option<&str>,
) -> anyhow::Result<Host> {
    let suffixes: Vec<String> = suffixes.iter().map(|s| format!("\"{s}\"")).collect();
    let admin_hash = fairlead_host::db::hash_password(ADMIN_PASSWORD)?;
    let admin_line = admin_host
        .map(|h| format!("admin_host = {h:?}\n"))
        .unwrap_or_default();
    let landing = landing_dir
        .map(|d| {
            let host = landing_host
                .map(|h| format!("host = {h:?}\n"))
                .unwrap_or_default();
            format!("\n[landing]\ndir = {:?}\n{host}", d.to_string_lossy())
        })
        .unwrap_or_default();
    let toml = format!(
        r#"
[server]
listen = "127.0.0.1:0"
{admin_line}tunnel_host = {tunnel_host:?}
database = {db:?}
allowed_suffixes = [{suffixes}]
public_port = 8080

[admin]
password_hash = {admin_hash:?}
allow_remote = true

[limits]
heartbeat_secs = 1
heartbeat_timeout_secs = 5
idle_timeout_secs = 30
{landing}"#,
        db = dir.join("fairlead.db").to_string_lossy(),
        suffixes = suffixes.join(", ")
    );
    let cfg = HostConfig::from_toml(&toml)?;
    cfg.validate()?;
    fairlead_host::start(cfg).await
}

/// A host whose one port serves the tunnel and edge planes, with the admin
/// plane on a socket of its own (`admin_listen`).
pub async fn start_unified_host_with_admin_port(
    dir: &Path,
    suffixes: &[&str],
    tunnel_host: &str,
) -> anyhow::Result<Host> {
    let suffixes: Vec<String> = suffixes.iter().map(|s| format!("\"{s}\"")).collect();
    let admin_hash = fairlead_host::db::hash_password(ADMIN_PASSWORD)?;
    let toml = format!(
        r#"
[server]
listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"
tunnel_host = {tunnel_host:?}
database = {db:?}
allowed_suffixes = [{suffixes}]
public_port = 8080

[admin]
password_hash = {admin_hash:?}
allow_remote = true

[limits]
heartbeat_secs = 1
heartbeat_timeout_secs = 5
idle_timeout_secs = 30
"#,
        db = dir.join("fairlead.db").to_string_lossy(),
        suffixes = suffixes.join(", ")
    );
    let cfg = HostConfig::from_toml(&toml)?;
    cfg.validate()?;
    fairlead_host::start(cfg).await
}

#[allow(clippy::too_many_arguments)]
pub async fn start_agent(
    host: &Host,
    name: &str,
    token: Option<&str>,
    routes: &[(&str, SocketAddr)],
    state_dir: &Path,
    tunnels: u8,
    allow_public_targets: bool,
) -> anyhow::Result<AgentFixture> {
    let server = format!("tls://{}", host.tunnel_addr());
    start_agent_at(&server, None, name, token, routes, state_dir, tunnels, allow_public_targets).await
}

/// Same as [`start_agent`] but with an explicit transport and tunnel vhost,
/// which is how an agent reaches a unified port.
#[allow(clippy::too_many_arguments)]
pub async fn start_agent_at(
    server: &str,
    tunnel_host: Option<&str>,
    name: &str,
    token: Option<&str>,
    routes: &[(&str, SocketAddr)],
    state_dir: &Path,
    tunnels: u8,
    allow_public_targets: bool,
) -> anyhow::Result<AgentFixture> {
    let routes_toml: String = routes
        .iter()
        .map(|(h, a)| format!("[[routes]]\nhost = \"{h}\"\ntarget = \"{a}\"\n"))
        .collect();
    let credential = if token.is_some() {
        String::new()
    } else {
        let state = fairlead_agent::state::load(&state_dir.join("agent.json"));
        match state.credential {
            Some(c) => format!("credential = {c:?}\n"),
            None => return Err(anyhow!("no credential in state file and no token given")),
        }
    };
    let tunnel_host_line = tunnel_host
        .map(|h| format!("tunnel_host = {h:?}\n"))
        .unwrap_or_default();
    let toml = format!(
        r#"
server = {server:?}
{tunnel_host_line}name = {name:?}
{cred}
{token_line}
state_file = {state:?}
tunnels = {tunnels}
allow_public_targets = {allow_public}
dial_timeout_secs = 3

[tls]
mode = "insecure"

{routes}
"#,
        server = server,
        tunnel_host_line = tunnel_host_line,
        cred = credential,
        name = name,
        token_line = token.map(|t| format!("token = {t:?}")).unwrap_or_default(),
        state = state_dir.join("agent.json").to_string_lossy(),
        allow_public = allow_public_targets,
        tunnels = tunnels,
        routes = routes_toml,
    );
    let cfg = AgentConfig::from_toml(&toml)?;
    cfg.validate()?;
    // Keep the config on disk: `fairlead agent add` edits it and the running
    // agent hot-reloads routes from it, which is what the CLI relies on.
    let config_path = state_dir.join("agent.toml");
    std::fs::write(&config_path, &toml)?;
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(async move { fairlead_agent::run_with_path(cfg, Some(config_path), rx).await });
    Ok(AgentFixture { stop: Some(stop), task: Some(task), state_file: state_dir.join("agent.json") })
}

/// The config file [`start_agent_at`] wrote, for tests that edit routes while
/// the agent is running.
pub fn agent_config_path(fixture: &AgentFixture) -> std::path::PathBuf {
    fixture.state_file.with_file_name("agent.toml")
}

/// Wait until `host` has at least `n` live tunnels.
pub async fn wait_tunnels(host: &Host, n: usize) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        let have = host.state.registry.agents().tunnel_count();
        if have >= n {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(5) {
            return Err(anyhow!("only {have}/{n} tunnels connected"));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Wait until the route table satisfies `done`. Used for edits the agent makes
/// on its own schedule (a config file the CLI rewrote), so the window is longer
/// than the one for a handshake.
pub async fn wait_routes<F>(host: &Host, done: F, secs: u64) -> anyhow::Result<()>
where
    F: Fn(&fairlead_host::registry::RouteTable) -> bool,
{
    let start = Instant::now();
    loop {
        if done(&host.state.registry.routes()) {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(secs) {
            return Err(anyhow!("route table did not settle within {secs}s"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub async fn wait_routes_active(host: &Host, expected: usize) -> anyhow::Result<()> {
    wait_routes_active_within(host, expected, 5).await
}

pub async fn wait_routes_active_within(host: &Host, expected: usize, secs: u64) -> anyhow::Result<()> {
    wait_routes(host, |t| t.active_count() >= expected, secs).await
}

pub async fn wait_routes_inactive(host: &Host) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        let active = host.state.registry.routes().active_count();
        let online = host.state.registry.agents().online_count();
        if active == 0 && online == 0 {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(8) {
            return Err(anyhow!("routes still active: {active}, agents online: {online}"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---------------------------------------------------------------- origin

pub struct Origin {
    pub addr: SocketAddr,
    _stop: watch::Sender<bool>,
}

/// A test origin with a few behaviours keyed by path.
pub async fn start_origin(name: &'static str) -> anyhow::Result<Origin> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop, mut rx) = watch::channel(false);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = rx.changed() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break };
                    tokio::spawn(async move { let _ = serve_origin(stream, name).await; });
                }
            }
        }
    });
    Ok(Origin { addr, _stop: stop })
}

async fn serve_origin(mut s: TcpStream, name: &'static str) -> anyhow::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Ok(());
        }
        let n = timeout(Duration::from_secs(10), s.read(&mut chunk)).await??;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(buf.len());
    let text = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut parts = text.split(' ');
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let content_length: usize = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l[15..].trim().parse().ok())
        .unwrap_or(0);

    if path == "/upload" {
        let mut received = buf.len() - head_end;
        let mut b = [0u8; 16 * 1024];
        while received < content_length {
            let n = timeout(Duration::from_secs(10), s.read(&mut b)).await??;
            if n == 0 {
                break;
            }
            received += n;
        }
        let body = format!("received={received}\n");
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nX-Origin: {name}\r\n\r\n",
            body.len()
        );
        s.write_all(head.as_bytes()).await?;
        s.write_all(body.as_bytes()).await?;
        let _ = s.shutdown().await;
        return Ok(());
    }

    if path.starts_with("/ws") {
        s.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .await?;
        // Echo bytes until the client closes.
        let mut b = [0u8; 1024];
        loop {
            let n = match s.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if s.write_all(&b[..n]).await.is_err() {
                break;
            }
        }
        return Ok(());
    }

    if path == "/stream" {
        s.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )
        .await?;
        for i in 0..4 {
            let line = format!("part-{i}\n");
            s.write_all(format!("{:x}\r\n", line.len()).as_bytes()).await?;
            s.write_all(line.as_bytes()).await?;
            s.write_all(b"\r\n").await?;
            s.flush().await?;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        s.write_all(b"0\r\n\r\n").await?;
        let _ = s.shutdown().await;
        return Ok(());
    }

    if let Some(rest) = path.strip_prefix("/big") {
        let n: u64 = rest
            .split_once("n=")
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(1024 * 1024);
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nConnection: close\r\nX-Origin: {name}\r\n\r\n"
        );
        s.write_all(head.as_bytes()).await?;
        let block = vec![b'z'; 32 * 1024];
        let mut sent = 0u64;
        while sent < n {
            let k = (n - sent).min(block.len() as u64) as usize;
            s.write_all(&block[..k]).await?;
            sent += k as u64;
        }
        let _ = s.shutdown().await;
        return Ok(());
    }

    let body = if path == "/echo" {
        text.to_string()
    } else {
        format!("origin={name}\nmethod={method}\npath={path}\n")
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nX-Origin: {name}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body.as_bytes()).await?;
    let _ = s.shutdown().await;
    Ok(())
}

// ---------------------------------------------------------------- client

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

pub async fn http(
    edge: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> anyhow::Result<Response> {
    let mut s = timeout(Duration::from_secs(5), TcpStream::connect(edge)).await??;
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: fairlead-test\r\nAccept: */*\r\n"
    );
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("Connection: keep-alive\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    if let Some(b) = body {
        s.write_all(b).await?;
    }
    s.flush().await?;
    read_response(&mut s).await
}

pub async fn read_response(s: &mut TcpStream) -> anyhow::Result<Response> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    let head_end;
    loop {
        let n = timeout(Duration::from_secs(10), s.read(&mut buf)).await??;
        if n == 0 {
            return Err(anyhow!("connection closed before response head"));
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            head_end = p + 4;
            break;
        }
        if raw.len() > 64 * 1024 {
            return Err(anyhow!("response head too large"));
        }
    }
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let mut lines = head.lines();
    let status_line = lines.next().ok_or_else(|| anyhow!("no status line"))?;
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .ok_or_else(|| anyhow!("bad status line: {status_line}"))?
        .parse()?;
    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().ok();
            }
            if k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked") {
                chunked = true;
            }
            headers.push((k, v));
        }
    }

    let mut body = raw[head_end..].to_vec();
    if chunked {
        loop {
            if let Some(decoded) = decode_chunked(&body) {
                body = decoded;
                break;
            }
            let n = timeout(Duration::from_secs(10), s.read(&mut buf)).await??;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buf[..n]);
        }
    } else if let Some(len) = content_length {
        while body.len() < len {
            let n = timeout(Duration::from_secs(10), s.read(&mut buf)).await??;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buf[..n]);
        }
        body.truncate(len);
    } else {
        loop {
            let n = timeout(Duration::from_secs(10), s.read(&mut buf)).await?;
            match n {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&buf[..n]),
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(Response { status, headers, body })
}

pub fn decode_chunked(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(&data[..line_end]).ok()?;
        let size = usize::from_str_radix(size_str.trim(), 16).ok()?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        if data.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

/// Open a raw connection through the edge, send `head`, and return the socket.
pub async fn raw_upgrade(edge: SocketAddr, host: &str, path: &str) -> anyhow::Result<TcpStream> {
    let mut s = TcpStream::connect(edge).await?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await?;
    Ok(s)
}

