//! Agent runtime: enroll, keep N tunnels alive, dispatch data streams.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use fairlead_proto::control::{self, AgentMsg, Credential, HostMsg};
use fairlead_proto::mux;
use fairlead_proto::PROTOCOL_VERSION;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, timeout};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, error, info, warn};

use crate::config::{AgentConfig, ServerEndpoint};
use crate::forward;
use crate::state::{self, CachedState};
use crate::tls;

pub struct Shared {
    pub cfg: Arc<AgentConfig>,
    pub credential: RwLock<Option<String>>,
    pub agent_id: RwLock<Option<String>>,
    pub state_path: std::path::PathBuf,
    pub desired_tunnels: AtomicU8,
}

impl Shared {
    fn credential_now(&self) -> Option<String> {
        self.credential.read().unwrap().clone()
    }

    fn remember(&self, credential: Option<String>, agent_id: Option<String>) {
        if let Some(c) = credential {
            *self.credential.write().unwrap() = Some(c);
        }
        if let Some(a) = agent_id {
            *self.agent_id.write().unwrap() = Some(a);
        }
        let _ = state::save(
            &self.state_path,
            &CachedState {
                credential: self.credential.read().unwrap().clone(),
                agent_id: self.agent_id.read().unwrap().clone(),
            },
        );
    }
}

#[derive(Debug)]
enum ServeError {
    /// Retrying will not help (bad credential, protocol mismatch, revoked).
    Fatal(String),
    /// Network or host hiccup; back off and retry.
    Transient(String),
}

impl ServeError {
    fn transient(e: impl std::fmt::Display) -> Self {
        ServeError::Transient(e.to_string())
    }
    fn fatal(e: impl std::fmt::Display) -> Self {
        ServeError::Fatal(e.to_string())
    }
}

/// Run until shutdown. Returns an error only when retrying is pointless.
pub async fn run(cfg: AgentConfig, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    cfg.validate()?;
    let cfg = Arc::new(cfg);
    let state_path = cfg.state_path();
    let cached = state::load(&state_path);
    let credential = cfg.credential.clone().or(cached.credential.clone());
    if credential.is_none() && cfg.token.is_none() {
        anyhow::bail!(
            "agent has no credential: put token = \"...\" (first run) or credential = \"...\" in the config"
        );
    }

    let shared = Arc::new(Shared {
        cfg: cfg.clone(),
        credential: RwLock::new(credential),
        agent_id: RwLock::new(cached.agent_id),
        state_path,
        desired_tunnels: AtomicU8::new(cfg.tunnels.max(1)),
    });

    let (ready_tx, mut ready_rx) = mpsc::channel::<u8>(8);
    let mut primary = tokio::spawn(supervise(shared.clone(), ready_tx.clone(), shutdown.clone()));

    // Enroll with a single connection first: several tunnels racing with the
    // same one-time token would all but one get `token_used`.
    let desired = tokio::select! {
        _ = shutdown.changed() => return Ok(()),
        n = ready_rx.recv() => n.unwrap_or(1),
        res = &mut primary => {
            match res {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(anyhow::anyhow!("agent task panicked: {e}")),
            }
        }
    };

    for i in 1..desired.max(1) {
        let shared = shared.clone();
        let ready_tx = ready_tx.clone();
        let shutdown = shutdown.clone();
        info!(tunnel = i + 1, "starting additional tunnel");
        tokio::spawn(supervise(shared, ready_tx, shutdown));
    }

    // Stay alive until asked to stop.
    tokio::select! {
        _ = shutdown.changed() => {}
        res = &mut primary => {
            match res {
                Ok(Err(e)) => return Err(e),
                Ok(Ok(())) => {}
                Err(e) => return Err(anyhow::anyhow!("agent task panicked: {e}")),
            }
        }
    }
    primary.abort();
    Ok(())
}

async fn supervise(
    shared: Arc<Shared>,
    ready_tx: mpsc::Sender<u8>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut failures: u32 = 0;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        match connect_and_serve(shared.clone(), &ready_tx, shutdown.clone()).await {
            Ok(()) => {
                failures = 0;
                debug!("tunnel closed cleanly");
            }
            Err(ServeError::Fatal(msg)) => {
                error!(%msg, "agent stopped: server refused this agent permanently");
                return Err(anyhow::anyhow!(msg));
            }
            Err(ServeError::Transient(msg)) => {
                failures = failures.saturating_add(1);
                warn!(%msg, failures, "tunnel lost, will reconnect");
            }
        }
        let delay = backoff(failures);
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            _ = sleep(delay) => {}
        }
    }
}

fn backoff(failures: u32) -> Duration {
    let base = 1u64 << failures.min(5);
    let jitter = 0.7 + rand::random::<f64>() * 0.6;
    Duration::from_millis((base as f64 * 1000.0 * jitter) as u64).min(Duration::from_secs(30))
}

/// The two transports an agent can speak. Both carry the same upgrade request:
/// on a single plaintext port the `Host` picks the tunnel plane, behind an
/// nginx TLS terminator the upgrade travels inside TLS.
enum Transport {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl tokio::io::AsyncRead for Transport {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Transport::Tls(s) => std::pin::Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Transport {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Transport::Plain(s) => std::pin::Pin::new(s).poll_write(cx, data),
            Transport::Tls(s) => std::pin::Pin::new(&mut **s).poll_write(cx, data),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Transport::Tls(s) => std::pin::Pin::new(&mut **s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Transport::Tls(s) => std::pin::Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

/// Connect and upgrade: the tunnel plane is always entered through an HTTP
/// `101`, on both transports.
async fn open_transport(
    cfg: &AgentConfig,
    ep: &ServerEndpoint,
) -> Result<fairlead_proto::Prefixed<Transport>, ServeError> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((ep.host.as_str(), ep.port))
        .await
        .map_err(ServeError::transient)?
        .collect();
    if addrs.is_empty() {
        return Err(ServeError::transient("server host resolved to no addresses"));
    }
    let mut tcp = None;
    let mut last = String::new();
    for addr in &addrs {
        match timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                tcp = Some(s);
                break;
            }
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "connect timed out".into(),
        }
    }
    let tcp = tcp.ok_or_else(|| {
        ServeError::transient(format!("cannot reach {}:{}: {last}", ep.host, ep.port))
    })?;
    tcp.set_nodelay(true).ok();

    let mut transport = if ep.tls {
        let tls_setup = tls::build(cfg, &ep.host).map_err(ServeError::fatal)?;
        let connector = tokio_rustls::TlsConnector::from(tls_setup.config);
        let stream = timeout(
            Duration::from_secs(10),
            connector.connect(tls_setup.server_name, tcp),
        )
        .await
        .map_err(ServeError::transient)?
        .map_err(ServeError::transient)?;
        Transport::Tls(Box::new(stream))
    } else {
        Transport::Plain(tcp)
    };

    let host_header = cfg.tunnel_host(ep);
    let request = fairlead_proto::front::upgrade_request(&host_header, &cfg.agent_name());
    timeout(Duration::from_secs(10), transport.write_all(&request))
        .await
        .map_err(|_| ServeError::transient("timed out writing the tunnel upgrade"))?
        .map_err(ServeError::transient)?;
    let leftover = match timeout(
        Duration::from_secs(10),
        fairlead_proto::front::read_upgrade_response(&mut transport, 8192),
    )
    .await
    {
        Ok(Ok(rest)) => rest,
        Ok(Err(why)) => {
            // A clear protocol answer from the host is fatal: retrying with the
            // same tunnel host and port cannot help.
            let permanent = why.contains("refused the upgrade");
            return Err(if permanent {
                ServeError::fatal(format!("{why} (server={})", cfg.server))
            } else {
                ServeError::transient(why)
            });
        }
        Err(_) => return Err(ServeError::transient("timed out reading the upgrade reply")),
    };
    // yamux starts talking immediately (the server's opening ping often lands
    // in the same segment as the `101`), so those bytes are not a violation:
    // they are the first frames of the session and must be replayed into it.
    debug!(host = %host_header, tls = ep.tls, early = leftover.len(), "tunnel upgraded");
    Ok(fairlead_proto::Prefixed::with_prefix(transport, leftover))
}

async fn connect_and_serve(
    shared: Arc<Shared>,
    ready_tx: &mpsc::Sender<u8>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServeError> {
    let cfg = shared.cfg.clone();
    let ep = cfg.server_parts().map_err(ServeError::fatal)?;
    let transport = open_transport(&cfg, &ep).await?;

    let mut ycfg = yamux::Config::default();
    ycfg.set_max_num_streams(2048);
    let conn = yamux::Connection::new(transport.compat(), ycfg, yamux::Mode::Client);
    let (open_tx, open_rx) = mpsc::channel(16);
    let (kill_tx, kill_rx) = mpsc::channel(1);
    let (inbound_tx, mut inbound_rx) = mpsc::channel(128);
    let _driver = mux::spawn(conn, open_rx, kill_rx, inbound_tx);

    let control = mux::open(&open_tx, Duration::from_secs(10))
        .await
        .map_err(ServeError::transient)?;
    let control = control.compat();
    let (mut reader, writer) = tokio::io::split(control);
    let (msg_tx, mut msg_rx) = mpsc::channel::<AgentMsg>(64);
    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(msg) = msg_rx.recv().await {
            if control::write_msg(&mut writer, &msg).await.is_err() {
                break;
            }
        }
    });

    let credential = match shared.credential_now() {
        Some(c) => Credential::Credential { value: c },
        None => Credential::Token {
            value: cfg.token.clone().ok_or_else(|| ServeError::fatal("no token and no credential"))?,
        },
    };

    let hello = AgentMsg::Hello {
        proto: PROTOCOL_VERSION,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        agent_name: cfg.agent_name(),
        credential,
        routes: cfg.routes.clone(),
        tunnels: cfg.tunnels.max(1),
    };
    if msg_tx.send(hello).await.is_err() {
        return Err(ServeError::transient("control writer stopped"));
    }

    let reply: HostMsg = timeout(Duration::from_secs(15), control::read_msg(&mut reader))
        .await
        .map_err(|_| ServeError::transient("handshake timed out"))?
        .map_err(ServeError::transient)?;

    let (accepted, rejected, tunnel_count) = match reply {
        HostMsg::Welcome { agent_id, credential, accepted, rejected, tunnel_count, .. } => {
            if credential.is_some() {
                info!(agent_id = %agent_id, "enrolled; credential stored in {:?}", shared.state_path);
            }
            shared.remember(credential, Some(agent_id.clone()));
            shared.desired_tunnels.store(tunnel_count.max(1), Ordering::Relaxed);
            (accepted, rejected, tunnel_count.max(1))
        }
        HostMsg::Reject { code, message } => {
            let permanent = matches!(
                code.as_str(),
                "invalid_credential" | "token_used" | "token_expired" | "revoked" | "protocol_mismatch" | "too_many_tunnels"
            );
            return Err(if permanent {
                ServeError::fatal(format!("{code}: {message}"))
            } else {
                ServeError::transient(format!("{code}: {message}"))
            });
        }
        other => {
            let _ = other;
            return Err(ServeError::transient("unexpected handshake reply"));
        }
    };

    info!(
        server = %cfg.server,
        accepted = accepted.len(),
        rejected = rejected.len(),
        "connected"
    );
    for r in &rejected {
        warn!(host = %r.host, reason = %r.reason, "route rejected by host");
    }
    let _ = ready_tx.try_send(tunnel_count);

    // Heartbeats.
    let beat_tx = msg_tx.clone();
    let mut beat_shutdown = shutdown.clone();
    let heartbeat = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = beat_shutdown.changed() => break,
                _ = ticker.tick() => {
                    let msg = AgentMsg::Heartbeat { ts_ms: now_ms() };
                    if beat_tx.send(msg).await.is_err() { break; }
                }
            }
        }
    });

    // Data streams: one task each, so a slow local target never blocks others.
    let forward_tx = shared.clone();
    let streams = tokio::spawn(async move {
        while let Some(stream) = inbound_rx.recv().await {
            let shared = forward_tx.clone();
            tokio::spawn(async move {
                forward::handle(shared, stream).await;
            });
        }
    });

    let result = loop {
        tokio::select! {
            _ = shutdown.changed() => break Ok(()),
            msg = control::read_msg::<_, HostMsg>(&mut reader) => {
                match msg {
                    Ok(HostMsg::Pong { .. }) => {}
                    Ok(HostMsg::Revoked { reason }) => {
                        break Err(ServeError::fatal(format!("revoked by host: {reason}")));
                    }
                    Ok(HostMsg::Reject { code, message }) => {
                        break Err(ServeError::fatal(format!("{code}: {message}")));
                    }
                    Ok(HostMsg::RouteUpdate { accepted, rejected }) => {
                        info!(accepted = accepted.len(), rejected = rejected.len(), "routes updated");
                        for r in rejected {
                            warn!(host = %r.host, reason = %r.reason, "route rejected");
                        }
                    }
                    Ok(HostMsg::Welcome { .. }) => {
                        break Err(ServeError::transient("duplicate welcome"));
                    }
                    Err(e) => break Err(ServeError::transient(e)),
                }
            }
        }
    };

    heartbeat.abort();
    streams.abort();
    writer_task.abort();
    drop(kill_tx);
    drop(open_tx);
    result
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[allow(dead_code)]
async fn flush<W: AsyncWrite + Unpin>(w: &mut W) {
    let _ = w.flush().await;
}
