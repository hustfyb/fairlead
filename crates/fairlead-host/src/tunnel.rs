//! Agent tunnel listener: TLS, yamux, handshake, heartbeats.
//!
//! One physical tunnel = one TLS connection carrying one yamux session.
//! An agent may hold several (`tunnels = 2..4`) so a single stalled download
//! cannot add head-of-line latency to every other request of that agent.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use fairlead_proto::control::{self, AgentMsg, Credential, HostMsg};
use fairlead_proto::mux::{self, MuxError};
use fairlead_proto::PROTOCOL_VERSION;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::db::AuthOutcome;
use crate::metrics::now_unix_ms;
use crate::registry::Registry;

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("tunnel is closed")]
    Closed,
    #[error("opening a stream timed out")]
    Timeout,
    #[error("tunnel protocol error: {0}")]
    Protocol(String),
}

pub struct Tunnel {
    pub id: String,
    pub agent_id: String,
    pub session_id: String,
    pub opened_at_ms: i64,
    last_beat: AtomicI64,
    open_tx: mpsc::Sender<OpenReq>,
    ctrl_tx: mpsc::Sender<HostMsg>,
    kill_tx: mpsc::Sender<()>,
    closed: AtomicBool,
}

pub type OpenReq = mux::OpenRequest;

impl Tunnel {
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub fn last_heartbeat_ms(&self) -> i64 {
        self.last_beat.load(Ordering::Relaxed)
    }

    pub fn touch(&self) {
        self.last_beat.store(now_unix_ms(), Ordering::Relaxed);
    }

    pub fn age_ms(&self) -> i64 {
        now_unix_ms() - self.last_beat.load(Ordering::Relaxed)
    }

    pub async fn open_stream(&self, wait: Duration) -> Result<yamux::Stream, TunnelError> {
        if self.is_closed() {
            return Err(TunnelError::Closed);
        }
        match mux::open(&self.open_tx, wait).await {
            Ok(s) => Ok(s),
            Err(MuxError::Closed) => Err(TunnelError::Closed),
            Err(MuxError::Protocol(m)) if m.contains("timed out") => Err(TunnelError::Timeout),
            Err(MuxError::Protocol(m)) => Err(TunnelError::Protocol(m)),
        }
    }

    pub async fn control(&self, msg: HostMsg) -> Result<(), TunnelError> {
        self.ctrl_tx.send(msg).await.map_err(|_| TunnelError::Closed)
    }

    /// Ask the driver to drop the connection. Idempotent.
    pub fn shutdown(&self) {
        if !self.closed.swap(true, Ordering::Relaxed) {
            let _ = self.kill_tx.try_send(());
        }
    }
}

/// Runs the listener until `shutdown` flips.
pub async fn accept_loop(
    registry: Arc<Registry>,
    tls: Arc<rustls::ServerConfig>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) {
    let permits = Arc::new(Semaphore::new(128));
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "tunnel accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!(%peer, "tunnel handshake budget exhausted");
                        continue;
                    }
                };
                let registry = registry.clone();
                let tls = tls.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_conn(registry, tls, tcp, peer, shutdown).await {
                        debug!(%peer, error = %e, "tunnel session ended");
                    }
                });
            }
        }
    }
    info!("tunnel listener stopped");
}

async fn handle_conn(
    registry: Arc<Registry>,
    tls: Arc<rustls::ServerConfig>,
    tcp: TcpStream,
    peer: std::net::SocketAddr,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    tcp.set_nodelay(true).ok();
    let hs = registry.cfg().limits.handshake_timeout();
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);

    let stream = match timeout(hs, acceptor.accept(tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            registry.metrics().tunnels_rejected.fetch_add(1, Ordering::Relaxed);
            debug!(%peer, error = %e, "tls handshake failed");
            return Ok(());
        }
        Err(_) => {
            registry.metrics().tunnels_rejected.fetch_add(1, Ordering::Relaxed);
            debug!(%peer, "tls handshake timed out");
            return Ok(());
        }
    };

    let mut ycfg = yamux::Config::default();
    ycfg.set_max_num_streams(registry.cfg().limits.max_streams_per_connection.max(16));
    let conn = yamux::Connection::new(stream.compat(), ycfg, yamux::Mode::Server);

    let (open_tx, open_rx) = mpsc::channel::<OpenReq>(64);
    let (kill_tx, kill_rx) = mpsc::channel::<()>(1);
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<yamux::Stream>(8);
    let driver = mux::spawn(conn, open_rx, kill_rx, inbound_tx);

    let mut control = match timeout(hs, inbound_rx.recv()).await {
        Ok(Some(s)) => s.compat(),
        _ => {
            driver.abort();
            registry.metrics().tunnels_rejected.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };
    // Any further agent-opened stream is a protocol violation; dropping the
    // receiver makes the driver hang up instead of pretending it is normal.
    drop(inbound_rx);

    let hello: AgentMsg = match timeout(hs, control::read_msg(&mut control)).await {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => {
            driver.abort();
            debug!(%peer, error = %e, "control hello failed");
            return Ok(());
        }
        Err(_) => {
            driver.abort();
            return Ok(());
        }
    };

    let AgentMsg::Hello { proto, agent_version, agent_name, credential, routes, tunnels } = hello else {
        reject(&mut control, "protocol", "first control message must be hello").await;
        driver.abort();
        return Ok(());
    };

    if proto != PROTOCOL_VERSION {
        registry.metrics().tunnels_rejected.fetch_add(1, Ordering::Relaxed);
        reject(
            &mut control,
            "protocol_mismatch",
            &format!("host speaks fairlead/{PROTOCOL_VERSION}, agent speaks fairlead/{proto}; upgrade both ends"),
        )
        .await;
        driver.abort();
        return Ok(());
    }

    let is_token = matches!(credential, Credential::Token { .. });
    let auth = registry
        .db
        .authenticate(credential.secret(), is_token, &agent_name, &agent_version)
        .await?;
    let grant = match auth {
        AuthOutcome::Ok(g) => g,
        AuthOutcome::Reject { code, message } => {
            registry.metrics().tunnels_rejected.fetch_add(1, Ordering::Relaxed);
            info!(%peer, %code, %message, "agent rejected");
            reject(&mut control, code, &message).await;
            driver.abort();
            return Ok(());
        }
    };

    let max_tunnels = registry.max_tunnels_per_agent() as usize;
    if registry.live_tunnel_count(&grant.agent_id).await >= max_tunnels {
        registry.metrics().tunnels_rejected.fetch_add(1, Ordering::Relaxed);
        reject(&mut control, "too_many_tunnels", &format!("agent already has {max_tunnels} tunnels")).await;
        driver.abort();
        return Ok(());
    }

    let (accepted, rejected, declared) = registry
        .db
        .register_routes(&grant.agent_id, grant.allowed_suffix.as_deref(), &routes)
        .await?;

    let tunnel_count = tunnels.clamp(1, max_tunnels as u8);
    let heartbeat_secs = registry.heartbeat_secs();
    let tunnel_id = uuid::Uuid::new_v4().to_string();
    let session_id = uuid::Uuid::new_v4().to_string();

    let welcome = HostMsg::Welcome {
        agent_id: grant.agent_id.clone(),
        session_id: session_id.clone(),
        credential: grant.fresh_credential.clone(),
        accepted: accepted.clone(),
        rejected: rejected.clone(),
        heartbeat_secs,
        tunnel_count,
    };
    control::write_msg(&mut control, &welcome).await?;
    control.flush().await.ok();

    let (mut reader, mut writer) = tokio::io::split(control);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<HostMsg>(32);
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = ctrl_rx.recv().await {
            if control::write_msg(&mut writer, &msg).await.is_err() {
                break;
            }
        }
    });

    let tunnel = Arc::new(Tunnel {
        id: tunnel_id.clone(),
        agent_id: grant.agent_id.clone(),
        session_id,
        opened_at_ms: now_unix_ms(),
        last_beat: AtomicI64::new(now_unix_ms()),
        open_tx,
        ctrl_tx,
        kill_tx,
        closed: AtomicBool::new(false),
    });

    let declared: HashSet<String> = declared.into_iter().collect();
    registry
        .register_tunnel(tunnel.clone(), &grant.agent_name, &agent_version, &declared)
        .await?;

    info!(
        %peer,
        agent = %grant.agent_name,
        agent_id = %grant.agent_id,
        tunnel = %tunnel_id,
        routes = accepted.len(),
        rejected = rejected.len(),
        "agent tunnel established"
    );

    let watchdog = {
        let tunnel = tunnel.clone();
        let timeout_ms = registry.cfg().limits.heartbeat_timeout().as_millis() as i64;
        let mut sh = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sh.changed() => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {
                        if tunnel.is_closed() {
                            break;
                        }
                        if tunnel.age_ms() > timeout_ms {
                            warn!(tunnel = %tunnel.id, agent_id = %tunnel.agent_id, "heartbeat timeout, closing tunnel");
                            tunnel.shutdown();
                            break;
                        }
                    }
                }
            }
        })
    };

    let result = read_control(registry.clone(), tunnel.clone(), &mut reader, grant.allowed_suffix.clone()).await;
    watchdog.abort();
    writer_task.abort();
    tunnel.shutdown();
    registry.remove_tunnel(&tunnel.agent_id, &tunnel.id).await;
    let _ = driver.await;

    if let Err(e) = result {
        debug!(error = %e, "control stream ended");
    }
    info!(agent_id = %grant.agent_id, tunnel = %tunnel_id, "agent tunnel closed");
    Ok(())
}

async fn read_control<R>(
    registry: Arc<Registry>,
    tunnel: Arc<Tunnel>,
    reader: &mut R,
    agent_suffix: Option<String>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let msg: AgentMsg = control::read_msg(reader).await?;
        match msg {
            AgentMsg::Heartbeat { ts_ms } => {
                tunnel.touch();
                let _ = tunnel.control(HostMsg::Pong { ts_ms }).await;
            }
            AgentMsg::Routes { routes } => {
                let (accepted, rejected, declared) = registry
                    .db
                    .register_routes(&tunnel.agent_id, agent_suffix.as_deref(), &routes)
                    .await?;
                registry
                    .set_declared(&tunnel.agent_id, declared.into_iter().collect())
                    .await;
                let _ = tunnel
                    .control(HostMsg::RouteUpdate { accepted, rejected })
                    .await;
            }
            AgentMsg::Hello { .. } => {
                anyhow::bail!("duplicate hello on control stream");
            }
        }
    }
}

async fn reject<W: AsyncWrite + Unpin>(control: &mut W, code: &str, message: &str) {
    let _ = control::write_msg(
        control,
        &HostMsg::Reject { code: code.to_string(), message: message.to_string() },
    )
    .await;
    let _ = control.flush().await;
    let _ = control.shutdown().await;
}
