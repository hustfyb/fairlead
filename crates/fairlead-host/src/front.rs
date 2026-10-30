//! Unified front door: one listener, three planes.
//!
//! Without TLS there is no SNI, so the plane cannot be chosen by the TLS
//! handshake. It is chosen by the request itself instead:
//!
//! ```text
//!                  ┌──────────── Host: admin.example.com ──> admin plane (axum)
//! one TCP port ──> │  Upgrade: fairlead/1 on tunnel.example.com ──> tunnel plane (yamux)
//!                  └──────────── any other host ──────────> edge plane (routes)
//! ```
//!
//! The first bytes are read with the same bounded head reader the edge plane
//! already used, so a merged port does not get a second, weaker HTTP parser.
//! Once the plane is known the connection is handed over whole: the edge plane
//! keeps its byte-splicing path, the tunnel plane gets a yamux session, and the
//! admin plane gets a stream that replays the head it already consumed.
//!
//! Why a vhost and not a path prefix: the `Host` is what the browser and every
//! proxy already route on, and it keeps the admin plane off every URL that a
//! site route could ever occupy.

use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fairlead_proto::front::{self, wants_tunnel};
use fairlead_proto::hostname;
use fairlead_proto::http1::{read_request_head, HeadError, Sniffed};
pub use fairlead_proto::stream::Prefixed;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::Plane;
use crate::HostState;

/// Connections allowed to be mid-head at the same time. A merged port sees
/// scanners, so this is the cheapest possible slowloris bound.
const HANDSHAKE_BUDGET: usize = 512;
/// Concurrent tunnel sessions (same number the split tunnel listener allows).
const TUNNEL_SLOTS: usize = 128;

/// A listener for `axum::serve` fed by the front door.
///
/// This keeps the admin plane on the ordinary axum/hyper path — real peer
/// address, keep-alive, all of it — while it shares the public socket with the
/// other two planes.
pub struct VhostListener {
    rx: mpsc::Receiver<(Prefixed<TcpStream>, std::net::SocketAddr)>,
    local: std::net::SocketAddr,
}

impl VhostListener {
    pub fn new(rx: mpsc::Receiver<(Prefixed<TcpStream>, std::net::SocketAddr)>, local: std::net::SocketAddr) -> Self {
        Self { rx, local }
    }
}

impl axum::serve::Listener for VhostListener {
    type Io = Prefixed<TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // `recv` is cancel-safe, so a shutdown that drops this future cannot
        // swallow an accepted connection.
        match self.rx.recv().await {
            Some(v) => v,
            // The front door is gone; nothing will ever arrive again.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// Read and answer the tunnel upgrade on a stream that has no front door in
/// front of it (the split TLS listener does its own TLS handshake first).
///
/// Returns `Err(reason)` after logging nothing: the caller decides whether a
/// rejected upgrade is metric-worthy.
pub(crate) async fn read_upgrade<S>(
    io: &mut S,
    max_head: usize,
    budget: Duration,
) -> Result<(), &'static str>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let max = max_head.clamp(1024, fairlead_proto::MAX_HEAD_BYTES);
    let sniffed = match timeout(budget, read_request_head(io, max)).await {
        Ok(Ok(s)) => s,
        Ok(Err(HeadError::TooLarge)) => return Err("upgrade head too large"),
        Ok(Err(HeadError::Eof)) => return Err("closed before the upgrade"),
        Ok(Err(HeadError::Malformed(m))) => return Err(m),
        Ok(Err(HeadError::Io(_))) => return Err("io error reading the upgrade"),
        Err(_) => return Err("upgrade timed out"),
    };
    if !wants_tunnel(&sniffed.head) {
        return Err("missing `Upgrade: fairlead/1`");
    }
    if !sniffed.body_prefix.is_empty() {
        return Err("unexpected body before the upgrade");
    }
    front::write_101(io).await.map_err(|_| "could not write 101")?;
    Ok(())
}

pub async fn accept_loop(
    state: Arc<HostState>,
    listener: TcpListener,
    admin_tx: mpsc::Sender<(Prefixed<TcpStream>, std::net::SocketAddr)>,
    mut shutdown: watch::Receiver<bool>,
) {
    let budget = Arc::new(Semaphore::new(HANDSHAKE_BUDGET));
    let tunnel_slots = Arc::new(Semaphore::new(TUNNEL_SLOTS));
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "front accept failed");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                };
                let permit = match budget.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // No head has arrived on 512 connections: dropping is
                        // cheaper than queueing and says the same thing.
                        continue;
                    }
                };
                let state = state.clone();
                let admin_tx = admin_tx.clone();
                let tunnel_slots = tunnel_slots.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve(state, stream, peer, admin_tx, permit, tunnel_slots, shutdown).await {
                        debug!(%peer, error = %e, "front connection ended");
                    }
                });
            }
        }
    }
    tracing::info!("front listener stopped");
}

async fn serve(
    state: Arc<HostState>,
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    admin_tx: mpsc::Sender<(Prefixed<TcpStream>, std::net::SocketAddr)>,
    permit: OwnedSemaphorePermit,
    tunnel_slots: Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    stream.set_nodelay(true).ok();
    let started = Instant::now();
    let request_id = format!("{:016x}", rand::random::<u64>());
    let head_timeout = Duration::from_secs(state.cfg.limits.head_timeout_secs.max(1));
    let max_head = state.cfg.limits.max_head_bytes.clamp(1024, fairlead_proto::MAX_HEAD_BYTES);

    let sniffed: Sniffed = match timeout(head_timeout, read_request_head(&mut stream, max_head)).await {
        Ok(Ok(s)) => s,
        Ok(Err(HeadError::TooLarge)) => {
            return crate::edge::respond(&mut stream, 431, "Request Header Fields Too Large", "request head too large", &request_id, None).await;
        }
        Ok(Err(HeadError::Eof)) => return Ok(()),
        Ok(Err(HeadError::Malformed(m))) => {
            return crate::edge::respond(&mut stream, 400, "Bad Request", m, &request_id, None).await;
        }
        Ok(Err(HeadError::Io(e))) => return Err(e.into()),
        Err(_) => {
            return crate::edge::respond(&mut stream, 408, "Request Timeout", "timed out reading request head", &request_id, None).await;
        }
    };

    let host = match sniffed.head.host_raw.as_deref().map(hostname::normalize) {
        Some(Ok(h)) => h,
        Some(Err(e)) => {
            return crate::edge::respond(&mut stream, 400, "Bad Request", &format!("invalid host: {e}"), &request_id, None).await;
        }
        None => {
            return crate::edge::respond(&mut stream, 400, "Bad Request", "missing host header", &request_id, None).await;
        }
    };

    let plane = state.cfg.plane_for(&host);
    // The head is in; this connection is no longer a slowloris risk.
    drop(permit);
    debug!(%request_id, %host, ?plane, t = ?started.elapsed(), "front plane");

    match plane {
        Plane::Admin => forward_admin(stream, sniffed, peer, &admin_tx, &request_id, &host).await,
        Plane::Tunnel => upgrade_tunnel(state, stream, sniffed, peer, tunnel_slots, shutdown, &request_id, &host, started).await,
        Plane::Edge => {
            state.metrics().requests.fetch_add(1, Ordering::Relaxed);
            crate::edge::serve_head(state, stream, peer, sniffed, started, request_id).await
        }
    }
}

async fn forward_admin(
    stream: TcpStream,
    sniffed: Sniffed,
    peer: std::net::SocketAddr,
    admin_tx: &mpsc::Sender<(Prefixed<TcpStream>, std::net::SocketAddr)>,
    request_id: &str,
    host: &str,
) -> anyhow::Result<()> {
    // Replay exactly what was consumed: head, then any body bytes that arrived
    // with it. axum sees a normal HTTP stream on a normal socket.
    let mut replay = sniffed.head.raw;
    replay.extend_from_slice(&sniffed.body_prefix);
    let io = Prefixed::with_prefix(stream, replay);
    match admin_tx.try_send((io, peer)) {
        Ok(()) => Ok(()),
        // `try_send` hands the connection back, so this is a clean 503 rather
        // than a dropped socket.
        Err(mpsc::error::TrySendError::Full((mut io, _))) => {
            debug!(%request_id, %host, "admin queue full");
            crate::edge::respond(&mut io, 503, "Service Unavailable", "admin plane is busy", request_id, Some(host)).await
        }
        Err(mpsc::error::TrySendError::Closed((mut io, _))) => {
            debug!(%request_id, %host, "admin plane is shut down");
            crate::edge::respond(&mut io, 503, "Service Unavailable", "admin plane is shutting down", request_id, Some(host)).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn upgrade_tunnel(
    state: Arc<HostState>,
    mut stream: TcpStream,
    sniffed: Sniffed,
    peer: std::net::SocketAddr,
    tunnel_slots: Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
    request_id: &str,
    host: &str,
    started: Instant,
) -> anyhow::Result<()> {
    if sniffed.head.method != "GET" && sniffed.head.method != "POST" {
        return crate::edge::respond(&mut stream, 400, "Bad Request", "tunnel upgrade must be GET", request_id, Some(host)).await;
    }
    if !wants_tunnel(&sniffed.head) {
        return crate::edge::respond(
            &mut stream,
            400,
            "Bad Request",
            &format!("expected `Upgrade: {}` on the tunnel host", front::UPGRADE_PROTOCOL),
            request_id,
            Some(host),
        )
        .await;
    }
    if !sniffed.body_prefix.is_empty() {
        // A body before the upgrade means the sender is not our agent, and
        // those bytes would be parsed as yamux frames.
        return crate::edge::respond(&mut stream, 400, "Bad Request", "unexpected body before upgrade", request_id, Some(host)).await;
    }
    // Held for the whole session: this is the "128 concurrent tunnels" cap.
    let _slot = match tunnel_slots.try_acquire_owned() {
        Ok(s) => s,
        Err(_) => {
            return crate::edge::respond(&mut stream, 503, "Service Unavailable", "tunnel handshake budget exhausted", request_id, Some(host)).await;
        }
    };
    debug!(%request_id, %host, t = ?started.elapsed(), "tunnel plane");
    if let Err(e) = front::write_101(&mut stream).await {
        warn!(%peer, error = %e, "failed to write 101");
        return Ok(());
    }
    crate::tunnel::serve_stream(state.registry.clone(), stream, peer, shutdown).await
}
