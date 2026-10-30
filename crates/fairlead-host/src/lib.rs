//! fairlead host: edge, tunnel, admin, storage.

pub mod admin;
pub mod config;
pub mod db;
pub mod edge;
pub mod front;
pub mod metrics;
pub mod registry;
pub mod tlsutil;
pub mod tunnel;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::info;

pub use config::{HostConfig, Plane};
pub use metrics::Metrics;

/// How many admin connections may wait for a hyper task.
const ADMIN_QUEUE: usize = 64;

pub struct HostState {
    pub cfg: Arc<HostConfig>,
    pub db: Arc<db::Db>,
    pub registry: Arc<registry::Registry>,
    pub tls_fingerprint: String,
    pub tls_source: &'static str,
    pub started_at: SystemTime,
    /// In unified mode all three are the same socket.
    pub edge_addr: SocketAddr,
    pub tunnel_addr: SocketAddr,
    pub admin_addr: SocketAddr,
    /// One listener, three planes selected by request host.
    pub unified: bool,
}

impl HostState {
    pub fn metrics(&self) -> &Metrics {
        self.registry.metrics()
    }
}

pub struct Host {
    pub state: Arc<HostState>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Host {
    pub fn edge_addr(&self) -> SocketAddr {
        self.state.edge_addr
    }
    pub fn tunnel_addr(&self) -> SocketAddr {
        self.state.tunnel_addr
    }
    pub fn admin_addr(&self) -> SocketAddr {
        self.state.admin_addr
    }

    /// Ask every listener to stop and wait briefly for them.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        for t in self.tasks.drain(..) {
            let _ = tokio::time::timeout(Duration::from_secs(3), t).await;
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

/// Listeners bound before anything is spawned, so a half-started host leaves
/// no socket behind for the next attempt to trip over.
struct Bound {
    front: Option<(TcpListener, SocketAddr)>,
    edge: Option<(TcpListener, SocketAddr)>,
    tunnel: Option<(TcpListener, SocketAddr)>,
    admin: Option<(TcpListener, SocketAddr)>,
}

impl Bound {
    async fn bind(cfg: &HostConfig) -> anyhow::Result<Self> {
        if cfg.server.unified() {
            let (l, a) = bind(&cfg.server.listen).await?;
            return Ok(Self { front: Some((l, a)), edge: None, tunnel: None, admin: None });
        }
        let (edge_l, edge_a) = bind(&cfg.server.edge_listen).await?;
        let (tunnel_l, tunnel_a) = bind(&cfg.server.tunnel_listen).await?;
        let (admin_l, admin_a) = bind(&cfg.server.admin_listen).await?;
        Ok(Self {
            front: None,
            edge: Some((edge_l, edge_a)),
            tunnel: Some((tunnel_l, tunnel_a)),
            admin: Some((admin_l, admin_a)),
        })
    }
}

pub async fn start(cfg: HostConfig) -> anyhow::Result<Host> {
    cfg.validate()?;
    let metrics = Arc::new(Metrics::default());
    metrics.mark_start();

    let db = Arc::new(db::Db::open(&cfg.server.database).await.context("open database")?);
    if db.ensure_bootstrap_admin(&cfg.admin.password_hash).await? {
        info!(
            "created admin account `admin` from [admin].password_hash — manage accounts with `fairlead admin`"
        );
    }
    if let Err(e) = db::prune_request_logs(&cfg.server.database, cfg.limits.request_log_retention_days).await {
        tracing::warn!(error = %e, "request log prune failed");
    }

    let unified = cfg.server.unified();
    // The unified port does not terminate TLS: either there is a proxy in
    // front of it, or the operator accepted plaintext. Building a certificate
    // that nothing would use only invites a stale-pin failure later.
    let (tls_config, tls_fingerprint, tls_source) = if unified {
        (None, String::new(), "none")
    } else {
        let t = tlsutil::build(&cfg)?;
        (Some(t.config), t.fingerprint, t.source)
    };

    let cfg = Arc::new(cfg);
    let registry = registry::Registry::new(cfg.clone(), db.clone(), metrics.clone());
    registry.load_initial().await?;

    let bound = Bound::bind(&cfg).await?;
    let public = bound.front.as_ref().map(|(_, a)| *a);
    let edge_addr = bound.edge.as_ref().map(|(_, a)| *a).or(public).expect("edge addr");
    let tunnel_addr = bound.tunnel.as_ref().map(|(_, a)| *a).or(public).expect("tunnel addr");
    let admin_addr = bound.admin.as_ref().map(|(_, a)| *a).or(public).expect("admin addr");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let state = Arc::new(HostState {
        cfg: cfg.clone(),
        db: db.clone(),
        registry: registry.clone(),
        tls_fingerprint,
        tls_source,
        started_at: SystemTime::now(),
        edge_addr,
        tunnel_addr,
        admin_addr,
        unified,
    });

    let mut tasks = Vec::new();
    let app = admin::router(state.clone());

    match bound.front {
        Some((listener, addr)) => {
            // One socket, three planes. The admin plane is still an ordinary
            // axum service: the front door feeds it connections whose head it
            // already parsed, so peer addresses, cookies and keep-alive all
            // behave exactly as they do on a dedicated port.
            let (admin_tx, admin_rx) = mpsc::channel(ADMIN_QUEUE);
            let vhost = front::VhostListener::new(admin_rx, addr);
            let mut sd = shutdown_rx.clone();
            tasks.push(tokio::spawn(async move {
                let server = axum::serve(vhost, app.into_make_service_with_connect_info::<admin::Peer>())
                    .with_graceful_shutdown(async move {
                        let _ = sd.changed().await;
                    });
                if let Err(e) = server.await {
                    tracing::warn!(error = %e, "admin server stopped");
                }
            }));
            tasks.push(tokio::spawn(front::accept_loop(
                state.clone(),
                listener,
                admin_tx,
                shutdown_rx.clone(),
            )));
            info!(
                listen = %addr,
                admin_host = %cfg.server.admin_host,
                tunnel_host = %cfg.server.tunnel_host,
                "fairlead host listening on one port: admin and tunnel by virtual host, everything else is edge"
            );
            if !addr.ip().is_loopback() {
                tracing::warn!(
                    listen = %addr,
                    "the unified port speaks plain HTTP and serves the admin plane; put TLS in front of it and set admin.secure_cookie=true before using it from the internet"
                );
            }
            if cfg.tls.cert.is_some() || cfg.tls.key.is_some() {
                tracing::warn!("[tls] cert/key are ignored while server.listen is set: the unified port does not terminate TLS");
            }
        }
        None => {
            let (edge_listener, _) = bound.edge.expect("edge listener");
            let (tunnel_listener, _) = bound.tunnel.expect("tunnel listener");
            let (admin_listener, _) = bound.admin.expect("admin listener");
            tasks.push(tokio::spawn(edge::accept_loop(state.clone(), edge_listener, shutdown_rx.clone())));
            tasks.push(tokio::spawn(tunnel::accept_loop(
                registry.clone(),
                tls_config.clone().expect("tls config"),
                tunnel_listener,
                shutdown_rx.clone(),
            )));
            let mut sd = shutdown_rx.clone();
            tasks.push(tokio::spawn(async move {
                let server = axum::serve(
                    admin_listener,
                    app.into_make_service_with_connect_info::<admin::Peer>(),
                )
                .with_graceful_shutdown(async move {
                    let _ = sd.changed().await;
                });
                if let Err(e) = server.await {
                    tracing::warn!(error = %e, "admin server stopped");
                }
            }));
            info!(
                edge = %edge_addr,
                tunnel = %tunnel_addr,
                admin = %admin_addr,
                tls = %state.tls_source,
                fingerprint = %state.tls_fingerprint,
                "fairlead host listening"
            );
            if !admin_addr.ip().is_loopback() && !cfg.admin.secure_cookie {
                tracing::warn!(
                    admin = %admin_addr,
                    "admin UI is reachable from the network over plain HTTP; terminate TLS in front of it and set admin.secure_cookie=true"
                );
            }
        }
    }

    if db.admins().await.map(|a| a.iter().all(|a| a.disabled)).unwrap_or(true) {
        tracing::warn!("no enabled admin account: run `fairlead admin add <name>` to enable the admin UI");
    }

    Ok(Host { state, shutdown: shutdown_tx, tasks })
}

async fn bind(addr: &str) -> anyhow::Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    let local = listener.local_addr()?;
    Ok((listener, local))
}
