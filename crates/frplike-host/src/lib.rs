//! frplike host: edge, tunnel, admin, storage.

pub mod admin;
pub mod config;
pub mod db;
pub mod edge;
pub mod metrics;
pub mod registry;
pub mod tlsutil;
pub mod tunnel;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::info;

pub use config::HostConfig;
pub use metrics::Metrics;

pub struct HostState {
    pub cfg: Arc<HostConfig>,
    pub db: Arc<db::Db>,
    pub registry: Arc<registry::Registry>,
    pub tls_fingerprint: String,
    pub tls_source: &'static str,
    pub started_at: SystemTime,
    pub edge_addr: SocketAddr,
    pub tunnel_addr: SocketAddr,
    pub admin_addr: SocketAddr,
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

pub async fn start(cfg: HostConfig) -> anyhow::Result<Host> {
    cfg.validate()?;
    let metrics = Arc::new(Metrics::default());
    metrics.mark_start();

    let db = Arc::new(db::Db::open(&cfg.server.database).await.context("open database")?);
    if db.ensure_bootstrap_admin(&cfg.admin.password_hash).await? {
        info!(
            "created admin account `admin` from [admin].password_hash — manage accounts with `frplike admin`"
        );
    }
    if let Err(e) = db::prune_request_logs(&cfg.server.database, cfg.limits.request_log_retention_days).await {
        tracing::warn!(error = %e, "request log prune failed");
    }

    let tls = tlsutil::build(&cfg)?;
    let cfg = Arc::new(cfg);
    let registry = registry::Registry::new(cfg.clone(), db.clone(), metrics.clone());
    registry.load_initial().await?;

    let (edge_listener, edge_addr) = bind(&cfg.server.edge_listen).await?;
    let (tunnel_listener, tunnel_addr) = bind(&cfg.server.tunnel_listen).await?;
    let (admin_listener, admin_addr) = bind(&cfg.server.admin_listen).await?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let state = Arc::new(HostState {
        cfg: cfg.clone(),
        db: db.clone(),
        registry: registry.clone(),
        tls_fingerprint: tls.fingerprint.clone(),
        tls_source: tls.source,
        started_at: SystemTime::now(),
        edge_addr,
        tunnel_addr,
        admin_addr,
    });

    let mut tasks = Vec::new();
    tasks.push(tokio::spawn(edge::accept_loop(state.clone(), edge_listener, shutdown_rx.clone())));
    tasks.push(tokio::spawn(tunnel::accept_loop(
        registry.clone(),
        tls.config.clone(),
        tunnel_listener,
        shutdown_rx.clone(),
    )));

    let app = admin::router(state.clone());
    let mut sd = shutdown_rx.clone();
    let admin_exposed = !admin_addr.ip().is_loopback();
    tasks.push(tokio::spawn(async move {
        let server = axum::serve(
            admin_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = sd.changed().await;
        });
        if let Err(e) = server.await {
            tracing::warn!(error = %e, "admin server stopped");
        }
    }));
    if admin_exposed && !cfg.admin.secure_cookie {
        tracing::warn!(
            admin = %admin_addr,
            "admin UI is reachable from the network over plain HTTP; terminate TLS in front of it and set admin.secure_cookie=true"
        );
    }
    if db.admins().await.map(|a| a.iter().all(|a| a.disabled)).unwrap_or(true) {
        tracing::warn!("no enabled admin account: run `frplike admin add <name>` to enable the admin UI");
    }

    info!(
        edge = %edge_addr,
        tunnel = %tunnel_addr,
        admin = %admin_addr,
        tls = %tls.source,
        fingerprint = %tls.fingerprint,
        "frplike host listening"
    );

    Ok(Host { state, shutdown: shutdown_tx, tasks })
}

async fn bind(addr: &str) -> anyhow::Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    let local = listener.local_addr()?;
    Ok((listener, local))
}
