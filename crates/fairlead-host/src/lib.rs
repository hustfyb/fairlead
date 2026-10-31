//! fairlead host: edge, tunnel, admin, storage.

pub mod admin;
mod clipboard;
pub mod config;
pub mod db;
pub mod edge;
pub mod front;
pub mod landing;
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

/// The environment variable that carries the admin password.
///
/// Read once at startup: a systemd unit or a container sets it, and the host
/// hashes it into the database. A value that already matches the stored hash
/// changes nothing, so restarts do not sign anyone out.
pub const ADMIN_PASSWORD_ENV: &str = "FAIRLEAD_ADMIN_PASSWORD";

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
    /// `server.listen` is the front door for more than one plane.
    pub unified: bool,
    /// The admin plane is one of them (selected by `admin_host`). False when
    /// `admin_listen` gave it a socket of its own.
    pub admin_shared: bool,
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
            // A split admin plane still needs its own socket; binding it here
            // keeps a half-started host from leaving one listener behind.
            let admin = if cfg.server.admin_shared() {
                None
            } else {
                let bound = bind(cfg.server.admin_addr()).await?;
                anyhow::ensure!(
                    bound.1 != a,
                    "server.admin_listen resolved to the same address as server.listen ({a})"
                );
                Some(bound)
            };
            return Ok(Self { front: Some((l, a)), edge: None, tunnel: None, admin });
        }
        let (edge_l, edge_a) = bind(&cfg.server.edge_listen).await?;
        let (tunnel_l, tunnel_a) = bind(&cfg.server.tunnel_listen).await?;
        let (admin_l, admin_a) = bind(cfg.server.admin_addr()).await?;
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
    match cfg.landing.dir.as_deref() {
        None => {}
        Some(dir) => match landing::scan(dir) {
            Ok(a) if a.is_empty() => tracing::warn!(
                dir = %dir.display(),
                "landing.dir holds no fairlead-*.tar.gz yet: the page will render without downloads"
            ),
            Ok(a) => info!(
                dir = %dir.display(),
                artifacts = a.len(),
                "landing page on: hosts with no route get the download page"
            ),
            Err(e) => tracing::warn!(dir = %dir.display(), error = %e, "cannot read landing.dir"),
        },
    }
    let metrics = Arc::new(Metrics::default());
    metrics.mark_start();

    let db = Arc::new(db::Db::open(&cfg.server.database).await.context("open database")?);
    if db.ensure_admin_password(&cfg.admin.password_hash).await? {
        info!("seeded the admin password from [admin].password_hash (legacy; prefer {ADMIN_PASSWORD_ENV})");
    }
    match admin_password_from_env(&db).await {
        Ok(Some(true)) => info!(
            "{ADMIN_PASSWORD_ENV}: admin password replaced, every admin session signed out"
        ),
        Ok(Some(false)) => tracing::debug!("{ADMIN_PASSWORD_ENV}: password already current"),
        Ok(None) => {}
        Err(e) => return Err(e.context(format!("apply {ADMIN_PASSWORD_ENV}"))),
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
        admin_shared: cfg.server.admin_shared(),
    });

    let mut tasks = Vec::new();
    let app = admin::router(state.clone());

    match bound.front {
        Some((listener, addr)) if state.admin_shared => {
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
                Some(admin_tx),
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
        }
        Some((listener, addr)) => {
            // `listen` carries the tunnel and edge planes; the admin plane has
            // a socket of its own, so a `Host` naming it here reaches nothing.
            let (admin_listener, admin_bound) = bound.admin.expect("admin listener");
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
            tasks.push(tokio::spawn(front::accept_loop(
                state.clone(),
                listener,
                None,
                shutdown_rx.clone(),
            )));
            info!(
                listen = %addr,
                tunnel_host = %cfg.server.tunnel_host,
                admin = %admin_bound,
                "fairlead host listening: tunnel by virtual host and everything else is edge on one port, admin on its own"
            );
            if !admin_bound.ip().is_loopback() && !cfg.admin.secure_cookie {
                tracing::warn!(
                    admin = %admin_bound,
                    "admin UI is reachable from the network over plain HTTP; terminate TLS in front of it and set admin.secure_cookie=true"
                );
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

    if db.admin().await.map(|a| a.is_none()).unwrap_or(true) {
        tracing::warn!(
            "no admin password yet: the admin UI refuses logins — set {ADMIN_PASSWORD_ENV} at startup or run `fairlead admin passwd`"
        );
    }

    Ok(Host { state, shutdown: shutdown_tx, tasks })
}

/// Apply `FAIRLEAD_ADMIN_PASSWORD` when it is set.
///
/// `Ok(None)` means the variable is absent (the database password stands);
/// `Ok(Some(true))` means the stored hash was replaced.
async fn admin_password_from_env(db: &db::Db) -> anyhow::Result<Option<bool>> {
    match std::env::var(ADMIN_PASSWORD_ENV) {
        Ok(value) if value.is_empty() => anyhow::bail!("{ADMIN_PASSWORD_ENV} is set but empty"),
        Ok(value) => set_admin_password(db, &value).await.map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => anyhow::bail!("{ADMIN_PASSWORD_ENV}: {e}"),
    }
}

/// Store `password` unless it already opens the door. Returns whether the
/// stored hash changed.
async fn set_admin_password(db: &db::Db, password: &str) -> anyhow::Result<bool> {
    anyhow::ensure!(
        password.chars().count() >= 10,
        "{ADMIN_PASSWORD_ENV} must be at least 10 characters"
    );
    if let Some(account) = db.admin().await? {
        if password_matches(password, &account.password_hash).await {
            return Ok(false);
        }
    }
    let owned = password.to_string();
    let hash = tokio::task::spawn_blocking(move || db::hash_password(&owned)).await??;
    db.admin_set_hash(&hash).await?;
    Ok(true)
}

async fn password_matches(password: &str, hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let (password, hash) = (password.to_string(), hash.to_string());
    tokio::task::spawn_blocking(move || match PasswordHash::new(&hash) {
        Ok(parsed) => argon2::Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    })
    .await
    .unwrap_or(false)
}

async fn bind(addr: &str) -> anyhow::Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    let local = listener.local_addr()?;
    Ok((listener, local))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_startup_password_is_stored_once_and_never_rehashed_in_vain() {
        let dir = std::env::temp_dir().join(format!("fairlead-envpw-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = db::Db::open(&dir.join("fairlead.db")).await.unwrap();

        assert!(set_admin_password(&db, "a long enough password").await.unwrap());
        let first = db.admin().await.unwrap().unwrap().password_hash;
        assert!(password_matches("a long enough password", &first).await);

        // The same value again is a no-op: restarts must not sign people out.
        assert!(!set_admin_password(&db, "a long enough password").await.unwrap());
        assert_eq!(db.admin().await.unwrap().unwrap().password_hash, first);

        // A different value replaces the hash, and the old one stops working.
        assert!(set_admin_password(&db, "another long password").await.unwrap());
        let second = db.admin().await.unwrap().unwrap().password_hash;
        assert_ne!(second, first);
        assert!(password_matches("another long password", &second).await);
        assert!(!password_matches("a long enough password", &second).await);

        // Too short is a startup error, not a quietly weaker door.
        assert!(set_admin_password(&db, "short").await.is_err());

        std::fs::remove_dir_all(&dir).ok();
    }
}
