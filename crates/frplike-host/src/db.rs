//! SQLite persistence with a single writer.
//!
//! Every mutation funnels through one OS thread holding the only
//! `rusqlite::Connection`. That makes `SQLITE_BUSY` structurally impossible and
//! gives request-log batching for free. Reads on the edge path never touch the
//! database: the route table is an in-memory snapshot rebuilt after writes.

use std::path::Path;
use std::thread;

use anyhow::{anyhow, Context};
use frplike_proto::control::{AcceptedRoute, RejectedRoute, RouteDecl};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

use crate::metrics::{now_unix, now_unix_ms};

#[derive(Debug, Clone)]
pub struct RouteRow {
    pub id: String,
    pub public_host: String,
    pub agent_id: String,
    pub target: String,
    pub enabled: bool,
    pub deleted_at: Option<i64>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct AgentRow {
    pub id: String,
    pub name: String,
    pub version: String,
    pub status: String,
    pub last_seen_at: Option<i64>,
    pub allowed_suffix: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct RequestLogRow {
    pub ts: i64,
    pub request_id: String,
    pub host: Option<String>,
    pub route_id: Option<String>,
    pub agent_id: Option<String>,
    pub status: i64,
    pub duration_ms: i64,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditRow {
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthGrant {
    pub agent_id: String,
    pub agent_name: String,
    pub allowed_suffix: Option<String>,
    /// Set exactly once, when a one-time enrollment token was consumed.
    pub fresh_credential: Option<String>,
}

#[derive(Debug, Clone)]
pub enum AuthOutcome {
    Ok(AuthGrant),
    Reject { code: &'static str, message: String },
}

type Reply<T> = oneshot::Sender<anyhow::Result<T>>;

enum Cmd {
    Authenticate {
        secret: String,
        is_token: bool,
        name: String,
        version: String,
        reply: Reply<AuthOutcome>,
    },
    RegisterRoutes {
        agent_id: String,
        agent_suffix: Option<String>,
        decls: Vec<RouteDecl>,
        reply: Reply<(Vec<AcceptedRoute>, Vec<RejectedRoute>)>,
    },
    Routes {
        reply: Reply<Vec<RouteRow>>,
    },
    Agents {
        reply: Reply<Vec<AgentRow>>,
    },
    SetRouteEnabled {
        id: String,
        enabled: bool,
        reply: Reply<bool>,
    },
    DeleteRoute {
        id: String,
        reply: Reply<bool>,
    },
    RestoreRoute {
        id: String,
        reply: Reply<bool>,
    },
    RevokeAgent {
        id: String,
        reply: Reply<bool>,
    },
    TouchAgent {
        id: String,
        online: bool,
        reply: Reply<()>,
    },
    CreateToken {
        suffix: String,
        ttl_secs: Option<u64>,
        note: String,
        reply: Reply<String>,
    },
    RevokeToken {
        id: String,
        reply: Reply<bool>,
    },
    RecentLogs {
        limit: u32,
        reply: Reply<Vec<RequestLogRow>>,
    },
    Audit {
        limit: u32,
        reply: Reply<Vec<AuditRow>>,
    },
    AuditWrite {
        actor: String,
        action: String,
        detail: String,
    },
    /// Fire-and-forget, bounded, droppable.
    Log(Box<RequestLogRow>),
}

#[derive(Clone)]
pub struct Db {
    tx: mpsc::Sender<Cmd>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Db {
    pub async fn open(path: &Path) -> anyhow::Result<Db> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let (init_tx, init_rx) = std::sync::mpsc::sync_channel::<anyhow::Result<()>>(1);
        let (tx, rx) = mpsc::channel::<Cmd>(4096);
        let p = path.to_path_buf();
        thread::Builder::new()
            .name("frplike-db".into())
            .spawn(move || match open_and_migrate(&p) {
                Ok(conn) => {
                    let _ = init_tx.send(Ok(()));
                    writer_loop(conn, rx);
                }
                Err(e) => {
                    let _ = init_tx.send(Err(e));
                }
            })
            .context("spawn db writer thread")?;
        init_rx.recv().context("db writer thread did not start")??;
        Ok(Db { tx, dropped: Default::default() })
    }

    async fn call<T>(&self, make: impl FnOnce(Reply<T>) -> Cmd) -> anyhow::Result<T> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(make(tx)).await.map_err(|_| anyhow!("database writer is gone"))?;
        rx.await.map_err(|_| anyhow!("database writer dropped the reply"))?
    }

    pub async fn authenticate(
        &self,
        secret: &str,
        is_token: bool,
        name: &str,
        version: &str,
    ) -> anyhow::Result<AuthOutcome> {
        self.call(|reply| Cmd::Authenticate {
            secret: secret.to_string(),
            is_token,
            name: name.to_string(),
            version: version.to_string(),
            reply,
        })
        .await
    }

    pub async fn register_routes(
        &self,
        agent_id: &str,
        agent_suffix: Option<&str>,
        decls: &[RouteDecl],
    ) -> anyhow::Result<(Vec<AcceptedRoute>, Vec<RejectedRoute>)> {
        self.call(|reply| Cmd::RegisterRoutes {
            agent_id: agent_id.to_string(),
            agent_suffix: agent_suffix.map(|s| s.to_string()),
            decls: decls.to_vec(),
            reply,
        })
        .await
    }

    pub async fn routes(&self) -> anyhow::Result<Vec<RouteRow>> {
        self.call(|reply| Cmd::Routes { reply }).await
    }

    pub async fn agents(&self) -> anyhow::Result<Vec<AgentRow>> {
        self.call(|reply| Cmd::Agents { reply }).await
    }

    pub async fn set_route_enabled(&self, id: &str, enabled: bool) -> anyhow::Result<bool> {
        self.call(|reply| Cmd::SetRouteEnabled { id: id.to_string(), enabled, reply }).await
    }

    pub async fn delete_route(&self, id: &str) -> anyhow::Result<bool> {
        self.call(|reply| Cmd::DeleteRoute { id: id.to_string(), reply }).await
    }

    pub async fn restore_route(&self, id: &str) -> anyhow::Result<bool> {
        self.call(|reply| Cmd::RestoreRoute { id: id.to_string(), reply }).await
    }

    pub async fn revoke_agent(&self, id: &str) -> anyhow::Result<bool> {
        self.call(|reply| Cmd::RevokeAgent { id: id.to_string(), reply }).await
    }

    pub async fn set_agent_online(&self, id: &str, online: bool) -> anyhow::Result<()> {
        self.call(|reply| Cmd::TouchAgent { id: id.to_string(), online, reply }).await
    }

    pub async fn create_token(
        &self,
        suffix: &str,
        ttl_secs: Option<u64>,
        note: &str,
    ) -> anyhow::Result<String> {
        self.call(|reply| Cmd::CreateToken {
            suffix: suffix.to_string(),
            ttl_secs,
            note: note.to_string(),
            reply,
        })
        .await
    }

    pub async fn revoke_token(&self, id: &str) -> anyhow::Result<bool> {
        self.call(|reply| Cmd::RevokeToken { id: id.to_string(), reply }).await
    }

    pub async fn recent_logs(&self, limit: u32) -> anyhow::Result<Vec<RequestLogRow>> {
        self.call(|reply| Cmd::RecentLogs { limit, reply }).await
    }

    pub async fn audit(&self, limit: u32) -> anyhow::Result<Vec<AuditRow>> {
        self.call(|reply| Cmd::Audit { limit, reply }).await
    }

    /// Never blocks the data path; drops and counts when the queue is full.
    pub fn log(&self, row: RequestLogRow) {
        if self.tx.try_send(Cmd::Log(Box::new(row))).is_err() {
            self.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn dropped_logs(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn audit_write(&self, actor: &str, action: &str, detail: &str) {
        let _ = self.tx.try_send(Cmd::AuditWrite {
            actor: actor.to_string(),
            action: action.to_string(),
            detail: detail.to_string(),
        });
    }
}

fn open_and_migrate(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            status TEXT NOT NULL,
            last_seen_at INTEGER,
            allowed_suffix TEXT,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS credentials (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            revoked_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_credentials_agent ON credentials(agent_id);
        CREATE TABLE IF NOT EXISTS enrollment_tokens (
            id TEXT PRIMARY KEY,
            hash TEXT NOT NULL UNIQUE,
            allowed_suffix TEXT NOT NULL,
            expires_at INTEGER,
            used_at INTEGER,
            used_agent_id TEXT,
            revoked_at INTEGER,
            note TEXT,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS routes (
            id TEXT PRIMARY KEY,
            public_host TEXT NOT NULL UNIQUE,
            agent_id TEXT NOT NULL,
            target TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            deleted_at INTEGER,
            last_error TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_routes_agent ON routes(agent_id);
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            request_id TEXT NOT NULL,
            host TEXT,
            route_id TEXT,
            agent_id TEXT,
            status INTEGER,
            duration_ms INTEGER,
            bytes_up INTEGER,
            bytes_down INTEGER,
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_request_logs_ts ON request_logs(ts);
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT
        );
        PRAGMA user_version = 1;
        "#,
    )?;
    Ok(conn)
}

fn writer_loop(mut conn: Connection, mut rx: mpsc::Receiver<Cmd>) {
    while let Some(first) = rx.blocking_recv() {
        let mut batch = vec![first];
        while batch.len() < 256 {
            match rx.try_recv() {
                Ok(c) => batch.push(c),
                Err(_) => break,
            }
        }
        let mut logs: Vec<RequestLogRow> = Vec::new();
        for cmd in batch {
            match cmd {
                Cmd::Log(row) => logs.push(*row),
                other => {
                    if !logs.is_empty() {
                        if let Err(e) = flush_logs(&mut conn, &mut logs) {
                            tracing::warn!(error = %e, "request log batch failed");
                            logs.clear();
                        }
                    }
                    if let Err(e) = handle(&mut conn, other) {
                        tracing::warn!(error = %e, "database command failed");
                    }
                }
            }
        }
        if !logs.is_empty() {
            if let Err(e) = flush_logs(&mut conn, &mut logs) {
                tracing::warn!(error = %e, "request log batch failed");
            }
        }
    }
}

fn flush_logs(conn: &mut Connection, logs: &mut Vec<RequestLogRow>) -> anyhow::Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO request_logs (ts, request_id, host, route_id, agent_id, status, duration_ms, bytes_up, bytes_down, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?;
        for l in logs.iter() {
            stmt.execute(params![
                l.ts,
                l.request_id,
                l.host,
                l.route_id,
                l.agent_id,
                l.status,
                l.duration_ms,
                l.bytes_up,
                l.bytes_down,
                l.error
            ])?;
        }
    }
    tx.commit()?;
    logs.clear();
    Ok(())
}

fn handle(conn: &mut Connection, cmd: Cmd) -> anyhow::Result<()> {
    match cmd {
        Cmd::Log(_) => unreachable!("logs are batched before handle()"),
        Cmd::Authenticate { secret, is_token, name, version, reply } => {
            let out = do_authenticate(conn, &secret, is_token, &name, &version);
            let _ = reply.send(out);
        }
        Cmd::RegisterRoutes { agent_id, agent_suffix, decls, reply } => {
            let out = do_register_routes(conn, &agent_id, agent_suffix.as_deref(), &decls);
            let _ = reply.send(out);
        }
        Cmd::Routes { reply } => {
            let out = (|| -> anyhow::Result<Vec<RouteRow>> {
                let mut stmt = conn.prepare(
                    "SELECT id, public_host, agent_id, target, enabled, deleted_at, last_error, created_at, updated_at FROM routes ORDER BY public_host",
                )?;
                let rows = stmt
                    .query_map([], |r| {
                        Ok(RouteRow {
                            id: r.get(0)?,
                            public_host: r.get(1)?,
                            agent_id: r.get(2)?,
                            target: r.get(3)?,
                            enabled: r.get::<_, i64>(4)? != 0,
                            deleted_at: r.get(5)?,
                            last_error: r.get(6)?,
                            created_at: r.get(7)?,
                            updated_at: r.get(8)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })();
            let _ = reply.send(out);
        }
        Cmd::Agents { reply } => {
            let out = (|| -> anyhow::Result<Vec<AgentRow>> {
                let mut stmt = conn.prepare(
                    "SELECT id, name, version, status, last_seen_at, allowed_suffix, created_at FROM agents ORDER BY name",
                )?;
                let rows = stmt
                    .query_map([], |r| {
                        Ok(AgentRow {
                            id: r.get(0)?,
                            name: r.get(1)?,
                            version: r.get(2)?,
                            status: r.get(3)?,
                            last_seen_at: r.get(4)?,
                            allowed_suffix: r.get(5)?,
                            created_at: r.get(6)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })();
            let _ = reply.send(out);
        }
        Cmd::SetRouteEnabled { id, enabled, reply } => {
            let n = conn.execute(
                "UPDATE routes SET enabled = ?2, updated_at = ?3 WHERE id = ?1 AND deleted_at IS NULL",
                params![id, enabled as i64, now_unix()],
            )?;
            let _ = reply.send(Ok(n > 0));
        }
        Cmd::DeleteRoute { id, reply } => {
            let n = conn.execute(
                "UPDATE routes SET deleted_at = ?2, updated_at = ?2 WHERE id = ?1 AND deleted_at IS NULL",
                params![id, now_unix()],
            )?;
            let _ = reply.send(Ok(n > 0));
        }
        Cmd::RestoreRoute { id, reply } => {
            let n = conn.execute(
                "UPDATE routes SET deleted_at = NULL, enabled = 1, updated_at = ?2 WHERE id = ?1",
                params![id, now_unix()],
            )?;
            let _ = reply.send(Ok(n > 0));
        }
        Cmd::RevokeAgent { id, reply } => {
            conn.execute(
                "UPDATE agents SET status = 'revoked' WHERE id = ?1",
                params![id],
            )?;
            conn.execute(
                "UPDATE credentials SET revoked_at = ?2 WHERE agent_id = ?1 AND revoked_at IS NULL",
                params![id, now_unix()],
            )?;
            let _ = reply.send(Ok(true));
        }
        Cmd::TouchAgent { id, online, reply } => {
            conn.execute(
                "UPDATE agents SET status = ?2, last_seen_at = ?3 WHERE id = ?1 AND status != 'revoked'",
                params![id, if online { "online" } else { "offline" }, now_unix()],
            )?;
            let _ = reply.send(Ok(()));
        }
        Cmd::CreateToken { suffix, ttl_secs, note, reply } => {
            let out = (|| -> anyhow::Result<String> {
                let token = random_secret();
                let hash = hash_secret(&token);
                let now = now_unix();
                let expires = ttl_secs.map(|t| now_s() + t as i64);
                conn.execute(
                    "INSERT INTO enrollment_tokens (id, hash, allowed_suffix, expires_at, note, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![uuid::Uuid::new_v4().to_string(), hash, suffix, expires, note, now],
                )?;
                Ok(token)
            })();
            let _ = reply.send(out);
        }
        Cmd::RevokeToken { id, reply } => {
            let n = conn.execute(
                "UPDATE enrollment_tokens SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
                params![id, now_unix()],
            )?;
            let _ = reply.send(Ok(n > 0));
        }
        Cmd::RecentLogs { limit, reply } => {
            let out = (|| -> anyhow::Result<Vec<RequestLogRow>> {
                let mut stmt = conn.prepare(
                    "SELECT ts, request_id, host, route_id, agent_id, status, duration_ms, bytes_up, bytes_down, error
                     FROM request_logs ORDER BY id DESC LIMIT ?1",
                )?;
                let rows = stmt
                    .query_map([limit], |r| {
                        Ok(RequestLogRow {
                            ts: r.get(0)?,
                            request_id: r.get(1)?,
                            host: r.get(2)?,
                            route_id: r.get(3)?,
                            agent_id: r.get(4)?,
                            status: r.get(5)?,
                            duration_ms: r.get(6)?,
                            bytes_up: r.get(7)?,
                            bytes_down: r.get(8)?,
                            error: r.get(9)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })();
            let _ = reply.send(out);
        }
        Cmd::Audit { limit, reply } => {
            let out = (|| -> anyhow::Result<Vec<AuditRow>> {
                let mut stmt = conn.prepare(
                    "SELECT ts, actor, action, detail FROM audit_logs ORDER BY id DESC LIMIT ?1",
                )?;
                let rows = stmt
                    .query_map([limit], |r| {
                        Ok(AuditRow {
                            ts: r.get(0)?,
                            actor: r.get(1)?,
                            action: r.get(2)?,
                            detail: r.get(3)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })();
            let _ = reply.send(out);
        }
        Cmd::AuditWrite { actor, action, detail } => {
            conn.execute(
                "INSERT INTO audit_logs (ts, actor, action, detail) VALUES (?1, ?2, ?3, ?4)",
                params![now_unix(), actor, action, detail],
            )?;
        }
    }
    Ok(())
}

fn do_authenticate(
    conn: &Connection,
    secret: &str,
    is_token: bool,
    name: &str,
    version: &str,
) -> anyhow::Result<AuthOutcome> {
    let hash = hash_secret(secret);
    let now = now_unix();
    if is_token {
        let row: Option<(String, String, Option<i64>, Option<i64>, Option<i64>)> = conn
            .query_row(
                "SELECT id, allowed_suffix, expires_at, used_at, revoked_at FROM enrollment_tokens WHERE hash = ?1",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let Some((token_id, suffix, expires_at, used_at, revoked_at)) = row else {
            return Ok(AuthOutcome::Reject { code: "invalid_credential", message: "unknown enrollment token".into() });
        };
        if revoked_at.is_some() {
            return Ok(AuthOutcome::Reject { code: "revoked", message: "enrollment token revoked".into() });
        }
        if used_at.is_some() {
            return Ok(AuthOutcome::Reject {
                code: "token_used",
                message: "enrollment token already used; enroll once, then reuse the issued credential".into(),
            });
        }
        if expires_at.is_some_and(|e| e <= now_s()) {
            return Ok(AuthOutcome::Reject { code: "token_expired", message: "enrollment token expired".into() });
        }
        let agent_id = uuid::Uuid::new_v4().to_string();
        let credential = random_secret();
        let name = if name.trim().is_empty() { "agent".to_string() } else { name.trim().to_string() };
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO agents (id, name, version, status, last_seen_at, allowed_suffix, created_at) VALUES (?1, ?2, ?3, 'online', ?4, ?5, ?4)",
            params![agent_id, name, version, now, suffix],
        )?;
        tx.execute(
            "INSERT INTO credentials (id, agent_id, hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![uuid::Uuid::new_v4().to_string(), agent_id, hash_secret(&credential), now],
        )?;
        tx.execute(
            "UPDATE enrollment_tokens SET used_at = ?2, used_agent_id = ?3 WHERE id = ?1",
            params![token_id, now, agent_id],
        )?;
        tx.commit()?;
        Ok(AuthOutcome::Ok(AuthGrant {
            agent_id,
            agent_name: name,
            allowed_suffix: Some(suffix),
            fresh_credential: Some(credential),
        }))
    } else {
        let row: Option<(String, String, Option<String>, String, Option<i64>)> = conn
            .query_row(
                "SELECT a.id, a.name, a.allowed_suffix, a.status, c.revoked_at
                 FROM credentials c JOIN agents a ON a.id = c.agent_id
                 WHERE c.hash = ?1",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let Some((agent_id, agent_name, suffix, status, revoked_at)) = row else {
            return Ok(AuthOutcome::Reject { code: "invalid_credential", message: "unknown credential".into() });
        };
        if revoked_at.is_some() || status == "revoked" {
            return Ok(AuthOutcome::Reject { code: "revoked", message: "credential revoked".into() });
        }
        conn.execute(
            "UPDATE agents SET status = 'online', last_seen_at = ?2, version = ?3 WHERE id = ?1",
            params![agent_id, now, version],
        )?;
        Ok(AuthOutcome::Ok(AuthGrant {
            agent_id,
            agent_name,
            allowed_suffix: suffix,
            fresh_credential: None,
        }))
    }
}

const MAX_ROUTES_PER_AGENT: usize = 500;

fn do_register_routes(
    conn: &mut Connection,
    agent_id: &str,
    agent_suffix: Option<&str>,
    decls: &[RouteDecl],
) -> anyhow::Result<(Vec<AcceptedRoute>, Vec<RejectedRoute>)> {
    let now = now_s();
    let tx = conn.transaction()?;
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let allowed: Vec<String> = match agent_suffix {
        Some(s) => vec![s.trim_start_matches('.').to_ascii_lowercase()],
        None => Vec::new(),
    };
    for (i, decl) in decls.iter().enumerate() {
        if i >= MAX_ROUTES_PER_AGENT {
            rejected.push(RejectedRoute {
                host: decl.host.clone(),
                target: decl.target.clone(),
                reason: "too_many_routes".into(),
            });
            continue;
        }
        let host = match frplike_proto::hostname::normalize(&decl.host) {
            Ok(h) => h,
            Err(e) => {
                rejected.push(RejectedRoute {
                    host: decl.host.clone(),
                    target: decl.target.clone(),
                    reason: format!("invalid_host: {e}"),
                });
                continue;
            }
        };
        if !allowed.is_empty() && !frplike_proto::hostname::matches_suffix(&host, &allowed) {
            rejected.push(RejectedRoute {
                host,
                target: decl.target.clone(),
                reason: "suffix_not_allowed".into(),
            });
            continue;
        }
        if let Err(e) = frplike_proto::control::validate_target(&decl.target) {
            rejected.push(RejectedRoute { host, target: decl.target.clone(), reason: e.into() });
            continue;
        }
        let existing: Option<(String, String, bool, Option<i64>)> = tx
            .query_row(
                "SELECT id, agent_id, enabled, deleted_at FROM routes WHERE public_host = ?1",
                [&host],
                |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0, r.get(3)?)),
            )
            .optional()?;
        match existing {
            Some((id, owner, enabled, deleted_at)) => {
                if owner != agent_id {
                    rejected.push(RejectedRoute { host, target: decl.target.clone(), reason: "conflict".into() });
                    continue;
                }
                if deleted_at.is_some() {
                    rejected.push(RejectedRoute {
                        host,
                        target: decl.target.clone(),
                        reason: "deleted_by_admin".into(),
                    });
                    continue;
                }
                if !enabled {
                    // Admin intent wins; keep the row, tell the agent it is not serving.
                    rejected.push(RejectedRoute {
                        host,
                        target: decl.target.clone(),
                        reason: "disabled_by_admin".into(),
                    });
                    continue;
                }
                tx.execute(
                    "UPDATE routes SET target = ?2, updated_at = ?3, last_error = NULL WHERE id = ?1",
                    params![id, decl.target, now],
                )?;
                accepted.push(AcceptedRoute { host, route_id: id, target: decl.target.clone() });
            }
            None => {
                let id = uuid::Uuid::new_v4().to_string();
                tx.execute(
                    "INSERT INTO routes (id, public_host, agent_id, target, enabled, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)",
                    params![id, host, agent_id, decl.target, now],
                )?;
                accepted.push(AcceptedRoute { host, route_id: id, target: decl.target.clone() });
            }
        }
    }
    tx.commit()?;
    Ok((accepted, rejected))
}

fn now_s() -> i64 {
    now_unix() as i64
}

fn random_secret() -> String {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn hash_secret(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    hex::encode(h.finalize())
}

/// Housekeeping at startup: keep the request log bounded and fresh.
pub async fn prune_request_logs(path: &Path, retention_days: u64) -> anyhow::Result<()> {
    let cutoff = now_unix_ms() / 1000 - (retention_days as i64 * 86_400).max(3600);
    let p = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let conn = Connection::open(p)?;
        conn.execute("DELETE FROM request_logs WHERE ts < ?1", [cutoff])?;
        conn.execute(
            "DELETE FROM request_logs WHERE id NOT IN (SELECT id FROM request_logs ORDER BY id DESC LIMIT 200000)",
            [],
        )?;
        Ok(())
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempdir::Dir {
        tempdir::Dir::new()
    }

    /// Minimal temp-dir helper so tests do not need another dependency.
    mod tempdir {
        pub struct Dir(pub std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let p = std::env::temp_dir().join(format!("frplike-db-{}", uuid::Uuid::new_v4()));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
            pub fn path(&self) -> std::path::PathBuf {
                self.0.join("frplike.db")
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).ok();
            }
        }
    }

    #[tokio::test]
    async fn token_enrolls_once_then_credential_works() {
        let d = tmp();
        let db = Db::open(&d.path()).await.unwrap();
        let token = db.create_token("relay.test", None, "t").await.unwrap();

        let first = db.authenticate(&token, true, "a1", "0.1.0").await.unwrap();
        let AuthOutcome::Ok(grant) = first else { panic!("expected grant: {first:?}") };
        let credential = grant.fresh_credential.clone().unwrap();

        let again = db.authenticate(&token, true, "a1", "0.1.0").await.unwrap();
        assert!(matches!(again, AuthOutcome::Reject { code: "token_used", .. }));

        let by_cred = db.authenticate(&credential, false, "a1", "0.1.0").await.unwrap();
        assert!(matches!(by_cred, AuthOutcome::Ok(_)));

        db.revoke_agent(&grant.agent_id).await.unwrap();
        let after = db.authenticate(&credential, false, "a1", "0.1.0").await.unwrap();
        assert!(matches!(after, AuthOutcome::Reject { code: "revoked", .. }));
    }

    #[tokio::test]
    async fn admin_intent_survives_agent_redeclaration() {
        let d = tmp();
        let db = Db::open(&d.path()).await.unwrap();
        let token = db.create_token("relay.test", None, "t").await.unwrap();
        let AuthOutcome::Ok(grant) = db.authenticate(&token, true, "a1", "0.1.0").await.unwrap() else {
            panic!()
        };
        let decl = vec![RouteDecl { host: "a1.relay.test".into(), target: "127.0.0.1:7884".into() }];
        let (acc, rej) = db.register_routes(&grant.agent_id, Some("relay.test"), &decl).await.unwrap();
        assert_eq!(acc.len(), 1);
        assert!(rej.is_empty());

        let routes = db.routes().await.unwrap();
        db.delete_route(&routes[0].id).await.unwrap();
        let (acc, rej) = db.register_routes(&grant.agent_id, Some("relay.test"), &decl).await.unwrap();
        assert!(acc.is_empty());
        assert_eq!(rej[0].reason, "deleted_by_admin");

        db.restore_route(&routes[0].id).await.unwrap();
        let (acc, _) = db.register_routes(&grant.agent_id, Some("relay.test"), &decl).await.unwrap();
        assert_eq!(acc.len(), 1);
    }

    #[tokio::test]
    async fn second_agent_cannot_steal_a_host() {
        let d = tmp();
        let db = Db::open(&d.path()).await.unwrap();
        let t1 = db.create_token("relay.test", None, "a").await.unwrap();
        let t2 = db.create_token("relay.test", None, "b").await.unwrap();
        let AuthOutcome::Ok(a) = db.authenticate(&t1, true, "a", "1").await.unwrap() else { panic!() };
        let AuthOutcome::Ok(b) = db.authenticate(&t2, true, "b", "1").await.unwrap() else { panic!() };
        let decl = vec![RouteDecl { host: "same.relay.test".into(), target: "127.0.0.1:1".into() }];
        assert_eq!(db.register_routes(&a.agent_id, Some("relay.test"), &decl).await.unwrap().0.len(), 1);
        let (acc, rej) = db.register_routes(&b.agent_id, Some("relay.test"), &decl).await.unwrap();
        assert!(acc.is_empty());
        assert_eq!(rej[0].reason, "conflict");
    }

    #[tokio::test]
    async fn suffix_is_enforced() {
        let d = tmp();
        let db = Db::open(&d.path()).await.unwrap();
        let token = db.create_token("a.relay.test", None, "t").await.unwrap();
        let AuthOutcome::Ok(g) = db.authenticate(&token, true, "a", "1").await.unwrap() else { panic!() };
        let decl = vec![
            RouteDecl { host: "x.relay.test".into(), target: "127.0.0.1:1".into() },
            RouteDecl { host: "x.a.relay.test".into(), target: "127.0.0.1:1".into() },
        ];
        let (acc, rej) = db.register_routes(&g.agent_id, Some("a.relay.test"), &decl).await.unwrap();
        assert_eq!(acc.len(), 1);
        assert_eq!(acc[0].host, "x.a.relay.test");
        assert_eq!(rej[0].reason, "suffix_not_allowed");
    }
}
