//! Host configuration (`frplike-host.toml`).
//!
//! `deny_unknown_fields` is deliberate: a typo in a security-relevant key
//! (`tls.cert`, `allowed_suffixes`) must fail loudly at startup, not silently
//! fall back to a default.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostConfig {
    pub server: ServerSection,
    pub admin: AdminSection,
    pub tls: TlsSection,
    pub limits: LimitsSection,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            server: ServerSection::default(),
            admin: AdminSection::default(),
            tls: TlsSection::default(),
            limits: LimitsSection::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSection {
    /// Nginx upstream. Bound to loopback by default on purpose.
    pub edge_listen: String,
    /// Agent control listener.
    pub tunnel_listen: String,
    /// Admin UI/API listener.
    pub admin_listen: String,
    pub database: PathBuf,
    /// Every route host must be one of these (or a subdomain of one).
    pub allowed_suffixes: Vec<String>,
    /// Escape hatch: allow `edge_listen` on a non-loopback address.
    pub allow_public_edge: bool,
    /// `frplike gen-nginx` and the doctor command read this.
    pub public_port: u16,
    pub public_scheme: String,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            edge_listen: "127.0.0.1:9000".into(),
            tunnel_listen: "0.0.0.0:9443".into(),
            admin_listen: "127.0.0.1:9001".into(),
            database: PathBuf::from("frplike.db"),
            allowed_suffixes: Vec::new(),
            allow_public_edge: false,
            public_port: 8080,
            public_scheme: "http".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminSection {
    /// Deprecated: migrated to the first account (`admin`) on startup.
    /// Real accounts live in SQLite and are managed with `frplike admin`.
    pub password_hash: String,
    pub session_ttl_secs: u64,
    /// Set when the admin UI is served over HTTPS (behind a TLS terminator).
    pub secure_cookie: bool,
    /// Allow `admin_listen` on a non-loopback address. Off by default: an
    /// admin UI reachable from the internet is a bigger risk than a tunnel.
    pub allow_remote: bool,
    /// Take the client address from `X-Real-IP` / `X-Forwarded-For`.
    /// Only enable behind a proxy you control, never on a directly exposed port.
    pub trust_forwarded_for: bool,
}

impl Default for AdminSection {
    fn default() -> Self {
        Self {
            password_hash: String::new(),
            session_ttl_secs: 12 * 3600,
            secure_cookie: false,
            allow_remote: false,
            trust_forwarded_for: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsSection {
    /// PEM certificate chain for the tunnel listener.
    pub cert: Option<PathBuf>,
    /// PEM private key for the tunnel listener.
    pub key: Option<PathBuf>,
    /// Generate an in-memory self-signed certificate when cert/key are absent.
    /// Meant for development and tests; the fingerprint is printed at startup.
    pub dev_self_signed: bool,
}

impl Default for TlsSection {
    fn default() -> Self {
        Self { cert: None, key: None, dev_self_signed: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsSection {
    pub max_head_bytes: usize,
    pub max_streams_per_connection: usize,
    pub max_tunnels_per_agent: u8,
    pub handshake_timeout_secs: u64,
    pub head_timeout_secs: u64,
    pub dial_timeout_secs: u64,
    pub dial_wait_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub upgrade_idle_timeout_secs: u64,
    pub heartbeat_secs: u64,
    pub heartbeat_timeout_secs: u64,
    pub request_log_capacity: usize,
    pub request_log_retention_days: u64,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_head_bytes: 16 * 1024,
            max_streams_per_connection: 2048,
            max_tunnels_per_agent: 4,
            handshake_timeout_secs: 10,
            head_timeout_secs: 10,
            dial_timeout_secs: 5,
            dial_wait_timeout_secs: 10,
            idle_timeout_secs: 120,
            upgrade_idle_timeout_secs: 300,
            heartbeat_secs: 10,
            heartbeat_timeout_secs: 30,
            request_log_capacity: 8192,
            request_log_retention_days: 7,
        }
    }
}

impl LimitsSection {
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout_secs.max(1))
    }
    pub fn dial_wait_timeout(&self) -> Duration {
        Duration::from_secs(self.dial_wait_timeout_secs.max(1))
    }
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs.max(1))
    }
    pub fn upgrade_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.upgrade_idle_timeout_secs.max(1))
    }
    pub fn heartbeat_timeout(&self) -> Duration {
        Duration::from_secs(self.heartbeat_timeout_secs.max(1))
    }
}

impl HostConfig {
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        let mut cfg: HostConfig = toml::from_str(text)?;
        cfg.server.allowed_suffixes = cfg
            .server
            .allowed_suffixes
            .iter()
            .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
            .collect();
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.server.allowed_suffixes.is_empty(),
            "server.allowed_suffixes must not be empty: a route suffix is the only thing stopping an agent from claiming arbitrary host names"
        );
        for s in &self.server.allowed_suffixes {
            anyhow::ensure!(
                frplike_proto::hostname::normalize(s).is_ok(),
                "invalid allowed suffix: {s}"
            );
        }
        anyhow::ensure!(
            self.server.public_port > 0,
            "server.public_port must be a real port"
        );
        anyhow::ensure!(
            self.admin.password_hash.is_empty() || self.admin.password_hash.starts_with("$argon2"),
            "admin.password_hash must be an argon2 PHC string (run `frplike passwd`)"
        );
        if !self.server.allow_public_edge {
            let addr: std::net::SocketAddr = self.server.edge_listen.parse()?;
            anyhow::ensure!(
                addr.ip().is_loopback(),
                "edge_listen={} is not loopback; set server.allow_public_edge=true only if you really mean to expose the host without nginx",
                addr
            );
        }
        let admin: std::net::SocketAddr = self.server.admin_listen.parse()?;
        anyhow::ensure!(
            admin.ip().is_loopback() || self.admin.allow_remote,
            "admin_listen={} is not loopback; set admin.allow_remote=true (and put TLS in front) if you mean to publish the admin UI",
            admin
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_keys() {
        let e = HostConfig::from_toml("[server]\nedge_lisen = \"127.0.0.1:1\"\n").unwrap_err();
        assert!(e.to_string().contains("edge_lisen"), "{e}");
    }

    #[test]
    fn rejects_public_edge_by_default() {
        let cfg = HostConfig::from_toml(
            "[server]\nedge_listen = \"0.0.0.0:9000\"\nallowed_suffixes = [\"r.test\"]\n",
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn admin_needs_allow_remote_for_non_loopback() {
        let base = "[server]\nallowed_suffixes = [\"r.test\"]\nadmin_listen = \"0.0.0.0:9001\"\n";
        let cfg = HostConfig::from_toml(base).unwrap();
        assert!(cfg.validate().is_err());
        let cfg = HostConfig::from_toml(&format!("{base}[admin]\nallow_remote = true\n")).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn accepts_sane_config() {
        let cfg = HostConfig::from_toml(
            "[server]\nallowed_suffixes = [\"relay.test\"]\n[admin]\npassword_hash = \"$argon2id$x\"\n",
        )
        .unwrap();
        cfg.validate().unwrap();
    }
}
