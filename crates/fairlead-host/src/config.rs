//! Host configuration (`fairlead-host.toml`).
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
    /// Unified front door: one listener, three planes selected by request
    /// host (`admin_host`, `tunnel_host`, everything else = edge).
    /// Empty means the legacy split layout with three separate sockets.
    pub listen: String,
    /// Virtual host that selects the admin plane on `listen`.
    pub admin_host: String,
    /// Virtual host that selects the tunnel plane on `listen`. Agents send it
    /// as the `Host` of their upgrade request.
    pub tunnel_host: String,
    /// Nginx upstream (split mode). Bound to loopback by default on purpose.
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
    /// `fairlead gen-nginx` and the doctor command read this.
    pub public_port: u16,
    pub public_scheme: String,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen: String::new(),
            admin_host: String::new(),
            tunnel_host: String::new(),
            edge_listen: "127.0.0.1:9000".into(),
            tunnel_listen: "0.0.0.0:9443".into(),
            admin_listen: "127.0.0.1:9001".into(),
            database: PathBuf::from("fairlead.db"),
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
    /// Real accounts live in SQLite and are managed with `fairlead admin`.
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

/// Which plane a request belongs to. Selected by the request `Host` when one
/// port serves everything, so the split between "public site traffic",
/// "agent control" and "management UI" survives the merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plane {
    Admin,
    Tunnel,
    Edge,
}

impl ServerSection {
    /// True when one listener serves all three planes.
    pub fn unified(&self) -> bool {
        !self.listen.trim().is_empty()
    }
}

impl HostConfig {
    /// Plane for an already-normalized host. In split mode each plane has its
    /// own socket, so everything that reaches the edge listener is `Edge`.
    pub fn plane_for(&self, host: &str) -> Plane {
        if !self.server.unified() {
            return Plane::Edge;
        }
        if !self.server.admin_host.is_empty() && host == self.server.admin_host {
            Plane::Admin
        } else if !self.server.tunnel_host.is_empty() && host == self.server.tunnel_host {
            Plane::Tunnel
        } else {
            Plane::Edge
        }
    }

    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        let mut cfg: HostConfig = toml::from_str(text)?;
        cfg.server.allowed_suffixes = cfg
            .server
            .allowed_suffixes
            .iter()
            .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
            .collect();
        // Virtual hosts are compared against a normalized `Host`, so they are
        // normalized once here: `Admin.Relay.Test.:9000` and `admin.relay.test`
        // must not be two different planes.
        for value in [&mut cfg.server.admin_host, &mut cfg.server.tunnel_host] {
            let raw = value.trim().to_string();
            if raw.is_empty() {
                value.clear();
                continue;
            }
            *value = fairlead_proto::hostname::normalize(&raw).unwrap_or(raw);
        }
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.server.allowed_suffixes.is_empty(),
            "server.allowed_suffixes must not be empty: a route suffix is the only thing stopping an agent from claiming arbitrary host names"
        );
        for s in &self.server.allowed_suffixes {
            anyhow::ensure!(
                fairlead_proto::hostname::normalize(s).is_ok(),
                "invalid allowed suffix: {s}"
            );
        }
        anyhow::ensure!(
            self.server.public_port > 0,
            "server.public_port must be a real port"
        );
        anyhow::ensure!(
            self.admin.password_hash.is_empty() || self.admin.password_hash.starts_with("$argon2"),
            "admin.password_hash must be an argon2 PHC string (run `fairlead passwd`)"
        );
        if self.server.unified() {
            let addr: std::net::SocketAddr = self
                .server
                .listen
                .parse()
                .map_err(|_| anyhow::anyhow!("server.listen is not an address:port"))?;
            for (key, value) in [
                ("admin_host", &self.server.admin_host),
                ("tunnel_host", &self.server.tunnel_host),
            ] {
                anyhow::ensure!(
                    !value.is_empty(),
                    "server.listen is set, so server.{key} must name the virtual host that selects that plane"
                );
            }
            anyhow::ensure!(
                self.server.admin_host != self.server.tunnel_host,
                "server.admin_host and server.tunnel_host must name different virtual hosts"
            );
            anyhow::ensure!(
                addr.ip().is_loopback() || self.admin.allow_remote,
                "server.listen={addr} publishes the admin plane; set admin.allow_remote=true (and put TLS in front) if you mean to do that"
            );
        } else {
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
        }
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
    fn unified_mode_needs_two_distinct_vhosts() {
        let base = "[server]\nlisten = \"127.0.0.1:9000\"\nallowed_suffixes = [\"r.test\"]\n";
        let cfg = HostConfig::from_toml(base).unwrap();
        assert!(cfg.validate().is_err(), "vhosts are required in unified mode");

        let cfg = HostConfig::from_toml(&format!(
            "{base}admin_host = \"admin.r.test\"\ntunnel_host = \"admin.r.test\"\n"
        ))
        .unwrap();
        assert!(cfg.validate().is_err(), "both planes must not share a host");

        let cfg = HostConfig::from_toml(&format!(
            "{base}admin_host = \"Admin.R.Test.:9000\"\ntunnel_host = \"tunnel.r.test\"\n"
        ))
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.server.admin_host, "admin.r.test");
        assert_eq!(cfg.plane_for("admin.r.test"), Plane::Admin);
        assert_eq!(cfg.plane_for("tunnel.r.test"), Plane::Tunnel);
        assert_eq!(cfg.plane_for("a1.r.test"), Plane::Edge);
    }

    #[test]
    fn unified_mode_on_a_public_address_needs_allow_remote() {
        let base = "[server]\nlisten = \"0.0.0.0:9000\"\nallowed_suffixes = [\"r.test\"]\nadmin_host = \"admin.r.test\"\ntunnel_host = \"tunnel.r.test\"\n";
        assert!(HostConfig::from_toml(base).unwrap().validate().is_err());
        let cfg = HostConfig::from_toml(&format!("{base}[admin]\nallow_remote = true\n")).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn split_mode_never_selects_admin_or_tunnel_by_host() {
        let cfg = HostConfig::from_toml(
            "[server]\nallowed_suffixes = [\"relay.test\"]\nadmin_host = \"admin.relay.test\"\ntunnel_host = \"tunnel.relay.test\"\n",
        )
        .unwrap();
        assert_eq!(cfg.plane_for("admin.relay.test"), Plane::Edge);
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
