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
    pub landing: LandingSection,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            server: ServerSection::default(),
            admin: AdminSection::default(),
            tls: TlsSection::default(),
            limits: LimitsSection::default(),
            landing: LandingSection::default(),
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
    /// Admin UI/API listener. Set it to take the admin plane off the unified
    /// port and serve it on its own socket (a LAN address, typically); leave
    /// it unset to keep all three planes on `listen`. Falls back to
    /// `127.0.0.1:9001` in the split layout.
    pub admin_listen: Option<String>,
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
            admin_listen: None,
            database: PathBuf::from("fairlead.db"),
            allowed_suffixes: Vec::new(),
            allow_public_edge: false,
            public_port: 8080,
            public_scheme: "http".into(),
        }
    }
}

/// The public page served when a request names no route: by IP, or on a host
/// name that is not a site under an allowed suffix. It carries the agent
/// downloads and the install one-liner, and nothing secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LandingSection {
    /// Directory holding the release artifacts written by `scripts/package.sh`.
    /// Unset (the default) turns the page off: an unknown host keeps answering
    /// 404/400, which does not advertise that this port is a relay.
    pub dir: Option<PathBuf>,
    /// A name that always serves the page, e.g. `app.relay.example.com`.
    ///
    /// Without it the page is reachable only on addresses that can never be a
    /// route: a bare IP, the apex of an allowed suffix, or a host outside every
    /// suffix. Naming one here gives the page a stable address of its own — and
    /// that name wins over a route that claims it.
    pub host: Option<String>,
}

impl Default for LandingSection {
    fn default() -> Self {
        Self { dir: None, host: None }
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

/// Where the admin plane is served in the split layout.
pub const DEFAULT_ADMIN_LISTEN: &str = "127.0.0.1:9001";

impl ServerSection {
    /// True when `listen` is the front door for more than one plane.
    pub fn unified(&self) -> bool {
        !self.listen.trim().is_empty()
    }

    /// True when the admin plane shares the unified port, selected by
    /// `admin_host`. False when `admin_listen` gives it a socket of its own -
    /// then `listen` carries only the tunnel and edge planes.
    pub fn admin_shared(&self) -> bool {
        self.unified() && self.admin_listen.is_none()
    }

    /// Admin address, whether it comes from `admin_listen` or the default.
    pub fn admin_addr(&self) -> &str {
        self.admin_listen.as_deref().unwrap_or(DEFAULT_ADMIN_LISTEN)
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
        // Same for the landing host: an empty or padded value must not look
        // like a different name than the `Host` it is compared against.
        cfg.landing.host = cfg
            .landing
            .host
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(|h| fairlead_proto::hostname::normalize(h).unwrap_or_else(|_| h.to_string()));
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
            matches!(self.server.public_scheme.as_str(), "http" | "https"),
            "server.public_scheme must be \"http\" or \"https\" (it is what agents and browsers dial)"
        );
        if let Some(dir) = &self.landing.dir {
            anyhow::ensure!(
                dir.is_dir(),
                "landing.dir={} is not a directory: it should hold the artifacts from `scripts/package.sh`",
                dir.display()
            );
        }
        if let Some(host) = &self.landing.host {
            anyhow::ensure!(
                self.landing.dir.is_some(),
                "landing.host={host} needs landing.dir: there is no page to put on that name"
            );
            anyhow::ensure!(
                fairlead_proto::hostname::normalize(host).is_ok(),
                "landing.host={host} is not a host name (a bare IP already reaches the page)"
            );
            anyhow::ensure!(
                *host != self.server.admin_host && *host != self.server.tunnel_host,
                "landing.host={host} is already a plane vhost: pick another name, that one selects the {} plane",
                if *host == self.server.admin_host { "admin" } else { "tunnel" }
            );
        }
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
            anyhow::ensure!(
                !self.server.tunnel_host.is_empty(),
                "server.listen is set, so server.tunnel_host must name the virtual host that selects the tunnel plane"
            );
            if self.server.admin_shared() {
                anyhow::ensure!(
                    !self.server.admin_host.is_empty(),
                    "server.admin_host is required while the admin plane shares server.listen; set server.admin_listen to give it its own port"
                );
                anyhow::ensure!(
                    addr.ip().is_loopback() || self.admin.allow_remote,
                    "server.listen={addr} publishes the admin plane; set admin.allow_remote=true (and put TLS in front) if you mean to do that"
                );
            } else {
                let admin: std::net::SocketAddr = self.server.admin_addr().parse().map_err(|_| {
                    anyhow::anyhow!("server.admin_listen is not an address:port")
                })?;
                // Port 0 means "any free port" (tests, demos); anything else
                // repeating the front door is a typo, not a layout.
                anyhow::ensure!(
                    admin.port() == 0 || admin != addr,
                    "server.admin_listen and server.listen must be different addresses"
                );
                anyhow::ensure!(
                    admin.ip().is_loopback() || self.admin.allow_remote,
                    "admin_listen={admin} is not loopback; set admin.allow_remote=true if you mean to publish the admin UI on the LAN"
                );
            }
            anyhow::ensure!(
                self.server.admin_host != self.server.tunnel_host,
                "server.admin_host and server.tunnel_host must name different virtual hosts"
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
            let admin: std::net::SocketAddr = self.server.admin_addr().parse()?;
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
    fn admin_listen_moves_the_admin_plane_off_the_shared_port() {
        let base = "[server]\nlisten = \"0.0.0.0:9001\"\nallowed_suffixes = [\"r.test\"]\ntunnel_host = \"tunnel.r.test\"\nadmin_listen = \"0.0.0.0:9002\"\n";
        let cfg = HostConfig::from_toml(base).unwrap();
        // Reaching the admin plane from the LAN is an explicit decision.
        assert!(cfg.validate().is_err());

        let cfg = HostConfig::from_toml(&format!("{base}[admin]\nallow_remote = true\n")).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.server.unified());
        assert!(!cfg.server.admin_shared(), "admin must not also answer on listen");
        assert_eq!(cfg.server.admin_addr(), "0.0.0.0:9002");
        // admin_host is not needed on the shared port: no vhost can reach it.
        assert!(cfg.server.admin_host.is_empty());
    }

    #[test]
    fn admin_listen_must_not_collide_with_listen() {
        let cfg = HostConfig::from_toml(
            "[server]\nlisten = \"127.0.0.1:9001\"\nallowed_suffixes = [\"r.test\"]\ntunnel_host = \"tunnel.r.test\"\nadmin_listen = \"127.0.0.1:9001\"\n",
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn split_admin_keeps_the_tunnel_vhost_required() {
        let cfg = HostConfig::from_toml(
            "[server]\nlisten = \"127.0.0.1:9001\"\nallowed_suffixes = [\"r.test\"]\nadmin_listen = \"127.0.0.1:9002\"\n",
        )
        .unwrap();
        assert!(cfg.validate().is_err(), "tunnel_host selects the mux plane");
    }

    #[test]
    fn public_scheme_must_be_http_or_https() {
        let cfg = HostConfig::from_toml(
            "[server]\nallowed_suffixes = [\"relay.test\"]\npublic_scheme = \"ftp\"\n",
        )
        .unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("public_scheme"), "{err}");
    }

    #[test]
    fn a_landing_host_needs_a_page_and_a_real_name() {
        let tmp = std::env::temp_dir().join("fairlead-landing-config-test");
        std::fs::create_dir_all(&tmp).unwrap();
        let dir = tmp.display();

        let cfg = HostConfig::from_toml(&format!(
            "[server]\nallowed_suffixes = [\"relay.test\"]\n[landing]\nhost = \"app.relay.test\"\ndir = \"{dir}\"\n"
        ))
        .unwrap();
        cfg.validate().unwrap();

        // A name without artifacts is a page that cannot exist.
        let cfg = HostConfig::from_toml(
            "[server]\nallowed_suffixes = [\"relay.test\"]\n[landing]\nhost = \"app.relay.test\"\n",
        )
        .unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("landing.host"), "{err}");

        // It cannot be a plane vhost: the front door would never hand it to edge.
        let cfg = HostConfig::from_toml(&format!(
            "[server]\nallowed_suffixes = [\"relay.test\"]\ntunnel_host = \"tunnel.relay.test\"\n[landing]\nhost = \"tunnel.relay.test\"\ndir = \"{dir}\"\n"
        ))
        .unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("plane vhost"), "{err}");

        // A bare IP already reaches the page; it is not a host name.
        let cfg = HostConfig::from_toml(&format!(
            "[server]\nallowed_suffixes = [\"relay.test\"]\n[landing]\nhost = \"203.0.113.9\"\ndir = \"{dir}\"\n"
        ))
        .unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("not a host name"), "{err}");
    }

    #[test]
    fn a_landing_host_is_normalized_like_a_host_header() {
        let tmp = std::env::temp_dir().join("fairlead-landing-normalize-test");
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg = HostConfig::from_toml(&format!(
            "[server]\nallowed_suffixes = [\"relay.test\"]\n[landing]\nhost = \"  APP.Relay.Test. \"\ndir = \"{}\"\n",
            tmp.display()
        ))
        .unwrap();
        assert_eq!(cfg.landing.host.as_deref(), Some("app.relay.test"));
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
