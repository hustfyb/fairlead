//! Host configuration (`fairlead-host.toml`).
//!
//! `deny_unknown_fields` is deliberate: a typo in a security-relevant key
//! (`tls.cert`, `allowed_suffixes`) must fail loudly at startup, not silently
//! fall back to a default.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostConfig {
    pub server: ServerSection,
    pub admin: AdminSection,
    pub tls: TlsSection,
    pub limits: LimitsSection,
    pub landing: LandingSection,
    pub proxy: ProxySection,
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

/// Forward-proxy passthrough on the same port.
///
/// A request addressed to a proxy (`CONNECT host:port`, or an absolute-form
/// target such as `GET http://host/ ...`) names its destination in the request
/// line, so its `Host` is the destination and cannot select a route. This
/// section names the one route that answers such requests instead, and the
/// relay then splices bytes: it stays a pipe, and the actual proxying happens
/// in a real forward proxy on the agent's machine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxySection {
    /// Route that answers proxy-form requests: `muse` expands to
    /// `muse.<first allowed suffix>`, a full host name is used as it is.
    /// Empty disables the feature and proxy-form requests are treated like any
    /// other request (a 404, in practice).
    pub route: String,
    /// `user:password` a client must send as `Proxy-Authorization: Basic`.
    /// Empty means no credential, which is only allowed together with
    /// `allow_from`.
    pub auth: String,
    /// Client addresses allowed to use the port as a proxy: `1.2.3.4`,
    /// `10.0.0.0/8`, `::1`. Empty means "any address that passed `auth`".
    pub allow_from: Vec<String>,
    /// Idle timeout for a spliced proxy stream. `0` never times out, which is
    /// what an idle `CONNECT` tunnel (an SSH session, a quiet browser tab)
    /// wants.
    pub idle_timeout_secs: u64,
}

impl ProxySection {
    pub fn enabled(&self) -> bool {
        !self.route.trim().is_empty()
    }

    /// Route key this section points at, or `None` when the feature is off.
    pub fn route_host(&self, suffixes: &[String]) -> Option<String> {
        let raw = self.route.trim();
        if raw.is_empty() {
            return None;
        }
        let full = if raw.contains('.') {
            raw.to_string()
        } else {
            format!("{raw}.{}", suffixes.first()?.trim().trim_start_matches('.'))
        };
        Some(fairlead_proto::hostname::normalize(&full).unwrap_or_else(|_| full.to_ascii_lowercase()))
    }

    /// True when `ip` may use the proxy. An empty list means "no address
    /// filter", never "nobody".
    pub fn allows(&self, ip: std::net::IpAddr) -> bool {
        self.allow_from.is_empty() || self.allow_from.iter().any(|e| ip_matches(e, ip))
    }

    /// Idle timeout for a proxy stream; `None` means "do not time out".
    pub fn idle(&self) -> Option<Duration> {
        (self.idle_timeout_secs > 0).then_some(Duration::from_secs(self.idle_timeout_secs))
    }
}

/// `entry` as an address or a CIDR prefix, matched against `ip`.
fn ip_matches(entry: &str, ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    let entry = entry.trim();
    let Some((base, bits)) = entry.split_once('/') else {
        return entry.parse::<IpAddr>().map(|e| e == ip).unwrap_or(false);
    };
    let (Ok(base), Ok(bits)) = (base.parse::<IpAddr>(), bits.parse::<u8>()) else {
        return false;
    };
    match (base, ip) {
        (IpAddr::V4(b), IpAddr::V4(i)) => bits <= 32 && prefix_eq(&b.octets(), &i.octets(), bits as usize),
        (IpAddr::V6(b), IpAddr::V6(i)) => bits <= 128 && prefix_eq(&b.octets(), &i.octets(), bits as usize),
        // A v4-mapped v6 client is compared as the v4 address it really is.
        (IpAddr::V4(b), IpAddr::V6(i)) => match i.to_ipv4_mapped() {
            Some(i) => bits <= 32 && prefix_eq(&b.octets(), &i.octets(), bits as usize),
            None => false,
        },
        _ => false,
    }
}

fn prefix_eq(a: &[u8], b: &[u8], bits: usize) -> bool {
    let (full, rem) = (bits / 8, bits % 8);
    if a.get(..full) != b.get(..full) {
        return false;
    }
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    matches!((a.get(full), b.get(full)), (Some(x), Some(y)) if (x & mask) == (y & mask))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
        if self.proxy.enabled() {
            let host = self
                .proxy
                .route_host(&self.server.allowed_suffixes)
                .expect("route_host only fails when route is empty");
            anyhow::ensure!(
                fairlead_proto::hostname::normalize(&host).is_ok(),
                "proxy.route={} is not a host name",
                self.proxy.route
            );
            anyhow::ensure!(
                fairlead_proto::hostname::matches_suffix(&host, &self.server.allowed_suffixes),
                "proxy.route={host} is outside server.allowed_suffixes: the egress route is a route like any other, so it needs a suffix you already publish"
            );
            anyhow::ensure!(
                host != self.server.admin_host && host != self.server.tunnel_host,
                "proxy.route={host} is already a plane virtual host"
            );
            anyhow::ensure!(
                !self.proxy.auth.is_empty() || !self.proxy.allow_from.is_empty(),
                "proxy.route={host} turns this public port into a forward proxy for the internet. Set proxy.auth=\"user:password\" (or proxy.allow_from) so strangers cannot borrow it"
            );
            if !self.proxy.auth.is_empty() {
                anyhow::ensure!(
                    self.proxy.auth.contains(':') && !self.proxy.auth.ends_with(':'),
                    "proxy.auth must look like \"user:password\": it is what Proxy-Authorization: Basic carries"
                );
            }
            for entry in &self.proxy.allow_from {
                anyhow::ensure!(
                    entry.parse::<std::net::IpAddr>().is_ok()
                        || entry
                            .split_once('/')
                            .is_some_and(|(b, p)| b.parse::<std::net::IpAddr>().is_ok() && p.parse::<u8>().is_ok()),
                    "proxy.allow_from entry {entry:?} is not an IP address or a CIDR prefix"
                );
            }
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
    fn a_short_proxy_route_expands_with_the_first_suffix() {
        let cfg = HostConfig::from_toml(
            "[server]\nallowed_suffixes = [\"relay.027mango.com\", \"other.test\"]\n[proxy]\nroute = \" Muse \"\nauth = \"u:p\"\n",
        )
        .unwrap();
        assert_eq!(
            cfg.proxy.route_host(&cfg.server.allowed_suffixes).as_deref(),
            Some("muse.relay.027mango.com")
        );
        cfg.validate().unwrap();
        let full = HostConfig::from_toml(
            "[server]\nallowed_suffixes = [\"relay.test\"]\n[proxy]\nroute = \"EGRESS.relay.test:443\"\nauth = \"u:p\"\n",
        )
        .unwrap();
        assert_eq!(
            full.proxy.route_host(&full.server.allowed_suffixes).as_deref(),
            Some("egress.relay.test")
        );
        full.validate().unwrap();
    }

    #[test]
    fn a_proxy_route_needs_a_credential_or_an_address_filter() {
        // An open forward proxy on a public port is found and abused within
        // hours; refusing to start is friendlier than starting one.
        let open = "[server]\nlisten = \"0.0.0.0:9001\"\nallowed_suffixes = [\"r.test\"]\ntunnel_host = \"tunnel.r.test\"\nadmin_listen = \"0.0.0.0:9002\"\n[admin]\nallow_remote = true\n[proxy]\nroute = \"muse\"\n";
        let cfg = HostConfig::from_toml(open).unwrap();
        let e = cfg.validate().unwrap_err().to_string();
        assert!(e.contains("proxy.auth"), "{e}");

        let with_auth = format!("{open}auth = \"user:pass\"\n");
        HostConfig::from_toml(&with_auth).unwrap().validate().unwrap();

        let with_filter = format!("{open}allow_from = [\"192.168.2.0/24\"]\n");
        HostConfig::from_toml(&with_filter).unwrap().validate().unwrap();

        let half = format!("{open}auth = \"userpass\"\n");
        let e = HostConfig::from_toml(&half).unwrap().validate().unwrap_err().to_string();
        assert!(e.contains("user:password"), "{e}");
    }

    #[test]
    fn a_proxy_route_must_be_a_route_like_any_other() {
        let base = "[server]\nallowed_suffixes = [\"r.test\"]\n[proxy]\nroute = \"muse.evil.test\"\nauth = \"u:p\"\n";
        let e = HostConfig::from_toml(base).unwrap().validate().unwrap_err().to_string();
        assert!(e.contains("allowed_suffixes"), "{e}");

        let plane = "[server]\nallowed_suffixes = [\"r.test\"]\ntunnel_host = \"tunnel.r.test\"\n[proxy]\nroute = \"tunnel\"\nauth = \"u:p\"\n";
        let e = HostConfig::from_toml(plane).unwrap().validate().unwrap_err().to_string();
        assert!(e.contains("plane virtual host"), "{e}");
    }

    #[test]
    fn proxy_address_filters_understand_prefixes() {
        use std::net::IpAddr;
        let cfg = HostConfig::from_toml(
            "[server]\nallowed_suffixes = [\"r.test\"]\n[proxy]\nroute = \"muse\"\nallow_from = [\"192.168.2.0/24\", \"10.1.2.3\", \"::1\"]\n",
        )
        .unwrap();
        let p = &cfg.proxy;
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(p.allows(ip("192.168.2.27")));
        assert!(!p.allows(ip("192.168.3.27")));
        assert!(p.allows(ip("10.1.2.3")));
        assert!(!p.allows(ip("10.1.2.4")));
        assert!(p.allows(ip("::1")));
        assert!(!p.allows(ip("8.8.8.8")));
        // Loopback in v4-mapped form is still loopback.
        let mapped = HostConfig::from_toml(
            "[server]\nallowed_suffixes = [\"r.test\"]\n[proxy]\nroute = \"muse\"\nallow_from = [\"127.0.0.0/8\"]\n",
        )
        .unwrap();
        assert!(mapped.proxy.allows(ip("::ffff:127.0.0.1")));
        // An empty filter allows everything; it never means "nobody".
        assert!(ProxySection::default().allows(ip("1.2.3.4")));
    }

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
        // TOML basic strings treat `\` as an escape and a Windows path is full
        // of them, so the separator is doubled before it goes into the config.
        let dir = tmp.display().to_string().replace('\\', "\\\\");

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
            tmp.display().to_string().replace('\\', "\\\\")
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
