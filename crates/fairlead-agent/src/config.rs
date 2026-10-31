//! Agent configuration (`fairlead-agent.toml`).

use std::path::PathBuf;

use fairlead_proto::control::RouteDecl;
use serde::{Deserialize, Serialize};

/// Where the agent connects, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEndpoint {
    /// Do a TLS handshake before the tunnel upgrade.
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// `tls://relay.example.com:9443` (TLS), `http://relay.example.com:9000`
    /// (plaintext), or a bare `host:port` which means TLS.
    pub server: String,
    /// `Host:` the upgrade request carries. On a single-port host this is what
    /// selects the tunnel plane, so it must equal the host's `server.tunnel_host`.
    /// Defaults to the host part of `server`.
    pub tunnel_host: Option<String>,
    pub name: String,
    /// One-time enrollment token. Only needed for the first run.
    pub token: Option<String>,
    /// Long-lived credential, usually read from `state_file` instead.
    pub credential: Option<String>,
    /// Preferred number of physical tunnels (1..=4).
    pub tunnels: u8,
    /// Where the issued credential is cached. Defaults to a per-user path.
    pub state_file: Option<PathBuf>,
    /// Allow forwarding to public addresses (default: private + loopback only).
    pub allow_public_targets: bool,
    pub dial_timeout_secs: u64,
    pub tls: AgentTls,
    pub routes: Vec<RouteDecl>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            tunnel_host: None,
            name: String::new(),
            token: None,
            credential: None,
            tunnels: 2,
            state_file: None,
            allow_public_targets: false,
            dial_timeout_secs: 5,
            tls: AgentTls::default(),
            routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentTls {
    pub mode: TlsMode,
    /// Required when `mode = "pin"`. Lowercase or uppercase hex, colons allowed.
    pub pin_sha256: Option<String>,
    /// Override SNI / verification name (defaults to the server host).
    pub server_name: Option<String>,
}

impl Default for AgentTls {
    fn default() -> Self {
        Self { mode: TlsMode::System, pin_sha256: None, server_name: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Verify with the bundled Mozilla root store.
    System,
    /// Pin the leaf certificate SHA-256 (works with self-signed certs).
    Pin,
    /// Accept any certificate. Development only.
    Insecure,
}

impl AgentConfig {
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        let mut cfg: AgentConfig = toml::from_str(text)?;
        if let Some(raw) = cfg.tunnel_host.clone() {
            let trimmed = raw.trim().to_string();
            if trimmed.is_empty() {
                cfg.tunnel_host = None;
            } else {
                cfg.tunnel_host =
                    Some(fairlead_proto::hostname::normalize(&trimmed).unwrap_or(trimmed));
            }
        }
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.server.trim().is_empty(), "server must be set");
        anyhow::ensure!(
            (1..=4).contains(&self.tunnels),
            "tunnels must be between 1 and 4"
        );
        // An empty route list is legal: `fairlead agent rm` can take the last
        // one away while the service keeps running, and `fairlead agent add`
        // fills it back in without a restart.
        if self.tls.mode == TlsMode::Pin {
            anyhow::ensure!(
                self.tls.pin_sha256.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false),
                "tls.mode = \"pin\" requires tls.pin_sha256"
            );
        }
        if let Some(host) = &self.tunnel_host {
            anyhow::ensure!(
                fairlead_proto::hostname::normalize(host).is_ok(),
                "tunnel_host must be a host name (no scheme, no path): {host}"
            );
        }
        for r in &self.routes {
            fairlead_proto::control::validate_target(&r.target)
                .map_err(|e| anyhow::anyhow!("route {}: {e}", r.host))?;
        }
        Ok(())
    }

    /// Split `server` into scheme, host and port.
    ///
    /// * `tls://` or `https://` — TLS, then the tunnel upgrade. Use this when
    ///   nginx terminates TLS in front of the host.
    /// * `http://` or `tcp://` — plaintext, then the tunnel upgrade.
    /// * no scheme — TLS, so old configs keep their meaning.
    pub fn server_parts(&self) -> anyhow::Result<ServerEndpoint> {
        let raw = self.server.trim();
        let (scheme, rest) = match raw.split_once("://") {
            Some((s, r)) => (s.to_ascii_lowercase(), r),
            None => (String::new(), raw),
        };
        let tls = match scheme.as_str() {
            "" | "tls" | "https" => true,
            "http" | "tcp" => false,
            other => anyhow::bail!(
                "unsupported scheme `{other}://` in server: use tls:// (TLS) or http:// (plaintext)"
            ),
        };
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("bad port in server: {rest}"))?,
            ),
            _ => (rest.to_string(), 9443),
        };
        anyhow::ensure!(!host.is_empty(), "server host is empty");
        anyhow::ensure!(port > 0, "server port must not be 0");
        Ok(ServerEndpoint { tls, host, port })
    }

    /// Value for the upgrade request's `Host:` header.
    pub fn tunnel_host(&self, ep: &ServerEndpoint) -> String {
        self.tunnel_host.clone().unwrap_or_else(|| ep.host.clone())
    }

    pub fn state_path(&self) -> PathBuf {
        self.state_file.clone().unwrap_or_else(default_state_path)
    }

    pub fn agent_name(&self) -> String {
        if !self.name.trim().is_empty() {
            return self.name.trim().to_string();
        }
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| format!("agent-{:04x}", rand::random::<u16>()))
    }

    pub fn dial_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.dial_timeout_secs.max(1))
    }
}

pub fn default_state_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("fairlead").join("agent.json");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join("Library/Application Support/fairlead/agent.json");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(state) = std::env::var("XDG_STATE_HOME") {
            return PathBuf::from(state).join("fairlead/agent.json");
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".local/state/fairlead/agent.json");
        }
    }
    PathBuf::from("fairlead-agent-state.json")
}
