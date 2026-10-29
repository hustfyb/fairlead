//! Agent configuration (`fairlead-agent.toml`).

use std::path::PathBuf;

use fairlead_proto::control::RouteDecl;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// `tls://relay.example.com:9443` or `relay.example.com:9443`.
    pub server: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let cfg: AgentConfig = toml::from_str(text)?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.server.trim().is_empty(), "server must be set");
        anyhow::ensure!(
            (1..=4).contains(&self.tunnels),
            "tunnels must be between 1 and 4"
        );
        anyhow::ensure!(
            !self.routes.is_empty(),
            "no [[routes]] declared: the agent would connect and serve nothing"
        );
        if self.tls.mode == TlsMode::Pin {
            anyhow::ensure!(
                self.tls.pin_sha256.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false),
                "tls.mode = \"pin\" requires tls.pin_sha256"
            );
        }
        for r in &self.routes {
            fairlead_proto::control::validate_target(&r.target)
                .map_err(|e| anyhow::anyhow!("route {}: {e}", r.host))?;
        }
        Ok(())
    }

    /// Split `server` into (host, port).
    pub fn server_parts(&self) -> anyhow::Result<(String, u16)> {
        let raw = self.server.trim();
        let raw = raw.strip_prefix("tls://").unwrap_or(raw);
        let (host, port) = match raw.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| anyhow::anyhow!("bad port in server: {raw}"))?),
            None => (raw, 9443),
        };
        anyhow::ensure!(!host.is_empty(), "server host is empty");
        Ok((host.to_string(), port))
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
