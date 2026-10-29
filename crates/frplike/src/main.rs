//! `frplike` — one binary, four jobs: host, agent, token/passwd tooling, and a
//! self-contained demo.

mod demo;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use frplike_agent::AgentConfig;
use frplike_host::{db::Db, HostConfig};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "frplike", version, about = "Single-node reverse TCP tunnel with dynamic Host routing")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the public-side host (edge + tunnel + admin).
    Host {
        #[arg(short, long, default_value = "frplike-host.toml")]
        config: PathBuf,
        /// Write a commented config template if the file does not exist.
        #[arg(long)]
        init: bool,
    },
    /// Run the internal-side agent.
    Agent {
        #[arg(short, long, default_value = "frplike-agent.toml")]
        config: PathBuf,
        #[arg(long)]
        init: bool,
    },
    /// Create a one-time enrollment token (prints it once).
    Token {
        #[arg(short, long, default_value = "frplike-host.toml")]
        config: PathBuf,
        /// Subdomain suffix the token may enroll, e.g. relay.example.com
        #[arg(long)]
        suffix: String,
        /// Lifetime: 30m, 24h, 7d. Omit for no expiry.
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Print an argon2id hash for [admin].password_hash.
    Passwd,
    /// Print an nginx server block that matches this host config.
    GenNginx {
        #[arg(short, long, default_value = "frplike-host.toml")]
        config: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Check config, database, TLS material and printing the tunnel fingerprint.
    Doctor {
        #[arg(short, long, default_value = "frplike-host.toml")]
        config: PathBuf,
    },
    /// Run host + agent + two demo origins on loopback. Ctrl-C to stop.
    Demo {
        /// Directory for the demo database and configs (default: temp).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Edge port that the demo agent reports as the public port.
        #[arg(long, default_value_t = 8080)]
        public_port: u16,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,frplike=info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        match cli.cmd {
            Cmd::Host { config, init } => cmd_host(config, init).await,
            Cmd::Agent { config, init } => cmd_agent(config, init).await,
            Cmd::Token { config, suffix, ttl, note } => cmd_token(config, suffix, ttl, note).await,
            Cmd::Passwd => cmd_passwd(),
            Cmd::GenNginx { config, out } => cmd_gen_nginx(config, out),
            Cmd::Doctor { config } => cmd_doctor(config).await,
            Cmd::Demo { dir, public_port } => demo::run(dir, public_port).await,
        }
    })
}

async fn cmd_host(path: PathBuf, init: bool) -> anyhow::Result<()> {
    if init && !path.exists() {
        std::fs::write(&path, HOST_TEMPLATE)?;
        println!("wrote {}", path.display());
        println!("edit allowed_suffixes / tls / admin.password_hash, then:");
        println!("  frplike doctor --config {}", path.display());
        println!("  frplike host   --config {}", path.display());
        return Ok(());
    }
    let cfg = read_host_config(&path)?;
    let host = frplike_host::start(cfg).await?;
    println!("edge     http://{}  (nginx upstream)", host.edge_addr());
    println!("tunnel   {}  (agents connect here)", host.tunnel_addr());
    println!("admin    http://{}", host.admin_addr());
    println!("tls      {} sha256={}", host.state.tls_source, host.state.tls_fingerprint);
    println!("press Ctrl-C to stop");
    wait_for_ctrl_c().await;
    println!("shutting down…");
    host.shutdown().await;
    Ok(())
}

async fn cmd_agent(path: PathBuf, init: bool) -> anyhow::Result<()> {
    if init && !path.exists() {
        std::fs::write(&path, AGENT_TEMPLATE)?;
        println!("wrote {}", path.display());
        println!("put server/token/routes in it, then:");
        println!("  frplike agent --config {}", path.display());
        return Ok(());
    }
    let text = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let cfg = AgentConfig::from_toml(&text)?;
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = wait_for_ctrl_c().await;
        let _ = tx.send(true);
    });
    frplike_agent::run(cfg, rx).await
}

async fn cmd_token(
    path: PathBuf,
    suffix: String,
    ttl: Option<String>,
    note: String,
) -> anyhow::Result<()> {
    let cfg = read_host_config(&path)?;
    let ttl_secs = match ttl {
        Some(t) => Some(parse_duration(&t)?),
        None => None,
    };
    let db = Db::open(&cfg.server.database).await?;
    let token = db.create_token(&suffix, ttl_secs, &note).await?;
    println!("{token}");
    eprintln!(
        "\nThis token is shown once and stored only as a hash.\nIt may enroll any host ending in .{suffix}{}.\n",
        match ttl_secs {
            Some(s) => format!(" and expires in {s}s"),
            None => String::new(),
        }
    );
    Ok(())
}

fn cmd_passwd() -> anyhow::Result<()> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let (pw, again) = read_password_pair()?;
    if pw.len() < 8 {
        return Err(anyhow!("password must be at least 8 characters"));
    }
    if pw != again {
        return Err(anyhow!("passwords do not match"));
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2::Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|e| anyhow!("hash: {e}"))?;
    println!("{hash}");
    eprintln!("\nPut this into [admin] password_hash in frplike-host.toml.");
    Ok(())
}

/// Hidden prompt on a TTY; two lines from stdin when piped (scriptable).
fn read_password_pair() -> anyhow::Result<(String, String)> {
    use std::io::{IsTerminal, Read};
    if std::io::stdin().is_terminal() {
        let a = rpassword::prompt_password("new admin password: ")?;
        let b = rpassword::prompt_password("repeat: ")?;
        Ok((a, b))
    } else {
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text)?;
        let mut lines = text.lines();
        let a = lines.next().unwrap_or_default().trim_end().to_string();
        let b = lines.next().unwrap_or_default().trim_end().to_string();
        Ok((a, b))
    }
}

fn cmd_gen_nginx(path: PathBuf, out: Option<PathBuf>) -> anyhow::Result<()> {
    let cfg = read_host_config(&path)?;
    let text = nginx_config(&cfg);
    match out {
        Some(p) => {
            std::fs::write(&p, &text)?;
            println!("wrote {}", p.display());
        }
        None => print!("{text}"),
    }
    Ok(())
}

async fn cmd_doctor(path: PathBuf) -> anyhow::Result<()> {
    let mut ok = true;
    let mut line = |good: bool, what: &str, detail: String| {
        println!("{} {:<28} {}", if good { "✓" } else { "✗" }, what, detail);
        if !good {
            ok = false;
        }
    };
    let cfg = match std::fs::read_to_string(&path)
        .map_err(|e| anyhow!("{}: {e}", path.display()))
        .and_then(|s| HostConfig::from_toml(&s))
    {
        Ok(c) => c,
        Err(e) => {
            line(false, "config", e.to_string());
            return Err(e);
        }
    };
    line(true, "config", format!("{}", path.display()));
    match cfg.validate() {
        Ok(()) => line(true, "validate", "ok".into()),
        Err(e) => line(false, "validate", e.to_string()),
    }
    line(
        !cfg.server.allowed_suffixes.is_empty(),
        "allowed suffixes",
        cfg.server.allowed_suffixes.join(", "),
    );
    line(
        !cfg.admin.password_hash.is_empty(),
        "admin password",
        if cfg.admin.password_hash.is_empty() {
            "not set — admin UI disabled".into()
        } else {
            "argon2 hash present".into()
        },
    );
    match Db::open(&cfg.server.database).await {
        Ok(db) => match db.routes().await {
            Ok(r) => line(true, "database", format!("{} routes", r.len())),
            Err(e) => line(false, "database", e.to_string()),
        },
        Err(e) => line(false, "database", e.to_string()),
    }
    match frplike_host::tlsutil::build(&cfg) {
        Ok(t) => {
            line(true, "tls", format!("{} sha256={}", t.source, t.fingerprint));
            println!("\nAgent snippet:\n{}", agent_snippet(&cfg, &t.fingerprint));
        }
        Err(e) => line(false, "tls", e.to_string()),
    }
    match std::process::Command::new("nginx").arg("-v").output() {
        Ok(o) => line(
            true,
            "nginx",
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
        ),
        Err(_) => line(false, "nginx", "not found in PATH".into()),
    }
    if cfg.server.edge_listen.parse::<std::net::SocketAddr>().map(|a| a.ip().is_loopback()).unwrap_or(false) {
        line(true, "edge binding", format!("{} (loopback)", cfg.server.edge_listen));
    } else {
        line(false, "edge binding", format!("{} is not loopback", cfg.server.edge_listen));
    }
    if ok {
        println!("\nall checks passed");
        Ok(())
    } else {
        Err(anyhow!("some checks failed"))
    }
}

fn read_host_config(path: &Path) -> anyhow::Result<HostConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read {} (run with --init to create a template)", path.display()))?;
    let cfg = HostConfig::from_toml(&text)?;
    cfg.validate()?;
    Ok(cfg)
}

async fn wait_for_ctrl_c() {
    let _ = tokio::signal::ctrl_c().await;
}

fn parse_duration(raw: &str) -> anyhow::Result<u64> {
    let raw = raw.trim();
    let (num, unit) = raw.split_at(raw.len().saturating_sub(1));
    let n: u64 = num.parse().map_err(|_| anyhow!("bad duration: {raw}"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        _ => return Err(anyhow!("duration unit must be s, m, h or d: {raw}")),
    };
    Ok(secs)
}

fn nginx_config(cfg: &HostConfig) -> String {
    let suffixes = cfg.server.allowed_suffixes.join(" ");
    let names: Vec<String> = cfg
        .server
        .allowed_suffixes
        .iter()
        .flat_map(|s| vec![format!("*.{s}"), s.clone()])
        .collect();
    format!(
        r#"# Generated by `frplike gen-nginx`. Include this file from the http {{}} block.
#
# Two lines here are load-bearing:
#   * X-Forwarded-For is overwritten with $remote_addr (never $proxy_add_x_forwarded_for),
#     otherwise a forged header from the client is passed through.
#   * proxy_buffering off / proxy_request_buffering off keep SSE and large uploads streaming.

map $http_upgrade $frplike_connection_upgrade {{
    default upgrade;
    ''      close;
}}

server {{
    listen {port};
    server_name {names};

    # Streaming, not buffering.
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_max_temp_file_size 0;

    client_max_body_size 0;
    proxy_connect_timeout 5s;
    proxy_send_timeout 3600s;
    proxy_read_timeout 3600s;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $frplike_connection_upgrade;

    access_log /var/log/nginx/frplike.access.log;
    error_log  /var/log/nginx/frplike.error.log warn;

    location / {{
        proxy_pass http://{edge};
    }}
}}
"#,
        port = cfg.server.public_port,
        names = names.join(" "),
        edge = cfg.server.edge_listen,
        // keep the variable referenced for docs / future templating
    )
    .replace("{suffixes}", &suffixes)
}

fn agent_snippet(cfg: &HostConfig, fingerprint: &str) -> String {
    let host = cfg
        .server
        .allowed_suffixes
        .first()
        .cloned()
        .unwrap_or_else(|| "relay.example.com".into());
    format!(
        r#"server = "tls://{host}:9443"
name = "agent-a"
token = "<from frplike token>"
tunnels = 2

[tls]
mode = "pin"
pin_sha256 = "{fingerprint}"

[[routes]]
host = "a1.{host}"
target = "127.0.0.1:7884""#
    )
}

pub const HOST_TEMPLATE: &str = r#"# frplike host configuration
[server]
edge_listen = "127.0.0.1:9000"      # nginx talks to this; loopback only
tunnel_listen = "0.0.0.0:9443"      # agents connect here
admin_listen = "127.0.0.1:9001"     # admin UI; use an SSH tunnel
database = "/var/lib/frplike/frplike.db"
allowed_suffixes = ["relay.example.com"]
public_port = 8080
public_scheme = "http"

[tls]
cert = "/etc/frplike/tls/tunnel.crt"
key = "/etc/frplike/tls/tunnel.key"
# dev_self_signed = true            # development only

[admin]
# Generate with: frplike passwd
password_hash = ""
session_ttl_secs = 43200

[limits]
max_head_bytes = 16384
max_streams_per_connection = 2048
max_tunnels_per_agent = 4
handshake_timeout_secs = 10
head_timeout_secs = 10
dial_timeout_secs = 5
dial_wait_timeout_secs = 10
idle_timeout_secs = 120
upgrade_idle_timeout_secs = 300
heartbeat_secs = 10
heartbeat_timeout_secs = 30
request_log_capacity = 8192
request_log_retention_days = 7
"#;

pub const AGENT_TEMPLATE: &str = r#"# frplike agent configuration
server = "tls://relay.example.com:9443"
name = "agent-a"

# First run: enroll with a token printed by `frplike token`.
# The host answers with a long-lived credential, cached in state_file.
token = "<token>"
# credential = "<issued-credential>"
state_file = "/var/lib/frplike/agent.json"

tunnels = 2
allow_public_targets = false
dial_timeout_secs = 5

[tls]
mode = "system"        # system | pin | insecure
# pin_sha256 = "..."   # from the host startup log or `frplike doctor`

[[routes]]
host = "a1.relay.example.com"
target = "127.0.0.1:7884"

[[routes]]
host = "a2.relay.example.com"
target = "127.0.0.1:7885"
"#;

#[allow(dead_code)]
async fn sleep_ms(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}
