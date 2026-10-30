//! `fairlead` — one binary, four jobs: host, agent, token/passwd tooling, and a
//! self-contained demo.

mod demo;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use fairlead_agent::AgentConfig;
use fairlead_host::{db::Db, HostConfig};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "fairlead", version, about = "Single-node reverse TCP tunnel with dynamic Host routing")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum AdminCmd {
    /// Create an account and prompt for its password.
    Add { username: String },
    /// Change an account's password (signs out its other sessions).
    Passwd { username: String },
    /// List accounts.
    List,
    /// Disable an account and sign out its sessions.
    Disable { username: String },
    /// Re-enable a disabled account.
    Enable { username: String },
    /// Delete an account.
    Rm { username: String },
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the public-side host (edge + tunnel + admin).
    Host {
        #[arg(short, long, default_value = "fairlead-host.toml")]
        config: PathBuf,
        /// Write a commented config template if the file does not exist.
        #[arg(long)]
        init: bool,
    },
    /// Run the internal-side agent.
    Agent {
        #[arg(short, long, default_value = "fairlead-agent.toml")]
        config: PathBuf,
        #[arg(long)]
        init: bool,
    },
    /// Create a one-time enrollment token (prints it once).
    Token {
        #[arg(short, long, default_value = "fairlead-host.toml")]
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
    /// Manage admin accounts (stored in the host database).
    Admin {
        #[arg(short, long, global = true, default_value = "fairlead-host.toml")]
        config: PathBuf,
        #[command(subcommand)]
        action: AdminCmd,
    },
    /// Print an argon2id hash (legacy; accounts live in the database now).
    Passwd,
    /// Print an nginx server block that matches this host config.
    GenNginx {
        #[arg(short, long, default_value = "fairlead-host.toml")]
        config: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Check config, database, TLS material and printing the tunnel fingerprint.
    Doctor {
        #[arg(short, long, default_value = "fairlead-host.toml")]
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
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,fairlead=info")),
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
            Cmd::Admin { config, action } => cmd_admin(config, action).await,
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
        println!("edit listen / admin_host / tunnel_host / allowed_suffixes, then create an admin account:");
        println!("  fairlead admin add admin --config {}", path.display());
        println!("  fairlead doctor --config {}", path.display());
        println!("  fairlead host   --config {}", path.display());
        return Ok(());
    }
    let cfg = read_host_config(&path)?;
    let unified = cfg.server.unified();
    let admin_host = cfg.server.admin_host.clone();
    let tunnel_host = cfg.server.tunnel_host.clone();
    let host = fairlead_host::start(cfg).await?;
    if unified {
        let addr = host.edge_addr();
        println!("one port  http://{addr}");
        println!("  admin   http://{admin_host}:{}   (Host: {admin_host})", addr.port());
        println!("  tunnel  {addr}                 (Host: {tunnel_host}, Upgrade: fairlead/1)");
        println!("  edge    everything else on that port, routed by Host");
        println!("tls       none (the unified port is plain HTTP; terminate TLS in front)");
    } else {
        println!("edge     http://{}  (nginx upstream)", host.edge_addr());
        println!("tunnel   {}  (agents connect here)", host.tunnel_addr());
        println!("admin    http://{}", host.admin_addr());
        println!("tls      {} sha256={}", host.state.tls_source, host.state.tls_fingerprint);
    }
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
        println!("put server / tunnel_host / token / routes in it, then:");
        println!("  fairlead agent --config {}", path.display());
        return Ok(());
    }
    let text = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let cfg = AgentConfig::from_toml(&text)?;
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = wait_for_ctrl_c().await;
        let _ = tx.send(true);
    });
    fairlead_agent::run(cfg, rx).await
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
    let (pw, again) = read_password_pair("new password")?;
    let hash = check_and_hash(&pw, &again)?;
    println!("{hash}");
    eprintln!("\nLegacy path: put this into [admin] password_hash. Prefer `fairlead admin add admin`.");
    Ok(())
}

fn check_and_hash(pw: &str, again: &str) -> anyhow::Result<String> {
    if pw.len() < 10 {
        return Err(anyhow!("password must be at least 10 characters"));
    }
    if pw != again {
        return Err(anyhow!("passwords do not match"));
    }
    fairlead_host::db::hash_password(pw)
}

/// Hidden prompt on a TTY; two lines from stdin when piped (scriptable).
fn read_password_pair(label: &str) -> anyhow::Result<(String, String)> {
    use std::io::{IsTerminal, Read};
    if std::io::stdin().is_terminal() {
        let a = rpassword::prompt_password(format!("password for {label}: "))?;
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

async fn cmd_admin(path: PathBuf, action: AdminCmd) -> anyhow::Result<()> {
    let cfg = read_host_config(&path)?;
    let db = Db::open(&cfg.server.database).await?;
    let enabled = |list: &[fairlead_host::db::AdminAccount]| list.iter().filter(|a| !a.disabled).count();
    match action {
        AdminCmd::List => {
            let list = db.admins().await?;
            if list.is_empty() {
                println!("no accounts yet — create one with: fairlead admin add admin");
                return Ok(());
            }
            println!("{:<20} {:<9} {:<20} {}", "USERNAME", "STATUS", "CREATED", "LAST LOGIN");
            for a in list {
                let last = a.last_login_at.map(fairlead_host::metrics::fmt_ts).unwrap_or_else(|| "-".into());
                println!(
                    "{:<20} {:<9} {:<20} {}",
                    a.username,
                    if a.disabled { "disabled" } else { "enabled" },
                    fairlead_host::metrics::fmt_ts(a.created_at),
                    last
                );
            }
        }
        AdminCmd::Add { username } => {
            let (pw, again) = read_password_pair(&username)?;
            let hash = check_and_hash(&pw, &again)?;
            let a = db.admin_create(&username, &hash).await?;
            println!("created admin `{}`", a.username);
        }
        AdminCmd::Passwd { username } => {
            if db.admin_by_username(&username).await?.is_none() {
                return Err(anyhow!("no such admin: {username}"));
            }
            let (pw, again) = read_password_pair(&username)?;
            let hash = check_and_hash(&pw, &again)?;
            if db.admin_set_hash(&username, &hash).await? {
                println!("password updated for `{}`; its sessions were signed out", username.to_ascii_lowercase());
            }
        }
        AdminCmd::Disable { username } => {
            let list = db.admins().await?;
            let target = list.iter().find(|a| a.username == username.to_ascii_lowercase());
            match target {
                None => return Err(anyhow!("no such admin: {username}")),
                Some(a) if !a.disabled && enabled(&list) <= 1 => {
                    return Err(anyhow!("refusing to disable the last enabled admin"))
                }
                Some(_) => {}
            }
            db.admin_set_disabled(&username, true).await?;
            println!("disabled `{}`", username.to_ascii_lowercase());
        }
        AdminCmd::Enable { username } => {
            if !db.admin_set_disabled(&username, false).await? {
                return Err(anyhow!("no such admin: {username}"));
            }
            println!("enabled `{}`", username.to_ascii_lowercase());
        }
        AdminCmd::Rm { username } => {
            let list = db.admins().await?;
            let target = list.iter().find(|a| a.username == username.to_ascii_lowercase());
            match target {
                None => return Err(anyhow!("no such admin: {username}")),
                Some(a) if !a.disabled && enabled(&list) <= 1 => {
                    return Err(anyhow!("refusing to delete the last enabled admin"))
                }
                Some(_) => {}
            }
            db.admin_delete(&username).await?;
            println!("deleted `{}`", username.to_ascii_lowercase());
        }
    }
    Ok(())
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
    match Db::open(&cfg.server.database).await {
        Ok(db) => {
            match db.routes().await {
                Ok(r) => line(true, "database", format!("{} routes", r.len())),
                Err(e) => line(false, "database", e.to_string()),
            }
            match db.admins().await {
                Ok(list) => {
                    let n = list.iter().filter(|a| !a.disabled).count();
                    line(
                        n > 0,
                        "admin accounts",
                        if n == 0 {
                            "none — run `fairlead admin add admin`".into()
                        } else {
                            format!("{n} enabled / {} total", list.len())
                        },
                    );
                }
                Err(e) => line(false, "admin accounts", e.to_string()),
            }
        }
        Err(e) => line(false, "database", e.to_string()),
    }
    if cfg.server.unified() {
        line(true, "listen", format!("{} (one port, three planes)", cfg.server.listen));
        line(true, "admin plane", format!("Host: {}", cfg.server.admin_host));
        line(true, "tunnel plane", format!("Host: {}", cfg.server.tunnel_host));
        line(true, "tls", "none — the unified port is plain HTTP; put nginx in front".into());
        println!("\nAgent snippet:\n{}", agent_snippet(&cfg, ""));
    } else {
        match fairlead_host::tlsutil::build(&cfg) {
            Ok(t) => {
                line(true, "tls", format!("{} sha256={}", t.source, t.fingerprint));
                println!("\nAgent snippet:\n{}", agent_snippet(&cfg, &t.fingerprint));
            }
            Err(e) => line(false, "tls", e.to_string()),
        }
    }
    match std::process::Command::new("nginx").arg("-v").output() {
        Ok(o) => line(
            true,
            "nginx",
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
        ),
        Err(_) => line(false, "nginx", "not found in PATH".into()),
    }
    let edge_like = if cfg.server.unified() { &cfg.server.listen } else { &cfg.server.edge_listen };
    if edge_like.parse::<std::net::SocketAddr>().map(|a| a.ip().is_loopback()).unwrap_or(false) {
        line(true, "edge binding", format!("{edge_like} (loopback)"));
    } else if cfg.server.unified() {
        line(true, "edge binding", format!("{edge_like} (public; nginx or a firewall must front it)"));
    } else {
        line(false, "edge binding", format!("{edge_like} is not loopback"));
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
    let unified = cfg.server.unified();
    // Everything nginx must route to the same upstream. In unified mode that
    // includes the two plane vhosts: nginx forwards `Host`, the host process
    // picks the plane.
    let mut names: Vec<String> = cfg
        .server
        .allowed_suffixes
        .iter()
        .flat_map(|s| vec![format!("*.{s}"), s.clone()])
        .collect();
    if unified {
        names.push(cfg.server.admin_host.clone());
        names.push(cfg.server.tunnel_host.clone());
    }
    let upstream = if unified { &cfg.server.listen } else { &cfg.server.edge_listen };
    // `0.0.0.0:9000` is what you bind, not what you dial.
    let upstream = upstream
        .strip_prefix("0.0.0.0:")
        .map(|port| format!("127.0.0.1:{port}"))
        .or_else(|| upstream.strip_prefix("[::]:").map(|port| format!("[::1]:{port}")))
        .unwrap_or_else(|| upstream.clone());
    format!(
        r#"# Generated by `fairlead gen-nginx`. Include this file from the http {{}} block.
#
# Two lines here are load-bearing:
#   * X-Forwarded-For is overwritten with $remote_addr (never $proxy_add_x_forwarded_for),
#     otherwise a forged header from the client is passed through.
#   * proxy_buffering off / proxy_request_buffering off keep SSE and large uploads streaming.
#
# The Upgrade/Connection pair is what lets an agent reach the tunnel plane
# through nginx: after the 101 the connection is a raw tunnel.

map $http_upgrade $fairlead_connection_upgrade {{
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

    # Host is not rewritten: on a unified port it is the plane selector.
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $fairlead_connection_upgrade;

    access_log /var/log/nginx/fairlead.access.log;
    error_log  /var/log/nginx/fairlead.error.log warn;

    location / {{
        proxy_pass http://{upstream};
    }}
}}
"#,
        port = cfg.server.public_port,
        names = names.join(" "),
    )
}

fn agent_snippet(cfg: &HostConfig, fingerprint: &str) -> String {
    let host = cfg
        .server
        .allowed_suffixes
        .first()
        .cloned()
        .unwrap_or_else(|| "relay.example.com".into());
    if cfg.server.unified() {
        let port = cfg
            .server
            .listen
            .rsplit_once(':')
            .map(|(_, p)| p.to_string())
            .unwrap_or_else(|| "9000".into());
        return format!(
            r#"server = "http://{host}:{port}"
tunnel_host = "{tunnel}"
name = "agent-a"
token = "<from fairlead token>"
tunnels = 2

# Behind an nginx TLS terminator: only `server` changes, nginx forwards
# `Host` and `Upgrade` unchanged:
#   server = "tls://{host}:443"
#   tunnel_host = "{tunnel}"

[[routes]]
host = "a1.{host}"
target = "127.0.0.1:7884""#,
            tunnel = cfg.server.tunnel_host
        );
    }
    format!(
        r#"server = "tls://{host}:9443"
name = "agent-a"
token = "<from fairlead token>"
tunnels = 2

[tls]
mode = "pin"
pin_sha256 = "{fingerprint}"

[[routes]]
host = "a1.{host}"
target = "127.0.0.1:7884""#
    )
}

pub const HOST_TEMPLATE: &str = r#"# fairlead host configuration
[server]
# One port, three planes, selected by the request host:
#   admin_host  -> admin plane   (your browser)
#   tunnel_host -> tunnel plane  (agents: Host + `Upgrade: fairlead/1`)
#   anything else -> edge plane  (site traffic, routed by Host)
# Leave `listen` empty to go back to three sockets (edge_listen /
# tunnel_listen / admin_listen) with TLS on the tunnel listener.
listen = "0.0.0.0:9000"
admin_host = "admin.relay.example.com"
tunnel_host = "tunnel.relay.example.com"

database = "/var/lib/fairlead/fairlead.db"
allowed_suffixes = ["relay.example.com"]
public_port = 8080
public_scheme = "http"

[admin]
# Accounts live in the database: fairlead admin add admin
session_ttl_secs = 43200
# Required when `listen` is not loopback: the admin plane shares that port.
allow_remote = true
trust_forwarded_for = false     # trust X-Real-IP / X-Forwarded-For (behind your proxy)
secure_cookie = false           # set true once TLS is in front

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

pub const AGENT_TEMPLATE: &str = r#"# fairlead agent configuration
# Plaintext single port (host has no TLS of its own):
server = "http://relay.example.com:9000"
# Behind an nginx TLS terminator instead: server = "tls://relay.example.com:443"
# and keep the same tunnel_host — nginx forwards Host and Upgrade unchanged.
tunnel_host = "tunnel.relay.example.com"

name = "agent-a"

# First run: enroll with a token printed by `fairlead token`.
# The host answers with a long-lived credential, cached in state_file.
token = "<token>"
# credential = "<issued-credential>"
state_file = "/var/lib/fairlead/agent.json"

tunnels = 2
allow_public_targets = false
dial_timeout_secs = 5

[tls]
mode = "system"        # system | pin | insecure (only used by tls:// servers)
# pin_sha256 = "..."   # from the host startup log or `fairlead doctor`

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
