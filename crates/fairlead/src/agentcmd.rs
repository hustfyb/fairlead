//! `fairlead agent list / add / rm / status` — the agent's control panel.
//!
//! Everything here edits the agent config and reads the status file the running
//! agent leaves behind; nothing talks to the relay. The running service notices
//! a changed config within a couple of seconds and re-declares its routes, so a
//! mapping added from a shell survives that shell closing and every reboot.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use fairlead_agent::status::{self, RouteStatus, StatusFile};
use fairlead_agent::AgentConfig;

use crate::agentcfg;
use crate::service;

pub const LOCAL_CONFIG: &str = "fairlead-agent.toml";
pub const SYSTEM_CONFIG: &str = "/etc/fairlead/agent.toml";

/// `--config`, else `./fairlead-agent.toml`, else `/etc/fairlead/agent.toml`
/// (a root install), else `~/.config/fairlead/agent.toml` (a home install).
pub fn resolve_config(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    let mut candidates = vec![PathBuf::from(LOCAL_CONFIG), PathBuf::from(SYSTEM_CONFIG)];
    candidates.extend(user_config());
    for candidate in candidates {
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from(LOCAL_CONFIG)
}

/// Where `install.sh` puts the config when it runs as you instead of as root:
/// `$XDG_CONFIG_HOME/fairlead/agent.toml`, else `~/.config/fairlead/agent.toml`.
pub fn user_config() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(p) if Path::new(&p).is_absolute() => PathBuf::from(p),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(base.join("fairlead").join("agent.toml"))
}

/// The `sudo` line that installs the service, spelled with this binary's real
/// path: a home install usually is not on `PATH`, so a bare `fairlead` in the
/// hint would not run for the person who just installed it there.
pub fn sudo_service_install(role: service::Role) -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "fairlead".to_string());
    format!("sudo {exe} {} service install", role.word())
}

struct Loaded {
    path: PathBuf,
    text: String,
    cfg: AgentConfig,
}

fn load(path: PathBuf) -> anyhow::Result<Loaded> {
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "read {} — no agent config there yet (run `fairlead agent --init`, or install with install.sh)",
            path.display()
        )
    })?;
    let cfg = AgentConfig::from_toml(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(Loaded { path, text, cfg })
}

fn status_of(cfg: &AgentConfig) -> Option<StatusFile> {
    let path = status::path_for_state(&cfg.state_path());
    StatusFile::load(&path).filter(|s| s.is_fresh(status::now_secs()))
}

// --------------------------------------------------------------------- list

pub fn list(config: Option<PathBuf>) -> anyhow::Result<()> {
    let loaded = load(resolve_config(config))?;
    let live = status_of(&loaded.cfg);

    println!(
        "{}  →  {}   ({})",
        loaded.cfg.agent_name(),
        loaded.cfg.server,
        loaded.path.display()
    );
    match &live {
        Some(s) => {
            let up = s.uptime_secs(status::now_secs()).map(status::human_uptime);
            let mut bits = vec![format!("pid {}", s.pid)];
            if let Some(up) = up {
                bits.push(format!("up {up}"));
            }
            bits.push(if s.connected {
                format!("connected, {} tunnel(s)", s.tunnels)
            } else {
                "connecting".to_string()
            });
            println!("service  running ({})", bits.join(", "));
        }
        None => println!("service  not running"),
    }
    if let Some(err) = live.as_ref().and_then(|s| s.last_error.clone()) {
        println!("error    {err}");
    }

    if loaded.cfg.routes.is_empty() {
        println!("\nno routes yet — publish a local port with:");
        println!("  fairlead agent add a1.<your-suffix> 8080");
        return Ok(());
    }

    let host_w = loaded
        .cfg
        .routes
        .iter()
        .map(|r| r.host.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let target_w = loaded
        .cfg
        .routes
        .iter()
        .map(|r| r.target.len())
        .max()
        .unwrap_or(6)
        .max(6);
    println!(
        "\n{:<host_w$}  {:<target_w$}  STATE",
        "HOST",
        "TARGET",
        host_w = host_w,
        target_w = target_w
    );
    for route in &loaded.cfg.routes {
        let (state, reason) = match live.as_ref().and_then(|s| {
            s.routes
                .iter()
                .find(|r| r.host.eq_ignore_ascii_case(&route.host))
        }) {
            Some(r) => (r.state.clone(), r.reason.clone()),
            None => ("-".to_string(), None),
        };
        println!(
            "{:<host_w$}  {:<target_w$}  {}{}",
            route.host,
            route.target,
            state,
            reason.map(|r| format!(" ({r})")).unwrap_or_default(),
            host_w = host_w,
            target_w = target_w
        );
    }
    Ok(())
}

// ------------------------------------------------------------------- enroll

/// Save the one-time token the admin console printed. The running service
/// re-reads the config every couple of seconds, so nothing has to be restarted:
/// an agent that was waiting for a token connects by itself.
pub fn enroll(config: Option<PathBuf>, token: String, fresh: bool) -> anyhow::Result<()> {
    let token = token.trim().to_string();
    if token.is_empty() {
        bail!("the token is empty");
    }
    let loaded = load(resolve_config(config))?;
    let state_path = loaded.cfg.state_path();
    let cached = fairlead_agent::state::load(&state_path);
    let enrolled = loaded.cfg.credential.is_some() || cached.credential.is_some();

    if enrolled && !fresh {
        println!("this agent is already enrolled; nothing changed.");
        if let Some(id) = cached.agent_id.as_deref() {
            println!("agent    {id}");
        }
        println!("to replace the credential (for example after revoking it in the console):");
        println!("  fairlead agent enroll <TOKEN> --fresh");
        return Ok(());
    }
    if enrolled {
        // The cached credential wins over the token, so drop it first: this is
        // the path after a revoke, and the new token has to be what is used.
        let _ = std::fs::remove_file(&state_path);
    }

    let text = agentcfg::clear_credential(&agentcfg::set_token(&loaded.text, &token)?)?;
    agentcfg::write(&loaded.path, &text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&loaded.path, std::fs::Permissions::from_mode(0o600));
    }
    println!("token saved to {}", loaded.path.display());

    // The token only matters at the next connection. An agent that is running
    // right now keeps the credential it already has — say so instead of
    // claiming success from a status file that is about the old credential.
    if fresh && status_of(&loaded.cfg).is_some() {
        println!("the running agent still holds its old credential; restart it to use this token:");
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "fairlead".into());
        println!("  sudo {exe} agent service restart");
        return Ok(());
    }

    let cfg = AgentConfig::from_toml(&text)?;
    match wait_connected(&cfg, 10) {
        Some(s) => println!("connected to {} ({} tunnel(s))", s.server, s.tunnels),
        None => {
            println!("not connected yet — `fairlead agent status` says why");
            if !service::status(service::Role::Agent).installed {
                println!(
                    "the service is not installed: {}",
                    sudo_service_install(service::Role::Agent)
                );
            }
        }
    }
    println!();
    println!("publish a port:");
    println!("  fairlead agent add 8080        # 127.0.0.1:8080 as a8080.<your suffix>");
    Ok(())
}

// ---------------------------------------------------------------------- add

pub fn add(config: Option<PathBuf>, host: String, target: Option<String>) -> anyhow::Result<()> {
    let loaded = load(resolve_config(config))?;
    let (host, target) = match target {
        Some(t) => (
            agentcfg::normalize_host(&host)?,
            agentcfg::normalize_target(&t)?,
        ),
        None => {
            // `fairlead agent add 8080`: name the route after the port, under
            // the suffix the tunnel host sits in.
            let port: u16 = host.trim().parse().map_err(|_| {
                anyhow!("usage: fairlead agent add <host> <port>  (e.g. a1.relay.example.com 8080)")
            })?;
            let suffix = loaded
                .cfg
                .tunnel_host
                .clone()
                .and_then(|h| agentcfg::suffix_from_tunnel_host(&h))
                .ok_or_else(|| {
                    anyhow!(
                        "cannot tell the relay suffix from tunnel_host; give the whole name: \
                         fairlead agent add a1.<your-suffix> {port}"
                    )
                })?;
            (format!("a{port}.{suffix}"), format!("127.0.0.1:{port}"))
        }
    };

    let (text, change) = agentcfg::add_or_update(&loaded.text, &host, &target)?;
    agentcfg::write(&loaded.path, &text)?;
    match change {
        agentcfg::Change::Unchanged => println!("{host} already points at {target}"),
        agentcfg::Change::Updated { from } => {
            println!("{host}: {from} → {target}  (in {})", loaded.path.display())
        }
        agentcfg::Change::Added => {
            println!("{host} → {target}  (in {})", loaded.path.display())
        }
    }
    warn_if_dark(&target);
    report_live(&loaded, &host, target.clone());
    if let Some(url) = public_url(&loaded.cfg, &host) {
        println!("open {url} once the relay has it");
    }
    Ok(())
}

// ----------------------------------------------------------------------- rm

/// The relay takes a route whether or not anything is listening on its target,
/// and the first request is what finds out — as a 502 that names no port. One
/// connect here turns that into a sentence at the moment the mapping is made.
fn warn_if_dark(target: &str) {
    if let Err(why) = fairlead_agent::probe::tcp(target, Duration::from_millis(700)) {
        println!(
            "warning: nothing answers on {target} ({why}); the route still publishes, \
             but requests to it come back 502 until something listens there"
        );
    }
}

pub fn rm(config: Option<PathBuf>, host: String) -> anyhow::Result<()> {
    let loaded = load(resolve_config(config))?;
    let host = agentcfg::normalize_host(&host)?;
    let Some(text) = agentcfg::remove(&loaded.text, &host)? else {
        let known: Vec<String> = loaded.cfg.routes.iter().map(|r| r.host.clone()).collect();
        bail!(
            "no route for {host}; this machine publishes {}",
            if known.is_empty() {
                "nothing".to_string()
            } else {
                known.join(", ")
            }
        );
    };
    agentcfg::write(&loaded.path, &text)?;
    println!("removed {host}  (from {})", loaded.path.display());

    if status_of(&loaded.cfg).is_some() {
        let path = status::path_for_state(&loaded.cfg.state_path());
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let gone = StatusFile::load(&path)
                .map(|s| !s.routes.iter().any(|r| r.host.eq_ignore_ascii_case(&host)))
                .unwrap_or(true);
            if gone {
                println!("the relay dropped it");
                return Ok(());
            }
            if Instant::now() >= deadline {
                println!("the agent has not picked it up yet; check `fairlead agent list`");
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }
    Ok(())
}

// ------------------------------------------------------------------- status

pub fn status_cmd(config: Option<PathBuf>) -> anyhow::Result<()> {
    let path = resolve_config(config);
    let svc = service::status(service::Role::Agent);
    println!("service  {} ({})", svc.state, svc.manager);
    if !svc.installed {
        println!(
            "         install it with: {}",
            sudo_service_install(service::Role::Agent)
        );
    }

    let loaded = load(path);
    let Ok(loaded) = loaded else {
        return Ok(());
    };
    println!("config   {}", loaded.path.display());
    match status_of(&loaded.cfg) {
        Some(s) => {
            let up = s.uptime_secs(status::now_secs()).map(status::human_uptime);
            println!(
                "agent    {} (pid {}, up {}), {}",
                s.agent_name,
                s.pid,
                up.unwrap_or_else(|| "?".into()),
                if s.connected {
                    "connected"
                } else {
                    "connecting"
                }
            );
            println!("relay    {}", s.server);
            let serving = s.routes.iter().filter(|r| r.state == "serving").count();
            println!(
                "routes   {} configured, {serving} serving",
                loaded.cfg.routes.len()
            );
            match s.last_error.as_deref() {
                Some(e) => println!("error    {e}"),
                None => println!("error    none"),
            }
        }
        None => println!("agent    not running"),
    }
    println!("log      {}", service::log_hint(service::Role::Agent));
    Ok(())
}

// --------------------------------------------------------------- helpers

/// Say what the running service did with a route that was just written.
fn report_live(loaded: &Loaded, host: &str, target: String) {
    if status_of(&loaded.cfg).is_none() {
        println!("the service is not running; it will publish this when it starts");
        return;
    }
    let path = status::path_for_state(&loaded.cfg.state_path());
    match wait_for_state(&path, host, 8) {
        Some(r) if r.state == "serving" => {
            println!("serving {target} as {host}");
        }
        Some(r) if r.state == "rejected" => {
            println!(
                "the relay refused {host}: {}",
                r.reason.unwrap_or_else(|| "no reason given".into())
            );
        }
        Some(r) if r.state == "offline" => {
            println!("saved; the agent is not connected to the relay right now")
        }
        Some(r) => println!("state: {}", r.state),
        None => println!("no answer from the agent yet; check `fairlead agent list`"),
    }
}

/// Wait until the status file says the agent is connected.
fn wait_connected(cfg: &AgentConfig, secs: u64) -> Option<StatusFile> {
    let path = status::path_for_state(&cfg.state_path());
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(s) = StatusFile::load(&path).filter(|s| s.is_fresh(status::now_secs())) {
            if s.connected {
                return Some(s);
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_state(path: &Path, host: &str, secs: u64) -> Option<RouteStatus> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(s) = StatusFile::load(path).filter(|s| s.is_fresh(status::now_secs())) {
            if let Some(r) = s.routes.iter().find(|r| r.host.eq_ignore_ascii_case(host)) {
                if r.state != "pending" {
                    return Some(r.clone());
                }
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

/// Best guess at the address a browser would use: the relay we dial, minus the
/// tunnel vhost, with the port dropped when it is the default one. A loopback
/// `server` says nothing about the public port, so no URL is offered then.
fn public_url(cfg: &AgentConfig, host: &str) -> Option<String> {
    let ep = cfg.server_parts().ok()?;
    if ep
        .host
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
        || ep.host.eq_ignore_ascii_case("localhost")
    {
        return None;
    }
    let scheme = if ep.tls { "https" } else { "http" };
    Some(match ep.port {
        80 | 443 => format!("{scheme}://{host}"),
        p => format!("{scheme}://{host}:{p}"),
    })
}
