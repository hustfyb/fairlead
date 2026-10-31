//! Installing the agent — or the relay host — as a service, so that a mapping
//! outlives the shell that created it and comes back after a reboot.
//!
//! * Linux: a systemd unit, `/etc/systemd/system/fairlead-agent.service`
//! * macOS: a launchd daemon, `/Library/LaunchDaemons/com.fairlead.agent.plist`
//! * Windows: a scheduled task that runs at sign-in (`schtasks`)
//!
//! One program, two units: `fairlead agent run` publishes this machine's ports
//! and `fairlead host` is the relay itself. Both may live on the same machine,
//! so the units are named `fairlead-agent` and `fairlead-host` — the program
//! itself is just `fairlead`.

use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, bail};
// Only the systemd and launchd branches build a message with a path in it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;

/// Which of the two programs the unit runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// `fairlead agent run`: publish this machine's ports through the relay.
    Agent,
    /// `fairlead host`: be the relay — one socket, three planes.
    Host,
}

impl Role {
    /// The unit / task name. Both units can be on one box, so it is never just
    /// `fairlead`.
    pub fn unit(self) -> &'static str {
        match self {
            Role::Agent => "fairlead-agent",
            Role::Host => "fairlead-host",
        }
    }

    /// The launchd label.
    pub fn label(self) -> &'static str {
        match self {
            Role::Agent => "com.fairlead.agent",
            Role::Host => "com.fairlead.host",
        }
    }

    /// What the binary has to be told to run this role in the foreground.
    fn words(self) -> &'static [&'static str] {
        match self {
            Role::Agent => &["agent", "run"],
            Role::Host => &["host"],
        }
    }

    /// The word after `fairlead`: the subcommand that runs this role.
    pub fn word(self) -> &'static str {
        match self {
            Role::Agent => "agent",
            Role::Host => "host",
        }
    }

    fn summary(self) -> &'static str {
        match self {
            Role::Agent => "fairlead agent (reverse tunnel)",
            Role::Host => "fairlead relay host (edge + tunnel + admin)",
        }
    }

    fn log_path(self) -> &'static str {
        match self {
            Role::Agent => "/var/log/fairlead-agent.log",
            Role::Host => "/var/log/fairlead-host.log",
        }
    }
}

/// What the service manager says, plus whether it knows the service at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub installed: bool,
    /// `running`, `stopped`, `failed`, `not installed`, …
    pub state: String,
    pub manager: &'static str,
}

pub fn manager_name() -> &'static str {
    if cfg!(target_os = "linux") {
        "systemd"
    } else if cfg!(target_os = "macos") {
        "launchd"
    } else if cfg!(target_os = "windows") {
        "scheduled task"
    } else {
        "unknown"
    }
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| anyhow!("cannot run {program}: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        bail!("{program} {}: {detail}", args.join(" "));
    }
    Ok(stdout)
}

/// Best effort: used for steps that may legitimately fail (nothing to stop).
fn try_run(program: &str, args: &[&str]) {
    let _ = Command::new(program).args(args).output();
}

// --------------------------------------------------------------- systemd

#[cfg(target_os = "linux")]
fn unit_path(role: Role) -> std::path::PathBuf {
    Path::new("/etc/systemd/system").join(format!("{}.service", role.unit()))
}

/// The unit file, without the parts only a real system knows. Built on every
/// platform so the tests can check it, written only on Linux.
#[allow(dead_code)]
pub fn unit_text(role: Role, exe: &Path, config: &Path, user: Option<&str>) -> String {
    let mut s = String::new();
    s.push_str("[Unit]\n");
    s.push_str(&format!("Description={}\n", role.summary()));
    s.push_str("After=network-online.target\n");
    s.push_str("Wants=network-online.target\n\n");
    s.push_str("[Service]\n");
    s.push_str("Type=simple\n");
    s.push_str(&format!(
        "ExecStart={} {} --config {}\n",
        exe.display(),
        role.words().join(" "),
        config.display()
    ));
    if let Some(user) = user {
        if user != "root" {
            s.push_str(&format!("User={user}\n"));
        }
    }
    s.push_str("Restart=always\n");
    s.push_str("RestartSec=3s\n");
    s.push_str("Environment=RUST_LOG=info\n");
    if role == Role::Host {
        // The admin password is the whole credential; it belongs in a 0600
        // file next to the config, not in a unit everyone can read.
        if let Some(dir) = config.parent() {
            s.push_str(&format!(
                "EnvironmentFile=-{}\n",
                dir.join("admin.env").display()
            ));
        }
    }
    s.push_str("\n[Install]\n");
    s.push_str("WantedBy=multi-user.target\n");
    s
}

// ----------------------------------------------------------------- launchd

/// The launchd property list. `user` runs the daemon as that user instead of
/// root; logs go to a world-readable file so `fairlead agent status` can point
/// at something useful. Written only on macOS.
#[allow(dead_code)]
pub fn plist_text(role: Role, exe: &Path, config: &Path, user: Option<&str>) -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    s.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    s.push_str("<plist version=\"1.0\">\n<dict>\n");
    s.push_str(&format!(
        "  <key>Label</key>\n  <string>{}</string>\n",
        role.label()
    ));
    s.push_str("  <key>ProgramArguments</key>\n  <array>\n");
    let mut args = vec![exe.display().to_string()];
    args.extend(role.words().iter().map(|w| w.to_string()));
    args.push("--config".into());
    args.push(config.display().to_string());
    for arg in args {
        s.push_str(&format!("    <string>{}</string>\n", xml_escape(&arg)));
    }
    s.push_str("  </array>\n");
    s.push_str("  <key>RunAtLoad</key>\n  <true/>\n");
    s.push_str("  <key>KeepAlive</key>\n  <true/>\n");
    s.push_str("  <key>ThrottleInterval</key>\n  <integer>5</integer>\n");
    if let Some(user) = user {
        if user != "root" {
            s.push_str(&format!(
                "  <key>UserName</key>\n  <string>{}</string>\n",
                xml_escape(user)
            ));
        }
    }
    s.push_str("  <key>EnvironmentVariables</key>\n  <dict>\n");
    s.push_str("    <key>RUST_LOG</key>\n    <string>info</string>\n");
    s.push_str("  </dict>\n");
    s.push_str(&format!(
        "  <key>StandardOutPath</key>\n  <string>{}</string>\n",
        role.log_path()
    ));
    s.push_str(&format!(
        "  <key>StandardErrorPath</key>\n  <string>{}</string>\n",
        role.log_path()
    ));
    s.push_str("</dict>\n</plist>\n");
    s
}

#[allow(dead_code)]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The file (or, on Windows, the command) `install` would write — for
/// `--dry-run`, and for anyone who wants to see what is being installed.
#[allow(unreachable_code, dead_code)]
pub fn describe(role: Role, exe: &Path, config: &Path, user: Option<&str>) -> String {
    #[cfg(target_os = "linux")]
    {
        return unit_text(role, exe, config, user);
    }
    #[cfg(target_os = "macos")]
    {
        return plist_text(role, exe, config, user);
    }
    #[cfg(target_os = "windows")]
    {
        if user.is_some() {
            return String::new();
        }
        return format!(
            "schtasks /Create /F /TN {} /TR \"\"{}\" {} --config \"{}\"\" /SC ONLOGON /RL LIMITED\n",
            role.unit(),
            exe.display(),
            role.words().join(" "),
            config.display()
        );
    }
    String::new()
}

// --------------------------------------------------------------- install

#[cfg(target_os = "linux")]
pub fn install(role: Role, exe: &Path, config: &Path, user: Option<&str>) -> anyhow::Result<()> {
    let path = unit_path(role);
    std::fs::write(&path, unit_text(role, exe, config, user)).with_context(|| {
        format!(
            "write {} — the service needs root: try sudo",
            path.display()
        )
    })?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", "--now", role.unit()])?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn install(role: Role, exe: &Path, config: &Path, user: Option<&str>) -> anyhow::Result<()> {
    let path =
        std::path::PathBuf::from("/Library/LaunchDaemons").join(format!("{}.plist", role.label()));
    std::fs::write(&path, plist_text(role, exe, config, user)).with_context(|| {
        format!(
            "write {} — the service needs root: try sudo",
            path.display()
        )
    })?;
    // A stale copy from an earlier install would make `bootstrap` fail.
    try_run(
        "launchctl",
        &["bootout", &format!("system/{}", role.label())],
    );
    run(
        "launchctl",
        &["bootstrap", "system", &path.display().to_string()],
    )?;
    let _ = run(
        "launchctl",
        &["enable", &format!("system/{}", role.label())],
    );
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn install(role: Role, exe: &Path, config: &Path, _user: Option<&str>) -> anyhow::Result<()> {
    // A console program cannot answer the service control manager, so a
    // scheduled task is the honest way to keep it running: it starts at
    // sign-in, as the user who installed it, with no stored password.
    let tr = format!(
        "\"{}\" {} --config \"{}\"",
        exe.display(),
        role.words().join(" "),
        config.display()
    );
    run(
        "schtasks",
        &[
            "/Create",
            "/F",
            "/TN",
            role.unit(),
            "/TR",
            &tr,
            "/SC",
            "ONLOGON",
            "/RL",
            "LIMITED",
        ],
    )?;
    let _ = run("schtasks", &["/Run", "/TN", role.unit()]);
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn install(
    _role: Role,
    _exe: &Path,
    _config: &Path,
    _user: Option<&str>,
) -> anyhow::Result<()> {
    bail!("no service manager support for this platform: run the binary under your own supervisor")
}

// --------------------------------------------------------------- uninstall

#[cfg(target_os = "linux")]
pub fn uninstall(role: Role) -> anyhow::Result<()> {
    try_run("systemctl", &["disable", "--now", role.unit()]);
    let path = unit_path(role);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("{} is not installed (no {})", role.unit(), path.display())
        }
        Err(e) => return Err(anyhow!("remove {}: {e} (try sudo)", path.display())),
    }
    let _ = run("systemctl", &["daemon-reload"]);
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn uninstall(role: Role) -> anyhow::Result<()> {
    let path =
        std::path::PathBuf::from("/Library/LaunchDaemons").join(format!("{}.plist", role.label()));
    if !path.exists() {
        bail!("{} is not installed (no {})", role.label(), path.display());
    }
    try_run(
        "launchctl",
        &["bootout", &format!("system/{}", role.label())],
    );
    std::fs::remove_file(&path)
        .map_err(|e| anyhow!("remove {}: {e} (try sudo)", path.display()))?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn uninstall(role: Role) -> anyhow::Result<()> {
    try_run("schtasks", &["/End", "/TN", role.unit()]);
    run("schtasks", &["/Delete", "/F", "/TN", role.unit()])?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn uninstall(_role: Role) -> anyhow::Result<()> {
    bail!("no service manager support for this platform")
}

// ---------------------------------------------------------- start/stop/etc.

#[cfg(target_os = "linux")]
pub fn start(role: Role) -> anyhow::Result<()> {
    run("systemctl", &["start", role.unit()]).map(|_| ())
}

#[cfg(target_os = "linux")]
pub fn stop(role: Role) -> anyhow::Result<()> {
    run("systemctl", &["stop", role.unit()]).map(|_| ())
}

#[cfg(target_os = "linux")]
pub fn restart(role: Role) -> anyhow::Result<()> {
    run("systemctl", &["restart", role.unit()]).map(|_| ())
}

#[cfg(target_os = "macos")]
pub fn start(role: Role) -> anyhow::Result<()> {
    run(
        "launchctl",
        &["kickstart", "-k", &format!("system/{}", role.label())],
    )
    .map(|_| ())
}

#[cfg(target_os = "macos")]
pub fn stop(role: Role) -> anyhow::Result<()> {
    run(
        "launchctl",
        &["kill", "SIGTERM", &format!("system/{}", role.label())],
    )
    .map(|_| ())
}

#[cfg(target_os = "macos")]
pub fn restart(role: Role) -> anyhow::Result<()> {
    run(
        "launchctl",
        &["kickstart", "-k", &format!("system/{}", role.label())],
    )
    .map(|_| ())
}

#[cfg(target_os = "windows")]
pub fn start(role: Role) -> anyhow::Result<()> {
    run("schtasks", &["/Run", "/TN", role.unit()]).map(|_| ())
}

#[cfg(target_os = "windows")]
pub fn stop(role: Role) -> anyhow::Result<()> {
    run("schtasks", &["/End", "/TN", role.unit()]).map(|_| ())
}

#[cfg(target_os = "windows")]
pub fn restart(role: Role) -> anyhow::Result<()> {
    try_run("schtasks", &["/End", "/TN", role.unit()]);
    run("schtasks", &["/Run", "/TN", role.unit()]).map(|_| ())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn start(_role: Role) -> anyhow::Result<()> {
    bail!("no service manager support for this platform")
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn stop(_role: Role) -> anyhow::Result<()> {
    bail!("no service manager support for this platform")
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn restart(_role: Role) -> anyhow::Result<()> {
    bail!("no service manager support for this platform")
}

// ------------------------------------------------------------------ status

#[cfg(target_os = "linux")]
pub fn status(role: Role) -> ServiceStatus {
    let installed = unit_path(role).exists();
    let state = if !installed {
        "not installed".to_string()
    } else {
        match run("systemctl", &["is-active", role.unit()]) {
            Ok(s) if s == "active" => "running".to_string(),
            Ok(s) if s.is_empty() => "stopped".to_string(),
            Ok(s) => s,
            Err(_) => "stopped".to_string(),
        }
    };
    ServiceStatus {
        installed,
        state,
        manager: "systemd",
    }
}

#[cfg(target_os = "macos")]
pub fn status(role: Role) -> ServiceStatus {
    let installed = std::path::PathBuf::from("/Library/LaunchDaemons")
        .join(format!("{}.plist", role.label()))
        .exists();
    let state = if !installed {
        "not installed".to_string()
    } else {
        match Command::new("launchctl")
            .args(["print", &format!("system/{}", role.label())])
            .output()
        {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                if text.contains("state = running") {
                    "running".to_string()
                } else {
                    "loaded, not running".to_string()
                }
            }
            _ => "stopped".to_string(),
        }
    };
    ServiceStatus {
        installed,
        state,
        manager: "launchd",
    }
}

#[cfg(target_os = "windows")]
pub fn status(role: Role) -> ServiceStatus {
    match Command::new("schtasks")
        .args(["/Query", "/TN", role.unit(), "/FO", "LIST"])
        .output()
    {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            let state = text
                .lines()
                .find_map(|l| l.strip_prefix("Status:"))
                .map(|s| s.trim().to_ascii_lowercase())
                .map(|s| {
                    if s == "running" {
                        "running".to_string()
                    } else {
                        s
                    }
                })
                .unwrap_or_else(|| "installed".into());
            ServiceStatus {
                installed: true,
                state,
                manager: "scheduled task",
            }
        }
        _ => ServiceStatus {
            installed: false,
            state: "not installed".into(),
            manager: "scheduled task",
        },
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn status(_role: Role) -> ServiceStatus {
    ServiceStatus {
        installed: false,
        state: "unsupported".into(),
        manager: "unknown",
    }
}

/// Where the logs end up, per platform, for `fairlead agent status` to print.
pub fn log_hint(role: Role) -> String {
    if cfg!(target_os = "linux") {
        format!("journalctl -u {} -n 50 --no-pager", role.unit())
    } else if cfg!(target_os = "macos") {
        format!("tail -n 50 {}", role.log_path())
    } else if cfg!(target_os = "windows") {
        format!("run it in a console: fairlead {}", role.words().join(" "))
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn exe() -> PathBuf {
        PathBuf::from("/usr/local/bin/fairlead")
    }
    fn cfg() -> PathBuf {
        PathBuf::from("/etc/fairlead/agent.toml")
    }

    #[test]
    fn the_unit_runs_the_agent_and_restarts_it() {
        let text = unit_text(Role::Agent, &exe(), &cfg(), Some("alice"));
        assert!(
            text.contains(
                "ExecStart=/usr/local/bin/fairlead agent run --config /etc/fairlead/agent.toml"
            ),
            "{text}"
        );
        assert!(text.contains("User=alice"));
        assert!(text.contains("Restart=always"));
        assert!(text.contains("WantedBy=multi-user.target"));
        assert!(
            text.contains("After=network-online.target"),
            "a reboot before the network is up must not lose the mapping"
        );
        assert!(
            !text.contains("EnvironmentFile"),
            "the agent needs no password file"
        );
    }

    #[test]
    fn the_host_unit_is_a_different_program_and_reads_the_password_file() {
        // `install.sh host` installs the relay, not an agent: the unit runs
        // `fairlead host`, and the admin password comes from a 0600 file next
        // to the config instead of being pasted into a world-readable unit.
        let text = unit_text(
            Role::Host,
            &exe(),
            Path::new("/etc/fairlead/host.toml"),
            Some("alice"),
        );
        assert!(
            text.contains(
                "ExecStart=/usr/local/bin/fairlead host --config /etc/fairlead/host.toml"
            ),
            "{text}"
        );
        assert!(
            text.contains("EnvironmentFile=-/etc/fairlead/admin.env"),
            "{text}"
        );
        assert!(
            !text.contains("agent run"),
            "the host is not the agent: {text}"
        );
        assert_eq!(Role::Host.unit(), "fairlead-host");
        assert_eq!(Role::Agent.unit(), "fairlead-agent");
        let plist = plist_text(
            Role::Host,
            &exe(),
            Path::new("/etc/fairlead/host.toml"),
            None,
        );
        assert!(plist.contains("<string>host</string>"), "{plist}");
        assert!(
            plist.contains("<string>com.fairlead.host</string>"),
            "{plist}"
        );
    }

    #[test]
    fn a_home_install_points_the_service_at_the_real_binary() {
        // install.sh now puts the binary in ~/.local/bin for a normal user and
        // passes the real path in; the unit must not fall back to /usr/local/bin.
        let home_exe = PathBuf::from("/home/ubuntu/.local/bin/fairlead");
        let home_cfg = PathBuf::from("/home/ubuntu/.config/fairlead/agent.toml");
        let unit = unit_text(Role::Agent, &home_exe, &home_cfg, Some("ubuntu"));
        assert!(
            unit.contains("ExecStart=/home/ubuntu/.local/bin/fairlead agent run ")
                && unit.contains("--config /home/ubuntu/.config/fairlead/agent.toml"),
            "{unit}"
        );
        assert!(unit.contains("User=ubuntu"), "{unit}");
        let plist = plist_text(Role::Agent, &home_exe, &home_cfg, Some("ubuntu"));
        assert!(
            plist.contains("<string>/home/ubuntu/.local/bin/fairlead</string>"),
            "{plist}"
        );
    }

    #[test]
    fn root_gets_no_user_line() {
        assert!(!unit_text(Role::Agent, &exe(), &cfg(), Some("root")).contains("User="));
        assert!(!unit_text(Role::Agent, &exe(), &cfg(), None).contains("User="));
    }

    #[test]
    fn the_plist_is_well_formed_and_runs_at_boot() {
        let text = plist_text(Role::Agent, &exe(), &cfg(), Some("alice"));
        assert!(text.starts_with("<?xml"));
        assert!(text.contains("<key>RunAtLoad</key>\n  <true/>"));
        assert!(text.contains("<key>KeepAlive</key>\n  <true/>"));
        assert!(text.contains("<string>/usr/local/bin/fairlead</string>"));
        assert!(text.contains("<string>--config</string>"));
        assert!(text.contains("<string>/etc/fairlead/agent.toml</string>"));
        assert!(text.contains("<key>UserName</key>\n  <string>alice</string>"));
        assert_eq!(
            text.matches("<dict>").count(),
            text.matches("</dict>").count()
        );
        assert_eq!(
            text.matches("<array>").count(),
            text.matches("</array>").count()
        );
    }

    #[test]
    fn a_path_with_an_ampersand_survives_the_plist() {
        let text = plist_text(Role::Agent, Path::new("/opt/A & B/fairlead"), &cfg(), None);
        assert!(text.contains("/opt/A &amp; B/fairlead"));
        assert!(!text.contains("A & B"));
    }
}
