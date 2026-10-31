//! Installing the agent as a service, so a mapping outlives the shell that
//! created it and comes back after a reboot.
//!
//! * Linux: a systemd unit, `/etc/systemd/system/fairlead-agent.service`
//! * macOS: a launchd daemon, `/Library/LaunchDaemons/com.fairlead.agent.plist`
//! * Windows: a scheduled task that runs at sign-in (`schtasks`)
//!
//! The unit is named `fairlead-agent`, not `fairlead`, because the relay host
//! may live on the same machine (`fairlead-host.service`). The program itself
//! is just `fairlead`.

use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, bail, Context};

pub const UNIT: &str = "fairlead-agent";
#[cfg(target_os = "macos")]
pub const LABEL: &str = "com.fairlead.agent";

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
fn unit_path() -> &'static Path {
    Path::new("/etc/systemd/system/fairlead-agent.service")
}

/// The unit file, without the parts only a real system knows. Built on every
/// platform so the tests can check it, written only on Linux.
#[allow(dead_code)]
pub fn unit_text(exe: &Path, config: &Path, user: Option<&str>) -> String {
    let mut s = String::new();
    s.push_str("[Unit]\n");
    s.push_str("Description=fairlead agent (reverse tunnel)\n");
    s.push_str("After=network-online.target\n");
    s.push_str("Wants=network-online.target\n\n");
    s.push_str("[Service]\n");
    s.push_str("Type=simple\n");
    s.push_str(&format!(
        "ExecStart={} agent run --config {}\n",
        exe.display(),
        config.display()
    ));
    if let Some(user) = user {
        if user != "root" {
            s.push_str(&format!("User={user}\n"));
        }
    }
    s.push_str("Restart=always\n");
    s.push_str("RestartSec=3s\n");
    s.push_str("Environment=RUST_LOG=info\n\n");
    s.push_str("[Install]\n");
    s.push_str("WantedBy=multi-user.target\n");
    s
}

// ----------------------------------------------------------------- launchd

/// The launchd property list. `user` runs the daemon as that user instead of
/// root; logs go to a world-readable file so `fairlead agent status` can point
/// at something useful. Written only on macOS.
#[allow(dead_code)]
pub fn plist_text(exe: &Path, config: &Path, user: Option<&str>) -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    s.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    s.push_str("<plist version=\"1.0\">\n<dict>\n");
    s.push_str("  <key>Label</key>\n  <string>com.fairlead.agent</string>\n");
    s.push_str("  <key>ProgramArguments</key>\n  <array>\n");
    for arg in [
        exe.display().to_string(),
        "agent".into(),
        "run".into(),
        "--config".into(),
        config.display().to_string(),
    ] {
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
    s.push_str("  <key>StandardOutPath</key>\n  <string>/var/log/fairlead-agent.log</string>\n");
    s.push_str("  <key>StandardErrorPath</key>\n  <string>/var/log/fairlead-agent.log</string>\n");
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
pub fn describe(exe: &Path, config: &Path, user: Option<&str>) -> String {
    #[cfg(target_os = "linux")]
    {
        return unit_text(exe, config, user);
    }
    #[cfg(target_os = "macos")]
    {
        return plist_text(exe, config, user);
    }
    #[cfg(target_os = "windows")]
    {
        return format!(
            "schtasks /Create /F /TN {UNIT} /TR \"\"{}\" agent run --config \"{}\"\" /SC ONLOGON /RL LIMITED\n",
            exe.display(),
            config.display()
        );
    }
    String::new()
}

// --------------------------------------------------------------- install

#[cfg(target_os = "linux")]
pub fn install(exe: &Path, config: &Path, user: Option<&str>) -> anyhow::Result<()> {
    let path = unit_path();
    std::fs::write(path, unit_text(exe, config, user)).with_context(|| {
        format!(
            "write {} — the service needs root: try sudo",
            path.display()
        )
    })?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", "--now", UNIT])?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn install(exe: &Path, config: &Path, user: Option<&str>) -> anyhow::Result<()> {
    let path = Path::new("/Library/LaunchDaemons/com.fairlead.agent.plist");
    std::fs::write(path, plist_text(exe, config, user)).with_context(|| {
        format!(
            "write {} — the service needs root: try sudo",
            path.display()
        )
    })?;
    // A stale copy from an earlier install would make `bootstrap` fail.
    try_run("launchctl", &["bootout", "system/com.fairlead.agent"]);
    run(
        "launchctl",
        &["bootstrap", "system", &path.display().to_string()],
    )?;
    let _ = run("launchctl", &["enable", "system/com.fairlead.agent"]);
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn install(exe: &Path, config: &Path, _user: Option<&str>) -> anyhow::Result<()> {
    // A console program cannot answer the service control manager, so a
    // scheduled task is the honest way to keep it running: it starts at
    // sign-in, as the user who installed it, with no stored password.
    let tr = format!(
        "\"{}\" agent run --config \"{}\"",
        exe.display(),
        config.display()
    );
    run(
        "schtasks",
        &[
            "/Create", "/F", "/TN", UNIT, "/TR", &tr, "/SC", "ONLOGON", "/RL", "LIMITED",
        ],
    )?;
    let _ = run("schtasks", &["/Run", "/TN", UNIT]);
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn install(_exe: &Path, _config: &Path, _user: Option<&str>) -> anyhow::Result<()> {
    bail!("no service manager support for this platform: run `fairlead agent run` under your own supervisor")
}

// --------------------------------------------------------------- uninstall

#[cfg(target_os = "linux")]
pub fn uninstall() -> anyhow::Result<()> {
    try_run("systemctl", &["disable", "--now", UNIT]);
    match std::fs::remove_file(unit_path()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("{UNIT} is not installed (no {})", unit_path().display())
        }
        Err(e) => return Err(anyhow!("remove {}: {e} (try sudo)", unit_path().display())),
    }
    let _ = run("systemctl", &["daemon-reload"]);
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn uninstall() -> anyhow::Result<()> {
    let path = "/Library/LaunchDaemons/com.fairlead.agent.plist";
    if !Path::new(path).exists() {
        bail!("{LABEL} is not installed (no {path})");
    }
    try_run("launchctl", &["bootout", "system/com.fairlead.agent"]);
    std::fs::remove_file(path).map_err(|e| anyhow!("remove {path}: {e} (try sudo)"))?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn uninstall() -> anyhow::Result<()> {
    try_run("schtasks", &["/End", "/TN", UNIT]);
    run("schtasks", &["/Delete", "/F", "/TN", UNIT])?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn uninstall() -> anyhow::Result<()> {
    bail!("no service manager support for this platform")
}

// ---------------------------------------------------------- start/stop/etc.

#[cfg(target_os = "linux")]
pub fn start() -> anyhow::Result<()> {
    run("systemctl", &["start", UNIT]).map(|_| ())
}

#[cfg(target_os = "linux")]
pub fn stop() -> anyhow::Result<()> {
    run("systemctl", &["stop", UNIT]).map(|_| ())
}

#[cfg(target_os = "linux")]
pub fn restart() -> anyhow::Result<()> {
    run("systemctl", &["restart", UNIT]).map(|_| ())
}

#[cfg(target_os = "macos")]
pub fn start() -> anyhow::Result<()> {
    run(
        "launchctl",
        &["kickstart", "-k", "system/com.fairlead.agent"],
    )
    .map(|_| ())
}

#[cfg(target_os = "macos")]
pub fn stop() -> anyhow::Result<()> {
    run(
        "launchctl",
        &["kill", "SIGTERM", "system/com.fairlead.agent"],
    )
    .map(|_| ())
}

#[cfg(target_os = "macos")]
pub fn restart() -> anyhow::Result<()> {
    run(
        "launchctl",
        &["kickstart", "-k", "system/com.fairlead.agent"],
    )
    .map(|_| ())
}

#[cfg(target_os = "windows")]
pub fn start() -> anyhow::Result<()> {
    run("schtasks", &["/Run", "/TN", UNIT]).map(|_| ())
}

#[cfg(target_os = "windows")]
pub fn stop() -> anyhow::Result<()> {
    run("schtasks", &["/End", "/TN", UNIT]).map(|_| ())
}

#[cfg(target_os = "windows")]
pub fn restart() -> anyhow::Result<()> {
    try_run("schtasks", &["/End", "/TN", UNIT]);
    run("schtasks", &["/Run", "/TN", UNIT]).map(|_| ())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn start() -> anyhow::Result<()> {
    bail!("no service manager support for this platform")
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn stop() -> anyhow::Result<()> {
    bail!("no service manager support for this platform")
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn restart() -> anyhow::Result<()> {
    bail!("no service manager support for this platform")
}

// ------------------------------------------------------------------ status

#[cfg(target_os = "linux")]
pub fn status() -> ServiceStatus {
    let installed = unit_path().exists();
    let state = if !installed {
        "not installed".to_string()
    } else {
        match run("systemctl", &["is-active", UNIT]) {
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
pub fn status() -> ServiceStatus {
    let installed = Path::new("/Library/LaunchDaemons/com.fairlead.agent.plist").exists();
    let state = if !installed {
        "not installed".to_string()
    } else {
        match Command::new("launchctl")
            .args(["print", "system/com.fairlead.agent"])
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
pub fn status() -> ServiceStatus {
    match Command::new("schtasks")
        .args(["/Query", "/TN", UNIT, "/FO", "LIST"])
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
pub fn status() -> ServiceStatus {
    ServiceStatus {
        installed: false,
        state: "unsupported".into(),
        manager: "unknown",
    }
}

/// Where the logs end up, per platform, for `fairlead agent status` to print.
pub fn log_hint() -> String {
    if cfg!(target_os = "linux") {
        format!("journalctl -u {UNIT} -n 50 --no-pager")
    } else if cfg!(target_os = "macos") {
        "tail -n 50 /var/log/fairlead-agent.log".to_string()
    } else if cfg!(target_os = "windows") {
        "run it in a console: fairlead agent run".to_string()
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
        let text = unit_text(&exe(), &cfg(), Some("alice"));
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
    }

    #[test]
    fn root_gets_no_user_line() {
        assert!(!unit_text(&exe(), &cfg(), Some("root")).contains("User="));
        assert!(!unit_text(&exe(), &cfg(), None).contains("User="));
    }

    #[test]
    fn the_plist_is_well_formed_and_runs_at_boot() {
        let text = plist_text(&exe(), &cfg(), Some("alice"));
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
        let text = plist_text(Path::new("/opt/A & B/fairlead"), &cfg(), None);
        assert!(text.contains("/opt/A &amp; B/fairlead"));
        assert!(!text.contains("A & B"));
    }
}
