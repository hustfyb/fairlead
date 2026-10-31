//! Runtime status file, written by the running agent next to its credential.
//!
//! `fairlead agent list` runs in a different process — often a different user —
//! and cannot ask the agent anything, so the agent leaves this small JSON file
//! behind: what it is connected to, which routes the relay accepted, and the
//! last error. It holds no secrets, and it is rewritten every second while the
//! agent runs, which is also how the CLI tells "running" from "stale file".

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// How long a status file is believed before the agent is presumed dead.
pub const FRESH_SECS: i64 = 20;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteStatus {
    pub host: String,
    pub target: String,
    /// `serving`, `rejected`, `pending` (connected, no answer yet) or
    /// `offline` (the agent is not connected).
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusFile {
    pub pid: u32,
    pub started_at: i64,
    pub updated_at: i64,
    pub agent_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub server: String,
    pub connected: bool,
    pub tunnels: u8,
    #[serde(default)]
    pub routes: Vec<RouteStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// `agent.json` -> `agent.status.json`, in the same directory.
pub fn path_for_state(state: &Path) -> PathBuf {
    let stem = state
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("agent");
    state.with_file_name(format!("{stem}.status.json"))
}

impl StatusFile {
    pub fn load(path: &Path) -> Option<Self> {
        serde_json::from_slice(&std::fs::read(path).ok()?).ok()
    }

    /// The file is rewritten every second, so an old one means the process is
    /// gone (a killed agent, a stopped service, a reboot).
    pub fn is_fresh(&self, now: i64) -> bool {
        (0..=FRESH_SECS).contains(&(now - self.updated_at))
    }

    pub fn save(&self, path: &Path) {
        let Ok(text) = serde_json::to_vec_pretty(self) else {
            return;
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, &text).is_err() {
            return;
        }
        let _ = std::fs::rename(&tmp, path);
    }

    /// Seconds since the agent started, or `None` when the clock disagrees.
    pub fn uptime_secs(&self, now: i64) -> Option<i64> {
        let up = now - self.started_at;
        (up >= 0).then_some(up)
    }
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `3m 12s`, `2h 04m`, `9d 01h` — enough to see a flapping service at a glance.
pub fn human_uptime(secs: i64) -> String {
    let secs = secs.max(0);
    if secs < 60 {
        return format!("{secs}s");
    }
    let (m, s) = (secs / 60, secs % 60);
    if m < 60 {
        return format!("{m}m {s:02}s");
    }
    let (h, m) = (m / 60, m % 60);
    if h < 24 {
        return format!("{h}h {m:02}m");
    }
    let (d, h) = (h / 24, h % 24);
    format!("{d}d {h:02}h")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_file_sits_next_to_the_credential() {
        assert_eq!(
            path_for_state(Path::new("/var/lib/fairlead/agent.json")),
            PathBuf::from("/var/lib/fairlead/agent.status.json")
        );
        assert_eq!(
            path_for_state(Path::new("/etc/fairlead/agent")),
            PathBuf::from("/etc/fairlead/agent.status.json")
        );
    }

    #[test]
    fn a_status_file_goes_stale() {
        let s = StatusFile {
            updated_at: 1_000,
            ..Default::default()
        };
        assert!(s.is_fresh(1_000));
        assert!(s.is_fresh(1_000 + FRESH_SECS));
        assert!(!s.is_fresh(1_001 + FRESH_SECS));
    }

    #[test]
    fn status_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("fairlead-status-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.status.json");
        let status = StatusFile {
            pid: 42,
            started_at: 10,
            updated_at: 12,
            agent_name: "机房-A".into(),
            agent_id: Some("id".into()),
            server: "http://relay.test:9000".into(),
            connected: true,
            tunnels: 2,
            routes: vec![RouteStatus {
                host: "a1.relay.test".into(),
                target: "127.0.0.1:8080".into(),
                state: "serving".into(),
                reason: None,
            }],
            last_error: None,
        };
        status.save(&path);
        let back = StatusFile::load(&path).expect("loads");
        assert_eq!(back.agent_name, "机房-A");
        assert_eq!(back.routes.len(), 1);
        assert_eq!(back.routes[0].state, "serving");
        assert!(
            !dir.join("agent.status.tmp").exists(),
            "no temp file left behind"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn uptimes_read_like_uptimes() {
        assert_eq!(human_uptime(9), "9s");
        assert_eq!(human_uptime(192), "3m 12s");
        assert_eq!(human_uptime(7_440), "2h 04m");
        assert_eq!(human_uptime(90_000), "1d 01h");
    }
}
