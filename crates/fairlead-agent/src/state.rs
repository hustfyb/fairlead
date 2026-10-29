//! Cached credential on disk.
//!
//! Format: `{"credential": "...", "agent_id": "..."}`. On Unix the file is
//! written 0600. Losing it is not fatal: enroll again with a fresh token.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CachedState {
    #[serde(default)]
    pub credential: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
}

pub fn load(path: &Path) -> CachedState {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(path: &Path, state: &CachedState) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let text = serde_json::to_vec_pretty(state).unwrap_or_default();
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&text)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
