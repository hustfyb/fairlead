//! Control-stream messages and framing.
//!
//! The control stream carries low-volume, human-debuggable JSON: one `u32`
//! big-endian length followed by a JSON body capped at [`MAX_CONTROL_FRAME`].
//! Data streams never use this framing; they are raw bytes after a preamble.

use std::io;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{MAX_CONTROL_FRAME, MAX_TARGET_BYTES};

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("control frame too large: {0} bytes")]
    TooLarge(usize),
    #[error("control frame is not valid json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("control stream closed")]
    Eof,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// One `Host:port` the agent wants to serve.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteDecl {
    pub host: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Credential {
    /// One-time enrollment token. Exchanged for a long-lived credential.
    Token { value: String },
    /// Long-lived credential issued by the host.
    Credential { value: String },
}

impl Credential {
    pub fn secret(&self) -> &str {
        match self {
            Credential::Token { value } | Credential::Credential { value } => value,
        }
    }
    pub fn is_token(&self) -> bool {
        matches!(self, Credential::Token { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum AgentMsg {
    Hello {
        proto: u16,
        agent_version: String,
        agent_name: String,
        credential: Credential,
        routes: Vec<RouteDecl>,
        /// How many physical tunnels the agent intends to run for this agent.
        tunnels: u8,
    },
    Heartbeat {
        ts_ms: u64,
    },
    /// Hot route update (no reconnect required).
    Routes {
        routes: Vec<RouteDecl>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptedRoute {
    pub host: String,
    pub route_id: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedRoute {
    pub host: String,
    pub target: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum HostMsg {
    Welcome {
        agent_id: String,
        session_id: String,
        /// Present exactly once, when a one-time token was just consumed.
        credential: Option<String>,
        accepted: Vec<AcceptedRoute>,
        rejected: Vec<RejectedRoute>,
        heartbeat_secs: u64,
        tunnel_count: u8,
    },
    Reject {
        code: String,
        message: String,
    },
    Pong {
        ts_ms: u64,
    },
    Revoked {
        reason: String,
    },
    RouteUpdate {
        accepted: Vec<AcceptedRoute>,
        rejected: Vec<RejectedRoute>,
    },
}

pub async fn write_msg<W, T>(w: &mut W, msg: &T) -> Result<(), ControlError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_CONTROL_FRAME {
        return Err(ControlError::TooLarge(body.len()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_msg<R, T>(r: &mut R) -> Result<T, ControlError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    read_exact_or_eof(r, &mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_CONTROL_FRAME {
        return Err(ControlError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    read_exact_or_eof(r, &mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

async fn read_exact_or_eof<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> Result<(), ControlError> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Err(ControlError::Eof);
        }
        filled += n;
    }
    Ok(())
}

/// Validate a declared target string (`host:port`). Rejects anything that is
/// not a plain `host:port`: no scheme, no path, no whitespace.
pub fn validate_target(target: &str) -> Result<(), &'static str> {
    if target.is_empty() || target.len() > MAX_TARGET_BYTES {
        return Err("target length out of range");
    }
    if target.bytes().any(|b| b.is_ascii_whitespace()) || target.contains('/') || target.contains('@') {
        return Err("target must be host:port");
    }
    let (host, port) = target.rsplit_once(':').ok_or("target must be host:port")?;
    if host.is_empty() {
        return Err("target host is empty");
    }
    let port: u16 = port.parse().map_err(|_| "target port is not a number")?;
    if port == 0 {
        return Err("target port 0");
    }
    Ok(())
}
