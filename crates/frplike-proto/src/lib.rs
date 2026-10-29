//! frplike wire protocol v1.
//!
//! This crate is the single source of truth shared by `frplike-host` and
//! `frplike-agent`. It has no I/O policy of its own: it parses, frames and
//! validates, and leaves decisions to the caller.
//!
//! Layers:
//!
//! ```text
//! TCP -> TLS 1.3 -> yamux -> [ control stream | data streams ]
//! ```
//!
//! * Control stream (opened by the agent): `u32 len | JSON`.
//! * Data stream (opened by the host): `0x01 | u16 target_len | target | HTTP/1.1 head + body`.
//! * The agent answers each data stream with exactly one status byte before
//!   any response bytes, so "refused" and "timeout" survive the tunnel.

pub mod control;
pub mod data;
pub mod hostname;
pub mod http1;
pub mod mux;
pub mod policy;

/// Bumped only on breaking changes. A host refuses agents with a different
/// major protocol number instead of guessing.
pub const PROTOCOL_VERSION: u16 = 1;

/// TLS ALPN protocol identifier.
pub const ALPN: &[u8] = b"frplike/1";

/// Hard ceiling on the HTTP request head the host buffers before it either
/// routes the request or answers 431.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Hard ceiling on a single control frame.
pub const MAX_CONTROL_FRAME: usize = 64 * 1024;

/// Hard ceiling on a route target string (`host:port`).
pub const MAX_TARGET_BYTES: usize = 255;

pub use control::{AgentMsg, Credential, HostMsg, RouteDecl};
pub use http1::{RequestHead, Sniffed};
