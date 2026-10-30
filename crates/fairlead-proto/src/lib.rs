//! fairlead wire protocol v1.
//!
//! This crate is the single source of truth shared by `fairlead-host` and
//! `fairlead-agent`. It has no I/O policy of its own: it parses, frames and
//! validates, and leaves decisions to the caller.
//!
//! Layers:
//!
//! ```text
//! TCP -> [TLS 1.3] -> HTTP/1.1 upgrade -> yamux -> [ control stream | data streams ]
//! ```
//!
//! TLS is optional: it is terminated either in front of the host (nginx) or by
//! the host's own tunnel listener. Either way the tunnel plane starts with the
//! same upgrade request, so a plaintext single port can still tell an agent
//! from a browser by `Host` + `Upgrade` (see [`front`]).
//!
//! * Control stream (opened by the agent): `u32 len | JSON`.
//! * Data stream (opened by the host): `0x01 | u16 target_len | target | HTTP/1.1 head + body`.
//! * The agent answers each data stream with exactly one status byte before
//!   any response bytes, so "refused" and "timeout" survive the tunnel.

pub mod control;
pub mod data;
pub mod front;
pub mod hostname;
pub mod http1;
pub mod mux;
pub mod policy;
pub mod stream;

/// Bumped only on breaking changes. A host refuses agents with a different
/// major protocol number instead of guessing.
pub const PROTOCOL_VERSION: u16 = 1;

/// TLS ALPN protocol identifier. Also the `Upgrade:` value agents send on a
/// plaintext port, so both transports select the same plane.
pub const ALPN: &[u8] = b"fairlead/1";

/// Hard ceiling on the HTTP request head the host buffers before it either
/// routes the request or answers 431.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Hard ceiling on a single control frame.
pub const MAX_CONTROL_FRAME: usize = 64 * 1024;

/// Hard ceiling on a route target string (`host:port`).
pub const MAX_TARGET_BYTES: usize = 255;

pub use control::{AgentMsg, Credential, HostMsg, RouteDecl};
pub use front::{upgrade_request, wants_tunnel, write_101, UPGRADE_PROTOCOL};
pub use http1::{RequestHead, Sniffed};
pub use stream::Prefixed;
