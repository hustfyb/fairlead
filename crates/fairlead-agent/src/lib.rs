//! fairlead agent: outbound-only tunnel client.

pub mod client;
pub mod config;
pub mod forward;
pub mod probe;
pub mod state;
pub mod status;
pub mod tls;

pub use client::{run, run_with_path};
pub use config::{default_state_path, AgentConfig, TlsMode};
