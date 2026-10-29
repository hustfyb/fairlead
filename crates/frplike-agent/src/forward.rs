//! Data-stream handling on the agent: policy, dial, status byte, splice.

use std::sync::Arc;
use std::time::Duration;

use frplike_proto::data::{read_preamble, DialStatus};
use frplike_proto::policy::{self, TargetError};
use tokio::io::{AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, warn};

use crate::client::Shared;

pub async fn handle(shared: Arc<Shared>, stream: yamux::Stream) {
    let started = std::time::Instant::now();
    let mut up = stream.compat();

    let target = match timeout(Duration::from_secs(5), read_preamble(&mut up)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            debug!(error = %e, "bad data stream preamble");
            return;
        }
        Err(_) => return,
    };

    debug!(%target, t = ?started.elapsed(), "preamble read");
    let resolved = match policy::resolve_target(&target, shared.cfg.allow_public_targets).await {
        Ok(t) => t,
        Err(TargetError::Blocked(ip)) => {
            warn!(%target, %ip, "target blocked by policy");
            let _ = up.write_all(&[DialStatus::Blocked.as_byte()]).await;
            return;
        }
        Err(e) => {
            debug!(%target, error = %e, "target does not resolve");
            let _ = up.write_all(&[DialStatus::Refused.as_byte()]).await;
            return;
        }
    };

    debug!(%target, t = ?started.elapsed(), "resolved");
    let mut tcp = None;
    let mut saw_timeout = false;
    for addr in &resolved.addrs {
        match timeout(shared.cfg.dial_timeout(), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                tcp = Some(s);
                break;
            }
            Ok(Err(e)) => debug!(%target, %addr, error = %e, "dial failed"),
            Err(_) => saw_timeout = true,
        }
    }
    let mut tcp = match tcp {
        Some(t) => t,
        None => {
            let status = if saw_timeout { DialStatus::Timeout } else { DialStatus::Refused };
            let _ = up.write_all(&[status.as_byte()]).await;
            return;
        }
    };
    tcp.set_nodelay(true).ok();

    if up.write_all(&[DialStatus::Ok.as_byte()]).await.is_err() {
        return;
    }

    debug!(%target, t = ?started.elapsed(), "connected, status sent");
    match tokio::io::copy_bidirectional(&mut up, &mut tcp).await {
        Ok((up_bytes, down_bytes)) => {
            debug!(%target, up_bytes, down_bytes, t = ?started.elapsed(), "stream finished")
        }
        Err(e) => debug!(%target, error = %e, "stream ended with error"),
    }
}
