//! Edge listener: the only place that understands HTTP.
//!
//! It reads a bounded request head, resolves the Host against the in-memory
//! route table, opens one yamux stream, and then copies bytes. It never parses
//! a response body and never rewrites one. See ARCHITECTURE §4.

use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fairlead_proto::data::{encode_preamble, DialStatus};
use fairlead_proto::hostname;
use fairlead_proto::http1::{head_with_connection_close, read_request_head, HeadError, StatusSniffer};
use fairlead_proto::Sniffed;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, warn};

use crate::db::RequestLogRow;
use crate::metrics::now_unix_ms;
use crate::registry::RouteStatus;
use crate::HostState;

pub async fn accept_loop(state: Arc<HostState>, listener: TcpListener, mut shutdown: watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "edge accept failed");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                };
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve(state, stream, peer).await {
                        debug!(%peer, error = %e, "edge request ended with error");
                    }
                });
            }
        }
    }
    tracing::info!("edge listener stopped");
}

async fn serve(state: Arc<HostState>, mut client: TcpStream, peer: std::net::SocketAddr) -> anyhow::Result<()> {
    client.set_nodelay(true).ok();
    let started = Instant::now();
    let request_id = format!("{:016x}", rand::random::<u64>());
    state.metrics().requests.fetch_add(1, Ordering::Relaxed);

    let head_timeout = Duration::from_secs(state.cfg.limits.head_timeout_secs.max(1));
    let max_head = state.cfg.limits.max_head_bytes.clamp(1024, fairlead_proto::MAX_HEAD_BYTES);

    let sniffed = match timeout(head_timeout, read_request_head(&mut client, max_head)).await {
        Ok(Ok(s)) => s,
        Ok(Err(HeadError::TooLarge)) => {
            return respond(&mut client, 431, "Request Header Fields Too Large", "request head too large", &request_id, None).await;
        }
        Ok(Err(HeadError::Eof)) => return Ok(()),
        Ok(Err(HeadError::Malformed(m))) => {
            return respond(&mut client, 400, "Bad Request", m, &request_id, None).await;
        }
        Ok(Err(HeadError::Io(e))) => return Err(e.into()),
        Err(_) => {
            return respond(&mut client, 408, "Request Timeout", "timed out reading request head", &request_id, None).await;
        }
    };

    serve_head(state, client, peer, sniffed, started, request_id).await
}

/// Everything after the request head: route lookup, tunnel stream, splicing.
///
/// Split out so the unified front door can hand over a connection whose head
/// it already read, instead of reading and parsing the head twice.
pub(crate) async fn serve_head<S>(
    state: Arc<HostState>,
    mut client: S,
    peer: std::net::SocketAddr,
    sniffed: Sniffed,
    started: Instant,
    request_id: String,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = match sniffed.head.host_raw.as_deref().map(hostname::normalize) {
        Some(Ok(h)) => h,
        Some(Err(e)) => {
            return respond(&mut client, 400, "Bad Request", &format!("invalid host: {e}"), &request_id, None).await;
        }
        None => {
            return respond(&mut client, 400, "Bad Request", "missing host header", &request_id, None)
                .await;
        }
    };

    if !hostname::matches_suffix(&host, &state.cfg.server.allowed_suffixes) {
        state.metrics().no_route.fetch_add(1, Ordering::Relaxed);
        return respond(&mut client, 404, "Not Found", "no route for this host", &request_id, Some(&host)).await;
    }

    let table = state.registry.routes();
    let route = match table.get(&host) {
        None => {
            state.metrics().no_route.fetch_add(1, Ordering::Relaxed);
            log_request(&state, &request_id, Some(host.clone()), None, None, 404, started, 0, 0, Some("no_route"));
            return respond(&mut client, 404, "Not Found", "no route for this host", &request_id, Some(&host)).await;
        }
        Some(r) if r.status == RouteStatus::Deleted => {
            state.metrics().no_route.fetch_add(1, Ordering::Relaxed);
            log_request(&state, &request_id, Some(host.clone()), Some(r.route_id.clone()), Some(r.agent_id.clone()), 404, started, 0, 0, Some("route deleted"));
            return respond(&mut client, 404, "Not Found", "no route for this host", &request_id, Some(&host)).await;
        }
        Some(r) if r.status != RouteStatus::Active => {
            state.metrics().route_offline.fetch_add(1, Ordering::Relaxed);
            let reason = match r.status {
                RouteStatus::Disabled => "route disabled by administrator",
                _ => "agent offline",
            };
            log_request(&state, &request_id, Some(host.clone()), Some(r.route_id.clone()), Some(r.agent_id.clone()), 503, started, 0, 0, Some(reason));
            return respond(&mut client, 503, "Service Unavailable", reason, &request_id, Some(&host)).await;
        }
        Some(r) => r.clone(),
    };

    let agents = state.registry.agents();
    let agent = match agents.get(&route.agent_id) {
        Some(a) => a.clone(),
        None => {
            state.metrics().route_offline.fetch_add(1, Ordering::Relaxed);
            return respond(&mut client, 503, "Service Unavailable", "agent offline", &request_id, Some(&host)).await;
        }
    };
    let tunnel = match agent.next_tunnel() {
        Some(t) if !t.is_closed() => t,
        _ => {
            state.metrics().route_offline.fetch_add(1, Ordering::Relaxed);
            log_request(&state, &request_id, Some(host.clone()), Some(route.route_id.clone()), Some(route.agent_id.clone()), 503, started, 0, 0, Some("no_tunnel"));
            return respond(&mut client, 503, "Service Unavailable", "agent offline", &request_id, Some(&host)).await;
        }
    };

    let dial_wait = state.cfg.limits.dial_wait_timeout();
    debug!(%request_id, host = %host, t = ?started.elapsed(), "routing to agent");
    let mut upstream = match tunnel.open_stream(dial_wait).await {
        Ok(s) => s.compat(),
        Err(e) => {
            state.metrics().upstream_timeout.fetch_add(1, Ordering::Relaxed);
            log_request(&state, &request_id, Some(host.clone()), Some(route.route_id.clone()), Some(route.agent_id.clone()), 504, started, 0, 0, Some(&format!("open_stream: {e}")));
            return respond(&mut client, 504, "Gateway Timeout", "could not open tunnel stream", &request_id, Some(&host)).await;
        }
    };

    let preamble = match encode_preamble(&route.target) {
        Ok(p) => p,
        Err(e) => {
            warn!(%host, error = %e, "invalid route target");
            return respond(&mut client, 502, "Bad Gateway", "invalid route target", &request_id, Some(&host)).await;
        }
    };
    let head_bytes = if sniffed.head.upgrade {
        sniffed.head.raw.clone()
    } else {
        head_with_connection_close(&sniffed.head)
    };

    debug!(%request_id, t = ?started.elapsed(), "stream opened");
    if let Err(e) = write_request(&mut upstream, &preamble, &head_bytes, &sniffed.body_prefix).await {
        log_request(&state, &request_id, Some(host.clone()), Some(route.route_id.clone()), Some(route.agent_id.clone()), 502, started, 0, 0, Some(&format!("write request: {e}")));
        return respond(&mut client, 502, "Bad Gateway", "tunnel write failed", &request_id, Some(&host)).await;
    }

    debug!(%request_id, t = ?started.elapsed(), "request written");
    let mut status_byte = [0u8; 1];
    let dial_status = match timeout(dial_wait, upstream.read_exact(&mut status_byte)).await {
        Ok(Ok(_)) => DialStatus::from_byte(status_byte[0]),
        Ok(Err(_)) => None,
        Err(_) => Some(DialStatus::Timeout),
    };

    match dial_status {
        Some(DialStatus::Ok) => {}
        Some(DialStatus::Blocked) => {
            log_request(&state, &request_id, Some(host.clone()), Some(route.route_id.clone()), Some(route.agent_id.clone()), 403, started, 0, 0, Some("target blocked by agent policy"));
            return respond(&mut client, 403, "Forbidden", "target blocked by agent policy", &request_id, Some(&host)).await;
        }
        Some(DialStatus::Timeout) => {
            state.metrics().upstream_timeout.fetch_add(1, Ordering::Relaxed);
            log_request(&state, &request_id, Some(host.clone()), Some(route.route_id.clone()), Some(route.agent_id.clone()), 504, started, 0, 0, Some("agent dial timed out"));
            return respond(&mut client, 504, "Gateway Timeout", "agent could not reach the local target in time", &request_id, Some(&host)).await;
        }
        Some(DialStatus::Refused) | Some(DialStatus::BadRequest) => {
            state.metrics().upstream_refused.fetch_add(1, Ordering::Relaxed);
            log_request(&state, &request_id, Some(host.clone()), Some(route.route_id.clone()), Some(route.agent_id.clone()), 502, started, 0, 0, Some("agent could not connect target"));
            return respond(&mut client, 502, "Bad Gateway", "agent could not connect to the local target", &request_id, Some(&host)).await;
        }
        None => {
            state.metrics().upstream_timeout.fetch_add(1, Ordering::Relaxed);
            log_request(&state, &request_id, Some(host.clone()), Some(route.route_id.clone()), Some(route.agent_id.clone()), 502, started, 0, 0, Some("tunnel closed before status"));
            return respond(&mut client, 502, "Bad Gateway", "tunnel closed before replying", &request_id, Some(&host)).await;
        }
    }

    debug!(%request_id, t = ?started.elapsed(), status = ?dial_status, "dial status received");
    let idle = if sniffed.head.upgrade {
        state.cfg.limits.upgrade_idle_timeout()
    } else {
        state.cfg.limits.idle_timeout()
    };
    state.metrics().active_streams.fetch_add(1, Ordering::Relaxed);
    let stats = pipe(client, upstream, idle).await;
    debug!(%request_id, t = ?started.elapsed(), up = stats.up, down = stats.down, "pipe done");
    state.metrics().active_streams.fetch_sub(1, Ordering::Relaxed);

    let code = stats.status.unwrap_or(if stats.error.is_some() { 502 } else { 200 }).min(599) as i64;
    state.metrics().status(code as u16);
    state.metrics().bytes_up.fetch_add(stats.up, Ordering::Relaxed);
    state.metrics().bytes_down.fetch_add(stats.down, Ordering::Relaxed);
    log_request(
        &state,
        &request_id,
        Some(host.clone()),
        Some(route.route_id.clone()),
        Some(route.agent_id.clone()),
        code as u16,
        started,
        stats.up,
        stats.down,
        stats.error.as_deref(),
    );
    let _ = peer;
    Ok(())
}

async fn write_request<W: AsyncWrite + Unpin>(
    w: &mut W,
    preamble: &[u8],
    head: &[u8],
    body_prefix: &[u8],
) -> io::Result<()> {
    w.write_all(preamble).await?;
    w.write_all(head).await?;
    if !body_prefix.is_empty() {
        w.write_all(body_prefix).await?;
    }
    w.flush().await
}

struct PipeStats {
    up: u64,
    down: u64,
    status: Option<u16>,
    error: Option<String>,
}

async fn pipe<C, U>(client: C, upstream: U, idle: Duration) -> PipeStats
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);

    let mut up = Box::pin(async move {
        let mut bytes = 0u64;
        let mut throwaway = StatusSniffer::default();
        let r = copy_dir(&mut { cr }, &mut { uw }, idle, &mut bytes, &mut throwaway).await;
        (bytes, r)
    });
    let mut down = Box::pin(async move {
        let mut bytes = 0u64;
        let mut sniffer = StatusSniffer::default();
        let r = copy_dir(&mut { ur }, &mut { cw }, idle, &mut bytes, &mut sniffer).await;
        (bytes, r, sniffer.status())
    });

    let mut up_out: Option<(u64, io::Result<()>)> = None;
    let mut down_out: Option<(u64, io::Result<()>, Option<u16>)> = None;
    tokio::select! {
        r = &mut up => up_out = Some(r),
        r = &mut down => down_out = Some(r),
    }
    // One direction finishing is normal (origin closed). Give the other a
    // short grace so half-closed clients still get their response.
    if down_out.is_none() {
        if let Ok(r) = timeout(Duration::from_secs(3), &mut down).await {
            down_out = Some(r);
        }
    }
    if up_out.is_none() {
        if let Ok(r) = timeout(Duration::from_millis(500), &mut up).await {
            up_out = Some(r);
        }
    }

    let mut error = None;
    let (up_bytes, up_res) = match up_out {
        Some(v) => v,
        None => (0, Ok(())),
    };
    let (down_bytes, down_res, status) = match down_out {
        Some(v) => v,
        None => (0, Ok(()), None),
    };
    if let Err(e) = up_res {
        error = Some(format!("upstream write: {e}"));
    }
    if let Err(e) = down_res {
        error.get_or_insert(format!("client write: {e}"));
    }
    PipeStats { up: up_bytes, down: down_bytes, status, error }
}

async fn copy_dir<R, W>(
    r: &mut R,
    w: &mut W,
    idle: Duration,
    bytes: &mut u64,
    sniffer: &mut StatusSniffer,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match timeout(idle, r.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => break,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                // Idle: treat as a normal end for upgrades and slow origins.
                break;
            }
        };
        sniffer.feed(&buf[..n]);
        w.write_all(&buf[..n]).await?;
        *bytes += n as u64;
    }
    let _ = w.shutdown().await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn log_request(
    state: &HostState,
    request_id: &str,
    host: Option<String>,
    route_id: Option<String>,
    agent_id: Option<String>,
    status: u16,
    started: Instant,
    up: u64,
    down: u64,
    error: Option<&str>,
) {
    state.db.log(RequestLogRow {
        ts: now_unix_ms() / 1000,
        request_id: request_id.to_string(),
        host,
        route_id,
        agent_id,
        status: status as i64,
        duration_ms: started.elapsed().as_millis() as i64,
        bytes_up: up as i64,
        bytes_down: down as i64,
        error: error.map(|s| s.to_string()),
    });
}

pub(crate) async fn respond<S>(
    client: &mut S,
    code: u16,
    reason: &str,
    message: &str,
    request_id: &str,
    host: Option<&str>,
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = format!("{code} {reason}\n{message}\nrequest-id: {request_id}\n");
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         x-fairlead-request-id: {request_id}\r\n\
         x-fairlead-error: {code}\r\n\r\n",
        body.len()
    );
    let _ = client.write_all(head.as_bytes()).await;
    let _ = client.write_all(body.as_bytes()).await;
    let _ = client.flush().await;
    let _ = client.shutdown().await;
    let _ = host;
    Ok(())
}
