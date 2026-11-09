//! Forward-proxy passthrough on the front door.
//!
//! A request addressed to a *proxy* names its destination in the request line:
//!
//! ```text
//! CONNECT example.com:443 HTTP/1.1        <- HTTPS, then raw TLS bytes
//! GET http://example.com/a?b=1 HTTP/1.1   <- plain HTTP, absolute form
//! ```
//!
//! In both, `Host` is the *destination*, so the front door has nothing to look
//! up: `example.com` is not one of our routes, and answering it with the
//! landing page's 404 is what made the relay useless as a proxy.
//!
//! `[proxy] route` names the one route that answers these requests instead. The
//! relay stays dumb: it opens the tunnel, writes the preamble for that route's
//! target, then splices bytes in both directions without parsing anything.
//! `CONNECT` therefore needs no implementation here — the agent's target is a
//! real forward proxy (xray, mihomo, squid, privoxy, …) and *that* speaks the
//! proxy protocol. One port, no extra listener, no HTTP parsing.
//!
//! See ARCHITECTURE §4.5 and DECISIONS ADR-19.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use fairlead_proto::data::{encode_preamble, DialStatus};
use fairlead_proto::http1::{RequestHead, Sniffed};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::debug;

use crate::config::HostConfig;
use crate::registry::RouteStatus;
use crate::HostState;

/// True when this request must go to `[proxy] route` instead of a route lookup.
pub(crate) fn is_proxy_request(cfg: &HostConfig, head: &RequestHead) -> bool {
    cfg.proxy.enabled() && head.is_proxy_form()
}

/// Answer everything after the head has been read, on a stream the caller owns.
///
/// The caller has already sniffed the head, so this owns the connection from
/// here: route lookup, tunnel, dial status, splice.
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
    let cfg = state.cfg.clone();

    // The destination, for the log and for error text: a proxy request never
    // carries our route name anywhere.
    let dest = sniffed.head.proxy_authority().unwrap_or_default().to_string();

    let Some(route_host) = cfg.proxy.route_host(&cfg.server.allowed_suffixes) else {
        return crate::edge::respond(
            &mut client,
            404,
            "Not Found",
            "this port is not a proxy",
            &request_id,
            None,
        )
        .await;
    };

    // 1. Who is asking. `Proxy-Authorization` is the standard slot, and 407 is
    //    what makes curl and every browser re-send the request with the
    //    credential from the `-x user:pass@` / proxy dialog.
    if !cfg.proxy.auth.is_empty() {
        let given = sniffed.head.header("proxy-authorization").unwrap_or_default();
        if !credential_ok(given, &cfg.proxy.auth) {
            debug!(%request_id, %peer, %dest, "proxy credential missing or wrong");
            return challenge(&mut client, &request_id).await;
        }
    }
    if !cfg.proxy.allows(peer.ip()) {
        state.metrics().no_route.fetch_add(1, Ordering::Relaxed);
        log(
            &state,
            &request_id,
            &dest,
            None,
            None,
            403,
            started,
            Some("proxy client address not allowed"),
        );
        return crate::edge::respond(
            &mut client,
            403,
            "Forbidden",
            &format!("proxy access from {peer} is not allowed"),
            &request_id,
            Some(&dest),
        )
        .await;
    }

    // 2. The egress route. Same rules as a site route: it has to be declared by
    //    a live agent, and a tombstone stays a tombstone.
    let table = state.registry.routes();
    let route = match table.get(&route_host) {
        Some(r) if r.status == RouteStatus::Active => r.clone(),
        Some(r) => {
            let reason = format!("proxy agent not ready ({})", r.status.as_str());
            state.metrics().route_offline.fetch_add(1, Ordering::Relaxed);
            log(
                &state,
                &request_id,
                &dest,
                Some(r.route_id.clone()),
                Some(r.agent_id.clone()),
                503,
                started,
                Some(&reason),
            );
            return crate::edge::respond(
                &mut client,
                503,
                "Service Unavailable",
                &reason,
                &request_id,
                Some(&dest),
            )
            .await;
        }
        None => {
            let reason = format!("no agent declares the proxy route {route_host}");
            state.metrics().route_offline.fetch_add(1, Ordering::Relaxed);
            log(&state, &request_id, &dest, None, None, 503, started, Some(&reason));
            return crate::edge::respond(
                &mut client,
                503,
                "Service Unavailable",
                &reason,
                &request_id,
                Some(&dest),
            )
            .await;
        }
    };

    let agents = state.registry.agents();
    let tunnel = match agents.get(&route.agent_id).and_then(|a| a.next_tunnel()) {
        Some(t) if !t.is_closed() => t,
        _ => {
            state.metrics().route_offline.fetch_add(1, Ordering::Relaxed);
            log(
                &state,
                &request_id,
                &dest,
                Some(route.route_id.clone()),
                Some(route.agent_id.clone()),
                503,
                started,
                Some("no_tunnel"),
            );
            return crate::edge::respond(
                &mut client,
                503,
                "Service Unavailable",
                "agent offline",
                &request_id,
                Some(&dest),
            )
            .await;
        }
    };

    let dial_wait = cfg.limits.dial_wait_timeout();
    let mut upstream = match tunnel.open_stream(dial_wait).await {
        Ok(s) => s.compat(),
        Err(e) => {
            state.metrics().upstream_timeout.fetch_add(1, Ordering::Relaxed);
            let reason = format!("open_stream: {e}");
            log(
                &state,
                &request_id,
                &dest,
                Some(route.route_id.clone()),
                Some(route.agent_id.clone()),
                504,
                started,
                Some(&reason),
            );
            return crate::edge::respond(
                &mut client,
                504,
                "Gateway Timeout",
                "could not open tunnel stream",
                &request_id,
                Some(&dest),
            )
            .await;
        }
    };

    let preamble = match encode_preamble(&route.target) {
        Ok(p) => p,
        Err(e) => {
            log(
                &state,
                &request_id,
                &dest,
                Some(route.route_id.clone()),
                Some(route.agent_id.clone()),
                502,
                started,
                Some("invalid route target"),
            );
            return crate::edge::respond(
                &mut client,
                502,
                "Bad Gateway",
                &format!("invalid egress target: {e}"),
                &request_id,
                Some(&dest),
            )
            .await;
        }
    };

    // 3. The head goes out **exactly as received**. It is the proxy's request,
    //    not ours: no `Connection: close` rewrite, no header filtering. A
    //    `CONNECT` head in particular must reach the target byte for byte, and
    //    a keep-alive client must be able to reuse this connection.
    let mut out = Vec::with_capacity(preamble.len() + sniffed.head.raw.len() + sniffed.body_prefix.len());
    out.extend_from_slice(&preamble);
    out.extend_from_slice(&sniffed.head.raw);
    out.extend_from_slice(&sniffed.body_prefix);
    if let Err(e) = upstream.write_all(&out).await {
        log(
            &state,
            &request_id,
            &dest,
            Some(route.route_id.clone()),
            Some(route.agent_id.clone()),
            502,
            started,
            Some("write to tunnel"),
        );
        return crate::edge::respond(
            &mut client,
            502,
            "Bad Gateway",
            &format!("tunnel write failed: {e}"),
            &request_id,
            Some(&dest),
        )
        .await;
    }
    let _ = upstream.flush().await;

    let mut status_byte = [0u8; 1];
    let dial_status = match timeout(
        dial_wait,
        tokio::io::AsyncReadExt::read_exact(&mut upstream, &mut status_byte),
    )
    .await
    {
        Ok(Ok(_)) => DialStatus::from_byte(status_byte[0]),
        Ok(Err(_)) => None,
        Err(_) => Some(DialStatus::Timeout),
    };
    match dial_status {
        Some(DialStatus::Ok) => {}
        Some(DialStatus::Blocked) => {
            log(
                &state,
                &request_id,
                &dest,
                Some(route.route_id.clone()),
                Some(route.agent_id.clone()),
                403,
                started,
                Some("target blocked by agent policy"),
            );
            return crate::edge::respond(
                &mut client,
                403,
                "Forbidden",
                "egress target blocked by agent policy",
                &request_id,
                Some(&dest),
            )
            .await;
        }
        Some(DialStatus::Timeout) => {
            state.metrics().upstream_timeout.fetch_add(1, Ordering::Relaxed);
            log(
                &state,
                &request_id,
                &dest,
                Some(route.route_id.clone()),
                Some(route.agent_id.clone()),
                504,
                started,
                Some("agent dial timed out"),
            );
            return crate::edge::respond(
                &mut client,
                504,
                "Gateway Timeout",
                "agent could not reach the egress proxy in time",
                &request_id,
                Some(&dest),
            )
            .await;
        }
        Some(DialStatus::Refused) | Some(DialStatus::BadRequest) => {
            state.metrics().upstream_refused.fetch_add(1, Ordering::Relaxed);
            log(
                &state,
                &request_id,
                &dest,
                Some(route.route_id.clone()),
                Some(route.agent_id.clone()),
                502,
                started,
                Some("agent could not connect target"),
            );
            return crate::edge::respond(
                &mut client,
                502,
                "Bad Gateway",
                &format!("agent could not reach the egress proxy at {}", route.target),
                &request_id,
                Some(&dest),
            )
            .await;
        }
        None => {
            state.metrics().upstream_timeout.fetch_add(1, Ordering::Relaxed);
            log(
                &state,
                &request_id,
                &dest,
                Some(route.route_id.clone()),
                Some(route.agent_id.clone()),
                502,
                started,
                Some("tunnel closed before status"),
            );
            return crate::edge::respond(
                &mut client,
                502,
                "Bad Gateway",
                "tunnel closed before replying",
                &request_id,
                Some(&dest),
            )
            .await;
        }
    }

    // 4. Splice. `idle_timeout_secs = 0` (the default) means an idle CONNECT
    //    tunnel is left alone; the stream ends when either side closes.
    debug!(%request_id, %dest, target = %route.target, t = ?started.elapsed(), "proxy stream opened");
    state.metrics().active_streams.fetch_add(1, Ordering::Relaxed);
    let stats = crate::edge::pipe(client, upstream, cfg.proxy.idle()).await;
    state.metrics().active_streams.fetch_sub(1, Ordering::Relaxed);

    let code = stats
        .status
        .unwrap_or(if stats.error.is_some() { 502 } else { 200 })
        .min(599) as i64;
    state.metrics().status(code as u16);
    state.metrics().bytes_up.fetch_add(stats.up, Ordering::Relaxed);
    state.metrics().bytes_down.fetch_add(stats.down, Ordering::Relaxed);
    log_bytes(
        &state,
        &request_id,
        &dest,
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

#[allow(clippy::too_many_arguments)]
fn log(
    state: &HostState,
    request_id: &str,
    dest: &str,
    route_id: Option<String>,
    agent_id: Option<String>,
    status: u16,
    started: Instant,
    error: Option<&str>,
) {
    log_bytes(
        state, request_id, dest, route_id, agent_id, status, started, 0, 0, error,
    );
}

/// Same, for the one call that knows how much actually moved.
#[allow(clippy::too_many_arguments)]
fn log_bytes(
    state: &HostState,
    request_id: &str,
    dest: &str,
    route_id: Option<String>,
    agent_id: Option<String>,
    status: u16,
    started: Instant,
    up: u64,
    down: u64,
    error: Option<&str>,
) {
    crate::edge::log_request(
        state,
        request_id,
        (!dest.is_empty()).then(|| dest.to_string()),
        route_id,
        agent_id,
        status,
        started,
        up,
        down,
        error,
    );
}

/// 407, with the challenge that makes a client try again with credentials.
async fn challenge<S>(client: &mut S, request_id: &str) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = format!(
        "407 Proxy Authentication Required\n\
         send `Proxy-Authorization: Basic base64(user:password)`\n\
         request-id: {request_id}\n"
    );
    let head = format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\n\
         Proxy-Authenticate: Basic realm=\"fairlead\", charset=\"UTF-8\"\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         x-fairlead-request-id: {request_id}\r\n\r\n",
        body.len()
    );
    let r = async {
        client.write_all(head.as_bytes()).await?;
        client.write_all(body.as_bytes()).await?;
        client.flush().await
    }
    .await;
    let _ = client.shutdown().await;
    r?;
    Ok(())
}

/// Compare a `Proxy-Authorization` value with `user:password`.
///
/// `Basic` only: it is the scheme every browser and curl use for a proxy
/// prompt, and the comparison is on the encoded form so nothing is decoded.
fn credential_ok(value: &[u8], expected: &str) -> bool {
    let text = String::from_utf8_lossy(value);
    let Some((scheme, rest)) = text.trim().split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }
    let want = base64(expected.as_bytes());
    let got = rest.trim().as_bytes();
    got.len() == want.len() && got.iter().zip(want.as_bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Minimal base64 (standard alphabet, padded). Adding a dependency for the 20
/// bytes that a proxy credential needs is not worth it.
fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_reference_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"Aladdin:open sesame"), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }

    #[test]
    fn only_basic_with_the_right_secret_passes() {
        let want = "Aladdin:open sesame";
        assert!(credential_ok(b"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", want));
        assert!(credential_ok(b"basic   QWxhZGRpbjpvcGVuIHNlc2FtZQ==  ", want));
        assert!(!credential_ok(b"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=", want), "truncated");
        assert!(!credential_ok(b"Basic d3Jvbmc6d3Jvbmc=", want), "wrong secret");
        assert!(
            !credential_ok(b"Bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ==", want),
            "wrong scheme"
        );
        assert!(!credential_ok(b"", want));
        assert!(!credential_ok(b"Basic", want));
    }
}
