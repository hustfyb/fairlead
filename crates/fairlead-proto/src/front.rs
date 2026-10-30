//! Tunnel-plane upgrade handshake.
//!
//! Without TLS there is no SNI, so a single plaintext port cannot tell an
//! agent from a browser until the agent says something HTTP-shaped. The
//! tunnel plane therefore starts with an ordinary HTTP/1.1 upgrade request
//! addressed to the tunnel virtual host; the host answers `101` and both
//! sides switch to yamux on the same connection.
//!
//! The upgrade is a *selector*, not an authentication step: credentials still
//! travel in the `Hello` frame on the control stream, exactly as before. That
//! keeps one auth path and one rejection vocabulary.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::http1::{read_head_bytes, HeadError, RequestHead};

/// Value of `Upgrade:`, `Connection:` and the TLS ALPN id.
pub const UPGRADE_PROTOCOL: &str = "fairlead/1";

/// Request path the agent uses. Anything on the tunnel vhost is accepted; this
/// is the documented, greppable default.
pub const UPGRADE_PATH: &str = "/tunnel";

/// The exact `101` the host writes before yamux starts.
pub const RESPONSE_101: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: fairlead/1\r\n\r\n";

/// Build the upgrade request an agent sends before its first yamux frame.
///
/// `host` is the tunnel virtual host (no port): it is what selects the tunnel
/// plane on a unified port. `agent` is informational and sanitized, because a
/// newline in a config value must not become a header injection.
pub fn upgrade_request(host: &str, agent: &str) -> Vec<u8> {
    let mut out = String::with_capacity(192 + host.len() + agent.len());
    out.push_str("GET ");
    out.push_str(UPGRADE_PATH);
    out.push_str(" HTTP/1.1\r\nHost: ");
    out.push_str(host);
    out.push_str("\r\nUser-Agent: fairlead/");
    out.push_str(env!("CARGO_PKG_VERSION"));
    out.push_str("\r\nUpgrade: ");
    out.push_str(UPGRADE_PROTOCOL);
    out.push_str("\r\nConnection: Upgrade\r\nX-Fairlead-Agent: ");
    out.push_str(&sanitize(agent, 128));
    out.push_str("\r\n\r\n");
    out.into_bytes()
}

fn sanitize(value: &str, max: usize) -> String {
    let cleaned: String = value
        .chars()
        .take(max)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    cleaned.trim().to_string()
}

/// True when this request asks to become a tunnel.
pub fn wants_tunnel(head: &RequestHead) -> bool {
    if !head.upgrade {
        return false;
    }
    match head.header("upgrade") {
        Some(v) => std::str::from_utf8(v)
            .map(|s| s.trim().eq_ignore_ascii_case(UPGRADE_PROTOCOL))
            .unwrap_or(false),
        None => false,
    }
}

/// Write the `101` and flush it. After this returns the connection belongs to
/// yamux; nothing else may be written to it by hand.
pub async fn write_101<W>(w: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    w.write_all(RESPONSE_101).await?;
    w.flush().await
}

/// Read and validate the host's upgrade reply.
///
/// Bytes past the response head are returned because they are the first yamux
/// frames: dropping them would silently stall the session.
pub async fn read_upgrade_response<R>(r: &mut R, max: usize) -> Result<Vec<u8>, String>
where
    R: AsyncRead + Unpin,
{
    let (raw, leftover) = read_head_bytes(r, max)
        .await
        .map_err(|e| match e {
            HeadError::Eof => "host closed the connection before replying".to_string(),
            HeadError::TooLarge => "host reply head too large".to_string(),
            other => other.to_string(),
        })?;
    let status = parse_status(&raw)?;
    if status != 101 {
        return Err(format!(
            "host refused the upgrade ({}); check the tunnel host, scheme and port",
            first_line(&raw)
        ));
    }
    Ok(leftover)
}

fn parse_status(raw: &[u8]) -> Result<u16, String> {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut res = httparse::Response::new(&mut headers);
    let status = res.parse(raw).map_err(|_| "malformed upgrade reply".to_string())?;
    if !status.is_complete() {
        return Err("incomplete upgrade reply".to_string());
    }
    let code = res.code.ok_or_else(|| "upgrade reply has no status".to_string())?;
    if code != 101 {
        return Ok(code);
    }
    let protocol_ok = res
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("upgrade") && h.value.eq_ignore_ascii_case(UPGRADE_PROTOCOL.as_bytes()));
    if !protocol_ok {
        return Err(format!("host did not answer with `Upgrade: {UPGRADE_PROTOCOL}`"));
    }
    Ok(code)
}

fn first_line(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == b'\r' || b == b'\n').unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end.min(120)]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_head(raw: &[u8]) -> RequestHead {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(raw).unwrap();
        let mut host = None;
        let mut upgrade = false;
        let mut conn_up = false;
        let mut hs = Vec::new();
        for h in req.headers.iter() {
            let v = h.value.to_vec();
            if h.name.eq_ignore_ascii_case("host") {
                host = Some(String::from_utf8_lossy(&v).trim().to_string());
            }
            if h.name.eq_ignore_ascii_case("upgrade") {
                upgrade = true;
            }
            if h.name.eq_ignore_ascii_case("connection") && String::from_utf8_lossy(&v).to_ascii_lowercase().contains("upgrade") {
                conn_up = true;
            }
            hs.push((h.name.to_string(), v));
        }
        RequestHead {
            raw: raw.to_vec(),
            method: req.method.unwrap().to_string(),
            target: req.path.unwrap().to_string(),
            version: req.version.unwrap(),
            host_raw: host,
            headers: hs,
            upgrade: upgrade && conn_up,
        }
    }

    #[test]
    fn upgrade_request_is_a_well_formed_tunnel_selector() {
        let raw = upgrade_request("tunnel.relay.test", "agent-a");
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(text.starts_with("GET /tunnel HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("Host: tunnel.relay.test\r\n"), "{text}");
        assert!(text.contains("Upgrade: fairlead/1\r\n"), "{text}");
        assert!(text.ends_with("\r\n\r\n"), "{text}");
        let head = parse_head(&raw);
        assert_eq!(head.host_raw.as_deref(), Some("tunnel.relay.test"));
        assert!(wants_tunnel(&head));
    }

    #[test]
    fn agent_name_cannot_inject_headers() {
        let raw = upgrade_request("t.relay.test", "evil\r\nX-Admin: 1");
        let text = String::from_utf8(raw.clone()).unwrap();
        // A newline in a config value would end the head early; it must not
        // create a new header line.
        assert_eq!(text.matches("\r\n").count(), 7, "{text}");
        assert!(text.lines().all(|l| !l.starts_with("X-Admin")), "{text}");
        // ... and the head is still exactly one request.
        assert!(wants_tunnel(&parse_head(&raw)));
    }

    #[test]
    fn a_plain_request_is_not_a_tunnel() {
        let head = parse_head(b"GET / HTTP/1.1\r\nHost: a1.relay.test\r\n\r\n");
        assert!(!wants_tunnel(&head));
        let head = parse_head(b"GET / HTTP/1.1\r\nHost: t.relay.test\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n");
        assert!(!wants_tunnel(&head));
    }

    #[tokio::test]
    async fn response_101_parses_and_keeps_leftover_bytes() {
        let mut buf: Vec<u8> = RESPONSE_101.to_vec();
        buf.extend_from_slice(&[0x01, 0x02, 0x03]);
        let mut r = std::io::Cursor::new(buf);
        let leftover = read_upgrade_response(&mut r, 8192).await.unwrap();
        assert_eq!(leftover, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn response_400_is_reported_with_the_status_line() {
        let msg = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        let mut r = std::io::Cursor::new(msg.to_vec());
        let err = read_upgrade_response(&mut r, 8192).await.unwrap_err();
        assert!(err.contains("400 Bad Request"), "{err}");
    }

    #[tokio::test]
    async fn response_without_the_upgrade_header_is_rejected() {
        let msg = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
        let mut r = std::io::Cursor::new(msg.to_vec());
        assert!(read_upgrade_response(&mut r, 8192).await.is_err());
    }
}
