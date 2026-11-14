//! HTTP/1.1 request-head sniffing.
//!
//! The host is **not** an HTTP proxy: it never parses a response body and
//! never rewrites a response. It reads exactly the request head (bounded),
//! learns the Host, and then splices bytes. The single exception is the
//! `Connection` header on non-upgrade requests: it is replaced with `close`
//! so the origin terminates the response for us (see ARCHITECTURE §4.2).
//! When TLS is terminated in front of the host, the forwarded head also gets
//! `X-Forwarded-Proto` so the origin can work out its own public origin.
//!
//! Everything that is not a well-formed HTTP/1.x request head is rejected
//! before a route lookup, never forwarded.

use std::io;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_HEADERS: usize = 96;

/// A parsed request head. `raw` is the exact bytes received, `headers` is the
/// parsed view used only when rewriting `Connection`.
#[derive(Debug, Clone)]
pub struct RequestHead {
    pub raw: Vec<u8>,
    pub method: String,
    pub target: String,
    /// 0 = HTTP/1.0, 1 = HTTP/1.1
    pub version: u8,
    pub host_raw: Option<String>,
    pub headers: Vec<(String, Vec<u8>)>,
    /// True only when both `Upgrade` and `Connection: upgrade` were present.
    pub upgrade: bool,
}

/// One sniff result: the head plus any body bytes that arrived with it.
#[derive(Debug, Clone)]
pub struct Sniffed {
    pub head: RequestHead,
    pub body_prefix: Vec<u8>,
}

impl RequestHead {
    /// True when the request is addressed to a *forward proxy* rather than to
    /// one of our sites: `CONNECT host:port`, or an absolute-form target
    /// (`GET http://host/ ...`, what every HTTP client sends to a proxy).
    ///
    /// Both forms name the destination in the request line, so `Host` is the
    /// destination too and cannot select a route. The front door needs this to
    /// tell proxy traffic from site traffic on the very same port.
    pub fn is_proxy_form(&self) -> bool {
        self.proxy_authority().is_some()
    }

    /// `host[:port]` that a proxy-form request is asking for, if it is one.
    pub fn proxy_authority(&self) -> Option<&str> {
        if self.method.eq_ignore_ascii_case("CONNECT") {
            return (!self.target.is_empty()).then_some(self.target.as_str());
        }
        absolute_authority(&self.target)
    }

    /// First value for `name`, case-insensitive. Header order is preserved.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
}

/// Authority of an absolute-form request target: `http://a.b:80/x` -> `a.b:80`.
///
/// Sliced on ASCII bytes, so a multi-byte character in the path cannot split a
/// char boundary.
fn absolute_authority(target: &str) -> Option<&str> {
    let bytes = target.as_bytes();
    let skip = if bytes.get(..7).is_some_and(|h| h.eq_ignore_ascii_case(b"http://")) {
        7
    } else if bytes.get(..8).is_some_and(|h| h.eq_ignore_ascii_case(b"https://")) {
        8
    } else {
        return None;
    };
    let rest = &target[skip..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    (!authority.is_empty()).then_some(authority)
}

#[derive(Debug, Error)]
pub enum HeadError {
    #[error("connection closed before request head")]
    Eof,
    #[error("request head exceeds limit")]
    TooLarge,
    #[error("malformed request head: {0}")]
    Malformed(&'static str),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Read one HTTP/1.x request head from `r`.
///
/// Bytes read past the head are returned in [`Sniffed::body_prefix`]; callers
/// must forward them, otherwise bodies that arrive in the same TCP segment as
/// the head are silently truncated.
pub async fn read_request_head<R>(r: &mut R, max: usize) -> Result<Sniffed, HeadError>
where
    R: AsyncRead + Unpin,
{
    let (raw, body_prefix) = read_head_bytes(r, max).await?;
    let head = parse(&raw)?;
    Ok(Sniffed { head, body_prefix })
}

/// Read raw bytes up to and including `\r\n\r\n`, bounded by `max`.
///
/// Returns `(head_bytes, leftover)`. The caller decides whether the head is a
/// request (host side) or a response (agent side).
pub async fn read_head_bytes<R>(r: &mut R, max: usize) -> Result<(Vec<u8>, Vec<u8>), HeadError>
where
    R: AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(pos) = find_head_end(&buf) {
            if pos > max {
                return Err(HeadError::TooLarge);
            }
            break pos;
        }
        if buf.len() >= max {
            return Err(HeadError::TooLarge);
        }
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            return Err(if buf.is_empty() { HeadError::Eof } else { HeadError::Malformed("truncated head") });
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let leftover = buf.split_off(end);
    Ok((buf, leftover))
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let mut i = 0;
    while i + 4 <= buf.len() {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}

fn parse(raw: &[u8]) -> Result<RequestHead, HeadError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    let status = req.parse(raw).map_err(|_| HeadError::Malformed("httparse"))?;
    if !status.is_complete() {
        return Err(HeadError::Malformed("incomplete head"));
    }
    let version_num = req.version.ok_or(HeadError::Malformed("missing version"))?;
    if version_num > 1 {
        return Err(HeadError::Malformed("unsupported version"));
    }
    let method = req.method.ok_or(HeadError::Malformed("missing method"))?.to_string();
    let target = req.path.ok_or(HeadError::Malformed("missing request target"))?.to_string();
    if method.is_empty() || target.is_empty() {
        return Err(HeadError::Malformed("empty method or target"));
    }

    let mut host_raw = None;
    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut parsed_headers: Vec<(String, Vec<u8>)> = Vec::with_capacity(req.headers.len());
    for h in req.headers.iter() {
        let name = h.name.to_string();
        let value = h.value.to_vec();
        if name.eq_ignore_ascii_case("host") {
            host_raw = Some(String::from_utf8_lossy(&value).trim().to_string());
        }
        if name.eq_ignore_ascii_case("upgrade") && !value.is_empty() {
            upgrade = true;
        }
        if name.eq_ignore_ascii_case("connection") {
            let v = String::from_utf8_lossy(&value).to_ascii_lowercase();
            if v.split(',').any(|t| t.trim() == "upgrade") {
                connection_upgrade = true;
            }
        }
        parsed_headers.push((name, value));
    }

    if version_num == 1 && host_raw.is_none() {
        return Err(HeadError::Malformed("missing host"));
    }

    Ok(RequestHead {
        raw: raw.to_vec(),
        method,
        target,
        version: version_num,
        host_raw,
        headers: parsed_headers,
        upgrade: upgrade && connection_upgrade,
    })
}

/// Rebuild the head with `Connection: close`, dropping hop-by-hop headers the
/// client may have sent. Header order changes; semantics do not.
///
/// Never call this for an `Upgrade` request.
pub fn head_with_connection_close(head: &RequestHead) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.raw.len() + 24);
    out.extend_from_slice(format!("{} {} HTTP/1.{}\r\n", head.method, head.target, head.version).as_bytes());
    for (name, value) in &head.headers {
        if name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("keep-alive")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

/// Rebuild the head for the origin, telling it which scheme the public entry
/// point speaks.
///
/// A TLS terminator in front of the relay (nginx `stream`, cloudflared,
/// Tailscale Serve) hands us plain HTTP. Origins behind it need
/// `X-Forwarded-Proto` to compute their own origin for OAuth resource
/// indicators, DPoP and pairing URLs; without it they advertise `http://`
/// while clients ask for `https://`, and token issuance fails `invalid_target`.
///
/// A client-supplied `X-Forwarded-Proto` is never trusted: the relay replaces
/// it with `scheme` (`server.public_scheme`, normalized to `http`/`https`).
/// Non-upgrade requests keep the usual hop-by-hop rewrite; Upgrade requests
/// keep their `Connection`/`Upgrade` pair but still get the scheme.
pub fn head_with_forwarded_proto(head: &RequestHead, scheme: &str) -> Vec<u8> {
    let scheme = if scheme.eq_ignore_ascii_case("https") { "https" } else { "http" };
    let mut out = Vec::with_capacity(head.raw.len() + 40);
    out.extend_from_slice(format!("{} {} HTTP/1.{}\r\n", head.method, head.target, head.version).as_bytes());
    for (name, value) in &head.headers {
        if name.eq_ignore_ascii_case("x-forwarded-proto") {
            continue;
        }
        if !head.upgrade
            && (name.eq_ignore_ascii_case("connection")
                || name.eq_ignore_ascii_case("keep-alive")
                || name.eq_ignore_ascii_case("proxy-connection"))
        {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"X-Forwarded-Proto: ");
    out.extend_from_slice(scheme.as_bytes());
    out.extend_from_slice(b"\r\n");
    if !head.upgrade {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Extracts the status code from the first response line without parsing or
/// buffering the body. Used only for request logs and metrics.
#[derive(Debug, Default)]
pub struct StatusSniffer {
    buf: Vec<u8>,
    done: bool,
}

impl StatusSniffer {
    pub fn status(&self) -> Option<u16> {
        parse_status_line(&self.buf)
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Option<u16> {
        if self.done {
            return None;
        }
        let take = chunk.len().min(64 - self.buf.len());
        self.buf.extend_from_slice(&chunk[..take]);
        if let Some(code) = parse_status_line(&self.buf) {
            self.done = true;
            return Some(code);
        }
        if self.buf.len() >= 64 || self.buf.contains(&b'\n') {
            self.done = true;
        }
        None
    }
}

fn parse_status_line(buf: &[u8]) -> Option<u16> {
    let line_end = buf.iter().position(|&b| b == b'\r' || b == b'\n')?;
    let line = std::str::from_utf8(&buf[..line_end]).ok()?;
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let code = parts.next()?;
    let code: u16 = code.parse().ok()?;
    if (100..=599).contains(&code) {
        Some(code)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn sniff(input: &[u8]) -> Result<Sniffed, HeadError> {
        let mut cursor = std::io::Cursor::new(input.to_vec());
        read_request_head(&mut cursor, 16 * 1024).await
    }

    #[tokio::test]
    async fn splits_head_and_body_prefix() {
        let raw = b"GET /x HTTP/1.1\r\nHost: A1.relay.test:8080\r\n\r\nBODY";
        let s = sniff(raw).await.unwrap();
        assert_eq!(s.head.method, "GET");
        assert_eq!(s.head.target, "/x");
        assert_eq!(s.head.host_raw.as_deref(), Some("A1.relay.test:8080"));
        assert_eq!(s.body_prefix, b"BODY");
    }

    #[tokio::test]
    async fn detects_upgrade() {
        let raw = b"GET /ws HTTP/1.1\r\nHost: a.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let s = sniff(raw).await.unwrap();
        assert!(s.head.upgrade);
        // Upgrade heads are forwarded byte-for-byte; the caller must not rewrite them.
        assert!(s.head.raw.ends_with(b"Upgrade: websocket\r\n\r\n"));
    }

    #[tokio::test]
    async fn rewrites_connection() {
        let raw = b"POST /a HTTP/1.1\r\nHost: a.test\r\nConnection: keep-alive\r\nContent-Length: 3\r\n\r\nabc";
        let s = sniff(raw).await.unwrap();
        let rewritten = String::from_utf8(head_with_connection_close(&s.head)).unwrap();
        assert!(rewritten.contains("Connection: close\r\n"));
        assert!(!rewritten.to_ascii_lowercase().contains("keep-alive"));
        assert!(rewritten.contains("Content-Length: 3\r\n"));
        assert!(rewritten.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn forwarded_proto_replaces_the_untrusted_client_value() {
        let raw = b"GET /.well-known/oauth-protected-resource HTTP/1.1\r\nHost: a.test:29001\r\nX-Forwarded-Proto: https\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\r\n";
        let s = sniff(raw).await.unwrap();
        let out = String::from_utf8(head_with_forwarded_proto(&s.head, "http")).unwrap();
        assert!(out.contains("X-Forwarded-Proto: http\r\n"), "{out}");
        assert_eq!(out.to_ascii_lowercase().matches("x-forwarded-proto").count(), 1, "{out}");
        assert!(!out.to_ascii_lowercase().contains("keep-alive"), "{out}");
        assert!(out.contains("Connection: close\r\n"), "{out}");
        assert!(out.ends_with("\r\n\r\n"), "{out}");
    }

    #[tokio::test]
    async fn forwarded_proto_survives_an_upgrade_head() {
        let raw = b"GET /ws HTTP/1.1\r\nHost: a.test\r\nX-Forwarded-Proto: http\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let s = sniff(raw).await.unwrap();
        assert!(s.head.upgrade);
        let out = String::from_utf8(head_with_forwarded_proto(&s.head, "https")).unwrap();
        assert!(out.contains("X-Forwarded-Proto: https\r\n"), "{out}");
        assert!(!out.to_ascii_lowercase().contains("x-forwarded-proto: http\r\n"), "{out}");
        assert!(out.contains("Connection: keep-alive, Upgrade\r\n"), "{out}");
        assert!(out.contains("Upgrade: websocket\r\n"), "{out}");
        assert!(!out.contains("Connection: close"), "{out}");
    }

    #[tokio::test]
    async fn forwarded_proto_cannot_inject_a_header_line() {
        let raw = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n";
        let s = sniff(raw).await.unwrap();
        let out = String::from_utf8(head_with_forwarded_proto(&s.head, "https\r\nX-Evil: 1")).unwrap();
        assert!(out.contains("X-Forwarded-Proto: http\r\n"), "{out}");
        assert!(!out.contains("X-Evil"), "{out}");
        assert!(out.ends_with("\r\n\r\n"), "{out}");
    }

    #[tokio::test]
    async fn rejects_missing_host() {
        let raw = b"GET / HTTP/1.1\r\n\r\n";
        assert!(matches!(sniff(raw).await, Err(HeadError::Malformed(_))));
    }

    #[tokio::test]
    async fn rejects_oversize() {
        let mut raw = b"GET / HTTP/1.1\r\nHost: a.test\r\nX: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', 17 * 1024));
        raw.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(sniff(&raw).await, Err(HeadError::TooLarge)));
    }

    #[tokio::test]
    async fn recognises_proxy_forms() {
        let connect = sniff(b"CONNECT Example.COM:443 HTTP/1.1\r\nHost: Example.COM:443\r\n\r\n\x03\x01")
            .await
            .unwrap();
        assert!(connect.head.is_proxy_form());
        assert_eq!(connect.head.proxy_authority(), Some("Example.COM:443"));

        let absolute = sniff(b"GET http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n").await.unwrap();
        assert!(absolute.head.is_proxy_form());
        assert_eq!(absolute.head.proxy_authority(), Some("example.com"));

        let absolute_tls = sniff(b"GET HTTPS://example.com:8443/ HTTP/1.1\r\nHost: example.com:8443\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(absolute_tls.head.proxy_authority(), Some("example.com:8443"));
    }

    #[tokio::test]
    async fn an_origin_form_request_is_not_proxy_traffic() {
        for raw in [
            &b"GET /a HTTP/1.1\r\nHost: a.test\r\n\r\n"[..],
            &b"GET /http://x HTTP/1.1\r\nHost: a.test\r\n\r\n"[..],
            &b"POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 0\r\n\r\n"[..],
        ] {
            let s = sniff(raw).await.unwrap();
            assert!(!s.head.is_proxy_form(), "{:?}", s.head.target);
            assert_eq!(s.head.proxy_authority(), None);
        }
    }

    #[test]
    fn sniffs_status() {
        let mut s = StatusSniffer::default();
        assert_eq!(s.feed(b"HTTP/1.1 2"), None);
        assert_eq!(s.feed(b"01 Created\r\n"), Some(201));
        assert_eq!(s.feed(b"more"), None);
    }
}
