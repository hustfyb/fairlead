//! Public host name normalization and suffix validation.
//!
//! Everything that reaches the route table goes through here exactly once.
//! Being strict here is what stops `a1.relay.example.com.` / `A1.Relay...`
//! from creating two routes that look different to an operator and identical
//! to a client.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostError {
    #[error("empty host")]
    Empty,
    #[error("host too long")]
    TooLong,
    #[error("host contains invalid characters")]
    InvalidCharacter,
    #[error("host contains an empty label")]
    EmptyLabel,
    #[error("host label too long")]
    LabelTooLong,
    #[error("host label starts or ends with '-'")]
    BadLabel,
    #[error("host is an ip literal")]
    IpLiteral,
}

/// Normalize an HTTP `Host` header (or a config value) to route-table form:
/// lowercase, port stripped, single trailing dot stripped.
pub fn normalize(raw: &str) -> Result<String, HostError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(HostError::Empty);
    }
    // IPv6 literal in Host (`[::1]:8080`) is never a route key.
    if raw.starts_with('[') {
        return Err(HostError::IpLiteral);
    }
    // Strip a single trailing dot (FQDN form) before the port, e.g. `a.test.:80`.
    let without_port = match raw.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        Some(_) => return Err(HostError::InvalidCharacter),
        None => raw,
    };
    let host = without_port.strip_suffix('.').unwrap_or(without_port);
    if host.is_empty() {
        return Err(HostError::Empty);
    }
    if host.len() > 253 {
        return Err(HostError::TooLong);
    }
    let mut out = String::with_capacity(host.len());
    for label in host.split('.') {
        if label.is_empty() {
            return Err(HostError::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(HostError::LabelTooLong);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(HostError::BadLabel);
        }
        for c in label.chars() {
            let c = c.to_ascii_lowercase();
            if !(c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(HostError::InvalidCharacter);
            }
            out.push(c);
        }
        out.push('.');
    }
    out.pop();
    if out.parse::<std::net::IpAddr>().is_ok() {
        return Err(HostError::IpLiteral);
    }
    Ok(out)
}

/// `host` matches one of `suffixes` if it equals the suffix or is a subdomain
/// of it. Suffixes are expected in normalized form.
pub fn matches_suffix(host: &str, suffixes: &[String]) -> bool {
    suffixes.iter().any(|s| {
        let s = s.trim_start_matches('.');
        host == s || (host.len() > s.len() && host.ends_with(s) && host.as_bytes()[host.len() - s.len() - 1] == b'.')
    })
}

/// Pick the most specific suffix match, used to report `allowed_suffix` on
/// enrollment tokens.
pub fn best_suffix(host: &str, suffixes: &[String]) -> Option<String> {
    suffixes
        .iter()
        .map(|s| s.trim_start_matches('.').to_string())
        .filter(|s| matches_suffix(host, std::slice::from_ref(s)))
        .max_by_key(|s| s.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        assert_eq!(normalize("A1.Relay.Example.COM").unwrap(), "a1.relay.example.com");
        assert_eq!(normalize("a1.relay.example.com:8080").unwrap(), "a1.relay.example.com");
        assert_eq!(normalize("a1.relay.example.com.").unwrap(), "a1.relay.example.com");
        assert_eq!(normalize(" a1.relay.example.com:80 ").unwrap(), "a1.relay.example.com");
        assert_eq!(normalize("localhost:9000").unwrap(), "localhost");
    }

    #[test]
    fn rejects() {
        assert_eq!(normalize(""), Err(HostError::Empty));
        assert_eq!(normalize("a1..example.com"), Err(HostError::EmptyLabel));
        assert_eq!(normalize("-a.example.com"), Err(HostError::BadLabel));
        assert_eq!(normalize("a b.example.com"), Err(HostError::InvalidCharacter));
        assert_eq!(normalize("127.0.0.1:80"), Err(HostError::IpLiteral));
        assert_eq!(normalize("[::1]:8080"), Err(HostError::IpLiteral));
        assert_eq!(normalize("a1.example.com:notaport"), Err(HostError::InvalidCharacter));
    }

    #[test]
    fn suffix_match_is_label_aware() {
        let s = vec!["relay.example.com".to_string()];
        assert!(matches_suffix("a1.relay.example.com", &s));
        assert!(matches_suffix("relay.example.com", &s));
        assert!(!matches_suffix("evilrelay.example.com", &s));
        assert!(!matches_suffix("relay.example.com.evil.net", &s));
        assert!(!matches_suffix("relay.example.co", &s));
    }
}
