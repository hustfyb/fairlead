//! Which local targets an agent is willing to dial.
//!
//! Default posture (ARCHITECTURE §6): loopback and private/link-local addresses
//! are allowed, public addresses are not. This blocks the obvious abuse of a
//! compromised or careless agent turning the edge into an open relay to the
//! public internet.

use std::net::IpAddr;

use crate::control::validate_target;

/// Policy decision for one resolved address.
pub fn ip_allowed(ip: IpAddr, allow_public: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_private() || v4.is_link_local() {
                return true;
            }
            if v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                return false;
            }
            allow_public
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            let seg = v6.segments();
            // fc00::/7 unique local, fe80::/10 link local.
            if (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            if v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_allowed(IpAddr::V4(v4), allow_public);
            }
            allow_public
        }
    }
}

/// A target that passed syntax validation and policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedTarget {
    pub host: String,
    pub port: u16,
    pub addrs: Vec<std::net::SocketAddr>,
}

/// Validate syntax, resolve, and apply [`ip_allowed`] to every resolved
/// address. A name that resolves to *any* public address is rejected unless
/// `allow_public` is set — partial answers are refused rather than picking a
/// friendly one.
pub async fn resolve_target(
    target: &str,
    allow_public: bool,
) -> Result<AllowedTarget, TargetError> {
    validate_target(target).map_err(|e| TargetError::Syntax(e.to_string()))?;
    let (host, port) = target.rsplit_once(':').expect("validated");
    let port: u16 = port.parse().expect("validated");
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| TargetError::Resolve(e.to_string()))?
        .collect();
    if addrs.is_empty() {
        return Err(TargetError::Resolve("no addresses".into()));
    }
    if !allow_public {
        for addr in &addrs {
            if !ip_allowed(addr.ip(), false) {
                return Err(TargetError::Blocked(addr.ip().to_string()));
            }
        }
    }
    Ok(AllowedTarget { host: host.to_string(), port, addrs })
}

#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    #[error("invalid target: {0}")]
    Syntax(String),
    #[error("cannot resolve target: {0}")]
    Resolve(String),
    #[error("target address {0} is not allowed by policy")]
    Blocked(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_and_private_allowed() {
        assert!(ip_allowed("127.0.0.1".parse().unwrap(), false));
        assert!(ip_allowed("10.1.2.3".parse().unwrap(), false));
        assert!(ip_allowed("172.16.0.9".parse().unwrap(), false));
        assert!(ip_allowed("192.168.1.1".parse().unwrap(), false));
        assert!(ip_allowed("::1".parse().unwrap(), false));
        assert!(ip_allowed("fd00::1".parse().unwrap(), false));
        assert!(ip_allowed("fe80::1".parse().unwrap(), false));
    }

    #[test]
    fn public_blocked_by_default() {
        assert!(!ip_allowed("1.1.1.1".parse().unwrap(), false));
        assert!(!ip_allowed("8.8.8.8".parse().unwrap(), false));
        assert!(!ip_allowed("2606:4700::1111".parse().unwrap(), false));
        assert!(ip_allowed("1.1.1.1".parse().unwrap(), true));
    }

    #[test]
    fn unspecified_and_multicast_blocked() {
        assert!(!ip_allowed("0.0.0.0".parse().unwrap(), true));
        assert!(!ip_allowed("224.0.0.1".parse().unwrap(), true));
        assert!(!ip_allowed("::".parse().unwrap(), true));
    }

    #[tokio::test]
    async fn resolves_localhost() {
        let t = resolve_target("127.0.0.1:9", false).await.unwrap();
        assert_eq!(t.port, 9);
        assert_eq!(t.addrs[0].ip().to_string(), "127.0.0.1");
    }

    #[tokio::test]
    async fn rejects_garbage() {
        assert!(resolve_target("http://x:80", false).await.is_err());
        assert!(resolve_target("127.0.0.1", false).await.is_err());
        assert!(resolve_target("127.0.0.1:0", false).await.is_err());
    }
}
