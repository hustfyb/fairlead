//! Is anything listening on a route's target?
//!
//! A route publishes whether or not its target is alive: the relay takes the
//! declaration, the tunnel opens, and only the first real request finds out
//! nobody is there — it comes back as `502 agent could not connect to the local
//! target`, which says nothing about *which* port on *which* machine. One TCP
//! connect at `fairlead agent add` time turns that into a sentence right where
//! the mapping was made.

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// `Ok(())` when something accepted the connection; `Err` carries a short
/// reason a person can act on ("connection refused", "timed out", …).
pub fn tcp(target: &str, timeout: Duration) -> Result<(), String> {
    let addrs = target
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve: {e}"))?;
    let mut reason = String::from("no address to try");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => return Ok(()),
            Err(e) => reason = describe(&e),
        }
    }
    Err(reason)
}

fn describe(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => "connection refused".to_string(),
        io::ErrorKind::TimedOut => "timed out".to_string(),
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
            "unreachable".to_string()
        }
        other => format!("{other:?}").to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn a_listening_port_passes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        assert_eq!(tcp(&target, Duration::from_millis(500)), Ok(()));
    }

    #[test]
    fn a_closed_port_says_refused() {
        // Bind to learn a port nobody else is likely to take, then let it go.
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let why = tcp(&format!("127.0.0.1:{port}"), Duration::from_millis(500)).unwrap_err();
        // Unix sends a reset, so the connect fails at once with "refused".
        // Windows drops it instead and the connect runs into the timeout, which
        // is still the right thing to tell the person who just added the route.
        #[cfg(not(windows))]
        assert_eq!(why, "connection refused");
        #[cfg(windows)]
        assert!(
            why == "connection refused" || why == "timed out",
            "a closed port must say refused or timed out, got {why:?}"
        );
    }

    #[test]
    fn a_name_that_does_not_resolve_says_so() {
        let why = tcp("no-such-name.invalid:1234", Duration::from_millis(200)).unwrap_err();
        assert!(why.starts_with("cannot resolve"), "{why}");
    }
}
