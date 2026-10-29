//! Data-stream preamble and status byte.
//!
//! The host writes `0x01 | u16 target_len | target` followed by the raw request
//! head and body. The agent answers with exactly one status byte before it
//! connects the target, which is the only reliable way to distinguish
//! "refused" from "timeout" across a yamux stream close.

use std::io;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::MAX_TARGET_BYTES;

/// Preamble version. Only bumped if the preamble layout changes.
pub const PREAMBLE_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DialStatus {
    Ok = 0x00,
    Refused = 0x01,
    Timeout = 0x02,
    Blocked = 0x03,
    BadRequest = 0x04,
}

impl DialStatus {
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x00 => DialStatus::Ok,
            0x01 => DialStatus::Refused,
            0x02 => DialStatus::Timeout,
            0x03 => DialStatus::Blocked,
            0x04 => DialStatus::BadRequest,
            _ => return None,
        })
    }
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Error)]
pub enum DataError {
    #[error("preamble version {0} is not supported")]
    Version(u8),
    #[error("preamble target too large")]
    TargetTooLarge,
    #[error("preamble target is not valid utf-8")]
    TargetUtf8,
    #[error("stream closed while reading preamble")]
    Eof,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Encode the data-stream preamble for `target`.
pub fn encode_preamble(target: &str) -> Result<Vec<u8>, DataError> {
    let bytes = target.as_bytes();
    if bytes.len() > MAX_TARGET_BYTES || bytes.len() > u16::MAX as usize {
        return Err(DataError::TargetTooLarge);
    }
    let mut out = Vec::with_capacity(3 + bytes.len());
    out.push(PREAMBLE_VERSION);
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Read the data-stream preamble. Reads exactly the preamble; no byte past it
/// is consumed, so the request head that follows stays intact.
pub async fn read_preamble<R: AsyncRead + Unpin>(r: &mut R) -> Result<String, DataError> {
    let mut header = [0u8; 3];
    read_exact(r, &mut header).await?;
    if header[0] != PREAMBLE_VERSION {
        return Err(DataError::Version(header[0]));
    }
    let len = u16::from_be_bytes([header[1], header[2]]) as usize;
    if len > MAX_TARGET_BYTES {
        return Err(DataError::TargetTooLarge);
    }
    let mut buf = vec![0u8; len];
    read_exact(r, &mut buf).await?;
    String::from_utf8(buf).map_err(|_| DataError::TargetUtf8)
}

async fn read_exact<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> Result<(), DataError> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Err(DataError::Eof);
        }
        filled += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_and_no_overread() {
        let mut bytes = encode_preamble("127.0.0.1:7884").unwrap();
        bytes.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        let mut cursor = std::io::Cursor::new(bytes);
        assert_eq!(read_preamble(&mut cursor).await.unwrap(), "127.0.0.1:7884");
        let mut rest = String::new();
        use tokio::io::AsyncReadExt;
        cursor.read_to_string(&mut rest).await.unwrap();
        assert_eq!(rest, "GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn rejects_bad_targets() {
        assert!(encode_preamble(&"x".repeat(MAX_TARGET_BYTES + 1)).is_err());
    }
}
