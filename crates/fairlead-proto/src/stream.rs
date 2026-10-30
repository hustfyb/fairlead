//! A stream with already-read bytes in front of it.
//!
//! Every "read the head, then hand the rest to someone else" step needs this:
//! the front door replays a request head into the admin plane, and an agent
//! replays the first yamux frames that arrived in the same segment as the
//! `101`. Dropping those bytes looks harmless and stalls the session forever.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The bytes are replayed before anything else comes off the socket, so the
/// consumer sees one continuous stream — including a body that arrived in the
/// same segment as the head.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(inner: S) -> Self {
        Self { prefix: Vec::new(), pos: 0, inner }
    }

    pub fn with_prefix(inner: S, prefix: Vec<u8>) -> Self {
        Self { prefix, pos: 0, inner }
    }
}

impl<S> AsRef<S> for Prefixed<S> {
    fn as_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.pos < me.prefix.len() {
            let rest = &me.prefix[me.pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            me.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

