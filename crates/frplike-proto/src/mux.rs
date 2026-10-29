//! Shared yamux driver.
//!
//! A `yamux::Connection` makes progress only while it is being polled, and it
//! is not `Sync`: one task must own it. This module is that task, shared by the
//! host and the agent so both sides behave identically.
//!
//! * `open_rx` — requests to open an outbound stream.
//! * `kill_rx` — dropping or sending on it tears the connection down.
//! * `inbound_tx` — streams opened by the peer.
//!
//! The driver polls until it makes no progress before returning `Pending`.
//! Returning as soon as a new stream is delivered looks correct and is not:
//! yamux yields one frame per `poll_next_inbound`, so a SYN followed by a DATA
//! frame in the same TCP segment would leave the DATA frame unread, with no
//! waker registered, until an unrelated event (a heartbeat) woke the task.

use std::task::Poll;

use tokio::sync::{mpsc, oneshot};
use yamux::Connection;

#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    #[error("mux connection closed")]
    Closed,
    #[error("mux protocol error: {0}")]
    Protocol(String),
}

pub struct OpenRequest {
    pub respond: oneshot::Sender<Result<yamux::Stream, MuxError>>,
}

/// Spawn the driver task. It ends when the connection closes, when `kill_rx`
/// fires, or when all `open_tx` senders are dropped.
pub fn spawn<T>(
    mut conn: Connection<T>,
    mut open_rx: mpsc::Receiver<OpenRequest>,
    mut kill_rx: mpsc::Receiver<()>,
    inbound_tx: mpsc::Sender<yamux::Stream>,
) -> tokio::task::JoinHandle<()>
where
    T: futures::io::AsyncRead + futures::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut pending: Option<OpenRequest> = None;
        std::future::poll_fn(|cx| loop {
            let mut progress = false;

            match kill_rx.poll_recv(cx) {
                Poll::Ready(_) => return Poll::Ready(()),
                Poll::Pending => {}
            }

            if let Some(req) = pending.take() {
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(Ok(stream)) => {
                        let _ = req.respond.send(Ok(stream));
                        progress = true;
                    }
                    Poll::Ready(Err(e)) => {
                        let _ = req.respond.send(Err(MuxError::Protocol(e.to_string())));
                        return Poll::Ready(());
                    }
                    Poll::Pending => pending = Some(req),
                }
            }
            if pending.is_none() {
                loop {
                    match open_rx.poll_recv(cx) {
                        Poll::Ready(Some(req)) => match conn.poll_new_outbound(cx) {
                            Poll::Ready(Ok(stream)) => {
                                let _ = req.respond.send(Ok(stream));
                                progress = true;
                            }
                            Poll::Ready(Err(e)) => {
                                let _ = req.respond.send(Err(MuxError::Protocol(e.to_string())));
                                return Poll::Ready(());
                            }
                            Poll::Pending => {
                                pending = Some(req);
                                break;
                            }
                        },
                        Poll::Ready(None) => return Poll::Ready(()),
                        Poll::Pending => break,
                    }
                }
            }

            match conn.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    if inbound_tx.try_send(stream).is_err() {
                        return Poll::Ready(());
                    }
                    progress = true;
                }
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => {}
            }

            // Drain whatever yamux already has buffered before yielding.
            if !progress {
                return Poll::Pending;
            }
        })
        .await;
    })
}

/// Ask the driver for a stream. Returns `MuxError::Closed` if the driver is gone.
pub async fn open(
    tx: &mpsc::Sender<OpenRequest>,
    wait: std::time::Duration,
) -> Result<yamux::Stream, MuxError> {
    let (respond, rx) = oneshot::channel();
    tx.send(OpenRequest { respond }).await.map_err(|_| MuxError::Closed)?;
    match tokio::time::timeout(wait, rx).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => Err(MuxError::Closed),
        Err(_) => Err(MuxError::Protocol("open_stream timed out".into())),
    }
}
