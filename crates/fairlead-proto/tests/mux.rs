//! The shared driver must deliver a stream and its bytes within milliseconds.
//! A regression here shows up as every request hanging until some other event
//! (heartbeat, second request) wakes the connection.

use std::time::Duration;

use fairlead_proto::mux;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

#[tokio::test]
async fn stream_bytes_flow_without_another_event() {
    let (a, b) = tokio::io::duplex(1 << 20);
    let cfg = yamux::Config::default();

    let (stx, srx) = mpsc::channel(4);
    let (ctx, crx) = mpsc::channel(4);
    let (s_in_tx, mut s_in_rx) = mpsc::channel(8);
    let (_c_in_tx, _c_in_rx) = mpsc::channel(8);
    let (_sk_tx, sk_rx) = mpsc::channel(1);
    let (_ck_tx, ck_rx) = mpsc::channel(1);

    let server = yamux::Connection::new(a.compat(), cfg.clone(), yamux::Mode::Server);
    let client = yamux::Connection::new(b.compat(), cfg, yamux::Mode::Client);
    let _s = mux::spawn(server, srx, sk_rx, s_in_tx);
    let _c = mux::spawn(client, crx, ck_rx, _c_in_tx);

    let stream = timeout(Duration::from_secs(1), mux::open(&ctx, Duration::from_secs(1)))
        .await
        .expect("open timed out")
        .expect("open failed");
    let mut client_stream = stream.compat();
    client_stream.write_all(b"hello").await.unwrap();

    let server_stream = timeout(Duration::from_secs(1), s_in_rx.recv())
        .await
        .expect("server did not see the stream")
        .expect("channel closed");
    let mut server_stream = server_stream.compat();
    let mut buf = [0u8; 5];
    timeout(Duration::from_secs(1), server_stream.read_exact(&mut buf))
        .await
        .expect("server did not receive bytes")
        .unwrap();
    assert_eq!(&buf, b"hello");

    server_stream.write_all(b"world").await.unwrap();
    let mut back = [0u8; 5];
    timeout(Duration::from_secs(1), client_stream.read_exact(&mut back))
        .await
        .expect("client did not receive the reply")
        .unwrap();
    assert_eq!(&back, b"world");
    let _ = (stx, _c_in_rx);
}

/// Regression: a DATA frame that arrives right after the stream's SYN must not
/// be stranded. Before the driver looped until no progress, the peer delivered
/// the stream, returned `Pending`, and left the DATA frame in the socket with
/// no waker — every request then waited for the next heartbeat.
#[tokio::test]
async fn data_arriving_with_the_syn_is_delivered() {
    let (a, b) = tokio::io::duplex(1 << 20);
    let cfg = yamux::Config::default();

    let (_stx, srx) = mpsc::channel(4);
    let (ctx, crx) = mpsc::channel(4);
    let (s_in_tx, mut s_in_rx) = mpsc::channel(8);
    let (_c_in_tx, _c_in_rx) = mpsc::channel(8);
    let (_sk_tx, sk_rx) = mpsc::channel(1);
    let (_ck_tx, ck_rx) = mpsc::channel(1);
    let server = yamux::Connection::new(a.compat(), cfg.clone(), yamux::Mode::Server);
    let client = yamux::Connection::new(b.compat(), cfg, yamux::Mode::Client);
    let _s = mux::spawn(server, srx, sk_rx, s_in_tx);
    let _c = mux::spawn(client, crx, ck_rx, _c_in_tx);

    let stream = mux::open(&ctx, Duration::from_secs(1)).await.unwrap();
    let mut client_stream = stream.compat();
    client_stream.write_all(b"payload").await.unwrap();

    // Give the peer driver every excuse to stop polling: the stream and the
    // payload are both sitting in its socket by now.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let server_stream = s_in_rx.recv().await.expect("stream lost");
    let mut server_stream = server_stream.compat();
    let mut buf = [0u8; 7];
    timeout(Duration::from_secs(1), server_stream.read_exact(&mut buf))
        .await
        .expect("payload stranded: the driver stopped polling after the SYN")
        .unwrap();
    assert_eq!(&buf, b"payload");
}
