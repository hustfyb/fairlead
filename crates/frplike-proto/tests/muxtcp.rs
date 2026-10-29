use std::time::Duration;
use frplike_proto::mux;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

async fn pair_over<A, B>(a: A, b: B) where A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
                                 B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {
    let cfg = yamux::Config::default();
    let (srx_tx, srx) = mpsc::channel(4);
    let (crx_tx, crx) = mpsc::channel(4);
    let (s_in_tx, mut s_in_rx) = mpsc::channel(8);
    let (_c_in_tx, _c_in_rx) = mpsc::channel(8);
    let (_sk, sk) = mpsc::channel(1);
    let (_ck, ck) = mpsc::channel(1);
    let server = yamux::Connection::new(a.compat(), cfg.clone(), yamux::Mode::Server);
    let client = yamux::Connection::new(b.compat(), cfg, yamux::Mode::Client);
    let _s = mux::spawn(server, srx, sk, s_in_tx);
    let _c = mux::spawn(client, crx, ck, _c_in_tx);
    let stream = timeout(Duration::from_secs(2), mux::open(&crx_tx, Duration::from_secs(2))).await.expect("open timeout").unwrap();
    let mut cs = stream.compat();
    let t0 = std::time::Instant::now();
    cs.write_all(b"hello").await.unwrap();
    let ss = timeout(Duration::from_secs(2), s_in_rx.recv()).await.expect("stream timeout").unwrap();
    let mut ss = ss.compat();
    let mut buf = [0u8;5];
    timeout(Duration::from_secs(2), ss.read_exact(&mut buf)).await.expect("read timeout").unwrap();
    println!("roundtrip in {:?}", t0.elapsed());
    let _ = srx_tx;
}

#[tokio::test]
async fn over_tcp() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let accept = tokio::spawn(async move { l.accept().await.unwrap().0 });
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server = accept.await.unwrap();
    pair_over(server, client).await;
}
