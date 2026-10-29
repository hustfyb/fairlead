//! yamux over TLS must behave like yamux over TCP: a stream write wakes the
//! peer's driver immediately, with no external event required.

use std::sync::Arc;
use std::time::Duration;

use fairlead_proto::mux;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

#[tokio::test]
async fn over_tls() {
    rustls::crypto::ring::default_provider().install_default().ok();
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = generated.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();

    let (a, b) = tokio::io::duplex(1 << 20);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let server_task = tokio::spawn(async move { acceptor.accept(a).await.unwrap() });
    let client = connector
        .connect(ServerName::try_from("localhost").unwrap(), b)
        .await
        .unwrap();
    let server = server_task.await.unwrap();

    let cfg = yamux::Config::default();
    let (_stx, srx) = mpsc::channel(4);
    let (ctx, crx) = mpsc::channel(4);
    let (s_in_tx, mut s_in_rx) = mpsc::channel(8);
    let (_c_in_tx, _c_in_rx) = mpsc::channel(8);
    let (_sk, sk) = mpsc::channel(1);
    let (_ck, ck) = mpsc::channel(1);
    let server_conn = yamux::Connection::new(server.compat(), cfg.clone(), yamux::Mode::Server);
    let client_conn = yamux::Connection::new(client.compat(), cfg, yamux::Mode::Client);
    let _s = mux::spawn(server_conn, srx, sk, s_in_tx);
    let _c = mux::spawn(client_conn, crx, ck, _c_in_tx);

    let stream = timeout(Duration::from_secs(2), mux::open(&ctx, Duration::from_secs(2)))
        .await
        .expect("open timed out")
        .unwrap();
    let mut cs = stream.compat();
    let t0 = std::time::Instant::now();
    cs.write_all(b"hello").await.unwrap();
    let ss = timeout(Duration::from_secs(2), s_in_rx.recv())
        .await
        .expect("server did not see the stream")
        .unwrap();
    let mut ss = ss.compat();
    let mut buf = [0u8; 5];
    timeout(Duration::from_secs(2), ss.read_exact(&mut buf))
        .await
        .expect("server did not receive bytes")
        .unwrap();
    assert_eq!(&buf, b"hello");
    println!("tls roundtrip in {:?}", t0.elapsed());
}
