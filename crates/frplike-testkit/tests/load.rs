//! Load check for the PRD target: 2000 concurrent logical streams.
//!
//! Ignored by default (it opens ~4000 sockets). Run with:
//!   ulimit -n 65535 && cargo test -p frplike-testkit --test load -- --ignored --nocapture

use std::sync::Arc;
use std::time::{Duration, Instant};

use frplike_testkit::*;
use tokio::sync::Semaphore;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn two_thousand_concurrent_streams() {
    let dir = TempDir::new("load");
    let host = start_host(dir.path(), &["relay.test"]).await.unwrap();
    let origin = start_origin("load").await.unwrap();
    let token = create_token(&host, "relay.test").await.unwrap();
    let _agent = start_agent(
        &host,
        "load-agent",
        Some(&token),
        &[("a1.relay.test", origin.addr)],
        dir.path(),
        4,
        false,
    )
    .await
    .unwrap();
    wait_routes_active(&host, 1).await.unwrap();
    wait_tunnels(&host, 4).await.unwrap();

    const N: usize = 2000;
    let edge = host.edge_addr();
    let sem = Arc::new(Semaphore::new(N));
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(N);
    for _ in 0..N {
        let sem = sem.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let t0 = Instant::now();
            let r = http(edge, "a1.relay.test", "GET", "/", None).await;
            (t0.elapsed(), r.map(|r| r.status))
        }));
    }
    let mut latencies = Vec::with_capacity(N);
    let mut failures = 0;
    for t in tasks {
        match t.await.unwrap() {
            (d, Ok(200)) => latencies.push(d),
            (_, other) => {
                failures += 1;
                if failures < 5 {
                    eprintln!("failure: {other:?}");
                }
            }
        }
    }
    latencies.sort();
    let total = started.elapsed();
    let p = |q: f64| latencies[((latencies.len() as f64 - 1.0) * q) as usize];
    println!(
        "N={N} ok={} failed={failures} total={total:?} p50={:?} p95={:?} p99={:?} max={:?}",
        latencies.len(),
        p(0.50),
        p(0.95),
        p(0.99),
        latencies.last().copied().unwrap_or_default()
    );
    assert_eq!(failures, 0, "some streams failed");
    // A burst of 2000 simultaneous *new* connections hits the listen backlog;
    // this is a survival test, not a latency SLO. Release builds are ~10x faster.
    assert!(p(0.99) < Duration::from_secs(5), "p99 too slow: {:?}", p(0.99));
}
