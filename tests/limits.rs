mod common;

use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

#[tokio::test]
async fn connection_limit_queues_extra_clients() {
    let mut cfg = config();
    cfg.server.max_connections = 2;
    let server = spawn(cfg).await;
    let first = greet(server.addr).await;
    let _second = greet(server.addr).await;

    let mut third = TcpStream::connect(server.addr).await.unwrap();
    third.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    assert!(
        tokio::time::timeout(Duration::from_millis(300), third.read_exact(&mut resp))
            .await
            .is_err(),
        "third client must wait while the limit is reached"
    );

    drop(first);
    tokio::time::timeout(Duration::from_secs(3), third.read_exact(&mut resp))
        .await
        .expect("third client served after a slot frees up")
        .unwrap();
    assert_eq!(resp, [5, 0]);
}

#[tokio::test]
async fn graceful_shutdown_drains_relays() {
    let mut cfg = config();
    cfg.server.shutdown_grace_secs = 1.0;
    let mut server = spawn(cfg).await;
    let echo = tcp_echo().await;
    let mut relay = Socks5Stream::connect(server.addr, echo).await.unwrap();

    server.handle.shutdown();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        TcpStream::connect(server.addr).await.is_err(),
        "listener closed"
    );

    // Active relays keep working during the grace period.
    relay.write_all(b"x").await.unwrap();
    let mut b = [0u8; 1];
    relay.read_exact(&mut b).await.unwrap();

    // Then they are closed and the server finishes.
    assert_closed(&mut relay, Duration::from_secs(3)).await;
    let task = server.task.take().unwrap();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn bind_rejects_an_invalid_config() {
    let mut cfg = config();
    cfg.server.max_connections = 0;
    let err = quinsock::Server::bind(cfg)
        .err()
        .expect("an invalid config must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn dropping_run_closes_everything() {
    let mut server = spawn(config()).await;
    let echo = tcp_echo().await;
    let mut relay = Socks5Stream::connect(server.addr, echo).await.unwrap();

    // Aborting the task drops the run() future without any shutdown call.
    server.task.take().unwrap().abort();
    assert_closed(&mut relay, Duration::from_secs(2)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while TcpStream::connect(server.addr).await.is_ok() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "listener still open"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
