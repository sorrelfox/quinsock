mod common;

use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_socks::tcp::Socks5Stream;

#[tokio::test]
async fn connect_to_ip_target() {
    let server = spawn(config()).await;
    let echo = tcp_echo().await;
    let mut s = Socks5Stream::connect(server.addr, echo).await.unwrap();
    s.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[tokio::test]
async fn connect_to_domain_target() {
    let server = spawn(config()).await;
    let echo = tcp_echo().await;
    // "localhost" may resolve to ::1 first; the server must fall back to 127.0.0.1.
    let mut s = Socks5Stream::connect(server.addr, ("localhost", echo.port()))
        .await
        .unwrap();
    s.write_all(b"domain").await.unwrap();
    let mut buf = [0u8; 6];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"domain");
}

#[tokio::test]
async fn large_transfer_with_half_close() {
    let server = spawn(config()).await;
    let echo = tcp_echo().await;
    let stream = Socks5Stream::connect(server.addr, echo).await.unwrap();
    let (mut r, mut w) = tokio::io::split(stream);
    let data: Vec<u8> = (0..(1usize << 20)).map(|i| (i % 251) as u8).collect();
    let expected = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&data).await.unwrap();
        // Half-close: the echoed data must still arrive after our write side is shut.
        w.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), r.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    writer.await.unwrap();
    assert_eq!(got.len(), expected.len());
    assert!(got == expected);
}

#[tokio::test]
async fn reply_carries_outbound_address() {
    let server = spawn(config()).await;
    let echo = tcp_echo().await;
    let mut s = greet(server.addr).await;
    send_request(&mut s, 1, &addr_bytes(echo)).await;
    let (rep, bound) = read_reply(&mut s).await;
    assert_eq!(rep, 0);
    assert_eq!(bound.ip().to_string(), "127.0.0.1");
    assert_ne!(bound.port(), 0);
}

#[tokio::test]
async fn closed_port_is_connection_refused() {
    let server = spawn(config()).await;
    let target = closed_port().await;
    let mut s = greet(server.addr).await;
    send_request(&mut s, 1, &addr_bytes(target)).await;
    assert_eq!(read_reply(&mut s).await.0, 0x05);
    assert_closed(&mut s, Duration::from_secs(2)).await;
}

#[tokio::test]
async fn unresolvable_domain_is_host_unreachable() {
    let server = spawn(config()).await;
    let mut s = greet(server.addr).await;
    send_request(&mut s, 1, &domain_bytes("does-not-exist.invalid", 80)).await;
    assert_eq!(read_reply(&mut s).await.0, 0x04);
}

#[tokio::test]
async fn acl_denied_destination_is_not_allowed() {
    let mut cfg = config();
    cfg.acl.dest_deny = vec!["127.0.0.0/8".parse().unwrap()];
    let server = spawn(cfg).await;
    let echo = tcp_echo().await;
    let mut s = greet(server.addr).await;
    send_request(&mut s, 1, &addr_bytes(echo)).await;
    assert_eq!(read_reply(&mut s).await.0, 0x02);
}

#[tokio::test]
async fn idle_relay_is_closed() {
    let mut cfg = config();
    cfg.timeouts.tcp_idle_secs = 0.5;
    let server = spawn(cfg).await;
    let echo = tcp_echo().await;
    let mut s = greet(server.addr).await;
    send_request(&mut s, 1, &addr_bytes(echo)).await;
    assert_eq!(read_reply(&mut s).await.0, 0);
    // Activity keeps it open...
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        s.write_all(b"x").await.unwrap();
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await.unwrap();
    }
    // ...and silence closes it.
    assert_closed(&mut s, Duration::from_secs(3)).await;
}
