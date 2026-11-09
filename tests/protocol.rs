mod common;

use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn unknown_command_is_not_supported() {
    let server = spawn(config()).await;
    let mut s = greet(server.addr).await;
    send_request(&mut s, 0x09, &addr_bytes("127.0.0.1:80".parse().unwrap())).await;
    assert_eq!(read_reply(&mut s).await.0, 0x07);
    assert_closed(&mut s, Duration::from_secs(2)).await;
}

#[tokio::test]
async fn disabled_command_is_not_supported() {
    let mut cfg = config();
    cfg.commands.bind = false;
    let server = spawn(cfg).await;
    let mut s = greet(server.addr).await;
    send_request(&mut s, 0x02, &addr_bytes("127.0.0.1:0".parse().unwrap())).await;
    assert_eq!(read_reply(&mut s).await.0, 0x07);
}

#[tokio::test]
async fn ipv6_address_with_ipv6_disabled() {
    let mut cfg = config();
    cfg.server.ipv6 = false;
    let server = spawn(cfg).await;
    let mut s = greet(server.addr).await;
    send_request(&mut s, 0x01, &addr_bytes("[::1]:80".parse().unwrap())).await;
    assert_eq!(read_reply(&mut s).await.0, 0x08);
}

#[tokio::test]
async fn unknown_address_type() {
    let server = spawn(config()).await;
    let mut s = greet(server.addr).await;
    s.write_all(&[5, 1, 0, 9]).await.unwrap();
    assert_eq!(read_reply(&mut s).await.0, 0x08);
}

#[tokio::test]
async fn empty_domain_is_general_failure() {
    let server = spawn(config()).await;
    let mut s = greet(server.addr).await;
    s.write_all(&[5, 1, 0, 3, 0, 0, 80]).await.unwrap();
    assert_eq!(read_reply(&mut s).await.0, 0x01);
}

#[tokio::test]
async fn wrong_version_is_dropped_silently() {
    let server = spawn(config()).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(&[4, 1, 0, 80, 127, 0, 0, 1, 0]).await.unwrap();
    assert_closed(&mut s, Duration::from_secs(2)).await;
}

#[tokio::test]
async fn silent_client_hits_handshake_timeout() {
    let mut cfg = config();
    cfg.timeouts.handshake_secs = 0.3;
    let server = spawn(cfg).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    // A partial greeting must not keep the connection alive either.
    s.write_all(&[5, 3, 0]).await.unwrap();
    assert_closed(&mut s, Duration::from_secs(2)).await;
}

#[tokio::test]
async fn garbage_does_not_affect_the_server() {
    let server = spawn(config()).await;
    let mut seed: u32 = 0x1234_5678;
    for len in [1usize, 2, 7, 64, 300, 4096] {
        let mut s = TcpStream::connect(server.addr).await.unwrap();
        let junk: Vec<u8> = (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed as u8
            })
            .collect();
        let _ = s.write_all(&junk).await;
        let mut buf = [0u8; 16];
        let _ = tokio::time::timeout(Duration::from_millis(200), s.read(&mut buf)).await;
    }
    // Still serving.
    let echo = tcp_echo().await;
    let mut s = greet(server.addr).await;
    send_request(&mut s, 1, &addr_bytes(echo)).await;
    assert_eq!(read_reply(&mut s).await.0, 0);
}
