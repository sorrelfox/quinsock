mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio_socks::TargetAddr;
use tokio_socks::tcp::Socks5Listener;

#[tokio::test]
async fn bind_accepts_expected_peer_and_relays() {
    let server = spawn(config()).await;
    let listener = Socks5Listener::bind(server.addr, "127.0.0.1:0")
        .await
        .unwrap();
    let TargetAddr::Ip(bind_addr) = listener.bind_addr() else {
        panic!("expected an IP bind address")
    };
    assert_ne!(bind_addr.port(), 0);

    let peer = tokio::spawn(async move {
        let mut s = TcpStream::connect(bind_addr).await.unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"pong");
    });
    let mut incoming = listener.accept().await.unwrap();
    let mut b = [0u8; 4];
    incoming.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping");
    incoming.write_all(b"pong").await.unwrap();
    peer.await.unwrap();
}

async fn connect_from(source: &str, to: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(source.parse().unwrap()).unwrap();
    socket.connect(to).await.unwrap()
}

#[tokio::test]
async fn strict_peer_check_rejects_other_hosts() {
    let server = spawn(config()).await;
    let mut control = greet(server.addr).await;
    send_request(&mut control, 2, &addr_bytes("127.0.0.2:0".parse().unwrap())).await;
    let (rep, bind_addr) = read_reply(&mut control).await;
    assert_eq!(rep, 0);

    // Wrong host: dropped, the BIND keeps waiting.
    let mut stranger = connect_from("127.0.0.1:0", bind_addr).await;
    assert_closed(&mut stranger, Duration::from_secs(2)).await;

    // Expected host: accepted, second reply names it.
    let mut expected = connect_from("127.0.0.2:0", bind_addr).await;
    let (rep, from) = read_reply(&mut control).await;
    assert_eq!(rep, 0);
    assert_eq!(from, expected.local_addr().unwrap());
    expected.write_all(b"hi").await.unwrap();
    let mut b = [0u8; 2];
    control.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"hi");
}

#[tokio::test]
async fn bind_times_out_without_peer() {
    let mut cfg = config();
    cfg.timeouts.bind_accept_secs = 0.3;
    let server = spawn(cfg).await;
    let mut control = greet(server.addr).await;
    send_request(&mut control, 2, &addr_bytes("127.0.0.1:0".parse().unwrap())).await;
    assert_eq!(read_reply(&mut control).await.0, 0);
    assert_eq!(read_reply(&mut control).await.0, 0x06);
}

#[tokio::test]
async fn acl_applies_to_bind_peers() {
    let mut cfg = config();
    cfg.acl.dest_deny = vec!["127.0.0.2/32".parse().unwrap()];
    let server = spawn(cfg).await;
    let mut control = greet(server.addr).await;
    // 0.0.0.0 lets any host connect back, but the ACL still applies.
    send_request(&mut control, 2, &addr_bytes("0.0.0.0:0".parse().unwrap())).await;
    let (rep, bind_addr) = read_reply(&mut control).await;
    assert_eq!(rep, 0);

    let mut denied = connect_from("127.0.0.2:0", bind_addr).await;
    assert_closed(&mut denied, Duration::from_secs(2)).await;

    let allowed = connect_from("127.0.0.1:0", bind_addr).await;
    let (rep, from) = read_reply(&mut control).await;
    assert_eq!(rep, 0);
    assert_eq!(from, allowed.local_addr().unwrap());
}
