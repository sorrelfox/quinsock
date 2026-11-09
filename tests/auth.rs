mod common;

use std::time::Duration;

use common::*;
use quinsock::Config;
use quinsock::config::{AuthMode, User};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

fn password_config() -> Config {
    let mut cfg = config();
    cfg.auth.mode = AuthMode::Password;
    cfg.auth.users = vec![User {
        username: "alice".into(),
        password: "secret".into(),
    }];
    cfg
}

#[tokio::test]
async fn correct_password_is_accepted() {
    let server = spawn(password_config()).await;
    let echo = tcp_echo().await;
    let mut s = Socks5Stream::connect_with_password(server.addr, echo, "alice", "secret")
        .await
        .unwrap();
    s.write_all(b"authed").await.unwrap();
    let mut buf = [0u8; 6];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"authed");
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let server = spawn(password_config()).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(&[5, 1, 2]).await.unwrap();
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 2]);
    let mut msg = vec![1, 5];
    msg.extend_from_slice(b"alice");
    msg.push(5);
    msg.extend_from_slice(b"wrong");
    s.write_all(&msg).await.unwrap();
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 1);
    assert_ne!(resp[1], 0);
    assert_closed(&mut s, Duration::from_secs(2)).await;

    let echo = tcp_echo().await;
    assert!(
        Socks5Stream::connect_with_password(server.addr, echo, "alice", "nope")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn password_mode_refuses_no_auth_clients() {
    let server = spawn(password_config()).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 0xFF]);
    assert_closed(&mut s, Duration::from_secs(2)).await;
}

#[tokio::test]
async fn no_auth_mode_refuses_password_only_clients() {
    let server = spawn(config()).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(&[5, 2, 1, 2]).await.unwrap();
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 0xFF]);
    assert_closed(&mut s, Duration::from_secs(2)).await;
}
