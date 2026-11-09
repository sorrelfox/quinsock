//! Shared integration-test helpers. Raw protocol helpers build messages by hand so they
//! do not share encoding code with the server under test.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

use quinsock::{Config, Server, ShutdownHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

pub struct TestServer {
    pub addr: SocketAddr,
    pub handle: ShutdownHandle,
    pub task: Option<JoinHandle<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.shutdown_now();
    }
}

/// Defaults with short timeouts, listening on an ephemeral loopback port.
pub fn config() -> Config {
    let mut cfg = Config::default();
    cfg.server.listen = vec!["127.0.0.1:0".parse().unwrap()];
    cfg.server.shutdown_grace_secs = 1.0;
    cfg.timeouts.handshake_secs = 2.0;
    cfg.timeouts.connect_secs = 2.0;
    cfg.timeouts.bind_accept_secs = 2.0;
    cfg.udp.recv_buffer_size = 1 << 20;
    cfg.udp.send_buffer_size = 1 << 20;
    cfg
}

pub async fn spawn(mut cfg: Config) -> TestServer {
    cfg.validate().expect("valid test config");
    let server = Server::bind(cfg).expect("bind test server");
    let addr = server.local_addrs()[0];
    let handle = server.shutdown_handle();
    let task = tokio::spawn(server.run());
    TestServer {
        addr,
        handle,
        task: Some(task),
    }
}

pub async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

pub async fn udp_echo(bind: &str) -> SocketAddr {
    let socket = UdpSocket::bind(bind).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// A loopback address with nothing listening on it.
pub async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// Connects and completes the no-auth greeting.
pub async fn greet(proxy: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 0]);
    s
}

/// `ATYP | ADDR | PORT` for an IP address.
pub fn addr_bytes(addr: SocketAddr) -> Vec<u8> {
    let mut v = Vec::new();
    match addr {
        SocketAddr::V4(a) => {
            v.push(1);
            v.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            v.push(4);
            v.extend_from_slice(&a.ip().octets());
        }
    }
    v.extend_from_slice(&addr.port().to_be_bytes());
    v
}

/// `ATYP | ADDR | PORT` for a domain name.
pub fn domain_bytes(host: &str, port: u16) -> Vec<u8> {
    let mut v = vec![3, host.len() as u8];
    v.extend_from_slice(host.as_bytes());
    v.extend_from_slice(&port.to_be_bytes());
    v
}

pub async fn send_request(s: &mut TcpStream, command: u8, addr: &[u8]) {
    let mut msg = vec![5, command, 0];
    msg.extend_from_slice(addr);
    s.write_all(&msg).await.unwrap();
}

/// Reads a reply, returning `(REP, BND)`.
pub async fn read_reply(s: &mut TcpStream) -> (u8, SocketAddr) {
    let mut head = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut head))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(head[0], 5, "reply version");
    let bound = match head[3] {
        1 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await.unwrap();
            SocketAddr::from(([b[0], b[1], b[2], b[3]], u16::from_be_bytes([b[4], b[5]])))
        }
        4 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await.unwrap();
            let ip: [u8; 16] = b[..16].try_into().unwrap();
            SocketAddr::from((ip, u16::from_be_bytes([b[16], b[17]])))
        }
        t => panic!("unexpected reply ATYP {t}"),
    };
    (head[1], bound)
}

/// Asserts the server closes the connection (EOF or reset) within `within`.
pub async fn assert_closed(s: &mut TcpStream, within: Duration) {
    let mut buf = [0u8; 64];
    match tokio::time::timeout(within, s.read(&mut buf)).await {
        Ok(Ok(0) | Err(_)) => {}
        Ok(Ok(n)) => panic!("expected the connection to close, got {n} bytes"),
        Err(_) => panic!("connection still open after {within:?}"),
    }
}

pub fn ipv6_available() -> bool {
    std::net::UdpSocket::bind("[::1]:0").is_ok()
}
