mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use quinsock::config::{Prefer, ReplyFilter};
use tokio::net::{TcpStream, UdpSocket};

/// Opens an association, returning the control connection and relay address.
async fn associate(proxy: SocketAddr, dst: &[u8]) -> (TcpStream, SocketAddr) {
    let mut control = greet(proxy).await;
    send_request(&mut control, 3, dst).await;
    let (rep, relay) = read_reply(&mut control).await;
    assert_eq!(rep, 0);
    (control, relay)
}

fn wrap(target: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0, 0, 0];
    v.extend_from_slice(target);
    v.extend_from_slice(payload);
    v
}

async fn recv(socket: &UdpSocket, within: Duration) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buf = vec![0u8; 70000];
    match tokio::time::timeout(within, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, from))) => Some((buf[..n].to_vec(), from)),
        _ => None,
    }
}

const WAIT: Duration = Duration::from_secs(2);
const SHORT: Duration = Duration::from_millis(300);

#[tokio::test]
async fn relays_datagrams_with_unspecified_client_address() {
    let server = spawn(config()).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let (_control, relay) = associate(server.addr, &addr_bytes("0.0.0.0:0".parse().unwrap())).await;
    assert_eq!(relay.ip().to_string(), "127.0.0.1");

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&wrap(&addr_bytes(echo), b"hello"), relay)
        .await
        .unwrap();
    let (reply, from) = recv(&client, WAIT).await.expect("echo reply");
    assert_eq!(from, relay);
    assert_eq!(reply, wrap(&addr_bytes(echo), b"hello"));
}

#[tokio::test]
async fn announced_client_port_is_enforced() {
    let server = spawn(config()).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (_control, relay) = associate(server.addr, &addr_bytes(client.local_addr().unwrap())).await;

    other
        .send_to(&wrap(&addr_bytes(echo), b"sneaky"), relay)
        .await
        .unwrap();
    assert!(
        recv(&other, SHORT).await.is_none(),
        "foreign source port must be dropped"
    );
    client
        .send_to(&wrap(&addr_bytes(echo), b"legit"), relay)
        .await
        .unwrap();
    assert!(recv(&client, WAIT).await.is_some());
}

#[tokio::test]
async fn learned_client_port_is_locked() {
    let server = spawn(config()).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let (_control, relay) = associate(server.addr, &addr_bytes("0.0.0.0:0".parse().unwrap())).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&wrap(&addr_bytes(echo), b"first"), relay)
        .await
        .unwrap();
    assert!(recv(&client, WAIT).await.is_some());

    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    other
        .send_to(&wrap(&addr_bytes(echo), b"second"), relay)
        .await
        .unwrap();
    assert!(recv(&other, SHORT).await.is_none());
}

#[tokio::test]
async fn fragments_and_malformed_datagrams_are_dropped() {
    let server = spawn(config()).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let (_control, relay) = associate(server.addr, &addr_bytes("0.0.0.0:0".parse().unwrap())).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut fragment = wrap(&addr_bytes(echo), b"frag");
    fragment[2] = 1;
    client.send_to(&fragment, relay).await.unwrap();
    client.send_to(&[0, 0, 0, 1, 127], relay).await.unwrap();
    assert!(recv(&client, SHORT).await.is_none());

    client
        .send_to(&wrap(&addr_bytes(echo), b"whole"), relay)
        .await
        .unwrap();
    let (reply, _) = recv(&client, WAIT).await.expect("association still works");
    assert!(reply.ends_with(b"whole"));
}

#[tokio::test]
async fn domain_destination_is_resolved() {
    let mut cfg = config();
    cfg.dns.prefer = Prefer::Ipv4;
    let server = spawn(cfg).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let (_control, relay) = associate(server.addr, &addr_bytes("0.0.0.0:0".parse().unwrap())).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..2 {
        client
            .send_to(
                &wrap(&domain_bytes("localhost", echo.port()), b"dns"),
                relay,
            )
            .await
            .unwrap();
        let (reply, _) = recv(&client, WAIT)
            .await
            .expect("reply via resolved address");
        // Replies always carry the numeric source address.
        assert_eq!(reply, wrap(&addr_bytes(echo), b"dns"));
    }
}

#[tokio::test]
async fn large_datagram_round_trips() {
    let server = spawn(config()).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let (_control, relay) = associate(server.addr, &addr_bytes("0.0.0.0:0".parse().unwrap())).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload: Vec<u8> = (0..65000usize).map(|i| (i % 253) as u8).collect();
    client
        .send_to(&wrap(&addr_bytes(echo), &payload), relay)
        .await
        .unwrap();
    let (reply, _) = recv(&client, WAIT).await.expect("large reply");
    assert_eq!(reply.len(), 10 + payload.len());
    assert!(reply[10..] == payload[..]);
}

#[tokio::test]
async fn association_ends_with_control_connection() {
    let server = spawn(config()).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let (control, relay) = associate(server.addr, &addr_bytes("0.0.0.0:0".parse().unwrap())).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&wrap(&addr_bytes(echo), b"a"), relay)
        .await
        .unwrap();
    assert!(recv(&client, WAIT).await.is_some());

    drop(control);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = client.send_to(&wrap(&addr_bytes(echo), b"b"), relay).await;
    assert!(recv(&client, SHORT).await.is_none());
}

#[tokio::test]
async fn idle_association_is_closed() {
    let mut cfg = config();
    cfg.timeouts.udp_idle_secs = 0.5;
    let server = spawn(cfg).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let (mut control, relay) =
        associate(server.addr, &addr_bytes("0.0.0.0:0".parse().unwrap())).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&wrap(&addr_bytes(echo), b"a"), relay)
        .await
        .unwrap();
    assert!(recv(&client, WAIT).await.is_some());
    assert_closed(&mut control, Duration::from_secs(3)).await;
}

#[tokio::test]
async fn address_port_filter_drops_strangers() {
    let mut cfg = config();
    cfg.udp.reply_filter = ReplyFilter::AddressPort;
    let server = spawn(cfg).await;
    let (_control, relay) = associate(server.addr, &addr_bytes("0.0.0.0:0".parse().unwrap())).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    client
        .send_to(
            &wrap(&addr_bytes(remote.local_addr().unwrap()), b"hi"),
            relay,
        )
        .await
        .unwrap();
    let (got, outbound) = recv(&remote, WAIT).await.expect("datagram reaches remote");
    assert_eq!(got, b"hi");

    stranger.send_to(b"spoof", outbound).await.unwrap();
    assert!(
        recv(&client, SHORT).await.is_none(),
        "stranger must be filtered"
    );
    remote.send_to(b"reply", outbound).await.unwrap();
    let (reply, _) = recv(&client, WAIT).await.expect("known peer passes");
    assert!(reply.ends_with(b"reply"));
}

#[tokio::test]
async fn ipv6_association() {
    if !ipv6_available() {
        eprintln!("skipping: IPv6 unavailable");
        return;
    }
    let mut cfg = config();
    cfg.server.listen = vec!["[::1]:0".parse().unwrap()];
    let server = spawn(cfg).await;
    let echo = udp_echo("[::1]:0").await;
    let (_control, relay) = associate(server.addr, &addr_bytes("[::]:0".parse().unwrap())).await;
    assert_eq!(relay.ip().to_string(), "::1");
    let client = UdpSocket::bind("[::1]:0").await.unwrap();
    client
        .send_to(&wrap(&addr_bytes(echo), b"six"), relay)
        .await
        .unwrap();
    let (reply, _) = recv(&client, WAIT).await.expect("IPv6 echo");
    assert_eq!(reply, wrap(&addr_bytes(echo), b"six"));
}

#[tokio::test]
async fn association_survives_graceful_shutdown() {
    let server = spawn(config()).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let (mut control, relay) =
        associate(server.addr, &addr_bytes("0.0.0.0:0".parse().unwrap())).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    server.handle.shutdown();
    tokio::time::sleep(Duration::from_millis(200)).await;
    client
        .send_to(&wrap(&addr_bytes(echo), b"grace"), relay)
        .await
        .unwrap();
    let (reply, _) = recv(&client, WAIT)
        .await
        .expect("relayed during the grace period");
    assert!(reply.ends_with(b"grace"));
    // The test grace period is 1 s; then the association closes with its connection.
    assert_closed(&mut control, Duration::from_secs(3)).await;
}

#[tokio::test]
async fn ipv6_client_address_accepted_with_ipv6_disabled() {
    let mut cfg = config();
    cfg.server.ipv6 = false;
    let server = spawn(cfg).await;
    let echo = udp_echo("127.0.0.1:0").await;
    // DST.ADDR only names the client's own endpoint; many clients send [::]:0.
    let (_control, relay) = associate(server.addr, &addr_bytes("[::]:0".parse().unwrap())).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&wrap(&addr_bytes(echo), b"v4"), relay)
        .await
        .unwrap();
    let (reply, _) = recv(&client, WAIT).await.expect("echo reply");
    assert_eq!(reply, wrap(&addr_bytes(echo), b"v4"));
}

#[tokio::test]
async fn advertise_address_only_for_its_family() {
    let mut cfg = config();
    cfg.udp.advertise_address = Some("203.0.113.10".parse().unwrap());
    let server = spawn(cfg).await;
    let (_control, relay) = associate(server.addr, &addr_bytes("0.0.0.0:0".parse().unwrap())).await;
    assert_eq!(relay.ip().to_string(), "203.0.113.10");

    if !ipv6_available() {
        eprintln!("skipping the IPv6 half: IPv6 unavailable");
        return;
    }
    let mut cfg = config();
    cfg.server.listen = vec!["[::1]:0".parse().unwrap()];
    cfg.udp.advertise_address = Some("203.0.113.10".parse().unwrap());
    let server = spawn(cfg).await;
    let (_control, relay) = associate(server.addr, &addr_bytes("[::]:0".parse().unwrap())).await;
    assert_eq!(relay.ip().to_string(), "::1");
}

#[tokio::test]
async fn names_resolve_with_the_cache_disabled() {
    let mut cfg = config();
    cfg.dns.prefer = Prefer::Ipv4;
    cfg.udp.dns_cache_size = 0;
    let server = spawn(cfg).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let (_control, relay) = associate(server.addr, &addr_bytes("0.0.0.0:0".parse().unwrap())).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Every datagram waits for its own lookup, outside the relay loop.
    for i in 0..3u8 {
        client
            .send_to(&wrap(&domain_bytes("localhost", echo.port()), &[i]), relay)
            .await
            .unwrap();
        let (reply, _) = recv(&client, WAIT)
            .await
            .expect("reply via resolved address");
        assert_eq!(reply, wrap(&addr_bytes(echo), &[i]));
    }
}
