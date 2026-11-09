//! BIND: listen for one incoming connection from the expected host, then relay.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use socket2::SockRef;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tracing::debug;

use crate::config::TcpConfig;
use crate::error::SocksError;
use crate::net;
use crate::protocol::handshake::write_reply;
use crate::protocol::{Address, Reply};
use crate::relay;
use crate::server::Context;

pub(crate) async fn run(mut control: TcpStream, target: &Address, ctx: &Context) {
    match accept_incoming(&mut control, target, ctx).await {
        Ok(Some(incoming)) => relay::run(control, incoming, ctx).await,
        Ok(None) => {}
        // Before the first reply this is the first reply; afterwards it is the second.
        Err(e) => {
            debug!(%target, error = %e, "BIND failed");
            let _ = write_reply(&mut control, e.reply(), net::UNSPECIFIED_V4).await;
        }
    }
}

/// Sends both BIND replies and returns the accepted connection, or `None` if the client
/// gave up or the server is shutting down.
async fn accept_incoming(
    control: &mut TcpStream,
    target: &Address,
    ctx: &Context,
) -> Result<Option<TcpStream>, SocksError> {
    let expected = expected_peers(target, ctx).await?;

    // Listen on the address the expected peer can reach us on.
    let control_ip = net::normalize(control.local_addr()?).ip();
    let listen_ip = expected
        .first()
        .and_then(|e| net::route_source_ip(e.ip()))
        .unwrap_or(control_ip);
    let listener = listen_on(SocketAddr::new(listen_ip, 0), &ctx.cfg.tcp)?;
    let port = listener.local_addr()?.port();
    // An external address of the other family would be unreachable for the peer.
    let external = ctx
        .cfg
        .bind
        .external_address
        .filter(|a| a.is_ipv4() == listen_ip.is_ipv4());
    let advertised = SocketAddr::new(external.unwrap_or(listen_ip), port);
    write_reply(control, Reply::Succeeded, advertised).await?;
    debug!(%advertised, "BIND listening");

    let deadline = tokio::time::Instant::now() + ctx.cfg.timeouts.bind_accept();
    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            () = ctx.shutdown.cancelled() => return Ok(None),
            // The client must stay silent until the second reply; data or EOF means it
            // abandoned the BIND.
            _ = control.read(&mut probe) => {
                debug!("client closed the control connection during BIND");
                return Ok(None);
            }
            () = tokio::time::sleep_until(deadline) => return Err(SocksError::AcceptTimeout),
            r = listener.accept() => {
                let (stream, from) = match r {
                    Ok(accepted) => accepted,
                    // The pending connection failed before it could be accepted.
                    Err(e) if net::is_connection_error(&e) => continue,
                    Err(e) if net::is_resource_exhaustion(&e) => {
                        debug!(error = %e, "BIND accept failed, retrying");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                let from = net::normalize(from);
                if ctx.cfg.bind.strict_peer_check
                    && !expected.is_empty()
                    && !expected.iter().any(|&e| peer_matches(e, from))
                {
                    debug!(%from, "rejected unexpected BIND peer");
                    continue;
                }
                if ctx.acl.check_dest_ip(from.ip()).is_err() {
                    debug!(%from, "BIND peer not allowed by the ACL");
                    continue;
                }
                write_reply(control, Reply::Succeeded, from).await?;
                net::configure_tcp(&stream, &ctx.cfg.tcp);
                return Ok(Some(stream));
            }
        }
    }
}

/// The addresses DST.ADDR allows to connect back; empty means any host. Only a literal
/// unspecified address means any host: a name that resolves to 0.0.0.0, as DNS
/// sinkholes answer, is refused by the ACL like any other denied destination.
async fn expected_peers(target: &Address, ctx: &Context) -> Result<Vec<SocketAddr>, SocksError> {
    if literal_ip(target).is_some_and(|ip| net::normalize_ip(ip).is_unspecified()) {
        return Ok(Vec::new());
    }
    let allowed: Vec<SocketAddr> = ctx
        .resolver
        .resolve(target)
        .await?
        .into_iter()
        .filter(|a| ctx.acl.check_dest_ip(a.ip()).is_ok())
        .collect();
    if allowed.is_empty() {
        return Err(SocksError::NotAllowed);
    }
    Ok(allowed)
}

/// The IP address in DST.ADDR, including a domain name that is an IP literal, as
/// clients using remote DNS often send.
fn literal_ip(target: &Address) -> Option<IpAddr> {
    match target {
        Address::Ip(a) => Some(a.ip()),
        Address::Domain(name, _) => name.as_str()?.parse().ok(),
    }
}

fn listen_on(addr: SocketAddr, tcp: &TcpConfig) -> std::io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // Before listen(2), so the accepted connection inherits them.
    net::set_tcp_buffer_sizes(&SockRef::from(&socket), tcp);
    socket.bind(addr)?;
    socket.listen(8)
}

/// The port only has to match when the client named one.
fn peer_matches(expected: SocketAddr, from: SocketAddr) -> bool {
    expected.ip() == from.ip() && (expected.port() == 0 || expected.port() == from.port())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::protocol::DomainName;

    #[test]
    fn peer_matching() {
        let from: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        assert!(peer_matches("10.0.0.1:0".parse().unwrap(), from));
        assert!(peer_matches("10.0.0.1:4000".parse().unwrap(), from));
        assert!(!peer_matches("10.0.0.1:4001".parse().unwrap(), from));
        assert!(!peer_matches("10.0.0.2:0".parse().unwrap(), from));
    }

    #[test]
    fn only_literal_addresses_are_literal() {
        let ip: Address = "0.0.0.0:0".parse().unwrap();
        assert_eq!(literal_ip(&ip), Some("0.0.0.0".parse().unwrap()));
        let literal = Address::Domain(DomainName::new(b"::").unwrap(), 0);
        assert_eq!(literal_ip(&literal), Some("::".parse().unwrap()));
        let name = Address::Domain(DomainName::new(b"sinkhole.example").unwrap(), 0);
        assert_eq!(literal_ip(&name), None);
    }

    #[tokio::test]
    async fn expected_peers_are_resolved_and_filtered() {
        let mut cfg = Config::default();
        cfg.acl.dest_deny = vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()];
        let ctx = Context::new(cfg);
        let anyone: Address = "0.0.0.0:0".parse().unwrap();
        assert!(expected_peers(&anyone, &ctx).await.unwrap().is_empty());
        let localhost: Address = "localhost:0".parse().unwrap();
        assert!(matches!(
            expected_peers(&localhost, &ctx).await,
            Err(SocksError::NotAllowed)
        ));

        let ctx = Context::new(Config::default());
        let peers = expected_peers(&localhost, &ctx).await.unwrap();
        assert!(peers.contains(&"127.0.0.1:0".parse().unwrap()), "{peers:?}");
    }
}
