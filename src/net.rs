//! Socket construction, socket options and process limits.
//!
//! The only module allowed to use `unsafe`, for options socket2 does not expose.
#![allow(unsafe_code)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use libc::c_int;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

use crate::config::{OutboundConfig, ServerConfig, TcpConfig, UdpConfig};

pub const UNSPECIFIED_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// Converts IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to plain IPv4.
pub fn normalize(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), a.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Creates a non-blocking listener. IPv6 listeners are IPv6-only so `[::]` and
/// `0.0.0.0` can share a port. TCP buffer sizes are set before listen(2), so accepted
/// sockets inherit them.
pub fn bind_listener(
    addr: SocketAddr,
    cfg: &ServerConfig,
    tcp: &TcpConfig,
) -> io::Result<TcpListener> {
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_reuse_address(cfg.reuse_address)?;
    if cfg.reuse_port {
        sock.set_reuse_port(true)?;
    }
    set_tcp_buffer_sizes(&SockRef::from(&sock), tcp);
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(c_int::try_from(cfg.backlog).unwrap_or(c_int::MAX))?;
    TcpListener::from_std(sock.into())
}

/// Sets SO_RCVBUF / SO_SNDBUF when configured; 0 keeps the kernel's autotuning.
/// They only take full effect before listen(2) or connect(2) (see tcp(7)), because
/// the receive window is sized during the handshake. Failures are logged, not fatal.
pub fn set_tcp_buffer_sizes(sock: &SockRef<'_>, cfg: &TcpConfig) {
    let apply = || -> io::Result<()> {
        if cfg.recv_buffer_size > 0 {
            sock.set_recv_buffer_size(cfg.recv_buffer_size)?;
        }
        if cfg.send_buffer_size > 0 {
            sock.set_send_buffer_size(cfg.send_buffer_size)?;
        }
        Ok(())
    };
    if let Err(e) = apply() {
        tracing::debug!(error = %e, "cannot set TCP buffer sizes");
    }
}

/// Applies per-connection TCP options to a relayed stream. Failures are logged, not
/// fatal. Buffer sizes are applied before the handshake by [`set_tcp_buffer_sizes`].
pub fn configure_tcp(stream: &TcpStream, cfg: &TcpConfig) {
    if let Err(e) = apply_tcp_options(&SockRef::from(stream), cfg) {
        tracing::debug!(error = %e, "cannot set TCP socket options");
    }
}

fn apply_tcp_options(sock: &SockRef<'_>, cfg: &TcpConfig) -> io::Result<()> {
    sock.set_tcp_nodelay(cfg.nodelay)?;
    if cfg.keepalive {
        let params = TcpKeepalive::new()
            .with_time(Duration::from_secs(cfg.keepalive_time_secs))
            .with_interval(Duration::from_secs(cfg.keepalive_interval_secs))
            .with_retries(cfg.keepalive_retries);
        sock.set_keepalive(true)?;
        sock.set_tcp_keepalive(&params)?;
    }
    Ok(())
}

/// Creates an unconnected outbound TCP socket for `target`, honoring the configured
/// source address, interface and buffer sizes.
pub fn outbound_tcp_socket(
    target: SocketAddr,
    out: &OutboundConfig,
    tcp: &TcpConfig,
) -> io::Result<TcpSocket> {
    let sock = if target.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(iface) = &out.interface {
        SockRef::from(&sock).bind_device(Some(iface.as_bytes()))?;
    }
    set_tcp_buffer_sizes(&SockRef::from(&sock), tcp);
    let source = match target {
        SocketAddr::V4(_) => out.bind_ipv4.map(IpAddr::V4),
        SocketAddr::V6(_) => out.bind_ipv6.map(IpAddr::V6),
    };
    if let Some(ip) = source {
        // Let connect() pick the port, so one source port can serve many destinations
        // instead of exhausting the ephemeral range at bind time.
        let _ = setsockopt_int(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_BIND_ADDRESS_NO_PORT,
            1,
        );
        sock.bind(SocketAddr::new(ip, 0))?;
    }
    Ok(sock)
}

/// Creates a non-blocking UDP socket for the relay.
pub fn udp_socket(
    bind: SocketAddr,
    cfg: &UdpConfig,
    dont_fragment: bool,
    interface: Option<&str>,
) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))?;
    if bind.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    // Buffer sizes are best effort: the kernel silently caps them at rmem_max/wmem_max.
    if cfg.recv_buffer_size > 0 {
        let _ = sock.set_recv_buffer_size(cfg.recv_buffer_size);
    }
    if cfg.send_buffer_size > 0 {
        let _ = sock.set_send_buffer_size(cfg.send_buffer_size);
    }
    if dont_fragment {
        set_pmtud_probe(&sock, bind.is_ipv6())?;
    }
    if let Some(iface) = interface {
        sock.bind_device(Some(iface.as_bytes()))?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&bind.into())?;
    UdpSocket::from_std(sock.into())
}

/// Logs the UDP buffer sizes the kernel actually grants, which may be lower than
/// configured.
pub fn log_udp_buffer_sizes(cfg: &UdpConfig) {
    let Ok(sock) = Socket::new(Domain::IPV4, Type::DGRAM, None) else {
        return;
    };
    if cfg.recv_buffer_size > 0 {
        let _ = sock.set_recv_buffer_size(cfg.recv_buffer_size);
    }
    if cfg.send_buffer_size > 0 {
        let _ = sock.set_send_buffer_size(cfg.send_buffer_size);
    }
    // Linux reports twice the usable size to account for bookkeeping overhead.
    let recv = sock.recv_buffer_size().unwrap_or(0) / 2;
    let send = sock.send_buffer_size().unwrap_or(0) / 2;
    tracing::info!(recv, send, "UDP relay socket buffers");
    if recv < cfg.recv_buffer_size || send < cfg.send_buffer_size {
        tracing::warn!(
            requested_recv = cfg.recv_buffer_size,
            requested_send = cfg.send_buffer_size,
            "UDP socket buffers capped by the kernel; raise net.core.rmem_max / \
             net.core.wmem_max for high-throughput QUIC"
        );
    }
}

/// Sets DF and ignores the cached path MTU (IP_PMTUDISC_PROBE), matching what QUIC
/// stacks do on their own sockets so their path MTU probes are never fragmented.
fn set_pmtud_probe(sock: &Socket, v6: bool) -> io::Result<()> {
    if v6 {
        setsockopt_int(
            sock.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            libc::IPV6_PMTUDISC_PROBE,
        )
    } else {
        setsockopt_int(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_PROBE,
        )
    }
}

fn setsockopt_int(fd: RawFd, level: c_int, name: c_int, value: c_int) -> io::Result<()> {
    // SAFETY: `fd` is an open socket borrowed from the caller for the duration of the
    // call, and the option value points to a live c_int whose size is passed along.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&raw const value).cast(),
            size_of::<c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Raises the soft RLIMIT_NOFILE to the hard limit. Returns `(soft, hard)`.
pub fn raise_nofile_limit() -> io::Result<(u64, u64)> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if lim.rlim_cur < lim.rlim_max {
        let raised = libc::rlimit {
            rlim_cur: lim.rlim_max,
            rlim_max: lim.rlim_max,
        };
        // SAFETY: `raised` is a valid rlimit.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            lim.rlim_cur = lim.rlim_max;
        }
    }
    Ok((lim.rlim_cur, lim.rlim_max))
}

/// The local address the kernel would use to reach `dst`. Connecting a UDP socket
/// performs the route lookup without sending anything.
pub fn route_source_ip(dst: IpAddr) -> Option<IpAddr> {
    let any: IpAddr = if dst.is_ipv4() {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    };
    let sock = std::net::UdpSocket::bind(SocketAddr::new(any, 0)).ok()?;
    sock.connect(SocketAddr::new(dst, 9)).ok()?;
    let ip = normalize_ip(sock.local_addr().ok()?.ip());
    (!ip.is_unspecified()).then_some(ip)
}

/// Errors after which accept(2) should simply be retried: the pending connection
/// failed before it could be accepted (see accept(2), "Error handling").
pub(crate) fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            libc::ECONNABORTED
                | libc::EINTR
                | libc::EPERM
                | libc::EPROTO
                | libc::ETIMEDOUT
                | libc::ENETDOWN
                | libc::ENOPROTOOPT
                | libc::EHOSTDOWN
                | libc::ENONET
                | libc::EHOSTUNREACH
                | libc::EOPNOTSUPP
                | libc::ENETUNREACH
        )
    )
}

/// Out of file descriptors or kernel memory: retrying at once would only spin.
pub(crate) fn is_resource_exhaustion(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_mapped_addresses_only() {
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:80".parse().unwrap();
        assert_eq!(normalize(mapped), "192.0.2.1:80".parse().unwrap());
        let scoped: SocketAddr = "[fe80::1%2]:80".parse().unwrap();
        assert_eq!(normalize(scoped), scoped);
        assert_eq!(
            normalize_ip("::1".parse().unwrap()),
            "::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn route_source_for_loopback() {
        assert_eq!(
            route_source_ip("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn udp_socket_with_pmtud() {
        let sock = udp_socket(
            "127.0.0.1:0".parse().unwrap(),
            &UdpConfig::default(),
            true,
            None,
        )
        .unwrap();
        assert_ne!(sock.local_addr().unwrap().port(), 0);
    }

    #[test]
    fn nofile_limit_is_readable() {
        let (soft, hard) = raise_nofile_limit().unwrap();
        assert!(soft > 0 && soft <= hard);
    }

    #[test]
    fn accept_errors_are_classified() {
        let err = io::Error::from_raw_os_error;
        assert!(is_connection_error(&err(libc::ECONNABORTED)));
        assert!(is_connection_error(&err(libc::ENETUNREACH)));
        assert!(!is_connection_error(&err(libc::EMFILE)));
        assert!(is_resource_exhaustion(&err(libc::EMFILE)));
        assert!(is_resource_exhaustion(&err(libc::ENOBUFS)));
        assert!(!is_resource_exhaustion(&err(libc::EBADF)));
    }

    #[tokio::test]
    async fn accepted_sockets_inherit_listener_buffer_sizes() {
        let tcp = TcpConfig {
            recv_buffer_size: 4096,
            ..TcpConfig::default()
        };
        let listener = bind_listener(
            "127.0.0.1:0".parse().unwrap(),
            &ServerConfig::default(),
            &tcp,
        )
        .unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        // Linux reports twice the requested size; autotuned sockets start far larger.
        let size = SockRef::from(&accepted).recv_buffer_size().unwrap();
        assert!((4096..=16384).contains(&size), "SO_RCVBUF {size}");
    }
}
