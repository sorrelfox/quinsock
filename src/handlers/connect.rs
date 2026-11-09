//! CONNECT: resolve, connect (Happy Eyeballs), reply, relay.

use std::io;
use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until};
use tracing::{debug, info, warn};

use crate::error::SocksError;
use crate::net;
use crate::protocol::handshake::write_reply;
use crate::protocol::{Address, Reply};
use crate::relay;
use crate::server::Context;

pub(crate) async fn run(mut client: TcpStream, target: &Address, ctx: &Context) {
    let outcome = tokio::select! {
        biased;
        () = ctx.shutdown.cancelled() => return,
        r = establish(target, ctx) => r,
    };
    let remote = match outcome {
        Ok(remote) => remote,
        Err(e) => {
            info!(%target, error = %e, "connect failed");
            let _ = write_reply(&mut client, e.reply(), net::UNSPECIFIED_V4).await;
            return;
        }
    };
    let bound = remote
        .local_addr()
        .map(net::normalize)
        .unwrap_or(net::UNSPECIFIED_V4);
    if let Err(e) = write_reply(&mut client, Reply::Succeeded, bound).await {
        debug!(error = %e, "cannot send reply");
        return;
    }
    debug!(%target, "connected");
    relay::run(client, remote, ctx).await;
}

async fn establish(target: &Address, ctx: &Context) -> Result<TcpStream, SocksError> {
    let candidates = ctx.resolver.resolve(target).await?;
    let stream = connect_any(interleave(candidates), ctx).await?;
    net::configure_tcp(&stream, &ctx.cfg.tcp);
    Ok(stream)
}

/// Happy Eyeballs (RFC 8305): attempts start `connection_attempt_delay_secs` apart, or
/// as soon as the previous one fails, and the first to connect wins. A destination
/// whose preferred address is blackholed (typically broken IPv6) then costs one delay
/// instead of the whole `connect_secs` budget.
async fn connect_any(candidates: Vec<SocketAddr>, ctx: &Context) -> Result<TcpStream, SocksError> {
    let deadline = Instant::now() + ctx.cfg.timeouts.connect();
    let timeout = sleep_until(deadline);
    tokio::pin!(timeout);
    let delay = ctx.cfg.timeouts.connection_attempt_delay();
    let mut pending = candidates.into_iter();
    let mut attempts = JoinSet::new();
    let mut next_start = Instant::now();
    let mut failure = Failure::default();
    loop {
        if attempts.is_empty() || Instant::now() >= next_start {
            match start_next(&mut pending, ctx, &mut failure) {
                Some((addr, socket)) => {
                    attempts
                        .spawn(async move { socket.connect(addr).await.map_err(|e| (addr, e)) });
                    next_start = Instant::now() + delay;
                }
                None if attempts.is_empty() => return Err(failure.into_error()),
                None => next_start = deadline,
            }
        }
        // Dropping `attempts` on return aborts the attempts still in flight.
        tokio::select! {
            Some(joined) = attempts.join_next() => match joined {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err((addr, e))) => {
                    debug!(%addr, error = %e, "connect attempt failed");
                    failure.attempt(addr, e, true);
                    next_start = Instant::now();
                }
                Err(e) => failure.record(0, SocksError::Io(io::Error::other(e))),
            },
            () = sleep_until(next_start), if next_start < deadline => {}
            () = &mut timeout => return Err(failure.at_deadline()),
        }
    }
}

/// Creates a socket for the next candidate the ACL allows. Denials and socket errors
/// are recorded, and the following candidate is tried at once.
fn start_next(
    pending: &mut impl Iterator<Item = SocketAddr>,
    ctx: &Context,
    failure: &mut Failure,
) -> Option<(SocketAddr, TcpSocket)> {
    for addr in pending {
        if ctx.acl.check_dest(addr).is_err() {
            failure.denied = true;
            continue;
        }
        match net::outbound_tcp_socket(addr, &ctx.cfg.outbound, &ctx.cfg.tcp) {
            Ok(socket) => return Some((addr, socket)),
            Err(e) => {
                debug!(%addr, error = %e, "cannot create outbound socket");
                failure.attempt(addr, e, false);
            }
        }
    }
    None
}

/// The error to report once every candidate has failed. Attempt errors are ranked so
/// the reply does not depend on the order in which addresses were tried, and an ACL
/// denial is reported only when no allowed address was left to try.
#[derive(Default)]
struct Failure {
    /// The most specific attempt error, with its rank.
    best: Option<(u8, SocksError)>,
    /// Some candidate was refused by the ACL.
    denied: bool,
}

impl Failure {
    /// Records an error from creating (`connecting == false`) or connecting a socket.
    /// Creation errors are local, e.g. EPERM from SO_BINDTODEVICE, so they rank lowest
    /// whatever their errno would suggest.
    fn attempt(&mut self, addr: SocketAddr, e: io::Error, connecting: bool) {
        if e.kind() == io::ErrorKind::AddrNotAvailable {
            warn_addr_not_available(addr, &e);
        }
        let e = SocksError::from(e);
        let rank = if connecting { rank(&e) } else { 0 };
        self.record(rank, e);
    }

    fn record(&mut self, rank: u8, e: SocksError) {
        // Strictly greater: on a tie the first error, from the preferred family, wins.
        if self.best.as_ref().is_none_or(|(best, _)| rank > *best) {
            self.best = Some((rank, e));
        }
    }

    fn into_error(self) -> SocksError {
        match self.best {
            Some((_, e)) => e,
            None if self.denied => SocksError::NotAllowed,
            None => SocksError::NoAddress,
        }
    }

    /// At the overall deadline a recorded refusal still says more than the timeout.
    fn at_deadline(self) -> SocksError {
        match self.best {
            Some((best, e)) if best > rank(&SocksError::ConnectTimeout) => e,
            _ => SocksError::ConnectTimeout,
        }
    }
}

/// How much a connect error tells the client about the destination; higher wins.
fn rank(e: &SocksError) -> u8 {
    match e.reply() {
        Reply::ConnectionRefused => 4,
        Reply::TtlExpired => 3,
        Reply::HostUnreachable => 2,
        Reply::NetworkUnreachable => 1,
        _ => 0,
    }
}

/// Running out of local addresses affects every client, so it is worth a warning, but
/// at most once per 10 seconds.
fn warn_addr_not_available(addr: SocketAddr, e: &io::Error) {
    static LAST: Mutex<Option<std::time::Instant>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(PoisonError::into_inner);
    if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(10)) {
        *last = Some(std::time::Instant::now());
        warn!(
            %addr,
            error = %e,
            "cannot assign a local address: ephemeral ports may be exhausted, or \
             outbound.bind_ipv4/bind_ipv6 is not configured on this host"
        );
    }
}

/// Alternates address families, starting with the family of the most preferred
/// address (RFC 8305 section 4).
fn interleave(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first_v6) = addrs.first().map(SocketAddr::is_ipv6) else {
        return addrs;
    };
    let (preferred, other): (Vec<_>, Vec<_>) =
        addrs.into_iter().partition(|a| a.is_ipv6() == first_v6);
    let mut out = Vec::with_capacity(preferred.len() + other.len());
    let (mut preferred, mut other) = (preferred.into_iter(), other.into_iter());
    loop {
        match (preferred.next(), other.next()) {
            (None, None) => return out,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::{TcpListener, TcpSocket};

    use super::*;
    use crate::config::Config;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn interleaves_address_families() {
        let got = interleave(vec![
            addr("[::1]:1"),
            addr("[::2]:1"),
            addr("[::3]:1"),
            addr("1.1.1.1:1"),
            addr("2.2.2.2:1"),
        ]);
        let want = ["[::1]:1", "1.1.1.1:1", "[::2]:1", "2.2.2.2:1", "[::3]:1"].map(addr);
        assert_eq!(got, want);
        assert_eq!(interleave(vec![addr("1.1.1.1:1")]), vec![addr("1.1.1.1:1")]);
        assert!(interleave(Vec::new()).is_empty());
    }

    /// A listener whose accept queue is full: the kernel silently drops further SYNs,
    /// so connecting to it hangs like a blackholed route. Returns `None` if the kernel
    /// does not behave that way here.
    async fn blackhole() -> Option<(SocketAddr, TcpListener, Vec<TcpStream>)> {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(addr("127.0.0.1:0")).unwrap();
        let listener = socket.listen(1).unwrap();
        let hole = listener.local_addr().unwrap();
        let mut fillers = Vec::new();
        for _ in 0..8 {
            match tokio::time::timeout(Duration::from_millis(300), TcpStream::connect(hole)).await {
                Ok(Ok(s)) => fillers.push(s),
                Ok(Err(_)) => return None,
                Err(_) => return Some((hole, listener, fillers)),
            }
        }
        None
    }

    fn context(connect_secs: f64) -> Context {
        let mut cfg = Config::default();
        cfg.timeouts.connect_secs = connect_secs;
        Context::new(cfg)
    }

    #[tokio::test]
    async fn blackholed_first_address_falls_back_quickly() {
        let Some((hole, _listener, _fillers)) = blackhole().await else {
            eprintln!("skipping: cannot build a blackholed listener here");
            return;
        };
        let good = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good.local_addr().unwrap();
        let started = std::time::Instant::now();
        let stream = connect_any(vec![hole, good_addr], &context(5.0))
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), good_addr);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn refused_address_starts_next_attempt_immediately() {
        let closed = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let good = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good.local_addr().unwrap();
        let started = std::time::Instant::now();
        let stream = connect_any(vec![closed, good_addr], &context(5.0))
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), good_addr);
        // Faster than the 250 ms attempt delay: the refusal triggers the fallback.
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn errors_and_timeouts_are_reported() {
        let closed = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let err = connect_any(vec![closed], &context(5.0)).await.unwrap_err();
        assert_eq!(err.reply(), Reply::ConnectionRefused);

        let Some((hole, _listener, _fillers)) = blackhole().await else {
            return;
        };
        let started = std::time::Instant::now();
        let err = connect_any(vec![hole], &context(0.5)).await.unwrap_err();
        assert!(matches!(err, SocksError::ConnectTimeout));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn most_specific_error_is_reported() {
        let closed = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let mut cfg = Config::default();
        cfg.acl.dest_deny = vec!["127.0.0.2/32".parse().unwrap()];
        let ctx = Context::new(cfg);
        // The refusal comes first and the ACL denial last; the refusal says more.
        let err = connect_any(vec![closed, addr("127.0.0.2:80")], &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.reply(), Reply::ConnectionRefused);
        // With nothing attempted, the denial is what the client learns.
        let err = connect_any(vec![addr("127.0.0.2:80")], &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.reply(), Reply::NotAllowed);
    }

    #[test]
    fn failure_ranking() {
        let refused = || SocksError::from(io::Error::from_raw_os_error(libc::ECONNREFUSED));
        let unreachable = || SocksError::from(io::Error::from_raw_os_error(libc::ENETUNREACH));
        let mut f = Failure::default();
        f.record(rank(&unreachable()), unreachable());
        f.record(rank(&refused()), refused());
        f.denied = true;
        assert_eq!(f.into_error().reply(), Reply::ConnectionRefused);

        let mut f = Failure::default();
        f.record(rank(&refused()), refused());
        assert_eq!(f.at_deadline().reply(), Reply::ConnectionRefused);
        let mut f = Failure::default();
        f.record(rank(&unreachable()), unreachable());
        assert!(matches!(f.at_deadline(), SocksError::ConnectTimeout));

        // A local failure still beats an ACL denial of another address.
        let mut f = Failure {
            denied: true,
            ..Failure::default()
        };
        f.record(
            0,
            SocksError::Io(io::Error::from_raw_os_error(libc::EMFILE)),
        );
        assert_eq!(f.into_error().reply(), Reply::GeneralFailure);
    }
}
