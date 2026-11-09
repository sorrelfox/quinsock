//! UDP ASSOCIATE: one relay task per association.
//!
//! The task owns the client-facing socket and up to two outbound sockets (one per
//! address family, created on first use). A single buffer serves every datagram, and
//! reply headers are written into headroom in front of the received payload, so the
//! hot path neither allocates nor copies payloads. Only a datagram whose destination
//! name is not cached is copied, while its lookup runs outside the relay loop.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;
use tokio_util::task::AbortOnDropHandle;
use tracing::{debug, trace};

use crate::config::ReplyFilter;
use crate::error::SocksError;
use crate::net;
use crate::protocol::handshake::write_reply;
use crate::protocol::{Address, DomainName, Reply, udp};
use crate::server::Context;

/// Headroom for the reply header, then room for the largest UDP payload.
const BUF_LEN: usize = udp::MAX_REPLY_HEADER_LEN + 65535;
/// Datagrams handled per wakeup before the other sockets get a turn.
const BATCH: usize = 64;

pub(crate) async fn run(
    mut control: TcpStream,
    peer: SocketAddr,
    requested: &Address,
    ctx: &Context,
) {
    let Ok(_permit) = Arc::clone(&ctx.udp_limit).try_acquire_owned() else {
        debug!("UDP association limit reached");
        let reply = SocksError::TooManyAssociations.reply();
        let _ = write_reply(&mut control, reply, net::UNSPECIFIED_V4).await;
        return;
    };

    // Receive client datagrams on the address the client reached us on.
    let setup = || -> io::Result<(UdpSocket, SocketAddr)> {
        let local_ip = net::normalize(control.local_addr()?).ip();
        let socket = net::udp_socket(SocketAddr::new(local_ip, 0), &ctx.cfg.udp, false, None)?;
        let port = socket.local_addr()?.port();
        // An advertised address of the other family would be unreachable for the client.
        let advertised = ctx
            .cfg
            .udp
            .advertise_address
            .filter(|a| a.is_ipv4() == local_ip.is_ipv4())
            .unwrap_or(local_ip);
        Ok((socket, SocketAddr::new(advertised, port)))
    };
    let (client_socket, relay_addr) = match setup() {
        Ok(v) => v,
        Err(e) => {
            debug!(error = %e, "cannot create UDP relay socket");
            let _ = write_reply(
                &mut control,
                SocksError::from(e).reply(),
                net::UNSPECIFIED_V4,
            )
            .await;
            return;
        }
    };
    if write_reply(&mut control, Reply::Succeeded, relay_addr)
        .await
        .is_err()
    {
        return;
    }

    // Datagrams are only accepted from the control connection's IP. DST.ADDR/PORT in the
    // request may name the client's UDP port; otherwise (commonly 0.0.0.0:0, or behind
    // NAT) the port is learned from the first valid datagram.
    let client_addr = match *requested {
        Address::Ip(a) => {
            let a = net::normalize(a);
            (a.port() != 0 && (a.ip().is_unspecified() || a.ip() == peer.ip()))
                .then(|| SocketAddr::new(peer.ip(), a.port()))
        }
        Address::Domain(..) => None,
    };
    debug!(relay = %relay_addr, client = ?client_addr, "UDP association established");

    let mut assoc = Association {
        ctx,
        client: client_socket,
        out4: None,
        out6: None,
        out_error_logged: false,
        client_ip: peer.ip(),
        client_addr,
        peers: PeerSet::new(ctx.cfg.udp.max_peers),
        dns: DnsCache::new(ctx.cfg.udp.dns_cache_size, ctx.cfg.udp.dns_cache_ttl()),
        pending: None,
        buf: vec![0u8; BUF_LEN].into_boxed_slice(),
        last_activity: Instant::now(),
    };
    let reason = assoc.run(&mut control).await;
    debug!(reason, "UDP association closed");
}

struct Association<'a> {
    ctx: &'a Context,
    client: UdpSocket,
    out4: Option<UdpSocket>,
    out6: Option<UdpSocket>,
    /// Whether a failure to create an outbound socket was logged already.
    out_error_logged: bool,
    client_ip: IpAddr,
    client_addr: Option<SocketAddr>,
    peers: PeerSet,
    dns: DnsCache,
    /// A datagram waiting for its destination name to resolve. Client datagrams are
    /// not read meanwhile, which keeps them in order.
    pending: Option<Pending>,
    buf: Box<[u8]>,
    last_activity: Instant,
}

/// A client datagram whose destination name is being resolved.
struct Pending {
    name: DomainName,
    port: u16,
    from: SocketAddr,
    payload: Box<[u8]>,
    lookup: AbortOnDropHandle<Result<SocketAddr, SocksError>>,
}

impl Association<'_> {
    async fn run(&mut self, control: &mut TcpStream) -> &'static str {
        let idle = self.ctx.cfg.timeouts.udp_idle();
        let idle_sleep = tokio::time::sleep(idle.unwrap_or(Duration::MAX));
        tokio::pin!(idle_sleep);
        let mut discard = [0u8; 64];
        loop {
            tokio::select! {
                // A graceful shutdown lets associations run for the grace period.
                () = self.ctx.force.cancelled() => return "shutdown",
                // The association lives exactly as long as its TCP connection.
                r = control.read(&mut discard) => match r {
                    Ok(0) | Err(_) => return "control connection closed",
                    Ok(_) => {}
                },
                () = &mut idle_sleep, if idle.is_some() => {
                    if let Some(idle) = idle {
                        let deadline = self.last_activity + idle;
                        if Instant::now() >= deadline {
                            return "idle timeout";
                        }
                        idle_sleep.as_mut().reset(deadline);
                    }
                }
                r = self.client.readable(), if self.pending.is_none() => {
                    if r.is_err() {
                        return "client socket error";
                    }
                    self.pump_client().await;
                }
                r = readable(self.out4.as_ref()) => {
                    if r.is_err() {
                        return "outbound socket error";
                    }
                    self.pump_remote(false).await;
                }
                r = readable(self.out6.as_ref()) => {
                    if r.is_err() {
                        return "outbound socket error";
                    }
                    self.pump_remote(true).await;
                }
                r = lookup(self.pending.as_mut()) => {
                    // Taken at once: a finished lookup handle must not be polled again.
                    if let Some(pending) = self.pending.take() {
                        self.finish_lookup(pending, r).await;
                    }
                }
            }
        }
    }

    /// Client -> destination: validate, unwrap and forward a batch of datagrams.
    async fn pump_client(&mut self) {
        let mut forwarded = false;
        for _ in 0..BATCH {
            // A datagram waiting for DNS goes out before any later one.
            if self.pending.is_some() {
                break;
            }
            let (len, from) = match self.client.try_recv_from(&mut self.buf) {
                Ok(v) => v,
                Err(e) => {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        trace!(error = %e, "client receive failed");
                    }
                    break;
                }
            };
            forwarded |= self.forward_to_remote(len, net::normalize(from)).await;
        }
        if forwarded {
            self.last_activity = Instant::now();
        }
    }

    /// Returns whether the datagram was sent.
    async fn forward_to_remote(&mut self, len: usize, from: SocketAddr) -> bool {
        if from.ip() != self.client_ip || self.client_addr.is_some_and(|c| c != from) {
            trace!(%from, "dropped datagram from unexpected source");
            return false;
        }
        let Some(datagram) = self.buf.get(..len) else {
            return false;
        };
        let header = match udp::parse(datagram) {
            Ok(h) if h.frag == 0 => h,
            Ok(_) => {
                trace!("dropped fragmented datagram (fragmentation is not supported)");
                return false;
            }
            Err(e) => {
                trace!(error = ?e, "dropped malformed datagram");
                return false;
            }
        };
        let target = match header.address {
            Address::Ip(a) => net::normalize(a),
            Address::Domain(name, port) => match self.dns.get(&name) {
                Some(ip) => SocketAddr::new(ip, port),
                None => {
                    let payload: Box<[u8]> =
                        self.buf.get(header.len..len).unwrap_or_default().into();
                    self.start_lookup(name, port, from, payload);
                    return false;
                }
            },
        };
        if !self.prepare(from, target) {
            return false;
        }
        let socket = if target.is_ipv6() {
            self.out6.as_ref()
        } else {
            self.out4.as_ref()
        };
        let (Some(socket), Some(payload)) = (socket, self.buf.get(header.len..len)) else {
            return false;
        };
        send(socket, payload, target).await;
        true
    }

    /// Resolves `name` outside the relay loop; client reads pause until it finishes.
    fn start_lookup(&mut self, name: DomainName, port: u16, from: SocketAddr, payload: Box<[u8]>) {
        let resolver = self.ctx.resolver.clone();
        let address = Address::Domain(name, port);
        let lookup =
            AbortOnDropHandle::new(tokio::spawn(
                async move { resolver.resolve_one(&address).await },
            ));
        self.pending = Some(Pending {
            name,
            port,
            from,
            payload,
            lookup,
        });
    }

    /// Sends the datagram that waited for DNS, if its destination resolved.
    async fn finish_lookup(&mut self, pending: Pending, resolved: Result<SocketAddr, SocksError>) {
        let target = match resolved {
            Ok(target) => target,
            Err(e) => {
                let address = Address::Domain(pending.name, pending.port);
                debug!(target = %address, error = %e, "cannot resolve UDP destination");
                return;
            }
        };
        self.dns.insert(pending.name, target.ip());
        if !self.prepare(pending.from, target) {
            return;
        }
        let socket = if target.is_ipv6() {
            self.out6.as_ref()
        } else {
            self.out4.as_ref()
        };
        if let Some(socket) = socket {
            send(socket, &pending.payload, target).await;
            self.last_activity = Instant::now();
        }
    }

    /// Applies the IPv6 switch and the ACL, learns the client's port from its first
    /// valid datagram, and makes sure the outbound socket for `target` exists.
    fn prepare(&mut self, from: SocketAddr, target: SocketAddr) -> bool {
        if target.is_ipv6() && !self.ctx.cfg.server.ipv6 {
            return false;
        }
        if !self.peers.contains(target) {
            if self.ctx.acl.check_dest(target).is_err() {
                trace!(%target, "UDP destination not allowed");
                return false;
            }
            self.peers.insert(target);
        }
        if self.client_addr.is_none() {
            self.client_addr = Some(from);
        }
        self.ensure_outbound(target.is_ipv6())
    }

    /// Destination -> client: filter, prepend the header in place and forward a batch.
    async fn pump_remote(&mut self, v6: bool) {
        let mut forwarded = false;
        for _ in 0..BATCH {
            let socket = if v6 {
                self.out6.as_ref()
            } else {
                self.out4.as_ref()
            };
            let (Some(socket), Some(space)) =
                (socket, self.buf.get_mut(udp::MAX_REPLY_HEADER_LEN..))
            else {
                break;
            };
            let (len, from) = match socket.try_recv_from(space) {
                Ok(v) => v,
                Err(e) => {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        trace!(error = %e, "outbound receive failed");
                    }
                    break;
                }
            };
            let from = net::normalize(from);
            let Some(client) = self.client_addr else {
                continue;
            };
            if !self.peers.allows_reply(from, self.ctx.cfg.udp.reply_filter) {
                trace!(%from, "dropped datagram from unknown peer");
                continue;
            }
            let start = udp::MAX_REPLY_HEADER_LEN - udp::header_len(from);
            let written = self
                .buf
                .get_mut(start..udp::MAX_REPLY_HEADER_LEN)
                .and_then(|head| udp::write_header(head, from));
            let (Some(_), Some(datagram)) = (
                written,
                self.buf.get(start..udp::MAX_REPLY_HEADER_LEN + len),
            ) else {
                continue;
            };
            send(&self.client, datagram, client).await;
            forwarded = true;
        }
        if forwarded {
            self.last_activity = Instant::now();
        }
    }

    fn ensure_outbound(&mut self, v6: bool) -> bool {
        let slot = if v6 { &mut self.out6 } else { &mut self.out4 };
        if slot.is_some() {
            return true;
        }
        let cfg = &self.ctx.cfg;
        let ip: IpAddr = if v6 {
            cfg.outbound
                .bind_ipv6
                .unwrap_or(Ipv6Addr::UNSPECIFIED)
                .into()
        } else {
            cfg.outbound
                .bind_ipv4
                .unwrap_or(Ipv4Addr::UNSPECIFIED)
                .into()
        };
        let iface = cfg.outbound.interface.as_deref();
        match net::udp_socket(
            SocketAddr::new(ip, 0),
            &cfg.udp,
            cfg.udp.dont_fragment,
            iface,
        ) {
            Ok(socket) => {
                *slot = Some(socket);
                true
            }
            Err(e) => {
                // Logged once: every later datagram would fail the same way.
                if !self.out_error_logged {
                    self.out_error_logged = true;
                    debug!(error = %e, "cannot create outbound UDP socket");
                }
                false
            }
        }
    }
}

async fn readable(socket: Option<&UdpSocket>) -> io::Result<()> {
    match socket {
        Some(s) => s.readable().await,
        None => std::future::pending().await,
    }
}

/// Completes when the pending lookup finishes; never, when there is none.
async fn lookup(pending: Option<&mut Pending>) -> Result<SocketAddr, SocksError> {
    match pending {
        Some(p) => (&mut p.lookup)
            .await
            .unwrap_or_else(|e| Err(SocksError::Io(io::Error::other(e)))),
        None => std::future::pending().await,
    }
}

/// Sends without waiting when possible; waits for buffer space rather than dropping.
/// Other errors (e.g. EMSGSIZE with DF set) drop the datagram, as UDP would.
async fn send(socket: &UdpSocket, datagram: &[u8], to: SocketAddr) {
    let result = match socket.try_send_to(datagram, to) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => socket.send_to(datagram, to).await,
        other => other,
    };
    if let Err(e) = result {
        trace!(%to, error = %e, "datagram dropped");
    }
}

/// Remote endpoints the client has sent to, used for reply filtering and to skip
/// repeated ACL checks. Bounded: when full, the oldest peer is forgotten.
struct PeerSet {
    addrs: HashSet<SocketAddr>,
    /// Insertion order, oldest first.
    order: VecDeque<SocketAddr>,
    /// Remembered peers per IP address, for [`ReplyFilter::Address`].
    ips: HashMap<IpAddr, usize>,
    last: Option<SocketAddr>,
    cap: usize,
}

impl PeerSet {
    fn new(cap: usize) -> Self {
        Self {
            addrs: HashSet::new(),
            order: VecDeque::new(),
            ips: HashMap::new(),
            last: None,
            cap,
        }
    }

    fn contains(&self, addr: SocketAddr) -> bool {
        self.last == Some(addr) || self.addrs.contains(&addr)
    }

    fn insert(&mut self, addr: SocketAddr) {
        self.last = Some(addr);
        if !self.addrs.insert(addr) {
            return;
        }
        if self.order.len() >= self.cap
            && let Some(oldest) = self.order.pop_front()
        {
            self.addrs.remove(&oldest);
            if let Some(n) = self.ips.get_mut(&oldest.ip()) {
                *n -= 1;
                if *n == 0 {
                    self.ips.remove(&oldest.ip());
                }
            }
        }
        self.order.push_back(addr);
        *self.ips.entry(addr.ip()).or_insert(0) += 1;
    }

    fn allows_reply(&self, from: SocketAddr, filter: ReplyFilter) -> bool {
        match filter {
            ReplyFilter::Any => true,
            ReplyFilter::AddressPort => self.contains(from),
            ReplyFilter::Address => {
                self.last.is_some_and(|l| l.ip() == from.ip()) || self.ips.contains_key(&from.ip())
            }
        }
    }
}

/// Small per-association cache of domain lookups for UDP datagrams.
struct DnsCache {
    entries: Vec<DnsEntry>,
    cap: usize,
    ttl: Duration,
}

struct DnsEntry {
    name: DomainName,
    ip: IpAddr,
    expires: Instant,
}

impl DnsCache {
    fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            entries: Vec::new(),
            cap,
            ttl,
        }
    }

    fn get(&self, name: &DomainName) -> Option<IpAddr> {
        let now = Instant::now();
        self.entries
            .iter()
            .find(|e| e.name == *name && e.expires > now)
            .map(|e| e.ip)
    }

    fn insert(&mut self, name: DomainName, ip: IpAddr) {
        // A zero TTL disables the cache: its entries would already be expired.
        if self.cap == 0 || self.ttl.is_zero() {
            return;
        }
        let entry = DnsEntry {
            name,
            ip,
            expires: Instant::now() + self.ttl,
        };
        if let Some(existing) = self.entries.iter_mut().find(|e| e.name == name) {
            *existing = entry;
        } else if self.entries.len() < self.cap {
            self.entries.push(entry);
        } else if let Some(oldest) = self.entries.iter_mut().min_by_key(|e| e.expires) {
            *oldest = entry;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_set_filters() {
        let mut peers = PeerSet::new(2);
        let a: SocketAddr = "10.0.0.1:443".parse().unwrap();
        peers.insert(a);
        assert!(peers.allows_reply(a, ReplyFilter::AddressPort));
        assert!(!peers.allows_reply("10.0.0.1:444".parse().unwrap(), ReplyFilter::AddressPort));
        assert!(peers.allows_reply("10.0.0.1:444".parse().unwrap(), ReplyFilter::Address));
        assert!(!peers.allows_reply("10.0.0.2:443".parse().unwrap(), ReplyFilter::Address));
        assert!(peers.allows_reply("10.0.0.2:443".parse().unwrap(), ReplyFilter::Any));

        peers.insert("10.0.0.2:1".parse().unwrap());
        peers.insert("10.0.0.3:1".parse().unwrap());
        assert!(!peers.contains(a), "cleared when full");
    }

    #[test]
    fn peer_set_evicts_only_the_oldest() {
        let mut peers = PeerSet::new(2);
        let a1: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let a2: SocketAddr = "10.0.0.1:2".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:1".parse().unwrap();
        peers.insert(a1);
        peers.insert(a2);
        peers.insert(b);
        assert!(!peers.contains(a1));
        assert!(peers.contains(a2) && peers.contains(b));
        // 10.0.0.1 is still known through a2.
        assert!(peers.allows_reply("10.0.0.1:9".parse().unwrap(), ReplyFilter::Address));

        peers.insert("10.0.0.3:1".parse().unwrap());
        assert!(!peers.contains(a2));
        assert!(!peers.allows_reply("10.0.0.1:9".parse().unwrap(), ReplyFilter::Address));
        assert!(peers.contains(b));
    }

    #[tokio::test]
    async fn dns_cache_evicts_and_expires() {
        let name = |s: &str| DomainName::new(s.as_bytes()).unwrap();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let mut cache = DnsCache::new(1, Duration::from_secs(60));
        cache.insert(name("a"), ip);
        assert_eq!(cache.get(&name("a")), Some(ip));
        cache.insert(name("b"), ip);
        assert_eq!(cache.get(&name("a")), None);
        assert_eq!(cache.get(&name("b")), Some(ip));

        let mut cache = DnsCache::new(4, Duration::ZERO);
        cache.insert(name("a"), ip);
        assert_eq!(cache.get(&name("a")), None);
        assert!(cache.entries.is_empty(), "a zero TTL disables the cache");
    }
}
