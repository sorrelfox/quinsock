//! Listeners, accept loops, connection limits and graceful shutdown.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{Instrument, debug, info, warn};

use crate::acl::Acl;
use crate::auth::Authenticator;
use crate::config::Config;
use crate::net;
use crate::resolver::Resolver;
use crate::session;

/// State shared by every connection.
pub(crate) struct Context {
    pub cfg: Config,
    pub auth: Authenticator,
    pub resolver: Resolver,
    pub acl: Acl,
    pub udp_limit: Arc<Semaphore>,
    /// Stop accepting; abort negotiations and pending CONNECTs and BINDs. Active TCP
    /// relays and UDP associations keep running for the grace period.
    pub shutdown: CancellationToken,
    /// Close the remaining TCP relays and UDP associations.
    pub force: CancellationToken,
}

impl Context {
    pub(crate) fn new(cfg: Config) -> Self {
        Self {
            auth: Authenticator::new(&cfg.auth),
            resolver: Resolver::new(&cfg),
            acl: Acl::new(&cfg.acl),
            udp_limit: Arc::new(Semaphore::new(cfg.udp.max_associations)),
            shutdown: CancellationToken::new(),
            force: CancellationToken::new(),
            cfg,
        }
    }
}

pub struct Server {
    ctx: Arc<Context>,
    listeners: Vec<TcpListener>,
    conn_limit: Arc<Semaphore>,
}

/// Triggers shutdown of a running [`Server`].
#[derive(Clone)]
pub struct ShutdownHandle {
    shutdown: CancellationToken,
    force: CancellationToken,
}

impl ShutdownHandle {
    /// Stops accepting and lets active relays run for the grace period.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    /// Closes everything immediately.
    pub fn shutdown_now(&self) {
        self.shutdown.cancel();
        self.force.cancel();
    }
}

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

impl Server {
    /// Validates `cfg` and binds all listeners. The warnings from
    /// [`Config::validate`] are not reported here: call it first to show them. Must be
    /// called within a Tokio runtime.
    pub fn bind(mut cfg: Config) -> io::Result<Self> {
        cfg.validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut listeners = Vec::with_capacity(cfg.server.listen.len());
        for &addr in &cfg.server.listen {
            match net::bind_listener(addr, &cfg.server, &cfg.tcp) {
                Ok(listener) => listeners.push(listener),
                Err(e) if ipv6_unavailable(addr, &e) => {
                    warn!(%addr, error = %e, "IPv6 is unavailable; not listening on this address");
                }
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("cannot listen on {addr}: {e}"),
                    ));
                }
            }
        }
        if listeners.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no listen address could be bound",
            ));
        }
        for listener in &listeners {
            if let Ok(addr) = listener.local_addr() {
                info!(%addr, "listening");
            }
        }
        if cfg.commands.udp_associate {
            net::log_udp_buffer_sizes(&cfg.udp);
        }

        let conn_limit = Arc::new(Semaphore::new(cfg.server.max_connections));
        Ok(Self {
            ctx: Arc::new(Context::new(cfg)),
            listeners,
            conn_limit,
        })
    }

    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|l| l.local_addr().ok())
            .collect()
    }

    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shutdown: self.ctx.shutdown.clone(),
            force: self.ctx.force.clone(),
        }
    }

    /// Serves until shutdown is requested, then drains connections. Dropping the
    /// future early closes everything, like [`ShutdownHandle::shutdown_now`].
    pub async fn run(self) {
        // Cancelled when this future is dropped or completes, so no accept loop or
        // session outlives it.
        let _stop_on_drop = (
            self.ctx.shutdown.clone().drop_guard(),
            self.ctx.force.clone().drop_guard(),
        );
        info!(
            version = env!("CARGO_PKG_VERSION"),
            auth = ?self.ctx.cfg.auth.mode,
            ipv6 = self.ctx.cfg.server.ipv6,
            max_connections = self.ctx.cfg.server.max_connections,
            "quinsock started"
        );
        let tracker = TaskTracker::new();
        let mut accept_loops = JoinSet::new();
        for listener in self.listeners {
            accept_loops.spawn(accept_loop(
                listener,
                Arc::clone(&self.ctx),
                Arc::clone(&self.conn_limit),
                tracker.clone(),
            ));
        }
        // Accept loops return (dropping their listeners) once shutdown is requested.
        while accept_loops.join_next().await.is_some() {}
        tracker.close();

        let grace = self.ctx.cfg.server.shutdown_grace();
        if !tracker.is_empty() {
            info!(
                connections = tracker.len(),
                grace_secs = grace.as_secs_f64(),
                "waiting for active connections"
            );
        }
        if tokio::time::timeout(grace, tracker.wait()).await.is_err() {
            info!(
                connections = tracker.len(),
                "grace period over, closing remaining connections"
            );
            self.ctx.force.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(1), tracker.wait()).await;
        }
        info!("server stopped");
    }
}

async fn accept_loop(
    listener: TcpListener,
    ctx: Arc<Context>,
    limit: Arc<Semaphore>,
    tracker: TaskTracker,
) {
    let mut last_warning: Option<Instant> = None;
    loop {
        // Take a connection slot before accepting: at the limit, new clients wait in
        // the kernel backlog instead of being accepted and dropped.
        let permit = tokio::select! {
            biased;
            () = ctx.shutdown.cancelled() => break,
            p = Arc::clone(&limit).acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => break,
            },
        };
        let (stream, peer) = tokio::select! {
            biased;
            () = ctx.shutdown.cancelled() => break,
            r = listener.accept() => match r {
                Ok(accepted) => accepted,
                // The pending connection failed before it could be accepted.
                Err(e) if net::is_connection_error(&e) => {
                    debug!(error = %e, "accept failed");
                    continue;
                }
                // Out of resources, or an unexpected error: back off so a persistent
                // failure cannot spin a core.
                Err(e) => {
                    if last_warning.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
                        warn!(error = %e, "accept failed, backing off");
                        last_warning = Some(Instant::now());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let peer = net::normalize(peer);
        if !ctx.acl.allows_client(peer.ip()) {
            debug!(%peer, "client rejected by acl.client_allow");
            continue;
        }
        let id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let span = tracing::debug_span!("conn", id, %peer);
        let ctx = Arc::clone(&ctx);
        tracker.spawn(
            async move {
                let _permit = permit;
                session::run(stream, peer, ctx).await;
            }
            .instrument(span),
        );
    }
}

/// Whether binding the IPv6 listen address `addr` failed only because the host has
/// no IPv6. With IPv6 disabled by sysctl even `::1` cannot be bound (EADDRNOTAVAIL);
/// for any other address that error is a configuration mistake and stays fatal.
fn ipv6_unavailable(addr: SocketAddr, e: &io::Error) -> bool {
    if !addr.is_ipv6() {
        return false;
    }
    match e.raw_os_error() {
        Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT) => true,
        Some(libc::EADDRNOTAVAIL) => addr.ip().is_unspecified() || addr.ip().is_loopback(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_downgrade_only_for_generic_addresses() {
        let err = io::Error::from_raw_os_error;
        let loopback: SocketAddr = "[::1]:1080".parse().unwrap();
        let global: SocketAddr = "[2001:db8::1]:1080".parse().unwrap();
        let v4: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        assert!(ipv6_unavailable(loopback, &err(libc::EADDRNOTAVAIL)));
        assert!(!ipv6_unavailable(global, &err(libc::EADDRNOTAVAIL)));
        assert!(ipv6_unavailable(global, &err(libc::EAFNOSUPPORT)));
        assert!(!ipv6_unavailable(v4, &err(libc::EAFNOSUPPORT)));
        assert!(!ipv6_unavailable(loopback, &err(libc::EADDRINUSE)));
    }
}
