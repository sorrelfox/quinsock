//! Bidirectional TCP relay with an idle timeout.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional_with_sizes};
use tokio::net::TcpStream;
use tracing::debug;

use crate::server::Context;

/// Copies data both ways until both sides close (half-close is propagated), the relay
/// is idle for `timeouts.tcp_idle_secs`, or a forced shutdown.
pub(crate) async fn run(client: TcpStream, remote: TcpStream, ctx: &Context) {
    let start = Instant::now();
    let last_read = AtomicU64::new(0);
    let mut client = Tracked {
        inner: client,
        last_read: &last_read,
        start,
    };
    let mut remote = Tracked {
        inner: remote,
        last_read: &last_read,
        start,
    };
    let size = ctx.cfg.tcp.relay_buffer_size;
    tokio::select! {
        r = copy_bidirectional_with_sizes(&mut client, &mut remote, size, size) => match r {
            Ok((sent, received)) => debug!(sent, received, "relay finished"),
            Err(e) => debug!(error = %e, "relay ended"),
        },
        () = idle_watchdog(&last_read, start, ctx.cfg.timeouts.tcp_idle()) => debug!("relay idle timeout"),
        () = ctx.force.cancelled() => debug!("relay closed by shutdown"),
    }
}

/// Sleeps until the last read is older than `idle`. Instead of resetting a timer on
/// every read, it wakes at the earliest possible expiry and re-checks.
async fn idle_watchdog(last_read: &AtomicU64, start: Instant, idle: Option<Duration>) {
    let Some(idle) = idle else {
        return std::future::pending().await;
    };
    loop {
        let deadline = start + Duration::from_millis(last_read.load(Ordering::Relaxed)) + idle;
        if Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep_until(deadline.into()).await;
    }
}

/// A stream that records the time of its last successful read.
struct Tracked<'a> {
    inner: TcpStream,
    last_read: &'a AtomicU64,
    start: Instant,
}

impl AsyncRead for Tracked<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(res, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            let now = u64::try_from(this.start.elapsed().as_millis()).unwrap_or(u64::MAX);
            this.last_read.store(now, Ordering::Relaxed);
        }
        res
    }
}

impl AsyncWrite for Tracked<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
