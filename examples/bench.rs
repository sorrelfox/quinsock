//! Load generator: N concurrent CONNECT tunnels through the proxy to an echo server,
//! each pushing `--bytes` and reading them back.
//!
//! ```text
//! ulimit -n 65536
//! cargo run --release -- --config config.toml &
//! cargo run --release --example bench -- --proxy 127.0.0.1:1080 --connections 10000 --bytes 65536
//! ```

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use clap::Parser;
use quinsock::client;
use quinsock::protocol::Address;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;

#[derive(Parser)]
struct Args {
    /// SOCKS5 proxy address
    #[arg(long)]
    proxy: SocketAddr,
    /// Concurrent tunnels
    #[arg(long, default_value_t = 1000)]
    connections: usize,
    /// Bytes echoed per tunnel
    #[arg(long, default_value_t = 1 << 20)]
    bytes: usize,
    /// Echo server to use instead of the built-in one
    #[arg(long)]
    target: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let target = match args.target {
        Some(t) => t,
        None => spawn_echo().await?,
    };
    let started = Instant::now();
    let tasks: Vec<_> = (0..args.connections)
        .map(|_| tokio::spawn(tunnel(args.proxy, target, args.bytes)))
        .collect();

    let mut connect_times = Vec::with_capacity(args.connections);
    let mut failures = 0usize;
    for t in tasks {
        match t.await? {
            Ok(connect) => connect_times.push(connect),
            Err(e) => {
                failures += 1;
                if failures <= 5 {
                    eprintln!("tunnel failed: {e}");
                }
            }
        }
    }
    let elapsed = started.elapsed();
    connect_times.sort();
    let pct = |p: usize| {
        connect_times
            .get(connect_times.len() * p / 100)
            .copied()
            .unwrap_or_default()
    };
    let total = (connect_times.len() * args.bytes * 2) as f64;
    println!(
        "tunnels ok {}, failed {failures}, elapsed {elapsed:.2?}",
        connect_times.len()
    );
    println!(
        "throughput {:.1} MiB/s (both directions)",
        total / elapsed.as_secs_f64() / (1024.0 * 1024.0)
    );
    println!(
        "connect latency p50 {:.2?}, p99 {:.2?}, max {:.2?}",
        pct(50),
        pct(99),
        connect_times.last().copied().unwrap_or_default()
    );
    Ok(())
}

/// Returns the time taken to establish the tunnel.
async fn tunnel(proxy: SocketAddr, target: SocketAddr, bytes: usize) -> std::io::Result<Duration> {
    let started = Instant::now();
    let stream = client::connect(proxy, &Address::Ip(target), None).await?;
    let connect = started.elapsed();
    let (mut r, mut w) = stream.into_split();
    let writer = tokio::spawn(async move {
        let chunk = vec![0x5a_u8; 16 * 1024];
        let mut left = bytes;
        while left > 0 {
            let n = left.min(chunk.len());
            w.write_all(&chunk[..n]).await?;
            left -= n;
        }
        w.shutdown().await
    });
    let mut buf = vec![0u8; 64 * 1024];
    let mut received = 0;
    while received < bytes {
        match r.read(&mut buf).await? {
            0 => break,
            n => received += n,
        }
    }
    writer.await.map_err(std::io::Error::other)??;
    if received != bytes {
        return Err(std::io::Error::other(format!(
            "echoed {received} of {bytes} bytes"
        )));
    }
    Ok(connect)
}

async fn spawn_echo() -> std::io::Result<SocketAddr> {
    // A large backlog so the echo server itself is not the bottleneck when thousands
    // of tunnels open at once (the default of 1024 overflows and resets connections).
    let socket = TcpSocket::new_v4()?;
    socket.bind("127.0.0.1:0".parse().expect("valid address"))?;
    let listener = socket.listen(65535)?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    Ok(addr)
}
