//! Exposes a UDP destination as a local port, tunnelled through a SOCKS5 UDP ASSOCIATE.
//! Handy for testing QUIC/HTTP3 and DNS through the proxy with ordinary tools:
//!
//! ```text
//! cargo run --example udp_forwarder -- --proxy 127.0.0.1:1080 \
//!     --listen 127.0.0.1:8443 --target cloudflare-quic.com:443
//! curl --http3-only --connect-to cloudflare-quic.com:443:127.0.0.1:8443 https://cloudflare-quic.com/
//!
//! cargo run --example udp_forwarder -- --proxy 127.0.0.1:1080 \
//!     --listen 127.0.0.1:5353 --target 1.1.1.1:53
//! dig @127.0.0.1 -p 5353 example.com
//! ```

use std::net::SocketAddr;

use anyhow::bail;
use clap::Parser;
use quinsock::client::{Credentials, UdpAssociation, forward_udp};
use quinsock::protocol::Address;
use tokio::net::UdpSocket;

#[derive(Parser)]
struct Args {
    /// SOCKS5 proxy address
    #[arg(long)]
    proxy: SocketAddr,
    /// Local UDP address to accept datagrams on
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    /// Destination as host:port or ip:port (domains are resolved by the proxy)
    #[arg(long)]
    target: String,
    #[arg(long)]
    user: Option<String>,
    #[arg(long)]
    password: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let target: Address = args.target.parse().map_err(anyhow::Error::msg)?;
    let creds = match (&args.user, &args.password) {
        (Some(username), Some(password)) => Some(Credentials { username, password }),
        (None, None) => None,
        _ => bail!("--user and --password must be given together"),
    };
    let local = UdpSocket::bind(args.listen).await?;
    let assoc = UdpAssociation::open(args.proxy, creds).await?;
    eprintln!(
        "forwarding udp://{} -> {target} via relay {}",
        args.listen,
        assoc.relay_addr()?
    );
    forward_udp(assoc, local, target).await?;
    Ok(())
}
