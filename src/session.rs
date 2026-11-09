//! One client connection: negotiation under a timeout, then command dispatch.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tracing::debug;

use crate::error::SocksError;
use crate::handlers::{bind, connect, udp};
use crate::net;
use crate::protocol::handshake::{self, Request};
use crate::protocol::{Address, cmd, method};
use crate::server::Context;

pub(crate) async fn run(mut stream: TcpStream, peer: SocketAddr, ctx: Arc<Context>) {
    net::configure_tcp(&stream, &ctx.cfg.tcp);
    let negotiated = tokio::select! {
        biased;
        () = ctx.shutdown.cancelled() => return,
        r = tokio::time::timeout(ctx.cfg.timeouts.handshake(), negotiate(&mut stream, &ctx)) => r,
    };
    let request = match negotiated {
        Ok(Ok(request)) => request,
        Ok(Err(e)) => {
            if e.needs_reply() {
                let _ = handshake::write_reply(&mut stream, e.reply(), net::UNSPECIFIED_V4).await;
            }
            debug!(error = %e, "negotiation failed");
            return;
        }
        Err(_) => {
            debug!("negotiation timed out");
            return;
        }
    };
    debug!(command = command_name(request.command), target = %request.address, "request");
    match request.command {
        cmd::CONNECT => connect::run(stream, &request.address, &ctx).await,
        cmd::BIND => bind::run(stream, &request.address, &ctx).await,
        cmd::UDP_ASSOCIATE => udp::run(stream, peer, &request.address, &ctx).await,
        _ => {}
    }
}

/// Method selection, authentication and request validation.
async fn negotiate(stream: &mut TcpStream, ctx: &Context) -> Result<Request, SocksError> {
    let methods = handshake::read_greeting(stream).await?;
    let selected = ctx.auth.select_method(&methods);
    handshake::write_method(stream, selected).await?;
    if selected == method::NO_ACCEPTABLE {
        return Err(SocksError::NoAcceptableMethod);
    }
    ctx.auth.authenticate(selected, stream).await?;

    let request = handshake::read_request(stream).await?;
    let commands = &ctx.cfg.commands;
    let enabled = match request.command {
        cmd::CONNECT => commands.connect,
        cmd::BIND => commands.bind,
        cmd::UDP_ASSOCIATE => commands.udp_associate,
        other => return Err(SocksError::CommandNotSupported(other)),
    };
    if !enabled {
        return Err(SocksError::CommandDisabled);
    }
    // For UDP ASSOCIATE, DST.ADDR only names the client's own endpoint, which clients
    // often send as [::]:0; the relay itself uses the address the client connected to.
    if request.command != cmd::UDP_ASSOCIATE
        && let Address::Ip(addr) = request.address
        && !ctx.cfg.server.ipv6
        && net::normalize(addr).is_ipv6()
    {
        return Err(SocksError::Ipv6Disabled);
    }
    Ok(request)
}

fn command_name(command: u8) -> &'static str {
    match command {
        cmd::CONNECT => "CONNECT",
        cmd::BIND => "BIND",
        cmd::UDP_ASSOCIATE => "UDP ASSOCIATE",
        _ => "unknown",
    }
}
