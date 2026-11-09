//! Minimal SOCKS5 client (CONNECT and UDP ASSOCIATE), used by the examples and tests.

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::protocol::{Address, VERSION, cmd, method, udp};

/// Username and password for RFC 1929 authentication.
#[derive(Debug, Clone, Copy)]
pub struct Credentials<'a> {
    pub username: &'a str,
    pub password: &'a str,
}

/// Opens a CONNECT tunnel to `target` through the proxy.
pub async fn connect(
    proxy: SocketAddr,
    target: &Address,
    creds: Option<Credentials<'_>>,
) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.set_nodelay(true)?;
    negotiate(&mut stream, creds).await?;
    request(&mut stream, cmd::CONNECT, target).await?;
    Ok(stream)
}

/// A UDP association: the control connection plus a UDP socket connected to the relay.
pub struct UdpAssociation {
    control: TcpStream,
    socket: UdpSocket,
}

impl UdpAssociation {
    pub async fn open(proxy: SocketAddr, creds: Option<Credentials<'_>>) -> io::Result<Self> {
        let mut control = TcpStream::connect(proxy).await?;
        control.set_nodelay(true)?;
        negotiate(&mut control, creds).await?;
        let local_ip = control.local_addr()?.ip();
        let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
        let announce = SocketAddr::new(local_ip, socket.local_addr()?.port());
        let Address::Ip(mut relay) =
            request(&mut control, cmd::UDP_ASSOCIATE, &Address::Ip(announce)).await?
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "relay address is not an IP address",
            ));
        };
        if relay.ip().is_unspecified() {
            relay.set_ip(proxy.ip());
        }
        socket.connect(relay).await?;
        Ok(Self { control, socket })
    }

    pub fn relay_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }

    /// Sends one datagram to `target` through the relay.
    pub async fn send_to(&self, payload: &[u8], target: &Address) -> io::Result<()> {
        let mut datagram = vec![0u8; 3 + target.encoded_len()];
        target
            .write(&mut datagram[3..])
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address"))?;
        datagram.extend_from_slice(payload);
        self.socket.send(&datagram).await.map(drop)
    }

    /// Receives one datagram, moving the payload to the start of `buf`.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        loop {
            let n = self.socket.recv(buf).await?;
            match udp::parse(&buf[..n]) {
                Ok(h) if h.frag == 0 => {
                    buf.copy_within(h.len..n, 0);
                    return Ok((n - h.len, h.address));
                }
                _ => continue,
            }
        }
    }

    pub fn into_parts(self) -> (TcpStream, UdpSocket) {
        (self.control, self.socket)
    }
}

/// Relays datagrams between `local` and `target` through the association until the
/// proxy closes it. Replies go to whichever local peer sent a datagram most recently.
pub async fn forward_udp(
    assoc: UdpAssociation,
    local: UdpSocket,
    target: Address,
) -> io::Result<()> {
    let (mut control, relay) = assoc.into_parts();
    let header_len = 3 + target.encoded_len();
    let mut up = vec![0u8; header_len + 65535];
    target
        .write(&mut up[3..header_len])
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address"))?;
    let mut down = vec![0u8; 65535];
    let mut app: Option<SocketAddr> = None;
    let mut discard = [0u8; 64];
    loop {
        tokio::select! {
            r = local.recv_from(&mut up[header_len..]) => {
                let (n, from) = r?;
                app = Some(from);
                // Errors such as ICMP port unreachable must not end the forwarder.
                let _ = relay.send(&up[..header_len + n]).await;
            }
            r = relay.recv(&mut down) => {
                let Ok(n) = r else { continue };
                if let (Some(app), Ok(h)) = (app, udp::parse(&down[..n]))
                    && h.frag == 0
                {
                    let _ = local.send_to(&down[h.len..n], app).await;
                }
            }
            r = control.read(&mut discard) => {
                if matches!(r, Ok(0) | Err(_)) {
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "proxy closed the UDP association"));
                }
            }
        }
    }
}

async fn negotiate(stream: &mut TcpStream, creds: Option<Credentials<'_>>) -> io::Result<()> {
    let wanted = if creds.is_some() {
        method::USER_PASS
    } else {
        method::NO_AUTH
    };
    stream.write_all(&[VERSION, 1, wanted]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp != [VERSION, wanted] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy refused the authentication method",
        ));
    }
    if let Some(c) = creds {
        let (user, pass) = (c.username.as_bytes(), c.password.as_bytes());
        let too_long = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "username or password longer than 255 bytes",
            )
        };
        let mut msg = vec![0x01, u8::try_from(user.len()).map_err(|_| too_long())?];
        msg.extend_from_slice(user);
        msg.push(u8::try_from(pass.len()).map_err(|_| too_long())?);
        msg.extend_from_slice(pass);
        stream.write_all(&msg).await?;
        stream.read_exact(&mut resp).await?;
        if resp[1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authentication failed",
            ));
        }
    }
    Ok(())
}

/// Sends a request and returns BND.ADDR from a successful reply.
async fn request(stream: &mut TcpStream, command: u8, target: &Address) -> io::Result<Address> {
    let mut msg = vec![VERSION, command, 0];
    msg.resize(3 + target.encoded_len(), 0);
    target
        .write(&mut msg[3..])
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address"))?;
    stream.write_all(&msg).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad reply version",
        ));
    }
    if head[1] != 0 {
        return Err(io::Error::other(format!(
            "proxy replied with error {:#04x}",
            head[1]
        )));
    }
    Address::read(stream, head[3])
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}
