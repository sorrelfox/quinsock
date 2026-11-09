//! Method negotiation, requests and replies on the TCP control connection.

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::addr::Writer;
use super::{Address, Reply, VERSION};
use crate::error::SocksError;

/// Maximum size of a reply: VER REP RSV + IPv6 address + port.
pub const MAX_REPLY_LEN: usize = 3 + 1 + 16 + 2;

/// Authentication methods offered by the client.
pub struct Methods {
    len: u8,
    buf: [u8; 255],
}

impl Methods {
    pub fn as_slice(&self) -> &[u8] {
        self.buf.get(..usize::from(self.len)).unwrap_or_default()
    }

    pub fn contains(&self, method: u8) -> bool {
        self.as_slice().contains(&method)
    }
}

/// Reads `VER | NMETHODS | METHODS`.
pub async fn read_greeting<R: AsyncRead + Unpin>(r: &mut R) -> Result<Methods, SocksError> {
    let [ver, len] = {
        let mut head = [0u8; 2];
        r.read_exact(&mut head).await?;
        head
    };
    if ver != VERSION {
        return Err(SocksError::BadVersion(ver));
    }
    let mut buf = [0u8; 255];
    let methods = buf
        .get_mut(..usize::from(len))
        .ok_or(SocksError::Malformed("method list"))?;
    r.read_exact(methods).await?;
    Ok(Methods { len, buf })
}

/// Writes `VER | METHOD`.
pub async fn write_method<W: AsyncWrite + Unpin>(w: &mut W, method: u8) -> io::Result<()> {
    w.write_all(&[VERSION, method]).await
}

/// A parsed `VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT` request.
#[derive(Debug, Clone, Copy)]
pub struct Request {
    pub command: u8,
    pub address: Address,
}

/// Reads a request. The command is returned raw; the caller decides whether it is supported.
/// A non-zero RSV byte is tolerated.
pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<Request, SocksError> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head).await?;
    let [ver, command, _rsv, kind] = head;
    if ver != VERSION {
        return Err(SocksError::BadVersion(ver));
    }
    let address = Address::read(r, kind).await?;
    Ok(Request { command, address })
}

/// Encodes `VER | REP | RSV | ATYP | BND.ADDR | BND.PORT`, returning the length.
pub fn encode_reply(reply: Reply, bound: SocketAddr, out: &mut [u8; MAX_REPLY_LEN]) -> usize {
    let mut w = Writer { buf: out, pos: 0 };
    // Cannot fail: the buffer fits the largest (IPv6) reply.
    let _ = w.put(&[VERSION, reply as u8, 0x00]);
    let head = w.pos;
    let addr_len = Address::Ip(bound).write(out.get_mut(head..).unwrap_or_default());
    head + addr_len.unwrap_or(0)
}

pub async fn write_reply<W: AsyncWrite + Unpin>(
    w: &mut W,
    reply: Reply,
    bound: SocketAddr,
) -> io::Result<()> {
    let mut buf = [0u8; MAX_REPLY_LEN];
    let len = encode_reply(reply, bound, &mut buf);
    w.write_all(buf.get(..len).unwrap_or_default()).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::protocol::cmd;

    #[test]
    fn reply_layout() {
        let mut buf = [0u8; MAX_REPLY_LEN];
        let n = encode_reply(Reply::Succeeded, "10.0.0.1:1080".parse().unwrap(), &mut buf);
        assert_eq!(&buf[..n], &[5, 0, 0, 1, 10, 0, 0, 1, 0x04, 0x38]);
        let n = encode_reply(Reply::HostUnreachable, "[::1]:1".parse().unwrap(), &mut buf);
        assert_eq!(n, 22);
        assert_eq!(&buf[..4], &[5, 4, 0, 4]);
        assert_eq!(buf[19], 1);
        assert_eq!(&buf[20..22], &[0, 1]);
    }

    #[tokio::test]
    async fn greeting_and_request() {
        let mut src: &[u8] = &[5, 2, 0, 2];
        let m = read_greeting(&mut src).await.unwrap();
        assert!(m.contains(0) && m.contains(2) && !m.contains(1));

        let mut src: &[u8] = &[5, 1, 0x7f, 1, 127, 0, 0, 1, 0, 80];
        let req = read_request(&mut src).await.unwrap();
        assert_eq!(req.command, cmd::CONNECT);
        assert_eq!(req.address, Address::Ip("127.0.0.1:80".parse().unwrap()));
    }

    #[tokio::test]
    async fn rejects_bad_version_and_truncation() {
        let mut src: &[u8] = &[4, 1, 0];
        assert!(matches!(
            read_greeting(&mut src).await,
            Err(SocksError::BadVersion(4))
        ));
        let full = [5u8, 1, 0, 3, 3, b'a', b'b', b'c', 0, 80];
        for i in 0..full.len() {
            let mut src = &full[..i];
            assert!(read_request(&mut src).await.is_err());
        }
        let mut src: &[u8] = &[5, 3, 0];
        assert!(read_greeting(&mut src).await.is_err());
        let mut src: &[u8] = &[5, 1, 0, 7, 1, 2];
        assert!(matches!(
            read_request(&mut src).await,
            Err(SocksError::AddressTypeNotSupported(7))
        ));
    }
}
