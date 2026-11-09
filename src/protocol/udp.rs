//! UDP relay datagram header: `RSV(2) | FRAG | ATYP | DST.ADDR | DST.PORT | DATA`.

use std::net::SocketAddr;

use super::addr::Writer;
use super::{Address, ParseError};

/// Header length when the address is IPv6, the largest header the relay ever writes.
pub const MAX_REPLY_HEADER_LEN: usize = 3 + 1 + 16 + 2;

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub frag: u8,
    pub address: Address,
    /// Offset of the payload within the datagram.
    pub len: usize,
}

/// Parses the header at the start of a client datagram. RSV is ignored.
pub fn parse(datagram: &[u8]) -> Result<Header, ParseError> {
    let (&[_, _, frag], rest) = datagram
        .split_first_chunk::<3>()
        .ok_or(ParseError::Truncated)?;
    let (address, addr_len) = Address::parse(rest)?;
    Ok(Header {
        frag,
        address,
        len: 3 + addr_len,
    })
}

/// Length of the header [`write_header`] produces for `addr`.
pub fn header_len(addr: SocketAddr) -> usize {
    3 + Address::Ip(addr).encoded_len()
}

/// Writes a header for `addr` into `out`, returning its length.
pub fn write_header(out: &mut [u8], addr: SocketAddr) -> Option<usize> {
    let mut w = Writer { buf: out, pos: 0 };
    w.put(&[0, 0, 0])?;
    let head = w.pos;
    let n = Address::Ip(addr).write(out.get_mut(head..)?)?;
    Some(head + n)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        for addr in ["1.2.3.4:53", "[2001:db8::2]:443"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let mut buf = [0u8; 64];
            let n = write_header(&mut buf, addr).unwrap();
            assert_eq!(n, header_len(addr));
            buf[n..n + 3].copy_from_slice(b"abc");
            let h = parse(&buf[..n + 3]).unwrap();
            assert_eq!(h.frag, 0);
            assert_eq!(h.address, Address::Ip(addr));
            assert_eq!(&buf[h.len..n + 3], b"abc");
        }
        assert!(MAX_REPLY_HEADER_LEN >= header_len("[::1]:1".parse().unwrap()));
    }

    #[test]
    fn domain_header_and_frag() {
        let dgram = [0, 0, 1, 3, 1, b'x', 0, 7, 0xAA];
        let h = parse(&dgram).unwrap();
        assert_eq!(h.frag, 1);
        assert_eq!(h.len, 8);
        assert!(matches!(h.address, Address::Domain(_, 7)));
    }

    #[test]
    fn truncated_headers_fail() {
        let dgram = [0u8, 0, 0, 1, 127, 0, 0, 1, 0, 53];
        for i in 0..dgram.len() {
            assert!(parse(&dgram[..i]).is_err());
        }
        assert!(parse(&dgram).is_ok());
    }
}
