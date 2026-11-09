//! SOCKS address encoding: `ATYP | ADDR | PORT`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::atyp;
use crate::error::SocksError;

pub const MAX_DOMAIN_LEN: usize = 255;

/// A domain name stored inline (no heap allocation), 1..=255 bytes.
#[derive(Clone, Copy)]
pub struct DomainName {
    len: u8,
    buf: [u8; MAX_DOMAIN_LEN],
}

impl DomainName {
    /// Returns `None` if `name` is empty or longer than 255 bytes.
    pub fn new(name: &[u8]) -> Option<Self> {
        let len = u8::try_from(name.len()).ok().filter(|&l| l > 0)?;
        let mut buf = [0u8; MAX_DOMAIN_LEN];
        buf.get_mut(..name.len())?.copy_from_slice(name);
        Some(Self { len, buf })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..usize::from(self.len)).unwrap_or_default()
    }

    /// The name as UTF-8, if it is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()).ok()
    }
}

impl PartialEq for DomainName {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for DomainName {}

/// Escapes control characters, quotes and backslashes: names come from untrusted
/// clients and are written to logs, where a raw newline could forge a log line.
impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&String::from_utf8_lossy(self.as_bytes()).escape_debug(), f)
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(self.as_bytes()))
    }
}

/// A SOCKS destination or bound address.
// Domain names are stored inline so parsing a UDP datagram header never allocates.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Address {
    Ip(SocketAddr),
    Domain(DomainName, u16),
}

/// Failure to parse an address from a byte slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    UnknownAddressType(u8),
    EmptyDomain,
}

impl From<ParseError> for SocksError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::Truncated => SocksError::Malformed("truncated address"),
            ParseError::UnknownAddressType(t) => SocksError::AddressTypeNotSupported(t),
            ParseError::EmptyDomain => SocksError::InvalidDomain,
        }
    }
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::Ip(a) => a.port(),
            Address::Domain(_, p) => *p,
        }
    }

    /// Length of the `ATYP | ADDR | PORT` encoding.
    pub fn encoded_len(&self) -> usize {
        match self {
            Address::Ip(SocketAddr::V4(_)) => 1 + 4 + 2,
            Address::Ip(SocketAddr::V6(_)) => 1 + 16 + 2,
            Address::Domain(d, _) => 1 + 1 + d.as_bytes().len() + 2,
        }
    }

    /// Parses `ATYP | ADDR | PORT` from the start of `buf`, returning the address and
    /// the number of bytes consumed.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        let (&kind, rest) = buf.split_first().ok_or(ParseError::Truncated)?;
        match kind {
            atyp::IPV4 => {
                let &[a, b, c, d, p0, p1] = rest.first_chunk::<6>().ok_or(ParseError::Truncated)?;
                let ip = Ipv4Addr::new(a, b, c, d);
                Ok((
                    Address::Ip(SocketAddr::new(ip.into(), u16::from_be_bytes([p0, p1]))),
                    7,
                ))
            }
            atyp::IPV6 => {
                let (ip, rest) = rest
                    .split_first_chunk::<16>()
                    .ok_or(ParseError::Truncated)?;
                let &[p0, p1] = rest.first_chunk::<2>().ok_or(ParseError::Truncated)?;
                let ip = Ipv6Addr::from(*ip);
                Ok((
                    Address::Ip(SocketAddr::new(ip.into(), u16::from_be_bytes([p0, p1]))),
                    19,
                ))
            }
            atyp::DOMAIN => {
                let (&len, rest) = rest.split_first().ok_or(ParseError::Truncated)?;
                let len = usize::from(len);
                if len == 0 {
                    return Err(ParseError::EmptyDomain);
                }
                let name = rest.get(..len).ok_or(ParseError::Truncated)?;
                let &[p0, p1] = rest
                    .get(len..)
                    .and_then(|r| r.first_chunk::<2>())
                    .ok_or(ParseError::Truncated)?;
                let name = DomainName::new(name).ok_or(ParseError::EmptyDomain)?;
                Ok((
                    Address::Domain(name, u16::from_be_bytes([p0, p1])),
                    1 + 1 + len + 2,
                ))
            }
            other => Err(ParseError::UnknownAddressType(other)),
        }
    }

    /// Reads `ADDR | PORT` for the already-consumed address type `kind`.
    pub async fn read<R: AsyncRead + Unpin>(r: &mut R, kind: u8) -> Result<Self, SocksError> {
        match kind {
            atyp::IPV4 => {
                let mut b = [0u8; 6];
                r.read_exact(&mut b).await?;
                let [a, b2, c, d, p0, p1] = b;
                let ip = Ipv4Addr::new(a, b2, c, d);
                Ok(Address::Ip(SocketAddr::new(
                    ip.into(),
                    u16::from_be_bytes([p0, p1]),
                )))
            }
            atyp::IPV6 => {
                let mut ip = [0u8; 16];
                r.read_exact(&mut ip).await?;
                let port = r.read_u16().await?;
                Ok(Address::Ip(SocketAddr::new(
                    Ipv6Addr::from(ip).into(),
                    port,
                )))
            }
            atyp::DOMAIN => {
                let len = usize::from(r.read_u8().await?);
                if len == 0 {
                    return Err(SocksError::InvalidDomain);
                }
                let mut buf = [0u8; MAX_DOMAIN_LEN];
                let name = buf.get_mut(..len).ok_or(SocksError::InvalidDomain)?;
                r.read_exact(name).await?;
                let port = r.read_u16().await?;
                let name = DomainName::new(name).ok_or(SocksError::InvalidDomain)?;
                Ok(Address::Domain(name, port))
            }
            other => Err(SocksError::AddressTypeNotSupported(other)),
        }
    }

    /// Writes `ATYP | ADDR | PORT` into `out`, returning the number of bytes written,
    /// or `None` if `out` is too small.
    pub fn write(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer { buf: out, pos: 0 };
        match self {
            Address::Ip(SocketAddr::V4(a)) => {
                w.put(&[atyp::IPV4])?;
                w.put(&a.ip().octets())?;
            }
            Address::Ip(SocketAddr::V6(a)) => {
                w.put(&[atyp::IPV6])?;
                w.put(&a.ip().octets())?;
            }
            Address::Domain(d, _) => {
                let name = d.as_bytes();
                w.put(&[atyp::DOMAIN, u8::try_from(name.len()).ok()?])?;
                w.put(name)?;
            }
        }
        w.put(&self.port().to_be_bytes())?;
        Some(w.pos)
    }
}

impl From<SocketAddr> for Address {
    fn from(a: SocketAddr) -> Self {
        Address::Ip(a)
    }
}

impl FromStr for Address {
    type Err = &'static str;

    /// Accepts `ip:port`, `[ipv6]:port` or `host:port`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(a) = s.parse::<SocketAddr>() {
            return Ok(Address::Ip(a));
        }
        let (host, port) = s.rsplit_once(':').ok_or("expected host:port")?;
        let port = port.parse().map_err(|_| "invalid port")?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Address::Ip(SocketAddr::new(ip, port)));
        }
        let name = DomainName::new(host.as_bytes()).ok_or("host must be 1..=255 bytes")?;
        Ok(Address::Domain(name, port))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ip(a) => write!(f, "{a}"),
            Address::Domain(d, p) => write!(f, "{d}:{p}"),
        }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Bounds-checked sequential writer over a byte slice.
pub(crate) struct Writer<'a> {
    pub buf: &'a mut [u8],
    pub pos: usize,
}

impl Writer<'_> {
    pub fn put(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.pos.checked_add(bytes.len())?;
        self.buf.get_mut(self.pos..end)?.copy_from_slice(bytes);
        self.pos = end;
        Some(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn samples() -> Vec<Address> {
        vec![
            "1.2.3.4:80".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
            "example.com:8080".parse().unwrap(),
            Address::Domain(DomainName::new(&[b'a'; 255]).unwrap(), 1),
        ]
    }

    #[test]
    fn round_trip_all_address_types() {
        for addr in samples() {
            let mut buf = [0u8; 300];
            let n = addr.write(&mut buf).unwrap();
            assert_eq!(n, addr.encoded_len());
            let (parsed, used) = Address::parse(&buf[..n]).unwrap();
            assert_eq!(parsed, addr);
            assert_eq!(used, n);
        }
    }

    #[test]
    fn known_encodings() {
        let mut buf = [0u8; 32];
        let n = Address::from_str("1.2.3.4:80")
            .unwrap()
            .write(&mut buf)
            .unwrap();
        assert_eq!(&buf[..n], &[1, 1, 2, 3, 4, 0, 80]);
        let n = Address::from_str("ab.c:258")
            .unwrap()
            .write(&mut buf)
            .unwrap();
        assert_eq!(&buf[..n], &[3, 4, b'a', b'b', b'.', b'c', 1, 2]);
    }

    #[tokio::test]
    async fn async_read_matches_parse() {
        for addr in samples() {
            let mut buf = [0u8; 300];
            let n = addr.write(&mut buf).unwrap();
            let mut src = &buf[1..n];
            let read = Address::read(&mut src, buf[0]).await.unwrap();
            assert_eq!(read, addr);
        }
    }

    #[tokio::test]
    async fn every_truncated_prefix_fails_without_panic() {
        for addr in samples() {
            let mut buf = [0u8; 300];
            let n = addr.write(&mut buf).unwrap();
            for i in 0..n {
                assert!(Address::parse(&buf[..i]).is_err(), "{addr} prefix {i}");
                if i >= 1 {
                    let mut src = &buf[1..i];
                    assert!(Address::read(&mut src, buf[0]).await.is_err());
                }
            }
        }
    }

    #[test]
    fn rejects_empty_domain_and_unknown_type() {
        assert_eq!(Address::parse(&[3, 0, 0, 80]), Err(ParseError::EmptyDomain));
        assert_eq!(
            Address::parse(&[9, 1, 2, 3]),
            Err(ParseError::UnknownAddressType(9))
        );
        assert!(DomainName::new(&[]).is_none());
        assert!(DomainName::new(&[b'x'; 256]).is_none());
    }

    #[test]
    fn from_str_forms() {
        assert_eq!(
            Address::from_str("[::1]:53").unwrap(),
            Address::Ip("[::1]:53".parse().unwrap())
        );
        assert!(matches!(
            Address::from_str("localhost:1").unwrap(),
            Address::Domain(_, 1)
        ));
        assert!(Address::from_str("nohost").is_err());
        assert!(Address::from_str("host:99999").is_err());
    }

    #[test]
    fn display_escapes_control_characters() {
        let name = DomainName::new(b"evil.example\nINFO forged").unwrap();
        let addr = Address::Domain(name, 80);
        assert_eq!(addr.to_string(), "evil.example\\nINFO forged:80");
        assert!(!format!("{addr:?}").contains('\n'));
        assert_eq!(
            Address::from_str("example.com:443").unwrap().to_string(),
            "example.com:443"
        );
    }
}
