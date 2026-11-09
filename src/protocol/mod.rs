//! SOCKS5 wire format (RFC 1928, RFC 1929).
//!
//! Everything in here parses untrusted input, so indexing that could panic is forbidden.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

pub mod addr;
pub mod handshake;
pub mod udp;

pub use addr::{Address, DomainName, ParseError};

/// Protocol version byte for SOCKS5.
pub const VERSION: u8 = 0x05;

/// Authentication method identifiers (RFC 1928 section 3).
pub mod method {
    pub const NO_AUTH: u8 = 0x00;
    pub const GSSAPI: u8 = 0x01;
    pub const USER_PASS: u8 = 0x02;
    pub const NO_ACCEPTABLE: u8 = 0xFF;
}

/// Request commands (RFC 1928 section 4).
pub mod cmd {
    pub const CONNECT: u8 = 0x01;
    pub const BIND: u8 = 0x02;
    pub const UDP_ASSOCIATE: u8 = 0x03;
}

/// Address types (RFC 1928 section 5).
pub mod atyp {
    pub const IPV4: u8 = 0x01;
    pub const DOMAIN: u8 = 0x03;
    pub const IPV6: u8 = 0x04;
}

/// Reply codes (RFC 1928 section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    NotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}
