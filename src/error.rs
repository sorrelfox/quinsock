//! Session errors and their mapping to SOCKS reply codes.

use std::io;

use crate::protocol::Reply;

#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("unsupported SOCKS version {0:#04x}")]
    BadVersion(u8),
    #[error("malformed message: {0}")]
    Malformed(&'static str),
    #[error("no acceptable authentication method offered")]
    NoAcceptableMethod,
    #[error("authentication failed")]
    AuthFailed,
    #[error("unsupported command {0:#04x}")]
    CommandNotSupported(u8),
    #[error("command disabled by configuration")]
    CommandDisabled,
    #[error("unsupported address type {0:#04x}")]
    AddressTypeNotSupported(u8),
    #[error("IPv6 is disabled")]
    Ipv6Disabled,
    #[error("invalid domain name")]
    InvalidDomain,
    #[error("DNS resolution failed: {0}")]
    Resolve(io::Error),
    #[error("DNS resolution timed out")]
    ResolveTimeout,
    #[error("no usable address for destination")]
    NoAddress,
    #[error("connect timed out")]
    ConnectTimeout,
    #[error("destination not allowed")]
    NotAllowed,
    #[error("timed out waiting for the incoming BIND connection")]
    AcceptTimeout,
    #[error("UDP association limit reached")]
    TooManyAssociations,
}

impl SocksError {
    /// The reply code sent to the client for this error.
    pub fn reply(&self) -> Reply {
        match self {
            SocksError::Io(e) => reply_for_io(e),
            SocksError::CommandNotSupported(_) | SocksError::CommandDisabled => {
                Reply::CommandNotSupported
            }
            SocksError::AddressTypeNotSupported(_) | SocksError::Ipv6Disabled => {
                Reply::AddressTypeNotSupported
            }
            SocksError::Resolve(_) | SocksError::ResolveTimeout | SocksError::NoAddress => {
                Reply::HostUnreachable
            }
            SocksError::ConnectTimeout | SocksError::AcceptTimeout => Reply::TtlExpired,
            SocksError::NotAllowed => Reply::NotAllowed,
            SocksError::BadVersion(_)
            | SocksError::Malformed(_)
            | SocksError::NoAcceptableMethod
            | SocksError::AuthFailed
            | SocksError::InvalidDomain
            | SocksError::TooManyAssociations => Reply::GeneralFailure,
        }
    }

    /// True for errors detected after a complete request header was received, which the
    /// client must be told about with a reply before the connection is closed.
    pub fn needs_reply(&self) -> bool {
        matches!(
            self,
            SocksError::CommandNotSupported(_)
                | SocksError::CommandDisabled
                | SocksError::AddressTypeNotSupported(_)
                | SocksError::Ipv6Disabled
                | SocksError::InvalidDomain
        )
    }
}

/// Maps an OS error from connect/bind/accept to the closest reply code.
pub fn reply_for_io(e: &io::Error) -> Reply {
    use io::ErrorKind as K;
    match e.kind() {
        K::ConnectionRefused => Reply::ConnectionRefused,
        K::TimedOut => Reply::TtlExpired,
        K::NetworkUnreachable => Reply::NetworkUnreachable,
        K::HostUnreachable => Reply::HostUnreachable,
        // A local problem, not the destination's: ephemeral ports are exhausted, or
        // the configured source address does not exist on this host.
        K::AddrNotAvailable => Reply::GeneralFailure,
        K::PermissionDenied => Reply::NotAllowed,
        _ => match e.raw_os_error() {
            Some(libc::ENETUNREACH | libc::ENETDOWN) => Reply::NetworkUnreachable,
            Some(libc::EHOSTUNREACH | libc::EHOSTDOWN) => Reply::HostUnreachable,
            Some(libc::ECONNREFUSED) => Reply::ConnectionRefused,
            Some(libc::ETIMEDOUT) => Reply::TtlExpired,
            Some(libc::EACCES | libc::EPERM) => Reply::NotAllowed,
            _ => Reply::GeneralFailure,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_mapping() {
        let table = [
            (libc::ECONNREFUSED, Reply::ConnectionRefused),
            (libc::ENETUNREACH, Reply::NetworkUnreachable),
            (libc::EHOSTUNREACH, Reply::HostUnreachable),
            (libc::ETIMEDOUT, Reply::TtlExpired),
            (libc::EPERM, Reply::NotAllowed),
            (libc::EADDRNOTAVAIL, Reply::GeneralFailure),
            (libc::EIO, Reply::GeneralFailure),
        ];
        for (errno, reply) in table {
            assert_eq!(
                reply_for_io(&io::Error::from_raw_os_error(errno)),
                reply,
                "errno {errno}"
            );
        }
        assert_eq!(
            reply_for_io(&io::ErrorKind::TimedOut.into()),
            Reply::TtlExpired
        );
    }

    #[test]
    fn error_mapping() {
        let table = [
            (
                SocksError::CommandNotSupported(9),
                Reply::CommandNotSupported,
            ),
            (SocksError::CommandDisabled, Reply::CommandNotSupported),
            (
                SocksError::AddressTypeNotSupported(5),
                Reply::AddressTypeNotSupported,
            ),
            (SocksError::Ipv6Disabled, Reply::AddressTypeNotSupported),
            (SocksError::ResolveTimeout, Reply::HostUnreachable),
            (SocksError::NoAddress, Reply::HostUnreachable),
            (SocksError::ConnectTimeout, Reply::TtlExpired),
            (SocksError::AcceptTimeout, Reply::TtlExpired),
            (SocksError::NotAllowed, Reply::NotAllowed),
            (SocksError::InvalidDomain, Reply::GeneralFailure),
        ];
        for (err, reply) in table {
            assert_eq!(err.reply(), reply, "{err}");
        }
        assert!(SocksError::Ipv6Disabled.needs_reply());
        assert!(!SocksError::AuthFailed.needs_reply());
    }
}
