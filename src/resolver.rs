//! Destination resolution with a timeout, a concurrency bound and the IPv6 switch.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::config::{Config, Prefer};
use crate::error::SocksError;
use crate::net::normalize;
use crate::protocol::{Address, DomainName};

/// Maximum number of addresses kept per address family from one lookup.
const MAX_PER_FAMILY: usize = 8;

#[derive(Clone)]
pub struct Resolver {
    /// Bounds concurrent getaddrinfo calls. The permit moves into the blocking task, so
    /// lookups that outlive their timeout still count, and a DNS outage cannot exhaust
    /// the blocking thread pool.
    limit: Arc<Semaphore>,
    timeout: Duration,
    ipv6: bool,
    prefer: Prefer,
}

impl Resolver {
    pub fn new(cfg: &Config) -> Self {
        Self {
            limit: Arc::new(Semaphore::new(cfg.dns.max_concurrent)),
            timeout: cfg.timeouts.dns(),
            ipv6: cfg.server.ipv6,
            prefer: cfg.dns.prefer,
        }
    }

    /// Resolves `addr` to candidate socket addresses in preference order.
    pub async fn resolve(&self, addr: &Address) -> Result<Vec<SocketAddr>, SocksError> {
        match addr {
            Address::Ip(a) => self.check_ip(*a).map(|a| vec![a]),
            Address::Domain(name, port) => self.lookup(name, *port).await,
        }
    }

    /// Resolves `addr` to its most preferred socket address.
    pub async fn resolve_one(&self, addr: &Address) -> Result<SocketAddr, SocksError> {
        match addr {
            Address::Ip(a) => self.check_ip(*a),
            Address::Domain(..) => self
                .resolve(addr)
                .await?
                .into_iter()
                .next()
                .ok_or(SocksError::NoAddress),
        }
    }

    fn check_ip(&self, addr: SocketAddr) -> Result<SocketAddr, SocksError> {
        let addr = normalize(addr);
        if addr.is_ipv6() && !self.ipv6 {
            return Err(SocksError::Ipv6Disabled);
        }
        Ok(addr)
    }

    async fn lookup(&self, name: &DomainName, port: u16) -> Result<Vec<SocketAddr>, SocksError> {
        let host = name.as_str().ok_or(SocksError::InvalidDomain)?;
        // Clients using remote DNS (socks5h) often send IP literals as domain names.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.check_ip(SocketAddr::new(ip, port)).map(|a| vec![a]);
        }
        let host = host.to_owned();
        let limit = Arc::clone(&self.limit);
        let ipv6 = self.ipv6;
        let lookup = async move {
            let permit = limit
                .acquire_owned()
                .await
                .map_err(|_| SocksError::NoAddress)?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                (host.as_str(), port)
                    .to_socket_addrs()
                    .map(|found| usable(found, ipv6))
            })
            .await
            .map_err(|e| SocksError::Resolve(std::io::Error::other(e)))?
            .map_err(SocksError::Resolve)
        };
        let mut addrs = tokio::time::timeout(self.timeout, lookup)
            .await
            .map_err(|_| SocksError::ResolveTimeout)??;
        order(&mut addrs, self.prefer);
        if addrs.is_empty() {
            return Err(SocksError::NoAddress);
        }
        Ok(addrs)
    }
}

/// Normalizes lookup results, drops IPv6 when it is disabled, and keeps at most
/// [`MAX_PER_FAMILY`] addresses of each family in system order. Filtering before
/// truncating means a long answer of one family cannot crowd out the other.
fn usable(found: impl Iterator<Item = SocketAddr>, ipv6: bool) -> Vec<SocketAddr> {
    let (mut v4, mut v6) = (0, 0);
    found
        .map(normalize)
        .filter(|a| {
            let count = if a.is_ipv4() {
                &mut v4
            } else if ipv6 {
                &mut v6
            } else {
                return false;
            };
            *count += 1;
            *count <= MAX_PER_FAMILY
        })
        .collect()
}

/// Stable-sorts addresses by family preference, keeping system order within a family.
fn order(addrs: &mut [SocketAddr], prefer: Prefer) {
    match prefer {
        Prefer::System => {}
        Prefer::Ipv4 => addrs.sort_by_key(SocketAddr::is_ipv6),
        Prefer::Ipv6 => addrs.sort_by_key(SocketAddr::is_ipv4),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn resolver(ipv6: bool) -> Resolver {
        let mut cfg = Config::default();
        cfg.server.ipv6 = ipv6;
        cfg.timeouts.dns_secs = 2.0;
        Resolver::new(&cfg)
    }

    #[tokio::test]
    async fn ip_addresses_honor_ipv6_switch() {
        let v6: Address = "[2001:db8::1]:80".parse().unwrap();
        assert!(matches!(
            resolver(false).resolve(&v6).await,
            Err(SocksError::Ipv6Disabled)
        ));
        assert_eq!(resolver(true).resolve(&v6).await.unwrap().len(), 1);

        let mapped: Address = "[::ffff:10.0.0.1]:80".parse().unwrap();
        let got = resolver(false).resolve_one(&mapped).await.unwrap();
        assert_eq!(got, "10.0.0.1:80".parse().unwrap());
    }

    #[tokio::test]
    async fn ip_literal_domains_skip_dns() {
        let lit = Address::Domain(DomainName::new(b"127.0.0.1").unwrap(), 5);
        assert_eq!(
            resolver(true).resolve_one(&lit).await.unwrap(),
            "127.0.0.1:5".parse().unwrap()
        );
        let lit6 = Address::Domain(DomainName::new(b"::1").unwrap(), 5);
        assert!(resolver(false).resolve(&lit6).await.is_err());
    }

    #[tokio::test]
    async fn localhost_without_ipv6_is_ipv4_only() {
        let host = Address::Domain(DomainName::new(b"localhost").unwrap(), 80);
        let addrs = resolver(false).resolve(&host).await.unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(SocketAddr::is_ipv4));
    }

    #[tokio::test]
    async fn invalid_names_fail() {
        let bad = Address::Domain(DomainName::new(&[0xff, 0xfe]).unwrap(), 80);
        assert!(matches!(
            resolver(true).resolve(&bad).await,
            Err(SocksError::InvalidDomain)
        ));
        let missing = Address::Domain(DomainName::new(b"does-not-exist.invalid").unwrap(), 80);
        assert!(resolver(true).resolve(&missing).await.is_err());
    }

    #[test]
    fn preference_ordering_is_stable() {
        let a4: SocketAddr = "1.1.1.1:1".parse().unwrap();
        let b4: SocketAddr = "2.2.2.2:1".parse().unwrap();
        let a6: SocketAddr = "[::1]:1".parse().unwrap();
        let mut v = vec![a6, a4, b4];
        order(&mut v, Prefer::Ipv4);
        assert_eq!(v, vec![a4, b4, a6]);
        order(&mut v, Prefer::Ipv6);
        assert_eq!(v, vec![a6, a4, b4]);
    }

    #[test]
    fn families_are_filtered_before_the_cap() {
        let v6 = (1..=20u16)
            .map(|i| SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i), 80)));
        let v4 = (1..=3u8).map(|i| SocketAddr::from((Ipv4Addr::new(192, 0, 2, i), 80)));
        let mapped: SocketAddr = "[::ffff:192.0.2.9]:80".parse().unwrap();
        let all: Vec<SocketAddr> = v6.chain(v4).chain([mapped]).collect();

        let only_v4 = usable(all.iter().copied(), false);
        assert_eq!(only_v4.len(), 4);
        assert!(only_v4.iter().all(SocketAddr::is_ipv4));
        assert_eq!(only_v4[3], "192.0.2.9:80".parse().unwrap());

        let both = usable(all.iter().copied(), true);
        assert_eq!(both.iter().filter(|a| a.is_ipv6()).count(), MAX_PER_FAMILY);
        assert_eq!(both.iter().filter(|a| a.is_ipv4()).count(), 4);
        assert_eq!(both[0], all[0], "system order is kept");
    }
}
