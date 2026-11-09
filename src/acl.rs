//! Client and destination access control.

use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;

use crate::config::AclConfig;
use crate::error::SocksError;
use crate::net::normalize_ip;

pub struct Acl {
    client_allow: Vec<IpNet>,
    dest_allow: Vec<IpNet>,
    dest_deny: Vec<IpNet>,
    dest_deny_ports: Vec<u16>,
}

impl Acl {
    pub fn new(cfg: &AclConfig) -> Self {
        Self {
            client_allow: cfg.client_allow.clone(),
            dest_allow: cfg.dest_allow.clone(),
            dest_deny: cfg.dest_deny.clone(),
            dest_deny_ports: cfg.dest_deny_ports.clone(),
        }
    }

    pub fn allows_client(&self, ip: IpAddr) -> bool {
        self.client_allow.is_empty() || contains(&self.client_allow, normalize_ip(ip))
    }

    /// Checks a resolved destination (CONNECT target or UDP datagram destination).
    pub fn check_dest(&self, addr: SocketAddr) -> Result<(), SocksError> {
        if addr.port() == 0 || self.dest_deny_ports.contains(&addr.port()) {
            return Err(SocksError::NotAllowed);
        }
        self.check_dest_ip(addr.ip())
    }

    /// Checks a destination host regardless of port (BIND's expected peer).
    pub fn check_dest_ip(&self, ip: IpAddr) -> Result<(), SocksError> {
        let ip = normalize_ip(ip);
        // Never relay to "any" addresses, multicast or broadcast.
        let special = ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast());
        if special
            || contains(&self.dest_deny, ip)
            || (!self.dest_allow.is_empty() && !contains(&self.dest_allow, ip))
        {
            return Err(SocksError::NotAllowed);
        }
        Ok(())
    }
}

fn contains(nets: &[IpNet], ip: IpAddr) -> bool {
    nets.iter().any(|n| n.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(toml: &str) -> Acl {
        let cfg = crate::Config::from_toml(toml).unwrap();
        Acl::new(&cfg.acl)
    }

    #[test]
    fn empty_acl_allows_normal_destinations() {
        let a = acl("");
        assert!(a.check_dest("93.184.216.34:443".parse().unwrap()).is_ok());
        assert!(a.check_dest("127.0.0.1:22".parse().unwrap()).is_ok());
        assert!(a.allows_client("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn special_addresses_are_always_denied() {
        let a = acl("");
        for bad in [
            "0.0.0.0:80",
            "[::]:80",
            "224.0.0.1:80",
            "255.255.255.255:80",
            "[ff02::1]:80",
            "1.2.3.4:0",
        ] {
            assert!(a.check_dest(bad.parse().unwrap()).is_err(), "{bad}");
        }
    }

    #[test]
    fn deny_and_allow_lists() {
        let a = acl("[acl]\ndest_deny = [\"127.0.0.0/8\"]\ndest_deny_ports = [25]");
        assert!(a.check_dest("127.0.0.1:80".parse().unwrap()).is_err());
        // IPv4-mapped IPv6 must not bypass IPv4 rules.
        assert!(
            a.check_dest("[::ffff:127.0.0.1]:80".parse().unwrap())
                .is_err()
        );
        assert!(a.check_dest("8.8.8.8:25".parse().unwrap()).is_err());
        assert!(a.check_dest("8.8.8.8:53".parse().unwrap()).is_ok());

        let a = acl("[acl]\ndest_allow = [\"10.0.0.0/8\"]\nclient_allow = [\"192.168.0.0/16\"]");
        assert!(a.check_dest("10.1.2.3:80".parse().unwrap()).is_ok());
        assert!(a.check_dest("11.1.2.3:80".parse().unwrap()).is_err());
        assert!(a.allows_client("192.168.1.1".parse().unwrap()));
        assert!(!a.allows_client("10.0.0.1".parse().unwrap()));
    }
}
