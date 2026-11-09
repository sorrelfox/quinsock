//! Configuration model, loaded from a TOML file.
//!
//! Every section and key is optional; missing values fall back to the defaults below.
//! Unknown keys are rejected so typos surface as errors instead of being silently ignored.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;

/// The fully commented example configuration shipped with the project.
pub const EXAMPLE: &str = include_str!("../config.example.toml");

/// Longest accepted timeout value in seconds (about 115 days).
const MAX_SECS: f64 = 10_000_000.0;

/// Shortest Happy Eyeballs connection attempt delay allowed by RFC 8305.
const MIN_ATTEMPT_DELAY_SECS: f64 = 0.01;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub log: LogConfig,
    pub auth: AuthConfig,
    pub commands: CommandsConfig,
    pub timeouts: TimeoutsConfig,
    pub tcp: TcpConfig,
    pub udp: UdpConfig,
    pub bind: BindConfig,
    pub dns: DnsConfig,
    pub outbound: OutboundConfig,
    pub acl: AclConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: Vec<SocketAddr>,
    pub ipv6: bool,
    /// Tokio worker threads; 0 = one per CPU.
    pub worker_threads: usize,
    /// Upper bound for the blocking pool (used by getaddrinfo).
    pub max_blocking_threads: usize,
    pub max_connections: usize,
    pub backlog: u32,
    pub reuse_address: bool,
    pub reuse_port: bool,
    pub raise_nofile_limit: bool,
    pub shutdown_grace_secs: f64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: vec![
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1080)),
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1080)),
            ],
            ipv6: true,
            worker_threads: 0,
            max_blocking_threads: 512,
            max_connections: 8192,
            backlog: 4096,
            reuse_address: true,
            reuse_port: false,
            raise_nofile_limit: true,
            shutdown_grace_secs: 10.0,
        }
    }
}

impl ServerConfig {
    pub fn shutdown_grace(&self) -> Duration {
        secs(self.shutdown_grace_secs)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// A tracing filter directive, e.g. "info" or "info,quinsock=debug".
    pub level: String,
    pub format: LogFormat,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            format: LogFormat::Full,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Full,
    Compact,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub mode: AuthMode,
    pub users: Vec<User>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    None,
    Password,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CommandsConfig {
    pub connect: bool,
    pub bind: bool,
    pub udp_associate: bool,
}

impl Default for CommandsConfig {
    fn default() -> Self {
        Self {
            connect: true,
            bind: true,
            udp_associate: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimeoutsConfig {
    pub handshake_secs: f64,
    /// Total budget for connecting to a destination, across all its addresses.
    pub connect_secs: f64,
    /// Happy Eyeballs delay before trying the next address (RFC 8305 recommends 0.25).
    pub connection_attempt_delay_secs: f64,
    /// Must exceed the system resolver's per-server timeout (5 s in glibc), or a
    /// single lost DNS packet fails the request instead of being retried.
    pub dns_secs: f64,
    /// 0 disables the idle timeout.
    pub tcp_idle_secs: f64,
    /// 0 disables the idle timeout; the association then lives as long as its TCP connection.
    pub udp_idle_secs: f64,
    pub bind_accept_secs: f64,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            handshake_secs: 10.0,
            connect_secs: 10.0,
            connection_attempt_delay_secs: 0.25,
            dns_secs: 15.0,
            tcp_idle_secs: 300.0,
            udp_idle_secs: 180.0,
            bind_accept_secs: 60.0,
        }
    }
}

impl TimeoutsConfig {
    pub fn handshake(&self) -> Duration {
        secs(self.handshake_secs)
    }
    pub fn connect(&self) -> Duration {
        secs(self.connect_secs)
    }
    pub fn connection_attempt_delay(&self) -> Duration {
        secs(self.connection_attempt_delay_secs)
    }
    pub fn dns(&self) -> Duration {
        secs(self.dns_secs)
    }
    pub fn tcp_idle(&self) -> Option<Duration> {
        secs_opt(self.tcp_idle_secs)
    }
    pub fn udp_idle(&self) -> Option<Duration> {
        secs_opt(self.udp_idle_secs)
    }
    pub fn bind_accept(&self) -> Duration {
        secs(self.bind_accept_secs)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TcpConfig {
    pub nodelay: bool,
    pub keepalive: bool,
    pub keepalive_time_secs: u64,
    pub keepalive_interval_secs: u64,
    pub keepalive_retries: u32,
    /// Relay buffer per direction per connection.
    pub relay_buffer_size: usize,
    /// SO_RCVBUF / SO_SNDBUF; 0 keeps kernel autotuning.
    pub recv_buffer_size: usize,
    pub send_buffer_size: usize,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            nodelay: true,
            keepalive: true,
            keepalive_time_secs: 60,
            keepalive_interval_secs: 10,
            keepalive_retries: 5,
            relay_buffer_size: 16 * 1024,
            recv_buffer_size: 0,
            send_buffer_size: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UdpConfig {
    pub max_associations: usize,
    pub recv_buffer_size: usize,
    pub send_buffer_size: usize,
    /// Set DF on outbound datagrams (IP_PMTUDISC_PROBE), as QUIC requires.
    pub dont_fragment: bool,
    pub reply_filter: ReplyFilter,
    /// BND.ADDR reported to clients instead of the local address (for NAT).
    pub advertise_address: Option<IpAddr>,
    /// Remote peers remembered per association for reply filtering.
    pub max_peers: usize,
    pub dns_cache_size: usize,
    pub dns_cache_ttl_secs: f64,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            max_associations: 2048,
            recv_buffer_size: 4 * 1024 * 1024,
            send_buffer_size: 4 * 1024 * 1024,
            dont_fragment: true,
            reply_filter: ReplyFilter::Address,
            advertise_address: None,
            max_peers: 4096,
            dns_cache_size: 64,
            dns_cache_ttl_secs: 60.0,
        }
    }
}

impl UdpConfig {
    pub fn dns_cache_ttl(&self) -> Duration {
        secs(self.dns_cache_ttl_secs)
    }
}

/// Which inbound datagrams are relayed back to the client.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyFilter {
    /// Anything arriving on the association's outbound socket.
    Any,
    /// Only from IP addresses the client has sent to.
    #[default]
    Address,
    /// Only from exact IP:port pairs the client has sent to.
    AddressPort,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BindConfig {
    /// BND.ADDR reported to clients instead of the local address (for NAT).
    pub external_address: Option<IpAddr>,
    /// Only accept the incoming connection from the host named in the request.
    pub strict_peer_check: bool,
}

impl Default for BindConfig {
    fn default() -> Self {
        Self {
            external_address: None,
            strict_peer_check: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub max_concurrent: usize,
    pub prefer: Prefer,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 256,
            prefer: Prefer::System,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Prefer {
    #[default]
    System,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutboundConfig {
    pub bind_ipv4: Option<Ipv4Addr>,
    pub bind_ipv6: Option<Ipv6Addr>,
    /// SO_BINDTODEVICE for outbound sockets (needs CAP_NET_RAW).
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AclConfig {
    /// Client networks allowed to connect; empty = everyone.
    pub client_allow: Vec<IpNet>,
    /// Destination networks allowed; empty = everything not denied.
    pub dest_allow: Vec<IpNet>,
    pub dest_deny: Vec<IpNet>,
    pub dest_deny_ports: Vec<u16>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(text)?)
    }

    /// Checks value ranges and consistency, normalizing where harmless (IPv6 listen
    /// addresses are dropped when IPv6 is off). Returns warnings to log.
    pub fn validate(&mut self) -> Result<Vec<String>, ConfigError> {
        let mut warnings = Vec::new();

        if !self.server.ipv6 {
            let before = self.server.listen.len();
            self.server.listen.retain(SocketAddr::is_ipv4);
            if self.server.listen.len() != before {
                warnings.push("server.ipv6 = false: IPv6 listen addresses are ignored".to_owned());
            }
            if self.outbound.bind_ipv6.take().is_some() {
                warnings.push("server.ipv6 = false: outbound.bind_ipv6 is ignored".to_owned());
            }
            for (name, addr) in [
                ("bind.external_address", self.bind.external_address),
                ("udp.advertise_address", self.udp.advertise_address),
            ] {
                if addr.is_some_and(|a| a.is_ipv6()) {
                    return Err(invalid(format!("{name} is IPv6 but server.ipv6 = false")));
                }
            }
        }
        if self.server.listen.is_empty() {
            return Err(invalid("server.listen contains no usable address"));
        }
        let mut seen = HashSet::new();
        for addr in &self.server.listen {
            if !seen.insert(addr) {
                return Err(invalid(format!("server.listen contains {addr} twice")));
            }
        }
        // The relay socket takes the family of the address the client connected to.
        if let Some(adv) = self.udp.advertise_address
            && !self
                .server
                .listen
                .iter()
                .any(|l| l.is_ipv4() == adv.is_ipv4())
        {
            warnings.push(format!(
                "udp.advertise_address {adv} is never used: it is only reported to clients \
                 of the same address family, and no listen address has it"
            ));
        }
        if let Err(e) = tracing_subscriber::EnvFilter::try_new(&self.log.level) {
            return Err(invalid(format!(
                "invalid log.level {:?}: {e}",
                self.log.level
            )));
        }

        let s = &self.server;
        check_range("server.worker_threads", s.worker_threads, 0, 1024)?;
        check_range(
            "server.max_blocking_threads",
            s.max_blocking_threads,
            1,
            16384,
        )?;
        check_range("server.max_connections", s.max_connections, 1, 10_000_000)?;
        check_range("server.backlog", s.backlog, 1, 65535)?;
        check_secs("server.shutdown_grace_secs", s.shutdown_grace_secs, false)?;

        let t = &self.timeouts;
        check_secs("timeouts.handshake_secs", t.handshake_secs, true)?;
        check_secs("timeouts.connect_secs", t.connect_secs, true)?;
        check_secs(
            "timeouts.connection_attempt_delay_secs",
            t.connection_attempt_delay_secs,
            false,
        )?;
        if t.connection_attempt_delay_secs < MIN_ATTEMPT_DELAY_SECS {
            return Err(invalid(format!(
                "timeouts.connection_attempt_delay_secs = {} is below the RFC 8305 minimum \
                 of {MIN_ATTEMPT_DELAY_SECS}",
                t.connection_attempt_delay_secs
            )));
        }
        check_secs("timeouts.dns_secs", t.dns_secs, true)?;
        check_secs("timeouts.bind_accept_secs", t.bind_accept_secs, true)?;
        check_secs("timeouts.tcp_idle_secs", t.tcp_idle_secs, false)?;
        check_secs("timeouts.udp_idle_secs", t.udp_idle_secs, false)?;

        let tcp = &self.tcp;
        check_range(
            "tcp.relay_buffer_size",
            tcp.relay_buffer_size,
            1024,
            1 << 20,
        )?;
        check_range("tcp.recv_buffer_size", tcp.recv_buffer_size, 0, 1 << 28)?;
        check_range("tcp.send_buffer_size", tcp.send_buffer_size, 0, 1 << 28)?;
        if tcp.keepalive {
            check_range("tcp.keepalive_time_secs", tcp.keepalive_time_secs, 1, 32767)?;
            check_range(
                "tcp.keepalive_interval_secs",
                tcp.keepalive_interval_secs,
                1,
                32767,
            )?;
            check_range("tcp.keepalive_retries", tcp.keepalive_retries, 1, 127)?;
        }

        let udp = &self.udp;
        check_range("udp.max_associations", udp.max_associations, 1, 10_000_000)?;
        check_range("udp.recv_buffer_size", udp.recv_buffer_size, 0, 1 << 28)?;
        check_range("udp.send_buffer_size", udp.send_buffer_size, 0, 1 << 28)?;
        check_range("udp.max_peers", udp.max_peers, 1, 1_000_000)?;
        check_range("udp.dns_cache_size", udp.dns_cache_size, 0, 4096)?;
        check_secs("udp.dns_cache_ttl_secs", udp.dns_cache_ttl_secs, false)?;

        check_range("dns.max_concurrent", self.dns.max_concurrent, 1, 65535)?;

        if self.outbound.interface.as_deref() == Some("") {
            self.outbound.interface = None;
        }
        if let Some(iface) = &self.outbound.interface
            && iface.len() >= 16
        {
            return Err(invalid(format!(
                "outbound.interface {iface:?} is longer than 15 bytes"
            )));
        }

        let auth = &self.auth;
        match auth.mode {
            AuthMode::Password => {
                if auth.users.is_empty() {
                    return Err(invalid(
                        "auth.mode = \"password\" requires at least one [[auth.users]]",
                    ));
                }
                let mut names = HashSet::new();
                for user in &auth.users {
                    if !(1..=255).contains(&user.username.len()) {
                        return Err(invalid("auth.users: username must be 1..=255 bytes"));
                    }
                    if !(1..=255).contains(&user.password.len()) {
                        return Err(invalid(format!(
                            "auth.users: password of {:?} must be 1..=255 bytes",
                            user.username
                        )));
                    }
                    if !names.insert(user.username.as_str()) {
                        return Err(invalid(format!(
                            "auth.users: duplicate user {:?}",
                            user.username
                        )));
                    }
                }
            }
            AuthMode::None => {
                if !auth.users.is_empty() {
                    warnings.push("auth.users is ignored because auth.mode = \"none\"".to_owned());
                }
                if self.server.listen.iter().any(|a| !a.ip().is_loopback()) {
                    warnings.push(
                        "authentication is disabled and the server listens on a non-loopback \
                         address: anyone who can reach it can use this proxy"
                            .to_owned(),
                    );
                }
            }
        }

        let c = &self.commands;
        if !(c.connect || c.bind || c.udp_associate) {
            return Err(invalid("all commands are disabled in [commands]"));
        }

        Ok(warnings)
    }
}

/// Warns when other users can change the config file, or read it while it holds
/// passwords.
pub fn permission_warning(path: &Path, cfg: &Config) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    let readable = mode & 0o004 != 0 && !cfg.auth.users.is_empty();
    let writable = mode & 0o002 != 0;
    let problem = match (readable, writable) {
        (true, true) => "contains passwords and is readable and writable by other users",
        (true, false) => "contains passwords but is readable by other users",
        (false, true) => "is writable by other users",
        (false, false) => return None,
    };
    Some(format!(
        "{} {problem} (mode {:o}); consider chmod 640",
        path.display(),
        mode & 0o777
    ))
}

fn secs(v: f64) -> Duration {
    Duration::try_from_secs_f64(v).unwrap_or(Duration::ZERO)
}

fn secs_opt(v: f64) -> Option<Duration> {
    (v > 0.0).then(|| secs(v))
}

fn invalid(msg: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(msg.into())
}

fn check_range<T: PartialOrd + fmt::Display>(
    name: &str,
    v: T,
    min: T,
    max: T,
) -> Result<(), ConfigError> {
    if v < min || v > max {
        return Err(invalid(format!(
            "{name} = {v} is out of range {min}..={max}"
        )));
    }
    Ok(())
}

fn check_secs(name: &str, v: f64, positive: bool) -> Result<(), ConfigError> {
    if !v.is_finite() || v < 0.0 || v > MAX_SECS || (positive && v == 0.0) {
        let bound = if positive { "> 0" } else { ">= 0" };
        return Err(invalid(format!(
            "{name} = {v} must be {bound} and at most {MAX_SECS}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_gives_defaults() {
        let mut cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.server.listen.len(), 2);
        assert_eq!(cfg.timeouts.handshake(), Duration::from_secs(10));
        assert_eq!(cfg.udp.reply_filter, ReplyFilter::Address);
        let warnings = cfg.validate().unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("authentication is disabled"))
        );
    }

    #[test]
    fn example_file_parses_and_validates() {
        let mut cfg = Config::from_toml(EXAMPLE).unwrap();
        cfg.validate().unwrap();
        let default = Config::default();
        assert_eq!(cfg.server.listen, default.server.listen);
        assert_eq!(cfg.server.max_connections, default.server.max_connections);
        assert_eq!(cfg.tcp.relay_buffer_size, default.tcp.relay_buffer_size);
        assert_eq!(cfg.udp.recv_buffer_size, default.udp.recv_buffer_size);
    }

    #[test]
    fn packaged_config_is_valid_and_loopback_only() {
        let mut cfg = Config::from_toml(include_str!("../packaging/config.toml")).unwrap();
        let warnings = cfg.validate().unwrap();
        assert!(cfg.server.listen.iter().all(|a| a.ip().is_loopback()));
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(Config::from_toml("[server]\nlisten_on = []").is_err());
        assert!(Config::from_toml("[nope]").is_err());
        assert!(Config::from_toml("[auth]\nmode = \"kerberos\"").is_err());
    }

    #[test]
    fn integer_seconds_are_accepted() {
        let cfg = Config::from_toml("[timeouts]\nhandshake_secs = 3\nconnect_secs = 0.5").unwrap();
        assert_eq!(cfg.timeouts.handshake(), Duration::from_secs(3));
        assert_eq!(cfg.timeouts.connect(), Duration::from_millis(500));
    }

    #[test]
    fn password_mode_requires_users() {
        let mut cfg = Config::from_toml("[auth]\nmode = \"password\"").unwrap();
        assert!(cfg.validate().is_err());
        let mut cfg = Config::from_toml(
            "[auth]\nmode = \"password\"\n[[auth.users]]\nusername = \"a\"\npassword = \"b\"",
        )
        .unwrap();
        cfg.validate().unwrap();
        assert!(!format!("{cfg:?}").contains("password: \"b\""));
    }

    #[test]
    fn ipv6_off_drops_ipv6_listeners() {
        let mut cfg = Config::from_toml("[server]\nipv6 = false").unwrap();
        let warnings = cfg.validate().unwrap();
        assert_eq!(cfg.server.listen, vec!["0.0.0.0:1080".parse().unwrap()]);
        assert!(warnings.iter().any(|w| w.contains("IPv6 listen")));

        let mut cfg =
            Config::from_toml("[server]\nipv6 = false\nlisten = [\"[::1]:1080\"]").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn out_of_range_values_fail() {
        for bad in [
            "[tcp]\nrelay_buffer_size = 10",
            "[timeouts]\nhandshake_secs = 0",
            "[timeouts]\ntcp_idle_secs = -1",
            "[server]\nmax_connections = 0",
            "[commands]\nconnect = false\nbind = false\nudp_associate = false",
            "[server]\nlisten = [\"127.0.0.1:1\", \"127.0.0.1:1\"]",
            "[timeouts]\nconnection_attempt_delay_secs = 0.001",
            "[timeouts]\nconnection_attempt_delay_secs = 0",
            "[log]\nlevel = \"quinsock=loud\"",
        ] {
            let mut cfg = Config::from_toml(bad).unwrap();
            assert!(cfg.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn advertise_address_of_a_missing_family_warns() {
        let warns = |toml: &str| {
            let mut cfg = Config::from_toml(toml).unwrap();
            let warnings = cfg.validate().unwrap();
            warnings.iter().any(|w| w.contains("advertise_address"))
        };
        assert!(warns(
            "[server]\nlisten = [\"127.0.0.1:1080\"]\n[udp]\nadvertise_address = \"2001:db8::1\""
        ));
        assert!(!warns(
            "[server]\nlisten = [\"127.0.0.1:1080\"]\n[udp]\nadvertise_address = \"192.0.2.1\""
        ));
        assert!(!warns("[udp]\nadvertise_address = \"2001:db8::1\""));
    }

    #[test]
    fn permission_warning_names_the_problem() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("quinsock-perm-{}.toml", std::process::id()));
        std::fs::write(&path, "").unwrap();
        let check = |mode: u32, cfg: &Config| {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            permission_warning(&path, cfg)
        };
        let mut with_users = Config::default();
        with_users.auth.users = vec![User {
            username: "a".into(),
            password: "b".into(),
        }];
        let without_users = Config::default();

        let warning = check(0o604, &with_users).unwrap();
        assert!(
            warning.contains("but is readable by other users"),
            "{warning}"
        );
        assert!(
            check(0o606, &with_users)
                .unwrap()
                .contains("readable and writable")
        );
        assert!(
            check(0o602, &without_users)
                .unwrap()
                .contains("is writable by other users")
        );
        assert_eq!(check(0o604, &without_users), None);
        assert_eq!(check(0o601, &with_users), None);
        assert_eq!(check(0o640, &with_users), None);
        std::fs::remove_file(&path).unwrap();
    }
}
