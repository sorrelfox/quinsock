# quinsock

[![CI](https://github.com/sorrelfox/quinsock/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/sorrelfox/quinsock/actions/workflows/ci.yml)
[![Packages](https://github.com/sorrelfox/quinsock/actions/workflows/packages.yml/badge.svg)](https://github.com/sorrelfox/quinsock/actions/workflows/packages.yml)
[![Release](https://img.shields.io/github/v/release/sorrelfox/quinsock)](https://github.com/sorrelfox/quinsock/releases/latest)

A high-performance SOCKS5 proxy server written in Rust.

- **RFC 1928 commands**: CONNECT, BIND and UDP ASSOCIATE, with IPv4, IPv6 and
  domain-name addresses and the correct reply code for every failure. GSSAPI
  authentication (method `0x01`) is not supported.
- **Authentication**: either none (method `0x00`) or username/password (RFC 1929,
  method `0x02`, compared in constant time).
- **QUIC and HTTP/3 through the proxy**: the UDP relay sets the DF bit, uses large
  socket buffers, and never allocates or copies per datagram.
- **Configuration**: everything is set in one TOML file, including every timeout
  and limit. Typos in key names are reported instead of ignored.
- **IPv6 switch**: IPv6 can be turned off entirely.
- **Built for load**: multi-threaded Tokio, a bounded connection count with
  backpressure through the kernel backlog, idle timeouts, graceful shutdown, and no
  panics on malformed input.

## Quick start

```sh
cargo build --release
./target/release/quinsock --print-default-config > config.toml   # annotated defaults
./target/release/quinsock --config config.toml --check-config
./target/release/quinsock --config config.toml
```

Test it:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com   # domain resolved by the proxy
curl --socks5 127.0.0.1:1080 https://example.com            # IP address sent by curl
curl -x socks5h://alice:secret@127.0.0.1:1080 https://example.com
```

## Command line

| Option | Meaning |
|---|---|
| `-c, --config <PATH>` | Configuration file. If not given, `./config.toml` is used; if that doesn't exist either, the built-in defaults apply. |
| `--check-config` | Validate the configuration, print any warnings, and exit. |
| `--print-default-config` | Print the fully commented default configuration. |
| `--log-level <FILTER>` | Override the log level from the config file and `RUST_LOG`, e.g. `debug`. |

`SIGTERM` or `SIGINT` stops accepting new connections and aborts negotiations and
pending CONNECTs and BINDs. Active TCP relays and UDP associations get
`server.shutdown_grace_secs` to finish. A second signal exits immediately.

## Configuration

[`config.example.toml`](config.example.toml) documents every key along with its
default. The main sections:

| Section | Controls |
|---|---|
| `[server]` | Listen addresses, the `ipv6` switch, worker threads, `max_connections`, backlog, shutdown grace period |
| `[auth]` | `mode = "none" \| "password"` and `[[auth.users]]` |
| `[commands]` | Turning CONNECT, BIND or UDP ASSOCIATE on or off |
| `[timeouts]` | Handshake, connect, DNS, TCP idle, UDP idle and BIND accept timeouts |
| `[tcp]` | `TCP_NODELAY`, keepalive, relay buffer size, socket buffers |
| `[udp]` | Association limit, socket buffers, DF bit, reply filtering, advertised address, DNS cache |
| `[bind]` | Advertised address for BIND and the strict peer check |
| `[dns]` | Maximum concurrent lookups, IPv4 vs IPv6 preference |
| `[outbound]` | Source addresses and interface for outgoing traffic |
| `[acl]` | Allow and deny lists for client and destination networks, and blocked ports |

With `ipv6 = false`:
- IPv6 listen addresses are ignored;
- CONNECT and BIND requests with an IPv6 address get reply `0x08`;
- DNS results are filtered down to IPv4;
- IPv6 UDP datagrams are dropped.

## Protocol behaviour

### Reply codes

| Reply | Sent when |
|---|---|
| `0x01` | Any other failure |
| `0x02` | The destination is denied by `[acl]` |
| `0x03` / `0x04` | The network or host is unreachable, DNS fails, or no usable address is left |
| `0x05` | The destination refused the connection |
| `0x06` | A connect or BIND timed out |
| `0x07` | The command is unknown or disabled |
| `0x08` | The address type is unknown, or it is IPv6 while IPv6 is off |

### CONNECT
- Domain names are resolved on the server, within `timeouts.dns_secs` (15 s by
  default, enough for the system resolver to fail over to a second nameserver).
- Resolved addresses are tried Happy Eyeballs style (RFC 8305): IPv6 and IPv4
  alternate, a new attempt starts every `connection_attempt_delay_secs` or as soon as
  one fails, and the first connection wins. A host with broken IPv6 therefore still
  reaches dual-stack sites.
- Failed CONNECTs are logged at `info` level with the reason.

### BIND
- The listener is opened on the local address that routes to the host named in the
  request. `bind.external_address` replaces it in the first reply when both have the
  same address family.
- The first reply reports that listener address; the second reports the peer that
  connected.
- With `bind.strict_peer_check`, only the named host may connect, from any of its
  addresses. Only a literal `0.0.0.0` or `::` lets any host connect.
- Every connecting peer is checked against `acl.dest_allow` and `acl.dest_deny`.

### UDP ASSOCIATE
- The relay listens on the address the client used for its TCP connection.
  `udp.advertise_address` replaces it in the reply for clients of the same address
  family.
- Datagrams are accepted only from the client's IP. The port is either the one named
  in the request or learned from the client's first datagram. On a client host shared
  by several users, another process could send that first datagram and take over the
  association, so such clients should name their UDP port in the request.
- Domain destinations are resolved without holding up replies or the control
  connection, and cached per association (`udp.dns_cache_size`,
  `udp.dns_cache_ttl_secs`).
- Fragmented datagrams (`FRAG ≠ 0`) are dropped, which RFC 1928 permits.
- Replies are filtered by `udp.reply_filter`.
- The association ends when its TCP connection closes or after `udp_idle_secs` with
  no traffic.

### QUIC
QUIC is ordinary UDP to the proxy, so any SOCKS5 client that supports UDP ASSOCIATE
can reach QUIC servers. To test with curl, which can't send HTTP/3 through a SOCKS
proxy itself, use the bundled forwarder:

```sh
cargo run --example udp_forwarder -- --proxy 127.0.0.1:1080 \
    --listen 127.0.0.1:8443 --target cloudflare-quic.com:443
curl --http3-only --connect-to cloudflare-quic.com:443:127.0.0.1:8443 https://cloudflare-quic.com/
```

## Performance tuning

**Memory**
- Each TCP relay uses `2 × tcp.relay_buffer_size` of buffer (16 KiB per direction
  by default).
- Each UDP association uses one 64 KiB buffer.

**Open files**
- The server raises its soft `RLIMIT_NOFILE` to the hard limit, and warns if that's
  too low for `max_connections`.
- The systemd unit sets `LimitNOFILE=1048576`.

**UDP buffers for heavy QUIC traffic**
- Linux caps UDP socket buffers at `net.core.rmem_max` and `net.core.wmem_max`. The
  sizes actually applied are logged at startup.
- To raise the caps:
  ```sh
  sudo sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
  ```

**Load test**

```sh
ulimit -n 65536
cargo run --release --example bench -- --proxy 127.0.0.1:1080 --connections 10000 --bytes 65536
```

## Security notes

- With `auth.mode = "none"` on a non-loopback address the server is an open proxy.
  It logs a warning at startup when configured this way.
- Passwords are stored in plain text. Keep the config file at mode `0640`. The server
  warns if other users can read it while it holds passwords, or can change it.
- To stop clients from reaching the proxy host itself or your private networks, set
  `acl.dest_deny`. The example config lists the usual ranges. The check runs after
  DNS resolution, so DNS rebinding can't bypass it. It also applies to peers that
  connect to a BIND listener.

## Packages (RPM and DEB)

Ready-made packages for every target below are attached to each
[GitHub Release](https://github.com/sorrelfox/quinsock/releases/latest):

```sh
sudo dnf install ./quinsock-*.el9.x86_64.rpm         # Fedora, RHEL, Rocky, Alma
sudo apt install ./quinsock_*~deb13_amd64.deb        # Debian, Ubuntu
```

To build them yourself, `packaging/build.sh` builds each package inside a podman container of its target
distribution, so the binary links against that distribution's own glibc:

```sh
./packaging/build.sh                 # all targets
./packaging/build.sh fedora44 debian13
```

| Target | Distributions | Output |
|---|---|---|
| `fedora44` | Fedora 44 | `dist/fedora44/*.rpm` |
| `el9` | RHEL, Rocky and Alma 9 | `dist/el9/*.rpm` |
| `el10` | RHEL, Rocky and Alma 10 | `dist/el10/*.rpm` |
| `ubuntu2404` | Ubuntu 24.04 | `dist/ubuntu2404/*.deb` |
| `ubuntu2604` | Ubuntu 26.04 | `dist/ubuntu2604/*.deb` |
| `debian13` | Debian 13 | `dist/debian13/*.deb` |

**Package contents**

| Path | Notes |
|---|---|
| `/usr/bin/quinsock` | |
| `/etc/quinsock/config.toml` | Config file, never overwritten on upgrade. Listens on loopback only by default. |
| `/usr/lib/systemd/system/quinsock.service` | Hardened unit |
| `/usr/lib/sysusers.d/quinsock.conf` | Creates the `quinsock` system user |
| `/usr/share/doc/quinsock/` | Docs and example config |

The service is not enabled automatically:

```sh
sudoedit /etc/quinsock/config.toml
sudo systemctl enable --now quinsock
journalctl -u quinsock -f
```

To listen on a port below 1024, or to use `outbound.interface`, grant capabilities
with `systemctl edit quinsock`. The unit file explains how.

## Development

```sh
cargo test                                   # unit and integration tests, including QUIC end to end
cargo clippy --all-targets -- -D warnings
```

Work happens on the `dev` branch; send pull requests there. `main` holds released
code only. CI runs formatting, Clippy, the tests and a build with the minimum
supported Rust version (`rust-version` in `Cargo.toml`) on every push and pull
request to either branch. Every push to `main` also builds all packages.

To make a release:

1. On `dev`, bump `version` in `Cargo.toml`, run `cargo check` to update
   `Cargo.lock`, and add an entry to `packaging/deb/changelog`. That entry becomes
   the release notes.
2. Merge `dev` into `main`.
3. Tag the merge on `main` and push the tag:
   ```sh
   git tag -a v0.2.0 -m "quinsock 0.2.0" && git push origin v0.2.0
   ```
   The Packages workflow checks that the tag matches `Cargo.toml`, is on `main`
   and has a changelog entry. It then builds every package and publishes them as a
   GitHub Release with a `SHA256SUMS` file. Tags with a suffix, such as
   `v0.2.0-rc.1`, are published as pre-releases.

## License

MIT OR Apache-2.0.
