//! End-to-end QUIC through UDP ASSOCIATE: quinn client -> local forwarder -> proxy
//! relay -> quinn server.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use quinn::rustls::RootCertStore;
use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use quinsock::client::{UdpAssociation, forward_udp};
use quinsock::protocol::Address;
use tokio::net::UdpSocket;

#[tokio::test]
async fn quic_streams_through_the_relay() {
    let proxy = spawn(config()).await;

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key).unwrap();
    let quic_server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let quic_addr = quic_server.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = quic_server.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    tokio::spawn(async move {
                        let data = recv.read_to_end(4 << 20).await.unwrap();
                        send.write_all(&data).await.unwrap();
                        send.finish().unwrap();
                    });
                }
            });
        }
    });

    let assoc = UdpAssociation::open(proxy.addr, None).await.unwrap();
    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let forwarder_addr = local.local_addr().unwrap();
    tokio::spawn(forward_udp(assoc, local, Address::Ip(quic_addr)));

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_millis(500)));
    transport.max_idle_timeout(Some(Duration::from_secs(3).try_into().unwrap()));
    client_config.transport_config(Arc::new(transport));
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);

    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(forwarder_addr, "localhost").unwrap(),
    )
    .await
    .expect("QUIC handshake through the proxy")
    .unwrap();

    // 1 MiB over four concurrent streams.
    let streams: Vec<_> = (0..4usize)
        .map(|i| {
            let conn = conn.clone();
            tokio::spawn(async move {
                let payload: Vec<u8> = (0..256 * 1024).map(|j| ((i * 7 + j) % 251) as u8).collect();
                let (mut send, mut recv) = conn.open_bi().await.unwrap();
                send.write_all(&payload).await.unwrap();
                send.finish().unwrap();
                let echoed = recv.read_to_end(1 << 20).await.unwrap();
                assert!(echoed == payload, "stream {i} corrupted");
            })
        })
        .collect();
    for s in streams {
        tokio::time::timeout(Duration::from_secs(20), s)
            .await
            .expect("streams finish")
            .unwrap();
    }

    // Idle longer than the QUIC idle timeout; keep-alives must traverse the relay.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"still alive").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(64).await.unwrap(), b"still alive");
    conn.close(0u32.into(), b"done");
}
