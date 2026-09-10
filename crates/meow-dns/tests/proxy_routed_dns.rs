//! Integration test for DNS-via-proxy (issue #67 phase 2, ADR-0012).
//!
//! Sets up a tiny in-process TCP "DNS server" that speaks RFC-7766
//! length-prefixed DNS over TCP and always answers `A example.com` →
//! `203.0.113.7`. Then plugs a mock [`Proxy`] adapter in front of it
//! and verifies that a `DnsClient::tcp(...).with_proxy(...)` query
//! routes through the proxy (the proxy records the destination it was
//! asked to dial; we assert it matches the configured DNS server).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use meow_common::{
    AdapterType, DelayHistory, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result as MeowResult,
};
use meow_dns::client::DnsClient;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const T: Duration = Duration::from_secs(5);

#[cfg(feature = "encrypted")]
#[tokio::test]
async fn encrypted_nameservers_send_tls_through_the_selected_proxy() {
    for is_https in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0; 5];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 22, "proxy must carry a TLS handshake");
            assert_eq!(header[1], 3);
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut hello = vec![0; length];
            stream.read_exact(&mut hello).await.unwrap();
            assert!(hello
                .windows(b"resolver.test".len())
                .any(|v| v == b"resolver.test"));
            // No trusted certificate: DNS must fail, never fall back to a
            // plaintext exchange or an unselected direct socket.
        });
        let dialed = Arc::new(Mutex::new(Vec::new()));
        let proxy: Arc<dyn Proxy> = Arc::new(MockProxy {
            name: "encrypted-dns".into(),
            dialed: Arc::clone(&dialed),
        });
        let client = if is_https {
            DnsClient::doh(addr, "resolver.test", "/dns-query")
        } else {
            DnsClient::dot(addr, "resolver.test")
        }
        .with_proxy(proxy);
        assert!(timeout(T, client.query("example.com", RecordType::A))
            .await
            .unwrap()
            .is_err());
        timeout(T, peer).await.unwrap().unwrap();
        assert_eq!(*dialed.lock(), vec![addr]);
    }
}

/// Start a stub DNS-over-TCP server that always answers `A example.com.` →
/// `203.0.113.7`. Returns the bound address.
async fn start_dns_tcp_stub() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                if sock.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut req = vec![0u8; len];
                if sock.read_exact(&mut req).await.is_err() {
                    return;
                }
                let Ok(req_msg) = Message::from_bytes(&req) else {
                    return;
                };

                let mut resp = Message::new(req_msg.id, MessageType::Response, OpCode::Query);
                resp.metadata.response_code = ResponseCode::NoError;
                resp.metadata.recursion_available = true;
                for q in &req_msg.queries {
                    resp.add_query(q.clone());
                    if q.query_type == RecordType::A {
                        let name: Name = "example.com.".parse().unwrap();
                        let rec = Record::from_rdata(
                            name,
                            60,
                            RData::A(A(Ipv4Addr::new(203, 0, 113, 7))),
                        );
                        resp.add_answer(rec);
                    }
                }

                let wire = resp.to_bytes().unwrap();
                let lenb = (wire.len() as u16).to_be_bytes();
                if sock.write_all(&lenb).await.is_err() {
                    return;
                }
                let _ = sock.write_all(&wire).await;
            });
        }
    });
    addr
}

/// Mock proxy adapter: records the destinations it was asked to dial,
/// then opens a normal TCP connection to the recorded address so the
/// caller (DnsClient) actually exchanges a real query. This proves the
/// DNS exchange went through the proxy, not through the global socket
/// factory.
struct MockProxy {
    name: String,
    dialed: Arc<Mutex<Vec<SocketAddr>>>,
}

#[async_trait]
impl ProxyAdapter for MockProxy {
    fn name(&self) -> &str {
        &self.name
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        false
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> MeowResult<Box<dyn ProxyConn>> {
        let ip = metadata.dst_ip.unwrap();
        let port = metadata.dst_port;
        let sa = SocketAddr::new(ip, port);
        self.dialed.lock().push(sa);
        let stream = TcpStream::connect(sa).await.unwrap();
        Ok(Box::new(stream))
    }
    async fn dial_udp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyPacketConn>> {
        unimplemented!("test mock has no UDP")
    }
    fn health(&self) -> &ProxyHealth {
        static H: std::sync::OnceLock<ProxyHealth> = std::sync::OnceLock::new();
        H.get_or_init(ProxyHealth::new)
    }
}

impl Proxy for MockProxy {
    fn alive(&self) -> bool {
        true
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        true
    }
    fn last_delay(&self) -> u16 {
        0
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        0
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        Vec::new()
    }
}

#[tokio::test]
async fn dns_client_routes_tcp_query_through_proxy() {
    let dns_addr = start_dns_tcp_stub().await;

    let dialed = Arc::new(Mutex::new(Vec::<SocketAddr>::new()));
    let proxy: Arc<dyn Proxy> = Arc::new(MockProxy {
        name: "PROXY-A".to_string(),
        dialed: Arc::clone(&dialed),
    });

    let client = DnsClient::tcp(dns_addr).with_proxy(proxy);
    let msg = timeout(T, client.query("example.com", RecordType::A))
        .await
        .expect("must not stall")
        .expect("query must succeed");

    let mut got: Option<IpAddr> = None;
    for ans in &msg.answers {
        if let RData::A(a) = &ans.data {
            got = Some(IpAddr::V4(a.0));
        }
    }
    assert_eq!(got, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));

    let dialed_snap = dialed.lock().clone();
    assert_eq!(
        dialed_snap,
        vec![dns_addr],
        "proxy must have been the dialer for the DNS exchange"
    );
}
