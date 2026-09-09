#![cfg(all(feature = "openconnect", feature = "listener-mixed"))]

#[cfg(all(feature = "openconnect-dtls", unix))]
#[path = "support/openconnect_benchmark.rs"]
mod benchmark;
#[path = "support/openconnect_gateway.rs"]
mod gateway;
#[path = "../../meow-netstack/tests/support/peer.rs"]
mod peer;
#[path = "support/udp_fault_relay.rs"]
mod udp_fault_relay;

use gateway::Gateway;
use meow_common::Metadata;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[cfg(all(feature = "openconnect-dtls", unix))]
#[tokio::test]
async fn dtls_blackhole_keeps_auto_cstp_usable_during_handshake() {
    let gateway = Gateway::start(false).await;
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    gateway.network.send_replace(Some(format!(
        "X-CSTP-Address: 192.0.2.2\r\nX-CSTP-MTU: 1280\r\nX-CSTP-DPD: 1\r\nX-DTLS-CipherSuite: PSK-NEGOTIATE\r\nX-DTLS-App-ID: {}\r\nX-DTLS-Port: {}\r\n",
        "42".repeat(32), sink.local_addr().unwrap().port(),
    )));
    let config = meow_config::load_config_from_str(
        &gateway
            .yaml("fixture-cookie")
            .replace("dtls-mode: off", "dtls-mode: auto"),
    )
    .await
    .unwrap();
    let proxy = config.proxies.get("vpn").unwrap();
    let target = Metadata {
        dst_ip: Some(peer::ADDRESS.into()),
        dst_port: 8080,
        ..Default::default()
    };
    let started = tokio::time::Instant::now();
    let mut tcp = tokio::time::timeout(Duration::from_secs(2), proxy.dial_tcp(&target))
        .await
        .expect("auto must not wait for the five-second DTLS handshake")
        .unwrap();
    let mut hello = [0; 4096];
    tokio::time::timeout(Duration::from_secs(2), sink.recv(&mut hello))
        .await
        .unwrap()
        .unwrap();
    for deadline in [started, started + Duration::from_secs(6)] {
        tokio::time::sleep_until(deadline).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            tcp.write_all(b"still alive").await.unwrap();
            let mut answer = [0; 11];
            tcp.read_exact(&mut answer).await.unwrap();
            assert_eq!(&answer, b"still alive");
        })
        .await
        .unwrap();
    }
    assert_eq!(
        *gateway.attempts.borrow(),
        1,
        "CSTP heartbeats must keep the same generation alive"
    );
}

#[cfg(all(feature = "openconnect-dtls", unix))]
#[tokio::test]
async fn required_dtls_is_not_satisfied_by_a_cstp_only_gateway() {
    let gateway = Gateway::start(false).await;
    let config = meow_config::load_config_from_str(
        &gateway
            .yaml("fixture-cookie")
            .replace("dtls-mode: off", "dtls-mode: require"),
    )
    .await
    .unwrap();
    let proxy = config.proxies.get("vpn").unwrap();
    let target = Metadata {
        dst_ip: Some(peer::ADDRESS.into()),
        dst_port: 8080,
        ..Default::default()
    };
    for _ in 0..2 {
        let result = tokio::time::timeout(Duration::from_secs(2), proxy.dial_tcp(&target))
            .await
            .unwrap();
        assert!(result.err().unwrap().to_string().contains("required DTLS"));
    }
    assert_eq!(*gateway.attempts.borrow(), 1);
}

#[tokio::test]
#[ignore = "requires Docker image meow-openconnect-ocserv:test; see docs/openconnect.md"]
async fn independent_ocserv_password_dns_ipv4_ipv6_tcp_udp() {
    ocserv_roundtrip("off", false, false).await;
}

#[cfg(all(feature = "openconnect-dtls", unix))]
#[tokio::test]
#[ignore = "requires Docker image meow-openconnect-ocserv:test and OpenSSL 3"]
async fn independent_ocserv_dtls_password_dns_ipv4_ipv6_tcp_udp() {
    ocserv_roundtrip("require", false, false).await;
}

#[cfg(all(feature = "openconnect-dtls", unix))]
#[tokio::test]
#[ignore = "requires Docker image meow-openconnect-ocserv:test and OpenSSL 3"]
async fn independent_ocserv_auto_preserves_sockets_across_udp_block_and_recovery() {
    ocserv_roundtrip("auto", true, false).await;
}

#[cfg(all(feature = "openconnect-dtls", unix))]
#[tokio::test]
#[ignore = "requires Docker image meow-openconnect-ocserv:test and OpenSSL 3"]
async fn independent_ocserv_require_fails_sockets_when_udp_is_blocked() {
    ocserv_roundtrip("require", true, false).await;
}

#[cfg(all(feature = "openconnect-dtls", unix))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real ocserv Docker benchmark; run with --release and --nocapture"]
#[allow(clippy::assertions_on_constants)] // Compile in debug test suites, refuse debug measurements.
async fn benchmark_real_ocserv_tls_dtls() {
    assert!(!cfg!(debug_assertions), "benchmark requires --release");
    for mode in ["off", "require"] {
        ocserv_roundtrip(mode, false, true).await;
    }
}

async fn ocserv_roundtrip(mode: &str, fault: bool, measure: bool) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("meow_proxy=debug,meow_openconnect=debug")
        .try_init();
    struct Container(String);
    impl Drop for Container {
        fn drop(&mut self) {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", &self.0])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    tokio::time::timeout(Duration::from_secs(if measure { 300 } else { 90 }), async {
        let fixture = tempfile::tempdir().unwrap();
        let mount = format!("{}:/fixture", fixture.path().display());
        let relay = udp_fault_relay::Relay::new().await;
        // Benchmarks bypass the fault relay so its copying and watch updates
        // do not become a DTLS-only performance cost.
        let udp_port = if measure { relay.backend.port() } else { relay.address.port() };
        let udp_mapping = format!("127.0.0.1:{}:{udp_port}/udp", relay.backend.port());
        let udp_env = format!("OCSERV_UDP_PORT={udp_port}");
        let dpd_env = if fault { "OCSERV_DPD=1" } else { "OCSERV_DPD=30" };
        let compatibility_env = if measure { "OCSERV_CISCO_COMPAT=false" } else { "OCSERV_CISCO_COMPAT=true" };
        let output = tokio::process::Command::new("docker").args([
            "run", "--rm", "-d", "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
            "--sysctl", "net.ipv6.conf.all.disable_ipv6=0", "-p", "127.0.0.1::443", "-v", &mount,
            "-p", &udp_mapping, "-e", &udp_env, "-e", dpd_env, "-e", compatibility_env,
            "meow-openconnect-ocserv:test",
        ]).output().await.unwrap();
        assert!(output.status.success(), "docker run failed: {}", String::from_utf8_lossy(&output.stderr));
        let container = Container(String::from_utf8(output.stdout).unwrap().trim().to_owned());
        let output = tokio::process::Command::new("docker").args(["port", &container.0, "443/tcp"]).output().await.unwrap();
        assert!(output.status.success());
        let address: SocketAddr = String::from_utf8(output.stdout).unwrap().trim().parse().unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                // Docker's published port can accept before ocserv (or even its
                // certificate) exists. Wait for the server's actual readiness.
                let logs = tokio::process::Command::new("docker").args(["logs", &container.0]).output().await.unwrap();
                if String::from_utf8_lossy(&logs.stderr).contains("listening (TCP)") { break; }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await.expect("ocserv did not become ready");
        let yaml = format!("dns:\n  enable: false\nproxies:\n  - name: vpn\n    type: openconnect\n    server: 127.0.0.1\n    port: {}\n    server-name: vpn.test\n    ca: '{}'\n    username: fixture-user\n    password: fixture-password\n    authgroup: engineering\n    ipv6-disabled: false\n    remote-dns-resolve: true\n", address.port(), fixture.path().join("ca.pem").display());
        let yaml = format!("{yaml}    dtls-mode: {mode}\n    mtu: 1400\n    compression: off\nrules:\n  - MATCH,vpn\n");
        #[cfg(all(feature = "openconnect-dtls", unix))]
        if measure {
            benchmark::run(&yaml, mode, &container.0).await;
            return;
        }
        let config = meow_config::load_config_from_str(&yaml).await.unwrap();
        let proxy = config.proxies.get("vpn").expect("ocserv fixture configuration must produce a VPN outbound");
        for host in ["service.vpn.test", "ipv6.vpn.test"] {
            let mut target = Metadata { host: host.into(), dst_port: 8080, ..Default::default() };
            let result = proxy.dial_tcp(&target).await;
            if result.is_err() {
                let logs = tokio::process::Command::new("docker").args(["logs", &container.0]).output().await.unwrap();
                eprintln!("ocserv fixture: {}", String::from_utf8_lossy(&logs.stderr));
            }
            let mut tcp = result.unwrap();
            tcp.write_all(b"independent ocserv").await.unwrap();
            let mut received = [0; 18]; tcp.read_exact(&mut received).await.unwrap(); assert_eq!(&received, b"independent ocserv");
            target.dst_port = 5353;
            let destination = proxy.resolve_udp_destination(&target).await.unwrap().unwrap().address;
            assert_eq!(destination.is_ipv6(), host == "ipv6.vpn.test");
            target.dst_ip = Some(destination.ip());
            let udp = proxy.dial_udp(&target).await.unwrap();
            udp.write_packet(b"ocserv UDP", &destination).await.unwrap();
            let mut received = [0; 32]; let (n, source) = udp.read_packet(&mut received).await.unwrap();
            assert_eq!(source, destination); assert_eq!(&received[..n], b"ocserv UDP");
            if fault && host == "service.vpn.test" {
                fault_roundtrip(tcp.as_mut(), udp.as_ref(), destination, mode, &relay).await;
                if mode == "require" { break; }
            }
        }
        if mode == "off" { assert_eq!(relay.stats.borrow().client_datagrams, 0); }
    }).await.unwrap();
}

async fn fault_roundtrip(
    tcp: &mut dyn meow_common::ProxyConn,
    udp: &dyn meow_common::ProxyPacketConn,
    destination: SocketAddr,
    mode: &str,
    relay: &udp_fault_relay::Relay,
) {
    use std::sync::atomic::Ordering;
    let mut stats = relay.stats.clone();
    tokio::time::timeout(
        Duration::from_secs(8),
        stats.wait_for(|s| s.client_application > 0 && s.server_application > 0),
    )
    .await
    .unwrap()
    .unwrap();
    relay.blocked.store(true, Ordering::SeqCst);
    let dropped = stats.borrow().dropped_client;
    udp.write_packet(b"lost-once", &destination).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        stats.wait_for(|s| s.dropped_client > dropped),
    )
    .await
    .unwrap()
    .unwrap();
    if mode == "require" {
        let mut received = [0; 32];
        let result = tokio::time::timeout(Duration::from_secs(8), tcp.read(&mut received))
            .await
            .unwrap();
        assert!(
            result.is_err(),
            "required DTLS must fail the old TCP socket"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(2), udp.read_packet(&mut received))
                .await
                .unwrap()
                .is_err()
        );
        return;
    }
    // Explicit new probes have distinct contents. A lost business datagram is
    // never retransmitted by this test, so its later appearance detects replay.
    tokio::time::timeout(Duration::from_secs(12), async {
        for sequence in 0u32.. {
            let probe = sequence.to_be_bytes();
            udp.write_packet(&probe, &destination).await.unwrap();
            let mut received = [0; 64];
            if let Ok(result) =
                tokio::time::timeout(Duration::from_millis(250), udp.read_packet(&mut received))
                    .await
            {
                let (n, source) = result.unwrap();
                assert_eq!(source, destination);
                assert_ne!(
                    &received[..n],
                    b"lost-once",
                    "ambiguous datagram was replayed"
                );
                assert_eq!(&received[..n], &probe);
                break;
            }
        }
    })
    .await
    .expect("auto did not fall back to CSTP");
    tcp.write_all(b"TLS fallback").await.unwrap();
    let mut response = [0; 12];
    tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"TLS fallback");
    let previous = *stats.borrow();
    relay.blocked.store(false, Ordering::SeqCst);
    tokio::time::timeout(
        Duration::from_secs(40),
        stats.wait_for(|s| {
            s.client_application > previous.client_application
                && s.server_application > previous.server_application
        }),
    )
    .await
    .expect("DTLS did not recover")
    .unwrap();
    tcp.write_all(b"DTLS recovered").await.unwrap();
    let mut response = [0; 14];
    tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"DTLS recovered");
    udp.write_packet(b"recovered UDP", &destination)
        .await
        .unwrap();
    let mut response = [0; 64];
    let (n, source) = tokio::time::timeout(Duration::from_secs(5), udp.read_packet(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, destination);
    assert_eq!(&response[..n], b"recovered UDP");
}

async fn socks(address: SocketAddr, command: u8, port: u16) -> (TcpStream, SocketAddr) {
    socks_target(
        address,
        command,
        SocketAddr::new(peer::ADDRESS.into(), port),
    )
    .await
}

async fn socks_target(
    address: SocketAddr,
    command: u8,
    target: SocketAddr,
) -> (TcpStream, SocketAddr) {
    let mut request = vec![5, command, 0];
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    socks_request(address, &request).await
}

async fn socks_request(address: SocketAddr, request: &[u8]) -> (TcpStream, SocketAddr) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    stream.write_all(request).await.unwrap();
    let mut response = [0; 10];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..4], &[5, 0, 0, 1]);
    let bound = SocketAddr::from((
        [response[4], response[5], response[6], response[7]],
        u16::from_be_bytes([response[8], response[9]]),
    ));
    (stream, bound)
}

#[tokio::test]
async fn vpn_dns_handles_internal_domains_udp_tcp_fallback_and_group_routing() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let gateway = Gateway::start(false).await;
        gateway.network.send_replace(Some("X-CSTP-Address: 192.0.2.2\r\nX-CSTP-Address-IP6: 2001:db8::2/64\r\nX-CSTP-MTU: 1280\r\nX-CSTP-DNS: 192.0.2.1\r\n".into()));
        let yaml = gateway.yaml("fixture-cookie")
            .replace("ipv6: false", "ipv6: true")
            .replace("    dtls-mode: off", "    dtls-mode: off\n    ipv6-disabled: false\n    remote-dns-resolve: true")
            .replace("rules:\n  - MATCH,vpn", "proxy-groups:\n  - name: selected-vpn\n    type: select\n    proxies: [vpn, REJECT]\nrules:\n  - IP-CIDR,192.0.2.0/24,REJECT,no-resolve\n  - MATCH,selected-vpn");
        let config = meow_config::load_config_from_str(&yaml).await.unwrap();
        let tunnel = meow_tunnel::Tunnel::new(Arc::clone(&config.dns.resolver));
        let selection = Arc::clone(config.proxies.get("selected-vpn").unwrap());
        tunnel.update_routing(config.proxies, config.rules);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mixed = meow_listener::MixedListener::new(tunnel.clone(), address, "vpn-dns".into());
        let task = tokio::spawn(async move { mixed.run_on(listener).await.unwrap(); });
        for name in ["service.vpn.test", "truncated.vpn.test", "ipv6.vpn.test"] {
            let mut request = vec![5, 1, 0, 3, name.len() as u8];
            request.extend_from_slice(name.as_bytes()); request.extend_from_slice(&peer::TCP_PORT.to_be_bytes());
            let (mut tcp, _) = socks_request(address, &request).await;
            tcp.write_all(b"VPN DNS").await.unwrap();
            let mut reply = [0; 7]; tcp.read_exact(&mut reply).await.unwrap(); assert_eq!(&reply, b"VPN DNS");
        }
        let (control, relay) = socks_target(address, 3, "0.0.0.0:0".parse().unwrap()).await;
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let name = "service.vpn.test";
        let mut packet = vec![0, 0, 0, 3, name.len() as u8];
        packet.extend_from_slice(name.as_bytes()); packet.extend_from_slice(&peer::UDP_PORT.to_be_bytes()); packet.extend_from_slice(b"internal UDP");
        udp.send_to(&packet, relay).await.unwrap();
        let mut response = [0; 1280]; let (n, from) = udp.recv_from(&mut response).await.unwrap();
        assert_eq!(from, relay); assert_eq!(&response[4..8], peer::ADDRESS.octets()); assert_eq!(&response[10..n], b"internal UDP");
        assert_eq!(*gateway.attempts.borrow(), 1);
        let mut target = Metadata { host: "service.vpn.test".into(), dst_port: peer::UDP_PORT, network: meow_common::Network::Udp, ..Default::default() };
        let route = tunnel.inner().resolve_udp_host(&mut target).await.unwrap().unwrap();
        selection.selection().unwrap().set("REJECT").await.unwrap();
        // Both the selection and an IP rule now disagree with the original route.
        // Its DNS answer must stay attached to the VPN that resolved it.
        let conn = route.0.dial_udp(&target).await.unwrap();
        conn.write_packet(b"pinned", &SocketAddr::new(target.dst_ip.unwrap(), target.dst_port)).await.unwrap();
        let mut reply = [0; 16]; let (n, _) = conn.read_packet(&mut reply).await.unwrap(); assert_eq!(&reply[..n], b"pinned");
        drop(control); task.abort(); let _ = task.await;
    }).await.unwrap();
}

#[tokio::test]
async fn explicit_vpn_dns_overrides_pushed_dns_and_missing_dns_fails_closed() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let gateway = Gateway::start(false).await;
        let yaml = gateway.yaml("fixture-cookie").replace(
            "    dtls-mode: off",
            "    dtls-mode: off\n    remote-dns-resolve: true",
        );
        let config = meow_config::load_config_from_str(&yaml).await.unwrap();
        let target = Metadata {
            host: "localhost".into(),
            ..metadata()
        };
        let error = config
            .proxies
            .get("vpn")
            .unwrap()
            .dial_tcp(&target)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("no usable VPN DNS"));
        // Pushed server is unreachable; the explicit server must take precedence.
        gateway.network.send_replace(Some(
            "X-CSTP-Address: 192.0.2.2\r\nX-CSTP-MTU: 1280\r\nX-CSTP-DNS: 192.0.2.99\r\n".into(),
        ));
        let config = meow_config::load_config_from_str(&yaml.replace(
            "    remote-dns-resolve: true",
            "    remote-dns-resolve: true\n    dns: [192.0.2.1]",
        ))
        .await
        .unwrap();
        let proxy = config.proxies.get("vpn").unwrap();
        // Preserve and use the original hostname even if routing supplied a different IP.
        let mut target = Metadata {
            host: "service.vpn.test".into(),
            dst_ip: Some("192.0.2.99".parse().unwrap()),
            ..metadata()
        };
        let mut tcp = proxy.dial_tcp(&target).await.unwrap();
        tcp.write_all(b"dns").await.unwrap();
        tcp.read_exact(&mut [0; 3]).await.unwrap();
        target.host = "missing.vpn.test".into();
        assert!(proxy
            .dial_tcp(&target)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("does not exist"));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ipv6_socks_tcp_and_udp_share_the_dual_stack_session() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let gateway = Gateway::start(false).await;
        let yaml = gateway
            .yaml("fixture-cookie")
            .replace("ipv6: false", "ipv6: true")
            .replace(
                "    dtls-mode: off",
                "    dtls-mode: off\n    ipv6-disabled: false",
            );
        let config = meow_config::load_config_from_str(&yaml).await.unwrap();
        let tunnel = meow_tunnel::Tunnel::new(Arc::clone(&config.dns.resolver));
        tunnel.update_routing(config.proxies, config.rules);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mixed = meow_listener::MixedListener::new(tunnel, address, "phase-two".into());
        let task = tokio::spawn(async move {
            mixed.run_on(listener).await.unwrap();
        });
        let (mut tcp, _) = socks_target(
            address,
            1,
            SocketAddr::new(peer::ADDRESS6.into(), peer::TCP_PORT),
        )
        .await;
        tcp.write_all(b"IPv6 through CSTP").await.unwrap();
        let mut reply = [0; 17];
        tcp.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"IPv6 through CSTP");
        let (control, relay) = socks_target(address, 3, "0.0.0.0:0".parse().unwrap()).await;
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = vec![0, 0, 0, 4];
        packet.extend_from_slice(&peer::ADDRESS6.octets());
        packet.extend_from_slice(&peer::UDP_PORT.to_be_bytes());
        packet.extend_from_slice(b"IPv6 UDP");
        udp.send_to(&packet, relay).await.unwrap();
        let mut response = [0; 1280];
        let (n, from) = udp.recv_from(&mut response).await.unwrap();
        assert_eq!(from, relay);
        assert_eq!(&response[..n], packet);
        assert_eq!(*gateway.attempts.borrow(), 1);
        drop((tcp, control));
        task.abort();
        let _ = task.await;
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yaml_to_mixed_listener_to_cstp_gateway_to_tcp_udp_service() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let gateway = Gateway::start(false).await;
        let config = meow_config::load_config_from_str(&gateway.yaml("fixture-cookie"))
            .await
            .unwrap();
        assert_eq!(
            *gateway.attempts.borrow(),
            0,
            "configuration must not open a VPN session"
        );
        let tunnel = meow_tunnel::Tunnel::new(Arc::clone(&config.dns.resolver));
        tunnel.update_routing(config.proxies, config.rules);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mixed = meow_listener::MixedListener::new(tunnel, address, "phase-one".into());
        let task = tokio::spawn(async move {
            mixed.run_on(listener).await.unwrap();
        });
        let mut clients = tokio::task::JoinSet::new();
        for seed in 0..8 {
            clients.spawn(async move {
                let (tcp, _) = socks(address, 1, peer::TCP_PORT).await;
                let (mut reader, mut writer) = tokio::io::split(tcp);
                let payload: Vec<u8> = (0..131072).map(|n| ((n + seed) % 251) as u8).collect();
                let write = async {
                    writer.write_all(&payload).await.unwrap();
                    writer.shutdown().await.unwrap();
                };
                let read = async {
                    let mut response = Vec::new();
                    reader.read_to_end(&mut response).await.unwrap();
                    assert_eq!(response, payload);
                };
                tokio::join!(write, read);
            });
        }
        while let Some(result) = clients.join_next().await {
            result.unwrap();
        }
        // UDP ASSOCIATE must advertise the actual client endpoint, not the target.
        let mut control = TcpStream::connect(address).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        control.read_exact(&mut [0; 2]).await.unwrap();
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut bound = [0; 10];
        control.read_exact(&mut bound).await.unwrap();
        assert_eq!(&bound[..4], &[5, 0, 0, 1]);
        let relay = SocketAddr::from((
            [bound[4], bound[5], bound[6], bound[7]],
            u16::from_be_bytes([bound[8], bound[9]]),
        ));
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for size in [1, 1200, 17] {
            let mut packet = vec![0, 0, 0, 1];
            packet.extend_from_slice(&peer::ADDRESS.octets());
            packet.extend_from_slice(&peer::UDP_PORT.to_be_bytes());
            packet.extend(vec![42; size]);
            udp.send_to(&packet, relay).await.unwrap();
            let mut response = [0; 1500];
            let (n, from) = udp.recv_from(&mut response).await.unwrap();
            assert_eq!(from, relay);
            assert_eq!(&response[..n], packet);
        }
        assert_eq!(
            *gateway.attempts.borrow(),
            1,
            "all TCP/UDP flows must share one CSTP session"
        );
        drop(control);
        task.abort();
        let _ = task.await;
    })
    .await
    .unwrap();
}

fn metadata() -> Metadata {
    Metadata {
        dst_ip: Some(peer::ADDRESS.into()),
        dst_port: peer::TCP_PORT,
        ..Default::default()
    }
}

#[tokio::test]
async fn reconnect_rebuilds_addresses_dns_and_mtu_without_reviving_old_sockets() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut gateway = Gateway::start(false).await;
        gateway.network.send_replace(Some("X-CSTP-Address: 192.0.2.2\r\nX-CSTP-MTU: 1280\r\nX-CSTP-DNS: 192.0.2.1\r\n".into()));
        let yaml = gateway.yaml("fixture-cookie")
            .replace("    cookie: fixture-cookie", "    username: fixture-user\n    password: fixture-password\n    authgroup: Engineering")
            .replace("    dtls-mode: off", "    dtls-mode: off\n    ipv6-disabled: false\n    remote-dns-resolve: true");
        let config = meow_config::load_config_from_str(&yaml).await.unwrap();
        let proxy = Arc::clone(config.proxies.get("vpn").unwrap()); drop(config);
        let target = Metadata { host: "service.vpn.test".into(), ..metadata() };
        let mut old_tcp = proxy.dial_tcp(&target).await.unwrap();
        let old_udp = proxy.dial_udp(&metadata()).await.unwrap();
        old_tcp.write_all(b"old").await.unwrap(); old_tcp.read_exact(&mut [0; 3]).await.unwrap();
        let udp_target = SocketAddr::new(peer::ADDRESS.into(), peer::UDP_PORT);
        old_udp.write_packet(b"old", &udp_target).await.unwrap(); old_udp.read_packet(&mut [0; 8]).await.unwrap();
        assert!(old_udp.write_packet(&[0; 1253], &udp_target).await.is_err());
        gateway.gate.acquire_many(gateway.gate.available_permits() as u32).await.unwrap().forget();
        gateway.network.send_replace(Some("X-CSTP-Address: 192.0.2.3\r\nX-CSTP-Address-IP6: 2001:db8::3/64\r\nX-CSTP-MTU: 1400\r\nX-CSTP-DNS: 2001:db8::1\r\n".into()));
        let mut packets = gateway.packets.subscribe();
        gateway.disconnect.send_modify(|n| *n += 1);
        assert!(old_tcp.read(&mut [0; 1]).await.is_err());
        assert!(old_udp.read_packet(&mut [0; 1]).await.is_err());
        // The adapter reconnects even before another application dial arrives.
        gateway.attempts.wait_for(|n| *n == 2).await.unwrap();
        let cancelled_proxy = Arc::clone(&proxy);
        let cancelled = tokio::spawn(async move { cancelled_proxy.dial_tcp(&metadata()).await });
        tokio::task::yield_now().await; cancelled.abort(); let _ = cancelled.await;
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..7 {
            let proxy = Arc::clone(&proxy); let target = target.clone();
            tasks.spawn(async move {
                let mut tcp = proxy.dial_tcp(&target).await.unwrap();
                tcp.write_all(b"new").await.unwrap(); let mut reply = [0; 3]; tcp.read_exact(&mut reply).await.unwrap(); assert_eq!(&reply, b"new");
            });
        }
        gateway.gate.add_permits(1);
        while let Some(result) = tasks.join_next().await { result.unwrap(); }
        assert_eq!(*gateway.attempts.borrow(), 2);
        assert!(old_tcp.write_all(b"must not cross generations").await.is_err());
        assert!(old_udp.write_packet(b"must not cross generations", &udp_target).await.is_err());
        let new_udp = proxy.dial_udp(&metadata()).await.unwrap();
        assert_eq!(new_udp.local_addr().unwrap().ip(), "192.0.2.3".parse::<std::net::IpAddr>().unwrap());
        new_udp.write_packet(&[0; 1253], &udp_target).await.unwrap();
        let mut new_dns_seen = false;
        while let Ok((generation, packet)) = packets.try_recv() {
            if generation != 2 { continue; }
            if packet[0] >> 4 == 4 { assert_eq!(&packet[12..16], &[192, 0, 2, 3]); }
            else {
                assert_eq!(&packet[8..24], &"2001:db8::3".parse::<std::net::Ipv6Addr>().unwrap().octets());
                if packet[6] == 17 && packet[42..44] == [0, 53] { new_dns_seen = true; }
            }
        }
        assert!(new_dns_seen, "new generation must discard the DNS cache and use its newly pushed server");
        drop((old_tcp, old_udp, new_udp, proxy));
        gateway.closed.wait_for(|n| *n == 2).await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn transient_failures_have_bounded_retry_and_terminal_result_is_shared() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let gateway = Gateway::start(false).await;
        gateway.status.send_replace(503);
        let config = meow_config::load_config_from_str(&gateway.yaml("fixture-cookie"))
            .await
            .unwrap();
        let proxy = config.proxies.get("vpn").unwrap();
        let target = metadata();
        let (first, second) = tokio::join!(proxy.dial_tcp(&target), proxy.dial_tcp(&target));
        assert!(first.is_err() && second.is_err());
        assert_eq!(*gateway.attempts.borrow(), 5);
        assert!(proxy.dial_tcp(&metadata()).await.is_err());
        assert_eq!(*gateway.attempts.borrow(), 5);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropping_adapter_during_initialization_releases_the_transport() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut gateway = Gateway::start(true).await;
        let config = meow_config::load_config_from_str(&gateway.yaml("fixture-cookie"))
            .await
            .unwrap();
        let proxy = Arc::clone(config.proxies.get("vpn").unwrap());
        drop(config);
        let waiting = tokio::spawn(async move { proxy.dial_tcp(&metadata()).await });
        gateway.attempts.wait_for(|n| *n == 1).await.unwrap();
        waiting.abort();
        let _ = waiting.await;
        gateway.gate.add_permits(1);
        gateway.closed.wait_for(|n| *n == 1).await.unwrap();
        assert_eq!(*gateway.attempts.borrow(), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn password_authentication_and_group_selection_share_one_initialization() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let gateway = Gateway::start(false).await;
        let yaml = gateway.yaml("fixture-cookie").replace("    cookie: fixture-cookie", "    username: fixture-user\n    password: fixture-password\n    authgroup: Engineering");
        let config = meow_config::load_config_from_str(&yaml).await.unwrap();
        let proxy = Arc::clone(config.proxies.get("vpn").unwrap());
        assert_eq!(*gateway.attempts.borrow(), 0);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let proxy = Arc::clone(&proxy);
            tasks.spawn(async move {
                let mut tcp = proxy.dial_tcp(&metadata()).await.unwrap();
                tcp.write_all(b"authenticated").await.unwrap();
                let mut reply = [0; 13]; tcp.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"authenticated");
            });
        }
        while let Some(result) = tasks.join_next().await { result.unwrap(); }
        assert_eq!(*gateway.attempts.borrow(), 1);
        let bad = meow_config::load_config_from_str(&yaml.replace("fixture-password", "bad-password")).await.unwrap();
        for _ in 0..3 {
            let error = bad.proxies.get("vpn").unwrap().dial_tcp(&metadata()).await.err().unwrap();
            assert!(!error.to_string().contains("bad-password"));
        }
        assert_eq!(*gateway.attempts.borrow(), 2, "authentication rejection is not retried");
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_config_validation_and_real_app_process_route_through_vpn() {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    tokio::time::timeout(Duration::from_secs(15), async {
        let gateway = Gateway::start(false).await;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("openconnect.yml");
        let yaml = format!("{}\nlisteners:\n  - name: phase-one\n    type: mixed\n    listen: 127.0.0.1\n    port: 0\n", gateway.yaml("fixture-cookie"));
        std::fs::write(&path, yaml).unwrap();
        let validation = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"))
            .arg("-f").arg(&path).arg("-t").current_dir(directory.path()).kill_on_drop(true).output().await.unwrap();
        assert!(validation.status.success(), "config check failed: {}", String::from_utf8_lossy(&validation.stderr));
        assert_eq!(*gateway.attempts.borrow(), 0);
        let mut process = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"))
            .arg("-f").arg(&path).current_dir(directory.path()).env("RUST_LOG", "info")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true).spawn().unwrap();
        let mut lines = BufReader::new(process.stdout.take().unwrap()).lines();
        let address = loop {
            let line = lines.next_line().await.unwrap().expect("meow exited before listener readiness");
            if line.contains("Mixed listener 'phase-one'") {
                break line.split(" on ").nth(1).unwrap().split_whitespace().next().unwrap().parse().unwrap();
            }
        };
        let (mut tcp, _) = socks(address, 1, peer::TCP_PORT).await;
        tcp.write_all(b"real meow process").await.unwrap();
        let mut reply = [0;17]; tcp.read_exact(&mut reply).await.unwrap(); assert_eq!(&reply, b"real meow process");
        assert_eq!(*gateway.attempts.borrow(), 1);
        process.kill().await.unwrap(); process.wait().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn cancelled_first_waiter_does_not_cancel_shared_initialization_and_last_drop_closes() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut gateway = Gateway::start(true).await;
        let config = meow_config::load_config_from_str(&gateway.yaml("fixture-cookie"))
            .await
            .unwrap();
        let proxy = Arc::clone(config.proxies.get("vpn").unwrap());
        drop(config);
        let first_proxy = Arc::clone(&proxy);
        let first = tokio::spawn(async move { first_proxy.dial_tcp(&metadata()).await });
        gateway.attempts.wait_for(|n| *n == 1).await.unwrap();
        first.abort();
        let _ = first.await;
        gateway.gate.add_permits(1);
        let mut connection = proxy.dial_tcp(&metadata()).await.unwrap();
        drop(proxy);
        connection
            .write_all(b"still owned by the stream")
            .await
            .unwrap();
        let mut reply = [0; 25];
        connection.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"still owned by the stream");
        assert_eq!(*gateway.attempts.borrow(), 1);
        drop(connection);
        gateway.closed.wait_for(|n| *n == 1).await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejected_cookie_and_bad_certificate_fail_without_retry_storm() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let gateway = Gateway::start(false).await;
        let config = meow_config::load_config_from_str(&gateway.yaml("wrong-cookie"))
            .await
            .unwrap();
        let proxy = config.proxies.get("vpn").unwrap();
        for _ in 0..3 {
            let error = proxy.dial_tcp(&metadata()).await.err().unwrap();
            assert!(error.to_string().contains("cookie rejected"));
            assert!(!error.to_string().contains("wrong-cookie"));
        }
        assert_eq!(*gateway.attempts.borrow(), 1);
        let config = meow_config::load_config_from_str(
            &gateway
                .yaml("fixture-cookie")
                .replace("server-name: vpn.test", "server-name: wrong.test"),
        )
        .await
        .unwrap();
        assert!(config
            .proxies
            .get("vpn")
            .unwrap()
            .dial_tcp(&metadata())
            .await
            .is_err());
    })
    .await
    .unwrap();
}
