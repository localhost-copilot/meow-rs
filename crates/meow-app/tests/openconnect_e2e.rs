#![cfg(all(feature = "openconnect", feature = "listener-mixed"))]

#[path = "support/openconnect_gateway.rs"]
mod gateway;
#[path = "../../meow-netstack/tests/support/peer.rs"]
mod peer;

use gateway::Gateway;
use meow_common::Metadata;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

async fn socks(address: SocketAddr, command: u8, port: u16) -> (TcpStream, SocketAddr) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, command, 0, 1];
    request.extend_from_slice(&peer::ADDRESS.octets());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut response = [0; 10];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..4], &[5, 0, 0, 1]);
    let bound = SocketAddr::from((
        [response[4], response[5], response[6], response[7]],
        u16::from_be_bytes([response[8], response[9]]),
    ));
    (stream, bound)
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
