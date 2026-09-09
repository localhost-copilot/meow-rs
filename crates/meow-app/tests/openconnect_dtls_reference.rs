#![cfg(all(feature = "openconnect-dtls", unix))]

use base64::Engine;
use meow_openconnect::dtls::{Channel, Offer};
use meow_transport::tls::{export_keying_material, TlsConfig, TlsLayer};
use meow_transport::Transport;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::test]
#[ignore = "requires MEOW_REFERENCE_GATEWAY; build experiments/openconnect/reference-gateway"]
async fn reference_psk_and_injected_session_exchange_datagrams() {
    for mode in ["psk-app-id", "injected"] {
        tokio::time::timeout(Duration::from_secs(15), async {
            let directory = tempfile::tempdir().unwrap();
            let ca = directory.path().join("ca.pem");
            let executable =
                std::env::var_os("MEOW_REFERENCE_GATEWAY").expect("set MEOW_REFERENCE_GATEWAY");
            let mut server = tokio::process::Command::new(executable)
                .arg(mode)
                .arg(&ca)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut lines = BufReader::new(server.stdout.take().unwrap()).lines();
            let address: std::net::SocketAddr =
                lines.next_line().await.unwrap().unwrap().parse().unwrap();
            let name = lines.next_line().await.unwrap().unwrap();
            let pem = std::fs::read_to_string(ca).unwrap();
            let encoded: String = pem
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            let certificate = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap();
            let layer = TlsLayer::new(&TlsConfig {
                additional_roots: vec![certificate],
                ..TlsConfig::new(name.clone())
            })
            .unwrap();
            let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
            let mut tls = layer.connect(Box::new(tcp)).await.unwrap();
            let offer = Offer::new(|key| {
                export_keying_material(tls.as_mut(), key, "EXPORTER-openconnect-psk", None)
                    .map_err(std::io::Error::other)
            })
            .unwrap();
            let tunnel = meow_openconnect::connect_with_dtls(
                tls,
                &meow_openconnect::Options {
                    authority: name,
                    cookie: "phase0-test-cookie".into(),
                    mtu: 1280,
                    ipv6: false,
                },
                Some(&offer),
            )
            .await
            .unwrap();
            let parameters = tunnel.dtls.as_ref().unwrap().as_ref().unwrap();
            let mut channel = Channel::connect(
                (address.ip(), parameters.port).into(),
                parameters.key.clone(),
                parameters.mtu,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            for size in [20usize, 1200, 37] {
                let mut packet = vec![0; size + 1];
                packet[1] = 0x45;
                packet[3..5].copy_from_slice(&(size as u16).to_be_bytes());
                channel.send(&packet).await.unwrap();
                assert_eq!(channel.recv().await.unwrap(), packet);
            }
            eprintln!(
                "reference {mode}: {} bidirectional datagrams passed",
                channel.cipher()
            );
            drop(channel);
            drop(tunnel);
            server.kill().await.unwrap();
            server.wait().await.unwrap();
        })
        .await
        .unwrap();
    }
}
