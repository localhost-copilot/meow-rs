#![cfg(all(feature = "dtls", unix))]

use meow_openconnect::dtls::{Channel, Key};
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
#[ignore = "requires DTLS_RESUMPTION_SERVER and DTLS_LEGACY_SERVER built from tests/openconnect/*.c"]
async fn independent_resumption_cbc_and_legacy_records() {
    use meow_openconnect::dtls::Cipher;
    use tokio::io::{AsyncBufReadExt, BufReader};
    let executable = std::env::var_os("DTLS_RESUMPTION_SERVER").expect("DTLS_RESUMPTION_SERVER");
    for (cipher, name, legacy, wrong_key) in [
        (Cipher::Aes128Gcm, "AES128-GCM-SHA256", false, false),
        (
            Cipher::EcdheRsaAes128Gcm,
            "ECDHE-RSA-AES128-GCM-SHA256",
            false,
            false,
        ),
        (Cipher::Aes128Sha, "AES128-SHA", false, false),
        (Cipher::LegacyAes128Sha, "AES128-SHA", true, false),
        (
            Cipher::LegacyDheAes256Sha,
            "DHE-RSA-AES256-SHA",
            true,
            false,
        ),
        (Cipher::Aes128Gcm, "AES128-GCM-SHA256", false, true),
        (Cipher::LegacyAes128Sha, "AES128-SHA", true, true),
    ] {
        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = reservation.local_addr().unwrap();
        drop(reservation);
        let executable = if legacy {
            std::env::var_os("DTLS_LEGACY_SERVER").expect("DTLS_LEGACY_SERVER")
        } else {
            executable.clone()
        };
        let mut server = tokio::process::Command::new(&executable)
            .args([
                peer.port().to_string(),
                name.into(),
                u8::from(legacy).to_string(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(server.stdout.take().unwrap())
            .read_line(&mut ready)
            .await
            .unwrap();
        assert_eq!(ready, "READY\n");
        let result = Channel::connect(
            peer,
            Key::Resume {
                secret: zeroize::Zeroizing::new([if wrong_key { 0x38 } else { 0x39 }; 48]),
                session_id: vec![0x42; 32],
                cipher,
            },
            1400,
            Duration::from_secs(3),
        )
        .await;
        if wrong_key {
            assert!(result.is_err(), "{name} accepted an unauthenticated key");
            let _ = server.kill().await;
            server.wait().await.unwrap();
            continue;
        }
        let mut channel = result.unwrap_or_else(|error| panic!("{name} legacy={legacy}: {error}"));
        assert_eq!(channel.cipher(), name);
        for size in [1, 1400, 39] {
            let payload = vec![0x53; size];
            channel.send(&payload).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(3), channel.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                payload
            );
        }
        server.kill().await.unwrap();
        server.wait().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the OpenSSL 3 command-line server"]
async fn independent_openssl_psk_datagrams() {
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = reservation.local_addr().unwrap();
    drop(reservation);
    let executable = std::env::var_os("OPENSSL_BIN").unwrap_or_else(|| "openssl".into());
    let mut server = tokio::process::Command::new(executable)
        .args(["s_server", "-dtls1_2", "-nocert", "-quiet", "-accept"])
        .arg(peer.to_string())
        .args([
            "-psk_identity",
            "psk",
            "-psk",
            &"39".repeat(32),
            "-cipher",
            "PSK-AES128-GCM-SHA256",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let forwarding = tokio::spawn(async move {
        let mut first = true;
        let mut client = None;
        let mut packet = [0; 65536];
        loop {
            let (n, source) = relay.recv_from(&mut packet).await.unwrap();
            let target = if source == peer {
                client.unwrap()
            } else {
                client = Some(source);
                if first {
                    first = false;
                    continue;
                }
                peer
            };
            relay.send_to(&packet[..n], target).await.unwrap();
        }
    });
    let mut channel = Channel::connect(
        relay_addr,
        Key::Psk {
            secret: zeroize::Zeroizing::new([0x39; 32]),
            application_id: vec![0x42; 32],
        },
        1280,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(channel.cipher(), "PSK-AES128-GCM-SHA256");
    for size in [1, 1200, 17] {
        let packet = vec![b'x'; size];
        channel.send(&packet).await.unwrap();
        let mut received = vec![0; size];
        tokio::time::timeout(
            Duration::from_secs(2),
            server.stdout.as_mut().unwrap().read_exact(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, packet);
        server
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&packet)
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), channel.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, packet);
    }
    server.kill().await.unwrap();
    server.wait().await.unwrap();
    forwarding.abort();
}

#[tokio::test]
async fn blackhole_retransmits_app_id_and_obeys_deadline() {
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = sink.local_addr().unwrap();
    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_port = local.local_addr().unwrap().port();
    drop(local);
    let connect = Channel::connect_bound(
        peer,
        Key::Psk {
            secret: zeroize::Zeroizing::new([0x39; 32]),
            application_id: vec![0x42; 32],
        },
        1280,
        Duration::from_millis(1500),
        local_port,
    );
    tokio::pin!(connect);
    let mut hellos = 0;
    let mut packet = [0; 4096];
    let started = tokio::time::Instant::now();
    loop {
        tokio::select! {
            result = &mut connect => {
                let error = result.err().expect("blackhole must not authenticate");
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
                break;
            }
            result = sink.recv_from(&mut packet) => {
                let (n, sender) = result.unwrap();
                assert_eq!(sender.port(), local_port);
                // DTLS record (13), handshake header (12), client version (2),
                // random (32), then the session-ID length and bytes.
                assert!(n >= 92);
                assert_eq!(packet[0], 22);
                assert_eq!(packet[13], 1);
                assert_eq!(packet[59], 32);
                assert_eq!(&packet[60..92], &[0x42; 32]);
                hellos += 1;
            }
        }
    }
    assert!(
        hellos >= 2,
        "initial ClientHello plus actual OpenSSL retransmission"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}
