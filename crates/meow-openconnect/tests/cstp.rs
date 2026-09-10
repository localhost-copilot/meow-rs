use meow_openconnect::{connect, read_frame, Options};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const RESPONSE: &[u8] = b"HTTP/1.1 200 CONNECTED\r\nX-CSTP-Version: 1\r\nX-CSTP-Address: 192.0.2.2\r\nX-CSTP-MTU: 1280\r\nX-CSTP-DPD: 1\r\n\r\n";
fn options() -> Options {
    Options {
        authority: "vpn.example:443".into(),
        cookie: "fixture-cookie".into(),
        mtu: 1400,
        ipv6: false,
    }
}
fn packet() -> Vec<u8> {
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[3] = 20;
    packet
}
async fn consume_request(stream: &mut tokio::io::DuplexStream) {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        request.push(stream.read_u8().await.unwrap());
    }
    assert!(String::from_utf8(request)
        .unwrap()
        .contains("Cookie: webvpn=fixture-cookie\r\n"));
}

#[tokio::test]
async fn fragmented_headers_coalesced_data_and_simultaneous_control() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (client, mut server) = tokio::io::duplex(8192);
        let peer = tokio::spawn(async move {
            consume_request(&mut server).await;
            for byte in &RESPONSE[..RESPONSE.len() - 2] {
                server.write_all(&[*byte]).await.unwrap();
            }
            let mut tail = RESPONSE[RESPONSE.len() - 2..].to_vec();
            tail.extend_from_slice(b"STF\x01\x00\x14\x00\x00");
            tail.extend_from_slice(&packet());
            server.write_all(&tail).await.unwrap();
            // A partial frame must survive concurrent outgoing traffic.
            server.write_all(b"STF\x01").await.unwrap();
            let (kind, data) = read_frame(&mut server, 1280).await.unwrap();
            assert_eq!(kind, 0);
            assert_eq!(data, packet());
            server.write_all(&[0, 0, 3, 0]).await.unwrap();
            assert_eq!(read_frame(&mut server, 1280).await.unwrap(), (4, vec![]));
        });
        let connection = connect(client, &options()).await.unwrap();
        assert_eq!(connection.network.mtu, 1280);
        let (outgoing, rx) = mpsc::channel(2);
        let (tx, mut incoming) = mpsc::channel(2);
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let worker = tokio::spawn(connection.run(rx, tx, token));
        assert_eq!(incoming.recv().await.unwrap(), packet());
        outgoing.send(packet()).await.unwrap();
        peer.await.unwrap();
        // EOF is a transport failure, not a silently ready session.
        assert!(worker.await.unwrap().is_err());
        cancel.cancel();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unsolicited_ipv6_does_not_disconnect_an_ipv4_tunnel() {
    use meow_openconnect::compression::Mode;
    use meow_openconnect::{connect_configured, write_frame, ConnectSettings};

    for compressed in [false, true] {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (client, mut server) = tokio::io::duplex(8192);
            let peer = tokio::spawn(async move {
                consume_request(&mut server).await;
                server
                    .write_all(&RESPONSE[..RESPONSE.len() - 2])
                    .await
                    .unwrap();
                if compressed {
                    server
                        .write_all(b"X-CSTP-Content-Encoding: oc-lz4\r\n")
                        .await
                        .unwrap();
                }
                server.write_all(b"\r\n").await.unwrap();
                let mut unsolicited = vec![0; 40];
                unsolicited[0] = 0x60;
                for data in [unsolicited, packet()] {
                    if compressed {
                        write_frame(&mut server, 8, &lz4_flex::block::compress(&data))
                            .await
                            .unwrap();
                    } else {
                        write_frame(&mut server, 0, &data).await.unwrap();
                    }
                }
                write_frame(&mut server, 3, &[]).await.unwrap();
                assert_eq!(read_frame(&mut server, 1280).await.unwrap(), (4, vec![]));
                server
            });
            let connection = connect_configured(
                client,
                &options(),
                &ConnectSettings {
                    compression: Mode::Stateless,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let (_outgoing, rx) = mpsc::channel(2);
            let (tx, mut incoming) = mpsc::channel(2);
            let cancel = CancellationToken::new();
            let worker = tokio::spawn(connection.run(rx, tx, cancel.clone()));
            assert_eq!(incoming.recv().await.unwrap(), packet());
            let _server = peer.await.unwrap();
            cancel.cancel();
            worker.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn rejected_cookie_and_unsupported_compression_do_not_echo_server_body() {
    for response in [
        b"HTTP/1.1 403 forbidden-private-text\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nX-CSTP-Content-Encoding: deflate\r\n\r\n",
    ] {
        let (client, mut server) = tokio::io::duplex(8192);
        let response = response.to_vec();
        let peer = tokio::spawn(async move {
            consume_request(&mut server).await;
            server.write_all(&response).await.unwrap();
        });
        let error = connect(client, &options()).await.err().unwrap();
        assert!(!error.to_string().contains("private-text"));
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn malformed_frames_fail_before_allocating_unbounded_payloads() {
    for mut bytes in [
        b"BAD\x01\x00\x00\x00\x00".as_slice(),
        b"STF\x01\xff\xff\x00\x00",
        b"STF\x01\x00\x14\x00\x00\x45",
    ] {
        assert!(read_frame(&mut bytes, 1280).await.is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn silent_peer_times_out() {
    let (client, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        consume_request(&mut server).await;
        server.write_all(RESPONSE).await.unwrap();
        server
    });
    let connection = connect(client, &options()).await.unwrap();
    let _server = peer.await.unwrap();
    let (_outgoing, rx) = mpsc::channel(2);
    let (tx, _incoming) = mpsc::channel(2);
    let token = CancellationToken::new();
    let worker = tokio::spawn(connection.run(rx, tx, token));
    let error = worker.await.unwrap().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn ipv6_network_parameters_and_packet_boundaries() {
    let (client, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        consume_request(&mut server).await;
        server.write_all(b"HTTP/1.1 200 OK\r\nX-CSTP-Version: 1\r\nX-CSTP-Address-IP6: 2001:db8::2/127\r\nX-CSTP-MTU: 1280\r\nX-CSTP-DNS: 192.0.2.53\r\nX-CSTP-DNS: 2001:db8::53\r\nX-CSTP-DNS: 192.0.2.53\r\n\r\n").await.unwrap();
        server
    });
    let mut options = options();
    options.ipv6 = true;
    let connection = connect(client, &options).await.unwrap();
    assert_eq!(connection.network.address, None);
    assert_eq!(
        connection.network.address6,
        Some("2001:db8::2".parse().unwrap())
    );
    assert_eq!(
        connection.network.dns,
        vec![
            "192.0.2.53".parse::<std::net::IpAddr>().unwrap(),
            "2001:db8::53".parse().unwrap()
        ]
    );
    let mut server = peer.await.unwrap();
    let (outgoing, rx) = mpsc::channel(2);
    let (tx, mut incoming) = mpsc::channel(2);
    let worker = tokio::spawn(connection.run(rx, tx, CancellationToken::new()));
    let mut packet6 = vec![0; 1280];
    packet6[0] = 0x60;
    packet6[4..6].copy_from_slice(&1240u16.to_be_bytes());
    meow_openconnect::write_frame(&mut server, 0, &packet6)
        .await
        .unwrap();
    assert_eq!(incoming.recv().await.unwrap(), packet6);
    outgoing.send(packet6.clone()).await.unwrap();
    assert_eq!(
        read_frame(&mut server, 1280).await.unwrap(),
        (0, packet6.clone())
    );
    // A valid IPv4 packet must not enter a generation configured only for IPv6.
    outgoing.send(packet()).await.unwrap();
    assert!(worker.await.unwrap().is_err());
    packet6[5] -= 1;
    assert!(meow_openconnect::validate_ip(&packet6, 1280).is_err());
    assert!(meow_openconnect::validate_ip(&[0x60; 39], 1280).is_err());
}

#[tokio::test]
async fn invalid_ipv6_network_configuration_is_rejected() {
    for (extra, ipv6) in [
        (
            "X-CSTP-Address-IP6: 2001:db8::2/129\r\nX-CSTP-MTU: 1280",
            true,
        ),
        (
            "X-CSTP-Address-IP6: 2001:db8::2/64\r\nX-CSTP-MTU: 1279",
            true,
        ),
        (
            "X-CSTP-Address-IP6: 2001:db8::2/64\r\nX-CSTP-MTU: 1280",
            false,
        ),
        ("X-CSTP-Address-IP6: ff02::1\r\nX-CSTP-MTU: 1280", true),
        (
            "X-CSTP-Address-IP6: 2001:db8::2\r\nX-CSTP-Address: 2001:db8::3\r\nX-CSTP-MTU: 1280",
            true,
        ),
        (
            "X-CSTP-Address: 192.0.2.2\r\nX-CSTP-DNS: invalid\r\nX-CSTP-MTU: 1280",
            true,
        ),
    ] {
        let (client, mut server) = tokio::io::duplex(8192);
        let peer = tokio::spawn(async move {
            consume_request(&mut server).await;
            server
                .write_all(
                    format!("HTTP/1.1 200 OK\r\nX-CSTP-Version: 1\r\n{extra}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
        });
        let mut options = options();
        options.ipv6 = ipv6;
        assert!(connect(client, &options).await.is_err(), "accepted {extra}");
        peer.await.unwrap();
    }
}
