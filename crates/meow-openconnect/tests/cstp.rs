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
