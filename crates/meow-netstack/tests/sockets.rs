#[path = "support/peer.rs"]
mod peer;
use meow_netstack::Stack;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn ipv6_only_and_dual_stack_transfer_and_explicit_close() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for ipv4 in [None, Some(Ipv4Addr::new(192, 0, 2, 2))] {
            let (to_peer, peer_in) = mpsc::channel(4);
            let (peer_out, from_peer) = mpsc::channel(4);
            let peer = tokio::spawn(peer::run(peer_in, peer_out, CancellationToken::new()));
            let stack = Stack::with_addresses(
                ipv4,
                Some("2001:db8::2".parse().unwrap()),
                1280,
                from_peer,
                to_peer,
            )
            .unwrap();
            let mut tcp = stack
                .connect(SocketAddr::new(peer::ADDRESS6.into(), peer::TCP_PORT))
                .await
                .unwrap();
            let expected = vec![23; 65536];
            let (mut read, mut write) = tokio::io::split(&mut tcp);
            let send = async {
                write.write_all(&expected).await.unwrap();
                write.shutdown().await.unwrap();
            };
            let receive = async {
                let mut actual = Vec::new();
                read.read_to_end(&mut actual).await.unwrap();
                assert_eq!(actual, expected);
            };
            tokio::join!(send, receive);
            let udp = stack.bind_udp().await.unwrap();
            // One UDP socket can alternate address families, including maximum-size IPv6 datagrams.
            let mut targets = vec![peer::ADDRESS6.into()];
            if ipv4.is_some() {
                targets.push(peer::ADDRESS.into());
            }
            for ip in targets {
                let target = SocketAddr::new(ip, peer::UDP_PORT);
                for size in [0, 1232] {
                    let bytes = vec![31; size];
                    udp.send_to(&bytes, target).await.unwrap();
                    let mut received = [0; 1280];
                    let (n, source) = udp.recv_from(&mut received).await.unwrap();
                    assert_eq!(source, target);
                    assert_eq!(&received[..n], bytes);
                }
            }
            assert!(udp
                .send_to(
                    &[0; 1233],
                    SocketAddr::new(peer::ADDRESS6.into(), peer::UDP_PORT)
                )
                .await
                .is_err());
            if ipv4.is_none() {
                assert!(stack
                    .connect(SocketAddr::new(peer::ADDRESS.into(), peer::TCP_PORT))
                    .await
                    .is_err());
            }
            let mut active = stack
                .connect(SocketAddr::new(peer::ADDRESS6.into(), peer::TCP_PORT))
                .await
                .unwrap();
            let read = async {
                assert!(active.read(&mut [0; 1]).await.is_err());
            };
            let receive = async {
                assert!(udp.recv_from(&mut [0; 1]).await.is_err());
            };
            let close = async {
                tokio::task::yield_now().await;
                stack.close();
            };
            tokio::join!(read, receive, close);
            stack.closed().await;
            assert!(stack.is_closed());
            // Teardown closes the packet channel even with application handles still alive.
            peer.await.unwrap();
        }
    })
    .await
    .unwrap();
}

fn stack() -> (Stack, CancellationToken, tokio::task::JoinHandle<()>) {
    let (to_peer, peer_in) = mpsc::channel(4);
    let (peer_out, from_peer) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(peer::run(peer_in, peer_out, cancel.clone()));
    (
        Stack::new(Ipv4Addr::new(192, 0, 2, 2), 1280, from_peer, to_peer).unwrap(),
        cancel,
        task,
    )
}

#[tokio::test]
async fn tcp_udp_and_half_close_with_bounded_packet_queues() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (stack, cancel, peer) = stack();
        let tcp = stack
            .connect(SocketAddr::new(peer::ADDRESS.into(), peer::TCP_PORT))
            .await
            .unwrap();
        let (mut reader, mut writer) = tokio::io::split(tcp);
        let expected: Vec<u8> = (0..262144).map(|n| (n % 251) as u8).collect();
        let write = async {
            writer.write_all(&expected).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let read = async {
            let mut received = Vec::new();
            reader.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, expected);
        };
        tokio::join!(write, read);
        drop((reader, writer));
        let udp = stack.bind_udp().await.unwrap();
        for length in [0, 1, 1200, 17] {
            let payload = vec![42; length];
            let target = SocketAddr::new(peer::ADDRESS.into(), peer::UDP_PORT);
            udp.send_to(&payload, target).await.unwrap();
            let mut buffer = vec![0; 1500];
            let (n, from) = udp.recv_from(&mut buffer).await.unwrap();
            assert_eq!(from, target);
            assert_eq!(&buffer[..n], payload);
        }
        assert!(udp
            .send_to(
                &vec![0; 1253],
                SocketAddr::new(peer::ADDRESS.into(), peer::UDP_PORT)
            )
            .await
            .is_err());
        udp.close();
        assert!(udp.recv_from(&mut [0; 1]).await.is_err());
        drop(udp);
        drop(stack);
        // The peer sees the last stack packet sender close; no leaked actor.
        peer.await.unwrap();
        cancel.cancel();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tunnel_failure_wakes_active_tcp_and_udp() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (stack, cancel, peer) = stack();
        let mut tcp = stack
            .connect(SocketAddr::new(peer::ADDRESS.into(), peer::TCP_PORT))
            .await
            .unwrap();
        let udp = stack.bind_udp().await.unwrap();
        cancel.cancel();
        peer.await.unwrap();
        assert!(tcp.read(&mut [0; 1]).await.is_err());
        assert!(udp.recv_from(&mut [0; 1]).await.is_err());
        assert!(stack.is_closed());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropping_cancelled_connect_releases_stack() {
    let (outgoing, mut packets) = mpsc::channel(4);
    let (_incoming, receiver) = mpsc::channel(4);
    let stack = Stack::new(Ipv4Addr::new(192, 0, 2, 2), 1280, receiver, outgoing).unwrap();
    let connecting_stack = stack.clone();
    let task = tokio::spawn(async move {
        connecting_stack
            .connect("192.0.2.1:8080".parse().unwrap())
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), packets.recv())
        .await
        .unwrap()
        .unwrap();
    task.abort();
    let _ = task.await;
    drop(stack);
    tokio::time::timeout(Duration::from_secs(2), async {
        while packets.recv().await.is_some() {}
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropping_one_stream_resets_peer_without_closing_shared_stack() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (to_wire, mut wire) = mpsc::channel::<Vec<u8>>(4);
        let (to_peer, peer_in) = mpsc::channel(4);
        let (peer_out, from_peer) = mpsc::channel(4);
        let (reset_tx, mut reset_rx) = tokio::sync::watch::channel(false);
        let forward = tokio::spawn(async move {
            while let Some(packet) = wire.recv().await {
                let ip = smoltcp::wire::Ipv4Packet::new_checked(&packet).unwrap();
                let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
                if tcp.rst() {
                    reset_tx.send_replace(true);
                }
                if to_peer.send(packet).await.is_err() {
                    break;
                }
            }
        });
        let cancel = CancellationToken::new();
        let peer = tokio::spawn(peer::run(peer_in, peer_out, cancel.clone()));
        let stack = Stack::new(Ipv4Addr::new(192, 0, 2, 2), 1280, from_peer, to_wire).unwrap();
        let stream = stack
            .connect(SocketAddr::new(peer::ADDRESS.into(), peer::TCP_PORT))
            .await
            .unwrap();
        drop(stream);
        reset_rx.wait_for(|seen| *seen).await.unwrap();
        assert!(!stack.is_closed());
        let error = stack
            .connect(SocketAddr::new(peer::ADDRESS.into(), 9999))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        drop(stack);
        forward.await.unwrap();
        peer.await.unwrap();
    })
    .await
    .unwrap();
}
