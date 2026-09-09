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
async fn shared_tcp_send_budget_recovers_loss_across_concurrent_flows() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (outgoing, mut packets) = mpsc::channel::<Vec<u8>>(4);
        let (to_peer, peer_in) = mpsc::channel(4);
        let (peer_out, incoming) = mpsc::channel(4);
        let peer = tokio::spawn(peer::run(peer_in, peer_out, CancellationToken::new()));
        let relay = tokio::spawn(async move {
            let mut dropped = false;
            while let Some(packet) = packets.recv().await {
                let ip = smoltcp::wire::Ipv4Packet::new_checked(&packet[..]).unwrap();
                let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
                if !dropped && !tcp.payload().is_empty() {
                    dropped = true;
                    continue;
                }
                if to_peer.send(packet).await.is_err() {
                    break;
                }
            }
            dropped
        });
        let stack = Stack::with_tcp_send_budget(
            Some(Ipv4Addr::new(192, 0, 2, 2)),
            None,
            1280,
            32 * 1024,
            incoming,
            outgoing,
        )
        .unwrap();
        let mut flows = tokio::task::JoinSet::new();
        for id in 0..4 {
            let stack = stack.clone();
            flows.spawn(async move {
                let tcp = stack
                    .connect(SocketAddr::new(peer::ADDRESS.into(), peer::TCP_PORT))
                    .await
                    .unwrap();
                let (mut read, mut write) = tokio::io::split(tcp);
                let payload: Vec<u8> = (0..131072).map(|n| ((n + id) % 251) as u8).collect();
                let send = async {
                    write.write_all(&payload).await.unwrap();
                    write.shutdown().await.unwrap();
                };
                let receive = async {
                    let mut answer = Vec::new();
                    read.read_to_end(&mut answer).await.unwrap();
                    assert_eq!(answer, payload);
                };
                tokio::join!(send, receive);
            });
        }
        while let Some(result) = flows.join_next().await {
            result.unwrap();
        }
        stack.close();
        stack.closed().await;
        assert!(relay.await.unwrap(), "the loss path must be exercised");
        peer.await.unwrap();
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
async fn new_flow_waits_for_send_credits_held_by_existing_flow() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (outgoing, mut packets) = mpsc::channel::<Vec<u8>>(4);
        let (to_peer, peer_in) = mpsc::channel(4);
        let (peer_out, mut replies) = mpsc::channel::<Vec<u8>>(4);
        let (to_stack, incoming) = mpsc::channel(4);
        let (release, mut released) = tokio::sync::watch::channel(false);
        let outgoing_released = released.clone();
        let (total_tx, mut total_rx) = tokio::sync::watch::channel(0usize);
        let (exceeded_tx, exceeded_rx) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(peer::run(peer_in, peer_out, CancellationToken::new()));
        let forward = tokio::spawn(async move {
            let mut seen = std::collections::HashMap::<u16, (i32, Vec<bool>)>::new();
            let mut total = 0;
            let mut exceeded = Some(exceeded_tx);
            while let Some(packet) = packets.recv().await {
                let ip = smoltcp::wire::Ipv4Packet::new_checked(&packet[..]).unwrap();
                let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
                if tcp.syn() {
                    seen.entry(tcp.src_port())
                        .or_insert_with(|| (tcp.seq_number().0.wrapping_add(1), Vec::new()));
                }
                // Retransmissions can use different segment boundaries. Count
                // unique sequence bytes, not distinct packet representations.
                if !tcp.payload().is_empty() {
                    let (base, covered) = seen.get_mut(&tcp.src_port()).expect("SYN precedes data");
                    let offset = tcp.seq_number().0.wrapping_sub(*base);
                    // A keepalive probe at SND.UNA - 1 is not application data.
                    if offset >= 0 {
                        let offset = offset as usize;
                        let end = offset + tcp.payload().len();
                        assert!(end <= 32768);
                        covered.resize(covered.len().max(end), false);
                        for byte in &mut covered[offset..end] {
                            if !*byte {
                                *byte = true;
                                total += 1;
                            }
                        }
                    }
                    total_tx.send_replace(total);
                    if total > 16384 && !*outgoing_released.borrow() {
                        if let Some(signal) = exceeded.take() {
                            let _ = signal.send(());
                        }
                    }
                }
                if to_peer.send(packet).await.is_err() {
                    break;
                }
            }
        });
        let backward = tokio::spawn(async move {
            let mut held = Vec::new();
            let mut open = false;
            loop {
                tokio::select! {
                    result = released.changed(), if !open => {
                        result.unwrap();
                        open = *released.borrow();
                        if open {
                            for packet in held.drain(..) {
                                if to_stack.send(packet).await.is_err() { return; }
                            }
                        }
                    },
                    packet = replies.recv() => {
                        let Some(packet) = packet else { break; };
                        let ip = smoltcp::wire::Ipv4Packet::new_checked(&packet[..]).unwrap();
                        let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
                        // New handshakes remain possible while data ACKs are held.
                        if open || tcp.syn() {
                            if to_stack.send(packet).await.is_err() { break; }
                        } else { held.push(packet); }
                    }
                }
            }
        });
        let stack = Stack::with_tcp_send_budget(
            Some(Ipv4Addr::new(192, 0, 2, 2)),
            None,
            1280,
            16384,
            incoming,
            outgoing,
        )
        .unwrap();
        let target = SocketAddr::new(peer::ADDRESS.into(), peer::TCP_PORT);
        let mut first = stack.connect(target).await.unwrap();
        first.write_all(&vec![11; 16384]).await.unwrap();
        total_rx.wait_for(|total| *total >= 16384).await.unwrap();
        let mut second = stack.connect(target).await.unwrap();
        second.write_all(&vec![22; 8192]).await.unwrap();
        // With ACKs withheld, admitting the new flow must not exceed the total
        // budget. This bounded absence check also spans possible retransmissions.
        let result = tokio::time::timeout(Duration::from_millis(30), exceeded_rx).await;
        assert!(
            result.is_err(),
            "send budget exceeded or relay closed: {result:?}"
        );
        release.send_replace(true);
        let receive_first = async {
            first.shutdown().await.unwrap();
            let mut answer = Vec::new();
            first.read_to_end(&mut answer).await.unwrap();
            assert_eq!(answer, vec![11; 16384]);
        };
        let receive_second = async {
            second.shutdown().await.unwrap();
            let mut answer = Vec::new();
            second.read_to_end(&mut answer).await.unwrap();
            assert_eq!(answer, vec![22; 8192]);
        };
        tokio::join!(receive_first, receive_second);
        drop((first, second));
        stack.close();
        stack.closed().await;
        forward.await.unwrap();
        peer.await.unwrap();
        backward.await.unwrap();
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
