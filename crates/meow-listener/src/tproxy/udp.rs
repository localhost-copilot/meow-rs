//! Linux TPROXY datagrams, keyed by the original (client, destination) tuple.
use super::linux;
use meow_common::{with_dial_timeout, ConnType, Metadata, Network, ProxyPacketConn};
use meow_tunnel::{tcp::ConnectionGuard, udp::DEFAULT_UDP_IDLE, Tunnel};
use smallvec::smallvec;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info};

struct Flow {
    packets: mpsc::Sender<Vec<u8>>,
    task: tokio::task::AbortHandle,
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Outbound(Box<dyn ProxyPacketConn>);
impl Drop for Outbound {
    fn drop(&mut self) {
        let _ = self.0.close();
    }
}

pub(super) async fn run(
    tunnel: Tunnel,
    socket: UdpSocket,
    name: String,
    mark: Option<u32>,
    max_flows: usize,
) -> io::Result<()> {
    let local = socket.local_addr()?;
    let mut flows: HashMap<(SocketAddr, SocketAddr), Flow> = HashMap::new();
    let mut buffer = vec![0u8; 65535];
    let mut sweep = tokio::time::interval(Duration::from_secs(15));
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    info!("TProxy UDP listener '{}' started on {}", name, local);
    loop {
        let packet = tokio::select! {
            packet = linux::recv_datagram(&socket, &mut buffer) => match packet {
                Ok(packet) => packet,
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    debug!("TProxy UDP: {error}");
                    continue;
                }
                Err(error) => return Err(error),
            },
            _ = sweep.tick() => {
                flows.retain(|_, flow| !flow.task.is_finished());
                continue;
            }
        };
        // Direct packets sent to the transparent port are not intercepted
        // traffic. Relaying them back to this listener would recurse forever.
        // A remote target using the same port remains a valid destination.
        if packet.destination.port() == local.port()
            && linux::is_local_address(packet.destination.ip())?
        {
            continue;
        }
        let key = (packet.source, packet.destination);
        if flows.get(&key).is_some_and(|flow| flow.packets.is_closed()) {
            flows.remove(&key);
        }
        if let Some(flow) = flows.get(&key) {
            let _ = flow.packets.try_send(buffer[..packet.length].to_vec());
            continue;
        }
        if max_flows != 0 && flows.len() >= max_flows {
            flows.retain(|_, flow| !flow.task.is_finished());
            if flows.len() >= max_flows {
                continue;
            }
        }
        let metadata = Metadata {
            network: Network::Udp,
            conn_type: ConnType::TProxy,
            src_ip: Some(packet.source.ip()),
            src_port: packet.source.port(),
            dst_ip: Some(packet.destination.ip()),
            dst_port: packet.destination.port(),
            in_name: name.clone().into(),
            in_port: local.port(),
            dscp: packet.dscp,
            ..Default::default()
        };
        let (sender, receiver) = mpsc::channel(64);
        sender
            .try_send(buffer[..packet.length].to_vec())
            .expect("new queue has capacity");
        let tunnel = tunnel.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = relay(&tunnel, receiver, key, metadata, mark).await {
                debug!("TProxy UDP flow: {error}");
            }
        })
        .abort_handle();
        flows.insert(
            key,
            Flow {
                packets: sender,
                task,
            },
        );
    }
}

async fn relay(
    tunnel: &Tunnel,
    mut receiver: mpsc::Receiver<Vec<u8>>,
    (client, original): (SocketAddr, SocketAddr),
    mut metadata: Metadata,
    mark: Option<u32>,
) -> Result<(), String> {
    let inner = tunnel.inner();
    inner.pre_handle_metadata(&mut metadata);
    let opening = inner.sniff_udp_initial(&mut metadata, &mut receiver).await;
    if opening.is_empty() {
        return Ok(());
    }
    let resolved_route = inner
        .resolve_udp_host(&mut metadata)
        .await
        .map_err(|e| e.to_string())?;
    let destination = SocketAddr::new(
        metadata.dst_ip.ok_or("unresolved UDP destination")?,
        metadata.dst_port,
    );
    let (proxy, rule, payload) = resolved_route
        .or_else(|| inner.resolve_proxy(&metadata))
        .ok_or("no matching UDP rule")?;
    let guard = ConnectionGuard::track(
        &inner.stats,
        metadata.clone(),
        rule,
        payload,
        smallvec![Arc::from(proxy.name())],
    );
    guard.run_until_closed(async {
        let outbound = Outbound(with_dial_timeout(proxy.name(), proxy.dial_udp(&metadata)).await.map_err(|e| e.to_string())?);
        // Bind the original destination, including a fake IP, so connected UDP
        // clients receive replies from exactly the endpoint they contacted.
        let reply = linux::reply_socket(original, client, mark).await.map_err(|e| e.to_string())?;
        for packet in opening {
            outbound.0.write_packet(&packet, &destination).await.map_err(|e| e.to_string())?;
            inner.stats.record_upload(guard.counters(), packet.len() as meow_common::atomic::Int);
        }
        let mut from_client = vec![0u8; 65535];
        let mut from_remote = vec![0u8; 65535];
        let idle = tokio::time::sleep(DEFAULT_UDP_IDLE);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                () = &mut idle => break,
                packet = receiver.recv() => {
                    let Some(packet) = packet else { break; };
                    outbound.0.write_packet(&packet, &destination).await.map_err(|e| e.to_string())?;
                    inner.stats.record_upload(guard.counters(), packet.len() as meow_common::atomic::Int);
                }
                // The kernel may deliver subsequent client datagrams directly
                // to this connected transparent socket after it is bound. They
                // must join the same outbound session as the listener's queue.
                result = reply.recv(&mut from_client) => {
                    let count = result.map_err(|e| e.to_string())?;
                    outbound.0.write_packet(&from_client[..count], &destination).await.map_err(|e| e.to_string())?;
                    inner.stats.record_upload(guard.counters(), count as meow_common::atomic::Int);
                }
                result = outbound.0.read_packet(&mut from_remote) => {
                    let (count, _) = result.map_err(|e| e.to_string())?;
                    reply.send(&from_remote[..count]).await.map_err(|e| e.to_string())?;
                    inner.stats.record_download(guard.counters(), count as meow_common::atomic::Int);
                }
            }
            idle.as_mut().reset(tokio::time::Instant::now() + DEFAULT_UDP_IDLE);
        }
        Ok(())
    }).await.unwrap_or(Ok(()))
}
