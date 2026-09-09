//! Independent in-process TCP/UDP echo service reached only via raw IP packets.
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
pub const TCP_PORT: u16 = 8080;
pub const UDP_PORT: u16 = 5353;

struct Wire {
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
}
struct Rx(Vec<u8>);
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, n: usize, f: F) -> R {
        let mut bytes = vec![0; n];
        let result = f(&mut bytes);
        self.0.push_back(bytes);
        result
    }
}
impl Device for Wire {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: SmolInstant) -> Option<(Rx, Tx<'_>)> {
        Some((Rx(self.incoming.pop_front()?), Tx(&mut self.outgoing)))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.outgoing))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1280;
        caps
    }
}

pub async fn run(
    mut incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
) {
    let mut wire = Wire {
        incoming: VecDeque::new(),
        outgoing: VecDeque::new(),
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 41;
    let mut iface = Interface::new(config, &mut wire, SmolInstant::ZERO);
    iface.update_ip_addrs(|addresses| {
        addresses.push(IpCidr::new(ADDRESS.into(), 24)).unwrap();
    });
    let mut sockets = SocketSet::new(vec![]);
    let handles: Vec<_> = (0..32)
        .map(|_| {
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 16384]),
                tcp::SocketBuffer::new(vec![0; 16384]),
            );
            socket.set_nagle_enabled(false);
            socket.listen(TCP_PORT).unwrap();
            sockets.add(socket)
        })
        .collect();
    let mut udp = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 65536]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 65536]),
    );
    udp.bind(UDP_PORT).unwrap();
    let udp = sockets.add(udp);
    let epoch = tokio::time::Instant::now();
    loop {
        let now = SmolInstant::from_millis(epoch.elapsed().as_millis() as i64);
        iface.poll(now, &mut wire, &mut sockets);
        let mut progress = false;
        for handle in &handles {
            let socket = sockets.get_mut::<tcp::Socket>(*handle);
            if socket.can_recv() && socket.can_send() {
                let capacity = socket.send_capacity() - socket.send_queue();
                let bytes = socket
                    .recv(|bytes| {
                        let n = capacity.min(bytes.len());
                        (n, bytes[..n].to_vec())
                    })
                    .unwrap();
                if !bytes.is_empty() {
                    socket.send_slice(&bytes).unwrap();
                    progress = true;
                }
            }
            if socket.state() == tcp::State::CloseWait && !socket.can_recv() {
                socket.close();
                progress = true;
            }
        }
        let socket = sockets.get_mut::<udp::Socket>(udp);
        if socket.can_recv() && socket.can_send() {
            let (data, meta) = socket.recv().unwrap();
            let packet = data.to_vec();
            assert_eq!(meta.endpoint.addr, IpAddress::v4(192, 0, 2, 2));
            socket.send_slice(&packet, meta.endpoint).unwrap();
            progress = true;
        }
        if progress {
            continue;
        }
        let delay = iface
            .poll_delay(now, &sockets)
            .map_or(Duration::from_secs(1), |n| {
                Duration::from_millis(n.total_millis())
            });
        tokio::select! {
            _ = cancel.cancelled() => return,
            packet = incoming.recv() => match packet { Some(p) => wire.incoming.push_back(p), None => return },
            permit = outgoing.reserve(), if !wire.outgoing.is_empty() => {
                let Ok(permit) = permit else { return; };
                permit.send(wire.outgoing.pop_front().unwrap());
            },
            _ = tokio::time::sleep(delay) => {},
        }
    }
}
