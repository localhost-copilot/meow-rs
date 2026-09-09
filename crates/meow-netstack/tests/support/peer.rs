//! Independent in-process TCP/UDP echo service reached only via raw IP packets.
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
pub const ADDRESS6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
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
        addresses.push(IpCidr::new(ADDRESS6.into(), 64)).unwrap();
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
    let mut dns_udp = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 65536]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 65536]),
    );
    dns_udp.bind(53).unwrap();
    let dns_udp = sockets.add(dns_udp);
    let mut dns_tcp: Vec<_> = (0..8)
        .map(|_| {
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 4096]),
                tcp::SocketBuffer::new(vec![0; 4096]),
            );
            socket.listen(53).unwrap();
            (sockets.add(socket), Vec::<u8>::new())
        })
        .collect();
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
            socket.send_slice(&packet, meta.endpoint).unwrap();
            progress = true;
        }
        let socket = sockets.get_mut::<udp::Socket>(dns_udp);
        if socket.can_recv() && socket.can_send() {
            let (bytes, meta) = socket.recv().unwrap();
            let reply = dns_reply(bytes, false);
            socket.send_slice(&reply, meta.endpoint).unwrap();
            progress = true;
        }
        for (handle, buffer) in &mut dns_tcp {
            let socket = sockets.get_mut::<tcp::Socket>(*handle);
            if socket.can_recv() {
                socket
                    .recv(|bytes| {
                        buffer.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
                progress = true;
            }
            if buffer.len() >= 2 {
                let n = usize::from(u16::from_be_bytes([buffer[0], buffer[1]]));
                if buffer.len() >= n + 2 && socket.can_send() {
                    let reply = dns_reply(&buffer[2..n + 2], true);
                    let mut bytes = (reply.len() as u16).to_be_bytes().to_vec();
                    bytes.extend(reply);
                    socket.send_slice(&bytes).unwrap();
                    buffer.drain(..n + 2);
                    progress = true;
                }
            }
            if socket.state() == tcp::State::CloseWait && !socket.can_recv() {
                socket.close();
                progress = true;
            }
            if socket.state() == tcp::State::Closed {
                socket.listen(53).unwrap();
                buffer.clear();
                progress = true;
            }
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

// A deliberately small independent wire-format DNS server. It never uses the
// host resolver, and only answers the fixture's private names.
fn dns_reply(query: &[u8], tcp: bool) -> Vec<u8> {
    assert!(query.len() >= 17);
    let mut offset = 12;
    let mut labels = Vec::new();
    while query[offset] != 0 {
        let size = usize::from(query[offset]);
        offset += 1;
        labels.push(std::str::from_utf8(&query[offset..offset + size]).unwrap());
        offset += size;
    }
    offset += 1;
    let kind = u16::from_be_bytes([query[offset], query[offset + 1]]);
    let name = labels.join(".");
    let mut response = query[..offset + 4].to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    response[6..12].fill(0);
    if name == "truncated.vpn.test" && !tcp {
        response[2] |= 2;
        return response;
    }
    if !matches!(
        name.as_str(),
        "service.vpn.test" | "truncated.vpn.test" | "ipv6.vpn.test"
    ) {
        response[3] = 0x83;
        return response;
    }
    let ip = match (kind, name.as_str()) {
        (1, "ipv6.vpn.test") => return response,
        (1, _) => ADDRESS.octets().to_vec(),
        (28, _) => ADDRESS6.octets().to_vec(),
        _ => return response,
    };
    response[7] = 1;
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&kind.to_be_bytes());
    response.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    response.extend_from_slice(&(ip.len() as u16).to_be_bytes());
    response.extend_from_slice(&ip);
    response
}
