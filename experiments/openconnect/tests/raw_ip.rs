use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Packet};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Default)]
struct Link {
    packets: VecDeque<Vec<u8>>,
    sent: usize,
    dropped: usize,
    drop_next: bool,
}

struct RawIp {
    incoming: Rc<RefCell<Link>>,
    outgoing: Rc<RefCell<Link>>,
}

impl RawIp {
    fn pair() -> (Self, Self) {
        let a = Rc::new(RefCell::new(Link::default()));
        let b = Rc::new(RefCell::new(Link::default()));
        (
            Self {
                incoming: a.clone(),
                outgoing: b.clone(),
            },
            Self {
                incoming: b,
                outgoing: a,
            },
        )
    }
}

struct Received(Vec<u8>);
impl RxToken for Received {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct Transmit(Rc<RefCell<Link>>);
impl TxToken for Transmit {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(len <= 1280, "packet exceeded configured IP MTU");
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        let ip = Ipv4Packet::new_checked(&packet).expect("raw IPv4, without Ethernet");
        assert!(ip.verify_checksum());
        let mut link = self.0.borrow_mut();
        link.sent += 1;
        if std::mem::take(&mut link.drop_next) {
            link.dropped += 1;
        } else {
            assert!(link.packets.len() < 64, "bounded test link overflow");
            link.packets.push_back(packet);
        }
        result
    }
}

impl Device for RawIp {
    type RxToken<'a> = Received;
    type TxToken<'a> = Transmit;

    fn receive(&mut self, _: Instant) -> Option<(Received, Transmit)> {
        let packet = self.incoming.borrow_mut().packets.pop_front()?;
        Some((Received(packet), Transmit(self.outgoing.clone())))
    }

    fn transmit(&mut self, _: Instant) -> Option<Transmit> {
        Some(Transmit(self.outgoing.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1280;
        caps
    }
}

fn interface(device: &mut RawIp, last: u8) -> Interface {
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = u64::from(last);
    let mut iface = Interface::new(config, device, Instant::ZERO);
    iface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::v4(192, 0, 2, last), 24))
            .unwrap();
    });
    iface
}

fn tcp_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 2048]),
        tcp::SocketBuffer::new(vec![0; 2048]),
    )
}

#[test]
fn active_tcp_over_raw_ip_retransmits_and_half_closes() {
    let (mut client_dev, mut server_dev) = RawIp::pair();
    // Force a SYN retransmission with virtual time, without sleeping or OS TCP sockets.
    client_dev.outgoing.borrow_mut().drop_next = true;
    let mut client = interface(&mut client_dev, 1);
    let mut server = interface(&mut server_dev, 2);
    let mut client_sockets = SocketSet::new(vec![]);
    let mut server_sockets = SocketSet::new(vec![]);
    let c = client_sockets.add(tcp_socket());
    let s = server_sockets.add(tcp_socket());
    server_sockets
        .get_mut::<tcp::Socket>(s)
        .listen(443)
        .unwrap();
    client_sockets
        .get_mut::<tcp::Socket>(c)
        .connect(client.context(), (IpAddress::v4(192, 0, 2, 2), 443), 49152)
        .unwrap();

    let payload: Vec<u8> = (0..16384).map(|n| (n % 251) as u8).collect();
    let mut sent = 0;
    let mut received = Vec::new();
    let mut echoed = Vec::new();
    let mut echo_sent = 0;
    let mut client_closed = false;
    let mut server_closed = false;
    for tick in 0..6000 {
        let now = Instant::from_millis(tick * 10);
        client.poll(now, &mut client_dev, &mut client_sockets);
        server.poll(now, &mut server_dev, &mut server_sockets);
        let socket = client_sockets.get_mut::<tcp::Socket>(c);
        if socket.can_send() && sent < payload.len() {
            sent += socket.send_slice(&payload[sent..]).unwrap();
        }
        if sent == payload.len() && !client_closed {
            socket.close();
            client_closed = true;
        }
        if socket.can_recv() {
            socket
                .recv(|data| {
                    echoed.extend_from_slice(data);
                    (data.len(), ())
                })
                .unwrap();
        }
        let socket = server_sockets.get_mut::<tcp::Socket>(s);
        if socket.can_recv() {
            socket
                .recv(|data| {
                    received.extend_from_slice(data);
                    (data.len(), ())
                })
                .unwrap();
        }
        if socket.can_send() && echo_sent < received.len() {
            echo_sent += socket.send_slice(&received[echo_sent..]).unwrap();
        }
        if received.len() == payload.len()
            && echo_sent == payload.len()
            && !socket.may_recv()
            && !server_closed
        {
            socket.close();
            server_closed = true;
        }
        if server_closed && echoed.len() == payload.len() {
            assert_eq!(received, payload);
            assert_eq!(echoed, payload);
            assert_eq!(client_dev.outgoing.borrow().dropped, 1);
            assert!(client_dev.outgoing.borrow().sent > 10);
            println!(
                "TCP: 16384 bytes echoed after client FIN; dropped SYN recovered; raw IP MTU 1280"
            );
            return;
        }
    }
    panic!(
        "virtual deadline: sent={sent}, received={}, echoed={}",
        received.len(),
        echoed.len()
    );
}

fn udp_socket() -> udp::Socket<'static> {
    udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 4096]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 4096]),
    )
}

#[test]
fn udp_over_raw_ip_preserves_datagrams_and_endpoints() {
    let (mut client_dev, mut server_dev) = RawIp::pair();
    let mut client = interface(&mut client_dev, 1);
    let mut server = interface(&mut server_dev, 2);
    let mut client_sockets = SocketSet::new(vec![]);
    let mut server_sockets = SocketSet::new(vec![]);
    let c = client_sockets.add(udp_socket());
    let s = server_sockets.add(udp_socket());
    client_sockets
        .get_mut::<udp::Socket>(c)
        .bind(49153)
        .unwrap();
    server_sockets.get_mut::<udp::Socket>(s).bind(5353).unwrap();
    let payloads = [vec![7; 1], vec![8; 1200], vec![9; 17]];
    for payload in &payloads {
        client_sockets
            .get_mut::<udp::Socket>(c)
            .send_slice(payload, (IpAddress::v4(192, 0, 2, 2), 5353))
            .unwrap();
    }
    let mut received = Vec::new();
    for tick in 0..100 {
        let now = Instant::from_millis(tick);
        client.poll(now, &mut client_dev, &mut client_sockets);
        server.poll(now, &mut server_dev, &mut server_sockets);
        let socket = server_sockets.get_mut::<udp::Socket>(s);
        while socket.can_recv() {
            let (data, meta) = socket.recv().unwrap();
            assert_eq!(meta.endpoint.addr, IpAddress::v4(192, 0, 2, 1));
            assert_eq!(meta.endpoint.port, 49153);
            let data = data.to_vec();
            socket.send_slice(&data, meta.endpoint).unwrap();
        }
        let socket = client_sockets.get_mut::<udp::Socket>(c);
        while socket.can_recv() {
            let (data, meta) = socket.recv().unwrap();
            assert_eq!(meta.endpoint.addr, IpAddress::v4(192, 0, 2, 2));
            assert_eq!(meta.endpoint.port, 5353);
            received.push(data.to_vec());
        }
        if received.len() == payloads.len() {
            assert_eq!(received, payloads);
            println!("UDP: 1/1200/17-byte datagrams echoed with correct IPs and ports");
            return;
        }
    }
    panic!("UDP virtual deadline");
}
