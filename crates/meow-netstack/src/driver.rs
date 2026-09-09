use crate::{closed, device::RawIp, Flow, Packet, MAX_SOCKETS, SOCKET_BUFFER};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub(crate) enum Command {
    Tcp {
        destination: SocketAddr,
        bridge: DuplexStream,
        flow: Arc<Flow>,
        ready: oneshot::Sender<io::Result<()>>,
    },
    Udp {
        outgoing: mpsc::Receiver<Packet>,
        incoming: mpsc::Sender<Packet>,
        flow: Arc<Flow>,
        ready: oneshot::Sender<io::Result<u16>>,
    },
}

struct Tcp {
    bridge: DuplexStream,
    ready: Option<oneshot::Sender<io::Result<()>>>,
    local_eof: bool,
    remote_eof: bool,
    close_deadline: Option<Instant>,
}

struct Udp {
    outgoing: mpsc::Receiver<Packet>,
    incoming: mpsc::Sender<Packet>,
    pending: Option<Packet>,
}

enum Socket {
    Tcp(Tcp),
    Udp(Udp),
    RetiringTcp,
}
struct Entry {
    handle: SocketHandle,
    port: u16,
    flow: Arc<Flow>,
    socket: Socket,
}

pub(crate) struct Driver {
    iface: Interface,
    device: RawIp,
    sockets: SocketSet<'static>,
    entries: Vec<Entry>,
    commands: mpsc::Receiver<Command>,
    wake: Arc<Notify>,
    next_port: u16,
    tcp_send_budget: usize,
}

impl Driver {
    pub fn new(
        address: Option<Ipv4Addr>,
        address6: Option<Ipv6Addr>,
        mtu: u16,
        tcp_send_budget: usize,
        commands: mpsc::Receiver<Command>,
        wake: Arc<Notify>,
    ) -> Self {
        let mut device = RawIp {
            incoming: VecDeque::new(),
            outgoing: VecDeque::new(),
            mtu: usize::from(mtu),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, SmolInstant::ZERO);
        iface.update_ip_addrs(|addresses| {
            if let Some(address) = address {
                addresses
                    .push(IpCidr::new(address.into(), 32))
                    .expect("IPv4 address fits");
            }
            if let Some(address) = address6 {
                addresses
                    .push(IpCidr::new(address.into(), 128))
                    .expect("IPv6 address fits");
            }
        });
        // An IP-only link has no ARP gateway. The route selects this tunnel;
        // the destination in emitted IP packets remains the remote endpoint.
        if let Some(address) = address {
            iface
                .routes_mut()
                .add_default_ipv4_route(address)
                .expect("IPv4 route fits");
        }
        if let Some(address) = address6 {
            iface
                .routes_mut()
                .add_default_ipv6_route(address)
                .expect("IPv6 route fits");
        }
        Self {
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            entries: vec![],
            commands,
            wake,
            next_port: 49152,
            tcp_send_budget,
        }
    }

    fn register(&mut self, command: Command) {
        if self.entries.len() >= MAX_SOCKETS {
            let error =
                || io::Error::new(io::ErrorKind::OutOfMemory, "userspace socket limit reached");
            match command {
                Command::Tcp { ready, .. } => {
                    let _ = ready.send(Err(error()));
                }
                Command::Udp { ready, .. } => {
                    let _ = ready.send(Err(error()));
                }
            }
            return;
        }
        while self
            .entries
            .iter()
            .any(|entry| entry.port == self.next_port)
        {
            self.next_port = self.next_port.checked_add(1).unwrap_or(49152);
        }
        let port = self.next_port;
        self.next_port = self.next_port.checked_add(1).unwrap_or(49152);
        let (handle, flow, socket) = match command {
            Command::Tcp {
                destination,
                bridge,
                flow,
                ready,
            } => {
                let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
                    tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
                );
                socket.set_timeout(Some(SmolDuration::from_secs(30)));
                socket.set_nagle_enabled(false);
                if socket
                    .connect(
                        self.iface.context(),
                        (IpAddress::from(destination.ip()), destination.port()),
                        port,
                    )
                    .is_err()
                {
                    let _ = ready.send(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "userspace TCP connect rejected",
                    )));
                    return;
                }
                (
                    self.sockets.add(socket),
                    flow,
                    Socket::Tcp(Tcp {
                        bridge,
                        ready: Some(ready),
                        local_eof: false,
                        remote_eof: false,
                        close_deadline: None,
                    }),
                )
            }
            Command::Udp {
                outgoing,
                incoming,
                flow,
                ready,
            } => {
                let mut socket = udp::Socket::new(
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; 32],
                        vec![0; SOCKET_BUFFER],
                    ),
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; 32],
                        vec![0; SOCKET_BUFFER],
                    ),
                );
                if socket.bind(port).is_err() {
                    let _ = ready.send(Err(closed()));
                    return;
                }
                if ready.send(Ok(port)).is_err() {
                    return;
                }
                (
                    self.sockets.add(socket),
                    flow,
                    Socket::Udp(Udp {
                        outgoing,
                        incoming,
                        pending: None,
                    }),
                )
            }
        };
        self.entries.push(Entry {
            handle,
            port,
            flow,
            socket,
        });
    }

    pub async fn run(
        &mut self,
        mut incoming: mpsc::Receiver<Vec<u8>>,
        outgoing: mpsc::Sender<Vec<u8>>,
        cancel: CancellationToken,
    ) -> io::Result<()> {
        let epoch = Instant::now();
        loop {
            let now = SmolInstant::from_millis(epoch.elapsed().as_millis() as i64);
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            let delay = if self.device.outgoing.len() >= 64 {
                Duration::from_secs(1)
            } else {
                self.iface
                    .poll_delay(now, &self.sockets)
                    .map_or(Duration::from_secs(1), |n| {
                        Duration::from_millis(n.total_millis()).min(Duration::from_secs(1))
                    })
            };
            let wake = Arc::clone(&self.wake);
            let tcp_flows = self
                .entries
                .iter()
                .filter(|entry| {
                    if !matches!(entry.socket, Socket::Tcp(_)) || entry.flow.cancel.is_cancelled() {
                        return false;
                    }
                    let socket = self.sockets.get::<tcp::Socket>(entry.handle);
                    socket.may_send() || socket.send_queue() != 0
                })
                .count()
                .max(1);
            let tcp_send_limit =
                (self.tcp_send_budget / tcp_flows).clamp(self.device.mtu, SOCKET_BUFFER);
            let tcp_total_limit = self.tcp_send_budget.max(tcp_flows * self.device.mtu);
            // All bridge and channel wakers are registered in this same select.
            // A full packet sink never blocks command handling or tunnel reads.
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = wake.notified() => {},
                _ = tokio::time::sleep(delay) => {},
                command = self.commands.recv() => self.register(command.ok_or_else(closed)?),
                packet = incoming.recv(), if self.device.incoming.len() < 64 => {
                    let packet = packet.ok_or_else(closed)?;
                    if packet.len() > self.device.mtu { return Err(io::Error::new(io::ErrorKind::InvalidData, "incoming IP packet exceeds MTU")); }
                    self.device.incoming.push_back(packet);
                },
                permit = outgoing.reserve(), if !self.device.outgoing.is_empty() => {
                    permit.map_err(|_| closed())?.send(self.device.outgoing.pop_front().expect("nonempty queue"));
                },
                _ = poll_fn(|cx| Self::pump(&mut self.entries, &mut self.sockets, tcp_send_limit, tcp_total_limit, cx)) => {},
            }
        }
    }

    fn pump(
        entries: &mut Vec<Entry>,
        sockets: &mut SocketSet<'static>,
        tcp_send_limit: usize,
        tcp_total_limit: usize,
        cx: &mut Context<'_>,
    ) -> Poll<()> {
        let mut progress = false;
        // A new flow must wait for credits held by older flows, whose queued
        // bytes cannot be recalled when their per-flow share shrinks.
        let queued: usize = entries
            .iter()
            .filter(|entry| matches!(entry.socket, Socket::Tcp(_)))
            .map(|entry| sockets.get::<tcp::Socket>(entry.handle).send_queue())
            .sum();
        let mut send_available = tcp_total_limit.saturating_sub(queued);
        entries.retain_mut(|entry| {
            let mut retain = !entry.flow.cancel.is_cancelled();
            if matches!(entry.socket, Socket::RetiringTcp) {
                // smoltcp clears the endpoint after dispatching the RST. Keep
                // this tombstone across a full packet sink until that happens.
                retain = sockets
                    .get::<tcp::Socket>(entry.handle)
                    .remote_endpoint()
                    .is_some();
            }
            if retain {
                retain = match &mut entry.socket {
                    Socket::Tcp(tcp) => pump_tcp(
                        tcp,
                        sockets.get_mut(entry.handle),
                        &entry.flow,
                        tcp_send_limit,
                        &mut send_available,
                        cx,
                        &mut progress,
                    ),
                    Socket::Udp(udp) => {
                        pump_udp(udp, sockets.get_mut(entry.handle), cx, &mut progress)
                    }
                    Socket::RetiringTcp => true,
                };
            }
            if !retain {
                if matches!(entry.socket, Socket::Tcp(_)) {
                    let socket = sockets.get_mut::<tcp::Socket>(entry.handle);
                    if socket.remote_endpoint().is_some() {
                        socket.abort();
                        // Drop the bridge now to wake readers; only the protocol
                        // socket remains until its reset reaches the packet queue.
                        entry.socket = Socket::RetiringTcp;
                        progress = true;
                        return true;
                    }
                }
                sockets.remove(entry.handle);
                progress = true;
            }
            retain
        });
        if progress {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

fn pump_tcp(
    entry: &mut Tcp,
    socket: &mut tcp::Socket<'_>,
    flow: &Flow,
    send_limit: usize,
    send_available: &mut usize,
    cx: &mut Context<'_>,
    progress: &mut bool,
) -> bool {
    if entry.ready.is_some() {
        if matches!(
            socket.state(),
            tcp::State::Established | tcp::State::CloseWait
        ) {
            socket.set_timeout(None);
            socket.set_keep_alive(Some(SmolDuration::from_secs(30)));
            if entry
                .ready
                .take()
                .expect("pending connect")
                .send(Ok(()))
                .is_err()
            {
                socket.abort();
                return false;
            }
            *progress = true;
        } else if socket.state() == tcp::State::Closed {
            let _ = entry
                .ready
                .take()
                .expect("pending connect")
                .send(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "userspace TCP handshake failed",
                )));
            return false;
        } else {
            return true;
        }
    }
    if socket.state() == tcp::State::Closed {
        if !entry.remote_eof {
            *flow.failure.lock() = Some("userspace TCP connection reset".to_owned());
        }
        return false;
    }
    if entry
        .close_deadline
        .is_some_and(|deadline| Instant::now() >= deadline)
    {
        *flow.failure.lock() = Some("userspace TCP close timed out".to_owned());
        socket.abort();
        return false;
    }
    if !entry.local_eof
        && socket.can_send()
        && socket.send_queue() < send_limit
        && *send_available != 0
    {
        let capacity = (send_limit - socket.send_queue())
            .min(*send_available)
            .min(8192);
        let mut scratch = [0; 8192];
        let mut buffer = ReadBuf::new(&mut scratch[..capacity]);
        match Pin::new(&mut entry.bridge).poll_read(cx, &mut buffer) {
            Poll::Ready(Ok(())) => {
                if buffer.filled().is_empty() {
                    socket.close();
                    entry.local_eof = true;
                    entry.close_deadline = Some(Instant::now() + Duration::from_secs(30));
                } else if socket.send_slice(buffer.filled()).is_err() {
                    socket.abort();
                    return false;
                } else {
                    *send_available -= buffer.filled().len();
                }
                *progress = true;
            }
            Poll::Ready(Err(_)) => {
                socket.abort();
                return false;
            }
            Poll::Pending => {}
        }
    }
    let mut broken = false;
    if socket.can_recv() {
        let _ = socket.recv(
            |data| match Pin::new(&mut entry.bridge).poll_write(cx, data) {
                Poll::Ready(Ok(n)) if n > 0 => {
                    *progress = true;
                    (n, ())
                }
                Poll::Ready(_) => {
                    broken = true;
                    (0, ())
                }
                Poll::Pending => (0, ()),
            },
        );
    }
    if broken {
        socket.abort();
        return false;
    }
    if !socket.may_recv()
        && !entry.remote_eof
        && Pin::new(&mut entry.bridge).poll_shutdown(cx).is_ready()
    {
        entry.remote_eof = true;
        *progress = true;
    }
    true
}

fn pump_udp(
    entry: &mut Udp,
    socket: &mut udp::Socket<'_>,
    cx: &mut Context<'_>,
    progress: &mut bool,
) -> bool {
    if entry.pending.is_none() {
        match entry.outgoing.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                entry.pending = Some(packet);
                *progress = true;
            }
            Poll::Ready(None) => return false,
            Poll::Pending => {}
        }
    }
    if let Some((bytes, target)) = entry.pending.as_ref() {
        if socket
            .send_slice(bytes, (IpAddress::from(target.ip()), target.port()))
            .is_ok()
        {
            entry.pending = None;
            *progress = true;
        }
    }
    // UDP has no backpressure to its peer. Drop when the bounded application
    // inbox is full rather than stalling every TCP connection on this tunnel.
    while socket.can_recv() {
        if let Ok((packet, meta)) = socket.recv() {
            let _ = entry.incoming.try_send((
                packet.to_vec(),
                SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port),
            ));
            *progress = true;
        }
    }
    true
}
