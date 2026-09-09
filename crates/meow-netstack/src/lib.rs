//! Tokio TCP/UDP sockets backed by an independent smoltcp IP stack.
//! Each stack owns its socket set in one task and exchanges raw IP packets with
//! its caller. No system interface, route, or global network stack is installed.

mod device;
mod driver;

use parking_lot::Mutex;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_util::sync::CancellationToken;

type Packet = (Vec<u8>, SocketAddr);
type Failure = Arc<Mutex<Option<String>>>;
const SOCKET_BUFFER: usize = 32768;
const MAX_SOCKETS: usize = 1024;

fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "userspace IP stack closed",
    )
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

struct Lifetime {
    commands: mpsc::Sender<driver::Command>,
    cancel: CancellationToken,
    wake: Arc<Notify>,
    failure: Failure,
    address: Option<Ipv4Addr>,
    address6: Option<Ipv6Addr>,
    mtu: u16,
}
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// A shared stack handle. Its task exits after the last handle/socket is dropped.
#[derive(Clone)]
pub struct Stack(Arc<Lifetime>);

impl Stack {
    pub fn new(
        address: Ipv4Addr,
        mtu: u16,
        incoming: mpsc::Receiver<Vec<u8>>,
        outgoing: mpsc::Sender<Vec<u8>>,
    ) -> io::Result<Self> {
        Self::with_addresses(Some(address), None, mtu, incoming, outgoing)
    }

    /// Create an independent stack for the negotiated address families.
    /// IPv6 requires an MTU of at least 1280. Must be called in a Tokio runtime.
    pub fn with_addresses(
        address: Option<Ipv4Addr>,
        address6: Option<Ipv6Addr>,
        mtu: u16,
        incoming: mpsc::Receiver<Vec<u8>>,
        outgoing: mpsc::Sender<Vec<u8>>,
    ) -> io::Result<Self> {
        if address.is_none() && address6.is_none()
            || address
                .is_some_and(|ip| ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast())
            || address6.is_some_and(|ip| {
                ip.is_unspecified() || ip.is_multicast() || ip.to_ipv4_mapped().is_some()
            })
            || !(576..=1500).contains(&mtu)
            || address6.is_some() && mtu < 1280
        {
            return Err(invalid("invalid userspace IP addresses or MTU"));
        }
        let (tx, rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let wake = Arc::new(Notify::new());
        let failure = Arc::new(Mutex::new(None));
        let actor = driver::Driver::new(address, address6, mtu, rx, Arc::clone(&wake));
        let stack = Self(Arc::new(Lifetime {
            commands: tx,
            cancel: cancel.clone(),
            wake,
            failure: Arc::clone(&failure),
            address,
            address6,
            mtu,
        }));
        tokio::spawn(async move {
            // Publish failure before dropping bridge endpoints, so awakened readers
            // observe an error rather than mistaking tunnel failure for orderly EOF.
            let mut actor = actor;
            let result = actor.run(incoming, outgoing, cancel.clone()).await;
            *failure.lock() = Some(
                result
                    .err()
                    .map_or_else(|| "userspace IP stack closed".to_owned(), |e| e.to_string()),
            );
            cancel.cancel();
        });
        Ok(stack)
    }

    pub fn is_closed(&self) -> bool {
        self.0.cancel.is_cancelled()
    }

    /// Stop this generation, waking pending connections and packet readers.
    pub fn close(&self) {
        *self.0.failure.lock() = Some("userspace IP stack closed".into());
        self.0.cancel.cancel();
    }

    pub async fn closed(&self) {
        self.0.cancel.cancelled().await;
    }

    pub fn supports(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(_) => self.0.address.is_some(),
            IpAddr::V6(_) => self.0.address6.is_some(),
        }
    }

    fn validate_destination(&self, destination: SocketAddr) -> io::Result<()> {
        let ip = destination.ip();
        if destination.port() == 0
            || ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
            || matches!(destination, SocketAddr::V6(addr) if addr.scope_id() != 0 || addr.ip().to_ipv4_mapped().is_some())
        {
            return Err(invalid("invalid userspace IP destination"));
        }
        if !self.supports(ip) {
            return Err(invalid("destination address family was not negotiated"));
        }
        Ok(())
    }

    pub async fn connect(&self, destination: SocketAddr) -> io::Result<TcpStream> {
        self.validate_destination(destination)?;
        let (application, bridge) = tokio::io::duplex(SOCKET_BUFFER);
        let flow = Flow::new();
        let stream = TcpStream {
            stream: application,
            stack: self.clone(),
            flow: Arc::clone(&flow),
        };
        let (ready, result) = oneshot::channel();
        self.0
            .commands
            .send(driver::Command::Tcp {
                destination,
                bridge,
                flow,
                ready,
            })
            .await
            .map_err(|_| closed())?;
        result.await.map_err(|_| closed())??;
        Ok(stream)
    }

    pub async fn bind_udp(&self) -> io::Result<UdpSocket> {
        let flow = Flow::new();
        let (send, outgoing) = mpsc::channel(32);
        let (incoming, receive) = mpsc::channel(32);
        let (ready, result) = oneshot::channel();
        // Cancellation while awaiting registration must also dispose the actor socket.
        let mut socket = UdpSocket {
            stack: self.clone(),
            flow: Arc::clone(&flow),
            send,
            receive: tokio::sync::Mutex::new(receive),
            port: 0,
        };
        self.0
            .commands
            .send(driver::Command::Udp {
                outgoing,
                incoming,
                flow,
                ready,
            })
            .await
            .map_err(|_| closed())?;
        socket.port = result.await.map_err(|_| closed())??;
        Ok(socket)
    }
}

struct Flow {
    cancel: CancellationToken,
    failure: Mutex<Option<String>>,
}
impl Flow {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cancel: CancellationToken::new(),
            failure: Mutex::new(None),
        })
    }
    fn error(&self, stack: &Stack) -> io::Result<()> {
        if let Some(reason) = self
            .failure
            .lock()
            .as_ref()
            .or(stack.0.failure.lock().as_ref())
        {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                reason.clone(),
            ));
        }
        if self.cancel.is_cancelled() {
            return Err(closed());
        }
        Ok(())
    }
}

/// A full-duplex byte stream. Shutdown half-closes TCP after queued writes.
pub struct TcpStream {
    stream: DuplexStream,
    stack: Stack,
    flow: Arc<Flow>,
}
impl Drop for TcpStream {
    fn drop(&mut self) {
        self.flow.cancel.cancel();
        self.stack.0.wake.notify_one();
    }
}
impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.flow.error(&self.stack)?;
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() == before {
            // The driver may publish a failure and drop its bridge between the
            // first check and poll_read. Never translate that race into clean EOF.
            self.flow.error(&self.stack)?;
        }
        result
    }
}
impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.flow.error(&self.stack)?;
        Pin::new(&mut self.stream).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flow.error(&self.stack)?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flow.error(&self.stack)?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// An ephemeral UDP socket accepting all negotiated address families.
/// Send completion means queued, not acknowledged.
/// Receive buffers are bounded; UDP packets are dropped when the application is slow.
pub struct UdpSocket {
    stack: Stack,
    flow: Arc<Flow>,
    send: mpsc::Sender<Packet>,
    receive: tokio::sync::Mutex<mpsc::Receiver<Packet>>,
    port: u16,
}
impl UdpSocket {
    pub fn local_addr(&self) -> SocketAddr {
        let address = self.stack.0.address.map_or_else(
            || self.stack.0.address6.expect("negotiated family").into(),
            IpAddr::V4,
        );
        SocketAddr::new(address, self.port)
    }
    pub fn close(&self) {
        self.flow.cancel.cancel();
        self.stack.0.wake.notify_one();
    }
    pub async fn send_to(&self, data: &[u8], destination: SocketAddr) -> io::Result<usize> {
        self.flow.error(&self.stack)?;
        self.stack.validate_destination(destination)?;
        let overhead = if destination.is_ipv4() { 28 } else { 48 };
        if data.len() > usize::from(self.stack.0.mtu) - overhead {
            return Err(invalid("UDP payload exceeds tunnel MTU"));
        }
        tokio::select! {
            _ = self.flow.cancel.cancelled() => Err(closed()),
            result = self.send.send((data.to_vec(), destination)) => {
                result.map_err(|_| closed())?;
                self.stack.0.wake.notify_one();
                Ok(data.len())
            },
        }
    }
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.flow.error(&self.stack)?;
        let mut receiver = self.receive.lock().await;
        let packet = tokio::select! {
            _ = self.flow.cancel.cancelled() => return Err(closed()),
            packet = receiver.recv() => packet.ok_or_else(closed)?,
        };
        let n = buf.len().min(packet.0.len());
        buf[..n].copy_from_slice(&packet.0[..n]);
        Ok((n, packet.1))
    }
}
impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.close();
    }
}
