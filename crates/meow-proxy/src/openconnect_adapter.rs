//! Shared, cookie-authenticated AnyConnect CSTP/TLS outbound.

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_netstack::Stack;
use meow_transport::tls::{TlsConfig, TlsLayer};
use meow_transport::Transport;
use parking_lot::Mutex;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

/// Cookie and TLS options are intentionally not Debug-printable.
pub struct Options {
    pub server: String,
    pub port: u16,
    pub cookie: String,
    pub server_name: String,
    pub additional_roots: Vec<Vec<u8>>,
    pub mtu: u16,
    pub handshake_timeout: Duration,
    pub udp: bool,
}

struct Parameters {
    options: Options,
    tls: TlsLayer,
    request: meow_openconnect::Options,
}

struct Session {
    stack: Stack,
    cancel: CancellationToken,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

type SessionResult = std::result::Result<Arc<Session>, Arc<str>>;
enum Init {
    Idle,
    Starting(watch::Receiver<Option<SessionResult>>),
    Done(SessionResult),
}
struct Shared {
    init: Mutex<Init>,
    cancel: CancellationToken,
}
impl Drop for Shared {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub struct OpenConnectAdapter {
    name: String,
    address: String,
    parameters: Arc<Parameters>,
    shared: Arc<Shared>,
    health: ProxyHealth,
}

impl OpenConnectAdapter {
    pub fn new(name: &str, options: Options) -> io::Result<Self> {
        if name.is_empty()
            || options.server.is_empty()
            || options.port == 0
            || options.server_name.is_empty()
            || options.handshake_timeout.is_zero()
            || options.handshake_timeout > Duration::from_secs(300)
            || options
                .server
                .bytes()
                .any(|b| b <= b' ' || b == b'/' || b == b'@' || b == b'\x7f')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid OpenConnect endpoint or handshake timeout",
            ));
        }
        let address = if options.server.contains(':') {
            format!("[{}]:{}", options.server, options.port)
        } else {
            format!("{}:{}", options.server, options.port)
        };
        let request = meow_openconnect::Options {
            authority: address.clone(),
            cookie: options.cookie.clone(),
            mtu: options.mtu,
        };
        request.validate()?;
        let tls = TlsLayer::new(&TlsConfig {
            additional_roots: options.additional_roots.clone(),
            alpn: vec!["http/1.1".into()],
            ..TlsConfig::new(options.server_name.clone())
        })
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        Ok(Self {
            name: name.to_owned(),
            address,
            parameters: Arc::new(Parameters {
                options,
                tls,
                request,
            }),
            shared: Arc::new(Shared {
                init: Mutex::new(Init::Idle),
                cancel: CancellationToken::new(),
            }),
            health: ProxyHealth::new(),
        })
    }

    async fn session(&self) -> Result<Arc<Session>> {
        let mut receiver = {
            let mut init = self.shared.init.lock();
            match &*init {
                Init::Done(result) => return usable(result.clone()),
                Init::Starting(receiver) => receiver.clone(),
                Init::Idle => {
                    let (sender, receiver) = watch::channel(None);
                    *init = Init::Starting(receiver.clone());
                    let parameters = Arc::clone(&self.parameters);
                    let owner = Arc::downgrade(&self.shared);
                    let cancel = self.shared.cancel.clone();
                    // Initialization belongs to the adapter, not the first waiter.
                    // Its task holds only a Weak back-reference, so cancellation or
                    // dropping all adapters cannot create a permanent task cycle.
                    tokio::spawn(async move {
                        let result = tokio::select! {
                            _ = cancel.cancelled() => return,
                            result = tokio::time::timeout(parameters.options.handshake_timeout, establish(&parameters)) => {
                                result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "OpenConnect handshake timed out")).and_then(|r| r)
                            },
                        }.map_err(|e| Arc::<str>::from(e.to_string()));
                        sender.send_replace(Some(result.clone()));
                        if let Some(owner) = owner.upgrade() {
                            *owner.init.lock() = Init::Done(result);
                        }
                    });
                    receiver
                }
            }
        };
        loop {
            if let Some(result) = receiver.borrow().clone() {
                return usable(result);
            }
            receiver
                .changed()
                .await
                .map_err(|_| MeowError::Proxy("OpenConnect initialization cancelled".into()))?;
        }
    }
}

fn usable(result: SessionResult) -> Result<Arc<Session>> {
    let session = result.map_err(|e| MeowError::Proxy(e.to_string()))?;
    if session.stack.is_closed() {
        return Err(MeowError::Proxy(
            "OpenConnect session closed; reload the node to reconnect".into(),
        ));
    }
    Ok(session)
}

async fn establish(parameters: &Parameters) -> io::Result<Arc<Session>> {
    let tcp =
        meow_common::connect_tcp_host(&parameters.options.server, parameters.options.port).await?;
    tcp.set_nodelay(true)?;
    let tls = parameters
        .tls
        .connect(Box::new(tcp))
        .await
        .map_err(|e| io::Error::other(format!("OpenConnect TLS: {e}")))?;
    let connection = meow_openconnect::connect(tls, &parameters.request).await?;
    let (to_stack, incoming) = mpsc::channel(64);
    let (outgoing, from_stack) = mpsc::channel(64);
    let stack = Stack::new(
        connection.network.address,
        connection.network.mtu,
        incoming,
        outgoing,
    )?;
    let cancel = CancellationToken::new();
    let worker_cancel = cancel.clone();
    tokio::spawn(async move {
        if let Err(error) = connection.run(from_stack, to_stack, worker_cancel).await {
            tracing::debug!(%error, "OpenConnect CSTP session ended");
        }
    });
    Ok(Arc::new(Session { stack, cancel }))
}

async fn destination(metadata: &Metadata) -> Result<SocketAddr> {
    if let Some(std::net::IpAddr::V4(ip)) = metadata.dst_ip {
        return Ok(SocketAddr::new(ip.into(), metadata.dst_port));
    }
    if metadata.host.is_empty() {
        return Err(MeowError::Proxy(
            "OpenConnect requires an IPv4 destination or hostname".into(),
        ));
    }
    meow_common::resolve_host_all(&metadata.host, metadata.dst_port)
        .await?
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| MeowError::Dns("OpenConnect target has no IPv4 address".into()))
}

#[async_trait]
impl ProxyAdapter for OpenConnectAdapter {
    fn name(&self) -> &str {
        &self.name
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::OpenConnect
    }
    fn addr(&self) -> &str {
        &self.address
    }
    fn support_udp(&self) -> bool {
        self.parameters.options.udp
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let target = destination(metadata).await?;
        let session = self.session().await?;
        let stream = session.stack.connect(target).await?;
        Ok(Box::new(Connection {
            stream,
            _session: session,
        }))
    }
    async fn dial_udp(&self, _: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.support_udp() {
            return Err(MeowError::UdpNotSupported);
        }
        let session = self.session().await?;
        let socket = session.stack.bind_udp().await?;
        Ok(Box::new(PacketConnection {
            socket,
            _session: session,
        }))
    }
}

struct Connection {
    stream: meow_netstack::TcpStream,
    _session: Arc<Session>,
}
impl ProxyConn for Connection {}
impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

struct PacketConnection {
    socket: meow_netstack::UdpSocket,
    _session: Arc<Session>,
}
#[async_trait]
impl ProxyPacketConn for PacketConnection {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Ok(self.socket.recv_from(buf).await?)
    }
    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        Ok(self.socket.send_to(buf, *addr).await?)
    }
    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr())
    }
    fn close(&self) -> Result<()> {
        self.socket.close();
        Ok(())
    }
}
