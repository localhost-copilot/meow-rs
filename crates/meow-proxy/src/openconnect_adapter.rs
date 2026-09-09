//! Shared AnyConnect CSTP/TLS outbound with authentication and isolated reconnect generations.

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

pub use meow_openconnect::auth::Credentials;

mod dns;

/// Authentication and TLS options are intentionally not Debug-printable.
pub struct Options {
    pub server: String,
    pub port: u16,
    pub cookie: Option<String>,
    pub credentials: Option<Credentials>,
    pub server_name: String,
    pub additional_roots: Vec<Vec<u8>>,
    pub mtu: u16,
    pub handshake_timeout: Duration,
    pub udp: bool,
    pub ipv6: bool,
    pub remote_dns_resolve: bool,
    pub dns: Vec<SocketAddr>,
}

struct Parameters {
    options: Options,
    tls: TlsLayer,
}

struct Session {
    generation: u64,
    stack: Stack,
    network: meow_openconnect::NetworkConfig,
    dns: dns::Resolver,
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
    Running(watch::Receiver<Option<SessionResult>>),
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
            cookie: options
                .cookie
                .clone()
                .unwrap_or_else(|| "authenticated-cookie".into()),
            mtu: options.mtu,
            ipv6: options.ipv6,
        };
        request.validate()?;
        if options.dns.len() > 16
            || !options.dns.is_empty() && !options.remote_dns_resolve
            || options.dns.iter().any(|server| {
                server.port() == 0 || server.ip().is_unspecified() || server.ip().is_multicast()
                    || matches!(server.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
                    || matches!(server, SocketAddr::V6(addr) if addr.scope_id() != 0 || addr.ip().to_ipv4_mapped().is_some())
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid VPN DNS servers or remote-dns-resolve is disabled",
            ));
        }
        match (&options.cookie, &options.credentials) {
            (Some(_), None) => {}
            (None, Some(credentials)) => credentials.validate()?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "OpenConnect requires either cookie or username/password",
                ))
            }
        }
        let tls = TlsLayer::new(&TlsConfig {
            additional_roots: options.additional_roots.clone(),
            alpn: vec!["http/1.1".into()],
            ..TlsConfig::new(options.server_name.clone())
        })
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        Ok(Self {
            name: name.to_owned(),
            address,
            parameters: Arc::new(Parameters { options, tls }),
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
                Init::Running(receiver) => receiver.clone(),
                Init::Idle => {
                    let (sender, receiver) = watch::channel(None);
                    *init = Init::Running(receiver.clone());
                    let parameters = Arc::clone(&self.parameters);
                    let cancel = self.shared.cancel.clone();
                    // The supervisor belongs to the adapter, not a waiting dial.
                    // It never owns Shared; dropping the adapter cancels supervision
                    // while application connections can retain their current session.
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = cancel.cancelled() => {},
                            _ = supervise(&parameters, sender) => {},
                        }
                    });
                    receiver
                }
            }
        };
        loop {
            if let Some(result) = receiver.borrow().clone() {
                let session = result.map_err(|error| MeowError::Proxy(error.to_string()))?;
                if !session.stack.is_closed() {
                    return Ok(session);
                }
            }
            receiver
                .changed()
                .await
                .map_err(|_| MeowError::Proxy("OpenConnect initialization cancelled".into()))?;
        }
    }
}

async fn supervise(parameters: &Parameters, sender: watch::Sender<Option<SessionResult>>) {
    let mut generation = 0u64;
    let mut failures = 0u32;
    loop {
        if failures > 0 {
            tokio::time::sleep(Duration::from_secs(1 << (failures - 1).min(4))).await;
        }
        generation += 1;
        let result = tokio::time::timeout(
            parameters.options.handshake_timeout,
            establish(parameters, generation),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "OpenConnect handshake timed out"))
        .and_then(|result| result);
        match result {
            Ok(session) => {
                let started = tokio::time::Instant::now();
                tracing::debug!(generation = session.generation, network = ?session.network, "OpenConnect generation ready");
                sender.send_replace(Some(Ok(Arc::clone(&session))));
                session.stack.closed().await;
                // Every generation owns new channels and a new stack. Retired
                // sockets keep only the failed old generation, never the new sink.
                sender.send_replace(None);
                session.cancel.cancel();
                failures = if started.elapsed() >= Duration::from_secs(30) {
                    1
                } else {
                    failures + 1
                };
                if failures >= 5 {
                    sender.send_replace(Some(Err(
                        "OpenConnect reconnect limit reached; reload node to retry".into(),
                    )));
                    return;
                }
            }
            Err(error) => {
                failures += 1;
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied
                        | io::ErrorKind::InvalidData
                        | io::ErrorKind::InvalidInput
                        | io::ErrorKind::Unsupported
                ) || failures >= 5
                {
                    let reason = if failures >= 5 {
                        format!(
                            "OpenConnect failed after 5 attempts; reload node to retry: {error}"
                        )
                    } else {
                        error.to_string()
                    };
                    sender.send_replace(Some(Err(reason.into())));
                    return;
                }
                tracing::debug!(
                    generation,
                    failures,
                    "OpenConnect transient failure; reconnect pending"
                );
            }
        }
    }
}

async fn establish(parameters: &Parameters, generation: u64) -> io::Result<Arc<Session>> {
    let tcp =
        meow_common::connect_tcp_host(&parameters.options.server, parameters.options.port).await?;
    tcp.set_nodelay(true)?;
    let tls = parameters
        .tls
        .connect(Box::new(tcp))
        .await
        .map_err(|e| match e {
            meow_transport::TransportError::Io(error) => error,
            // TLS verification/configuration errors cannot be repaired by retrying.
            _ => io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("OpenConnect TLS: {e}"),
            ),
        })?;
    let authority = if parameters.options.server.contains(':') {
        format!(
            "[{}]:{}",
            parameters.options.server, parameters.options.port
        )
    } else {
        format!("{}:{}", parameters.options.server, parameters.options.port)
    };
    let (tls, cookie) = if let Some(credentials) = &parameters.options.credentials {
        meow_openconnect::auth::authenticate(tls, &authority, credentials).await?
    } else {
        (
            tokio::io::BufReader::new(tls),
            parameters
                .options
                .cookie
                .clone()
                .expect("validated authentication"),
        )
    };
    let connection = meow_openconnect::connect(
        tls,
        &meow_openconnect::Options {
            authority,
            cookie,
            mtu: parameters.options.mtu,
            ipv6: parameters.options.ipv6,
        },
    )
    .await?;
    let (to_stack, incoming) = mpsc::channel(64);
    let (outgoing, from_stack) = mpsc::channel(64);
    let stack = Stack::with_addresses(
        connection.network.address,
        connection.network.address6,
        connection.network.mtu,
        incoming,
        outgoing,
    )?;
    let network = connection.network.clone();
    let servers = if parameters.options.dns.is_empty() {
        network
            .dns
            .iter()
            .map(|ip| SocketAddr::new(*ip, 53))
            .collect()
    } else {
        parameters.options.dns.clone()
    };
    if parameters.options.remote_dns_resolve
        && !servers.iter().any(|server| stack.supports(server.ip()))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no usable VPN DNS server; local fallback is disabled",
        ));
    }
    let cancel = CancellationToken::new();
    let worker_cancel = cancel.clone();
    tokio::spawn(async move {
        if let Err(error) = connection.run(from_stack, to_stack, worker_cancel).await {
            tracing::debug!(%error, "OpenConnect CSTP session ended");
        }
    });
    Ok(Arc::new(Session {
        generation,
        stack,
        network,
        cancel,
        dns: dns::Resolver::new(servers),
    }))
}

async fn destination(metadata: &Metadata, stack: &Stack) -> Result<SocketAddr> {
    if let Some(ip) = metadata.dst_ip.filter(|ip| stack.supports(*ip)) {
        return Ok(SocketAddr::new(ip, metadata.dst_port));
    }
    if metadata.host.is_empty() {
        return Err(MeowError::Proxy(
            "OpenConnect destination requires a negotiated address family or hostname".into(),
        ));
    }
    meow_common::resolve_host_all(&metadata.host, metadata.dst_port)
        .await?
        .into_iter()
        .find(|address| stack.supports(address.ip()))
        .ok_or_else(|| MeowError::Dns("OpenConnect target has no negotiated address family".into()))
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
        let session = self.session().await?;
        let target = if self.parameters.options.remote_dns_resolve && !metadata.host.is_empty() {
            session
                .dns
                .resolve(&session.stack, &metadata.host, metadata.dst_port)
                .await?
        } else {
            destination(metadata, &session.stack).await?
        };
        let stream = session.stack.connect(target).await?;
        Ok(Box::new(Connection {
            stream,
            _session: session,
        }))
    }
    async fn resolve_udp_destination(
        &self,
        metadata: &Metadata,
    ) -> Result<Option<meow_common::adapter::ResolvedUdpDestination>> {
        if !self.parameters.options.remote_dns_resolve || metadata.host.is_empty() {
            return Ok(None);
        }
        let session = self.session().await?;
        let address = session
            .dns
            .resolve(&session.stack, &metadata.host, metadata.dst_port)
            .await?;
        Ok(Some(meow_common::adapter::ResolvedUdpDestination {
            address,
            outbound: None,
        }))
    }
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.support_udp() {
            return Err(MeowError::UdpNotSupported);
        }
        let session = self.session().await?;
        // Resolution used for the NAT key may have raced a reconnect. Bind the
        // actual destination to this socket's generation before sending traffic.
        let target = if self.parameters.options.remote_dns_resolve && !metadata.host.is_empty() {
            let resolved = session
                .dns
                .resolve(&session.stack, &metadata.host, metadata.dst_port)
                .await?;
            Some((
                metadata
                    .dst_ip
                    .map_or(resolved, |ip| SocketAddr::new(ip, metadata.dst_port)),
                resolved,
            ))
        } else {
            None
        };
        let socket = session.stack.bind_udp().await?;
        Ok(Box::new(PacketConnection {
            socket,
            target,
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
    target: Option<(SocketAddr, SocketAddr)>,
    _session: Arc<Session>,
}
#[async_trait]
impl ProxyPacketConn for PacketConnection {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Ok(self.socket.recv_from(buf).await?)
    }
    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        let addr = self
            .target
            .filter(|(original, _)| original == addr)
            .map_or(*addr, |(_, resolved)| resolved);
        Ok(self.socket.send_to(buf, addr).await?)
    }
    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr())
    }
    fn close(&self) -> Result<()> {
        self.socket.close();
        Ok(())
    }
}
