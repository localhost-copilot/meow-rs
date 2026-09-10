//! Shared AnyConnect CSTP/TLS outbound with authentication and isolated reconnect generations.

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_netstack::Stack;
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
pub use meow_openconnect::auth::{AuthOptions, FormEntry};
pub use meow_openconnect::DtlsMode;

mod dns;
mod tls;
mod underlay;
pub use meow_openconnect::compression::Mode as Compression;
pub use meow_openconnect::token::Token;
pub use meow_openconnect::{
    settings::{ClientProfile, Mobile},
    ConnectSettings,
};
pub use tls::TlsOptions;
pub use underlay::{IpVersion, NetworkOptions};

pub struct AdvancedOptions {
    pub dialer: Arc<dyn crate::dialer::TcpDialer>,
    pub network: NetworkOptions,
    pub tls: TlsOptions,
    pub auth: AuthOptions,
    pub connection: ConnectSettings,
    pub queue_length: usize,
    pub dtls_resumption_only: bool,
    pub legacy_dtls: bool,
    pub dtls_local_port: u16,
    pub reconnect_timeout: Duration,
}

impl Default for AdvancedOptions {
    fn default() -> Self {
        Self {
            dialer: Arc::new(crate::dialer::DirectDialer),
            network: NetworkOptions::default(),
            tls: TlsOptions::default(),
            auth: AuthOptions::default(),
            connection: ConnectSettings::default(),
            queue_length: 32,
            dtls_resumption_only: false,
            legacy_dtls: true,
            dtls_local_port: 0,
            reconnect_timeout: Duration::from_secs(300),
        }
    }
}

fn validate_header(value: &str) -> io::Result<()> {
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid OpenConnect header value",
        ));
    }
    Ok(())
}

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
    pub dtls_mode: DtlsMode,
}

struct Parameters {
    options: Options,
    advanced: AdvancedOptions,
    tls: tls::Connector,
    underlay: Arc<underlay::Underlay>,
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
        Self::new_configured(name, options, AdvancedOptions::default())
    }

    pub fn new_configured(
        name: &str,
        options: Options,
        mut advanced: AdvancedOptions,
    ) -> io::Result<Self> {
        if let Some(identity) = tls::McaIdentity::new(&advanced.tls)? {
            advanced.auth.mca = Some(Arc::new(identity));
        }
        advanced.connection.profile.validate()?;
        advanced.network.validate()?;
        advanced.auth.validate()?;
        if !(1..=4096).contains(&advanced.queue_length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "queue-length must be between 1 and 4096",
            ));
        }
        if options.dtls_mode != DtlsMode::Off && !cfg!(all(feature = "openconnect-dtls", unix)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DTLS requires the openconnect-dtls feature and a supported Unix platform",
            ));
        }
        if name.is_empty()
            || options.server.is_empty()
            || options.port == 0
            || options.server_name.is_empty()
            || options
                .server
                .bytes()
                .any(|b| b <= b' ' || b == b'/' || b == b'@' || b == b'\x7f')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid OpenConnect endpoint",
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
            mtu: if options.mtu == 0 { 1280 } else { options.mtu },
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
            (None, Some(credentials))
                if !credentials.username.is_empty() || !advanced.tls.certificate.is_empty() =>
            {
                credentials.validate()?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "OpenConnect requires a cookie, username or client certificate",
                ))
            }
        }
        let tls = tls::Connector::new(
            &options.server_name,
            &options.additional_roots,
            &advanced.tls,
        )?;
        let underlay = Arc::new(underlay::Underlay {
            dialer: Arc::clone(&advanced.dialer),
            options: advanced.network.clone(),
        });
        Ok(Self {
            name: name.to_owned(),
            address,
            parameters: Arc::new(Parameters {
                options,
                advanced,
                tls,
                underlay,
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
    let mut retry_deadline: Option<tokio::time::Instant> = None;
    loop {
        if retry_deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
            sender.send_replace(Some(Err(
                "OpenConnect reconnect timeout reached; reload node to retry".into(),
            )));
            return;
        }
        if failures > 0 {
            let retry = tokio::time::Instant::now()
                + Duration::from_millis((250u64 << (failures - 1).min(7)).min(30_000));
            tokio::time::sleep_until(retry_deadline.map_or(retry, |deadline| deadline.min(retry)))
                .await;
            if retry_deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
                continue;
            }
        }
        generation += 1;
        let handshake_deadline = (!parameters.options.handshake_timeout.is_zero())
            .then(|| tokio::time::Instant::now() + parameters.options.handshake_timeout);
        let deadline = match (handshake_deadline, retry_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let result = if let Some(deadline) = deadline {
            tokio::time::timeout_at(deadline, establish(parameters, generation))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "OpenConnect handshake timed out")
                })
                .and_then(|result| result)
        } else {
            establish(parameters, generation).await
        };
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
                if started.elapsed() >= Duration::from_secs(30) || retry_deadline.is_none() {
                    retry_deadline =
                        Some(tokio::time::Instant::now() + parameters.advanced.reconnect_timeout);
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
                ) {
                    let reason = error.to_string();
                    sender.send_replace(Some(Err(reason.into())));
                    return;
                }
                if retry_deadline.is_none() {
                    retry_deadline =
                        Some(tokio::time::Instant::now() + parameters.advanced.reconnect_timeout);
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
    let (peer, mut tcp) = parameters
        .underlay
        .tcp(&parameters.options.server, parameters.options.port)
        .await?;
    let mut settings = parameters.advanced.connection.clone();
    if settings.base_mtu == 0 {
        settings.base_mtu = underlay::probe_mtu(tcp.as_mut()).unwrap_or(1406);
    }
    settings.base_mtu = settings.base_mtu.max(1280);
    let tls = parameters.tls.connect(tcp).await?;
    let authority = if parameters.options.server.contains(':') {
        format!(
            "[{}]:{}",
            parameters.options.server, parameters.options.port
        )
    } else {
        format!("{}:{}", parameters.options.server, parameters.options.port)
    };
    let (tls, cookie) = if let Some(credentials) = &parameters.options.credentials {
        meow_openconnect::auth::authenticate_configured(
            tls,
            &authority,
            credentials,
            &parameters.advanced.connection.profile,
            &parameters.advanced.auth,
            || async {
                let tcp = parameters
                    .underlay
                    .tcp_addr(SocketAddr::new(peer, parameters.options.port))
                    .await?;
                parameters.tls.connect(tcp).await
            },
        )
        .await?
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
    let request = meow_openconnect::Options {
        authority,
        cookie,
        mtu: if parameters.options.mtu == 0 {
            (settings.base_mtu - if peer.is_ipv6() { 130 } else { 110 })
                .max(if parameters.options.ipv6 { 1280 } else { 576 })
        } else {
            parameters.options.mtu
        },
        ipv6: parameters.options.ipv6,
    };
    #[cfg(all(feature = "openconnect-dtls", unix))]
    let (connection, dtls) = {
        let mut tls = tls;
        let mode = parameters.options.dtls_mode;
        let offer = if mode == DtlsMode::Off {
            None
        } else {
            let offer = meow_openconnect::dtls::Offer::new(|key| {
                meow_transport::tls::export_keying_material(
                    tls.get_mut().as_mut(),
                    key,
                    "EXPORTER-openconnect-psk",
                    None,
                )
                .map_err(|_| io::Error::other("OpenConnect TLS exporter unavailable"))
            });
            match offer {
                Ok(offer) => Some(
                    offer
                        .resumption_only(parameters.advanced.dtls_resumption_only)
                        .legacy(parameters.advanced.legacy_dtls),
                ),
                Err(error) if mode == DtlsMode::Auto => {
                    tracing::debug!(%error, "OpenConnect DTLS backend unavailable; using CSTP");
                    None
                }
                Err(error) => return Err(error),
            }
        };
        let mut connection = meow_openconnect::connect_configured_with_dtls(
            tls,
            &request,
            &settings,
            offer.as_ref(),
        )
        .await?;
        let negotiated = std::mem::replace(&mut connection.dtls, Ok(None));
        let dtls = match negotiated {
            Ok(Some(mut settings)) => {
                tracing::debug!(
                    dtls_mtu = settings.mtu,
                    dtls_compression = ?settings.compression,
                    "OpenConnect DTLS parameters"
                );
                settings.local_port = parameters.advanced.dtls_local_port;
                settings.connector = Some(Arc::clone(&parameters.underlay)
                    as Arc<dyn meow_openconnect::dtls::DatagramConnector>);
                if !parameters.advanced.connection.dpd_interval.is_zero() {
                    settings.dpd = parameters.advanced.connection.dpd_interval;
                }
                // Fix one MTU for the whole control generation so switching
                // transports never changes existing TCP segmentation limits.
                connection.network.mtu = settings.mtu;
                Some(settings)
            }
            Ok(None) if mode == DtlsMode::Require => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "gateway did not negotiate required DTLS",
                ))
            }
            Err(error) if mode == DtlsMode::Require => return Err(error),
            Err(error) => {
                tracing::debug!(%error, "OpenConnect DTLS negotiation unavailable; using CSTP");
                None
            }
            Ok(None) => None,
        };
        (connection, dtls)
    };
    #[cfg(not(all(feature = "openconnect-dtls", unix)))]
    let connection = meow_openconnect::connect_configured(tls, &request, &settings).await?;
    let (to_stack, incoming) = mpsc::channel(parameters.advanced.queue_length);
    let (outgoing, from_stack) = mpsc::channel(parameters.advanced.queue_length);
    let tcp_send_budget = usize::MAX;
    #[cfg(all(feature = "openconnect-dtls", unix))]
    let tcp_send_budget = if dtls.is_some() {
        // Share a burst budget across flows into the datagram carrier. Larger windows
        // overflow ocserv's UDP receive buffer under concurrent TCP traffic,
        // and smoltcp's loss recovery can then dominate the transfer time.
        64 * 1024
    } else {
        tcp_send_budget
    };
    let stack = Stack::with_tcp_send_budget(
        connection.network.address,
        connection.network.address6,
        connection.network.mtu,
        tcp_send_budget,
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
    #[cfg(all(feature = "openconnect-dtls", unix))]
    let mode = parameters.options.dtls_mode;
    #[cfg(all(feature = "openconnect-dtls", unix))]
    let (ready, readiness) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        #[cfg(all(feature = "openconnect-dtls", unix))]
        if let Some(settings) = dtls {
            if let Err(error) = connection
                .run_with_dtls(
                    from_stack,
                    to_stack,
                    worker_cancel,
                    mode,
                    peer,
                    settings,
                    (mode == DtlsMode::Require).then_some(ready),
                )
                .await
            {
                tracing::debug!(%error, "OpenConnect DTLS/CSTP session ended");
            }
            return;
        }
        if let Err(error) = connection.run(from_stack, to_stack, worker_cancel).await {
            tracing::debug!(%error, "OpenConnect CSTP session ended");
        }
    });
    let session = Arc::new(Session {
        generation,
        stack,
        network,
        cancel,
        dns: dns::Resolver::new(servers, parameters.advanced.network.ip_version),
    });
    #[cfg(all(feature = "openconnect-dtls", unix))]
    if mode == DtlsMode::Require {
        // Construct Session first so cancellation/initialization timeout drops
        // its token and stops both transports while waiting for DTLS readiness.
        readiness.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "OpenConnect control session ended before DTLS was ready",
            )
        })??;
    }
    Ok(session)
}

async fn destination(
    metadata: &Metadata,
    stack: &Stack,
    ip_version: IpVersion,
) -> Result<SocketAddr> {
    if let Some(ip) = metadata.dst_ip.filter(|ip| stack.supports(*ip)) {
        return Ok(SocketAddr::new(ip, metadata.dst_port));
    }
    if metadata.host.is_empty() {
        return Err(MeowError::Proxy(
            "OpenConnect destination requires a negotiated address family or hostname".into(),
        ));
    }
    let mut addresses = meow_common::resolve_host_all(&metadata.host, metadata.dst_port).await?;
    ip_version.select(&mut addresses);
    addresses
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
            destination(
                metadata,
                &session.stack,
                self.parameters.advanced.network.ip_version,
            )
            .await?
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
