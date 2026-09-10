use crate::dialer::TcpDialer;
use meow_transport::Stream;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

#[derive(Clone, Copy, Default)]
pub enum IpVersion {
    #[default]
    Dual,
    Ipv4,
    Ipv6,
    Ipv4Prefer,
    Ipv6Prefer,
}
impl IpVersion {
    pub(super) fn accepts(self, ip: IpAddr) -> bool {
        match self {
            Self::Ipv4 => ip.is_ipv4(),
            Self::Ipv6 => ip.is_ipv6(),
            _ => true,
        }
    }
    pub(super) fn prefer_ipv6(self) -> bool {
        matches!(self, Self::Ipv6 | Self::Ipv6Prefer)
    }
    pub(super) fn select(self, addresses: &mut Vec<SocketAddr>) {
        addresses.retain(|address| self.accepts(address.ip()));
        if matches!(self, Self::Ipv4Prefer | Self::Ipv6Prefer) {
            addresses.sort_by_key(|address| address.is_ipv6() != self.prefer_ipv6());
        }
    }
}

#[derive(Clone, Default)]
pub struct NetworkOptions {
    pub interface_name: String,
    pub routing_mark: u32,
    pub ip_version: IpVersion,
    pub tfo: bool,
    pub mptcp: bool,
}

pub(super) struct Underlay {
    pub dialer: Arc<dyn TcpDialer>,
    pub options: NetworkOptions,
}
impl Underlay {
    pub async fn tcp(&self, host: &str, port: u16) -> io::Result<(IpAddr, Box<dyn Stream>)> {
        let mut addresses = meow_common::resolve_host_all(host, port).await?;
        self.options.ip_version.select(&mut addresses);
        let mut error = io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "gateway has no address matching ip-version",
        );
        for address in addresses {
            match self.tcp_addr(address).await {
                Ok(tcp) => return Ok((address.ip(), tcp)),
                Err(failure) => error = failure,
            }
        }
        Err(error)
    }

    pub async fn tcp_addr(&self, address: SocketAddr) -> io::Result<Box<dyn Stream>> {
        if self.dialer.is_proxy() {
            return self.dialer.dial_addr(address).await;
        }
        let tcp = if self.options.interface_name.is_empty()
            && self.options.routing_mark == 0
            && !self.options.tfo
            && !self.options.mptcp
        {
            meow_common::connect_tcp(address).await?
        } else {
            let domain = if address.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let protocol = if cfg!(target_os = "linux") && self.options.mptcp {
                Protocol::from(262)
            } else {
                Protocol::TCP
            };
            let socket = Socket::new(domain, Type::STREAM, Some(protocol));
            #[cfg(target_os = "linux")]
            let socket = socket.or_else(|error| {
                if self.options.mptcp
                    && matches!(
                        error.raw_os_error(),
                        Some(libc::EPROTONOSUPPORT | libc::EINVAL)
                    )
                {
                    return Socket::new(domain, Type::STREAM, Some(Protocol::TCP));
                }
                Err(error)
            });
            let socket = socket?;
            self.options.apply(&socket, address.ip())?;
            socket.set_nonblocking(true)?;
            let socket = tokio::net::TcpSocket::from_std_stream(socket.into());
            if self.options.tfo {
                let stream = tokio_tfo::TfoStream::connect_with_socket(socket, address).await?;
                stream.set_nodelay(true)?;
                return Ok(Box::new(stream));
            }
            socket.connect(address).await?
        };
        tcp.set_nodelay(true)?;
        Ok(Box::new(tcp))
    }
}

impl NetworkOptions {
    pub(super) fn validate(&self) -> io::Result<()> {
        if self.interface_name.len() > 255 || self.interface_name.chars().any(char::is_control) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid interface-name",
            ));
        }
        Ok(())
    }
    fn apply(&self, socket: &Socket, ip: IpAddr) -> io::Result<()> {
        let _ = ip;
        #[cfg(target_os = "android")]
        if let Some(protector) = meow_common::socket_protector() {
            use std::os::fd::AsRawFd;
            protector.protect(socket.as_raw_fd())?;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if self.interface_name.is_empty() {
                meow_common::apply_outbound_interface(socket)?;
            } else {
                socket.bind_device(Some(self.interface_name.as_bytes()))?;
            }
            if self.routing_mark != 0 {
                socket.set_mark(self.routing_mark)?;
            }
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if !self.interface_name.is_empty() {
            let name = std::ffi::CString::new(self.interface_name.as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid interface-name")
            })?;
            // SAFETY: name remains a valid NUL-terminated string for the call.
            let index = std::num::NonZeroU32::new(unsafe { libc::if_nametoindex(name.as_ptr()) })
                .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "outbound interface not found")
            })?;
            if ip.is_ipv4() {
                socket.bind_device_by_index_v4(Some(index))?;
            } else {
                socket.bind_device_by_index_v6(Some(index))?;
            }
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios"
        )))]
        if !self.interface_name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "interface-name is unsupported on this platform",
            ));
        }
        Ok(())
    }
}

pub(super) fn probe_mtu(stream: &mut dyn Stream) -> Option<u16> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = if let Some(tcp) = stream.as_any_mut().downcast_mut::<tokio::net::TcpStream>() {
            tcp.as_raw_fd()
        } else {
            // A proxy stream has no usable gateway path MTU.
            stream
                .as_any_mut()
                .downcast_mut::<tokio_tfo::TfoStream>()?
                .as_raw_fd()
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // SAFETY: the output object and its length match the getsockopt buffer.
            let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
            let mut length = std::mem::size_of_val(&info) as libc::socklen_t;
            let result = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_INFO,
                    (&mut info as *mut libc::tcp_info).cast(),
                    &mut length,
                )
            };
            if result == 0 && (1280..=65535).contains(&info.tcpi_pmtu) {
                return Some(info.tcpi_pmtu as u16);
            }
        }
        let mut mss: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&mss) as libc::socklen_t;
        // SAFETY: fd belongs to the live TCP stream and mss is an integer output buffer.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                (&mut mss as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        if result == 0 && (1293..=65548).contains(&mss) {
            return Some((mss - 13) as u16);
        }
    }
    let _ = stream;
    None
}

#[cfg(all(feature = "openconnect-dtls", unix))]
#[async_trait::async_trait]
impl meow_openconnect::dtls::DatagramConnector for Underlay {
    async fn connect(
        &self,
        peer: SocketAddr,
        local_port: u16,
    ) -> io::Result<meow_openconnect::dtls::DatagramSocket> {
        use meow_openconnect::dtls::{DatagramGuard, DatagramSocket};
        use tokio_util::sync::CancellationToken;
        if !self.dialer.is_proxy() {
            let local = SocketAddr::new(
                if peer.is_ipv4() { "0.0.0.0" } else { "::" }
                    .parse()
                    .expect("literal"),
                local_port,
            );
            let socket = if self.options.interface_name.is_empty() && self.options.routing_mark == 0
            {
                meow_common::bind_udp(local).await?.into_std()?
            } else {
                let socket = Socket::new(
                    if peer.is_ipv4() {
                        Domain::IPV4
                    } else {
                        Domain::IPV6
                    },
                    Type::DGRAM,
                    Some(Protocol::UDP),
                )?;
                self.options.apply(&socket, peer.ip())?;
                socket.bind(&local.into())?;
                socket.into()
            };
            socket.connect(peer)?;
            return Ok(DatagramSocket {
                socket,
                guard: DatagramGuard(CancellationToken::new()),
            });
        }
        // OpenSSL's datagram BIO consumes an fd. A connected loopback pair bridges
        // that fd to the configured proxy's packet API; no packet can bypass it.
        let proxy = self.dialer.dial_udp(peer).await?;
        let setup = async {
            let bridge = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, local_port))?;
            socket.connect(bridge.local_addr()?)?;
            bridge.connect(socket.local_addr()?).await?;
            Ok::<_, io::Error>((bridge, socket))
        }
        .await;
        let (bridge, socket) = match setup {
            Ok(pair) => pair,
            Err(error) => {
                let _ = proxy.close();
                return Err(error);
            }
        };
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        tokio::spawn(async move {
            let send = async {
                let mut data = vec![0; 65536];
                loop {
                    let size = bridge.recv(&mut data).await?;
                    let sent = proxy
                        .write_packet(&data[..size], &peer)
                        .await
                        .map_err(io::Error::other)?;
                    if sent != size {
                        return Err::<(), _>(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "short DTLS proxy datagram write",
                        ));
                    }
                }
            };
            let receive = async {
                let mut data = vec![0; 65536];
                loop {
                    let (size, source) = proxy
                        .read_packet(&mut data)
                        .await
                        .map_err(io::Error::other)?;
                    if source == peer {
                        let sent = bridge.send(&data[..size]).await?;
                        if sent != size {
                            return Err::<(), _>(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "short DTLS bridge write",
                            ));
                        }
                    }
                }
            };
            tokio::select! {
                _ = worker_cancel.cancelled() => {},
                _ = async { tokio::try_join!(send, receive) } => {},
            }
            let _ = proxy.close();
        });
        Ok(DatagramSocket {
            socket,
            guard: DatagramGuard(cancel),
        })
    }
}

#[cfg(all(test, feature = "openconnect-dtls", unix))]
mod tests {
    use super::*;
    use meow_openconnect::dtls::DatagramConnector;
    use tokio_util::sync::CancellationToken;

    struct Dialer {
        closed: CancellationToken,
    }
    struct Packet {
        socket: tokio::net::UdpSocket,
        closed: CancellationToken,
    }
    #[async_trait::async_trait]
    impl TcpDialer for Dialer {
        async fn dial(&self, _: &str, _: u16) -> io::Result<Box<dyn Stream>> {
            unreachable!()
        }
        fn is_proxy(&self) -> bool {
            true
        }
        async fn dial_udp(
            &self,
            _: SocketAddr,
        ) -> io::Result<Box<dyn meow_common::ProxyPacketConn>> {
            Ok(Box::new(Packet {
                socket: tokio::net::UdpSocket::bind("127.0.0.1:0").await?,
                closed: self.closed.clone(),
            }))
        }
    }
    #[async_trait::async_trait]
    impl meow_common::ProxyPacketConn for Packet {
        async fn read_packet(&self, data: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
            Ok(self.socket.recv_from(data).await?)
        }
        async fn write_packet(&self, data: &[u8], peer: &SocketAddr) -> meow_common::Result<usize> {
            Ok(self.socket.send_to(data, peer).await?)
        }
        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok(self.socket.local_addr()?)
        }
        fn close(&self) -> meow_common::Result<()> {
            self.closed.cancel();
            Ok(())
        }
    }

    #[tokio::test]
    async fn datagram_bridge_preserves_packets_and_closes_on_drop_or_setup_failure() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let closed = CancellationToken::new();
        let underlay = Underlay {
            dialer: Arc::new(Dialer {
                closed: closed.clone(),
            }),
            options: NetworkOptions::default(),
        };
        let connection = underlay
            .connect(peer.local_addr().unwrap(), 0)
            .await
            .unwrap();
        connection.socket.set_nonblocking(true).unwrap();
        let client = tokio::net::UdpSocket::from_std(connection.socket).unwrap();
        client.send(b"outbound").await.unwrap();
        let mut data = [0; 64];
        let (n, source) =
            tokio::time::timeout(std::time::Duration::from_secs(2), peer.recv_from(&mut data))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&data[..n], b"outbound");
        assert_ne!(source, client.local_addr().unwrap());
        peer.send_to(b"inbound", source).await.unwrap();
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data[..n], b"inbound");
        drop(connection.guard);
        tokio::time::timeout(std::time::Duration::from_secs(2), closed.cancelled())
            .await
            .unwrap();

        let closed = CancellationToken::new();
        let underlay = Underlay {
            dialer: Arc::new(Dialer {
                closed: closed.clone(),
            }),
            options: NetworkOptions::default(),
        };
        assert!(underlay
            .connect(
                peer.local_addr().unwrap(),
                peer.local_addr().unwrap().port()
            )
            .await
            .is_err());
        assert!(closed.is_cancelled());
    }
}
