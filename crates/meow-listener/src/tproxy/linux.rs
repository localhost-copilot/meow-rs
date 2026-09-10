use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;
use tokio::net::{TcpListener, UdpSocket};

pub(super) fn set_option(socket: &Socket, level: i32, option: i32, value: i32) -> io::Result<()> {
    // SAFETY: value is a live c_int and the supplied length matches its size.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn transparent_socket(
    addr: SocketAddr,
    kind: Type,
    protocol: Protocol,
) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), kind, Some(protocol))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_ip_transparent(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
        set_option(&socket, libc::SOL_IPV6, libc::IPV6_TRANSPARENT, 1)?;
    }
    Ok(socket)
}

pub(super) fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = transparent_socket(addr, Type::STREAM, Protocol::TCP)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

pub(super) fn bind_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = transparent_socket(addr, Type::DGRAM, Protocol::UDP)?;
    set_option(&socket, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1)?;
    set_option(&socket, libc::SOL_IP, libc::IP_RECVTOS, 1)?;
    if addr.is_ipv6() {
        set_option(&socket, libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR, 1)?;
        set_option(&socket, libc::SOL_IPV6, libc::IPV6_RECVTCLASS, 1)?;
    }
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

pub(super) async fn reply_socket(
    source: SocketAddr,
    client: SocketAddr,
    mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let socket = transparent_socket(source, Type::DGRAM, Protocol::UDP)?;
    if let Some(mark) = mark {
        socket.set_mark(mark)?;
    }
    socket.bind(&source.into())?;
    let socket = UdpSocket::from_std(socket.into())?;
    socket.connect(client).await?;
    Ok(socket)
}

pub(super) struct Datagram {
    pub length: usize,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub dscp: Option<u8>,
}

pub(super) async fn recv_datagram(socket: &UdpSocket, buffer: &mut [u8]) -> io::Result<Datagram> {
    socket
        .async_io(tokio::io::Interest::READABLE, || {
            recv_message(socket, buffer)
        })
        .await
}

fn recv_message(socket: &UdpSocket, buffer: &mut [u8]) -> io::Result<Datagram> {
    // cmsghdr contains size_t: align the ancillary buffer on a usize boundary,
    // including on 32-bit musl. The kernel fills at most the supplied capacity.
    let mut ancillary = [0usize; 32];
    // SAFETY: zero is a valid initial representation for these C socket structs.
    let mut source: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    message.msg_name = std::ptr::from_mut(&mut source).cast();
    message.msg_namelen = std::mem::size_of_val(&source) as libc::socklen_t;
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&ancillary) as _;
    // SAFETY: all pointers refer to live, writable buffers of the specified sizes.
    let count = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated transparent UDP datagram",
        ));
    }
    if message.msg_namelen as usize > std::mem::size_of_val(&source) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid UDP source address length",
        ));
    }
    // SAFETY: recvmsg initialized this address and returned its checked length.
    let source = unsafe { socket2::SockAddr::new(source, message.msg_namelen) }
        .as_socket()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-IP UDP source"))?;
    let source = canonical(source);
    let mut destination = None;
    let mut dscp = None;
    // SAFETY: recvmsg produced the control-message chain within the aligned
    // ancillary buffer. Every payload read additionally checks cmsg_len.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let cmsg = &*header;
            let data = libc::CMSG_DATA(header);
            let has = |size: usize| cmsg.cmsg_len as usize >= libc::CMSG_LEN(size as _) as usize;
            match (cmsg.cmsg_level, cmsg.cmsg_type) {
                (libc::SOL_IP, libc::IP_ORIGDSTADDR)
                    if has(std::mem::size_of::<libc::sockaddr_in>()) =>
                {
                    let addr = data.cast::<libc::sockaddr_in>().read_unaligned();
                    destination = Some(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes())),
                        u16::from_be(addr.sin_port),
                    ));
                }
                (libc::SOL_IPV6, libc::IPV6_ORIGDSTADDR)
                    if has(std::mem::size_of::<libc::sockaddr_in6>()) =>
                {
                    let addr = data.cast::<libc::sockaddr_in6>().read_unaligned();
                    destination = Some(canonical(SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::from(addr.sin6_addr.s6_addr),
                        u16::from_be(addr.sin6_port),
                        u32::from_be(addr.sin6_flowinfo),
                        addr.sin6_scope_id,
                    ))));
                }
                (libc::SOL_IP, libc::IP_TOS) if has(1) => dscp = Some(*data >> 2),
                (libc::SOL_IPV6, libc::IPV6_TCLASS) if has(std::mem::size_of::<libc::c_int>()) => {
                    dscp = Some((data.cast::<libc::c_int>().read_unaligned() as u8) >> 2);
                }
                _ => {}
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    Ok(Datagram {
        length: count as usize,
        source,
        destination: destination.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "transparent UDP packet has no original destination",
            )
        })?,
        dscp,
    })
}

pub(super) fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some() => {
            SocketAddr::new(IpAddr::V4(v6.ip().to_ipv4_mapped().unwrap()), v6.port())
        }
        other => other,
    }
}

pub(super) fn is_local_address(ip: IpAddr) -> io::Result<bool> {
    if ip.is_loopback() || ip.is_unspecified() {
        return Ok(true);
    }
    let mut first = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes first; a successful list is owned until
    // freeifaddrs below. Each non-null ifa_addr has its family's socket layout.
    unsafe {
        if libc::getifaddrs(&mut first) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut current = first;
        let mut found = false;
        while !current.is_null() {
            let addr = (*current).ifa_addr;
            if !addr.is_null() {
                let candidate = match i32::from((*addr).sa_family) {
                    libc::AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                        (*addr.cast::<libc::sockaddr_in>())
                            .sin_addr
                            .s_addr
                            .to_ne_bytes(),
                    ))),
                    libc::AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(
                        (*addr.cast::<libc::sockaddr_in6>()).sin6_addr.s6_addr,
                    ))),
                    _ => None,
                };
                if candidate == Some(ip) {
                    found = true;
                    break;
                }
            }
            current = (*current).ifa_next;
        }
        libc::freeifaddrs(first);
        Ok(found)
    }
}
