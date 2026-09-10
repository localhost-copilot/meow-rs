use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use tokio::net::TcpListener;

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
