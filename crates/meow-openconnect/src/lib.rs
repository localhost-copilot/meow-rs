//! Cookie-authenticated AnyConnect CSTP over an already verified TLS stream.
//! This crate transports raw IP packets; it does not resolve names or route sockets.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const HEADER_LIMIT: usize = 32768;

pub mod auth;

#[cfg(feature = "dtls")]
pub mod dtls;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DtlsMode {
    #[default]
    Off,
    Auto,
    Require,
}

/// Request parameters. Cookie is intentionally excluded from Debug output.
pub struct Options {
    pub authority: String,
    pub cookie: String,
    pub mtu: u16,
    pub ipv6: bool,
}

impl Options {
    pub fn validate(&self) -> io::Result<()> {
        if self.authority.is_empty()
            || self.cookie.is_empty()
            || [&self.authority, &self.cookie]
                .iter()
                .any(|value| value.bytes().any(|b| b < 0x20 || b == 0x7f))
        {
            return Err(invalid(
                "CSTP authority and cookie must be nonempty and contain no control characters",
            ));
        }
        if !(576..=1500).contains(&self.mtu) {
            return Err(invalid("CSTP MTU must be between 576 and 1500"));
        }
        if self.ipv6 && self.mtu < 1280 {
            return Err(invalid("IPv6 requires an MTU of at least 1280"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    pub address: Option<Ipv4Addr>,
    pub address6: Option<Ipv6Addr>,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
}

impl NetworkConfig {
    fn validate_packet(&self, packet: &[u8]) -> io::Result<()> {
        validate_ip(packet, self.mtu)?;
        if packet[0] >> 4 == 4 && self.address.is_none()
            || packet[0] >> 4 == 6 && self.address6.is_none()
        {
            return Err(invalid("CSTP packet address family was not negotiated"));
        }
        Ok(())
    }
}

/// A negotiated tunnel. The buffered reader retains any DATA following the HTTP headers.
pub struct Connection<S> {
    stream: BufReader<S>,
    pub network: NetworkConfig,
    dpd: Duration,
    keepalive: Duration,
    #[cfg(feature = "dtls")]
    pub dtls: io::Result<Option<dtls::Parameters>>,
}

pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    options: &Options,
) -> io::Result<Connection<S>> {
    connect_inner(
        stream,
        options,
        #[cfg(feature = "dtls")]
        None,
    )
    .await
}

#[cfg(feature = "dtls")]
pub async fn connect_with_dtls<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    options: &Options,
    offer: Option<&dtls::Offer>,
) -> io::Result<Connection<S>> {
    connect_inner(stream, options, offer).await
}

async fn connect_inner<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    options: &Options,
    #[cfg(feature = "dtls")] offer: Option<&dtls::Offer>,
) -> io::Result<Connection<S>> {
    options.validate()?;
    let cookie = if options.cookie.starts_with("webvpn=") {
        options.cookie.clone()
    } else {
        format!("webvpn={}", options.cookie)
    };
    #[cfg(feature = "dtls")]
    let dtls_headers = offer.map(dtls::Offer::headers).unwrap_or_default();
    #[cfg(feature = "dtls")]
    let dtls_text: &str = &dtls_headers;
    #[cfg(not(feature = "dtls"))]
    let dtls_text = "";
    let request = format!(
        "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nHost: {}\r\nUser-Agent: meow-rs\r\nCookie: {cookie}\r\nX-CSTP-Version: 1\r\nX-CSTP-MTU: {}\r\nX-CSTP-Address-Type: {}\r\nX-CSTP-Accept-Encoding: identity\r\n{}\r\n",
        options.authority, options.mtu, if options.ipv6 { "IPv4,IPv6" } else { "IPv4" },
        dtls_text,
    );
    #[cfg(feature = "dtls")]
    let request = zeroize::Zeroizing::new(request);
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut stream = BufReader::new(stream);
    let mut remaining = HEADER_LIMIT;
    let status = header_line(&mut stream, &mut remaining).await?;
    let mut parts = status.split_whitespace();
    if !matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(invalid("invalid CSTP HTTP response"));
    }
    match parts.next() {
        Some("200") => {}
        Some("401" | "403") => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "CSTP cookie rejected",
            ))
        }
        Some("500" | "502" | "503" | "504") => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "CSTP gateway temporarily unavailable",
            ));
        }
        _ => return Err(invalid("CSTP CONNECT did not return HTTP 200")),
    }
    let mut address = None;
    let mut address6 = None;
    let mut dns = Vec::new();
    let mut mtu = None;
    let mut version = None;
    let mut dpd = Duration::from_secs(30);
    let mut keepalive = Duration::from_secs(30);
    #[cfg(feature = "dtls")]
    let mut dtls_headers = dtls::Headers::default();
    loop {
        let line = header_line(&mut stream, &mut remaining).await?;
        if line == "\r\n" {
            break;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("malformed CSTP response header"))?;
        let value = value.trim();
        match key.to_ascii_lowercase().as_str() {
            "x-cstp-version" => {
                if version.replace(value.to_owned()).is_some() || value != "1" {
                    return Err(invalid("unsupported or duplicate CSTP version"));
                }
            }
            "x-cstp-address-ip6" => set_ipv6(value, &mut address6, options.ipv6)?,
            "x-cstp-address" if value.contains(':') => {
                set_ipv6(value, &mut address6, options.ipv6)?;
            }
            "x-cstp-address" => {
                let ip: Ipv4Addr = value
                    .parse()
                    .map_err(|_| invalid("invalid CSTP IPv4 address"))?;
                if address.replace(ip).is_some()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_broadcast()
                {
                    return Err(invalid("invalid or duplicate CSTP IPv4 address"));
                }
            }
            "x-cstp-dns" | "x-cstp-dns-ip6" => {
                let ip: IpAddr = value
                    .parse()
                    .map_err(|_| invalid("invalid CSTP DNS address"))?;
                if ip.is_unspecified()
                    || ip.is_multicast()
                    || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
                {
                    return Err(invalid("invalid CSTP DNS address"));
                }
                if !dns.contains(&ip) {
                    if dns.len() >= 16 {
                        return Err(invalid("too many CSTP DNS servers"));
                    }
                    dns.push(ip);
                }
            }
            "x-cstp-mtu" => {
                let n: u16 = value.parse().map_err(|_| invalid("invalid CSTP MTU"))?;
                if mtu.replace(n.min(options.mtu)).is_some() || n < 576 {
                    return Err(invalid("invalid or duplicate CSTP MTU"));
                }
            }
            "x-cstp-content-encoding" if value != "identity" => {
                return Err(invalid("CSTP compression is not supported"))
            }
            "x-cstp-dpd" => dpd = interval(value)?,
            "x-cstp-keepalive" => keepalive = interval(value)?,
            #[cfg(feature = "dtls")]
            name if offer.is_some()
                && (name.starts_with("x-dtls-") || name.starts_with("x-dtls12-")) =>
            {
                dtls_headers.push(name, value)?;
            }
            _ => {}
        }
    }
    if version.is_none() {
        return Err(invalid("CSTP version missing"));
    }
    let mtu = mtu.ok_or_else(|| invalid("CSTP MTU missing"))?;
    if address.is_none() && address6.is_none() {
        return Err(invalid("CSTP IP address missing"));
    }
    if address6.is_some() && mtu < 1280 {
        return Err(invalid("CSTP IPv6 MTU below 1280"));
    }
    Ok(Connection {
        stream,
        network: NetworkConfig {
            address,
            address6,
            dns,
            mtu,
        },
        dpd,
        keepalive,
        #[cfg(feature = "dtls")]
        dtls: match offer {
            Some(offer) => dtls_headers.negotiate(offer, mtu, address6.is_some()),
            None => Ok(None),
        },
    })
}

fn set_ipv6(value: &str, address: &mut Option<Ipv6Addr>, enabled: bool) -> io::Result<()> {
    let (ip, prefix) = value.split_once('/').unwrap_or((value, "128"));
    let ip: Ipv6Addr = ip
        .parse()
        .map_err(|_| invalid("invalid CSTP IPv6 address"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| invalid("invalid CSTP IPv6 prefix"))?;
    if !enabled
        || prefix > 128
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.to_ipv4_mapped().is_some()
        || address.replace(ip).is_some()
    {
        return Err(invalid(
            "invalid, unrequested or duplicate CSTP IPv6 address",
        ));
    }
    Ok(())
}

async fn header_line<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
    remaining: &mut usize,
) -> io::Result<String> {
    let mut line = Vec::new();
    let n = stream
        .take(*remaining as u64)
        .read_until(b'\n', &mut line)
        .await?;
    if n == 0 || n >= *remaining || !line.ends_with(b"\r\n") {
        return Err(invalid("truncated or oversized CSTP HTTP headers"));
    }
    *remaining -= n;
    String::from_utf8(line).map_err(|_| invalid("invalid CSTP HTTP header encoding"))
}

fn interval(value: &str) -> io::Result<Duration> {
    let seconds: u64 = value
        .parse()
        .map_err(|_| invalid("invalid CSTP heartbeat interval"))?;
    if seconds > 86400 {
        return Err(invalid("CSTP heartbeat interval exceeds one day"));
    }
    Ok(Duration::from_secs(seconds))
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    /// Run until cancelled, the stack closes, or a transport/protocol error occurs.
    /// The reader and writer remain separate so an outgoing packet never cancels
    /// a partially consumed incoming CSTP frame.
    pub async fn run(
        self,
        mut outgoing: mpsc::Receiver<Vec<u8>>,
        incoming: mpsc::Sender<Vec<u8>>,
        cancel: CancellationToken,
    ) -> io::Result<()> {
        let (mut reader, mut writer) = tokio::io::split(self.stream);
        let (control_tx, mut control_rx) = mpsc::channel(8);
        let epoch = Instant::now();
        let last_received = AtomicU64::new(0);
        let read = async {
            loop {
                let (kind, payload) = read_frame(&mut reader, self.network.mtu).await?;
                last_received.store(epoch.elapsed().as_secs(), Ordering::Relaxed);
                match kind {
                    0 => {
                        self.network.validate_packet(&payload)?;
                        incoming.send(payload).await.map_err(|_| closed())?;
                    }
                    3 => control_tx.send(4).await.map_err(|_| closed())?,
                    4 | 7 => {}
                    5 => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "CSTP server disconnected",
                        ))
                    }
                    _ => return Err(invalid("unsupported CSTP packet type")),
                }
            }
        };
        let write = async {
            let period = [self.dpd, self.keepalive]
                .into_iter()
                .filter(|n| !n.is_zero())
                .min()
                .unwrap_or(Duration::from_secs(86400));
            let mut tick = tokio::time::interval_at(Instant::now() + period, period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let (kind, payload) = tokio::select! {
                    packet = outgoing.recv() => (0, packet.ok_or_else(closed)?),
                    kind = control_rx.recv() => (kind.ok_or_else(closed)?, Vec::new()),
                    _ = tick.tick(), if !self.dpd.is_zero() || !self.keepalive.is_zero() => {
                        if !self.dpd.is_zero() && epoch.elapsed().as_secs().saturating_sub(last_received.load(Ordering::Relaxed)) >= self.dpd.as_secs() * 3 {
                            return Err(io::Error::new(io::ErrorKind::TimedOut, "CSTP peer stopped responding"));
                        }
                        (if self.dpd.is_zero() { 7 } else { 3 }, Vec::new())
                    },
                };
                if kind == 0 {
                    self.network.validate_packet(&payload)?;
                }
                write_frame(&mut writer, kind, &payload).await?;
            }
        };
        tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            result = async { tokio::try_join!(read, write) } => result.map(|_: ((), ())| ()),
        }
    }
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    mtu: u16,
) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0; 8];
    reader.read_exact(&mut header).await?;
    if header[..4] != *b"STF\x01" || header[7] != 0 {
        return Err(invalid("invalid CSTP frame header"));
    }
    let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if length > usize::from(mtu) {
        return Err(invalid("CSTP packet exceeds negotiated MTU"));
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    if header[6] == 0 {
        validate_ip(&payload, mtu)?;
    }
    Ok((header[6], payload))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: u8,
    payload: &[u8],
) -> io::Result<()> {
    let length = u16::try_from(payload.len())
        .map_err(|_| invalid("CSTP packet too large"))?
        .to_be_bytes();
    // ocserv consumes each TLS application record as one complete CSTP frame.
    // Separate header/payload writes become separate records in SSL_write and
    // are rejected, even though a stream-only fixture can reassemble them.
    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.extend_from_slice(&[b'S', b'T', b'F', 1, length[0], length[1], kind, 0]);
    frame.extend_from_slice(payload);
    writer.write_all(&frame).await?;
    writer.flush().await
}

pub fn validate_ip(packet: &[u8], mtu: u16) -> io::Result<()> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => validate_ipv4(packet, mtu),
        Some(6)
            if packet.len() >= 40
                && packet.len() <= usize::from(mtu)
                && usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 == packet.len() =>
        {
            Ok(())
        }
        _ => Err(invalid("invalid IP packet in CSTP tunnel")),
    }
}

pub fn validate_ipv4(packet: &[u8], mtu: u16) -> io::Result<()> {
    if packet.len() < 20
        || packet.len() > usize::from(mtu)
        || packet[0] >> 4 != 4
        || packet[0] & 15 < 5
        || usize::from(packet[0] & 15) * 4 > packet.len()
        || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
    {
        return Err(invalid("invalid IPv4 packet in CSTP tunnel"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "CSTP packet channel closed")
}
