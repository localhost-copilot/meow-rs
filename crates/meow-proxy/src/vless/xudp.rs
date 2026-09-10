//! Single UDP association over Xray's Mux.Cool framing (sing-vmess XUDP).
//! Each datagram retains its destination; this does not multiplex TCP dials.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use meow_common::{MeowError, ProxyConn, ProxyPacketConn, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

struct Reader {
    io: ReadHalf<Box<dyn ProxyConn>>,
    buffered: BytesMut,
}

impl Reader {
    async fn require(&mut self, length: usize) -> io::Result<()> {
        while self.buffered.len() < length {
            // Read only the outstanding frame, retaining partial progress
            // when a caller cancels read_packet between socket reads.
            let remaining = length - self.buffered.len();
            let n = (&mut self.io)
                .take(remaining as u64)
                .read_buf(&mut self.buffered)
                .await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "XUDP stream closed",
                ));
            }
        }
        Ok(())
    }

    async fn read(
        &mut self,
        output: &mut [u8],
        fallback: SocketAddr,
    ) -> Result<(usize, SocketAddr)> {
        loop {
            self.require(2).await?;
            let meta_len = u16::from_be_bytes([self.buffered[0], self.buffered[1]]) as usize;
            if !(4..=512).contains(&meta_len) {
                return Err(MeowError::Proxy("XUDP invalid metadata length".into()));
            }
            let meta_end = 2 + meta_len;
            self.require(meta_end).await?;
            let status = self.buffered[4];
            let options = self.buffered[5];
            if options & 2 != 0 || status == 3 {
                return Err(MeowError::Io(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "XUDP remote closed",
                )));
            }
            if !matches!(status, 2 | 4) {
                return Err(MeowError::Proxy("XUDP unexpected frame status".into()));
            }
            let source = if status == 2 && meta_len > 4 {
                if self.buffered[6] != 2 {
                    return Err(MeowError::Proxy("XUDP response is not UDP".into()));
                }
                decode_address(&self.buffered[7..meta_end])?
            } else {
                fallback
            };
            if options & 1 == 0 {
                self.buffered.advance(meta_end);
                continue;
            }
            self.require(meta_end + 2).await?;
            let len =
                u16::from_be_bytes([self.buffered[meta_end], self.buffered[meta_end + 1]]) as usize;
            let end = meta_end + 2 + len;
            self.require(end).await?;
            let copy_len = output.len().min(len);
            output[..copy_len]
                .copy_from_slice(&self.buffered[meta_end + 2..meta_end + 2 + copy_len]);
            self.buffered.advance(end);
            return Ok((copy_len, source));
        }
    }
}

fn decode_address(data: &[u8]) -> Result<SocketAddr> {
    let invalid = || MeowError::Proxy("XUDP malformed response address".into());
    if data.len() < 3 {
        return Err(invalid());
    }
    let port = u16::from_be_bytes([data[0], data[1]]);
    let ip = match data[2] {
        1 if data.len() >= 7 => IpAddr::V4(Ipv4Addr::new(data[3], data[4], data[5], data[6])),
        3 if data.len() >= 19 => {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[3..19]).unwrap()))
        }
        2 if data.len() >= 4 && data.len() >= 4 + data[3] as usize => {
            std::str::from_utf8(&data[4..4 + data[3] as usize])
                .ok()
                .and_then(|host| host.parse().ok())
                .ok_or_else(invalid)?
        }
        _ => return Err(invalid()),
    };
    Ok(SocketAddr::new(ip, port))
}

struct Writer {
    io: WriteHalf<Box<dyn ProxyConn>>,
    first: bool,
    pending: Bytes,
}

impl Writer {
    async fn flush_pending(&mut self) -> io::Result<()> {
        while !self.pending.is_empty() {
            let n = self.io.write(&self.pending).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "XUDP stream closed",
                ));
            }
            self.pending.advance(n);
        }
        self.io.flush().await
    }

    async fn write(&mut self, data: &[u8], addr: &SocketAddr) -> Result<usize> {
        let length = u16::try_from(data.len())
            .map_err(|_| MeowError::Proxy("XUDP datagram exceeds 65535 bytes".into()))?;
        // Finish a previously admitted frame even if its caller was cancelled.
        // Otherwise its partial payload would consume the next frame's header.
        if !self.first {
            self.flush_pending().await?;
        }
        let mut frame = BytesMut::with_capacity(32 + data.len());
        frame.put_u16(0);
        frame.put_u16(0); // One logical association per VLESS stream.
        frame.put_u8(if self.first { 1 } else { 2 });
        frame.put_u8(1); // DATA
        frame.put_u8(2); // UDP
        frame.put_u16(addr.port());
        match addr.ip().to_canonical() {
            IpAddr::V4(ip) => {
                frame.put_u8(1);
                frame.put_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                frame.put_u8(3);
                frame.put_slice(&ip.octets());
            }
        }
        let metadata_len = (frame.len() - 2) as u16;
        frame[..2].copy_from_slice(&metadata_len.to_be_bytes());
        frame.put_u16(length);
        frame.put_slice(data);
        self.pending = frame.freeze();
        self.first = false;
        self.flush_pending().await?;
        Ok(data.len())
    }
}

pub(crate) struct XudpConn {
    reader: Mutex<Reader>,
    writer: Mutex<Writer>,
    destination: SocketAddr,
    closed: CancellationToken,
    started: CancellationToken,
}

impl XudpConn {
    pub fn new(stream: Box<dyn ProxyConn>, destination: SocketAddr) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(Reader {
                io: reader,
                buffered: BytesMut::with_capacity(2048),
            }),
            writer: Mutex::new(Writer {
                io: writer,
                first: true,
                pending: Bytes::new(),
            }),
            destination,
            closed: CancellationToken::new(),
            started: CancellationToken::new(),
        }
    }
}

#[async_trait::async_trait]
impl ProxyPacketConn for XudpConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        tokio::select! {
            biased;
            _ = self.closed.cancelled() => Err(MeowError::Proxy("XUDP connection closed".into())),
            result = async {
                // A read must not flush the deferred VLESS/Vision request
                // before the first XUDP datagram has been written with it.
                self.started.cancelled().await;
                self.reader.lock().await.read(buf, self.destination).await
            } => result,
        }
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        tokio::select! {
            biased;
            _ = self.closed.cancelled() => Err(MeowError::Proxy("XUDP connection closed".into())),
            result = async {
                let result = self.writer.lock().await.write(buf, addr).await;
                if result.is_ok() { self.started.cancel(); }
                result
            } => result,
        }
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Err(MeowError::NotSupported("XUDP uses a TCP stream".into()))
    }

    fn close(&self) -> Result<()> {
        self.closed.cancel();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_conn::StreamConn;
    use tokio::io::duplex;

    #[tokio::test]
    async fn xudp_preserves_destinations_and_framing_across_cancelled_reads() {
        let (client, mut peer) = duplex(4096);
        let target: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let conn = XudpConn::new(Box::new(StreamConn(Box::new(client))), target);
        conn.write_packet(b"query", &target).await.unwrap();
        let mut request = [0; 21];
        peer.read_exact(&mut request).await.unwrap();
        // Independent sing-vmess fixture: New+Data, port before address.
        assert_eq!(
            &request,
            b"\x00\x0c\x00\x00\x01\x01\x02\x00\x35\x01\xc0\x00\x02\x01\x00\x05query"
        );
        // Keepalive without data, then two Keep replies; the first carries
        // a different source, the second uses the association destination.
        let replies = b"\x00\x04\x00\x00\x04\x00\x00\x0c\x00\x00\x02\x01\x02\x00\x35\x01\xc0\x00\x02\x02\x00\x05reply\x00\x04\x00\x00\x02\x01\x00\x04next";
        peer.write_all(&replies[..11]).await.unwrap();
        let mut output = [0; 3];
        let mut read = Box::pin(conn.read_packet(&mut output));
        assert!(futures::poll!(&mut read).is_pending());
        drop(read);
        peer.write_all(&replies[11..]).await.unwrap();
        assert_eq!(
            conn.read_packet(&mut output).await.unwrap(),
            (3, "192.0.2.2:53".parse().unwrap())
        );
        assert_eq!(&output, b"rep");
        assert_eq!(conn.read_packet(&mut output).await.unwrap(), (3, target));
        assert_eq!(&output, b"nex");
        conn.close().unwrap();
        assert!(conn.read_packet(&mut output).await.is_err());
        assert!(conn.write_packet(b"closed", &target).await.is_err());
    }
}
