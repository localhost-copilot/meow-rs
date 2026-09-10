//! AnyConnect packet compression. LZS bit grammar: RFC 1974, section 2.5.5.
//! Histories are per packet for LZ4/LZS and per CSTP direction for DEFLATE.

use crate::invalid;
use std::io;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Off,
    Stateless,
    All,
}

impl Mode {
    pub(crate) fn offer(self, dtls: bool) -> &'static str {
        match self {
            Self::Off => "identity",
            Self::All if !dtls => "oc-lz4,lzs,deflate",
            _ => "oc-lz4,lzs",
        }
    }
    pub(crate) fn negotiate(self, value: &str, dtls: bool) -> io::Result<Encoding> {
        match (self, value) {
            (_, "" | "identity") => Ok(Encoding::Identity),
            (Self::Stateless | Self::All, "oc-lz4") => Ok(Encoding::Lz4),
            (Self::Stateless | Self::All, "lzs") => Ok(Encoding::Lzs),
            (Self::All, "deflate") if !dtls => Ok(Encoding::Deflate),
            _ => Err(invalid("gateway selected unoffered compression")),
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Encoding {
    #[default]
    Identity,
    Lz4,
    Lzs,
    Deflate,
}

pub(crate) struct Encoder {
    encoding: Encoding,
    deflate: Option<flate2::Compress>,
    checksum: u32,
}
pub(crate) struct Decoder {
    encoding: Encoding,
    deflate: Option<flate2::Decompress>,
    checksum: u32,
}

impl Encoder {
    pub fn new(encoding: Encoding) -> Self {
        Self {
            encoding,
            deflate: (encoding == Encoding::Deflate).then(|| {
                flate2::Compress::new_with_window_bits(flate2::Compression::fast(), false, 12)
            }),
            checksum: 1,
        }
    }
    /// None means the caller should send an ordinary DATA packet.
    pub fn encode(&mut self, packet: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let compressed = match self.encoding {
            Encoding::Identity => return Ok(None),
            Encoding::Lz4 | Encoding::Lzs if packet.len() < 40 => return Ok(None),
            Encoding::Lz4 => lz4_flex::block::compress(packet),
            Encoding::Lzs => lzs_encode(packet),
            Encoding::Deflate => {
                let compressor = self.deflate.as_mut().expect("deflate state");
                let mut output = vec![0; packet.len() + packet.len() / 8 + 128];
                let (input, written) = (compressor.total_in(), compressor.total_out());
                compressor
                    .compress(packet, &mut output, flate2::FlushCompress::Sync)
                    .map_err(|_| invalid("DEFLATE compression failed"))?;
                if compressor.total_in() - input != packet.len() as u64 {
                    return Err(invalid("DEFLATE compression output exceeded limit"));
                }
                output.truncate((compressor.total_out() - written) as usize);
                self.checksum = adler32(self.checksum, packet);
                output.extend_from_slice(&self.checksum.to_be_bytes());
                if output.len() > u16::MAX as usize {
                    return Err(invalid("compressed packet exceeds CSTP frame limit"));
                }
                return Ok(Some(output));
            }
        };
        Ok((compressed.len() <= packet.len()).then_some(compressed))
    }
}

impl Decoder {
    pub fn new(encoding: Encoding) -> Self {
        Self {
            encoding,
            deflate: (encoding == Encoding::Deflate).then(|| flate2::Decompress::new(false)),
            checksum: 1,
        }
    }
    pub fn decode(&mut self, packet: &[u8], mtu: u16) -> io::Result<Vec<u8>> {
        let mut output = vec![0; usize::from(mtu) + 1];
        let size = match self.encoding {
            Encoding::Identity => return Err(invalid("received unnegotiated compressed packet")),
            Encoding::Lz4 => lz4_flex::block::decompress_into(packet, &mut output)
                .map_err(|_| invalid("invalid or oversized LZ4 packet"))?,
            Encoding::Lzs => lzs_decode(packet, &mut output)?,
            Encoding::Deflate => {
                if packet.len() < 4 {
                    return Err(invalid("DEFLATE checksum missing"));
                }
                let (packet, checksum) = packet.split_at(packet.len() - 4);
                let decoder = self.deflate.as_mut().expect("deflate state");
                let (input, written) = (decoder.total_in(), decoder.total_out());
                decoder
                    .decompress(packet, &mut output, flate2::FlushDecompress::Sync)
                    .map_err(|_| invalid("invalid DEFLATE packet"))?;
                let size = (decoder.total_out() - written) as usize;
                if decoder.total_in() - input != packet.len() as u64 || size > usize::from(mtu) {
                    return Err(invalid("DEFLATE packet exceeds receive limit"));
                }
                self.checksum = adler32(self.checksum, &output[..size]);
                if self.checksum.to_be_bytes() != checksum {
                    return Err(invalid("DEFLATE checksum mismatch"));
                }
                size
            }
        };
        output.truncate(size);
        crate::validate_ip(&output, mtu)?;
        Ok(output)
    }
}

fn adler32(checksum: u32, bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (checksum & 65535, checksum >> 16);
    for block in bytes.chunks(5552) {
        for byte in block {
            a += u32::from(*byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

struct BitInput<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl BitInput<'_> {
    fn get(&mut self, count: usize) -> io::Result<usize> {
        if self.position + count > self.bytes.len() * 8 {
            return Err(invalid("truncated LZS packet"));
        }
        let mut result = 0;
        for bit in self.position..self.position + count {
            result = (result << 1) | usize::from((self.bytes[bit / 8] >> (7 - bit % 8)) & 1);
        }
        self.position += count;
        Ok(result)
    }
}

fn lzs_decode(packet: &[u8], output: &mut [u8]) -> io::Result<usize> {
    let mut bits = BitInput {
        bytes: packet,
        position: 0,
    };
    let mut used = 0;
    loop {
        if bits.get(1)? == 0 {
            let byte = bits.get(8)? as u8;
            *output
                .get_mut(used)
                .ok_or_else(|| invalid("LZS packet exceeds receive limit"))? = byte;
            used += 1;
            continue;
        }
        let width = if bits.get(1)? == 1 { 7 } else { 11 };
        let distance = bits.get(width)?;
        if width == 7 && distance == 0 {
            return Ok(used);
        }
        if distance == 0 || distance > used {
            return Err(invalid("invalid LZS history offset"));
        }
        let mut length = 2 + bits.get(2)?;
        if length == 5 {
            length += bits.get(2)?;
            if length == 8 {
                loop {
                    let extra = bits.get(4)?;
                    length += extra;
                    if length > output.len() - used {
                        return Err(invalid("LZS packet exceeds receive limit"));
                    }
                    if extra != 15 {
                        break;
                    }
                }
            }
        }
        if length > output.len() - used {
            return Err(invalid("LZS packet exceeds receive limit"));
        }
        for _ in 0..length {
            output[used] = output[used - distance];
            used += 1;
        }
    }
}

struct BitOutput {
    bytes: Vec<u8>,
    position: usize,
}
impl BitOutput {
    fn put(&mut self, value: usize, count: usize) {
        for shift in (0..count).rev() {
            if self.position.is_multiple_of(8) {
                self.bytes.push(0);
            }
            let index = self.position / 8;
            self.bytes[index] |= (((value >> shift) & 1) as u8) << (7 - self.position % 8);
            self.position += 1;
        }
    }
}

fn lzs_encode(packet: &[u8]) -> Vec<u8> {
    // A bounded single-candidate table avoids data-dependent search chains.
    let mut recent = [usize::MAX; 4096];
    let mut bits = BitOutput {
        bytes: Vec::with_capacity(packet.len()),
        position: 0,
    };
    let mut pos = 0;
    while pos < packet.len() {
        let mut length = 0;
        let mut distance = 0;
        if pos + 1 < packet.len() {
            let bucket = ((usize::from(packet[pos]) << 4) ^ usize::from(packet[pos + 1])) & 4095;
            let candidate = std::mem::replace(&mut recent[bucket], pos);
            if candidate < pos && pos - candidate < 2048 {
                while pos + length < packet.len()
                    && packet[candidate + length] == packet[pos + length]
                {
                    length += 1;
                }
                distance = pos - candidate;
            }
        }
        if length < 2 {
            bits.put(usize::from(packet[pos]), 9);
            pos += 1;
        } else {
            if distance < 128 {
                bits.put(0x180 | distance, 9);
            } else {
                bits.put(0x1000 | distance, 13);
            }
            if length < 5 {
                bits.put(length - 2, 2);
            } else if length < 8 {
                bits.put(0xc | (length - 5), 4);
            } else {
                bits.put(0xf, 4);
                let mut remaining = length - 8;
                while remaining >= 15 {
                    bits.put(15, 4);
                    remaining -= 15;
                }
                bits.put(remaining, 4);
            }
            pos += length;
        }
    }
    bits.put(0x180, 9);
    bits.bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(size: usize, byte: u8) -> Vec<u8> {
        let mut packet = vec![byte; size];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
        packet
    }

    #[test]
    fn compressed_packets_preserve_history_and_enforce_ip_and_size_limits() {
        for encoding in [Encoding::Lz4, Encoding::Lzs, Encoding::Deflate] {
            let mut encoder = Encoder::new(encoding);
            let mut decoder = Decoder::new(encoding);
            for size in [1280, 1400, 9000, 100, 1500] {
                let packet = ip(size, 42);
                let compressed = encoder.encode(&packet).unwrap().unwrap();
                assert_eq!(decoder.decode(&compressed, size as u16).unwrap(), packet);
                assert!(Decoder::new(encoding).decode(&compressed, 40).is_err());
            }
        }
    }

    #[test]
    fn lzs_literal_and_end_marker_follow_rfc1974() {
        let mut buffer = [0; 20];
        assert_eq!(lzs_decode(&[0x20, 0xe0, 0], &mut buffer).unwrap(), 1);
        assert_eq!(buffer[0], b'A');
        assert_eq!(lzs_encode(b"A"), [0x20, 0xe0, 0]);
        for bad in [&[0x80, 0x10][..], &[0x20, 0xe0], &[0xff, 0xff, 0xff]] {
            assert!(lzs_decode(bad, &mut buffer).is_err());
        }
    }

    #[test]
    fn corrupted_deflate_checksum_is_rejected() {
        let packet = ip(1280, 7);
        let mut compressed = Encoder::new(Encoding::Deflate)
            .encode(&packet)
            .unwrap()
            .unwrap();
        *compressed.last_mut().unwrap() ^= 1;
        assert!(Decoder::new(Encoding::Deflate)
            .decode(&compressed, 1280)
            .is_err());
    }
}
