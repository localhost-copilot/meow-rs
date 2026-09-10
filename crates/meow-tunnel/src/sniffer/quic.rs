//! QUIC Initial inspection (RFC 9000/9001 and RFC 9369).
//! Rustls supplies packet/header protection; only Initial keys are derived.
//! Application traffic is never decrypted by the sniffer.

use meow_common::sniffer::tls::sniff_client_hello;
use rustls::quic::{DirectionalKeys, Version};
use smol_str::SmolStr;

const MAX_CRYPTO: usize = 65536;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    NeedMore,
    Found(SmolStr),
    NoMatch,
}

#[derive(Default)]
pub struct QuicInitial {
    connection_id: Vec<u8>,
    version: u32,
    keys: Option<DirectionalKeys>,
    largest_pn: Option<u64>,
    crypto: Vec<u8>,
    received: Vec<u8>,
    contiguous: usize,
}

impl QuicInitial {
    /// Accept a client datagram, including coalesced long-header packets.
    /// Out-of-order and repeated CRYPTO fragments are accumulated up to 64 KiB.
    pub fn inspect(&mut self, datagram: &[u8]) -> Outcome {
        match self.inspect_inner(datagram) {
            Ok(Some(host)) => Outcome::Found(host),
            Ok(None) => Outcome::NeedMore,
            Err(()) => Outcome::NoMatch,
        }
    }

    fn inspect_inner(&mut self, mut data: &[u8]) -> Result<Option<SmolStr>, ()> {
        let mut initial = false;
        while !data.is_empty() {
            if data[0] & 0xc0 != 0xc0 {
                break;
            }
            let mut input = Input(data);
            let first = input.take(1)?[0];
            let version = u32::from_be_bytes(input.take(4)?.try_into().map_err(|_| ())?);
            let (crypto_version, initial_type, retry_type) = match version {
                1 => (Version::V1, 0, 3),
                0x6b3343cf => (Version::V2, 1, 0),
                0xff00001d..=0xff000020 => (Version::V1Draft, 0, 3),
                _ => return Err(()),
            };
            let dst_len = input.take(1)?[0] as usize;
            if dst_len > 20 {
                return Err(());
            }
            let dst = input.take(dst_len)?;
            let src_len = input.take(1)?[0] as usize;
            if src_len > 20 {
                return Err(());
            }
            input.take(src_len)?;
            let packet_type = (first >> 4) & 3;
            if packet_type == retry_type {
                break;
            }
            if packet_type == initial_type {
                let token_len = input.varint_usize()?;
                input.take(token_len)?;
            }
            let protected_len = input.varint_usize()?;
            let pn_offset = data.len() - input.0.len();
            let protected = input.take(protected_len)?;
            let packet_len = pn_offset + protected.len();
            if packet_type != initial_type {
                data = &data[packet_len..];
                continue;
            }
            initial = true;
            if self.keys.is_none() || self.connection_id != dst || self.version != version {
                let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
                    .tls13()
                    .ok_or(())?
                    .quic_suite()
                    .ok_or(())?;
                *self = Self {
                    connection_id: dst.to_vec(),
                    version,
                    keys: Some(suite.keys(dst, rustls::Side::Server, crypto_version).remote),
                    ..Self::default()
                };
            }
            let keys = self.keys.as_ref().ok_or(())?;
            let sample: [u8; 16] = protected.get(4..20).ok_or(())?.try_into().map_err(|_| ())?;
            let mut packet = data[..packet_len].to_vec();
            let (prefix, suffix) = packet.split_at_mut(pn_offset);
            keys.header
                .decrypt_in_place(&sample, &mut prefix[0], &mut suffix[..4])
                .map_err(|_| ())?;
            if prefix[0] & 0x0c != 0 {
                return Err(());
            }
            let pn_len = usize::from((prefix[0] & 3) + 1);
            let truncated = suffix[..pn_len]
                .iter()
                .fold(0u64, |number, byte| (number << 8) | u64::from(*byte));
            let pn = packet_number(truncated, pn_len, self.largest_pn);
            let (header, body) = packet.split_at_mut(pn_offset + pn_len);
            let plaintext = keys
                .packet
                .decrypt_in_place(pn, header, body)
                .map_err(|_| ())?;
            self.largest_pn = Some(self.largest_pn.map_or(pn, |old| old.max(pn)));
            self.frames(plaintext)?;
            if self.contiguous >= 4 {
                let len = 4
                    + (usize::from(self.crypto[1]) << 16
                        | usize::from(self.crypto[2]) << 8
                        | usize::from(self.crypto[3]));
                if self.crypto[0] != 1 || len > MAX_CRYPTO {
                    return Err(());
                }
                if self.contiguous >= len {
                    return sniff_client_hello(&self.crypto[..len]).map(Some).ok_or(());
                }
            }
            data = &data[packet_len..];
        }
        if initial || self.keys.is_some() {
            Ok(None)
        } else {
            Err(())
        }
    }

    fn frames(&mut self, plaintext: &[u8]) -> Result<(), ()> {
        let mut input = Input(plaintext);
        while !input.0.is_empty() {
            match input.varint()? {
                0 | 1 => {} // PADDING / PING
                kind @ (2 | 3) => {
                    input.varint()?;
                    input.varint()?;
                    let ranges = input.varint_usize()?;
                    input.varint()?;
                    if ranges > input.0.len() / 2 {
                        return Err(());
                    }
                    for _ in 0..ranges {
                        input.varint()?;
                        input.varint()?;
                    }
                    if kind == 3 {
                        input.varint()?;
                        input.varint()?;
                        input.varint()?;
                    }
                }
                6 => {
                    let offset = input.varint_usize()?;
                    let len = input.varint_usize()?;
                    let bytes = input.take(len)?;
                    let end = offset
                        .checked_add(len)
                        .filter(|end| *end <= MAX_CRYPTO)
                        .ok_or(())?;
                    self.crypto.resize(self.crypto.len().max(end), 0);
                    self.received
                        .resize(self.received.len().max(end.div_ceil(8)), 0);
                    for (index, &byte) in (offset..end).zip(bytes) {
                        let mask = 1 << (index % 8);
                        if self.received[index / 8] & mask != 0 && self.crypto[index] != byte {
                            return Err(());
                        }
                        self.crypto[index] = byte;
                        self.received[index / 8] |= mask;
                    }
                    while self.contiguous < self.crypto.len()
                        && self.received[self.contiguous / 8] & (1 << (self.contiguous % 8)) != 0
                    {
                        self.contiguous += 1;
                    }
                }
                0x1c => {
                    input.varint()?;
                    input.varint()?;
                    let len = input.varint_usize()?;
                    input.take(len)?;
                }
                _ => return Err(()),
            }
        }
        Ok(())
    }
}

fn packet_number(truncated: u64, len: usize, largest: Option<u64>) -> u64 {
    let expected = largest.map_or(0, |n| n + 1);
    let window = 1u64 << (8 * len);
    let candidate = (expected & !(window - 1)) | truncated;
    if candidate + window / 2 <= expected && candidate < (1u64 << 62) - window {
        candidate + window
    } else if candidate > expected + window / 2 && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], ()> {
        let bytes = self.0.get(..len).ok_or(())?;
        self.0 = &self.0[len..];
        Ok(bytes)
    }
    fn varint(&mut self) -> Result<u64, ()> {
        let first = *self.0.first().ok_or(())?;
        let bytes = self.take(1 << (first >> 6))?;
        Ok(bytes[1..]
            .iter()
            .fold(u64::from(first & 0x3f), |n, b| n << 8 | u64::from(*b)))
    }
    fn varint_usize(&mut self) -> Result<usize, ()> {
        self.varint()?.try_into().map_err(|_| ())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub fn fixture(hex: &str) -> Vec<u8> {
        let hex: String = hex.split_whitespace().collect();
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    pub fn hello(host: &str) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        body.extend_from_slice(&((host.len() + 9) as u16).to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&((host.len() + 5) as u16).to_be_bytes());
        body.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        body.extend_from_slice(host.as_bytes());
        let mut message = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        message.extend(body);
        message
    }

    fn vi(out: &mut Vec<u8>, value: usize) {
        if value < 64 {
            out.push(value as u8);
        } else if value < 16384 {
            out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
        } else {
            out.extend_from_slice(&((value as u32) | 0x80000000).to_be_bytes());
        }
    }

    pub fn initial(version: u32, pn: u64, offset: usize, fragment: &[u8]) -> Vec<u8> {
        let v = match version {
            1 => Version::V1,
            0x6b3343cf => Version::V2,
            _ => Version::V1Draft,
        };
        let cid = b"clientid";
        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap();
        let keys = suite.keys(cid, rustls::Side::Client, v).local;
        let mut payload = vec![1, 0, 6]; // PING, PADDING, CRYPTO
        vi(&mut payload, offset);
        vi(&mut payload, fragment.len());
        payload.extend_from_slice(fragment);
        payload.resize(payload.len().max(32), 0);
        let mut packet = vec![if version == 0x6b3343cf { 0xd0 } else { 0xc0 }];
        packet.extend_from_slice(&version.to_be_bytes());
        packet.push(8);
        packet.extend_from_slice(cid);
        packet.extend_from_slice(&[0, 0]); // no source CID or token
        vi(&mut packet, payload.len() + 17);
        let pn_offset = packet.len();
        packet.push(pn as u8);
        let tag = keys
            .packet
            .encrypt_in_place(pn, &packet, &mut payload)
            .unwrap();
        packet.extend(payload);
        packet.extend_from_slice(tag.as_ref());
        let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
        let (header, body) = packet.split_at_mut(pn_offset);
        keys.header
            .encrypt_in_place(&sample, &mut header[0], &mut body[..1])
            .unwrap();
        packet
    }

    #[test]
    fn published_rfc_client_initials_decrypt_without_a_server_connection() {
        for hex in [
            include_str!("../../tests/fixtures/quic/rfc9001-client-initial.hex"),
            include_str!("../../tests/fixtures/quic/rfc9369-client-initial.hex"),
        ] {
            let packet = fixture(hex);
            assert_eq!(
                QuicInitial::default().inspect(&packet),
                Outcome::Found("example.com".into())
            );
            for len in 0..packet.len() {
                assert_ne!(
                    QuicInitial::default().inspect(&packet[..len]),
                    Outcome::Found("example.com".into())
                );
            }
            let mut corrupted = packet;
            *corrupted.last_mut().unwrap() ^= 1;
            assert_eq!(QuicInitial::default().inspect(&corrupted), Outcome::NoMatch);
        }
    }

    #[test]
    fn reassembles_coalesced_out_of_order_and_retransmitted_crypto() {
        let hello = hello("fragmented.example");
        for version in [1, 0x6b3343cf, 0xff00001d] {
            let mut parser = QuicInitial::default();
            let tail = initial(version, 255, 30, &hello[30..]);
            assert_eq!(parser.inspect(&tail), Outcome::NeedMore);
            assert_eq!(parser.inspect(&tail), Outcome::NeedMore);
            let mut coalesced = initial(version, 256, 10, &hello[10..30]);
            coalesced.extend(initial(version, 254, 0, &hello[..15]));
            assert_eq!(
                parser.inspect(&coalesced),
                Outcome::Found("fragmented.example".into())
            );
        }
    }

    #[test]
    fn conflicting_and_oversized_crypto_cannot_change_routing() {
        let mut parser = QuicInitial::default();
        assert_eq!(
            parser.inspect(&initial(1, 0, 10, b"abcdefgh")),
            Outcome::NeedMore
        );
        assert_eq!(
            parser.inspect(&initial(1, 1, 10, b"conflict")),
            Outcome::NoMatch
        );
        assert_eq!(
            QuicInitial::default().inspect(&initial(1, 0, MAX_CRYPTO, b"x")),
            Outcome::NoMatch
        );
    }
}
