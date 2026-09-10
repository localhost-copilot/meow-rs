//! SecurID CTF provisioning and time-derived software tokens.
//!
//! The numeric CTF format packs three bits per decimal character. CTF 3/4 uses
//! an authenticated, AES-CBC encrypted payload; verify it before reading fields.
//! Tokens never implement Debug and do not require a native stoken installation.

use super::Token;
use crate::invalid;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::io;
use subtle::ConstantTimeEq;

pub(super) struct SecurId {
    seed: [u8; 16],
    serial: [u8; 12],
    digits: usize,
    pub period: u64,
    add_pin: bool,
}

impl SecurId {
    pub fn parse(options: &Token) -> io::Result<Self> {
        let raw = options.secret.trim();
        let lower = raw.to_ascii_lowercase();
        if lower.contains("<?xml") || raw.starts_with(['@', '/']) || lower.starts_with("version ") {
            return Err(invalid(
                "RSA token-secret must contain an encoded CTF token, not a file or SDTID",
            ));
        }
        let smartphone = [
            "com.rsa.securid.iphone://ctf",
            "com.rsa.securid://ctf",
            "http://127.0.0.1/securid/ctf",
        ]
        .iter()
        .any(|prefix| lower.starts_with(prefix));
        let mut text = raw;
        for marker in ["ctfdata=3d", "ctfdata="] {
            if let Some(index) = lower.find(marker) {
                text = &raw[index + marker.len()..];
                break;
            }
        }
        text = text.split('&').next().unwrap_or("").trim();
        let mut decoded = Vec::new();
        let mut bytes = text.bytes();
        while let Some(byte) = bytes.next() {
            decoded.push(if byte == b'%' {
                let a = bytes.next().and_then(|b| (b as char).to_digit(16));
                let b = bytes.next().and_then(|b| (b as char).to_digit(16));
                match (a, b) {
                    (Some(a), Some(b)) => (a * 16 + b) as u8,
                    _ => return Err(invalid("invalid RSA CTF percent encoding")),
                }
            } else {
                byte
            });
        }
        let token = match decoded.first() {
            Some(b'1' | b'2') => Self::numeric(&decoded, smartphone, options)?,
            Some(b'A' | b'B') => Self::base64(&decoded, options)?,
            _ => {
                return Err(invalid(
                    "RSA token-secret requires CTF version 1, 2, 3 or 4",
                ))
            }
        };
        if token.add_pin
            && (!(4..=8).contains(&options.pin.len())
                || !options.pin.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(invalid("RSA token-pin must contain 4 to 8 digits"));
        }
        Ok(token)
    }

    fn numeric(encoded: &[u8], smartphone: bool, options: &Token) -> io::Result<Self> {
        let digits: Vec<_> = encoded
            .iter()
            .copied()
            .take_while(|b| b.is_ascii_digit() || *b == b'-')
            .filter(|b| *b != b'-')
            .collect();
        if !(81..=85).contains(&digits.len()) {
            return Err(invalid("invalid numeric RSA CTF length"));
        }
        // Serial digits are decimal; payload digits carry only their low three bits.
        let bitstream = |digits: &[u8]| -> Vec<u8> {
            digits
                .iter()
                .flat_map(|b| (0..3).rev().map(move |shift| ((b - b'0') >> shift) & 1))
                .collect()
        };
        let bits = bitstream(&digits[13..76]);
        let field = |offset: usize, length: usize| -> u16 {
            bits[offset..offset + length]
                .iter()
                .fold(0, |value, bit| value * 2 + u16::from(*bit))
        };
        let checksum = bitstream(&digits[digits.len() - 5..])
            .iter()
            .fold(0u16, |a, b| a * 2 + u16::from(*b));
        if checksum != short_mac(&digits[..digits.len() - 5]) {
            return Err(invalid("RSA CTF checksum mismatch"));
        }
        let flags = field(128, 16);
        let password = protected(
            &options.password,
            flags & 0x2000 != 0,
            "RSA token-password is required",
        )?;
        if password.len() > 40 {
            return Err(invalid("RSA token-password exceeds 40 bytes"));
        }
        let device = protected(
            &options.device_id,
            flags & 0x1000 != 0,
            "RSA token-device-id is required",
        )?;
        let device_length = if smartphone { 40 } else { 32 };
        let mut normalized = vec![0; device_length];
        let version_one = digits[0] == b'1';
        let device: Vec<_> = device
            .bytes()
            .take(device_length)
            .filter(|b| {
                if version_one {
                    !b.is_ascii_digit()
                } else {
                    b.is_ascii_hexdigit()
                }
            })
            .map(|b| b.to_ascii_uppercase())
            .collect();
        normalized[..device.len()].copy_from_slice(&device);
        if flags & 0x1000 != 0 && short_mac(&normalized) != field(174, 15) {
            return Err(invalid("RSA token-device-id mismatch"));
        }
        let mut key = password.as_bytes().to_vec();
        key.extend(device);
        key.extend([0xd8, 0xf5, 0x32, 0x53, 0x82, 0x89]);
        let encrypted: Vec<_> = bits[..128]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|byte| byte.iter().fold(0u8, |a, b| a * 2 + b))
            .collect();
        let mut seed: [u8; 16] = encrypted.try_into().expect("128-bit seed");
        aes::Aes128::new(&ctf_mac(&key).into()).decrypt_block((&mut seed).into());
        if short_mac(&seed) != field(159, 15) {
            return Err(invalid("RSA token password or device verification failed"));
        }
        Ok(Self {
            seed,
            serial: digits[1..13].try_into().expect("12-digit serial"),
            digits: usize::from((flags >> 6) & 7) + 1,
            period: if flags & 3 == 0 { 30 } else { 60 },
            add_pin: (flags >> 3) & 3 >= 2,
        })
    }

    fn base64(encoded: &[u8], options: &Token) -> io::Result<Self> {
        let bytes = STANDARD
            .decode(encoded)
            .or_else(|_| STANDARD_NO_PAD.decode(encoded))
            .map_err(|_| invalid("invalid RSA CTF base64"))?;
        if bytes.len() != 291 || !matches!(bytes[0], 3 | 4) {
            return Err(invalid("invalid RSA CTF version or size"));
        }
        let password = protected(
            &options.password,
            bytes[1] != 0,
            "RSA token-password is required",
        )?;
        if password.len() > 40 {
            return Err(invalid("RSA token-password exceeds 40 bytes"));
        }
        let raw_device = protected(
            &options.device_id,
            bytes[2] != 0,
            "RSA token-device-id is required",
        )?;
        let mut device = [0u8; 48];
        for (target, byte) in device
            .iter_mut()
            .zip(raw_device.bytes().filter(u8::is_ascii_alphanumeric))
        {
            *target = byte.to_ascii_uppercase();
        }
        let nonce = &bytes[67..83];
        let mut hash = Sha256::new();
        hash.update(nonce);
        hash.update(device);
        if !bool::from(hash.clone().finalize().as_slice().ct_eq(&bytes[3..35])) {
            return Err(invalid("RSA token-device-id mismatch"));
        }
        hash.update(password.as_bytes());
        if !bool::from(hash.finalize().as_slice().ct_eq(&bytes[35..67])) {
            return Err(invalid("RSA token-password mismatch"));
        }
        let derive = |purpose: [u8; 16]| {
            let mut input = password.as_bytes().to_vec();
            input.extend(device);
            input.extend(purpose);
            input.extend(nonce);
            // CTF 3 retains only odd bytes of this password material; CTF 4 fixes it.
            if bytes[0] == 3 {
                input = input.into_iter().skip(1).step_by(2).collect();
            }
            let mut key = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(&input, nonce, 1000, &mut key);
            key
        };
        let authentication_key = derive([
            0xd0, 0x14, 0x43, 0x3c, 0x6d, 0x17, 0x9f, 0xeb, 0xda, 0x09, 0xab, 0xfc, 0x32, 0x49,
            0x63, 0x4c,
        ]);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&authentication_key).expect("HMAC key");
        mac.update(&bytes[..259]);
        mac.verify_slice(&bytes[259..])
            .map_err(|_| invalid("RSA CTF integrity verification failed"))?;
        let encryption_key = derive([
            0x3b, 0xaf, 0xff, 0x4d, 0x91, 0x8d, 0x89, 0xb6, 0x81, 0x60, 0xde, 0x44, 0x4e, 0x05,
            0xc0, 0xdd,
        ]);
        let cipher = aes::Aes256::new(&encryption_key.into());
        let mut payload = bytes[83..259].to_vec();
        let mut previous: [u8; 16] = nonce.try_into().expect("nonce");
        for block in payload.as_chunks_mut::<16>().0 {
            let ciphertext = *block;
            cipher.decrypt_block((&mut *block).into());
            for (byte, iv) in block.iter_mut().zip(previous) {
                *byte ^= iv;
            }
            previous = ciphertext;
        }
        if !payload[..12].iter().all(u8::is_ascii_digit)
            || payload[12] != 0
            || !(1..=8).contains(&payload[35])
        {
            return Err(invalid("invalid RSA CTF serial or digit count"));
        }
        Ok(Self {
            seed: payload[16..32].try_into().expect("seed"),
            serial: payload[..12].try_into().expect("serial"),
            digits: usize::from(payload[35]),
            period: if payload[37] == 60 { 60 } else { 30 },
            add_pin: payload[36] != 0x1f,
        })
    }

    pub fn code(&self, seconds: u64, pin: &str) -> io::Result<String> {
        let date = time::OffsetDateTime::from_unix_timestamp(
            seconds
                .try_into()
                .map_err(|_| invalid("invalid token time"))?,
        )
        .map_err(|_| invalid("invalid token time"))?;
        let bcd = |value: u8| (value / 10) * 16 + value % 10;
        let year = u16::try_from(date.year()).map_err(|_| invalid("invalid token year"))?;
        let minute = date.minute() & if self.period == 30 { !1 } else { !3 };
        let time = [
            bcd((year / 100) as u8),
            bcd((year % 100) as u8),
            bcd(date.month() as u8),
            bcd(date.day()),
            bcd(date.hour()),
            bcd(minute),
            0,
            0,
        ];
        let mut key = self.seed;
        for length in [2, 3, 4, 5, 8] {
            let mut block = [0xaa; 16];
            block[..length].copy_from_slice(&time[..length]);
            block[12..].fill(0xbb);
            for (output, digits) in block[8..12]
                .iter_mut()
                .zip(self.serial[4..].as_chunks::<2>().0)
            {
                *output = (digits[0] - b'0') * 16 + digits[1] - b'0';
            }
            aes::Aes128::new(&key.into()).encrypt_block((&mut block).into());
            key = block;
        }
        let offset = if self.period == 30 {
            usize::from(date.minute() & 1) * 8 + usize::from(date.second() >= 30) * 4
        } else {
            usize::from(date.minute() & 3) * 4
        };
        let number = u32::from_be_bytes(key[offset..offset + 4].try_into().expect("code bytes"));
        let mut code = format!(
            "{:0width$}",
            number % 10u32.pow(self.digits as u32),
            width = self.digits
        )
        .into_bytes();
        if self.add_pin {
            for (digit, pin) in code.iter_mut().rev().zip(pin.bytes().rev()) {
                *digit = ((*digit - b'0') + (pin - b'0')) % 10 + b'0';
            }
            Ok(String::from_utf8(code).expect("decimal code"))
        } else {
            Ok(format!(
                "{pin}{}",
                String::from_utf8(code).expect("decimal code")
            ))
        }
    }
}

fn protected<'a>(value: &'a str, required: bool, message: &'static str) -> io::Result<&'a str> {
    if required && value.is_empty() {
        return Err(invalid(message));
    }
    Ok(if required { value } else { "" })
}

fn short_mac(bytes: &[u8]) -> u16 {
    let mac = ctf_mac(bytes);
    u16::from_be_bytes([mac[0], mac[1]]) >> 1
}

fn ctf_mac(bytes: &[u8]) -> [u8; 16] {
    let mut blocks = bytes.to_vec();
    blocks.resize(bytes.len().max(1).div_ceil(16) * 16, 0);
    // Odd data-block count, followed by the 128-bit big-endian bit length.
    if (blocks.len() / 16).is_multiple_of(2) {
        blocks.extend([0; 16]);
    }
    blocks.extend(((bytes.len() as u128) * 8).to_be_bytes());
    let mut state = [0xff; 16];
    for block in blocks.as_chunks::<16>().0 {
        let mut encrypted = state;
        aes::Aes128::new_from_slice(block)
            .expect("AES key")
            .encrypt_block((&mut encrypted).into());
        for (byte, encrypted) in state.iter_mut().zip(encrypted) {
            *byte ^= encrypted;
        }
    }
    let mut encrypted = state;
    aes::Aes128::new(&state.into()).encrypt_block((&mut encrypted).into());
    for (byte, encrypted) in state.iter_mut().zip(encrypted) {
        *byte ^= encrypted;
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic token from stoken 0.93 --random, then exported with each wrapping
    // mode. Expected codes are from stoken --use-time, not this implementation.
    const NUMERIC: &str =
        "238339854010654331644246673150250376332724752775351575204173146716404552716727007";
    const LOCKED: &str =
        "238339854010636003610544607707347044047677566562354341347173146716404556643176374";
    const IPHONE: &str = "com.rsa.securid.iphone://ctf?ctfData=238339854010670426114617622234241575677576540420610655647173146716404552204711431";
    const V3: &str = "http://127.0.0.1/securid/ctf?ctfData=AwEBFFe3GELrGa2LzlOGeqtLpxL1FdEjWcwAn0%2FxjK6GK%2B8%2B%2FmMZ7oO40ax1qmCA76n8dk5Z%2BOb5Ol62x79l52mTtSytKe8%2BPF7Rtn5YwcnkR3b0%2Fhh3TuTJmR8UxyDFfBEAuzeIfD7DyBhP2BPb7rPITGyaz1thku2Mhfe5NCdmA9PlSO0AOAXtJwMhhn8%2FcxCHf%2BtySukiAnxKNp3p0APSSR7ptte4DIeXzhRd%2F4sJIGhqSCdiNaE8RzeDRD%2BUAG2gRT1GU%2BC2scsBApE%2Fays%2B%2Bhh4WNFY1AvohuR%2FC%2F3yiQbXA%2F1NsVDMkgKI8S9YfE%2FzPPIYRL37V3W5PCRbq%2FrMQSh74OovGkvZi5CKoswgIeJrdcMVYSiErC4oB9%2B1TLA5";

    #[test]
    fn libstoken_wrapping_and_tokencode_vectors() {
        for (secret, password, device_id) in [
            (NUMERIC, "", ""),
            (
                LOCKED,
                "fixture-password",
                "0123456789ABCDEF0123456789ABCDEF",
            ),
            (
                IPHONE,
                "fixture-password",
                "0123456789ABCDEF0123456789ABCDEF12345678",
            ),
            (V3, "fixture-password", "0123456789ABCDEF0123456789ABCDEF"),
        ] {
            let mut options = Token {
                mode: "rsa".into(),
                secret: secret.into(),
                password: password.into(),
                device_id: device_id.into(),
                pin: "1234".into(),
                ..Default::default()
            };
            let token = SecurId::parse(&options).unwrap();
            assert_eq!(token.code(1777777777, &options.pin).unwrap(), "25850151");
            assert_eq!(token.code(1777777837, &options.pin).unwrap(), "91881640");
            if !password.is_empty() {
                options.password = "incorrect".into();
                assert!(SecurId::parse(&options).is_err());
                options.password = password.into();
                options.device_id = "incorrect".into();
                assert!(SecurId::parse(&options).is_err());
            }
        }
    }
}
