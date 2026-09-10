//! Software token configuration. Secrets and generated codes are never Debug-printable.

use crate::invalid;
mod rsa;
use hmac::{Hmac, Mac};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
pub struct Token {
    pub mode: String,
    pub secret: String,
    pub pin: String,
    pub password: String,
    pub device_id: String,
    pub counter: u64,
}

impl Token {
    pub fn validate(&self) -> io::Result<()> {
        if self.secret.is_empty() || self.secret.len() > 65536 {
            return Err(invalid(
                "token-secret is required and must not exceed 65536 bytes",
            ));
        }
        match self.mode.as_str() {
            "totp" => { Oath::parse(&self.secret)?; }
            "rsa" => { rsa::SecurId::parse(self)?; }
            "hotp" => return Err(invalid("HOTP requires a persistent counter update callback; YAML cannot supply one (same as mihomo)")),
            "oidc" => crate::settings::validate_header(&self.secret)?,
            _ => return Err(invalid("unsupported software token mode")),
        }
        Ok(())
    }
}

pub(crate) struct Generator<'a> {
    token: Option<&'a Token>,
    attempts: u64,
    first_time: u64,
}
impl<'a> Generator<'a> {
    pub fn new(token: Option<&'a Token>) -> Self {
        Self {
            token,
            attempts: 0,
            first_time: 0,
        }
    }
    pub fn enabled(&self) -> bool {
        self.token
            .is_some_and(|token| matches!(token.mode.as_str(), "totp" | "rsa"))
    }
    pub fn is_rsa(&self) -> bool {
        self.token.is_some_and(|token| token.mode == "rsa")
    }
    pub fn generate(&mut self) -> io::Result<String> {
        let token = self
            .token
            .ok_or_else(|| invalid("software token is not configured"))?;
        if self.attempts >= 2 {
            return Err(invalid("automatic token attempt limit reached"));
        }
        if self.attempts == 0 {
            self.first_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| invalid("system clock precedes Unix epoch"))?
                .as_secs();
        }
        let code = if token.mode == "rsa" {
            let rsa = rsa::SecurId::parse(token)?;
            rsa.code(self.first_time + self.attempts * rsa.period, &token.pin)?
        } else {
            let oath = Oath::parse(&token.secret)?;
            oath.code(self.first_time / oath.period + self.attempts)?
        };
        self.attempts += 1;
        Ok(code)
    }
}

struct Oath {
    secret: Vec<u8>,
    algorithm: String,
    digits: u32,
    period: u64,
}
impl Oath {
    fn parse(secret: &str) -> io::Result<Self> {
        let mut key = secret.trim().to_owned();
        let mut algorithm = "SHA1".to_owned();
        let mut digits = 6;
        let mut period = 30;
        if key.to_ascii_lowercase().starts_with("otpauth://") {
            let uri = url::Url::parse(&key).map_err(|_| invalid("invalid token URI"))?;
            if uri.host_str() != Some("totp") {
                return Err(invalid("token URI type does not match token-mode"));
            }
            key.clear();
            for (name, value) in uri.query_pairs() {
                match name.to_ascii_lowercase().as_str() {
                    "secret" if key.is_empty() => key = value.into_owned(),
                    "algorithm" => algorithm = value.to_ascii_uppercase(),
                    "digits" => {
                        digits = value
                            .parse()
                            .map_err(|_| invalid("invalid token digit count"))?;
                    }
                    "period" => {
                        period = value.parse().map_err(|_| invalid("invalid token period"))?;
                    }
                    _ => {}
                }
            }
        }
        if key.to_ascii_lowercase().starts_with("base32:") {
            key = key[7..].trim().to_owned();
        }
        let secret = data_encoding::BASE32_NOPAD
            .decode(key.trim_end_matches('=').to_ascii_uppercase().as_bytes())
            .map_err(|_| invalid("invalid base32 token-secret"))?;
        if secret.is_empty()
            || !matches!(algorithm.as_str(), "SHA1" | "SHA256" | "SHA512")
            || !matches!(digits, 6 | 8)
            || period == 0
            || period > i64::MAX as u64
        {
            return Err(invalid("invalid token algorithm, digit count or period"));
        }
        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
        })
    }
    fn code(&self, counter: u64) -> io::Result<String> {
        macro_rules! digest {
            ($hash:ty) => {{
                let mut mac = Hmac::<$hash>::new_from_slice(&self.secret)
                    .map_err(|_| invalid("invalid token key"))?;
                mac.update(&counter.to_be_bytes());
                mac.finalize().into_bytes().to_vec()
            }};
        }
        let bytes = match self.algorithm.as_str() {
            "SHA1" => digest!(sha1::Sha1),
            "SHA256" => digest!(sha2::Sha256),
            "SHA512" => digest!(sha2::Sha512),
            _ => unreachable!(),
        };
        let offset = usize::from(bytes[bytes.len() - 1] & 15);
        let value = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("bounded digest offset"),
        ) & 0x7fffffff;
        Ok(format!(
            "{:0width$}",
            value % 10u32.pow(self.digits),
            width = self.digits as usize
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_vectors_with_all_hashes_and_uri_settings() {
        for (algorithm, secret, code) in [
            ("SHA1", "12345678901234567890", "94287082"),
            ("SHA256", "12345678901234567890123456789012", "46119246"),
            (
                "SHA512",
                "1234567890123456789012345678901234567890123456789012345678901234",
                "90693936",
            ),
        ] {
            let secret = data_encoding::BASE32_NOPAD.encode(secret.as_bytes());
            let oath = Oath::parse(&format!(
                "otpauth://totp/fixture?secret={secret}&algorithm={algorithm}&digits=8&period=30"
            ))
            .unwrap();
            assert_eq!(oath.code(59 / oath.period).unwrap(), code);
        }
    }
}
