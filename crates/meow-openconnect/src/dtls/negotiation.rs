use super::{Cipher, Key};
use std::collections::HashMap;
use std::fmt::Write;
use std::io;
use std::time::Duration;
use zeroize::Zeroizing;

/// Per-control-connection offer. Neither secrets nor derived headers implement Debug.
pub struct Offer {
    master: Zeroizing<[u8; 48]>,
    exporter: Zeroizing<[u8; 32]>,
    resumption_only: bool,
    legacy: bool,
}

impl Offer {
    /// `exporter` must come from this control TLS connection with label
    /// `EXPORTER-openconnect-psk` and no context.
    pub fn new(export: impl FnOnce(&mut [u8]) -> io::Result<()>) -> io::Result<Self> {
        let mut exporter = Zeroizing::new([0u8; 32]);
        export(&mut exporter[..])?;
        #[cfg(unix)]
        {
            Ok(Self {
                master: super::openssl::random_secret()?,
                exporter,
                resumption_only: false,
                legacy: false,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = exporter;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "OpenConnect DTLS platform unsupported",
            ))
        }
    }

    pub fn resumption_only(mut self, enabled: bool) -> Self {
        self.resumption_only = enabled;
        self
    }

    pub fn legacy(mut self, enabled: bool) -> Self {
        self.legacy = enabled;
        self
    }

    pub(crate) fn headers(&self, compression: crate::compression::Mode) -> Zeroizing<String> {
        let ciphers = if self.resumption_only {
            "OC-DTLS1_2-AES256-GCM:OC-DTLS1_2-AES128-GCM"
        } else if self.legacy {
            "PSK-NEGOTIATE:OC2-DTLS1_2-CHACHA20-POLY1305:OC-DTLS1_2-AES256-GCM:OC-DTLS1_2-AES128-GCM:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA"
        } else {
            "PSK-NEGOTIATE:OC2-DTLS1_2-CHACHA20-POLY1305:OC-DTLS1_2-AES256-GCM:OC-DTLS1_2-AES128-GCM"
        };
        let dtls12 = if self.resumption_only {
            String::new()
        } else if self.legacy {
            "X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA\r\n".into()
        } else {
            "X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256\r\n".into()
        };
        let mut headers = Zeroizing::new(format!("X-DTLS-CipherSuite: {ciphers}\r\n{dtls12}X-DTLS-Accept-Encoding: {}\r\nX-DTLS-Master-Secret: ", compression.offer(true)));
        for byte in self.master.iter() {
            write!(&mut *headers, "{byte:02x}").expect("write to String");
        }
        headers.push_str("\r\n");
        headers
    }
}

/// DTLS settings authenticated by the CSTP response. Clones keep the same key
/// only within one control connection; never reuse across reconnect generations.
#[derive(Clone)]
pub struct Parameters {
    pub port: u16,
    pub local_port: u16,
    pub compression: crate::compression::Encoding,
    pub connector: Option<std::sync::Arc<dyn super::DatagramConnector>>,
    pub mtu: u16,
    pub dpd: Duration,
    pub keepalive: Duration,
    pub rekey: Option<Duration>,
    pub key: Key,
}

#[derive(Default)]
pub(crate) struct Headers(HashMap<String, String>);

impl Headers {
    pub(crate) fn push(&mut self, key: &str, value: &str) -> io::Result<()> {
        if self.0.len() >= 32 || self.0.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(invalid("duplicate or excessive DTLS headers"));
        }
        Ok(())
    }

    pub(crate) fn negotiate(
        self,
        offer: &Offer,
        mtu: u16,
        ipv6: bool,
        compression: crate::compression::Mode,
    ) -> io::Result<Option<Parameters>> {
        let get = |name: &str| {
            self.0
                .get(&format!("x-dtls12-{name}"))
                .or_else(|| self.0.get(&format!("x-dtls-{name}")))
                .map(String::as_str)
        };
        let Some(cipher) = get("ciphersuite") else {
            return Ok(None);
        };
        let compression = compression.negotiate(get("content-encoding").unwrap_or(""), true)?;
        let port: u16 = get("port")
            .ok_or_else(|| invalid("DTLS port missing"))?
            .parse()
            .map_err(|_| invalid("invalid DTLS port"))?;
        if port == 0 {
            return Err(invalid("invalid DTLS port"));
        }
        let mtu = match get("mtu") {
            Some(value) => value
                .parse::<u16>()
                .map_err(|_| invalid("invalid DTLS MTU"))?
                .min(mtu),
            None => mtu,
        }
        .min(16383); // One IP packet and its type byte must fit a TLS record.
        if mtu < if ipv6 { 1280 } else { 576 } {
            return Err(invalid("DTLS MTU below IP minimum"));
        }
        let key = if cipher == "PSK-NEGOTIATE" {
            if offer.resumption_only {
                return Err(invalid("gateway selected unoffered DTLS PSK negotiation"));
            }
            Key::Psk {
                secret: offer.exporter.clone(),
                application_id: decode_id(get("app-id"))?,
            }
        } else {
            let dtls12 = self.0.contains_key("x-dtls12-ciphersuite");
            let cipher = match cipher {
                "OC-DTLS1_2-AES128-GCM" | "AES128-GCM-SHA256" => Cipher::Aes128Gcm,
                "OC-DTLS1_2-AES256-GCM" | "AES256-GCM-SHA384" => Cipher::Aes256Gcm,
                "OC2-DTLS1_2-CHACHA20-POLY1305" if !offer.resumption_only => {
                    Cipher::Chacha20Poly1305
                }
                "ECDHE-RSA-AES128-GCM-SHA256" if !offer.resumption_only => {
                    Cipher::EcdheRsaAes128Gcm
                }
                "ECDHE-RSA-AES256-GCM-SHA384" if !offer.resumption_only => {
                    Cipher::EcdheRsaAes256Gcm
                }
                "AES128-SHA" if offer.legacy && dtls12 && !offer.resumption_only => {
                    Cipher::Aes128Sha
                }
                "AES256-SHA" if offer.legacy && dtls12 && !offer.resumption_only => {
                    Cipher::Aes256Sha
                }
                "DHE-RSA-AES128-SHA" if offer.legacy && dtls12 && !offer.resumption_only => {
                    Cipher::DheAes128Sha
                }
                "DHE-RSA-AES256-SHA" if offer.legacy && dtls12 && !offer.resumption_only => {
                    Cipher::DheAes256Sha
                }
                "AES128-SHA" if offer.legacy && !offer.resumption_only => Cipher::LegacyAes128Sha,
                "AES256-SHA" if offer.legacy && !offer.resumption_only => Cipher::LegacyAes256Sha,
                "DHE-RSA-AES128-SHA" if offer.legacy && !offer.resumption_only => {
                    Cipher::LegacyDheAes128Sha
                }
                "DHE-RSA-AES256-SHA" if offer.legacy && !offer.resumption_only => {
                    Cipher::LegacyDheAes256Sha
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "unsupported DTLS cipher or legacy version",
                    ))
                }
            };
            Key::Resume {
                secret: offer.master.clone(),
                session_id: decode_id(get("session-id"))?,
                cipher,
            }
        };
        let duration = |name: &str, default: u64| -> io::Result<Duration> {
            let seconds = get(name)
                .map(str::parse::<u64>)
                .transpose()
                .map_err(|_| invalid("invalid DTLS timer"))?
                .unwrap_or(default);
            if seconds > 86400 * 365 {
                return Err(invalid("DTLS timer exceeds limit"));
            }
            Ok(Duration::from_secs(seconds))
        };
        let rekey = duration("rekey-time", 0)?;
        Ok(Some(Parameters {
            port,
            local_port: 0,
            compression,
            connector: None,
            mtu,
            dpd: duration("dpd", 30)?,
            keepalive: duration("keepalive", 30)?,
            rekey: (!rekey.is_zero()).then_some(rekey),
            key,
        }))
    }
}

fn decode_id(value: Option<&str>) -> io::Result<Vec<u8>> {
    let value = value.ok_or_else(|| invalid("DTLS session/application ID missing"))?;
    if value.is_empty() || value.len() > 64 || value.len() % 2 != 0 {
        return Err(invalid("invalid DTLS session/application ID"));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| invalid("invalid DTLS session/application ID"))?;
            let low = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| invalid("invalid DTLS session/application ID"))?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
