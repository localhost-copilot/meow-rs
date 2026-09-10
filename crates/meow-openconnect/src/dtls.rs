//! OpenSSL 3 DTLS, isolated from the application's BoringSSL symbols.
//!
//! Each channel owns its UDP socket and SSL object. No key, SSL pointer, or
//! allocation is shared with the control TLS implementation.

#[cfg(unix)]
mod openssl;

#[cfg(unix)]
pub use openssl::Channel;

mod negotiation;
pub(crate) use negotiation::Headers;
pub use negotiation::{Offer, Parameters};

#[cfg(unix)]
mod session;

/// Only authenticated DTLS 1.2 modes with AEAD ciphers are supported.
#[derive(Clone)]
pub enum Key {
    /// RFC 5705 key from the actual control TLS connection; application ID is
    /// placed in ClientHello's session ID, not the textual PSK identity.
    Psk {
        secret: zeroize::Zeroizing<[u8; 32]>,
        application_id: Vec<u8>,
    },
    /// A master secret supplied through the authenticated CSTP connection.
    Resume {
        secret: zeroize::Zeroizing<[u8; 48]>,
        session_id: Vec<u8>,
        cipher: Cipher,
    },
}

#[derive(Clone, Copy, Debug)]
pub enum Cipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

#[cfg(unix)]
impl Cipher {
    fn name(self) -> &'static std::ffi::CStr {
        match self {
            Self::Aes128Gcm => c"AES128-GCM-SHA256",
            Self::Aes256Gcm => c"AES256-GCM-SHA384",
            Self::Chacha20Poly1305 => c"PSK-CHACHA20-POLY1305",
        }
    }

    fn id(self) -> [u8; 2] {
        match self {
            Self::Aes128Gcm => [0, 0x9c],
            Self::Aes256Gcm => [0, 0x9d],
            Self::Chacha20Poly1305 => [0xcc, 0xab],
        }
    }
}
