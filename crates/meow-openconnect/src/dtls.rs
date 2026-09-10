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

/// Supplies a connected UDP socket, possibly backed by a proxy relay.
#[async_trait::async_trait]
pub trait DatagramConnector: Send + Sync {
    async fn connect(
        &self,
        peer: std::net::SocketAddr,
        local_port: u16,
    ) -> std::io::Result<DatagramSocket>;
}

pub struct DatagramSocket {
    pub socket: std::net::UdpSocket,
    pub guard: DatagramGuard,
}

/// Cancels any relay when setup fails, a handshake times out, or the channel closes.
pub struct DatagramGuard(pub tokio_util::sync::CancellationToken);
impl Drop for DatagramGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(unix)]
mod session;

/// Key material authenticated by the CSTP control connection.
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
    EcdheRsaAes128Gcm,
    EcdheRsaAes256Gcm,
    Aes128Sha,
    Aes256Sha,
    DheAes128Sha,
    DheAes256Sha,
    LegacyAes128Sha,
    LegacyAes256Sha,
    LegacyDheAes128Sha,
    LegacyDheAes256Sha,
}

#[cfg(unix)]
impl Cipher {
    fn legacy(self) -> bool {
        matches!(
            self,
            Self::LegacyAes128Sha
                | Self::LegacyAes256Sha
                | Self::LegacyDheAes128Sha
                | Self::LegacyDheAes256Sha
        )
    }
}

#[cfg(unix)]
impl Cipher {
    fn name(self) -> &'static std::ffi::CStr {
        match self {
            Self::Aes128Gcm => c"AES128-GCM-SHA256",
            Self::Aes256Gcm => c"AES256-GCM-SHA384",
            Self::Chacha20Poly1305 => c"PSK-CHACHA20-POLY1305",
            Self::EcdheRsaAes128Gcm => c"ECDHE-RSA-AES128-GCM-SHA256",
            Self::EcdheRsaAes256Gcm => c"ECDHE-RSA-AES256-GCM-SHA384",
            Self::Aes128Sha | Self::LegacyAes128Sha => c"AES128-SHA",
            Self::Aes256Sha | Self::LegacyAes256Sha => c"AES256-SHA",
            Self::DheAes128Sha | Self::LegacyDheAes128Sha => c"DHE-RSA-AES128-SHA",
            Self::DheAes256Sha | Self::LegacyDheAes256Sha => c"DHE-RSA-AES256-SHA",
        }
    }

    fn id(self) -> [u8; 2] {
        match self {
            Self::Aes128Gcm => [0, 0x9c],
            Self::Aes256Gcm => [0, 0x9d],
            Self::Chacha20Poly1305 => [0xcc, 0xab],
            Self::EcdheRsaAes128Gcm => [0xc0, 0x2f],
            Self::EcdheRsaAes256Gcm => [0xc0, 0x30],
            Self::Aes128Sha | Self::LegacyAes128Sha => [0, 0x2f],
            Self::Aes256Sha | Self::LegacyAes256Sha => [0, 0x35],
            Self::DheAes128Sha | Self::LegacyDheAes128Sha => [0, 0x33],
            Self::DheAes256Sha | Self::LegacyDheAes256Sha => [0, 0x39],
        }
    }
}

#[cfg(unix)]
impl Key {
    fn version(&self) -> libc::c_int {
        if matches!(self, Self::Resume { cipher, .. } if cipher.legacy()) {
            0x100
        } else {
            0xfefd
        }
    }
}
