use base64::{engine::general_purpose::STANDARD, Engine};
use boring::{
    asn1::Asn1Time,
    hash::{hash, MessageDigest},
    pkey::{PKey, Private},
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{store::X509StoreBuilder, X509},
};
use meow_transport::Stream;
use std::{io, time::SystemTime};

/// OpenConnect trust modes and identities. Secret material has no Debug implementation.
#[derive(Default)]
pub struct TlsOptions {
    pub certificate: Vec<u8>,
    pub key: Vec<u8>,
    pub key_password: String,
    pub mca_certificate: Vec<u8>,
    pub mca_key: Vec<u8>,
    pub mca_key_password: String,
    pub peer_fingerprints: Vec<String>,
    pub system_trust_disabled: bool,
    pub skip_cert_verify: bool,
    pub pfs: bool,
    pub allow_insecure_crypto: bool,
    /// Days before client-certificate expiration; zero disables the warning.
    pub cert_expire_warning: Option<u32>,
}

pub(super) struct Connector {
    connector: SslConnector,
    server_name: String,
    fingerprints: Vec<Fingerprint>,
}

impl Connector {
    pub fn new(server_name: &str, roots: &[Vec<u8>], options: &TlsOptions) -> io::Result<Self> {
        super::validate_header(server_name)?;
        if [
            !roots.is_empty(),
            !options.peer_fingerprints.is_empty(),
            options.skip_cert_verify,
        ]
        .into_iter()
        .filter(|set| *set)
        .count()
            > 1
        {
            return Err(invalid(
                "ca, peer fingerprint and skip-cert-verify are mutually exclusive",
            ));
        }
        let fingerprints = options
            .peer_fingerprints
            .iter()
            .map(|value| Fingerprint::parse(value))
            .collect::<io::Result<Vec<_>>>()?;
        let mut connector = SslConnector::builder(SslMethod::tls()).map_err(crypto_error)?;
        connector
            .set_min_proto_version(Some(if options.allow_insecure_crypto {
                SslVersion::TLS1
            } else {
                SslVersion::TLS1_2
            }))
            .map_err(crypto_error)?;
        // PFS applies to TLS 1.2 and below; TLS 1.3 always uses ephemeral key exchange.
        let ciphers = if options.pfs {
            "ECDHE+AESGCM:ECDHE+CHACHA20:ECDHE+AES"
        } else if options.allow_insecure_crypto {
            "ALL:!aNULL:!eNULL"
        } else {
            "ECDHE+AESGCM:ECDHE+CHACHA20:ECDHE+AES:AESGCM:AES"
        };
        connector.set_cipher_list(ciphers).map_err(crypto_error)?;
        connector
            .set_alpn_protos(b"\x08http/1.1")
            .map_err(crypto_error)?;
        if options.skip_cert_verify || !fingerprints.is_empty() {
            connector.set_verify(SslVerifyMode::NONE);
        } else {
            let mut store = X509StoreBuilder::new().map_err(crypto_error)?;
            if !options.system_trust_disabled {
                // Preserve the application's Mozilla roots and honor system OpenSSL CA paths.
                let _ = store.set_default_paths();
                for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
                    store
                        .add_cert(X509::from_der(cert.as_ref()).map_err(crypto_error)?)
                        .map_err(crypto_error)?;
                }
            }
            for cert in roots {
                store
                    .add_cert(X509::from_der(cert).map_err(crypto_error)?)
                    .map_err(crypto_error)?;
            }
            connector.set_cert_store_builder(store);
        }
        if let Some((certificates, key)) = identity(
            &options.certificate,
            &options.key,
            &options.key_password,
            options.cert_expire_warning,
        )? {
            connector
                .set_certificate(&certificates[0])
                .map_err(crypto_error)?;
            for cert in certificates.into_iter().skip(1) {
                connector.add_extra_chain_cert(cert).map_err(crypto_error)?;
            }
            connector.set_private_key(&key).map_err(crypto_error)?;
            connector
                .check_private_key()
                .map_err(|_| invalid("client certificate and key do not match"))?;
        }
        Ok(Self {
            connector: connector.build(),
            server_name: server_name.into(),
            fingerprints,
        })
    }

    pub async fn connect(&self, stream: Box<dyn Stream>) -> io::Result<Box<dyn Stream>> {
        let mut config = self.connector.configure().map_err(crypto_error)?;
        if self.server_name.parse::<std::net::IpAddr>().is_ok() {
            config.set_use_server_name_indication(false);
        }
        if !self.fingerprints.is_empty() {
            config.set_verify_hostname(false);
        }
        let tls = tokio_boring::connect(config, &self.server_name, stream)
            .await
            .map_err(|error| {
                io::Error::new(
                    error
                        .as_io_error()
                        .map_or(io::ErrorKind::PermissionDenied, io::Error::kind),
                    "OpenConnect TLS handshake or certificate verification failed",
                )
            })?;
        if !self.fingerprints.is_empty() {
            let certificate = tls
                .ssl()
                .peer_certificate()
                .ok_or_else(|| invalid("TLS peer certificate missing"))?;
            let mut matched = false;
            for fingerprint in &self.fingerprints {
                matched |= fingerprint.matches(&certificate)?;
            }
            if !matched {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TLS peer certificate fingerprint mismatch",
                ));
            }
        }
        Ok(Box::new(tls))
    }
}

pub(super) fn identity(
    cert: &[u8],
    key: &[u8],
    password: &str,
    warning: Option<u32>,
) -> io::Result<Option<(Vec<X509>, PKey<Private>)>> {
    if cert.is_empty() && key.is_empty() && password.is_empty() {
        return Ok(None);
    }
    if cert.is_empty() || key.is_empty() {
        return Err(invalid("certificate and key must be configured together"));
    }
    let certs = X509::stack_from_pem(cert).map_err(|_| invalid("invalid certificate PEM"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| invalid("empty certificate PEM"))?;
    let key = if password.is_empty() {
        PKey::private_key_from_pem(key)
    } else {
        PKey::private_key_from_pem_passphrase(key, password.as_bytes())
    }
    .map_err(|_| invalid("invalid private key or key password"))?;
    if !leaf.public_key().map_err(crypto_error)?.public_eq(&key) {
        return Err(invalid("certificate and key do not match"));
    }
    let days = warning.unwrap_or(60);
    if days > 0 {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| invalid("system clock precedes Unix epoch"))?
            .as_secs();
        let threshold = now + u64::from(days) * 86400;
        let threshold = Asn1Time::from_unix(
            i64::try_from(threshold)
                .map_err(|_| invalid("certificate expiry warning too large"))?,
        )
        .map_err(crypto_error)?;
        if leaf.not_after() < threshold.as_ref() {
            tracing::warn!(days, "OpenConnect client certificate has expired or will expire within the warning interval");
        }
    }
    Ok(Some((certs, key)))
}

enum Digest {
    CertificateSha1,
    SpkiSha1,
    SpkiSha256,
    PinSha256,
}
struct Fingerprint {
    digest: Digest,
    prefix: String,
}
impl Fingerprint {
    fn parse(value: &str) -> io::Result<Self> {
        let (digest, prefix, max, base64) = if let Some(value) = value.strip_prefix("pin-sha256:") {
            (Digest::PinSha256, value, 44, true)
        } else if let Some(value) = value.strip_prefix("sha256:") {
            (Digest::SpkiSha256, value, 64, false)
        } else if let Some(value) = value.strip_prefix("sha1:") {
            (Digest::SpkiSha1, value, 40, false)
        } else {
            (Digest::CertificateSha1, value, 40, false)
        };
        if !(4..=max).contains(&prefix.len())
            || !prefix.bytes().all(|c| {
                if base64 {
                    c.is_ascii_alphanumeric() || b"+/=".contains(&c)
                } else {
                    c.is_ascii_hexdigit()
                }
            })
            || base64 && prefix.len() == max && STANDARD.decode(prefix).is_err()
        {
            return Err(invalid("invalid peer fingerprint"));
        }
        Ok(Self {
            digest,
            prefix: if base64 {
                prefix.into()
            } else {
                prefix.to_ascii_lowercase()
            },
        })
    }
    fn matches(&self, cert: &X509) -> io::Result<bool> {
        let der = if matches!(self.digest, Digest::CertificateSha1) {
            cert.to_der()
        } else {
            cert.public_key().and_then(|key| key.public_key_to_der())
        }
        .map_err(crypto_error)?;
        let digest = hash(
            if matches!(self.digest, Digest::CertificateSha1 | Digest::SpkiSha1) {
                MessageDigest::sha1()
            } else {
                MessageDigest::sha256()
            },
            &der,
        )
        .map_err(crypto_error)?;
        let actual = if matches!(self.digest, Digest::PinSha256) {
            STANDARD.encode(digest)
        } else {
            hex::encode(digest)
        };
        Ok(boring::memcmp::eq(
            &actual.as_bytes()[..self.prefix.len()],
            self.prefix.as_bytes(),
        ))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn crypto_error(_: boring::error::ErrorStack) -> io::Error {
    invalid("invalid OpenConnect TLS configuration or certificate material")
}

pub(super) struct McaIdentity {
    certificates: Vec<u8>,
    key: PKey<Private>,
}
impl McaIdentity {
    pub fn new(options: &TlsOptions) -> io::Result<Option<Self>> {
        let Some((certificates, key)) = identity(
            &options.mca_certificate,
            &options.mca_key,
            &options.mca_key_password,
            options.cert_expire_warning,
        )?
        else {
            return Ok(None);
        };
        if !matches!(key.id(), boring::pkey::Id::RSA | boring::pkey::Id::EC) {
            return Err(invalid("MCA requires an RSA or ECDSA key"));
        }
        // Degenerate PKCS#7 SignedData carries only the certificate chain.
        fn der(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut result = vec![tag];
            if body.len() < 128 {
                result.push(body.len() as u8);
            } else {
                let bytes = body.len().to_be_bytes();
                let first = bytes
                    .iter()
                    .position(|byte| *byte != 0)
                    .expect("nonempty body");
                result.push(0x80 | (bytes.len() - first) as u8);
                result.extend_from_slice(&bytes[first..]);
            }
            result.extend_from_slice(body);
            result
        }
        let data_oid = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
        ];
        let mut chain = Vec::new();
        for cert in certificates {
            chain.extend(cert.to_der().map_err(crypto_error)?);
        }
        let mut signed = vec![0x02, 0x01, 0x01, 0x31, 0x00];
        signed.extend(der(0x30, &data_oid));
        signed.extend(der(0xa0, &chain));
        signed.extend([0x31, 0x00]);
        let mut content = data_oid.to_vec();
        *content.last_mut().expect("OID") = 2;
        content.extend(der(0xa0, &der(0x30, &signed)));
        Ok(Some(Self {
            certificates: der(0x30, &content),
            key,
        }))
    }
}

impl meow_openconnect::auth::MultipleCertificate for McaIdentity {
    fn sign(
        &self,
        offered_hashes: &[&str],
        challenge: &[u8],
    ) -> io::Result<meow_openconnect::auth::CertificateResponse> {
        let (name, digest) = [
            ("sha512", MessageDigest::sha512()),
            ("sha384", MessageDigest::sha384()),
            ("sha256", MessageDigest::sha256()),
        ]
        .into_iter()
        .find(|(name, _)| {
            offered_hashes
                .iter()
                .any(|offered| offered.trim().eq_ignore_ascii_case(name))
        })
        .ok_or_else(|| invalid("MCA gateway offered no supported signature hash"))?;
        let mut signer = boring::sign::Signer::new(digest, &self.key).map_err(crypto_error)?;
        signer.update(challenge).map_err(crypto_error)?;
        Ok(meow_openconnect::auth::CertificateResponse {
            certificates_pkcs7: self.certificates.clone(),
            hash_algorithm: name.into(),
            signature: signer.sign_to_vec().map_err(crypto_error)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn mca_signature_authenticates_the_original_challenge() {
        use meow_openconnect::auth::MultipleCertificate;
        let client = rcgen::generate_simple_self_signed(vec!["client.test".into()]).unwrap();
        let options = TlsOptions {
            mca_certificate: client.cert.pem().into_bytes(),
            mca_key: client.key_pair.serialize_pem().into_bytes(),
            cert_expire_warning: Some(0),
            ..Default::default()
        };
        let identity = McaIdentity::new(&options).unwrap().unwrap();
        let challenge = b"<config-auth><multiple-client-cert-request/></config-auth>";
        let signed = identity.sign(&["sha256", "sha512"], challenge).unwrap();
        let cert = X509::from_pem(&options.mca_certificate).unwrap();
        let key = cert.public_key().unwrap();
        let mut verifier = boring::sign::Verifier::new(MessageDigest::sha512(), &key).unwrap();
        verifier.update(challenge).unwrap();
        assert!(verifier.verify(&signed.signature).unwrap());
        let mut verifier = boring::sign::Verifier::new(MessageDigest::sha512(), &key).unwrap();
        verifier.update(b"different challenge").unwrap();
        assert!(!verifier.verify(&signed.signature).unwrap());
        assert!(identity.sign(&["sha1"], challenge).is_err());
    }

    #[tokio::test]
    async fn encrypted_client_key_is_used_for_mutual_tls() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = rcgen::generate_simple_self_signed(vec!["vpn.test".into()]).unwrap();
        let client = rcgen::generate_simple_self_signed(vec!["client.test".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(client.cert.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(server.key_pair.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let expected = client.cert.der().clone();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            assert_eq!(tls.get_ref().1.peer_certificates().unwrap()[0], expected);
            tls.write_all(b"client authenticated").await.unwrap();
        });
        let key = PKey::private_key_from_pem(client.key_pair.serialize_pem().as_bytes()).unwrap();
        let encrypted = key
            .private_key_to_pem_pkcs8_passphrase(
                boring::symm::Cipher::aes_256_cbc(),
                b"fixture-password",
            )
            .unwrap();
        let mut options = TlsOptions {
            certificate: client.cert.pem().into_bytes(),
            key: encrypted,
            key_password: "fixture-password".into(),
            system_trust_disabled: true,
            ..Default::default()
        };
        let roots = vec![server.cert.der().to_vec()];
        let connector = Connector::new("vpn.test", &roots, &options).unwrap();
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut tls = connector.connect(Box::new(tcp)).await.unwrap();
        let mut reply = [0; 20];
        tls.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"client authenticated");
        task.await.unwrap();
        options.key_password = "wrong".into();
        assert!(Connector::new("vpn.test", &roots, &options).is_err());
    }
}
