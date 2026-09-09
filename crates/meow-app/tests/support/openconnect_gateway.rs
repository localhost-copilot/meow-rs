use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch, Semaphore};
use tokio_util::sync::CancellationToken;

pub struct Gateway {
    pub address: SocketAddr,
    pub ca: tempfile::NamedTempFile,
    pub attempts: watch::Receiver<usize>,
    pub closed: watch::Receiver<usize>,
    pub gate: Arc<Semaphore>,
    pub cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

struct Closed(watch::Sender<usize>);
impl Drop for Closed {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n += 1);
    }
}

impl Gateway {
    pub async fn start(paused: bool) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certificate = rcgen::generate_simple_self_signed(vec!["vpn.test".into()]).unwrap();
        let ca = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(ca.path(), certificate.cert.pem()).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()], key.into())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (attempt_tx, attempts) = watch::channel(0);
        let (closed_tx, closed) = watch::channel(0);
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let gate = Arc::new(Semaphore::new(if paused { 0 } else { 1024 }));
        let worker_gate = Arc::clone(&gate);
        let task = tokio::spawn(async move {
            loop {
                let (tcp, _) = tokio::select! {
                    _ = worker_cancel.cancelled() => return,
                    accepted = listener.accept() => accepted.unwrap(),
                };
                attempt_tx.send_modify(|n| *n += 1);
                let acceptor = acceptor.clone();
                let token = worker_cancel.clone();
                let gate = Arc::clone(&worker_gate);
                let closed = Closed(closed_tx.clone());
                tokio::spawn(async move {
                    let _closed = closed;
                    let serve = async {
                        let mut tls = acceptor.accept(tcp).await.map_err(io::Error::other)?;
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") {
                            request.push(tls.read_u8().await?);
                            if request.len() > 32768 {
                                return Err(io::Error::other("request too large"));
                            }
                        }
                        let request = String::from_utf8(request).unwrap();
                        assert!(request.starts_with("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"));
                        assert!(!request.contains("X-DTLS"));
                        if !request.contains("Cookie: webvpn=fixture-cookie\r\n") {
                            tls.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                            return Ok(());
                        }
                        gate.acquire().await.unwrap().forget();
                        tls.write_all(b"HTTP/1.1 200 CONNECTED\r\nX-CSTP-Version: 1\r\nX-CSTP-Address: 192.0.2.2\r\nX-CSTP-MTU: 1280\r\nX-CSTP-DPD: 30\r\n\r\n").await?;
                        tls.flush().await?;
                        let (to_peer, peer_in) = mpsc::channel(16);
                        let (peer_out, mut from_peer) = mpsc::channel(16);
                        let (control_tx, mut control_rx) = mpsc::channel(8);
                        let (mut reader, mut writer) = tokio::io::split(tls);
                        let read = async {
                            loop {
                                let (kind, packet) =
                                    meow_openconnect::read_frame(&mut reader, 1280).await?;
                                match kind {
                                    0 => to_peer.send(packet).await.map_err(io::Error::other)?,
                                    3 => control_tx.send(4).await.map_err(io::Error::other)?,
                                    4 | 7 => {}
                                    _ => return Err(io::Error::other("unexpected CSTP type")),
                                }
                            }
                        };
                        let write = async {
                            loop {
                                let (kind, packet) = tokio::select! {
                                    packet = from_peer.recv() => (0, packet.ok_or_else(|| io::Error::other("peer closed"))?),
                                    kind = control_rx.recv() => (kind.ok_or_else(|| io::Error::other("reader closed"))?, vec![]),
                                };
                                meow_openconnect::write_frame(&mut writer, kind, &packet).await?;
                            }
                        };
                        let peer = crate::peer::run(peer_in, peer_out, token.clone());
                        tokio::select! {
                            result = read => result,
                            result = write => result,
                            _ = peer => Ok(()),
                        }
                    };
                    tokio::select! { _ = token.cancelled() => {}, _ = serve => {} }
                });
            }
        });
        Self {
            address,
            ca,
            attempts,
            closed,
            gate,
            cancel,
            task,
        }
    }

    pub fn yaml(&self, cookie: &str) -> String {
        format!("mode: rule\nipv6: false\ndns:\n  enable: false\nproxies:\n  - name: vpn\n    type: openconnect\n    server: 127.0.0.1\n    port: {}\n    server-name: vpn.test\n    cookie: {cookie}\n    ca: '{}'\n    dtls-mode: off\nrules:\n  - MATCH,vpn\n", self.address.port(), self.ca.path().display())
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
