use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch, Semaphore};
use tokio_util::sync::CancellationToken;

pub struct Gateway {
    pub address: SocketAddr,
    pub ca: tempfile::NamedTempFile,
    pub attempts: watch::Receiver<usize>,
    pub closed: watch::Receiver<usize>,
    pub gate: Arc<Semaphore>,
    pub cancel: CancellationToken,
    pub network: watch::Sender<Option<String>>,
    pub disconnect: watch::Sender<u64>,
    pub packets: broadcast::Sender<(usize, Vec<u8>)>,
    pub status: watch::Sender<u16>,
    task: tokio::task::JoinHandle<()>,
}

struct Closed(watch::Sender<usize>);

async fn request<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(String, String)> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await?);
        if bytes.len() > 32768 {
            return Err(io::Error::other("request too large"));
        }
    }
    let headers = String::from_utf8(bytes).map_err(io::Error::other)?;
    let length = headers
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .map_or(0, |length| length.parse::<usize>().unwrap());
    assert!(length <= 65536);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok((headers, String::from_utf8(body).map_err(io::Error::other)?))
}
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
        let (network, worker_network) = watch::channel::<Option<String>>(None);
        let (disconnect, disconnected) = watch::channel(0);
        let (packets, _) = broadcast::channel(256);
        let (status, worker_status) = watch::channel(200);
        let worker_packets = packets.clone();
        let task = tokio::spawn(async move {
            loop {
                let (tcp, _) = tokio::select! {
                    _ = worker_cancel.cancelled() => return,
                    accepted = listener.accept() => accepted.unwrap(),
                };
                attempt_tx.send_modify(|n| *n += 1);
                let attempt = *attempt_tx.borrow();
                let packets = worker_packets.clone();
                let network = worker_network.clone();
                let status = worker_status.clone();
                let mut disconnected = disconnected.clone();
                disconnected.borrow_and_update();
                let acceptor = acceptor.clone();
                let token = worker_cancel.clone();
                let gate = Arc::clone(&worker_gate);
                let closed = Closed(closed_tx.clone());
                tokio::spawn(async move {
                    let _closed = closed;
                    let serve = async {
                        let mut tls = acceptor.accept(tcp).await.map_err(io::Error::other)?;
                        let (mut headers, _) = request(&mut tls).await?;
                        if headers.starts_with("POST / HTTP/1.1") {
                            let body = r#"<config-auth type="auth-request"><opaque><state>fixture</state></opaque><auth><form action="/auth" method="post"><input name="username" type="text"/><input name="password" type="password"/><select name="group_list"><option value="engineering">Engineering</option><option value="guest">Guest</option></select></form></auth></config-auth>"#;
                            tls.write_all(
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                                    body.len()
                                )
                                .as_bytes(),
                            )
                            .await?;
                            let (auth_headers, body) = request(&mut tls).await?;
                            assert!(auth_headers.starts_with("POST /auth HTTP/1.1"));
                            // Protocol crate tests parse XML; this independent fixture checks the wire values.
                            if !body.contains("<username>fixture-user</username>")
                                || !body.contains("<password>fixture-password</password>")
                                || !body.contains("</auth>")
                                || !body.contains("<group-select>engineering</group-select>")
                            {
                                tls.write_all(
                                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
                                )
                                .await?;
                                return Ok(());
                            }
                            let body = "<config-auth type=\"complete\"><auth id=\"success\"/></config-auth>";
                            tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSet-Cookie: webvpn=fixture-cookie; Secure\r\n\r\n{body}", body.len()).as_bytes()).await?;
                            (headers, _) = request(&mut tls).await?;
                        }
                        assert!(headers.starts_with("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"));
                        assert!(!headers.contains("X-DTLS"));
                        if !headers.contains("Cookie: webvpn=fixture-cookie\r\n") {
                            tls.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                            return Ok(());
                        }
                        gate.acquire().await.unwrap().forget();
                        let status = *status.borrow();
                        if status != 200 {
                            tls.write_all(
                                format!(
                                    "HTTP/1.1 {status} Fixture Error\r\nContent-Length: 0\r\n\r\n"
                                )
                                .as_bytes(),
                            )
                            .await?;
                            return Ok(());
                        }
                        let ipv6 = if headers.contains("X-CSTP-Address-Type: IPv4,IPv6\r\n") {
                            "X-CSTP-Address-IP6: 2001:db8::2/64\r\n"
                        } else {
                            ""
                        };
                        let network = network.borrow().clone().unwrap_or_else(|| {
                            format!("X-CSTP-Address: 192.0.2.2\r\n{ipv6}X-CSTP-MTU: 1280\r\n")
                        });
                        tls.write_all(format!("HTTP/1.1 200 CONNECTED\r\nX-CSTP-Version: 1\r\n{network}X-CSTP-DPD: 30\r\n\r\n").as_bytes()).await?;
                        tls.flush().await?;
                        let (to_peer, peer_in) = mpsc::channel(16);
                        let (peer_out, mut from_peer) = mpsc::channel(16);
                        let (control_tx, mut control_rx) = mpsc::channel(8);
                        let (mut reader, mut writer) = tokio::io::split(tls);
                        let read = async {
                            loop {
                                let (kind, packet) =
                                    meow_openconnect::read_frame(&mut reader, 1500).await?;
                                match kind {
                                    0 => {
                                        let _ = packets.send((attempt, packet.clone()));
                                        to_peer.send(packet).await.map_err(io::Error::other)?;
                                    }
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
                    tokio::select! { _ = token.cancelled() => {}, _ = disconnected.changed() => {}, _ = serve => {} }
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
            network,
            disconnect,
            packets,
            status,
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
