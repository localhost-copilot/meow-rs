use super::{Channel, Parameters};
use crate::{Connection, DtlsMode, NetworkConfig};
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

type Handshake = Pin<Box<dyn Future<Output = io::Result<Channel>> + Send>>;
const RETRY: Duration = Duration::from_secs(30);
const HANDSHAKE: Duration = Duration::from_secs(5);

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    /// Keep the CSTP control reader/writer active while switching only the raw
    /// IP data channel. The caller retains one stack and socket generation.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_with_dtls(
        self,
        outgoing: mpsc::Receiver<Vec<u8>>,
        incoming: mpsc::Sender<Vec<u8>>,
        cancel: CancellationToken,
        mode: DtlsMode,
        peer: IpAddr,
        parameters: Parameters,
        ready: Option<oneshot::Sender<io::Result<()>>>,
    ) -> io::Result<()> {
        if mode == DtlsMode::Off {
            return self.run(outgoing, incoming, cancel).await;
        }
        let (tls_tx, tls_out) = mpsc::channel(64);
        let (tls_in, tls_rx) = mpsc::channel(64);
        let network = self.network.clone();
        let control = self.run(tls_out, tls_in, cancel.clone());
        let data = run_data(
            outgoing, incoming, tls_tx, tls_rx, network, mode, peer, parameters, ready,
        );
        tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            result = control => result,
            result = data => result,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_data(
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    incoming: mpsc::Sender<Vec<u8>>,
    tls_tx: mpsc::Sender<Vec<u8>>,
    mut tls_rx: mpsc::Receiver<Vec<u8>>,
    network: NetworkConfig,
    mode: DtlsMode,
    peer: IpAddr,
    parameters: Parameters,
    mut ready: Option<oneshot::Sender<io::Result<()>>>,
) -> io::Result<()> {
    let mut channel: Option<Channel> = None;
    let mut handshake: Option<Handshake> = None;
    let mut retry = Instant::now();
    let mut received = Instant::now();
    let dpd = if parameters.dpd.is_zero() {
        Duration::from_secs(30)
    } else {
        parameters.dpd.min(Duration::from_secs(30))
    };
    let period = if parameters.keepalive.is_zero() {
        dpd
    } else {
        dpd.min(parameters.keepalive)
    };
    let mut tick = tokio::time::interval_at(Instant::now() + period, period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let rekey = Instant::now() + parameters.rekey.unwrap_or(Duration::from_secs(86400 * 365));
    let mut data = Vec::with_capacity(usize::from(network.mtu) + 1);
    loop {
        enum Event {
            Out(Option<Vec<u8>>),
            Tls(Option<Vec<u8>>),
            Dtls(io::Result<Vec<u8>>),
            Ready(io::Result<Channel>),
            Tick,
            Retry,
            Rekey,
        }
        let event = tokio::select! {
            packet = outgoing.recv(), if mode == DtlsMode::Auto || channel.is_some() => Event::Out(packet),
            packet = tls_rx.recv() => Event::Tls(packet),
            packet = async { channel.as_mut().expect("guarded").recv().await }, if channel.is_some() => Event::Dtls(packet),
            result = async { handshake.as_mut().expect("guarded").await }, if handshake.is_some() => Event::Ready(result),
            _ = tick.tick() => Event::Tick,
            _ = tokio::time::sleep_until(retry), if channel.is_none() && handshake.is_none() => Event::Retry,
            _ = tokio::time::sleep_until(rekey), if parameters.rekey.is_some() => Event::Rekey,
        };
        let mut failure = None;
        match event {
            Event::Out(Some(packet)) => {
                network.validate_packet(&packet)?;
                if let Some(active) = &mut channel {
                    data.clear();
                    data.push(0);
                    data.extend_from_slice(&packet);
                    failure = send(active, &data).await.err();
                    // An attempted send is never replayed through TLS: its
                    // delivery may already have succeeded at the gateway.
                } else if mode == DtlsMode::Auto {
                    tls_tx.send(packet).await.map_err(|_| crate::closed())?;
                } else {
                    return Err(unavailable());
                }
            }
            Event::Tls(Some(packet)) => {
                // Gateways can send unsolicited IP traffic before DTLS is
                // ready. A require session discards it rather than admitting
                // TLS fallback traffic or aborting a valid ongoing handshake.
                if mode == DtlsMode::Require {
                    continue;
                }
                incoming.send(packet).await.map_err(|_| crate::closed())?;
            }
            Event::Out(None) | Event::Tls(None) => return Err(crate::closed()),
            Event::Dtls(Ok(mut packet)) => {
                received = Instant::now();
                match packet.first() {
                    Some(0) => {
                        network.validate_packet(&packet[1..])?;
                        packet.remove(0);
                        incoming.send(packet).await.map_err(|_| crate::closed())?;
                    }
                    Some(3) => failure = send(channel.as_mut().expect("active"), &[4]).await.err(),
                    Some(4 | 7) => {}
                    _ => {
                        failure = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unsupported DTLS packet",
                        ));
                    }
                }
            }
            Event::Dtls(Err(error)) => failure = Some(error),
            Event::Tick => {
                if let Some(active) = &mut channel {
                    if received.elapsed() >= dpd * 3 {
                        failure = Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "DTLS peer stopped responding",
                        ));
                    } else {
                        failure = send(active, &[3]).await.err();
                    }
                }
            }
            Event::Retry => {
                let parameters = parameters.clone();
                handshake = Some(Box::pin(async move {
                    Channel::connect(
                        (peer, parameters.port).into(),
                        parameters.key,
                        parameters.mtu,
                        HANDSHAKE,
                    )
                    .await
                }));
            }
            Event::Ready(result) => {
                handshake = None;
                match result {
                    Ok(active) => {
                        tracing::debug!(cipher = active.cipher(), "OpenConnect switched to DTLS");
                        channel = Some(active);
                        received = Instant::now();
                        if let Some(ready) = ready.take() {
                            let _ = ready.send(Ok(()));
                        }
                    }
                    Err(error) => failure = Some(error),
                }
            }
            // Reauthenticate in a new control generation instead of reusing
            // expired key material or pretending to support in-place rekey.
            Event::Rekey => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "DTLS rekey requires a new control session",
                ))
            }
        }
        if let Some(error) = failure {
            if mode == DtlsMode::Require {
                if let Some(ready) = ready.take() {
                    let _ = ready.send(Err(io::Error::new(error.kind(), error.to_string())));
                }
                return Err(error);
            }
            tracing::debug!(%error, "OpenConnect DTLS unavailable; using CSTP data channel");
            channel = None;
            retry = Instant::now() + RETRY;
        }
    }
}

async fn send(channel: &mut Channel, packet: &[u8]) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), channel.send(packet))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DTLS send timed out"))?
}
fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "required DTLS data channel unavailable",
    )
}
