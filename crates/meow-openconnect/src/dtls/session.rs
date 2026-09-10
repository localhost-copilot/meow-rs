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
    let mut pending = None;
    let mut encoder = crate::compression::Encoder::new(parameters.compression);
    let mut decoder = crate::compression::Decoder::new(parameters.compression);
    loop {
        enum Event {
            Out(Option<Vec<u8>>),
            Tls(Option<Vec<u8>>),
            Dtls(io::Result<Vec<u8>>),
            Ready(io::Result<Channel>),
            Delivered(io::Result<()>),
            Tick,
            Retry,
            Rekey,
        }
        let can_receive = pending.is_none();
        let event = tokio::select! {
            packet = outgoing.recv(), if mode == DtlsMode::Auto || channel.is_some() => Event::Out(packet),
            packet = tls_rx.recv(), if can_receive || mode == DtlsMode::Require => Event::Tls(packet),
            packet = async { channel.as_mut().expect("guarded").recv().await }, if channel.is_some() && can_receive => Event::Dtls(packet),
            result = async {
                let permit = incoming.reserve().await.map_err(|_| crate::closed())?;
                permit.send(pending.take().expect("pending packet"));
                Ok::<_, io::Error>(())
            }, if !can_receive => Event::Delivered(result),
            result = async { handshake.as_mut().expect("guarded").await }, if handshake.is_some() => Event::Ready(result),
            _ = tick.tick() => Event::Tick,
            _ = tokio::time::sleep_until(retry), if channel.is_none() && handshake.is_none() => Event::Retry,
            _ = tokio::time::sleep_until(rekey), if parameters.rekey.is_some() => Event::Rekey,
        };
        let mut failure = None;
        match event {
            Event::Delivered(result) => result?,
            Event::Out(Some(packet)) => {
                network.validate_packet(&packet)?;
                if let Some(active) = &mut channel {
                    data.clear();
                    if let Some(compressed) = encoder.encode(&packet)? {
                        data.push(8);
                        data.extend_from_slice(&compressed);
                    } else {
                        data.push(0);
                        data.extend_from_slice(&packet);
                    }
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
                pending = deliver_or_defer(&incoming, packet)?;
            }
            Event::Out(None) | Event::Tls(None) => return Err(crate::closed()),
            Event::Dtls(Ok(mut packet)) => {
                received = Instant::now();
                match packet.first() {
                    Some(0) => {
                        network.validate_packet(&packet[1..])?;
                        packet.remove(0);
                        // Keep at most one undelivered IP packet. Waiting inline
                        // here can block outbound ACKs needed to drain the stack.
                        pending = deliver_or_defer(&incoming, packet)?;
                    }
                    Some(8) => {
                        let packet = decoder.decode(&packet[1..], network.mtu)?;
                        network.validate_packet(&packet)?;
                        pending = deliver_or_defer(&incoming, packet)?;
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
                    let connect = async {
                        if let Some(connector) = parameters.connector {
                            let socket = connector
                                .connect((peer, parameters.port).into(), parameters.local_port)
                                .await?;
                            Channel::connect_socket(
                                socket,
                                parameters.key,
                                parameters.mtu,
                                HANDSHAKE,
                            )
                            .await
                        } else {
                            Channel::connect_bound(
                                (peer, parameters.port).into(),
                                parameters.key,
                                parameters.mtu,
                                HANDSHAKE,
                                parameters.local_port,
                            )
                            .await
                        }
                    };
                    tokio::time::timeout(HANDSHAKE, connect)
                        .await
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "DTLS dial or handshake timed out",
                            )
                        })?
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

fn deliver_or_defer(
    incoming: &mpsc::Sender<Vec<u8>>,
    packet: Vec<u8>,
) -> io::Result<Option<Vec<u8>>> {
    match incoming.try_send(packet) {
        Ok(()) => Ok(None),
        Err(mpsc::error::TrySendError::Full(packet)) => Ok(Some(packet)),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(crate::closed()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inbound_backpressure_preserves_outbound_progress_and_packet_order() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (outgoing, outgoing_rx) = mpsc::channel(1);
            let (incoming, mut incoming_rx) = mpsc::channel(1);
            let (tls_tx, mut tls_outgoing) = mpsc::channel(1);
            let (tls_incoming, tls_rx) = mpsc::channel(1);
            incoming.send(vec![1]).await.unwrap();
            let network = NetworkConfig {
                address: Some(std::net::Ipv4Addr::new(192, 0, 2, 2)),
                address6: None,
                dns: vec![],
                mtu: 1400,
            };
            // Reject DTLS setup before loading a library: exercise the shared
            // loop's TLS fallback path using fully controlled packet channels.
            let parameters = Parameters {
                port: 0,
                local_port: 0,
                compression: crate::compression::Encoding::Identity,
                connector: None,
                mtu: 1400,
                dpd: Duration::from_secs(30),
                keepalive: Duration::from_secs(30),
                rekey: None,
                key: super::super::Key::Psk {
                    secret: zeroize::Zeroizing::new([0; 32]),
                    application_id: vec![1],
                },
            };
            let task = tokio::spawn(run_data(
                outgoing_rx,
                incoming,
                tls_tx,
                tls_rx,
                network,
                DtlsMode::Auto,
                std::net::Ipv4Addr::LOCALHOST.into(),
                parameters,
                None,
            ));
            tls_incoming.send(vec![2]).await.unwrap();
            // Reserving the sole slot proves the loop consumed the packet and
            // encountered the already-full delivery channel; no timing sleeps.
            drop(tls_incoming.reserve().await.unwrap());
            let mut packet = vec![0; 20];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&20u16.to_be_bytes());
            outgoing.send(packet.clone()).await.unwrap();
            assert_eq!(tls_outgoing.recv().await.unwrap(), packet);
            assert_eq!(incoming_rx.recv().await.unwrap(), vec![1]);
            assert_eq!(incoming_rx.recv().await.unwrap(), vec![2]);
            drop(outgoing);
            assert!(task.await.unwrap().is_err());
        })
        .await
        .unwrap();
    }
}
