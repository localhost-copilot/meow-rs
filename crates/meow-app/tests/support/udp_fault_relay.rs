//! UDP fault injection outside both TLS implementations and the VPN server.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;

#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub client_datagrams: usize,
    pub client_application: usize,
    pub server_application: usize,
    pub dropped_client: usize,
}

pub struct Relay {
    pub address: SocketAddr,
    pub backend: SocketAddr,
    pub blocked: Arc<AtomicBool>,
    pub stats: watch::Receiver<Stats>,
    task: tokio::task::JoinHandle<()>,
}

impl Relay {
    pub async fn new() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend = reservation.local_addr().unwrap();
        drop(reservation);
        let blocked = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&blocked);
        let (tx, stats) = watch::channel(Stats::default());
        let task = tokio::spawn(async move {
            let mut client = None;
            let mut bytes = vec![0; 65536];
            loop {
                let (n, source) = socket.recv_from(&mut bytes).await.unwrap();
                let from_client = source != backend;
                let blocked = flag.load(Ordering::SeqCst);
                tx.send_modify(|stats| {
                    if from_client {
                        stats.client_datagrams += 1;
                    }
                    if blocked && from_client {
                        stats.dropped_client += 1;
                    }
                    if !blocked && bytes.first() == Some(&23) {
                        if from_client {
                            stats.client_application += 1;
                        } else {
                            stats.server_application += 1;
                        }
                    }
                });
                let target = if from_client {
                    client = Some(source);
                    backend
                } else if let Some(client) = client {
                    client
                } else {
                    continue;
                };
                if !blocked {
                    socket.send_to(&bytes[..n], target).await.unwrap();
                }
            }
        });
        Self {
            address,
            backend,
            blocked,
            stats,
            task,
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}
