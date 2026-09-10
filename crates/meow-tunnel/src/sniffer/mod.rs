pub mod quic;

use meow_common::{sniffer::SnifferConfig, DnsMode, Metadata};
use meow_trie::DomainTrie;
use std::time::Duration;
use tokio::{sync::mpsc, time::Instant};

pub(crate) struct UdpSniffer {
    config: SnifferConfig,
    skip: DomainTrie<()>,
    force: DomainTrie<()>,
}

impl UdpSniffer {
    pub fn new(config: SnifferConfig) -> Self {
        let mut skip = DomainTrie::new();
        let mut force = DomainTrie::new();
        for domain in &config.skip_domain {
            skip.insert(domain, ());
        }
        for domain in &config.force_domain {
            force.insert(domain, ());
        }
        Self {
            config,
            skip,
            force,
        }
    }

    /// Hold only the opening datagrams until SNI is known, then let the caller
    /// route and replay every original datagram in order. A 3-second deadline,
    /// 64-datagram limit and 128-KiB byte limit bound incomplete handshakes.
    pub async fn collect(
        &self,
        metadata: &mut Metadata,
        receiver: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Vec<Vec<u8>> {
        let Some(first) = receiver.recv().await else {
            return Vec::new();
        };
        let mut packets = vec![first];
        let cfg = &self.config;
        let pure_ip = metadata.host.is_empty() || metadata.host.parse::<std::net::IpAddr>().is_ok();
        let eligible = pure_ip && cfg.parse_pure_ip
            || metadata.dns_mode == DnsMode::Mapping && cfg.force_dns_mapping
            || self.force.search(&metadata.host).is_some();
        if !cfg.enable || !cfg.quic_ports.contains(&metadata.dst_port) || !eligible {
            return packets;
        }
        let mut parser = quic::QuicInitial::default();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut bytes = packets[0].len();
        loop {
            match parser.inspect(packets.last().expect("first packet is retained")) {
                quic::Outcome::Found(host) => {
                    if self.skip.search(&host).is_none() {
                        metadata.sniff_host = host.clone();
                        if cfg
                            .quic_override_destination
                            .unwrap_or(cfg.override_destination)
                        {
                            metadata.host = host;
                            metadata.dst_ip = None;
                        }
                        metadata.dns_mode = DnsMode::Normal;
                    }
                    break;
                }
                quic::Outcome::NoMatch => break,
                quic::Outcome::NeedMore => {}
            }
            if packets.len() >= 64 || bytes >= 128 * 1024 {
                break;
            }
            match tokio::time::timeout_at(deadline, receiver.recv()).await {
                Ok(Some(packet)) => {
                    bytes += packet.len();
                    packets.push(packet);
                }
                _ => break,
            }
        }
        packets
    }
}

#[cfg(test)]
mod tests {
    use super::quic::tests::{hello, initial};
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn buffers_fragments_before_applying_the_per_protocol_routing_policy() {
        let hello = hello("service.example.com");
        let packets = vec![
            initial(1, 0, 20, &hello[20..]),
            initial(1, 1, 0, &hello[..20]),
        ];
        for (override_destination, skip) in [(true, false), (false, false), (true, true)] {
            let sniffer = UdpSniffer::new(SnifferConfig {
                enable: true,
                quic_override_destination: Some(override_destination),
                skip_domain: if skip {
                    vec!["+.example.com".into()]
                } else {
                    vec![]
                },
                ..Default::default()
            });
            let (tx, mut rx) = mpsc::channel(4);
            for packet in &packets {
                tx.try_send(packet.clone()).unwrap();
            }
            let ip = "192.0.2.1".parse().unwrap();
            let mut metadata = Metadata {
                dst_ip: Some(ip),
                dst_port: 443,
                ..Default::default()
            };
            assert_eq!(sniffer.collect(&mut metadata, &mut rx).await, packets);
            assert_eq!(
                metadata.sniff_host.as_str(),
                if skip { "" } else { "service.example.com" }
            );
            if !skip && override_destination {
                assert_eq!(metadata.host, "service.example.com");
                assert_eq!(metadata.dst_ip, None);
            } else {
                assert!(metadata.host.is_empty());
                assert_eq!(metadata.dst_ip, Some(ip));
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn incomplete_initials_expire_and_ordinary_udp_does_not_wait() {
        let sniffer = UdpSniffer::new(SnifferConfig {
            enable: true,
            ..Default::default()
        });
        for (packet, delay) in [
            (b"ordinary UDP".to_vec(), Duration::ZERO),
            (
                initial(1, 0, 100, b"missing prefix"),
                Duration::from_secs(3),
            ),
        ] {
            let (tx, mut rx) = mpsc::channel(1);
            tx.try_send(packet.clone()).unwrap();
            let mut metadata = Metadata {
                dst_port: 443,
                ..Default::default()
            };
            let start = Instant::now();
            assert_eq!(sniffer.collect(&mut metadata, &mut rx).await, vec![packet]);
            assert_eq!(start.elapsed(), delay);
            assert!(metadata.sniff_host.is_empty());
        }
    }
}
