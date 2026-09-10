use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use meow_dns::client::{decode_validated_response, relevant_ip_answers, ExpectedResponse};
use meow_netstack::Stack;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

/// The cache and upstream list belong to one VPN generation. Neither survives reconnect.
pub(super) struct Resolver {
    ip_version: super::IpVersion,
    servers: Vec<SocketAddr>,
    cache: Mutex<HashMap<String, (IpAddr, Instant)>>,
}

impl Resolver {
    pub fn new(servers: Vec<SocketAddr>, ip_version: super::IpVersion) -> Self {
        Self {
            ip_version,
            servers,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub async fn resolve(&self, stack: &Stack, host: &str, port: u16) -> io::Result<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        if stack.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "VPN DNS generation closed",
            ));
        }
        let name = Name::from_ascii(host).map_err(|_| invalid("invalid VPN DNS name"))?;
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some((ip, expiry)) = self.cache.lock().get(&key) {
            if *expiry > Instant::now() {
                return Ok(SocketAddr::new(*ip, port));
            }
        }
        let (ip, ttl) = tokio::time::timeout(Duration::from_secs(5), self.lookup(stack, name))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VPN DNS lookup timed out"))??;
        let mut cache = self.cache.lock();
        cache.retain(|_, (_, expiry)| *expiry > Instant::now());
        if cache.len() >= 256 {
            cache.clear();
        }
        if ttl > 0 {
            cache.insert(
                key,
                (
                    ip,
                    Instant::now() + Duration::from_secs(u64::from(ttl.min(300))),
                ),
            );
        }
        Ok(SocketAddr::new(ip, port))
    }

    async fn lookup(&self, stack: &Stack, name: Name) -> io::Result<(IpAddr, u32)> {
        let mut last_error = invalid("no usable VPN DNS server; local fallback is disabled");
        for server in self
            .servers
            .iter()
            .filter(|server| stack.supports(server.ip()))
        {
            let mut kinds = [
                (RecordType::A, "0.0.0.0".parse().unwrap()),
                (RecordType::AAAA, "::".parse().unwrap()),
            ];
            if self.ip_version.prefer_ipv6() {
                kinds.reverse();
            }
            for (kind, ip) in kinds {
                let enabled = stack.supports(ip) && self.ip_version.accepts(ip);
                if !enabled {
                    continue;
                }
                let reply = tokio::time::timeout(
                    Duration::from_secs(2),
                    exchange(stack, *server, name.clone(), kind),
                )
                .await;
                let message = match reply {
                    Ok(Ok(message)) => message,
                    Ok(Err(error)) => {
                        last_error = error;
                        continue;
                    }
                    Err(_) => {
                        last_error =
                            io::Error::new(io::ErrorKind::TimedOut, "VPN DNS server timed out");
                        continue;
                    }
                };
                if message.metadata.response_code == ResponseCode::NXDomain {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "VPN DNS name does not exist",
                    ));
                }
                if message.metadata.response_code != ResponseCode::NoError {
                    last_error = invalid("VPN DNS server returned an error");
                    continue;
                }
                let (ips, ttl) = relevant_ip_answers(&message);
                if let Some(ip) = ips
                    .into_iter()
                    .find(|ip| stack.supports(*ip) && self.ip_version.accepts(*ip))
                {
                    return Ok((ip, ttl.unwrap_or(0)));
                }
                last_error = io::Error::new(
                    io::ErrorKind::NotFound,
                    "VPN DNS returned no usable address",
                );
            }
        }
        Err(last_error)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn exchange(
    stack: &Stack,
    server: SocketAddr,
    name: Name,
    kind: RecordType,
) -> io::Result<Message> {
    let query = Query::query(name, kind);
    let id = rand::random();
    let expected = ExpectedResponse {
        id,
        query: query.clone(),
    };
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(query);
    let bytes = message
        .to_bytes()
        .map_err(|_| invalid("cannot encode VPN DNS query"))?;
    let socket = stack.bind_udp().await?;
    socket.send_to(&bytes, server).await?;
    let mut buffer = [0; 65535];
    let reply = loop {
        let (size, source) = socket.recv_from(&mut buffer).await?;
        if source != server {
            continue;
        }
        // Ignore unrelated UDP replies, including a wrong-ID truncated packet.
        if let Ok(reply) = decode_validated_response(&buffer[..size], &expected) {
            break reply;
        }
    };
    if !reply.metadata.truncation {
        return Ok(reply);
    }
    let mut tcp = stack.connect(server).await?;
    tcp.write_u16(bytes.len() as u16).await?;
    tcp.write_all(&bytes).await?;
    let size = usize::from(tcp.read_u16().await?);
    if size < 12 {
        return Err(invalid("truncated VPN DNS TCP response"));
    }
    tcp.read_exact(&mut buffer[..size]).await?;
    let reply = decode_validated_response(&buffer[..size], &expected)
        .map_err(|_| invalid("invalid VPN DNS TCP response"))?;
    if reply.metadata.truncation {
        return Err(invalid("truncated VPN DNS TCP response"));
    }
    Ok(reply)
}
