//! Real app routing/listener path, against the independent ocserv Docker fixture.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

pub async fn run(yaml: &str, mode: &str, container: &str) {
    if let Ok(binary) = std::env::var("MEOW_BENCH_PROXY_BINARY") {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let path = directory.path().join("config.yaml");
        // mihomo's `ca` is PEM text; meow's is a file path. Keep the actual
        // trust anchor identical while adapting this configuration syntax.
        let yaml = if std::env::var("MEOW_BENCH_PROXY_KIND").as_deref() == Ok("mihomo") {
            let line = yaml
                .lines()
                .find(|line| line.starts_with("    ca: '"))
                .unwrap();
            let ca_path = line
                .trim()
                .strip_prefix("ca: '")
                .unwrap()
                .strip_suffix('\'')
                .unwrap();
            let pem = std::fs::read_to_string(ca_path).unwrap();
            let inline = format!(
                "    ca: |\n{}",
                pem.lines()
                    .map(|line| format!("      {line}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            yaml.replace(line, &inline)
        } else {
            yaml.to_owned()
        };
        let level = std::env::var("MEOW_BENCH_LOG_LEVEL").unwrap_or_else(|_| "error".into());
        let yaml = format!(
            "mixed-port: {}\nmode: rule\nlog-level: {level}\nipv6: true\n{yaml}",
            address.port()
        );
        std::fs::write(&path, yaml).unwrap();
        let mut process = tokio::process::Command::new(binary)
            .arg("-d")
            .arg(directory.path())
            .arg("-f")
            .arg(&path)
            .env("GOMAXPROCS", "4")
            .env("TOKIO_WORKER_THREADS", "4")
            .env("RUST_LOG", "error")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                assert!(
                    process.try_wait().unwrap().is_none(),
                    "proxy exited before readiness"
                );
                if tokio::net::TcpStream::connect(address).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        workload(address, mode, container).await;
        process.kill().await.unwrap();
        process.wait().await.unwrap();
        return;
    }
    let config = meow_config::load_config_from_str(yaml).await.unwrap();
    let tunnel = meow_tunnel::Tunnel::new(Arc::clone(&config.dns.resolver));
    tunnel.update_routing(config.proxies, config.rules);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mixed = meow_listener::MixedListener::new(tunnel, address, "ocserv-benchmark".into());
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        mixed.run_on(listener).await.unwrap();
    });
    workload(address, mode, container).await;
}

async fn workload(address: SocketAddr, mode: &str, container: &str) {
    udp_counters(container, mode, "before").await;
    let target: SocketAddr = "192.0.2.1:8080".parse().unwrap();
    // Establish the VPN and warm the persistent connection before recording
    // latency. TCP throughput below includes each new SOCKS flow's dial time.
    let (mut stream, _) = super::socks_target(address, 1, target).await;
    stream.write_all(&[0x5a; 128]).await.unwrap();
    stream.read_exact(&mut [0; 128]).await.unwrap();
    for sample in 1..=3 {
        let mut rtts = Vec::with_capacity(300);
        for _ in 0..300 {
            let start = Instant::now();
            stream.write_all(&[0x5a; 128]).await.unwrap();
            let mut answer = [0; 128];
            stream.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer, [0x5a; 128]);
            rtts.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        latency(mode, "tcp128", sample, rtts);
    }
    drop(stream);
    let flow_mib: usize = std::env::var("MEOW_BENCH_TCP_MIB").map_or(8, |value| {
        value
            .parse()
            .expect("MEOW_BENCH_TCP_MIB must be an integer")
    });
    assert!((1..=256).contains(&flow_mib));
    for concurrency in [1usize, 4] {
        for sample in 1..=3 {
            let start = Instant::now();
            let mut clients = tokio::task::JoinSet::new();
            for _ in 0..concurrency {
                clients.spawn(async move {
                    let (stream, _) = super::socks_target(address, 1, target).await;
                    let (mut reader, mut writer) = tokio::io::split(stream);
                    let payload: Vec<u8> = (0..32768).map(|n| (n % 251) as u8).collect();
                    let write = async {
                        for _ in 0..flow_mib * 32 {
                            writer.write_all(&payload).await.unwrap();
                        }
                        writer.shutdown().await.unwrap();
                    };
                    let read = async {
                        let mut answer = vec![0; payload.len()];
                        for _ in 0..flow_mib * 32 {
                            reader.read_exact(&mut answer).await.unwrap();
                            assert_eq!(answer, payload);
                        }
                    };
                    tokio::join!(write, read);
                });
            }
            while let Some(result) = clients.join_next().await {
                result.unwrap();
            }
            let seconds = start.elapsed().as_secs_f64();
            let mib = (concurrency * flow_mib) as f64;
            println!(
                "BENCH_TCP,{mode},{concurrency},{sample},{mib},{:.3},{:.3}",
                seconds * 1000.0,
                mib / seconds
            );
        }
    }
    let (control, udp_address) =
        super::socks_target(address, 3, "0.0.0.0:0".parse().unwrap()).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let header = [0, 0, 0, 1, 192, 0, 2, 1, 0x14, 0xe9]; // SOCKS5 / 5353
    let mut packet = header.to_vec();
    packet.extend_from_slice(&[0x5a; 128]);
    let mut answer = [0; 1500];
    udp.send_to(&packet, udp_address).await.unwrap();
    udp.recv_from(&mut answer).await.unwrap();
    for sample in 1..=3 {
        let mut rtts = Vec::with_capacity(300);
        for _ in 0..300 {
            let start = Instant::now();
            udp.send_to(&packet, udp_address).await.unwrap();
            let (n, from) =
                tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut answer))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(from, udp_address);
            assert_eq!(&answer[..n], packet);
            rtts.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        latency(mode, "udp128", sample, rtts);
    }
    for sample in 1..=3 {
        let mut received = vec![false; 8192];
        let mut packet = header.to_vec();
        packet.resize(1210, 0x5a);
        let start = Instant::now();
        for batch in 0..512 {
            for offset in 0..16 {
                let sequence = (batch * 16 + offset) as u32;
                packet[10..14].copy_from_slice(&sequence.to_be_bytes());
                udp.send_to(&packet, udp_address).await.unwrap();
            }
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            let mut count = 0;
            while count < 16 {
                let Ok(result) =
                    tokio::time::timeout_at(deadline, udp.recv_from(&mut answer)).await
                else {
                    break;
                };
                let (n, from) = result.unwrap();
                assert_eq!(from, udp_address);
                assert_eq!(n, 1210);
                assert_eq!(&answer[..10], &header);
                assert!(answer[14..n].iter().all(|b| *b == 0x5a));
                let sequence = u32::from_be_bytes(answer[10..14].try_into().unwrap()) as usize;
                assert!(sequence < received.len());
                assert!(!received[sequence], "duplicate UDP echo");
                received[sequence] = true;
                if sequence / 16 == batch {
                    count += 1;
                }
            }
        }
        let seconds = start.elapsed().as_secs_f64();
        let count = received.iter().filter(|seen| **seen).count();
        println!(
            "BENCH_UDP,{mode},16,{sample},8192,{count},{:.3},{:.3}",
            seconds * 1000.0,
            (count * 1200) as f64 / 1048576.0 / seconds
        );
    }
    // Query the live server's session description outside timed intervals.
    // This verifies DTLS without a forwarding hop or per-packet instrumentation.
    let status = tokio::process::Command::new("docker")
        .args([
            "exec",
            container,
            "occtl",
            "--json",
            "show",
            "user",
            "fixture-user",
        ])
        .output()
        .await
        .unwrap();
    assert!(status.status.success(), "occtl inspection failed");
    let status = String::from_utf8(status.stdout).unwrap();
    assert!(
        status.contains("fixture-user"),
        "live VPN session missing from occtl"
    );
    let dtls = status.contains("DTLS1.2");
    let sessions: serde_json::Value = serde_json::from_str(&status).unwrap();
    let session = &sessions[0];
    assert!(session["TLS ciphersuite"]
        .as_str()
        .unwrap()
        .contains("AES-128-GC"));
    if mode == "require" {
        assert!(session["DTLS cipher"]
            .as_str()
            .unwrap()
            .contains("(PSK)-(AES-128-GCM)"));
    }
    // ocserv subtracts carrier overhead and adjusts again after DTLS negotiation.
    assert_eq!(
        session["MTU"].as_str(),
        Some(if mode == "require" { "1334" } else { "1372" })
    );
    for field in ["MTU", "TLS ciphersuite", "DTLS cipher", "DTLS ciphersuite"] {
        if let Some(value) = session[field].as_str() {
            println!("BENCH_NEGOTIATED,{mode},{field},{value}");
        }
    }
    assert_eq!(
        dtls,
        mode == "require",
        "server DTLS session disagrees with requested mode"
    );
    println!("BENCH_TRANSPORT,{mode},direct-docker-port,server-dtls-session={dtls}");
    udp_counters(container, mode, "after").await;
    drop(control);
}

async fn udp_counters(container: &str, mode: &str, phase: &str) {
    let output = tokio::process::Command::new("docker")
        .args(["exec", container, "cat", "/proc/net/snmp"])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    for line in String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("Udp:"))
    {
        println!("BENCH_SERVER_UDP,{mode},{phase},{line}");
    }
}

fn latency(mode: &str, kind: &str, sample: usize, mut values: Vec<f64>) {
    values.sort_by(f64::total_cmp);
    let quantile = |percent: usize| values[(values.len() * percent / 100).min(values.len() - 1)];
    println!(
        "BENCH_LATENCY,{mode},{kind},{sample},{:.3},{:.3},{:.3}",
        quantile(50),
        quantile(95),
        quantile(99)
    );
}
