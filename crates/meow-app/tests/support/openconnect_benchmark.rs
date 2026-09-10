//! Real app routing/listener path, against the independent ocserv Docker fixture.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Legacy,
    A,
    B,
}

impl Profile {
    pub fn selected() -> Self {
        match std::env::var("MEOW_BENCH_PROFILE").as_deref() {
            Err(_) | Ok("legacy") => Self::Legacy,
            Ok("a") => Self::A,
            Ok("b") => Self::B,
            _ => panic!("MEOW_BENCH_PROFILE must be legacy, a or b"),
        }
    }

    fn server_mtu(self) -> u16 {
        match self {
            Self::Legacy => 1400,
            Self::A => 1280,
            Self::B => 1383,
        }
    }

    fn cipher(self) -> &'static str {
        match std::env::var("MEOW_BENCH_CIPHER").as_deref() {
            Ok("AES-128-GCM") => "AES-128-GCM",
            Ok("AES-256-GCM") => "AES-256-GCM",
            Err(_) if self == Self::Legacy => "AES-128-GCM",
            Err(_) => "AES-256-GCM",
            _ => panic!("MEOW_BENCH_CIPHER must be AES-128-GCM or AES-256-GCM"),
        }
    }

    pub fn server_env(self) -> [(&'static str, String); 3] {
        [
            ("OCSERV_MTU", self.server_mtu().to_string()),
            ("OCSERV_CIPHER", self.cipher().into()),
            ("OCSERV_IPV6", (self == Self::Legacy).to_string()),
        ]
    }

    pub fn configure(self, yaml: &str) -> String {
        if self == Self::Legacy {
            return yaml.into();
        }
        // Public fixture values only; the private YAML is never loaded here.
        let mut config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let proxy = &mut config["proxies"][0];
        proxy["mtu"] = 0.into();
        proxy["base-mtu"] = 0.into();
        proxy["compression"] = "stateless".into();
        proxy["ipv6-disabled"] = (self == Self::A).into();
        proxy["queue-length"] = if self == Self::A { 128 } else { 32 }.into();
        proxy["dpd-interval"] = 5.into();
        proxy["reconnect-timeout"] = if self == Self::A { 60 } else { 300 }.into();
        serde_yaml::to_string(&config).unwrap()
    }
}

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
            let mut config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
            let ca = &mut config["proxies"][0]["ca"];
            *ca = std::fs::read_to_string(ca.as_str().unwrap())
                .unwrap()
                .into();
            serde_yaml::to_string(&config).unwrap()
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
        println!("BENCH_PROXY_PID,{}", process.id().unwrap());
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
    if let Ok(delay) = std::env::var("MEOW_BENCH_DELAY_MS") {
        let delay: u32 = delay
            .parse()
            .expect("MEOW_BENCH_DELAY_MS must be an integer");
        assert!((1..=1000).contains(&delay));
        // Delay the isolated fixture's egress only; this adds the stated amount
        // to RTT without changing host interfaces or production services.
        let output = tokio::process::Command::new("docker")
            .args([
                "exec",
                container,
                "tc",
                "qdisc",
                "add",
                "dev",
                "eth0",
                "root",
                "netem",
                "limit",
                "100000",
                "delay",
                &format!("{delay}ms"),
            ])
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "fixture netem failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        println!("BENCH_ADDED_RTT_MS,{mode},{delay}");
    }
    let (mut warm, _) = super::socks_target(address, 1, "192.0.2.1:8080".parse().unwrap()).await;
    warm.write_all(&[0x5a; 128]).await.unwrap();
    let mut answer = [0; 128];
    if let Err(error) = warm.read_exact(&mut answer).await {
        let logs = tokio::process::Command::new("docker")
            .args(["logs", container])
            .output()
            .await
            .unwrap();
        panic!(
            "local benchmark warmup failed: {error}; ocserv: {}",
            String::from_utf8_lossy(&logs.stderr)
        );
    }
    assert_eq!(answer, [0x5a; 128]);
    if mode != "off" {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if session_status(container)
                    .await
                    .to_string()
                    .contains("DTLS1.2")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("benchmark must establish DTLS before timing");
    }
    inspect_session(container, mode).await;
    drop(warm);
    if std::env::var("MEOW_BENCH_WORKLOAD").as_deref() == Ok("iperf3") {
        iperf(address, mode, container).await;
        return;
    }
    network_counters(container, mode, "before").await;
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
    let udp_payload =
        usize::from(Profile::selected().server_mtu() - if mode == "off" { 28 } else { 66 } - 28)
            .min(1200);
    println!("BENCH_UDP_PAYLOAD,{mode},{udp_payload}");
    for sample in 1..=3 {
        let mut received = vec![false; 8192];
        let mut packet = header.to_vec();
        packet.resize(header.len() + udp_payload, 0x5a);
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
                assert_eq!(n, header.len() + udp_payload);
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
            (count * udp_payload) as f64 / 1048576.0 / seconds
        );
    }
    inspect_session(container, mode).await;
    network_counters(container, mode, "after").await;
    drop(control);
}

async fn session_status(container: &str) -> serde_json::Value {
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
    serde_json::from_str(&status).unwrap()
}

async fn inspect_session(container: &str, mode: &str) {
    let sessions = session_status(container).await;
    let dtls = sessions.to_string().contains("DTLS1.2");
    let session = &sessions[0];
    let profile = Profile::selected();
    assert!(session["TLS ciphersuite"]
        .as_str()
        .unwrap()
        .contains(profile.cipher().trim_end_matches('M')));
    if mode != "off" {
        assert!(session["DTLS cipher"]
            .as_str()
            .unwrap()
            .contains(&format!("(PSK)-({})", profile.cipher())));
    }
    // ocserv subtracts carrier overhead and adjusts again after DTLS negotiation.
    assert_eq!(
        session["MTU"].as_str(),
        Some(
            (profile.server_mtu() - if mode == "off" { 28 } else { 66 })
                .to_string()
                .as_str()
        )
    );
    for field in ["MTU", "TLS ciphersuite", "DTLS cipher", "DTLS ciphersuite"] {
        if let Some(value) = session[field].as_str() {
            println!("BENCH_NEGOTIATED,{mode},{field},{value}");
        }
    }
    assert_eq!(
        dtls,
        mode != "off",
        "server DTLS session disagrees with requested mode"
    );
    println!("BENCH_TRANSPORT,{mode},direct-docker-port,server-dtls-session={dtls}");
}

async fn iperf(address: SocketAddr, mode: &str, container: &str) {
    let samples: usize = std::env::var("MEOW_BENCH_IPERF_SAMPLES").map_or(3, |value| {
        value.parse().expect("invalid iperf sample count")
    });
    assert!((1..=10).contains(&samples));
    let directions = std::env::var("MEOW_BENCH_IPERF_DIRECTIONS").unwrap_or_else(|_| {
        if Profile::selected() == Profile::Legacy {
            "upload,download"
        } else {
            "upload,download,bidir"
        }
        .into()
    });
    let directions: Vec<_> = directions.split(',').collect();
    assert!(
        !directions.is_empty()
            && directions
                .iter()
                .all(|direction| matches!(*direction, "upload" | "download" | "bidir"))
    );
    let streams = std::env::var("MEOW_BENCH_IPERF_STREAMS").unwrap_or_else(|_| "1,4".into());
    let streams: Vec<usize> = streams
        .split(',')
        .map(|value| value.parse().unwrap())
        .collect();
    assert!(!streams.is_empty() && streams.iter().all(|count| matches!(count, 1 | 4)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    // iperf3 has no SOCKS support. Forward both control and data TCP connections
    // through the same SOCKS path for both kernels, including reverse transfers.
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        let mut flows = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut local, _) = accepted.unwrap();
                    flows.spawn(async move {
                        let (mut remote, _) = super::socks_target(address, 1, "192.0.2.1:5201".parse().unwrap()).await;
                        tokio::io::copy_bidirectional(&mut local, &mut remote).await
                    });
                }
                result = flows.join_next(), if !flows.is_empty() => {
                    // iperf closes control/data connections independently;
                    // a reset during teardown is harmless if its JSON succeeds.
                    let _ = result.unwrap().unwrap();
                }
            }
        }
    });
    let version = tokio::process::Command::new("iperf3")
        .arg("--version")
        .output()
        .await
        .unwrap();
    assert!(version.status.success());
    println!(
        "BENCH_IPERF_VERSION,{}",
        String::from_utf8_lossy(&version.stdout)
            .lines()
            .next()
            .unwrap()
    );
    network_counters(container, mode, "before").await;
    for direction in directions {
        let label = match direction {
            "upload" => "false",
            "download" => "true",
            _ => "bidir",
        };
        for concurrency in &streams {
            for sample in 1..=samples {
                let mut command = tokio::process::Command::new("iperf3");
                command.args([
                    "-c",
                    "127.0.0.1",
                    "-p",
                    &port,
                    "-P",
                    &concurrency.to_string(),
                    "-t",
                    "10",
                    "-O",
                    "2",
                    "-J",
                ]);
                if direction == "download" {
                    command.arg("-R");
                } else if direction == "bidir" {
                    command.arg("--bidir");
                }
                let output = command.kill_on_drop(true).output().await.unwrap();
                assert!(
                    output.status.success(),
                    "iperf3 failed: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert!(report.get("error").is_none(), "iperf3 error: {report}");
                let rate = report["end"]["sum_received"]["bits_per_second"]
                    .as_f64()
                    .unwrap();
                assert!(rate > 0.0);
                if direction == "bidir" {
                    let reverse_rate = report["end"]["sum_received_bidir_reverse"]
                        ["bits_per_second"]
                        .as_f64()
                        .unwrap();
                    assert!(reverse_rate > 0.0);
                    println!(
                        "BENCH_IPERF_BIDIR,{mode},{concurrency},{sample},{:.3},{:.3}",
                        rate / 1_000_000.0,
                        reverse_rate / 1_000_000.0
                    );
                } else {
                    println!(
                        "BENCH_IPERF,{mode},{label},{concurrency},{sample},{:.3}",
                        rate / 1_000_000.0
                    );
                }
                println!("BENCH_IPERF_JSON,{mode},{label},{concurrency},{sample},{report}");
                network_counters(
                    container,
                    mode,
                    &format!("iperf-{label}-{concurrency}-{sample}"),
                )
                .await;
            }
        }
    }
    inspect_session(container, mode).await;
    network_counters(container, mode, "after").await;
}

async fn network_counters(container: &str, mode: &str, phase: &str) {
    let output = tokio::process::Command::new("docker")
        .args(["exec", container, "cat", "/proc/net/snmp"])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    for line in String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|line| {
            line.starts_with("Udp:") || line.starts_with("Tcp:") || line.starts_with("Ip:")
        })
    {
        let protocol = line.split(':').next().unwrap().to_ascii_uppercase();
        println!("BENCH_SERVER_{protocol},{mode},{phase},{line}");
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
