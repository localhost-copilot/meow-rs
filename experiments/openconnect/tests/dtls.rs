//! Loopback DTLS backend probes. All key material is synthetic test data.
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::ssl::{
    ErrorCode, Ssl, SslContext, SslContextBuilder, SslMethod, SslOptions, SslSession,
    SslSessionCacheMode, SslStream, SslVersion,
};
use std::io::{self, Read, Write};
use std::net::UdpSocket;
use std::os::raw::{c_int, c_long, c_uint};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Public OpenSSL C APIs absent from openssl/openssl-sys at the pinned versions.
// No OpenSSL private struct layout or hand-built ASN.1 session encoding is used.
unsafe extern "C" {
    fn SSL_SESSION_new() -> *mut openssl_sys::SSL_SESSION;
    fn SSL_SESSION_set_protocol_version(s: *mut openssl_sys::SSL_SESSION, v: c_int) -> c_int;
    fn SSL_SESSION_set_cipher(
        s: *mut openssl_sys::SSL_SESSION,
        c: *const openssl_sys::SSL_CIPHER,
    ) -> c_int;
    fn SSL_SESSION_set1_master_key(
        s: *mut openssl_sys::SSL_SESSION,
        key: *const u8,
        len: usize,
    ) -> c_int;
    fn SSL_SESSION_set1_id(s: *mut openssl_sys::SSL_SESSION, id: *const u8, len: c_uint) -> c_int;
    fn SSL_SESSION_set1_id_context(
        s: *mut openssl_sys::SSL_SESSION,
        id: *const u8,
        len: c_uint,
    ) -> c_int;
    fn SSL_SESSION_set_time(s: *mut openssl_sys::SSL_SESSION, time: c_long) -> c_long;
    fn SSL_SESSION_set_timeout(s: *mut openssl_sys::SSL_SESSION, time: c_long) -> c_long;
    fn SSL_CIPHER_find(ssl: *mut openssl_sys::SSL, id: *const u8)
        -> *const openssl_sys::SSL_CIPHER;
}

const SESSION_ID: [u8; 32] = [0x42; 32];
const SECRET: [u8; 48] = [0x5a; 48];
const ID_CONTEXT: &[u8] = b"meow-phase-zero";
const PSK: [u8; 32] = [0x39; 32];

#[derive(Clone, Copy, Debug)]
enum Mode {
    Psk,
    Injected12,
    InjectedChacha12,
    CiscoLegacy,
}

impl Mode {
    fn cipher(self) -> &'static str {
        match self {
            Self::Psk => "PSK-AES128-GCM-SHA256",
            Self::Injected12 => "AES128-GCM-SHA256",
            Self::InjectedChacha12 => "PSK-CHACHA20-POLY1305",
            Self::CiscoLegacy => "AES128-SHA",
        }
    }
    fn version(self) -> c_int {
        match self {
            Self::Psk | Self::Injected12 | Self::InjectedChacha12 => 0xfefd,
            // OpenSSL's public DTLS1_BAD_VER value, used by Cisco's pre-RFC DTLS.
            Self::CiscoLegacy => 0x0100,
        }
    }
}

fn injected_session(ssl: &openssl::ssl::SslRef, mode: Mode, wrong_key: bool) -> SslSession {
    let cipher_id = match mode {
        Mode::Injected12 => [0x00, 0x9c],
        Mode::InjectedChacha12 => [0xcc, 0xab],
        Mode::CiscoLegacy => [0x00, 0x2f],
        Mode::Psk => unreachable!(),
    };
    let mut secret = SECRET;
    if wrong_key {
        secret[0] ^= 1;
    }
    // SAFETY: `ssl` is live, cipher ID is exactly two bytes, and setters copy
    // these bounded slices. The new session has one owned reference, transferred
    // to the Rust RAII wrapper immediately so all later failures free it.
    unsafe {
        let cipher = SSL_CIPHER_find(ssl.as_ptr(), cipher_id.as_ptr());
        assert!(!cipher.is_null(), "cipher unavailable");
        let raw = SSL_SESSION_new();
        assert!(!raw.is_null());
        let session = SslSession::from_ptr(raw);
        assert_eq!(SSL_SESSION_set_protocol_version(raw, mode.version()), 1);
        assert_eq!(SSL_SESSION_set_cipher(raw, cipher), 1);
        assert_eq!(
            SSL_SESSION_set1_master_key(raw, secret.as_ptr(), secret.len()),
            1
        );
        assert_eq!(
            SSL_SESSION_set1_id(raw, SESSION_ID.as_ptr(), SESSION_ID.len() as c_uint),
            1
        );
        assert_eq!(
            SSL_SESSION_set1_id_context(raw, ID_CONTEXT.as_ptr(), ID_CONTEXT.len() as c_uint),
            1
        );
        SSL_SESSION_set_time(
            raw,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as c_long,
        );
        SSL_SESSION_set_timeout(raw, 300);
        session
    }
}

fn context(mode: Mode, server: bool, wrong_key: bool) -> SslContext {
    let mut ctx = SslContextBuilder::new(if server {
        SslMethod::dtls_server()
    } else {
        SslMethod::dtls_client()
    })
    .unwrap();
    if matches!(mode, Mode::CiscoLegacy) {
        // SslVersion exposes neither DTLS1_BAD_VER nor a raw constructor.
        // SAFETY: these public version-setting macros take an integer, not a pointer.
        unsafe {
            assert_eq!(
                openssl_sys::SSL_CTX_ctrl(
                    ctx.as_ptr(),
                    123,
                    mode.version().into(),
                    std::ptr::null_mut()
                ),
                1
            );
            assert_eq!(
                openssl_sys::SSL_CTX_ctrl(
                    ctx.as_ptr(),
                    124,
                    mode.version().into(),
                    std::ptr::null_mut()
                ),
                1
            );
        }
    } else {
        ctx.set_min_proto_version(Some(SslVersion::DTLS1_2))
            .unwrap();
        ctx.set_max_proto_version(Some(SslVersion::DTLS1_2))
            .unwrap();
    }
    ctx.set_cipher_list(mode.cipher()).unwrap();
    ctx.set_options(SslOptions::NO_TICKET | SslOptions::NO_QUERY_MTU);
    match mode {
        Mode::Psk if server => ctx.set_psk_server_callback(|_, identity, key| {
            assert_eq!(identity, Some(b"phase-zero".as_slice()));
            key[..PSK.len()].copy_from_slice(&PSK);
            Ok(PSK.len())
        }),
        Mode::Psk => ctx.set_psk_client_callback(move |_, _, identity, key| {
            identity[..11].copy_from_slice(b"phase-zero\0");
            key[..PSK.len()].copy_from_slice(&PSK);
            if wrong_key {
                key[0] ^= 1;
            }
            Ok(PSK.len())
        }),
        Mode::Injected12 | Mode::InjectedChacha12 | Mode::CiscoLegacy => {
            if matches!(mode, Mode::InjectedChacha12) && !server {
                // OpenSSL filters PSK ciphers unless a callback exists, even for
                // resumption. Refuse any fallback that actually asks for a PSK.
                ctx.set_psk_client_callback(|_, _, _, _| Err(openssl::error::ErrorStack::get()));
            }
            // An externally constructed session has no EMS transcript. This is
            // scoped to this probe context, never a global TLS policy change.
            unsafe {
                openssl_sys::SSL_CTX_set_options(
                    ctx.as_ptr(),
                    1, /* SSL_OP_NO_EXTENDED_MASTER_SECRET */
                );
            }
            if matches!(mode, Mode::CiscoLegacy) {
                // Explicit legacy experiment only; modern probes retain defaults.
                ctx.set_security_level(0);
                // SAFETY: public SSL_OP_NO_ENCRYPT_THEN_MAC flag on a live context.
                unsafe {
                    openssl_sys::SSL_CTX_set_options(ctx.as_ptr(), 1 << 19);
                }
            }
            ctx.set_session_id_context(ID_CONTEXT).unwrap();
            if server {
                ctx.set_session_cache_mode(
                    SslSessionCacheMode::SERVER | SslSessionCacheMode::NO_INTERNAL,
                );
                // SAFETY: each session is freshly created for the requesting SSL;
                // it has never been associated with another SslContext.
                unsafe {
                    ctx.set_get_session_callback(move |ssl, id| {
                        (id == SESSION_ID).then(|| injected_session(ssl, mode, false))
                    });
                }
            }
        }
    }
    ctx.build()
}

#[derive(Debug)]
struct Datagram {
    socket: UdpSocket,
    drop_next: bool,
    blackhole: bool,
    dropped: usize,
    sent: usize,
    client_hellos: usize,
}

impl Read for Datagram {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }
}
impl Write for Datagram {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sent += 1;
        if std::env::var_os("MEOW_DTLS_TRACE").is_some()
            && buf.len() >= 25
            && buf[0] == 22
            && buf[3..5] == [0, 0]
        {
            eprintln!(
                "DTLS handshake record version={:02x}{:02x} type={} message_seq={} bytes={}",
                buf[1],
                buf[2],
                buf[13],
                u16::from_be_bytes([buf[17], buf[18]]),
                buf.len()
            );
        }
        if buf.len() > 13 && buf[0] == 22 && buf[13] == 1 {
            self.client_hellos += 1;
        }
        if self.blackhole || std::mem::take(&mut self.drop_next) {
            self.dropped += 1;
            Ok(buf.len())
        } else {
            self.socket.send(buf)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn pair(
    mode: Mode,
    wrong_key: bool,
    drop_first: bool,
    blackhole: bool,
) -> (SslStream<Datagram>, SslStream<Datagram>) {
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    a.connect(b.local_addr().unwrap()).unwrap();
    b.connect(a.local_addr().unwrap()).unwrap();
    a.set_nonblocking(true).unwrap();
    b.set_nonblocking(true).unwrap();
    let mut client_ssl = Ssl::new(&context(mode, false, wrong_key)).unwrap();
    client_ssl.set_connect_state();
    client_ssl.set_mtu(1200).unwrap();
    if !matches!(mode, Mode::Psk) {
        let session = injected_session(&client_ssl, mode, wrong_key);
        // SAFETY: the session was constructed for this SSL's context. OpenSSL
        // retains its own reference, so the local wrapper can be dropped.
        unsafe {
            client_ssl.set_session(&session).unwrap();
        }
    }
    let mut server_ssl = Ssl::new(&context(mode, true, false)).unwrap();
    server_ssl.set_accept_state();
    server_ssl.set_mtu(1200).unwrap();
    let client = SslStream::new(
        client_ssl,
        Datagram {
            socket: a,
            drop_next: drop_first,
            blackhole,
            dropped: 0,
            sent: 0,
            client_hellos: 0,
        },
    )
    .unwrap();
    let server = SslStream::new(
        server_ssl,
        Datagram {
            socket: b,
            drop_next: false,
            blackhole: false,
            dropped: 0,
            sent: 0,
            client_hellos: 0,
        },
    )
    .unwrap();
    (client, server)
}

fn handle_timeout(stream: &SslStream<Datagram>) -> i64 {
    // SAFETY: live SSL pointer; DTLSv1_handle_timeout is the public C macro
    // SSL_ctrl(ssl, DTLS_CTRL_HANDLE_TIMEOUT=74, 0, NULL), no pointer output.
    unsafe { openssl_sys::SSL_ctrl(stream.ssl().as_ptr(), 74, 0, std::ptr::null_mut()) as i64 }
}

fn handshake(
    client: &mut SslStream<Datagram>,
    server: &mut SslStream<Datagram>,
    budget: Duration,
) -> Result<usize, String> {
    let deadline = Instant::now() + budget;
    let mut ready = [false; 2];
    let mut retransmits = 0;
    loop {
        for (i, stream) in [&mut *client, &mut *server].into_iter().enumerate() {
            if ready[i] {
                continue;
            }
            match stream.do_handshake() {
                Ok(()) => ready[i] = true,
                Err(err) if matches!(err.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => {}
                Err(err) => return Err(format!("peer {i}: {err}")),
            }
            let result = handle_timeout(stream);
            if result < 0 {
                return Err("DTLS timer failed".into());
            }
            retransmits += usize::from(result > 0);
        }
        if ready == [true; 2] {
            return Ok(retransmits);
        }
        if Instant::now() >= deadline {
            return Err("handshake deadline".into());
        }
        // Real OpenSSL timers and loopback UDP need wall time. No background
        // tasks survive this bounded driver; production will use Tokio readiness.
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn receive(stream: &mut SslStream<Datagram>) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buf = vec![0; 16384];
    loop {
        match stream.ssl_read(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                return buf;
            }
            Err(e) if matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => {}
            Err(e) => panic!("application read: {e}"),
        }
        assert!(Instant::now() < deadline, "application read deadline");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn success(mode: Mode, drop_first: bool) {
    println!("backend: {}; mode={mode:?}", openssl::version::version());
    let (mut client, mut server) = pair(mode, false, drop_first, false);
    let explicit_timer_actions =
        handshake(&mut client, &mut server, Duration::from_secs(5)).unwrap();
    assert_eq!(client.ssl().session_reused(), !matches!(mode, Mode::Psk));
    assert_eq!(server.ssl().session_reused(), !matches!(mode, Mode::Psk));
    assert_eq!(client.ssl().current_cipher().unwrap().name(), mode.cipher());
    for payload in [vec![1; 1], vec![2; 1100], vec![3; 19]] {
        assert_eq!(client.ssl_write(&payload).unwrap(), payload.len());
        assert_eq!(receive(&mut server), payload);
        assert_eq!(server.ssl_write(&payload).unwrap(), payload.len());
        assert_eq!(receive(&mut client), payload);
    }
    if drop_first {
        assert_eq!(client.get_ref().dropped, 1);
        // SSL_do_handshake can process an expired timer before our explicit
        // handle_timeout call. Observe the wire flight, not the macro's return.
        assert!(
            client.get_ref().client_hellos >= 2,
            "dropped ClientHello must be retransmitted"
        );
    }
    println!("{mode:?}: version={}, cipher={}, reused={}, client_hellos={}, explicit_timer_actions={explicit_timer_actions}; bidirectional datagrams OK",
        client.ssl().version_str(), client.ssl().current_cipher().unwrap().name(), client.ssl().session_reused(), client.get_ref().client_hellos);
}

#[test]
fn dtls12_psk_and_lost_client_hello() {
    success(Mode::Psk, true);
}

#[test]
fn dtls12_injected_session_without_prior_handshake() {
    success(Mode::Injected12, false);
}

#[test]
fn injected_session_retransmits_lost_client_hello() {
    success(Mode::Injected12, true);
}

#[test]
fn wrong_psk_cannot_establish_session() {
    let (mut client, mut server) = pair(Mode::Psk, true, false, false);
    let result = handshake(&mut client, &mut server, Duration::from_millis(1500));
    assert!(result.is_err(), "wrong key accepted");
    println!("wrong PSK: {}", result.unwrap_err());
}

#[test]
fn wrong_injected_secret_cannot_establish_session() {
    let (mut client, mut server) = pair(Mode::Injected12, true, false, false);
    let result = handshake(&mut client, &mut server, Duration::from_millis(1500));
    assert!(result.is_err(), "wrong injected secret accepted");
    println!("wrong injected secret: {}", result.unwrap_err());
}

#[test]
fn udp_blackhole_has_bounded_failure() {
    let (mut client, mut server) = pair(Mode::Psk, false, false, true);
    let result = handshake(&mut client, &mut server, Duration::from_millis(1500));
    assert_eq!(result.unwrap_err(), "handshake deadline");
    assert!(
        client.get_ref().dropped >= 2,
        "initial flight plus timed retransmission"
    );
    println!(
        "UDP blackhole: bounded deadline after retransmission; caller can select TLS fallback"
    );
}

struct ReferenceGateway {
    child: std::process::Child,
    ca: std::path::PathBuf,
}

impl Drop for ReferenceGateway {
    fn drop(&mut self) {
        // Also run on assertion failure: no gateway or certificate fixture leaks.
        self.child.stdin.take();
        for _ in 0..50 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.ca);
    }
}

fn reference_gateway(mode: Mode) {
    use openssl::ssl::SslConnector;
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;
    use std::process::{Command, Stdio};

    let name = match mode {
        Mode::Psk => "psk",
        Mode::InjectedChacha12 => "injected",
        Mode::CiscoLegacy => "legacy",
        Mode::Injected12 => unreachable!(),
    };
    let executable = std::env::var_os("MEOW_REFERENCE_GATEWAY")
        .expect("set MEOW_REFERENCE_GATEWAY to the compiled fixture driver");
    let ca = std::env::temp_dir().join(format!("meow-probe-ca-{}-{name}.pem", std::process::id()));
    let child = Command::new(executable)
        .args([name])
        .arg(&ca)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut gateway = ReferenceGateway { child, ca };
    let mut output = BufReader::new(gateway.child.stdout.take().unwrap());
    let mut address = String::new();
    let mut hostname = String::new();
    output.read_line(&mut address).unwrap();
    output.read_line(&mut hostname).unwrap();
    let mut tls_config = SslConnector::builder(SslMethod::tls_client()).unwrap();
    tls_config.set_ca_file(&gateway.ca).unwrap();
    let tcp = TcpStream::connect(address.trim()).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut tls = tls_config.build().connect(hostname.trim(), tcp).unwrap();
    // Synthetic secret and Cookie only. Keep the authenticated control connection
    // alive for the entire independent DTLS probe, as required by the fixture.
    let secret_hex = SECRET
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let offered = match mode {
        Mode::Psk => "PSK-NEGOTIATE",
        Mode::InjectedChacha12 => "OC2-DTLS1_2-CHACHA20-POLY1305",
        Mode::CiscoLegacy => "AES128-SHA",
        Mode::Injected12 => unreachable!(),
    };
    write!(tls, "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nHost: {}\r\nCookie: webvpn=phase0-test-cookie\r\nX-CSTP-Version: 1\r\nX-DTLS-CipherSuite: {offered}\r\nX-DTLS12-CipherSuite: {offered}\r\nX-DTLS-Master-Secret: {secret_hex}\r\n\r\n", hostname.trim()).unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        tls.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
        assert!(response.len() < 16384);
    }
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 "));
    let header = |key: &str| {
        response
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case(key)
                    .then(|| value.trim().to_owned())
            })
            .unwrap_or_else(|| panic!("missing {key}"))
    };
    let prefix = if matches!(mode, Mode::CiscoLegacy) {
        "X-DTLS"
    } else {
        "X-DTLS12"
    };
    let port: u16 = header(&format!("{prefix}-Port")).parse().unwrap();
    assert_eq!(header(&format!("{prefix}-CipherSuite")), offered);
    let mut ctx = context(mode, false, false);
    if matches!(mode, Mode::Psk) {
        let mut exported = [0; 32];
        tls.ssl()
            .export_keying_material(&mut exported, "EXPORTER-openconnect-psk", None)
            .unwrap();
        let mut builder = SslContextBuilder::new(SslMethod::dtls_client()).unwrap();
        builder
            .set_min_proto_version(Some(SslVersion::DTLS1_2))
            .unwrap();
        builder
            .set_max_proto_version(Some(SslVersion::DTLS1_2))
            .unwrap();
        builder.set_cipher_list(mode.cipher()).unwrap();
        builder.set_options(SslOptions::NO_QUERY_MTU | SslOptions::NO_TICKET);
        builder.set_psk_client_callback(move |_, _, identity, key| {
            identity[..4].copy_from_slice(b"psk\0");
            key[..exported.len()].copy_from_slice(&exported);
            Ok(exported.len())
        });
        ctx = builder.build();
    } else {
        assert_eq!(header(&format!("{prefix}-Session-ID")), "42".repeat(32));
    }
    let mut ssl = Ssl::new(&ctx).unwrap();
    ssl.set_connect_state();
    ssl.set_mtu(1200).unwrap();
    if !matches!(mode, Mode::Psk) {
        let session = injected_session(&ssl, mode, false);
        // SAFETY: session was built for this SSL/context and has a live owner.
        unsafe {
            ssl.set_session(&session).unwrap();
        }
    }
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(("127.0.0.1", port)).unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut dtls = SslStream::new(
        ssl,
        Datagram {
            socket,
            drop_next: false,
            blackhole: false,
            dropped: 0,
            sent: 0,
            client_hellos: 0,
        },
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match dtls.do_handshake() {
            Ok(()) => break,
            Err(e) if matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => {}
            Err(e) => panic!("{mode:?}: reference handshake: {e}"),
        }
        assert!(handle_timeout(&dtls) >= 0);
        assert!(
            Instant::now() < deadline,
            "{mode:?}: reference handshake deadline; state={}",
            dtls.ssl().state_string_long()
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(dtls.ssl().session_reused(), !matches!(mode, Mode::Psk));
    for size in [1, 1100, 19] {
        // DTLS application type 0 means DATA; the fixture peer echoes its payload.
        let mut packet = vec![0x45; size + 1];
        packet[0] = 0;
        assert_eq!(dtls.ssl_write(&packet).unwrap(), packet.len());
        assert_eq!(receive(&mut dtls), packet);
    }
    println!(
        "reference {mode:?}: {}; {}; reused={}; 1/1100/19-byte DATA round trips OK",
        openssl::version::version(),
        dtls.ssl().version_str(),
        dtls.ssl().session_reused()
    );
}

#[test]
#[ignore = "requires separately built mihomo reference-gateway; see README"]
fn reference_psk_uses_control_tls_exporter() {
    reference_gateway(Mode::Psk);
}

#[test]
#[ignore = "requires separately built mihomo reference-gateway; see README"]
fn reference_injected_dtls12() {
    reference_gateway(Mode::InjectedChacha12);
}

#[test]
#[ignore = "known failing legacy diagnostic against the recorded fixture; see README"]
fn reference_cisco_legacy() {
    reference_gateway(Mode::CiscoLegacy);
}
