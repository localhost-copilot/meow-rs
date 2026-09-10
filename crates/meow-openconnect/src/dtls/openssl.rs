use super::Key;
use std::ffi::{c_char, c_int, c_long, c_uint, c_void, CStr};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::ptr::NonNull;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::time::Instant;

type Ptr = *mut c_void;
type ConstPtr = *const c_void;
type PskCallback =
    unsafe extern "C" fn(Ptr, *const c_char, *mut c_char, c_uint, *mut u8, c_uint) -> c_uint;

// musl links a private, symbol-prefixed OpenSSL. Other supported platforms keep
// every lookup on one isolated library handle; never link unprefixed openssl-sys.
macro_rules! api {
    ($($field:ident: $symbol:literal ($($arg:ty),*) -> $ret:ty;)+) => {
        struct Api {
            #[cfg(not(all(target_os = "linux", target_env = "musl")))]
            _library: libloading::Library,
            $($field: unsafe extern "C" fn($($arg),*) -> $ret,)+
        }
        impl Api {
            #[cfg(not(all(target_os = "linux", target_env = "musl")))]
            unsafe fn from_library(library: libloading::Library) -> io::Result<Self> {
                // SAFETY: callers load OpenSSL 3; these are its public C ABI
                // signatures. The owned library outlives all function pointers.
                unsafe {
                    $(let $field = *library.get::<unsafe extern "C" fn($($arg),*) -> $ret>(
                        concat!($symbol, "\0").as_bytes()
                    ).map_err(|_| unavailable("OpenSSL 3 DTLS API unavailable"))?;)+
                    Ok(Self { _library: library, $($field,)+ })
                }
            }
            #[cfg(all(target_os = "linux", target_env = "musl"))]
            fn linked() -> Self {
                unsafe extern "C" {
                    $(#[link_name = concat!("meow_oc_", $symbol)]
                    fn $field($(_: $arg),*) -> $ret;)+
                }
                Self { $($field,)+ }
            }
        }
    }
}

api! {
    version: "OpenSSL_version_num" () -> libc::c_ulong;
    last_error: "ERR_peek_last_error" () -> libc::c_ulong;
    error_reason: "ERR_reason_error_string" (libc::c_ulong) -> *const c_char;
    method: "DTLS_client_method" () -> ConstPtr;
    ctx_new: "SSL_CTX_new" (ConstPtr) -> Ptr;
    ctx_free: "SSL_CTX_free" (Ptr) -> ();
    ctx_ctrl: "SSL_CTX_ctrl" (Ptr, c_int, c_long, Ptr) -> c_long;
    ctx_options: "SSL_CTX_set_options" (Ptr, u64) -> u64;
    ctx_ciphers: "SSL_CTX_set_cipher_list" (Ptr, *const c_char) -> c_int;
    ctx_security_level: "SSL_CTX_set_security_level" (Ptr, c_int) -> ();
    ctx_psk: "SSL_CTX_set_psk_client_callback" (Ptr, Option<PskCallback>) -> ();
    ssl_new: "SSL_new" (Ptr) -> Ptr;
    ssl_free: "SSL_free" (Ptr) -> ();
    ssl_ctrl: "SSL_ctrl" (Ptr, c_int, c_long, Ptr) -> c_long;
    ssl_connect_state: "SSL_set_connect_state" (Ptr) -> ();
    ssl_handshake: "SSL_do_handshake" (Ptr) -> c_int;
    ssl_error: "SSL_get_error" (ConstPtr, c_int) -> c_int;
    ssl_read: "SSL_read" (Ptr, Ptr, c_int) -> c_int;
    ssl_write: "SSL_write" (Ptr, ConstPtr, c_int) -> c_int;
    ssl_ex_set: "SSL_set_ex_data" (Ptr, c_int, Ptr) -> c_int;
    ssl_ex_get: "SSL_get_ex_data" (ConstPtr, c_int) -> Ptr;
    ssl_bio: "SSL_set_bio" (Ptr, Ptr, Ptr) -> ();
    ssl_session: "SSL_set_session" (Ptr, Ptr) -> c_int;
    ssl_reused: "SSL_session_reused" (ConstPtr) -> c_int;
    ssl_cipher: "SSL_get_current_cipher" (ConstPtr) -> ConstPtr;
    cipher_name: "SSL_CIPHER_get_name" (ConstPtr) -> *const c_char;
    cipher_find: "SSL_CIPHER_find" (ConstPtr, *const u8) -> ConstPtr;
    bio_new: "BIO_new_dgram" (c_int, c_int) -> Ptr;
    bio_ctrl: "BIO_ctrl" (Ptr, c_int, c_long, Ptr) -> c_long;
    session_new: "SSL_SESSION_new" () -> Ptr;
    session_free: "SSL_SESSION_free" (Ptr) -> ();
    session_version: "SSL_SESSION_set_protocol_version" (Ptr, c_int) -> c_int;
    session_cipher: "SSL_SESSION_set_cipher" (Ptr, ConstPtr) -> c_int;
    session_secret: "SSL_SESSION_set1_master_key" (Ptr, *const u8, usize) -> c_int;
    session_id: "SSL_SESSION_set1_id" (Ptr, *const u8, c_uint) -> c_int;
    session_time: "SSL_SESSION_set_time" (Ptr, c_long) -> c_long;
    session_timeout: "SSL_SESSION_set_timeout" (Ptr, c_long) -> c_long;
    random: "RAND_bytes" (*mut u8, c_int) -> c_int;
    clear_error: "ERR_clear_error" () -> ();
}

static API: OnceLock<Result<Arc<Api>, String>> = OnceLock::new();

fn api() -> io::Result<Arc<Api>> {
    API.get_or_init(|| load().map(Arc::new).map_err(|e| e.to_string()))
        .as_ref()
        .map(Arc::clone)
        .map_err(|e| unavailable(e.clone()))
}

pub(super) fn random_secret() -> io::Result<zeroize::Zeroizing<[u8; 48]>> {
    let api = api()?;
    let mut secret = zeroize::Zeroizing::new([0u8; 48]);
    // SAFETY: output is an owned writable 48-byte buffer, API remains loaded.
    check(unsafe { (api.random)(secret.as_mut_ptr(), 48) })?;
    Ok(secret)
}

#[cfg(all(target_os = "linux", target_env = "musl"))]
fn load() -> io::Result<Api> {
    let api = Api::linked();
    // SAFETY: points to our statically linked, prefixed OpenSSL implementation.
    if unsafe { (api.version)() } >> 28 != 3 {
        return Err(unavailable("OpenConnect DTLS requires OpenSSL 3"));
    }
    Ok(api)
}

#[cfg(not(all(target_os = "linux", target_env = "musl")))]
fn load() -> io::Result<Api> {
    #[cfg(target_os = "macos")]
    let candidates = [
        "libssl.3.dylib",
        "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
        "/usr/local/opt/openssl@3/lib/libssl.3.dylib",
    ];
    #[cfg(not(target_os = "macos"))]
    let candidates = ["libssl.so.3"];
    // glibc deep binding and macOS two-level namespaces are the currently
    // supported dynamic isolation mechanisms. musl uses prefixed static linkage.
    if !cfg!(any(
        target_os = "macos",
        all(target_os = "linux", target_env = "gnu")
    )) {
        return Err(unavailable(
            "OpenConnect DTLS supports macOS and glibc Linux",
        ));
    }
    for candidate in candidates {
        // SAFETY: loading a system OpenSSL library, never a network-provided
        // path. Its symbols and allocations stay behind this module's boundary.
        let library = unsafe {
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            {
                libloading::os::unix::Library::open(
                    Some(candidate),
                    libloading::os::unix::RTLD_NOW
                        | libloading::os::unix::RTLD_LOCAL
                        | libc::RTLD_DEEPBIND,
                )
                .map(Into::into)
            }
            #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
            {
                libloading::Library::new(candidate)
            }
        };
        if let Ok(library) = library {
            // SAFETY: see Api::from_library's ownership and ABI contract.
            let loaded = unsafe { Api::from_library(library)? };
            // SAFETY: no arguments, library remains owned by loaded.
            if unsafe { (loaded.version)() } >> 28 != 3 {
                return Err(unavailable("OpenConnect DTLS requires OpenSSL 3"));
            }
            return Ok(loaded);
        }
    }
    Err(unavailable(
        "OpenSSL 3 libssl is required for OpenConnect DTLS",
    ))
}

/// One authenticated DTLS channel. All operations preserve datagram boundaries.
pub struct Channel {
    api: Arc<Api>,
    ssl: NonNull<c_void>,
    socket: AsyncFd<UdpSocket>,
    _guard: super::DatagramGuard,
    key: Box<Key>,
    mtu: usize,
    resumed: bool,
    read_buffer: Box<[u8; 16384]>,
}

// SAFETY: SSL is exclusively owned; every operation requires &mut Channel.
// OpenSSL permits moving an object between threads when not concurrently used.
unsafe impl Send for Channel {}

impl Drop for Channel {
    fn drop(&mut self) {
        // SAFETY: this SSL was allocated by this API and is freed exactly once,
        // before its borrowed key and socket are dropped. BIO uses BIO_NOCLOSE.
        unsafe { (self.api.ssl_free)(self.ssl.as_ptr()) };
    }
}

unsafe extern "C" fn psk(
    ssl: Ptr,
    _: *const c_char,
    identity: *mut c_char,
    identity_max: c_uint,
    output: *mut u8,
    output_max: c_uint,
) -> c_uint {
    let Some(Ok(api)) = API.get() else { return 0 };
    if identity_max < 4 || output_max < 32 {
        return 0;
    }
    // SAFETY: SSL owns a reference to Channel's boxed key via ex_data; that box
    // remains alive until SSL_free. OpenSSL supplies buffers of the stated sizes.
    unsafe {
        let key = (api.ssl_ex_get)(ssl, 0).cast::<Key>();
        if key.is_null() {
            return 0;
        }
        match &*key {
            Key::Psk { secret, .. } => {
                std::ptr::copy_nonoverlapping(c"psk".as_ptr(), identity, 4);
                std::ptr::copy_nonoverlapping(secret.as_ptr(), output, 32);
                32
            }
            // Injected sessions must never fall back to an unauthenticated full
            // handshake. The callback only makes PSK ciphers selectable.
            Key::Resume { .. } => 0,
        }
    }
}

impl Channel {
    pub async fn connect(
        peer: SocketAddr,
        key: Key,
        mtu: u16,
        budget: Duration,
    ) -> io::Result<Self> {
        Self::connect_bound(peer, key, mtu, budget, 0).await
    }

    pub async fn connect_bound(
        peer: SocketAddr,
        key: Key,
        mtu: u16,
        budget: Duration,
        local_port: u16,
    ) -> io::Result<Self> {
        let ip = if peer.is_ipv4() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        };
        let socket = UdpSocket::bind(SocketAddr::new(ip, local_port))?;
        socket.connect(peer)?;
        Self::connect_socket(
            super::DatagramSocket {
                socket,
                guard: super::DatagramGuard(tokio_util::sync::CancellationToken::new()),
            },
            key,
            mtu,
            budget,
        )
        .await
    }

    pub async fn connect_socket(
        socket: super::DatagramSocket,
        key: Key,
        mtu: u16,
        budget: Duration,
    ) -> io::Result<Self> {
        let mut channel = Self::new_socket(socket, key, mtu)?;
        tokio::time::timeout(budget, channel.handshake())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DTLS handshake timed out"))??;
        Ok(channel)
    }

    fn new_socket(datagram: super::DatagramSocket, key: Key, mtu: u16) -> io::Result<Self> {
        let peer = datagram.socket.peer_addr()?;
        let id = match &key {
            Key::Psk { application_id, .. } => application_id,
            Key::Resume { session_id, .. } => session_id,
        };
        if id.is_empty() || id.len() > 32 || mtu < 576 || peer.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DTLS parameters",
            ));
        }
        let api = api()?;
        let socket = datagram.socket;
        socket.set_nonblocking(true)?;
        let socket = AsyncFd::new(socket)?;
        // SAFETY: each API call uses objects from this library, all buffers are
        // bounded, and ownership is transferred to RAII before fallible setup.
        unsafe {
            let ctx = NonNull::new((api.ctx_new)((api.method)())).ok_or_else(failed)?;
            let resumed = matches!(key, Key::Resume { .. });
            let setup = (|| {
                if key.version() == 0x100 {
                    // OpenSSL's Cisco compatibility mode implements DTLS_BAD_VER.
                    // The session must resume the CSTP-authenticated master secret.
                    (api.ctx_security_level)(ctx.as_ptr(), 0);
                    (api.ctx_options)(ctx.as_ptr(), 1 << 15); // SSL_OP_CISCO_ANYCONNECT
                }
                check((api.ctx_ctrl)(
                    ctx.as_ptr(),
                    123,
                    key.version().into(),
                    std::ptr::null_mut(),
                ) as c_int)?;
                check((api.ctx_ctrl)(
                    ctx.as_ptr(),
                    124,
                    key.version().into(),
                    std::ptr::null_mut(),
                ) as c_int)?;
                // NO_QUERY_MTU | NO_TICKET; externally injected sessions did not
                // negotiate EMS, so disable it only for that context.
                (api.ctx_options)(ctx.as_ptr(), (1 << 12) | (1 << 14) | u64::from(resumed));
                if resumed {
                    // Injected AnyConnect sessions omit RFC 5746. Permit only the
                    // initial connection; handshake() still requires resumption of
                    // the CSTP-authenticated key, never a new certificate handshake.
                    (api.ctx_options)(ctx.as_ptr(), 1 << 2); // LEGACY_SERVER_CONNECT
                }
                (api.ctx_ctrl)(ctx.as_ptr(), 41, 1, std::ptr::null_mut()); // read ahead
                let ciphers = match &key {
                    Key::Psk { .. } => {
                        c"PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:PSK-CHACHA20-POLY1305:PSK-AES128-CCM:PSK-AES128-CCM8:PSK-AES256-CCM8:PSK-AES128-CBC-SHA256"
                    }
                    Key::Resume { cipher, .. } => cipher.name(),
                };
                check((api.ctx_ciphers)(ctx.as_ptr(), ciphers.as_ptr()))?;
                (api.ctx_psk)(ctx.as_ptr(), Some(psk));
                NonNull::new((api.ssl_new)(ctx.as_ptr())).ok_or_else(failed)
            })();
            (api.ctx_free)(ctx.as_ptr()); // A successfully created SSL retains CTX.
            let ssl = setup?;
            let mut channel = Self {
                _guard: datagram.guard,
                api,
                ssl,
                socket,
                key: Box::new(key),
                mtu: usize::from(mtu) + 1,
                resumed,
                read_buffer: Box::new([0; 16384]),
            };
            channel.configure()?;
            Ok(channel)
        }
    }

    unsafe fn configure(&mut self) -> io::Result<()> {
        // SAFETY: all objects belong to this Channel's API. Setters copy session
        // bytes. SSL owns the BIO after SSL_set_bio; socket ownership stays Rust.
        unsafe {
            let api = &self.api;
            let ssl = self.ssl.as_ptr();
            (api.ssl_connect_state)(ssl);
            check((api.ssl_ex_set)(
                ssl,
                0,
                (&mut *self.key as *mut Key).cast(),
            ))?;
            let bio = NonNull::new((api.bio_new)(self.socket.get_ref().as_raw_fd(), 0))
                .ok_or_else(failed)?;
            (api.ssl_bio)(ssl, bio.as_ptr(), bio.as_ptr());
            let mut address: libc::sockaddr_storage = std::mem::zeroed();
            let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
            if libc::getpeername(
                self.socket.get_ref().as_raw_fd(),
                (&mut address as *mut libc::sockaddr_storage).cast(),
                &mut length,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            check((api.bio_ctrl)(
                bio.as_ptr(),
                32,
                0,
                (&mut address as *mut libc::sockaddr_storage).cast(),
            ) as c_int)?;
            // SSL_set_mtu takes record MTU, including DTLS overhead. The tunnel
            // MTU is checked separately for each application datagram.
            check(
                (api.ssl_ctrl)(ssl, 17, (self.mtu + 64) as c_long, std::ptr::null_mut()) as c_int,
            )?;
            // Modern PSK uses a deliberately unresumable random session solely
            // to carry App-ID in ClientHello. The server must perform a full
            // PSK handshake; resumed modes require the opposite outcome.
            let mut random = zeroize::Zeroizing::new([0u8; 48]);
            let (id, secret, cipher_id) = match &*self.key {
                Key::Psk { application_id, .. } => {
                    check((api.random)(random.as_mut_ptr(), 48))?;
                    (application_id.as_slice(), random.as_slice(), [0, 0xa8])
                }
                Key::Resume {
                    session_id,
                    secret,
                    cipher,
                } => (session_id.as_slice(), secret.as_slice(), cipher.id()),
            };
            let session = NonNull::new((api.session_new)()).ok_or_else(failed)?;
            let result = (|| {
                let cipher = (api.cipher_find)(ssl, cipher_id.as_ptr());
                if cipher.is_null() {
                    return Err(failed());
                }
                check((api.session_version)(session.as_ptr(), self.key.version()))?;
                check((api.session_cipher)(session.as_ptr(), cipher))?;
                check((api.session_secret)(
                    session.as_ptr(),
                    secret.as_ptr(),
                    secret.len(),
                ))?;
                check((api.session_id)(
                    session.as_ptr(),
                    id.as_ptr(),
                    id.len() as c_uint,
                ))?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| failed())?
                    .as_secs();
                (api.session_time)(session.as_ptr(), now.try_into().map_err(|_| failed())?);
                (api.session_timeout)(session.as_ptr(), 300);
                check((api.ssl_session)(ssl, session.as_ptr()))
            })();
            (api.session_free)(session.as_ptr()); // SSL_set_session takes a reference.
            result?;
            Ok(())
        }
    }

    async fn handshake(&mut self) -> io::Result<()> {
        loop {
            // SAFETY: exclusive live SSL, error queue read on the same thread.
            let result = unsafe {
                (self.api.clear_error)();
                (self.api.ssl_handshake)(self.ssl.as_ptr())
            };
            if result == 1 {
                // SAFETY: successful handshake on a live SSL.
                let reused = unsafe { (self.api.ssl_reused)(self.ssl.as_ptr()) != 0 };
                if reused != self.resumed {
                    return Err(failed());
                }
                return Ok(());
            }
            let interest = self.interest(result)?;
            self.wait(interest, true).await?;
        }
    }

    fn interest(&self, result: c_int) -> io::Result<Interest> {
        // SAFETY: called immediately after SSL operation, before any await.
        match unsafe { (self.api.ssl_error)(self.ssl.as_ptr(), result) } {
            2 => Ok(Interest::READABLE),
            3 => Ok(Interest::WRITABLE),
            _ => {
                // OpenSSL's static reason excludes peer-controlled error data and secrets.
                let reason = unsafe { (self.api.error_reason)((self.api.last_error)()) };
                if reason.is_null() {
                    Err(failed())
                } else {
                    let reason = unsafe { CStr::from_ptr(reason) }.to_string_lossy();
                    Err(io::Error::other(format!("OpenSSL DTLS: {reason}")))
                }
            }
        }
    }

    async fn wait(&mut self, interest: Interest, handshake: bool) -> io::Result<()> {
        let mut deadline = Instant::now() + Duration::from_secs(86400);
        if handshake {
            let mut timeout = libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            // SAFETY: DTLS_CTRL_GET_TIMEOUT writes a timeval to this live buffer.
            if unsafe {
                (self.api.ssl_ctrl)(
                    self.ssl.as_ptr(),
                    73,
                    0,
                    (&mut timeout as *mut libc::timeval).cast(),
                )
            } == 1
            {
                deadline = Instant::now()
                    + Duration::from_secs(timeout.tv_sec.max(0) as u64)
                    + Duration::from_micros(timeout.tv_usec.max(0) as u64);
            }
        }
        tokio::select! {
            ready = self.socket.ready(interest) => { ready?.clear_ready(); }
            _ = tokio::time::sleep_until(deadline), if handshake => {
                // SAFETY: public DTLSv1_handle_timeout macro, exclusive SSL.
                if unsafe { (self.api.ssl_ctrl)(self.ssl.as_ptr(), 74, 0, std::ptr::null_mut()) } < 0 { return Err(failed()); }
            }
        }
        Ok(())
    }

    pub async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() || packet.len() > self.mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DTLS datagram exceeds MTU",
            ));
        }
        loop {
            // SAFETY: stable input remains unchanged across WANT_READ/WRITE.
            let result = unsafe {
                (self.api.clear_error)();
                (self.api.ssl_write)(
                    self.ssl.as_ptr(),
                    packet.as_ptr().cast(),
                    packet.len() as c_int,
                )
            };
            if result > 0 {
                return if result as usize == packet.len() {
                    Ok(())
                } else {
                    Err(failed())
                };
            }
            let interest = self.interest(result)?;
            self.wait(interest, false).await?;
        }
    }

    pub async fn recv(&mut self) -> io::Result<Vec<u8>> {
        // Read the entire TLS plaintext record before applying tunnel limits,
        // so oversized records cannot be mistaken for valid truncated packets.
        loop {
            // SAFETY: writable buffer covers the passed length, exclusive SSL.
            let result = unsafe {
                (self.api.clear_error)();
                (self.api.ssl_read)(
                    self.ssl.as_ptr(),
                    self.read_buffer.as_mut_ptr().cast(),
                    self.read_buffer.len() as c_int,
                )
            };
            if result > 0 {
                if result as usize > self.mtu {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DTLS datagram exceeds MTU",
                    ));
                }
                return Ok(self.read_buffer[..result as usize].to_vec());
            }
            let interest = self.interest(result)?;
            self.wait(interest, false).await?;
        }
    }

    pub fn cipher(&self) -> String {
        // SAFETY: called after a successful handshake; name belongs to SSL.
        unsafe {
            let cipher = (self.api.ssl_cipher)(self.ssl.as_ptr());
            if cipher.is_null() {
                return String::new();
            }
            CStr::from_ptr((self.api.cipher_name)(cipher))
                .to_string_lossy()
                .into_owned()
        }
    }
}

fn check(result: c_int) -> io::Result<()> {
    if result > 0 {
        Ok(())
    } else {
        Err(failed())
    }
}
fn failed() -> io::Error {
    io::Error::other("OpenSSL DTLS operation failed")
}
fn unavailable(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
