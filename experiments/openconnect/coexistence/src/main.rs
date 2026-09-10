//! Diagnostic only: context ownership across two unrelated crypto libraries.
use std::ffi::{c_char, c_int, c_void, CStr};

fn main() {
    let path = std::env::args_os()
        .nth(1)
        .expect("pass the OpenSSL 3 libssl path");
    // SAFETY: this diagnostic explicitly loads the operator-selected OpenSSL 3
    // library. All signatures below are its public C API. The library outlives
    // every symbol and allocation; each object is freed by its own backend.
    unsafe {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let lib: libloading::Library = libloading::os::unix::Library::open(
            Some(&path),
            libloading::os::unix::RTLD_NOW | libloading::os::unix::RTLD_LOCAL | libc::RTLD_DEEPBIND,
        )
        .unwrap()
        .into();
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        let lib = libloading::Library::new(path).unwrap();

        let version = lib
            .get::<unsafe extern "C" fn(c_int) -> *const c_char>(b"OpenSSL_version\0")
            .unwrap();
        let method = lib
            .get::<unsafe extern "C" fn() -> *const c_void>(b"DTLS_client_method\0")
            .unwrap();
        let new_ctx = lib
            .get::<unsafe extern "C" fn(*const c_void) -> *mut c_void>(b"SSL_CTX_new\0")
            .unwrap();
        let free_ctx = lib
            .get::<unsafe extern "C" fn(*mut c_void)>(b"SSL_CTX_free\0")
            .unwrap();
        let new_ssl = lib
            .get::<unsafe extern "C" fn(*mut c_void) -> *mut c_void>(b"SSL_new\0")
            .unwrap();
        let free_ssl = lib
            .get::<unsafe extern "C" fn(*mut c_void)>(b"SSL_free\0")
            .unwrap();
        for _ in 0..1000 {
            let boring = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())
                .unwrap()
                .build();
            let bssl = boring.configure().unwrap().into_ssl("localhost").unwrap();
            let ctx = new_ctx(method());
            assert!(!ctx.is_null());
            let ssl = new_ssl(ctx);
            assert!(!ssl.is_null());
            free_ssl(ssl);
            free_ctx(ctx);
            drop(bssl);
        }
        println!(
            "{}: 1000 contexts/sessions coexist with BoringSSL",
            CStr::from_ptr(version(0)).to_str().unwrap()
        );
    }
}
