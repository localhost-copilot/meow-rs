# OpenSSL / BoringSSL coexistence probe

The phase-zero DTLS experiments do not link BoringSSL. Production meow does.
Adding `openssl = "=0.10.81"` alongside `boring = "=4.22.0"` to a minimal binary
on macOS ARM64 failed to link (`ERR_get_error_all` unresolved). Both dependencies
request libraries named ssl/crypto. Merely resolving the library search order
does not establish ABI isolation: the two implementations also export overlapping
C symbol names.

This separate diagnostic loads OpenSSL 3 through a library handle and invokes
only symbols obtained from that handle. It allocates and frees 1,000 contexts
and sessions while BoringSSL is active in the same process. Linux glibc uses
`RTLD_DEEPBIND` to avoid resolving OpenSSL's internal references to BoringSSL.
Other platforms still require separate verification; the fallback loader is not
a portability claim.

```sh
cargo run --manifest-path experiments/openconnect/coexistence/Cargo.toml -- \
  /opt/homebrew/opt/openssl@3/lib/libssl.3.dylib
```

This is only a backend loading/ownership probe. It does **not** prove handshake,
data transport, cancellation, Linux/musl/Windows packaging, or VPN interoperability.
The production backend must establish those independently before release.

Verified on 2026-09-09: macOS ARM64, Rust 1.98.0, OpenSSL 3.6.3, BoringSSL
bindings 4.22.0; all 1,000 allocation/free iterations completed successfully.

The design alternatives remain symbol-prefixing a crypto backend at build time
or resolving OpenSSL's public API dynamically with platform-specific isolation.
Do not suppress duplicate symbols or cast BoringSSL objects to OpenSSL objects.

References: [BoringSSL incorporation guidance](https://github.com/google/boringssl/blob/main/INCORPORATING.md),
[binding symbol-prefix issue](https://github.com/cloudflare/boring/issues/197).
