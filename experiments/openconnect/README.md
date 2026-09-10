# OpenConnect phase-zero probes

Standalone, non-published experiments for the [OpenConnect design](../../docs/specs/openconnect-design.md).
This is not a usable meow outbound. Its nested workspace keeps OpenSSL and smoltcp
out of the product dependency graph and root lockfile.

## Prerequisites and local suite

- Rust compatible with the declared 1.89 MSRV. The recorded execution used Rust 1.98;
  an actual 1.89 toolchain build has not been run.
- OpenSSL 3.x development headers/libraries and a C compiler.
- On macOS, explicitly select Homebrew OpenSSL 3 if the unversioned formula points
  to another major version. On other systems, use the appropriate `OPENSSL_DIR` or pkg-config.

```bash
export OPENSSL_DIR="$(brew --prefix openssl@3)"
cargo test --locked --manifest-path experiments/openconnect/Cargo.toml -- --nocapture
cargo clippy --locked --manifest-path experiments/openconnect/Cargo.toml --all-targets -- -D warnings
cargo build --locked --release --tests --manifest-path experiments/openconnect/Cargo.toml
cargo fmt --manifest-path experiments/openconnect/Cargo.toml -- --check
```

The recorded host's `rust-objcopy` could not load `libLLVM.dylib` when stripping
release test binaries. Compilation still completed; optimized execution was also
verified with the command below. This is a host toolchain workaround, not a product
profile change.

```bash
CARGO_PROFILE_RELEASE_STRIP=none cargo test --locked --release \
  --manifest-path experiments/openconnect/Cargo.toml
```

`raw_ip.rs` connects two independently configured smoltcp interfaces using bounded
in-memory raw IPv4 packet queues, with no OS TCP/UDP socket substituting for the stack.
It checks active TCP establishment, recovery from a deliberately lost SYN, 16 KiB
transfer across a 1280-byte MTU, half-close followed by echo, and UDP datagram boundaries
and endpoints. Virtual time drives this experiment.

`dtls.rs` uses nonblocking loopback UDP sockets with a datagram-preserving Read/Write
wrapper and explicit MTU. The bounded driver services OpenSSL handshakes and timers;
its short sleeps are only for OpenSSL's wall-clock retransmission timers. This is not
a production Tokio DTLS adapter or a complete datagram BIO implementation.

The local suite tests DTLS 1.2 PSK and externally constructed session resumption,
bidirectional application datagrams, lost ClientHello recovery, incorrect keys, and
UDP blackholes. Synthetic fixture keys are public test data; no real node is contacted.

## Cross-implementation reference gateway

The optional Go driver builds against the user's mihomo checkout without modifying it.
The helper source only invokes the reference fixture's public API; it does not vendor
the fixture. The executable includes reference dependencies and must not be shipped
as part of the MIT meow product. Build requires Go 1.25+ and network/cache access for
that checkout's dependencies. The temporary Go build directory is removed on exit.

```bash
bash experiments/openconnect/reference-gateway/build.sh \
  /Users/deepdream/Developer/github/Demogorgon314/mihomo \
  /tmp/meow-reference-gateway
export MEOW_REFERENCE_GATEWAY=/tmp/meow-reference-gateway

cargo test --locked --manifest-path experiments/openconnect/Cargo.toml \
  --test dtls reference_psk_ -- --ignored --nocapture
cargo test --locked --manifest-path experiments/openconnect/Cargo.toml \
  --test dtls reference_injected_ -- --ignored --nocapture
```

Each test launches its own local gateway, verifies its control TLS certificate against
the fixture CA, issues a minimal CSTP CONNECT, keeps that connection alive, and performs
DTLS data exchanges. The PSK test uses `EXPORTER-openconnect-psk` from the actual control
TLS session. The injected test requires session reuse and rejects a fallback PSK handshake.
The peer echoes DATA payload bytes; this is DTLS/CSTP parameter integration, not validation
of routed IP traffic through an actual AnyConnect server. Raw IP correctness is tested
separately by `raw_ip.rs`.

Reference tests are explicitly ignored in the default suite because they require this
separately built executable. Child processes and temporary CA files are cleaned up.

## Known failing legacy compatibility probe

The following is a diagnostic reproducer, **expected to fail** against the recorded
reference revision. It is retained so future fixture/backend changes can be verified.
Do not count it as a passing legacy compatibility test or run all ignored tests expecting green.

```bash
MEOW_DTLS_TRACE=1 cargo test --locked \
  --manifest-path experiments/openconnect/Cargo.toml \
  --test dtls reference_cisco_ -- --ignored --nocapture
```

OpenSSL emits `DTLS1_BAD_VER` records (`0x0100`) with AES128-SHA. After HelloVerify,
its second ClientHello has message sequence 1. The reference fixture rejects that sequence
before completing the handshake. Trace output contains record metadata only, not keys
or payloads. Legacy requires security level 0 in a dedicated experimental context;
modern tests leave the default security level intact.

See the [results and API gaps](../../docs/specs/openconnect-phase-zero-results.md) for
the supported backend modes, evidence and remaining production work.
