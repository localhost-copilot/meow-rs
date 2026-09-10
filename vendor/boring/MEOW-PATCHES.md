# Local changes to boring 4.22.0

Source: the `boring` 4.22.0 crates.io release, including its Apache-2.0 license,
examples and public test fixtures. `boring-sys` remains the pinned registry
release: this patch does not replace or fork the BoringSSL C library.

`src/ssl/bio.rs` backports upstream commit
[ed768854a495fb919478f8d90480d3354db7c774](https://github.com/cloudflare/boring/commit/ed768854a495fb919478f8d90480d3354db7c774):
clear the BIO retry flags before flushing and set retry-write when `flush`
returns WouldBlock or NotConnected. Without this, TLS over an asynchronous
buffered transport can fail its handshake with WouldBlock, marking working
AnyTLS/Hysteria2 nodes offline during HTTPS health checks.

Regression coverage lives in
`crates/meow-transport/tests/boring_tls_test.rs`:
`handshake_waits_for_an_asynchronous_flush` checks handshake and application
data through an independently implemented TLS server and a transport whose
buffered flush deterministically returns Pending.

Remove the patch when a compatible registry release includes this fix. Do not
run workspace formatting over the vendored upstream sources.
