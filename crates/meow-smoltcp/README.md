# meow-smoltcp

Vendored [smoltcp 0.14.0](https://crates.io/crates/smoltcp/0.14.0), licensed
under 0BSD. Upstream commit: `cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3`.
Registry archive SHA-256:
`b6f8b28ad56c6e35524a37dd492af5d1a47e31e1a4d175cd12f89c075f01980f`.

The library remains named `smoltcp`; the package is published with the meow
workspace version so registry consumers receive the same implementation as
repository builds. OpenConnect is the consumer through `meow-netstack`.

The source tree, its unit tests, build script and license are preserved.
Upstream examples, standalone simulation tests and utilities are omitted;
their manifest targets are removed. See [UPSTREAM.md](UPSTREAM.md) for the
original documentation. When updating, compare against the pinned registry
archive and preserve the local changes described here.

At import, protocol behavior is unchanged from upstream. The manifest
uses workspace package metadata, removes unused example/test dependencies,
and the library root adds an introductory rustdoc paragraph. Three equivalent
style changes satisfy current Clippy: TCP keepalive initialization, DHCP DNS
address chunk iteration, and IEEE 802.15.4 optional PAN ID matching.
