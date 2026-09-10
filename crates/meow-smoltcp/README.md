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
and the library root adds an introductory rustdoc paragraph. Equivalent style
changes satisfy current Clippy: TCP keepalive initialization, DHCP DNS address
chunk iteration, IEEE 802.15.4 optional PAN ID matching, and the test hardware
address selection under different feature combinations.

Default features match the IPv4/IPv6 TCP/UDP IP-only stack used by
`meow-netstack`. This prevents a workspace-wide build from enabling additional
protocols in the application through Cargo feature unification. Other upstream
features remain available explicitly; the measured-RTO policy remains opt-in.

## TCP recovery changes

- A negotiated SACK range containing more than two sender MSS beyond the
  oldest unacknowledged byte triggers fast retransmission of that hole, even
  when the ACK carries application data. This sufficient loss criterion comes
  from [RFC 6675 section 4](https://www.rfc-editor.org/rfc/rfc6675.html#section-4).
  This is limited oldest-hole detection, not a complete SACK scoreboard, RACK
  or Tail Loss Probe implementation. Cumulative ACKs alone release payload.
- Ranges must lie within transmitted data, including across sequence wrap.
  Repeated reports of the same hole do not repeatedly request retransmission.
  Cumulative progress permits recovery of the next hole.
- `tcp-min-rto-200ms`, enabled by `meow-netstack`, lowers only the measured RTO
  floor to 200 ms. The initial 1 second RTO, RTT/variance estimate, Karn's rule,
  exponential backoff and 60 second ceiling remain. Without this feature the
  upstream 1 second floor is retained. This deliberately differs from the
  recommended floor in [RFC 6298](https://www.rfc-editor.org/rfc/rfc6298.html).
  The reference gVisor sender also uses a 200 ms minimum; local measurements
  and limits are recorded in the repository's OpenConnect benchmark report.

Regression tests exercise data-bearing SACK, successive holes, repeated SACK,
invalid/untransmitted ranges, sequence wrap, and timed tail loss with backoff.
