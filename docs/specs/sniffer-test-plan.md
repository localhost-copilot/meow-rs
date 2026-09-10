# Sniffer verification

Updated September 2026. Companion to [sniffer.md](sniffer.md).

Run the behavior tests with:

```sh
cargo test -p meow-common --lib sniffer
cargo test -p meow-config --test sniffer_config_test
cargo test -p meow-tunnel --lib sniffer
cargo test -p meow-listener --lib --features listener-tun
```

Coverage includes:

- HTTP Host and TLS SNI extraction, truncation and malformed input.
- Disabled sniffing, port dispatch, HTTP/TLS port overlap, protocol-specific
  destination replacement, skip/force domains and DNS mapping gates.
- Configured port ranges and QUIC-only configurations.
- Independently published QUIC v1/v2 Initial packets, all truncated prefixes
  and authentication corruption.
- Draft 29, v1 and v2 fragmented ClientHello reassembly, coalesced packets,
  out-of-order delivery, packet-number wrap and retransmission.
- Conflicting fragments and the 64-KiB CRYPTO bound.
- Incomplete handshake deadlines under paused Tokio time, immediate ordinary
  UDP passthrough and byte-identical replay of opening datagrams.
- A real SOCKS5 association sending a published QUIC Initial to an IP that
  would otherwise hit REJECT. The SNI domain rule selects DIRECT, resolves the
  host to a local UDP receiver, forwards later short-header packets and returns
  replies with the client's original destination address.
- Non-hijacked port-53 routing through SOCKS and TUN, association source
  validation and control-connection teardown.

Live-node smoke tests remain opt-in and use temporary configurations with
isolated listeners. Network reachability tests complement these deterministic
tests; they do not replace malformed-input or routing-boundary coverage.
