# TLS, HTTP and QUIC sniffing

Status: implemented, September 2026. This replaces the original TLS/HTTP
prototype specification. Reference: the local mihomo checkout's
`component/sniffer/dispatcher.go` and `quic_sniffer.go`.

```yaml
sniffer:
  enable: true
  parse-pure-ip: true
  force-dns-mapping: true
  override-destination: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]
  skip-domain: ['+.private.example']
  force-domain: ['+.force.example']
```

`enable` defaults to false. An enabled sniffer requires at least one recognized
protocol with ports. Port entries accept integers and inclusive ranges.
Protocol-specific `override-destination` overrides the global setting, whose
default is true. HTTP/TLS port overlap tries both parsers and uses the successful
protocol's setting. QUIC-only configurations are valid.

Listeners recover DNS mappings before sniffing. `parse-pure-ip` enables sniffing
when there is no hostname; `force-dns-mapping` enables it for ordinary reverse
DNS mappings. Both default to true. Known hostnames and fake-IP mappings retain
their original identity unless `force-domain` matches. `skip-domain` discards
matching extracted hostnames.

Successful sniffing sets `metadata.sniff_host` for domain rules. Destination
replacement also updates `metadata.host` and clears `dst_ip`, allowing the
selected outbound to resolve the extracted name. Without replacement, domain
rules still use the sniffed name but the original destination is retained.

## TCP

HTTP, SOCKS5 CONNECT, mixed and TProxy listeners use `SnifferRuntime` in
`meow-listener`. Pure HTTP Host and TLS ClientHello parsers live in
`meow-common::sniffer`. TCP uses an 8-KiB peek with a default 100-ms timeout;
`sniffer.timeout` accepts 1–60000 milliseconds. Failed or incomplete inspection
leaves the destination unchanged and does not consume the stream.

The deprecated `tproxy-sni` option synthesizes the historical TLS-only
configuration when no `sniffer` block exists. Outbound `client-fingerprint`
belongs in each proxy configuration.

## QUIC and UDP

SOCKS5 UDP ASSOCIATE (including mixed listeners) and TUN UDP flows inspect the
opening datagrams before DNS resolution and rule matching. Each flow queues
datagrams independently, so an incomplete ClientHello does not stall unrelated
destinations in the same SOCKS association. Subsequent short-header packets
reuse the route selected for that flow.

`meow-tunnel::sniffer::quic` supports QUIC v1, v2 and drafts 29–32. Rustls supplies
AES header protection and Initial packet decryption. The parser handles
coalesced long-header packets, packet-number reconstruction and out-of-order
CRYPTO fragments, including identical retransmissions. Conflicting fragments,
authentication failures and malformed lengths abandon inspection.

Only Initial protection is removed; application traffic is not decrypted.
ClientHello data is capped at 64 KiB. Opening datagrams are retained for at most
3 seconds, 64 packets or approximately 128 KiB (the final received datagram can
cross the byte threshold). Ordinary UDP bypasses inspection immediately.
Failure or timeout forwards the retained datagrams using the original metadata.
All datagrams are replayed unchanged and in arrival order after selecting the
outbound. SOCKS replies preserve an original IP destination even when sniffing
caused a different outbound address to be resolved.

Embedders using `meow-tunnel` directly can call
`Tunnel::set_sniffer` and `TunnelInner::sniff_udp_initial` on their per-flow packet
receiver before routing. The low-level `udp::handle_udp` datagram API does not
own an inbound packet receiver.

## Verification

See [the test plan](sniffer-test-plan.md). Published packet fixtures come from
[RFC 9001 Appendix A.2](https://www.rfc-editor.org/rfc/rfc9001.html#name-client-initial)
and [RFC 9369 Appendix A.2](https://www.rfc-editor.org/rfc/rfc9369.html#name-client-initial).
