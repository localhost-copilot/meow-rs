# ADR 0012: Route DNS exchanges through live outbounds

- **Status:** Implemented
- **Updated:** 2026-09-10

## Configuration

Nameserver fragments name an outbound or group. Encrypted servers retain their
own TLS identity; an optional `&sni=NAME` overrides it.

| Nameserver | Transport |
|---|---|
| `1.1.1.1#DNS-EXIT` | UDP through DNS-EXIT |
| `tcp://1.1.1.1#DNS-EXIT` | TCP through DNS-EXIT |
| `tls://1.1.1.1#DNS-EXIT` | TLS over a TCP connection through DNS-EXIT |
| `https://dns.example/dns-query#DNS-EXIT` | HTTPS through DNS-EXIT |
| `tls://1.1.1.1#DNS-EXIT&sni=dns.example` | TLS with an explicit certificate name |

`dns.respect-rules: true` sends untagged main, fallback, and nameserver-policy
upstreams through the current routing rules and mode. Explicit tags take
precedence. It requires a nonempty `proxy-server-nameserver`, matching mihomo.
Bootstrap, proxy-server, and dedicated direct nameservers do not inherit this
flag. A direct resolver following nameserver-policy shares that policy's routes.

## Runtime behavior

Configuration validates named outbounds before serving queries. Once the final
resolver-aware proxy registry exists, DNS clients release their startup adapters
and use weak references to that registry. A tunnel binds a lookup against its
current routing snapshot. Selector changes, provider changes, and whole-registry
reloads therefore affect subsequent uncached DNS exchanges.

An unavailable configured outbound fails the query. It never silently falls back
to direct networking or a stale group. Lookups retain no routing locks across
asynchronous network operations, and weak ownership prevents resolver/proxy cycles.
Embedders constructing dedicated resolvers should call
`Tunnel::bind_dns_resolver` to attach them to runtime routing.

UDP uses the selected adapter's packet connection. Replies must match the
upstream address and DNS transaction/question. A valid truncated reply retries
over TCP through the same outbound. Query timeout or cancellation closes the
packet connection. An adapter without UDP support returns an error.

DoT and DoH wrap the outbound stream with `TlsLayer`; the nameserver certificate
and HTTP Host name are independent of the proxy server's TLS settings. TLS or
outbound failures propagate without changing the route.

## Bootstrap and recursion

Nameserver hostnames are resolved during construction using bootstrap clients.
Proxy server hostnames use the dedicated proxy-server resolver when configured.
The existing host-resolver hook detects recursive adapter resolution: nested
lookups consult hosts and cache, then its established system-resolver fallback.
Operators should avoid proxy-server nameservers whose tagged proxy itself needs
that same resolver to become reachable.

Fake-IP synthesis precedes upstream exchanges. Only names excluded from fake-IP
or explicit real-address lookups reach these transports.

## Verification

Tunnel tests use local DNS servers to verify live selector changes, registry
replacement/removal, wildcard policy routing, UDP transaction validation,
`respect-rules`, explicit-tag precedence, dedicated resolver isolation, and
release of resolver ownership. Encrypted DNS tests separately cover proxy
transport and independent TLS authentication.
