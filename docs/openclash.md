# OpenClash integration

Linux `redir-port` and `tproxy-port` use firewall rules managed by OpenClash.
The core does not install or remove nftables rules in this mode.

```yaml
allow-lan: true
bind-address: 0.0.0.0
redir-port: 7892
tproxy-port: 7895
```

`redir-port` accepts TCP NAT REDIRECT traffic. `tproxy-port` accepts TCP and UDP
with `IP_TRANSPARENT`; the UDP path reads the original destination from ancillary
data and returns replies from the address contacted by the client. Both support
IPv4 and IPv6 on Linux. Named listeners also accept `type: redir` and `type: tproxy`.
The process needs the socket capabilities required by Linux transparent proxying;
OpenClash normally starts the core as root.

For a standalone installation, configure the firewall and policy routes yourself;
see the [Linux kernel TPROXY documentation](https://docs.kernel.org/networking/tproxy.html).
Setting listener ports alone does not redirect traffic.

## Legacy local TCP NAT

On Linux, the previous automatically managed local TCP redirect is now explicit:

```yaml
tproxy-port: 7893
tproxy-auto-route: true
routing-mark: 9527
```

This mode retains the `inet meow_tproxy` output-chain rules and is TCP-only.
It requires `routing-mark` on Linux to keep DIRECT connections from looping.
Do not enable it under OpenClash. macOS retains its existing automatic pf behavior.

Existing OpenClash `GeoIP.dat`, `GeoSite.dat`, and `ASN.mmdb` files are reused when
the corresponding default meow filenames are absent. No extra database copies or
case-only symlinks are needed.

## Dashboard paths

`external-ui` is the directory served at `/ui/`. `external-ui-name` only selects
the download subdirectory; it does not change that shared root. For example,
`external-ui: /usr/share/openclash/ui` with `external-ui-name: zashboard` serves
the dashboard at `/ui/zashboard/`, preserving OpenClash's generated links and
access to sibling dashboards such as `/ui/metacubexd/`.

## Validation

Run the isolated fixture with a Linux binary matching the Docker architecture:

```sh
bash tests/test_transparent_linux.sh /absolute/path/to/linux/meow
```

The privileged container creates separate client and server network namespaces.
It checks IPv4/IPv6 REDIRECT and TCP/UDP TPROXY, byte-exact UDP payloads from 0 to
65,000 bytes, repeated and multiple replies, fake-IP resolution and return
addresses, DSCP and connection statistics, local-loop rejection, remote targets
using the listener's port, controller reachability, and external firewall
preservation at startup and shutdown. All addresses and data are synthetic.

The existing `tests/test_tproxy_qemu.sh` fixture continues to exercise the explicit
legacy NAT mode. A YAML `-t` check and a SOCKS smoke test alone do not validate an
OpenClash deployment: verify the generated transparent ports and actual firewall
traffic after starting the service.
