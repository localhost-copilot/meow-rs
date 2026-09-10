# OpenWrt packaging

Packaging sources for the official OpenWrt `.ipk` release artifacts
(issue [#284](https://github.com/madeye/meow-rs/issues/284)).

- `build-ipk.sh` — assembles opkg-format `.ipk` packages from a prebuilt
  static musl binary, without the OpenWrt SDK. Run with no arguments for
  usage.
- `meow/files/` — procd init script, `/etc/config/meow` UCI settings and
  the default `/etc/meow/config.yaml` shipped on-device.
- `luci-app-meow/` — LuCI app: `root/` overlays `/` on the device,
  `htdocs/` maps to `/www`. The Panel tab embeds the built-in web UI served
  by the meow REST API at `/ui` instead of reimplementing a dashboard.

Release wiring lives in `.github/workflows/release.yml` (ipk matrix), the
QEMU end-to-end test in `tests/test_openwrt_qemu.sh`, and user-facing
documentation in [docs/openwrt.md](../docs/openwrt.md).

OpenConnect DTLS is opt-in (`minimal,openconnect-dtls` or `full,openconnect-dtls`).
ARM64 musl builds embed a symbol-prefixed OpenSSL and require no device `libssl`.
See [build instructions](../docs/openconnect.md#openwrt--musl-构建) and
[OpenWrt DTLS validation](../docs/openconnect-openwrt-validation.md).
The default release feature set remains unchanged. Packages include the OpenSSL
license for builds that embed it.
