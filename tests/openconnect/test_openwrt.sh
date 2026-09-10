#!/usr/bin/env bash
# Opt-in: real OpenWrt kernel/userland + static musl client + Docker ocserv.
# Requires MEOW_BINARY (aarch64 musl), Docker, QEMU, expect, curl and Python 3.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
: "${MEOW_BINARY:?set MEOW_BINARY to the static aarch64 musl meow executable}"
for tool in docker qemu-system-aarch64 expect curl python3; do command -v "$tool" >/dev/null; done
work=$(mktemp -d /tmp/meow-openwrt-dtls.XXXXXX)
server="meow-openwrt-dtls-$$"
http_pid=""
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then docker logs "$server" 2>&1 || true; fi
    [ -z "$http_pid" ] || kill "$http_pid" 2>/dev/null || true
    docker rm -f "$server" >/dev/null 2>&1 || true
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT
udp_port=$(python3 -c 'import socket; s=socket.socket(type=socket.SOCK_DGRAM); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
docker run --rm -d --name "$server" --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 -p 127.0.0.1::443 \
    -p "127.0.0.1:$udp_port:$udp_port/udp" -e "OCSERV_UDP_PORT=$udp_port" -e OCSERV_DPD=1 \
    -v "$work:/fixture" meow-openconnect-ocserv:test >/dev/null
for _ in $(seq 1 100); do
    if docker logs "$server" 2>&1 | grep -q 'listening (TCP)'; then break; fi
    sleep 0.1
done
test -s "$work/ca.pem"
tcp_port=$(docker port "$server" 443/tcp | sed 's/.*://')
if [ -n "${MEOW_IPK:-}" ]; then
    cp "$MEOW_IPK" "$work/meow.ipk"
else
    bash "$root/openwrt/build-ipk.sh" meow --binary "$MEOW_BINARY" \
        --version 0.0.0-dtls --arch aarch64_generic --outdir "$work"
    mv "$work/meow_0.0.0-dtls_aarch64_generic.ipk" "$work/meow.ipk"
fi
cp "$root/tests/openconnect/openwrt-guest.sh" "$work/guest-test.sh"
echo "$udp_port" >"$work/udp-port"
for mode in off auto require; do
    cat >"$work/$mode.yaml" <<EOF
mixed-port: 1080
allow-lan: false
ipv6: true
dns:
  enable: false
proxies:
  - name: vpn
    type: openconnect
    server: 10.0.2.2
    port: $tcp_port
    server-name: vpn.test
    ca: /tmp/ca.pem
    username: fixture-user
    password: fixture-password
    authgroup: engineering
    ipv6-disabled: false
    remote-dns-resolve: true
    dtls-mode: $mode
rules:
  - MATCH,vpn
EOF
done
version=24.10.7
image="openwrt-$version-armsr-armv8-generic-initramfs-kernel.bin"
cache="$root/target/openwrt-images"
mkdir -p "$cache"
base="https://downloads.openwrt.org/releases/$version/targets/armsr/armv8"
curl -fsSL "$base/sha256sums" -o "$work/sha256sums"
if [ ! -s "$cache/$image" ]; then
    curl -fL --retry 3 "$base/$image" -o "$cache/$image"
fi
python3 - "$cache/$image" "$work/sha256sums" <<'PY'
import hashlib, pathlib, sys
image = pathlib.Path(sys.argv[1])
expected = next(line.split()[0] for line in pathlib.Path(sys.argv[2]).read_text().splitlines()
                if line.split()[-1].lstrip('*') == image.name)
assert hashlib.sha256(image.read_bytes()).hexdigest() == expected, 'OpenWrt image checksum mismatch'
PY
python3 -u -m http.server --bind 127.0.0.1 --directory "$work" 0 >"$work/http.log" 2>&1 &
http_pid=$!
http_port=""
for _ in $(seq 1 50); do
    http_port=$(sed -n 's/.*port \([0-9]*\).*/\1/p' "$work/http.log" | head -n 1)
    [ -z "$http_port" ] || break
    sleep 0.1
done
test -n "$http_port"
OPENWRT_IMAGE="$cache/$image" HOST_HTTP_PORT="$http_port" \
    expect "$root/tests/openwrt-qemu/driver.exp" 2>&1 | tee "$work/qemu.log"
! grep -q '^TEST_FAIL:' "$work/qemu.log"
grep -q '^TEST_PASS:openconnect-all-modes' "$work/qemu.log"
