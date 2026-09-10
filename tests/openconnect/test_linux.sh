#!/usr/bin/env bash
# Run after building Dockerfile and Dockerfile.client. No host VPN/TUN changes.
set -euo pipefail
fixture=$(mktemp -d /tmp/meow-ocserv-linux.XXXXXX)
network="meow-ocserv-linux-$$"
server="${network}-server"
client="${network}-client"
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        docker logs "$server" 2>&1 || true
        docker logs "$client" 2>&1 || true
    fi
    docker rm -f "$client" "$server" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    rm -rf "$fixture"
    exit "$status"
}
trap cleanup EXIT
docker network create "$network" >/dev/null
docker run --rm -d --name "$server" --network "$network" --network-alias ocserv \
    --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    -e OCSERV_UDP_PORT=443 -v "$fixture:/fixture" meow-openconnect-ocserv:test >/dev/null
ready=false
for _ in $(seq 1 100); do
    if docker logs "$server" 2>&1 | grep -q 'listening (TCP)'; then ready=true; break; fi
    sleep 0.1
done
test "$ready" = true
cat >"$fixture/client.yaml" <<'YAML'
mixed-port: 1080
allow-lan: false
ipv6: true
dns:
  enable: false
proxies:
  - name: vpn
    type: openconnect
    server: ocserv
    port: 443
    server-name: vpn.test
    ca: /fixture/ca.pem
    username: fixture-user
    password: fixture-password
    authgroup: engineering
    ipv6-disabled: false
    remote-dns-resolve: true
    dtls-mode: require
rules:
  - MATCH,vpn
YAML
docker run --rm -d --name "$client" --network "$network" -v "$fixture:/fixture" \
    -e RUST_LOG=meow_openconnect=debug,meow_proxy=debug meow-openconnect-client:test >/dev/null
for host in service.vpn.test ipv6.vpn.test; do
    reply=$(docker exec "$client" curl -fsS --max-time 10 --retry 5 --retry-connrefused \
        --retry-delay 1 --proxy socks5h://127.0.0.1:1080 "http://$host:8081/")
    test "$reply" = ocserv-http
    echo "Linux DTLS SOCKS5 + VPN DNS + HTTP: $host passed"
done
docker logs "$client" 2>&1 | grep 'OpenConnect switched to DTLS'
docker exec "$client" openssl version
