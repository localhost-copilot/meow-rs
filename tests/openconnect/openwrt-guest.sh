#!/bin/sh
# Run by the existing OpenWrt serial-console driver, never on the host.
set -eu
base="http://10.0.2.2:$1"
pid=""
echo_pid=""
cleanup() {
    nft delete table inet meow_dtls_test 2>/dev/null || true
    [ -z "$echo_pid" ] || kill "$echo_pid" 2>/dev/null || true
    [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
}
trap cleanup EXIT
wget -q -O /tmp/meow.ipk "$base/meow.ipk"
opkg install /tmp/meow.ipk
test -s /usr/share/licenses/meow/OpenSSL.LICENSE
wget -q -O /tmp/ca.pem "$base/ca.pem"
wget -q -O /tmp/udp-port "$base/udp-port"
udp_port=$(cat /tmp/udp-port)
cat /etc/openwrt_release
check_echo() {
    printf '%s\n' "$1" >&3
    IFS= read -r -t 10 reply <&4
    [ "$reply" = "$1" ]
}
for mode in off require auto; do
    wget -q -O /tmp/vpn.yaml "$base/$mode.yaml"
    /usr/bin/meow -f /tmp/vpn.yaml -t
    RUST_LOG=meow_openconnect=debug,meow_proxy=debug \
        /usr/bin/meow -f /tmp/vpn.yaml >/tmp/meow-dtls.log 2>&1 &
    pid=$!
    for host in service.vpn.test ipv6.vpn.test; do
        ready=false
        for attempt in $(seq 1 20); do
            printf 'GET http://%s:8081/ HTTP/1.1\r\nHost: %s:8081\r\nConnection: close\r\n\r\n' "$host" "$host" \
                | nc 127.0.0.1 1080 >/tmp/reply || true
            if grep -q 'ocserv-http' /tmp/reply; then ready=true; break; fi
            sleep 1
        done
        if [ "$ready" != true ]; then cat /tmp/meow-dtls.log; echo "TEST_FAIL:$mode-$host"; exit 1; fi
        echo "TEST_PASS:$mode-$host"
    done
    if [ "$mode" != off ]; then
        for attempt in $(seq 1 10); do
            grep -q 'OpenConnect switched to DTLS' /tmp/meow-dtls.log && break
            sleep 1
        done
        grep 'OpenConnect switched to DTLS' /tmp/meow-dtls.log
    else
        ! grep -q 'OpenConnect switched to DTLS' /tmp/meow-dtls.log
    fi
    if [ "$mode" != off ]; then
        # Keep one actual proxy TCP connection open across the UDP fault.
        rm -f /tmp/echo-in /tmp/echo-out
        mkfifo /tmp/echo-in /tmp/echo-out
        nc 127.0.0.1 1080 </tmp/echo-in >/tmp/echo-out &
        echo_pid=$!
        exec 3>/tmp/echo-in
        exec 4</tmp/echo-out
        printf 'CONNECT service.vpn.test:8080 HTTP/1.1\r\nHost: service.vpn.test:8080\r\n\r\n' >&3
        IFS= read -r -t 15 status <&4
        case "$status" in *' 200 '*) ;; *) echo "TEST_FAIL:$mode-connect"; exit 1;; esac
        while IFS= read -r -t 10 header <&4; do
            [ "$header" != "$(printf '\r')" ] || break
        done
        check_echo "$mode-before"
        nft add table inet meow_dtls_test
        nft 'add chain inet meow_dtls_test output { type filter hook output priority -10; policy accept; }'
        nft add rule inet meow_dtls_test output ip daddr 10.0.2.2 udp dport "$udp_port" drop
        if [ "$mode" = auto ]; then
            for attempt in $(seq 1 15); do
                grep -q 'using CSTP data channel' /tmp/meow-dtls.log && break
                sleep 1
            done
            grep 'using CSTP data channel' /tmp/meow-dtls.log
            check_echo auto-fallback-same-socket
            nft delete table inet meow_dtls_test
            for attempt in $(seq 1 45); do
                [ "$(grep -c 'OpenConnect switched to DTLS' /tmp/meow-dtls.log)" -ge 2 ] && break
                sleep 1
            done
            [ "$(grep -c 'OpenConnect switched to DTLS' /tmp/meow-dtls.log)" -ge 2 ]
            check_echo auto-recovered-same-socket
            echo 'TEST_PASS:auto-fallback-recovery-same-socket'
        else
            for attempt in $(seq 1 15); do
                kill -0 "$echo_pid" 2>/dev/null || break
                sleep 1
            done
            ! kill -0 "$echo_pid" 2>/dev/null
            ! grep -q 'using CSTP data channel' /tmp/meow-dtls.log
            nft delete table inet meow_dtls_test
            echo 'TEST_PASS:require-fails-socket-without-fallback'
        fi
        exec 3>&-
        exec 4<&-
        kill "$echo_pid" 2>/dev/null || true
        wait "$echo_pid" || true
        echo_pid=""
    fi
    kill "$pid"
    wait "$pid" || true
    pid=""
done
echo 'TEST_PASS:openconnect-all-modes'
echo ALL_TESTS_DONE
