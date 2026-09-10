#!/usr/bin/env python3
"""Privileged, isolated Linux network-namespace checks; run via the Docker wrapper."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args}: {result.stderr}")
    return result.stdout


def api(path):
    with urllib.request.urlopen("http://127.0.0.1:19090/" + path, timeout=3) as response:
        return json.load(response)


def echo_server():
    import selectors
    sel = selectors.DefaultSelector()
    for family, host in [(socket.AF_INET, "10.204.0.2"), (socket.AF_INET6, "fd00:204::2")]:
        for port in [18100, 18101, 18102]:
            for kind in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
                sock = socket.socket(family, kind)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((host, port))
                if kind == socket.SOCK_STREAM:
                    sock.listen()
                sock.setblocking(False)
                sel.register(sock, selectors.EVENT_READ, kind)
    Path("/tmp/echo-ready").touch()
    while True:
        for key, _ in sel.select():
            sock, kind = key.fileobj, key.data
            if kind == socket.SOCK_STREAM:
                conn, _ = sock.accept()
                sel.register(conn, selectors.EVENT_READ, None)
            elif kind == socket.SOCK_DGRAM:
                data, peer = sock.recvfrom(65535)
                sock.sendto(data, peer)
            else:
                data = sock.recv(65535)
                if data:
                    sock.sendall(data)
                else:
                    sel.unregister(sock)
                    sock.close()


def tcp_client():
    for host in ["10.204.0.2", "fd00:204::2"]:
        for port in [18100, 18101]:
            with socket.create_connection((host, port), timeout=5) as conn:
                for size in [1, 4096, 65536]:
                    data = bytes(i % 251 for i in range(size))
                    conn.sendall(data)
                    received = bytearray()
                    while len(received) < size:
                        chunk = conn.recv(size - len(received))
                        assert chunk, "unexpected EOF"
                        received.extend(chunk)
                    assert received == data
            print(f"PASS TCP {host}:{port} exact echo")


def main():
    assert Path("/.dockerenv").exists(), "must run in the disposable Docker fixture"
    parser = argparse.ArgumentParser()
    parser.add_argument("--tcp-only", action="store_true")
    parser.parse_args()
    processes = []
    try:
        for name, subnet in [("client", 203), ("server", 204)]:
            run("ip", "netns", "add", name)
            run("ip", "link", "add", name, "type", "veth", "peer", "name", name + "-peer")
            run("ip", "link", "set", name + "-peer", "netns", name)
            for cmd in [
                ["addr", "add", f"10.{subnet}.0.1/24", "dev", name],
                ["-6", "addr", "add", f"fd00:{subnet}::1/64", "dev", name, "nodad"],
                ["link", "set", name, "up"],
            ]:
                run("ip", *cmd)
            prefix = ["ip", "-n", name]
            for cmd in [
                ["link", "set", "lo", "up"],
                ["addr", "add", f"10.{subnet}.0.2/24", "dev", name + "-peer"],
                ["-6", "addr", "add", f"fd00:{subnet}::2/64", "dev", name + "-peer", "nodad"],
                ["link", "set", name + "-peer", "up"],
                ["route", "add", "default", "via", f"10.{subnet}.0.1"],
                ["-6", "route", "add", "default", "via", f"fd00:{subnet}::1"],
            ]:
                run(*prefix, *cmd)
        run("sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
        run("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.client.rp_filter=0")
        for family in ["-4", "-6"]:
            run("ip", family, "rule", "add", "fwmark", "0x162", "table", "162")
            run("ip", family, "route", "add", "local", "default", "dev", "lo", "table", "162")
        run("nft", "-f", "-", input='''table inet fixture {
chain nat_in { type nat hook prerouting priority dstnat; policy accept;
  iifname "client" tcp dport 18100 redirect to :7892
}
chain tproxy_in { type filter hook prerouting priority mangle; policy accept;
  iifname "client" meta l4proto tcp tcp dport 18101 tproxy to :7895 meta mark set 0x162 accept
  iifname "client" meta l4proto udp udp dport { 18101, 18102 } tproxy to :7895 meta mark set 0x162 accept
}
}''')
        expected_firewall = run("nft", "list", "ruleset")
        config = Path("/tmp/transparent.yaml")
        config.write_text('''allow-lan: true
bind-address: "::"
ipv6: true
redir-port: 7892
tproxy-port: 7895
tproxy-auto-route: false
external-controller: 0.0.0.0:19090
dns: {enable: false}
sniffer: {enable: false}
rules: ["MATCH,DIRECT"]
''')
        server = subprocess.Popen(["ip", "netns", "exec", "server", sys.executable, __file__, "server"])
        processes.append(server)
        log = open("/tmp/meow-transparent.log", "w")
        core = subprocess.Popen(["/usr/local/bin/meow", "-d", "/tmp", "-f", str(config)], stdout=log, stderr=subprocess.STDOUT)
        processes.append(core)
        deadline = time.monotonic() + 30
        while True:
            assert core.poll() is None, Path(log.name).read_text()
            try:
                ports = api("configs")
                if Path("/tmp/echo-ready").exists():
                    break
            except (OSError, ValueError):
                pass
            assert time.monotonic() < deadline, "listener startup timeout"
            time.sleep(0.05)
        assert ports["redir-port"] == 7892 and ports["tproxy-port"] == 7895
        assert run("nft", "list", "ruleset") == expected_firewall, "core altered externally managed firewall"
        print("PASS external firewall ownership and API listener ports")
        print(run("ip", "netns", "exec", "client", sys.executable, __file__, "tcp"), end="")
        # The regression loop was local traffic to a non-loopback controller IP.
        with urllib.request.urlopen("http://10.203.0.1:19090/version", timeout=3) as response:
            assert json.load(response)["meta"]
        assert len(api("connections")["connections"]) < 8
        print("PASS controller access without recursive transparent connections")
        core.terminate()
        core.wait(timeout=10)
        assert run("nft", "list", "ruleset") == expected_firewall
        print("PASS shutdown preserves external firewall")
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    if sys.argv[1:] == ["server"]:
        echo_server()
    elif sys.argv[1:] == ["tcp"]:
        tcp_client()
    else:
        main()
