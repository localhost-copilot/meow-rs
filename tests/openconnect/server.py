"""Independent local ocserv, DNS and echo endpoints; no external VPN or credentials."""
import socket
import subprocess
import threading

subprocess.run([
    "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
    "-nodes", "-keyout", "/run/key.pem", "-out", "/fixture/ca.pem", "-days", "1",
    "-subj", "/CN=vpn.test", "-addext", "subjectAltName=DNS:vpn.test",
], check=True)
subprocess.run(["ocpasswd", "-c", "/run/ocpasswd", "-g", "engineering", "fixture-user"],
               input=b"fixture-password\nfixture-password\n", check=True)
with open("/run/ocserv.conf", "w") as config:
    config.write('''auth = "plain[passwd=/run/ocpasswd]"
tcp-port = 443
udp-port = 0
run-as-user = nobody
run-as-group = nogroup
socket-file = /run/ocserv-socket
server-cert = /fixture/ca.pem
server-key = /run/key.pem
isolate-workers = false
max-clients = 8
max-same-clients = 8
rate-limit-ms = 0
keepalive = 60
dpd = 30
cookie-timeout = 300
rekey-time = 86400
rekey-method = ssl
use-utmp = false
use-occtl = false
device = vpns
ipv4-network = 192.0.2.0
ipv4-netmask = 255.255.255.0
ipv6-network = 2001:db8::/64
ipv6-subnet-prefix = 128
dns = 192.0.2.1
route = default
cisco-client-compat = true
compression = false
select-group = engineering[Engineering]
''')


def echo(stream):
    with stream:
        while data := stream.recv(32768):
            stream.sendall(data)


def tcp_echo(family, address):
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind((address, 8080))
    listener.listen()
    while True:
        stream, _ = listener.accept()
        threading.Thread(target=echo, args=(stream,), daemon=True).start()


def udp_echo(family, address):
    listener = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind((address, 5353))
    while True:
        data, peer = listener.recvfrom(65535)
        listener.sendto(data, peer)


for family, address in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
    threading.Thread(target=tcp_echo, args=(family, address), daemon=True).start()
    threading.Thread(target=udp_echo, args=(family, address), daemon=True).start()

subprocess.Popen(["dnsmasq", "--no-daemon", "--no-resolv", "--no-hosts",
                  "--address=/service.vpn.test/192.0.2.1", "--address=/ipv6.vpn.test/2001:db8::1"])
subprocess.run(["ocserv", "-f", "-d", "1", "-c", "/run/ocserv.conf"], check=True)
