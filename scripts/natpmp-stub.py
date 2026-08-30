#!/usr/bin/env python3
"""Minimal NAT-PMP (RFC 6886) + PCP MAP (RFC 6887) responder for the netns
harness. On a UDP MAP request it installs a 1:1 iptables port-forward for the
requesting host — DNAT inbound and SNAT outbound (scoped to exclude the relay,
so the existing relay/bind connection is untouched) — emulating a router's
PCP/NAT-PMP. That makes a symmetric NAT punchable: the mapped external port
reaches the punch socket bidirectionally.

Runs inside a NAT namespace (its iptables edits apply there).

    ip netns exec <natns> python3 natpmp-stub.py --public-ip 192.0.2.2 \\
        --iface public --relay-ip 192.0.2.1
"""
import argparse
import socket
import struct
import subprocess


def sh(*args):
    subprocess.run(list(args), check=False)


def add_forward(iface, public_ip, relay_ip, internal_ip, port):
    # Inbound: external:port -> internal:port.
    sh("iptables", "-t", "nat", "-I", "PREROUTING", "1", "-i", iface,
       "-p", "udp", "--dport", str(port),
       "-j", "DNAT", "--to-destination", f"{internal_ip}:{port}")
    # Outbound: internal:port -> external:port, but NOT toward the relay (that
    # flow keeps its MASQUERADE mapping). Inserted before the general rule.
    sh("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-o", iface,
       "-p", "udp", "-s", internal_ip, "--sport", str(port), "!", "-d", relay_ip,
       "-j", "SNAT", "--to-source", f"{public_ip}:{port}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--public-ip", required=True)
    ap.add_argument("--iface", required=True)
    ap.add_argument("--relay-ip", required=True)
    args = ap.parse_args()
    ext = bytes(int(x) for x in args.public_ip.split("."))

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 5351))
    while True:
        data, frm = s.recvfrom(1500)
        src_ip = frm[0]
        if len(data) >= 2 and data[0] == 0:  # NAT-PMP
            op = data[1]
            if op == 0:  # external-address request
                s.sendto(struct.pack("!BBHI", 0, 128, 0, 0) + ext, frm)
            elif op == 1 and len(data) >= 12:  # UDP mapping
                port = struct.unpack("!H", data[4:6])[0]
                add_forward(args.iface, args.public_ip, args.relay_ip, src_ip, port)
                s.sendto(struct.pack("!BBHIHHI", 0, 129, 0, 0, port, port, 3600), frm)
        elif len(data) >= 60 and data[0] == 2:  # PCP MAP
            nonce = data[24:36]
            port = struct.unpack("!H", data[40:42])[0]
            add_forward(args.iface, args.public_ip, args.relay_ip, src_ip, port)
            resp = bytearray(60)
            resp[0] = 2
            resp[1] = 0x81
            struct.pack_into("!I", resp, 4, 3600)
            resp[24:36] = nonce
            struct.pack_into("!H", resp, 42, port)
            resp[54] = 0xff
            resp[55] = 0xff
            resp[56:60] = ext
            s.sendto(bytes(resp), frm)


if __name__ == "__main__":
    main()
