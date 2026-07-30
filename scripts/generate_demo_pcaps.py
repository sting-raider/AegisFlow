from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap


def generate(path: Path) -> None:
    packets = [
        Ether()
        / IP(src="10.20.0.15", dst="198.51.100.10")
        / TCP(sport=50000, dport=443, flags="S"),
        Ether()
        / IP(src="198.51.100.10", dst="10.20.0.15")
        / TCP(sport=443, dport=50000, flags="SA"),
        Ether()
        / IP(src="10.20.0.15", dst="198.51.100.11")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="demo.invalid")),
    ]
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index * 0.01
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path, nargs="?", default=Path("tests/fixtures/demo.pcap"))
    args = parser.parse_args()
    generate(args.path)
    print(args.path.resolve())


if __name__ == "__main__":
    main()
