from __future__ import annotations

import argparse
import json
import socket
import threading
import time
from pathlib import Path

from packages.contracts import CaptureMode
from services.sensor import NfstreamAdapter


def _send_loopback_probe(interface: str) -> threading.Thread:
    if interface not in {"lo", "lo0"}:
        raise ValueError("the built-in live probe is restricted to a loopback interface")

    def exchange() -> None:
        time.sleep(0.8)
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            server.bind(("127.0.0.1", 0))
            target = server.getsockname()
            server.settimeout(1.0)
            for _ in range(20):
                client.sendto(b"aegisflow-local-nfstream-evaluation", target)
                server.recvfrom(256)
                time.sleep(0.25)
        finally:
            client.close()
            server.close()

    thread = threading.Thread(target=exchange, name="nfstream-loopback-probe", daemon=True)
    thread.start()
    return thread


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate NFStream without external traffic")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", type=Path)
    source.add_argument("--interface")
    parser.add_argument(
        "--loopback-probe",
        action="store_true",
        help="emit one local UDP exchange; valid only for lo/lo0",
    )
    args = parser.parse_args()
    if args.pcap is not None:
        if args.loopback_probe:
            parser.error("--loopback-probe is only valid with --interface")
        adapter = NfstreamAdapter(args.pcap, max_flows=100)
        flows = list(adapter.flows())
    else:
        if not args.loopback_probe:
            parser.error("live evaluation requires --loopback-probe to remain isolated")
        probe = _send_loopback_probe(args.interface)
        adapter = NfstreamAdapter(
            args.interface,
            capture_mode=CaptureMode.LIVE,
            idle_timeout=1,
            active_timeout=2,
            max_flows=1,
        )
        flows = [next(iter(adapter.flows()))]
        probe.join(timeout=3)
    if not flows:
        raise RuntimeError("NFStream produced no completed flows")
    print(
        json.dumps(
            {
                "flows": len(flows),
                "adapter": flows[0].source_adapter,
                "capture_mode": flows[0].capture_mode.value,
                "first_flow": flows[0].model_dump(mode="json"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
