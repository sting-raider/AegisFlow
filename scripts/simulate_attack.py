from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from packages.contracts import SignatureEvent
from services.sensor import PcapAdapter
from services.sensor.main import correlate_signatures, load_eve_file

SIMULATION_SIGNATURE_ID = "9000100"
SIMULATION_PACKETS = 24


def generate_header_only_syn_sweep(path: Path) -> None:
    """Write a deterministic, payload-free PCAP without transmitting any traffic."""

    from scapy.all import IP, TCP, Ether, wrpcap

    if path.exists():
        raise FileExistsError(f"refusing to overwrite simulation capture: {path}")
    packets = []
    for index in range(SIMULATION_PACKETS):
        packet = (
            Ether()
            / IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=40_000 + index, dport=20_000 + index, flags="S")
        )
        packet.time = 1_800_000_000 + index * 0.1
        packets.append(packet)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)


def verify_outputs(pcap: Path, eve: Path) -> dict[str, Any]:
    flows = list(PcapAdapter(pcap).flows())
    batch = load_eve_file(eve)
    if batch.errors:
        raise RuntimeError(
            "Suricata output contained processing errors: "
            + ", ".join(error.error for error in batch.errors)
        )
    signatures = [
        event
        for event in batch.events
        if isinstance(event, SignatureEvent)
        and event.signature_id == SIMULATION_SIGNATURE_ID
    ]
    if not signatures:
        raise RuntimeError("Suricata did not emit the safe SYN-sweep signature")
    correlated = correlate_signatures(flows, batch)
    if not any(event.signature_id == SIMULATION_SIGNATURE_ID for event in correlated.values()):
        raise RuntimeError("AegisFlow could not correlate the Suricata signature to a flow")
    return {
        "simulation": "header-only TCP SYN sweep",
        "network_access": "disabled",
        "payload_bytes": 0,
        "pcap_flows": len(flows),
        "suricata_signature_events": len(signatures),
        "aegisflow_correlated_flows": sum(
            event.signature_id == SIMULATION_SIGNATURE_ID for event in correlated.values()
        ),
        "signature_id": SIMULATION_SIGNATURE_ID,
    }


def run_simulation(root: Path) -> tuple[Path, dict[str, Any]]:
    run_name = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + f"-{uuid4().hex[:8]}"
    output = root / ".runtime" / "attack-simulation" / run_name
    pcap = output / "syn-sweep.pcap"
    generate_header_only_syn_sweep(pcap)

    environment = os.environ.copy()
    environment.update(
        {
            "SURICATA_PCAP": str(pcap.resolve()),
            "SURICATA_RULES": str(
                (root / "configs/suricata/rules/aegisflow-simulation.rules").resolve()
            ),
            "SURICATA_LOG_DIR": str(output.resolve()),
        }
    )
    command = [
        "docker",
        "compose",
        "-f",
        str(root / "compose.suricata.yml"),
        "--profile",
        "suricata",
        "run",
        "--rm",
        "suricata-replay",
    ]
    try:
        subprocess.run(command, cwd=root, env=environment, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("Docker CLI is not installed or is not on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            "isolated Suricata simulation failed; check that Docker Desktop is ready"
        ) from exc

    summary = verify_outputs(pcap, output / "eve.json")
    report = output / "report.json"
    report.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return report, summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a payload-free SYN-sweep PCAP through network-isolated Suricata"
    )
    parser.add_argument(
        "--generate-only",
        type=Path,
        help="write only the header-only PCAP, without starting Docker",
    )
    args = parser.parse_args()
    if args.generate_only is not None:
        generate_header_only_syn_sweep(args.generate_only.resolve())
        print(args.generate_only.resolve())
        return

    root = Path(__file__).resolve().parents[1]
    try:
        report, summary = run_simulation(root)
    except RuntimeError as exc:
        parser.exit(1, f"attack simulation failed: {exc}\n")
    print(json.dumps(summary, indent=2))
    print(f"Report: {report}")


if __name__ == "__main__":
    main()
