from __future__ import annotations

import json
from pathlib import Path

from scapy.all import Raw, rdpcap

from scripts.simulate_attack import (
    SIMULATION_PACKETS,
    SIMULATION_SIGNATURE_ID,
    generate_header_only_syn_sweep,
    verify_outputs,
)
from services.sensor import PcapAdapter


def test_simulation_pcap_is_header_only_and_uses_documentation_addresses(
    tmp_path: Path,
) -> None:
    pcap = tmp_path / "run" / "syn-sweep.pcap"
    generate_header_only_syn_sweep(pcap)

    packets = rdpcap(str(pcap))
    assert len(packets) == SIMULATION_PACKETS
    assert all(not packet.haslayer(Raw) for packet in packets)
    assert {packet["IP"].src for packet in packets} == {"192.0.2.10"}
    assert {packet["IP"].dst for packet in packets} == {"198.51.100.20"}


def test_simulation_verifier_requires_and_correlates_suricata_signature(
    tmp_path: Path,
) -> None:
    pcap = tmp_path / "run" / "syn-sweep.pcap"
    generate_header_only_syn_sweep(pcap)
    flow = list(PcapAdapter(pcap).flows())[11]
    eve = tmp_path / "eve.json"
    eve.write_text(
        json.dumps(
            {
                "timestamp": flow.timestamp_start.isoformat(),
                "event_type": "alert",
                "community_id": flow.community_flow_id,
                "src_ip": str(flow.src_ip),
                "src_port": flow.src_port,
                "dest_ip": str(flow.dst_ip),
                "dest_port": flow.dst_port,
                "proto": flow.protocol,
                "alert": {
                    "signature_id": int(SIMULATION_SIGNATURE_ID),
                    "signature": "AEGISFLOW SAFE SIMULATION TCP SYN sweep",
                    "category": "Potentially Bad Traffic",
                    "severity": 2,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    summary = verify_outputs(pcap, eve)
    assert summary["payload_bytes"] == 0
    assert summary["suricata_signature_events"] == 1
    assert summary["aegisflow_correlated_flows"] == 1
