from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from scapy.all import Raw, rdpcap

from scripts.simulate_attack import (
    SIMULATION_PACKETS,
    SIMULATION_SIGNATURE_ID,
    build_pipeline_simulation,
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


def test_pipeline_simulation_is_provenanced_unique_and_signature_bearing(
    tmp_path: Path,
) -> None:
    started_at = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
    envelopes, summary = build_pipeline_simulation(
        tmp_path / "pipeline-run",
        simulation_id=UUID("11111111-1111-4111-8111-111111111111"),
        started_at=started_at,
    )

    assert len(envelopes) == SIMULATION_PACKETS
    assert summary == {
        "simulation_id": "11111111-1111-4111-8111-111111111111",
        "status": "queued",
        "simulation": "header-only TCP SYN sweep",
        "simulated": True,
        "network_transmitted": False,
        "payload_bytes": 0,
        "flows_queued": SIMULATION_PACKETS,
        "signature_id": SIMULATION_SIGNATURE_ID,
        "target_flow_event_id": summary["target_flow_event_id"],
    }
    assert len({envelope["flow"]["event_id"] for envelope in envelopes}) == SIMULATION_PACKETS
    assert all(envelope["flow"]["capture_mode"] == "pcap" for envelope in envelopes)
    timestamps = [
        datetime.fromisoformat(envelope["flow"]["timestamp_start"])
        for envelope in envelopes
    ]
    assert min(timestamps) == started_at
    assert all(envelope["flow"]["protocol_metadata"]["simulated"] for envelope in envelopes)
    assert all(
        envelope["flow"]["protocol_metadata"]["network_transmitted"] is False
        for envelope in envelopes
    )
    signed = [envelope for envelope in envelopes if "signature" in envelope]
    assert len(signed) == 1
    assert signed[0]["flow"]["event_id"] == summary["target_flow_event_id"]
    assert signed[0]["signature"]["signature_id"] == SIMULATION_SIGNATURE_ID
    assert signed[0]["signature"]["source"] == "fixture"
    assert signed[0]["signature"]["metadata"]["offline_suricata_rule_verified"] is True
