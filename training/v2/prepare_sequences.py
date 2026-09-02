"""Prepare labeled packet-sequence development records from official IoT-23 PCAPs.

Replays each official scenario capture through the same PcapAdapter the runtime uses,
joins flows to the scenario's Zeek conn.log.labeled ground truth by unordered endpoint
pair plus time overlap, and emits one JSONL record per unambiguously labeled flow.
The packet parser reads captures; only sizes, directions, timings, and flag counts
are retained in the prepared records, never packet payload contents.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packages.contracts import FlowEvent
from services.sensor.adapters import PcapAdapter

PROTOCOL_ALIASES = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp", "ICMPV6": "icmp6"}
FAMILY_PREFIXES = {
    "PartOfAHorizontalPortScan": "port_scan",
    "C&C": "c_and_c",
    "DDoS": "ddos",
    "OKIRU": "okiru",
    "Attack": "attack_generic",
}
OBSERVABILITY_PACKET_FLOOR = 2


FlowJoinKey = tuple[tuple[str, int], tuple[str, int], str]


class AmbiguousFlowLabel(ValueError):
    """A coalesced flow overlaps incompatible ground-truth labels."""


def endpoint_key(ip: str, port: int) -> tuple[str, int]:
    return (ip.lower(), int(port))


def flow_join_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str
) -> FlowJoinKey:
    left = endpoint_key(src_ip, src_port)
    right = endpoint_key(dst_ip, dst_port)
    first, second = sorted([left, right])
    return (first, second, PROTOCOL_ALIASES.get(protocol.upper(), protocol.lower()))


def parse_zeek_labels(
    path: Path,
) -> tuple[list[dict[str, Any]], dict[FlowJoinKey, list[dict[str, Any]]]]:
    rows: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        columns = line.split("\t")
        # The official IoT-23 labeled logs separate the trailing
        # "tunnel_parents label detailed-label" group with spaces, unlike the
        # tab-separated conn.log body, so recover them by whitespace tokenization.
        columns = columns[:-1] + columns[-1].split()
        if len(columns) < 18:
            continue
        try:
            ts = float(columns[0])
            duration = float(columns[7]) if columns[7] not in {"-", ""} else 0.0
            raw_label = columns[-2].strip().lower()
            detailed = columns[-1].strip()
        except ValueError:
            continue
        if raw_label not in {"benign", "malicious"}:
            continue
        binary_label = raw_label.capitalize()
        rows.append(
            {
                "ts": ts,
                "orig_h": columns[2],
                "orig_p": int(columns[3]),
                "resp_h": columns[4],
                "resp_p": int(columns[5]),
                "proto": columns[6].lower(),
                "duration_s": duration,
                "label": binary_label,
                "detailed_label": detailed,
                "family": FAMILY_PREFIXES.get(
                    detailed, "benign" if binary_label == "Benign" else "other_attack"
                ),
            }
        )
    index: dict[FlowJoinKey, list[dict[str, Any]]] = {}
    for row in rows:
        key = flow_join_key(
            row["orig_h"], row["orig_p"], row["resp_h"], row["resp_p"], row["proto"]
        )
        index.setdefault(key, []).append(row)
    return rows, index


def match_row(
    index: dict[FlowJoinKey, list[dict[str, Any]]],
    key: FlowJoinKey,
    start: float,
    end: float,
) -> dict[str, Any] | None:
    best: dict[str, Any] | None = None
    best_gap: float | None = None
    nearest: set[tuple[str, str]] = set()
    for candidate in index.get(key, ()):
        candidate_start = candidate["ts"]
        candidate_end = candidate_start + max(candidate["duration_s"], 0.0)
        gap = max(candidate_start - end, start - candidate_end, 0.0)
        if gap <= 1.0 and (best_gap is None or gap < best_gap):
            best = candidate
            best_gap = gap
            nearest = {(str(candidate["label"]), str(candidate["family"]))}
        elif gap <= 1.0 and gap == best_gap:
            nearest.add((str(candidate["label"]), str(candidate["family"])))
    if len(nearest) > 1:
        raise AmbiguousFlowLabel("ambiguous ground-truth labels for coalesced flow")
    return best


def sequence_record(flow: FlowEvent, row: dict[str, Any], scenario: str) -> dict[str, Any]:
    sizes = list(flow.first_packet_sizes)[:20]
    directions = list(flow.first_packet_directions)[:20]
    iats = [round(float(value), 6) for value in flow.first_packet_interarrival_times][:20]
    observed = min(len(sizes), len(directions), len(iats))
    binary = "malicious" if row["label"] == "Malicious" else "benign"
    total_packets = flow.packets_forward + flow.packets_reverse
    return {
        "event_id": str(flow.event_id),
        "scenario": scenario,
        "family": row["family"] if binary == "malicious" else "benign",
        "detailed_label": row["detailed_label"],
        "binary_label": binary,
        "seq_sizes": sizes[:observed],
        "seq_directions": directions[:observed],
        "seq_iats_ms": iats[:observed],
        "total_packets": total_packets,
        "duration_ms": round(flow.duration_ms, 3),
        "protocol": flow.protocol,
        "tcp_syn_count": flow.tcp_syn_count,
        "tcp_ack_count": flow.tcp_ack_count,
        "tcp_fin_count": flow.tcp_fin_count,
        "tcp_rst_count": flow.tcp_rst_count,
        "tcp_psh_count": flow.tcp_psh_count,
        "bytes_forward": flow.bytes_forward,
        "bytes_reverse": flow.bytes_reverse,
        "packets_forward": flow.packets_forward,
        "packets_reverse": flow.packets_reverse,
        "src_port": int(flow.src_port),
        "dst_port": int(flow.dst_port),
        "ip_version": flow.ip_version,
    }


def observability_tier(record: dict[str, Any]) -> str:
    packets = record["total_packets"]
    sequence_length = len(record["seq_sizes"])
    has_state = bool(record["tcp_syn_count"] or record["tcp_fin_count"] or record["tcp_rst_count"])
    if packets >= 4 and sequence_length >= 4 and record["protocol"] in {"TCP", "UDP"}:
        return "HIGH" if record["duration_ms"] >= 10 or has_state else "MEDIUM"
    if packets >= 2:
        return "MEDIUM"
    return "LOW"


def prepare_scenario(scenario: str, directory: Path, output_path: Path) -> dict[str, Any]:
    if output_path.exists():
        raise FileExistsError(f"refusing to overwrite prepared evidence: {output_path}")
    manifest = json.loads((directory / f"{scenario}.manifest.json").read_text(encoding="utf-8"))
    pcap_path = directory / str(manifest["pcap_filename"])
    labels_path = directory / f"{scenario}.conn.log.labeled"
    if not pcap_path.exists() or not labels_path.exists():
        raise FileNotFoundError(f"scenario {scenario} is missing its pcap or labels")
    _, label_index = parse_zeek_labels(labels_path)
    adapter = PcapAdapter(pcap_path, sensor_id=f"v2-{scenario}")
    matched = unmatched = unlabeled = ambiguous = 0
    label_counts: Counter[str] = Counter()
    family_counts: Counter[str] = Counter()
    observability_counts: Counter[str] = Counter()
    with output_path.open("x", encoding="utf-8", newline="\n") as output:
        for flow in adapter.flows():
            protocol = PROTOCOL_ALIASES.get(flow.protocol.upper())
            if protocol is None:
                continue
            key = flow_join_key(
                str(flow.src_ip),
                int(flow.src_port),
                str(flow.dst_ip),
                int(flow.dst_port),
                flow.protocol,
            )
            start = flow.timestamp_start.timestamp()
            end = max(flow.timestamp_end.timestamp(), start)
            try:
                row = match_row(label_index, key, start, end)
            except AmbiguousFlowLabel:
                ambiguous += 1
                continue
            if row is None:
                if label_index.get(key):
                    unmatched += 1
                else:
                    unlabeled += 1
                continue
            record = sequence_record(flow, row, scenario)
            record["observability"] = observability_tier(record)
            output.write(json.dumps(record, sort_keys=True) + "\n")
            matched += 1
            label_counts[record["binary_label"]] += 1
            family_counts[record["family"]] += 1
            observability_counts[record["observability"]] += 1
    digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
    return {
        "scenario": scenario,
        "records": matched,
        "matched_unlabeled_flows": unmatched,
        "flows_without_label_candidate": unlabeled,
        "ambiguous_label_flows": ambiguous,
        "labels": dict(sorted(label_counts.items())),
        "families": dict(sorted(family_counts.items())),
        "observability": dict(sorted(observability_counts.items())),
        "output_sha256": digest,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare Detector-v2 packet-sequence development records from IoT-23 PCAPs"
    )
    parser.add_argument("--pcap-dir", type=Path, default=Path("data/pcap_v2"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/sequences_v2"))
    parser.add_argument("--scenarios", nargs="*", help="subset of scenarios to prepare")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifests = sorted(args.pcap_dir.glob("*.manifest.json"))
    scenarios = args.scenarios or [
        path.name.removesuffix(".manifest.json") for path in manifests
    ]
    reports = []
    for scenario in scenarios:
        print(f"preparing {scenario} ...", flush=True)
        report = prepare_scenario(
            scenario, args.pcap_dir, args.output_dir / f"{scenario}.jsonl"
        )
        reports.append(report)
        print(json.dumps(report, indent=2, sort_keys=True), flush=True)
    summary_path = args.output_dir / "preparation-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "generated_at": datetime.now(UTC).isoformat(),
                "sequence_capacity": 20,
                "scenarios": reports,
                "notes": [
                    "Flows replayed through the runtime PcapAdapter share the "
                    "inference feature contract.",
                    "Labels join on unordered endpoint pair plus protocol plus "
                    "<=1s interval gap.",
                    "No payload content is read or stored anywhere in this pipeline.",
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {summary_path}")


if __name__ == "__main__":
    main()
