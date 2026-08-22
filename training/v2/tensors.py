"""Tensor construction for Detector-v2 experiments.

Uses the same shared representation functions as runtime inference, so training and
inference parity holds by construction. Records are the JSONL rows produced by
`training/v2/prepare_sequences.py`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

import numpy as np

from packages.detection_v2.sequences import (
    SEQUENCE_FEATURES_PER_PACKET,
    connection_state_vector,
    sequence_arrays,
)
from packages.features.research import portable_feature_matrix

AGGREGATE_FEATURE_NAMES = (
    "duration_log1p_ms",
    "packets_total_log1p",
    "packets_forward_fraction",
    "bytes_total_log1p",
    "bytes_forward_fraction",
    "packet_rate_log1p_derived",
    "byte_rate_log1p_derived",
    "packet_length_mean_log1p_derived",
    "forward_reverse_byte_log_ratio",
    "protocol_tcp",
    "protocol_udp",
    "protocol_icmp",
    "protocol_other",
    "destination_port_missing",
    "port_well_known",
    "port_registered",
    "port_dynamic",
    "service_dns",
    "service_web",
    "service_mail",
    "service_remote_access",
    "service_file_transfer",
    "service_database",
    "service_other",
)


@dataclass(frozen=True)
class V2Dataset:
    sequence: np.ndarray
    mask: np.ndarray
    state: np.ndarray
    aggregate: np.ndarray
    binary_label: np.ndarray
    family: list[str]
    scenario: list[str]
    observability: list[str]
    event_ids: list[str]

    @property
    def rows(self) -> int:
        return len(self.binary_label)


class SequenceRecord(TypedDict):
    event_id: str
    scenario: str
    family: str
    detailed_label: str
    binary_label: str
    seq_sizes: list[float]
    seq_directions: list[int]
    seq_iats_ms: list[float]
    total_packets: int
    duration_ms: float
    protocol: str
    tcp_syn_count: int
    tcp_ack_count: int
    tcp_fin_count: int
    tcp_rst_count: int
    tcp_psh_count: int
    bytes_forward: int
    bytes_reverse: int
    packets_forward: int
    packets_reverse: int
    src_port: int
    dst_port: int
    ip_version: int
    observability: str


def load_records(paths: Iterable[Path]) -> list[SequenceRecord]:
    records: list[SequenceRecord] = []
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                if isinstance(record, dict):
                    records.append(record)  # type: ignore[arg-type]
    return records


def deduplicate_records(records: Sequence[SequenceRecord]) -> list[SequenceRecord]:
    """Exact-vector deduplication across scenarios to prevent near-identical reuse."""

    seen: set[tuple[object, ...]] = set()
    unique: list[SequenceRecord] = []
    duplicates = 0
    for record in records:
        fingerprint: tuple[object, ...] = (
            tuple(record["seq_sizes"]),
            tuple(record["seq_directions"]),
            tuple(record["seq_iats_ms"]),
            record["total_packets"],
            record["duration_ms"],
            record["bytes_forward"],
            record["bytes_reverse"],
            record["protocol"],
        )
        if fingerprint in seen:
            duplicates += 1
            continue
        seen.add(fingerprint)
        unique.append(record)
    del duplicates
    return unique


def aggregate_matrix(records: Sequence[SequenceRecord]) -> np.ndarray:
    matrix = portable_feature_matrix(
        duration_ms=np.asarray([float(r["duration_ms"]) for r in records]),
        packets_forward=np.asarray([int(r["packets_forward"]) for r in records]),
        packets_reverse=np.asarray([int(r["packets_reverse"]) for r in records]),
        bytes_forward=np.asarray([int(r["bytes_forward"]) for r in records]),
        bytes_reverse=np.asarray([int(r["bytes_reverse"]) for r in records]),
        destination_ports=[
            int(r["dst_port"]) if r.get("dst_port") is not None else None for r in records
        ],
        protocols=[str(r["protocol"]) for r in records],
    )
    return np.asarray(matrix, dtype=np.float64)


def build_dataset(
    records: Sequence[SequenceRecord], *, max_length: int = 20
) -> V2Dataset:
    if not records:
        raise ValueError("cannot build a dataset from zero records")
    rows = len(records)
    sequence = np.zeros((rows, max_length, SEQUENCE_FEATURES_PER_PACKET), dtype=np.float32)
    mask = np.zeros((rows, max_length), dtype=np.float32)
    state = np.zeros((rows, 8), dtype=np.float64)
    labels: list[float] = []
    families: list[str] = []
    scenarios: list[str] = []
    tiers: list[str] = []
    event_ids: list[str] = []
    for index, record in enumerate(records):
        tensor, row_mask = sequence_arrays(
            list(record["seq_sizes"]),
            list(record["seq_directions"]),
            list(record["seq_iats_ms"]),
            max_length=max_length,
        )
        sequence[index] = tensor
        mask[index] = row_mask
        state[index] = connection_state_vector(
            protocol=str(record["protocol"]),
            total_packets=int(record["total_packets"]),
            syn_count=int(record["tcp_syn_count"]),
            ack_count=int(record["tcp_ack_count"]),
            fin_count=int(record["tcp_fin_count"]),
            rst_count=int(record["tcp_rst_count"]),
            psh_count=int(record["tcp_psh_count"]),
            bytes_forward=int(record["bytes_forward"]),
            bytes_reverse=int(record["bytes_reverse"]),
        )
        labels.append(1.0 if record["binary_label"] == "malicious" else 0.0)
        families.append(str(record["family"]))
        scenarios.append(str(record["scenario"]))
        tiers.append(str(record["observability"]))
        event_ids.append(str(record["event_id"]))
    return V2Dataset(
        sequence=sequence,
        mask=mask,
        state=state,
        aggregate=aggregate_matrix(records),
        binary_label=np.asarray(labels),
        family=families,
        scenario=scenarios,
        observability=tiers,
        event_ids=event_ids,
    )


def class_capped_subset(
    records: Sequence[SequenceRecord],
    *,
    scenarios: set[str],
    per_class_cap: int,
    seed: int,
) -> list[SequenceRecord]:
    """Deterministic per-class cap inside the given scenario subset."""

    selected: list[SequenceRecord] = []
    counts = {"benign": 0, "malicious": 0}
    ordered = sorted(records, key=lambda item: str(item["event_id"]))
    generator = np.random.default_rng(seed)
    permutation = generator.permutation(len(ordered))
    for position in permutation.tolist():
        record = ordered[int(position)]
        if str(record["scenario"]) not in scenarios:
            continue
        label = str(record["binary_label"])
        if label not in counts or counts[label] >= per_class_cap:
            continue
        counts[label] += 1
        selected.append(record)
    if counts["benign"] == 0 or counts["malicious"] == 0:
        raise ValueError("class-capped subset requires both classes")
    return selected
