from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import numpy as np
import pandas as pd

from packages.features.registry import FEATURE_NAMES
from training.data.models import CanonicalDataset, InputProvenance, SourceColumnProfile

DatasetKind = Literal["cic_ids2017", "cse_cic_ids2018", "unsw_nb15", "nfstream_csv"]
MAX_INPUT_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_MAX_ROWS = 5_000_000


@dataclass(frozen=True)
class ColumnRule:
    aliases: tuple[str, ...]
    scale: float = 1.0


def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.strip().lower())


def _rule(*aliases: str, scale: float = 1.0) -> ColumnRule:
    return ColumnRule(tuple(_key(alias) for alias in aliases), scale)


CIC_RULES: dict[str, ColumnRule] = {
    "duration_ms": _rule("Flow Duration", scale=0.001),
    "packets_forward": _rule("Total Fwd Packets", "Tot Fwd Pkts"),
    "packets_reverse": _rule("Total Backward Packets", "Tot Bwd Pkts"),
    "bytes_forward": _rule("Total Length of Fwd Packets", "TotLen Fwd Pkts"),
    "bytes_reverse": _rule("Total Length of Bwd Packets", "TotLen Bwd Pkts"),
    "packet_rate": _rule("Flow Packets/s", "Flow Pkts/s"),
    "byte_rate": _rule("Flow Bytes/s", "Flow Byts/s"),
    "packet_length_mean": _rule("Packet Length Mean", "Pkt Len Mean"),
    "packet_length_std": _rule("Packet Length Std", "Pkt Len Std"),
    "iat_mean": _rule("Flow IAT Mean", scale=0.001),
    "iat_std": _rule("Flow IAT Std", scale=0.001),
    "tcp_syn_count": _rule("SYN Flag Count", "SYN Flag Cnt"),
    "tcp_ack_count": _rule("ACK Flag Count", "ACK Flag Cnt"),
    "tcp_rst_count": _rule("RST Flag Count", "RST Flag Cnt"),
    "destination_port": _rule("Destination Port", "Dst Port"),
}

UNSW_RULES: dict[str, ColumnRule] = {
    "duration_ms": _rule("dur", scale=1000.0),
    "packets_forward": _rule("spkts"),
    "packets_reverse": _rule("dpkts"),
    "bytes_forward": _rule("sbytes"),
    "bytes_reverse": _rule("dbytes"),
    "packet_rate": _rule("rate"),
    "byte_rate_forward": _rule("sload", scale=0.125),
    "byte_rate_reverse": _rule("dload", scale=0.125),
    "packet_length_mean_forward": _rule("smean"),
    "packet_length_mean_reverse": _rule("dmean"),
    "iat_mean_forward": _rule("sinpkt"),
    "iat_mean_reverse": _rule("dinpkt"),
    "destination_port": _rule("dsport", "destination_port"),
}

NFSTREAM_RULES: dict[str, ColumnRule] = {
    "duration_ms": _rule("duration_ms", "bidirectional_duration_ms"),
    "packets_forward": _rule("packets_forward", "src2dst_packets"),
    "packets_reverse": _rule("packets_reverse", "dst2src_packets"),
    "bytes_forward": _rule("bytes_forward", "src2dst_bytes"),
    "bytes_reverse": _rule("bytes_reverse", "dst2src_bytes"),
    "packet_rate": _rule("packet_rate", "bidirectional_packets_rate"),
    "byte_rate": _rule("byte_rate", "bidirectional_bytes_rate"),
    "packet_length_mean": _rule("packet_length_mean", "bidirectional_mean_ps"),
    "packet_length_std": _rule("packet_length_std", "bidirectional_stddev_ps"),
    "iat_mean": _rule("iat_mean", "bidirectional_mean_piat_ms"),
    "iat_std": _rule("iat_std", "bidirectional_stddev_piat_ms"),
    "tcp_syn_count": _rule("tcp_syn_count", "bidirectional_syn_packets"),
    "tcp_ack_count": _rule("tcp_ack_count", "bidirectional_ack_packets"),
    "tcp_rst_count": _rule("tcp_rst_count", "bidirectional_rst_packets"),
    "destination_port": _rule("destination_port", "dst_port"),
}

BENIGN_LABELS = {"benign", "normal", "normaltraffic", "0", "background"}
LABEL_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("brute_force", ("patator", "bruteforce", "brute force")),
    ("web_attack", ("xss", "sql injection", "web attack")),
    ("port_scan", ("portscan", "port scan", "reconnaissance")),
    ("ddos", ("ddos", "distributed denial")),
    ("dos", ("dos", "denial of service", "hulk", "slowloris", "goldeneye")),
    ("infiltration", ("infiltration",)),
    ("botnet", ("botnet", " bot", "bot ")),
    ("heartbleed", ("heartbleed",)),
)


def normalize_label(value: object) -> str:
    raw = str(value).replace("�", "").strip().lower()
    compact = _key(raw)
    if compact in BENIGN_LABELS or raw in BENIGN_LABELS:
        return "benign"
    for family, patterns in LABEL_FAMILIES:
        if any(pattern in raw for pattern in patterns):
            return family
    normalized = re.sub(r"[^a-z0-9]+", "_", raw).strip("_")
    return normalized or "unlabeled"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _provenance(path: Path) -> InputProvenance:
    actual_sha256 = _sha256(path)
    manifest_path = path.with_suffix(f"{path.suffix}.manifest.json")
    declared: dict[str, Any] | None = None
    if manifest_path.is_file():
        decoded = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError(f"dataset manifest must be a JSON object: {manifest_path}")
        declared = decoded
        expected = str(declared.get("sha256", "")).lower()
        if expected and expected != actual_sha256:
            raise ValueError(f"dataset checksum does not match manifest: {path}")
        declared_size = declared.get("size_bytes")
        if declared_size is not None and int(declared_size) != path.stat().st_size:
            raise ValueError(f"dataset size does not match manifest: {path}")
    return InputProvenance(path.name, path.stat().st_size, actual_sha256, declared)


def _resolve_column(lookup: dict[str, str], aliases: tuple[str, ...]) -> str | None:
    return next((lookup[alias] for alias in aliases if alias in lookup), None)


def _numeric(
    frame: pd.DataFrame, lookup: dict[str, str], rule: ColumnRule
) -> pd.Series[float] | None:
    column = _resolve_column(lookup, rule.aliases)
    if column is None:
        return None
    return pd.to_numeric(frame[column], errors="coerce").astype(float) * rule.scale


def _identifier_like(name: str) -> bool:
    normalized = _key(name)
    return normalized in {"id", "recordid"} or any(
        token in normalized
        for token in ("srcip", "sourceip", "dstip", "destinationip", "flowid", "sessionid")
    )


def _source_profiles(
    frame: pd.DataFrame, labels: pd.Series[str], label_column: str
) -> tuple[SourceColumnProfile, ...]:
    profiles: list[SourceColumnProfile] = []
    rows = max(len(frame), 1)
    for column in frame.columns:
        if column == label_column:
            continue
        values = frame[column].fillna("<missing>").astype(str)
        unique_count = int(values.nunique(dropna=False))
        purity = 0.0
        if unique_count and unique_count <= min(10_000, rows):
            grouped = pd.DataFrame({"value": values, "label": labels}).groupby("value")["label"]
            purity = float(grouped.value_counts().groupby(level=0).max().sum() / rows)
        profiles.append(
            SourceColumnProfile(
                name=str(column),
                unique_count=unique_count,
                unique_ratio=unique_count / rows,
                label_purity=purity,
                identifier_like=_identifier_like(str(column)),
            )
        )
    return tuple(profiles)


def _label_column(kind: DatasetKind, lookup: dict[str, str], requested: str | None) -> str:
    if requested:
        resolved = lookup.get(_key(requested))
        if resolved is None:
            raise ValueError(f"label column is missing: {requested}")
        return resolved
    candidates = ("attackcat", "label") if kind == "unsw_nb15" else ("label", "attackcat")
    resolved = _resolve_column(lookup, candidates)
    if resolved is None:
        raise ValueError("no label column found; provide --label-column")
    return resolved


def _timestamps(frame: pd.DataFrame, lookup: dict[str, str], requested: str | None) -> np.ndarray:
    candidates = (_key(requested),) if requested else ("timestamp", "stime", "starttime")
    column = _resolve_column(lookup, candidates)
    if column is None:
        return np.full(len(frame), np.datetime64("NaT"), dtype="datetime64[ns]")
    parsed = pd.to_datetime(frame[column], errors="coerce", utc=True, format="mixed", dayfirst=True)
    return parsed.to_numpy(dtype="datetime64[ns]")


def _canonical_features(
    frame: pd.DataFrame,
    lookup: dict[str, str],
    rules: dict[str, ColumnRule],
    *,
    allow_missing_destination_port: bool = False,
) -> tuple[pd.DataFrame, tuple[str, ...]]:
    notes: list[str] = []
    values: dict[str, pd.Series[float]] = {}
    for feature, rule in rules.items():
        numeric = _numeric(frame, lookup, rule)
        if numeric is not None:
            values[feature] = numeric

    if allow_missing_destination_port and "destination_port" not in values:
        values["destination_port"] = pd.Series(np.zeros(len(frame)), index=frame.index, dtype=float)
        notes.append(
            "destination_port=0 because the official UNSW training/testing partitions "
            "do not publish transport ports"
        )

    required = (
        "duration_ms",
        "packets_forward",
        "packets_reverse",
        "bytes_forward",
        "bytes_reverse",
        "destination_port",
    )
    missing = [name for name in required if name not in values]
    if missing:
        raise ValueError(f"dataset is missing required canonical inputs: {', '.join(missing)}")
    duration_seconds = values["duration_ms"] / 1000.0
    packets_total = values["packets_forward"] + values["packets_reverse"]
    bytes_total = values["bytes_forward"] + values["bytes_reverse"]
    if {
        "packet_length_mean_forward",
        "packet_length_mean_reverse",
    }.issubset(values):
        values["packet_length_mean"] = (
            values["packet_length_mean_forward"] * values["packets_forward"]
            + values["packet_length_mean_reverse"] * values["packets_reverse"]
        ) / packets_total.where(packets_total > 0)
        notes.append("packet_length_mean is directionally packet-weighted")
    if {"byte_rate_forward", "byte_rate_reverse"}.issubset(values):
        values["byte_rate"] = values["byte_rate_forward"] + values["byte_rate_reverse"]
        notes.append("byte_rate converts and sums UNSW directional bit/s load fields")
    if {"iat_mean_forward", "iat_mean_reverse"}.issubset(values):
        values["iat_mean"] = (
            values["iat_mean_forward"] * values["packets_forward"]
            + values["iat_mean_reverse"] * values["packets_reverse"]
        ) / packets_total.where(packets_total > 0)
        notes.append("iat_mean is directionally packet-weighted")
    values.setdefault("packet_rate", packets_total / duration_seconds.where(duration_seconds > 0))
    values.setdefault("byte_rate", bytes_total / duration_seconds.where(duration_seconds > 0))
    values.setdefault("packet_length_mean", bytes_total / packets_total.where(packets_total > 0))
    for unavailable in (
        "packet_length_std",
        "iat_mean",
        "iat_std",
        "tcp_syn_count",
        "tcp_rst_count",
    ):
        if unavailable not in values:
            values[unavailable] = pd.Series(np.zeros(len(frame)), index=frame.index, dtype=float)
            notes.append(f"{unavailable}=0 because the source schema does not provide it")
    values["forward_reverse_byte_ratio"] = values["bytes_forward"] / values["bytes_reverse"].clip(
        lower=1.0
    )
    if "tcp_ack_count" not in values:
        values["tcp_ack_count"] = pd.Series(np.zeros(len(frame)), index=frame.index, dtype=float)
        notes.append("tcp_ack_count=0 because the source schema does not provide it")
    values["syn_ack_ratio"] = values["tcp_syn_count"] / values["tcp_ack_count"].clip(lower=1.0)
    values["packets_total"] = packets_total
    values["bytes_total"] = bytes_total
    canonical = pd.DataFrame({name: values[name] for name in FEATURE_NAMES}, index=frame.index)
    return canonical, tuple(notes)


def load_dataset(
    kind: DatasetKind,
    paths: list[Path],
    *,
    label_column: str | None = None,
    group_column: str | None = None,
    timestamp_column: str | None = None,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> CanonicalDataset:
    if not paths:
        raise ValueError("at least one dataset CSV is required")
    if max_rows < 1:
        raise ValueError("max_rows must be positive")
    rules = (
        UNSW_RULES
        if kind == "unsw_nb15"
        else NFSTREAM_RULES
        if kind == "nfstream_csv"
        else CIC_RULES
    )
    frames: list[pd.DataFrame] = []
    provenances: list[InputProvenance] = []
    remaining = max_rows + 1
    for requested_path in paths:
        path = requested_path.resolve()
        if not path.is_file() or path.suffix.lower() != ".csv":
            raise ValueError(f"dataset input must be an existing CSV: {path}")
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError(f"dataset input exceeds 8 GiB: {path}")
        frame = pd.read_csv(path, nrows=remaining, low_memory=False)
        frame["__aegisflow_source_file"] = path.name
        frames.append(frame)
        provenances.append(_provenance(path))
        remaining -= len(frame)
        if remaining <= 0:
            raise ValueError(f"dataset exceeds the configured {max_rows}-row safety limit")
    raw = pd.concat(frames, ignore_index=True)
    lookup = {_key(str(column)): str(column) for column in raw.columns}
    resolved_label = _label_column(kind, lookup, label_column)
    raw_labels = raw[resolved_label].fillna("unlabeled").astype(str)
    if kind == "unsw_nb15":
        fallback = _resolve_column(lookup, ("label",))
        if fallback and fallback != resolved_label:
            missing_attack_category = raw_labels.str.strip().isin({"", "nan", "unlabeled"})
            raw_labels = raw_labels.where(
                ~missing_attack_category, raw[fallback].fillna("unlabeled").astype(str)
            )
    labels = raw_labels.map(normalize_label)
    canonical, notes = _canonical_features(
        raw,
        lookup,
        rules,
        allow_missing_destination_port=kind == "unsw_nb15",
    )
    if group_column:
        resolved_group = lookup.get(_key(group_column))
        if resolved_group is None:
            raise ValueError(f"group column is missing: {group_column}")
        groups = raw[resolved_group].fillna("<missing>").astype(str).to_numpy(dtype=str)
    else:
        groups = raw["__aegisflow_source_file"].astype(str).to_numpy(dtype=str)
    source_files = raw["__aegisflow_source_file"].astype(str).to_numpy(dtype=str)
    profiles = _source_profiles(
        raw.drop(columns=["__aegisflow_source_file"]), labels, resolved_label
    )
    return CanonicalDataset(
        name=kind,
        features=canonical.to_numpy(dtype=np.float64),
        labels=labels.to_numpy(dtype=str),
        raw_labels=raw_labels.to_numpy(dtype=str),
        groups=groups,
        timestamps=_timestamps(raw, lookup, timestamp_column),
        source_files=source_files,
        raw_column_names=tuple(
            str(column) for column in raw.columns if column != "__aegisflow_source_file"
        ),
        source_profiles=profiles,
        provenance=tuple(provenances),
        adapter_notes=notes,
    )
