"""Causal temporal-context replay for the DEV2-CONTEXT-001 study.

Replays a capture's completed flows through the shared
:class:`packages.features.research.TemporalFeatureState` in causal completion
order so each flow's 16 Schema-B temporal features depend only on completions
at or before its own end. Absolute timestamps, endpoint addresses, and sensor
identifiers exist only ephemerally inside the replay; persisted sidecar output
carries the temporal vector plus integer audit fields, never identifiers.

Only development captures flow through this path. Frozen final evidence is
never loaded here; the study registration binds the permitted sources.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from packages.contracts import FlowEvent
from packages.features.research import (
    TEMPORAL_FEATURE_NAMES,
    TEMPORAL_SCHEMA_VERSION,
    FlowObservation,
    TemporalFeatureState,
)
from services.sensor.adapters import PcapAdapter
from training.v2.prepare_sequences import (
    PROTOCOL_ALIASES,
    AmbiguousFlowLabel,
    flow_join_key,
    match_row,
    parse_zeek_labels,
)
from training.v2.provenance import sha256_file
from training.v2.tensors import load_records

CAUSAL_SIDECAR_SCHEMA_VERSION = "1.0.0"
MULTIVIEW_SIDECAR_SCHEMA_VERSION = "1.1.0"


def causal_completion_order(flows: Sequence[FlowEvent]) -> list[FlowEvent]:
    """Order flows by causal completion instant, deterministically.

    Primary key ``timestamp_end`` is the only observable runtime decision
    point for a whole-capture-merged five-tuple; ``timestamp_start`` orders
    same-end completions by earliest evidence and the deterministic event id
    breaks residual ties without randomness.
    """
    return sorted(
        flows,
        key=lambda flow: (
            max(flow.timestamp_end, flow.timestamp_start),
            min(flow.timestamp_start, flow.timestamp_end),
            str(flow.event_id),
        ),
    )


@dataclass(frozen=True)
class CausalContextEntry:
    event_id: str
    completion_index: int
    prior_completions: int
    coalesced_span_ms: float
    cold_start: bool
    late_event: bool
    vector: tuple[float, ...]


@dataclass(frozen=True)
class CausalReplayResult:
    entries: tuple[CausalContextEntry, ...]
    ledger_sha256: str
    flow_count: int
    cold_count: int
    late_count: int


@dataclass(frozen=True)
class TerminalContextEntry:
    event_id: str
    completion_index: int
    cold_start: bool
    late_event: bool
    vector: tuple[float, ...]


@dataclass(frozen=True)
class TerminalReplayResult:
    entries: tuple[TerminalContextEntry, ...]
    ledger_sha256: str
    flow_count: int
    cold_count: int
    late_count: int


def _ordered_unique_flows(flows: Sequence[FlowEvent]) -> list[FlowEvent]:
    ordered = causal_completion_order(list(flows))
    seen: set[str] = set()
    for flow in ordered:
        event_id = str(flow.event_id)
        if event_id in seen:
            raise ValueError(f"duplicate event_id in context replay: {event_id}")
        seen.add(event_id)
    return ordered


def replay_causal_context(flows: Sequence[FlowEvent]) -> CausalReplayResult:
    """Feed every flow through a fresh state in completion order.

    All flows join the ephemeral history, including flows a label join would
    later exclude: at runtime the sensor observes completions without a label
    oracle. Each ``event_id`` may appear exactly once; a repeat is a replay
    bug and fails closed instead of returning a cached vector.
    """
    ordered = _ordered_unique_flows(flows)
    state = TemporalFeatureState()
    entries: list[CausalContextEntry] = []
    ledger = sha256()
    for index, flow in enumerate(ordered):
        observation = FlowObservation.from_completed_flow(flow)
        mapping = state.observe_mapping(observation)
        vector = tuple(float(mapping[name]) for name in TEMPORAL_FEATURE_NAMES)
        cold = mapping["temporal_cold_start"] == 1.0
        late = mapping["temporal_late_event"] == 1.0
        entries.append(
            CausalContextEntry(
                event_id=str(flow.event_id),
                completion_index=index,
                prior_completions=index,
                coalesced_span_ms=float(flow.duration_ms),
                cold_start=cold,
                late_event=late,
                vector=vector,
            )
        )
        ledger.update(str(flow.event_id).encode("utf-8"))
    return CausalReplayResult(
        entries=tuple(entries),
        ledger_sha256=ledger.hexdigest(),
        flow_count=len(entries),
        cold_count=sum(1 for entry in entries if entry.cold_start),
        late_count=sum(1 for entry in entries if entry.late_event),
    )


def replay_noncausal_terminal_context(
    flows: Sequence[FlowEvent],
) -> TerminalReplayResult:
    """Query every flow against its source's completed full-capture state.

    This is an intentionally future-leaking, non-deployable reference view.
    The terminal snapshot query is read-only, so the result is independent of
    query order and cannot contaminate causal replay or runtime state.
    """
    ordered = _ordered_unique_flows(flows)
    state = TemporalFeatureState()
    ledger = sha256()
    for flow in ordered:
        state.observe_mapping(FlowObservation.from_completed_flow(flow))
        ledger.update(str(flow.event_id).encode("utf-8"))
    entries: list[TerminalContextEntry] = []
    for index, flow in enumerate(ordered):
        mapping = state.noncausal_terminal_snapshot_mapping(
            FlowObservation.from_completed_flow(flow)
        )
        entries.append(
            TerminalContextEntry(
                event_id=str(flow.event_id),
                completion_index=index,
                cold_start=mapping["temporal_cold_start"] == 1.0,
                late_event=mapping["temporal_late_event"] == 1.0,
                vector=tuple(float(mapping[name]) for name in TEMPORAL_FEATURE_NAMES),
            )
        )
    return TerminalReplayResult(
        entries=tuple(entries),
        ledger_sha256=ledger.hexdigest(),
        flow_count=len(entries),
        cold_count=sum(1 for entry in entries if entry.cold_start),
        late_count=sum(1 for entry in entries if entry.late_event),
    )


def sidecar_payload(
    result: CausalReplayResult,
    *,
    scenario: str,
    emitted_ids: set[str] | None = None,
    noncausal_result: TerminalReplayResult | None = None,
) -> dict[str, Any]:
    """Build the persistable aggregate sidecar for emitted rows only.

    ``emitted_ids`` selects the unambiguously labeled rows that join the study
    cohort; every other flow contributed history and leaves no persisted
    trace. The payload carries no timestamps, addresses, or sensor ids.
    """
    selected = (
        result.entries
        if emitted_ids is None
        else tuple(entry for entry in result.entries if entry.event_id in emitted_ids)
    )
    if emitted_ids is not None:
        missing = emitted_ids - {entry.event_id for entry in selected}
        if missing:
            raise ValueError(
                "sidecar selection references unknown event ids: "
                f"{sorted(missing)[:5]}"
            )
    terminal_by_id: dict[str, TerminalContextEntry] = {}
    if noncausal_result is not None:
        if (
            noncausal_result.ledger_sha256 != result.ledger_sha256
            or noncausal_result.flow_count != result.flow_count
        ):
            raise ValueError("causal and terminal context replays differ")
        terminal_by_id = {entry.event_id: entry for entry in noncausal_result.entries}
        if set(terminal_by_id) != {entry.event_id for entry in result.entries}:
            raise ValueError("causal and terminal context event ids differ")
    entries = []
    for entry in selected:
        item = {
            "event_id": entry.event_id,
            "completion_index": entry.completion_index,
            "prior_completions": entry.prior_completions,
            "coalesced_span_ms": entry.coalesced_span_ms,
            "cold_start": entry.cold_start,
            "late_event": entry.late_event,
            "vector": list(entry.vector),
        }
        if noncausal_result is not None:
            item["non_causal_terminal_vector"] = list(
                terminal_by_id[entry.event_id].vector
            )
        entries.append(item)
    payload = {
        "schema_version": (
            MULTIVIEW_SIDECAR_SCHEMA_VERSION
            if noncausal_result is not None
            else CAUSAL_SIDECAR_SCHEMA_VERSION
        ),
        "temporal_schema_version": TEMPORAL_SCHEMA_VERSION,
        "temporal_feature_names": list(TEMPORAL_FEATURE_NAMES),
        "scenario": scenario,
        "ledger_sha256": result.ledger_sha256,
        "history_flow_count": result.flow_count,
        "emitted_count": len(selected),
        "entries": entries,
    }
    if noncausal_result is not None:
        payload["non_causal_reference"] = {
            "kind": "read_only_terminal_retained_state",
            "deployable": False,
            "cold_count": sum(
                1
                for entry in selected
                if terminal_by_id[entry.event_id].cold_start
            ),
            "late_count": sum(
                1 for entry in selected if terminal_by_id[entry.event_id].late_event
            ),
        }
    return payload


def build_scenario_sidecar(
    scenario: str,
    pcap_dir: Path,
    sequences_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Replay one scenario capture and persist causal context for sealed rows.

    Every adapter flow joins the ephemeral history; only `event_id` values
    already present in the sealed `sequences_path` JSONL are emitted, so the
    ablation views share identical rows with the frozen cohort. Sealed rows
    absent from this replay fail closed: the replay disagrees with the sealed
    preparation and must not produce a partial sidecar.
    """
    if output_path.exists():
        raise FileExistsError(f"refusing to overwrite causal sidecar: {output_path}")
    manifest_path = pcap_dir / f"{scenario}.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    pcap_filename = manifest.get("pcap_filename")
    if (
        not isinstance(pcap_filename, str)
        or not pcap_filename
        or Path(pcap_filename).name != pcap_filename
    ):
        raise ValueError(f"scenario {scenario} has an unsafe PCAP filename")
    if manifest.get("scenario", scenario) != scenario:
        raise ValueError(f"scenario manifest mismatch: {scenario}")
    pcap_path = pcap_dir / pcap_filename
    labels_path = pcap_dir / f"{scenario}.conn.log.labeled"
    if not pcap_path.exists() or not labels_path.exists():
        raise FileNotFoundError(f"scenario {scenario} is missing its pcap or labels")
    if not sequences_path.is_file():
        raise FileNotFoundError(f"scenario {scenario} is missing sealed rows: {sequences_path}")
    sealed_records = load_records([sequences_path])
    if not sealed_records:
        raise ValueError(f"scenario {scenario} has no sealed rows to contextualize")
    if any(record["scenario"] != scenario for record in sealed_records):
        raise ValueError(f"scenario {scenario} sealed rows contain another scenario")
    sealed_event_ids = [str(record["event_id"]) for record in sealed_records]
    sealed_ids = set(sealed_event_ids)
    if len(sealed_ids) != len(sealed_event_ids):
        raise ValueError(f"scenario {scenario} sealed rows contain duplicate event ids")
    _, label_index = parse_zeek_labels(labels_path)
    adapter = PcapAdapter(pcap_path, sensor_id=f"v2-{scenario}")
    buffered: list[FlowEvent] = []
    gated = ambiguous = unmatched = unlabeled = 0
    matched_ids: set[str] = set()
    for flow in adapter.flows():
        buffered.append(flow)
        if PROTOCOL_ALIASES.get(flow.protocol.upper()) is None:
            gated += 1
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
        matched_ids.add(str(flow.event_id))
    missing_matches = sealed_ids - matched_ids
    unexpected_matches = matched_ids - sealed_ids
    if missing_matches or unexpected_matches:
        raise ValueError(
            f"scenario {scenario} label alignment differs from sealed rows: "
            f"missing={sorted(missing_matches)[:5]}, "
            f"unexpected={sorted(unexpected_matches)[:5]}"
        )
    result = replay_causal_context(buffered)
    noncausal_result = replay_noncausal_terminal_context(buffered)
    replayed_ids = {entry.event_id for entry in result.entries}
    missing = sealed_ids - replayed_ids
    if missing:
        raise ValueError(
            f"scenario {scenario} replay is missing sealed rows: {sorted(missing)[:5]}"
        )
    payload = sidecar_payload(
        result,
        scenario=scenario,
        emitted_ids=sealed_ids,
        noncausal_result=noncausal_result,
    )
    payload["source_hashes"] = {
        "pcap_sha256": sha256_file(pcap_path),
        "labels_sha256": sha256_file(labels_path),
        "sealed_rows_sha256": sha256_file(sequences_path),
    }
    with output_path.open("x", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(payload, sort_keys=True, indent=2) + "\n")
    digest = sha256(output_path.read_bytes()).hexdigest()
    return {
        "scenario": scenario,
        "adapter_flows": len(buffered),
        "non_tcp_udp_icmp_flows": gated,
        "ambiguous_label_flows": ambiguous,
        "matched_unlabeled_flows": unmatched,
        "flows_without_label_candidate": unlabeled,
        "sealed_rows": len(sealed_ids),
        "emitted_rows": len(sealed_ids),
        "context_only_flows": len(buffered) - len(sealed_ids),
        "cold_rows": sum(
            1 for entry in result.entries if entry.event_id in sealed_ids and entry.cold_start
        ),
        "late_rows": sum(
            1 for entry in result.entries if entry.event_id in sealed_ids and entry.late_event
        ),
        "non_causal_cold_rows": sum(
            1
            for entry in noncausal_result.entries
            if entry.event_id in sealed_ids and entry.cold_start
        ),
        "non_causal_late_rows": sum(
            1
            for entry in noncausal_result.entries
            if entry.event_id in sealed_ids and entry.late_event
        ),
        "ledger_sha256": result.ledger_sha256,
        "source_hashes": payload["source_hashes"],
        "output_sha256": digest,
    }
