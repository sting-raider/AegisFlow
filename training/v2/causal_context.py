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

from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from packages.contracts import FlowEvent
from packages.features.research import (
    TEMPORAL_FEATURE_NAMES,
    TEMPORAL_SCHEMA_VERSION,
    FlowObservation,
    TemporalFeatureState,
)

CAUSAL_SIDECAR_SCHEMA_VERSION = "1.0.0"


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


def replay_causal_context(flows: Sequence[FlowEvent]) -> CausalReplayResult:
    """Feed every flow through a fresh state in completion order.

    All flows join the ephemeral history, including flows a label join would
    later exclude: at runtime the sensor observes completions without a label
    oracle. Each ``event_id`` may appear exactly once; a repeat is a replay
    bug and fails closed instead of returning a cached vector.
    """
    ordered = causal_completion_order(list(flows))
    seen: set[str] = set()
    for flow in ordered:
        event_id = str(flow.event_id)
        if event_id in seen:
            raise ValueError(f"duplicate event_id in causal replay: {event_id}")
        seen.add(event_id)
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


def sidecar_payload(
    result: CausalReplayResult, *, scenario: str, emitted_ids: set[str] | None = None
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
    return {
        "schema_version": CAUSAL_SIDECAR_SCHEMA_VERSION,
        "temporal_schema_version": TEMPORAL_SCHEMA_VERSION,
        "temporal_feature_names": list(TEMPORAL_FEATURE_NAMES),
        "scenario": scenario,
        "ledger_sha256": result.ledger_sha256,
        "history_flow_count": result.flow_count,
        "entries": [
            {
                "event_id": entry.event_id,
                "completion_index": entry.completion_index,
                "prior_completions": entry.prior_completions,
                "coalesced_span_ms": entry.coalesced_span_ms,
                "cold_start": entry.cold_start,
                "late_event": entry.late_event,
                "vector": list(entry.vector),
            }
            for entry in selected
        ],
    }
