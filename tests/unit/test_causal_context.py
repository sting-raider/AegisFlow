"""Unit tests for causal temporal-context replay (synthetic flows only).

No capture, development-row, or frozen data enters these tests. Fixtures build
synthetic FlowEvents from a single DemoAdapter template with controlled
completion times.
"""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from packages.features.research import (
    TEMPORAL_FEATURE_NAMES,
    TEMPORAL_SCHEMA_VERSION,
    FlowObservation,
    TemporalFeatureState,
)
from services.sensor import DemoAdapter
from training.v2.causal_context import (
    CAUSAL_SIDECAR_SCHEMA_VERSION,
    causal_completion_order,
    replay_causal_context,
    sidecar_payload,
)

_TEMPLATE = next(iter(DemoAdapter().flows()))
_EPOCH = datetime(2021, 1, 1, tzinfo=UTC)


def _flow(index: int, *, start_s: float, end_s: float, **changes: object):
    values: dict[str, object] = {
        "event_id": uuid4(),
        "sensor_id": "v2-synthetic",
        "timestamp_start": _EPOCH + timedelta(seconds=start_s),
        "timestamp_end": _EPOCH + timedelta(seconds=end_s),
        "duration_ms": max((end_s - start_s) * 1000.0, 0.0),
        "source_ip": "10.0.0.1",
        "destination_ip": f"192.0.2.{index % 200 + 1}",
    }
    values.update(changes)
    return _TEMPLATE.model_copy(update=values)


def _series(count: int, step_s: float = 10.0):
    return [
        _flow(index, start_s=index * step_s, end_s=index * step_s + 1.0)
        for index in range(count)
    ]


def test_from_completed_flow_keeps_fields_and_uses_completion_instant() -> None:
    flow = _flow(0, start_s=0.0, end_s=3600.0)
    started = FlowObservation.from_flow_event(flow)
    completed = FlowObservation.from_completed_flow(flow)

    assert completed.timestamp == flow.timestamp_end
    assert started.timestamp == flow.timestamp_start
    assert completed.event_id == started.event_id
    assert completed.sensor_id == started.sensor_id
    assert completed.source_ip == started.source_ip
    assert completed.destination_ip == started.destination_ip
    assert completed.destination_port == started.destination_port
    assert completed.protocol == started.protocol
    assert completed.duration_ms == started.duration_ms
    completed.validate()


def test_from_completed_flow_clamps_reversed_timestamps() -> None:
    flow = _flow(0, start_s=10.0, end_s=5.0)
    completed = FlowObservation.from_completed_flow(flow)

    assert completed.timestamp == flow.timestamp_start
    completed.validate()


def test_completion_order_is_deterministic_and_end_first() -> None:
    flows = _series(6)
    reversed_flows = list(reversed(flows))

    assert [str(flow.event_id) for flow in causal_completion_order(reversed_flows)] == [
        str(flow.event_id) for flow in flows
    ]
    result = replay_causal_context(reversed_flows)
    assert [entry.event_id for entry in result.entries] == [
        str(flow.event_id) for flow in flows
    ]
    assert [entry.completion_index for entry in result.entries] == list(range(6))


def test_replay_is_deterministic_across_runs() -> None:
    flows = _series(8)
    left = replay_causal_context(flows)
    right = replay_causal_context(list(reversed(flows)))

    assert left.ledger_sha256 == right.ledger_sha256
    assert [entry.vector for entry in left.entries] == [
        entry.vector for entry in right.entries
    ]
    assert left.flow_count == 8
    assert left.cold_count >= 1


def test_prefix_replay_matches_full_run_for_shared_prefix() -> None:
    flows = _series(8)
    full = replay_causal_context(flows)
    prefix = replay_causal_context(flows[:5])

    for position in range(5):
        assert prefix.entries[position].vector == full.entries[position].vector


def test_future_flows_do_not_change_prefix_vectors() -> None:
    flows = _series(6)
    before = replay_causal_context(flows)
    extra = _flow(99, start_s=10_000.0, end_s=10_001.0)
    extended = [*_series(6), extra]
    # Reuse identical event ids for the shared prefix so history matches exactly.
    extended = [
        flow.model_copy(update={"event_id": original.event_id})
        for flow, original in zip(extended, [*flows, extra], strict=True)
    ]
    after = replay_causal_context(extended)

    assert after.flow_count == 7
    for position in range(6):
        assert after.entries[position].vector == before.entries[position].vector


def test_duplicate_event_id_fails_closed() -> None:
    flows = _series(3)
    repeated = [*flows, flows[0].model_copy(update={})]

    with pytest.raises(ValueError, match="duplicate event_id"):
        replay_causal_context(repeated)


def test_replay_matches_direct_state_machine_sequence() -> None:
    flows = _series(5)
    result = replay_causal_context(flows)
    state = TemporalFeatureState()

    for flow, entry in zip(flows, result.entries, strict=True):
        mapping = state.observe_mapping(FlowObservation.from_completed_flow(flow))
        assert tuple(mapping[name] for name in TEMPORAL_FEATURE_NAMES) == entry.vector


def test_unlabeled_interleaving_flow_contributes_to_history() -> None:
    labeled = _series(6)
    interleaved = [
        *_series(6),
        _flow(50, start_s=25.0, end_s=26.0, destination_ip="198.51.100.7"),
    ]
    with_history = replay_causal_context(interleaved)
    without_history = replay_causal_context(labeled)

    # The interleaving completion at t=26 sorts fourth, so the flow completing
    # at t=50 is seventh with history present and sixth without it.
    assert (
        with_history.entries[6].vector[TEMPORAL_FEATURE_NAMES.index("source_flows_60s_log1p")]
        == math.log1p(7)
    )
    assert (
        without_history.entries[5].vector[
            TEMPORAL_FEATURE_NAMES.index("source_flows_60s_log1p")
        ]
        == math.log1p(6)
    )


def test_sidecar_payload_carries_no_identifiers_or_timestamps() -> None:
    result = replay_causal_context(_series(4))
    payload = sidecar_payload(result, scenario="synthetic")

    assert payload["schema_version"] == CAUSAL_SIDECAR_SCHEMA_VERSION
    assert payload["temporal_schema_version"] == TEMPORAL_SCHEMA_VERSION
    assert payload["temporal_feature_names"] == list(TEMPORAL_FEATURE_NAMES)
    assert payload["history_flow_count"] == 4
    assert len(payload["entries"]) == 4
    dumped = json.dumps(payload)
    assert "10.0.0.1" not in dumped
    assert "192.0.2." not in dumped
    assert "v2-synthetic" not in dumped
    assert "2021-01-01" not in dumped
    for item in payload["entries"]:
        assert set(item) == {
            "event_id",
            "completion_index",
            "prior_completions",
            "coalesced_span_ms",
            "cold_start",
            "late_event",
            "vector",
        }
        assert len(item["vector"]) == len(TEMPORAL_FEATURE_NAMES)
        assert all(math.isfinite(value) for value in item["vector"])


def test_sidecar_selection_binds_emitted_rows() -> None:
    result = replay_causal_context(_series(4))
    emitted = {result.entries[0].event_id, result.entries[2].event_id}
    payload = sidecar_payload(result, scenario="synthetic", emitted_ids=emitted)

    assert [item["event_id"] for item in payload["entries"]] == [
        result.entries[0].event_id,
        result.entries[2].event_id,
    ]
    with pytest.raises(ValueError, match="unknown event ids"):
        sidecar_payload(result, scenario="synthetic", emitted_ids={"missing-id"})
