from __future__ import annotations

from datetime import timedelta

import numpy as np
import pytest

from packages.features.research import (
    PORTABLE_FEATURE_NAMES,
    RUNTIME_ENRICHED_FEATURE_NAMES,
    TEMPORAL_FEATURE_NAMES,
    FlowObservation,
    TemporalFeatureState,
    portable_feature_mapping,
    portable_feature_matrix,
    portable_feature_vector,
    research_feature_schema,
)
from services.sensor import DemoAdapter


def _observation(index: int, **changes: object) -> FlowObservation:
    base = next(iter(DemoAdapter().flows()))
    values: dict[str, object] = {
        "event_id": f"event-{index}",
        "sensor_id": "sensor-a",
        "timestamp": base.timestamp_start + timedelta(seconds=index),
        "source_ip": "10.0.0.1",
        "destination_ip": f"192.0.2.{index % 200 + 1}",
        "destination_port": 443,
        "protocol": "TCP",
        "duration_ms": 250.0,
        "packets_forward": 4,
        "packets_reverse": 2,
        "bytes_forward": 400,
        "bytes_reverse": 200,
    }
    values.update(changes)
    return FlowObservation(**values)  # type: ignore[arg-type]


def test_portable_schema_uses_semantic_categories_not_identity_or_raw_port() -> None:
    first = _observation(1)
    second = _observation(
        1,
        source_ip="2001:db8::1",
        destination_ip="2001:db8::2",
    )
    mapping = portable_feature_mapping(first)

    np.testing.assert_array_equal(portable_feature_vector(first), portable_feature_vector(second))
    assert tuple(mapping) == PORTABLE_FEATURE_NAMES
    assert "destination_port" not in PORTABLE_FEATURE_NAMES
    assert mapping["protocol_tcp"] == 1.0
    assert mapping["port_well_known"] == 1.0
    assert mapping["service_web"] == 1.0
    assert np.isfinite(list(mapping.values())).all()


def test_missing_port_is_explicit_without_masquerading_as_port_zero() -> None:
    mapping = portable_feature_mapping(_observation(1, destination_port=None))

    assert mapping["destination_port_missing"] == 1.0
    assert mapping["port_well_known"] == 0.0
    assert mapping["port_registered"] == 0.0
    assert mapping["port_dynamic"] == 0.0


def test_flow_event_and_training_observation_have_exact_portable_parity() -> None:
    flow = next(iter(DemoAdapter().flows()))
    runtime = FlowObservation.from_flow_event(flow)
    training = FlowObservation(
        event_id=str(flow.event_id),
        sensor_id=flow.sensor_id,
        timestamp=flow.timestamp_start,
        source_ip=str(flow.src_ip),
        destination_ip=str(flow.dst_ip),
        destination_port=flow.dst_port,
        protocol=flow.protocol,
        duration_ms=float(flow.duration_ms),
        packets_forward=flow.packets_forward,
        packets_reverse=flow.packets_reverse,
        bytes_forward=flow.bytes_forward,
        bytes_reverse=flow.bytes_reverse,
    )

    np.testing.assert_array_equal(
        portable_feature_vector(runtime), portable_feature_vector(training)
    )
    batch = portable_feature_matrix(
        duration_ms=np.asarray([runtime.duration_ms]),
        packets_forward=np.asarray([runtime.packets_forward]),
        packets_reverse=np.asarray([runtime.packets_reverse]),
        bytes_forward=np.asarray([runtime.bytes_forward]),
        bytes_reverse=np.asarray([runtime.bytes_reverse]),
        destination_ports=[runtime.destination_port],
        protocols=[runtime.protocol],
    )
    np.testing.assert_array_equal(batch[0], portable_feature_vector(runtime))


def test_temporal_replay_is_deterministic_and_duplicate_idempotent() -> None:
    events = [_observation(index) for index in range(8)]
    left = TemporalFeatureState()
    right = TemporalFeatureState()

    left_vectors = [left.observe_runtime_enriched_vector(event) for event in events]
    right_vectors = [right.observe_runtime_enriched_vector(event) for event in events]

    np.testing.assert_array_equal(left_vectors, right_vectors)
    assert left_vectors[0].shape == (len(RUNTIME_ENRICHED_FEATURE_NAMES),)
    before = left.event_count
    duplicate = left.observe_runtime_enriched_vector(events[-1])
    assert left.event_count == before
    np.testing.assert_array_equal(duplicate, left_vectors[-1])


def test_temporal_state_is_sensor_scoped_and_expires_old_events() -> None:
    state = TemporalFeatureState(max_sources=2, max_events_per_source=3)
    first = state.observe_mapping(_observation(0))
    other_sensor = state.observe_mapping(_observation(1, event_id="other", sensor_id="sensor-b"))
    late_time = _observation(100, event_id="future")
    future = state.observe_mapping(late_time)

    assert first["temporal_cold_start"] == 1.0
    assert other_sensor["temporal_cold_start"] == 1.0
    assert future["source_flows_60s_log1p"] == pytest.approx(np.log1p(1))
    assert state.source_count == 2
    assert state.event_count <= 3


def test_temporal_duplicate_cache_is_sensor_scoped_even_when_event_ids_match() -> None:
    state = TemporalFeatureState()
    state.observe_mapping(_observation(0, event_id="warmup"))
    # PCAP replay event IDs do not include the sensor identity.
    first_sensor = _observation(1, event_id="same-observation")
    second_sensor = _observation(1, event_id="same-observation", sensor_id="sensor-b")
    warm = state.observe_mapping(first_sensor)
    cold = state.observe_mapping(second_sensor)

    assert warm["temporal_cold_start"] == 0.0
    assert cold["temporal_cold_start"] == 1.0
    assert cold["source_flows_60s_log1p"] == pytest.approx(np.log1p(1))
    assert state.source_count == 2
    assert state.event_count == 3
    assert state.observe_mapping(first_sensor) == warm
    assert state.observe_mapping(second_sensor) == cold
    assert state.event_count == 3


def test_temporal_clear_removes_sensor_scoped_duplicate_entries() -> None:
    state = TemporalFeatureState()
    state.observe_mapping(_observation(0, event_id="warmup"))
    event = _observation(1, event_id="repeat-after-restart")
    assert state.observe_mapping(event)["temporal_cold_start"] == 0.0
    state.clear()
    assert state.source_count == state.event_count == 0
    assert state.observe_mapping(event)["temporal_cold_start"] == 1.0


def test_reordered_and_too_late_events_are_visible_and_do_not_corrupt_state() -> None:
    state = TemporalFeatureState(max_clock_skew_seconds=2.0)
    state.observe_mapping(_observation(10))
    before = state.event_count
    reordered = state.observe_mapping(_observation(9, event_id="reordered"))
    very_late = state.observe_mapping(_observation(1, event_id="very-late"))

    assert reordered["temporal_late_event"] == 1.0
    assert very_late["temporal_late_event"] == 1.0
    assert state.event_count == before + 1


def test_schema_metadata_binds_order_and_state_semantics() -> None:
    schema = research_feature_schema()

    assert schema["schema_a"]["feature_order"] == list(PORTABLE_FEATURE_NAMES)  # type: ignore[index]
    assert schema["schema_b"]["feature_order"] == list(  # type: ignore[index]
        RUNTIME_ENRICHED_FEATURE_NAMES
    )
    assert len(TEMPORAL_FEATURE_NAMES) == 16
    assert schema["schema_b"]["state"]["duplicate_key"] == [  # type: ignore[index]
        "sensor_id",
        "event_id",
    ]


def test_observation_rejects_mixed_ip_versions_and_nonfinite_values() -> None:
    with pytest.raises(ValueError, match="IP version"):
        portable_feature_vector(_observation(1, destination_ip="2001:db8::1"))
    with pytest.raises(ValueError, match="finite"):
        portable_feature_vector(_observation(1, duration_ms=float("inf")))
