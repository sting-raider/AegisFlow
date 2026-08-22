import math
from datetime import UTC, datetime
from uuid import uuid4

import numpy as np
import pytest

from packages.contracts import CaptureMode, FlowEvent
from packages.detection_v2.sequences import (
    CONNECTION_STATE_FEATURE_NAMES,
    SEQUENCE_FEATURES_PER_PACKET,
    observability_tier,
    sequence_arrays,
    sequence_representation,
    sequence_representation_from_flow_event,
)


def _flow(**overrides: object) -> FlowEvent:
    base: dict[str, object] = {
        "event_id": uuid4(),
        "sensor_id": "test-sensor",
        "capture_mode": CaptureMode.PCAP,
        "timestamp_start": datetime(2026, 1, 1, tzinfo=UTC),
        "timestamp_end": datetime(2026, 1, 1, second=1, tzinfo=UTC),
        "duration_ms": 1000.0,
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.5",
        "src_port": 44_000,
        "dst_port": 80,
        "ip_version": 4,
        "protocol": "TCP",
        "packets_forward": 3,
        "packets_reverse": 2,
        "bytes_forward": 900,
        "bytes_reverse": 300,
        "packet_rate": 5.0,
        "byte_rate": 1200.0,
        "packet_length_min": 60.0,
        "packet_length_max": 500.0,
        "packet_length_mean": 240.0,
        "packet_length_std": 100.0,
        "iat_min": 1.0,
        "iat_max": 50.0,
        "iat_mean": 25.0,
        "iat_std": 12.0,
        "tcp_syn_count": 1,
        "tcp_ack_count": 2,
        "first_packet_sizes": [64, 520, 80, 400, 66],
        "first_packet_directions": [1, -1, 1, -1, 1],
        "first_packet_interarrival_times": [0.0, 2.0, 8.0, 30.0, 45.0],
        "community_flow_id": "community-id-test",
        "source_adapter": "unit-test",
    }
    base.update(overrides)
    return FlowEvent.model_validate(base)


def test_padding_is_explicit_and_masked() -> None:
    tensor, mask = sequence_arrays([64, 520], [1, -1], [0.0, 3.5], max_length=8)
    assert tensor.shape == (8, SEQUENCE_FEATURES_PER_PACKET)
    assert mask.tolist() == [1, 1, 0, 0, 0, 0, 0, 0]
    assert np.all(tensor[2:] == 0.0), "padded slots must be zero and masked"
    assert math.isclose(float(tensor[0, 0]), math.log1p(64), rel_tol=1e-6)
    assert math.isclose(float(tensor[1, 0]), -math.log1p(520), rel_tol=1e-6)
    assert math.isclose(float(tensor[1, 1]), math.log1p(3.5), rel_tol=1e-6)


def test_one_packet_flow_has_zero_leading_iat_and_low_observability() -> None:
    representation = sequence_representation(
        protocol="TCP",
        total_packets=1,
        duration_ms=0.001,
        sizes=[60],
        directions=[1],
        interarrival_ms=[0.0],
        syn_count=1,
    )
    assert representation.mask.sum() == 1
    assert representation.tensor[0, 1] == 0.0
    assert representation.tensor[0, 3] == 0.0
    assert representation.observability == "LOW"


def test_truncates_to_common_prefix_when_evidence_incomplete() -> None:
    tensor, mask = sequence_arrays(
        [100, 200, 300, 400], [1, -1, 1], [0.0, 1.0, 2.0], max_length=20
    )
    assert mask.sum() == 3


def test_position_feature_is_contract_normalized() -> None:
    tensor, _ = sequence_arrays(
        [10, 20, 30, 40], [1, 1, 1, 1], [0, 1, 2, 3], max_length=7
    )
    positions = tensor[:4, 3]
    assert float(positions[0]) == 0.0
    assert float(positions[-1]) == pytest.approx(3 / 19)


def test_tcp_state_categories_are_inspectable() -> None:
    handshake = sequence_representation(
        protocol="TCP",
        total_packets=10,
        duration_ms=500,
        sizes=[60, 60, 400, 100],
        directions=[1, -1, 1, -1],
        interarrival_ms=[0, 1, 2, 3],
        syn_count=1,
        ack_count=3,
        psh_count=2,
    )
    state = dict(zip(CONNECTION_STATE_FEATURE_NAMES, handshake.connection_state, strict=True))
    assert state["state_syn_observed"] == 1.0
    assert state["state_handshake_evidence"] == 1.0
    assert state["state_midstream_capture"] == 0.0
    assert state["state_data_exchange"] == 1.0

    reset = sequence_representation(
        protocol="TCP",
        total_packets=2,
        duration_ms=1,
        sizes=[60, 40],
        directions=[1, -1],
        interarrival_ms=[0, 1],
        syn_count=1,
        rst_count=1,
    )
    reset_state = dict(
        zip(CONNECTION_STATE_FEATURE_NAMES, reset.connection_state, strict=True)
    )
    assert reset_state["state_reset_terminated"] == 1.0
    assert reset_state["state_short_failed"] == 1.0
    assert reset_state["state_half_open_suspected"] == 0.0

    midstream = sequence_representation(
        protocol="TCP",
        total_packets=9,
        duration_ms=8000,
        sizes=[500, 200],
        directions=[1, -1],
        interarrival_ms=[0, 5],
    )
    midstream_state = dict(
        zip(CONNECTION_STATE_FEATURE_NAMES, midstream.connection_state, strict=True)
    )
    assert midstream_state["state_midstream_capture"] == 1.0
    assert midstream_state["state_syn_observed"] == 0.0

    udp = sequence_representation(
        protocol="UDP",
        total_packets=2,
        duration_ms=20,
        sizes=[90, 190],
        directions=[1, -1],
        interarrival_ms=[0, 12],
    )
    assert float(udp.connection_state.sum()) in {0.0, 1.0}


def test_non_tcp_clears_transport_state_except_exchange() -> None:
    representation = sequence_representation(
        protocol="UDP",
        total_packets=6,
        duration_ms=100,
        sizes=[80, 220, 90, 210, 88, 205],
        directions=[1, -1, 1, -1, 1, -1],
        interarrival_ms=[0, 5, 10, 15, 20, 25],
        syn_count=0,
    )
    state = dict(zip(CONNECTION_STATE_FEATURE_NAMES, representation.connection_state, strict=True))
    assert all(value == 0.0 for name, value in state.items() if name != "state_data_exchange")


def test_observability_tiers_distinguish_information_content() -> None:
    low = observability_tier(
        protocol="TCP", total_packets=1, sequence_length=1, duration_ms=0.001,
        has_state_evidence=False,
    )
    medium = observability_tier(
        protocol="TCP", total_packets=2, sequence_length=2, duration_ms=5,
        has_state_evidence=True,
    )
    high = observability_tier(
        protocol="TCP", total_packets=12, sequence_length=12, duration_ms=900,
        has_state_evidence=True,
    )
    assert (low, medium, high) == ("LOW", "MEDIUM", "HIGH")


def test_flow_event_adapter_matches_direct_representation() -> None:
    flow = _flow()
    direct = sequence_representation(
        protocol=flow.protocol,
        total_packets=flow.packets_forward + flow.packets_reverse,
        duration_ms=float(flow.duration_ms),
        sizes=list(flow.first_packet_sizes),
        directions=list(flow.first_packet_directions),
        interarrival_ms=list(flow.first_packet_interarrival_times),
        syn_count=flow.tcp_syn_count,
        ack_count=flow.tcp_ack_count,
        fin_count=flow.tcp_fin_count,
        rst_count=flow.tcp_rst_count,
        psh_count=flow.tcp_psh_count,
        bytes_forward=flow.bytes_forward,
        bytes_reverse=flow.bytes_reverse,
    )
    adapted = sequence_representation_from_flow_event(flow)
    assert np.array_equal(direct.tensor, adapted.tensor)
    assert np.array_equal(direct.mask, adapted.mask)
    assert np.array_equal(direct.connection_state, adapted.connection_state)
    assert direct.observability == adapted.observability


def test_representation_is_endpoint_identity_independent() -> None:
    first = _flow(src_ip="192.168.1.10", dst_ip="10.0.0.5")
    second = _flow(
        src_ip="2001:db8::1", dst_ip="2001:db8::2", ip_version=6
    )
    left = sequence_representation_from_flow_event(first)
    right = sequence_representation_from_flow_event(second)
    assert np.array_equal(left.tensor, right.tensor)
    assert np.array_equal(left.mask, right.mask)


def test_sequence_lengths_of_eight_twelve_twenty_share_prefixes() -> None:
    sizes = [float(60 + index * 37) for index in range(20)]
    directions = [1 if index % 2 == 0 else -1 for index in range(20)]
    iats = [float(index) for index in range(20)]
    reference = None
    for length in (8, 12, 20):
        tensor, mask = sequence_arrays(sizes, directions, iats, max_length=length)
        assert int(mask.sum()) == min(length, 20)
        if reference is not None:
            assert np.array_equal(reference, tensor[: len(reference)])
        reference = tensor


def test_position_feature_is_independent_of_tensor_length() -> None:
    _, short_mask = sequence_arrays([1.0] * 4, [1] * 4, [0.0] * 4, max_length=8)
    long_tensor, _ = sequence_arrays([1.0] * 4, [1] * 4, [0.0] * 4, max_length=20)
    assert float(long_tensor[3, 3]) == pytest.approx(3 / 19)
