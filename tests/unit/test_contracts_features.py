from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import ip_address
from random import Random

import numpy as np
import pytest
from pydantic import ValidationError

from packages.contracts import FlowEvent
from packages.features import FEATURE_NAMES, flow_to_mapping, flow_to_vector
from services.sensor import DemoAdapter


def test_flow_contract_and_fixed_feature_order() -> None:
    flow = next(iter(DemoAdapter().flows()))
    vector = flow_to_vector(flow)
    assert vector.shape == (1, len(FEATURE_NAMES))
    assert FEATURE_NAMES[0] == "duration_ms"
    assert FEATURE_NAMES[-1] == "bytes_total"
    assert np.isfinite(vector).all()
    assert "src_ip" not in FEATURE_NAMES
    assert "dst_ip" not in FEATURE_NAMES


def test_unknown_fields_are_ignored_but_missing_required_fields_fail() -> None:
    payload = next(iter(DemoAdapter().flows())).model_dump(mode="json")
    payload["future_optional_field"] = "ignored"
    assert FlowEvent.model_validate(payload).schema_version == "1.0.0"
    payload.pop("bytes_forward")
    with pytest.raises(ValidationError):
        FlowEvent.model_validate(payload)


def test_malformed_flow_is_not_coerced_to_benign() -> None:
    payload = next(iter(DemoAdapter().flows())).model_dump(mode="json")
    payload["packet_length_min"] = 2000
    payload["packet_length_max"] = 100
    with pytest.raises(ValidationError, match="packet_length_min"):
        FlowEvent.model_validate(payload)


def test_timezone_and_ip_version_are_enforced() -> None:
    payload = next(iter(DemoAdapter().flows())).model_dump()
    payload["timestamp_start"] = datetime.now()
    with pytest.raises(ValidationError, match="timezone"):
        FlowEvent.model_validate(payload)
    payload = next(iter(DemoAdapter().flows())).model_dump()
    payload["timestamp_end"] = payload["timestamp_start"] - timedelta(seconds=1)
    with pytest.raises(ValidationError, match="precede"):
        FlowEvent.model_validate(payload)


def test_randomized_valid_flows_preserve_registry_order_and_identity_independence() -> None:
    random = Random(20260801)
    base = next(iter(DemoAdapter().flows()))
    for _ in range(256):
        duration_ms = random.uniform(1, 60_000)
        packets_forward = random.randint(1, 20_000)
        packets_reverse = random.randint(0, 20_000)
        bytes_forward = random.randint(packets_forward, packets_forward * 1500)
        bytes_reverse = random.randint(packets_reverse, max(packets_reverse, 1) * 1500)
        payload = base.model_dump(mode="json")
        payload.update(
            {
                "duration_ms": duration_ms,
                "packets_forward": packets_forward,
                "packets_reverse": packets_reverse,
                "bytes_forward": bytes_forward,
                "bytes_reverse": bytes_reverse,
                "packet_rate": (packets_forward + packets_reverse) / (duration_ms / 1000),
                "byte_rate": (bytes_forward + bytes_reverse) / (duration_ms / 1000),
                "packet_length_mean": random.uniform(1, 1500),
                "packet_length_std": random.uniform(0, 750),
                "iat_mean": random.uniform(0, duration_ms),
                "iat_std": random.uniform(0, duration_ms),
                "tcp_syn_count": random.randint(0, packets_forward),
                "tcp_ack_count": random.randint(0, packets_reverse),
                "tcp_rst_count": random.randint(0, packets_forward + packets_reverse),
            }
        )
        flow = FlowEvent.model_validate(payload)
        mapping = flow_to_mapping(flow)
        vector = flow_to_vector(flow)
        np.testing.assert_allclose(vector[0], [mapping[name] for name in FEATURE_NAMES])

        different_identity = flow.model_copy(
            update={
                "src_ip": ip_address("203.0.113.200"),
                "dst_ip": ip_address("198.51.100.200"),
            }
        )
        np.testing.assert_array_equal(flow_to_vector(flow), flow_to_vector(different_identity))


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0, 86_400_001.0])
def test_feature_registry_rejects_nonfinite_or_out_of_range_duration(value: float) -> None:
    flow = next(iter(DemoAdapter().flows())).model_copy(update={"duration_ms": value})
    with pytest.raises(ValueError, match="duration_ms"):
        flow_to_mapping(flow)
