from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np
import pytest
from pydantic import ValidationError

from packages.contracts import FlowEvent
from packages.features import FEATURE_NAMES, flow_to_vector
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
