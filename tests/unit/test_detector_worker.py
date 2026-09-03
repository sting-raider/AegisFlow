from __future__ import annotations

from typing import cast
from unittest.mock import Mock

import pytest

from packages.common.bus import RedisStreamBus
from packages.detection import DetectionEngine
from packages.model_bundle import ModelBundle
from services.detector.worker import DetectorWorker
from services.sensor import DemoAdapter


def test_detector_worker_runs_one_hybrid_call_for_a_redis_batch(bundle: ModelBundle) -> None:
    flows = list(DemoAdapter().flows())
    messages = [
        (str(index), {"flow": flow.model_dump(mode="json"), "signature": None})
        for index, flow in enumerate(flows)
    ]
    bus = Mock(spec=RedisStreamBus)
    engine = Mock(wraps=DetectionEngine(bundle))
    worker = DetectorWorker(bus=cast(RedisStreamBus, bus), engine=cast(DetectionEngine, engine))

    result = worker.process_batch(messages)

    assert result.received == len(flows)
    assert result.published == len(flows)
    assert result.rejected == 0
    engine.detect_batch.assert_called_once()
    bus.publish_batch.assert_called_once()
    bus.acknowledge_many.assert_called_once_with(
        "aegisflow:flows",
        "detectors",
        [str(index) for index in range(len(flows))],
    )
    bus.publish.assert_not_called()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("packet_rate", -1),
        ("first_packet_interarrival_times", [0.0, float("nan")]),
        ("first_packet_interarrival_times", [0.0, float("inf")]),
    ],
)
def test_detector_worker_quarantines_invalid_rows_without_poisoning_valid_batch(
    bundle: ModelBundle, field: str, value: object,
) -> None:
    flow = next(iter(DemoAdapter().flows()))
    invalid = flow.model_dump(mode="json")
    invalid[field] = value
    messages = [
        ("invalid", {"flow": invalid, "signature": None}),
        ("valid", {"flow": flow.model_dump(mode="json"), "signature": None}),
    ]
    bus = Mock(spec=RedisStreamBus)
    engine = Mock(wraps=DetectionEngine(bundle))
    worker = DetectorWorker(bus=cast(RedisStreamBus, bus), engine=cast(DetectionEngine, engine))

    result = worker.process_batch(messages)

    assert result == result.__class__(received=2, published=1, rejected=1)
    engine.detect_batch.assert_called_once()
    bus.publish.assert_called_once()
    bus.publish_batch.assert_called_once()
    bus.acknowledge.assert_any_call("aegisflow:flows", "detectors", "invalid")
    bus.acknowledge_many.assert_called_once_with(
        "aegisflow:flows", "detectors", ["valid"]
    )
    dead_letter = bus.publish.call_args_list[0].args
    assert dead_letter[0] == "aegisflow:dead-letter"
    assert field not in str(dead_letter[1])


def test_detector_worker_isolates_feature_registry_error_and_retries_remaining_rows(
    bundle: ModelBundle,
) -> None:
    flow = next(iter(DemoAdapter().flows()))
    invalid = flow.model_dump(mode="json")
    invalid["packets_forward"] = 1_000_000_001
    messages = [
        ("feature-invalid", {"flow": invalid, "signature": None}),
        ("valid", {"flow": flow.model_dump(mode="json"), "signature": None}),
    ]
    bus = Mock(spec=RedisStreamBus)
    engine = Mock(wraps=DetectionEngine(bundle))
    worker = DetectorWorker(bus=cast(RedisStreamBus, bus), engine=cast(DetectionEngine, engine))

    result = worker.process_batch(messages)

    assert result.published == 1
    assert result.rejected == 1
    assert engine.detect_batch.call_count == 2
    bus.acknowledge.assert_any_call("aegisflow:flows", "detectors", "feature-invalid")
    bus.acknowledge_many.assert_called_once_with(
        "aegisflow:flows", "detectors", ["valid"]
    )


def test_detector_worker_leaves_batch_pending_on_model_wide_failure(bundle: ModelBundle) -> None:
    flow = next(iter(DemoAdapter().flows()))
    bus = Mock(spec=RedisStreamBus)
    engine = Mock(spec=DetectionEngine)
    engine.bundle = bundle
    engine.detect_batch.side_effect = ValueError("model-wide inference failure")
    worker = DetectorWorker(bus=cast(RedisStreamBus, bus), engine=cast(DetectionEngine, engine))

    with pytest.raises(ValueError, match="model-wide inference failure"):
        worker.process_batch(
            [("pending", {"flow": flow.model_dump(mode="json"), "signature": None})]
        )

    bus.publish.assert_not_called()
    bus.acknowledge.assert_not_called()
