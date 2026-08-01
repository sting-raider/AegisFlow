from datetime import UTC, datetime
from unittest.mock import Mock

from sqlalchemy.exc import SQLAlchemyError

from apps.api.consumer import DetectionConsumer
from apps.api.database import Repository
from packages.common.bus import RedisStreamBus
from packages.detection import DetectionEngine
from packages.incidents import DriftEvent, RuntimeDriftMonitor
from packages.model_bundle import ModelBundle
from services.sensor import DemoAdapter


def detection_envelope(bundle: ModelBundle) -> dict[str, object]:
    flow = next(iter(DemoAdapter().flows()))
    detection = DetectionEngine(bundle).detect(flow)
    return {
        "flow": flow.model_dump(mode="json"),
        "detection": detection.model_dump(mode="json"),
        "signature": None,
    }


def test_database_failure_is_retried_before_acknowledgement(bundle: ModelBundle) -> None:
    repository = Mock(spec=Repository)
    repository.ingest.side_effect = [SQLAlchemyError("offline"), None]
    repository.detection_exists.return_value = False
    bus = Mock(spec=RedisStreamBus)
    database_error = Mock()
    received = Mock()
    validated = Mock()
    processing_latency = Mock()
    detection_result = Mock()
    consumer = DetectionConsumer(
        repository,
        "redis://unused",
        bus=bus,
        retry_base_seconds=0,
        on_database_error=database_error,
        on_flow_received=received,
        on_flow_validated=validated,
        on_processing_latency=processing_latency,
        on_detection_result=detection_result,
    )

    assert consumer.process_message("1-0", detection_envelope(bundle))
    assert repository.ingest.call_count == 2
    database_error.assert_called_once_with()
    received.assert_called_once_with()
    validated.assert_called_once_with()
    processing_latency.assert_called_once()
    detection_result.assert_called_once()
    telemetry = consumer.telemetry()
    assert telemetry["received_total"] == 1
    assert telemetry["validated_total"] == 1
    assert telemetry["rejected_total"] == 0
    assert telemetry["processing_latency_ms"] is not None
    bus.acknowledge.assert_called_once_with("aegisflow:detections", "api-core", "1-0")


def test_exhausted_database_retry_remains_pending(bundle: ModelBundle) -> None:
    repository = Mock(spec=Repository)
    repository.ingest.side_effect = SQLAlchemyError("offline")
    bus = Mock(spec=RedisStreamBus)
    consumer = DetectionConsumer(
        repository,
        "redis://unused",
        bus=bus,
        database_attempts=2,
        retry_base_seconds=0,
    )

    assert not consumer.process_message("2-0", detection_envelope(bundle))
    assert repository.ingest.call_count == 2
    bus.acknowledge.assert_not_called()


def test_schema_error_is_quarantined_and_acknowledged() -> None:
    repository = Mock(spec=Repository)
    bus = Mock(spec=RedisStreamBus)
    rejected = Mock()
    consumer = DetectionConsumer(
        repository, "redis://unused", bus=bus, on_flow_rejected=rejected
    )
    envelope = {"flow": {"schema_version": "unsupported"}}

    assert consumer.process_message("3-0", envelope)
    repository.ingest.assert_not_called()
    bus.publish.assert_called_once()
    assert bus.publish.call_args.args[0] == "aegisflow:dead-letter"
    dead_letter = bus.publish.call_args.args[1]
    assert dead_letter["error_code"] == "ValidationError"
    assert "unsupported" not in str(dead_letter)
    rejected.assert_called_once_with("ValidationError")
    assert consumer.telemetry()["rejected_total"] == 1
    bus.acknowledge.assert_called_once_with("aegisflow:detections", "api-core", "3-0")


def test_new_detection_persists_drift_before_acknowledgement(bundle: ModelBundle) -> None:
    repository = Mock(spec=Repository)
    repository.detection_exists.return_value = False
    repository.record_drift_event.return_value = True
    bus = Mock(spec=RedisStreamBus)
    monitor = Mock(spec=RuntimeDriftMonitor)
    event = DriftEvent(
        signal="anomaly_score",
        detection_time=datetime.now(UTC),
        reference_window=8,
        recent_window=8,
        magnitude=0.5,
        reference_mean=0.1,
        recent_mean=0.6,
        model_version="0.2.0",
    )
    monitor.observe.return_value = (event,)
    callback = Mock()
    consumer = DetectionConsumer(
        repository,
        "redis://unused",
        bus=bus,
        drift_monitor=monitor,
        on_drift_event=callback,
    )

    assert consumer.process_message("4-0", detection_envelope(bundle))
    repository.record_drift_event.assert_called_once_with(event)
    callback.assert_called_once_with(event)
    bus.acknowledge.assert_called_once_with("aegisflow:detections", "api-core", "4-0")


def test_queue_pressure_is_counted_once_per_threshold_crossing(monkeypatch) -> None:
    monkeypatch.setenv("AEGISFLOW_STREAM_MAXLEN", "100")
    repository = Mock(spec=Repository)
    bus = Mock(spec=RedisStreamBus)
    bus.group_status.return_value = {"pending": 30, "lag": 50, "consumers": 1}
    backpressure = Mock()
    consumer = DetectionConsumer(
        repository, "redis://unused", bus=bus, on_backpressure=backpressure
    )

    consumer._update_queue_status()
    consumer._update_queue_status()

    assert consumer.queue_status["backpressure"] is True
    assert consumer.queue_status["utilization"] == 0.8
    assert consumer.queue_status["backpressure_events"] == 1
    backpressure.assert_called_once_with()
